//! Non-interactive CLI helpers (list / get / status / sync / generate / CRUD / …).
//!
//! Vault operations go through [`Backend`]: either the unlock daemon (when `BW_SESSION` /
//! `--session` is set and the agent is running) or a one-shot local unlock that prompts for
//! the master password. Both run the same [`crate::api::dispatch`] implementation.

use std::io::{self, BufRead, Read, Write};
use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use vault_session::{
    apply_generator_policy, generate_passphrase_opts, generate_password_checked, profile_dir,
    GeneratorOptions, PassphraseOptions, Session,
};

use crate::agent;
use crate::api;
use crate::profiles::{load_registry_from, ProfilesFile};

pub struct CliCtx {
    pub root: PathBuf,
    pub registry: ProfilesFile,
    pub profile_id: String,
    pub json: bool,
    /// `BW_SESSION` / `--session` token for the unlock daemon.
    pub session_token: Option<String>,
}

impl CliCtx {
    pub fn load(root: PathBuf, profile: Option<String>, json: bool) -> Result<Self> {
        let registry = load_registry_from(&root);
        let profile_id = profile.unwrap_or_else(|| registry.active.clone());
        if !registry.profiles.iter().any(|p| p.id == profile_id) {
            bail!("unknown profile `{profile_id}`");
        }
        Ok(Self {
            root,
            registry,
            profile_id,
            json,
            session_token: std::env::var("BW_SESSION").ok().filter(|t| !t.is_empty()),
        })
    }

    /// Override the session token (e.g. from `--session`).
    pub fn with_session(mut self, token: Option<String>) -> Self {
        if token.as_deref().is_some_and(|t| !t.is_empty()) {
            self.session_token = token;
        }
        self
    }

    pub fn data_dir(&self) -> PathBuf {
        profile_dir(&self.root, &self.profile_id)
    }

    pub fn profile(&self) -> &crate::profiles::VaultProfile {
        self.registry
            .profiles
            .iter()
            .find(|p| p.id == self.profile_id)
            .expect("validated")
    }
}

pub fn read_password() -> Result<String> {
    if let Ok(p) = std::env::var("BW_PASSWORD") {
        eprintln!("warning: BW_PASSWORD is set (prefer stdin for scripts)");
        return Ok(p);
    }
    eprint!("Master password: ");
    let _ = io::stderr().flush();
    let mut line = String::new();
    io::stdin().read_line(&mut line).context("read password")?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

/// Read a value from a command-line argument, or stdin when the argument is `-` / absent.
pub fn read_arg_or_stdin(arg: Option<&str>) -> Result<String> {
    match arg {
        Some(a) if a != "-" => Ok(a.to_string()),
        _ => {
            let mut buf = String::new();
            io::stdin().read_to_string(&mut buf).context("read stdin")?;
            Ok(buf)
        }
    }
}

pub async fn unlock_session_for_generate(ctx: &CliCtx) -> Result<Session> {
    unlock_session(ctx).await
}

pub(crate) async fn unlock_session(ctx: &CliCtx) -> Result<Session> {
    let allow = ctx.profile().allow_plaintext_token;
    let mut session = Session::try_restore_saved(ctx.data_dir(), allow)
        .await
        .context("restore session")?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no saved session for profile `{}` — run `login` (or sign in via the TUI) first",
                ctx.profile_id
            )
        })?;
    let password = read_password()?;
    session.unlock(&password).await.context("unlock")?;
    Ok(session)
}

/// Where vault operations run: the unlock daemon, or a locally unlocked session.
#[allow(clippy::large_enum_variant)]
pub enum Backend {
    Local(Session),
    Agent { profile: String, token: String },
}

impl Backend {
    /// Prefer the daemon when `BW_SESSION` is set and reachable; otherwise unlock locally.
    pub async fn open(ctx: &CliCtx) -> Result<Self> {
        if let Some(token) = &ctx.session_token {
            if agent::is_running(&ctx.profile_id).await {
                return Ok(Self::Agent {
                    profile: ctx.profile_id.clone(),
                    token: token.clone(),
                });
            }
            eprintln!(
                "warning: BW_SESSION is set but no unlock agent is running for profile `{}`; \
                 unlocking directly",
                ctx.profile_id
            );
        }
        Ok(Self::Local(unlock_session(ctx).await?))
    }

    pub async fn call(&mut self, method: &str, params: Value) -> Result<Value> {
        match self {
            Self::Local(s) => api::dispatch(s, method, &params).await,
            Self::Agent { profile, token } => agent::request(profile, token, method, &params)
                .await
                .map_err(|e| anyhow!("{e}")),
        }
    }

    /// Advance idle auto-lock for a local session. Returns `false` once it has locked.
    pub fn tick(&mut self) -> bool {
        match self {
            Self::Local(s) => {
                s.tick();
                s.status() == vault_session::SessionStatus::Unlocked
            }
            Self::Agent { .. } => true,
        }
    }

    /// Lock a local session (the daemon keeps its own lifecycle).
    pub async fn close(self) {
        if let Self::Local(mut s) = self {
            s.lock();
        }
    }
}

/// One-shot: open a backend, run a single call, close.
pub async fn call(ctx: &CliCtx, method: &str, params: Value) -> Result<Value> {
    let mut backend = Backend::open(ctx).await?;
    let result = backend.call(method, params).await;
    backend.close().await;
    result
}

/// Print an api result: strings raw, objects as pretty JSON.
fn print_value(v: &Value) -> Result<()> {
    match v {
        Value::String(s) => println!("{s}"),
        other => println!("{}", serde_json::to_string_pretty(other)?),
    }
    Ok(())
}

pub async fn cmd_status(ctx: &CliCtx) -> Result<()> {
    let allow = ctx.profile().allow_plaintext_token;
    let agent_running = agent::is_running(&ctx.profile_id).await;
    match Session::try_restore_saved(ctx.data_dir(), allow).await? {
        Some(session) => {
            if ctx.json {
                println!(
                    "{}",
                    json!({
                        "profile": ctx.profile_id,
                        "email": session.email(),
                        "status": format!("{:?}", session.status()),
                        "offline": session.is_offline(),
                        "agent": agent_running,
                        "warning": session.storage_warning,
                    })
                );
            } else {
                println!("profile\t{}", ctx.profile_id);
                println!("email\t{}", session.email().unwrap_or("-"));
                println!("status\t{:?}", session.status());
                println!(
                    "offline\t{}",
                    if session.is_offline() { "yes" } else { "no" }
                );
                println!("agent\t{}", if agent_running { "unlocked" } else { "-" });
                if let Some(w) = session.storage_warning.as_deref() {
                    println!("warning\t{w}");
                }
            }
        }
        None => {
            if ctx.json {
                println!(
                    "{}",
                    json!({
                        "profile": ctx.profile_id,
                        "status": "logged_out",
                    })
                );
            } else {
                println!("profile\t{}", ctx.profile_id);
                println!("status\tlogged_out");
            }
        }
    }
    Ok(())
}

pub async fn cmd_sync(ctx: &CliCtx) -> Result<()> {
    let v = call(ctx, "sync", Value::Null).await?;
    let n = v["synced"].as_u64().unwrap_or(0);
    if ctx.json {
        println!("{}", json!({ "synced": n }));
    } else {
        println!("synced\t{n}");
    }
    Ok(())
}

#[derive(Default)]
pub struct ListOpts {
    pub search: Option<String>,
    pub folder: Option<String>,
    pub item_type: Option<String>,
    pub collection: Option<String>,
    pub organization: Option<String>,
    pub url: Option<String>,
    pub trash: bool,
    /// `tsv` (default), `json`, or `template`.
    pub format: Option<String>,
    /// Row template for `--format template` (`{id} {type} {name} {username} {uri} {folder}`).
    pub template: Option<String>,
}

/// Expand `\t`, `\n` and `\\` escapes in a user-supplied row template.
fn unescape_template(t: &str) -> String {
    let mut out = String::with_capacity(t.len());
    let mut chars = t.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('t') => out.push('\t'),
            Some('n') => out.push('\n'),
            Some('\\') => out.push('\\'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// Render one list row. Tabs/newlines inside values are flattened to spaces.
pub fn render_row(template: &str, item: &Value, folder_name: &str) -> String {
    let clean = |s: &str| s.replace(['\t', '\n', '\r'], " ");
    let get = |p: &str| item.pointer(p).and_then(Value::as_str).unwrap_or("");
    let type_label = match item["type"].as_u64() {
        Some(1) => "Login",
        Some(2) => "Note",
        Some(3) => "Card",
        Some(4) => "Identity",
        Some(5) => "SSH Key",
        _ => "Item",
    };
    let username = if get("/login/username").is_empty() {
        get("/identity/username")
    } else {
        get("/login/username")
    };
    template
        .replace("{id}", get("/id"))
        .replace("{type}", type_label)
        .replace("{name}", &clean(get("/name")))
        .replace("{username}", &clean(username))
        .replace("{uri}", &clean(get("/login/uris/0/uri")))
        .replace("{folder}", &clean(folder_name))
}

pub async fn cmd_list(ctx: &CliCtx, opts: ListOpts) -> Result<()> {
    let format = opts
        .format
        .as_deref()
        .map(str::to_lowercase)
        .unwrap_or_else(|| {
            if ctx.json {
                "json".into()
            } else {
                "tsv".into()
            }
        });
    if !matches!(format.as_str(), "json" | "tsv" | "template") {
        bail!("unknown list format `{format}` (tsv|json|template)");
    }
    let template = opts
        .template
        .as_deref()
        .map(unescape_template)
        .unwrap_or_else(|| "{id}\t{name}\t{username}".to_string());
    let wants_folder = format == "template" && template.contains("{folder}");

    let mut params = json!({ "object": "items", "trash": opts.trash });
    for (k, v) in [
        ("search", &opts.search),
        ("folder", &opts.folder),
        ("type", &opts.item_type),
        ("collection", &opts.collection),
        ("organization", &opts.organization),
        ("url", &opts.url),
    ] {
        if let Some(v) = v {
            params[k] = v.clone().into();
        }
    }

    let mut backend = Backend::open(ctx).await?;
    let rows = backend.call("list", params).await;
    let folders = match (&rows, wants_folder) {
        (Ok(_), true) => backend.call("list", json!({ "object": "folders" })).await,
        _ => Ok(Value::Null),
    };
    backend.close().await;
    let rows = rows?;
    let folders = folders?;
    let rows = rows.as_array().cloned().unwrap_or_default();
    let folder_name = |id: Option<&str>| -> String {
        id.and_then(|id| {
            folders
                .as_array()?
                .iter()
                .find(|f| f["id"].as_str() == Some(id))
                .and_then(|f| f["name"].as_str())
                .map(str::to_string)
        })
        .unwrap_or_default()
    };

    match format.as_str() {
        "json" => {
            let summary: Vec<Value> = rows
                .iter()
                .map(|i| {
                    json!({
                        "id": i["id"],
                        "type": render_row("{type}", i, ""),
                        "name": i["name"],
                        "username": i.pointer("/login/username"),
                        "folderId": i["folderId"],
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&summary)?);
        }
        "template" => {
            for i in &rows {
                println!(
                    "{}",
                    render_row(&template, i, &folder_name(i["folderId"].as_str()))
                );
            }
        }
        _ => {
            for i in &rows {
                println!("{}", render_row("{id}\t{type}\t{name}", i, ""));
            }
        }
    }
    Ok(())
}

/// `get`: `what` is a scalar field (`password`, `username`, `totp`, `uri`, `name`, `notes`,
/// `custom:<n>`) or an object kind (`item`, `exposed`, `folder`, `collection`, `organization`,
/// `template`, `fingerprint`, `send`).
pub async fn cmd_get_what(
    ctx: &CliCtx,
    what: &str,
    query: Option<&str>,
    uri: Option<&str>,
) -> Result<()> {
    // Templates are static: no unlock needed.
    if what == "template" {
        let kind = query.ok_or_else(|| anyhow!("provide a template name (e.g. item.login)"))?;
        return print_value(&api::template_json(kind)?);
    }
    let mut params = json!({ "what": what });
    if let Some(q) = query {
        params["query"] = q.into();
    }
    if let Some(u) = uri {
        params["uri"] = u.into();
    }
    let v = call(ctx, "get", params).await?;
    match (&v, ctx.json) {
        (Value::String(s), true) => println!("{}", json!({ "field": what, "value": s })),
        _ => print_value(&v)?,
    }
    Ok(())
}

pub async fn cmd_get(
    ctx: &CliCtx,
    query: Option<&str>,
    uri: Option<&str>,
    field: &str,
) -> Result<()> {
    cmd_get_what(ctx, field, query, uri).await
}

pub async fn cmd_totp(ctx: &CliCtx, query: &str) -> Result<()> {
    let item = call(ctx, "get", json!({ "what": "item", "query": query })).await?;
    let secret = item
        .pointer("/login/totp")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("no TOTP on item"))?;
    let display = vault_session::totp_display_from_secret(secret)?;
    if ctx.json {
        println!(
            "{}",
            json!({
                "code": display.code,
                "period": display.period,
                "remaining": display.remaining,
            })
        );
    } else {
        println!("{}", display.code);
    }
    Ok(())
}

pub struct GenerateOpts {
    pub length: usize,
    pub passphrase: bool,
    pub words: usize,
    pub capitalize: bool,
    pub include_number: bool,
    pub no_uppercase: bool,
    pub no_lowercase: bool,
    pub no_digits: bool,
    pub no_symbols: bool,
    pub avoid_ambiguous: bool,
    pub org_policy: Option<vault_session::GeneratorPolicy>,
}

/// Generate a password / passphrase from CLI-style options.
pub fn generate_value(opts: GenerateOpts) -> Result<String> {
    let value = if opts.passphrase {
        generate_passphrase_opts(
            PassphraseOptions {
                words: opts.words,
                capitalize: opts.capitalize,
                include_number: opts.include_number,
            },
            "-",
        )
    } else {
        let mut gen = GeneratorOptions {
            length: opts.length,
            uppercase: !opts.no_uppercase,
            lowercase: !opts.no_lowercase,
            digits: !opts.no_digits,
            symbols: !opts.no_symbols,
            avoid_ambiguous: opts.avoid_ambiguous,
            ..Default::default()
        };
        if let Some(policy) = opts.org_policy.as_ref() {
            apply_generator_policy(&mut gen, policy);
        }
        generate_password_checked(gen).map_err(|e| anyhow::anyhow!(e))?
    };
    Ok(value)
}

pub fn cmd_generate(opts: GenerateOpts, json: bool) -> Result<()> {
    let value = generate_value(opts)?;
    if json {
        println!("{}", json!({ "password": value }));
    } else {
        println!("{value}");
    }
    Ok(())
}

/// `git credential` helper protocol (get).
pub async fn cmd_git_credential(ctx: &CliCtx) -> Result<()> {
    let stdin = io::stdin();
    let mut protocol = String::new();
    let mut host = String::new();
    let mut path = String::new();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once('=') {
            match k {
                "protocol" => protocol = v.to_string(),
                "host" => host = v.to_string(),
                "path" => path = v.to_string(),
                _ => {}
            }
        }
    }
    if host.is_empty() {
        return Ok(());
    }
    let target = if protocol.is_empty() {
        format!("https://{host}/{path}")
    } else {
        format!("{protocol}://{host}/{path}")
    };

    match call(ctx, "get", json!({ "what": "item", "uri": target })).await {
        Ok(item) => {
            if let Some(user) = item.pointer("/login/username").and_then(Value::as_str) {
                println!("username={user}");
            }
            if let Some(pass) = item.pointer("/login/password").and_then(Value::as_str) {
                println!("password={pass}");
            }
            Ok(())
        }
        // git expects silence when there is no matching credential.
        Err(e) if e.to_string().contains("no login matches") => Ok(()),
        Err(e) => Err(e),
    }
}

/// SSH_ASKPASS / SUDO_ASKPASS: print password for a matching prompt host if possible,
/// otherwise unlock and search by prompt text; falls back to reading BW_PASSWORD.
pub async fn cmd_askpass(ctx: &CliCtx, prompt: Option<String>) -> Result<()> {
    if let Ok(p) = std::env::var("BW_PASSWORD") {
        print!("{p}");
        return Ok(());
    }
    let prompt = prompt.unwrap_or_default();
    let mut session = unlock_session(ctx).await?;
    // Heuristic: find login whose name or URI appears in the askpass prompt.
    let item = session.items().iter().find(|i| {
        !i.deleted
            && (!prompt.is_empty())
            && (prompt.to_lowercase().contains(&i.name.to_lowercase())
                || i.uris
                    .iter()
                    .any(|u| prompt.contains(&u.uri) || u.uri.contains(&prompt)))
    });
    if let Some(item) = item {
        if let Some(pass) = &item.password {
            print!("{pass}");
            session.lock();
            return Ok(());
        }
    }
    session.lock();
    bail!("no matching credential for askpass prompt");
}

#[allow(clippy::too_many_arguments)]
pub async fn cmd_export(
    ctx: &CliCtx,
    path: &std::path::Path,
    format: &str,
    encrypted: bool,
    password: Option<&str>,
    organization: Option<&str>,
) -> Result<()> {
    let format = format.trim().to_ascii_lowercase();
    // Validate cheap argument combinations before prompting for the master password.
    if encrypted && organization.is_some() {
        bail!("--encrypted is not supported together with --organization");
    }
    if let Some(org) = organization {
        if !matches!(format.as_str(), "json" | "csv") {
            bail!(
                "organization export supports json|csv (got `{format}`) — endpoint stub: {}",
                vault_session::organization_export_endpoint(org)
            );
        }
    } else if !matches!(
        format.as_str(),
        "json" | "csv" | "csv-extended" | "csv-simple" | "zip"
    ) {
        bail!("unknown export format `{format}` (json|csv|csv-extended|csv-simple|zip)");
    }

    let mut session = unlock_session(ctx).await?;
    let mut warnings: Vec<String> = Vec::new();
    let body: Vec<u8> = if encrypted {
        let kdf = session.account_kdf().ok_or_else(|| {
            anyhow::anyhow!("missing KDF — unlock online once before encrypted export")
        })?;
        let pwd = match password {
            Some(p) if !p.is_empty() => p.to_string(),
            _ => read_password()?,
        };
        if pwd.is_empty() {
            bail!("encrypted export requires a password (--password or prompt)");
        }
        vault_session::export_encrypted_json(session.items(), session.folders(), &pwd, &kdf)
            .map_err(|e| anyhow::anyhow!("{e}"))?
            .into_bytes()
    } else if let Some(org) = organization {
        if !session
            .organizations()
            .iter()
            .any(|o| o.id == org || o.name.eq_ignore_ascii_case(org))
        {
            bail!("unknown organization `{org}`");
        }
        let org_id = session
            .organizations()
            .iter()
            .find(|o| o.id == org || o.name.eq_ignore_ascii_case(org))
            .map(|o| o.id.clone())
            .expect("checked above");
        match format.as_str() {
            "json" => vault_session::export_organization_json(
                &org_id,
                session.items(),
                session.collections(),
            ),
            _ => vault_session::export_organization_csv(
                &org_id,
                session.items(),
                session.collections(),
            ),
        }
        .into_bytes()
    } else {
        match format.as_str() {
            "json" => vault_session::export_json(session.items(), session.folders()).into_bytes(),
            "csv" => vault_session::export_csv_full(session.items(), session.folders(), false)
                .into_bytes(),
            "csv-extended" => {
                vault_session::export_csv_full(session.items(), session.folders(), true)
                    .into_bytes()
            }
            "csv-simple" => vault_session::export_csv(session.items()).into_bytes(),
            "zip" => {
                let (attachments, att_warnings) = vault_session::collect_attachments(&mut session)
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                warnings.extend(att_warnings);
                vault_session::export_zip(session.items(), session.folders(), &attachments)
                    .map_err(|e| anyhow::anyhow!("{e}"))?
            }
            _ => unreachable!("validated above"),
        }
    };
    std::fs::write(path, body).with_context(|| format!("write {}", path.display()))?;
    for w in &warnings {
        eprintln!("warning: {w}");
    }
    if ctx.json {
        println!(
            "{}",
            json!({
                "exported": path.display().to_string(),
                "format": if encrypted { "encrypted_json" } else { format.as_str() },
                "warnings": warnings,
            })
        );
    } else {
        println!("exported\t{}", path.display());
    }
    session.lock();
    Ok(())
}

pub async fn cmd_import(
    ctx: &CliCtx,
    path: &std::path::Path,
    format: Option<&str>,
    password: Option<&str>,
) -> Result<()> {
    use vault_session::ImportFormat;

    let format = match format {
        Some(f) => ImportFormat::parse(f).ok_or_else(|| {
            anyhow::anyhow!("unknown import format `{f}` ({})", ImportFormat::names())
        })?,
        None => ImportFormat::guess_from_extension(path).ok_or_else(|| {
            anyhow::anyhow!(
                "cannot infer import format from `{}` — pass --format ({})",
                path.display(),
                ImportFormat::names()
            )
        })?,
    };
    let raw = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;

    // Prompt for the export password up front only when the file is a protected Bitwarden JSON.
    let encrypted_json = format == ImportFormat::BitwardenJson && {
        let text = String::from_utf8_lossy(&raw);
        text.contains("encKeyValidation_DO_NOT_EDIT")
            || text.contains("\"passwordProtected\": true")
            || text.contains("\"passwordProtected\":true")
    };
    let mut session = unlock_session(ctx).await?;
    let pwd = if encrypted_json {
        let p = match password {
            Some(p) if !p.is_empty() => p.to_string(),
            _ => read_password()?,
        };
        if p.is_empty() {
            bail!("encrypted import requires a password (--password or prompt)");
        }
        Some(p)
    } else {
        None
    };
    let bundle = vault_session::import_from_bytes(format, &raw, pwd.as_deref())
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    // Map importer folder ids -> real folder ids (reuse existing folders with the same name).
    let mut folder_map: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    let mut folders_created = 0usize;
    for folder in &bundle.folders {
        let existing = session
            .folders()
            .iter()
            .find(|f| f.name == folder.name)
            .map(|f| f.id.clone());
        let real_id = match existing {
            Some(id) => id,
            None => {
                folders_created += 1;
                session.create_folder(&folder.name).await?
            }
        };
        folder_map.insert(folder.id.clone(), real_id);
    }
    let remap = |id: &Option<String>| id.as_ref().and_then(|i| folder_map.get(i).cloned());

    let mut count = 0usize;
    for draft in &bundle.login_drafts {
        let mut d = draft.clone();
        d.folder_id = remap(&draft.folder_id);
        session.create_login(&d).await?;
        count += 1;
    }
    for draft in &bundle.note_drafts {
        let mut d = draft.clone();
        d.folder_id = remap(&draft.folder_id);
        session.create_note(&d).await?;
        count += 1;
    }
    for draft in &bundle.card_drafts {
        let mut d = draft.clone();
        d.folder_id = remap(&draft.folder_id);
        session.create_card(&d).await?;
        count += 1;
    }
    for draft in &bundle.identity_drafts {
        let mut d = draft.clone();
        d.folder_id = remap(&draft.folder_id);
        session.create_identity(&d).await?;
        count += 1;
    }
    for w in &bundle.warnings {
        eprintln!("warning: {w}");
    }
    if ctx.json {
        println!(
            "{}",
            json!({
                "imported": count,
                "folders_created": folders_created,
                "format": format.name(),
                "warnings": bundle.warnings,
            })
        );
    } else {
        println!("imported\t{count}");
        if folders_created > 0 {
            println!("folders\t{folders_created}");
        }
    }
    session.lock();
    Ok(())
}

pub async fn cmd_delete(ctx: &CliCtx, query: &str, permanent: bool) -> Result<()> {
    let v = call(
        ctx,
        "item.delete",
        json!({ "query": query, "permanent": permanent }),
    )
    .await?;
    let id = v["deleted"].as_str().unwrap_or(query);
    if ctx.json {
        println!("{}", json!({ "deleted": id, "permanent": permanent }));
    } else {
        println!("deleted\t{id}");
    }
    Ok(())
}

pub async fn cmd_restore(ctx: &CliCtx, query: &str) -> Result<()> {
    let v = call(ctx, "item.restore", json!({ "query": query })).await?;
    let id = v["restored"].as_str().unwrap_or(query);
    if ctx.json {
        println!("{}", json!({ "restored": id }));
    } else {
        println!("restored\t{id}");
    }
    Ok(())
}

pub async fn cmd_move(ctx: &CliCtx, query: &str, folder: &str) -> Result<()> {
    let v = call(
        ctx,
        "item.move",
        json!({ "query": query, "folder": folder }),
    )
    .await?;
    if ctx.json {
        println!("{v}");
    } else {
        println!("moved\t{}", v["moved"].as_str().unwrap_or(query));
    }
    Ok(())
}

pub async fn cmd_share(
    ctx: &CliCtx,
    query: &str,
    organization: &str,
    collections: Vec<String>,
) -> Result<()> {
    let v = call(
        ctx,
        "item.share",
        json!({ "query": query, "organization": organization, "collections": collections }),
    )
    .await?;
    if ctx.json {
        println!("{v}");
    } else {
        println!("shared\t{}", v["shared"].as_str().unwrap_or(query));
    }
    Ok(())
}

/// `create item|folder <json|base64|->`.
pub async fn cmd_create(ctx: &CliCtx, kind: &str, data: Option<&str>) -> Result<()> {
    let raw = read_arg_or_stdin(data)?;
    let v = match kind {
        "item" => {
            let item = api::parse_item_input(&raw)?;
            call(ctx, "item.create", json!({ "item": item })).await?
        }
        "folder" => {
            let name = folder_name_input(&raw)?;
            call(ctx, "folder.create", json!({ "name": name })).await?
        }
        other => bail!("unknown create target `{other}` (item|folder)"),
    };
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

/// `edit item|folder <id> <json|base64|->`. Item JSON is merged over the existing item,
/// so partial documents (e.g. just `{"login":{"password":"…"}}`) work.
pub async fn cmd_edit(ctx: &CliCtx, kind: &str, id: &str, data: Option<&str>) -> Result<()> {
    let raw = read_arg_or_stdin(data)?;
    let v = match kind {
        "item" => {
            let item = api::parse_item_input(&raw)?;
            call(ctx, "item.edit", json!({ "query": id, "item": item })).await?
        }
        "folder" => {
            let name = folder_name_input(&raw)?;
            call(ctx, "folder.edit", json!({ "query": id, "name": name })).await?
        }
        other => bail!("unknown edit target `{other}` (item|folder)"),
    };
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

/// Accept a bare folder name, a `{"name": …}` JSON document, or its base64 encoding.
fn folder_name_input(raw: &str) -> Result<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        bail!("folder name is required");
    }
    if raw.starts_with('{') {
        let v = api::parse_item_input(raw)?;
        return v["name"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .ok_or_else(|| anyhow!("folder JSON needs a non-empty `name`"));
    }
    Ok(raw.to_string())
}

/// `delete folder <id|name>`.
pub async fn cmd_delete_folder(ctx: &CliCtx, query: &str) -> Result<()> {
    let v = call(ctx, "folder.delete", json!({ "query": query })).await?;
    println!("deleted\t{}", v["deleted"].as_str().unwrap_or(query));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_unescape_and_render() {
        assert_eq!(unescape_template(r"{id}\t{name}\n"), "{id}\t{name}\n");
        let item = json!({
            "id": "abc", "type": 1, "name": "My\tSite",
            "login": { "username": "me", "uris": [{ "uri": "https://x.test" }] }
        });
        assert_eq!(
            render_row(
                "{id}|{type}|{name}|{username}|{uri}|{folder}",
                &item,
                "Work"
            ),
            "abc|Login|My Site|me|https://x.test|Work"
        );
    }

    #[test]
    fn folder_input_forms() {
        assert_eq!(folder_name_input("Work\n").unwrap(), "Work");
        assert_eq!(folder_name_input(r#"{"name":"X"}"#).unwrap(), "X");
        assert!(folder_name_input("  ").is_err());
    }
}
