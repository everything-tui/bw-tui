//! Non-interactive CLI helpers (list / get / status / sync / generate / …).

use std::io::{self, BufRead, Write};
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use serde_json::json;
use vault_session::{
    apply_generator_policy, generate_passphrase_opts, generate_password_checked, item_matches_uri_decrypted,
    profile_dir, GeneratorOptions, PassphraseOptions, Session,
};

use crate::profiles::{load_registry_from, ProfilesFile};

pub struct CliCtx {
    pub root: PathBuf,
    pub registry: ProfilesFile,
    pub profile_id: String,
    pub json: bool,
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
        })
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

fn read_password() -> Result<String> {
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

pub async fn unlock_session_for_generate(ctx: &CliCtx) -> Result<Session> {
    unlock_session(ctx).await
}

async fn unlock_session(ctx: &CliCtx) -> Result<Session> {
    let allow = ctx.profile().allow_plaintext_token;
    let mut session = Session::try_restore_saved(ctx.data_dir(), allow)
        .await
        .context("restore session")?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no saved session for profile `{}` — sign in via the TUI first",
                ctx.profile_id
            )
        })?;
    let password = read_password()?;
    session.unlock(&password).await.context("unlock")?;
    Ok(session)
}

pub async fn cmd_status(ctx: &CliCtx) -> Result<()> {
    let allow = ctx.profile().allow_plaintext_token;
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
    let mut session = unlock_session(ctx).await?;
    session.sync().await.context("sync")?;
    let n = session.items().len();
    if ctx.json {
        println!("{}", json!({ "synced": n }));
    } else {
        println!("synced\t{n}");
    }
    session.lock();
    Ok(())
}

pub struct ListOpts {
    pub search: Option<String>,
    pub folder: Option<String>,
    pub item_type: Option<String>,
}

pub async fn cmd_list(ctx: &CliCtx, opts: ListOpts) -> Result<()> {
    let mut session = unlock_session(ctx).await?;
    let folder_id = opts.folder.as_ref().and_then(|name| {
        session
            .folders()
            .iter()
            .find(|f| f.name.eq_ignore_ascii_case(name) || f.id == *name)
            .map(|f| f.id.clone())
    });
    if opts.folder.is_some() && folder_id.is_none() {
        bail!("folder not found");
    }

    let mut rows = Vec::new();
    for item in session.items() {
        if item.deleted {
            continue;
        }
        if let Some(ref fid) = folder_id {
            if item.folder_id.as_ref() != Some(fid) {
                continue;
            }
        }
        if let Some(ref t) = opts.item_type {
            if !item.item_type.label().eq_ignore_ascii_case(t)
                && format!("{:?}", item.item_type).to_lowercase() != t.to_lowercase()
            {
                continue;
            }
        }
        if let Some(ref q) = opts.search {
            let hay = format!(
                "{} {} {} {}",
                item.name,
                item.username.as_deref().unwrap_or(""),
                item.notes.as_deref().unwrap_or(""),
                item.uris
                    .iter()
                    .map(|u| u.uri.as_str())
                    .collect::<Vec<_>>()
                    .join(" ")
            );
            if !hay.to_lowercase().contains(&q.to_lowercase()) {
                continue;
            }
        }
        rows.push(json!({
            "id": item.id,
            "type": item.item_type.label(),
            "name": item.name,
            "username": item.username,
            "folderId": item.folder_id,
        }));
        if !ctx.json {
            println!(
                "{}\t{}\t{}",
                item.id,
                item.item_type.label(),
                item.name.replace('\t', " ")
            );
        }
    }
    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&rows)?);
    }
    session.lock();
    Ok(())
}

fn resolve_item<'a>(
    session: &'a Session,
    query: &str,
) -> Result<&'a vault_session::DecryptedItem> {
    let matches: Vec<_> = session
        .items()
        .iter()
        .filter(|i| {
            !i.deleted
                && (i.id == query
                    || i.name.eq_ignore_ascii_case(query)
                    || i.name.to_lowercase().contains(&query.to_lowercase()))
        })
        .collect();
    match matches.as_slice() {
        [] => bail!("item not found: {query}"),
        [one] => Ok(*one),
        many => {
            let names: Vec<_> = many
                .iter()
                .map(|i| format!("{} ({})", i.name, i.id))
                .collect();
            bail!(
                "ambiguous match for `{query}` — candidates:\n  {}",
                names.join("\n  ")
            );
        }
    }
}

pub async fn cmd_get(ctx: &CliCtx, query: Option<&str>, uri: Option<&str>, field: &str) -> Result<()> {
    let mut session = unlock_session(ctx).await?;
    let item = if let Some(target) = uri {
        let groups = session.uri_equivalent_groups();
        session
            .items()
            .iter()
            .find(|i| {
                !i.deleted
                    && item_matches_uri_decrypted(&i.uris, target, &groups)
            })
            .ok_or_else(|| anyhow::anyhow!("no login matches uri `{target}`"))?
            .clone()
    } else {
        let query = query.ok_or_else(|| anyhow::anyhow!("provide item query or --uri"))?;
        resolve_item(&session, query)?.clone()
    };
    let value = match field {
        "password" => item.password.clone(),
        "username" => item.username.clone(),
        "totp" => item
            .totp
            .as_deref()
            .and_then(|s| vault_session::totp_from_secret(s).ok()),
        "uri" => item.primary_uri().map(str::to_string),
        "name" => Some(item.name.clone()),
        "notes" => item.notes.clone(),
        custom if custom.starts_with("custom:") => {
            let name = custom.trim_start_matches("custom:");
            item.custom_fields
                .iter()
                .find(|f| f.name.eq_ignore_ascii_case(name))
                .map(|f| f.value.clone())
        }
        other => bail!(
            "unknown field `{other}` (password|username|totp|uri|name|notes|custom:<name>)"
        ),
    };
    match value {
        Some(v) => {
            if ctx.json {
                println!("{}", json!({ "field": field, "value": v }));
            } else {
                println!("{v}");
            }
        }
        None => bail!("field `{field}` empty on item"),
    }
    session.lock();
    Ok(())
}

pub async fn cmd_totp(ctx: &CliCtx, query: &str) -> Result<()> {
    let mut session = unlock_session(ctx).await?;
    let item = resolve_item(&session, query)?;
    let secret = item
        .totp
        .as_deref()
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
    session.lock();
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

pub fn cmd_generate(opts: GenerateOpts, json: bool) -> Result<()> {
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

    let mut session = unlock_session(ctx).await?;
    let groups = session.uri_equivalent_groups();
    let item = session.items().iter().find(|i| {
        !i.deleted && item_matches_uri_decrypted(&i.uris, &target, &groups)
    });
    if let Some(item) = item {
        if let Some(user) = &item.username {
            println!("username={user}");
        }
        if let Some(pass) = &item.password {
            println!("password={pass}");
        }
    }
    session.lock();
    Ok(())
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
                || i.uris.iter().any(|u| {
                    prompt.contains(&u.uri) || u.uri.contains(&prompt)
                }))
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

pub async fn cmd_export(
    ctx: &CliCtx,
    path: &std::path::Path,
    format: &str,
    encrypted: bool,
    password: Option<&str>,
) -> Result<()> {
    let mut session = unlock_session(ctx).await?;
    let items = session.items();
    let folders = session.folders();
    let body = if encrypted {
        let kdf = session
            .account_kdf()
            .ok_or_else(|| anyhow::anyhow!("missing KDF — unlock online once before encrypted export"))?;
        let pwd = match password {
            Some(p) if !p.is_empty() => p.to_string(),
            _ => read_password()?,
        };
        if pwd.is_empty() {
            bail!("encrypted export requires a password (--password or prompt)");
        }
        vault_session::export_encrypted_json(items, folders, &pwd, &kdf)
            .map_err(|e| anyhow::anyhow!("{e}"))?
    } else {
        match format {
            "json" => vault_session::export_json(items, folders),
            "csv" => vault_session::export_csv(items),
            other => bail!("unknown export format `{other}` (json|csv)"),
        }
    };
    std::fs::write(path, body).with_context(|| format!("write {}", path.display()))?;
    if ctx.json {
        println!("{}", json!({ "exported": path.display().to_string(), "format": format }));
    } else {
        println!("exported\t{}", path.display());
    }
    session.lock();
    Ok(())
}

pub async fn cmd_import(
    ctx: &CliCtx,
    path: &std::path::Path,
    password: Option<&str>,
) -> Result<()> {
    let mut session = unlock_session(ctx).await?;
    let raw = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let looks_encrypted = raw.contains("encKeyValidation_DO_NOT_EDIT")
        || raw.contains("\"passwordProtected\": true")
        || raw.contains("\"passwordProtected\":true");
    let bundle = if looks_encrypted {
        let pwd = match password {
            Some(p) if !p.is_empty() => p.to_string(),
            _ => read_password()?,
        };
        if pwd.is_empty() {
            bail!("encrypted import requires a password (--password or prompt)");
        }
        vault_session::import_encrypted_json(&raw, &pwd).map_err(|e| anyhow::anyhow!("{e}"))?
    } else {
        vault_session::import_bitwarden_json(&raw).map_err(|e| anyhow::anyhow!("{e}"))?
    };
    let mut count = 0usize;
    for folder in &bundle.folders {
        session.create_folder(&folder.name).await?;
        count += 1;
    }
    for draft in &bundle.login_drafts {
        session.create_login(draft).await?;
        count += 1;
    }
    for draft in &bundle.note_drafts {
        session.create_note(draft).await?;
        count += 1;
    }
    for draft in &bundle.card_drafts {
        session.create_card(draft).await?;
        count += 1;
    }
    for draft in &bundle.identity_drafts {
        session.create_identity(draft).await?;
        count += 1;
    }
    if ctx.json {
        println!("{}", json!({ "imported": count }));
    } else {
        println!("imported\t{count}");
    }
    session.lock();
    Ok(())
}

pub async fn cmd_delete(ctx: &CliCtx, query: &str, permanent: bool) -> Result<()> {
    let mut session = unlock_session(ctx).await?;
    let id = resolve_item(&session, query)?.id.clone();
    if permanent {
        session.hard_delete(&id).await?;
    } else {
        session.soft_delete(&id).await?;
    }
    if ctx.json {
        println!("{}", json!({ "deleted": id, "permanent": permanent }));
    } else {
        println!("deleted\t{id}");
    }
    session.lock();
    Ok(())
}
