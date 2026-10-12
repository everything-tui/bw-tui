//! Non-interactive CLI helpers (list / get / status / sync).

use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use vault_session::{profile_dir, Session};

use crate::profiles::{load_registry_from, ProfilesFile};

pub struct CliCtx {
    pub root: PathBuf,
    pub registry: ProfilesFile,
    pub profile_id: String,
}

impl CliCtx {
    pub fn load(root: PathBuf, profile: Option<String>) -> Result<Self> {
        let registry = load_registry_from(&root);
        let profile_id = profile.unwrap_or_else(|| registry.active.clone());
        if !registry.profiles.iter().any(|p| p.id == profile_id) {
            bail!("unknown profile `{profile_id}`");
        }
        Ok(Self {
            root,
            registry,
            profile_id,
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
        None => {
            println!("profile\t{}", ctx.profile_id);
            println!("status\tlogged_out");
        }
    }
    Ok(())
}

pub async fn cmd_sync(ctx: &CliCtx) -> Result<()> {
    let mut session = unlock_session(ctx).await?;
    session.sync().await.context("sync")?;
    println!("synced\t{}", session.items().len());
    session.lock();
    Ok(())
}

pub async fn cmd_list(ctx: &CliCtx) -> Result<()> {
    let mut session = unlock_session(ctx).await?;
    for item in session.items() {
        if item.deleted {
            continue;
        }
        println!(
            "{}\t{}\t{}",
            item.id,
            item.item_type.label(),
            item.name.replace('\t', " ")
        );
    }
    session.lock();
    Ok(())
}

pub async fn cmd_get(ctx: &CliCtx, query: &str, field: &str) -> Result<()> {
    let mut session = unlock_session(ctx).await?;
    let item = session
        .items()
        .iter()
        .find(|i| !i.deleted && (i.id == query || i.name.eq_ignore_ascii_case(query)))
        .ok_or_else(|| anyhow::anyhow!("item not found: {query}"))?
        .clone();
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
        other => bail!("unknown field `{other}` (password|username|totp|uri|name|notes)"),
    };
    match value {
        Some(v) => println!("{v}"),
        None => bail!("field `{field}` empty on item"),
    }
    session.lock();
    Ok(())
}
