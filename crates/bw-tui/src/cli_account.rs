//! Account / daemon / server CLI commands: `unlock`, `lock`, `login`, `logout`, `config`,
//! `encode`, `serve`.

use std::io::{self, Write};

use anyhow::{bail, Context, Result};
use base64::Engine;
use serde_json::json;
use vault_session::{normalize_server_url, LoginResult, Session};

use crate::agent;
use crate::cli::{read_password, Backend, CliCtx};
use crate::profiles::{profile_has_auth, update_profile_credentials};
use crate::serve::{self, ServeOpts};

fn prompt_line(prompt: &str) -> Result<String> {
    eprint!("{prompt}");
    let _ = io::stderr().flush();
    let mut line = String::new();
    io::stdin().read_line(&mut line).context("read input")?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

/// `unlock`: start the per-profile daemon and print a `BW_SESSION` token.
pub async fn cmd_unlock(ctx: &CliCtx, raw: bool) -> Result<()> {
    if agent::is_running(&ctx.profile_id).await {
        bail!(
            "profile `{}` is already unlocked — run `lock` first (the session token is only \
             shown once)",
            ctx.profile_id
        );
    }
    let password = read_password()?;
    let token = agent::spawn_unlocked(&ctx.profile_id, &password).await?;
    if raw {
        println!("{token}");
    } else if ctx.json {
        println!("{}", json!({ "session": token, "profile": ctx.profile_id }));
    } else {
        eprintln!("Vault unlocked. Export the session token to use it from this shell:");
        println!("export BW_SESSION=\"{token}\"");
    }
    Ok(())
}

/// `lock`: stop the daemon (zeroizes the in-memory session).
pub async fn cmd_lock(ctx: &CliCtx) -> Result<()> {
    let was_running = agent::lock(&ctx.profile_id).await?;
    if ctx.json {
        println!("{}", json!({ "locked": was_running }));
    } else if was_running {
        println!("locked\t{}", ctx.profile_id);
    } else {
        println!("not unlocked\t{}", ctx.profile_id);
    }
    Ok(())
}

pub struct LoginOpts {
    pub email: Option<String>,
    pub server: Option<String>,
    /// Use `BW_CLIENTID` / `BW_CLIENTSECRET` (personal API key) instead of a password grant.
    pub apikey: bool,
    /// Two-step verification code.
    pub code: Option<String>,
    /// Two-step provider: 0 authenticator, 1 email, 3 YubiKey, 5 remember, …
    pub method: Option<u8>,
}

/// `login`: authenticate, persist the refresh token, remember server/email on the profile.
pub async fn cmd_login(ctx: &CliCtx, opts: LoginOpts) -> Result<()> {
    let profile = ctx.profile().clone();
    let server = opts
        .server
        .filter(|s| !s.trim().is_empty())
        .or_else(|| Some(profile.server_url.clone()).filter(|s| !s.is_empty()))
        .map(Ok)
        .unwrap_or_else(|| {
            let typed = prompt_line("Server URL: ")?;
            if typed.trim().is_empty() {
                bail!("server URL is required (--server, BW_SERVER, or `config server <url>`)");
            }
            Ok(typed)
        })?;
    let server = normalize_server_url(&server).map_err(|e| anyhow::anyhow!("{e}"))?;
    let email = match opts
        .email
        .filter(|e| !e.is_empty())
        .or_else(|| Some(profile.email.clone()).filter(|e| !e.is_empty()))
    {
        Some(e) => e,
        None => prompt_line("Email: ")?,
    };
    if email.trim().is_empty() {
        bail!("email is required (--email, BW_EMAIL, or the profile email)");
    }
    let email = email.trim().to_string();

    // A running daemon would keep serving the previous account.
    let _ = agent::lock(&ctx.profile_id).await;

    let mut session =
        Session::with_data_dir(&server, ctx.data_dir()).map_err(|e| anyhow::anyhow!("{e}"))?;
    session.set_allow_plaintext_token(vault_session::plaintext_token_allowed(
        profile.allow_plaintext_token,
    ));
    session.set_auto_lock(profile.auto_lock_minutes);
    let password = read_password()?;

    if opts.apikey {
        let client_id = match std::env::var("BW_CLIENTID") {
            Ok(v) if !v.is_empty() => v,
            _ => prompt_line("client_id: ")?,
        };
        let client_secret = match std::env::var("BW_CLIENTSECRET") {
            Ok(v) if !v.is_empty() => v,
            _ => prompt_line("client_secret: ")?,
        };
        session
            .login_api_key(&email, &password, client_id.trim(), client_secret.trim())
            .await
            .context("API key login")?;
    } else {
        let two = opts.code.as_deref().map(|c| (opts.method.unwrap_or(0), c));
        match session
            .login(&email, &password, two)
            .await
            .context("login")?
        {
            LoginResult::Success => {}
            LoginResult::TwoFactorRequired { providers } => {
                if opts.code.is_some() {
                    bail!("two-step verification rejected (providers: {providers:?})");
                }
                let provider = opts.method.unwrap_or_else(|| {
                    if providers.contains(&0) {
                        0
                    } else {
                        providers.first().copied().unwrap_or(0)
                    }
                });
                if provider == 1 {
                    session
                        .send_email_login_2fa(&email, &password)
                        .await
                        .context("send email code")?;
                    eprintln!("A verification code was emailed to you.");
                }
                let code = prompt_line(&format!("Two-step login code (provider {provider}): "))?;
                if code.trim().is_empty() {
                    bail!("two-step login code required (rerun with --code)");
                }
                session
                    .login_2fa(&email, &password, provider, code.trim())
                    .await
                    .context("two-step login")?;
            }
        }
    }

    session.lock();

    let mut registry = crate::profiles::load_registry_from(&ctx.root);
    update_profile_credentials(&ctx.root, &mut registry, &ctx.profile_id, &server, &email)
        .map_err(|e| anyhow::anyhow!("save profile: {e}"))?;

    if ctx.json {
        println!(
            "{}",
            json!({ "loggedIn": true, "profile": ctx.profile_id, "email": email, "server": server })
        );
    } else {
        println!("logged in\t{email}\t{server}");
    }
    Ok(())
}

/// `logout`: stop the daemon and delete the saved session for the profile.
pub async fn cmd_logout(ctx: &CliCtx) -> Result<()> {
    let _ = agent::lock(&ctx.profile_id).await;
    let had_auth = profile_has_auth(&ctx.root, &ctx.profile_id);
    Session::clear_persisted_auth(&ctx.data_dir());
    if ctx.json {
        println!(
            "{}",
            json!({ "loggedOut": had_auth, "profile": ctx.profile_id })
        );
    } else if had_auth {
        println!("logged out\t{}", ctx.profile_id);
    } else {
        println!("not logged in\t{}", ctx.profile_id);
    }
    Ok(())
}

/// `config server [url]`: show or set the server URL of the selected profile.
pub async fn cmd_config_server(ctx: &CliCtx, url: Option<&str>) -> Result<()> {
    let profile = ctx.profile();
    match url {
        None => {
            if ctx.json {
                println!("{}", json!({ "serverUrl": profile.server_url }));
            } else if profile.server_url.is_empty() {
                println!("-");
            } else {
                println!("{}", profile.server_url);
            }
        }
        Some(raw) => {
            let normalized = normalize_server_url(raw).map_err(|e| anyhow::anyhow!("{e}"))?;
            if profile_has_auth(&ctx.root, &ctx.profile_id)
                && normalized.trim_end_matches('/') != profile.server_url.trim_end_matches('/')
            {
                bail!(
                    "profile `{}` is logged in to {} — run `logout` before changing the server",
                    ctx.profile_id,
                    profile.server_url
                );
            }
            let mut registry = crate::profiles::load_registry_from(&ctx.root);
            update_profile_credentials(
                &ctx.root,
                &mut registry,
                &ctx.profile_id,
                &normalized,
                &profile.email,
            )
            .map_err(|e| anyhow::anyhow!("{e}"))?;
            if ctx.json {
                println!("{}", json!({ "serverUrl": normalized }));
            } else {
                println!("server\t{normalized}");
            }
        }
    }
    Ok(())
}

/// `config show`: profile settings as JSON-ish key/values.
pub async fn cmd_config_show(ctx: &CliCtx) -> Result<()> {
    let p = ctx.profile();
    let logged_in = profile_has_auth(&ctx.root, &p.id);
    if ctx.json {
        println!(
            "{}",
            json!({
                "profile": p.id,
                "name": p.name,
                "serverUrl": p.server_url,
                "email": p.email,
                "autoLockMinutes": p.auto_lock_minutes,
                "clipboardClearSecs": p.clipboard_clear_secs,
                "loggedIn": logged_in,
            })
        );
    } else {
        println!("profile\t{}", p.id);
        println!(
            "server\t{}",
            if p.server_url.is_empty() {
                "-"
            } else {
                &p.server_url
            }
        );
        println!("email\t{}", if p.email.is_empty() { "-" } else { &p.email });
        println!(
            "auto_lock\t{}",
            crate::profiles::format_auto_lock_label(p.auto_lock_minutes)
        );
        println!("logged_in\t{}", if logged_in { "yes" } else { "no" });
    }
    Ok(())
}

/// `encode [text]`: base64-encode stdin / an argument (as `bw encode`); `--decode` reverses it.
pub fn cmd_encode(input: Option<&str>, decode: bool) -> Result<()> {
    let raw = crate::cli::read_arg_or_stdin(input)?;
    let engine = base64::engine::general_purpose::STANDARD;
    if decode {
        let bytes = engine
            .decode(raw.trim())
            .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(raw.trim()))
            .context("input is not valid base64")?;
        io::stdout().write_all(&bytes)?;
        if !bytes.ends_with(b"\n") {
            println!();
        }
    } else {
        println!("{}", engine.encode(raw.as_bytes()));
    }
    Ok(())
}

/// `serve`: REST API on localhost, token-protected.
pub async fn cmd_serve(
    ctx: &CliCtx,
    hostname: String,
    port: u16,
    token: Option<String>,
) -> Result<()> {
    let backend = Backend::open(ctx).await?;
    let (token, generated) = match token.filter(|t| !t.is_empty()) {
        Some(t) => (t, false),
        None => (agent::generate_token(), true),
    };
    if generated {
        eprintln!("API token: {token}");
    }
    serve::run(
        backend,
        ServeOpts {
            host: hostname,
            port,
            token,
        },
    )
    .await
}
