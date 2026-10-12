//! bitwarden-tui — Vaultwarden password manager terminal UI.

use std::io::{self, stdout, Write};
use std::panic;
use std::process::ExitCode;
use std::sync::{Once, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser};
use clap_complete::{generate, Shell};
use crossterm::event::{DisableMouseCapture, EnableMouseCapture, Event, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use tracing_subscriber::EnvFilter;
use vault_session::app_data_dir;
use vault_tui::app::{self, App};
use vault_tui::cli::{GenerateOpts, ListOpts};
use vault_tui::events;
use vault_tui::profiles::{load_registry_from, profile_has_auth};
use vault_tui::ui::{self, PaneVisibility};

#[derive(Debug, clap::Subcommand)]
enum Commands {
    /// Print session status for a profile
    Status,
    /// Authenticate and store a refresh token (like `bw login`)
    Login {
        #[arg(long)]
        email: Option<String>,
        #[arg(long)]
        server: Option<String>,
        /// Use BW_CLIENTID / BW_CLIENTSECRET instead of password grant
        #[arg(long)]
        apikey: bool,
        /// Two-step verification code
        #[arg(long)]
        code: Option<String>,
        /// Two-step provider (0 authenticator, 1 email, …)
        #[arg(long)]
        method: Option<u8>,
    },
    /// Clear stored credentials for the profile
    Logout,
    /// Start the unlock daemon and print `export BW_SESSION=…`
    Unlock {
        /// Print only the token (no shell export line)
        #[arg(long)]
        raw: bool,
    },
    /// Stop the unlock daemon
    Lock,
    /// Show or set profile config (`config server <url>` or `config` to show)
    Config {
        /// Subcommand: `server` (optional URL) or omit to show
        action: Option<String>,
        /// URL when action is `server`
        value: Option<String>,
    },
    /// Base64-encode stdin / argument (like `bw encode`); `--decode` reverses
    Encode {
        input: Option<String>,
        #[arg(long)]
        decode: bool,
    },
    /// Local REST API (localhost, token-protected) compatible with `bw serve`
    Serve {
        #[arg(long, default_value = "127.0.0.1")]
        hostname: String,
        #[arg(long, default_value_t = 8087)]
        port: u16,
        #[arg(long, env = "BW_SERVE_TOKEN")]
        token: Option<String>,
    },
    /// Unlock and list vault items
    List {
        #[arg(long)]
        search: Option<String>,
        #[arg(long)]
        folder: Option<String>,
        #[arg(long = "type")]
        item_type: Option<String>,
        #[arg(long)]
        collection: Option<String>,
        #[arg(long)]
        organization: Option<String>,
        #[arg(long)]
        url: Option<String>,
        #[arg(long)]
        trash: bool,
        /// tsv | json | template
        #[arg(long)]
        format: Option<String>,
        /// Row template for `--format template` (e.g. `{name}\t{username}`)
        #[arg(long)]
        template: Option<String>,
    },
    /// Unlock and print one field from an item (by id or name)
    Get {
        /// Item id or name (fuzzy; errors if ambiguous). Also `bw` style: `get <kind> <id>` with
        /// kind = item|password|username|uri|totp|notes|exposed|folder|collection|organization|
        /// template|fingerprint|send (e.g. `get template item.login`, `get fingerprint me`)
        query: Option<String>,
        /// Item id / template name when the first argument is a kind
        target: Option<String>,
        /// Match login by URI / host (uses equivalent domains from sync)
        #[arg(long)]
        uri: Option<String>,
        /// Field / object to print (password, username, notes, item, template, fingerprint, …)
        #[arg(long, default_value = "password")]
        field: String,
    },
    /// Create an item or folder from JSON / base64 / stdin (`-`)
    Create {
        /// `item` or `folder`
        kind: String,
        /// JSON document, base64, or `-` for stdin
        data: Option<String>,
    },
    /// Edit an item or folder (partial JSON merge for items)
    Edit {
        /// `item` or `folder`
        kind: String,
        /// Id or name
        id: String,
        /// JSON document, base64, or `-` for stdin
        data: Option<String>,
    },
    /// Restore a soft-deleted item
    Restore { query: String },
    /// Move an item to a folder
    Move { query: String, folder: String },
    /// Share a personal item to an organization
    Share {
        query: String,
        organization: String,
        #[arg(long = "collection", required = true, value_delimiter = ',')]
        collections: Vec<String>,
    },
    /// Unlock and print current TOTP for an item
    Totp { query: String },
    /// Unlock and sync the vault
    Sync,
    /// Generate a password or passphrase (no unlock required)
    Generate {
        #[arg(long, default_value_t = 20)]
        length: usize,
        #[arg(long)]
        passphrase: bool,
        #[arg(long, default_value_t = 4)]
        words: usize,
        #[arg(long)]
        capitalize: bool,
        #[arg(long)]
        include_number: bool,
        #[arg(long)]
        no_uppercase: bool,
        #[arg(long)]
        no_lowercase: bool,
        #[arg(long)]
        no_digits: bool,
        #[arg(long)]
        no_symbols: bool,
        #[arg(long)]
        avoid_ambiguous: bool,
        /// Unlock briefly and clamp options to org generator policy
        #[arg(long)]
        apply_org_policy: bool,
    },
    /// Soft-delete (or permanently delete) an item
    Delete {
        query: String,
        #[arg(long)]
        permanent: bool,
        /// Delete a folder instead of an item
        #[arg(long)]
        folder: bool,
    },
    /// Create / list / delete Sends, or print a share link
    Send {
        #[command(subcommand)]
        action: SendCmd,
    },
    /// Receive a Send from a share URL (no unlock required)
    Receive {
        url: String,
        #[arg(long, env = "BW_SEND_PASSWORD")]
        password: Option<String>,
        /// Output path for file Sends (file or directory)
        #[arg(long, short = 'o')]
        output: Option<std::path::PathBuf>,
    },
    /// git-credential helper (`get`)
    #[command(name = "git-credential")]
    GitCredential,
    /// SSH_ASKPASS / SUDO_ASKPASS helper
    Askpass {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        prompt: Vec<String>,
    },
    /// Export vault to JSON, CSV, or ZIP (with attachments); optionally password-protected JSON
    Export {
        path: std::path::PathBuf,
        /// json | csv (Bitwarden schema) | csv-extended (+cards/identities) | csv-simple | zip
        #[arg(long, default_value = "json")]
        format: String,
        #[arg(long)]
        encrypted: bool,
        #[arg(long)]
        password: Option<String>,
        /// Export only this organization (id or name); supports json|csv
        #[arg(long)]
        organization: Option<String>,
    },
    /// Import items from Bitwarden / browser / 1Password / LastPass / KeePass / Proton Pass exports
    Import {
        path: std::path::PathBuf,
        /// bitwarden-json|bitwarden-csv|chrome-csv|edge-csv|firefox-csv|1password-1pux|
        /// 1password-csv|lastpass-csv|keepass-xml|keepass-csv|proton-json|proton-csv
        /// (inferred from .json/.1pux/.xml when omitted)
        #[arg(long)]
        format: Option<String>,
        /// Password for encrypted exports (prompted if omitted and file is encrypted)
        #[arg(long)]
        password: Option<String>,
    },
    /// Generate shell completions
    Completions {
        /// bash | zsh | fish | elvish | powershell
        shell: String,
    },
    /// Write a man page to stdout
    Man,
    /// Internal: background unlock agent (spawned by `unlock`)
    #[command(name = "agent-run", hide = true)]
    AgentRun,
}

#[derive(Debug, clap::Subcommand)]
enum SendCmd {
    /// Create a text or file Send
    Create {
        /// Text body (`-` = stdin); omit when using `--file`
        text: Option<String>,
        #[arg(long)]
        file: Option<std::path::PathBuf>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        notes: Option<String>,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        max_access: Option<u32>,
        #[arg(long)]
        expires: Option<String>,
        #[arg(long)]
        delete_in: Option<String>,
        #[arg(long)]
        hide_email: bool,
        #[arg(long)]
        hidden: bool,
    },
    /// List Sends
    List,
    /// Delete a Send
    Delete { query: String },
    /// Print the share URL for a Send
    Link { query: String },
}

#[derive(Debug, Parser)]
#[command(
    name = "bitwarden-tui",
    about = "Terminal UI client for Vaultwarden / Bitwarden",
    version
)]
struct Cli {
    /// Named profile (see profiles.json)
    #[arg(long, env = "BW_PROFILE", global = true)]
    profile: Option<String>,

    /// List profiles and exit
    #[arg(long)]
    list_profiles: bool,

    /// Vaultwarden / Bitwarden server URL
    #[arg(long, env = "BW_SERVER")]
    server: Option<String>,

    /// Account email
    #[arg(long, env = "BW_EMAIL")]
    email: Option<String>,

    /// Emit JSON for scripting subcommands
    #[arg(long, global = true)]
    json: bool,

    /// Session token from `unlock` (talks to the background agent instead of prompting)
    #[arg(long, env = "BW_SESSION", global = true, hide_env_values = true)]
    session: Option<String>,

    /// Use in-memory mock vault (no network) for UI testing
    #[arg(long)]
    mock: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[tokio::main]
async fn main() -> ExitCode {
    if let Err(e) = run().await {
        eprintln!("error: {e:#}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

async fn run() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("vault_tui=info".parse()?))
        .with_writer(io::stderr)
        .init();

    let cli = Cli::parse();

    if cli.list_profiles {
        list_profiles();
        return Ok(());
    }

    if let Some(cmd) = &cli.command {
        // Commands that need no profile / unlock
        match cmd {
            Commands::Encode { input, decode } => {
                vault_tui::cli_account::cmd_encode(input.as_deref(), *decode)?;
                return Ok(());
            }
            Commands::Completions { shell } => {
                print_completions(shell)?;
                return Ok(());
            }
            Commands::Man => {
                print_man()?;
                return Ok(());
            }
            Commands::Receive {
                url,
                password,
                output,
            } => {
                vault_tui::cli_send::cmd_receive(
                    cli.json,
                    url,
                    password.as_deref(),
                    output.clone(),
                )
                .await?;
                return Ok(());
            }
            Commands::Generate {
                length,
                passphrase,
                words,
                capitalize,
                include_number,
                no_uppercase,
                no_lowercase,
                no_digits,
                no_symbols,
                avoid_ambiguous,
                apply_org_policy,
            } => {
                let org_policy = if *apply_org_policy {
                    let ctx = vault_tui::cli::CliCtx::load(
                        app_data_dir(),
                        cli.profile.clone(),
                        cli.json,
                    )?;
                    let mut session = vault_tui::cli::unlock_session_for_generate(&ctx).await?;
                    let policy = session.generator_policy();
                    session.lock();
                    Some(policy)
                } else {
                    None
                };
                vault_tui::cli::cmd_generate(
                    GenerateOpts {
                        length: *length,
                        passphrase: *passphrase,
                        words: *words,
                        capitalize: *capitalize,
                        include_number: *include_number,
                        no_uppercase: *no_uppercase,
                        no_lowercase: *no_lowercase,
                        no_digits: *no_digits,
                        no_symbols: *no_symbols,
                        avoid_ambiguous: *avoid_ambiguous,
                        org_policy,
                    },
                    cli.json,
                )?;
                return Ok(());
            }
            _ => {}
        }

        let ctx = vault_tui::cli::CliCtx::load(app_data_dir(), cli.profile.clone(), cli.json)?
            .with_session(cli.session.clone());
        match cmd {
            Commands::Status => vault_tui::cli::cmd_status(&ctx).await?,
            Commands::Login {
                email,
                server,
                apikey,
                code,
                method,
            } => {
                vault_tui::cli_account::cmd_login(
                    &ctx,
                    vault_tui::cli_account::LoginOpts {
                        email: email.clone().or(cli.email.clone()),
                        server: server.clone().or(cli.server.clone()),
                        apikey: *apikey,
                        code: code.clone(),
                        method: *method,
                    },
                )
                .await?
            }
            Commands::Logout => vault_tui::cli_account::cmd_logout(&ctx).await?,
            Commands::Unlock { raw } => vault_tui::cli_account::cmd_unlock(&ctx, *raw).await?,
            Commands::Lock => vault_tui::cli_account::cmd_lock(&ctx).await?,
            Commands::Config { action, value } => match action.as_deref() {
                None => vault_tui::cli_account::cmd_config_show(&ctx).await?,
                Some("server") => {
                    vault_tui::cli_account::cmd_config_server(&ctx, value.as_deref()).await?
                }
                Some(other) => anyhow::bail!("unknown config action `{other}` (server)"),
            },
            Commands::Serve {
                hostname,
                port,
                token,
            } => {
                vault_tui::cli_account::cmd_serve(&ctx, hostname.clone(), *port, token.clone())
                    .await?
            }
            Commands::List {
                search,
                folder,
                item_type,
                collection,
                organization,
                url,
                trash,
                format,
                template,
            } => {
                vault_tui::cli::cmd_list(
                    &ctx,
                    ListOpts {
                        search: search.clone(),
                        folder: folder.clone(),
                        item_type: item_type.clone(),
                        collection: collection.clone(),
                        organization: organization.clone(),
                        url: url.clone(),
                        trash: *trash,
                        format: format.clone(),
                        template: template.clone(),
                    },
                )
                .await?
            }
            Commands::Get {
                query,
                target,
                uri,
                field,
            } => {
                const KINDS: [&str; 13] = [
                    "item",
                    "password",
                    "username",
                    "uri",
                    "totp",
                    "notes",
                    "exposed",
                    "folder",
                    "collection",
                    "organization",
                    "template",
                    "fingerprint",
                    "send",
                ];
                match (query.as_deref(), target.as_deref()) {
                    // `get <kind> <id>` (bw style)
                    (Some(kind), Some(t)) if KINDS.contains(&kind) => {
                        vault_tui::cli::cmd_get_what(&ctx, kind, Some(t), uri.as_deref()).await?
                    }
                    (Some(_), Some(_)) => anyhow::bail!(
                        "unexpected second argument — use `get <kind> <id>` or `get <id> --field <field>`"
                    ),
                    (q, None) => vault_tui::cli::cmd_get(&ctx, q, uri.as_deref(), field).await?,
                    (None, Some(_)) => unreachable!("clap fills positionals in order"),
                }
            }
            Commands::Create { kind, data } => {
                vault_tui::cli::cmd_create(&ctx, kind, data.as_deref()).await?
            }
            Commands::Edit { kind, id, data } => {
                vault_tui::cli::cmd_edit(&ctx, kind, id, data.as_deref()).await?
            }
            Commands::Restore { query } => vault_tui::cli::cmd_restore(&ctx, query).await?,
            Commands::Move { query, folder } => {
                vault_tui::cli::cmd_move(&ctx, query, folder).await?
            }
            Commands::Share {
                query,
                organization,
                collections,
            } => vault_tui::cli::cmd_share(&ctx, query, organization, collections.clone()).await?,
            Commands::Totp { query } => vault_tui::cli::cmd_totp(&ctx, query).await?,
            Commands::Sync => vault_tui::cli::cmd_sync(&ctx).await?,
            Commands::Delete {
                query,
                permanent,
                folder,
            } => {
                if *folder {
                    vault_tui::cli::cmd_delete_folder(&ctx, query).await?
                } else {
                    vault_tui::cli::cmd_delete(&ctx, query, *permanent).await?
                }
            }
            Commands::Send { action } => match action {
                SendCmd::Create {
                    text,
                    file,
                    name,
                    notes,
                    password,
                    max_access,
                    expires,
                    delete_in,
                    hide_email,
                    hidden,
                } => {
                    vault_tui::cli_send::cmd_send_create(
                        &ctx,
                        vault_tui::cli_send::SendCreateOpts {
                            text: text.clone(),
                            file: file.clone(),
                            name: name.clone(),
                            notes: notes.clone(),
                            password: password.clone(),
                            max_access: *max_access,
                            expires: expires.clone(),
                            delete_in: delete_in.clone(),
                            hide_email: *hide_email,
                            hidden: *hidden,
                        },
                    )
                    .await?
                }
                SendCmd::List => vault_tui::cli_send::cmd_send_list(&ctx).await?,
                SendCmd::Delete { query } => {
                    vault_tui::cli_send::cmd_send_delete(&ctx, query).await?
                }
                SendCmd::Link { query } => vault_tui::cli_send::cmd_send_link(&ctx, query).await?,
            },
            Commands::GitCredential => vault_tui::cli::cmd_git_credential(&ctx).await?,
            Commands::Askpass { prompt } => {
                let joined = if prompt.is_empty() {
                    None
                } else {
                    Some(prompt.join(" "))
                };
                vault_tui::cli::cmd_askpass(&ctx, joined).await?
            }
            Commands::Export {
                path,
                format,
                encrypted,
                password,
                organization,
            } => {
                vault_tui::cli::cmd_export(
                    &ctx,
                    path,
                    format,
                    *encrypted,
                    password.as_deref(),
                    organization.as_deref(),
                )
                .await?
            }
            Commands::Import {
                path,
                format,
                password,
            } => {
                vault_tui::cli::cmd_import(&ctx, path, format.as_deref(), password.as_deref())
                    .await?
            }
            Commands::AgentRun => {
                let profile = ctx.profile();
                vault_tui::agent::run_daemon(
                    ctx.data_dir(),
                    ctx.profile_id.clone(),
                    vault_session::plaintext_token_allowed(profile.allow_plaintext_token),
                    profile.auto_lock_minutes,
                )
                .await?
            }
            Commands::Encode { .. }
            | Commands::Completions { .. }
            | Commands::Man
            | Commands::Receive { .. }
            | Commands::Generate { .. } => unreachable!("handled above"),
        }
        return Ok(());
    }

    let mut app = match App::new(cli.profile, cli.server, cli.email, cli.mock) {
        Ok(app) => app,
        Err(msg) => {
            eprintln!("error: {msg}");
            std::process::exit(2);
        }
    };
    app.restore_session_if_saved().await;

    let mut terminal = setup_terminal(app.config.mouse)?;
    let result = run_loop(&mut terminal, &mut app).await;
    app.clear_session_clipboard();
    restore_terminal(&mut terminal)?;
    result
}

fn list_profiles() {
    let root = app_data_dir();
    let file = load_registry_from(&root);
    let mut out = io::stdout();
    let _ = writeln!(
        out,
        "{:<2} {:<16} {:<20} {:<32} SERVER",
        "", "ID", "NAME", "EMAIL"
    );
    for p in &file.profiles {
        let marker = if p.id == file.active { "*" } else { " " };
        let auth = if profile_has_auth(&root, &p.id) {
            "saved"
        } else {
            "-"
        };
        let _ = writeln!(
            out,
            "{marker:<2} {id:<16} {name:<20} {email:<32} {server}  ({auth})",
            id = p.id,
            name = p.name,
            email = if p.email.is_empty() { "-" } else { &p.email },
            server = if p.server_url.is_empty() {
                "-"
            } else {
                &p.server_url
            },
        );
    }
}

type PanicHookFn = Box<dyn Fn(&panic::PanicHookInfo<'_>) + Send + Sync>;
static PANIC_HOOK: OnceLock<PanicHookFn> = OnceLock::new();
static PANIC_RESTORE: Once = Once::new();

fn install_panic_hook() {
    let default = panic::take_hook();
    let _ = PANIC_HOOK.set(default);
    panic::set_hook(Box::new(|info| {
        PANIC_RESTORE.call_once(|| {
            let _ = disable_raw_mode();
            let _ = execute!(
                io::stdout(),
                LeaveAlternateScreen,
                DisableMouseCapture,
                crossterm::cursor::Show,
            );
        });
        if let Some(default) = PANIC_HOOK.get() {
            default(info);
        }
    }));
}

fn setup_terminal(mouse: bool) -> Result<Terminal<CrosstermBackend<io::Stdout>>> {
    install_panic_hook();
    enable_raw_mode().context("enable raw mode")?;
    let mut out = stdout();
    if mouse {
        execute!(out, EnterAlternateScreen, EnableMouseCapture)
            .context("enter alternate screen")?;
    } else {
        // Mouse capture breaks keyboard input in some IDE terminals — leave off by default.
        execute!(out, EnterAlternateScreen).context("enter alternate screen")?;
    }
    let backend = CrosstermBackend::new(out);
    Terminal::new(backend).context("create terminal")
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
    disable_raw_mode().ok();
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )
    .ok();
    terminal.show_cursor().ok();
    Ok(())
}

async fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> Result<()> {
    let poll_timeout = Duration::from_millis(100);

    loop {
        let size = terminal.size()?;
        let vis = PaneVisibility::from_width(size.width);

        if !vis.detail && app.focus == app::FocusPane::Detail {
            app.focus = app::FocusPane::Items;
        }
        if !vis.folders && app.focus == app::FocusPane::Folders {
            app.focus = app::FocusPane::Items;
        }

        terminal.draw(|frame| {
            ui::draw(frame, app);
        })?;

        if app.should_quit {
            break;
        }

        // The busy frame is on screen now; run the queued auth work.
        if app.pending.is_some() {
            app.run_pending().await;
            continue;
        }

        // `$EDITOR` for notes: suspend the TUI around the child process.
        if let Some(req) = app.power.pending_editor.take() {
            run_external_editor(terminal, app, req)?;
            continue;
        }

        let maybe = wait_event(poll_timeout).await?;
        app.on_tick();
        app.power_on_tick();

        if let Some(event) = maybe {
            if let Event::Key(key) = &event {
                // Accept Press + Repeat. Also accept Release for printable chars only
                // (some IDE terminals emit Release without Press).
                let accept = match key.kind {
                    KeyEventKind::Press | KeyEventKind::Repeat => true,
                    KeyEventKind::Release => matches!(key.code, crossterm::event::KeyCode::Char(_)),
                };
                if !accept {
                    continue;
                }
            }
            let quit = events::handle_event(app, event, vis.detail, vis.folders).await;
            if quit || app.should_quit {
                break;
            }
        }
    }

    Ok(())
}

/// Leave the alternate screen, run `$VISUAL`/`$EDITOR` on a private temp file, then resume.
fn run_external_editor(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    mut req: vault_tui::app::EditorRequest,
) -> Result<()> {
    use zeroize::Zeroize;
    disable_raw_mode().ok();
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture,
        crossterm::cursor::Show
    )
    .ok();
    let result = vault_tui::editor::edit_text(&req.initial);
    req.initial.zeroize();
    enable_raw_mode().context("re-enable raw mode")?;
    execute!(terminal.backend_mut(), EnterAlternateScreen).context("re-enter alternate screen")?;
    if app.config.mouse {
        execute!(terminal.backend_mut(), EnableMouseCapture).ok();
    }
    terminal.clear().ok();
    app.finish_external_edit(result);
    Ok(())
}

async fn wait_event(timeout: Duration) -> Result<Option<Event>> {
    let poll = tokio::task::spawn_blocking(move || -> io::Result<Option<Event>> {
        if crossterm::event::poll(timeout)? {
            Ok(Some(crossterm::event::read()?))
        } else {
            Ok(None)
        }
    })
    .await
    .context("event poll task join")?
    .context("poll terminal events")?;
    Ok(poll)
}

fn print_completions(shell: &str) -> Result<()> {
    let shell = shell.parse::<Shell>().map_err(|_| {
        anyhow::anyhow!("unknown shell `{shell}` (bash|zsh|fish|elvish|powershell)")
    })?;
    let mut cmd = Cli::command();
    let name = cmd.get_name().to_string();
    generate(shell, &mut cmd, name, &mut io::stdout());
    Ok(())
}

fn print_man() -> Result<()> {
    let cmd = Cli::command();
    let man = clap_mangen::Man::new(cmd);
    let mut buffer = Vec::new();
    man.render(&mut buffer)?;
    io::stdout().write_all(&buffer)?;
    Ok(())
}
