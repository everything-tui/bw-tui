//! bitwarden-tui — Vaultwarden password manager terminal UI.

use std::io::{self, stdout, Write};
use std::panic;
use std::process::ExitCode;
use std::sync::{Once, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use crossterm::event::{DisableMouseCapture, Event, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use tracing_subscriber::EnvFilter;
use vault_session::app_data_dir;
use vault_tui::app::{self, App};
use vault_tui::events;
use vault_tui::profiles::{load_registry_from, profile_has_auth};
use vault_tui::ui::{self, PaneVisibility};

#[derive(Debug, clap::Subcommand)]
enum Commands {
    /// Print session status for a profile
    Status,
    /// Unlock and list vault items (id, type, name)
    List,
    /// Unlock and print one field from an item (by id or name)
    Get {
        /// Item id or exact name
        query: String,
        /// Field to print
        #[arg(long, default_value = "password")]
        field: String,
    },
    /// Unlock and sync the vault
    Sync,
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
        let ctx = vault_tui::cli::CliCtx::load(app_data_dir(), cli.profile.clone())?;
        match cmd {
            Commands::Status => vault_tui::cli::cmd_status(&ctx).await?,
            Commands::List => vault_tui::cli::cmd_list(&ctx).await?,
            Commands::Get { query, field } => vault_tui::cli::cmd_get(&ctx, query, field).await?,
            Commands::Sync => vault_tui::cli::cmd_sync(&ctx).await?,
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

    let mut terminal = setup_terminal()?;
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

fn setup_terminal() -> Result<Terminal<CrosstermBackend<io::Stdout>>> {
    install_panic_hook();
    enable_raw_mode().context("enable raw mode")?;
    let mut out = stdout();
    // Do NOT enable mouse capture — it breaks keyboard input in some IDE terminals.
    execute!(out, EnterAlternateScreen).context("enter alternate screen")?;
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

        let maybe = wait_event(poll_timeout).await?;
        app.on_tick();

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
