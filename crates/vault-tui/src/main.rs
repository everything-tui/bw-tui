//! bitwarden-tui — Vaultwarden password manager terminal UI.

use std::io::{self, stdout, IsTerminal};
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
use vault_tui::app::{self, App};
use vault_tui::debug_log;
use vault_tui::ui::{self, PaneVisibility};
use vault_tui::events;

#[derive(Debug, Parser)]
#[command(
    name = "bitwarden-tui",
    about = "Terminal UI client for Vaultwarden / Bitwarden",
    version
)]
struct Cli {
    /// Vaultwarden / Bitwarden server URL
    #[arg(long, env = "BW_SERVER")]
    server: Option<String>,

    /// Account email
    #[arg(long, env = "BW_EMAIL")]
    email: Option<String>,

    /// Use in-memory mock vault (no network) for UI testing
    #[arg(long)]
    mock: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("vault_tui=info".parse()?))
        .with_writer(io::stderr)
        .init();

    let cli = Cli::parse();
    let mut app = App::new(cli.server, cli.email, cli.mock);
    app.restore_session_if_saved().await;

    // #region agent log
    debug_log::log(
        "C",
        "main.rs:main",
        "app_start",
        serde_json::json!({
            "mock": cli.mock,
            "screen": format!("{:?}", app.screen),
            "login_field": format!("{:?}", app.login_field),
            "server_len": app.server_url.len(),
            "email_len": app.email.len(),
            "stdin_is_tty": io::stdin().is_terminal(),
            "stdout_is_tty": io::stdout().is_terminal(),
        }),
    );
    // #endregion

    let mut terminal = setup_terminal()?;
    let result = run_loop(&mut terminal, &mut app).await;
    restore_terminal(&mut terminal)?;
    result
}

fn setup_terminal() -> Result<Terminal<CrosstermBackend<io::Stdout>>> {
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
                // #region agent log
                debug_log::log(
                    "A",
                    "main.rs:run_loop",
                    "key_event_raw",
                    serde_json::json!({
                        "kind": format!("{:?}", key.kind),
                        "code": format!("{:?}", key.code),
                        "modifiers": format!("{:?}", key.modifiers),
                        "screen": format!("{:?}", app.screen),
                        "login_field": format!("{:?}", app.login_field),
                        "show_help": app.show_help,
                        "overlay_none": matches!(app.overlay, app::Overlay::None),
                    }),
                );
                // #endregion
                // Accept Press + Repeat. Also accept Release for printable chars only
                // (some IDE terminals emit Release without Press).
                let accept = match key.kind {
                    KeyEventKind::Press | KeyEventKind::Repeat => true,
                    KeyEventKind::Release => matches!(key.code, crossterm::event::KeyCode::Char(_)),
                };
                if !accept {
                    // #region agent log
                    debug_log::log(
                        "A",
                        "main.rs:run_loop",
                        "key_event_filtered_out",
                        serde_json::json!({
                            "kind": format!("{:?}", key.kind),
                            "code": format!("{:?}", key.code),
                        }),
                    );
                    // #endregion
                    continue;
                }
            } else {
                // #region agent log
                debug_log::log(
                    "C",
                    "main.rs:run_loop",
                    "non_key_event",
                    serde_json::json!({ "event": format!("{event:?}") }),
                );
                // #endregion
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
