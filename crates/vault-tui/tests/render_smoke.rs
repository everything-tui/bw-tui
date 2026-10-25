//! Every theme × terminal size × main screen renders without panicking.

use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
use ratatui::{backend::TestBackend, Terminal};
use vault_tui::app::{App, FocusPane, Overlay, Screen};
use vault_tui::events::handle_event;
use vault_tui::ui::theme::{theme, THEME_NAMES};

async fn key(app: &mut App, code: KeyCode) {
    let mods = match code {
        KeyCode::Char(c) if c.is_ascii_uppercase() => KeyModifiers::SHIFT,
        _ => KeyModifiers::NONE,
    };
    handle_event(app, Event::Key(KeyEvent::new(code, mods)), true, true).await;
}

async fn ctrl(app: &mut App, c: char) {
    let ev = Event::Key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL));
    handle_event(app, ev, true, true).await;
}

/// The theme is process-global; tests in this file must not switch it concurrently.
static THEME_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn draw_all_sizes(app: &App) {
    for (w, h) in [(20, 6), (50, 15), (80, 24), (120, 40), (220, 60)] {
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| vault_tui::ui::draw(f, app)).unwrap();
    }
}

async fn mock_vault() -> App {
    let mut app = App::new(None, Some("http://127.0.0.1:8080".into()), None, true).unwrap();
    draw_all_sizes(&app);
    for c in "a@b.c".chars() {
        key(&mut app, KeyCode::Char(c)).await;
    }
    key(&mut app, KeyCode::Tab).await;
    for c in "pw".chars() {
        key(&mut app, KeyCode::Char(c)).await;
    }
    key(&mut app, KeyCode::Enter).await;
    app.run_pending().await;
    assert_eq!(app.screen, Screen::Vault);
    app.focus = FocusPane::Items;
    app
}

#[tokio::test]
async fn all_themes_render_all_screens_at_all_sizes() {
    let _guard = THEME_LOCK.lock().await;
    for name in THEME_NAMES {
        let mut app = mock_vault().await;
        app.apply_theme(name);
        assert_eq!(theme().name, *name);
        draw_all_sizes(&app);

        // Detail focus with secrets revealed.
        app.focus = FocusPane::Detail;
        app.reprompt_ok_for = app.selected_id();
        key(&mut app, KeyCode::Char('r')).await;
        draw_all_sizes(&app);
        app.focus = FocusPane::Items;

        // Overlays opened from the vault, each closed with Esc.
        for open in [':', '?', 'n', 'P', 'R', ','] {
            key(&mut app, KeyCode::Char(open)).await;
            draw_all_sizes(&app);
            key(&mut app, KeyCode::Esc).await;
        }
        key(&mut app, KeyCode::Char('d')).await;
        draw_all_sizes(&app);
        key(&mut app, KeyCode::Esc).await;
        key(&mut app, KeyCode::Char('g')).await;
        draw_all_sizes(&app);
        key(&mut app, KeyCode::Esc).await;

        // New login form + generator on top of it.
        key(&mut app, KeyCode::Char('n')).await;
        key(&mut app, KeyCode::Enter).await;
        draw_all_sizes(&app);
        ctrl(&mut app, 'g').await;
        draw_all_sizes(&app);
        key(&mut app, KeyCode::Esc).await;
        key(&mut app, KeyCode::Esc).await;

        // Search, Sends, Trash views.
        key(&mut app, KeyCode::Char('/')).await;
        key(&mut app, KeyCode::Char('x')).await;
        draw_all_sizes(&app);
        key(&mut app, KeyCode::Esc).await;
        for target in ['s', 't'] {
            key(&mut app, KeyCode::Char('g')).await;
            key(&mut app, KeyCode::Char(target)).await;
            draw_all_sizes(&app);
        }

        ctrl(&mut app, 't').await;
        draw_all_sizes(&app);
        key(&mut app, KeyCode::Esc).await;

        app.lock();
        draw_all_sizes(&app);
    }
    vault_tui::ui::init_theme("default", None);
}

#[tokio::test]
async fn theme_picker_previews_live_and_esc_reverts() {
    let _guard = THEME_LOCK.lock().await;
    let mut app = mock_vault().await;
    app.apply_theme("default");
    ctrl(&mut app, 't').await;
    assert!(matches!(app.overlay, Overlay::ThemePicker { .. }));
    key(&mut app, KeyCode::Char('j')).await;
    assert_eq!(theme().name, THEME_NAMES[1], "moving previews the theme");
    key(&mut app, KeyCode::Esc).await;
    assert!(matches!(app.overlay, Overlay::None));
    assert_eq!(theme().name, "default", "Esc restores the original");
}
