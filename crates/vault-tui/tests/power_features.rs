//! P4 power-user features driven through the mock vault.

use crossterm::event::{
    Event, KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use vault_tui::app::{App, FocusPane, Overlay, PowerOverlay, Screen, SortMode};
use vault_tui::events::handle_event;

fn press(code: KeyCode) -> Event {
    Event::Key(KeyEvent::new(code, KeyModifiers::NONE))
}

fn ctrl(c: char) -> Event {
    Event::Key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL))
}

async fn key(app: &mut App, code: KeyCode) {
    handle_event(app, press(code), true, true).await;
}

async fn mock_vault() -> App {
    let mut app = App::new(None, Some("http://127.0.0.1:8080".into()), None, true).unwrap();
    for c in "a@b.c".chars() {
        key(&mut app, KeyCode::Char(c)).await;
    }
    key(&mut app, KeyCode::Tab).await;
    for c in "password".chars() {
        key(&mut app, KeyCode::Char(c)).await;
    }
    key(&mut app, KeyCode::Enter).await;
    app.run_pending().await;
    assert_eq!(app.screen, Screen::Vault);
    app.focus = FocusPane::Items;
    app
}

#[tokio::test]
async fn sort_cycle_updates_mode_and_toasts() {
    let mut app = mock_vault().await;
    assert_eq!(app.power.sort, SortMode::Name);
    key(&mut app, KeyCode::Char('s')).await;
    assert_eq!(app.power.sort, SortMode::Recent);
    key(&mut app, KeyCode::Char('s')).await;
    assert_eq!(app.power.sort, SortMode::Modified);
    key(&mut app, KeyCode::Char('s')).await;
    assert_eq!(app.power.sort, SortMode::Name);
    assert!(
        !app.power.toasts.is_empty(),
        "status messages mirror into toasts"
    );
}

#[tokio::test]
async fn recently_used_sorts_last_copied_first() {
    let mut app = mock_vault().await;
    assert!(app.visible.len() >= 2);
    let last = *app.visible.last().unwrap();
    let last_id = app.items[last].id.clone();
    app.record_item_used(&last_id);
    key(&mut app, KeyCode::Char('s')).await; // Recent
    assert_eq!(app.items[app.visible[0]].id, last_id);
}

#[tokio::test]
async fn qr_overlay_opens_cycles_and_closes() {
    let mut app = mock_vault().await;
    // First mock item is a login with password; ensure no reprompt gate in the way.
    app.reprompt_ok_for = app.selected_id();
    key(&mut app, KeyCode::Char('Q')).await;
    let Overlay::Power(PowerOverlay::Qr { entries, lines, .. }) = &app.overlay else {
        panic!("expected QR overlay, got {:?}", app.overlay);
    };
    assert!(!entries.is_empty());
    assert!(!lines.is_empty());
    let multi = entries.len() > 1;
    if multi {
        key(&mut app, KeyCode::Tab).await;
        let Overlay::Power(PowerOverlay::Qr { index, .. }) = &app.overlay else {
            panic!("overlay changed");
        };
        assert_eq!(*index, 1);
    }
    key(&mut app, KeyCode::Esc).await;
    assert!(matches!(app.overlay, Overlay::None));
}

#[tokio::test]
async fn copy_sequence_walks_username_then_password() {
    let mut app = mock_vault().await;
    app.reprompt_ok_for = app.selected_id();
    key(&mut app, KeyCode::Char('S')).await;
    assert!(app.status.contains("Sequence 1/"), "status: {}", app.status);
    assert!(app.power.copy_seq.is_some());
    key(&mut app, KeyCode::Char('S')).await;
    assert!(app.status.contains("Sequence 2/"), "status: {}", app.status);
}

#[tokio::test]
async fn ctrl_e_in_note_form_requests_editor() {
    let mut app = mock_vault().await;
    app.open_new_note();
    assert!(matches!(app.overlay, Overlay::NoteForm { .. }));
    if let Overlay::NoteForm { notes, .. } = &mut app.overlay {
        notes.push_str("hello");
    }
    handle_event(&mut app, ctrl('e'), true, true).await;
    assert_eq!(
        app.power
            .pending_editor
            .as_ref()
            .map(|r| r.initial.as_str()),
        Some("hello")
    );
    app.power.pending_editor = None;
    app.finish_external_edit(Ok(Some("edited body".into())));
    let Overlay::NoteForm { notes, .. } = &app.overlay else {
        panic!("form closed");
    };
    assert_eq!(notes, "edited body");
}

#[tokio::test]
async fn ctrl_g_generates_ed25519_with_replace_guard() {
    let mut app = mock_vault().await;
    app.open_new_ssh_key();
    handle_event(&mut app, ctrl('g'), true, true).await;
    let (private, public, fp) = match &app.overlay {
        Overlay::SshKeyForm {
            private_key,
            public_key,
            fingerprint,
            ..
        } => (private_key.clone(), public_key.clone(), fingerprint.clone()),
        other => panic!("unexpected overlay {other:?}"),
    };
    assert!(private.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
    assert!(public.starts_with("ssh-ed25519 "));
    assert!(fp.starts_with("SHA256:"));

    // Existing key: first Ctrl+g only arms, second replaces.
    handle_event(&mut app, ctrl('g'), true, true).await;
    if let Overlay::SshKeyForm { private_key, .. } = &app.overlay {
        assert_eq!(*private_key, private, "first press must not replace");
    }
    handle_event(&mut app, ctrl('g'), true, true).await;
    if let Overlay::SshKeyForm { private_key, .. } = &app.overlay {
        assert_ne!(*private_key, private, "second press replaces");
    }
}

#[tokio::test]
async fn domain_rules_overlay_adds_group() {
    let mut app = mock_vault().await;
    key(&mut app, KeyCode::Char('D')).await;
    assert!(matches!(
        app.overlay,
        Overlay::Power(PowerOverlay::DomainRules { .. })
    ));
    key(&mut app, KeyCode::Char('a')).await;
    for c in "foo.com, bar.net".chars() {
        key(&mut app, KeyCode::Char(c)).await;
    }
    key(&mut app, KeyCode::Enter).await;
    let Overlay::Power(PowerOverlay::DomainRules { rules, dirty, .. }) = &app.overlay else {
        panic!("overlay closed");
    };
    assert!(*dirty);
    assert!(rules
        .custom_groups
        .iter()
        .any(|g| g == &vec!["foo.com".to_string(), "bar.net".to_string()]));
}

#[tokio::test]
async fn watchtower_badge_appears_after_tick() {
    let mut app = mock_vault().await;
    app.power_on_tick();
    assert!(app.watchtower_badge().is_some());
}

#[tokio::test]
async fn mouse_click_selects_item_and_wheel_scrolls() {
    let mut app = mock_vault().await;
    app.config.mouse = true;
    app.power.view_size.set((120, 40));
    assert!(app.visible.len() >= 3);

    // Layout at 120x40: folders 22 cols, items next. Click inside the items pane, 3rd data row
    // (top border + header + two rows).
    let click = MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column: 30,
        row: 4,
        modifiers: KeyModifiers::NONE,
    };
    handle_event(&mut app, Event::Mouse(click), true, true).await;
    assert_eq!(app.focus, FocusPane::Items);
    assert_eq!(app.selected_item, 2);

    let wheel = MouseEvent {
        kind: MouseEventKind::ScrollUp,
        column: 30,
        row: 4,
        modifiers: KeyModifiers::NONE,
    };
    handle_event(&mut app, Event::Mouse(wheel), true, true).await;
    assert_eq!(app.selected_item, 1);

    // Disabled config ignores the mouse entirely.
    app.config.mouse = false;
    handle_event(&mut app, Event::Mouse(click), true, true).await;
    assert_eq!(app.selected_item, 1);
}

#[tokio::test]
async fn ssh_agent_confirmation_prompt_returns_to_previous_overlay() {
    use vault_tui::app::ssh_confirm_overlay;
    let mut app = mock_vault().await;
    app.overlay = ssh_confirm_overlay(
        Overlay::AccountSettings {
            section: 0,
            status: String::new(),
        },
        vec!["deploy key".into()],
        false,
    );
    key(&mut app, KeyCode::Esc).await;
    assert!(matches!(app.overlay, Overlay::AccountSettings { .. }));
}
