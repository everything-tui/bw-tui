//! Unit-test login field typing without a real TTY.

use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
use vault_tui::app::{App, LoginField, Overlay, ProfileManagerMode, Screen};
use vault_tui::events::handle_event;
use vault_tui::profiles::VaultProfile;

fn press(code: KeyCode) -> Event {
    Event::Key(KeyEvent::new(code, KeyModifiers::NONE))
}

fn mock_app() -> App {
    App::new(None, Some("http://127.0.0.1:8080".into()), None, true).unwrap()
}

async fn mock_login(app: &mut App) {
    for c in "a@b.c".chars() {
        handle_event(app, press(KeyCode::Char(c)), true, true).await;
    }
    handle_event(app, press(KeyCode::Tab), true, true).await;
    for c in "password".chars() {
        handle_event(app, press(KeyCode::Char(c)), true, true).await;
    }
    handle_event(app, press(KeyCode::Enter), true, true).await;
    app.run_pending().await;
}

#[tokio::test]
async fn types_into_email_password_and_server() {
    let mut app = mock_app();
    assert_eq!(app.screen, Screen::Login);
    assert_eq!(app.login_field, LoginField::Email);

    for c in "user@test.local".chars() {
        handle_event(&mut app, press(KeyCode::Char(c)), true, true).await;
    }
    assert_eq!(app.email, "user@test.local");

    handle_event(&mut app, press(KeyCode::Tab), true, true).await;
    assert_eq!(app.login_field, LoginField::Password);

    for c in "s3cret!".chars() {
        handle_event(&mut app, press(KeyCode::Char(c)), true, true).await;
    }
    assert_eq!(app.password, "s3cret!");

    // Password -> Remember -> Server, then append
    handle_event(&mut app, press(KeyCode::Tab), true, true).await;
    assert_eq!(app.login_field, LoginField::Remember);
    handle_event(&mut app, press(KeyCode::Tab), true, true).await;
    assert_eq!(app.login_field, LoginField::Server);
    let before = app.server_url.clone();
    handle_event(&mut app, press(KeyCode::Char('X')), true, true).await;
    assert_eq!(app.server_url, format!("{before}X"));
}

#[tokio::test]
async fn toggles_password_visibility_with_ctrl_h() {
    let mut app = mock_app();
    assert!(!app.show_password);

    let toggle = Event::Key(KeyEvent::new(KeyCode::Char('h'), KeyModifiers::CONTROL));
    handle_event(&mut app, toggle.clone(), true, true).await;
    assert!(app.show_password);
    handle_event(&mut app, toggle, true, true).await;
    assert!(!app.show_password);
}

#[tokio::test]
async fn toggles_remember_login_with_ctrl_r_and_checkbox() {
    let mut app = mock_app();
    assert!(!app.remember_login);

    let ctrl_r = Event::Key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL));
    handle_event(&mut app, ctrl_r, true, true).await;
    assert!(app.remember_login);

    // Tab to Remember field: Email -> Password -> Remember
    handle_event(&mut app, press(KeyCode::Tab), true, true).await; // Password
    handle_event(&mut app, press(KeyCode::Tab), true, true).await; // Remember
    assert_eq!(app.login_field, LoginField::Remember);
    handle_event(&mut app, press(KeyCode::Char(' ')), true, true).await;
    assert!(!app.remember_login);
}

#[tokio::test]
async fn mock_login_reaches_vault() {
    let mut app = mock_app();
    mock_login(&mut app).await;
    assert_eq!(app.screen, Screen::Vault);
    assert!(!app.items.is_empty());
}

#[tokio::test]
async fn ctrl_p_opens_profile_manager() {
    let mut app = mock_app();
    let ctrl_p = Event::Key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::CONTROL));
    handle_event(&mut app, ctrl_p, true, true).await;
    assert!(matches!(app.overlay, Overlay::ProfileManager { .. }));
}

#[tokio::test]
async fn mock_switch_back_keeps_vault_when_lock_on_switch_off() {
    let mut app = mock_app();
    assert!(!app.profiles.lock_on_profile_switch);
    mock_login(&mut app).await;
    assert_eq!(app.screen, Screen::Vault);
    let item_count = app.items.len();

    app.profiles.profiles.push(VaultProfile {
        id: "work".into(),
        name: "Work".into(),
        server_url: String::new(),
        email: String::new(),
        auto_lock_minutes: Some(15),
        allow_plaintext_token: false,
    });

    let default_id = app.active_profile_id.clone();
    app.switch_to_profile("work").await;
    assert_eq!(app.active_profile_id, "work");
    assert_eq!(app.screen, Screen::Login);
    assert!(app.profile_is_open(&default_id));

    app.switch_to_profile(&default_id).await;
    assert_eq!(app.screen, Screen::Vault);
    assert_eq!(app.items.len(), item_count);
}

#[tokio::test]
async fn mock_switch_away_does_not_restore_when_lock_on_switch_on() {
    let mut app = mock_app();
    app.profiles.lock_on_profile_switch = true;
    mock_login(&mut app).await;
    assert_eq!(app.screen, Screen::Vault);

    app.profiles.profiles.push(VaultProfile {
        id: "work".into(),
        name: "Work".into(),
        server_url: String::new(),
        email: String::new(),
        auto_lock_minutes: Some(15),
        allow_plaintext_token: false,
    });

    let default_id = app.active_profile_id.clone();
    app.switch_to_profile("work").await;
    assert!(!app.profile_is_open(&default_id));

    app.switch_to_profile(&default_id).await;
    assert_eq!(app.screen, Screen::Login);
    assert!(app.items.is_empty());
}

#[tokio::test]
async fn profile_edit_save_updates_fields() {
    let mut app = mock_app();
    app.open_profile_manager();
    handle_event(&mut app, press(KeyCode::Char('e')), true, true).await;
    assert!(matches!(
        app.overlay,
        Overlay::ProfileManager {
            mode: ProfileManagerMode::Edit { .. },
            ..
        }
    ));

    if let Overlay::ProfileManager {
        mode:
            ProfileManagerMode::Edit {
                name,
                server_url,
                email,
                auto_lock_input,
                ..
            },
        ..
    } = &mut app.overlay
    {
        *name = "Home".into();
        *server_url = "https://vw.example".into();
        *email = "u@ex.com".into();
        *auto_lock_input = "45".into();
    }
    app.profile_manager_edit_save();

    let p = app.profiles.get("default").unwrap();
    assert_eq!(p.name, "Home");
    assert_eq!(p.server_url, "https://vw.example");
    assert_eq!(p.email, "u@ex.com");
    assert_eq!(p.auto_lock_minutes, Some(45));
    assert_eq!(app.auto_lock_minutes, Some(45));
    assert_eq!(app.email, "u@ex.com");
}
