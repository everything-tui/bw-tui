//! Unit-test login field typing without a real TTY.

use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
use vault_tui::app::{App, LoginField, Screen};
use vault_tui::events::handle_event;

fn press(code: KeyCode) -> Event {
    Event::Key(KeyEvent::new(code, KeyModifiers::NONE))
}

#[tokio::test]
async fn types_into_email_password_and_server() {
    let mut app = App::new(Some("http://127.0.0.1:8080".into()), None, true);
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
    let mut app = App::new(Some("http://127.0.0.1:8080".into()), None, true);
    assert!(!app.show_password);

    let toggle = Event::Key(KeyEvent::new(KeyCode::Char('h'), KeyModifiers::CONTROL));
    handle_event(&mut app, toggle.clone(), true, true).await;
    assert!(app.show_password);
    handle_event(&mut app, toggle, true, true).await;
    assert!(!app.show_password);
}

#[tokio::test]
async fn toggles_remember_login_with_ctrl_r_and_checkbox() {
    let mut app = App::new(Some("http://127.0.0.1:8080".into()), None, true);
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
    let mut app = App::new(Some("http://127.0.0.1:8080".into()), None, true);
    for c in "a@b.c".chars() {
        handle_event(&mut app, press(KeyCode::Char(c)), true, true).await;
    }
    handle_event(&mut app, press(KeyCode::Tab), true, true).await;
    for c in "password".chars() {
        handle_event(&mut app, press(KeyCode::Char(c)), true, true).await;
    }
    handle_event(&mut app, press(KeyCode::Enter), true, true).await;
    assert!(app.pending.is_some());
    app.run_pending().await;
    assert_eq!(app.screen, Screen::Vault);
    assert!(!app.items.is_empty());
}
