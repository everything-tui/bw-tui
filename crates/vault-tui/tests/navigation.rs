//! Vault-browser navigation and keymap dispatch, driven through the mock vault.

use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
use vault_tui::app::{App, ClipboardKind, FocusPane, Overlay, Screen};
use vault_tui::events::handle_event;
use vault_tui::models::{FilterKind, ItemType};

fn press(code: KeyCode) -> Event {
    let mods = match code {
        KeyCode::Char(c) if c.is_ascii_uppercase() => KeyModifiers::SHIFT,
        _ => KeyModifiers::NONE,
    };
    Event::Key(KeyEvent::new(code, mods))
}

async fn key(app: &mut App, code: KeyCode) {
    handle_event(app, press(code), true, true).await;
}

async fn ctrl(app: &mut App, c: char) {
    handle_event(
        app,
        Event::Key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)),
        true,
        true,
    )
    .await;
}

async fn chars(app: &mut App, s: &str) {
    for c in s.chars() {
        key(app, KeyCode::Char(c)).await;
    }
}

async fn mock_vault() -> App {
    let mut app = App::new(None, Some("http://127.0.0.1:8080".into()), None, true).unwrap();
    chars(&mut app, "a@b.c").await;
    key(&mut app, KeyCode::Tab).await;
    chars(&mut app, "password").await;
    key(&mut app, KeyCode::Enter).await;
    app.run_pending().await;
    assert_eq!(app.screen, Screen::Vault);
    app.focus = FocusPane::Items;
    app
}

#[tokio::test]
async fn goto_prefix_jumps_to_filters() {
    let mut app = mock_vault().await;
    key(&mut app, KeyCode::Char('g')).await;
    assert!(app.pending_goto, "g arms the go-to popup");
    key(&mut app, KeyCode::Char('t')).await;
    assert!(!app.pending_goto);
    assert_eq!(app.current_filter(), FilterKind::Trash);

    chars(&mut app, "gf").await;
    assert_eq!(app.current_filter(), FilterKind::Favorites);

    chars(&mut app, "gs").await;
    assert_eq!(app.current_filter(), FilterKind::Sends);

    // Unknown second key cancels without side effects.
    chars(&mut app, "gz").await;
    assert!(!app.pending_goto);
    assert_eq!(app.current_filter(), FilterKind::Sends);
}

#[tokio::test]
async fn gg_and_shift_g_jump_to_edges() {
    let mut app = mock_vault().await;
    assert!(app.visible.len() > 2);
    key(&mut app, KeyCode::Char('G')).await;
    assert_eq!(app.selected_item, app.visible.len() - 1);
    chars(&mut app, "gg").await;
    assert_eq!(app.selected_item, 0);
}

#[tokio::test]
async fn enter_drills_in_and_esc_backs_out() {
    let mut app = mock_vault().await;
    app.focus = FocusPane::Folders;
    key(&mut app, KeyCode::Enter).await;
    assert_eq!(app.focus, FocusPane::Items);
    key(&mut app, KeyCode::Enter).await;
    assert_eq!(app.focus, FocusPane::Detail);
    key(&mut app, KeyCode::Esc).await;
    assert_eq!(app.focus, FocusPane::Items);
    key(&mut app, KeyCode::Enter).await;
    key(&mut app, KeyCode::Enter).await;
    // The mock has no session, so the edit is refused — but it was attempted.
    assert!(
        matches!(app.overlay, Overlay::ItemForm { .. }) || app.status.contains("Cannot edit"),
        "Enter in the detail pane edits (status: {})",
        app.status
    );
}

#[tokio::test]
async fn jk_scroll_detail_instead_of_moving_selection() {
    let mut app = mock_vault().await;
    app.focus = FocusPane::Detail;
    app.detail_scroll_max.set(5);
    let before = app.selected_item;
    key(&mut app, KeyCode::Char('j')).await;
    key(&mut app, KeyCode::Char('j')).await;
    assert_eq!(app.selected_item, before);
    assert_eq!(app.detail_scroll_offset(), 2);
    // A different selection starts back at the top.
    app.focus = FocusPane::Items;
    key(&mut app, KeyCode::Char('j')).await;
    assert_eq!(app.detail_scroll_offset(), 0);
}

#[tokio::test]
async fn card_copy_keys_work_from_item_list() {
    let mut app = mock_vault().await;
    let card = app
        .visible
        .iter()
        .position(|&i| app.items[i].item_type == ItemType::Card)
        .expect("mock vault has a card");
    app.selected_item = card;
    app.reprompt_ok_for = app.selected_id();
    assert_eq!(app.focus, FocusPane::Items);
    key(&mut app, KeyCode::Char('m')).await;
    assert_eq!(app.clipboard_kind, Some(ClipboardKind::CardNumber));
}

#[tokio::test]
async fn shift_c_clones_while_c_copies() {
    let mut app = mock_vault().await;
    app.reprompt_ok_for = app.selected_id();
    key(&mut app, KeyCode::Char('c')).await;
    assert_eq!(app.clipboard_kind, Some(ClipboardKind::Password));
    assert!(app.pending.is_none());
    key(&mut app, KeyCode::Char('C')).await;
    assert!(app.pending.is_some(), "Shift+C queues a clone");
}

#[tokio::test]
async fn esc_clears_search_then_marks() {
    let mut app = mock_vault().await;
    key(&mut app, KeyCode::Char('/')).await;
    chars(&mut app, "git").await;
    key(&mut app, KeyCode::Enter).await;
    assert!(!app.searching);
    assert_eq!(app.search_query, "git");
    key(&mut app, KeyCode::Char(' ')).await;
    assert_eq!(app.selected_ids.len(), 1);
    key(&mut app, KeyCode::Esc).await;
    assert!(app.search_query.is_empty());
    assert_eq!(app.selected_ids.len(), 1);
    key(&mut app, KeyCode::Esc).await;
    assert!(app.selected_ids.is_empty());
}

#[tokio::test]
async fn search_ctrl_n_moves_results_without_typing() {
    let mut app = mock_vault().await;
    key(&mut app, KeyCode::Char('/')).await;
    ctrl(&mut app, 'n').await;
    assert!(app.searching);
    assert!(app.search_query.is_empty());
    assert_eq!(app.selected_item, 1);
    ctrl(&mut app, 'p').await;
    assert_eq!(app.selected_item, 0);
    assert!(
        !matches!(app.overlay, Overlay::ProfileManager { .. }),
        "Ctrl+p navigates while searching"
    );
}

#[tokio::test]
async fn palette_runs_commands_directly() {
    let mut app = mock_vault().await;
    let id = app.selected_id().unwrap();
    let fav = |app: &App| app.items.iter().find(|i| i.id == id).unwrap().favorite;
    let was_fav = fav(&app);
    key(&mut app, KeyCode::Char(':')).await;
    chars(&mut app, "toggle favorite").await;
    let first = app.palette_filtered_actions()[0];
    assert_eq!(first, vault_tui::action::Action::ToggleFavorite);
    key(&mut app, KeyCode::Enter).await;
    assert!(matches!(app.overlay, Overlay::None));
    assert_ne!(fav(&app), was_fav);
}

#[tokio::test]
async fn palette_hides_navigation_primitives() {
    let mut app = mock_vault().await;
    key(&mut app, KeyCode::Char(':')).await;
    let actions = app.palette_filtered_actions();
    assert!(!actions.contains(&vault_tui::action::Action::MoveDown));
    assert!(actions.contains(&vault_tui::action::Action::GotoTrash));
    assert!(actions.contains(&vault_tui::action::Action::ReceiveSend));
}

#[tokio::test]
async fn generator_moved_to_shift_p() {
    let mut app = mock_vault().await;
    key(&mut app, KeyCode::Char('P')).await;
    assert!(matches!(app.overlay, Overlay::Generator { .. }));
}

#[tokio::test]
async fn q_needs_a_second_press_on_a_live_vault() {
    let mut app = mock_vault().await;
    app.using_mock = false;
    key(&mut app, KeyCode::Char('q')).await;
    assert!(!app.should_quit);
    assert!(app.quit_armed);
    // Another key disarms.
    key(&mut app, KeyCode::Char('j')).await;
    assert!(!app.quit_armed);
    key(&mut app, KeyCode::Char('q')).await;
    key(&mut app, KeyCode::Char('q')).await;
    assert!(app.should_quit);
}

#[tokio::test]
async fn r_reveals_outside_trash() {
    let mut app = mock_vault().await;
    app.reprompt_ok_for = app.selected_id();
    assert!(!app.reveal_secrets);
    key(&mut app, KeyCode::Char('r')).await;
    assert!(app.reveal_secrets);
}

#[tokio::test]
async fn new_login_form_generates_password_with_ctrl_g() {
    let mut app = mock_vault().await;
    key(&mut app, KeyCode::Char('n')).await;
    assert!(matches!(app.overlay, Overlay::NewItemType { .. }));
    key(&mut app, KeyCode::Enter).await; // Login
    assert!(matches!(app.overlay, Overlay::ItemForm { .. }));
    chars(&mut app, "Example").await;

    ctrl(&mut app, 'g').await;
    let Overlay::Generator {
        preview,
        insert_to_form,
        ..
    } = &app.overlay
    else {
        panic!("Ctrl+g opens the generator");
    };
    assert!(*insert_to_form);
    let generated = preview.clone();
    assert!(!generated.is_empty());

    key(&mut app, KeyCode::Enter).await;
    let Overlay::ItemForm { name, password, .. } = &app.overlay else {
        panic!("Enter returns to the form");
    };
    assert_eq!(name, "Example", "form contents survive the round trip");
    assert_eq!(password, &generated);
}

#[tokio::test]
async fn esc_in_generator_returns_to_form_unchanged() {
    let mut app = mock_vault().await;
    key(&mut app, KeyCode::Char('n')).await;
    key(&mut app, KeyCode::Enter).await;
    chars(&mut app, "Example").await;
    ctrl(&mut app, 'g').await;
    key(&mut app, KeyCode::Esc).await;
    let Overlay::ItemForm { name, password, .. } = &app.overlay else {
        panic!("Esc returns to the form");
    };
    assert_eq!(name, "Example");
    assert!(password.is_empty());
}
