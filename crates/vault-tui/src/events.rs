//! Keyboard / terminal event handling.

use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};

use crate::app::{
    App, ClipboardKind, EditField, FocusPane, LoginField, Overlay, PendingAction, ProfileEditField,
    ProfileManagerMode, Screen,
};
use crate::debug_log;
use crate::profiles::format_auto_lock_input;

/// True for printable typing (letters, digits, punctuation), including Shift.
/// Rejects Control/Alt/Super chords used as shortcuts.
fn is_typing(key: &KeyEvent) -> bool {
    !key.modifiers
        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT | KeyModifiers::SUPER)
}

/// Handle a crossterm event. Returns `true` if the app should quit.
pub async fn handle_event(
    app: &mut App,
    event: Event,
    detail_visible: bool,
    folders_visible: bool,
) -> bool {
    match event {
        Event::Key(key) => handle_key(app, key, detail_visible, folders_visible).await,
        Event::Resize(_, _) => {
            if !detail_visible && app.focus == FocusPane::Detail {
                app.focus = FocusPane::Items;
            }
            if !folders_visible && app.focus == FocusPane::Folders {
                app.focus = FocusPane::Items;
            }
            false
        }
        _ => false,
    }
}

async fn handle_key(
    app: &mut App,
    key: KeyEvent,
    detail_visible: bool,
    folders_visible: bool,
) -> bool {
    // #region agent log
    debug_log::log(
        "D",
        "events.rs:handle_key",
        "handle_key_enter",
        serde_json::json!({
            "screen": format!("{:?}", app.screen),
            "show_help": app.show_help,
            "overlay_none": matches!(app.overlay, Overlay::None),
            "is_typing": is_typing(&key),
            "code": format!("{:?}", key.code),
            "modifiers": format!("{:?}", key.modifiers),
        }),
    );
    // #endregion

    if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
        app.should_quit = true;
        return true;
    }

    if app.show_help {
        // #region agent log
        debug_log::log(
            "D",
            "events.rs:handle_key",
            "swallowed_by_help",
            serde_json::json!({ "code": format!("{:?}", key.code) }),
        );
        // #endregion
        match key.code {
            KeyCode::Esc | KeyCode::Char('?') | KeyCode::Char('q') | KeyCode::Enter => {
                app.show_help = false;
            }
            _ => {}
        }
        return false;
    }

    if key.code == KeyCode::Char('p')
        && key.modifiers.contains(KeyModifiers::CONTROL)
        && matches!(app.overlay, Overlay::None)
    {
        app.open_profile_manager();
        return false;
    }

    if !matches!(app.overlay, Overlay::None) {
        // #region agent log
        debug_log::log(
            "D",
            "events.rs:handle_key",
            "routed_to_overlay",
            serde_json::json!({ "code": format!("{:?}", key.code) }),
        );
        // #endregion
        return handle_overlay(app, key).await;
    }

    match app.screen {
        Screen::Login => handle_login(app, key).await,
        Screen::TwoFactor => handle_2fa(app, key).await,
        Screen::Unlock => handle_unlock(app, key).await,
        Screen::Vault => handle_vault(app, key, detail_visible, folders_visible).await,
    }
}

fn push_char(buf: &mut String, c: char) {
    // Ignore control characters that sometimes arrive as Char('\n') etc.
    if !c.is_control() {
        buf.push(c);
    }
}

async fn handle_login(app: &mut App, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Esc => {
            app.should_quit = true;
            true
        }
        KeyCode::Char('h') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.show_password = !app.show_password;
            false
        }
        KeyCode::Char('r') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.remember_login = !app.remember_login;
            false
        }
        KeyCode::Char('?')
            if is_typing(&key)
                && app.login_field != LoginField::Password
                && app.login_field != LoginField::Remember =>
        {
            app.show_help = true;
            false
        }
        KeyCode::Tab | KeyCode::Down => {
            app.login_field = match app.login_field {
                LoginField::Server => LoginField::Email,
                LoginField::Email => LoginField::Password,
                LoginField::Password => LoginField::Remember,
                LoginField::Remember => LoginField::Server,
            };
            false
        }
        KeyCode::BackTab | KeyCode::Up => {
            app.login_field = match app.login_field {
                LoginField::Server => LoginField::Remember,
                LoginField::Email => LoginField::Server,
                LoginField::Password => LoginField::Email,
                LoginField::Remember => LoginField::Password,
            };
            false
        }
        KeyCode::Char(' ') if is_typing(&key) && app.login_field == LoginField::Remember => {
            app.remember_login = !app.remember_login;
            false
        }
        KeyCode::Enter if app.login_field == LoginField::Remember => {
            app.remember_login = !app.remember_login;
            false
        }
        KeyCode::Enter => {
            if app.login_field == LoginField::Password {
                app.queue(PendingAction::Login);
            } else {
                app.login_field = match app.login_field {
                    LoginField::Server => LoginField::Email,
                    LoginField::Email => LoginField::Password,
                    LoginField::Password => LoginField::Remember,
                    LoginField::Remember => LoginField::Server,
                };
            }
            false
        }
        KeyCode::Backspace | KeyCode::Delete => {
            match app.login_field {
                LoginField::Server => {
                    app.server_url.pop();
                }
                LoginField::Email => {
                    app.email.pop();
                }
                LoginField::Password => {
                    app.password.pop();
                }
                LoginField::Remember => {}
            }
            app.form_error = None;
            false
        }
        KeyCode::Char(c) if is_typing(&key) && app.login_field != LoginField::Remember => {
            match app.login_field {
                LoginField::Server => push_char(&mut app.server_url, c),
                LoginField::Email => push_char(&mut app.email, c),
                LoginField::Password => push_char(&mut app.password, c),
                LoginField::Remember => {}
            }
            app.form_error = None;
            // #region agent log
            debug_log::log(
                "B",
                "events.rs:handle_login",
                "char_accepted",
                serde_json::json!({
                    "field": format!("{:?}", app.login_field),
                    "char": c.to_string(),
                    "server_len": app.server_url.len(),
                    "email_len": app.email.len(),
                    "password_len": app.password.len(),
                }),
            );
            // #endregion
            false
        }
        KeyCode::Char(c) => {
            // #region agent log
            debug_log::log(
                "B",
                "events.rs:handle_login",
                "char_rejected_by_is_typing",
                serde_json::json!({
                    "char": c.to_string(),
                    "modifiers": format!("{:?}", key.modifiers),
                    "field": format!("{:?}", app.login_field),
                }),
            );
            // #endregion
            false
        }
        other => {
            // #region agent log
            debug_log::log(
                "E",
                "events.rs:handle_login",
                "unhandled_login_key",
                serde_json::json!({
                    "code": format!("{other:?}"),
                    "modifiers": format!("{:?}", key.modifiers),
                    "field": format!("{:?}", app.login_field),
                }),
            );
            // #endregion
            false
        }
    }
}

async fn handle_2fa(app: &mut App, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Esc => {
            app.screen = Screen::Login;
            app.totp_code.clear();
            app.form_error = None;
            app.set_status("Cancelled 2FA");
            false
        }
        KeyCode::Enter => {
            app.queue(PendingAction::TwoFactor);
            false
        }
        KeyCode::Backspace | KeyCode::Delete => {
            app.totp_code.pop();
            app.form_error = None;
            false
        }
        KeyCode::Char(c) if is_typing(&key) => {
            if c.is_ascii_alphanumeric() || c == '-' {
                push_char(&mut app.totp_code, c);
                app.form_error = None;
            }
            false
        }
        _ => false,
    }
}

async fn handle_unlock(app: &mut App, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Esc => {
            app.should_quit = true;
            true
        }
        KeyCode::Char('h') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.show_password = !app.show_password;
            false
        }
        KeyCode::Char('o') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.sign_out_current_profile();
            false
        }
        KeyCode::Char('?') if is_typing(&key) => {
            app.show_help = true;
            false
        }
        KeyCode::Enter => {
            app.queue(PendingAction::Unlock);
            false
        }
        KeyCode::Backspace | KeyCode::Delete => {
            app.unlock_password.pop();
            app.form_error = None;
            false
        }
        KeyCode::Char(c) if is_typing(&key) => {
            push_char(&mut app.unlock_password, c);
            app.form_error = None;
            false
        }
        _ => false,
    }
}

async fn handle_vault(
    app: &mut App,
    key: KeyEvent,
    detail_visible: bool,
    folders_visible: bool,
) -> bool {
    if app.searching {
        return handle_search(app, key);
    }

    if key.modifiers.contains(KeyModifiers::CONTROL) {
        match key.code {
            KeyCode::Char('s') => {
                if !app.busy {
                    app.sync_vault().await;
                }
                return false;
            }
            KeyCode::Char('l') => {
                app.lock();
                return false;
            }
            KeyCode::Char('n') => {
                app.open_folder_form();
                return false;
            }
            _ => {}
        }
    }

    match key.code {
        KeyCode::Char('q') if is_typing(&key) => {
            app.should_quit = true;
            return true;
        }
        KeyCode::Char('?') if is_typing(&key) => {
            app.show_help = true;
        }
        KeyCode::Tab => {
            app.focus_next(detail_visible, folders_visible);
        }
        KeyCode::BackTab => {
            app.focus_prev(detail_visible, folders_visible);
        }
        KeyCode::Char('h') | KeyCode::Left if is_typing(&key) || key.code == KeyCode::Left => {
            app.focus_left(folders_visible);
        }
        KeyCode::Char('l') | KeyCode::Right if is_typing(&key) || key.code == KeyCode::Right => {
            app.focus_right(detail_visible);
        }
        KeyCode::Char('j') | KeyCode::Down if is_typing(&key) || key.code == KeyCode::Down => {
            app.move_selection(1);
        }
        KeyCode::Char('k') | KeyCode::Up if is_typing(&key) || key.code == KeyCode::Up => {
            app.move_selection(-1);
        }
        KeyCode::Char('/') if is_typing(&key) => {
            app.start_search();
        }
        KeyCode::Esc => {
            if !app.search_query.is_empty() {
                app.clear_search();
            }
        }
        KeyCode::Char('n') if is_typing(&key) => {
            app.open_new_login();
        }
        KeyCode::Char('e') if is_typing(&key) => {
            app.open_edit_login();
        }
        KeyCode::Enter => {
            app.open_edit_login();
        }
        KeyCode::Char('d') if is_typing(&key) => {
            app.open_delete_confirm();
        }
        KeyCode::Char('f') if is_typing(&key) => {
            if !app.busy {
                app.toggle_favorite().await;
            }
        }
        KeyCode::Char('g') if is_typing(&key) => {
            app.open_generator(false);
        }
        KeyCode::Char('c') if is_typing(&key) => {
            app.copy_field(ClipboardKind::Password);
        }
        KeyCode::Char('y') if is_typing(&key) => {
            app.copy_field(ClipboardKind::Username);
        }
        KeyCode::Char('t') if is_typing(&key) => {
            app.copy_field(ClipboardKind::Totp);
        }
        KeyCode::Char('u') if is_typing(&key) => {
            app.copy_field(ClipboardKind::Uri);
        }
        KeyCode::Home => {
            match app.focus {
                FocusPane::Folders => {
                    app.selected_sidebar = 0;
                    app.selected_item = 0;
                    app.recompute_visible();
                }
                FocusPane::Items | FocusPane::Detail => {
                    app.selected_item = 0;
                }
            }
            app.touch();
        }
        KeyCode::End => {
            match app.focus {
                FocusPane::Folders => {
                    app.selected_sidebar = app.sidebar.len().saturating_sub(1);
                    app.selected_item = 0;
                    app.recompute_visible();
                }
                FocusPane::Items | FocusPane::Detail => {
                    app.selected_item = app.visible.len().saturating_sub(1);
                }
            }
            app.touch();
        }
        KeyCode::PageDown => {
            app.move_selection(10);
        }
        KeyCode::PageUp => {
            app.move_selection(-10);
        }
        _ => {}
    }
    false
}

fn handle_search(app: &mut App, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Esc => {
            app.clear_search();
        }
        KeyCode::Enter => {
            app.end_search();
        }
        KeyCode::Backspace | KeyCode::Delete => {
            app.search_query.pop();
            app.recompute_visible();
            app.touch();
        }
        KeyCode::Char(c) if is_typing(&key) => {
            push_char(&mut app.search_query, c);
            app.recompute_visible();
            app.touch();
        }
        KeyCode::Down => {
            app.move_selection(1);
        }
        KeyCode::Up => {
            app.move_selection(-1);
        }
        _ => {}
    }
    false
}

async fn handle_overlay(app: &mut App, key: KeyEvent) -> bool {
    match &app.overlay {
        Overlay::None => false,
        Overlay::ItemForm { .. } => handle_item_form(app, key).await,
        Overlay::Generator { .. } => handle_generator(app, key),
        Overlay::FolderForm { .. } => handle_folder_form(app, key).await,
        Overlay::ConfirmDelete { .. } => handle_confirm_delete(app, key).await,
        Overlay::ProfileManager { .. } => handle_profile_manager(app, key).await,
    }
}

async fn handle_profile_manager(app: &mut App, key: KeyEvent) -> bool {
    let mode_is_list = matches!(
        &app.overlay,
        Overlay::ProfileManager {
            mode: ProfileManagerMode::List,
            ..
        }
    );
    if mode_is_list {
        return handle_profile_list(app, key).await;
    }
    match &app.overlay {
        Overlay::ProfileManager {
            mode: ProfileManagerMode::Create { .. },
            ..
        } => handle_profile_create(app, key).await,
        Overlay::ProfileManager {
            mode: ProfileManagerMode::Edit { .. },
            ..
        } => handle_profile_edit(app, key),
        Overlay::ProfileManager {
            mode: ProfileManagerMode::ConfirmDelete { .. },
            ..
        } => handle_profile_confirm_delete(app, key).await,
        _ => false,
    }
}

async fn handle_profile_list(app: &mut App, key: KeyEvent) -> bool {
    let len = app.profiles.profiles.len();
    match key.code {
        KeyCode::Esc => {
            app.close_overlay();
            false
        }
        KeyCode::Char('j') | KeyCode::Down if is_typing(&key) || key.code == KeyCode::Down => {
            if let Overlay::ProfileManager { selected, .. } = &mut app.overlay {
                if len > 0 {
                    *selected = (*selected + 1) % len;
                }
            }
            false
        }
        KeyCode::Char('k') | KeyCode::Up if is_typing(&key) || key.code == KeyCode::Up => {
            if let Overlay::ProfileManager { selected, .. } = &mut app.overlay {
                if len > 0 {
                    *selected = if *selected == 0 { len - 1 } else { *selected - 1 };
                }
            }
            false
        }
        KeyCode::Enter => {
            let id = match &app.overlay {
                Overlay::ProfileManager { selected, .. } => app
                    .profiles
                    .profiles
                    .get(*selected)
                    .map(|p| p.id.clone()),
                _ => None,
            };
            if let Some(id) = id {
                app.switch_to_profile(&id).await;
            }
            false
        }
        KeyCode::Char('n') if is_typing(&key) => {
            let selected = match &app.overlay {
                Overlay::ProfileManager { selected, .. } => *selected,
                _ => 0,
            };
            app.overlay = Overlay::ProfileManager {
                selected,
                mode: ProfileManagerMode::Create {
                    name: String::new(),
                    error: None,
                },
            };
            false
        }
        KeyCode::Char('e') if is_typing(&key) => {
            let selected = match &app.overlay {
                Overlay::ProfileManager { selected, .. } => *selected,
                _ => return false,
            };
            let Some(p) = app.profiles.profiles.get(selected).cloned() else {
                return false;
            };
            app.overlay = Overlay::ProfileManager {
                selected,
                mode: ProfileManagerMode::Edit {
                    id: p.id,
                    name: p.name,
                    server_url: p.server_url,
                    email: p.email,
                    auto_lock_input: format_auto_lock_input(p.auto_lock_minutes),
                    field: ProfileEditField::Name,
                    error: None,
                },
            };
            false
        }
        KeyCode::Char('d') if is_typing(&key) => {
            let (selected, id, name) = match &app.overlay {
                Overlay::ProfileManager { selected, .. } => {
                    let p = app.profiles.profiles.get(*selected);
                    (
                        *selected,
                        p.map(|p| p.id.clone()).unwrap_or_default(),
                        p.map(|p| p.name.clone()).unwrap_or_default(),
                    )
                }
                _ => return false,
            };
            if !id.is_empty() {
                app.overlay = Overlay::ProfileManager {
                    selected,
                    mode: ProfileManagerMode::ConfirmDelete { id, name },
                };
            }
            false
        }
        KeyCode::Char('L') if is_typing(&key) => {
            app.toggle_lock_on_profile_switch();
            false
        }
        _ => false,
    }
}

fn handle_profile_edit(app: &mut App, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Esc => {
            if let Overlay::ProfileManager { selected, .. } = &app.overlay {
                let selected = *selected;
                app.overlay = Overlay::ProfileManager {
                    selected,
                    mode: ProfileManagerMode::List,
                };
            }
            false
        }
        KeyCode::Enter => {
            app.profile_manager_edit_save();
            false
        }
        KeyCode::Tab | KeyCode::Down => {
            if let Overlay::ProfileManager {
                mode: ProfileManagerMode::Edit { field, .. },
                ..
            } = &mut app.overlay
            {
                *field = field.next();
            }
            false
        }
        KeyCode::BackTab | KeyCode::Up => {
            if let Overlay::ProfileManager {
                mode: ProfileManagerMode::Edit { field, .. },
                ..
            } = &mut app.overlay
            {
                *field = field.prev();
            }
            false
        }
        KeyCode::Backspace | KeyCode::Delete => {
            if let Overlay::ProfileManager {
                mode:
                    ProfileManagerMode::Edit {
                        name,
                        server_url,
                        email,
                        auto_lock_input,
                        field,
                        error,
                        ..
                    },
                ..
            } = &mut app.overlay
            {
                match field {
                    ProfileEditField::Name => {
                        name.pop();
                    }
                    ProfileEditField::Server => {
                        server_url.pop();
                    }
                    ProfileEditField::Email => {
                        email.pop();
                    }
                    ProfileEditField::AutoLock => {
                        auto_lock_input.pop();
                    }
                }
                *error = None;
            }
            false
        }
        KeyCode::Char(c) if is_typing(&key) => {
            if let Overlay::ProfileManager {
                mode:
                    ProfileManagerMode::Edit {
                        name,
                        server_url,
                        email,
                        auto_lock_input,
                        field,
                        error,
                        ..
                    },
                ..
            } = &mut app.overlay
            {
                match field {
                    ProfileEditField::Name => push_char(name, c),
                    ProfileEditField::Server => push_char(server_url, c),
                    ProfileEditField::Email => push_char(email, c),
                    ProfileEditField::AutoLock => {
                        if c.is_ascii_alphanumeric() {
                            push_char(auto_lock_input, c.to_ascii_lowercase());
                        }
                    }
                }
                *error = None;
            }
            false
        }
        _ => false,
    }
}

async fn handle_profile_create(app: &mut App, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Esc => {
            if let Overlay::ProfileManager { selected, .. } = &app.overlay {
                let selected = *selected;
                app.overlay = Overlay::ProfileManager {
                    selected,
                    mode: ProfileManagerMode::List,
                };
            }
            false
        }
        KeyCode::Enter => {
            app.profile_manager_create_save().await;
            false
        }
        KeyCode::Backspace | KeyCode::Delete => {
            if let Overlay::ProfileManager {
                mode: ProfileManagerMode::Create { name, error, .. },
                ..
            } = &mut app.overlay
            {
                name.pop();
                *error = None;
            }
            false
        }
        KeyCode::Char(c) if is_typing(&key) => {
            if let Overlay::ProfileManager {
                mode: ProfileManagerMode::Create { name, error, .. },
                ..
            } = &mut app.overlay
            {
                push_char(name, c);
                *error = None;
            }
            false
        }
        _ => false,
    }
}

async fn handle_profile_confirm_delete(app: &mut App, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => {
            if let Overlay::ProfileManager { selected, .. } = &app.overlay {
                let selected = *selected;
                app.overlay = Overlay::ProfileManager {
                    selected,
                    mode: ProfileManagerMode::List,
                };
            }
            false
        }
        KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
            app.profile_manager_confirm_delete().await;
            false
        }
        _ => false,
    }
}

async fn handle_item_form(app: &mut App, key: KeyEvent) -> bool {
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        match key.code {
            KeyCode::Char('g') => {
                app.open_generator(true);
                return false;
            }
            KeyCode::Char('s') => {
                if !app.busy {
                    app.save_item_form().await;
                }
                return false;
            }
            _ => {}
        }
    }

    match key.code {
        KeyCode::Esc => {
            app.close_overlay();
            false
        }
        KeyCode::Tab | KeyCode::Down => {
            if let Overlay::ItemForm { field, .. } = &mut app.overlay {
                *field = field.next();
            }
            false
        }
        KeyCode::BackTab | KeyCode::Up => {
            if let Overlay::ItemForm { field, .. } = &mut app.overlay {
                *field = field.prev();
            }
            false
        }
        KeyCode::Enter => {
            let on_notes = matches!(
                &app.overlay,
                Overlay::ItemForm {
                    field: EditField::Notes,
                    ..
                }
            );
            if on_notes {
                if !app.busy {
                    app.save_item_form().await;
                }
            } else if let Overlay::ItemForm { field, .. } = &mut app.overlay {
                *field = field.next();
            }
            false
        }
        KeyCode::Backspace | KeyCode::Delete => {
            if let Overlay::ItemForm {
                field,
                name,
                username,
                password,
                totp,
                uri,
                notes,
                ..
            } = &mut app.overlay
            {
                match field {
                    EditField::Name => {
                        name.pop();
                    }
                    EditField::Username => {
                        username.pop();
                    }
                    EditField::Password => {
                        password.pop();
                    }
                    EditField::Totp => {
                        totp.pop();
                    }
                    EditField::Uri => {
                        uri.pop();
                    }
                    EditField::Notes => {
                        notes.pop();
                    }
                }
            }
            false
        }
        KeyCode::Char(c) if is_typing(&key) => {
            if let Overlay::ItemForm {
                field,
                name,
                username,
                password,
                totp,
                uri,
                notes,
                ..
            } = &mut app.overlay
            {
                match field {
                    EditField::Name => push_char(name, c),
                    EditField::Username => push_char(username, c),
                    EditField::Password => push_char(password, c),
                    EditField::Totp => push_char(totp, c),
                    EditField::Uri => push_char(uri, c),
                    EditField::Notes => push_char(notes, c),
                }
            }
            false
        }
        _ => false,
    }
}

fn handle_generator(app: &mut App, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Esc => {
            app.close_overlay();
        }
        KeyCode::Enter | KeyCode::Char('c') if is_typing(&key) || key.code == KeyCode::Enter => {
            app.apply_generator();
        }
        KeyCode::Char('r') if is_typing(&key) => {
            app.regenerate_password();
        }
        KeyCode::Char('+') | KeyCode::Char('=') if is_typing(&key) => {
            if let Overlay::Generator { length, .. } = &mut app.overlay {
                *length = (*length + 1).min(128);
            }
            app.regenerate_password();
        }
        KeyCode::Char('-') if is_typing(&key) => {
            if let Overlay::Generator { length, .. } = &mut app.overlay {
                *length = (*length).saturating_sub(1).max(8);
            }
            app.regenerate_password();
        }
        KeyCode::Char('u') if is_typing(&key) => {
            if let Overlay::Generator { uppercase, .. } = &mut app.overlay {
                *uppercase = !*uppercase;
            }
            app.regenerate_password();
        }
        KeyCode::Char('l') if is_typing(&key) => {
            if let Overlay::Generator { lowercase, .. } = &mut app.overlay {
                *lowercase = !*lowercase;
            }
            app.regenerate_password();
        }
        KeyCode::Char('d') if is_typing(&key) => {
            if let Overlay::Generator { digits, .. } = &mut app.overlay {
                *digits = !*digits;
            }
            app.regenerate_password();
        }
        KeyCode::Char('s') if is_typing(&key) => {
            if let Overlay::Generator { symbols, .. } = &mut app.overlay {
                *symbols = !*symbols;
            }
            app.regenerate_password();
        }
        _ => {}
    }
    false
}

async fn handle_folder_form(app: &mut App, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Esc => {
            app.close_overlay();
            false
        }
        KeyCode::Enter => {
            if !app.busy {
                app.save_folder_form().await;
            }
            false
        }
        KeyCode::Backspace | KeyCode::Delete => {
            if let Overlay::FolderForm { name } = &mut app.overlay {
                name.pop();
            }
            false
        }
        KeyCode::Char(c) if is_typing(&key) => {
            if let Overlay::FolderForm { name } = &mut app.overlay {
                push_char(name, c);
            }
            false
        }
        _ => false,
    }
}

async fn handle_confirm_delete(app: &mut App, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => {
            app.close_overlay();
            false
        }
        KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
            if !app.busy {
                app.confirm_delete().await;
            }
            false
        }
        _ => false,
    }
}
