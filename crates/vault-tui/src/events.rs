//! Keyboard / terminal event handling.

use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};

use crate::app::{
    writable_share_collections, App, CardField, ChangePasswordField, ClipboardKind, EditField,
    FocusPane, FormUriLine, IdentityField, LoginAuthMode, LoginField, NoteField, Overlay,
    PendingAction, PinSetupField, ProfileEditField, ProfileManagerMode, Screen, ShareToOrgStep,
    SshKeyField,
};
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
        Event::Mouse(m) => {
            app.handle_mouse(m, detail_visible, folders_visible);
            false
        }
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
    if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
        app.should_quit = true;
        return true;
    }

    if app.show_help {
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
        return handle_overlay(app, key).await;
    }

    match app.screen {
        Screen::Login => handle_login(app, key).await,
        Screen::TwoFactor => {
            if crate::app::auth_ext_handle_2fa_key(app, &key) {
                return false;
            }
            handle_2fa(app, key).await
        }
        Screen::AuthWait => crate::app::auth_ext_handle_wait_key(app, &key),
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
    if crate::app::auth_ext_handle_login_key(app, &key) {
        return false;
    }
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
        KeyCode::Char('a') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.login_auth_mode = match app.login_auth_mode {
                LoginAuthMode::Password => LoginAuthMode::ApiKey,
                LoginAuthMode::ApiKey => LoginAuthMode::Password,
            };
            app.form_error = None;
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
            app.login_field = cycle_login_field(app, true);
            false
        }
        KeyCode::BackTab | KeyCode::Up => {
            app.login_field = cycle_login_field(app, false);
            false
        }
        KeyCode::Char(' ') if is_typing(&key) && app.login_field == LoginField::Remember => {
            app.remember_login = !app.remember_login;
            false
        }
        KeyCode::Enter if app.login_field == LoginField::Remember => {
            // Enter on Remember submits (Space still toggles the checkbox).
            app.queue(PendingAction::Login);
            false
        }
        KeyCode::Enter => {
            if matches!(
                app.login_field,
                LoginField::Password | LoginField::ApiKeyClientSecret
            ) {
                app.queue(PendingAction::Login);
            } else {
                app.login_field = cycle_login_field(app, true);
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
                LoginField::ApiKeyClientId => {
                    app.api_client_id.pop();
                }
                LoginField::ApiKeyClientSecret => {
                    app.api_client_secret.pop();
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
                LoginField::ApiKeyClientId => push_char(&mut app.api_client_id, c),
                LoginField::ApiKeyClientSecret => push_char(&mut app.api_client_secret, c),
                LoginField::Remember => {}
            }
            app.form_error = None;
            false
        }
        KeyCode::Char(_) => false,
        _ => false,
    }
}

async fn handle_2fa(app: &mut App, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Char(' ') if is_typing(&key) => {
            app.remember_2fa_device = !app.remember_2fa_device;
            false
        }
        KeyCode::Esc => {
            app.screen = Screen::Login;
            app.totp_code.clear();
            app.form_error = None;
            app.set_status("Cancelled 2FA");
            false
        }
        KeyCode::Char('m') if is_typing(&key) => {
            app.queue(PendingAction::ResendEmail2fa);
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
        KeyCode::Tab | KeyCode::Char('p') if is_typing(&key) => {
            if app
                .session
                .as_ref()
                .is_some_and(|s| s.pin_unlock_available())
            {
                app.unlock_use_pin = !app.unlock_use_pin;
                app.form_error = None;
            } else if is_typing(&key) {
                app.set_status("PIN unlock not configured");
            }
            false
        }
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
            if app.unlock_use_pin {
                app.queue(PendingAction::UnlockPin);
            } else {
                app.queue(PendingAction::Unlock);
            }
            false
        }
        KeyCode::Backspace | KeyCode::Delete => {
            if app.unlock_use_pin {
                app.unlock_pin.pop();
            } else {
                app.unlock_password.pop();
            }
            app.form_error = None;
            false
        }
        KeyCode::Char(c) if is_typing(&key) => {
            if app.unlock_use_pin {
                if c.is_ascii_digit() {
                    push_char(&mut app.unlock_pin, c);
                }
            } else {
                push_char(&mut app.unlock_password, c);
            }
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

    if let Some(quit) = crate::power_events::handle_vault_key(app, &key).await {
        return quit;
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
            KeyCode::Char('k') => {
                app.open_command_palette();
                return false;
            }
            _ => {}
        }
    }

    match key.code {
        KeyCode::Char('q') if is_typing(&key) => {
            if app.screen == Screen::Vault && !app.using_mock {
                app.set_status("Press Ctrl+c to quit (vault unlocked)");
                return false;
            }
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
            if matches!(app.current_filter(), crate::models::FilterKind::Sends) {
                app.open_send_form();
            } else {
                app.open_new_item_picker();
            }
        }
        KeyCode::Char(',') if is_typing(&key) => {
            app.open_account_settings();
        }
        KeyCode::Char('C') if key.modifiers.contains(KeyModifiers::SHIFT) && is_typing(&key) => {
            app.queue(PendingAction::CloneItem);
        }
        KeyCode::Char('e') if is_typing(&key) => {
            if app.focus == FocusPane::Folders {
                app.open_rename_folder_form();
            } else if matches!(app.current_filter(), crate::models::FilterKind::Sends) {
                app.open_edit_send();
            } else {
                app.open_edit_item();
            }
        }
        KeyCode::Enter => {
            if app.in_trash() {
                if !app.busy {
                    app.restore_selected().await;
                }
            } else {
                app.open_edit_item();
            }
        }
        KeyCode::Char('M') if key.modifiers.contains(KeyModifiers::SHIFT) && is_typing(&key) => {
            app.open_move_to_folder();
        }
        KeyCode::Char('O') if key.modifiers.contains(KeyModifiers::SHIFT) && is_typing(&key) => {
            app.open_share_to_org();
        }
        KeyCode::Char(' ') if is_typing(&key) => {
            app.toggle_bulk_select_current();
        }
        KeyCode::Char('d') if is_typing(&key) => {
            if app.focus == FocusPane::Folders {
                app.open_delete_folder_confirm();
            } else if matches!(app.current_filter(), crate::models::FilterKind::Sends) {
                app.open_delete_send_confirm();
            } else {
                app.open_delete_confirm();
            }
        }
        KeyCode::Char('u') if is_typing(&key) => {
            if app.pending_undo.is_some() {
                app.undo_delete().await;
            }
        }
        KeyCode::Char('X') if is_typing(&key) && app.in_trash() => {
            app.open_empty_trash_confirm();
        }
        KeyCode::Char('F') if is_typing(&key) && app.focus == FocusPane::Detail => {
            app.open_custom_fields_editor();
        }
        KeyCode::Char('L')
            if is_typing(&key)
                && matches!(app.current_filter(), crate::models::FilterKind::Sends) =>
        {
            app.copy_send_link();
        }
        KeyCode::Char('O') if is_typing(&key) => {
            app.open_receive_send();
        }
        KeyCode::Char('f') if is_typing(&key) => {
            if !app.busy {
                app.toggle_favorite().await;
            }
        }
        KeyCode::Char('g') if is_typing(&key) => {
            app.open_generator(false);
        }
        KeyCode::Char('H') if is_typing(&key) => {
            app.open_password_history();
        }
        KeyCode::Char('R') if is_typing(&key) => {
            app.open_health_report();
        }
        KeyCode::Char(':') if is_typing(&key) => {
            app.open_command_palette();
        }
        KeyCode::Char(c @ '1'..='9') if is_typing(&key) && app.focus == FocusPane::Detail => {
            app.copy_custom_field((c as u8 - b'1') as usize);
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
        KeyCode::Char('m') if is_typing(&key) && app.focus == FocusPane::Detail => {
            app.copy_field(ClipboardKind::CardNumber);
        }
        KeyCode::Char('v') if is_typing(&key) && app.focus == FocusPane::Detail => {
            app.copy_field(ClipboardKind::CardCode);
        }
        KeyCode::Char('x') if is_typing(&key) && app.focus == FocusPane::Detail => {
            app.copy_field(ClipboardKind::CardExpiry);
        }
        KeyCode::Char('p') if is_typing(&key) && app.focus == FocusPane::Detail => {
            app.copy_field(ClipboardKind::SshPublic);
        }
        KeyCode::Char('b') if is_typing(&key) && app.focus == FocusPane::Detail => {
            app.copy_field(ClipboardKind::SshPrivate);
        }
        KeyCode::Char(c @ '1'..='9')
            if key.modifiers.contains(KeyModifiers::CONTROL) && app.focus == FocusPane::Detail =>
        {
            let idx = (c as u8 - b'1') as usize;
            app.download_attachment_at(idx).await;
        }
        KeyCode::Char(c @ '1'..='9')
            if key
                .modifiers
                .contains(KeyModifiers::CONTROL | KeyModifiers::SHIFT)
                && app.focus == FocusPane::Detail =>
        {
            let idx = (c as u8 - b'1') as usize;
            app.open_delete_attachment_confirm(idx);
        }
        KeyCode::Char('A') if is_typing(&key) && app.focus == FocusPane::Detail => {
            app.open_attachment_upload();
        }
        KeyCode::Char('o') if is_typing(&key) && app.focus == FocusPane::Detail => {
            app.copy_field(ClipboardKind::Notes);
        }
        KeyCode::Char('r') if is_typing(&key) => {
            if app.in_trash() {
                if !app.busy {
                    app.restore_selected().await;
                }
            } else {
                app.toggle_reveal();
            }
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
    if let Some(quit) = crate::power_events::pre_overlay_key(app, &key).await {
        return quit;
    }
    match &app.overlay {
        Overlay::None => false,
        Overlay::Power(_) => crate::power_events::handle_power_overlay(app, key).await,
        Overlay::ItemForm { .. } => handle_item_form(app, key).await,
        Overlay::NoteForm { .. } => handle_note_form(app, key).await,
        Overlay::NewItemType { .. } => handle_new_item_type(app, key),
        Overlay::Generator { .. } => handle_generator(app, key),
        Overlay::FolderForm { .. } => handle_folder_form(app, key).await,
        Overlay::ConfirmDelete { .. } => handle_confirm_delete(app, key).await,
        Overlay::Reprompt { .. } => handle_reprompt(app, key),
        Overlay::ProfileManager { .. } => handle_profile_manager(app, key).await,
        Overlay::CommandPalette { .. } => handle_command_palette(app, key),
        Overlay::PasswordHistory => handle_password_history(app, key),
        Overlay::HealthReport { .. } => handle_health_report(app, key),
        Overlay::AccountSettings { .. } => handle_account_settings(app, key).await,
        Overlay::AccountTools(_) => crate::app::account_tools_handle_key(app, key).await,
        Overlay::SendForm { .. } => handle_send_form(app, key).await,
        Overlay::ReceiveSend { .. } => handle_receive_send(app, key).await,
        Overlay::AttachmentPath { .. } => handle_attachment_path(app, key).await,
        Overlay::CardForm { .. } => handle_card_form(app, key).await,
        Overlay::IdentityForm { .. } => handle_identity_form(app, key).await,
        Overlay::SshKeyForm { .. } => handle_ssh_key_form(app, key).await,
        Overlay::MoveToFolder { .. } => handle_move_to_folder(app, key).await,
        Overlay::ShareToOrg { .. } => handle_share_to_org(app, key).await,
        Overlay::PinSetup { .. } => handle_pin_setup(app, key),
        Overlay::ChangeMasterPassword { .. } => handle_change_master_password(app, key).await,
        Overlay::CustomFieldsForm { .. } => handle_custom_fields_form(app, key).await,
    }
}

async fn handle_custom_fields_form(app: &mut App, key: KeyEvent) -> bool {
    use crate::app::CustomFieldEditFocus;
    use crate::models::CustomFieldKind;
    if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('s')) {
        app.submit_custom_fields().await;
        return false;
    }
    match key.code {
        KeyCode::Esc => {
            if let Overlay::CustomFieldsForm { editing, .. } = &mut app.overlay {
                if editing.is_some() {
                    *editing = None;
                    return false;
                }
            }
            app.close_overlay();
        }
        KeyCode::Char('n') if is_typing(&key) => {
            if let Overlay::CustomFieldsForm {
                editing,
                edit_name,
                edit_value,
                edit_type,
                edit_focus,
                ..
            } = &mut app.overlay
            {
                if editing.is_none() {
                    *editing = Some(usize::MAX); // sentinel: new field
                    edit_name.clear();
                    edit_value.clear();
                    *edit_type = CustomFieldKind::Text;
                    *edit_focus = CustomFieldEditFocus::Name;
                }
            }
        }
        KeyCode::Char('d') if is_typing(&key) => {
            if let Overlay::CustomFieldsForm {
                fields,
                selected,
                editing,
                ..
            } = &mut app.overlay
            {
                if editing.is_none() && *selected < fields.len() {
                    fields.remove(*selected);
                    if *selected > 0 && *selected >= fields.len() {
                        *selected = fields.len().saturating_sub(1);
                    }
                }
            }
        }
        KeyCode::Enter => {
            if let Overlay::CustomFieldsForm {
                fields,
                selected,
                editing,
                edit_name,
                edit_value,
                edit_type,
                edit_focus,
                ..
            } = &mut app.overlay
            {
                if let Some(idx) = *editing {
                    let view = crate::models::CustomFieldView {
                        name: edit_name.clone(),
                        value: edit_value.clone(),
                        kind: *edit_type,
                        linked_id: None,
                    };
                    if idx == usize::MAX {
                        fields.push(view);
                    } else if let Some(slot) = fields.get_mut(idx) {
                        *slot = view;
                    }
                    *editing = None;
                } else if let Some(f) = fields.get(*selected) {
                    *editing = Some(*selected);
                    *edit_name = f.name.clone();
                    *edit_value = f.value.clone();
                    *edit_type = f.kind;
                    *edit_focus = CustomFieldEditFocus::Name;
                }
            }
        }
        KeyCode::Tab => {
            if let Overlay::CustomFieldsForm {
                editing,
                edit_focus,
                edit_type,
                ..
            } = &mut app.overlay
            {
                if editing.is_some() {
                    *edit_focus = match *edit_focus {
                        CustomFieldEditFocus::Name => CustomFieldEditFocus::Value,
                        CustomFieldEditFocus::Value => CustomFieldEditFocus::Type,
                        CustomFieldEditFocus::Type => {
                            *edit_type = edit_type.next();
                            CustomFieldEditFocus::Type
                        }
                    };
                }
            }
        }
        KeyCode::Down | KeyCode::Char('j') if is_typing(&key) || key.code == KeyCode::Down => {
            if let Overlay::CustomFieldsForm {
                fields,
                selected,
                editing,
                ..
            } = &mut app.overlay
            {
                if editing.is_none() && !fields.is_empty() {
                    *selected = (*selected + 1) % fields.len();
                }
            }
        }
        KeyCode::Up | KeyCode::Char('k') if is_typing(&key) || key.code == KeyCode::Up => {
            if let Overlay::CustomFieldsForm {
                fields,
                selected,
                editing,
                ..
            } = &mut app.overlay
            {
                if editing.is_none() && !fields.is_empty() {
                    *selected = (*selected + fields.len() - 1) % fields.len();
                }
            }
        }
        KeyCode::Backspace | KeyCode::Delete => {
            if let Overlay::CustomFieldsForm {
                editing,
                edit_focus,
                edit_name,
                edit_value,
                ..
            } = &mut app.overlay
            {
                if editing.is_some() {
                    match *edit_focus {
                        CustomFieldEditFocus::Name => {
                            edit_name.pop();
                        }
                        CustomFieldEditFocus::Value => {
                            edit_value.pop();
                        }
                        CustomFieldEditFocus::Type => {}
                    }
                }
            }
        }
        KeyCode::Char(c) if is_typing(&key) => {
            if let Overlay::CustomFieldsForm {
                editing,
                edit_focus,
                edit_name,
                edit_value,
                ..
            } = &mut app.overlay
            {
                if editing.is_some() {
                    match *edit_focus {
                        CustomFieldEditFocus::Name => push_char(edit_name, c),
                        CustomFieldEditFocus::Value => push_char(edit_value, c),
                        CustomFieldEditFocus::Type => {}
                    }
                }
            }
        }
        _ => {}
    }
    false
}

fn cycle_login_field(app: &App, forward: bool) -> LoginField {
    if forward {
        app.login_field.next(app.login_auth_mode)
    } else {
        app.login_field.prev(app.login_auth_mode)
    }
}

fn handle_reprompt(app: &mut App, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Esc => {
            app.close_overlay();
            false
        }
        KeyCode::Enter => {
            app.submit_reprompt();
            false
        }
        KeyCode::Backspace | KeyCode::Delete => {
            if let Overlay::Reprompt {
                password, error, ..
            } = &mut app.overlay
            {
                password.pop();
                *error = None;
            }
            false
        }
        KeyCode::Char(c) if is_typing(&key) => {
            if let Overlay::Reprompt {
                password, error, ..
            } = &mut app.overlay
            {
                push_char(password, c);
                *error = None;
            }
            false
        }
        _ => false,
    }
}

fn handle_new_item_type(app: &mut App, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Esc => {
            app.close_overlay();
        }
        KeyCode::Tab | KeyCode::Down | KeyCode::Char('j') if is_typing(&key) => {
            if let Overlay::NewItemType { selected } = &mut app.overlay {
                *selected = (*selected + 1) % 5;
            }
        }
        KeyCode::BackTab | KeyCode::Up | KeyCode::Char('k') if is_typing(&key) => {
            if let Overlay::NewItemType { selected } = &mut app.overlay {
                *selected = selected.saturating_sub(1) % 5;
            }
        }
        KeyCode::Enter => {
            let selected = match &app.overlay {
                Overlay::NewItemType { selected } => *selected,
                _ => 0,
            };
            app.close_overlay();
            match selected {
                0 => app.open_new_login(),
                1 => app.open_new_note(),
                2 => app.open_new_card(),
                3 => app.open_new_identity(),
                4 => app.open_new_ssh_key(),
                _ => {}
            }
        }
        _ => {}
    }
    false
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
                    *selected = if *selected == 0 {
                        len - 1
                    } else {
                        *selected - 1
                    };
                }
            }
            false
        }
        KeyCode::Enter => {
            let id = match &app.overlay {
                Overlay::ProfileManager { selected, .. } => {
                    app.profiles.profiles.get(*selected).map(|p| p.id.clone())
                }
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
                    clipboard_clear_input: p.clipboard_clear_secs.to_string(),
                    timeout_action: p.timeout_action,
                    timeout_on_startup: p.timeout_on_startup,
                    lock_on_system_lock: p.lock_on_system_lock,
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
                        clipboard_clear_input,
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
                    ProfileEditField::ClipboardClear => {
                        clipboard_clear_input.pop();
                    }
                    ProfileEditField::TimeoutAction
                    | ProfileEditField::TimeoutOnStartup
                    | ProfileEditField::LockOnSystemLock => {}
                }
                *error = None;
            }
            false
        }
        KeyCode::Char(' ') | KeyCode::Left | KeyCode::Right
            if matches!(
                &app.overlay,
                Overlay::ProfileManager {
                    mode: ProfileManagerMode::Edit { field, .. },
                    ..
                } if field.is_toggle()
            ) =>
        {
            if let Overlay::ProfileManager {
                mode:
                    ProfileManagerMode::Edit {
                        timeout_action,
                        timeout_on_startup,
                        lock_on_system_lock,
                        field,
                        error,
                        ..
                    },
                ..
            } = &mut app.overlay
            {
                match field {
                    ProfileEditField::TimeoutAction => *timeout_action = timeout_action.toggled(),
                    ProfileEditField::TimeoutOnStartup => {
                        *timeout_on_startup = !*timeout_on_startup
                    }
                    ProfileEditField::LockOnSystemLock => {
                        *lock_on_system_lock = !*lock_on_system_lock
                    }
                    _ => {}
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
                        clipboard_clear_input,
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
                    ProfileEditField::ClipboardClear => {
                        if c.is_ascii_digit() {
                            push_char(clipboard_clear_input, c);
                        }
                    }
                    ProfileEditField::TimeoutAction
                    | ProfileEditField::TimeoutOnStartup
                    | ProfileEditField::LockOnSystemLock => {}
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
                uris,
                uri_line,
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
                        if uris.is_empty() {
                            uris.push(FormUriLine {
                                uri: String::new(),
                                match_type: 0,
                            });
                        }
                        let idx = (*uri_line).min(uris.len().saturating_sub(1));
                        uris[idx].uri.pop();
                    }
                    EditField::Notes => {
                        notes.pop();
                    }
                    EditField::Reprompt => {}
                }
            }
            false
        }
        KeyCode::Char('m') if is_typing(&key) => {
            if let Overlay::ItemForm {
                field: EditField::Uri,
                uris,
                uri_line,
                ..
            } = &mut app.overlay
            {
                if uris.is_empty() {
                    uris.push(FormUriLine {
                        uri: String::new(),
                        match_type: 0,
                    });
                }
                let idx = (*uri_line).min(uris.len().saturating_sub(1));
                uris[idx].match_type = (uris[idx].match_type + 1) % 6;
            }
            false
        }
        KeyCode::Char('+') | KeyCode::Char('=') if is_typing(&key) => {
            if let Overlay::ItemForm {
                field: EditField::Uri,
                uris,
                uri_line,
                ..
            } = &mut app.overlay
            {
                uris.push(FormUriLine {
                    uri: String::new(),
                    match_type: 0,
                });
                *uri_line = uris.len().saturating_sub(1);
            }
            false
        }
        KeyCode::Char('-') | KeyCode::Char('_') if is_typing(&key) => {
            if let Overlay::ItemForm {
                field: EditField::Uri,
                uris,
                uri_line,
                ..
            } = &mut app.overlay
            {
                if uris.len() > 1 {
                    let idx = (*uri_line).min(uris.len().saturating_sub(1));
                    uris.remove(idx);
                    *uri_line = (*uri_line).min(uris.len().saturating_sub(1));
                }
            }
            false
        }
        KeyCode::Char('[') if is_typing(&key) => {
            if let Overlay::ItemForm {
                field: EditField::Uri,
                uri_line,
                uris,
                ..
            } = &mut app.overlay
            {
                if !uris.is_empty() && *uri_line > 0 {
                    *uri_line -= 1;
                }
            }
            false
        }
        KeyCode::Char(']') if is_typing(&key) => {
            if let Overlay::ItemForm {
                field: EditField::Uri,
                uri_line,
                uris,
                ..
            } = &mut app.overlay
            {
                if !uris.is_empty() && *uri_line + 1 < uris.len() {
                    *uri_line += 1;
                }
            }
            false
        }
        KeyCode::Char(' ') if is_typing(&key) => {
            if let Overlay::ItemForm {
                field: EditField::Reprompt,
                reprompt,
                ..
            } = &mut app.overlay
            {
                *reprompt = !*reprompt;
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
                uris,
                uri_line,
                notes,
                ..
            } = &mut app.overlay
            {
                match field {
                    EditField::Name => push_char(name, c),
                    EditField::Username => push_char(username, c),
                    EditField::Password => push_char(password, c),
                    EditField::Totp => push_char(totp, c),
                    EditField::Uri => {
                        if uris.is_empty() {
                            uris.push(FormUriLine {
                                uri: String::new(),
                                match_type: 0,
                            });
                        }
                        let idx = (*uri_line).min(uris.len().saturating_sub(1));
                        push_char(&mut uris[idx].uri, c);
                    }
                    EditField::Notes => push_char(notes, c),
                    EditField::Reprompt => {}
                }
            }
            false
        }
        _ => false,
    }
}

async fn handle_note_form(app: &mut App, key: KeyEvent) -> bool {
    if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('s')) {
        if !app.busy {
            app.save_note_form().await;
        }
        return false;
    }
    match key.code {
        KeyCode::Esc => {
            app.close_overlay();
            false
        }
        KeyCode::Tab | KeyCode::Down | KeyCode::BackTab | KeyCode::Up => {
            if let Overlay::NoteForm { field, .. } = &mut app.overlay {
                *field = match field {
                    NoteField::Name => NoteField::Notes,
                    NoteField::Notes => NoteField::Name,
                };
            }
            false
        }
        KeyCode::Enter => {
            if !app.busy {
                app.save_note_form().await;
            }
            false
        }
        KeyCode::Backspace | KeyCode::Delete => {
            if let Overlay::NoteForm {
                field, name, notes, ..
            } = &mut app.overlay
            {
                match *field {
                    NoteField::Name => {
                        name.pop();
                    }
                    NoteField::Notes => {
                        notes.pop();
                    }
                }
            }
            false
        }
        KeyCode::Char(c) if is_typing(&key) => {
            if let Overlay::NoteForm {
                field, name, notes, ..
            } = &mut app.overlay
            {
                match *field {
                    NoteField::Name => push_char(name, c),
                    NoteField::Notes => push_char(notes, c),
                }
            }
            false
        }
        _ => false,
    }
}

fn handle_generator(app: &mut App, key: KeyEvent) -> bool {
    use crate::app::{GeneratorMode, UsernameKind};

    match key.code {
        KeyCode::Esc => {
            app.close_overlay();
        }
        KeyCode::Enter | KeyCode::Char('c') if is_typing(&key) || key.code == KeyCode::Enter => {
            app.apply_generator();
        }
        KeyCode::Char('r') if is_typing(&key) => {
            app.regenerate_password();
            app.fetch_forwarded_alias_if_selected();
        }
        KeyCode::Char('m') if is_typing(&key) => {
            if let Overlay::Generator { mode, .. } = &mut app.overlay {
                *mode = match mode {
                    GeneratorMode::Password => GeneratorMode::Passphrase,
                    GeneratorMode::Passphrase => GeneratorMode::Username,
                    GeneratorMode::Username => GeneratorMode::Password,
                };
            }
            app.regenerate_password();
        }
        KeyCode::Char('k') if is_typing(&key) => {
            if let Overlay::Generator {
                mode,
                username_kind,
                ..
            } = &mut app.overlay
            {
                if *mode == GeneratorMode::Username {
                    *username_kind = match username_kind {
                        UsernameKind::Word => UsernameKind::Plus,
                        UsernameKind::Plus => UsernameKind::Catchall,
                        UsernameKind::Catchall => UsernameKind::SimpleLogin,
                        UsernameKind::SimpleLogin => UsernameKind::AddyIo,
                        UsernameKind::AddyIo => UsernameKind::Word,
                    };
                }
            }
            app.regenerate_password();
        }
        KeyCode::Char('+') | KeyCode::Char('=') if is_typing(&key) => {
            if let Overlay::Generator {
                mode,
                length,
                passphrase_words,
                min_numbers,
                ..
            } = &mut app.overlay
            {
                match mode {
                    GeneratorMode::Password => *length = (*length + 1).min(128),
                    GeneratorMode::Passphrase => {
                        *passphrase_words = (*passphrase_words + 1).min(20)
                    }
                    GeneratorMode::Username => {}
                }
                if *mode == GeneratorMode::Password {
                    *min_numbers = (*min_numbers + 1).min(10);
                }
            }
            app.clamp_generator_overlay();
        }
        KeyCode::Char('-') if is_typing(&key) => {
            if let Overlay::Generator {
                mode,
                length,
                passphrase_words,
                min_numbers,
                ..
            } = &mut app.overlay
            {
                match mode {
                    GeneratorMode::Password => *length = (*length).saturating_sub(1).max(8),
                    GeneratorMode::Passphrase => {
                        *passphrase_words = (*passphrase_words).saturating_sub(1).max(3)
                    }
                    GeneratorMode::Username => {}
                }
                if *mode == GeneratorMode::Password {
                    *min_numbers = (*min_numbers).saturating_sub(1);
                }
            }
            app.clamp_generator_overlay();
        }
        KeyCode::Char('{') if is_typing(&key) => {
            if let Overlay::Generator { min_special, .. } = &mut app.overlay {
                *min_special = (*min_special).saturating_sub(1);
            }
            app.clamp_generator_overlay();
        }
        KeyCode::Char('}') if is_typing(&key) => {
            if let Overlay::Generator { min_special, .. } = &mut app.overlay {
                *min_special = (*min_special + 1).min(10);
            }
            app.clamp_generator_overlay();
        }
        KeyCode::Char('u') if is_typing(&key) => {
            if let Overlay::Generator {
                mode, uppercase, ..
            } = &mut app.overlay
            {
                if *mode == GeneratorMode::Password {
                    *uppercase = !*uppercase;
                }
            }
            app.clamp_generator_overlay();
        }
        KeyCode::Char('l') if is_typing(&key) => {
            if let Overlay::Generator {
                mode, lowercase, ..
            } = &mut app.overlay
            {
                if *mode == GeneratorMode::Password {
                    *lowercase = !*lowercase;
                }
            }
            app.clamp_generator_overlay();
        }
        KeyCode::Char('d') if is_typing(&key) => {
            if let Overlay::Generator { mode, digits, .. } = &mut app.overlay {
                if *mode == GeneratorMode::Password {
                    *digits = !*digits;
                }
            }
            app.clamp_generator_overlay();
        }
        KeyCode::Char('s') if is_typing(&key) => {
            if let Overlay::Generator { mode, symbols, .. } = &mut app.overlay {
                if *mode == GeneratorMode::Password {
                    *symbols = !*symbols;
                }
            }
            app.clamp_generator_overlay();
        }
        KeyCode::Char('a') if is_typing(&key) => {
            if let Overlay::Generator {
                mode,
                avoid_ambiguous,
                ..
            } = &mut app.overlay
            {
                if *mode == GeneratorMode::Password {
                    *avoid_ambiguous = !*avoid_ambiguous;
                }
            }
            app.clamp_generator_overlay();
        }
        KeyCode::Char('C') if is_typing(&key) => {
            if let Overlay::Generator {
                mode,
                passphrase_capitalize,
                ..
            } = &mut app.overlay
            {
                if *mode == GeneratorMode::Passphrase {
                    *passphrase_capitalize = !*passphrase_capitalize;
                }
            }
            app.regenerate_password();
        }
        KeyCode::Char('n') if is_typing(&key) => {
            if let Overlay::Generator {
                mode,
                passphrase_include_number,
                ..
            } = &mut app.overlay
            {
                if *mode == GeneratorMode::Passphrase {
                    *passphrase_include_number = !*passphrase_include_number;
                }
            }
            app.regenerate_password();
        }
        KeyCode::Char('w') if is_typing(&key) => {
            if let Overlay::Generator {
                mode,
                passphrase_words,
                ..
            } = &mut app.overlay
            {
                if *mode == GeneratorMode::Passphrase {
                    *passphrase_words = (*passphrase_words + 1).min(20);
                }
            }
            app.regenerate_password();
        }
        KeyCode::Char('W') if is_typing(&key) => {
            if let Overlay::Generator {
                mode,
                passphrase_words,
                ..
            } = &mut app.overlay
            {
                if *mode == GeneratorMode::Passphrase {
                    *passphrase_words = (*passphrase_words).saturating_sub(1).max(3);
                }
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
            if let Overlay::FolderForm { name, .. } = &mut app.overlay {
                name.pop();
            }
            false
        }
        KeyCode::Char(c) if is_typing(&key) => {
            if let Overlay::FolderForm { name, .. } = &mut app.overlay {
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

fn handle_command_palette(app: &mut App, key: KeyEvent) -> bool {
    use crate::action::Action;
    match key.code {
        KeyCode::Esc => {
            app.close_overlay();
        }
        KeyCode::Down | KeyCode::Char('j') if is_typing(&key) || key.code == KeyCode::Down => {
            let n = app.palette_filtered_actions().len();
            if let Overlay::CommandPalette { selected, .. } = &mut app.overlay {
                if n > 0 {
                    *selected = (*selected + 1) % n;
                }
            }
        }
        KeyCode::Up | KeyCode::Char('k') if is_typing(&key) || key.code == KeyCode::Up => {
            let n = app.palette_filtered_actions().len();
            if let Overlay::CommandPalette { selected, .. } = &mut app.overlay {
                if n > 0 {
                    *selected = if *selected == 0 { n - 1 } else { *selected - 1 };
                }
            }
        }
        KeyCode::Backspace | KeyCode::Delete => {
            if let Overlay::CommandPalette {
                query, selected, ..
            } = &mut app.overlay
            {
                query.pop();
                *selected = 0;
            }
        }
        KeyCode::Char(c) if is_typing(&key) => {
            if let Overlay::CommandPalette {
                query, selected, ..
            } = &mut app.overlay
            {
                push_char(query, c);
                *selected = 0;
            }
        }
        KeyCode::Enter => {
            let action = match &app.overlay {
                Overlay::CommandPalette { selected, .. } => {
                    app.palette_filtered_actions().get(*selected).cloned()
                }
                _ => None,
            };
            if let Some(action) = action {
                let keep_open = matches!(action, Action::OpenCommandPalette);
                app.invoke_palette_action(action);
                if !keep_open {
                    app.close_overlay();
                }
            }
        }
        _ => {}
    }
    false
}

fn handle_password_history(app: &mut App, key: KeyEvent) -> bool {
    if key.code == KeyCode::Esc {
        app.close_overlay();
    }
    false
}

fn handle_health_report(app: &mut App, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Esc => app.close_overlay(),
        KeyCode::Char('h') if is_typing(&key) => app.toggle_hibp_opt_in(),
        KeyCode::Char('e') if is_typing(&key) => app.toggle_hibp_email_opt_in(),
        KeyCode::Char('j') | KeyCode::Down => {
            if let Overlay::HealthReport { scroll, .. } = &mut app.overlay {
                *scroll = scroll.saturating_add(1);
            }
        }
        KeyCode::Char('k') | KeyCode::Up => {
            if let Overlay::HealthReport { scroll, .. } = &mut app.overlay {
                *scroll = scroll.saturating_sub(1);
            }
        }
        _ => {}
    }
    false
}

async fn handle_account_settings(app: &mut App, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Esc => app.close_overlay(),
        KeyCode::Char('h') if is_typing(&key) => {
            if app.using_mock {
                if let Overlay::AccountSettings { status, .. } = &mut app.overlay {
                    *status = "Mock mode — no server".into();
                }
            } else if let Some(session) = app.session.as_ref() {
                match session.fingerprint_phrase() {
                    Ok(p) => {
                        if let Overlay::AccountSettings { status, .. } = &mut app.overlay {
                            *status = format!("Fingerprint: {p}");
                        }
                    }
                    Err(e) => app.set_status(format!("Fingerprint: {e}")),
                }
            }
        }
        KeyCode::Char('H') if is_typing(&key) => {
            if let Some(session) = app.session.as_ref() {
                match session.request_password_hint().await {
                    Ok(()) => {
                        if let Overlay::AccountSettings { status, .. } = &mut app.overlay {
                            *status = "Password hint email requested".into();
                        }
                    }
                    Err(e) => app.set_status(format!("Hint request failed: {e}")),
                }
            }
        }
        KeyCode::Char('p') if is_typing(&key) => {
            app.overlay = Overlay::ChangeMasterPassword {
                old: String::new(),
                new: String::new(),
                confirm: String::new(),
                hint: String::new(),
                field: ChangePasswordField::Old,
                error: None,
            };
        }
        KeyCode::Char('i') if is_typing(&key) => {
            app.open_pin_setup();
        }
        KeyCode::Char('c') if is_typing(&key) => {
            app.clear_pin_from_ui();
        }
        KeyCode::Char('s') if is_typing(&key) => {
            app.toggle_ssh_agent();
        }
        KeyCode::Char('a') if is_typing(&key) => {
            app.open_account_tools();
        }
        _ => {}
    }
    false
}

fn handle_pin_setup(app: &mut App, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Esc => app.close_overlay(),
        KeyCode::Enter => app.submit_pin_setup(),
        KeyCode::Tab | KeyCode::Down => {
            if let Overlay::PinSetup { field, .. } = &mut app.overlay {
                *field = field.next();
            }
        }
        KeyCode::BackTab | KeyCode::Up => {
            if let Overlay::PinSetup { field, .. } = &mut app.overlay {
                *field = field.prev();
            }
        }
        KeyCode::Backspace | KeyCode::Delete => {
            if let Overlay::PinSetup {
                field,
                pin,
                confirm,
                status,
            } = &mut app.overlay
            {
                match field {
                    PinSetupField::Pin => {
                        pin.pop();
                    }
                    PinSetupField::Confirm => {
                        confirm.pop();
                    }
                }
                status.clear();
            }
        }
        KeyCode::Char(c) if is_typing(&key) => {
            if let Overlay::PinSetup {
                field,
                pin,
                confirm,
                status,
            } = &mut app.overlay
            {
                match field {
                    PinSetupField::Pin => push_char(pin, c),
                    PinSetupField::Confirm => push_char(confirm, c),
                }
                status.clear();
            }
        }
        _ => {}
    }
    false
}

async fn handle_change_master_password(app: &mut App, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Esc => {
            app.overlay = Overlay::AccountSettings {
                section: 0,
                status: String::new(),
            };
        }
        KeyCode::Enter => {
            app.submit_change_master_password().await;
        }
        KeyCode::Tab | KeyCode::Down => {
            if let Overlay::ChangeMasterPassword { field, .. } = &mut app.overlay {
                *field = field.next();
            }
        }
        KeyCode::BackTab | KeyCode::Up => {
            if let Overlay::ChangeMasterPassword { field, .. } = &mut app.overlay {
                *field = field.prev();
            }
        }
        KeyCode::Backspace | KeyCode::Delete => {
            if let Overlay::ChangeMasterPassword {
                field,
                old,
                new,
                confirm,
                hint,
                error,
            } = &mut app.overlay
            {
                match field {
                    ChangePasswordField::Old => {
                        old.pop();
                    }
                    ChangePasswordField::New => {
                        new.pop();
                    }
                    ChangePasswordField::Confirm => {
                        confirm.pop();
                    }
                    ChangePasswordField::Hint => {
                        hint.pop();
                    }
                }
                *error = None;
            }
        }
        KeyCode::Char(c) if is_typing(&key) => {
            if let Overlay::ChangeMasterPassword {
                field,
                old,
                new,
                confirm,
                hint,
                error,
            } = &mut app.overlay
            {
                match field {
                    ChangePasswordField::Old => push_char(old, c),
                    ChangePasswordField::New => push_char(new, c),
                    ChangePasswordField::Confirm => push_char(confirm, c),
                    ChangePasswordField::Hint => push_char(hint, c),
                }
                *error = None;
            }
        }
        _ => {}
    }
    false
}

async fn handle_send_form(app: &mut App, key: KeyEvent) -> bool {
    use crate::send_form::SendFormField;
    if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('s')) {
        app.submit_send_form().await;
        return false;
    }
    // Ctrl+t: switch text <-> file (new Sends only).
    if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('t')) {
        if let Overlay::SendForm { form } = &mut app.overlay {
            form.toggle_kind();
        }
        return false;
    }
    match key.code {
        KeyCode::Esc => app.close_overlay(),
        KeyCode::Tab | KeyCode::Down => {
            if let Overlay::SendForm { form } = &mut app.overlay {
                form.next_field();
            }
        }
        KeyCode::BackTab | KeyCode::Up => {
            if let Overlay::SendForm { form } = &mut app.overlay {
                form.prev_field();
            }
        }
        KeyCode::Char(' ') if is_typing(&key) => {
            if let Overlay::SendForm { form } = &mut app.overlay {
                if form.field.is_toggle()
                    || matches!(form.field, SendFormField::Password if form.has_password)
                {
                    form.toggle_current();
                } else {
                    form.push_char(' ');
                }
            }
        }
        KeyCode::Char(c) if is_typing(&key) => {
            if let Overlay::SendForm { form } = &mut app.overlay {
                form.push_char(c);
            }
        }
        KeyCode::Backspace | KeyCode::Delete => {
            if let Overlay::SendForm { form } = &mut app.overlay {
                form.backspace();
            }
        }
        _ => {}
    }
    false
}

async fn handle_receive_send(app: &mut App, key: KeyEvent) -> bool {
    let (received, is_file) = match &app.overlay {
        Overlay::ReceiveSend { state } => (
            state.received.is_some(),
            state.received.as_ref().is_some_and(|r| r.is_file()),
        ),
        _ => return false,
    };
    let view_only = received && !is_file;
    if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('s')) {
        if is_file {
            app.save_received_send_file().await;
        } else if !received {
            app.submit_receive_send().await;
        }
        return false;
    }
    match key.code {
        KeyCode::Esc => app.close_overlay(),
        KeyCode::Enter => {
            if !received {
                app.submit_receive_send().await;
            } else if is_file {
                app.save_received_send_file().await;
            }
        }
        KeyCode::Tab | KeyCode::Down | KeyCode::BackTab | KeyCode::Up => {
            if let Overlay::ReceiveSend { state } = &mut app.overlay {
                state.next_field();
            }
        }
        KeyCode::Char(c) if is_typing(&key) && view_only => match c {
            'r' => app.toggle_received_send_reveal(),
            'c' | 'y' => app.copy_received_send_text(),
            _ => {}
        },
        KeyCode::Char(c) if is_typing(&key) => {
            if let Overlay::ReceiveSend { state } = &mut app.overlay {
                if !c.is_control() {
                    state.push_char(c);
                }
            }
        }
        KeyCode::Backspace | KeyCode::Delete => {
            if let Overlay::ReceiveSend { state } = &mut app.overlay {
                state.backspace();
            }
        }
        _ => {}
    }
    false
}

async fn handle_attachment_path(app: &mut App, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Esc => app.close_overlay(),
        KeyCode::Enter if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.submit_attachment_upload().await;
        }
        KeyCode::Char(c) if is_typing(&key) => {
            if let Overlay::AttachmentPath { path } = &mut app.overlay {
                push_char(path, c);
            }
        }
        KeyCode::Backspace | KeyCode::Delete => {
            if let Overlay::AttachmentPath { path } = &mut app.overlay {
                path.pop();
            }
        }
        _ => {}
    }
    false
}

async fn handle_card_form(app: &mut App, key: KeyEvent) -> bool {
    if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('s')) {
        app.submit_card_form().await;
        return false;
    }
    match key.code {
        KeyCode::Esc => app.close_overlay(),
        KeyCode::Tab | KeyCode::Down => {
            if let Overlay::CardForm { field, .. } = &mut app.overlay {
                *field = field.next();
            }
        }
        KeyCode::BackTab | KeyCode::Up => {
            if let Overlay::CardForm { field, .. } = &mut app.overlay {
                *field = field.prev();
            }
        }
        KeyCode::Char(' ') if is_typing(&key) => {
            if let Overlay::CardForm {
                field: CardField::Reprompt,
                reprompt,
                ..
            } = &mut app.overlay
            {
                *reprompt = !*reprompt;
            }
        }
        KeyCode::Char(c) if is_typing(&key) => {
            if let Overlay::CardForm {
                field,
                name,
                cardholder_name,
                brand,
                number,
                exp_month,
                exp_year,
                code,
                notes,
                ..
            } = &mut app.overlay
            {
                match field {
                    CardField::Name => push_char(name, c),
                    CardField::Cardholder => push_char(cardholder_name, c),
                    CardField::Brand => push_char(brand, c),
                    CardField::Number => push_char(number, c),
                    CardField::ExpMonth => push_char(exp_month, c),
                    CardField::ExpYear => push_char(exp_year, c),
                    CardField::Code => push_char(code, c),
                    CardField::Notes => push_char(notes, c),
                    CardField::Reprompt => {}
                }
            }
        }
        _ => {}
    }
    false
}

async fn handle_identity_form(app: &mut App, key: KeyEvent) -> bool {
    if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('s')) {
        app.submit_identity_form().await;
        return false;
    }
    match key.code {
        KeyCode::Esc => app.close_overlay(),
        KeyCode::Tab | KeyCode::Down => {
            if let Overlay::IdentityForm { field, .. } = &mut app.overlay {
                *field = field.next();
            }
        }
        KeyCode::BackTab | KeyCode::Up => {
            if let Overlay::IdentityForm { field, .. } = &mut app.overlay {
                *field = field.prev();
            }
        }
        KeyCode::Char(' ') if is_typing(&key) => {
            if let Overlay::IdentityForm {
                field: IdentityField::Reprompt,
                reprompt,
                ..
            } = &mut app.overlay
            {
                *reprompt = !*reprompt;
            }
        }
        KeyCode::Char(c) if is_typing(&key) => {
            if let Overlay::IdentityForm {
                field,
                name,
                title,
                first_name,
                middle_name,
                last_name,
                email,
                phone,
                username,
                company,
                address1,
                address2,
                address3,
                city,
                state,
                postal_code,
                country,
                ssn,
                passport,
                license,
                notes,
                ..
            } = &mut app.overlay
            {
                match field {
                    IdentityField::Name => push_char(name, c),
                    IdentityField::Title => push_char(title, c),
                    IdentityField::FirstName => push_char(first_name, c),
                    IdentityField::MiddleName => push_char(middle_name, c),
                    IdentityField::LastName => push_char(last_name, c),
                    IdentityField::Email => push_char(email, c),
                    IdentityField::Phone => push_char(phone, c),
                    IdentityField::Username => push_char(username, c),
                    IdentityField::Company => push_char(company, c),
                    IdentityField::Address1 => push_char(address1, c),
                    IdentityField::Address2 => push_char(address2, c),
                    IdentityField::Address3 => push_char(address3, c),
                    IdentityField::City => push_char(city, c),
                    IdentityField::State => push_char(state, c),
                    IdentityField::PostalCode => push_char(postal_code, c),
                    IdentityField::Country => push_char(country, c),
                    IdentityField::Ssn => push_char(ssn, c),
                    IdentityField::Passport => push_char(passport, c),
                    IdentityField::License => push_char(license, c),
                    IdentityField::Notes => push_char(notes, c),
                    IdentityField::Reprompt => {}
                }
            }
        }
        _ => {}
    }
    false
}

async fn handle_ssh_key_form(app: &mut App, key: KeyEvent) -> bool {
    if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('s')) {
        app.submit_ssh_key_form().await;
        return false;
    }
    match key.code {
        KeyCode::Esc => app.close_overlay(),
        KeyCode::Tab | KeyCode::Down => {
            if let Overlay::SshKeyForm { field, .. } = &mut app.overlay {
                *field = field.next();
            }
        }
        KeyCode::BackTab | KeyCode::Up => {
            if let Overlay::SshKeyForm { field, .. } = &mut app.overlay {
                *field = field.prev();
            }
        }
        KeyCode::Char(c) if is_typing(&key) => {
            if let Overlay::SshKeyForm {
                field,
                name,
                private_key,
                public_key,
                fingerprint,
                notes,
                ..
            } = &mut app.overlay
            {
                match field {
                    SshKeyField::Name => push_char(name, c),
                    SshKeyField::PrivateKey => push_char(private_key, c),
                    SshKeyField::PublicKey => push_char(public_key, c),
                    SshKeyField::Fingerprint => push_char(fingerprint, c),
                    SshKeyField::Notes => push_char(notes, c),
                }
            }
        }
        _ => {}
    }
    false
}

async fn handle_move_to_folder(app: &mut App, key: KeyEvent) -> bool {
    let len = app.folders.len() + 1;
    match key.code {
        KeyCode::Esc => app.close_overlay(),
        KeyCode::Enter => {
            if !app.busy {
                app.confirm_move_to_folder().await;
            }
        }
        KeyCode::Char('j') | KeyCode::Down if is_typing(&key) || key.code == KeyCode::Down => {
            if let Overlay::MoveToFolder { selected, .. } = &mut app.overlay {
                *selected = (*selected + 1) % len.max(1);
            }
        }
        KeyCode::Char('k') | KeyCode::Up if is_typing(&key) || key.code == KeyCode::Up => {
            if let Overlay::MoveToFolder { selected, .. } = &mut app.overlay {
                *selected = if *selected == 0 {
                    len.saturating_sub(1)
                } else {
                    *selected - 1
                };
            }
        }
        _ => {}
    }
    false
}

async fn handle_share_to_org(app: &mut App, key: KeyEvent) -> bool {
    let wizard = match &app.overlay {
        Overlay::ShareToOrg {
            step,
            org_index,
            groups,
            ..
        } => Some((*step, *org_index, groups.clone())),
        _ => None,
    };
    let Some((step, org_index, groups)) = wizard else {
        return false;
    };
    let org_len = groups.len();

    match key.code {
        KeyCode::Esc => {
            if step == ShareToOrgStep::PickCollections {
                if let Overlay::ShareToOrg {
                    step,
                    collection_cursor,
                    selected_collections,
                    ..
                } = &mut app.overlay
                {
                    *step = ShareToOrgStep::PickOrganization;
                    *collection_cursor = 0;
                    selected_collections.clear();
                }
            } else {
                app.close_overlay();
            }
        }
        KeyCode::Enter if !app.busy => {
            if step == ShareToOrgStep::PickOrganization {
                if org_len == 0 {
                    app.set_status("No organization to share to");
                } else {
                    let cols = writable_share_collections(&groups, org_index);
                    if cols.is_empty() {
                        app.set_status("No writable collections in this org");
                    } else if let Overlay::ShareToOrg {
                        step,
                        collection_cursor,
                        selected_collections,
                        ..
                    } = &mut app.overlay
                    {
                        *step = ShareToOrgStep::PickCollections;
                        *collection_cursor = 0;
                        selected_collections.clear();
                        if cols.len() == 1 {
                            selected_collections.insert(cols[0].0.clone());
                        }
                    }
                }
            } else {
                app.execute_share_to_org().await;
            }
        }
        KeyCode::Char('j') | KeyCode::Down if is_typing(&key) || key.code == KeyCode::Down => {
            if let Overlay::ShareToOrg {
                step,
                org_index,
                collection_cursor,
                ..
            } = &mut app.overlay
            {
                match step {
                    ShareToOrgStep::PickOrganization => {
                        *org_index = (*org_index + 1) % org_len.max(1);
                    }
                    ShareToOrgStep::PickCollections => {
                        let len = writable_share_collections(&groups, *org_index).len();
                        if len > 0 {
                            *collection_cursor = (*collection_cursor + 1) % len;
                        }
                    }
                }
            }
        }
        KeyCode::Char('k') | KeyCode::Up if is_typing(&key) || key.code == KeyCode::Up => {
            if let Overlay::ShareToOrg {
                step,
                org_index,
                collection_cursor,
                ..
            } = &mut app.overlay
            {
                match step {
                    ShareToOrgStep::PickOrganization => {
                        *org_index = if *org_index == 0 {
                            org_len.saturating_sub(1)
                        } else {
                            *org_index - 1
                        };
                    }
                    ShareToOrgStep::PickCollections => {
                        let len = writable_share_collections(&groups, *org_index).len();
                        if len > 0 {
                            *collection_cursor = if *collection_cursor == 0 {
                                len - 1
                            } else {
                                *collection_cursor - 1
                            };
                        }
                    }
                }
            }
        }
        KeyCode::Char(' ') if is_typing(&key) && step == ShareToOrgStep::PickCollections => {
            if let Overlay::ShareToOrg {
                org_index,
                collection_cursor,
                selected_collections,
                ..
            } = &mut app.overlay
            {
                let cols = writable_share_collections(&groups, *org_index);
                if let Some((id, _)) = cols.get(*collection_cursor) {
                    if selected_collections.contains(id) {
                        selected_collections.remove(id);
                    } else {
                        selected_collections.insert(id.clone());
                    }
                }
            }
        }
        _ => {}
    }
    false
}
