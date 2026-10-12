//! Key handling for the P4 power-user features.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::app::{App, DomainInput, FocusPane, Overlay, PowerOverlay, Screen};
use vault_session::{format_domain_group, parse_domain_group};

fn is_typing(key: &KeyEvent) -> bool {
    !key.modifiers
        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT | KeyModifiers::SUPER)
}

fn ctrl(key: &KeyEvent, c: char) -> bool {
    key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char(c)
}

/// New vault-browser shortcuts. Returns `Some(quit)` when the key was consumed.
///
/// `a` auto-type · `T` type TOTP · `S` copy sequence · `Q` QR · `E` edit notes in `$EDITOR` ·
/// `s` Quick Send (sidebar) / sort cycle (items·detail) · `V` attachments · `D` domain rules.
pub async fn handle_vault_key(app: &mut App, key: &KeyEvent) -> Option<bool> {
    if app.screen != Screen::Vault || !is_typing(key) {
        return None;
    }
    match key.code {
        KeyCode::Char('a') => app.start_autotype(false),
        KeyCode::Char('T') => app.start_autotype(true),
        KeyCode::Char('S') => app.copy_sequence_step(),
        KeyCode::Char('Q') => app.open_qr(),
        KeyCode::Char('E') => app.request_notes_editor(),
        KeyCode::Char('s') => {
            if app.focus == FocusPane::Folders {
                app.open_send_form();
            } else {
                app.cycle_sort();
            }
        }
        KeyCode::Char('V') => app.open_attachments_overlay(),
        KeyCode::Char('D') => {
            if !app.busy {
                app.open_domain_rules().await;
            }
        }
        _ => return None,
    }
    Some(false)
}

/// Shortcuts that work inside existing form overlays (before their own handlers).
///
/// `Ctrl+e` edits the notes field in `$EDITOR`; `Ctrl+g` in the SSH key form generates Ed25519.
pub async fn pre_overlay_key(app: &mut App, key: &KeyEvent) -> Option<bool> {
    if !matches!(app.overlay, Overlay::SshKeyForm { .. }) || !ctrl(key, 'g') {
        app.power.keygen_armed = false;
    }
    if ctrl(key, 'e')
        && matches!(
            app.overlay,
            Overlay::ItemForm { .. }
                | Overlay::NoteForm { .. }
                | Overlay::CardForm { .. }
                | Overlay::IdentityForm { .. }
                | Overlay::SshKeyForm { .. }
        )
    {
        app.request_notes_editor();
        return Some(false);
    }
    if ctrl(key, 'g') && matches!(app.overlay, Overlay::SshKeyForm { .. }) {
        app.generate_ssh_key_into_form();
        return Some(false);
    }
    None
}

/// Handle keys for `Overlay::Power(..)`.
pub async fn handle_power_overlay(app: &mut App, key: KeyEvent) -> bool {
    let Overlay::Power(p) = &app.overlay else {
        return false;
    };
    match p {
        PowerOverlay::Qr { .. } => handle_qr(app, key),
        PowerOverlay::Attachments { .. } => handle_attachments(app, key).await,
        PowerOverlay::DomainRules { .. } => handle_domain_rules(app, key).await,
        PowerOverlay::SshAgentConfirm { .. } => handle_ssh_confirm(app, key),
    }
    false
}

fn handle_qr(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') | KeyCode::Enter => app.close_power_overlay(),
        KeyCode::Tab | KeyCode::Right | KeyCode::Char('n') | KeyCode::Char('l') => app.qr_cycle(),
        _ => {}
    }
    app.touch();
}

fn handle_ssh_confirm(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Char('t') | KeyCode::Char('T') => {
            if let Overlay::Power(PowerOverlay::SshAgentConfirm { each_use, .. }) = &mut app.overlay
            {
                *each_use = !*each_use;
            }
        }
        KeyCode::Enter | KeyCode::Char('y') | KeyCode::Char('Y') => app.confirm_ssh_agent_start(),
        KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => {
            app.close_power_overlay();
            app.set_status("SSH agent not started");
        }
        _ => {}
    }
}

async fn handle_attachments(app: &mut App, key: KeyEvent) {
    // Preview sub-view: scroll / close.
    let previewing = matches!(
        &app.overlay,
        Overlay::Power(PowerOverlay::Attachments {
            preview: Some(_),
            ..
        })
    );
    if previewing {
        if let Overlay::Power(PowerOverlay::Attachments { preview, .. }) = &mut app.overlay {
            if let Some(pv) = preview {
                match key.code {
                    KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('p') => *preview = None,
                    KeyCode::Down | KeyCode::Char('j') => {
                        pv.scroll = (pv.scroll + 1).min(pv.lines.len().saturating_sub(1));
                    }
                    KeyCode::Up | KeyCode::Char('k') => pv.scroll = pv.scroll.saturating_sub(1),
                    KeyCode::PageDown => {
                        pv.scroll = (pv.scroll + 10).min(pv.lines.len().saturating_sub(1));
                    }
                    KeyCode::PageUp => pv.scroll = pv.scroll.saturating_sub(10),
                    KeyCode::Home => pv.scroll = 0,
                    _ => {}
                }
            }
        }
        app.touch();
        return;
    }

    let (selected, len) = match &app.overlay {
        Overlay::Power(PowerOverlay::Attachments {
            selected, items, ..
        }) => (*selected, items.len()),
        _ => return,
    };
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => app.close_power_overlay(),
        KeyCode::Down | KeyCode::Char('j') => {
            if let Overlay::Power(PowerOverlay::Attachments { selected, .. }) = &mut app.overlay {
                if len > 0 {
                    *selected = (*selected + 1) % len;
                }
            }
        }
        KeyCode::Up | KeyCode::Char('k') => {
            if let Overlay::Power(PowerOverlay::Attachments { selected, .. }) = &mut app.overlay {
                if len > 0 {
                    *selected = (*selected + len - 1) % len;
                }
            }
        }
        KeyCode::Enter | KeyCode::Char('o') => {
            if !app.busy {
                app.open_attachment_externally(selected).await;
            }
        }
        KeyCode::Char('p') => {
            if !app.busy {
                app.preview_attachment(selected).await;
            }
        }
        KeyCode::Char('s') if !app.busy => {
            app.download_attachment_at(selected).await;
        }
        _ => {}
    }
    app.touch();
}

async fn handle_domain_rules(app: &mut App, key: KeyEvent) {
    // Inline text input mode.
    let editing = matches!(
        &app.overlay,
        Overlay::Power(PowerOverlay::DomainRules { input: Some(_), .. })
    );
    if editing {
        handle_domain_input(app, key);
        return;
    }

    if ctrl(&key, 's') || (is_typing(&key) && key.code == KeyCode::Char('s')) {
        if !app.busy {
            app.save_domain_rules().await;
        }
        return;
    }

    let Overlay::Power(PowerOverlay::DomainRules {
        rules,
        selected,
        input,
        dirty,
        status,
        confirm_discard,
    }) = &mut app.overlay
    else {
        return;
    };
    let custom = rules.custom_groups.len();
    let rows = custom + rules.global_groups.len();

    if key.code != KeyCode::Esc {
        *confirm_discard = false;
    }
    match key.code {
        KeyCode::Esc => {
            if *dirty && !*confirm_discard {
                *confirm_discard = true;
                *status = "Unsaved changes — press Esc again to discard, s to save".into();
            } else {
                app.close_power_overlay();
            }
        }
        KeyCode::Down | KeyCode::Char('j') if rows > 0 => *selected = (*selected + 1) % rows,
        KeyCode::Up | KeyCode::Char('k') if rows > 0 => *selected = (*selected + rows - 1) % rows,
        KeyCode::Char('a') | KeyCode::Char('n') => {
            *input = Some(DomainInput {
                index: None,
                text: String::new(),
            });
            status.clear();
        }
        KeyCode::Char('e') | KeyCode::Enter | KeyCode::Char(' ') | KeyCode::Char('x') => {
            if *selected < custom {
                if matches!(key.code, KeyCode::Char('e') | KeyCode::Enter) {
                    *input = Some(DomainInput {
                        index: Some(*selected),
                        text: format_domain_group(&rules.custom_groups[*selected]),
                    });
                }
            } else if let Some(g) = rules.global_groups.get_mut(*selected - custom) {
                g.excluded = !g.excluded;
                *dirty = true;
                *status = if g.excluded {
                    "Global group excluded".into()
                } else {
                    "Global group enabled".into()
                };
            }
        }
        KeyCode::Char('d') | KeyCode::Delete if *selected < custom => {
            rules.custom_groups.remove(*selected);
            *dirty = true;
            let rows = rows - 1;
            if *selected >= rows {
                *selected = rows.saturating_sub(1);
            }
            *status = "Group removed".into();
        }
        _ => {}
    }
    app.touch();
}

fn handle_domain_input(app: &mut App, key: KeyEvent) {
    let Overlay::Power(PowerOverlay::DomainRules {
        rules,
        selected,
        input,
        dirty,
        status,
        ..
    }) = &mut app.overlay
    else {
        return;
    };
    let Some(buf) = input.as_mut() else {
        return;
    };
    match key.code {
        KeyCode::Esc => *input = None,
        KeyCode::Backspace => {
            buf.text.pop();
        }
        KeyCode::Enter => {
            let group = parse_domain_group(&buf.text);
            if group.len() < 2 {
                *status = "Enter at least two domains (comma separated)".into();
                return;
            }
            match buf.index {
                Some(i) if i < rules.custom_groups.len() => rules.custom_groups[i] = group,
                _ => {
                    rules.custom_groups.push(group);
                    *selected = rules.custom_groups.len() - 1;
                }
            }
            *dirty = true;
            status.clear();
            *input = None;
        }
        KeyCode::Char(c) if is_typing(&key) && !c.is_control() => buf.text.push(c),
        _ => {}
    }
}
