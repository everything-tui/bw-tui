//! Modal overlays: item form, generator, folder create, delete confirm, reprompt.

use ratatui::layout::{Alignment, Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{App, DeleteTarget, EditField, NoteField, Overlay, uri_match_label};
use crate::ui::form::draw_form_field;
use crate::ui::layout::center_fixed;

const ACCENT: Color = Color::Rgb(175, 82, 222);
const MUTED: Color = Color::DarkGray;
const FG: Color = Color::White;
const ERR: Color = Color::LightRed;

pub fn draw_overlay(frame: &mut Frame, app: &App) {
    match &app.overlay {
        Overlay::None => {}
        Overlay::ItemForm { .. } => draw_item_form(frame, app),
        Overlay::NoteForm { .. } => draw_note_form(frame, app),
        Overlay::NewItemType { .. } => draw_new_item_type(frame, app),
        Overlay::Generator { .. } => draw_generator(frame, app),
        Overlay::FolderForm { .. } => draw_folder_form(frame, app),
        Overlay::ConfirmDelete { .. } => draw_confirm_delete(frame, app),
        Overlay::Reprompt { .. } => draw_reprompt(frame, app),
        Overlay::ProfileManager { .. } => super::profiles::draw_profile_manager(frame, app),
        Overlay::CommandPalette { .. } => super::palette::draw_command_palette(frame, app),
        Overlay::PasswordHistory => super::history::draw_password_history(frame, app),
        Overlay::HealthReport { .. } => super::health::draw_health_report(frame, app),
        Overlay::AccountSettings { .. } => super::account::draw_account_settings(frame, app),
        Overlay::SendForm { .. } => super::account::draw_send_form(frame, app),
        Overlay::CardForm { .. } => super::account::draw_card_form(frame, app),
        Overlay::PinSetup { .. } => super::account::draw_pin_setup(frame, app),
        Overlay::ChangeMasterPassword { .. } => {
            super::account::draw_change_master_password(frame, app)
        }
        Overlay::AttachmentPath { .. } => draw_attachment_path(frame, app),
        Overlay::IdentityForm { .. } => draw_identity_form(frame, app),
        Overlay::SshKeyForm { .. } => draw_ssh_key_form(frame, app),
        Overlay::MoveToFolder { .. } => draw_move_to_folder(frame, app),
    }
}

fn draw_attachment_path(frame: &mut Frame, app: &App) {
    let Overlay::AttachmentPath { path } = &app.overlay else {
        return;
    };
    let area = frame.area();
    let popup = center_fixed(56, 7, area);
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(" Upload attachment ")
        .title_bottom(Span::styled(
            " Ctrl+s upload · Esc cancel ",
            Style::default().fg(MUTED),
        ));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    draw_form_field(frame, inner, "Path", path, true, false);
}

fn draw_item_form(frame: &mut Frame, app: &App) {
    let Overlay::ItemForm {
        editing_id,
        name,
        username,
        password,
        totp,
        uris,
        uri_line,
        notes,
        reprompt,
        field,
    } = &app.overlay
    else {
        return;
    };

    let area = frame.area();
    let popup = center_fixed(68, 26, area);
    frame.render_widget(Clear, popup);

    let title = if editing_id.is_some() {
        " Edit login "
    } else {
        " New login "
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(Span::styled(
            title,
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ))
        .title_bottom(Span::styled(
            " Tab · Ctrl+s save · URI: m match · +/- lines · [/] line · Esc ",
            Style::default().fg(MUTED),
        ));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(3),
            Constraint::Length(2),
        ])
        .split(inner);

    draw_form_field(frame, rows[0], "Name", name, *field == EditField::Name, false);
    draw_form_field(
        frame,
        rows[1],
        "Username",
        username,
        *field == EditField::Username,
        false,
    );
    draw_form_field(
        frame,
        rows[2],
        "Password",
        password,
        *field == EditField::Password,
        true,
    );
    draw_form_field(frame, rows[3], "TOTP", totp, *field == EditField::Totp, true);
    let uri_idx = (*uri_line).min(uris.len().saturating_sub(1));
    let uri_active = *field == EditField::Uri;
    let uri_label = format!(
        "URI {}/{} [{}]",
        uri_idx + 1,
        uris.len().max(1),
        uri_match_label(uris.get(uri_idx).map(|u| u.match_type).unwrap_or(0))
    );
    let uri_text = uris
        .get(uri_idx)
        .map(|u| u.uri.as_str())
        .unwrap_or("");
    draw_form_field(frame, rows[4], &uri_label, uri_text, uri_active, false);
    draw_form_field(
        frame,
        rows[5],
        "Notes",
        notes,
        *field == EditField::Notes,
        false,
    );
    let reprompt_label = format!("[{}] Require master password re-prompt", on(*reprompt));
    frame.render_widget(
        Paragraph::new(reprompt_label).style(if *field == EditField::Reprompt {
            Style::default().fg(ACCENT)
        } else {
            Style::default().fg(MUTED)
        }),
        rows[6],
    );
}

fn draw_note_form(frame: &mut Frame, app: &App) {
    let Overlay::NoteForm {
        editing_id,
        name,
        notes,
        field,
    } = &app.overlay
    else {
        return;
    };
    let area = frame.area();
    let popup = center_fixed(64, 16, area);
    frame.render_widget(Clear, popup);
    let title = if editing_id.is_some() {
        " Edit note "
    } else {
        " New note "
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(Span::styled(
            title,
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ))
        .title_bottom(Span::styled(
            " Tab fields · Ctrl+s / Enter save · Esc cancel ",
            Style::default().fg(MUTED),
        ));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(3)])
        .split(inner);
    draw_form_field(
        frame,
        rows[0],
        "Name",
        name,
        *field == NoteField::Name,
        false,
    );
    draw_form_field(
        frame,
        rows[1],
        "Notes",
        notes,
        *field == NoteField::Notes,
        false,
    );
}

fn draw_new_item_type(frame: &mut Frame, app: &App) {
    let Overlay::NewItemType { selected } = &app.overlay else {
        return;
    };
    let area = frame.area();
    let popup = center_fixed(40, 12, area);
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(Span::styled(
            " New item ",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ))
        .title_bottom(Span::styled(
            " j/k · Enter · Esc ",
            Style::default().fg(MUTED),
        ));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    let options = ["Login", "Secure note", "Card", "Identity", "SSH key"];
    let lines: Vec<Line> = options
        .iter()
        .enumerate()
        .map(|(i, label)| {
            let marker = if i == *selected { "› " } else { "  " };
            let style = if i == *selected {
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(FG)
            };
            Line::from(Span::styled(format!("{marker}{label}"), style))
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), inner);
}

fn draw_generator(frame: &mut Frame, app: &App) {
    use crate::app::{GeneratorMode, Overlay, UsernameKind};
    use vault_session::{password_entropy_for_string, password_strength_label};

    let Overlay::Generator {
        mode,
        username_kind,
        length,
        uppercase,
        lowercase,
        digits,
        symbols,
        avoid_ambiguous,
        min_numbers,
        min_special,
        passphrase_words,
        passphrase_separator,
        passphrase_capitalize,
        passphrase_include_number,
        preview,
        insert_to_form,
    } = &app.overlay
    else {
        return;
    };

    let area = frame.area();
    let popup = center_fixed(68, 18, area);
    frame.render_widget(Clear, popup);

    let title = match mode {
        GeneratorMode::Passphrase => " Passphrase generator ",
        GeneratorMode::Username => " Username generator ",
        GeneratorMode::Password => " Password generator ",
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(Span::styled(
            title,
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ))
        .title_bottom(Span::styled(
            if *insert_to_form {
                " Enter insert · m mode · r regen · Esc "
            } else {
                " Enter/c copy · m mode · r regen · Esc "
            },
            Style::default().fg(MUTED),
        ));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(2),
            Constraint::Length(2),
            Constraint::Length(2),
            Constraint::Min(1),
        ])
        .margin(1)
        .split(inner);

    frame.render_widget(
        Paragraph::new(preview.as_str())
            .style(Style::default().fg(FG).add_modifier(Modifier::BOLD))
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true }),
        rows[0],
    );

    let strength = if *mode == GeneratorMode::Password && !preview.is_empty() {
        let bits = password_entropy_for_string(preview);
        format!(
            "Strength: {} ({:.0} bits)",
            password_strength_label(bits),
            bits
        )
    } else {
        String::new()
    };
    frame.render_widget(
        Paragraph::new(strength)
            .style(Style::default().fg(MUTED))
            .alignment(Alignment::Center),
        rows[1],
    );

    let flags = match mode {
        GeneratorMode::Passphrase => format!(
            "words {passphrase_words}  sep '{passphrase_separator}'  [{}] Cap  [{}] number",
            on(*passphrase_capitalize),
            on(*passphrase_include_number),
        ),
        GeneratorMode::Username => format!(
            "kind: {}",
            match username_kind {
                UsernameKind::Word => "word",
                UsernameKind::Plus => "plus-address",
                UsernameKind::Catchall => "catch-all",
            }
        ),
        GeneratorMode::Password => format!(
            "len {length}  [{}] U  [{}] L  [{}] #  [{}] !  [{}] unambig  min# {min_numbers} min! {min_special}",
            on(*uppercase),
            on(*lowercase),
            on(*digits),
            on(*symbols),
            on(*avoid_ambiguous),
        ),
    };
    frame.render_widget(
        Paragraph::new(flags)
            .style(Style::default().fg(MUTED))
            .alignment(Alignment::Center),
        rows[2],
    );
    frame.render_widget(
        Paragraph::new("m cycle mode · k username kind · a unambig · [/] min# · {/} min!")
            .style(Style::default().fg(MUTED))
            .alignment(Alignment::Center),
        rows[3],
    );
}

fn on(v: bool) -> char {
    if v {
        'x'
    } else {
        ' '
    }
}

fn draw_folder_form(frame: &mut Frame, app: &App) {
    let Overlay::FolderForm { folder_id, name } = &app.overlay else {
        return;
    };

    let area = frame.area();
    let popup = center_fixed(48, 8, area);
    frame.render_widget(Clear, popup);

    let title = if folder_id.is_some() {
        " Rename folder "
    } else {
        " New folder "
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(Span::styled(
            title,
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ))
        .title_bottom(Span::styled(
            " Enter save · Esc cancel ",
            Style::default().fg(MUTED),
        ));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    draw_form_field(frame, inner, "Name", name, true, false);
}

fn draw_confirm_delete(frame: &mut Frame, app: &App) {
    let Overlay::ConfirmDelete { target } = &app.overlay else {
        return;
    };
    let (title, prompt) = match target {
        DeleteTarget::Item { name, .. } => (" Delete item ", format!("Move \"{name}\" to trash?")),
        DeleteTarget::Folder { name, .. } => (" Delete folder ", format!("Delete folder \"{name}\"?")),
        DeleteTarget::Send { name, .. } => (" Delete send ", format!("Delete send \"{name}\"?")),
        DeleteTarget::Attachment { name, .. } => {
            (" Delete attachment ", format!("Delete attachment \"{name}\"?"))
        }
    };

    let area = frame.area();
    let popup = center_fixed(50, 7, area);
    frame.render_widget(Clear, popup);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ERR))
        .title(Span::styled(
            title,
            Style::default().fg(ERR).add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let lines = vec![
        Line::from(Span::styled(prompt, Style::default().fg(FG))),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                "y",
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
            ),
            Span::styled(" yes   ", Style::default().fg(MUTED)),
            Span::styled(
                "n",
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
            ),
            Span::styled(" / Esc cancel", Style::default().fg(MUTED)),
        ]),
    ];
    frame.render_widget(Paragraph::new(lines).alignment(Alignment::Center), inner);
}

fn draw_reprompt(frame: &mut Frame, app: &App) {
    let Overlay::Reprompt {
        password,
        error,
        ..
    } = &app.overlay
    else {
        return;
    };
    let area = frame.area();
    let popup = center_fixed(52, 9, area);
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(Span::styled(
            " Master password required ",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ))
        .title_bottom(Span::styled(
            " Enter confirm · Esc cancel ",
            Style::default().fg(MUTED),
        ));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Length(1)])
        .split(inner);
    draw_form_field(frame, rows[0], "Password", password, true, true);
    if let Some(err) = error {
        frame.render_widget(
            Paragraph::new(err.as_str()).style(Style::default().fg(ERR)),
            rows[1],
        );
    }
}

fn draw_identity_form(frame: &mut Frame, app: &App) {
    use crate::app::IdentityField;
    let Overlay::IdentityForm {
        editing_id,
        name,
        title,
        first_name,
        last_name,
        email,
        phone,
        username,
        notes,
        reprompt,
        field,
    } = &app.overlay
    else {
        return;
    };
    let area = frame.area();
    let popup = center_fixed(64, 22, area);
    frame.render_widget(Clear, popup);
    let title_hdr = if editing_id.is_some() {
        " Edit identity "
    } else {
        " New identity "
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(Span::styled(
            title_hdr,
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ))
        .title_bottom(Span::styled(
            " Tab · Ctrl+s save · Esc cancel ",
            Style::default().fg(MUTED),
        ));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(3),
            Constraint::Length(2),
        ])
        .split(inner);
    draw_form_field(frame, rows[0], "Name", name, *field == IdentityField::Name, false);
    draw_form_field(frame, rows[1], "Title", title, *field == IdentityField::Title, false);
    draw_form_field(
        frame,
        rows[2],
        "First name",
        first_name,
        *field == IdentityField::FirstName,
        false,
    );
    draw_form_field(
        frame,
        rows[3],
        "Last name",
        last_name,
        *field == IdentityField::LastName,
        false,
    );
    draw_form_field(frame, rows[4], "Email", email, *field == IdentityField::Email, false);
    draw_form_field(frame, rows[5], "Phone", phone, *field == IdentityField::Phone, false);
    draw_form_field(
        frame,
        rows[6],
        "Username",
        username,
        *field == IdentityField::Username,
        false,
    );
    draw_form_field(frame, rows[7], "Notes", notes, *field == IdentityField::Notes, false);
    let reprompt_label = format!("[{}] Require master password re-prompt", on(*reprompt));
    frame.render_widget(
        Paragraph::new(reprompt_label).style(if *field == IdentityField::Reprompt {
            Style::default().fg(ACCENT)
        } else {
            Style::default().fg(MUTED)
        }),
        rows[8],
    );
}

fn draw_ssh_key_form(frame: &mut Frame, app: &App) {
    use crate::app::SshKeyField;
    let Overlay::SshKeyForm {
        editing_id,
        name,
        private_key,
        public_key,
        fingerprint,
        notes,
        field,
    } = &app.overlay
    else {
        return;
    };
    let area = frame.area();
    let popup = center_fixed(64, 18, area);
    frame.render_widget(Clear, popup);
    let title_hdr = if editing_id.is_some() {
        " Edit SSH key "
    } else {
        " New SSH key "
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(Span::styled(
            title_hdr,
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ))
        .title_bottom(Span::styled(
            " Tab · Ctrl+s save · Esc cancel ",
            Style::default().fg(MUTED),
        ));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(3),
        ])
        .split(inner);
    draw_form_field(frame, rows[0], "Name", name, *field == SshKeyField::Name, false);
    draw_form_field(
        frame,
        rows[1],
        "Private key",
        private_key,
        *field == SshKeyField::PrivateKey,
        true,
    );
    draw_form_field(
        frame,
        rows[2],
        "Public key",
        public_key,
        *field == SshKeyField::PublicKey,
        false,
    );
    draw_form_field(
        frame,
        rows[3],
        "Fingerprint",
        fingerprint,
        *field == SshKeyField::Fingerprint,
        false,
    );
    draw_form_field(frame, rows[4], "Notes", notes, *field == SshKeyField::Notes, false);
}

fn draw_move_to_folder(frame: &mut Frame, app: &App) {
    let Overlay::MoveToFolder { selected, .. } = &app.overlay else {
        return;
    };
    let area = frame.area();
    let popup = center_fixed(44, (app.folders.len() + 5).min(18) as u16, area);
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(Span::styled(
            " Move to folder ",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ))
        .title_bottom(Span::styled(
            " j/k · Enter confirm · Esc cancel ",
            Style::default().fg(MUTED),
        ));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    let mut lines = vec![Line::from(Span::styled(
        if *selected == 0 {
            "› (no folder)"
        } else {
            "  (no folder)"
        },
        if *selected == 0 {
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(FG)
        },
    ))];
    for (i, folder) in app.folders.iter().enumerate() {
        let idx = i + 1;
        let marker = if idx == *selected { "› " } else { "  " };
        let style = if idx == *selected {
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(FG)
        };
        lines.push(Line::from(Span::styled(
            format!("{marker}{}", folder.name),
            style,
        )));
    }
    frame.render_widget(Paragraph::new(lines), inner);
}

