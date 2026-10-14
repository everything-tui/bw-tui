//! Modal overlays: item form, generator, folder create, delete confirm, reprompt.

use ratatui::layout::{Alignment, Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{
    uri_match_label, App, DeleteTarget, EditField, NoteField, Overlay, ShareToOrgStep,
};
use crate::ui::form::draw_form_field;
use crate::ui::layout::center_fixed;

const ACCENT: Color = Color::Rgb(175, 82, 222);
const MUTED: Color = Color::DarkGray;
const FG: Color = Color::White;
const ERR: Color = Color::LightRed;

pub fn draw_overlay(frame: &mut Frame, app: &App) {
    match &app.overlay {
        Overlay::None => {}
        Overlay::Power(_) => super::power::draw_power_overlay(frame, app),
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
        Overlay::AccountTools(_) => super::account_tools::draw_account_tools(frame, app),
        Overlay::SendForm { .. } => super::account::draw_send_form(frame, app),
        Overlay::ReceiveSend { .. } => super::account::draw_receive_send(frame, app),
        Overlay::CardForm { .. } => super::account::draw_card_form(frame, app),
        Overlay::PinSetup { .. } => super::account::draw_pin_setup(frame, app),
        Overlay::ChangeMasterPassword { .. } => {
            super::account::draw_change_master_password(frame, app)
        }
        Overlay::AttachmentPath { .. } => draw_attachment_path(frame, app),
        Overlay::IdentityForm { .. } => draw_identity_form(frame, app),
        Overlay::SshKeyForm { .. } => draw_ssh_key_form(frame, app),
        Overlay::MoveToFolder { .. } => draw_move_to_folder(frame, app),
        Overlay::ShareToOrg { .. } => draw_share_to_org(frame, app),
        Overlay::CustomFieldsForm { .. } => draw_custom_fields_form(frame, app),
    }
}

fn draw_custom_fields_form(frame: &mut Frame, app: &App) {
    let Overlay::CustomFieldsForm {
        fields,
        selected,
        editing,
        edit_name,
        edit_value,
        edit_type,
        edit_focus,
        ..
    } = &app.overlay
    else {
        return;
    };
    let area = frame.area();
    let popup = center_fixed(64, 18, area);
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(Span::styled(
            " Custom fields ",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ))
        .title_bottom(Span::styled(
            " n new · d delete · Enter edit · Ctrl+s save · Esc ",
            Style::default().fg(MUTED),
        ));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let mut lines: Vec<Line> = Vec::new();
    if editing.is_some() {
        use crate::app::CustomFieldEditFocus;
        let name_mark = if *edit_focus == CustomFieldEditFocus::Name {
            ">"
        } else {
            " "
        };
        let val_mark = if *edit_focus == CustomFieldEditFocus::Value {
            ">"
        } else {
            " "
        };
        let typ_mark = if *edit_focus == CustomFieldEditFocus::Type {
            ">"
        } else {
            " "
        };
        lines.push(Line::from(format!("{name_mark} Name:  {edit_name}")));
        lines.push(Line::from(format!("{val_mark} Value: {edit_value}")));
        lines.push(Line::from(format!(
            "{typ_mark} Type:  {} (Tab cycles)",
            edit_type.label()
        )));
        lines.push(Line::from(Span::styled(
            "Enter to apply field",
            Style::default().fg(MUTED),
        )));
    } else if fields.is_empty() {
        lines.push(Line::from(Span::styled(
            "No custom fields — press n to add",
            Style::default().fg(MUTED),
        )));
    } else {
        for (i, f) in fields.iter().enumerate() {
            let prefix = if i == *selected { "> " } else { "  " };
            let hidden = if f.hidden() { " •••" } else { "" };
            lines.push(Line::from(format!(
                "{prefix}{} [{}]{hidden}",
                f.name,
                f.kind.label()
            )));
        }
    }
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
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
            " Tab · Ctrl+s save · URI: ^t match · ^n add · ^d del · ^b/^f line · Esc ",
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

    draw_form_field(
        frame,
        rows[0],
        "Name",
        name,
        *field == EditField::Name,
        false,
    );
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
    draw_form_field(
        frame,
        rows[3],
        "TOTP",
        totp,
        *field == EditField::Totp,
        true,
    );
    let uri_idx = (*uri_line).min(uris.len().saturating_sub(1));
    let uri_active = *field == EditField::Uri;
    let uri_label = format!(
        "URI {}/{} [{}]",
        uri_idx + 1,
        uris.len().max(1),
        uri_match_label(uris.get(uri_idx).map(|u| u.match_type).unwrap_or(0))
    );
    let uri_text = uris.get(uri_idx).map(|u| u.uri.as_str()).unwrap_or("");
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
    use vault_session::evaluate_password;

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

    let strength = if matches!(mode, GeneratorMode::Password | GeneratorMode::Passphrase)
        && !preview.is_empty()
    {
        // zxcvbn: dictionary / pattern aware, not just charset size.
        let s = evaluate_password(preview, &[]);
        format!(
            "Strength: {} ({}/4, ~{:.0} bits)",
            s.label, s.score, s.entropy_bits
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
                UsernameKind::SimpleLogin => "SimpleLogin alias",
                UsernameKind::AddyIo => "addy.io alias",
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
        DeleteTarget::Item {
            name,
            permanent: true,
            ..
        } => (
            " Permanently delete ",
            format!("Permanently delete \"{name}\"? This cannot be undone."),
        ),
        DeleteTarget::Item { name, .. } => (" Delete item ", format!("Move \"{name}\" to trash?")),
        DeleteTarget::Folder { name, .. } => {
            (" Delete folder ", format!("Delete folder \"{name}\"?"))
        }
        DeleteTarget::Send { name, .. } => (" Delete send ", format!("Delete send \"{name}\"?")),
        DeleteTarget::Attachment { name, .. } => (
            " Delete attachment ",
            format!("Delete attachment \"{name}\"?"),
        ),
        DeleteTarget::EmptyTrash { count } => (
            " Empty trash ",
            format!("Permanently delete {count} item(s) in trash?"),
        ),
        DeleteTarget::BulkItems { count, .. } => (
            " Delete items ",
            format!("Move {count} marked item(s) to trash?"),
        ),
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
        password, error, ..
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
        reprompt,
        field,
    } = &app.overlay
    else {
        return;
    };
    let area = frame.area();
    let popup = center_fixed(70, 24, area);
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
            " Tab cycle fields · Ctrl+s save · Esc cancel ",
            Style::default().fg(MUTED),
        ));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    // Show a window of fields around the focused one (compact scrolling form).
    let entries: Vec<(&str, &str, IdentityField)> = vec![
        ("Name", name.as_str(), IdentityField::Name),
        ("Title", title.as_str(), IdentityField::Title),
        ("First", first_name.as_str(), IdentityField::FirstName),
        ("Middle", middle_name.as_str(), IdentityField::MiddleName),
        ("Last", last_name.as_str(), IdentityField::LastName),
        ("Email", email.as_str(), IdentityField::Email),
        ("Phone", phone.as_str(), IdentityField::Phone),
        ("Username", username.as_str(), IdentityField::Username),
        ("Company", company.as_str(), IdentityField::Company),
        ("Address1", address1.as_str(), IdentityField::Address1),
        ("Address2", address2.as_str(), IdentityField::Address2),
        ("Address3", address3.as_str(), IdentityField::Address3),
        ("City", city.as_str(), IdentityField::City),
        ("State", state.as_str(), IdentityField::State),
        ("Postal", postal_code.as_str(), IdentityField::PostalCode),
        ("Country", country.as_str(), IdentityField::Country),
        ("SSN", ssn.as_str(), IdentityField::Ssn),
        ("Passport", passport.as_str(), IdentityField::Passport),
        ("License", license.as_str(), IdentityField::License),
        ("Notes", notes.as_str(), IdentityField::Notes),
    ];
    let focus_idx = entries
        .iter()
        .position(|(_, _, f)| *f == *field)
        .unwrap_or(0);
    let window = 7usize;
    let start = focus_idx
        .saturating_sub(window / 2)
        .min(entries.len().saturating_sub(window));
    let end = (start + window).min(entries.len());
    let visible = &entries[start..end];
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            std::iter::repeat_n(Constraint::Length(3), visible.len())
                .chain(std::iter::once(Constraint::Length(2)))
                .collect::<Vec<_>>(),
        )
        .split(inner);
    for (i, (label, value, f)) in visible.iter().enumerate() {
        draw_form_field(frame, rows[i], label, value, *f == *field, false);
    }
    let reprompt_label = format!("[{}] Require master password re-prompt", on(*reprompt));
    frame.render_widget(
        Paragraph::new(reprompt_label).style(if *field == IdentityField::Reprompt {
            Style::default().fg(ACCENT)
        } else {
            Style::default().fg(MUTED)
        }),
        rows[visible.len()],
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
            " Tab · Ctrl+g gen Ed25519 · Ctrl+e notes in $EDITOR · Ctrl+s save · Esc ",
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
    draw_form_field(
        frame,
        rows[0],
        "Name",
        name,
        *field == SshKeyField::Name,
        false,
    );
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
    draw_form_field(
        frame,
        rows[4],
        "Notes",
        notes,
        *field == SshKeyField::Notes,
        false,
    );
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

fn draw_share_to_org(frame: &mut Frame, app: &App) {
    let Overlay::ShareToOrg {
        item_ids,
        groups,
        org_index,
        step,
        collection_cursor,
        selected_collections,
    } = &app.overlay
    else {
        return;
    };
    let writable = app.share_writable_collections(*org_index);
    let area = frame.area();
    let height = match step {
        ShareToOrgStep::PickOrganization => (groups.len() + 7).min(20) as u16,
        ShareToOrgStep::PickCollections => (writable.len() + 8).min(22) as u16,
    };
    let popup = center_fixed(52, height.max(8), area);
    frame.render_widget(Clear, popup);
    let title = match step {
        ShareToOrgStep::PickOrganization => {
            format!(" Share to org · {} item(s) ", item_ids.len())
        }
        ShareToOrgStep::PickCollections => format!(
            " Collections · {} ",
            groups
                .get(*org_index)
                .map(|g| g.organization_name.as_str())
                .unwrap_or("org")
        ),
    };
    let hints = match step {
        ShareToOrgStep::PickOrganization => " j/k · Enter next · Esc cancel ",
        ShareToOrgStep::PickCollections => " j/k · Space toggle · Enter share · Esc back ",
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(Span::styled(
            title,
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ))
        .title_bottom(Span::styled(hints, Style::default().fg(MUTED)));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let mut lines: Vec<Line> = Vec::new();
    match step {
        ShareToOrgStep::PickOrganization => {
            for (i, g) in groups.iter().enumerate() {
                let marker = if i == *org_index { "› " } else { "  " };
                let style = if i == *org_index {
                    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(FG)
                };
                lines.push(Line::from(Span::styled(
                    format!(
                        "{marker}{} ({} collections)",
                        g.organization_name,
                        g.collections.iter().filter(|c| c.writable()).count()
                    ),
                    style,
                )));
            }
        }
        ShareToOrgStep::PickCollections => {
            for (i, (id, name)) in writable.iter().enumerate() {
                let checked = if selected_collections.contains(id) {
                    "[x]"
                } else {
                    "[ ]"
                };
                let marker = if i == *collection_cursor {
                    "› "
                } else {
                    "  "
                };
                let style = if i == *collection_cursor {
                    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(FG)
                };
                lines.push(Line::from(Span::styled(
                    format!("{marker}{checked} {name}"),
                    style,
                )));
            }
            if writable.is_empty() {
                lines.push(Line::from(Span::styled(
                    "No writable collections",
                    Style::default().fg(MUTED),
                )));
            }
        }
    }
    frame.render_widget(Paragraph::new(lines), inner);
}
