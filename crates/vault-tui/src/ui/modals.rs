//! Modal overlays: item form, generator, folder create, delete confirm, reprompt.

use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{
    uri_match_label, App, DeleteTarget, EditField, NoteField, Overlay, ShareToOrgStep,
};
use crate::ui::chrome;
use crate::ui::form::{draw_form_field, draw_form_field_with_hint};
use crate::ui::layout::center_fixed;
use crate::ui::theme::pal;

pub fn draw_overlay(frame: &mut Frame, app: &App) {
    match &app.overlay {
        Overlay::None => {}
        Overlay::ThemePicker { .. } => draw_theme_picker(frame, app),
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

fn draw_theme_picker(frame: &mut Frame, app: &App) {
    use crate::ui::theme::{theme, Theme, THEME_NAMES};
    let Overlay::ThemePicker { selected, .. } = &app.overlay else {
        return;
    };
    let t = theme();
    let height = (THEME_NAMES.len() as u16 + 4).min(frame.area().height);
    let popup = center_fixed(52, height, frame.area());
    let inner = chrome::modal(
        frame,
        popup,
        "Theme",
        "↑↓ preview · Enter keep · Esc revert",
    );
    for (i, name) in THEME_NAMES.iter().enumerate() {
        let y = inner.y + 1 + i as u16;
        if y >= inner.bottom() {
            break;
        }
        let Some(th) = Theme::builtin(name) else {
            continue;
        };
        let is_sel = i == *selected;
        let bg = if is_sel { t.select_bg } else { t.overlay };
        let mut spans = vec![
            Span::styled(
                if is_sel { "▌ " } else { "  " },
                Style::default().fg(t.accent),
            ),
            Span::styled(
                format!("{name:<20}"),
                if is_sel {
                    Style::default().fg(t.text).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(t.subtext)
                },
            ),
        ];
        // Swatches: the theme's own surfaces and accents.
        for c in [
            th.mantle, th.base, th.surface, th.accent, th.login, th.card, th.note, th.danger,
        ] {
            spans.push(Span::styled("██", Style::default().fg(c)));
        }
        if name.eq_ignore_ascii_case(&app.config.theme) {
            spans.push(Span::styled("  current", Style::default().fg(t.muted)));
        }
        frame.render_widget(
            Paragraph::new(Line::from(spans)).style(Style::default().bg(bg)),
            ratatui::layout::Rect::new(inner.x, y, inner.width, 1),
        );
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
    let inner = chrome::modal(
        frame,
        popup,
        " Custom fields ",
        " n new · d delete · Enter edit · Ctrl+s save · Esc ",
    );

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
            Style::default().fg(pal::muted()),
        )));
    } else if fields.is_empty() {
        lines.push(Line::from(Span::styled(
            "No custom fields — press n to add",
            Style::default().fg(pal::muted()),
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
    let inner = chrome::modal(
        frame,
        popup,
        " Upload attachment ",
        " Ctrl+s upload · Esc cancel ",
    );
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

    let title = if editing_id.is_some() {
        " Edit login "
    } else {
        " New login "
    };
    let inner = chrome::modal(
        frame,
        popup,
        title, // Popup is 68 wide: only show the keys that apply to the focused field.
        if *field == EditField::Uri {
            " ^n add · ^d del · ^f/^b next/prev · ^t match · ^s save · Esc "
        } else {
            " Tab next · Ctrl+s save · Ctrl+g generate password · Esc cancel "
        },
    );

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
    draw_form_field_with_hint(
        frame,
        rows[2],
        "Password",
        password,
        *field == EditField::Password,
        true,
        "Ctrl+g generate",
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
    let reprompt_label = format!(
        "{}  Require master password re-prompt",
        chrome::check(*reprompt)
    );
    frame.render_widget(
        Paragraph::new(reprompt_label).style(if *field == EditField::Reprompt {
            Style::default().fg(pal::accent())
        } else {
            Style::default().fg(pal::muted())
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
    let title = if editing_id.is_some() {
        " Edit note "
    } else {
        " New note "
    };
    let inner = chrome::modal(
        frame,
        popup,
        title,
        " Tab fields · Ctrl+s / Enter save · Esc cancel ",
    );
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
    let t = crate::ui::theme::theme();
    let area = frame.area();
    let popup = center_fixed(46, 13, area);
    let inner = chrome::modal(
        frame,
        popup,
        "New item",
        "↑↓ choose · Enter create · Esc cancel",
    );
    let options = [
        ("Login", "website credentials and TOTP", t.login),
        ("Secure note", "free-form encrypted text", t.note),
        ("Card", "payment card details", t.card),
        ("Identity", "name, address, documents", t.identity),
        ("SSH key", "Ed25519 key pair", t.ssh),
    ];
    for (i, (label, desc, color)) in options.iter().enumerate() {
        let y = inner.y + 1 + (i as u16) * 2;
        if y >= inner.bottom() {
            break;
        }
        let is_sel = i == *selected;
        let bg = if is_sel { t.select_bg } else { t.overlay };
        let line = Line::from(vec![
            Span::styled(
                if is_sel { "▌ " } else { "  " },
                Style::default().fg(t.accent),
            ),
            chrome::avatar(label, *color),
            Span::styled(
                format!("  {label:<12}"),
                if is_sel {
                    Style::default().fg(t.text).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(t.text)
                },
            ),
            Span::styled(desc.to_string(), Style::default().fg(t.muted)),
        ])
        .style(Style::default().bg(bg));
        frame.render_widget(Paragraph::new(line), Rect::new(inner.x, y, inner.width, 1));
    }
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

    let t = crate::ui::theme::theme();
    let area = frame.area();
    let popup = center_fixed(68, 16, area);

    let title = match mode {
        GeneratorMode::Passphrase => "Passphrase generator",
        GeneratorMode::Username => "Username generator",
        GeneratorMode::Password => "Password generator",
    };
    let primary = if *insert_to_form {
        "Enter insert"
    } else {
        "Enter copy"
    };
    let inner = chrome::modal(
        frame,
        popup,
        title,
        format!("{primary} · r regenerate · m mode · Esc close"),
    );
    if inner.height < 9 {
        return;
    }

    // The value, large and centred in an inset well.
    let well = Rect::new(inner.x + 1, inner.y + 1, inner.width.saturating_sub(2), 3);
    chrome::fill(frame, well, t.surface);
    let shown: Vec<Span> = if matches!(mode, GeneratorMode::Username) {
        vec![Span::styled(preview.clone(), Style::default().fg(t.text))]
    } else {
        t.password_spans(preview)
    };
    frame.render_widget(
        Paragraph::new(Line::from(shown))
            .style(Style::default().add_modifier(Modifier::BOLD))
            .alignment(Alignment::Center),
        Rect::new(well.x, well.y + 1, well.width, 1),
    );

    // Strength meter.
    let mut y = well.bottom() + 1;
    if matches!(mode, GeneratorMode::Password | GeneratorMode::Passphrase) && !preview.is_empty() {
        // zxcvbn: dictionary / pattern aware, not just charset size.
        let st = evaluate_password(preview, &[]);
        let color = match st.score {
            0 | 1 => t.danger,
            2 => t.warning,
            _ => t.success,
        };
        let mut spans = vec![Span::styled("  Strength  ", Style::default().fg(t.muted))];
        spans.extend(chrome::meter((st.score as usize + 1) * 4, 20, color));
        spans.push(Span::styled(
            format!("  {}  ·  ~{:.0} bits", st.label, st.entropy_bits),
            Style::default().fg(t.subtext),
        ));
        frame.render_widget(
            Paragraph::new(Line::from(spans)),
            Rect::new(inner.x, y, inner.width, 1),
        );
    }
    y += 2;

    // Options as toggles.
    let toggle = |on: bool, label: &str| -> Vec<Span<'static>> {
        vec![
            Span::styled(
                chrome::check(on),
                Style::default().fg(if on { t.accent } else { t.muted }),
            ),
            Span::styled(
                format!(" {label}   "),
                Style::default().fg(if on { t.text } else { t.subtext }),
            ),
        ]
    };
    let value = |label: &str, v: String| -> Vec<Span<'static>> {
        vec![
            Span::styled(format!("{label} "), Style::default().fg(t.muted)),
            Span::styled(
                format!("{v}   "),
                Style::default().fg(t.text).add_modifier(Modifier::BOLD),
            ),
        ]
    };
    let mut opts: Vec<Span> = vec![Span::raw("  ")];
    let legend: &str = match mode {
        GeneratorMode::Password => {
            opts.extend(value("Length", length.to_string()));
            opts.extend(toggle(*uppercase, "A-Z"));
            opts.extend(toggle(*lowercase, "a-z"));
            opts.extend(toggle(*digits, "0-9"));
            opts.extend(toggle(*symbols, "!@#"));
            opts.extend(toggle(*avoid_ambiguous, "unambiguous"));
            "+/- length · u A-Z · l a-z · d 0-9 · s !@# · a unambiguous"
        }
        GeneratorMode::Passphrase => {
            opts.extend(value("Words", passphrase_words.to_string()));
            opts.extend(value("Separator", format!("“{passphrase_separator}”")));
            opts.extend(toggle(*passphrase_capitalize, "Capitalize"));
            opts.extend(toggle(*passphrase_include_number, "Number"));
            "+/- words · C capitalize · n number"
        }
        GeneratorMode::Username => {
            opts.extend(value(
                "Kind",
                match username_kind {
                    UsernameKind::Word => "random word",
                    UsernameKind::Plus => "plus-address",
                    UsernameKind::Catchall => "catch-all",
                    UsernameKind::SimpleLogin => "SimpleLogin alias",
                    UsernameKind::AddyIo => "addy.io alias",
                }
                .to_string(),
            ));
            "k cycle kind"
        }
    };
    frame.render_widget(
        Paragraph::new(Line::from(opts)),
        Rect::new(inner.x, y, inner.width, 1),
    );
    if matches!(mode, GeneratorMode::Password) {
        let mins =
            format!("min digits {min_numbers}  ·  min symbols {min_special}  ({{ }} adjust)");
        frame.render_widget(
            Paragraph::new(Span::styled(
                format!("  {mins}"),
                Style::default().fg(t.muted),
            )),
            Rect::new(inner.x, y + 1, inner.width, 1),
        );
    }
    let mut legend_spans = vec![Span::raw("  ")];
    legend_spans.extend(chrome::fit(
        chrome::hint_spans(legend, t.overlay),
        inner.width.saturating_sub(2) as usize,
    ));
    frame.render_widget(
        Paragraph::new(Line::from(legend_spans)),
        Rect::new(inner.x, inner.bottom().saturating_sub(1), inner.width, 1),
    );
}

fn draw_folder_form(frame: &mut Frame, app: &App) {
    let Overlay::FolderForm { folder_id, name } = &app.overlay else {
        return;
    };

    let area = frame.area();
    let popup = center_fixed(48, 8, area);

    let title = if folder_id.is_some() {
        " Rename folder "
    } else {
        " New folder "
    };
    let inner = chrome::modal(frame, popup, title, " Enter save · Esc cancel ");

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

    let t = crate::ui::theme::theme();
    let permanent = matches!(
        target,
        DeleteTarget::Item {
            permanent: true,
            ..
        } | DeleteTarget::EmptyTrash { .. }
    );
    let verb = if permanent {
        "Delete forever"
    } else {
        "Delete"
    };
    let area = frame.area();
    let popup = center_fixed(56, 8, area);
    let inner = chrome::modal(frame, popup, title, "");

    let warn = if t.ascii { "!" } else { "⚠" };
    let lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(format!("{warn}  "), Style::default().fg(t.danger)),
            Span::styled(prompt, Style::default().fg(t.text)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                format!(" y  {verb} "),
                Style::default()
                    .fg(t.accent_fg)
                    .bg(t.danger)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("    "),
            chrome::keycap("Esc", t.overlay),
            Span::styled(" Cancel", Style::default().fg(t.subtext)),
        ]),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: false }),
        inner,
    );
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
    let inner = chrome::modal(
        frame,
        popup,
        " Master password required ",
        " Enter confirm · Esc cancel ",
    );
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Length(1)])
        .split(inner);
    draw_form_field(frame, rows[0], "Password", password, true, true);
    if let Some(err) = error {
        frame.render_widget(
            Paragraph::new(err.as_str()).style(Style::default().fg(pal::danger())),
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
    let title_hdr = if editing_id.is_some() {
        " Edit identity "
    } else {
        " New identity "
    };
    let inner = chrome::modal(
        frame,
        popup,
        title_hdr,
        " Tab cycle fields · Ctrl+s save · Esc cancel ",
    );

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
    let reprompt_label = format!(
        "{}  Require master password re-prompt",
        chrome::check(*reprompt)
    );
    frame.render_widget(
        Paragraph::new(reprompt_label).style(if *field == IdentityField::Reprompt {
            Style::default().fg(pal::accent())
        } else {
            Style::default().fg(pal::muted())
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
    let title_hdr = if editing_id.is_some() {
        " Edit SSH key "
    } else {
        " New SSH key "
    };
    let inner = chrome::modal(
        frame,
        popup,
        title_hdr,
        " Tab · Ctrl+g gen Ed25519 · Ctrl+e notes in $EDITOR · Ctrl+s save · Esc ",
    );
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
    let inner = chrome::modal(
        frame,
        popup,
        " Move to folder ",
        " j/k · Enter confirm · Esc cancel ",
    );
    let mut lines = vec![Line::from(Span::styled(
        if *selected == 0 {
            "› (no folder)"
        } else {
            "  (no folder)"
        },
        if *selected == 0 {
            Style::default()
                .fg(pal::accent())
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(pal::text())
        },
    ))];
    for (i, folder) in app.folders.iter().enumerate() {
        let idx = i + 1;
        let marker = if idx == *selected { "› " } else { "  " };
        let style = if idx == *selected {
            Style::default()
                .fg(pal::accent())
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(pal::text())
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
    let inner = chrome::modal(frame, popup, title, hints);

    let mut lines: Vec<Line> = Vec::new();
    match step {
        ShareToOrgStep::PickOrganization => {
            for (i, g) in groups.iter().enumerate() {
                let marker = if i == *org_index { "› " } else { "  " };
                let style = if i == *org_index {
                    Style::default()
                        .fg(pal::accent())
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(pal::text())
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
                    chrome::check(true)
                } else {
                    chrome::check(false)
                };
                let marker = if i == *collection_cursor {
                    "› "
                } else {
                    "  "
                };
                let style = if i == *collection_cursor {
                    Style::default()
                        .fg(pal::accent())
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(pal::text())
                };
                lines.push(Line::from(Span::styled(
                    format!("{marker}{checked} {name}"),
                    style,
                )));
            }
            if writable.is_empty() {
                lines.push(Line::from(Span::styled(
                    "No writable collections",
                    Style::default().fg(pal::muted()),
                )));
            }
        }
    }
    frame.render_widget(Paragraph::new(lines), inner);
}
