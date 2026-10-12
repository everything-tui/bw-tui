//! Account settings overlay.

use ratatui::layout::{Alignment, Constraint, Direction, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;

use crate::app::{App, CardField, ChangePasswordField, Overlay, PinSetupField};
use crate::ui::form::draw_form_field;
use crate::ui::layout::center_fixed;
use ratatui::style::Color;

const ACCENT: Color = Color::Rgb(175, 82, 222);
const FG: Color = Color::White;
const MUTED: Color = Color::DarkGray;
const ERR: Color = Color::Rgb(255, 100, 100);

pub fn draw_account_settings(frame: &mut Frame, app: &App) {
    let Overlay::AccountSettings { status, .. } = &app.overlay else {
        return;
    };
    let area = frame.area();
    let popup = center_fixed(68, 18, area);
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(Span::styled(
            " Account ",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ))
        .title_bottom(Span::styled(
            " h fp · H hint · p pw · i PIN · c clr · s ssh · a more · Esc ",
            Style::default().fg(MUTED),
        ));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    let lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(
                "h",
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
            ),
            Span::styled("  Show fingerprint phrase", Style::default().fg(FG)),
        ]),
        Line::from(vec![
            Span::styled(
                "H",
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
            ),
            Span::styled("  Email master password hint", Style::default().fg(FG)),
        ]),
        Line::from(vec![
            Span::styled(
                "p",
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
            ),
            Span::styled("  Change master password", Style::default().fg(FG)),
        ]),
        Line::from(vec![
            Span::styled(
                "i",
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
            ),
            Span::styled("  Set / update PIN unlock", Style::default().fg(FG)),
        ]),
        Line::from(vec![
            Span::styled(
                "c",
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
            ),
            Span::styled("  Clear PIN unlock", Style::default().fg(FG)),
        ]),
        Line::from(vec![
            Span::styled(
                "s",
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
            ),
            Span::styled("  Start / stop vault SSH agent", Style::default().fg(FG)),
        ]),
        Line::from(vec![
            Span::styled(
                "a",
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "  Account tools (KDF, sessions, 2FA, devices, aliases)",
                Style::default().fg(FG),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(status.as_str(), Style::default().fg(MUTED))),
    ];
    frame.render_widget(Paragraph::new(lines).alignment(Alignment::Left), inner);
}

pub fn draw_pin_setup(frame: &mut Frame, app: &App) {
    let Overlay::PinSetup {
        pin,
        confirm,
        field,
        status,
    } = &app.overlay
    else {
        return;
    };
    let area = frame.area();
    let popup = center_fixed(52, 12, area);
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(" PIN unlock ")
        .title_bottom(Span::styled(
            " Tab fields · Enter save · Esc cancel ",
            Style::default().fg(MUTED),
        ));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(2),
        ])
        .split(inner);
    draw_form_field(
        frame,
        rows[0],
        "PIN (4+ digits)",
        pin,
        *field == PinSetupField::Pin,
        true,
    );
    draw_form_field(
        frame,
        rows[1],
        "Confirm PIN",
        confirm,
        *field == PinSetupField::Confirm,
        true,
    );
    if !status.is_empty() {
        frame.render_widget(
            Paragraph::new(status.as_str()).style(Style::default().fg(MUTED)),
            rows[2],
        );
    }
}

pub fn draw_change_master_password(frame: &mut Frame, app: &App) {
    let Overlay::ChangeMasterPassword {
        old,
        new,
        confirm,
        hint,
        field,
        error,
    } = &app.overlay
    else {
        return;
    };
    let area = frame.area();
    let popup = center_fixed(54, 16, area);
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(" Change master password ")
        .title_bottom(Span::styled(
            " Tab fields · Enter submit · Esc cancel ",
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
            Constraint::Length(2),
        ])
        .split(inner);
    draw_form_field(
        frame,
        rows[0],
        "Current password",
        old,
        *field == ChangePasswordField::Old,
        true,
    );
    draw_form_field(
        frame,
        rows[1],
        "New password",
        new,
        *field == ChangePasswordField::New,
        true,
    );
    draw_form_field(
        frame,
        rows[2],
        "Confirm new",
        confirm,
        *field == ChangePasswordField::Confirm,
        true,
    );
    draw_form_field(
        frame,
        rows[3],
        "Hint (optional)",
        hint,
        *field == ChangePasswordField::Hint,
        false,
    );
    if let Some(err) = error {
        frame.render_widget(
            Paragraph::new(err.as_str()).style(Style::default().fg(ERR)),
            rows[4],
        );
    }
}

pub fn draw_send_form(frame: &mut Frame, app: &App) {
    use crate::send_form::{SendFormField, SendKind};
    let Overlay::SendForm { form } = &app.overlay else {
        return;
    };
    let area = frame.area();
    let popup = center_fixed(64, 20, area);
    frame.render_widget(Clear, popup);
    let title = if form.editing_id.is_some() {
        " Edit Send "
    } else {
        " New Send "
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(title)
        .title_bottom(Span::styled(
            " Tab · Ctrl+t type · Ctrl+s save · Esc ",
            Style::default().fg(MUTED),
        ));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    let kind = match form.kind {
        SendKind::Text => "Text",
        SendKind::File => "File",
    };
    let content_label = match form.kind {
        SendKind::Text => "Text",
        SendKind::File => "File path",
    };
    let pw = if form.password.is_empty() {
        if form.has_password {
            if form.remove_password {
                "(will remove)"
            } else {
                "(set · Space clears)"
            }
        } else {
            ""
        }
    } else {
        "••••••••"
    };
    let on = |b: bool| if b { "x" } else { " " };
    let row = |label: &str, value: &str, active: bool| {
        let style = if active {
            Style::default().fg(ACCENT)
        } else {
            Style::default().fg(FG)
        };
        Line::from(Span::styled(format!("{label:<12} {value}"), style))
    };
    let lines = vec![
        row("Type", kind, false),
        row("Name", &form.name, form.field == SendFormField::Name),
        row(
            content_label,
            &form.content,
            form.field == SendFormField::Content,
        ),
        row("Notes", &form.notes, form.field == SendFormField::Notes),
        row("Password", pw, form.field == SendFormField::Password),
        row(
            "Max access",
            &form.max_access,
            form.field == SendFormField::MaxAccess,
        ),
        row(
            "Expires",
            &form.expiration,
            form.field == SendFormField::Expiration,
        ),
        row(
            "Deletion",
            &form.deletion,
            form.field == SendFormField::Deletion,
        ),
        row(
            "Hide email",
            &format!("[{}]", on(form.hide_email)),
            form.field == SendFormField::HideEmail,
        ),
        row(
            "Hide text",
            &format!("[{}]", on(form.hidden_text)),
            form.field == SendFormField::HiddenText,
        ),
        row(
            "Disabled",
            &format!("[{}]", on(form.disabled)),
            form.field == SendFormField::Disabled,
        ),
    ];
    let mut out = lines;
    if let Some(err) = &form.error {
        out.push(Line::from(Span::styled(
            err.clone(),
            Style::default().fg(ERR),
        )));
    }
    frame.render_widget(Paragraph::new(out), inner);
}

pub fn draw_receive_send(frame: &mut Frame, app: &App) {
    use crate::send_form::ReceiveField;
    let Overlay::ReceiveSend { state } = &app.overlay else {
        return;
    };
    let area = frame.area();
    let popup = center_fixed(64, 16, area);
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(" Open Send link ")
        .title_bottom(Span::styled(
            " Enter fetch/save · c copy · r reveal · Esc ",
            Style::default().fg(MUTED),
        ));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    let mut lines = vec![
        Line::from(Span::styled(
            format!(
                "{} URL: {}",
                if state.field == ReceiveField::Url {
                    ">"
                } else {
                    " "
                },
                state.url
            ),
            Style::default().fg(if state.field == ReceiveField::Url {
                ACCENT
            } else {
                FG
            }),
        )),
        Line::from(Span::styled(
            format!(
                "{} Password: {}",
                if state.field == ReceiveField::Password {
                    ">"
                } else {
                    " "
                },
                if state.password.is_empty() {
                    ""
                } else {
                    "••••"
                }
            ),
            Style::default().fg(if state.field == ReceiveField::Password {
                ACCENT
            } else {
                FG
            }),
        )),
    ];
    if let Some(r) = &state.received {
        lines.push(Line::from(""));
        lines.push(Line::from(format!("Name: {}", r.name)));
        if let Some(who) = r.creator_identifier.as_deref().filter(|s| !s.is_empty()) {
            lines.push(Line::from(format!("From: {who}")));
        }
        if let Some(text) = &r.text {
            let shown = if r.text_hidden && !state.reveal {
                "•••••••• (r reveal)"
            } else {
                text.as_str()
            };
            lines.push(Line::from(format!("Text: {shown}")));
        }
        if let Some(f) = &r.file {
            lines.push(Line::from(format!(
                "File: {} ({})",
                f.name,
                f.size_name.as_deref().unwrap_or("?")
            )));
            lines.push(Line::from(Span::styled(
                format!(
                    "{} Save to: {}",
                    if state.field == ReceiveField::SavePath {
                        ">"
                    } else {
                        " "
                    },
                    state.save_path
                ),
                Style::default().fg(ACCENT),
            )));
        }
    }
    if let Some(msg) = &state.message {
        lines.push(Line::from(Span::styled(
            msg.clone(),
            Style::default().fg(MUTED),
        )));
    }
    frame.render_widget(Paragraph::new(lines), inner);
}

pub fn draw_card_form(frame: &mut Frame, app: &App) {
    let Overlay::CardForm {
        editing_id,
        name,
        cardholder_name,
        brand,
        number,
        exp_month,
        exp_year,
        code,
        notes,
        reprompt,
        field,
    } = &app.overlay
    else {
        return;
    };
    let area = frame.area();
    let popup = center_fixed(58, 22, area);
    frame.render_widget(Clear, popup);
    let title = if editing_id.is_some() {
        " Edit card "
    } else {
        " New card "
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(title)
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
            Constraint::Length(3),
            Constraint::Length(2),
        ])
        .split(inner);
    draw_form_field(
        frame,
        rows[0],
        "Name",
        name,
        *field == CardField::Name,
        false,
    );
    draw_form_field(
        frame,
        rows[1],
        "Cardholder",
        cardholder_name,
        *field == CardField::Cardholder,
        false,
    );
    draw_form_field(
        frame,
        rows[2],
        "Brand",
        brand,
        *field == CardField::Brand,
        false,
    );
    draw_form_field(
        frame,
        rows[3],
        "Number",
        number,
        *field == CardField::Number,
        true,
    );
    draw_form_field(
        frame,
        rows[4],
        "Exp month",
        exp_month,
        *field == CardField::ExpMonth,
        false,
    );
    draw_form_field(
        frame,
        rows[5],
        "Exp year",
        exp_year,
        *field == CardField::ExpYear,
        false,
    );
    draw_form_field(frame, rows[6], "CVC", code, *field == CardField::Code, true);
    draw_form_field(
        frame,
        rows[7],
        "Notes",
        notes,
        *field == CardField::Notes,
        false,
    );
    let reprompt_label = format!(
        "[{}] Require master password re-prompt",
        if *reprompt { 'x' } else { ' ' }
    );
    frame.render_widget(
        Paragraph::new(reprompt_label).style(if *field == CardField::Reprompt {
            Style::default().fg(ACCENT)
        } else {
            Style::default().fg(MUTED)
        }),
        rows[8],
    );
}
