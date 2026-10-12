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
            " h fingerprint · H hint · p password · i PIN · c clear PIN · s SSH agent · Esc ",
            Style::default().fg(MUTED),
        ));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    let lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("h", Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
            Span::styled("  Show fingerprint phrase", Style::default().fg(FG)),
        ]),
        Line::from(vec![
            Span::styled("H", Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
            Span::styled("  Email master password hint", Style::default().fg(FG)),
        ]),
        Line::from(vec![
            Span::styled("p", Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
            Span::styled("  Change master password", Style::default().fg(FG)),
        ]),
        Line::from(vec![
            Span::styled("i", Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
            Span::styled("  Set / update PIN unlock", Style::default().fg(FG)),
        ]),
        Line::from(vec![
            Span::styled("c", Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
            Span::styled("  Clear PIN unlock", Style::default().fg(FG)),
        ]),
        Line::from(vec![
            Span::styled("s", Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
            Span::styled("  Start / stop vault SSH agent", Style::default().fg(FG)),
        ]),
        Line::from(""),
        Line::from(Span::styled(status.as_str(), Style::default().fg(MUTED))),
    ];
    frame.render_widget(
        Paragraph::new(lines).alignment(Alignment::Left),
        inner,
    );
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
    let Overlay::SendForm { name, text, field, .. } = &app.overlay else {
        return;
    };
    let area = frame.area();
    let popup = center_fixed(52, 10, area);
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(" New text send ")
        .title_bottom(Span::styled(" Ctrl+s save · Esc cancel ", Style::default().fg(MUTED)));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(2), Constraint::Length(2), Constraint::Min(1)])
        .split(inner);
    let mk = |label: &str, val: &str, active: bool| {
        Paragraph::new(format!("{label}: {val}")).style(if active {
            Style::default().fg(ACCENT)
        } else {
            Style::default().fg(FG)
        })
    };
    frame.render_widget(mk("Name", name, *field == crate::app::SendField::Name), rows[0]);
    frame.render_widget(mk("Text", text, *field == crate::app::SendField::Text), rows[1]);
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
    draw_form_field(frame, rows[0], "Name", name, *field == CardField::Name, false);
    draw_form_field(
        frame,
        rows[1],
        "Cardholder",
        cardholder_name,
        *field == CardField::Cardholder,
        false,
    );
    draw_form_field(frame, rows[2], "Brand", brand, *field == CardField::Brand, false);
    draw_form_field(frame, rows[3], "Number", number, *field == CardField::Number, true);
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
    draw_form_field(frame, rows[7], "Notes", notes, *field == CardField::Notes, false);
    let reprompt_label = format!("[{}] Require master password re-prompt", if *reprompt { 'x' } else { ' ' });
    frame.render_widget(
        Paragraph::new(reprompt_label).style(if *field == CardField::Reprompt {
            Style::default().fg(ACCENT)
        } else {
            Style::default().fg(MUTED)
        }),
        rows[8],
    );
}
