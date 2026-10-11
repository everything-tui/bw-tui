//! Login, unlock, and 2FA screens.

use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{App, LoginField, Screen};
use crate::ui::layout::{center_fixed, split_status};

const ACCENT: Color = Color::Rgb(175, 82, 222);
const MUTED: Color = Color::DarkGray;
const FG: Color = Color::White;
const DIM_BORDER: Color = Color::Rgb(60, 60, 70);
const FIELD_BG: Color = Color::Rgb(28, 28, 34);
const SELECT_BG: Color = Color::Rgb(55, 40, 70);
const STATUS_BG: Color = Color::Rgb(30, 30, 36);
const ERR: Color = Color::Rgb(247, 118, 142);
const BG: Color = Color::Rgb(14, 14, 18);

pub fn draw_login(frame: &mut Frame, app: &App) {
    let area = frame.area();
    let (body, status) = split_status(area);

    frame.render_widget(Clear, area);
    frame.render_widget(Block::default().style(Style::default().bg(BG)), area);

    // Brand above the card, then a single rounded form.
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4), // brand
            Constraint::Min(14),   // form
            Constraint::Length(1), // breathing room above status
        ])
        .split(body);

    draw_brand(frame, chunks[0], "Sign in");

    let form = center_fixed(60, 18, chunks[1]);
    let card = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(DIM_BORDER))
        .style(Style::default().bg(FIELD_BG));
    let inner = card.inner(form);
    frame.render_widget(card, form);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // spacer
            Constraint::Length(2), // server
            Constraint::Length(2), // email
            Constraint::Length(2), // password
            Constraint::Length(1), // spacer
            Constraint::Length(1), // remember
            Constraint::Length(1), // spacer
            Constraint::Min(2),    // message / busy (wrap long errors)
        ])
        .margin(1)
        .split(inner);

    draw_input_row(
        frame,
        rows[1],
        "Server",
        &app.server_url,
        app.login_field == LoginField::Server,
        false,
    );
    draw_input_row(
        frame,
        rows[2],
        "Email",
        &app.email,
        app.login_field == LoginField::Email,
        false,
    );
    draw_input_row(
        frame,
        rows[3],
        "Password",
        &app.password,
        app.login_field == LoginField::Password,
        !app.show_password,
    );

    draw_remember(frame, rows[5], app.remember_login, app.login_field == LoginField::Remember);

    if app.pending.is_some() {
        draw_message(frame, rows[7], MessageKind::Busy, "Signing in…");
    } else if let Some(err) = &app.form_error {
        draw_message(frame, rows[7], MessageKind::Error, err);
    } else if app.using_mock {
        draw_message(
            frame,
            rows[7],
            MessageKind::Hint,
            "Mock mode · any password loads a demo vault",
        );
    }

    draw_status_bar(
        frame,
        status,
        app,
        &["Tab fields", "Ctrl+p profiles", "Ctrl+r remember", "Enter"],
    );
}

pub fn draw_2fa(frame: &mut Frame, app: &App) {
    let area = frame.area();
    let (body, status) = split_status(area);

    frame.render_widget(Clear, area);
    frame.render_widget(Block::default().style(Style::default().bg(BG)), area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Min(10),
            Constraint::Length(1),
        ])
        .split(body);

    draw_brand(frame, chunks[0], "Two-factor");

    let form = center_fixed(48, 11, chunks[1]);
    let card = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(DIM_BORDER))
        .style(Style::default().bg(FIELD_BG));
    let inner = card.inner(form);
    frame.render_widget(card, form);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1), // account
            Constraint::Length(1),
            Constraint::Length(2), // code
            Constraint::Length(1),
            Constraint::Length(1), // message
            Constraint::Min(1),
        ])
        .margin(1)
        .split(inner);

    let providers = format_providers(&app.two_factor_providers);
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(app.email.clone(), Style::default().fg(FG)),
            Span::styled(format!("  ·  {providers}"), Style::default().fg(MUTED)),
        ]))
        .alignment(Alignment::Center),
        rows[1],
    );

    draw_input_row(frame, rows[3], "Code", &app.totp_code, true, false);

    if app.pending.is_some() {
        draw_message(frame, rows[5], MessageKind::Busy, "Verifying…");
    } else if let Some(err) = &app.form_error {
        draw_message(frame, rows[5], MessageKind::Error, err);
    } else {
        draw_message(frame, rows[5], MessageKind::Hint, "Enter the code from your authenticator");
    }

    draw_status_bar(frame, status, app, &["Enter verify", "Esc back"]);
}

pub fn draw_unlock(frame: &mut Frame, app: &App) {
    let area = frame.area();
    let (body, status) = split_status(area);

    frame.render_widget(Clear, area);
    frame.render_widget(Block::default().style(Style::default().bg(BG)), area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Min(10),
            Constraint::Length(1),
        ])
        .split(body);

    draw_brand(frame, chunks[0], "Vault locked");

    let form = center_fixed(48, 11, chunks[1]);
    let card = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(DIM_BORDER))
        .style(Style::default().bg(FIELD_BG));
    let inner = card.inner(form);
    frame.render_widget(card, form);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1), // account
            Constraint::Length(1),
            Constraint::Length(2), // password
            Constraint::Length(1),
            Constraint::Length(1), // message
            Constraint::Min(1),
        ])
        .margin(1)
        .split(inner);

    let account = if app.email.is_empty() {
        app.server_url.clone()
    } else {
        format!("{}  ·  {}", app.email, app.server_url)
    };
    frame.render_widget(
        Paragraph::new(account)
            .style(Style::default().fg(MUTED))
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true }),
        rows[1],
    );

    draw_input_row(
        frame,
        rows[3],
        "Password",
        &app.unlock_password,
        true,
        !app.show_password,
    );

    if app.pending.is_some() {
        draw_message(frame, rows[5], MessageKind::Busy, "Unlocking…");
    } else if let Some(err) = &app.form_error {
        draw_message(frame, rows[5], MessageKind::Error, err);
    } else {
        draw_message(frame, rows[5], MessageKind::Hint, "Enter your master password");
    }

    draw_status_bar(
        frame,
        status,
        app,
        &["Ctrl+h show", "Ctrl+p profiles", "Ctrl+o signout", "Enter"],
    );
}

fn draw_brand(frame: &mut Frame, area: Rect, subtitle: &str) {
    let lines = vec![
        Line::from(Span::styled(
            "bitwarden-tui",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(subtitle, Style::default().fg(MUTED))),
    ];
    // Vertically center the two lines in the brand band.
    let y = area.y + area.height.saturating_sub(2) / 2;
    frame.render_widget(
        Paragraph::new(lines).alignment(Alignment::Center),
        Rect {
            x: area.x,
            y,
            width: area.width,
            height: 2.min(area.height),
        },
    );
}

/// Label + value row. Focused rows get a violet bar and fill — same language as the vault list.
fn draw_input_row(
    frame: &mut Frame,
    area: Rect,
    label: &str,
    value: &str,
    focused: bool,
    secret: bool,
) {
    let fill = if focused { SELECT_BG } else { FIELD_BG };
    let marker = if focused { "▌" } else { " " };
    let label_style = Style::default()
        .fg(if focused { ACCENT } else { MUTED })
        .bg(fill)
        .add_modifier(if focused {
            Modifier::BOLD
        } else {
            Modifier::empty()
        });
    let value_style = Style::default().fg(FG).bg(fill);

    let raw = if secret && !value.is_empty() {
        "•".repeat(value.chars().count())
    } else {
        value.to_string()
    };

    // "▌ " + label(10) + " " + value…
    let chrome = 2 + 10 + 1;
    let max_chars = area.width.saturating_sub(chrome as u16) as usize;
    let visible = if raw.chars().count() > max_chars {
        raw.chars()
            .skip(raw.chars().count().saturating_sub(max_chars))
            .collect::<String>()
    } else {
        raw
    };
    let caret = if focused { "▌" } else { "" };
    let display = if visible.is_empty() && focused {
        caret.to_string()
    } else {
        format!("{visible}{caret}")
    };

    let line = Line::from(vec![
        Span::styled(marker, Style::default().fg(ACCENT).bg(fill)),
        Span::styled(" ", Style::default().bg(fill)),
        Span::styled(format!("{label:<10}"), label_style),
        Span::styled(" ", Style::default().bg(fill)),
        Span::styled(display, value_style),
    ]);

    // Fill the whole row so the selection band is solid.
    let used: usize = line.spans.iter().map(|s| s.content.chars().count()).sum();
    let pad = (area.width as usize).saturating_sub(used);
    let mut spans = line.spans;
    if pad > 0 {
        spans.push(Span::styled(" ".repeat(pad), Style::default().bg(fill)));
    }

    // Vertically center the single content line in the 2-row slot.
    let y = area.y + area.height.saturating_sub(1) / 2;
    frame.render_widget(
        Paragraph::new(Line::from(spans)),
        Rect {
            x: area.x,
            y,
            width: area.width,
            height: 1,
        },
    );
}

fn draw_remember(frame: &mut Frame, area: Rect, checked: bool, focused: bool) {
    let fill = if focused { SELECT_BG } else { FIELD_BG };
    let marker = if focused { "▌" } else { " " };
    let box_mark = if checked { "✓" } else { " " };
    let line = Line::from(vec![
        Span::styled(marker, Style::default().fg(ACCENT).bg(fill)),
        Span::styled(" ", Style::default().bg(fill)),
        Span::styled(
            format!("[{box_mark}]"),
            Style::default()
                .fg(if checked || focused { ACCENT } else { MUTED })
                .bg(fill)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "  Remember me",
            Style::default()
                .fg(if focused { FG } else { MUTED })
                .bg(fill),
        ),
        Span::styled(
            "   keeps you signed in",
            Style::default().fg(MUTED).bg(fill),
        ),
    ]);
    let used: usize = line.spans.iter().map(|s| s.content.chars().count()).sum();
    let pad = (area.width as usize).saturating_sub(used);
    let mut spans = line.spans;
    if pad > 0 {
        spans.push(Span::styled(" ".repeat(pad), Style::default().bg(fill)));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

enum MessageKind {
    Busy,
    Error,
    Hint,
}

fn draw_message(frame: &mut Frame, area: Rect, kind: MessageKind, text: &str) {
    let (prefix, style) = match kind {
        MessageKind::Busy => (
            "◌ ",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ),
        MessageKind::Error => ("✕ ", Style::default().fg(ERR)),
        MessageKind::Hint => ("", Style::default().fg(MUTED)),
    };
    frame.render_widget(
        Paragraph::new(format!("{prefix}{text}"))
            .style(style)
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn format_providers(providers: &[u8]) -> String {
    if providers.is_empty() {
        return "authenticator".into();
    }
    providers
        .iter()
        .map(|p| match p {
            0 => "authenticator",
            1 => "email",
            2 => "Duo",
            3 => "YubiKey",
            4 => "U2F",
            5 => "remember",
            6 => "organization Duo",
            7 => "FIDO2",
            _ => "provider",
        })
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn draw_status_bar(frame: &mut Frame, area: Rect, app: &App, hints: &[&str]) {
    let screen = match app.screen {
        Screen::Login => "LOGIN",
        Screen::TwoFactor => "2FA",
        Screen::Unlock => "UNLOCK",
        Screen::Vault => "VAULT",
    };
    let mode = if app.using_mock { " MOCK " } else { " LIVE " };

    let mut right: Vec<Span> = Vec::new();
    for (i, h) in hints.iter().enumerate() {
        if i > 0 {
            right.push(Span::styled("  ", Style::default().bg(STATUS_BG)));
        }
        if let Some((key, label)) = h.split_once(' ') {
            right.push(Span::styled(
                key.to_string(),
                Style::default().fg(ACCENT).bg(STATUS_BG),
            ));
            right.push(Span::styled(
                format!(" {label}"),
                Style::default().fg(MUTED).bg(STATUS_BG),
            ));
        } else {
            right.push(Span::styled(
                (*h).to_string(),
                Style::default().fg(ACCENT).bg(STATUS_BG),
            ));
        }
    }
    right.push(Span::styled(" ", Style::default().bg(STATUS_BG)));
    let right_w: usize = right.iter().map(|s| s.content.chars().count()).sum();

    let profile = app.active_profile_name();
    // Badge + screen + profile always shown; status text fills remaining space and truncates.
    let prefix = format!("{mode} {screen} · {profile} ");
    let status_budget = (area.width as usize).saturating_sub(prefix.chars().count() + right_w + 1);
    let status = truncate_str(&app.status, status_budget);

    let mut spans = vec![
        Span::styled(
            mode.to_string(),
            Style::default()
                .fg(Color::Black)
                .bg(ACCENT)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" {screen} · {profile} "),
            Style::default().fg(MUTED).bg(STATUS_BG),
        ),
        Span::styled(
            format!(" {status}"),
            Style::default().fg(FG).bg(STATUS_BG),
        ),
    ];
    let used: usize = spans.iter().map(|s| s.content.chars().count()).sum::<usize>() + right_w;
    spans.push(Span::styled(
        " ".repeat((area.width as usize).saturating_sub(used)),
        Style::default().bg(STATUS_BG),
    ));
    spans.extend(right);

    frame.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::default().bg(STATUS_BG)),
        area,
    );
}

fn truncate_str(s: &str, max: usize) -> String {
    if max == 0 {
        return String::new();
    }
    let n = s.chars().count();
    if n <= max {
        s.to_string()
    } else if max <= 1 {
        "…".into()
    } else {
        format!("{}…", s.chars().take(max - 1).collect::<String>())
    }
}
