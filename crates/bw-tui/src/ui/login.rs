//! Login, unlock, and 2FA screens.

use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{App, LoginField, Screen};
use crate::ui::chrome;
use crate::ui::layout::{center_fixed, split_status};
use crate::ui::theme::pal;

pub fn draw_login(frame: &mut Frame, app: &App) {
    let area = frame.area();
    let (body, status) = split_status(area);

    chrome::fill(frame, area, pal::mantle());

    // Brand above the card, then a single rounded form.
    let chunks = split_brand_card(body, 20);

    draw_brand(frame, chunks[1], "Sign in");

    let form = center_fixed(60, 20, chunks[3]);
    let inner = chrome::panel(frame, form, pal::overlay());

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // spacer
            Constraint::Length(3), // server
            Constraint::Length(3), // email
            Constraint::Length(3), // password
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

    draw_remember(
        frame,
        rows[4],
        app.remember_login,
        app.login_field == LoginField::Remember,
        "Remember session",
    );

    if app.pending.is_some() {
        draw_message(frame, rows[6], MessageKind::Busy, "Signing in…");
    } else if let Some(err) = &app.form_error {
        draw_message(frame, rows[6], MessageKind::Error, err);
    } else if app.using_mock {
        draw_message(
            frame,
            rows[6],
            MessageKind::Hint,
            "Mock mode · any password loads a demo vault",
        );
    }

    draw_status_bar(
        frame,
        status,
        app,
        &[
            "Tab fields",
            "Ctrl+p profiles",
            "Ctrl+r remember",
            "Ctrl+d device",
            "Ctrl+o SSO",
            "Enter",
        ],
    );
}

pub fn draw_2fa(frame: &mut Frame, app: &App) {
    let area = frame.area();
    let (body, status) = split_status(area);

    chrome::fill(frame, area, pal::mantle());

    let chunks = split_brand_card(body, 14);

    draw_brand(frame, chunks[1], "Two-factor");

    let form = center_fixed(52, 14, chunks[3]);
    let inner = chrome::panel(frame, form, pal::overlay());

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1), // account
            Constraint::Length(1),
            Constraint::Length(3), // code
            Constraint::Length(1),
            Constraint::Length(1), // remember device
            Constraint::Length(1), // message
            Constraint::Min(1),
        ])
        .margin(1)
        .split(inner);

    let providers = app.two_factor_summary();
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(app.email.clone(), Style::default().fg(pal::text())),
            Span::styled(
                format!("  ·  {providers}"),
                Style::default().fg(pal::muted()),
            ),
        ]))
        .alignment(Alignment::Center),
        rows[1],
    );

    draw_input_row(frame, rows[3], "Code", &app.totp_code, true, false);

    draw_remember(
        frame,
        rows[5],
        app.remember_2fa_device,
        false,
        "Remember this device",
    );

    if app.pending.is_some() {
        draw_message(frame, rows[6], MessageKind::Busy, "Verifying…");
    } else if let Some(err) = &app.form_error {
        draw_message(frame, rows[6], MessageKind::Error, err);
    } else {
        draw_message(frame, rows[6], MessageKind::Hint, &app.two_factor_hint());
    }

    draw_status_bar(
        frame,
        status,
        app,
        &[
            "Tab/j/k method",
            "Ctrl+o Duo",
            "Space remember",
            "Enter verify",
            "Esc back",
        ],
    );
}

pub fn draw_unlock(frame: &mut Frame, app: &App) {
    let area = frame.area();
    let (body, status) = split_status(area);

    chrome::fill(frame, area, pal::mantle());

    let chunks = split_brand_card(body, 12);

    draw_brand(frame, chunks[1], "Vault locked");

    let form = center_fixed(52, 12, chunks[3]);
    let inner = chrome::panel(frame, form, pal::overlay());

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1), // account
            Constraint::Length(1),
            Constraint::Length(3), // password
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
            .style(Style::default().fg(pal::muted()))
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true }),
        rows[1],
    );

    if app.unlock_use_pin {
        draw_input_row(frame, rows[3], "PIN", &app.unlock_pin, true, false);
    } else {
        draw_input_row(
            frame,
            rows[3],
            "Password",
            &app.unlock_password,
            true,
            !app.show_password,
        );
    }

    if app.pending.is_some() {
        draw_message(frame, rows[5], MessageKind::Busy, "Unlocking…");
    } else if let Some(err) = &app.form_error {
        draw_message(frame, rows[5], MessageKind::Error, err);
    } else {
        draw_message(
            frame,
            rows[5],
            MessageKind::Hint,
            "Enter your master password",
        );
    }

    draw_status_bar(
        frame,
        status,
        app,
        &["Ctrl+h show", "Ctrl+p profiles", "Ctrl+o signout", "Enter"],
    );
}

/// Rows: [top pad, brand (3), gap (2), card, rest], centred as one block.
fn split_brand_card(body: Rect, card_h: u16) -> std::rc::Rc<[Rect]> {
    let top = body.height.saturating_sub(card_h + 5) / 2;
    Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(top),
            Constraint::Length(3),
            Constraint::Length(2),
            Constraint::Length(card_h),
            Constraint::Min(0),
        ])
        .split(body)
}

fn draw_brand(frame: &mut Frame, area: Rect, subtitle: &str) {
    let t = crate::ui::theme::theme();
    let glyph = if t.ascii { "#" } else { "◆" };
    let lines = vec![
        Line::from(vec![
            Span::styled(format!("{glyph}  "), Style::default().fg(pal::accent())),
            Span::styled(
                "bitwarden-tui",
                Style::default()
                    .fg(pal::text())
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(subtitle, Style::default().fg(pal::subtext()))),
    ];
    // Vertically center the block in the brand band.
    let h = 3.min(area.height);
    let y = area.y + area.height.saturating_sub(h) / 2;
    frame.render_widget(
        Paragraph::new(lines).alignment(Alignment::Center),
        Rect {
            x: area.x,
            y,
            width: area.width,
            height: h,
        },
    );
}

/// Labelled filled input (label row + field row).
fn draw_input_row(
    frame: &mut Frame,
    area: Rect,
    label: &str,
    value: &str,
    focused: bool,
    secret: bool,
) {
    let inset = Rect {
        x: area.x + 1,
        width: area.width.saturating_sub(2),
        ..area
    };
    chrome::input(frame, inset, label, value, focused, secret, "", false);
}

fn draw_remember(frame: &mut Frame, area: Rect, checked: bool, focused: bool, label: &str) {
    let mark_color = if checked || focused {
        pal::accent()
    } else {
        pal::muted()
    };
    let line = Line::from(vec![
        Span::styled(
            if focused { " ▸ " } else { "   " },
            Style::default().fg(pal::accent()),
        ),
        Span::styled(
            chrome::check(checked),
            Style::default().fg(mark_color).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("  {label}"),
            Style::default().fg(if focused { pal::text() } else { pal::subtext() }),
        ),
    ]);
    frame.render_widget(Paragraph::new(line), area);
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
            Style::default()
                .fg(pal::accent())
                .add_modifier(Modifier::BOLD),
        ),
        MessageKind::Error => ("✕ ", Style::default().fg(pal::danger())),
        MessageKind::Hint => ("", Style::default().fg(pal::muted())),
    };
    frame.render_widget(
        Paragraph::new(format!("{prefix}{text}"))
            .style(style)
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true }),
        area,
    );
}

pub fn draw_status_bar(frame: &mut Frame, area: Rect, app: &App, hints: &[&str]) {
    let t = crate::ui::theme::theme();
    chrome::fill(frame, area, t.mantle);
    let screen = match app.screen {
        Screen::Login => "SIGN IN",
        Screen::TwoFactor => "2FA",
        Screen::AuthWait => "AUTH",
        Screen::Unlock => "LOCKED",
        Screen::Vault => "VAULT",
    };
    let mut left = vec![chrome::chip(screen, t.accent_fg, t.accent)];
    if app.using_mock {
        left.push(Span::raw(" "));
        left.push(chrome::chip("MOCK", t.accent_fg, t.warning));
    }
    left.push(Span::styled(
        format!("  {}", app.active_profile_name()),
        Style::default().fg(t.subtext),
    ));

    let right = chrome::hint_spans(&hints.join(" · "), t.mantle);
    let width = |spans: &[Span]| -> usize { spans.iter().map(|s| s.width()).sum() };
    let budget = (area.width as usize).saturating_sub(width(&left) + width(&right) + 3);
    let status = truncate_str(&app.status, budget);
    left.push(Span::styled(
        format!("  {status}"),
        Style::default().fg(t.muted),
    ));

    let gap = (area.width as usize).saturating_sub(width(&left) + width(&right));
    let mut spans = left;
    spans.push(Span::raw(" ".repeat(gap)));
    spans.extend(right);
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
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

/// "Waiting for another device / SSO browser" screen.
pub fn draw_auth_wait(frame: &mut Frame, app: &App) {
    use crate::app::WaitKind;

    let area = frame.area();
    let (body, status) = split_status(area);

    chrome::fill(frame, area, pal::mantle());

    let chunks = split_brand_card(body, 14);

    let Some(wait) = app.auth_ext.wait.as_ref() else {
        draw_brand(frame, chunks[1], "Authenticating");
        draw_status_bar(frame, status, app, &["Esc back"]);
        return;
    };
    let title = match wait.kind {
        WaitKind::DeviceApproval => "Login with device",
        WaitKind::Sso => "Single sign-on",
    };
    draw_brand(frame, chunks[1], title);

    let form = center_fixed(72, 14, chunks[3]);
    let inner = chrome::panel(frame, form, pal::overlay());

    let mut lines: Vec<Line> = vec![Line::from(Span::styled(
        app.email.clone(),
        Style::default().fg(pal::text()),
    ))];
    lines.push(Line::from(""));
    match wait.kind {
        WaitKind::DeviceApproval => {
            lines.push(Line::from(Span::styled(
                "Approve this request on a device where you are logged in.",
                Style::default().fg(pal::muted()),
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("Fingerprint  ", Style::default().fg(pal::muted())),
                Span::styled(
                    wait.fingerprint.clone(),
                    Style::default()
                        .fg(pal::accent())
                        .add_modifier(Modifier::BOLD),
                ),
            ]));
            lines.push(Line::from(Span::styled(
                wait.detail.clone(),
                Style::default().fg(pal::muted()),
            )));
            lines.push(Line::from(""));
            let secs = wait.started.elapsed().as_secs();
            lines.push(Line::from(Span::styled(
                format!("Waiting… {}:{:02}", secs / 60, secs % 60),
                Style::default().fg(pal::text()),
            )));
        }
        WaitKind::Sso => {
            lines.push(Line::from(Span::styled(
                "Finish signing in with your identity provider in the browser.",
                Style::default().fg(pal::muted()),
            )));
            lines.push(Line::from(Span::styled(
                "If the redirect does not reach this terminal, paste it below.",
                Style::default().fg(pal::muted()),
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                truncate_str(&wait.detail, inner.width.saturating_sub(2) as usize),
                Style::default().fg(pal::muted()),
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("Callback  ", Style::default().fg(pal::muted())),
                Span::styled(
                    format!("{}▌", truncate_str(&wait.paste, 52)),
                    Style::default().fg(pal::text()),
                ),
            ]));
        }
    }
    if let Some(err) = &app.form_error {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            err.clone(),
            Style::default().fg(pal::danger()),
        )));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true }),
        ratatui::layout::Rect {
            x: inner.x + 1,
            y: inner.y + 1,
            width: inner.width.saturating_sub(2),
            height: inner.height.saturating_sub(1),
        },
    );

    let hints: &[&str] = match wait.kind {
        WaitKind::DeviceApproval => &["Esc cancel"],
        WaitKind::Sso => &["Enter submit pasted URL", "Esc cancel"],
    };
    draw_status_bar(frame, status, app, hints);
}
