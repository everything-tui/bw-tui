//! Account tools overlay drawing (KDF, 2FA setup, device approvals, forwarders, …).

use ratatui::layout::{Alignment, Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{tool_fields, App, Overlay, ToolScreen, TOOL_MENU};
use crate::ui::layout::center_fixed;

const ACCENT: Color = Color::Rgb(175, 82, 222);
const MUTED: Color = Color::DarkGray;
const FG: Color = Color::White;
const ERR: Color = Color::LightRed;
const OK: Color = Color::LightGreen;

pub fn draw_account_tools(frame: &mut Frame, app: &App) {
    let Overlay::AccountTools(st) = &app.overlay else {
        return;
    };
    let area = center_fixed(72, 22, frame.area());
    frame.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(
            " Account tools ",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ))
        .style(Style::default().fg(FG));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(8),
            Constraint::Length(2),
            Constraint::Length(1),
        ])
        .split(inner);

    let title = match st.screen {
        ToolScreen::Menu => "Choose a tool (Enter / 1–8 · Esc closes)".to_string(),
        ToolScreen::ChangeKdf => "Change KDF".into(),
        ToolScreen::Deauthorize => "Deauthorize other sessions".into(),
        ToolScreen::TwoFactor => "Authenticator app 2FA".into(),
        ToolScreen::ChangeEmail => "Change email (stub)".into(),
        ToolScreen::DeleteAccount => "Delete account (stub)".into(),
        ToolScreen::DeviceApprovals => "Incoming login requests".into(),
        ToolScreen::Forwarders => "Forwarded email aliases".into(),
        ToolScreen::Biometric => "Biometric unlock".into(),
    };
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            title,
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ))),
        chunks[0],
    );

    let mut lines: Vec<Line> = Vec::new();
    match st.screen {
        ToolScreen::Menu => {
            for (i, (key, label)) in TOOL_MENU.iter().enumerate() {
                let selected = i == st.selected;
                let prefix = if selected { "› " } else { "  " };
                lines.push(Line::from(Span::styled(
                    format!("{prefix}[{key}] {label}"),
                    if selected {
                        Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(FG)
                    },
                )));
            }
        }
        ToolScreen::DeviceApprovals => {
            if st.incoming.is_empty() {
                lines.push(Line::from(Span::styled(
                    "No pending login requests.",
                    Style::default().fg(MUTED),
                )));
            } else {
                for (i, req) in st.incoming.iter().enumerate() {
                    let selected = i == st.selected;
                    let prefix = if selected { "› " } else { "  " };
                    lines.push(Line::from(Span::styled(
                        format!(
                            "{prefix}{} · {} · {}",
                            req.device_type, req.ip_address, req.fingerprint
                        ),
                        if selected {
                            Style::default().fg(ACCENT)
                        } else {
                            Style::default().fg(FG)
                        },
                    )));
                }
                lines.push(Line::from(Span::styled(
                    "y approve · n deny · Esc back",
                    Style::default().fg(MUTED),
                )));
            }
        }
        ToolScreen::Forwarders if st.forwarder_edit.is_none() => {
            for (i, (svc, configured)) in st.forwarder_configured.iter().enumerate() {
                let selected = i == st.selected;
                let prefix = if selected { "› " } else { "  " };
                let flag = if *configured { "configured" } else { "not set" };
                lines.push(Line::from(Span::styled(
                    format!("{prefix}{svc:?} — {flag}"),
                    if selected {
                        Style::default().fg(ACCENT)
                    } else {
                        Style::default().fg(FG)
                    },
                )));
            }
            lines.push(Line::from(Span::styled(
                "Enter edit · d clear · Esc back",
                Style::default().fg(MUTED),
            )));
        }
        ToolScreen::Biometric => {
            for line in &st.info_lines {
                lines.push(Line::from(Span::styled(
                    line.clone(),
                    Style::default().fg(FG),
                )));
            }
        }
        _ => {
            let fields = tool_fields(st);
            for (i, (label, secret)) in fields.iter().enumerate() {
                let focused = i == st.focus;
                let raw = st.fields.get(i).map(String::as_str).unwrap_or("");
                let shown = if *secret && !raw.is_empty() {
                    "•".repeat(raw.chars().count().min(24))
                } else {
                    raw.to_string()
                };
                let style = if focused {
                    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(FG)
                };
                lines.push(Line::from(vec![
                    Span::styled(format!("{label}: "), Style::default().fg(MUTED)),
                    Span::styled(shown, style),
                ]));
            }
            for line in &st.info_lines {
                lines.push(Line::from(Span::styled(
                    line.clone(),
                    Style::default().fg(MUTED),
                )));
            }
            for qr in st.qr_lines.iter().take(12) {
                lines.push(Line::from(Span::raw(qr.clone())));
            }
            if let Some(confirm) = &st.confirm {
                lines.push(Line::from(Span::styled(
                    format!("Confirm {confirm:?}?  y / n"),
                    Style::default().fg(Color::Yellow),
                )));
            }
        }
    }

    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), chunks[1]);

    if !st.message.is_empty() {
        let color = if st.is_error { ERR } else { OK };
        frame.render_widget(
            Paragraph::new(st.message.as_str()).style(Style::default().fg(color)),
            chunks[2],
        );
    }

    frame.render_widget(
        Paragraph::new("Esc back · Tab fields · Enter submit")
            .style(Style::default().fg(MUTED))
            .alignment(Alignment::Center),
        chunks[3],
    );
}
