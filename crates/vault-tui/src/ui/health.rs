//! Vault health report overlay (R).

use ratatui::layout::Alignment;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{App, Overlay};

use super::layout::center_fixed;

const ACCENT: Color = Color::Rgb(175, 82, 222);
const MUTED: Color = Color::DarkGray;
const FG: Color = Color::White;
const WARN: Color = Color::Rgb(247, 118, 142);

pub fn draw_health_report(frame: &mut Frame, app: &App) {
    let Overlay::HealthReport {
        scroll,
        hibp_opt_in,
        hibp_busy,
        hibp_results,
    } = &app.overlay
    else {
        return;
    };
    let area = frame.area();
    let popup = center_fixed(62, 20, area);
    frame.render_widget(Clear, popup);

    let hibp_hint = if *hibp_busy {
        "HIBP scan running…"
    } else if *hibp_opt_in {
        "HIBP on (h toggle off) — network"
    } else {
        "h opt-in HIBP breach counts (network)"
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(Span::styled(
            " Vault health ",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ))
        .title_bottom(Span::styled(
            format!(" j/k scroll · {hibp_hint} · Esc close "),
            Style::default().fg(MUTED),
        ));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let report = app.health_report();
    let mut lines: Vec<Line> = vec![
        Line::from(Span::styled(
            format!(
                "Reused passwords: {} · Weak: {} · HTTP logins: {} · Duplicates: {}",
                report.reused_passwords.len(),
                report.weak_passwords.len(),
                report.unsecured_http.len(),
                report.duplicate_items.len(),
            ),
            Style::default().fg(FG).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];

    for group in report.reused_passwords.iter().take(5) {
        lines.push(Line::from(Span::styled(
            format!("Reused: {}", group.item_names.join(", ")),
            Style::default().fg(WARN),
        )));
    }
    for weak in report.weak_passwords.iter().take(5) {
        lines.push(Line::from(Span::styled(
            format!(
                "Weak ({} bits): {}",
                weak.entropy_bits as u32, weak.item_name
            ),
            Style::default().fg(WARN),
        )));
    }
    for http in report.unsecured_http.iter().take(5) {
        lines.push(Line::from(Span::styled(
            format!("HTTP: {} — {}", http.item_name, http.uri),
            Style::default().fg(WARN),
        )));
    }

    if *hibp_opt_in {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Have I Been Pwned (reused + selected login):",
            Style::default().fg(FG).add_modifier(Modifier::BOLD),
        )));
        if hibp_results.is_empty() && !*hibp_busy {
            lines.push(Line::from(Span::styled(
                "No passwords to check.",
                Style::default().fg(MUTED),
            )));
        }
        for row in hibp_results.iter().take(8) {
            let style = if row.count > 0 {
                Style::default().fg(WARN)
            } else {
                Style::default().fg(MUTED)
            };
            lines.push(Line::from(Span::styled(
                format!("{} — {} breaches", row.label, row.count),
                style,
            )));
        }
    }

    if lines.len() <= 2 {
        lines.push(Line::from(Span::styled(
            "No issues detected in the current vault snapshot.",
            Style::default().fg(MUTED),
        )));
    }

    let start = (*scroll).min(lines.len().saturating_sub(1));
    let visible: Vec<Line> = lines.into_iter().skip(start).take(16).collect();
    frame.render_widget(
        Paragraph::new(visible)
            .alignment(Alignment::Left)
            .wrap(Wrap { trim: true }),
        inner,
    );
}
