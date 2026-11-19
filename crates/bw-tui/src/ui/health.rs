//! Vault health report overlay (R).

use ratatui::layout::Alignment;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{App, Overlay};

use super::layout::center_fixed;
use crate::ui::chrome;
use crate::ui::theme::pal;

pub fn draw_health_report(frame: &mut Frame, app: &App) {
    let Overlay::HealthReport {
        scroll,
        hibp_opt_in,
        hibp_busy,
        hibp_results,
        hibp_email_opt_in,
        hibp_email_results,
        report,
        ..
    } = &app.overlay
    else {
        return;
    };
    let area = frame.area();
    let popup = center_fixed(62, 20, area);

    let hibp_hint = if *hibp_busy {
        "HIBP scan running…"
    } else if *hibp_opt_in || *hibp_email_opt_in {
        "HIBP on (h pw · e email) — network"
    } else {
        "h opt-in HIBP pw · e email (network)"
    };

    let inner = chrome::modal(
        frame,
        popup,
        " Vault health ",
        format!(" j/k scroll · {hibp_hint} · Esc close "),
    );

    // Stat tiles: count (green when clean, red when not) over a label.
    let stats = [
        ("Reused", report.reused_passwords.len()),
        ("Weak", report.weak_passwords.len()),
        ("Old", report.old_passwords.len()),
        ("HTTP", report.unsecured_http.len()),
        ("Dupes", report.duplicate_items.len()),
        ("Cards", report.expired_cards.len()),
        ("No 2FA", report.inactive_2fa.len()),
    ];
    let total: usize = stats.iter().map(|(_, n)| n).sum();
    let mut counts = Vec::new();
    let mut labels = Vec::new();
    for (label, n) in stats {
        let color = if n == 0 {
            pal::success()
        } else {
            pal::danger()
        };
        let w = label.chars().count().max(3) + 2;
        counts.push(Span::styled(
            format!("{n:<w$}"),
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ));
        labels.push(Span::styled(
            format!("{label:<w$}"),
            Style::default().fg(pal::muted()),
        ));
    }
    let verdict = if total == 0 {
        Span::styled(
            "✓ All clear",
            Style::default()
                .fg(pal::success())
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(
            format!("{total} issue{} found", if total == 1 { "" } else { "s" }),
            Style::default()
                .fg(pal::warning())
                .add_modifier(Modifier::BOLD),
        )
    };
    let mut lines: Vec<Line> = vec![
        Line::from(verdict),
        Line::from(""),
        Line::from(counts),
        Line::from(labels),
        Line::from(""),
    ];

    for group in report.reused_passwords.iter().take(5) {
        lines.push(Line::from(Span::styled(
            format!("Reused: {}", group.item_names.join(", ")),
            Style::default().fg(pal::danger()),
        )));
    }
    for weak in report.weak_passwords.iter().take(5) {
        lines.push(Line::from(Span::styled(
            format!(
                "Weak ({}, ~{} bits{}): {}",
                weak.strength_label,
                weak.entropy_bits as u32,
                weak.warning
                    .as_deref()
                    .map(|w| format!(" — {w}"))
                    .unwrap_or_default(),
                weak.item_name
            ),
            Style::default().fg(pal::danger()),
        )));
    }
    for http in report.unsecured_http.iter().take(5) {
        lines.push(Line::from(Span::styled(
            format!("HTTP: {} — {}", http.item_name, http.uri),
            Style::default().fg(pal::danger()),
        )));
    }
    for card in report.expired_cards.iter().take(5) {
        let label = if card.expired { "Expired" } else { "Expiring" };
        lines.push(Line::from(Span::styled(
            format!(
                "{label} card: {} ({}/{})",
                card.item_name, card.exp_month, card.exp_year
            ),
            Style::default().fg(pal::danger()),
        )));
    }

    for old in report.old_passwords.iter().take(5) {
        lines.push(Line::from(Span::styled(
            format!("Old password ({}d): {}", old.age_days, old.item_name),
            Style::default().fg(pal::danger()),
        )));
    }
    for entry in report.inactive_2fa.iter().take(5) {
        lines.push(Line::from(Span::styled(
            format!(
                "2FA available, not set up: {} ({})",
                entry.item_name, entry.host
            ),
            Style::default().fg(pal::danger()),
        )));
    }

    if *hibp_email_opt_in {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "HIBP email breaches (usernames that look like emails):",
            Style::default()
                .fg(pal::text())
                .add_modifier(Modifier::BOLD),
        )));
        if hibp_email_results.is_empty() && !*hibp_busy {
            lines.push(Line::from(Span::styled(
                "No emails to check.",
                Style::default().fg(pal::muted()),
            )));
        }
        for row in hibp_email_results.iter().take(8) {
            let style = if row.count > 0 {
                Style::default().fg(pal::danger())
            } else {
                Style::default().fg(pal::muted())
            };
            lines.push(Line::from(Span::styled(
                format!("{} — {} breaches", row.label, row.count),
                style,
            )));
        }
    }

    if *hibp_opt_in {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Have I Been Pwned (reused + selected login):",
            Style::default()
                .fg(pal::text())
                .add_modifier(Modifier::BOLD),
        )));
        if hibp_results.is_empty() && !*hibp_busy {
            lines.push(Line::from(Span::styled(
                "No passwords to check.",
                Style::default().fg(pal::muted()),
            )));
        }
        for row in hibp_results.iter().take(8) {
            let style = if row.count > 0 {
                Style::default().fg(pal::danger())
            } else {
                Style::default().fg(pal::muted())
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
            Style::default().fg(pal::muted()),
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
