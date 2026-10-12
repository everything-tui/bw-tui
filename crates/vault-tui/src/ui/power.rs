//! Rendering for P4 power-user overlays and the toast stack.

use ratatui::layout::{Alignment, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{App, AttachmentPreview, DomainInput, Overlay, PowerOverlay};
use crate::toast::ToastKind;
use crate::ui::layout::center_fixed;
use crate::ui::theme::theme;

fn popup_block(title: &str, hint: &str) -> Block<'static> {
    let t = theme();
    Block::default()
        .borders(Borders::ALL)
        .border_style(t.focused_border())
        .title(Span::styled(format!(" {title} "), t.title()))
        .title_bottom(Span::styled(format!(" {hint} "), t.muted_style()))
}

pub fn draw_power_overlay(frame: &mut Frame, app: &App) {
    let Overlay::Power(p) = &app.overlay else {
        return;
    };
    match p {
        PowerOverlay::Qr { .. } => draw_qr(frame, p),
        PowerOverlay::Attachments { .. } => draw_attachments(frame, p),
        PowerOverlay::DomainRules { .. } => draw_domain_rules(frame, p),
        PowerOverlay::SshAgentConfirm { .. } => draw_ssh_confirm(frame, p),
    }
}

fn draw_qr(frame: &mut Frame, p: &PowerOverlay) {
    let PowerOverlay::Qr {
        item_name,
        entries,
        index,
        lines,
        error,
        ..
    } = p
    else {
        return;
    };
    let t = theme();
    let area = frame.area();
    let qr_w = lines
        .first()
        .map(|l| l.chars().count() as u16)
        .unwrap_or(30);
    let qr_h = lines.len() as u16;
    let width = (qr_w + 4).max(46);
    let height = (qr_h + 7).max(9);
    let popup = center_fixed(width, height, area);
    frame.render_widget(Clear, popup);

    let kind = entries
        .get(*index)
        .map(|(k, _)| k.label())
        .unwrap_or("Secret");
    let multi = if entries.len() > 1 {
        "Tab next · "
    } else {
        ""
    };
    let block = popup_block(
        &format!("QR · {item_name} · {kind}"),
        &format!("{multi}Esc close (auto-closes in 60s)"),
    );
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let mut out: Vec<Line> = Vec::new();
    out.push(Line::from(Span::styled(
        "Secret on screen — scan, then close.",
        Style::default().fg(t.warning),
    )));
    if let Some(err) = error {
        out.push(Line::from(""));
        out.push(Line::from(Span::styled(
            err.clone(),
            Style::default().fg(t.danger),
        )));
    } else {
        // Light modules filled: white on the terminal background scans on dark terminals.
        let qr_style = Style::default()
            .fg(ratatui::style::Color::White)
            .bg(ratatui::style::Color::Black);
        for l in lines {
            out.push(Line::from(Span::styled(l.clone(), qr_style)));
        }
    }
    frame.render_widget(Paragraph::new(out).alignment(Alignment::Center), inner);
}

fn draw_attachments(frame: &mut Frame, p: &PowerOverlay) {
    let PowerOverlay::Attachments {
        items,
        selected,
        preview,
        ..
    } = p
    else {
        return;
    };
    let t = theme();
    let area = frame.area();

    if let Some(pv) = preview {
        draw_preview(frame, area, pv);
        return;
    }
    let height = (items.len() as u16 + 4).clamp(6, 18);
    let popup = center_fixed(64, height, area);
    frame.render_widget(Clear, popup);
    let block = popup_block("Attachments", "o open · p preview · s save · Esc close");
    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    let lines: Vec<Line> = items
        .iter()
        .enumerate()
        .map(|(i, (_, name))| {
            let style = if i == *selected {
                t.selected()
            } else {
                t.normal()
            };
            Line::from(Span::styled(format!(" {:>2}. {name}", i + 1), style))
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), inner);
}

fn draw_preview(frame: &mut Frame, area: Rect, pv: &AttachmentPreview) {
    let t = theme();
    let popup = center_fixed(
        area.width.saturating_sub(6).min(100),
        area.height.saturating_sub(4).min(30),
        area,
    );
    frame.render_widget(Clear, popup);
    let block = popup_block(&format!("Preview · {}", pv.name), "j/k scroll · p/Esc back");
    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    if let Some(note) = &pv.note {
        frame.render_widget(
            Paragraph::new(note.clone())
                .style(Style::default().fg(t.muted))
                .wrap(Wrap { trim: true }),
            inner,
        );
        return;
    }
    let visible: Vec<Line> = pv
        .lines
        .iter()
        .skip(pv.scroll)
        .take(inner.height as usize)
        .map(|l| Line::from(Span::styled(l.clone(), t.normal())))
        .collect();
    frame.render_widget(Paragraph::new(visible), inner);
}

fn draw_domain_rules(frame: &mut Frame, p: &PowerOverlay) {
    let PowerOverlay::DomainRules {
        rules,
        selected,
        input,
        dirty,
        status,
        ..
    } = p
    else {
        return;
    };
    let t = theme();
    let area = frame.area();
    let popup = center_fixed(76.min(area.width), 24.min(area.height), area);
    frame.render_widget(Clear, popup);
    let title = if *dirty {
        "Domain rules (modified)"
    } else {
        "Domain rules"
    };
    let block = popup_block(
        title,
        "a add · e edit · d delete · x toggle global · s save · Esc close",
    );
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let mut rows: Vec<Line> = Vec::new();
    rows.push(Line::from(Span::styled(
        "Custom equivalent domains",
        t.title(),
    )));
    if rules.custom_groups.is_empty() {
        rows.push(Line::from(Span::styled(
            "  (none — press a)",
            t.muted_style(),
        )));
    }
    for (i, g) in rules.custom_groups.iter().enumerate() {
        let style = if i == *selected {
            t.selected()
        } else {
            t.normal()
        };
        rows.push(Line::from(Span::styled(
            format!("  {}", g.join(", ")),
            style,
        )));
    }
    rows.push(Line::from(""));
    rows.push(Line::from(Span::styled(
        "Global groups (x toggles exclusion)",
        t.title(),
    )));
    let custom = rules.custom_groups.len();
    for (i, g) in rules.global_groups.iter().enumerate() {
        let sel = custom + i == *selected;
        let style = if sel {
            t.selected()
        } else if g.excluded {
            t.muted_style()
        } else {
            t.normal()
        };
        let mark = if g.excluded { "[ ]" } else { "[x]" };
        rows.push(Line::from(Span::styled(
            format!("  {mark} {}", g.domains.join(", ")),
            style,
        )));
    }

    // Keep the selected row visible (title rows + blank row are part of the list).
    let sel_row = if *selected < custom {
        1 + *selected + usize::from(custom == 0)
    } else {
        // header + (custom rows or placeholder) + blank + header
        1 + custom.max(1) + 2 + (*selected - custom)
    };
    let footer_h = 2u16;
    let list_h = inner.height.saturating_sub(footer_h) as usize;
    let skip = (sel_row + 1).saturating_sub(list_h);
    let list_area = Rect::new(inner.x, inner.y, inner.width, list_h as u16);
    let visible: Vec<Line> = rows.into_iter().skip(skip).take(list_h).collect();
    frame.render_widget(Paragraph::new(visible), list_area);

    let footer = Rect::new(
        inner.x,
        inner.y + inner.height.saturating_sub(footer_h),
        inner.width,
        footer_h.min(inner.height),
    );
    let mut foot: Vec<Line> = Vec::new();
    if let Some(DomainInput { index, text }) = input {
        let label = if index.is_some() {
            "Edit group"
        } else {
            "New group"
        };
        foot.push(Line::from(vec![
            Span::styled(format!("{label}: "), Style::default().fg(t.accent)),
            Span::styled(format!("{text}▏"), t.normal()),
        ]));
        foot.push(Line::from(Span::styled(
            "comma-separated domains · Enter commit · Esc cancel",
            t.muted_style(),
        )));
    } else if !status.is_empty() {
        foot.push(Line::from(Span::styled(
            status.clone(),
            Style::default().fg(t.warning),
        )));
    }
    frame.render_widget(Paragraph::new(foot), footer);
}

fn draw_ssh_confirm(frame: &mut Frame, p: &PowerOverlay) {
    let PowerOverlay::SshAgentConfirm { keys, each_use, .. } = p else {
        return;
    };
    let t = theme();
    let area = frame.area();
    let height = (keys.len() as u16 + 8).clamp(9, 20);
    let popup = center_fixed(64, height, area);
    frame.render_widget(Clear, popup);
    let block = popup_block(
        "Start SSH agent?",
        "t toggle confirm-each-use · y start · n/Esc cancel",
    );
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let mut lines: Vec<Line> = vec![
        Line::from(Span::styled(
            "These vault SSH keys will be loaded into a local ssh-agent:",
            t.normal(),
        )),
        Line::from(""),
    ];
    if keys.is_empty() {
        lines.push(Line::from(Span::styled(
            "  (no SSH keys in vault)",
            t.muted_style(),
        )));
    }
    for k in keys.iter().take(10) {
        lines.push(Line::from(Span::styled(format!("  • {k}"), t.normal())));
    }
    if keys.len() > 10 {
        lines.push(Line::from(Span::styled(
            format!("  … and {} more", keys.len() - 10),
            t.muted_style(),
        )));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        if *each_use {
            "Each signature will ask for confirmation (ssh-add -c; needs SSH_ASKPASS)."
        } else {
            "Any process that can reach the socket can use the keys while it runs."
        },
        Style::default().fg(t.warning),
    )));
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), inner);
}

/// Toast stack in the top-right corner (newest on top).
pub fn draw_toasts(frame: &mut Frame, app: &App) {
    let t = theme();
    let area = frame.area();
    if app.power.toasts.is_empty() || area.width < 20 || area.height < 4 {
        return;
    }
    let max_w = area.width.saturating_sub(2).min(52);
    let mut y = area.y + 1;
    for toast in app.power.toasts.iter_newest_first() {
        if y + 3 > area.y + area.height {
            break;
        }
        let color = match toast.kind {
            ToastKind::Info => t.accent,
            ToastKind::Success => t.success,
            ToastKind::Warning => t.warning,
            ToastKind::Error => t.danger,
        };
        let text_w = toast.text.chars().count() as u16 + 6;
        let w = text_w.clamp(14, max_w);
        let x = area.x + area.width.saturating_sub(w + 1);
        let rect = Rect::new(x, y, w, 3);
        let glyph = if t.ascii {
            match toast.kind {
                ToastKind::Info => "i",
                ToastKind::Success => "+",
                ToastKind::Warning => "!",
                ToastKind::Error => "x",
            }
        } else {
            toast.kind.glyph()
        };
        let avail = w.saturating_sub(6) as usize;
        let mut text: String = toast.text.chars().take(avail).collect();
        if toast.text.chars().count() > avail && avail > 1 {
            text.pop();
            text.push('…');
        }
        frame.render_widget(Clear, rect);
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(
                    format!("{glyph} "),
                    Style::default().fg(color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(text, t.normal()),
            ]))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(color)),
            ),
            rect,
        );
        y += 3;
    }
}
