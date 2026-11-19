//! Command palette overlay (`:` / Ctrl+k).

use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::app::{App, Overlay};
use crate::ui::chrome::{self, keycap, raised};
use crate::ui::layout::center_fixed;
use crate::ui::theme::theme;

pub fn draw_command_palette(frame: &mut Frame, app: &App) {
    let Overlay::CommandPalette { query, selected } = &app.overlay else {
        return;
    };
    let t = theme();
    let popup = center_fixed(72, 20, frame.area());
    let inner = chrome::modal(
        frame,
        popup,
        "Command palette",
        "↑↓ select · Enter run · Esc close",
    );
    if inner.height < 4 {
        return;
    }

    // Prompt row.
    let input = Rect::new(inner.x, inner.y, inner.width, 1);
    let prompt = if t.ascii { ">" } else { "›" };
    let mut spans = vec![Span::styled(
        format!(" {prompt} "),
        Style::new().fg(t.accent).add_modifier(Modifier::BOLD),
    )];
    if query.is_empty() {
        spans.push(Span::styled("Type a command…", Style::new().fg(t.muted)));
    } else {
        spans.push(Span::styled(query.clone(), Style::new().fg(t.text)));
        spans.push(Span::styled(
            if t.ascii { "_" } else { "▏" },
            Style::new().fg(t.accent),
        ));
    }
    frame.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::new().bg(raised(t.overlay))),
        input,
    );

    let list = Rect::new(
        inner.x,
        inner.y + 2,
        inner.width,
        inner.height.saturating_sub(2),
    );
    let actions = app.palette_filtered_actions();
    if actions.is_empty() {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "  No matching commands",
                Style::new().fg(t.muted),
            ))),
            list,
        );
        return;
    }
    let viewport = list.height as usize;
    let width = list.width as usize;
    // Keep the selection in view once it moves past the first page.
    let offset = selected.saturating_sub(viewport.saturating_sub(1));
    for (row, (i, action)) in actions
        .iter()
        .enumerate()
        .skip(offset)
        .take(viewport)
        .enumerate()
    {
        let is_sel = i == *selected;
        let bg = if is_sel { t.select_bg } else { t.overlay };
        let key = app.keymap.label(*action);
        let group = action.group().title().split(' ').next().unwrap_or("");
        let label = action.label();
        let cap = if key.is_empty() {
            Span::raw("")
        } else {
            keycap(&key, bg)
        };
        let used = 2 + label.chars().count() + group.chars().count() + 2 + cap.width() + 1;
        let gap = width.saturating_sub(used);
        let bar = if is_sel {
            Span::styled(if t.ascii { ">" } else { "▌" }, Style::new().fg(t.accent))
        } else {
            Span::raw(" ")
        };
        let label_style = if is_sel {
            Style::new().fg(t.text).add_modifier(Modifier::BOLD)
        } else {
            Style::new().fg(t.text)
        };
        let line = Line::from(vec![
            bar,
            Span::raw(" "),
            Span::styled(label.to_string(), label_style),
            Span::raw(" ".repeat(gap)),
            Span::styled(format!("{group}  "), Style::new().fg(t.muted)),
            cap,
            Span::raw(" "),
        ])
        .style(Style::new().bg(bg));
        frame.render_widget(
            Paragraph::new(line),
            Rect::new(list.x, list.y + row as u16, list.width, 1),
        );
    }
}
