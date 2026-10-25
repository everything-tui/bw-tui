//! Command palette overlay (`:` / Ctrl+k).

use ratatui::layout::{Alignment, Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;

use crate::app::{App, Overlay};
use crate::ui::layout::center_fixed;

const ACCENT: Color = Color::Rgb(175, 82, 222);
const MUTED: Color = Color::DarkGray;
const FG: Color = Color::White;
const SELECT: Color = Color::Rgb(40, 40, 55);

pub fn draw_command_palette(frame: &mut Frame, app: &App) {
    let Overlay::CommandPalette { query, selected } = &app.overlay else {
        return;
    };
    let area = frame.area();
    let popup = center_fixed(72, 20, area);
    frame.render_widget(Clear, popup);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(Span::styled(
            " Command palette ",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ))
        .title_bottom(Span::styled(
            " ↑↓ / Ctrl+n,p select · Enter run · Esc close ",
            Style::default().fg(MUTED),
        ));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(1)])
        .split(inner);

    frame.render_widget(
        Paragraph::new(format!("> {query}▌"))
            .style(Style::default().fg(FG))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(MUTED)),
            ),
        rows[0],
    );

    let actions = app.palette_filtered_actions();
    let viewport = rows[1].height as usize;
    let width = rows[1].width as usize;
    // Keep the selection in view once it moves past the first page.
    let offset = selected.saturating_sub(viewport.saturating_sub(1));
    let mut lines = Vec::new();
    for (i, action) in actions.iter().enumerate().skip(offset).take(viewport) {
        let bg = if i == *selected { SELECT } else { Color::Reset };
        let key = app.keymap.label(*action);
        let label = action.label();
        let gap = width.saturating_sub(label.chars().count() + key.chars().count() + 2);
        lines.push(Line::from(vec![
            Span::styled(format!(" {label}"), Style::default().fg(FG).bg(bg)),
            Span::styled(" ".repeat(gap), Style::default().bg(bg)),
            Span::styled(format!("{key} "), Style::default().fg(ACCENT).bg(bg)),
        ]));
    }
    frame.render_widget(Paragraph::new(lines).alignment(Alignment::Left), rows[1]);
}
