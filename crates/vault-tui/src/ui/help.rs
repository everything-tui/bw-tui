//! Help overlay modal — driven by the canonical keymap table.

use ratatui::layout::{Alignment, Constraint, Direction, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;

use crate::app::App;
use crate::keymap::{HelpSection, BINDINGS};
use crate::ui::layout::center_fixed;
use crate::ui::theme;

pub fn draw_help(frame: &mut Frame, app: &App) {
    let t = theme();
    let area = frame.area();
    let height = area.height.saturating_sub(2).min(28).max(12);
    let popup = center_fixed(78, height, area);

    frame.render_widget(Clear, popup);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(t.focused_border())
        .title(Span::styled(" Help ", t.title()))
        .title_bottom(Span::styled(
            " j/k scroll · Esc / ? / q close ",
            t.muted_style(),
        ));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(inner);

    let lines = build_help_lines();
    let viewport = chunks[0].height as usize;
    let max_scroll = lines.len().saturating_sub(viewport);
    let scroll = app.help_scroll.min(max_scroll);
    let visible: Vec<Line> = lines.into_iter().skip(scroll).take(viewport).collect();

    frame.render_widget(Paragraph::new(visible), chunks[0]);
    frame.render_widget(
        Paragraph::new("bitwarden-tui · Vaultwarden client")
            .style(t.muted_style())
            .alignment(Alignment::Center),
        chunks[1],
    );
}

fn build_help_lines() -> Vec<Line<'static>> {
    let t = theme();
    let mut lines: Vec<Line<'static>> = Vec::new();

    for (i, section) in HelpSection::ALL.iter().enumerate() {
        let section_bindings: Vec<_> = BINDINGS
            .iter()
            .filter(|b| b.section == *section)
            .collect();
        if section_bindings.is_empty() {
            continue;
        }
        if i > 0 {
            lines.push(Line::from(""));
        }
        lines.push(Line::from(Span::styled(
            format!("── {} ──", section.title()),
            Style::default()
                .fg(t.accent)
                .add_modifier(Modifier::BOLD),
        )));
        for b in section_bindings {
            lines.push(Line::from(vec![
                Span::styled(
                    format!("  {:<22}", b.keys),
                    Style::default().fg(t.accent).add_modifier(Modifier::BOLD),
                ),
                Span::styled(b.action, t.normal()),
            ]));
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Panes collapse: detail <80 cols · folders <60 cols",
        t.muted_style(),
    )));
    lines
}
