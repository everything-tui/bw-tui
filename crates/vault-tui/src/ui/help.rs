//! Help overlay modal.

use ratatui::layout::{Alignment, Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;

use crate::ui::layout::center_fixed;

const ACCENT: Color = Color::Rgb(175, 82, 222);
const MUTED: Color = Color::DarkGray;
const FG: Color = Color::White;

pub fn draw_help(frame: &mut Frame) {
    let area = frame.area();
    let popup = center_fixed(64, 24, area);

    frame.render_widget(Clear, popup);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(Span::styled(
            " Help ",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ))
        .title_bottom(Span::styled(
            " Esc / ? / q to close ",
            Style::default().fg(MUTED),
        ));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(inner);

    let lines = vec![
        bind_line("Ctrl+h", "Show/hide password (login · unlock)"),
        bind_line("Ctrl+r", "Toggle remember server & email"),
        bind_line("Tab / h l", "Focus panes (folders · items · detail)"),
        bind_line("j / k", "Move selection"),
        bind_line("Enter / e", "Edit login"),
        bind_line("/", "Search"),
        bind_line("n", "New login"),
        bind_line("Ctrl+n", "New folder"),
        bind_line("d", "Delete item"),
        bind_line("f", "Toggle favorite"),
        bind_line("g", "Password generator"),
        bind_line("c", "Copy password"),
        bind_line("y", "Copy username"),
        bind_line("t", "Copy TOTP code"),
        bind_line("u", "Copy URI"),
        bind_line("Ctrl+s", "Sync vault"),
        bind_line("Ctrl+l", "Lock vault"),
        bind_line("q", "Quit"),
        bind_line("?", "Toggle this help"),
        Line::from(""),
        Line::from(Span::styled(
            "Panes collapse: detail <80 cols · folders <60 cols",
            Style::default().fg(MUTED),
        )),
    ];

    frame.render_widget(Paragraph::new(lines), chunks[0]);
    frame.render_widget(
        Paragraph::new("bitwarden-tui · Vaultwarden client")
            .style(Style::default().fg(MUTED))
            .alignment(Alignment::Center),
        chunks[1],
    );
}

fn bind_line(keys: &str, desc: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("  {keys:<12}"),
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ),
        Span::styled(desc.to_string(), Style::default().fg(FG)),
    ])
}
