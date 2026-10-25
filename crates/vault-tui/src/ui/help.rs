//! Help overlay and the `g` go-to popup. Vault keys come from the live keymap,
//! so config overrides show up here automatically.

use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::action::{Action, Group, GOTO_TARGETS};
use crate::app::{App, Screen};
use crate::keymap::{HelpSection, BINDINGS};
use crate::ui::layout::center_fixed;
use crate::ui::{chrome, theme};

const KEY_W: usize = 26;

pub fn draw_help(frame: &mut Frame, app: &App) {
    let t = theme();
    let area = frame.area();
    let height = area.height.saturating_sub(2).clamp(12, 40);
    let popup = center_fixed(80, height, area);

    let inner = chrome::modal(
        frame,
        popup,
        " Help ",
        " j/k scroll · Space/PgDn page · Esc close ",
    );

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(inner);

    let lines = build_help_lines(app);
    let viewport = chunks[0].height as usize;
    let max_scroll = lines.len().saturating_sub(viewport);
    let scroll = app.help_scroll.min(max_scroll);
    let visible: Vec<Line> = lines.into_iter().skip(scroll).take(viewport).collect();

    frame.render_widget(Paragraph::new(visible), chunks[0]);
    let footer = if app.screen == Screen::Vault {
        let palette = app.keymap.label(Action::OpenCommandPalette);
        format!("All commands are in the palette ({palette}) · rebind keys in config.toml")
    } else {
        "bitwarden-tui · Vaultwarden client".to_string()
    };
    frame.render_widget(
        Paragraph::new(footer)
            .style(t.muted_style())
            .alignment(Alignment::Center),
        chunks[1],
    );
}

fn heading(title: &str) -> Line<'static> {
    let t = theme();
    Line::from(Span::styled(
        format!("  {}", title.to_uppercase()),
        Style::default().fg(t.accent).add_modifier(Modifier::BOLD),
    ))
}

/// `keys` like `"j / ↓"` become keycaps; the action label follows in a column.
fn row(keys: String, action: &str) -> Line<'static> {
    let t = theme();
    let mut spans = vec![Span::raw("  ")];
    let mut used = 2;
    if keys == "palette" {
        let s = Span::styled("palette", Style::default().fg(t.muted));
        used += s.width();
        spans.push(s);
    } else {
        for (i, k) in keys.split(" / ").enumerate() {
            if i > 0 {
                spans.push(Span::raw(" "));
                used += 1;
            }
            let cap = chrome::keycap(k.trim(), t.overlay);
            used += cap.width();
            spans.push(cap);
        }
    }
    spans.push(Span::raw(
        " ".repeat((KEY_W + 2).saturating_sub(used).max(1)),
    ));
    spans.push(Span::styled(action.to_string(), t.normal()));
    Line::from(spans)
}

fn static_section(lines: &mut Vec<Line<'static>>, section: HelpSection) {
    if !lines.is_empty() {
        lines.push(Line::from(""));
    }
    lines.push(heading(section.title()));
    for b in BINDINGS.iter().filter(|b| b.section == section) {
        lines.push(row(b.keys.to_string(), b.action));
    }
}

fn vault_sections(lines: &mut Vec<Line<'static>>, app: &App) {
    let km = &app.keymap;
    for &group in Group::ALL {
        if !lines.is_empty() {
            lines.push(Line::from(""));
        }
        lines.push(heading(group.title()));
        if group == Group::GoTo {
            for (_, action) in GOTO_TARGETS {
                lines.push(row(
                    km.label(*action),
                    action.label().trim_start_matches("Go to "),
                ));
            }
            continue;
        }
        for &action in Action::all().iter().filter(|a| a.group() == group) {
            let keys = km.label_all(action);
            let keys = if keys.is_empty() {
                "palette".to_string()
            } else {
                keys
            };
            lines.push(row(keys, action.label()));
        }
        if group == Group::Copy {
            lines.push(row("1–9".into(), "Copy custom field by number"));
        }
    }
}

fn build_help_lines(app: &App) -> Vec<Line<'static>> {
    let mut lines: Vec<Line<'static>> = Vec::new();
    // The screen you're on comes first.
    let first = match app.screen {
        Screen::Login | Screen::AuthWait => Some(HelpSection::Login),
        Screen::TwoFactor => Some(HelpSection::TwoFactor),
        Screen::Unlock => Some(HelpSection::Unlock),
        Screen::Vault => None,
    };
    match first {
        Some(section) => static_section(&mut lines, section),
        None => vault_sections(&mut lines, app),
    }
    for &section in HelpSection::ALL {
        if Some(section) != first {
            static_section(&mut lines, section);
        }
    }
    if first.is_some() {
        vault_sections(&mut lines, app);
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Panes collapse: detail <80 cols · folders <60 cols",
        theme().muted_style(),
    )));
    lines
}

/// Which-key style popup shown after the go-to prefix.
pub fn draw_goto_hint(frame: &mut Frame, app: &App) {
    let t = theme();
    let area = frame.area();
    let rows = GOTO_TARGETS.len() as u16 + 2;
    let width = 24;
    if area.height < rows + 2 || area.width < width + 2 {
        return;
    }
    // Bottom-right, just above the status bar (inside the panel's padding).
    let popup = Rect::new(
        area.right() - width - 3,
        area.bottom() - rows - 2,
        width,
        rows,
    );
    let prefix = app.keymap.label(Action::GotoPrefix);
    let inner = chrome::modal(frame, popup, format!("Go to  ({prefix} …)"), "Esc cancel");
    let lines: Vec<Line> = GOTO_TARGETS
        .iter()
        .map(|(c, action)| {
            Line::from(vec![
                chrome::keycap(&c.to_string(), t.overlay),
                Span::raw("  "),
                Span::styled(action.label().trim_start_matches("Go to "), t.normal()),
            ])
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), inner);
}
