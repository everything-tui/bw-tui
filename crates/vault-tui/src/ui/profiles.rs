//! Profile manager overlay.

use ratatui::layout::{Alignment, Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;

use crate::app::{App, Overlay, ProfileEditField, ProfileManagerMode};
use crate::profiles::{format_auto_lock_label, profile_has_auth};
use crate::ui::layout::center_fixed;

const ACCENT: Color = Color::Rgb(175, 82, 222);
const MUTED: Color = Color::DarkGray;
const FG: Color = Color::White;
const ERR: Color = Color::LightRed;
const SELECT: Color = Color::Rgb(40, 40, 55);
const OPEN: Color = Color::Rgb(80, 200, 120);

pub fn draw_profile_manager(frame: &mut Frame, app: &App) {
    let Overlay::ProfileManager { selected, mode } = &app.overlay else {
        return;
    };
    match mode {
        ProfileManagerMode::List => draw_list(frame, app, *selected),
        ProfileManagerMode::Create { name, error } => draw_create(frame, name, error.as_deref()),
        ProfileManagerMode::Edit {
            name,
            server_url,
            email,
            auto_lock_input,
            clipboard_clear_input,
            field,
            error,
            ..
        } => draw_edit(
            frame,
            name,
            server_url,
            email,
            auto_lock_input,
            clipboard_clear_input,
            *field,
            error.as_deref(),
        ),
        ProfileManagerMode::ConfirmDelete { id, name } => draw_confirm_delete(frame, app, id, name),
    }
}

fn draw_list(frame: &mut Frame, app: &App, selected: usize) {
    let area = frame.area();
    let n = app.profiles.profiles.len() as u16;
    // 2 content lines + 1 separator per item (no trailing sep), plus chrome.
    let body_h = if n == 0 {
        2
    } else {
        n.saturating_mul(3).saturating_sub(1)
    };
    let height = (body_h + 4).clamp(10, 22);
    let popup = center_fixed(68, height, area);
    frame.render_widget(Clear, popup);

    let lock_switch = if app.profiles.lock_on_profile_switch {
        "on"
    } else {
        "off"
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(Span::styled(
            " Profiles ",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ))
        .title_bottom(Span::styled(
            format!(
                " Enter switch · n new · e edit · d delete · L lock-on-switch: {lock_switch} · Esc "
            ),
            Style::default().fg(MUTED),
        ));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    if app.profiles.profiles.is_empty() {
        frame.render_widget(
            Paragraph::new("No profiles")
                .style(Style::default().fg(MUTED))
                .alignment(Alignment::Center),
            inner,
        );
        return;
    }

    let width = inner.width as usize;
    let inner_lines = inner.height as usize;
    let lines_per_profile = 3usize;
    let max_visible = (inner_lines / lines_per_profile).max(1);
    let n = app.profiles.profiles.len();
    let window_start = if n <= max_visible {
        0
    } else {
        let half = max_visible / 2;
        selected
            .saturating_sub(half)
            .min(n.saturating_sub(max_visible))
    };
    let window_end = (window_start + max_visible).min(n);

    let mut lines: Vec<Line> = Vec::new();
    for (i, p) in app.profiles.profiles[window_start..window_end]
        .iter()
        .enumerate()
    {
        let i = window_start + i;
        let is_sel = i == selected;
        let is_active = p.id == app.active_profile_id;
        let is_open = app.profile_is_open(&p.id);
        let bg = if is_sel { SELECT } else { Color::Reset };
        let name_style = Style::default()
            .fg(FG)
            .bg(bg)
            .add_modifier(if is_sel || is_active {
                Modifier::BOLD
            } else {
                Modifier::empty()
            });
        let meta_style = Style::default().fg(MUTED).bg(bg);

        let marker = if is_active { "●" } else { " " };
        let saved = if profile_has_auth(&app.data_root, &p.id) {
            "session saved"
        } else {
            "not signed in"
        };
        let email = if p.email.is_empty() {
            "—"
        } else {
            p.email.as_str()
        };
        let server = if p.server_url.is_empty() {
            "—"
        } else {
            p.server_url.as_str()
        };
        let lock = format_auto_lock_label(p.auto_lock_minutes);

        let meta = pad_line(
            &format!("   {email}  ·  {server}  ·  {saved}  ·  {lock}"),
            width,
        );

        if is_open {
            let mut spans = Vec::new();
            let prefix = format!(" {marker} {} ", p.name);
            let prefix_len = prefix.chars().count().min(width);
            let prefix_padded: String = prefix.chars().take(prefix_len).collect();
            spans.push(Span::styled(prefix_padded, name_style));
            let rest = width.saturating_sub(prefix_len);
            if rest > 0 {
                let badge = "open";
                let badge_style = Style::default()
                    .fg(OPEN)
                    .bg(bg)
                    .add_modifier(Modifier::BOLD);
                if badge.len() <= rest {
                    spans.push(Span::styled(badge, badge_style));
                    let pad = rest - badge.len();
                    if pad > 0 {
                        spans.push(Span::styled(" ".repeat(pad), Style::default().bg(bg)));
                    }
                } else {
                    spans.push(Span::styled(" ".repeat(rest), Style::default().bg(bg)));
                }
            }
            lines.push(Line::from(spans));
        } else {
            let title = pad_line(&format!(" {marker} {} ", p.name), width);
            lines.push(Line::from(Span::styled(title, name_style)));
        }
        lines.push(Line::from(Span::styled(meta, meta_style)));
        if i + 1 < window_end {
            lines.push(Line::from(Span::styled(
                "─".repeat(width),
                Style::default().fg(Color::Rgb(55, 55, 70)),
            )));
        }
    }

    frame.render_widget(Paragraph::new(lines), inner);
}

fn pad_line(s: &str, width: usize) -> String {
    let mut out = s.chars().take(width).collect::<String>();
    let len = out.chars().count();
    if len < width {
        out.push_str(&" ".repeat(width - len));
    }
    out
}

fn draw_create(frame: &mut Frame, name: &str, error: Option<&str>) {
    let area = frame.area();
    let popup = center_fixed(56, 10, area);
    frame.render_widget(Clear, popup);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(Span::styled(
            " New profile ",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ))
        .title_bottom(Span::styled(
            " Enter save · Esc back ",
            Style::default().fg(MUTED),
        ));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(1)])
        .split(inner);

    draw_field(frame, rows[0], "Name", name, true);
    if let Some(err) = error {
        frame.render_widget(
            Paragraph::new(Span::styled(err, Style::default().fg(ERR))),
            rows[1],
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn draw_edit(
    frame: &mut Frame,
    name: &str,
    server_url: &str,
    email: &str,
    auto_lock_input: &str,
    clipboard_clear_input: &str,
    field: ProfileEditField,
    error: Option<&str>,
) {
    let area = frame.area();
    let popup = center_fixed(60, 20, area);
    frame.render_widget(Clear, popup);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(Span::styled(
            " Edit profile ",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ))
        .title_bottom(Span::styled(
            " Tab fields · Enter save · Esc back ",
            Style::default().fg(MUTED),
        ));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(1),
        ])
        .split(inner);

    draw_field(
        frame,
        rows[0],
        "Name",
        name,
        field == ProfileEditField::Name,
    );
    draw_field(
        frame,
        rows[1],
        "Server URL",
        server_url,
        field == ProfileEditField::Server,
    );
    draw_field(
        frame,
        rows[2],
        "Email",
        email,
        field == ProfileEditField::Email,
    );
    draw_field(
        frame,
        rows[3],
        "Auto-lock (minutes / off)",
        auto_lock_input,
        field == ProfileEditField::AutoLock,
    );
    draw_field(
        frame,
        rows[4],
        "Clipboard clear (seconds)",
        clipboard_clear_input,
        field == ProfileEditField::ClipboardClear,
    );
    if let Some(err) = error {
        frame.render_widget(
            Paragraph::new(Span::styled(err, Style::default().fg(ERR))),
            rows[5],
        );
    } else {
        frame.render_widget(
            Paragraph::new(Span::styled(
                "Idle timeout · clipboard auto-clear (min 5s when applied)",
                Style::default().fg(MUTED),
            )),
            rows[5],
        );
    }
}

fn draw_confirm_delete(frame: &mut Frame, app: &App, id: &str, name: &str) {
    let area = frame.area();
    let popup = center_fixed(54, 9, area);
    frame.render_widget(Clear, popup);

    let has_auth = profile_has_auth(&app.data_root, id);
    let warn = if has_auth {
        "This will also remove the remembered session."
    } else {
        "Delete this profile?"
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ERR))
        .title(Span::styled(
            " Delete profile ",
            Style::default().fg(ERR).add_modifier(Modifier::BOLD),
        ))
        .title_bottom(Span::styled(
            " y confirm · n / Esc cancel ",
            Style::default().fg(MUTED),
        ));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let text = format!("Delete “{name}”?\n{warn}");
    frame.render_widget(
        Paragraph::new(text)
            .alignment(Alignment::Center)
            .style(Style::default().fg(FG)),
        inner,
    );
}

fn draw_field(
    frame: &mut Frame,
    area: ratatui::layout::Rect,
    label: &str,
    value: &str,
    focused: bool,
) {
    let border = if focused { ACCENT } else { MUTED };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border))
        .title(Span::styled(
            format!(" {label} "),
            Style::default().fg(border),
        ));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    frame.render_widget(
        Paragraph::new(value.to_string()).style(Style::default().fg(FG)),
        inner,
    );
}
