//! Shared visual building blocks: floating panels on a dimmed backdrop,
//! keycaps, chips, section labels, avatars and filled input fields.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};
use ratatui::Frame;

use crate::ui::theme::{pal, theme};

/// Paint `area` with a background color.
pub fn fill(frame: &mut Frame, area: Rect, bg: Color) {
    frame.render_widget(Block::new().style(Style::new().bg(bg)), area);
}

/// Mix two colors (`t` = 0 → `a`, 1 → `b`). Non-RGB colors snap to whichever is closer.
pub fn blend(a: Color, b: Color, t: f32) -> Color {
    match (a, b) {
        (Color::Rgb(r1, g1, b1), Color::Rgb(r2, g2, b2)) => {
            let mix = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t).round() as u8;
            Color::Rgb(mix(r1, r2), mix(g1, g2), mix(b1, b2))
        }
        _ if t < 0.5 => a,
        _ => b,
    }
}

/// Fade everything already drawn toward the backdrop color, so a popup on top
/// reads as the only thing in focus.
pub fn dim_backdrop(buf: &mut Buffer, area: Rect) {
    let t = theme();
    if t.no_color {
        for cell in buf.content.iter_mut() {
            cell.modifier.insert(Modifier::DIM);
        }
        return;
    }
    let back = t.backdrop;
    for y in area.top()..area.bottom() {
        for x in area.left()..area.right() {
            let cell = &mut buf[(x, y)];
            let bg = if cell.bg == Color::Reset {
                t.base
            } else {
                cell.bg
            };
            let fg = if cell.fg == Color::Reset {
                t.text
            } else {
                cell.fg
            };
            cell.bg = blend(bg, back, 0.55);
            cell.fg = blend(fg, back, 0.6);
            cell.modifier.remove(Modifier::BOLD);
        }
    }
}

/// Draw a floating panel and return the content area inside it.
///
/// `area` is the size a dialog asked for (historically including a 1-cell
/// border). The panel grows outward around it for breathing room, so the
/// returned content rect is exactly what a bordered block used to give.
/// The top row holds the title and the bottom row key hints (`"key label · …"`).
pub fn modal(frame: &mut Frame, area: Rect, title: impl AsRef<str>, hint: impl AsRef<str>) -> Rect {
    let (title, hint) = (title.as_ref(), hint.as_ref());
    let t = theme();
    let screen = frame.area();
    let area = area.intersection(screen);
    let inner = modal_inner(area);
    if area.width < 4 || area.height < 3 {
        return inner;
    }
    // Grow by 2 columns and 1 row on each side where the screen allows.
    let x0 = area.x.saturating_sub(2).max(screen.x);
    let y0 = area.y.saturating_sub(1).max(screen.y);
    let x1 = (area.right() + 2).min(screen.right());
    let y1 = (area.bottom() + 1).min(screen.bottom());
    let outer = Rect::new(x0, y0, x1 - x0, y1 - y0);

    let panel = t.overlay;
    paint_panel(frame, outer, panel);

    let title_row = Rect::new(outer.x + 2, outer.y, outer.width.saturating_sub(4), 1);
    let title_line = Line::from(vec![
        Span::styled(if t.ascii { "# " } else { "◆ " }, Style::new().fg(t.accent)),
        Span::styled(
            title.trim().to_string(),
            Style::new().fg(t.text).add_modifier(Modifier::BOLD),
        ),
    ]);
    frame.render_widget(Paragraph::new(title_line), title_row);

    let hint_row = Rect::new(
        outer.x + 2,
        outer.bottom() - 1,
        outer.width.saturating_sub(4),
        1,
    );
    let spans = fit(hint_spans(hint, panel), hint_row.width as usize);
    frame.render_widget(Paragraph::new(Line::from(spans)), hint_row);

    inner
}

/// Solid panel with half-block side edges (no line border). Returns the
/// content rect: one row of padding top and bottom, one column each side.
pub fn panel(frame: &mut Frame, area: Rect, bg: Color) -> Rect {
    let area = area.intersection(frame.area());
    paint_panel(frame, area, bg);
    modal_inner(area)
}

fn paint_panel(frame: &mut Frame, area: Rect, panel: Color) {
    let t = theme();
    let buf = frame.buffer_mut();
    for y in area.top()..area.bottom() {
        for x in area.left()..area.right() {
            let cell = &mut buf[(x, y)];
            let edge = x == area.left() || x + 1 == area.right();
            if edge && !t.no_color && !t.ascii {
                // Panel color on the inner half, whatever was behind on the outer half.
                cell.set_symbol(if x == area.left() { "▐" } else { "▌" });
                cell.fg = panel;
                cell.modifier = Modifier::empty();
            } else {
                cell.reset();
                cell.bg = panel;
                cell.fg = t.text;
            }
        }
    }
    if t.no_color || t.ascii {
        frame.render_widget(
            Block::bordered().border_style(Style::new().fg(t.border)),
            area,
        );
    }
}

/// Keep whole keycap+label pairs that fit in `width` (pairs are 2 spans).
pub fn fit(spans: Vec<Span<'static>>, width: usize) -> Vec<Span<'static>> {
    let mut out = Vec::new();
    let mut used = 0;
    for pair in spans.chunks(2) {
        let w: usize = pair.iter().map(|s| s.width()).sum();
        if used + w > width {
            break;
        }
        used += w;
        out.extend(pair.iter().cloned());
    }
    out
}

/// Inner content rect of a [`modal`] drawn in `area` (for layout math).
pub fn modal_inner(area: Rect) -> Rect {
    Rect::new(
        area.x + 1,
        area.y + 1,
        area.width.saturating_sub(2),
        area.height.saturating_sub(2),
    )
}

/// `" c "` keycap on a raised background.
pub fn keycap(key: &str, on: Color) -> Span<'static> {
    let t = theme();
    if t.no_color {
        return Span::styled(
            format!("[{key}]"),
            Style::new().add_modifier(Modifier::BOLD),
        );
    }
    Span::styled(
        format!(" {key} "),
        Style::new()
            .fg(t.accent)
            .bg(raised(on))
            .add_modifier(Modifier::BOLD),
    )
}

/// A background one step lighter (dark themes) or darker (light themes) than `on`.
pub fn raised(on: Color) -> Color {
    let t = theme();
    let on = if on == Color::Reset { t.base } else { on };
    let toward = if is_light(t.base) {
        Color::Rgb(0, 0, 0)
    } else {
        Color::Rgb(255, 255, 255)
    };
    blend(on, toward, 0.08)
}

fn is_light(c: Color) -> bool {
    match c {
        Color::Rgb(r, g, b) => (r as u32 * 299 + g as u32 * 587 + b as u32 * 114) / 1000 > 140,
        Color::White | Color::Gray => true,
        _ => false,
    }
}

/// Keycap + label pairs: `[(“c”, “copy”), …]`.
pub fn hints(pairs: &[(String, String)], on: Color) -> Vec<Span<'static>> {
    let t = theme();
    let mut out = Vec::new();
    for (key, label) in pairs {
        if key.is_empty() {
            continue;
        }
        out.push(keycap(key, on));
        out.push(Span::styled(
            format!(" {label}  "),
            Style::new().fg(t.subtext),
        ));
    }
    out
}

/// Parse a `"Enter save · Esc cancel"` hint string into keycap spans.
pub fn hint_spans(hint: &str, on: Color) -> Vec<Span<'static>> {
    let t = theme();
    let mut out = Vec::new();
    for seg in hint.split('·').map(str::trim).filter(|s| !s.is_empty()) {
        if seg.starts_with('(') {
            out.push(Span::styled(format!("{seg}  "), Style::new().fg(t.muted)));
            out.push(Span::raw(""));
            continue;
        }
        let (key, label) = seg.split_once(' ').unwrap_or((seg, ""));
        out.push(keycap(key, on));
        if label.is_empty() {
            out.push(Span::raw("  "));
        } else {
            out.push(Span::styled(
                format!(" {}  ", label.trim()),
                Style::new().fg(t.subtext),
            ));
        }
    }
    out
}

/// Small rounded-looking chip: ` text ` on a colored background.
pub fn chip(text: &str, fg: Color, bg: Color) -> Span<'static> {
    if theme().no_color {
        return Span::styled(
            format!("[{text}]"),
            Style::new().add_modifier(Modifier::BOLD),
        );
    }
    Span::styled(
        format!(" {text} "),
        Style::new().fg(fg).bg(bg).add_modifier(Modifier::BOLD),
    )
}

/// Uppercase, letter-spaced section label (`V I E W S` style is too wide; plain caps).
pub fn section(title: &str) -> Line<'static> {
    let t = theme();
    Line::from(Span::styled(
        title.to_uppercase(),
        Style::new().fg(t.muted).add_modifier(Modifier::BOLD),
    ))
}

/// Colored letter tile for a list row: ` G `.
pub fn avatar(name: &str, color: Color) -> Span<'static> {
    let t = theme();
    let letter = name
        .chars()
        .find(|c| c.is_alphanumeric())
        .map(|c| c.to_uppercase().next().unwrap_or(c))
        .unwrap_or('•');
    if t.no_color {
        return Span::styled(
            format!(" {letter} "),
            Style::new().add_modifier(Modifier::BOLD),
        );
    }
    Span::styled(
        format!(" {letter} "),
        Style::new()
            .fg(t.accent_fg)
            .bg(color)
            .add_modifier(Modifier::BOLD),
    )
}

/// Filled single-line input with its label on the row above (3 rows total,
/// same footprint as the old bordered field).
#[allow(clippy::too_many_arguments)]
pub fn input(
    frame: &mut Frame,
    area: Rect,
    label: &str,
    value: &str,
    focused: bool,
    secret: bool,
    hint: &str,
    error: bool,
) {
    let t = theme();
    if area.height == 0 {
        return;
    }
    let label_style = if error {
        Style::new().fg(t.danger).add_modifier(Modifier::BOLD)
    } else if focused {
        Style::new().fg(t.accent).add_modifier(Modifier::BOLD)
    } else {
        Style::new().fg(t.subtext)
    };
    let label_row = Rect::new(area.x, area.y, area.width, 1);
    let mut label_line = vec![Span::styled(format!("  {label}"), label_style)];
    if !hint.is_empty() {
        let used = label.chars().count() + 2;
        let gap = (area.width as usize).saturating_sub(used + hint.chars().count() + 1);
        label_line.push(Span::raw(" ".repeat(gap)));
        label_line.push(Span::styled(
            hint.to_string(),
            Style::new().fg(if focused { t.accent } else { t.muted }),
        ));
    }
    frame.render_widget(Paragraph::new(Line::from(label_line)), label_row);
    if area.height < 2 {
        return;
    }

    let field_row = Rect::new(area.x, area.y + 1, area.width, 1);
    let bg = if focused {
        raised(t.surface)
    } else {
        t.surface
    };
    let shown = if secret && !value.is_empty() {
        "•".repeat(value.chars().count().min(48))
    } else {
        value.to_string()
    };
    let bar = if t.ascii { "|" } else { "▎" };
    let mut spans = vec![
        Span::styled(bar, Style::new().fg(if focused { t.accent } else { bg })),
        Span::raw(" "),
    ];
    // Keep the end of long values (where the cursor is) visible.
    let room = (area.width as usize).saturating_sub(4);
    let count = shown.chars().count();
    let visible: String = if count > room {
        shown.chars().skip(count - room).collect()
    } else {
        shown
    };
    spans.push(Span::styled(visible, Style::new().fg(t.text)));
    if focused {
        spans.push(Span::styled(
            if t.ascii { "_" } else { "▏" },
            Style::new().fg(t.accent).add_modifier(Modifier::SLOW_BLINK),
        ));
    }
    let style = if t.no_color {
        if focused {
            Style::new().add_modifier(Modifier::UNDERLINED)
        } else {
            Style::new()
        }
    } else {
        Style::new().bg(bg)
    };
    frame.render_widget(Paragraph::new(Line::from(spans)).style(style), field_row);
}

/// Checkbox glyph.
pub fn check(on: bool) -> &'static str {
    match (on, theme().ascii) {
        (true, false) => "◉",
        (false, false) => "○",
        (true, true) => "[x]",
        (false, true) => "[ ]",
    }
}

/// Small horizontal meter: `▰▰▰▱▱`.
pub fn meter(filled: usize, total: usize, color: Color) -> Vec<Span<'static>> {
    let t = theme();
    let (on, off) = if t.ascii { ("#", "-") } else { ("▰", "▱") };
    vec![
        Span::styled(on.repeat(filled.min(total)), Style::new().fg(color)),
        Span::styled(
            off.repeat(total.saturating_sub(filled)),
            Style::new().fg(pal::border()),
        ),
    ]
}
