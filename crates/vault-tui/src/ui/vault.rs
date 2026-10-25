//! Vault browser: header · sidebar | items | detail · status bar.
//!
//! Flat, layered look: no pane borders; each column sits on its own background
//! tone (`mantle` → `base` → `surface`) and focus is shown by the pane title
//! and the strength of the selection highlight.

use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState, Wrap};
use ratatui::Frame;

use crate::action::Action;
use crate::app::{App, FocusPane};
use crate::models::{FilterKind, ItemType};
use crate::ui::chrome::{self, avatar, chip, fill, hints, keycap, raised};
use crate::ui::layout::{vault_layout, HitMap};
use crate::ui::theme::{pal, theme};

pub fn draw_vault(frame: &mut Frame, app: &App) {
    let layout = vault_layout(frame.area());
    let mut hit = HitMap {
        layout,
        ..HitMap::default()
    };

    draw_header(frame, layout.header, app);
    if let Some(fa) = layout.folders {
        draw_folders(frame, fa, app, &mut hit);
    }
    draw_items(frame, layout.items, app, &mut hit);
    if let Some(da) = layout.detail {
        draw_detail(frame, da, app);
    }
    if theme().separators {
        draw_separators(frame, &layout);
    }
    draw_vault_status(frame, layout.status, app);
    *app.hitmap.borrow_mut() = hit;
}

/// Thin vertical rules between panes for themes without distinct layers.
fn draw_separators(frame: &mut Frame, layout: &crate::ui::layout::VaultLayout) {
    let t = theme();
    let style = Style::new().fg(t.border);
    let mut rule = |x: u16, r: Rect| {
        for y in r.top()..r.bottom() {
            if let Some(cell) = frame.buffer_mut().cell_mut((x, y)) {
                cell.set_symbol(if t.ascii { "|" } else { "│" })
                    .set_style(style);
            }
        }
    };
    if let Some(f) = layout.folders {
        rule(f.right().saturating_sub(1), f);
    }
    if let Some(d) = layout.detail {
        rule(d.x, d);
    }
}

/// Pane title row: `LOGINS` in muted caps, accent with a bar when focused.
fn pane_title(
    title: &str,
    focused: bool,
    right: Option<String>,
    width: u16,
    bg: Color,
) -> Line<'static> {
    let t = theme();
    let (bar, style) = if focused {
        (
            Span::styled(if t.ascii { "|" } else { "▍" }, Style::new().fg(t.accent)),
            Style::new().fg(t.accent).add_modifier(Modifier::BOLD),
        )
    } else {
        (
            Span::raw(" "),
            Style::new().fg(t.muted).add_modifier(Modifier::BOLD),
        )
    };
    let title = title.to_uppercase();
    let mut spans = vec![bar, Span::styled(title.clone(), style)];
    if let Some(r) = right {
        let used = 1 + title.chars().count();
        let gap = (width as usize).saturating_sub(used + r.chars().count() + 1);
        spans.push(Span::raw(" ".repeat(gap)));
        spans.push(Span::styled(r, Style::new().fg(t.muted)));
    }
    Line::from(spans).style(Style::new().bg(bg))
}

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

fn draw_header(frame: &mut Frame, area: Rect, app: &App) {
    let t = theme();
    fill(frame, area, t.mantle);

    let glyph = if t.ascii { "#" } else { "◆" };
    let filter_label = app
        .sidebar
        .get(app.selected_sidebar)
        .map(|e| sidebar_label(&e.label).to_string())
        .unwrap_or_else(|| "All items".into());
    let sep = if t.ascii { ">" } else { "›" };
    let mut left = vec![
        Span::styled(
            format!(" {glyph} "),
            Style::new().fg(t.accent).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "bitwarden-tui",
            Style::new().fg(t.text).add_modifier(Modifier::BOLD),
        ),
        Span::styled(format!("   Vault {sep} "), Style::new().fg(t.muted)),
        Span::styled(filter_label, Style::new().fg(t.subtext)),
    ];
    if !app.search_query.is_empty() {
        left.push(Span::styled(format!(" {sep} "), Style::new().fg(t.muted)));
        left.push(Span::styled(
            format!("“{}”", app.search_query),
            Style::new().fg(t.accent),
        ));
    }

    // Right side: status chips, most important last (closest to the edge).
    let mut right: Vec<Span> = Vec::new();
    let dot = if t.ascii { "*" } else { "●" };
    if let Some((text, level)) = app.watchtower_badge() {
        let color = match level {
            crate::app::BadgeLevel::Ok => t.success,
            crate::app::BadgeLevel::Warn => t.danger,
        };
        right.push(Span::styled(format!("{text}  "), Style::new().fg(color)));
    }
    if app.power.sort != crate::app::SortMode::Name {
        right.push(Span::styled(
            format!(
                "{} {}  ",
                if t.ascii { "sort" } else { "⇅" },
                app.power.sort.label()
            ),
            Style::new().fg(t.subtext),
        ));
    }
    if let Some(d) = app.clipboard_remaining() {
        right.push(Span::styled(
            format!("clip {}s  ", d.as_secs()),
            Style::new().fg(t.favorite),
        ));
    }
    if let Some(sync) = app.sync_badge() {
        let color = if sync == "offline" {
            t.warning
        } else {
            t.success
        };
        right.push(Span::styled(format!("{dot} "), Style::new().fg(color)));
        right.push(Span::styled(
            format!("{sync}  "),
            Style::new().fg(t.subtext),
        ));
    }
    let lock = if app.effective_auto_lock_minutes().is_none() {
        None
    } else {
        app.lock_remaining().map(|d| d.as_secs())
    };
    if let Some(secs) = lock {
        let color = if secs < 60 { t.warning } else { t.subtext };
        right.push(Span::styled(
            format!(
                "{} {:02}:{:02}  ",
                if t.ascii { "lock" } else { "◷" },
                secs / 60,
                secs % 60
            ),
            Style::new().fg(color),
        ));
    }
    right.push(Span::styled(
        format!(
            "{} {} ",
            if t.ascii { "@" } else { "◉" },
            app.active_profile_name()
        ),
        Style::new().fg(t.subtext),
    ));
    if app.using_mock {
        right.push(Span::raw(" "));
        right.push(chip("MOCK", t.accent_fg, t.warning));
        right.push(Span::raw(" "));
    }

    let width = |spans: &[Span]| -> usize { spans.iter().map(|s| s.width()).sum() };
    let gap = (area.width as usize).saturating_sub(width(&left) + width(&right));
    let mut spans = left;
    spans.push(Span::raw(" ".repeat(gap)));
    spans.extend(right);
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

// ---------------------------------------------------------------------------
// Sidebar
// ---------------------------------------------------------------------------

/// Sidebar group a filter belongs to (a header is drawn when it changes).
fn sidebar_group(kind: &FilterKind) -> &'static str {
    match kind {
        FilterKind::All | FilterKind::MyVault | FilterKind::Favorites => "Vault",
        FilterKind::Login
        | FilterKind::SecureNote
        | FilterKind::Card
        | FilterKind::Identity
        | FilterKind::SshKey => "Types",
        FilterKind::Folder(_) | FilterKind::NoFolder => "Folders",
        FilterKind::Organization(_) | FilterKind::Collection(_) => "Organizations",
        FilterKind::Sends | FilterKind::Trash => "More",
    }
}

/// Labels carry `Org · ` / `Col · ` prefixes; the section header says that already.
fn sidebar_label(label: &str) -> &str {
    label
        .strip_prefix("Org · ")
        .or_else(|| label.strip_prefix("Col · "))
        .unwrap_or(label)
}

fn draw_folders(frame: &mut Frame, area: Rect, app: &App, hit: &mut HitMap) {
    let t = theme();
    let bg = t.mantle;
    fill(frame, area, bg);
    let focused = app.focus == FocusPane::Folders;
    let inner = Rect::new(
        area.x + 1,
        area.y + 1,
        area.width.saturating_sub(2),
        area.height.saturating_sub(1),
    );
    if inner.height == 0 {
        return;
    }
    let width = inner.width as usize;

    // Build display rows: section headers interleaved with entries.
    enum Row<'a> {
        Header(&'static str),
        Gap,
        Entry(usize, &'a crate::models::SidebarEntry),
    }
    let mut rows: Vec<Row> = Vec::new();
    let mut last_group = "";
    for (i, entry) in app.sidebar.iter().enumerate() {
        let group = sidebar_group(&entry.kind);
        if group != last_group {
            if !rows.is_empty() {
                rows.push(Row::Gap);
            }
            rows.push(Row::Header(group));
            last_group = group;
        }
        rows.push(Row::Entry(i, entry));
    }
    let selected_row = rows
        .iter()
        .position(|r| matches!(r, Row::Entry(i, _) if *i == app.selected_sidebar))
        .unwrap_or(0);
    let viewport = inner.height as usize;
    // Keep a header above the selection visible when scrolling up.
    let offset = (selected_row + 1).saturating_sub(viewport);

    for (screen_i, row) in rows.iter().skip(offset).take(viewport).enumerate() {
        let y = inner.y + screen_i as u16;
        let r = Rect::new(inner.x, y, inner.width, 1);
        match row {
            Row::Gap => {}
            Row::Header(title) => {
                let title = if *title == "Vault" && focused {
                    Line::from(vec![Span::styled(
                        title.to_uppercase(),
                        Style::new().fg(t.accent).add_modifier(Modifier::BOLD),
                    )])
                } else {
                    chrome::section(title)
                };
                frame.render_widget(
                    Paragraph::new(title.style(Style::new().bg(bg))),
                    Rect {
                        x: r.x + 1,
                        width: r.width.saturating_sub(1),
                        ..r
                    },
                );
            }
            Row::Entry(i, entry) => {
                hit.sidebar_rows.push((y, *i));
                let selected = *i == app.selected_sidebar;
                let (glyph, glyph_color) = filter_glyph(&entry.kind);
                let label = sidebar_label(&entry.label);
                let count = if entry.count > 0 {
                    entry.count.to_string()
                } else {
                    String::new()
                };
                let label_budget = width.saturating_sub(5 + count.len());
                let label = truncate(label, label_budget);
                let gap = width.saturating_sub(4 + label.chars().count() + count.len() + 1);
                let row_style = if selected {
                    t.row_selected(focused)
                } else {
                    Style::new().bg(bg)
                };
                let bar = if selected && focused {
                    Span::styled(if t.ascii { ">" } else { "▌" }, Style::new().fg(t.accent))
                } else {
                    Span::raw(" ")
                };
                let label_style = if selected {
                    Style::new().fg(t.text).add_modifier(Modifier::BOLD)
                } else {
                    Style::new().fg(t.subtext)
                };
                let line = Line::from(vec![
                    bar,
                    Span::styled(format!(" {glyph} "), Style::new().fg(glyph_color)),
                    Span::styled(label, label_style),
                    Span::raw(" ".repeat(gap)),
                    Span::styled(format!("{count} "), Style::new().fg(t.muted)),
                ])
                .style(row_style);
                frame.render_widget(Paragraph::new(line), r);
            }
        }
    }
}

/// Width reserved at the end of each item row for ★ / org badges.
const BADGE_COL: usize = 5;

// ---------------------------------------------------------------------------
// Item list
// ---------------------------------------------------------------------------

fn draw_search_bar(frame: &mut Frame, area: Rect, app: &App, count_label: String) {
    let t = theme();
    let bg = raised(t.base);
    let active = app.searching;
    let icon = if t.ascii { "/" } else { "⌕" };
    let mut spans = vec![Span::styled(
        format!(" {icon} "),
        Style::new().fg(if active { t.accent } else { t.muted }),
    )];
    if app.search_query.is_empty() && !active {
        spans.push(Span::styled("Search", Style::new().fg(t.muted)));
        let key = app.keymap.label(Action::SearchStart);
        spans.push(Span::styled(format!("  {key}"), Style::new().fg(t.border)));
    } else {
        spans.push(Span::styled(
            app.search_query.clone(),
            Style::new().fg(t.text),
        ));
        if active {
            spans.push(Span::styled(
                if t.ascii { "_" } else { "▏" },
                Style::new().fg(t.accent),
            ));
        }
    }
    let used: usize = spans.iter().map(|s| s.width()).sum();
    let gap = (area.width as usize).saturating_sub(used + count_label.chars().count() + 1);
    spans.push(Span::raw(" ".repeat(gap)));
    spans.push(Span::styled(
        format!("{count_label} "),
        Style::new().fg(t.muted),
    ));
    let style = if t.no_color {
        Style::new().add_modifier(if active {
            Modifier::UNDERLINED
        } else {
            Modifier::empty()
        })
    } else {
        Style::new().bg(bg)
    };
    frame.render_widget(Paragraph::new(Line::from(spans)).style(style), area);
}

fn draw_items(frame: &mut Frame, area: Rect, app: &App, hit: &mut HitMap) {
    let t = theme();
    fill(frame, area, t.base);
    let focused = app.focus == FocusPane::Items;
    let inner = Rect::new(
        area.x + 1,
        area.y + 1,
        area.width.saturating_sub(2),
        area.height.saturating_sub(1),
    );
    if inner.height < 3 {
        return;
    }
    let sends = matches!(app.current_filter(), FilterKind::Sends);
    let count = if sends {
        app.visible_sends.len()
    } else {
        app.visible.len()
    };
    let noun = match (sends, count) {
        (true, 1) => "send",
        (true, _) => "sends",
        (false, 1) => "item",
        (false, _) => "items",
    };
    let marked = if app.selected_ids.is_empty() {
        String::new()
    } else {
        format!("{} marked · ", app.selected_ids.len())
    };
    draw_search_bar(
        frame,
        Rect::new(inner.x, inner.y, inner.width, 1),
        app,
        format!("{marked}{count} {noun}"),
    );
    frame.render_widget(
        Paragraph::new(pane_title(
            if sends { "Sends" } else { "Items" },
            focused,
            None,
            inner.width,
            t.base,
        )),
        Rect::new(inner.x, inner.y + 2, inner.width, 1),
    );
    let list = Rect::new(
        inner.x,
        inner.y + 3,
        inner.width,
        inner.height.saturating_sub(3),
    );

    if count == 0 {
        let msg = if sends {
            format!(
                "No Sends yet.\n\nPress {} to create one.",
                app.keymap.label(Action::New)
            )
        } else if app.search_query.is_empty() {
            format!(
                "Nothing here yet.\n\nPress {} to create an item.",
                app.keymap.label(Action::New)
            )
        } else {
            format!(
                "No matches for “{}”.\n\nEsc clears the search.",
                app.search_query
            )
        };
        frame.render_widget(
            Paragraph::new(format!("\n\n{msg}"))
                .style(Style::new().fg(t.muted))
                .alignment(Alignment::Center),
            list,
        );
        return;
    }

    let selected = app.selected_item.min(count - 1);
    let viewport = list.height as usize;
    let offset = (selected + 1).saturating_sub(viewport);
    let width = list.width.saturating_sub(1) as usize; // leave a column for the scrollbar
    let wide = width >= 46;

    for (row_i, idx) in (offset..count).take(viewport).enumerate() {
        let y = list.y + row_i as u16;
        hit.item_rows.push((y, idx));
        let is_sel = idx == selected;
        let row_style = if is_sel {
            t.row_selected(focused)
        } else {
            Style::new().bg(t.base)
        };
        let bar = if is_sel && focused {
            Span::styled(if t.ascii { ">" } else { "▌" }, Style::new().fg(t.accent))
        } else {
            Span::raw(" ")
        };
        let name_style = if is_sel {
            Style::new().fg(t.text).add_modifier(Modifier::BOLD)
        } else {
            Style::new().fg(t.text)
        };

        let (av, name, sub, badges): (Span, String, String, Vec<Span>) = if sends {
            let s = &app.sends[app.visible_sends[idx]];
            let color = if s.is_file { t.info } else { t.accent };
            let mut badges = Vec::new();
            if s.has_password {
                badges.push(Span::styled(
                    if t.ascii { "pw " } else { "⚿ " },
                    Style::new().fg(t.subtext),
                ));
            }
            if s.disabled {
                badges.push(Span::styled("off ", Style::new().fg(t.muted)));
            }
            let sub = if s.is_file { "file" } else { "text" };
            (
                avatar(&s.name, color),
                s.name.clone(),
                sub.to_string(),
                badges,
            )
        } else {
            let item = &app.items[app.visible[idx]];
            let mut badges = Vec::new();
            if item.organization_id.is_some() {
                badges.push(Span::styled(
                    if t.ascii { "org " } else { "◎ " },
                    Style::new().fg(t.accent),
                ));
            }
            if item.favorite {
                badges.push(Span::styled(
                    format!("{} ", t.star()),
                    Style::new().fg(t.favorite),
                ));
            }
            let av = if app.selected_ids.contains(&item.id) {
                chip(if t.ascii { "x" } else { "✓" }, t.accent_fg, t.accent)
            } else {
                avatar(&item.name, type_color(item.item_type))
            };
            (av, item.name.clone(), item.subtitle(), badges)
        };

        let badge_w: usize = badges.iter().map(|b| b.width()).sum();
        // bar(1) + space + avatar(3) + space(2) … fixed badge column (so the
        // subtitle column lines up whether or not a row has badges).
        let fixed = 1 + 1 + 3 + 2 + BADGE_COL.max(badge_w) + 1;
        let room = width.saturating_sub(fixed);
        let (name_w, sub_w) = if wide {
            let name_w = (room * 55 / 100).max(8);
            (name_w, room.saturating_sub(name_w + 2))
        } else {
            (room, 0)
        };
        let name_txt = truncate(&name, name_w);
        let mut spans = vec![bar, Span::raw(" "), av, Span::raw("  ")];
        spans.push(Span::styled(name_txt.clone(), name_style));
        let mut used = 1 + 1 + 3 + 2 + name_txt.chars().count();
        if wide {
            let pad = name_w.saturating_sub(name_txt.chars().count()) + 2;
            let sub_txt = truncate(&sub, sub_w);
            spans.push(Span::raw(" ".repeat(pad)));
            used += pad + sub_txt.chars().count();
            spans.push(Span::styled(sub_txt, Style::new().fg(t.muted)));
        }
        let gap = width.saturating_sub(used + badge_w);
        spans.push(Span::raw(" ".repeat(gap)));
        spans.extend(badges);
        frame.render_widget(
            Paragraph::new(Line::from(spans).style(row_style)),
            Rect::new(list.x, y, width as u16, 1),
        );
    }

    if count > viewport {
        let mut sb = ScrollbarState::new(count.saturating_sub(viewport) + 1).position(offset);
        frame.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(None)
                .end_symbol(None)
                .track_symbol(Some(" "))
                .thumb_symbol(if t.ascii { "#" } else { "▐" })
                .thumb_style(Style::new().fg(if focused { t.accent_dim } else { t.border })),
            list,
            &mut sb,
        );
    }
}

fn draw_detail(frame: &mut Frame, area: Rect, app: &App) {
    let t = theme();
    fill(frame, area, t.surface);
    let focused = app.focus == FocusPane::Detail;
    let inner = Rect::new(
        area.x + 2,
        area.y + 1,
        area.width.saturating_sub(4),
        area.height.saturating_sub(1),
    );

    if matches!(app.current_filter(), FilterKind::Sends) {
        let Some(idx) = app.visible_sends.get(app.selected_item).copied() else {
            frame.render_widget(
                Paragraph::new("\nSelect a send")
                    .style(Style::default().fg(pal::muted()))
                    .alignment(Alignment::Center),
                inner,
            );
            return;
        };
        let send = &app.sends[idx];
        let mut lines: Vec<Line> = vec![
            Line::from(Span::styled(
                send.name.clone(),
                Style::default()
                    .fg(pal::text())
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled(
                if send.is_file {
                    "File Send"
                } else {
                    "Text Send"
                },
                Style::default().fg(pal::muted()),
            )),
            Line::from(""),
        ];
        if send.is_file {
            lines.push(Line::from(format!(
                "File: {}{}",
                send.file_name.as_deref().unwrap_or("-"),
                send.file_size_name
                    .as_deref()
                    .map(|s| format!(" ({s})"))
                    .unwrap_or_default()
            )));
        } else {
            lines.push(Line::from(
                send.text.clone().unwrap_or_else(|| "(empty)".into()),
            ));
        }
        lines.push(Line::from(""));
        let fmt_date = |d: &Option<String>| {
            d.as_deref()
                .map(crate::send_form::format_local_datetime)
                .unwrap_or_else(|| "never".into())
        };
        let access = match send.max_access_count {
            Some(max) => format!("{} / {max}", send.access_count),
            None => format!("{} (no limit)", send.access_count),
        };
        let yes_no = |b: bool| if b { "yes" } else { "no" };
        for (label, value) in [
            ("Password", yes_no(send.has_password).to_string()),
            ("Accesses", access),
            ("Expires", fmt_date(&send.expiration_date)),
            ("Deletes", fmt_date(&send.deletion_date)),
            ("Hide email", yes_no(send.hide_email).to_string()),
            ("Disabled", yes_no(send.disabled).to_string()),
        ] {
            lines.push(Line::from(vec![
                Span::styled(format!("{label:<11}"), Style::default().fg(pal::muted())),
                Span::raw(value),
            ]));
        }
        if let Some(notes) = send.notes.as_deref().filter(|n| !n.is_empty()) {
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("Notes      ", Style::default().fg(pal::muted())),
                Span::raw(notes.to_string()),
            ]));
        }
        lines.push(Line::from(""));
        let km = &app.keymap;
        lines.push(Line::from(hints(
            &[
                (km.label(Action::Edit), "edit".into()),
                (km.label(Action::Delete), "delete".into()),
                (km.label(Action::CopySendLink), "copy link".into()),
            ],
            t.surface,
        )));
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
        return;
    }

    let totp_now = app.totp_display();
    let Some(item) = app.selected_decrypted() else {
        frame.render_widget(
            Paragraph::new("\nSelect an item")
                .style(Style::default().fg(pal::muted()))
                .alignment(Alignment::Center),
            inner,
        );
        return;
    };

    let [body, footer] = Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).areas(inner);
    let width = body.width;
    // Copy-key labels next to fields follow the live keymap.
    let key = |a: crate::action::Action| app.keymap.label(a);
    let (k_user, k_pass, k_totp, k_uri) = (
        key(Action::CopyUsername),
        key(Action::CopyPassword),
        key(Action::CopyTotp),
        key(Action::CopyUri),
    );

    let mut meta = vec![Span::styled(
        item.item_type.label().to_string(),
        Style::new().fg(type_color(item.item_type)),
    )];
    let dot = || Span::styled("  ·  ", Style::new().fg(t.muted));
    if item.favorite {
        meta.push(dot());
        meta.push(Span::styled(
            format!("{} Favorite", t.star()),
            Style::new().fg(t.favorite),
        ));
    }
    if let Some(folder) = app.folder_name_for_item(item.folder_id.as_deref()) {
        meta.push(dot());
        meta.push(Span::styled(folder, Style::new().fg(t.subtext)));
    }
    if let Some(org) = item
        .organization_id
        .as_ref()
        .and_then(|id| app.org_labels.get(id))
    {
        meta.push(dot());
        meta.push(Span::styled(org.clone(), Style::new().fg(t.accent)));
    }
    let mut lines: Vec<Line> = vec![
        Line::from(vec![
            avatar(&item.name, type_color(item.item_type)),
            Span::raw("  "),
            Span::styled(
                truncate(&item.name, (width as usize).saturating_sub(5)),
                Style::new().fg(t.text).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(meta),
        Line::from(""),
    ];
    if item.reprompt {
        let lock = if t.ascii { "!" } else { "⚿" };
        lines.push(Line::from(Span::styled(
            format!("{lock} Master password re-prompt on sensitive actions"),
            Style::default().fg(pal::warning()),
        )));
        lines.push(Line::from(""));
    }

    match item.item_type {
        ItemType::Login => {
            kv(
                &mut lines,
                width,
                "Username",
                item.username.as_deref(),
                &k_user,
            );
            if app.reveal_secrets {
                if let Some(pw) = item.password.as_deref() {
                    kv_password(&mut lines, width, "Password", pw, &k_pass);
                } else {
                    kv(&mut lines, width, "Password", None, &k_pass);
                }
            } else {
                let pw = item.password.as_deref().map(|_| "••••••••••");
                kv(&mut lines, width, "Password", pw, &k_pass);
            }
            let totp_label = if let Some(display) = totp_now {
                let secs = display.remaining;
                let code = if app.reveal_secrets {
                    group_code(&display.code)
                } else {
                    "••• •••".to_string()
                };
                Some(format!("{code}    {} {secs}s", pie(secs)))
            } else {
                item.totp.as_ref().map(|_| "configured".to_string())
            };
            kv(&mut lines, width, "TOTP", totp_label.as_deref(), &k_totp);
            if item.uris.is_empty() {
                kv(&mut lines, width, "Website", None, &k_uri);
            }
            for (i, uri) in item.uris.iter().enumerate() {
                let (label, key) = if i == 0 {
                    ("Website", k_uri.as_str())
                } else {
                    ("", "")
                };
                let mt = uri.match_type.unwrap_or(0);
                let display = if mt == 0 {
                    uri.uri.clone()
                } else {
                    format!("{} [{}]", uri.uri, crate::app::uri_match_label(mt))
                };
                kv(&mut lines, width, label, Some(&display), key);
            }
            for (i, field) in item.custom_fields.iter().enumerate().take(9) {
                let slot = (i + 1).to_string();
                let value = if field.hidden() && !app.reveal_secrets {
                    Some("••••••")
                } else if field.value.is_empty() {
                    None
                } else {
                    Some(field.value.as_str())
                };
                let label = if matches!(
                    field.kind,
                    crate::models::CustomFieldKind::Boolean
                        | crate::models::CustomFieldKind::Linked
                ) {
                    format!("{} [{}]", field.name, field.kind.label())
                } else {
                    field.name.clone()
                };
                kv(&mut lines, width, &label, value, &slot);
            }
            for (i, pk) in item.passkeys.iter().enumerate() {
                let label = if i == 0 { "Passkey" } else { "" };
                let mut value = pk.label();
                if pk.discoverable {
                    value.push_str(" · discoverable");
                }
                if let Some(date) = pk.creation_date.as_deref() {
                    value.push_str(&format!(" · {date}"));
                }
                kv(&mut lines, width, label, Some(&value), "");
            }
        }
        ItemType::Card => {
            kv(
                &mut lines,
                width,
                "Cardholder",
                item.cardholder_name.as_deref(),
                "",
            );
            let detected = item
                .card_number
                .as_deref()
                .and_then(vault_session::detect_card_brand);
            let brand = item
                .card_brand
                .as_deref()
                .or(detected)
                .map(|b| b.to_string());
            kv(&mut lines, width, "Brand", brand.as_deref(), "");
            let masked_owned = item.card_number.as_deref().map(mask_card);
            let number = if app.reveal_secrets {
                item.card_number.as_deref()
            } else {
                masked_owned.as_deref()
            };
            kv(
                &mut lines,
                width,
                "Number",
                number,
                &key(Action::CopyCardNumber),
            );
            if let Some(num) = item.card_number.as_deref() {
                if app.reveal_secrets && !vault_session::luhn_valid(num) {
                    // Sit directly under the number, before the field spacer.
                    let at = lines.len().saturating_sub(1);
                    lines.insert(
                        at,
                        Line::from(Span::styled(
                            "⚠ fails Luhn check",
                            Style::default().fg(pal::danger()),
                        )),
                    );
                }
            }
            if let (Some(m), Some(y)) = (&item.card_exp_month, &item.card_exp_year) {
                let exp = format!("{m}/{y}");
                kv(
                    &mut lines,
                    width,
                    "Expires",
                    Some(&exp),
                    &key(Action::CopyCardExpiry),
                );
                if vault_session::card_is_expired(m, y) {
                    lines.push(Line::from(Span::styled(
                        "  ⚠ Card expired",
                        Style::default().fg(pal::danger()),
                    )));
                } else if vault_session::card_expires_soon(m, y, 2) {
                    lines.push(Line::from(Span::styled(
                        "  ⚠ Card expires soon",
                        Style::default().fg(pal::favorite()),
                    )));
                }
            }
            let code = if app.reveal_secrets {
                item.card_code.as_deref()
            } else {
                item.card_code.as_deref().map(|_| "***")
            };
            kv(&mut lines, width, "CVC", code, &key(Action::CopyCardCode));
        }
        ItemType::Identity => {
            kv(
                &mut lines,
                width,
                "Title",
                item.identity_title.as_deref(),
                "",
            );
            kv(&mut lines, width, "Name", item.identity_name.as_deref(), "");
            kv(
                &mut lines,
                width,
                "Email",
                item.identity_email.as_deref(),
                "",
            );
            kv(
                &mut lines,
                width,
                "Phone",
                item.identity_phone.as_deref(),
                "",
            );
            kv(
                &mut lines,
                width,
                "Username",
                item.identity_username.as_deref(),
                "",
            );
            kv(
                &mut lines,
                width,
                "Company",
                item.identity_company.as_deref(),
                "",
            );
            let addr = [
                item.identity_address1.as_deref(),
                item.identity_address2.as_deref(),
                item.identity_address3.as_deref(),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(", ");
            if !addr.is_empty() {
                kv(&mut lines, width, "Address", Some(addr.as_str()), "");
            }
            let city_line = match (
                item.identity_city.as_deref(),
                item.identity_state.as_deref(),
                item.identity_postal_code.as_deref(),
            ) {
                (Some(c), s, p) => Some(format!(
                    "{c}{}{}",
                    s.map(|x| format!(", {x}")).unwrap_or_default(),
                    p.map(|x| format!(" {x}")).unwrap_or_default()
                )),
                _ => None,
            };
            kv(&mut lines, width, "City", city_line.as_deref(), "");
            kv(
                &mut lines,
                width,
                "Country",
                item.identity_country.as_deref(),
                "",
            );
        }
        ItemType::SshKey => {
            kv(
                &mut lines,
                width,
                "Public key",
                item.ssh_public_key.as_deref(),
                &key(Action::CopySshPublic),
            );
            let priv_key = if app.reveal_secrets {
                item.ssh_private_key.as_deref()
            } else {
                item.ssh_private_key.as_ref().map(|_| "[hidden]")
            };
            kv(
                &mut lines,
                width,
                "Private key",
                priv_key,
                &key(Action::CopySshPrivate),
            );
            kv(
                &mut lines,
                width,
                "Fingerprint",
                item.ssh_fingerprint.as_deref(),
                "",
            );
        }
        ItemType::SecureNote | ItemType::Unknown => {}
    }

    if !app.detail_attachments.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Attachments",
            Style::default()
                .fg(pal::muted())
                .add_modifier(Modifier::BOLD),
        )));
        for (i, (_, name)) in app.detail_attachments.iter().enumerate() {
            lines.push(Line::from(format!("  {}. {name}", i + 1)));
        }
        let km = &app.keymap;
        lines.push(Line::from(Span::styled(
            format!(
                "{} open · save · delete   {} upload",
                km.label(Action::Attachments),
                km.label(Action::UploadAttachment)
            ),
            Style::default().fg(pal::muted()),
        )));
    }
    if item.organization_id.is_some() && !app.item_editable_public(&item.id) {
        lines.push(Line::from(Span::styled(
            "Organization item — read-only (missing org key)",
            Style::default().fg(pal::danger()),
        )));
    }

    if let Some(notes) = item.notes.as_deref().filter(|n| !n.trim().is_empty()) {
        if lines.last().is_some_and(|l| l.width() > 0) {
            lines.push(Line::from(""));
        }
        field_label(&mut lines, width, "Notes", &key(Action::CopyNotes));
        for line in notes.lines() {
            lines.push(Line::from(Span::styled(
                line.to_string(),
                Style::default().fg(pal::text()),
            )));
        }
    }

    // Wrapped height estimate; drives scroll clamping for j/k in the focused pane.
    let wrap_w = body.width.max(1) as usize;
    let content_h: usize = lines
        .iter()
        .map(|l| l.width().max(1).div_ceil(wrap_w))
        .sum();
    let viewport = body.height as usize;
    let max_scroll = content_h.saturating_sub(viewport).min(u16::MAX as usize) as u16;
    app.detail_scroll_max.set(max_scroll);
    let scroll = app.detail_scroll_offset().min(max_scroll);
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0)),
        body,
    );
    if max_scroll > 0 {
        let mut sb = ScrollbarState::new(max_scroll as usize + 1).position(scroll as usize);
        frame.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(None)
                .end_symbol(None)
                .track_symbol(Some(" "))
                .thumb_symbol("┃")
                .thumb_style(Style::default().fg(if focused {
                    pal::accent()
                } else {
                    pal::muted()
                })),
            // The 1-col margin right of the text, inside the border.
            body.offset(ratatui::layout::Offset { x: 1, y: 0 }),
            &mut sb,
        );
    }

    let km = &app.keymap;
    let mut pairs: Vec<(String, String)> = Vec::new();
    let mut hint = |action: Action, label: &str| pairs.push((km.label(action), label.to_string()));
    if focused {
        hint(Action::MoveDown, "scroll");
        hint(Action::Open, "edit");
    } else {
        hint(Action::Edit, "edit");
    }
    hint(
        Action::ToggleReveal,
        if app.reveal_secrets { "hide" } else { "reveal" },
    );
    hint(Action::ToggleFavorite, "fav");
    if !app.detail_attachments.is_empty() {
        hint(Action::Attachments, "files");
    }
    frame.render_widget(Paragraph::new(Line::from(hints(&pairs, t.surface))), footer);
}

/// Stacked field: `LABEL ······ [key]` then the value, then a spacer.
/// An empty label continues the previous field (extra URIs).
fn kv(lines: &mut Vec<Line>, width: u16, label: &str, value: Option<&str>, key: &str) {
    let t = theme();
    let (value, value_style) = match value {
        Some(v) if !v.is_empty() => (truncate(v, width as usize), Style::new().fg(t.text)),
        _ => ("—".to_string(), Style::new().fg(t.muted)),
    };
    field_label(lines, width, label, key);
    lines.push(Line::from(Span::styled(value, value_style)));
    lines.push(Line::from(""));
}

fn field_label(lines: &mut Vec<Line>, width: u16, label: &str, key: &str) {
    let t = theme();
    if label.is_empty() {
        if lines.last().is_some_and(|l| l.width() == 0) {
            lines.pop();
        }
        return;
    }
    let label = label.to_uppercase();
    let mut spans = vec![Span::styled(
        label.clone(),
        Style::new().fg(t.muted).add_modifier(Modifier::BOLD),
    )];
    if !key.is_empty() {
        let cap = keycap(key, t.surface);
        let gap = (width as usize).saturating_sub(label.chars().count() + cap.width());
        spans.push(Span::raw(" ".repeat(gap)));
        spans.push(cap);
    }
    lines.push(Line::from(spans));
}

/// Password field with digit/symbol coloring when revealed.
fn kv_password(lines: &mut Vec<Line>, width: u16, label: &str, password: &str, key: &str) {
    let shown = truncate(password, width as usize);
    field_label(lines, width, label, key);
    lines.push(Line::from(theme().password_spans(&shown)));
    lines.push(Line::from(""));
}

fn mask_card(num: &str) -> String {
    let digits: String = num.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() >= 4 {
        format!("•••• {}", &digits[digits.len() - 4..])
    } else {
        "••••".into()
    }
}

/// `482 913` grouping for TOTP codes.
fn group_code(code: &str) -> String {
    if code.len() == 6 && code.is_ascii() {
        format!("{} {}", &code[..3], &code[3..])
    } else {
        code.to_string()
    }
}

/// Countdown glyph for the TOTP period.
fn pie(remaining: u64) -> &'static str {
    if theme().ascii {
        return "";
    }
    match remaining {
        23.. => "●",
        16..=22 => "◕",
        8..=15 => "◑",
        _ => "◔",
    }
}

fn draw_vault_status(frame: &mut Frame, area: Rect, app: &App) {
    let t = theme();
    fill(frame, area, t.mantle);
    let mode = if app.searching {
        "SEARCH"
    } else if app.focus == FocusPane::Folders {
        "FOLDERS"
    } else if matches!(app.current_filter(), FilterKind::Sends) {
        "SENDS"
    } else if app.in_trash() {
        "TRASH"
    } else if app.focus == FocusPane::Detail {
        "DETAIL"
    } else {
        "VAULT"
    };
    let mode_bg = if app.in_trash() { t.danger } else { t.accent };
    let left = vec![
        chip(mode, t.accent_fg, mode_bg),
        Span::styled(format!(" {}", app.status), Style::new().fg(t.subtext)),
    ];

    let width_of = |spans: &[Span]| -> usize { spans.iter().map(|s| s.width()).sum() };
    let mut budget = (area.width as usize).saturating_sub(width_of(&left) + 1);

    let km = &app.keymap;
    let to_pair = |(action, label): (Action, String)| (km.label(action), label);
    let help = hints(&[to_pair((Action::ToggleHelp, "help".into()))], t.mantle);
    budget = budget.saturating_sub(width_of(&help));
    let mut right: Vec<Span> = Vec::new();
    for pair in context_hints(app).into_iter().map(to_pair) {
        let h = hints(&[pair], t.mantle);
        let w = width_of(&h);
        if w > budget {
            break;
        }
        budget -= w;
        right.extend(h);
    }
    right.extend(help);

    let used = width_of(&left) + width_of(&right);
    let mut spans = left;
    spans.push(Span::raw(
        " ".repeat((area.width as usize).saturating_sub(used)),
    ));
    spans.extend(right);
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// Key hints for the status bar, based on what has focus and what's selected.
fn context_hints(app: &App) -> Vec<(crate::action::Action, String)> {
    use crate::action::Action::*;
    let h = |a, l: &str| (a, l.to_string());
    if app.searching {
        return vec![
            h(Open, "done"),
            h(Back, "clear"),
            h(MoveDown, "next result"),
        ];
    }
    if app.focus == FocusPane::Folders {
        return vec![
            h(Open, "open"),
            h(New, "new folder"),
            h(Edit, "rename"),
            h(Delete, "delete"),
            h(GotoPrefix, "go to"),
        ];
    }
    if matches!(app.current_filter(), FilterKind::Sends) {
        return vec![
            h(New, "new"),
            h(CopySendLink, "copy link"),
            h(Edit, "edit"),
            h(Delete, "delete"),
            h(ReceiveSend, "open link"),
        ];
    }
    if !app.selected_ids.is_empty() {
        return vec![
            h(ToggleMark, "mark"),
            (Delete, format!("delete {}", app.selected_ids.len())),
            h(ShareToOrg, "share"),
            h(Back, "clear marks"),
        ];
    }
    if app.in_trash() {
        return vec![
            h(Restore, "restore"),
            h(Delete, "delete"),
            h(EmptyTrash, "empty trash"),
        ];
    }
    if app.focus == FocusPane::Detail {
        return vec![
            h(MoveDown, "scroll"),
            h(Open, "edit"),
            h(CopyPassword, "pass"),
            h(CopyUsername, "user"),
            h(Back, "back"),
        ];
    }
    let mut hints = vec![h(CopyPassword, "pass"), h(CopyUsername, "user")];
    if app
        .selected_decrypted()
        .is_some_and(|i| i.totp.as_deref().is_some_and(|t| !t.is_empty()))
    {
        hints.push(h(CopyTotp, "totp"));
    }
    if app.pending_undo.is_some() {
        hints.insert(0, h(UndoDelete, "undo"));
    }
    hints.extend([
        h(SearchStart, "search"),
        h(GotoPrefix, "go to"),
        h(OpenCommandPalette, "commands"),
    ]);
    hints
}

/// Single-width glyphs only: emoji are double-width in most terminals and break alignment.
fn filter_glyph(kind: &FilterKind) -> (&'static str, Color) {
    match kind {
        FilterKind::All => ("◆", pal::text()),
        FilterKind::Favorites => ("★", pal::favorite()),
        FilterKind::Login => ("●", type_color(ItemType::Login)),
        FilterKind::SecureNote => ("●", type_color(ItemType::SecureNote)),
        FilterKind::Card => ("●", type_color(ItemType::Card)),
        FilterKind::Identity => ("●", type_color(ItemType::Identity)),
        FilterKind::SshKey => ("●", type_color(ItemType::SshKey)),
        FilterKind::Folder(_) => ("▸", pal::muted()),
        FilterKind::NoFolder => ("▹", pal::muted()),
        FilterKind::Trash => ("✕", pal::danger()),
        FilterKind::MyVault => ("◆", pal::text()),
        FilterKind::Organization(_) => ("◎", pal::accent()),
        FilterKind::Collection(_) => ("▣", pal::muted()),
        FilterKind::Sends => ("➤", pal::accent()),
    }
}

fn type_color(t: ItemType) -> Color {
    match t {
        ItemType::Login => pal::login(),
        ItemType::SecureNote => pal::note(),
        ItemType::Card => pal::card(),
        ItemType::Identity => pal::identity(),
        ItemType::SshKey => pal::ssh(),
        ItemType::Unknown => pal::muted(),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if max == 0 {
        return String::new();
    }
    let count = s.chars().count();
    if count <= max {
        s.to_string()
    } else if max <= 1 {
        "…".into()
    } else {
        let take = max - 1;
        format!("{}…", s.chars().take(take).collect::<String>())
    }
}
