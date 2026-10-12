//! Vault browser: folders | items | detail + status bar.

use ratatui::layout::{Alignment, Constraint, Direction, Layout, Margin, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{
    Block, BorderType, Borders, Cell, HighlightSpacing, List, ListItem, ListState, Paragraph, Row,
    Scrollbar, ScrollbarOrientation, ScrollbarState, Table, TableState, Wrap,
};
use ratatui::Frame;

use crate::app::{App, FocusPane};
use crate::models::{FilterKind, ItemType};
use crate::ui::layout::{split_status, split_vault_panes};

const ACCENT: Color = Color::Rgb(175, 82, 222);
const MUTED: Color = Color::DarkGray;
const FG: Color = Color::White;
const DIM_BORDER: Color = Color::Rgb(60, 60, 70);
const SELECT_BG: Color = Color::Rgb(55, 40, 70);
const SELECT_BG_IDLE: Color = Color::Rgb(36, 34, 44);
const ZEBRA_BG: Color = Color::Rgb(24, 24, 30);
const STATUS_BG: Color = Color::Rgb(30, 30, 36);
const FAV: Color = Color::Yellow;
const DANGER: Color = Color::Rgb(247, 118, 142);

/// Below this inner width the items table drops the secondary column.
const ITEMS_WIDE_MIN: u16 = 44;

pub fn draw_vault(frame: &mut Frame, app: &App) {
    let area = frame.area();
    let (body, status) = split_status(area);

    // Optional search bar takes a row from body.
    let (search_area, panes_area) = if app.searching || !app.search_query.is_empty() {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(1)])
            .split(body);
        (Some(chunks[0]), chunks[1])
    } else {
        (None, body)
    };

    if let Some(sa) = search_area {
        draw_search(frame, sa, app);
    }

    let (folders, items, detail) = split_vault_panes(panes_area);

    if let Some(fa) = folders {
        draw_folders(frame, fa, app);
    }
    draw_items(frame, items, app);
    if let Some(da) = detail {
        draw_detail(frame, da, app);
    }

    draw_vault_status(frame, status, app);
}

fn pane(title: &str, focused: bool) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(if focused { ACCENT } else { DIM_BORDER }))
        .title(title_span(title, focused))
}

fn draw_search(frame: &mut Frame, area: Rect, app: &App) {
    let title = if app.searching {
        " Search "
    } else {
        " Filter "
    };
    let text = Line::from(vec![
        Span::styled("/ ", Style::default().fg(ACCENT)),
        Span::styled(app.search_query.clone(), Style::default().fg(FG)),
        Span::styled(
            if app.searching { "▌" } else { "" },
            Style::default().fg(ACCENT),
        ),
    ]);
    frame.render_widget(Paragraph::new(text).block(pane(title, app.searching)), area);
}

fn draw_folders(frame: &mut Frame, area: Rect, app: &App) {
    let focused = app.focus == FocusPane::Folders;
    // Inner width minus the 2-col highlight gutter.
    let width = area.width.saturating_sub(4) as usize;

    let items: Vec<ListItem> = app
        .sidebar
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            let (glyph, glyph_color) = filter_glyph(&entry.kind);
            let count = entry.count.to_string();
            let label_budget = width.saturating_sub(2 + count.len() + 1);
            let label = truncate(&entry.label, label_budget);
            let gap = width.saturating_sub(2 + label.chars().count() + count.len());
            let mut spans = selection_marker(focused && i == app.selected_sidebar)
                .lines
                .remove(0)
                .spans;
            spans.extend([
                Span::styled(format!("{glyph} "), Style::default().fg(glyph_color)),
                Span::styled(label, Style::default().fg(FG)),
                Span::raw(" ".repeat(gap)),
                Span::styled(count, Style::default().fg(MUTED)),
            ]);
            ListItem::new(Line::from(spans))
        })
        .collect();

    let mut state = ListState::default();
    state.select(Some(app.selected_sidebar));
    frame.render_stateful_widget(
        List::new(items)
            .block(pane(" Folders ", focused))
            .highlight_style(selection_style(focused)),
        area,
        &mut state,
    );
}

fn draw_items(frame: &mut Frame, area: Rect, app: &App) {
    let focused = app.focus == FocusPane::Items;
    if matches!(app.current_filter(), FilterKind::Sends) {
        let block = pane(" Sends ", focused);
        let items: Vec<ListItem> = app
            .visible_sends
            .iter()
            .map(|&i| {
                let s = &app.sends[i];
                ListItem::new(format!(
                    "{}  {} {}{}",
                    if s.disabled { "○" } else { "●" },
                    if s.is_file { "▤" } else { "≡" },
                    s.name,
                    if s.has_password { " (pw)" } else { "" }
                ))
            })
            .collect();
        let mut state = ListState::default().with_selected(Some(app.selected_item));
        frame.render_stateful_widget(
            List::new(items)
                .block(block)
                .highlight_style(selection_style(focused)),
            area,
            &mut state,
        );
        return;
    }
    let count = app.visible.len();
    let block = pane(" Items ", focused).title_top(
        Line::from(Span::styled(
            format!(" {count} "),
            Style::default().fg(MUTED),
        ))
        .right_aligned(),
    );

    if app.visible.is_empty() {
        let empty = Paragraph::new(if app.search_query.is_empty() {
            "\nNo items in this filter.\nPress n to create one."
        } else {
            "\nNo matches.\nEsc to clear search."
        })
        .style(Style::default().fg(MUTED))
        .alignment(Alignment::Center)
        .block(block);
        frame.render_widget(empty, area);
        return;
    }

    let wide = area.width.saturating_sub(4) >= ITEMS_WIDE_MIN;
    let header_style = Style::default().fg(MUTED).add_modifier(Modifier::BOLD);
    let (header, widths): (Row, Vec<Constraint>) = if wide {
        (
            Row::new(["", "", "NAME", "DETAILS", "TYPE"]).style(header_style),
            vec![
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Fill(3),
                Constraint::Fill(2),
                Constraint::Length(5),
            ],
        )
    } else {
        (
            Row::new(["", "", "NAME", "TYPE"]).style(header_style),
            vec![
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Fill(1),
                Constraint::Length(5),
            ],
        )
    };

    // Resolve the Fill columns the way Table will, so text can be cut with an ellipsis
    // instead of being clipped mid-word. Inner = borders (2) + highlight gutter (2).
    let row_area = Rect {
        width: area.width.saturating_sub(4),
        ..area
    };
    let cols = Layout::horizontal(widths.clone())
        .spacing(1)
        .split(row_area);
    let name_w = cols[2].width as usize;
    let details_w = if wide { cols[3].width as usize } else { 0 };

    let rows: Vec<Row> = app
        .visible
        .iter()
        .enumerate()
        .map(|(i, &idx)| {
            let item = &app.items[idx];
            let org_badge = item
                .organization_id
                .as_ref()
                .and_then(|id| app.org_labels.get(id))
                .map(|n| format!(" [{n}]"))
                .unwrap_or_default();
            let mark = if app.selected_ids.contains(&item.id) {
                "◉ "
            } else {
                ""
            };
            let mut cells = vec![
                Cell::from(Span::styled(
                    "●",
                    Style::default().fg(type_color(item.item_type)),
                )),
                Cell::from(Span::styled(
                    if item.favorite { "★" } else { " " },
                    Style::default().fg(FAV),
                )),
                Cell::from(Span::styled(
                    truncate(&format!("{mark}{}{org_badge}", item.name), name_w),
                    Style::default().fg(FG),
                )),
            ];
            if wide {
                cells.push(Cell::from(Span::styled(
                    truncate(&item.subtitle(), details_w),
                    Style::default().fg(MUTED),
                )));
            }
            cells.push(Cell::from(Span::styled(
                short_type(item.item_type),
                Style::default().fg(MUTED),
            )));
            let bg = if i % 2 == 1 { ZEBRA_BG } else { Color::Reset };
            Row::new(cells).style(Style::default().bg(bg))
        })
        .collect();

    let selected = app.selected_item.min(count.saturating_sub(1));
    let mut state = TableState::default().with_selected(Some(selected));
    frame.render_stateful_widget(
        Table::new(rows, widths)
            .header(header)
            .block(block)
            .column_spacing(1)
            .highlight_symbol(selection_marker(focused))
            .row_highlight_style(selection_style(focused))
            .highlight_spacing(HighlightSpacing::Always),
        area,
        &mut state,
    );

    // Header row + 2 border rows are not part of the scrollable viewport.
    let viewport = area.height.saturating_sub(3) as usize;
    if count > viewport {
        let mut sb = ScrollbarState::new(count)
            .viewport_content_length(viewport)
            .position(selected);
        frame.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(None)
                .end_symbol(None)
                .track_symbol(Some("│"))
                .track_style(Style::default().fg(if focused { ACCENT } else { DIM_BORDER }))
                .thumb_symbol("┃")
                .thumb_style(Style::default().fg(if focused { FG } else { MUTED })),
            area.inner(Margin {
                vertical: 1,
                horizontal: 0,
            }),
            &mut sb,
        );
    }
}

fn draw_detail(frame: &mut Frame, area: Rect, app: &App) {
    let focused = app.focus == FocusPane::Detail;
    let block = pane(" Detail ", focused);
    let inner = block.inner(area).inner(Margin {
        vertical: 0,
        horizontal: 1,
    });
    frame.render_widget(block, area);

    if matches!(app.current_filter(), FilterKind::Sends) {
        let Some(idx) = app.visible_sends.get(app.selected_item).copied() else {
            frame.render_widget(
                Paragraph::new("\nSelect a send")
                    .style(Style::default().fg(MUTED))
                    .alignment(Alignment::Center),
                inner,
            );
            return;
        };
        let send = &app.sends[idx];
        let mut lines: Vec<Line> = vec![
            Line::from(Span::styled(
                send.name.clone(),
                Style::default().fg(FG).add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled(
                if send.is_file {
                    "File Send"
                } else {
                    "Text Send"
                },
                Style::default().fg(MUTED),
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
                Span::styled(format!("{label:<11}"), Style::default().fg(MUTED)),
                Span::raw(value),
            ]));
        }
        if let Some(notes) = send.notes.as_deref().filter(|n| !n.is_empty()) {
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("Notes      ", Style::default().fg(MUTED)),
                Span::raw(notes.to_string()),
            ]));
        }
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "e edit · d delete · L copy link · O open link",
            Style::default().fg(MUTED),
        )));
        frame.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: false })
                .block(Block::default()),
            inner,
        );
        return;
    }

    let totp_now = app.totp_display();
    let Some(item) = app.selected_decrypted() else {
        frame.render_widget(
            Paragraph::new("\nSelect an item")
                .style(Style::default().fg(MUTED))
                .alignment(Alignment::Center),
            inner,
        );
        return;
    };

    let [body, footer] = Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).areas(inner);
    let width = body.width;

    let mut lines: Vec<Line> = vec![
        Line::from(Span::styled(
            truncate(&item.name, width as usize),
            Style::default().fg(FG).add_modifier(Modifier::BOLD),
        )),
        {
            let mut meta = vec![
                Span::styled("● ", Style::default().fg(type_color(item.item_type))),
                Span::styled(item.item_type.label(), Style::default().fg(MUTED)),
            ];
            if item.favorite {
                meta.push(Span::styled("  ★ Favorite", Style::default().fg(FAV)));
            }
            Line::from(meta)
        },
        Line::from(Span::styled(
            "─".repeat(width as usize),
            Style::default().fg(DIM_BORDER),
        )),
    ];
    if let Some(folder) = app.folder_name_for_item(item.folder_id.as_deref()) {
        kv(&mut lines, width, "Folder", Some(folder.as_str()), "");
    }
    if let Some(created) = item.creation_date.as_deref() {
        kv(&mut lines, width, "Created", Some(created), "");
    }
    if item.reprompt {
        lines.push(Line::from(Span::styled(
            "Master password re-prompt required for sensitive actions",
            Style::default().fg(FAV),
        )));
    }

    match item.item_type {
        ItemType::Login => {
            kv(&mut lines, width, "Username", item.username.as_deref(), "y");
            if app.reveal_secrets {
                if let Some(pw) = item.password.as_deref() {
                    kv_password(&mut lines, width, "Password", pw, "c");
                } else {
                    kv(&mut lines, width, "Password", None, "c");
                }
            } else {
                let pw = item.password.as_deref().map(|_| "••••••••••");
                kv(&mut lines, width, "Password", pw, "c");
            }
            let totp_label = if let Some(display) = totp_now {
                let secs = display.remaining;
                if app.reveal_secrets {
                    Some(format!("{} ({secs}s) · r hide", display.code))
                } else {
                    Some(format!("•••••• ({secs}s) · r reveal · t copy"))
                }
            } else {
                item.totp.as_ref().map(|_| "configured".to_string())
            };
            kv(&mut lines, width, "TOTP", totp_label.as_deref(), "t");
            if item.uris.is_empty() {
                kv(&mut lines, width, "Website", None, "u");
            }
            for (i, uri) in item.uris.iter().enumerate() {
                let (label, key) = if i == 0 { ("Website", "u") } else { ("", "") };
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
            kv(&mut lines, width, "Number", number, "m");
            if let Some(num) = item.card_number.as_deref() {
                if app.reveal_secrets && !vault_session::luhn_valid(num) {
                    lines.push(Line::from(Span::styled(
                        "  ⚠ Card number fails Luhn check",
                        Style::default().fg(DANGER),
                    )));
                }
            }
            if let (Some(m), Some(y)) = (&item.card_exp_month, &item.card_exp_year) {
                let exp = format!("{m}/{y}");
                kv(&mut lines, width, "Expires", Some(&exp), "x");
                if vault_session::card_is_expired(m, y) {
                    lines.push(Line::from(Span::styled(
                        "  ⚠ Card expired",
                        Style::default().fg(DANGER),
                    )));
                } else if vault_session::card_expires_soon(m, y, 2) {
                    lines.push(Line::from(Span::styled(
                        "  ⚠ Card expires soon",
                        Style::default().fg(FAV),
                    )));
                }
            }
            let code = if app.reveal_secrets {
                item.card_code.as_deref()
            } else {
                item.card_code.as_deref().map(|_| "***")
            };
            kv(&mut lines, width, "CVC", code, "v");
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
                "p",
            );
            let priv_key = if app.reveal_secrets {
                item.ssh_private_key.as_deref()
            } else {
                item.ssh_private_key.as_ref().map(|_| "[hidden]")
            };
            kv(&mut lines, width, "Private key", priv_key, "b");
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
            Style::default().fg(MUTED).add_modifier(Modifier::BOLD),
        )));
        for (i, (_, name)) in app.detail_attachments.iter().enumerate() {
            lines.push(Line::from(format!(
                "  {}. {name} (Ctrl+{i} download · Ctrl+Shift+{i} delete)",
                i + 1
            )));
        }
        lines.push(Line::from(Span::styled(
            "A upload attachment path",
            Style::default().fg(MUTED),
        )));
    }
    if item.organization_id.is_some() && !app.item_editable_public(&item.id) {
        lines.push(Line::from(Span::styled(
            "Organization item — read-only (missing org key)",
            Style::default().fg(DANGER),
        )));
    }

    if let Some(notes) = item.notes.as_deref().filter(|n| !n.trim().is_empty()) {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Notes",
            Style::default().fg(MUTED).add_modifier(Modifier::BOLD),
        )));
        for line in notes.lines() {
            lines.push(Line::from(Span::styled(
                line.to_string(),
                Style::default().fg(FG),
            )));
        }
    }

    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), body);

    let hint = |key: &'static str, label: &'static str| {
        [
            Span::styled(key, Style::default().fg(ACCENT)),
            Span::styled(label, Style::default().fg(MUTED)),
        ]
    };
    let footer_line = Line::from(
        [
            hint("c", " copy  "),
            hint("y", " user  "),
            hint("f", " fav  "),
            hint("e", " edit"),
        ]
        .concat(),
    );
    frame.render_widget(Paragraph::new(footer_line), footer);
}

/// `Label     value                      key` row with the copy key pinned right.
fn kv(lines: &mut Vec<Line>, width: u16, label: &str, value: Option<&str>, key: &str) {
    const LABEL_W: usize = 10;
    let key_w = if key.is_empty() { 0 } else { key.len() + 1 };
    let value_budget = (width as usize).saturating_sub(LABEL_W + key_w);
    let (value, value_style) = match value {
        Some(v) if !v.is_empty() => (truncate(v, value_budget), Style::default().fg(FG)),
        _ => ("—".to_string(), Style::default().fg(MUTED)),
    };
    let gap = value_budget.saturating_sub(value.chars().count());
    let mut spans = vec![
        Span::styled(format!("{label:<LABEL_W$}"), Style::default().fg(MUTED)),
        Span::styled(value, value_style),
    ];
    if !key.is_empty() {
        spans.push(Span::raw(" ".repeat(gap + 1)));
        spans.push(Span::styled(key.to_string(), Style::default().fg(ACCENT)));
    }
    lines.push(Line::from(spans));
}

/// Password row with digit/symbol coloring when revealed.
fn kv_password(lines: &mut Vec<Line>, width: u16, label: &str, password: &str, key: &str) {
    use crate::ui::theme::theme;
    const LABEL_W: usize = 10;
    let key_w = if key.is_empty() { 0 } else { key.len() + 1 };
    let value_budget = (width as usize).saturating_sub(LABEL_W + key_w);
    let shown = truncate(password, value_budget);
    let mut spans = vec![Span::styled(
        format!("{label:<LABEL_W$}"),
        Style::default().fg(MUTED),
    )];
    spans.extend(theme().password_spans(&shown));
    let gap = value_budget.saturating_sub(shown.chars().count());
    if !key.is_empty() {
        spans.push(Span::raw(" ".repeat(gap + 1)));
        spans.push(Span::styled(key.to_string(), Style::default().fg(ACCENT)));
    }
    lines.push(Line::from(spans));
}

fn mask_card(num: &str) -> String {
    let digits: String = num.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() >= 4 {
        format!("•••• {}", &digits[digits.len() - 4..])
    } else {
        "••••".into()
    }
}

fn draw_vault_status(frame: &mut Frame, area: Rect, app: &App) {
    let lock =
        if app.screen == crate::app::Screen::Vault && app.effective_auto_lock_minutes().is_none() {
            "off".to_string()
        } else {
            app.lock_remaining()
                .map(|d| {
                    let secs = d.as_secs();
                    format!("{:02}:{:02}", secs / 60, secs % 60)
                })
                .unwrap_or_else(|| "locked".into())
        };
    let clip = app
        .clipboard_remaining()
        .map(|d| format!("clip {}s  ", d.as_secs()))
        .unwrap_or_default();

    let mode = if app.using_mock { " MOCK " } else { " LIVE " };
    let profile = app.active_profile_name();
    let left = vec![
        Span::styled(
            mode,
            Style::default()
                .fg(Color::Black)
                .bg(ACCENT)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(format!(" {profile} "), Style::default().fg(MUTED)),
        Span::styled(format!(" {}", app.status), Style::default().fg(FG)),
    ];
    let mut right = Vec::new();
    if let Some((text, level)) = app.watchtower_badge() {
        let color = match level {
            crate::app::BadgeLevel::Ok => Color::Rgb(115, 218, 202),
            crate::app::BadgeLevel::Warn => DANGER,
        };
        right.push(Span::styled(
            format!("{text}  "),
            Style::default().fg(color),
        ));
    }
    if app.power.sort != crate::app::SortMode::Name {
        right.push(Span::styled(
            format!("sort:{}  ", app.power.sort.label()),
            Style::default().fg(MUTED),
        ));
    }
    right.extend(vec![
        Span::styled(clip, Style::default().fg(FAV)),
        Span::styled("lock ", Style::default().fg(MUTED)),
        Span::styled(lock, Style::default().fg(FG)),
        Span::styled("  Ctrl+p ", Style::default().fg(ACCENT)),
        Span::styled("profiles ", Style::default().fg(MUTED)),
        Span::styled("? ", Style::default().fg(ACCENT)),
        Span::styled("help ", Style::default().fg(MUTED)),
    ]);
    let used: usize = left
        .iter()
        .chain(right.iter())
        .map(|s| s.content.chars().count())
        .sum();
    let mut spans = left;
    spans.push(Span::raw(
        " ".repeat((area.width as usize).saturating_sub(used)),
    ));
    spans.extend(right);
    frame.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::default().bg(STATUS_BG)),
        area,
    );
}

fn selection_marker(focused: bool) -> Text<'static> {
    if focused {
        Text::from(Span::styled("▌ ", Style::default().fg(ACCENT)))
    } else {
        Text::from("  ")
    }
}

fn selection_style(focused: bool) -> Style {
    if focused {
        Style::default().bg(SELECT_BG).add_modifier(Modifier::BOLD)
    } else {
        Style::default().bg(SELECT_BG_IDLE)
    }
}

/// Single-width glyphs only: emoji are double-width in most terminals and break alignment.
fn filter_glyph(kind: &FilterKind) -> (&'static str, Color) {
    match kind {
        FilterKind::All => ("◆", FG),
        FilterKind::Favorites => ("★", FAV),
        FilterKind::Login => ("●", type_color(ItemType::Login)),
        FilterKind::SecureNote => ("●", type_color(ItemType::SecureNote)),
        FilterKind::Card => ("●", type_color(ItemType::Card)),
        FilterKind::Identity => ("●", type_color(ItemType::Identity)),
        FilterKind::SshKey => ("●", type_color(ItemType::SshKey)),
        FilterKind::Folder(_) => ("▸", MUTED),
        FilterKind::NoFolder => ("▹", MUTED),
        FilterKind::Trash => ("✕", DANGER),
        FilterKind::MyVault => ("◆", FG),
        FilterKind::Organization(_) => ("◎", ACCENT),
        FilterKind::Collection(_) => ("▣", MUTED),
        FilterKind::Sends => ("➤", ACCENT),
    }
}

fn type_color(t: ItemType) -> Color {
    match t {
        ItemType::Login => Color::Rgb(122, 162, 247),
        ItemType::SecureNote => Color::Rgb(224, 175, 104),
        ItemType::Card => Color::Rgb(158, 206, 106),
        ItemType::Identity => Color::Rgb(187, 154, 247),
        ItemType::SshKey => Color::Rgb(125, 207, 255),
        ItemType::Unknown => MUTED,
    }
}

fn short_type(t: ItemType) -> &'static str {
    match t {
        ItemType::Login => "Login",
        ItemType::SecureNote => "Note",
        ItemType::Card => "Card",
        ItemType::Identity => "ID",
        ItemType::SshKey => "SSH",
        ItemType::Unknown => "Item",
    }
}

fn title_span(text: &str, focused: bool) -> Span<'static> {
    let style = if focused {
        Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(MUTED)
    };
    Span::styled(text.to_string(), style)
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
