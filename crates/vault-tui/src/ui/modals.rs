//! Modal overlays: item form, generator, folder create, delete confirm.

use ratatui::layout::{Alignment, Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{App, EditField, Overlay};
use crate::ui::layout::center_fixed;

const ACCENT: Color = Color::Rgb(175, 82, 222);
const MUTED: Color = Color::DarkGray;
const FG: Color = Color::White;
const ERR: Color = Color::LightRed;

pub fn draw_overlay(frame: &mut Frame, app: &App) {
    match &app.overlay {
        Overlay::None => {}
        Overlay::ItemForm { .. } => draw_item_form(frame, app),
        Overlay::Generator { .. } => draw_generator(frame, app),
        Overlay::FolderForm { .. } => draw_folder_form(frame, app),
        Overlay::ConfirmDelete { .. } => draw_confirm_delete(frame, app),
    }
}

fn draw_item_form(frame: &mut Frame, app: &App) {
    let Overlay::ItemForm {
        editing_id,
        name,
        username,
        password,
        totp,
        uri,
        notes,
        field,
    } = &app.overlay
    else {
        return;
    };

    let area = frame.area();
    let popup = center_fixed(64, 22, area);
    frame.render_widget(Clear, popup);

    let title = if editing_id.is_some() {
        " Edit login "
    } else {
        " New login "
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(Span::styled(
            title,
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ))
        .title_bottom(Span::styled(
            " Tab fields · Ctrl+s save · Ctrl+g generate · Esc cancel ",
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
            Constraint::Min(3),
        ])
        .split(inner);

    draw_form_field(frame, rows[0], "Name", name, *field == EditField::Name, false);
    draw_form_field(
        frame,
        rows[1],
        "Username",
        username,
        *field == EditField::Username,
        false,
    );
    draw_form_field(
        frame,
        rows[2],
        "Password",
        password,
        *field == EditField::Password,
        true,
    );
    draw_form_field(frame, rows[3], "TOTP", totp, *field == EditField::Totp, false);
    draw_form_field(frame, rows[4], "URI", uri, *field == EditField::Uri, false);
    draw_form_field(frame, rows[5], "Notes", notes, *field == EditField::Notes, false);
}

fn draw_generator(frame: &mut Frame, app: &App) {
    let Overlay::Generator {
        length,
        uppercase,
        lowercase,
        digits,
        symbols,
        preview,
        insert_to_form,
    } = &app.overlay
    else {
        return;
    };

    let area = frame.area();
    let popup = center_fixed(56, 14, area);
    frame.render_widget(Clear, popup);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(Span::styled(
            " Password generator ",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ))
        .title_bottom(Span::styled(
            if *insert_to_form {
                " Enter insert · r regen · +/- length · u/l/d/s toggles · Esc "
            } else {
                " Enter/c copy · r regen · +/- length · u/l/d/s toggles · Esc "
            },
            Style::default().fg(MUTED),
        ));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(2),
            Constraint::Length(2),
            Constraint::Min(1),
        ])
        .margin(1)
        .split(inner);

    frame.render_widget(
        Paragraph::new(preview.as_str())
            .style(Style::default().fg(FG).add_modifier(Modifier::BOLD))
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true }),
        rows[0],
    );

    let flags = format!(
        "length {length}  [{}] upper  [{}] lower  [{}] digits  [{}] symbols",
        on(*uppercase),
        on(*lowercase),
        on(*digits),
        on(*symbols),
    );
    frame.render_widget(
        Paragraph::new(flags)
            .style(Style::default().fg(MUTED))
            .alignment(Alignment::Center),
        rows[1],
    );
    frame.render_widget(
        Paragraph::new("r regenerate · +/− length · u/l/d/s toggle charset")
            .style(Style::default().fg(MUTED))
            .alignment(Alignment::Center),
        rows[2],
    );
}

fn on(v: bool) -> char {
    if v {
        'x'
    } else {
        ' '
    }
}

fn draw_folder_form(frame: &mut Frame, app: &App) {
    let Overlay::FolderForm { name } = &app.overlay else {
        return;
    };

    let area = frame.area();
    let popup = center_fixed(48, 8, area);
    frame.render_widget(Clear, popup);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(Span::styled(
            " New folder ",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ))
        .title_bottom(Span::styled(
            " Enter create · Esc cancel ",
            Style::default().fg(MUTED),
        ));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    draw_form_field(frame, inner, "Name", name, true, false);
}

fn draw_confirm_delete(frame: &mut Frame, app: &App) {
    let Overlay::ConfirmDelete { name, .. } = &app.overlay else {
        return;
    };

    let area = frame.area();
    let popup = center_fixed(50, 7, area);
    frame.render_widget(Clear, popup);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ERR))
        .title(Span::styled(
            " Delete item ",
            Style::default().fg(ERR).add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let lines = vec![
        Line::from(Span::styled(
            format!("Move \"{name}\" to trash?"),
            Style::default().fg(FG),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("y", Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
            Span::styled(" yes   ", Style::default().fg(MUTED)),
            Span::styled("n", Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
            Span::styled(" / Esc cancel", Style::default().fg(MUTED)),
        ]),
    ];
    frame.render_widget(
        Paragraph::new(lines).alignment(Alignment::Center),
        inner,
    );
}

fn draw_form_field(
    frame: &mut Frame,
    area: ratatui::layout::Rect,
    label: &str,
    value: &str,
    focused: bool,
    secret: bool,
) {
    let border = if focused {
        Style::default().fg(ACCENT)
    } else {
        Style::default().fg(MUTED)
    };
    let title_style = if focused {
        Style::default().fg(FG).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(MUTED)
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border)
        .title(Span::styled(format!(" {label} "), title_style));
    let display = if secret && !value.is_empty() {
        let masked = "•".repeat(value.chars().count().min(48));
        if focused {
            format!("{masked}▌")
        } else {
            masked
        }
    } else if value.is_empty() && focused {
        "▌".to_string()
    } else if focused {
        format!("{value}▌")
    } else {
        value.to_string()
    };
    frame.render_widget(
        Paragraph::new(display)
            .style(Style::default().fg(FG))
            .block(block),
        area,
    );
}
