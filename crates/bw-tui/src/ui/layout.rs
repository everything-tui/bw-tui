//! Responsive layout helpers for the vault browser.

use ratatui::layout::{Constraint, Direction, Layout, Rect};

/// Collapse detail pane below this width.
pub const DETAIL_MIN_COLS: u16 = 80;
/// Collapse folder pane below this width.
pub const FOLDER_MIN_COLS: u16 = 60;

#[derive(Debug, Clone, Copy)]
pub struct PaneVisibility {
    pub folders: bool,
    pub detail: bool,
}

impl PaneVisibility {
    pub fn from_width(width: u16) -> Self {
        Self {
            folders: width >= FOLDER_MIN_COLS,
            detail: width >= DETAIL_MIN_COLS,
        }
    }
}

/// Split the main vault area into up to three panes.
///
/// Returns `(folders, items, detail)` where collapsed panes are `None`.
pub fn split_vault_panes(area: Rect) -> (Option<Rect>, Rect, Option<Rect>) {
    let vis = PaneVisibility::from_width(area.width);

    match (vis.folders, vis.detail) {
        (true, true) => {
            let cols = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Length(26),
                    Constraint::Min(30),
                    Constraint::Percentage(40),
                ])
                .split(area);
            (Some(cols[0]), cols[1], Some(cols[2]))
        }
        (true, false) => {
            let cols = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Length(24), Constraint::Min(20)])
                .split(area);
            (Some(cols[0]), cols[1], None)
        }
        (false, true) => {
            let cols = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Min(24), Constraint::Percentage(42)])
                .split(area);
            (None, cols[0], Some(cols[1]))
        }
        (false, false) => (None, area, None),
    }
}

/// Header row, three panes, status row.
#[derive(Debug, Clone, Copy, Default)]
pub struct VaultLayout {
    pub header: Rect,
    pub folders: Option<Rect>,
    pub items: Rect,
    pub detail: Option<Rect>,
    pub status: Rect,
}

pub fn vault_layout(area: Rect) -> VaultLayout {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(1),
        ])
        .split(area);
    let (folders, items, detail) = split_vault_panes(rows[1]);
    VaultLayout {
        header: rows[0],
        folders,
        items,
        detail,
        status: rows[2],
    }
}

/// Where things were drawn last frame, for mouse hit-testing.
#[derive(Debug, Clone, Default)]
pub struct HitMap {
    pub layout: VaultLayout,
    /// Screen row → sidebar entry index.
    pub sidebar_rows: Vec<(u16, usize)>,
    /// Screen row → item (or Send) index in the visible list.
    pub item_rows: Vec<(u16, usize)>,
}

/// Vertical split: body + status bar.
pub fn split_status(area: Rect) -> (Rect, Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(1)])
        .split(area);
    (chunks[0], chunks[1])
}

/// Center a fixed-size rect within `area`.
pub fn center_fixed(width: u16, height: u16, area: Rect) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    let x = area.x + (area.width.saturating_sub(width)) / 2;
    let y = area.y + (area.height.saturating_sub(height)) / 2;
    Rect::new(x, y, width, height)
}
