//! Shared form field widgets (thin wrappers over [`super::chrome::input`]).

use ratatui::layout::Rect;
use ratatui::Frame;

use super::chrome;

pub fn draw_form_field(
    frame: &mut Frame,
    area: Rect,
    label: &str,
    value: &str,
    focused: bool,
    secret: bool,
) {
    chrome::input(frame, area, label, value, focused, secret, "", false);
}

/// Like [`draw_form_field`], with a key hint right-aligned on the label row
/// (e.g. `Ctrl+g generate` on a password field).
pub fn draw_form_field_with_hint(
    frame: &mut Frame,
    area: Rect,
    label: &str,
    value: &str,
    focused: bool,
    secret: bool,
    hint: &str,
) {
    chrome::input(frame, area, label, value, focused, secret, hint, false);
}
