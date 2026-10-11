//! Ratatui widgets and screens.

mod help;
mod layout;
mod login;
mod modals;
mod profiles;
mod vault;

use ratatui::Frame;

use crate::app::{App, Overlay, Screen};

pub use layout::PaneVisibility;

pub fn draw(frame: &mut Frame, app: &App) {
    match app.screen {
        Screen::Login => login::draw_login(frame, app),
        Screen::TwoFactor => login::draw_2fa(frame, app),
        Screen::Unlock => login::draw_unlock(frame, app),
        Screen::Vault => vault::draw_vault(frame, app),
    }

    if !matches!(app.overlay, Overlay::None) {
        modals::draw_overlay(frame, app);
    }

    if app.show_help {
        help::draw_help(frame);
    }
}
