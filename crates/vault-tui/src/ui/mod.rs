//! Ratatui widgets and screens.

mod account;
mod form;
mod health;
mod help;
mod history;
mod layout;
mod login;
mod modals;
mod palette;
mod profiles;
mod theme;
mod vault;

pub use theme::theme;

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
