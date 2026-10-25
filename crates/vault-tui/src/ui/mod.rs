//! Ratatui widgets and screens.

mod account;
mod account_tools;
mod form;
mod health;
mod help;
mod history;
pub(crate) mod layout;
mod login;
mod modals;
mod palette;
mod power;
mod profiles;
mod theme;
mod vault;

pub use theme::{init_theme, theme, CustomThemeColors};

use ratatui::Frame;

use crate::app::{App, Overlay, Screen};

pub use layout::PaneVisibility;

pub fn draw(frame: &mut Frame, app: &App) {
    let area = frame.area();
    app.power.view_size.set((area.width, area.height));
    match app.screen {
        Screen::Login => login::draw_login(frame, app),
        Screen::TwoFactor => login::draw_2fa(frame, app),
        Screen::AuthWait => login::draw_auth_wait(frame, app),
        Screen::Unlock => login::draw_unlock(frame, app),
        Screen::Vault => vault::draw_vault(frame, app),
    }

    if !matches!(app.overlay, Overlay::None) {
        modals::draw_overlay(frame, app);
    }

    if app.pending_goto && app.screen == Screen::Vault && matches!(app.overlay, Overlay::None) {
        help::draw_goto_hint(frame, app);
    }

    if app.show_help {
        help::draw_help(frame, app);
    }

    power::draw_toasts(frame, app);
}
