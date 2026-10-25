//! Fixed bindings for screens and overlays outside the vault browser.
//! Vault-browser keys live in [`crate::keybinds::KeyMap`] (configurable) and the
//! help overlay renders them from there.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelpSection {
    Search,
    Forms,
    Dialogs,
    Login,
    TwoFactor,
    Unlock,
    Profiles,
}

impl HelpSection {
    pub const ALL: &[HelpSection] = &[
        Self::Search,
        Self::Forms,
        Self::Dialogs,
        Self::Login,
        Self::TwoFactor,
        Self::Unlock,
        Self::Profiles,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Self::Search => "While searching",
            Self::Forms => "Item forms",
            Self::Dialogs => "Dialogs & lists",
            Self::Login => "Login screen",
            Self::TwoFactor => "Two-factor screen",
            Self::Unlock => "Unlock screen",
            Self::Profiles => "Profile manager",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct KeyBinding {
    pub keys: &'static str,
    pub action: &'static str,
    pub section: HelpSection,
}

const fn kb(keys: &'static str, action: &'static str, section: HelpSection) -> KeyBinding {
    KeyBinding {
        keys,
        action,
        section,
    }
}

use HelpSection::*;

/// Ordered by [`HelpSection`].
pub const BINDINGS: &[KeyBinding] = &[
    kb(
        "type",
        "Filter (type:login folder:work url:github.com …)",
        Search,
    ),
    kb("↑ ↓ · Ctrl+n / Ctrl+p", "Move through results", Search),
    kb("Ctrl+u", "Clear query", Search),
    kb("Enter", "Keep filter, back to the list", Search),
    kb("Esc", "Clear filter", Search),
    kb("Tab / Shift+Tab · ↑ ↓", "Next / previous field", Forms),
    kb("Ctrl+s", "Save", Forms),
    kb("Esc", "Cancel", Forms),
    kb("Ctrl+g", "Generate password into the form", Forms),
    kb("Ctrl+e", "Edit notes in $EDITOR", Forms),
    kb("Ctrl+n / Ctrl+d", "Add / remove URI (URI field)", Forms),
    kb("Ctrl+f / Ctrl+b", "Next / previous URI (URI field)", Forms),
    kb("Ctrl+t", "Cycle URI match type (URI field)", Forms),
    kb("Space", "Toggle checkbox", Forms),
    kb("Ctrl+g", "Generate Ed25519 key (SSH key form)", Forms),
    kb("j k · ↑ ↓", "Move", Dialogs),
    kb("Enter / y", "Confirm", Dialogs),
    kb("Esc / n", "Cancel / close", Dialogs),
    kb("Tab / ↓", "Next field", Login),
    kb("Enter", "Sign in", Login),
    kb("Ctrl+h", "Show / hide password", Login),
    kb("Ctrl+r", "Toggle remember session", Login),
    kb("Ctrl+a", "Password ↔ API-key login", Login),
    kb("Ctrl+p", "Profile manager", Login),
    kb("F1", "Help", Login),
    kb("Esc", "Quit", Login),
    kb("Tab / j k / ← →", "Change 2FA provider", TwoFactor),
    kb("m", "Resend email code", TwoFactor),
    kb("Space", "Remember this device", TwoFactor),
    kb("Ctrl+o", "Open Duo URL", TwoFactor),
    kb("Esc", "Back to login", TwoFactor),
    kb("Enter", "Unlock", Unlock),
    kb("Tab", "Master password ↔ PIN", Unlock),
    kb("Ctrl+h", "Show / hide password", Unlock),
    kb("Ctrl+o", "Sign out of this profile", Unlock),
    kb("Ctrl+p", "Profile manager", Unlock),
    kb("F1", "Help", Unlock),
    kb("Esc", "Quit", Unlock),
    kb("Enter", "Switch to profile", Profiles),
    kb("n / e / d", "New / edit / delete profile", Profiles),
    kb("L", "Toggle lock-on-switch", Profiles),
];
