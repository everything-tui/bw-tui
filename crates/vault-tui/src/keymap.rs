//! Canonical keybinding table used by help UI (and future Action dispatcher).

#[derive(Debug, Clone, Copy)]
pub struct KeyBinding {
    pub keys: &'static str,
    pub action: &'static str,
    pub context: &'static str,
}

/// Single source of truth for documented bindings.
pub const BINDINGS: &[KeyBinding] = &[
    KeyBinding {
        keys: "Ctrl+h",
        action: "Show/hide password",
        context: "login · unlock · forms",
    },
    KeyBinding {
        keys: "Ctrl+r",
        action: "Toggle remember session",
        context: "login",
    },
    KeyBinding {
        keys: "Ctrl+p",
        action: "Profile manager",
        context: "global",
    },
    KeyBinding {
        keys: "e",
        action: "Edit profile / edit item",
        context: "profiles · vault",
    },
    KeyBinding {
        keys: "L",
        action: "Toggle lock-on-switch",
        context: "profiles",
    },
    KeyBinding {
        keys: "Ctrl+o",
        action: "Sign out current profile",
        context: "unlock",
    },
    KeyBinding {
        keys: "Tab / h l",
        action: "Cycle pane focus",
        context: "vault",
    },
    KeyBinding {
        keys: "j / k · ↑/↓",
        action: "Move selection",
        context: "vault",
    },
    KeyBinding {
        keys: "Home / End",
        action: "First / last item",
        context: "vault",
    },
    KeyBinding {
        keys: "PgUp / PgDn",
        action: "Page selection",
        context: "vault",
    },
    KeyBinding {
        keys: "Enter",
        action: "Edit item / confirm",
        context: "vault · dialogs",
    },
    KeyBinding {
        keys: "Shift+M",
        action: "Move item to folder",
        context: "vault",
    },
    KeyBinding {
        keys: "/",
        action: "Fuzzy search",
        context: "vault",
    },
    KeyBinding {
        keys: "Esc",
        action: "Clear search / close overlay",
        context: "vault · modals",
    },
    KeyBinding {
        keys: "n",
        action: "New item (login / note)",
        context: "vault",
    },
    KeyBinding {
        keys: "e / d",
        action: "Rename / delete folder",
        context: "folders pane",
    },
    KeyBinding {
        keys: "Ctrl+a",
        action: "Toggle password / API-key login",
        context: "login",
    },
    KeyBinding {
        keys: "m",
        action: "Resend email 2FA",
        context: "2FA",
    },
    KeyBinding {
        keys: "Space",
        action: "Remember this device",
        context: "2FA",
    },
    KeyBinding {
        keys: "Tab / p",
        action: "Toggle PIN unlock",
        context: "unlock",
    },
    KeyBinding {
        keys: ",",
        action: "Account settings",
        context: "vault",
    },
    KeyBinding {
        keys: "Shift+C",
        action: "Clone item",
        context: "vault",
    },
    KeyBinding {
        keys: "Ctrl+n",
        action: "New folder",
        context: "vault",
    },
    KeyBinding {
        keys: "Ctrl+1–9",
        action: "Download attachment",
        context: "detail",
    },
    KeyBinding {
        keys: "Ctrl+Shift+1–9",
        action: "Delete attachment",
        context: "detail",
    },
    KeyBinding {
        keys: "A",
        action: "Upload attachment (path)",
        context: "detail",
    },
    KeyBinding {
        keys: "e / d / L",
        action: "Edit / delete / copy link",
        context: "Sends filter",
    },
    KeyBinding {
        keys: "d",
        action: "Delete / soft-delete",
        context: "vault",
    },
    KeyBinding {
        keys: "f",
        action: "Toggle favorite",
        context: "vault",
    },
    KeyBinding {
        keys: "g",
        action: "Password generator",
        context: "vault · forms",
    },
    KeyBinding {
        keys: "c",
        action: "Copy password",
        context: "vault",
    },
    KeyBinding {
        keys: "y",
        action: "Copy username",
        context: "vault",
    },
    KeyBinding {
        keys: "t",
        action: "Copy TOTP",
        context: "vault",
    },
    KeyBinding {
        keys: "u",
        action: "Copy URI",
        context: "vault",
    },
    KeyBinding {
        keys: "r",
        action: "Reveal secrets / restore trash",
        context: "vault detail · trash",
    },
    KeyBinding {
        keys: "Enter",
        action: "Restore from trash",
        context: "trash filter",
    },
    KeyBinding {
        keys: "Ctrl+s",
        action: "Sync vault / save form",
        context: "vault · forms",
    },
    KeyBinding {
        keys: "Ctrl+l",
        action: "Lock vault",
        context: "vault",
    },
    KeyBinding {
        keys: "Ctrl+g",
        action: "Insert generated password",
        context: "forms",
    },
    KeyBinding {
        keys: "q",
        action: "Quit",
        context: "global",
    },
    KeyBinding {
        keys: "?",
        action: "Toggle help",
        context: "global",
    },
];

pub fn help_lines() -> Vec<(String, String)> {
    BINDINGS
        .iter()
        .map(|b| (b.keys.to_string(), format!("{} ({})", b.action, b.context)))
        .collect()
}
