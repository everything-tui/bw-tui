//! Canonical keybinding table used by help UI (and future Action dispatcher).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelpSection {
    Global,
    Login,
    TwoFactor,
    Unlock,
    Profiles,
    Vault,
    Folders,
    Detail,
    Forms,
    Sends,
    Trash,
    SshKeyForm,
}

impl HelpSection {
    pub const ALL: &[HelpSection] = &[
        Self::Global,
        Self::Login,
        Self::TwoFactor,
        Self::Unlock,
        Self::Profiles,
        Self::Vault,
        Self::Folders,
        Self::Detail,
        Self::Forms,
        Self::Sends,
        Self::Trash,
        Self::SshKeyForm,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Self::Global => "Global",
            Self::Login => "Login",
            Self::TwoFactor => "2FA",
            Self::Unlock => "Unlock",
            Self::Profiles => "Profiles",
            Self::Vault => "Vault",
            Self::Folders => "Folders",
            Self::Detail => "Detail",
            Self::Forms => "Forms",
            Self::Sends => "Sends",
            Self::Trash => "Trash",
            Self::SshKeyForm => "SSH key form",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct KeyBinding {
    pub keys: &'static str,
    pub action: &'static str,
    pub section: HelpSection,
}

/// Single source of truth for documented bindings, ordered by [`HelpSection`].
pub const BINDINGS: &[KeyBinding] = &[
    // --- Global ---
    KeyBinding {
        keys: "Ctrl+p",
        action: "Profile manager",
        section: HelpSection::Global,
    },
    KeyBinding {
        keys: "q",
        action: "Quit",
        section: HelpSection::Global,
    },
    KeyBinding {
        keys: "?",
        action: "Toggle help",
        section: HelpSection::Global,
    },
    // --- Login ---
    KeyBinding {
        keys: "Ctrl+h",
        action: "Show/hide password",
        section: HelpSection::Login,
    },
    KeyBinding {
        keys: "Ctrl+r",
        action: "Toggle remember session",
        section: HelpSection::Login,
    },
    KeyBinding {
        keys: "Ctrl+a",
        action: "Toggle password / API-key login",
        section: HelpSection::Login,
    },
    // --- 2FA ---
    KeyBinding {
        keys: "m",
        action: "Resend email 2FA",
        section: HelpSection::TwoFactor,
    },
    KeyBinding {
        keys: "Tab / Shift+Tab / j k / ← →",
        action: "Change 2FA provider",
        section: HelpSection::TwoFactor,
    },
    KeyBinding {
        keys: "Ctrl+o",
        action: "Open Duo URL",
        section: HelpSection::TwoFactor,
    },
    KeyBinding {
        keys: "Space",
        action: "Remember this device",
        section: HelpSection::TwoFactor,
    },
    // --- Unlock ---
    KeyBinding {
        keys: "Ctrl+h",
        action: "Show/hide password",
        section: HelpSection::Unlock,
    },
    KeyBinding {
        keys: "Ctrl+o",
        action: "Sign out current profile",
        section: HelpSection::Unlock,
    },
    KeyBinding {
        keys: "Tab / p",
        action: "Toggle PIN unlock",
        section: HelpSection::Unlock,
    },
    // --- Profiles ---
    KeyBinding {
        keys: "e",
        action: "Edit profile",
        section: HelpSection::Profiles,
    },
    KeyBinding {
        keys: "L",
        action: "Toggle lock-on-switch",
        section: HelpSection::Profiles,
    },
    // --- Vault ---
    KeyBinding {
        keys: "Tab / h l",
        action: "Cycle pane focus",
        section: HelpSection::Vault,
    },
    KeyBinding {
        keys: "j / k · ↑/↓",
        action: "Move selection",
        section: HelpSection::Vault,
    },
    KeyBinding {
        keys: "Home / End",
        action: "First / last item",
        section: HelpSection::Vault,
    },
    KeyBinding {
        keys: "PgUp / PgDn",
        action: "Page selection",
        section: HelpSection::Vault,
    },
    KeyBinding {
        keys: "Enter",
        action: "Edit item / confirm dialog",
        section: HelpSection::Vault,
    },
    KeyBinding {
        keys: "e",
        action: "Edit item",
        section: HelpSection::Vault,
    },
    KeyBinding {
        keys: "Shift+M",
        action: "Move item to folder",
        section: HelpSection::Vault,
    },
    KeyBinding {
        keys: "Shift+O",
        action: "Share to organization",
        section: HelpSection::Vault,
    },
    KeyBinding {
        keys: "Space",
        action: "Mark item for bulk share/delete",
        section: HelpSection::Vault,
    },
    KeyBinding {
        keys: "/",
        action: "Fuzzy search",
        section: HelpSection::Vault,
    },
    KeyBinding {
        keys: "Esc",
        action: "Clear search / close overlay",
        section: HelpSection::Vault,
    },
    KeyBinding {
        keys: "n",
        action: "New item (login / note)",
        section: HelpSection::Vault,
    },
    KeyBinding {
        keys: ",",
        action: "Account settings",
        section: HelpSection::Vault,
    },
    KeyBinding {
        keys: "Shift+C",
        action: "Clone item",
        section: HelpSection::Vault,
    },
    KeyBinding {
        keys: "Ctrl+n",
        action: "New folder",
        section: HelpSection::Vault,
    },
    KeyBinding {
        keys: "d",
        action: "Delete / soft-delete",
        section: HelpSection::Vault,
    },
    KeyBinding {
        keys: "f",
        action: "Toggle favorite",
        section: HelpSection::Vault,
    },
    KeyBinding {
        keys: "g",
        action: "Password generator",
        section: HelpSection::Vault,
    },
    KeyBinding {
        keys: "c",
        action: "Copy password",
        section: HelpSection::Vault,
    },
    KeyBinding {
        keys: "y",
        action: "Copy username",
        section: HelpSection::Vault,
    },
    KeyBinding {
        keys: "t",
        action: "Copy TOTP",
        section: HelpSection::Vault,
    },
    KeyBinding {
        keys: "u",
        action: "Copy URI",
        section: HelpSection::Vault,
    },
    KeyBinding {
        keys: "r",
        action: "Reveal secrets",
        section: HelpSection::Vault,
    },
    KeyBinding {
        keys: "Ctrl+s",
        action: "Sync vault",
        section: HelpSection::Vault,
    },
    KeyBinding {
        keys: "Ctrl+l",
        action: "Lock vault",
        section: HelpSection::Vault,
    },
    KeyBinding {
        keys: "a / T",
        action: "Auto-type login / TOTP (focus target first)",
        section: HelpSection::Vault,
    },
    KeyBinding {
        keys: "S",
        action: "Copy sequence: username → password → TOTP",
        section: HelpSection::Vault,
    },
    KeyBinding {
        keys: "Q",
        action: "Show password / TOTP as QR code",
        section: HelpSection::Vault,
    },
    KeyBinding {
        keys: "E · Ctrl+e",
        action: "Edit notes in $EDITOR",
        section: HelpSection::Vault,
    },
    KeyBinding {
        keys: "s",
        action: "Cycle sort: name / recently used / modified",
        section: HelpSection::Vault,
    },
    KeyBinding {
        keys: "V",
        action: "Attachments: open · preview · save",
        section: HelpSection::Vault,
    },
    KeyBinding {
        keys: "D",
        action: "Domain rules editor",
        section: HelpSection::Vault,
    },
    KeyBinding {
        keys: "click · wheel",
        action: "Select / scroll (config mouse = true)",
        section: HelpSection::Vault,
    },
    // --- Folders ---
    KeyBinding {
        keys: "e / d",
        action: "Rename / delete folder",
        section: HelpSection::Folders,
    },
    // --- Detail ---
    KeyBinding {
        keys: "Ctrl+1–9",
        action: "Download attachment",
        section: HelpSection::Detail,
    },
    KeyBinding {
        keys: "Ctrl+Shift+1–9",
        action: "Delete attachment",
        section: HelpSection::Detail,
    },
    KeyBinding {
        keys: "A",
        action: "Upload attachment (path)",
        section: HelpSection::Detail,
    },
    // --- Forms ---
    KeyBinding {
        keys: "Ctrl+h",
        action: "Show/hide password",
        section: HelpSection::Forms,
    },
    KeyBinding {
        keys: "g",
        action: "Password generator",
        section: HelpSection::Forms,
    },
    KeyBinding {
        keys: "Ctrl+s",
        action: "Save form",
        section: HelpSection::Forms,
    },
    KeyBinding {
        keys: "Ctrl+g",
        action: "Insert generated password",
        section: HelpSection::Forms,
    },
    KeyBinding {
        keys: "E · Ctrl+e",
        action: "Edit notes in $EDITOR",
        section: HelpSection::Forms,
    },
    // --- Sends ---
    KeyBinding {
        keys: "s",
        action: "New Send (quick) — sidebar focused",
        section: HelpSection::Sends,
    },
    KeyBinding {
        keys: "n",
        action: "New Send (quick: text/file + password; Advanced… for options)",
        section: HelpSection::Sends,
    },
    KeyBinding {
        keys: "e / d / L",
        action: "Edit / delete / copy link",
        section: HelpSection::Sends,
    },
    KeyBinding {
        keys: "a / Advanced…",
        action: "Expand quick Send form to full options",
        section: HelpSection::Sends,
    },
    // --- Trash ---
    KeyBinding {
        keys: "r",
        action: "Restore from trash",
        section: HelpSection::Trash,
    },
    KeyBinding {
        keys: "Enter",
        action: "Restore from trash",
        section: HelpSection::Trash,
    },
    // --- SSH key form ---
    KeyBinding {
        keys: "Ctrl+g",
        action: "Generate Ed25519 key",
        section: HelpSection::SshKeyForm,
    },
];

pub fn help_lines() -> Vec<(String, String)> {
    BINDINGS
        .iter()
        .map(|b| {
            (
                b.keys.to_string(),
                format!("{} ({})", b.action, b.section.title()),
            )
        })
        .collect()
}
