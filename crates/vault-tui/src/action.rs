//! Vault-screen commands. Key presses, the command palette and the help overlay
//! all go through this one table, so a binding change shows up everywhere.

use crate::models::FilterKind;

/// Where an action's key is live. Lets one key mean different things in
/// disjoint contexts (`r` reveals secrets, but restores inside Trash).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Anywhere on the vault screen.
    Global,
    /// Viewing ciphers (any filter except Sends).
    Ciphers,
    /// Viewing the Trash filter (takes precedence over `Ciphers`).
    Trash,
    /// Viewing the Sends filter.
    Sends,
}

impl Scope {
    /// Lower = checked first when several actions share a key.
    pub fn priority(self) -> u8 {
        match self {
            Self::Trash | Self::Sends => 0,
            Self::Ciphers => 1,
            Self::Global => 2,
        }
    }

    /// Would two actions in these scopes sharing a key be a conflict?
    /// `Trash` deliberately overrides `Ciphers`; `Sends` and `Ciphers` never co-occur.
    pub fn overlaps(self, other: Scope) -> bool {
        matches!((self, other), (Scope::Global, _) | (_, Scope::Global)) || self == other
    }
}

/// Grouping used by the help overlay and the command palette.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Group {
    Navigate,
    GoTo,
    Copy,
    Item,
    Sends,
    App,
}

impl Group {
    pub const ALL: &[Group] = &[
        Self::Navigate,
        Self::GoTo,
        Self::Copy,
        Self::Item,
        Self::Sends,
        Self::App,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Self::Navigate => "Navigate",
            Self::GoTo => "Go to (prefix key, then…)",
            Self::Copy => "Copy",
            Self::Item => "Item",
            Self::Sends => "Sends",
            Self::App => "App",
        }
    }
}

/// Second key of a `g` sequence and the sidebar filter it jumps to.
pub const GOTO_TARGETS: &[(char, Action)] = &[
    ('g', Action::Top),
    ('a', Action::GotoAll),
    ('f', Action::GotoFavorites),
    ('l', Action::GotoLogins),
    ('n', Action::GotoNotes),
    ('c', Action::GotoCards),
    ('i', Action::GotoIdentities),
    ('k', Action::GotoSshKeys),
    ('s', Action::GotoSends),
    ('t', Action::GotoTrash),
];

/// Application-level command dispatched by `events::dispatch`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    // Navigate
    MoveUp,
    MoveDown,
    PageUp,
    PageDown,
    Top,
    Bottom,
    FocusLeft,
    FocusRight,
    FocusNext,
    FocusPrev,
    Open,
    Back,
    SearchStart,
    GotoPrefix,
    // Go to
    GotoAll,
    GotoFavorites,
    GotoLogins,
    GotoNotes,
    GotoCards,
    GotoIdentities,
    GotoSshKeys,
    GotoSends,
    GotoTrash,
    // Copy
    CopyPassword,
    CopyUsername,
    CopyTotp,
    CopyUri,
    CopyNotes,
    CopyCardNumber,
    CopyCardCode,
    CopyCardExpiry,
    CopySshPublic,
    CopySshPrivate,
    CopySequence,
    // Item
    New,
    Edit,
    Delete,
    ToggleFavorite,
    ToggleReveal,
    ToggleMark,
    CloneItem,
    MoveToFolder,
    ShareToOrg,
    UndoDelete,
    EditNotesExternal,
    EditCustomFields,
    Attachments,
    UploadAttachment,
    PasswordHistory,
    ShowQr,
    AutoType,
    AutoTypeTotp,
    CycleSort,
    Restore,
    EmptyTrash,
    // Sends
    NewSend,
    CopySendLink,
    ReceiveSend,
    // App
    OpenGenerator,
    OpenHealthReport,
    DomainRules,
    AccountSettings,
    NewFolder,
    Sync,
    Lock,
    OpenProfileManager,
    SignOutProfile,
    OpenCommandPalette,
    ToggleHelp,
    Quit,
}

impl Action {
    /// Every action, in help / palette display order.
    pub fn all() -> &'static [Action] {
        use Action::*;
        &[
            MoveDown,
            MoveUp,
            PageDown,
            PageUp,
            Top,
            Bottom,
            FocusLeft,
            FocusRight,
            FocusNext,
            FocusPrev,
            Open,
            Back,
            SearchStart,
            GotoPrefix,
            GotoAll,
            GotoFavorites,
            GotoLogins,
            GotoNotes,
            GotoCards,
            GotoIdentities,
            GotoSshKeys,
            GotoSends,
            GotoTrash,
            CopyPassword,
            CopyUsername,
            CopyTotp,
            CopyUri,
            CopyNotes,
            CopyCardNumber,
            CopyCardCode,
            CopyCardExpiry,
            CopySshPublic,
            CopySshPrivate,
            CopySequence,
            New,
            Edit,
            Delete,
            ToggleFavorite,
            ToggleReveal,
            ToggleMark,
            CloneItem,
            MoveToFolder,
            ShareToOrg,
            UndoDelete,
            EditNotesExternal,
            EditCustomFields,
            Attachments,
            UploadAttachment,
            PasswordHistory,
            ShowQr,
            AutoType,
            AutoTypeTotp,
            CycleSort,
            Restore,
            EmptyTrash,
            NewSend,
            CopySendLink,
            ReceiveSend,
            OpenGenerator,
            OpenHealthReport,
            DomainRules,
            AccountSettings,
            NewFolder,
            Sync,
            Lock,
            OpenProfileManager,
            SignOutProfile,
            OpenCommandPalette,
            ToggleHelp,
            Quit,
        ]
    }

    pub fn label(self) -> &'static str {
        use Action::*;
        match self {
            MoveUp => "Move up / scroll up",
            MoveDown => "Move down / scroll down",
            PageUp => "Page up",
            PageDown => "Page down",
            Top => "First item",
            Bottom => "Last item",
            FocusLeft => "Focus pane to the left",
            FocusRight => "Focus pane to the right",
            FocusNext => "Next pane",
            FocusPrev => "Previous pane",
            Open => "Open: folder → items → detail → edit",
            Back => "Back: leave pane · clear search · clear marks",
            SearchStart => "Search",
            GotoPrefix => "Go to… (shows targets)",
            GotoAll => "Go to All items",
            GotoFavorites => "Go to Favorites",
            GotoLogins => "Go to Logins",
            GotoNotes => "Go to Secure notes",
            GotoCards => "Go to Cards",
            GotoIdentities => "Go to Identities",
            GotoSshKeys => "Go to SSH keys",
            GotoSends => "Go to Sends",
            GotoTrash => "Go to Trash",
            CopyPassword => "Copy password",
            CopyUsername => "Copy username",
            CopyTotp => "Copy TOTP code",
            CopyUri => "Copy URI",
            CopyNotes => "Copy notes",
            CopyCardNumber => "Copy card number",
            CopyCardCode => "Copy card CVC",
            CopyCardExpiry => "Copy card expiry",
            CopySshPublic => "Copy SSH public key",
            CopySshPrivate => "Copy SSH private key",
            CopySequence => "Copy sequence: username → password → TOTP",
            New => "New item (folder in Folders pane)",
            Edit => "Edit item (rename in Folders pane)",
            Delete => "Delete item (folder in Folders pane)",
            ToggleFavorite => "Toggle favorite",
            ToggleReveal => "Reveal secrets (15s)",
            ToggleMark => "Mark item for bulk delete / share",
            CloneItem => "Clone item",
            MoveToFolder => "Move to folder",
            ShareToOrg => "Share to organization",
            UndoDelete => "Undo last delete",
            EditNotesExternal => "Edit notes in $EDITOR",
            EditCustomFields => "Edit custom fields",
            Attachments => "Attachments: open · preview · save · delete",
            UploadAttachment => "Upload attachment",
            PasswordHistory => "Password history",
            ShowQr => "Show password / TOTP as QR code",
            AutoType => "Auto-type login into focused window",
            AutoTypeTotp => "Auto-type TOTP into focused window",
            CycleSort => "Cycle sort: name / recent / modified",
            Restore => "Restore from trash",
            EmptyTrash => "Empty trash",
            NewSend => "New Send",
            CopySendLink => "Copy Send link",
            ReceiveSend => "Open a Send link",
            OpenGenerator => "Password generator",
            OpenHealthReport => "Vault health report",
            DomainRules => "Domain rules",
            AccountSettings => "Account settings",
            NewFolder => "New folder",
            Sync => "Sync vault",
            Lock => "Lock vault",
            OpenProfileManager => "Profile manager",
            SignOutProfile => "Sign out of profile",
            OpenCommandPalette => "Command palette",
            ToggleHelp => "Help",
            Quit => "Quit",
        }
    }

    pub fn group(self) -> Group {
        use Action::*;
        match self {
            MoveUp | MoveDown | PageUp | PageDown | Top | Bottom | FocusLeft | FocusRight
            | FocusNext | FocusPrev | Open | Back | SearchStart | GotoPrefix => Group::Navigate,
            GotoAll | GotoFavorites | GotoLogins | GotoNotes | GotoCards | GotoIdentities
            | GotoSshKeys | GotoSends | GotoTrash => Group::GoTo,
            CopyPassword | CopyUsername | CopyTotp | CopyUri | CopyNotes | CopyCardNumber
            | CopyCardCode | CopyCardExpiry | CopySshPublic | CopySshPrivate | CopySequence => {
                Group::Copy
            }
            New | Edit | Delete | ToggleFavorite | ToggleReveal | ToggleMark | CloneItem
            | MoveToFolder | ShareToOrg | UndoDelete | EditNotesExternal | EditCustomFields
            | Attachments | UploadAttachment | PasswordHistory | ShowQr | AutoType
            | AutoTypeTotp | CycleSort | Restore | EmptyTrash => Group::Item,
            NewSend | CopySendLink | ReceiveSend => Group::Sends,
            OpenGenerator | OpenHealthReport | DomainRules | AccountSettings | NewFolder | Sync
            | Lock | OpenProfileManager | SignOutProfile | OpenCommandPalette | ToggleHelp
            | Quit => Group::App,
        }
    }

    pub fn scope(self) -> Scope {
        use Action::*;
        match self.group() {
            Group::Copy => Scope::Ciphers,
            Group::Item => match self {
                New | Edit | Delete | UndoDelete => Scope::Global,
                Restore | EmptyTrash => Scope::Trash,
                _ => Scope::Ciphers,
            },
            Group::Sends => match self {
                NewSend => Scope::Global,
                _ => Scope::Sends,
            },
            _ => Scope::Global,
        }
    }

    /// Pure navigation primitives are pointless from the palette.
    pub fn in_palette(self) -> bool {
        !matches!(self.group(), Group::Navigate) || matches!(self, Action::SearchStart)
    }

    /// The sidebar filter a `Goto*` action selects.
    pub fn goto_filter(self) -> Option<FilterKind> {
        use Action::*;
        Some(match self {
            GotoAll => FilterKind::All,
            GotoFavorites => FilterKind::Favorites,
            GotoLogins => FilterKind::Login,
            GotoNotes => FilterKind::SecureNote,
            GotoCards => FilterKind::Card,
            GotoIdentities => FilterKind::Identity,
            GotoSshKeys => FilterKind::SshKey,
            GotoSends => FilterKind::Sends,
            GotoTrash => FilterKind::Trash,
            _ => return None,
        })
    }

    /// `g` sequence that triggers this action, if any.
    pub fn goto_key(self) -> Option<char> {
        GOTO_TARGETS
            .iter()
            .find(|(_, a)| *a == self)
            .map(|(c, _)| *c)
    }
}
