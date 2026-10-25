//! Application state machine for the Vaultwarden TUI.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use chrono::{DateTime, Local};
use fuzzy_matcher::skim::SkimMatcherV2;
use fuzzy_matcher::FuzzyMatcher;
use vault_session::{
    app_data_dir, apply_generator_policy, find_reused_passwords, generate_passphrase_opts,
    generate_password_checked, generate_username_catchall, generate_username_plus_address,
    generate_username_word, hibp_password_pwned_count, normalize_server_url,
    plaintext_token_allowed, profile_dir, CardDraft, DecryptedUri, GeneratorOptions, IdentityDraft,
    ItemType as SessionItemType, LoginDraft, LoginResult, NoteDraft, OrgCollectionGroup,
    PassphraseOptions, Session, SessionError, SessionStatus, SshKeyDraft, TimeoutAction,
    TotpDisplay, VaultHealthReport,
};
use zeroize::Zeroize;

use crate::config::{load_config_from, AppConfig};
use crate::folder_tree::nested_folder_entries;
use crate::keybinds::KeyMap;
use crate::mock::{sample_folders, sample_items, with_folder_counts};
use crate::models::{DecryptedItem, FilterKind, FolderView, ItemType, SidebarEntry};
use crate::profiles::{
    allocate_profile_id, create_profile, delete_profile, load_registry_from, parse_auto_lock_input,
    parse_clipboard_clear_input, profile_has_auth, set_active, set_lock_on_profile_switch,
    update_profile, update_profile_credentials, ProfilesFile, VaultProfile,
};
use crate::search::parse_search_query;
use crate::system_lock::{SystemLockEvent, SystemLockMonitor};
use crate::ui::init_theme;

mod account_tools;
mod auth_ext;
pub use account_tools::{
    account_tools_handle_key, tool_fields, AccountToolsState, ToolScreen, TOOL_MENU,
};
pub use auth_ext::{
    auth_ext_handle_2fa_key, auth_ext_handle_login_key, auth_ext_handle_wait_key, AuthExtState,
    WaitKind, WaitState,
};

/// High-level screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Login,
    TwoFactor,
    /// Waiting for another device to approve, or for the SSO browser callback.
    AuthWait,
    Unlock,
    Vault,
}

/// Which pane has keyboard focus in the vault browser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FocusPane {
    Folders,
    Items,
    Detail,
}

/// Password vs API-key authentication on the login screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginAuthMode {
    Password,
    ApiKey,
}

/// Active field on the login form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginField {
    Server,
    Email,
    Password,
    ApiKeyClientId,
    ApiKeyClientSecret,
    /// Checkbox: persist server URL + email (never the master password).
    Remember,
}

impl LoginField {
    pub fn next(self, mode: LoginAuthMode) -> Self {
        match mode {
            LoginAuthMode::Password => match self {
                Self::Server => Self::Email,
                Self::Email => Self::Password,
                Self::Password => Self::Remember,
                Self::Remember => Self::Server,
                Self::ApiKeyClientId | Self::ApiKeyClientSecret => Self::Email,
            },
            LoginAuthMode::ApiKey => match self {
                Self::Server => Self::Email,
                Self::Email => Self::ApiKeyClientId,
                Self::ApiKeyClientId => Self::ApiKeyClientSecret,
                Self::ApiKeyClientSecret => Self::Password,
                Self::Password => Self::Remember,
                Self::Remember => Self::Server,
            },
        }
    }

    pub fn prev(self, mode: LoginAuthMode) -> Self {
        match mode {
            LoginAuthMode::Password => match self {
                Self::Server => Self::Remember,
                Self::Email => Self::Server,
                Self::Password => Self::Email,
                Self::Remember => Self::Password,
                Self::ApiKeyClientId | Self::ApiKeyClientSecret => Self::Email,
            },
            LoginAuthMode::ApiKey => match self {
                Self::Server => Self::Remember,
                Self::Email => Self::Server,
                Self::ApiKeyClientId => Self::Email,
                Self::ApiKeyClientSecret => Self::ApiKeyClientId,
                Self::Password => Self::ApiKeyClientSecret,
                Self::Remember => Self::Password,
            },
        }
    }
}

/// Fields in the create/edit login modal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditField {
    Name,
    Username,
    Password,
    Totp,
    Uri,
    Notes,
    Reprompt,
}

impl EditField {
    pub fn next(self) -> Self {
        match self {
            Self::Name => Self::Username,
            Self::Username => Self::Password,
            Self::Password => Self::Totp,
            Self::Totp => Self::Uri,
            Self::Uri => Self::Notes,
            Self::Notes => Self::Reprompt,
            Self::Reprompt => Self::Name,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            Self::Name => Self::Reprompt,
            Self::Username => Self::Name,
            Self::Password => Self::Username,
            Self::Totp => Self::Password,
            Self::Uri => Self::Totp,
            Self::Notes => Self::Uri,
            Self::Reprompt => Self::Notes,
        }
    }
}

/// One login URI row in the item form (plaintext + match type 0–5).
#[derive(Debug, Clone)]
pub struct FormUriLine {
    pub uri: String,
    pub match_type: i32,
}

pub fn uri_match_label(t: i32) -> &'static str {
    match t {
        0 => "domain",
        1 => "host",
        2 => "startsWith",
        3 => "exact",
        4 => "regex",
        5 => "never",
        _ => "domain",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoteField {
    Name,
    Notes,
}

impl NoteField {
    pub fn next(self) -> Self {
        match self {
            Self::Name => Self::Notes,
            Self::Notes => Self::Name,
        }
    }

    pub fn prev(self) -> Self {
        self.next()
    }
}

/// Which secret was last copied (for status + auto-clear).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardKind {
    Password,
    Username,
    Totp,
    Uri,
    CardNumber,
    CardCode,
    CardExpiry,
    SshPublic,
    SshPrivate,
    Notes,
}

/// Deferred action after master-password re-prompt succeeds.
#[derive(Debug, Clone)]
pub enum PendingRepromptAction {
    Reveal,
    Copy(ClipboardKind),
    Edit,
}

/// Focused field in the profile edit dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileEditField {
    Name,
    Server,
    Email,
    AutoLock,
    ClipboardClear,
    /// Toggle: lock vs log out when the vault timeout fires.
    TimeoutAction,
    /// Toggle: apply the timeout action at TUI startup.
    TimeoutOnStartup,
    /// Toggle: apply the timeout action on system sleep / screen lock.
    LockOnSystemLock,
}

impl ProfileEditField {
    pub fn next(self) -> Self {
        match self {
            Self::Name => Self::Server,
            Self::Server => Self::Email,
            Self::Email => Self::AutoLock,
            Self::AutoLock => Self::ClipboardClear,
            Self::ClipboardClear => Self::TimeoutAction,
            Self::TimeoutAction => Self::TimeoutOnStartup,
            Self::TimeoutOnStartup => Self::LockOnSystemLock,
            Self::LockOnSystemLock => Self::Name,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            Self::Name => Self::LockOnSystemLock,
            Self::Server => Self::Name,
            Self::Email => Self::Server,
            Self::AutoLock => Self::Email,
            Self::ClipboardClear => Self::AutoLock,
            Self::TimeoutAction => Self::ClipboardClear,
            Self::TimeoutOnStartup => Self::TimeoutAction,
            Self::LockOnSystemLock => Self::TimeoutOnStartup,
        }
    }

    /// True for on/off or choice rows (toggled with Space / ←/→ rather than typed).
    pub fn is_toggle(self) -> bool {
        matches!(
            self,
            Self::TimeoutAction | Self::TimeoutOnStartup | Self::LockOnSystemLock
        )
    }
}

#[derive(Debug, Clone)]
pub enum DeleteTarget {
    Item {
        id: String,
        name: String,
        /// When true, confirm permanently deletes (item already in trash).
        permanent: bool,
    },
    Folder {
        id: String,
        name: String,
    },
    Send {
        id: String,
        name: String,
    },
    Attachment {
        cipher_id: String,
        attachment_id: String,
        name: String,
    },
    /// Purge all items currently in trash.
    EmptyTrash {
        count: usize,
    },
    /// Soft-delete many marked vault items.
    BulkItems {
        ids: Vec<String>,
        count: usize,
    },
}

/// Step in the share-to-organization wizard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareToOrgStep {
    PickOrganization,
    PickCollections,
}

/// Soft-delete undo window (press `u` to restore).
#[derive(Debug, Clone)]
pub struct PendingUndoDelete {
    pub item_id: String,
    pub item_name: String,
    pub expires_at: Instant,
}

/// Sub-mode of the profile manager overlay.
#[derive(Debug, Clone)]
pub enum ProfileManagerMode {
    List,
    Create {
        name: String,
        error: Option<String>,
    },
    Edit {
        id: String,
        name: String,
        server_url: String,
        email: String,
        /// Same parse rules as today: off/0/empty → None; 1..=1440 → Some
        auto_lock_input: String,
        clipboard_clear_input: String,
        timeout_action: TimeoutAction,
        timeout_on_startup: bool,
        lock_on_system_lock: bool,
        field: ProfileEditField,
        error: Option<String>,
    },
    ConfirmDelete {
        id: String,
        name: String,
    },
}

/// Parked mock vault snapshot for a background profile.
#[derive(Debug, Clone)]
struct MockParked {
    folders: Vec<FolderView>,
    items: Vec<DecryptedItem>,
    last_activity: Instant,
    auto_lock_minutes: Option<u64>,
}

/// Modal overlays on top of the vault (or login) screen.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum Overlay {
    None,
    /// P4 power-user overlays (QR, attachments, domain rules, SSH agent confirmation).
    Power(crate::app::PowerOverlay),
    ItemForm {
        editing_id: Option<String>,
        name: String,
        username: String,
        password: String,
        totp: String,
        uris: Vec<FormUriLine>,
        uri_line: usize,
        notes: String,
        reprompt: bool,
        field: EditField,
    },
    NoteForm {
        editing_id: Option<String>,
        name: String,
        notes: String,
        field: NoteField,
    },
    NewItemType {
        selected: usize,
    },
    Generator {
        mode: GeneratorMode,
        username_kind: UsernameKind,
        length: usize,
        uppercase: bool,
        lowercase: bool,
        digits: bool,
        symbols: bool,
        avoid_ambiguous: bool,
        min_numbers: usize,
        min_special: usize,
        passphrase_words: usize,
        passphrase_separator: String,
        passphrase_capitalize: bool,
        passphrase_include_number: bool,
        preview: String,
        /// When true, Enter inserts into an open ItemForm password field.
        insert_to_form: bool,
    },
    FolderForm {
        folder_id: Option<String>,
        name: String,
    },
    ConfirmDelete {
        target: DeleteTarget,
    },
    Reprompt {
        item_id: String,
        password: String,
        error: Option<String>,
        then: PendingRepromptAction,
    },
    ProfileManager {
        selected: usize,
        mode: ProfileManagerMode,
    },
    CommandPalette {
        query: String,
        selected: usize,
    },
    PasswordHistory,
    HealthReport {
        scroll: usize,
        hibp_opt_in: bool,
        hibp_busy: bool,
        hibp_results: Vec<HibpResultLine>,
        /// Opt-in HIBP breached-account (email) lookups; needs `BW_TUI_HIBP_API_KEY`.
        hibp_email_opt_in: bool,
        hibp_email_results: Vec<HibpResultLine>,
        /// Computed once when the overlay opens (zxcvbn is too slow to run per frame).
        report: Box<VaultHealthReport>,
    },
    AccountSettings {
        section: usize,
        status: String,
    },
    SendForm {
        form: Box<crate::send_form::SendFormState>,
    },
    ReceiveSend {
        state: Box<crate::send_form::ReceiveSendState>,
    },
    AttachmentPath {
        path: String,
    },
    CardForm {
        editing_id: Option<String>,
        name: String,
        cardholder_name: String,
        brand: String,
        number: String,
        exp_month: String,
        exp_year: String,
        code: String,
        notes: String,
        reprompt: bool,
        field: CardField,
    },
    IdentityForm {
        editing_id: Option<String>,
        name: String,
        title: String,
        first_name: String,
        middle_name: String,
        last_name: String,
        email: String,
        phone: String,
        username: String,
        company: String,
        address1: String,
        address2: String,
        address3: String,
        city: String,
        state: String,
        postal_code: String,
        country: String,
        ssn: String,
        passport: String,
        license: String,
        notes: String,
        reprompt: bool,
        field: IdentityField,
    },
    /// Edit custom fields for a cipher.
    CustomFieldsForm {
        item_id: String,
        fields: Vec<crate::models::CustomFieldView>,
        selected: usize,
        /// When editing a single field: index into fields, or None for list mode.
        editing: Option<usize>,
        edit_name: String,
        edit_value: String,
        edit_type: crate::models::CustomFieldKind,
        edit_focus: CustomFieldEditFocus,
    },
    SshKeyForm {
        editing_id: Option<String>,
        name: String,
        private_key: String,
        public_key: String,
        fingerprint: String,
        notes: String,
        field: SshKeyField,
    },
    MoveToFolder {
        item_id: String,
        selected: usize,
    },
    ShareToOrg {
        item_ids: Vec<String>,
        groups: Vec<OrgCollectionGroup>,
        org_index: usize,
        step: ShareToOrgStep,
        collection_cursor: usize,
        selected_collections: HashSet<String>,
    },
    PinSetup {
        pin: String,
        confirm: String,
        field: PinSetupField,
        status: String,
    },
    /// Account tools hub (KDF, deauthorize, 2FA setup, device approvals, forwarders, …).
    AccountTools(Box<AccountToolsState>),
    ChangeMasterPassword {
        old: String,
        new: String,
        confirm: String,
        hint: String,
        field: ChangePasswordField,
        error: Option<String>,
    },
}

/// Slow auth work queued by a key press so the loop can paint a busy frame before running it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingAction {
    Login,
    TwoFactor,
    Unlock,
    UnlockPin,
    ResendEmail2fa,
    DeviceLoginStart,
    DeviceLoginPoll,
    SsoStart,
    SsoFinish,
    CloneItem,
    BackgroundSync,
    HibpScan,
    HibpEmailScan,
    /// Cheap `GET /accounts/revision-date` probe; full sync only when it changed.
    RevisionCheck,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeneratorMode {
    Password,
    Passphrase,
    Username,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsernameKind {
    Word,
    Plus,
    Catchall,
    /// SimpleLogin alias (API token in keychain).
    SimpleLogin,
    /// addy.io alias (API token in keychain).
    AddyIo,
}

#[derive(Debug, Clone)]
pub struct HibpResultLine {
    pub label: String,
    pub count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustomFieldEditFocus {
    Name,
    Value,
    Type,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardField {
    Name,
    Cardholder,
    Brand,
    Number,
    ExpMonth,
    ExpYear,
    Code,
    Notes,
    Reprompt,
}

impl CardField {
    pub fn next(self) -> Self {
        match self {
            Self::Name => Self::Cardholder,
            Self::Cardholder => Self::Brand,
            Self::Brand => Self::Number,
            Self::Number => Self::ExpMonth,
            Self::ExpMonth => Self::ExpYear,
            Self::ExpYear => Self::Code,
            Self::Code => Self::Notes,
            Self::Notes => Self::Reprompt,
            Self::Reprompt => Self::Name,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            Self::Name => Self::Reprompt,
            Self::Cardholder => Self::Name,
            Self::Brand => Self::Cardholder,
            Self::Number => Self::Brand,
            Self::ExpMonth => Self::Number,
            Self::ExpYear => Self::ExpMonth,
            Self::Code => Self::ExpYear,
            Self::Notes => Self::Code,
            Self::Reprompt => Self::Notes,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityField {
    Name,
    Title,
    FirstName,
    MiddleName,
    LastName,
    Email,
    Phone,
    Username,
    Company,
    Address1,
    Address2,
    Address3,
    City,
    State,
    PostalCode,
    Country,
    Ssn,
    Passport,
    License,
    Notes,
    Reprompt,
}

impl IdentityField {
    const ORDER: &'static [IdentityField] = &[
        Self::Name,
        Self::Title,
        Self::FirstName,
        Self::MiddleName,
        Self::LastName,
        Self::Email,
        Self::Phone,
        Self::Username,
        Self::Company,
        Self::Address1,
        Self::Address2,
        Self::Address3,
        Self::City,
        Self::State,
        Self::PostalCode,
        Self::Country,
        Self::Ssn,
        Self::Passport,
        Self::License,
        Self::Notes,
        Self::Reprompt,
    ];

    pub fn next(self) -> Self {
        let idx = Self::ORDER.iter().position(|f| *f == self).unwrap_or(0);
        Self::ORDER[(idx + 1) % Self::ORDER.len()]
    }

    pub fn prev(self) -> Self {
        let idx = Self::ORDER.iter().position(|f| *f == self).unwrap_or(0);
        Self::ORDER[(idx + Self::ORDER.len() - 1) % Self::ORDER.len()]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshKeyField {
    Name,
    PrivateKey,
    PublicKey,
    Fingerprint,
    Notes,
}

impl SshKeyField {
    pub fn next(self) -> Self {
        match self {
            Self::Name => Self::PrivateKey,
            Self::PrivateKey => Self::PublicKey,
            Self::PublicKey => Self::Fingerprint,
            Self::Fingerprint => Self::Notes,
            Self::Notes => Self::Name,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            Self::Name => Self::Notes,
            Self::PrivateKey => Self::Name,
            Self::PublicKey => Self::PrivateKey,
            Self::Fingerprint => Self::PublicKey,
            Self::Notes => Self::Fingerprint,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinSetupField {
    Pin,
    Confirm,
}

impl PinSetupField {
    pub fn next(self) -> Self {
        match self {
            Self::Pin => Self::Confirm,
            Self::Confirm => Self::Pin,
        }
    }

    pub fn prev(self) -> Self {
        self.next()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangePasswordField {
    Old,
    New,
    Confirm,
    Hint,
}

impl ChangePasswordField {
    pub fn next(self) -> Self {
        match self {
            Self::Old => Self::New,
            Self::New => Self::Confirm,
            Self::Confirm => Self::Hint,
            Self::Hint => Self::Old,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            Self::Old => Self::Hint,
            Self::New => Self::Old,
            Self::Confirm => Self::New,
            Self::Hint => Self::Confirm,
        }
    }
}

pub struct App {
    pub screen: Screen,
    pub should_quit: bool,
    pub show_help: bool,
    /// Scroll offset (lines) while the help overlay is open.
    pub help_scroll: usize,
    pub overlay: Overlay,

    /// App data root (profile registry lives here).
    pub data_root: PathBuf,
    /// In-memory profile registry.
    pub profiles: ProfilesFile,
    /// Currently selected profile id (mirrors `profiles.active`).
    pub active_profile_id: String,
    /// Effective idle auto-lock for the active profile (`None` = disabled).
    pub auto_lock_minutes: Option<u64>,

    // --- Login / Unlock / 2FA ---
    pub server_url: String,
    pub email: String,
    pub password: String,
    /// When true, show master password characters on login/unlock screens.
    pub show_password: bool,
    /// When true, remember this profile's session after a successful login.
    pub remember_login: bool,
    pub login_auth_mode: LoginAuthMode,
    pub api_client_id: String,
    pub api_client_secret: String,
    pub login_field: LoginField,
    pub unlock_password: String,
    pub totp_code: String,
    pub two_factor_providers: Vec<u8>,
    /// Remember this device after successful 2FA (Bitwarden device token).
    pub remember_2fa_device: bool,
    /// 2FA picker / new-device OTP / device login / SSO state.
    pub auth_ext: AuthExtState,
    pub form_error: Option<String>,
    pub unlock_use_pin: bool,
    pub unlock_pin: String,

    // --- Vault data ---
    pub folders: Vec<FolderView>,
    pub items: Vec<DecryptedItem>,
    pub sends: Vec<crate::models::SendView>,
    pub visible_sends: Vec<usize>,
    pub org_labels: HashMap<String, String>,
    pub detail_attachments: Vec<(String, String)>,
    pub sidebar: Vec<SidebarEntry>,
    pub selected_sidebar: usize,
    pub selected_item: usize,
    pub focus: FocusPane,
    pub visible: Vec<usize>,
    /// Multi-select marks for bulk share / delete (`Space` in the item list).
    pub selected_ids: HashSet<String>,

    // --- Search ---
    pub searching: bool,
    pub search_query: String,

    // --- Status / timers ---
    pub status: String,
    pub status_expires: Option<Instant>,
    /// When true, idle status expiry must not replace the message (lock / sync idle).
    pub status_sticky: bool,
    /// Local time of the most recent successful vault sync.
    pub last_synced_at: Option<DateTime<Local>>,
    pub last_activity: Instant,
    pub locked_at: Option<Instant>,
    pub clipboard_clear_at: Option<Instant>,
    pub clipboard_kind: Option<ClipboardKind>,
    pub clipboard_demo: Option<String>,
    /// Temporarily show password / TOTP / card code in the detail pane.
    pub reveal_secrets: bool,
    pub reveal_until: Option<Instant>,
    /// Item id for which master re-prompt was satisfied this session.
    pub reprompt_ok_for: Option<String>,
    /// Mock-mode master password retained for re-prompt verification.
    mock_master_password: String,
    /// Profile clipboard auto-clear (seconds).
    pub clipboard_clear_secs: u64,

    /// When true, use mock vault (no network). Set by `--mock`.
    pub using_mock: bool,
    /// Live session when not in mock mode.
    pub session: Option<Session>,
    /// Unlocked/locked sessions parked while another profile is active.
    pub background_sessions: HashMap<String, Session>,
    /// Mock vault snapshots parked while another profile is active.
    background_mocks: HashMap<String, MockParked>,
    pub busy: bool,
    pub pending: Option<PendingAction>,
    /// Backup of ItemForm when opening the generator from it.
    pub item_form_backup: Option<Overlay>,
    /// Power-user feature state (toasts, sort, copy sequence, auto-type, QR, …).
    pub power: crate::app::PowerState,
    /// Loaded from `config.toml` (theme, generator defaults, keybindings).
    pub config: AppConfig,
    /// Resolved keybindings (defaults + config overrides).
    pub keymap: KeyMap,
    /// Soft-delete undo window.
    pub pending_undo: Option<PendingUndoDelete>,
    /// Detail pane scroll (j/k while it has focus), keyed by item id so a new
    /// selection starts at the top.
    pub detail_scroll: (Option<String>, u16),
    /// Largest useful detail scroll, measured at draw time.
    pub detail_scroll_max: std::cell::Cell<u16>,
    /// `g` was pressed; the next key picks a go-to target.
    pub pending_goto: bool,
    /// First `q` on an unlocked vault arms quitting; a second `q` quits.
    pub quit_armed: bool,
    last_auto_sync: Instant,
    last_revision_check: Instant,
    /// Lazily started watcher for system sleep / screen lock.
    system_lock: Option<SystemLockMonitor>,
    system_lock_probed: bool,
}

impl App {
    /// Build the app. Returns `Err` if `--profile` names an unknown profile.
    pub fn new(
        profile: Option<String>,
        server: Option<String>,
        email: Option<String>,
        mock: bool,
    ) -> Result<Self, String> {
        let (data_root, mut profiles) = if mock {
            (
                PathBuf::from(".bitwarden-tui-mock"),
                ProfilesFile::empty_default(),
            )
        } else {
            let root = app_data_dir();
            let file = load_registry_from(&root);
            (root, file)
        };

        if let Some(ref id) = profile {
            if profiles.get(id).is_none() {
                return Err(format!("Unknown profile '{id}'"));
            }
            if !mock {
                set_active(&data_root, &mut profiles, id)?;
            } else {
                profiles.active = id.clone();
            }
        }

        let active_id = profiles.active.clone();
        let active = profiles
            .get(&active_id)
            .cloned()
            .unwrap_or_else(|| VaultProfile {
                id: "default".into(),
                name: "default".into(),
                server_url: String::new(),
                email: String::new(),
                auto_lock_minutes: Some(15),
                allow_plaintext_token: false,
                clipboard_clear_secs: 30,
                timeout_action: vault_session::TimeoutAction::Lock,
                timeout_on_startup: false,
                lock_on_system_lock: false,
            });

        let cli_server = server.filter(|s| !s.is_empty());
        let cli_email = email.filter(|e| !e.is_empty());
        let server_url = cli_server
            .clone()
            .or_else(|| {
                if active.server_url.trim().is_empty() {
                    None
                } else {
                    Some(active.server_url.clone())
                }
            })
            .unwrap_or_else(|| "http://127.0.0.1:8080".into());
        let email = cli_email
            .clone()
            .or_else(|| {
                if active.email.trim().is_empty() {
                    None
                } else {
                    Some(active.email.clone())
                }
            })
            .unwrap_or_default();

        let has_auth = !mock && profile_has_auth(&data_root, &active_id);
        let has_creds = !active.server_url.trim().is_empty() || !active.email.trim().is_empty();
        let remember_login = has_auth || has_creds;
        let has_email = !email.is_empty();

        let auto_lock_minutes = active.auto_lock_minutes;
        let clipboard_clear_secs = active.clipboard_clear_secs;
        let config = load_config_from(&data_root);
        let custom = if config.colors.has_any() {
            Some(config.colors.to_custom())
        } else {
            None
        };
        init_theme(&config.theme, custom.as_ref());
        let keymap = KeyMap::resolve(&config.keybindings);
        for w in &keymap.warnings {
            tracing::warn!("keybinding: {w}");
        }
        let mut app = Self {
            screen: Screen::Login,
            should_quit: false,
            show_help: false,
            help_scroll: 0,
            overlay: Overlay::None,
            data_root,
            profiles,
            active_profile_id: active_id,
            auto_lock_minutes,
            server_url,
            email,
            password: String::new(),
            show_password: false,
            remember_login,
            login_auth_mode: LoginAuthMode::Password,
            api_client_id: String::new(),
            api_client_secret: String::new(),
            login_field: if has_email {
                LoginField::Password
            } else {
                LoginField::Email
            },
            unlock_password: String::new(),
            totp_code: String::new(),
            two_factor_providers: Vec::new(),
            remember_2fa_device: false,
            auth_ext: AuthExtState::default(),
            form_error: None,
            unlock_use_pin: false,
            unlock_pin: String::new(),
            folders: Vec::new(),
            items: Vec::new(),
            sends: Vec::new(),
            visible_sends: Vec::new(),
            org_labels: HashMap::new(),
            detail_attachments: Vec::new(),
            sidebar: Vec::new(),
            selected_sidebar: 0,
            selected_item: 0,
            focus: FocusPane::Items,
            visible: Vec::new(),
            selected_ids: HashSet::new(),
            searching: false,
            search_query: String::new(),
            status: if mock {
                "Mock mode — press ? for help".into()
            } else {
                "Ready — press ? for help".into()
            },
            status_expires: None,
            status_sticky: true,
            last_synced_at: None,
            last_activity: Instant::now(),
            locked_at: None,
            clipboard_clear_at: None,
            clipboard_kind: None,
            clipboard_demo: None,
            reveal_secrets: false,
            reveal_until: None,
            reprompt_ok_for: None,
            mock_master_password: String::new(),
            clipboard_clear_secs,
            using_mock: mock,
            session: None,
            background_sessions: HashMap::new(),
            background_mocks: HashMap::new(),
            busy: false,
            pending: None,
            item_form_backup: None,
            power: crate::app::PowerState::new(&config),
            config,
            keymap,
            pending_undo: None,
            detail_scroll: (None, 0),
            detail_scroll_max: std::cell::Cell::new(0),
            pending_goto: false,
            quit_armed: false,
            last_auto_sync: Instant::now(),
            last_revision_check: Instant::now(),
            system_lock: None,
            system_lock_probed: false,
        };
        if !app.email.is_empty() {
            app.login_field = LoginField::Password;
        }
        Ok(app)
    }

    /// Copy text via session clipboard, falling back to OSC 52 over SSH.
    pub fn copy_text_with_fallback(&mut self, value: &str, label: &str) -> bool {
        if value.is_empty() {
            self.set_status(format!("No {label} on this item"));
            return false;
        }
        let session_ok = if let Some(session) = self.session.as_mut() {
            session.copy_text(value).is_ok()
        } else {
            false
        };
        if session_ok {
            self.set_status(format!("{label} copied"));
            self.touch();
            return true;
        }
        if crate::osc52::try_copy_osc52(value) {
            self.set_status(format!("{label} copied (OSC 52)"));
            self.touch();
            return true;
        }
        if self.using_mock {
            if let Some(mut prev) = self.clipboard_demo.take() {
                prev.zeroize();
            }
            self.clipboard_demo = Some(value.to_string());
            self.clipboard_clear_at = Some(Instant::now() + self.demo_clipboard_duration());
            self.set_status(format!(
                "{label} copied (demo) — clears in {}s",
                self.demo_clipboard_duration().as_secs()
            ));
            self.touch();
            return true;
        }
        self.set_status("Copy failed (no clipboard / OSC 52)");
        false
    }

    pub fn profile_data_dir(&self) -> PathBuf {
        profile_dir(&self.data_root, &self.active_profile_id)
    }

    fn profile_plaintext_token_allowed(&self) -> bool {
        plaintext_token_allowed(
            self.profiles
                .get(&self.active_profile_id)
                .map(|p| p.allow_plaintext_token)
                .unwrap_or(false),
        )
    }

    fn configure_session_persist(&self, session: &mut Session) {
        session.set_allow_plaintext_token(self.profile_plaintext_token_allowed());
        session.set_clipboard_clear_secs(self.clipboard_clear_secs);
    }

    pub fn clear_session_clipboard(&mut self) {
        if let Some(session) = self.session.as_mut() {
            session.clear_clipboard_if_ours();
        }
    }

    pub fn active_profile_name(&self) -> &str {
        self.profiles
            .get(&self.active_profile_id)
            .map(|p| p.name.as_str())
            .unwrap_or(self.active_profile_id.as_str())
    }

    pub fn apply_auto_lock_from_profile(&mut self) {
        let minutes = self
            .profiles
            .get(&self.active_profile_id)
            .and_then(|p| p.auto_lock_minutes);
        let action = self
            .profiles
            .get(&self.active_profile_id)
            .map(|p| p.timeout_action)
            .unwrap_or_default();
        self.auto_lock_minutes = minutes;
        if let Some(session) = self.session.as_mut() {
            session.set_auto_lock(minutes);
            session.set_timeout_action(action);
        }
    }

    /// Idle timeout actually in force (profile value capped by org policy type 9).
    pub fn effective_auto_lock_minutes(&self) -> Option<u64> {
        match self.session.as_ref() {
            Some(session) => session.effective_auto_lock_minutes(),
            None => self.auto_lock_minutes,
        }
    }

    /// Org vault-timeout policy for a profile's live session, if any.
    pub fn vault_timeout_policy_for(&self, id: &str) -> Option<vault_session::VaultTimeoutPolicy> {
        let session = if id == self.active_profile_id {
            self.session.as_ref()
        } else {
            self.background_sessions.get(id)
        }?;
        let policy = session.vault_timeout_policy();
        policy.is_active().then_some(policy)
    }

    /// Ensure `auto-lock` minutes (profile edit) obey org policy type 9.
    fn check_timeout_policy(&self, id: &str, minutes: Option<u64>) -> Result<(), String> {
        let Some(policy) = self.vault_timeout_policy_for(id) else {
            return Ok(());
        };
        if let Some(max) = policy.max_minutes {
            match minutes {
                None => {
                    return Err(format!(
                        "Organization policy limits the vault timeout to {max} min — \"never\" is not allowed"
                    ))
                }
                Some(m) if m > max => {
                    return Err(format!(
                        "Organization policy limits the vault timeout to {max} min"
                    ))
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub fn apply_clipboard_clear_from_profile(&mut self) {
        let secs = self
            .profiles
            .get(&self.active_profile_id)
            .map(|p| p.clipboard_clear_secs)
            .unwrap_or(30);
        self.clipboard_clear_secs = secs;
        if let Some(session) = self.session.as_mut() {
            session.set_clipboard_clear_secs(secs);
        }
    }

    fn demo_clipboard_duration(&self) -> Duration {
        Duration::from_secs(self.clipboard_clear_secs.max(5))
    }

    fn reprompt_granted(&self, item_id: &str) -> bool {
        self.reprompt_ok_for.as_deref() == Some(item_id)
    }

    fn copy_kind_needs_reprompt(kind: ClipboardKind) -> bool {
        matches!(
            kind,
            ClipboardKind::Password
                | ClipboardKind::Totp
                | ClipboardKind::CardNumber
                | ClipboardKind::CardCode
                | ClipboardKind::CardExpiry
                | ClipboardKind::SshPrivate
                | ClipboardKind::Notes
        )
    }

    fn open_reprompt(&mut self, item_id: String, then: PendingRepromptAction) {
        self.overlay = Overlay::Reprompt {
            item_id,
            password: String::new(),
            error: None,
            then,
        };
    }

    pub fn submit_reprompt(&mut self) {
        let Overlay::Reprompt {
            item_id,
            password,
            then,
            ..
        } = &self.overlay
        else {
            return;
        };
        let item_id = item_id.clone();
        let password = password.clone();
        let then = then.clone();

        let ok = if self.using_mock {
            !password.is_empty() && password == self.mock_master_password
        } else if let Some(session) = self.session.as_ref() {
            session.verify_reprompt(&password).unwrap_or(false)
        } else {
            false
        };

        if !ok {
            if let Overlay::Reprompt { error, .. } = &mut self.overlay {
                *error = Some("Incorrect master password".into());
            }
            return;
        }

        self.reprompt_ok_for = Some(item_id);
        self.overlay = Overlay::None;
        self.execute_reprompt_action(then);
    }

    fn execute_reprompt_action(&mut self, action: PendingRepromptAction) {
        match action {
            PendingRepromptAction::Reveal => self.toggle_reveal_inner(),
            PendingRepromptAction::Copy(kind) => self.copy_field_inner(kind),
            PendingRepromptAction::Edit => self.open_edit_item_inner(),
        }
    }

    pub(crate) fn gate_reprompt(
        &mut self,
        item: &DecryptedItem,
        then: PendingRepromptAction,
    ) -> bool {
        if !item.reprompt || self.reprompt_granted(&item.id) {
            return false;
        }
        self.open_reprompt(item.id.clone(), then);
        true
    }

    /// Whether a profile currently has an unlocked vault in memory.
    pub fn profile_is_open(&self, id: &str) -> bool {
        if id == self.active_profile_id {
            return self.screen == Screen::Vault;
        }
        if self.background_mocks.contains_key(id) {
            return true;
        }
        self.background_sessions
            .get(id)
            .is_some_and(|s| s.status() == SessionStatus::Unlocked)
    }

    pub fn open_profile_manager(&mut self) {
        let selected = self
            .profiles
            .profiles
            .iter()
            .position(|p| p.id == self.active_profile_id)
            .unwrap_or(0);
        self.overlay = Overlay::ProfileManager {
            selected,
            mode: ProfileManagerMode::List,
        };
    }

    /// Toggle global lock-on-switch. Enabling clears all parked sessions.
    pub fn toggle_lock_on_profile_switch(&mut self) {
        let enabled = !self.profiles.lock_on_profile_switch;
        if self.using_mock {
            self.profiles.lock_on_profile_switch = enabled;
        } else if let Err(e) =
            set_lock_on_profile_switch(&self.data_root, &mut self.profiles, enabled)
        {
            self.set_status(e);
            return;
        }
        if enabled {
            self.clear_background_sessions();
        }
        self.set_status(if enabled {
            "Lock on profile switch: on"
        } else {
            "Lock on profile switch: off"
        });
    }

    fn clear_background_sessions(&mut self) {
        for (_, mut session) in self.background_sessions.drain() {
            session.lock();
        }
        self.background_mocks.clear();
    }

    fn park_outgoing_profile(&mut self, outgoing_id: &str) {
        if outgoing_id.is_empty() {
            if let Some(mut session) = self.session.take() {
                session.lock();
            }
            return;
        }
        let lock_on_switch = self.profiles.lock_on_profile_switch;
        if self.using_mock {
            if lock_on_switch {
                self.background_mocks.remove(outgoing_id);
            } else if self.screen == Screen::Vault && !self.items.is_empty() {
                self.background_mocks.insert(
                    outgoing_id.to_string(),
                    MockParked {
                        folders: std::mem::take(&mut self.folders),
                        items: std::mem::take(&mut self.items),
                        last_activity: self.last_activity,
                        auto_lock_minutes: self.auto_lock_minutes,
                    },
                );
            }
            return;
        }

        if let Some(mut session) = self.session.take() {
            if lock_on_switch {
                session.lock();
            } else {
                self.background_sessions
                    .insert(outgoing_id.to_string(), session);
            }
        }
    }

    fn mock_parked_still_open(parked: &MockParked) -> bool {
        match parked.auto_lock_minutes {
            None => true,
            Some(mins) => {
                let timeout = Duration::from_secs(mins.saturating_mul(60));
                parked.last_activity.elapsed() < timeout
            }
        }
    }

    fn restore_mock_parked(&mut self, parked: MockParked) {
        self.folders = parked.folders;
        self.items = parked.items;
        self.last_activity = parked.last_activity;
        self.auto_lock_minutes = parked.auto_lock_minutes;
        self.rebuild_sidebar();
        self.recompute_visible();
        self.selected_sidebar = 0;
        self.selected_item = 0;
        self.focus = FocusPane::Items;
        self.screen = Screen::Vault;
        self.locked_at = None;
    }

    // -------------------------------------------------------------------------
    // Session / mock auth
    // -------------------------------------------------------------------------

    pub fn queue(&mut self, action: PendingAction) {
        if !self.busy && self.pending.is_none() {
            self.pending = Some(action);
        }
    }

    pub async fn run_pending(&mut self) {
        match self.pending.take() {
            Some(PendingAction::Login) => self.submit_login().await,
            Some(PendingAction::TwoFactor) => self.submit_2fa().await,
            Some(PendingAction::Unlock) => self.submit_unlock().await,
            Some(PendingAction::UnlockPin) => self.submit_unlock_pin().await,
            Some(PendingAction::ResendEmail2fa) => self.resend_email_2fa().await,
            Some(PendingAction::DeviceLoginStart) => self.start_device_login().await,
            Some(PendingAction::DeviceLoginPoll) => self.poll_device_login().await,
            Some(PendingAction::SsoStart) => self.start_sso().await,
            Some(PendingAction::SsoFinish) => self.finish_sso().await,
            Some(PendingAction::CloneItem) => self.clone_selected_item().await,
            Some(PendingAction::BackgroundSync) => self.sync_vault().await,
            Some(PendingAction::HibpScan) => self.run_hibp_scan().await,
            Some(PendingAction::HibpEmailScan) => self.run_hibp_email_scan().await,
            Some(PendingAction::RevisionCheck) => self.check_revision().await,
            None => {}
        }
    }

    pub async fn resend_email_2fa(&mut self) {
        if self.current_two_factor_provider() != vault_session::TWO_FACTOR_EMAIL {
            self.set_status("Switch to Email 2FA to resend (Tab / j k)");
            return;
        }
        if self.password.is_empty() {
            self.set_status("Master password required to resend email code");
            return;
        }
        let email = self.email.trim().to_string();
        let password = self.password.clone();
        let Some(session) = self.session.as_ref() else {
            self.set_status("No active login session");
            return;
        };
        self.busy = true;
        match session.send_email_login_2fa(&email, &password).await {
            Ok(()) => self.set_status("Verification email sent"),
            Err(e) => self.set_status(format!("Resend failed: {e}")),
        }
        self.busy = false;
    }

    pub async fn submit_login(&mut self) {
        self.form_error = None;
        if self.email.trim().is_empty() {
            self.form_error = Some("Email is required".into());
            return;
        }
        if self.password.is_empty() {
            self.form_error = Some("Master password is required".into());
            return;
        }

        let server = match normalize_server_url(&self.server_url) {
            Ok(s) => s,
            Err(e) => {
                self.form_error = Some(e.to_string());
                return;
            }
        };
        // Reflect normalized URL in the form (e.g. added https://).
        self.server_url = server.clone();

        if self.using_mock {
            self.mock_master_password = self.password.clone();
            self.password.zeroize();
            self.load_mock_vault();
            self.apply_auto_lock_from_profile();
            self.apply_clipboard_clear_from_profile();
            self.screen = Screen::Vault;
            self.set_status("Logged in (mock vault)");
            self.touch();
            return;
        }

        // Persist typed server/email on the active profile even if auth fails,
        // so switching away and back doesn't wipe what the user entered.
        let email = self.email.trim().to_string();
        let _ = update_profile_credentials(
            &self.data_root,
            &mut self.profiles,
            &self.active_profile_id,
            &server,
            &email,
        );

        self.busy = true;
        self.set_status(format!("Logging in to {server}…"));
        let password = self.password.clone();

        let mut session = match Session::with_data_dir(&server, self.profile_data_dir()) {
            Ok(s) => s,
            Err(e) => {
                self.busy = false;
                self.form_error = Some(e.to_string());
                self.set_status("Login failed");
                return;
            }
        };
        self.configure_session_persist(&mut session);
        if let Some(otp) = self.auth_ext.pending_new_device_otp.take() {
            session.set_new_device_otp(Some(&otp));
        }

        let login_result = if self.login_auth_mode == LoginAuthMode::ApiKey {
            if self.api_client_id.trim().is_empty() || self.api_client_secret.is_empty() {
                self.busy = false;
                self.form_error = Some("API client id and secret are required".into());
                return;
            }
            session
                .login_api_key(
                    &email,
                    &password,
                    self.api_client_id.trim(),
                    self.api_client_secret.trim(),
                )
                .await
        } else {
            session.login(&email, &password, None).await
        };

        match login_result {
            Ok(LoginResult::Success) => {
                self.password.zeroize();
                self.persist_login_prefs(&server, &email);
                self.session = Some(session);
                self.apply_auto_lock_from_profile();
                self.apply_clipboard_clear_from_profile();
                self.reload_from_session();
                self.screen = Screen::Vault;
                self.locked_at = None;
                self.mark_synced();
                self.show_last_synced_status();
                self.touch();
            }
            Ok(LoginResult::TwoFactorRequired { providers }) => {
                self.session = Some(session);
                self.apply_auto_lock_from_profile();
                self.two_factor_providers = providers;
                self.auth_ext.two_factor_selected = 0;
                self.auth_ext.new_device_mode = false;
                self.totp_code.clear();
                self.screen = Screen::TwoFactor;
                self.set_status("Two-factor authentication required");
            }
            Err(e) if e.is_new_device_verification_required() => {
                self.enter_new_device_mode();
            }
            Err(e) => {
                self.form_error = Some(e.to_string());
                self.set_status("Login failed");
            }
        }
        self.busy = false;
    }

    fn persist_login_prefs(&mut self, server: &str, email: &str) {
        if self.using_mock {
            return;
        }
        if self.remember_login {
            let _ = update_profile_credentials(
                &self.data_root,
                &mut self.profiles,
                &self.active_profile_id,
                server,
                email,
            );
            // Session already wrote auth.json during login; keep it for next launch.
        } else {
            Session::clear_persisted_auth(&self.profile_data_dir());
            let _ = update_profile_credentials(
                &self.data_root,
                &mut self.profiles,
                &self.active_profile_id,
                server,
                email,
            );
        }
    }

    /// If the user previously checked “Remember”, restore the refresh-token session
    /// and open the unlock screen (master password still required).
    pub async fn restore_session_if_saved(&mut self) {
        if self.using_mock || !self.remember_login {
            return;
        }
        self.set_status("Restoring session…");
        match Session::try_restore_saved(
            self.profile_data_dir(),
            self.profile_plaintext_token_allowed(),
        )
        .await
        {
            Ok(Some(mut session)) => {
                let apply_on_startup = self
                    .profiles
                    .get(&self.active_profile_id)
                    .is_some_and(|p| p.timeout_on_startup);
                if apply_on_startup {
                    let action = self
                        .profiles
                        .get(&self.active_profile_id)
                        .map(|p| p.timeout_action)
                        .unwrap_or_default();
                    session.set_timeout_action(action);
                    if session.effective_timeout_action() == TimeoutAction::Logout {
                        // Timeout-on-startup with "log out": drop the remembered session.
                        session.logout();
                        self.remember_login = false;
                        self.screen = Screen::Login;
                        self.set_status("Logged out on startup (vault timeout action)");
                        return;
                    }
                }
                if let Some(email) = session.email() {
                    self.email = email.to_string();
                }
                self.server_url = session.server_url().to_string();
                self.session = Some(session);
                self.apply_auto_lock_from_profile();
                self.screen = Screen::Unlock;
                self.locked_at = Some(Instant::now());
                self.set_status("Session restored — enter master password");
            }
            Ok(None) => {
                // Prefs without a live session: stay on login with prefilled fields.
                self.set_status("Ready — press ? for help");
            }
            Err(_) => {
                self.set_status("Ready — press ? for help");
            }
        }
    }

    /// Switch to another named profile (keeps other profiles' auth.json intact).
    pub async fn switch_to_profile(&mut self, id: &str) {
        if id == self.active_profile_id {
            self.overlay = Overlay::None;
            return;
        }
        if self.profiles.get(id).is_none() {
            self.set_status(format!("Unknown profile '{id}'"));
            return;
        }

        self.password.zeroize();
        self.unlock_password.zeroize();
        self.totp_code.clear();
        self.form_error = None;
        self.searching = false;
        self.search_query.clear();
        self.show_help = false;
        self.overlay = Overlay::None;
        if let Some(mut s) = self.clipboard_demo.take() {
            s.zeroize();
        }
        self.clipboard_clear_at = None;
        self.clipboard_kind = None;

        let outgoing = self.active_profile_id.clone();
        self.park_outgoing_profile(&outgoing);

        self.items.clear();
        self.folders.clear();
        self.sidebar.clear();
        self.visible.clear();
        self.selected_sidebar = 0;
        self.selected_item = 0;
        self.session = None;

        if !self.using_mock {
            if let Err(e) = set_active(&self.data_root, &mut self.profiles, id) {
                self.set_status(e);
                return;
            }
        } else {
            self.profiles.active = id.to_string();
        }
        self.active_profile_id = id.to_string();

        // Keep the current server URL when the target profile has none yet
        // (new profiles inherit the previous URL instead of resetting to localhost).
        if let Some(p) = self.profiles.get(id) {
            if !p.server_url.trim().is_empty() {
                self.server_url = p.server_url.clone();
            } else if self.server_url.trim().is_empty() {
                self.server_url = "http://127.0.0.1:8080".into();
            }
            self.email = p.email.clone();
        }

        let name = self.active_profile_name().to_string();
        self.apply_auto_lock_from_profile();

        if self.using_mock {
            if !self.profiles.lock_on_profile_switch {
                if let Some(parked) = self.background_mocks.remove(id) {
                    if Self::mock_parked_still_open(&parked) {
                        self.restore_mock_parked(parked);
                        self.set_status(format!("Switched to {name}"));
                        return;
                    }
                }
            }
            self.screen = Screen::Login;
            self.login_field = if self.email.is_empty() {
                LoginField::Email
            } else {
                LoginField::Password
            };
            self.remember_login = false;
            self.locked_at = None;
            self.set_status(format!("Switched to {name}"));
            return;
        }

        if let Some(session) = self.background_sessions.remove(id) {
            let status = session.status();
            if let Some(email) = session.email() {
                self.email = email.to_string();
            }
            self.server_url = session.server_url().to_string();
            self.session = Some(session);
            self.apply_auto_lock_from_profile();
            match status {
                SessionStatus::Unlocked => {
                    self.reload_from_session();
                    self.screen = Screen::Vault;
                    self.locked_at = None;
                    self.remember_login = true;
                    self.set_status(format!("Switched to {name}"));
                }
                SessionStatus::Locked => {
                    self.screen = Screen::Unlock;
                    self.locked_at = Some(Instant::now());
                    self.remember_login = true;
                    self.set_status(format!("Switched to {name} — enter master password"));
                }
                SessionStatus::LoggedOut => {
                    self.session = None;
                    self.screen = Screen::Login;
                    self.locked_at = None;
                    self.login_field = if self.email.is_empty() {
                        LoginField::Email
                    } else {
                        LoginField::Password
                    };
                    self.set_status(format!("Switched to {name}"));
                }
            }
            return;
        }

        let has_auth = profile_has_auth(&self.data_root, id);
        self.remember_login = has_auth
            || self
                .profiles
                .get(id)
                .map(|p| !p.server_url.trim().is_empty() || !p.email.trim().is_empty())
                .unwrap_or(false);

        match Session::try_restore_saved(
            self.profile_data_dir(),
            self.profile_plaintext_token_allowed(),
        )
        .await
        {
            Ok(Some(session)) => {
                if let Some(email) = session.email() {
                    self.email = email.to_string();
                }
                self.server_url = session.server_url().to_string();
                self.session = Some(session);
                self.apply_auto_lock_from_profile();
                self.screen = Screen::Unlock;
                self.locked_at = Some(Instant::now());
                self.set_status(format!("Switched to {name} — enter master password"));
            }
            _ => {
                self.screen = Screen::Login;
                self.locked_at = None;
                self.login_field = if self.email.is_empty() {
                    LoginField::Email
                } else {
                    LoginField::Password
                };
                self.set_status(format!("Switched to {name}"));
            }
        }
    }

    /// Sign out of the current profile (clears this profile's auth.json only).
    pub fn sign_out_current_profile(&mut self) {
        let id = self.active_profile_id.clone();
        self.background_sessions.remove(&id);
        self.background_mocks.remove(&id);
        if let Some(session) = self.session.as_mut() {
            session.logout();
        } else if !self.using_mock {
            Session::clear_persisted_auth(&self.profile_data_dir());
        }
        self.session = None;
        self.password.zeroize();
        self.unlock_password.zeroize();
        self.items.clear();
        self.folders.clear();
        self.sidebar.clear();
        self.visible.clear();
        self.overlay = Overlay::None;
        self.screen = Screen::Login;
        self.locked_at = None;
        self.remember_login = false;
        self.login_field = if self.email.is_empty() {
            LoginField::Email
        } else {
            LoginField::Password
        };
        self.last_synced_at = None;
        self.set_status("Signed out");
    }

    pub async fn profile_manager_create_save(&mut self) {
        let name = match &self.overlay {
            Overlay::ProfileManager {
                mode: ProfileManagerMode::Create { name, .. },
                ..
            } => name.clone(),
            _ => return,
        };
        let inherit_server = self.server_url.trim().to_string();
        let result = if self.using_mock {
            let display = name.trim();
            if display.is_empty() {
                Err("Name cannot be empty".into())
            } else {
                let id = allocate_profile_id(&self.profiles, display);
                self.profiles.profiles.push(VaultProfile {
                    id: id.clone(),
                    name: display.to_string(),
                    server_url: inherit_server.clone(),
                    email: String::new(),
                    auto_lock_minutes: Some(15),
                    allow_plaintext_token: false,
                    clipboard_clear_secs: 30,
                    timeout_action: vault_session::TimeoutAction::Lock,
                    timeout_on_startup: false,
                    lock_on_system_lock: false,
                });
                Ok(id)
            }
        } else {
            create_profile(&self.data_root, &mut self.profiles, &name, &inherit_server)
        };
        let id = match result {
            Ok(id) => id,
            Err(e) => {
                if let Overlay::ProfileManager {
                    mode: ProfileManagerMode::Create { error, .. },
                    ..
                } = &mut self.overlay
                {
                    *error = Some(e);
                }
                return;
            }
        };
        self.switch_to_profile(&id).await;
    }

    pub fn profile_manager_edit_save(&mut self) {
        let (
            id,
            name,
            server_url,
            email,
            auto_lock_input,
            clipboard_clear_input,
            timeout_action,
            timeout_on_startup,
            lock_on_system_lock,
            selected,
        ) = match &self.overlay {
            Overlay::ProfileManager {
                mode:
                    ProfileManagerMode::Edit {
                        id,
                        name,
                        server_url,
                        email,
                        auto_lock_input,
                        clipboard_clear_input,
                        timeout_action,
                        timeout_on_startup,
                        lock_on_system_lock,
                        ..
                    },
                selected,
            } => (
                id.clone(),
                name.clone(),
                server_url.clone(),
                email.clone(),
                auto_lock_input.clone(),
                clipboard_clear_input.clone(),
                *timeout_action,
                *timeout_on_startup,
                *lock_on_system_lock,
                *selected,
            ),
            _ => return,
        };

        if name.trim().is_empty() {
            if let Overlay::ProfileManager {
                mode: ProfileManagerMode::Edit { error, .. },
                ..
            } = &mut self.overlay
            {
                *error = Some("Name cannot be empty".into());
            }
            return;
        }

        let minutes = match parse_auto_lock_input(&auto_lock_input) {
            Ok(m) => m,
            Err(e) => {
                if let Overlay::ProfileManager {
                    mode: ProfileManagerMode::Edit { error, .. },
                    ..
                } = &mut self.overlay
                {
                    *error = Some(e);
                }
                return;
            }
        };

        if let Err(e) = self.check_timeout_policy(&id, minutes) {
            if let Overlay::ProfileManager {
                mode: ProfileManagerMode::Edit { error, .. },
                ..
            } = &mut self.overlay
            {
                *error = Some(e);
            }
            return;
        }

        let clipboard_secs = match parse_clipboard_clear_input(&clipboard_clear_input) {
            Ok(s) => s,
            Err(e) => {
                if let Overlay::ProfileManager {
                    mode: ProfileManagerMode::Edit { error, .. },
                    ..
                } = &mut self.overlay
                {
                    *error = Some(e);
                }
                return;
            }
        };

        let result = if self.using_mock {
            match self.profiles.get_mut(&id) {
                Some(p) => {
                    p.name = name.trim().to_string();
                    p.server_url = server_url.trim().to_string();
                    p.email = email.trim().to_string();
                    p.auto_lock_minutes = minutes;
                    p.clipboard_clear_secs = clipboard_secs;
                    p.timeout_action = timeout_action;
                    p.timeout_on_startup = timeout_on_startup;
                    p.lock_on_system_lock = lock_on_system_lock;
                    Ok(())
                }
                None => Err(format!("Unknown profile '{id}'")),
            }
        } else {
            update_profile(
                &self.data_root,
                &mut self.profiles,
                &id,
                &name,
                &server_url,
                &email,
                minutes,
            )
            .and_then(|_| {
                if let Some(p) = self.profiles.get_mut(&id) {
                    p.clipboard_clear_secs = clipboard_secs;
                    p.timeout_action = timeout_action;
                    p.timeout_on_startup = timeout_on_startup;
                    p.lock_on_system_lock = lock_on_system_lock;
                    crate::profiles::save_registry_to(&self.data_root, &self.profiles)
                } else {
                    Ok(())
                }
            })
        };
        if let Err(e) = result {
            if let Overlay::ProfileManager {
                mode: ProfileManagerMode::Edit { error, .. },
                ..
            } = &mut self.overlay
            {
                *error = Some(e);
            }
            return;
        }

        if id == self.active_profile_id {
            if let Some(p) = self.profiles.get(&id) {
                if !p.server_url.trim().is_empty() {
                    self.server_url = p.server_url.clone();
                }
                self.email = p.email.clone();
            }
            self.apply_auto_lock_from_profile();
            self.apply_clipboard_clear_from_profile();
        }
        if let Some(session) = self.background_sessions.get_mut(&id) {
            session.set_auto_lock(minutes);
            session.set_timeout_action(timeout_action);
            session.set_clipboard_clear_secs(clipboard_secs);
        }
        if let Some(parked) = self.background_mocks.get_mut(&id) {
            parked.auto_lock_minutes = minutes;
        }

        self.overlay = Overlay::ProfileManager {
            selected,
            mode: ProfileManagerMode::List,
        };
        self.set_status("Profile updated");
    }

    pub async fn profile_manager_confirm_delete(&mut self) {
        let Overlay::ProfileManager {
            mode: ProfileManagerMode::ConfirmDelete { id, .. },
            ..
        } = &self.overlay
        else {
            return;
        };
        let id = id.clone();
        self.background_sessions.remove(&id);
        self.background_mocks.remove(&id);
        let was_active = id == self.active_profile_id;
        let new_active = if self.using_mock {
            self.profiles.profiles.retain(|p| p.id != id);
            if self.profiles.profiles.is_empty() {
                self.profiles = ProfilesFile::empty_default();
            }
            if was_active {
                self.profiles.active = self.profiles.profiles[0].id.clone();
            }
            self.profiles.active.clone()
        } else {
            match delete_profile(&self.data_root, &mut self.profiles, &id) {
                Ok(a) => a,
                Err(e) => {
                    self.set_status(e);
                    return;
                }
            }
        };
        if was_active {
            // Drop foreground session for the deleted profile; clear active id so
            // switch still runs when the replacement reuses the same slug (e.g. default).
            if let Some(mut session) = self.session.take() {
                session.lock();
            }
            self.items.clear();
            self.folders.clear();
            self.sidebar.clear();
            self.visible.clear();
            self.active_profile_id.clear();
            self.switch_to_profile(&new_active).await;
        } else {
            let selected = self
                .profiles
                .profiles
                .iter()
                .position(|p| p.id == self.active_profile_id)
                .unwrap_or(0);
            self.overlay = Overlay::ProfileManager {
                selected,
                mode: ProfileManagerMode::List,
            };
            self.set_status("Profile deleted");
        }
    }

    pub async fn submit_2fa(&mut self) {
        self.form_error = None;
        if self.totp_code.trim().is_empty() {
            self.form_error = Some("Enter the verification code".into());
            return;
        }
        if self.auth_ext.new_device_mode {
            self.submit_new_device_otp().await;
            return;
        }
        if self.using_mock {
            self.totp_code.clear();
            self.password.zeroize();
            self.load_mock_vault();
            self.screen = Screen::Vault;
            self.set_status("2FA accepted (mock)");
            return;
        }

        let email = self.email.trim().to_string();
        let password = self.password.clone();
        let code = self.totp_code.trim().to_string();
        let provider = self.current_two_factor_provider();
        let Some(code) = self.prepare_two_factor_code(provider, code) else {
            return;
        };

        if self.session.is_none() {
            self.form_error = Some("Session missing — return to login".into());
            self.screen = Screen::Login;
            return;
        }

        self.busy = true;
        self.set_status("Verifying 2FA…");
        let result = self
            .session
            .as_mut()
            .unwrap()
            .login_2fa_remember(&email, &password, provider, &code, self.remember_2fa_device)
            .await;
        match result {
            Ok(()) => {
                let server = self.server_url.trim().to_string();
                self.password.zeroize();
                self.totp_code.clear();
                self.persist_login_prefs(&server, &email);
                self.apply_auto_lock_from_profile();
                self.reload_from_session();
                self.screen = Screen::Vault;
                self.locked_at = None;
                self.mark_synced();
                self.show_last_synced_status();
                self.touch();
            }
            Err(e) => {
                self.form_error = Some(e.to_string());
                self.set_status("2FA failed");
            }
        }
        self.busy = false;
    }

    pub async fn submit_unlock(&mut self) {
        self.form_error = None;
        if self.unlock_password.is_empty() {
            self.form_error = Some("Master password is required".into());
            return;
        }

        if self.using_mock {
            self.unlock_password.zeroize();
            if self.items.is_empty() {
                self.load_mock_vault();
            }
            self.apply_auto_lock_from_profile();
            self.screen = Screen::Vault;
            self.locked_at = None;
            self.last_activity = Instant::now();
            self.set_status("Vault unlocked");
            return;
        }

        let password = self.unlock_password.clone();
        if self.session.is_none() {
            self.form_error = Some("Not logged in".into());
            self.screen = Screen::Login;
            return;
        }

        self.busy = true;
        self.set_status("Unlocking…");
        let result = self.session.as_mut().unwrap().unlock(&password).await;
        match result {
            Ok(()) => {
                self.unlock_password.zeroize();
                self.apply_auto_lock_from_profile();
                self.reload_from_session();
                self.screen = Screen::Vault;
                self.locked_at = None;
                self.last_activity = Instant::now();
                self.mark_synced();
                self.show_last_synced_status();
                self.touch();
            }
            Err(e) => {
                self.form_error = Some(e.to_string());
                self.set_status("Unlock failed");
            }
        }
        self.busy = false;
    }

    pub async fn submit_unlock_pin(&mut self) {
        self.form_error = None;
        if self.unlock_pin.is_empty() {
            self.form_error = Some("Enter your PIN".into());
            return;
        }
        if self.session.is_none() {
            self.form_error = Some("Not logged in".into());
            return;
        }
        let pin = self.unlock_pin.clone();
        self.busy = true;
        let result = self
            .session
            .as_mut()
            .unwrap()
            .unlock_with_pin_code(&pin)
            .await;
        match result {
            Ok(()) => {
                self.unlock_pin.zeroize();
                self.unlock_password.zeroize();
                self.apply_auto_lock_from_profile();
                self.reload_from_session();
                self.screen = Screen::Vault;
                self.locked_at = None;
                self.mark_synced();
                self.show_last_synced_status();
                self.touch();
            }
            Err(e) => {
                self.form_error = Some(e.to_string());
                self.set_status("PIN unlock failed");
            }
        }
        self.busy = false;
    }

    pub fn lock(&mut self) {
        if let Some(session) = self.session.as_mut() {
            session.stop_ssh_agent();
        }
        self.unlock_password.zeroize();
        self.password.zeroize();
        self.searching = false;
        self.search_query.clear();
        self.show_help = false;
        self.overlay = Overlay::None;
        self.reveal_secrets = false;
        self.reveal_until = None;
        if let Some(mut s) = self.clipboard_demo.take() {
            s.zeroize();
        }
        self.clipboard_clear_at = None;
        self.clipboard_kind = None;
        self.reprompt_ok_for = None;

        if let Some(session) = self.session.as_mut() {
            session.lock();
        }
        // Clear secrets from UI cache when locking a live session.
        if !self.using_mock {
            self.items.clear();
            self.folders.clear();
            self.sidebar.clear();
            self.visible.clear();
        }

        self.screen = Screen::Unlock;
        self.locked_at = Some(Instant::now());
        self.set_sticky_status("Vault locked");
    }

    fn load_mock_vault(&mut self) {
        let folders = sample_folders();
        let items = sample_items();
        self.folders = with_folder_counts(folders, &items);
        self.items = items;
        self.using_mock = true;
        self.rebuild_sidebar();
        self.recompute_visible();
        self.selected_sidebar = 0;
        self.selected_item = 0;
        self.focus = FocusPane::Items;
    }

    pub fn reload_from_session(&mut self) {
        let Some(session) = self.session.as_ref() else {
            return;
        };
        if let Some(ts) = session.last_synced_at() {
            self.last_synced_at = Some(ts.with_timezone(&Local));
        }
        let items: Vec<DecryptedItem> = session
            .items()
            .iter()
            .map(DecryptedItem::from_session)
            .collect();
        let folders: Vec<FolderView> = session
            .folders()
            .iter()
            .map(|f| {
                let count = items
                    .iter()
                    .filter(|i| !i.deleted && i.folder_id.as_deref() == Some(f.id.as_str()))
                    .count();
                FolderView::from_session(f, count)
            })
            .collect();
        self.folders = folders;
        self.items = items;
        self.org_labels = session
            .organizations()
            .iter()
            .map(|o| (o.id.clone(), o.name.clone()))
            .collect();
        self.sends = session
            .sends()
            .iter()
            .map(|s| crate::models::SendView {
                id: s.id.clone(),
                name: s.name.clone(),
                text: s.text.clone(),
                notes: s.notes.clone(),
                disabled: s.disabled,
                is_file: s.send_type == vault_session::SEND_TYPE_FILE,
                file_name: s.file_name.clone(),
                file_size_name: s.file_size_name.clone(),
                has_password: s.has_password,
                max_access_count: s.max_access_count,
                access_count: s.access_count,
                expiration_date: s.expiration_date.clone(),
                deletion_date: s.deletion_date.clone(),
                hide_email: s.hide_email,
                text_hidden: s.text_hidden,
            })
            .collect();
        self.rebuild_sidebar();
        self.recompute_visible();
        self.refresh_detail_attachments();
        if self.selected_sidebar >= self.sidebar.len() {
            self.selected_sidebar = self.sidebar.len().saturating_sub(1);
        }
        if self.selected_item >= self.visible.len() {
            self.selected_item = self.visible.len().saturating_sub(1);
        }
        self.refresh_detail_attachments();
    }

    fn session_is_offline(&self) -> bool {
        self.session.as_ref().is_some_and(|s| s.is_offline())
    }

    // -------------------------------------------------------------------------
    // Sidebar / filtering
    // -------------------------------------------------------------------------

    pub fn rebuild_sidebar(&mut self) {
        let items = &self.items;
        let active =
            |pred: &dyn Fn(&DecryptedItem) -> bool| items.iter().filter(|i| pred(i)).count();

        let mut entries = vec![
            SidebarEntry {
                label: "All items".into(),
                kind: FilterKind::All,
                count: active(&|i| !i.deleted),
            },
            SidebarEntry {
                label: "My vault".into(),
                kind: FilterKind::MyVault,
                count: active(&|i| !i.deleted && i.organization_id.is_none()),
            },
            SidebarEntry {
                label: "Favorites".into(),
                kind: FilterKind::Favorites,
                count: active(&|i| i.favorite && !i.deleted),
            },
            SidebarEntry {
                label: "Logins".into(),
                kind: FilterKind::Login,
                count: active(&|i| i.item_type == ItemType::Login && !i.deleted),
            },
            SidebarEntry {
                label: "Notes".into(),
                kind: FilterKind::SecureNote,
                count: active(&|i| i.item_type == ItemType::SecureNote && !i.deleted),
            },
            SidebarEntry {
                label: "Cards".into(),
                kind: FilterKind::Card,
                count: active(&|i| i.item_type == ItemType::Card && !i.deleted),
            },
            SidebarEntry {
                label: "Identities".into(),
                kind: FilterKind::Identity,
                count: active(&|i| i.item_type == ItemType::Identity && !i.deleted),
            },
            SidebarEntry {
                label: "SSH Keys".into(),
                kind: FilterKind::SshKey,
                count: active(&|i| i.item_type == ItemType::SshKey && !i.deleted),
            },
        ];

        entries.extend(nested_folder_entries(&self.folders));

        if !self.org_labels.is_empty() {
            for (id, name) in &self.org_labels {
                let oid = id.clone();
                let count = active(&|i| i.organization_id.as_deref() == Some(oid.as_str()));
                if count > 0 {
                    entries.push(SidebarEntry {
                        label: format!("Org · {name}"),
                        kind: FilterKind::Organization(id.clone()),
                        count,
                    });
                }
            }
        }
        if let Some(session) = self.session.as_ref() {
            for col in session.collections() {
                let cid = col.id.clone();
                let count = active(&|i| i.collection_ids.iter().any(|c| c == &cid));
                if count > 0 {
                    entries.push(SidebarEntry {
                        label: format!("Col · {}", col.name),
                        kind: FilterKind::Collection(col.id.clone()),
                        count,
                    });
                }
            }
        }
        let send_count = self.sends.len();
        entries.push(SidebarEntry {
            label: "Sends".into(),
            kind: FilterKind::Sends,
            count: send_count,
        });

        let no_folder = active(&|i| !i.deleted && i.folder_id.is_none());
        entries.push(SidebarEntry {
            label: "No folder".into(),
            kind: FilterKind::NoFolder,
            count: no_folder,
        });
        entries.push(SidebarEntry {
            label: "Trash".into(),
            kind: FilterKind::Trash,
            count: active(&|i| i.deleted),
        });

        self.sidebar = entries;
        if self.selected_sidebar >= self.sidebar.len() {
            self.selected_sidebar = self.sidebar.len().saturating_sub(1);
        }
    }

    pub fn current_filter(&self) -> FilterKind {
        self.sidebar
            .get(self.selected_sidebar)
            .map(|e| e.kind.clone())
            .unwrap_or(FilterKind::All)
    }

    pub fn recompute_visible(&mut self) {
        let filter = self.current_filter();
        if matches!(filter, FilterKind::Sends) {
            self.visible_sends = (0..self.sends.len()).collect();
            self.visible.clear();
            if self.selected_item >= self.visible_sends.len() {
                self.selected_item = self.visible_sends.len().saturating_sub(1);
            }
            return;
        }
        self.visible_sends.clear();
        let matcher = SkimMatcherV2::default();
        let parsed = parse_search_query(self.search_query.trim());
        let fuzzy = parsed.free_text.trim();
        let uri_groups = self.uri_equivalent_groups();

        let mut scored: Vec<(i64, usize)> = self
            .items
            .iter()
            .enumerate()
            .filter(|(_, item)| filter.matches(item))
            .filter(|(_, item)| {
                let folder_name = self.folder_name_for_item(item.folder_id.as_deref());
                parsed.matches_item(item, folder_name.as_deref(), &uri_groups)
            })
            .filter_map(|(idx, item)| {
                if fuzzy.is_empty() {
                    return Some((0, idx));
                }
                let hay = format!(
                    "{} {} {} {}",
                    item.name,
                    item.subtitle(),
                    item.uris
                        .iter()
                        .map(|u| u.uri.as_str())
                        .collect::<Vec<_>>()
                        .join(" "),
                    item.notes.as_deref().unwrap_or("")
                );
                matcher.fuzzy_match(&hay, fuzzy).map(|score| (score, idx))
            })
            .collect();

        if !fuzzy.is_empty() {
            scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        } else {
            self.sort_unscored(&mut scored);
        }

        self.visible = scored.into_iter().map(|(_, idx)| idx).collect();
        if self.selected_item >= self.visible.len() {
            self.selected_item = self.visible.len().saturating_sub(1);
        }
    }

    pub fn selected_decrypted(&self) -> Option<&DecryptedItem> {
        self.visible
            .get(self.selected_item)
            .and_then(|&idx| self.items.get(idx))
    }

    pub fn selected_id(&self) -> Option<String> {
        self.selected_decrypted().map(|i| i.id.clone())
    }

    // -------------------------------------------------------------------------
    // Navigation
    // -------------------------------------------------------------------------

    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
        if let Some(session) = self.session.as_mut() {
            session.touch();
        }
    }

    pub fn focus_next(&mut self, detail_visible: bool, folders_visible: bool) {
        self.focus = match self.focus {
            FocusPane::Folders => FocusPane::Items,
            FocusPane::Items => {
                if detail_visible {
                    FocusPane::Detail
                } else if folders_visible {
                    FocusPane::Folders
                } else {
                    FocusPane::Items
                }
            }
            FocusPane::Detail => {
                if folders_visible {
                    FocusPane::Folders
                } else {
                    FocusPane::Items
                }
            }
        };
        self.touch();
    }

    pub fn focus_prev(&mut self, detail_visible: bool, folders_visible: bool) {
        self.focus = match self.focus {
            FocusPane::Folders => {
                if detail_visible {
                    FocusPane::Detail
                } else {
                    FocusPane::Items
                }
            }
            FocusPane::Items => {
                if folders_visible {
                    FocusPane::Folders
                } else if detail_visible {
                    FocusPane::Detail
                } else {
                    FocusPane::Items
                }
            }
            FocusPane::Detail => FocusPane::Items,
        };
        self.touch();
    }

    pub fn focus_left(&mut self, folders_visible: bool) {
        self.focus = match self.focus {
            FocusPane::Detail => FocusPane::Items,
            FocusPane::Items if folders_visible => FocusPane::Folders,
            other => other,
        };
        self.touch();
    }

    pub fn focus_right(&mut self, detail_visible: bool) {
        self.focus = match self.focus {
            FocusPane::Folders => FocusPane::Items,
            FocusPane::Items if detail_visible => FocusPane::Detail,
            other => other,
        };
        self.touch();
    }

    /// Detail pane scroll offset for the current selection.
    pub fn detail_scroll_offset(&self) -> u16 {
        match &self.detail_scroll {
            (Some(id), off) if self.selected_id().as_deref() == Some(id.as_str()) => *off,
            _ => 0,
        }
    }

    /// Scroll the detail pane; `None` jumps to the top.
    pub fn scroll_detail(&mut self, delta: Option<isize>) {
        let current = self.detail_scroll_offset() as isize;
        let max = self.detail_scroll_max.get() as isize;
        let next = match delta {
            Some(d) => (current.min(max) + d).clamp(0, max) as u16,
            None => 0,
        };
        self.detail_scroll = (self.selected_id(), next);
        self.touch();
    }

    /// Jump to the first (`false`) or last (`true`) row of the focused list.
    pub fn select_edge(&mut self, last: bool) {
        match self.focus {
            FocusPane::Folders => {
                self.selected_sidebar = if last {
                    self.sidebar.len().saturating_sub(1)
                } else {
                    0
                };
                self.selected_item = 0;
                self.recompute_visible();
            }
            FocusPane::Items | FocusPane::Detail => {
                let len = if matches!(self.current_filter(), FilterKind::Sends) {
                    self.visible_sends.len()
                } else {
                    self.visible.len()
                };
                let prev_id = self.selected_id();
                self.selected_item = if last { len.saturating_sub(1) } else { 0 };
                if self.selected_id() != prev_id {
                    self.reprompt_ok_for = None;
                    self.refresh_detail_attachments();
                }
            }
        }
        self.touch();
    }

    /// Select the sidebar row for `kind` (used by the `g` go-to keys).
    pub fn goto_filter(&mut self, kind: &FilterKind) {
        let Some(idx) = self.sidebar.iter().position(|e| &e.kind == kind) else {
            self.set_status("That view isn't available in this vault");
            return;
        };
        if idx != self.selected_sidebar {
            self.selected_sidebar = idx;
            self.selected_item = 0;
            self.recompute_visible();
            self.refresh_detail_attachments();
        }
        if self.focus == FocusPane::Folders {
            self.focus = FocusPane::Items;
        }
        self.touch();
    }

    pub fn move_selection(&mut self, delta: isize) {
        match self.focus {
            FocusPane::Folders => {
                let len = self.sidebar.len() as isize;
                if len == 0 {
                    return;
                }
                let next = (self.selected_sidebar as isize + delta).rem_euclid(len) as usize;
                self.selected_sidebar = next;
                self.selected_item = 0;
                self.recompute_visible();
            }
            FocusPane::Items | FocusPane::Detail => {
                let viewing_sends = matches!(self.current_filter(), FilterKind::Sends);
                let len = if viewing_sends {
                    self.visible_sends.len()
                } else {
                    self.visible.len()
                } as isize;
                if len == 0 {
                    return;
                }
                let prev_id = self.selected_id();
                let next = (self.selected_item as isize + delta).rem_euclid(len) as usize;
                self.selected_item = next;
                if self.selected_id() != prev_id {
                    self.reprompt_ok_for = None;
                    self.refresh_detail_attachments();
                }
            }
        }
        self.touch();
    }

    // -------------------------------------------------------------------------
    // Actions
    // -------------------------------------------------------------------------

    pub fn set_status(&mut self, msg: impl Into<String>) {
        self.status = msg.into();
        self.status_sticky = false;
        self.status_expires = Some(Instant::now() + Duration::from_secs(4));
        let toast = self.status.clone();
        self.toast_from_status(&toast);
    }

    fn set_sticky_status(&mut self, msg: impl Into<String>) {
        self.status = msg.into();
        self.status_sticky = true;
        self.status_expires = None;
    }

    fn mark_synced(&mut self) {
        if let Some(ts) = self.session.as_ref().and_then(|s| s.last_synced_at()) {
            self.last_synced_at = Some(ts.with_timezone(&Local));
        } else {
            self.last_synced_at = Some(Local::now());
        }
        self.last_auto_sync = Instant::now();
    }

    fn last_synced_status(&self) -> Option<String> {
        self.last_synced_at.map(|t| {
            let age = format_sync_age(t);
            let time = t.format("%H:%M:%S");
            if self.session_is_offline() {
                format!("Offline — synced {age} ({time})")
            } else if self.using_mock {
                format!("Synced {age} ({time}, mock)")
            } else {
                format!("Synced {age} ({time})")
            }
        })
    }

    fn vault_idle_status(&self) -> String {
        self.last_synced_status().unwrap_or_else(|| {
            if self.using_mock {
                "Mock vault — press ? for help".into()
            } else if self.session_is_offline() {
                "Offline — no sync timestamp".into()
            } else {
                "Ready".into()
            }
        })
    }

    fn show_last_synced_status(&mut self) {
        self.status = self.vault_idle_status();
        self.status_sticky = true;
        self.status_expires = None;
    }

    /// Live-update poll: only reloads the vault when the server's revision date changed.
    /// Failures are silent (the periodic full sync / manual sync report errors).
    pub async fn check_revision(&mut self) {
        if self.using_mock {
            return;
        }
        let Some(session) = self.session.as_mut() else {
            return;
        };
        if session.status() != SessionStatus::Unlocked {
            return;
        }
        match session.sync_if_changed().await {
            Ok(vault_session::SyncOutcome::Synced) => {
                self.reload_from_session();
                self.mark_synced();
                self.set_status("Vault updated from server");
            }
            Ok(vault_session::SyncOutcome::Unchanged) | Err(_) => {}
        }
    }

    pub async fn sync_vault(&mut self) {
        if self.using_mock {
            self.mark_synced();
            self.show_last_synced_status();
            self.touch();
            return;
        }
        if self.session.is_none() {
            self.set_status("Not logged in");
            return;
        }
        self.busy = true;
        self.set_status("Syncing…");
        let result = self.session.as_mut().unwrap().sync().await;
        match result {
            Ok(()) => {
                self.reload_from_session();
                self.mark_synced();
                self.show_last_synced_status();
                self.touch();
            }
            Err(e) => self.set_status(format!("Sync failed: {e}")),
        }
        self.busy = false;
    }

    pub async fn toggle_favorite(&mut self) {
        let Some(id) = self.selected_id() else {
            self.set_status("No item selected");
            return;
        };

        if self.using_mock {
            if let Some(item) = self.items.iter_mut().find(|i| i.id == id) {
                item.favorite = !item.favorite;
                let fav = item.favorite;
                let name = item.name.clone();
                self.rebuild_sidebar();
                self.recompute_visible();
                self.set_status(if fav {
                    format!("★ Favorited {name}")
                } else {
                    format!("Removed favorite {name}")
                });
            }
            self.touch();
            return;
        }

        let Some(session) = self.session.as_mut() else {
            return;
        };
        self.busy = true;
        match session.toggle_favorite(&id).await {
            Ok(()) => {
                self.reload_from_session();
                self.set_status("Favorite updated");
                self.touch();
            }
            Err(e) => self.set_status(format!("Favorite failed: {e}")),
        }
        self.busy = false;
    }

    pub fn toggle_reveal(&mut self) {
        let Some(item) = self.selected_decrypted().cloned() else {
            self.set_status("No item selected");
            return;
        };
        if self.gate_reprompt(&item, PendingRepromptAction::Reveal) {
            return;
        }
        self.toggle_reveal_inner();
    }

    fn toggle_reveal_inner(&mut self) {
        if self.reveal_secrets {
            self.reveal_secrets = false;
            self.reveal_until = None;
            self.set_status("Secrets hidden");
        } else {
            self.reveal_secrets = true;
            self.reveal_until = Some(Instant::now() + Duration::from_secs(15));
            self.set_status("Secrets revealed (15s)");
        }
        self.touch();
    }

    pub fn copy_field(&mut self, kind: ClipboardKind) {
        let Some(item) = self.selected_decrypted().cloned() else {
            self.set_status("No item selected");
            return;
        };
        if Self::copy_kind_needs_reprompt(kind)
            && self.gate_reprompt(&item, PendingRepromptAction::Copy(kind))
        {
            return;
        }
        self.copy_field_inner(kind);
    }

    fn copy_field_inner(&mut self, kind: ClipboardKind) {
        let Some(item) = self.selected_decrypted().cloned() else {
            return;
        };
        let reprompt_ok = self.reprompt_granted(&item.id);
        let label = clipboard_kind_label(kind);
        self.record_item_used(&item.id);

        // Prefer session copy APIs (reprompt-aware) when online.
        if !self.using_mock {
            if let Some(session) = self.session.as_mut() {
                let result = match kind {
                    ClipboardKind::Password => session.copy_password(&item.id, reprompt_ok),
                    ClipboardKind::Username => session.copy_username(&item.id),
                    ClipboardKind::Totp => session.copy_totp(&item.id, reprompt_ok).map(|_| ()),
                    ClipboardKind::Uri => {
                        let Some(uri) = item.primary_uri().map(str::to_string) else {
                            self.set_status("No URI on this item");
                            return;
                        };
                        session.copy_text(&uri)
                    }
                    ClipboardKind::CardNumber => item
                        .card_number
                        .as_deref()
                        .ok_or_else(|| SessionError::Other("no card number".into()))
                        .and_then(|v| session.copy_text(v)),
                    ClipboardKind::CardCode => item
                        .card_code
                        .as_deref()
                        .ok_or_else(|| SessionError::Other("no CVC".into()))
                        .and_then(|v| session.copy_text(v)),
                    ClipboardKind::CardExpiry => {
                        let exp = match (&item.card_exp_month, &item.card_exp_year) {
                            (Some(m), Some(y)) => format!("{m}/{y}"),
                            _ => {
                                self.set_status("No expiry on this card");
                                return;
                            }
                        };
                        session.copy_text(&exp)
                    }
                    ClipboardKind::SshPublic => item
                        .ssh_public_key
                        .as_deref()
                        .ok_or_else(|| SessionError::Other("no public key".into()))
                        .and_then(|v| session.copy_text(v)),
                    ClipboardKind::SshPrivate => item
                        .ssh_private_key
                        .as_deref()
                        .ok_or_else(|| SessionError::Other("no private key".into()))
                        .and_then(|v| session.copy_text(v)),
                    ClipboardKind::Notes => item
                        .notes
                        .as_deref()
                        .ok_or_else(|| SessionError::Other("no notes".into()))
                        .and_then(|v| session.copy_text(v)),
                };
                match result {
                    Ok(()) => {
                        self.clipboard_kind = Some(kind);
                        self.set_status(format!("{label} copied"));
                        self.touch();
                        return;
                    }
                    Err(SessionError::RepromptRequired) => {
                        self.open_reprompt(item.id.clone(), PendingRepromptAction::Copy(kind));
                        return;
                    }
                    Err(SessionError::Clipboard(_)) => {
                        // Fall through to OSC 52 / value-based copy.
                    }
                    Err(e) => {
                        self.set_status(format!("Copy failed: {e}"));
                        return;
                    }
                }
            }
        }

        let value = self.clipboard_value_for(&item, kind);
        let Some(value) = value.filter(|s| !s.is_empty()) else {
            self.set_status(format!("No {label} on this item"));
            return;
        };
        self.clipboard_kind = Some(kind);
        let _ = self.copy_text_with_fallback(&value, label);
    }

    fn clipboard_value_for(&self, item: &DecryptedItem, kind: ClipboardKind) -> Option<String> {
        match kind {
            ClipboardKind::Password => item.password.clone(),
            ClipboardKind::Username => item.username.clone(),
            ClipboardKind::Totp => item
                .totp
                .as_deref()
                .and_then(|s| vault_session::totp_from_secret(s).ok()),
            ClipboardKind::Uri => item.primary_uri().map(str::to_string),
            ClipboardKind::CardNumber => item.card_number.clone(),
            ClipboardKind::CardCode => item.card_code.clone(),
            ClipboardKind::CardExpiry => match (&item.card_exp_month, &item.card_exp_year) {
                (Some(m), Some(y)) => Some(format!("{m}/{y}")),
                _ => None,
            },
            ClipboardKind::SshPublic => item.ssh_public_key.clone(),
            ClipboardKind::SshPrivate => item.ssh_private_key.clone(),
            ClipboardKind::Notes => item.notes.clone(),
        }
    }

    pub fn start_search(&mut self) {
        self.searching = true;
        self.focus = FocusPane::Items;
        self.touch();
    }

    pub fn end_search(&mut self) {
        self.searching = false;
    }

    pub fn clear_search(&mut self) {
        self.searching = false;
        self.search_query.clear();
        self.recompute_visible();
        self.touch();
    }

    // -------------------------------------------------------------------------
    // Modals: create / edit / delete / folder / generator
    // -------------------------------------------------------------------------

    /// Org policy gate (personal vault disabled / restricted item types) for creating items.
    /// Sets a status message and returns false when blocked.
    fn item_creation_allowed(&mut self, ty: SessionItemType) -> bool {
        let Some(session) = self.session.as_ref() else {
            return true;
        };
        match session.check_item_creation_allowed(ty) {
            Ok(()) => true,
            Err(e) => {
                self.set_status(e.to_string());
                false
            }
        }
    }

    pub fn open_new_item_picker(&mut self) {
        if let Some(session) = self.session.as_ref() {
            if session.personal_vault_blocked_by_policy() {
                self.set_status(
                    "Organization policy: personal vault is disabled — cannot create items",
                );
                return;
            }
        }
        self.overlay = Overlay::NewItemType { selected: 0 };
        self.touch();
    }

    pub fn open_new_login(&mut self) {
        if !self.item_creation_allowed(SessionItemType::Login) {
            return;
        }
        self.overlay = Overlay::ItemForm {
            editing_id: None,
            name: String::new(),
            username: String::new(),
            password: String::new(),
            totp: String::new(),
            uris: vec![FormUriLine {
                uri: String::new(),
                match_type: 0,
            }],
            uri_line: 0,
            notes: String::new(),
            reprompt: false,
            field: EditField::Name,
        };
        self.touch();
    }

    pub fn open_new_note(&mut self) {
        if !self.item_creation_allowed(SessionItemType::SecureNote) {
            return;
        }
        self.overlay = Overlay::NoteForm {
            editing_id: None,
            name: String::new(),
            notes: String::new(),
            field: NoteField::Name,
        };
        self.touch();
    }

    pub fn open_edit_login(&mut self) {
        self.open_edit_item();
    }

    pub fn open_edit_item(&mut self) {
        let Some(item) = self.selected_decrypted().cloned() else {
            self.set_status("No item selected");
            return;
        };
        if self.gate_reprompt(&item, PendingRepromptAction::Edit) {
            return;
        }
        self.open_edit_item_inner();
    }

    fn item_editable(&self, id: &str) -> bool {
        self.session.as_ref().is_some_and(|s| s.item_editable(id))
    }

    pub fn item_editable_public(&self, id: &str) -> bool {
        self.item_editable(id)
    }

    fn open_edit_item_inner(&mut self) {
        let Some(item) = self.selected_decrypted().cloned() else {
            return;
        };
        if !self.item_editable(&item.id) {
            self.set_status("Cannot edit item (read-only or missing key)");
            return;
        }
        match item.item_type {
            ItemType::Login => {
                let uris = if item.uris.is_empty() {
                    vec![FormUriLine {
                        uri: String::new(),
                        match_type: 0,
                    }]
                } else {
                    item.uris
                        .iter()
                        .map(|u| FormUriLine {
                            uri: u.uri.clone(),
                            match_type: u.match_type.unwrap_or(0),
                        })
                        .collect()
                };
                self.overlay = Overlay::ItemForm {
                    editing_id: Some(item.id),
                    name: item.name,
                    username: item.username.unwrap_or_default(),
                    password: item.password.unwrap_or_default(),
                    totp: item.totp.unwrap_or_default(),
                    uris,
                    uri_line: 0,
                    notes: item.notes.unwrap_or_default(),
                    reprompt: item.reprompt,
                    field: EditField::Name,
                };
            }
            ItemType::SecureNote => {
                self.overlay = Overlay::NoteForm {
                    editing_id: Some(item.id),
                    name: item.name,
                    notes: item.notes.unwrap_or_default(),
                    field: NoteField::Name,
                };
            }
            ItemType::Card => {
                self.overlay = Overlay::CardForm {
                    editing_id: Some(item.id),
                    name: item.name,
                    cardholder_name: item.cardholder_name.unwrap_or_default(),
                    brand: item.card_brand.unwrap_or_default(),
                    number: item.card_number.unwrap_or_default(),
                    exp_month: item.card_exp_month.unwrap_or_default(),
                    exp_year: item.card_exp_year.unwrap_or_default(),
                    code: item.card_code.unwrap_or_default(),
                    notes: item.notes.unwrap_or_default(),
                    reprompt: item.reprompt,
                    field: CardField::Name,
                };
            }
            ItemType::Identity => {
                self.overlay = Overlay::IdentityForm {
                    editing_id: Some(item.id),
                    name: item.name,
                    title: item.identity_title.unwrap_or_default(),
                    first_name: item.identity_first_name.unwrap_or_default(),
                    middle_name: item.identity_middle_name.unwrap_or_default(),
                    last_name: item.identity_last_name.unwrap_or_default(),
                    email: item.identity_email.unwrap_or_default(),
                    phone: item.identity_phone.unwrap_or_default(),
                    username: item.identity_username.unwrap_or_default(),
                    company: item.identity_company.unwrap_or_default(),
                    address1: item.identity_address1.unwrap_or_default(),
                    address2: item.identity_address2.unwrap_or_default(),
                    address3: item.identity_address3.unwrap_or_default(),
                    city: item.identity_city.unwrap_or_default(),
                    state: item.identity_state.unwrap_or_default(),
                    postal_code: item.identity_postal_code.unwrap_or_default(),
                    country: item.identity_country.unwrap_or_default(),
                    ssn: item.identity_ssn.unwrap_or_default(),
                    passport: item.identity_passport_number.unwrap_or_default(),
                    license: item.identity_license_number.unwrap_or_default(),
                    notes: item.notes.unwrap_or_default(),
                    reprompt: item.reprompt,
                    field: IdentityField::Name,
                };
            }
            ItemType::SshKey => {
                self.overlay = Overlay::SshKeyForm {
                    editing_id: Some(item.id),
                    name: item.name,
                    private_key: item.ssh_private_key.unwrap_or_default(),
                    public_key: item.ssh_public_key.unwrap_or_default(),
                    fingerprint: item.ssh_fingerprint.unwrap_or_default(),
                    notes: item.notes.unwrap_or_default(),
                    field: SshKeyField::Name,
                };
            }
            ItemType::Unknown => {
                self.set_status("Cannot edit this item type");
                return;
            }
        }
        self.touch();
    }

    pub fn open_move_to_folder(&mut self) {
        let Some(item) = self.selected_decrypted().cloned() else {
            self.set_status("No item selected");
            return;
        };
        let selected = item
            .folder_id
            .as_ref()
            .and_then(|fid| {
                self.folders
                    .iter()
                    .position(|f| f.id.as_deref() == Some(fid.as_str()))
                    .map(|i| i + 1)
            })
            .unwrap_or(0);
        self.overlay = Overlay::MoveToFolder {
            item_id: item.id,
            selected,
        };
        self.touch();
    }

    pub async fn confirm_move_to_folder(&mut self) {
        let Overlay::MoveToFolder { item_id, selected } = &self.overlay else {
            return;
        };
        let item_id = item_id.clone();
        let folder_id = if *selected == 0 {
            None
        } else {
            self.folders.get(*selected - 1).and_then(|f| f.id.clone())
        };
        if self.using_mock {
            if let Some(item) = self.items.iter_mut().find(|i| i.id == item_id) {
                item.folder_id = folder_id;
            }
            self.folders = with_folder_counts(self.folders.clone(), &self.items);
            self.rebuild_sidebar();
            self.recompute_visible();
            self.close_overlay();
            self.set_status("Moved (mock)");
            self.touch();
            return;
        }
        if self.session_is_offline() {
            self.set_status("Offline — move requires network");
            return;
        }
        let Some(session) = self.session.as_mut() else {
            self.set_status("Not logged in");
            return;
        };
        self.busy = true;
        match session.move_to_folder(&item_id, folder_id).await {
            Ok(()) => {
                self.reload_from_session();
                self.close_overlay();
                self.set_status("Moved to folder");
                self.touch();
            }
            Err(e) => self.set_status(format!("Move failed: {e}")),
        }
        self.busy = false;
    }

    pub fn toggle_bulk_select_current(&mut self) {
        if !matches!(self.focus, FocusPane::Items | FocusPane::Detail) {
            return;
        }
        if matches!(self.current_filter(), FilterKind::Sends | FilterKind::Trash) {
            return;
        }
        let Some(item) = self.selected_decrypted().cloned() else {
            return;
        };
        if item.deleted {
            return;
        }
        if item.organization_id.is_some() {
            self.set_status("Only personal items can be marked for share");
            return;
        }
        if self.selected_ids.contains(&item.id) {
            self.selected_ids.remove(&item.id);
            self.set_status(format!("Unmarked \"{}\"", item.name));
        } else {
            self.selected_ids.insert(item.id);
            self.set_status(format!("Marked \"{}\" (Space toggles)", item.name));
        }
        self.touch();
    }

    fn share_wizard_item_ids(&self) -> Option<Vec<String>> {
        let raw: Vec<String> = if self.selected_ids.is_empty() {
            self.selected_decrypted().map(|i| vec![i.id.clone()])?
        } else {
            self.selected_ids.iter().cloned().collect()
        };
        let ids: Vec<String> = raw
            .into_iter()
            .filter(|id| {
                self.items
                    .iter()
                    .any(|i| i.id == *id && !i.deleted && i.organization_id.is_none())
            })
            .collect();
        if ids.is_empty() {
            None
        } else {
            Some(ids)
        }
    }

    /// Writable collections for the share wizard org step (id, name).
    pub fn share_writable_collections(&self, org_index: usize) -> Vec<(String, String)> {
        let Overlay::ShareToOrg { groups, .. } = &self.overlay else {
            return Vec::new();
        };
        writable_share_collections(groups, org_index)
    }
}

pub fn writable_share_collections(
    groups: &[OrgCollectionGroup],
    org_index: usize,
) -> Vec<(String, String)> {
    groups
        .get(org_index)
        .map(|g| {
            g.collections
                .iter()
                .filter(|c| c.writable())
                .map(|c| (c.id.clone(), c.name.clone()))
                .collect()
        })
        .unwrap_or_default()
}

impl App {
    pub fn open_share_to_org(&mut self) {
        if matches!(self.current_filter(), FilterKind::Sends | FilterKind::Trash) {
            self.set_status("Share is not available in this view");
            return;
        }
        let Some(item_ids) = self.share_wizard_item_ids() else {
            self.set_status("Select personal item(s) to share");
            return;
        };
        let groups = if self.using_mock {
            crate::mock::sample_share_targets()
        } else if let Some(session) = self.session.as_ref() {
            session.share_targets()
        } else {
            self.set_status("Not logged in");
            return;
        };
        if groups.is_empty() {
            self.set_status("No organizations with writable collections");
            return;
        }
        self.overlay = Overlay::ShareToOrg {
            item_ids,
            groups,
            org_index: 0,
            step: ShareToOrgStep::PickOrganization,
            collection_cursor: 0,
            selected_collections: HashSet::new(),
        };
        self.touch();
    }

    pub async fn execute_share_to_org(&mut self) {
        let Overlay::ShareToOrg {
            item_ids,
            groups,
            org_index,
            selected_collections,
            ..
        } = &self.overlay
        else {
            return;
        };
        if selected_collections.is_empty() {
            self.set_status("Select at least one collection (Space toggles)");
            return;
        }
        let org_id = groups[*org_index].organization_id.clone();
        let cols: Vec<String> = selected_collections.iter().cloned().collect();
        let ids = item_ids.clone();
        let n = ids.len();

        if self.using_mock {
            for id in &ids {
                if let Some(item) = self.items.iter_mut().find(|i| i.id == *id) {
                    item.organization_id = Some(org_id.clone());
                }
            }
            self.org_labels
                .insert(org_id, groups[*org_index].organization_name.clone());
            self.selected_ids.clear();
            self.close_overlay();
            self.rebuild_sidebar();
            self.recompute_visible();
            self.set_status(format!("Shared {n} item(s) to org (mock)"));
            self.touch();
            return;
        }
        if self.session_is_offline() {
            self.set_status("Offline — share requires network");
            return;
        }
        let Some(session) = self.session.as_mut() else {
            self.set_status("Not logged in");
            return;
        };
        self.busy = true;
        let result = if n == 1 {
            session.share_item(&ids[0], &org_id, &cols).await.map(|_| n)
        } else {
            session.bulk_share_to_org(&ids, &org_id, &cols).await
        };
        match result {
            Ok(count) => {
                self.reload_from_session();
                self.selected_ids.clear();
                self.close_overlay();
                self.set_status(format!("Shared {count} item(s)"));
                self.touch();
            }
            Err(e) => self.set_status(format!("Share failed: {e}")),
        }
        self.busy = false;
    }

    pub fn open_new_identity(&mut self) {
        if !self.item_creation_allowed(SessionItemType::Identity) {
            return;
        }
        self.overlay = Overlay::IdentityForm {
            editing_id: None,
            name: String::new(),
            title: String::new(),
            first_name: String::new(),
            middle_name: String::new(),
            last_name: String::new(),
            email: String::new(),
            phone: String::new(),
            username: String::new(),
            company: String::new(),
            address1: String::new(),
            address2: String::new(),
            address3: String::new(),
            city: String::new(),
            state: String::new(),
            postal_code: String::new(),
            country: String::new(),
            ssn: String::new(),
            passport: String::new(),
            license: String::new(),
            notes: String::new(),
            reprompt: false,
            field: IdentityField::Name,
        };
        self.touch();
    }

    pub fn open_new_ssh_key(&mut self) {
        if !self.item_creation_allowed(SessionItemType::SshKey) {
            return;
        }
        self.overlay = Overlay::SshKeyForm {
            editing_id: None,
            name: String::new(),
            private_key: String::new(),
            public_key: String::new(),
            fingerprint: String::new(),
            notes: String::new(),
            field: SshKeyField::Name,
        };
        self.touch();
    }

    pub fn open_new_card(&mut self) {
        if !self.item_creation_allowed(SessionItemType::Card) {
            return;
        }
        self.overlay = Overlay::CardForm {
            editing_id: None,
            name: String::new(),
            cardholder_name: String::new(),
            brand: String::new(),
            number: String::new(),
            exp_month: String::new(),
            exp_year: String::new(),
            code: String::new(),
            notes: String::new(),
            reprompt: false,
            field: CardField::Name,
        };
        self.touch();
    }

    pub fn open_delete_confirm(&mut self) {
        if !self.selected_ids.is_empty()
            && self.focus != FocusPane::Folders
            && !matches!(self.current_filter(), FilterKind::Sends | FilterKind::Trash)
        {
            let ids: Vec<String> = self.selected_ids.iter().cloned().collect();
            let count = ids.len();
            self.overlay = Overlay::ConfirmDelete {
                target: DeleteTarget::BulkItems { ids, count },
            };
            self.touch();
            return;
        }
        let Some(item) = self.selected_decrypted() else {
            self.set_status("No item selected");
            return;
        };
        self.overlay = Overlay::ConfirmDelete {
            target: DeleteTarget::Item {
                id: item.id.clone(),
                name: item.name.clone(),
                permanent: item.deleted,
            },
        };
        self.touch();
    }

    pub fn open_empty_trash_confirm(&mut self) {
        let count = self.items.iter().filter(|i| i.deleted).count();
        if count == 0 {
            self.set_status("Trash is empty");
            return;
        }
        self.overlay = Overlay::ConfirmDelete {
            target: DeleteTarget::EmptyTrash { count },
        };
        self.touch();
    }

    pub async fn undo_delete(&mut self) {
        let Some(pending) = self.pending_undo.take() else {
            self.set_status("Nothing to undo");
            return;
        };
        if Instant::now() > pending.expires_at {
            self.set_status("Undo window expired");
            return;
        }
        if self.using_mock {
            if let Some(i) = self.items.iter_mut().find(|i| i.id == pending.item_id) {
                i.deleted = false;
            }
            self.rebuild_sidebar();
            self.recompute_visible();
            self.set_status(format!("Restored \"{}\"", pending.item_name));
            self.touch();
            return;
        }
        let Some(session) = self.session.as_mut() else {
            return;
        };
        match session.restore(&pending.item_id).await {
            Ok(()) => {
                self.reload_from_session();
                self.set_status(format!("Restored \"{}\"", pending.item_name));
                self.touch();
            }
            Err(e) => self.set_status(format!("Undo failed: {e}")),
        }
    }

    pub fn open_delete_folder_confirm(&mut self) {
        let folder_id = match self.current_filter() {
            FilterKind::Folder(id) => id,
            _ => {
                self.set_status("Select a folder to delete");
                return;
            }
        };
        let name = self
            .folders
            .iter()
            .find(|f| f.id.as_deref() == Some(folder_id.as_str()))
            .map(|f| f.name.clone())
            .unwrap_or_else(|| folder_id.clone());
        self.overlay = Overlay::ConfirmDelete {
            target: DeleteTarget::Folder {
                id: folder_id,
                name,
            },
        };
        self.touch();
    }

    pub fn open_rename_folder_form(&mut self) {
        let folder_id = match self.current_filter() {
            FilterKind::Folder(id) => id,
            _ => {
                self.set_status("Select a folder to rename");
                return;
            }
        };
        let name = self
            .folders
            .iter()
            .find(|f| f.id.as_deref() == Some(folder_id.as_str()))
            .map(|f| f.name.clone())
            .unwrap_or_default();
        self.overlay = Overlay::FolderForm {
            folder_id: Some(folder_id),
            name,
        };
        self.touch();
    }

    pub fn in_trash(&self) -> bool {
        matches!(self.current_filter(), FilterKind::Trash)
    }

    pub async fn restore_selected(&mut self) {
        let Some(item) = self.selected_decrypted().cloned() else {
            self.set_status("No item selected");
            return;
        };
        if !item.deleted {
            self.set_status("Item is not in trash");
            return;
        }
        if self.using_mock {
            if let Some(i) = self.items.iter_mut().find(|i| i.id == item.id) {
                i.deleted = false;
            }
            self.rebuild_sidebar();
            self.recompute_visible();
            self.set_status("Restored (mock)");
            self.touch();
            return;
        }
        let Some(session) = self.session.as_mut() else {
            return;
        };
        self.busy = true;
        match session.restore(&item.id).await {
            Ok(()) => {
                self.reload_from_session();
                self.set_status("Restored from trash");
                self.touch();
            }
            Err(e) => self.set_status(format!("Restore failed: {e}")),
        }
        self.busy = false;
    }

    pub fn open_folder_form(&mut self) {
        self.overlay = Overlay::FolderForm {
            folder_id: None,
            name: String::new(),
        };
        self.touch();
    }

    fn org_generator_policy(&self) -> vault_session::GeneratorPolicy {
        self.session
            .as_ref()
            .map(|s| s.generator_policy())
            .unwrap_or_default()
    }

    fn uri_equivalent_groups(&self) -> Vec<Vec<String>> {
        self.session
            .as_ref()
            .map(|s| s.uri_equivalent_groups())
            .unwrap_or_default()
    }

    pub fn open_generator(&mut self, insert_to_form: bool) {
        if insert_to_form && matches!(self.overlay, Overlay::ItemForm { .. }) {
            self.item_form_backup = Some(std::mem::replace(&mut self.overlay, Overlay::None));
        }
        let gen_cfg = &self.config.generator;
        self.overlay = Overlay::Generator {
            mode: GeneratorMode::Password,
            username_kind: UsernameKind::Word,
            length: gen_cfg.length,
            uppercase: gen_cfg.uppercase,
            lowercase: gen_cfg.lowercase,
            digits: gen_cfg.digits,
            symbols: gen_cfg.symbols,
            avoid_ambiguous: gen_cfg.avoid_ambiguous,
            min_numbers: 1,
            min_special: 1,
            passphrase_words: gen_cfg.passphrase_words,
            passphrase_separator: "-".into(),
            passphrase_capitalize: false,
            passphrase_include_number: false,
            preview: String::new(),
            insert_to_form,
        };
        self.regenerate_password();
        self.touch();
    }

    pub fn regenerate_password(&mut self) {
        let policy = self.org_generator_policy();
        let Overlay::Generator {
            mode,
            username_kind,
            length,
            uppercase,
            lowercase,
            digits,
            symbols,
            avoid_ambiguous,
            min_numbers,
            min_special,
            passphrase_words,
            passphrase_separator,
            passphrase_capitalize,
            passphrase_include_number,
            preview,
            ..
        } = &mut self.overlay
        else {
            return;
        };

        *preview = match mode {
            GeneratorMode::Passphrase => generate_passphrase_opts(
                PassphraseOptions {
                    words: *passphrase_words,
                    capitalize: *passphrase_capitalize,
                    include_number: *passphrase_include_number,
                },
                passphrase_separator,
            ),
            GeneratorMode::Username => {
                let email = self
                    .session
                    .as_ref()
                    .and_then(|s| s.email().map(str::to_string))
                    .or_else(|| {
                        if let Some(Overlay::ItemForm { username, .. }) =
                            self.item_form_backup.as_ref()
                        {
                            username.contains('@').then(|| username.clone())
                        } else {
                            None
                        }
                    });
                match username_kind {
                    UsernameKind::Word => generate_username_word(),
                    UsernameKind::Plus => email
                        .as_ref()
                        .and_then(|e| generate_username_plus_address(e).ok())
                        .unwrap_or_else(generate_username_word),
                    UsernameKind::Catchall => email
                        .as_ref()
                        .and_then(|e| e.split('@').nth(1))
                        .and_then(|d| generate_username_catchall(d).ok())
                        .unwrap_or_else(generate_username_word),
                    // Aliases are created on demand (`r`), never on mode/kind switches.
                    UsernameKind::SimpleLogin | UsernameKind::AddyIo => {
                        "(press r to create an alias)".to_string()
                    }
                }
            }
            GeneratorMode::Password => {
                let mut opts = GeneratorOptions {
                    length: *length,
                    uppercase: *uppercase,
                    lowercase: *lowercase,
                    digits: *digits,
                    symbols: *symbols,
                    avoid_ambiguous: *avoid_ambiguous,
                    min_numbers: *min_numbers,
                    min_special: *min_special,
                };
                apply_generator_policy(&mut opts, &policy);
                *length = opts.length;
                *uppercase = opts.uppercase;
                *lowercase = opts.lowercase;
                *digits = opts.digits;
                *symbols = opts.symbols;
                *min_numbers = opts.min_numbers;
                *min_special = opts.min_special;
                generate_password_checked(opts).unwrap_or_else(|_| String::new())
            }
        };
        self.touch();
    }

    pub fn clamp_generator_overlay(&mut self) {
        if !matches!(self.overlay, Overlay::Generator { .. }) {
            return;
        }
        self.regenerate_password();
    }

    pub fn close_overlay(&mut self) {
        if let Overlay::ItemForm { password, .. } = &mut self.overlay {
            password.zeroize();
        }
        if let Overlay::SshKeyForm { private_key, .. } = &mut self.overlay {
            private_key.zeroize();
        }
        if let Overlay::Reprompt { password, .. } = &mut self.overlay {
            password.zeroize();
        }
        if let Overlay::PinSetup { pin, confirm, .. } = &mut self.overlay {
            pin.zeroize();
            confirm.zeroize();
        }
        if let Overlay::ChangeMasterPassword {
            old, new, confirm, ..
        } = &mut self.overlay
        {
            old.zeroize();
            new.zeroize();
            confirm.zeroize();
        }
        if let Overlay::Generator {
            preview,
            insert_to_form,
            ..
        } = &mut self.overlay
        {
            preview.zeroize();
            if *insert_to_form {
                if let Some(form) = self.item_form_backup.take() {
                    self.overlay = form;
                    return;
                }
            }
        }
        self.overlay = Overlay::None;
        self.item_form_backup = None;
    }

    pub async fn save_item_form(&mut self) {
        let Overlay::ItemForm {
            editing_id,
            name,
            username,
            password,
            totp,
            uris,
            notes,
            reprompt,
            ..
        } = &self.overlay
        else {
            return;
        };

        if name.trim().is_empty() {
            self.set_status("Name is required");
            return;
        }

        use vault_session::DecryptedUri;
        let draft_uris: Vec<DecryptedUri> = uris
            .iter()
            .filter(|u| !u.uri.trim().is_empty())
            .map(|u| DecryptedUri {
                uri: u.uri.trim().to_string(),
                match_type: Some(u.match_type),
            })
            .collect();

        let draft = LoginDraft {
            name: name.trim().to_string(),
            username: nonempty(username),
            password: nonempty(password),
            totp: nonempty(totp),
            uris: draft_uris.clone(),
            notes: nonempty(notes),
            folder_id: None,
            favorite: false,
            reprompt: *reprompt,
        };
        let editing_id = editing_id.clone();

        if self.using_mock {
            if let Some(id) = editing_id {
                if let Some(item) = self.items.iter_mut().find(|i| i.id == id) {
                    item.name = draft.name.clone();
                    item.username = draft.username.clone();
                    item.password = draft.password.clone();
                    item.totp = draft.totp.clone();
                    item.uris = draft_uris;
                    item.notes = draft.notes.clone();
                    item.reprompt = draft.reprompt;
                }
                self.set_status("Login updated (mock)");
            } else {
                let id = format!("mock-{}", self.items.len() + 1);
                let mut item = crate::mock::sample_items()
                    .into_iter()
                    .next()
                    .expect("mock samples");
                item.id = id;
                item.name = draft.name.clone();
                item.item_type = ItemType::Login;
                item.folder_id = None;
                item.favorite = false;
                item.deleted = false;
                item.username = draft.username.clone();
                item.password = draft.password.clone();
                item.totp = draft.totp.clone();
                item.uris = draft_uris;
                item.notes = draft.notes.clone();
                item.reprompt = draft.reprompt;
                self.items.push(item);
                self.set_status("Login created (mock)");
            }
            self.folders = with_folder_counts(self.folders.clone(), &self.items);
            self.rebuild_sidebar();
            self.recompute_visible();
            self.close_overlay();
            self.touch();
            return;
        }

        if self.session_is_offline() {
            self.set_status("Offline — save requires network");
            return;
        }

        let Some(session) = self.session.as_mut() else {
            self.set_status("Not logged in");
            return;
        };

        self.busy = true;
        let result = if let Some(id) = editing_id {
            session
                .update_login(&id, &draft)
                .await
                .map(|_| "Login updated".to_string())
        } else {
            session
                .create_login(&draft)
                .await
                .map(|_| "Login created".to_string())
        };
        match result {
            Ok(msg) => {
                self.reload_from_session();
                self.close_overlay();
                self.set_status(msg);
                self.touch();
            }
            Err(e) => self.set_status(format!("Save failed: {e}")),
        }
        self.busy = false;
    }

    pub async fn confirm_delete(&mut self) {
        let Overlay::ConfirmDelete { target } = &self.overlay else {
            return;
        };
        let target = target.clone();

        match target {
            DeleteTarget::Folder { id, .. } => {
                if self.using_mock {
                    self.folders
                        .retain(|f| f.id.as_deref() != Some(id.as_str()));
                    for item in &mut self.items {
                        if item.folder_id.as_deref() == Some(id.as_str()) {
                            item.folder_id = None;
                        }
                    }
                    self.folders = with_folder_counts(self.folders.clone(), &self.items);
                    self.rebuild_sidebar();
                    self.recompute_visible();
                    self.close_overlay();
                    self.set_status("Folder deleted (mock)");
                    self.touch();
                    return;
                }
                let Some(session) = self.session.as_mut() else {
                    return;
                };
                self.busy = true;
                match session.delete_folder(&id).await {
                    Ok(()) => {
                        self.reload_from_session();
                        self.close_overlay();
                        self.set_status("Folder deleted");
                        self.touch();
                    }
                    Err(e) => self.set_status(format!("Folder delete failed: {e}")),
                }
                self.busy = false;
            }
            DeleteTarget::Item {
                id,
                name,
                permanent,
            } => {
                if self.using_mock {
                    if permanent {
                        self.items.retain(|i| i.id != id);
                        self.set_status("Permanently deleted (mock)");
                    } else if let Some(item) = self.items.iter_mut().find(|i| i.id == id) {
                        item.deleted = true;
                        self.pending_undo = Some(PendingUndoDelete {
                            item_id: id.clone(),
                            item_name: name.clone(),
                            expires_at: Instant::now() + Duration::from_secs(8),
                        });
                        let undo = self.keymap.label(crate::action::Action::UndoDelete);
                        self.set_status(format!("Deleted \"{name}\" — press {undo} to undo"));
                    }
                    self.rebuild_sidebar();
                    self.recompute_visible();
                    self.close_overlay();
                    self.touch();
                    return;
                }

                let Some(session) = self.session.as_mut() else {
                    return;
                };
                self.busy = true;
                let result = if permanent {
                    session.hard_delete(&id).await
                } else {
                    session.soft_delete(&id).await
                };
                match result {
                    Ok(()) => {
                        self.reload_from_session();
                        self.close_overlay();
                        if permanent {
                            self.set_status("Permanently deleted");
                        } else {
                            self.pending_undo = Some(PendingUndoDelete {
                                item_id: id,
                                item_name: name.clone(),
                                expires_at: Instant::now() + Duration::from_secs(8),
                            });
                            let undo = self.keymap.label(crate::action::Action::UndoDelete);
                            self.set_status(format!("Deleted \"{name}\" — press {undo} to undo"));
                        }
                        self.touch();
                    }
                    Err(e) => self.set_status(format!("Delete failed: {e}")),
                }
                self.busy = false;
            }
            DeleteTarget::BulkItems { ids, count } => {
                if self.using_mock {
                    for id in &ids {
                        if let Some(item) = self.items.iter_mut().find(|i| i.id == *id) {
                            item.deleted = true;
                        }
                    }
                    self.selected_ids.clear();
                    self.rebuild_sidebar();
                    self.recompute_visible();
                    self.close_overlay();
                    self.set_status(format!("Deleted {count} item(s) (mock)"));
                    self.touch();
                    return;
                }
                let Some(session) = self.session.as_mut() else {
                    return;
                };
                self.busy = true;
                match session.bulk_soft_delete(&ids).await {
                    Ok(n) => {
                        self.reload_from_session();
                        self.selected_ids.clear();
                        self.close_overlay();
                        self.set_status(format!("Deleted {n} item(s)"));
                        self.touch();
                    }
                    Err(e) => self.set_status(format!("Bulk delete failed: {e}")),
                }
                self.busy = false;
            }
            DeleteTarget::EmptyTrash { .. } => {
                let ids: Vec<String> = self
                    .items
                    .iter()
                    .filter(|i| i.deleted)
                    .map(|i| i.id.clone())
                    .collect();
                if ids.is_empty() {
                    self.close_overlay();
                    self.set_status("Trash is empty");
                    return;
                }
                if self.using_mock {
                    self.items.retain(|i| !i.deleted);
                    self.rebuild_sidebar();
                    self.recompute_visible();
                    self.close_overlay();
                    self.set_status(format!("Emptied trash ({} items, mock)", ids.len()));
                    self.touch();
                    return;
                }
                let Some(session) = self.session.as_mut() else {
                    return;
                };
                self.busy = true;
                let mut failed = 0usize;
                for id in &ids {
                    if session.hard_delete(id).await.is_err() {
                        failed += 1;
                    }
                }
                self.reload_from_session();
                self.close_overlay();
                if failed == 0 {
                    self.set_status(format!("Emptied trash ({} items)", ids.len()));
                } else {
                    self.set_status(format!("Emptied trash with {failed} error(s)"));
                }
                self.touch();
                self.busy = false;
            }
            DeleteTarget::Send { id, .. } => {
                let Some(session) = self.session.as_mut() else {
                    return;
                };
                self.busy = true;
                match session.delete_send(&id).await {
                    Ok(()) => {
                        self.reload_from_session();
                        self.close_overlay();
                        self.set_status("Send deleted");
                        self.touch();
                    }
                    Err(e) => self.set_status(format!("Send delete failed: {e}")),
                }
                self.busy = false;
            }
            DeleteTarget::Attachment {
                cipher_id,
                attachment_id,
                ..
            } => {
                let Some(session) = self.session.as_mut() else {
                    return;
                };
                self.busy = true;
                match session.delete_attachment(&cipher_id, &attachment_id).await {
                    Ok(()) => {
                        self.reload_from_session();
                        self.close_overlay();
                        self.set_status("Attachment deleted");
                        self.touch();
                    }
                    Err(e) => self.set_status(format!("Attachment delete failed: {e}")),
                }
                self.busy = false;
            }
        }
    }

    pub async fn save_folder_form(&mut self) {
        let Overlay::FolderForm { folder_id, name } = &self.overlay else {
            return;
        };
        let name = name.trim().to_string();
        if name.is_empty() {
            self.set_status("Folder name is required");
            return;
        }
        let folder_id = folder_id.clone();

        if self.using_mock {
            if let Some(id) = folder_id {
                if let Some(f) = self
                    .folders
                    .iter_mut()
                    .find(|f| f.id.as_deref() == Some(id.as_str()))
                {
                    f.name = name;
                }
                self.close_overlay();
                self.set_status("Folder renamed (mock)");
            } else {
                let id = format!("folder-{}", self.folders.len() + 1);
                self.folders.push(FolderView {
                    id: Some(id),
                    name,
                    count: 0,
                });
                self.rebuild_sidebar();
                self.close_overlay();
                self.set_status("Folder created (mock)");
            }
            self.touch();
            return;
        }

        let Some(session) = self.session.as_mut() else {
            return;
        };
        self.busy = true;
        let result = if let Some(id) = folder_id {
            session
                .rename_folder(&id, &name)
                .await
                .map(|_| "Folder renamed")
        } else {
            session.create_folder(&name).await.map(|_| "Folder created")
        };
        match result {
            Ok(msg) => {
                self.reload_from_session();
                self.close_overlay();
                self.set_status(msg);
                self.touch();
            }
            Err(e) => self.set_status(format!("Folder save failed: {e}")),
        }
        self.busy = false;
    }

    pub async fn save_note_form(&mut self) {
        let Overlay::NoteForm {
            editing_id,
            name,
            notes,
            ..
        } = &self.overlay
        else {
            return;
        };
        if name.trim().is_empty() {
            self.set_status("Name is required");
            return;
        }
        let draft = NoteDraft {
            name: name.trim().to_string(),
            notes: nonempty(notes),
            folder_id: None,
            favorite: false,
        };
        let editing_id = editing_id.clone();

        if self.using_mock {
            if let Some(id) = editing_id.clone() {
                if let Some(item) = self.items.iter_mut().find(|i| i.id == id) {
                    item.name = draft.name.clone();
                    item.notes = draft.notes.clone();
                }
                self.set_status("Note updated (mock)");
            } else {
                let id = format!("mock-note-{}", self.items.len() + 1);
                self.items.push(DecryptedItem {
                    id,
                    name: draft.name.clone(),
                    item_type: ItemType::SecureNote,
                    notes: draft.notes.clone(),
                    ..mock_item_shell()
                });
                self.set_status("Note created (mock)");
            }
            self.folders = with_folder_counts(self.folders.clone(), &self.items);
            self.rebuild_sidebar();
            self.recompute_visible();
            self.close_overlay();
            self.touch();
            return;
        }

        if self.session_is_offline() {
            self.set_status("Offline — save requires network");
            return;
        }

        let Some(session) = self.session.as_mut() else {
            self.set_status("Not logged in");
            return;
        };
        self.busy = true;
        let result = if let Some(id) = editing_id {
            session
                .update_note(&id, &draft)
                .await
                .map(|_| "Note updated".to_string())
        } else {
            session
                .create_note(&draft)
                .await
                .map(|_| "Note created".to_string())
        };
        match result {
            Ok(msg) => {
                self.reload_from_session();
                self.close_overlay();
                self.set_status(msg);
                self.touch();
            }
            Err(e) => self.set_status(format!("Save failed: {e}")),
        }
        self.busy = false;
    }

    pub fn apply_generator(&mut self) {
        let (preview, insert, mode) = match &self.overlay {
            Overlay::Generator {
                preview,
                insert_to_form,
                mode,
                ..
            } => (preview.clone(), *insert_to_form, *mode),
            _ => return,
        };

        if self.using_mock {
            if let Some(mut prev) = self.clipboard_demo.take() {
                prev.zeroize();
            }
            self.clipboard_demo = Some(preview.clone());
            self.clipboard_clear_at = Some(Instant::now() + self.demo_clipboard_duration());
        } else if let Some(session) = self.session.as_mut() {
            let _ = session.clipboard.copy_secret(&preview);
        }

        if insert {
            if let Some(mut form) = self.item_form_backup.take() {
                if let Overlay::ItemForm {
                    password,
                    username,
                    field,
                    ..
                } = &mut form
                {
                    if mode == GeneratorMode::Username {
                        *username = preview;
                        *field = EditField::Username;
                        self.set_status("Username inserted into form");
                    } else {
                        *password = preview;
                        *field = EditField::Password;
                        self.set_status("Password inserted into form");
                    }
                }
                self.overlay = form;
            } else {
                self.close_overlay();
                self.set_status("Generated value copied");
            }
        } else {
            self.close_overlay();
            self.set_status("Generated value copied");
        }
        self.touch();
    }

    // -------------------------------------------------------------------------
    // Tick
    // -------------------------------------------------------------------------

    pub fn on_tick(&mut self) {
        let now = Instant::now();
        self.auth_ext_tick();

        if let Some(session) = self.session.as_mut() {
            match session.tick() {
                Some(TimeoutAction::Lock) => {
                    self.lock();
                    self.set_sticky_status("Auto-locked after idle");
                }
                Some(TimeoutAction::Logout) => {
                    self.finish_forced_logout("Logged out after idle timeout");
                }
                None => {}
            }
        }

        for session in self.background_sessions.values_mut() {
            session.tick();
        }
        // Background sessions that timed out with "log out" are gone for good.
        self.background_sessions
            .retain(|_, s| s.status() != SessionStatus::LoggedOut);

        self.poll_system_lock();

        self.background_mocks
            .retain(|_, parked| Self::mock_parked_still_open(parked));

        if let Some(exp) = self.status_expires {
            if now >= exp && !self.status_sticky && !self.busy {
                self.status = match self.screen {
                    Screen::Vault => self.vault_idle_status(),
                    Screen::Login => "Enter credentials to continue".into(),
                    Screen::TwoFactor => "Enter your two-factor code".into(),
                    Screen::AuthWait => "Waiting for approval…".into(),
                    Screen::Unlock => "Enter master password to unlock".into(),
                };
                self.status_sticky = self.screen == Screen::Vault;
                self.status_expires = None;
            }
        }

        if let Some(until) = self.reveal_until {
            if now >= until {
                self.reveal_secrets = false;
                self.reveal_until = None;
            }
        }

        if let Some(clear_at) = self.clipboard_clear_at {
            if now >= clear_at {
                if let Some(mut s) = self.clipboard_demo.take() {
                    s.zeroize();
                }
                self.clipboard_clear_at = None;
                self.clipboard_kind = None;
                self.set_status("Clipboard cleared");
            }
        }

        if self.using_mock && self.screen == Screen::Vault {
            if let Some(mins) = self.auto_lock_minutes {
                let timeout = Duration::from_secs(mins.saturating_mul(60));
                if now.duration_since(self.last_activity) >= timeout {
                    self.lock();
                    self.set_sticky_status(format!("Auto-locked after {mins}m idle"));
                }
            }
        }

        if self.screen == Screen::Vault
            && !self.busy
            && self.pending.is_none()
            && !self.using_mock
            && self
                .session
                .as_ref()
                .is_some_and(|s| s.status() == SessionStatus::Unlocked)
        {
            if let Some(mins) = self.config.sync.background_interval_minutes {
                if mins > 0 {
                    let every = Duration::from_secs(mins.saturating_mul(60));
                    if now.duration_since(self.last_auto_sync) >= every {
                        self.last_auto_sync = now;
                        self.last_revision_check = now;
                        self.queue(PendingAction::BackgroundSync);
                    }
                }
            }
            if let Some(secs) = self.config.sync.revision_poll_seconds {
                if secs > 0
                    && self.pending.is_none()
                    && matches!(self.overlay, Overlay::None)
                    && now.duration_since(self.last_revision_check)
                        >= Duration::from_secs(secs.max(10))
                {
                    self.last_revision_check = now;
                    self.queue(PendingAction::RevisionCheck);
                }
            }
        }
    }

    /// Reset UI after the session logged itself out (timeout / system lock).
    fn finish_forced_logout(&mut self, reason: &str) {
        // Session already cleared tokens + persisted auth in `logout()`.
        self.sign_out_current_profile();
        self.set_sticky_status(reason);
    }

    /// Start the system sleep / screen-lock watcher once any profile asks for it, and
    /// apply the timeout action when it fires.
    fn poll_system_lock(&mut self) {
        if self.using_mock {
            return;
        }
        let wanted = self.profiles.profiles.iter().any(|p| p.lock_on_system_lock);
        if !wanted {
            // Stop the helper when no profile needs it any more.
            self.system_lock = None;
            self.system_lock_probed = false;
            return;
        }
        if !self.system_lock_probed {
            self.system_lock_probed = true;
            self.system_lock = SystemLockMonitor::start();
        }
        let Some(event) = self.system_lock.as_ref().and_then(|m| m.poll()) else {
            return;
        };
        self.handle_system_lock(event);
    }

    /// Apply the timeout action to every profile with "lock on system lock" enabled.
    pub fn handle_system_lock(&mut self, event: SystemLockEvent) {
        let reason = match event {
            SystemLockEvent::ScreenLocked => "Locked: screen locked",
            SystemLockEvent::Sleep => "Locked: system sleep",
        };

        // Background (parked) sessions.
        let ids: Vec<String> = self.background_sessions.keys().cloned().collect();
        for id in ids {
            let enabled = self
                .profiles
                .get(&id)
                .is_some_and(|p| p.lock_on_system_lock);
            if !enabled {
                continue;
            }
            if let Some(session) = self.background_sessions.get_mut(&id) {
                if session.status() == SessionStatus::Unlocked {
                    session.apply_timeout_action();
                }
            }
        }
        self.background_sessions
            .retain(|_, s| s.status() != SessionStatus::LoggedOut);

        // Active session.
        let active_enabled = self
            .profiles
            .get(&self.active_profile_id)
            .is_some_and(|p| p.lock_on_system_lock);
        if !active_enabled || self.screen != Screen::Vault {
            return;
        }
        let action = self
            .session
            .as_ref()
            .map(|s| s.effective_timeout_action())
            .unwrap_or_else(|| {
                self.profiles
                    .get(&self.active_profile_id)
                    .map(|p| p.timeout_action)
                    .unwrap_or_default()
            });
        match action {
            TimeoutAction::Lock => {
                self.lock();
                self.set_sticky_status(reason);
            }
            TimeoutAction::Logout => {
                self.finish_forced_logout(&reason.replace("Locked", "Logged out"));
            }
        }
    }

    pub fn lock_remaining(&self) -> Option<Duration> {
        if self.screen != Screen::Vault {
            return None;
        }
        if let Some(session) = self.session.as_ref() {
            return session.lock_remaining();
        }
        if self.using_mock {
            let mins = self.auto_lock_minutes?;
            let timeout = Duration::from_secs(mins.saturating_mul(60));
            return timeout.checked_sub(self.last_activity.elapsed());
        }
        None
    }

    pub fn clipboard_remaining(&self) -> Option<Duration> {
        if let Some(session) = self.session.as_ref() {
            return session
                .clipboard
                .seconds_until_clear()
                .map(Duration::from_secs);
        }
        self.clipboard_clear_at
            .and_then(|t| t.checked_duration_since(Instant::now()))
    }

    pub fn totp_display(&self) -> Option<TotpDisplay> {
        let item = self.selected_decrypted()?;
        if let Some(session) = self.session.as_ref() {
            return session.totp_now(&item.id);
        }
        item.totp
            .as_deref()
            .and_then(|s| vault_session::totp_display_from_secret(s).ok())
    }

    pub fn folder_name_for_item(&self, folder_id: Option<&str>) -> Option<String> {
        let id = folder_id?;
        self.folders
            .iter()
            .find(|f| f.id.as_deref() == Some(id))
            .map(|f| f.name.clone())
    }

    pub fn open_command_palette(&mut self) {
        self.overlay = Overlay::CommandPalette {
            query: String::new(),
            selected: 0,
        };
        self.touch();
    }

    pub fn palette_filtered_actions(&self) -> Vec<crate::action::Action> {
        use crate::action::Action;
        let all = Action::all().iter().copied().filter(|a| a.in_palette());
        let query = match &self.overlay {
            Overlay::CommandPalette { query, .. } => query.trim(),
            _ => "",
        };
        if query.is_empty() {
            return all.collect();
        }
        let matcher = SkimMatcherV2::default();
        let mut scored: Vec<(i64, Action)> = all
            .filter_map(|a| {
                // Match the key too, so typing `ctrl+s` or `g t` finds its command.
                let hay = format!("{} {}", a.label(), self.keymap.label(a));
                matcher.fuzzy_match(&hay, query).map(|score| (score, a))
            })
            .collect();
        scored.sort_by_key(|a| std::cmp::Reverse(a.0));
        scored.into_iter().map(|(_, a)| a).collect()
    }

    pub fn open_password_history(&mut self) {
        if self.selected_decrypted().is_none() {
            self.set_status("Select an item");
            return;
        }
        self.overlay = Overlay::PasswordHistory;
        self.touch();
    }

    pub fn open_health_report(&mut self) {
        let report = Box::new(self.health_report());
        self.overlay = Overlay::HealthReport {
            scroll: 0,
            hibp_opt_in: false,
            hibp_busy: false,
            hibp_results: Vec::new(),
            hibp_email_opt_in: false,
            hibp_email_results: Vec::new(),
            report,
        };
        self.touch();
    }

    pub fn toggle_hibp_opt_in(&mut self) {
        let Overlay::HealthReport {
            hibp_opt_in,
            hibp_busy,
            ..
        } = &mut self.overlay
        else {
            return;
        };
        if *hibp_busy {
            return;
        }
        *hibp_opt_in = !*hibp_opt_in;
        if *hibp_opt_in {
            self.queue(PendingAction::HibpScan);
        } else if let Overlay::HealthReport { hibp_results, .. } = &mut self.overlay {
            hibp_results.clear();
        }
    }

    pub fn toggle_hibp_email_opt_in(&mut self) {
        let Overlay::HealthReport {
            hibp_email_opt_in,
            hibp_busy,
            hibp_email_results,
            ..
        } = &mut self.overlay
        else {
            return;
        };
        if *hibp_busy {
            return;
        }
        if *hibp_email_opt_in {
            *hibp_email_opt_in = false;
            hibp_email_results.clear();
            return;
        }
        if vault_session::hibp_api_key_from_env().is_none() {
            self.set_status("Email breach check needs a HIBP API key: set BW_TUI_HIBP_API_KEY");
            return;
        }
        *hibp_email_opt_in = true;
        self.queue(PendingAction::HibpEmailScan);
    }

    pub async fn run_hibp_email_scan(&mut self) {
        let run = matches!(
            &self.overlay,
            Overlay::HealthReport {
                hibp_email_opt_in: true,
                ..
            }
        );
        let Some(api_key) = vault_session::hibp_api_key_from_env().filter(|_| run) else {
            return;
        };
        if let Overlay::HealthReport {
            hibp_busy,
            hibp_email_results,
            ..
        } = &mut self.overlay
        {
            *hibp_busy = true;
            hibp_email_results.clear();
        }

        // HIBP rate-limits breached-account lookups; keep the batch small and paced.
        let emails = vault_session::collect_breach_check_emails(&self.report_items(), 10);
        let mut results = Vec::new();
        for (i, email) in emails.iter().enumerate() {
            if i > 0 {
                tokio::time::sleep(Duration::from_millis(1600)).await;
            }
            match vault_session::hibp_email_breaches(email, &api_key).await {
                Ok(breaches) => results.push(HibpResultLine {
                    label: if breaches.is_empty() {
                        email.clone()
                    } else {
                        format!("{email} ({})", breaches.join(", "))
                    },
                    count: breaches.len() as u64,
                }),
                Err(e) => {
                    let fatal = matches!(
                        e,
                        vault_session::HibpError::Unauthorized
                            | vault_session::HibpError::RateLimited
                    );
                    results.push(HibpResultLine {
                        label: format!("{email}: {e}"),
                        count: 0,
                    });
                    if fatal {
                        break;
                    }
                }
            }
        }

        if let Overlay::HealthReport {
            hibp_busy,
            hibp_email_results,
            ..
        } = &mut self.overlay
        {
            *hibp_email_results = results;
            *hibp_busy = false;
        }
    }

    pub async fn run_hibp_scan(&mut self) {
        let run = matches!(
            &self.overlay,
            Overlay::HealthReport {
                hibp_opt_in: true,
                ..
            }
        );
        if !run {
            return;
        }
        if let Overlay::HealthReport {
            hibp_busy,
            hibp_results,
            ..
        } = &mut self.overlay
        {
            *hibp_busy = true;
            hibp_results.clear();
        }

        let items = self.report_items();
        let reused = find_reused_passwords(&items);
        let mut seen = std::collections::HashSet::new();
        let mut pairs: Vec<(String, String)> = Vec::new();
        for group in &reused {
            if let Some(item) = items.iter().find(|i| i.id == group.item_ids[0]) {
                if let Some(pw) = &item.password {
                    if seen.insert(pw.clone()) {
                        pairs.push((group.item_names.join(", "), pw.clone()));
                    }
                }
            }
        }
        if let Some(item) = self.selected_decrypted() {
            if let Some(pw) = &item.password {
                if seen.insert(pw.clone()) {
                    pairs.push((item.name.clone(), pw.clone()));
                }
            }
        }

        let mut results = Vec::new();
        for (label, pw) in pairs {
            match hibp_password_pwned_count(&pw).await {
                Ok(count) => results.push(HibpResultLine { label, count }),
                Err(e) => results.push(HibpResultLine {
                    label: format!("{label}: {e}"),
                    count: 0,
                }),
            }
        }

        if let Overlay::HealthReport {
            hibp_busy,
            hibp_results,
            ..
        } = &mut self.overlay
        {
            *hibp_results = results;
            *hibp_busy = false;
        }
    }

    pub fn open_account_settings(&mut self) {
        let pin_hint: String = self
            .session
            .as_ref()
            .map(|s| {
                if s.pin_unlock_available() {
                    "PIN unlock: configured".to_string()
                } else {
                    "PIN unlock: not configured".to_string()
                }
            })
            .unwrap_or_default();
        let agent_hint = self
            .session
            .as_ref()
            .and_then(|s| {
                s.ssh_agent_socket()
                    .map(|p| format!("SSH agent: {}", p.display()))
            })
            .unwrap_or_else(|| "SSH agent: stopped".into());
        self.overlay = Overlay::AccountSettings {
            section: 0,
            status: format!("{pin_hint} · {agent_hint}"),
        };
        self.touch();
    }

    pub fn open_pin_setup(&mut self) {
        if self
            .session
            .as_ref()
            .is_some_and(|s| s.pin_unlock_blocked_by_policy())
        {
            self.set_status("Organization policy: PIN unlock is disabled");
            return;
        }
        self.overlay = Overlay::PinSetup {
            pin: String::new(),
            confirm: String::new(),
            field: PinSetupField::Pin,
            status: String::new(),
        };
    }

    pub fn submit_pin_setup(&mut self) {
        let Overlay::PinSetup { pin, confirm, .. } = &self.overlay else {
            return;
        };
        if pin.len() < 4 {
            if let Overlay::PinSetup { status, .. } = &mut self.overlay {
                *status = "PIN must be at least 4 characters".into();
            }
            return;
        }
        if pin != confirm {
            if let Overlay::PinSetup { status, .. } = &mut self.overlay {
                *status = "PIN and confirmation do not match".into();
            }
            return;
        }
        let pin = pin.clone();
        if self.using_mock {
            if let Overlay::PinSetup { status, .. } = &mut self.overlay {
                *status = "Mock mode — PIN not persisted".into();
            }
            return;
        }
        match self.session.as_ref().unwrap().configure_pin(&pin) {
            Ok(()) => {
                self.close_overlay();
                self.set_status("PIN unlock configured");
            }
            Err(e) => {
                if let Overlay::PinSetup { status, .. } = &mut self.overlay {
                    *status = e.to_string();
                }
            }
        }
    }

    pub fn clear_pin_from_ui(&mut self) {
        if self.using_mock {
            if let Overlay::AccountSettings { status, .. } = &mut self.overlay {
                *status = "Mock mode — nothing to clear".into();
            }
            return;
        }
        if let Some(session) = self.session.as_ref() {
            session.clear_pin_unlock();
            if let Overlay::AccountSettings { status, .. } = &mut self.overlay {
                *status = "PIN unlock cleared".into();
            }
            self.set_status("PIN unlock cleared");
        }
    }

    pub fn toggle_ssh_agent(&mut self) {
        if self.using_mock {
            if let Overlay::AccountSettings { status, .. } = &mut self.overlay {
                *status = "Mock mode — SSH agent unavailable".into();
            }
            return;
        }
        let Some(session) = self.session.as_mut() else {
            return;
        };
        if session.ssh_agent_running() {
            session.stop_ssh_agent();
            if let Overlay::AccountSettings { status, .. } = &mut self.overlay {
                *status = "SSH agent stopped".into();
            }
            self.set_status("SSH agent stopped");
            return;
        }
        if self.config.power.ssh_agent_confirm && !self.power.ssh_confirmed {
            match session.ssh_agent_key_names() {
                Ok(names) => {
                    let prev = std::mem::replace(&mut self.overlay, Overlay::None);
                    self.overlay = crate::app::ssh_confirm_overlay(
                        prev,
                        names,
                        self.config.power.ssh_agent_confirm_each_use,
                    );
                }
                Err(e) => {
                    if let Overlay::AccountSettings { status, .. } = &mut self.overlay {
                        *status = e.to_string();
                    }
                }
            }
            return;
        }
        match session.start_ssh_agent_opts(self.config.power.ssh_agent_confirm_each_use) {
            Ok(socket) => {
                let msg = format!(
                    "SSH agent running — export SSH_AUTH_SOCK={}",
                    socket.display()
                );
                if let Overlay::AccountSettings { status, .. } = &mut self.overlay {
                    *status = msg.clone();
                }
                self.set_status(msg);
            }
            Err(e) => {
                if let Overlay::AccountSettings { status, .. } = &mut self.overlay {
                    *status = e.to_string();
                }
                self.set_status(format!("SSH agent: {e}"));
            }
        }
    }

    pub async fn submit_change_master_password(&mut self) {
        let Overlay::ChangeMasterPassword {
            old,
            new,
            confirm,
            hint,
            ..
        } = &self.overlay
        else {
            return;
        };
        if new.len() < 8 {
            if let Overlay::ChangeMasterPassword { error, .. } = &mut self.overlay {
                *error = Some("New password must be at least 8 characters".into());
            }
            return;
        }
        if new != confirm {
            if let Overlay::ChangeMasterPassword { error, .. } = &mut self.overlay {
                *error = Some("New password and confirmation do not match".into());
            }
            return;
        }
        let old = old.clone();
        let new = new.clone();
        let hint = hint.clone();
        if self.using_mock {
            if let Overlay::ChangeMasterPassword { error, .. } = &mut self.overlay {
                *error = Some("Mock mode — use a real session".into());
            }
            return;
        }
        if let Some(Err(e)) = self
            .session
            .as_ref()
            .map(|s| s.check_master_password_policy(&new))
        {
            if let Overlay::ChangeMasterPassword { error, .. } = &mut self.overlay {
                *error = Some(e.to_string());
            }
            return;
        }
        self.busy = true;
        let hint_ref = hint.trim();
        let hint_opt = if hint_ref.is_empty() {
            None
        } else {
            Some(hint_ref)
        };
        let result = self
            .session
            .as_mut()
            .unwrap()
            .change_master_password(&old, &new, hint_opt)
            .await;
        self.busy = false;
        match result {
            Ok(()) => {
                self.close_overlay();
                self.items.clear();
                self.folders.clear();
                self.sidebar.clear();
                self.visible.clear();
                self.screen = Screen::Unlock;
                self.locked_at = Some(Instant::now());
                self.set_sticky_status(
                    "Master password changed — unlock with your new password (PIN was cleared if set)",
                );
            }
            Err(e) => {
                if let Overlay::ChangeMasterPassword { error, .. } = &mut self.overlay {
                    *error = Some(e.to_string());
                }
            }
        }
    }

    pub fn open_send_form(&mut self) {
        if self
            .session
            .as_ref()
            .is_some_and(|s| !s.send_creation_allowed())
        {
            self.set_status("Organization policy disables Send");
            return;
        }
        let mut form = crate::send_form::SendFormState::new(crate::send_form::SendKind::Text);
        form.hide_email_blocked = self
            .session
            .as_ref()
            .is_some_and(|s| s.send_policy().disable_hide_email == Some(true));
        // Quick create: Content + Password only (`a` expands to advanced).
        debug_assert!(!form.advanced);
        debug_assert_eq!(form.field, crate::send_form::SendFormField::Content);
        self.overlay = Overlay::SendForm {
            form: Box::new(form),
        };
        self.touch();
    }

    pub fn open_edit_send(&mut self) {
        let Some(idx) = self.visible_sends.get(self.selected_item).copied() else {
            self.set_status("No send selected");
            return;
        };
        let send = &self.sends[idx];
        let kind = if send.is_file {
            crate::send_form::SendKind::File
        } else {
            crate::send_form::SendKind::Text
        };
        let mut form = crate::send_form::SendFormState::new(kind);
        form.advanced = true;
        form.field = crate::send_form::SendFormField::Name;
        form.editing_id = Some(send.id.clone());
        form.name = send.name.clone();
        form.content = if send.is_file {
            send.file_name.clone().unwrap_or_default()
        } else {
            send.text.clone().unwrap_or_default()
        };
        form.notes = send.notes.clone().unwrap_or_default();
        form.max_access = send
            .max_access_count
            .map(|n| n.to_string())
            .unwrap_or_default();
        form.expiration = send
            .expiration_date
            .as_deref()
            .map(crate::send_form::format_local_datetime)
            .unwrap_or_default();
        form.deletion = send
            .deletion_date
            .as_deref()
            .map(crate::send_form::format_local_datetime)
            .unwrap_or_default();
        form.hide_email = send.hide_email;
        form.hidden_text = send.text_hidden;
        form.disabled = send.disabled;
        form.has_password = send.has_password;
        form.hide_email_blocked = self
            .session
            .as_ref()
            .is_some_and(|s| s.send_policy().disable_hide_email == Some(true))
            && !send.hide_email;
        self.overlay = Overlay::SendForm {
            form: Box::new(form),
        };
        self.touch();
    }

    pub fn open_delete_send_confirm(&mut self) {
        let Some(idx) = self.visible_sends.get(self.selected_item).copied() else {
            self.set_status("No send selected");
            return;
        };
        let send = &self.sends[idx];
        self.overlay = Overlay::ConfirmDelete {
            target: DeleteTarget::Send {
                id: send.id.clone(),
                name: send.name.clone(),
            },
        };
        self.touch();
    }

    pub fn copy_send_link(&mut self) {
        let Some(idx) = self.visible_sends.get(self.selected_item).copied() else {
            self.set_status("No send selected");
            return;
        };
        let id = self.sends[idx].id.clone();
        let Some(session) = self.session.as_mut() else {
            self.set_status("Send link requires a session");
            return;
        };
        match session.send_share_link(&id) {
            Ok(link) => match session.copy_text(&link) {
                Ok(()) => self.set_status("Send link copied"),
                Err(e) => {
                    if crate::osc52::try_copy_osc52(&link) {
                        self.set_status("Send link copied (OSC 52)");
                    } else {
                        self.set_status(format!("Copy failed: {e}"));
                    }
                }
            },
            Err(e) => self.set_status(format!("Send link: {e}")),
        }
    }

    pub fn open_attachment_upload(&mut self) {
        if self.selected_decrypted().is_none() {
            self.set_status("Select an item first");
            return;
        }
        if self.session_is_offline() {
            self.set_status("Upload requires an online session");
            return;
        }
        self.overlay = Overlay::AttachmentPath {
            path: String::new(),
        };
        self.touch();
    }

    pub fn open_delete_attachment_confirm(&mut self, index: usize) {
        let Some(item) = self.selected_decrypted().cloned() else {
            return;
        };
        let Some((att_id, name)) = self.detail_attachments.get(index).cloned() else {
            self.set_status("No attachment at that slot");
            return;
        };
        self.overlay = Overlay::ConfirmDelete {
            target: DeleteTarget::Attachment {
                cipher_id: item.id,
                attachment_id: att_id,
                name,
            },
        };
        self.touch();
    }

    pub fn refresh_detail_attachments(&mut self) {
        self.detail_attachments.clear();
        let Some(item) = self.selected_decrypted() else {
            return;
        };
        if self.using_mock {
            return;
        }
        if let Some(session) = self.session.as_ref() {
            if let Ok(list) = session.list_attachments(&item.id) {
                self.detail_attachments = list.into_iter().map(|a| (a.id, a.file_name)).collect();
            }
        }
    }

    pub async fn clone_selected_item(&mut self) {
        let Some(item) = self.selected_decrypted().cloned() else {
            self.set_status("No item selected");
            return;
        };
        if item.organization_id.is_some() {
            self.set_status("Cannot clone organization items");
            return;
        }
        if self.using_mock {
            self.set_status("Clone not available in mock mode");
            return;
        }
        let id = item.id.clone();
        let Some(session) = self.session.as_mut() else {
            return;
        };
        self.busy = true;
        let clone_warn = tui_item_for_report(&item)
            .clone_warnings()
            .into_iter()
            .next();
        match session.clone_item(&id).await {
            Ok(_) => {
                self.reload_from_session();
                match clone_warn {
                    Some(w) => self.set_sticky_status(format!("Item cloned — {w}")),
                    None => self.set_status("Item cloned"),
                }
                self.touch();
            }
            Err(e) => self.set_status(format!("Clone failed: {e}")),
        }
        self.busy = false;
    }

    fn set_send_form_error(&mut self, msg: String) {
        if let Overlay::SendForm { form } = &mut self.overlay {
            form.error = Some(msg.clone());
        }
        self.set_status(msg);
    }

    pub async fn submit_send_form(&mut self) {
        let Overlay::SendForm { form } = &mut self.overlay else {
            return;
        };
        form.ensure_name();
        let form = (**form).clone();
        if let Err(e) = form.validate_required() {
            self.set_send_form_error(e);
            return;
        }
        let opts = match form.to_options(chrono::Utc::now()) {
            Ok(o) => o,
            Err(e) => {
                self.set_send_form_error(e);
                return;
            }
        };
        if self.using_mock || self.session.is_none() || self.session_is_offline() {
            self.set_send_form_error("Send requires an online session".into());
            return;
        }
        use crate::send_form::SendKind;
        let name = form.name.trim().to_string();
        let is_edit = form.editing_id.is_some();
        self.busy = true;
        let result = {
            let session = self.session.as_mut().unwrap();
            match (&form.editing_id, form.kind) {
                (Some(id), SendKind::Text) => {
                    session
                        .update_send(id, &name, Some(&form.content), &opts)
                        .await
                }
                (Some(id), SendKind::File) => session.update_send(id, &name, None, &opts).await,
                (None, SendKind::Text) => session
                    .create_send(&name, &form.content, &opts)
                    .await
                    .map(|_| ()),
                (None, SendKind::File) => {
                    let path = expand_user_path(form.content.trim());
                    session
                        .create_file_send(&name, &path, &opts)
                        .await
                        .map(|_| ())
                }
            }
        };
        self.busy = false;
        match result {
            Ok(()) => {
                self.close_overlay();
                self.reload_from_session();
                self.set_status(if is_edit {
                    "Send updated"
                } else {
                    "Send created"
                });
            }
            Err(e) => self.set_send_form_error(format!("Send failed: {e}")),
        }
    }

    pub fn open_receive_send(&mut self) {
        let dir = std::env::current_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| ".".into());
        self.overlay = Overlay::ReceiveSend {
            state: Box::new(crate::send_form::ReceiveSendState::new(dir)),
        };
        self.touch();
    }

    /// Fetch the Send for the URL (and password) typed in the receive overlay.
    pub async fn submit_receive_send(&mut self) {
        let Overlay::ReceiveSend { state } = &mut self.overlay else {
            return;
        };
        if state.received.is_some() {
            return;
        }
        let url = state.url.trim().to_string();
        if url.is_empty() {
            state.message = Some("Paste a Send link".into());
            return;
        }
        let password = state.password.clone();
        self.busy = true;
        let result =
            vault_session::receive_send(&url, (!password.is_empty()).then_some(password.as_str()))
                .await;
        self.busy = false;
        if let Overlay::ReceiveSend { state } = &mut self.overlay {
            match result {
                Ok(r) => state.set_received(r),
                Err(e) => state.set_error(&e),
            }
        }
        self.touch();
    }

    /// Download the received file Send into the chosen directory or path.
    pub async fn save_received_send_file(&mut self) {
        let Overlay::ReceiveSend { state } = &self.overlay else {
            return;
        };
        let Some(received) = state.received.clone() else {
            return;
        };
        if !received.is_file() {
            return;
        }
        let dest = expand_user_path(state.save_path.trim());
        self.busy = true;
        let result = vault_session::save_received_file(&received, &dest).await;
        self.busy = false;
        match result {
            Ok(path) => {
                let msg = format!("Saved {}", path.display());
                if let Overlay::ReceiveSend { state } = &mut self.overlay {
                    state.message = Some(msg.clone());
                }
                self.set_status(msg);
            }
            Err(e) => {
                if let Overlay::ReceiveSend { state } = &mut self.overlay {
                    state.message = Some(format!("Save failed: {e}"));
                }
            }
        }
        self.touch();
    }

    pub fn toggle_received_send_reveal(&mut self) {
        if let Overlay::ReceiveSend { state } = &mut self.overlay {
            state.reveal = !state.reveal;
        }
    }

    pub fn copy_received_send_text(&mut self) {
        let Overlay::ReceiveSend { state } = &self.overlay else {
            return;
        };
        let Some(text) = state.received.as_ref().and_then(|r| r.text.clone()) else {
            return;
        };
        let copied = match self.session.as_mut() {
            Some(session) => session.copy_text(&text).is_ok(),
            None => false,
        };
        if copied {
            self.set_status("Send text copied");
        } else if crate::osc52::try_copy_osc52(&text) {
            self.set_status("Send text copied (OSC 52)");
        } else {
            self.set_status("Copy failed");
        }
    }

    pub async fn submit_attachment_upload(&mut self) {
        let Overlay::AttachmentPath { path } = &self.overlay else {
            return;
        };
        let path = path.trim();
        if path.is_empty() {
            self.set_status("Enter a file path");
            return;
        }
        let Some(item) = self.selected_decrypted().cloned() else {
            return;
        };
        if self.session_is_offline() {
            self.set_status("Upload requires an online session");
            return;
        }
        let file_path = std::path::PathBuf::from(path);
        self.busy = true;
        match self
            .session
            .as_mut()
            .unwrap()
            .upload_attachment(&item.id, &file_path)
            .await
        {
            Ok(()) => {
                self.close_overlay();
                self.reload_from_session();
                self.set_status("Attachment uploaded");
            }
            Err(e) => self.set_status(format!("Upload failed: {e}")),
        }
        self.busy = false;
    }

    pub async fn submit_card_form(&mut self) {
        let Overlay::CardForm {
            editing_id,
            name,
            cardholder_name,
            brand,
            number,
            exp_month,
            exp_year,
            code,
            notes,
            reprompt,
            ..
        } = &self.overlay
        else {
            return;
        };
        if name.trim().is_empty() {
            self.set_status("Card name is required");
            return;
        }
        let draft = CardDraft {
            name: name.trim().to_string(),
            cardholder_name: nonempty(cardholder_name),
            brand: nonempty(brand),
            number: nonempty(number),
            exp_month: nonempty(exp_month),
            exp_year: nonempty(exp_year),
            code: nonempty(code),
            notes: nonempty(notes),
            folder_id: None,
            favorite: false,
            reprompt: *reprompt,
        };
        let editing_id = editing_id.clone();
        if self.using_mock {
            self.set_status("Card save requires an online session");
            return;
        }
        if self.session_is_offline() {
            self.set_status("Offline — save requires network");
            return;
        }
        let Some(session) = self.session.as_mut() else {
            return;
        };
        self.busy = true;
        let result = if let Some(id) = editing_id {
            session
                .update_card(&id, &draft)
                .await
                .map(|_| "Card updated".to_string())
        } else {
            session
                .create_card(&draft)
                .await
                .map(|_| "Card created".to_string())
        };
        match result {
            Ok(msg) => {
                self.close_overlay();
                self.reload_from_session();
                self.set_status(msg);
            }
            Err(e) => self.set_status(format!("Card failed: {e}")),
        }
        self.busy = false;
    }

    pub async fn submit_identity_form(&mut self) {
        let Overlay::IdentityForm {
            editing_id,
            name,
            title,
            first_name,
            middle_name,
            last_name,
            email,
            phone,
            username,
            company,
            address1,
            address2,
            address3,
            city,
            state,
            postal_code,
            country,
            ssn,
            passport,
            license,
            notes,
            reprompt,
            ..
        } = &self.overlay
        else {
            return;
        };
        if name.trim().is_empty() {
            self.set_status("Identity name is required");
            return;
        }
        let draft = IdentityDraft {
            name: name.trim().to_string(),
            title: nonempty(title),
            first_name: nonempty(first_name),
            middle_name: nonempty(middle_name),
            last_name: nonempty(last_name),
            address1: nonempty(address1),
            address2: nonempty(address2),
            address3: nonempty(address3),
            city: nonempty(city),
            state: nonempty(state),
            postal_code: nonempty(postal_code),
            country: nonempty(country),
            company: nonempty(company),
            email: nonempty(email),
            phone: nonempty(phone),
            ssn: nonempty(ssn),
            username: nonempty(username),
            passport_number: nonempty(passport),
            license_number: nonempty(license),
            notes: nonempty(notes),
            folder_id: None,
            favorite: false,
            reprompt: *reprompt,
        };
        let editing_id = editing_id.clone();
        if self.using_mock {
            self.set_status("Identity save requires an online session");
            return;
        }
        if self.session_is_offline() {
            self.set_status("Offline — save requires network");
            return;
        }
        let Some(session) = self.session.as_mut() else {
            return;
        };
        self.busy = true;
        let result = if let Some(id) = editing_id {
            session
                .update_identity(&id, &draft)
                .await
                .map(|_| "Identity updated".to_string())
        } else {
            session
                .create_identity(&draft)
                .await
                .map(|_| "Identity created".to_string())
        };
        match result {
            Ok(msg) => {
                self.close_overlay();
                self.reload_from_session();
                self.set_status(msg);
            }
            Err(e) => self.set_status(format!("Identity failed: {e}")),
        }
        self.busy = false;
    }

    pub async fn submit_ssh_key_form(&mut self) {
        let Overlay::SshKeyForm {
            editing_id,
            name,
            private_key,
            public_key,
            fingerprint,
            notes,
            ..
        } = &self.overlay
        else {
            return;
        };
        if name.trim().is_empty() {
            self.set_status("SSH key name is required");
            return;
        }
        let draft = SshKeyDraft {
            name: name.trim().to_string(),
            private_key: nonempty(private_key),
            public_key: nonempty(public_key),
            fingerprint: nonempty(fingerprint),
            notes: nonempty(notes),
            folder_id: None,
            favorite: false,
        };
        let editing_id = editing_id.clone();
        if self.using_mock {
            self.set_status("SSH key save requires an online session");
            return;
        }
        if self.session_is_offline() {
            self.set_status("Offline — save requires network");
            return;
        }
        let Some(session) = self.session.as_mut() else {
            return;
        };
        self.busy = true;
        let result = if let Some(id) = editing_id {
            session
                .update_ssh_key(&id, &draft)
                .await
                .map(|_| "SSH key updated".to_string())
        } else {
            session
                .create_ssh_key(&draft)
                .await
                .map(|_| "SSH key created".to_string())
        };
        match result {
            Ok(msg) => {
                self.close_overlay();
                self.reload_from_session();
                self.set_status(msg);
            }
            Err(e) => self.set_status(format!("SSH key failed: {e}")),
        }
        self.busy = false;
    }

    pub async fn download_attachment_at(&mut self, index: usize) {
        let Some((cipher_id, (att_id, name))) = self
            .selected_decrypted()
            .map(|i| i.id.clone())
            .zip(self.detail_attachments.get(index).cloned())
        else {
            self.set_status("No attachment selected");
            return;
        };
        if self.session.is_none() || self.using_mock {
            self.set_status("Attachments require an online session");
            return;
        }
        let dest = self.profile_data_dir().join("downloads").join(&name);
        self.busy = true;
        let result = self
            .session
            .as_mut()
            .unwrap()
            .download_attachment(&cipher_id, &att_id, &dest)
            .await;
        match result {
            Ok(()) => self.set_status(format!("Saved to {}", dest.display())),
            Err(e) => self.set_status(format!("Download failed: {e}")),
        }
        self.busy = false;
    }

    pub fn open_custom_fields_editor(&mut self) {
        let Some(item) = self.selected_decrypted().cloned() else {
            self.set_status("No item selected");
            return;
        };
        if item.organization_id.is_some() && !self.item_editable_public(&item.id) {
            self.set_status("Cannot edit organization item fields");
            return;
        }
        self.overlay = Overlay::CustomFieldsForm {
            item_id: item.id,
            fields: item.custom_fields,
            selected: 0,
            editing: None,
            edit_name: String::new(),
            edit_value: String::new(),
            edit_type: crate::models::CustomFieldKind::Text,
            edit_focus: CustomFieldEditFocus::Name,
        };
        self.touch();
    }

    pub async fn submit_custom_fields(&mut self) {
        let Overlay::CustomFieldsForm {
            item_id, fields, ..
        } = &self.overlay
        else {
            return;
        };
        let item_id = item_id.clone();
        let session_fields: Vec<vault_session::DecryptedField> = fields
            .iter()
            .map(|f| vault_session::DecryptedField {
                name: f.name.clone(),
                value: f.value.clone(),
                field_type: f.kind.to_session(),
                linked_id: f.linked_id,
            })
            .collect();
        if self.using_mock {
            if let Some(item) = self.items.iter_mut().find(|i| i.id == item_id) {
                item.custom_fields = fields.clone();
            }
            self.close_overlay();
            self.set_status("Custom fields saved (mock)");
            self.touch();
            return;
        }
        if self.session_is_offline() {
            self.set_status("Offline — save requires network");
            return;
        }
        let Some(session) = self.session.as_mut() else {
            return;
        };
        self.busy = true;
        match session
            .update_custom_fields(&item_id, &session_fields)
            .await
        {
            Ok(()) => {
                self.reload_from_session();
                self.close_overlay();
                self.set_status("Custom fields updated");
                self.touch();
            }
            Err(e) => self.set_status(format!("Custom fields failed: {e}")),
        }
        self.busy = false;
    }

    pub fn health_report(&self) -> VaultHealthReport {
        let opts = vault_session::HealthOptions {
            two_factor_directory: Some(vault_session::TwoFactorDirectory::load(
                &app_data_dir().join("2fa-directory.json"),
            )),
            ..Default::default()
        };
        vault_session::build_health_report_with(&self.report_items(), &opts)
    }

    fn report_items(&self) -> Vec<vault_session::DecryptedItem> {
        self.items.iter().map(tui_item_for_report).collect()
    }

    pub fn copy_custom_field(&mut self, index: usize) {
        let Some(item) = self.selected_decrypted().cloned() else {
            return;
        };
        let Some(field) = item.custom_fields.get(index) else {
            self.set_status("No custom field at that slot");
            return;
        };
        if field.hidden() && !self.reveal_secrets {
            self.set_status("Reveal secrets to copy hidden fields");
            return;
        }
        let value = field.value.clone();
        if value.is_empty() {
            self.set_status("Custom field is empty");
            return;
        }
        if let Some(session) = self.session.as_mut() {
            match session.copy_text(&value) {
                Ok(()) => self.set_status(format!("Copied custom field `{}`", field.name)),
                Err(e) => {
                    if crate::osc52::try_copy_osc52(&value) {
                        self.set_status(format!(
                            "Copied `{}` via OSC 52 (clipboard unavailable)",
                            field.name
                        ));
                    } else {
                        self.set_status(format!("Copy failed: {e}"));
                    }
                }
            }
            return;
        }
        if crate::osc52::try_copy_osc52(&value) {
            self.set_status(format!("Copied `{}` via OSC 52", field.name));
        } else if let Some(mut prev) = self.clipboard_demo.take() {
            prev.zeroize();
            self.clipboard_demo = Some(value);
            self.set_status(format!("Copied `{}` (demo)", field.name));
        }
        self.touch();
    }
}

fn format_sync_age(t: DateTime<Local>) -> String {
    let secs = (Local::now() - t).num_seconds().max(0);
    if secs < 60 {
        format!("{secs}s ago")
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86_400 {
        format!("{}h ago", secs / 3600)
    } else {
        format!("{}d ago", secs / 86_400)
    }
}

fn tui_item_for_report(item: &DecryptedItem) -> vault_session::DecryptedItem {
    vault_session::DecryptedItem {
        id: item.id.clone(),
        name: item.name.clone(),
        item_type: match item.item_type {
            ItemType::Login => SessionItemType::Login,
            ItemType::SecureNote => SessionItemType::SecureNote,
            ItemType::Card => SessionItemType::Card,
            ItemType::Identity => SessionItemType::Identity,
            ItemType::SshKey => SessionItemType::SshKey,
            ItemType::Unknown => SessionItemType::Unknown,
        },
        folder_id: item.folder_id.clone(),
        organization_id: item.organization_id.clone(),
        collection_ids: item.collection_ids.clone(),
        favorite: item.favorite,
        deleted: item.deleted,
        reprompt: item.reprompt,
        notes: item.notes.clone(),
        username: item.username.clone(),
        password: item.password.clone(),
        totp: item.totp.clone(),
        uris: item
            .uris
            .iter()
            .map(|u| DecryptedUri {
                uri: u.uri.clone(),
                match_type: None,
            })
            .collect(),
        custom_fields: vec![],
        password_history: vec![],
        password_revision_date: None,
        creation_date: item.creation_date.clone(),
        revision_date: None,
        cardholder_name: item.cardholder_name.clone(),
        card_brand: item.card_brand.clone(),
        card_number: item.card_number.clone(),
        card_exp_month: item.card_exp_month.clone(),
        card_exp_year: item.card_exp_year.clone(),
        card_code: item.card_code.clone(),
        identity_title: item.identity_title.clone(),
        identity_first_name: item.identity_first_name.clone(),
        identity_middle_name: item.identity_middle_name.clone(),
        identity_last_name: item.identity_last_name.clone(),
        identity_email: item.identity_email.clone(),
        identity_phone: item.identity_phone.clone(),
        identity_username: item.identity_username.clone(),
        identity_address1: item.identity_address1.clone(),
        identity_address2: item.identity_address2.clone(),
        identity_address3: item.identity_address3.clone(),
        identity_city: item.identity_city.clone(),
        identity_state: item.identity_state.clone(),
        identity_postal_code: item.identity_postal_code.clone(),
        identity_country: item.identity_country.clone(),
        identity_company: item.identity_company.clone(),
        identity_ssn: item.identity_ssn.clone(),
        identity_passport_number: item.identity_passport_number.clone(),
        identity_license_number: item.identity_license_number.clone(),
        ssh_private_key: item.ssh_private_key.clone(),
        ssh_public_key: item.ssh_public_key.clone(),
        ssh_fingerprint: item.ssh_fingerprint.clone(),
        passkeys: item.passkeys.clone(),
        has_item_key: item.has_item_key,
    }
}

fn mock_item_shell() -> DecryptedItem {
    DecryptedItem::default()
}

fn clipboard_kind_label(kind: ClipboardKind) -> &'static str {
    match kind {
        ClipboardKind::Password => "Password",
        ClipboardKind::Username => "Username",
        ClipboardKind::Totp => "TOTP",
        ClipboardKind::Uri => "URI",
        ClipboardKind::CardNumber => "Card number",
        ClipboardKind::CardCode => "CVC",
        ClipboardKind::CardExpiry => "Expiry",
        ClipboardKind::SshPublic => "SSH public key",
        ClipboardKind::SshPrivate => "SSH private key",
        ClipboardKind::Notes => "Notes",
    }
}

fn nonempty(s: &str) -> Option<String> {
    let t = s.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

impl Drop for App {
    fn drop(&mut self) {
        self.password.zeroize();
        self.unlock_password.zeroize();
        self.totp_code.zeroize();
        if let Some(mut s) = self.clipboard_demo.take() {
            s.zeroize();
        }
        self.clear_background_sessions();
        if let Some(session) = self.session.as_mut() {
            session.lock();
        }
        self.session = None;
    }
}

/// Expand a leading `~/` to the user's home directory.
pub(crate) fn expand_user_path(raw: &str) -> std::path::PathBuf {
    if let Some(rest) = raw.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return std::path::PathBuf::from(home).join(rest);
        }
    }
    std::path::PathBuf::from(raw)
}
