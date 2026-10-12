//! Application state machine for the Vaultwarden TUI.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use chrono::{DateTime, Local};
use fuzzy_matcher::skim::SkimMatcherV2;
use fuzzy_matcher::FuzzyMatcher;
use vault_session::{
    app_data_dir, generate_password, normalize_server_url, profile_dir, LoginDraft, LoginResult,
    Session, SessionStatus,
};
use zeroize::Zeroize;

use crate::mock::{sample_folders, sample_items, with_folder_counts};
use crate::models::{DecryptedItem, FilterKind, FolderView, ItemType, SidebarEntry};
use crate::profiles::{
    allocate_profile_id, create_profile, delete_profile, load_registry_from, parse_auto_lock_input,
    profile_has_auth, set_active, set_lock_on_profile_switch, update_profile,
    update_profile_credentials, ProfilesFile, VaultProfile,
};

/// High-level screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Login,
    TwoFactor,
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

/// Active field on the login form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginField {
    Server,
    Email,
    Password,
    /// Checkbox: persist server URL + email (never the master password).
    Remember,
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
}

impl EditField {
    pub fn next(self) -> Self {
        match self {
            Self::Name => Self::Username,
            Self::Username => Self::Password,
            Self::Password => Self::Totp,
            Self::Totp => Self::Uri,
            Self::Uri => Self::Notes,
            Self::Notes => Self::Name,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            Self::Name => Self::Notes,
            Self::Username => Self::Name,
            Self::Password => Self::Username,
            Self::Totp => Self::Password,
            Self::Uri => Self::Totp,
            Self::Notes => Self::Uri,
        }
    }
}

/// Which secret was last copied (for status + auto-clear).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardKind {
    Password,
    Username,
    Totp,
    Uri,
}

/// Focused field in the profile edit dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileEditField {
    Name,
    Server,
    Email,
    AutoLock,
}

impl ProfileEditField {
    pub fn next(self) -> Self {
        match self {
            Self::Name => Self::Server,
            Self::Server => Self::Email,
            Self::Email => Self::AutoLock,
            Self::AutoLock => Self::Name,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            Self::Name => Self::AutoLock,
            Self::Server => Self::Name,
            Self::Email => Self::Server,
            Self::AutoLock => Self::Email,
        }
    }
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
pub enum Overlay {
    None,
    ItemForm {
        editing_id: Option<String>,
        name: String,
        username: String,
        password: String,
        totp: String,
        uri: String,
        notes: String,
        field: EditField,
    },
    Generator {
        length: usize,
        uppercase: bool,
        lowercase: bool,
        digits: bool,
        symbols: bool,
        preview: String,
        /// When true, Enter inserts into an open ItemForm password field.
        insert_to_form: bool,
    },
    FolderForm {
        name: String,
    },
    ConfirmDelete {
        id: String,
        name: String,
    },
    ProfileManager {
        selected: usize,
        mode: ProfileManagerMode,
    },
}

/// Slow auth work queued by a key press so the loop can paint a busy frame before running it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingAction {
    Login,
    TwoFactor,
    Unlock,
}

/// Clear demo clipboard after this duration.
const CLIPBOARD_CLEAR_AFTER: Duration = Duration::from_secs(30);

pub struct App {
    pub screen: Screen,
    pub should_quit: bool,
    pub show_help: bool,
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
    pub login_field: LoginField,
    pub unlock_password: String,
    pub totp_code: String,
    pub two_factor_providers: Vec<u8>,
    pub form_error: Option<String>,

    // --- Vault data ---
    pub folders: Vec<FolderView>,
    pub items: Vec<DecryptedItem>,
    pub sidebar: Vec<SidebarEntry>,
    pub selected_sidebar: usize,
    pub selected_item: usize,
    pub focus: FocusPane,
    pub visible: Vec<usize>,

    // --- Search ---
    pub searching: bool,
    pub search_query: String,

    // --- Status / timers ---
    pub status: String,
    pub status_expires: Option<Instant>,
    /// Local time of the most recent successful vault sync.
    pub last_synced_at: Option<DateTime<Local>>,
    pub last_activity: Instant,
    pub locked_at: Option<Instant>,
    pub clipboard_clear_at: Option<Instant>,
    pub clipboard_kind: Option<ClipboardKind>,
    pub clipboard_demo: Option<String>,

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
        let mut app = Self {
            screen: Screen::Login,
            should_quit: false,
            show_help: false,
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
            login_field: if has_email {
                LoginField::Password
            } else {
                LoginField::Email
            },
            unlock_password: String::new(),
            totp_code: String::new(),
            two_factor_providers: Vec::new(),
            form_error: None,
            folders: Vec::new(),
            items: Vec::new(),
            sidebar: Vec::new(),
            selected_sidebar: 0,
            selected_item: 0,
            focus: FocusPane::Items,
            visible: Vec::new(),
            searching: false,
            search_query: String::new(),
            status: if mock {
                "Mock mode — press ? for help".into()
            } else {
                "Ready — press ? for help".into()
            },
            status_expires: None,
            last_synced_at: None,
            last_activity: Instant::now(),
            locked_at: None,
            clipboard_clear_at: None,
            clipboard_kind: None,
            clipboard_demo: None,
            using_mock: mock,
            session: None,
            background_sessions: HashMap::new(),
            background_mocks: HashMap::new(),
            busy: false,
            pending: None,
            item_form_backup: None,
        };
        if !app.email.is_empty() {
            app.login_field = LoginField::Password;
        }
        Ok(app)
    }

    pub fn profile_data_dir(&self) -> PathBuf {
        profile_dir(&self.data_root, &self.active_profile_id)
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
        self.auto_lock_minutes = minutes;
        if let Some(session) = self.session.as_mut() {
            session.set_auto_lock(minutes);
        }
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
            None => {}
        }
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
            self.password.zeroize();
            self.load_mock_vault();
            self.apply_auto_lock_from_profile();
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

        match session.login(&email, &password, None).await {
            Ok(LoginResult::Success) => {
                self.password.zeroize();
                self.persist_login_prefs(&server, &email);
                self.session = Some(session);
                self.apply_auto_lock_from_profile();
                self.reload_from_session();
                self.screen = Screen::Vault;
                self.locked_at = None;
                self.mark_synced();
                self.set_status("Logged in");
                self.touch();
            }
            Ok(LoginResult::TwoFactorRequired { providers }) => {
                self.session = Some(session);
                self.apply_auto_lock_from_profile();
                self.two_factor_providers = providers;
                self.totp_code.clear();
                self.screen = Screen::TwoFactor;
                self.set_status("Two-factor authentication required");
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
        match Session::try_restore_saved(self.profile_data_dir()).await {
            Ok(Some(session)) => {
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

        match Session::try_restore_saved(self.profile_data_dir()).await {
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
                });
                Ok(id)
            }
        } else {
            create_profile(
                &self.data_root,
                &mut self.profiles,
                &name,
                &inherit_server,
            )
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
        let (id, name, server_url, email, auto_lock_input, selected) = match &self.overlay {
            Overlay::ProfileManager {
                mode:
                    ProfileManagerMode::Edit {
                        id,
                        name,
                        server_url,
                        email,
                        auto_lock_input,
                        ..
                    },
                selected,
            } => (
                id.clone(),
                name.clone(),
                server_url.clone(),
                email.clone(),
                auto_lock_input.clone(),
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

        let result = if self.using_mock {
            match self.profiles.get_mut(&id) {
                Some(p) => {
                    p.name = name.trim().to_string();
                    p.server_url = server_url.trim().to_string();
                    p.email = email.trim().to_string();
                    p.auto_lock_minutes = minutes;
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
        }
        if let Some(session) = self.background_sessions.get_mut(&id) {
            session.set_auto_lock(minutes);
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
        let provider = self.two_factor_providers.first().copied().unwrap_or(0);

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
            .login_2fa(&email, &password, provider, &code)
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
                self.set_status("Logged in");
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
                self.set_status("Vault unlocked");
                self.touch();
            }
            Err(e) => {
                self.form_error = Some(e.to_string());
                self.set_status("Unlock failed");
            }
        }
        self.busy = false;
    }

    pub fn lock(&mut self) {
        self.unlock_password.zeroize();
        self.password.zeroize();
        self.searching = false;
        self.search_query.clear();
        self.show_help = false;
        self.overlay = Overlay::None;
        if let Some(mut s) = self.clipboard_demo.take() {
            s.zeroize();
        }
        self.clipboard_clear_at = None;
        self.clipboard_kind = None;

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
        self.set_status("Vault locked");
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
        let items: Vec<DecryptedItem> = session.items().iter().map(DecryptedItem::from_session).collect();
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
        self.rebuild_sidebar();
        self.recompute_visible();
        if self.selected_sidebar >= self.sidebar.len() {
            self.selected_sidebar = self.sidebar.len().saturating_sub(1);
        }
        if self.selected_item >= self.visible.len() {
            self.selected_item = self.visible.len().saturating_sub(1);
        }
    }

    // -------------------------------------------------------------------------
    // Sidebar / filtering
    // -------------------------------------------------------------------------

    pub fn rebuild_sidebar(&mut self) {
        let items = &self.items;
        let active = |pred: fn(&DecryptedItem) -> bool| items.iter().filter(|i| pred(i)).count();

        let mut entries = vec![
            SidebarEntry {
                label: "All items".into(),
                kind: FilterKind::All,
                count: active(|i| !i.deleted),
            },
            SidebarEntry {
                label: "Favorites".into(),
                kind: FilterKind::Favorites,
                count: active(|i| i.favorite && !i.deleted),
            },
            SidebarEntry {
                label: "Logins".into(),
                kind: FilterKind::Login,
                count: active(|i| i.item_type == ItemType::Login && !i.deleted),
            },
            SidebarEntry {
                label: "Notes".into(),
                kind: FilterKind::SecureNote,
                count: active(|i| i.item_type == ItemType::SecureNote && !i.deleted),
            },
            SidebarEntry {
                label: "Cards".into(),
                kind: FilterKind::Card,
                count: active(|i| i.item_type == ItemType::Card && !i.deleted),
            },
            SidebarEntry {
                label: "Identities".into(),
                kind: FilterKind::Identity,
                count: active(|i| i.item_type == ItemType::Identity && !i.deleted),
            },
        ];

        for folder in &self.folders {
            if let Some(id) = &folder.id {
                entries.push(SidebarEntry {
                    label: folder.name.clone(),
                    kind: FilterKind::Folder(id.clone()),
                    count: folder.count,
                });
            }
        }

        let no_folder = active(|i| !i.deleted && i.folder_id.is_none());
        entries.push(SidebarEntry {
            label: "No folder".into(),
            kind: FilterKind::NoFolder,
            count: no_folder,
        });
        entries.push(SidebarEntry {
            label: "Trash".into(),
            kind: FilterKind::Trash,
            count: active(|i| i.deleted),
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
        let matcher = SkimMatcherV2::default();
        let query = self.search_query.trim();

        let mut scored: Vec<(i64, usize)> = self
            .items
            .iter()
            .enumerate()
            .filter(|(_, item)| filter.matches(item))
            .filter_map(|(idx, item)| {
                if query.is_empty() {
                    return Some((0, idx));
                }
                let hay = format!(
                    "{} {} {} {}",
                    item.name,
                    item.subtitle(),
                    item.uris.join(" "),
                    item.notes.as_deref().unwrap_or("")
                );
                matcher.fuzzy_match(&hay, query).map(|score| (score, idx))
            })
            .collect();

        if !query.is_empty() {
            scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        } else {
            scored.sort_by(|a, b| {
                let ia = &self.items[a.1];
                let ib = &self.items[b.1];
                ib.favorite
                    .cmp(&ia.favorite)
                    .then_with(|| ia.name.to_lowercase().cmp(&ib.name.to_lowercase()))
            });
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
                let len = self.visible.len() as isize;
                if len == 0 {
                    return;
                }
                let next = (self.selected_item as isize + delta).rem_euclid(len) as usize;
                self.selected_item = next;
            }
        }
        self.touch();
    }

    // -------------------------------------------------------------------------
    // Actions
    // -------------------------------------------------------------------------

    pub fn set_status(&mut self, msg: impl Into<String>) {
        self.status = msg.into();
        self.status_expires = Some(Instant::now() + Duration::from_secs(4));
    }

    fn mark_synced(&mut self) {
        self.last_synced_at = Some(Local::now());
    }

    fn last_synced_status(&self) -> Option<String> {
        self.last_synced_at.map(|t| {
            let base = format!("Synced last at {}", t.format("%H:%M:%S"));
            if self.using_mock {
                format!("{base} (mock)")
            } else {
                base
            }
        })
    }

    fn vault_idle_status(&self) -> String {
        self.last_synced_status().unwrap_or_else(|| {
            if self.using_mock {
                "Mock vault — press ? for help".into()
            } else {
                "Ready".into()
            }
        })
    }

    fn show_last_synced_status(&mut self) {
        self.status = self.vault_idle_status();
        self.status_expires = None;
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

    pub fn copy_field(&mut self, kind: ClipboardKind) {
        let Some(item) = self.selected_decrypted().cloned() else {
            self.set_status("No item selected");
            return;
        };

        if !self.using_mock {
            if let Some(session) = self.session.as_mut() {
                let result = match kind {
                    ClipboardKind::Password => session
                        .copy_password(&item.id)
                        .map(|_| "Password".to_string()),
                    ClipboardKind::Username => session
                        .copy_username(&item.id)
                        .map(|_| "Username".to_string()),
                    ClipboardKind::Totp => session
                        .copy_totp(&item.id)
                        .map(|code| format!("TOTP {code}")),
                    ClipboardKind::Uri => {
                        let Some(uri) = item.primary_uri().map(str::to_string) else {
                            self.set_status("No URI on this item");
                            return;
                        };
                        session
                            .clipboard
                            .copy_secret(&uri)
                            .map(|_| "URI".to_string())
                    }
                };
                match result {
                    Ok(label) => {
                        self.clipboard_kind = Some(kind);
                        self.set_status(format!("{label} copied"));
                        self.touch();
                    }
                    Err(e) => self.set_status(format!("Copy failed: {e}")),
                }
                return;
            }
        }

        // Mock / demo clipboard
        let value = match kind {
            ClipboardKind::Password => item.password.clone(),
            ClipboardKind::Username => item.username.clone(),
            ClipboardKind::Totp => item.totp.clone(),
            ClipboardKind::Uri => item.primary_uri().map(str::to_string),
        };
        let Some(value) = value.filter(|s| !s.is_empty()) else {
            let label = match kind {
                ClipboardKind::Password => "password",
                ClipboardKind::Username => "username",
                ClipboardKind::Totp => "TOTP",
                ClipboardKind::Uri => "URI",
            };
            self.set_status(format!("No {label} on this item"));
            return;
        };

        if let Some(mut prev) = self.clipboard_demo.take() {
            prev.zeroize();
        }
        self.clipboard_demo = Some(value);
        self.clipboard_kind = Some(kind);
        self.clipboard_clear_at = Some(Instant::now() + CLIPBOARD_CLEAR_AFTER);
        let label = match kind {
            ClipboardKind::Password => "Password",
            ClipboardKind::Username => "Username",
            ClipboardKind::Totp => "TOTP secret",
            ClipboardKind::Uri => "URI",
        };
        self.set_status(format!(
            "{label} copied (demo) — clears in {}s",
            CLIPBOARD_CLEAR_AFTER.as_secs()
        ));
        self.touch();
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

    pub fn open_new_login(&mut self) {
        self.overlay = Overlay::ItemForm {
            editing_id: None,
            name: String::new(),
            username: String::new(),
            password: String::new(),
            totp: String::new(),
            uri: String::new(),
            notes: String::new(),
            field: EditField::Name,
        };
        self.touch();
    }

    pub fn open_edit_login(&mut self) {
        let Some(item) = self.selected_decrypted().cloned() else {
            self.set_status("No item selected");
            return;
        };
        if item.item_type != ItemType::Login {
            self.set_status("Only logins can be edited here");
            return;
        }
        let uri = item.primary_uri().unwrap_or("").to_string();
        self.overlay = Overlay::ItemForm {
            editing_id: Some(item.id),
            name: item.name,
            username: item.username.unwrap_or_default(),
            password: item.password.unwrap_or_default(),
            totp: item.totp.unwrap_or_default(),
            uri,
            notes: item.notes.unwrap_or_default(),
            field: EditField::Name,
        };
        self.touch();
    }

    pub fn open_delete_confirm(&mut self) {
        let Some(item) = self.selected_decrypted() else {
            self.set_status("No item selected");
            return;
        };
        self.overlay = Overlay::ConfirmDelete {
            id: item.id.clone(),
            name: item.name.clone(),
        };
        self.touch();
    }

    pub fn open_folder_form(&mut self) {
        self.overlay = Overlay::FolderForm {
            name: String::new(),
        };
        self.touch();
    }

    pub fn open_generator(&mut self, insert_to_form: bool) {
        if insert_to_form && matches!(self.overlay, Overlay::ItemForm { .. }) {
            self.item_form_backup = Some(std::mem::replace(&mut self.overlay, Overlay::None));
        }
        let preview = generate_password(20, true, true, true, true);
        self.overlay = Overlay::Generator {
            length: 20,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
            preview,
            insert_to_form,
        };
        self.touch();
    }

    pub fn regenerate_password(&mut self) {
        if let Overlay::Generator {
            length,
            uppercase,
            lowercase,
            digits,
            symbols,
            preview,
            ..
        } = &mut self.overlay
        {
            *preview = generate_password(*length, *uppercase, *lowercase, *digits, *symbols);
        }
        self.touch();
    }

    pub fn close_overlay(&mut self) {
        if let Overlay::ItemForm { password, .. } = &mut self.overlay {
            password.zeroize();
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
            uri,
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

        let draft = LoginDraft {
            name: name.trim().to_string(),
            username: nonempty(username),
            password: nonempty(password),
            totp: nonempty(totp),
            uri: nonempty(uri),
            notes: nonempty(notes),
            folder_id: None,
            favorite: false,
            reprompt: false,
        };
        let editing_id = editing_id.clone();

        if self.using_mock {
            if let Some(id) = editing_id {
                if let Some(item) = self.items.iter_mut().find(|i| i.id == id) {
                    item.name = draft.name.clone();
                    item.username = draft.username.clone();
                    item.password = draft.password.clone();
                    item.totp = draft.totp.clone();
                    item.uris = draft.uri.clone().into_iter().collect();
                    item.notes = draft.notes.clone();
                }
                self.set_status("Login updated (mock)");
            } else {
                let id = format!("mock-{}", self.items.len() + 1);
                self.items.push(DecryptedItem {
                    id,
                    name: draft.name.clone(),
                    item_type: ItemType::Login,
                    folder_id: None,
                    favorite: false,
                    deleted: false,
                    username: draft.username.clone(),
                    password: draft.password.clone(),
                    totp: draft.totp.clone(),
                    uris: draft.uri.clone().into_iter().collect(),
                    notes: draft.notes.clone(),
                    card_number: None,
                    card_brand: None,
                    identity_name: None,
                });
                self.set_status("Login created (mock)");
            }
            self.folders = with_folder_counts(self.folders.clone(), &self.items);
            self.rebuild_sidebar();
            self.recompute_visible();
            self.close_overlay();
            self.touch();
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
        let Overlay::ConfirmDelete { id, .. } = &self.overlay else {
            return;
        };
        let id = id.clone();

        if self.using_mock {
            if let Some(item) = self.items.iter_mut().find(|i| i.id == id) {
                item.deleted = true;
            }
            self.rebuild_sidebar();
            self.recompute_visible();
            self.close_overlay();
            self.set_status("Moved to trash (mock)");
            self.touch();
            return;
        }

        let Some(session) = self.session.as_mut() else {
            return;
        };
        self.busy = true;
        match session.soft_delete(&id).await {
            Ok(()) => {
                self.reload_from_session();
                self.close_overlay();
                self.set_status("Moved to trash");
                self.touch();
            }
            Err(e) => self.set_status(format!("Delete failed: {e}")),
        }
        self.busy = false;
    }

    pub async fn save_folder_form(&mut self) {
        let Overlay::FolderForm { name } = &self.overlay else {
            return;
        };
        let name = name.trim().to_string();
        if name.is_empty() {
            self.set_status("Folder name is required");
            return;
        }

        if self.using_mock {
            let id = format!("folder-{}", self.folders.len() + 1);
            self.folders.push(FolderView {
                id: Some(id),
                name,
                count: 0,
            });
            self.rebuild_sidebar();
            self.close_overlay();
            self.set_status("Folder created (mock)");
            self.touch();
            return;
        }

        let Some(session) = self.session.as_mut() else {
            return;
        };
        self.busy = true;
        match session.create_folder(&name).await {
            Ok(_) => {
                self.reload_from_session();
                self.close_overlay();
                self.set_status("Folder created");
                self.touch();
            }
            Err(e) => self.set_status(format!("Folder create failed: {e}")),
        }
        self.busy = false;
    }

    pub fn apply_generator(&mut self) {
        let (preview, insert) = match &self.overlay {
            Overlay::Generator {
                preview,
                insert_to_form,
                ..
            } => (preview.clone(), *insert_to_form),
            _ => return,
        };

        if self.using_mock {
            if let Some(mut prev) = self.clipboard_demo.take() {
                prev.zeroize();
            }
            self.clipboard_demo = Some(preview.clone());
            self.clipboard_clear_at = Some(Instant::now() + CLIPBOARD_CLEAR_AFTER);
        } else if let Some(session) = self.session.as_mut() {
            let _ = session.clipboard.copy_secret(&preview);
        }

        if insert {
            if let Some(mut form) = self.item_form_backup.take() {
                if let Overlay::ItemForm { password, field, .. } = &mut form {
                    *password = preview;
                    *field = EditField::Password;
                }
                self.overlay = form;
                self.set_status("Password inserted into form");
            } else {
                self.close_overlay();
                self.set_status("Generated password copied");
            }
        } else {
            self.close_overlay();
            self.set_status("Generated password copied");
        }
        self.touch();
    }

    // -------------------------------------------------------------------------
    // Tick
    // -------------------------------------------------------------------------

    pub fn on_tick(&mut self) {
        let now = Instant::now();

        if let Some(session) = self.session.as_mut() {
            let was_unlocked = session.status() == SessionStatus::Unlocked;
            session.tick();
            if was_unlocked && session.status() == SessionStatus::Locked {
                self.items.clear();
                self.folders.clear();
                self.sidebar.clear();
                self.visible.clear();
                self.overlay = Overlay::None;
                self.searching = false;
                self.screen = Screen::Unlock;
                self.locked_at = Some(Instant::now());
                self.set_status("Auto-locked after idle");
            }
        }

        for session in self.background_sessions.values_mut() {
            session.tick();
        }

        self.background_mocks
            .retain(|_, parked| Self::mock_parked_still_open(parked));

        if let Some(exp) = self.status_expires {
            if now >= exp && !self.status.starts_with("Locked") && !self.busy {
                self.status = match self.screen {
                    Screen::Vault => self.vault_idle_status(),
                    Screen::Login => "Enter credentials to continue".into(),
                    Screen::TwoFactor => "Enter your two-factor code".into(),
                    Screen::Unlock => "Enter master password to unlock".into(),
                };
                self.status_expires = None;
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
                    self.set_status(format!("Auto-locked after {mins}m idle"));
                }
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

    pub fn totp_display(&self) -> Option<String> {
        let id = self.selected_decrypted()?.id.clone();
        self.session.as_ref().and_then(|s| s.totp_now(&id))
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
