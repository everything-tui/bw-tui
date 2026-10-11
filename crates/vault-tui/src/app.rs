//! Application state machine for the Vaultwarden TUI.

use std::time::{Duration, Instant};

use fuzzy_matcher::skim::SkimMatcherV2;
use fuzzy_matcher::FuzzyMatcher;
use vault_session::{generate_password, LoginDraft, LoginResult, Session, SessionStatus};
use zeroize::Zeroize;

use crate::mock::{sample_folders, sample_items, with_folder_counts};
use crate::models::{DecryptedItem, FilterKind, FolderView, ItemType, SidebarEntry};

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
}

/// Slow auth work queued by a key press so the loop can paint a busy frame before running it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingAction {
    Login,
    TwoFactor,
    Unlock,
}

/// Auto-lock idle timeout for mock mode.
const MOCK_LOCK_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// Clear demo clipboard after this duration.
const CLIPBOARD_CLEAR_AFTER: Duration = Duration::from_secs(30);

pub struct App {
    pub screen: Screen,
    pub should_quit: bool,
    pub show_help: bool,
    pub overlay: Overlay,

    // --- Login / Unlock / 2FA ---
    pub server_url: String,
    pub email: String,
    pub password: String,
    /// When true, show master password characters on login/unlock screens.
    pub show_password: bool,
    /// When true, save server URL + email after a successful login.
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
    pub last_activity: Instant,
    pub locked_at: Option<Instant>,
    pub clipboard_clear_at: Option<Instant>,
    pub clipboard_kind: Option<ClipboardKind>,
    pub clipboard_demo: Option<String>,

    /// When true, use mock vault (no network). Set by `--mock`.
    pub using_mock: bool,
    /// Live session when not in mock mode.
    pub session: Option<Session>,
    pub busy: bool,
    pub pending: Option<PendingAction>,
    /// Backup of ItemForm when opening the generator from it.
    pub item_form_backup: Option<Overlay>,
}

impl App {
    pub fn new(server: Option<String>, email: Option<String>, mock: bool) -> Self {
        let saved = if mock {
            None
        } else {
            crate::prefs::load_saved_login()
        };
        let cli_server = server.filter(|s| !s.is_empty());
        let cli_email = email.filter(|e| !e.is_empty());
        let server_url = cli_server
            .clone()
            .or_else(|| saved.as_ref().map(|s| s.server_url.clone()))
            .unwrap_or_else(|| "http://127.0.0.1:8080".into());
        let email = cli_email
            .clone()
            .or_else(|| saved.as_ref().map(|s| s.email.clone()))
            .unwrap_or_default();
        let remember_login = saved.is_some();
        let has_email = !email.is_empty();
        let mut app = Self {
            screen: Screen::Login,
            should_quit: false,
            show_help: false,
            overlay: Overlay::None,
            server_url,
            email,
            password: String::new(),
            show_password: false,
            remember_login,
            // Server is prefilled for local Docker; start on Email (or Password
            // if email was provided on the CLI / prefs) so typing goes to an empty field.
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
            last_activity: Instant::now(),
            locked_at: None,
            clipboard_clear_at: None,
            clipboard_kind: None,
            clipboard_demo: None,
            using_mock: mock,
            session: None,
            busy: false,
            pending: None,
            item_form_backup: None,
        };
        if !app.email.is_empty() {
            app.login_field = LoginField::Password;
        }
        app
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
        if self.server_url.trim().is_empty() {
            self.form_error = Some("Server URL is required".into());
            return;
        }
        if self.email.trim().is_empty() {
            self.form_error = Some("Email is required".into());
            return;
        }
        if self.password.is_empty() {
            self.form_error = Some("Master password is required".into());
            return;
        }

        if self.using_mock {
            self.password.zeroize();
            self.load_mock_vault();
            self.screen = Screen::Vault;
            self.set_status("Logged in (mock vault)");
            self.touch();
            return;
        }

        self.busy = true;
        self.set_status("Logging in…");
        let server = self.server_url.trim().to_string();
        let email = self.email.trim().to_string();
        let password = self.password.clone();

        let mut session = match Session::new(&server) {
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
                self.reload_from_session();
                self.screen = Screen::Vault;
                self.locked_at = None;
                self.set_status("Logged in");
                self.touch();
            }
            Ok(LoginResult::TwoFactorRequired { providers }) => {
                self.session = Some(session);
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

    fn persist_login_prefs(&self, server: &str, email: &str) {
        if self.remember_login {
            let _ = crate::prefs::save_login(server, email);
            // Session already wrote auth.json during login; keep it for next launch.
        } else {
            crate::prefs::clear_saved_login();
            Session::clear_persisted_auth();
        }
    }

    /// If the user previously checked “Remember”, restore the refresh-token session
    /// and open the unlock screen (master password still required).
    pub async fn restore_session_if_saved(&mut self) {
        if self.using_mock || !self.remember_login {
            return;
        }
        self.set_status("Restoring session…");
        match Session::try_restore_saved().await {
            Ok(Some(session)) => {
                if let Some(email) = session.email() {
                    self.email = email.to_string();
                }
                self.server_url = session.server_url().to_string();
                self.session = Some(session);
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
                self.reload_from_session();
                self.screen = Screen::Vault;
                self.locked_at = None;
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
                self.reload_from_session();
                self.screen = Screen::Vault;
                self.locked_at = None;
                self.last_activity = Instant::now();
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

    pub async fn sync_vault(&mut self) {
        if self.using_mock {
            self.set_status("Synced (mock — no remote)");
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
                self.set_status("Synced");
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

        if let Some(exp) = self.status_expires {
            if now >= exp && !self.status.starts_with("Locked") && !self.busy {
                self.status = match self.screen {
                    Screen::Vault => {
                        if self.using_mock {
                            "Mock vault — press ? for help".into()
                        } else {
                            "Ready".into()
                        }
                    }
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

        if self.using_mock
            && self.screen == Screen::Vault
            && now.duration_since(self.last_activity) >= MOCK_LOCK_TIMEOUT
        {
            self.lock();
            self.set_status(format!(
                "Auto-locked after {}m idle",
                MOCK_LOCK_TIMEOUT.as_secs() / 60
            ));
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
            return MOCK_LOCK_TIMEOUT.checked_sub(self.last_activity.elapsed());
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
    }
}
