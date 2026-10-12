//! Account tools overlay: change KDF, deauthorize sessions, 2FA (authenticator) setup,
//! change-email / delete-account stubs, approve other devices' logins, forwarded-email
//! alias credentials and the biometric stub.
//!
//! Child module of `state` so it can use the app's private helpers.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use vault_session::{
    biometric_authenticate, biometric_available, biometric_clear_enrollment, biometric_is_enrolled,
    biometric_mark_enrolled, biometric_status_hint, delete_forwarder_credentials,
    generate_forwarded_alias_blocking, load_forwarder_credentials, store_forwarder_credentials,
    AuthenticatorSetupInfo, ForwarderCredentials, ForwarderService, IncomingAuthRequest, KdfParams,
};

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolScreen {
    Menu,
    ChangeKdf,
    Deauthorize,
    TwoFactor,
    ChangeEmail,
    DeleteAccount,
    DeviceApprovals,
    Forwarders,
    Biometric,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolConfirm {
    ChangeKdf,
    Deauthorize,
    ChangeEmail,
    DeleteAccount,
    ApproveDevice,
    DenyDevice,
}

#[derive(Debug, Clone)]
pub struct AccountToolsState {
    pub screen: ToolScreen,
    /// Selected row (menu / device list / forwarder list).
    pub selected: usize,
    pub fields: Vec<String>,
    pub focus: usize,
    pub message: String,
    pub is_error: bool,
    pub confirm: Option<ToolConfirm>,
    pub incoming: Vec<IncomingAuthRequest>,
    pub authenticator: Option<AuthenticatorSetupInfo>,
    pub info_lines: Vec<String>,
    pub qr_lines: Vec<String>,
    /// Forwarder currently being edited (token / URL / domain fields).
    pub forwarder_edit: Option<ForwarderService>,
    pub forwarder_configured: Vec<(ForwarderService, bool)>,
}

impl AccountToolsState {
    fn new(screen: ToolScreen) -> Self {
        Self {
            screen,
            selected: 0,
            fields: Vec::new(),
            focus: 0,
            message: String::new(),
            is_error: false,
            confirm: None,
            incoming: Vec::new(),
            authenticator: None,
            info_lines: Vec::new(),
            qr_lines: Vec::new(),
            forwarder_edit: None,
            forwarder_configured: Vec::new(),
        }
    }
}

/// Menu rows: (key, label).
pub const TOOL_MENU: &[(char, &str)] = &[
    ('1', "Change KDF (PBKDF2 / Argon2id)"),
    ('2', "Deauthorize all other sessions"),
    ('3', "Two-step login: authenticator app setup"),
    ('4', "Change account email (stub)"),
    ('5', "Delete account (stub)"),
    ('6', "Approve login requests from other devices"),
    ('7', "Forwarded email aliases (SimpleLogin / addy.io)"),
    ('8', "Biometric unlock (Touch ID stub)"),
];

fn screen_for_menu(idx: usize) -> ToolScreen {
    match idx {
        0 => ToolScreen::ChangeKdf,
        1 => ToolScreen::Deauthorize,
        2 => ToolScreen::TwoFactor,
        3 => ToolScreen::ChangeEmail,
        4 => ToolScreen::DeleteAccount,
        5 => ToolScreen::DeviceApprovals,
        6 => ToolScreen::Forwarders,
        _ => ToolScreen::Biometric,
    }
}

fn kdf_is_argon(st: &AccountToolsState) -> bool {
    st.fields
        .get(1)
        .is_some_and(|t| t.eq_ignore_ascii_case("argon2id"))
}

/// Visible form fields for the current screen: `(label, secret)`.
pub fn tool_fields(st: &AccountToolsState) -> Vec<(&'static str, bool)> {
    match st.screen {
        ToolScreen::ChangeKdf => {
            let mut v = vec![
                ("Master password", true),
                ("KDF (Space toggles)", false),
                ("Iterations", false),
            ];
            if kdf_is_argon(st) {
                v.push(("Memory MiB", false));
                v.push(("Parallelism", false));
            }
            v
        }
        ToolScreen::Deauthorize => vec![("Master password", true)],
        ToolScreen::TwoFactor => {
            let mut v = vec![("Master password", true)];
            if st.authenticator.is_some() {
                v.push(("Code from your authenticator app", false));
            }
            v
        }
        ToolScreen::ChangeEmail => vec![("New email", false), ("Master password", true)],
        ToolScreen::DeleteAccount => vec![
            ("Type DELETE to continue", false),
            ("Master password", true),
        ],
        ToolScreen::Forwarders if st.forwarder_edit.is_some() => {
            let mut v = vec![("API token", true), ("Base URL (optional)", false)];
            if st.forwarder_edit == Some(ForwarderService::AddyIo) {
                v.push(("Alias domain (optional)", false));
            }
            v
        }
        _ => Vec::new(),
    }
}

fn parse_u32(s: &str, what: &str) -> Result<u32, String> {
    s.trim()
        .parse::<u32>()
        .map_err(|_| format!("{what} must be a whole number"))
}

impl App {
    fn tools_mut(&mut self) -> Option<&mut AccountToolsState> {
        match &mut self.overlay {
            Overlay::AccountTools(st) => Some(st),
            _ => None,
        }
    }

    fn tools_msg(&mut self, msg: impl Into<String>, is_error: bool) {
        let msg = msg.into();
        if let Some(st) = self.tools_mut() {
            st.message = msg;
            st.is_error = is_error;
            st.confirm = None;
        }
    }

    pub fn open_account_tools(&mut self) {
        self.overlay = Overlay::AccountTools(Box::new(AccountToolsState::new(ToolScreen::Menu)));
        self.touch();
    }

    fn tools_live_session(&self) -> Result<(), String> {
        if self.using_mock {
            return Err("Mock mode — no server".into());
        }
        if self.session.is_none() {
            return Err("Not logged in".into());
        }
        Ok(())
    }

    async fn tools_open_screen(&mut self, screen: ToolScreen) {
        let mut st = AccountToolsState::new(screen);
        match screen {
            ToolScreen::Menu => {}
            ToolScreen::ChangeKdf => {
                st.fields = match self.session.as_ref().and_then(|s| s.account_kdf()) {
                    Some(KdfParams::Pbkdf2 { iterations }) => vec![
                        String::new(),
                        "pbkdf2".into(),
                        iterations.to_string(),
                        "64".into(),
                        "4".into(),
                    ],
                    Some(KdfParams::Argon2id {
                        iterations,
                        memory_mib,
                        parallelism,
                    }) => vec![
                        String::new(),
                        "argon2id".into(),
                        iterations.to_string(),
                        memory_mib.to_string(),
                        parallelism.to_string(),
                    ],
                    None => vec![
                        String::new(),
                        "pbkdf2".into(),
                        "600000".into(),
                        "64".into(),
                        "4".into(),
                    ],
                };
                st.message = "Re-wraps your vault key; locks the vault afterwards.".into();
            }
            ToolScreen::Deauthorize => {
                st.fields = vec![String::new()];
                st.message = "Logs out every other device (and this one).".into();
            }
            ToolScreen::TwoFactor => {
                st.fields = vec![String::new(), String::new()];
                st.message = "Enter your master password to load the authenticator secret.".into();
            }
            ToolScreen::ChangeEmail | ToolScreen::DeleteAccount => {
                st.fields = vec![String::new(), String::new()];
            }
            ToolScreen::DeviceApprovals => {}
            ToolScreen::Forwarders => {
                st.forwarder_configured = self.forwarder_status();
            }
            ToolScreen::Biometric => {
                st.info_lines = vec![biometric_status_hint(&self.active_profile_id)];
                st.message = if biometric_available() {
                    "Enter toggles enrollment · t tests the prompt".into()
                } else {
                    "Rebuild with `--features biometric` on macOS to enable.".into()
                };
            }
        }
        self.overlay = Overlay::AccountTools(Box::new(st));
        if screen == ToolScreen::DeviceApprovals {
            self.tools_load_approvals().await;
        }
    }

    /// In the username generator: create an alias via SimpleLogin / addy.io when one of those
    /// kinds is selected. Never runs implicitly (each call creates a real alias).
    pub fn fetch_forwarded_alias_if_selected(&mut self) {
        let svc = match &self.overlay {
            Overlay::Generator {
                mode: GeneratorMode::Username,
                username_kind: UsernameKind::SimpleLogin,
                ..
            } => ForwarderService::SimpleLogin,
            Overlay::Generator {
                mode: GeneratorMode::Username,
                username_kind: UsernameKind::AddyIo,
                ..
            } => ForwarderService::AddyIo,
            _ => return,
        };
        let result: Result<String, String> = if self.using_mock {
            Err("mock mode — no forwarder access".into())
        } else {
            match load_forwarder_credentials(&self.active_profile_id, svc) {
                Ok(Some(creds)) => {
                    self.set_status(format!("Creating {} alias…", svc.label()));
                    generate_forwarded_alias_blocking(svc, &creds, "Created by bitwarden-tui")
                }
                Ok(None) => Err(format!(
                    "no {} token — Account settings → a → 7",
                    svc.label()
                )),
                Err(e) => Err(format!("keychain: {e}")),
            }
        };
        match result {
            Ok(alias) => {
                if let Overlay::Generator { preview, .. } = &mut self.overlay {
                    *preview = alias;
                }
                self.set_status(format!("{} alias created", svc.label()));
            }
            Err(e) => {
                if let Overlay::Generator { preview, .. } = &mut self.overlay {
                    *preview = "(alias not created)".into();
                }
                self.set_status(e);
            }
        }
    }

    fn forwarder_status(&self) -> Vec<(ForwarderService, bool)> {
        ForwarderService::ALL
            .iter()
            .map(|s| {
                let ok = matches!(
                    load_forwarder_credentials(&self.active_profile_id, *s),
                    Ok(Some(_))
                );
                (*s, ok)
            })
            .collect()
    }

    async fn tools_load_approvals(&mut self) {
        if let Err(e) = self.tools_live_session() {
            self.tools_msg(e, true);
            return;
        }
        self.busy = true;
        let res = self
            .session
            .as_ref()
            .unwrap()
            .list_incoming_auth_requests()
            .await;
        self.busy = false;
        match res {
            Ok(list) => {
                let n = list.len();
                if let Some(st) = self.tools_mut() {
                    st.incoming = list;
                    st.selected = 0;
                    st.message = if n == 0 {
                        "No pending login requests.".into()
                    } else {
                        "a approve · d deny · r refresh".into()
                    };
                    st.is_error = false;
                }
            }
            Err(e) => self.tools_msg(format!("Could not load requests: {e}"), true),
        }
    }

    /// Enter pressed on a form screen.
    async fn tools_submit(&mut self) {
        let Some(st) = self.tools_mut() else {
            return;
        };
        let screen = st.screen;
        let fields = st.fields.clone();
        let has_authenticator = st.authenticator.is_some();
        let forwarder_edit = st.forwarder_edit;
        if screen == ToolScreen::Forwarders {
            if forwarder_edit.is_some() {
                self.tools_save_forwarder();
            }
            return;
        }
        if let Err(e) = self.tools_live_session() {
            self.tools_msg(e, true);
            return;
        }
        let pw = fields.first().cloned().unwrap_or_default();
        match screen {
            ToolScreen::ChangeKdf => {
                if pw.is_empty() {
                    self.tools_msg("Master password is required", true);
                    return;
                }
                if let Err(e) = Self::tools_kdf_from_fields(&fields) {
                    self.tools_msg(e, true);
                    return;
                }
                self.tools_ask(
                    ToolConfirm::ChangeKdf,
                    "Change KDF now? Vault will lock. y = yes",
                );
            }
            ToolScreen::Deauthorize => {
                if pw.is_empty() {
                    self.tools_msg("Master password is required", true);
                    return;
                }
                self.tools_ask(
                    ToolConfirm::Deauthorize,
                    "Log out ALL sessions including this one? y = yes",
                );
            }
            ToolScreen::TwoFactor => {
                if pw.is_empty() {
                    self.tools_msg("Master password is required", true);
                    return;
                }
                if has_authenticator {
                    self.tools_enable_authenticator().await;
                } else {
                    self.tools_load_authenticator().await;
                }
            }
            ToolScreen::ChangeEmail => {
                if !fields.first().is_some_and(|e| e.contains('@')) {
                    self.tools_msg("Enter a valid new email address", true);
                    return;
                }
                self.tools_ask(
                    ToolConfirm::ChangeEmail,
                    "Continue with email change? y = yes",
                );
            }
            ToolScreen::DeleteAccount => {
                if fields.first().map(|s| s.trim()) != Some("DELETE") {
                    self.tools_msg("Type DELETE (capitals) to continue", true);
                    return;
                }
                self.tools_ask(
                    ToolConfirm::DeleteAccount,
                    "Permanently delete this account? y = yes",
                );
            }
            _ => {}
        }
    }

    fn tools_ask(&mut self, c: ToolConfirm, msg: &str) {
        if let Some(st) = self.tools_mut() {
            st.confirm = Some(c);
            st.message = msg.to_string();
            st.is_error = false;
        }
    }

    fn tools_kdf_from_fields(fields: &[String]) -> Result<KdfParams, String> {
        let argon = fields
            .get(1)
            .is_some_and(|t| t.eq_ignore_ascii_case("argon2id"));
        let iterations = parse_u32(
            fields.get(2).map(String::as_str).unwrap_or(""),
            "Iterations",
        )?;
        let kdf = if argon {
            KdfParams::Argon2id {
                iterations,
                memory_mib: parse_u32(fields.get(3).map(String::as_str).unwrap_or(""), "Memory")?,
                parallelism: parse_u32(
                    fields.get(4).map(String::as_str).unwrap_or(""),
                    "Parallelism",
                )?,
            }
        } else {
            KdfParams::Pbkdf2 { iterations }
        };
        kdf.validate().map_err(|e| e.to_string())?;
        Ok(kdf)
    }

    /// `y` pressed while a confirmation is pending.
    async fn tools_confirmed(&mut self) {
        let Some(st) = self.tools_mut() else {
            return;
        };
        let Some(confirm) = st.confirm.take() else {
            return;
        };
        let fields = st.fields.clone();
        let selected = st.selected;
        let incoming = st.incoming.clone();
        let pw = fields.first().cloned().unwrap_or_default();
        match confirm {
            ToolConfirm::ChangeKdf => {
                let kdf = match Self::tools_kdf_from_fields(&fields) {
                    Ok(k) => k,
                    Err(e) => {
                        self.tools_msg(e, true);
                        return;
                    }
                };
                self.busy = true;
                self.set_status("Changing KDF…");
                let res = self.session.as_mut().unwrap().change_kdf(&pw, kdf).await;
                self.busy = false;
                match res {
                    Ok(()) => {
                        self.lock();
                        self.set_sticky_status(
                            "KDF changed — unlock with your master password (re-login if asked)",
                        );
                    }
                    Err(e) => self.tools_msg(format!("KDF change failed: {e}"), true),
                }
            }
            ToolConfirm::Deauthorize => {
                self.busy = true;
                self.set_status("Deauthorizing sessions…");
                let res = self
                    .session
                    .as_mut()
                    .unwrap()
                    .deauthorize_sessions(&pw)
                    .await;
                self.busy = false;
                match res {
                    Ok(()) => {
                        self.sign_out_current_profile();
                        self.set_status("All sessions deauthorized — log in again");
                    }
                    Err(e) => self.tools_msg(format!("Failed: {e}"), true),
                }
            }
            ToolConfirm::ChangeEmail => self.tools_msg(
                "Stub: email change is not implemented in the TUI yet — use the web vault \
                 (the master-key salt depends on your email, so it needs a careful re-key).",
                false,
            ),
            ToolConfirm::DeleteAccount => self.tools_msg(
                "Stub: account deletion is intentionally not wired up — use the web vault.",
                false,
            ),
            ToolConfirm::ApproveDevice | ToolConfirm::DenyDevice => {
                let Some(req) = incoming.get(selected) else {
                    return;
                };
                let approve = confirm == ToolConfirm::ApproveDevice;
                self.busy = true;
                let res = self
                    .session
                    .as_ref()
                    .unwrap()
                    .answer_auth_request(&req.id, approve)
                    .await;
                self.busy = false;
                match res {
                    Ok(()) => {
                        self.tools_load_approvals().await;
                        self.set_status(if approve {
                            "Login request approved"
                        } else {
                            "Login request denied"
                        });
                    }
                    Err(e) => self.tools_msg(format!("Failed: {e}"), true),
                }
            }
        }
    }

    async fn tools_load_authenticator(&mut self) {
        let pw = self
            .tools_mut()
            .and_then(|s| s.fields.first().cloned())
            .unwrap_or_default();
        self.busy = true;
        let session = self.session.as_ref().unwrap();
        let setup = session.authenticator_setup(&pw).await;
        let providers = session
            .list_two_factor_providers()
            .await
            .unwrap_or_default();
        self.busy = false;
        match setup {
            Ok(info) => {
                let qr = crate::qr::qr_lines(&info.otpauth_uri).unwrap_or_default();
                let enabled: Vec<String> = providers
                    .iter()
                    .filter(|(_, on)| *on)
                    .map(|(t, _)| vault_session::two_factor_provider_name(*t).to_string())
                    .collect();
                if let Some(st) = self.tools_mut() {
                    st.info_lines = vec![
                        format!(
                            "Enabled: {}",
                            if enabled.is_empty() {
                                "none".to_string()
                            } else {
                                enabled.join(", ")
                            }
                        ),
                        format!("Secret: {}", info.secret),
                    ];
                    st.qr_lines = qr;
                    st.authenticator = Some(info);
                    st.focus = 1;
                    st.message =
                        "Scan the QR / enter the secret, then type a code and press Enter.".into();
                    st.is_error = false;
                }
            }
            Err(e) => self.tools_msg(format!("Could not load secret: {e}"), true),
        }
    }

    async fn tools_enable_authenticator(&mut self) {
        let Some(st) = self.tools_mut() else {
            return;
        };
        let pw = st.fields.first().cloned().unwrap_or_default();
        let code = st.fields.get(1).cloned().unwrap_or_default();
        let Some(setup) = st.authenticator.clone() else {
            return;
        };
        if code.trim().len() < 6 {
            self.tools_msg("Enter the 6-digit code from your authenticator", true);
            return;
        }
        self.busy = true;
        let res = self
            .session
            .as_ref()
            .unwrap()
            .enable_authenticator(&pw, &setup, &code)
            .await;
        self.busy = false;
        match res {
            Ok(()) => {
                if let Some(st) = self.tools_mut() {
                    st.authenticator = None;
                    st.qr_lines.clear();
                    st.info_lines = vec!["Authenticator two-step login is enabled.".into()];
                    st.fields = vec![String::new(), String::new()];
                    st.focus = 0;
                    st.message =
                        "Done. Keep your recovery code safe (web vault → Security).".into();
                    st.is_error = false;
                }
            }
            Err(e) => self.tools_msg(format!("Enable failed: {e}"), true),
        }
    }

    fn tools_save_forwarder(&mut self) {
        let profile = self.active_profile_id.clone();
        let Some(st) = self.tools_mut() else {
            return;
        };
        let Some(service) = st.forwarder_edit else {
            return;
        };
        let get = |i: usize| {
            st.fields
                .get(i)
                .map(|s| s.trim().to_string())
                .unwrap_or_default()
        };
        let nonempty = |s: String| (!s.is_empty()).then_some(s);
        let creds = ForwarderCredentials {
            token: get(0),
            base_url: nonempty(get(1)),
            domain: nonempty(get(2)),
        };
        match store_forwarder_credentials(&profile, service, &creds) {
            Ok(()) => {
                let configured = self.forwarder_status();
                if let Some(st) = self.tools_mut() {
                    st.forwarder_edit = None;
                    st.fields.clear();
                    st.forwarder_configured = configured;
                    st.message = format!("{} token saved to the OS keychain.", service.label());
                    st.is_error = false;
                }
            }
            Err(e) => self.tools_msg(format!("Keychain error: {e}"), true),
        }
    }
}

// ---------------------------------------------------------------------------
// Key handling
// ---------------------------------------------------------------------------

fn field_count(st: &AccountToolsState) -> usize {
    tool_fields(st).len()
}

/// Handle a key for `Overlay::AccountTools`. Returns `true` only to request quit (never).
pub async fn account_tools_handle_key(app: &mut App, key: KeyEvent) -> bool {
    let typing = !key
        .modifiers
        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT | KeyModifiers::SUPER);
    let Some(st) = app.tools_mut() else {
        return false;
    };
    if st.confirm.is_some() {
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => app.tools_confirmed().await,
            _ => {
                if let Some(st) = app.tools_mut() {
                    st.confirm = None;
                    st.message = "Cancelled".into();
                }
            }
        }
        return false;
    }
    let screen = st.screen;
    let editing_forwarder = st.forwarder_edit.is_some();

    // Esc / back navigation.
    if key.code == KeyCode::Esc {
        if screen == ToolScreen::Menu {
            app.open_account_settings();
        } else if screen == ToolScreen::Forwarders && editing_forwarder {
            if let Some(st) = app.tools_mut() {
                st.forwarder_edit = None;
                st.fields.clear();
                st.message.clear();
            }
        } else {
            app.tools_open_screen(ToolScreen::Menu).await;
        }
        return false;
    }

    match screen {
        ToolScreen::Menu => match key.code {
            KeyCode::Down | KeyCode::Char('j') => {
                if let Some(st) = app.tools_mut() {
                    st.selected = (st.selected + 1) % TOOL_MENU.len();
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if let Some(st) = app.tools_mut() {
                    st.selected = (st.selected + TOOL_MENU.len() - 1) % TOOL_MENU.len();
                }
            }
            KeyCode::Enter => {
                let idx = app.tools_mut().map(|s| s.selected).unwrap_or(0);
                app.tools_open_screen(screen_for_menu(idx)).await;
            }
            KeyCode::Char(c) if typing => {
                if let Some(idx) = TOOL_MENU.iter().position(|(k, _)| *k == c) {
                    app.tools_open_screen(screen_for_menu(idx)).await;
                }
            }
            _ => {}
        },
        ToolScreen::DeviceApprovals => match key.code {
            KeyCode::Down | KeyCode::Char('j') => {
                if let Some(st) = app.tools_mut() {
                    if !st.incoming.is_empty() {
                        st.selected = (st.selected + 1) % st.incoming.len();
                    }
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if let Some(st) = app.tools_mut() {
                    if !st.incoming.is_empty() {
                        st.selected = (st.selected + st.incoming.len() - 1) % st.incoming.len();
                    }
                }
            }
            KeyCode::Char('r') if typing => app.tools_load_approvals().await,
            KeyCode::Char('a') if typing => {
                if app.tools_mut().is_some_and(|s| !s.incoming.is_empty()) {
                    app.tools_ask(
                        ToolConfirm::ApproveDevice,
                        "Approve ONLY if the fingerprint matches the other device. y = approve",
                    );
                }
            }
            KeyCode::Char('d')
                if typing && app.tools_mut().is_some_and(|s| !s.incoming.is_empty()) =>
            {
                app.tools_ask(ToolConfirm::DenyDevice, "Deny this request? y = deny");
            }
            _ => {}
        },
        ToolScreen::Biometric => match key.code {
            KeyCode::Enter => {
                let profile = app.active_profile_id.clone();
                let res = if biometric_is_enrolled(&profile) {
                    biometric_clear_enrollment(&profile).map(|_| "Biometric enrollment cleared")
                } else {
                    biometric_mark_enrolled(&profile).map(|_| "Biometric enrollment marked")
                };
                match res {
                    Ok(m) => {
                        if let Some(st) = app.tools_mut() {
                            st.info_lines = vec![biometric_status_hint(&profile)];
                            st.message = m.into();
                            st.is_error = false;
                        }
                    }
                    Err(e) => app.tools_msg(e.to_string(), true),
                }
            }
            KeyCode::Char('t') if typing => match biometric_authenticate("Unlock Bitwarden TUI") {
                Ok(()) => app.tools_msg("Biometric check passed", false),
                Err(e) => app.tools_msg(e.to_string(), true),
            },
            _ => {}
        },
        ToolScreen::Forwarders if !editing_forwarder => match key.code {
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Up | KeyCode::Char('k') => {
                if let Some(st) = app.tools_mut() {
                    st.selected = (st.selected + 1) % ForwarderService::ALL.len();
                }
            }
            KeyCode::Enter | KeyCode::Char('e') => {
                if let Some(st) = app.tools_mut() {
                    let svc = ForwarderService::ALL[st.selected % ForwarderService::ALL.len()];
                    st.forwarder_edit = Some(svc);
                    st.fields = vec![String::new(), String::new(), String::new()];
                    st.focus = 0;
                    st.message = format!("Paste your {} API token.", svc.label());
                    st.is_error = false;
                }
            }
            KeyCode::Char('x') if typing => {
                let profile = app.active_profile_id.clone();
                let svc = app
                    .tools_mut()
                    .map(|s| ForwarderService::ALL[s.selected % ForwarderService::ALL.len()]);
                if let Some(svc) = svc {
                    let msg = match delete_forwarder_credentials(&profile, svc) {
                        Ok(()) => format!("{} token removed.", svc.label()),
                        Err(e) => format!("Keychain error: {e}"),
                    };
                    let configured = app.forwarder_status();
                    if let Some(st) = app.tools_mut() {
                        st.forwarder_configured = configured;
                        st.message = msg;
                    }
                }
            }
            _ => {}
        },
        // Form screens (including forwarder editing).
        _ => match key.code {
            KeyCode::Tab | KeyCode::Down => {
                if let Some(st) = app.tools_mut() {
                    let n = field_count(st).max(1);
                    st.focus = (st.focus + 1) % n;
                }
            }
            KeyCode::BackTab | KeyCode::Up => {
                if let Some(st) = app.tools_mut() {
                    let n = field_count(st).max(1);
                    st.focus = (st.focus + n - 1) % n;
                }
            }
            KeyCode::Enter => {
                if !app.busy {
                    app.tools_submit().await;
                }
            }
            KeyCode::Backspace | KeyCode::Delete => {
                if let Some(st) = app.tools_mut() {
                    let f = st.focus;
                    if st.screen == ToolScreen::ChangeKdf && f == 1 {
                        return false;
                    }
                    if let Some(v) = st.fields.get_mut(f) {
                        v.pop();
                    }
                    st.message.clear();
                }
            }
            KeyCode::Left | KeyCode::Right => {
                let _ = toggle_kdf(app);
            }
            KeyCode::Char(' ') if typing => {
                if !toggle_kdf(app) {
                    push_field_char(app, ' ');
                }
            }
            KeyCode::Char(c) if typing => push_field_char(app, c),
            _ => {}
        },
    }
    false
}

/// Toggle PBKDF2 / Argon2id when the KDF row is focused. Returns true when handled.
fn toggle_kdf(app: &mut App) -> bool {
    let Some(st) = app.tools_mut() else {
        return false;
    };
    if st.screen != ToolScreen::ChangeKdf || st.focus != 1 {
        return false;
    }
    let to_argon = !kdf_is_argon(st);
    st.fields[1] = if to_argon { "argon2id" } else { "pbkdf2" }.into();
    if to_argon {
        st.fields[2] = "3".into();
        st.fields[3] = "64".into();
        st.fields[4] = "4".into();
    } else {
        st.fields[2] = "600000".into();
    }
    true
}

fn push_field_char(app: &mut App, c: char) {
    if c.is_control() {
        return;
    }
    if let Some(st) = app.tools_mut() {
        if st.screen == ToolScreen::ChangeKdf && st.focus == 1 {
            return;
        }
        let f = st.focus;
        if let Some(v) = st.fields.get_mut(f) {
            v.push(c);
        }
        st.message.clear();
        st.is_error = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_validation_rejects_low_iterations() {
        let f = vec![
            "pw".to_string(),
            "pbkdf2".into(),
            "10".into(),
            "64".into(),
            "4".into(),
        ];
        assert!(App::tools_kdf_from_fields(&f).is_err());
        let ok = vec![
            "pw".to_string(),
            "pbkdf2".into(),
            "600000".into(),
            "64".into(),
            "4".into(),
        ];
        assert!(App::tools_kdf_from_fields(&ok).is_ok());
    }

    #[test]
    fn menu_covers_all_screens() {
        assert_eq!(TOOL_MENU.len(), 8);
        assert_eq!(screen_for_menu(7), ToolScreen::Biometric);
    }

    #[test]
    fn kdf_fields_depend_on_type() {
        let mut st = AccountToolsState::new(ToolScreen::ChangeKdf);
        st.fields = vec!["".into(), "pbkdf2".into(), "1".into(), "".into(), "".into()];
        assert_eq!(tool_fields(&st).len(), 3);
        st.fields[1] = "argon2id".into();
        assert_eq!(tool_fields(&st).len(), 5);
    }
}
