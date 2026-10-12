//! TUI glue for advanced authentication:
//! 2FA method picker, Duo (browser + loopback), WebAuthn paste mode, new-device OTP,
//! login with device (auth requests) and SSO (PKCE browser flow).
//!
//! Child module of `state` so it can use the app's private helpers.

use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use vault_session::{
    open_url, parse_callback_params, parse_duo_callback, selectable_two_factor_providers,
    two_factor_provider_name, DeviceLoginStatus, LoopbackListener, SessionError, TWO_FACTOR_DUO,
    TWO_FACTOR_EMAIL, TWO_FACTOR_ORG_DUO, TWO_FACTOR_U2F, TWO_FACTOR_WEBAUTHN,
};

use super::*;

const DEVICE_POLL_EVERY: Duration = Duration::from_secs(3);
const DEVICE_LOGIN_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const SSO_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const MAX_POLL_ERRORS: u8 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitKind {
    DeviceApproval,
    Sso,
}

/// "Waiting for another device / the browser" screen state.
#[derive(Debug, Clone)]
pub struct WaitState {
    pub kind: WaitKind,
    /// Fingerprint phrase to compare on the approving device.
    pub fingerprint: String,
    /// Extra line (e.g. SSO URL for manual opening).
    pub detail: String,
    pub started: Instant,
    pub last_poll: Instant,
    pub poll_errors: u8,
    /// Manually pasted callback URL (SSO fallback).
    pub paste: String,
}

/// Extra login state for the advanced flows (single field on `App`).
#[derive(Default)]
pub struct AuthExtState {
    /// Index into [`App::two_factor_choices`].
    pub two_factor_selected: usize,
    /// True when the 2FA screen is asking for the emailed new-device OTP.
    pub new_device_mode: bool,
    pub pending_new_device_otp: Option<String>,
    /// Loopback callback listener (Duo / SSO).
    pub listener: Option<LoopbackListener>,
    pub wait: Option<WaitState>,
    pub sso_callback: Option<(String, Option<String>)>,
}

/// Providers where the "code" is pasted free-form text (URL / JSON / `code|state`).
fn is_freeform_provider(p: u8) -> bool {
    matches!(
        p,
        TWO_FACTOR_DUO | TWO_FACTOR_ORG_DUO | TWO_FACTOR_WEBAUTHN | TWO_FACTOR_U2F
    )
}

impl App {
    // ----- 2FA picker --------------------------------------------------------

    /// Selectable providers in display order (never empty).
    pub fn two_factor_choices(&self) -> Vec<u8> {
        let c = selectable_two_factor_providers(&self.two_factor_providers);
        if c.is_empty() {
            vec![0]
        } else {
            c
        }
    }

    pub fn current_two_factor_provider(&self) -> u8 {
        let c = self.two_factor_choices();
        c[self.auth_ext.two_factor_selected.min(c.len() - 1)]
    }

    /// Provider strip for the 2FA screen, e.g. `‹Authenticator app›  Email  Duo`.
    pub fn two_factor_summary(&self) -> String {
        if self.auth_ext.new_device_mode {
            return "New device verification".into();
        }
        let choices = self.two_factor_choices();
        let cur = self.current_two_factor_provider();
        choices
            .iter()
            .map(|p| {
                let name = two_factor_provider_name(*p);
                let label = format!("{p} {name}");
                if *p == cur && choices.len() > 1 {
                    format!("‹{label}›")
                } else {
                    label
                }
            })
            .collect::<Vec<_>>()
            .join("  ")
    }

    /// Context hint under the code field.
    pub fn two_factor_hint(&self) -> String {
        if self.auth_ext.new_device_mode {
            return "Enter the verification code emailed to you".into();
        }
        match self.current_two_factor_provider() {
            TWO_FACTOR_EMAIL => {
                let masked = self
                    .session
                    .as_ref()
                    .and_then(|s| s.email_two_factor_hint())
                    .map(|e| format!(" to {e}"))
                    .unwrap_or_default();
                format!("Enter the emailed code{masked} · m resend")
            }
            TWO_FACTOR_DUO | TWO_FACTOR_ORG_DUO => {
                let has_url = self
                    .session
                    .as_ref()
                    .and_then(|s| s.duo_auth_url(self.current_two_factor_provider()))
                    .is_some();
                if has_url {
                    "Open Duo (Ctrl+o), approve, then paste the redirected URL or code|state".into()
                } else {
                    "Complete Duo approval in the web vault, then paste the code if prompted".into()
                }
            }
            TWO_FACTOR_WEBAUTHN => {
                if vault_session::webauthn_supported() {
                    "Touch your security key".into()
                } else {
                    "Hardware keys unsupported — paste a WebAuthn assertion JSON, or Tab to another method".into()
                }
            }
            TWO_FACTOR_U2F => "Legacy U2F is not supported — Tab to another method".into(),
            3 => "Touch your YubiKey to type its OTP".into(),
            _ => "Enter the code from your authenticator".into(),
        }
    }

    pub fn cycle_two_factor(&mut self, forward: bool) {
        let n = self.two_factor_choices().len();
        if n <= 1 {
            return;
        }
        let cur = self.auth_ext.two_factor_selected.min(n - 1);
        self.auth_ext.two_factor_selected = if forward {
            (cur + 1) % n
        } else {
            (cur + n - 1) % n
        };
        self.totp_code.clear();
        self.form_error = None;
        self.auth_ext.listener = None;
        let p = self.current_two_factor_provider();
        self.set_status(format!("2FA method: {}", two_factor_provider_name(p)));
        if p == TWO_FACTOR_EMAIL && !self.password.is_empty() {
            // The server only auto-sends the code for the default provider.
            self.queue(PendingAction::ResendEmail2fa);
        }
    }

    /// Open the Duo auth URL in the browser and listen for a localhost redirect.
    pub fn open_duo_browser(&mut self) {
        let provider = self.current_two_factor_provider();
        if !matches!(provider, TWO_FACTOR_DUO | TWO_FACTOR_ORG_DUO) {
            self.set_status("Duo is not the selected 2FA method");
            return;
        }
        let Some(url) = self.session.as_ref().and_then(|s| s.duo_auth_url(provider)) else {
            self.set_status(
                "Server sent no Duo URL — approve via the web vault and paste the code",
            );
            return;
        };
        self.auth_ext.listener = LoopbackListener::start(Duration::from_secs(300)).ok();
        match open_url(&url) {
            Ok(()) => {
                self.set_status("Opened Duo — paste the redirected URL or code|state, then Enter")
            }
            Err(e) => self.set_status(format!("{e} — open manually: {url}")),
        }
    }

    /// Normalize the typed code for the selected provider; `None` = error already shown.
    pub(super) fn prepare_two_factor_code(&mut self, provider: u8, code: String) -> Option<String> {
        match provider {
            TWO_FACTOR_DUO | TWO_FACTOR_ORG_DUO => match parse_duo_callback(&code) {
                Some(tok) => Some(tok),
                None if code.contains('|') => Some(code),
                None => {
                    self.form_error =
                        Some("Paste the redirected URL (…?code=…&state=…) or code|state".into());
                    None
                }
            },
            TWO_FACTOR_U2F => {
                self.form_error = Some("U2F is not supported — choose another method (Tab)".into());
                None
            }
            _ => Some(code),
        }
    }

    // ----- New-device OTP ----------------------------------------------------

    pub(super) fn enter_new_device_mode(&mut self) {
        self.auth_ext.new_device_mode = true;
        self.two_factor_providers.clear();
        self.auth_ext.two_factor_selected = 0;
        self.totp_code.clear();
        self.form_error = None;
        self.screen = Screen::TwoFactor;
        self.set_status("New device — enter the code emailed to you");
    }

    /// Retry the password login with the emailed OTP.
    pub(super) async fn submit_new_device_otp(&mut self) {
        let otp = self.totp_code.trim().to_string();
        self.auth_ext.pending_new_device_otp = Some(otp);
        self.auth_ext.new_device_mode = false;
        self.totp_code.clear();
        self.submit_login().await;
        // submit_login only moves screens on success / 2FA / new-device. On any other
        // failure fall back to the login form so the user sees the error.
        if self.screen == Screen::TwoFactor
            && !self.auth_ext.new_device_mode
            && self.two_factor_providers.is_empty()
        {
            self.screen = Screen::Login;
        }
    }

    // ----- Shared completion -------------------------------------------------

    fn finish_login_success(&mut self) {
        let server = self.server_url.trim().to_string();
        let email = self.email.trim().to_string();
        self.password.zeroize();
        self.persist_login_prefs(&server, &email);
        self.apply_auto_lock_from_profile();
        self.apply_clipboard_clear_from_profile();
        self.reload_from_session();
        self.screen = Screen::Vault;
        self.locked_at = None;
        self.mark_synced();
        self.show_last_synced_status();
        self.touch();
    }

    fn prepare_browserless_login(&mut self) -> Option<(String, String)> {
        self.form_error = None;
        let email = self.email.trim().to_string();
        if email.is_empty() {
            self.form_error = Some("Email is required".into());
            return None;
        }
        if self.using_mock {
            self.form_error = Some("Not available in mock mode".into());
            return None;
        }
        let server = match normalize_server_url(&self.server_url) {
            Ok(s) => s,
            Err(e) => {
                self.form_error = Some(e.to_string());
                return None;
            }
        };
        self.server_url = server.clone();
        Some((server, email))
    }

    pub(super) fn leave_auth_wait(&mut self) {
        if let Some(s) = self.session.as_mut() {
            s.cancel_device_login();
        }
        self.auth_ext.wait = None;
        self.auth_ext.listener = None;
        self.auth_ext.sso_callback = None;
        // A half-open session has no credentials yet.
        if self
            .session
            .as_ref()
            .is_some_and(|s| s.status() == SessionStatus::LoggedOut)
        {
            self.session = None;
        }
        self.screen = Screen::Login;
    }

    // ----- Login with device -------------------------------------------------

    pub async fn start_device_login(&mut self) {
        let Some((server, email)) = self.prepare_browserless_login() else {
            return;
        };
        self.busy = true;
        self.set_status("Creating login request…");
        let mut session = match Session::with_data_dir(&server, self.profile_data_dir()) {
            Ok(s) => s,
            Err(e) => {
                self.busy = false;
                self.form_error = Some(e.to_string());
                return;
            }
        };
        self.configure_session_persist(&mut session);
        match session.start_device_login(&email).await {
            Ok(start) => {
                self.session = Some(session);
                let now = Instant::now();
                self.auth_ext.wait = Some(WaitState {
                    kind: WaitKind::DeviceApproval,
                    fingerprint: start.fingerprint,
                    detail: format!("Request {}", start.request_id),
                    started: now,
                    last_poll: now,
                    poll_errors: 0,
                    paste: String::new(),
                });
                self.screen = Screen::AuthWait;
                self.set_status("Approve this login on another device");
            }
            Err(e) => {
                self.form_error = Some(format!("Login with device failed: {e}"));
                self.set_status("Login with device failed");
            }
        }
        self.busy = false;
    }

    pub async fn poll_device_login(&mut self) {
        let Some(session) = self.session.as_mut() else {
            self.leave_auth_wait();
            return;
        };
        match session.poll_device_login().await {
            Ok(DeviceLoginStatus::Waiting) => {
                if let Some(w) = self.auth_ext.wait.as_mut() {
                    w.poll_errors = 0;
                }
            }
            Ok(DeviceLoginStatus::Denied) => {
                self.leave_auth_wait();
                self.form_error = Some("Login request was denied".into());
                self.set_status("Login request denied");
            }
            Ok(DeviceLoginStatus::Approved) => {
                self.auth_ext.wait = None;
                self.finish_login_success();
            }
            Err(SessionError::TwoFactorRequired { .. }) => {
                self.leave_auth_wait();
                self.form_error =
                    Some("This account requires two-factor — use password login".into());
            }
            Err(e) => {
                let give_up = self.auth_ext.wait.as_mut().is_some_and(|w| {
                    w.poll_errors += 1;
                    w.poll_errors >= MAX_POLL_ERRORS
                });
                if give_up {
                    self.leave_auth_wait();
                    self.form_error = Some(format!("Login with device failed: {e}"));
                } else {
                    self.set_status(format!("Waiting… ({e})"));
                }
            }
        }
    }

    // ----- SSO ---------------------------------------------------------------

    pub async fn start_sso(&mut self) {
        let Some((server, email)) = self.prepare_browserless_login() else {
            return;
        };
        let listener = match LoopbackListener::start(SSO_TIMEOUT) {
            Ok(l) => l,
            Err(e) => {
                self.form_error = Some(format!("Cannot open local callback port: {e}"));
                return;
            }
        };
        let mut session = match Session::with_data_dir(&server, self.profile_data_dir()) {
            Ok(s) => s,
            Err(e) => {
                self.form_error = Some(e.to_string());
                return;
            }
        };
        self.configure_session_persist(&mut session);
        let start = match session.begin_sso(&email, &listener.redirect_uri()) {
            Ok(s) => s,
            Err(e) => {
                self.form_error = Some(e.to_string());
                return;
            }
        };
        let opened = open_url(&start.url);
        self.session = Some(session);
        self.auth_ext.listener = Some(listener);
        self.auth_ext.sso_callback = None;
        let now = Instant::now();
        self.auth_ext.wait = Some(WaitState {
            kind: WaitKind::Sso,
            fingerprint: String::new(),
            detail: start.url,
            started: now,
            last_poll: now,
            poll_errors: 0,
            paste: String::new(),
        });
        self.screen = Screen::AuthWait;
        match opened {
            Ok(()) => self.set_status("Complete SSO in your browser"),
            Err(e) => self.set_status(format!("{e} — open the URL shown manually")),
        }
    }

    pub async fn finish_sso(&mut self) {
        let Some((code, state)) = self.auth_ext.sso_callback.take() else {
            return;
        };
        self.busy = true;
        self.set_status("Finishing SSO…");
        let result = match self.session.as_mut() {
            Some(s) => s.finish_sso(&code, state.as_deref()).await,
            None => Err(SessionError::NotLoggedIn),
        };
        match result {
            Ok(()) => {
                let server = self.server_url.trim().to_string();
                let email = self.email.trim().to_string();
                self.persist_login_prefs(&server, &email);
                self.auth_ext.wait = None;
                self.auth_ext.listener = None;
                self.apply_auto_lock_from_profile();
                self.unlock_password.zeroize();
                self.screen = Screen::Unlock;
                self.locked_at = Some(Instant::now());
                self.set_status("SSO complete — enter master password to unlock");
            }
            Err(e) => {
                self.leave_auth_wait();
                self.form_error = Some(format!("SSO failed: {e}"));
                self.set_status("SSO failed");
            }
        }
        self.busy = false;
    }

    /// Submit a manually pasted SSO callback URL from the wait screen.
    fn submit_sso_paste(&mut self) {
        let text = self
            .auth_ext
            .wait
            .as_ref()
            .map(|w| w.paste.trim().to_string())
            .unwrap_or_default();
        match parse_callback_params(&text) {
            Some((code, state)) => {
                self.auth_ext.sso_callback = Some((code, state));
                self.queue(PendingAction::SsoFinish);
            }
            None => self.set_status("No code= found in the pasted text"),
        }
    }

    // ----- Tick --------------------------------------------------------------

    /// Called from `on_tick`: drain callbacks, schedule device-login polls, enforce timeouts.
    pub(super) fn auth_ext_tick(&mut self) {
        let got = self.auth_ext.listener.as_ref().and_then(|l| l.try_recv());
        if let Some(target) = got {
            match self.screen {
                Screen::TwoFactor => {
                    if let Some(tok) = parse_duo_callback(&target) {
                        self.totp_code = tok;
                        self.auth_ext.listener = None;
                        self.queue(PendingAction::TwoFactor);
                    }
                }
                Screen::AuthWait => {
                    if let Some((code, state)) = parse_callback_params(&target) {
                        self.auth_ext.sso_callback = Some((code, state));
                        self.auth_ext.listener = None;
                        self.queue(PendingAction::SsoFinish);
                    }
                }
                _ => {}
            }
        }

        if self.screen != Screen::AuthWait || self.busy || self.pending.is_some() {
            return;
        }
        let Some(w) = self.auth_ext.wait.as_mut() else {
            return;
        };
        let now = Instant::now();
        match w.kind {
            WaitKind::DeviceApproval => {
                if now.duration_since(w.started) >= DEVICE_LOGIN_TIMEOUT {
                    self.leave_auth_wait();
                    self.form_error = Some("Login request timed out".into());
                } else if now.duration_since(w.last_poll) >= DEVICE_POLL_EVERY {
                    w.last_poll = now;
                    self.queue(PendingAction::DeviceLoginPoll);
                }
            }
            WaitKind::Sso => {
                if now.duration_since(w.started) >= SSO_TIMEOUT {
                    self.leave_auth_wait();
                    self.form_error = Some("SSO timed out".into());
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Key handling (called from events.rs before the stock handlers)
// ---------------------------------------------------------------------------

/// Extra keys on the login screen. Returns true when handled.
pub fn auth_ext_handle_login_key(app: &mut App, key: &KeyEvent) -> bool {
    if !key.modifiers.contains(KeyModifiers::CONTROL) {
        return false;
    }
    match key.code {
        KeyCode::Char('d') => {
            app.queue(PendingAction::DeviceLoginStart);
            true
        }
        KeyCode::Char('o') => {
            app.queue(PendingAction::SsoStart);
            true
        }
        _ => false,
    }
}

/// Extra keys on the 2FA screen. Returns true when handled.
pub fn auth_ext_handle_2fa_key(app: &mut App, key: &KeyEvent) -> bool {
    let typing = !key
        .modifiers
        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT | KeyModifiers::SUPER);
    let new_device = app.auth_ext.new_device_mode;
    let provider = app.current_two_factor_provider();
    match key.code {
        KeyCode::Esc => {
            app.auth_ext.new_device_mode = false;
            app.auth_ext.pending_new_device_otp = None;
            app.auth_ext.listener = None;
            false // stock handler returns to the login screen
        }
        KeyCode::Tab if !new_device => {
            app.cycle_two_factor(true);
            true
        }
        KeyCode::BackTab if !new_device => {
            app.cycle_two_factor(false);
            true
        }
        KeyCode::Char('j') | KeyCode::Down if typing && !new_device => {
            app.cycle_two_factor(true);
            true
        }
        KeyCode::Char('k') | KeyCode::Up if typing && !new_device => {
            app.cycle_two_factor(false);
            true
        }
        KeyCode::Right if !new_device => {
            app.cycle_two_factor(true);
            true
        }
        KeyCode::Left if !new_device => {
            app.cycle_two_factor(false);
            true
        }
        KeyCode::Char('o') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.open_duo_browser();
            true
        }
        KeyCode::Char(c) if typing && !new_device && is_freeform_provider(provider) => {
            if !c.is_control() {
                app.totp_code.push(c);
                app.form_error = None;
            }
            true
        }
        // Stock handler binds `m` to "resend email code"; only meaningful for email 2FA.
        KeyCode::Char('m') if typing && (new_device || provider != TWO_FACTOR_EMAIL) => true,
        _ => false,
    }
}

/// Keys on the "waiting for approval / browser" screen.
pub fn auth_ext_handle_wait_key(app: &mut App, key: &KeyEvent) -> bool {
    let typing = !key
        .modifiers
        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT | KeyModifiers::SUPER);
    let kind = app.auth_ext.wait.as_ref().map(|w| w.kind);
    match key.code {
        KeyCode::Esc => {
            app.leave_auth_wait();
            app.set_status("Cancelled");
        }
        KeyCode::Enter if kind == Some(WaitKind::Sso) => app.submit_sso_paste(),
        KeyCode::Backspace | KeyCode::Delete => {
            if let Some(w) = app.auth_ext.wait.as_mut() {
                w.paste.pop();
            }
        }
        KeyCode::Char(c) if typing && kind == Some(WaitKind::Sso) && !c.is_control() => {
            if let Some(w) = app.auth_ext.wait.as_mut() {
                w.paste.push(c);
            }
        }
        _ => {}
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn freeform_providers() {
        assert!(is_freeform_provider(TWO_FACTOR_DUO));
        assert!(is_freeform_provider(TWO_FACTOR_WEBAUTHN));
        assert!(!is_freeform_provider(0));
        assert!(!is_freeform_provider(TWO_FACTOR_EMAIL));
    }
}
