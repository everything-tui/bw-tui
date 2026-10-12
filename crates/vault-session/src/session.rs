use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use chrono::{DateTime, FixedOffset};
use totp_rs::{Algorithm, Secret, TOTP};
use vault_api::{
    is_insecure_http, ChangePasswordRequest, CipherCard, CipherIdentity, CipherLogin,
    CipherPartialRequest, CipherRequest, CipherSecureNote, CipherSshKey, ClientConfig, LoginUri,
    PasswordHistoryEntry, RegisterKeys, RegisterRequest, VaultClient,
};
use vault_crypto::{
    auth_hash, decrypt_bytes, decrypt_private_key, decrypt_with_key, derive_master_key,
    encrypt_bytes, encrypt_with_key, generate_rsa_keypair, generate_user_key, unwrap_user_key,
    wrap_user_key, KdfParams, MasterKey, SymmetricCryptoKey, UserKey,
};
use zeroize::Zeroize;

use crate::clipboard::ClipboardService;
use crate::decrypt::{build_index, resolve_cipher_key};
use crate::domains::parse_domains;
use crate::error::{Result, SessionError};
use crate::fingerprint::fingerprint_phrase_from_public_der;
use crate::models::*;
use crate::paths::{app_data_dir, ensure_dir, write_atomic};
use crate::pin::{clear_pin, pin_configured, store_pin_wrapped_key, unlock_with_pin};
use crate::policies::{
    clear_policies, effective_timeout_action, effective_timeout_minutes, generator_policy,
    load_policies, master_password_policy, parse_policies, personal_vault_disabled,
    pin_unlock_disabled, restricted_item_types, save_policies, send_policy, vault_timeout_policy,
    GeneratorPolicy, MasterPasswordPolicy, Policy, SendPolicy, TimeoutAction, VaultTimeoutPolicy,
};
use crate::secure_storage::{
    delete_refresh_token_best_effort, get_refresh_token, profile_id_from_data_dir,
    set_refresh_token,
};
use crate::send::{
    build_send_request, format_file_size, ReceivedSend, SendOptions, SendRequestInput,
    MAX_SEND_FILE_BYTES, SEND_TYPE_FILE, SEND_TYPE_TEXT,
};
use crate::ssh_agent::{parse_ssh_key_item, start_agent_with_keys, ParsedSshKey, SshAgentHandle};
use crate::vault_cache;

/// Result of [`Session::sync_if_changed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncOutcome {
    /// Server revision matched; no `/sync` request was made.
    Unchanged,
    /// A full sync ran and the in-memory vault was rebuilt.
    Synced,
}

/// True when the vault must be re-fetched: no stored revision, or the server's differs.
pub(crate) fn revision_changed(stored: Option<i64>, remote: i64) -> bool {
    stored != Some(remote)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStatus {
    LoggedOut,
    Locked,
    Unlocked,
}

#[derive(Debug, Clone)]
pub enum LoginResult {
    Success,
    TwoFactorRequired { providers: Vec<u8> },
}

/// Profile `allow_plaintext_token` or env `BW_ALLOW_PLAINTEXT_TOKEN` (`1` / `true` / `yes`).
pub fn plaintext_token_allowed(profile_allow_plaintext: bool) -> bool {
    if profile_allow_plaintext {
        return true;
    }
    match std::env::var("BW_ALLOW_PLAINTEXT_TOKEN") {
        Ok(v) => {
            let t = v.trim();
            t == "1" || t.eq_ignore_ascii_case("true") || t.eq_ignore_ascii_case("yes")
        }
        Err(_) => false,
    }
}

mod auth_flows;
mod org;
mod power;

pub use auth_flows::{
    pkce_pair, AuthenticatorSetupInfo, DeviceLoginStart, DeviceLoginStatus, IncomingAuthRequest,
    SsoStart,
};

pub struct Session {
    client: VaultClient,
    email: Option<String>,
    user_id: Option<String>,
    protected_key: Option<String>,
    private_key_enc: Option<String>,
    user_key: Option<UserKey>,
    master_key: Option<MasterKey>,
    /// Cached KDF params from last successful prelogin (for offline unlock).
    kdf: Option<KdfParams>,
    index: VaultIndex,
    status: SessionStatus,
    last_activity: Instant,
    /// Profile-requested idle timeout. `None` = never (org policy may still impose a max).
    auto_lock: Option<Duration>,
    /// Profile-requested action when the timeout fires (org policy may override).
    timeout_action: TimeoutAction,
    pub clipboard: ClipboardService,
    data_dir: PathBuf,
    /// True when the in-memory vault came from the encrypted offline cache.
    offline: bool,
    last_synced_at: Option<DateTime<FixedOffset>>,
    /// Server account revision (epoch ms) observed just before the last full sync.
    /// `None` forces the next [`Session::sync_if_changed`] to do a full sync.
    revision_ms: Option<i64>,
    allow_plaintext_token: bool,
    /// Set when refresh token was written to disk because secure storage failed.
    pub storage_warning: Option<String>,
    insecure_http: bool,
    two_factor_device_token: Option<String>,
    /// Advanced auth state (2FA details, device login, SSO). See `auth_flows`.
    auth_ext: auth_flows::AuthExtSession,
    ssh_agent: Option<SshAgentHandle>,
    policies: Vec<Policy>,
    global_equivalent_domains: Vec<String>,
    equivalent_domain_groups: Vec<Vec<String>>,
    /// Give newly created items their own random cipher key.
    item_keys_on_create: bool,
}

impl Session {
    /// Create a session using the default app data directory (legacy / tests).
    pub fn new(server_url: &str) -> Result<Self> {
        Self::with_data_dir(server_url, app_data_dir())
    }

    /// Create a session that persists auth under `data_dir` (typically a profile directory).
    pub fn with_data_dir(server_url: &str, data_dir: PathBuf) -> Result<Self> {
        let client = VaultClient::new(ClientConfig::new(server_url)?)?;
        let _ = ensure_dir(&data_dir);
        Ok(Self {
            client,
            email: None,
            user_id: None,
            protected_key: None,
            private_key_enc: None,
            user_key: None,
            master_key: None,
            kdf: None,
            index: VaultIndex::default(),
            status: SessionStatus::LoggedOut,
            last_activity: Instant::now(),
            auto_lock: Some(Duration::from_secs(15 * 60)),
            timeout_action: TimeoutAction::Lock,
            clipboard: ClipboardService::new(30),
            last_synced_at: vault_cache::synced_at(&data_dir),
            offline: false,
            revision_ms: None,
            allow_plaintext_token: false,
            storage_warning: None,
            insecure_http: is_insecure_http(server_url),
            two_factor_device_token: None,
            auth_ext: auth_flows::AuthExtSession::default(),
            ssh_agent: None,
            policies: load_policies(&data_dir),
            global_equivalent_domains: Vec::new(),
            equivalent_domain_groups: Vec::new(),
            item_keys_on_create: true,
            data_dir,
        })
    }

    pub fn set_allow_plaintext_token(&mut self, allow: bool) {
        self.allow_plaintext_token = allow;
    }

    pub fn server_uses_insecure_http(&self) -> bool {
        self.insecure_http
    }

    pub fn clear_clipboard_if_ours(&mut self) {
        self.clipboard.clear_if_ours();
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    fn user_id(&self) -> Result<&str> {
        self.user_id
            .as_deref()
            .ok_or_else(|| SessionError::Other("missing user id — sync first".into()))
    }

    pub fn server_url(&self) -> &str {
        self.client.base_url()
    }

    pub fn email(&self) -> Option<&str> {
        self.email.as_deref()
    }

    pub fn status(&self) -> SessionStatus {
        self.status
    }

    pub fn is_offline(&self) -> bool {
        self.offline
    }

    /// Cached account KDF parameters (for encrypted export).
    pub fn account_kdf(&self) -> Option<KdfParams> {
        self.kdf.clone()
    }

    pub fn last_synced_at(&self) -> Option<DateTime<FixedOffset>> {
        self.last_synced_at
            .or_else(|| vault_cache::synced_at(&self.data_dir))
    }

    pub fn index(&self) -> &VaultIndex {
        &self.index
    }

    fn ensure_online(&self) -> Result<()> {
        if self.offline {
            Err(SessionError::Offline)
        } else {
            Ok(())
        }
    }

    fn remember_kdf(&mut self, kdf: KdfParams) {
        self.kdf = Some(kdf);
    }

    fn apply_sync_profile(&mut self, sync: &vault_api::SyncResponse) {
        if let Some(profile) = &sync.profile {
            self.user_id = Some(profile.id.clone());
            if let Some(k) = &profile.key {
                self.protected_key = Some(k.clone());
            }
            if let Some(pk) = &profile.private_key {
                self.private_key_enc = Some(pk.clone());
            }
            if let Some(email) = &profile.email {
                self.email = Some(email.clone());
            }
        }
    }

    fn apply_sync_metadata(&mut self, sync: &vault_api::SyncResponse) {
        self.policies = parse_policies(&sync.policies);
        if let Err(e) = save_policies(&self.data_dir, &self.policies) {
            tracing::warn!(error = %e, "failed to persist organization policies");
        }
        // Org policy type 14: drop any previously configured PIN.
        if pin_unlock_disabled(&self.policies) && pin_configured(&self.data_dir) {
            clear_pin(&self.data_dir);
        }
        if let Some(domains) = &sync.domains {
            match parse_domains(domains, self.user_key.as_ref()) {
                Ok(parsed) => {
                    self.global_equivalent_domains = parsed.global_equivalent;
                    self.equivalent_domain_groups = parsed.equivalent_groups;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to parse sync domains");
                }
            }
        }
    }

    pub fn policies(&self) -> &[Policy] {
        &self.policies
    }

    pub fn generator_policy(&self) -> GeneratorPolicy {
        generator_policy(&self.policies)
    }

    pub fn send_policy(&self) -> SendPolicy {
        send_policy(&self.policies)
    }

    pub fn send_creation_allowed(&self) -> bool {
        !self.send_policy().send_disabled
    }

    /// Org vault timeout restrictions (type 9).
    pub fn vault_timeout_policy(&self) -> VaultTimeoutPolicy {
        vault_timeout_policy(&self.policies)
    }

    /// Org master-password requirements (type 1).
    pub fn master_password_policy(&self) -> MasterPasswordPolicy {
        master_password_policy(&self.policies)
    }

    /// Org policy type 14 — PIN unlock disallowed.
    pub fn pin_unlock_blocked_by_policy(&self) -> bool {
        pin_unlock_disabled(&self.policies)
    }

    /// Org policy type 5 — personal vault items disallowed.
    pub fn personal_vault_blocked_by_policy(&self) -> bool {
        personal_vault_disabled(&self.policies)
    }

    /// Org policy type 15 — Bitwarden cipher type numbers that may not be created.
    pub fn restricted_item_type_numbers(&self) -> Vec<u8> {
        restricted_item_types(&self.policies)
    }

    /// Whether an item of `item_type` may be created (personal vault + restricted types).
    pub fn check_item_creation_allowed(&self, item_type: ItemType) -> Result<()> {
        if personal_vault_disabled(&self.policies) {
            return Err(SessionError::PolicyViolation(
                "personal vault is disabled — items must be owned by an organization".into(),
            ));
        }
        let n = match item_type {
            ItemType::Login => 1,
            ItemType::SecureNote => 2,
            ItemType::Card => 3,
            ItemType::Identity => 4,
            ItemType::SshKey => 5,
            ItemType::Unknown => return Ok(()),
        };
        if restricted_item_types(&self.policies).contains(&n) {
            return Err(SessionError::PolicyViolation(format!(
                "creating {} items is restricted",
                item_type_label(item_type)
            )));
        }
        Ok(())
    }

    pub fn uri_equivalent_groups(&self) -> Vec<Vec<String>> {
        let mut out = self.equivalent_domain_groups.clone();
        if !self.global_equivalent_domains.is_empty() {
            out.insert(0, self.global_equivalent_domains.clone());
        }
        out
    }

    fn load_from_cache(&mut self) -> Result<()> {
        let (sync, synced_at) = {
            let user_key = self.user_key.as_ref().ok_or(SessionError::Locked)?;
            vault_cache::load(&self.data_dir, user_key, self.user_id.as_deref())?
        };
        self.apply_sync_profile(&sync);
        {
            let user_key = self.user_key.as_ref().ok_or(SessionError::Locked)?;
            self.index = build_index(&sync, user_key)?;
        }
        self.apply_sync_metadata(&sync);
        self.last_synced_at = Some(synced_at);
        self.offline = true;
        self.touch();
        Ok(())
    }

    fn write_cache(&mut self, sync: &vault_api::SyncResponse) {
        let Some(user_key) = self.user_key.as_ref() else {
            return;
        };
        let Some(user_id) = sync
            .profile
            .as_ref()
            .map(|p| p.id.as_str())
            .or(self.user_id.as_deref())
        else {
            return;
        };
        match vault_cache::save(&self.data_dir, sync, user_key, user_id) {
            Ok(synced_at) => {
                self.last_synced_at = Some(synced_at);
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to write encrypted vault cache");
            }
        }
    }

    /// Set the profile's idle auto-lock timeout in minutes. `None` = never.
    /// The effective value is still capped by org policy type 9.
    pub fn set_auto_lock(&mut self, minutes: Option<u64>) {
        self.auto_lock = minutes.map(|m| Duration::from_secs(m.saturating_mul(60)));
    }

    /// Set the profile's preferred timeout action (org policy may override).
    pub fn set_timeout_action(&mut self, action: TimeoutAction) {
        self.timeout_action = action;
    }

    /// Idle timeout in minutes after applying the org maximum (`None` = never).
    pub fn effective_auto_lock_minutes(&self) -> Option<u64> {
        let profile = self.auto_lock.map(|d| (d.as_secs() / 60).max(1));
        effective_timeout_minutes(profile, &self.vault_timeout_policy())
    }

    /// Timeout action after applying org policy.
    pub fn effective_timeout_action(&self) -> TimeoutAction {
        effective_timeout_action(self.timeout_action, &self.vault_timeout_policy())
    }

    fn effective_auto_lock(&self) -> Option<Duration> {
        let policy = self.vault_timeout_policy();
        match (self.auto_lock, policy.max_minutes) {
            (Some(d), Some(m)) => Some(d.min(Duration::from_secs(m.saturating_mul(60)))),
            (None, Some(m)) => Some(Duration::from_secs(m.saturating_mul(60))),
            (d, None) => d,
        }
    }

    /// Apply the effective timeout action now (idle expiry, system lock / sleep).
    /// Returns the action performed.
    pub fn apply_timeout_action(&mut self) -> TimeoutAction {
        let action = self.effective_timeout_action();
        match action {
            TimeoutAction::Lock => self.lock(),
            TimeoutAction::Logout => self.logout(),
        }
        action
    }

    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    pub fn lock_remaining(&self) -> Option<Duration> {
        if self.status != SessionStatus::Unlocked {
            return None;
        }
        let timeout = self.effective_auto_lock()?;
        Some(timeout.saturating_sub(self.last_activity.elapsed()))
    }

    /// Periodic maintenance. Returns the timeout action if the idle timeout just fired.
    pub fn tick(&mut self) -> Option<TimeoutAction> {
        self.clipboard.tick();
        let timeout = self.effective_auto_lock()?;
        if self.status == SessionStatus::Unlocked && self.last_activity.elapsed() >= timeout {
            return Some(self.apply_timeout_action());
        }
        None
    }

    pub fn lock(&mut self) {
        self.stop_ssh_agent();
        self.clipboard.clear_if_ours();
        self.user_key = None;
        if let Some(mk) = self.master_key.as_mut() {
            let _ = mk; // ZeroizeOnDrop
        }
        self.master_key = None;
        self.revision_ms = None;
        self.index = VaultIndex::default();
        if self.status == SessionStatus::Unlocked {
            self.status = SessionStatus::Locked;
        }
    }

    pub async fn register(
        &mut self,
        email: &str,
        password: &str,
        name: Option<&str>,
    ) -> Result<()> {
        let kdf = vault_crypto::KdfParams::Pbkdf2 {
            iterations: 600_000,
        };
        let master = derive_master_key(password, email, &kdf)?;
        let hash = auth_hash(&master, password)?;
        let user_key = generate_user_key();
        let protected = wrap_user_key(&user_key, &master)?;
        let rsa = generate_rsa_keypair()?;
        let enc_private = encrypt_bytes(&rsa.private_key_der, &user_key)?;

        let req = RegisterRequest {
            email: email.to_string(),
            name: name.map(str::to_string),
            master_password_hash: hash.as_str().to_string(),
            master_password_hint: None,
            key: protected,
            kdf: Some(0),
            kdf_iterations: Some(600_000),
            kdf_memory: None,
            kdf_parallelism: None,
            keys: Some(RegisterKeys {
                public_key: rsa.public_key_b64,
                encrypted_private_key: enc_private,
            }),
            email_verification_token: None,
        };
        match self.client.register(&req).await {
            Ok(()) => Ok(()),
            Err(vault_api::ApiError::Other(msg)) if msg.contains("already exists") => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    pub async fn login(
        &mut self,
        email: &str,
        password: &str,
        two_factor: Option<(u8, &str)>,
    ) -> Result<LoginResult> {
        self.login_with_2fa_options(email, password, two_factor, false)
            .await
    }

    /// Login with optional 2FA and "remember this device".
    pub async fn login_with_2fa_options(
        &mut self,
        email: &str,
        password: &str,
        two_factor: Option<(u8, &str)>,
        remember_device: bool,
    ) -> Result<LoginResult> {
        let prelogin = self.client.prelogin(email).await?;
        let kdf = prelogin.to_kdf_params();
        self.remember_kdf(kdf.clone());
        let master = derive_master_key(password, email, &kdf)?;
        let hash = auth_hash(&master, password)?;

        let two = two_factor.map(|(p, t)| (p, t, remember_device));
        let remembered = self.two_factor_device_token.as_deref();
        match self
            .client
            .login(email, hash.as_str(), two, remembered)
            .await
        {
            Ok(token) => {
                self.client.set_new_device_otp(None);
                self.auth_ext.two_factor_raw = None;
                if let Some(dt) = token.two_factor_token.filter(|t| !t.is_empty()) {
                    self.two_factor_device_token = Some(dt);
                }
                self.email = Some(email.to_string());
                self.protected_key = token.key.clone().or_else(|| {
                    token.user_decryption_options.as_ref().and_then(|v| {
                        v.pointer("/MasterPasswordUnlock/MasterKeyEncryptedUserKey")
                            .and_then(|x| x.as_str())
                            .map(str::to_string)
                    })
                });
                self.private_key_enc = token.private_key.clone();
                self.master_key = Some(master);
                self.status = SessionStatus::Locked;
                self.persist_auth()?;
                // Auto-unlock with the password we already have
                self.unlock_with_master()?;
                self.sync().await?;
                Ok(LoginResult::Success)
            }
            Err(vault_api::ApiError::TwoFactorRequired { providers, raw }) => {
                self.auth_ext.two_factor_raw = Some(raw);
                self.email = Some(email.to_string());
                // Do not retain master_key while still LoggedOut — login_2fa re-derives.
                drop(master);
                Ok(LoginResult::TwoFactorRequired { providers })
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Complete 2FA after TwoFactorRequired (re-derives from stored master key — need password again).
    pub async fn login_2fa(
        &mut self,
        email: &str,
        password: &str,
        provider: u8,
        code: &str,
    ) -> Result<()> {
        self.login_2fa_remember(email, password, provider, code, false)
            .await
    }

    pub async fn login_2fa_remember(
        &mut self,
        email: &str,
        password: &str,
        provider: u8,
        code: &str,
        remember_device: bool,
    ) -> Result<()> {
        match self
            .login_with_2fa_options(email, password, Some((provider, code)), remember_device)
            .await?
        {
            LoginResult::Success => Ok(()),
            LoginResult::TwoFactorRequired { .. } => Err(SessionError::Other(
                "2FA still required — check code".into(),
            )),
        }
    }

    /// Clone a personal login into a new cipher (name suffixed with " (copy)").
    pub async fn clone_login(&mut self, id: &str) -> Result<String> {
        self.ensure_online()?;
        self.check_item_creation_allowed(ItemType::Login)?;
        let item = self.get_item(id).ok_or(SessionError::NotFound)?.clone();
        if item.item_type != ItemType::Login {
            return Err(SessionError::Other(
                "only login items can be cloned currently".into(),
            ));
        }
        let draft = LoginDraft {
            name: format!("{} (copy)", item.name),
            username: item.username.clone(),
            password: item.password.clone(),
            totp: item.totp.clone(),
            uris: item.uris.clone(),
            notes: item.notes.clone(),
            folder_id: item.folder_id.clone(),
            favorite: item.favorite,
            reprompt: item.reprompt,
        };
        self.create_login(&draft).await
    }

    /// Move an item to a folder (or no folder) via partial update.
    pub async fn move_to_folder(&mut self, id: &str, folder_id: Option<String>) -> Result<()> {
        self.ensure_online()?;
        let item = self.get_item(id).ok_or(SessionError::NotFound)?.clone();
        let partial = CipherPartialRequest {
            folder_id,
            favorite: item.favorite,
        };
        self.client.update_cipher_partial(id, &partial).await?;
        self.sync().await?;
        Ok(())
    }

    /// Share a personal item with an organization (`bw share`). See
    /// [`Session::share_item_to_org`] (kept as the CLI-facing name).
    pub async fn share_item(
        &mut self,
        id: &str,
        organization_id: &str,
        collection_ids: &[String],
    ) -> Result<()> {
        self.share_item_to_org(id, organization_id, collection_ids)
            .await
    }

    /// OAuth2 client-credentials login (Bitwarden API key). Master password still required to decrypt vault keys.
    pub async fn login_api_key(
        &mut self,
        email: &str,
        password: &str,
        client_id: &str,
        client_secret: &str,
    ) -> Result<LoginResult> {
        let prelogin = self.client.prelogin(email).await?;
        let kdf = prelogin.to_kdf_params();
        self.remember_kdf(kdf.clone());
        let master = derive_master_key(password, email, &kdf)?;
        let token = self
            .client
            .login_api_key(client_id, client_secret)
            .await
            .map_err(|e| SessionError::Other(e.to_string()))?;
        self.email = Some(email.to_string());
        self.protected_key = token.key.clone().or_else(|| {
            token.user_decryption_options.as_ref().and_then(|v| {
                v.pointer("/MasterPasswordUnlock/MasterKeyEncryptedUserKey")
                    .and_then(|x| x.as_str())
                    .map(str::to_string)
            })
        });
        self.private_key_enc = token.private_key.clone();
        self.master_key = Some(master);
        self.status = SessionStatus::Locked;
        self.persist_auth()?;
        self.unlock_with_master()?;
        self.sync().await?;
        Ok(LoginResult::Success)
    }

    /// Resend email 2FA code during login (provider 1).
    pub async fn send_email_login_2fa(&self, email: &str, password: &str) -> Result<()> {
        let kdf = self
            .kdf
            .clone()
            .ok_or_else(|| SessionError::Other("missing KDF — start login first".into()))?;
        let master = derive_master_key(password, email, &kdf)?;
        let hash = auth_hash(&master, password)?;
        self.client
            .send_email_login_2fa(email, hash.as_str())
            .await
            .map_err(|e| SessionError::Other(e.to_string()))
    }

    pub async fn unlock(&mut self, password: &str) -> Result<()> {
        let email = self.email.clone().ok_or(SessionError::NotLoggedIn)?;
        // Refresh tokens if needed (ignore transport failures — may unlock offline).
        if self.client.access_token().is_none() && self.client.refresh_token().is_some() {
            let _ = self.client.refresh().await;
        }

        let kdf = match self.client.prelogin(&email).await {
            Ok(prelogin) => {
                let kdf = prelogin.to_kdf_params();
                self.remember_kdf(kdf.clone());
                let _ = self.persist_auth();
                kdf
            }
            Err(e) if e.is_transport() || matches!(e, vault_api::ApiError::Http(_)) => {
                self.kdf.clone().ok_or_else(|| {
                    SessionError::Other(
                        "Cannot unlock offline: missing cached KDF (unlock once online first)"
                            .into(),
                    )
                })?
            }
            Err(e) => return Err(e.into()),
        };

        let master = derive_master_key(password, &email, &kdf)?;
        // Keep master local until unwrap succeeds so a wrong password does not linger.
        let protected = self
            .protected_key
            .as_ref()
            .ok_or_else(|| SessionError::Other("missing protected key".into()))?;
        let user_key = unwrap_user_key(protected, &master)?;
        self.master_key = Some(master);
        self.user_key = Some(user_key);
        self.status = SessionStatus::Unlocked;
        self.touch();

        match self.sync().await {
            Ok(()) => Ok(()),
            Err(SessionError::Api(ref e))
                if e.is_transport()
                    || matches!(e, vault_api::ApiError::Http(_))
                    || matches!(e, vault_api::ApiError::NotAuthenticated)
                    || matches!(e, vault_api::ApiError::Api { status, .. } if *status >= 500) =>
            {
                self.load_from_cache().map_err(|cache_err| {
                    if matches!(cache_err, SessionError::Other(ref msg) if msg.contains("No offline"))
                    {
                        SessionError::Other(format!(
                            "Unlock offline failed: {cache_err} (server: {e})"
                        ))
                    } else {
                        cache_err
                    }
                })
            }
            Err(e) => Err(e),
        }
    }

    fn unlock_with_master(&mut self) -> Result<()> {
        let master = self.master_key.as_ref().ok_or(SessionError::Locked)?;
        let protected = self
            .protected_key
            .as_ref()
            .ok_or_else(|| SessionError::Other("missing protected key".into()))?;
        let user_key = unwrap_user_key(protected, master)?;
        self.user_key = Some(user_key);
        self.status = SessionStatus::Unlocked;
        self.touch();
        Ok(())
    }

    /// Cheap change check: `GET /accounts/revision-date` and compare with the revision seen at
    /// the last full sync. Only fetches `/sync` when the server reports a newer revision (or when
    /// offline / never synced / the probe itself fails).
    ///
    /// Does not call [`Session::touch`] when nothing changed, so background polling never resets
    /// the idle auto-lock timer.
    pub async fn sync_if_changed(&mut self) -> Result<SyncOutcome> {
        if self.offline || self.revision_ms.is_none() || self.status != SessionStatus::Unlocked {
            self.sync().await?;
            return Ok(SyncOutcome::Synced);
        }
        match self.client.get_revision_date().await {
            Ok(remote) if !revision_changed(self.revision_ms, remote) => Ok(SyncOutcome::Unchanged),
            // Changed, or probe failed (expired token, transport, …): full sync handles
            // token refresh and offline fallback consistently.
            _ => {
                self.sync().await?;
                Ok(SyncOutcome::Synced)
            }
        }
    }

    pub async fn sync(&mut self) -> Result<()> {
        // Record the revision *before* fetching so a concurrent server change is never missed
        // (worst case: one redundant full sync next poll). Best-effort — failure just disables
        // the shortcut until the next successful sync.
        let revision_before = self.client.get_revision_date().await.ok();
        // Sync is allowed while offline — success clears the offline flag.
        let sync = match self.client.sync().await {
            Ok(s) => s,
            Err(first) => match self.client.refresh().await {
                Ok(_) => self.client.sync().await?,
                Err(refresh_err) => {
                    if self.offline && vault_cache::exists(&self.data_dir) {
                        return Err(SessionError::Offline);
                    }
                    return Err(
                        if matches!(
                            first,
                            vault_api::ApiError::Http(_) | vault_api::ApiError::NotAuthenticated
                        ) {
                            refresh_err.into()
                        } else {
                            first.into()
                        },
                    );
                }
            },
        };
        self.apply_sync_profile(&sync);
        {
            let user_key = self.user_key.as_ref().ok_or(SessionError::Locked)?;
            self.index = build_index(&sync, user_key)?;
        }
        self.apply_sync_metadata(&sync);
        self.write_cache(&sync);
        self.revision_ms = revision_before;
        self.offline = false;
        let _ = self.persist_auth();
        self.touch();
        Ok(())
    }

    pub fn items(&self) -> &[DecryptedItem] {
        &self.index.items
    }

    pub fn folders(&self) -> &[DecryptedFolder] {
        &self.index.folders
    }

    pub fn organizations(&self) -> &[DecryptedOrganization] {
        &self.index.organizations
    }

    pub fn collections(&self) -> &[DecryptedCollection] {
        &self.index.collections
    }

    pub fn sends(&self) -> &[DecryptedSend] {
        &self.index.sends
    }

    /// Validate `password` against org master-password requirements (type 1).
    pub fn check_master_password_policy(&self, password: &str) -> Result<()> {
        let policy = self.master_password_policy();
        if !policy.is_active() {
            return Ok(());
        }
        let email = self.email.as_deref().unwrap_or("");
        let inputs: Vec<&str> = email.split('@').filter(|s| !s.is_empty()).collect();
        let problems = policy.validate(password, &inputs);
        if problems.is_empty() {
            Ok(())
        } else {
            Err(SessionError::PolicyViolation(format!(
                "master password {}",
                problems.join("; ")
            )))
        }
    }

    pub fn pin_unlock_available(&self) -> bool {
        !pin_unlock_disabled(&self.policies) && pin_configured(&self.data_dir)
    }

    pub fn configure_pin(&self, pin: &str) -> Result<()> {
        if pin_unlock_disabled(&self.policies) {
            return Err(SessionError::PolicyViolation(
                "PIN unlock is disabled".into(),
            ));
        }
        let user_key = self.user_key.as_ref().ok_or(SessionError::Locked)?;
        let email = self.email.as_ref().ok_or(SessionError::NotLoggedIn)?;
        store_pin_wrapped_key(&self.data_dir, email, pin, user_key)
    }

    pub fn clear_pin_unlock(&self) {
        clear_pin(&self.data_dir);
    }

    pub fn ssh_agent_socket(&self) -> Option<&Path> {
        self.ssh_agent.as_ref().map(|a| a.socket_path())
    }

    pub fn ssh_agent_running(&self) -> bool {
        self.ssh_agent.is_some()
    }

    pub fn list_ssh_keys_for_agent(&self) -> Result<Vec<ParsedSshKey>> {
        if self.status != SessionStatus::Unlocked {
            return Err(SessionError::Locked);
        }
        self.index
            .items
            .iter()
            .filter(|i| i.item_type == ItemType::SshKey && !i.deleted)
            .map(parse_ssh_key_item)
            .collect()
    }

    pub fn start_ssh_agent(&mut self) -> Result<PathBuf> {
        if self.status != SessionStatus::Unlocked {
            return Err(SessionError::Locked);
        }
        self.stop_ssh_agent();
        let keys = self.list_ssh_keys_for_agent()?;
        let handle = start_agent_with_keys(&self.data_dir, &keys)?;
        let socket = handle.socket_path().to_path_buf();
        self.ssh_agent = Some(handle);
        Ok(socket)
    }

    pub fn stop_ssh_agent(&mut self) {
        self.ssh_agent = None;
    }

    /// Change master password on the server and update local wrapped user key.
    pub async fn change_master_password(
        &mut self,
        old_password: &str,
        new_password: &str,
        hint: Option<&str>,
    ) -> Result<()> {
        if new_password.len() < 8 {
            return Err(SessionError::Other(
                "new master password must be at least 8 characters".into(),
            ));
        }
        let email = self.email.clone().ok_or(SessionError::NotLoggedIn)?;
        self.check_master_password_policy(new_password)?;
        let kdf = self
            .kdf
            .clone()
            .ok_or_else(|| SessionError::Other("missing KDF parameters".into()))?;
        let user_key = self.user_key.as_ref().ok_or(SessionError::Locked)?;
        let old_master = derive_master_key(old_password, &email, &kdf)?;
        let stored_ok = self
            .master_key
            .as_ref()
            .is_some_and(|m| constant_time_eq(m.as_bytes(), old_master.as_bytes()));
        if !stored_ok {
            let protected = self
                .protected_key
                .as_ref()
                .ok_or_else(|| SessionError::Other("missing protected key".into()))?;
            unwrap_user_key(protected, &old_master)?;
        }
        let new_master = derive_master_key(new_password, &email, &kdf)?;
        let old_hash = auth_hash(&old_master, old_password)?;
        let new_hash = auth_hash(&new_master, new_password)?;
        let new_protected = wrap_user_key(user_key, &new_master)?;
        let req = ChangePasswordRequest {
            master_password_hash: old_hash.as_str().to_string(),
            new_master_password_hash: new_hash.as_str().to_string(),
            user_key_encrypted: new_protected.clone(),
            master_password_hint: hint.filter(|h| !h.is_empty()).map(str::to_string),
        };
        self.client.change_password(&req).await?;
        self.protected_key = Some(new_protected);
        if pin_configured(&self.data_dir) {
            clear_pin(&self.data_dir);
        }
        self.stop_ssh_agent();
        self.user_key = None;
        self.master_key = None;
        self.index = VaultIndex::default();
        if self.status == SessionStatus::Unlocked {
            self.status = SessionStatus::Locked;
        }
        self.persist_auth()?;
        Ok(())
    }

    pub async fn unlock_with_pin_code(&mut self, pin: &str) -> Result<()> {
        if pin_unlock_disabled(&self.policies) {
            clear_pin(&self.data_dir);
            return Err(SessionError::PolicyViolation(
                "PIN unlock is disabled — use your master password".into(),
            ));
        }
        let email = self.email.clone().ok_or(SessionError::NotLoggedIn)?;
        let user_key = unlock_with_pin(&self.data_dir, &email, pin)?;
        self.user_key = Some(user_key);
        self.status = SessionStatus::Unlocked;
        self.touch();
        match self.sync().await {
            Ok(()) => Ok(()),
            Err(_e) if self.offline || vault_cache::exists(&self.data_dir) => {
                self.load_from_cache()
            }
            Err(e) => Err(e),
        }
    }

    pub fn fingerprint_phrase(&self) -> Result<String> {
        use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey};
        use rsa::RsaPrivateKey;
        let user_key = self.user_key.as_ref().ok_or(SessionError::Locked)?;
        let private_enc = self
            .private_key_enc
            .as_ref()
            .ok_or_else(|| SessionError::Other("missing account keys".into()))?;
        let private_der = decrypt_private_key(private_enc, user_key)?;
        let private = RsaPrivateKey::from_pkcs8_der(&private_der)
            .map_err(|e| SessionError::Other(e.to_string()))?;
        let public_der = private
            .to_public_key()
            .to_public_key_der()
            .map_err(|e| SessionError::Other(e.to_string()))?
            .as_bytes()
            .to_vec();
        Ok(fingerprint_phrase_from_public_der(&public_der))
    }

    pub async fn request_password_hint(&self) -> Result<()> {
        let email = self.email.as_ref().ok_or(SessionError::NotLoggedIn)?;
        self.client
            .request_password_hint(email)
            .await
            .map_err(|e| e.into())
    }

    pub fn list_attachments(&self, cipher_id: &str) -> Result<Vec<AttachmentInfo>> {
        let raw = self
            .index
            .raw_ciphers
            .get(cipher_id)
            .ok_or(SessionError::NotFound)?;
        let user_key = self.user_key.as_ref().ok_or(SessionError::Locked)?;
        let key = resolve_cipher_key(raw, user_key, &self.index.org_keys)?;
        let attachments = raw.attachments.as_deref().unwrap_or(&[]);
        Ok(attachments
            .iter()
            .filter_map(|a| {
                let id = a.id.clone()?;
                let file_name = a
                    .file_name
                    .as_ref()
                    .and_then(|n| decrypt_with_key(n, &key).ok())
                    .unwrap_or_else(|| "attachment".into());
                Some(AttachmentInfo {
                    id,
                    file_name,
                    size_name: a.size_name.clone(),
                })
            })
            .collect())
    }

    pub async fn download_attachment(
        &mut self,
        cipher_id: &str,
        attachment_id: &str,
        dest: &Path,
    ) -> Result<()> {
        self.ensure_online()?;
        let raw = self
            .index
            .raw_ciphers
            .get(cipher_id)
            .ok_or(SessionError::NotFound)?
            .clone();
        let user_key = self.user_key.as_ref().ok_or(SessionError::Locked)?;
        let cipher_key = resolve_cipher_key(&raw, user_key, &self.index.org_keys)?;
        let attachment = raw
            .attachments
            .as_ref()
            .and_then(|v| v.iter().find(|a| a.id.as_deref() == Some(attachment_id)))
            .ok_or(SessionError::NotFound)?;
        let att_key = attachment
            .key
            .as_ref()
            .and_then(|k| decrypt_bytes(k, &cipher_key).ok())
            .and_then(|raw| SymmetricCryptoKey::from_bytes(&raw).ok());
        let url = vault_api::VaultClient::attachment_direct_url(attachment)
            .map(str::to_string)
            .unwrap_or_else(|| {
                self.client
                    .attachment_download_url(cipher_id, attachment_id)
            });
        let use_bearer = vault_api::VaultClient::attachment_direct_url(attachment).is_none();
        let encrypted = self.client.download_bytes(&url, use_bearer).await?;
        let plain = if let Some(sym) = att_key {
            let enc_str = String::from_utf8_lossy(&encrypted);
            decrypt_bytes(enc_str.trim(), &sym)?
        } else {
            encrypted
        };
        if let Some(parent) = dest.parent() {
            ensure_dir(parent)?;
        }
        write_atomic(dest, &plain)?;
        Ok(())
    }

    pub async fn delete_attachment(&mut self, cipher_id: &str, attachment_id: &str) -> Result<()> {
        self.ensure_online()?;
        self.client
            .delete_attachment(cipher_id, attachment_id)
            .await?;
        self.sync().await?;
        Ok(())
    }

    pub async fn upload_attachment(&mut self, cipher_id: &str, path: &Path) -> Result<()> {
        self.ensure_online()?;
        let _raw = self
            .index
            .raw_ciphers
            .get(cipher_id)
            .ok_or(SessionError::NotFound)?;
        let cipher_key = self.resolve_item_cipher_key(cipher_id)?;
        let file_name = path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| SessionError::Other("invalid file path".into()))?;
        let plain = std::fs::read(path).map_err(|e| SessionError::Other(e.to_string()))?;
        let att_key = generate_user_key();
        let enc_file = encrypt_bytes(&plain, &att_key)?;
        let enc_key = encrypt_bytes(att_key.to_bytes().as_ref(), &cipher_key)?;
        let enc_name = encrypt_with_key(file_name, &cipher_key)?;
        self.client
            .upload_cipher_attachment_v2(cipher_id, &enc_key, &enc_name, enc_file.into_bytes())
            .await?;
        self.sync().await?;
        Ok(())
    }

    /// Create a text Send with default options (7-day deletion, no password).
    pub async fn create_text_send(&mut self, name: &str, text: &str) -> Result<String> {
        self.create_send(name, text, &SendOptions::default()).await
    }

    fn check_send_creation(&self, opts: &SendOptions) -> Result<()> {
        if !self.send_creation_allowed() {
            return Err(SessionError::Other(
                "organization policy disables Bitwarden Send".into(),
            ));
        }
        if opts.hide_email && self.send_policy().disable_hide_email == Some(true) {
            return Err(SessionError::Other(
                "organization policy disallows hiding your email on Sends".into(),
            ));
        }
        Ok(())
    }

    /// Create a text Send with full options (password, max access count, dates, …).
    pub async fn create_send(
        &mut self,
        name: &str,
        text: &str,
        opts: &SendOptions,
    ) -> Result<String> {
        self.ensure_online()?;
        self.check_send_creation(opts)?;
        if text.is_empty() {
            return Err(SessionError::Other("send text is required".into()));
        }
        let user_key = self.user_key.as_ref().ok_or(SessionError::Locked)?;
        let key = crate::send_crypto::generate_send_key_material();
        let wrapped_key = encrypt_bytes(key.as_slice(), user_key)?;
        let req = build_send_request(SendRequestInput {
            send_type: SEND_TYPE_TEXT,
            key: &key,
            wrapped_key,
            name,
            opts,
            text: Some(text),
            file: None,
            file_length: None,
            existing_deletion: None,
            now: chrono::Utc::now(),
        })?;
        let created = self.client.create_send(&req).await?;
        self.sync().await?;
        Ok(created.id.unwrap_or_default())
    }

    /// Create a file Send: encrypts the file locally and uploads it.
    pub async fn create_file_send(
        &mut self,
        name: &str,
        path: &Path,
        opts: &SendOptions,
    ) -> Result<String> {
        self.ensure_online()?;
        self.check_send_creation(opts)?;
        let meta = std::fs::metadata(path)?;
        if !meta.is_file() {
            return Err(SessionError::Other(format!(
                "{} is not a file",
                path.display()
            )));
        }
        if meta.len() == 0 {
            return Err(SessionError::Other("cannot send an empty file".into()));
        }
        if meta.len() > MAX_SEND_FILE_BYTES {
            return Err(SessionError::Other(format!(
                "file too large for Send (max {})",
                format_file_size(MAX_SEND_FILE_BYTES)
            )));
        }
        let file_name = path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| SessionError::Other("invalid file path".into()))?
            .to_string();
        let plain = std::fs::read(path)?;

        let user_key = self.user_key.as_ref().ok_or(SessionError::Locked)?;
        let key = crate::send_crypto::generate_send_key_material();
        let wrapped_key = encrypt_bytes(key.as_slice(), user_key)?;
        let enc_file = crate::send_crypto::encrypt_send_file_bytes(&key, &plain)?;
        let enc_len = enc_file.len() as u64;
        let enc_file_name = crate::send_crypto::encrypt_send_meta(&key, &file_name)?;
        let req = build_send_request(SendRequestInput {
            send_type: SEND_TYPE_FILE,
            key: &key,
            wrapped_key,
            name,
            opts,
            text: None,
            file: Some(vault_api::SendFile {
                id: None,
                file_name: Some(enc_file_name.clone()),
                size: Some(enc_len),
                size_name: Some(format_file_size(enc_len)),
                validated: false,
            }),
            file_length: Some(enc_len),
            existing_deletion: None,
            now: chrono::Utc::now(),
        })?;

        let created = self.client.create_file_send(&req).await?;
        let send_id = created.send_response.id.clone().unwrap_or_default();
        let file_id = created
            .send_response
            .file
            .as_ref()
            .and_then(|f| f.id.clone())
            .unwrap_or_default();
        let upload = if created.file_upload_type == vault_api::SEND_FILE_UPLOAD_AZURE {
            self.client
                .upload_send_file_azure(&created.url, enc_file)
                .await
        } else {
            self.client
                .upload_send_file_direct(&send_id, &file_id, &enc_file_name, enc_file)
                .await
        };
        if let Err(e) = upload {
            // Don't leave a dangling, un-downloadable Send behind.
            let _ = self.client.delete_send(&send_id).await;
            return Err(e.into());
        }
        self.sync().await?;
        Ok(send_id)
    }

    /// Options currently stored for a Send (notes decrypted) — used to pre-fill edit forms.
    pub fn send_options(&self, id: &str) -> Result<SendOptions> {
        let user_key = self.user_key.as_ref().ok_or(SessionError::Locked)?;
        let raw = self.index.raw_sends.get(id).ok_or(SessionError::NotFound)?;
        let notes = match (raw.key.as_deref(), raw.notes.as_deref()) {
            (Some(k), Some(n)) => {
                let km = crate::decrypt::unwrap_send_key_material(k, user_key)?;
                crate::send_crypto::decrypt_send_meta_field(&km, n).ok()
            }
            _ => None,
        };
        Ok(SendOptions {
            notes,
            password: None,
            remove_password: false,
            max_access_count: raw.max_access_count,
            expiration_date: raw.expiration_date.clone(),
            deletion_date: raw.deletion_date.clone(),
            hide_email: raw.hide_email,
            disabled: raw.disabled,
            hidden_text: raw.text.as_ref().map(|t| t.hidden).unwrap_or(false),
        })
    }

    /// Update a text Send's name/body, keeping its other options.
    pub async fn update_text_send(&mut self, id: &str, name: &str, text: &str) -> Result<()> {
        let opts = self.send_options(id)?;
        self.update_send(id, name, Some(text), &opts).await
    }

    /// Update any Send. `text` applies to text Sends (`None` keeps the body); file Sends keep
    /// their file. `opts.password = None` leaves the password untouched unless
    /// `opts.remove_password` is set.
    pub async fn update_send(
        &mut self,
        id: &str,
        name: &str,
        text: Option<&str>,
        opts: &SendOptions,
    ) -> Result<()> {
        self.ensure_online()?;
        if opts.hide_email && self.send_policy().disable_hide_email == Some(true) {
            return Err(SessionError::Other(
                "organization policy disallows hiding your email on Sends".into(),
            ));
        }
        let user_key = self.user_key.as_ref().ok_or(SessionError::Locked)?.clone();
        let raw = self
            .index
            .raw_sends
            .get(id)
            .ok_or(SessionError::NotFound)?
            .clone();
        let key_enc = raw
            .key
            .as_deref()
            .ok_or_else(|| SessionError::Other("send has no key material".into()))?;
        let key_material = crate::decrypt::unwrap_send_key_material(key_enc, &user_key)?;
        let is_text = raw.send_type == SEND_TYPE_TEXT;
        let mut req = build_send_request(SendRequestInput {
            send_type: raw.send_type,
            key: &key_material,
            wrapped_key: key_enc.to_string(),
            name,
            opts,
            text: if is_text { text } else { None },
            file: if is_text { None } else { raw.file.clone() },
            file_length: None,
            existing_deletion: raw.deletion_date.as_deref(),
            now: chrono::Utc::now(),
        })?;
        if is_text && text.is_none() {
            req.text = raw.text.clone();
        }
        self.client.update_send(id, &req).await?;
        if opts.remove_password && opts.password.as_deref().is_none_or(str::is_empty) {
            self.client.remove_send_password(id).await?;
        }
        self.sync().await?;
        Ok(())
    }

    /// Receive a Send from a share link (does not require a session).
    pub async fn receive_send(url: &str, password: Option<&str>) -> Result<ReceivedSend> {
        crate::send::receive_send(url, password).await
    }

    pub async fn delete_send(&mut self, id: &str) -> Result<()> {
        self.ensure_online()?;
        self.client.delete_send(id).await?;
        self.sync().await?;
        Ok(())
    }

    /// Bitwarden Send share URL: `{server}/#/send/{accessId}/{urlSafeKey}`.
    pub fn send_share_link(&self, send_id: &str) -> Result<String> {
        let user_key = self.user_key.as_ref().ok_or(SessionError::Locked)?;
        let raw = self
            .index
            .raw_sends
            .get(send_id)
            .ok_or(SessionError::NotFound)?;
        let access_id = raw
            .access_id
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| SessionError::Other("send missing accessId".into()))?;
        let key_enc = raw
            .key
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| SessionError::Other("send missing key".into()))?;
        let material = crate::decrypt::unwrap_send_key_material(key_enc, user_key)?;
        let url_key = crate::send_crypto::encode_send_key(&material);
        let base = self.server_url().trim_end_matches('/');
        Ok(format!("{base}/#/send/{access_id}/{url_key}"))
    }

    /// True when the item can be re-encrypted *and* the user has write permission
    /// (see [`Session::can_edit_item`]).
    pub fn item_editable(&self, id: &str) -> bool {
        self.can_edit_item(id)
    }

    pub async fn clone_item(&mut self, id: &str) -> Result<String> {
        let item = self.get_item(id).ok_or(SessionError::NotFound)?.clone();
        self.check_item_creation_allowed(item.item_type)?;
        match item.item_type {
            ItemType::Login => self.clone_login(id).await,
            ItemType::SecureNote => {
                let draft = NoteDraft {
                    name: format!("{} (copy)", item.name),
                    notes: item.notes.clone(),
                    folder_id: item.folder_id.clone(),
                    favorite: item.favorite,
                };
                self.create_note(&draft).await
            }
            ItemType::Card => {
                let draft = CardDraft {
                    name: format!("{} (copy)", item.name),
                    cardholder_name: item.cardholder_name.clone(),
                    brand: item.card_brand.clone(),
                    number: item.card_number.clone(),
                    exp_month: item.card_exp_month.clone(),
                    exp_year: item.card_exp_year.clone(),
                    code: item.card_code.clone(),
                    notes: item.notes.clone(),
                    folder_id: item.folder_id.clone(),
                    favorite: item.favorite,
                    reprompt: item.reprompt,
                };
                self.create_card(&draft).await
            }
            ItemType::Identity => {
                let draft = IdentityDraft {
                    name: format!("{} (copy)", item.name),
                    title: item.identity_title.clone(),
                    first_name: item.identity_first_name.clone(),
                    middle_name: item.identity_middle_name.clone(),
                    last_name: item.identity_last_name.clone(),
                    address1: item.identity_address1.clone(),
                    address2: item.identity_address2.clone(),
                    address3: item.identity_address3.clone(),
                    city: item.identity_city.clone(),
                    state: item.identity_state.clone(),
                    postal_code: item.identity_postal_code.clone(),
                    country: item.identity_country.clone(),
                    company: item.identity_company.clone(),
                    email: item.identity_email.clone(),
                    phone: item.identity_phone.clone(),
                    ssn: item.identity_ssn.clone(),
                    username: item.identity_username.clone(),
                    passport_number: item.identity_passport_number.clone(),
                    license_number: item.identity_license_number.clone(),
                    notes: item.notes.clone(),
                    folder_id: item.folder_id.clone(),
                    favorite: item.favorite,
                    reprompt: item.reprompt,
                };
                self.create_identity(&draft).await
            }
            ItemType::SshKey => {
                let draft = SshKeyDraft {
                    name: format!("{} (copy)", item.name),
                    private_key: item.ssh_private_key.clone(),
                    public_key: item.ssh_public_key.clone(),
                    fingerprint: item.ssh_fingerprint.clone(),
                    notes: item.notes.clone(),
                    folder_id: item.folder_id.clone(),
                    favorite: item.favorite,
                };
                self.create_ssh_key(&draft).await
            }
            ItemType::Unknown => Err(SessionError::Other("cannot clone item type".into())),
        }
    }

    pub fn get_item(&self, id: &str) -> Option<&DecryptedItem> {
        self.index.items.iter().find(|i| i.id == id)
    }

    pub fn verify_reprompt(&self, password: &str) -> Result<bool> {
        let email = self.email.as_ref().ok_or(SessionError::NotLoggedIn)?;
        let master = self.master_key.as_ref().ok_or(SessionError::Locked)?;
        let kdf = self
            .kdf
            .clone()
            .ok_or_else(|| SessionError::Other("missing KDF parameters".into()))?;
        let derived = derive_master_key(password, email, &kdf)?;
        Ok(constant_time_eq(master.as_bytes(), derived.as_bytes()))
    }

    fn resolve_item_cipher_key(&self, id: &str) -> Result<SymmetricCryptoKey> {
        let raw = self
            .index
            .raw_ciphers
            .get(id)
            .ok_or(SessionError::NotFound)?;
        let user_key = self.user_key.as_ref().ok_or(SessionError::Locked)?;
        resolve_cipher_key(raw, user_key, &self.index.org_keys)
    }

    fn cipher_encrypted_for(raw: &vault_api::Cipher, user_id: &str) -> String {
        raw.extra
            .get("encryptedFor")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| {
                raw.organization_id
                    .clone()
                    .unwrap_or_else(|| user_id.to_string())
            })
    }

    /// Copy password. When `reprompt_ok` is false and the item requires
    /// master-password re-prompt, returns [`SessionError::RepromptRequired`].
    pub fn copy_password(&mut self, id: &str, reprompt_ok: bool) -> Result<()> {
        let item = self.get_item(id).ok_or(SessionError::NotFound)?;
        if item.reprompt && !reprompt_ok {
            return Err(SessionError::RepromptRequired);
        }
        let pw = item
            .password
            .clone()
            .ok_or_else(|| SessionError::Other("no password".into()))?;
        self.clipboard.copy_secret(&pw)?;
        self.touch();
        Ok(())
    }

    pub fn copy_username(&mut self, id: &str) -> Result<()> {
        let item = self.get_item(id).ok_or(SessionError::NotFound)?;
        let u = item
            .username
            .clone()
            .ok_or_else(|| SessionError::Other("no username".into()))?;
        self.clipboard.copy_secret(&u)?;
        self.touch();
        Ok(())
    }

    /// Copy current TOTP. See [`Self::copy_password`] for `reprompt_ok`.
    pub fn copy_totp(&mut self, id: &str, reprompt_ok: bool) -> Result<String> {
        let item = self.get_item(id).ok_or(SessionError::NotFound)?;
        if item.reprompt && !reprompt_ok {
            return Err(SessionError::RepromptRequired);
        }
        let secret = item
            .totp
            .clone()
            .ok_or_else(|| SessionError::Other("no totp".into()))?;
        let code = totp_from_secret(&secret)?;
        self.clipboard.copy_secret(&code)?;
        self.touch();
        Ok(code)
    }

    /// Current TOTP code and timing for display (period + seconds remaining).
    pub fn totp_now(&self, id: &str) -> Option<TotpDisplay> {
        let item = self.get_item(id)?;
        let secret = item.totp.as_ref()?;
        totp_display_from_secret(secret).ok()
    }

    /// Copy an arbitrary secret string to the clipboard (card number, notes, etc.).
    pub fn copy_text(&mut self, value: &str) -> Result<()> {
        self.clipboard.copy_secret(value)?;
        self.touch();
        Ok(())
    }

    /// Set clipboard auto-clear duration in seconds (minimum 5).
    pub fn set_clipboard_clear_secs(&mut self, secs: u64) {
        self.clipboard.set_clear_after(secs.max(5));
    }

    pub async fn create_login(&mut self, draft: &LoginDraft) -> Result<String> {
        self.create_login_in(draft, None).await
    }

    pub async fn update_login(&mut self, id: &str, draft: &LoginDraft) -> Result<()> {
        self.ensure_online()?;
        let item = self.get_item(id).ok_or(SessionError::NotFound)?.clone();
        let cipher_key = self.resolve_item_cipher_key(id)?;
        let user_id = self.user_id()?;
        let mut req = encrypt_login(draft, &cipher_key, user_id)?;
        req.last_known_revision_date = item.revision_date.clone();

        // Preserve fields the draft does not model (custom fields, attachments, extra URIs, etc.).
        if let Some(raw) = self.index.raw_ciphers.get(id) {
            req.encrypted_for = Self::cipher_encrypted_for(raw, user_id);
            preserve_cipher_metadata(&mut req, raw);
            if let (Some(login_req), Some(raw_login)) = (req.login.as_mut(), raw.login.as_ref()) {
                login_req.autofill_on_page_load = raw_login.autofill_on_page_load;
                login_req.fido2_credentials = raw_login.fido2_credentials.clone();
                login_req.extra = raw_login.extra.clone();
            }
            // Password history: prepend old password when it changed.
            let mut history = raw.password_history.clone().unwrap_or_default();
            let password_changed = draft.password.as_deref() != item.password.as_deref()
                && draft.password.is_some()
                && item.password.is_some();
            if password_changed {
                if let Some(old_pw) = &item.password {
                    let enc = encrypt_with_key(old_pw, &cipher_key)?;
                    history.insert(
                        0,
                        PasswordHistoryEntry {
                            password: enc,
                            last_used_date: Some(chrono::Utc::now().to_rfc3339()),
                        },
                    );
                    history.truncate(5);
                }
            }
            req.password_history = if history.is_empty() {
                None
            } else {
                Some(history)
            };
        }

        self.client.update_cipher(id, &req).await?;
        self.sync().await?;
        Ok(())
    }

    /// Replace custom fields on a cipher (encrypts name/value with the item key).
    pub async fn update_custom_fields(
        &mut self,
        id: &str,
        fields: &[DecryptedField],
    ) -> Result<()> {
        self.ensure_online()?;
        let item = self.get_item(id).ok_or(SessionError::NotFound)?.clone();
        self.ensure_item_editable(&item)?;
        let cipher_key = self.resolve_item_cipher_key(id)?;
        let user_id = self.user_id()?;
        let raw = self
            .index
            .raw_ciphers
            .get(id)
            .cloned()
            .ok_or(SessionError::NotFound)?;

        // Rebuild a CipherRequest from the existing raw cipher, swapping only fields.
        let mut req = CipherRequest {
            cipher_type: raw.cipher_type,
            name: raw.name.clone(),
            notes: raw.notes.clone(),
            folder_id: raw.folder_id.clone(),
            favorite: raw.favorite,
            reprompt: raw.reprompt,
            login: raw.login.clone(),
            secure_note: raw.secure_note.clone(),
            card: raw.card.clone(),
            identity: raw.identity.clone(),
            fields: None,
            password_history: raw.password_history.clone(),
            attachments: raw.attachments.clone(),
            attachments2: None,
            organization_id: raw.organization_id.clone(),
            collection_ids: raw.collection_ids.clone(),
            key: raw.key.clone(),
            ssh_key: raw.ssh_key.clone(),
            last_known_revision_date: item.revision_date.clone(),
            encrypted_for: Self::cipher_encrypted_for(&raw, user_id),
        };
        // Name/notes on raw are already encrypted; keep them.
        let enc_fields: Result<Vec<_>> = fields
            .iter()
            .map(|f| {
                Ok(vault_api::CipherField {
                    field_type: f.field_type.as_u8(),
                    name: Some(encrypt_with_key(&f.name, &cipher_key)?),
                    value: Some(encrypt_with_key(&f.value, &cipher_key)?),
                    linked_id: f.linked_id,
                })
            })
            .collect();
        req.fields = Some(enc_fields?);
        self.client.update_cipher(id, &req).await?;
        self.sync().await?;
        Ok(())
    }

    pub async fn create_note(&mut self, draft: &NoteDraft) -> Result<String> {
        self.create_note_in(draft, None).await
    }

    pub async fn update_note(&mut self, id: &str, draft: &NoteDraft) -> Result<()> {
        self.ensure_online()?;
        let item = self.get_item(id).ok_or(SessionError::NotFound)?.clone();
        self.ensure_item_editable(&item)?;
        if item.item_type != ItemType::SecureNote {
            return Err(SessionError::Other("item is not a secure note".into()));
        }
        let cipher_key = self.resolve_item_cipher_key(id)?;
        let user_id = self.user_id()?;
        let mut req = encrypt_note(draft, &cipher_key, user_id)?;
        req.last_known_revision_date = item.revision_date.clone();
        if let Some(raw) = self.index.raw_ciphers.get(id) {
            preserve_cipher_metadata(&mut req, raw);
            if let (Some(note_req), Some(raw_note)) =
                (req.secure_note.as_mut(), raw.secure_note.as_ref())
            {
                note_req.note_type = raw_note.note_type;
            }
        }
        self.client.update_cipher(id, &req).await?;
        self.sync().await?;
        Ok(())
    }

    pub async fn create_card(&mut self, draft: &CardDraft) -> Result<String> {
        self.create_card_in(draft, None).await
    }

    pub async fn update_card(&mut self, id: &str, draft: &CardDraft) -> Result<()> {
        self.ensure_online()?;
        let item = self.get_item(id).ok_or(SessionError::NotFound)?.clone();
        self.ensure_item_editable(&item)?;
        if item.item_type != ItemType::Card {
            return Err(SessionError::Other("item is not a card".into()));
        }
        let cipher_key = self.resolve_item_cipher_key(id)?;
        let user_id = self.user_id()?;
        let mut req = encrypt_card(draft, &cipher_key, user_id)?;
        req.last_known_revision_date = item.revision_date.clone();
        if let Some(raw) = self.index.raw_ciphers.get(id) {
            preserve_cipher_metadata(&mut req, raw);
        }
        self.client.update_cipher(id, &req).await?;
        self.sync().await?;
        Ok(())
    }

    pub async fn create_identity(&mut self, draft: &IdentityDraft) -> Result<String> {
        self.create_identity_in(draft, None).await
    }

    pub async fn update_identity(&mut self, id: &str, draft: &IdentityDraft) -> Result<()> {
        self.ensure_online()?;
        let item = self.get_item(id).ok_or(SessionError::NotFound)?.clone();
        self.ensure_item_editable(&item)?;
        if item.item_type != ItemType::Identity {
            return Err(SessionError::Other("item is not an identity".into()));
        }
        let cipher_key = self.resolve_item_cipher_key(id)?;
        let user_id = self.user_id()?;
        let mut req = encrypt_identity(draft, &cipher_key, user_id)?;
        req.last_known_revision_date = item.revision_date.clone();
        if let Some(raw) = self.index.raw_ciphers.get(id) {
            preserve_cipher_metadata(&mut req, raw);
        }
        self.client.update_cipher(id, &req).await?;
        self.sync().await?;
        Ok(())
    }

    pub async fn create_ssh_key(&mut self, draft: &SshKeyDraft) -> Result<String> {
        self.create_ssh_key_in(draft, None).await
    }

    pub async fn update_ssh_key(&mut self, id: &str, draft: &SshKeyDraft) -> Result<()> {
        self.ensure_online()?;
        let item = self.get_item(id).ok_or(SessionError::NotFound)?.clone();
        self.ensure_item_editable(&item)?;
        if item.item_type != ItemType::SshKey {
            return Err(SessionError::Other("item is not an SSH key".into()));
        }
        let cipher_key = self.resolve_item_cipher_key(id)?;
        let user_id = self.user_id()?;
        let mut req = encrypt_ssh_key(draft, &cipher_key, user_id)?;
        req.last_known_revision_date = item.revision_date.clone();
        if let Some(raw) = self.index.raw_ciphers.get(id) {
            preserve_cipher_metadata(&mut req, raw);
        }
        self.client.update_cipher(id, &req).await?;
        self.sync().await?;
        Ok(())
    }

    pub async fn soft_delete(&mut self, id: &str) -> Result<()> {
        self.ensure_online()?;
        self.client.soft_delete_cipher(id).await?;
        self.sync().await?;
        Ok(())
    }

    pub async fn restore(&mut self, id: &str) -> Result<()> {
        self.ensure_online()?;
        self.client.restore_cipher(id).await?;
        self.sync().await?;
        Ok(())
    }

    pub async fn hard_delete(&mut self, id: &str) -> Result<()> {
        self.ensure_online()?;
        self.client.delete_cipher(id).await?;
        self.sync().await?;
        Ok(())
    }

    pub async fn toggle_favorite(&mut self, id: &str) -> Result<()> {
        self.ensure_online()?;
        let item = self.get_item(id).ok_or(SessionError::NotFound)?.clone();
        // Org items: favoriting via partial is OK (does not re-encrypt). Item-key personal
        // items are also fine — partial does not touch ciphertext.
        let partial = CipherPartialRequest {
            folder_id: item.folder_id.clone(),
            favorite: !item.favorite,
        };
        self.client.update_cipher_partial(id, &partial).await?;
        self.sync().await?;
        Ok(())
    }

    pub async fn create_folder(&mut self, name: &str) -> Result<String> {
        self.ensure_online()?;
        let user_key = self.user_key.as_ref().ok_or(SessionError::Locked)?;
        let enc_name = encrypt_with_key(name, user_key)?;
        let folder = self.client.create_folder(&enc_name).await?;
        let id = folder.id.clone().unwrap_or_default();
        self.sync().await?;
        Ok(id)
    }

    pub async fn rename_folder(&mut self, id: &str, name: &str) -> Result<()> {
        self.ensure_online()?;
        let user_key = self.user_key.as_ref().ok_or(SessionError::Locked)?;
        let enc_name = encrypt_with_key(name, user_key)?;
        self.client.update_folder(id, &enc_name).await?;
        self.sync().await?;
        Ok(())
    }

    pub async fn delete_folder(&mut self, id: &str) -> Result<()> {
        self.ensure_online()?;
        self.client.delete_folder(id).await?;
        self.sync().await?;
        Ok(())
    }

    fn persist_auth(&mut self) -> Result<()> {
        let Some(email) = &self.email else {
            return Ok(());
        };
        let Some(refresh) = self.client.refresh_token() else {
            return Ok(());
        };

        let allow_plaintext = plaintext_token_allowed(self.allow_plaintext_token);
        let profile_id = profile_id_from_data_dir(&self.data_dir);
        let mut used_disk_fallback = false;
        let disk_refresh = match profile_id.as_deref() {
            Some(id) => match set_refresh_token(id, refresh) {
                Ok(()) => {
                    let _ = scrub_refresh_token_from_auth_file(&self.data_dir);
                    None
                }
                Err(e) => {
                    if !allow_plaintext {
                        return Err(SessionError::Other(format!(
                            "secure storage unavailable and plaintext refresh token storage is disabled ({e})"
                        )));
                    }
                    tracing::warn!(
                        profile_id = %id,
                        error = %e,
                        "secure storage unavailable; storing refresh token on disk"
                    );
                    used_disk_fallback = true;
                    Some(refresh.to_string())
                }
            },
            None => {
                if !allow_plaintext {
                    return Err(SessionError::Other(
                        "cannot store refresh token: profile id missing and plaintext storage is disabled"
                            .into(),
                    ));
                }
                used_disk_fallback = true;
                Some(refresh.to_string())
            }
        };

        let mut auth = PersistedAuth {
            server_url: self.client.base_url().to_string(),
            email: email.clone(),
            refresh_token: disk_refresh,
            device_id: self.client.device_id().to_string(),
            protected_key: self.protected_key.clone(),
            private_key: self.private_key_enc.clone(),
            kdf: None,
            kdf_iterations: None,
            kdf_memory: None,
            kdf_parallelism: None,
            two_factor_device_token: self.two_factor_device_token.clone(),
        };
        if let Some(kdf) = &self.kdf {
            auth.set_kdf_from_params(kdf);
        }
        ensure_dir(&self.data_dir)?;
        let path = self.data_dir.join("auth.json");
        let json =
            serde_json::to_string_pretty(&auth).map_err(|e| SessionError::Other(e.to_string()))?;
        write_atomic(&path, json.as_bytes())?;
        if used_disk_fallback {
            tracing::warn!("refresh token stored in auth.json (secure storage fallback)");
            self.storage_warning =
                Some("Refresh token saved to auth.json because OS secure storage failed".into());
        }
        Ok(())
    }

    /// Remove persisted session (`auth.json`, vault cache, secure-storage refresh token).
    pub fn clear_persisted_auth(data_dir: &Path) {
        if let Some(id) = profile_id_from_data_dir(data_dir) {
            delete_refresh_token_best_effort(&id);
        }
        let path = data_dir.join("auth.json");
        let _ = std::fs::remove_file(path);
        clear_policies(data_dir);
        vault_cache::clear(data_dir);
    }

    fn resolve_refresh_token(data_dir: &Path, auth: &PersistedAuth) -> Option<String> {
        if let Some(id) = profile_id_from_data_dir(data_dir) {
            match get_refresh_token(&id) {
                Ok(Some(t)) if !t.is_empty() => return Some(t),
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(
                        profile_id = %id,
                        error = %e,
                        "failed to read refresh token from secure storage; trying disk"
                    );
                }
            }
        }
        auth.refresh_token
            .as_ref()
            .filter(|t| !t.is_empty())
            .cloned()
    }

    /// Restore a locked session from `auth.json` in `data_dir` if the server URL matches.
    pub async fn try_restore(
        server_url: &str,
        data_dir: PathBuf,
        allow_plaintext_token: bool,
    ) -> Result<Option<Self>> {
        let Some((session, stored_server)) =
            Self::try_restore_inner(data_dir, allow_plaintext_token).await?
        else {
            return Ok(None);
        };
        if stored_server.trim_end_matches('/') != server_url.trim_end_matches('/') {
            return Ok(None);
        }
        Ok(Some(session))
    }

    /// Restore a locked session from whatever server is stored in `data_dir/auth.json`.
    pub async fn try_restore_saved(
        data_dir: PathBuf,
        allow_plaintext_token: bool,
    ) -> Result<Option<Self>> {
        Ok(Self::try_restore_inner(data_dir, allow_plaintext_token)
            .await?
            .map(|(s, _)| s))
    }

    async fn try_restore_inner(
        data_dir: PathBuf,
        allow_plaintext_token: bool,
    ) -> Result<Option<(Self, String)>> {
        let path = data_dir.join("auth.json");
        if !path.exists() {
            return Ok(None);
        }
        let json = std::fs::read_to_string(&path)?;
        let auth: PersistedAuth =
            serde_json::from_str(&json).map_err(|e| SessionError::Other(e.to_string()))?;
        if let Some(id) = profile_id_from_data_dir(&data_dir) {
            if matches!(get_refresh_token(&id), Ok(Some(t)) if !t.is_empty()) {
                let _ = scrub_refresh_token_from_auth_file(&data_dir);
            }
        }
        let Some(refresh) = Self::resolve_refresh_token(&data_dir, &auth) else {
            // Metadata without a usable refresh token — treat as logged out.
            Self::clear_persisted_auth(&data_dir);
            return Ok(None);
        };
        let server_url = auth.server_url.clone();
        let mut config = ClientConfig::new(&server_url)?;
        config.device_id = auth.device_id.clone();
        let mut client = VaultClient::new(config)?;
        client.set_tokens(String::new(), Some(refresh));

        let has_cache = vault_cache::exists(&data_dir);
        let refresh_ok = match client.refresh().await {
            Ok(_) => true,
            Err(e) if has_cache && !e.is_auth_rejection() => {
                // Transport / transient failure with an offline cache — keep auth.
                tracing::warn!(
                    error = %e,
                    "token refresh failed; restoring locked session for offline unlock"
                );
                false
            }
            Err(_) => {
                // Stale refresh token with no usable offline cache — drop session.
                Self::clear_persisted_auth(&data_dir);
                return Ok(None);
            }
        };

        let kdf = auth.to_kdf_params();
        let last_synced_at = vault_cache::synced_at(&data_dir);
        let mut session = Self {
            client,
            email: Some(auth.email),
            user_id: None,
            protected_key: auth.protected_key,
            private_key_enc: auth.private_key,
            user_key: None,
            master_key: None,
            kdf,
            index: VaultIndex::default(),
            status: SessionStatus::Locked,
            last_activity: Instant::now(),
            auto_lock: Some(Duration::from_secs(15 * 60)),
            timeout_action: TimeoutAction::Lock,
            clipboard: ClipboardService::new(30),
            last_synced_at,
            offline: false,
            revision_ms: None,
            allow_plaintext_token,
            storage_warning: None,
            insecure_http: is_insecure_http(&server_url),
            two_factor_device_token: auth.two_factor_device_token.clone(),
            auth_ext: auth_flows::AuthExtSession::default(),
            ssh_agent: None,
            policies: load_policies(&data_dir),
            global_equivalent_domains: Vec::new(),
            equivalent_domain_groups: Vec::new(),
            item_keys_on_create: true,
            data_dir,
        };
        if refresh_ok {
            // Re-persist in case the server rotated the refresh token (and upgrade disk → keyring).
            let _ = session.persist_auth();
        }
        Ok(Some((session, server_url)))
    }

    pub fn logout(&mut self) {
        self.clipboard.clear_if_ours();
        self.lock();
        self.client.clear_tokens();
        self.email = None;
        self.protected_key = None;
        self.private_key_enc = None;
        self.kdf = None;
        self.offline = false;
        self.last_synced_at = None;
        self.status = SessionStatus::LoggedOut;
        Self::clear_persisted_auth(&self.data_dir);
    }
}

impl LoginDraft {
    pub fn zeroize_fields(&mut self) {
        if let Some(p) = &mut self.password {
            p.zeroize();
        }
        if let Some(t) = &mut self.totp {
            t.zeroize();
        }
    }
}

fn item_type_label(t: ItemType) -> &'static str {
    match t {
        ItemType::Login => "login",
        ItemType::SecureNote => "secure note",
        ItemType::Card => "card",
        ItemType::Identity => "identity",
        ItemType::SshKey => "SSH key",
        ItemType::Unknown => "unknown",
    }
}

fn preserve_cipher_metadata(req: &mut CipherRequest, raw: &vault_api::Cipher) {
    req.fields = raw.fields.clone();
    req.attachments = raw.attachments.clone();
    req.organization_id = raw.organization_id.clone();
    req.collection_ids = raw.collection_ids.clone();
    req.key = raw.key.clone();
}

fn opt_enc(key: &UserKey, v: &Option<String>) -> Result<Option<String>> {
    v.as_ref()
        .map(|s| encrypt_with_key(s, key).map_err(Into::into))
        .transpose()
}

fn encrypt_login_uris(key: &UserKey, uris: &[DecryptedUri]) -> Option<Vec<LoginUri>> {
    if uris.is_empty() {
        return None;
    }
    Some(
        uris.iter()
            .filter(|u| !u.uri.is_empty())
            .map(|u| LoginUri {
                uri: encrypt_with_key(&u.uri, key).ok(),
                match_type: Some(u.match_type.unwrap_or(0)),
            })
            .collect(),
    )
    .filter(|v: &Vec<LoginUri>| !v.is_empty())
}

fn encrypt_login(
    draft: &LoginDraft,
    key: &SymmetricCryptoKey,
    user_id: &str,
) -> Result<CipherRequest> {
    let uris = encrypt_login_uris(key, &draft.uris);
    Ok(CipherRequest {
        cipher_type: 1,
        name: encrypt_with_key(&draft.name, key)?,
        notes: draft
            .notes
            .as_ref()
            .map(|n| encrypt_with_key(n, key))
            .transpose()?,
        folder_id: draft.folder_id.clone(),
        favorite: draft.favorite,
        reprompt: Some(if draft.reprompt { 1 } else { 0 }),
        login: Some(CipherLogin {
            uris,
            username: draft
                .username
                .as_ref()
                .map(|u| encrypt_with_key(u, key))
                .transpose()?,
            password: draft
                .password
                .as_ref()
                .map(|p| encrypt_with_key(p, key))
                .transpose()?,
            password_revision_date: None,
            totp: draft
                .totp
                .as_ref()
                .map(|t| encrypt_with_key(t, key))
                .transpose()?,
            autofill_on_page_load: None,
            fido2_credentials: None,
            extra: Default::default(),
        }),
        secure_note: None,
        card: None,
        identity: None,
        fields: None,
        password_history: None,
        attachments: None,
        attachments2: None,
        organization_id: None,
        collection_ids: None,
        key: None,
        ssh_key: None,
        encrypted_for: user_id.to_string(),
        last_known_revision_date: None,
    })
}

fn encrypt_note(draft: &NoteDraft, key: &UserKey, user_id: &str) -> Result<CipherRequest> {
    Ok(CipherRequest {
        cipher_type: 2,
        name: encrypt_with_key(&draft.name, key)?,
        notes: opt_enc(key, &draft.notes)?,
        folder_id: draft.folder_id.clone(),
        favorite: draft.favorite,
        reprompt: Some(0),
        login: None,
        secure_note: Some(CipherSecureNote { note_type: Some(0) }),
        card: None,
        identity: None,
        fields: None,
        password_history: None,
        attachments: None,
        attachments2: None,
        organization_id: None,
        collection_ids: None,
        key: None,
        ssh_key: None,
        encrypted_for: user_id.to_string(),
        last_known_revision_date: None,
    })
}

fn encrypt_card(draft: &CardDraft, key: &UserKey, user_id: &str) -> Result<CipherRequest> {
    Ok(CipherRequest {
        cipher_type: 3,
        name: encrypt_with_key(&draft.name, key)?,
        notes: opt_enc(key, &draft.notes)?,
        folder_id: draft.folder_id.clone(),
        favorite: draft.favorite,
        reprompt: Some(if draft.reprompt { 1 } else { 0 }),
        login: None,
        secure_note: None,
        card: Some(CipherCard {
            cardholder_name: opt_enc(key, &draft.cardholder_name)?,
            brand: opt_enc(key, &draft.brand)?,
            number: opt_enc(key, &draft.number)?,
            exp_month: opt_enc(key, &draft.exp_month)?,
            exp_year: opt_enc(key, &draft.exp_year)?,
            code: opt_enc(key, &draft.code)?,
        }),
        identity: None,
        fields: None,
        password_history: None,
        attachments: None,
        attachments2: None,
        organization_id: None,
        collection_ids: None,
        key: None,
        ssh_key: None,
        encrypted_for: user_id.to_string(),
        last_known_revision_date: None,
    })
}

fn encrypt_identity(draft: &IdentityDraft, key: &UserKey, user_id: &str) -> Result<CipherRequest> {
    Ok(CipherRequest {
        cipher_type: 4,
        name: encrypt_with_key(&draft.name, key)?,
        notes: opt_enc(key, &draft.notes)?,
        folder_id: draft.folder_id.clone(),
        favorite: draft.favorite,
        reprompt: Some(if draft.reprompt { 1 } else { 0 }),
        login: None,
        secure_note: None,
        card: None,
        identity: Some(CipherIdentity {
            title: opt_enc(key, &draft.title)?,
            first_name: opt_enc(key, &draft.first_name)?,
            middle_name: opt_enc(key, &draft.middle_name)?,
            last_name: opt_enc(key, &draft.last_name)?,
            address1: opt_enc(key, &draft.address1)?,
            address2: opt_enc(key, &draft.address2)?,
            address3: opt_enc(key, &draft.address3)?,
            city: opt_enc(key, &draft.city)?,
            state: opt_enc(key, &draft.state)?,
            postal_code: opt_enc(key, &draft.postal_code)?,
            country: opt_enc(key, &draft.country)?,
            company: opt_enc(key, &draft.company)?,
            email: opt_enc(key, &draft.email)?,
            phone: opt_enc(key, &draft.phone)?,
            ssn: opt_enc(key, &draft.ssn)?,
            username: opt_enc(key, &draft.username)?,
            passport_number: opt_enc(key, &draft.passport_number)?,
            license_number: opt_enc(key, &draft.license_number)?,
        }),
        fields: None,
        password_history: None,
        attachments: None,
        attachments2: None,
        organization_id: None,
        collection_ids: None,
        key: None,
        ssh_key: None,
        encrypted_for: user_id.to_string(),
        last_known_revision_date: None,
    })
}

fn encrypt_ssh_key(draft: &SshKeyDraft, key: &UserKey, user_id: &str) -> Result<CipherRequest> {
    Ok(CipherRequest {
        cipher_type: 5,
        name: encrypt_with_key(&draft.name, key)?,
        notes: opt_enc(key, &draft.notes)?,
        folder_id: draft.folder_id.clone(),
        favorite: draft.favorite,
        reprompt: Some(0),
        login: None,
        secure_note: None,
        card: None,
        identity: None,
        fields: None,
        password_history: None,
        attachments: None,
        attachments2: None,
        organization_id: None,
        collection_ids: None,
        key: None,
        ssh_key: Some(CipherSshKey {
            private_key: opt_enc(key, &draft.private_key)?,
            public_key: opt_enc(key, &draft.public_key)?,
            key_fingerprint: opt_enc(key, &draft.fingerprint)?,
        }),
        encrypted_for: user_id.to_string(),
        last_known_revision_date: None,
    })
}

/// Remove a legacy plaintext refresh token from `auth.json` when the keyring holds the secret.
fn scrub_refresh_token_from_auth_file(data_dir: &Path) -> Result<()> {
    let path = data_dir.join("auth.json");
    if !path.is_file() {
        return Ok(());
    }
    let json = std::fs::read_to_string(&path)?;
    let mut auth: PersistedAuth =
        serde_json::from_str(&json).map_err(|e| SessionError::Other(e.to_string()))?;
    if auth.refresh_token.is_none() {
        return Ok(());
    }
    auth.refresh_token = None;
    let out =
        serde_json::to_string_pretty(&auth).map_err(|e| SessionError::Other(e.to_string()))?;
    write_atomic(&path, out.as_bytes())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Current TOTP code plus timing for UI countdowns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpDisplay {
    pub code: String,
    pub period: u64,
    pub remaining: u64,
}

/// Build a [`TOTP`] from a Bitwarden secret, `otpauth://`, or `steam://` URI.
fn totp_from_secret_inner(secret_or_uri: &str) -> Result<TOTP> {
    let s = secret_or_uri.trim();
    if s.starts_with("otpauth://") {
        return TOTP::from_url(s).map_err(|e| SessionError::Other(e.to_string()));
    }
    if let Some(rest) = s.strip_prefix("steam://") {
        let secret = Secret::Encoded(rest.to_string())
            .to_bytes()
            .map_err(|e| SessionError::Other(format!("{e:?}")))?;
        return Ok(TOTP::new_steam(secret, "Steam".into()));
    }
    let secret = Secret::Encoded(s.to_string())
        .to_bytes()
        .map_err(|e| SessionError::Other(format!("{e:?}")))?;
    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret,
        None,
        "bitwarden-tui".to_string(),
    )
    .map_err(|e| SessionError::Other(e.to_string()))
}

/// Compute the current TOTP code from a Bitwarden secret or `otpauth://` / `steam://` URI.
pub fn totp_from_secret(secret_or_uri: &str) -> Result<String> {
    totp_display_from_secret(secret_or_uri).map(|d| d.code)
}

/// Current TOTP code with period and seconds remaining in the window.
pub fn totp_display_from_secret(secret_or_uri: &str) -> Result<TotpDisplay> {
    let totp = totp_from_secret_inner(secret_or_uri)?;
    let code = totp
        .generate_current()
        .map_err(|e| SessionError::Other(e.to_string()))?;
    let period = totp.step.max(1);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let remaining = period - (now % period);
    Ok(TotpDisplay {
        code,
        period,
        remaining,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn revision_change_detection() {
        assert!(revision_changed(None, 5));
        assert!(!revision_changed(Some(5), 5));
        assert!(revision_changed(Some(5), 6));
    }

    use std::sync::Arc;

    use super::*;
    use crate::models::PersistedAuth;
    use crate::secure_storage::{
        with_refresh_token_store_for_tests, FailingRefreshTokenStore, MemoryRefreshTokenStore,
        RefreshTokenStore,
    };

    fn block_on_test<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(fut)
    }

    fn write_dummy_auth(dir: &Path, refresh: Option<&str>) {
        let auth = PersistedAuth {
            server_url: "http://127.0.0.1:8080".into(),
            email: "a@b.c".into(),
            refresh_token: refresh.map(str::to_string),
            device_id: "dev".into(),
            protected_key: None,
            private_key: None,
            kdf: None,
            kdf_iterations: None,
            kdf_memory: None,
            kdf_parallelism: None,
            two_factor_device_token: None,
        };
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(
            dir.join("auth.json"),
            serde_json::to_string_pretty(&auth).unwrap(),
        )
        .unwrap();
    }

    fn read_auth(dir: &Path) -> PersistedAuth {
        let json = std::fs::read_to_string(dir.join("auth.json")).unwrap();
        serde_json::from_str(&json).unwrap()
    }

    #[test]
    fn encrypt_login_round_trips_uris_and_match_types() {
        use crate::models::DecryptedUri;
        use vault_crypto::{decrypt_with_key, generate_user_key};

        let key = generate_user_key();
        let draft = LoginDraft {
            name: "Site".into(),
            uris: vec![
                DecryptedUri {
                    uri: "https://a.example".into(),
                    match_type: Some(2),
                },
                DecryptedUri {
                    uri: "https://b.example".into(),
                    match_type: Some(3),
                },
            ],
            ..Default::default()
        };
        let req = encrypt_login(&draft, &key, "user-1").unwrap();
        let login = req.login.expect("login");
        let uris = login.uris.expect("uris");
        assert_eq!(uris.len(), 2);
        assert_eq!(uris[0].match_type, Some(2));
        assert_eq!(uris[1].match_type, Some(3));
        let a = decrypt_with_key(uris[0].uri.as_ref().unwrap(), &key).unwrap();
        assert_eq!(a, "https://a.example");
    }

    #[test]
    fn with_data_dir_uses_given_path() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("profiles/work");
        let session = Session::with_data_dir("http://127.0.0.1:8080", dir.clone()).unwrap();
        assert_eq!(session.data_dir(), dir.as_path());
        assert!(dir.is_dir());
    }

    #[test]
    fn clear_persisted_auth_only_touches_given_dir() {
        with_refresh_token_store_for_tests(Arc::new(MemoryRefreshTokenStore::new()), || {
            let tmp = tempfile::tempdir().unwrap();
            let a = tmp.path().join("a");
            let b = tmp.path().join("b");
            write_dummy_auth(&a, Some("tok-a"));
            write_dummy_auth(&b, Some("tok-b"));
            Session::clear_persisted_auth(&a);
            assert!(!a.join("auth.json").exists());
            assert!(b.join("auth.json").exists());
        });
    }

    #[test]
    fn master_password_rewrap_roundtrip() {
        use vault_crypto::{
            auth_hash, derive_master_key, generate_user_key, unwrap_user_key, wrap_user_key,
            KdfParams,
        };
        let email = "user@example.com";
        let kdf = KdfParams::Pbkdf2 {
            iterations: 600_000,
        };
        let old_pw = "OldMasterPass1!";
        let new_pw = "NewMasterPass2!";
        let user = generate_user_key();
        let old_master = derive_master_key(old_pw, email, &kdf).unwrap();
        let _old_hash = auth_hash(&old_master, old_pw).unwrap();
        let new_master = derive_master_key(new_pw, email, &kdf).unwrap();
        let new_hash = auth_hash(&new_master, new_pw).unwrap();
        assert_ne!(
            _old_hash.as_str(),
            new_hash.as_str(),
            "hashes must differ when password changes"
        );
        let new_protected = wrap_user_key(&user, &new_master).unwrap();
        let unlocked = unwrap_user_key(&new_protected, &new_master).unwrap();
        assert_eq!(unlocked.to_bytes().as_ref(), user.to_bytes().as_ref());
    }

    #[test]
    fn logout_clears_only_session_auth_file() {
        with_refresh_token_store_for_tests(Arc::new(MemoryRefreshTokenStore::new()), || {
            let tmp = tempfile::tempdir().unwrap();
            let a = tmp.path().join("a");
            let b = tmp.path().join("b");
            write_dummy_auth(&a, Some("tok-a"));
            write_dummy_auth(&b, Some("tok-b"));
            let mut session = Session::with_data_dir("http://127.0.0.1:8080", a.clone()).unwrap();
            session.logout();
            assert!(!a.join("auth.json").exists());
            assert!(b.join("auth.json").exists());
            assert_eq!(session.status(), SessionStatus::LoggedOut);
        });
    }

    #[tokio::test]
    async fn try_restore_saved_none_without_auth() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("empty");
        std::fs::create_dir_all(&dir).unwrap();
        let restored = Session::try_restore_saved(dir, false).await.unwrap();
        assert!(restored.is_none());
    }

    #[test]
    fn persist_auth_uses_secure_storage_and_omits_disk_token() {
        let mem = Arc::new(MemoryRefreshTokenStore::new());
        with_refresh_token_store_for_tests(mem.clone(), || {
            let tmp = tempfile::tempdir().unwrap();
            let dir = tmp.path().join("profiles/work");
            let mut session = Session::with_data_dir("http://127.0.0.1:8080", dir.clone()).unwrap();
            session.email = Some("u@ex.com".into());
            session
                .client
                .set_tokens("access".into(), Some("refresh-secret".into()));
            session.persist_auth().unwrap();

            let auth = read_auth(&dir);
            assert!(auth.refresh_token.is_none());
            assert_eq!(mem.get("work").unwrap().as_deref(), Some("refresh-secret"));
        });
    }

    #[test]
    fn persist_auth_falls_back_to_disk_when_secure_storage_fails() {
        with_refresh_token_store_for_tests(Arc::new(FailingRefreshTokenStore), || {
            let tmp = tempfile::tempdir().unwrap();
            let dir = tmp.path().join("profiles/home");
            let mut session = Session::with_data_dir("http://127.0.0.1:8080", dir.clone()).unwrap();
            session.set_allow_plaintext_token(true);
            session.email = Some("u@ex.com".into());
            session
                .client
                .set_tokens("access".into(), Some("disk-tok".into()));
            session.persist_auth().unwrap();

            let auth = read_auth(&dir);
            assert_eq!(auth.refresh_token.as_deref(), Some("disk-tok"));
            assert!(session.storage_warning.is_some());
        });
    }

    #[test]
    fn persist_auth_scrubs_legacy_disk_token_when_keyring_works() {
        let mem = Arc::new(MemoryRefreshTokenStore::new());
        with_refresh_token_store_for_tests(mem.clone(), || {
            let tmp = tempfile::tempdir().unwrap();
            let dir = tmp.path().join("profiles/work");
            write_dummy_auth(&dir, Some("legacy-disk"));
            let mut session = Session::with_data_dir("http://127.0.0.1:8080", dir.clone()).unwrap();
            session.email = Some("u@ex.com".into());
            session
                .client
                .set_tokens("access".into(), Some("refresh-new".into()));
            session.persist_auth().unwrap();
            let auth = read_auth(&dir);
            assert!(auth.refresh_token.is_none());
            assert_eq!(mem.get("work").unwrap().as_deref(), Some("refresh-new"));
        });
    }

    #[test]
    fn persist_auth_errors_when_secure_storage_fails_without_plaintext() {
        with_refresh_token_store_for_tests(Arc::new(FailingRefreshTokenStore), || {
            let tmp = tempfile::tempdir().unwrap();
            let dir = tmp.path().join("profiles/home");
            let mut session = Session::with_data_dir("http://127.0.0.1:8080", dir.clone()).unwrap();
            session.set_allow_plaintext_token(false);
            session.email = Some("u@ex.com".into());
            session
                .client
                .set_tokens("access".into(), Some("disk-tok".into()));
            assert!(session.persist_auth().is_err());
        });
    }

    #[test]
    fn resolve_refresh_prefers_secure_storage_over_disk() {
        let mem = Arc::new(MemoryRefreshTokenStore::new());
        with_refresh_token_store_for_tests(mem.clone(), || {
            mem.set("work", "from-keyring").unwrap();
            let tmp = tempfile::tempdir().unwrap();
            let dir = tmp.path().join("profiles/work");
            write_dummy_auth(&dir, Some("from-disk"));
            let auth = read_auth(&dir);
            let resolved = Session::resolve_refresh_token(&dir, &auth).unwrap();
            assert_eq!(resolved, "from-keyring");
        });
    }

    #[test]
    fn resolve_refresh_uses_legacy_disk_token() {
        with_refresh_token_store_for_tests(Arc::new(MemoryRefreshTokenStore::new()), || {
            let tmp = tempfile::tempdir().unwrap();
            let dir = tmp.path().join("profiles/work");
            // Legacy plaintext string in JSON
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                dir.join("auth.json"),
                r#"{"server_url":"http://127.0.0.1:8080","email":"a@b.c","refresh_token":"legacy","device_id":"dev"}"#,
            )
            .unwrap();
            let auth = read_auth(&dir);
            assert_eq!(auth.refresh_token.as_deref(), Some("legacy"));
            assert_eq!(
                Session::resolve_refresh_token(&dir, &auth).as_deref(),
                Some("legacy")
            );
        });
    }

    #[test]
    fn clear_removes_secure_storage_entry() {
        let mem = Arc::new(MemoryRefreshTokenStore::new());
        with_refresh_token_store_for_tests(mem.clone(), || {
            mem.set("work", "tok").unwrap();
            let tmp = tempfile::tempdir().unwrap();
            let dir = tmp.path().join("profiles/work");
            write_dummy_auth(&dir, None);
            Session::clear_persisted_auth(&dir);
            assert!(!dir.join("auth.json").exists());
            assert_eq!(mem.get("work").unwrap(), None);
        });
    }

    fn seed_offline_vault(dir: &Path, email: &str, password: &str) -> UserKey {
        use vault_api::{Cipher, CipherLogin, Folder, Profile, SyncResponse};
        use vault_crypto::{derive_master_key, generate_user_key, wrap_user_key, KdfParams};

        let kdf = KdfParams::Pbkdf2 {
            iterations: 100_000,
        };
        let master = derive_master_key(password, email, &kdf).unwrap();
        let user_key = generate_user_key();
        let protected = wrap_user_key(&user_key, &master).unwrap();

        let auth = PersistedAuth {
            server_url: "http://127.0.0.1:1".into(), // unreachable — forces offline paths
            email: email.into(),
            refresh_token: Some("offline-refresh".into()),
            device_id: "dev".into(),
            protected_key: Some(protected),
            private_key: None,
            kdf: Some(0),
            kdf_iterations: Some(100_000),
            kdf_memory: None,
            kdf_parallelism: None,
            two_factor_device_token: None,
        };
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(
            dir.join("auth.json"),
            serde_json::to_string_pretty(&auth).unwrap(),
        )
        .unwrap();

        let sync = SyncResponse {
            profile: Some(Profile {
                id: "user-offline".into(),
                email: Some(email.into()),
                name: Some("Offline".into()),
                key: None,
                private_key: None,
                organizations: vec![],
                security_stamp: None,
            }),
            folders: vec![Folder {
                id: Some("f1".into()),
                name: encrypt_with_key("Personal", &user_key).unwrap(),
                revision_date: None,
                object: None,
            }],
            collections: vec![],
            ciphers: vec![Cipher {
                id: Some("c1".into()),
                folder_id: Some("f1".into()),
                organization_id: None,
                name: encrypt_with_key("Example", &user_key).unwrap(),
                notes: None,
                cipher_type: 1,
                favorite: false,
                deleted_date: None,
                reprompt: Some(0),
                key: None,
                login: Some(CipherLogin {
                    uris: None,
                    username: Some(encrypt_with_key("user", &user_key).unwrap()),
                    password: Some(encrypt_with_key("secret-pw", &user_key).unwrap()),
                    password_revision_date: None,
                    totp: None,
                    autofill_on_page_load: None,
                    fido2_credentials: None,
                    extra: Default::default(),
                }),
                secure_note: None,
                card: None,
                identity: None,
                fields: None,
                password_history: None,
                attachments: None,
                organization_use_totp: None,
                revision_date: None,
                creation_date: None,
                collection_ids: None,
                object: None,
                ssh_key: None,
                extra: Default::default(),
            }],
            sends: vec![],
            policies: vec![],
            domains: None,
        };
        vault_cache::save(dir, &sync, &user_key, "user-offline").unwrap();
        user_key
    }

    #[test]
    fn restore_keeps_auth_when_refresh_fails_but_cache_exists() {
        with_refresh_token_store_for_tests(Arc::new(MemoryRefreshTokenStore::new()), || {
            block_on_test(async {
                let tmp = tempfile::tempdir().unwrap();
                let dir = tmp.path().join("profiles/work");
                let _ = seed_offline_vault(&dir, "a@b.c", "TestPassword123!");
                assert!(dir.join("auth.json").exists());
                assert!(vault_cache::exists(&dir));

                let restored = Session::try_restore_saved(dir.clone(), false)
                    .await
                    .unwrap();
                assert!(restored.is_some());
                assert!(dir.join("auth.json").exists());
                assert!(vault_cache::exists(&dir));
                let session = restored.unwrap();
                assert_eq!(session.status(), SessionStatus::Locked);
                assert_eq!(session.email(), Some("a@b.c"));
            });
        });
    }

    #[test]
    fn unlock_offline_from_encrypted_cache() {
        with_refresh_token_store_for_tests(Arc::new(MemoryRefreshTokenStore::new()), || {
            block_on_test(async {
                let tmp = tempfile::tempdir().unwrap();
                let dir = tmp.path().join("profiles/work");
                let _ = seed_offline_vault(&dir, "a@b.c", "TestPassword123!");

                let mut session = Session::try_restore_saved(dir.clone(), true)
                    .await
                    .unwrap()
                    .expect("restored");
                session
                    .unlock("TestPassword123!")
                    .await
                    .expect("offline unlock");
                assert!(session.is_offline());
                assert_eq!(session.status(), SessionStatus::Unlocked);
                assert_eq!(session.items().len(), 1);
                assert_eq!(session.items()[0].name, "Example");
                assert_eq!(session.items()[0].password.as_deref(), Some("secret-pw"));
                assert!(session.last_synced_at().is_some());

                let err = session
                    .create_login(&LoginDraft {
                        name: "x".into(),
                        ..Default::default()
                    })
                    .await
                    .unwrap_err();
                assert!(matches!(err, SessionError::Offline));

                session.logout();
                assert!(!dir.join("auth.json").exists());
                assert!(!vault_cache::exists(&dir));
            });
        });
    }

    #[test]
    fn restore_clears_auth_when_refresh_fails_without_cache() {
        with_refresh_token_store_for_tests(Arc::new(MemoryRefreshTokenStore::new()), || {
            block_on_test(async {
                let tmp = tempfile::tempdir().unwrap();
                let dir = tmp.path().join("profiles/work");
                let auth = PersistedAuth {
                    server_url: "http://127.0.0.1:1".into(),
                    email: "a@b.c".into(),
                    refresh_token: Some("stale".into()),
                    device_id: "dev".into(),
                    protected_key: None,
                    private_key: None,
                    kdf: Some(0),
                    kdf_iterations: Some(100_000),
                    kdf_memory: None,
                    kdf_parallelism: None,
                    two_factor_device_token: None,
                };
                std::fs::create_dir_all(&dir).unwrap();
                std::fs::write(
                    dir.join("auth.json"),
                    serde_json::to_string_pretty(&auth).unwrap(),
                )
                .unwrap();

                let restored = Session::try_restore_saved(dir.clone(), false)
                    .await
                    .unwrap();
                assert!(restored.is_none());
                assert!(!dir.join("auth.json").exists());
            });
        });
    }
}

#[cfg(test)]
mod policy_enforcement_tests {
    use super::*;
    use crate::policies::parse_policies;
    use serde_json::json;

    fn session_with(policies: Vec<serde_json::Value>) -> (tempfile::TempDir, Session) {
        let tmp = tempfile::tempdir().unwrap();
        let mut s = Session::with_data_dir("http://127.0.0.1:8080", tmp.path().join("p")).unwrap();
        s.policies = parse_policies(&policies);
        (tmp, s)
    }

    fn pol(ty: u8, data: serde_json::Value) -> serde_json::Value {
        json!({ "id": format!("p{ty}"), "organizationId": "o", "type": ty, "enabled": true, "data": data })
    }

    #[test]
    fn vault_timeout_policy_caps_profile_timeout() {
        let (_t, mut s) = session_with(vec![pol(9, json!({ "minutes": 10, "action": "logOut" }))]);
        s.set_auto_lock(Some(60));
        assert_eq!(s.effective_auto_lock_minutes(), Some(10));
        s.set_auto_lock(None);
        assert_eq!(s.effective_auto_lock_minutes(), Some(10));
        s.set_auto_lock(Some(5));
        assert_eq!(s.effective_auto_lock_minutes(), Some(5));
        s.set_timeout_action(TimeoutAction::Lock);
        assert_eq!(s.effective_timeout_action(), TimeoutAction::Logout);
    }

    #[test]
    fn no_policy_keeps_profile_timeout_and_action() {
        let (_t, mut s) = session_with(vec![]);
        s.set_auto_lock(None);
        assert_eq!(s.effective_auto_lock_minutes(), None);
        s.set_timeout_action(TimeoutAction::Logout);
        assert_eq!(s.effective_timeout_action(), TimeoutAction::Logout);
    }

    #[test]
    fn timeout_action_logout_logs_out() {
        let (_t, mut s) = session_with(vec![]);
        s.status = SessionStatus::Unlocked;
        s.set_timeout_action(TimeoutAction::Logout);
        assert_eq!(s.apply_timeout_action(), TimeoutAction::Logout);
        assert_eq!(s.status(), SessionStatus::LoggedOut);

        s.status = SessionStatus::Unlocked;
        s.set_timeout_action(TimeoutAction::Lock);
        assert_eq!(s.apply_timeout_action(), TimeoutAction::Lock);
        assert_eq!(s.status(), SessionStatus::Locked);
    }

    #[test]
    fn pin_policy_blocks_pin() {
        let (_t, s) = session_with(vec![pol(14, json!({}))]);
        assert!(!s.pin_unlock_available());
        assert!(matches!(
            s.configure_pin("1234"),
            Err(SessionError::PolicyViolation(_))
        ));
    }

    #[test]
    fn item_creation_policies() {
        let (_t, s) = session_with(vec![pol(15, json!([3]))]);
        assert!(s.check_item_creation_allowed(ItemType::Login).is_ok());
        assert!(matches!(
            s.check_item_creation_allowed(ItemType::Card),
            Err(SessionError::PolicyViolation(_))
        ));
        let (_t, s) = session_with(vec![pol(5, json!({}))]);
        assert!(s.check_item_creation_allowed(ItemType::Login).is_err());
    }

    #[test]
    fn master_password_policy_check() {
        let (_t, s) = session_with(vec![pol(
            1,
            json!({ "minLength": 14, "requireNumbers": true }),
        )]);
        assert!(s.check_master_password_policy("short").is_err());
        assert!(s
            .check_master_password_policy("a-long-enough-pass-9")
            .is_ok());
    }

    #[test]
    fn policies_load_from_disk_on_new_session() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("p");
        {
            let mut s = Session::with_data_dir("http://127.0.0.1:8080", dir.clone()).unwrap();
            s.policies = parse_policies(&[pol(14, json!({}))]);
            save_policies(&dir, &s.policies).unwrap();
        }
        let s = Session::with_data_dir("http://127.0.0.1:8080", dir).unwrap();
        assert!(s.pin_unlock_blocked_by_policy());
    }
}
