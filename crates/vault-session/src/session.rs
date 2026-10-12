use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use chrono::{DateTime, FixedOffset};
use totp_rs::{Algorithm, Secret, TOTP};
use vault_api::{
    CipherLogin, CipherRequest, CipherSecureNote, ClientConfig, LoginUri, RegisterKeys,
    RegisterRequest, VaultClient,
};
use vault_crypto::{
    auth_hash, derive_master_key, encrypt_bytes, encrypt_with_key, generate_rsa_keypair,
    generate_user_key, unwrap_user_key, wrap_user_key, KdfParams, MasterKey, UserKey,
};
use zeroize::Zeroize;

use crate::clipboard::ClipboardService;
use crate::decrypt::build_index;
use crate::error::{Result, SessionError};
use crate::models::*;
use crate::paths::app_data_dir;
use crate::secure_storage::{
    delete_refresh_token_best_effort, get_refresh_token, profile_id_from_data_dir,
    set_refresh_token,
};
use crate::vault_cache;

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
    /// `None` disables idle auto-lock.
    auto_lock: Option<Duration>,
    pub clipboard: ClipboardService,
    data_dir: PathBuf,
    /// True when the in-memory vault came from the encrypted offline cache.
    offline: bool,
    last_synced_at: Option<DateTime<FixedOffset>>,
}

impl Session {
    /// Create a session using the default app data directory (legacy / tests).
    pub fn new(server_url: &str) -> Result<Self> {
        Self::with_data_dir(server_url, app_data_dir())
    }

    /// Create a session that persists auth under `data_dir` (typically a profile directory).
    pub fn with_data_dir(server_url: &str, data_dir: PathBuf) -> Result<Self> {
        let client = VaultClient::new(ClientConfig::new(server_url))?;
        let _ = std::fs::create_dir_all(&data_dir);
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
            clipboard: ClipboardService::new(30),
            last_synced_at: vault_cache::synced_at(&data_dir),
            data_dir,
            offline: false,
        })
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

    fn load_from_cache(&mut self) -> Result<()> {
        let (sync, synced_at) = {
            let user_key = self.user_key.as_ref().ok_or(SessionError::Locked)?;
            vault_cache::load(&self.data_dir, user_key)?
        };
        self.apply_sync_profile(&sync);
        {
            let user_key = self.user_key.as_ref().ok_or(SessionError::Locked)?;
            self.index = build_index(&sync, user_key)?;
        }
        self.last_synced_at = Some(synced_at);
        self.offline = true;
        self.touch();
        Ok(())
    }

    fn write_cache(&mut self, sync: &vault_api::SyncResponse) {
        let Some(user_key) = self.user_key.as_ref() else {
            return;
        };
        match vault_cache::save(&self.data_dir, sync, user_key) {
            Ok(synced_at) => {
                self.last_synced_at = Some(synced_at);
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to write encrypted vault cache");
            }
        }
    }

    /// Set idle auto-lock timeout in minutes. `None` disables auto-lock.
    pub fn set_auto_lock(&mut self, minutes: Option<u64>) {
        self.auto_lock = minutes.map(|m| Duration::from_secs(m.saturating_mul(60)));
    }

    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    pub fn lock_remaining(&self) -> Option<Duration> {
        if self.status != SessionStatus::Unlocked {
            return None;
        }
        let timeout = self.auto_lock?;
        Some(timeout.saturating_sub(self.last_activity.elapsed()))
    }

    pub fn tick(&mut self) {
        self.clipboard.tick();
        if let Some(timeout) = self.auto_lock {
            if self.status == SessionStatus::Unlocked && self.last_activity.elapsed() >= timeout {
                self.lock();
            }
        }
    }

    pub fn lock(&mut self) {
        self.user_key = None;
        if let Some(mk) = self.master_key.as_mut() {
            let _ = mk; // ZeroizeOnDrop
        }
        self.master_key = None;
        self.index = VaultIndex::default();
        if self.status == SessionStatus::Unlocked {
            self.status = SessionStatus::Locked;
        }
    }

    pub async fn register(&mut self, email: &str, password: &str, name: Option<&str>) -> Result<()> {
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
        let prelogin = self.client.prelogin(email).await?;
        let kdf = prelogin.to_kdf_params();
        self.remember_kdf(kdf.clone());
        let master = derive_master_key(password, email, &kdf)?;
        let hash = auth_hash(&master, password)?;

        match self
            .client
            .login(email, hash.as_str(), two_factor)
            .await
        {
            Ok(token) => {
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
            Err(vault_api::ApiError::TwoFactorRequired { providers, .. }) => {
                self.email = Some(email.to_string());
                self.master_key = Some(master);
                // Keep hash path: caller retries with 2FA
                // Store password hash context via master key only
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
        match self.login(email, password, Some((provider, code))).await? {
            LoginResult::Success => Ok(()),
            LoginResult::TwoFactorRequired { .. } => Err(SessionError::Other(
                "2FA still required — check code".into(),
            )),
        }
    }

    pub async fn unlock(&mut self, password: &str) -> Result<()> {
        let email = self
            .email
            .clone()
            .ok_or(SessionError::NotLoggedIn)?;
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
                self.kdf
                    .clone()
                    .ok_or_else(|| SessionError::Other(
                        "Cannot unlock offline: missing cached KDF (unlock once online first)"
                            .into(),
                    ))?
            }
            Err(e) => return Err(e.into()),
        };

        let master = derive_master_key(password, &email, &kdf)?;
        self.master_key = Some(master);
        self.unlock_with_master()?;

        match self.sync().await {
            Ok(()) => Ok(()),
            Err(SessionError::Api(ref e))
                if e.is_transport()
                    || matches!(e, vault_api::ApiError::Http(_))
                    || matches!(e, vault_api::ApiError::NotAuthenticated) =>
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

    pub async fn sync(&mut self) -> Result<()> {
        // Sync is allowed while offline — success clears the offline flag.
        let sync = match self.client.sync().await {
            Ok(s) => s,
            Err(first) => {
                match self.client.refresh().await {
                    Ok(_) => self.client.sync().await?,
                    Err(refresh_err) => {
                        if self.offline && vault_cache::exists(&self.data_dir) {
                            return Err(SessionError::Offline);
                        }
                        return Err(if matches!(
                            first,
                            vault_api::ApiError::Http(_) | vault_api::ApiError::NotAuthenticated
                        ) {
                            refresh_err.into()
                        } else {
                            first.into()
                        });
                    }
                }
            }
        };
        self.apply_sync_profile(&sync);
        {
            let user_key = self.user_key.as_ref().ok_or(SessionError::Locked)?;
            self.index = build_index(&sync, user_key)?;
        }
        self.write_cache(&sync);
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

    pub fn get_item(&self, id: &str) -> Option<&DecryptedItem> {
        self.index.items.iter().find(|i| i.id == id)
    }

    pub fn verify_reprompt(&self, password: &str) -> Result<bool> {
        let email = self.email.as_ref().ok_or(SessionError::NotLoggedIn)?;
        let master = self.master_key.as_ref();
        // Re-derive and compare to stored master key bytes
        // We may have cleared master on lock — for unlock path use derive
        let kdf = vault_crypto::KdfParams::default();
        let derived = derive_master_key(password, email, &kdf)?;
        if let Some(mk) = master {
            Ok(mk.as_bytes() == derived.as_bytes())
        } else {
            Ok(false)
        }
    }

    pub fn copy_password(&mut self, id: &str) -> Result<()> {
        let item = self.get_item(id).ok_or(SessionError::NotFound)?;
        if item.reprompt {
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

    pub fn copy_totp(&mut self, id: &str) -> Result<String> {
        let item = self.get_item(id).ok_or(SessionError::NotFound)?;
        if item.reprompt {
            return Err(SessionError::RepromptRequired);
        }
        let secret = item
            .totp
            .clone()
            .ok_or_else(|| SessionError::Other("no totp".into()))?;
        let code = totp_code(&secret)?;
        self.clipboard.copy_secret(&code)?;
        self.touch();
        Ok(code)
    }

    pub fn totp_now(&self, id: &str) -> Option<String> {
        let item = self.get_item(id)?;
        let secret = item.totp.as_ref()?;
        totp_code(secret).ok()
    }

    pub async fn create_login(&mut self, draft: &LoginDraft) -> Result<String> {
        self.ensure_online()?;
        let user_key = self.user_key.as_ref().ok_or(SessionError::Locked)?;
        let user_id = self.user_id()?;
        let req = encrypt_login(draft, user_key, user_id)?;
        let created = self.client.create_cipher(&req).await?;
        let id = created.id.clone().unwrap_or_default();
        self.sync().await?;
        Ok(id)
    }

    pub async fn update_login(&mut self, id: &str, draft: &LoginDraft) -> Result<()> {
        self.ensure_online()?;
        let user_key = self.user_key.as_ref().ok_or(SessionError::Locked)?;
        let user_id = self.user_id()?;
        let mut req = encrypt_login(draft, user_key, user_id)?;
        if let Some(item) = self.get_item(id) {
            req.last_known_revision_date = item.revision_date.clone();
        }
        self.client.update_cipher(id, &req).await?;
        self.sync().await?;
        Ok(())
    }

    pub async fn create_note(&mut self, draft: &NoteDraft) -> Result<String> {
        self.ensure_online()?;
        let user_key = self.user_key.as_ref().ok_or(SessionError::Locked)?;
        let user_id = self.user_id()?.to_string();
        let req = CipherRequest {
            cipher_type: 2,
            name: encrypt_with_key(&draft.name, user_key)?,
            notes: draft
                .notes
                .as_ref()
                .map(|n| encrypt_with_key(n, user_key))
                .transpose()?,
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
            organization_id: None,
            collection_ids: None,
            key: None,
            encrypted_for: user_id,
            last_known_revision_date: None,
        };
        let created = self.client.create_cipher(&req).await?;
        let id = created.id.clone().unwrap_or_default();
        self.sync().await?;
        Ok(id)
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
        let user_key = self.user_key.as_ref().ok_or(SessionError::Locked)?;
        let user_id = self.user_id()?.to_string();
        let mut draft = LoginDraft {
            name: item.name.clone(),
            username: item.username.clone(),
            password: item.password.clone(),
            totp: item.totp.clone(),
            uri: item.primary_uri().map(str::to_string),
            notes: item.notes.clone(),
            folder_id: item.folder_id.clone(),
            favorite: !item.favorite,
            reprompt: item.reprompt,
        };
        if item.item_type == ItemType::Login {
            let mut req = encrypt_login(&draft, user_key, &user_id)?;
            req.last_known_revision_date = item.revision_date.clone();
            self.client.update_cipher(id, &req).await?;
        } else if item.item_type == ItemType::SecureNote {
            let req = CipherRequest {
                cipher_type: 2,
                name: encrypt_with_key(&draft.name, user_key)?,
                notes: draft
                    .notes
                    .as_ref()
                    .map(|n| encrypt_with_key(n, user_key))
                    .transpose()?,
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
                organization_id: None,
                collection_ids: None,
                key: None,
                encrypted_for: user_id,
                last_known_revision_date: item.revision_date.clone(),
            };
            self.client.update_cipher(id, &req).await?;
        }
        draft.zeroize_fields();
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

    fn persist_auth(&self) -> Result<()> {
        let Some(email) = &self.email else {
            return Ok(());
        };
        let Some(refresh) = self.client.refresh_token() else {
            return Ok(());
        };

        let profile_id = profile_id_from_data_dir(&self.data_dir);
        let disk_refresh = match profile_id.as_deref() {
            Some(id) => match set_refresh_token(id, refresh) {
                Ok(()) => None,
                Err(e) => {
                    tracing::warn!(
                        profile_id = %id,
                        error = %e,
                        "secure storage unavailable; storing refresh token on disk"
                    );
                    Some(refresh.to_string())
                }
            },
            None => Some(refresh.to_string()),
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
        };
        if let Some(kdf) = &self.kdf {
            auth.set_kdf_from_params(kdf);
        }
        let _ = std::fs::create_dir_all(&self.data_dir);
        let path = self.data_dir.join("auth.json");
        let json = serde_json::to_string_pretty(&auth)
            .map_err(|e| SessionError::Other(e.to_string()))?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Remove persisted session (`auth.json`, vault cache, secure-storage refresh token).
    pub fn clear_persisted_auth(data_dir: &Path) {
        if let Some(id) = profile_id_from_data_dir(data_dir) {
            delete_refresh_token_best_effort(&id);
        }
        let path = data_dir.join("auth.json");
        let _ = std::fs::remove_file(path);
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
    pub async fn try_restore(server_url: &str, data_dir: PathBuf) -> Result<Option<Self>> {
        let Some((session, stored_server)) = Self::try_restore_inner(data_dir).await? else {
            return Ok(None);
        };
        if stored_server.trim_end_matches('/') != server_url.trim_end_matches('/') {
            return Ok(None);
        }
        Ok(Some(session))
    }

    /// Restore a locked session from whatever server is stored in `data_dir/auth.json`.
    pub async fn try_restore_saved(data_dir: PathBuf) -> Result<Option<Self>> {
        Ok(Self::try_restore_inner(data_dir).await?.map(|(s, _)| s))
    }

    async fn try_restore_inner(data_dir: PathBuf) -> Result<Option<(Self, String)>> {
        let path = data_dir.join("auth.json");
        if !path.exists() {
            return Ok(None);
        }
        let json = std::fs::read_to_string(&path)?;
        let auth: PersistedAuth =
            serde_json::from_str(&json).map_err(|e| SessionError::Other(e.to_string()))?;
        let Some(refresh) = Self::resolve_refresh_token(&data_dir, &auth) else {
            // Metadata without a usable refresh token — treat as logged out.
            Self::clear_persisted_auth(&data_dir);
            return Ok(None);
        };
        let server_url = auth.server_url.clone();
        let mut config = ClientConfig::new(&server_url);
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
        let session = Self {
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
            clipboard: ClipboardService::new(30),
            last_synced_at,
            data_dir,
            offline: false,
        };
        if refresh_ok {
            // Re-persist in case the server rotated the refresh token (and upgrade disk → keyring).
            let _ = session.persist_auth();
        }
        Ok(Some((session, server_url)))
    }

    pub fn logout(&mut self) {
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
    fn zeroize_fields(&mut self) {
        if let Some(p) = &mut self.password {
            p.zeroize();
        }
    }
}

fn encrypt_login(draft: &LoginDraft, key: &UserKey, user_id: &str) -> Result<CipherRequest> {
    let uris = draft.uri.as_ref().map(|u| {
        vec![LoginUri {
            uri: encrypt_with_key(u, key).ok(),
            match_type: Some(0),
        }]
    });
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
        }),
        secure_note: None,
        card: None,
        identity: None,
        fields: None,
        password_history: None,
        attachments: None,
        organization_id: None,
        collection_ids: None,
        key: None,
        encrypted_for: user_id.to_string(),
        last_known_revision_date: None,
    })
}

fn totp_code(secret_or_uri: &str) -> Result<String> {
    let totp = if secret_or_uri.starts_with("otpauth://") {
        TOTP::from_url(secret_or_uri).map_err(|e| SessionError::Other(e.to_string()))?
    } else {
        let secret = Secret::Encoded(secret_or_uri.to_string())
            .to_bytes()
            .map_err(|e| SessionError::Other(format!("{e:?}")))?;
        TOTP::new(Algorithm::SHA1, 6, 1, 30, secret, None, "bitwarden-tui".to_string())
            .map_err(|e| SessionError::Other(e.to_string()))?
    };
    totp.generate_current()
        .map_err(|e| SessionError::Other(e.to_string()))
}

#[cfg(test)]
mod tests {
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
        let restored = Session::try_restore_saved(dir).await.unwrap();
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
            assert_eq!(
                mem.get("work").unwrap().as_deref(),
                Some("refresh-secret")
            );
        });
    }

    #[test]
    fn persist_auth_falls_back_to_disk_when_secure_storage_fails() {
        with_refresh_token_store_for_tests(Arc::new(FailingRefreshTokenStore), || {
            let tmp = tempfile::tempdir().unwrap();
            let dir = tmp.path().join("profiles/home");
            let mut session = Session::with_data_dir("http://127.0.0.1:8080", dir.clone()).unwrap();
            session.email = Some("u@ex.com".into());
            session
                .client
                .set_tokens("access".into(), Some("disk-tok".into()));
            session.persist_auth().unwrap();

            let auth = read_auth(&dir);
            assert_eq!(auth.refresh_token.as_deref(), Some("disk-tok"));
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
            }],
            sends: vec![],
            policies: vec![],
            domains: None,
        };
        vault_cache::save(dir, &sync, &user_key).unwrap();
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

                let restored = Session::try_restore_saved(dir.clone()).await.unwrap();
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

                let mut session = Session::try_restore_saved(dir.clone())
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
                };
                std::fs::create_dir_all(&dir).unwrap();
                std::fs::write(
                    dir.join("auth.json"),
                    serde_json::to_string_pretty(&auth).unwrap(),
                )
                .unwrap();

                let restored = Session::try_restore_saved(dir.clone()).await.unwrap();
                assert!(restored.is_none());
                assert!(!dir.join("auth.json").exists());
            });
        });
    }
}
