use std::path::PathBuf;
use std::time::{Duration, Instant};

use directories::ProjectDirs;
use totp_rs::{Algorithm, Secret, TOTP};
use vault_api::{
    CipherLogin, CipherRequest, CipherSecureNote, ClientConfig, LoginUri, RegisterKeys,
    RegisterRequest, VaultClient,
};
use vault_crypto::{
    auth_hash, derive_master_key, encrypt_bytes, encrypt_with_key, generate_rsa_keypair,
    generate_user_key, unwrap_user_key, wrap_user_key, MasterKey, UserKey,
};
use zeroize::Zeroize;

use crate::clipboard::ClipboardService;
use crate::decrypt::build_index;
use crate::error::{Result, SessionError};
use crate::models::*;

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
    index: VaultIndex,
    status: SessionStatus,
    last_activity: Instant,
    auto_lock: Duration,
    pub clipboard: ClipboardService,
    data_dir: PathBuf,
}

impl Session {
    pub fn new(server_url: &str) -> Result<Self> {
        let client = VaultClient::new(ClientConfig::new(server_url))?;
        let data_dir = ProjectDirs::from("com", "bitwarden-tui", "bitwarden-tui")
            .map(|p| p.data_dir().to_path_buf())
            .unwrap_or_else(|| PathBuf::from(".bitwarden-tui"));
        let _ = std::fs::create_dir_all(&data_dir);
        Ok(Self {
            client,
            email: None,
            user_id: None,
            protected_key: None,
            private_key_enc: None,
            user_key: None,
            master_key: None,
            index: VaultIndex::default(),
            status: SessionStatus::LoggedOut,
            last_activity: Instant::now(),
            auto_lock: Duration::from_secs(15 * 60),
            clipboard: ClipboardService::new(30),
            data_dir,
        })
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

    pub fn index(&self) -> &VaultIndex {
        &self.index
    }

    pub fn set_auto_lock_secs(&mut self, secs: u64) {
        self.auto_lock = Duration::from_secs(secs);
    }

    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    pub fn lock_remaining(&self) -> Option<Duration> {
        if self.status != SessionStatus::Unlocked {
            return None;
        }
        Some(
            self.auto_lock
                .saturating_sub(self.last_activity.elapsed()),
        )
    }

    pub fn tick(&mut self) {
        self.clipboard.tick();
        if self.status == SessionStatus::Unlocked
            && self.last_activity.elapsed() >= self.auto_lock
        {
            self.lock();
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
        // Refresh tokens if needed
        if self.client.access_token().is_none() {
            if self.client.refresh_token().is_some() {
                let _ = self.client.refresh().await;
            }
        }
        let prelogin = self.client.prelogin(&email).await?;
        let kdf = prelogin.to_kdf_params();
        let master = derive_master_key(password, &email, &kdf)?;
        self.master_key = Some(master);
        self.unlock_with_master()?;
        self.sync().await?;
        Ok(())
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
        let user_key = self.user_key.as_ref().ok_or(SessionError::Locked)?;
        let sync = match self.client.sync().await {
            Ok(s) => s,
            Err(_) => {
                // try refresh
                self.client.refresh().await?;
                self.client.sync().await?
            }
        };
        // Update protected keys from profile if present
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
        self.index = build_index(&sync, user_key)?;
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
        let user_key = self.user_key.as_ref().ok_or(SessionError::Locked)?;
        let user_id = self.user_id()?;
        let req = encrypt_login(draft, user_key, user_id)?;
        let created = self.client.create_cipher(&req).await?;
        let id = created.id.clone().unwrap_or_default();
        self.sync().await?;
        Ok(id)
    }

    pub async fn update_login(&mut self, id: &str, draft: &LoginDraft) -> Result<()> {
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
        self.client.soft_delete_cipher(id).await?;
        self.sync().await?;
        Ok(())
    }

    pub async fn restore(&mut self, id: &str) -> Result<()> {
        self.client.restore_cipher(id).await?;
        self.sync().await?;
        Ok(())
    }

    pub async fn hard_delete(&mut self, id: &str) -> Result<()> {
        self.client.delete_cipher(id).await?;
        self.sync().await?;
        Ok(())
    }

    pub async fn toggle_favorite(&mut self, id: &str) -> Result<()> {
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
        let user_key = self.user_key.as_ref().ok_or(SessionError::Locked)?;
        let enc_name = encrypt_with_key(name, user_key)?;
        let folder = self.client.create_folder(&enc_name).await?;
        let id = folder.id.clone().unwrap_or_default();
        self.sync().await?;
        Ok(id)
    }

    pub async fn rename_folder(&mut self, id: &str, name: &str) -> Result<()> {
        let user_key = self.user_key.as_ref().ok_or(SessionError::Locked)?;
        let enc_name = encrypt_with_key(name, user_key)?;
        self.client.update_folder(id, &enc_name).await?;
        self.sync().await?;
        Ok(())
    }

    pub async fn delete_folder(&mut self, id: &str) -> Result<()> {
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
        let auth = PersistedAuth {
            server_url: self.client.base_url().to_string(),
            email: email.clone(),
            refresh_token: refresh.to_string(),
            device_id: self.client.device_id().to_string(),
            protected_key: self.protected_key.clone(),
            private_key: self.private_key_enc.clone(),
        };
        let path = self.data_dir.join("auth.json");
        let json = serde_json::to_string_pretty(&auth)
            .map_err(|e| SessionError::Other(e.to_string()))?;
        std::fs::write(path, json)?;
        Ok(())
    }

    fn auth_data_dir() -> PathBuf {
        ProjectDirs::from("com", "bitwarden-tui", "bitwarden-tui")
            .map(|p| p.data_dir().to_path_buf())
            .unwrap_or_else(|| PathBuf::from(".bitwarden-tui"))
    }

    /// Remove persisted refresh-token session (`auth.json`).
    pub fn clear_persisted_auth() {
        let path = Self::auth_data_dir().join("auth.json");
        let _ = std::fs::remove_file(path);
    }

    /// Restore a locked session from `auth.json` if the server URL matches.
    pub async fn try_restore(server_url: &str) -> Result<Option<Self>> {
        let Some((session, stored_server)) = Self::try_restore_inner().await? else {
            return Ok(None);
        };
        if stored_server.trim_end_matches('/') != server_url.trim_end_matches('/') {
            return Ok(None);
        }
        Ok(Some(session))
    }

    /// Restore a locked session from whatever server is stored in `auth.json`.
    pub async fn try_restore_saved() -> Result<Option<Self>> {
        Ok(Self::try_restore_inner().await?.map(|(s, _)| s))
    }

    async fn try_restore_inner() -> Result<Option<(Self, String)>> {
        let data_dir = Self::auth_data_dir();
        let path = data_dir.join("auth.json");
        if !path.exists() {
            return Ok(None);
        }
        let json = std::fs::read_to_string(&path)?;
        let auth: PersistedAuth =
            serde_json::from_str(&json).map_err(|e| SessionError::Other(e.to_string()))?;
        let server_url = auth.server_url.clone();
        let mut config = ClientConfig::new(&server_url);
        config.device_id = auth.device_id;
        let mut client = VaultClient::new(config)?;
        client.set_tokens(String::new(), Some(auth.refresh_token));
        // refresh to get access token
        if client.refresh().await.is_err() {
            // Stale refresh token — drop it so we do not loop on a dead session.
            let _ = std::fs::remove_file(path);
            return Ok(None);
        }
        // Re-persist in case the server rotated the refresh token.
        let session = Self {
            client,
            email: Some(auth.email),
            user_id: None,
            protected_key: auth.protected_key,
            private_key_enc: auth.private_key,
            user_key: None,
            master_key: None,
            index: VaultIndex::default(),
            status: SessionStatus::Locked,
            last_activity: Instant::now(),
            auto_lock: Duration::from_secs(15 * 60),
            clipboard: ClipboardService::new(30),
            data_dir,
        };
        let _ = session.persist_auth();
        Ok(Some((session, server_url)))
    }

    pub fn logout(&mut self) {
        self.lock();
        self.client.clear_tokens();
        self.email = None;
        self.protected_key = None;
        self.private_key_enc = None;
        self.status = SessionStatus::LoggedOut;
        Self::clear_persisted_auth();
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
