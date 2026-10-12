//! Advanced authentication and account-management flows on [`Session`]:
//! 2FA provider details (Duo / WebAuthn), new-device OTP, login with device
//! (auth requests), SSO (PKCE), KDF change, session deauthorization and
//! authenticator-app 2FA setup.
//!
//! Child module of `session` so it can reuse private session state.

use base64::Engine;
use rand::Rng;
use sha2::{Digest, Sha256};
use vault_api::{
    percent_encode, ApiError, AuthRequestApproval, ChangeKdfRequest, CreateAuthRequest,
    EnableAuthenticatorRequest, TokenResponse, AUTH_REQUEST_AUTHENTICATE_AND_UNLOCK,
};
use vault_crypto::{public_key_der_from_b64, rsa_encrypt_user_key, unwrap_org_key};
use zeroize::Zeroizing;

use super::*;

/// State owned by the advanced auth flows (kept out of the main `Session` field list).
#[derive(Default)]
pub(super) struct AuthExtSession {
    /// Raw `TwoFactorProviders2` payload from the last 2FA challenge.
    pub two_factor_raw: Option<serde_json::Value>,
    device_login: Option<PendingDeviceLogin>,
    sso: Option<PendingSso>,
}

struct PendingDeviceLogin {
    id: String,
    access_code: String,
    private_der: Zeroizing<Vec<u8>>,
    email: String,
}

struct PendingSso {
    verifier: Zeroizing<String>,
    state: String,
    redirect_uri: String,
    email: String,
}

/// Started "login with device" request (show the fingerprint to the user).
#[derive(Debug, Clone)]
pub struct DeviceLoginStart {
    pub request_id: String,
    /// Compare with the phrase shown on the approving device.
    pub fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceLoginStatus {
    /// Still waiting for the other device.
    Waiting,
    /// The other device denied the request.
    Denied,
    /// Approved; session is now unlocked and synced.
    Approved,
}

/// Another device asking this (unlocked) account to approve its login.
#[derive(Debug, Clone)]
pub struct IncomingAuthRequest {
    pub id: String,
    pub public_key: String,
    pub device_type: String,
    pub ip_address: String,
    pub created: String,
    pub fingerprint: String,
}

/// SSO browser flow start data.
#[derive(Debug, Clone)]
pub struct SsoStart {
    pub url: String,
    pub state: String,
}

/// Authenticator-app 2FA setup info.
#[derive(Debug, Clone)]
pub struct AuthenticatorSetupInfo {
    pub enabled: bool,
    pub secret: String,
    /// `otpauth://` URI suitable for QR encoding.
    pub otpauth_uri: String,
    verification_token: Option<String>,
}

impl SessionError {
    /// True when the server wants the emailed new-device verification code.
    pub fn is_new_device_verification_required(&self) -> bool {
        matches!(
            self,
            SessionError::Api(ApiError::NewDeviceVerificationRequired)
        )
    }
}

/// PKCE verifier / S256 challenge pair.
pub fn pkce_pair() -> (String, String) {
    let mut bytes = [0u8; 48];
    rand::thread_rng().fill(&mut bytes[..]);
    let enc = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let verifier = enc.encode(bytes);
    let challenge = enc.encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

fn random_token(len: usize) -> String {
    const CHARS: &[u8] = b"abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
        .collect()
}

fn protected_key_from_token(token: &TokenResponse) -> Option<String> {
    token.key.clone().or_else(|| {
        token.user_decryption_options.as_ref().and_then(|v| {
            v.pointer("/MasterPasswordUnlock/MasterKeyEncryptedUserKey")
                .and_then(|x| x.as_str())
                .map(str::to_string)
        })
    })
}

fn kdf_type_and_params(kdf: &KdfParams) -> (u8, u32, Option<u32>, Option<u32>) {
    match kdf {
        KdfParams::Pbkdf2 { iterations } => (0, *iterations, None, None),
        KdfParams::Argon2id {
            iterations,
            memory_mib,
            parallelism,
        } => (1, *iterations, Some(*memory_mib), Some(*parallelism)),
    }
}

impl Session {
    // ----- 2FA details -------------------------------------------------------

    /// Raw provider payload from the last two-factor challenge, if any.
    pub fn two_factor_details(&self) -> Option<&serde_json::Value> {
        self.auth_ext.two_factor_raw.as_ref()
    }

    /// Duo authorization URL for provider 2 (or organization Duo, 6).
    pub fn duo_auth_url(&self, provider: u8) -> Option<String> {
        self.auth_ext
            .two_factor_raw
            .as_ref()
            .and_then(|raw| vault_api::duo_auth_url(raw, provider))
    }

    /// Masked email address the server sent the 2FA code to.
    pub fn email_two_factor_hint(&self) -> Option<String> {
        self.auth_ext
            .two_factor_raw
            .as_ref()
            .and_then(vault_api::email_two_factor_hint)
    }

    /// WebAuthn (provider 7) challenge JSON.
    pub fn webauthn_challenge(&self) -> Option<serde_json::Value> {
        self.auth_ext
            .two_factor_raw
            .as_ref()
            .and_then(vault_api::webauthn_challenge)
    }

    /// Provide the emailed new-device verification code for the next password login.
    pub fn set_new_device_otp(&mut self, otp: Option<&str>) {
        self.client
            .set_new_device_otp(otp.map(|o| o.trim().to_string()));
    }

    // ----- Login with device (requester side) --------------------------------

    pub fn device_login_pending(&self) -> bool {
        self.auth_ext.device_login.is_some()
    }

    pub fn cancel_device_login(&mut self) {
        self.auth_ext.device_login = None;
    }

    /// Create an auth request that another logged-in device can approve.
    pub async fn start_device_login(&mut self, email: &str) -> Result<DeviceLoginStart> {
        let email = email.trim();
        if email.is_empty() {
            return Err(SessionError::Other("email is required".into()));
        }
        let pair = generate_rsa_keypair()?;
        let access_code = random_token(25);
        let req = CreateAuthRequest {
            email: email.to_string(),
            device_identifier: self.client.device_id().to_string(),
            public_key: pair.public_key_b64.clone(),
            access_code: access_code.clone(),
            request_type: AUTH_REQUEST_AUTHENTICATE_AND_UNLOCK,
        };
        let resp = self.client.create_auth_request(&req).await?;
        let der = public_key_der_from_b64(&pair.public_key_b64)?;
        let fingerprint = fingerprint_phrase_from_public_der(&der);
        self.auth_ext.device_login = Some(PendingDeviceLogin {
            id: resp.id.clone(),
            access_code,
            private_der: Zeroizing::new(pair.private_key_der.clone()),
            email: email.to_string(),
        });
        Ok(DeviceLoginStart {
            request_id: resp.id,
            fingerprint,
        })
    }

    /// Poll the pending auth request; on approval completes login + sync.
    pub async fn poll_device_login(&mut self) -> Result<DeviceLoginStatus> {
        let (id, code, email) = {
            let p = self
                .auth_ext
                .device_login
                .as_ref()
                .ok_or_else(|| SessionError::Other("no device login in progress".into()))?;
            (p.id.clone(), p.access_code.clone(), p.email.clone())
        };
        let resp = self.client.get_auth_request_response(&id, &code).await?;
        match resp.request_approved {
            None => return Ok(DeviceLoginStatus::Waiting),
            Some(false) => {
                self.auth_ext.device_login = None;
                return Ok(DeviceLoginStatus::Denied);
            }
            Some(true) => {}
        }
        let enc_key = resp
            .key
            .filter(|k| !k.is_empty())
            .ok_or_else(|| SessionError::Other("approval did not include a key".into()))?;
        let user_key = {
            let p = self.auth_ext.device_login.as_ref().unwrap();
            unwrap_org_key(&enc_key, p.private_der.as_slice())?
        };
        let token = match self
            .client
            .login_with_auth_request(&email, &code, &id)
            .await
        {
            Ok(t) => t,
            Err(ApiError::TwoFactorRequired { providers, .. }) => {
                self.auth_ext.device_login = None;
                return Err(SessionError::TwoFactorRequired { providers });
            }
            Err(e) => return Err(e.into()),
        };
        self.auth_ext.device_login = None;
        self.email = Some(email.clone());
        self.protected_key = protected_key_from_token(&token);
        self.private_key_enc = token.private_key.clone();
        self.master_key = None;
        self.user_key = Some(user_key);
        self.status = SessionStatus::Unlocked;
        if let Ok(pre) = self.client.prelogin(&email).await {
            self.remember_kdf(pre.to_kdf_params());
        }
        self.persist_auth()?;
        self.touch();
        self.sync().await?;
        Ok(DeviceLoginStatus::Approved)
    }

    // ----- Login with device (approver side) ---------------------------------

    /// Pending login requests from other devices (requires an authenticated session).
    pub async fn list_incoming_auth_requests(&self) -> Result<Vec<IncomingAuthRequest>> {
        let list = self.client.list_pending_auth_requests().await?;
        let mut out = Vec::new();
        for r in list {
            if r.request_approved.is_some() || r.response_date.is_some() {
                continue;
            }
            let public_key = r.public_key.clone().unwrap_or_default();
            let fingerprint = public_key_der_from_b64(&public_key)
                .map(|d| fingerprint_phrase_from_public_der(&d))
                .unwrap_or_default();
            out.push(IncomingAuthRequest {
                id: r.id,
                public_key,
                device_type: r
                    .request_device_type
                    .unwrap_or_else(|| "unknown device".into()),
                ip_address: r.request_ip_address.unwrap_or_default(),
                created: r.creation_date.unwrap_or_default(),
                fingerprint,
            });
        }
        Ok(out)
    }

    /// Approve or deny another device's login request (vault must be unlocked).
    pub async fn answer_auth_request(&self, id: &str, approve: bool) -> Result<()> {
        let user_key = self.user_key.as_ref().ok_or(SessionError::Locked)?;
        let pending = self.client.list_pending_auth_requests().await?;
        let req = pending
            .into_iter()
            .find(|r| r.id == id)
            .ok_or(SessionError::NotFound)?;
        let public_key = req
            .public_key
            .filter(|k| !k.is_empty())
            .ok_or_else(|| SessionError::Other("request has no public key".into()))?;
        let key = rsa_encrypt_user_key(user_key, &public_key)?;
        let approval = AuthRequestApproval {
            device_identifier: self.client.device_id().to_string(),
            key,
            master_password_hash: None,
            request_approved: approve,
        };
        self.client.answer_auth_request(id, &approval).await?;
        Ok(())
    }

    // ----- SSO (PKCE) --------------------------------------------------------

    /// Build the browser URL for an SSO login and remember the PKCE verifier.
    ///
    /// `redirect_uri` is normally a `http://localhost:<port>` loopback address.
    pub fn begin_sso(&mut self, email: &str, redirect_uri: &str) -> Result<SsoStart> {
        let email = email.trim();
        if email.is_empty() {
            return Err(SessionError::Other("email is required for SSO".into()));
        }
        let (verifier, challenge) = pkce_pair();
        let state = random_token(32);
        let url = self
            .client
            .sso_authorize_url(email, redirect_uri, &state, &challenge);
        self.auth_ext.sso = Some(PendingSso {
            verifier: Zeroizing::new(verifier),
            state: state.clone(),
            redirect_uri: redirect_uri.to_string(),
            email: email.to_string(),
        });
        Ok(SsoStart { url, state })
    }

    /// Complete SSO with the callback `code`. On success the session is **locked**
    /// (master password still needed to decrypt the vault).
    pub async fn finish_sso(&mut self, code: &str, state: Option<&str>) -> Result<()> {
        let pending = self
            .auth_ext
            .sso
            .take()
            .ok_or_else(|| SessionError::Other("no SSO login in progress".into()))?;
        if let Some(s) = state {
            if !s.is_empty() && !constant_time_eq(s.as_bytes(), pending.state.as_bytes()) {
                return Err(SessionError::Other(
                    "SSO state mismatch — retry login".into(),
                ));
            }
        }
        let token = self
            .client
            .login_sso_code(code, pending.verifier.as_str(), &pending.redirect_uri)
            .await?;
        let protected = protected_key_from_token(&token).ok_or_else(|| {
            SessionError::Other(
                "SSO account has no master-password key (trusted-device encryption is not supported yet)"
                    .into(),
            )
        })?;
        self.email = Some(pending.email.clone());
        self.protected_key = Some(protected);
        self.private_key_enc = token.private_key.clone();
        self.master_key = None;
        self.user_key = None;
        self.status = SessionStatus::Locked;
        if let Ok(pre) = self.client.prelogin(&pending.email).await {
            self.remember_kdf(pre.to_kdf_params());
        }
        self.persist_auth()?;
        Ok(())
    }

    // ----- Account management ------------------------------------------------

    fn master_password_hash_for(&self, password: &str) -> Result<String> {
        let email = self.email.clone().ok_or(SessionError::NotLoggedIn)?;
        let kdf = self
            .kdf
            .clone()
            .ok_or_else(|| SessionError::Other("missing KDF parameters".into()))?;
        let master = derive_master_key(password, &email, &kdf)?;
        Ok(auth_hash(&master, password)?.as_str().to_string())
    }

    /// Change the account KDF (PBKDF2 iterations or Argon2id params). Locks the vault afterwards.
    pub async fn change_kdf(&mut self, password: &str, new_kdf: KdfParams) -> Result<()> {
        self.ensure_online()?;
        new_kdf.validate()?;
        let email = self.email.clone().ok_or(SessionError::NotLoggedIn)?;
        let old_kdf = self
            .kdf
            .clone()
            .ok_or_else(|| SessionError::Other("missing KDF parameters".into()))?;
        let user_key = self.user_key.as_ref().ok_or(SessionError::Locked)?;
        let old_master = derive_master_key(password, &email, &old_kdf)?;
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
        let new_master = derive_master_key(password, &email, &new_kdf)?;
        let old_hash = auth_hash(&old_master, password)?;
        let new_hash = auth_hash(&new_master, password)?;
        let new_protected = wrap_user_key(user_key, &new_master)?;
        let (kdf, kdf_iterations, kdf_memory, kdf_parallelism) = kdf_type_and_params(&new_kdf);
        let req = ChangeKdfRequest {
            kdf,
            kdf_iterations,
            kdf_memory,
            kdf_parallelism,
            master_password_hash: old_hash.as_str().to_string(),
            new_master_password_hash: new_hash.as_str().to_string(),
            key: new_protected.clone(),
        };
        self.client.change_kdf(&req).await?;
        self.kdf = Some(new_kdf);
        self.protected_key = Some(new_protected);
        if pin_configured(&self.data_dir) {
            clear_pin(&self.data_dir);
        }
        self.lock();
        self.persist_auth()?;
        Ok(())
    }

    /// Rotate the security stamp: every other device is logged out. This session is
    /// logged out too (its refresh token is invalidated by the server).
    pub async fn deauthorize_sessions(&mut self, password: &str) -> Result<()> {
        self.ensure_online()?;
        let hash = self.master_password_hash_for(password)?;
        self.client.rotate_security_stamp(&hash).await?;
        self.logout();
        Ok(())
    }

    /// Enabled two-factor providers (`(type, enabled)`).
    pub async fn list_two_factor_providers(&self) -> Result<Vec<(u8, bool)>> {
        Ok(self
            .client
            .list_two_factor_providers()
            .await?
            .into_iter()
            .map(|p| (p.r#type, p.enabled))
            .collect())
    }

    /// Fetch / generate the authenticator secret (needs master password).
    pub async fn authenticator_setup(&self, password: &str) -> Result<AuthenticatorSetupInfo> {
        let email = self.email.clone().ok_or(SessionError::NotLoggedIn)?;
        let hash = self.master_password_hash_for(password)?;
        let setup = self.client.get_authenticator_setup(&hash).await?;
        let otpauth_uri = format!(
            "otpauth://totp/Bitwarden:{}?secret={}&issuer=Bitwarden",
            percent_encode(&email),
            setup.key
        );
        Ok(AuthenticatorSetupInfo {
            enabled: setup.enabled,
            secret: setup.key,
            otpauth_uri,
            verification_token: setup.user_verification_token,
        })
    }

    /// Enable authenticator 2FA by proving a code from the new secret works.
    pub async fn enable_authenticator(
        &self,
        password: &str,
        setup: &AuthenticatorSetupInfo,
        code: &str,
    ) -> Result<()> {
        let hash = self.master_password_hash_for(password)?;
        self.client
            .enable_authenticator(&EnableAuthenticatorRequest {
                token: code.trim().to_string(),
                key: setup.secret.clone(),
                master_password_hash: hash,
                user_verification_token: setup.verification_token.clone(),
            })
            .await?;
        Ok(())
    }

    /// Disable a two-factor provider (e.g. `0` authenticator).
    pub async fn disable_two_factor(&self, password: &str, provider: u8) -> Result<()> {
        let hash = self.master_password_hash_for(password)?;
        self.client.disable_two_factor(&hash, provider).await?;
        Ok(())
    }

    /// Step 1 of an email change: the server emails a code to `new_email`.
    pub async fn request_email_change(&self, new_email: &str, password: &str) -> Result<()> {
        let hash = self.master_password_hash_for(password)?;
        self.client
            .request_email_change_token(new_email.trim(), &hash)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_challenge_matches_verifier() {
        let (v, c) = pkce_pair();
        let expect =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(v.as_bytes()));
        assert_eq!(c, expect);
        assert!(v.len() >= 43);
    }

    #[test]
    fn kdf_request_fields() {
        let (t, i, m, p) = kdf_type_and_params(&KdfParams::Argon2id {
            iterations: 3,
            memory_mib: 64,
            parallelism: 4,
        });
        assert_eq!((t, i, m, p), (1, 3, Some(64), Some(4)));
        let (t, _, m, _) = kdf_type_and_params(&KdfParams::Pbkdf2 {
            iterations: 600_000,
        });
        assert_eq!((t, m), (0, None));
    }

    #[test]
    fn random_token_is_alnum() {
        let t = random_token(25);
        assert_eq!(t.len(), 25);
        assert!(t.chars().all(|c| c.is_ascii_alphanumeric()));
    }
}
