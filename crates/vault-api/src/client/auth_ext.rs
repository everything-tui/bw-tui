//! Advanced authentication + account-management endpoints.
//!
//! Child module of `client` so it can reuse the private HTTP helpers.

use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde::Serialize;

use super::{extract_2fa_providers, VaultClient, DEVICE_TYPE};
use crate::auth_models::*;
use crate::error::{ApiError, Result};
use crate::models::TokenResponse;

/// Map a failed `/connect/token` response onto a typed [`ApiError`].
pub(super) fn token_error(status: u16, body: &str) -> ApiError {
    if is_new_device_verification_required(body) {
        return ApiError::NewDeviceVerificationRequired;
    }
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
        if v.get("TwoFactorProviders2").is_some() || v.get("TwoFactorProviders").is_some() {
            return ApiError::TwoFactorRequired {
                providers: extract_2fa_providers(&v),
                raw: v,
            };
        }
        let msg = v
            .get("ErrorModel")
            .and_then(|e| e.get("Message"))
            .and_then(|m| m.as_str())
            .or_else(|| v.get("error_description").and_then(|m| m.as_str()))
            .or_else(|| v.get("error").and_then(|m| m.as_str()))
            .unwrap_or(body)
            .to_string();
        return ApiError::Api {
            status,
            message: msg,
        };
    }
    ApiError::Api {
        status,
        message: body.to_string(),
    }
}

impl VaultClient {
    /// One-time passcode emailed by the server for "new device verification".
    /// Sent as `newDeviceOtp` on the next password login. Pass `None` to clear.
    pub fn set_new_device_otp(&mut self, otp: Option<String>) {
        self.new_device_otp = otp.filter(|o| !o.trim().is_empty());
    }

    fn base_token_form(&self, scope: &str) -> Vec<(&'static str, String)> {
        vec![
            ("scope", scope.to_string()),
            ("client_id", "cli".to_string()),
            ("deviceType", DEVICE_TYPE.to_string()),
            ("deviceIdentifier", self.config.device_id.clone()),
            ("deviceName", self.config.device_name.clone()),
        ]
    }

    async fn post_token_form(
        &mut self,
        form: Vec<(&'static str, String)>,
    ) -> Result<TokenResponse> {
        let resp = self
            .http
            .post(self.identity("/connect/token"))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .form(&form)
            .send()
            .await?;
        let status = resp.status();
        let body = resp.text().await?;
        if !status.is_success() {
            return Err(token_error(status.as_u16(), &body));
        }
        let token: TokenResponse = serde_json::from_str(&body)?;
        self.access_token = Some(token.access_token.clone());
        if let Some(ref r) = token.refresh_token {
            self.refresh_token = Some(r.clone());
        }
        Ok(token)
    }

    // ----- Login with device (auth requests) -------------------------------

    /// `POST /auth-requests` — ask another logged-in device to approve this login.
    pub async fn create_auth_request(
        &self,
        req: &CreateAuthRequest,
    ) -> Result<AuthRequestResponse> {
        let resp = self
            .http
            .post(self.api("/auth-requests"))
            .json(req)
            .send()
            .await?;
        self.json(resp).await
    }

    /// `GET /auth-requests/{id}/response?code=` — poll the requester side.
    pub async fn get_auth_request_response(
        &self,
        id: &str,
        access_code: &str,
    ) -> Result<AuthRequestResponse> {
        let url = format!(
            "{}?code={}",
            self.api(&format!("/auth-requests/{id}/response")),
            percent_encode(access_code)
        );
        let resp = self.http.get(url).send().await?;
        self.json(resp).await
    }

    /// `GET /auth-requests/pending` — requests from other devices awaiting this account's answer.
    pub async fn list_pending_auth_requests(&self) -> Result<Vec<AuthRequestResponse>> {
        let resp = self
            .http
            .get(self.api("/auth-requests/pending"))
            .header(AUTHORIZATION, self.bearer()?)
            .send()
            .await?;
        let list: AuthRequestList = self.json(resp).await?;
        Ok(list.data)
    }

    /// `PUT /auth-requests/{id}` — approve or deny an incoming request.
    pub async fn answer_auth_request(
        &self,
        id: &str,
        approval: &AuthRequestApproval,
    ) -> Result<AuthRequestResponse> {
        let resp = self
            .http
            .put(self.api(&format!("/auth-requests/{id}")))
            .header(AUTHORIZATION, self.bearer()?)
            .json(approval)
            .send()
            .await?;
        self.json(resp).await
    }

    /// Password-grant login where the "password" is the auth-request access code.
    pub async fn login_with_auth_request(
        &mut self,
        email: &str,
        access_code: &str,
        auth_request_id: &str,
    ) -> Result<TokenResponse> {
        let mut form = vec![
            ("grant_type", "password".to_string()),
            ("username", email.to_string()),
            ("password", access_code.to_string()),
            ("authRequest", auth_request_id.to_string()),
        ];
        form.extend(self.base_token_form("api offline_access"));
        self.post_token_form(form).await
    }

    // ----- SSO --------------------------------------------------------------

    /// `GET /identity/sso/prevalidate?domainHint=` — organization SSO identifier check.
    pub async fn sso_prevalidate(&self, org_identifier: &str) -> Result<SsoPrevalidate> {
        let url = format!(
            "{}?domainHint={}",
            self.identity("/sso/prevalidate"),
            percent_encode(org_identifier)
        );
        let resp = self.http.get(url).send().await?;
        self.json(resp).await
    }

    /// Web-vault SSO entry point for a CLI-style client (`/#/sso?...`).
    pub fn sso_authorize_url(
        &self,
        email: &str,
        redirect_uri: &str,
        state: &str,
        code_challenge: &str,
    ) -> String {
        format!(
            "{}/#/sso?clientId=cli&redirectUri={}&state={}&codeChallenge={}&email={}",
            self.config.base_url,
            percent_encode(redirect_uri),
            percent_encode(state),
            percent_encode(code_challenge),
            percent_encode(email),
        )
    }

    /// Exchange an SSO authorization code (PKCE) for tokens.
    pub async fn login_sso_code(
        &mut self,
        code: &str,
        code_verifier: &str,
        redirect_uri: &str,
    ) -> Result<TokenResponse> {
        let mut form = vec![
            ("grant_type", "authorization_code".to_string()),
            ("code", code.to_string()),
            ("code_verifier", code_verifier.to_string()),
            ("redirect_uri", redirect_uri.to_string()),
        ];
        form.extend(self.base_token_form("api offline_access"));
        self.post_token_form(form).await
    }

    // ----- Account management ----------------------------------------------

    async fn post_authed<B: Serialize>(&self, path: &str, body: &B) -> Result<reqwest::Response> {
        Ok(self
            .http
            .post(self.api(path))
            .header(AUTHORIZATION, self.bearer()?)
            .json(body)
            .send()
            .await?)
    }

    /// `POST /accounts/kdf` — change KDF settings (re-wrapped user key + new auth hash).
    pub async fn change_kdf(&self, req: &ChangeKdfRequest) -> Result<()> {
        let resp = self.post_authed("/accounts/kdf", req).await?;
        self.empty(resp).await
    }

    /// `POST /accounts/security-stamp` — invalidate every other session / refresh token.
    pub async fn rotate_security_stamp(&self, master_password_hash: &str) -> Result<()> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            master_password_hash: &'a str,
        }
        let resp = self
            .post_authed(
                "/accounts/security-stamp",
                &Body {
                    master_password_hash,
                },
            )
            .await?;
        self.empty(resp).await
    }

    /// `GET /two-factor` — enabled providers for the account.
    pub async fn list_two_factor_providers(&self) -> Result<Vec<TwoFactorProviderEntry>> {
        let resp = self
            .http
            .get(self.api("/two-factor"))
            .header(AUTHORIZATION, self.bearer()?)
            .send()
            .await?;
        let list: TwoFactorProviderList = self.json(resp).await?;
        Ok(list.data)
    }

    /// `POST /two-factor/get-authenticator` — fetch (or generate) the TOTP secret.
    pub async fn get_authenticator_setup(
        &self,
        master_password_hash: &str,
    ) -> Result<AuthenticatorSetup> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            master_password_hash: &'a str,
        }
        let resp = self
            .post_authed(
                "/two-factor/get-authenticator",
                &Body {
                    master_password_hash,
                },
            )
            .await?;
        self.json(resp).await
    }

    /// `PUT /two-factor/authenticator` — enable authenticator 2FA after verifying a code.
    pub async fn enable_authenticator(&self, req: &EnableAuthenticatorRequest) -> Result<()> {
        let resp = self
            .http
            .put(self.api("/two-factor/authenticator"))
            .header(AUTHORIZATION, self.bearer()?)
            .json(req)
            .send()
            .await?;
        self.empty(resp).await
    }

    /// `PUT /two-factor/disable` — disable one provider type.
    pub async fn disable_two_factor(&self, master_password_hash: &str, provider: u8) -> Result<()> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            master_password_hash: &'a str,
            r#type: u8,
        }
        let resp = self
            .http
            .put(self.api("/two-factor/disable"))
            .header(AUTHORIZATION, self.bearer()?)
            .json(&Body {
                master_password_hash,
                r#type: provider,
            })
            .send()
            .await?;
        self.empty(resp).await
    }

    /// `POST /accounts/email-token` — step 1 of an email change (server emails a code).
    pub async fn request_email_change_token(
        &self,
        new_email: &str,
        master_password_hash: &str,
    ) -> Result<()> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            new_email: &'a str,
            master_password_hash: &'a str,
        }
        let resp = self
            .post_authed(
                "/accounts/email-token",
                &Body {
                    new_email,
                    master_password_hash,
                },
            )
            .await?;
        self.empty(resp).await
    }

    /// `POST /accounts/delete` — permanently delete the account. **Irreversible.**
    ///
    /// Not wired to any UI action; kept so tooling can opt in explicitly.
    pub async fn delete_account(&self, master_password_hash: &str) -> Result<()> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            master_password_hash: &'a str,
        }
        let resp = self
            .post_authed(
                "/accounts/delete",
                &Body {
                    master_password_hash,
                },
            )
            .await?;
        self.empty(resp).await
    }
}
