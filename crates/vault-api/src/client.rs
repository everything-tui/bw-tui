use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE, USER_AGENT};
use reqwest::Client;
use serde::Serialize;
use uuid::Uuid;

use crate::error::{ApiError, Result};
use crate::models::*;

const CLIENT_NAME: &str = "cli";
const CLIENT_VERSION: &str = "2024.12.0";
const DEVICE_TYPE: &str = "7";

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub base_url: String,
    pub device_id: String,
    pub device_name: String,
}

impl ClientConfig {
    pub fn new(base_url: impl Into<String>) -> Result<Self> {
        let raw = base_url.into();
        let base_url = normalize_server_url(&raw)?;
        Ok(Self {
            base_url,
            device_id: Uuid::new_v4().to_string(),
            device_name: "bitwarden-tui".to_string(),
        })
    }

    /// Build config, falling back to a trimmed URL only for tests that need a
    /// placeholder before a real URL is known.
    pub fn new_unchecked(base_url: impl Into<String>) -> Self {
        let raw = base_url.into();
        let base_url = normalize_server_url(&raw)
            .unwrap_or_else(|_| raw.trim().trim_end_matches('/').to_string());
        Self {
            base_url,
            device_id: Uuid::new_v4().to_string(),
            device_name: "bitwarden-tui".to_string(),
        }
    }
}

/// Trim, ensure `http(s)://` scheme, drop trailing slash. Rejects empty / non-http URLs.
pub fn normalize_server_url(raw: &str) -> Result<String> {
    let trimmed = raw.trim().trim_end_matches('/').to_string();
    if trimmed.is_empty() {
        return Err(ApiError::Url("server URL is required".into()));
    }
    let with_scheme = if trimmed.contains("://") {
        trimmed
    } else {
        format!("https://{trimmed}")
    };
    let parsed = url::Url::parse(&with_scheme)
        .map_err(|e| ApiError::Url(format!("invalid server URL: {e}")))?;
    match parsed.scheme() {
        "http" | "https" => {}
        other => {
            return Err(ApiError::Url(format!(
                "server URL must be http or https (got {other})"
            )));
        }
    }
    if parsed.host_str().is_none() {
        return Err(ApiError::Url("server URL is missing a host".into()));
    }
    // Keep path if the user intentionally set one (unusual); drop only trailing slash.
    let mut out = with_scheme;
    while out.ends_with('/') {
        out.pop();
    }
    Ok(out)
}

/// True for `http://` URLs whose host is not loopback / localhost.
pub fn is_insecure_http(url: &str) -> bool {
    let trimmed = url.trim();
    let with_scheme = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    };
    let Ok(parsed) = url::Url::parse(&with_scheme) else {
        return false;
    };
    if parsed.scheme() != "http" {
        return false;
    }
    match parsed.host() {
        None => true,
        Some(url::Host::Domain(host)) => {
            let h = host.to_ascii_lowercase();
            h != "localhost" && h != "localhost.localdomain"
        }
        Some(url::Host::Ipv4(ip)) => !ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => !ip.is_loopback(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_bare_host_to_https() {
        assert_eq!(
            normalize_server_url("vault.example.com").unwrap(),
            "https://vault.example.com"
        );
    }

    #[test]
    fn keeps_http_and_strips_slash() {
        assert_eq!(
            normalize_server_url("http://127.0.0.1:8080/").unwrap(),
            "http://127.0.0.1:8080"
        );
    }

    #[test]
    fn insecure_http_flags_remote_only() {
        assert!(is_insecure_http("http://vault.example.com"));
        assert!(!is_insecure_http("https://vault.example.com"));
        assert!(!is_insecure_http("http://127.0.0.1:8080"));
        assert!(!is_insecure_http("http://localhost:8080"));
    }
}

#[derive(Debug, Clone)]
pub struct VaultClient {
    http: Client,
    config: ClientConfig,
    access_token: Option<String>,
    refresh_token: Option<String>,
}

impl VaultClient {
    pub fn new(config: ClientConfig) -> Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static("bitwarden-tui/0.1.0"));
        headers.insert(
            "Bitwarden-Client-Name",
            HeaderValue::from_static(CLIENT_NAME),
        );
        headers.insert(
            "Bitwarden-Client-Version",
            HeaderValue::from_static(CLIENT_VERSION),
        );
        headers.insert("Device-Type", HeaderValue::from_static(DEVICE_TYPE));

        let http = Client::builder()
            .default_headers(headers)
            .timeout(std::time::Duration::from_secs(60))
            .build()?;

        Ok(Self {
            http,
            config,
            access_token: None,
            refresh_token: None,
        })
    }

    pub fn base_url(&self) -> &str {
        &self.config.base_url
    }

    pub fn device_id(&self) -> &str {
        &self.config.device_id
    }

    pub fn set_device_id(&mut self, id: String) {
        self.config.device_id = id;
    }

    pub fn access_token(&self) -> Option<&str> {
        self.access_token.as_deref()
    }

    pub fn refresh_token(&self) -> Option<&str> {
        self.refresh_token.as_deref()
    }

    pub fn set_tokens(&mut self, access: String, refresh: Option<String>) {
        self.access_token = Some(access);
        self.refresh_token = refresh;
    }

    pub fn clear_tokens(&mut self) {
        self.access_token = None;
        self.refresh_token = None;
    }

    fn api(&self, path: &str) -> String {
        format!("{}/api{}", self.config.base_url, path)
    }

    fn identity(&self, path: &str) -> String {
        format!("{}/identity{}", self.config.base_url, path)
    }

    fn bearer(&self) -> Result<HeaderValue> {
        let token = self
            .access_token
            .as_ref()
            .ok_or(ApiError::NotAuthenticated)?;
        HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|e| ApiError::Other(e.to_string()))
    }

    pub async fn get_config(&self) -> Result<ServerConfig> {
        let resp = self.http.get(self.api("/config")).send().await?;
        self.json(resp).await
    }

    pub async fn prelogin(&self, email: &str) -> Result<PreloginResponse> {
        #[derive(Serialize)]
        struct Body<'a> {
            email: &'a str,
        }
        let resp = self
            .http
            .post(self.identity("/accounts/prelogin"))
            .json(&Body { email })
            .send()
            .await?;
        self.json(resp).await
    }

    pub async fn login(
        &mut self,
        email: &str,
        password_hash: &str,
        two_factor: Option<(u8, &str)>,
    ) -> Result<TokenResponse> {
        let mut form = vec![
            ("grant_type", "password".to_string()),
            ("username", email.to_string()),
            ("password", password_hash.to_string()),
            ("scope", "api offline_access".to_string()),
            ("client_id", "cli".to_string()),
            ("deviceType", DEVICE_TYPE.to_string()),
            ("deviceIdentifier", self.config.device_id.clone()),
            ("deviceName", self.config.device_name.clone()),
        ];
        if let Some((provider, token)) = two_factor {
            form.push(("twoFactorProvider", provider.to_string()));
            form.push(("twoFactorToken", token.to_string()));
            form.push(("twoFactorRemember", "0".to_string()));
        }

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
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                if v.get("TwoFactorProviders2").is_some() || v.get("TwoFactorProviders").is_some() {
                    return Err(ApiError::TwoFactorRequired {
                        providers: extract_2fa_providers(&v),
                        raw: v,
                    });
                }
                let msg = v
                    .get("ErrorModel")
                    .and_then(|e| e.get("Message"))
                    .and_then(|m| m.as_str())
                    .or_else(|| v.get("error_description").and_then(|m| m.as_str()))
                    .or_else(|| v.get("error").and_then(|m| m.as_str()))
                    .unwrap_or(&body)
                    .to_string();
                return Err(ApiError::Api {
                    status: status.as_u16(),
                    message: msg,
                });
            }
            return Err(ApiError::Api {
                status: status.as_u16(),
                message: body,
            });
        }

        let token: TokenResponse = serde_json::from_str(&body)?;
        self.access_token = Some(token.access_token.clone());
        if let Some(ref r) = token.refresh_token {
            self.refresh_token = Some(r.clone());
        }
        Ok(token)
    }

    pub async fn refresh(&mut self) -> Result<TokenResponse> {
        let refresh = self
            .refresh_token
            .clone()
            .ok_or(ApiError::NotAuthenticated)?;
        let form = [
            ("grant_type", "refresh_token".to_string()),
            ("refresh_token", refresh),
            ("client_id", "cli".to_string()),
            ("deviceType", DEVICE_TYPE.to_string()),
            ("deviceIdentifier", self.config.device_id.clone()),
            ("deviceName", self.config.device_name.clone()),
        ];
        let resp = self
            .http
            .post(self.identity("/connect/token"))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .form(&form)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            if matches!(status.as_u16(), 400 | 401) {
                self.clear_tokens();
            }
            return Err(ApiError::Api {
                status: status.as_u16(),
                message: body,
            });
        }
        let token: TokenResponse = self.json(resp).await?;
        self.access_token = Some(token.access_token.clone());
        // Always assign refresh (including None) so rotation clears stale tokens.
        if token.refresh_token.is_some() {
            self.refresh_token = token.refresh_token.clone();
        }
        Ok(token)
    }

    /// API-key login (`client_credentials`) for headless / automation use.
    pub async fn login_api_key(
        &mut self,
        client_id: &str,
        client_secret: &str,
    ) -> Result<TokenResponse> {
        let form = [
            ("grant_type", "client_credentials"),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("scope", "api"),
            ("deviceType", DEVICE_TYPE),
            ("deviceIdentifier", self.config.device_id.as_str()),
            ("deviceName", self.config.device_name.as_str()),
        ];
        let resp = self
            .http
            .post(self.identity("/connect/token"))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .form(&form)
            .send()
            .await?;
        let token: TokenResponse = self.json(resp).await?;
        self.set_tokens(token.access_token.clone(), token.refresh_token.clone());
        Ok(token)
    }

    /// Ask the server to email a 2FA code (provider 1).
    pub async fn send_email_login_2fa(
        &self,
        email: &str,
        master_password_hash: &str,
    ) -> Result<()> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            email: &'a str,
            master_password_hash: &'a str,
        }
        let resp = self
            .http
            .post(self.api("/two-factor/send-email-login"))
            .json(&Body {
                email,
                master_password_hash,
            })
            .send()
            .await?;
        self.empty(resp).await
    }

    /// Step 1 of modern registration: obtain email verification JWT (returned
    /// directly when SMTP verification is not required).
    pub async fn register_send_verification_email(
        &self,
        email: &str,
        name: Option<&str>,
    ) -> Result<String> {
        let req = RegisterSendEmailRequest {
            email: email.to_string(),
            name: name.map(str::to_string),
        };
        let resp = self
            .http
            .post(self.identity("/accounts/register/send-verification-email"))
            .header(reqwest::header::ACCEPT, "application/json")
            .json(&req)
            .send()
            .await?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            if body.to_lowercase().contains("already") {
                return Err(ApiError::Other("user already exists".into()));
            }
            return Err(ApiError::Api {
                status: status.as_u16(),
                message: body,
            });
        }
        // Body may be a JSON string ("eyJ...") or plain JWT text.
        if let Ok(token) = serde_json::from_str::<String>(&body) {
            return Ok(token);
        }
        let trimmed = body.trim().trim_matches('"').to_string();
        if trimmed.is_empty() {
            return Err(ApiError::Other(
                "empty verification token (is SMTP verification required?)".into(),
            ));
        }
        Ok(trimmed)
    }

    /// Step 2: finish registration with crypto material + verification token.
    pub async fn register_finish(&self, req: &RegisterRequest) -> Result<()> {
        let resp = self
            .http
            .post(self.identity("/accounts/register/finish"))
            .json(req)
            .send()
            .await?;
        let status = resp.status();
        if status.is_success() || status.as_u16() == 204 {
            return Ok(());
        }
        let body = resp.text().await.unwrap_or_default();
        let lower = body.to_lowercase();
        if lower.contains("already") || lower.contains("taken") {
            return Err(ApiError::UserExists);
        }
        Err(ApiError::Api {
            status: status.as_u16(),
            message: body,
        })
    }

    /// Convenience: send-verification + finish.
    pub async fn register(&self, req: &RegisterRequest) -> Result<()> {
        let mut req = req.clone();
        if req.email_verification_token.is_none() {
            let token = self
                .register_send_verification_email(&req.email, req.name.as_deref())
                .await?;
            req.email_verification_token = Some(token);
        }
        self.register_finish(&req).await
    }

    pub async fn sync(&self) -> Result<SyncResponse> {
        let resp = self
            .http
            .get(self.api("/sync"))
            .header(AUTHORIZATION, self.bearer()?)
            .query(&[("excludeDomains", "true")])
            .send()
            .await?;
        self.json(resp).await
    }

    pub async fn create_cipher(&self, cipher: &CipherRequest) -> Result<Cipher> {
        // POST /ciphers expects bare CipherData (not ShareCipherData wrap).
        let resp = self
            .http
            .post(self.api("/ciphers"))
            .header(AUTHORIZATION, self.bearer()?)
            .json(cipher)
            .send()
            .await?;
        self.json(resp).await
    }

    pub async fn update_cipher(&self, id: &str, cipher: &CipherRequest) -> Result<Cipher> {
        let resp = self
            .http
            .put(self.api(&format!("/ciphers/{id}")))
            .header(AUTHORIZATION, self.bearer()?)
            .json(cipher)
            .send()
            .await?;
        self.json(resp).await
    }

    /// Update only folder/favorite without rewriting cipher payload.
    pub async fn update_cipher_partial(
        &self,
        id: &str,
        partial: &CipherPartialRequest,
    ) -> Result<()> {
        let resp = self
            .http
            .put(self.api(&format!("/ciphers/{id}/partial")))
            .header(AUTHORIZATION, self.bearer()?)
            .json(partial)
            .send()
            .await?;
        self.empty(resp).await
    }

    pub async fn delete_cipher(&self, id: &str) -> Result<()> {
        let resp = self
            .http
            .delete(self.api(&format!("/ciphers/{id}")))
            .header(AUTHORIZATION, self.bearer()?)
            .send()
            .await?;
        self.empty(resp).await
    }

    pub async fn soft_delete_cipher(&self, id: &str) -> Result<()> {
        let resp = self
            .http
            .put(self.api(&format!("/ciphers/{id}/delete")))
            .header(AUTHORIZATION, self.bearer()?)
            .send()
            .await?;
        if matches!(resp.status().as_u16(), 404 | 405) {
            let resp = self
                .http
                .post(self.api(&format!("/ciphers/{id}/delete")))
                .header(AUTHORIZATION, self.bearer()?)
                .send()
                .await?;
            return self.empty(resp).await;
        }
        self.empty(resp).await
    }

    pub async fn restore_cipher(&self, id: &str) -> Result<()> {
        let resp = self
            .http
            .put(self.api(&format!("/ciphers/{id}/restore")))
            .header(AUTHORIZATION, self.bearer()?)
            .send()
            .await?;
        if matches!(resp.status().as_u16(), 404 | 405) {
            let resp = self
                .http
                .post(self.api(&format!("/ciphers/{id}/restore")))
                .header(AUTHORIZATION, self.bearer()?)
                .send()
                .await?;
            return self.empty(resp).await;
        }
        self.empty(resp).await
    }

    pub async fn create_folder(&self, name: &str) -> Result<Folder> {
        let req = FolderRequest {
            name: name.to_string(),
        };
        let resp = self
            .http
            .post(self.api("/folders"))
            .header(AUTHORIZATION, self.bearer()?)
            .json(&req)
            .send()
            .await?;
        self.json(resp).await
    }

    pub async fn update_folder(&self, id: &str, name: &str) -> Result<Folder> {
        let req = FolderRequest {
            name: name.to_string(),
        };
        let resp = self
            .http
            .put(self.api(&format!("/folders/{id}")))
            .header(AUTHORIZATION, self.bearer()?)
            .json(&req)
            .send()
            .await?;
        self.json(resp).await
    }

    pub async fn delete_folder(&self, id: &str) -> Result<()> {
        let resp = self
            .http
            .delete(self.api(&format!("/folders/{id}")))
            .header(AUTHORIZATION, self.bearer()?)
            .send()
            .await?;
        self.empty(resp).await
    }

    async fn json<T: serde::de::DeserializeOwned>(&self, resp: reqwest::Response) -> Result<T> {
        let status = resp.status();
        let body = resp.text().await?;
        if !status.is_success() {
            return Err(ApiError::Api {
                status: status.as_u16(),
                message: body,
            });
        }
        Ok(serde_json::from_str(&body)?)
    }

    async fn empty(&self, resp: reqwest::Response) -> Result<()> {
        let status = resp.status();
        if status.is_success() || status.as_u16() == 204 {
            return Ok(());
        }
        let body = resp.text().await.unwrap_or_default();
        Err(ApiError::Api {
            status: status.as_u16(),
            message: body,
        })
    }
}

fn extract_2fa_providers(v: &serde_json::Value) -> Vec<u8> {
    if let Some(arr) = v.get("TwoFactorProviders").and_then(|a| a.as_array()) {
        return arr
            .iter()
            .filter_map(|x| x.as_u64().map(|n| n as u8))
            .collect();
    }
    if let Some(obj) = v.get("TwoFactorProviders2").and_then(|o| o.as_object()) {
        return obj.keys().filter_map(|k| k.parse::<u8>().ok()).collect();
    }
    Vec::new()
}
