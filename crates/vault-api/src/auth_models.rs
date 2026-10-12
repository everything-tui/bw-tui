//! Models and pure helpers for advanced authentication flows:
//! two-factor provider details, Duo, WebAuthn, new-device OTP, auth requests
//! (login with device), SSO (PKCE) and account-management requests.

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ---------------------------------------------------------------------------
// Two-factor provider constants / details
// ---------------------------------------------------------------------------

pub const TWO_FACTOR_AUTHENTICATOR: u8 = 0;
pub const TWO_FACTOR_EMAIL: u8 = 1;
pub const TWO_FACTOR_DUO: u8 = 2;
pub const TWO_FACTOR_YUBIKEY: u8 = 3;
pub const TWO_FACTOR_U2F: u8 = 4;
pub const TWO_FACTOR_REMEMBER: u8 = 5;
pub const TWO_FACTOR_ORG_DUO: u8 = 6;
pub const TWO_FACTOR_WEBAUTHN: u8 = 7;

/// Human readable name for a Bitwarden two-factor provider id.
pub fn two_factor_provider_name(provider: u8) -> &'static str {
    match provider {
        TWO_FACTOR_AUTHENTICATOR => "Authenticator app",
        TWO_FACTOR_EMAIL => "Email",
        TWO_FACTOR_DUO => "Duo",
        TWO_FACTOR_YUBIKEY => "YubiKey OTP",
        TWO_FACTOR_U2F => "FIDO U2F",
        TWO_FACTOR_REMEMBER => "Remembered device",
        TWO_FACTOR_ORG_DUO => "Duo (organization)",
        TWO_FACTOR_WEBAUTHN => "FIDO2 WebAuthn",
        _ => "Unknown provider",
    }
}

/// Providers the user can pick between (the "remember" pseudo-provider is never a choice).
pub fn selectable_two_factor_providers(providers: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = providers
        .iter()
        .copied()
        .filter(|p| *p != TWO_FACTOR_REMEMBER)
        .collect();
    out.sort_by_key(|p| provider_priority(*p));
    out.dedup();
    out
}

/// Lower sorts first. Mirrors the official clients (WebAuthn > Duo > YubiKey > authenticator > email).
fn provider_priority(p: u8) -> u8 {
    match p {
        TWO_FACTOR_AUTHENTICATOR => 0,
        TWO_FACTOR_WEBAUTHN => 1,
        TWO_FACTOR_DUO | TWO_FACTOR_ORG_DUO => 2,
        TWO_FACTOR_YUBIKEY => 3,
        TWO_FACTOR_EMAIL => 4,
        TWO_FACTOR_U2F => 5,
        _ => 9,
    }
}

/// Provider-specific payload from `TwoFactorProviders2` (empty object / null when none).
pub fn two_factor_provider_data(raw: &Value, provider: u8) -> Option<&Value> {
    raw.get("TwoFactorProviders2")
        .and_then(|o| o.get(provider.to_string()))
        .filter(|v| !v.is_null())
}

/// Duo (universal prompt) authorization URL, when the server supplied one.
pub fn duo_auth_url(raw: &Value, provider: u8) -> Option<String> {
    let data = two_factor_provider_data(raw, provider)?;
    for key in ["AuthUrl", "authUrl"] {
        if let Some(u) = data.get(key).and_then(|v| v.as_str()) {
            if !u.is_empty() {
                return Some(u.to_string());
            }
        }
    }
    None
}

/// Masked destination hint for email 2FA (`Email` field, e.g. `j***@example.com`).
pub fn email_two_factor_hint(raw: &Value) -> Option<String> {
    two_factor_provider_data(raw, TWO_FACTOR_EMAIL)
        .and_then(|d| d.get("Email"))
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

/// WebAuthn challenge (`PublicKeyCredentialRequestOptions` JSON) for provider 7.
pub fn webauthn_challenge(raw: &Value) -> Option<Value> {
    let data = two_factor_provider_data(raw, TWO_FACTOR_WEBAUTHN)?;
    data.get("Challenge")
        .or_else(|| data.get("challenge"))
        .cloned()
        .or_else(|| (!data.is_null()).then(|| data.clone()))
}

/// Extract `code` and `state` from a Duo / SSO callback URL or `code|state` pair.
///
/// Returns the Bitwarden token form `code|state` for Duo; for SSO use [`parse_callback_params`].
pub fn parse_duo_callback(input: &str) -> Option<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }
    if !trimmed.contains("://") && !trimmed.contains('?') {
        return trimmed.contains('|').then(|| trimmed.to_string());
    }
    let (code, state) = parse_callback_params(trimmed)?;
    Some(format!("{code}|{}", state.unwrap_or_default()))
}

/// Parse `code` (+ optional `state`) from a callback URL / query string.
pub fn parse_callback_params(input: &str) -> Option<(String, Option<String>)> {
    let query = input.split_once('?').map(|(_, q)| q).unwrap_or(input);
    let query = query.split('#').next().unwrap_or(query);
    let mut code = None;
    let mut state = None;
    for pair in query.split('&') {
        let Some((k, v)) = pair.split_once('=') else {
            continue;
        };
        let v = percent_decode(v);
        match k {
            "code" => code = Some(v),
            "state" => state = Some(v),
            _ => {}
        }
    }
    code.filter(|c| !c.is_empty()).map(|c| (c, state))
}

/// Minimal percent-decoding (also maps `+` to space).
pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let h = std::str::from_utf8(&bytes[i + 1..i + 3])
                    .ok()
                    .and_then(|h| u8::from_str_radix(h, 16).ok());
                if let Some(b) = h {
                    out.push(b);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Percent-encode a query component (RFC 3986 unreserved characters kept).
pub fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// True when a token-endpoint error body asks for new-device verification (emailed OTP).
pub fn is_new_device_verification_required(body: &str) -> bool {
    body.to_ascii_lowercase()
        .contains("new device verification required")
}

// ---------------------------------------------------------------------------
// Auth requests (login with device)
// ---------------------------------------------------------------------------

/// `AuthRequestType`: 0 = authenticate and unlock, 1 = unlock only, 2 = admin approval.
pub const AUTH_REQUEST_AUTHENTICATE_AND_UNLOCK: u8 = 0;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAuthRequest {
    pub email: String,
    pub device_identifier: String,
    pub public_key: String,
    pub access_code: String,
    #[serde(rename = "type")]
    pub request_type: u8,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthRequestResponse {
    pub id: String,
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(default)]
    pub request_device_identifier: Option<String>,
    #[serde(default)]
    pub request_device_type: Option<String>,
    #[serde(default)]
    pub request_ip_address: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub master_password_hash: Option<String>,
    #[serde(default)]
    pub creation_date: Option<String>,
    #[serde(default)]
    pub response_date: Option<String>,
    /// `None` = pending, `Some(false)` = denied, `Some(true)` = approved.
    #[serde(default)]
    pub request_approved: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthRequestList {
    #[serde(default, alias = "Data")]
    pub data: Vec<AuthRequestResponse>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthRequestApproval {
    pub device_identifier: String,
    pub key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub master_password_hash: Option<String>,
    pub request_approved: bool,
}

// ---------------------------------------------------------------------------
// Account management
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeKdfRequest {
    pub kdf: u8,
    pub kdf_iterations: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf_memory: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf_parallelism: Option<u32>,
    pub master_password_hash: String,
    pub new_master_password_hash: String,
    pub key: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TwoFactorProviderEntry {
    #[serde(default, alias = "Type")]
    pub r#type: u8,
    #[serde(default, alias = "Enabled")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TwoFactorProviderList {
    #[serde(default, alias = "Data")]
    pub data: Vec<TwoFactorProviderEntry>,
}

/// Response of `POST /two-factor/get-authenticator`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorSetup {
    #[serde(default, alias = "Enabled")]
    pub enabled: bool,
    #[serde(default, alias = "Key")]
    pub key: String,
    #[serde(default, alias = "UserVerificationToken")]
    pub user_verification_token: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnableAuthenticatorRequest {
    pub token: String,
    pub key: String,
    pub master_password_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_verification_token: Option<String>,
}

// ---------------------------------------------------------------------------
// SSO (PKCE)
// ---------------------------------------------------------------------------

/// Response of `GET /identity/sso/prevalidate`.
#[derive(Debug, Clone, Deserialize)]
pub struct SsoPrevalidate {
    #[serde(default, alias = "Token")]
    pub token: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn selectable_providers_drop_remember_and_sort() {
        let p = selectable_two_factor_providers(&[1, 5, 0, 7]);
        assert_eq!(p, vec![0, 7, 1]);
    }

    #[test]
    fn duo_url_from_providers2() {
        let raw = json!({"TwoFactorProviders2": {"2": {"Host": "api-x.duosecurity.com", "AuthUrl": "https://duo/auth?x=1"}}});
        assert_eq!(
            duo_auth_url(&raw, 2).as_deref(),
            Some("https://duo/auth?x=1")
        );
        assert!(duo_auth_url(&raw, 6).is_none());
    }

    #[test]
    fn duo_callback_parsing() {
        assert_eq!(
            parse_duo_callback("http://localhost:8123/?code=abc%2B1&state=xyz").as_deref(),
            Some("abc+1|xyz")
        );
        assert_eq!(parse_duo_callback("abc|xyz").as_deref(), Some("abc|xyz"));
        assert_eq!(parse_duo_callback("plain"), None);
    }

    #[test]
    fn new_device_detection() {
        assert!(is_new_device_verification_required(
            r#"{"ErrorModel":{"Message":"New device verification required."}}"#
        ));
        assert!(!is_new_device_verification_required(
            "invalid_username_or_password"
        ));
    }

    #[test]
    fn percent_roundtrip() {
        let s = "a b&c/d=é";
        assert_eq!(percent_decode(&percent_encode(s)), s);
    }
}
