//! Forwarded email alias services (SimpleLogin, addy.io) for the username generator.
//!
//! API tokens live in the OS keychain (never on disk), keyed per profile + service.

use keyring::Entry;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const SERVICE_NAME: &str = "com.bitwarden-tui.bitwarden-tui.forwarders";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ForwarderService {
    SimpleLogin,
    AddyIo,
}

impl ForwarderService {
    pub const ALL: [ForwarderService; 2] =
        [ForwarderService::SimpleLogin, ForwarderService::AddyIo];

    pub fn id(self) -> &'static str {
        match self {
            Self::SimpleLogin => "simplelogin",
            Self::AddyIo => "addyio",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::SimpleLogin => "SimpleLogin",
            Self::AddyIo => "addy.io",
        }
    }

    pub fn default_base_url(self) -> &'static str {
        match self {
            Self::SimpleLogin => "https://app.simplelogin.io",
            Self::AddyIo => "https://app.addy.io",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "simplelogin" | "sl" => Some(Self::SimpleLogin),
            "addyio" | "addy.io" | "addy" | "anonaddy" => Some(Self::AddyIo),
            _ => None,
        }
    }
}

/// Stored (keychain) credentials for one forwarder.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForwarderCredentials {
    pub token: String,
    /// Self-hosted base URL; defaults to the public service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    /// addy.io alias domain (default `anonaddy.me`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
}

impl std::fmt::Debug for ForwarderCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForwarderCredentials")
            .field("token", &"<redacted>")
            .field("base_url", &self.base_url)
            .field("domain", &self.domain)
            .finish()
    }
}

fn entry(profile_id: &str, service: ForwarderService) -> Result<Entry, String> {
    Entry::new(SERVICE_NAME, &format!("{profile_id}_{}", service.id())).map_err(|e| e.to_string())
}

pub fn store_forwarder_credentials(
    profile_id: &str,
    service: ForwarderService,
    creds: &ForwarderCredentials,
) -> Result<(), String> {
    if creds.token.trim().is_empty() {
        return Err("API token is empty".into());
    }
    let json = serde_json::to_string(creds).map_err(|e| e.to_string())?;
    entry(profile_id, service)?
        .set_password(&json)
        .map_err(|e| e.to_string())
}

pub fn load_forwarder_credentials(
    profile_id: &str,
    service: ForwarderService,
) -> Result<Option<ForwarderCredentials>, String> {
    match entry(profile_id, service)?.get_password() {
        Ok(raw) => serde_json::from_str(&raw)
            .map(Some)
            .map_err(|e| e.to_string()),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

pub fn delete_forwarder_credentials(
    profile_id: &str,
    service: ForwarderService,
) -> Result<(), String> {
    match entry(profile_id, service)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

fn base(service: ForwarderService, creds: &ForwarderCredentials) -> String {
    creds
        .base_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(service.default_base_url())
        .trim_end_matches('/')
        .to_string()
}

pub fn parse_simplelogin_alias(v: &Value) -> Option<String> {
    v.get("alias")
        .and_then(|a| a.as_str())
        .filter(|a| !a.is_empty())
        .map(str::to_string)
}

pub fn parse_addy_alias(v: &Value) -> Option<String> {
    v.pointer("/data/email")
        .and_then(|a| a.as_str())
        .filter(|a| !a.is_empty())
        .map(str::to_string)
}

/// Create a new random alias. `note` is stored as the alias description.
pub async fn generate_forwarded_alias(
    service: ForwarderService,
    creds: &ForwarderCredentials,
    note: &str,
) -> Result<String, String> {
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .user_agent("bitwarden-tui")
        .build()
        .map_err(|e| e.to_string())?;
    let base = base(service, creds);
    let req = match service {
        ForwarderService::SimpleLogin => http
            .post(format!("{base}/api/alias/random/new"))
            .header("Authentication", creds.token.trim())
            .json(&json!({ "note": note })),
        ForwarderService::AddyIo => http
            .post(format!("{base}/api/v1/aliases"))
            .bearer_auth(creds.token.trim())
            .header("X-Requested-With", "XMLHttpRequest")
            .header("Accept", "application/json")
            .json(&json!({
                "domain": creds.domain.as_deref().filter(|d| !d.is_empty()).unwrap_or("anonaddy.me"),
                "description": note,
            })),
    };
    let resp = req.send().await.map_err(|e| e.to_string())?;
    let status = resp.status();
    let body = resp.text().await.map_err(|e| e.to_string())?;
    if !status.is_success() {
        let snippet: String = body.chars().take(160).collect();
        return Err(format!("{} API {status}: {snippet}", service.label()));
    }
    let v: Value = serde_json::from_str(&body).map_err(|e| e.to_string())?;
    match service {
        ForwarderService::SimpleLogin => parse_simplelogin_alias(&v),
        ForwarderService::AddyIo => parse_addy_alias(&v),
    }
    .ok_or_else(|| format!("{}: unexpected response", service.label()))
}

/// Synchronous wrapper for UI code paths that cannot `.await` (multi-thread runtime only).
pub fn generate_forwarded_alias_blocking(
    service: ForwarderService,
    creds: &ForwarderCredentials,
    note: &str,
) -> Result<String, String> {
    use tokio::runtime::{Handle, RuntimeFlavor};
    let handle = Handle::try_current().map_err(|_| "no async runtime".to_string())?;
    if handle.runtime_flavor() != RuntimeFlavor::MultiThread {
        return Err("alias generation needs the multi-thread runtime".into());
    }
    tokio::task::block_in_place(|| handle.block_on(generate_forwarded_alias(service, creds, note)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_service_names() {
        assert_eq!(
            ForwarderService::parse("SimpleLogin"),
            Some(ForwarderService::SimpleLogin)
        );
        assert_eq!(
            ForwarderService::parse("addy.io"),
            Some(ForwarderService::AddyIo)
        );
        assert_eq!(ForwarderService::parse("nope"), None);
    }

    #[test]
    fn parses_alias_responses() {
        assert_eq!(
            parse_simplelogin_alias(&json!({"alias": "x@simplelogin.com"})).as_deref(),
            Some("x@simplelogin.com")
        );
        assert_eq!(
            parse_addy_alias(&json!({"data": {"email": "y@anonaddy.me"}})).as_deref(),
            Some("y@anonaddy.me")
        );
        assert!(parse_addy_alias(&json!({})).is_none());
    }

    #[test]
    fn base_url_defaults_and_trims() {
        let mut c = ForwarderCredentials {
            token: "t".into(),
            base_url: None,
            domain: None,
        };
        assert_eq!(base(ForwarderService::AddyIo, &c), "https://app.addy.io");
        c.base_url = Some("https://sl.example.com/".into());
        assert_eq!(
            base(ForwarderService::SimpleLogin, &c),
            "https://sl.example.com"
        );
    }

    #[test]
    fn debug_redacts_token() {
        let c = ForwarderCredentials {
            token: "secret".into(),
            base_url: None,
            domain: None,
        };
        assert!(!format!("{c:?}").contains("secret"));
    }
}
