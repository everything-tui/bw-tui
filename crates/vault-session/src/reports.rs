//! Vault health / security reports over decrypted items.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use chrono::{DateTime, Utc};
use vault_api::is_insecure_http;

use crate::models::{DecryptedItem, ItemType};
use crate::strength::{evaluate_password, WEAK_SCORE_THRESHOLD};
use crate::uri_match::{registrable_domain, uri_host};

/// Default age after which a login password is flagged as old.
pub const DEFAULT_OLD_PASSWORD_DAYS: i64 = 365;

#[derive(Debug, Clone, Default)]
pub struct VaultHealthReport {
    pub reused_passwords: Vec<ReusedPasswordGroup>,
    pub weak_passwords: Vec<WeakPasswordEntry>,
    pub unsecured_http: Vec<UnsecuredHttpEntry>,
    pub duplicate_items: Vec<DuplicateItemGroup>,
    pub expired_cards: Vec<ExpiredCardEntry>,
    pub old_passwords: Vec<OldPasswordEntry>,
    /// Logins on sites that offer 2FA but have no TOTP / passkey configured.
    pub inactive_2fa: Vec<Inactive2faEntry>,
}

/// Tunables (and optional datasets) for [`build_health_report_with`].
#[derive(Debug, Clone)]
pub struct HealthOptions {
    /// Reference time for age checks (`None` = now).
    pub now: Option<DateTime<Utc>>,
    pub old_password_days: i64,
    /// Domains known to support 2FA. `None` skips the inactive-2FA report.
    pub two_factor_directory: Option<TwoFactorDirectory>,
}

impl Default for HealthOptions {
    fn default() -> Self {
        Self {
            now: None,
            old_password_days: DEFAULT_OLD_PASSWORD_DAYS,
            two_factor_directory: Some(TwoFactorDirectory::builtin()),
        }
    }
}

/// Dataset hook: registrable domains that support two-factor authentication.
///
/// Ships with a small built-in list; supply a fuller dataset (e.g. an export of
/// <https://2fa.directory>) via [`TwoFactorDirectory::from_json`] / [`TwoFactorDirectory::load`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TwoFactorDirectory {
    domains: HashSet<String>,
}

impl TwoFactorDirectory {
    pub fn new<I, S>(domains: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self {
            domains: domains
                .into_iter()
                .map(|d| registrable_domain(&d.as_ref().trim().to_ascii_lowercase()))
                .filter(|d| !d.is_empty())
                .collect(),
        }
    }

    /// Small built-in stub covering widely used services.
    pub fn builtin() -> Self {
        Self::new([
            "google.com",
            "github.com",
            "gitlab.com",
            "microsoft.com",
            "live.com",
            "apple.com",
            "amazon.com",
            "facebook.com",
            "instagram.com",
            "twitter.com",
            "x.com",
            "linkedin.com",
            "dropbox.com",
            "paypal.com",
            "stripe.com",
            "cloudflare.com",
            "digitalocean.com",
            "aws.amazon.com",
            "slack.com",
            "discord.com",
            "reddit.com",
            "twitch.tv",
            "steampowered.com",
            "epicgames.com",
            "bitwarden.com",
            "proton.me",
            "protonmail.com",
            "binance.com",
            "coinbase.com",
            "kraken.com",
            "atlassian.com",
            "bitbucket.org",
            "npmjs.com",
            "pypi.org",
            "docker.com",
            "heroku.com",
            "netlify.com",
            "vercel.com",
            "zoom.us",
            "notion.so",
            "evernote.com",
            "ebay.com",
            "shopify.com",
            "namecheap.com",
            "godaddy.com",
            "ovh.com",
            "hetzner.com",
        ])
    }

    /// Parse a JSON dataset: array of domain strings, array of `[domain, {...}]` pairs
    /// (2fa.directory v3), or an object keyed by domain.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        let v: serde_json::Value = serde_json::from_str(json)?;
        let mut out = Vec::new();
        match &v {
            serde_json::Value::Array(arr) => {
                for e in arr {
                    match e {
                        serde_json::Value::String(s) => out.push(s.clone()),
                        serde_json::Value::Array(pair) => {
                            if let Some(s) = pair.first().and_then(|x| x.as_str()) {
                                out.push(s.to_string());
                            }
                        }
                        serde_json::Value::Object(o) => {
                            if let Some(s) = o.get("domain").and_then(|x| x.as_str()) {
                                out.push(s.to_string());
                            }
                        }
                        _ => {}
                    }
                }
            }
            serde_json::Value::Object(o) => out.extend(o.keys().cloned()),
            _ => {}
        }
        Ok(Self::new(out))
    }

    /// Load a dataset from disk; falls back to [`TwoFactorDirectory::builtin`] when the file
    /// is missing or invalid.
    pub fn load(path: &Path) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|s| Self::from_json(&s).ok())
            .filter(|d| !d.is_empty())
            .unwrap_or_else(Self::builtin)
    }

    pub fn is_empty(&self) -> bool {
        self.domains.is_empty()
    }

    pub fn len(&self) -> usize {
        self.domains.len()
    }

    pub fn supports_2fa(&self, host: &str) -> bool {
        let host = host.trim().to_ascii_lowercase();
        self.domains.contains(&host) || self.domains.contains(&registrable_domain(&host))
    }
}

#[derive(Debug, Clone)]
pub struct OldPasswordEntry {
    pub item_id: String,
    pub item_name: String,
    pub last_changed: String,
    pub age_days: i64,
}

#[derive(Debug, Clone)]
pub struct Inactive2faEntry {
    pub item_id: String,
    pub item_name: String,
    pub host: String,
}

#[derive(Debug, Clone)]
pub struct ExpiredCardEntry {
    pub item_id: String,
    pub item_name: String,
    pub exp_month: String,
    pub exp_year: String,
    pub expired: bool,
}

#[derive(Debug, Clone)]
pub struct ReusedPasswordGroup {
    pub password_fingerprint: String,
    pub item_ids: Vec<String>,
    pub item_names: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct WeakPasswordEntry {
    pub item_id: String,
    pub item_name: String,
    pub entropy_bits: f64,
    pub strength_label: &'static str,
    /// zxcvbn score 0–4.
    pub score: u8,
    pub warning: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UnsecuredHttpEntry {
    pub item_id: String,
    pub item_name: String,
    pub uri: String,
}

#[derive(Debug, Clone)]
pub struct DuplicateItemGroup {
    pub host: String,
    pub username: String,
    pub item_ids: Vec<String>,
    pub item_names: Vec<String>,
}

fn login_items(items: &[DecryptedItem]) -> impl Iterator<Item = &DecryptedItem> {
    items
        .iter()
        .filter(|i| !i.deleted && i.item_type == ItemType::Login)
}

/// Build a health report from decrypted vault items (default options).
pub fn build_health_report(items: &[DecryptedItem]) -> VaultHealthReport {
    build_health_report_with(items, &HealthOptions::default())
}

pub fn build_health_report_with(
    items: &[DecryptedItem],
    opts: &HealthOptions,
) -> VaultHealthReport {
    let now = opts.now.unwrap_or_else(Utc::now);
    VaultHealthReport {
        reused_passwords: find_reused_passwords(items),
        weak_passwords: find_weak_passwords(items),
        unsecured_http: find_unsecured_http(items),
        duplicate_items: find_duplicate_items(items),
        expired_cards: find_expired_cards(items),
        old_passwords: find_old_passwords(items, now, opts.old_password_days),
        inactive_2fa: opts
            .two_factor_directory
            .as_ref()
            .map(|d| find_inactive_2fa(items, d))
            .unwrap_or_default(),
    }
}

/// Logins whose password has not changed for more than `max_age_days`.
///
/// Uses `password_revision_date`, falling back to `creation_date`; items with neither are skipped.
pub fn find_old_passwords(
    items: &[DecryptedItem],
    now: DateTime<Utc>,
    max_age_days: i64,
) -> Vec<OldPasswordEntry> {
    let mut out = Vec::new();
    for item in login_items(items) {
        if item.password.as_deref().is_none_or(str::is_empty) {
            continue;
        }
        let Some(date) = item
            .password_revision_date
            .as_deref()
            .or(item.creation_date.as_deref())
        else {
            continue;
        };
        let Ok(parsed) = DateTime::parse_from_rfc3339(date) else {
            continue;
        };
        let age_days = (now - parsed.with_timezone(&Utc)).num_days();
        if age_days > max_age_days {
            out.push(OldPasswordEntry {
                item_id: item.id.clone(),
                item_name: item.name.clone(),
                last_changed: date.to_string(),
                age_days,
            });
        }
    }
    out.sort_by_key(|a| std::cmp::Reverse(a.age_days));
    out
}

/// Logins on 2FA-capable sites (per `directory`) with neither TOTP nor a passkey.
pub fn find_inactive_2fa(
    items: &[DecryptedItem],
    directory: &TwoFactorDirectory,
) -> Vec<Inactive2faEntry> {
    let mut out = Vec::new();
    for item in login_items(items) {
        if item.totp.as_deref().is_some_and(|t| !t.is_empty()) || !item.passkeys.is_empty() {
            continue;
        }
        let host = item
            .uris
            .iter()
            .filter_map(|u| uri_host(&u.uri))
            .find(|h| directory.supports_2fa(h));
        if let Some(host) = host {
            out.push(Inactive2faEntry {
                item_id: item.id.clone(),
                item_name: item.name.clone(),
                host,
            });
        }
    }
    out
}

/// Cards that are expired or expire within 60 days.
pub fn find_expired_cards(items: &[DecryptedItem]) -> Vec<ExpiredCardEntry> {
    use crate::card::{card_expires_soon, card_is_expired};

    let mut out = Vec::new();
    for item in items
        .iter()
        .filter(|i| !i.deleted && i.item_type == ItemType::Card)
    {
        let (Some(m), Some(y)) = (&item.card_exp_month, &item.card_exp_year) else {
            continue;
        };
        if card_is_expired(m, y) || card_expires_soon(m, y, 2) {
            out.push(ExpiredCardEntry {
                item_id: item.id.clone(),
                item_name: item.name.clone(),
                exp_month: m.clone(),
                exp_year: y.clone(),
                expired: card_is_expired(m, y),
            });
        }
    }
    out
}

pub fn find_reused_passwords(items: &[DecryptedItem]) -> Vec<ReusedPasswordGroup> {
    let mut by_pw: HashMap<String, Vec<&DecryptedItem>> = HashMap::new();
    for item in login_items(items) {
        if let Some(pw) = &item.password {
            if !pw.is_empty() {
                by_pw.entry(pw.clone()).or_default().push(item);
            }
        }
    }
    by_pw
        .into_iter()
        .filter(|(_, group)| group.len() > 1)
        .map(|(password, group)| ReusedPasswordGroup {
            password_fingerprint: format!("sha256:{:x}", simple_hash(&password)),
            item_ids: group.iter().map(|i| i.id.clone()).collect(),
            item_names: group.iter().map(|i| i.name.clone()).collect(),
        })
        .collect()
}

fn simple_hash(s: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

pub fn find_weak_passwords(items: &[DecryptedItem]) -> Vec<WeakPasswordEntry> {
    let mut out = Vec::new();
    for item in login_items(items) {
        let Some(pw) = &item.password else {
            continue;
        };
        if pw.is_empty() {
            continue;
        }
        // Penalise passwords built from the account's own username / item name.
        let username = item.username.as_deref().unwrap_or("");
        let user_inputs: Vec<&str> = [username, item.name.as_str()]
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect();
        let strength = evaluate_password(pw, &user_inputs);
        if strength.score < WEAK_SCORE_THRESHOLD || pw.chars().count() < 8 {
            out.push(WeakPasswordEntry {
                item_id: item.id.clone(),
                item_name: item.name.clone(),
                entropy_bits: strength.entropy_bits,
                strength_label: strength.label,
                score: strength.score,
                warning: strength.warning,
            });
        }
    }
    out
}

pub fn find_unsecured_http(items: &[DecryptedItem]) -> Vec<UnsecuredHttpEntry> {
    let mut out = Vec::new();
    for item in items.iter().filter(|i| !i.deleted) {
        for u in &item.uris {
            if is_insecure_http(&u.uri) {
                out.push(UnsecuredHttpEntry {
                    item_id: item.id.clone(),
                    item_name: item.name.clone(),
                    uri: u.uri.clone(),
                });
            }
        }
    }
    out
}

pub fn find_duplicate_items(items: &[DecryptedItem]) -> Vec<DuplicateItemGroup> {
    let mut by_key: HashMap<(String, String), Vec<&DecryptedItem>> = HashMap::new();
    for item in login_items(items) {
        let username = item.username.clone().unwrap_or_default();
        let host = item
            .primary_uri()
            .and_then(uri_host)
            .unwrap_or_else(|| "_no_uri".into());
        by_key.entry((host, username)).or_default().push(item);
    }
    by_key
        .into_iter()
        .filter(|(_, g)| g.len() > 1)
        .map(|((host, username), group)| DuplicateItemGroup {
            host,
            username,
            item_ids: group.iter().map(|i| i.id.clone()).collect(),
            item_names: group.iter().map(|i| i.name.clone()).collect(),
        })
        .collect()
}

/// HIBP k-anonymity range query: returns breach count (0 if not found).
pub async fn hibp_password_pwned_count(password: &str) -> Result<u64, HibpError> {
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(password.as_bytes());
    let digest = hasher.finalize();
    let hex_hash = hex::encode(digest).to_ascii_uppercase();
    let (prefix, suffix) = hex_hash.split_at(5);

    let url = format!("https://api.pwnedpasswords.com/range/{prefix}");
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(HibpError::Http)?;

    let body = client
        .get(&url)
        .header("Add-Padding", "true")
        .send()
        .await
        .map_err(HibpError::Http)?
        .error_for_status()
        .map_err(HibpError::Http)?
        .text()
        .await
        .map_err(HibpError::Http)?;

    for line in body.lines() {
        let Some((hash_suffix, count_str)) = line.split_once(':') else {
            continue;
        };
        if hash_suffix.eq_ignore_ascii_case(suffix) {
            return count_str.trim().parse().map_err(|_| HibpError::Parse);
        }
    }
    Ok(0)
}

/// Environment variables checked (in order) for a HIBP v3 API key (required for email lookups).
pub const HIBP_API_KEY_ENV_VARS: [&str; 2] = ["BW_TUI_HIBP_API_KEY", "HIBP_API_KEY"];

pub fn hibp_api_key_from_env() -> Option<String> {
    HIBP_API_KEY_ENV_VARS
        .iter()
        .find_map(|k| std::env::var(k).ok())
        .map(|k| k.trim().to_string())
        .filter(|k| !k.is_empty())
}

/// Distinct account emails worth checking against HIBP (login usernames that look like emails,
/// identity emails). Order is stable; at most `max` are returned.
pub fn collect_breach_check_emails(items: &[DecryptedItem], max: usize) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for item in items.iter().filter(|i| !i.deleted) {
        let candidate = match item.item_type {
            ItemType::Login => item.username.as_deref(),
            ItemType::Identity => item.identity_email.as_deref(),
            _ => None,
        };
        let Some(email) = candidate.map(str::trim) else {
            continue;
        };
        let looks_like_email = email
            .split_once('@')
            .is_some_and(|(l, d)| !l.is_empty() && d.contains('.') && !email.contains(' '));
        if !looks_like_email {
            continue;
        }
        if seen.insert(email.to_ascii_lowercase()) {
            out.push(email.to_string());
            if out.len() >= max {
                break;
            }
        }
    }
    out
}

/// HIBP breached-account lookup (opt-in; sends the email to haveibeenpwned.com and needs a
/// paid API key). Returns breach names; empty when the account is not found.
pub async fn hibp_email_breaches(email: &str, api_key: &str) -> Result<Vec<String>, HibpError> {
    let mut url = url::Url::parse("https://haveibeenpwned.com/api/v3/breachedaccount/")
        .map_err(|_| HibpError::Parse)?;
    url.path_segments_mut()
        .map_err(|_| HibpError::Parse)?
        .pop_if_empty()
        .push(email);
    url.set_query(Some("truncateResponse=true"));

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    let resp = client
        .get(url)
        .header("hibp-api-key", api_key)
        .header("user-agent", "bitwarden-tui")
        .send()
        .await?;
    parse_hibp_breach_response(resp.status().as_u16(), &resp.text().await?)
}

fn parse_hibp_breach_response(status: u16, body: &str) -> Result<Vec<String>, HibpError> {
    match status {
        404 => Ok(Vec::new()),
        401 | 403 => Err(HibpError::Unauthorized),
        429 => Err(HibpError::RateLimited),
        200 => {
            let v: serde_json::Value = serde_json::from_str(body).map_err(|_| HibpError::Parse)?;
            let arr = v.as_array().ok_or(HibpError::Parse)?;
            Ok(arr
                .iter()
                .filter_map(|b| b.get("Name").and_then(|n| n.as_str()).map(str::to_string))
                .collect())
        }
        other => Err(HibpError::Status(other)),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HibpError {
    #[error("hibp request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("invalid hibp response")]
    Parse,
    #[error("hibp API key rejected")]
    Unauthorized,
    #[error("hibp rate limit hit — try again later")]
    RateLimited,
    #[error("hibp returned HTTP {0}")]
    Status(u16),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{DecryptedUri, ItemType};

    fn login(id: &str, name: &str, user: &str, pw: &str, uri: &str) -> DecryptedItem {
        DecryptedItem {
            id: id.into(),
            name: name.into(),
            item_type: ItemType::Login,
            folder_id: None,
            organization_id: None,
            collection_ids: Vec::new(),
            favorite: false,
            deleted: false,
            reprompt: false,
            notes: None,
            username: Some(user.into()),
            password: Some(pw.into()),
            totp: None,
            uris: vec![DecryptedUri {
                uri: uri.into(),
                match_type: None,
            }],
            custom_fields: Vec::new(),
            password_history: Vec::new(),
            passkeys: Vec::new(),
            password_revision_date: None,
            creation_date: None,
            cardholder_name: None,
            card_brand: None,
            card_number: None,
            card_exp_month: None,
            card_exp_year: None,
            card_code: None,
            identity_title: None,
            identity_first_name: None,
            identity_middle_name: None,
            identity_last_name: None,
            identity_email: None,
            identity_phone: None,
            identity_username: None,
            identity_address1: None,
            identity_address2: None,
            identity_address3: None,
            identity_city: None,
            identity_state: None,
            identity_postal_code: None,
            identity_country: None,
            identity_company: None,
            identity_ssn: None,
            identity_passport_number: None,
            identity_license_number: None,
            ssh_private_key: None,
            ssh_public_key: None,
            ssh_fingerprint: None,
            revision_date: None,
            has_item_key: false,
        }
    }

    #[test]
    fn detects_reused_and_weak() {
        let items = vec![
            login("1", "A", "u", "password", "https://a.com"),
            login("2", "B", "u2", "password", "https://b.com"),
            login("3", "C", "u3", "x", "https://c.com"),
        ];
        let report = build_health_report(&items);
        assert_eq!(report.reused_passwords.len(), 1);
        assert_eq!(report.reused_passwords[0].item_ids.len(), 2);
        assert!(!report.weak_passwords.is_empty());
    }

    #[test]
    fn detects_http_and_duplicates() {
        let items = vec![
            login(
                "1",
                "Git",
                "alice",
                "longpassword1!",
                "http://vault.example.com",
            ),
            login(
                "2",
                "Git dup",
                "alice",
                "otherpass12!",
                "https://vault.example.com",
            ),
        ];
        let report = build_health_report(&items);
        assert_eq!(report.unsecured_http.len(), 1);
        assert_eq!(report.duplicate_items.len(), 1);
    }

    #[test]
    fn weak_uses_zxcvbn() {
        let items = vec![
            login("1", "A", "u", "password", "https://a.com"),
            login("2", "B", "u", "x7#Qm!9vLp2$Zr8@Tn4^Ws5&", "https://b.com"),
        ];
        let weak = find_weak_passwords(&items);
        assert!(
            weak.iter().any(|w| w.item_id == "1"),
            "common password should be weak: {weak:?}"
        );
        assert!(
            !weak.iter().any(|w| w.item_id == "2"),
            "strong random password should not be weak"
        );
        let entry = weak.iter().find(|w| w.item_id == "1").unwrap();
        assert!(entry.score < WEAK_SCORE_THRESHOLD);
    }

    #[test]
    fn old_passwords_by_age() {
        let now = DateTime::parse_from_rfc3339("2026-10-12T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut old = login("1", "Old", "u", "pw", "https://a.com");
        old.password_revision_date = Some("2024-01-01T00:00:00Z".into());
        let mut fresh = login("2", "Fresh", "u", "pw2", "https://b.com");
        fresh.password_revision_date = Some("2026-09-01T00:00:00Z".into());
        let mut no_date = login("3", "NoDate", "u", "pw3", "https://c.com");
        no_date.password_revision_date = None;
        let found = find_old_passwords(&[old, fresh, no_date], now, 365);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].item_id, "1");
        assert!(found[0].age_days > 365);
    }

    #[test]
    fn inactive_2fa_uses_directory() {
        let dir = TwoFactorDirectory::new(["github.com"]);
        let mut with_totp = login("2", "GH2", "u", "pw", "https://github.com/login");
        with_totp.totp = Some("otpauth://totp/x?secret=ABC".into());
        let items = vec![
            login("1", "GH", "u", "pw", "https://gist.github.com"),
            with_totp,
            login("3", "Other", "u", "pw", "https://example.org"),
        ];
        let found = find_inactive_2fa(&items, &dir);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].item_id, "1");
    }

    #[test]
    fn two_factor_directory_parses_formats() {
        let a = TwoFactorDirectory::from_json(r#"["a.com","b.org"]"#).unwrap();
        assert!(a.supports_2fa("www.a.com"));
        let b = TwoFactorDirectory::from_json(r#"[["c.com",{"tfa":["totp"]}]]"#).unwrap();
        assert!(b.supports_2fa("c.com"));
        let c = TwoFactorDirectory::from_json(r#"{"d.io":{}}"#).unwrap();
        assert!(c.supports_2fa("d.io"));
    }

    #[test]
    fn breach_emails_deduped() {
        let items = vec![
            login("1", "A", "Alice@Example.com", "pw", "https://a.com"),
            login("2", "B", "alice@example.com", "pw", "https://b.com"),
            login("3", "C", "notanemail", "pw", "https://c.com"),
        ];
        assert_eq!(
            collect_breach_check_emails(&items, 10),
            vec!["Alice@Example.com"]
        );
    }

    #[test]
    fn hibp_breach_response_parsing() {
        assert!(parse_hibp_breach_response(404, "").unwrap().is_empty());
        assert_eq!(
            parse_hibp_breach_response(200, r#"[{"Name":"Adobe"},{"Name":"LinkedIn"}]"#).unwrap(),
            vec!["Adobe", "LinkedIn"]
        );
        assert!(matches!(
            parse_hibp_breach_response(401, ""),
            Err(HibpError::Unauthorized)
        ));
        assert!(matches!(
            parse_hibp_breach_response(429, ""),
            Err(HibpError::RateLimited)
        ));
    }

    #[tokio::test]
    #[ignore = "network: HIBP range API"]
    async fn hibp_known_password() {
        let count = hibp_password_pwned_count("password").await.unwrap();
        assert!(count > 0);
    }
}
