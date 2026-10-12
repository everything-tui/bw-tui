//! Vault health / security reports over decrypted items.

use std::collections::HashMap;

use vault_api::is_insecure_http;

use crate::generator::{password_entropy_bits, password_strength_label};
use crate::models::{DecryptedItem, ItemType};
use crate::uri_match::uri_host;

const WEAK_ENTROPY_THRESHOLD: f64 = 40.0;

#[derive(Debug, Clone, Default)]
pub struct VaultHealthReport {
    pub reused_passwords: Vec<ReusedPasswordGroup>,
    pub weak_passwords: Vec<WeakPasswordEntry>,
    pub unsecured_http: Vec<UnsecuredHttpEntry>,
    pub duplicate_items: Vec<DuplicateItemGroup>,
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

fn estimate_charset_size(password: &str) -> usize {
    let mut classes = 0usize;
    if password.chars().any(|c| c.is_ascii_lowercase()) {
        classes += 26;
    }
    if password.chars().any(|c| c.is_ascii_uppercase()) {
        classes += 26;
    }
    if password.chars().any(|c| c.is_ascii_digit()) {
        classes += 10;
    }
    if password.chars().any(|c| !c.is_ascii_alphanumeric()) {
        classes += 32;
    }
    classes.max(1)
}

fn password_entropy(password: &str) -> f64 {
    password_entropy_bits(password.len(), estimate_charset_size(password))
}

/// Build a health report from decrypted vault items.
pub fn build_health_report(items: &[DecryptedItem]) -> VaultHealthReport {
    VaultHealthReport {
        reused_passwords: find_reused_passwords(items),
        weak_passwords: find_weak_passwords(items),
        unsecured_http: find_unsecured_http(items),
        duplicate_items: find_duplicate_items(items),
    }
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
        let bits = password_entropy(pw);
        if bits < WEAK_ENTROPY_THRESHOLD
            || password_strength_label(bits) == "weak"
            || pw.len() < 8
        {
            out.push(WeakPasswordEntry {
                item_id: item.id.clone(),
                item_name: item.name.clone(),
                entropy_bits: bits,
                strength_label: password_strength_label(bits),
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
        by_key
            .entry((host, username))
            .or_default()
            .push(item);
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
            return count_str
                .trim()
                .parse()
                .map_err(|_| HibpError::Parse);
        }
    }
    Ok(0)
}

#[derive(Debug, thiserror::Error)]
pub enum HibpError {
    #[error("hibp request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("invalid hibp response")]
    Parse,
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
            login("1", "Git", "alice", "longpassword1!", "http://vault.example.com"),
            login("2", "Git dup", "alice", "otherpass12!", "https://vault.example.com"),
        ];
        let report = build_health_report(&items);
        assert_eq!(report.unsecured_http.len(), 1);
        assert_eq!(report.duplicate_items.len(), 1);
    }

    #[tokio::test]
    #[ignore = "network: HIBP range API"]
    async fn hibp_known_password() {
        let count = hibp_password_pwned_count("password").await.unwrap();
        assert!(count > 0);
    }
}
