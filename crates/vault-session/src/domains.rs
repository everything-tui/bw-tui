//! Equivalent / global domain lists from sync `domains` payload.

use serde_json::Value;
use vault_crypto::{decrypt_bytes, UserKey};

use crate::error::{Result, SessionError};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VaultDomains {
    pub global_equivalent: Vec<String>,
    pub equivalent_groups: Vec<Vec<String>>,
}

impl VaultDomains {
    /// Groups passed to URI matching (`global` list is one equivalence group).
    pub fn uri_equivalent_groups(&self) -> Vec<Vec<String>> {
        let mut out = self.equivalent_groups.clone();
        if !self.global_equivalent.is_empty() {
            out.insert(0, self.global_equivalent.clone());
        }
        out
    }
}

fn looks_encrypted(s: &str) -> bool {
    let t = s.trim();
    !t.is_empty() && t.chars().next().is_some_and(|c| c.is_ascii_digit())
}

fn decrypt_json_value(raw: &str, user_key: &UserKey) -> Result<Value> {
    let plain = decrypt_bytes(raw.trim(), user_key)?;
    serde_json::from_slice(&plain).map_err(|e| SessionError::Other(e.to_string()))
}

fn parse_string_list(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_ascii_lowercase()))
                .collect()
        })
        .unwrap_or_default()
}

fn parse_group_list(value: &Value) -> Vec<Vec<String>> {
    value
        .as_array()
        .map(|outer| {
            outer
                .iter()
                .filter_map(|inner| {
                    inner.as_array().map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_ascii_lowercase()))
                            .collect()
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Parse sync `domains` (plaintext object or EncString JSON).
pub fn parse_domains(raw: &Value, user_key: Option<&UserKey>) -> Result<VaultDomains> {
    let obj = match raw {
        Value::String(s) if looks_encrypted(s) => {
            let uk = user_key.ok_or(SessionError::Locked)?;
            decrypt_json_value(s, uk)?
        }
        Value::Object(_) => raw.clone(),
        _ => {
            return Err(SessionError::Other(
                "unexpected domains payload shape".into(),
            ));
        }
    };

    let Value::Object(map) = obj else {
        return Err(SessionError::Other("domains JSON must be an object".into()));
    };

    let mut global = Vec::new();
    let mut groups = Vec::new();

    for (key, value) in map {
        match key.as_str() {
            "globalEquivalentDomains" => {
                global = match value {
                    Value::String(s) if looks_encrypted(&s) => {
                        let uk = user_key.ok_or(SessionError::Locked)?;
                        let v = decrypt_json_value(&s, uk)?;
                        parse_string_list(&v)
                    }
                    other => parse_string_list(&other),
                };
            }
            "equivalentDomains" => {
                groups = match value {
                    Value::String(s) if looks_encrypted(&s) => {
                        let uk = user_key.ok_or(SessionError::Locked)?;
                        let v = decrypt_json_value(&s, uk)?;
                        parse_group_list(&v)
                    }
                    other => parse_group_list(&other),
                };
            }
            _ => {}
        }
    }

    Ok(VaultDomains {
        global_equivalent: global,
        equivalent_groups: groups,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_plain_domains() {
        let raw = json!({
            "globalEquivalentDomains": ["Google.com", "youtube.com"],
            "equivalentDomains": [
                ["apple.com", "icloud.com"]
            ]
        });
        let d = parse_domains(&raw, None).unwrap();
        assert_eq!(d.global_equivalent, vec!["google.com", "youtube.com"]);
        assert_eq!(d.equivalent_groups[0], vec!["apple.com", "icloud.com"]);
        let groups = d.uri_equivalent_groups();
        assert_eq!(groups.len(), 2);
    }
}
