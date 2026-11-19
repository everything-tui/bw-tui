//! Equivalent-domain rules editor API (`GET`/`PUT /settings/domains`).
//!
//! The sync payload only exposes a flattened view (see [`crate::domains`]); the editor needs the
//! full server representation so global groups can be excluded and custom groups saved back.

use serde::Serialize;
use serde_json::Value;

use crate::error::{Result, SessionError};

/// One built-in ("global") equivalent-domain group shipped by the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalDomainGroup {
    /// Server `GlobalEquivalentDomainsType` id (used when excluding the group).
    pub type_id: i64,
    pub domains: Vec<String>,
    pub excluded: bool,
}

/// Editable domain rules: user-defined groups plus the excluded set of global groups.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DomainRules {
    pub custom_groups: Vec<Vec<String>>,
    pub global_groups: Vec<GlobalDomainGroup>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainRulesRequest {
    pub excluded_global_equivalent_domains: Vec<i64>,
    pub equivalent_domains: Vec<Vec<String>>,
}

impl DomainRules {
    /// Parse the `GET /settings/domains` JSON body.
    pub fn from_json(v: &Value) -> Result<Self> {
        let obj = v
            .as_object()
            .ok_or_else(|| SessionError::Other("domains response must be an object".into()))?;
        // Accept both camelCase and PascalCase keys.
        let get = |name: &str| -> Option<&Value> {
            obj.get(name).or_else(|| {
                let mut c = name.chars();
                let pascal: String = match c.next() {
                    Some(f) => f.to_uppercase().chain(c).collect(),
                    None => String::new(),
                };
                obj.get(&pascal)
            })
        };

        let custom_groups = get("equivalentDomains")
            .and_then(Value::as_array)
            .map(|outer| {
                outer
                    .iter()
                    .filter_map(|g| g.as_array())
                    .map(|g| {
                        g.iter()
                            .filter_map(|d| d.as_str().map(normalize_domain))
                            .filter(|d| !d.is_empty())
                            .collect::<Vec<_>>()
                    })
                    .filter(|g: &Vec<String>| !g.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        let excluded_ids: Vec<i64> = get("excludedGlobalEquivalentDomains")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_i64).collect())
            .unwrap_or_default();

        let global_groups = get("globalEquivalentDomains")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|g| {
                        let o = g.as_object()?;
                        let type_id = o
                            .get("type")
                            .or_else(|| o.get("Type"))
                            .and_then(Value::as_i64)?;
                        let domains = o
                            .get("domains")
                            .or_else(|| o.get("Domains"))
                            .and_then(Value::as_array)
                            .map(|d| {
                                d.iter()
                                    .filter_map(|x| x.as_str().map(normalize_domain))
                                    .collect()
                            })
                            .unwrap_or_default();
                        let excluded = o
                            .get("excluded")
                            .or_else(|| o.get("Excluded"))
                            .and_then(Value::as_bool)
                            .unwrap_or(false)
                            || excluded_ids.contains(&type_id);
                        Some(GlobalDomainGroup {
                            type_id,
                            domains,
                            excluded,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(Self {
            custom_groups,
            global_groups,
        })
    }

    /// Request body for `PUT /settings/domains`.
    pub fn to_request(&self) -> DomainRulesRequest {
        DomainRulesRequest {
            excluded_global_equivalent_domains: self
                .global_groups
                .iter()
                .filter(|g| g.excluded)
                .map(|g| g.type_id)
                .collect(),
            equivalent_domains: self
                .custom_groups
                .iter()
                .filter(|g| g.len() >= 2)
                .cloned()
                .collect(),
        }
    }
}

/// Lowercase and strip scheme / path / port-less noise from a user-typed domain.
pub fn normalize_domain(raw: &str) -> String {
    let mut s = raw.trim().to_ascii_lowercase();
    if let Some(idx) = s.find("://") {
        s = s[idx + 3..].to_string();
    }
    if let Some(idx) = s.find(['/', '?', '#']) {
        s.truncate(idx);
    }
    s.trim_matches('.').to_string()
}

/// Parse `"a.com, b.com c.com"` into a normalized, de-duplicated group.
pub fn parse_domain_group(line: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for part in line.split(|c: char| c == ',' || c == ';' || c.is_whitespace()) {
        let d = normalize_domain(part);
        if d.is_empty() || !is_plausible_domain(&d) || out.contains(&d) {
            continue;
        }
        out.push(d);
    }
    out
}

/// Format a group for display / editing.
pub fn format_domain_group(group: &[String]) -> String {
    group.join(", ")
}

fn is_plausible_domain(d: &str) -> bool {
    !d.is_empty()
        && d.len() <= 253
        && d.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '*' || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_server_payload() {
        let v = json!({
            "equivalentDomains": [["Example.com", "example.net"]],
            "globalEquivalentDomains": [
                {"type": 2, "domains": ["ameritrade.com", "tdameritrade.com"], "excluded": false},
                {"type": 3, "domains": ["bank.com"], "excluded": true}
            ],
            "excludedGlobalEquivalentDomains": [3]
        });
        let r = DomainRules::from_json(&v).unwrap();
        assert_eq!(r.custom_groups, vec![vec!["example.com", "example.net"]]);
        assert_eq!(r.global_groups.len(), 2);
        assert!(!r.global_groups[0].excluded);
        assert!(r.global_groups[1].excluded);
        let req = r.to_request();
        assert_eq!(req.excluded_global_equivalent_domains, vec![3]);
        assert_eq!(req.equivalent_domains.len(), 1);
    }

    #[test]
    fn group_parsing_normalizes() {
        assert_eq!(
            parse_domain_group("https://A.com/x, b.com  a.com;c.org"),
            vec!["a.com", "b.com", "c.org"]
        );
    }

    #[test]
    fn single_domain_groups_are_dropped_from_request() {
        let r = DomainRules {
            custom_groups: vec![vec!["a.com".into()], vec!["a.com".into(), "b.com".into()]],
            global_groups: vec![],
        };
        assert_eq!(r.to_request().equivalent_domains.len(), 1);
    }
}
