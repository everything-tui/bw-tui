//! Bitwarden-style URI matching for autofill / CLI lookup.

use url::Url;

use crate::error::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UriMatchType {
    Domain = 0,
    Host = 1,
    StartsWith = 2,
    Exact = 3,
    RegularExpression = 4,
    Never = 5,
}

impl UriMatchType {
    pub fn from_i32(v: i32) -> Self {
        match v {
            0 => Self::Domain,
            1 => Self::Host,
            2 => Self::StartsWith,
            3 => Self::Exact,
            4 => Self::RegularExpression,
            5 => Self::Never,
            _ => Self::Domain,
        }
    }
}

pub fn uri_host(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let with_scheme = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    };
    Url::parse(&with_scheme)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_ascii_lowercase()))
}

pub fn registrable_domain(host: &str) -> String {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let parts: Vec<&str> = host.split('.').filter(|p| !p.is_empty()).collect();
    if parts.len() <= 2 {
        return host;
    }
    format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
}

fn flatten_equivalent(equivalent_domains: &[Vec<String>]) -> Vec<String> {
    equivalent_domains
        .iter()
        .flat_map(|g| g.iter().cloned())
        .collect()
}

/// Returns true if any stored URI on the item matches `target_url`.
pub fn item_matches_uri(
    item_uris: &[impl AsRef<str>],
    match_types: &[Option<i32>],
    target_url: &str,
    equivalent_domains: &[Vec<String>],
) -> bool {
    let flat = flatten_equivalent(equivalent_domains);
    for (i, uri) in item_uris.iter().enumerate() {
        let mt = match_types.get(i).copied().flatten();
        if uri_matches(uri.as_ref(), mt, target_url, &flat).unwrap_or(false) {
            return true;
        }
    }
    false
}

pub fn item_matches_uri_decrypted(
    uris: &[crate::DecryptedUri],
    target_url: &str,
    equivalent_domains: &[Vec<String>],
) -> bool {
    let strings: Vec<&str> = uris.iter().map(|u| u.uri.as_str()).collect();
    let types: Vec<Option<i32>> = uris.iter().map(|u| u.match_type).collect();
    item_matches_uri(&strings, &types, target_url, equivalent_domains)
}

/// Match a stored login URI against a target URL (or host fragment).
///
/// `match_type` follows Bitwarden: 0=domain, 1=host, 2=starts with, 3=exact, 4=regex, 5=never.
pub fn uri_matches(
    uri: &str,
    match_type: Option<i32>,
    target: &str,
    equivalent_domains: &[String],
) -> Result<bool> {
    let mt = match_type.unwrap_or(0);
    if mt == 5 {
        return Ok(false);
    }
    let uri_l = uri.to_lowercase();
    let target_l = target.to_lowercase();
    let host = extract_host(&target_l).unwrap_or(target_l.as_str());

    let domain_match = |u: &str| -> bool {
        let u_host = extract_host(u).unwrap_or(u);
        if u_host == host {
            return true;
        }
        for eq in equivalent_domains {
            if host.ends_with(eq.as_str()) || u_host.ends_with(eq.as_str()) {
                return true;
            }
        }
        host.ends_with(&format!(".{u_host}")) || u_host.ends_with(&format!(".{host}"))
    };

    Ok(match mt {
        0 => domain_match(&uri_l),
        1 => {
            let u_host = extract_host(&uri_l).unwrap_or(uri_l.as_str());
            u_host == host
        }
        2 => target_l.starts_with(&uri_l) || uri_l.starts_with(&target_l),
        3 => uri_l == target_l,
        4 => {
            // Bitwarden stores a regex pattern in the URI field.
            match regex::Regex::new(uri) {
                Ok(re) => re.is_match(target),
                Err(_) => false,
            }
        }
        _ => domain_match(&uri_l),
    })
}

fn extract_host(url: &str) -> Option<&str> {
    let s = url.trim();
    let after_scheme = s
        .strip_prefix("http://")
        .or_else(|| s.strip_prefix("https://"))
        .or_else(|| s.strip_prefix("ftp://"))
        .unwrap_or(s);
    let host = after_scheme.split('/').next()?.split('@').next()?;
    let host = host.split(':').next()?;
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_match_subdomain() {
        assert!(uri_matches(
            "https://github.com",
            Some(0),
            "https://api.github.com/foo",
            &[]
        )
        .unwrap());
    }

    #[test]
    fn exact_match() {
        assert!(uri_matches(
            "https://example.com/login",
            Some(3),
            "https://example.com/login",
            &[]
        )
        .unwrap());
    }

    #[test]
    fn item_matches_uri_github_subdomain() {
        let uris = ["https://github.com"];
        assert!(item_matches_uri(
            &uris,
            &[Some(0)],
            "https://www.github.com/login",
            &[]
        ));
    }

    #[test]
    fn equivalent_domain_groups() {
        let equiv = vec![vec![
            "apple.com".into(),
            "icloud.com".into(),
            "me.com".into(),
        ]];
        assert!(item_matches_uri(
            &["https://icloud.com"],
            &[Some(0)],
            "https://apple.com",
            &equiv
        ));
    }

    #[test]
    fn regex_match_type() {
        assert!(uri_matches(
            r"^https://example\.com/.*",
            Some(4),
            "https://example.com/a",
            &[]
        )
        .unwrap());
        assert!(!uri_matches(
            r"^https://example\.com/.*",
            Some(4),
            "https://other.com/a",
            &[]
        )
        .unwrap());
        assert!(!uri_matches("[invalid", Some(4), "https://example.com", &[]).unwrap());
    }
}
