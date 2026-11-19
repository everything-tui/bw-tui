//! Vault list search query parsing (`type:login`, `folder:work`, `name:foo`, …).

use vault_session::item_matches_uri;

use crate::models::{DecryptedItem, ItemType};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedSearch {
    pub free_text: String,
    pub item_type: Option<ItemType>,
    pub folder: Option<String>,
    pub name: Option<String>,
    pub favorite: Option<bool>,
    pub url: Option<String>,
}

/// Split a search bar query into operators and remaining fuzzy text.
pub fn parse_search_query(raw: &str) -> ParsedSearch {
    let mut out = ParsedSearch::default();
    let mut free = Vec::new();
    for token in raw.split_whitespace() {
        if let Some((key, value)) = token.split_once(':') {
            let key = key.to_ascii_lowercase();
            let value = value.trim();
            if value.is_empty() {
                free.push(token);
                continue;
            }
            match key.as_str() {
                "type" | "t" => out.item_type = parse_item_type(value),
                "folder" | "f" => out.folder = Some(value.to_string()),
                "name" | "n" => out.name = Some(value.to_string()),
                "favorite" | "fav" => out.favorite = parse_bool(value),
                "url" | "uri" | "u" => out.url = Some(value.to_string()),
                _ => free.push(token),
            }
        } else {
            free.push(token);
        }
    }
    out.free_text = free.join(" ");
    out
}

fn parse_item_type(s: &str) -> Option<ItemType> {
    match s.to_ascii_lowercase().as_str() {
        "login" | "logins" => Some(ItemType::Login),
        "note" | "notes" | "securenote" => Some(ItemType::SecureNote),
        "card" | "cards" => Some(ItemType::Card),
        "identity" | "identities" => Some(ItemType::Identity),
        "ssh" | "sshkey" | "ssh-key" => Some(ItemType::SshKey),
        _ => None,
    }
}

fn parse_bool(s: &str) -> Option<bool> {
    match s.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "y" => Some(true),
        "0" | "false" | "no" | "n" => Some(false),
        _ => None,
    }
}

impl ParsedSearch {
    pub fn matches_item(
        &self,
        item: &DecryptedItem,
        folder_name: Option<&str>,
        equivalent_domains: &[Vec<String>],
    ) -> bool {
        if let Some(t) = self.item_type {
            if item.item_type != t {
                return false;
            }
        }
        if let Some(ref want) = self.folder {
            let hay = folder_name.unwrap_or("");
            if !hay.eq_ignore_ascii_case(want) && item.folder_id.as_deref() != Some(want.as_str()) {
                return false;
            }
        }
        if let Some(ref want) = self.name {
            if !item.name.to_lowercase().contains(&want.to_lowercase()) {
                return false;
            }
        }
        if let Some(fav) = self.favorite {
            if item.favorite != fav {
                return false;
            }
        }
        if let Some(ref target) = self.url {
            let uris: Vec<&str> = item.uris.iter().map(|u| u.uri.as_str()).collect();
            let types: Vec<Option<i32>> = item.uris.iter().map(|u| u.match_type).collect();
            if !item_matches_uri(&uris, &types, target, equivalent_domains) {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_operators() {
        let p = parse_search_query("type:login folder:work github");
        assert_eq!(p.item_type, Some(ItemType::Login));
        assert_eq!(p.folder.as_deref(), Some("work"));
        assert_eq!(p.free_text, "github");
    }

    #[test]
    fn parses_url_operator() {
        let p = parse_search_query("url:github.com");
        assert_eq!(p.url.as_deref(), Some("github.com"));
    }
}
