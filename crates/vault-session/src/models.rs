use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemType {
    Login,
    SecureNote,
    Card,
    Identity,
    SshKey,
    Unknown,
}

impl ItemType {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Login,
            2 => Self::SecureNote,
            3 => Self::Card,
            4 => Self::Identity,
            5 => Self::SshKey,
            _ => Self::Unknown,
        }
    }

    pub fn as_u8(self) -> u8 {
        match self {
            Self::Login => 1,
            Self::SecureNote => 2,
            Self::Card => 3,
            Self::Identity => 4,
            Self::SshKey => 5,
            Self::Unknown => 1,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Login => "Login",
            Self::SecureNote => "Note",
            Self::Card => "Card",
            Self::Identity => "Identity",
            Self::SshKey => "SSH Key",
            Self::Unknown => "Item",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DecryptedItem {
    pub id: String,
    pub name: String,
    pub item_type: ItemType,
    pub folder_id: Option<String>,
    pub organization_id: Option<String>,
    pub favorite: bool,
    pub deleted: bool,
    pub reprompt: bool,
    pub notes: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub totp: Option<String>,
    pub uris: Vec<String>,
    pub cardholder_name: Option<String>,
    pub card_brand: Option<String>,
    pub card_number: Option<String>,
    pub card_exp_month: Option<String>,
    pub card_exp_year: Option<String>,
    pub card_code: Option<String>,
    pub identity_title: Option<String>,
    pub identity_first_name: Option<String>,
    pub identity_last_name: Option<String>,
    pub identity_email: Option<String>,
    pub identity_phone: Option<String>,
    pub identity_username: Option<String>,
    pub revision_date: Option<String>,
}

impl DecryptedItem {
    pub fn primary_uri(&self) -> Option<&str> {
        self.uris.first().map(String::as_str)
    }

    pub fn identity_name(&self) -> Option<String> {
        let first = self.identity_first_name.as_deref().unwrap_or("");
        let last = self.identity_last_name.as_deref().unwrap_or("");
        let combined = format!("{first} {last}").trim().to_string();
        if combined.is_empty() {
            None
        } else {
            Some(combined)
        }
    }

    pub fn subtitle(&self) -> String {
        match self.item_type {
            ItemType::Login => self
                .username
                .clone()
                .or_else(|| self.primary_uri().map(str::to_string))
                .unwrap_or_default(),
            ItemType::SecureNote => self
                .notes
                .as_deref()
                .and_then(|n| n.lines().next())
                .unwrap_or("")
                .chars()
                .take(48)
                .collect(),
            ItemType::Card => self
                .card_brand
                .clone()
                .or_else(|| self.card_number.clone())
                .unwrap_or_default(),
            ItemType::Identity => self.identity_name().unwrap_or_default(),
            _ => String::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DecryptedFolder {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedAuth {
    pub server_url: String,
    pub email: String,
    /// Present only for disk fallback / legacy files. Prefer OS secure storage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    pub device_id: String,
    pub protected_key: Option<String>,
    pub private_key: Option<String>,
}

#[derive(Clone, Default)]
pub struct VaultIndex {
    pub folders: Vec<DecryptedFolder>,
    pub items: Vec<DecryptedItem>,
    pub org_keys: HashMap<String, vault_crypto::OrgKey>,
}

/// Fields for creating/editing a login (plaintext, encrypted by session).
#[derive(Debug, Clone, Default)]
pub struct LoginDraft {
    pub name: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub totp: Option<String>,
    pub uri: Option<String>,
    pub notes: Option<String>,
    pub folder_id: Option<String>,
    pub favorite: bool,
    pub reprompt: bool,
}

#[derive(Debug, Clone, Default)]
pub struct NoteDraft {
    pub name: String,
    pub notes: Option<String>,
    pub folder_id: Option<String>,
    pub favorite: bool,
}
