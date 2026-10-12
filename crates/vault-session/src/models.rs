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

    pub fn as_u8(self) -> Option<u8> {
        match self {
            Self::Login => Some(1),
            Self::SecureNote => Some(2),
            Self::Card => Some(3),
            Self::Identity => Some(4),
            Self::SshKey => Some(5),
            Self::Unknown => None,
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
    pub ssh_private_key: Option<String>,
    pub ssh_public_key: Option<String>,
    pub ssh_fingerprint: Option<String>,
    pub revision_date: Option<String>,
    /// Encrypted item-level key present → edits must use that key.
    pub has_item_key: bool,
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
    /// Cached prelogin KDF type (0 = PBKDF2, 1 = Argon2id) for offline unlock.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kdf: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kdf_iterations: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kdf_memory: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kdf_parallelism: Option<u32>,
}

impl PersistedAuth {
    pub fn to_kdf_params(&self) -> Option<vault_crypto::KdfParams> {
        let iterations = self.kdf_iterations?;
        Some(match self.kdf.unwrap_or(0) {
            1 => {
                // Persist/load as MiB. Migrate legacy KiB values (>1024).
                let raw = self
                    .kdf_memory
                    .unwrap_or(vault_crypto::ARGON2_DEFAULT_MEMORY_MIB);
                vault_crypto::KdfParams::Argon2id {
                    iterations,
                    memory_mib: vault_crypto::KdfParams::migrate_memory_mib(raw),
                    parallelism: self
                        .kdf_parallelism
                        .unwrap_or(vault_crypto::ARGON2_DEFAULT_PARALLELISM),
                }
            }
            _ => vault_crypto::KdfParams::Pbkdf2 { iterations },
        })
    }

    pub fn set_kdf_from_params(&mut self, kdf: &vault_crypto::KdfParams) {
        match kdf {
            vault_crypto::KdfParams::Pbkdf2 { iterations } => {
                self.kdf = Some(0);
                self.kdf_iterations = Some(*iterations);
                self.kdf_memory = None;
                self.kdf_parallelism = None;
            }
            vault_crypto::KdfParams::Argon2id {
                iterations,
                memory_mib,
                parallelism,
            } => {
                self.kdf = Some(1);
                self.kdf_iterations = Some(*iterations);
                // Store MiB (API unit).
                self.kdf_memory = Some(*memory_mib);
                self.kdf_parallelism = Some(*parallelism);
            }
        }
    }
}

#[derive(Clone, Default)]
pub struct VaultIndex {
    pub folders: Vec<DecryptedFolder>,
    pub items: Vec<DecryptedItem>,
    pub org_keys: HashMap<String, vault_crypto::OrgKey>,
    /// Raw encrypted ciphers from last sync (for round-trip-safe updates).
    pub raw_ciphers: HashMap<String, vault_api::Cipher>,
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
