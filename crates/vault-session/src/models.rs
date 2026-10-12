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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecryptedFieldType {
    Text,
    Hidden,
    Boolean,
    Linked,
    Unknown(u8),
}

impl DecryptedFieldType {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Text,
            1 => Self::Hidden,
            2 => Self::Boolean,
            3 => Self::Linked,
            other => Self::Unknown(other),
        }
    }

    pub fn as_u8(self) -> u8 {
        match self {
            Self::Text => 0,
            Self::Hidden => 1,
            Self::Boolean => 2,
            Self::Linked => 3,
            Self::Unknown(v) => v,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DecryptedField {
    pub name: String,
    pub value: String,
    pub field_type: DecryptedFieldType,
    pub linked_id: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct DecryptedPasswordHistory {
    pub password: String,
    pub last_used_date: Option<String>,
}

/// Decrypted FIDO2 / passkey metadata (private key material is never exposed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptedPasskey {
    pub credential_id: Option<String>,
    pub rp_id: String,
    pub rp_name: Option<String>,
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
    pub discoverable: bool,
    pub creation_date: Option<String>,
}

impl DecryptedPasskey {
    /// Short single-line label, e.g. `example.com (alice)`.
    pub fn label(&self) -> String {
        match self
            .user_name
            .as_deref()
            .or(self.user_display_name.as_deref())
        {
            Some(u) if !u.is_empty() => format!("{} ({u})", self.rp_id),
            _ => self.rp_id.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DecryptedUri {
    pub uri: String,
    pub match_type: Option<i32>,
}

#[derive(Debug, Clone)]
pub struct DecryptedItem {
    pub id: String,
    pub name: String,
    pub item_type: ItemType,
    pub folder_id: Option<String>,
    pub organization_id: Option<String>,
    pub collection_ids: Vec<String>,
    pub favorite: bool,
    pub deleted: bool,
    pub reprompt: bool,
    pub notes: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub totp: Option<String>,
    pub uris: Vec<DecryptedUri>,
    pub custom_fields: Vec<DecryptedField>,
    pub password_history: Vec<DecryptedPasswordHistory>,
    /// FIDO2 credentials stored on a login (display only; preserved verbatim on edit).
    pub passkeys: Vec<DecryptedPasskey>,
    pub password_revision_date: Option<String>,
    pub creation_date: Option<String>,
    pub revision_date: Option<String>,
    pub cardholder_name: Option<String>,
    pub card_brand: Option<String>,
    pub card_number: Option<String>,
    pub card_exp_month: Option<String>,
    pub card_exp_year: Option<String>,
    pub card_code: Option<String>,
    pub identity_title: Option<String>,
    pub identity_first_name: Option<String>,
    pub identity_middle_name: Option<String>,
    pub identity_last_name: Option<String>,
    pub identity_email: Option<String>,
    pub identity_phone: Option<String>,
    pub identity_username: Option<String>,
    pub identity_address1: Option<String>,
    pub identity_address2: Option<String>,
    pub identity_address3: Option<String>,
    pub identity_city: Option<String>,
    pub identity_state: Option<String>,
    pub identity_postal_code: Option<String>,
    pub identity_country: Option<String>,
    pub identity_company: Option<String>,
    pub identity_ssn: Option<String>,
    pub identity_passport_number: Option<String>,
    pub identity_license_number: Option<String>,
    pub ssh_private_key: Option<String>,
    pub ssh_public_key: Option<String>,
    pub ssh_fingerprint: Option<String>,
    /// Encrypted item-level key present → edits must use that key.
    pub has_item_key: bool,
}

impl DecryptedItem {
    pub fn primary_uri(&self) -> Option<&str> {
        self.uris.first().map(|u| u.uri.as_str())
    }

    pub fn uri_strings(&self) -> impl Iterator<Item = &str> {
        self.uris.iter().map(|u| u.uri.as_str())
    }

    pub fn uri_match_types(&self) -> impl Iterator<Item = Option<i32>> + '_ {
        self.uris.iter().map(|u| u.match_type)
    }

    /// Warnings shown to the user when cloning this item (data that a clone cannot carry over).
    pub fn clone_warnings(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !self.passkeys.is_empty() {
            out.push(format!(
                "{} passkey(s) are not copied — register new passkeys for the clone",
                self.passkeys.len()
            ));
        }
        out
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

#[derive(Debug, Clone)]
pub struct DecryptedOrganization {
    pub id: String,
    pub name: String,
    /// Membership role: 0 owner, 1 admin, 2 user, 3 manager (legacy), 4 custom.
    pub org_type: Option<u8>,
    /// Membership status: 0 invited, 1 accepted, 2 confirmed.
    pub status: Option<u8>,
    pub enabled: bool,
    /// Custom-role permission: may edit any collection in the org.
    pub edit_any_collection: bool,
    /// Custom-role permission: may create collections.
    pub create_new_collections: bool,
}

impl DecryptedOrganization {
    /// Owner or admin.
    pub fn is_admin(&self) -> bool {
        matches!(self.org_type, Some(0) | Some(1))
    }

    /// Membership is confirmed (or unknown on older servers) and the org is enabled.
    pub fn is_usable(&self) -> bool {
        self.enabled && self.status.is_none_or(|s| s == 2)
    }

    /// May write to collections the member is not explicitly assigned to.
    pub fn can_edit_any_collection(&self) -> bool {
        self.is_admin() || self.edit_any_collection
    }
}

#[derive(Debug, Clone)]
pub struct DecryptedCollection {
    pub id: String,
    pub name: String,
    pub organization_id: Option<String>,
    /// Current user may only view items in this collection.
    pub read_only: bool,
    /// Passwords are hidden from the current user in this collection.
    pub hide_passwords: bool,
    /// Current user may manage this collection (`None` on servers that do not report it).
    pub manage: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct DecryptedSend {
    pub id: String,
    pub access_id: Option<String>,
    pub name: String,
    pub notes: Option<String>,
    pub text: Option<String>,
    pub send_type: u8,
    pub disabled: bool,
    pub deletion_date: Option<String>,
    pub expiration_date: Option<String>,
    pub max_access_count: Option<u32>,
    pub access_count: u32,
    pub hide_email: bool,
    /// Text Send body is hidden by default on the receive page.
    pub text_hidden: bool,
    /// A password hash is stored server-side for this Send.
    pub has_password: bool,
    /// Decrypted file name (file Sends).
    pub file_name: Option<String>,
    /// Human-readable file size from the server (file Sends).
    pub file_size_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AttachmentInfo {
    pub id: String,
    pub file_name: String,
    pub size_name: Option<String>,
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
    /// Remember-this-device token for skipping 2FA on future logins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub two_factor_device_token: Option<String>,
}

impl PersistedAuth {
    pub fn to_kdf_params(&self) -> Option<vault_crypto::KdfParams> {
        let iterations = self.kdf_iterations?;
        Some(match self.kdf.unwrap_or(0) {
            1 => {
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
    pub organizations: Vec<DecryptedOrganization>,
    pub collections: Vec<DecryptedCollection>,
    pub sends: Vec<DecryptedSend>,
    pub org_keys: HashMap<String, vault_crypto::OrgKey>,
    /// Raw encrypted ciphers from last sync (for round-trip-safe updates).
    pub raw_ciphers: HashMap<String, vault_api::Cipher>,
    pub raw_sends: HashMap<String, vault_api::Send>,
}

/// Fields for creating/editing a login (plaintext, encrypted by session).
#[derive(Debug, Clone, Default)]
pub struct LoginDraft {
    pub name: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub totp: Option<String>,
    pub uris: Vec<DecryptedUri>,
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

#[derive(Debug, Clone, Default)]
pub struct CardDraft {
    pub name: String,
    pub cardholder_name: Option<String>,
    pub brand: Option<String>,
    pub number: Option<String>,
    pub exp_month: Option<String>,
    pub exp_year: Option<String>,
    pub code: Option<String>,
    pub notes: Option<String>,
    pub folder_id: Option<String>,
    pub favorite: bool,
    pub reprompt: bool,
}

#[derive(Debug, Clone, Default)]
pub struct IdentityDraft {
    pub name: String,
    pub title: Option<String>,
    pub first_name: Option<String>,
    pub middle_name: Option<String>,
    pub last_name: Option<String>,
    pub address1: Option<String>,
    pub address2: Option<String>,
    pub address3: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub postal_code: Option<String>,
    pub country: Option<String>,
    pub company: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub ssn: Option<String>,
    pub username: Option<String>,
    pub passport_number: Option<String>,
    pub license_number: Option<String>,
    pub notes: Option<String>,
    pub folder_id: Option<String>,
    pub favorite: bool,
    pub reprompt: bool,
}

#[derive(Debug, Clone, Default)]
pub struct SshKeyDraft {
    pub name: String,
    pub private_key: Option<String>,
    pub public_key: Option<String>,
    pub fingerprint: Option<String>,
    pub notes: Option<String>,
    pub folder_id: Option<String>,
    pub favorite: bool,
}
