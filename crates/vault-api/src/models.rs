use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerConfig {
    pub version: Option<String>,
    pub environment: Option<EnvironmentUrls>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvironmentUrls {
    pub vault: Option<String>,
    pub api: Option<String>,
    pub identity: Option<String>,
    pub notifications: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreloginResponse {
    #[serde(alias = "kdf", alias = "Kdf")]
    pub kdf: u8,
    #[serde(alias = "kdfIterations", alias = "KdfIterations")]
    pub kdf_iterations: u32,
    #[serde(default, alias = "kdfMemory", alias = "KdfMemory")]
    pub kdf_memory: Option<u32>,
    #[serde(default, alias = "kdfParallelism", alias = "KdfParallelism")]
    pub kdf_parallelism: Option<u32>,
}

impl PreloginResponse {
    /// Convert prelogin KDF fields to crypto params.
    ///
    /// Server `kdfMemory` is in **MiB** (Bitwarden API). Defaults match the
    /// official clients: Argon2id 3 / 64 MiB / 4.
    pub fn to_kdf_params(&self) -> vault_crypto::KdfParams {
        match self.kdf {
            1 => vault_crypto::KdfParams::Argon2id {
                iterations: self.kdf_iterations,
                memory_mib: self
                    .kdf_memory
                    .unwrap_or(vault_crypto::ARGON2_DEFAULT_MEMORY_MIB),
                parallelism: self
                    .kdf_parallelism
                    .unwrap_or(vault_crypto::ARGON2_DEFAULT_PARALLELISM),
            },
            _ => vault_crypto::KdfParams::Pbkdf2 {
                iterations: self.kdf_iterations,
            },
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: Option<u64>,
    pub token_type: Option<String>,
    #[serde(default, rename = "Key")]
    pub key: Option<String>,
    #[serde(default, rename = "PrivateKey")]
    pub private_key: Option<String>,
    #[serde(default, rename = "Kdf")]
    pub kdf: Option<u8>,
    #[serde(default, rename = "KdfIterations")]
    pub kdf_iterations: Option<u32>,
    #[serde(default, rename = "KdfMemory")]
    pub kdf_memory: Option<u32>,
    #[serde(default, rename = "KdfParallelism")]
    pub kdf_parallelism: Option<u32>,
    #[serde(default, rename = "ResetMasterPassword")]
    pub reset_master_password: Option<bool>,
    #[serde(default, rename = "UserDecryptionOptions")]
    pub user_decryption_options: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum CipherType {
    Login = 1,
    SecureNote = 2,
    Card = 3,
    Identity = 4,
    SshKey = 5,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncResponse {
    pub profile: Option<Profile>,
    #[serde(default)]
    pub folders: Vec<Folder>,
    #[serde(default)]
    pub collections: Vec<Collection>,
    #[serde(default)]
    pub ciphers: Vec<Cipher>,
    #[serde(default)]
    pub sends: Vec<serde_json::Value>,
    #[serde(default)]
    pub policies: Vec<serde_json::Value>,
    #[serde(default)]
    pub domains: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    pub id: String,
    pub email: Option<String>,
    pub name: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub private_key: Option<String>,
    #[serde(default)]
    pub organizations: Vec<Organization>,
    #[serde(default)]
    pub security_stamp: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Organization {
    pub id: String,
    pub name: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Folder {
    pub id: Option<String>,
    pub name: String,
    #[serde(default)]
    pub revision_date: Option<String>,
    #[serde(default)]
    pub object: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Collection {
    pub id: Option<String>,
    pub organization_id: Option<String>,
    pub name: String,
    #[serde(default)]
    pub object: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Cipher {
    pub id: Option<String>,
    #[serde(default)]
    pub organization_id: Option<String>,
    #[serde(default)]
    pub folder_id: Option<String>,
    #[serde(rename = "type")]
    pub cipher_type: u8,
    pub name: String,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub reprompt: Option<u8>,
    #[serde(default)]
    pub login: Option<CipherLogin>,
    #[serde(default)]
    pub secure_note: Option<CipherSecureNote>,
    #[serde(default)]
    pub card: Option<CipherCard>,
    #[serde(default)]
    pub identity: Option<CipherIdentity>,
    #[serde(default)]
    pub fields: Option<Vec<CipherField>>,
    #[serde(default)]
    pub password_history: Option<Vec<PasswordHistoryEntry>>,
    #[serde(default)]
    pub attachments: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    pub organization_use_totp: Option<bool>,
    #[serde(default)]
    pub revision_date: Option<String>,
    #[serde(default)]
    pub creation_date: Option<String>,
    #[serde(default)]
    pub deleted_date: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub collection_ids: Option<Vec<String>>,
    #[serde(default)]
    pub object: Option<String>,
    #[serde(default)]
    pub ssh_key: Option<CipherSshKey>,
    /// Preserve unknown server fields across deserialize → re-serialize.
    #[serde(flatten, default)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CipherSshKey {
    #[serde(default)]
    pub private_key: Option<String>,
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(default)]
    pub key_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordHistoryEntry {
    pub password: String,
    #[serde(default)]
    pub last_used_date: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CipherLogin {
    #[serde(default)]
    pub uris: Option<Vec<LoginUri>>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub password_revision_date: Option<String>,
    #[serde(default)]
    pub totp: Option<String>,
    #[serde(default)]
    pub autofill_on_page_load: Option<bool>,
    #[serde(default)]
    pub fido2_credentials: Option<Vec<serde_json::Value>>,
    #[serde(flatten, default)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginUri {
    #[serde(default)]
    pub uri: Option<String>,
    #[serde(default, rename = "match")]
    pub match_type: Option<i32>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CipherSecureNote {
    #[serde(default, rename = "type")]
    pub note_type: Option<u8>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CipherCard {
    #[serde(default)]
    pub cardholder_name: Option<String>,
    #[serde(default)]
    pub brand: Option<String>,
    #[serde(default)]
    pub number: Option<String>,
    #[serde(default)]
    pub exp_month: Option<String>,
    #[serde(default)]
    pub exp_year: Option<String>,
    #[serde(default)]
    pub code: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CipherIdentity {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub first_name: Option<String>,
    #[serde(default)]
    pub middle_name: Option<String>,
    #[serde(default)]
    pub last_name: Option<String>,
    #[serde(default)]
    pub address1: Option<String>,
    #[serde(default)]
    pub address2: Option<String>,
    #[serde(default)]
    pub address3: Option<String>,
    #[serde(default)]
    pub city: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub postal_code: Option<String>,
    #[serde(default)]
    pub country: Option<String>,
    #[serde(default)]
    pub company: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub phone: Option<String>,
    #[serde(default)]
    pub ssn: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub passport_number: Option<String>,
    #[serde(default)]
    pub license_number: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CipherField {
    #[serde(rename = "type")]
    pub field_type: u8,
    pub name: Option<String>,
    pub value: Option<String>,
    #[serde(default)]
    pub linked_id: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CipherRequest {
    #[serde(rename = "type")]
    pub cipher_type: u8,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub folder_id: Option<String>,
    pub favorite: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reprompt: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login: Option<CipherLogin>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secure_note: Option<CipherSecureNote>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card: Option<CipherCard>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<CipherIdentity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<Vec<CipherField>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_history: Option<Vec<PasswordHistoryEntry>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachments: Option<Vec<serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collection_ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_key: Option<CipherSshKey>,
    /// Required by Vaultwarden ≥1.34 / Bitwarden web-v2025.6.0
    pub encrypted_for: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_known_revision_date: Option<String>,
}

/// Minimal body for `PUT /api/ciphers/{id}/partial` (favorite / folder only).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CipherPartialRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub folder_id: Option<String>,
    pub favorite: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderRequest {
    pub name: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterRequest {
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub master_password_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub master_password_hint: Option<String>,
    #[serde(rename = "userSymmetricKey")]
    pub key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf_iterations: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf_memory: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf_parallelism: Option<u32>,
    #[serde(rename = "userAsymmetricKeys", skip_serializing_if = "Option::is_none")]
    pub keys: Option<RegisterKeys>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verification_token: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterSendEmailRequest {
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterKeys {
    pub public_key: String,
    pub encrypted_private_key: String,
}
