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
    /// Remember-device token returned after successful 2FA when requested.
    #[serde(default, rename = "TwoFactorToken")]
    pub two_factor_token: Option<String>,
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
    pub sends: Vec<Send>,
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
    /// Membership role: 0 owner, 1 admin, 2 user, 3 manager (legacy), 4 custom.
    #[serde(default, rename = "type")]
    pub org_type: Option<u8>,
    /// Membership status: 0 invited, 1 accepted, 2 confirmed.
    #[serde(default)]
    pub status: Option<u8>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub permissions: Option<OrgPermissions>,
    #[serde(default)]
    pub use_policies: Option<bool>,
}

/// Collection-related slice of the profile's organization permissions (custom roles).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgPermissions {
    #[serde(default)]
    pub edit_any_collection: bool,
    #[serde(default)]
    pub delete_any_collection: bool,
    #[serde(default)]
    pub create_new_collections: bool,
    #[serde(default)]
    pub edit_assigned_collections: bool,
    #[serde(default)]
    pub delete_assigned_collections: bool,
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
    /// Current user may only view items in this collection.
    #[serde(default)]
    pub read_only: bool,
    /// Passwords are hidden from the current user in this collection.
    #[serde(default)]
    pub hide_passwords: bool,
    /// Current user may manage the collection (newer servers only).
    #[serde(default)]
    pub manage: Option<bool>,
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
    pub attachments: Option<Vec<CipherAttachment>>,
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

impl Cipher {
    /// Server-provided `edit` permission flag (defaults to `true` when absent).
    pub fn server_can_edit(&self) -> Option<bool> {
        self.extra.get("edit").and_then(|v| v.as_bool())
    }

    /// Server-provided `viewPassword` flag (defaults to `true` when absent).
    pub fn view_password(&self) -> bool {
        self.extra
            .get("viewPassword")
            .and_then(|v| v.as_bool())
            .unwrap_or(true)
    }

    /// RFC 3339 archive timestamp when the cipher is archived (`archivedDate`).
    pub fn archived_date(&self) -> Option<&str> {
        self.extra
            .get("archivedDate")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
    }

    pub fn is_archived(&self) -> bool {
        self.archived_date().is_some()
    }
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

#[derive(Debug, Clone, Serialize, Default)]
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
    pub attachments: Option<Vec<CipherAttachment>>,
    /// Re-keyed attachment metadata (id → fileName/key), used when sharing to an org.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachments2:
        Option<std::collections::BTreeMap<String, crate::org_models::AttachmentRekey>>,
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

/// Self-service master password change (legacy Bitwarden payload).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangePasswordRequest {
    pub master_password_hash: String,
    pub new_master_password_hash: String,
    #[serde(rename = "key")]
    pub user_key_encrypted: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub master_password_hint: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum SendType {
    Text = 0,
    File = 1,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Send {
    pub id: Option<String>,
    #[serde(rename = "type")]
    pub send_type: u8,
    #[serde(default)]
    pub access_id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub max_access_count: Option<u32>,
    #[serde(default)]
    pub access_count: Option<u32>,
    #[serde(default)]
    pub text: Option<SendText>,
    #[serde(default)]
    pub file: Option<SendFile>,
    #[serde(default)]
    pub deletion_date: Option<String>,
    #[serde(default)]
    pub expiration_date: Option<String>,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub hide_email: bool,
    #[serde(flatten, default)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SendText {
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub hidden: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SendFile {
    #[serde(default)]
    pub id: Option<String>,
    /// File size in bytes (server may send a number or a numeric string).
    #[serde(
        default,
        deserialize_with = "deserialize_size_opt",
        serialize_with = "serialize_size_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub size: Option<u64>,
    #[serde(default)]
    pub size_name: Option<String>,
    #[serde(default)]
    pub file_name: Option<String>,
    #[serde(default)]
    pub validated: bool,
}

fn deserialize_size_opt<'de, D>(d: D) -> std::result::Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum NumOrStr {
        Num(u64),
        Str(String),
    }
    Ok(match Option::<NumOrStr>::deserialize(d)? {
        Some(NumOrStr::Num(n)) => Some(n),
        Some(NumOrStr::Str(s)) => s.trim().parse().ok(),
        None => None,
    })
}

fn serialize_size_opt<S>(v: &Option<u64>, s: S) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match v {
        Some(n) => s.serialize_u64(*n),
        None => s.serialize_none(),
    }
}

/// `POST /sends/access/{accessId}` request body.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SendAccessRequest {
    /// Base64 PBKDF2 hash of the send password (never the plaintext).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

/// Public Send payload returned by `POST /sends/access/{accessId}`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SendAccessResponse {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(rename = "type")]
    pub send_type: u8,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub text: Option<SendText>,
    #[serde(default)]
    pub file: Option<SendFile>,
    #[serde(default)]
    pub expiration_date: Option<String>,
    #[serde(default)]
    pub creator_identifier: Option<String>,
}

/// `POST /sends/{id}/access/file/{fileId}` response.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendFileDownloadData {
    #[serde(default)]
    pub id: Option<String>,
    pub url: String,
}

/// `fileUploadType` values for `POST /sends/file/v2`.
pub const SEND_FILE_UPLOAD_DIRECT: u8 = 0;
pub const SEND_FILE_UPLOAD_AZURE: u8 = 1;

/// `POST /sends/file/v2` response.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendFileUploadDataResponse {
    #[serde(default)]
    pub file_upload_type: u8,
    #[serde(default)]
    pub url: String,
    pub send_response: SendResponse,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SendRequest {
    #[serde(rename = "type")]
    pub send_type: u8,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_access_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration_date: Option<String>,
    pub disabled: bool,
    pub hide_email: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<SendText>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<SendFile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deletion_date: Option<String>,
    /// Encrypted file length in bytes (required by `POST /sends/file/v2`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_length: Option<u64>,
}

pub type SendResponse = Send;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CipherAttachment {
    pub id: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub file_name: Option<String>,
    #[serde(default)]
    pub size: Option<String>,
    #[serde(default)]
    pub size_name: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(flatten, default)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[cfg(test)]
mod send_tests {
    use super::*;

    #[test]
    fn send_file_size_accepts_number_or_string() {
        let n: SendFile =
            serde_json::from_str(r#"{"id":"f","size":123,"sizeName":"123 Bytes"}"#).unwrap();
        assert_eq!(n.size, Some(123));
        let s: SendFile = serde_json::from_str(r#"{"id":"f","size":"456"}"#).unwrap();
        assert_eq!(s.size, Some(456));
        let none: SendFile = serde_json::from_str(r#"{"id":"f"}"#).unwrap();
        assert_eq!(none.size, None);
        let out = serde_json::to_value(&n).unwrap();
        assert_eq!(out["size"], 123);
    }

    #[test]
    fn send_access_response_parses() {
        let r: SendAccessResponse = serde_json::from_str(
            r#"{"id":"sid","type":1,"name":"2.a|b|c","file":{"id":"fid","fileName":"2.x|y|z","size":"10","sizeName":"10 Bytes"},"creatorIdentifier":"a@b.c","object":"send-access"}"#,
        )
        .unwrap();
        assert_eq!(r.send_type, 1);
        assert_eq!(r.file.unwrap().id.as_deref(), Some("fid"));
        assert_eq!(r.creator_identifier.as_deref(), Some("a@b.c"));
    }

    #[test]
    fn send_request_serializes_file_length_and_password() {
        let req = SendRequest {
            send_type: 1,
            name: "n".into(),
            notes: None,
            key: Some("k".into()),
            password: Some("hash".into()),
            max_access_count: Some(3),
            expiration_date: None,
            disabled: false,
            hide_email: true,
            text: None,
            file: Some(SendFile {
                file_name: Some("enc".into()),
                size: Some(9),
                ..Default::default()
            }),
            deletion_date: Some("2030-01-01T00:00:00.000Z".into()),
            file_length: Some(9),
        };
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(v["fileLength"], 9);
        assert_eq!(v["maxAccessCount"], 3);
        assert_eq!(v["hideEmail"], true);
        assert_eq!(v["file"]["size"], 9);
        assert!(v.get("text").is_none());
    }
}
