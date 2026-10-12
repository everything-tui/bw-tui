//! Encrypted on-disk cache of the last successful vault sync.

use std::path::{Path, PathBuf};

use chrono::{DateTime, FixedOffset, Local};
use serde::{Deserialize, Serialize};
use vault_api::SyncResponse;
use vault_crypto::{decrypt_bytes, encrypt_bytes, UserKey};

use crate::error::{Result, SessionError};

const CACHE_VERSION: u32 = 1;
const CACHE_FILE: &str = "vault.cache";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultCacheEnvelope {
    pub version: u32,
    /// RFC3339 timestamp of the sync that produced this cache.
    pub synced_at: String,
    /// EncString of the serialized [`SyncResponse`], encrypted with the user key.
    pub ciphertext: String,
}

pub fn cache_path(data_dir: &Path) -> PathBuf {
    data_dir.join(CACHE_FILE)
}

pub fn exists(data_dir: &Path) -> bool {
    cache_path(data_dir).is_file()
}

pub fn clear(data_dir: &Path) {
    let _ = std::fs::remove_file(cache_path(data_dir));
}

/// Encrypt and write the sync payload. Returns the synced_at timestamp used.
pub fn save(data_dir: &Path, sync: &SyncResponse, user_key: &UserKey) -> Result<DateTime<FixedOffset>> {
    let synced_at = Local::now().fixed_offset();
    let json = serde_json::to_vec(sync).map_err(|e| SessionError::Other(e.to_string()))?;
    let ciphertext = encrypt_bytes(&json, user_key)?;
    let envelope = VaultCacheEnvelope {
        version: CACHE_VERSION,
        synced_at: synced_at.to_rfc3339(),
        ciphertext,
    };
    let _ = std::fs::create_dir_all(data_dir);
    let path = cache_path(data_dir);
    let body =
        serde_json::to_string_pretty(&envelope).map_err(|e| SessionError::Other(e.to_string()))?;
    std::fs::write(path, body)?;
    Ok(synced_at)
}

/// Load envelope metadata without decrypting.
pub fn load_envelope(data_dir: &Path) -> Result<Option<VaultCacheEnvelope>> {
    let path = cache_path(data_dir);
    if !path.is_file() {
        return Ok(None);
    }
    let json = std::fs::read_to_string(&path)?;
    let envelope: VaultCacheEnvelope =
        serde_json::from_str(&json).map_err(|e| SessionError::Other(e.to_string()))?;
    if envelope.version != CACHE_VERSION {
        return Err(SessionError::Other(format!(
            "unsupported vault cache version {}",
            envelope.version
        )));
    }
    Ok(Some(envelope))
}

pub fn synced_at(data_dir: &Path) -> Option<DateTime<FixedOffset>> {
    let envelope = load_envelope(data_dir).ok().flatten()?;
    DateTime::parse_from_rfc3339(&envelope.synced_at).ok()
}

/// Decrypt the cached sync response with the user key.
pub fn load(data_dir: &Path, user_key: &UserKey) -> Result<(SyncResponse, DateTime<FixedOffset>)> {
    let envelope = load_envelope(data_dir)?
        .ok_or_else(|| SessionError::Other("No offline vault cache".into()))?;
    let synced_at = DateTime::parse_from_rfc3339(&envelope.synced_at)
        .map_err(|e| SessionError::Other(format!("invalid cache synced_at: {e}")))?;
    let plain = decrypt_bytes(&envelope.ciphertext, user_key)?;
    let sync: SyncResponse =
        serde_json::from_slice(&plain).map_err(|e| SessionError::Other(e.to_string()))?;
    Ok((sync, synced_at))
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_api::{Cipher, Folder, Profile};
    use vault_crypto::generate_user_key;

    fn sample_sync() -> SyncResponse {
        SyncResponse {
            profile: Some(Profile {
                id: "user-1".into(),
                email: Some("a@b.c".into()),
                name: Some("Test".into()),
                key: None,
                private_key: None,
                organizations: vec![],
                security_stamp: None,
            }),
            folders: vec![Folder {
                id: Some("f1".into()),
                name: "2.placeholder".into(),
                revision_date: None,
                object: None,
            }],
            collections: vec![],
            ciphers: vec![Cipher {
                id: Some("c1".into()),
                folder_id: None,
                organization_id: None,
                name: "2.placeholder".into(),
                notes: None,
                cipher_type: 1,
                favorite: false,
                deleted_date: None,
                reprompt: None,
                key: None,
                login: None,
                secure_note: None,
                card: None,
                identity: None,
                fields: None,
                password_history: None,
                attachments: None,
                organization_use_totp: None,
                revision_date: None,
                creation_date: None,
                collection_ids: None,
                object: None,
            }],
            sends: vec![],
            policies: vec![],
            domains: None,
        }
    }

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let dir = tempfile::tempdir().unwrap();
        let key = generate_user_key();
        let sync = sample_sync();
        save(dir.path(), &sync, &key).unwrap();
        assert!(exists(dir.path()));
        let (loaded, _) = load(dir.path(), &key).unwrap();
        assert_eq!(loaded.profile.as_ref().unwrap().id, "user-1");
        assert_eq!(loaded.ciphers.len(), 1);
        assert_eq!(loaded.folders.len(), 1);
    }

    #[test]
    fn wrong_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let key = generate_user_key();
        let other = generate_user_key();
        save(dir.path(), &sample_sync(), &key).unwrap();
        assert!(load(dir.path(), &other).is_err());
    }

    #[test]
    fn clear_removes_file() {
        let dir = tempfile::tempdir().unwrap();
        let key = generate_user_key();
        save(dir.path(), &sample_sync(), &key).unwrap();
        clear(dir.path());
        assert!(!exists(dir.path()));
        assert!(load(dir.path(), &key).is_err());
    }

    #[test]
    fn envelope_not_plaintext_sync() {
        let dir = tempfile::tempdir().unwrap();
        let key = generate_user_key();
        save(dir.path(), &sample_sync(), &key).unwrap();
        let raw = std::fs::read_to_string(cache_path(dir.path())).unwrap();
        assert!(!raw.contains("user-1"));
        assert!(!raw.contains("\"ciphers\""));
        assert!(raw.contains("ciphertext"));
    }
}
