//! Encrypted on-disk cache of the last successful vault sync.

use std::path::{Path, PathBuf};

use chrono::{DateTime, FixedOffset, Local};
use serde::{Deserialize, Serialize};
use vault_api::SyncResponse;
use vault_crypto::{decrypt_bytes, encrypt_bytes, UserKey};
use zeroize::Zeroizing;

use crate::error::{Result, SessionError};
use crate::paths::{ensure_dir, write_atomic};

const CACHE_VERSION: u32 = 2;
const CACHE_VERSION_LEGACY: u32 = 1;
const PAYLOAD_VERSION: u32 = 1;
const CACHE_FILE: &str = "vault.cache";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultCacheEnvelope {
    pub version: u32,
    /// RFC3339 timestamp of the sync that produced this cache.
    pub synced_at: String,
    /// EncString of the serialized inner payload, encrypted with the user key.
    pub ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VaultCachePayload {
    version: u32,
    user_id: String,
    sync: SyncResponse,
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
pub fn save(
    data_dir: &Path,
    sync: &SyncResponse,
    user_key: &UserKey,
    user_id: &str,
) -> Result<DateTime<FixedOffset>> {
    let synced_at = Local::now().fixed_offset();
    let payload = VaultCachePayload {
        version: PAYLOAD_VERSION,
        user_id: user_id.to_string(),
        sync: sync.clone(),
    };
    let json = serde_json::to_vec(&payload).map_err(|e| SessionError::Other(e.to_string()))?;
    let ciphertext = encrypt_bytes(&json, user_key)?;
    let envelope = VaultCacheEnvelope {
        version: CACHE_VERSION,
        synced_at: synced_at.to_rfc3339(),
        ciphertext,
    };
    ensure_dir(data_dir)?;
    let path = cache_path(data_dir);
    let body =
        serde_json::to_string_pretty(&envelope).map_err(|e| SessionError::Other(e.to_string()))?;
    write_atomic(&path, body.as_bytes())?;
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
    if envelope.version != CACHE_VERSION && envelope.version != CACHE_VERSION_LEGACY {
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

fn decrypt_payload(
    envelope: &VaultCacheEnvelope,
    user_key: &UserKey,
    expected_user_id: Option<&str>,
) -> Result<SyncResponse> {
    let plain = Zeroizing::new(decrypt_bytes(&envelope.ciphertext, user_key)?);
    match envelope.version {
        CACHE_VERSION_LEGACY => {
            let sync: SyncResponse =
                serde_json::from_slice(&plain).map_err(|e| SessionError::Other(e.to_string()))?;
            Ok(sync)
        }
        CACHE_VERSION => {
            let payload: VaultCachePayload =
                serde_json::from_slice(&plain).map_err(|e| SessionError::Other(e.to_string()))?;
            if payload.version != PAYLOAD_VERSION {
                return Err(SessionError::Other(format!(
                    "unsupported vault cache payload version {}",
                    payload.version
                )));
            }
            if let Some(expected) = expected_user_id {
                if payload.user_id != expected {
                    return Err(SessionError::Other(
                        "vault cache user id does not match session".into(),
                    ));
                }
            }
            Ok(payload.sync)
        }
        other => Err(SessionError::Other(format!(
            "unsupported vault cache version {other}"
        ))),
    }
}

/// Decrypt the cached sync response with the user key.
pub fn load(
    data_dir: &Path,
    user_key: &UserKey,
    expected_user_id: Option<&str>,
) -> Result<(SyncResponse, DateTime<FixedOffset>)> {
    let envelope = load_envelope(data_dir)?
        .ok_or_else(|| SessionError::Other("No offline vault cache".into()))?;
    let synced_at = DateTime::parse_from_rfc3339(&envelope.synced_at)
        .map_err(|e| SessionError::Other(format!("invalid cache synced_at: {e}")))?;
    let sync = decrypt_payload(&envelope, user_key, expected_user_id)?;
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
                ssh_key: None,
                extra: Default::default(),
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
        save(dir.path(), &sync, &key, "user-1").unwrap();
        assert!(exists(dir.path()));
        let (loaded, _) = load(dir.path(), &key, Some("user-1")).unwrap();
        assert_eq!(loaded.profile.as_ref().unwrap().id, "user-1");
        assert_eq!(loaded.ciphers.len(), 1);
        assert_eq!(loaded.folders.len(), 1);
    }

    #[test]
    fn user_id_mismatch_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let key = generate_user_key();
        save(dir.path(), &sample_sync(), &key, "user-1").unwrap();
        assert!(load(dir.path(), &key, Some("other-user")).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let key = generate_user_key();
        let other = generate_user_key();
        save(dir.path(), &sample_sync(), &key, "user-1").unwrap();
        assert!(load(dir.path(), &other, None).is_err());
    }

    #[test]
    fn clear_removes_file() {
        let dir = tempfile::tempdir().unwrap();
        let key = generate_user_key();
        save(dir.path(), &sample_sync(), &key, "user-1").unwrap();
        clear(dir.path());
        assert!(!exists(dir.path()));
        assert!(load(dir.path(), &key, None).is_err());
    }

    #[test]
    fn envelope_not_plaintext_sync() {
        let dir = tempfile::tempdir().unwrap();
        let key = generate_user_key();
        save(dir.path(), &sample_sync(), &key, "user-1").unwrap();
        let raw = std::fs::read_to_string(cache_path(dir.path())).unwrap();
        assert!(!raw.contains("user-1"));
        assert!(!raw.contains("\"ciphers\""));
        assert!(raw.contains("ciphertext"));
    }
}
