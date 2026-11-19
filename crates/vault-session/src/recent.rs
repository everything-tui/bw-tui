//! Local encrypted cache of "last used" timestamps per vault item (never synced).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use vault_crypto::{decrypt_bytes, encrypt_bytes, UserKey};

use crate::error::{Result, SessionError};
use crate::paths::{ensure_dir, write_atomic};

const RECENT_FILE: &str = "recent.cache";
const RECENT_VERSION: u32 = 1;
/// Cap the stored map so the file cannot grow without bound.
pub const MAX_RECENT_ENTRIES: usize = 500;

#[derive(Debug, Serialize, Deserialize)]
struct RecentEnvelope {
    version: u32,
    /// EncString of the JSON `{ item_id: unix_seconds }` map, encrypted with the user key.
    ciphertext: String,
}

/// `item id -> unix seconds` of the last time a secret was copied / typed.
pub type RecentMap = HashMap<String, i64>;

pub fn recent_path(data_dir: &Path) -> PathBuf {
    data_dir.join(RECENT_FILE)
}

/// Remove the on-disk recent cache (e.g. on sign-out).
pub fn clear_recent(data_dir: &Path) {
    let _ = std::fs::remove_file(recent_path(data_dir));
}

/// Load and decrypt the map. Missing or undecryptable files yield an empty map.
pub fn load_recent(data_dir: &Path, user_key: &UserKey) -> RecentMap {
    let path = recent_path(data_dir);
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return RecentMap::new();
    };
    let Ok(env) = serde_json::from_str::<RecentEnvelope>(&raw) else {
        return RecentMap::new();
    };
    if env.version != RECENT_VERSION {
        return RecentMap::new();
    }
    let Ok(plain) = decrypt_bytes(&env.ciphertext, user_key) else {
        return RecentMap::new();
    };
    serde_json::from_slice(&plain).unwrap_or_default()
}

/// Encrypt and persist the map atomically (file mode 0600 on Unix).
pub fn save_recent(data_dir: &Path, user_key: &UserKey, map: &RecentMap) -> Result<()> {
    let mut pruned: Vec<(&String, &i64)> = map.iter().collect();
    pruned.sort_by(|a, b| b.1.cmp(a.1));
    pruned.truncate(MAX_RECENT_ENTRIES);
    let pruned: RecentMap = pruned.into_iter().map(|(k, v)| (k.clone(), *v)).collect();

    let json = serde_json::to_vec(&pruned).map_err(|e| SessionError::Other(e.to_string()))?;
    let ciphertext = encrypt_bytes(&json, user_key)?;
    let env = RecentEnvelope {
        version: RECENT_VERSION,
        ciphertext,
    };
    ensure_dir(data_dir)?;
    let path = recent_path(data_dir);
    let body = serde_json::to_string(&env).map_err(|e| SessionError::Other(e.to_string()))?;
    write_atomic(&path, body.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_crypto::generate_user_key;

    #[test]
    fn round_trip_encrypted() {
        let dir = tempfile::tempdir().unwrap();
        let key = generate_user_key();
        let mut map = RecentMap::new();
        map.insert("a".into(), 100);
        map.insert("b".into(), 200);
        save_recent(dir.path(), &key, &map).unwrap();
        let raw = std::fs::read_to_string(recent_path(dir.path())).unwrap();
        assert!(
            !raw.contains("\"a\""),
            "item ids must not be stored in plaintext"
        );
        assert_eq!(load_recent(dir.path(), &key), map);
    }

    #[test]
    fn wrong_key_yields_empty() {
        let dir = tempfile::tempdir().unwrap();
        let key = generate_user_key();
        let mut map = RecentMap::new();
        map.insert("a".into(), 1);
        save_recent(dir.path(), &key, &map).unwrap();
        let other = generate_user_key();
        assert!(load_recent(dir.path(), &other).is_empty());
    }
}
