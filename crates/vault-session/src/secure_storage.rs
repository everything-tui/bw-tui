//! OS secure storage for refresh tokens (Bitwarden TokenService-style).

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};

use keyring::Entry;
use tracing::warn;

const SERVICE_NAME: &str = "com.bitwarden-tui.bitwarden-tui";

/// Abstraction over where refresh tokens are stored (OS keyring or test double).
pub trait RefreshTokenStore: Send + Sync {
    fn set(&self, profile_id: &str, token: &str) -> Result<(), String>;
    fn get(&self, profile_id: &str) -> Result<Option<String>, String>;
    fn delete(&self, profile_id: &str) -> Result<(), String>;
}

/// macOS Keychain / Windows Credential Manager / Linux Secret Service.
pub struct OsKeyringStore;

impl OsKeyringStore {
    fn entry(profile_id: &str) -> Result<Entry, String> {
        Entry::new(SERVICE_NAME, &account_key(profile_id)).map_err(|e| e.to_string())
    }
}

impl RefreshTokenStore for OsKeyringStore {
    fn set(&self, profile_id: &str, token: &str) -> Result<(), String> {
        self::OsKeyringStore::entry(profile_id)?
            .set_password(token)
            .map_err(|e| e.to_string())
    }

    fn get(&self, profile_id: &str) -> Result<Option<String>, String> {
        match self::OsKeyringStore::entry(profile_id)?.get_password() {
            Ok(t) => Ok(Some(t)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    fn delete(&self, profile_id: &str) -> Result<(), String> {
        match self::OsKeyringStore::entry(profile_id)?.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }
}

/// In-memory store for unit tests.
#[derive(Default)]
pub struct MemoryRefreshTokenStore {
    inner: Mutex<HashMap<String, String>>,
}

impl MemoryRefreshTokenStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl RefreshTokenStore for MemoryRefreshTokenStore {
    fn set(&self, profile_id: &str, token: &str) -> Result<(), String> {
        self.inner
            .lock()
            .map_err(|e| e.to_string())?
            .insert(profile_id.to_string(), token.to_string());
        Ok(())
    }

    fn get(&self, profile_id: &str) -> Result<Option<String>, String> {
        Ok(self
            .inner
            .lock()
            .map_err(|e| e.to_string())?
            .get(profile_id)
            .cloned())
    }

    fn delete(&self, profile_id: &str) -> Result<(), String> {
        self.inner
            .lock()
            .map_err(|e| e.to_string())?
            .remove(profile_id);
        Ok(())
    }
}

/// Store that always fails (forces disk fallback in tests).
pub struct FailingRefreshTokenStore;

impl RefreshTokenStore for FailingRefreshTokenStore {
    fn set(&self, _profile_id: &str, _token: &str) -> Result<(), String> {
        Err("secure storage unavailable".into())
    }

    fn get(&self, _profile_id: &str) -> Result<Option<String>, String> {
        Err("secure storage unavailable".into())
    }

    fn delete(&self, _profile_id: &str) -> Result<(), String> {
        Err("secure storage unavailable".into())
    }
}

static OVERRIDE: RwLock<Option<Arc<dyn RefreshTokenStore>>> = RwLock::new(None);
/// Serializes tests that swap the global store.
static TEST_STORE_LOCK: Mutex<()> = Mutex::new(());

fn active_store() -> Arc<dyn RefreshTokenStore> {
    if let Ok(guard) = OVERRIDE.read() {
        if let Some(store) = guard.as_ref() {
            return Arc::clone(store);
        }
    }
    Arc::new(OsKeyringStore)
}

/// Install a custom store (tests). Pass `None` to restore the OS keyring.
pub fn set_refresh_token_store_for_tests(store: Option<Arc<dyn RefreshTokenStore>>) {
    if let Ok(mut guard) = OVERRIDE.write() {
        *guard = store;
    }
}

/// Run `f` with a temporary store override, holding an exclusive lock so parallel
/// tests do not race on the process-global override.
pub fn with_refresh_token_store_for_tests<R>(
    store: Arc<dyn RefreshTokenStore>,
    f: impl FnOnce() -> R + std::panic::UnwindSafe,
) -> R {
    let _lock = TEST_STORE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    set_refresh_token_store_for_tests(Some(store));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    set_refresh_token_store_for_tests(None);
    match result {
        Ok(v) => v,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

fn account_key(profile_id: &str) -> String {
    format!("{profile_id}_refreshToken")
}

/// Profile id is the last component of the profile data directory (`profiles/<id>`).
pub fn profile_id_from_data_dir(data_dir: &Path) -> Option<String> {
    data_dir
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

pub fn set_refresh_token(profile_id: &str, token: &str) -> Result<(), String> {
    active_store().set(profile_id, token)
}

pub fn get_refresh_token(profile_id: &str) -> Result<Option<String>, String> {
    active_store().get(profile_id)
}

pub fn delete_refresh_token(profile_id: &str) -> Result<(), String> {
    match active_store().delete(profile_id) {
        Ok(()) => Ok(()),
        Err(e) => {
            warn!(%profile_id, error = %e, "failed to delete refresh token from secure storage");
            Err(e)
        }
    }
}

/// Best-effort delete; ignores store errors (used on logout / clear).
pub fn delete_refresh_token_best_effort(profile_id: &str) {
    let _ = delete_refresh_token(profile_id);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_store_roundtrip() {
        let store = MemoryRefreshTokenStore::new();
        store.set("work", "tok").unwrap();
        assert_eq!(store.get("work").unwrap().as_deref(), Some("tok"));
        store.delete("work").unwrap();
        assert_eq!(store.get("work").unwrap(), None);
    }

    #[test]
    fn profile_id_from_dir() {
        assert_eq!(
            profile_id_from_data_dir(Path::new("/data/profiles/work")).as_deref(),
            Some("work")
        );
        assert_eq!(profile_id_from_data_dir(Path::new("/")).as_deref(), None);
    }
}
