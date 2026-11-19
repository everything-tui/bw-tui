//! PIN unlock: wrap the user key with a PIN-derived key (official-client style).
//!
//! The wrapped key is stored in the profile data dir (`pin.key`). After N failed
//! attempts the file is wiped and the user must unlock with the master password.

use std::fs;
use std::path::{Path, PathBuf};

use rand::RngCore;
use vault_crypto::{
    decrypt_bytes, derive_master_key, encrypt_bytes, stretch_master_key, KdfParams,
    SymmetricCryptoKey, UserKey, PBKDF2_MIN_ITERATIONS,
};

use crate::error::{Result, SessionError};
use crate::paths::write_atomic;

pub const MAX_PIN_FAILURES: u32 = 5;
const PIN_FILE: &str = "pin.key";
const ATTEMPTS_FILE: &str = "pin.attempts";

fn pin_path(data_dir: &Path) -> PathBuf {
    data_dir.join(PIN_FILE)
}

fn attempts_path(data_dir: &Path) -> PathBuf {
    data_dir.join(ATTEMPTS_FILE)
}

fn pin_key(pin: &str, email: &str) -> Result<SymmetricCryptoKey> {
    let material = format!("{pin}\0{email}");
    let master = derive_master_key(
        &material,
        email,
        &KdfParams::Pbkdf2 {
            iterations: PBKDF2_MIN_ITERATIONS,
        },
    )?;
    let stretched = stretch_master_key(&master)?;
    Ok((&stretched).into())
}

pub fn store_pin_wrapped_key(
    data_dir: &Path,
    email: &str,
    pin: &str,
    user_key: &UserKey,
) -> Result<()> {
    if pin.len() < 4 {
        return Err(SessionError::Other(
            "PIN must be at least 4 characters".into(),
        ));
    }
    let key = pin_key(pin, email)?;
    let enc = encrypt_bytes(user_key.to_bytes().as_ref(), &key)?;
    write_atomic(&pin_path(data_dir), enc.as_bytes())?;
    let _ = fs::remove_file(attempts_path(data_dir));
    Ok(())
}

pub fn pin_configured(data_dir: &Path) -> bool {
    pin_path(data_dir).is_file()
}

pub fn clear_pin(data_dir: &Path) {
    let _ = fs::remove_file(pin_path(data_dir));
    let _ = fs::remove_file(attempts_path(data_dir));
}

fn read_attempts(data_dir: &Path) -> u32 {
    fs::read_to_string(attempts_path(data_dir))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

fn write_attempts(data_dir: &Path, n: u32) {
    let _ = write_atomic(&attempts_path(data_dir), n.to_string().as_bytes());
}

pub fn unlock_with_pin(data_dir: &Path, email: &str, pin: &str) -> Result<UserKey> {
    let path = pin_path(data_dir);
    if !path.is_file() {
        return Err(SessionError::Other("PIN unlock is not configured".into()));
    }
    let attempts = read_attempts(data_dir);
    if attempts >= MAX_PIN_FAILURES {
        clear_pin(data_dir);
        return Err(SessionError::Other(
            "PIN locked out — unlock with master password and reconfigure PIN".into(),
        ));
    }
    let enc = fs::read_to_string(&path).map_err(|e| SessionError::Other(e.to_string()))?;
    let key = pin_key(pin, email)?;
    match decrypt_bytes(enc.trim(), &key) {
        Ok(raw) => {
            let _ = fs::remove_file(attempts_path(data_dir));
            UserKey::from_bytes(&raw).map_err(|e| SessionError::Other(e.to_string()))
        }
        Err(_) => {
            let next = attempts + 1;
            write_attempts(data_dir, next);
            if next >= MAX_PIN_FAILURES {
                clear_pin(data_dir);
                Err(SessionError::Other(
                    "too many PIN attempts — PIN cleared".into(),
                ))
            } else {
                Err(SessionError::Other(format!(
                    "incorrect PIN ({next}/{MAX_PIN_FAILURES})"
                )))
            }
        }
    }
}

pub fn random_numeric_pin(digits: usize) -> String {
    let n = digits.clamp(4, 12);
    let mut rng = rand::rngs::OsRng;
    (0..n)
        .map(|_| {
            let mut b = [0u8; 1];
            rng.fill_bytes(&mut b);
            char::from(b'0' + (b[0] % 10))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use vault_crypto::generate_user_key;

    #[test]
    fn pin_roundtrip() {
        let dir = tempdir().unwrap();
        let user = generate_user_key();
        store_pin_wrapped_key(dir.path(), "a@b.c", "1234", &user).unwrap();
        let unlocked = unlock_with_pin(dir.path(), "a@b.c", "1234").unwrap();
        assert_eq!(unlocked.to_bytes().as_ref(), user.to_bytes().as_ref());
    }
}
