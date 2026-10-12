//! Biometric unlock (macOS Touch ID) — **feature-flagged stub**.
//!
//! Enabled with `--features biometric` on macOS. In every other configuration all
//! functions report "unsupported" and never touch the OS keychain, so the default
//! build is unaffected.
//!
//! What exists today:
//! * a non-secret *enrollment hint* stored in the Keychain (`mark_enrolled`) so the UI can
//!   remember that the user opted in;
//! * [`authenticate`] — placeholder for a `LocalAuthentication` (`LAContext`) prompt.
//!
//! What is intentionally missing: wrapping the user key with a Keychain item protected by
//! `kSecAccessControlBiometryCurrentSet`. That needs Security.framework bindings
//! (`security-framework` / `objc2-local-authentication`) and is tracked as follow-up work.
//! Until then biometric unlock never releases key material.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum BiometricError {
    #[error(
        "biometric unlock is not available in this build (enable the `biometric` feature on macOS)"
    )]
    Unsupported,
    #[error("biometric unlock is not implemented yet: {0}")]
    NotImplemented(&'static str),
    #[error("keychain: {0}")]
    Keychain(String),
}

/// True when this binary was built with Touch ID support.
pub const fn available() -> bool {
    cfg!(all(feature = "biometric", target_os = "macos"))
}

/// One-line UI hint describing the biometric state.
pub fn status_hint(profile_id: &str) -> String {
    if !available() {
        return "Biometric unlock: unavailable (build with --features biometric on macOS)".into();
    }
    if is_enrolled(profile_id) {
        "Biometric unlock: enrolled (stub — falls back to master password)".into()
    } else {
        "Biometric unlock: not enrolled".into()
    }
}

#[cfg(all(feature = "biometric", target_os = "macos"))]
mod imp {
    use super::BiometricError;
    use keyring::Entry;

    const SERVICE: &str = "com.bitwarden-tui.bitwarden-tui.biometric";

    fn entry(profile_id: &str) -> Result<Entry, BiometricError> {
        Entry::new(SERVICE, &format!("{profile_id}_biometricEnrolled"))
            .map_err(|e| BiometricError::Keychain(e.to_string()))
    }

    pub fn mark_enrolled(profile_id: &str) -> Result<(), BiometricError> {
        entry(profile_id)?
            .set_password("1")
            .map_err(|e| BiometricError::Keychain(e.to_string()))
    }

    pub fn is_enrolled(profile_id: &str) -> bool {
        entry(profile_id)
            .and_then(|e| {
                e.get_password()
                    .map_err(|e| BiometricError::Keychain(e.to_string()))
            })
            .is_ok()
    }

    pub fn clear_enrollment(profile_id: &str) -> Result<(), BiometricError> {
        match entry(profile_id)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(BiometricError::Keychain(e.to_string())),
        }
    }

    pub fn authenticate(_reason: &str) -> Result<(), BiometricError> {
        Err(BiometricError::NotImplemented(
            "LocalAuthentication prompt is not wired up",
        ))
    }
}

#[cfg(not(all(feature = "biometric", target_os = "macos")))]
mod imp {
    use super::BiometricError;

    pub fn mark_enrolled(_profile_id: &str) -> Result<(), BiometricError> {
        Err(BiometricError::Unsupported)
    }

    pub fn is_enrolled(_profile_id: &str) -> bool {
        false
    }

    pub fn clear_enrollment(_profile_id: &str) -> Result<(), BiometricError> {
        Err(BiometricError::Unsupported)
    }

    pub fn authenticate(_reason: &str) -> Result<(), BiometricError> {
        Err(BiometricError::Unsupported)
    }
}

/// Remember (in the Keychain) that the user opted in to biometric unlock.
pub fn mark_enrolled(profile_id: &str) -> Result<(), BiometricError> {
    imp::mark_enrolled(profile_id)
}

pub fn is_enrolled(profile_id: &str) -> bool {
    imp::is_enrolled(profile_id)
}

pub fn clear_enrollment(profile_id: &str) -> Result<(), BiometricError> {
    imp::clear_enrollment(profile_id)
}

/// Prompt for Touch ID. Currently always an error (see module docs).
pub fn authenticate(reason: &str) -> Result<(), BiometricError> {
    imp::authenticate(reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_build_is_unsupported() {
        if !available() {
            assert!(matches!(
                authenticate("x"),
                Err(BiometricError::Unsupported)
            ));
            assert!(!is_enrolled("p"));
        }
    }
}
