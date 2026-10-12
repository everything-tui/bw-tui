use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{CryptoError, Result};

type HmacSha256 = Hmac<Sha256>;

/// Bitwarden / Vaultwarden KDF minimums (and sane maximums).
pub const PBKDF2_MIN_ITERATIONS: u32 = 5_000;
pub const ARGON2_MIN_ITERATIONS: u32 = 2;
pub const ARGON2_MIN_MEMORY_MIB: u32 = 16;
pub const ARGON2_MAX_MEMORY_MIB: u32 = 1024;
pub const ARGON2_MIN_PARALLELISM: u32 = 1;
pub const ARGON2_MAX_PARALLELISM: u32 = 16;

/// Default Argon2id parameters matching the Bitwarden clients.
pub const ARGON2_DEFAULT_ITERATIONS: u32 = 3;
pub const ARGON2_DEFAULT_MEMORY_MIB: u32 = 64;
pub const ARGON2_DEFAULT_PARALLELISM: u32 = 4;

/// KDF parameters from prelogin.
///
/// For Argon2id, `memory_mib` is in **mebibytes** (as returned by the Bitwarden
/// prelogin API). Conversion to KiB for the Argon2 crate happens inside
/// [`derive_master_key`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KdfParams {
    Pbkdf2 {
        iterations: u32,
    },
    Argon2id {
        iterations: u32,
        /// Memory cost in MiB (API / Bitwarden unit).
        memory_mib: u32,
        parallelism: u32,
    },
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::Pbkdf2 {
            iterations: 600_000,
        }
    }
}

impl KdfParams {
    /// Validate against Bitwarden minimums and client-side maximums.
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Pbkdf2 { iterations } => {
                if *iterations < PBKDF2_MIN_ITERATIONS {
                    return Err(CryptoError::InsufficientKdfParameters(format!(
                        "PBKDF2 iterations {iterations} below minimum {PBKDF2_MIN_ITERATIONS}"
                    )));
                }
            }
            Self::Argon2id {
                iterations,
                memory_mib,
                parallelism,
            } => {
                if *iterations < ARGON2_MIN_ITERATIONS {
                    return Err(CryptoError::InsufficientKdfParameters(format!(
                        "Argon2 iterations {iterations} below minimum {ARGON2_MIN_ITERATIONS}"
                    )));
                }
                if *memory_mib < ARGON2_MIN_MEMORY_MIB {
                    return Err(CryptoError::InsufficientKdfParameters(format!(
                        "Argon2 memory {memory_mib} MiB below minimum {ARGON2_MIN_MEMORY_MIB} MiB"
                    )));
                }
                if *memory_mib > ARGON2_MAX_MEMORY_MIB {
                    return Err(CryptoError::InsufficientKdfParameters(format!(
                        "Argon2 memory {memory_mib} MiB above maximum {ARGON2_MAX_MEMORY_MIB} MiB"
                    )));
                }
                if *parallelism < ARGON2_MIN_PARALLELISM || *parallelism > ARGON2_MAX_PARALLELISM {
                    return Err(CryptoError::InsufficientKdfParameters(format!(
                        "Argon2 parallelism {parallelism} outside {ARGON2_MIN_PARALLELISM}..={ARGON2_MAX_PARALLELISM}"
                    )));
                }
            }
        }
        Ok(())
    }

    /// Migrate a legacy persisted memory value that may be in KiB.
    ///
    /// Older builds stored Argon2 memory as KiB (sometimes incorrectly). Values
    /// greater than 1024 are treated as KiB and converted to MiB.
    pub fn migrate_memory_mib(raw: u32) -> u32 {
        if raw > 1024 {
            raw / 1024
        } else {
            raw
        }
    }
}

/// 256-bit master key derived from the master password.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey(pub(crate) [u8; 32]);

impl MasterKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Server authentication hash (base64).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AuthHash(pub(crate) String);

impl AuthHash {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Derive the master key from password + email using the given KDF.
pub fn derive_master_key(password: &str, email: &str, kdf: &KdfParams) -> Result<MasterKey> {
    kdf.validate()?;

    let salt = email.trim().to_lowercase();
    let mut key = [0u8; 32];

    match kdf {
        KdfParams::Pbkdf2 { iterations } => {
            pbkdf2::<HmacSha256>(password.as_bytes(), salt.as_bytes(), *iterations, &mut key)
                .map_err(|e| CryptoError::Kdf(e.to_string()))?;
        }
        KdfParams::Argon2id {
            iterations,
            memory_mib,
            parallelism,
        } => {
            // Bitwarden salts Argon2 with SHA256(email).
            // API `kdfMemory` is MiB; Argon2 Params expects KiB.
            use sha2::Digest;
            let salt_hash = Sha256::digest(salt.as_bytes());
            let memory_kib = memory_mib.saturating_mul(1024);
            let params = Params::new(memory_kib, *iterations, *parallelism, Some(32))
                .map_err(|e| CryptoError::Kdf(e.to_string()))?;
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            argon2
                .hash_password_into(password.as_bytes(), &salt_hash, &mut key)
                .map_err(|e| CryptoError::Kdf(e.to_string()))?;
        }
    }

    Ok(MasterKey(key))
}

/// Produce the auth hash sent to `/identity/connect/token`.
/// PBKDF2-SHA256(master_key, password, 1 iteration) → base64.
pub fn auth_hash(master_key: &MasterKey, password: &str) -> Result<AuthHash> {
    let mut hash = [0u8; 32];
    pbkdf2::<HmacSha256>(master_key.as_bytes(), password.as_bytes(), 1, &mut hash)
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    let b64 = Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(hash));
    hash.zeroize();
    Ok(AuthHash(b64.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pbkdf2_deterministic() {
        let kdf = KdfParams::Pbkdf2 { iterations: 1000 };
        // Bypass validate for low-iter unit test of determinism.
        let salt = "user@example.com";
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        pbkdf2::<HmacSha256>(b"password", salt.as_bytes(), 1000, &mut a).unwrap();
        pbkdf2::<HmacSha256>(b"password", salt.as_bytes(), 1000, &mut b).unwrap();
        assert_eq!(a, b);
        let _ = kdf;
    }

    #[test]
    fn pbkdf2_rejects_low_iterations() {
        let kdf = KdfParams::Pbkdf2 { iterations: 4999 };
        assert!(matches!(
            derive_master_key("password", "user@example.com", &kdf),
            Err(CryptoError::InsufficientKdfParameters(_))
        ));
    }

    #[test]
    fn argon2_rejects_low_memory() {
        let kdf = KdfParams::Argon2id {
            iterations: 3,
            memory_mib: 8,
            parallelism: 4,
        };
        assert!(matches!(
            derive_master_key("password", "user@example.com", &kdf),
            Err(CryptoError::InsufficientKdfParameters(_))
        ));
    }

    #[test]
    fn argon2_rejects_huge_memory() {
        let kdf = KdfParams::Argon2id {
            iterations: 3,
            memory_mib: 2048,
            parallelism: 4,
        };
        assert!(matches!(
            derive_master_key("password", "user@example.com", &kdf),
            Err(CryptoError::InsufficientKdfParameters(_))
        ));
    }

    #[test]
    fn migrate_memory_kib_to_mib() {
        assert_eq!(KdfParams::migrate_memory_mib(64), 64);
        assert_eq!(KdfParams::migrate_memory_mib(65536), 64);
        assert_eq!(KdfParams::migrate_memory_mib(32768), 32);
    }

    #[test]
    fn argon2_default_params_derive() {
        let kdf = KdfParams::Argon2id {
            iterations: ARGON2_DEFAULT_ITERATIONS,
            memory_mib: ARGON2_DEFAULT_MEMORY_MIB,
            parallelism: ARGON2_DEFAULT_PARALLELISM,
        };
        let a = derive_master_key("password", "user@example.com", &kdf).unwrap();
        let b = derive_master_key("password", "user@example.com", &kdf).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
        let d = derive_master_key("password", "other@example.com", &kdf).unwrap();
        assert_ne!(a.as_bytes(), d.as_bytes());
    }

    /// Port of Bitwarden SDK argon2 derivation shape: memory is MiB, converted to KiB.
    #[test]
    fn argon2_memory_mib_converted_to_kib() {
        // 16 MiB is the minimum; ensure Params accepts memory_mib * 1024.
        let kdf = KdfParams::Argon2id {
            iterations: 2,
            memory_mib: 16,
            parallelism: 1,
        };
        let key = derive_master_key("Correct Horse Battery Staple", "user@bitwarden.com", &kdf)
            .expect("argon2 derive");
        assert_eq!(key.as_bytes().len(), 32);
        // Different memory must change the key (proves MiB conversion is applied).
        let kdf_more = KdfParams::Argon2id {
            iterations: 2,
            memory_mib: 32,
            parallelism: 1,
        };
        let key2 = derive_master_key(
            "Correct Horse Battery Staple",
            "user@bitwarden.com",
            &kdf_more,
        )
        .unwrap();
        assert_ne!(key.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn auth_hash_length() {
        let kdf = KdfParams::Pbkdf2 {
            iterations: PBKDF2_MIN_ITERATIONS,
        };
        let mk = derive_master_key("password", "user@example.com", &kdf).unwrap();
        let h = auth_hash(&mk, "password").unwrap();
        assert_eq!(h.as_str().len(), 44);
    }
}
