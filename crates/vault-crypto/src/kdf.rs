use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{CryptoError, Result};

type HmacSha256 = Hmac<Sha256>;

/// KDF parameters from prelogin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KdfParams {
    Pbkdf2 { iterations: u32 },
    Argon2id {
        iterations: u32,
        memory_kb: u32,
        parallelism: u32,
    },
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::Pbkdf2 { iterations: 600_000 }
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
pub fn derive_master_key(
    password: &str,
    email: &str,
    kdf: &KdfParams,
) -> Result<MasterKey> {
    let salt = email.trim().to_lowercase();
    let mut key = [0u8; 32];

    match kdf {
        KdfParams::Pbkdf2 { iterations } => {
            pbkdf2::<HmacSha256>(password.as_bytes(), salt.as_bytes(), *iterations, &mut key)
                .map_err(|e| CryptoError::Kdf(e.to_string()))?;
        }
        KdfParams::Argon2id {
            iterations,
            memory_kb,
            parallelism,
        } => {
            // Bitwarden salts Argon2 with SHA256(email)
            use sha2::Digest;
            let salt_hash = Sha256::digest(salt.as_bytes());
            let params = Params::new(*memory_kb, *iterations, *parallelism, Some(32))
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
        let a = derive_master_key("password", "user@example.com", &kdf).unwrap();
        let b = derive_master_key("password", "user@example.com", &kdf).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
        let d = derive_master_key("password", "other@example.com", &kdf).unwrap();
        assert_ne!(a.as_bytes(), d.as_bytes());
    }

    #[test]
    fn auth_hash_length() {
        let kdf = KdfParams::Pbkdf2 { iterations: 1000 };
        let mk = derive_master_key("password", "user@example.com", &kdf).unwrap();
        let h = auth_hash(&mk, "password").unwrap();
        // base64 of 32 bytes
        assert_eq!(h.as_str().len(), 44);
    }
}
