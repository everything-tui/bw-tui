//! Bitwarden/Vaultwarden client-side cryptography.
//!
//! Implements KDF, EncString encrypt/decrypt, and key hierarchy operations.

mod enc_string;
mod error;
mod kdf;
mod keys;
mod rsa_share;
mod symmetric;

pub use enc_string::EncString;
pub use error::{CryptoError, Result};
pub use kdf::{
    auth_hash, derive_master_key, AuthHash, KdfParams, MasterKey, ARGON2_DEFAULT_ITERATIONS,
    ARGON2_DEFAULT_MEMORY_MIB, ARGON2_DEFAULT_PARALLELISM, ARGON2_MAX_MEMORY_MIB,
    ARGON2_MAX_PARALLELISM, ARGON2_MIN_ITERATIONS, ARGON2_MIN_MEMORY_MIB, ARGON2_MIN_PARALLELISM,
    PBKDF2_MIN_ITERATIONS,
};
pub use keys::{
    decrypt_private_key, generate_rsa_keypair, generate_user_key, stretch_master_key,
    unwrap_org_key, unwrap_org_key_with_user, unwrap_user_key, wrap_user_key, CipherKey, OrgKey,
    RsaKeyPair, StretchedMasterKey, SymmetricCryptoKey, UserKey,
};
pub use rsa_share::{public_key_der_from_b64, rsa_encrypt_user_key};
pub use symmetric::{decrypt_bytes, decrypt_with_key, encrypt_bytes, encrypt_with_key};
