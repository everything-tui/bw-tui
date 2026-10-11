//! Bitwarden/Vaultwarden client-side cryptography.
//!
//! Implements KDF, EncString encrypt/decrypt, and key hierarchy operations.

mod enc_string;
mod error;
mod kdf;
mod keys;
mod symmetric;

pub use enc_string::EncString;
pub use error::{CryptoError, Result};
pub use kdf::{auth_hash, derive_master_key, AuthHash, KdfParams, MasterKey};
pub use keys::{
    decrypt_private_key, generate_rsa_keypair, generate_user_key, stretch_master_key,
    unwrap_org_key, unwrap_user_key, wrap_user_key, CipherKey, OrgKey, RsaKeyPair,
    StretchedMasterKey, SymmetricCryptoKey, UserKey,
};
pub use symmetric::{decrypt_bytes, decrypt_with_key, encrypt_bytes, encrypt_with_key};
