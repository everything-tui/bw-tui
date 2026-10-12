//! Bitwarden Send encryption helpers (text sends).
//!
//! Key derivation matches official clients' `makeSendKey`:
//! HKDF-SHA256 with salt `bitwarden-send` and info `send`, producing a 64-byte
//! symmetric key from 16-byte random key material.

use base64::Engine;
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use vault_crypto::{decrypt_with_key, encrypt_with_key, SymmetricCryptoKey};

use crate::error::{Result, SessionError};

/// Random 16-byte send key material (Bitwarden URL fragment / secret).
pub fn generate_send_key_material() -> [u8; 16] {
    let mut key = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

/// Encode send key material for the share URL fragment.
pub fn encode_send_key(key: &[u8; 16]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key)
}

/// Decode URL-safe or standard base64 send key material (16 bytes).
pub fn decode_send_key_material(encoded: &str) -> Result<[u8; 16]> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded.trim())
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(encoded.trim()))
        .map_err(|e| SessionError::Other(e.to_string()))?;
    if bytes.len() != 16 {
        return Err(SessionError::Other(format!(
            "invalid send key length {} (expected 16)",
            bytes.len()
        )));
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Derive the 64-byte Send encryption key (`makeSendKey`).
pub fn derive_send_key(key_material: &[u8; 16]) -> Result<SymmetricCryptoKey> {
    let hk = Hkdf::<Sha256>::new(Some(b"bitwarden-send"), key_material);
    let mut derived = [0u8; 64];
    hk.expand(b"send", &mut derived)
        .map_err(|e| SessionError::Other(format!("send hkdf expand: {e}")))?;
    SymmetricCryptoKey::from_bytes(&derived).map_err(|e| SessionError::Other(e.to_string()))
}

/// Encrypt plaintext for a text Send (`Send.text` field).
pub fn encrypt_send_text(key_material: &[u8; 16], plaintext: &str) -> Result<String> {
    let sym = derive_send_key(key_material)?;
    encrypt_with_key(plaintext, &sym).map_err(|e| SessionError::Other(e.to_string()))
}

/// Encrypt send name / notes with the derived send key.
pub fn encrypt_send_meta(key_material: &[u8; 16], plaintext: &str) -> Result<String> {
    let sym = derive_send_key(key_material)?;
    encrypt_with_key(plaintext, &sym).map_err(|e| SessionError::Other(e.to_string()))
}

pub fn decrypt_send_meta_field(key_material: &[u8; 16], ciphertext: &str) -> Result<String> {
    let sym = derive_send_key(key_material)?;
    decrypt_with_key(ciphertext, &sym).map_err(|e| SessionError::Other(e.to_string()))
}

pub fn decrypt_send_text_field(key_material: &[u8; 16], ciphertext: &str) -> Result<String> {
    let sym = derive_send_key(key_material)?;
    decrypt_with_key(ciphertext, &sym).map_err(|e| SessionError::Other(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_text_round_trip() {
        let key = generate_send_key_material();
        let enc = encrypt_send_text(&key, "hello send").unwrap();
        let plain = decrypt_send_text_field(&key, &enc).unwrap();
        assert_eq!(plain, "hello send");
    }

    #[test]
    fn meta_uses_same_derived_key() {
        let key = generate_send_key_material();
        let enc = encrypt_send_meta(&key, "name").unwrap();
        assert_eq!(decrypt_send_meta_field(&key, &enc).unwrap(), "name");
    }

    #[test]
    fn encode_decode_url_safe() {
        let key = generate_send_key_material();
        let enc = encode_send_key(&key);
        assert_eq!(decode_send_key_material(&enc).unwrap(), key);
    }
}
