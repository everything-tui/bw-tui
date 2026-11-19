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

/// PBKDF2 iterations used by official clients for Send password hashing.
pub const SEND_PASSWORD_ITERATIONS: u32 = 100_000;

/// Hash a Send password the way official clients do: PBKDF2-HMAC-SHA256 over the UTF-8
/// password with the 16-byte send key material as salt, then standard base64.
pub fn hash_send_password(password: &str, key_material: &[u8; 16]) -> Result<String> {
    hash_send_password_with_iterations(password, key_material, SEND_PASSWORD_ITERATIONS)
}

pub(crate) fn hash_send_password_with_iterations(
    password: &str,
    key_material: &[u8; 16],
    iterations: u32,
) -> Result<String> {
    let mut out = [0u8; 32];
    pbkdf2::pbkdf2::<hmac::Hmac<Sha256>>(password.as_bytes(), key_material, iterations, &mut out)
        .map_err(|e| SessionError::Other(format!("send password pbkdf2: {e}")))?;
    Ok(base64::engine::general_purpose::STANDARD.encode(out))
}

/// Encrypt file bytes into the binary `EncArrayBuffer` layout used for Send/attachment
/// blobs: `[type=2][iv(16)][mac(32)][ciphertext]`.
pub fn encrypt_send_file_bytes(key_material: &[u8; 16], plaintext: &[u8]) -> Result<Vec<u8>> {
    let sym = derive_send_key(key_material)?;
    let enc_str = vault_crypto::encrypt_bytes(plaintext, &sym)
        .map_err(|e| SessionError::Other(e.to_string()))?;
    let enc =
        vault_crypto::EncString::parse(&enc_str).map_err(|e| SessionError::Other(e.to_string()))?;
    let mac = enc
        .mac
        .ok_or_else(|| SessionError::Other("missing mac".into()))?;
    let mut out = Vec::with_capacity(1 + enc.iv.len() + mac.len() + enc.data.len());
    out.push(enc.enc_type);
    out.extend_from_slice(&enc.iv);
    out.extend_from_slice(&mac);
    out.extend_from_slice(&enc.data);
    Ok(out)
}

/// Decrypt a binary `EncArrayBuffer` blob (type 2) downloaded for a file Send.
pub fn decrypt_send_file_bytes(key_material: &[u8; 16], blob: &[u8]) -> Result<Vec<u8>> {
    // type(1) + iv(16) + mac(32) + at least one AES block
    if blob.len() < 1 + 16 + 32 + 16 {
        return Err(SessionError::Other("send file blob too short".into()));
    }
    if blob[0] != 2 {
        return Err(SessionError::Other(format!(
            "unsupported send file encryption type {}",
            blob[0]
        )));
    }
    let enc = vault_crypto::EncString {
        enc_type: 2,
        iv: blob[1..17].to_vec(),
        mac: Some(blob[17..49].to_vec()),
        data: blob[49..].to_vec(),
    };
    let sym = derive_send_key(key_material)?;
    vault_crypto::decrypt_bytes(&enc.to_string(), &sym)
        .map_err(|e| SessionError::Other(e.to_string()))
}

/// Parsed Bitwarden Send share link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSendUrl {
    /// API/web origin to talk to (scheme + host[:port]).
    pub origin: String,
    pub access_id: String,
    pub key: [u8; 16],
}

/// Parse `https://host/#/send/{accessId}/{key}` and `https://send.host/#/{accessId}/{key}`
/// (also `#{accessId}/{key}` without the leading slash).
pub fn parse_send_url(raw: &str) -> Result<ParsedSendUrl> {
    let trimmed = raw.trim();
    let with_scheme = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    };
    let url = url::Url::parse(&with_scheme)
        .map_err(|e| SessionError::Other(format!("invalid send URL: {e}")))?;
    let host = url
        .host_str()
        .ok_or_else(|| SessionError::Other("send URL has no host".into()))?;
    let fragment = url
        .fragment()
        .ok_or_else(|| SessionError::Other("send URL is missing the #/… key fragment".into()))?;
    let mut parts: Vec<&str> = fragment.split('/').filter(|s| !s.is_empty()).collect();
    if parts
        .first()
        .is_some_and(|p| p.eq_ignore_ascii_case("send"))
    {
        parts.remove(0);
    }
    if parts.len() != 2 {
        return Err(SessionError::Other(
            "send URL fragment must be #/send/{id}/{key}".into(),
        ));
    }
    let key = decode_send_key_material(parts[1])?;

    // Official send hosts have no API of their own; use the matching vault host.
    let mapped_host = match host.to_ascii_lowercase().as_str() {
        "send.bitwarden.com" => "vault.bitwarden.com".to_string(),
        "send.bitwarden.eu" => "vault.bitwarden.eu".to_string(),
        _ => host.to_string(),
    };
    let mut origin = format!("{}://{}", url.scheme(), mapped_host);
    if let Some(port) = url.port() {
        origin.push_str(&format!(":{port}"));
    }
    Ok(ParsedSendUrl {
        origin,
        access_id: parts[0].to_string(),
        key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hash_is_deterministic_and_salted() {
        let key = [7u8; 16];
        let a = hash_send_password_with_iterations("pw", &key, 10).unwrap();
        let b = hash_send_password_with_iterations("pw", &key, 10).unwrap();
        assert_eq!(a, b);
        let other = hash_send_password_with_iterations("pw", &[8u8; 16], 10).unwrap();
        assert_ne!(a, other);
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(&a)
                .unwrap()
                .len(),
            32
        );
    }

    #[test]
    fn password_hash_matches_pbkdf2() {
        let mut expected = [0u8; 32];
        pbkdf2::pbkdf2::<hmac::Hmac<Sha256>>(b"password", &[0u8; 16], 1, &mut expected).unwrap();
        assert_eq!(
            hash_send_password_with_iterations("password", &[0u8; 16], 1).unwrap(),
            base64::engine::general_purpose::STANDARD.encode(expected)
        );
    }

    #[test]
    fn file_bytes_round_trip_and_layout() {
        let key = generate_send_key_material();
        let data = b"binary payload \x00\x01\x02".to_vec();
        let blob = encrypt_send_file_bytes(&key, &data).unwrap();
        assert_eq!(blob[0], 2);
        assert_eq!(decrypt_send_file_bytes(&key, &blob).unwrap(), data);
        let mut bad = blob.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0xff;
        assert!(decrypt_send_file_bytes(&key, &bad).is_err());
        assert!(decrypt_send_file_bytes(&key, &blob[..10]).is_err());
    }

    #[test]
    fn parse_send_url_variants() {
        let key = generate_send_key_material();
        let k = encode_send_key(&key);
        let p = parse_send_url(&format!("https://vault.example.com/#/send/abc123/{k}")).unwrap();
        assert_eq!(p.origin, "https://vault.example.com");
        assert_eq!(p.access_id, "abc123");
        assert_eq!(p.key, key);

        let p = parse_send_url(&format!("https://send.bitwarden.com/#abc123/{k}")).unwrap();
        assert_eq!(p.origin, "https://vault.bitwarden.com");
        assert_eq!(p.access_id, "abc123");

        let p = parse_send_url(&format!("http://localhost:8080/#/send/zz/{k}")).unwrap();
        assert_eq!(p.origin, "http://localhost:8080");

        assert!(parse_send_url("https://vault.example.com/#/send/abc").is_err());
        assert!(parse_send_url("https://vault.example.com/").is_err());
        assert!(parse_send_url("https://h/#/send/a/AAAA").is_err());
    }

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
