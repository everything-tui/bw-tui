use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::enc_string::EncString;
use crate::error::{CryptoError, Result};
use crate::keys::SymmetricCryptoKey;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type HmacSha256 = Hmac<Sha256>;

/// Encrypt plaintext with AesCbc256_HmacSha256_B64 (type 2).
pub fn encrypt_with_key(plaintext: &str, key: &SymmetricCryptoKey) -> Result<String> {
    let enc = encrypt_raw(plaintext.as_bytes(), key)?;
    Ok(enc.to_string())
}

/// Encrypt raw bytes with AesCbc256_HmacSha256_B64 (type 2).
pub fn encrypt_bytes(plaintext: &[u8], key: &SymmetricCryptoKey) -> Result<String> {
    let enc = encrypt_raw(plaintext, key)?;
    Ok(enc.to_string())
}

/// Decrypt EncString to UTF-8 string.
pub fn decrypt_with_key(enc_str: &str, key: &SymmetricCryptoKey) -> Result<String> {
    let enc = EncString::parse(enc_str)?;
    let bytes = decrypt_raw(&enc, key)?;
    String::from_utf8(bytes).map_err(|_| CryptoError::Utf8)
}

/// Decrypt EncString to raw bytes (e.g. nested cipher keys).
pub fn decrypt_bytes(enc_str: &str, key: &SymmetricCryptoKey) -> Result<Vec<u8>> {
    let enc = EncString::parse(enc_str)?;
    decrypt_raw(&enc, key)
}

pub fn encrypt_raw(plaintext: &[u8], key: &SymmetricCryptoKey) -> Result<EncString> {
    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);

    let encryptor = Aes256CbcEnc::new(key.enc_key().into(), (&iv).into());
    let ciphertext = encryptor.encrypt_padded_vec_mut::<Pkcs7>(plaintext);

    // MAC = HMAC-SHA256(mac_key, iv || ciphertext)
    let mut mac =
        HmacSha256::new_from_slice(key.mac_key()).map_err(|_| CryptoError::EncryptFailed)?;
    mac.update(&iv);
    mac.update(&ciphertext);
    let mac_bytes = mac.finalize().into_bytes().to_vec();

    Ok(EncString {
        enc_type: 2,
        iv: iv.to_vec(),
        data: ciphertext,
        mac: Some(mac_bytes),
    })
}

pub fn decrypt_raw(enc: &EncString, key: &SymmetricCryptoKey) -> Result<Vec<u8>> {
    match enc.enc_type {
        2 => decrypt_type2(enc, key),
        1 => decrypt_type1(enc, key),
        0 => decrypt_type0(enc, key),
        other => Err(CryptoError::UnsupportedEncType(other)),
    }
}

fn decrypt_type2(enc: &EncString, key: &SymmetricCryptoKey) -> Result<Vec<u8>> {
    let mac_bytes = enc.mac.as_ref().ok_or(CryptoError::MacMismatch)?;
    if mac_bytes.len() != 32 {
        return Err(CryptoError::MacMismatch);
    }

    let mut mac =
        HmacSha256::new_from_slice(key.mac_key()).map_err(|_| CryptoError::DecryptFailed)?;
    mac.update(&enc.iv);
    mac.update(&enc.data);
    mac.verify_slice(mac_bytes)
        .map_err(|_| CryptoError::MacMismatch)?;

    if enc.iv.len() != 16 {
        return Err(CryptoError::DecryptFailed);
    }
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&enc.iv);

    let decryptor = Aes256CbcDec::new(key.enc_key().into(), (&iv).into());
    let mut buf = Zeroizing::new(enc.data.clone());
    decryptor
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map(|pt| pt.to_vec())
        .map_err(|_| CryptoError::DecryptFailed)
}

/// AesCbc128_HmacSha256_B64 — legacy. Uses first 16 bytes of enc_key + full mac_key.
fn decrypt_type1(enc: &EncString, key: &SymmetricCryptoKey) -> Result<Vec<u8>> {
    let mac_bytes = enc.mac.as_ref().ok_or(CryptoError::MacMismatch)?;
    if mac_bytes.len() != 32 {
        return Err(CryptoError::MacMismatch);
    }

    let mut mac =
        HmacSha256::new_from_slice(key.type1_mac_key()).map_err(|_| CryptoError::DecryptFailed)?;
    mac.update(&enc.iv);
    mac.update(&enc.data);
    mac.verify_slice(mac_bytes)
        .map_err(|_| CryptoError::MacMismatch)?;

    if enc.iv.len() != 16 {
        return Err(CryptoError::DecryptFailed);
    }
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&enc.iv);
    let mut aes_key = [0u8; 16];
    aes_key.copy_from_slice(&key.enc_key()[..16]);

    let decryptor = Aes128CbcDec::new((&aes_key).into(), (&iv).into());
    let mut buf = Zeroizing::new(enc.data.clone());
    decryptor
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map(|pt| pt.to_vec())
        .map_err(|_| CryptoError::DecryptFailed)
}

fn decrypt_type0(enc: &EncString, key: &SymmetricCryptoKey) -> Result<Vec<u8>> {
    // Legacy AES-CBC-256 without MAC — still seen in some older data.
    if enc.iv.len() != 16 {
        return Err(CryptoError::DecryptFailed);
    }
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&enc.iv);
    let decryptor = Aes256CbcDec::new(key.enc_key().into(), (&iv).into());
    let mut buf = Zeroizing::new(enc.data.clone());
    decryptor
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map(|pt| pt.to_vec())
        .map_err(|_| CryptoError::DecryptFailed)
}

#[cfg(test)]
mod tests {
    use base64::Engine;

    use super::*;
    use crate::keys::SymmetricCryptoKey;

    fn test_key() -> SymmetricCryptoKey {
        SymmetricCryptoKey::from_parts([7u8; 32], [9u8; 32])
    }

    #[test]
    fn roundtrip() {
        let key = test_key();
        let ct = encrypt_with_key("hello vaultwarden", &key).unwrap();
        assert!(ct.starts_with("2."));
        let pt = decrypt_with_key(&ct, &key).unwrap();
        assert_eq!(pt, "hello vaultwarden");
    }

    #[test]
    fn mac_tamper_fails() {
        let key = test_key();
        let ct = encrypt_with_key("secret", &key).unwrap();
        let mut enc = EncString::parse(&ct).unwrap();
        if let Some(mac) = enc.mac.as_mut() {
            mac[0] ^= 0xff;
        }
        assert!(decrypt_raw(&enc, &key).is_err());
    }

    #[test]
    fn empty_string() {
        let key = test_key();
        let ct = encrypt_with_key("", &key).unwrap();
        assert_eq!(decrypt_with_key(&ct, &key).unwrap(), "");
    }

    #[test]
    fn type0_decrypt_roundtrip() {
        use aes::cipher::{BlockEncryptMut, KeyIvInit};
        type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

        let key = test_key();
        let iv = [3u8; 16];
        let encryptor = Aes256CbcEnc::new(key.enc_key().into(), (&iv).into());
        let ct = encryptor.encrypt_padded_vec_mut::<Pkcs7>(b"legacy-type0");
        let engine = base64::engine::general_purpose::STANDARD;
        let enc_str = format!("0.{}|{}", engine.encode(iv), engine.encode(&ct));
        assert_eq!(decrypt_with_key(&enc_str, &key).unwrap(), "legacy-type0");
    }

    #[test]
    fn type1_decrypt_with_64_byte_key() {
        use aes::cipher::{BlockEncryptMut, KeyIvInit};
        type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
        type HmacSha256 = Hmac<Sha256>;

        let key = test_key();
        let iv = [5u8; 16];
        let mut aes_key = [0u8; 16];
        aes_key.copy_from_slice(&key.enc_key()[..16]);
        let encryptor = Aes128CbcEnc::new((&aes_key).into(), (&iv).into());
        let ct = encryptor.encrypt_padded_vec_mut::<Pkcs7>(b"type-one");
        let mut mac = HmacSha256::new_from_slice(key.mac_key()).unwrap();
        mac.update(&iv);
        mac.update(&ct);
        let mac_bytes = mac.finalize().into_bytes();
        let engine = base64::engine::general_purpose::STANDARD;
        let enc_str = format!(
            "1.{}|{}|{}",
            engine.encode(iv),
            engine.encode(&ct),
            engine.encode(mac_bytes.as_slice())
        );
        assert_eq!(decrypt_with_key(&enc_str, &key).unwrap(), "type-one");
    }

    #[test]
    fn type1_wrong_mac_length_rejected() {
        let key = test_key();
        let mut enc = EncString::parse("1.AAAAAAAAAAAAAAAAAAAAAA==|AAAA|AA==").unwrap();
        enc.mac = Some(vec![0u8; 8]);
        assert!(decrypt_raw(&enc, &key).is_err());
    }
}
