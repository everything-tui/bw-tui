//! RSA helpers for sharing the user key with another device (login-with-device approvals).

use base64::Engine;

use crate::error::{CryptoError, Result};
use crate::keys::UserKey;

/// Encrypt a 64-byte user key for another device's public key (SPKI DER, base64).
///
/// Returns an EncString of type 4 (`RSA-OAEP-SHA1`), the format Bitwarden clients use for
/// auth-request approvals.
pub fn rsa_encrypt_user_key(user_key: &UserKey, public_key_b64: &str) -> Result<String> {
    use rsa::pkcs8::DecodePublicKey;
    use rsa::{Oaep, RsaPublicKey};
    use sha1::Sha1;

    let der = base64::engine::general_purpose::STANDARD
        .decode(public_key_b64.trim())
        .map_err(|_| CryptoError::Base64)?;
    let public =
        RsaPublicKey::from_public_key_der(&der).map_err(|e| CryptoError::Rsa(e.to_string()))?;
    let bytes = user_key.to_bytes();
    let ct = public
        .encrypt(&mut rand::thread_rng(), Oaep::new::<Sha1>(), bytes.as_ref())
        .map_err(|e| CryptoError::Rsa(e.to_string()))?;
    Ok(format!(
        "4.{}",
        base64::engine::general_purpose::STANDARD.encode(ct)
    ))
}

/// Decode a base64 SPKI public key into raw DER bytes.
pub fn public_key_der_from_b64(public_key_b64: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(public_key_b64.trim())
        .map_err(|_| CryptoError::Base64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{generate_rsa_keypair, generate_user_key, unwrap_org_key};

    #[test]
    fn roundtrip_user_key_via_rsa() {
        let pair = generate_rsa_keypair().unwrap();
        let uk = generate_user_key();
        let enc = rsa_encrypt_user_key(&uk, &pair.public_key_b64).unwrap();
        assert!(enc.starts_with("4."));
        let back = unwrap_org_key(&enc, &pair.private_key_der).unwrap();
        assert_eq!(back.to_bytes()[..], uk.to_bytes()[..]);
    }
}
