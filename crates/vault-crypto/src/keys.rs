use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::enc_string::EncString;
use crate::error::{CryptoError, Result};
use crate::kdf::MasterKey;
use crate::symmetric::{decrypt_raw, encrypt_raw};

/// 512-bit stretched master key: enc(32) || mac(32).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct StretchedMasterKey {
    pub enc_key: [u8; 32],
    pub mac_key: [u8; 32],
}

/// Symmetric crypto key used for EncString type 2 (AES-CBC-256 + HMAC-SHA256).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SymmetricCryptoKey {
    pub enc_key: [u8; 32],
    pub mac_key: [u8; 32],
}

impl SymmetricCryptoKey {
    pub fn from_parts(enc_key: [u8; 32], mac_key: [u8; 32]) -> Self {
        Self { enc_key, mac_key }
    }

    /// Parse a 64-byte key (enc || mac).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 64 {
            return Err(CryptoError::InvalidKeyLength);
        }
        let mut enc_key = [0u8; 32];
        let mut mac_key = [0u8; 32];
        enc_key.copy_from_slice(&bytes[..32]);
        mac_key.copy_from_slice(&bytes[32..]);
        Ok(Self { enc_key, mac_key })
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.enc_key);
        out[32..].copy_from_slice(&self.mac_key);
        out
    }
}

pub type UserKey = SymmetricCryptoKey;
pub type OrgKey = SymmetricCryptoKey;
pub type CipherKey = SymmetricCryptoKey;

/// Stretch master key via HKDF-SHA256 expand (Bitwarden).
///
/// Bitwarden treats the 32-byte master key as the PRK and runs HKDF-Expand
/// only — not Extract+Expand. Using `Hkdf::new` here produces the wrong keys
/// and causes "MAC verification failed" against vaults created by official clients.
pub fn stretch_master_key(master_key: &MasterKey) -> Result<StretchedMasterKey> {
    let hk = Hkdf::<Sha256>::from_prk(master_key.as_bytes())
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    let mut enc_key = [0u8; 32];
    let mut mac_key = [0u8; 32];
    hk.expand(b"enc", &mut enc_key)
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    hk.expand(b"mac", &mut mac_key)
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    Ok(StretchedMasterKey { enc_key, mac_key })
}

impl From<&StretchedMasterKey> for SymmetricCryptoKey {
    fn from(s: &StretchedMasterKey) -> Self {
        Self {
            enc_key: s.enc_key,
            mac_key: s.mac_key,
        }
    }
}

/// Decrypt the protected user key (EncString) with the stretched master key.
pub fn unwrap_user_key(
    protected_key: &str,
    master_key: &MasterKey,
) -> Result<UserKey> {
    let stretched = stretch_master_key(master_key)?;
    let sym: SymmetricCryptoKey = (&stretched).into();
    let enc = EncString::parse(protected_key)?;
    let raw = decrypt_raw(&enc, &sym)?;
    SymmetricCryptoKey::from_bytes(&raw)
}

/// Encrypt a user key with the stretched master key (for registration).
pub fn wrap_user_key(user_key: &UserKey, master_key: &MasterKey) -> Result<String> {
    let stretched = stretch_master_key(master_key)?;
    let sym: SymmetricCryptoKey = (&stretched).into();
    let bytes = user_key.to_bytes();
    let enc = encrypt_raw(&bytes, &sym)?;
    Ok(enc.to_string())
}

/// Generate a new random user key.
pub fn generate_user_key() -> UserKey {
    use rand::RngCore;
    let mut enc_key = [0u8; 32];
    let mut mac_key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut enc_key);
    rand::thread_rng().fill_bytes(&mut mac_key);
    SymmetricCryptoKey { enc_key, mac_key }
}

/// Decrypt RSA private key (PKCS8 DER encrypted as EncString) with user key.
pub fn decrypt_private_key(protected: &str, user_key: &UserKey) -> Result<Vec<u8>> {
    let enc = EncString::parse(protected)?;
    decrypt_raw(&enc, user_key)
}

/// Generated RSA key material for account registration.
pub struct RsaKeyPair {
    pub public_key_b64: String,
    pub private_key_der: Vec<u8>,
}

/// Generate a 2048-bit RSA key pair (SPKI public + PKCS8 private DER).
pub fn generate_rsa_keypair() -> Result<RsaKeyPair> {
    use base64::Engine;
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
    use rsa::RsaPrivateKey;

    let mut rng = rand::thread_rng();
    let private_key =
        RsaPrivateKey::new(&mut rng, 2048).map_err(|e| CryptoError::Rsa(e.to_string()))?;
    let public_key = private_key.to_public_key();

    let private_der = private_key
        .to_pkcs8_der()
        .map_err(|e| CryptoError::Rsa(e.to_string()))?
        .as_bytes()
        .to_vec();
    let public_der = public_key
        .to_public_key_der()
        .map_err(|e| CryptoError::Rsa(e.to_string()))?
        .as_bytes()
        .to_vec();

    Ok(RsaKeyPair {
        public_key_b64: base64::engine::general_purpose::STANDARD.encode(public_der),
        private_key_der: private_der,
    })
}

/// Unwrap an organization key using the RSA private key (OAEP-SHA1).
pub fn unwrap_org_key(protected_org_key: &str, private_key_der: &[u8]) -> Result<OrgKey> {
    use base64::Engine;
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::{Oaep, RsaPrivateKey};
    use sha1::Sha1;

    // Org keys are typically "4.<base64>" (RSA2048_OaepSha1_B64) or just base64.
    let b64 = if let Some(rest) = protected_org_key.strip_prefix("4.") {
        rest
    } else {
        protected_org_key
    };
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|_| CryptoError::Base64)?;

    let private_key = RsaPrivateKey::from_pkcs8_der(private_key_der)
        .map_err(|e| CryptoError::Rsa(e.to_string()))?;
    let padding = Oaep::new::<Sha1>();
    let decrypted = private_key
        .decrypt(padding, &ciphertext)
        .map_err(|e| CryptoError::Rsa(e.to_string()))?;
    SymmetricCryptoKey::from_bytes(&decrypted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::MasterKey;

    #[test]
    fn stretch_matches_bitwarden_sdk_vector() {
        // From bitwarden_crypto::keys::utils::tests::test_stretch_kdf_key
        let master = MasterKey([
            31, 79, 104, 226, 150, 71, 177, 90, 194, 80, 172, 209, 17, 129, 132, 81, 138, 167, 69,
            167, 254, 149, 2, 27, 39, 197, 64, 42, 22, 195, 86, 75,
        ]);
        let stretched = stretch_master_key(&master).unwrap();
        assert_eq!(
            stretched.enc_key,
            [
                111, 31, 178, 45, 238, 152, 37, 114, 143, 215, 124, 83, 135, 173, 195, 23, 142, 134,
                120, 249, 61, 132, 163, 182, 113, 197, 189, 204, 188, 21, 237, 96
            ]
        );
        assert_eq!(
            stretched.mac_key,
            [
                221, 127, 206, 234, 101, 27, 202, 38, 86, 52, 34, 28, 78, 28, 185, 16, 48, 61, 127,
                166, 209, 247, 194, 87, 232, 26, 48, 85, 193, 249, 179, 155
            ]
        );
    }
}
