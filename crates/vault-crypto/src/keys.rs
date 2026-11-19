use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::enc_string::EncString;
use crate::error::{CryptoError, Result};
use crate::kdf::MasterKey;
use crate::symmetric::{decrypt_raw, encrypt_raw};

type HmacSha256 = Hmac<Sha256>;

/// 512-bit stretched master key: enc(32) || mac(32).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct StretchedMasterKey {
    pub enc_key: [u8; 32],
    pub mac_key: [u8; 32],
}

/// Symmetric crypto key (64-byte composite: 32-byte AES + 32-byte HMAC subkeys for type 2).
///
/// For legacy [AesCbc128_HmacSha256_B64](EncString) (type 1), Bitwarden used a 32-byte composite
/// (16-byte AES + 16-byte HMAC). Use [`SymmetricCryptoKey::from_type1_key_32`] for that layout.
/// When decrypting type 1 with a normal 64-byte user/org key, the first 16 bytes of `enc_key`
/// and the full 32-byte `mac_key` are used (48-byte effective material).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SymmetricCryptoKey {
    enc_key: [u8; 32],
    mac_key: [u8; 32],
}

impl SymmetricCryptoKey {
    pub fn from_parts(enc_key: [u8; 32], mac_key: [u8; 32]) -> Self {
        Self { enc_key, mac_key }
    }

    pub fn enc_key(&self) -> &[u8; 32] {
        &self.enc_key
    }

    pub fn mac_key(&self) -> &[u8; 32] {
        &self.mac_key
    }

    /// Legacy 32-byte type-1 material: enc(16) || mac(16), zero-padded into the 64-byte layout.
    pub fn from_type1_key_32(material: [u8; 32]) -> Self {
        let mut enc_key = [0u8; 32];
        let mut mac_key = [0u8; 32];
        enc_key[..16].copy_from_slice(&material[..16]);
        mac_key[..16].copy_from_slice(&material[16..]);
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

    pub fn to_bytes(&self) -> Zeroizing<[u8; 64]> {
        let mut out = Zeroizing::new([0u8; 64]);
        out[..32].copy_from_slice(&self.enc_key);
        out[32..].copy_from_slice(&self.mac_key);
        out
    }

    /// HMAC key bytes for type 1 (16-byte legacy vs full 32-byte mac subkey).
    pub(crate) fn type1_mac_key(&self) -> &[u8] {
        if self.enc_key[16..] == [0u8; 16] {
            &self.mac_key[..16]
        } else {
            &self.mac_key
        }
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
pub fn unwrap_user_key(protected_key: &str, master_key: &MasterKey) -> Result<UserKey> {
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
    let enc = encrypt_raw(bytes.as_ref(), &sym)?;
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

fn verify_rsa_payload_mac(mac: &[u8], ciphertext: &[u8], user_key: &UserKey) -> Result<()> {
    if mac.len() != 32 {
        return Err(CryptoError::MacMismatch);
    }
    let mut hmac =
        HmacSha256::new_from_slice(user_key.mac_key()).map_err(|_| CryptoError::MacMismatch)?;
    hmac.update(ciphertext);
    hmac.verify_slice(mac).map_err(|_| CryptoError::MacMismatch)
}

/// Unwrap an organization key using the RSA private key (EncString types 3–6).
///
/// Bare base64 without a type prefix is treated as type 4 for legacy payloads.
/// For types 5/6, pass `user_key` to verify the HMAC over the RSA ciphertext before decryption.
pub fn unwrap_org_key(protected_org_key: &str, private_key_der: &[u8]) -> Result<OrgKey> {
    unwrap_org_key_with_user(protected_org_key, private_key_der, None)
}

/// Like [`unwrap_org_key`] but optionally verifies type 5/6 HMAC with the account user key.
pub fn unwrap_org_key_with_user(
    protected_org_key: &str,
    private_key_der: &[u8],
    user_key: Option<&UserKey>,
) -> Result<OrgKey> {
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::{Oaep, RsaPrivateKey};
    use sha1::Sha1;
    use sha2::Sha256;

    let enc = if protected_org_key.contains('.') {
        EncString::parse(protected_org_key)?
    } else {
        use base64::Engine;
        EncString {
            enc_type: 4,
            iv: Vec::new(),
            data: base64::engine::general_purpose::STANDARD
                .decode(protected_org_key)
                .map_err(|_| CryptoError::Base64)?,
            mac: None,
        }
    };

    if matches!(enc.enc_type, 5 | 6) {
        if let Some(mac) = enc.mac.as_ref() {
            if let Some(uk) = user_key {
                verify_rsa_payload_mac(mac, &enc.data, uk)?;
            }
        }
    }

    let private_key = RsaPrivateKey::from_pkcs8_der(private_key_der)
        .map_err(|e| CryptoError::Rsa(e.to_string()))?;

    let ciphertext = &enc.data;

    let decrypted = match enc.enc_type {
        3 | 5 => {
            let padding = Oaep::new::<Sha256>();
            private_key
                .decrypt(padding, ciphertext)
                .map_err(|e| CryptoError::Rsa(e.to_string()))?
        }
        4 | 6 => {
            let padding = Oaep::new::<Sha1>();
            private_key
                .decrypt(padding, ciphertext)
                .map_err(|e| CryptoError::Rsa(e.to_string()))?
        }
        other => return Err(CryptoError::UnsupportedEncType(other)),
    };
    SymmetricCryptoKey::from_bytes(&decrypted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::MasterKey;

    const RSA_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCXRVrCX+2hfOQS
8HzYUS2oc/jGVTZpv+/Ryuoh9d8ihYX9dd0cYh2tl6KWdFc88lPUH11Oxqy20Rk2
e5r/RF6T9yM0Me3NPnaKt+hlhLtfoc0h86LnhD56A9FDUfuI0dVnPcrwNv0YJIo9
4LwxtbqBULNvXl6wJ7WAbODrCQy5ZgMVg+iH+gGpwiqsZqHt+KuoHWcN53MSPDfa
F4/YMB99U3TziJMOOJask1TEEnakMPln11PczNDazT17DXIxYrbPfutPdh6sLs6A
QOajdZijfEvepgnOe7cQ7aeatiOJFrjTApKPGxOVRzEMX4XS4xbyhH0QxQeB6l16
l8C0uxIBAgMBAAECggEASaWfeVDA3cVzOPFSpvJm20OTE+R6uGOU+7vh36TX/POq
92qBuwbd0h0oMD32FxsXywd2IxtBDUSiFM9699qufTVuM0Q3tZw6lHDTOVG08+tP
dr8qSbMtw7PGFxN79fHLBxejjO4IrM9lapjWpxEF+11x7r+wM+0xRZQ8sNFYG46a
PfIaty4BGbL0I2DQ2y8I57iBCAy69eht59NLMm27fRWGJIWCuBIjlpfzET1j2HLX
UIh5bTBNzqaN039WH49HczGE3mQKVEJZc/efk3HaVd0a1Sjzyn0QY+N1jtZN3jTR
buDWA1AknkX1LX/0tUhuS3/7C3ejHxjw4Dk1ZLo5/QKBgQDIWvqFn0+IKRSu6Ua2
hDsufIHHUNLelbfLUMmFthxabcUn4zlvIscJO00Tq/ezopSRRvbGiqnxjv/mYxuc
vOUBeZtlus0Q9RTACBtw9TGoNTmQbEunJ2FOSlqbQxkBBAjgGEppRPt30iGj/VjA
hCATq2MYOa/X4dVR51BqQAFIEwKBgQDBSIfTFKC/hDk6FKZlgwvupWYJyU9Rkyfs
tPErZFmzoKhPkQ3YORo2oeAYmVUbS9I2iIYpYpYQJHX8jMuCbCz4ONxTCuSIXYQY
UcUq4PglCKp31xBAE6TN8SvhfME9/MvuDssnQinAHuF0GDAhF646T3LLS1not6Vs
zv7brwSoGwKBgQC88v/8cGfi80ssQZeMnVvq1UTXIeQcQnoY5lGHJl3K8mbS3TnX
E6c9j417Fdz+rj8KWzBzwWXQB5pSPflWcdZO886Xu/mVGmy9RWgLuVFhXwCwsVEP
jNX5ramRb0/vY0yzenUCninBsIxFSbIfrPtLUYCc4hpxr+sr2Mg/y6jpvQKBgBez
MRRs3xkcuXepuI2R+BCXL1/b02IJTUf1F+1eLLGd7YV0H+J3fgNc7gGWK51hOrF9
JBZHBGeOUPlaukmPwiPdtQZpu4QNE3l37VlIpKTF30E6mb+BqR+nht3rUjarnMXg
AoEZ18y6/KIjpSMpqC92Nnk/EBM9EYe6Cf4eA9ApAoGAeqEUg46UTlJySkBKURGp
Is3v1kkf5I0X8DnOhwb+HPxNaiEdmO7ckm8+tPVgppLcG0+tMdLjigFQiDUQk2y3
WjyxP5ZvXu7U96jaJRI8PFMoE06WeVYcdIzrID2HvqH+w0UQJFrLJ/0Mn4stFAEz
XKZBokBGnjFnTnKcs7nv/O8=
-----END PRIVATE KEY-----";

    const ORG_KEY_TYPE4: &str = "4.DMD1D5r6BsDDd7C/FE1eZbMCKrmryvAsCKj6+bO54gJNUxisOI7SDcpPLRXf+JdhqY15pT+wimQ5cD9C+6OQ6s71LFQHewXPU29l9Pa1JxGeiKqp37KLYf+1IS6UB2K3ANN35C52ZUHh2TlzIS5RuntxnpCw7APbcfpcnmIdLPJBtuj/xbFd6eBwnI3GSe5qdS6/Ixdd0dgsZcpz3gHJBKmIlSo0YN60SweDq3kTJwox9xSqdCueIDg5U4khc7RhjYx8b33HXaNJj3DwgIH8iLj+lqpDekogr630OhHG3XRpvl4QzYO45bmHb8wAh67Dj70nsZcVg6bAEFHdSFohww==";

    const ORG_KEY_TYPE6: &str = "6.DMD1D5r6BsDDd7C/FE1eZbMCKrmryvAsCKj6+bO54gJNUxisOI7SDcpPLRXf+JdhqY15pT+wimQ5cD9C+6OQ6s71LFQHewXPU29l9Pa1JxGeiKqp37KLYf+1IS6UB2K3ANN35C52ZUHh2TlzIS5RuntxnpCw7APbcfpcnmIdLPJBtuj/xbFd6eBwnI3GSe5qdS6/Ixdd0dgsZcpz3gHJBKmIlSo0YN60SweDq3kTJwox9xSqdCueIDg5U4khc7RhjYx8b33HXaNJj3DwgIH8iLj+lqpDekogr630OhHG3XRpvl4QzYO45bmHb8wAh67Dj70nsZcVg6bAEFHdSFohww==|AA==";

    fn rsa_private_der_from_pem() -> Vec<u8> {
        use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};
        use rsa::RsaPrivateKey;
        RsaPrivateKey::from_pkcs8_pem(RSA_PRIVATE_KEY_PEM)
            .unwrap()
            .to_pkcs8_der()
            .unwrap()
            .as_bytes()
            .to_vec()
    }

    #[test]
    fn stretch_matches_bitwarden_sdk_vector() {
        let master = MasterKey([
            31, 79, 104, 226, 150, 71, 177, 90, 194, 80, 172, 209, 17, 129, 132, 81, 138, 167, 69,
            167, 254, 149, 2, 27, 39, 197, 64, 42, 22, 195, 86, 75,
        ]);
        let stretched = stretch_master_key(&master).unwrap();
        assert_eq!(
            stretched.enc_key,
            [
                111, 31, 178, 45, 238, 152, 37, 114, 143, 215, 124, 83, 135, 173, 195, 23, 142,
                134, 120, 249, 61, 132, 163, 182, 113, 197, 189, 204, 188, 21, 237, 96
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

    #[test]
    fn unwrap_org_key_type4_bitwarden_vector() {
        let der = rsa_private_der_from_pem();
        let org = unwrap_org_key(ORG_KEY_TYPE4, &der).unwrap();
        assert_eq!(org.to_bytes().len(), 64);
    }

    #[test]
    fn unwrap_org_key_type6_matches_type4_payload() {
        let der = rsa_private_der_from_pem();
        let from4 = unwrap_org_key(ORG_KEY_TYPE4, &der).unwrap();
        let from6 = unwrap_org_key(ORG_KEY_TYPE6, &der).unwrap();
        assert_eq!(from4.to_bytes()[..], from6.to_bytes()[..]);
    }

    #[test]
    fn unwrap_org_key_type6_mac_length_enforced_when_verifying() {
        let der = rsa_private_der_from_pem();
        let user = SymmetricCryptoKey::from_parts([1u8; 32], [2u8; 32]);
        assert!(unwrap_org_key_with_user(ORG_KEY_TYPE6, &der, Some(&user)).is_err());
    }
}
