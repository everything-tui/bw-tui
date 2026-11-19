use std::fmt;
use std::str::FromStr;

use base64::Engine;

use crate::error::{CryptoError, Result};

/// Bitwarden EncString: `type.iv|data|mac` (or RSA variants).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncString {
    pub enc_type: u8,
    pub iv: Vec<u8>,
    pub data: Vec<u8>,
    pub mac: Option<Vec<u8>>,
}

impl EncString {
    pub fn parse(s: &str) -> Result<Self> {
        s.parse()
    }

    pub fn to_string_enc(&self) -> String {
        self.to_string()
    }
}

impl FromStr for EncString {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self> {
        let (type_str, rest) = s
            .split_once('.')
            .ok_or_else(|| CryptoError::InvalidEncString("missing type".into()))?;
        let enc_type: u8 = type_str
            .parse()
            .map_err(|_| CryptoError::InvalidEncString("bad type".into()))?;

        let engine = base64::engine::general_purpose::STANDARD;

        match enc_type {
            // AesCbc256_B64: iv|data
            0 => {
                let (iv_b64, data_b64) = rest
                    .split_once('|')
                    .ok_or_else(|| CryptoError::InvalidEncString("type0 parts".into()))?;
                Ok(Self {
                    enc_type,
                    iv: engine.decode(iv_b64).map_err(|_| CryptoError::Base64)?,
                    data: engine.decode(data_b64).map_err(|_| CryptoError::Base64)?,
                    mac: None,
                })
            }
            // AesCbc128_HmacSha256_B64 / AesCbc256_HmacSha256_B64: iv|data|mac
            1 | 2 => {
                let parts: Vec<&str> = rest.split('|').collect();
                if parts.len() != 3 {
                    return Err(CryptoError::InvalidEncString("expected iv|data|mac".into()));
                }
                Ok(Self {
                    enc_type,
                    iv: engine.decode(parts[0]).map_err(|_| CryptoError::Base64)?,
                    data: engine.decode(parts[1]).map_err(|_| CryptoError::Base64)?,
                    mac: Some(engine.decode(parts[2]).map_err(|_| CryptoError::Base64)?),
                })
            }
            // Rsa2048_OaepSha256_B64 / Rsa2048_OaepSha1_B64: data only
            3 | 4 => Ok(Self {
                enc_type,
                iv: Vec::new(),
                data: engine.decode(rest).map_err(|_| CryptoError::Base64)?,
                mac: None,
            }),
            // Rsa2048_OaepSha*_HmacSha256_B64: data|mac (Bitwarden wire format)
            5 | 6 => {
                let (data_b64, mac_b64) = rest.split_once('|').ok_or_else(|| {
                    CryptoError::InvalidEncString("type5/6 expected data|mac".into())
                })?;
                Ok(Self {
                    enc_type,
                    iv: Vec::new(),
                    data: engine.decode(data_b64).map_err(|_| CryptoError::Base64)?,
                    mac: Some(engine.decode(mac_b64).map_err(|_| CryptoError::Base64)?),
                })
            }
            other => Err(CryptoError::UnsupportedEncType(other)),
        }
    }
}

impl fmt::Display for EncString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let engine = base64::engine::general_purpose::STANDARD;
        match self.enc_type {
            0 => write!(
                f,
                "{}.{}|{}",
                self.enc_type,
                engine.encode(&self.iv),
                engine.encode(&self.data)
            ),
            1 | 2 => {
                let mac = self
                    .mac
                    .as_ref()
                    .map(|m| engine.encode(m))
                    .unwrap_or_default();
                write!(
                    f,
                    "{}.{}|{}|{}",
                    self.enc_type,
                    engine.encode(&self.iv),
                    engine.encode(&self.data),
                    mac
                )
            }
            5 | 6 => {
                let mac = self
                    .mac
                    .as_ref()
                    .map(|m| engine.encode(m))
                    .unwrap_or_default();
                write!(f, "{}.{}|{}", self.enc_type, engine.encode(&self.data), mac)
            }
            _ => write!(f, "{}.{}", self.enc_type, engine.encode(&self.data)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RSA_TYPE6_FIXTURE: &str = "6.DMD1D5r6BsDDd7C/FE1eZbMCKrmryvAsCKj6+bO54gJNUxisOI7SDcpPLRXf+JdhqY15pT+wimQ5cD9C+6OQ6s71LFQHewXPU29l9Pa1JxGeiKqp37KLYf+1IS6UB2K3ANN35C52ZUHh2TlzIS5RuntxnpCw7APbcfpcnmIdLPJBtuj/xbFd6eBwnI3GSe5qdS6/Ixdd0dgsZcpz3gHJBKmIlSo0YN60SweDq3kTJwox9xSqdCueIDg5U4khc7RhjYx8b33HXaNJj3DwgIH8iLj+lqpDekogr630OhHG3XRpvl4QzYO45bmHb8wAh67Dj70nsZcVg6bAEFHdSFohww==|AA==";

    #[test]
    fn parse_types_0_1_2_structure() {
        let engine = base64::engine::general_purpose::STANDARD;
        let iv = engine.encode([0u8; 16]);
        let data = engine.encode([1u8; 16]);
        let mac = engine.encode([2u8; 32]);

        let t0 = EncString::parse(&format!("0.{iv}|{data}")).unwrap();
        assert_eq!(t0.enc_type, 0);
        assert_eq!(t0.iv.len(), 16);
        assert!(t0.mac.is_none());
        assert_eq!(EncString::parse(&t0.to_string()).unwrap(), t0);

        for t in [1u8, 2] {
            let enc = EncString::parse(&format!("{t}.{iv}|{data}|{mac}")).unwrap();
            assert_eq!(enc.enc_type, t);
            assert_eq!(enc.iv.len(), 16);
            assert_eq!(enc.mac.as_ref().unwrap().len(), 32);
            assert_eq!(EncString::parse(&enc.to_string()).unwrap(), enc);
        }
    }

    #[test]
    fn parse_type2_roundtrip_display() {
        let s = "2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let enc = EncString::parse(s).unwrap();
        assert_eq!(enc.enc_type, 2);
        assert!(enc.mac.is_some());
        let again = EncString::parse(&enc.to_string()).unwrap();
        assert_eq!(enc, again);
    }

    #[test]
    fn parse_type5_data_mac() {
        let engine = base64::engine::general_purpose::STANDARD;
        let mac = engine.encode([1u8; 32]);
        let data = engine.encode([2u8; 16]);
        let s = format!("5.{data}|{mac}");
        let enc = EncString::parse(&s).unwrap();
        assert_eq!(enc.enc_type, 5);
        assert_eq!(enc.mac.as_ref().unwrap(), &[1u8; 32]);
        assert_eq!(enc.data, vec![2u8; 16]);
        assert_eq!(EncString::parse(&enc.to_string()).unwrap(), enc);
    }

    #[test]
    fn parse_type6_bitwarden_fixture() {
        let enc = EncString::parse(RSA_TYPE6_FIXTURE).unwrap();
        assert_eq!(enc.enc_type, 6);
        assert!(!enc.data.is_empty());
        assert_eq!(enc.mac.as_deref(), Some([0u8].as_ref()));
    }

    #[test]
    fn parse_type3_and_4_data_only() {
        let engine = base64::engine::general_purpose::STANDARD;
        let data = engine.encode([9u8; 16]);
        for t in [3u8, 4] {
            let enc = EncString::parse(&format!("{t}.{data}")).unwrap();
            assert_eq!(enc.enc_type, t);
            assert!(enc.mac.is_none());
            assert_eq!(enc.data, vec![9u8; 16]);
            assert_eq!(EncString::parse(&enc.to_string()).unwrap(), enc);
        }
    }
}
