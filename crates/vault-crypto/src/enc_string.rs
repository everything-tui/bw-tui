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
                    return Err(CryptoError::InvalidEncString(
                        "expected iv|data|mac".into(),
                    ));
                }
                Ok(Self {
                    enc_type,
                    iv: engine.decode(parts[0]).map_err(|_| CryptoError::Base64)?,
                    data: engine.decode(parts[1]).map_err(|_| CryptoError::Base64)?,
                    mac: Some(engine.decode(parts[2]).map_err(|_| CryptoError::Base64)?),
                })
            }
            // RSA variants: data only
            3 | 4 | 5 | 6 => Ok(Self {
                enc_type,
                iv: Vec::new(),
                data: engine.decode(rest).map_err(|_| CryptoError::Base64)?,
                mac: None,
            }),
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
                let mac = self.mac.as_ref().map(|m| engine.encode(m)).unwrap_or_default();
                write!(
                    f,
                    "{}.{}|{}|{}",
                    self.enc_type,
                    engine.encode(&self.iv),
                    engine.encode(&self.data),
                    mac
                )
            }
            _ => write!(f, "{}.{}", self.enc_type, engine.encode(&self.data)),
        }
    }
}
