use thiserror::Error;

pub type Result<T> = std::result::Result<T, CryptoError>;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid EncString format: {0}")]
    InvalidEncString(String),
    #[error("unsupported encryption type: {0}")]
    UnsupportedEncType(u8),
    #[error("MAC verification failed")]
    MacMismatch,
    #[error("decryption failed")]
    DecryptFailed,
    #[error("encryption failed")]
    EncryptFailed,
    #[error("invalid key length")]
    InvalidKeyLength,
    #[error("KDF failed: {0}")]
    Kdf(String),
    #[error("RSA error: {0}")]
    Rsa(String),
    #[error("base64 decode error")]
    Base64,
    #[error("utf-8 decode error")]
    Utf8,
}
