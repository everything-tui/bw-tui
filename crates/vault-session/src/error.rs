use thiserror::Error;

pub type Result<T> = std::result::Result<T, SessionError>;

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("API: {0}")]
    Api(#[from] vault_api::ApiError),
    #[error("crypto: {0}")]
    Crypto(#[from] vault_crypto::CryptoError),
    #[error("not unlocked")]
    Locked,
    #[error("not logged in")]
    NotLoggedIn,
    #[error("offline — connect to sync or edit")]
    Offline,
    #[error("two-factor required (providers: {providers:?})")]
    TwoFactorRequired { providers: Vec<u8> },
    #[error("item not found")]
    NotFound,
    #[error("reprompt required")]
    RepromptRequired,
    #[error("organization / shared items cannot be edited yet")]
    OrgEditUnsupported,
    #[error("clipboard: {0}")]
    Clipboard(String),
    #[error("IO: {0}")]
    Io(#[from] std::io::Error),
    #[error("organization policy: {0}")]
    PolicyViolation(String),
    #[error("{0}")]
    Other(String),
}
