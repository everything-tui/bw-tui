use thiserror::Error;

pub type Result<T> = std::result::Result<T, ApiError>;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("API error ({status}): {message}")]
    Api { status: u16, message: String },
    #[error("two-factor authentication required")]
    TwoFactorRequired {
        providers: Vec<u8>,
        raw: serde_json::Value,
    },
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("URL error: {0}")]
    Url(String),
    #[error("not authenticated")]
    NotAuthenticated,
    #[error("{0}")]
    Other(String),
}
