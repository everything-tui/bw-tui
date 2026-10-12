use thiserror::Error;

pub type Result<T> = std::result::Result<T, ApiError>;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("{}", format_http(.0))]
    Http(reqwest::Error),
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
    #[error("user already exists")]
    UserExists,
    #[error("{0}")]
    Other(String),
}

impl From<reqwest::Error> for ApiError {
    fn from(err: reqwest::Error) -> Self {
        Self::Http(err)
    }
}

impl ApiError {
    /// True for connect/timeout/request transport failures (not HTTP 4xx/5xx bodies).
    pub fn is_transport(&self) -> bool {
        match self {
            Self::Http(err) => err.is_connect() || err.is_timeout() || err.is_request(),
            _ => false,
        }
    }

    /// True when the server rejected credentials / tokens.
    pub fn is_auth_rejection(&self) -> bool {
        matches!(self, Self::Api { status, .. } if matches!(*status, 401 | 403))
    }
}

fn format_http(err: &reqwest::Error) -> String {
    // Prefer a short host:port label so TUI error rows stay readable.
    let target = err
        .url()
        .map(|u| {
            let host = u.host_str().unwrap_or("server");
            match u.port() {
                Some(port) => format!("{host}:{port}"),
                None => host.to_string(),
            }
        })
        .or_else(|| {
            // reqwest sometimes omits url() on connect failures; parse from Display.
            let msg = err.to_string();
            msg.split("://")
                .nth(1)
                .and_then(|rest| rest.split(['/', ')', ' ']).next())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| "server".into());

    let chain = {
        let mut parts = Vec::new();
        let mut src: Option<&(dyn std::error::Error + 'static)> = Some(err);
        while let Some(e) = src {
            parts.push(e.to_string());
            src = e.source();
        }
        parts.join(" | ")
    };
    let chain_l = chain.to_ascii_lowercase();

    if chain_l.contains("unknownissuer")
        || chain_l.contains("unknown issuer")
        || chain_l.contains("certificate")
        || chain_l.contains("cert")
    {
        return format!("TLS certificate error for {target} (incomplete chain?)");
    }
    if err.is_timeout() {
        return format!("timed out reaching {target}");
    }
    if err.is_connect() {
        return format!("cannot connect to {target}");
    }
    if err.is_request() || err.is_builder() {
        return format!("bad request to {target}");
    }
    let msg = err.to_string();
    if let Some(rest) = msg
        .strip_prefix("error sending request for url ")
        .and_then(|s| s.split_once(": ").map(|(_, r)| r))
    {
        return format!("{target}: {rest}");
    }
    format!("{target}: {msg}")
}
