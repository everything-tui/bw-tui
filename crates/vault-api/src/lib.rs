//! Vaultwarden / Bitwarden client HTTP API.

mod auth_models;
mod client;
mod error;
mod models;
mod org_models;

pub use auth_models::*;
pub use client::{
    is_insecure_http, is_unsupported_route, normalize_server_url, ClientConfig, VaultClient,
};
pub use error::{ApiError, Result};
pub use models::*;
pub use org_models::*;
