//! Vaultwarden / Bitwarden client HTTP API.

mod client;
mod error;
mod models;

pub use client::{normalize_server_url, ClientConfig, VaultClient};
pub use error::{ApiError, Result};
pub use models::*;
