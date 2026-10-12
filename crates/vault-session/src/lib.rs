//! Vault session: login, unlock, sync, decrypt, CRUD, clipboard.

mod clipboard;
mod decrypt;
mod error;
mod generator;
mod models;
mod paths;
mod secure_storage;
mod session;
mod vault_cache;

pub use clipboard::ClipboardService;
pub use error::{Result, SessionError};
pub use generator::{
    generate_passphrase, generate_password, generate_password_checked, password_entropy_bits,
    GeneratorOptions,
};
pub use models::*;
pub use paths::{app_data_dir, ensure_dir, profile_dir, profiles_dir, profiles_file, write_atomic};
pub use secure_storage::{
    with_refresh_token_store_for_tests, FailingRefreshTokenStore, MemoryRefreshTokenStore,
    RefreshTokenStore,
};
pub use session::{plaintext_token_allowed, totp_from_secret, LoginResult, Session, SessionStatus};
pub use vault_api::normalize_server_url;
