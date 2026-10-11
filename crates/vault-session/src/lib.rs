//! Vault session: login, unlock, sync, decrypt, CRUD, clipboard.

mod clipboard;
mod decrypt;
mod error;
mod generator;
mod models;
mod paths;
mod session;

pub use clipboard::ClipboardService;
pub use error::{Result, SessionError};
pub use generator::generate_password;
pub use models::*;
pub use paths::{app_data_dir, profile_dir, profiles_dir, profiles_file};
pub use session::{LoginResult, Session, SessionStatus};
pub use vault_api::normalize_server_url;
