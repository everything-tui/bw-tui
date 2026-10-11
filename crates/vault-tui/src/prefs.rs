//! Persisted login preferences (server URL + email only — never the master password).

use std::fs;
use std::path::PathBuf;

use directories::ProjectDirs;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SavedLogin {
    pub server_url: String,
    pub email: String,
}

fn prefs_path() -> PathBuf {
    ProjectDirs::from("com", "bitwarden-tui", "bitwarden-tui")
        .map(|p| p.data_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from(".bitwarden-tui"))
        .join("login.json")
}

pub fn load_saved_login() -> Option<SavedLogin> {
    let path = prefs_path();
    let json = fs::read_to_string(path).ok()?;
    let saved: SavedLogin = serde_json::from_str(&json).ok()?;
    if saved.server_url.trim().is_empty() && saved.email.trim().is_empty() {
        return None;
    }
    Some(saved)
}

pub fn save_login(server_url: &str, email: &str) -> Result<(), String> {
    let path = prefs_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let saved = SavedLogin {
        server_url: server_url.trim().to_string(),
        email: email.trim().to_string(),
    };
    let json = serde_json::to_string_pretty(&saved).map_err(|e| e.to_string())?;
    fs::write(path, json).map_err(|e| e.to_string())
}

pub fn clear_saved_login() {
    let path = prefs_path();
    let _ = fs::remove_file(path);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_serde() {
        let s = SavedLogin {
            server_url: "http://127.0.0.1:8080".into(),
            email: "a@b.c".into(),
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: SavedLogin = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}
