//! Application data directory helpers.

use std::path::{Path, PathBuf};

use directories::ProjectDirs;

/// Root application data directory (shared by all profiles).
pub fn app_data_dir() -> PathBuf {
    ProjectDirs::from("com", "bitwarden-tui", "bitwarden-tui")
        .map(|p| p.data_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from(".bitwarden-tui"))
}

/// Directory containing per-profile subdirectories.
pub fn profiles_dir(root: &Path) -> PathBuf {
    root.join("profiles")
}

/// Data directory for a single named profile.
pub fn profile_dir(root: &Path, id: &str) -> PathBuf {
    profiles_dir(root).join(id)
}

/// Path to the profile registry file.
pub fn profiles_file(root: &Path) -> PathBuf {
    root.join("profiles.json")
}
