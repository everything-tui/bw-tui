//! Application data directory helpers.

use std::io::Write;
use std::path::{Path, PathBuf};

use directories::ProjectDirs;

use crate::error::{Result, SessionError};

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

/// Create `path` and parents with mode `0700` on Unix.
pub fn ensure_dir(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() {
        return Err(SessionError::Other("empty directory path".into()));
    }
    if path.is_dir() {
        #[cfg(unix)]
        tighten_dir_mode(path);
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(path)?;
    }
    Ok(())
}

#[cfg(unix)]
fn tighten_dir_mode(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
}

/// Write `data` to `path` atomically (`.tmp` → fsync → rename). File mode `0600` on Unix.
pub fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Err(SessionError::Other("path has no parent directory".into()));
    };
    ensure_dir(parent)?;

    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let tmp_path = parent.join(format!(".{file_name}.{}.tmp", std::process::id()));

    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)?;
        file.write_all(data)?;
        file.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&tmp_path, data)?;
    }

    std::fs::rename(&tmp_path, path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_atomic_creates_target_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auth.json");
        write_atomic(&path, br#"{"ok":true}"#).unwrap();
        assert!(path.is_file());
        assert_eq!(std::fs::read(&path).unwrap(), br#"{"ok":true}"#);
        assert!(!dir.path().join(".auth.json.tmp").exists());
    }

    #[test]
    fn ensure_dir_creates_hierarchy() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a").join("b");
        ensure_dir(&nested).unwrap();
        assert!(nested.is_dir());
    }
}
