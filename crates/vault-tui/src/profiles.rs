//! Named vault profiles registry (`profiles.json` + per-profile auth dirs).

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use vault_session::{app_data_dir, profile_dir, profiles_file};

/// On-disk profile registry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfilesFile {
    pub version: u32,
    pub active: String,
    /// When true, switching profiles locks/drops the outgoing session.
    /// When false (default), unlocked sessions stay parked in memory.
    #[serde(default)]
    pub lock_on_profile_switch: bool,
    pub profiles: Vec<VaultProfile>,
}

/// A local named account slot (not the Bitwarden sync Profile API type).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultProfile {
    pub id: String,
    pub name: String,
    pub server_url: String,
    pub email: String,
    /// Idle auto-lock in minutes. `None` disables auto-lock.
    #[serde(default = "default_auto_lock_minutes")]
    pub auto_lock_minutes: Option<u64>,
}

const REGISTRY_VERSION: u32 = 1;
const MAX_AUTO_LOCK_MINUTES: u64 = 24 * 60;

fn default_auto_lock_minutes() -> Option<u64> {
    Some(15)
}

/// Legacy login prefs (pre-profiles).
#[derive(Debug, Clone, Deserialize)]
struct LegacySavedLogin {
    server_url: String,
    email: String,
}

/// Legacy auth.json fields we need for migration (ignore the rest via deny_unknown_fields off).
#[derive(Debug, Clone, Deserialize)]
struct LegacyAuthHint {
    server_url: String,
    email: String,
}

impl ProfilesFile {
    pub fn empty_default() -> Self {
        Self {
            version: REGISTRY_VERSION,
            active: "default".into(),
            lock_on_profile_switch: false,
            profiles: vec![VaultProfile {
                id: "default".into(),
                name: "default".into(),
                server_url: String::new(),
                email: String::new(),
                auto_lock_minutes: default_auto_lock_minutes(),
            }],
        }
    }

    pub fn get(&self, id: &str) -> Option<&VaultProfile> {
        self.profiles.iter().find(|p| p.id == id)
    }

    pub fn get_mut(&mut self, id: &str) -> Option<&mut VaultProfile> {
        self.profiles.iter_mut().find(|p| p.id == id)
    }

    pub fn active_profile(&self) -> Option<&VaultProfile> {
        self.get(&self.active)
    }
}

/// Validate profile id slug: `^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$` (1–64 chars).
pub fn validate_profile_id(id: &str) -> Result<(), String> {
    let len = id.len();
    if len == 0 || len > 64 {
        return Err("Profile id must be 1–64 characters".into());
    }
    let bytes = id.as_bytes();
    if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
        return Err("Profile id must start with a-z or 0-9".into());
    }
    if len > 1 {
        let last = bytes[len - 1];
        if !last.is_ascii_lowercase() && !last.is_ascii_digit() {
            return Err("Profile id must end with a-z or 0-9".into());
        }
        for &b in &bytes[1..len - 1] {
            if !(b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
                return Err("Profile id may only contain a-z, 0-9, and hyphen".into());
            }
        }
    }
    Ok(())
}

/// Suggest a slug from a display name.
pub fn slugify_suggestion(name: &str) -> String {
    let mut out = String::new();
    let mut prev_hyphen = false;
    for c in name.chars() {
        let lower = c.to_ascii_lowercase();
        if lower.is_ascii_alphanumeric() {
            out.push(lower);
            prev_hyphen = false;
        } else if !out.is_empty() && !prev_hyphen {
            out.push('-');
            prev_hyphen = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        return "profile".into();
    }
    out.truncate(64);
    while out.ends_with('-') {
        out.pop();
    }
    if validate_profile_id(&out).is_err() {
        "profile".into()
    } else {
        out
    }
}

/// Allocate a unique profile id from a display name (`work`, `work-2`, …).
pub fn allocate_profile_id(file: &ProfilesFile, name: &str) -> String {
    let base = slugify_suggestion(name);
    if file.get(&base).is_none() {
        return base;
    }
    for n in 2u32..10_000 {
        let candidate = {
            let suffix = format!("-{n}");
            let max_base = 64usize.saturating_sub(suffix.len());
            let mut b = base.clone();
            b.truncate(max_base);
            while b.ends_with('-') {
                b.pop();
            }
            if b.is_empty() {
                b = "profile".into();
            }
            format!("{b}{suffix}")
        };
        if validate_profile_id(&candidate).is_ok() && file.get(&candidate).is_none() {
            return candidate;
        }
    }
    format!("profile-{}", uuid_lite())
}

fn uuid_lite() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{nanos:x}")
}

pub fn load_registry() -> ProfilesFile {
    load_registry_from(&app_data_dir())
}

pub fn save_registry(file: &ProfilesFile) -> Result<(), String> {
    save_registry_to(&app_data_dir(), file)
}

pub fn load_registry_from(root: &Path) -> ProfilesFile {
    let path = profiles_file(root);
    if path.exists() {
        if let Ok(json) = fs::read_to_string(&path) {
            if let Ok(mut file) = serde_json::from_str::<ProfilesFile>(&json) {
                normalize_registry(&mut file, root);
                let _ = save_registry_to(root, &file);
                return file;
            }
        }
    }

    if let Some(migrated) = migrate_legacy(root) {
        let _ = save_registry_to(root, &migrated);
        return migrated;
    }

    let file = ProfilesFile::empty_default();
    let _ = save_registry_to(root, &file);
    let _ = fs::create_dir_all(profile_dir(root, "default"));
    file
}

pub fn save_registry_to(root: &Path, file: &ProfilesFile) -> Result<(), String> {
    let path = profiles_file(root);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let json = serde_json::to_string_pretty(file).map_err(|e| e.to_string())?;
    fs::write(path, json).map_err(|e| e.to_string())
}

fn normalize_registry(file: &mut ProfilesFile, root: &Path) {
    file.version = REGISTRY_VERSION;
    file.profiles.retain(|p| validate_profile_id(&p.id).is_ok());
    if file.profiles.is_empty() {
        *file = ProfilesFile::empty_default();
    }
    if file.get(&file.active).is_none() {
        file.active = file.profiles[0].id.clone();
    }
    for p in &file.profiles {
        let _ = fs::create_dir_all(profile_dir(root, &p.id));
    }
}

fn migrate_legacy(root: &Path) -> Option<ProfilesFile> {
    let login_path = root.join("login.json");
    let auth_path = root.join("auth.json");
    if !login_path.exists() && !auth_path.exists() {
        return None;
    }

    let mut server_url = String::new();
    let mut email = String::new();

    if let Ok(json) = fs::read_to_string(&login_path) {
        if let Ok(saved) = serde_json::from_str::<LegacySavedLogin>(&json) {
            server_url = saved.server_url.trim().to_string();
            email = saved.email.trim().to_string();
        }
    }
    if (server_url.is_empty() || email.is_empty()) && auth_path.exists() {
        if let Ok(json) = fs::read_to_string(&auth_path) {
            if let Ok(auth) = serde_json::from_str::<LegacyAuthHint>(&json) {
                if server_url.is_empty() {
                    server_url = auth.server_url.trim().to_string();
                }
                if email.is_empty() {
                    email = auth.email.trim().to_string();
                }
            }
        }
    }

    let dest_dir = profile_dir(root, "default");
    let _ = fs::create_dir_all(&dest_dir);
    if auth_path.exists() {
        let dest = dest_dir.join("auth.json");
        if !dest.exists() {
            let _ = fs::rename(&auth_path, &dest).or_else(|_| {
                fs::copy(&auth_path, &dest)?;
                fs::remove_file(&auth_path)
            });
        } else {
            let _ = fs::remove_file(&auth_path);
        }
    }
    let _ = fs::remove_file(&login_path);

    Some(ProfilesFile {
        version: REGISTRY_VERSION,
        active: "default".into(),
        lock_on_profile_switch: false,
        profiles: vec![VaultProfile {
            id: "default".into(),
            name: "default".into(),
            server_url,
            email,
            auto_lock_minutes: default_auto_lock_minutes(),
        }],
    })
}

pub fn active_profile_dir_for(root: &Path, file: &ProfilesFile) -> PathBuf {
    profile_dir(root, &file.active)
}

pub fn active_profile_dir() -> PathBuf {
    let root = app_data_dir();
    let file = load_registry_from(&root);
    active_profile_dir_for(&root, &file)
}

pub fn profile_has_auth(root: &Path, id: &str) -> bool {
    profile_dir(root, id).join("auth.json").exists()
}

/// Create a profile with an auto-generated id. Returns the new id.
pub fn create_profile(
    root: &Path,
    file: &mut ProfilesFile,
    name: &str,
    server_url: &str,
) -> Result<String, String> {
    let display = name.trim();
    if display.is_empty() {
        return Err("Name cannot be empty".into());
    }
    let id = allocate_profile_id(file, display);
    fs::create_dir_all(profile_dir(root, &id)).map_err(|e| e.to_string())?;
    file.profiles.push(VaultProfile {
        id: id.clone(),
        name: display.to_string(),
        server_url: server_url.trim().to_string(),
        email: String::new(),
        auto_lock_minutes: default_auto_lock_minutes(),
    });
    save_registry_to(root, file)?;
    Ok(id)
}

/// Parse TUI input: `off` / `0` / empty → disabled; `1..=1440` → minutes.
pub fn parse_auto_lock_input(raw: &str) -> Result<Option<u64>, String> {
    let t = raw.trim().to_ascii_lowercase();
    if t.is_empty() || t == "off" || t == "0" {
        return Ok(None);
    }
    let mins: u64 = t
        .parse()
        .map_err(|_| "Enter minutes (1–1440), or off / 0 to disable".to_string())?;
    if !(1..=MAX_AUTO_LOCK_MINUTES).contains(&mins) {
        return Err(format!(
            "Minutes must be 1–{MAX_AUTO_LOCK_MINUTES}, or off / 0 to disable"
        ));
    }
    Ok(Some(mins))
}

pub fn update_profile_auto_lock(
    root: &Path,
    file: &mut ProfilesFile,
    id: &str,
    minutes: Option<u64>,
) -> Result<(), String> {
    if let Some(m) = minutes {
        if !(1..=MAX_AUTO_LOCK_MINUTES).contains(&m) {
            return Err(format!("Minutes must be 1–{MAX_AUTO_LOCK_MINUTES}"));
        }
    }
    let profile = file
        .get_mut(id)
        .ok_or_else(|| format!("Unknown profile '{id}'"))?;
    profile.auto_lock_minutes = minutes;
    save_registry_to(root, file)
}

pub fn format_auto_lock_label(minutes: Option<u64>) -> String {
    match minutes {
        None => "lock off".into(),
        Some(m) => format!("lock {m}m"),
    }
}

pub fn format_auto_lock_input(minutes: Option<u64>) -> String {
    match minutes {
        None => "off".into(),
        Some(m) => m.to_string(),
    }
}

pub fn rename_profile(
    root: &Path,
    file: &mut ProfilesFile,
    id: &str,
    name: &str,
) -> Result<(), String> {
    let display = name.trim();
    if display.is_empty() {
        return Err("Name cannot be empty".into());
    }
    let profile = file
        .get_mut(id)
        .ok_or_else(|| format!("Unknown profile '{id}'"))?;
    profile.name = display.to_string();
    save_registry_to(root, file)
}

/// Update name, server URL, email, and auto-lock for a profile in one save.
pub fn update_profile(
    root: &Path,
    file: &mut ProfilesFile,
    id: &str,
    name: &str,
    server_url: &str,
    email: &str,
    auto_lock_minutes: Option<u64>,
) -> Result<(), String> {
    let display = name.trim();
    if display.is_empty() {
        return Err("Name cannot be empty".into());
    }
    if let Some(m) = auto_lock_minutes {
        if !(1..=MAX_AUTO_LOCK_MINUTES).contains(&m) {
            return Err(format!("Minutes must be 1–{MAX_AUTO_LOCK_MINUTES}"));
        }
    }
    let profile = file
        .get_mut(id)
        .ok_or_else(|| format!("Unknown profile '{id}'"))?;
    profile.name = display.to_string();
    profile.server_url = server_url.trim().to_string();
    profile.email = email.trim().to_string();
    profile.auto_lock_minutes = auto_lock_minutes;
    save_registry_to(root, file)
}

pub fn set_lock_on_profile_switch(
    root: &Path,
    file: &mut ProfilesFile,
    enabled: bool,
) -> Result<(), String> {
    file.lock_on_profile_switch = enabled;
    save_registry_to(root, file)
}

pub fn set_active(root: &Path, file: &mut ProfilesFile, id: &str) -> Result<(), String> {
    if file.get(id).is_none() {
        return Err(format!("Unknown profile '{id}'"));
    }
    file.active = id.to_string();
    save_registry_to(root, file)
}

/// Delete a profile directory and registry entry. Recreates `default` if none remain.
/// Returns the new active profile id.
pub fn delete_profile(
    root: &Path,
    file: &mut ProfilesFile,
    id: &str,
) -> Result<String, String> {
    if file.get(id).is_none() {
        return Err(format!("Unknown profile '{id}'"));
    }
    let dir = profile_dir(root, id);
    if dir.exists() {
        fs::remove_dir_all(&dir).map_err(|e| e.to_string())?;
    }
    file.profiles.retain(|p| p.id != id);

    if file.profiles.is_empty() {
        *file = ProfilesFile::empty_default();
        let _ = fs::create_dir_all(profile_dir(root, "default"));
        save_registry_to(root, file)?;
        return Ok(file.active.clone());
    }

    if file.active == id {
        file.active = file.profiles[0].id.clone();
    }
    save_registry_to(root, file)?;
    Ok(file.active.clone())
}

pub fn update_profile_credentials(
    root: &Path,
    file: &mut ProfilesFile,
    id: &str,
    server_url: &str,
    email: &str,
) -> Result<(), String> {
    let profile = file
        .get_mut(id)
        .ok_or_else(|| format!("Unknown profile '{id}'"))?;
    profile.server_url = server_url.trim().to_string();
    profile.email = email.trim().to_string();
    save_registry_to(root, file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_profile_ids() {
        assert!(validate_profile_id("work").is_ok());
        assert!(validate_profile_id("a").is_ok());
        assert!(validate_profile_id("home-1").is_ok());
        assert!(validate_profile_id("").is_err());
        assert!(validate_profile_id("-work").is_err());
        assert!(validate_profile_id("work-").is_err());
        assert!(validate_profile_id("Work").is_err());
        assert!(validate_profile_id("has space").is_err());
    }

    #[test]
    fn slugify_basic() {
        assert_eq!(slugify_suggestion("Work Home"), "work-home");
        assert_eq!(slugify_suggestion("  "), "profile");
    }

    #[test]
    fn migrate_from_legacy_login_and_auth() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fs::write(
            root.join("login.json"),
            r#"{"server_url":"http://127.0.0.1:8080","email":"u@ex.com"}"#,
        )
        .unwrap();
        fs::write(
            root.join("auth.json"),
            r#"{"server_url":"http://127.0.0.1:8080","email":"u@ex.com","refresh_token":"r","device_id":"d"}"#,
        )
        .unwrap();

        let file = load_registry_from(root);
        assert_eq!(file.active, "default");
        assert_eq!(file.profiles.len(), 1);
        assert_eq!(file.profiles[0].email, "u@ex.com");
        assert_eq!(file.profiles[0].server_url, "http://127.0.0.1:8080");
        assert!(profile_dir(root, "default").join("auth.json").exists());
        assert!(!root.join("login.json").exists());
        assert!(!root.join("auth.json").exists());
        assert!(profiles_file(root).exists());
    }

    #[test]
    fn create_rename_delete_set_active() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let mut file = load_registry_from(root);
        let id = create_profile(root, &mut file, "Work", "http://vw.example").unwrap();
        assert_eq!(id, "work");
        assert!(file.get("work").is_some());
        assert_eq!(file.get("work").unwrap().server_url, "http://vw.example");
        assert!(profile_dir(root, "work").is_dir());

        rename_profile(root, &mut file, "work", "Office").unwrap();
        assert_eq!(file.get("work").unwrap().name, "Office");

        set_active(root, &mut file, "work").unwrap();
        assert_eq!(file.active, "work");

        let new_active = delete_profile(root, &mut file, "work").unwrap();
        assert_eq!(new_active, "default");
        assert!(file.get("work").is_none());
        assert!(!profile_dir(root, "work").exists());
    }

    #[test]
    fn delete_last_recreates_default() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let mut file = load_registry_from(root);
        let active = delete_profile(root, &mut file, "default").unwrap();
        assert_eq!(active, "default");
        assert_eq!(file.profiles.len(), 1);
        assert_eq!(file.profiles[0].id, "default");
    }

    #[test]
    fn auto_id_dedupes() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let mut file = load_registry_from(root);
        assert_eq!(
            create_profile(root, &mut file, "Work", "").unwrap(),
            "work"
        );
        assert_eq!(
            create_profile(root, &mut file, "Work", "").unwrap(),
            "work-2"
        );
        assert!(create_profile(root, &mut file, "   ", "").is_err());
    }

    #[test]
    fn auto_lock_defaults_and_update() {
        let json = r#"{"id":"a","name":"A","server_url":"","email":""}"#;
        let p: VaultProfile = serde_json::from_str(json).unwrap();
        assert_eq!(p.auto_lock_minutes, Some(15));

        assert_eq!(parse_auto_lock_input("off").unwrap(), None);
        assert_eq!(parse_auto_lock_input("0").unwrap(), None);
        assert_eq!(parse_auto_lock_input("").unwrap(), None);
        assert_eq!(parse_auto_lock_input("30").unwrap(), Some(30));
        assert!(parse_auto_lock_input("1441").is_err());

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let mut file = load_registry_from(root);
        update_profile_auto_lock(root, &mut file, "default", None).unwrap();
        assert_eq!(file.get("default").unwrap().auto_lock_minutes, None);
        update_profile_auto_lock(root, &mut file, "default", Some(45)).unwrap();
        assert_eq!(file.get("default").unwrap().auto_lock_minutes, Some(45));
        assert!(update_profile_auto_lock(root, &mut file, "default", Some(0)).is_err());
    }

    #[test]
    fn lock_on_profile_switch_defaults_false() {
        let json = r#"{"version":1,"active":"default","profiles":[{"id":"default","name":"default","server_url":"","email":""}]}"#;
        let file: ProfilesFile = serde_json::from_str(json).unwrap();
        assert!(!file.lock_on_profile_switch);

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let mut file = load_registry_from(root);
        assert!(!file.lock_on_profile_switch);
        set_lock_on_profile_switch(root, &mut file, true).unwrap();
        let reloaded = load_registry_from(root);
        assert!(reloaded.lock_on_profile_switch);
    }

    #[test]
    fn update_profile_writes_all_fields() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let mut file = load_registry_from(root);
        update_profile(
            root,
            &mut file,
            "default",
            "Home",
            "https://vw.example",
            "u@ex.com",
            Some(30),
        )
        .unwrap();
        let p = file.get("default").unwrap();
        assert_eq!(p.name, "Home");
        assert_eq!(p.server_url, "https://vw.example");
        assert_eq!(p.email, "u@ex.com");
        assert_eq!(p.auto_lock_minutes, Some(30));

        update_profile(root, &mut file, "default", "Home", "", "", None).unwrap();
        let p = file.get("default").unwrap();
        assert!(p.server_url.is_empty());
        assert!(p.email.is_empty());
        assert_eq!(p.auto_lock_minutes, None);
        assert!(update_profile(root, &mut file, "default", "  ", "", "", None).is_err());
    }
}
