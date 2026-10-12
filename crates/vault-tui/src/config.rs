//! User preferences loaded from `config.toml` under the app data directory.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use vault_session::{app_data_dir, ensure_dir, GeneratorOptions};

const CONFIG_FILE: &str = "config.toml";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppConfig {
    /// UI theme name (see `ui::theme`).
    #[serde(default = "default_theme")]
    pub theme: String,
    /// Per-action keybinding overrides (not wired yet — reserved for custom keymaps).
    #[serde(default)]
    pub keybindings: KeybindingOverrides,
    /// Default password generator options for the TUI / CLI.
    #[serde(default)]
    pub generator: GeneratorConfig,
    /// Background vault sync while unlocked.
    #[serde(default)]
    pub sync: SyncConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncConfig {
    /// Periodic sync interval in minutes (`0` or absent = disabled).
    #[serde(default = "default_background_sync_minutes")]
    pub background_interval_minutes: Option<u64>,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            background_interval_minutes: default_background_sync_minutes(),
        }
    }
}

fn default_background_sync_minutes() -> Option<u64> {
    Some(5)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeybindingOverrides {
    /// Example: `{ action = "quit", keys = "Ctrl+q" }` entries (stub).
    #[serde(default)]
    pub overrides: Vec<KeybindingOverride>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeybindingOverride {
    pub action: String,
    pub keys: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GeneratorConfig {
    #[serde(default = "default_gen_length")]
    pub length: usize,
    #[serde(default = "default_true")]
    pub uppercase: bool,
    #[serde(default = "default_true")]
    pub lowercase: bool,
    #[serde(default = "default_true")]
    pub digits: bool,
    #[serde(default = "default_true")]
    pub symbols: bool,
    #[serde(default)]
    pub avoid_ambiguous: bool,
    #[serde(default = "default_passphrase_words")]
    pub passphrase_words: usize,
}

impl Default for GeneratorConfig {
    fn default() -> Self {
        Self {
            length: default_gen_length(),
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
            avoid_ambiguous: false,
            passphrase_words: default_passphrase_words(),
        }
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            theme: default_theme(),
            keybindings: KeybindingOverrides::default(),
            generator: GeneratorConfig::default(),
            sync: SyncConfig::default(),
        }
    }
}

impl GeneratorConfig {
    pub fn to_session_options(&self) -> GeneratorOptions {
        GeneratorOptions {
            length: self.length,
            uppercase: self.uppercase,
            lowercase: self.lowercase,
            digits: self.digits,
            symbols: self.symbols,
            avoid_ambiguous: self.avoid_ambiguous,
            ..Default::default()
        }
    }
}

fn default_theme() -> String {
    "default".into()
}

fn default_gen_length() -> usize {
    20
}

fn default_passphrase_words() -> usize {
    6
}

fn default_true() -> bool {
    true
}

pub fn config_path(root: &Path) -> PathBuf {
    root.join(CONFIG_FILE)
}

pub fn load_config_from(root: &Path) -> AppConfig {
    let path = config_path(root);
    let Ok(raw) = fs::read_to_string(&path) else {
        return AppConfig::default();
    };
    toml::from_str(&raw).unwrap_or_else(|e| {
        tracing::warn!("invalid {CONFIG_FILE}: {e}");
        AppConfig::default()
    })
}

pub fn load_config() -> AppConfig {
    load_config_from(&app_data_dir())
}

/// Write config atomically (creates app data dir if needed).
pub fn save_config(root: &Path, config: &AppConfig) -> std::io::Result<()> {
    ensure_dir(root).map_err(|e| std::io::Error::other(e.to_string()))?;
    let path = config_path(root);
    let body = toml::to_string_pretty(config).map_err(std::io::Error::other)?;
    vault_session::write_atomic(&path, body.as_bytes()).map_err(std::io::Error::other)
}
