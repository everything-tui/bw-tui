//! User preferences loaded from `config.toml` under the app data directory.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use vault_session::{app_data_dir, ensure_dir, GeneratorOptions};

use crate::ui::CustomThemeColors;

const CONFIG_FILE: &str = "config.toml";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppConfig {
    /// UI theme name: `default`, `light`, `high-contrast`, `solarized`, or custom.
    #[serde(default = "default_theme")]
    pub theme: String,
    /// Optional RGB color overrides for the active theme.
    #[serde(default)]
    pub colors: ThemeColorConfig,
    /// Let the terminal background show through the main panes.
    #[serde(default)]
    pub transparent_background: bool,
    /// Per-action keybinding overrides.
    #[serde(default)]
    pub keybindings: KeybindingOverrides,
    /// Default password generator options for the TUI / CLI.
    #[serde(default)]
    pub generator: GeneratorConfig,
    /// Background vault sync while unlocked.
    #[serde(default)]
    pub sync: SyncConfig,
    /// Enable mouse click/scroll interactions.
    #[serde(default)]
    pub mouse: bool,
    /// Power-user features (copy sequence, auto-type, SSH agent confirmation, sorting).
    #[serde(default)]
    pub power: PowerConfig,
}

/// Settings for the P4 power-user features.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PowerConfig {
    /// Copy sequence (`S`): offer TOTP as a third step after the password.
    #[serde(default = "default_true")]
    pub copy_sequence_totp: bool,
    /// Ask for confirmation (listing the keys) before starting the SSH agent.
    #[serde(default = "default_true")]
    pub ssh_agent_confirm: bool,
    /// Add agent keys with `ssh-add -c` (requires an `SSH_ASKPASS` helper).
    #[serde(default)]
    pub ssh_agent_confirm_each_use: bool,
    /// Seconds to wait before auto-typing so the target window can be focused.
    #[serde(default = "default_autotype_delay")]
    pub autotype_delay_secs: u64,
    /// Press Tab between username and password and Enter after the last field when auto-typing.
    #[serde(default = "default_true")]
    pub autotype_press_enter: bool,
    /// Initial vault sort: `name`, `recent`, or `modified`.
    #[serde(default = "default_sort")]
    pub default_sort: String,
}

impl Default for PowerConfig {
    fn default() -> Self {
        Self {
            copy_sequence_totp: true,
            ssh_agent_confirm: true,
            ssh_agent_confirm_each_use: false,
            autotype_delay_secs: default_autotype_delay(),
            autotype_press_enter: true,
            default_sort: default_sort(),
        }
    }
}

fn default_autotype_delay() -> u64 {
    3
}

fn default_sort() -> String {
    "name".into()
}

/// `[colors]`: per-token overrides on top of the selected theme, e.g.
/// `accent = "#ff79c6"`. Any name in `ui::theme::TOKEN_NAMES` is accepted.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ThemeColorConfig {
    #[serde(flatten)]
    pub tokens: BTreeMap<String, String>,
}

impl ThemeColorConfig {
    pub fn to_custom(&self, transparent: bool) -> CustomThemeColors {
        let mut overrides = Vec::new();
        for (name, value) in &self.tokens {
            if !crate::ui::theme::TOKEN_NAMES.contains(&name.as_str()) {
                tracing::warn!("[colors]: unknown token '{name}'");
                continue;
            }
            match parse_rgb(Some(value)) {
                Some(c) => overrides.push((name.clone(), c)),
                None => tracing::warn!("[colors]: invalid color '{value}' for '{name}'"),
            }
        }
        CustomThemeColors {
            overrides,
            transparent,
        }
    }

    pub fn has_any(&self) -> bool {
        !self.tokens.is_empty()
    }
}

fn parse_rgb(s: Option<&str>) -> Option<(u8, u8, u8)> {
    let s = s?.trim();
    if let Some(hex) = s.strip_prefix('#') {
        if hex.len() == 6 {
            let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
            let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
            let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
            return Some((r, g, b));
        }
    }
    let parts: Vec<_> = s.split(',').map(str::trim).collect();
    if parts.len() == 3 {
        let r = parts[0].parse().ok()?;
        let g = parts[1].parse().ok()?;
        let b = parts[2].parse().ok()?;
        return Some((r, g, b));
    }
    None
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncConfig {
    /// Periodic sync interval in minutes (`0` or absent = disabled).
    #[serde(default = "default_background_sync_minutes")]
    pub background_interval_minutes: Option<u64>,
    /// How often (seconds) to probe `GET /accounts/revision-date` while unlocked; a full `/sync`
    /// only runs when the revision changed. `0` disables the probe.
    ///
    /// This is the live-update mechanism: the SignalR/WebSocket notification hub
    /// (`/notifications/hub`) is not implemented, so changes made on other devices appear within
    /// one poll interval. `background_interval_minutes` remains as a forced full-sync fallback.
    #[serde(default = "default_revision_poll_seconds")]
    pub revision_poll_seconds: Option<u64>,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            background_interval_minutes: default_background_sync_minutes(),
            revision_poll_seconds: default_revision_poll_seconds(),
        }
    }
}

fn default_revision_poll_seconds() -> Option<u64> {
    Some(60)
}

fn default_background_sync_minutes() -> Option<u64> {
    Some(5)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeybindingOverrides {
    /// Example: `{ action = "quit", keys = "Ctrl+q" }`
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
            colors: ThemeColorConfig::default(),
            transparent_background: false,
            keybindings: KeybindingOverrides::default(),
            generator: GeneratorConfig::default(),
            sync: SyncConfig::default(),
            mouse: false,
            power: PowerConfig::default(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn colors_table_accepts_any_token() {
        let cfg: AppConfig = toml::from_str(
            "theme = \"nord\"\ntransparent_background = true\n[colors]\naccent = \"#ff0000\"\nsurface = \"1, 2, 3\"\n",
        )
        .unwrap();
        let custom = cfg.colors.to_custom(cfg.transparent_background);
        assert!(custom.transparent);
        assert_eq!(custom.overrides.len(), 2);
    }

    #[test]
    fn parse_hex_and_csv_rgb() {
        assert_eq!(parse_rgb(Some("#af52de")), Some((175, 82, 222)));
        assert_eq!(parse_rgb(Some("175, 82, 222")), Some((175, 82, 222)));
    }
}
