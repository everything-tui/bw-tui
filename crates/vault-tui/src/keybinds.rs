//! Runtime keybinding resolution with config.toml overrides.

use std::collections::HashMap;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::action::Action;
use crate::config::KeybindingOverrides;

/// Parsed binding: modifiers + key code.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeySpec {
    pub modifiers: KeyModifiers,
    pub code: KeyCode,
}

impl KeySpec {
    pub fn matches(&self, key: &KeyEvent) -> bool {
        // Ignore SHIFT on letters (crossterm encodes Shift+c as Char('C')).
        let self_mods = self.modifiers - KeyModifiers::SHIFT;
        let key_mods = key.modifiers - KeyModifiers::SHIFT;
        self_mods == key_mods && codes_eq(&self.code, &key.code)
    }
}

fn codes_eq(a: &KeyCode, b: &KeyCode) -> bool {
    match (a, b) {
        (KeyCode::Char(x), KeyCode::Char(y)) => x.eq_ignore_ascii_case(y),
        _ => a == b,
    }
}

/// Default vault-screen bindings (context-free global shortcuts).
fn default_bindings() -> HashMap<Action, KeySpec> {
    let mut m = HashMap::new();
    m.insert(Action::Quit, parse_keys("q").unwrap());
    m.insert(Action::ToggleHelp, parse_keys("?").unwrap());
    m.insert(Action::OpenProfileManager, parse_keys("Ctrl+p").unwrap());
    m.insert(Action::Lock, parse_keys("Ctrl+l").unwrap());
    m.insert(Action::Sync, parse_keys("Ctrl+s").unwrap());
    m.insert(Action::SearchStart, parse_keys("/").unwrap());
    m.insert(Action::MoveUp, parse_keys("k").unwrap());
    m.insert(Action::MoveDown, parse_keys("j").unwrap());
    m.insert(Action::CopyPassword, parse_keys("c").unwrap());
    m.insert(Action::CopyUsername, parse_keys("y").unwrap());
    m.insert(Action::CopyTotp, parse_keys("t").unwrap());
    m.insert(Action::CopyUri, parse_keys("u").unwrap());
    m.insert(Action::ToggleFavorite, parse_keys("f").unwrap());
    m.insert(Action::ToggleReveal, parse_keys("r").unwrap());
    m.insert(Action::NewLogin, parse_keys("n").unwrap());
    m.insert(Action::EditItem, parse_keys("e").unwrap());
    m.insert(Action::DeleteItem, parse_keys("d").unwrap());
    m.insert(Action::NewFolder, parse_keys("Ctrl+n").unwrap());
    m.insert(Action::OpenGenerator, parse_keys("g").unwrap());
    m.insert(Action::OpenPasswordHistory, parse_keys("H").unwrap());
    m.insert(Action::OpenHealthReport, parse_keys("R").unwrap());
    m.insert(Action::OpenCommandPalette, parse_keys(":").unwrap());
    m.insert(Action::CloneItem, parse_keys("Shift+C").unwrap());
    m.insert(Action::MoveToFolder, parse_keys("Shift+M").unwrap());
    m.insert(Action::ShareToOrg, parse_keys("Shift+O").unwrap());
    m.insert(Action::CopySendLink, parse_keys("L").unwrap());
    m.insert(Action::ReceiveSend, parse_keys("O").unwrap());
    m
}

/// Resolve action name (kebab/snake/label) to Action.
pub fn action_from_name(name: &str) -> Option<Action> {
    let n = name.trim().to_ascii_lowercase().replace(['-', ' '], "_");
    Some(match n.as_str() {
        "quit" => Action::Quit,
        "toggle_help" | "help" => Action::ToggleHelp,
        "open_profile_manager" | "profile_manager" | "profiles" => Action::OpenProfileManager,
        "lock" => Action::Lock,
        "sync" => Action::Sync,
        "search" | "search_start" => Action::SearchStart,
        "search_clear" | "clear_search" => Action::SearchClear,
        "move_up" | "up" => Action::MoveUp,
        "move_down" | "down" => Action::MoveDown,
        "page_up" => Action::PageUp,
        "page_down" => Action::PageDown,
        "home" => Action::Home,
        "end" => Action::End,
        "focus_next" | "next_pane" => Action::FocusNext,
        "focus_prev" | "prev_pane" => Action::FocusPrev,
        "copy_password" | "password" => Action::CopyPassword,
        "copy_username" | "username" => Action::CopyUsername,
        "copy_totp" | "totp" => Action::CopyTotp,
        "copy_uri" | "uri" => Action::CopyUri,
        "toggle_favorite" | "favorite" => Action::ToggleFavorite,
        "toggle_reveal" | "reveal" => Action::ToggleReveal,
        "new_login" | "new" => Action::NewLogin,
        "edit_item" | "edit" => Action::EditItem,
        "delete_item" | "delete" => Action::DeleteItem,
        "new_folder" => Action::NewFolder,
        "open_generator" | "generator" => Action::OpenGenerator,
        "open_password_history" | "password_history" | "history" => Action::OpenPasswordHistory,
        "open_health_report" | "health" | "health_report" => Action::OpenHealthReport,
        "open_command_palette" | "command_palette" | "palette" => Action::OpenCommandPalette,
        "clone_item" | "clone" => Action::CloneItem,
        "move_to_folder" | "move" => Action::MoveToFolder,
        "share_to_org" | "share" => Action::ShareToOrg,
        "copy_send_link" | "send_link" => Action::CopySendLink,
        "receive_send" | "open_send_link" | "open_send" => Action::ReceiveSend,
        "sign_out_profile" | "sign_out" => Action::SignOutProfile,
        _ => return None,
    })
}

/// Parse a key string like `Ctrl+q`, `Shift+M`, `g`, `F1`, `Esc`.
pub fn parse_keys(s: &str) -> Result<KeySpec, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty keybinding".into());
    }
    let mut modifiers = KeyModifiers::NONE;
    let parts: Vec<&str> = s.split('+').map(str::trim).collect();
    let (key_part, mod_parts) = parts
        .split_last()
        .ok_or_else(|| "empty keybinding".to_string())?;
    for m in mod_parts {
        match m.to_ascii_lowercase().as_str() {
            "ctrl" | "control" | "c" => modifiers |= KeyModifiers::CONTROL,
            "alt" | "option" | "a" | "m" | "meta" => modifiers |= KeyModifiers::ALT,
            "shift" | "s" => modifiers |= KeyModifiers::SHIFT,
            "super" | "cmd" | "win" => modifiers |= KeyModifiers::SUPER,
            other => return Err(format!("unknown modifier '{other}'")),
        }
    }
    let code = parse_key_code(key_part)?;
    Ok(KeySpec { modifiers, code })
}

fn parse_key_code(s: &str) -> Result<KeyCode, String> {
    let lower = s.to_ascii_lowercase();
    Ok(match lower.as_str() {
        "esc" | "escape" => KeyCode::Esc,
        "enter" | "return" => KeyCode::Enter,
        "tab" => KeyCode::Tab,
        "backtab" => KeyCode::BackTab,
        "backspace" => KeyCode::Backspace,
        "delete" | "del" => KeyCode::Delete,
        "up" => KeyCode::Up,
        "down" => KeyCode::Down,
        "left" => KeyCode::Left,
        "right" => KeyCode::Right,
        "home" => KeyCode::Home,
        "end" => KeyCode::End,
        "pageup" | "pgup" => KeyCode::PageUp,
        "pagedown" | "pgdn" | "pgdown" => KeyCode::PageDown,
        "space" => KeyCode::Char(' '),
        "f1" => KeyCode::F(1),
        "f2" => KeyCode::F(2),
        "f3" => KeyCode::F(3),
        "f4" => KeyCode::F(4),
        "f5" => KeyCode::F(5),
        "f6" => KeyCode::F(6),
        "f7" => KeyCode::F(7),
        "f8" => KeyCode::F(8),
        "f9" => KeyCode::F(9),
        "f10" => KeyCode::F(10),
        "f11" => KeyCode::F(11),
        "f12" => KeyCode::F(12),
        other if other.chars().count() == 1 => {
            let c = s.chars().next().unwrap();
            KeyCode::Char(c)
        }
        other => return Err(format!("unknown key '{other}'")),
    })
}

#[derive(Debug, Clone)]
pub struct KeyMap {
    bindings: HashMap<Action, KeySpec>,
    /// Reverse lookup for conflict detection / help.
    by_key: HashMap<KeySpec, Action>,
    pub warnings: Vec<String>,
}

impl KeyMap {
    pub fn resolve(overrides: &KeybindingOverrides) -> Self {
        let mut bindings = default_bindings();
        let mut warnings = Vec::new();

        for entry in &overrides.overrides {
            let Some(action) = action_from_name(&entry.action) else {
                warnings.push(format!("unknown action '{}'", entry.action));
                continue;
            };
            match parse_keys(&entry.keys) {
                Ok(spec) => {
                    bindings.insert(action, spec);
                }
                Err(e) => warnings.push(format!(
                    "invalid keys '{}' for '{}': {e}",
                    entry.keys, entry.action
                )),
            }
        }

        let mut by_key: HashMap<KeySpec, Action> = HashMap::new();
        for (action, spec) in &bindings {
            if let Some(prev) = by_key.insert(spec.clone(), action.clone()) {
                warnings.push(format!(
                    "key conflict: {:?} bound to both {:?} and {:?}",
                    spec, prev, action
                ));
            }
        }

        Self {
            bindings,
            by_key,
            warnings,
        }
    }

    pub fn action_for(&self, key: &KeyEvent) -> Option<Action> {
        self.by_key
            .iter()
            .find(|(spec, _)| spec.matches(key))
            .map(|(_, a)| a.clone())
    }

    pub fn keys_for(&self, action: &Action) -> Option<&KeySpec> {
        self.bindings.get(action)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::KeybindingOverride;

    #[test]
    fn parse_ctrl_q() {
        let spec = parse_keys("Ctrl+q").unwrap();
        assert!(spec.modifiers.contains(KeyModifiers::CONTROL));
        assert_eq!(spec.code, KeyCode::Char('q'));
    }

    #[test]
    fn override_quit() {
        let overrides = KeybindingOverrides {
            overrides: vec![KeybindingOverride {
                action: "quit".into(),
                keys: "Ctrl+q".into(),
            }],
        };
        let map = KeyMap::resolve(&overrides);
        let key = KeyEvent::new(KeyCode::Char('q'), KeyModifiers::CONTROL);
        assert_eq!(map.action_for(&key), Some(Action::Quit));
    }
}
