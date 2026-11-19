//! Runtime keybinding resolution with config.toml overrides.

use std::collections::HashMap;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::action::{Action, Scope};
use crate::config::KeybindingOverrides;

/// Parsed binding: modifiers + key code, normalized so it can be hashed against
/// incoming events. Characters are case-sensitive (`c` ≠ `C`) and carry no SHIFT
/// bit, since terminals disagree on whether `C` arrives with SHIFT set.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeySpec {
    pub modifiers: KeyModifiers,
    pub code: KeyCode,
}

impl KeySpec {
    fn normalized(code: KeyCode, modifiers: KeyModifiers) -> Self {
        let mut modifiers = modifiers;
        let code = match code {
            KeyCode::Char(c) => {
                let shifted = modifiers.contains(KeyModifiers::SHIFT);
                modifiers.remove(KeyModifiers::SHIFT);
                // `Ctrl+Shift+c` style specs: keep the letter uppercase.
                KeyCode::Char(if shifted { c.to_ascii_uppercase() } else { c })
            }
            KeyCode::BackTab => {
                modifiers.remove(KeyModifiers::SHIFT);
                KeyCode::BackTab
            }
            KeyCode::Tab if modifiers.contains(KeyModifiers::SHIFT) => {
                modifiers.remove(KeyModifiers::SHIFT);
                KeyCode::BackTab
            }
            other => other,
        };
        // Ctrl+letter arrives lowercase from most terminals.
        let code = match code {
            KeyCode::Char(c) if modifiers.contains(KeyModifiers::CONTROL) => {
                KeyCode::Char(c.to_ascii_lowercase())
            }
            other => other,
        };
        Self { modifiers, code }
    }

    pub fn from_event(key: &KeyEvent) -> Self {
        Self::normalized(key.code, key.modifiers)
    }

    pub fn matches(&self, key: &KeyEvent) -> bool {
        *self == Self::from_event(key)
    }

    /// Short human label: `c`, `C`, `Ctrl+s`, `Space`, `⏎`, `Tab`.
    pub fn display(&self) -> String {
        let key = match self.code {
            KeyCode::Char(' ') => "Space".to_string(),
            KeyCode::Char(c) => c.to_string(),
            KeyCode::Enter => "Enter".into(),
            KeyCode::Esc => "Esc".into(),
            KeyCode::Tab => "Tab".into(),
            KeyCode::BackTab => "Shift+Tab".into(),
            KeyCode::Backspace => "Backspace".into(),
            KeyCode::Delete => "Del".into(),
            KeyCode::Up => "↑".into(),
            KeyCode::Down => "↓".into(),
            KeyCode::Left => "←".into(),
            KeyCode::Right => "→".into(),
            KeyCode::Home => "Home".into(),
            KeyCode::End => "End".into(),
            KeyCode::PageUp => "PgUp".into(),
            KeyCode::PageDown => "PgDn".into(),
            KeyCode::F(n) => format!("F{n}"),
            other => format!("{other:?}"),
        };
        let mut out = String::new();
        if self.modifiers.contains(KeyModifiers::CONTROL) {
            out.push_str("Ctrl+");
        }
        if self.modifiers.contains(KeyModifiers::ALT) {
            out.push_str("Alt+");
        }
        if self.modifiers.contains(KeyModifiers::SUPER) {
            out.push_str("Super+");
        }
        out.push_str(&key);
        out
    }
}

/// Default vault-screen bindings. Each action may have several keys; the first
/// is the one shown in compact hints.
fn default_keys(action: Action) -> &'static [&'static str] {
    use Action::*;
    match action {
        MoveUp => &["k", "Up"],
        MoveDown => &["j", "Down"],
        PageUp => &["Ctrl+u", "PageUp"],
        PageDown => &["Ctrl+d", "PageDown"],
        Top => &["Home"],
        Bottom => &["G", "End"],
        FocusLeft => &["h", "Left"],
        FocusRight => &["l", "Right"],
        FocusNext => &["Tab"],
        FocusPrev => &["Shift+Tab"],
        Open => &["Enter"],
        Back => &["Esc"],
        SearchStart => &["/"],
        GotoPrefix => &["g"],
        CopyPassword => &["c"],
        CopyUsername => &["y"],
        CopyTotp => &["t"],
        CopyUri => &["u"],
        CopyNotes => &["o"],
        CopyCardNumber => &["m"],
        CopyCardCode => &["v"],
        CopyCardExpiry => &["x"],
        CopySshPublic => &["p"],
        CopySshPrivate => &["b"],
        CopySequence => &["S"],
        New => &["n"],
        Edit => &["e"],
        Delete => &["d"],
        ToggleFavorite => &["f"],
        ToggleReveal => &["r"],
        ToggleMark => &["Space"],
        CloneItem => &["C"],
        MoveToFolder => &["M"],
        ShareToOrg => &["O"],
        UndoDelete => &["U"],
        EditNotesExternal => &["E"],
        EditCustomFields => &["F"],
        Attachments => &["V"],
        UploadAttachment => &["A"],
        PasswordHistory => &["H"],
        ShowQr => &["Q"],
        AutoType => &["a"],
        AutoTypeTotp => &["T"],
        CycleSort => &["s"],
        Restore => &["r"],
        EmptyTrash => &["X"],
        CopySendLink => &["c", "L"],
        ReceiveSend => &["o"],
        OpenGenerator => &["P"],
        ChangeTheme => &["Ctrl+t"],
        OpenHealthReport => &["R"],
        DomainRules => &["D"],
        AccountSettings => &[","],
        NewFolder => &["Ctrl+n"],
        Sync => &["Ctrl+s"],
        Lock => &["Ctrl+l"],
        OpenProfileManager => &["Ctrl+p"],
        OpenCommandPalette => &[":", "Ctrl+k"],
        ToggleHelp => &["?"],
        Quit => &["q"],
        GotoAll | GotoFavorites | GotoLogins | GotoNotes | GotoCards | GotoIdentities
        | GotoSshKeys | GotoSends | GotoTrash | NewSend | SignOutProfile => &[],
    }
}

/// Resolve action name (kebab/snake/label) to Action. Old names stay accepted
/// so existing config.toml files keep working.
pub fn action_from_name(name: &str) -> Option<Action> {
    let n = name.trim().to_ascii_lowercase().replace(['-', ' '], "_");
    if let Some(a) = Action::all().iter().find(|a| snake_name(**a) == n).copied() {
        return Some(a);
    }
    Some(match n.as_str() {
        "toggle_help" | "help" => Action::ToggleHelp,
        "profile_manager" | "profiles" => Action::OpenProfileManager,
        "search" => Action::SearchStart,
        "search_clear" | "clear_search" => Action::Back,
        "up" => Action::MoveUp,
        "down" => Action::MoveDown,
        "home" => Action::Top,
        "end" => Action::Bottom,
        "next_pane" => Action::FocusNext,
        "prev_pane" => Action::FocusPrev,
        "password" => Action::CopyPassword,
        "username" => Action::CopyUsername,
        "totp" => Action::CopyTotp,
        "uri" => Action::CopyUri,
        "favorite" => Action::ToggleFavorite,
        "reveal" => Action::ToggleReveal,
        "new_login" | "new_item" => Action::New,
        "edit_item" => Action::Edit,
        "delete_item" => Action::Delete,
        "generator" => Action::OpenGenerator,
        "open_password_history" | "history" => Action::PasswordHistory,
        "health" | "health_report" => Action::OpenHealthReport,
        "command_palette" | "palette" => Action::OpenCommandPalette,
        "clone" => Action::CloneItem,
        "move" => Action::MoveToFolder,
        "share" => Action::ShareToOrg,
        "send_link" => Action::CopySendLink,
        "open_send_link" | "open_send" => Action::ReceiveSend,
        "sign_out" => Action::SignOutProfile,
        "undo" => Action::UndoDelete,
        "mark" => Action::ToggleMark,
        "sort" => Action::CycleSort,
        "qr" => Action::ShowQr,
        "settings" => Action::AccountSettings,
        "theme" => Action::ChangeTheme,
        _ => return None,
    })
}

/// `CopyPassword` → `copy_password` (the canonical config name).
pub fn snake_name(action: Action) -> String {
    let dbg = format!("{action:?}");
    let mut out = String::new();
    for (i, ch) in dbg.chars().enumerate() {
        if ch.is_ascii_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

/// Parse a key string like `Ctrl+q`, `Shift+M`, `g`, `F1`, `Esc`.
pub fn parse_keys(s: &str) -> Result<KeySpec, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty keybinding".into());
    }
    // A lone `+` is the plus key, not a separator.
    if s == "+" {
        return Ok(KeySpec::normalized(KeyCode::Char('+'), KeyModifiers::NONE));
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
    Ok(KeySpec::normalized(code, modifiers))
}

/// Parse a whitespace-separated list of keys: `"j Down"`.
pub fn parse_key_list(s: &str) -> Result<Vec<KeySpec>, String> {
    let specs: Vec<KeySpec> = s
        .split_whitespace()
        .map(parse_keys)
        .collect::<Result<_, _>>()?;
    if specs.is_empty() {
        return Err("empty keybinding".into());
    }
    Ok(specs)
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
        f if f.len() >= 2 && f.starts_with('f') && f[1..].parse::<u8>().is_ok() => {
            let n: u8 = f[1..].parse().unwrap();
            if !(1..=12).contains(&n) {
                return Err(format!("unknown key '{s}'"));
            }
            KeyCode::F(n)
        }
        _ if s.chars().count() == 1 => KeyCode::Char(s.chars().next().unwrap()),
        other => return Err(format!("unknown key '{other}'")),
    })
}

/// Which scopes are live right now (see [`Scope`]).
#[derive(Debug, Clone, Copy, Default)]
pub struct KeyContext {
    pub sends: bool,
    pub trash: bool,
}

impl KeyContext {
    fn active(self, scope: Scope) -> bool {
        match scope {
            Scope::Global => true,
            Scope::Ciphers => !self.sends,
            Scope::Trash => self.trash,
            Scope::Sends => self.sends,
        }
    }
}

#[derive(Debug, Clone)]
pub struct KeyMap {
    bindings: HashMap<Action, Vec<KeySpec>>,
    /// Reverse lookup; several actions may share a key in disjoint scopes.
    by_key: HashMap<KeySpec, Vec<Action>>,
    pub warnings: Vec<String>,
}

impl Default for KeyMap {
    fn default() -> Self {
        Self::resolve(&KeybindingOverrides::default())
    }
}

impl KeyMap {
    pub fn resolve(overrides: &KeybindingOverrides) -> Self {
        let mut bindings: HashMap<Action, Vec<KeySpec>> = Action::all()
            .iter()
            .map(|&a| {
                let keys = default_keys(a)
                    .iter()
                    .map(|k| parse_keys(k).expect("default keybinding parses"))
                    .collect();
                (a, keys)
            })
            .collect();
        let mut warnings = Vec::new();

        for entry in &overrides.overrides {
            let Some(action) = action_from_name(&entry.action) else {
                warnings.push(format!("unknown action '{}'", entry.action));
                continue;
            };
            // `keys = "none"` unbinds an action.
            if entry.keys.trim().eq_ignore_ascii_case("none") {
                bindings.insert(action, Vec::new());
                continue;
            }
            match parse_key_list(&entry.keys) {
                Ok(specs) => {
                    // A user binding steals the key from any default that had it.
                    for (other, keys) in bindings.iter_mut() {
                        if *other != action && other.scope().overlaps(action.scope()) {
                            keys.retain(|k| !specs.contains(k));
                        }
                    }
                    bindings.insert(action, specs);
                }
                Err(e) => warnings.push(format!(
                    "invalid keys '{}' for '{}': {e}",
                    entry.keys, entry.action
                )),
            }
        }

        let mut by_key: HashMap<KeySpec, Vec<Action>> = HashMap::new();
        for &action in Action::all() {
            for spec in &bindings[&action] {
                let slot = by_key.entry(spec.clone()).or_default();
                if let Some(prev) = slot.iter().find(|p| p.scope().overlaps(action.scope())) {
                    warnings.push(format!(
                        "key conflict: {} bound to both {} and {}",
                        spec.display(),
                        snake_name(*prev),
                        snake_name(action)
                    ));
                }
                slot.push(action);
            }
        }
        for actions in by_key.values_mut() {
            actions.sort_by_key(|a| a.scope().priority());
        }

        Self {
            bindings,
            by_key,
            warnings,
        }
    }

    /// The action a key triggers in the given context, most specific scope first.
    pub fn action_for(&self, key: &KeyEvent, ctx: KeyContext) -> Option<Action> {
        self.by_key
            .get(&KeySpec::from_event(key))?
            .iter()
            .find(|a| ctx.active(a.scope()))
            .copied()
    }

    pub fn keys_for(&self, action: Action) -> &[KeySpec] {
        self.bindings.get(&action).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Primary key label (`"c"`), `g x` for go-to targets, or `""` when unbound.
    pub fn label(&self, action: Action) -> String {
        if let Some(c) = action.goto_key() {
            return self.goto_label(c);
        }
        self.keys_for(action)
            .first()
            .map(KeySpec::display)
            .unwrap_or_default()
    }

    /// All keys joined: `"j / ↓"`.
    pub fn label_all(&self, action: Action) -> String {
        let mut keys: Vec<String> = self.keys_for(action).iter().map(KeySpec::display).collect();
        if let Some(c) = action.goto_key() {
            keys.push(self.goto_label(c));
        }
        keys.join(" / ")
    }

    fn goto_label(&self, c: char) -> String {
        let prefix = self
            .keys_for(Action::GotoPrefix)
            .first()
            .map(KeySpec::display)
            .unwrap_or_else(|| "g".into());
        format!("{prefix} {c}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::KeybindingOverride;

    fn ev(code: KeyCode, mods: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, mods)
    }

    fn ov(action: &str, keys: &str) -> KeybindingOverrides {
        KeybindingOverrides {
            overrides: vec![KeybindingOverride {
                action: action.into(),
                keys: keys.into(),
            }],
        }
    }

    #[test]
    fn parse_ctrl_q() {
        let spec = parse_keys("Ctrl+q").unwrap();
        assert!(spec.modifiers.contains(KeyModifiers::CONTROL));
        assert_eq!(spec.code, KeyCode::Char('q'));
    }

    #[test]
    fn defaults_have_no_conflicts() {
        let map = KeyMap::default();
        assert!(map.warnings.is_empty(), "{:?}", map.warnings);
    }

    #[test]
    fn override_quit() {
        let map = KeyMap::resolve(&ov("quit", "Ctrl+q"));
        let key = ev(KeyCode::Char('q'), KeyModifiers::CONTROL);
        assert_eq!(
            map.action_for(&key, KeyContext::default()),
            Some(Action::Quit)
        );
        // Plain q no longer quits.
        let key = ev(KeyCode::Char('q'), KeyModifiers::NONE);
        assert_eq!(map.action_for(&key, KeyContext::default()), None);
    }

    #[test]
    fn letter_case_is_significant() {
        let map = KeyMap::default();
        let ctx = KeyContext::default();
        let lower = ev(KeyCode::Char('c'), KeyModifiers::NONE);
        let upper = ev(KeyCode::Char('C'), KeyModifiers::SHIFT);
        let upper_no_shift = ev(KeyCode::Char('C'), KeyModifiers::NONE);
        assert_eq!(map.action_for(&lower, ctx), Some(Action::CopyPassword));
        assert_eq!(map.action_for(&upper, ctx), Some(Action::CloneItem));
        assert_eq!(
            map.action_for(&upper_no_shift, ctx),
            Some(Action::CloneItem)
        );
    }

    #[test]
    fn scoped_keys_resolve_by_context() {
        let map = KeyMap::default();
        let r = ev(KeyCode::Char('r'), KeyModifiers::NONE);
        let c = ev(KeyCode::Char('c'), KeyModifiers::NONE);
        let trash = KeyContext {
            trash: true,
            sends: false,
        };
        let sends = KeyContext {
            trash: false,
            sends: true,
        };
        assert_eq!(
            map.action_for(&r, KeyContext::default()),
            Some(Action::ToggleReveal)
        );
        assert_eq!(map.action_for(&r, trash), Some(Action::Restore));
        assert_eq!(map.action_for(&c, sends), Some(Action::CopySendLink));
    }

    #[test]
    fn shift_tab_matches_backtab() {
        let map = KeyMap::default();
        let key = ev(KeyCode::BackTab, KeyModifiers::SHIFT);
        assert_eq!(
            map.action_for(&key, KeyContext::default()),
            Some(Action::FocusPrev)
        );
    }

    #[test]
    fn override_steals_key_and_supports_lists() {
        // Rebind generator to `g`: the go-to prefix loses it, no conflict warning.
        let map = KeyMap::resolve(&ov("open_generator", "g F2"));
        assert!(map.warnings.is_empty(), "{:?}", map.warnings);
        let g = ev(KeyCode::Char('g'), KeyModifiers::NONE);
        let f2 = ev(KeyCode::F(2), KeyModifiers::NONE);
        assert_eq!(
            map.action_for(&g, KeyContext::default()),
            Some(Action::OpenGenerator)
        );
        assert_eq!(
            map.action_for(&f2, KeyContext::default()),
            Some(Action::OpenGenerator)
        );
        assert!(map.keys_for(Action::GotoPrefix).is_empty());
    }

    #[test]
    fn readme_config_example_applies() {
        let cfg: crate::config::AppConfig = toml::from_str(
            r#"
[[keybindings.overrides]]
action = "open_generator"
keys = "g F2"

[[keybindings.overrides]]
action = "quit"
keys = "Ctrl+q"
"#,
        )
        .unwrap();
        let map = KeyMap::resolve(&cfg.keybindings);
        assert!(map.warnings.is_empty(), "{:?}", map.warnings);
        let ctrl_q = ev(KeyCode::Char('q'), KeyModifiers::CONTROL);
        assert_eq!(
            map.action_for(&ctrl_q, KeyContext::default()),
            Some(Action::Quit)
        );
        assert_eq!(map.label(Action::OpenGenerator), "g");
    }

    #[test]
    fn legacy_action_names_still_resolve() {
        assert_eq!(action_from_name("new_login"), Some(Action::New));
        assert_eq!(
            action_from_name("copy-password"),
            Some(Action::CopyPassword)
        );
        assert_eq!(
            action_from_name("open_generator"),
            Some(Action::OpenGenerator)
        );
    }
}
