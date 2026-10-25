//! Central theme tokens. Respects `NO_COLOR`, `BW_ASCII`, and `config.toml` theme.
//!
//! The UI is drawn in layers: `mantle` (sidebar, header, status bar) sits
//! behind `base` (item list), which sits behind `surface` (detail pane, inputs).
//! Popups use `overlay` on a dimmed `backdrop`. Every token can be overridden
//! from `[colors]` in config.toml, and the theme can be switched at runtime.

use ratatui::style::{Color, Modifier, Style};
use std::sync::RwLock;

#[derive(Debug, Clone)]
pub struct Theme {
    pub name: String,
    // Surfaces, back to front.
    pub mantle: Color,
    pub base: Color,
    pub surface: Color,
    pub overlay: Color,
    pub backdrop: Color,
    // Text.
    pub text: Color,
    pub subtext: Color,
    pub muted: Color,
    // Accent.
    pub accent: Color,
    pub accent_fg: Color,
    pub accent_dim: Color,
    pub select_bg: Color,
    pub select_bg_idle: Color,
    pub border: Color,
    pub border_focused: Color,
    // Semantic.
    pub danger: Color,
    pub success: Color,
    pub warning: Color,
    pub info: Color,
    pub favorite: Color,
    // Item types.
    pub login: Color,
    pub note: Color,
    pub card: Color,
    pub identity: Color,
    pub ssh: Color,
    // Revealed passwords.
    pub digit: Color,
    pub symbol: Color,
    /// Draw thin separators between panes (themes where bg layers aren't enough).
    pub separators: bool,
    pub no_color: bool,
    pub ascii: bool,
}

/// Built-in theme names, in picker order.
pub const THEME_NAMES: &[&str] = &[
    "default",
    "catppuccin-mocha",
    "catppuccin-latte",
    "tokyo-night",
    "rose-pine",
    "gruvbox",
    "dracula",
    "nord",
    "bitwarden",
    "solarized",
    "light",
    "high-contrast",
];

fn detect_no_color() -> bool {
    std::env::var_os("NO_COLOR").is_some() || std::env::var("TERM").as_deref() == Ok("dumb")
}

static THEME: RwLock<Option<&'static Theme>> = RwLock::new(None);

/// Install a theme by name (plus optional overrides). Can be called again at
/// runtime to switch themes; each switch leaks one small `Theme`, which is fine
/// for an interactive picker.
pub fn init_theme(name: &str, custom: Option<&CustomThemeColors>) {
    set_theme(Theme::from_name(name, custom));
}

pub fn set_theme(theme: Theme) {
    let leaked: &'static Theme = Box::leak(Box::new(theme));
    if let Ok(mut slot) = THEME.write() {
        *slot = Some(leaked);
    }
}

pub fn theme() -> &'static Theme {
    if let Some(t) = THEME.read().ok().and_then(|g| *g) {
        return t;
    }
    let t: &'static Theme = Box::leak(Box::new(Theme::from_name("default", None)));
    if let Ok(mut slot) = THEME.write() {
        slot.get_or_insert(t);
    }
    t
}

/// Optional RGB overrides loaded from `[colors]` in config.toml.
#[derive(Debug, Clone, Default)]
pub struct CustomThemeColors {
    pub overrides: Vec<(String, (u8, u8, u8))>,
    pub transparent: bool,
}

/// Token names accepted in `[colors]`.
pub const TOKEN_NAMES: &[&str] = &[
    "mantle",
    "base",
    "surface",
    "overlay",
    "backdrop",
    "text",
    "subtext",
    "muted",
    "accent",
    "accent_fg",
    "accent_dim",
    "select_bg",
    "select_bg_idle",
    "border",
    "border_focused",
    "danger",
    "success",
    "warning",
    "info",
    "favorite",
    "login",
    "note",
    "card",
    "identity",
    "ssh",
    "digit",
    "symbol",
];

const fn rgb(hex: u32) -> Color {
    Color::Rgb((hex >> 16) as u8, (hex >> 8) as u8, hex as u8)
}

impl Theme {
    pub fn from_name(name: &str, custom: Option<&CustomThemeColors>) -> Self {
        let no_color = detect_no_color();
        let ascii = std::env::var_os("BW_ASCII").is_some() || no_color;
        if no_color {
            return Self::monochrome(name, ascii);
        }
        let mut t = Self::builtin(name).unwrap_or_else(Self::default_dark);
        t.name = name.to_string();
        t.ascii = ascii;
        t.no_color = false;
        if let Some(c) = custom {
            for (token, (r, g, b)) in &c.overrides {
                t.set_token(token, Color::Rgb(*r, *g, *b));
            }
            if c.transparent {
                // Let the terminal background show through; popups stay opaque.
                t.mantle = Color::Reset;
                t.base = Color::Reset;
                t.surface = Color::Reset;
                t.separators = true;
            }
        }
        t
    }

    pub fn builtin(name: &str) -> Option<Self> {
        Some(match name.to_ascii_lowercase().replace('_', "-").as_str() {
            "default" | "violet" => Self::default_dark(),
            "catppuccin" | "catppuccin-mocha" | "mocha" => Self::catppuccin_mocha(),
            "catppuccin-latte" | "latte" => Self::catppuccin_latte(),
            "tokyo-night" | "tokyonight" => Self::tokyo_night(),
            "rose-pine" | "rosepine" => Self::rose_pine(),
            "gruvbox" | "gruvbox-dark" => Self::gruvbox(),
            "dracula" => Self::dracula(),
            "nord" => Self::nord(),
            "bitwarden" => Self::bitwarden(),
            "solarized" | "solarized-dark" => Self::solarized(),
            "light" => Self::light(),
            "high-contrast" | "hc" => Self::high_contrast(),
            _ => return None,
        })
    }

    /// Set one token by its config name. Returns false for unknown names.
    pub fn set_token(&mut self, token: &str, c: Color) -> bool {
        let slot = match token {
            "mantle" => &mut self.mantle,
            "base" => &mut self.base,
            "surface" => &mut self.surface,
            "overlay" => &mut self.overlay,
            "backdrop" => &mut self.backdrop,
            "text" => &mut self.text,
            "subtext" => &mut self.subtext,
            "muted" => &mut self.muted,
            "accent" => &mut self.accent,
            "accent_fg" => &mut self.accent_fg,
            "accent_dim" => &mut self.accent_dim,
            "select_bg" => &mut self.select_bg,
            "select_bg_idle" => &mut self.select_bg_idle,
            "border" => &mut self.border,
            "border_focused" => &mut self.border_focused,
            "danger" => &mut self.danger,
            "success" => &mut self.success,
            "warning" => &mut self.warning,
            "info" => &mut self.info,
            "favorite" => &mut self.favorite,
            "login" => &mut self.login,
            "note" => &mut self.note,
            "card" => &mut self.card,
            "identity" => &mut self.identity,
            "ssh" => &mut self.ssh,
            "digit" => &mut self.digit,
            "symbol" => &mut self.symbol,
            _ => return false,
        };
        *slot = c;
        true
    }

    fn monochrome(name: &str, ascii: bool) -> Self {
        let w = Color::Reset;
        Self {
            name: name.into(),
            mantle: w,
            base: w,
            surface: w,
            overlay: w,
            backdrop: w,
            text: w,
            subtext: w,
            muted: w,
            accent: w,
            accent_fg: w,
            accent_dim: w,
            select_bg: w,
            select_bg_idle: w,
            border: w,
            border_focused: w,
            danger: w,
            success: w,
            warning: w,
            info: w,
            favorite: w,
            login: w,
            note: w,
            card: w,
            identity: w,
            ssh: w,
            digit: w,
            symbol: w,
            separators: true,
            no_color: true,
            ascii,
        }
    }

    fn default_dark() -> Self {
        Self {
            name: "default".into(),
            mantle: rgb(0x111117),
            base: rgb(0x16161d),
            surface: rgb(0x1c1c25),
            overlay: rgb(0x232330),
            backdrop: rgb(0x0b0b0f),
            text: rgb(0xe6e4f0),
            subtext: rgb(0xa9a6bb),
            muted: rgb(0x676479),
            accent: rgb(0xb07cf7),
            accent_fg: rgb(0x120d1c),
            accent_dim: rgb(0x5b3da3),
            select_bg: rgb(0x2e2443),
            select_bg_idle: rgb(0x23212e),
            border: rgb(0x2c2a39),
            border_focused: rgb(0xb07cf7),
            danger: rgb(0xf7768e),
            success: rgb(0x9ece6a),
            warning: rgb(0xe0af68),
            info: rgb(0x7dcfff),
            favorite: rgb(0xf5c451),
            login: rgb(0x7aa2f7),
            note: rgb(0xe0af68),
            card: rgb(0x9ece6a),
            identity: rgb(0xbb9af7),
            ssh: rgb(0x7dcfff),
            digit: rgb(0x7dcfff),
            symbol: rgb(0xff9e64),
            separators: false,
            no_color: false,
            ascii: false,
        }
    }

    fn catppuccin_mocha() -> Self {
        Self {
            name: "catppuccin-mocha".into(),
            mantle: rgb(0x181825),
            base: rgb(0x1e1e2e),
            surface: rgb(0x242436),
            overlay: rgb(0x313244),
            backdrop: rgb(0x11111b),
            text: rgb(0xcdd6f4),
            subtext: rgb(0xa6adc8),
            muted: rgb(0x6c7086),
            accent: rgb(0xcba6f7),
            accent_fg: rgb(0x1e1e2e),
            accent_dim: rgb(0x7f6aa6),
            select_bg: rgb(0x3a3350),
            select_bg_idle: rgb(0x2a2b3c),
            border: rgb(0x313244),
            border_focused: rgb(0xcba6f7),
            danger: rgb(0xf38ba8),
            success: rgb(0xa6e3a1),
            warning: rgb(0xf9e2af),
            info: rgb(0x89dceb),
            favorite: rgb(0xf9e2af),
            login: rgb(0x89b4fa),
            note: rgb(0xf9e2af),
            card: rgb(0xa6e3a1),
            identity: rgb(0xf5c2e7),
            ssh: rgb(0x94e2d5),
            digit: rgb(0x89b4fa),
            symbol: rgb(0xfab387),
            separators: false,
            no_color: false,
            ascii: false,
        }
    }

    fn catppuccin_latte() -> Self {
        Self {
            name: "catppuccin-latte".into(),
            mantle: rgb(0xe6e9ef),
            base: rgb(0xeff1f5),
            surface: rgb(0xf7f8fa),
            overlay: rgb(0xffffff),
            backdrop: rgb(0xbcc0cc),
            text: rgb(0x4c4f69),
            subtext: rgb(0x6c6f85),
            muted: rgb(0x9ca0b0),
            accent: rgb(0x8839ef),
            accent_fg: rgb(0xffffff),
            accent_dim: rgb(0xb98ff5),
            select_bg: rgb(0xe2d6f8),
            select_bg_idle: rgb(0xdfe2ea),
            border: rgb(0xccd0da),
            border_focused: rgb(0x8839ef),
            danger: rgb(0xd20f39),
            success: rgb(0x40a02b),
            warning: rgb(0xdf8e1d),
            info: rgb(0x04a5e5),
            favorite: rgb(0xdf8e1d),
            login: rgb(0x1e66f5),
            note: rgb(0xdf8e1d),
            card: rgb(0x40a02b),
            identity: rgb(0xea76cb),
            ssh: rgb(0x179299),
            digit: rgb(0x1e66f5),
            symbol: rgb(0xfe640b),
            separators: false,
            no_color: false,
            ascii: false,
        }
    }

    fn tokyo_night() -> Self {
        Self {
            name: "tokyo-night".into(),
            mantle: rgb(0x16161e),
            base: rgb(0x1a1b26),
            surface: rgb(0x1f2335),
            overlay: rgb(0x24283b),
            backdrop: rgb(0x0e0e14),
            text: rgb(0xc0caf5),
            subtext: rgb(0xa9b1d6),
            muted: rgb(0x565f89),
            accent: rgb(0x7aa2f7),
            accent_fg: rgb(0x1a1b26),
            accent_dim: rgb(0x3d59a1),
            select_bg: rgb(0x283457),
            select_bg_idle: rgb(0x222436),
            border: rgb(0x292e42),
            border_focused: rgb(0x7aa2f7),
            danger: rgb(0xf7768e),
            success: rgb(0x9ece6a),
            warning: rgb(0xe0af68),
            info: rgb(0x7dcfff),
            favorite: rgb(0xe0af68),
            login: rgb(0x7aa2f7),
            note: rgb(0xe0af68),
            card: rgb(0x9ece6a),
            identity: rgb(0xbb9af7),
            ssh: rgb(0x7dcfff),
            digit: rgb(0x7dcfff),
            symbol: rgb(0xff9e64),
            separators: false,
            no_color: false,
            ascii: false,
        }
    }

    fn rose_pine() -> Self {
        Self {
            name: "rose-pine".into(),
            mantle: rgb(0x15131f),
            base: rgb(0x191724),
            surface: rgb(0x1f1d2e),
            overlay: rgb(0x26233a),
            backdrop: rgb(0x0f0e16),
            text: rgb(0xe0def4),
            subtext: rgb(0x908caa),
            muted: rgb(0x6e6a86),
            accent: rgb(0xc4a7e7),
            accent_fg: rgb(0x191724),
            accent_dim: rgb(0x7a6a96),
            select_bg: rgb(0x312c4a),
            select_bg_idle: rgb(0x232136),
            border: rgb(0x2a273f),
            border_focused: rgb(0xc4a7e7),
            danger: rgb(0xeb6f92),
            success: rgb(0x9ccfd8),
            warning: rgb(0xf6c177),
            info: rgb(0x9ccfd8),
            favorite: rgb(0xf6c177),
            login: rgb(0x9ccfd8),
            note: rgb(0xf6c177),
            card: rgb(0xebbcba),
            identity: rgb(0xc4a7e7),
            ssh: rgb(0x56949f),
            digit: rgb(0x9ccfd8),
            symbol: rgb(0xebbcba),
            separators: false,
            no_color: false,
            ascii: false,
        }
    }

    fn gruvbox() -> Self {
        Self {
            name: "gruvbox".into(),
            mantle: rgb(0x1d2021),
            base: rgb(0x282828),
            surface: rgb(0x32302f),
            overlay: rgb(0x3c3836),
            backdrop: rgb(0x141617),
            text: rgb(0xebdbb2),
            subtext: rgb(0xa89984),
            muted: rgb(0x7c6f64),
            accent: rgb(0xfabd2f),
            accent_fg: rgb(0x282828),
            accent_dim: rgb(0xb57614),
            select_bg: rgb(0x45403d),
            select_bg_idle: rgb(0x343130),
            border: rgb(0x3c3836),
            border_focused: rgb(0xfabd2f),
            danger: rgb(0xfb4934),
            success: rgb(0xb8bb26),
            warning: rgb(0xfe8019),
            info: rgb(0x83a598),
            favorite: rgb(0xfabd2f),
            login: rgb(0x83a598),
            note: rgb(0xfabd2f),
            card: rgb(0xb8bb26),
            identity: rgb(0xd3869b),
            ssh: rgb(0x8ec07c),
            digit: rgb(0x83a598),
            symbol: rgb(0xfe8019),
            separators: false,
            no_color: false,
            ascii: false,
        }
    }

    fn dracula() -> Self {
        Self {
            name: "dracula".into(),
            mantle: rgb(0x21222c),
            base: rgb(0x282a36),
            surface: rgb(0x2d2f3d),
            overlay: rgb(0x363949),
            backdrop: rgb(0x16171e),
            text: rgb(0xf8f8f2),
            subtext: rgb(0xbfbfd0),
            muted: rgb(0x6272a4),
            accent: rgb(0xbd93f9),
            accent_fg: rgb(0x282a36),
            accent_dim: rgb(0x6d5a9e),
            select_bg: rgb(0x44475a),
            select_bg_idle: rgb(0x33354a),
            border: rgb(0x383a4a),
            border_focused: rgb(0xbd93f9),
            danger: rgb(0xff5555),
            success: rgb(0x50fa7b),
            warning: rgb(0xffb86c),
            info: rgb(0x8be9fd),
            favorite: rgb(0xf1fa8c),
            login: rgb(0x8be9fd),
            note: rgb(0xf1fa8c),
            card: rgb(0x50fa7b),
            identity: rgb(0xff79c6),
            ssh: rgb(0xbd93f9),
            digit: rgb(0x8be9fd),
            symbol: rgb(0xffb86c),
            separators: false,
            no_color: false,
            ascii: false,
        }
    }

    fn nord() -> Self {
        Self {
            name: "nord".into(),
            mantle: rgb(0x272c36),
            base: rgb(0x2e3440),
            surface: rgb(0x343b49),
            overlay: rgb(0x3b4252),
            backdrop: rgb(0x1d2129),
            text: rgb(0xeceff4),
            subtext: rgb(0xd8dee9),
            muted: rgb(0x6c7a96),
            accent: rgb(0x88c0d0),
            accent_fg: rgb(0x2e3440),
            accent_dim: rgb(0x5e81ac),
            select_bg: rgb(0x434c5e),
            select_bg_idle: rgb(0x3b4252),
            border: rgb(0x3b4252),
            border_focused: rgb(0x88c0d0),
            danger: rgb(0xbf616a),
            success: rgb(0xa3be8c),
            warning: rgb(0xebcb8b),
            info: rgb(0x81a1c1),
            favorite: rgb(0xebcb8b),
            login: rgb(0x81a1c1),
            note: rgb(0xebcb8b),
            card: rgb(0xa3be8c),
            identity: rgb(0xb48ead),
            ssh: rgb(0x8fbcbb),
            digit: rgb(0x88c0d0),
            symbol: rgb(0xd08770),
            separators: false,
            no_color: false,
            ascii: false,
        }
    }

    fn bitwarden() -> Self {
        Self {
            name: "bitwarden".into(),
            mantle: rgb(0x11151b),
            base: rgb(0x161b22),
            surface: rgb(0x1c222b),
            overlay: rgb(0x232a35),
            backdrop: rgb(0x0a0d11),
            text: rgb(0xe3e8ef),
            subtext: rgb(0xa4adba),
            muted: rgb(0x67707d),
            accent: rgb(0x5b93ff),
            accent_fg: rgb(0x0b1220),
            accent_dim: rgb(0x175ddc),
            select_bg: rgb(0x1d3256),
            select_bg_idle: rgb(0x1f252e),
            border: rgb(0x2a313c),
            border_focused: rgb(0x5b93ff),
            danger: rgb(0xff6b6b),
            success: rgb(0x4fd18b),
            warning: rgb(0xf2c14e),
            info: rgb(0x5bc0eb),
            favorite: rgb(0xf2c14e),
            login: rgb(0x5b93ff),
            note: rgb(0xf2c14e),
            card: rgb(0x4fd18b),
            identity: rgb(0xc792ea),
            ssh: rgb(0x5bc0eb),
            digit: rgb(0x5bc0eb),
            symbol: rgb(0xff9e64),
            separators: false,
            no_color: false,
            ascii: false,
        }
    }

    fn solarized() -> Self {
        Self {
            name: "solarized".into(),
            mantle: rgb(0x00212b),
            base: rgb(0x002b36),
            surface: rgb(0x03323e),
            overlay: rgb(0x073642),
            backdrop: rgb(0x00171d),
            text: rgb(0x93a1a1),
            subtext: rgb(0x839496),
            muted: rgb(0x586e75),
            accent: rgb(0x268bd2),
            accent_fg: rgb(0x002b36),
            accent_dim: rgb(0x2aa198),
            select_bg: rgb(0x0a4757),
            select_bg_idle: rgb(0x073642),
            border: rgb(0x073642),
            border_focused: rgb(0x268bd2),
            danger: rgb(0xdc322f),
            success: rgb(0x859900),
            warning: rgb(0xb58900),
            info: rgb(0x2aa198),
            favorite: rgb(0xb58900),
            login: rgb(0x268bd2),
            note: rgb(0xb58900),
            card: rgb(0x859900),
            identity: rgb(0xd33682),
            ssh: rgb(0x2aa198),
            digit: rgb(0x2aa198),
            symbol: rgb(0xcb4b16),
            separators: false,
            no_color: false,
            ascii: false,
        }
    }

    fn light() -> Self {
        Self {
            name: "light".into(),
            mantle: rgb(0xeceef2),
            base: rgb(0xf6f7f9),
            surface: rgb(0xffffff),
            overlay: rgb(0xffffff),
            backdrop: rgb(0xc4c7cf),
            text: rgb(0x1c1c28),
            subtext: rgb(0x4f5060),
            muted: rgb(0x8a8b99),
            accent: rgb(0x6e36b2),
            accent_fg: rgb(0xffffff),
            accent_dim: rgb(0x9a6ed0),
            select_bg: rgb(0xe6dcf5),
            select_bg_idle: rgb(0xe4e6ec),
            border: rgb(0xd5d7de),
            border_focused: rgb(0x6e36b2),
            danger: rgb(0xb4283c),
            success: rgb(0x1f7a42),
            warning: rgb(0xa06400),
            info: rgb(0x0064b4),
            favorite: rgb(0xc58a00),
            login: rgb(0x2f5fd0),
            note: rgb(0xa06400),
            card: rgb(0x1f7a42),
            identity: rgb(0x8a3fbf),
            ssh: rgb(0x00808a),
            digit: rgb(0x0064b4),
            symbol: rgb(0xb45000),
            separators: false,
            no_color: false,
            ascii: false,
        }
    }

    fn high_contrast() -> Self {
        Self {
            name: "high-contrast".into(),
            mantle: Color::Black,
            base: Color::Black,
            surface: Color::Black,
            overlay: Color::Black,
            backdrop: Color::Black,
            text: Color::White,
            subtext: Color::White,
            muted: Color::Gray,
            accent: Color::Yellow,
            accent_fg: Color::Black,
            accent_dim: Color::Rgb(200, 200, 0),
            select_bg: Color::Blue,
            select_bg_idle: Color::DarkGray,
            border: Color::White,
            border_focused: Color::Yellow,
            danger: Color::LightRed,
            success: Color::LightGreen,
            warning: Color::Yellow,
            info: Color::Cyan,
            favorite: Color::Yellow,
            login: Color::Cyan,
            note: Color::Yellow,
            card: Color::LightGreen,
            identity: Color::LightMagenta,
            ssh: Color::Cyan,
            digit: Color::Cyan,
            symbol: Color::Magenta,
            separators: true,
            no_color: false,
            ascii: false,
        }
    }

    pub fn title(&self) -> Style {
        Style::default()
            .fg(self.accent)
            .add_modifier(Modifier::BOLD)
    }

    pub fn normal(&self) -> Style {
        Style::default().fg(self.text)
    }

    pub fn muted_style(&self) -> Style {
        Style::default().fg(self.muted)
    }

    pub fn focused_border(&self) -> Style {
        Style::default().fg(self.border_focused)
    }

    pub fn border_style(&self) -> Style {
        Style::default().fg(self.border)
    }

    pub fn selected(&self) -> Style {
        if self.no_color {
            Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD)
        } else {
            Style::default()
                .fg(self.accent_fg)
                .bg(self.accent)
                .add_modifier(Modifier::BOLD)
        }
    }

    /// Highlighted list row: strong when the list has focus, quiet otherwise.
    pub fn row_selected(&self, focused: bool) -> Style {
        if self.no_color {
            return if focused {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default().add_modifier(Modifier::UNDERLINED)
            };
        }
        if focused {
            Style::default()
                .bg(self.select_bg)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().bg(self.select_bg_idle)
        }
    }

    pub fn star(&self) -> &'static str {
        if self.ascii {
            "*"
        } else {
            "★"
        }
    }

    /// Style a revealed password with distinct colors for digits and symbols.
    pub fn password_spans(&self, password: &str) -> Vec<ratatui::text::Span<'static>> {
        password
            .chars()
            .map(|c| {
                let style = if c.is_ascii_digit() {
                    Style::default().fg(self.digit)
                } else if c.is_ascii_alphabetic() {
                    Style::default().fg(self.text)
                } else {
                    Style::default().fg(self.symbol)
                };
                ratatui::text::Span::styled(c.to_string(), style)
            })
            .collect()
    }
}

/// Short accessors so drawing code reads `pal::accent()` instead of threading
/// a theme reference everywhere.
pub mod pal {
    use super::theme;
    use ratatui::style::Color;

    macro_rules! tokens {
        ($($name:ident),* $(,)?) => {
            $(#[inline] pub fn $name() -> Color { theme().$name })*
        };
    }
    tokens!(
        mantle,
        base,
        surface,
        overlay,
        backdrop,
        text,
        subtext,
        muted,
        accent,
        accent_fg,
        accent_dim,
        select_bg,
        select_bg_idle,
        border,
        border_focused,
        danger,
        success,
        warning,
        info,
        favorite,
        login,
        note,
        card,
        identity,
        ssh,
        digit,
        symbol,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_in_themes_construct() {
        for name in THEME_NAMES {
            let t = Theme::builtin(name).expect(name);
            assert!(!t.name.is_empty());
        }
    }

    #[test]
    fn every_token_name_is_settable() {
        let mut t = Theme::default_dark();
        for token in TOKEN_NAMES {
            assert!(t.set_token(token, Color::Rgb(1, 2, 3)), "{token}");
        }
        assert!(!t.set_token("nope", Color::Reset));
    }

    #[test]
    fn overrides_and_transparency_apply() {
        let custom = CustomThemeColors {
            overrides: vec![("accent".into(), (1, 2, 3))],
            transparent: true,
        };
        let t = Theme::from_name("tokyo-night", Some(&custom));
        if !t.no_color {
            assert_eq!(t.accent, Color::Rgb(1, 2, 3));
            assert_eq!(t.base, Color::Reset);
            assert!(t.separators);
        }
    }

    #[test]
    fn password_spans_color_classes() {
        let t = Theme::default_dark();
        let spans = t.password_spans("Ab1!");
        assert_eq!(spans.len(), 4);
    }
}
