//! Central theme tokens. Respects `NO_COLOR`, `BW_ASCII`, and `config.toml` theme.

use ratatui::style::{Color, Modifier, Style};
use std::sync::OnceLock;

#[derive(Debug, Clone)]
pub struct Theme {
    pub name: String,
    pub accent: Color,
    pub accent_dim: Color,
    pub text: Color,
    pub muted: Color,
    pub danger: Color,
    pub success: Color,
    pub warning: Color,
    pub border: Color,
    pub border_focused: Color,
    pub select_bg: Color,
    pub select_bg_idle: Color,
    pub zebra_bg: Color,
    pub status_bg: Color,
    pub digit: Color,
    pub symbol: Color,
    pub no_color: bool,
    pub ascii: bool,
}

fn detect_no_color() -> bool {
    std::env::var_os("NO_COLOR").is_some() || std::env::var("TERM").as_deref() == Ok("dumb")
}

static THEME: OnceLock<Theme> = OnceLock::new();

/// Initialize the global theme from a config name (and optional custom colors).
/// Safe to call once at startup; later calls are ignored.
pub fn init_theme(name: &str, custom: Option<&CustomThemeColors>) {
    let _ = THEME.set(Theme::from_name(name, custom));
}

pub fn theme() -> &'static Theme {
    THEME.get_or_init(|| Theme::from_name("default", None))
}

/// Optional RGB overrides loaded from `[theme.colors]` in config.toml.
#[derive(Debug, Clone, Default)]
pub struct CustomThemeColors {
    pub accent: Option<(u8, u8, u8)>,
    pub accent_dim: Option<(u8, u8, u8)>,
    pub text: Option<(u8, u8, u8)>,
    pub muted: Option<(u8, u8, u8)>,
    pub danger: Option<(u8, u8, u8)>,
    pub success: Option<(u8, u8, u8)>,
    pub warning: Option<(u8, u8, u8)>,
    pub border: Option<(u8, u8, u8)>,
    pub border_focused: Option<(u8, u8, u8)>,
    pub digit: Option<(u8, u8, u8)>,
    pub symbol: Option<(u8, u8, u8)>,
}

impl Theme {
    pub fn from_name(name: &str, custom: Option<&CustomThemeColors>) -> Self {
        let no_color = detect_no_color();
        let ascii = std::env::var_os("BW_ASCII").is_some() || no_color;
        if no_color {
            return Self::monochrome(name, ascii);
        }
        let mut t = match name.to_ascii_lowercase().as_str() {
            "light" => Self::light(),
            "high-contrast" | "high_contrast" | "hc" => Self::high_contrast(),
            "solarized" => Self::solarized(),
            _ => Self::default_dark(),
        };
        t.name = name.to_string();
        t.ascii = ascii;
        t.no_color = false;
        if let Some(c) = custom {
            apply_custom(&mut t, c);
        }
        t
    }

    fn monochrome(name: &str, ascii: bool) -> Self {
        Self {
            name: name.into(),
            accent: Color::White,
            accent_dim: Color::White,
            text: Color::White,
            muted: Color::White,
            danger: Color::White,
            success: Color::White,
            warning: Color::White,
            border: Color::White,
            border_focused: Color::White,
            select_bg: Color::White,
            select_bg_idle: Color::White,
            zebra_bg: Color::Black,
            status_bg: Color::Black,
            digit: Color::White,
            symbol: Color::White,
            no_color: true,
            ascii,
        }
    }

    fn default_dark() -> Self {
        Self {
            name: "default".into(),
            accent: Color::Rgb(175, 82, 222),
            accent_dim: Color::Rgb(91, 61, 163),
            text: Color::Rgb(255, 255, 255),
            muted: Color::DarkGray,
            danger: Color::Rgb(247, 118, 142),
            success: Color::Green,
            warning: Color::Yellow,
            border: Color::Rgb(60, 60, 70),
            border_focused: Color::Rgb(175, 82, 222),
            select_bg: Color::Rgb(55, 40, 70),
            select_bg_idle: Color::Rgb(36, 34, 44),
            zebra_bg: Color::Rgb(24, 24, 30),
            status_bg: Color::Rgb(30, 30, 36),
            digit: Color::Rgb(125, 207, 255),
            symbol: Color::Rgb(255, 166, 87),
            no_color: false,
            ascii: false,
        }
    }

    fn light() -> Self {
        Self {
            name: "light".into(),
            accent: Color::Rgb(110, 54, 178),
            accent_dim: Color::Rgb(150, 110, 200),
            text: Color::Rgb(20, 20, 30),
            muted: Color::Rgb(100, 100, 110),
            danger: Color::Rgb(180, 40, 60),
            success: Color::Rgb(20, 120, 60),
            warning: Color::Rgb(160, 100, 0),
            border: Color::Rgb(180, 180, 190),
            border_focused: Color::Rgb(110, 54, 178),
            select_bg: Color::Rgb(230, 220, 245),
            select_bg_idle: Color::Rgb(240, 238, 245),
            zebra_bg: Color::Rgb(248, 248, 252),
            status_bg: Color::Rgb(235, 235, 240),
            digit: Color::Rgb(0, 100, 180),
            symbol: Color::Rgb(180, 80, 0),
            no_color: false,
            ascii: false,
        }
    }

    fn high_contrast() -> Self {
        Self {
            name: "high-contrast".into(),
            accent: Color::Yellow,
            accent_dim: Color::Rgb(200, 200, 0),
            text: Color::White,
            muted: Color::Gray,
            danger: Color::Red,
            success: Color::Green,
            warning: Color::Yellow,
            border: Color::White,
            border_focused: Color::Yellow,
            select_bg: Color::Blue,
            select_bg_idle: Color::DarkGray,
            zebra_bg: Color::Black,
            status_bg: Color::Black,
            digit: Color::Cyan,
            symbol: Color::Magenta,
            no_color: false,
            ascii: false,
        }
    }

    fn solarized() -> Self {
        Self {
            name: "solarized".into(),
            accent: Color::Rgb(38, 139, 210),
            accent_dim: Color::Rgb(42, 161, 152),
            text: Color::Rgb(147, 161, 161),
            muted: Color::Rgb(88, 110, 117),
            danger: Color::Rgb(220, 50, 47),
            success: Color::Rgb(133, 153, 0),
            warning: Color::Rgb(181, 137, 0),
            border: Color::Rgb(7, 54, 66),
            border_focused: Color::Rgb(38, 139, 210),
            select_bg: Color::Rgb(7, 54, 66),
            select_bg_idle: Color::Rgb(0, 43, 54),
            zebra_bg: Color::Rgb(0, 43, 54),
            status_bg: Color::Rgb(7, 54, 66),
            digit: Color::Rgb(42, 161, 152),
            symbol: Color::Rgb(203, 75, 22),
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
                .fg(Color::Black)
                .bg(self.accent)
                .add_modifier(Modifier::BOLD)
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

fn apply_custom(t: &mut Theme, c: &CustomThemeColors) {
    if let Some((r, g, b)) = c.accent {
        t.accent = Color::Rgb(r, g, b);
    }
    if let Some((r, g, b)) = c.accent_dim {
        t.accent_dim = Color::Rgb(r, g, b);
    }
    if let Some((r, g, b)) = c.text {
        t.text = Color::Rgb(r, g, b);
    }
    if let Some((r, g, b)) = c.muted {
        t.muted = Color::Rgb(r, g, b);
    }
    if let Some((r, g, b)) = c.danger {
        t.danger = Color::Rgb(r, g, b);
    }
    if let Some((r, g, b)) = c.success {
        t.success = Color::Rgb(r, g, b);
    }
    if let Some((r, g, b)) = c.warning {
        t.warning = Color::Rgb(r, g, b);
    }
    if let Some((r, g, b)) = c.border {
        t.border = Color::Rgb(r, g, b);
    }
    if let Some((r, g, b)) = c.border_focused {
        t.border_focused = Color::Rgb(r, g, b);
    }
    if let Some((r, g, b)) = c.digit {
        t.digit = Color::Rgb(r, g, b);
    }
    if let Some((r, g, b)) = c.symbol {
        t.symbol = Color::Rgb(r, g, b);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_in_themes_construct() {
        for name in ["default", "light", "high-contrast", "solarized"] {
            let t = Theme::from_name(name, None);
            assert!(!t.name.is_empty());
        }
    }

    #[test]
    fn password_spans_color_classes() {
        let t = Theme::default_dark();
        let spans = t.password_spans("Ab1!");
        assert_eq!(spans.len(), 4);
    }
}
