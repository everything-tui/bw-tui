//! Central theme tokens. Respects `NO_COLOR` and optional ASCII high-contrast mode.

use ratatui::style::{Color, Modifier, Style};
use std::sync::OnceLock;

#[derive(Debug, Clone)]
pub struct Theme {
    pub accent: Color,
    pub accent_dim: Color,
    pub text: Color,
    pub muted: Color,
    pub danger: Color,
    pub success: Color,
    pub border: Color,
    pub border_focused: Color,
    pub no_color: bool,
    pub ascii: bool,
}

fn detect_no_color() -> bool {
    std::env::var_os("NO_COLOR").is_some() || std::env::var("TERM").as_deref() == Ok("dumb")
}

static THEME: OnceLock<Theme> = OnceLock::new();

pub fn theme() -> &'static Theme {
    THEME.get_or_init(|| {
        let no_color = detect_no_color();
        let ascii = std::env::var_os("BW_ASCII").is_some() || no_color;
        if no_color {
            Theme {
                accent: Color::White,
                accent_dim: Color::White,
                text: Color::White,
                muted: Color::White,
                danger: Color::White,
                success: Color::White,
                border: Color::White,
                border_focused: Color::White,
                no_color,
                ascii,
            }
        } else {
            Theme {
                accent: Color::Rgb(139, 92, 246),
                accent_dim: Color::Rgb(91, 61, 163),
                text: Color::Rgb(255, 255, 255),
                muted: Color::DarkGray,
                danger: Color::Red,
                success: Color::Green,
                border: Color::DarkGray,
                border_focused: Color::Rgb(139, 92, 246),
                no_color,
                ascii,
            }
        }
    })
}

impl Theme {
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
}
