use std::time::{Duration, Instant};

use arboard::Clipboard;

use crate::error::{Result, SessionError};

pub struct ClipboardService {
    clipboard: Option<Clipboard>,
    last_secret: Option<String>,
    clear_at: Option<Instant>,
    clear_after: Duration,
}

impl ClipboardService {
    pub fn new(clear_after_secs: u64) -> Self {
        Self {
            clipboard: Clipboard::new().ok(),
            last_secret: None,
            clear_at: None,
            clear_after: Duration::from_secs(clear_after_secs),
        }
    }

    pub fn copy_secret(&mut self, value: &str) -> Result<()> {
        let cb = self
            .clipboard
            .as_mut()
            .ok_or_else(|| SessionError::Clipboard("unavailable".into()))?;
        cb.set_text(value.to_string())
            .map_err(|e| SessionError::Clipboard(e.to_string()))?;
        self.last_secret = Some(value.to_string());
        self.clear_at = Some(Instant::now() + self.clear_after);
        Ok(())
    }

    /// Call on each tick; clears clipboard if it still holds our secret.
    pub fn tick(&mut self) {
        let Some(deadline) = self.clear_at else {
            return;
        };
        if Instant::now() < deadline {
            return;
        }
        self.clear_at = None;
        let Some(expected) = self.last_secret.take() else {
            return;
        };
        if let Some(cb) = self.clipboard.as_mut() {
            if let Ok(current) = cb.get_text() {
                if current == expected {
                    let _ = cb.set_text(String::new());
                }
            }
        }
    }

    pub fn seconds_until_clear(&self) -> Option<u64> {
        self.clear_at.map(|t| {
            t.saturating_duration_since(Instant::now())
                .as_secs()
        })
    }
}
