//! Toast notification stack (transient messages shown top-right over any screen).

use std::time::{Duration, Instant};

/// Maximum toasts kept / shown at once; older ones are dropped first.
pub const MAX_TOASTS: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToastKind {
    Info,
    Success,
    Warning,
    Error,
}

impl ToastKind {
    /// Classify a free-form status message.
    pub fn infer(msg: &str) -> Self {
        let m = msg.to_ascii_lowercase();
        if m.contains("fail")
            || m.contains("error")
            || m.contains("denied")
            || m.contains("cannot")
            || m.contains("invalid")
            || m.contains("unavailable")
        {
            Self::Error
        } else if m.contains("required")
            || m.contains("offline")
            || m.contains("warning")
            || m.starts_with("no ")
            || m.contains("not ")
        {
            Self::Warning
        } else if m.contains("copied")
            || m.contains("saved")
            || m.contains("created")
            || m.contains("updated")
            || m.contains("deleted")
            || m.contains("synced")
            || m.contains("cleared")
            || m.contains("opened")
            || m.contains("started")
            || m.contains("typed")
        {
            Self::Success
        } else {
            Self::Info
        }
    }

    pub fn ttl(self) -> Duration {
        match self {
            Self::Error => Duration::from_secs(7),
            Self::Warning => Duration::from_secs(5),
            Self::Success | Self::Info => Duration::from_secs(3),
        }
    }

    pub fn glyph(self) -> &'static str {
        match self {
            Self::Info => "ℹ",
            Self::Success => "✓",
            Self::Warning => "!",
            Self::Error => "✗",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Toast {
    pub text: String,
    pub kind: ToastKind,
    pub expires: Instant,
}

#[derive(Debug, Clone, Default)]
pub struct ToastStack {
    toasts: Vec<Toast>,
}

impl ToastStack {
    pub fn push(&mut self, text: impl Into<String>, kind: ToastKind) {
        self.push_at(text, kind, Instant::now());
    }

    pub fn push_at(&mut self, text: impl Into<String>, kind: ToastKind, now: Instant) {
        let text = text.into();
        if text.trim().is_empty() {
            return;
        }
        // Re-pushing the same message refreshes it instead of stacking duplicates.
        self.toasts.retain(|t| t.text != text);
        self.toasts.push(Toast {
            text,
            kind,
            expires: now + kind.ttl(),
        });
        while self.toasts.len() > MAX_TOASTS {
            self.toasts.remove(0);
        }
    }

    /// Drop expired toasts. Returns true when something was removed.
    pub fn tick(&mut self, now: Instant) -> bool {
        let before = self.toasts.len();
        self.toasts.retain(|t| t.expires > now);
        before != self.toasts.len()
    }

    /// Newest first.
    pub fn iter_newest_first(&self) -> impl Iterator<Item = &Toast> {
        self.toasts.iter().rev()
    }

    pub fn len(&self) -> usize {
        self.toasts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.toasts.is_empty()
    }

    pub fn clear(&mut self) {
        self.toasts.clear();
    }

    /// Dismiss the newest toast.
    pub fn dismiss_newest(&mut self) {
        self.toasts.pop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caps_and_dedupes() {
        let mut s = ToastStack::default();
        for i in 0..10 {
            s.push(format!("m{i}"), ToastKind::Info);
        }
        assert_eq!(s.len(), MAX_TOASTS);
        s.push("m9", ToastKind::Info);
        assert_eq!(s.len(), MAX_TOASTS);
        assert_eq!(s.iter_newest_first().next().unwrap().text, "m9");
    }

    #[test]
    fn expires() {
        let mut s = ToastStack::default();
        let t0 = Instant::now();
        s.push_at("a", ToastKind::Info, t0);
        assert!(!s.tick(t0 + Duration::from_secs(1)));
        assert!(s.tick(t0 + Duration::from_secs(10)));
        assert!(s.is_empty());
    }

    #[test]
    fn infers_kind() {
        assert_eq!(ToastKind::infer("Copy failed: x"), ToastKind::Error);
        assert_eq!(ToastKind::infer("Password copied"), ToastKind::Success);
        assert_eq!(ToastKind::infer("Select an item first"), ToastKind::Info);
    }
}
