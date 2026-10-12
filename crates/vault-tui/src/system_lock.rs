//! Best-effort detection of system sleep / screen lock.
//!
//! * macOS: Darwin / distributed notifications (`com.apple.screenIsLocked`,
//!   `com.apple.screensaver.didstart`) via the system `notifyutil` tool.
//! * Linux: systemd-logind D-Bus signals (`PrepareForSleep`, `Session.Lock`) via
//!   `dbus-monitor`.
//!
//! Detection runs in a helper process + reader thread and reports through an
//! [`mpsc`] channel. When the helper tool is missing the monitor simply never
//! fires (no error is surfaced).

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;

/// Why the system-lock hook fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemLockEvent {
    ScreenLocked,
    Sleep,
}

/// Handle to the background watcher. Dropping it kills the helper process.
pub struct SystemLockMonitor {
    rx: Receiver<SystemLockEvent>,
    child: Option<Child>,
}

impl SystemLockMonitor {
    /// Start watching. Returns `None` when no mechanism is available on this platform.
    pub fn start() -> Option<Self> {
        let (tx, rx) = mpsc::channel();
        let mut child = spawn_helper()?;
        let stdout = child.stdout.take()?;
        thread::Builder::new()
            .name("system-lock-monitor".into())
            .spawn(move || {
                let mut parser = LineParser::default();
                for line in BufReader::new(stdout).lines().map_while(|l| l.ok()) {
                    if let Some(ev) = parser.feed(&line) {
                        if tx.send(ev).is_err() {
                            break;
                        }
                    }
                }
            })
            .ok()?;
        Some(Self {
            rx,
            child: Some(child),
        })
    }

    /// Drain pending events; returns the most relevant one (if any).
    pub fn poll(&self) -> Option<SystemLockEvent> {
        let mut last = None;
        while let Ok(ev) = self.rx.try_recv() {
            last = Some(ev);
        }
        last
    }
}

impl Drop for SystemLockMonitor {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[cfg(target_os = "macos")]
fn spawn_helper() -> Option<Child> {
    Command::new("/usr/bin/notifyutil")
        .args([
            "-w",
            "com.apple.screenIsLocked",
            "-w",
            "com.apple.screensaver.didstart",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()
}

#[cfg(all(unix, not(target_os = "macos")))]
fn spawn_helper() -> Option<Child> {
    Command::new("dbus-monitor")
        .args([
            "--system",
            "type='signal',interface='org.freedesktop.login1.Manager',member='PrepareForSleep'",
            "type='signal',interface='org.freedesktop.login1.Session',member='Lock'",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()
}

#[cfg(not(unix))]
fn spawn_helper() -> Option<Child> {
    None
}

/// Incremental parser for helper output.
#[derive(Default)]
struct LineParser {
    /// Saw `member=PrepareForSleep`; waiting for the boolean argument.
    awaiting_sleep_arg: bool,
}

impl LineParser {
    fn feed(&mut self, line: &str) -> Option<SystemLockEvent> {
        let t = line.trim();

        // macOS `notifyutil -w` prints the notification name per event.
        if t.contains("com.apple.screenIsLocked") {
            return Some(SystemLockEvent::ScreenLocked);
        }
        if t.contains("com.apple.screensaver.didstart") {
            return Some(SystemLockEvent::ScreenLocked);
        }

        // Linux `dbus-monitor` output.
        if t.starts_with("signal") && t.contains("member=Lock") {
            self.awaiting_sleep_arg = false;
            return Some(SystemLockEvent::ScreenLocked);
        }
        if t.starts_with("signal") && t.contains("member=PrepareForSleep") {
            self.awaiting_sleep_arg = true;
            return None;
        }
        if self.awaiting_sleep_arg && t.starts_with("boolean") {
            self.awaiting_sleep_arg = false;
            if t.ends_with("true") {
                return Some(SystemLockEvent::Sleep);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_macos_notifications() {
        let mut p = LineParser::default();
        assert_eq!(
            p.feed("com.apple.screenIsLocked"),
            Some(SystemLockEvent::ScreenLocked)
        );
        assert_eq!(
            p.feed("com.apple.screensaver.didstart"),
            Some(SystemLockEvent::ScreenLocked)
        );
        assert_eq!(p.feed("com.apple.screenIsUnlocked"), None);
    }

    #[test]
    fn parses_logind_signals() {
        let mut p = LineParser::default();
        assert_eq!(
            p.feed("signal time=1 sender=:1.2 -> destination=(null destination) serial=9 path=/org/freedesktop/login1/session/_31; interface=org.freedesktop.login1.Session; member=Lock"),
            Some(SystemLockEvent::ScreenLocked)
        );
        assert_eq!(
            p.feed("signal time=2 sender=:1.2 -> destination=(null destination) serial=10 path=/org/freedesktop/login1; interface=org.freedesktop.login1.Manager; member=PrepareForSleep"),
            None
        );
        assert_eq!(p.feed("   boolean false"), None);
        p.feed("signal time=3 ... member=PrepareForSleep");
        assert_eq!(p.feed("   boolean true"), Some(SystemLockEvent::Sleep));
    }
}
