//! Auto-type credentials into the focused window (feature `autotype`).
//!
//! Backends: macOS `osascript` (System Events), Wayland `wtype`, X11 `xdotool`.
//! Secrets are passed to helpers via environment variable / stdin, never on the command line,
//! so they do not show up in `ps` output.

use std::fmt;
use std::time::Duration;

/// What to type, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    Text(String),
    Tab,
    Enter,
    Pause(Duration),
}

/// Auto-type failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutoTypeError {
    /// Built without the `autotype` feature.
    Disabled,
    /// No supported helper found for this platform / session.
    NoBackend(String),
    /// Helper ran but failed.
    Backend(String),
}

impl fmt::Display for AutoTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => write!(f, "auto-type disabled at build time (feature `autotype`)"),
            Self::NoBackend(m) | Self::Backend(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for AutoTypeError {}

/// Typing backend in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    MacOsAscript,
    Wtype,
    Xdotool,
}

impl Backend {
    pub fn label(self) -> &'static str {
        match self {
            Self::MacOsAscript => "osascript",
            Self::Wtype => "wtype",
            Self::Xdotool => "xdotool",
        }
    }
}

/// Build the step list for a login: `user [Tab] password [Tab totp] [Enter]`.
pub fn login_steps(
    username: Option<&str>,
    password: Option<&str>,
    totp: Option<&str>,
    press_enter: bool,
) -> Vec<Step> {
    fn push_field(steps: &mut Vec<Step>, first: &mut bool, text: &str) {
        if !*first {
            steps.push(Step::Tab);
        }
        steps.push(Step::Text(text.to_string()));
        *first = false;
    }
    let mut steps = Vec::new();
    let mut first = true;
    if let Some(u) = username.filter(|s| !s.is_empty()) {
        push_field(&mut steps, &mut first, u);
    }
    if let Some(p) = password.filter(|s| !s.is_empty()) {
        push_field(&mut steps, &mut first, p);
    }
    if let Some(t) = totp.filter(|s| !s.is_empty()) {
        // Many sites show the 2FA field only after submitting the password.
        if !steps.is_empty() {
            steps.push(Step::Enter);
            steps.push(Step::Pause(Duration::from_millis(1500)));
        }
        first = true;
        push_field(&mut steps, &mut first, t);
    }
    if press_enter && !steps.is_empty() {
        steps.push(Step::Enter);
    }
    steps
}

/// Detect the backend for this platform / session, if any helper is installed.
#[cfg(feature = "autotype")]
pub fn detect_backend() -> Result<Backend, AutoTypeError> {
    #[cfg(target_os = "macos")]
    {
        if which("osascript") {
            return Ok(Backend::MacOsAscript);
        }
        Err(AutoTypeError::NoBackend("osascript not found".into()))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let wayland = std::env::var_os("WAYLAND_DISPLAY").is_some_and(|v| !v.is_empty());
        let x11 = std::env::var_os("DISPLAY").is_some_and(|v| !v.is_empty());
        if wayland && which("wtype") {
            return Ok(Backend::Wtype);
        }
        if x11 && which("xdotool") {
            return Ok(Backend::Xdotool);
        }
        if wayland {
            return Err(AutoTypeError::NoBackend(
                "Wayland session: install `wtype` for auto-type".into(),
            ));
        }
        if x11 {
            return Err(AutoTypeError::NoBackend(
                "X11 session: install `xdotool` for auto-type".into(),
            ));
        }
        Err(AutoTypeError::NoBackend(
            "no graphical session (DISPLAY / WAYLAND_DISPLAY unset)".into(),
        ))
    }
}

#[cfg(not(feature = "autotype"))]
pub fn detect_backend() -> Result<Backend, AutoTypeError> {
    Err(AutoTypeError::Disabled)
}

/// True when auto-type can run here.
pub fn available() -> bool {
    detect_backend().is_ok()
}

#[cfg(feature = "autotype")]
fn which(program: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|paths| {
        std::env::split_paths(&paths).any(|dir| {
            let p = dir.join(program);
            p.is_file()
        })
    })
}

/// Run all steps (blocking). Call from a background thread.
#[cfg(feature = "autotype")]
pub fn run_steps(steps: &[Step]) -> Result<(), AutoTypeError> {
    let backend = detect_backend()?;
    for step in steps {
        match step {
            Step::Text(t) => type_text(backend, t)?,
            Step::Tab => press_key(backend, Key::Tab)?,
            Step::Enter => press_key(backend, Key::Enter)?,
            Step::Pause(d) => std::thread::sleep(*d),
        }
        // Small gap so slow input fields keep up.
        std::thread::sleep(Duration::from_millis(40));
    }
    Ok(())
}

#[cfg(not(feature = "autotype"))]
pub fn run_steps(_steps: &[Step]) -> Result<(), AutoTypeError> {
    Err(AutoTypeError::Disabled)
}

#[cfg(feature = "autotype")]
#[derive(Clone, Copy)]
enum Key {
    Tab,
    Enter,
}

#[cfg(feature = "autotype")]
fn type_text(backend: Backend, text: &str) -> Result<(), AutoTypeError> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    match backend {
        Backend::MacOsAscript => {
            // Secret travels in the environment of the child only.
            let out = Command::new("osascript")
                .arg("-e")
                .arg("tell application \"System Events\" to keystroke (system attribute \"BWTUI_AUTOTYPE\")")
                .env("BWTUI_AUTOTYPE", text)
                .stdin(Stdio::null())
                .output()
                .map_err(|e| AutoTypeError::Backend(format!("osascript: {e}")))?;
            check(out.status.success(), &out.stderr, "osascript")
        }
        Backend::Wtype => {
            // `wtype -` reads text from stdin.
            let mut child = Command::new("wtype")
                .arg("-")
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|e| AutoTypeError::Backend(format!("wtype: {e}")))?;
            if let Some(mut stdin) = child.stdin.take() {
                stdin
                    .write_all(text.as_bytes())
                    .map_err(|e| AutoTypeError::Backend(format!("wtype: {e}")))?;
            }
            let out = child
                .wait_with_output()
                .map_err(|e| AutoTypeError::Backend(format!("wtype: {e}")))?;
            check(out.status.success(), &out.stderr, "wtype")
        }
        Backend::Xdotool => {
            let mut child = Command::new("xdotool")
                .args(["type", "--clearmodifiers", "--delay", "12", "--file", "-"])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|e| AutoTypeError::Backend(format!("xdotool: {e}")))?;
            if let Some(mut stdin) = child.stdin.take() {
                stdin
                    .write_all(text.as_bytes())
                    .map_err(|e| AutoTypeError::Backend(format!("xdotool: {e}")))?;
            }
            let out = child
                .wait_with_output()
                .map_err(|e| AutoTypeError::Backend(format!("xdotool: {e}")))?;
            check(out.status.success(), &out.stderr, "xdotool")
        }
    }
}

#[cfg(feature = "autotype")]
fn press_key(backend: Backend, key: Key) -> Result<(), AutoTypeError> {
    use std::process::{Command, Stdio};
    let out = match backend {
        Backend::MacOsAscript => {
            // key code 48 = Tab, 36 = Return.
            let code = match key {
                Key::Tab => "48",
                Key::Enter => "36",
            };
            Command::new("osascript")
                .arg("-e")
                .arg(format!(
                    "tell application \"System Events\" to key code {code}"
                ))
                .stdin(Stdio::null())
                .output()
        }
        Backend::Wtype => {
            let name = match key {
                Key::Tab => "Tab",
                Key::Enter => "Return",
            };
            Command::new("wtype")
                .args(["-k", name])
                .stdin(Stdio::null())
                .output()
        }
        Backend::Xdotool => {
            let name = match key {
                Key::Tab => "Tab",
                Key::Enter => "Return",
            };
            Command::new("xdotool")
                .args(["key", "--clearmodifiers", name])
                .stdin(Stdio::null())
                .output()
        }
    }
    .map_err(|e| AutoTypeError::Backend(format!("{}: {e}", backend.label())))?;
    check(out.status.success(), &out.stderr, backend.label())
}

#[cfg(feature = "autotype")]
fn check(ok: bool, stderr: &[u8], who: &str) -> Result<(), AutoTypeError> {
    if ok {
        return Ok(());
    }
    let msg = String::from_utf8_lossy(stderr);
    let msg = msg.trim();
    let hint = if who == "osascript" && msg.contains("not allowed") {
        " — grant Accessibility permission to your terminal in System Settings"
    } else {
        ""
    };
    Err(AutoTypeError::Backend(format!(
        "{who} failed: {}{hint}",
        if msg.is_empty() { "unknown error" } else { msg }
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_sequence_with_tab_and_enter() {
        let s = login_steps(Some("me"), Some("pw"), None, true);
        assert_eq!(
            s,
            vec![
                Step::Text("me".into()),
                Step::Tab,
                Step::Text("pw".into()),
                Step::Enter
            ]
        );
    }

    #[test]
    fn password_only_has_no_tab() {
        let s = login_steps(None, Some("pw"), None, false);
        assert_eq!(s, vec![Step::Text("pw".into())]);
    }

    #[test]
    fn totp_goes_after_submit_pause() {
        let s = login_steps(Some("u"), Some("p"), Some("123456"), true);
        assert!(s.contains(&Step::Pause(Duration::from_millis(1500))));
        assert_eq!(s.last(), Some(&Step::Enter));
        let totp_idx = s
            .iter()
            .position(|x| *x == Step::Text("123456".into()))
            .unwrap();
        let pause_idx = s.iter().position(|x| matches!(x, Step::Pause(_))).unwrap();
        assert!(totp_idx > pause_idx);
    }

    #[test]
    fn empty_input_yields_no_steps() {
        assert!(login_steps(None, None, None, true).is_empty());
    }
}
