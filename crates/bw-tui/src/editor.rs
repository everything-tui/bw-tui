//! Edit text in `$VISUAL` / `$EDITOR` via a private (0600) temp file.
//!
//! The temp file lives in a freshly created 0700 directory, is overwritten with zeros and removed
//! after the editor exits (also on error). The caller is responsible for suspending the TUI
//! (leave alternate screen / raw mode) around [`edit_text`].

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Resolve the editor command: `$VISUAL`, then `$EDITOR`, then `vi`.
pub fn editor_command() -> String {
    for var in ["VISUAL", "EDITOR"] {
        if let Ok(v) = std::env::var(var) {
            if !v.trim().is_empty() {
                return v;
            }
        }
    }
    "vi".to_string()
}

/// Split an editor command line (`code -w`, `"my editor" --flag`) into program + args.
pub fn split_command(cmd: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut has_token = false;
    for c in cmd.chars() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => cur.push(c),
            (None, '"') | (None, '\'') => {
                quote = Some(c);
                has_token = true;
            }
            (None, c) if c.is_whitespace() => {
                if has_token || !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                    has_token = false;
                }
            }
            (None, c) => cur.push(c),
        }
    }
    if has_token || !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Private scratch directory (0700) containing one note file (0600).
struct PrivateTemp {
    dir: PathBuf,
    file: PathBuf,
}

impl PrivateTemp {
    fn create(initial: &str) -> io::Result<Self> {
        let base = std::env::temp_dir();
        let mut last_err = None;
        for _ in 0..8 {
            let suffix: u64 = rand_suffix();
            let dir = base.join(format!("bwtui-edit-{}-{suffix:016x}", std::process::id()));
            match create_private_dir(&dir) {
                Ok(()) => {
                    let file = dir.join("note.txt");
                    let this = Self {
                        dir,
                        file: file.clone(),
                    };
                    write_private_file(&file, initial.as_bytes())?;
                    return Ok(this);
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last_err = Some(e),
                Err(e) => return Err(e),
            }
        }
        Err(last_err.unwrap_or_else(|| io::Error::other("cannot create temp dir")))
    }

    fn scrub(&self) {
        if let Ok(meta) = fs::metadata(&self.file) {
            if let Ok(mut f) = OpenOptions::new().write(true).open(&self.file) {
                let zeros = vec![0u8; meta.len() as usize];
                let _ = f.write_all(&zeros);
                let _ = f.sync_all();
            }
        }
        let _ = fs::remove_file(&self.file);
        let _ = fs::remove_dir(&self.dir);
    }
}

impl Drop for PrivateTemp {
    fn drop(&mut self) {
        self.scrub();
    }
}

fn rand_suffix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    // Mix in a stack address for a little extra entropy; the 0700 dir is the real protection.
    let marker = 0u8;
    nanos ^ ((&marker as *const u8 as u64).rotate_left(32))
}

#[cfg(unix)]
fn create_private_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(dir)
}

#[cfg(not(unix))]
fn create_private_dir(dir: &Path) -> io::Result<()> {
    fs::create_dir(dir)
}

#[cfg(unix)]
fn write_private_file(path: &Path, data: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)?;
    f.sync_all()
}

#[cfg(not(unix))]
fn write_private_file(path: &Path, data: &[u8]) -> io::Result<()> {
    let mut f = OpenOptions::new().write(true).create_new(true).open(path)?;
    f.write_all(data)?;
    f.sync_all()
}

/// Open `initial` in the user's editor and return the edited text.
///
/// `Ok(None)` means the editor exited with a non-zero status (treated as "cancel").
pub fn edit_text(initial: &str) -> io::Result<Option<String>> {
    edit_text_with(&editor_command(), initial)
}

/// Same as [`edit_text`] with an explicit editor command line (used by tests).
pub fn edit_text_with(editor: &str, initial: &str) -> io::Result<Option<String>> {
    let parts = split_command(editor);
    let Some((program, args)) = parts.split_first() else {
        return Err(io::Error::other("empty editor command"));
    };
    let tmp = PrivateTemp::create(initial)?;
    let status = Command::new(program).args(args).arg(&tmp.file).status()?;
    if !status.success() {
        return Ok(None);
    }
    let mut text = fs::read_to_string(&tmp.file)?;
    // Editors append a trailing newline; drop exactly one.
    if text.ends_with('\n') {
        text.pop();
        if text.ends_with('\r') {
            text.pop();
        }
    }
    Ok(Some(text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_quoted_commands() {
        assert_eq!(split_command("code -w"), vec!["code", "-w"]);
        assert_eq!(
            split_command("\"/Applications/My Editor\" --wait"),
            vec!["/Applications/My Editor", "--wait"]
        );
        assert!(split_command("   ").is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn temp_file_is_private_and_cleaned() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = PrivateTemp::create("secret").unwrap();
        let fm = fs::metadata(&tmp.file).unwrap().permissions().mode() & 0o777;
        let dm = fs::metadata(&tmp.dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(fm, 0o600);
        assert_eq!(dm, 0o700);
        let (f, d) = (tmp.file.clone(), tmp.dir.clone());
        drop(tmp);
        assert!(!f.exists());
        assert!(!d.exists());
    }

    #[cfg(unix)]
    #[test]
    fn round_trip_with_fake_editor() {
        // `sh -c 'printf edited > "$1"' sh FILE` — the editor writes new content.
        let got = edit_text_with("sh -c 'echo edited > \"$1\"' sh", "orig").unwrap();
        // `echo` appends a newline which the editor wrapper strips.
        assert_eq!(got.as_deref(), Some("edited"));
    }

    #[cfg(unix)]
    #[test]
    fn failing_editor_cancels() {
        assert_eq!(edit_text_with("false", "x").unwrap(), None);
    }
}
