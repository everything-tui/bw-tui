//! Unlock daemon: a per-profile background process that keeps one unlocked
//! [`Session`] in memory and serves it over a Unix socket.
//!
//! `bitwarden-tui unlock` prints a `BW_SESSION` token. Any later CLI invocation that sees
//! `BW_SESSION` (or `--session`) talks to the daemon instead of prompting for the master
//! password. The socket lives in a `0700` directory with mode `0600` and every request must
//! carry the token. The daemon exits (and zeroizes the session) on `lock`, or when the
//! profile's idle auto-lock fires.
//!
//! Wire format: one JSON object per line.
//! Request `{ "token": "...", "method": "list", "params": {...} }`,
//! response `{ "ok": true, "result": ... }` or `{ "ok": false, "error": "..." }`.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Debug, Serialize, Deserialize)]
struct Request {
    #[serde(default)]
    token: String,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Serialize, Deserialize)]
struct Response {
    ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Why a daemon request did not produce a value.
#[derive(Debug)]
pub enum AgentError {
    /// No daemon is listening for this profile.
    Unavailable,
    /// The daemon answered with an error (bad token, failed operation, …).
    Remote(String),
}

impl std::fmt::Display for AgentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable => write!(f, "unlock agent is not running"),
            Self::Remote(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for AgentError {}

/// Random 256-bit session token (URL-safe base64, no padding).
pub fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Directory that holds agent sockets (short path: `sockaddr_un` is ~104 bytes on macOS).
pub fn socket_dir() -> PathBuf {
    if let Some(rt) = std::env::var_os("XDG_RUNTIME_DIR").filter(|v| !v.is_empty()) {
        return PathBuf::from(rt).join("bitwarden-tui");
    }
    #[cfg(unix)]
    let uid = unsafe { libc::getuid() };
    #[cfg(not(unix))]
    let uid = 0u32;
    std::env::temp_dir().join(format!("bitwarden-tui-{uid}"))
}

pub fn socket_path(profile_id: &str) -> PathBuf {
    let name = if profile_id.len() <= 24 {
        profile_id.to_string()
    } else {
        let digest = Sha256::digest(profile_id.as_bytes());
        digest[..8].iter().map(|b| format!("{b:02x}")).collect()
    };
    socket_dir().join(format!("{name}.sock"))
}

#[cfg(unix)]
mod imp {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Command, Stdio};
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
    use tokio::net::{UnixListener, UnixStream};
    use vault_session::{ensure_dir, Session, SessionStatus};

    /// Send one request to the daemon for `profile_id`.
    pub async fn request(
        profile_id: &str,
        token: &str,
        method: &str,
        params: &Value,
    ) -> std::result::Result<Value, AgentError> {
        let path = socket_path(profile_id);
        let stream = match UnixStream::connect(&path).await {
            Ok(s) => s,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::ConnectionRefused {
                    let _ = std::fs::remove_file(&path); // stale socket
                }
                return Err(AgentError::Unavailable);
            }
        };
        let req = Request {
            token: token.to_string(),
            method: method.to_string(),
            params: params.clone(),
        };
        let mut line =
            serde_json::to_string(&req).map_err(|e| AgentError::Remote(e.to_string()))?;
        line.push('\n');
        let (rd, mut wr) = stream.into_split();
        wr.write_all(line.as_bytes())
            .await
            .map_err(|e| AgentError::Remote(format!("agent write: {e}")))?;
        let mut reader = TokioBufReader::new(rd);
        let mut resp_line = String::new();
        reader
            .read_line(&mut resp_line)
            .await
            .map_err(|e| AgentError::Remote(format!("agent read: {e}")))?;
        if resp_line.trim().is_empty() {
            return Err(AgentError::Remote("agent closed the connection".into()));
        }
        let resp: Response = serde_json::from_str(&resp_line)
            .map_err(|e| AgentError::Remote(format!("bad agent response: {e}")))?;
        if resp.ok {
            Ok(resp.result.unwrap_or(Value::Null))
        } else {
            Err(AgentError::Remote(
                resp.error.unwrap_or_else(|| "agent error".into()),
            ))
        }
    }

    pub async fn is_running(profile_id: &str) -> bool {
        UnixStream::connect(socket_path(profile_id)).await.is_ok()
    }

    /// Ask the daemon to lock and exit. Returns `false` when none was running.
    pub async fn lock(profile_id: &str) -> Result<bool> {
        match request(profile_id, "", "lock", &Value::Null).await {
            Ok(_) => Ok(true),
            Err(AgentError::Unavailable) => Ok(false),
            Err(AgentError::Remote(e)) => bail!("{e}"),
        }
    }

    /// Spawn the daemon (`agent-run` hidden subcommand), hand it the password over a pipe
    /// and wait until it reports a successful unlock. Returns the new session token.
    pub async fn spawn_unlocked(profile_id: &str, password: &str) -> Result<String> {
        if is_running(profile_id).await {
            bail!("already unlocked for profile `{profile_id}` — run `lock` first");
        }
        let token = generate_token();
        let exe = std::env::current_exe().context("locate current executable")?;
        let mut child = Command::new(exe)
            .arg("--profile")
            .arg(profile_id)
            .arg("agent-run")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("spawn unlock agent")?;
        {
            let mut stdin = child.stdin.take().context("agent stdin")?;
            stdin.write_all(token.as_bytes())?;
            stdin.write_all(b"\n")?;
            stdin.write_all(password.as_bytes())?;
            stdin.write_all(b"\n")?;
        } // stdin dropped → EOF
        let stdout = child.stdout.take().context("agent stdout")?;
        let reply = tokio::task::spawn_blocking(move || {
            let mut line = String::new();
            let _ = BufReader::new(stdout).read_line(&mut line);
            line
        })
        .await
        .context("wait for agent")?;
        let reply = reply.trim();
        if reply == "ok" {
            // Daemon keeps running detached; do not wait on it.
            drop(child);
            Ok(token)
        } else {
            let _ = child.wait();
            match reply.strip_prefix("error: ") {
                Some(msg) => bail!("{msg}"),
                None => bail!("unlock agent failed to start"),
            }
        }
    }

    fn detach_stdio() {
        // Point fds 0/1/2 at /dev/null so the daemon never touches the caller's terminal.
        unsafe {
            let devnull = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
            if devnull >= 0 {
                libc::dup2(devnull, 0);
                libc::dup2(devnull, 1);
                libc::dup2(devnull, 2);
                if devnull > 2 {
                    libc::close(devnull);
                }
            }
            libc::setsid();
        }
    }

    /// Daemon entry point (stdin: `token\npassword\n`; stdout: `ok` / `error: ...`).
    pub async fn run_daemon(
        data_dir: PathBuf,
        profile_id: String,
        allow_plaintext_token: bool,
        auto_lock_minutes: Option<u64>,
    ) -> Result<()> {
        let mut input = String::new();
        std::io::stdin().read_to_string(&mut input)?;
        let mut lines = input.lines();
        let token = lines.next().unwrap_or("").to_string();
        let password = lines.next().unwrap_or("").to_string();

        let started = start_session(
            &data_dir,
            allow_plaintext_token,
            auto_lock_minutes,
            &password,
        )
        .await
        .and_then(|s| bind_socket(&profile_id).map(|l| (s, l)));
        let (mut session, listener) = match started {
            Ok(v) => v,
            Err(e) => {
                println!("error: {e:#}");
                let _ = std::io::stdout().flush();
                return Ok(());
            }
        };
        println!("ok");
        let _ = std::io::stdout().flush();
        detach_stdio();

        let path = socket_path(&profile_id);
        serve_loop(&listener, &mut session, &token, true).await;
        let _ = std::fs::remove_file(&path);
        Ok(())
    }

    /// Accept connections until `lock` is requested (or, when `exit_when_locked`, until the
    /// session auto-locks), then zeroize the session.
    pub(super) async fn serve_loop(
        listener: &UnixListener,
        session: &mut Session,
        token: &str,
        exit_when_locked: bool,
    ) {
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let Ok((stream, _)) = accepted else { continue };
                    let outcome = tokio::time::timeout(
                        Duration::from_secs(120),
                        handle_conn(stream, session, token),
                    ).await;
                    if matches!(outcome, Ok(true)) {
                        break;
                    }
                }
                _ = tick.tick() => {
                    session.tick();
                    if exit_when_locked && session.status() != SessionStatus::Unlocked {
                        break;
                    }
                }
            }
        }
        session.lock();
    }

    async fn start_session(
        data_dir: &Path,
        allow_plaintext_token: bool,
        auto_lock_minutes: Option<u64>,
        password: &str,
    ) -> Result<Session> {
        let mut session = Session::try_restore_saved(data_dir.to_path_buf(), allow_plaintext_token)
            .await
            .context("restore session")?
            .ok_or_else(|| anyhow!("no saved session — run `login` first"))?;
        session.set_auto_lock(auto_lock_minutes);
        session.unlock(password).await.context("unlock")?;
        Ok(session)
    }

    fn bind_socket(profile_id: &str) -> Result<UnixListener> {
        let dir = socket_dir();
        ensure_dir(&dir).map_err(|e| anyhow!("create {}: {e}", dir.display()))?;
        let path = socket_path(profile_id);
        let _ = std::fs::remove_file(&path);
        let listener =
            UnixListener::bind(&path).with_context(|| format!("bind {}", path.display()))?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        Ok(listener)
    }

    /// Serve one connection. Returns `true` when the daemon should shut down.
    async fn handle_conn(stream: UnixStream, session: &mut Session, token: &str) -> bool {
        let (rd, mut wr) = stream.into_split();
        let mut reader = TokioBufReader::new(rd);
        let mut line = String::new();
        if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
            return false;
        }
        let (resp, shutdown) = match serde_json::from_str::<Request>(&line) {
            Err(e) => (err_resp(format!("bad request: {e}")), false),
            Ok(req) if req.method == "lock" => {
                // Locking needs no token: the socket is already user-private.
                (ok_resp(serde_json::json!({ "locked": true })), true)
            }
            Ok(req) if !ct_eq(&req.token, token) => (err_resp("invalid session token"), false),
            Ok(req) if req.method == "ping" => (ok_resp(Value::Null), false),
            Ok(req) => match crate::api::dispatch(session, &req.method, &req.params).await {
                Ok(v) => (ok_resp(v), false),
                Err(e) => (err_resp(format!("{e:#}")), false),
            },
        };
        let mut out = serde_json::to_string(&resp).unwrap_or_else(|_| "{\"ok\":false}".into());
        out.push('\n');
        let _ = wr.write_all(out.as_bytes()).await;
        let _ = wr.flush().await;
        shutdown
    }

    fn ok_resp(v: Value) -> Response {
        Response {
            ok: true,
            result: Some(v),
            error: None,
        }
    }

    fn err_resp(msg: impl Into<String>) -> Response {
        Response {
            ok: false,
            result: None,
            error: Some(msg.into()),
        }
    }
}

#[cfg(not(unix))]
mod imp {
    use super::*;

    pub async fn request(
        _profile_id: &str,
        _token: &str,
        _method: &str,
        _params: &Value,
    ) -> std::result::Result<Value, AgentError> {
        Err(AgentError::Unavailable)
    }

    pub async fn is_running(_profile_id: &str) -> bool {
        false
    }

    pub async fn lock(_profile_id: &str) -> Result<bool> {
        Ok(false)
    }

    pub async fn spawn_unlocked(_profile_id: &str, _password: &str) -> Result<String> {
        bail!("the unlock agent requires a Unix platform")
    }

    pub async fn run_daemon(
        _data_dir: PathBuf,
        _profile_id: String,
        _allow_plaintext_token: bool,
        _auto_lock_minutes: Option<u64>,
    ) -> Result<()> {
        bail!("the unlock agent requires a Unix platform")
    }
}

pub use imp::{is_running, lock, request, run_daemon, spawn_unlocked};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_unique_and_compare() {
        let a = generate_token();
        let b = generate_token();
        assert_ne!(a, b);
        assert!(ct_eq(&a, &a.clone()));
        assert!(!ct_eq(&a, &b));
        assert!(!ct_eq("a", "ab"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn socket_round_trip_checks_token_and_locks() {
        use tokio::net::UnixListener;
        use vault_session::Session;

        let dir = tempfile::Builder::new()
            .prefix("bwtui")
            .tempdir_in("/tmp")
            .unwrap();
        std::env::set_var("XDG_RUNTIME_DIR", dir.path());
        std::fs::create_dir_all(socket_dir()).unwrap();
        let path = socket_path("t");
        let listener = UnixListener::bind(&path).unwrap();
        let mut session =
            Session::with_data_dir("https://vault.example", dir.path().join("p")).unwrap();
        let server = tokio::spawn(async move {
            imp::serve_loop(&listener, &mut session, "secret", false).await;
        });

        assert!(is_running("t").await);
        let ok = request("t", "secret", "status", &Value::Null)
            .await
            .unwrap();
        assert_eq!(ok["serverUrl"], "https://vault.example");
        match request("t", "wrong", "status", &Value::Null).await {
            Err(AgentError::Remote(m)) => assert!(m.contains("invalid session token")),
            other => panic!("expected token rejection, got {other:?}"),
        }
        match request("t", "secret", "nope", &Value::Null).await {
            Err(AgentError::Remote(m)) => assert!(m.contains("unknown method")),
            other => panic!("expected unknown method, got {other:?}"),
        }
        assert!(lock("t").await.unwrap());
        server.await.unwrap();
        drop(dir);
    }

    #[test]
    fn long_profile_ids_get_short_socket_names() {
        let long = "a".repeat(60);
        let name = socket_path(&long);
        assert!(name.file_name().unwrap().len() < 30);
        assert_eq!(socket_path("work").file_name().unwrap(), "work.sock");
    }
}
