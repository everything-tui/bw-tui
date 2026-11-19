//! One-shot `http://localhost:<port>` callback listener (Duo / SSO redirects).
//!
//! Runs on a background thread so the TUI event loop never blocks: poll with
//! [`LoopbackListener::try_recv`] from the tick handler.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub struct LoopbackListener {
    port: u16,
    rx: Receiver<String>,
    cancel: Arc<AtomicBool>,
}

impl LoopbackListener {
    /// Bind `127.0.0.1:0` and wait up to `timeout` for a request carrying `code=` or `error=`.
    pub fn start(timeout: Duration) -> std::io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let (tx, rx) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let cancel_thread = Arc::clone(&cancel);
        std::thread::spawn(move || {
            let deadline = Instant::now() + timeout;
            while Instant::now() < deadline && !cancel_thread.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        if let Some(target) = handle_conn(stream) {
                            let _ = tx.send(target);
                            return;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    Err(_) => return,
                }
            }
        });
        Ok(Self { port, rx, cancel })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn redirect_uri(&self) -> String {
        format!("http://localhost:{}", self.port)
    }

    /// Request target (`/?code=…&state=…`) once the browser has been redirected here.
    pub fn try_recv(&self) -> Option<String> {
        self.rx.try_recv().ok()
    }
}

impl Drop for LoopbackListener {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}

fn handle_conn(mut stream: TcpStream) -> Option<String> {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let mut buf = [0u8; 8192];
    let n = stream.read(&mut buf).ok()?;
    let req = String::from_utf8_lossy(&buf[..n]);
    let target = parse_request_target(&req)?;
    let wanted = target.contains("code=") || target.contains("error=");
    let (status, body) = if wanted {
        (
            "200 OK",
            "<html><body style=\"font-family:sans-serif\"><h3>Authentication complete</h3>\
             <p>You can close this tab and return to the terminal.</p></body></html>",
        )
    } else {
        ("404 Not Found", "not found")
    };
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(resp.as_bytes());
    let _ = stream.flush();
    wanted.then_some(target)
}

fn parse_request_target(req: &str) -> Option<String> {
    let line = req.lines().next()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?;
    if method != "GET" {
        return None;
    }
    parts.next().map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_get_target() {
        assert_eq!(
            parse_request_target("GET /?code=a&state=b HTTP/1.1\r\nHost: x\r\n").as_deref(),
            Some("/?code=a&state=b")
        );
        assert_eq!(parse_request_target("POST / HTTP/1.1"), None);
    }

    #[test]
    fn receives_callback() {
        let l = LoopbackListener::start(Duration::from_secs(5)).unwrap();
        let mut s = TcpStream::connect(("127.0.0.1", l.port())).unwrap();
        s.write_all(b"GET /?code=abc&state=xyz HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap();
        let mut got = None;
        for _ in 0..50 {
            if let Some(t) = l.try_recv() {
                got = Some(t);
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(got.as_deref(), Some("/?code=abc&state=xyz"));
    }
}
