//! `serve`: a small localhost REST API compatible with a subset of `bw serve`.
//!
//! Unlike `bw serve`, every request must carry the server token
//! (`Authorization: Bearer <token>` or `?token=`), and only loopback `Host` headers are
//! accepted when bound to a loopback address (DNS-rebinding guard).
//!
//! Routes (responses use `{ "success": true, "data": … }` like `bw serve`):
//!
//! | Method | Path |
//! |--------|------|
//! | GET    | `/status` |
//! | GET    | `/list/object/{items,folders,collections,organizations,org-collections}` |
//! | GET    | `/object/{item,password,username,uri,totp,notes,exposed,folder,collection,organization,template,fingerprint}/{id}` |
//! | POST   | `/sync` |
//! | GET/POST | `/generate` |
//! | POST/PUT/DELETE | `/object/item[/{id}]`, `POST /restore/item/{id}`, `POST /move/{id}/{folder}` |
//! | POST   | `/lock` (locks and stops the server) |

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use percent_encoding::percent_decode_str;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::cli::Backend;

const MAX_HEADER: usize = 16 * 1024;
const MAX_BODY: usize = 1024 * 1024;

pub struct ServeOpts {
    pub host: String,
    pub port: u16,
    pub token: String,
}

#[derive(Debug)]
pub struct HttpReq {
    pub method: String,
    pub segments: Vec<String>,
    pub query: HashMap<String, String>,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

fn is_loopback_host(h: &str) -> bool {
    matches!(h, "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

fn host_header_ok(raw: &str) -> bool {
    let host = if let Some(rest) = raw.strip_prefix('[') {
        rest.split(']').next().unwrap_or("")
    } else {
        raw.rsplit_once(':').map(|(h, _)| h).unwrap_or(raw)
    };
    is_loopback_host(host)
}

fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn dec(s: &str) -> String {
    percent_decode_str(s).decode_utf8_lossy().into_owned()
}

fn parse_target(target: &str) -> (Vec<String>, HashMap<String, String>) {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let segments = path.split('/').filter(|s| !s.is_empty()).map(dec).collect();
    let query = query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (dec(&k.replace('+', " ")), dec(&v.replace('+', " ")))
        })
        .collect();
    (segments, query)
}

async fn read_request(stream: &mut TcpStream) -> Result<HttpReq> {
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0u8; 2048];
    let header_end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
        if buf.len() > MAX_HEADER {
            bail!("headers too large");
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            bail!("connection closed");
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_uppercase();
    let target = parts.next().unwrap_or("/");
    let mut headers = HashMap::new();
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            headers.insert(k.trim().to_lowercase(), v.trim().to_string());
        }
    }
    let content_len: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if content_len > MAX_BODY {
        bail!("body too large");
    }
    let mut body = buf[header_end + 4..].to_vec();
    while body.len() < content_len {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            bail!("connection closed mid-body");
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(content_len);
    let (segments, query) = parse_target(target);
    Ok(HttpReq {
        method,
        segments,
        query,
        headers,
        body,
    })
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Error",
    }
}

async fn write_response(stream: &mut TcpStream, status: u16, body: &Value) {
    let payload = body.to_string();
    let head = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nConnection: close\r\n\r\n",
        reason(status),
        payload.len()
    );
    let _ = stream.write_all(head.as_bytes()).await;
    let _ = stream.write_all(payload.as_bytes()).await;
    let _ = stream.shutdown().await;
}

fn failure(msg: impl Into<String>) -> Value {
    json!({ "success": false, "message": msg.into() })
}

fn success(data: Value) -> Value {
    json!({ "success": true, "data": data })
}

/// Wrap an api result the way `bw serve` does.
fn wrap(v: Value, template: bool) -> Value {
    match v {
        Value::String(s) => success(json!({ "object": "string", "data": s })),
        Value::Array(a) => success(json!({ "object": "list", "data": a })),
        other if template => success(json!({ "object": "template", "template": other })),
        other => success(other),
    }
}

fn authorized(req: &HttpReq, token: &str) -> bool {
    let bearer = req
        .headers
        .get("authorization")
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
        })
        .map(str::trim);
    let supplied = bearer.or_else(|| req.query.get("token").map(String::as_str));
    supplied.is_some_and(|t| ct_eq(t, token))
}

fn json_body(req: &HttpReq) -> Result<Value> {
    if req.body.is_empty() {
        bail!("request body required");
    }
    serde_json::from_slice(&req.body).context("body is not valid JSON")
}

/// Query-string → api params for list endpoints (`folderid` → `folder`, …).
fn list_params(kind: &str, q: &HashMap<String, String>) -> Value {
    let mut p = json!({ "object": kind });
    for (from, to) in [
        ("search", "search"),
        ("url", "url"),
        ("folderid", "folder"),
        ("collectionid", "collection"),
        ("organizationid", "organization"),
        ("trash", "trash"),
    ] {
        if let Some(v) = q.get(from) {
            p[to] = Value::String(v.clone());
        }
    }
    p
}

/// Route one request. Returns `(http status, body, stop_server)`.
async fn route(backend: &mut Backend, req: &HttpReq) -> (u16, Value, bool) {
    let segs: Vec<&str> = req.segments.iter().map(String::as_str).collect();
    let method = req.method.as_str();

    let result: Result<(Value, bool)> = async {
        match (method, segs.as_slice()) {
            ("GET", ["status"]) => {
                let v = backend.call("status", Value::Null).await?;
                Ok((wrap(v, true), false))
            }
            ("GET", ["list", "object", kind]) => {
                let v = backend.call("list", list_params(kind, &req.query)).await?;
                Ok((wrap(v, false), false))
            }
            ("GET", ["object", what, id]) => {
                let what = match *what {
                    "org" => "organization",
                    w => w,
                };
                let mut params = json!({ "what": what, "query": id });
                if let Some(u) = req.query.get("uri").or_else(|| req.query.get("url")) {
                    params["uri"] = u.clone().into();
                }
                let v = backend.call("get", params).await?;
                Ok((wrap(v, what == "template"), false))
            }
            ("POST", ["sync"]) => {
                backend.call("sync", Value::Null).await?;
                Ok((
                    success(json!({ "object": "string", "data": "Syncing complete." })),
                    false,
                ))
            }
            ("GET" | "POST", ["generate"]) => {
                let mut params = serde_json::Map::new();
                for (k, v) in &req.query {
                    if k != "token" {
                        params.insert(k.clone(), Value::String(v.clone()));
                    }
                }
                let v = backend.call("generate", Value::Object(params)).await?;
                Ok((wrap(v, false), false))
            }
            ("POST", ["object", "item"]) => {
                let item = json_body(req)?;
                let v = backend.call("item.create", json!({ "item": item })).await?;
                Ok((wrap(v, false), false))
            }
            ("PUT", ["object", "item", id]) => {
                let item = json_body(req)?;
                let v = backend
                    .call("item.edit", json!({ "query": id, "item": item }))
                    .await?;
                Ok((wrap(v, false), false))
            }
            ("DELETE", ["object", "item", id]) => {
                let permanent = req
                    .query
                    .get("permanent")
                    .is_some_and(|v| v != "false" && v != "0");
                let v = backend
                    .call(
                        "item.delete",
                        json!({ "query": id, "permanent": permanent }),
                    )
                    .await?;
                Ok((wrap(v, false), false))
            }
            ("POST", ["restore", "item", id]) => {
                let v = backend.call("item.restore", json!({ "query": id })).await?;
                Ok((wrap(v, false), false))
            }
            ("POST", ["move", id, folder]) => {
                let v = backend
                    .call("item.move", json!({ "query": id, "folder": folder }))
                    .await?;
                Ok((wrap(v, false), false))
            }
            ("POST", ["lock"]) => Ok((
                success(json!({ "object": "string", "data": "Your vault is locked." })),
                true,
            )),
            _ => bail!("__404"),
        }
    }
    .await;

    match result {
        Ok((body, stop)) => (200, body, stop),
        Err(e) if e.to_string() == "__404" => (404, failure("Not found"), false),
        Err(e) => (400, failure(format!("{e:#}")), false),
    }
}

/// Run the server until `/lock` or Ctrl-C. The backend is locked on exit.
pub async fn run(mut backend: Backend, opts: ServeOpts) -> Result<()> {
    let loopback = is_loopback_host(&opts.host);
    if !loopback {
        eprintln!(
            "warning: binding to non-loopback address `{}` — the API exposes your decrypted vault",
            opts.host
        );
    }
    let listener = TcpListener::bind((opts.host.as_str(), opts.port))
        .await
        .with_context(|| format!("bind {}:{}", opts.host, opts.port))?;
    let addr = listener.local_addr()?;
    eprintln!("listening on http://{addr}  (send `Authorization: Bearer <token>`)");

    let mut tick = tokio::time::interval(Duration::from_secs(5));
    loop {
        let (mut stream, peer) = tokio::select! {
            r = listener.accept() => r?,
            _ = tokio::signal::ctrl_c() => break,
            _ = tick.tick() => {
                if !backend.tick() {
                    eprintln!("session auto-locked; stopping server");
                    break;
                }
                continue;
            }
        };
        let req =
            match tokio::time::timeout(Duration::from_secs(10), read_request(&mut stream)).await {
                Ok(Ok(r)) => r,
                Ok(Err(e)) => {
                    write_response(&mut stream, 400, &failure(e.to_string())).await;
                    continue;
                }
                Err(_) => continue,
            };
        if loopback && !peer.ip().is_loopback() {
            write_response(&mut stream, 403, &failure("Forbidden")).await;
            continue;
        }
        if loopback {
            if let Some(h) = req.headers.get("host") {
                if !host_header_ok(h) {
                    write_response(&mut stream, 403, &failure("Forbidden host")).await;
                    continue;
                }
            }
        }
        if !authorized(&req, &opts.token) {
            write_response(&mut stream, 401, &failure("Unauthorized")).await;
            continue;
        }
        let (status, body, stop) = route(&mut backend, &req).await;
        write_response(&mut stream, status, &body).await;
        if stop {
            break;
        }
    }
    backend.close().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_target() {
        let (segs, q) = parse_target("/list/object/items?search=my%20bank&folderid=abc&trash=true");
        assert_eq!(segs, ["list", "object", "items"]);
        assert_eq!(q["search"], "my bank");
        assert_eq!(q["folderid"], "abc");
        let p = list_params("items", &q);
        assert_eq!(p["folder"], "abc");
        assert_eq!(p["trash"], "true");
    }

    #[test]
    fn host_guard() {
        assert!(host_header_ok("localhost:8087"));
        assert!(host_header_ok("127.0.0.1:1"));
        assert!(host_header_ok("[::1]:80"));
        assert!(!host_header_ok("evil.example:8087"));
    }

    #[test]
    fn auth_bearer_or_query() {
        let mut req = HttpReq {
            method: "GET".into(),
            segments: vec![],
            query: HashMap::new(),
            headers: HashMap::new(),
            body: vec![],
        };
        assert!(!authorized(&req, "t"));
        req.headers
            .insert("authorization".into(), "Bearer t".into());
        assert!(authorized(&req, "t"));
        req.headers.clear();
        req.query.insert("token".into(), "t".into());
        assert!(authorized(&req, "t"));
        req.query.insert("token".into(), "x".into());
        assert!(!authorized(&req, "t"));
    }

    #[test]
    fn wraps_like_bw() {
        assert_eq!(wrap(json!("x"), false)["data"]["object"], "string");
        assert_eq!(wrap(json!([1]), false)["data"]["object"], "list");
        assert_eq!(wrap(json!({"a":1}), true)["data"]["object"], "template");
    }
}
