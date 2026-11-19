//! Bitwarden Send: create options, request building, and public receive flow.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Duration, Local, NaiveDate, NaiveDateTime, SecondsFormat, TimeZone, Utc};
use vault_api::{ApiError, ClientConfig, SendFile, SendRequest, SendText, VaultClient};

use crate::error::{Result, SessionError};
use crate::send_crypto::{
    decrypt_send_file_bytes, decrypt_send_meta_field, decrypt_send_text_field, encrypt_send_meta,
    encrypt_send_text, hash_send_password, parse_send_url,
};

/// Server-enforced maximum lifetime of a Send.
pub const MAX_SEND_LIFETIME_DAYS: i64 = 31;
/// Default deletion date offset when none is chosen.
pub const DEFAULT_SEND_LIFETIME_DAYS: i64 = 7;
/// Hard cap for file Sends handled in memory.
pub const MAX_SEND_FILE_BYTES: u64 = 500 * 1024 * 1024;

pub const SEND_TYPE_TEXT: u8 = 0;
pub const SEND_TYPE_FILE: u8 = 1;

/// Options shared by text and file Sends.
#[derive(Debug, Clone, Default)]
pub struct SendOptions {
    /// Private notes (encrypted with the send key; never shown to recipients).
    pub notes: Option<String>,
    /// Plaintext password to protect the Send (hashed before upload). `None` = unchanged/none.
    pub password: Option<String>,
    /// On update: drop the existing password.
    pub remove_password: bool,
    /// Maximum number of accesses; `None` or `0` = unlimited.
    pub max_access_count: Option<u32>,
    /// RFC 3339 timestamp after which the Send can no longer be accessed.
    pub expiration_date: Option<String>,
    /// RFC 3339 deletion timestamp. `None` = keep existing (update) / now + 7 days (create).
    pub deletion_date: Option<String>,
    /// Hide the creator's email from recipients.
    pub hide_email: bool,
    /// Deactivate the Send without deleting it.
    pub disabled: bool,
    /// Text Sends: hide the body by default on the receive page.
    pub hidden_text: bool,
}

/// Result of a successful public Send access.
#[derive(Debug, Clone)]
pub struct ReceivedSend {
    pub origin: String,
    pub access_id: String,
    /// Server Send id (needed for the file download endpoint).
    pub send_id: Option<String>,
    pub send_type: u8,
    pub name: String,
    pub text: Option<String>,
    pub text_hidden: bool,
    pub file: Option<ReceivedSendFile>,
    pub expiration_date: Option<String>,
    pub creator_identifier: Option<String>,
    key: [u8; 16],
    password_hash: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ReceivedSendFile {
    pub id: String,
    pub name: String,
    pub size_name: Option<String>,
    pub size: Option<u64>,
}

impl ReceivedSend {
    pub fn is_file(&self) -> bool {
        self.send_type == SEND_TYPE_FILE
    }
}

/// True when the access error means the Send needs (or rejected) a password.
pub fn is_send_password_error(err: &SessionError) -> bool {
    match err {
        SessionError::Api(ApiError::Api { status, message }) => {
            *status == 401 || (*status == 400 && message.to_ascii_lowercase().contains("password"))
        }
        _ => false,
    }
}

/// Fetch and decrypt a Send from a share link (no login required).
pub async fn receive_send(url: &str, password: Option<&str>) -> Result<ReceivedSend> {
    let parsed = parse_send_url(url)?;
    let client = VaultClient::new(ClientConfig::new(&parsed.origin)?)?;
    let password_hash = match password.filter(|p| !p.is_empty()) {
        Some(p) => Some(hash_send_password(p, &parsed.key)?),
        None => None,
    };
    let resp = client
        .access_send(&parsed.access_id, password_hash.as_deref())
        .await?;
    received_from_response(
        parsed.origin,
        parsed.access_id,
        parsed.key,
        password_hash,
        resp,
    )
}

fn received_from_response(
    origin: String,
    access_id: String,
    key: [u8; 16],
    password_hash: Option<String>,
    resp: vault_api::SendAccessResponse,
) -> Result<ReceivedSend> {
    let name = match resp.name.as_deref() {
        Some(n) => decrypt_send_meta_field(&key, n)?,
        None => String::new(),
    };
    let (text, text_hidden) = match resp.text.as_ref() {
        Some(t) => (
            match t.text.as_deref() {
                Some(enc) => Some(decrypt_send_text_field(&key, enc)?),
                None => None,
            },
            t.hidden,
        ),
        None => (None, false),
    };
    let file = match resp.file.as_ref() {
        Some(f) => Some(ReceivedSendFile {
            id: f.id.clone().unwrap_or_default(),
            name: match f.file_name.as_deref() {
                Some(enc) => decrypt_send_meta_field(&key, enc)?,
                None => "send-file".into(),
            },
            size_name: f.size_name.clone(),
            size: f.size,
        }),
        None => None,
    };
    Ok(ReceivedSend {
        origin,
        access_id,
        send_id: resp.id,
        send_type: resp.send_type,
        name,
        text,
        text_hidden,
        file,
        expiration_date: resp.expiration_date,
        creator_identifier: resp.creator_identifier,
        key,
        password_hash,
    })
}

/// Download and decrypt the file of a received file Send.
pub async fn download_received_file(received: &ReceivedSend) -> Result<Vec<u8>> {
    let file = received
        .file
        .as_ref()
        .ok_or_else(|| SessionError::Other("send has no file".into()))?;
    let send_id = received
        .send_id
        .as_deref()
        .ok_or_else(|| SessionError::Other("send response missing id".into()))?;
    let client = VaultClient::new(ClientConfig::new(&received.origin)?)?;
    let dl = client
        .access_send_file(send_id, &file.id, received.password_hash.as_deref())
        .await?;
    let blob = client.download_url_bytes(&dl.url).await?;
    decrypt_send_file_bytes(&received.key, &blob)
}

/// Reduce an untrusted file name to a safe single path component.
pub fn sanitize_file_name(name: &str) -> String {
    let base = name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("")
        .trim()
        .trim_start_matches('.');
    let cleaned: String = base
        .chars()
        .map(|c| if c.is_control() { '_' } else { c })
        .collect();
    if cleaned.is_empty() {
        "send-file".into()
    } else {
        cleaned
    }
}

/// Download a received file Send to `dest` (a file path, or an existing directory).
/// Refuses to overwrite an existing file. Returns the written path.
pub async fn save_received_file(received: &ReceivedSend, dest: &Path) -> Result<PathBuf> {
    let name = received
        .file
        .as_ref()
        .map(|f| f.name.as_str())
        .unwrap_or("send-file");
    let target = if dest.is_dir() {
        dest.join(sanitize_file_name(name))
    } else {
        dest.to_path_buf()
    };
    if target.exists() {
        return Err(SessionError::Other(format!(
            "refusing to overwrite {}",
            target.display()
        )));
    }
    let bytes = download_received_file(received).await?;
    std::fs::write(&target, bytes)?;
    Ok(target)
}

/// Human-readable byte size (`1.5 KB`).
pub fn format_file_size(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["Bytes", "KB", "MB", "GB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} Bytes")
    } else {
        format!("{:.1} {}", value, UNITS[unit])
    }
}

fn to_rfc3339(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Parse a user-entered date for send expiration/deletion into an RFC 3339 UTC string.
///
/// Accepts RFC 3339, `YYYY-MM-DD` / `YYYY-MM-DD HH:MM[:SS]` (local time, date only = 00:00),
/// or relative offsets from `now` such as `30m`, `12h`, `7d`, `2w`.
pub fn parse_send_date(input: &str, now: DateTime<Utc>) -> Result<String> {
    let s = input.trim();
    if s.is_empty() {
        return Err(SessionError::Other("empty date".into()));
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Ok(to_rfc3339(dt.with_timezone(&Utc)));
    }
    // Relative: <n><m|h|d|w>
    if let Some(unit) = s.chars().last() {
        let digits = &s[..s.len() - unit.len_utf8()];
        if let Ok(n) = digits.parse::<i64>() {
            let delta = match unit.to_ascii_lowercase() {
                'm' => Some(Duration::minutes(n)),
                'h' => Some(Duration::hours(n)),
                'd' => Some(Duration::days(n)),
                'w' => Some(Duration::weeks(n)),
                _ => None,
            };
            if let Some(d) = delta {
                return Ok(to_rfc3339(now + d));
            }
        }
    }
    let naive = NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S")
        .or_else(|_| NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M"))
        .or_else(|_| {
            NaiveDate::parse_from_str(s, "%Y-%m-%d").map(|d| d.and_hms_opt(0, 0, 0).unwrap())
        })
        .map_err(|_| {
            SessionError::Other(format!(
                "invalid date `{s}` (use YYYY-MM-DD[ HH:MM], RFC 3339, or 30m/12h/7d/2w)"
            ))
        })?;
    let local = Local
        .from_local_datetime(&naive)
        .earliest()
        .ok_or_else(|| SessionError::Other(format!("ambiguous local date `{s}`")))?;
    Ok(to_rfc3339(local.with_timezone(&Utc)))
}

/// Everything needed to build a `SendRequest` (pure; no I/O).
pub(crate) struct SendRequestInput<'a> {
    pub send_type: u8,
    pub key: &'a [u8; 16],
    pub wrapped_key: String,
    pub name: &'a str,
    pub opts: &'a SendOptions,
    pub text: Option<&'a str>,
    pub file: Option<SendFile>,
    pub file_length: Option<u64>,
    /// Existing deletion date to preserve when `opts.deletion_date` is `None`.
    pub existing_deletion: Option<&'a str>,
    pub now: DateTime<Utc>,
}

pub(crate) fn build_send_request(input: SendRequestInput<'_>) -> Result<SendRequest> {
    let SendRequestInput {
        send_type,
        key,
        wrapped_key,
        name,
        opts,
        text,
        file,
        file_length,
        existing_deletion,
        now,
    } = input;

    if name.trim().is_empty() {
        return Err(SessionError::Other("send name is required".into()));
    }
    let deletion = match (opts.deletion_date.as_deref(), existing_deletion) {
        (Some(d), _) | (None, Some(d)) => d.to_string(),
        (None, None) => to_rfc3339(now + Duration::days(DEFAULT_SEND_LIFETIME_DAYS)),
    };
    // Only validate dates we are (re)setting; an existing server date is trusted.
    if opts.deletion_date.is_some() || existing_deletion.is_none() {
        validate_deletion_date(&deletion, now)?;
    }
    if let Some(exp) = opts.expiration_date.as_deref() {
        let exp_dt = DateTime::parse_from_rfc3339(exp)
            .map_err(|_| SessionError::Other(format!("invalid expiration date `{exp}`")))?;
        let del_dt = DateTime::parse_from_rfc3339(&deletion)
            .map_err(|_| SessionError::Other(format!("invalid deletion date `{deletion}`")))?;
        if exp_dt > del_dt {
            return Err(SessionError::Other(
                "expiration date must not be after the deletion date".into(),
            ));
        }
    }

    let notes = match opts.notes.as_deref().map(str::trim) {
        Some(n) if !n.is_empty() => Some(encrypt_send_meta(key, n)?),
        _ => None,
    };
    let password = match opts.password.as_deref() {
        Some(p) if !p.is_empty() => Some(hash_send_password(p, key)?),
        _ => None,
    };
    let text = match text {
        Some(t) => Some(SendText {
            text: Some(encrypt_send_text(key, t)?),
            hidden: opts.hidden_text,
        }),
        None => None,
    };

    Ok(SendRequest {
        send_type,
        name: encrypt_send_meta(key, name.trim())?,
        notes,
        key: Some(wrapped_key),
        password,
        max_access_count: opts.max_access_count.filter(|n| *n > 0),
        expiration_date: opts.expiration_date.clone(),
        disabled: opts.disabled,
        hide_email: opts.hide_email,
        text,
        file,
        deletion_date: Some(deletion),
        file_length,
    })
}

fn validate_deletion_date(deletion: &str, now: DateTime<Utc>) -> Result<()> {
    let dt = DateTime::parse_from_rfc3339(deletion)
        .map_err(|_| SessionError::Other(format!("invalid deletion date `{deletion}`")))?
        .with_timezone(&Utc);
    if dt <= now {
        return Err(SessionError::Other(
            "deletion date must be in the future".into(),
        ));
    }
    if dt > now + Duration::days(MAX_SEND_LIFETIME_DAYS) + Duration::minutes(5) {
        return Err(SessionError::Other(format!(
            "deletion date must be within {MAX_SEND_LIFETIME_DAYS} days"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::send_crypto::{
        decrypt_send_meta_field, encode_send_key, encrypt_send_file_bytes,
        generate_send_key_material,
    };

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 12, 9, 0, 0).unwrap()
    }

    #[test]
    fn parse_relative_and_rfc3339_dates() {
        assert_eq!(
            parse_send_date("7d", now()).unwrap(),
            "2026-10-19T09:00:00.000Z"
        );
        assert_eq!(
            parse_send_date("2h", now()).unwrap(),
            "2026-10-12T11:00:00.000Z"
        );
        assert_eq!(
            parse_send_date("2026-12-01T10:00:00+02:00", now()).unwrap(),
            "2026-12-01T08:00:00.000Z"
        );
        assert!(parse_send_date("tomorrow-ish", now()).is_err());
        assert!(parse_send_date("", now()).is_err());
        // Local date-only parses to some RFC 3339 UTC timestamp.
        assert!(parse_send_date("2026-10-20", now()).unwrap().ends_with('Z'));
        assert!(parse_send_date("2026-10-20 14:30", now())
            .unwrap()
            .ends_with('Z'));
    }

    #[test]
    fn build_request_applies_options() {
        let key = generate_send_key_material();
        let opts = SendOptions {
            notes: Some("private".into()),
            password: Some("hunter2".into()),
            max_access_count: Some(5),
            expiration_date: Some("2026-10-14T09:00:00.000Z".into()),
            deletion_date: Some("2026-10-20T09:00:00.000Z".into()),
            hide_email: true,
            disabled: true,
            hidden_text: true,
            ..Default::default()
        };
        let req = build_send_request(SendRequestInput {
            send_type: SEND_TYPE_TEXT,
            key: &key,
            wrapped_key: "wrapped".into(),
            name: "My send",
            opts: &opts,
            text: Some("secret body"),
            file: None,
            file_length: None,
            existing_deletion: None,
            now: now(),
        })
        .unwrap();
        assert_eq!(decrypt_send_meta_field(&key, &req.name).unwrap(), "My send");
        assert_eq!(
            decrypt_send_meta_field(&key, req.notes.as_deref().unwrap()).unwrap(),
            "private"
        );
        assert_eq!(
            req.password.unwrap(),
            hash_send_password("hunter2", &key).unwrap()
        );
        assert_eq!(req.max_access_count, Some(5));
        assert!(req.hide_email && req.disabled);
        assert!(req.text.as_ref().unwrap().hidden);
        assert_eq!(
            req.deletion_date.as_deref(),
            Some("2026-10-20T09:00:00.000Z")
        );
        assert_eq!(req.key.as_deref(), Some("wrapped"));
    }

    #[test]
    fn build_request_defaults_and_validation() {
        let key = generate_send_key_material();
        let mk = |opts: &SendOptions, existing: Option<&str>| {
            build_send_request(SendRequestInput {
                send_type: SEND_TYPE_TEXT,
                key: &key,
                wrapped_key: "w".into(),
                name: "n",
                opts,
                text: Some("t"),
                file: None,
                file_length: None,
                existing_deletion: existing,
                now: now(),
            })
        };
        let req = mk(&SendOptions::default(), None).unwrap();
        assert_eq!(
            req.deletion_date.as_deref(),
            Some("2026-10-19T09:00:00.000Z")
        );
        assert!(req.password.is_none() && req.max_access_count.is_none());

        let keep = mk(&SendOptions::default(), Some("2026-10-15T00:00:00.000Z")).unwrap();
        assert_eq!(
            keep.deletion_date.as_deref(),
            Some("2026-10-15T00:00:00.000Z")
        );

        let zero = mk(
            &SendOptions {
                max_access_count: Some(0),
                ..Default::default()
            },
            None,
        )
        .unwrap();
        assert!(zero.max_access_count.is_none());

        let past = SendOptions {
            deletion_date: Some("2026-10-01T00:00:00.000Z".into()),
            ..Default::default()
        };
        assert!(mk(&past, None).is_err());
        let far = SendOptions {
            deletion_date: Some("2027-01-01T00:00:00.000Z".into()),
            ..Default::default()
        };
        assert!(mk(&far, None).is_err());
        let exp_after = SendOptions {
            deletion_date: Some("2026-10-14T00:00:00.000Z".into()),
            expiration_date: Some("2026-10-15T00:00:00.000Z".into()),
            ..Default::default()
        };
        assert!(mk(&exp_after, None).is_err());
    }

    #[test]
    fn received_text_send_decrypts() {
        let key = generate_send_key_material();
        let resp = vault_api::SendAccessResponse {
            id: Some("sid".into()),
            send_type: SEND_TYPE_TEXT,
            name: Some(encrypt_send_meta(&key, "hello").unwrap()),
            text: Some(SendText {
                text: Some(encrypt_send_text(&key, "body").unwrap()),
                hidden: true,
            }),
            file: None,
            expiration_date: None,
            creator_identifier: Some("a@b.c".into()),
        };
        let r = received_from_response("https://x".into(), "acc".into(), key, None, resp).unwrap();
        assert_eq!(r.name, "hello");
        assert_eq!(r.text.as_deref(), Some("body"));
        assert!(r.text_hidden && !r.is_file());
        assert_eq!(r.creator_identifier.as_deref(), Some("a@b.c"));
        // Key encoded for share links stays 16 bytes.
        assert_eq!(encode_send_key(&key).len(), 22);
    }

    #[test]
    fn received_file_send_metadata() {
        let key = generate_send_key_material();
        let resp = vault_api::SendAccessResponse {
            id: Some("sid".into()),
            send_type: SEND_TYPE_FILE,
            name: Some(encrypt_send_meta(&key, "doc").unwrap()),
            text: None,
            file: Some(SendFile {
                id: Some("fid".into()),
                file_name: Some(encrypt_send_meta(&key, "report.pdf").unwrap()),
                size: Some(2048),
                size_name: Some("2.0 KB".into()),
                validated: true,
            }),
            expiration_date: None,
            creator_identifier: None,
        };
        let r = received_from_response("https://x".into(), "acc".into(), key, None, resp).unwrap();
        let f = r.file.as_ref().unwrap();
        assert_eq!(f.name, "report.pdf");
        assert_eq!(f.id, "fid");
        assert!(r.is_file());
        // Blob layout used by upload matches what download decrypts.
        let blob = encrypt_send_file_bytes(&key, b"x").unwrap();
        assert_eq!(decrypt_send_file_bytes(&key, &blob).unwrap(), b"x");
    }

    #[test]
    fn password_error_detection() {
        let e401 = SessionError::Api(ApiError::Api {
            status: 401,
            message: String::new(),
        });
        let e400 = SessionError::Api(ApiError::Api {
            status: 400,
            message: "Invalid password.".into(),
        });
        let e404 = SessionError::Api(ApiError::Api {
            status: 404,
            message: String::new(),
        });
        assert!(is_send_password_error(&e401));
        assert!(is_send_password_error(&e400));
        assert!(!is_send_password_error(&e404));
    }

    #[test]
    fn sanitize_and_size_helpers() {
        assert_eq!(sanitize_file_name("../../etc/passwd"), "passwd");
        assert_eq!(sanitize_file_name("..\\evil.txt"), "evil.txt");
        assert_eq!(sanitize_file_name(""), "send-file");
        assert_eq!(sanitize_file_name(".hidden"), "hidden");
        assert_eq!(format_file_size(10), "10 Bytes");
        assert_eq!(format_file_size(1536), "1.5 KB");
    }
}
