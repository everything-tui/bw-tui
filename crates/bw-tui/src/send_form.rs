//! State and validation for the Send create/edit form (text + file Sends).

use std::path::Path;

use chrono::{DateTime, Local, Utc};
use vault_session::{parse_send_date, SendOptions};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendKind {
    Text,
    File,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendFormField {
    Name,
    /// Text body (text Sends) or local file path (file Sends).
    Content,
    Notes,
    Password,
    MaxAccess,
    Expiration,
    Deletion,
    HideEmail,
    HiddenText,
    Disabled,
    /// Quick-create only: Tab here and Enter/Space/a expands to the full form.
    Advanced,
}

impl SendFormField {
    pub fn is_toggle(self) -> bool {
        matches!(
            self,
            Self::HideEmail | Self::HiddenText | Self::Disabled | Self::Advanced
        )
    }
}

#[derive(Debug, Clone)]
pub struct SendFormState {
    pub editing_id: Option<String>,
    pub kind: SendKind,
    pub name: String,
    pub content: String,
    pub notes: String,
    pub password: String,
    pub max_access: String,
    pub expiration: String,
    pub deletion: String,
    pub hide_email: bool,
    pub hidden_text: bool,
    pub disabled: bool,
    /// Editing: a password is already set on the server.
    pub has_password: bool,
    /// Editing: remove the existing password on save.
    pub remove_password: bool,
    /// Org policy forbids hiding the creator email.
    pub hide_email_blocked: bool,
    /// When false on a new Send, only Content + Password are shown (Quick create).
    pub advanced: bool,
    pub field: SendFormField,
    pub error: Option<String>,
}

impl SendFormState {
    pub fn new(kind: SendKind) -> Self {
        Self {
            editing_id: None,
            kind,
            name: String::new(),
            content: String::new(),
            notes: String::new(),
            password: String::new(),
            max_access: String::new(),
            expiration: String::new(),
            deletion: String::new(),
            hide_email: false,
            hidden_text: false,
            disabled: false,
            has_password: false,
            remove_password: false,
            hide_email_blocked: false,
            advanced: false,
            field: SendFormField::Content,
            error: None,
        }
    }

    /// Quick create: content + optional password only (new Sends before Advanced).
    pub fn is_quick(&self) -> bool {
        !self.advanced && self.editing_id.is_none()
    }

    /// Expand Quick → Advanced (keeps content/password; focuses Name if empty).
    pub fn set_advanced(&mut self, on: bool) {
        if on == self.advanced {
            return;
        }
        self.advanced = on;
        if on {
            self.field = if self.name.trim().is_empty() {
                SendFormField::Name
            } else if self.fields().contains(&self.field) {
                self.field
            } else {
                SendFormField::Content
            };
        }
        self.error = None;
    }

    /// Suggested name when the user left Name blank.
    pub fn auto_name(&self) -> String {
        match self.kind {
            SendKind::File => Path::new(self.content.trim())
                .file_name()
                .and_then(|s| s.to_str())
                .filter(|s| !s.is_empty())
                .unwrap_or("File")
                .to_string(),
            SendKind::Text => {
                let t = self.content.trim();
                if t.is_empty() {
                    return "Send".into();
                }
                let mut out = String::new();
                for (i, c) in t.chars().enumerate() {
                    if i >= 40 {
                        out.push('…');
                        break;
                    }
                    if c == '\n' || c == '\r' {
                        break;
                    }
                    out.push(c);
                }
                if out.is_empty() {
                    "Send".into()
                } else {
                    out
                }
            }
        }
    }

    /// Fill blank name from content before validate/submit.
    pub fn ensure_name(&mut self) {
        if self.name.trim().is_empty() {
            self.name = self.auto_name();
        }
    }

    /// Fields shown for the current mode, in tab order.
    pub fn fields(&self) -> Vec<SendFormField> {
        if self.is_quick() {
            return vec![
                SendFormField::Content,
                SendFormField::Password,
                SendFormField::Advanced,
            ];
        }
        let mut v = vec![
            SendFormField::Name,
            SendFormField::Content,
            SendFormField::Notes,
            SendFormField::Password,
            SendFormField::MaxAccess,
            SendFormField::Expiration,
            SendFormField::Deletion,
        ];
        if !self.hide_email_blocked {
            v.push(SendFormField::HideEmail);
        }
        if self.kind == SendKind::Text {
            v.push(SendFormField::HiddenText);
        }
        v.push(SendFormField::Disabled);
        v
    }

    /// File Sends can't change their file after creation.
    pub fn content_editable(&self) -> bool {
        !(self.editing_id.is_some() && self.kind == SendKind::File)
    }

    pub fn next_field(&mut self) {
        self.step(1);
    }

    pub fn prev_field(&mut self) {
        self.step(-1);
    }

    fn step(&mut self, delta: isize) {
        let fields = self.fields();
        let len = fields.len() as isize;
        let mut idx = fields.iter().position(|f| *f == self.field).unwrap_or(0) as isize;
        for _ in 0..len {
            idx = (idx + delta).rem_euclid(len);
            let f = fields[idx as usize];
            if f == SendFormField::Content && !self.content_editable() {
                continue;
            }
            self.field = f;
            return;
        }
    }

    /// Switch text <-> file (new Sends only).
    pub fn toggle_kind(&mut self) {
        if self.editing_id.is_some() {
            return;
        }
        self.kind = match self.kind {
            SendKind::Text => SendKind::File,
            SendKind::File => SendKind::Text,
        };
        self.content.clear();
        if self.field == SendFormField::HiddenText && self.kind == SendKind::File {
            self.field = SendFormField::Content;
        }
    }

    pub fn toggle_current(&mut self) {
        match self.field {
            SendFormField::HideEmail => self.hide_email = !self.hide_email,
            SendFormField::HiddenText => self.hidden_text = !self.hidden_text,
            SendFormField::Disabled => self.disabled = !self.disabled,
            SendFormField::Advanced => self.set_advanced(true),
            SendFormField::Password if self.has_password && self.password.is_empty() => {
                self.remove_password = !self.remove_password;
            }
            _ => {}
        }
    }

    fn text_field_mut(&mut self) -> Option<&mut String> {
        match self.field {
            SendFormField::Name => Some(&mut self.name),
            SendFormField::Content if self.content_editable() => Some(&mut self.content),
            SendFormField::Notes => Some(&mut self.notes),
            SendFormField::Password => Some(&mut self.password),
            SendFormField::MaxAccess => Some(&mut self.max_access),
            SendFormField::Expiration => Some(&mut self.expiration),
            SendFormField::Deletion => Some(&mut self.deletion),
            _ => None,
        }
    }

    pub fn push_char(&mut self, c: char) {
        if self.field == SendFormField::MaxAccess && !c.is_ascii_digit() {
            return;
        }
        if self.field == SendFormField::Password {
            self.remove_password = false;
        }
        self.error = None;
        if let Some(f) = self.text_field_mut() {
            f.push(c);
        }
    }

    pub fn backspace(&mut self) {
        self.error = None;
        if let Some(f) = self.text_field_mut() {
            f.pop();
        }
    }

    /// Validate and convert the form into `SendOptions` (dates resolved against `now`).
    pub fn to_options(&self, now: DateTime<Utc>) -> Result<SendOptions, String> {
        let max_access = match self.max_access.trim() {
            "" => None,
            s => Some(
                s.parse::<u32>()
                    .map_err(|_| "Max access count must be a whole number".to_string())?,
            ),
        };
        let expiration_date = match self.expiration.trim() {
            "" => None,
            s => Some(parse_send_date(s, now).map_err(|e| format!("Expiration: {e}"))?),
        };
        let deletion_date = match self.deletion.trim() {
            "" => None,
            s => Some(parse_send_date(s, now).map_err(|e| format!("Deletion: {e}"))?),
        };
        let password = (!self.password.is_empty()).then(|| self.password.clone());
        Ok(SendOptions {
            notes: (!self.notes.trim().is_empty()).then(|| self.notes.trim().to_string()),
            password,
            remove_password: self.remove_password,
            max_access_count: max_access.filter(|n| *n > 0),
            expiration_date,
            deletion_date,
            hide_email: self.hide_email && !self.hide_email_blocked,
            disabled: self.disabled,
            hidden_text: self.kind == SendKind::Text && self.hidden_text,
        })
    }

    /// Basic completeness check before hitting the network.
    /// Call [`Self::ensure_name`] first so Quick create can omit the name field.
    pub fn validate_required(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("Send name is required".into());
        }
        if self.content_editable() && self.content.trim().is_empty() {
            return Err(match self.kind {
                SendKind::Text => "Send text is required".into(),
                SendKind::File => "File path is required".into(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiveField {
    Url,
    Password,
    SavePath,
}

/// "Open Send link" overlay: paste a share URL, optionally a password, view or download.
#[derive(Debug, Clone)]
pub struct ReceiveSendState {
    pub url: String,
    pub password: String,
    pub save_path: String,
    pub field: ReceiveField,
    /// The server asked for a password (or rejected the one given).
    pub needs_password: bool,
    pub received: Option<vault_session::ReceivedSend>,
    /// Reveal hidden text Sends.
    pub reveal: bool,
    pub message: Option<String>,
}

impl ReceiveSendState {
    pub fn new(default_dir: String) -> Self {
        Self {
            url: String::new(),
            password: String::new(),
            save_path: default_dir,
            field: ReceiveField::Url,
            needs_password: false,
            received: None,
            reveal: false,
            message: None,
        }
    }

    /// Fields editable in the current phase.
    pub fn fields(&self) -> Vec<ReceiveField> {
        if let Some(r) = &self.received {
            return if r.is_file() {
                vec![ReceiveField::SavePath]
            } else {
                vec![]
            };
        }
        if self.needs_password {
            vec![ReceiveField::Url, ReceiveField::Password]
        } else {
            vec![ReceiveField::Url]
        }
    }

    pub fn next_field(&mut self) {
        let fields = self.fields();
        if fields.is_empty() {
            return;
        }
        let idx = fields.iter().position(|f| *f == self.field).unwrap_or(0);
        self.field = fields[(idx + 1) % fields.len()];
    }

    pub fn push_char(&mut self, c: char) {
        self.message = None;
        match self.field {
            ReceiveField::Url => self.url.push(c),
            ReceiveField::Password => self.password.push(c),
            ReceiveField::SavePath => self.save_path.push(c),
        }
    }

    pub fn backspace(&mut self) {
        self.message = None;
        match self.field {
            ReceiveField::Url => self.url.pop(),
            ReceiveField::Password => self.password.pop(),
            ReceiveField::SavePath => self.save_path.pop(),
        };
    }

    /// Apply a successful receive.
    pub fn set_received(&mut self, r: vault_session::ReceivedSend) {
        self.field = ReceiveField::SavePath;
        self.received = Some(r);
        self.needs_password = false;
        self.message = None;
    }

    /// Record a failed receive; shows a password prompt when the server wants one.
    pub fn set_error(&mut self, err: &vault_session::SessionError) {
        if vault_session::is_send_password_error(err) {
            let had_password = !self.password.is_empty();
            self.needs_password = true;
            self.field = ReceiveField::Password;
            self.password.clear();
            self.message = Some(if had_password {
                "Wrong password — try again".into()
            } else {
                "This Send is password protected".into()
            });
        } else {
            self.message = Some(format!("{err}"));
        }
    }
}

/// Render an RFC 3339 timestamp as local `YYYY-MM-DD HH:MM` for form prefill.
pub fn format_local_datetime(rfc3339: &str) -> String {
    DateTime::parse_from_rfc3339(rfc3339)
        .map(|d| d.with_timezone(&Local).format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_else(|_| rfc3339.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 12, 9, 0, 0).unwrap()
    }

    #[test]
    fn quick_create_fields_and_cycle() {
        let mut f = SendFormState::new(SendKind::Text);
        assert!(f.is_quick());
        assert_eq!(
            f.fields(),
            vec![
                SendFormField::Content,
                SendFormField::Password,
                SendFormField::Advanced,
            ]
        );
        assert_eq!(f.field, SendFormField::Content);
        f.next_field();
        assert_eq!(f.field, SendFormField::Password);
        f.next_field();
        assert_eq!(f.field, SendFormField::Advanced);
        f.toggle_current();
        assert!(!f.is_quick());
        assert_eq!(f.field, SendFormField::Name);
    }

    #[test]
    fn advanced_expands_fields_and_focuses_name() {
        let mut f = SendFormState::new(SendKind::Text);
        f.content = "hello world".into();
        f.set_advanced(true);
        assert!(!f.is_quick());
        assert!(f.fields().contains(&SendFormField::HiddenText));
        assert_eq!(f.field, SendFormField::Name);
        f.next_field();
        assert_eq!(f.field, SendFormField::Content);
        f.prev_field();
        f.prev_field();
        assert_eq!(f.field, SendFormField::Disabled);
        f.toggle_current();
        assert!(f.disabled);
    }

    #[test]
    fn auto_name_from_text_and_file_path() {
        let mut f = SendFormState::new(SendKind::Text);
        f.content = "  secret note line\nmore".into();
        assert_eq!(f.auto_name(), "secret note line");
        f.content = "x".repeat(50);
        let n = f.auto_name();
        assert!(n.ends_with('…'));
        assert_eq!(n.chars().count(), 41);
        f.kind = SendKind::File;
        f.content = "/tmp/reports/out.pdf".into();
        assert_eq!(f.auto_name(), "out.pdf");
        f.ensure_name();
        assert_eq!(f.name, "out.pdf");
    }

    #[test]
    fn file_kind_hides_hidden_text_and_clears_content() {
        let mut f = SendFormState::new(SendKind::Text);
        f.set_advanced(true);
        f.content = "abc".into();
        f.toggle_kind();
        assert_eq!(f.kind, SendKind::File);
        assert!(f.content.is_empty());
        assert!(!f.fields().contains(&SendFormField::HiddenText));
    }

    #[test]
    fn editing_file_send_skips_content_and_cannot_change_kind() {
        let mut f = SendFormState::new(SendKind::File);
        f.advanced = true;
        f.editing_id = Some("id".into());
        f.field = SendFormField::Name;
        f.toggle_kind();
        assert_eq!(f.kind, SendKind::File);
        f.next_field();
        assert_eq!(f.field, SendFormField::Notes);
        assert!(f.validate_required().is_err()); // name still empty
        f.name = "x".into();
        assert!(f.validate_required().is_ok());
    }

    #[test]
    fn edit_path_is_not_quick() {
        let mut f = SendFormState::new(SendKind::Text);
        f.editing_id = Some("id".into());
        f.advanced = true;
        assert!(!f.is_quick());
        assert!(f.fields().contains(&SendFormField::Name));
    }

    #[test]
    fn hide_email_blocked_by_policy() {
        let mut f = SendFormState::new(SendKind::Text);
        f.set_advanced(true);
        f.hide_email_blocked = true;
        f.hide_email = true;
        assert!(!f.fields().contains(&SendFormField::HideEmail));
        assert!(!f.to_options(now()).unwrap().hide_email);
    }

    #[test]
    fn max_access_only_digits_and_options_conversion() {
        let mut f = SendFormState::new(SendKind::Text);
        f.set_advanced(true);
        f.field = SendFormField::MaxAccess;
        f.push_char('x');
        f.push_char('5');
        assert_eq!(f.max_access, "5");
        f.field = SendFormField::Password;
        for c in "pw".chars() {
            f.push_char(c);
        }
        f.field = SendFormField::Deletion;
        for c in "3d".chars() {
            f.push_char(c);
        }
        f.notes = "  note ".into();
        f.hide_email = true;
        f.hidden_text = true;
        let o = f.to_options(now()).unwrap();
        assert_eq!(o.max_access_count, Some(5));
        assert_eq!(o.password.as_deref(), Some("pw"));
        assert_eq!(o.deletion_date.as_deref(), Some("2026-10-15T09:00:00.000Z"));
        assert_eq!(o.notes.as_deref(), Some("note"));
        assert!(o.hide_email && o.hidden_text && o.expiration_date.is_none());
    }

    #[test]
    fn invalid_dates_report_field() {
        let mut f = SendFormState::new(SendKind::Text);
        f.expiration = "soon".into();
        assert!(f.to_options(now()).unwrap_err().starts_with("Expiration"));
        f.expiration.clear();
        f.deletion = "later".into();
        assert!(f.to_options(now()).unwrap_err().starts_with("Deletion"));
    }

    #[test]
    fn editing_password_toggle_removes() {
        let mut f = SendFormState::new(SendKind::Text);
        f.editing_id = Some("x".into());
        f.has_password = true;
        f.field = SendFormField::Password;
        f.toggle_current();
        assert!(f.to_options(now()).unwrap().remove_password);
        f.push_char('a');
        assert!(!f.remove_password);
    }

    #[test]
    fn receive_state_password_prompt_flow() {
        use vault_session::{ApiError, SessionError};
        let mut s = ReceiveSendState::new(".".into());
        assert_eq!(s.fields(), vec![ReceiveField::Url]);
        for c in "https://x/#/send/a/b".chars() {
            s.push_char(c);
        }
        s.set_error(&SessionError::Api(ApiError::Api {
            status: 401,
            message: String::new(),
        }));
        assert!(s.needs_password);
        assert_eq!(s.field, ReceiveField::Password);
        assert_eq!(s.fields(), vec![ReceiveField::Url, ReceiveField::Password]);
        s.next_field();
        assert_eq!(s.field, ReceiveField::Url);
        s.field = ReceiveField::Password;
        s.push_char('x');
        s.set_error(&SessionError::Api(ApiError::Api {
            status: 400,
            message: "Invalid password.".into(),
        }));
        assert!(s.message.as_deref().unwrap().contains("Wrong password"));
        assert!(s.password.is_empty());
        s.set_error(&SessionError::Api(ApiError::Api {
            status: 404,
            message: String::new(),
        }));
        assert!(s.message.as_deref().unwrap().contains("404"));
    }

    #[test]
    fn format_local_datetime_roundtrips_shape() {
        let s = format_local_datetime("2026-10-12T09:00:00.000Z");
        assert_eq!(s.len(), 16);
        assert_eq!(format_local_datetime("garbage"), "garbage");
    }
}
