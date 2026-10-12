//! P4 power-user features layered on top of [`App`]:
//! toasts, sort cycle / recently used, copy sequence, auto-type, QR codes, external notes
//! editor, attachment open / preview, domain rules editor, SSH agent confirmation / keygen,
//! watchtower badge and mouse support.
//!
//! Kept in its own module (second `impl App` block) so the core state machine stays additive.

use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::{Duration, Instant};

use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use vault_session::{DomainRules, RecentMap, SessionStatus};
use zeroize::Zeroize;

use super::{App, ClipboardKind, FocusPane, Overlay, PendingRepromptAction, Screen, SshKeyField};
use crate::autotype::{self, AutoTypeError, Step};
use crate::config::AppConfig;
use crate::models::{DecryptedItem, FilterKind, ItemType};
use crate::toast::{ToastKind, ToastStack};

/// How long a QR code stays on screen before auto-closing.
pub const QR_TIMEOUT: Duration = Duration::from_secs(60);
/// A started copy sequence expires after this long.
pub const COPY_SEQ_TIMEOUT: Duration = Duration::from_secs(60);
/// Temp copies of attachments are removed after this long (and on lock / exit).
pub const TEMP_FILE_TTL: Duration = Duration::from_secs(10 * 60);
const WATCHTOWER_REFRESH: Duration = Duration::from_secs(120);
const PREVIEW_MAX_BYTES: usize = 64 * 1024;
const PREVIEW_MAX_LINES: usize = 500;

// -----------------------------------------------------------------------------
// Types
// -----------------------------------------------------------------------------

/// Item list sort order (`s` cycles).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortMode {
    /// Favorites first, then name.
    #[default]
    Name,
    /// Most recently copied / typed first (local, encrypted cache).
    Recent,
    /// Most recently modified first.
    Modified,
}

impl SortMode {
    pub fn next(self) -> Self {
        match self {
            Self::Name => Self::Recent,
            Self::Recent => Self::Modified,
            Self::Modified => Self::Name,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Recent => "recently used",
            Self::Modified => "last modified",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "recent" | "recently-used" | "used" => Self::Recent,
            "modified" | "updated" | "date" => Self::Modified,
            _ => Self::Name,
        }
    }
}

/// Which secret a QR code encodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QrKind {
    Password,
    Totp,
    Username,
    Uri,
    SshPublic,
}

impl QrKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Password => "Password",
            Self::Totp => "TOTP (otpauth)",
            Self::Username => "Username",
            Self::Uri => "URI",
            Self::SshPublic => "SSH public key",
        }
    }
}

/// External-editor request consumed by the main loop (it must suspend the terminal).
#[derive(Debug, Clone)]
pub struct EditorRequest {
    pub initial: String,
}

/// Progress of the copy sequence (`S`).
#[derive(Debug, Clone)]
pub struct CopySeq {
    pub item_id: String,
    /// 0 = username next, 1 = password next, 2 = TOTP next.
    pub step: usize,
    pub at: Instant,
}

/// Cached vault-health counts shown as a status-bar badge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Watchtower {
    pub reused: usize,
    pub weak: usize,
    pub http: usize,
    pub duplicates: usize,
    pub cards: usize,
    key: (usize, Option<chrono::DateTime<chrono::Local>>),
    at: Instant,
}

impl Watchtower {
    pub fn total(&self) -> usize {
        self.reused + self.weak + self.http + self.duplicates + self.cards
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BadgeLevel {
    Ok,
    Warn,
}

/// Text preview of an attachment.
#[derive(Debug, Clone)]
pub struct AttachmentPreview {
    pub name: String,
    pub lines: Vec<String>,
    /// Set for binary / empty files (no text lines).
    pub note: Option<String>,
    pub scroll: usize,
}

/// Inline edit buffer in the domain-rules editor.
#[derive(Debug, Clone)]
pub struct DomainInput {
    /// `Some(i)` edits custom group `i`; `None` adds a new one.
    pub index: Option<usize>,
    pub text: String,
}

/// Overlays owned by the power-user module (wrapped as `Overlay::Power`).
#[derive(Debug, Clone)]
pub enum PowerOverlay {
    Qr {
        item_name: String,
        entries: Vec<(QrKind, String)>,
        index: usize,
        lines: Vec<String>,
        error: Option<String>,
        opened: Instant,
    },
    Attachments {
        cipher_id: String,
        items: Vec<(String, String)>,
        selected: usize,
        preview: Option<AttachmentPreview>,
    },
    DomainRules {
        rules: DomainRules,
        selected: usize,
        input: Option<DomainInput>,
        dirty: bool,
        status: String,
        confirm_discard: bool,
    },
    SshAgentConfirm {
        /// Overlay to return to (account settings).
        prev: Box<Overlay>,
        keys: Vec<String>,
        each_use: bool,
    },
}

/// Mutable state for all power-user features (one field on `App`).
pub struct PowerState {
    pub toasts: ToastStack,
    pub sort: SortMode,
    pub recent: RecentMap,
    pub recent_loaded: bool,
    pub pending_editor: Option<EditorRequest>,
    pub copy_seq: Option<CopySeq>,
    pub watchtower: Option<Watchtower>,
    pub temp_files: Vec<(PathBuf, Instant)>,
    pub autotype_rx: Option<Receiver<Result<(), AutoTypeError>>>,
    /// Last drawn terminal size (set by the renderer; used for mouse hit-testing).
    pub view_size: Cell<(u16, u16)>,
    /// Set while the SSH-agent confirmation has been accepted.
    pub ssh_confirmed: bool,
    /// First `Ctrl+g` in an SSH key form with an existing key arms replacement.
    pub keygen_armed: bool,
}

impl PowerState {
    pub fn new(config: &AppConfig) -> Self {
        Self {
            toasts: ToastStack::default(),
            sort: SortMode::parse(&config.power.default_sort),
            recent: RecentMap::new(),
            recent_loaded: false,
            pending_editor: None,
            copy_seq: None,
            watchtower: None,
            temp_files: Vec::new(),
            autotype_rx: None,
            view_size: Cell::new((0, 0)),
            ssh_confirmed: false,
            keygen_armed: false,
        }
    }

    /// Delete temp files (all when `older_than` is `None`).
    pub fn cleanup_temp(&mut self, older_than: Option<Duration>) {
        let now = Instant::now();
        self.temp_files.retain(|(path, created)| {
            let expired = older_than.is_none_or(|d| now.duration_since(*created) >= d);
            if expired {
                scrub_and_remove(path);
            }
            !expired
        });
    }
}

impl Drop for PowerState {
    fn drop(&mut self) {
        self.cleanup_temp(None);
    }
}

fn scrub_and_remove(path: &Path) {
    use std::io::Write;
    if let Ok(meta) = std::fs::metadata(path) {
        if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(path) {
            let _ = f.write_all(&vec![0u8; meta.len().min(64 * 1024 * 1024) as usize]);
            let _ = f.sync_all();
        }
    }
    let _ = std::fs::remove_file(path);
}

// -----------------------------------------------------------------------------
// Pure helpers (unit-tested)
// -----------------------------------------------------------------------------

fn pct_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Build an `otpauth://` URI authenticator apps can scan (pass-through for existing URIs).
pub fn totp_otpauth_uri(secret: &str, label: &str) -> Option<String> {
    let s = secret.trim();
    if s.is_empty() || s.starts_with("steam://") {
        return None;
    }
    if s.starts_with("otpauth://") {
        return Some(s.to_string());
    }
    let clean: String = s
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_uppercase();
    let label = if label.trim().is_empty() {
        "vault"
    } else {
        label
    };
    Some(format!(
        "otpauth://totp/{}?secret={clean}&issuer={}",
        pct_encode(label),
        pct_encode(label)
    ))
}

/// Text preview lines for attachment bytes, or `None` when the content looks binary.
pub fn text_preview(bytes: &[u8]) -> Option<Vec<String>> {
    let head = &bytes[..bytes.len().min(8192)];
    if head.contains(&0) {
        return None;
    }
    let slice = &bytes[..bytes.len().min(PREVIEW_MAX_BYTES)];
    let text = String::from_utf8_lossy(slice);
    let bad = text.chars().filter(|c| *c == '\u{FFFD}').count();
    // A multi-byte char cut at the preview limit produces at most one replacement char.
    if bad > 1 && bad * 20 > text.chars().count() {
        return None;
    }
    let mut lines: Vec<String> = text
        .lines()
        .take(PREVIEW_MAX_LINES)
        .map(|l| {
            l.replace('\t', "    ")
                .chars()
                .filter(|c| !c.is_control())
                .collect()
        })
        .collect();
    if bytes.len() > PREVIEW_MAX_BYTES || text.lines().count() > PREVIEW_MAX_LINES {
        lines.push("… (preview truncated)".into());
    }
    Some(lines)
}

/// Strip any directory components / odd characters from an attachment file name.
pub fn sanitize_file_name(name: &str) -> String {
    let base = Path::new(name)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("attachment");
    let cleaned: String = base
        .chars()
        .map(|c| {
            if c.is_control() || c == '/' || c == '\\' {
                '_'
            } else {
                c
            }
        })
        .collect();
    let cleaned = cleaned.trim_matches('.').to_string();
    if cleaned.is_empty() {
        "attachment".into()
    } else {
        cleaned
    }
}

/// Build the SSH-agent confirmation overlay (wrapped around the overlay to restore).
pub fn ssh_confirm_overlay(prev: Overlay, keys: Vec<String>, each_use: bool) -> Overlay {
    Overlay::Power(PowerOverlay::SshAgentConfirm {
        prev: Box::new(prev),
        keys,
        each_use,
    })
}

/// Open a file with the platform's default application (detached).
pub fn open_with_default_app(path: &Path) -> std::io::Result<()> {
    use std::process::{Command, Stdio};
    #[cfg(target_os = "macos")]
    let mut cmd = Command::new("open");
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut cmd = Command::new("xdg-open");
    #[cfg(windows)]
    let mut cmd = {
        let mut c = Command::new("cmd");
        c.args(["/C", "start", ""]);
        c
    };
    cmd.arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(|_| ())
}

#[cfg(unix)]
fn create_private_dir_all(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn create_private_dir_all(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)
}

// -----------------------------------------------------------------------------
// App behaviors
// -----------------------------------------------------------------------------

impl App {
    // ---- toasts -------------------------------------------------------------

    pub fn push_toast(&mut self, msg: impl Into<String>, kind: ToastKind) {
        self.power.toasts.push(msg, kind);
    }

    /// Mirror a status message into the toast stack (called by `set_status`).
    pub fn toast_from_status(&mut self, msg: &str) {
        self.power.toasts.push(msg, ToastKind::infer(msg));
    }

    // ---- sort / recently used ----------------------------------------------

    pub fn ensure_recent_loaded(&mut self) {
        if self.power.recent_loaded {
            return;
        }
        if self.using_mock {
            self.power.recent_loaded = true;
            return;
        }
        if let Some(s) = self.session.as_ref() {
            if s.status() == SessionStatus::Unlocked {
                self.power.recent = s.recent_map();
                self.power.recent_loaded = true;
            }
        }
    }

    /// Record that an item's secret was just used (copy / type) in the encrypted local cache.
    pub fn record_item_used(&mut self, id: &str) {
        self.ensure_recent_loaded();
        if !self.power.recent_loaded {
            return;
        }
        self.power
            .recent
            .insert(id.to_string(), chrono::Utc::now().timestamp());
        if !self.using_mock {
            if let Some(s) = self.session.as_ref() {
                if let Err(e) = s.save_recent_map(&self.power.recent) {
                    tracing::warn!(error = %e, "failed to save recent-use cache");
                }
            }
        }
    }

    fn modified_ts(&self, item: &DecryptedItem) -> i64 {
        let parse = |s: &str| {
            chrono::DateTime::parse_from_rfc3339(s)
                .map(|d| d.timestamp())
                .ok()
        };
        self.session
            .as_ref()
            .filter(|_| !self.using_mock)
            .and_then(|s| s.get_item(&item.id))
            .and_then(|i| i.revision_date.as_deref().and_then(parse))
            .or_else(|| item.creation_date.as_deref().and_then(parse))
            .unwrap_or(0)
    }

    /// Order the unfiltered (no fuzzy query) item list according to the active [`SortMode`].
    pub fn sort_unscored(&mut self, scored: &mut [(i64, usize)]) {
        let mode = self.power.sort;
        if mode == SortMode::Recent {
            self.ensure_recent_loaded();
        }
        let items = &self.items;
        let name_key = |idx: usize| items[idx].name.to_lowercase();
        match mode {
            SortMode::Name => scored.sort_by(|a, b| {
                let (ia, ib) = (&items[a.1], &items[b.1]);
                ib.favorite
                    .cmp(&ia.favorite)
                    .then_with(|| name_key(a.1).cmp(&name_key(b.1)))
            }),
            SortMode::Recent => {
                let recent = &self.power.recent;
                let used = |idx: usize| recent.get(&items[idx].id).copied().unwrap_or(0);
                scored.sort_by(|a, b| {
                    used(b.1)
                        .cmp(&used(a.1))
                        .then_with(|| items[b.1].favorite.cmp(&items[a.1].favorite))
                        .then_with(|| name_key(a.1).cmp(&name_key(b.1)))
                });
            }
            SortMode::Modified => {
                let ts: std::collections::HashMap<usize, i64> = scored
                    .iter()
                    .map(|(_, idx)| (*idx, self.modified_ts(&items[*idx])))
                    .collect();
                scored.sort_by(|a, b| {
                    ts[&b.1]
                        .cmp(&ts[&a.1])
                        .then_with(|| name_key(a.1).cmp(&name_key(b.1)))
                });
            }
        }
    }

    /// `s`: cycle name → recently used → last modified, keeping the selection.
    pub fn cycle_sort(&mut self) {
        let keep = self.selected_id();
        self.power.sort = self.power.sort.next();
        self.recompute_visible();
        if let Some(id) = keep {
            if let Some(pos) = self.visible.iter().position(|&i| self.items[i].id == id) {
                self.selected_item = pos;
            }
        }
        self.set_status(format!("Sort: {}", self.power.sort.label()));
        self.touch();
    }

    // ---- periodic housekeeping ------------------------------------------------

    /// Called from the main loop each tick (after [`App::on_tick`]).
    pub fn power_on_tick(&mut self) {
        let now = Instant::now();
        self.power.toasts.tick(now);
        self.poll_autotype();
        self.power.cleanup_temp(Some(TEMP_FILE_TTL));

        if self.screen != Screen::Vault {
            if !self.power.temp_files.is_empty() {
                self.power.cleanup_temp(None);
            }
            self.power.recent_loaded = false;
            self.power.recent.clear();
            self.power.copy_seq = None;
            self.power.watchtower = None;
            if matches!(self.overlay, Overlay::Power(_)) {
                self.close_power_overlay();
            }
            return;
        }

        let qr_expired = matches!(
            &self.overlay,
            Overlay::Power(PowerOverlay::Qr { opened, .. }) if opened.elapsed() >= QR_TIMEOUT
        );
        if qr_expired {
            self.close_power_overlay();
            self.set_status("QR code closed (timeout)");
        }
        if self
            .power
            .copy_seq
            .as_ref()
            .is_some_and(|s| s.at.elapsed() >= COPY_SEQ_TIMEOUT)
        {
            self.power.copy_seq = None;
        }
        self.refresh_watchtower();
    }

    // ---- watchtower badge -----------------------------------------------------

    fn refresh_watchtower(&mut self) {
        let key = (self.items.len(), self.last_synced_at);
        let stale = match &self.power.watchtower {
            None => true,
            Some(w) => w.key != key || w.at.elapsed() >= WATCHTOWER_REFRESH,
        };
        if !stale || self.busy {
            return;
        }
        let r = self.health_report();
        self.power.watchtower = Some(Watchtower {
            reused: r.reused_passwords.len(),
            weak: r.weak_passwords.len(),
            http: r.unsecured_http.len(),
            duplicates: r.duplicate_items.len(),
            cards: r.expired_cards.len(),
            key,
            at: Instant::now(),
        });
    }

    /// Status-bar badge text + level (`None` until the first computation).
    pub fn watchtower_badge(&self) -> Option<(String, BadgeLevel)> {
        let w = self.power.watchtower.as_ref()?;
        let n = w.total();
        Some(if n == 0 {
            ("watchtower ✓".to_string(), BadgeLevel::Ok)
        } else {
            (format!("watchtower {n}"), BadgeLevel::Warn)
        })
    }

    // ---- copy sequence --------------------------------------------------------

    /// `S`: username → password → (optional) TOTP, one press per step.
    pub fn copy_sequence_step(&mut self) {
        let Some(item) = self.selected_decrypted().cloned() else {
            self.set_status("No item selected");
            return;
        };
        if item.item_type != ItemType::Login {
            self.set_status("Copy sequence works on logins");
            return;
        }
        let has_user = item.username.as_deref().is_some_and(|s| !s.is_empty());
        let has_totp = self.config.power.copy_sequence_totp
            && item.totp.as_deref().is_some_and(|s| !s.trim().is_empty());

        let mut step = match &self.power.copy_seq {
            Some(s) if s.item_id == item.id && s.at.elapsed() < COPY_SEQ_TIMEOUT => s.step,
            _ => 0,
        };
        if step == 0 && !has_user {
            step = 1;
        }
        if step >= 2 && !has_totp {
            self.power.copy_seq = None;
            self.set_status("Copy sequence complete");
            return;
        }
        let (kind, name) = match step {
            0 => (ClipboardKind::Username, "username"),
            1 => (ClipboardKind::Password, "password"),
            _ => (ClipboardKind::Totp, "TOTP"),
        };
        self.copy_field(kind);
        // A reprompt overlay or failed copy leaves the sequence where it was.
        if !matches!(self.overlay, Overlay::None) || self.clipboard_kind != Some(kind) {
            return;
        }

        let last = if has_totp { 2 } else { 1 };
        let first = if has_user { 0 } else { 1 };
        let total = last - first + 1;
        let n = step - first + 1;
        if step >= last {
            self.power.copy_seq = None;
            self.set_status(format!("Sequence {n}/{total}: {name} copied — done"));
        } else {
            let next = if step == 0 { "password" } else { "TOTP" };
            self.power.copy_seq = Some(CopySeq {
                item_id: item.id.clone(),
                step: step + 1,
                at: Instant::now(),
            });
            self.set_status(format!(
                "Sequence {n}/{total}: {name} copied — S for {next}"
            ));
        }
    }

    // ---- auto-type ------------------------------------------------------------

    /// `a` (login) / `T` (TOTP only): type into the focused window after a short delay.
    pub fn start_autotype(&mut self, totp_only: bool) {
        let Some(item) = self.selected_decrypted().cloned() else {
            self.set_status("No item selected");
            return;
        };
        if item.item_type != ItemType::Login {
            self.set_status("Auto-type works on logins");
            return;
        }
        if self.power.autotype_rx.is_some() {
            self.set_status("Auto-type already pending");
            return;
        }
        if let Err(e) = autotype::detect_backend() {
            self.set_status(format!("Auto-type unavailable: {e}"));
            return;
        }
        if self.gate_reprompt(&item, PendingRepromptAction::Reveal) {
            return;
        }
        let press_enter = self.config.power.autotype_press_enter;
        let steps = if totp_only {
            let code = item
                .totp
                .as_deref()
                .and_then(|s| vault_session::totp_from_secret(s).ok());
            let Some(code) = code else {
                self.set_status("No TOTP on this item");
                return;
            };
            let mut s = vec![Step::Text(code)];
            if press_enter {
                s.push(Step::Enter);
            }
            s
        } else {
            autotype::login_steps(
                item.username.as_deref(),
                item.password.as_deref(),
                None,
                press_enter,
            )
        };
        if steps.is_empty() {
            self.set_status("Nothing to type");
            return;
        }
        let delay = Duration::from_secs(self.config.power.autotype_delay_secs);
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            std::thread::sleep(delay);
            let result = autotype::run_steps(&steps);
            for step in steps {
                if let Step::Text(mut t) = step {
                    t.zeroize();
                }
            }
            let _ = tx.send(result);
        });
        self.power.autotype_rx = Some(rx);
        self.record_item_used(&item.id);
        self.set_status(format!(
            "Auto-type in {}s — focus the target field",
            delay.as_secs()
        ));
        self.touch();
    }

    fn poll_autotype(&mut self) {
        let Some(rx) = self.power.autotype_rx.as_ref() else {
            return;
        };
        match rx.try_recv() {
            Ok(Ok(())) => {
                self.power.autotype_rx = None;
                self.push_toast("Auto-typed", ToastKind::Success);
            }
            Ok(Err(e)) => {
                self.power.autotype_rx = None;
                self.set_status(format!("Auto-type failed: {e}"));
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.power.autotype_rx = None;
            }
        }
    }

    // ---- QR codes -------------------------------------------------------------

    /// `Q`: show the selected item's password / TOTP / username / URI as a terminal QR code.
    pub fn open_qr(&mut self) {
        let Some(item) = self.selected_decrypted().cloned() else {
            self.set_status("No item selected");
            return;
        };
        if self.gate_reprompt(&item, PendingRepromptAction::Reveal) {
            return;
        }
        let mut entries: Vec<(QrKind, String)> = Vec::new();
        let non_empty =
            |s: &Option<String>| s.as_deref().filter(|v| !v.is_empty()).map(str::to_string);
        if let Some(p) = non_empty(&item.password) {
            entries.push((QrKind::Password, p));
        }
        if let Some(uri) = item
            .totp
            .as_deref()
            .and_then(|t| totp_otpauth_uri(t, &item.name))
        {
            entries.push((QrKind::Totp, uri));
        }
        if let Some(u) = non_empty(&item.username) {
            entries.push((QrKind::Username, u));
        }
        if let Some(u) = item.primary_uri().filter(|u| !u.is_empty()) {
            entries.push((QrKind::Uri, u.to_string()));
        }
        if let Some(k) = non_empty(&item.ssh_public_key) {
            entries.push((QrKind::SshPublic, k));
        }
        if entries.is_empty() {
            self.set_status("Nothing to encode as QR");
            return;
        }
        self.record_item_used(&item.id);
        let (lines, error) = render_qr(&entries[0].1);
        self.overlay = Overlay::Power(PowerOverlay::Qr {
            item_name: item.name,
            entries,
            index: 0,
            lines,
            error,
            opened: Instant::now(),
        });
        self.touch();
    }

    /// Switch the QR overlay to the next available secret.
    pub fn qr_cycle(&mut self) {
        if let Overlay::Power(PowerOverlay::Qr {
            entries,
            index,
            lines,
            error,
            opened,
            ..
        }) = &mut self.overlay
        {
            if entries.is_empty() {
                return;
            }
            *index = (*index + 1) % entries.len();
            let (l, e) = render_qr(&entries[*index].1);
            for old in lines.iter_mut() {
                old.zeroize();
            }
            *lines = l;
            *error = e;
            *opened = Instant::now();
        }
    }

    /// Close any power overlay, zeroizing secrets it holds.
    pub fn close_power_overlay(&mut self) {
        if let Overlay::Power(p) = &mut self.overlay {
            match p {
                PowerOverlay::Qr { entries, lines, .. } => {
                    for (_, v) in entries.iter_mut() {
                        v.zeroize();
                    }
                    for l in lines.iter_mut() {
                        l.zeroize();
                    }
                }
                PowerOverlay::SshAgentConfirm { prev, .. } => {
                    let restored = std::mem::replace(prev.as_mut(), Overlay::None);
                    self.overlay = restored;
                    return;
                }
                _ => {}
            }
        }
        self.overlay = Overlay::None;
    }

    // ---- external editor ------------------------------------------------------

    /// `E` (vault) / `Ctrl+e` (forms): edit the notes field in `$EDITOR`.
    pub fn request_notes_editor(&mut self) {
        if matches!(self.overlay, Overlay::None) {
            if self.screen != Screen::Vault {
                return;
            }
            if matches!(self.current_filter(), FilterKind::Sends) {
                self.set_status("Notes editor is not available for Sends");
                return;
            }
            self.open_edit_item();
        }
        let initial = match &self.overlay {
            Overlay::ItemForm { notes, .. }
            | Overlay::NoteForm { notes, .. }
            | Overlay::CardForm { notes, .. }
            | Overlay::IdentityForm { notes, .. }
            | Overlay::SshKeyForm { notes, .. } => notes.clone(),
            _ => return,
        };
        self.power.pending_editor = Some(EditorRequest { initial });
        self.set_status(format!("Opening {}…", crate::editor::editor_command()));
    }

    /// Apply the editor result to the open form's notes field.
    pub fn finish_external_edit(&mut self, result: std::io::Result<Option<String>>) {
        match result {
            Ok(Some(text)) => {
                let applied = match &mut self.overlay {
                    Overlay::ItemForm { notes, .. }
                    | Overlay::NoteForm { notes, .. }
                    | Overlay::CardForm { notes, .. }
                    | Overlay::IdentityForm { notes, .. }
                    | Overlay::SshKeyForm { notes, .. } => {
                        notes.zeroize();
                        *notes = text;
                        true
                    }
                    _ => false,
                };
                if applied {
                    self.set_status("Notes updated — Ctrl+s to save");
                } else {
                    self.set_status("Form closed — editor changes discarded");
                }
            }
            Ok(None) => self.set_status("Editor cancelled — notes unchanged"),
            Err(e) => self.set_status(format!("Editor failed: {e}")),
        }
        self.touch();
    }

    // ---- SSH keygen / agent ---------------------------------------------------

    /// `Ctrl+g` in the SSH key form: generate an Ed25519 key pair into the form fields.
    pub fn generate_ssh_key_into_form(&mut self) {
        let (name, has_key) = match &self.overlay {
            Overlay::SshKeyForm {
                name, private_key, ..
            } => (name.clone(), !private_key.trim().is_empty()),
            _ => return,
        };
        if has_key && !self.power.keygen_armed {
            self.power.keygen_armed = true;
            self.set_status("A private key is already set — press Ctrl+g again to replace it");
            return;
        }
        self.power.keygen_armed = false;
        let comment = if name.trim().is_empty() {
            "bitwarden-tui".to_string()
        } else {
            name.trim().to_string()
        };
        match vault_session::generate_ed25519_ssh_key(&comment) {
            Ok(k) => {
                if let Overlay::SshKeyForm {
                    private_key,
                    public_key,
                    fingerprint,
                    field,
                    ..
                } = &mut self.overlay
                {
                    private_key.zeroize();
                    *private_key = k.private_key.to_string();
                    *public_key = k.public_key.clone();
                    *fingerprint = k.fingerprint.clone();
                    *field = SshKeyField::Name;
                }
                self.set_status(format!("Generated Ed25519 key {}", k.fingerprint));
            }
            Err(e) => self.set_status(format!("Key generation failed: {e}")),
        }
    }

    /// Accept the SSH-agent confirmation and start the agent.
    pub fn confirm_ssh_agent_start(&mut self) {
        let each_use = match &self.overlay {
            Overlay::Power(PowerOverlay::SshAgentConfirm { each_use, .. }) => *each_use,
            _ => return,
        };
        self.close_power_overlay();
        if self.using_mock {
            if let Overlay::AccountSettings { status, .. } = &mut self.overlay {
                *status = "Mock mode — SSH agent unavailable".into();
            }
            return;
        }
        let Some(session) = self.session.as_mut() else {
            return;
        };
        match session.start_ssh_agent_opts(each_use) {
            Ok(socket) => {
                let msg = format!(
                    "SSH agent running — export SSH_AUTH_SOCK={}",
                    socket.display()
                );
                if let Overlay::AccountSettings { status, .. } = &mut self.overlay {
                    *status = msg.clone();
                }
                self.set_status(msg);
            }
            Err(e) => {
                if let Overlay::AccountSettings { status, .. } = &mut self.overlay {
                    *status = e.to_string();
                }
                self.set_status(format!("SSH agent: {e}"));
            }
        }
    }

    // ---- attachments ----------------------------------------------------------

    /// `O`: list attachments of the selected item (open / preview / save).
    pub fn open_attachments_overlay(&mut self) {
        let Some(item) = self.selected_decrypted().cloned() else {
            self.set_status("No item selected");
            return;
        };
        self.refresh_detail_attachments();
        if self.detail_attachments.is_empty() {
            self.set_status("No attachments on this item");
            return;
        }
        self.overlay = Overlay::Power(PowerOverlay::Attachments {
            cipher_id: item.id,
            items: self.detail_attachments.clone(),
            selected: 0,
            preview: None,
        });
        self.touch();
    }

    async fn attachment_to_temp(
        &mut self,
        cipher_id: &str,
        att_id: &str,
        name: &str,
    ) -> Result<PathBuf, String> {
        if self.using_mock || self.session.is_none() {
            return Err("Attachments require an online session".into());
        }
        let dir = self.profile_data_dir().join("tmp-open");
        create_private_dir_all(&dir).map_err(|e| format!("cannot create temp dir: {e}"))?;
        let short: String = att_id
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .take(8)
            .collect();
        let dest = dir.join(format!("{short}-{}", sanitize_file_name(name)));
        self.busy = true;
        let result = self
            .session
            .as_mut()
            .expect("checked above")
            .download_attachment(cipher_id, att_id, &dest)
            .await;
        self.busy = false;
        match result {
            Ok(()) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o600));
                }
                self.power.temp_files.push((dest.clone(), Instant::now()));
                Ok(dest)
            }
            Err(e) => Err(format!("Download failed: {e}")),
        }
    }

    /// Download to a private temp file and open with the default application.
    pub async fn open_attachment_externally(&mut self, index: usize) {
        let Overlay::Power(PowerOverlay::Attachments {
            cipher_id, items, ..
        }) = &self.overlay
        else {
            return;
        };
        let Some((att_id, name)) = items.get(index).cloned() else {
            return;
        };
        let cipher_id = cipher_id.clone();
        match self.attachment_to_temp(&cipher_id, &att_id, &name).await {
            Ok(path) => match open_with_default_app(&path) {
                Ok(()) => self.set_status(format!(
                    "Opened {name} (temp copy removed after 10 min / lock)"
                )),
                Err(e) => self.set_status(format!("Cannot open {name}: {e}")),
            },
            Err(msg) => self.set_status(msg),
        }
    }

    /// Download and show a small text preview inside the overlay.
    pub async fn preview_attachment(&mut self, index: usize) {
        let Overlay::Power(PowerOverlay::Attachments {
            cipher_id, items, ..
        }) = &self.overlay
        else {
            return;
        };
        let Some((att_id, name)) = items.get(index).cloned() else {
            return;
        };
        let cipher_id = cipher_id.clone();
        let path = match self.attachment_to_temp(&cipher_id, &att_id, &name).await {
            Ok(p) => p,
            Err(msg) => {
                self.set_status(msg);
                return;
            }
        };
        let bytes = std::fs::read(&path).unwrap_or_default();
        // Previews never leave a copy behind.
        self.power.temp_files.retain(|(p, _)| p != &path);
        scrub_and_remove(&path);
        let (lines, note) = match text_preview(&bytes) {
            Some(l) if !l.is_empty() => (l, None),
            Some(_) => (Vec::new(), Some("Empty file".to_string())),
            None => (
                Vec::new(),
                Some(format!(
                    "Binary file ({} bytes) — Enter opens it with the default app",
                    bytes.len()
                )),
            ),
        };
        if let Overlay::Power(PowerOverlay::Attachments { preview, .. }) = &mut self.overlay {
            *preview = Some(AttachmentPreview {
                name,
                lines,
                note,
                scroll: 0,
            });
        }
    }

    // ---- domain rules editor --------------------------------------------------

    /// `D`: fetch and edit custom equivalent domains / excluded global groups.
    pub async fn open_domain_rules(&mut self) {
        if self.using_mock {
            self.overlay = Overlay::Power(PowerOverlay::DomainRules {
                rules: DomainRules {
                    custom_groups: vec![vec!["example.com".into(), "example.net".into()]],
                    global_groups: Vec::new(),
                },
                selected: 0,
                input: None,
                dirty: false,
                status: "Mock mode — changes are not saved".into(),
                confirm_discard: false,
            });
            return;
        }
        let Some(session) = self.session.as_ref() else {
            return;
        };
        if session.is_offline() {
            self.set_status("Domain rules require an online session");
            return;
        }
        self.busy = true;
        let result = session.fetch_domain_rules().await;
        self.busy = false;
        match result {
            Ok(rules) => {
                self.overlay = Overlay::Power(PowerOverlay::DomainRules {
                    rules,
                    selected: 0,
                    input: None,
                    dirty: false,
                    status: String::new(),
                    confirm_discard: false,
                });
                self.touch();
            }
            Err(e) => self.set_status(format!("Cannot load domain rules: {e}")),
        }
    }

    /// Save the edited rules to the server and re-sync.
    pub async fn save_domain_rules(&mut self) {
        let Overlay::Power(PowerOverlay::DomainRules { rules, .. }) = &self.overlay else {
            return;
        };
        let rules = rules.clone();
        if self.using_mock {
            self.set_status("Mock mode — domain rules not saved");
            return;
        }
        let Some(session) = self.session.as_mut() else {
            return;
        };
        self.busy = true;
        let result = session.save_domain_rules(&rules).await;
        self.busy = false;
        match result {
            Ok(()) => {
                self.close_power_overlay();
                self.reload_from_session();
                self.set_status("Domain rules saved");
            }
            Err(e) => {
                if let Overlay::Power(PowerOverlay::DomainRules { status, .. }) = &mut self.overlay
                {
                    *status = format!("Save failed: {e}");
                }
                self.set_status(format!("Domain rules save failed: {e}"));
            }
        }
    }

    // ---- mouse ----------------------------------------------------------------

    /// Mouse clicks / scrolling in the vault browser (only when `config.mouse`).
    pub fn handle_mouse(&mut self, ev: MouseEvent, detail_visible: bool, folders_visible: bool) {
        if !self.config.mouse
            || self.screen != Screen::Vault
            || !matches!(self.overlay, Overlay::None)
            || self.show_help
            || self.busy
        {
            return;
        }
        let (w, h) = self.power.view_size.get();
        if w == 0 || h == 0 {
            return;
        }
        let (folders, items, detail) = self.pane_rects(Rect::new(0, 0, w, h));
        let pos = (ev.column, ev.row);
        let hit = |r: Rect| {
            pos.0 >= r.x && pos.0 < r.x + r.width && pos.1 >= r.y && pos.1 < r.y + r.height
        };
        let pane = if folders.is_some_and(hit) && folders_visible {
            Some(FocusPane::Folders)
        } else if hit(items) {
            Some(FocusPane::Items)
        } else if detail.is_some_and(hit) && detail_visible {
            Some(FocusPane::Detail)
        } else {
            None
        };
        let Some(pane) = pane else {
            return;
        };

        match ev.kind {
            MouseEventKind::ScrollUp | MouseEventKind::ScrollDown => {
                let delta = if matches!(ev.kind, MouseEventKind::ScrollUp) {
                    -1
                } else {
                    1
                };
                // Scrolling over the detail pane scrolls the item list (same as j/k there).
                self.focus = pane;
                self.move_selection_clamped(delta);
            }
            MouseEventKind::Down(MouseButton::Left) => {
                self.focus = pane;
                match pane {
                    FocusPane::Folders => {
                        if let Some(r) = folders {
                            let row = ev.row.saturating_sub(r.y + 1) as usize;
                            let viewport = r.height.saturating_sub(2) as usize;
                            let idx = scroll_offset(self.selected_sidebar, viewport) + row;
                            if ev.row > r.y && idx < self.sidebar.len() {
                                self.selected_sidebar = idx;
                                self.selected_item = 0;
                                self.recompute_visible();
                                self.refresh_detail_attachments();
                            }
                        }
                    }
                    FocusPane::Items => {
                        let sends = matches!(self.current_filter(), FilterKind::Sends);
                        let (header, len) = if sends {
                            (1u16, self.visible_sends.len())
                        } else {
                            (2u16, self.visible.len())
                        };
                        // Items table: top border + header row; sends list: top border only.
                        let chrome = items.height.saturating_sub(header + 1) as usize;
                        if ev.row >= items.y + header && len > 0 {
                            let row = (ev.row - items.y - header) as usize;
                            let idx = scroll_offset(self.selected_item.min(len - 1), chrome) + row;
                            if idx < len {
                                let prev = self.selected_id();
                                self.selected_item = idx;
                                if self.selected_id() != prev {
                                    self.reprompt_ok_for = None;
                                    self.refresh_detail_attachments();
                                }
                            }
                        }
                    }
                    FocusPane::Detail => {}
                }
                self.touch();
            }
            _ => {}
        }
    }

    fn move_selection_clamped(&mut self, delta: isize) {
        // `move_selection` wraps around; wheel scrolling should stop at the ends.
        let (cur, len) = match self.focus {
            FocusPane::Folders => (self.selected_sidebar, self.sidebar.len()),
            _ => {
                if matches!(self.current_filter(), FilterKind::Sends) {
                    (self.selected_item, self.visible_sends.len())
                } else {
                    (self.selected_item, self.visible.len())
                }
            }
        };
        if len == 0 {
            return;
        }
        let next = cur as isize + delta;
        if next < 0 || next >= len as isize {
            return;
        }
        self.move_selection(delta);
    }

    fn pane_rects(&self, area: Rect) -> (Option<Rect>, Rect, Option<Rect>) {
        use crate::ui::layout::{split_status, split_vault_panes};
        let (body, _status) = split_status(area);
        let panes = if self.searching || !self.search_query.is_empty() {
            Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(3), Constraint::Min(1)])
                .split(body)[1]
        } else {
            body
        };
        split_vault_panes(panes)
    }
}

/// Ratatui keeps the selection visible by scrolling just enough from offset 0.
fn scroll_offset(selected: usize, viewport: usize) -> usize {
    if viewport == 0 {
        0
    } else {
        (selected + 1).saturating_sub(viewport)
    }
}

fn render_qr(payload: &str) -> (Vec<String>, Option<String>) {
    match crate::qr::qr_lines(payload) {
        Ok(l) => (l, None),
        Err(e) => (Vec::new(), Some(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn otpauth_from_plain_secret() {
        let u = totp_otpauth_uri("jbsw y3dp", "My Site").unwrap();
        assert_eq!(
            u,
            "otpauth://totp/My%20Site?secret=JBSWY3DP&issuer=My%20Site"
        );
        assert_eq!(
            totp_otpauth_uri("otpauth://totp/x?secret=A", "n").unwrap(),
            "otpauth://totp/x?secret=A"
        );
        assert!(totp_otpauth_uri("steam://ABC", "n").is_none());
        assert!(totp_otpauth_uri("  ", "n").is_none());
    }

    #[test]
    fn preview_detects_binary() {
        assert!(text_preview(b"hello\nworld\n").is_some());
        assert!(text_preview(&[0x89, b'P', b'N', b'G', 0, 1, 2]).is_none());
        let lines = text_preview(b"a\tb\nc").unwrap();
        assert_eq!(lines, vec!["a    b".to_string(), "c".to_string()]);
    }

    #[test]
    fn preview_truncates() {
        let big = "line\n".repeat(PREVIEW_MAX_LINES + 10);
        let lines = text_preview(big.as_bytes()).unwrap();
        assert_eq!(lines.len(), PREVIEW_MAX_LINES + 1);
        assert!(lines.last().unwrap().contains("truncated"));
    }

    #[test]
    fn sanitizes_names() {
        assert_eq!(sanitize_file_name("../../etc/passwd"), "passwd");
        assert_eq!(sanitize_file_name(".."), "attachment");
        assert_eq!(sanitize_file_name("a\\b.txt"), "a_b.txt");
        assert_eq!(sanitize_file_name(""), "attachment");
    }

    #[test]
    fn sort_cycle_and_parse() {
        assert_eq!(SortMode::Name.next(), SortMode::Recent);
        assert_eq!(SortMode::Modified.next(), SortMode::Name);
        assert_eq!(SortMode::parse("Recent"), SortMode::Recent);
        assert_eq!(SortMode::parse("zzz"), SortMode::Name);
    }

    #[test]
    fn scroll_offsets() {
        assert_eq!(scroll_offset(0, 10), 0);
        assert_eq!(scroll_offset(9, 10), 0);
        assert_eq!(scroll_offset(10, 10), 1);
        assert_eq!(scroll_offset(5, 0), 0);
    }
}
