//! Shared helpers for importers: CSV table reading, bundle building, note formatting.

use std::collections::HashMap;

use crate::error::{Result, SessionError};
use crate::export::ImportBundle;
use crate::models::{
    CardDraft, DecryptedFolder, DecryptedUri, IdentityDraft, LoginDraft, NoteDraft,
};

/// Placeholder item name used when the source has none (matches Bitwarden's importers).
pub(crate) const UNNAMED: &str = "--";

pub(crate) fn decode_text(bytes: &[u8]) -> Result<String> {
    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    match std::str::from_utf8(bytes) {
        Ok(s) => Ok(s.to_string()),
        Err(_) => Ok(String::from_utf8_lossy(bytes).into_owned()),
    }
}

pub(crate) fn truthy(s: Option<String>) -> bool {
    matches!(
        s.as_deref()
            .map(|v| v.trim().to_ascii_lowercase())
            .as_deref(),
        Some("1" | "true" | "yes" | "y")
    )
}

/// Append `name: value` lines (unmapped source fields) to the notes so no data is dropped.
pub(crate) fn with_extras(notes: Option<String>, extras: &[(String, String)]) -> Option<String> {
    let extras: Vec<String> = extras
        .iter()
        .filter(|(_, v)| !v.trim().is_empty())
        .map(|(k, v)| {
            if k.is_empty() {
                v.clone()
            } else {
                format!("{k}: {v}")
            }
        })
        .collect();
    if extras.is_empty() {
        return notes.filter(|n| !n.trim().is_empty());
    }
    match notes.filter(|n| !n.trim().is_empty()) {
        Some(n) => Some(format!("{n}\n\n{}", extras.join("\n"))),
        None => Some(extras.join("\n")),
    }
}

/// Item name fallback: explicit title, else host of the first URL, else `--`.
pub(crate) fn name_or_host(name: Option<String>, url: Option<&str>) -> String {
    if let Some(n) = name.filter(|n| !n.trim().is_empty()) {
        return n;
    }
    if let Some(u) = url {
        if let Some(h) = host_of(u) {
            return h;
        }
    }
    UNNAMED.to_string()
}

pub(crate) fn host_of(url: &str) -> Option<String> {
    let with_scheme = if url.contains("://") {
        url.to_string()
    } else {
        format!("https://{url}")
    };
    let parsed = url::Url::parse(&with_scheme).ok()?;
    let host = parsed.host_str()?;
    let host = host.strip_prefix("www.").unwrap_or(host);
    Some(host.to_string())
}

pub(crate) fn uris_from(urls: impl IntoIterator<Item = String>) -> Vec<DecryptedUri> {
    urls.into_iter()
        .filter(|u| !u.trim().is_empty())
        .map(|uri| DecryptedUri {
            uri,
            match_type: None,
        })
        .collect()
}

/// Split Bitwarden-style multi-value cells (newline separated).
pub(crate) fn split_lines(s: &str) -> Vec<String> {
    s.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

// ---------------------------------------------------------------------------
// CSV
// ---------------------------------------------------------------------------

pub(crate) struct Table {
    headers: HashMap<String, usize>,
    records: Vec<csv::StringRecord>,
}

pub(crate) struct Row<'a> {
    headers: &'a HashMap<String, usize>,
    rec: &'a csv::StringRecord,
}

pub(crate) fn read_table(text: &str) -> Result<Table> {
    let text = text.trim_start_matches('\u{feff}');
    let mut rdr = csv::ReaderBuilder::new()
        .flexible(true)
        .has_headers(true)
        .from_reader(text.as_bytes());
    let mut headers = HashMap::new();
    for (i, h) in rdr
        .headers()
        .map_err(|e| SessionError::Other(format!("csv header: {e}")))?
        .iter()
        .enumerate()
    {
        headers
            .entry(h.trim().trim_start_matches('\u{feff}').to_ascii_lowercase())
            .or_insert(i);
    }
    if headers.is_empty() {
        return Err(SessionError::Other("csv: empty file".into()));
    }
    let mut records = Vec::new();
    for rec in rdr.records() {
        let rec = rec.map_err(|e| SessionError::Other(format!("csv parse: {e}")))?;
        if rec.iter().all(|c| c.trim().is_empty()) {
            continue;
        }
        records.push(rec);
    }
    Ok(Table { headers, records })
}

impl Table {
    pub fn has_any(&self, names: &[&str]) -> bool {
        names.iter().any(|n| self.headers.contains_key(*n))
    }

    pub fn require_any(&self, names: &[&str], what: &str) -> Result<()> {
        if self.has_any(names) {
            Ok(())
        } else {
            Err(SessionError::Other(format!(
                "csv does not look like {what} (missing column `{}`)",
                names.join("` / `")
            )))
        }
    }

    pub fn rows(&self) -> impl Iterator<Item = Row<'_>> {
        self.records.iter().map(|rec| Row {
            headers: &self.headers,
            rec,
        })
    }
}

impl Row<'_> {
    /// First non-empty cell among the candidate column names (lowercase).
    pub fn get(&self, names: &[&str]) -> Option<String> {
        for n in names {
            if let Some(&i) = self.headers.get(*n) {
                if let Some(v) = self.rec.get(i) {
                    if !v.trim().is_empty() {
                        return Some(v.to_string());
                    }
                }
            }
        }
        None
    }

    /// Columns not in `known`, as `(header, value)` pairs (non-empty only).
    pub fn extras(&self, known: &[&str]) -> Vec<(String, String)> {
        let mut cols: Vec<(&String, &usize)> = self.headers.iter().collect();
        cols.sort_by_key(|(_, i)| **i);
        cols.into_iter()
            .filter(|(h, _)| !known.contains(&h.as_str()))
            .filter_map(|(h, &i)| {
                let v = self.rec.get(i)?;
                if v.trim().is_empty() {
                    None
                } else {
                    Some((h.clone(), v.to_string()))
                }
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Bundle builder
// ---------------------------------------------------------------------------

#[derive(Default)]
pub(crate) struct Builder {
    bundle: ImportBundle,
    folder_ids: HashMap<String, String>,
}

impl Builder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register (or look up) a folder by name; returns its synthetic id.
    pub fn folder(&mut self, name: Option<&str>) -> Option<String> {
        let name = name?.trim().replace('\\', "/");
        let name = name.trim_matches('/').trim().to_string();
        if name.is_empty() || name == "(none)" {
            return None;
        }
        if let Some(id) = self.folder_ids.get(&name) {
            return Some(id.clone());
        }
        let id = format!("import-folder-{}", self.folder_ids.len() + 1);
        self.folder_ids.insert(name.clone(), id.clone());
        self.bundle.folders.push(DecryptedFolder {
            id: id.clone(),
            name,
        });
        Some(id)
    }

    pub fn login(&mut self, d: LoginDraft) {
        self.bundle.login_drafts.push(d);
    }

    pub fn note(&mut self, d: NoteDraft) {
        self.bundle.note_drafts.push(d);
    }

    pub fn card(&mut self, d: CardDraft) {
        self.bundle.card_drafts.push(d);
    }

    pub fn identity(&mut self, d: IdentityDraft) {
        self.bundle.identity_drafts.push(d);
    }

    pub fn warn(&mut self, msg: impl Into<String>) {
        self.bundle.warnings.push(msg.into());
    }

    pub fn finish(self) -> ImportBundle {
        self.bundle
    }
}

/// Convenience constructor for a login draft.
#[allow(clippy::too_many_arguments)]
pub(crate) fn login_draft(
    name: String,
    username: Option<String>,
    password: Option<String>,
    totp: Option<String>,
    uris: Vec<DecryptedUri>,
    notes: Option<String>,
    folder_id: Option<String>,
    favorite: bool,
) -> LoginDraft {
    LoginDraft {
        name,
        username,
        password,
        totp,
        uris,
        notes,
        folder_id,
        favorite,
        reprompt: false,
    }
}

pub(crate) fn note_draft(
    name: String,
    notes: Option<String>,
    folder_id: Option<String>,
    favorite: bool,
) -> NoteDraft {
    NoteDraft {
        name,
        notes,
        folder_id,
        favorite,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_reads_quoted_multiline_cells_and_bom() {
        let t = read_table("\u{feff}Name,Notes\n\"a, b\",\"line1\nline2\"\n").unwrap();
        let rows: Vec<_> = t.rows().collect();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get(&["name"]).as_deref(), Some("a, b"));
        assert_eq!(rows[0].get(&["notes"]).as_deref(), Some("line1\nline2"));
    }

    #[test]
    fn extras_append_to_notes() {
        let n = with_extras(Some("hi".into()), &[("k".into(), "v".into())]);
        assert_eq!(n.as_deref(), Some("hi\n\nk: v"));
        assert_eq!(with_extras(None, &[]), None);
    }

    #[test]
    fn folder_builder_dedupes_and_normalizes() {
        let mut b = Builder::new();
        let a = b.folder(Some("Work\\Sub"));
        let c = b.folder(Some("Work/Sub"));
        assert_eq!(a, c);
        assert_eq!(b.folder(Some("(none)")), None);
        assert_eq!(b.finish().folders[0].name, "Work/Sub");
    }

    #[test]
    fn host_name_fallback() {
        assert_eq!(
            name_or_host(None, Some("https://www.example.com/x")),
            "example.com"
        );
        assert_eq!(name_or_host(None, None), "--");
    }
}
