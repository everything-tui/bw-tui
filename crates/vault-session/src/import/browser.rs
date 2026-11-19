//! Chrome / Edge / Firefox saved-password CSV exports.
//!
//! * Chrome: `name,url,username,password,note`
//! * Edge:   `name,url,username,password`
//! * Firefox: `url,username,password,httpRealm,formActionOrigin,guid,timeCreated,…`

use super::common::{login_draft, name_or_host, read_table, uris_from, with_extras, Builder};
use crate::error::Result;
use crate::export::ImportBundle;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserKind {
    Chrome,
    Edge,
    Firefox,
}

impl BrowserKind {
    fn label(self) -> &'static str {
        match self {
            Self::Chrome => "Chrome",
            Self::Edge => "Edge",
            Self::Firefox => "Firefox",
        }
    }
}

pub fn import_browser_csv(text: &str, kind: BrowserKind) -> Result<ImportBundle> {
    let table = read_table(text)?;
    table.require_any(
        &["url", "origin"],
        &format!("a {} password CSV", kind.label()),
    )?;
    table.require_any(&["password"], &format!("a {} password CSV", kind.label()))?;

    let mut b = Builder::new();
    for row in table.rows() {
        let url = row.get(&["url", "origin"]);
        // Firefox stores internal sync entries under `chrome://`; skip them.
        if url
            .as_deref()
            .is_some_and(|u| u.starts_with("chrome://") || u.starts_with("moz-extension://"))
        {
            b.warn(format!(
                "skipped internal {} entry `{}`",
                kind.label(),
                url.unwrap_or_default()
            ));
            continue;
        }
        let name = name_or_host(row.get(&["name", "title"]), url.as_deref());
        let notes = with_extras(row.get(&["note", "notes"]), &[]);
        b.login(login_draft(
            name,
            row.get(&["username"]),
            row.get(&["password"]),
            None,
            uris_from(url),
            notes,
            None,
            false,
        ));
    }
    Ok(b.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrome_csv() {
        let csv = "name,url,username,password,note\nExample,https://example.com/login,bob,s3cret,\"hello\"\n,https://www.nolabel.org,alice,pw,\n";
        let b = import_browser_csv(csv, BrowserKind::Chrome).unwrap();
        assert_eq!(b.login_drafts.len(), 2);
        assert_eq!(b.login_drafts[0].name, "Example");
        assert_eq!(b.login_drafts[0].notes.as_deref(), Some("hello"));
        assert_eq!(b.login_drafts[1].name, "nolabel.org");
        assert_eq!(b.login_drafts[1].uris[0].uri, "https://www.nolabel.org");
    }

    #[test]
    fn edge_csv_without_note() {
        let csv = "name,url,username,password\nSite,https://s.example,u,p\n";
        let b = import_browser_csv(csv, BrowserKind::Edge).unwrap();
        assert_eq!(b.login_drafts[0].password.as_deref(), Some("p"));
    }

    #[test]
    fn firefox_csv_skips_internal() {
        let csv = "url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged\n\
https://mozilla.org,me,pw,,https://mozilla.org,{abc},1,2,3\n\
chrome://FirefoxAccounts,me@x.org,pw2,Firefox Accounts credentials,,{def},1,2,3\n";
        let b = import_browser_csv(csv, BrowserKind::Firefox).unwrap();
        assert_eq!(b.login_drafts.len(), 1);
        assert_eq!(b.login_drafts[0].name, "mozilla.org");
        assert_eq!(b.warnings.len(), 1);
    }

    #[test]
    fn rejects_non_password_csv() {
        assert!(import_browser_csv("a,b\n1,2\n", BrowserKind::Chrome).is_err());
    }
}
