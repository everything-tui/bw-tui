//! Importers for other password managers and browser exports.
//!
//! Every importer converts its source format into an [`ImportBundle`] of drafts which the
//! caller then creates through the session. Folder ids inside a bundle produced here are
//! synthetic (`import-folder-N`); callers must map them to the real folder ids returned by
//! `Session::create_folder` before creating items.

mod bitwarden_csv;
mod browser;
mod common;
mod keepass;
mod lastpass;
mod onepassword;
mod proton;

use crate::error::{Result, SessionError};
use crate::export::{import_bitwarden_json, import_encrypted_json, ImportBundle};

pub use bitwarden_csv::import_bitwarden_csv;
pub use browser::{import_browser_csv, BrowserKind};
pub use keepass::{import_keepass_csv, import_keepass_xml};
pub use lastpass::import_lastpass_csv;
pub use onepassword::{import_1password_1pux, import_1password_csv};
pub use proton::{import_proton_csv, import_proton_json};

/// Supported import formats (CLI `import --format <name>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportFormat {
    BitwardenJson,
    BitwardenCsv,
    ChromeCsv,
    EdgeCsv,
    FirefoxCsv,
    OnePasswordCsv,
    OnePassword1pux,
    LastPassCsv,
    KeePassXml,
    KeePassCsv,
    ProtonPassJson,
    ProtonPassCsv,
}

impl ImportFormat {
    pub const ALL: [ImportFormat; 12] = [
        Self::BitwardenJson,
        Self::BitwardenCsv,
        Self::ChromeCsv,
        Self::EdgeCsv,
        Self::FirefoxCsv,
        Self::OnePasswordCsv,
        Self::OnePassword1pux,
        Self::LastPassCsv,
        Self::KeePassXml,
        Self::KeePassCsv,
        Self::ProtonPassJson,
        Self::ProtonPassCsv,
    ];

    /// Canonical CLI name.
    pub fn name(self) -> &'static str {
        match self {
            Self::BitwardenJson => "bitwarden-json",
            Self::BitwardenCsv => "bitwarden-csv",
            Self::ChromeCsv => "chrome-csv",
            Self::EdgeCsv => "edge-csv",
            Self::FirefoxCsv => "firefox-csv",
            Self::OnePasswordCsv => "1password-csv",
            Self::OnePassword1pux => "1password-1pux",
            Self::LastPassCsv => "lastpass-csv",
            Self::KeePassXml => "keepass-xml",
            Self::KeePassCsv => "keepass-csv",
            Self::ProtonPassJson => "proton-json",
            Self::ProtonPassCsv => "proton-csv",
        }
    }

    /// Comma-separated list of accepted format names (for help / error messages).
    pub fn names() -> String {
        Self::ALL
            .iter()
            .map(|f| f.name())
            .collect::<Vec<_>>()
            .join("|")
    }

    /// Parse a CLI format string (case-insensitive, with a few aliases).
    pub fn parse(s: &str) -> Option<Self> {
        let k = s.trim().to_ascii_lowercase().replace('_', "-");
        Some(match k.as_str() {
            "bitwarden-json" | "bitwarden" | "json" => Self::BitwardenJson,
            "bitwarden-csv" | "csv" => Self::BitwardenCsv,
            "chrome-csv" | "chrome" | "chromium-csv" | "brave-csv" => Self::ChromeCsv,
            "edge-csv" | "edge" => Self::EdgeCsv,
            "firefox-csv" | "firefox" => Self::FirefoxCsv,
            "1password-csv" | "onepassword-csv" => Self::OnePasswordCsv,
            "1password-1pux" | "1pux" | "1password" | "onepassword-1pux" => Self::OnePassword1pux,
            "lastpass-csv" | "lastpass" => Self::LastPassCsv,
            "keepass-xml" | "keepassxc-xml" | "keepass" | "keepassxc" => Self::KeePassXml,
            "keepass-csv" | "keepassxc-csv" => Self::KeePassCsv,
            "proton-json" | "proton-pass-json" | "proton" | "protonpass" | "proton-pass" => {
                Self::ProtonPassJson
            }
            "proton-csv" | "proton-pass-csv" => Self::ProtonPassCsv,
            _ => return None,
        })
    }

    /// Guess a format from a file extension (`json`, `csv`, `xml`, `1pux`), when unambiguous.
    pub fn guess_from_extension(path: &std::path::Path) -> Option<Self> {
        match path
            .extension()
            .and_then(|e| e.to_str())?
            .to_ascii_lowercase()
            .as_str()
        {
            "json" => Some(Self::BitwardenJson),
            "1pux" => Some(Self::OnePassword1pux),
            "xml" => Some(Self::KeePassXml),
            _ => None,
        }
    }

    /// Whether the importer needs the raw bytes (binary container) rather than UTF-8 text.
    pub fn is_binary(self) -> bool {
        matches!(self, Self::OnePassword1pux)
    }
}

/// Import `bytes` in the given format. `password` is only used for encrypted Bitwarden JSON.
pub fn import_from_bytes(
    format: ImportFormat,
    bytes: &[u8],
    password: Option<&str>,
) -> Result<ImportBundle> {
    if format == ImportFormat::OnePassword1pux {
        return import_1password_1pux(bytes);
    }
    let text = common::decode_text(bytes)?;
    import_from_text(format, &text, password)
}

/// Import already-decoded text in the given (non-binary) format.
pub fn import_from_text(
    format: ImportFormat,
    text: &str,
    password: Option<&str>,
) -> Result<ImportBundle> {
    let text = text.trim_start_matches('\u{feff}');
    match format {
        ImportFormat::BitwardenJson => {
            let looks_encrypted = text.contains("encKeyValidation_DO_NOT_EDIT")
                || text.contains("\"passwordProtected\": true")
                || text.contains("\"passwordProtected\":true");
            if looks_encrypted {
                let pwd = password.filter(|p| !p.is_empty()).ok_or_else(|| {
                    SessionError::Other("encrypted import requires a password".into())
                })?;
                import_encrypted_json(text, pwd)
            } else {
                import_bitwarden_json(text)
            }
        }
        ImportFormat::BitwardenCsv => import_bitwarden_csv(text),
        ImportFormat::ChromeCsv => import_browser_csv(text, BrowserKind::Chrome),
        ImportFormat::EdgeCsv => import_browser_csv(text, BrowserKind::Edge),
        ImportFormat::FirefoxCsv => import_browser_csv(text, BrowserKind::Firefox),
        ImportFormat::OnePasswordCsv => import_1password_csv(text),
        ImportFormat::OnePassword1pux => Err(SessionError::Other(
            "1pux is a binary (zip) format — use import_from_bytes".into(),
        )),
        ImportFormat::LastPassCsv => import_lastpass_csv(text),
        ImportFormat::KeePassXml => import_keepass_xml(text),
        ImportFormat::KeePassCsv => import_keepass_csv(text),
        ImportFormat::ProtonPassJson => import_proton_json(text),
        ImportFormat::ProtonPassCsv => import_proton_csv(text),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_format_names_and_aliases() {
        for f in ImportFormat::ALL {
            assert_eq!(ImportFormat::parse(f.name()), Some(f));
        }
        assert_eq!(
            ImportFormat::parse("1PUX"),
            Some(ImportFormat::OnePassword1pux)
        );
        assert_eq!(ImportFormat::parse("Chrome"), Some(ImportFormat::ChromeCsv));
        assert_eq!(ImportFormat::parse("nope"), None);
    }

    #[test]
    fn dispatch_bitwarden_csv() {
        let csv = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n,,login,A,,,,https://a.example,u,p,\n";
        let b = import_from_bytes(ImportFormat::BitwardenCsv, csv.as_bytes(), None).unwrap();
        assert_eq!(b.login_drafts.len(), 1);
    }
}
