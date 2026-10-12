//! View models for the TUI.
//!
//! Mapped from `vault-session` types; ids are `String` to match the session API.

use vault_session::{DecryptedFolder, DecryptedItem as SessionItem, ItemType as SessionItemType};

/// Cipher type for display / filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemType {
    Login,
    SecureNote,
    Card,
    Identity,
    SshKey,
    Unknown,
}

impl ItemType {
    pub fn from_session(t: SessionItemType) -> Self {
        match t {
            SessionItemType::Login => Self::Login,
            SessionItemType::SecureNote => Self::SecureNote,
            SessionItemType::Card => Self::Card,
            SessionItemType::Identity => Self::Identity,
            SessionItemType::SshKey => Self::SshKey,
            SessionItemType::Unknown => Self::Unknown,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Login => "Login",
            Self::SecureNote => "Note",
            Self::Card => "Card",
            Self::Identity => "Identity",
            Self::SshKey => "SSH Key",
            Self::Unknown => "Item",
        }
    }

    pub fn icon(self) -> &'static str {
        match self {
            Self::Login => "🔑",
            Self::SecureNote => "📝",
            Self::Card => "💳",
            Self::Identity => "🪪",
            Self::SshKey => "🔐",
            Self::Unknown => "•",
        }
    }
}

/// Decrypted vault item ready for the UI.
#[derive(Debug, Clone)]
pub struct DecryptedItem {
    pub id: String,
    pub name: String,
    pub item_type: ItemType,
    pub folder_id: Option<String>,
    pub favorite: bool,
    pub deleted: bool,
    pub username: Option<String>,
    pub password: Option<String>,
    pub totp: Option<String>,
    pub uris: Vec<String>,
    pub notes: Option<String>,
    pub card_number: Option<String>,
    pub card_brand: Option<String>,
    pub card_exp_month: Option<String>,
    pub card_exp_year: Option<String>,
    pub card_code: Option<String>,
    pub identity_name: Option<String>,
    pub ssh_private_key: Option<String>,
    pub ssh_public_key: Option<String>,
    pub ssh_fingerprint: Option<String>,
    pub has_item_key: bool,
    pub reprompt: bool,
}

impl DecryptedItem {
    pub fn from_session(item: &SessionItem) -> Self {
        Self {
            id: item.id.clone(),
            name: item.name.clone(),
            item_type: ItemType::from_session(item.item_type),
            folder_id: item.folder_id.clone(),
            favorite: item.favorite,
            deleted: item.deleted,
            username: item.username.clone(),
            password: item.password.clone(),
            totp: item.totp.clone(),
            uris: item.uris.clone(),
            notes: item.notes.clone(),
            card_number: item.card_number.clone(),
            card_brand: item.card_brand.clone(),
            card_exp_month: item.card_exp_month.clone(),
            card_exp_year: item.card_exp_year.clone(),
            card_code: item.card_code.clone(),
            identity_name: item.identity_name(),
            ssh_private_key: item.ssh_private_key.clone(),
            ssh_public_key: item.ssh_public_key.clone(),
            ssh_fingerprint: item.ssh_fingerprint.clone(),
            has_item_key: item.has_item_key,
            reprompt: item.reprompt,
        }
    }

    pub fn primary_uri(&self) -> Option<&str> {
        self.uris.first().map(String::as_str)
    }

    pub fn subtitle(&self) -> String {
        match self.item_type {
            ItemType::Login => self
                .username
                .clone()
                .or_else(|| self.primary_uri().map(str::to_string))
                .unwrap_or_default(),
            ItemType::SecureNote => self
                .notes
                .as_deref()
                .map(truncate_note_preview)
                .unwrap_or_default(),
            ItemType::Card => {
                card_list_subtitle(self.card_brand.as_deref(), self.card_number.as_deref())
            }
            ItemType::Identity => self.identity_name.clone().unwrap_or_default(),
            ItemType::SshKey => self
                .ssh_fingerprint
                .clone()
                .or_else(|| {
                    self.ssh_public_key
                        .as_ref()
                        .map(|k| truncate_note_preview(k))
                })
                .unwrap_or_default(),
            ItemType::Unknown => String::new(),
        }
    }
}

fn truncate_note_preview(line: &str) -> String {
    let line = line.lines().next().unwrap_or("");
    let truncated: String = line.chars().take(45).collect();
    if line.chars().count() > 48 {
        format!("{truncated}…")
    } else {
        line.to_string()
    }
}

fn card_list_subtitle(brand: Option<&str>, number: Option<&str>) -> String {
    let last4 = number.and_then(card_last4);
    match (brand.filter(|b| !b.is_empty()), last4) {
        (Some(b), Some(l4)) => format!("{b} •••• {l4}"),
        (Some(b), None) => b.to_string(),
        (None, Some(l4)) => format!("•••• {l4}"),
        (None, None) => String::new(),
    }
}

fn card_last4(number: &str) -> Option<String> {
    let digits: String = number.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() >= 4 {
        Some(digits[digits.len() - 4..].to_string())
    } else {
        None
    }
}

/// Folder / sidebar filter entry.
#[derive(Debug, Clone)]
pub struct FolderView {
    pub id: Option<String>,
    pub name: String,
    pub count: usize,
}

impl FolderView {
    pub fn from_session(folder: &DecryptedFolder, count: usize) -> Self {
        Self {
            id: Some(folder.id.clone()),
            name: folder.name.clone(),
            count,
        }
    }
}

/// Built-in sidebar filters (not real folders).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterKind {
    All,
    Favorites,
    Login,
    SecureNote,
    Card,
    Identity,
    SshKey,
    Trash,
    Folder(String),
    NoFolder,
}

impl FilterKind {
    pub fn matches(&self, item: &DecryptedItem) -> bool {
        match self {
            Self::All => !item.deleted,
            Self::Favorites => item.favorite && !item.deleted,
            Self::Login => item.item_type == ItemType::Login && !item.deleted,
            Self::SecureNote => item.item_type == ItemType::SecureNote && !item.deleted,
            Self::Card => item.item_type == ItemType::Card && !item.deleted,
            Self::Identity => item.item_type == ItemType::Identity && !item.deleted,
            Self::SshKey => item.item_type == ItemType::SshKey && !item.deleted,
            Self::Trash => item.deleted,
            Self::Folder(id) => !item.deleted && item.folder_id.as_ref() == Some(id),
            Self::NoFolder => !item.deleted && item.folder_id.is_none(),
        }
    }
}

/// Sidebar row combining built-in filters and user folders.
#[derive(Debug, Clone)]
pub struct SidebarEntry {
    pub label: String,
    pub kind: FilterKind,
    pub count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn note_subtitle_truncates_by_char_not_byte() {
        let item = DecryptedItem {
            id: "x".into(),
            name: "n".into(),
            item_type: ItemType::SecureNote,
            folder_id: None,
            favorite: false,
            deleted: false,
            username: None,
            password: None,
            totp: None,
            uris: vec![],
            notes: Some("😀".repeat(50)),
            card_number: None,
            card_brand: None,
            card_exp_month: None,
            card_exp_year: None,
            card_code: None,
            identity_name: None,
            ssh_private_key: None,
            ssh_public_key: None,
            ssh_fingerprint: None,
            has_item_key: false,
            reprompt: false,
        };
        let sub = item.subtitle();
        assert!(sub.ends_with('…'));
        assert!(sub.chars().count() <= 48);
    }

    #[test]
    fn card_subtitle_masks_pan() {
        let item = DecryptedItem {
            id: "c".into(),
            name: "card".into(),
            item_type: ItemType::Card,
            folder_id: None,
            favorite: false,
            deleted: false,
            username: None,
            password: None,
            totp: None,
            uris: vec![],
            notes: None,
            card_number: Some("4111 1111 1111 1234".into()),
            card_brand: Some("Visa".into()),
            card_exp_month: None,
            card_exp_year: None,
            card_code: None,
            identity_name: None,
            ssh_private_key: None,
            ssh_public_key: None,
            ssh_fingerprint: None,
            has_item_key: false,
            reprompt: false,
        };
        assert_eq!(item.subtitle(), "Visa •••• 1234");
        assert!(!item.subtitle().contains("4111"));
    }
}
