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
    pub identity_name: Option<String>,
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
            identity_name: item.identity_name(),
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
                .map(|n| {
                    let line = n.lines().next().unwrap_or("");
                    if line.len() > 48 {
                        format!("{}…", &line[..45])
                    } else {
                        line.to_string()
                    }
                })
                .unwrap_or_default(),
            ItemType::Card => self
                .card_brand
                .clone()
                .or_else(|| self.card_number.clone())
                .unwrap_or_default(),
            ItemType::Identity => self.identity_name.clone().unwrap_or_default(),
            ItemType::SshKey | ItemType::Unknown => String::new(),
        }
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
