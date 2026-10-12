//! View models for the TUI.
//!
//! Mapped from `vault-session` types; ids are `String` to match the session API.

use vault_session::{
    DecryptedField, DecryptedFieldType, DecryptedFolder, DecryptedItem as SessionItem,
    DecryptedPasswordHistory, ItemType as SessionItemType,
};

pub use vault_session::DecryptedUri;

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

/// Custom field row for detail view / copy shortcuts.
#[derive(Debug, Clone)]
pub struct CustomFieldView {
    pub name: String,
    pub value: String,
    pub hidden: bool,
}

#[derive(Debug, Clone)]
pub struct PasswordHistoryView {
    pub password: String,
    pub last_used_date: Option<String>,
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
    pub uris: Vec<DecryptedUri>,
    pub notes: Option<String>,
    pub cardholder_name: Option<String>,
    pub card_number: Option<String>,
    pub card_brand: Option<String>,
    pub card_exp_month: Option<String>,
    pub card_exp_year: Option<String>,
    pub card_code: Option<String>,
    pub identity_title: Option<String>,
    pub identity_first_name: Option<String>,
    pub identity_middle_name: Option<String>,
    pub identity_last_name: Option<String>,
    pub identity_email: Option<String>,
    pub identity_phone: Option<String>,
    pub identity_username: Option<String>,
    pub identity_address1: Option<String>,
    pub identity_address2: Option<String>,
    pub identity_address3: Option<String>,
    pub identity_city: Option<String>,
    pub identity_state: Option<String>,
    pub identity_postal_code: Option<String>,
    pub identity_country: Option<String>,
    pub identity_company: Option<String>,
    pub identity_ssn: Option<String>,
    pub identity_passport_number: Option<String>,
    pub identity_license_number: Option<String>,
    pub identity_name: Option<String>,
    pub ssh_private_key: Option<String>,
    pub ssh_public_key: Option<String>,
    pub ssh_fingerprint: Option<String>,
    pub creation_date: Option<String>,
    pub organization_id: Option<String>,
    pub collection_ids: Vec<String>,
    pub has_item_key: bool,
    pub reprompt: bool,
    pub custom_fields: Vec<CustomFieldView>,
    pub password_history: Vec<PasswordHistoryView>,
}

#[derive(Debug, Clone)]
pub struct SendView {
    pub id: String,
    pub name: String,
    pub text: Option<String>,
    pub notes: Option<String>,
    pub disabled: bool,
}

impl Default for DecryptedItem {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            item_type: ItemType::Login,
            folder_id: None,
            favorite: false,
            deleted: false,
            username: None,
            password: None,
            totp: None,
            uris: vec![],
            notes: None,
            cardholder_name: None,
            card_number: None,
            card_brand: None,
            card_exp_month: None,
            card_exp_year: None,
            card_code: None,
            identity_title: None,
            identity_first_name: None,
            identity_middle_name: None,
            identity_last_name: None,
            identity_email: None,
            identity_phone: None,
            identity_username: None,
            identity_address1: None,
            identity_address2: None,
            identity_address3: None,
            identity_city: None,
            identity_state: None,
            identity_postal_code: None,
            identity_country: None,
            identity_company: None,
            identity_ssn: None,
            identity_passport_number: None,
            identity_license_number: None,
            identity_name: None,
            ssh_private_key: None,
            ssh_public_key: None,
            ssh_fingerprint: None,
            creation_date: None,
            organization_id: None,
            collection_ids: Vec::new(),
            has_item_key: false,
            reprompt: false,
            custom_fields: Vec::new(),
            password_history: Vec::new(),
        }
    }
}

fn field_from_session(f: &DecryptedField) -> CustomFieldView {
    CustomFieldView {
        name: f.name.clone(),
        value: f.value.clone(),
        hidden: matches!(f.field_type, DecryptedFieldType::Hidden),
    }
}

fn history_from_session(h: &DecryptedPasswordHistory) -> PasswordHistoryView {
    PasswordHistoryView {
        password: h.password.clone(),
        last_used_date: h.last_used_date.clone(),
    }
}

impl DecryptedItem {
    pub fn from_session(item: &SessionItem) -> Self {
        Self {
            id: item.id.clone(),
            name: item.name.clone(),
            item_type: ItemType::from_session(item.item_type),
            folder_id: item.folder_id.clone(),
            organization_id: item.organization_id.clone(),
            collection_ids: item.collection_ids.clone(),
            favorite: item.favorite,
            deleted: item.deleted,
            username: item.username.clone(),
            password: item.password.clone(),
            totp: item.totp.clone(),
            uris: item.uris.clone(),
            notes: item.notes.clone(),
            cardholder_name: item.cardholder_name.clone(),
            card_number: item.card_number.clone(),
            card_brand: item.card_brand.clone(),
            card_exp_month: item.card_exp_month.clone(),
            card_exp_year: item.card_exp_year.clone(),
            card_code: item.card_code.clone(),
            identity_title: item.identity_title.clone(),
            identity_first_name: item.identity_first_name.clone(),
            identity_middle_name: item.identity_middle_name.clone(),
            identity_last_name: item.identity_last_name.clone(),
            identity_email: item.identity_email.clone(),
            identity_phone: item.identity_phone.clone(),
            identity_username: item.identity_username.clone(),
            identity_address1: item.identity_address1.clone(),
            identity_address2: item.identity_address2.clone(),
            identity_address3: item.identity_address3.clone(),
            identity_city: item.identity_city.clone(),
            identity_state: item.identity_state.clone(),
            identity_postal_code: item.identity_postal_code.clone(),
            identity_country: item.identity_country.clone(),
            identity_company: item.identity_company.clone(),
            identity_ssn: item.identity_ssn.clone(),
            identity_passport_number: item.identity_passport_number.clone(),
            identity_license_number: item.identity_license_number.clone(),
            identity_name: item.identity_name(),
            ssh_private_key: item.ssh_private_key.clone(),
            ssh_public_key: item.ssh_public_key.clone(),
            ssh_fingerprint: item.ssh_fingerprint.clone(),
            creation_date: item.creation_date.clone(),
            has_item_key: item.has_item_key,
            reprompt: item.reprompt,
            custom_fields: item.custom_fields.iter().map(field_from_session).collect(),
            password_history: item
                .password_history
                .iter()
                .map(history_from_session)
                .collect(),
        }
    }

    pub fn primary_uri(&self) -> Option<&str> {
        self.uris.first().map(|u| u.uri.as_str())
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
    MyVault,
    Favorites,
    Login,
    SecureNote,
    Card,
    Identity,
    SshKey,
    Trash,
    Folder(String),
    NoFolder,
    Organization(String),
    Collection(String),
    Sends,
}

impl FilterKind {
    pub fn matches(&self, item: &DecryptedItem) -> bool {
        match self {
            Self::All => !item.deleted,
            Self::MyVault => !item.deleted && item.organization_id.is_none(),
            Self::Favorites => item.favorite && !item.deleted,
            Self::Login => item.item_type == ItemType::Login && !item.deleted,
            Self::SecureNote => item.item_type == ItemType::SecureNote && !item.deleted,
            Self::Card => item.item_type == ItemType::Card && !item.deleted,
            Self::Identity => item.item_type == ItemType::Identity && !item.deleted,
            Self::SshKey => item.item_type == ItemType::SshKey && !item.deleted,
            Self::Trash => item.deleted,
            Self::Folder(id) => !item.deleted && item.folder_id.as_ref() == Some(id),
            Self::NoFolder => !item.deleted && item.folder_id.is_none(),
            Self::Organization(id) => {
                !item.deleted && item.organization_id.as_deref() == Some(id.as_str())
            }
            Self::Collection(id) => {
                !item.deleted && item.collection_ids.iter().any(|c| c == id)
            }
            Self::Sends => false,
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

    fn minimal_item() -> DecryptedItem {
        DecryptedItem {
            id: "x".into(),
            name: "n".into(),
            item_type: ItemType::SecureNote,
            ..Default::default()
        }
    }

    #[test]
    fn note_subtitle_truncates_by_char_not_byte() {
        let mut item = minimal_item();
        item.notes = Some("😀".repeat(50));
        let sub = item.subtitle();
        assert!(sub.ends_with('…'));
        assert!(sub.chars().count() <= 48);
    }

    #[test]
    fn card_subtitle_masks_pan() {
        let mut item = minimal_item();
        item.item_type = ItemType::Card;
        item.card_number = Some("4111 1111 1111 1234".into());
        item.card_brand = Some("Visa".into());
        assert_eq!(item.subtitle(), "Visa •••• 1234");
        assert!(!item.subtitle().contains("4111"));
    }
}
