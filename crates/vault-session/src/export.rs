//! Bitwarden-compatible export / import (JSON, CSV, encrypted JSON).

use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use argon2::{Algorithm, Argon2, Params, Version};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha256 as Sha256Digest;
use vault_crypto::{
    decrypt_with_key, encrypt_with_key, stretch_master_key, KdfParams, MasterKey,
    PBKDF2_MIN_ITERATIONS, SymmetricCryptoKey,
};

type HmacSha256 = Hmac<Sha256Digest>;

use crate::error::{Result, SessionError};
use crate::models::{
    CardDraft, DecryptedFieldType, DecryptedFolder, DecryptedItem, IdentityDraft, ItemType,
    LoginDraft, NoteDraft,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BitwardenExport {
    #[serde(default)]
    encrypted: bool,
    #[serde(default)]
    folders: Vec<ExportFolder>,
    #[serde(default)]
    items: Vec<ExportItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExportFolder {
    id: String,
    name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExportItem {
    id: String,
    name: String,
    #[serde(rename = "type")]
    item_type: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    folder_id: Option<String>,
    favorite: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    login: Option<ExportLogin>,
    #[serde(skip_serializing_if = "Option::is_none")]
    secure_note: Option<ExportSecureNote>,
    #[serde(skip_serializing_if = "Option::is_none")]
    card: Option<ExportCard>,
    #[serde(skip_serializing_if = "Option::is_none")]
    identity: Option<ExportIdentity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fields: Option<Vec<ExportField>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password_history: Option<Vec<ExportPasswordHistory>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    creation_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    revision_date: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExportLogin {
    #[serde(skip_serializing_if = "Option::is_none")]
    uris: Option<Vec<ExportUri>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    totp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password_revision_date: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExportUri {
    uri: String,
    #[serde(rename = "match", skip_serializing_if = "Option::is_none")]
    match_type: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExportSecureNote {
    #[serde(rename = "type")]
    note_type: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ExportCard {
    #[serde(skip_serializing_if = "Option::is_none")]
    cardholder_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    brand: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exp_month: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exp_year: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ExportIdentity {
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    first_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    middle_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    address1: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    address2: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    address3: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    city: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    postal_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    company: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    phone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ssn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    passport_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    license_number: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExportField {
    name: String,
    value: String,
    #[serde(rename = "type")]
    field_type: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    linked_id: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExportPasswordHistory {
    password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_used_date: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedExport {
    encrypted: bool,
    password_protected: bool,
    salt: String,
    kdf_iterations: u32,
    kdf_type: u8,
    kdf_memory: Option<u32>,
    kdf_parallelism: Option<u32>,
    #[serde(rename = "encKeyValidation_DO_NOT_EDIT")]
    enc_key_validation_do_not_edit: String,
    data: String,
}

fn item_to_export(item: &DecryptedItem) -> ExportItem {
    let login = if item.item_type == ItemType::Login {
        Some(ExportLogin {
            uris: if item.uris.is_empty() {
                None
            } else {
                Some(
                    item.uris
                        .iter()
                        .map(|u| ExportUri {
                            uri: u.uri.clone(),
                            match_type: u.match_type,
                        })
                        .collect(),
                )
            },
            username: item.username.clone(),
            password: item.password.clone(),
            totp: item.totp.clone(),
            password_revision_date: item.password_revision_date.clone(),
        })
    } else {
        None
    };

    let secure_note = if item.item_type == ItemType::SecureNote {
        Some(ExportSecureNote { note_type: 0 })
    } else {
        None
    };

    let card = if item.item_type == ItemType::Card {
        Some(ExportCard {
            cardholder_name: item.cardholder_name.clone(),
            brand: item.card_brand.clone(),
            number: item.card_number.clone(),
            exp_month: item.card_exp_month.clone(),
            exp_year: item.card_exp_year.clone(),
            code: item.card_code.clone(),
        })
    } else {
        None
    };

    let identity = if item.item_type == ItemType::Identity {
        Some(ExportIdentity {
            title: item.identity_title.clone(),
            first_name: item.identity_first_name.clone(),
            middle_name: item.identity_middle_name.clone(),
            last_name: item.identity_last_name.clone(),
            address1: item.identity_address1.clone(),
            address2: item.identity_address2.clone(),
            address3: item.identity_address3.clone(),
            city: item.identity_city.clone(),
            state: item.identity_state.clone(),
            postal_code: item.identity_postal_code.clone(),
            country: item.identity_country.clone(),
            company: item.identity_company.clone(),
            email: item.identity_email.clone(),
            phone: item.identity_phone.clone(),
            ssn: item.identity_ssn.clone(),
            username: item.identity_username.clone(),
            passport_number: item.identity_passport_number.clone(),
            license_number: item.identity_license_number.clone(),
        })
    } else {
        None
    };

    let fields = if item.custom_fields.is_empty() {
        None
    } else {
        Some(
            item.custom_fields
                .iter()
                .map(|f| ExportField {
                    name: f.name.clone(),
                    value: f.value.clone(),
                    field_type: field_type_to_u8(f.field_type),
                    linked_id: f.linked_id,
                })
                .collect(),
        )
    };

    let password_history = if item.password_history.is_empty() {
        None
    } else {
        Some(
            item.password_history
                .iter()
                .map(|h| ExportPasswordHistory {
                    password: h.password.clone(),
                    last_used_date: h.last_used_date.clone(),
                })
                .collect(),
        )
    };

    ExportItem {
        id: item.id.clone(),
        name: item.name.clone(),
        item_type: item.item_type.as_u8().unwrap_or(0),
        folder_id: item.folder_id.clone(),
        favorite: item.favorite,
        notes: item.notes.clone(),
        login,
        secure_note,
        card,
        identity,
        fields,
        password_history,
        creation_date: item.creation_date.clone(),
        revision_date: item.revision_date.clone(),
    }
}

fn field_type_to_u8(t: DecryptedFieldType) -> u8 {
    match t {
        DecryptedFieldType::Text => 0,
        DecryptedFieldType::Hidden => 1,
        DecryptedFieldType::Boolean => 2,
        DecryptedFieldType::Linked => 3,
        DecryptedFieldType::Unknown(v) => v,
    }
}

/// Unencrypted Bitwarden JSON export.
pub fn export_json(items: &[DecryptedItem], folders: &[DecryptedFolder]) -> String {
    let doc = BitwardenExport {
        encrypted: false,
        folders: folders
            .iter()
            .map(|f| ExportFolder {
                id: f.id.clone(),
                name: f.name.clone(),
            })
            .collect(),
        items: items.iter().filter(|i| !i.deleted).map(item_to_export).collect(),
    };
    serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into())
}

/// CSV export (login-focused columns).
pub fn export_csv(items: &[DecryptedItem]) -> String {
    let mut w = String::from("name,username,password,uri,notes,favorite\n");
    for item in items.iter().filter(|i| !i.deleted && i.item_type == ItemType::Login) {
        let uri = item.primary_uri().unwrap_or("");
        w.push_str(&csv_row(&[
            &item.name,
            item.username.as_deref().unwrap_or(""),
            item.password.as_deref().unwrap_or(""),
            uri,
            item.notes.as_deref().unwrap_or(""),
            if item.favorite { "true" } else { "false" },
        ]));
    }
    w
}

fn csv_row(cols: &[&str]) -> String {
    cols.iter()
        .map(|s| csv_escape(s))
        .collect::<Vec<_>>()
        .join(",")
        + "\n"
}

fn csv_escape(s: &str) -> String {
    if s.contains(['"', ',', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Password-protected export compatible with Bitwarden encrypted JSON shape.
pub fn export_encrypted_json(
    items: &[DecryptedItem],
    folders: &[DecryptedFolder],
    password: &str,
    kdf: &KdfParams,
) -> Result<String> {
    kdf.validate().map_err(|e| SessionError::Other(e.to_string()))?;
    let plaintext = export_json(items, folders);

    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let master = derive_export_master_key(password, kdf, &salt)?;
    let stretched = stretch_master_key(&master)?;
    let sym: SymmetricCryptoKey = (&stretched).into();

    let validation = encrypt_with_key("bitwarden-export-check", &sym)?;
    let data = encrypt_with_key(&plaintext, &sym)?;

    let (kdf_type, iterations, memory, parallelism) = match kdf {
        KdfParams::Pbkdf2 { iterations } => (0u8, *iterations, None, None),
        KdfParams::Argon2id {
            iterations,
            memory_mib,
            parallelism,
        } => (1u8, *iterations, Some(*memory_mib), Some(*parallelism)),
    };

    let doc = EncryptedExport {
        encrypted: true,
        password_protected: true,
        salt: base64::engine::general_purpose::STANDARD.encode(salt),
        kdf_iterations: iterations,
        kdf_type,
        kdf_memory: memory,
        kdf_parallelism: parallelism,
        enc_key_validation_do_not_edit: validation,
        data,
    };
    serde_json::to_string_pretty(&doc).map_err(|e| SessionError::Other(e.to_string()))
}

/// Export KDF uses the random file salt (not account email).
fn derive_export_master_key(
    password: &str,
    kdf: &KdfParams,
    salt: &[u8],
) -> Result<MasterKey> {
    let mut key = [0u8; 32];
    match kdf {
        KdfParams::Pbkdf2 { iterations } => {
            if *iterations < PBKDF2_MIN_ITERATIONS {
                return Err(SessionError::Other(format!(
                    "PBKDF2 iterations {iterations} below minimum {PBKDF2_MIN_ITERATIONS}"
                )));
            }
            pbkdf2::<HmacSha256>(password.as_bytes(), salt, *iterations, &mut key)
                .map_err(|e| SessionError::Other(e.to_string()))?;
        }
        KdfParams::Argon2id {
            iterations,
            memory_mib,
            parallelism,
        } => {
            let memory_kib = memory_mib.saturating_mul(1024);
            let params = Params::new(memory_kib, *iterations, *parallelism, Some(32))
                .map_err(|e| SessionError::Other(e.to_string()))?;
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            argon2
                .hash_password_into(password.as_bytes(), salt, &mut key)
                .map_err(|e| SessionError::Other(e.to_string()))?;
        }
    }
    Ok(MasterKey::from_bytes(key))
}

#[derive(Debug, Clone, Default)]
pub struct ImportBundle {
    pub folders: Vec<DecryptedFolder>,
    pub login_drafts: Vec<LoginDraft>,
    pub note_drafts: Vec<NoteDraft>,
    pub card_drafts: Vec<CardDraft>,
    pub identity_drafts: Vec<IdentityDraft>,
}

/// Decrypt a password-protected export produced by [`export_encrypted_json`], then parse.
pub fn import_encrypted_json(json: &str, password: &str) -> Result<ImportBundle> {
    let doc: EncryptedExport = serde_json::from_str(json)
        .map_err(|e| SessionError::Other(format!("encrypted import parse: {e}")))?;
    if !doc.encrypted && !doc.password_protected {
        return import_bitwarden_json(json);
    }
    let salt = base64::engine::general_purpose::STANDARD
        .decode(&doc.salt)
        .map_err(|e| SessionError::Other(format!("export salt: {e}")))?;
    let kdf = match doc.kdf_type {
        0 => KdfParams::Pbkdf2 {
            iterations: doc.kdf_iterations,
        },
        1 => KdfParams::Argon2id {
            iterations: doc.kdf_iterations,
            memory_mib: doc.kdf_memory.unwrap_or(64),
            parallelism: doc.kdf_parallelism.unwrap_or(4),
        },
        other => {
            return Err(SessionError::Other(format!(
                "unsupported export KDF type {other}"
            )))
        }
    };
    let master = derive_export_master_key(password, &kdf, &salt)?;
    let stretched = stretch_master_key(&master)?;
    let sym: SymmetricCryptoKey = (&stretched).into();
    let validation = decrypt_with_key(&doc.enc_key_validation_do_not_edit, &sym).map_err(|_| {
        SessionError::Other("incorrect export password (validation failed)".into())
    })?;
    if validation != "bitwarden-export-check" {
        return Err(SessionError::Other(
            "incorrect export password (validation mismatch)".into(),
        ));
    }
    let plaintext = decrypt_with_key(&doc.data, &sym)
        .map_err(|e| SessionError::Other(format!("decrypt export data: {e}")))?;
    import_bitwarden_json(&plaintext)
}

/// Parse an unencrypted Bitwarden JSON export into import drafts.
pub fn import_bitwarden_json(json: &str) -> Result<ImportBundle> {
    // Detect our password-protected envelope without a password.
    if let Ok(enc) = serde_json::from_str::<EncryptedExport>(json) {
        if enc.encrypted || enc.password_protected {
            return Err(SessionError::Other(
                "encrypted export requires a password — use import_encrypted_json".into(),
            ));
        }
    }
    let doc: BitwardenExport =
        serde_json::from_str(json).map_err(|e| SessionError::Other(format!("import parse: {e}")))?;
    if doc.encrypted {
        return Err(SessionError::Other(
            "encrypted export requires a password — use import_encrypted_json".into(),
        ));
    }

    let folders = doc
        .folders
        .into_iter()
        .map(|f| DecryptedFolder {
            id: f.id,
            name: f.name,
        })
        .collect();

    let mut login_drafts = Vec::new();
    let mut note_drafts = Vec::new();
    let mut card_drafts = Vec::new();
    let mut identity_drafts = Vec::new();

    for item in doc.items {
        let folder_id = item.folder_id;
        let favorite = item.favorite;
        match ItemType::from_u8(item.item_type) {
            ItemType::Login => {
                let login = item.login.unwrap_or_default_login();
                login_drafts.push(LoginDraft {
                    name: item.name,
                    username: login.username,
                    password: login.password,
                    totp: login.totp,
                    uris: login
                        .uris
                        .map(|list| {
                            list.into_iter()
                                .map(|u| crate::models::DecryptedUri {
                                    uri: u.uri,
                                    match_type: u.match_type,
                                })
                                .collect()
                        })
                        .unwrap_or_default(),
                    notes: item.notes,
                    folder_id,
                    favorite,
                    reprompt: false,
                });
            }
            ItemType::SecureNote => {
                note_drafts.push(NoteDraft {
                    name: item.name,
                    notes: item.notes,
                    folder_id,
                    favorite,
                });
            }
            ItemType::Card => {
                let card = item.card.unwrap_or_default();
                card_drafts.push(CardDraft {
                    name: item.name,
                    cardholder_name: card.cardholder_name,
                    brand: card.brand,
                    number: card.number,
                    exp_month: card.exp_month,
                    exp_year: card.exp_year,
                    code: card.code,
                    notes: item.notes,
                    folder_id,
                    favorite,
                    reprompt: false,
                });
            }
            ItemType::Identity => {
                let ident = item.identity.unwrap_or_default();
                identity_drafts.push(IdentityDraft {
                    name: item.name,
                    title: ident.title,
                    first_name: ident.first_name,
                    middle_name: ident.middle_name,
                    last_name: ident.last_name,
                    address1: ident.address1,
                    address2: ident.address2,
                    address3: ident.address3,
                    city: ident.city,
                    state: ident.state,
                    postal_code: ident.postal_code,
                    country: ident.country,
                    company: ident.company,
                    email: ident.email,
                    phone: ident.phone,
                    ssn: ident.ssn,
                    username: ident.username,
                    passport_number: ident.passport_number,
                    license_number: ident.license_number,
                    notes: item.notes,
                    folder_id,
                    favorite,
                    reprompt: false,
                });
            }
            _ => {}
        }
    }

    Ok(ImportBundle {
        folders,
        login_drafts,
        note_drafts,
        card_drafts,
        identity_drafts,
    })
}

trait DefaultLogin {
    fn unwrap_or_default_login(self) -> ExportLogin;
}

impl DefaultLogin for Option<ExportLogin> {
    fn unwrap_or_default_login(self) -> ExportLogin {
        self.unwrap_or(ExportLogin {
            uris: None,
            username: None,
            password: None,
            totp: None,
            password_revision_date: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        DecryptedField, DecryptedPasswordHistory, DecryptedUri, ItemType,
    };

    fn sample_item() -> DecryptedItem {
        DecryptedItem {
            id: "id-1".into(),
            name: "Sample".into(),
            item_type: ItemType::Login,
            folder_id: Some("f1".into()),
            organization_id: None,
            collection_ids: Vec::new(),
            favorite: true,
            deleted: false,
            reprompt: false,
            notes: Some("note".into()),
            username: Some("user".into()),
            password: Some("secret".into()),
            totp: None,
            uris: vec![DecryptedUri {
                uri: "https://example.com".into(),
                match_type: Some(0),
            }],
            custom_fields: vec![DecryptedField {
                name: "pin".into(),
                value: "1234".into(),
                field_type: DecryptedFieldType::Hidden,
                linked_id: None,
            }],
            password_history: vec![DecryptedPasswordHistory {
                password: "old".into(),
                last_used_date: None,
            }],
            password_revision_date: None,
            creation_date: None,
            cardholder_name: None,
            card_brand: None,
            card_number: None,
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
            ssh_private_key: None,
            ssh_public_key: None,
            ssh_fingerprint: None,
            revision_date: None,
            has_item_key: false,
        }
    }

    #[test]
    fn json_round_trip_fields() {
        let items = vec![sample_item()];
        let folders = vec![DecryptedFolder {
            id: "f1".into(),
            name: "Folder".into(),
        }];
        let json = export_json(&items, &folders);
        let bundle = import_bitwarden_json(&json).unwrap();
        assert_eq!(bundle.folders.len(), 1);
        assert_eq!(bundle.login_drafts.len(), 1);
        assert_eq!(bundle.login_drafts[0].username.as_deref(), Some("user"));
    }

    #[test]
    fn csv_contains_login() {
        let csv = export_csv(&[sample_item()]);
        assert!(csv.contains("Sample"));
        assert!(csv.contains("https://example.com"));
    }

    #[test]
    fn encrypted_export_decrypts() {
        let items = vec![sample_item()];
        let folders = vec![];
        let kdf = KdfParams::Pbkdf2 {
            iterations: PBKDF2_MIN_ITERATIONS,
        };
        let enc = export_encrypted_json(&items, &folders, "export-pass", &kdf).unwrap();
        assert!(enc.contains("encKeyValidation_DO_NOT_EDIT"));
        let bundle = import_encrypted_json(&enc, "export-pass").unwrap();
        assert_eq!(bundle.login_drafts.len(), 1);
        assert_eq!(bundle.login_drafts[0].name, "Sample");
        assert!(import_encrypted_json(&enc, "wrong").is_err());
    }

    #[test]
    fn json_imports_card_and_identity() {
        let json = r#"{
            "encrypted": false,
            "folders": [],
            "items": [
                {
                    "id": "c1",
                    "name": "Visa",
                    "type": 3,
                    "favorite": false,
                    "card": { "number": "4111", "brand": "Visa" }
                },
                {
                    "id": "i1",
                    "name": "Me",
                    "type": 4,
                    "favorite": true,
                    "identity": { "firstName": "Ada", "lastName": "Lovelace" }
                }
            ]
        }"#;
        let bundle = import_bitwarden_json(json).unwrap();
        assert_eq!(bundle.card_drafts.len(), 1);
        assert_eq!(bundle.card_drafts[0].number.as_deref(), Some("4111"));
        assert_eq!(bundle.identity_drafts.len(), 1);
        assert_eq!(
            bundle.identity_drafts[0].first_name.as_deref(),
            Some("Ada")
        );
    }
}
