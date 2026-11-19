//! Organization sharing helpers: re-encryption of personal ciphers for an org key,
//! per-item cipher keys on create, and picker view models.

use std::collections::BTreeMap;

use vault_api::{
    AttachmentRekey, Cipher, CipherCard, CipherField, CipherIdentity, CipherLogin, CipherRequest,
    CipherSshKey, EmergencyAccessEntry, LoginUri, PasswordHistoryEntry,
};
use vault_crypto::{
    decrypt_bytes, encrypt_bytes, generate_user_key, EncString, SymmetricCryptoKey,
};

use crate::error::{Result, SessionError};

/// Where a new item should be created: an organization plus one or more collections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgPlacement {
    pub organization_id: String,
    pub collection_ids: Vec<String>,
}

impl OrgPlacement {
    pub fn new(organization_id: impl Into<String>, collection_ids: Vec<String>) -> Self {
        Self {
            organization_id: organization_id.into(),
            collection_ids,
        }
    }
}

/// One selectable collection in a share / create / edit-collections picker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionChoice {
    pub id: String,
    pub name: String,
    pub organization_id: String,
    pub organization_name: String,
    /// The current user may only view this collection (cannot add / move items into it).
    pub read_only: bool,
    pub hide_passwords: bool,
    /// Set by item-specific pickers: the item is currently in this collection.
    pub selected: bool,
}

impl CollectionChoice {
    /// Items may be added to / edited in this collection.
    pub fn writable(&self) -> bool {
        !self.read_only
    }
}

/// Collections grouped by organization — the data model for a two-level picker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgCollectionGroup {
    pub organization_id: String,
    pub organization_name: String,
    pub collections: Vec<CollectionChoice>,
}

/// Trusted contacts and granted accesses for the emergency-access screen.
#[derive(Debug, Clone, Default)]
pub struct EmergencyAccessOverview {
    /// People the current user designated (they can recover this vault).
    pub trusted: Vec<EmergencyAccessEntry>,
    /// Accounts that designated the current user.
    pub granted: Vec<EmergencyAccessEntry>,
}

/// Re-encrypt one EncString from `from` to `to`, preserving raw plaintext bytes.
fn reencrypt_str(s: &str, from: &SymmetricCryptoKey, to: &SymmetricCryptoKey) -> Result<String> {
    if s.is_empty() {
        return Ok(String::new());
    }
    let bytes = decrypt_bytes(s, from)?;
    Ok(encrypt_bytes(&bytes, to)?)
}

/// Walk arbitrary JSON (e.g. FIDO2 credentials) re-encrypting every EncString leaf.
fn reencrypt_json(
    v: &mut serde_json::Value,
    from: &SymmetricCryptoKey,
    to: &SymmetricCryptoKey,
) -> Result<()> {
    match v {
        serde_json::Value::String(s) => {
            if EncString::parse(s).is_ok() {
                *s = reencrypt_str(s, from, to)?;
            }
        }
        serde_json::Value::Array(a) => {
            for x in a {
                reencrypt_json(x, from, to)?;
            }
        }
        serde_json::Value::Object(o) => {
            for (_, x) in o.iter_mut() {
                reencrypt_json(x, from, to)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Build the request body for sharing a personal cipher with an organization.
///
/// * With an item key (`raw.key`): only the key is re-wrapped under `org_key`; every field
///   stays encrypted under the (unchanged) item key.
/// * Without: every EncString — including custom fields, password history, passkeys and
///   attachment metadata — is decrypted with `user_key` and re-encrypted with `org_key`.
///
/// `organization_id` / `collection_ids` are filled in by the caller.
pub fn reencrypt_cipher_for_org(
    raw: &Cipher,
    user_key: &SymmetricCryptoKey,
    org_key: &SymmetricCryptoKey,
    user_id: &str,
) -> Result<CipherRequest> {
    let wrapped_item_key = match raw.key.as_deref().filter(|k| !k.is_empty()) {
        Some(k) => {
            let bytes = decrypt_bytes(k, user_key)?;
            Some(encrypt_bytes(&bytes, org_key)?)
        }
        None => None,
    };
    let item_keyed = wrapped_item_key.is_some();

    // Field-level conversion is the identity when an item key protects the payload.
    let conv = |s: &str| -> Result<String> {
        if item_keyed {
            Ok(s.to_string())
        } else {
            reencrypt_str(s, user_key, org_key)
        }
    };
    let conv_opt =
        |v: &Option<String>| -> Result<Option<String>> { v.as_ref().map(|s| conv(s)).transpose() };

    let login = raw
        .login
        .as_ref()
        .map(|l| -> Result<CipherLogin> {
            let uris = l
                .uris
                .as_ref()
                .map(|us| {
                    us.iter()
                        .map(|u| {
                            Ok(LoginUri {
                                uri: conv_opt(&u.uri)?,
                                match_type: u.match_type,
                            })
                        })
                        .collect::<Result<Vec<_>>>()
                })
                .transpose()?;
            let fido2 = match (&l.fido2_credentials, item_keyed) {
                (Some(c), false) => {
                    let mut out = Vec::with_capacity(c.len());
                    for cred in c {
                        let mut cred = cred.clone();
                        reencrypt_json(&mut cred, user_key, org_key)?;
                        out.push(cred);
                    }
                    Some(out)
                }
                (other, _) => other.clone(),
            };
            let mut extra = l.extra.clone();
            if !item_keyed {
                for (_, v) in extra.iter_mut() {
                    reencrypt_json(v, user_key, org_key)?;
                }
            }
            Ok(CipherLogin {
                uris,
                username: conv_opt(&l.username)?,
                password: conv_opt(&l.password)?,
                password_revision_date: l.password_revision_date.clone(),
                totp: conv_opt(&l.totp)?,
                autofill_on_page_load: l.autofill_on_page_load,
                fido2_credentials: fido2,
                extra,
            })
        })
        .transpose()?;

    let card = raw
        .card
        .as_ref()
        .map(|c| -> Result<CipherCard> {
            Ok(CipherCard {
                cardholder_name: conv_opt(&c.cardholder_name)?,
                brand: conv_opt(&c.brand)?,
                number: conv_opt(&c.number)?,
                exp_month: conv_opt(&c.exp_month)?,
                exp_year: conv_opt(&c.exp_year)?,
                code: conv_opt(&c.code)?,
            })
        })
        .transpose()?;

    let identity = raw
        .identity
        .as_ref()
        .map(|i| -> Result<CipherIdentity> {
            Ok(CipherIdentity {
                title: conv_opt(&i.title)?,
                first_name: conv_opt(&i.first_name)?,
                middle_name: conv_opt(&i.middle_name)?,
                last_name: conv_opt(&i.last_name)?,
                address1: conv_opt(&i.address1)?,
                address2: conv_opt(&i.address2)?,
                address3: conv_opt(&i.address3)?,
                city: conv_opt(&i.city)?,
                state: conv_opt(&i.state)?,
                postal_code: conv_opt(&i.postal_code)?,
                country: conv_opt(&i.country)?,
                company: conv_opt(&i.company)?,
                email: conv_opt(&i.email)?,
                phone: conv_opt(&i.phone)?,
                ssn: conv_opt(&i.ssn)?,
                username: conv_opt(&i.username)?,
                passport_number: conv_opt(&i.passport_number)?,
                license_number: conv_opt(&i.license_number)?,
            })
        })
        .transpose()?;

    let ssh_key = raw
        .ssh_key
        .as_ref()
        .map(|k| -> Result<CipherSshKey> {
            Ok(CipherSshKey {
                private_key: conv_opt(&k.private_key)?,
                public_key: conv_opt(&k.public_key)?,
                key_fingerprint: conv_opt(&k.key_fingerprint)?,
            })
        })
        .transpose()?;

    let fields = raw
        .fields
        .as_ref()
        .map(|fs| {
            fs.iter()
                .map(|f| {
                    Ok(CipherField {
                        field_type: f.field_type,
                        name: conv_opt(&f.name)?,
                        value: conv_opt(&f.value)?,
                        linked_id: f.linked_id,
                    })
                })
                .collect::<Result<Vec<_>>>()
        })
        .transpose()?;

    let password_history = raw
        .password_history
        .as_ref()
        .map(|hs| {
            hs.iter()
                .map(|h| {
                    Ok(PasswordHistoryEntry {
                        password: conv(&h.password)?,
                        last_used_date: h.last_used_date.clone(),
                    })
                })
                .collect::<Result<Vec<_>>>()
        })
        .transpose()?;

    // Attachment file contents stay encrypted under their own attachment key; only the
    // metadata (file name + wrapped attachment key) follows the cipher key change.
    let attachments2 = match (&raw.attachments, item_keyed) {
        (Some(atts), false) if !atts.is_empty() => {
            let mut map = BTreeMap::new();
            for a in atts {
                let id =
                    a.id.clone()
                        .ok_or_else(|| SessionError::Other("attachment without id".into()))?;
                let key = a.key.as_deref().filter(|k| !k.is_empty()).ok_or_else(|| {
                    SessionError::Other(
                        "attachment has no key (legacy format) and cannot be shared".into(),
                    )
                })?;
                let file_name = a.file_name.as_deref().unwrap_or("");
                map.insert(
                    id,
                    AttachmentRekey {
                        file_name: reencrypt_str(file_name, user_key, org_key)?,
                        key: reencrypt_str(key, user_key, org_key)?,
                    },
                );
            }
            Some(map)
        }
        _ => None,
    };

    Ok(CipherRequest {
        cipher_type: raw.cipher_type,
        name: conv(&raw.name)?,
        notes: conv_opt(&raw.notes)?,
        folder_id: raw.folder_id.clone(),
        favorite: raw.favorite,
        reprompt: raw.reprompt,
        login,
        secure_note: raw.secure_note.clone(),
        card,
        identity,
        fields,
        password_history,
        attachments: None,
        attachments2,
        organization_id: None,
        collection_ids: None,
        key: wrapped_item_key,
        ssh_key,
        encrypted_for: user_id.to_string(),
        last_known_revision_date: raw.revision_date.clone(),
    })
}

/// Build a new cipher request, optionally protecting it with a fresh per-item key.
///
/// `base` is the user key (personal) or organization key. `build` receives the key that must
/// encrypt the payload: the new item key when `use_item_key`, else `base`. The item key is
/// stored on the request wrapped under `base`.
pub fn seal_new_cipher<F>(
    base: &SymmetricCryptoKey,
    use_item_key: bool,
    build: F,
) -> Result<CipherRequest>
where
    F: FnOnce(&SymmetricCryptoKey) -> Result<CipherRequest>,
{
    if !use_item_key {
        return build(base);
    }
    let item_key = generate_user_key();
    let mut req = build(&item_key)?;
    req.key = Some(encrypt_bytes(item_key.to_bytes().as_ref(), base)?);
    Ok(req)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decrypt::{decrypt_cipher, resolve_cipher_key};
    use std::collections::HashMap;
    use vault_crypto::encrypt_with_key;

    fn enc(s: &str, k: &SymmetricCryptoKey) -> String {
        encrypt_with_key(s, k).unwrap()
    }

    fn personal_cipher(user: &SymmetricCryptoKey) -> Cipher {
        let att_key = generate_user_key();
        serde_json::from_value(serde_json::json!({
            "id": "c1",
            "type": 1,
            "name": enc("Site", user),
            "notes": enc("note", user),
            "revisionDate": "2025-01-01T00:00:00Z",
            "login": {
                "username": enc("alice", user),
                "password": enc("hunter2", user),
                "uris": [{"uri": enc("https://a.example", user), "match": 1}],
                "fido2Credentials": [{"rpId": enc("a.example", user), "creationDate": "2025-01-01T00:00:00.000Z"}]
            },
            "fields": [{"type": 0, "name": enc("f", user), "value": enc("v", user)}],
            "passwordHistory": [{"password": enc("old", user), "lastUsedDate": "2024-01-01T00:00:00Z"}],
            "attachments": [{
                "id": "a1",
                "fileName": enc("file.txt", user),
                "key": encrypt_bytes(att_key.to_bytes().as_ref(), user).unwrap()
            }]
        }))
        .unwrap()
    }

    #[test]
    fn share_reencrypts_all_fields_without_item_key() {
        let user = generate_user_key();
        let org = generate_user_key();
        let raw = personal_cipher(&user);
        let req = reencrypt_cipher_for_org(&raw, &user, &org, "user-1").unwrap();

        assert!(req.key.is_none());
        assert_eq!(decrypt_bytes(&req.name, &org).unwrap(), b"Site");
        assert!(decrypt_bytes(&req.name, &user).is_err());
        assert_eq!(
            vault_crypto::decrypt_with_key(req.notes.as_ref().unwrap(), &org).unwrap(),
            "note"
        );
        let login = req.login.as_ref().unwrap();
        assert_eq!(
            vault_crypto::decrypt_with_key(login.password.as_ref().unwrap(), &org).unwrap(),
            "hunter2"
        );
        let uris = login.uris.as_ref().unwrap();
        assert_eq!(uris[0].match_type, Some(1));
        assert_eq!(
            vault_crypto::decrypt_with_key(uris[0].uri.as_ref().unwrap(), &org).unwrap(),
            "https://a.example"
        );
        // FIDO2 EncString leaf re-encrypted; plain date untouched.
        let cred = &login.fido2_credentials.as_ref().unwrap()[0];
        assert_eq!(
            vault_crypto::decrypt_with_key(cred["rpId"].as_str().unwrap(), &org).unwrap(),
            "a.example"
        );
        assert_eq!(cred["creationDate"], "2025-01-01T00:00:00.000Z");
        let fields = req.fields.as_ref().unwrap();
        assert_eq!(
            vault_crypto::decrypt_with_key(fields[0].value.as_ref().unwrap(), &org).unwrap(),
            "v"
        );
        let hist = req.password_history.as_ref().unwrap();
        assert_eq!(
            vault_crypto::decrypt_with_key(&hist[0].password, &org).unwrap(),
            "old"
        );
        let a2 = req.attachments2.as_ref().unwrap();
        assert_eq!(
            vault_crypto::decrypt_with_key(&a2["a1"].file_name, &org).unwrap(),
            "file.txt"
        );
        assert!(decrypt_bytes(&a2["a1"].key, &org).is_ok());
        assert_eq!(req.encrypted_for, "user-1");
        assert_eq!(
            req.last_known_revision_date.as_deref(),
            Some("2025-01-01T00:00:00Z")
        );
    }

    #[test]
    fn share_with_item_key_only_rewraps_key() {
        let user = generate_user_key();
        let org = generate_user_key();
        let item_key = generate_user_key();
        let mut raw = personal_cipher(&user);
        // Re-encrypt payload under the item key.
        raw.name = enc("Keyed", &item_key);
        raw.key = Some(encrypt_bytes(item_key.to_bytes().as_ref(), &user).unwrap());

        let req = reencrypt_cipher_for_org(&raw, &user, &org, "u").unwrap();
        assert_eq!(req.name, raw.name, "payload must be untouched");
        assert!(req.attachments2.is_none());
        let wrapped = req.key.as_ref().unwrap();
        let unwrapped = decrypt_bytes(wrapped, &org).unwrap();
        assert_eq!(unwrapped.as_slice(), item_key.to_bytes().as_ref());
        // Org member resolves the key and reads the name.
        let mut shared = raw.clone();
        shared.key = req.key.clone();
        shared.organization_id = Some("org".into());
        let mut org_keys = HashMap::new();
        org_keys.insert("org".to_string(), org.clone());
        let item = decrypt_cipher(&shared, &user, &org_keys).unwrap();
        assert_eq!(item.name, "Keyed");
    }

    #[test]
    fn share_fails_on_undecryptable_field() {
        let user = generate_user_key();
        let org = generate_user_key();
        let other = generate_user_key();
        let mut raw = personal_cipher(&user);
        raw.name = enc("x", &other);
        assert!(reencrypt_cipher_for_org(&raw, &user, &org, "u").is_err());
    }

    #[test]
    fn seal_new_cipher_wraps_item_key_under_base() {
        let base = generate_user_key();
        let req = seal_new_cipher(&base, true, |k| {
            Ok(CipherRequest {
                cipher_type: 2,
                name: encrypt_with_key("Note", k).unwrap(),
                encrypted_for: "u".into(),
                ..Default::default()
            })
        })
        .unwrap();
        let key_enc = req.key.clone().expect("item key");
        // Payload is NOT readable with the base key directly...
        assert!(vault_crypto::decrypt_with_key(&req.name, &base).is_err());
        // ...but is once the item key is resolved the way sync does it.
        let cipher: Cipher = serde_json::from_value(serde_json::json!({
            "id": "n1", "type": 2, "name": req.name, "key": key_enc
        }))
        .unwrap();
        let resolved = resolve_cipher_key(&cipher, &base, &HashMap::new()).unwrap();
        assert_eq!(
            vault_crypto::decrypt_with_key(&cipher.name, &resolved).unwrap(),
            "Note"
        );
    }

    #[test]
    fn seal_new_cipher_without_item_key_uses_base() {
        let base = generate_user_key();
        let req = seal_new_cipher(&base, false, |k| {
            Ok(CipherRequest {
                cipher_type: 2,
                name: encrypt_with_key("Note", k).unwrap(),
                ..Default::default()
            })
        })
        .unwrap();
        assert!(req.key.is_none());
        assert_eq!(
            vault_crypto::decrypt_with_key(&req.name, &base).unwrap(),
            "Note"
        );
    }
}
