use std::collections::HashMap;

use vault_api::{Cipher, Collection, Folder, Send, SyncResponse};
use vault_crypto::{
    decrypt_bytes, decrypt_private_key, decrypt_with_key, unwrap_org_key,
    unwrap_org_key_with_user, CryptoError, SymmetricCryptoKey, UserKey,
};

use crate::error::Result;
use crate::models::{
    DecryptedCollection, DecryptedField, DecryptedFieldType, DecryptedFolder, DecryptedItem,
    DecryptedOrganization, DecryptedPasswordHistory, DecryptedSend, DecryptedUri, ItemType,
    VaultIndex,
};

pub fn build_index(sync: &SyncResponse, user_key: &UserKey) -> Result<VaultIndex> {
    let mut org_keys = HashMap::new();
    if let Some(profile) = &sync.profile {
        if let Some(private_enc) = &profile.private_key {
            if let Ok(private_der) = decrypt_private_key(private_enc, user_key) {
                for org in &profile.organizations {
                    if let Some(org_key_enc) = &org.key {
                        let ok = match unwrap_org_key_with_user(
                            org_key_enc,
                            &private_der,
                            Some(user_key),
                        ) {
                            Ok(k) => Some(k),
                            Err(CryptoError::MacMismatch) => {
                                unwrap_org_key(org_key_enc, &private_der).ok()
                            }
                            Err(_) => None,
                        };
                        if let Some(ok) = ok {
                            org_keys.insert(org.id.clone(), ok);
                        }
                    }
                }
            }
        }
    }

    let folders = sync
        .folders
        .iter()
        .filter_map(|f| decrypt_folder(f, user_key).ok())
        .collect();

    let organizations = sync
        .profile
        .as_ref()
        .map(|p| {
            p.organizations
                .iter()
                .map(|o| DecryptedOrganization {
                    id: o.id.clone(),
                    name: o.name.clone().unwrap_or_else(|| o.id.clone()),
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let collections = sync
        .collections
        .iter()
        .filter_map(|c| decrypt_collection(c, user_key, &org_keys).ok())
        .collect();

    let mut raw_sends = HashMap::new();
    let mut sends = Vec::with_capacity(sync.sends.len());
    for s in &sync.sends {
        if let Some(id) = s.id.clone() {
            raw_sends.insert(id, s.clone());
        }
        if let Ok(send) = decrypt_send(s, user_key) {
            sends.push(send);
        }
    }

    let mut raw_ciphers = HashMap::new();
    let mut items = Vec::with_capacity(sync.ciphers.len());
    for c in &sync.ciphers {
        if let Some(id) = c.id.clone() {
            raw_ciphers.insert(id, c.clone());
        }
        match decrypt_cipher(c, user_key, &org_keys) {
            Ok(item) => items.push(item),
            Err(_) => items.push(placeholder_item(c)),
        }
    }

    Ok(VaultIndex {
        folders,
        items,
        organizations,
        collections,
        sends,
        org_keys,
        raw_ciphers,
        raw_sends,
    })
}

fn empty_item_base(c: &Cipher) -> DecryptedItem {
    DecryptedItem {
        id: c.id.clone().unwrap_or_default(),
        name: String::new(),
        item_type: ItemType::from_u8(c.cipher_type),
        folder_id: c.folder_id.clone(),
        organization_id: c.organization_id.clone(),
        collection_ids: c.collection_ids.clone().unwrap_or_default(),
        favorite: c.favorite,
        deleted: c.deleted_date.is_some(),
        reprompt: c.reprompt.unwrap_or(0) != 0,
        notes: None,
        username: None,
        password: None,
        totp: None,
        uris: Vec::new(),
        custom_fields: Vec::new(),
        password_history: Vec::new(),
        password_revision_date: None,
        creation_date: c.creation_date.clone(),
        revision_date: c.revision_date.clone(),
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
        has_item_key: c.key.is_some(),
    }
}

fn placeholder_item(c: &Cipher) -> DecryptedItem {
    let mut item = empty_item_base(c);
    item.name = "[cannot decrypt]".into();
    item
}

fn decrypt_collection(
    collection: &Collection,
    user_key: &UserKey,
    org_keys: &HashMap<String, SymmetricCryptoKey>,
) -> Result<DecryptedCollection> {
    let id = collection.id.clone().unwrap_or_default();
    let key = if let Some(org_id) = &collection.organization_id {
        org_keys
            .get(org_id)
            .cloned()
            .unwrap_or_else(|| user_key.clone())
    } else {
        user_key.clone()
    };
    let name = decrypt_with_key(&collection.name, &key).unwrap_or_else(|_| collection.name.clone());
    Ok(DecryptedCollection {
        id,
        name,
        organization_id: collection.organization_id.clone(),
    })
}

fn decrypt_send(send: &Send, user_key: &UserKey) -> Result<DecryptedSend> {
    let id = send.id.clone().unwrap_or_default();
    let key_material = send
        .key
        .as_deref()
        .and_then(|k| unwrap_send_key_material(k, user_key).ok());
    let name = match key_material {
        Some(km) => send
            .name
            .as_ref()
            .and_then(|n| crate::send_crypto::decrypt_send_meta_field(&km, n).ok())
            .unwrap_or_else(|| "[send]".into()),
        None => send.name.clone().unwrap_or_else(|| "Send".into()),
    };
    let notes = match key_material {
        Some(km) => send
            .notes
            .as_ref()
            .and_then(|n| crate::send_crypto::decrypt_send_meta_field(&km, n).ok()),
        None => send.notes.clone(),
    };
    let text = send.text.as_ref().and_then(|t| {
        t.text.as_ref().and_then(|enc| match key_material {
            Some(km) => crate::send_crypto::decrypt_send_text_field(&km, enc).ok(),
            None => Some(enc.clone()),
        })
    });
    Ok(DecryptedSend {
        id,
        access_id: send.access_id.clone(),
        name,
        notes,
        text,
        send_type: send.send_type,
        disabled: send.disabled,
        deletion_date: send.deletion_date.clone(),
    })
}

/// Decrypt the server-stored Send.key EncString into 16-byte key material.
pub fn unwrap_send_key_material(encrypted_key: &str, user_key: &UserKey) -> Result<[u8; 16]> {
    let bytes = decrypt_bytes(encrypted_key, user_key)?;
    if bytes.len() == 16 {
        let mut out = [0u8; 16];
        out.copy_from_slice(&bytes);
        return Ok(out);
    }
    // Legacy: some builds stored URL-safe base64 of raw material in `key`.
    if let Ok(s) = std::str::from_utf8(&bytes) {
        if let Ok(km) = crate::send_crypto::decode_send_key_material(s.trim()) {
            return Ok(km);
        }
    }
    crate::send_crypto::decode_send_key_material(encrypted_key)
}

fn decrypt_folder(folder: &Folder, key: &UserKey) -> Result<DecryptedFolder> {
    let id = folder.id.clone().unwrap_or_default();
    let name = decrypt_with_key(&folder.name, key).unwrap_or_else(|_| folder.name.clone());
    Ok(DecryptedFolder { id, name })
}

fn opt_decrypt(enc: &Option<String>, key: &SymmetricCryptoKey) -> Option<String> {
    enc.as_ref()
        .filter(|s| !s.is_empty())
        .and_then(|s| decrypt_with_key(s, key).ok())
}

pub fn resolve_cipher_key(
    cipher: &Cipher,
    user_key: &UserKey,
    org_keys: &HashMap<String, SymmetricCryptoKey>,
) -> Result<SymmetricCryptoKey> {
    let base = if let Some(org_id) = &cipher.organization_id {
        org_keys
            .get(org_id)
            .cloned()
            .ok_or_else(|| crate::error::SessionError::Other("missing org key".into()))?
    } else {
        user_key.clone()
    };

    if let Some(ck) = &cipher.key {
        if let Ok(raw) = decrypt_bytes(ck, &base) {
            if let Ok(sk) = SymmetricCryptoKey::from_bytes(&raw) {
                return Ok(sk);
            }
        }
    }
    Ok(base)
}

pub fn decrypt_cipher(
    cipher: &Cipher,
    user_key: &UserKey,
    org_keys: &HashMap<String, SymmetricCryptoKey>,
) -> Result<DecryptedItem> {
    let key = resolve_cipher_key(cipher, user_key, org_keys)?;

    let mut item = empty_item_base(cipher);
    item.name = decrypt_with_key(&cipher.name, &key).unwrap_or_else(|_| "[decrypt error]".into());
    item.notes = opt_decrypt(&cipher.notes, &key);

    if let Some(login) = &cipher.login {
        item.username = opt_decrypt(&login.username, &key);
        item.password = opt_decrypt(&login.password, &key);
        item.totp = opt_decrypt(&login.totp, &key);
        item.password_revision_date = login.password_revision_date.clone();
        if let Some(uris) = &login.uris {
            for u in uris {
                if let Some(uri) = opt_decrypt(&u.uri, &key) {
                    item.uris.push(DecryptedUri {
                        uri,
                        match_type: u.match_type,
                    });
                }
            }
        }
    }
    if let Some(card) = &cipher.card {
        item.cardholder_name = opt_decrypt(&card.cardholder_name, &key);
        item.card_brand = opt_decrypt(&card.brand, &key);
        item.card_number = opt_decrypt(&card.number, &key);
        item.card_exp_month = opt_decrypt(&card.exp_month, &key);
        item.card_exp_year = opt_decrypt(&card.exp_year, &key);
        item.card_code = opt_decrypt(&card.code, &key);
    }
    if let Some(ident) = &cipher.identity {
        item.identity_title = opt_decrypt(&ident.title, &key);
        item.identity_first_name = opt_decrypt(&ident.first_name, &key);
        item.identity_middle_name = opt_decrypt(&ident.middle_name, &key);
        item.identity_last_name = opt_decrypt(&ident.last_name, &key);
        item.identity_address1 = opt_decrypt(&ident.address1, &key);
        item.identity_address2 = opt_decrypt(&ident.address2, &key);
        item.identity_address3 = opt_decrypt(&ident.address3, &key);
        item.identity_city = opt_decrypt(&ident.city, &key);
        item.identity_state = opt_decrypt(&ident.state, &key);
        item.identity_postal_code = opt_decrypt(&ident.postal_code, &key);
        item.identity_country = opt_decrypt(&ident.country, &key);
        item.identity_company = opt_decrypt(&ident.company, &key);
        item.identity_email = opt_decrypt(&ident.email, &key);
        item.identity_phone = opt_decrypt(&ident.phone, &key);
        item.identity_ssn = opt_decrypt(&ident.ssn, &key);
        item.identity_username = opt_decrypt(&ident.username, &key);
        item.identity_passport_number = opt_decrypt(&ident.passport_number, &key);
        item.identity_license_number = opt_decrypt(&ident.license_number, &key);
    }
    if let Some(ssh) = &cipher.ssh_key {
        item.ssh_private_key = opt_decrypt(&ssh.private_key, &key);
        item.ssh_public_key = opt_decrypt(&ssh.public_key, &key);
        item.ssh_fingerprint = opt_decrypt(&ssh.key_fingerprint, &key);
    }

    if let Some(fields) = &cipher.fields {
        for f in fields {
            let name = opt_decrypt(&f.name, &key).unwrap_or_default();
            let value = opt_decrypt(&f.value, &key).unwrap_or_default();
            item.custom_fields.push(DecryptedField {
                name,
                value,
                field_type: DecryptedFieldType::from_u8(f.field_type),
                linked_id: f.linked_id,
            });
        }
    }

    if let Some(history) = &cipher.password_history {
        for h in history {
            if let Ok(password) = decrypt_with_key(&h.password, &key) {
                item.password_history.push(DecryptedPasswordHistory {
                    password,
                    last_used_date: h.last_used_date.clone(),
                });
            }
        }
    }

    Ok(item)
}
