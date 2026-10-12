use std::collections::HashMap;

use vault_api::{Cipher, Folder, SyncResponse};
use vault_crypto::{
    decrypt_bytes, decrypt_private_key, decrypt_with_key, unwrap_org_key,
    unwrap_org_key_with_user, CryptoError, SymmetricCryptoKey, UserKey,
};

use crate::error::Result;
use crate::models::{DecryptedFolder, DecryptedItem, ItemType, VaultIndex};

pub fn build_index(sync: &SyncResponse, user_key: &UserKey) -> Result<VaultIndex> {
    let mut org_keys = HashMap::new();
    if let Some(profile) = &sync.profile {
        if let Some(private_enc) = &profile.private_key {
            if let Ok(private_der) = decrypt_private_key(private_enc, user_key) {
                for org in &profile.organizations {
                    if let Some(org_key_enc) = &org.key {
                        // Prefer HMAC-verified unwrap for types 5/6; fall back without
                        // MAC for legacy Vaultwarden payloads (non-32-byte MAC).
                        let ok = match unwrap_org_key_with_user(
                            org_key_enc,
                            &private_der,
                            Some(user_key),
                        ) {
                            Ok(k) => Some(k),
                            // Legacy org keys may carry a non-32-byte MAC; skip verify.
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

    let mut raw_ciphers = HashMap::new();
    let mut items = Vec::with_capacity(sync.ciphers.len());
    for c in &sync.ciphers {
        if let Some(id) = c.id.clone() {
            raw_ciphers.insert(id, c.clone());
        }
        match decrypt_cipher(c, user_key, &org_keys) {
            Ok(item) => items.push(item),
            Err(_) => {
                // Keep a placeholder so the item remains visible (e.g. missing org key).
                items.push(DecryptedItem {
                    id: c.id.clone().unwrap_or_default(),
                    name: "[cannot decrypt]".into(),
                    item_type: ItemType::from_u8(c.cipher_type),
                    folder_id: c.folder_id.clone(),
                    organization_id: c.organization_id.clone(),
                    favorite: c.favorite,
                    deleted: c.deleted_date.is_some(),
                    reprompt: c.reprompt.unwrap_or(0) != 0,
                    notes: None,
                    username: None,
                    password: None,
                    totp: None,
                    uris: Vec::new(),
                    cardholder_name: None,
                    card_brand: None,
                    card_number: None,
                    card_exp_month: None,
                    card_exp_year: None,
                    card_code: None,
                    identity_title: None,
                    identity_first_name: None,
                    identity_last_name: None,
                    identity_email: None,
                    identity_phone: None,
                    identity_username: None,
                    ssh_private_key: None,
                    ssh_public_key: None,
                    ssh_fingerprint: None,
                    revision_date: c.revision_date.clone(),
                    has_item_key: c.key.is_some(),
                });
            }
        }
    }

    Ok(VaultIndex {
        folders,
        items,
        org_keys,
        raw_ciphers,
    })
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

fn resolve_key(
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
    let key = resolve_key(cipher, user_key, org_keys)?;

    let name = decrypt_with_key(&cipher.name, &key).unwrap_or_else(|_| "[decrypt error]".into());
    let notes = opt_decrypt(&cipher.notes, &key);

    let mut item = DecryptedItem {
        id: cipher.id.clone().unwrap_or_default(),
        name,
        item_type: ItemType::from_u8(cipher.cipher_type),
        folder_id: cipher.folder_id.clone(),
        organization_id: cipher.organization_id.clone(),
        favorite: cipher.favorite,
        deleted: cipher.deleted_date.is_some(),
        reprompt: cipher.reprompt.unwrap_or(0) != 0,
        notes,
        username: None,
        password: None,
        totp: None,
        uris: Vec::new(),
        cardholder_name: None,
        card_brand: None,
        card_number: None,
        card_exp_month: None,
        card_exp_year: None,
        card_code: None,
        identity_title: None,
        identity_first_name: None,
        identity_last_name: None,
        identity_email: None,
        identity_phone: None,
        identity_username: None,
        ssh_private_key: None,
        ssh_public_key: None,
        ssh_fingerprint: None,
        revision_date: cipher.revision_date.clone(),
        has_item_key: cipher.key.is_some(),
    };

    if let Some(login) = &cipher.login {
        item.username = opt_decrypt(&login.username, &key);
        item.password = opt_decrypt(&login.password, &key);
        item.totp = opt_decrypt(&login.totp, &key);
        if let Some(uris) = &login.uris {
            item.uris = uris
                .iter()
                .filter_map(|u| opt_decrypt(&u.uri, &key))
                .collect();
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
        item.identity_last_name = opt_decrypt(&ident.last_name, &key);
        item.identity_email = opt_decrypt(&ident.email, &key);
        item.identity_phone = opt_decrypt(&ident.phone, &key);
        item.identity_username = opt_decrypt(&ident.username, &key);
    }
    if let Some(ssh) = &cipher.ssh_key {
        item.ssh_private_key = opt_decrypt(&ssh.private_key, &key);
        item.ssh_public_key = opt_decrypt(&ssh.public_key, &key);
        item.ssh_fingerprint = opt_decrypt(&ssh.key_fingerprint, &key);
    }

    Ok(item)
}
