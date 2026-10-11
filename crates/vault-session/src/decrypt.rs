use std::collections::HashMap;

use vault_api::{Cipher, Folder, SyncResponse};
use vault_crypto::{
    decrypt_bytes, decrypt_private_key, decrypt_with_key, unwrap_org_key, SymmetricCryptoKey,
    UserKey,
};

use crate::error::{Result, SessionError};
use crate::models::{DecryptedFolder, DecryptedItem, ItemType, VaultIndex};

pub fn build_index(sync: &SyncResponse, user_key: &UserKey) -> Result<VaultIndex> {
    let mut org_keys = HashMap::new();
    if let Some(profile) = &sync.profile {
        if let Some(private_enc) = &profile.private_key {
            if let Ok(private_der) = decrypt_private_key(private_enc, user_key) {
                for org in &profile.organizations {
                    if let Some(org_key_enc) = &org.key {
                        if let Ok(ok) = unwrap_org_key(org_key_enc, &private_der) {
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

    let items = sync
        .ciphers
        .iter()
        .filter_map(|c| decrypt_cipher(c, user_key, &org_keys).ok())
        .collect();

    Ok(VaultIndex {
        folders,
        items,
        org_keys,
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
            .ok_or_else(|| SessionError::Other("missing org key".into()))?
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
        revision_date: cipher.revision_date.clone(),
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

    Ok(item)
}
