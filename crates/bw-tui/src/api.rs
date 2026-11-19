//! Transport-agnostic vault operations expressed as `method + JSON params -> JSON`.
//!
//! The same dispatcher backs the unlock daemon ([`crate::agent`]), the REST server
//! ([`crate::serve`]) and the one-shot CLI commands, so every front-end shares one
//! implementation. Item JSON follows the official `bw` CLI shape where practical
//! (`object`, `type`, `login.uris[].match`, `fields[]`, ...).

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use serde_json::{json, Map, Value};
use vault_session::{
    item_matches_uri_decrypted, CardDraft, DecryptedItem, DecryptedUri, IdentityDraft, ItemType,
    LoginDraft, NoteDraft, Session, SessionStatus, SshKeyDraft,
};

use crate::cli::{generate_value, GenerateOpts};

fn opt_str(v: &Value, pointer: &str) -> Option<String> {
    v.pointer(pointer)
        .and_then(Value::as_str)
        .map(str::to_string)
        .filter(|s| !s.is_empty())
}

fn p_str(params: &Value, key: &str) -> Option<String> {
    match params.get(key) {
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        Some(Value::Number(n)) => Some(n.to_string()),
        Some(Value::Bool(b)) => Some(b.to_string()),
        _ => None,
    }
}

fn p_bool(params: &Value, key: &str) -> bool {
    match params.get(key) {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => !matches!(s.as_str(), "" | "0" | "false" | "no"),
        Some(Value::Number(n)) => n.as_i64().unwrap_or(0) != 0,
        _ => false,
    }
}

fn p_req(params: &Value, key: &str) -> Result<String> {
    p_str(params, key).ok_or_else(|| anyhow!("missing parameter `{key}`"))
}

// ---------------------------------------------------------------------------
// JSON shapes
// ---------------------------------------------------------------------------

/// Decrypted item in `bw` JSON format.
pub fn item_json(i: &DecryptedItem) -> Value {
    let mut o = Map::new();
    o.insert("object".into(), "item".into());
    o.insert("id".into(), i.id.clone().into());
    o.insert("organizationId".into(), json!(i.organization_id));
    o.insert("folderId".into(), json!(i.folder_id));
    o.insert("type".into(), json!(i.item_type.as_u8().unwrap_or(0)));
    o.insert("reprompt".into(), json!(u8::from(i.reprompt)));
    o.insert("name".into(), i.name.clone().into());
    o.insert("notes".into(), json!(i.notes));
    o.insert("favorite".into(), i.favorite.into());
    o.insert("collectionIds".into(), json!(i.collection_ids));
    o.insert("revisionDate".into(), json!(i.revision_date));
    o.insert("creationDate".into(), json!(i.creation_date));
    o.insert(
        "deletedDate".into(),
        if i.deleted {
            json!(i.revision_date)
        } else {
            Value::Null
        },
    );
    if !i.custom_fields.is_empty() {
        let fields: Vec<Value> = i
            .custom_fields
            .iter()
            .map(|f| {
                json!({
                    "name": f.name,
                    "value": f.value,
                    "type": f.field_type.as_u8(),
                    "linkedId": f.linked_id,
                })
            })
            .collect();
        o.insert("fields".into(), Value::Array(fields));
    }
    match i.item_type {
        ItemType::Login => {
            let uris: Vec<Value> = i
                .uris
                .iter()
                .map(|u| json!({ "match": u.match_type, "uri": u.uri }))
                .collect();
            o.insert(
                "login".into(),
                json!({
                    "username": i.username,
                    "password": i.password,
                    "totp": i.totp,
                    "uris": uris,
                    "passwordRevisionDate": i.password_revision_date,
                }),
            );
        }
        ItemType::SecureNote => {
            o.insert("secureNote".into(), json!({ "type": 0 }));
        }
        ItemType::Card => {
            o.insert(
                "card".into(),
                json!({
                    "cardholderName": i.cardholder_name,
                    "brand": i.card_brand,
                    "number": i.card_number,
                    "expMonth": i.card_exp_month,
                    "expYear": i.card_exp_year,
                    "code": i.card_code,
                }),
            );
        }
        ItemType::Identity => {
            o.insert(
                "identity".into(),
                json!({
                    "title": i.identity_title,
                    "firstName": i.identity_first_name,
                    "middleName": i.identity_middle_name,
                    "lastName": i.identity_last_name,
                    "address1": i.identity_address1,
                    "address2": i.identity_address2,
                    "address3": i.identity_address3,
                    "city": i.identity_city,
                    "state": i.identity_state,
                    "postalCode": i.identity_postal_code,
                    "country": i.identity_country,
                    "company": i.identity_company,
                    "email": i.identity_email,
                    "phone": i.identity_phone,
                    "ssn": i.identity_ssn,
                    "username": i.identity_username,
                    "passportNumber": i.identity_passport_number,
                    "licenseNumber": i.identity_license_number,
                }),
            );
        }
        ItemType::SshKey => {
            o.insert(
                "sshKey".into(),
                json!({
                    "privateKey": i.ssh_private_key,
                    "publicKey": i.ssh_public_key,
                    "keyFingerprint": i.ssh_fingerprint,
                }),
            );
        }
        ItemType::Unknown => {}
    }
    Value::Object(o)
}

pub fn folder_json(id: &str, name: &str) -> Value {
    json!({ "object": "folder", "id": id, "name": name })
}

fn send_json(s: &vault_session::DecryptedSend) -> Value {
    json!({
        "object": "send",
        "id": s.id,
        "accessId": s.access_id,
        "name": s.name,
        "notes": s.notes,
        "type": s.send_type,
        "text": s.text.as_ref().map(|t| json!({ "text": t })),
        "disabled": s.disabled,
        "deletionDate": s.deletion_date,
    })
}

/// Recursively merge `patch` into `base` (objects merge, everything else replaces).
pub fn deep_merge(base: &mut Value, patch: &Value) {
    match (base, patch) {
        (Value::Object(b), Value::Object(p)) => {
            for (k, v) in p {
                match b.get_mut(k) {
                    Some(existing) if existing.is_object() && v.is_object() => {
                        deep_merge(existing, v)
                    }
                    _ => {
                        b.insert(k.clone(), v.clone());
                    }
                }
            }
        }
        (b, p) => *b = p.clone(),
    }
}

/// Parse `bw`-style item input: raw JSON, or base64 (standard / url-safe) encoded JSON.
pub fn parse_item_input(raw: &str) -> Result<Value> {
    let raw = raw.trim();
    if raw.starts_with('{') {
        return serde_json::from_str(raw).context("invalid item JSON");
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(raw)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(raw))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(raw))
        .context("input is neither JSON nor base64 (see `encode`)")?;
    serde_json::from_slice(&bytes).context("decoded input is not valid JSON")
}

// ---------------------------------------------------------------------------
// Lookups
// ---------------------------------------------------------------------------

pub fn resolve_item<'a>(session: &'a Session, query: &str) -> Result<&'a DecryptedItem> {
    if let Some(exact) = session.items().iter().find(|i| i.id == query) {
        return Ok(exact);
    }
    let q = query.to_lowercase();
    let live: Vec<_> = session.items().iter().filter(|i| !i.deleted).collect();
    let exact: Vec<_> = live
        .iter()
        .copied()
        .filter(|i| i.name.eq_ignore_ascii_case(query))
        .collect();
    let matches = if exact.len() == 1 {
        exact
    } else {
        live.into_iter()
            .filter(|i| i.name.to_lowercase().contains(&q))
            .collect()
    };
    match matches.as_slice() {
        [] => bail!("item not found: {query}"),
        [one] => Ok(*one),
        many => {
            let names: Vec<_> = many
                .iter()
                .map(|i| format!("{} ({})", i.name, i.id))
                .collect();
            bail!(
                "ambiguous match for `{query}` — candidates:\n  {}",
                names.join("\n  ")
            );
        }
    }
}

/// Folder id from id or (case-insensitive) name. `null` / `none` / empty → `None`.
pub fn resolve_folder_id(session: &Session, query: &str) -> Result<Option<String>> {
    let q = query.trim();
    if q.is_empty() || q.eq_ignore_ascii_case("null") || q.eq_ignore_ascii_case("none") {
        return Ok(None);
    }
    session
        .folders()
        .iter()
        .find(|f| f.id == q || f.name.eq_ignore_ascii_case(q))
        .map(|f| Some(f.id.clone()))
        .ok_or_else(|| anyhow!("folder not found: {q}"))
}

fn resolve_folder<'a>(
    session: &'a Session,
    query: &str,
) -> Result<&'a vault_session::DecryptedFolder> {
    session
        .folders()
        .iter()
        .find(|f| f.id == query || f.name.eq_ignore_ascii_case(query))
        .ok_or_else(|| anyhow!("folder not found: {query}"))
}

fn resolve_collection<'a>(
    session: &'a Session,
    query: &str,
) -> Result<&'a vault_session::DecryptedCollection> {
    session
        .collections()
        .iter()
        .find(|c| c.id == query || c.name.eq_ignore_ascii_case(query))
        .ok_or_else(|| anyhow!("collection not found: {query}"))
}

fn resolve_org<'a>(
    session: &'a Session,
    query: &str,
) -> Result<&'a vault_session::DecryptedOrganization> {
    session
        .organizations()
        .iter()
        .find(|o| o.id == query || o.name.eq_ignore_ascii_case(query))
        .ok_or_else(|| anyhow!("organization not found: {query}"))
}

/// Scalar field of an item (`password`, `username`, `totp`, `uri`, `name`, `notes`, `custom:<n>`).
pub fn item_field(item: &DecryptedItem, field: &str) -> Result<Option<String>> {
    Ok(match field {
        "password" => item.password.clone(),
        "username" => item.username.clone(),
        "totp" => item
            .totp
            .as_deref()
            .and_then(|s| vault_session::totp_from_secret(s).ok()),
        "uri" => item.primary_uri().map(str::to_string),
        "name" => Some(item.name.clone()),
        "notes" => item.notes.clone(),
        "id" => Some(item.id.clone()),
        custom if custom.starts_with("custom:") => {
            let name = custom.trim_start_matches("custom:");
            item.custom_fields
                .iter()
                .find(|f| f.name.eq_ignore_ascii_case(name))
                .map(|f| f.value.clone())
        }
        other => {
            bail!("unknown field `{other}` (password|username|totp|uri|name|notes|custom:<name>)")
        }
    })
}

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

pub fn template_json(kind: &str) -> Result<Value> {
    let login = json!({
        "uris": [{ "match": null, "uri": "" }],
        "username": "", "password": "", "totp": ""
    });
    Ok(match kind {
        "item" => json!({
            "organizationId": null, "collectionIds": null, "folderId": null,
            "type": 1, "name": "Item name", "notes": "Some notes about this item.",
            "favorite": false, "fields": [], "login": null, "secureNote": null,
            "card": null, "identity": null, "reprompt": 0
        }),
        "item.field" => json!({ "name": "Field name", "value": "Some value", "type": 0 }),
        "item.login" => login,
        "item.login.uri" => json!({ "match": null, "uri": "" }),
        "item.card" => json!({
            "cardholderName": "John Doe", "brand": "visa", "number": "4242424242424242",
            "expMonth": "04", "expYear": "2023", "code": "123"
        }),
        "item.identity" => json!({
            "title": "Mr", "firstName": "John", "middleName": "William", "lastName": "Doe",
            "address1": "123 Main St", "address2": null, "address3": null,
            "city": "New York", "state": "NY", "postalCode": "10001", "country": "US",
            "company": "Acme", "email": "john@example.com", "phone": "5555551234",
            "ssn": "000-00-0000", "username": "jdoe", "passportNumber": "", "licenseNumber": ""
        }),
        "item.securenote" => json!({ "type": 0 }),
        "item.sshkey" => json!({ "privateKey": "", "publicKey": "", "keyFingerprint": "" }),
        "folder" => json!({ "name": "Folder name" }),
        "send.text" => json!({
            "type": 0, "name": "Send name", "notes": null,
            "text": { "text": "Some text", "hidden": false }
        }),
        other => bail!(
            "unknown template `{other}` (item|item.field|item.login|item.login.uri|item.card|\
             item.identity|item.securenote|item.sshkey|folder|send.text)"
        ),
    })
}

// ---------------------------------------------------------------------------
// Drafts from JSON
// ---------------------------------------------------------------------------

#[allow(clippy::large_enum_variant)]
enum AnyDraft {
    Login(LoginDraft),
    Note(NoteDraft),
    Card(CardDraft),
    Identity(IdentityDraft),
    Ssh(SshKeyDraft),
}

fn item_type_of(v: &Value) -> Result<ItemType> {
    match v.get("type") {
        Some(Value::Number(n)) => Ok(ItemType::from_u8(n.as_u64().unwrap_or(0) as u8)),
        Some(Value::String(s)) => Ok(match s.to_lowercase().as_str() {
            "login" | "1" => ItemType::Login,
            "note" | "securenote" | "2" => ItemType::SecureNote,
            "card" | "3" => ItemType::Card,
            "identity" | "4" => ItemType::Identity,
            "sshkey" | "ssh" | "5" => ItemType::SshKey,
            _ => ItemType::Unknown,
        }),
        _ => bail!("item JSON is missing `type`"),
    }
}

fn draft_from_json(v: &Value) -> Result<AnyDraft> {
    let ty = item_type_of(v)?;
    let name = opt_str(v, "/name").ok_or_else(|| anyhow!("item JSON is missing `name`"))?;
    let notes = opt_str(v, "/notes");
    let folder_id = opt_str(v, "/folderId");
    let favorite = v.get("favorite").and_then(Value::as_bool).unwrap_or(false);
    let reprompt = v.get("reprompt").and_then(Value::as_u64).unwrap_or(0) != 0;
    Ok(match ty {
        ItemType::Login => {
            let uris = v
                .pointer("/login/uris")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|u| {
                            Some(DecryptedUri {
                                uri: u.get("uri")?.as_str()?.to_string(),
                                match_type: u
                                    .get("match")
                                    .and_then(Value::as_i64)
                                    .map(|m| m as i32),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();
            AnyDraft::Login(LoginDraft {
                name,
                username: opt_str(v, "/login/username"),
                password: opt_str(v, "/login/password"),
                totp: opt_str(v, "/login/totp"),
                uris,
                notes,
                folder_id,
                favorite,
                reprompt,
            })
        }
        ItemType::SecureNote => AnyDraft::Note(NoteDraft {
            name,
            notes,
            folder_id,
            favorite,
        }),
        ItemType::Card => AnyDraft::Card(CardDraft {
            name,
            cardholder_name: opt_str(v, "/card/cardholderName"),
            brand: opt_str(v, "/card/brand"),
            number: opt_str(v, "/card/number"),
            exp_month: opt_str(v, "/card/expMonth"),
            exp_year: opt_str(v, "/card/expYear"),
            code: opt_str(v, "/card/code"),
            notes,
            folder_id,
            favorite,
            reprompt,
        }),
        ItemType::Identity => AnyDraft::Identity(IdentityDraft {
            name,
            title: opt_str(v, "/identity/title"),
            first_name: opt_str(v, "/identity/firstName"),
            middle_name: opt_str(v, "/identity/middleName"),
            last_name: opt_str(v, "/identity/lastName"),
            address1: opt_str(v, "/identity/address1"),
            address2: opt_str(v, "/identity/address2"),
            address3: opt_str(v, "/identity/address3"),
            city: opt_str(v, "/identity/city"),
            state: opt_str(v, "/identity/state"),
            postal_code: opt_str(v, "/identity/postalCode"),
            country: opt_str(v, "/identity/country"),
            company: opt_str(v, "/identity/company"),
            email: opt_str(v, "/identity/email"),
            phone: opt_str(v, "/identity/phone"),
            ssn: opt_str(v, "/identity/ssn"),
            username: opt_str(v, "/identity/username"),
            passport_number: opt_str(v, "/identity/passportNumber"),
            license_number: opt_str(v, "/identity/licenseNumber"),
            notes,
            folder_id,
            favorite,
            reprompt,
        }),
        ItemType::SshKey => AnyDraft::Ssh(SshKeyDraft {
            name,
            private_key: opt_str(v, "/sshKey/privateKey"),
            public_key: opt_str(v, "/sshKey/publicKey"),
            fingerprint: opt_str(v, "/sshKey/keyFingerprint"),
            notes,
            folder_id,
            favorite,
        }),
        ItemType::Unknown => bail!("unsupported item type"),
    })
}

async fn create_from_draft(session: &mut Session, draft: &AnyDraft) -> Result<String> {
    Ok(match draft {
        AnyDraft::Login(d) => session.create_login(d).await?,
        AnyDraft::Note(d) => session.create_note(d).await?,
        AnyDraft::Card(d) => session.create_card(d).await?,
        AnyDraft::Identity(d) => session.create_identity(d).await?,
        AnyDraft::Ssh(d) => session.create_ssh_key(d).await?,
    })
}

async fn update_from_draft(session: &mut Session, id: &str, draft: &AnyDraft) -> Result<()> {
    match draft {
        AnyDraft::Login(d) => session.update_login(id, d).await?,
        AnyDraft::Note(d) => session.update_note(id, d).await?,
        AnyDraft::Card(d) => session.update_card(id, d).await?,
        AnyDraft::Identity(d) => session.update_identity(id, d).await?,
        AnyDraft::Ssh(d) => session.update_ssh_key(id, d).await?,
    }
    Ok(())
}

fn id_list(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

pub fn status_json(session: &Session) -> Value {
    let status = match session.status() {
        SessionStatus::Unlocked => "unlocked",
        SessionStatus::Locked => "locked",
        _ => "unauthenticated",
    };
    json!({
        "serverUrl": session.server_url(),
        "lastSync": session.last_synced_at().map(|d| d.to_rfc3339()),
        "userEmail": session.email(),
        "status": status,
        "offline": session.is_offline(),
    })
}

fn list_items(session: &Session, params: &Value) -> Result<Value> {
    let folder_id = match p_str(params, "folder") {
        Some(f) => resolve_folder_id(session, &f)?,
        None => None,
    };
    let folder_filter = p_str(params, "folder").is_some();
    let type_filter = p_str(params, "type").map(|t| t.to_lowercase());
    let search = p_str(params, "search").map(|s| s.to_lowercase());
    let collection = p_str(params, "collection");
    let org = p_str(params, "organization");
    let trash = p_bool(params, "trash");
    let url = p_str(params, "url");
    let groups = if url.is_some() {
        session.uri_equivalent_groups()
    } else {
        Vec::new()
    };

    let mut rows = Vec::new();
    for item in session.items() {
        if item.deleted != trash {
            continue;
        }
        if folder_filter && item.folder_id != folder_id {
            continue;
        }
        if let Some(c) = &collection {
            if !item.collection_ids.iter().any(|x| x == c) {
                continue;
            }
        }
        if let Some(o) = &org {
            if item.organization_id.as_deref() != Some(o.as_str()) {
                continue;
            }
        }
        if let Some(t) = &type_filter {
            let numeric = item.item_type.as_u8().map(|n| n.to_string());
            let ok = item.item_type.label().eq_ignore_ascii_case(t)
                || format!("{:?}", item.item_type).to_lowercase() == *t
                || numeric.as_deref() == Some(t.as_str());
            if !ok {
                continue;
            }
        }
        if let Some(u) = &url {
            if !item_matches_uri_decrypted(&item.uris, u, &groups) {
                continue;
            }
        }
        if let Some(q) = &search {
            let hay = format!(
                "{} {} {} {}",
                item.name,
                item.username.as_deref().unwrap_or(""),
                item.notes.as_deref().unwrap_or(""),
                item.uris
                    .iter()
                    .map(|u| u.uri.as_str())
                    .collect::<Vec<_>>()
                    .join(" ")
            )
            .to_lowercase();
            if !hay.contains(q) {
                continue;
            }
        }
        rows.push(item_json(item));
    }
    Ok(Value::Array(rows))
}

fn do_list(session: &Session, params: &Value) -> Result<Value> {
    let object = p_str(params, "object").unwrap_or_else(|| "items".into());
    match object.as_str() {
        "items" => list_items(session, params),
        "folders" => {
            let search = p_str(params, "search").map(|s| s.to_lowercase());
            Ok(Value::Array(
                session
                    .folders()
                    .iter()
                    .filter(|f| {
                        search
                            .as_ref()
                            .is_none_or(|q| f.name.to_lowercase().contains(q))
                    })
                    .map(|f| folder_json(&f.id, &f.name))
                    .collect(),
            ))
        }
        "collections" | "org-collections" => {
            let org = p_str(params, "organization");
            Ok(Value::Array(
                session
                    .collections()
                    .iter()
                    .filter(|c| {
                        org.as_ref()
                            .is_none_or(|o| c.organization_id.as_deref() == Some(o.as_str()))
                    })
                    .map(|c| {
                        json!({
                            "object": "collection", "id": c.id,
                            "organizationId": c.organization_id, "name": c.name
                        })
                    })
                    .collect(),
            ))
        }
        "organizations" => Ok(Value::Array(
            session
                .organizations()
                .iter()
                .map(|o| json!({ "object": "organization", "id": o.id, "name": o.name }))
                .collect(),
        )),
        "sends" => Ok(Value::Array(
            session.sends().iter().map(send_json).collect(),
        )),
        other => {
            bail!("unknown list object `{other}` (items|folders|collections|organizations|sends)")
        }
    }
}

async fn do_get(session: &mut Session, params: &Value) -> Result<Value> {
    let what = p_str(params, "what").unwrap_or_else(|| "item".into());
    let query = p_str(params, "query");
    let uri = p_str(params, "uri");

    let find_item = |session: &Session| -> Result<DecryptedItem> {
        if let Some(target) = &uri {
            let groups = session.uri_equivalent_groups();
            return session
                .items()
                .iter()
                .find(|i| !i.deleted && item_matches_uri_decrypted(&i.uris, target, &groups))
                .cloned()
                .ok_or_else(|| anyhow!("no login matches uri `{target}`"));
        }
        let q = query
            .as_deref()
            .ok_or_else(|| anyhow!("provide an item id/name or --uri"))?;
        resolve_item(session, q).cloned()
    };

    match what.as_str() {
        "item" => Ok(item_json(&find_item(session)?)),
        "password" | "username" | "totp" | "uri" | "notes" | "name" => {
            let item = find_item(session)?;
            match item_field(&item, &what)? {
                Some(v) => Ok(Value::String(v)),
                None => bail!("field `{what}` empty on item"),
            }
        }
        f if f.starts_with("custom:") => {
            let item = find_item(session)?;
            match item_field(&item, f)? {
                Some(v) => Ok(Value::String(v)),
                None => bail!("field `{f}` empty on item"),
            }
        }
        "exposed" => {
            let item = find_item(session)?;
            let pw = item
                .password
                .as_deref()
                .ok_or_else(|| anyhow!("item has no password"))?;
            let n = vault_session::hibp_password_pwned_count(pw)
                .await
                .map_err(|e| anyhow!("HIBP lookup failed: {e}"))?;
            Ok(Value::String(if n == 0 {
                "Not exposed".to_string()
            } else {
                format!("Exposed {n} time(s) in data breaches")
            }))
        }
        "folder" => {
            let q = p_req(params, "query")?;
            let f = resolve_folder(session, &q)?;
            Ok(folder_json(&f.id, &f.name))
        }
        "collection" => {
            let q = p_req(params, "query")?;
            let c = resolve_collection(session, &q)?;
            Ok(json!({
                "object": "collection", "id": c.id,
                "organizationId": c.organization_id, "name": c.name
            }))
        }
        "organization" | "org" => {
            let q = p_req(params, "query")?;
            let o = resolve_org(session, &q)?;
            Ok(json!({ "object": "organization", "id": o.id, "name": o.name }))
        }
        "template" => template_json(&p_req(params, "query")?),
        "fingerprint" => Ok(Value::String(session.fingerprint_phrase()?)),
        "send" => {
            let q = p_req(params, "query")?;
            let s = session
                .sends()
                .iter()
                .find(|s| s.id == q || s.name.eq_ignore_ascii_case(&q))
                .ok_or_else(|| anyhow!("send not found: {q}"))?;
            Ok(send_json(s))
        }
        other => bail!(
            "unknown get target `{other}` (item|password|username|uri|totp|notes|exposed|folder|\
             collection|organization|template|fingerprint|send)"
        ),
    }
}

/// Run one operation against an unlocked session.
pub async fn dispatch(session: &mut Session, method: &str, params: &Value) -> Result<Value> {
    session.touch();
    match method {
        "status" => Ok(status_json(session)),
        "sync" => {
            session.sync().await.context("sync")?;
            Ok(json!({ "synced": session.items().len() }))
        }
        "list" => do_list(session, params),
        "get" => do_get(session, params).await,
        "generate" => {
            let g = |k: &str| p_bool(params, k);
            let num = |k: &str, d: usize| {
                p_str(params, k)
                    .and_then(|v| v.parse::<usize>().ok())
                    .unwrap_or(d)
            };
            // bw semantics: character classes are on unless explicitly set to 0/false.
            let off = |k: &str| params.get(k).is_some() && !g(k);
            let value = generate_value(GenerateOpts {
                length: num("length", 20).clamp(5, 128),
                passphrase: g("passphrase"),
                words: num("words", 4).clamp(3, 20),
                capitalize: g("capitalize"),
                include_number: g("includeNumber"),
                no_uppercase: off("uppercase"),
                no_lowercase: off("lowercase"),
                no_digits: off("number"),
                no_symbols: off("special"),
                avoid_ambiguous: g("avoidAmbiguous"),
                org_policy: Some(session.generator_policy()),
            })?;
            Ok(Value::String(value))
        }
        "item.create" => {
            let item = params
                .get("item")
                .ok_or_else(|| anyhow!("missing parameter `item`"))?;
            let mut draft_json = item.clone();
            if let Some(f) = opt_str(&draft_json, "/folderId") {
                let fid = resolve_folder_id(session, &f)?;
                draft_json["folderId"] = json!(fid);
            }
            let draft = draft_from_json(&draft_json)?;
            let id = create_from_draft(session, &draft).await?;
            // Org target: created as personal, then shared into the organization.
            if let Some(org) = opt_str(item, "/organizationId") {
                let cols = id_list(item.get("collectionIds"));
                session.share_item(&id, &org, &cols).await?;
            }
            let created = session
                .get_item(&id)
                .map(item_json)
                .unwrap_or_else(|| json!({ "id": id }));
            Ok(created)
        }
        "item.edit" => {
            let q = p_req(params, "query")?;
            let id = resolve_item(session, &q)?.id.clone();
            let mut merged = item_json(session.get_item(&id).ok_or_else(|| anyhow!("not found"))?);
            if let Some(patch) = params.get("item") {
                deep_merge(&mut merged, patch);
            }
            if let Some(f) = opt_str(&merged, "/folderId") {
                let fid = resolve_folder_id(session, &f)?;
                merged["folderId"] = json!(fid);
            }
            let draft = draft_from_json(&merged)?;
            update_from_draft(session, &id, &draft).await?;
            Ok(session
                .get_item(&id)
                .map(item_json)
                .unwrap_or_else(|| json!({ "id": id })))
        }
        "item.delete" => {
            let q = p_req(params, "query")?;
            let id = resolve_item(session, &q)?.id.clone();
            let permanent = p_bool(params, "permanent");
            if permanent {
                session.hard_delete(&id).await?;
            } else {
                session.soft_delete(&id).await?;
            }
            Ok(json!({ "deleted": id, "permanent": permanent }))
        }
        "item.restore" => {
            let q = p_req(params, "query")?;
            let item = session
                .items()
                .iter()
                .find(|i| i.id == q || i.name.eq_ignore_ascii_case(&q))
                .filter(|i| i.deleted)
                .ok_or_else(|| anyhow!("no deleted item matches `{q}`"))?;
            let id = item.id.clone();
            session.restore(&id).await?;
            Ok(json!({ "restored": id }))
        }
        "item.move" => {
            let q = p_req(params, "query")?;
            let id = resolve_item(session, &q)?.id.clone();
            let folder = p_str(params, "folder").unwrap_or_default();
            let fid = resolve_folder_id(session, &folder)?;
            session.move_to_folder(&id, fid.clone()).await?;
            Ok(json!({ "moved": id, "folderId": fid }))
        }
        "item.share" => {
            let q = p_req(params, "query")?;
            let id = resolve_item(session, &q)?.id.clone();
            let org = resolve_org(session, &p_req(params, "organization")?)?
                .id
                .clone();
            let mut cols = Vec::new();
            for c in id_list(params.get("collections")) {
                cols.push(resolve_collection(session, &c)?.id.clone());
            }
            session.share_item(&id, &org, &cols).await?;
            Ok(json!({ "shared": id, "organizationId": org, "collectionIds": cols }))
        }
        "folder.create" => {
            let name = p_req(params, "name")?;
            let id = session.create_folder(&name).await?;
            Ok(folder_json(&id, &name))
        }
        "folder.edit" => {
            let q = p_req(params, "query")?;
            let name = p_req(params, "name")?;
            let id = resolve_folder(session, &q)?.id.clone();
            session.rename_folder(&id, &name).await?;
            Ok(folder_json(&id, &name))
        }
        "folder.delete" => {
            let q = p_req(params, "query")?;
            let id = resolve_folder(session, &q)?.id.clone();
            session.delete_folder(&id).await?;
            Ok(json!({ "deleted": id }))
        }
        "send.create" => {
            let name = p_str(params, "name");
            let mut opts = vault_session::SendOptions {
                notes: p_str(params, "notes"),
                password: p_str(params, "password"),
                max_access_count: p_str(params, "maxAccess").and_then(|v| v.parse().ok()),
                hide_email: p_bool(params, "hideEmail"),
                hidden_text: p_bool(params, "hidden"),
                ..Default::default()
            };
            let now = chrono::Utc::now();
            if let Some(d) = p_str(params, "expires") {
                opts.expiration_date = Some(vault_session::parse_send_date(&d, now)?);
            }
            if let Some(d) = p_str(params, "deleteIn") {
                opts.deletion_date = Some(vault_session::parse_send_date(&d, now)?);
            }
            let id = if let Some(file) = p_str(params, "file") {
                let path = std::path::PathBuf::from(&file);
                let name = name.clone().unwrap_or_else(|| {
                    path.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("Send")
                        .to_string()
                });
                session.create_file_send(&name, &path, &opts).await?
            } else {
                let text = p_req(params, "text")?;
                let name = name.clone().unwrap_or_else(|| "Send".into());
                session.create_send(&name, &text, &opts).await?
            };
            let url = session.send_share_link(&id).ok();
            Ok(json!({ "id": id, "name": name, "url": url }))
        }
        "send.list" => Ok(Value::Array(
            session.sends().iter().map(send_json).collect(),
        )),
        "send.delete" => {
            let q = p_req(params, "query")?;
            let id = session
                .sends()
                .iter()
                .find(|s| s.id == q || s.name.eq_ignore_ascii_case(&q))
                .map(|s| s.id.clone())
                .ok_or_else(|| anyhow!("send not found: {q}"))?;
            session.delete_send(&id).await?;
            Ok(json!({ "deleted": id }))
        }
        "send.link" => {
            let q = p_req(params, "query")?;
            let id = session
                .sends()
                .iter()
                .find(|s| s.id == q || s.name.eq_ignore_ascii_case(&q))
                .map(|s| s.id.clone())
                .ok_or_else(|| anyhow!("send not found: {q}"))?;
            Ok(json!({ "id": id, "url": session.send_share_link(&id)? }))
        }
        other => bail!("unknown method `{other}`"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_overrides_nested() {
        let mut a = json!({ "name": "a", "login": { "username": "u", "password": "p" } });
        deep_merge(
            &mut a,
            &json!({ "login": { "password": "q" }, "name": "b" }),
        );
        assert_eq!(a["login"]["username"], "u");
        assert_eq!(a["login"]["password"], "q");
        assert_eq!(a["name"], "b");
    }

    #[test]
    fn parses_raw_and_base64_input() {
        let raw = r#"{"type":1,"name":"x"}"#;
        assert_eq!(parse_item_input(raw).unwrap()["name"], "x");
        let b64 = base64::engine::general_purpose::STANDARD.encode(raw);
        assert_eq!(parse_item_input(&b64).unwrap()["type"], 1);
        assert!(parse_item_input("!!!").is_err());
    }

    #[test]
    fn login_draft_from_json() {
        let v = json!({
            "type": 1, "name": "Site", "favorite": true,
            "login": { "username": "me", "password": "pw",
                       "uris": [{ "match": 1, "uri": "https://a.example" }] }
        });
        match draft_from_json(&v).unwrap() {
            AnyDraft::Login(d) => {
                assert_eq!(d.username.as_deref(), Some("me"));
                assert_eq!(d.uris.len(), 1);
                assert_eq!(d.uris[0].match_type, Some(1));
                assert!(d.favorite);
            }
            _ => panic!("expected login"),
        }
    }

    #[test]
    fn templates_exist() {
        assert!(template_json("item.login").is_ok());
        assert!(template_json("nope").is_err());
    }
}
