//! Proton Pass importers (unencrypted JSON export and CSV).

use serde_json::Value;

use super::common::{
    login_draft, name_or_host, note_draft, read_table, uris_from, with_extras, Builder, UNNAMED,
};
use crate::error::{Result, SessionError};
use crate::export::ImportBundle;
use crate::models::{CardDraft, IdentityDraft};

fn s(v: &Value, key: &str) -> Option<String> {
    v.get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .filter(|x| !x.is_empty())
}

/// Import a Proton Pass JSON export (`{"encrypted": false, "vaults": {...}}`).
pub fn import_proton_json(text: &str) -> Result<ImportBundle> {
    let root: Value = serde_json::from_str(text)
        .map_err(|e| SessionError::Other(format!("proton json parse: {e}")))?;
    if root.get("encrypted").and_then(Value::as_bool) == Some(true) {
        return Err(SessionError::Other(
            "Proton Pass export is PGP-encrypted — export it unencrypted (or decrypt it) first"
                .into(),
        ));
    }
    let vaults = root
        .get("vaults")
        .and_then(Value::as_object)
        .ok_or_else(|| SessionError::Other("not a Proton Pass export (missing `vaults`)".into()))?;

    let mut b = Builder::new();
    for vault in vaults.values() {
        let vault_name = s(vault, "name");
        let folder_id = b.folder(vault_name.as_deref());
        let items = vault.get("items").and_then(Value::as_array);
        for item in items.into_iter().flatten() {
            import_item(item, folder_id.clone(), &mut b);
        }
    }
    Ok(b.finish())
}

fn import_item(item: &Value, folder_id: Option<String>, b: &mut Builder) {
    // state 1 = active, 2 = trashed
    if item.get("state").and_then(Value::as_i64) == Some(2) {
        return;
    }
    let favorite = item.get("pinned").and_then(Value::as_bool).unwrap_or(false);
    let data = item.get("data").unwrap_or(&Value::Null);
    let meta = data.get("metadata").unwrap_or(&Value::Null);
    let name = s(meta, "name");
    let note = s(meta, "note");
    let content = data.get("content").unwrap_or(&Value::Null);
    let kind = s(data, "type").unwrap_or_default();

    let mut extras: Vec<(String, String)> = Vec::new();
    for f in data
        .get("extraFields")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let fname = s(f, "fieldName").unwrap_or_default();
        let fdata = f.get("data").unwrap_or(&Value::Null);
        let val = s(fdata, "content").or_else(|| s(fdata, "totpUri"));
        if let Some(v) = val {
            extras.push((fname, v));
        }
    }

    match kind.as_str() {
        "login" | "alias" => {
            let user = s(content, "itemUsername");
            let email = s(content, "itemEmail");
            let alias_email = s(item, "aliasEmail");
            if let (Some(u), Some(e)) = (&user, &email) {
                if u != e {
                    extras.insert(0, ("Email".into(), e.clone()));
                }
            }
            let username = user.or(email).or(alias_email);
            let urls: Vec<String> = content
                .get("urls")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            b.login(login_draft(
                name_or_host(name, urls.first().map(String::as_str)),
                username,
                s(content, "password"),
                s(content, "totpUri"),
                uris_from(urls),
                with_extras(note, &extras),
                folder_id,
                favorite,
            ));
        }
        "note" => {
            b.note(note_draft(
                name.unwrap_or_else(|| UNNAMED.into()),
                with_extras(note, &extras),
                folder_id,
                favorite,
            ));
        }
        "creditCard" => {
            let (exp_year, exp_month) = match s(content, "expirationDate")
                .as_deref()
                .and_then(|e| e.split_once('-'))
            {
                Some((y, m)) => (
                    Some(y.to_string()),
                    Some(m.trim_start_matches('0').to_string()).filter(|m| !m.is_empty()),
                ),
                None => (None, None),
            };
            if let Some(pin) = s(content, "pin") {
                extras.insert(0, ("PIN".into(), pin));
            }
            b.card(CardDraft {
                name: name.unwrap_or_else(|| UNNAMED.into()),
                cardholder_name: s(content, "cardholderName"),
                brand: s(content, "cardType"),
                number: s(content, "number"),
                exp_month,
                exp_year,
                code: s(content, "verificationNumber"),
                notes: with_extras(note, &extras),
                folder_id,
                favorite,
                reprompt: false,
            });
        }
        "identity" => {
            const USED: [&str; 14] = [
                "fullName",
                "email",
                "phoneNumber",
                "firstName",
                "middleName",
                "lastName",
                "organization",
                "streetAddress",
                "zipOrPostalCode",
                "city",
                "stateOrProvince",
                "countryOrRegion",
                "socialSecurityNumber",
                "passportNumber",
            ];
            if let Some(obj) = content.as_object() {
                for (k, v) in obj {
                    if USED.contains(&k.as_str()) || k == "licenseNumber" {
                        continue;
                    }
                    if let Some(text) = v.as_str().filter(|t| !t.is_empty()) {
                        extras.push((k.clone(), text.to_string()));
                    }
                }
            }
            let (first, last) = match (s(content, "firstName"), s(content, "lastName")) {
                (None, None) => match s(content, "fullName") {
                    Some(full) => match full.rsplit_once(' ') {
                        Some((f, l)) => (Some(f.to_string()), Some(l.to_string())),
                        None => (Some(full), None),
                    },
                    None => (None, None),
                },
                other => other,
            };
            b.identity(IdentityDraft {
                name: name.unwrap_or_else(|| UNNAMED.into()),
                title: None,
                first_name: first,
                middle_name: s(content, "middleName"),
                last_name: last,
                address1: s(content, "streetAddress"),
                address2: None,
                address3: None,
                city: s(content, "city"),
                state: s(content, "stateOrProvince"),
                postal_code: s(content, "zipOrPostalCode"),
                country: s(content, "countryOrRegion"),
                company: s(content, "organization"),
                email: s(content, "email"),
                phone: s(content, "phoneNumber"),
                ssn: s(content, "socialSecurityNumber"),
                username: None,
                passport_number: s(content, "passportNumber"),
                license_number: s(content, "licenseNumber"),
                notes: with_extras(note, &extras),
                folder_id,
                favorite,
                reprompt: false,
            });
        }
        other => {
            b.warn(format!(
                "{}: Proton Pass item type `{other}` imported as secure note",
                name.as_deref().unwrap_or(UNNAMED)
            ));
            b.note(note_draft(
                name.unwrap_or_else(|| UNNAMED.into()),
                with_extras(note, &extras),
                folder_id,
                favorite,
            ));
        }
    }
}

/// Import a Proton Pass CSV (`type,name,url,email,username,password,note,totp,createTime,modifyTime,vault`).
pub fn import_proton_csv(text: &str) -> Result<ImportBundle> {
    let table = read_table(text)?;
    table.require_any(&["name"], "a Proton Pass CSV")?;
    table.require_any(&["vault", "totp", "createtime"], "a Proton Pass CSV")?;

    let mut b = Builder::new();
    for row in table.rows() {
        let folder_id = {
            let v = row.get(&["vault"]);
            b.folder(v.as_deref())
        };
        let kind = row.get(&["type"]).unwrap_or_default().to_ascii_lowercase();
        let name = row.get(&["name"]);
        let note = row.get(&["note"]);
        if kind == "note" {
            b.note(note_draft(
                name.unwrap_or_else(|| UNNAMED.into()),
                note,
                folder_id,
                false,
            ));
            continue;
        }
        let url = row.get(&["url"]);
        let user = row.get(&["username"]);
        let email = row.get(&["email"]);
        let mut extras = Vec::new();
        if let (Some(u), Some(e)) = (&user, &email) {
            if u != e {
                extras.push(("Email".to_string(), e.clone()));
            }
        }
        b.login(login_draft(
            name_or_host(name, url.as_deref()),
            user.or(email),
            row.get(&["password"]),
            row.get(&["totp"]),
            uris_from(
                url.map(|u| {
                    // Proton joins multiple URLs with newlines.
                    u.lines()
                        .map(str::trim)
                        .filter(|l| !l.is_empty())
                        .map(str::to_string)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default(),
            ),
            with_extras(note, &extras),
            folder_id,
            false,
        ));
    }
    Ok(b.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    const JSON: &str = r#"{
      "version": "1.21.0", "userId": "u", "encrypted": false,
      "vaults": {
        "v1": {"name": "Personal", "items": [
          {"itemId": "a", "state": 1, "pinned": true, "data": {
            "type": "login",
            "metadata": {"name": "Proton Mail", "note": "main account"},
            "extraFields": [{"fieldName": "Recovery", "type": "hidden", "data": {"content": "rc-123"}}],
            "content": {"itemEmail": "me@proton.me", "itemUsername": "me", "password": "pw", "urls": ["https://proton.me"], "totpUri": "otpauth://totp/p?secret=ABC"}
          }},
          {"itemId": "b", "state": 1, "data": {
            "type": "note", "metadata": {"name": "Memo", "note": "text"}, "extraFields": [], "content": {}
          }},
          {"itemId": "c", "state": 1, "data": {
            "type": "creditCard", "metadata": {"name": "Card", "note": ""}, "extraFields": [],
            "content": {"cardholderName": "Me", "number": "4242424242424242", "verificationNumber": "999", "expirationDate": "2028-09", "pin": "1111"}
          }},
          {"itemId": "d", "state": 1, "aliasEmail": "x@passmail.net", "data": {
            "type": "alias", "metadata": {"name": "Alias", "note": ""}, "extraFields": [], "content": {}
          }},
          {"itemId": "e", "state": 2, "data": {
            "type": "login", "metadata": {"name": "Trashed"}, "extraFields": [], "content": {}
          }},
          {"itemId": "f", "state": 1, "data": {
            "type": "identity", "metadata": {"name": "ID", "note": ""}, "extraFields": [],
            "content": {"fullName": "Ada Lovelace", "email": "a@l.org", "city": "London", "birthdate": "1815-12-10"}
          }}
        ]}
      }
    }"#;

    #[test]
    fn json_all_types() {
        let b = import_proton_json(JSON).unwrap();
        assert_eq!(b.folders.len(), 1);
        assert_eq!(b.login_drafts.len(), 2);
        let l = &b.login_drafts[0];
        assert_eq!(l.username.as_deref(), Some("me"));
        assert!(l.favorite);
        assert_eq!(l.totp.as_deref(), Some("otpauth://totp/p?secret=ABC"));
        let notes = l.notes.as_deref().unwrap();
        assert!(notes.contains("main account"));
        assert!(notes.contains("Email: me@proton.me"));
        assert!(notes.contains("Recovery: rc-123"));
        assert_eq!(
            b.login_drafts[1].username.as_deref(),
            Some("x@passmail.net")
        );

        assert_eq!(b.note_drafts.len(), 1);
        assert_eq!(b.card_drafts.len(), 1);
        let c = &b.card_drafts[0];
        assert_eq!(c.exp_month.as_deref(), Some("9"));
        assert_eq!(c.exp_year.as_deref(), Some("2028"));
        assert!(c.notes.as_deref().unwrap().contains("PIN: 1111"));

        assert_eq!(b.identity_drafts.len(), 1);
        assert_eq!(b.identity_drafts[0].first_name.as_deref(), Some("Ada"));
        assert_eq!(b.identity_drafts[0].last_name.as_deref(), Some("Lovelace"));
        assert!(b.identity_drafts[0]
            .notes
            .as_deref()
            .unwrap()
            .contains("birthdate: 1815-12-10"));
    }

    #[test]
    fn json_rejects_encrypted_and_foreign() {
        assert!(import_proton_json(r#"{"encrypted": true}"#).is_err());
        assert!(import_proton_json(r#"{"items": []}"#).is_err());
    }

    #[test]
    fn csv_import() {
        let csv = "type,name,url,email,username,password,note,totp,createTime,modifyTime,vault\n\
login,Site,https://site.example,e@x.org,,pw,hello,otpauth://totp/s?secret=Z,1,2,Personal\n\
note,Memo,,,,,body,,1,2,Personal\n";
        let b = import_proton_csv(csv).unwrap();
        assert_eq!(b.login_drafts.len(), 1);
        assert_eq!(b.login_drafts[0].username.as_deref(), Some("e@x.org"));
        assert_eq!(b.note_drafts[0].notes.as_deref(), Some("body"));
        assert_eq!(b.folders.len(), 1);
    }
}
