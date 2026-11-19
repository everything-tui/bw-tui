//! 1Password importers: `.1pux` (zip + `export.data` JSON) and CSV.

use std::io::{Cursor, Read};

use serde_json::Value;

use super::common::{
    login_draft, name_or_host, note_draft, read_table, truthy, uris_from, with_extras, Builder,
    UNNAMED,
};
use crate::error::{Result, SessionError};
use crate::export::ImportBundle;
use crate::models::{CardDraft, IdentityDraft};

// ---------------------------------------------------------------------------
// CSV
// ---------------------------------------------------------------------------

/// 1Password CSV (v8: `Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes`;
/// v7: `Title,Website,Username,Password,Notes,Type,Folder`).
pub fn import_1password_csv(text: &str) -> Result<ImportBundle> {
    let table = read_table(text)?;
    table.require_any(&["title"], "a 1Password CSV")?;
    table.require_any(&["password", "username"], "a 1Password CSV")?;

    const KNOWN: [&str; 13] = [
        "title",
        "url",
        "website",
        "username",
        "password",
        "otpauth",
        "one-time password",
        "favorite",
        "archived",
        "tags",
        "notes",
        "type",
        "folder",
    ];

    let mut b = Builder::new();
    for row in table.rows() {
        if truthy(row.get(&["archived"])) {
            continue;
        }
        let name = row.get(&["title"]).unwrap_or_else(|| UNNAMED.to_string());
        // `Folder` (v7) wins; v8 `Tags` use the first tag as the folder.
        let folder = row.get(&["folder"]).or_else(|| {
            row.get(&["tags"])
                .and_then(|t| t.split([',', ';']).next().map(|s| s.trim().to_string()))
        });
        let folder_id = b.folder(folder.as_deref());
        let favorite = truthy(row.get(&["favorite"]));
        let extras = row.extras(&KNOWN);
        let notes = with_extras(row.get(&["notes"]), &extras);
        let kind = row.get(&["type"]).unwrap_or_default().to_ascii_lowercase();
        let url = row.get(&["url", "website"]);
        let username = row.get(&["username"]);
        let password = row.get(&["password"]);

        if kind.contains("note") && username.is_none() && password.is_none() {
            b.note(note_draft(name, notes, folder_id, favorite));
        } else {
            b.login(login_draft(
                name,
                username,
                password,
                row.get(&["otpauth", "one-time password"]),
                uris_from(url),
                notes,
                folder_id,
                favorite,
            ));
        }
    }
    Ok(b.finish())
}

// ---------------------------------------------------------------------------
// 1PUX
// ---------------------------------------------------------------------------

/// Import a `.1pux` export (a zip archive with `export.data`).
pub fn import_1password_1pux(bytes: &[u8]) -> Result<ImportBundle> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))
        .map_err(|e| SessionError::Other(format!("1pux: not a zip archive: {e}")))?;
    let mut data = String::new();
    archive
        .by_name("export.data")
        .map_err(|_| SessionError::Other("1pux: missing export.data".into()))?
        .read_to_string(&mut data)
        .map_err(|e| SessionError::Other(format!("1pux: read export.data: {e}")))?;
    import_1password_export_data(&data)
}

/// Parse the JSON payload of a 1pux archive.
pub(crate) fn import_1password_export_data(json: &str) -> Result<ImportBundle> {
    let root: Value = serde_json::from_str(json)
        .map_err(|e| SessionError::Other(format!("1pux: invalid export.data: {e}")))?;
    let accounts = root
        .get("accounts")
        .and_then(Value::as_array)
        .ok_or_else(|| SessionError::Other("1pux: no accounts in export.data".into()))?;

    let mut b = Builder::new();
    for account in accounts {
        let vaults = account.get("vaults").and_then(Value::as_array);
        for vault in vaults.into_iter().flatten() {
            let vault_name = vault
                .pointer("/attrs/name")
                .and_then(Value::as_str)
                .map(str::to_string);
            let folder_id = b.folder(vault_name.as_deref());
            let items = vault.get("items").and_then(Value::as_array);
            for entry in items.into_iter().flatten() {
                import_item(entry, folder_id.clone(), &mut b);
            }
        }
    }
    Ok(b.finish())
}

fn str_at(v: &Value, ptr: &str) -> Option<String> {
    v.pointer(ptr)
        .and_then(Value::as_str)
        .map(str::to_string)
        .filter(|s| !s.is_empty())
}

/// Render a 1Password field `value` object (`{"string": "…"}`, `{"monthYear": 202703}`, …).
fn value_to_string(v: &Value) -> Option<String> {
    let obj = v.as_object()?;
    for (kind, inner) in obj {
        let s = match kind.as_str() {
            "address" => {
                let a = inner.as_object()?;
                let parts: Vec<&str> = ["street", "city", "state", "zip", "country"]
                    .iter()
                    .filter_map(|k| a.get(*k).and_then(Value::as_str))
                    .filter(|s| !s.is_empty())
                    .collect();
                parts.join(", ")
            }
            "monthYear" => {
                let n = inner.as_i64().or_else(|| inner.as_str()?.parse().ok())?;
                format!("{:04}-{:02}", n / 100, n % 100)
            }
            "date" => inner.as_i64()?.to_string(),
            "reference" => continue,
            _ => match inner {
                Value::String(s) => s.clone(),
                Value::Number(n) => n.to_string(),
                Value::Bool(b) => b.to_string(),
                _ => continue,
            },
        };
        if !s.is_empty() {
            return Some(s);
        }
    }
    None
}

struct SectionField {
    id: String,
    title: String,
    kind: String,
    text: String,
    raw: Value,
}

fn collect_fields(details: &Value) -> Vec<SectionField> {
    let mut out = Vec::new();
    let sections = details.get("sections").and_then(Value::as_array);
    for section in sections.into_iter().flatten() {
        let fields = section.get("fields").and_then(Value::as_array);
        for f in fields.into_iter().flatten() {
            let Some(value) = f.get("value") else {
                continue;
            };
            let Some(text) = value_to_string(value) else {
                continue;
            };
            let kind = value
                .as_object()
                .and_then(|o| o.keys().next())
                .cloned()
                .unwrap_or_default();
            out.push(SectionField {
                id: str_at(f, "/id").unwrap_or_default(),
                title: str_at(f, "/title").unwrap_or_default(),
                kind,
                text,
                raw: value.clone(),
            });
        }
    }
    out
}

fn import_item(entry: &Value, folder_id: Option<String>, b: &mut Builder) {
    let item = entry.get("item").unwrap_or(entry);
    let overview = item.get("overview").cloned().unwrap_or(Value::Null);
    let details = item.get("details").cloned().unwrap_or(Value::Null);
    let state = str_at(item, "/state").unwrap_or_default();
    if state == "trashed" {
        return;
    }
    let category = str_at(item, "/categoryUuid").unwrap_or_default();
    let favorite = item
        .get("favIndex")
        .and_then(Value::as_i64)
        .is_some_and(|i| i > 0);
    let title = str_at(&overview, "/title");

    let mut urls: Vec<String> = Vec::new();
    if let Some(u) = str_at(&overview, "/url") {
        urls.push(u);
    }
    if let Some(list) = overview.get("urls").and_then(Value::as_array) {
        for u in list {
            if let Some(s) = u.get("url").and_then(Value::as_str) {
                if !s.is_empty() && !urls.iter().any(|x| x == s) {
                    urls.push(s.to_string());
                }
            }
        }
    }
    let fields = collect_fields(&details);
    let notes_plain = str_at(&details, "/notesPlain");

    // Section fields not mapped to a dedicated draft field end up in the notes.
    let extras_except = |used: &[&str]| -> Vec<(String, String)> {
        fields
            .iter()
            .filter(|f| !used.contains(&f.id.as_str()) && f.kind != "totp")
            .map(|f| {
                let label = if f.title.is_empty() {
                    f.id.clone()
                } else {
                    f.title.clone()
                };
                (label, f.text.clone())
            })
            .collect()
    };
    let field = |id: &str| {
        fields
            .iter()
            .find(|f| f.id == id)
            .map(|f| f.text.clone())
            .filter(|s| !s.is_empty())
    };

    match category.as_str() {
        // Login / Password / (and anything with login fields)
        "001" | "005" => {
            let login_fields = details.get("loginFields").and_then(Value::as_array);
            let mut username = None;
            let mut password = str_at(&details, "/password");
            for lf in login_fields.into_iter().flatten() {
                let value = str_at(lf, "/value");
                match str_at(lf, "/designation").as_deref() {
                    Some("username") if username.is_none() => username = value,
                    Some("password") if password.is_none() => password = value,
                    _ => {}
                }
            }
            let totp = fields
                .iter()
                .find(|f| f.kind == "totp")
                .map(|f| f.text.clone());
            let extras = extras_except(&[]);
            b.login(login_draft(
                name_or_host(title, urls.first().map(String::as_str)),
                username,
                password,
                totp,
                uris_from(urls),
                with_extras(notes_plain, &extras),
                folder_id,
                favorite,
            ));
        }
        // Credit card
        "002" => {
            let used = ["cardholder", "ccnum", "cvv", "expiry", "type"];
            let expiry = fields
                .iter()
                .find(|f| f.id == "expiry")
                .map(|f| f.text.clone());
            let (exp_year, exp_month) = match expiry.as_deref().and_then(|e| e.split_once('-')) {
                Some((y, m)) => (
                    Some(y.to_string()),
                    Some(m.trim_start_matches('0').to_string()).filter(|m| !m.is_empty()),
                ),
                None => (None, None),
            };
            let extras = extras_except(&used);
            b.card(CardDraft {
                name: title.unwrap_or_else(|| UNNAMED.into()),
                cardholder_name: field("cardholder"),
                brand: field("type"),
                number: field("ccnum").or_else(|| {
                    fields
                        .iter()
                        .find(|f| f.kind == "creditCardNumber")
                        .map(|f| f.text.clone())
                }),
                exp_month,
                exp_year,
                code: field("cvv"),
                notes: with_extras(notes_plain, &extras),
                folder_id,
                favorite,
                reprompt: false,
            });
        }
        // Identity
        "004" => {
            let used = [
                "firstname",
                "initial",
                "lastname",
                "address",
                "defphone",
                "email",
                "company",
                "username",
            ];
            let address = fields
                .iter()
                .find(|f| f.id == "address")
                .and_then(|f| f.raw.get("address").cloned());
            let addr = |k: &str| {
                address
                    .as_ref()
                    .and_then(|a| a.get(k))
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .filter(|s| !s.is_empty())
            };
            let extras = extras_except(&used);
            b.identity(IdentityDraft {
                name: title.unwrap_or_else(|| UNNAMED.into()),
                title: None,
                first_name: field("firstname"),
                middle_name: field("initial"),
                last_name: field("lastname"),
                address1: addr("street"),
                address2: None,
                address3: None,
                city: addr("city"),
                state: addr("state"),
                postal_code: addr("zip"),
                country: addr("country"),
                company: field("company"),
                email: field("email"),
                phone: field("defphone"),
                ssn: None,
                username: field("username"),
                passport_number: None,
                license_number: None,
                notes: with_extras(notes_plain, &extras),
                folder_id,
                favorite,
                reprompt: false,
            });
        }
        // Secure note and every other category (documents, licenses, bank accounts, …)
        other => {
            let extras = extras_except(&[]);
            let mut all_extras = extras;
            if !urls.is_empty() {
                all_extras.push(("URL".into(), urls.join("\n")));
            }
            if other != "003" {
                b.warn(format!(
                    "{}: 1Password category {other} imported as secure note",
                    title.as_deref().unwrap_or(UNNAMED)
                ));
            }
            b.note(note_draft(
                title.unwrap_or_else(|| UNNAMED.into()),
                with_extras(notes_plain, &all_extras),
                folder_id,
                favorite,
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const EXPORT_DATA: &str = r#"{
      "accounts": [{
        "attrs": {"accountName": "Me"},
        "vaults": [{
          "attrs": {"name": "Personal"},
          "items": [
            {"item": {
              "uuid": "1", "favIndex": 1, "state": "active", "categoryUuid": "001",
              "details": {
                "loginFields": [
                  {"value": "ada", "designation": "username", "fieldType": "T"},
                  {"value": "lovelace1", "designation": "password", "fieldType": "P"}
                ],
                "notesPlain": "login note",
                "sections": [{"title": "", "fields": [
                  {"title": "one-time password", "id": "TOTP_1", "value": {"totp": "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"}},
                  {"title": "Recovery", "id": "r1", "value": {"concealed": "abcd-efgh"}}
                ]}]
              },
              "overview": {"title": "Analytical Engine", "url": "https://engine.example", "urls": [{"label": "w", "url": "https://engine.example"}, {"label": "x", "url": "https://alt.example"}]}
            }},
            {"item": {
              "uuid": "2", "favIndex": 0, "state": "active", "categoryUuid": "002",
              "details": {"notesPlain": "", "sections": [{"title": "", "fields": [
                {"title": "cardholder name", "id": "cardholder", "value": {"string": "Ada Lovelace"}},
                {"title": "type", "id": "type", "value": {"creditCardType": "visa"}},
                {"title": "number", "id": "ccnum", "value": {"creditCardNumber": "4111111111111111"}},
                {"title": "verification number", "id": "cvv", "value": {"concealed": "123"}},
                {"title": "expiry date", "id": "expiry", "value": {"monthYear": 202703}}
              ]}]},
              "overview": {"title": "Visa"}
            }},
            {"item": {
              "uuid": "3", "state": "active", "categoryUuid": "003",
              "details": {"notesPlain": "secret thoughts", "sections": []},
              "overview": {"title": "Journal"}
            }},
            {"item": {
              "uuid": "4", "state": "trashed", "categoryUuid": "001",
              "details": {"loginFields": []}, "overview": {"title": "Trash"}
            }},
            {"item": {
              "uuid": "5", "state": "active", "categoryUuid": "004",
              "details": {"sections": [{"title": "", "fields": [
                {"title": "first name", "id": "firstname", "value": {"string": "Ada"}},
                {"title": "last name", "id": "lastname", "value": {"string": "Lovelace"}},
                {"title": "address", "id": "address", "value": {"address": {"street": "1 Main St", "city": "London", "zip": "N1", "country": "gb", "state": ""}}}
              ]}]},
              "overview": {"title": "Me"}
            }}
          ]
        }]
      }]
    }"#;

    fn make_1pux() -> Vec<u8> {
        let mut zw = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default();
        zw.start_file("export.attributes", opts).unwrap();
        zw.write_all(b"{\"version\":3}").unwrap();
        zw.start_file("export.data", opts).unwrap();
        zw.write_all(EXPORT_DATA.as_bytes()).unwrap();
        zw.finish().unwrap().into_inner()
    }

    #[test]
    fn imports_1pux_archive() {
        let b = import_1password_1pux(&make_1pux()).unwrap();
        assert_eq!(b.folders.len(), 1);
        assert_eq!(b.folders[0].name, "Personal");

        assert_eq!(b.login_drafts.len(), 1);
        let l = &b.login_drafts[0];
        assert_eq!(l.name, "Analytical Engine");
        assert_eq!(l.username.as_deref(), Some("ada"));
        assert_eq!(l.password.as_deref(), Some("lovelace1"));
        assert!(l.favorite);
        assert_eq!(l.uris.len(), 2);
        assert_eq!(
            l.totp.as_deref(),
            Some("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP")
        );
        let notes = l.notes.as_deref().unwrap();
        assert!(notes.contains("login note"));
        assert!(notes.contains("Recovery: abcd-efgh"));

        assert_eq!(b.card_drafts.len(), 1);
        let c = &b.card_drafts[0];
        assert_eq!(c.number.as_deref(), Some("4111111111111111"));
        assert_eq!(c.exp_month.as_deref(), Some("3"));
        assert_eq!(c.exp_year.as_deref(), Some("2027"));
        assert_eq!(c.code.as_deref(), Some("123"));
        assert_eq!(c.cardholder_name.as_deref(), Some("Ada Lovelace"));

        assert_eq!(b.note_drafts.len(), 1);
        assert_eq!(b.note_drafts[0].notes.as_deref(), Some("secret thoughts"));

        assert_eq!(b.identity_drafts.len(), 1);
        let i = &b.identity_drafts[0];
        assert_eq!(i.first_name.as_deref(), Some("Ada"));
        assert_eq!(i.city.as_deref(), Some("London"));
        assert_eq!(i.address1.as_deref(), Some("1 Main St"));
    }

    #[test]
    fn rejects_non_zip() {
        assert!(import_1password_1pux(b"plain").is_err());
    }

    #[test]
    fn csv_v8() {
        let csv = "Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\n\
Example,https://example.com,me,pw,otpauth://totp/e?secret=ABC,true,false,\"Work,Misc\",hello\n\
Old,https://old.example,x,y,,false,true,,\n";
        let b = import_1password_csv(csv).unwrap();
        assert_eq!(b.login_drafts.len(), 1);
        let l = &b.login_drafts[0];
        assert!(l.favorite);
        assert_eq!(l.totp.as_deref(), Some("otpauth://totp/e?secret=ABC"));
        assert_eq!(b.folders[0].name, "Work");
    }

    #[test]
    fn csv_v7_notes() {
        let csv = "Title,Website,Username,Password,Notes,Type,Folder\nMemo,,,,body text,Secure Note,Home\n";
        let b = import_1password_csv(csv).unwrap();
        assert_eq!(b.note_drafts.len(), 1);
        assert_eq!(b.note_drafts[0].notes.as_deref(), Some("body text"));
        assert_eq!(b.folders[0].name, "Home");
    }
}
