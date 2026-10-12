//! Bitwarden CSV (`folder,favorite,type,name,notes,fields,reprompt,login_uri,…`).

use super::common::{
    login_draft, note_draft, read_table, split_lines, truthy, uris_from, with_extras, Builder,
    UNNAMED,
};
use crate::error::Result;
use crate::export::ImportBundle;
use crate::models::{CardDraft, IdentityDraft};

/// Import a Bitwarden CSV export (personal or organization; extended card/identity columns
/// written by this client are honoured when present).
pub fn import_bitwarden_csv(text: &str) -> Result<ImportBundle> {
    let table = read_table(text)?;
    table.require_any(&["name"], "a Bitwarden CSV")?;
    table.require_any(&["type", "login_uri", "login_username"], "a Bitwarden CSV")?;

    let mut b = Builder::new();
    if table.has_any(&["collections"]) {
        b.warn(
            "organization `collections` column ignored (items imported into your personal vault)",
        );
    }

    for row in table.rows() {
        let name = row.get(&["name"]).unwrap_or_else(|| UNNAMED.to_string());
        let folder_id = {
            let f = row.get(&["folder"]);
            b.folder(f.as_deref())
        };
        let favorite = truthy(row.get(&["favorite"]));
        let reprompt = truthy(row.get(&["reprompt"]));
        let field_extras: Vec<(String, String)> = row
            .get(&["fields"])
            .map(|f| {
                split_lines(&f)
                    .into_iter()
                    .map(|l| match l.split_once(": ") {
                        Some((k, v)) => (k.to_string(), v.to_string()),
                        None => (String::new(), l),
                    })
                    .collect()
            })
            .unwrap_or_default();
        let notes = with_extras(row.get(&["notes"]), &field_extras);
        let kind = row
            .get(&["type"])
            .map(|t| t.trim().to_ascii_lowercase())
            .unwrap_or_else(|| "login".into());

        match kind.as_str() {
            "login" | "" => {
                let mut d = login_draft(
                    name,
                    row.get(&["login_username"]),
                    row.get(&["login_password"]),
                    row.get(&["login_totp"]),
                    uris_from(
                        row.get(&["login_uri"])
                            .map(|u| split_lines(&u))
                            .unwrap_or_default(),
                    ),
                    notes,
                    folder_id,
                    favorite,
                );
                d.reprompt = reprompt;
                b.login(d);
            }
            "note" | "securenote" | "secure_note" => {
                b.note(note_draft(name, notes, folder_id, favorite));
            }
            "card" => b.card(CardDraft {
                name,
                cardholder_name: row.get(&["card_cardholder_name"]),
                brand: row.get(&["card_brand"]),
                number: row.get(&["card_number"]),
                exp_month: row.get(&["card_exp_month"]),
                exp_year: row.get(&["card_exp_year"]),
                code: row.get(&["card_code"]),
                notes,
                folder_id,
                favorite,
                reprompt,
            }),
            "identity" => b.identity(IdentityDraft {
                name,
                title: row.get(&["identity_title"]),
                first_name: row.get(&["identity_first_name"]),
                middle_name: row.get(&["identity_middle_name"]),
                last_name: row.get(&["identity_last_name"]),
                address1: row.get(&["identity_address1"]),
                address2: row.get(&["identity_address2"]),
                address3: row.get(&["identity_address3"]),
                city: row.get(&["identity_city"]),
                state: row.get(&["identity_state"]),
                postal_code: row.get(&["identity_postal_code"]),
                country: row.get(&["identity_country"]),
                company: row.get(&["identity_company"]),
                email: row.get(&["identity_email"]),
                phone: row.get(&["identity_phone"]),
                ssn: row.get(&["identity_ssn"]),
                username: row.get(&["identity_username"]),
                passport_number: row.get(&["identity_passport_number"]),
                license_number: row.get(&["identity_license_number"]),
                notes,
                folder_id,
                favorite,
                reprompt,
            }),
            other => b.warn(format!("{name}: unsupported item type `{other}` skipped")),
        }
    }
    Ok(b.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::export::export_csv_full;
    use crate::models::{DecryptedFolder, DecryptedItem, ItemType};

    const FIXTURE: &str = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
Work,1,login,GitHub,\"my note\",\"pin: 1234\",1,\"https://github.com\nhttps://gist.github.com\",octo,hunter2,otpauth://totp/x?secret=ABC\n\
,,note,Wifi,\"ssid: home\",,0,,,,\n";

    #[test]
    fn imports_logins_and_notes() {
        let b = import_bitwarden_csv(FIXTURE).unwrap();
        assert_eq!(b.folders.len(), 1);
        assert_eq!(b.folders[0].name, "Work");
        assert_eq!(b.login_drafts.len(), 1);
        let l = &b.login_drafts[0];
        assert_eq!(l.name, "GitHub");
        assert!(l.favorite && l.reprompt);
        assert_eq!(l.uris.len(), 2);
        assert_eq!(l.username.as_deref(), Some("octo"));
        assert_eq!(l.totp.as_deref(), Some("otpauth://totp/x?secret=ABC"));
        assert_eq!(l.folder_id.as_deref(), Some(b.folders[0].id.as_str()));
        assert!(l.notes.as_deref().unwrap().contains("pin: 1234"));
        assert_eq!(b.note_drafts.len(), 1);
        assert_eq!(b.note_drafts[0].notes.as_deref(), Some("ssid: home"));
    }

    #[test]
    fn rejects_unrelated_csv() {
        assert!(import_bitwarden_csv("a,b\n1,2\n").is_err());
    }

    #[test]
    fn export_full_round_trips_extended() {
        let mut login = blank("Site", ItemType::Login);
        login.username = Some("me".into());
        login.password = Some("pw,\"x\"".into());
        login.folder_id = Some("f1".into());
        let mut card = blank("Visa", ItemType::Card);
        card.card_number = Some("4111111111111111".into());
        card.card_brand = Some("Visa".into());
        let folders = vec![DecryptedFolder {
            id: "f1".into(),
            name: "Fin".into(),
        }];
        let csv = export_csv_full(&[login, card], &folders, true);
        assert!(csv.starts_with("folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp,"));
        let b = import_bitwarden_csv(&csv).unwrap();
        assert_eq!(b.login_drafts[0].password.as_deref(), Some("pw,\"x\""));
        assert_eq!(b.folders[0].name, "Fin");
        assert_eq!(b.card_drafts[0].number.as_deref(), Some("4111111111111111"));
        // Standard (non-extended) export has exactly the 11 Bitwarden columns and no cards.
        let std_csv = export_csv_full(&[blank("N", ItemType::SecureNote)], &[], false);
        assert_eq!(
            std_csv.lines().next().unwrap(),
            "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp"
        );
    }

    fn blank(name: &str, t: ItemType) -> DecryptedItem {
        DecryptedItem {
            id: format!("id-{name}"),
            name: name.into(),
            item_type: t,
            folder_id: None,
            organization_id: None,
            collection_ids: Vec::new(),
            favorite: false,
            deleted: false,
            reprompt: false,
            notes: None,
            username: None,
            password: None,
            totp: None,
            uris: Vec::new(),
            custom_fields: Vec::new(),
            password_history: Vec::new(),
            password_revision_date: None,
            creation_date: None,
            revision_date: None,
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
            passkeys: Vec::new(),
            has_item_key: false,
        }
    }
}
