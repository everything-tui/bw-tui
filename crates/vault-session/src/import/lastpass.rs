//! LastPass CSV export (`url,username,password,totp,extra,name,grouping,fav`).

use super::common::{
    login_draft, name_or_host, note_draft, read_table, truthy, uris_from, with_extras, Builder,
};
use crate::error::Result;
use crate::export::ImportBundle;

pub fn import_lastpass_csv(text: &str) -> Result<ImportBundle> {
    let table = read_table(text)?;
    table.require_any(&["url", "name"], "a LastPass CSV")?;

    let mut b = Builder::new();
    for row in table.rows() {
        let url = row.get(&["url"]);
        let is_note = url
            .as_deref()
            .is_some_and(|u| u.eq_ignore_ascii_case("http://sn"));
        let name = name_or_host(row.get(&["name"]), url.as_deref());
        let folder_id = b.folder(row.get(&["grouping"]).as_deref());
        let favorite = truthy(row.get(&["fav"]));
        let notes = with_extras(row.get(&["extra", "notes"]), &[]);
        if is_note {
            b.note(note_draft(name, notes, folder_id, favorite));
        } else {
            b.login(login_draft(
                name,
                row.get(&["username"]),
                row.get(&["password"]),
                row.get(&["totp"]),
                uris_from(url),
                notes,
                folder_id,
                favorite,
            ));
        }
    }
    Ok(b.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lastpass_login_and_note() {
        let csv = "url,username,password,totp,extra,name,grouping,fav\n\
https://example.com,u,p,,n,Ex,Work,0\n\
http://sn,,, ,secure note body,Note,Personal,1\n";
        let b = import_lastpass_csv(csv).unwrap();
        assert_eq!(b.login_drafts.len(), 1);
        assert_eq!(b.note_drafts.len(), 1);
    }
}
