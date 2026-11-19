//! KeePass / KeePassXC importers (2.x XML export and CSV).

use roxmltree::{Document, Node};

use super::common::{login_draft, name_or_host, read_table, uris_from, with_extras, Builder};
use crate::error::{Result, SessionError};
use crate::export::ImportBundle;

const STANDARD_KEYS: [&str; 6] = ["Title", "UserName", "Password", "URL", "Notes", "otp"];

fn child<'a, 'i>(n: Node<'a, 'i>, tag: &str) -> Option<Node<'a, 'i>> {
    n.children().find(|c| c.is_element() && c.has_tag_name(tag))
}

fn text_of(n: Node<'_, '_>) -> String {
    n.descendants()
        .filter(|d| d.is_text())
        .filter_map(|d| d.text())
        .collect::<String>()
}

/// Import a KeePass 2.x / KeePassXC XML export.
pub fn import_keepass_xml(text: &str) -> Result<ImportBundle> {
    let doc = Document::parse(text.trim_start_matches('\u{feff}'))
        .map_err(|e| SessionError::Other(format!("keepass xml parse: {e}")))?;
    let root = doc.root_element();
    if !root.has_tag_name("KeePassFile") {
        return Err(SessionError::Other(
            "not a KeePass XML export (missing <KeePassFile>)".into(),
        ));
    }
    let root_group = child(root, "Root")
        .and_then(|r| child(r, "Group"))
        .ok_or_else(|| SessionError::Other("KeePass XML has no <Root><Group>".into()))?;
    let recycle_uuid = child(root, "Meta")
        .and_then(|m| child(m, "RecycleBinUUID"))
        .map(|n| text_of(n).trim().to_string())
        .filter(|u| !u.is_empty() && u != "AAAAAAAAAAAAAAAAAAAAAA==");

    let mut b = Builder::new();
    walk_group(
        root_group,
        &mut Vec::new(),
        true,
        recycle_uuid.as_deref(),
        &mut b,
    );
    Ok(b.finish())
}

fn walk_group(
    group: Node<'_, '_>,
    path: &mut Vec<String>,
    is_root: bool,
    recycle_uuid: Option<&str>,
    b: &mut Builder,
) {
    if !is_root {
        let uuid = child(group, "UUID").map(|n| text_of(n).trim().to_string());
        let name = child(group, "Name").map(text_of).unwrap_or_default();
        let is_recycle = match (recycle_uuid, uuid.as_deref()) {
            (Some(r), Some(u)) => r == u,
            _ => false,
        };
        if is_recycle {
            return;
        }
        path.push(name.trim().to_string());
    }
    let folder_name = if path.is_empty() {
        None
    } else {
        Some(path.join("/"))
    };

    for entry in group
        .children()
        .filter(|c| c.is_element() && c.has_tag_name("Entry"))
    {
        let mut fields: Vec<(String, String)> = Vec::new();
        for s in entry
            .children()
            .filter(|c| c.is_element() && c.has_tag_name("String"))
        {
            let key = child(s, "Key").map(text_of).unwrap_or_default();
            let value = child(s, "Value").map(text_of).unwrap_or_default();
            if !key.is_empty() {
                fields.push((key, value));
            }
        }
        let get = |k: &str| {
            fields
                .iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.clone())
                .filter(|v| !v.is_empty())
        };
        let url = get("URL");
        let totp = get("otp").or_else(|| get("TimeOtp-Secret-Base32"));
        let extras: Vec<(String, String)> = fields
            .iter()
            .filter(|(k, _)| !STANDARD_KEYS.contains(&k.as_str()) && k != "TimeOtp-Secret-Base32")
            .cloned()
            .collect();
        let folder_id = b.folder(folder_name.as_deref());
        b.login(login_draft(
            name_or_host(get("Title"), url.as_deref()),
            get("UserName"),
            get("Password"),
            totp,
            uris_from(url),
            with_extras(get("Notes"), &extras),
            folder_id,
            false,
        ));
    }

    for sub in group
        .children()
        .filter(|c| c.is_element() && c.has_tag_name("Group"))
    {
        walk_group(sub, path, false, recycle_uuid, b);
    }
    if !is_root {
        path.pop();
    }
}

/// Import a KeePassXC CSV (`Group,Title,Username,Password,URL,Notes,TOTP,…`) or a KeePass 2
/// CSV (`Account,Login Name,Password,Web Site,Comments`).
pub fn import_keepass_csv(text: &str) -> Result<ImportBundle> {
    let table = read_table(text)?;
    table.require_any(&["title", "account"], "a KeePass CSV")?;
    table.require_any(&["password"], "a KeePass CSV")?;

    const KNOWN: [&str; 14] = [
        "group",
        "title",
        "account",
        "username",
        "login name",
        "password",
        "url",
        "web site",
        "notes",
        "comments",
        "totp",
        "icon",
        "last modified",
        "created",
    ];

    let mut b = Builder::new();
    for row in table.rows() {
        let group = row.get(&["group"]).map(|g| {
            let g = g.trim().trim_start_matches('/').to_string();
            match g.strip_prefix("Root/") {
                Some(rest) => rest.to_string(),
                None if g == "Root" => String::new(),
                None => g,
            }
        });
        if group
            .as_deref()
            .is_some_and(|g| g == "Recycle Bin" || g.starts_with("Recycle Bin/"))
        {
            continue;
        }
        let folder_id = b.folder(group.as_deref());
        let url = row.get(&["url", "web site"]);
        let mut extras = row.extras(&KNOWN);
        extras.retain(|(k, _)| k != "icon");
        b.login(login_draft(
            name_or_host(row.get(&["title", "account"]), url.as_deref()),
            row.get(&["username", "login name"]),
            row.get(&["password"]),
            row.get(&["totp"]),
            uris_from(url),
            with_extras(row.get(&["notes", "comments"]), &extras),
            folder_id,
            false,
        ));
    }
    Ok(b.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    const XML: &str = r#"<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<KeePassFile>
  <Meta><RecycleBinUUID>rb==</RecycleBinUUID></Meta>
  <Root>
    <Group>
      <UUID>root</UUID><Name>Database</Name>
      <Entry>
        <String><Key>Title</Key><Value>Top</Value></String>
        <String><Key>UserName</Key><Value>u0</Value></String>
        <String><Key>Password</Key><Value ProtectInMemory="True">p0</Value></String>
        <String><Key>URL</Key><Value>https://top.example</Value></String>
        <String><Key>Notes</Key><Value>n0</Value></String>
        <String><Key>otp</Key><Value>otpauth://totp/Top?secret=JBSWY3DPEHPK3PXP</Value></String>
        <String><Key>Custom</Key><Value>extra-v</Value></String>
        <History><Entry><String><Key>Title</Key><Value>OLD</Value></String></Entry></History>
      </Entry>
      <Group>
        <UUID>g1</UUID><Name>Email</Name>
        <Entry>
          <String><Key>Title</Key><Value>Mail</Value></String>
          <String><Key>Password</Key><Value>pm</Value></String>
        </Entry>
        <Group>
          <UUID>g2</UUID><Name>Work</Name>
          <Entry><String><Key>Title</Key><Value>Deep</Value></String></Entry>
        </Group>
      </Group>
      <Group>
        <UUID>rb==</UUID><Name>Recycle Bin</Name>
        <Entry><String><Key>Title</Key><Value>Trashed</Value></String></Entry>
      </Group>
    </Group>
  </Root>
</KeePassFile>"#;

    #[test]
    fn xml_groups_entries_and_recycle_bin() {
        let b = import_keepass_xml(XML).unwrap();
        let names: Vec<_> = b.login_drafts.iter().map(|l| l.name.as_str()).collect();
        assert_eq!(names, vec!["Top", "Mail", "Deep"]);
        let top = &b.login_drafts[0];
        assert!(top.folder_id.is_none());
        assert_eq!(top.password.as_deref(), Some("p0"));
        assert_eq!(
            top.totp.as_deref(),
            Some("otpauth://totp/Top?secret=JBSWY3DPEHPK3PXP")
        );
        assert_eq!(top.notes.as_deref(), Some("n0\n\nCustom: extra-v"));
        let folders: Vec<_> = b.folders.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(folders, vec!["Email", "Email/Work"]);
    }

    #[test]
    fn xml_rejects_other_documents() {
        assert!(import_keepass_xml("<foo/>").is_err());
        assert!(import_keepass_xml("not xml").is_err());
    }

    #[test]
    fn keepassxc_csv() {
        let csv = "\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"TOTP\",\"Icon\",\"Last Modified\",\"Created\"\n\
\"Root/Social\",\"Mastodon\",\"me\",\"pw\",\"https://m.example\",\"hi\",\"\",\"0\",\"2024-01-01\",\"2024-01-01\"\n\
\"Recycle Bin\",\"Gone\",\"x\",\"y\",\"\",\"\",\"\",\"0\",\"\",\"\"\n\
\"Root\",\"Rootie\",\"r\",\"pr\",\"\",\"\",\"\",\"0\",\"\",\"\"\n";
        let b = import_keepass_csv(csv).unwrap();
        assert_eq!(b.login_drafts.len(), 2);
        assert_eq!(b.folders.len(), 1);
        assert_eq!(b.folders[0].name, "Social");
        assert!(b.login_drafts[1].folder_id.is_none());
    }

    #[test]
    fn keepass2_csv() {
        let csv = "\"Account\",\"Login Name\",\"Password\",\"Web Site\",\"Comments\"\n\"Bank\",\"jd\",\"pw\",\"https://bank.example\",\"c\"\n";
        let b = import_keepass_csv(csv).unwrap();
        assert_eq!(b.login_drafts[0].name, "Bank");
        assert_eq!(b.login_drafts[0].username.as_deref(), Some("jd"));
    }
}
