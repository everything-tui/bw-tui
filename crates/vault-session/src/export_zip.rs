//! Bitwarden-style ZIP export: `data.json` plus `attachments/<cipherId>/<fileName>`.

use std::collections::HashSet;
use std::io::{Cursor, Write};

use zip::write::SimpleFileOptions;
use zip::ZipWriter;

use crate::error::{Result, SessionError};
use crate::export::export_json;
use crate::models::{DecryptedFolder, DecryptedItem};
use crate::session::Session;

/// A decrypted attachment ready to be written into an export archive.
#[derive(Debug, Clone)]
pub struct ExportAttachment {
    pub cipher_id: String,
    pub file_name: String,
    pub data: Vec<u8>,
}

/// Build a ZIP archive containing the unencrypted JSON export and all attachments.
pub fn export_zip(
    items: &[DecryptedItem],
    folders: &[DecryptedFolder],
    attachments: &[ExportAttachment],
) -> Result<Vec<u8>> {
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    zip.start_file("data.json", opts).map_err(zip_err)?;
    zip.write_all(export_json(items, folders).as_bytes())
        .map_err(|e| SessionError::Other(e.to_string()))?;

    let mut used: HashSet<String> = HashSet::new();
    for att in attachments {
        let safe = sanitize_file_name(&att.file_name);
        let mut name = safe.clone();
        let mut n = 1;
        while !used.insert(format!("{}/{}", att.cipher_id, name)) {
            n += 1;
            name = match safe.rsplit_once('.') {
                Some((stem, ext)) => format!("{stem} ({n}).{ext}"),
                None => format!("{safe} ({n})"),
            };
        }
        let path = format!(
            "attachments/{}/{}",
            sanitize_file_name(&att.cipher_id),
            name
        );
        zip.start_file(path, opts).map_err(zip_err)?;
        zip.write_all(&att.data)
            .map_err(|e| SessionError::Other(e.to_string()))?;
    }

    let cursor = zip.finish().map_err(zip_err)?;
    Ok(cursor.into_inner())
}

/// Download and decrypt every attachment of every non-deleted item (requires an online,
/// unlocked session). Returns the attachments plus per-file warnings for failures.
pub async fn collect_attachments(
    session: &mut Session,
) -> Result<(Vec<ExportAttachment>, Vec<String>)> {
    let ids: Vec<(String, String)> = session
        .items()
        .iter()
        .filter(|i| !i.deleted)
        .map(|i| (i.id.clone(), i.name.clone()))
        .collect();
    let tmp = std::env::temp_dir().join(format!("bw-tui-export-{}", uuid::Uuid::new_v4()));
    let mut out = Vec::new();
    let mut warnings = Vec::new();
    for (id, name) in ids {
        let list = match session.list_attachments(&id) {
            Ok(l) => l,
            Err(e) => {
                warnings.push(format!("{name}: list attachments failed: {e}"));
                continue;
            }
        };
        for att in list {
            let dest = tmp.join(sanitize_file_name(&att.id));
            match session.download_attachment(&id, &att.id, &dest).await {
                Ok(()) => match std::fs::read(&dest) {
                    Ok(data) => out.push(ExportAttachment {
                        cipher_id: id.clone(),
                        file_name: att.file_name.clone(),
                        data,
                    }),
                    Err(e) => warnings.push(format!("{name}/{}: read failed: {e}", att.file_name)),
                },
                Err(e) => warnings.push(format!("{name}/{}: download failed: {e}", att.file_name)),
            }
            let _ = std::fs::remove_file(&dest);
        }
    }
    let _ = std::fs::remove_dir_all(&tmp);
    Ok((out, warnings))
}

fn sanitize_file_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if matches!(c, '/' | '\\' | '\0' | ':') {
                '_'
            } else {
                c
            }
        })
        .collect();
    let cleaned = cleaned.trim().trim_start_matches('.').to_string();
    if cleaned.is_empty() {
        "attachment".into()
    } else {
        cleaned
    }
}

fn zip_err(e: zip::result::ZipError) -> SessionError {
    SessionError::Other(format!("zip: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn zip_contains_data_and_attachments() {
        let atts = vec![
            ExportAttachment {
                cipher_id: "c1".into(),
                file_name: "../evil.txt".into(),
                data: b"hello".to_vec(),
            },
            ExportAttachment {
                cipher_id: "c1".into(),
                file_name: "../evil.txt".into(),
                data: b"again".to_vec(),
            },
        ];
        let bytes = export_zip(&[], &[], &atts).unwrap();
        let mut ar = zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
        let mut names: Vec<String> = ar.file_names().map(str::to_string).collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                "attachments/c1/_evil (2).txt".to_string(),
                "attachments/c1/_evil.txt".to_string(),
                "data.json".to_string(),
            ]
        );
        let mut s = String::new();
        ar.by_name("data.json")
            .unwrap()
            .read_to_string(&mut s)
            .unwrap();
        assert!(s.contains("\"items\""));
    }
}
