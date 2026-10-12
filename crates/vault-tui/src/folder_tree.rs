//! Nested folder labels for the sidebar (uses `/` in folder names as hierarchy).

use crate::models::{FilterKind, FolderView, SidebarEntry};

/// Expand flat folders into indented sidebar rows (e.g. `Work/Projects` → two levels).
pub fn nested_folder_entries(folders: &[FolderView]) -> Vec<SidebarEntry> {
    let mut entries = Vec::new();
    let mut sorted: Vec<_> = folders
        .iter()
        .filter(|f| f.id.is_some())
        .collect();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));

    for folder in sorted {
        let Some(id) = folder.id.clone() else {
            continue;
        };
        let depth = folder.name.matches('/').count();
        let leaf = folder.name.rsplit('/').next().unwrap_or(&folder.name);
        let indent = "  ".repeat(depth);
        entries.push(SidebarEntry {
            label: format!("{indent}{leaf}"),
            kind: FilterKind::Folder(id),
            count: folder.count,
        });
    }
    entries
}
