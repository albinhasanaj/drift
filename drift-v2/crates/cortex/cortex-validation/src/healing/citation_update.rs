//! Auto-update citations via git rename detection.

use cortex_core::memory::BaseMemory;

/// Update file citations in a memory when files have been renamed.
///
/// `rename_map`: maps old file paths to new file paths.
///
/// Returns the number of citations updated.
pub fn update_citations(
    memory: &mut BaseMemory,
    rename_map: &std::collections::HashMap<String, String>,
) -> usize {
    let mut updated = 0;

    for file_link in &mut memory.linked_files {
        if let Some(new_path) = rename_map.get(&file_link.file_path) {
            file_link.file_path = new_path.clone();
            // Clear the content hash since the file content may have changed.
            file_link.content_hash = None;
            updated += 1;
        }
    }

    // Also update function links that reference renamed files.
    for func_link in &mut memory.linked_functions {
        if let Some(new_path) = rename_map.get(&func_link.file_path) {
            func_link.file_path = new_path.clone();
            updated += 1;
        }
    }

    updated
}
