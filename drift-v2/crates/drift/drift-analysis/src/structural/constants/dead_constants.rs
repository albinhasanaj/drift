//! Phase 5: Dead constant detection via call graph integration.
//!
//! A dead constant is one that is defined but never referenced anywhere
//! in the codebase. Detection requires cross-referencing constant names
//! against all usage sites (imports, function bodies, etc.).

use drift_core::types::collections::FxHashSet;

use super::types::Constant;

/// Detect dead (unused) constants.
///
/// Takes a list of constants and a set of all referenced names in the codebase.
/// Any constant whose name does not appear in the referenced set is dead.
pub fn detect_dead_constants(
    constants: &[Constant],
    referenced_names: &FxHashSet<String>,
) -> Vec<Constant> {
    constants
        .iter()
        .filter(|c| !referenced_names.contains(&c.name))
        .cloned()
        .map(|mut c| {
            c.is_used = false;
            c
        })
        .collect()
}

/// Build a set of all referenced names from source content.
///
/// This is a simplified approach — in production, this would use the
/// resolution index from the analysis engine for precise cross-referencing.
pub fn collect_referenced_names(files: &[(&str, &str)]) -> FxHashSet<String> {
    let mut names = FxHashSet::default();

    for (_file_path, content) in files {
        for line in content.lines() {
            // Extract identifiers from the line
            let mut chars = line.chars().peekable();
            while let Some(&ch) = chars.peek() {
                if ch.is_alphabetic() || ch == '_' {
                    let mut ident = String::new();
                    while let Some(&c) = chars.peek() {
                        if c.is_alphanumeric() || c == '_' {
                            ident.push(c);
                            chars.next();
                        } else {
                            break;
                        }
                    }
                    if !ident.is_empty() {
                        names.insert(ident);
                    }
                } else {
                    chars.next();
                }
            }
        }
    }

    names
}
