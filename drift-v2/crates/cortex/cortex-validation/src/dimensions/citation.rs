//! Citation validation: file existence, content hash drift, line number validity.
//!
//! Checks that file links in a memory still point to valid, unchanged content.
//! Supports git rename detection for auto-updating citations.

use cortex_core::memory::BaseMemory;
use cortex_core::models::{HealingAction, HealingActionType};

/// Result of citation validation for a single memory.
#[derive(Debug, Clone)]
pub struct CitationValidationResult {
    /// Score from 0.0 (all citations invalid) to 1.0 (all valid).
    pub score: f64,
    /// Healing actions needed.
    pub healing_actions: Vec<HealingAction>,
    /// Details per file link.
    pub details: Vec<CitationDetail>,
}

/// Validation detail for a single file citation.
#[derive(Debug, Clone)]
pub struct CitationDetail {
    pub file_path: String,
    pub exists: bool,
    pub content_hash_matches: Option<bool>,
    pub line_numbers_valid: Option<bool>,
    pub renamed_to: Option<String>,
}

/// Validate all file citations in a memory.
///
/// `file_checker`: callback that checks if a file exists and returns its current content hash.
/// `rename_detector`: callback that checks if a file was renamed (git mv detection).
pub fn validate(
    memory: &BaseMemory,
    file_checker: &dyn Fn(&str) -> Option<FileInfo>,
    rename_detector: &dyn Fn(&str) -> Option<String>,
) -> CitationValidationResult {
    if memory.linked_files.is_empty() {
        return CitationValidationResult {
            score: 1.0,
            healing_actions: vec![],
            details: vec![],
        };
    }

    let mut valid_count = 0;
    let mut total_count = 0;
    let mut healing_actions = Vec::new();
    let mut details = Vec::new();

    for file_link in &memory.linked_files {
        total_count += 1;

        match file_checker(&file_link.file_path) {
            Some(info) => {
                let mut detail = CitationDetail {
                    file_path: file_link.file_path.clone(),
                    exists: true,
                    content_hash_matches: None,
                    line_numbers_valid: None,
                    renamed_to: None,
                };

                // Check content hash drift.
                let hash_ok = match (&file_link.content_hash, &info.content_hash) {
                    (Some(expected), Some(actual)) => {
                        let matches = expected == actual;
                        detail.content_hash_matches = Some(matches);
                        if !matches {
                            healing_actions.push(HealingAction {
                                action_type: HealingActionType::EmbeddingRefresh,
                                description: format!(
                                    "Content hash drift in {}: re-embed memory",
                                    file_link.file_path
                                ),
                                applied: false,
                            });
                        }
                        matches
                    }
                    _ => true, // No hash to compare.
                };

                // Check line number validity.
                let lines_ok = match (file_link.line_start, info.total_lines) {
                    (Some(start), Some(total)) => {
                        let valid = start <= total;
                        detail.line_numbers_valid = Some(valid);
                        if !valid {
                            healing_actions.push(HealingAction {
                                action_type: HealingActionType::CitationUpdate,
                                description: format!(
                                    "Line {} exceeds file length {} in {}",
                                    start, total, file_link.file_path
                                ),
                                applied: false,
                            });
                        }
                        valid
                    }
                    _ => true,
                };

                if hash_ok && lines_ok {
                    valid_count += 1;
                }

                details.push(detail);
            }
            None => {
                // File doesn't exist — check for rename.
                let renamed_to = rename_detector(&file_link.file_path);

                let detail = CitationDetail {
                    file_path: file_link.file_path.clone(),
                    exists: false,
                    content_hash_matches: None,
                    line_numbers_valid: None,
                    renamed_to: renamed_to.clone(),
                };

                if let Some(new_path) = renamed_to {
                    healing_actions.push(HealingAction {
                        action_type: HealingActionType::CitationUpdate,
                        description: format!(
                            "File renamed: {} → {}",
                            file_link.file_path, new_path
                        ),
                        applied: false,
                    });
                    // Renamed files count as partially valid.
                    valid_count += 1;
                } else {
                    healing_actions.push(HealingAction {
                        action_type: HealingActionType::ConfidenceAdjust,
                        description: format!("File not found: {}", file_link.file_path),
                        applied: false,
                    });
                }

                details.push(detail);
            }
        }
    }

    let score = if total_count > 0 {
        valid_count as f64 / total_count as f64
    } else {
        1.0
    };

    CitationValidationResult {
        score,
        healing_actions,
        details,
    }
}

/// Information about a file on disk.
pub struct FileInfo {
    pub content_hash: Option<String>,
    pub total_lines: Option<u32>,
}
