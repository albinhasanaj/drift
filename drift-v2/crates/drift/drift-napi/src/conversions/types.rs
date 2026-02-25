//! Rust ↔ JS type conversions.
//!
//! Types annotated with `#[napi(object)]` get automatic TypeScript type generation.
//! These are the lightweight summaries that cross the NAPI boundary — full results
//! stay in Rust/SQLite and are queried on demand.

use std::collections::HashMap;

use napi_derive::napi;

use drift_analysis::scanner::types::{ScanDiff, ScanStats};

// ---- Scan Types ----

/// Options for a scan operation, passed from TypeScript.
#[napi(object)]
#[derive(Debug, Clone, Default)]
pub struct ScanOptions {
    /// Force full rescan, ignoring mtime optimization.
    pub force_full: Option<bool>,
    /// Maximum file size in bytes.
    pub max_file_size: Option<i64>,
    /// Include glob patterns — if non-empty, only matching paths are scanned.
    pub include: Option<Vec<String>>,
    /// Additional ignore/exclude patterns.
    pub extra_ignore: Option<Vec<String>>,
    /// Follow symbolic links.
    pub follow_symlinks: Option<bool>,
}

/// Lightweight scan summary returned to TypeScript.
/// Full results are persisted to drift.db — TS queries them on demand.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct ScanSummary {
    pub files_total: u32,
    pub files_added: u32,
    pub files_modified: u32,
    pub files_removed: u32,
    pub files_unchanged: u32,
    pub errors_count: u32,
    pub duration_ms: u32,
    pub status: String,
    pub languages: HashMap<String, u32>,
}

impl From<&ScanDiff> for ScanSummary {
    fn from(diff: &ScanDiff) -> Self {
        let total_ms = diff.stats.discovery_ms + diff.stats.hashing_ms + diff.stats.diff_ms;

        let mut languages = HashMap::new();
        for (lang, count) in &diff.stats.languages_found {
            languages.insert(format!("{lang:?}"), *count as u32);
        }

        Self {
            files_total: diff.stats.total_files as u32,
            files_added: diff.added.len() as u32,
            files_modified: diff.modified.len() as u32,
            files_removed: diff.removed.len() as u32,
            files_unchanged: diff.unchanged.len() as u32,
            errors_count: diff.errors.len() as u32,
            duration_ms: total_ms as u32,
            status: if diff.errors.is_empty() {
                "complete".to_string()
            } else {
                "partial".to_string()
            },
            languages,
        }
    }
}

/// Detailed scan statistics returned to TypeScript.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct ScanStatsJs {
    pub total_files: u32,
    pub total_size_bytes: f64,
    pub discovery_ms: u32,
    pub hashing_ms: u32,
    pub diff_ms: u32,
    pub cache_hit_rate: f64,
    pub files_skipped_large: u32,
    pub files_skipped_ignored: u32,
    pub files_skipped_binary: u32,
}

impl From<&ScanStats> for ScanStatsJs {
    fn from(stats: &ScanStats) -> Self {
        Self {
            total_files: stats.total_files as u32,
            total_size_bytes: stats.total_size_bytes as f64,
            discovery_ms: stats.discovery_ms as u32,
            hashing_ms: stats.hashing_ms as u32,
            diff_ms: stats.diff_ms as u32,
            cache_hit_rate: stats.cache_hit_rate,
            files_skipped_large: stats.files_skipped_large as u32,
            files_skipped_ignored: stats.files_skipped_ignored as u32,
            files_skipped_binary: stats.files_skipped_binary as u32,
        }
    }
}

/// Progress update sent to TypeScript via ThreadsafeFunction.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct ProgressUpdate {
    pub processed: u32,
    pub total: u32,
    pub phase: String,
    pub current_file: Option<String>,
}
