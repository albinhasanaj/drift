//! Scanner data types: ScanEntry, ScanDiff, ScanStats.

use std::path::PathBuf;
use std::time::SystemTime;

use drift_core::types::collections::FxHashMap;
use serde::{Deserialize, Serialize};

use super::language_detect::Language;

/// Metadata for a single discovered file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanEntry {
    pub path: PathBuf,
    pub content_hash: u64,
    pub mtime_secs: i64,
    pub mtime_nanos: u32,
    pub file_size: u64,
    pub language: Option<Language>,
    pub scan_duration_us: u64,
}

/// The primary output of a scan operation. Classifies every file relative to the last scan.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanDiff {
    pub added: Vec<PathBuf>,
    pub modified: Vec<PathBuf>,
    pub removed: Vec<PathBuf>,
    pub unchanged: Vec<PathBuf>,
    pub errors: Vec<String>,
    pub stats: ScanStats,
    pub entries: FxHashMap<PathBuf, ScanEntry>,
}

/// Aggregate statistics for a scan operation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanStats {
    pub total_files: usize,
    pub total_size_bytes: u64,
    pub discovery_ms: u64,
    pub hashing_ms: u64,
    pub diff_ms: u64,
    pub cache_hit_rate: f64,
    pub files_skipped_large: usize,
    pub files_skipped_ignored: usize,
    pub files_skipped_binary: usize,
    pub languages_found: FxHashMap<Language, usize>,
}

/// Intermediate type during discovery phase.
#[derive(Debug, Clone)]
pub struct DiscoveredFile {
    pub path: PathBuf,
    pub file_size: u64,
    pub mtime: SystemTime,
    pub language: Option<Language>,
}

/// File classification during incremental comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileStatus {
    Added,
    Modified,
    Unchanged,
}

/// Cached file metadata from a previous scan (loaded from storage).
#[derive(Debug, Clone)]
pub struct CachedFileMetadata {
    pub path: PathBuf,
    pub content_hash: u64,
    pub mtime_secs: i64,
    pub mtime_nanos: u32,
    pub file_size: u64,
    pub language: Option<Language>,
}
