//! Incremental scan logic: two-level mtime + content hash comparison.

use std::path::PathBuf;
use std::time::Instant;

use drift_core::types::collections::{FxHashMap, FxHashSet};

use super::hasher::hash_content;
use super::types::{
    CachedFileMetadata, DiscoveredFile, FileStatus, ScanDiff, ScanEntry, ScanStats,
};

/// Classify a single file against cached metadata using two-level detection.
///
/// Level 1: mtime comparison (catches ~95% unchanged files).
/// Level 2: content hash for mtime-changed files.
pub fn classify_file(
    file: &DiscoveredFile,
    cached: Option<&CachedFileMetadata>,
    force_full: bool,
) -> Result<(FileStatus, ScanEntry), std::io::Error> {
    let start = Instant::now();

    let (mtime_secs, mtime_nanos) = mtime_parts(&file.mtime);

    match cached {
        None => {
            // New file — not in cache
            let content = std::fs::read(&file.path)?;
            let content_hash = hash_content(&content);
            Ok((
                FileStatus::Added,
                ScanEntry {
                    path: file.path.clone(),
                    content_hash,
                    mtime_secs,
                    mtime_nanos,
                    file_size: file.file_size,
                    language: file.language,
                    scan_duration_us: start.elapsed().as_micros() as u64,
                },
            ))
        }
        Some(cached) => {
            // Level 1: mtime check
            if !force_full
                && mtime_secs == cached.mtime_secs
                && mtime_nanos == cached.mtime_nanos
            {
                return Ok((
                    FileStatus::Unchanged,
                    ScanEntry {
                        path: file.path.clone(),
                        content_hash: cached.content_hash,
                        mtime_secs,
                        mtime_nanos,
                        file_size: file.file_size,
                        language: file.language,
                        scan_duration_us: start.elapsed().as_micros() as u64,
                    },
                ));
            }

            // Level 2: content hash
            let content = std::fs::read(&file.path)?;
            let content_hash = hash_content(&content);
            let status = if content_hash == cached.content_hash {
                FileStatus::Unchanged
            } else {
                FileStatus::Modified
            };

            Ok((
                status,
                ScanEntry {
                    path: file.path.clone(),
                    content_hash,
                    mtime_secs,
                    mtime_nanos,
                    file_size: file.file_size,
                    language: file.language,
                    scan_duration_us: start.elapsed().as_micros() as u64,
                },
            ))
        }
    }
}

/// Compute the ScanDiff from classified entries and cached metadata.
pub fn compute_diff(
    entries: Vec<(FileStatus, ScanEntry)>,
    cached: &FxHashMap<PathBuf, CachedFileMetadata>,
    stats: ScanStats,
) -> ScanDiff {
    let mut diff = ScanDiff {
        stats,
        ..Default::default()
    };
    let mut seen_paths: FxHashSet<PathBuf> = FxHashSet::default();

    for (status, entry) in entries {
        seen_paths.insert(entry.path.clone());
        match status {
            FileStatus::Added => diff.added.push(entry.path.clone()),
            FileStatus::Modified => diff.modified.push(entry.path.clone()),
            FileStatus::Unchanged => diff.unchanged.push(entry.path.clone()),
        }
        diff.entries.insert(entry.path.clone(), entry);
    }

    // Files in cache but not on disk → removed
    for cached_path in cached.keys() {
        if !seen_paths.contains(cached_path) {
            diff.removed.push(cached_path.clone());
        }
    }

    // Sort for deterministic output
    diff.added.sort();
    diff.modified.sort();
    diff.removed.sort();
    diff.unchanged.sort();

    // Update stats
    diff.stats.total_files = diff.entries.len();
    diff.stats.total_size_bytes = diff.entries.values().map(|e| e.file_size).sum();

    diff
}

/// Extract mtime as (seconds, nanoseconds) from SystemTime.
fn mtime_parts(mtime: &std::time::SystemTime) -> (i64, u32) {
    match mtime.duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => (d.as_secs() as i64, d.subsec_nanos()),
        Err(_) => (0, 0),
    }
}
