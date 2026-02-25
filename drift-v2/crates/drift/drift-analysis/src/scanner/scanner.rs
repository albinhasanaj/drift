//! Top-level Scanner struct orchestrating walker → hasher → language detect → incremental → diff.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use drift_core::config::ScanConfig;
use drift_core::errors::ScanError;
use drift_core::events::handler::DriftEventHandler;
use drift_core::events::types::*;
use drift_core::types::collections::FxHashMap;
use rayon::prelude::*;

use super::cancellation::ScanCancellation;
use super::incremental::{classify_file, compute_diff};
use super::types::{CachedFileMetadata, DiscoveredFile, ScanDiff, ScanStats};
use super::walker;

/// The top-level scanner that orchestrates file discovery, hashing, and incremental detection.
pub struct Scanner {
    config: ScanConfig,
    cancellation: ScanCancellation,
}

impl Scanner {
    /// Create a new scanner with the given configuration.
    pub fn new(config: ScanConfig) -> Self {
        Self {
            config,
            cancellation: ScanCancellation::new(),
        }
    }

    /// Get a reference to the cancellation handle for external cancellation.
    pub fn cancellation(&self) -> &ScanCancellation {
        &self.cancellation
    }

    /// Perform a full scan of the given root directory.
    ///
    /// If `cached_metadata` is provided, performs incremental detection.
    /// Emits events via the provided event handler.
    pub fn scan(
        &self,
        root: &Path,
        cached_metadata: &FxHashMap<PathBuf, CachedFileMetadata>,
        event_handler: &dyn DriftEventHandler,
    ) -> Result<ScanDiff, ScanError> {
        self.cancellation.reset();

        // Emit scan started
        event_handler.on_scan_started(&ScanStartedEvent {
            root: root.to_path_buf(),
            file_count: None,
        });

        // Phase 1: Discovery
        let discovery_start = Instant::now();
        let files = match walker::walk_directory(
            root,
            &self.config,
            self.cancellation.as_atomic(),
        ) {
            Ok(files) => files,
            Err(e) => {
                event_handler.on_scan_error(&ScanErrorEvent {
                    message: e.to_string(),
                });
                return Err(e);
            }
        };
        let discovery_ms = discovery_start.elapsed().as_millis() as u64;

        if self.cancellation.is_cancelled() {
            return Ok(self.partial_diff(&files, cached_metadata, discovery_ms));
        }

        // Emit progress with total count
        event_handler.on_scan_progress(&ScanProgressEvent {
            processed: 0,
            total: files.len(),
        });

        // Phase 2: Processing (hash + classify)
        let hashing_start = Instant::now();
        let force_full = self.config.force_full_scan.unwrap_or(false);
        let processed = AtomicUsize::new(0);
        let total = files.len();
        let errors = Vec::new();

        let entries: Vec<_> = files
            .par_iter()
            .filter_map(|file| {
                if self.cancellation.is_cancelled() {
                    return None;
                }

                let count = processed.fetch_add(1, Ordering::Relaxed);
                if count % 100 == 0 {
                    event_handler.on_scan_progress(&ScanProgressEvent {
                        processed: count,
                        total,
                    });
                }

                let cached = cached_metadata.get(&file.path);
                match classify_file(file, cached, force_full) {
                    Ok(result) => Some(result),
                    Err(e) => {
                        // Non-fatal — skip file, continue scanning
                        tracing::warn!(
                            path = %file.path.display(),
                            error = %e,
                            "file scan error"
                        );
                        None
                    }
                }
            })
            .collect();

        let hashing_ms = hashing_start.elapsed().as_millis() as u64;

        // Phase 3: Compute diff
        let diff_start = Instant::now();

        // Compute language stats
        let mut languages_found = FxHashMap::default();
        for (_, entry) in &entries {
            if let Some(lang) = entry.language {
                *languages_found.entry(lang).or_insert(0usize) += 1;
            }
        }

        // Compute cache hit rate
        let mtime_hits = entries
            .iter()
            .filter(|(status, _)| *status == super::types::FileStatus::Unchanged)
            .count();
        let cache_hit_rate = if total > 0 {
            mtime_hits as f64 / total as f64
        } else {
            0.0
        };

        let stats = ScanStats {
            total_files: entries.len(),
            total_size_bytes: entries.iter().map(|(_, e)| e.file_size).sum(),
            discovery_ms,
            hashing_ms,
            diff_ms: 0, // Updated below
            cache_hit_rate,
            files_skipped_large: 0,
            files_skipped_ignored: 0,
            files_skipped_binary: 0,
            languages_found,
        };

        let mut diff = compute_diff(entries, cached_metadata, stats);
        diff.stats.diff_ms = diff_start.elapsed().as_millis() as u64;
        diff.errors = errors.to_vec();

        // Emit scan complete
        event_handler.on_scan_complete(&ScanCompleteEvent {
            added: diff.added.len(),
            modified: diff.modified.len(),
            removed: diff.removed.len(),
            unchanged: diff.unchanged.len(),
            duration_ms: discovery_ms + hashing_ms + diff.stats.diff_ms,
        });

        Ok(diff)
    }

    /// Build a partial diff when scan is cancelled mid-way.
    fn partial_diff(
        &self,
        _files: &[DiscoveredFile],
        cached_metadata: &FxHashMap<PathBuf, CachedFileMetadata>,
        discovery_ms: u64,
    ) -> ScanDiff {
        let stats = ScanStats {
            discovery_ms,
            ..Default::default()
        };
        compute_diff(Vec::new(), cached_metadata, stats)
    }
}
