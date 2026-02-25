//! Incremental analysis — process only changed files, skip unchanged via content hash.

use std::path::PathBuf;

use drift_core::types::collections::FxHashMap;

use crate::scanner::types::ScanDiff;

/// Incremental analyzer that determines which files need re-analysis.
pub struct IncrementalAnalyzer {
    /// Content hashes from the last analysis run.
    previous_hashes: FxHashMap<String, u64>,
}

impl IncrementalAnalyzer {
    /// Create a new incremental analyzer.
    pub fn new() -> Self {
        Self {
            previous_hashes: FxHashMap::default(),
        }
    }

    /// Create with known previous hashes (loaded from storage).
    pub fn with_previous_hashes(hashes: FxHashMap<String, u64>) -> Self {
        Self {
            previous_hashes: hashes,
        }
    }

    /// Determine which files need analysis based on the scan diff.
    /// Returns paths that need re-analysis (added + modified).
    pub fn files_to_analyze(&self, diff: &ScanDiff) -> Vec<PathBuf> {
        let mut files = Vec::new();

        // Added files always need analysis
        files.extend(diff.added.iter().cloned());

        // Modified files need re-analysis
        files.extend(diff.modified.iter().cloned());

        files
    }

    /// Check if a specific file needs re-analysis based on content hash.
    /// L2 incremental: content-hash skip for unchanged files.
    pub fn needs_analysis(&self, file: &str, current_hash: u64) -> bool {
        match self.previous_hashes.get(file) {
            Some(&prev_hash) => prev_hash != current_hash,
            None => true, // New file, needs analysis
        }
    }

    /// Update the hash for a file after analysis.
    pub fn update_hash(&mut self, file: String, hash: u64) {
        self.previous_hashes.insert(file, hash);
    }

    /// Remove hashes for deleted files.
    pub fn remove_files(&mut self, files: &[PathBuf]) {
        for file in files {
            if let Some(path_str) = file.to_str() {
                self.previous_hashes.remove(path_str);
            }
        }
    }

    /// Number of tracked files.
    pub fn tracked_count(&self) -> usize {
        self.previous_hashes.len()
    }

    /// Get all tracked hashes (for persistence).
    pub fn hashes(&self) -> &FxHashMap<String, u64> {
        &self.previous_hashes
    }
}

impl Default for IncrementalAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
