//! Scanner configuration.

use serde::{Deserialize, Serialize};

/// Configuration for the file scanner subsystem.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ScanConfig {
    /// Maximum file size in bytes. Default: 1MB (1_048_576).
    pub max_file_size: Option<u64>,
    /// Number of threads. 0 = auto-detect via num_cpus.
    pub threads: Option<usize>,
    /// Include glob patterns — if non-empty, only matching paths are scanned.
    /// Patterns use gitignore syntax (e.g., "src/**", "lib/**").
    #[serde(default)]
    pub include: Vec<String>,
    /// Additional ignore patterns beyond .gitignore/.driftignore.
    #[serde(default)]
    pub extra_ignore: Vec<String>,
    /// Follow symbolic links. Default: false.
    pub follow_symlinks: Option<bool>,
    /// Compute content hashes. Default: true.
    pub compute_hashes: Option<bool>,
    /// Force full rescan, skip mtime optimization. Default: false.
    pub force_full_scan: Option<bool>,
    /// Skip binary files. Default: true.
    pub skip_binary: Option<bool>,
    /// Hash algorithm. Default: "xxh3".
    pub hash_algorithm: Option<String>,
    /// Path to .driftignore file.
    pub driftignore_path: Option<String>,
    /// Enable incremental scanning. Default: true.
    pub incremental: Option<bool>,
    /// Parallelism level for scanning.
    pub parallelism: Option<usize>,
}

impl ScanConfig {
    /// Returns the effective max file size, defaulting to 1MB.
    pub fn effective_max_file_size(&self) -> u64 {
        self.max_file_size.unwrap_or(1_048_576)
    }

    /// Returns the effective thread count, defaulting to 0 (auto-detect).
    pub fn effective_threads(&self) -> usize {
        self.threads.unwrap_or(0)
    }

    /// Returns whether incremental scanning is enabled, defaulting to true.
    pub fn effective_incremental(&self) -> bool {
        self.incremental.unwrap_or(true)
    }
}
