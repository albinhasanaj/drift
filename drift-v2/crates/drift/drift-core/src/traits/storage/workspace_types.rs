//! Supporting types for `IWorkspaceStorage` trait.

/// Workspace status information.
#[derive(Debug, Clone)]
pub struct WorkspaceStatus {
    pub initialized: bool,
    pub db_path: Option<String>,
    pub schema_version: u32,
    pub file_count: i64,
    pub db_size_bytes: u64,
    pub wal_size_bytes: u64,
}

/// Project information within a workspace.
#[derive(Debug, Clone)]
pub struct ProjectInfo {
    pub root_path: String,
    pub name: String,
    pub language_breakdown: Vec<(String, u64)>,
    pub total_files: i64,
    pub total_functions: i64,
    pub total_patterns: i64,
    pub last_scan_at: Option<i64>,
}

/// Workspace context for AI/MCP consumption.
#[derive(Debug, Clone)]
pub struct WorkspaceContext {
    pub root_path: String,
    pub languages: Vec<String>,
    pub frameworks: Vec<String>,
    pub file_count: i64,
    pub function_count: i64,
    pub pattern_count: i64,
    pub boundary_count: i64,
    pub detection_count: i64,
}

/// Garbage collection statistics.
#[derive(Debug, Clone, Default)]
pub struct GcStats {
    pub orphan_files_removed: u64,
    pub stale_cache_entries_removed: u64,
    pub wal_checkpointed: bool,
    pub freed_bytes: u64,
}

/// Backup result.
#[derive(Debug, Clone)]
pub struct BackupResult {
    pub destination: String,
    pub size_bytes: u64,
    pub duration_ms: u64,
}

/// Integrity check result.
#[derive(Debug, Clone)]
pub struct IntegrityResult {
    pub ok: bool,
    pub issues: Vec<String>,
}

/// Error returned when an operation is not supported by the backend.
/// Cloud backends return this for SQLite-specific operations like backup.
#[derive(Debug, Clone)]
pub struct NotSupportedError {
    pub operation: String,
    pub reason: String,
}

impl std::fmt::Display for NotSupportedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "operation '{}' not supported: {}", self.operation, self.reason)
    }
}

impl std::error::Error for NotSupportedError {}
