//! Workspace management — project lifecycle orchestrator.
//!
//! This is the first thing that runs on every CLI command, every MCP tool call,
//! every IDE interaction. Without it, there is no `.drift/` directory, no `drift.db`,
//! no configuration, no project context — nothing works.
//!
//! ## Components
//! - **init** — Workspace initialization (`.drift/`, `drift.db`, `drift.toml`)
//! - **migration** — Schema migration via `PRAGMA user_version`
//! - **backup** — Hot backup via SQLite Backup API with tiered retention
//! - **lock** — Workspace locking via `fd-lock` for concurrent access safety
//! - **project** — Multi-project switching with health indicators
//! - **monorepo** — Monorepo workspace detection and per-package partitioning
//! - **context** — Event-driven context refresh (zero staleness)
//! - **detect** — Language and framework auto-detection
//! - **status** — Comprehensive workspace status
//! - **integrity** — Workspace integrity check and recovery
//! - **gc** — Garbage collection and size management
//! - **destructive** — Destructive operation safety (auto-backup + confirmation)
//! - **ci** — CI environment detection
//! - **export** — Workspace export/import for portability

pub mod backup;
pub mod ci;
pub mod context;
pub mod destructive;
pub mod detect;
pub mod errors;
pub mod export;
pub mod gc;
pub mod init;
pub mod integrity;
pub mod lock;
pub mod migration;
pub mod monorepo;
pub mod project;
pub mod sqlite_storage;
pub mod status;

// Re-export the most commonly used types.
pub use sqlite_storage::SqliteWorkspaceStorage;
pub use backup::{BackupConfig, BackupManager, BackupManifest, BackupReason, BackupTier};
pub use ci::{detect_ci_environment, is_ci, CIEnvironment};
pub use context::{get_agent_context, get_workspace_context, refresh_workspace_context};
pub use errors::{WorkspaceError, WorkspaceResult};
pub use gc::{garbage_collect, GCOptions, GCReport};
pub use init::{is_initialized, open_workspace, workspace_init, InitOptions, WorkspaceInfo};
pub use integrity::{auto_recover, verify_workspace, IntegrityReport};
pub use lock::WorkspaceLock;
pub use migration::{get_schema_version, initialize_workspace_db};
pub use monorepo::{detect_workspace, WorkspaceLayout};
pub use project::{
    format_project_header, format_project_indicator, get_active_project, list_projects,
    resolve_project, switch_project, HealthStatus, ProjectInfo,
};
pub use status::{workspace_status, DiskUsage, WorkspaceStatus};
