//! Workspace status — comprehensive view of workspace state.

use std::path::Path;

use rusqlite::Connection;
use serde::Serialize;

use super::context::WorkspaceContext;
use super::errors::WorkspaceResult;
use super::project::{get_active_project, HealthStatus, ProjectInfo};

/// Workspace status — comprehensive view of workspace state.
#[derive(Debug, Clone, Serialize)]
pub struct WorkspaceStatus {
    pub initialized: bool,
    pub active_project: Option<ProjectInfo>,
    pub context_loaded: bool,
    pub migration_needed: bool,
    pub schema_version: u32,
    pub backup_count: u32,
    pub health_status: HealthStatus,
    pub disk_usage: Option<DiskUsage>,
    pub workspace_layout: WorkspaceLayoutInfo,
    pub lock_status: LockStatus,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiskUsage {
    pub drift_db_bytes: u64,
    pub cortex_db_bytes: u64,
    pub backups_bytes: u64,
    pub cache_bytes: u64,
    pub total_bytes: u64,
    pub reclaimable_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub enum WorkspaceLayoutInfo {
    SingleProject,
    Monorepo { package_count: u32 },
}

#[derive(Debug, Clone, Serialize)]
pub enum LockStatus {
    Unlocked,
    ReadLocked,
    WriteLocked,
}

/// Calculate health status from workspace context.
pub fn calculate_health(ctx: &WorkspaceContext) -> HealthStatus {
    if ctx.project.last_scan_at.is_none() {
        return HealthStatus::Unknown;
    }

    let mut score = 100i32;

    // No call graph → -15
    if !ctx.analysis.call_graph_built {
        score -= 15;
    }

    // No test topology → -10
    if !ctx.analysis.test_topology_built {
        score -= 10;
    }

    // No constraints → -10
    if !ctx.analysis.constraints_mined {
        score -= 10;
    }

    // No security scan → -10
    if !ctx.analysis.security_scanned {
        score -= 10;
    }

    match score {
        70..=100 => HealthStatus::Healthy,
        40..=69 => HealthStatus::Warning,
        _ => HealthStatus::Critical,
    }
}

/// Get comprehensive workspace status.
pub fn workspace_status(
    conn: &Connection,
    drift_path: &Path,
) -> WorkspaceResult<WorkspaceStatus> {
    let active_project = get_active_project(conn)?;
    let context = super::context::get_workspace_context(conn).ok();
    let health = context
        .as_ref()
        .map(calculate_health)
        .unwrap_or(HealthStatus::Unknown);

    let schema_version: u32 = conn
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap_or(0);

    let backup_count: u32 = conn
        .query_row("SELECT COUNT(*) FROM backup_registry", [], |row| {
            row.get(0)
        })
        .unwrap_or(0);

    let package_count: u32 = conn
        .query_row("SELECT COUNT(*) FROM workspace_packages", [], |row| {
            row.get(0)
        })
        .unwrap_or(0);

    let disk_usage = get_disk_usage(conn, drift_path).ok();

    Ok(WorkspaceStatus {
        initialized: true,
        active_project,
        context_loaded: context.is_some(),
        migration_needed: false,
        schema_version,
        backup_count,
        health_status: health,
        disk_usage,
        workspace_layout: if package_count > 0 {
            WorkspaceLayoutInfo::Monorepo { package_count }
        } else {
            WorkspaceLayoutInfo::SingleProject
        },
        lock_status: LockStatus::Unlocked,
    })
}

/// Get disk usage breakdown.
pub fn get_disk_usage(conn: &Connection, drift_path: &Path) -> WorkspaceResult<DiskUsage> {
    let page_count: u64 = conn
        .pragma_query_value(None, "page_count", |row| row.get(0))
        .unwrap_or(0);
    let page_size: u64 = conn
        .pragma_query_value(None, "page_size", |row| row.get(0))
        .unwrap_or(4096);
    let freelist: u64 = conn
        .pragma_query_value(None, "freelist_count", |row| row.get(0))
        .unwrap_or(0);

    let drift_db_bytes = page_count * page_size;
    let reclaimable_bytes = freelist * page_size;

    let cortex_db_path = drift_path.join("cortex.db");
    let cortex_db_bytes = if cortex_db_path.exists() {
        std::fs::metadata(&cortex_db_path).map(|m| m.len()).unwrap_or(0)
    } else {
        0
    };

    let backup_dir = drift_path
        .parent()
        .unwrap_or(drift_path)
        .join(".drift-backups");
    let backups_bytes = dir_size(&backup_dir).unwrap_or(0);

    let cache_dir = drift_path.join("cache");
    let cache_bytes = dir_size(&cache_dir).unwrap_or(0);

    Ok(DiskUsage {
        drift_db_bytes,
        cortex_db_bytes,
        backups_bytes,
        cache_bytes,
        total_bytes: drift_db_bytes + cortex_db_bytes + backups_bytes + cache_bytes,
        reclaimable_bytes,
    })
}

/// Calculate total size of a directory recursively.
fn dir_size(path: &Path) -> Result<u64, std::io::Error> {
    if !path.exists() {
        return Ok(0);
    }
    let mut total = 0u64;
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            total += dir_size(&entry.path())?;
        } else {
            total += metadata.len();
        }
    }
    Ok(total)
}
