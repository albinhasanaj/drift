//! Garbage collection and size management.
//! Incremental vacuum, old event cleanup, orphaned cache removal.

use std::path::Path;

use rusqlite::Connection;
use serde::Serialize;

use super::errors::WorkspaceResult;

/// GC configuration options.
#[derive(Debug, Clone)]
pub struct GCOptions {
    pub max_pages: u32,
    pub retention_days: u32,
    pub dry_run: bool,
}

impl Default for GCOptions {
    fn default() -> Self {
        Self {
            max_pages: 0,
            retention_days: 90,
            dry_run: false,
        }
    }
}

/// GC report — what was cleaned and how much space was freed.
#[derive(Debug, Clone, Serialize)]
pub struct GCReport {
    pub pages_freed: u64,
    pub bytes_freed: u64,
    pub old_events_deleted: u64,
    pub orphaned_files_deleted: u64,
    pub duration_ms: u64,
}

/// Run garbage collection on the workspace.
pub fn garbage_collect(
    conn: &Connection,
    drift_path: &Path,
    opts: GCOptions,
) -> WorkspaceResult<GCReport> {
    let start = std::time::Instant::now();
    let mut report = GCReport {
        pages_freed: 0,
        bytes_freed: 0,
        old_events_deleted: 0,
        orphaned_files_deleted: 0,
        duration_ms: 0,
    };

    let page_size: u64 = conn
        .pragma_query_value(None, "page_size", |row| row.get(0))
        .unwrap_or(4096);

    if opts.dry_run {
        let freelist: u64 = conn
            .pragma_query_value(None, "freelist_count", |row| row.get(0))
            .unwrap_or(0);
        report.pages_freed = freelist;
        report.bytes_freed = freelist * page_size;

        report.old_events_deleted = conn
            .query_row(
                "SELECT COUNT(*) FROM workspace_events
                 WHERE created_at < datetime('now', ?1)",
                [format!("-{} days", opts.retention_days)],
                |row| row.get(0),
            )
            .unwrap_or(0);

        report.duration_ms = start.elapsed().as_millis() as u64;
        return Ok(report);
    }

    // 1. Incremental vacuum
    let freelist_before: u64 = conn
        .pragma_query_value(None, "freelist_count", |row| row.get(0))
        .unwrap_or(0);

    if opts.max_pages > 0 {
        let _ = conn.execute_batch(&format!(
            "PRAGMA incremental_vacuum({});",
            opts.max_pages
        ));
    } else {
        let _ = conn.execute_batch("PRAGMA incremental_vacuum;");
    }

    let freelist_after: u64 = conn
        .pragma_query_value(None, "freelist_count", |row| row.get(0))
        .unwrap_or(0);
    report.pages_freed = freelist_before.saturating_sub(freelist_after);
    report.bytes_freed = report.pages_freed * page_size;

    // 2. Delete old workspace events beyond retention
    report.old_events_deleted = conn
        .execute(
            "DELETE FROM workspace_events
             WHERE created_at < datetime('now', ?1)",
            [format!("-{} days", opts.retention_days)],
        )
        .unwrap_or(0) as u64;

    // 3. Clean up orphaned cache files
    let cache_dir = drift_path.join("cache");
    if cache_dir.exists() {
        report.orphaned_files_deleted = clean_orphaned_cache(&cache_dir).unwrap_or(0);
    }

    report.duration_ms = start.elapsed().as_millis() as u64;
    Ok(report)
}

/// Remove orphaned cache entries (files in cache dir that are no longer needed).
fn clean_orphaned_cache(cache_dir: &Path) -> Result<u64, std::io::Error> {
    let mut count = 0u64;
    if let Ok(entries) = std::fs::read_dir(cache_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Ok(metadata) = path.metadata() {
                    // Remove cache files older than 30 days
                    if let Ok(modified) = metadata.modified() {
                        let age = std::time::SystemTime::now()
                            .duration_since(modified)
                            .unwrap_or_default();
                        if age.as_secs() > 30 * 86400 {
                            let _ = std::fs::remove_file(&path);
                            count += 1;
                        }
                    }
                }
            }
        }
    }
    Ok(count)
}
