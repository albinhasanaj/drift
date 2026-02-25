//! Hot backup via SQLite Backup API with tiered retention.
//! Safe for WAL-mode databases. Non-blocking for readers.

use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::backup::Backup;
use rusqlite::{Connection, OpenFlags};
use tracing::{info, warn};

use super::errors::{WorkspaceError, WorkspaceResult};

/// Backup reasons — all 6 v1 reasons preserved + ci_export added.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupReason {
    VersionUpgrade,
    SchemaMigration,
    UserRequested,
    PreDestructiveOperation,
    Scheduled,
    AutoSave,
    CiExport,
}

impl BackupReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::VersionUpgrade => "version_upgrade",
            Self::SchemaMigration => "schema_migration",
            Self::UserRequested => "user_requested",
            Self::PreDestructiveOperation => "pre_destructive",
            Self::Scheduled => "scheduled",
            Self::AutoSave => "auto_save",
            Self::CiExport => "ci_export",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "version_upgrade" => Self::VersionUpgrade,
            "schema_migration" => Self::SchemaMigration,
            "user_requested" => Self::UserRequested,
            "pre_destructive" => Self::PreDestructiveOperation,
            "scheduled" => Self::Scheduled,
            "auto_save" => Self::AutoSave,
            "ci_export" => Self::CiExport,
            _ => Self::UserRequested,
        }
    }
}

/// Backup tier for tiered retention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupTier {
    Operational,
    Daily,
    Weekly,
}

impl BackupTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Operational => "operational",
            Self::Daily => "daily",
            Self::Weekly => "weekly",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "daily" => Self::Daily,
            "weekly" => Self::Weekly,
            _ => Self::Operational,
        }
    }
}

/// Backup configuration — tiered retention replaces v1's flat max_backups.
#[derive(Debug, Clone)]
pub struct BackupConfig {
    pub max_operational: u32,
    pub max_daily: u32,
    pub max_weekly: u32,
    pub max_total_size_mb: u64,
    pub verify_after_backup: bool,
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            max_operational: 5,
            max_daily: 7,
            max_weekly: 4,
            max_total_size_mb: 500,
            verify_after_backup: true,
        }
    }
}

/// Backup manifest — richer than v1's manifest.
#[derive(Debug, Clone)]
pub struct BackupManifest {
    pub id: String,
    pub reason: BackupReason,
    pub created_at: String,
    pub drift_db_size: u64,
    pub cortex_db_size: Option<u64>,
    pub schema_version: u32,
    pub drift_version: String,
    pub backup_path: PathBuf,
    pub integrity_verified: bool,
    pub tier: BackupTier,
}

fn reason_to_tier(reason: BackupReason) -> BackupTier {
    match reason {
        BackupReason::SchemaMigration
        | BackupReason::PreDestructiveOperation
        | BackupReason::VersionUpgrade => BackupTier::Operational,
        BackupReason::Scheduled | BackupReason::AutoSave => BackupTier::Daily,
        BackupReason::UserRequested | BackupReason::CiExport => BackupTier::Weekly,
    }
}

/// Manages hot backups using the SQLite Backup API.
pub struct BackupManager {
    drift_db_path: PathBuf,
    cortex_db_path: PathBuf,
    backup_dir: PathBuf,
    config: BackupConfig,
}

impl BackupManager {
    pub fn new(drift_path: &Path, config: BackupConfig) -> Self {
        Self {
            drift_db_path: drift_path.join("drift.db"),
            cortex_db_path: drift_path.join("cortex.db"),
            backup_dir: drift_path
                .parent()
                .unwrap_or(drift_path)
                .join(".drift-backups"),
            config,
        }
    }

    /// Create a hot backup using SQLite Backup API.
    /// Safe for WAL-mode databases. Non-blocking for readers.
    pub fn create_backup(
        &self,
        reason: BackupReason,
        drift_version: &str,
    ) -> WorkspaceResult<BackupManifest> {
        let timestamp = now_timestamp();
        let backup_id = format!("backup-{}-{}", timestamp, reason.as_str());
        let backup_path = self.backup_dir.join(&backup_id);
        std::fs::create_dir_all(&backup_path)?;

        // Backup drift.db via SQLite Backup API
        let drift_backup_path = backup_path.join("drift.db");
        self.backup_database(&self.drift_db_path, &drift_backup_path)?;
        let drift_db_size = std::fs::metadata(&drift_backup_path)?.len();

        // Backup cortex.db if it exists (per D6: independent databases)
        let cortex_db_size = if self.cortex_db_path.exists() {
            let cortex_backup_path = backup_path.join("cortex.db");
            self.backup_database(&self.cortex_db_path, &cortex_backup_path)?;
            Some(std::fs::metadata(&cortex_backup_path)?.len())
        } else {
            None
        };

        // Get schema version from drift.db
        let conn = Connection::open_with_flags(
            &self.drift_db_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let schema_version: u32 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap_or(0);

        let manifest = BackupManifest {
            id: backup_id,
            reason,
            created_at: timestamp.clone(),
            drift_db_size,
            cortex_db_size,
            schema_version,
            drift_version: drift_version.to_string(),
            backup_path: backup_path.clone(),
            integrity_verified: self.config.verify_after_backup,
            tier: reason_to_tier(reason),
        };

        // Register in drift.db backup_registry table
        self.register_backup(&manifest)?;

        // Enforce tiered retention policy
        if let Err(e) = self.enforce_retention() {
            warn!(error = %e, "Failed to enforce backup retention policy");
        }

        info!(
            backup_id = %manifest.id,
            reason = reason.as_str(),
            size = drift_db_size,
            "Backup created"
        );

        Ok(manifest)
    }

    /// Core backup operation using SQLite Backup API.
    /// 1000 pages per step, 10ms sleep between steps.
    fn backup_database(&self, source: &Path, dest: &Path) -> WorkspaceResult<()> {
        let src_conn = Connection::open_with_flags(source, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let mut dst_conn = Connection::open(dest)?;

        {
            let backup = Backup::new(&src_conn, &mut dst_conn)?;
            backup.run_to_completion(1000, Duration::from_millis(10), None)?;
        }

        // Verify backup integrity
        if self.config.verify_after_backup {
            let result: String = dst_conn
                .pragma_query_value(None, "integrity_check", |row| row.get(0))
                .unwrap_or_else(|_| "error".to_string());
            if result != "ok" {
                std::fs::remove_file(dest)?;
                return Err(WorkspaceError::BackupCorrupted {
                    backup_id: dest.display().to_string(),
                    integrity_result: result,
                });
            }
        }

        Ok(())
    }

    /// Restore from backup. Creates a safety backup of current state first.
    pub fn restore(&self, backup_id: &str, drift_version: &str) -> WorkspaceResult<()> {
        let backup_path = self.backup_dir.join(backup_id);
        if !backup_path.exists() {
            return Err(WorkspaceError::BackupNotFound(backup_id.to_string()));
        }

        let backup_drift = backup_path.join("drift.db");
        let backup_conn =
            Connection::open_with_flags(&backup_drift, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let result: String = backup_conn
            .pragma_query_value(None, "integrity_check", |row| row.get(0))
            .unwrap_or_else(|_| "error".to_string());
        if result != "ok" {
            return Err(WorkspaceError::BackupCorrupted {
                backup_id: backup_id.to_string(),
                integrity_result: result,
            });
        }
        drop(backup_conn);

        // Create safety backup of current state
        let _ = self.create_backup(BackupReason::PreDestructiveOperation, drift_version);

        // Restore drift.db
        self.backup_database(&backup_drift, &self.drift_db_path)?;

        // Restore cortex.db if present
        let backup_cortex = backup_path.join("cortex.db");
        if backup_cortex.exists() {
            self.backup_database(&backup_cortex, &self.cortex_db_path)?;
        }

        info!(backup_id = backup_id, "Restored from backup");
        Ok(())
    }

    /// List all backups from the registry.
    pub fn list_backups(&self, conn: &Connection) -> WorkspaceResult<Vec<BackupManifest>> {
        let mut stmt = conn.prepare_cached(
            "SELECT id, reason, created_at, drift_db_size, cortex_db_size,
                    schema_version, drift_version, backup_path,
                    integrity_verified, tier
             FROM backup_registry
             ORDER BY created_at DESC",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok(BackupManifest {
                    id: row.get(0)?,
                    reason: BackupReason::parse(&row.get::<_, String>(1)?),
                    created_at: row.get(2)?,
                    drift_db_size: row.get(3)?,
                    cortex_db_size: row.get(4)?,
                    schema_version: row.get(5)?,
                    drift_version: row.get(6)?,
                    backup_path: PathBuf::from(row.get::<_, String>(7)?),
                    integrity_verified: row.get::<_, i32>(8)? != 0,
                    tier: BackupTier::parse(&row.get::<_, String>(9)?),
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Delete a backup. Requires explicit "DELETE" confirmation token.
    pub fn delete_backup(
        &self,
        conn: &Connection,
        backup_id: &str,
        confirmation: &str,
    ) -> WorkspaceResult<()> {
        if confirmation != "DELETE" {
            return Err(WorkspaceError::ConfirmationRequired {
                operation: "delete_backup".to_string(),
            });
        }

        let backup_path = self.backup_dir.join(backup_id);
        if backup_path.exists() {
            std::fs::remove_dir_all(&backup_path)?;
        }

        conn.execute("DELETE FROM backup_registry WHERE id = ?1", [backup_id])?;
        Ok(())
    }

    /// Enforce tiered retention policy.
    fn enforce_retention(&self) -> WorkspaceResult<()> {
        let conn = Connection::open(&self.drift_db_path)?;

        for (tier, max) in [
            ("operational", self.config.max_operational),
            ("daily", self.config.max_daily),
            ("weekly", self.config.max_weekly),
        ] {
            let mut stmt = conn.prepare(
                "SELECT id FROM backup_registry
                 WHERE tier = ?1
                 ORDER BY created_at DESC
                 LIMIT -1 OFFSET ?2",
            )?;
            let excess: Vec<String> = stmt
                .query_map(rusqlite::params![tier, max], |row| row.get(0))?
                .collect::<Result<Vec<_>, _>>()?;
            drop(stmt);

            for bid in excess {
                let path = self.backup_dir.join(&bid);
                if path.exists() {
                    let _ = std::fs::remove_dir_all(&path);
                }
                conn.execute("DELETE FROM backup_registry WHERE id = ?1", [&bid])?;
            }
        }

        Ok(())
    }

    fn register_backup(&self, manifest: &BackupManifest) -> WorkspaceResult<()> {
        let conn = Connection::open(&self.drift_db_path)?;
        conn.execute(
            "INSERT INTO backup_registry
             (id, reason, created_at, drift_db_size, cortex_db_size,
              schema_version, drift_version, backup_path, integrity_verified, tier)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            rusqlite::params![
                manifest.id,
                manifest.reason.as_str(),
                manifest.created_at,
                manifest.drift_db_size,
                manifest.cortex_db_size,
                manifest.schema_version,
                manifest.drift_version,
                manifest.backup_path.display().to_string(),
                manifest.integrity_verified as i32,
                manifest.tier.as_str(),
            ],
        )?;
        Ok(())
    }

    /// Get the backup directory path.
    pub fn backup_dir(&self) -> &Path {
        &self.backup_dir
    }
}

/// Generate a timestamp string for backup IDs (compact, sortable).
/// Uses nanosecond precision + atomic counter to guarantee uniqueness under rapid creation.
fn now_timestamp() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{}.{:09}.{}", duration.as_secs(), duration.subsec_nanos(), seq)
}
