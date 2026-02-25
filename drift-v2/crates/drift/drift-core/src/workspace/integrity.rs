//! Workspace integrity check and recovery.
//! Checks: database integrity, config validity, backup consistency.

use std::path::Path;

use rusqlite::{Connection, OpenFlags};
use serde::Serialize;

use super::errors::WorkspaceResult;

/// Integrity report — comprehensive workspace health check.
#[derive(Debug, Clone, Serialize)]
pub struct IntegrityReport {
    pub drift_db: DatabaseIntegrity,
    pub cortex_db: DatabaseIntegrity,
    pub config: ConfigIntegrity,
    pub backups: BackupIntegrity,
    pub overall: OverallIntegrity,
}

#[derive(Debug, Clone, Serialize)]
pub enum DatabaseIntegrity {
    Ok,
    QuickCheckFailed(String),
    FullCheckFailed(String),
    Missing,
    Locked,
    VersionMismatch { current: u32, expected: u32 },
}

#[derive(Debug, Clone, Serialize)]
pub enum ConfigIntegrity {
    Ok,
    ParseError(String),
    Missing,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupIntegrity {
    pub total_backups: u32,
    pub verified_backups: u32,
    pub corrupted_backups: Vec<String>,
    pub orphaned_entries: u32,
    pub orphaned_files: u32,
}

#[derive(Debug, Clone, Serialize)]
pub enum OverallIntegrity {
    Healthy,
    Degraded(Vec<String>),
    Corrupted(Vec<String>),
}

/// Verify workspace integrity.
pub fn verify_workspace(drift_path: &Path, thorough: bool) -> WorkspaceResult<IntegrityReport> {
    let mut issues: Vec<String> = Vec::new();

    // 1. Check drift.db integrity
    let drift_db = check_database_integrity(&drift_path.join("drift.db"), thorough);
    if !matches!(drift_db, DatabaseIntegrity::Ok) {
        issues.push(format!("drift.db: {:?}", drift_db));
    }

    // 2. Check cortex.db integrity (if exists)
    let cortex_path = drift_path.join("cortex.db");
    let cortex_db = if cortex_path.exists() {
        check_database_integrity(&cortex_path, thorough)
    } else {
        DatabaseIntegrity::Missing
    };

    // 3. Validate drift.toml
    let config = check_config_integrity(
        &drift_path
            .parent()
            .unwrap_or(drift_path)
            .join("drift.toml"),
    );
    if matches!(config, ConfigIntegrity::ParseError(_)) {
        issues.push(format!("drift.toml: {:?}", config));
    }

    // 4. Check backup consistency
    let backups = check_backup_integrity(drift_path);
    if !backups.corrupted_backups.is_empty() {
        issues.push(format!(
            "{} corrupted backups found",
            backups.corrupted_backups.len()
        ));
    }

    let overall = if issues.is_empty() {
        OverallIntegrity::Healthy
    } else if issues.iter().any(|i| i.contains("drift.db")) {
        OverallIntegrity::Corrupted(issues.clone())
    } else {
        OverallIntegrity::Degraded(issues.clone())
    };

    Ok(IntegrityReport {
        drift_db,
        cortex_db,
        config,
        backups,
        overall,
    })
}

fn check_database_integrity(db_path: &Path, thorough: bool) -> DatabaseIntegrity {
    if !db_path.exists() {
        return DatabaseIntegrity::Missing;
    }

    let conn = match Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY) {
        Ok(c) => c,
        Err(_) => return DatabaseIntegrity::Locked,
    };

    let pragma = if thorough {
        "integrity_check"
    } else {
        "quick_check"
    };
    match conn.pragma_query_value(None, pragma, |row| row.get::<_, String>(0)) {
        Ok(result) if result == "ok" => DatabaseIntegrity::Ok,
        Ok(result) => {
            if thorough {
                DatabaseIntegrity::FullCheckFailed(result)
            } else {
                DatabaseIntegrity::QuickCheckFailed(result)
            }
        }
        Err(_) => DatabaseIntegrity::Locked,
    }
}

fn check_config_integrity(toml_path: &Path) -> ConfigIntegrity {
    if !toml_path.exists() {
        return ConfigIntegrity::Missing;
    }
    match std::fs::read_to_string(toml_path) {
        Ok(content) => match toml::from_str::<toml::Value>(&content) {
            Ok(_) => ConfigIntegrity::Ok,
            Err(e) => ConfigIntegrity::ParseError(e.to_string()),
        },
        Err(e) => ConfigIntegrity::ParseError(e.to_string()),
    }
}

fn check_backup_integrity(drift_path: &Path) -> BackupIntegrity {
    let backup_dir = drift_path
        .parent()
        .unwrap_or(drift_path)
        .join(".drift-backups");

    let mut total = 0u32;
    let mut verified = 0u32;
    let mut corrupted = Vec::new();

    if backup_dir.exists() {
        if let Ok(entries) = std::fs::read_dir(&backup_dir) {
            for entry in entries.flatten() {
                if entry.path().is_dir() {
                    total += 1;
                    let db_path = entry.path().join("drift.db");
                    if db_path.exists() {
                        match check_database_integrity(&db_path, false) {
                            DatabaseIntegrity::Ok => verified += 1,
                            _ => corrupted.push(
                                entry
                                    .file_name()
                                    .to_string_lossy()
                                    .to_string(),
                            ),
                        }
                    } else {
                        corrupted.push(entry.file_name().to_string_lossy().to_string());
                    }
                }
            }
        }
    }

    BackupIntegrity {
        total_backups: total,
        verified_backups: verified,
        corrupted_backups: corrupted,
        orphaned_entries: 0,
        orphaned_files: 0,
    }
}

/// Recovery result.
#[derive(Debug)]
pub struct RecoveryResult {
    pub success: bool,
    pub actions_taken: Vec<String>,
}

/// Attempt automatic recovery based on integrity report.
pub fn auto_recover(
    drift_path: &Path,
    report: &IntegrityReport,
) -> WorkspaceResult<RecoveryResult> {
    let mut actions_taken = Vec::new();

    // Recovery 1: Invalid config → reset to defaults
    if matches!(report.config, ConfigIntegrity::ParseError(_)) {
        let root = drift_path.parent().unwrap_or(drift_path);
        let toml_path = root.join("drift.toml");
        let project_name = root
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unnamed");
        let content =
            super::detect::generate_config_template("default", project_name);
        std::fs::write(&toml_path, content)?;
        actions_taken.push("Reset drift.toml to defaults".to_string());
    }

    Ok(RecoveryResult {
        success: !actions_taken.is_empty(),
        actions_taken,
    })
}
