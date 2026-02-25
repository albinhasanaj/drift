//! Phase B workspace tests (CT0-B-11 through CT0-B-13).
//!
//! Tests `SqliteWorkspaceStorage` implementing `IWorkspaceStorage`.

use drift_core::traits::storage::workspace::IWorkspaceStorage;
use drift_core::workspace::SqliteWorkspaceStorage;
use tempfile::TempDir;

/// CT0-B-11: SqliteWorkspaceStorage::new → initialize → status → initialized.
#[test]
fn ct0_b11_workspace_trait_impl_works() {
    let dir = TempDir::new().unwrap();
    let drift_path = dir.path().join(".drift");

    let storage = SqliteWorkspaceStorage::new(&drift_path);
    storage.initialize("").unwrap();

    let status = storage.status().unwrap();
    assert!(status.initialized, "Workspace should be initialized");
    // Workspace uses PRAGMA user_version which defaults to 0
    assert_eq!(status.schema_version, 0);
    assert!(
        status.db_path.is_some(),
        "DB path should be present"
    );
}

/// CT0-B-12: Initialize → backup → integrity_check on backup → clean.
#[test]
fn ct0_b12_backup_through_trait() {
    let dir = TempDir::new().unwrap();
    let drift_path = dir.path().join(".drift");

    let storage = SqliteWorkspaceStorage::new(&drift_path);
    storage.initialize("").unwrap();

    // Create backup
    let backup_path = dir.path().join("backup.db");
    let result = storage
        .backup(backup_path.to_str().unwrap())
        .unwrap();
    assert!(result.size_bytes > 0, "Backup should have non-zero size");
    assert!(backup_path.exists(), "Backup file should exist");

    // Verify backup integrity via a separate SqliteWorkspaceStorage
    let backup_drift_dir = dir.path().join("backup_drift");
    std::fs::create_dir_all(&backup_drift_dir).unwrap();
    std::fs::copy(&backup_path, backup_drift_dir.join("drift.db")).unwrap();

    let backup_storage = SqliteWorkspaceStorage::new(&backup_drift_dir);
    let integrity = backup_storage.integrity_check().unwrap();
    assert!(integrity.ok, "Backup integrity check should pass");
}

/// CT0-B-13a: schema_version through trait returns valid version.
#[test]
fn ct0_b13a_schema_version_through_trait() {
    let dir = TempDir::new().unwrap();
    let drift_path = dir.path().join(".drift");

    let storage = SqliteWorkspaceStorage::new(&drift_path);
    storage.initialize("").unwrap();

    // Workspace uses PRAGMA user_version which defaults to 0
    let version = storage.schema_version().unwrap();
    assert_eq!(version, 0);
}

/// CT0-B-13b: project_info through trait returns empty defaults on fresh workspace.
#[test]
fn ct0_b13b_project_info_fresh_workspace() {
    let dir = TempDir::new().unwrap();
    let drift_path = dir.path().join(".drift");

    let storage = SqliteWorkspaceStorage::new(&drift_path);
    storage.initialize("").unwrap();

    let info = storage.project_info().unwrap();
    assert_eq!(info.total_files, 0);
    assert_eq!(info.total_functions, 0);
    assert_eq!(info.total_patterns, 0);
    assert_eq!(info.last_scan_at, None);
}

/// CT0-B-13c: gc through trait runs without error on fresh workspace.
#[test]
fn ct0_b13c_gc_through_trait() {
    let dir = TempDir::new().unwrap();
    let drift_path = dir.path().join(".drift");

    let storage = SqliteWorkspaceStorage::new(&drift_path);
    storage.initialize("").unwrap();

    let stats = storage.gc().unwrap();
    assert!(stats.wal_checkpointed, "WAL checkpoint should succeed");
}

/// CT0-B-13d: export and import through trait.
#[test]
fn ct0_b13d_export_import_through_trait() {
    let dir = TempDir::new().unwrap();
    let drift_path = dir.path().join(".drift");

    let storage = SqliteWorkspaceStorage::new(&drift_path);
    storage.initialize("").unwrap();

    // Export
    let export_path = dir.path().join("export.db");
    storage.export(export_path.to_str().unwrap()).unwrap();
    assert!(export_path.exists(), "Export file should exist");

    // Import into a new workspace
    let dir2 = TempDir::new().unwrap();
    let drift_path2 = dir2.path().join(".drift");
    std::fs::create_dir_all(&drift_path2).unwrap();

    let storage2 = SqliteWorkspaceStorage::new(&drift_path2);
    storage2.import(export_path.to_str().unwrap()).unwrap();

    // Verify imported workspace is functional
    let status = storage2.status().unwrap();
    assert!(status.initialized);
}

/// CT0-B-13e: integrity_check on missing DB returns not-ok.
#[test]
fn ct0_b13e_integrity_check_missing_db() {
    let dir = TempDir::new().unwrap();
    let drift_path = dir.path().join(".drift");
    // Don't initialize — drift.db doesn't exist

    let storage = SqliteWorkspaceStorage::new(&drift_path);
    let integrity = storage.integrity_check().unwrap();
    assert!(!integrity.ok, "Missing DB should report not ok");
    assert!(!integrity.issues.is_empty());
}
