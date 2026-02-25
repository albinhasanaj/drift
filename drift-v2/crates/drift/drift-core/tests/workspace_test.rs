//! Comprehensive tests for Phase 10 Workspace Management.
//!
//! T10-WS-01: Schema creation + idempotent init
//! T10-WS-02: Workspace init (dirs, db, toml, lang detection)
//! T10-WS-03: Project registry (register, resolve 5-step, switch, list)
//! T10-WS-04: Backup lifecycle (create, list, restore, delete, retention)
//! T10-WS-05: Workspace lock (read/write semantics)
//! T10-WS-06: Context refresh + agent context
//! T10-WS-07: Status, health, disk usage, GC
//! T10-WS-08: Destructive ops, integrity, CI detection, export/import

use std::fs;

use drift_core::workspace;

// ============================================================
// T10-WS-01: Schema creation + idempotent init
// ============================================================

#[test]
fn t10_ws_01a_schema_creates_all_tables() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    workspace::initialize_workspace_db(&conn).unwrap();

    let tables = [
        "workspace_config",
        "project_registry",
        "backup_registry",
        "migration_history",
        "workspace_context",
        "workspace_packages",
        "workspace_events",
    ];

    for table in &tables {
        let count: i64 = conn
            .query_row(
                &format!("SELECT COUNT(*) FROM {}", table),
                [],
                |row| row.get(0),
            )
            .unwrap_or_else(|e| panic!("Table {} should exist: {}", table, e));
        assert_eq!(count, 0, "Table {} should be empty initially", table);
    }
}

#[test]
fn t10_ws_01b_schema_idempotent() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    workspace::initialize_workspace_db(&conn).unwrap();
    // Insert some data
    conn.execute(
        "INSERT INTO workspace_config (key, value) VALUES ('test', 'val')",
        [],
    )
    .unwrap();
    // Re-initialize — should not fail or lose data
    workspace::initialize_workspace_db(&conn).unwrap();
    let val: String = conn
        .query_row(
            "SELECT value FROM workspace_config WHERE key = 'test'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(val, "val");
}

#[test]
fn t10_ws_01c_wal_mode_enabled() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    workspace::initialize_workspace_db(&conn).unwrap();
    let mode: String = conn
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .unwrap();
    // In-memory databases use "memory" journal mode; file-based would be "wal"
    assert!(
        mode == "wal" || mode == "memory",
        "Expected WAL or memory mode, got: {}",
        mode
    );
}

#[test]
fn t10_ws_01d_migration_history_recording() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    workspace::initialize_workspace_db(&conn).unwrap();
    workspace::migration::record_migration(&conn, 0, 1, 42, true, None).unwrap();
    workspace::migration::record_migration(&conn, 1, 2, 100, false, Some("test error")).unwrap();

    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM migration_history", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(count, 2);

    let (success, err): (i32, Option<String>) = conn
        .query_row(
            "SELECT success, error_message FROM migration_history WHERE to_version = 2",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(success, 0);
    assert_eq!(err.as_deref(), Some("test error"));
}

// ============================================================
// T10-WS-02: Workspace init
// ============================================================

#[test]
fn t10_ws_02a_workspace_init_creates_dirs_and_db() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    let info = workspace::workspace_init(workspace::InitOptions {
        root: Some(root.to_path_buf()),
        ..Default::default()
    })
    .unwrap();

    assert!(info.is_new);
    assert!(root.join(".drift").exists());
    assert!(root.join(".drift").join("drift.db").exists());
    assert!(root.join(".drift-backups").exists());
    assert!(root.join("drift.toml").exists());
}

#[test]
fn t10_ws_02b_workspace_init_idempotent() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    let info1 = workspace::workspace_init(workspace::InitOptions {
        root: Some(root.to_path_buf()),
        ..Default::default()
    })
    .unwrap();
    assert!(info1.is_new);

    let info2 = workspace::workspace_init(workspace::InitOptions {
        root: Some(root.to_path_buf()),
        ..Default::default()
    })
    .unwrap();
    assert!(!info2.is_new);
}

#[test]
fn t10_ws_02c_workspace_init_writes_config_to_db() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    workspace::workspace_init(workspace::InitOptions {
        root: Some(root.to_path_buf()),
        ..Default::default()
    })
    .unwrap();

    let conn = workspace::open_workspace(root).unwrap();
    let name: String = conn
        .query_row(
            "SELECT value FROM workspace_config WHERE key = 'project_name'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    // Project name should be the directory name
    let expected = root
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unnamed");
    assert_eq!(name, expected);
}

#[test]
fn t10_ws_02d_workspace_init_config_template() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    workspace::workspace_init(workspace::InitOptions {
        root: Some(root.to_path_buf()),
        template: Some("strict".to_string()),
        ..Default::default()
    })
    .unwrap();

    let toml_content = fs::read_to_string(root.join("drift.toml")).unwrap();
    assert!(toml_content.contains("Strict Mode"));
    assert!(toml_content.contains("fail_on_violation = true"));
}

#[test]
fn t10_ws_02e_is_initialized_check() {
    let tmp = tempfile::tempdir().unwrap();
    assert!(!workspace::is_initialized(tmp.path()));

    workspace::workspace_init(workspace::InitOptions {
        root: Some(tmp.path().to_path_buf()),
        ..Default::default()
    })
    .unwrap();

    assert!(workspace::is_initialized(tmp.path()));
}

// ============================================================
// T10-WS-03: Project registry
// ============================================================

#[test]
fn t10_ws_03a_project_registered_on_init() {
    let tmp = tempfile::tempdir().unwrap();
    workspace::workspace_init(workspace::InitOptions {
        root: Some(tmp.path().to_path_buf()),
        ..Default::default()
    })
    .unwrap();

    let conn = workspace::open_workspace(tmp.path()).unwrap();
    let projects = workspace::list_projects(&conn).unwrap();
    assert_eq!(projects.len(), 1);
    assert!(projects[0].is_active);
}

#[test]
fn t10_ws_03b_active_project_query() {
    let tmp = tempfile::tempdir().unwrap();
    workspace::workspace_init(workspace::InitOptions {
        root: Some(tmp.path().to_path_buf()),
        ..Default::default()
    })
    .unwrap();

    let conn = workspace::open_workspace(tmp.path()).unwrap();
    let active = workspace::get_active_project(&conn).unwrap();
    assert!(active.is_some());
    let project = active.unwrap();
    assert!(project.is_active);
    assert_eq!(project.health_status, workspace::HealthStatus::Unknown);
}

#[test]
fn t10_ws_03c_resolve_by_name() {
    let tmp = tempfile::tempdir().unwrap();
    workspace::workspace_init(workspace::InitOptions {
        root: Some(tmp.path().to_path_buf()),
        ..Default::default()
    })
    .unwrap();

    let conn = workspace::open_workspace(tmp.path()).unwrap();
    let name = tmp
        .path()
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap();
    let resolved = workspace::resolve_project(&conn, name).unwrap();
    assert_eq!(resolved.name, name);
}

#[test]
fn t10_ws_03d_health_status_formatting() {
    assert_eq!(workspace::HealthStatus::Healthy.emoji(), "🟢");
    assert_eq!(workspace::HealthStatus::Warning.emoji(), "🟡");
    assert_eq!(workspace::HealthStatus::Critical.emoji(), "🔴");
    assert_eq!(workspace::HealthStatus::Unknown.emoji(), "⚪");

    assert_eq!(workspace::HealthStatus::Healthy.label(), "healthy");
    assert_eq!(workspace::HealthStatus::parse("warning"), workspace::HealthStatus::Warning);
    assert_eq!(workspace::HealthStatus::parse("invalid"), workspace::HealthStatus::Unknown);
}

#[test]
fn t10_ws_03e_project_header_formatting() {
    let project = workspace::ProjectInfo {
        id: "test-id".to_string(),
        name: "my-project".to_string(),
        root_path: std::path::PathBuf::from("/tmp/my-project"),
        drift_path: std::path::PathBuf::from("/tmp/my-project/.drift"),
        health_status: workspace::HealthStatus::Healthy,
        is_active: true,
    };
    let indicator = workspace::format_project_indicator(&project);
    assert_eq!(indicator, "[my-project]");

    let header = workspace::format_project_header(&project);
    assert!(header.contains("🟢"));
    assert!(header.contains("my-project"));
}

// ============================================================
// T10-WS-04: Backup lifecycle
// ============================================================

#[test]
fn t10_ws_04a_backup_create_and_list() {
    let tmp = tempfile::tempdir().unwrap();
    workspace::workspace_init(workspace::InitOptions {
        root: Some(tmp.path().to_path_buf()),
        ..Default::default()
    })
    .unwrap();

    let drift_path = tmp.path().join(".drift");
    let mgr = workspace::BackupManager::new(&drift_path, workspace::BackupConfig::default());
    let manifest = mgr
        .create_backup(workspace::BackupReason::UserRequested, "0.1.0")
        .unwrap();

    assert!(manifest.backup_path.exists());
    assert!(manifest.backup_path.join("drift.db").exists());
    assert!(manifest.drift_db_size > 0);
    assert_eq!(manifest.reason, workspace::BackupReason::UserRequested);

    let conn = workspace::open_workspace(tmp.path()).unwrap();
    let backups = mgr.list_backups(&conn).unwrap();
    assert_eq!(backups.len(), 1);
    assert_eq!(backups[0].id, manifest.id);
}

#[test]
fn t10_ws_04b_backup_reason_roundtrip() {
    let reasons = [
        workspace::BackupReason::VersionUpgrade,
        workspace::BackupReason::SchemaMigration,
        workspace::BackupReason::UserRequested,
        workspace::BackupReason::PreDestructiveOperation,
        workspace::BackupReason::Scheduled,
        workspace::BackupReason::AutoSave,
        workspace::BackupReason::CiExport,
    ];

    for reason in &reasons {
        let s = reason.as_str();
        let parsed = workspace::BackupReason::parse(s);
        assert_eq!(*reason, parsed, "Roundtrip failed for {:?}", reason);
    }
}

#[test]
fn t10_ws_04c_backup_tier_mapping() {
    // Operational tier: schema_migration, pre_destructive, version_upgrade
    assert_eq!(
        workspace::BackupTier::Operational,
        workspace::BackupTier::parse("operational")
    );
    assert_eq!(
        workspace::BackupTier::Daily,
        workspace::BackupTier::parse("daily")
    );
    assert_eq!(
        workspace::BackupTier::Weekly,
        workspace::BackupTier::parse("weekly")
    );
    // Unknown → Operational
    assert_eq!(
        workspace::BackupTier::Operational,
        workspace::BackupTier::parse("unknown")
    );
}

#[test]
fn t10_ws_04d_backup_delete_requires_confirmation() {
    let tmp = tempfile::tempdir().unwrap();
    workspace::workspace_init(workspace::InitOptions {
        root: Some(tmp.path().to_path_buf()),
        ..Default::default()
    })
    .unwrap();

    let drift_path = tmp.path().join(".drift");
    let mgr = workspace::BackupManager::new(&drift_path, workspace::BackupConfig::default());
    let manifest = mgr
        .create_backup(workspace::BackupReason::UserRequested, "0.1.0")
        .unwrap();

    let conn = workspace::open_workspace(tmp.path()).unwrap();

    // Wrong confirmation → error
    let result = mgr.delete_backup(&conn, &manifest.id, "WRONG");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.error_code(), "CONFIRMATION_REQUIRED");

    // Correct confirmation → success
    mgr.delete_backup(&conn, &manifest.id, "DELETE").unwrap();
    let backups = mgr.list_backups(&conn).unwrap();
    assert_eq!(backups.len(), 0);
}

#[test]
fn t10_ws_04e_backup_restore() {
    let tmp = tempfile::tempdir().unwrap();
    workspace::workspace_init(workspace::InitOptions {
        root: Some(tmp.path().to_path_buf()),
        ..Default::default()
    })
    .unwrap();

    let drift_path = tmp.path().join(".drift");
    let conn = workspace::open_workspace(tmp.path()).unwrap();

    // Write some unique data
    conn.execute(
        "INSERT OR REPLACE INTO workspace_config (key, value) VALUES ('test_key', 'before_backup')",
        [],
    )
    .unwrap();

    let mgr = workspace::BackupManager::new(&drift_path, workspace::BackupConfig::default());
    let manifest = mgr
        .create_backup(workspace::BackupReason::UserRequested, "0.1.0")
        .unwrap();

    // Modify data after backup
    conn.execute(
        "UPDATE workspace_config SET value = 'after_backup' WHERE key = 'test_key'",
        [],
    )
    .unwrap();

    drop(conn);

    // Restore from backup
    mgr.restore(&manifest.id, "0.1.0").unwrap();

    // Verify data was restored
    let conn = workspace::open_workspace(tmp.path()).unwrap();
    let val: String = conn
        .query_row(
            "SELECT value FROM workspace_config WHERE key = 'test_key'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(val, "before_backup");
}

// ============================================================
// T10-WS-05: Workspace lock
// ============================================================

#[test]
fn t10_ws_05a_lock_create() {
    let tmp = tempfile::tempdir().unwrap();
    let drift_path = tmp.path().join(".drift");
    fs::create_dir_all(&drift_path).unwrap();

    let lock = workspace::WorkspaceLock::new(&drift_path);
    assert!(lock.is_ok());
    assert!(drift_path.join("workspace.lock").exists());
}

#[test]
fn t10_ws_05b_lock_read_write() {
    let tmp = tempfile::tempdir().unwrap();
    let drift_path = tmp.path().join(".drift");
    fs::create_dir_all(&drift_path).unwrap();

    let mut lock = workspace::WorkspaceLock::new(&drift_path).unwrap();

    // Read lock should succeed
    {
        let _guard = lock.read().unwrap();
        // Lock is held here
    }

    // Write lock should succeed
    {
        let _guard = lock.write().unwrap();
        // Exclusive lock held here
    }
}

// ============================================================
// T10-WS-06: Context refresh + agent context
// ============================================================

#[test]
fn t10_ws_06a_context_refresh() {
    let tmp = tempfile::tempdir().unwrap();
    workspace::workspace_init(workspace::InitOptions {
        root: Some(tmp.path().to_path_buf()),
        ..Default::default()
    })
    .unwrap();

    let conn = workspace::open_workspace(tmp.path()).unwrap();
    workspace::refresh_workspace_context(&conn).unwrap();

    let ctx = workspace::get_workspace_context(&conn).unwrap();
    assert!(!ctx.project.name.is_empty());
    assert!(!ctx.project.drift_version.is_empty());
}

#[test]
fn t10_ws_06b_context_zero_staleness() {
    let tmp = tempfile::tempdir().unwrap();
    workspace::workspace_init(workspace::InitOptions {
        root: Some(tmp.path().to_path_buf()),
        ..Default::default()
    })
    .unwrap();

    let conn = workspace::open_workspace(tmp.path()).unwrap();

    // Update config
    conn.execute(
        "INSERT OR REPLACE INTO workspace_config (key, value) VALUES ('last_scan_at', '2026-02-09')",
        [],
    )
    .unwrap();

    // Refresh context
    workspace::refresh_workspace_context(&conn).unwrap();

    let ctx = workspace::get_workspace_context(&conn).unwrap();
    assert_eq!(ctx.project.last_scan_at.as_deref(), Some("2026-02-09"));
}

#[test]
fn t10_ws_06c_agent_context() {
    let tmp = tempfile::tempdir().unwrap();
    workspace::workspace_init(workspace::InitOptions {
        root: Some(tmp.path().to_path_buf()),
        ..Default::default()
    })
    .unwrap();

    let conn = workspace::open_workspace(tmp.path()).unwrap();
    workspace::refresh_workspace_context(&conn).unwrap();

    let agent = workspace::get_agent_context(&conn).unwrap();
    assert!(!agent.summary.is_empty());
    assert!(!agent.available_commands.is_empty());
    // No scan → should have warning
    assert!(agent.warnings.iter().any(|w| w.contains("No scan")));
    assert!(!agent.readiness.scanned);
}

// ============================================================
// T10-WS-07: Status, health, disk usage, GC
// ============================================================

#[test]
fn t10_ws_07a_workspace_status() {
    let tmp = tempfile::tempdir().unwrap();
    workspace::workspace_init(workspace::InitOptions {
        root: Some(tmp.path().to_path_buf()),
        ..Default::default()
    })
    .unwrap();

    let conn = workspace::open_workspace(tmp.path()).unwrap();
    let drift_path = tmp.path().join(".drift");
    let status = workspace::workspace_status(&conn, &drift_path).unwrap();

    assert!(status.initialized);
    assert!(status.active_project.is_some());
    assert_eq!(status.health_status, workspace::HealthStatus::Unknown);
    assert!(status.disk_usage.is_some());
    let usage = status.disk_usage.unwrap();
    assert!(usage.drift_db_bytes > 0);
    assert!(usage.total_bytes > 0);
}

#[test]
fn t10_ws_07b_health_calculation() {
    use workspace::context::{AnalysisStatus, ProjectContext, WorkspaceContext};
    use workspace::status::calculate_health;

    // No scan → Unknown
    let ctx_no_scan = WorkspaceContext {
        project: ProjectContext {
            name: "test".into(),
            root_path: "/tmp".into(),
            schema_version: "1".into(),
            drift_version: "0.1.0".into(),
            last_scan_at: None,
            health_score: None,
            languages: vec![],
            frameworks: vec![],
        },
        analysis: AnalysisStatus::default(),
        loaded_at: "0".into(),
    };
    assert_eq!(calculate_health(&ctx_no_scan), workspace::HealthStatus::Unknown);

    // All systems built → Healthy
    let ctx_healthy = WorkspaceContext {
        project: ProjectContext {
            last_scan_at: Some("2026-02-09".into()),
            ..ctx_no_scan.project.clone()
        },
        analysis: AnalysisStatus {
            call_graph_built: true,
            test_topology_built: true,
            coupling_built: true,
            dna_profile_exists: true,
            constants_extracted: true,
            constraints_mined: true,
            contracts_detected: true,
            security_scanned: true,
        },
        loaded_at: "0".into(),
    };
    assert_eq!(calculate_health(&ctx_healthy), workspace::HealthStatus::Healthy);

    // Nothing built → Warning (score = 100 - 15 - 10 - 10 - 10 = 55)
    let ctx_warning = WorkspaceContext {
        project: ProjectContext {
            last_scan_at: Some("2026-02-09".into()),
            ..ctx_no_scan.project.clone()
        },
        analysis: AnalysisStatus::default(),
        loaded_at: "0".into(),
    };
    assert_eq!(calculate_health(&ctx_warning), workspace::HealthStatus::Warning);
}

#[test]
fn t10_ws_07c_garbage_collection_dry_run() {
    let tmp = tempfile::tempdir().unwrap();
    workspace::workspace_init(workspace::InitOptions {
        root: Some(tmp.path().to_path_buf()),
        ..Default::default()
    })
    .unwrap();

    let conn = workspace::open_workspace(tmp.path()).unwrap();
    let drift_path = tmp.path().join(".drift");

    let report = workspace::garbage_collect(
        &conn,
        &drift_path,
        workspace::GCOptions {
            dry_run: true,
            ..Default::default()
        },
    )
    .unwrap();

    // Dry run should report but not delete
    assert!(report.duration_ms < 5000);
}

#[test]
fn t10_ws_07d_garbage_collection_deletes_old_events() {
    let tmp = tempfile::tempdir().unwrap();
    workspace::workspace_init(workspace::InitOptions {
        root: Some(tmp.path().to_path_buf()),
        ..Default::default()
    })
    .unwrap();

    let conn = workspace::open_workspace(tmp.path()).unwrap();
    let drift_path = tmp.path().join(".drift");

    // Insert an old event
    conn.execute(
        "INSERT INTO workspace_events (event_type, details, created_at)
         VALUES ('test', 'old event', datetime('now', '-100 days'))",
        [],
    )
    .unwrap();

    let report = workspace::garbage_collect(
        &conn,
        &drift_path,
        workspace::GCOptions {
            retention_days: 90,
            dry_run: false,
            ..Default::default()
        },
    )
    .unwrap();

    assert_eq!(report.old_events_deleted, 1);
}

// ============================================================
// T10-WS-08: Destructive ops, integrity, CI detection, export/import
// ============================================================

#[test]
fn t10_ws_08a_destructive_op_requires_confirmation() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    workspace::initialize_workspace_db(&conn).unwrap();

    let tmp = tempfile::tempdir().unwrap();
    let drift_path = tmp.path().join(".drift");
    fs::create_dir_all(&drift_path).unwrap();

    let result = workspace::destructive::perform_destructive_operation(
        &conn,
        &drift_path,
        "test_op",
        "WRONG",
        "0.1.0",
        || Ok(()),
    );
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().error_code(), "CONFIRMATION_REQUIRED");
}

#[test]
fn t10_ws_08b_workspace_reset_requires_confirmation() {
    let tmp = tempfile::tempdir().unwrap();
    workspace::workspace_init(workspace::InitOptions {
        root: Some(tmp.path().to_path_buf()),
        ..Default::default()
    })
    .unwrap();

    let drift_path = tmp.path().join(".drift");

    // Wrong confirmation
    let result = workspace::destructive::workspace_reset(&drift_path, "WRONG", "0.1.0");
    assert!(result.is_err());

    // Correct confirmation — should delete drift.db
    workspace::destructive::workspace_reset(&drift_path, "DELETE", "0.1.0").unwrap();
    assert!(!drift_path.join("drift.db").exists());
}

#[test]
fn t10_ws_08c_integrity_check_healthy() {
    let tmp = tempfile::tempdir().unwrap();
    workspace::workspace_init(workspace::InitOptions {
        root: Some(tmp.path().to_path_buf()),
        ..Default::default()
    })
    .unwrap();

    let drift_path = tmp.path().join(".drift");
    let report = workspace::verify_workspace(&drift_path, false).unwrap();

    assert!(matches!(
        report.drift_db,
        workspace::integrity::DatabaseIntegrity::Ok
    ));
    assert!(matches!(
        report.config,
        workspace::integrity::ConfigIntegrity::Ok
    ));
    assert!(matches!(
        report.overall,
        workspace::integrity::OverallIntegrity::Healthy
    ));
}

#[test]
fn t10_ws_08d_integrity_check_missing_db() {
    let tmp = tempfile::tempdir().unwrap();
    let drift_path = tmp.path().join(".drift");
    fs::create_dir_all(&drift_path).unwrap();
    // Create drift.toml so config check passes
    fs::write(
        tmp.path().join("drift.toml"),
        "[workspace]\nname = \"test\"\n",
    )
    .unwrap();

    let report = workspace::verify_workspace(&drift_path, false).unwrap();
    assert!(matches!(
        report.drift_db,
        workspace::integrity::DatabaseIntegrity::Missing
    ));
}

#[test]
fn t10_ws_08e_ci_detection() {
    // Without CI env vars, should return None
    // (We can't easily test the positive case without setting env vars
    // which could affect other tests. Just verify the function runs.)
    let result = workspace::detect_ci_environment();
    // In local dev, should be None. In CI, might be Some.
    // Just verify it doesn't panic.
    let _ = result;

    // Test is_ci helper
    let _ = workspace::is_ci();
}

#[test]
fn t10_ws_08f_export_import() {
    let tmp = tempfile::tempdir().unwrap();
    workspace::workspace_init(workspace::InitOptions {
        root: Some(tmp.path().to_path_buf()),
        ..Default::default()
    })
    .unwrap();

    let conn = workspace::open_workspace(tmp.path()).unwrap();

    // Write test data
    conn.execute(
        "INSERT OR REPLACE INTO workspace_config (key, value) VALUES ('export_test', 'hello')",
        [],
    )
    .unwrap();

    // Export
    let export_path = tmp.path().join("export.db");
    let manifest = workspace::export::export_workspace(&conn, &export_path).unwrap();
    assert!(export_path.exists());
    assert!(manifest.size_bytes > 0);
    assert_eq!(manifest.drift_version, env!("CARGO_PKG_VERSION"));

    drop(conn);

    // Create a new workspace and import
    let tmp2 = tempfile::tempdir().unwrap();
    workspace::workspace_init(workspace::InitOptions {
        root: Some(tmp2.path().to_path_buf()),
        ..Default::default()
    })
    .unwrap();

    let drift_path2 = tmp2.path().join(".drift");
    workspace::export::import_workspace(&drift_path2, &export_path).unwrap();

    // Verify imported data
    let conn2 = workspace::open_workspace(tmp2.path()).unwrap();
    let val: String = conn2
        .query_row(
            "SELECT value FROM workspace_config WHERE key = 'export_test'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(val, "hello");
}

#[test]
fn t10_ws_08g_auto_recovery_bad_config() {
    let tmp = tempfile::tempdir().unwrap();
    workspace::workspace_init(workspace::InitOptions {
        root: Some(tmp.path().to_path_buf()),
        ..Default::default()
    })
    .unwrap();

    // Corrupt drift.toml
    fs::write(tmp.path().join("drift.toml"), "this is { not valid toml").unwrap();

    let drift_path = tmp.path().join(".drift");
    let report = workspace::verify_workspace(&drift_path, false).unwrap();
    assert!(matches!(
        report.config,
        workspace::integrity::ConfigIntegrity::ParseError(_)
    ));

    // Auto-recover should reset config
    let recovery = workspace::auto_recover(&drift_path, &report).unwrap();
    assert!(recovery.success);
    assert!(!recovery.actions_taken.is_empty());

    // Verify config is now valid
    let report2 = workspace::verify_workspace(&drift_path, false).unwrap();
    assert!(matches!(
        report2.config,
        workspace::integrity::ConfigIntegrity::Ok
    ));
}

#[test]
fn t10_ws_08h_error_codes_complete() {
    // Verify every error variant has a distinct error code
    let codes = vec![
        workspace::WorkspaceError::AlreadyInitialized("x".into()).error_code(),
        workspace::WorkspaceError::NotInitialized.error_code(),
        workspace::WorkspaceError::Locked {
            operation: "x".into(),
            message: "y".into(),
        }
        .error_code(),
        workspace::WorkspaceError::MigrationFailed {
            message: "x".into(),
        }
        .error_code(),
        workspace::WorkspaceError::BackupNotFound("x".into()).error_code(),
        workspace::WorkspaceError::BackupCorrupted {
            backup_id: "x".into(),
            integrity_result: "y".into(),
        }
        .error_code(),
        workspace::WorkspaceError::NoVerifiedBackup.error_code(),
        workspace::WorkspaceError::ProjectNotFound("x".into()).error_code(),
        workspace::WorkspaceError::AmbiguousProject {
            identifier: "x".into(),
            matches: vec![],
        }
        .error_code(),
        workspace::WorkspaceError::ConfirmationRequired {
            operation: "x".into(),
        }
        .error_code(),
        workspace::WorkspaceError::ExportCorrupted("x".into()).error_code(),
        workspace::WorkspaceError::ImportCorrupted("x".into()).error_code(),
        workspace::WorkspaceError::ConfigError("x".into()).error_code(),
    ];

    // Ensure all codes are non-empty and distinct
    for code in &codes {
        assert!(!code.is_empty());
    }

    let unique: std::collections::HashSet<_> = codes.iter().collect();
    assert_eq!(unique.len(), codes.len(), "All error codes should be unique");
}

// ============================================================
// T10-WS-09: Language/framework detection
// ============================================================

#[test]
fn t10_ws_09a_detect_languages_typescript() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("tsconfig.json"), "{}").unwrap();
    fs::write(tmp.path().join("package.json"), "{}").unwrap();

    let langs = workspace::detect::detect_languages(tmp.path());
    assert!(langs.contains(&"typescript".to_string()));
    // Should NOT contain javascript when typescript is present
    assert!(!langs.contains(&"javascript".to_string()));
}

#[test]
fn t10_ws_09b_detect_languages_python() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("requirements.txt"), "flask\n").unwrap();

    let langs = workspace::detect::detect_languages(tmp.path());
    assert!(langs.contains(&"python".to_string()));
}

#[test]
fn t10_ws_09c_detect_languages_rust() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("Cargo.toml"), "[package]\nname = \"test\"\n").unwrap();

    let langs = workspace::detect::detect_languages(tmp.path());
    assert!(langs.contains(&"rust".to_string()));
}

#[test]
fn t10_ws_09d_detect_frameworks_react() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("package.json"),
        r#"{"dependencies":{"react":"^18.0.0","next":"^14.0.0"}}"#,
    )
    .unwrap();

    let frameworks = workspace::detect::detect_frameworks(tmp.path());
    assert!(frameworks.contains(&"React".to_string()));
    assert!(frameworks.contains(&"Next.js".to_string()));
}

#[test]
fn t10_ws_09e_detect_frameworks_django() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("requirements.txt"), "django>=4.0\n").unwrap();

    let frameworks = workspace::detect::detect_frameworks(tmp.path());
    assert!(frameworks.contains(&"Django".to_string()));
}

#[test]
fn t10_ws_09f_config_template_variants() {
    let default = workspace::detect::generate_config_template("default", "test-proj");
    assert!(default.contains("test-proj"));
    assert!(default.contains("[scan]"));
    assert!(default.contains("[backup]"));

    let strict = workspace::detect::generate_config_template("strict", "test-proj");
    assert!(strict.contains("Strict Mode"));
    assert!(strict.contains("fail_on_violation = true"));

    let ci = workspace::detect::generate_config_template("ci", "test-proj");
    assert!(ci.contains("CI Mode"));

    // Unknown template → falls back to default
    let unknown = workspace::detect::generate_config_template("nonexistent", "test-proj");
    assert!(unknown.contains("[scan]"));
}

// ============================================================
// T10-WS-10: Monorepo detection
// ============================================================

#[test]
fn t10_ws_10a_single_project_no_workspace() {
    let tmp = tempfile::tempdir().unwrap();
    let layout = workspace::detect_workspace(tmp.path()).unwrap();
    assert!(matches!(layout, workspace::WorkspaceLayout::SingleProject(_)));
}

#[test]
fn t10_ws_10b_pnpm_workspace_detection() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("pnpm-workspace.yaml"),
        "packages:\n  - 'packages/*'\n",
    )
    .unwrap();

    // Create package dirs
    let pkg_dir = tmp.path().join("packages").join("frontend");
    fs::create_dir_all(&pkg_dir).unwrap();
    fs::write(pkg_dir.join("package.json"), "{}").unwrap();

    let layout = workspace::detect_workspace(tmp.path()).unwrap();
    match layout {
        workspace::WorkspaceLayout::Monorepo { packages, .. } => {
            assert_eq!(packages.len(), 1);
            assert_eq!(packages[0].name, "frontend");
        }
        _ => panic!("Expected Monorepo layout"),
    }
}

#[test]
fn t10_ws_10c_npm_workspace_detection() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("package.json"),
        r#"{"workspaces":["packages/*"]}"#,
    )
    .unwrap();

    let pkg_dir = tmp.path().join("packages").join("api");
    fs::create_dir_all(&pkg_dir).unwrap();
    fs::write(pkg_dir.join("package.json"), "{}").unwrap();

    let layout = workspace::detect_workspace(tmp.path()).unwrap();
    match layout {
        workspace::WorkspaceLayout::Monorepo { packages, .. } => {
            assert!(packages.iter().any(|p| p.name == "api"));
        }
        _ => panic!("Expected Monorepo layout"),
    }
}

#[test]
fn t10_ws_10d_monorepo_package_registration() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    workspace::initialize_workspace_db(&conn).unwrap();

    let packages = vec![
        workspace::monorepo::PackageInfo {
            name: "frontend".to_string(),
            path: std::path::PathBuf::from("packages/frontend"),
            language: Some("typescript".to_string()),
            framework: Some("React".to_string()),
            dependencies: vec!["shared".to_string()],
        },
        workspace::monorepo::PackageInfo {
            name: "backend".to_string(),
            path: std::path::PathBuf::from("packages/backend"),
            language: Some("typescript".to_string()),
            framework: Some("Express".to_string()),
            dependencies: vec!["shared".to_string()],
        },
    ];

    workspace::monorepo::register_packages(&conn, &packages).unwrap();

    let loaded = workspace::monorepo::list_packages(&conn).unwrap();
    assert_eq!(loaded.len(), 2);
    assert!(loaded.iter().any(|p| p.name == "frontend"));
    assert!(loaded.iter().any(|p| p.name == "backend"));
}

// ============================================================
// T10-WS-11: Workspace events audit trail
// ============================================================

#[test]
fn t10_ws_11a_init_logs_event() {
    let tmp = tempfile::tempdir().unwrap();
    workspace::workspace_init(workspace::InitOptions {
        root: Some(tmp.path().to_path_buf()),
        ..Default::default()
    })
    .unwrap();

    let conn = workspace::open_workspace(tmp.path()).unwrap();
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM workspace_events WHERE event_type = 'workspace_init'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(count >= 1);
}

#[test]
fn t10_ws_11b_unique_active_project_constraint() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    workspace::initialize_workspace_db(&conn).unwrap();

    // Insert first active project
    conn.execute(
        "INSERT INTO project_registry (id, name, root_path, drift_path, is_active)
         VALUES ('p1', 'proj1', '/a', '/a/.drift', 1)",
        [],
    )
    .unwrap();

    // Inserting second active project should fail (unique index)
    let result = conn.execute(
        "INSERT INTO project_registry (id, name, root_path, drift_path, is_active)
         VALUES ('p2', 'proj2', '/b', '/b/.drift', 1)",
        [],
    );
    assert!(result.is_err());
}
