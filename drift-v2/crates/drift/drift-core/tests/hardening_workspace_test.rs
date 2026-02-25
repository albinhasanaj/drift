//! Hardening tests for Phase 10 — edge cases, security, concurrency.
//! These tests verify production-readiness beyond happy-path coverage.

use std::fs;

use drift_core::workspace;

// ============================================================
// Unicode and special character paths
// ============================================================

#[test]
fn harden_unicode_project_name() {
    let tmp = tempfile::tempdir().unwrap();
    let unicode_dir = tmp.path().join("项目-проект-プロジェクト");
    fs::create_dir_all(&unicode_dir).unwrap();

    let info = workspace::workspace_init(workspace::InitOptions {
        root: Some(unicode_dir.clone()),
        ..Default::default()
    })
    .unwrap();

    assert!(info.is_new);
    assert!(unicode_dir.join(".drift").join("drift.db").exists());

    // Verify we can open and query the workspace
    let conn = workspace::open_workspace(&unicode_dir).unwrap();
    let name: String = conn
        .query_row(
            "SELECT value FROM workspace_config WHERE key = 'project_name'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(name, "项目-проект-プロジェクト");
}

#[test]
fn harden_spaces_in_path() {
    let tmp = tempfile::tempdir().unwrap();
    let spaced = tmp.path().join("my project (v2)");
    fs::create_dir_all(&spaced).unwrap();

    let info = workspace::workspace_init(workspace::InitOptions {
        root: Some(spaced.clone()),
        ..Default::default()
    })
    .unwrap();
    assert!(info.is_new);

    let conn = workspace::open_workspace(&spaced).unwrap();
    let projects = workspace::list_projects(&conn).unwrap();
    assert_eq!(projects.len(), 1);
}

// ============================================================
// Empty / minimal database edge cases
// ============================================================

#[test]
fn harden_empty_db_context_refresh() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    workspace::initialize_workspace_db(&conn).unwrap();

    // Context refresh on empty DB should not panic
    workspace::refresh_workspace_context(&conn).unwrap();

    let ctx = workspace::get_workspace_context(&conn).unwrap();
    assert!(ctx.project.name.is_empty());
    assert!(ctx.project.last_scan_at.is_none());
}

#[test]
fn harden_empty_db_status() {
    let tmp = tempfile::tempdir().unwrap();
    workspace::workspace_init(workspace::InitOptions {
        root: Some(tmp.path().to_path_buf()),
        ..Default::default()
    })
    .unwrap();

    let conn = workspace::open_workspace(tmp.path()).unwrap();
    let drift_path = tmp.path().join(".drift");

    // Status on fresh workspace should work
    let status = workspace::workspace_status(&conn, &drift_path).unwrap();
    assert!(status.initialized);
    assert_eq!(status.backup_count, 0);
}

#[test]
fn harden_empty_db_gc() {
    let tmp = tempfile::tempdir().unwrap();
    workspace::workspace_init(workspace::InitOptions {
        root: Some(tmp.path().to_path_buf()),
        ..Default::default()
    })
    .unwrap();

    let conn = workspace::open_workspace(tmp.path()).unwrap();
    let drift_path = tmp.path().join(".drift");

    // GC on empty workspace should succeed with zero cleanup
    let report = workspace::garbage_collect(
        &conn,
        &drift_path,
        workspace::GCOptions::default(),
    )
    .unwrap();
    assert_eq!(report.old_events_deleted, 0);
}

#[test]
fn harden_no_active_project() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    workspace::initialize_workspace_db(&conn).unwrap();

    // No projects registered — should return None, not error
    let active = workspace::get_active_project(&conn).unwrap();
    assert!(active.is_none());
}

#[test]
fn harden_resolve_nonexistent_project() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    workspace::initialize_workspace_db(&conn).unwrap();

    let result = workspace::resolve_project(&conn, "nonexistent");
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().error_code(), "PROJECT_NOT_FOUND");
}

// ============================================================
// Backup edge cases
// ============================================================

#[test]
fn harden_backup_nonexistent_restore() {
    let tmp = tempfile::tempdir().unwrap();
    workspace::workspace_init(workspace::InitOptions {
        root: Some(tmp.path().to_path_buf()),
        ..Default::default()
    })
    .unwrap();

    let drift_path = tmp.path().join(".drift");
    let mgr = workspace::BackupManager::new(&drift_path, workspace::BackupConfig::default());

    let result = mgr.restore("nonexistent-backup-id", "0.1.0");
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().error_code(), "BACKUP_NOT_FOUND");
}

#[test]
fn harden_backup_multiple_create() {
    let tmp = tempfile::tempdir().unwrap();
    workspace::workspace_init(workspace::InitOptions {
        root: Some(tmp.path().to_path_buf()),
        ..Default::default()
    })
    .unwrap();

    let drift_path = tmp.path().join(".drift");
    let mgr = workspace::BackupManager::new(&drift_path, workspace::BackupConfig::default());

    // Create 3 backups rapidly — should all succeed with unique IDs
    let b1 = mgr.create_backup(workspace::BackupReason::UserRequested, "0.1.0").unwrap();
    let b2 = mgr.create_backup(workspace::BackupReason::UserRequested, "0.1.0").unwrap();
    let b3 = mgr.create_backup(workspace::BackupReason::UserRequested, "0.1.0").unwrap();

    assert_ne!(b1.id, b2.id);
    assert_ne!(b2.id, b3.id);

    let conn = workspace::open_workspace(tmp.path()).unwrap();
    let backups = mgr.list_backups(&conn).unwrap();
    assert!(backups.len() >= 3);
}

// ============================================================
// Export path injection prevention
// ============================================================

#[test]
fn harden_export_path_semicolon_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    workspace::workspace_init(workspace::InitOptions {
        root: Some(tmp.path().to_path_buf()),
        ..Default::default()
    })
    .unwrap();

    let conn = workspace::open_workspace(tmp.path()).unwrap();

    // Path with semicolon should be rejected (SQL injection attempt)
    let malicious_path = tmp.path().join("export;DROP TABLE workspace_config.db");
    let result = workspace::export::export_workspace(&conn, &malicious_path);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().error_code(), "CONFIG_ERROR");
}

#[test]
fn harden_export_path_double_dash_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    workspace::workspace_init(workspace::InitOptions {
        root: Some(tmp.path().to_path_buf()),
        ..Default::default()
    })
    .unwrap();

    let conn = workspace::open_workspace(tmp.path()).unwrap();

    // Path with -- should be rejected (SQL comment injection)
    let malicious_path = tmp.path().join("export--comment.db");
    let result = workspace::export::export_workspace(&conn, &malicious_path);
    assert!(result.is_err());
}

// ============================================================
// Workspace lock edge cases
// ============================================================

#[test]
fn harden_lock_on_nonexistent_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let nonexistent = tmp.path().join("does_not_exist");

    // Should fail gracefully, not panic
    let result = workspace::WorkspaceLock::new(&nonexistent);
    assert!(result.is_err());
}

#[test]
fn harden_lock_multiple_reads() {
    let tmp = tempfile::tempdir().unwrap();
    let drift_path = tmp.path().join(".drift");
    fs::create_dir_all(&drift_path).unwrap();

    let mut lock = workspace::WorkspaceLock::new(&drift_path).unwrap();

    // Multiple sequential read locks should work
    for _ in 0..10 {
        let _guard = lock.read().unwrap();
    }
}

// ============================================================
// Monorepo edge cases
// ============================================================

#[test]
fn harden_monorepo_empty_packages_dir() {
    let tmp = tempfile::tempdir().unwrap();
    // pnpm workspace file but empty packages dir
    fs::write(
        tmp.path().join("pnpm-workspace.yaml"),
        "packages:\n  - 'packages/*'\n",
    )
    .unwrap();
    fs::create_dir_all(tmp.path().join("packages")).unwrap();
    // No actual packages inside

    let layout = workspace::detect_workspace(tmp.path()).unwrap();
    match layout {
        workspace::WorkspaceLayout::Monorepo { packages, .. } => {
            assert_eq!(packages.len(), 0, "Empty packages dir should yield 0 packages");
        }
        _ => panic!("Should still detect as monorepo even with empty packages"),
    }
}

#[test]
fn harden_monorepo_nested_detection() {
    let tmp = tempfile::tempdir().unwrap();
    // Cargo workspace
    fs::write(
        tmp.path().join("Cargo.toml"),
        "[workspace]\nmembers = [\"crates/*\"]\n",
    )
    .unwrap();
    let crate_dir = tmp.path().join("crates").join("my-crate");
    fs::create_dir_all(&crate_dir).unwrap();
    fs::write(
        crate_dir.join("Cargo.toml"),
        "[package]\nname = \"my-crate\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();

    let layout = workspace::detect_workspace(tmp.path()).unwrap();
    match layout {
        workspace::WorkspaceLayout::Monorepo { packages, .. } => {
            assert!(packages.iter().any(|p| p.name == "my-crate"));
        }
        _ => panic!("Should detect Cargo workspace"),
    }
}

// ============================================================
// Language detection edge cases
// ============================================================

#[test]
fn harden_detect_empty_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let langs = workspace::detect::detect_languages(tmp.path());
    assert!(langs.is_empty(), "Empty dir should detect no languages");
}

#[test]
fn harden_detect_multiple_languages() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("Cargo.toml"), "[package]\n").unwrap();
    fs::write(tmp.path().join("package.json"), "{}").unwrap();
    fs::write(tmp.path().join("requirements.txt"), "flask\n").unwrap();
    fs::write(tmp.path().join("go.mod"), "module test\n").unwrap();

    let langs = workspace::detect::detect_languages(tmp.path());
    assert!(langs.contains(&"rust".to_string()));
    assert!(langs.contains(&"javascript".to_string()));
    assert!(langs.contains(&"python".to_string()));
    assert!(langs.contains(&"go".to_string()));
}

// ============================================================
// Integrity check edge cases
// ============================================================

#[test]
fn harden_integrity_missing_everything() {
    let tmp = tempfile::tempdir().unwrap();
    let drift_path = tmp.path().join(".drift");
    fs::create_dir_all(&drift_path).unwrap();

    let report = workspace::verify_workspace(&drift_path, false).unwrap();
    assert!(matches!(
        report.drift_db,
        workspace::integrity::DatabaseIntegrity::Missing
    ));
    assert!(matches!(
        report.config,
        workspace::integrity::ConfigIntegrity::Missing
    ));
}

#[test]
fn harden_integrity_thorough_check() {
    let tmp = tempfile::tempdir().unwrap();
    workspace::workspace_init(workspace::InitOptions {
        root: Some(tmp.path().to_path_buf()),
        ..Default::default()
    })
    .unwrap();

    let drift_path = tmp.path().join(".drift");

    // Thorough check (full integrity_check instead of quick_check)
    let report = workspace::verify_workspace(&drift_path, true).unwrap();
    assert!(matches!(
        report.drift_db,
        workspace::integrity::DatabaseIntegrity::Ok
    ));
}

// ============================================================
// Telemetry buffer overflow protection
// ============================================================

#[test]
fn harden_telemetry_buffer_cap() {
    use drift_core::config::telemetry_config::TelemetryConfig;
    use drift_core::telemetry::{TelemetryCollector, TelemetryEventType};

    let config = TelemetryConfig {
        enabled: Some(true),
        ..Default::default()
    };
    let collector = TelemetryCollector::new(&config, None);

    // Push 1500 events — buffer should cap at 1000
    for _ in 0..1500 {
        collector.record_simple(TelemetryEventType::ScanCompleted);
    }
    assert_eq!(collector.pending_count(), 1000);
}

#[test]
fn harden_telemetry_serialize_batch() {
    use drift_core::config::telemetry_config::TelemetryConfig;
    use drift_core::telemetry::{TelemetryCollector, TelemetryEventType};

    let config = TelemetryConfig {
        enabled: Some(true),
        ..Default::default()
    };
    let collector = TelemetryCollector::new(&config, None);
    collector.record_simple(TelemetryEventType::WorkspaceInit);

    let batch = collector.serialize_batch();
    assert!(batch.is_some());
    let json = batch.unwrap();
    assert!(json.contains("workspace_init"));

    // After serialize, buffer should be drained
    assert_eq!(collector.pending_count(), 0);
    assert!(collector.serialize_batch().is_none());
}

// ============================================================
// Licensing edge cases
// ============================================================

#[test]
fn harden_jwt_empty_claims() {
    use drift_core::licensing;

    // JWT with minimal/empty claims
    let claims = licensing::LicenseClaims {
        sub: String::new(),
        tier: String::new(),
        iat: 0,
        exp: 0,
        features: vec![],
        org_id: None,
        seats: None,
    };

    let token = licensing::jwt::create_test_jwt(&claims);
    let parsed = licensing::jwt::parse_jwt(&token).unwrap();
    assert_eq!(parsed.sub, "");
    assert_eq!(parsed.tier, "");

    // exp=0 means never expires
    assert!(licensing::jwt::validate_claims(&parsed).is_ok());
}

#[test]
fn harden_jwt_unicode_subject() {
    use drift_core::licensing;

    let claims = licensing::LicenseClaims {
        sub: "用户@例え.jp".to_string(),
        tier: "enterprise".to_string(),
        iat: 1000000,
        exp: 0,
        features: vec!["taint_analysis".to_string()],
        org_id: Some("org-日本".to_string()),
        seats: Some(100),
    };

    let token = licensing::jwt::create_test_jwt(&claims);
    let parsed = licensing::jwt::parse_jwt(&token).unwrap();
    assert_eq!(parsed.sub, "用户@例え.jp");
    assert_eq!(parsed.org_id.as_deref(), Some("org-日本"));
}

