//! Phase 7 advanced storage integration tests.
//!
//! Tests: T7-INT-01, T7-SPEC-24, T7-SPEC-26, T7-SPEC-27, T7-SPEC-33 (db round-trip).
//! All tests use in-memory SQLite via `rusqlite::Connection::open_in_memory()`.

use drift_storage::connection::pragmas::apply_pragmas;
use drift_storage::migrations;
use drift_storage::queries::advanced;
use rusqlite::Connection;

fn test_connection() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    apply_pragmas(&conn).unwrap();
    migrations::run_migrations(&conn).unwrap();
    conn
}

// ─── T7-INT-01: All Phase 7 results persist to drift.db ───

#[test]
fn t7_int_01_simulations_persist() {
    let conn = test_connection();

    let id = advanced::insert_simulation(
        &conn,
        "add_feature",
        "Add user profile page",
        3,
        Some("incremental"),
        2.5,
        5.0,
        12.0,
    )
    .unwrap();

    assert!(id > 0);

    let rows = advanced::get_simulations(&conn, 10).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].task_category, "add_feature");
    assert_eq!(rows[0].task_description, "Add user profile page");
    assert_eq!(rows[0].approach_count, 3);
    assert_eq!(rows[0].recommended_approach.as_deref(), Some("incremental"));
    assert!((rows[0].p10_effort - 2.5).abs() < f64::EPSILON);
    assert!((rows[0].p50_effort - 5.0).abs() < f64::EPSILON);
    assert!((rows[0].p90_effort - 12.0).abs() < f64::EPSILON);
}

#[test]
fn t7_int_01_decisions_persist() {
    let conn = test_connection();

    let id = advanced::insert_decision(
        &conn,
        "architecture",
        "Switched from monolith to microservices",
        Some("abc123"),
        0.85,
        Some("service_boundary,api_gateway"),
        Some("alice"),
        Some("src/gateway.ts,src/services/"),
    )
    .unwrap();

    assert!(id > 0);

    // Verify via raw query
    let desc: String = conn
        .query_row("SELECT description FROM decisions WHERE id = ?1", [id], |r| r.get(0))
        .unwrap();
    assert_eq!(desc, "Switched from monolith to microservices");
}

#[test]
fn t7_int_01_context_cache_persists() {
    let conn = test_connection();

    let id = advanced::insert_context_cache(
        &conn,
        "session-001",
        "fix_bug",
        "deep",
        8500,
        "sha256:abcdef1234567890",
    )
    .unwrap();

    assert!(id > 0);

    let (session, intent, depth, tokens): (String, String, String, i32) = conn
        .query_row(
            "SELECT session_id, intent, depth, token_count FROM context_cache WHERE id = ?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();

    assert_eq!(session, "session-001");
    assert_eq!(intent, "fix_bug");
    assert_eq!(depth, "deep");
    assert_eq!(tokens, 8500);
}


#[test]
fn t7_int_01_migration_projects_persist() {
    let conn = test_connection();

    let proj_id = advanced::create_migration_project(
        &conn,
        "Legacy CRM Migration",
        "python",
        "typescript",
        Some("django"),
        Some("nestjs"),
    )
    .unwrap();

    assert!(proj_id > 0);

    let mod_id = advanced::create_migration_module(&conn, proj_id, "auth_module").unwrap();
    assert!(mod_id > 0);

    advanced::update_module_status(&conn, mod_id, "spec_generated").unwrap();

    let status: String = conn
        .query_row(
            "SELECT status FROM migration_modules WHERE id = ?1",
            [mod_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(status, "spec_generated");
}

#[test]
fn t7_int_01_multiple_simulations_ordered() {
    let conn = test_connection();

    for i in 0..5 {
        advanced::insert_simulation(
            &conn,
            &format!("category_{}", i),
            &format!("task {}", i),
            i + 1,
            None,
            1.0 * (i as f64 + 1.0),
            2.0 * (i as f64 + 1.0),
            3.0 * (i as f64 + 1.0),
        )
        .unwrap();
    }

    let rows = advanced::get_simulations(&conn, 3).unwrap();
    assert_eq!(rows.len(), 3);
    // Most recent first (DESC order)
    assert_eq!(rows[0].task_category, "category_4");
}

// ─── T7-SPEC-24: Concurrent migration status updates ───

#[test]
fn t7_spec_24_concurrent_status_updates() {
    // Use a temp file so multiple threads can open the same db
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    // Set up schema on main connection
    {
        let conn = Connection::open(&db_path).unwrap();
        apply_pragmas(&conn).unwrap();
        migrations::run_migrations(&conn).unwrap();

        let proj_id = advanced::create_migration_project(
            &conn,
            "Concurrent Test",
            "java",
            "kotlin",
            None,
            None,
        )
        .unwrap();

        for i in 0..4 {
            advanced::create_migration_module(&conn, proj_id, &format!("module_{}", i)).unwrap();
        }
    }

    // 4 threads update different modules simultaneously
    let handles: Vec<_> = (0..4)
        .map(|i| {
            let path = db_path.clone();
            std::thread::spawn(move || {
                let conn = Connection::open(&path).unwrap();
                conn.busy_timeout(std::time::Duration::from_secs(5)).unwrap();
                let module_id = (i + 1) as i64;
                advanced::update_module_status(&conn, module_id, "spec_generated")
            })
        })
        .collect();

    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    // All updates should succeed
    for (i, result) in results.iter().enumerate() {
        assert!(result.is_ok(), "Thread {} failed: {:?}", i, result);
    }

    // Verify all updates persisted
    let conn = Connection::open(&db_path).unwrap();
    for i in 1..=4 {
        let status: String = conn
            .query_row(
                "SELECT status FROM migration_modules WHERE id = ?1",
                [i as i64],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(status, "spec_generated", "Module {} not updated", i);
    }
}

// ─── T7-SPEC-26: migration_projects table created by v007 migration ───

#[test]
fn t7_spec_26_migration_tables_created_by_migration() {
    let conn = Connection::open_in_memory().unwrap();
    apply_pragmas(&conn).unwrap();
    // v007 migration creates migration_projects, migration_modules, migration_corrections
    migrations::run_migrations(&conn).unwrap();

    // Verify all 3 tables exist after migrations
    for table in &["migration_projects", "migration_modules", "migration_corrections"] {
        let count: i32 = conn
            .query_row(
                &format!("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='{table}'"),
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "Table {table} should exist after v007 migration");
    }

    // create_migration_project works on migrated database
    let proj_id = advanced::create_migration_project(
        &conn,
        "Migrated Project",
        "ruby",
        "go",
        Some("rails"),
        None,
    )
    .unwrap();

    assert!(proj_id > 0);

    let name: String = conn
        .query_row(
            "SELECT name FROM migration_projects WHERE id = ?1",
            [proj_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(name, "Migrated Project");
}

// ─── T7-SPEC-27: Invalid status string in migration_modules row ───

#[test]
fn t7_spec_27_invalid_status_string_readable() {
    let conn = test_connection();

    let proj_id = advanced::create_migration_project(
        &conn,
        "Status Test",
        "python",
        "rust",
        None,
        None,
    )
    .unwrap();

    let mod_id = advanced::create_migration_module(&conn, proj_id, "test_mod").unwrap();

    // Manually insert an invalid status
    conn.execute(
        "UPDATE migration_modules SET status = 'banana' WHERE id = ?1",
        [mod_id],
    )
    .unwrap();

    // Reading the raw status string should work (it's just TEXT)
    let status: String = conn
        .query_row(
            "SELECT status FROM migration_modules WHERE id = ?1",
            [mod_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(status, "banana");

    // The raw string 'banana' is stored — the domain layer (drift-context)
    // is responsible for rejecting it via MigrationModuleStatus::from_str_loose.
    // That validation is tested in specification_test.rs (test_migration_status_from_str).
    // Here we verify the storage layer doesn't crash on arbitrary status strings.
}

// ─── T7-SPEC-33 (db round-trip): Correction preserves text through SQLite ───

#[test]
fn t7_spec_33_correction_round_trip_through_db() {
    let conn = test_connection();

    let proj_id = advanced::create_migration_project(
        &conn,
        "Correction Test",
        "java",
        "kotlin",
        None,
        None,
    )
    .unwrap();

    let mod_id = advanced::create_migration_module(&conn, proj_id, "auth").unwrap();

    let original = "Unicode: 你好世界 🌍\nNewlines: line1\nline2\nSpecial: <>&\"'\tTab\0Null";
    let corrected = "Fixed version with proper handling";

    let corr_id = advanced::insert_migration_correction(
        &conn,
        mod_id,
        "overview",
        original,
        corrected,
        Some("improve clarity"),
    )
    .unwrap();

    let row = advanced::get_migration_correction(&conn, corr_id)
        .unwrap()
        .expect("Correction should exist");

    assert_eq!(row.original_text, original, "Original text must survive SQLite round-trip");
    assert_eq!(row.corrected_text, corrected);
    assert_eq!(row.section, "overview");
    assert_eq!(row.reason.as_deref(), Some("improve clarity"));
    assert_eq!(row.module_id, mod_id);
}

// ─── Additional: Edge cases ───

#[test]
fn test_simulation_with_null_recommended_approach() {
    let conn = test_connection();

    let _id = advanced::insert_simulation(
        &conn,
        "refactor",
        "Extract service layer",
        2,
        None,
        1.0,
        3.0,
        8.0,
    )
    .unwrap();

    let rows = advanced::get_simulations(&conn, 10).unwrap();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].recommended_approach.is_none());
}

#[test]
fn test_get_nonexistent_correction() {
    let conn = test_connection();
    let result = advanced::get_migration_correction(&conn, 99999).unwrap();
    assert!(result.is_none());
}

#[test]
fn test_empty_simulations_table() {
    let conn = test_connection();
    let rows = advanced::get_simulations(&conn, 10).unwrap();
    assert!(rows.is_empty());
}
