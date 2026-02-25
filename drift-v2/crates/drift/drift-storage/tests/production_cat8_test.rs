//! Production Cat 8: Migration & Schema Evolution
//!
//! 7 migration files (v001–v007), v006 has PART2 split.
//! Tests: T8-01 through T8-06.

use drift_storage::connection::pragmas::apply_pragmas;
use drift_storage::migrations;
use drift_storage::DatabaseManager;
use rusqlite::Connection;
use tempfile::TempDir;

// ---- Helpers ----

fn fresh_migrated_conn() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    apply_pragmas(&conn).unwrap();
    migrations::run_migrations(&conn).unwrap();
    conn
}

fn get_table_names(conn: &Connection) -> Vec<String> {
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        .unwrap();
    stmt.query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
}

fn get_column_count(conn: &Connection, table: &str) -> usize {
    let mut stmt = conn
        .prepare(&format!("PRAGMA table_info({})", table))
        .unwrap();
    stmt.query_map([], |row| row.get::<_, String>(1))
        .unwrap()
        .filter_map(|r| r.ok())
        .count()
}

// ---- T8-01: Fresh DB — All 45 Tables Created ----

#[test]
fn t8_01_fresh_db_all_45_tables_created() {
    let conn = fresh_migrated_conn();

    let tables = get_table_names(&conn);

    // All 46 expected tables from v001–v009 (+ v006 PART2)
    let expected_tables = [
        // v001
        "file_metadata",
        "parse_cache",
        "functions",
        "scan_history",
        // v002
        "call_edges",
        "data_access",
        "detections",
        "boundaries",
        // v003
        "pattern_confidence",
        "outliers",
        "conventions",
        // v004
        "reachability_cache",
        "taint_flows",
        "error_gaps",
        "impact_scores",
        "test_coverage",
        "test_quality",
        // v005
        "coupling_metrics",
        "coupling_cycles",
        "constraints",
        "constraint_verifications",
        "contracts",
        "contract_mismatches",
        "constants",
        "secrets",
        "env_variables",
        "wrappers",
        "dna_genes",
        "dna_mutations",
        "crypto_findings",
        "owasp_findings",
        "decomposition_decisions",
        // v006 PART1
        "violations",
        "gate_results",
        // v006 PART2
        "audit_snapshots",
        "health_trends",
        "feedback",
        "policy_results",
        "degradation_alerts",
        // v007
        "simulations",
        "decisions",
        "context_cache",
        "migration_projects",
        "migration_modules",
        "migration_corrections",
        // v009
        "pattern_status",
    ];

    assert_eq!(
        expected_tables.len(),
        46,
        "sanity: expected_tables array must have 46 entries"
    );

    for table_name in &expected_tables {
        assert!(
            tables.contains(&table_name.to_string()),
            "missing table: {table_name}"
        );
    }

    // Verify total table count matches
    assert_eq!(
        tables.len(),
        46,
        "expected 46 tables, got {}: {:?}",
        tables.len(),
        tables
    );

    // Verify total column count across all tables matches DD-15 audit
    // v001-v007: 398 columns + v008 scan_root: 1 column + v009 pattern_status: 7 columns = 406
    let total_columns: usize = expected_tables
        .iter()
        .map(|t| get_column_count(&conn, t))
        .sum();
    assert_eq!(
        total_columns, 406,
        "total column count across 46 tables must be 406 (DD-15 audit + v008 + v009)"
    );

    // Verify schema version
    let version = migrations::current_version(&conn).unwrap();
    assert_eq!(version, 9);
}

// ---- T8-02: Idempotent Re-Open ----

#[test]
fn t8_02_idempotent_reopen() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test_idempotent.db");

    // First open — creates and migrates
    {
        let _db = DatabaseManager::open(&db_path).unwrap();
    }

    // Second open — must not fail with "table already exists"
    {
        let db = DatabaseManager::open(&db_path).unwrap();
        db.with_writer(|conn| {
            let version = migrations::current_version(conn).unwrap();
            assert_eq!(version, 9, "version must remain 9 after re-open");

            let tables = get_table_names(conn);
            assert_eq!(tables.len(), 46, "all 46 tables must still exist after re-open");
            Ok(())
        })
        .unwrap();
    }

    // Third open — triple-check idempotency
    {
        let db = DatabaseManager::open(&db_path).unwrap();
        db.with_writer(|conn| {
            let version = migrations::current_version(conn).unwrap();
            assert_eq!(version, 9);
            Ok(())
        })
        .unwrap();
    }
}

// ---- T8-03: v006 PART2 Execution ----

#[test]
fn t8_03_v006_part2_execution() {
    let conn = fresh_migrated_conn();

    // Tables from v006 PART1
    let part1_tables = ["violations", "gate_results"];

    // Tables from v006 PART2
    let part2_tables = [
        "audit_snapshots",
        "health_trends",
        "feedback",
        "policy_results",
        "degradation_alerts",
    ];

    let all_tables = get_table_names(&conn);

    for t in &part1_tables {
        assert!(
            all_tables.contains(&t.to_string()),
            "v006 PART1 table missing: {t}"
        );
    }

    for t in &part2_tables {
        assert!(
            all_tables.contains(&t.to_string()),
            "v006 PART2 table missing: {t}"
        );
    }

    // Verify PART2 tables have correct columns
    // audit_snapshots: id, health_score, avg_confidence, approval_ratio,
    //   compliance_rate, cross_validation_rate, duplicate_free_rate,
    //   pattern_count, category_scores, created_at = 10 columns
    //   + scan_root (v008) = 11 columns
    assert_eq!(
        get_column_count(&conn, "audit_snapshots"),
        11,
        "audit_snapshots column count"
    );

    // feedback: id, violation_id, pattern_id, detector_id, action,
    //   dismissal_reason, reason, author, created_at = 9 columns
    assert_eq!(
        get_column_count(&conn, "feedback"),
        9,
        "feedback column count"
    );

    // policy_results: id, policy_name, aggregation_mode, overall_passed,
    //   overall_score, gate_count, gates_passed, gates_failed, details,
    //   run_at = 10 columns
    assert_eq!(
        get_column_count(&conn, "policy_results"),
        10,
        "policy_results column count"
    );

    // degradation_alerts: id, alert_type, severity, message, current_value,
    //   previous_value, delta, created_at = 8 columns
    assert_eq!(
        get_column_count(&conn, "degradation_alerts"),
        8,
        "degradation_alerts column count"
    );
}

// ---- T8-04: Foreign Key Integrity — constraint_verifications ----

#[test]
fn t8_04_fk_integrity_constraint_verifications() {
    let conn = fresh_migrated_conn();

    // Verify foreign_keys is ON
    let fk_enabled: i64 = conn
        .pragma_query_value(None, "foreign_keys", |row| row.get(0))
        .unwrap();
    assert_eq!(fk_enabled, 1, "foreign_keys must be ON");

    // Insert into constraint_verifications with a non-existent constraint_id
    // This must fail due to FK constraint: constraint_verifications.constraint_id → constraints(id)
    let result = conn.execute(
        "INSERT INTO constraint_verifications (constraint_id, passed, violations, verified_at) \
         VALUES ('nonexistent_constraint_id', 1, '[]', unixepoch())",
        [],
    );

    assert!(
        result.is_err(),
        "inserting with invalid constraint_id must fail due to FK constraint"
    );

    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("FOREIGN KEY"),
        "error must mention FOREIGN KEY: {err_msg}"
    );

    // Now insert a valid constraint first, then a verification referencing it
    conn.execute(
        "INSERT INTO constraints (id, description, invariant_type, target, source) \
         VALUES ('c1', 'test constraint', 'type_a', 'target_a', 'source_a')",
        [],
    )
    .unwrap();

    conn.execute(
        "INSERT INTO constraint_verifications (constraint_id, passed, violations, verified_at) \
         VALUES ('c1', 1, '[]', unixepoch())",
        [],
    )
    .unwrap();

    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM constraint_verifications WHERE constraint_id = 'c1'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 1, "valid FK insert must succeed");
}

// ---- T8-05: FK Cascade — migration_modules ----

#[test]
fn t8_05_fk_cascade_migration_modules() {
    let conn = fresh_migrated_conn();

    // Insert a migration_project
    conn.execute(
        "INSERT INTO migration_projects (name, source_language, target_language, status) \
         VALUES ('test-project', 'python', 'rust', 'active')",
        [],
    )
    .unwrap();

    let project_id: i64 = conn
        .query_row(
            "SELECT id FROM migration_projects WHERE name = 'test-project'",
            [],
            |row| row.get(0),
        )
        .unwrap();

    // Insert a migration_module referencing the project
    conn.execute(
        "INSERT INTO migration_modules (project_id, module_name, status) VALUES (?1, 'mod_a', 'pending')",
        [project_id],
    )
    .unwrap();

    let module_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM migration_modules WHERE project_id = ?1",
            [project_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(module_count, 1, "module must be inserted");

    // Delete the parent project — since there is no ON DELETE CASCADE,
    // this must fail while child rows exist
    let delete_result = conn.execute(
        "DELETE FROM migration_projects WHERE id = ?1",
        [project_id],
    );

    assert!(
        delete_result.is_err(),
        "deleting parent with FK children must fail (no CASCADE defined)"
    );

    let err_msg = delete_result.unwrap_err().to_string();
    assert!(
        err_msg.contains("FOREIGN KEY"),
        "error must mention FOREIGN KEY: {err_msg}"
    );

    // Verify: insert migration_module with invalid project_id must also fail
    let invalid_result = conn.execute(
        "INSERT INTO migration_modules (project_id, module_name, status) VALUES (99999, 'mod_b', 'pending')",
        [],
    );
    assert!(
        invalid_result.is_err(),
        "inserting module with non-existent project_id must fail"
    );

    // Also verify migration_corrections FK to migration_modules
    let module_id: i64 = conn
        .query_row(
            "SELECT id FROM migration_modules WHERE module_name = 'mod_a'",
            [],
            |row| row.get(0),
        )
        .unwrap();

    // Valid correction insert
    conn.execute(
        "INSERT INTO migration_corrections (module_id, section, original_text, corrected_text, reason) \
         VALUES (?1, 'imports', 'old', 'new', 'test')",
        [module_id],
    )
    .unwrap();

    // Invalid correction insert (bad module_id)
    let bad_correction = conn.execute(
        "INSERT INTO migration_corrections (module_id, section, original_text, corrected_text) \
         VALUES (99999, 'imports', 'old', 'new')",
        [],
    );
    assert!(
        bad_correction.is_err(),
        "inserting correction with non-existent module_id must fail"
    );
}

// ---- T8-06: WAL Mode Verification ----

#[test]
fn t8_06_wal_mode_verification() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test_wal.db");

    let db = DatabaseManager::open(&db_path).unwrap();

    db.with_writer(|conn| {
        // Verify journal_mode = wal
        let mode: String = conn
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .unwrap();
        assert!(
            mode.eq_ignore_ascii_case("wal"),
            "journal_mode must be 'wal', got '{mode}'"
        );

        // Also verify other key pragmas from apply_pragmas
        let synchronous: i64 = conn
            .pragma_query_value(None, "synchronous", |row| row.get(0))
            .unwrap();
        assert_eq!(synchronous, 1, "synchronous must be NORMAL (1)");

        let fk: i64 = conn
            .pragma_query_value(None, "foreign_keys", |row| row.get(0))
            .unwrap();
        assert_eq!(fk, 1, "foreign_keys must be ON");

        let cache_size: i64 = conn
            .pragma_query_value(None, "cache_size", |row| row.get(0))
            .unwrap();
        assert_eq!(cache_size, -64000, "cache_size must be -64000 (64MB)");

        let mmap_size: i64 = conn
            .pragma_query_value(None, "mmap_size", |row| row.get(0))
            .unwrap();
        assert_eq!(mmap_size, 268435456, "mmap_size must be 256MB");

        let busy_timeout: i64 = conn
            .pragma_query_value(None, "busy_timeout", |row| row.get(0))
            .unwrap();
        assert_eq!(busy_timeout, 5000, "busy_timeout must be 5000ms");

        let temp_store: i64 = conn
            .pragma_query_value(None, "temp_store", |row| row.get(0))
            .unwrap();
        assert_eq!(temp_store, 2, "temp_store must be MEMORY (2)");

        let auto_vacuum: i64 = conn
            .pragma_query_value(None, "auto_vacuum", |row| row.get(0))
            .unwrap();
        assert_eq!(auto_vacuum, 2, "auto_vacuum must be INCREMENTAL (2)");

        Ok(())
    })
    .unwrap();

    // Also verify using the dedicated helper
    db.with_writer(|conn| {
        let is_wal = drift_storage::connection::pragmas::verify_wal_mode(conn).unwrap();
        assert!(is_wal, "verify_wal_mode() must return true");
        Ok(())
    })
    .unwrap();
}
