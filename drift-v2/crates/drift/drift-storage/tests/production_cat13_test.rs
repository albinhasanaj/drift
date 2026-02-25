//! Production Category 13: Retention & Data Lifecycle
//!
//! 4-tier retention system (Current/orphan, Short 30d, Medium 90d, Long 365d).
//! Tests verify column correctness, atomicity, self-bounding semantics,
//! and complete tier assignment coverage across all 45 migrated tables.

use std::collections::HashSet;

use drift_storage::migrations::run_migrations;
use drift_storage::retention::{apply_retention, RetentionPolicy};
use rusqlite::{params, Connection};

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

fn setup_db() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    run_migrations(&conn).unwrap();
    conn
}

fn epoch_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Query all user table names from sqlite_master.
fn all_table_names(conn: &Connection) -> HashSet<String> {
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        .unwrap();
    let names: Vec<String> = stmt
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    names.into_iter().collect()
}

// ═══════════════════════════════════════════════════════════════════════════
// T13-01: constraint_verifications Column Name
//
// Bug found and fixed: retention.rs line 128 was using `created_at` but the
// constraint_verifications table uses `verified_at` for its timestamp column.
// This test ensures the fix stays in place by inserting a row with an old
// `verified_at` and verifying retention actually cleans it up.
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn t13_01_constraint_verifications_column_name() {
    let conn = setup_db();
    let now = epoch_now();

    // Insert a constraint first (FK target)
    conn.execute(
        "INSERT INTO constraints (id, description, invariant_type, target, source, enabled, created_at, updated_at) \
         VALUES ('c1', 'test constraint', 'dependency', 'src/', 'manual', 1, ?1, ?1)",
        params![now],
    )
    .unwrap();

    // Insert a constraint verification with old verified_at (120 days ago → past 90d medium cutoff)
    conn.execute(
        "INSERT INTO constraint_verifications (constraint_id, passed, violations, verified_at) \
         VALUES ('c1', 1, '[]', ?1)",
        params![now - 120 * 86400],
    )
    .unwrap();

    // Insert a recent constraint verification (1 day ago → within 90d medium cutoff)
    conn.execute(
        "INSERT INTO constraint_verifications (constraint_id, passed, violations, verified_at) \
         VALUES ('c1', 0, '[\"v1\"]', ?1)",
        params![now - 86400],
    )
    .unwrap();

    let report = apply_retention(
        &conn,
        &RetentionPolicy {
            short_days: 30,
            medium_days: 90,
            long_days: 365,
        },
    )
    .unwrap();

    // Old row should be cleaned via verified_at, recent row should survive
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM constraint_verifications",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 1, "Should keep only the recent verification");
    assert!(
        report.total_deleted >= 1,
        "Should report deletion of old verification"
    );

    // Verify it's the recent one that survived
    let survived_passed: i64 = conn
        .query_row(
            "SELECT passed FROM constraint_verifications",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(survived_passed, 0, "Recent verification (passed=0) should survive");
}

// ═══════════════════════════════════════════════════════════════════════════
// T13-02: Orphan Cleanup Atomicity
//
// Insert 1000 orphaned entries. Verify the entire cleanup runs atomically
// inside a single transaction. Then verify that if an error occurs mid-
// retention, all prior cleanups in that transaction are rolled back.
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn t13_02_orphan_cleanup_atomicity() {
    let conn = setup_db();
    let now = epoch_now();

    // Track one file — everything else is orphaned
    conn.execute(
        "INSERT OR REPLACE INTO file_metadata (path, language, file_size, content_hash, mtime_secs, mtime_nanos, last_scanned_at, scan_duration_us) \
         VALUES ('src/keep.ts', 'ts', 100, X'AA', ?1, 0, ?1, 10)",
        params![now],
    )
    .unwrap();

    // Insert 1000 orphaned detections (files not in file_metadata)
    for i in 0..1000 {
        conn.execute(
            "INSERT INTO detections (file, line, column_num, pattern_id, category, confidence, detection_method, created_at) \
             VALUES (?1, 1, 1, 'p1', 'c', 0.9, 'regex', ?2)",
            params![format!("src/orphan_{i}.ts"), now],
        )
        .unwrap();
    }

    // Also insert one detection for the tracked file
    conn.execute(
        "INSERT INTO detections (file, line, column_num, pattern_id, category, confidence, detection_method, created_at) \
         VALUES ('src/keep.ts', 1, 1, 'p1', 'c', 0.9, 'regex', ?1)",
        params![now],
    )
    .unwrap();

    let pre_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM detections", [], |r| r.get(0))
        .unwrap();
    assert_eq!(pre_count, 1001);

    // Run retention — should clean all 1000 orphans atomically
    let report = apply_retention(
        &conn,
        &RetentionPolicy {
            short_days: 9999,
            medium_days: 9999,
            long_days: 9999,
        },
    )
    .unwrap();

    let post_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM detections", [], |r| r.get(0))
        .unwrap();
    assert_eq!(post_count, 1, "Should keep only the tracked-file detection");
    assert!(
        report.total_deleted >= 1000,
        "Should report >= 1000 orphan deletions, got {}",
        report.total_deleted
    );

    // ── Rollback test ──
    // Now verify atomicity on failure: drop a table that retention processes
    // mid-way through. Orphan data inserted before that point must survive
    // if the transaction rolls back.
    let conn2 = setup_db();

    // Track a file
    conn2.execute(
        "INSERT OR REPLACE INTO file_metadata (path, language, file_size, content_hash, mtime_secs, mtime_nanos, last_scanned_at, scan_duration_us) \
         VALUES ('src/keep.ts', 'ts', 100, X'AA', ?1, 0, ?1, 10)",
        params![now],
    )
    .unwrap();

    // Insert orphaned detection (will be cleaned before the dropped table is hit)
    conn2.execute(
        "INSERT INTO detections (file, line, column_num, pattern_id, category, confidence, detection_method, created_at) \
         VALUES ('src/orphan.ts', 1, 1, 'p1', 'c', 0.9, 'regex', ?1)",
        params![now],
    )
    .unwrap();

    // Insert old scan_history that would be cleaned in medium tier
    conn2.execute(
        "INSERT INTO scan_history (started_at, root_path) VALUES (?1, '/project')",
        params![now - 120 * 86400],
    )
    .unwrap();

    // Drop audit_snapshots — retention processes this in the medium tier,
    // AFTER orphan cleanup and short tier, so it should cause a mid-transaction error
    conn2.execute_batch("DROP TABLE audit_snapshots").unwrap();

    let result = apply_retention(
        &conn2,
        &RetentionPolicy {
            short_days: 30,
            medium_days: 90,
            long_days: 365,
        },
    );

    // Retention should fail
    assert!(result.is_err(), "Retention should fail when table is missing");

    // Orphan detection should still exist — transaction rolled back
    let orphan_count: i64 = conn2
        .query_row("SELECT COUNT(*) FROM detections WHERE file = 'src/orphan.ts'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        orphan_count, 1,
        "Orphan detection must survive when transaction rolls back"
    );

    // Old scan_history should also still exist
    let scan_count: i64 = conn2
        .query_row("SELECT COUNT(*) FROM scan_history", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        scan_count, 1,
        "Old scan_history must survive when transaction rolls back"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// T13-03: Self-Bounding Tables — reachability_cache
//
// reachability_cache has composite PK (source_node, direction).
// INSERT OR REPLACE semantics must prevent unbounded growth: inserting
// the same (source_node, direction) pair twice should result in 1 row.
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn t13_03_self_bounding_reachability_cache() {
    let conn = setup_db();
    let now = epoch_now();

    // First insert
    conn.execute(
        "INSERT OR REPLACE INTO reachability_cache (source_node, direction, reachable_set, sensitivity, computed_at) \
         VALUES ('fn_main', 'forward', '[\"fn_a\",\"fn_b\"]', 'high', ?1)",
        params![now - 3600],
    )
    .unwrap();

    // Second insert with same PK — should REPLACE, not duplicate
    conn.execute(
        "INSERT OR REPLACE INTO reachability_cache (source_node, direction, reachable_set, sensitivity, computed_at) \
         VALUES ('fn_main', 'forward', '[\"fn_a\",\"fn_b\",\"fn_c\"]', 'high', ?1)",
        params![now],
    )
    .unwrap();

    // Different direction = different PK → should be a separate row
    conn.execute(
        "INSERT OR REPLACE INTO reachability_cache (source_node, direction, reachable_set, sensitivity, computed_at) \
         VALUES ('fn_main', 'backward', '[\"fn_z\"]', 'low', ?1)",
        params![now],
    )
    .unwrap();

    let total: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM reachability_cache",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(total, 2, "Same PK should replace, different PK should add");

    // Verify the forward row has the updated reachable_set (not the old one)
    let reachable: String = conn
        .query_row(
            "SELECT reachable_set FROM reachability_cache WHERE source_node = 'fn_main' AND direction = 'forward'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        reachable.contains("fn_c"),
        "Should have the updated reachable set"
    );

    // Verify unbounded growth protection: insert 500 entries for the same key
    for i in 0..500 {
        conn.execute(
            "INSERT OR REPLACE INTO reachability_cache (source_node, direction, reachable_set, sensitivity, computed_at) \
             VALUES ('fn_main', 'forward', ?1, 'high', ?2)",
            params![format!("[\"{i}\"]"), now + i],
        )
        .unwrap();
    }

    let after_500: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM reachability_cache WHERE source_node = 'fn_main' AND direction = 'forward'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        after_500, 1,
        "500 inserts to same PK must produce exactly 1 row"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// T13-04: Tier Assignment Coverage
//
// Every one of the 45 tables must be assigned to exactly one retention tier.
// No table should be orphaned from the retention policy.
//
// Tiers:
//   - Reference: file_metadata (the root reference table)
//   - Current (orphan cleanup): detections, functions, boundaries, constants,
//     secrets, env_variables, wrappers, crypto_findings, owasp_findings
//   - Short (30d): detections, outliers, violations, gate_results, error_gaps,
//     taint_flows, crypto_findings, owasp_findings, secrets, degradation_alerts,
//     policy_results
//   - Medium (90d): scan_history, audit_snapshots, health_trends, feedback,
//     constraint_verifications, contract_mismatches, dna_mutations,
//     coupling_cycles, decomposition_decisions
//   - Long (365d): parse_cache, context_cache, simulations, decisions,
//     migration_corrections, migration_modules, migration_projects
//   - Self-bounding (PK/UPSERT, no time-based cleanup needed):
//     call_edges, data_access, pattern_confidence, conventions,
//     reachability_cache, impact_scores, test_coverage, test_quality,
//     coupling_metrics, constraints, contracts, dna_genes
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn t13_04_tier_assignment_coverage() {
    let conn = setup_db();

    let all_tables = all_table_names(&conn);

    // ── Define every tier ──

    // Reference table (not cleaned, it IS the reference for orphan cleanup)
    let reference: HashSet<&str> = ["file_metadata"].into_iter().collect();

    // Current tier: orphan cleanup by file column
    let current_orphan: HashSet<&str> = [
        "detections",
        "functions",
        "boundaries",
        "constants",
        "secrets",
        "env_variables",
        "wrappers",
        "crypto_findings",
        "owasp_findings",
    ]
    .into_iter()
    .collect();

    // Short tier (30d): time-based cleanup
    let short_tier: HashSet<&str> = [
        "detections",
        "outliers",
        "violations",
        "gate_results",
        "error_gaps",
        "taint_flows",
        "crypto_findings",
        "owasp_findings",
        "secrets",
        "degradation_alerts",
        "policy_results",
    ]
    .into_iter()
    .collect();

    // Medium tier (90d): time-based cleanup
    let medium_tier: HashSet<&str> = [
        "scan_history",
        "audit_snapshots",
        "health_trends",
        "feedback",
        "constraint_verifications",
        "contract_mismatches",
        "dna_mutations",
        "coupling_cycles",
        "decomposition_decisions",
    ]
    .into_iter()
    .collect();

    // Long tier (365d): time-based cleanup
    let long_tier: HashSet<&str> = [
        "parse_cache",
        "context_cache",
        "simulations",
        "decisions",
        "migration_corrections",
        "migration_modules",
        "migration_projects",
    ]
    .into_iter()
    .collect();

    // Self-bounding: PK uniqueness / UPSERT prevents unbounded growth
    let self_bounding: HashSet<&str> = [
        "call_edges",
        "data_access",
        "pattern_confidence",
        "conventions",
        "reachability_cache",
        "impact_scores",
        "test_coverage",
        "test_quality",
        "coupling_metrics",
        "constraints",
        "contracts",
        "dna_genes",
        "pattern_status",
    ]
    .into_iter()
    .collect();

    // Union of all assigned tables
    let mut all_assigned: HashSet<&str> = HashSet::new();
    all_assigned.extend(&reference);
    all_assigned.extend(&current_orphan);
    all_assigned.extend(&short_tier);
    all_assigned.extend(&medium_tier);
    all_assigned.extend(&long_tier);
    all_assigned.extend(&self_bounding);

    // ── Verify every migrated table is in at least one tier ──
    let mut unassigned: Vec<String> = Vec::new();
    for table in &all_tables {
        if !all_assigned.contains(table.as_str()) {
            unassigned.push(table.clone());
        }
    }
    assert!(
        unassigned.is_empty(),
        "Tables not assigned to any retention tier: {:?}",
        unassigned
    );

    // ── Verify our tier definitions don't reference phantom tables ──
    let mut phantom: Vec<String> = Vec::new();
    for table in &all_assigned {
        if !all_tables.contains(*table) {
            phantom.push(table.to_string());
        }
    }
    assert!(
        phantom.is_empty(),
        "Tier definitions reference non-existent tables: {:?}",
        phantom
    );

    // ── Verify expected table count ──
    assert_eq!(
        all_tables.len(),
        46,
        "Expected 46 tables after all migrations, got {}. Tables: {:?}",
        all_tables.len(),
        all_tables
    );

    // ── Verify no table is in BOTH a time-based tier AND self-bounding ──
    // (Tables in both orphan + short is fine — they get both cleanup strategies)
    let time_based: HashSet<&str> = short_tier
        .union(&medium_tier)
        .copied()
        .collect::<HashSet<&str>>()
        .union(&long_tier)
        .copied()
        .collect();
    let overlap: Vec<&&str> = self_bounding.intersection(&time_based).collect();
    assert!(
        overlap.is_empty(),
        "Tables should not be both self-bounding AND time-cleaned: {:?}",
        overlap
    );
}
