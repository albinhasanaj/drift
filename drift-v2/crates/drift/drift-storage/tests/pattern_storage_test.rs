//! Phase 3 — Storage Round-Trip Tests
//!
//! Verifies that P3 pipeline output persists correctly to drift.db
//! and reads back identically. Tests the v003 migration, CRUD queries,
//! keyset pagination, and high-volume inserts.

use drift_storage::migrations;
use drift_storage::queries::patterns::{
    self, ConventionRow, OutlierRow, PatternConfidenceRow,
};
use rusqlite::Connection;

fn setup_db() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    // Enable WAL mode like production
    conn.pragma_update(None, "journal_mode", "WAL").unwrap();
    conn.pragma_update(None, "synchronous", "NORMAL").unwrap();
    migrations::run_migrations(&conn).unwrap();
    conn
}

// ═══════════════════════════════════════════════════════════════════════════
// CONFIDENCE ROUND-TRIP
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn roundtrip_confidence_insert_and_read() {
    let conn = setup_db();

    let row = PatternConfidenceRow {
        pattern_id: "pat_001".to_string(),
        alpha: 51.0,
        beta: 50.0,
        posterior_mean: 0.505,
        credible_interval_low: 0.41,
        credible_interval_high: 0.60,
        tier: "tentative".to_string(),
        momentum: "rising".to_string(),
        last_updated: 1700000000,
    };

    patterns::upsert_confidence(&conn, &row).unwrap();
    let all = patterns::query_all_confidence(&conn).unwrap();

    assert_eq!(all.len(), 1);
    let r = &all[0];
    assert_eq!(r.pattern_id, "pat_001");
    assert!((r.alpha - 51.0).abs() < 1e-10);
    assert!((r.beta - 50.0).abs() < 1e-10);
    assert!((r.posterior_mean - 0.505).abs() < 1e-10);
    assert_eq!(r.tier, "tentative");
    assert_eq!(r.momentum, "rising");
}

#[test]
fn roundtrip_confidence_upsert_overwrites() {
    let conn = setup_db();

    let row1 = PatternConfidenceRow {
        pattern_id: "pat_upsert".to_string(),
        alpha: 10.0,
        beta: 90.0,
        posterior_mean: 0.1,
        credible_interval_low: 0.05,
        credible_interval_high: 0.17,
        tier: "uncertain".to_string(),
        momentum: "stable".to_string(),
        last_updated: 1000,
    };
    patterns::upsert_confidence(&conn, &row1).unwrap();

    // Upsert with new values
    let row2 = PatternConfidenceRow {
        pattern_id: "pat_upsert".to_string(),
        alpha: 80.0,
        beta: 20.0,
        posterior_mean: 0.8,
        credible_interval_low: 0.71,
        credible_interval_high: 0.87,
        tier: "emerging".to_string(),
        momentum: "rising".to_string(),
        last_updated: 2000,
    };
    patterns::upsert_confidence(&conn, &row2).unwrap();

    let all = patterns::query_all_confidence(&conn).unwrap();
    assert_eq!(all.len(), 1, "Upsert should not create duplicate");
    assert!((all[0].alpha - 80.0).abs() < 1e-10);
    assert_eq!(all[0].tier, "emerging");
    assert_eq!(all[0].last_updated, 2000);
}

#[test]
fn roundtrip_confidence_1000_rows() {
    let conn = setup_db();

    for i in 0..1000 {
        let row = PatternConfidenceRow {
            pattern_id: format!("pat_{:04}", i),
            alpha: (i as f64) + 1.0,
            beta: (1000 - i) as f64 + 1.0,
            posterior_mean: (i as f64 + 1.0) / 1002.0,
            credible_interval_low: 0.0,
            credible_interval_high: 1.0,
            tier: if i > 850 { "established" } else { "tentative" }.to_string(),
            momentum: "stable".to_string(),
            last_updated: 1000 + i as i64,
        };
        patterns::upsert_confidence(&conn, &row).unwrap();
    }

    let all = patterns::query_all_confidence(&conn).unwrap();
    assert_eq!(all.len(), 1000);

    // Verify ordering (by posterior_mean DESC)
    for i in 1..all.len() {
        assert!(
            all[i - 1].posterior_mean >= all[i].posterior_mean,
            "Results should be ordered by posterior_mean DESC"
        );
    }
}

#[test]
fn roundtrip_confidence_keyset_pagination() {
    let conn = setup_db();

    // Insert 50 "established" patterns
    for i in 0..50 {
        let row = PatternConfidenceRow {
            pattern_id: format!("est_{:03}", i),
            alpha: 90.0,
            beta: 10.0,
            posterior_mean: 0.9,
            credible_interval_low: 0.85,
            credible_interval_high: 0.95,
            tier: "established".to_string(),
            momentum: "stable".to_string(),
            last_updated: 1000,
        };
        patterns::upsert_confidence(&conn, &row).unwrap();
    }

    // Page through with limit=10
    let mut all_ids = Vec::new();
    let mut cursor: Option<String> = None;

    loop {
        let page = patterns::query_confidence_by_tier(
            &conn,
            "established",
            cursor.as_deref(),
            10,
        )
        .unwrap();

        if page.is_empty() {
            break;
        }

        for row in &page {
            all_ids.push(row.pattern_id.clone());
        }
        cursor = Some(page.last().unwrap().pattern_id.clone());
    }

    assert_eq!(all_ids.len(), 50, "Pagination should return all 50 rows");

    // Verify no duplicates
    let unique: std::collections::HashSet<&String> = all_ids.iter().collect();
    assert_eq!(unique.len(), 50, "Pagination must not produce duplicates");

    // Verify sorted order
    for i in 1..all_ids.len() {
        assert!(all_ids[i - 1] < all_ids[i], "Keyset pagination must be sorted");
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// OUTLIER ROUND-TRIP
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn roundtrip_outlier_insert_and_query() {
    let conn = setup_db();

    let row = OutlierRow {
        id: 0, // auto-increment
        pattern_id: "pat_outlier".to_string(),
        file: "src/main.ts".to_string(),
        line: 42,
        deviation_score: 3.5,
        significance: "high".to_string(),
        method: "zscore".to_string(),
        created_at: 0, // default
    };
    patterns::insert_outlier(&conn, &row).unwrap();

    let results = patterns::query_outliers_by_pattern(&conn, "pat_outlier").unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].file, "src/main.ts");
    assert_eq!(results[0].line, 42);
    assert!((results[0].deviation_score - 3.5).abs() < 1e-10);
    assert_eq!(results[0].method, "zscore");
}

#[test]
fn roundtrip_outlier_500_rows() {
    let conn = setup_db();

    for i in 0..500 {
        let row = OutlierRow {
            id: 0,
            pattern_id: format!("pat_{}", i % 50),
            file: format!("src/file_{}.ts", i),
            line: i as i64,
            deviation_score: (i as f64) * 0.1,
            significance: if i % 3 == 0 { "high" } else { "medium" }.to_string(),
            method: "grubbs".to_string(),
            created_at: 0,
        };
        patterns::insert_outlier(&conn, &row).unwrap();
    }

    // Each of the 50 patterns should have 10 outliers
    for p in 0..50 {
        let results = patterns::query_outliers_by_pattern(&conn, &format!("pat_{}", p)).unwrap();
        assert_eq!(
            results.len(), 10,
            "Pattern pat_{} should have 10 outliers, got {}",
            p, results.len()
        );

        // Verify ordered by deviation_score DESC
        for i in 1..results.len() {
            assert!(
                results[i - 1].deviation_score >= results[i].deviation_score,
                "Outliers should be ordered by deviation_score DESC"
            );
        }
    }
}

#[test]
fn roundtrip_outlier_unicode_file_paths() {
    let conn = setup_db();

    let paths = [
        "src/模块/文件.ts",
        "src/модуль/файл.ts",
        "src/🚀/launch.ts",
        "src/données/fichier.ts",
    ];

    for (i, path) in paths.iter().enumerate() {
        let row = OutlierRow {
            id: 0,
            pattern_id: "unicode_pat".to_string(),
            file: path.to_string(),
            line: i as i64 + 1,
            deviation_score: 2.0,
            significance: "medium".to_string(),
            method: "iqr".to_string(),
            created_at: 0,
        };
        patterns::insert_outlier(&conn, &row).unwrap();
    }

    let results = patterns::query_outliers_by_pattern(&conn, "unicode_pat").unwrap();
    assert_eq!(results.len(), 4);

    let stored_paths: Vec<&str> = results.iter().map(|r| r.file.as_str()).collect();
    for path in &paths {
        assert!(
            stored_paths.contains(path),
            "Unicode path '{}' not found in results",
            path
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// CONVENTION ROUND-TRIP
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn roundtrip_convention_insert_and_query() {
    let conn = setup_db();

    let row = ConventionRow {
        id: 0,
        pattern_id: "naming_camel".to_string(),
        category: "universal".to_string(),
        scope: "project".to_string(),
        dominance_ratio: 0.85,
        promotion_status: "promoted".to_string(),
        discovered_at: 1700000000,
        last_seen: 1700100000,
        expires_at: None,
    };
    patterns::insert_convention(&conn, &row).unwrap();

    let results = patterns::query_conventions_by_category(&conn, "universal").unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].pattern_id, "naming_camel");
    assert!((results[0].dominance_ratio - 0.85).abs() < 1e-10);
    assert_eq!(results[0].promotion_status, "promoted");
    assert!(results[0].expires_at.is_none());
}

#[test]
fn roundtrip_convention_with_expiry() {
    let conn = setup_db();

    let row = ConventionRow {
        id: 0,
        pattern_id: "legacy_style".to_string(),
        category: "legacy".to_string(),
        scope: "project".to_string(),
        dominance_ratio: 0.3,
        promotion_status: "discovered".to_string(),
        discovered_at: 1600000000,
        last_seen: 1600000000,
        expires_at: Some(1700000000),
    };
    patterns::insert_convention(&conn, &row).unwrap();

    let results = patterns::query_conventions_by_category(&conn, "legacy").unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].expires_at, Some(1700000000));
}

#[test]
fn roundtrip_convention_multiple_categories() {
    let conn = setup_db();

    let categories = ["universal", "emerging", "contested", "legacy", "project_specific"];
    for (i, cat) in categories.iter().enumerate() {
        for j in 0..5 {
            let row = ConventionRow {
                id: 0,
                pattern_id: format!("{}_{}", cat, j),
                category: cat.to_string(),
                scope: "project".to_string(),
                dominance_ratio: 0.9 - (i as f64 * 0.1) - (j as f64 * 0.01),
                promotion_status: "discovered".to_string(),
                discovered_at: 1000,
                last_seen: 1000,
                expires_at: None,
            };
            patterns::insert_convention(&conn, &row).unwrap();
        }
    }

    // Query each category
    for cat in &categories {
        let results = patterns::query_conventions_by_category(&conn, cat).unwrap();
        assert_eq!(results.len(), 5, "Category '{}' should have 5 conventions", cat);

        // Verify ordered by dominance_ratio DESC
        for i in 1..results.len() {
            assert!(
                results[i - 1].dominance_ratio >= results[i].dominance_ratio,
                "Conventions should be ordered by dominance_ratio DESC"
            );
        }
    }

    // Query all
    let all = patterns::query_all_conventions(&conn).unwrap();
    assert_eq!(all.len(), 25);
}

// ═══════════════════════════════════════════════════════════════════════════
// MIGRATION INTEGRITY
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn migration_v003_idempotent() {
    let conn = setup_db();
    let version = migrations::current_version(&conn).unwrap();
    assert_eq!(version, 9);

    // Running migrations again should be a no-op
    migrations::run_migrations(&conn).unwrap();
    let version2 = migrations::current_version(&conn).unwrap();
    assert_eq!(version2, 9);
}

#[test]
fn migration_v003_tables_exist() {
    let conn = setup_db();

    // Verify all P3 tables exist by querying them
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM pattern_confidence", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 0);

    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM outliers", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 0);

    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM conventions", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 0);
}

#[test]
fn migration_v003_indexes_exist() {
    let conn = setup_db();

    // Verify indexes by checking sqlite_master
    let indexes: Vec<String> = {
        let mut stmt = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%'")
            .unwrap();
        stmt.query_map([], |row| row.get(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect()
    };

    assert!(indexes.contains(&"idx_outliers_pattern".to_string()));
    assert!(indexes.contains(&"idx_outliers_file".to_string()));
    assert!(indexes.contains(&"idx_conventions_pattern".to_string()));
    assert!(indexes.contains(&"idx_conventions_category".to_string()));
    assert!(indexes.contains(&"idx_conventions_status".to_string()));
}

// ═══════════════════════════════════════════════════════════════════════════
// EDGE CASES
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn roundtrip_confidence_extreme_values() {
    let conn = setup_db();

    let row = PatternConfidenceRow {
        pattern_id: "extreme".to_string(),
        alpha: f64::MIN_POSITIVE,
        beta: 999_999.0,
        posterior_mean: 0.000001,
        credible_interval_low: 0.0,
        credible_interval_high: 0.00001,
        tier: "uncertain".to_string(),
        momentum: "falling".to_string(),
        last_updated: i64::MAX,
    };
    patterns::upsert_confidence(&conn, &row).unwrap();

    let all = patterns::query_all_confidence(&conn).unwrap();
    assert_eq!(all.len(), 1);
    assert!(all[0].alpha > 0.0);
    assert!((all[0].beta - 999_999.0).abs() < 1e-5);
}

#[test]
fn roundtrip_empty_queries() {
    let conn = setup_db();

    let conf = patterns::query_all_confidence(&conn).unwrap();
    assert!(conf.is_empty());

    let outliers = patterns::query_outliers_by_pattern(&conn, "nonexistent").unwrap();
    assert!(outliers.is_empty());

    let convs = patterns::query_conventions_by_category(&conn, "nonexistent").unwrap();
    assert!(convs.is_empty());

    let all_convs = patterns::query_all_conventions(&conn).unwrap();
    assert!(all_convs.is_empty());
}
