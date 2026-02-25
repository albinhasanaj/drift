//! V008 migration: Enforcement fixes.
//!
//! Adds scan_root column to audit_snapshots for scope-aware degradation comparison.

pub const MIGRATION_SQL: &str = r#"
ALTER TABLE audit_snapshots ADD COLUMN scan_root TEXT DEFAULT '';
"#;
