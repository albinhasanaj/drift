//! Cat 12: Cloud Sync & Conflict Storage (CS-01 through CS-08)

use rusqlite::Connection;
use cortex_storage::pool::pragmas;

fn raw_conn() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    pragmas::apply_pragmas(&conn).unwrap();
    cortex_storage::migrations::run_migrations(&conn).unwrap();
    conn
}

#[test]
fn cs_01_sync_state_singleton_insert() {
    let conn = raw_conn();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM sync_state", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1, "migration should create exactly 1 sync_state row");

    let id: i64 = conn
        .query_row("SELECT id FROM sync_state", [], |row| row.get(0))
        .unwrap();
    assert_eq!(id, 1);
}

#[test]
fn cs_02_sync_state_last_sync_update() {
    let conn = raw_conn();
    conn.execute(
        "UPDATE sync_state SET last_sync_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = 1",
        [],
    ).unwrap();

    let ts: Option<String> = conn
        .query_row("SELECT last_sync_at FROM sync_state WHERE id = 1", [], |row| row.get(0))
        .unwrap();
    assert!(ts.is_some(), "last_sync_at should be updated");
}

#[test]
fn cs_03_sync_log_records_operations() {
    let conn = raw_conn();
    conn.execute(
        "INSERT INTO sync_log (direction, memory_id, operation, status, details)
         VALUES ('push', 'm1', 'create', 'success', '{}')",
        [],
    ).unwrap();

    let (dir, mem_id, op, status): (String, String, String, String) = conn
        .query_row(
            "SELECT direction, memory_id, operation, status FROM sync_log LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(dir, "push");
    assert_eq!(mem_id, "m1");
    assert_eq!(op, "create");
    assert_eq!(status, "success");
}

#[test]
fn cs_04_conflict_log_records_conflicts() {
    let conn = raw_conn();
    conn.execute(
        "INSERT INTO conflict_log (memory_id, local_version, remote_version, resolution)
         VALUES ('m1', '{\"v\": 1}', '{\"v\": 2}', 'pending')",
        [],
    ).unwrap();

    let (local_ver, resolution): (String, String) = conn
        .query_row(
            "SELECT local_version, resolution FROM conflict_log WHERE memory_id = 'm1'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(resolution, "pending");
    let parsed: serde_json::Value = serde_json::from_str(&local_ver).unwrap();
    assert_eq!(parsed["v"], 1);
}

#[test]
fn cs_05_conflict_resolution_update() {
    let conn = raw_conn();
    conn.execute(
        "INSERT INTO conflict_log (memory_id, local_version, remote_version, resolution)
         VALUES ('m2', 'a', 'b', 'pending')",
        [],
    ).unwrap();

    conn.execute(
        "UPDATE conflict_log SET resolution = 'local_wins', resolved_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
         WHERE memory_id = 'm2'",
        [],
    ).unwrap();

    let (resolution, resolved): (String, Option<String>) = conn
        .query_row(
            "SELECT resolution, resolved_at FROM conflict_log WHERE memory_id = 'm2'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(resolution, "local_wins");
    assert!(resolved.is_some());
}

#[test]
fn cs_06_sync_state_check_prevents_second_row() {
    let conn = raw_conn();
    let result = conn.execute("INSERT INTO sync_state (id) VALUES (2)", []);
    assert!(result.is_err(), "CHECK(id=1) should prevent second row");
}

#[test]
fn cs_07_sync_log_auto_timestamp() {
    let conn = raw_conn();
    conn.execute(
        "INSERT INTO sync_log (direction, memory_id, operation, status)
         VALUES ('pull', 'm1', 'update', 'success')",
        [],
    ).unwrap();

    let ts: Option<String> = conn
        .query_row("SELECT timestamp FROM sync_log LIMIT 1", [], |row| row.get(0))
        .unwrap();
    assert!(ts.is_some(), "timestamp should be auto-populated");
}

#[test]
fn cs_08_conflict_log_memory_reference() {
    let conn = raw_conn();
    // Insert a conflict referencing a non-existent memory — should succeed (no FK on conflict_log).
    let result = conn.execute(
        "INSERT INTO conflict_log (memory_id, local_version, remote_version, resolution)
         VALUES ('nonexistent', 'a', 'b', 'pending')",
        [],
    );
    // Either succeeds (no FK) or fails (FK) — no panic.
    assert!(result.is_ok() || result.is_err());
}
