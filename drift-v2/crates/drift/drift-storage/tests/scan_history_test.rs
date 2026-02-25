//! Tests for scan_history lifecycle: insert, update, query, count.

use drift_storage::migrations::run_migrations;
use drift_storage::queries::scan_history::*;
use rusqlite::Connection;

fn setup_db() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    run_migrations(&conn).unwrap();
    conn
}

#[test]
fn scan_start_and_complete_roundtrip() {
    let conn = setup_db();
    let id = insert_scan_start(&conn, 1700000000, "/project").unwrap();
    assert!(id > 0);

    update_scan_complete(
        &conn, id, 1700000010, 100, 20, 5, 3, 72, 10000, "completed", None,
    ).unwrap();

    let scans = query_recent(&conn, 10).unwrap();
    assert_eq!(scans.len(), 1);
    assert_eq!(scans[0].id, id);
    assert_eq!(scans[0].root_path, "/project");
    assert_eq!(scans[0].status, "completed");
    assert_eq!(scans[0].total_files, Some(100));
    assert_eq!(scans[0].added_files, Some(20));
    assert_eq!(scans[0].modified_files, Some(5));
    assert_eq!(scans[0].removed_files, Some(3));
    assert_eq!(scans[0].unchanged_files, Some(72));
    assert_eq!(scans[0].duration_ms, Some(10000));
    assert!(scans[0].error.is_none());
}

#[test]
fn scan_with_error() {
    let conn = setup_db();
    let id = insert_scan_start(&conn, 1700000000, "/project").unwrap();
    update_scan_complete(
        &conn, id, 1700000005, 0, 0, 0, 0, 0, 5000, "failed",
        Some("disk full"),
    ).unwrap();

    let scans = query_recent(&conn, 10).unwrap();
    assert_eq!(scans[0].status, "failed");
    assert_eq!(scans[0].error, Some("disk full".to_string()));
}

#[test]
fn multiple_scans_ordered_by_started_at_desc() {
    let conn = setup_db();
    let id1 = insert_scan_start(&conn, 1700000000, "/project").unwrap();
    update_scan_complete(&conn, id1, 1700000010, 50, 10, 5, 2, 33, 5000, "completed", None).unwrap();

    let id2 = insert_scan_start(&conn, 1700000100, "/project").unwrap();
    update_scan_complete(&conn, id2, 1700000110, 60, 15, 3, 1, 41, 6000, "completed", None).unwrap();

    let scans = query_recent(&conn, 10).unwrap();
    assert_eq!(scans.len(), 2);
    // Most recent first
    assert_eq!(scans[0].started_at, 1700000100);
    assert_eq!(scans[1].started_at, 1700000000);
}

#[test]
fn query_recent_limit() {
    let conn = setup_db();
    for i in 0..5 {
        let id = insert_scan_start(&conn, 1700000000 + i * 100, "/project").unwrap();
        update_scan_complete(&conn, id, 1700000010 + i * 100, 10, 1, 0, 0, 9, 1000, "completed", None).unwrap();
    }

    let scans = query_recent(&conn, 2).unwrap();
    assert_eq!(scans.len(), 2);
}

#[test]
fn count_scans() {
    let conn = setup_db();
    assert_eq!(count(&conn).unwrap(), 0);

    insert_scan_start(&conn, 1700000000, "/a").unwrap();
    insert_scan_start(&conn, 1700000100, "/b").unwrap();
    assert_eq!(count(&conn).unwrap(), 2);
}
