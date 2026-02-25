//! Batch writer tests — T1-STR-02, T1-STR-12, T1-STR-13.

use std::time::Duration;

use drift_storage::batch::commands::{BatchCommand, FileMetadataRow};
use drift_storage::batch::writer::BatchWriter;
use drift_storage::connection::pragmas::apply_pragmas;
use rusqlite::Connection;

/// Create a test connection with schema applied.
fn test_connection() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    apply_pragmas(&conn).unwrap();
    drift_storage::migrations::run_migrations(&conn).unwrap();
    conn
}

// ---- T1-STR-02: Batch writer persists 500 rows ----

#[test]
fn t1_str_02_batch_writer_500_rows() {
    let conn = test_connection();
    let writer = BatchWriter::new(conn);

    // Send 500 rows in a single batch command
    let rows: Vec<FileMetadataRow> = (0..500)
        .map(|i| FileMetadataRow {
            path: format!("file_{i}.ts"),
            language: Some("TypeScript".to_string()),
            file_size: 100 + i as i64,
            content_hash: vec![0u8; 8],
            mtime_secs: 1000,
            mtime_nanos: 0,
            last_scanned_at: 1000,
            scan_duration_us: Some(42),
        })
        .collect();

    writer.send(BatchCommand::UpsertFileMetadata(rows)).unwrap();
    let stats = writer.shutdown().unwrap();

    assert_eq!(stats.file_metadata_rows, 500, "should persist all 500 rows");
    assert!(stats.flushes >= 1, "should have at least one flush");
}

// ---- T1-STR-12: Channel backpressure ----

#[test]
fn t1_str_12_channel_backpressure() {
    let conn = test_connection();
    let writer = BatchWriter::new(conn);

    // Send 2048 commands to bounded(1024) channel
    // Producer should block (not drop), all commands eventually processed
    let total_rows = 2048;
    for i in 0..total_rows {
        let row = FileMetadataRow {
            path: format!("bp_file_{i}.ts"),
            language: Some("TypeScript".to_string()),
            file_size: 100,
            content_hash: vec![0u8; 8],
            mtime_secs: 1000,
            mtime_nanos: 0,
            last_scanned_at: 1000,
            scan_duration_us: None,
        };
        writer
            .send(BatchCommand::UpsertFileMetadata(vec![row]))
            .unwrap();
    }

    let stats = writer.shutdown().unwrap();
    assert_eq!(
        stats.file_metadata_rows, total_rows,
        "all {total_rows} rows should be processed (no drops)"
    );
}

// ---- T1-STR-13: recv_timeout flush ----

#[test]
fn t1_str_13_recv_timeout_flush() {
    let conn = test_connection();
    let writer = BatchWriter::new(conn);

    // Send 50 rows (below batch size 500)
    let rows: Vec<FileMetadataRow> = (0..50)
        .map(|i| FileMetadataRow {
            path: format!("timeout_file_{i}.ts"),
            language: Some("TypeScript".to_string()),
            file_size: 100,
            content_hash: vec![0u8; 8],
            mtime_secs: 1000,
            mtime_nanos: 0,
            last_scanned_at: 1000,
            scan_duration_us: None,
        })
        .collect();

    writer.send(BatchCommand::UpsertFileMetadata(rows)).unwrap();

    // Wait for timeout-triggered flush (100ms timeout + margin)
    std::thread::sleep(Duration::from_millis(300));

    // Shutdown and verify all rows were flushed
    let stats = writer.shutdown().unwrap();
    assert_eq!(
        stats.file_metadata_rows, 50,
        "50 rows should be flushed via timeout"
    );
}
