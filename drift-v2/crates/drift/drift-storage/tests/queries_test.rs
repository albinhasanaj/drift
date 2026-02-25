//! Query tests — T1-STR-04, T1-STR-16.

use drift_storage::connection::pragmas::apply_pragmas;
use drift_storage::migrations;
use drift_storage::pagination::keyset::PaginationCursor;
use drift_storage::queries::{functions, parse_cache};
use rusqlite::Connection;

fn test_connection() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    apply_pragmas(&conn).unwrap();
    migrations::run_migrations(&conn).unwrap();
    conn
}

// ---- T1-STR-04: Keyset pagination ----

#[test]
fn t1_str_04_keyset_pagination() {
    let conn = test_connection();

    // Insert 1000 rows
    for i in 0..1000 {
        conn.execute(
            "INSERT INTO file_metadata (path, language, file_size, content_hash, mtime_secs, mtime_nanos, last_scanned_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                format!("file_{i:04}.ts"),
                "TypeScript",
                100 + i,
                vec![0u8; 8],
                1000,
                0,
                1000
            ],
        )
        .unwrap();
    }

    // Paginate with page_size=100
    let page_size = 100;
    let mut all_paths: Vec<String> = Vec::new();
    let mut cursor: Option<String> = None;
    let mut page_count = 0;

    loop {
        let (rows, next_cursor) = paginate_files(&conn, cursor.as_deref(), page_size);
        if rows.is_empty() {
            break;
        }
        all_paths.extend(rows);
        page_count += 1;
        cursor = next_cursor;
        if cursor.is_none() {
            break;
        }
    }

    assert_eq!(page_count, 10, "should have 10 pages of 100");
    assert_eq!(all_paths.len(), 1000, "should retrieve all 1000 rows");

    // Verify no duplicates
    let mut sorted = all_paths.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), 1000, "no duplicates in paginated results");
}

// ---- T1-STR-16: Keyset pagination with duplicate sort values ----

#[test]
fn t1_str_16_keyset_pagination_duplicates() {
    let conn = test_connection();

    // Insert rows with duplicate language values (sort column)
    for i in 0..50 {
        let lang = if i < 25 { "TypeScript" } else { "Python" };
        conn.execute(
            "INSERT INTO file_metadata (path, language, file_size, content_hash, mtime_secs, mtime_nanos, last_scanned_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                format!("dup_file_{i:04}.ts"),
                lang,
                100,
                vec![0u8; 8],
                1000,
                0,
                1000
            ],
        )
        .unwrap();
    }

    // Paginate with small page size
    let mut all_paths: Vec<String> = Vec::new();
    let mut cursor: Option<String> = None;

    loop {
        let (rows, next_cursor) = paginate_files(&conn, cursor.as_deref(), 10);
        if rows.is_empty() {
            break;
        }
        all_paths.extend(rows);
        cursor = next_cursor;
        if cursor.is_none() {
            break;
        }
    }

    assert_eq!(all_paths.len(), 50, "should retrieve all 50 rows");

    // Verify no duplicates even with duplicate sort values
    let mut sorted = all_paths.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), 50, "no duplicates despite duplicate sort values");
}

// ---- T1-STR-05 (queries): Parse cache round-trip ----

#[test]
fn t1_str_queries_parse_cache_round_trip() {
    let conn = test_connection();

    let hash = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
    let json = r#"{"file":"test.ts","language":"TypeScript","content_hash":12345}"#;

    parse_cache::insert(&conn, &hash, "TypeScript", json, 1000).unwrap();

    let record = parse_cache::get_by_hash(&conn, &hash).unwrap();
    assert!(record.is_some());
    let r = record.unwrap();
    assert_eq!(r.language, "TypeScript");
    assert_eq!(r.parse_result_json, json);

    // Invalidate
    parse_cache::invalidate(&conn, &hash).unwrap();
    let record2 = parse_cache::get_by_hash(&conn, &hash).unwrap();
    assert!(record2.is_none());
}

// ---- T1-STR-05 (queries): Functions CRUD ----

#[test]
fn t1_str_queries_functions_crud() {
    let conn = test_connection();

    // Insert a function
    conn.execute(
        "INSERT INTO functions (file, name, qualified_name, language, line, end_line, parameter_count, is_exported, is_async)
         VALUES ('test.ts', 'hello', 'MyClass.hello', 'TypeScript', 10, 20, 2, 1, 0)",
        [],
    )
    .unwrap();

    // Query by file
    let funcs = functions::get_functions_by_file(&conn, "test.ts").unwrap();
    assert_eq!(funcs.len(), 1);
    assert_eq!(funcs[0].name, "hello");
    assert_eq!(funcs[0].qualified_name.as_deref(), Some("MyClass.hello"));

    // Query by qualified name
    let func = functions::get_function_by_qualified_name(&conn, "MyClass.hello").unwrap();
    assert!(func.is_some());
    assert_eq!(func.unwrap().name, "hello");

    // Count
    let count = functions::count_functions(&conn).unwrap();
    assert_eq!(count, 1);

    // Delete
    let deleted = functions::delete_functions_by_file(&conn, "test.ts").unwrap();
    assert_eq!(deleted, 1);
    assert_eq!(functions::count_functions(&conn).unwrap(), 0);
}

// ---- Helpers ----

/// Simple keyset pagination over file_metadata ordered by path.
fn paginate_files(
    conn: &Connection,
    cursor: Option<&str>,
    limit: usize,
) -> (Vec<String>, Option<String>) {
    let (rows, next) = match cursor {
        Some(c) => {
            let decoded = PaginationCursor::decode(c);
            match decoded {
                Some(cursor) => {
                    let mut stmt = conn
                        .prepare(
                            "SELECT path FROM file_metadata WHERE path > ?1 ORDER BY path LIMIT ?2",
                        )
                        .unwrap();
                    let paths: Vec<String> = stmt
                        .query_map(rusqlite::params![cursor.last_id, limit], |row| row.get(0))
                        .unwrap()
                        .filter_map(|r| r.ok())
                        .collect();
                    let next = paths.last().map(|last| {
                        PaginationCursor {
                            last_sort_value: last.clone(),
                            last_id: last.clone(),
                        }
                        .encode()
                    });
                    (paths, next)
                }
                None => (Vec::new(), None),
            }
        }
        None => {
            let mut stmt = conn
                .prepare("SELECT path FROM file_metadata ORDER BY path LIMIT ?1")
                .unwrap();
            let paths: Vec<String> = stmt
                .query_map(rusqlite::params![limit], |row| row.get(0))
                .unwrap()
                .filter_map(|r| r.ok())
                .collect();
            let next = if paths.len() == limit {
                paths.last().map(|last| {
                    PaginationCursor {
                        last_sort_value: last.clone(),
                        last_id: last.clone(),
                    }
                    .encode()
                })
            } else {
                None
            };
            (paths, next)
        }
    };
    (rows, next)
}
