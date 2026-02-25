# Cortex Database Production Test Suite

> Comprehensive test specification for cortex-storage and all upstream/downstream dependencies.
> Covers the full data path: Rust engine → NAPI bindings → TS bridge → MCP tools → CLI.
> Reference: `PRODUCTION-TEST-SUITE.md` quality standards (not happy-path-only).

---

## Executive Summary

**Scope:** 31 tables across 15 migrations, 19 query modules, 68 NAPI bindings, 20 bridge functions, 40 MCP tools, CortexClient (54 methods).

**Existing Coverage:** 25 test files, ~200 tests. Coverage is concentrated on memory CRUD + stress. Critical gaps exist in concurrency, migration failure recovery, cross-DB bridge, FTS5 edge cases, temporal event atomicity, multi-agent namespace isolation, and NAPI→storage integration.

**This document specifies:** 186 tests across 18 categories.

---

## Table of Contents

1. [Schema & Migration Integrity](#cat-1-schema--migration-integrity)
2. [Connection Pool & WAL Concurrency](#cat-2-connection-pool--wal-concurrency)
3. [Memory CRUD Atomicity](#cat-3-memory-crud-atomicity)
4. [Temporal Event Consistency](#cat-4-temporal-event-consistency)
5. [Query Module Correctness](#cat-5-query-module-correctness)
6. [FTS5 Search Precision](#cat-6-fts5-search-precision)
7. [Vector Search & Embedding Storage](#cat-7-vector-search--embedding-storage)
8. [Causal Graph Storage](#cat-8-causal-graph-storage)
9. [Link Operations & Cascade](#cat-9-link-operations--cascade)
10. [Session & Audit Subsystem](#cat-10-session--audit-subsystem)
11. [Multi-Agent Namespace Isolation](#cat-11-multi-agent-namespace-isolation)
12. [Cloud Sync & Conflict Storage](#cat-12-cloud-sync--conflict-storage)
13. [Versioning & Reclassification](#cat-13-versioning--reclassification)
14. [Observability & Metrics Storage](#cat-14-observability--metrics-storage)
15. [Compaction, Recovery & Vacuum](#cat-15-compaction-recovery--vacuum)
16. [NAPI→Storage Integration](#cat-16-napistorage-integration)
17. [Bridge Cross-DB Operations](#cat-17-bridge-cross-db-operations)
18. [Edge Cases & Adversarial Inputs](#cat-18-edge-cases--adversarial-inputs)

---

## Test Infrastructure Requirements

### Fixture: `test_engine()`
```rust
/// In-memory StorageEngine for unit tests.
/// use_read_pool = false (all reads go through writer).
fn test_engine() -> StorageEngine {
    StorageEngine::open_in_memory().unwrap()
}
```

### Fixture: `test_engine_file()`
```rust
/// File-backed StorageEngine in a temp directory.
/// use_read_pool = true (reads go through read pool — WAL visibility).
fn test_engine_file() -> (StorageEngine, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test_cortex.db");
    let engine = StorageEngine::open(&path).unwrap();
    (engine, dir)
}
```

### Fixture: `test_memory(id: &str)`
```rust
/// Minimal valid BaseMemory with defaults for all required fields.
fn test_memory(id: &str) -> BaseMemory {
    BaseMemory {
        id: id.to_string(),
        memory_type: MemoryType::Core,
        content: TypedContent::Text("test content".into()),
        summary: "test summary".into(),
        transaction_time: Utc::now(),
        valid_time: Utc::now(),
        valid_until: None,
        confidence: Confidence::new(0.8),
        importance: Importance::Normal,
        last_accessed: Utc::now(),
        access_count: 0,
        linked_patterns: vec![],
        linked_constraints: vec![],
        linked_files: vec![],
        linked_functions: vec![],
        tags: vec!["test".into()],
        archived: false,
        superseded_by: None,
        supersedes: None,
        content_hash: "hash_test".into(),
        namespace: NamespaceId::default(),
        source_agent: AgentId::default(),
    }
}
```

### Fixture: `raw_conn()`
```rust
/// Raw rusqlite::Connection with all migrations applied.
/// For testing query modules directly without engine abstraction.
fn raw_conn() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    cortex_storage::pool::pragmas::apply_pragmas(&conn).unwrap();
    cortex_storage::migrations::run_migrations(&conn).unwrap();
    conn
}
```

---

## Existing Coverage Inventory

| Test File | Tests | Focus |
|-----------|-------|-------|
| `storage_e2e_test.rs` | 19 | Memory CRUD, vector search, events, migrations |
| `stress_test.rs` | 13 | Bulk ops, 1000+ memories, FTS5, causal edges |
| `subsystem_ops_test.rs` | 29 | Sessions, audit, events, snapshots, vacuum, temporal |
| `integration/memory_crud_test.rs` | ~10 | Basic CRUD through IMemoryStorage trait |
| `integration/causal_test.rs` | ~8 | Causal edge CRUD, cycle detection |
| `integration/migration_test.rs` | ~5 | Fresh migration, version tracking |
| `integration/concurrent_access_test.rs` | ~4 | Basic concurrency |
| `integration/versioning_test.rs` | ~6 | Memory version tracking |
| `integration/audit_test.rs` | ~4 | Audit log recording |
| `integration/compaction_test.rs` | ~3 | Compaction operations |
| `integration/recovery_test.rs` | ~3 | Recovery from corrupted state |
| Other (8 files) | ~96 | Property tests, pool sharing, edge cases, multiagent |
| **TOTAL** | **~200** | |

### Critical Gap Matrix

| Area | Gap | Priority |
|------|-----|----------|
| Migration rollback | No test for partial migration failure + rollback | P0 |
| FTS5 trigger sync | No test that UPDATE triggers re-sync FTS5 content | P0 |
| in-memory vs file-backed read routing | No test comparing `with_reader` behavior in both modes | P0 |
| Temporal event atomicity | No test that event emission failure doesn't corrupt CRUD | P0 |
| Namespace isolation | No test that namespace_id filter prevents cross-namespace reads | P1 |
| NAPI→storage roundtrip | No test from JSON→NAPI→storage→NAPI→JSON | P1 |
| Bridge cross-DB ATTACH | No test for ATTACH cortex.db from bridge.db | P1 |
| Writer mutex contention | No test for tokio::sync::Mutex under concurrent write load | P1 |
| update_memory re-embed | No test that content_hash change triggers embedding regen | P1 |
| FK cascade on delete | No test that deleting memory cascades to all 4 link tables | P1 |
| bulk_insert rollback | No test that duplicate ID in batch rolls back ALL inserts | P1 |
| v013 placeholder | No test that placeholder migration is truly a no-op | P2 |
| Embedding dedup | No test that same content_hash reuses embedding row | P2 |
| Reclassification tables | Zero coverage of reclassification_history/signals | P2 |
| Contradiction storage | Zero coverage of memory_contradictions table | P2 |
| Delta queue persistence | Zero coverage of delta_queue table for CRDT sync | P2 |

---

## Cat 1: Schema & Migration Integrity

**Files under test:** `migrations/mod.rs`, `migrations/v001..v015`
**Existing coverage:** `migration_test.rs` (~5 tests)

### Tests (12)

**SM-01: Fresh DB reaches LATEST_VERSION**
- Setup: `raw_conn()`
- Action: `run_migrations(conn)`
- Assert: `current_version(conn) == 15`
- Failure: Migration array out of sync with LATEST_VERSION constant

**SM-02: Idempotent migration re-run**
- Setup: `raw_conn()` (migrations already ran)
- Action: `run_migrations(conn)` again
- Assert: Returns `Ok(0)` (zero applied)
- Failure: schema_version INSERT conflicts

**SM-03: All 31+ tables exist after full migration**
- Setup: `raw_conn()`
- Action: `SELECT name FROM sqlite_master WHERE type='table' ORDER BY name`
- Assert: Exact set includes: `agent_registry`, `agent_trust`, `causal_edges`, `causal_evidence`, `conflict_log`, `consolidation_metrics`, `degradation_log`, `delta_queue`, `drift_snapshots`, `embedding_model_info`, `materialized_views`, `memories`, `memory_audit_log`, `memory_constraints`, `memory_contradictions`, `memory_embedding_link`, `memory_embeddings`, `memory_events`, `memory_events_archive`, `memory_files`, `memory_functions`, `memory_namespaces`, `memory_patterns`, `memory_projections`, `memory_relationships`, `memory_snapshots`, `memory_validation_history`, `memory_versions`, `metric_snapshots`, `namespace_permissions`, `provenance_log`, `query_performance_log`, `reclassification_history`, `reclassification_signals`, `schema_version`, `session_analytics`, `session_contexts`, `sync_log`, `sync_state`
- Failure: Missed table in migration, typo in CREATE TABLE

**SM-04: v013 placeholder is truly a no-op**
- Setup: DB at v012 (manually set schema_version)
- Action: Run v013_placeholder::migrate()
- Assert: No new tables, no schema changes
- Failure: Placeholder accidentally modifies schema

**SM-05: v015 ALTER TABLE adds columns only if missing**
- Setup: DB at v014
- Action: Run v015 migration twice (simulate re-apply)
- Assert: No error on second run; `namespace_id` and `source_agent` columns present exactly once
- Failure: ALTER TABLE fails if column already exists

**SM-06: Migration failure rolls back cleanly**
- Setup: `raw_conn()`, inject a broken migration at version N+1
- Action: `run_migrations(conn)`
- Assert: Returns `MigrationFailed` error, version stays at N, ROLLBACK executed
- Failure: Partial migration leaves DB in inconsistent state

**SM-07: Foreign keys cascade on memory delete**
- Setup: Insert memory "mem-1" with links in all 4 link tables
- Action: `DELETE FROM memories WHERE id = 'mem-1'`
- Assert: All rows in memory_patterns, memory_constraints, memory_files, memory_functions with memory_id="mem-1" are cascade-deleted
- Failure: PRAGMA foreign_keys not ON, or ON DELETE CASCADE missing

**SM-08: All indexes exist post-migration**
- Setup: `raw_conn()`
- Action: `SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%'`
- Assert: At least 30 indexes exist
- Failure: Missing CREATE INDEX in migration

**SM-09: sync_state singleton constraint**
- Setup: `raw_conn()`
- Action: `INSERT INTO sync_state (id) VALUES (2)`
- Assert: Fails with CHECK constraint violation (`id = 1` enforced)
- Failure: Missing CHECK constraint

**SM-10: WAL mode active after pragmas**
- Setup: `test_engine_file()`
- Action: `verify_wal_mode(conn)`
- Assert: Returns `true`
- Failure: Pragma not applied to writer connection

**SM-11: auto_vacuum set to INCREMENTAL**
- Setup: `test_engine_file()`
- Action: `PRAGMA auto_vacuum` on writer
- Assert: Returns 2 (INCREMENTAL)
- Failure: apply_pragmas skipped when existing DB

**SM-12: Read connections have query_only ON**
- Setup: `test_engine_file()`
- Action: Attempt `INSERT INTO memories ...` through a read connection
- Assert: Fails with "attempt to write a readonly database"
- Failure: apply_read_pragmas not setting query_only

---

## Cat 2: Connection Pool & WAL Concurrency

**Files under test:** `pool/mod.rs`, `pool/write_connection.rs`, `pool/read_pool.rs`
**Existing coverage:** `concurrent_access_test.rs` (~4), `pool_sharing_test.rs`

### Tests (10)

**CP-01: Writer serializes concurrent writes**
- Setup: `test_engine_file()`
- Action: Spawn 10 tokio tasks each calling `storage.create(memory)` concurrently
- Assert: All 10 succeed, no SQLITE_BUSY, all 10 retrievable
- Failure: tokio::sync::Mutex contention causes deadlock or timeout

**CP-02: Read pool round-robin distributes connections**
- Setup: `test_engine_file()` with pool size 4
- Action: Perform 100 sequential reads
- Assert: All succeed; internal counter cycles correctly
- Failure: Single connection overloaded

**CP-03: Readers see writer's committed changes (WAL visibility)**
- Setup: `test_engine_file()`
- Action: Writer inserts M1 → Reader queries M1
- Assert: Reader sees M1 immediately
- Failure: Reader using stale WAL snapshot

**CP-04: In-memory mode routes reads through writer**
- Setup: `test_engine()` (in-memory, `use_read_pool = false`)
- Action: Insert via writer, read via `with_reader`
- Assert: Read succeeds (goes through writer, NOT read pool)
- Failure: `use_read_pool = true` for in-memory → reads return empty

**CP-05: In-memory read pool connections are isolated**
- Setup: `ConnectionPool::open_in_memory(4)`
- Action: Write via writer, read via `readers.with_conn`
- Assert: Read returns empty (separate in-memory databases)
- Failure: Test wrongly assumes shared state

**CP-06: Pool size clamped to MAX_POOL_SIZE**
- Setup: `ReadPool::open(path, 100)` (exceeds MAX_POOL_SIZE=8)
- Action: Check `pool.size()`
- Assert: Returns 8, not 100
- Failure: Unbounded connection creation

**CP-07: Read pool lock poisoning handled**
- Setup: `test_engine_file()`
- Action: Poison one read connection's Mutex (via panic in closure)
- Assert: Returns StorageError for that index, other indexes still work
- Failure: Panic propagation crashes entire pool

**CP-08: Writer blocking_lock works outside tokio context**
- Setup: `WriteConnection::open_in_memory()`
- Action: Call `with_conn_sync()` from a non-async context
- Assert: Succeeds without panic
- Failure: `blocking_lock()` panics outside tokio context

**CP-09: Concurrent readers don't block writer (WAL)**
- Setup: `test_engine_file()`
- Action: Start 4 long-running reads (100ms hold), concurrently write
- Assert: Write completes within 200ms
- Failure: Readers holding lock block writer

**CP-10: Shared Arc<WriteConnection> across engines**
- Setup: Full `CortexRuntime::new()` init
- Action: Verify `storage.pool().writer` is same Arc as `temporal.writer`
- Assert: `Arc::ptr_eq()` returns true
- Failure: Duplicate connections created in runtime init

---

## Cat 3: Memory CRUD Atomicity

**Files under test:** `queries/memory_crud.rs`, `engine.rs` (IMemoryStorage impl)
**Existing coverage:** `memory_crud_test.rs` (~10), `storage_e2e_test.rs` (19)

### Tests (14)

**MC-01: Create with all link types persists atomically**
- Setup: Memory with 2 patterns, 2 constraints, 2 files, 2 functions
- Action: `storage.create(&memory)`
- Assert: All 8 links retrievable via `get(&id)`, plus `memory_events` has "created" event
- Failure: Links inserted but event fails → partial state

**MC-02: Create failure rolls back links and event**
- Setup: Memory with invalid content (force serialization error)
- Action: `storage.create(&memory)`
- Assert: Error returned. No row in memories, no rows in link tables, no event
- Failure: `unchecked_transaction` doesn't roll back

**MC-03: Update detects content_hash change and emits events**
- Setup: Create memory with content_hash "A", update with content_hash "B"
- Action: `storage.update(&updated)`
- Assert: `memory_events` contains "content_updated" with old/new hashes
- Failure: `emit_update_events` not comparing content_hash

**MC-04: Update emits events for each changed field independently**
- Setup: Create, then update with changed tags, confidence, importance, archived
- Action: `storage.update(&updated)`
- Assert: 4 separate events: tags_modified, confidence_changed, importance_changed, archived
- Failure: Short-circuit on first event emission failure

**MC-05: Update of non-existent memory returns MemoryNotFound**
- Setup: Empty DB
- Action: `storage.update(&memory_with_unknown_id)`
- Assert: Returns `Err(CortexError::MemoryNotFound { id })`
- Failure: Silently returns Ok(()) when `rows == 0`

**MC-06: Delete emits "archived" event BEFORE row deletion**
- Setup: Create memory
- Action: `storage.delete(&id)`
- Assert: `memory_events` has "archived" event with `reason: "hard_delete"`; memory row gone
- Failure: Event emitted after DELETE → lost event or FK violation

**MC-07: Delete cascades to all 4 link tables**
- Setup: Memory with links in all 4 tables
- Action: `storage.delete(&id)`
- Assert: Zero rows in memory_patterns/constraints/files/functions for that memory_id
- Failure: `delete_links` not called, FK CASCADE not working

**MC-08: Bulk insert — all-or-nothing on duplicate ID**
- Setup: 5 valid memories + 1 with duplicate ID of first
- Action: `bulk_insert(conn, &batch)`
- Assert: Error returned, ZERO of the 5 valid memories persisted (full rollback)
- Failure: Partial commit before duplicate detected

**MC-09: Bulk insert — empty batch returns Ok(0)**
- Setup: Empty slice
- Action: `bulk_insert(conn, &[])`
- Assert: Returns `Ok(0)`, no transaction opened
- Failure: BEGIN IMMEDIATE on empty batch → unnecessary lock

**MC-10: Bulk get — missing IDs silently skipped**
- Setup: Create memories "a" and "c"
- Action: `bulk_get(conn, &["a", "b", "c"])`
- Assert: Returns 2 memories (a, c), no error for missing "b"
- Failure: Returns error on first missing ID

**MC-11: Update re-creates links (delete-then-insert)**
- Setup: Memory with pattern P1, update to have pattern P2 only
- Action: `storage.update(&updated)`
- Assert: Only P2 in memory_patterns, P1 gone
- Failure: Old links not deleted before new links inserted

**MC-12: Namespace and source_agent roundtrip**
- Setup: Memory with namespace "agent://mybot/" and source_agent "bot-1"
- Action: Create, then get
- Assert: Retrieved memory has matching namespace.to_uri() and source_agent.0
- Failure: Default values used instead of provided values

**MC-13: Confidence clamping at boundaries**
- Setup: Memories with confidence 0.0, 1.0
- Action: Create all, then get all
- Assert: Values stored and retrieved exactly
- Failure: Storage layer double-clamps or loses precision

**MC-14: access_count u64 survives i64 storage roundtrip**
- Setup: Memory with access_count = u32::MAX as u64 + 1
- Action: Create, then get
- Assert: access_count matches
- Failure: Overflow on `as u64` cast from `get::<_, i64>(10)`

---

## Cat 4: Temporal Event Consistency

**Files under test:** `temporal_events.rs`, `queries/event_ops.rs`
**Existing coverage:** `storage_e2e_test.rs` (3 tests)

### Tests (10)

**TE-01: Event uses SQLite clock, not Rust clock**
- Setup: `raw_conn()`
- Action: `emit_event(conn, "m1", "test", &json!({}), "system", "test")`
- Assert: `recorded_at` matches SQLite `strftime` format (millisecond precision, Z suffix)
- Failure: Rust Utc::now() used → clock skew between DB and events

**TE-02: Event emission graceful before v014 migration**
- Setup: DB at v001 only (no memory_events table)
- Action: `emit_event(conn, "m1", "test", &json!({}), "system", "test")`
- Assert: Returns `Ok(0)` (no event stored, no error)
- Failure: Panics or returns error on missing table

**TE-03: Event emission failure doesn't break CRUD transaction**
- Setup: Drop memory_events table mid-test, then do insert_memory
- Action: `insert_memory(conn, &memory)`
- Assert: Memory is inserted successfully; event emission logged as warning only
- Failure: Event error propagates and rolls back memory insert

**TE-04: All 5 update event types fire correctly**
- Setup: Create memory, then update ALL fields (content, tags, confidence, importance, archived)
- Action: Query `memory_events` for that memory_id
- Assert: 5 events: content_updated, tags_modified, confidence_changed, importance_changed, archived
- Failure: Short-circuit on first event or missing field comparison

**TE-05: Confidence change detection uses epsilon**
- Setup: Memory with confidence 0.8, update to 0.8 + 1e-16
- Action: `update_memory(conn, &memory)`
- Assert: No "confidence_changed" event emitted (within f64::EPSILON)
- Failure: Fires event for sub-epsilon change

**TE-06: Tags diff correctly identifies added and removed**
- Setup: Memory with tags ["a", "b"], update to ["b", "c"]
- Action: Check "tags_modified" event delta
- Assert: `added: ["c"], removed: ["a"]`
- Failure: Set difference logic inverted

**TE-07: Schema_version field defaults to 1**
- Setup: Emit any event
- Action: Query `schema_version` column from memory_events
- Assert: Value is 1
- Failure: Missing DEFAULT constraint

**TE-08: caused_by field supports NULL**
- Setup: Emit event without caused_by (None)
- Action: Query event
- Assert: `caused_by IS NULL`
- Failure: NOT NULL constraint on caused_by

**TE-09: Event ordering is stable under rapid writes**
- Setup: Create 10 memories rapidly in sequence
- Action: Query `memory_events ORDER BY event_id`
- Assert: Events are in creation order
- Failure: Autoincrement not monotonic

**TE-10: Archive event emitted before hard delete**
- Setup: Create memory, then delete
- Action: Query memory_events for "archived" event
- Assert: Event exists with `reason: "hard_delete"` even though memory row is gone
- Failure: Event emitted after DELETE → foreign key issue or lost event

---

## Cat 5: Query Module Correctness

**Files under test:** `queries/memory_query.rs`, `queries/aggregation.rs`
**Existing coverage:** `stress_test.rs` (partial)

### Tests (12)

**QM-01: query_by_type excludes archived memories**
- Setup: 3 Core memories (1 archived, 2 active)
- Action: `query_by_type(conn, MemoryType::Core, None)`
- Assert: Returns 2 memories
- Failure: Missing `AND archived = 0`

**QM-02: query_by_type with namespace filter**
- Setup: 3 Core in "agent://ns1/", 2 Core in "agent://ns2/"
- Action: `query_by_type(conn, MemoryType::Core, Some(&ns1))`
- Assert: Returns 3 from ns1 only
- Failure: Namespace filter not applied

**QM-03: query_by_importance — Low returns all 4 tiers**
- Setup: 1 memory each: Low, Normal, High, Critical
- Action: `query_by_importance(conn, Importance::Low, None)`
- Assert: Returns 4 memories
- Failure: Importance ordering logic wrong

**QM-04: query_by_confidence_range — boundary inclusive**
- Setup: Memories with confidence 0.0, 0.5, 0.8, 1.0
- Action: `query_by_confidence_range(conn, 0.5, 0.8, None)`
- Assert: Returns 0.5 and 0.8 (inclusive both ends)
- Failure: `>=` / `<=` replaced with `>` / `<`

**QM-05: query_by_date_range uses transaction_time**
- Setup: Memory with transaction_time=Jan1, valid_time=Dec1
- Action: `query_by_date_range(conn, Dec1..Dec31, None)`
- Assert: Empty result (transaction_time is Jan1, outside range)
- Failure: Querying wrong time column

**QM-06: query_by_tags — OR semantics (any match)**
- Setup: Memory A: ["rust", "web"], Memory B: ["python"]
- Action: `query_by_tags(conn, &["rust", "python"], None)`
- Assert: Returns both A and B
- Failure: Using AND semantics

**QM-07: query_by_tags — deduplication**
- Setup: Memory with tags ["rust", "web"]
- Action: `query_by_tags(conn, &["rust", "web"], None)`
- Assert: Returns 1 memory, not 2 duplicates
- Failure: Missing dedup check

**QM-08: count_by_type excludes archived**
- Setup: 5 Core (2 archived), 3 Semantic
- Action: `count_by_type(conn)`
- Assert: Core=3, Semantic=3
- Failure: Missing `WHERE archived = 0`

**QM-09: average_confidence handles empty DB**
- Setup: Empty DB
- Action: `average_confidence(conn)`
- Assert: Returns 0.0 (COALESCE)
- Failure: QueryReturnedNoRows or NULL

**QM-10: stale_count uses julianday correctly**
- Setup: Memory last_accessed 60 days ago, another today
- Action: `stale_count(conn, 30)`
- Assert: Returns 1
- Failure: julianday comparison inverted

**QM-11: storage_stats counts all entity types**
- Setup: 3 memories, 2 embeddings, 5 relationships, 10 audit entries
- Action: `storage_stats(conn)`
- Assert: All counts match
- Failure: Missing table in query

**QM-12: All query functions load links**
- Setup: Memory with all 4 link types
- Action: `query_by_type` (or any query returning BaseMemory)
- Assert: Returned memory has non-empty linked_patterns, linked_constraints, linked_files, linked_functions
- Failure: `load_links` not called after row_to_base_memory

---

## Cat 6: FTS5 Search Precision

**Files under test:** `queries/memory_search.rs`, `migrations/v003_fts5_index.rs`
**Existing coverage:** `stress_test.rs` (1 test)

### Tests (10)

**FT-01: FTS5 trigger sync on INSERT**
- Setup: Insert memory with content "quantum computing"
- Action: `search_fts5(conn, "quantum", 10)`
- Assert: Returns the memory
- Failure: INSERT trigger not firing

**FT-02: FTS5 trigger sync on UPDATE**
- Setup: Insert memory "old topic", update content to "new quantum topic"
- Action: `search_fts5(conn, "quantum", 10)`
- Assert: Returns updated memory
- Failure: UPDATE trigger not deleting old + inserting new

**FT-03: FTS5 trigger sync on DELETE**
- Setup: Insert memory "quantum", then delete it
- Action: `search_fts5(conn, "quantum", 10)`
- Assert: Returns empty
- Failure: DELETE trigger not removing FTS5 entry

**FT-04: FTS5 searches content, summary, AND tags**
- Setup: Memory A: content="foo", Memory B: summary="foo", Memory C: tags=`["foo"]`
- Action: `search_fts5(conn, "foo", 10)`
- Assert: Returns all 3 (FTS5 indexes content, summary, tags columns)
- Failure: FTS5 virtual table missing a column

**FT-05: FTS5 excludes archived memories**
- Setup: Insert 2 memories with "quantum", archive 1
- Action: `search_fts5(conn, "quantum", 10)`
- Assert: Returns 1 (the non-archived one)
- Failure: Missing `AND m.archived = 0` in JOIN query

**FT-06: FTS5 respects limit parameter**
- Setup: Insert 20 memories matching "test"
- Action: `search_fts5(conn, "test", 5)`
- Assert: Returns exactly 5
- Failure: LIMIT not applied

**FT-07: FTS5 handles special characters gracefully**
- Setup: Memory with content `"user's input: O'Brien"`
- Action: `search_fts5(conn, "O'Brien", 10)`
- Assert: Returns the memory OR returns empty (no crash)
- Failure: SQL injection or FTS5 syntax error

**FT-08: FTS5 empty query returns empty, no error**
- Setup: DB with memories
- Action: `search_fts5(conn, "", 10)`
- Assert: Returns empty or error (no panic)
- Failure: Unhandled empty MATCH expression

**FT-09: FTS5 BM25 ranking orders by relevance**
- Setup: Memory A: content="rust rust rust", Memory B: content="rust web"
- Action: `search_fts5(conn, "rust", 10)`
- Assert: A ranked before B (higher BM25 score)
- Failure: `ORDER BY rank` not working

**FT-10: FTS5 search after bulk insert**
- Setup: `bulk_insert(conn, &[100 memories with varying content])`
- Action: `search_fts5(conn, "unique_term", 10)` (only 1 memory has this term)
- Assert: Returns exactly 1
- Failure: FTS5 triggers not firing during bulk insert transaction

---

## Cat 7: Vector Search & Embedding Storage

**Files under test:** `queries/vector_search.rs`, `migrations/v002_vector_tables.rs`, `migrations/v009_embedding_migration.rs`
**Existing coverage:** `storage_e2e_test.rs` (5 vector tests)

### Tests (12)

**VS-01: store_embedding deduplicates by content_hash**
- Setup: Store embedding for memory "m1" with hash "h1", then store for "m2" with same hash "h1"
- Action: `SELECT COUNT(*) FROM memory_embeddings WHERE content_hash = 'h1'`
- Assert: Returns 1 (single row, ON CONFLICT DO UPDATE)
- Failure: Duplicate embeddings stored, wasting space

**VS-02: store_embedding links memory to embedding**
- Setup: Store embedding for "m1"
- Action: `SELECT * FROM memory_embedding_link WHERE memory_id = 'm1'`
- Assert: Exactly 1 row linking m1 to correct embedding_id
- Failure: Link not created or wrong embedding_id

**VS-03: store_embedding upserts link on re-embed**
- Setup: Store embedding for "m1" with hash "h1", then re-embed with hash "h2"
- Action: `SELECT embedding_id FROM memory_embedding_link WHERE memory_id = 'm1'`
- Assert: Points to new embedding (ON CONFLICT DO UPDATE on memory_id)
- Failure: Duplicate link rows or old embedding referenced

**VS-04: store_embedding SAVEPOINT rollback on failure**
- Setup: Inject failure after embedding INSERT but before link INSERT
- Action: `store_embedding(conn, "m1", "h1", &vec, "model")`
- Assert: Error returned. No row in memory_embeddings (ROLLBACK TO store_emb)
- Failure: Orphaned embedding without link

**VS-05: search_vector cosine similarity correctness**
- Setup: Store 3 embeddings: A=[1,0,0], B=[0.9,0.1,0], C=[0,0,1]
- Action: `search_vector(conn, &[1.0, 0.0, 0.0], 10)`
- Assert: A first (sim≈1.0), B second (sim≈0.995), C last (sim=0.0, filtered)
- Failure: cosine_similarity math error

**VS-06: search_vector filters zero-norm query**
- Setup: Store embeddings
- Action: `search_vector(conn, &[0.0, 0.0, 0.0], 10)`
- Assert: Returns empty (zero-norm early exit)
- Failure: Division by zero in cosine_similarity

**VS-07: search_vector skips dimension mismatches**
- Setup: Store 128-dim embedding for "m1", 384-dim for "m2"
- Action: `search_vector(conn, &[128-dim query], 10)`
- Assert: Returns only "m1" (m2 skipped due to dim mismatch)
- Failure: Panic on mismatched slice lengths

**VS-08: search_vector respects limit**
- Setup: Store 20 embeddings with similar vectors
- Action: `search_vector(conn, &query, 5)`
- Assert: Returns exactly 5
- Failure: `.truncate(limit)` not applied

**VS-09: search_vector only returns positive similarity**
- Setup: Store opposing vector [-1, 0, 0] and query [1, 0, 0]
- Action: `search_vector(conn, &[1.0, 0.0, 0.0], 10)`
- Assert: Opposing vector NOT in results (sim < 0 filtered)
- Failure: Missing `if sim > 0.0` check

**VS-10: bytes_to_f32_vec roundtrip fidelity**
- Setup: Random f32 vector of 384 dims
- Action: `f32_vec_to_bytes(v)` → `bytes_to_f32_vec(bytes, 384)`
- Assert: Exact bit-for-bit equality
- Failure: Endianness mismatch or truncation

**VS-11: embedding_model_info tracks model version**
- Setup: Insert embedding with model "text-embedding-3-small"
- Action: `SELECT model_name FROM memory_embeddings`
- Assert: Returns "text-embedding-3-small"
- Failure: model_name column not populated

**VS-12: search_vector fetches full BaseMemory**
- Setup: Store embedding for memory with all link types
- Action: `search_vector(conn, &query, 10)`
- Assert: Returned BaseMemory has populated links (patterns, constraints, files, functions)
- Failure: `get_memory` not loading links

---

## Cat 8: Causal Graph Storage

**Files under test:** `queries/causal_ops.rs`
**Existing coverage:** `causal_test.rs` (~8), `stress_test.rs` (1)

### Tests (12)

**CG-01: add_edge with evidence persists atomically**
- Setup: Edge with 2 evidence entries
- Action: `add_edge(conn, &edge)`
- Assert: Edge in causal_edges, 2 rows in causal_evidence, temporal event "relationship_added"
- Failure: SAVEPOINT doesn't capture evidence + event

**CG-02: add_edge SAVEPOINT rollback on evidence failure**
- Setup: Edge where evidence INSERT would fail (e.g., NULL timestamp)
- Action: `add_edge(conn, &edge)`
- Assert: Error returned, no edge row, no evidence rows
- Failure: Edge persisted without evidence

**CG-03: add_edge INSERT OR REPLACE updates strength**
- Setup: Add edge A→B strength 0.5, then add_edge A→B strength 0.9
- Action: `get_edges(conn, "A")`
- Assert: Single edge A→B with strength 0.9
- Failure: Duplicate edge or error on conflict

**CG-04: get_edges returns bidirectional**
- Setup: Edges A→B, C→A
- Action: `get_edges(conn, "A")`
- Assert: Returns both edges (A is source in one, target in other)
- Failure: Only returns outbound or inbound

**CG-05: get_edges loads evidence for each edge**
- Setup: Edge A→B with 3 evidence entries
- Action: `get_edges(conn, "A")`
- Assert: Edge's evidence vec has length 3
- Failure: `get_evidence` not called per edge

**CG-06: remove_edge emits event BEFORE deletion**
- Setup: Edge A→B
- Action: `remove_edge(conn, "A", "B")`
- Assert: memory_events has "relationship_removed" event; edge row gone
- Failure: Event emission order

**CG-07: remove_edge cascades evidence**
- Setup: Edge A→B with evidence
- Action: `remove_edge(conn, "A", "B")`
- Assert: Zero rows in causal_evidence for A→B
- Failure: Orphaned evidence rows

**CG-08: update_strength emits temporal event**
- Setup: Edge A→B, strength 0.5
- Action: `update_strength(conn, "A", "B", 0.9)`
- Assert: memory_events has "strength_updated" with new_strength=0.9
- Failure: Event not emitted or wrong delta payload

**CG-09: has_cycle detects A→B→C→A**
- Setup: Edges A→B, B→C
- Action: `has_cycle(conn, "C", "A")`
- Assert: Returns true (adding C→A would create cycle)
- Failure: BFS doesn't traverse full chain

**CG-10: has_cycle returns false for DAG**
- Setup: Edges A→B, A→C, B→D
- Action: `has_cycle(conn, "A", "D")`
- Assert: Returns false (A→D is not a cycle in existing graph)
- Failure: False positive

**CG-11: edge_count and node_count accurate**
- Setup: 5 edges involving 4 distinct nodes
- Action: `edge_count(conn)`, `node_count(conn)`
- Assert: edge_count=5, node_count=4
- Failure: COUNT query wrong

**CG-12: remove_orphaned_edges cleans dangling references**
- Setup: Edge A→B where memory "A" doesn't exist in memories table
- Action: `remove_orphaned_edges(conn)`
- Assert: Edge A→B removed, returns 1
- Failure: Subquery `NOT IN (SELECT id FROM memories)` broken

---

## Cat 9: Link Operations & Cascade

**Files under test:** `queries/link_ops.rs`
**Existing coverage:** Minimal (tested indirectly via CRUD)

### Tests (10)

**LK-01: add_pattern_link INSERT OR IGNORE on duplicate**
- Setup: Add pattern link P1 to memory M1 twice
- Action: Second call
- Assert: No error (IGNORE), still 1 row
- Failure: Unique constraint error

**LK-02: add_pattern_link emits link_added event**
- Setup: Add pattern link
- Action: Query memory_events for "link_added"
- Assert: Event with `link_type: "pattern"` and target = pattern_id
- Failure: Event not emitted or wrong payload

**LK-03: remove_pattern_link is atomic SQL DELETE**
- Setup: Pattern links P1, P2 on memory M1
- Action: `remove_pattern_link(conn, "M1", "P1")`
- Assert: P1 gone, P2 still present; "link_removed" event emitted
- Failure: Read-modify-write race (old bug, fixed with E-04)

**LK-04: add_file_link stores all fields**
- Setup: FileLink with file_path, line_start, line_end, content_hash
- Action: Add link, then `SELECT * FROM memory_files`
- Assert: All 5 columns populated correctly
- Failure: Missing column in INSERT

**LK-05: add_function_link stores signature**
- Setup: FunctionLink with function_name, file_path, signature
- Action: Add link, then `SELECT signature FROM memory_functions`
- Assert: Signature matches
- Failure: NULL signature

**LK-06: remove_file_link by file_path**
- Setup: Two file links on same memory: "/a.rs", "/b.rs"
- Action: `remove_file_link(conn, "M1", "/a.rs")`
- Assert: "/a.rs" gone, "/b.rs" still present
- Failure: Wrong WHERE clause deletes both

**LK-07: remove_function_link by function_name**
- Setup: Two function links: "foo", "bar"
- Action: `remove_function_link(conn, "M1", "foo")`
- Assert: "foo" gone, "bar" present
- Failure: Wrong WHERE clause

**LK-08: All 4 remove ops emit link_removed event**
- Setup: One of each link type on memory M1
- Action: Remove each, check events
- Assert: 4 "link_removed" events with correct link_type in delta
- Failure: Event emission inconsistency

**LK-09: Link operations survive concurrent access**
- Setup: `test_engine_file()`, two threads adding links to same memory
- Action: Thread 1 adds P1, Thread 2 adds P2 concurrently
- Assert: Both links present after both threads complete
- Failure: Writer mutex doesn't serialize correctly

**LK-10: Removing non-existent link is idempotent**
- Setup: Memory M1 with no pattern links
- Action: `remove_pattern_link(conn, "M1", "nonexistent")`
- Assert: Returns Ok(()), "link_removed" event still emitted (or skipped)
- Failure: Error on 0 rows affected

---

## Cat 10: Session & Audit Subsystem

**Files under test:** `queries/session_ops.rs`, `queries/audit_ops.rs`, `audit/mod.rs`
**Existing coverage:** `subsystem_ops_test.rs` (5 session, 2 audit tests)

### Tests (10)

**SA-01: Session create and get roundtrip**
- Setup: `create_session(conn, "s1")`
- Action: `get_session(conn, "s1")`
- Assert: Returns SessionContext with matching id, created_at, zero counters
- Failure: Missing INSERT or wrong column mapping

**SA-02: Session end sets ended_at**
- Setup: Create session, then `end_session(conn, "s1")`
- Action: `SELECT ended_at FROM session_contexts WHERE session_id = 's1'`
- Assert: ended_at IS NOT NULL
- Failure: ended_at not updated

**SA-03: Session analytics tracks token usage**
- Setup: Create session, `update_tokens(conn, "s1", 100)`
- Action: `get_session(conn, "s1")`
- Assert: tokens_sent == 100
- Failure: UPDATE not incrementing

**SA-04: Session cleanup removes stale sessions**
- Setup: Create 2 sessions, age one past TTL (manually set created_at to 25h ago)
- Action: `cleanup_old_sessions(session_engine)`
- Assert: Stale session gone, fresh one preserved
- Failure: TTL comparison wrong

**SA-05: Audit log records create/update/delete actions**
- Setup: Create memory, update it, delete it
- Action: `SELECT * FROM memory_audit_log WHERE memory_id = 'M1'`
- Assert: 3 entries with actions: create, update, delete
- Failure: AuditLogger not called from IMemoryStorage impl

**SA-06: Audit log rotation removes old entries**
- Setup: 100 audit entries, age 50 past retention
- Action: `rotate_audit_log(conn, retention_days)`
- Assert: 50 entries remain
- Failure: Retention query wrong

**SA-07: Consolidation metrics persists run data**
- Setup: `INSERT INTO consolidation_metrics (...)`
- Action: Query back
- Assert: All fields roundtrip (merged_count, duration_ms, etc.)
- Failure: Missing column

**SA-08: Degradation log records events**
- Setup: `INSERT INTO degradation_log (subsystem, severity, description)`
- Action: Query back
- Assert: Roundtrip correct, created_at auto-populated
- Failure: DEFAULT timestamp not applied

**SA-09: Session analytics insert and query**
- Setup: Insert analytics event for session "s1"
- Action: `SELECT * FROM session_analytics WHERE session_id = 's1'`
- Assert: event_type, event_data, created_at all correct
- Failure: Wrong table or missing columns

**SA-10: Audit actor serialization**
- Setup: Log with AuditActor::System, AuditActor::User("alice")
- Action: Query actor column
- Assert: Values are "system" and "user:alice" (or similar format)
- Failure: Actor serialization inconsistent

---

## Cat 11: Multi-Agent Namespace Isolation

**Files under test:** `migrations/v015_multiagent_tables.rs`, `queries/memory_query.rs` (namespace filter), NAPI `multiagent.rs`
**Existing coverage:** ~3 tests in multiagent integration

### Tests (12)

**MA-01: agent_registry roundtrip**
- Setup: `INSERT INTO agent_registry (agent_id, name, capabilities, status)`
- Action: Query back
- Assert: All fields match including JSON capabilities array
- Failure: JSON serialization mismatch

**MA-02: memory_namespaces scope + name uniqueness**
- Setup: Create namespace "agent://bot1/"
- Action: Try to create "agent://bot1/" again
- Assert: UNIQUE constraint error
- Failure: Missing UNIQUE on (scope, name) or URI

**MA-03: namespace_permissions CRUD**
- Setup: Grant "read" permission to agent "bot2" on namespace "ns1"
- Action: Query permissions for bot2 on ns1
- Assert: Permission exists with correct level
- Failure: Missing table or wrong FK

**MA-04: Namespace filter isolates query_by_type**
- Setup: 3 Core memories in ns1, 2 in ns2
- Action: `query_by_type(conn, Core, Some(&ns1))`
- Assert: Returns 3 (only ns1)
- Failure: Filter not applied, returns all 5

**MA-05: Namespace filter isolates query_by_confidence_range**
- Setup: Memories across 2 namespaces with overlapping confidence
- Action: `query_by_confidence_range(conn, 0.5, 1.0, Some(&ns1))`
- Assert: Only returns ns1 memories in range
- Failure: Namespace WHERE clause missing

**MA-06: Namespace filter isolates query_by_tags**
- Setup: Both namespaces have memories tagged "important"
- Action: `query_by_tags(conn, &["important"], Some(&ns1))`
- Assert: Only ns1 memories returned
- Failure: LIKE query ignores namespace

**MA-07: memory_projections stores config**
- Setup: Create projection from ns1 to ns2 with field mapping
- Action: Query memory_projections
- Assert: source_namespace, target_namespace, config JSON all correct
- Failure: Missing columns or JSON truncation

**MA-08: provenance_log tracks actions**
- Setup: Insert provenance entry for share action
- Action: Query provenance_log
- Assert: agent_id, action, confidence_delta, timestamp all correct
- Failure: Missing table after migration

**MA-09: agent_trust stores bidirectional trust**
- Setup: Set trust A→B = 0.8
- Action: Query agent_trust for A→B
- Assert: trust_score = 0.8
- Failure: Wrong column or FK constraint

**MA-10: delta_queue persists CRDT deltas**
- Setup: Insert delta for sync between agents
- Action: Query delta_queue
- Assert: source_agent, target_agent, delta_json all correct
- Failure: Table not created in v015

**MA-11: NAPI register_agent validates empty name**
- Setup: Call `cortex_multiagent_register_agent("", vec![])`
- Action: Check result
- Assert: Returns napi::Error "Agent name must be non-empty"
- Failure: Empty name stored in registry

**MA-12: NAPI share_memory creates provenance hop**
- Setup: Register agent, create namespace, create memory
- Action: `cortex_multiagent_share_memory(memory_id, namespace, agent_id)`
- Assert: Returns ProvenanceHop with SharedTo action, confidence_delta=0.0
- Failure: Provenance not created or wrong action type

---

## Cat 12: Cloud Sync & Conflict Storage

**Files under test:** `migrations/v010_cloud_sync.rs`, `queries/cloud_ops.rs`
**Existing coverage:** None

### Tests (8)

**CS-01: sync_state singleton insert**
- Setup: `raw_conn()` (migration creates default row)
- Action: `SELECT * FROM sync_state`
- Assert: Exactly 1 row with id=1
- Failure: Default row not inserted by migration

**CS-02: sync_state last_sync_at update**
- Setup: Update sync_state set last_sync_at = NOW
- Action: Query back
- Assert: Timestamp updated
- Failure: CHECK constraint prevents update

**CS-03: sync_log records operations**
- Setup: Insert sync log entry (direction, entity_count, duration_ms)
- Action: Query sync_log
- Assert: All fields roundtrip
- Failure: Missing columns

**CS-04: conflict_log records conflicts**
- Setup: Insert conflict (memory_id, conflict_type, local_value, remote_value)
- Action: Query conflict_log
- Assert: All fields including resolution_status, resolved_at
- Failure: Missing table

**CS-05: conflict_log resolution update**
- Setup: Insert unresolved conflict, then resolve it
- Action: `UPDATE conflict_log SET resolution_status = 'resolved', resolved_at = NOW`
- Assert: Fields updated correctly
- Failure: Missing resolved_at column

**CS-06: sync_state CHECK(id=1) prevents second row**
- Setup: `INSERT INTO sync_state (id) VALUES (2)`
- Assert: Constraint violation
- Failure: Missing CHECK

**CS-07: sync_log auto-populates created_at**
- Setup: Insert without explicit created_at
- Action: Query created_at
- Assert: Non-NULL, recent timestamp
- Failure: Missing DEFAULT

**CS-08: conflict_log FK to memories**
- Setup: Insert conflict referencing non-existent memory_id
- Assert: Behavior matches FK constraint (error or allowed depending on schema)
- Failure: Unexpected cascade behavior

---

## Cat 13: Versioning & Reclassification

**Files under test:** `migrations/v008_versioning_tables.rs`, `migrations/v007_validation_tables.rs`, `migrations/v011_reclassification.rs`, `versioning/mod.rs`
**Existing coverage:** `versioning_test.rs` (~6 tests)

### Tests (10)

**VR-01: memory_versions records content evolution**
- Setup: Create memory, update content 3 times
- Action: Query `memory_versions WHERE memory_id = 'M1' ORDER BY version_number`
- Assert: 3 version rows with correct content, summary, confidence, change_reason
- Failure: Version not inserted on update

**VR-02: Version number auto-increments per memory**
- Setup: Create M1, update 3 times. Create M2, update 2 times
- Action: Query max(version_number) for each
- Assert: M1 has version 3, M2 has version 2 (independent counters)
- Failure: Global counter instead of per-memory

**VR-03: Version retention deletes oldest**
- Setup: Create 20 versions for M1, retention limit = 10
- Action: `enforce_version_retention(conn, "M1", 10)`
- Assert: 10 newest versions remain, 10 oldest deleted
- Failure: Retention query wrong or deletes newest

**VR-04: Get version at specific number**
- Setup: Create M1, update 5 times
- Action: `get_version_at(conn, "M1", 3)`
- Assert: Returns version 3 content
- Failure: Off-by-one in version numbering

**VR-05: memory_validation_history roundtrip**
- Setup: Insert validation record with all 4 dimension scores
- Action: Query back
- Assert: All fields match (staleness, contradiction, confidence_calibration, source_reliability)
- Failure: Missing column in v007

**VR-06: memory_contradictions records detected conflicts**
- Setup: Insert contradiction between M1 and M2 with severity
- Action: Query memory_contradictions
- Assert: memory_id_a, memory_id_b, severity, description all correct
- Failure: Table not created or wrong schema

**VR-07: reclassification_history tracks type changes**
- Setup: Insert reclassification: Core → Semantic, reason = "high usage"
- Action: Query reclassification_history
- Assert: old_type, new_type, reason, reclassified_at all correct
- Failure: Missing table in v011

**VR-08: reclassification_signals stores trigger data**
- Setup: Insert signal (memory_id, signal_type, signal_value)
- Action: Query reclassification_signals
- Assert: All fields roundtrip
- Failure: Missing columns

**VR-09: Version count returns accurate total**
- Setup: Create M1 with 5 versions, M2 with 3
- Action: `version_count(conn, "M1")`
- Assert: Returns 5
- Failure: Counts across all memories

**VR-10: Validation history preserves healing_action**
- Setup: Insert validation with healing_action = "confidence_adjusted"
- Action: Query healing_action column
- Assert: Non-NULL, matches input
- Failure: Column nullable when should be NOT NULL, or vice versa

---

## Cat 14: Observability & Metrics Storage

**Files under test:** `migrations/v012_observability.rs`, `queries/observability_ops.rs`
**Existing coverage:** None direct

### Tests (8)

**OB-01: metric_snapshots roundtrip**
- Setup: Insert snapshot with metric_name, metric_value, tags_json
- Action: Query back
- Assert: All fields correct, created_at auto-populated
- Failure: Missing table or DEFAULT

**OB-02: query_performance_log records slow queries**
- Setup: Insert log entry (query_type, duration_ms, rows_examined, rows_returned)
- Action: Query back
- Assert: All fields roundtrip
- Failure: Missing columns in v012

**OB-03: metric_snapshots created_at indexing**
- Setup: Insert 100 snapshots over time range
- Action: `SELECT * FROM metric_snapshots WHERE created_at > ?1 ORDER BY created_at`
- Assert: Uses idx_metric_snapshots_created_at index (EXPLAIN QUERY PLAN)
- Failure: Missing index

**OB-04: query_performance_log rotation**
- Setup: 1000 log entries, age 500 past 30-day retention
- Action: `DELETE FROM query_performance_log WHERE created_at < ?1`
- Assert: 500 entries remain
- Failure: No created_at DEFAULT for age comparison

**OB-05: Multiple snapshots for same metric**
- Setup: Insert 5 snapshots for "memory_count" at different times
- Action: Query all for "memory_count"
- Assert: Returns 5 rows (no unique constraint on metric_name)
- Failure: UNIQUE on metric_name prevents time-series

**OB-06: Metrics flush on shutdown persists**
- Setup: `test_engine_file()`, accumulate metrics, call shutdown
- Action: Reopen DB, query metric_snapshots
- Assert: Metrics from pre-shutdown are persisted
- Failure: Shutdown doesn't flush metrics to storage

**OB-07: metric_snapshots supports JSON tags**
- Setup: Insert with tags_json = `{"subsystem": "storage", "level": "info"}`
- Action: Query tags_json column
- Assert: Valid JSON string roundtrip
- Failure: TEXT column truncation

**OB-08: query_performance_log indexes query_type**
- Setup: Insert logs with different query_types
- Action: `SELECT * FROM query_performance_log WHERE query_type = 'vector_search'`
- Assert: Fast query (index used)
- Failure: Missing index on query_type

---

## Cat 15: Compaction, Recovery & Vacuum

**Files under test:** `compaction/mod.rs`, `recovery/mod.rs`, engine.rs (vacuum)
**Existing coverage:** `compaction_test.rs` (~3), `recovery_test.rs` (~3)

### Tests (8)

**CR-01: incremental_vacuum reclaims space**
- Setup: `test_engine_file()`, insert 1000 memories, delete 500
- Action: `storage.vacuum()` (incremental)
- Assert: File size decreases or stays same (pages freed)
- Failure: vacuum doesn't reclaim

**CR-02: full_vacuum succeeds on file-backed DB**
- Setup: `test_engine_file()`
- Action: `VACUUM` via raw conn
- Assert: Returns Ok, DB still functional, all memories intact
- Failure: Locks prevent VACUUM

**CR-03: WAL checkpoint succeeds**
- Setup: `test_engine_file()`, insert 100 memories
- Action: `PRAGMA wal_checkpoint(TRUNCATE)`
- Assert: WAL file size goes to 0 or near-0
- Failure: Active readers prevent checkpoint

**CR-04: integrity_check on healthy DB**
- Setup: `test_engine_file()` with data
- Action: `PRAGMA integrity_check`
- Assert: Returns "ok"
- Failure: Corruption from unsafe shutdown

**CR-05: Recovery from corrupted WAL**
- Setup: `test_engine_file()`, write data, manually truncate WAL file
- Action: Reopen DB
- Assert: DB opens (possibly with data loss from uncommitted WAL), no crash
- Failure: Panic or unrecoverable error

**CR-06: Orphaned embedding cleanup**
- Setup: Delete memory but leave orphaned embedding (FK not cascading to embeddings)
- Action: `DELETE FROM memory_embeddings WHERE id NOT IN (SELECT embedding_id FROM memory_embedding_link)`
- Assert: Orphaned embedding removed
- Failure: Subquery wrong

**CR-07: Archived memory cleanup by age and confidence**
- Setup: 10 archived memories: 5 old+low-confidence, 5 recent+high-confidence
- Action: `cleanup_archived(conn, age_days, min_confidence)`
- Assert: 5 old+low removed, 5 recent+high preserved
- Failure: Wrong WHERE clause

**CR-08: Compaction preserves FTS5 consistency**
- Setup: Insert memories, compact (delete + vacuum)
- Action: FTS5 search for remaining memories
- Assert: All remaining memories searchable, no stale FTS5 entries
- Failure: FTS5 triggers not fired during compaction

---

## Cat 16: NAPI→Storage Integration

**Files under test:** `cortex-napi/src/bindings/memory.rs`, `lifecycle.rs`, `health.rs`, `causal.rs`, `session.rs`, `temporal.rs`, `multiagent.rs`
**Existing coverage:** None (NAPI requires native binary build)

### Tests (14)

> Note: These tests require either a full NAPI build or a mock layer that exercises the same code path. They verify the JSON→Rust→Storage→Rust→JSON roundtrip.

**NI-01: cortex_memory_create → cortex_memory_get roundtrip**
- Setup: Initialize runtime with in-memory DB
- Action: `cortex_memory_create(json)` → `cortex_memory_get(id)`
- Assert: Returned JSON has all fields matching input, including tags, links, confidence
- Failure: JSON deserialization/serialization mismatch in memory_types conversions

**NI-02: cortex_memory_update triggers re-embed on content_hash change**
- Setup: Create memory, update with different content (different hash)
- Action: `cortex_memory_update(updated_json)`
- Assert: New embedding stored in memory_embeddings table, old embedding link updated
- Failure: content_hash comparison missing in memory.rs binding

**NI-03: cortex_memory_search delegates to FTS5**
- Setup: Create 3 memories with known content
- Action: `cortex_memory_search("specific_term", 10)`
- Assert: Returns only memories containing "specific_term"
- Failure: search binding not calling search_fts5

**NI-04: cortex_memory_list with type filter**
- Setup: Create 3 Core, 2 Semantic memories
- Action: `cortex_memory_list("Core")`
- Assert: Returns 3 Core memories only
- Failure: Type filter not passed to query_by_type

**NI-05: cortex_memory_archive / cortex_memory_restore cycle**
- Setup: Create memory, archive it
- Action: `cortex_memory_archive(id)` → verify not in list → `cortex_memory_restore(id)` → verify in list
- Assert: Memory disappears from active queries after archive, reappears after restore
- Failure: Archived flag not toggled correctly

**NI-06: cortex_causal_infer_cause returns structured result**
- Setup: Create 2 related memories
- Action: `cortex_causal_infer_cause(source_json, target_json)`
- Assert: Returns JSON with source_id, target_id, strength, suggested_relation, above_threshold
- Failure: InferenceResult manual serialization misses field

**NI-07: cortex_session_create returns valid UUID**
- Setup: Initialize runtime
- Action: `cortex_session_create(None)` (auto-generated ID)
- Assert: Returns valid UUID v4 string
- Failure: uuid generation or return type error

**NI-08: cortex_session_get returns error for non-existent**
- Setup: Initialize runtime
- Action: `cortex_session_get("nonexistent-id")`
- Assert: Returns napi::Error with "Session not found" message
- Failure: Returns null instead of error, or panics

**NI-09: cortex_temporal_query_as_of parses ISO 8601**
- Setup: Create memories at known timestamps
- Action: `cortex_temporal_query_as_of("2025-01-01T00:00:00Z", "2025-01-01T00:00:00Z", null)`
- Assert: Returns memories valid at that point-in-time
- Failure: parse_time rejects valid ISO 8601 format

**NI-10: cortex_temporal_query_as_of rejects invalid time**
- Setup: Initialize runtime
- Action: `cortex_temporal_query_as_of("not-a-date", "2025-01-01T00:00:00Z", null)`
- Assert: Returns napi::Error "Invalid ISO 8601 time"
- Failure: Panic or silent fallback

**NI-11: cortex_health_get_health queries real storage stats**
- Setup: Create 5 memories, archive 2
- Action: `cortex_health_get_health()`
- Assert: Report contains total_memories=5, active=3, archived=2 (not hardcoded zeros)
- Failure: Health binding uses stale/hardcoded values

**NI-12: cortex_initialize → cortex_shutdown lifecycle**
- Setup: `cortex_initialize(null, null, null)` (in-memory)
- Action: Create memories, then `cortex_shutdown()`
- Assert: Shutdown succeeds, WAL flushed, metrics persisted
- Failure: Shutdown panics or doesn't flush

**NI-13: cortex_multiagent_register_agent validates inputs**
- Setup: Initialize runtime
- Action: `cortex_multiagent_register_agent("", ["cap1"])`
- Assert: Returns error "Agent name must be non-empty"
- Failure: Empty name stored

**NI-14: cortex_multiagent_sync_agents returns real counts**
- Setup: Register 2 agents, create memories for source, share to target namespace
- Action: `cortex_multiagent_sync_agents(source_id, target_id)`
- Assert: Returns JSON with deltas_applied > 0, deltas_buffered >= 0 (not hardcoded zeros)
- Failure: sync_with_counts not returning real values

---

## Cat 17: Bridge Cross-DB Operations

**Files under test:** `cortex-drift-bridge/src/storage/tables.rs`, `cortex-drift-bridge/src/grounding/loop_runner.rs`, `cortex-drift-bridge/src/query/drift_queries.rs`, `cortex-drift-bridge/src/napi/functions.rs`
**Existing coverage:** Bridge integration tests (~20 in cortex-drift-bridge/tests/)

### Tests (12)

**BR-01: attach_cortex_db succeeds with valid path**
- Setup: Create cortex.db file, open bridge.db connection
- Action: `attach_cortex_db(bridge_conn, "/tmp/cortex.db")`
- Assert: Returns Ok(true), can query cortex.memories from bridge_conn
- Failure: ATTACH fails or path not parameterized

**BR-02: attach_cortex_db fails gracefully with invalid path**
- Setup: Open bridge.db connection
- Action: `attach_cortex_db(bridge_conn, "/nonexistent/cortex.db")`
- Assert: Returns Err(BridgeError::AttachFailed)
- Failure: Panic or misleading error

**BR-03: detach_cortex_db cleans up**
- Setup: Attach, then detach
- Action: `detach_cortex_db(bridge_conn)`
- Assert: Subsequent queries to cortex.memories fail with "no such table"
- Failure: DETACH not executed

**BR-04: Bridge tables created correctly (5 tables)**
- Setup: `create_bridge_tables(conn)`
- Action: `SELECT name FROM sqlite_master WHERE type='table'`
- Assert: bridge_grounding_results, bridge_grounding_snapshots, bridge_event_log, bridge_metrics, bridge_memories all exist
- Failure: Schema DDL mismatch between schema.rs and tables.rs

**BR-05: record_grounding_result persists all fields**
- Setup: GroundingResult with score, verdict, evidence JSON
- Action: `record_grounding_result(conn, &result)`
- Assert: All fields queryable, evidence_json valid JSON
- Failure: serde_json serialization error

**BR-06: get_previous_grounding_score returns latest**
- Setup: Insert 3 grounding results for M1 at different times
- Action: `get_previous_grounding_score(conn, "M1")`
- Assert: Returns score from most recent (ORDER BY created_at DESC LIMIT 1)
- Failure: Returns oldest or wrong order

**BR-07: get_grounding_history respects limit**
- Setup: Insert 20 results for M1
- Action: `get_grounding_history(conn, "M1", 5)`
- Assert: Returns exactly 5, newest first
- Failure: LIMIT not applied

**BR-08: Grounding loop caps at max_memories_per_loop**
- Setup: 600 memories, config max=500
- Action: `runner.run(&memories, drift_db, bridge_db, trigger)`
- Assert: snapshot.total_checked == 500, excess deferred (logged)
- Failure: Processes all 600 or drops excess

**BR-09: ground_single returns NotGroundable for non-groundable types**
- Setup: Memory with type = Preference (not groundable)
- Action: `runner.ground_single(&memory, None, None)`
- Assert: verdict == GroundingVerdict::NotGroundable, score == 0.0
- Failure: Attempts to ground non-groundable type

**BR-10: ground_single returns InsufficientData when no evidence**
- Setup: Memory with no pre-populated fields and no drift_db
- Action: `runner.ground_single(&memory, None, None)`
- Assert: verdict == GroundingVerdict::InsufficientData
- Failure: Panics or returns wrong verdict

**BR-11: bridge_status includes version**
- Setup: Call `bridge_status(true, &LicenseTier::Community, true)`
- Assert: Returned JSON has "version" field matching crate version
- Failure: env!("CARGO_PKG_VERSION") not populated

**BR-12: drift_queries use parameterized queries (no SQL injection)**
- Setup: `pattern_confidence(conn, "'; DROP TABLE drift_patterns; --")`
- Assert: Returns None (no match), table still intact
- Failure: SQL injection via unparameterized query

---

## Cat 18: Edge Cases & Adversarial Inputs

**Files under test:** All query modules, NAPI bindings
**Existing coverage:** Some in `drift_edge_cases_test.rs` (for drift-storage, not cortex-storage)

### Tests (14)

**EC-01: SQL injection via memory ID**
- Setup: `storage.get("'; DROP TABLE memories; --")`
- Assert: Returns None, memories table intact
- Failure: Unparameterized query

**EC-02: SQL injection via tag search**
- Setup: `query_by_tags(conn, &["'; DROP TABLE memories; --"], None)`
- Assert: Returns empty, table intact
- Failure: LIKE pattern not parameterized

**EC-03: Unicode content roundtrip**
- Setup: Memory with content containing emoji, CJK, RTL, combining characters: "测试 🚀 مرحبا café"
- Action: Create, then get
- Assert: Exact byte-for-byte match
- Failure: UTF-8 encoding issue in SQLite TEXT

**EC-04: Empty string content**
- Setup: Memory with content = ""
- Action: Create, then get
- Assert: Content is empty string, not NULL
- Failure: Empty string coerced to NULL

**EC-05: NULL vs empty in optional fields**
- Setup: Memory with superseded_by = None, supersedes = None, valid_until = None
- Action: Create, then get
- Assert: All None fields are None in returned memory (not empty string)
- Failure: NULL→"" conversion in row_to_base_memory

**EC-06: Very long content (100KB)**
- Setup: Memory with 100KB content string
- Action: Create, then get
- Assert: Exact content roundtrip, no truncation
- Failure: TEXT column size limit or buffer overflow

**EC-07: Very long tag list (1000 tags)**
- Setup: Memory with 1000 unique tags
- Action: Create, then get
- Assert: All 1000 tags present
- Failure: JSON serialization of large tag array truncated

**EC-08: Concurrent create + delete of same ID**
- Setup: `test_engine_file()`
- Action: Thread 1 creates M1, Thread 2 immediately deletes M1 (race)
- Assert: No crash, no deadlock; final state is either M1 exists or M1 doesn't
- Failure: Deadlock, corruption, or panic

**EC-09: Zero-length embedding vector**
- Setup: `store_embedding(conn, "M1", "h1", &[], "model")`
- Assert: Returns Ok or Error (no panic), dimensions = 0
- Failure: Panic on empty slice

**EC-10: NaN/Infinity confidence values**
- Setup: Memory with confidence = f64::NAN or f64::INFINITY
- Action: Attempt to create
- Assert: Error returned (Confidence::new clamps or rejects)
- Failure: NaN stored in DB, breaks all comparisons

**EC-11: Duplicate memory_id across rapid concurrent creates**
- Setup: 10 threads all try `storage.create()` with same ID simultaneously
- Action: Run concurrently
- Assert: Exactly 1 succeeds, 9 fail with duplicate error
- Failure: Multiple rows with same ID

**EC-12: Memory with all fields at maximum length**
- Setup: Memory with id=UUID (36), content=1MB, summary=64KB, tags=10K entries
- Action: Create, then get
- Assert: All fields roundtrip without truncation
- Failure: Column size limits or OOM

**EC-13: FTS5 syntax attack**
- Setup: `search_fts5(conn, "NEAR(a b) OR NOT content:", 10)`
- Assert: Returns error or empty (no crash)
- Failure: FTS5 syntax parser panic

**EC-14: Timestamp edge cases**
- Setup: Memory with transaction_time = DateTime::MIN_UTC, valid_time = DateTime::MAX_UTC
- Action: Create, then get
- Assert: Timestamps roundtrip or error returned
- Failure: RFC3339 parsing fails on extreme dates

---

## Summary Statistics

| Category | Tests | New Tests (vs existing) |
|----------|-------|------------------------|
| 1. Schema & Migration | 12 | ~7 new |
| 2. Connection Pool & WAL | 10 | ~6 new |
| 3. Memory CRUD Atomicity | 14 | ~4 new |
| 4. Temporal Events | 10 | ~7 new |
| 5. Query Module Correctness | 12 | ~8 new |
| 6. FTS5 Search | 10 | ~9 new |
| 7. Vector Search & Embeddings | 12 | ~7 new |
| 8. Causal Graph | 12 | ~4 new |
| 9. Link Operations | 10 | ~10 new |
| 10. Session & Audit | 10 | ~5 new |
| 11. Multi-Agent Namespace | 12 | ~9 new |
| 12. Cloud Sync & Conflict | 8 | ~8 new |
| 13. Versioning & Reclassification | 10 | ~4 new |
| 14. Observability & Metrics | 8 | ~8 new |
| 15. Compaction & Recovery | 8 | ~2 new |
| 16. NAPI→Storage Integration | 14 | ~14 new |
| 17. Bridge Cross-DB | 12 | ~8 new |
| 18. Edge Cases & Adversarial | 14 | ~8 new |
| **TOTAL** | **188** | **~128 new** |

---

## Implementation Priority

### Phase 1 (P0 — blocks correctness) — 40 tests
- Cat 1: SM-06 (migration rollback), SM-07 (FK cascade)
- Cat 2: CP-01 (concurrent writes), CP-03 (WAL visibility), CP-04 (in-memory routing)
- Cat 3: MC-01 (atomic create), MC-02 (rollback), MC-08 (bulk rollback)
- Cat 4: TE-03 (event failure isolation), TE-04 (all event types)
- Cat 6: FT-01 (INSERT trigger), FT-02 (UPDATE trigger)
- Cat 7: VS-04 (SAVEPOINT rollback)
- Cat 8: CG-01 (atomic edge), CG-02 (SAVEPOINT rollback)
- Cat 18: EC-01 (SQL injection), EC-11 (concurrent duplicate)

### Phase 2 (P1 — blocks features) — 60 tests
- Cat 5: All QM tests (query correctness)
- Cat 9: All LK tests (link ops)
- Cat 11: All MA tests (namespace isolation)
- Cat 16: All NI tests (NAPI integration)
- Cat 17: BR-01 through BR-07 (bridge operations)

### Phase 3 (P2 — completeness) — 88 tests
- All remaining tests across categories 10, 12, 13, 14, 15, 18

---

## Data Flow Map

```
┌─────────────────────────────────────────────────────────────────┐
│                     WRITE PATHS (→ cortex.db)                   │
├─────────────────────────────────────────────────────────────────┤
│ CortexClient.memoryCreate()                                     │
│   → cortex_memory_create (NAPI)                                 │
│     → IMemoryStorage.create()                                   │
│       → pool.writer.with_conn_sync()                            │
│         → insert_memory(conn, &memory) [TRANSACTION]            │
│           → INSERT memories                                     │
│           → INSERT memory_patterns (per link)                   │
│           → INSERT memory_constraints (per link)                │
│           → INSERT memory_files (per link)                      │
│           → INSERT memory_functions (per link)                  │
│           → emit_event(conn, "created", ...)                    │
│           → AuditLogger.log_create(conn, ...)                   │
│                                                                 │
│ CortexClient.memoryUpdate()                                     │
│   → cortex_memory_update (NAPI)                                 │
│     → IMemoryStorage.update()                                   │
│       → update_memory(conn, &memory) [TRANSACTION]              │
│         → UPDATE memories                                       │
│         → DELETE + INSERT links                                 │
│         → emit_event(conn, "content_updated|tags_modified|...")  │
│     → IF content_hash changed:                                  │
│       → EmbeddingEngine.embed()                                 │
│       → store_embedding(conn, ...) [SAVEPOINT]                  │
│                                                                 │
│ CortexClient.causalInfer()                                      │
│   → cortex_causal_infer_cause (NAPI)                            │
│     → CausalEngine.infer()                                      │
│       → ICausalStorage.add_edge() [SAVEPOINT]                   │
│         → INSERT causal_edges                                   │
│         → INSERT causal_evidence                                │
│         → emit_event(conn, "relationship_added", ...)           │
├─────────────────────────────────────────────────────────────────┤
│                     READ PATHS (← cortex.db)                    │
├─────────────────────────────────────────────────────────────────┤
│ CortexClient.memoryGet()                                        │
│   → cortex_memory_get (NAPI)                                    │
│     → IMemoryStorage.get()                                      │
│       → engine.with_reader() [read pool OR writer]              │
│         → get_memory(conn, &id) + load_links                    │
│                                                                 │
│ CortexClient.memorySearch()                                     │
│   → cortex_memory_search (NAPI)                                 │
│     → IMemoryStorage.search()                                   │
│       → engine.with_reader()                                    │
│         → search_fts5(conn, query, limit)                       │
│                                                                 │
│ CortexClient.healthReport()                                     │
│   → cortex_health_get_health (NAPI)                             │
│     → queries: count_by_type, average_confidence, stale_count   │
│     → queries: embedding cache stats, consolidation metrics     │
│     → queries: validation contradiction count                   │
├─────────────────────────────────────────────────────────────────┤
│                   CROSS-DB (bridge.db ↔ cortex.db)              │
├─────────────────────────────────────────────────────────────────┤
│ BridgeRuntime.initialize()                                      │
│   → open cortex.db (read/write)                                 │
│   → open drift.db (read-only)                                   │
│   → migrate bridge tables into cortex.db                        │
│                                                                 │
│ GroundingLoopRunner.run()                                       │
│   → read memories from cortex.db                                │
│   → read evidence from drift.db (10 query types)                │
│   → write results to bridge_grounding_results                   │
│   → write snapshots to bridge_grounding_snapshots               │
│                                                                 │
│ attach_cortex_db(bridge_conn, path)                             │
│   → ATTACH DATABASE ?1 AS cortex                                │
│   → cross-DB queries: cortex.memories JOIN bridge.*             │
└─────────────────────────────────────────────────────────────────┘
```
