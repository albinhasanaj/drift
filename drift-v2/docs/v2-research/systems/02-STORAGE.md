# Storage (drift.db) — Research & Decision Guide

> System: Single SQLite database, WAL mode, 40+ tables, CQRS pattern
> Hierarchy: Level 0 — Bedrock
> Dependencies: None (foundational)
> Consumers: Every system that persists or queries data

---

## What This System Does

drift.db is the single source of truth for all Drift data. Every pattern, every call graph edge, every violation, every constraint lives here. Per Decision 6 (PLANNING-DRIFT.md), drift.db is fully self-contained — ATTACH cortex.db is an optional read-only overlay.

---

## Key Library: rusqlite

`rusqlite` is the standard Rust binding for SQLite. It wraps the SQLite C library and provides a safe Rust API. Used by: cargo (Rust's package manager), Firefox, and hundreds of production Rust applications.

Current version: 0.32.x (as of early 2026).

Key features:
- `prepare_cached()` for prepared statement caching (avoids re-compilation)
- `backup::Backup` for hot backup via SQLite Backup API
- `blob` module for incremental blob I/O
- Feature flags for bundled SQLite vs system SQLite
- `bundled` feature compiles SQLite from source (recommended for reproducibility)

---

## Key Decision: Connection Architecture

### The Problem

SQLite supports concurrent readers but only one writer at a time (even in WAL mode). You need a strategy for managing connections.

### Option A: Single Connection with Mutex — NOT RECOMMENDED

```rust
struct Database {
    conn: Mutex<Connection>,
}
```

Simple but serializes all reads behind the write lock. Terrible for MCP server scenarios where multiple tools query simultaneously.

### Option B: Write-Serialized + Read-Pooled — RECOMMENDED

```rust
struct DatabaseManager {
    writer: Mutex<Connection>,           // single writer, serialized
    readers: Vec<Mutex<Connection>>,     // N read connections
}
```

This is the pattern recommended by SQLite documentation for WAL mode:
- One writer connection protected by a Mutex
- N reader connections (typically `num_cpus`) each with their own Mutex
- Readers never block each other (WAL mode allows concurrent reads)
- Writer never blocks readers (WAL mode — readers see the last committed state)
- Readers never block the writer

This is the same pattern used by Django's SQLite backend, Litestream, and other production SQLite deployments.

### Connection Pragmas

From the [SQLite Pragma Cheatsheet](https://cj.rs/blog/sqlite-pragma-cheatsheet-for-performance-and-consistency/):

**On open (every connection):**
```sql
PRAGMA journal_mode = WAL;          -- concurrent readers + writer
PRAGMA synchronous = NORMAL;        -- safe with WAL, much faster than FULL
PRAGMA foreign_keys = ON;           -- enforce referential integrity
PRAGMA cache_size = -64000;         -- 64MB page cache per connection
PRAGMA mmap_size = 268435456;       -- 256MB memory-mapped I/O
PRAGMA busy_timeout = 5000;         -- 5s retry on SQLITE_BUSY
PRAGMA temp_store = MEMORY;         -- temp tables in memory
```

**On close:**
```sql
PRAGMA analysis_limit = 400;        -- limit optimize scan
PRAGMA optimize;                    -- gather query planner statistics
```

**Read-only connections additionally:**
```sql
PRAGMA query_only = ON;             -- prevent accidental writes
```

### WAL Checkpoint Strategy

- Automatic PASSIVE checkpointing during normal operation (SQLite default)
- Explicit TRUNCATE checkpoint after scans (resets WAL file size)
- Emergency checkpoint if WAL exceeds 100MB
- `wal_autocheckpoint` set to 1000 pages (default, ~4MB)

### Decision: Write-serialized + read-pooled with the pragma set above

---

## Key Decision: STRICT Tables

SQLite 3.37+ (2021) supports the `STRICT` keyword on table creation. This enforces type checking — a TEXT column rejects INTEGER values and vice versa.

From the pragma cheatsheet: without STRICT, SQLite uses "type affinity" which silently coerces types. This is dangerous for a system like Drift where data integrity matters.

```sql
CREATE TABLE patterns (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    category TEXT NOT NULL CHECK(category IN ('api','auth','components',...)),
    status TEXT NOT NULL CHECK(status IN ('discovered','approved','ignored')),
    confidence_alpha REAL NOT NULL DEFAULT 1.0,
    confidence_beta REAL NOT NULL DEFAULT 1.0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;
```

For JSON columns, use `TEXT` with `CHECK(json_valid(column))`:

```sql
CREATE TABLE pattern_locations (
    pattern_id TEXT NOT NULL REFERENCES patterns(id),
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    column_num INTEGER NOT NULL,
    metadata TEXT CHECK(json_valid(metadata)),
    PRIMARY KEY (pattern_id, file, line)
) STRICT;
```

### Decision: All tables use STRICT. JSON columns use TEXT + json_valid CHECK.

---

## Key Decision: Schema Migration

### rusqlite_migration

The [`rusqlite_migration`](https://lib.rs/crates/rusqlite_migration) crate is purpose-built for this:
- Uses `PRAGMA user_version` (integer at fixed offset in SQLite file — no migration table needed)
- Migrations defined as `const` SQL strings via `include_str!()`
- Forward-only (no down migrations — simpler, safer)
- Fast: checking migration state is a single integer read, not a table query

```rust
use rusqlite_migration::{Migrations, M};

static MIGRATIONS: Migrations = Migrations::new(vec![
    M::up(include_str!("migrations/001_initial.sql")),
    M::up(include_str!("migrations/002_add_call_graph.sql")),
    M::up(include_str!("migrations/003_add_constraints.sql")),
    // ...
]);

// On startup:
MIGRATIONS.to_latest(&mut conn)?;
```

Rules:
- Never remove a migration
- Never modify an existing migration
- Auto-backup before migration via SQLite Backup API
- CI test that migrations apply cleanly to an empty database

### Decision: rusqlite_migration with user_version tracking

---

## Key Decision: Batch Writer Pattern

### The Problem

During a scan, thousands of patterns/functions/edges need to be written. Individual INSERT statements are slow due to transaction overhead.

### The Solution: Batched Writes via Crossbeam Channel

```rust
use crossbeam_channel::{bounded, Sender, Receiver};

struct BatchWriter {
    tx: Sender<WriteOp>,
    handle: JoinHandle<WriteStats>,
}

impl BatchWriter {
    fn new(conn: Connection, batch_size: usize) -> Self {
        let (tx, rx) = bounded(1024);  // backpressure at 1024 pending ops
        
        let handle = std::thread::spawn(move || {
            let mut batch = Vec::with_capacity(batch_size);
            let mut stats = WriteStats::default();
            
            loop {
                match rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(op) => {
                        batch.push(op);
                        if batch.len() >= batch_size {
                            flush_batch(&conn, &mut batch, &mut stats);
                        }
                    }
                    Err(RecvTimeoutError::Timeout) => {
                        if !batch.is_empty() {
                            flush_batch(&conn, &mut batch, &mut stats);
                        }
                    }
                    Err(RecvTimeoutError::Disconnected) => {
                        flush_batch(&conn, &mut batch, &mut stats);
                        break;
                    }
                }
            }
            stats
        });
        
        BatchWriter { tx, handle }
    }
}

fn flush_batch(conn: &Connection, batch: &mut Vec<WriteOp>, stats: &mut WriteStats) {
    conn.execute_batch("BEGIN IMMEDIATE").unwrap();
    for op in batch.drain(..) {
        // execute prepared statement
    }
    conn.execute_batch("COMMIT").unwrap();
    stats.batches_written += 1;
}
```

Key design choices:
- `bounded(1024)` channel provides backpressure — producers slow down if writer can't keep up
- `BEGIN IMMEDIATE` prevents SQLITE_BUSY on write transactions
- Batch size of 500 (from audit) balances throughput vs memory
- Dedicated writer thread — no contention with rayon workers
- Returns `WriteStats` for telemetry

This pattern is generalized from the call graph builder to all domains (patterns, functions, boundaries, etc.).

### Decision: Crossbeam bounded channel + dedicated writer thread + batched transactions

---

## Key Decision: Medallion Architecture (Bronze/Silver/Gold)

From audit A25, this is the data flow architecture:

### Bronze Layer (Staging)
- Ephemeral staging tables cleared at scan start
- Write-optimized, minimal indexes
- May be implicit in v2 — detectors can write directly to Silver if no staging needed

### Silver Layer (Normalized Analysis)
- Schema-enforced (STRICT + CHECK), foreign keys, referential integrity
- Standard B-tree indexes
- Source of truth — Gold can always be rebuilt from Silver
- Tables: `patterns`, `pattern_locations`, `functions`, `call_edges`, `data_access`, `sensitive_fields`, `contracts`, `constraints`, `env_variables`, `file_metadata`

### Gold Layer (Pre-computed Consumption)
- Refreshed explicitly after scans (not during)
- Covering indexes, partial indexes, materialized tables
- Read-only from consumer perspective
- Tables: `materialized_status`, `materialized_security`, `health_trends`

### Data Flow

```
Scan Pipeline (write path):
  Detectors/Parsers → writer() → Silver tables → refresh_read_model() → Gold tables
  Uses BEGIN IMMEDIATE transactions

Query Path (read path):
  MCP/CLI → reader() → Gold tables (materialized) + Silver tables (indexed)
  Read connections use PRAGMA query_only = ON

Refresh Path (post-scan):
  refresh_read_model() → rebuilds materialized_status, materialized_security
  Acquires write connection (INSERT/REPLACE into Gold tables)
```

### Decision: Implement Medallion architecture. Silver is source of truth. Gold is rebuilt after each scan.

---

## Key Decision: Keyset Pagination

All list queries should use keyset pagination (not OFFSET/LIMIT):

```sql
-- First page
SELECT * FROM patterns
ORDER BY confidence DESC, id ASC
LIMIT 50;

-- Next page (using last row's values as cursor)
SELECT * FROM patterns
WHERE (confidence, id) < (:last_confidence, :last_id)
ORDER BY confidence DESC, id ASC
LIMIT 50;
```

Advantages over OFFSET:
- Constant time regardless of page depth (OFFSET scans and discards rows)
- Stable results even when data changes between pages
- Composable with any sort order

Cursors are Base64-encoded `(sort_column, id)` tuples, opaque to consumers.

### Decision: Keyset pagination for all list operations

---

## Key Decision: Hot Backup

Use SQLite's Backup API via `rusqlite::backup::Backup`:

```rust
use rusqlite::backup;

fn backup_database(src: &Connection, dst_path: &Path) -> Result<()> {
    let mut dst = Connection::open(dst_path)?;
    let backup = backup::Backup::new(src, &mut dst)?;
    
    // Chunked transfer: 1000 pages at a time, 10ms sleep between chunks
    // This allows concurrent reads to continue during backup
    backup.run_to_completion(1000, Duration::from_millis(10), None)?;
    
    // Verify integrity
    let result: String = dst.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
    assert_eq!(result, "ok");
    
    Ok(())
}
```

Triggers:
- Before schema migrations
- Before destructive operations (`drift reset`)
- On user request (`drift backup`)
- Tiered retention: max 5 operational, 7 daily, 4 weekly

### Decision: SQLite Backup API with chunked transfer and integrity verification

---

## Key Decision: ATTACH for Cross-DB Queries (per D6)

When Cortex is present, drift.db can ATTACH cortex.db for read-only cross-queries:

```sql
ATTACH DATABASE '/path/to/cortex.db' AS cortex;

-- Cross-DB query example: patterns with linked memories
SELECT p.*, m.content
FROM patterns p
LEFT JOIN cortex.memories m ON m.entity_id = p.id
WHERE p.status = 'approved';
```

Key rules (from PLANNING-DRIFT.md D6):
- ATTACH is ~1ms, done once at startup
- Cross-DB reads are same speed as same-DB reads (SQLite treats attached DBs as additional schemas)
- Writes always go to the owning database only
- Drift connections do NOT load sqlite-vec (Cortex's vector extension)
- Graceful degradation: if cortex.db doesn't exist, ATTACH fails silently and cross-DB queries return empty results

### Decision: Optional ATTACH at startup, read-only, graceful degradation

---

## Key Decision: Process-Level Locking

From audit A22: use `fd-lock` crate for cross-platform advisory locks.

```rust
use fd_lock::RwLock;

// Shared read lock (MCP queries, CLI reads, backup) — concurrent OK
let lock = RwLock::new(File::open("drift.db.lock")?);
let _guard = lock.read()?;

// Exclusive write lock (scan, migrate, reset) — blocks others
let _guard = lock.write()?;
```

RAII-based release — auto-released on process exit, even on crash.

### Decision: fd-lock for cross-process advisory locking

---

## Summary of Decisions

| Decision | Choice | Confidence |
|----------|--------|------------|
| SQLite binding | rusqlite with `bundled` feature | Very High |
| Connection model | Write-serialized + read-pooled | Very High |
| Table mode | STRICT on all tables | High |
| Migration | rusqlite_migration + user_version | High |
| Batch writes | Crossbeam bounded channel + dedicated writer thread | High |
| Data architecture | Medallion (Bronze/Silver/Gold) with CQRS | High |
| Pagination | Keyset (not OFFSET) | High |
| Backup | SQLite Backup API, chunked, with integrity check | High |
| Cross-DB | Optional ATTACH cortex.db, read-only | High (per D6) |
| Process locking | fd-lock advisory locks | High |
