# Storage (drift.db) — V2 Implementation Prep

> Comprehensive build specification for Drift v2's storage layer.
> Synthesized from: 02-STORAGE.md, DRIFT-V2-FULL-SYSTEM-AUDIT.md (A25),
> .research/08-storage/RECOMMENDATIONS.md (29 recs), .research/08-storage/RESEARCH.md,
> PLANNING-DRIFT.md (D6), DRIFT-V2-STACK-HIERARCHY.md, Cortex's cortex-storage implementation,
> and current internet research on SQLite best practices.
>
> This is the single reference document for building drift.db from scratch.
> Generated: 2026-02-07

---

## 1. Architectural Position

drift.db is Level 0 Bedrock. Every system in Drift reads from or writes to it. Per PLANNING-DRIFT.md D6, drift.db is fully self-contained — ATTACH cortex.db is an optional read-only overlay that never appears on the critical path.

The storage layer replaces v1's entire Data Lake (~4,870 lines of TypeScript across 10 stores) with ~800 lines of Rust: a refresh pipeline, query functions, and reconciliation checks.

### What Lives Here
- 40+ STRICT tables organized by domain
- Medallion architecture (Bronze/Silver/Gold layers)
- CQRS read/write separation
- Batch writer with crossbeam backpressure
- Keyset pagination for all list operations
- Hot backup via SQLite Backup API
- Process-level locking via fd-lock
- Schema migration via rusqlite_migration + user_version
- Optional ATTACH cortex.db for bridge queries

### What Does NOT Live Here
- cortex.db (owned by Cortex, separate lifecycle)
- sqlite-vec extension (Cortex only — Drift connections never load it)
- Any JSON shard files, data lake files, or hybrid stores (v1 eliminated)

---

## 2. Core Library: rusqlite with `bundled` Feature

**Crate**: `rusqlite` v0.32+ with `bundled` feature flag.

The `bundled` feature compiles SQLite from source, guaranteeing:
- Consistent SQLite version across all 7 NAPI platform targets
- STRICT table support (requires SQLite 3.37+, 2021)
- JSONB support (requires SQLite 3.45+, 2024) — binary JSON storage that avoids reparsing
- JSON functions built-in by default (SQLite 3.38+)
- Generated columns support
- FTS5 for future full-text search needs

This is the same approach used by Cargo (Rust's package manager), Firefox, and the existing Cortex storage layer in this repo.

```toml
[dependencies]
rusqlite = { version = "0.32", features = ["bundled", "backup", "blob"] }
```

---

## 3. Connection Architecture: Write-Serialized + Read-Pooled

### The Pattern

Cortex already implements this pattern in `crates/cortex/cortex-storage/src/pool/`. Drift follows the same architecture with one key difference: Drift uses `std::sync::Mutex` (not `tokio::sync::Mutex`) because Drift's Rust core is synchronous (rayon-based parallelism, not async).

```rust
pub struct DatabaseManager {
    writer: Mutex<Connection>,           // Single write connection, serialized
    readers: ReadPool,                   // N read connections, round-robin
    path: PathBuf,
    config: DatabaseConfig,
}

pub struct DatabaseConfig {
    pub read_pool_size: usize,           // Default: num_cpus::get().min(8)
    pub cache_size_kb: i64,              // Default: 64000 (64MB)
    pub mmap_size: i64,                  // Default: 268435456 (256MB)
    pub busy_timeout_ms: u32,            // Default: 5000
    pub wal_autocheckpoint: u32,         // Default: 1000 pages (~4MB)
}

pub struct ReadPool {
    connections: Vec<Mutex<Connection>>,
    next: AtomicUsize,                   // Round-robin index
}
```

### Why This Works

SQLite WAL mode allows concurrent readers with a single writer. Readers never block each other, the writer never blocks readers, and readers never block the writer. This is validated by [SQLite's official WAL documentation](https://www.sqlite.org/wal.html) and is the same pattern used by Django's SQLite backend, Litestream, and the `sqlite-rwc` crate.

Application-level write serialization via `Mutex<Connection>` is more predictable than relying on SQLite's internal busy handler (which uses a sleep-retry loop). Read connections opened with `SQLITE_OPEN_READ_ONLY | SQLITE_OPEN_NO_MUTEX` flags prevent accidental writes and avoid unnecessary internal locking.

### Connection Pragmas

Applied to every connection on open (matching Cortex's `apply_pragmas`):

```sql
PRAGMA journal_mode = WAL;          -- Concurrent readers + writer
PRAGMA synchronous = NORMAL;        -- Safe with WAL, much faster than FULL
PRAGMA foreign_keys = ON;           -- Enforce referential integrity
PRAGMA cache_size = -64000;         -- 64MB page cache per connection
PRAGMA mmap_size = 268435456;       -- 256MB memory-mapped I/O
PRAGMA busy_timeout = 5000;         -- 5s retry on SQLITE_BUSY
PRAGMA temp_store = MEMORY;         -- Temp tables in memory
PRAGMA auto_vacuum = INCREMENTAL;   -- Enable incremental vacuum
```

Applied on connection close:

```sql
PRAGMA analysis_limit = 400;        -- Limit optimize scan
PRAGMA optimize;                    -- Gather query planner statistics
```

Read-only connections additionally:

```sql
PRAGMA query_only = ON;             -- Prevent accidental writes
```

Source: [SQLite Pragma Cheatsheet](https://cj.rs/blog/sqlite-pragma-cheatsheet-for-performance-and-consistency/) by the rusqlite_migration author.

### WAL Checkpoint Strategy

Three tiers:
1. **Automatic PASSIVE** — SQLite default, `wal_autocheckpoint=1000` pages (~4MB). Runs transparently during normal operation.
2. **Explicit TRUNCATE** — Called after scan completion. Resets WAL file to zero bytes, reclaiming disk space.
3. **Emergency** — If WAL exceeds 100MB (safety net for runaway writes), force a TRUNCATE checkpoint.

```rust
impl DatabaseManager {
    pub fn post_scan_checkpoint(&self) -> Result<CheckpointResult, StorageError> {
        let writer = self.writer.lock().map_err(|_| StorageError::LockPoisoned)?;
        let (log_frames, checkpointed): (i32, i32) = writer.query_row(
            "PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            }
        )?;
        Ok(CheckpointResult { log_frames, checkpointed })
    }
}
```

---

## 4. Schema Migration: rusqlite_migration + user_version

**Crate**: `rusqlite_migration`

Uses `PRAGMA user_version` (an integer at a fixed offset in the SQLite file header) instead of a migration tracking table. This is faster than table-based tracking because it requires no SQL parsing — just a single integer read.

This is the same approach used by Cargo and Mozilla Application Services.

```rust
use rusqlite_migration::{Migrations, M};

static MIGRATIONS: Migrations<'static> = Migrations::new(vec![
    M::up(include_str!("../sql/001_initial_schema.sql")),
    M::up(include_str!("../sql/002_call_graph.sql")),
    M::up(include_str!("../sql/003_constraints.sql")),
    M::up(include_str!("../sql/004_test_topology.sql")),
    M::up(include_str!("../sql/005_error_handling.sql")),
    M::up(include_str!("../sql/006_dna.sql")),
    M::up(include_str!("../sql/007_materialized_views.sql")),
    M::up(include_str!("../sql/008_audit.sql")),
    // Future migrations appended here — NEVER remove or reorder
]);

pub fn initialize(conn: &mut Connection) -> Result<(), StorageError> {
    MIGRATIONS.to_latest(conn).map_err(|e| StorageError::MigrationFailed {
        version: 0,
        message: e.to_string(),
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn migrations_are_valid() {
        assert!(super::MIGRATIONS.validate().is_ok());
    }
}
```

### Migration Rules
1. Never remove a migration entry from the list
2. Never modify an existing migration's SQL
3. Store SQL in separate `.sql` files via `include_str!()` for readability
4. Auto-backup before applying migrations (SQLite Backup API)
5. CI test that migrations apply cleanly to an empty database
6. Forward-only — no down migrations (simpler, safer)

---

## 5. STRICT Tables + JSONB

### STRICT Mode

All v2 tables use the `STRICT` keyword (SQLite 3.37+). This enforces column types at insert time, preventing SQLite's default type affinity behavior where a TEXT value silently coerces into an INTEGER column.

```sql
CREATE TABLE patterns (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    category TEXT NOT NULL CHECK(category IN (
        'api','auth','components','config','contracts','data-access',
        'documentation','errors','logging','performance','security',
        'structural','styling','testing','types','accessibility'
    )),
    status TEXT NOT NULL CHECK(status IN ('discovered','approved','ignored')),
    confidence_alpha REAL NOT NULL DEFAULT 1.0,
    confidence_beta REAL NOT NULL DEFAULT 1.0,
    confidence_score REAL NOT NULL DEFAULT 0.0,
    location_count INTEGER NOT NULL DEFAULT 0,
    outlier_count INTEGER NOT NULL DEFAULT 0,
    severity TEXT NOT NULL DEFAULT 'info' CHECK(severity IN ('error','warning','info','hint')),
    hash TEXT,
    parent_id TEXT REFERENCES patterns(id),
    decay_rate REAL,
    first_seen TEXT NOT NULL DEFAULT (datetime('now')),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    -- Generated columns for indexed derived fields
    confidence_level TEXT GENERATED ALWAYS AS (
        CASE
            WHEN confidence_score >= 0.85 THEN 'high'
            WHEN confidence_score >= 0.70 THEN 'medium'
            WHEN confidence_score >= 0.50 THEN 'low'
            ELSE 'uncertain'
        END
    ) VIRTUAL,
    is_actionable INTEGER GENERATED ALWAYS AS (
        CASE WHEN status = 'approved' AND confidence_score >= 0.70 THEN 1 ELSE 0 END
    ) VIRTUAL
) STRICT;
```

### JSON Columns: TEXT + json_valid or JSONB

SQLite 3.45+ introduced JSONB — a binary JSON format that avoids reparsing on every `json_extract()` call. Since we use `bundled` rusqlite (compiling SQLite from source), we get JSONB support.

For columns that are frequently queried via `json_extract()`, store as JSONB using the `jsonb()` function at insert time:

```sql
-- Insert with JSONB conversion
INSERT INTO patterns (id, tags) VALUES ('abc', jsonb('["api","rest","express"]'));

-- Query works identically — json_extract handles both TEXT and JSONB
SELECT * FROM patterns WHERE json_extract(tags, '$[0]') = 'api';
```

For columns that are rarely queried (just stored and returned whole), plain TEXT with `CHECK(json_valid(column))` is sufficient:

```sql
CREATE TABLE pattern_locations (
    pattern_id TEXT NOT NULL REFERENCES patterns(id),
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    column_num INTEGER NOT NULL,
    end_line INTEGER,
    end_column INTEGER,
    snippet TEXT,
    deviation_score REAL,
    metadata TEXT CHECK(metadata IS NULL OR json_valid(metadata)),
    PRIMARY KEY (pattern_id, file, line)
) STRICT;
```

### When to Normalize vs Keep as JSON

| Keep as JSON/JSONB | Normalize into separate table |
|---|---|
| Data always read/written as a unit (tags, decorators, parameters) | Data frequently filtered/sorted individually |
| Rarely appears in WHERE clauses | Appears in WHERE, ORDER BY, or JOIN |
| Variable schema across rows | Consistent schema |

Specific normalization: `pattern_tags` junction table for multi-tag filtering (dual storage: JSON column for full retrieval, junction table for indexed queries).

---

## 6. Medallion Architecture (Bronze/Silver/Gold)

From audit A25. This is the data flow architecture that replaces v1's Data Lake.

### Bronze Layer (Staging)
- Ephemeral staging tables cleared at scan start
- Write-optimized, minimal indexes
- May be implicit in v2 — detectors can write directly to Silver if no staging needed
- Tables: `scan_results` (temporary), `raw_pattern_matches` (append-only during detection)

### Silver Layer (Normalized Analysis) — Source of Truth
- Schema-enforced (STRICT + CHECK), foreign keys, referential integrity
- Standard B-tree indexes
- Gold can always be rebuilt from Silver
- Core tables:

| Domain | Tables |
|--------|--------|
| Patterns | `patterns`, `pattern_locations`, `pattern_variants`, `pattern_examples`, `pattern_history`, `pattern_tags`, `pattern_suppressions` |
| Call Graph | `functions`, `call_edges`, `data_access` |
| Security | `boundaries`, `sensitive_fields`, `boundary_rules` |
| Contracts | `contracts`, `contract_endpoints`, `contract_schemas`, `contract_mismatches` |
| Constraints | `constraints`, `constraint_violations` |
| Test Topology | `test_files`, `test_cases`, `test_coverage`, `mock_statements`, `test_smells`, `uncovered_functions` |
| DNA | `dna_profiles`, `dna_genes`, `dna_comparisons` |
| Error Handling | `error_boundaries`, `error_gaps`, `error_types` |
| Audit | `audit_snapshots`, `audit_health`, `audit_degradation` |
| Environment | `env_vars`, `env_files` |
| Constants | `constants`, `magic_numbers` |
| Coupling | `module_coupling`, `coupling_metrics` |
| Learning | `learned_conventions` |
| Quality Gates | `gate_snapshots`, `gate_runs`, `violation_feedback` |
| Infrastructure | `file_metadata`, `scan_history`, `packages`, `feature_flags`, `cache_entries`, `parse_cache` |

### Gold Layer (Pre-computed Consumption)
- Refreshed explicitly after scans (not during)
- Covering indexes, partial indexes, materialized tables
- Read-only from consumer perspective
- Tables: `materialized_status`, `materialized_security`, `health_trends`
- Covering indexes on Silver tables, generated columns

### Data Flow (CQRS)

```
Write Path (drift scan):
  Detectors/Parsers → BatchWriter → Silver tables → refresh_read_model() → Gold tables
  Uses BEGIN IMMEDIATE transactions via writer connection

Read Path (MCP/CLI):
  Consumer → ReadPool → Gold tables (materialized) + Silver tables (indexed)
  Read connections use PRAGMA query_only = ON

Refresh Path (post-scan):
  refresh_read_model() → rebuilds materialized_status, materialized_security
  → appends health_trends → reconciles counter caches
  Acquires writer connection (INSERT/REPLACE into Gold tables)
  Entire refresh in single BEGIN IMMEDIATE transaction
```


---

## 7. Batch Writer: Crossbeam Channel + Dedicated Writer Thread

### The Problem

During a scan, thousands of patterns/functions/edges need to be written. Individual INSERT statements are slow due to per-statement transaction overhead. SQLite can do ~100K inserts/second in a single transaction but only ~50 inserts/second with auto-commit.

### The Solution

Generalize the call graph builder's parallel writer pattern to all domains. Use `crossbeam-channel` (not `std::mpsc`) for better throughput under contention.

```rust
use crossbeam_channel::{bounded, Sender, Receiver};

pub enum WriteBatch {
    Patterns(Vec<PatternRow>),
    Functions(Vec<FunctionRow>),
    CallEdges(Vec<CallEdgeRow>),
    Locations(Vec<LocationRow>),
    Boundaries(Vec<BoundaryRow>),
    FileMetadata(Vec<FileMetadataRow>),
    Flush,
    Shutdown,
}

pub struct BatchWriter {
    tx: Sender<WriteBatch>,
    handle: Option<JoinHandle<Result<WriteStats, StorageError>>>,
}

impl BatchWriter {
    pub fn new(conn: Connection, batch_size: usize) -> Self {
        let (tx, rx) = bounded(1024); // Backpressure at 1024 pending ops

        let handle = std::thread::spawn(move || {
            let mut buffer = Vec::with_capacity(batch_size);
            let mut stats = WriteStats::default();

            loop {
                match rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(WriteBatch::Shutdown) => {
                        flush_buffer(&conn, &mut buffer, &mut stats)?;
                        break;
                    }
                    Ok(WriteBatch::Flush) => {
                        flush_buffer(&conn, &mut buffer, &mut stats)?;
                    }
                    Ok(batch) => {
                        buffer.push(batch);
                        if buffer.len() >= batch_size {
                            flush_buffer(&conn, &mut buffer, &mut stats)?;
                        }
                    }
                    Err(RecvTimeoutError::Timeout) => {
                        if !buffer.is_empty() {
                            flush_buffer(&conn, &mut buffer, &mut stats)?;
                        }
                    }
                    Err(RecvTimeoutError::Disconnected) => {
                        flush_buffer(&conn, &mut buffer, &mut stats)?;
                        break;
                    }
                }
            }
            Ok(stats)
        });

        Self { tx, handle: Some(handle) }
    }
}

fn flush_buffer(
    conn: &Connection,
    buffer: &mut Vec<WriteBatch>,
    stats: &mut WriteStats,
) -> Result<(), StorageError> {
    let tx = conn.transaction_with_behavior(
        rusqlite::TransactionBehavior::Immediate
    )?;
    for batch in buffer.drain(..) {
        match batch {
            WriteBatch::Patterns(rows) => {
                let mut stmt = tx.prepare_cached(
                    "INSERT OR REPLACE INTO patterns (id, name, category, ...) VALUES (?, ?, ?, ...)"
                )?;
                for row in &rows {
                    stmt.execute(params![row.id, row.name, row.category, ...])?;
                }
                stats.patterns += rows.len();
            }
            WriteBatch::Functions(rows) => {
                stats.functions += insert_functions(&tx, &rows)?;
            }
            // ... other domains
            _ => {}
        }
    }
    tx.commit()?;
    stats.flushes += 1;
    Ok(())
}
```

### Key Design Choices

| Choice | Rationale |
|--------|-----------|
| `bounded(1024)` channel | Backpressure — rayon workers slow down if writer can't keep up. Prevents OOM. |
| `BEGIN IMMEDIATE` | Acquires write lock at transaction start, preventing SQLITE_BUSY from concurrent readers. Source: [Gotchas with SQLite in Production](https://blog.pecar.me/sqlite-prod) |
| Batch size 500 | Balances throughput vs memory. 500 rows per transaction is ~20KB for patterns, well within page cache. |
| Dedicated writer thread | No contention with rayon workers. Writer runs on its own core. |
| `crossbeam-channel` | Proven faster than `std::mpsc` for high-throughput scenarios. Source: [Rust Users Forum benchmarks](https://users.rust-lang.org/t/poor-performance-of-sending-items-over-an-mpsc-channel/50559) |
| `prepare_cached()` | Reuses compiled SQL statements across batches. Built into rusqlite. |
| `recv_timeout(100ms)` | Flushes partial batches if producers pause. Prevents data sitting in buffer. |

### WriteStats for Telemetry

```rust
#[derive(Default)]
pub struct WriteStats {
    pub patterns: usize,
    pub functions: usize,
    pub call_edges: usize,
    pub locations: usize,
    pub boundaries: usize,
    pub file_metadata: usize,
    pub flushes: usize,
    pub total_duration: Duration,
}
```

Returned when the writer thread completes. Fed into tracing spans for observability (per AD10).

---

## 8. Gold Layer: Materialized Tables

SQLite doesn't support true materialized views. Instead, build "materialized tables" — regular tables populated by explicit refresh calls after scans.

### materialized_status (Singleton)

The most-queried table in the system. Every `drift_status` MCP call and every `drift status` CLI invocation reads this single row. Must be <1ms.

```sql
CREATE TABLE materialized_status (
    id INTEGER PRIMARY KEY CHECK (id = 1),  -- Singleton row
    health_score REAL NOT NULL,
    health_trend TEXT NOT NULL CHECK(health_trend IN ('improving','stable','declining')),
    total_patterns INTEGER NOT NULL,
    approved_patterns INTEGER NOT NULL,
    discovered_patterns INTEGER NOT NULL,
    ignored_patterns INTEGER NOT NULL,
    category_counts TEXT NOT NULL,           -- JSONB: {"api": 12, "auth": 5, ...}
    critical_issues INTEGER NOT NULL,
    warning_issues INTEGER NOT NULL,
    top_issues TEXT,                         -- JSONB array
    security_risk_level TEXT NOT NULL,
    security_violations INTEGER NOT NULL,
    sensitive_exposures INTEGER NOT NULL,
    last_scan_at TEXT,
    last_scan_duration_ms INTEGER,
    last_scan_files INTEGER,
    last_scan_patterns INTEGER,
    last_scan_incremental INTEGER,
    last_scan_changed_files INTEGER,
    refreshed_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;
```

### materialized_security (Singleton)

```sql
CREATE TABLE materialized_security (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    risk_level TEXT NOT NULL CHECK(risk_level IN ('low','medium','high','critical')),
    overall_risk_score REAL NOT NULL,
    total_tables INTEGER NOT NULL,
    total_access_points INTEGER NOT NULL,
    sensitive_fields INTEGER NOT NULL,
    violations INTEGER NOT NULL,
    unprotected_access_points INTEGER NOT NULL,
    raw_sql_access_points INTEGER NOT NULL,
    sensitivity_breakdown TEXT NOT NULL,     -- JSONB
    violation_breakdown TEXT NOT NULL,       -- JSONB
    top_risk_tables TEXT NOT NULL,           -- JSONB array
    top_violations TEXT NOT NULL,            -- JSONB array
    refreshed_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;
```

### health_trends (Append-Only Gold)

```sql
CREATE TABLE health_trends (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recorded_at TEXT NOT NULL DEFAULT (datetime('now')),
    scan_id TEXT,
    health_score REAL NOT NULL,
    total_patterns INTEGER NOT NULL,
    approved_patterns INTEGER NOT NULL,
    security_risk_level TEXT,
    security_violations INTEGER,
    total_functions INTEGER,
    total_call_edges INTEGER,
    entry_points INTEGER,
    contracts_verified INTEGER,
    contracts_mismatched INTEGER,
    trend TEXT NOT NULL CHECK(trend IN ('improving','stable','declining'))
) STRICT;

CREATE INDEX idx_health_trends_time ON health_trends(recorded_at DESC);
CREATE INDEX idx_health_trends_scan ON health_trends(scan_id);
```

### Refresh Pipeline

```rust
pub struct RefreshPipeline;

impl RefreshPipeline {
    /// Full refresh after scan completion. Order matters.
    pub fn refresh_all(conn: &Connection) -> Result<RefreshReport, StorageError> {
        let tx = conn.transaction_with_behavior(
            rusqlite::TransactionBehavior::Immediate
        )?;
        let mut report = RefreshReport::default();

        // 1. Security first (status reads security_risk_level)
        report.security = Self::refresh_materialized_security(&tx)?;

        // 2. Status (aggregates everything including security)
        report.status = Self::refresh_materialized_status(&tx)?;

        // 3. Append health trend
        report.trend = Self::append_health_trend(&tx)?;

        // 4. Reconcile counter caches
        report.counters = Self::reconcile_counter_caches(&tx)?;

        tx.commit()?;
        Ok(report)
    }

    /// Selective refresh for incremental scans.
    /// Only refreshes domains that changed.
    pub fn refresh_selective(
        conn: &Connection,
        changed_domains: &[Domain],
    ) -> Result<RefreshReport, StorageError> {
        // If no domains changed, skip refresh entirely
        if changed_domains.is_empty() {
            return Ok(RefreshReport::skipped());
        }
        // Always refresh status (aggregates everything)
        // Only refresh security if security-related domains changed
        // ...
    }
}
```

Health trend uses ±0.02 threshold to classify trend direction, avoiding noise from minor fluctuations.

---

## 9. Index Strategy

### Covering Indexes (IX1)

Replace v1's PatternIndexView. The covering index contains all columns needed for pattern listing, so the query planner never touches the patterns table:

```sql
CREATE INDEX idx_patterns_covering ON patterns(
    category, status, confidence_score DESC,
    id, name, severity, location_count, outlier_count
);
```

Visible in `EXPLAIN QUERY PLAN` as `USING COVERING INDEX`. ~50-100 bytes per pattern overhead.

### Partial Indexes (IX2)

3-10x smaller and faster indexes for frequently queried subsets:

```sql
-- Approved patterns only (~10-30% of all patterns)
CREATE INDEX idx_approved_patterns
    ON patterns(category, confidence_score DESC)
    WHERE status = 'approved';

-- Entry points only (<5% of functions)
CREATE INDEX idx_entry_points
    ON functions(file, name, return_type)
    WHERE is_entry_point = 1;

-- High confidence patterns
CREATE INDEX idx_high_confidence
    ON patterns(category, status)
    WHERE confidence_score >= 0.85;

-- Sensitive fields by type
CREATE INDEX idx_sensitive_pii
    ON sensitive_fields(table_name, field_name)
    WHERE sensitivity = 'PII';

CREATE INDEX idx_sensitive_credentials
    ON sensitive_fields(table_name, field_name)
    WHERE sensitivity = 'credentials';

-- Active patterns (not ignored)
CREATE INDEX idx_active_patterns
    ON patterns(category, name)
    WHERE status != 'ignored';

-- Files with errors
CREATE INDEX idx_files_with_errors
    ON file_metadata(path)
    WHERE error IS NOT NULL;

-- Patterns with outliers
CREATE INDEX idx_patterns_with_outliers
    ON patterns(category, id)
    WHERE outlier_count > 0;
```

Query must include matching WHERE clause to use partial index.

### Expression Indexes on JSON (IX3)

```sql
-- Index for filtering patterns by first tag
CREATE INDEX idx_patterns_tags
    ON patterns(json_extract(tags, '$[0]'))
    WHERE tags IS NOT NULL;

-- Index for contract mismatch type filtering
CREATE INDEX idx_contracts_mismatch_type
    ON contracts(json_extract(mismatches, '$[0].type'))
    WHERE mismatches IS NOT NULL;
```

For multi-tag filtering, normalize into junction table:

```sql
CREATE TABLE pattern_tags (
    pattern_id TEXT NOT NULL REFERENCES patterns(id) ON DELETE CASCADE,
    tag TEXT NOT NULL,
    PRIMARY KEY (pattern_id, tag)
) STRICT;

CREATE INDEX idx_pattern_tags_tag ON pattern_tags(tag, pattern_id);
```

Dual storage: JSON column for full retrieval, junction table for indexed queries. Both updated in same transaction.

### Dimension-Replacement Indexes (IX4)

Replace v1's four JSON index files (~440 lines of IndexStore code):

```sql
-- Replaces FileIndex
CREATE INDEX idx_pattern_locations_file ON pattern_locations(file, pattern_id);

-- Replaces CategoryIndex
CREATE INDEX idx_patterns_category ON patterns(category, id);

-- Replaces TableIndex
CREATE INDEX idx_data_access_table ON data_access(table_name);
CREATE INDEX idx_data_access_function ON data_access(function_id);

-- Replaces EntryPointIndex (via recursive CTE for reachability)
CREATE INDEX idx_functions_entry ON functions(is_entry_point, id)
    WHERE is_entry_point = 1;
CREATE INDEX idx_call_edges_caller ON call_edges(caller_id);
CREATE INDEX idx_call_edges_callee ON call_edges(callee_id);
```


---

## 10. Keyset Pagination

All list queries use keyset (cursor-based) pagination, not OFFSET/LIMIT.

OFFSET degrades linearly with page depth — the database must scan and discard all rows before the offset. Keyset pagination achieves constant-time page retrieval regardless of position. Source: [Keyset Pagination Performance Analysis](https://openillumi.com/en/en-sqlite-limit-offset-slow-fix-seek-method/)

```rust
pub struct PaginationCursor {
    pub last_sort_value: String,     // e.g., confidence score
    pub last_id: String,             // Tiebreaker
}

pub struct PaginatedResult<T> {
    pub items: Vec<T>,
    pub total: u64,
    pub has_more: bool,
    pub next_cursor: Option<String>, // Base64-encoded PaginationCursor
}

fn query_patterns_paginated(
    conn: &Connection,
    filters: &PatternFilters,
    cursor: Option<&PaginationCursor>,
    limit: usize,
) -> Result<PaginatedResult<PatternRow>, StorageError> {
    let mut sql = String::from(
        "SELECT * FROM patterns WHERE 1=1"
    );
    let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

    if let Some(category) = &filters.category {
        sql.push_str(" AND category = ?");
        params.push(Box::new(category.clone()));
    }

    if let Some(cursor) = cursor {
        sql.push_str(" AND (confidence_score, id) < (?, ?)");
        params.push(Box::new(cursor.last_sort_value.clone()));
        params.push(Box::new(cursor.last_id.clone()));
    }

    sql.push_str(" ORDER BY confidence_score DESC, id ASC");
    sql.push_str(&format!(" LIMIT {}", limit + 1)); // +1 to detect has_more

    // Execute and build result...
}
```

Composite cursor `(sort_column, id)` handles ties in the sort column. The `id` column breaks ties deterministically. Cursors are Base64-encoded, opaque to consumers.

---

## 11. Incremental File Index

The `file_metadata` table is the foundation for O(changes) scanning instead of O(repository).

```sql
CREATE TABLE file_metadata (
    path TEXT PRIMARY KEY,
    language TEXT,
    size INTEGER NOT NULL,
    content_hash BLOB NOT NULL,         -- xxh3 hash (8 bytes)
    mtime_secs INTEGER NOT NULL,
    mtime_nanos INTEGER NOT NULL,
    last_scanned TEXT,
    scan_duration_us INTEGER,
    pattern_count INTEGER DEFAULT 0,    -- Counter cache
    function_count INTEGER DEFAULT 0,   -- Counter cache
    error_count INTEGER DEFAULT 0,
    error TEXT                          -- Last parse error, if any
) STRICT;

CREATE INDEX idx_file_metadata_language ON file_metadata(language);
CREATE INDEX idx_file_metadata_errors ON file_metadata(path) WHERE error IS NOT NULL;
CREATE INDEX idx_file_metadata_scanned ON file_metadata(last_scanned);
```

### Two-Level Change Detection

1. **Level 1: mtime comparison** — Instant. If mtime hasn't changed, skip. Catches ~95% of unchanged files.
2. **Level 2: content hash** — For files where mtime changed but content might not have (git operations, `touch`, IDE saves). Compare xxh3 hash against stored hash.

### Ownership-Based Invalidation (from audit A25 AD3)

Every derived fact (pattern location, function, call edge) is linked to the source file that produced it via `file_metadata`. When a file changes, only its owned facts are invalidated:

```
1. Walk filesystem → collect (path, mtime, size)
2. Compare against file_metadata:
   - mtime unchanged → SKIP (~95%)
   - mtime changed → compute xxh3 → hash unchanged → UPDATE mtime only
   - hash changed → MARK for re-scan
   - file not in table → NEW
   - file in table but not on disk → DELETED
3. For DELETED files: DELETE owned facts from pattern_locations, functions, call_edges, etc.
4. For re-scan files: DELETE owned facts, re-scan, INSERT new facts, UPDATE file_metadata
5. Refresh Gold layer only if any files changed
```

Counter caches (`pattern_count`, `function_count`) on `file_metadata` provide instant per-file stats without JOINs. Maintained by triggers on Silver tables (disabled during bulk scan, reconciled after).

---

## 12. Hot Backup via SQLite Backup API

Never copy database files directly — this risks creating an inconsistent backup, especially in WAL mode where the WAL and SHM files must be consistent with the main file. Source: [SQLite Online Backup API](https://sqlite.org/c3ref/backup_finish.html)

```rust
impl DatabaseManager {
    pub fn backup(&self, dest_path: &Path) -> Result<BackupResult, StorageError> {
        let start = Instant::now();
        let reader = self.readers.get_conn()?;
        let mut dest = Connection::open(dest_path)?;

        let backup = rusqlite::backup::Backup::new(&reader, &mut dest)?;

        // Chunked transfer: 1000 pages at a time, 10ms sleep between chunks
        // Allows concurrent reads to continue during backup
        backup.run_to_completion(1000, Duration::from_millis(10), None)?;

        // Verify integrity
        let result: String = dest.query_row(
            "PRAGMA integrity_check", [], |r| r.get(0)
        )?;
        if result != "ok" {
            return Err(StorageError::Corrupt {
                details: format!("Backup integrity check failed: {}", result),
            });
        }

        Ok(BackupResult {
            path: dest_path.to_path_buf(),
            size: std::fs::metadata(dest_path)?.len(),
            duration: start.elapsed(),
            verified: true,
        })
    }
}
```

### Backup Triggers
- Before schema migrations (automatic)
- Before destructive operations like `drift reset` (automatic)
- On user request via `drift backup` (manual)

### Retention Policy
- Max 5 operational backups (configurable)
- 7 daily, 4 weekly for enterprise
- Auto-delete oldest when limit exceeded
- Store in `.drift/backups/drift-{timestamp}-{reason}.db`

### Backup Reasons

```rust
pub enum BackupReason {
    VersionUpgrade,
    SchemaMigration,
    UserRequested,
    PreDestructiveOperation,
    Scheduled,
}
```

Each backup includes SHA-256 checksum for verification.

---

## 13. Process-Level Locking

**Crate**: `fd-lock`

Advisory cross-platform file locks using file descriptors. RAII-based — auto-released on process exit, even on crash. Source: [fd-lock crate](https://lib.rs/crates/fd-lock)

```rust
use fd_lock::RwLock;

pub struct ProcessLock {
    _lock: fd_lock::RwLockWriteGuard<'static, File>,
}

impl ProcessLock {
    /// Acquire exclusive scan lock. Returns Err if another scan is running.
    pub fn acquire_scan_lock(drift_dir: &Path) -> Result<Self, StorageError> {
        let lock_path = drift_dir.join("drift.db.lock");
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(&lock_path)?;

        let lock = RwLock::new(file);
        match lock.try_write() {
            Ok(guard) => {
                // Write PID and timestamp for diagnostics
                // ...
                Ok(Self { _lock: guard })
            }
            Err(_) => Err(StorageError::ConcurrentScan {
                message: "Another drift scan is already running".into(),
            }),
        }
    }
}
```

### Lock Semantics
- Read operations (MCP tools, CLI queries) do NOT acquire the lock — WAL mode handles read concurrency
- Only scan operations acquire the exclusive lock — prevents two scans from corrupting data
- Lock auto-released on process exit (even crash) via OS file lock semantics
- `--force` flag allows overriding the lock (for stuck processes)
- PID and timestamp in lock file enable diagnostics (`drift doctor` can detect stale locks)

---

## 14. ATTACH for Cross-DB Queries (per D6)

When Cortex is present, drift.db can ATTACH cortex.db for read-only cross-queries:

```rust
impl DatabaseManager {
    pub fn attach_cortex(&self, cortex_path: &Path) -> Result<(), StorageError> {
        // Only attach on read connections — never on writer
        for reader in &self.readers.connections {
            let conn = reader.lock()?;
            conn.execute(
                "ATTACH DATABASE ?1 AS cortex",
                rusqlite::params![cortex_path.to_str()],
            )?;
        }
        Ok(())
    }

    pub fn detach_cortex(&self) -> Result<(), StorageError> {
        for reader in &self.readers.connections {
            let conn = reader.lock()?;
            conn.execute("DETACH DATABASE cortex", [])?;
        }
        Ok(())
    }
}
```

### Rules (from PLANNING-DRIFT.md D6)
- ATTACH is ~1ms, done once at startup
- Cross-DB reads are same speed as same-DB reads (SQLite treats attached DBs as additional schemas)
- Writes always go to the owning database only
- Drift connections do NOT load sqlite-vec (Cortex's vector extension)
- Graceful degradation: if cortex.db doesn't exist, ATTACH fails silently and cross-DB queries return empty results
- Cross-DB queries are a presentation-layer concern (bridge MCP tools), not an analysis-layer concern

---

## 15. Error Handling

Per AD6: structured error types from the first line of code.

```rust
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("Database busy (another process is writing). Retrying...")]
    Busy,

    #[error("Disk full. Run `drift doctor` to free space via retention policies and VACUUM.")]
    DiskFull,

    #[error("Database corrupt: {details}")]
    Corrupt { details: String },

    #[error("I/O error: {detail}")]
    IoError { detail: String },

    #[error("Database is read-only: {reason}")]
    ReadOnly { reason: String },

    #[error("Schema migration failed at version {version}: {message}")]
    MigrationFailed { version: u32, message: String },

    #[error("Another drift scan is already running: {message}")]
    ConcurrentScan { message: String },

    #[error("Lock poisoned")]
    LockPoisoned,

    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

impl DatabaseManager {
    fn handle_sqlite_error(&self, err: rusqlite::Error) -> StorageError {
        match &err {
            rusqlite::Error::SqliteFailure(e, msg) => match e.code {
                rusqlite::ErrorCode::DatabaseBusy => StorageError::Busy,
                rusqlite::ErrorCode::DiskFull => StorageError::DiskFull,
                rusqlite::ErrorCode::DatabaseCorrupt => StorageError::Corrupt {
                    details: msg.clone().unwrap_or_default(),
                },
                rusqlite::ErrorCode::ReadOnly => StorageError::ReadOnly {
                    reason: msg.clone().unwrap_or_default(),
                },
                _ => StorageError::Sqlite(err),
            },
            _ => StorageError::Sqlite(err),
        }
    }
}
```

### Auto-Restore on Corruption

When `SQLITE_CORRUPT` is detected:
1. Find most recent backup in `.drift/backups/`
2. Verify backup integrity via `PRAGMA integrity_check`
3. Restore from backup using Backup API in reverse
4. Log the auto-restore event
5. Notify user that data since last backup may be lost

---

## 16. Data Integrity Validation

Three validation levels, run at different times:

| Level | When | Duration | Checks |
|-------|------|----------|--------|
| Quick | Every database open | <1ms | Schema version + materialized table existence |
| Normal | After migrations | <100ms | Quick + `PRAGMA foreign_key_check` |
| Full | `drift doctor`, after crash | seconds | Normal + `PRAGMA integrity_check` + reconciliation |

### Reconciliation Checks (8 checks via `drift doctor`)

1. `location_count` counter cache vs actual `COUNT(*)`
2. `outlier_count` counter cache vs actual
3. `file_metadata.pattern_count` counter cache vs actual
4. `materialized_status` fields vs computed values from Silver
5. Orphaned `pattern_locations` without parent patterns
6. Foreign key integrity (`PRAGMA foreign_key_check`)
7. File metadata staleness (files on disk not in table)
8. `pattern_tags` junction table vs `patterns.tags` JSON column

`drift doctor --fix` auto-fixes inconsistencies. Also runs after database restore and schema migrations.

---

## 17. Operational Safety

### VACUUM Strategy

Conditional VACUUM based on freelist ratio:

```rust
impl DatabaseManager {
    pub fn maybe_vacuum(&self) -> Result<VacuumResult, StorageError> {
        let writer = self.writer.lock()?;
        let page_count: i64 = writer.pragma_query_value(None, "page_count", |r| r.get(0))?;
        let freelist_count: i64 = writer.pragma_query_value(None, "freelist_count", |r| r.get(0))?;
        let free_ratio = freelist_count as f64 / page_count.max(1) as f64;

        if free_ratio > 0.20 {
            // >20% free pages — VACUUM is worthwhile
            writer.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
            writer.execute_batch("VACUUM")?;
            Ok(VacuumResult { performed: true, pages_freed: freelist_count })
        } else {
            Ok(VacuumResult { performed: false, pages_freed: 0 })
        }
    }
}
```

Why not `auto_vacuum`: `auto_vacuum=INCREMENTAL` adds overhead to every COMMIT and does NOT defragment. Manual VACUUM after large deletes is more efficient. Source: [SQLite VACUUM documentation](https://sqlite.org/draft/matrix/lang_vacuum.html)

### Retention Policies

```rust
pub struct RetentionConfig {
    pub scan_history_max_entries: usize,      // Default: 100
    pub pattern_history_max_days: usize,      // Default: 365
    pub health_trends_max_days: usize,        // Default: 180
    pub health_trends_max_entries: usize,     // Default: 500
    pub audit_snapshots_max_entries: usize,   // Default: 50
    pub cache_entries_max_age_hours: usize,   // Default: 24
    pub backup_max_count: usize,             // Default: 5
}
```

Enforced after each scan completion, as part of the post-scan pipeline. Age-based + count-based pruning. `PRAGMA incremental_vacuum` after pruning.

### Cache Warming on Startup

Before accepting the first MCP request, execute lightweight warming queries:

1. `SELECT * FROM materialized_status WHERE id = 1`
2. `SELECT * FROM materialized_security WHERE id = 1`
3. Patterns covering index touch (`LIMIT 1` with ORDER BY matching IX1)
4. Functions entry point index touch
5. Recent health trends (`LIMIT 5`)

Total <10ms. Ensures page cache is hot for the most common queries.

---

## 18. NAPI Bridge for Storage

All storage operations exposed to TypeScript via typed NAPI bindings. Not raw SQL — high-level functions with structured inputs and outputs.

```rust
#[napi(object)]
pub struct PatternQueryOptions {
    pub category: Option<String>,
    pub status: Option<String>,
    pub min_confidence: Option<f64>,
    pub file: Option<String>,
    pub cursor: Option<String>,
    pub limit: Option<u32>,
}

#[napi]
pub struct DriftDatabase { /* ... */ }

#[napi]
impl DriftDatabase {
    #[napi(constructor)]
    pub fn new(path: String) -> napi::Result<Self> { /* ... */ }

    // Status (instant — reads materialized table)
    #[napi]
    pub fn get_status(&self) -> napi::Result<serde_json::Value> { /* ... */ }

    // Pattern queries (keyset paginated)
    #[napi]
    pub fn query_patterns(&self, opts: PatternQueryOptions) -> napi::Result<serde_json::Value> { /* ... */ }

    // Call graph queries
    #[napi]
    pub fn get_callers(&self, function_id: String, depth: u32) -> napi::Result<serde_json::Value> { /* ... */ }

    // Backup
    #[napi]
    pub fn backup(&self, dest: String) -> napi::Result<serde_json::Value> { /* ... */ }

    // Integrity check
    #[napi]
    pub fn validate_integrity(&self) -> napi::Result<serde_json::Value> { /* ... */ }

    // Raw query (escape hatch)
    #[napi]
    pub fn execute_raw(&self, sql: String) -> napi::Result<serde_json::Value> { /* ... */ }
}
```

### MCP Tool → SQL Query Mapping

| MCP Tool | Query |
|----------|-------|
| `drift_status` | `SELECT * FROM materialized_status WHERE id = 1` |
| `drift_patterns_list` | Covering index IX1 with category/status filters |
| `drift_file_patterns` | JOIN via `idx_pattern_locations_file` (IX4) |
| `drift_security_summary` | `SELECT * FROM materialized_security WHERE id = 1` |
| `drift_code_examples` | `SELECT * FROM pattern_examples WHERE pattern_id = ? ORDER BY quality_score DESC` |
| `drift_impact_analysis` | Recursive CTE on `call_edges` |
| `drift_health_trends` | `SELECT * FROM health_trends ORDER BY recorded_at DESC LIMIT ?` |

All queries via `reader()` connections with `PRAGMA query_only = ON`. Use `prepare_cached()`. Keyset pagination.

---

## 19. Monorepo Support

```sql
CREATE TABLE packages (
    name TEXT PRIMARY KEY,
    path TEXT NOT NULL,                  -- Relative path from project root
    package_manager TEXT,                -- npm, yarn, pnpm, cargo, pip, etc.
    version TEXT,
    dependencies TEXT,                   -- JSONB array of dependency names
    dev_dependencies TEXT,               -- JSONB array
    language TEXT,
    framework TEXT,
    pattern_count INTEGER DEFAULT 0,
    function_count INTEGER DEFAULT 0,
    last_scanned TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;
```

Auto-detect packages by scanning for `package.json`, `Cargo.toml`, `pyproject.toml`, `go.mod`, `pom.xml`, `composer.json`, `build.gradle`, `pom.xml`, `*.csproj`, `*.sln`, `Gemfile` in subdirectories.

Per-package analysis: filter patterns, functions, and security data by package path prefix. Enable `drift status --package=@myorg/api`.

---

## 20. Feature Flags

```sql
CREATE TABLE feature_flags (
    feature TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 1,
    config TEXT CHECK(config IS NULL OR json_valid(config)),
    description TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;
```

Default flags seeded in migration:

```sql
INSERT INTO feature_flags (feature, enabled, description) VALUES
    ('incremental_scan', 1, 'Skip unchanged files during scans'),
    ('materialized_views', 1, 'Use materialized status tables'),
    ('cortex_integration', 1, 'Enable AI memory system'),
    ('sarif_export', 1, 'Enable SARIF output format'),
    ('telemetry', 0, 'Collect anonymous usage statistics'),
    ('experimental_detectors', 0, 'Enable experimental pattern detectors'),
    ('bayesian_confidence', 1, 'Use Bayesian confidence scoring');
```

---

## 21. Storage Telemetry

```rust
pub struct StorageTelemetry {
    pub query_count: AtomicU64,
    pub write_count: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub total_query_time_us: AtomicU64,
    pub total_write_time_us: AtomicU64,
    pub slowest_query_us: AtomicU64,
    pub slowest_query_sql: Mutex<String>,
}
```

Optional query telemetry table with sampling (10% default, always record slow queries >10ms):

```sql
CREATE TABLE query_telemetry (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    query_type TEXT NOT NULL,
    source TEXT NOT NULL,                -- mcp, cli, quality_gate
    execution_time_us INTEGER NOT NULL,
    rows_returned INTEGER,
    filters TEXT,                        -- JSONB
    used_index TEXT,
    was_cache_hit INTEGER,
    was_slow INTEGER,
    recorded_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

CREATE INDEX idx_telemetry_time ON query_telemetry(recorded_at);
CREATE INDEX idx_telemetry_slow ON query_telemetry(recorded_at)
    WHERE was_slow = 1;
```

Subject to retention policies (30 days, 10K entries max).

---

## 22. Global Database (~/.drift/global.db)

Separate from per-project drift.db. Stores cross-project state.

```sql
CREATE TABLE project_registry (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    path TEXT NOT NULL UNIQUE,
    last_accessed TEXT NOT NULL,
    schema_version TEXT,
    drift_version TEXT,
    health_score REAL,
    pattern_count INTEGER DEFAULT 0,
    last_scan_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;
```

Why separate: opening every project's drift.db just to list registered projects is wasteful. The global database is tiny (one row per project) and always fast to open.

---

## 23. Lock File Generation

Generate `drift.lock` from the database as a deterministic, human-readable TOML snapshot of approved patterns:

```toml
[meta]
version = "2.0.0"
generated_at = "2026-02-07T12:00:00Z"
checksum = "a1b2c3d4e5f6"

[[patterns]]
id = "abc123"
name = "express-route-handler"
category = "api"
confidence = 0.92
locations = 47
severity = "info"
```

CI integration: `drift lock validate` returns exit code 1 if lock file is out of sync with DB.

---

## 24. Performance Targets

| Operation | V1 (JSON) | V1 (SQLite) | V2 Target | How |
|-----------|-----------|-------------|-----------|-----|
| Load all patterns | 200-800ms | 50-150ms | 10-30ms | Rust + mmap + prepared statements |
| Find pattern by ID | O(n) scan | O(1) index | O(1) index | Same, faster via Rust |
| Status query | 100-300ms | 5-10ms | <1ms | Materialized table singleton |
| Insert 10K patterns | 500ms+ | 100-200ms | 20-50ms | Batch writer + IMMEDIATE |
| Call graph build (50K fn) | N/A | 15s | 2s | Parallel writer + rayon |
| Backup (50MB DB) | 2s (file copy) | 2s (file copy) | 200ms | SQLite Backup API |
| Incremental scan (10 files) | Full rescan | Full rescan | <500ms | File index + content hashing |
| Pattern search | N/A | 100ms | 10ms | Prepared statements + indexes |

---

## 25. Build Order

```
Phase 0 (Architecture):  ConnectionPool + Migrations + STRICT tables
Phase 1 (Core Schema):   All Silver tables + file_metadata + batch writer
Phase 2 (Gold Layer):    Materialized tables + refresh pipeline + health trends
Phase 3 (Query):         Keyset pagination + prepared statements + JSON indexes
Phase 4 (Safety):        Hot backup + integrity validation + process locking
Phase 5 (Operations):    VACUUM strategy + WAL checkpoint + retention + error handling
Phase 6 (Integration):   ATTACH cortex + NAPI bridge + telemetry
Phase 7 (Features):      Monorepo support + feature flags + lock file + global DB
```

### Dependency Graph

```
ConnectionPool (FA1) ──→ ALL subsystems
Migrations (FA2) ──→ Schema (R1)
STRICT (FA3) ──→ Schema (R1)

Schema (R1) ──→ Materialized Tables → Batch Writer → File Index
Schema (R1) ──→ Keyset Pagination → JSON Indexes
ConnectionPool ──→ Prepared Statements → Hot Backup → Integrity Validation
ConnectionPool ──→ ATTACH Cortex → Process Locking

Materialized + Batch Writer + File Index + Pagination ──→ NAPI Bridge
NAPI Bridge ──→ Telemetry → SARIF Export
Retention ──→ VACUUM Strategy
Backup + Error Handling ──→ Upgrade Path
```

---

## 26. Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Schema migration corrupts DB | Low | Critical | Auto-backup before migration, integrity check after |
| WAL file grows unbounded | Medium | Medium | Two-tier checkpoint: autocheckpoint + post-scan TRUNCATE |
| Concurrent write contention | Low | Medium | Single writer with Mutex, IMMEDIATE transactions, process lock |
| Database corruption from crash | Low | High | WAL + NORMAL sync provides crash recovery, auto-restore from backup |
| NAPI serialization overhead | Medium | Low | Compute + store in Rust, return summaries only |
| Database size exceeds expectations | Low | Medium | Retention policies, VACUUM after large deletes |
| Disk full during scan | Low | High | Graceful SQLITE_FULL handling, actionable error message |
| Two drift processes corrupt data | Medium | High | Process-level lock file, WAL for read concurrency |
| Stale lock file from crashed process | Low | Low | PID-based stale detection in `drift doctor`, `--force` override |
| Consumer missed during migration | Medium | Medium | Consumer checklist tracks every MCP tool and CLI command |

---

## 27. Consumer Update Checklist

Every consumer that reads from or writes to storage must be updated when the storage layer changes:

| Consumer | V2 Source | Notes |
|----------|-----------|-------|
| `drift_status` MCP | `materialized_status` via NAPI | <1ms singleton read |
| `drift_patterns_list` MCP | `patterns` covering index via NAPI | Keyset paginated |
| `drift_file_patterns` MCP | `pattern_locations` JOIN via NAPI | IX4 index |
| `drift_security_summary` MCP | `materialized_security` via NAPI | <1ms singleton read |
| `drift_code_examples` MCP | `pattern_examples` via NAPI | Sorted by quality_score |
| `drift_impact_analysis` MCP | Recursive CTE on `call_edges` | petgraph fallback for large graphs |
| `drift scan` CLI | Rust BatchWriter → Silver → Gold | No JSON output |
| `drift status` CLI | `materialized_status` via NAPI | Same as MCP |
| `drift approve/ignore` CLI | UPDATE patterns via NAPI | Single row update |
| `drift backup` CLI | SQLite Backup API via NAPI | Chunked, verified |
| `drift doctor` CLI | Integrity + reconciliation via NAPI | 8 checks |
| Detectors | Rust BatchWriter | Patterns + locations |
| Quality Gates | `materialized_status` + Silver tables | Gate-specific queries |
| Cortex bridge | ATTACH cortex.db read-only | Optional, graceful degradation |

---

*This document synthesizes all storage-related research from the v2-research directory, the Cortex implementation patterns, the full system audit (including A25's 9-phase data lake replacement), and current internet research on SQLite best practices. It is the single reference for building drift.db from scratch.*
