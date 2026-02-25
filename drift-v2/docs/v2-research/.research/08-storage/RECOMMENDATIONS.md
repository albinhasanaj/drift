# 08 Storage — V2 Build Recommendations

> **Context**: Drift v2 is a greenfield build. These recommendations define how to BUILD the storage layer from scratch using best practices, informed by v1's architecture (treated as a requirements specification) and external research from Tier 1-3 sources. Every recommendation is framed as "build new" not "migrate/port."

## Summary

29 recommendations organized into 8 build phases. The storage layer is the foundation that every other subsystem depends on — getting it right from day one is critical. The v1 Drift Lake's architectural concepts (pre-computation, selective loading, query routing, incremental materialization) are preserved but implemented natively in SQLite rather than as JSON files. Phase 6 adds operational safety: VACUUM strategy, WAL checkpoint management, concurrent process safety, graceful error handling, v1→v2 upgrade path, monorepo support, and feature flags. Phase 7 addresses context management, global state, search, backup enterprise features, consumer update tracking, and domain-level rebuild operations.

---

## Foundational Architecture Decisions

### FA1: Single Rust-Owned Database with Connection Pool

**Priority**: P0 (Build First)
**Effort**: Medium
**Impact**: Every subsystem reads/writes through this — defines the entire data access pattern

**What to Build**:
A `DatabaseManager` in Rust that owns the single `drift.db` file with a write-serialized, read-pooled connection strategy.

```rust
pub struct DatabaseManager {
    writer: Mutex<Connection>,           // Single write connection
    readers: Vec<Mutex<Connection>>,     // Pool of N read connections
    path: PathBuf,
    config: DatabaseConfig,
}

pub struct DatabaseConfig {
    pub read_pool_size: usize,           // Default: 4
    pub cache_size_kb: i64,              // Default: 64000 (64MB)
    pub mmap_size: i64,                  // Default: 268435456 (256MB)
    pub busy_timeout_ms: u32,            // Default: 5000
    pub wal_autocheckpoint: u32,         // Default: 1000 pages
}
```

**Connection initialization pragmas** (applied to every connection on open):
```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;
PRAGMA temp_store = 2;              -- Memory for temp tables
PRAGMA cache_size = -64000;         -- 64MB page cache
PRAGMA mmap_size = 268435456;       -- 256MB memory-mapped I/O
PRAGMA busy_timeout = 5000;         -- 5s busy timeout
```

**Connection close pragmas** (applied before closing):
```sql
PRAGMA analysis_limit = 400;
PRAGMA optimize;                    -- Gather statistics for query planner
```

**Write operations** use `BEGIN IMMEDIATE` transactions to acquire the write lock at transaction start, preventing SQLITE_BUSY errors from concurrent readers.

**Key design decisions**:
- Application-level write serialization via `Mutex<Connection>` is more predictable than relying on SQLite's internal busy handler
- Read connections are created with `PRAGMA query_only = ON` for safety
- All connections share the same WAL file, enabling concurrent reads during writes
- Use `crossbeam-channel` instead of `std::mpsc` for the batch writer (proven faster)

**Evidence**:
- SQLite WAL documentation: https://www.sqlite.org/wal.html
- SQLite pragma cheatsheet: https://cj.rs/blog/sqlite-pragma-cheatsheet-for-performance-and-consistency/
- sqlite-rwc connection pool pattern: https://www.lib.rs/crates/sqlite-rwc
- Gotchas with SQLite in Production: https://blog.pecar.me/sqlite-prod

---

### FA2: Schema Migration via user_version

**Priority**: P0 (Build First)
**Effort**: Low
**Impact**: Enables safe schema evolution across versions — every upgrade depends on this

**What to Build**:
Use `rusqlite_migration` crate with `PRAGMA user_version` for migration tracking. Define migrations as a const slice of SQL strings.

```rust
use rusqlite_migration::{Migrations, M};

const MIGRATIONS: &[M<'_>] = &[
    // v1: Initial schema
    M::up(include_str!("../sql/001_initial.sql")),
    // v2: Add file_metadata table
    M::up(include_str!("../sql/002_file_metadata.sql")),
    // v3: Add pattern_suppressions
    M::up(include_str!("../sql/003_suppressions.sql")),
    // Future migrations added here — NEVER remove or reorder
];

pub fn initialize(conn: &mut Connection) -> Result<()> {
    let migrations = Migrations::from_slice(MIGRATIONS);
    migrations.to_latest(conn)?;
    Ok(())
}
```

**Rules**:
1. Never remove a migration entry from the list
2. Never perform backwards-incompatible changes (no DROP TABLE, no DROP COLUMN)
3. Store SQL in separate `.sql` files using `include_str!()` for maintainability
4. Auto-backup before applying migrations (use SQLite backup API)
5. Add `#[test] fn migrations_test() { assert!(MIGRATIONS.validate().is_ok()); }` for CI validation

**Evidence**:
- rusqlite_migration: https://cj.rs/rusqlite_migration
- Cargo's migration pattern: https://doc.rust-lang.org/nightly/nightly-rustc/src/cargo/util/sqlite.rs.html
- Mozilla Application Services: https://mozilla.github.io/application-services/book/rust-docs/src/webext_storage/schema.rs.html

---

### FA3: STRICT Tables for Type Safety

**Priority**: P0 (Build First)
**Effort**: Trivial
**Impact**: Catches type errors at insert time — prevents silent data corruption

**What to Build**:
All v2 tables use the `STRICT` keyword (SQLite 3.37+). This enforces column types at insert time, preventing SQLite's default type affinity behavior where a TEXT value can be stored in an INTEGER column.

```sql
CREATE TABLE patterns (
    id TEXT PRIMARY KEY,
    category TEXT NOT NULL,
    confidence_score REAL NOT NULL DEFAULT 0.0,
    location_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;
```

JSON columns use the `TEXT` type with `CHECK(json_valid(column_name))` constraints:
```sql
CREATE TABLE patterns (
    ...
    tags TEXT CHECK(tags IS NULL OR json_valid(tags)),
    ...
) STRICT;
```

**Evidence**:
- SQLite STRICT tables: https://www.sqlite.org/stricttables.html
- SQLite pragma cheatsheet: https://cj.rs/blog/sqlite-pragma-cheatsheet-for-performance-and-consistency/

---

## Phase 1: Core Schema and Infrastructure

### R1: Unified Schema with Domain Separation

**Priority**: P0
**Effort**: High
**Impact**: Defines the data model for the entire system

**What to Build**:
A single `drift.db` with all 40+ tables from v1's schema.sql, plus new tables for v2 capabilities. Organize tables by domain with clear naming conventions.

**New tables to add**:

| Table | Purpose |
|-------|---------|
| `file_metadata` | Per-file stats: language, size, last_modified, content_hash (xxhash). Foundation for incremental scanning |
| `packages` | Monorepo package registry: name, path, dependencies. Enables per-package analysis |
| `pattern_suppressions` | Inline `// drift-ignore` tracking: file, line, pattern_id, reason, expires_at |
| `migration_history` | Schema migration audit trail: version, applied_at, checksum, duration_ms |
| `cache_entries` | Replaces JSON cache manager: key, value (JSON), ttl, created_at, accessed_at |
| `project_registry` | Replaces ~/.drift/registry.json: name, path, last_accessed, schema_version |
| `materialized_status` | Cached status dashboard data (replaces v_status view for instant reads) |
| `materialized_security` | Cached security posture data (replaces v_security_summary view) |

**Schema refinements to existing tables**:
1. `patterns` — Add `hash TEXT` for deduplication, `parent_id TEXT` for hierarchy, `decay_rate REAL` for temporal confidence
2. `functions` — Add `complexity INTEGER` (cyclomatic), `return_type TEXT`, `visibility TEXT`
3. `scan_history` — Add `incremental INTEGER` flag, `changed_files INTEGER`, `skipped_files INTEGER`
4. `pattern_locations` — Add `end_line INTEGER`, `end_column INTEGER`, `snippet TEXT`, `deviation_score REAL`

**All tables use STRICT mode** (FA3).

**Evidence**:
- V1 schema.sql (899 lines) serves as the requirements specification
- V1 removal-plan.md defines what gets added/removed

---

### R2: Materialized Status Tables (Replacing Data Lake Views)

**Priority**: P0
**Effort**: Medium
**Impact**: Enables instant `drift_status` responses — the most common query

**What to Build**:
SQLite doesn't support true materialized views. Instead, build "materialized tables" — regular tables populated by explicit refresh calls after scans.

```sql
-- Materialized status (refreshed after each scan)
CREATE TABLE materialized_status (
    id INTEGER PRIMARY KEY CHECK (id = 1),  -- Singleton row
    health_score REAL NOT NULL,
    health_trend TEXT NOT NULL CHECK (health_trend IN ('improving', 'stable', 'declining')),
    total_patterns INTEGER NOT NULL,
    approved_patterns INTEGER NOT NULL,
    discovered_patterns INTEGER NOT NULL,
    ignored_patterns INTEGER NOT NULL,
    category_counts TEXT NOT NULL,           -- JSON: {category: count}
    critical_issues INTEGER NOT NULL,
    warning_issues INTEGER NOT NULL,
    security_risk_level TEXT NOT NULL,
    security_violations INTEGER NOT NULL,
    sensitive_exposures INTEGER NOT NULL,
    last_scan_at TEXT,
    last_scan_duration_ms INTEGER,
    last_scan_files INTEGER,
    last_scan_patterns INTEGER,
    refreshed_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

-- Materialized security posture (refreshed after each scan)
CREATE TABLE materialized_security (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    risk_level TEXT NOT NULL,
    total_tables INTEGER NOT NULL,
    total_access_points INTEGER NOT NULL,
    sensitive_fields INTEGER NOT NULL,
    violations INTEGER NOT NULL,
    top_sensitive_tables TEXT NOT NULL,      -- JSON array
    top_violations TEXT NOT NULL,            -- JSON array
    refreshed_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;
```

**Refresh function** (called after scan completion):
```rust
pub fn refresh_materialized_status(conn: &Connection) -> Result<()> {
    conn.execute_batch("
        INSERT OR REPLACE INTO materialized_status (id, health_score, ...)
        SELECT 1,
            -- health score calculation
            COALESCE(AVG(confidence_score), 0.0),
            -- ... aggregations from patterns, scan_history, etc.
        FROM patterns
        LEFT JOIN scan_history ON ...
    ")?;
    Ok(())
}
```

**Why not regular SQL views**: Regular views recompute on every query. For `drift_status` (called by every MCP interaction), this means re-aggregating all patterns every time. A materialized table is computed once after scan and read instantly thereafter.

**Preserves v1 Lake concept**: The Data Lake's core insight — pre-compute common queries — is preserved. The implementation changes from JSON files to SQLite tables, but the architecture is the same.

**Evidence**:
- V1 Data Lake overview: pre-compute common queries as materialized views
- V1 ViewMaterializer: selective rebuild after scans
- Materialized view patterns: https://www.dremio.com/wiki/materialized-views/

---

### R3: Batch Writer with Crossbeam Channel

**Priority**: P0
**Effort**: Medium
**Impact**: Enables parallel scanning with efficient sequential writes

**What to Build**:
Generalize v1's `ParallelWriter` pattern from call-graph-only to all domains. Use `crossbeam-channel` instead of `std::mpsc` for better performance.

```rust
use crossbeam_channel::{Sender, Receiver, bounded};

pub struct BatchWriter {
    sender: Sender<WriteBatch>,
    handle: Option<JoinHandle<Result<WriteStats>>>,
}

pub enum WriteBatch {
    Patterns(Vec<PatternRow>),
    Functions(Vec<FunctionRow>),
    Locations(Vec<LocationRow>),
    Contracts(Vec<ContractRow>),
    FileMetadata(Vec<FileMetadataRow>),
    Flush,
    Shutdown,
}

impl BatchWriter {
    pub fn new(conn: Connection, buffer_threshold: usize) -> Self {
        let (sender, receiver) = bounded(1024);  // Bounded channel prevents OOM
        
        let handle = thread::spawn(move || {
            let mut buffer: Vec<WriteBatch> = Vec::with_capacity(buffer_threshold);
            let mut stats = WriteStats::default();
            
            for batch in receiver {
                match batch {
                    WriteBatch::Shutdown => {
                        Self::flush_buffer(&conn, &mut buffer, &mut stats)?;
                        break;
                    }
                    WriteBatch::Flush => {
                        Self::flush_buffer(&conn, &mut buffer, &mut stats)?;
                    }
                    other => {
                        buffer.push(other);
                        if buffer.len() >= buffer_threshold {
                            Self::flush_buffer(&conn, &mut buffer, &mut stats)?;
                        }
                    }
                }
            }
            Ok(stats)
        });
        
        Self { sender, handle: Some(handle) }
    }
    
    fn flush_buffer(conn: &Connection, buffer: &mut Vec<WriteBatch>, stats: &mut WriteStats) -> Result<()> {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        for batch in buffer.drain(..) {
            match batch {
                WriteBatch::Patterns(rows) => {
                    stats.patterns += Self::insert_patterns(&tx, &rows)?;
                }
                WriteBatch::Functions(rows) => {
                    stats.functions += Self::insert_functions(&tx, &rows)?;
                }
                // ... other domains
                _ => {}
            }
        }
        tx.commit()?;
        stats.flushes += 1;
        Ok(())
    }
}
```

**Key improvements over v1**:
- Bounded channel prevents OOM if writer falls behind
- `BEGIN IMMEDIATE` transactions prevent SQLITE_BUSY
- Generalized to all domains (not just call graph)
- Returns `WriteStats` for telemetry
- Uses `crossbeam-channel` for better throughput

**Evidence**:
- V1 ParallelWriter pattern (proven in production)
- crossbeam-channel performance: https://users.rust-lang.org/t/poor-performance-of-sending-items-over-an-mpsc-channel/50559
- IMMEDIATE transactions: https://blog.pecar.me/sqlite-prod

---

### R4: Incremental File Index with Content Hashing

**Priority**: P0
**Effort**: Medium
**Impact**: Enables O(changes) scanning instead of O(repository)

**What to Build**:
A `file_metadata` table that tracks every file's content hash, enabling the scanner to skip unchanged files.

```sql
CREATE TABLE file_metadata (
    path TEXT PRIMARY KEY,
    language TEXT,
    size INTEGER NOT NULL,
    content_hash TEXT NOT NULL,          -- xxhash of file content
    last_modified TEXT NOT NULL,
    last_scanned TEXT,
    scan_duration_us INTEGER,           -- Microseconds to scan this file
    pattern_count INTEGER DEFAULT 0,
    function_count INTEGER DEFAULT 0,
    error_count INTEGER DEFAULT 0
) STRICT;
```

**Scan flow**:
```
1. Walk filesystem → collect file paths + sizes + mtimes
2. For each file:
   a. Check file_metadata table for existing entry
   b. If mtime unchanged → skip (fast path)
   c. If mtime changed → compute xxhash of content
   d. If content_hash unchanged → skip (mtime changed but content didn't)
   e. If content_hash changed → mark for re-scanning
3. Scan only changed files
4. Delete file_metadata entries for removed files
5. Update file_metadata for scanned files
```

**Two-level change detection**:
- Level 1: mtime comparison (instant, catches most changes)
- Level 2: content hash comparison (catches mtime-only changes from git operations)

**Evidence**:
- V1 ManifestStore already tracks file hashes (SHA-256)
- Glean incremental indexing: https://glean.software/blog/incremental/
- rust-analyzer architecture: https://rust-analyzer.github.io/blog/2020/07/20/three-architectures-for-responsive-ide.html

---

## Phase 2: Query Layer

### R5: Keyset Pagination for All List Queries

**Priority**: P1
**Effort**: Low
**Impact**: Constant-time pagination regardless of dataset size

**What to Build**:
Replace OFFSET/LIMIT pagination with keyset (cursor-based) pagination for all list queries exposed through MCP and CLI.

```rust
pub struct PaginationCursor {
    pub last_id: String,
    pub last_sort_value: Option<String>,  // For non-ID sort columns
}

pub struct PaginatedResult<T> {
    pub items: Vec<T>,
    pub total: usize,
    pub has_more: bool,
    pub next_cursor: Option<String>,      // Base64-encoded PaginationCursor
    pub execution_time_us: u64,
}

// Query builder
fn query_patterns_paginated(
    conn: &Connection,
    filters: &PatternFilters,
    cursor: Option<&PaginationCursor>,
    limit: usize,
) -> Result<PaginatedResult<PatternRow>> {
    let mut sql = String::from("SELECT * FROM patterns WHERE 1=1");
    let mut params: Vec<Box<dyn ToSql>> = Vec::new();
    
    // Apply filters
    if let Some(category) = &filters.category {
        sql.push_str(" AND category = ?");
        params.push(Box::new(category.clone()));
    }
    
    // Apply cursor (keyset pagination)
    if let Some(cursor) = cursor {
        sql.push_str(" AND (created_at, id) > (?, ?)");
        params.push(Box::new(cursor.last_sort_value.clone()));
        params.push(Box::new(cursor.last_id.clone()));
    }
    
    sql.push_str(" ORDER BY created_at ASC, id ASC LIMIT ?");
    params.push(Box::new(limit as i64 + 1));  // Fetch one extra to detect has_more
    
    // Execute and build result...
}
```

**Composite cursor**: Use `(sort_column, id)` as the cursor to handle ties in the sort column. The `id` column breaks ties deterministically.

**Backward compatibility**: MCP tools already return `nextCursor` — the backend change is transparent to consumers.

**Evidence**:
- Keyset pagination: https://openillumi.com/en/en-sqlite-limit-offset-slow-fix-seek-method/
- Cursor-based pagination: https://blog.sequinstream.com/keyset-cursors-not-offsets-for-postgres-pagination/

---

### R6: Prepared Statement Cache

**Priority**: P1
**Effort**: Low
**Impact**: Eliminates query parsing overhead for repeated queries

**What to Build**:
Cache prepared statements for frequently-executed queries. `rusqlite` supports `prepare_cached()` which automatically caches prepared statements per connection.

```rust
impl DatabaseManager {
    pub fn get_pattern(&self, id: &str) -> Result<Option<PatternRow>> {
        let reader = self.get_reader()?;
        // prepare_cached() reuses the prepared statement on subsequent calls
        let mut stmt = reader.prepare_cached(
            "SELECT * FROM patterns WHERE id = ?"
        )?;
        let result = stmt.query_row(params![id], |row| PatternRow::from_row(row)).optional()?;
        Ok(result)
    }
    
    pub fn query_patterns(&self, filters: &PatternFilters) -> Result<Vec<PatternRow>> {
        let reader = self.get_reader()?;
        // For dynamic queries, use a statement cache keyed by filter combination
        let sql = filters.to_sql();
        let mut stmt = reader.prepare_cached(&sql)?;
        // ...
    }
}
```

**Key points**:
- `prepare_cached()` is built into rusqlite — no external crate needed
- Each connection maintains its own statement cache
- Cache is automatically invalidated when the schema changes
- For dynamic queries (variable WHERE clauses), cache by the SQL string

**Evidence**:
- rusqlite prepare_cached: https://docs.rs/rusqlite/latest/rusqlite/struct.Connection.html#method.prepare_cached

---

### R7: Expression Indexes on JSON Columns

**Priority**: P1
**Effort**: Low
**Impact**: Enables indexed lookups into JSON columns without normalization

**What to Build**:
Add expression indexes on JSON columns that are used in WHERE clauses or JOINs.

```sql
-- Index for filtering patterns by tag
CREATE INDEX idx_patterns_tags ON patterns(json_extract(tags, '$'))
    WHERE tags IS NOT NULL;

-- Index for filtering contracts by backend framework
CREATE INDEX idx_contracts_framework ON contracts(json_extract(backend_response_fields, '$[0].type'))
    WHERE backend_response_fields IS NOT NULL;

-- Index for querying memory content by type-specific fields
CREATE INDEX idx_memories_content_type ON memories(json_extract(content, '$.type'))
    WHERE content IS NOT NULL;
```

**When to normalize vs index**:
- **Keep as JSON + expression index**: Data always read/written as a unit (tags, decorators, parameters)
- **Normalize into separate table**: Data frequently filtered/sorted individually (mismatches → `contract_mismatches` table)

**Specific normalization recommendation**: The `mismatches` JSON column in `contracts` should be normalized into a `contract_mismatches` table for v2, enabling queries like "find all contracts with missing_in_frontend mismatches":

```sql
CREATE TABLE contract_mismatches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    contract_id TEXT NOT NULL REFERENCES contracts(id) ON DELETE CASCADE,
    field_path TEXT NOT NULL,
    mismatch_type TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL,
    backend_field TEXT,              -- JSON
    frontend_field TEXT              -- JSON
) STRICT;
```

**Evidence**:
- SQLite JSON and denormalization: https://maximeblanc.fr/blog/sqlite-json-and-denormalization/
- Using SQLite with JSON data: https://peter-hoffmann.com/2024/using-sqlite-with-json-data.html

---

## Phase 3: Backup, Recovery, and Data Safety

### R8: Hot Backup via SQLite Backup API

**Priority**: P0
**Effort**: Low
**Impact**: Data safety — prevents data loss during upgrades and destructive operations

**What to Build**:
Use `rusqlite`'s backup API (wrapping `sqlite3_backup_init`) for all backup operations. Never copy database files directly.

```rust
impl DatabaseManager {
    pub fn backup(&self, dest_path: &Path) -> Result<BackupResult> {
        let reader = self.get_reader()?;
        let mut dest = Connection::open(dest_path)?;
        
        let backup = rusqlite::backup::Backup::new(&reader, &mut dest)?;
        
        // Transfer in chunks of 1000 pages, sleeping 10ms between chunks
        // to avoid blocking readers for too long
        backup.run_to_completion(1000, Duration::from_millis(10), None)?;
        
        // Verify backup integrity
        dest.pragma_query(None, "integrity_check", |row| {
            let result: String = row.get(0)?;
            if result != "ok" {
                return Err(rusqlite::Error::QueryReturnedNoRows);
            }
            Ok(())
        })?;
        
        Ok(BackupResult {
            path: dest_path.to_path_buf(),
            size: std::fs::metadata(dest_path)?.len(),
            duration: start.elapsed(),
            verified: true,
        })
    }
    
    pub fn restore(&self, backup_path: &Path) -> Result<()> {
        // 1. Verify backup integrity
        // 2. Close all connections
        // 3. Backup current DB (safety net)
        // 4. Restore from backup using backup API in reverse
        // 5. Reopen connections
        // 6. Verify restored DB integrity
    }
}
```

**Backup triggers**:
- Before schema migrations (automatic)
- Before `drift upgrade` (automatic)
- Before destructive operations like `drift reset` (automatic)
- On user request via `drift backup create` (manual)

**Retention policy**:
- Keep last 5 backups by default (configurable)
- Auto-delete oldest when limit exceeded
- Store in `.drift/backups/drift-{timestamp}.db`

**Evidence**:
- SQLite Online Backup API: https://sqlite.org/c3ref/backup_finish.html
- Safe SQLite backup: https://openillumi.com/en/en-sqlite-safe-backup-method/

---

### R9: Data Integrity Validation

**Priority**: P1
**Effort**: Low
**Impact**: Detects corruption before it causes downstream failures

**What to Build**:
Periodic integrity checks and foreign key validation.

```rust
impl DatabaseManager {
    /// Run on startup and after restore operations
    pub fn validate_integrity(&self) -> Result<IntegrityReport> {
        let reader = self.get_reader()?;
        let mut report = IntegrityReport::default();
        
        // 1. SQLite integrity check
        reader.pragma_query(None, "integrity_check", |row| {
            let result: String = row.get(0)?;
            if result != "ok" {
                report.integrity_errors.push(result);
            }
            Ok(())
        })?;
        
        // 2. Foreign key check
        reader.pragma_query(None, "foreign_key_check", |row| {
            let table: String = row.get(0)?;
            let rowid: i64 = row.get(1)?;
            let parent: String = row.get(2)?;
            report.fk_violations.push(FkViolation { table, rowid, parent });
            Ok(())
        })?;
        
        // 3. Schema version check
        let version: i32 = reader.pragma_query_value(None, "user_version", |row| row.get(0))?;
        report.schema_version = version;
        report.expected_version = CURRENT_SCHEMA_VERSION;
        
        // 4. Row count sanity checks
        report.pattern_count = reader.query_row("SELECT COUNT(*) FROM patterns", [], |r| r.get(0))?;
        report.function_count = reader.query_row("SELECT COUNT(*) FROM functions", [], |r| r.get(0))?;
        
        Ok(report)
    }
}
```

**When to run**:
- On database open (quick check: schema version only)
- After restore operations (full integrity check)
- On `drift doctor` command (full check + foreign key check)
- After crash recovery (full check)

**Evidence**:
- SQLite integrity_check: https://www.sqlite.org/pragma.html#pragma_integrity_check
- SQLite foreign_key_check: https://www.sqlite.org/pragma.html#pragma_foreign_key_check

---

## Phase 4: Cross-Database and Cortex Integration

### R10: ATTACH DATABASE for Cortex Queries

**Priority**: P1
**Effort**: Low
**Impact**: Enables cross-domain queries between analysis data and AI memory

**What to Build**:
Use `ATTACH DATABASE` to enable cross-database queries between drift.db and cortex.db when needed.

```rust
impl DatabaseManager {
    pub fn attach_cortex(&self, cortex_path: &Path) -> Result<()> {
        let reader = self.get_reader()?;
        reader.execute(
            "ATTACH DATABASE ?1 AS cortex",
            params![cortex_path.to_str()],
        )?;
        Ok(())
    }
    
    /// Find memories linked to high-confidence patterns
    pub fn get_pattern_memories(&self, min_confidence: f64) -> Result<Vec<PatternMemory>> {
        let reader = self.get_reader()?;
        let mut stmt = reader.prepare_cached("
            SELECT p.id, p.name, p.confidence_score, m.summary, m.type
            FROM patterns p
            JOIN cortex.memory_patterns mp ON mp.pattern_id = p.id
            JOIN cortex.memories m ON m.id = mp.memory_id
            WHERE p.confidence_score >= ?1
            AND m.archived = 0
            ORDER BY p.confidence_score DESC
        ")?;
        // ...
    }
}
```

**Design decision**: Keep drift.db and cortex.db separate for v2.0:
- sqlite-vec extension only loaded for cortex connections (not all connections)
- Independent schema migration histories
- Independent backup/restore
- Cortex stays TypeScript-owned (AI orchestration layer)

**ATTACH is used on-demand** for cross-domain queries, not permanently. This avoids the performance overhead of a permanently attached database.

**Evidence**:
- SQLite ATTACH DATABASE: https://openillumi.com/en/en-sqlite-multi-db-join-attach-command/
- V1 architecture: separate cortex.db recommended for v2.0

---

### R11: Cortex Embedding Cache in Rust

**Priority**: P2
**Effort**: Medium
**Impact**: Faster memory retrieval for MCP tools

**What to Build**:
Port the L1 embedding cache from TypeScript to Rust for lower latency. Keep L2 (SQLite) and L3 (precomputed) in TypeScript since Cortex stays TS-owned.

```rust
use moka::sync::Cache;

pub struct EmbeddingCache {
    l1: Cache<String, Vec<f32>>,  // In-memory LRU with TTL
}

impl EmbeddingCache {
    pub fn new(max_entries: u64, ttl_seconds: u64) -> Self {
        Self {
            l1: Cache::builder()
                .max_capacity(max_entries)
                .time_to_live(Duration::from_secs(ttl_seconds))
                .build(),
        }
    }
    
    pub fn get(&self, memory_id: &str) -> Option<Vec<f32>> {
        self.l1.get(memory_id)
    }
    
    pub fn insert(&self, memory_id: &str, embedding: Vec<f32>) {
        self.l1.insert(memory_id.to_string(), embedding);
    }
}
```

**Why `moka`**: Production-grade concurrent cache with TTL, LRU eviction, and lock-free reads. Used by major Rust projects. Better than `DashMap` for cache use cases because it handles eviction and TTL natively.

**Evidence**:
- moka crate: https://docs.rs/moka/latest/moka/
- V1 Cortex cache architecture: L1 (memory) → L2 (SQLite) → L3 (precomputed)

---

## Phase 5: NAPI Bridge and TypeScript Integration

### R12: Typed NAPI Bindings for Storage Operations

**Priority**: P0
**Effort**: Medium
**Impact**: TypeScript layer gets fast, type-safe access to all storage operations

**What to Build**:
NAPI bindings that expose high-level storage operations to TypeScript. Not raw SQL — typed functions with structured inputs and outputs.

```rust
use napi_derive::napi;

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
pub struct DriftDatabase {
    manager: DatabaseManager,
}

#[napi]
impl DriftDatabase {
    #[napi(constructor)]
    pub fn new(path: String) -> napi::Result<Self> { ... }
    
    // Status (instant — reads materialized table)
    #[napi]
    pub fn get_status(&self) -> napi::Result<serde_json::Value> { ... }
    
    // Pattern queries (keyset paginated)
    #[napi]
    pub fn query_patterns(&self, opts: PatternQueryOptions) -> napi::Result<serde_json::Value> { ... }
    
    // Batch writes (uses BatchWriter internally)
    #[napi]
    pub fn insert_patterns(&self, patterns: Vec<serde_json::Value>) -> napi::Result<Vec<String>> { ... }
    
    // Call graph queries
    #[napi]
    pub fn get_callers(&self, function_id: String) -> napi::Result<Vec<serde_json::Value>> { ... }
    
    // Backup
    #[napi]
    pub fn backup(&self, dest: String) -> napi::Result<serde_json::Value> { ... }
    
    // Migrations
    #[napi]
    pub fn run_migrations(&self) -> napi::Result<()> { ... }
    
    // Integrity check
    #[napi]
    pub fn validate_integrity(&self) -> napi::Result<serde_json::Value> { ... }
    
    // Raw query (escape hatch for complex queries)
    #[napi]
    pub fn execute_raw(&self, sql: String, params: Vec<serde_json::Value>) -> napi::Result<serde_json::Value> { ... }
}
```

**Design principles**:
- High-level typed functions for common operations (not raw SQL)
- `execute_raw()` as escape hatch for complex/ad-hoc queries
- All results as `serde_json::Value` for flexible TypeScript consumption
- Async variants for long-running operations (full scan, backup)

**Evidence**:
- napi-rs: https://napi.rs/
- V1 NAPI bridge: ~25 exported functions

---

### R13: Storage Telemetry and Diagnostics

**Priority**: P1
**Effort**: Low
**Impact**: Enables performance monitoring and debugging

**What to Build**:
Built-in telemetry for storage operations.

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

impl DatabaseManager {
    pub fn get_telemetry(&self) -> TelemetrySnapshot {
        TelemetrySnapshot {
            queries: self.telemetry.query_count.load(Ordering::Relaxed),
            writes: self.telemetry.write_count.load(Ordering::Relaxed),
            cache_hit_rate: self.cache_hit_rate(),
            avg_query_time_us: self.avg_query_time(),
            slowest_query: self.telemetry.slowest_query_sql.lock().clone(),
            db_size_bytes: std::fs::metadata(&self.path)?.len(),
            wal_size_bytes: std::fs::metadata(self.wal_path())?.len(),
            page_count: self.get_page_count()?,
            freelist_count: self.get_freelist_count()?,
        }
    }
}
```

**Exposed via NAPI** as `drift_storage_stats` for MCP tools and CLI diagnostics.

**Evidence**:
- V1 QueryEngine tracks hit counts and response times per source
- V1 ManifestStore tracks view freshness

---

### R14: SARIF Export from Storage

**Priority**: P2
**Effort**: Medium
**Impact**: Interoperability with GitHub Code Scanning, Azure DevOps, and CI/CD platforms

**What to Build**:
A SARIF 2.1.0 exporter that generates standards-compliant output from the patterns and violations stored in drift.db.

```rust
pub fn export_sarif(conn: &Connection, options: &SarifOptions) -> Result<SarifLog> {
    let patterns = query_patterns(conn, &options.filters)?;
    
    SarifLog {
        version: "2.1.0".to_string(),
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifToolComponent {
                    name: "drift".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    rules: patterns.iter().map(|p| pattern_to_rule(p)).collect(),
                },
            },
            results: patterns.iter()
                .flat_map(|p| pattern_to_results(p))
                .collect(),
        }],
    }
}
```

**Evidence**:
- SARIF standard: https://www.sonarsource.com/resources/library/sarif/
- V1 already supports SARIF output for quality gates

---

### R15: Retention Policies and Data Lifecycle

**Priority**: P1
**Effort**: Low
**Impact**: Prevents unbounded database growth

**What to Build**:
Configurable retention policies for historical data.

```rust
pub struct RetentionConfig {
    pub scan_history_max_entries: usize,      // Default: 100
    pub pattern_history_max_days: usize,      // Default: 365
    pub audit_snapshots_max_entries: usize,   // Default: 50
    pub health_trends_max_days: usize,        // Default: 180
    pub backup_max_count: usize,              // Default: 5
    pub cache_entries_max_age_hours: usize,   // Default: 24
}

impl DatabaseManager {
    pub fn enforce_retention(&self, config: &RetentionConfig) -> Result<RetentionResult> {
        let writer = self.get_writer()?;
        let tx = writer.transaction_with_behavior(TransactionBehavior::Immediate)?;
        
        let mut result = RetentionResult::default();
        
        // Prune scan history
        result.scan_history_pruned = tx.execute(
            "DELETE FROM scan_history WHERE scan_id NOT IN (
                SELECT scan_id FROM scan_history ORDER BY started_at DESC LIMIT ?1
            )", params![config.scan_history_max_entries]
        )?;
        
        // Prune pattern history
        result.pattern_history_pruned = tx.execute(
            "DELETE FROM pattern_history WHERE created_at < datetime('now', ?1)",
            params![format!("-{} days", config.pattern_history_max_days)]
        )?;
        
        // Prune cache entries
        result.cache_pruned = tx.execute(
            "DELETE FROM cache_entries WHERE created_at < datetime('now', ?1)",
            params![format!("-{} hours", config.cache_entries_max_age_hours)]
        )?;
        
        tx.commit()?;
        Ok(result)
    }
}
```

**When to run**: After each scan completion, as part of the post-scan pipeline.

**Evidence**:
- V1 quality gates: max 50 snapshots per branch, max 100 runs
- V1 workspace: max 10 backups

---

### R16: Lock File Generation from Database

**Priority**: P2
**Effort**: Low
**Impact**: Version-controlled pattern snapshot for code review

**What to Build**:
Generate `drift.lock` from the database as a deterministic, human-readable snapshot of approved patterns.

```rust
pub fn generate_lock_file(conn: &Connection) -> Result<LockFile> {
    let patterns: Vec<LockPattern> = conn.prepare_cached("
        SELECT id, name, category, subcategory, confidence_score, 
               location_count, severity
        FROM patterns 
        WHERE status = 'approved'
        ORDER BY category, name, id
    ")?.query_map([], |row| {
        Ok(LockPattern {
            id: row.get(0)?,
            name: row.get(1)?,
            category: row.get(2)?,
            subcategory: row.get(3)?,
            confidence: row.get(4)?,
            locations: row.get(5)?,
            severity: row.get(6)?,
        })
    })?.collect::<Result<Vec<_>, _>>()?;
    
    let checksum = compute_lock_checksum(&patterns);
    
    Ok(LockFile {
        version: "2.0.0".to_string(),
        generated_at: Utc::now().to_rfc3339(),
        checksum,
        patterns,
    })
}
```

**Format**: TOML for human readability in code review:
```toml
[meta]
version = "2.0.0"
generated_at = "2026-02-06T12:00:00Z"
checksum = "a1b2c3d4e5f6"

[[patterns]]
id = "abc123"
name = "express-route-handler"
category = "api"
confidence = 0.92
locations = 47
severity = "info"
```

**Validation** (`drift lock validate`):
```rust
pub fn validate_lock_file(conn: &Connection, lock: &LockFile) -> Result<LockValidation> {
    let db_patterns = generate_lock_file(conn)?;
    let mut validation = LockValidation::default();
    
    // Check checksum match
    if lock.checksum != db_patterns.checksum {
        validation.checksum_mismatch = true;
    }
    
    // Find patterns in lock but not in DB (removed)
    for lp in &lock.patterns {
        if !db_patterns.patterns.iter().any(|dp| dp.id == lp.id) {
            validation.removed.push(lp.id.clone());
        }
    }
    
    // Find patterns in DB but not in lock (added)
    for dp in &db_patterns.patterns {
        if !lock.patterns.iter().any(|lp| lp.id == dp.id) {
            validation.added.push(dp.id.clone());
        }
    }
    
    // Find patterns with changed confidence/locations
    for dp in &db_patterns.patterns {
        if let Some(lp) = lock.patterns.iter().find(|lp| lp.id == dp.id) {
            if (dp.confidence - lp.confidence).abs() > 0.01 || dp.locations != lp.locations {
                validation.changed.push(dp.id.clone());
            }
        }
    }
    
    validation.is_valid = validation.removed.is_empty() 
        && validation.added.is_empty() 
        && validation.changed.is_empty();
    
    Ok(validation)
}
```

**CI integration**: `drift lock validate` returns exit code 1 if lock file is out of sync with DB. Use in CI to enforce that `drift.lock` is regenerated after pattern changes.

**Evidence**:
- V1 lock-file-manager.ts generates drift.lock for version control
- V1 removal plan: keep drift.lock concept, rewrite for DB-backed generation

---

## Phase 6: Operational Safety and Edge Cases

### R17: VACUUM Strategy with Freelist Monitoring

**Priority**: P1
**Effort**: Low
**Impact**: Prevents database bloat after retention enforcement and large deletes

**What to Build**:
A conditional VACUUM strategy that runs only when the database has significant free space.

```rust
impl DatabaseManager {
    pub fn maybe_vacuum(&self) -> Result<VacuumResult> {
        let writer = self.get_writer()?;
        
        let page_count: i64 = writer.pragma_query_value(None, "page_count", |r| r.get(0))?;
        let freelist_count: i64 = writer.pragma_query_value(None, "freelist_count", |r| r.get(0))?;
        
        let free_ratio = freelist_count as f64 / page_count as f64;
        
        if free_ratio > 0.20 {
            // >20% free pages — VACUUM is worthwhile
            // Checkpoint WAL first to ensure clean state
            writer.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
            writer.execute_batch("VACUUM")?;
            
            Ok(VacuumResult {
                performed: true,
                pages_before: page_count,
                pages_freed: freelist_count,
                free_ratio,
            })
        } else {
            Ok(VacuumResult { performed: false, pages_before: page_count, pages_freed: 0, free_ratio })
        }
    }
}
```

**When to run**: After `enforce_retention()` (R15), as part of `drift doctor`, or on explicit `drift vacuum` command.

**Why not auto_vacuum**: `auto_vacuum=INCREMENTAL` adds overhead to every COMMIT and does NOT defragment — it only moves free pages to the end of the file. Manual VACUUM after large deletes is more efficient and provides defragmentation.

**Evidence**:
- SQLite VACUUM documentation: https://sqlite.org/draft/matrix/lang_vacuum.html
- SQLite auto_vacuum forum discussion: https://sqlite.org/forum/forumpost/1be1a5d418ff2499

---

### R18: WAL Checkpoint Strategy

**Priority**: P1
**Effort**: Low
**Impact**: Prevents WAL file growth and maintains read performance

**What to Build**:
A two-tier checkpoint strategy: automatic PASSIVE checkpoints during normal operation, explicit TRUNCATE checkpoint after scans.

```rust
impl DatabaseManager {
    /// Called after scan completion to reclaim WAL space
    pub fn post_scan_checkpoint(&self) -> Result<CheckpointResult> {
        let writer = self.get_writer()?;
        
        // TRUNCATE mode: checkpoint all frames, then truncate WAL file to zero bytes
        let (log_frames, checkpointed_frames): (i32, i32) = writer.query_row(
            "PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            }
        )?;
        
        Ok(CheckpointResult {
            mode: "TRUNCATE",
            log_frames,
            checkpointed_frames,
        })
    }
    
    /// Emergency checkpoint if WAL exceeds threshold (e.g., 100MB)
    pub fn emergency_checkpoint(&self, max_wal_bytes: u64) -> Result<bool> {
        let wal_path = self.path.with_extension("db-wal");
        if let Ok(meta) = std::fs::metadata(&wal_path) {
            if meta.len() > max_wal_bytes {
                self.post_scan_checkpoint()?;
                return Ok(true);
            }
        }
        Ok(false)
    }
}
```

**Configuration**: `wal_autocheckpoint=1000` (default) handles normal operation. `post_scan_checkpoint()` is called explicitly after scan completion. `emergency_checkpoint(100MB)` is checked periodically as a safety net.

**Evidence**:
- SQLite WAL Checkpoint API: https://www.sqlite.org/c3ref/wal_checkpoint_v2.html
- Litestream WAL strategy: https://litestream.io/guides/wal-truncate-threshold/

---

### R19: Concurrent Process Safety

**Priority**: P0
**Effort**: Low
**Impact**: Prevents data corruption when multiple drift processes access the same database

**What to Build**:
A process-level lock file that prevents concurrent scans while allowing concurrent reads.

```rust
use std::fs::OpenOptions;

pub struct ProcessLock {
    lock_path: PathBuf,
    _file: Option<std::fs::File>,
}

impl ProcessLock {
    /// Acquire exclusive scan lock. Returns Err if another scan is running.
    pub fn acquire_scan_lock(drift_dir: &Path) -> Result<Self> {
        let lock_path = drift_dir.join("drift.db.lock");
        
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(&lock_path)?;
        
        // Try to acquire exclusive file lock (non-blocking)
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = file.as_raw_fd();
            let result = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
            if result != 0 {
                return Err(DriftError::ConcurrentScan(
                    "Another drift scan is already running. Wait for it to complete or use --force.".into()
                ));
            }
        }
        
        #[cfg(windows)]
        {
            // Windows file locking via LockFileEx
            use std::os::windows::io::AsRawHandle;
            // ... platform-specific locking
        }
        
        // Write PID and timestamp for diagnostics
        use std::io::Write;
        let mut f = &file;
        writeln!(f, "pid={}", std::process::id())?;
        writeln!(f, "started={}", chrono::Utc::now().to_rfc3339())?;
        
        Ok(Self { lock_path, _file: Some(file) })
    }
}

impl Drop for ProcessLock {
    fn drop(&mut self) {
        // Lock is automatically released when file handle is dropped
        self._file.take();
        let _ = std::fs::remove_file(&self.lock_path);
    }
}
```

**Design decisions**:
- Read operations (MCP tools, CLI queries) do NOT acquire the lock — WAL mode handles read concurrency
- Only scan operations acquire the exclusive lock — prevents two scans from corrupting data
- Lock is automatically released on process exit (even crash) via OS file lock semantics
- `--force` flag allows overriding the lock (for stuck processes)
- PID and timestamp in lock file enable diagnostics (`drift doctor` can detect stale locks)

**Evidence**:
- SQLite File Locking: https://sqlite.org/lockingv3.html
- SQLite Concurrency: https://openillumi.com/en/en-sqlite-concurrency-wal-mode/

---

### R20: Graceful Error Handling for Storage Operations

**Priority**: P0
**Effort**: Medium
**Impact**: Prevents data loss and provides actionable error messages

**What to Build**:
A comprehensive error handling strategy for all SQLite error codes.

```rust
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("Database is busy (another process is writing). Retrying...")]
    Busy,
    
    #[error("Disk is full. Run `drift doctor` to free space via retention policies and VACUUM.")]
    DiskFull,
    
    #[error("Database is corrupt. Attempting automatic restore from backup...")]
    Corrupt { backup_available: bool },
    
    #[error("I/O error: {detail}. Check disk permissions and available space.")]
    IoError { detail: String },
    
    #[error("Database is read-only: {reason}")]
    ReadOnly { reason: String },
    
    #[error("Schema migration failed at version {version}: {detail}")]
    MigrationFailed { version: i32, detail: String },
    
    #[error("Another drift scan is already running (PID {pid})")]
    ConcurrentScan { pid: u32 },
}

impl DatabaseManager {
    fn handle_error(&self, err: rusqlite::Error) -> StorageError {
        match err {
            rusqlite::Error::SqliteFailure(e, msg) => match e.code {
                ErrorCode::DatabaseBusy => StorageError::Busy,
                ErrorCode::DatabaseFull => StorageError::DiskFull,
                ErrorCode::DatabaseCorrupt => {
                    // Attempt automatic restore
                    let backup_available = self.try_auto_restore().is_ok();
                    StorageError::Corrupt { backup_available }
                }
                ErrorCode::IoError => StorageError::IoError {
                    detail: msg.unwrap_or_default(),
                },
                ErrorCode::ReadOnly => StorageError::ReadOnly {
                    reason: msg.unwrap_or_default(),
                },
                _ => StorageError::IoError {
                    detail: format!("{}: {}", e.code, msg.unwrap_or_default()),
                },
            },
            _ => StorageError::IoError { detail: err.to_string() },
        }
    }
    
    fn try_auto_restore(&self) -> Result<()> {
        // 1. Find most recent backup
        // 2. Verify backup integrity
        // 3. Restore from backup
        // 4. Log the auto-restore event
        // 5. Notify user that data since last backup may be lost
    }
}
```

**Key behaviors**:
- `SQLITE_BUSY`: Already handled by `busy_timeout=5000`. If still busy after timeout, surface error with PID of blocking process
- `SQLITE_FULL`: Surface actionable message — run `drift doctor` which triggers retention + VACUUM
- `SQLITE_CORRUPT`: Attempt automatic restore from most recent backup. If no backup, suggest `drift reset`
- `SQLITE_IOERR`: Surface OS-level error details for debugging
- All errors are logged with full context (operation, table, parameters)

**Evidence**:
- SQLite Result Codes: https://www.sqlite.org/rescode.html
- SQLite Recovery: https://sqlite.org/recovery.html

---

### R21: v1→v2 Upgrade Path (`drift upgrade`)

**Priority**: P0
**Effort**: Medium
**Impact**: Enables existing v1 users to migrate to v2 without data loss

**What to Build**:
A `drift upgrade` command that migrates v1 data to v2 format.

```rust
pub struct UpgradeManager {
    drift_dir: PathBuf,
}

impl UpgradeManager {
    pub fn detect_v1_state(&self) -> V1State {
        let has_json = self.drift_dir.join("patterns").exists();
        let has_sqlite = self.drift_dir.join("drift.db").exists();
        let has_lake = self.drift_dir.join("lake").exists();
        let has_manifest = self.drift_dir.join("manifest.json").exists();
        
        match (has_json, has_sqlite) {
            (true, false) => V1State::JsonOnly,
            (true, true) => V1State::Hybrid,
            (false, true) => V1State::SqliteOnly,
            (false, false) => V1State::Fresh,
        }
    }
    
    pub fn upgrade(&self) -> Result<UpgradeResult> {
        let state = self.detect_v1_state();
        let mut result = UpgradeResult::default();
        
        // 1. Create backup of everything
        result.backup_path = self.create_full_backup()?;
        
        // 2. Create v2 schema (or migrate existing)
        match state {
            V1State::Fresh => {
                self.create_v2_database()?;
            }
            V1State::SqliteOnly | V1State::Hybrid => {
                // Run schema migrations to add v2 tables/columns
                self.run_schema_migrations()?;
                
                if state == V1State::Hybrid {
                    // Migrate any JSON-only data to SQLite
                    result.json_migrated = self.migrate_json_to_sqlite()?;
                }
            }
            V1State::JsonOnly => {
                self.create_v2_database()?;
                result.json_migrated = self.migrate_json_to_sqlite()?;
            }
        }
        
        // 3. Migrate quality gate data (JSON → SQLite)
        result.quality_gates_migrated = self.migrate_quality_gates()?;
        
        // 4. Migrate constraint data (JSON → SQLite)
        result.constraints_migrated = self.migrate_constraints()?;
        
        // 5. Archive v1 files
        result.archived_files = self.archive_v1_files()?;
        
        // 6. Verify migration
        result.verified = self.verify_migration()?;
        
        // 7. Update .gitignore
        self.update_gitignore()?;
        
        Ok(result)
    }
    
    fn migrate_quality_gates(&self) -> Result<usize> {
        // Read .drift/quality-gates/snapshots/{branch}/*.json
        // Insert into quality_gate_snapshots table
        // Read .drift/quality-gates/history/runs/*.json
        // Insert into quality_gate_runs table
    }
    
    fn migrate_constraints(&self) -> Result<usize> {
        // Read .drift/constraints/{category}.json
        // Insert into constraints table
    }
    
    fn archive_v1_files(&self) -> Result<Vec<PathBuf>> {
        // Move .drift/patterns/, .drift/contracts/, .drift/lake/, etc.
        // to .drift/.v1-archive/
    }
}
```

**Evidence**:
- V1 overview.md: migration path for JSON-only, hybrid, and SQLite-only users
- V1 removal-plan.md: 13-step migration order

---

### R22: Monorepo Support via Packages Table

**Priority**: P1
**Effort**: Low
**Impact**: Enables per-package analysis in monorepo codebases

**What to Build**:
A `packages` table that registers monorepo packages and enables per-package filtering.

```sql
CREATE TABLE packages (
    name TEXT PRIMARY KEY,
    path TEXT NOT NULL,              -- Relative path from project root
    package_manager TEXT,            -- npm, yarn, pnpm, cargo, pip, etc.
    version TEXT,
    dependencies TEXT,               -- JSON array of dependency names
    dev_dependencies TEXT,           -- JSON array
    language TEXT,                   -- Primary language
    framework TEXT,                  -- Primary framework (if detected)
    pattern_count INTEGER DEFAULT 0,
    function_count INTEGER DEFAULT 0,
    last_scanned TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

-- Enable per-package pattern queries
CREATE INDEX idx_file_metadata_package ON file_metadata(
    -- Derived from path prefix matching against packages.path
);
```

**Package detection**: Auto-detect packages by scanning for `package.json`, `Cargo.toml`, `pyproject.toml`, `go.mod`, `pom.xml` in subdirectories. Register each as a package with its dependencies.

**Per-package analysis**: Filter patterns, functions, and security data by package path prefix. Enable `drift status --package=@myorg/api` for focused analysis.

**Evidence**:
- V1 overview.md: `packages` table listed as new v2 table
- V1 removal-plan.md: monorepo package registry

---

### R23: Feature Flags Table

**Priority**: P2
**Effort**: Trivial
**Impact**: Enables runtime feature toggling without config file changes

**What to Build**:
A `feature_flags` table for runtime feature control.

```sql
CREATE TABLE feature_flags (
    feature TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 1,
    config TEXT,                     -- JSON for feature-specific config
    description TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

-- Default flags
INSERT INTO feature_flags (feature, enabled, description) VALUES
    ('incremental_scan', 1, 'Skip unchanged files during scans'),
    ('materialized_views', 1, 'Use materialized status tables for instant queries'),
    ('cortex_integration', 1, 'Enable AI memory system'),
    ('sarif_export', 1, 'Enable SARIF output format'),
    ('telemetry', 0, 'Collect anonymous usage statistics'),
    ('experimental_detectors', 0, 'Enable experimental pattern detectors');
```

**API**:
```rust
impl DatabaseManager {
    pub fn is_feature_enabled(&self, feature: &str) -> Result<bool> {
        let reader = self.get_reader()?;
        reader.query_row(
            "SELECT enabled FROM feature_flags WHERE feature = ?1",
            params![feature],
            |row| row.get(0),
        ).optional()?.unwrap_or(false)
    }
    
    pub fn set_feature(&self, feature: &str, enabled: bool) -> Result<()> {
        let writer = self.get_writer()?;
        writer.execute(
            "UPDATE feature_flags SET enabled = ?1, updated_at = datetime('now') WHERE feature = ?2",
            params![enabled as i32, feature],
        )?;
        Ok(())
    }
}
```

**Evidence**:
- V1 sqlite-schema.md: `feature_flags` table already defined in v1 schema

---

## Phase 7: Context, Global State, and Search

### R24: Global Database for Project Registry

**Priority**: P1
**Effort**: Low
**Impact**: Enables multi-project switching without opening every project's database

**What to Build**:
A separate `~/.drift/global.db` database for cross-project state. The `project_registry` table lives here, NOT in the per-project `drift.db`.

```sql
-- ~/.drift/global.db
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

**Why separate**: Opening every project's `drift.db` just to list registered projects is wasteful. The global database is tiny (one row per project) and always fast to open. The `ProjectSwitcher` reads from `global.db` for project resolution, then opens the selected project's `drift.db`.

**Migration**: `drift upgrade` reads `~/.drift/registry.json` and inserts rows into `~/.drift/global.db`.

**Evidence**:
- V1 project-registry.ts: `~/.drift/registry.json`
- V1 removal-plan.md: "project-registry.ts → SQLite table (move to `~/.drift/global.db`)"

---

### R25: WorkspaceContext Replacement Strategy

**Priority**: P1
**Effort**: Low
**Impact**: Eliminates `.drift/.context-cache.json` while preserving fast MCP/CLI access

**What to Build**:
Replace the `ContextLoader`'s L2 disk cache (`.drift/.context-cache.json`) with direct reads from `materialized_status` (R2) and `feature_flags` (R23) tables. The `WorkspaceContext` type is served from SQLite, not a JSON cache file.

```rust
#[napi(object)]
pub struct WorkspaceContext {
    pub project: ProjectInfo,
    pub status: StatusSummary,        // From materialized_status table
    pub analysis: AnalysisState,      // From feature_flags + scan_history
    pub loaded_at: String,
}

#[napi]
impl DriftDatabase {
    /// Replaces ContextLoader.getContext() — no disk cache needed
    #[napi]
    pub fn get_workspace_context(&self) -> napi::Result<WorkspaceContext> {
        let reader = self.get_reader()?;
        
        let project = self.get_project_info(&reader)?;
        let status = self.get_materialized_status(&reader)?;
        let analysis = self.get_analysis_state(&reader)?;
        
        Ok(WorkspaceContext {
            project,
            status,
            analysis,
            loaded_at: chrono::Utc::now().to_rfc3339(),
        })
    }
}
```

**Why this works**: SQLite reads from `materialized_status` are sub-millisecond (singleton row, in page cache). The L1 in-memory cache can be preserved in the Rust `DatabaseManager` for repeated access within the same process. The L2 disk cache is unnecessary because SQLite IS the disk cache.

**Evidence**:
- V1 ContextLoader: L1 in-memory + L2 `.drift/.context-cache.json`
- V1 overview.md: `.drift/.context-cache.json` listed as removed in v2

---

### R26: Pattern Search via LIKE and Expression Indexes

**Priority**: P2
**Effort**: Low
**Impact**: Enables the `search_patterns(query)` read operation from rust-ownership.md

**What to Build**:
Pattern search using SQLite's `LIKE` operator with expression indexes. Full-text search (FTS5) is overkill for Drift's search volume — `LIKE` with proper indexes is sufficient.

```rust
impl DatabaseManager {
    pub fn search_patterns(&self, query: &str, limit: usize) -> Result<Vec<PatternRow>> {
        let reader = self.get_reader()?;
        let search = format!("%{}%", query);
        
        let mut stmt = reader.prepare_cached("
            SELECT * FROM patterns
            WHERE name LIKE ?1
               OR description LIKE ?1
               OR category LIKE ?1
               OR subcategory LIKE ?1
            ORDER BY confidence_score DESC
            LIMIT ?2
        ")?;
        
        stmt.query_map(params![search, limit as i64], |row| {
            PatternRow::from_row(row)
        })?.collect()
    }
}
```

**If search volume grows**: Add FTS5 virtual table as an index over pattern names and descriptions:
```sql
CREATE VIRTUAL TABLE patterns_fts USING fts5(name, description, category, content=patterns, content_rowid=rowid);
```
This is a v2.1 optimization — start with `LIKE` and measure.

**Evidence**:
- V1 rust-ownership.md: `search_patterns(query)` listed as a read operation
- SQLite FTS5: https://www.sqlite.org/fts5.html

---

### R27: Backup Manifest and Reason Tracking

**Priority**: P2
**Effort**: Trivial
**Impact**: Preserves v1 BackupManager's enterprise features in v2

**What to Build**:
Extend R8's backup system with backup reasons and a manifest.

```rust
#[derive(Debug, Clone, Copy)]
pub enum BackupReason {
    VersionUpgrade,
    SchemaMigration,
    UserRequested,
    PreDestructiveOperation,
    Scheduled,
    AutoSave,
}

pub struct BackupResult {
    pub id: String,                    // "backup-{timestamp}-{reason}"
    pub path: PathBuf,
    pub size: u64,
    pub duration: Duration,
    pub checksum: String,              // SHA-256 of backup file
    pub reason: BackupReason,
    pub verified: bool,
}

impl DatabaseManager {
    pub fn backup_with_reason(&self, dest_dir: &Path, reason: BackupReason) -> Result<BackupResult> {
        let timestamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
        let reason_str = reason.as_str();
        let filename = format!("drift-{}-{}.db", timestamp, reason_str);
        let dest_path = dest_dir.join(&filename);
        
        let result = self.backup(&dest_path)?;
        
        // Compute SHA-256 checksum
        let checksum = compute_sha256(&dest_path)?;
        
        Ok(BackupResult {
            id: filename,
            path: dest_path,
            size: result.size,
            duration: result.duration,
            checksum,
            reason,
            verified: result.verified,
        })
    }
}
```

**Retention**: Keep last N backups per reason category (default: 5 total). Auto-delete oldest when limit exceeded.

**Evidence**:
- V1 BackupManager: SHA-256 checksums, gzip compression, 6 backup reasons, backup-manifest.json
- V1 workspace/overview.md: enterprise-grade backup with retention

---

### R28: Consumer Update Checklist (Non-Code Recommendation)

**Priority**: P0 (Documentation)
**Effort**: N/A (tracking only)
**Impact**: Ensures no consumer is missed during v2 migration

**What to Track**:
Every consumer that reads from or writes to storage must be updated when the storage layer changes. This is a checklist, not code.

| Consumer | Current Source | V2 Source | Status |
|----------|---------------|-----------|--------|
| `drift_status` MCP tool | manifest.json | `materialized_status` table via NAPI | Pending |
| `drift_patterns_list` MCP tool | pattern shards | `patterns` table via NAPI | Pending |
| `drift_file_patterns` MCP tool | file index | `pattern_locations` JOIN via NAPI | Pending |
| `drift_security_summary` MCP tool | security shards | `materialized_security` table via NAPI | Pending |
| `drift_code_examples` MCP tool | examples store | `pattern_examples` table via NAPI | Pending |
| `drift scan` CLI | writes JSON + SQLite | writes SQLite only via Rust | Pending |
| `drift status` CLI | reads manifest | reads `materialized_status` via NAPI | Pending |
| `drift approve/ignore` CLI | updates JSON + SQLite | updates SQLite only via NAPI | Pending |
| `drift backup` CLI | copies JSON dirs | SQLite backup API via NAPI | Pending |
| `drift migrate-storage` CLI | JSON → SQLite | becomes `drift upgrade` (R21) | Pending |
| Detectors | return patterns → PatternStore | return patterns → Rust BatchWriter | Pending |
| Quality Gates | read JSON snapshots | read SQLite tables | Pending |
| Cortex | own SQLite connection | unchanged (stays TS-owned) | No change |

**Evidence**:
- V1 removal-plan.md: "Consumers That Need Updating" section

---

### R29: clear_and_rebuild(domain) Write Operation

**Priority**: P1
**Effort**: Low
**Impact**: Enables domain-level data refresh without full database rebuild

**What to Build**:
A `clear_and_rebuild(domain)` operation that deletes all rows for a specific domain and re-inserts fresh data. Used when a domain's data is fully recomputed (e.g., after a full scan of call graph).

```rust
pub enum Domain {
    Patterns,
    CallGraph,
    Contracts,
    Boundaries,
    Environment,
    DNA,
    TestTopology,
    Constants,
    Coupling,
    Errors,
    Wrappers,
}

impl DatabaseManager {
    pub fn clear_and_rebuild(&self, domain: Domain, data: WriteBatch) -> Result<RebuildStats> {
        let writer = self.get_writer()?;
        let tx = writer.transaction_with_behavior(TransactionBehavior::Immediate)?;
        
        // Delete all rows for the domain
        let deleted = match domain {
            Domain::Patterns => {
                tx.execute("DELETE FROM pattern_locations", [])?;
                tx.execute("DELETE FROM pattern_examples", [])?;
                tx.execute("DELETE FROM pattern_variants", [])?;
                tx.execute("DELETE FROM patterns", [])?
            }
            Domain::CallGraph => {
                tx.execute("DELETE FROM function_data_access", [])?;
                tx.execute("DELETE FROM function_calls", [])?;
                tx.execute("DELETE FROM functions", [])?
            }
            // ... other domains
            _ => 0,
        };
        
        // Insert fresh data
        let inserted = self.insert_batch_in_tx(&tx, data)?;
        
        tx.commit()?;
        
        Ok(RebuildStats { domain, deleted, inserted })
    }
}
```

**Key design**: The delete + insert happens in a single IMMEDIATE transaction, so readers always see either the old data or the new data, never an empty state.

**Evidence**:
- V1 rust-ownership.md: `clear_and_rebuild(domain)` listed as a write operation

---

## Build Order

```
Phase 0 (Architecture):  FA1 + FA2 + FA3           [Connection pool, migrations, STRICT tables]
Phase 1 (Core):          R1 → R2 → R3 → R4         [Schema, materialized tables, batch writer, file index]
Phase 2 (Query):         R5 → R6 → R7              [Keyset pagination, prepared statements, JSON indexes]
Phase 3 (Safety):        R8 → R9                    [Hot backup, integrity validation]
Phase 4 (Integration):   R10 → R11                  [ATTACH cortex, embedding cache]
Phase 5 (Bridge):        R12 → R13 → R14 → R15 → R16 [NAPI, telemetry, SARIF, retention, lock file]
Phase 6 (Operations):    R17 → R18 → R19 → R20 → R21 → R22 → R23 [VACUUM, WAL checkpoint, process safety, error handling, upgrade, monorepo, feature flags]
Phase 7 (Context):       R24 → R25 → R26 → R27 → R28 → R29 [Global DB, workspace context, search, backup manifest, consumer checklist, clear_and_rebuild]
```

---

## Dependency Graph

```
FA1 (Connection Pool) ──→ ALL subsystems
FA2 (Migrations) ────────→ R1 (Schema)
FA3 (STRICT) ────────────→ R1 (Schema)

R1 (Schema) ─────→ R2 (Materialized Tables)
R1 (Schema) ─────→ R3 (Batch Writer)
R1 (Schema) ─────→ R4 (File Index)
R1 (Schema) ─────→ R5 (Keyset Pagination)
R1 (Schema) ─────→ R7 (JSON Indexes)

FA1 (Connection Pool) ──→ R6 (Prepared Statements)
FA1 (Connection Pool) ──→ R8 (Hot Backup)
FA1 (Connection Pool) ──→ R9 (Integrity Validation)
FA1 (Connection Pool) ──→ R10 (ATTACH Cortex)

R1 + R2 + R3 + R4 + R5 ──→ R12 (NAPI Bridge)
R12 (NAPI) ──→ R13 (Telemetry)
R1 (Schema) ──→ R14 (SARIF Export)
R1 (Schema) ──→ R15 (Retention)
R1 (Schema) ──→ R16 (Lock File)

R15 (Retention) ──→ R17 (VACUUM Strategy)
FA1 (Connection Pool) ──→ R18 (WAL Checkpoint)
FA1 (Connection Pool) ──→ R19 (Process Safety)
FA1 (Connection Pool) ──→ R20 (Error Handling)
R8 (Backup) + R20 (Error Handling) ──→ R21 (Upgrade Path)
R1 (Schema) ──→ R22 (Monorepo Support)
R1 (Schema) ──→ R23 (Feature Flags)

FA1 (Connection Pool) ──→ R24 (Global Database)
R2 (Materialized Tables) + R23 (Feature Flags) ──→ R25 (Workspace Context)
R1 (Schema) + R6 (Prepared Statements) ──→ R26 (Pattern Search)
R8 (Hot Backup) ──→ R27 (Backup Manifest)
R12 (NAPI) ──→ R28 (Consumer Checklist)
R3 (Batch Writer) ──→ R29 (clear_and_rebuild)
```

---

## Performance Targets

| Operation | V1 (JSON) | V1 (SQLite) | V2 Target | How |
|-----------|-----------|-------------|-----------|-----|
| Load all patterns | 200-800ms | 50-150ms | 10-30ms | Rust + mmap + prepared statements |
| Find pattern by ID | O(n) scan | O(1) index | O(1) index | Same, but faster via Rust |
| Find patterns by file | O(n×m) scan | O(log n) | O(log n) | Same, but faster via Rust |
| Insert 10k patterns | 500ms+ | 100-200ms | 20-50ms | Batch writer + IMMEDIATE transactions |
| Status query | 100-300ms | 5-10ms | <1ms | Materialized table (R2) |
| Pattern search (complex) | N/A | 100ms | 10ms | Prepared statements + indexes |
| Call graph build (50k fn) | N/A | 15s | 2s | Parallel writer + rayon |
| Backup (50MB DB) | 2s (file copy) | 2s (file copy) | 200ms | SQLite backup API (R8) |
| Incremental scan (10 files changed) | Full rescan | Full rescan | <500ms | File index + content hashing (R4) |

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Schema migration failure corrupts DB | Low | Critical | Auto-backup before migration (R8), integrity check after (R9) |
| WAL file grows unbounded | Medium | Medium | Two-tier checkpoint strategy (R18): autocheckpoint + post-scan TRUNCATE |
| Concurrent write contention | Low | Medium | Single writer with Mutex (FA1), IMMEDIATE transactions (R3), process lock (R19) |
| Database corruption from crash | Low | High | WAL + NORMAL sync provides crash recovery, integrity check on startup (R9), auto-restore from backup (R20) |
| NAPI serialization overhead | Medium | Low | Use serde_json for zero-copy where possible, batch operations (R12) |
| Cortex ATTACH performance | Low | Low | On-demand ATTACH, not permanent (R10) |
| Database size exceeds expectations | Low | Medium | Retention policies (R15), VACUUM after large deletes (R17) |
| Disk full during scan | Low | High | Graceful SQLITE_FULL handling (R20), actionable error message |
| Two drift processes corrupt data | Medium | High | Process-level lock file (R19), WAL for read concurrency |
| v1→v2 upgrade loses data | Low | Critical | Full backup before upgrade (R21), verification step, archive (not delete) v1 files |
| Stale lock file from crashed process | Low | Low | PID-based stale detection in `drift doctor`, `--force` override |
| Recursive CTE infinite loop on cyclic graph | Low | Medium | max_depth parameter, cycle detection in reachability queries |
| Consumer missed during migration | Medium | Medium | R28 consumer checklist tracks every consumer with status |
| Global DB and project DB version mismatch | Low | Low | R24 global.db stores schema_version per project, validated on open |

---

## Quality Checklist

- [x] All v1 storage files accounted for (6 backends, ~35 files, ~12,000 lines)
- [x] All v2 notes from every source document addressed
- [x] All limitations from RECAP resolved in recommendations
- [x] Every recommendation framed as "build new" not "migrate/port"
- [x] External evidence cited for every architectural decision (21 sources across Tiers 1-3)
- [x] Build order defined with dependency graph
- [x] Performance targets defined with specific metrics
- [x] Risk assessment with mitigations (12 risks identified)
- [x] No feature deferred to "add later" — everything built into the right phase
- [x] Traceability: every source doc maps to at least one recommendation
- [x] Full-circle impact analysis: how each decision affects the rest of the pipeline
- [x] **AUDIT PASS 2**: VACUUM strategy with freelist monitoring (R17)
- [x] **AUDIT PASS 2**: WAL checkpoint strategy — two-tier PASSIVE + TRUNCATE (R18)
- [x] **AUDIT PASS 2**: Concurrent process safety via lock file (R19)
- [x] **AUDIT PASS 2**: Graceful error handling for all SQLite error codes (R20)
- [x] **AUDIT PASS 2**: v1→v2 upgrade path with quality gate + constraint migration (R21)
- [x] **AUDIT PASS 2**: Monorepo support via packages table (R22)
- [x] **AUDIT PASS 2**: Feature flags table for runtime toggling (R23)
- [x] **AUDIT PASS 2**: sync_log repurposing addressed in R21 upgrade path
- [x] **AUDIT PASS 2**: drift.lock validation (lock vs DB comparison) addressed in R16
- [x] **AUDIT PASS 2**: Quality gate JSON→SQLite migration addressed in R21
- [x] **AUDIT PASS 2**: Constraint store JSON→SQLite migration addressed in R21
- [x] **AUDIT PASS 2**: Boundary store persistence changes addressed in R1 (schema carries forward boundary tables)
- [x] **AUDIT PASS 3**: Global database (~/.drift/global.db) for project_registry addressed in R24
- [x] **AUDIT PASS 3**: WorkspaceContext / ContextLoader replacement addressed in R25
- [x] **AUDIT PASS 3**: search_patterns(query) full-text search addressed in R26
- [x] **AUDIT PASS 3**: BackupManager enterprise features (reasons, manifest, checksums) addressed in R27
- [x] **AUDIT PASS 3**: Consumer update enumeration addressed in R28 (5 MCP tools, 5 CLI commands, detectors, quality gates)
- [x] **AUDIT PASS 3**: clear_and_rebuild(domain) write operation addressed in R29
- [x] **AUDIT PASS 3**: Violation data model confirmed as ephemeral (not stored) — no recommendation needed
- [x] **AUDIT PASS 3**: Pattern ID generation, confidence thresholds, PatternFile structure — documented in RECAP, no recommendation needed (storage-agnostic)
- [x] **AUDIT PASS 3**: Cortex queries.ts and factory.ts — documented in RECAP, no recommendation needed (Cortex stays TS-owned)
- [x] **AUDIT PASS 3**: Repository interface methods — documented in RECAP, covered by R12 NAPI bindings
- [x] **AUDIT PASS 3**: DataLake facade refactoring — subsumed by R12 NAPI bindings
- [x] **AUDIT PASS 3**: migration.ts temporary keep timeline — documented in RECAP (remove in v2.1)
- [x] **AUDIT PASS 3**: SchemaMigrator v1 lifecycle — documented in RECAP, superseded by FA2
- [x] **AUDIT PASS 3**: Total recommendations increased from 23 to 29, phases from 7 to 8, risks from 12 to 14
