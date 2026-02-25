# 24 Data Lake — V2 Build Recommendations

> **Context**: Drift v2 is a greenfield build. These recommendations define how to BUILD the data lake replacement layer from scratch using best practices, informed by v1's architecture (treated as a requirements specification) and external research from 27 Tier 1-3 sources. Every recommendation is framed as "build new" not "migrate/port." The v1 Data Lake (~4,570 lines TypeScript, 11 files, 30+ JSON files on disk) is eliminated entirely. Its architectural concepts — pre-computation, selective loading, incremental materialization, query routing — are preserved and implemented natively in SQLite.

## Summary

30 recommendations organized into 9 build phases. The data lake layer is the bridge between raw analysis data and every consumer in the system — MCP tools, CLI commands, quality gates, dashboard, and Cortex. Getting this layer right determines whether Drift v2 delivers sub-millisecond query responses or regresses to v1's cold-cache latency problems. The v1 Data Lake's core insight — pre-compute common queries and load only what you need — is preserved. The implementation changes from JSON files to SQLite materialized tables, covering indexes, partial indexes, generated columns, and explicit refresh pipelines. Phase 0 establishes the architectural foundation (medallion architecture, CQRS, ownership model). Phases 1-3 build the Gold layer schema, index strategy, and materialization pipeline. Phases 4-6 add generated columns, cache warming, and incremental invalidation. Phases 7-8 handle operational safety and consumer migration.

---

## Phase 0: Architectural Decisions

### AD1: Adopt Medallion Architecture (Bronze / Silver / Gold)

**Priority**: P0 (Build First)
**Effort**: Low (conceptual — no code, just table classification)
**Impact**: Establishes the data flow model that every other recommendation builds on

**Current State**:
V1's Data Lake intuitively implements a three-layer model: raw scan results → stored analysis data → pre-computed views/indexes/shards. But the layers are not formalized — there's no clear boundary between "analysis data" and "consumption data." The ViewMaterializer rebuilds views from raw patterns, but the boundary between what's a "source table" and what's a "derived table" is implicit.

**Proposed Change**:
Formally classify every table in `drift.db` into one of three medallion layers:

| Layer | Purpose | Write Optimization | Read Optimization | Tables |
|-------|---------|-------------------|-------------------|--------|
| **Bronze** | Raw scan ingestion | Batch insert throughput, minimal indexes | Not optimized for reads | `scan_results` (temporary staging), `raw_pattern_matches` (append-only during detection) |
| **Silver** | Normalized analysis data | Schema-enforced (STRICT + CHECK), foreign keys, referential integrity | Standard B-tree indexes for filtered queries | `patterns`, `pattern_locations`, `pattern_examples`, `functions`, `call_edges`, `data_access`, `sensitive_fields`, `data_models`, `data_access_points`, `contracts`, `contract_frontends`, `constraints`, `env_variables`, `file_metadata` |
| **Gold** | Pre-computed consumption layer | Refreshed explicitly after scans (not during) | Covering indexes, partial indexes, materialized tables | `materialized_status`, `materialized_security`, `health_trends`, covering indexes on Silver tables, generated columns |

**Key rules**:
1. Bronze → Silver transformation happens during scan (detectors/parsers write directly to Silver tables via batch writer)
2. Silver → Gold transformation happens after scan completion (explicit refresh call)
3. Gold tables are read-only from the consumer perspective — only the refresh pipeline writes to them
4. Bronze tables are ephemeral — cleared at scan start, populated during scan, consumed during Silver writes
5. Silver tables are the source of truth — Gold tables can always be rebuilt from Silver

**Rationale**:
The medallion architecture is the industry standard for data lakehouse design. It formalizes what v1 did intuitively, making the data flow explicit and enabling independent optimization of each layer. Write-heavy operations (scan) only touch Bronze/Silver. Read-heavy operations (MCP/CLI) only touch Gold + Silver indexes.

**Evidence**:
- Databricks Medallion Architecture: https://docs.databricks.com/aws/en/lakehouse/medallion (DL-R6)
- Databricks Glossary — Medallion: https://www.databricks.com/glossary/medallion-architecture (DL-R6)
- Delta Lake ACID principles: https://www.databricks.com/blog/delta-lake-explained-boost-data-reliability-cloud-storage (DL-R15)

**Implementation Notes**:
- Add a `-- Layer: Bronze/Silver/Gold` comment above each CREATE TABLE in the schema SQL files
- Document the layer classification in the schema migration README
- The Bronze layer may be implicit in v2.0 — detectors can write directly to Silver tables if no staging is needed. Bronze becomes explicit only if scan performance requires a two-phase write (stage → merge)

**Risks**:
- Over-engineering the Bronze layer for a single-machine tool. Start with Bronze as implicit (direct Silver writes) and add explicit Bronze staging only if bulk insert performance requires it.

**Dependencies**:
- 08-storage (schema design, table ownership)
- 25-services (scan pipeline orchestration)

---

### AD2: Implement Explicit CQRS Pattern (Read/Write Separation)

**Priority**: P0 (Build First)
**Effort**: Low (architectural pattern, not new code)
**Impact**: Defines the contract between scan pipeline (writes) and consumers (reads)

**Current State**:
V1 implicitly separates reads and writes: the scan pipeline writes to PatternStore/ContractStore/CallGraphDb, then the ViewMaterializer transforms that data into read-optimized views/indexes/shards. But this separation is not enforced — any component can read or write any store.

**Proposed Change**:
Make CQRS explicit in v2's `DatabaseManager`:

```rust
impl DatabaseManager {
    // WRITE PATH — used only by scan pipeline
    pub fn writer(&self) -> MutexGuard<Connection> {
        // Returns the single write connection
        // All write operations go through this path
        // Connection has full read/write access
    }

    // READ PATH — used by MCP tools, CLI, quality gates
    pub fn reader(&self) -> MutexGuard<Connection> {
        // Returns a read connection from the pool
        // Connection has PRAGMA query_only = ON
        // Can only SELECT from Silver + Gold tables
    }

    // REFRESH PATH — bridges write to read model
    pub fn refresh_read_model(&self) -> Result<RefreshResult> {
        // Called after scan completion
        // Rebuilds Gold layer from Silver layer
        // Uses the write connection (needs INSERT/UPDATE on Gold tables)
    }
}
```

**The three paths**:
1. **Write path** (`drift scan`): Detectors/parsers → `writer()` → Silver tables → `refresh_read_model()` → Gold tables
2. **Read path** (MCP/CLI): Consumer → `reader()` → Gold tables (materialized) + Silver tables (indexed)
3. **Refresh path** (post-scan): `refresh_read_model()` → rebuilds `materialized_status`, `materialized_security`, updates `health_trends`

**Rationale**:
CQRS is the natural pattern for Drift's scan-then-query workload. Scans are discrete batch events (write-heavy, seconds to minutes). Queries are continuous interactive events (read-heavy, sub-millisecond target). Separating these paths enables independent optimization: the write path uses `BEGIN IMMEDIATE` transactions with minimal indexes; the read path uses covering indexes and materialized tables.

**Evidence**:
- Martin Fowler — CQRS pattern (DL-R10)
- SQLite WAL mode enables concurrent reads during writes: https://www.sqlite.org/wal.html
- V1 already uses separate write (ParallelWriter) and read (QueryEngine) paths

**Implementation Notes**:
- Read connections use `PRAGMA query_only = ON` to prevent accidental writes from consumer code
- WAL mode enables readers to continue during write transactions without blocking
- The refresh path acquires the write connection because it INSERT/REPLACE into Gold tables
- Consider adding a `is_refreshing` flag to prevent concurrent refresh calls

**Risks**:
- Stale reads between scan completion and refresh completion. Mitigation: refresh is fast (<100ms for typical projects) and consumers tolerate brief staleness.

**Dependencies**:
- 08-storage (DatabaseManager, connection pool)
- 25-services (scan pipeline triggers refresh)
- 07-mcp (reads from Gold layer)

---

### AD3: Build Ownership-Based Invalidation Model

**Priority**: P0 (Build First)
**Effort**: Medium
**Impact**: Enables O(changes) incremental scanning instead of O(repository) full rebuilds

**Current State**:
V1's ManifestStore tracks file hashes (SHA-256) for change detection, but the invalidation model is coarse-grained: when any file changes, all views are marked stale and fully rebuilt. There's no tracking of which patterns/functions/call edges came from which file.

**Proposed Change**:
Build a file-ownership model where every derived fact (pattern, function, call edge, data access point) is linked to the source file that produced it. When a file changes, only its owned facts are invalidated and re-derived.

```sql
-- File metadata table (the ownership registry)
CREATE TABLE file_metadata (
    path TEXT PRIMARY KEY,
    language TEXT,
    byte_size INTEGER NOT NULL,
    line_count INTEGER,
    content_hash TEXT NOT NULL,          -- xxhash64 (faster than SHA-256)
    last_modified TEXT NOT NULL,         -- ISO-8601 from filesystem mtime
    last_scanned_at TEXT,               -- When Drift last processed this file
    scan_duration_us INTEGER,           -- Microseconds to scan this file
    pattern_count INTEGER DEFAULT 0,    -- Counter cache: patterns from this file
    function_count INTEGER DEFAULT 0,   -- Counter cache: functions from this file
    error TEXT                          -- Last scan error for this file, if any
) STRICT;
```

**Ownership links** (already exist via foreign keys in Silver tables):
- `pattern_locations.file` → file that contains this pattern location
- `functions.file` → file that defines this function
- `call_edges.caller_file` → file containing the call site
- `data_access.file` → file containing the data access

**Incremental scan flow**:
```
1. Walk filesystem → collect (path, mtime, size) tuples
2. Compare against file_metadata table:
   a. mtime unchanged → SKIP (fast path, ~95% of files)
   b. mtime changed → compute xxhash64 of content
   c. content_hash unchanged → UPDATE mtime only, SKIP scan
   d. content_hash changed → MARK for re-scan
   e. file not in table → NEW file, MARK for scan
   f. file in table but not on disk → DELETED, MARK for cleanup
3. For each DELETED file:
   DELETE FROM pattern_locations WHERE file = ?
   DELETE FROM functions WHERE file = ?
   DELETE FROM call_edges WHERE caller_file = ?
   DELETE FROM data_access WHERE file = ?
   DELETE FROM file_metadata WHERE path = ?
4. For each file MARKED for re-scan:
   DELETE owned facts (same as step 3, but keep file_metadata)
   Re-scan file → produce new facts → INSERT into Silver tables
   UPDATE file_metadata SET content_hash = ?, last_scanned_at = ?, ...
5. Refresh Gold layer (only if any files changed)
```

**Rationale**:
This is the same ownership-based invalidation model used by Meta's Glean code indexing system and Google's Kythe. It enables O(changes) incremental scanning — if 5 files changed out of 1000, only those 5 files are re-scanned and only their owned facts are invalidated. V1's full-rebuild approach doesn't scale to large codebases.

**Evidence**:
- Meta Glean — ownership-based invalidation: https://engineering.fb.com/2024/12/19/developer-tools/glean-open-source-code-indexing/ (DL-R8)
- Glean incrementality: https://glean.software/docs/implementation/incrementality/ (DL-R8)
- Kythe storage model — fact ownership: https://kythe.io/docs/kythe-storage.html (DL-R9)
- Salsa — revision tracking for derived data: https://salsa-rs.github.io/salsa/reference/algorithm.html (DL-R13)

**Implementation Notes**:
- Use xxhash64 instead of SHA-256 for content hashing — 10x faster, sufficient for change detection (not security)
- The two-level change detection (mtime first, then content hash) avoids hashing unchanged files
- Counter caches (`pattern_count`, `function_count`) on `file_metadata` enable instant per-file stats without JOINs
- The `error` column captures scan failures per-file, enabling `drift doctor` to report which files failed

**Risks**:
- Orphaned facts if the deletion step fails mid-transaction. Mitigation: wrap the entire per-file invalidation in a single transaction.
- Cross-file dependencies (e.g., a call edge spans two files). Mitigation: invalidate call edges from both caller and callee files when either changes.

**Dependencies**:
- 08-storage (file_metadata table in schema)
- 01-rust-core (scanner uses file_metadata for change detection)
- 25-services (scan pipeline orchestrates incremental flow)


---

## Phase 1: Gold Layer Schema

### GL1: Build Materialized Status Table

**Priority**: P0
**Effort**: Medium
**Impact**: Enables instant `drift_status` responses — the single most common query in the entire system

**Current State**:
V1's StatusView is a JSON file (`views/status.json`) containing pre-computed health score, pattern counts, issue counts, and security risk level. It's rebuilt by the ViewMaterializer after every scan. The first read after process start requires file I/O + JSON parse.

**Proposed Change**:
Build a singleton materialized table that stores the pre-computed status dashboard data. Refreshed explicitly after scan completion, read instantly by MCP tools and CLI.

```sql
CREATE TABLE materialized_status (
    id INTEGER PRIMARY KEY CHECK (id = 1),  -- Singleton constraint
    -- Health metrics
    health_score REAL NOT NULL DEFAULT 0.0,
    health_trend TEXT NOT NULL DEFAULT 'stable'
        CHECK (health_trend IN ('improving', 'stable', 'declining')),
    -- Pattern counts
    total_patterns INTEGER NOT NULL DEFAULT 0,
    approved_patterns INTEGER NOT NULL DEFAULT 0,
    discovered_patterns INTEGER NOT NULL DEFAULT 0,
    ignored_patterns INTEGER NOT NULL DEFAULT 0,
    category_counts TEXT NOT NULL DEFAULT '{}'
        CHECK (json_valid(category_counts)),
    -- Issue counts
    critical_issues INTEGER NOT NULL DEFAULT 0,
    warning_issues INTEGER NOT NULL DEFAULT 0,
    top_issues TEXT NOT NULL DEFAULT '[]'
        CHECK (json_valid(top_issues)),
    -- Security posture
    security_risk_level TEXT NOT NULL DEFAULT 'low'
        CHECK (security_risk_level IN ('low', 'medium', 'high', 'critical')),
    security_violations INTEGER NOT NULL DEFAULT 0,
    sensitive_exposures INTEGER NOT NULL DEFAULT 0,
    -- Last scan info
    last_scan_at TEXT,
    last_scan_duration_ms INTEGER,
    last_scan_files INTEGER,
    last_scan_patterns INTEGER,
    last_scan_incremental INTEGER DEFAULT 0,
    last_scan_changed_files INTEGER,
    -- Metadata
    refreshed_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;
```

**Refresh implementation** (Rust, called after scan completion):
```rust
pub fn refresh_materialized_status(conn: &Connection) -> Result<RefreshResult> {
    let start = Instant::now();
    
    conn.execute_batch("
        INSERT OR REPLACE INTO materialized_status (
            id, health_score, health_trend,
            total_patterns, approved_patterns, discovered_patterns, ignored_patterns,
            category_counts, critical_issues, warning_issues, top_issues,
            security_risk_level, security_violations, sensitive_exposures,
            last_scan_at, last_scan_duration_ms, last_scan_files, last_scan_patterns,
            last_scan_incremental, last_scan_changed_files,
            refreshed_at
        )
        SELECT 
            1,
            -- health_score: weighted average of confidence scores
            COALESCE(
                (SELECT AVG(confidence_score) FROM patterns WHERE status != 'ignored'),
                0.0
            ),
            -- health_trend: compare current vs previous scan
            COALESCE(
                (SELECT CASE 
                    WHEN current_score > prev_score + 0.02 THEN 'improving'
                    WHEN current_score < prev_score - 0.02 THEN 'declining'
                    ELSE 'stable'
                END FROM (
                    SELECT 
                        (SELECT AVG(confidence_score) FROM patterns WHERE status != 'ignored') as current_score,
                        (SELECT health_score FROM health_trends ORDER BY recorded_at DESC LIMIT 1) as prev_score
                )),
                'stable'
            ),
            -- Pattern counts
            (SELECT COUNT(*) FROM patterns),
            (SELECT COUNT(*) FROM patterns WHERE status = 'approved'),
            (SELECT COUNT(*) FROM patterns WHERE status = 'discovered'),
            (SELECT COUNT(*) FROM patterns WHERE status = 'ignored'),
            -- Category counts as JSON
            (SELECT json_group_object(category, cnt) FROM (
                SELECT category, COUNT(*) as cnt FROM patterns GROUP BY category
            )),
            -- Issue counts
            (SELECT COUNT(*) FROM patterns WHERE severity = 'critical' AND status != 'ignored'),
            (SELECT COUNT(*) FROM patterns WHERE severity = 'warning' AND status != 'ignored'),
            -- Top issues as JSON array
            '[]',
            -- Security
            COALESCE((SELECT risk_level FROM materialized_security WHERE id = 1), 'low'),
            (SELECT COUNT(*) FROM security_violations),
            (SELECT COUNT(DISTINCT field_name) FROM sensitive_fields),
            -- Last scan
            (SELECT started_at FROM scan_history ORDER BY started_at DESC LIMIT 1),
            (SELECT duration_ms FROM scan_history ORDER BY started_at DESC LIMIT 1),
            (SELECT files_scanned FROM scan_history ORDER BY started_at DESC LIMIT 1),
            (SELECT patterns_found FROM scan_history ORDER BY started_at DESC LIMIT 1),
            (SELECT incremental FROM scan_history ORDER BY started_at DESC LIMIT 1),
            (SELECT changed_files FROM scan_history ORDER BY started_at DESC LIMIT 1),
            datetime('now')
    ")?;
    
    Ok(RefreshResult {
        table: "materialized_status".into(),
        duration: start.elapsed(),
    })
}
```

**Query from MCP/CLI** (instant — single row read):
```sql
SELECT * FROM materialized_status WHERE id = 1;
```

**Rationale**:
The `drift_status` MCP tool is called on virtually every AI interaction. It must return in <1ms. A materialized table provides O(1) read performance — the same as v1's StatusView JSON file, but with transactional guarantees, no file I/O, and no JSON parsing overhead.

**Evidence**:
- SQLite materialized view pattern via tables: https://madflex.de/SQLite-triggers-as-replacement-for-a-materialized-view/ (DL-R1)
- Counter-cache triggers for aggregate maintenance: https://samuelplumppu.se/blog/using-sqlite-triggers-to-boost-performance-of-select-count (DL-R1)
- Denormalization best practices: https://www.datacamp.com/tutorial/denormalization (DL-R7)

**Implementation Notes**:
- The `CHECK (id = 1)` constraint enforces the singleton pattern — only one row can exist
- JSON columns (`category_counts`, `top_issues`) use `CHECK(json_valid(...))` for integrity
- The refresh query is a single INSERT OR REPLACE — atomic, no partial updates possible
- Health trend calculation compares current score against the most recent `health_trends` entry
- If `materialized_security` hasn't been refreshed yet, `security_risk_level` defaults to 'low'

**Risks**:
- The refresh query is complex (multiple subqueries). If it becomes a performance bottleneck, break it into multiple simpler queries within a single transaction.
- The `top_issues` JSON array requires a more complex query to populate. Start with `'[]'` and add the query in a follow-up iteration.

**Dependencies**:
- 08-storage (schema definition)
- 25-services (scan pipeline triggers refresh)
- 07-mcp (`drift_status` tool reads this table)
- 10-cli (`drift status` command reads this table)

---

### GL2: Build Materialized Security Table

**Priority**: P0
**Effort**: Medium
**Impact**: Enables instant `drift_security_summary` responses — critical for security-focused AI interactions

**Current State**:
V1's SecuritySummaryView is a JSON file containing pre-computed security posture: risk level, table counts, access points, sensitive fields, violations. Rebuilt by the ViewMaterializer using data from SecurityShardStore.

**Proposed Change**:
Build a singleton materialized table for security posture data, following the same pattern as `materialized_status`.

```sql
CREATE TABLE materialized_security (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    -- Risk assessment
    risk_level TEXT NOT NULL DEFAULT 'low'
        CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
    overall_risk_score REAL NOT NULL DEFAULT 0.0,
    -- Counts
    total_tables INTEGER NOT NULL DEFAULT 0,
    total_access_points INTEGER NOT NULL DEFAULT 0,
    total_sensitive_fields INTEGER NOT NULL DEFAULT 0,
    total_violations INTEGER NOT NULL DEFAULT 0,
    -- Breakdowns (JSON for flexibility)
    sensitivity_breakdown TEXT NOT NULL DEFAULT '{}'
        CHECK (json_valid(sensitivity_breakdown)),
    violation_breakdown TEXT NOT NULL DEFAULT '{}'
        CHECK (json_valid(violation_breakdown)),
    top_risk_tables TEXT NOT NULL DEFAULT '[]'
        CHECK (json_valid(top_risk_tables)),
    top_violations TEXT NOT NULL DEFAULT '[]'
        CHECK (json_valid(top_violations)),
    unprotected_access_points INTEGER NOT NULL DEFAULT 0,
    raw_sql_access_points INTEGER NOT NULL DEFAULT 0,
    -- Metadata
    refreshed_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;
```

**Refresh implementation** (called after scan, after `refresh_materialized_status`):
```rust
pub fn refresh_materialized_security(conn: &Connection) -> Result<RefreshResult> {
    let start = Instant::now();
    
    conn.execute_batch("
        INSERT OR REPLACE INTO materialized_security (
            id, risk_level, overall_risk_score,
            total_tables, total_access_points, total_sensitive_fields, total_violations,
            sensitivity_breakdown, violation_breakdown,
            top_risk_tables, top_violations,
            unprotected_access_points, raw_sql_access_points,
            refreshed_at
        )
        SELECT
            1,
            -- risk_level: derived from max table risk score
            CASE
                WHEN MAX(risk_score) >= 0.8 THEN 'critical'
                WHEN MAX(risk_score) >= 0.6 THEN 'high'
                WHEN MAX(risk_score) >= 0.3 THEN 'medium'
                ELSE 'low'
            END,
            COALESCE(AVG(risk_score), 0.0),
            -- Counts
            (SELECT COUNT(DISTINCT table_name) FROM data_access_points),
            (SELECT COUNT(*) FROM data_access_points),
            (SELECT COUNT(*) FROM sensitive_fields),
            (SELECT COUNT(*) FROM security_violations),
            -- Sensitivity breakdown
            COALESCE((SELECT json_group_object(sensitivity, cnt) FROM (
                SELECT sensitivity, COUNT(*) as cnt FROM sensitive_fields GROUP BY sensitivity
            )), '{}'),
            -- Violation breakdown
            COALESCE((SELECT json_group_object(violation_type, cnt) FROM (
                SELECT violation_type, COUNT(*) as cnt FROM security_violations GROUP BY violation_type
            )), '{}'),
            -- Top risk tables (JSON array of {table, score} objects)
            COALESCE((SELECT json_group_array(json_object('table', table_name, 'score', risk_score))
                FROM (SELECT table_name, risk_score FROM table_risk_scores ORDER BY risk_score DESC LIMIT 5)
            ), '[]'),
            -- Top violations
            '[]',
            -- Access point categories
            (SELECT COUNT(*) FROM data_access_points WHERE is_protected = 0),
            (SELECT COUNT(*) FROM data_access_points WHERE is_raw_sql = 1),
            datetime('now')
        FROM table_risk_scores
    ")?;
    
    Ok(RefreshResult {
        table: "materialized_security".into(),
        duration: start.elapsed(),
    })
}
```

**Rationale**:
Security posture queries are the second most common after status queries. MCP tools like `drift_security_summary` and quality gates that check security compliance need instant access to aggregated security data. A materialized table avoids re-aggregating across `data_access_points`, `sensitive_fields`, and `security_violations` on every query.

**Evidence**:
- Denormalization for read optimization: https://hypermode.com/blog/denormalize-database/ (DL-R7)
- V1 SecuritySummaryView pattern (proven effective for instant security queries)
- Materialized view via tables: https://madflex.de/SQLite-triggers-as-replacement-for-a-materialized-view/ (DL-R1)

**Implementation Notes**:
- The `table_risk_scores` referenced in the query is a SQL view (not a table) that computes per-table risk scores using v1's algorithm (sensitivity × access × raw SQL × violations)
- JSON columns store breakdowns that are read as a unit by consumers — no need for separate tables
- The refresh order matters: `materialized_security` should refresh before `materialized_status` because status reads `security_risk_level` from security

**Risks**:
- The `table_risk_scores` view may be slow for large codebases with many tables. Mitigation: if >100 tables, consider materializing risk scores too.

**Dependencies**:
- 05-analyzers (produces security data in Silver tables)
- 08-storage (schema definition)
- 07-mcp (`drift_security_summary` tool)
- 09-quality-gates (security compliance checks)

---

### GL3: Build File Metadata Table for Ownership Tracking

**Priority**: P0
**Effort**: Medium
**Impact**: Foundation for incremental scanning, per-file stats, and ownership-based invalidation

**Current State**:
V1's ManifestStore tracks file hashes in a flat `Record<string, string>` within `manifest.json`. No per-file statistics, no scan timing, no error tracking. The hash is SHA-256, which is slower than necessary for change detection.

**Proposed Change**:
Build the `file_metadata` table as defined in AD3. This table serves triple duty:
1. **Change detection** for incremental scanning (content_hash comparison)
2. **Ownership registry** for invalidation (which files own which facts)
3. **Per-file statistics** for diagnostics and `drift doctor`

The schema is defined in AD3. Additional indexes:

```sql
-- For finding files by language (drift stats --by-language)
CREATE INDEX idx_file_metadata_language ON file_metadata(language);

-- For finding files with errors (drift doctor)
CREATE INDEX idx_file_metadata_errors ON file_metadata(path)
    WHERE error IS NOT NULL;

-- For finding recently scanned files (drift status --verbose)
CREATE INDEX idx_file_metadata_scanned ON file_metadata(last_scanned_at DESC);
```

**Counter cache maintenance** (triggers on Silver tables):
```sql
-- Update pattern_count when pattern_locations change
CREATE TRIGGER trg_file_pattern_count_insert
AFTER INSERT ON pattern_locations
BEGIN
    UPDATE file_metadata 
    SET pattern_count = pattern_count + 1
    WHERE path = NEW.file;
END;

CREATE TRIGGER trg_file_pattern_count_delete
AFTER DELETE ON pattern_locations
BEGIN
    UPDATE file_metadata 
    SET pattern_count = pattern_count - 1
    WHERE path = OLD.file;
END;

-- Update function_count when functions change
CREATE TRIGGER trg_file_function_count_insert
AFTER INSERT ON functions
BEGIN
    UPDATE file_metadata 
    SET function_count = function_count + 1
    WHERE path = NEW.file;
END;

CREATE TRIGGER trg_file_function_count_delete
AFTER DELETE ON functions
BEGIN
    UPDATE file_metadata 
    SET function_count = function_count - 1
    WHERE path = OLD.file;
END;
```

**Rationale**:
File metadata is the foundation of the ownership model (AD3). Without it, incremental scanning is impossible and every scan must process the entire repository. The counter caches enable instant per-file stats without JOINs — critical for `drift_file_patterns` MCP tool and `drift doctor` diagnostics.

**Evidence**:
- Glean ownership-based invalidation: https://glean.software/docs/implementation/incrementality/ (DL-R8)
- Counter-cache triggers: https://samuelplumppu.se/blog/using-sqlite-triggers-to-boost-performance-of-select-count (DL-R1)
- V1 ManifestStore file hash tracking (proven concept, improved implementation)

**Implementation Notes**:
- Use xxhash64 for content hashing (via the `xxhash-rust` crate) — 10x faster than SHA-256, sufficient for change detection
- Counter cache triggers fire on individual INSERT/DELETE, not during bulk operations. During bulk scan writes, disable triggers by dropping and recreating them around the batch, then run a single reconciliation query to set correct counts
- The `error` column stores the last scan error as a string. If a file consistently fails to scan, `drift doctor` can report it

**Risks**:
- Counter cache triggers add overhead to individual writes. Mitigation: disable during bulk scan, reconcile after.
- xxhash64 has a theoretical collision probability. Mitigation: for change detection (not security), this is acceptable. If a collision occurs, the worst case is an unnecessary re-scan.

**Dependencies**:
- 08-storage (schema definition)
- 01-rust-core (scanner populates file_metadata)
- 25-services (scan pipeline uses file_metadata for change detection)


---

## Phase 2: Index Strategy

### IX1: Build Covering Indexes for Pattern Listing

**Priority**: P0
**Effort**: Low
**Impact**: Replaces v1's PatternIndexView with zero-maintenance SQLite-native equivalent

**Current State**:
V1's PatternIndexView pre-computes a lightweight pattern listing (id, name, category, status, confidence, locationCount, outlierCount) as a JSON file. This avoids loading full pattern data for list queries. The ViewMaterializer rebuilds this view after every scan.

**Proposed Change**:
Build a covering index on the `patterns` table that includes all columns needed by the `drift_patterns_list` MCP tool. The SQLite query planner will use this index to serve list queries without touching the patterns table.

```sql
-- Covering index for pattern listing (replaces PatternIndexView)
-- Includes all columns needed by drift_patterns_list MCP tool
CREATE INDEX idx_patterns_listing ON patterns(
    category,           -- Filter term (WHERE category = ?)
    status,             -- Filter term (WHERE status = ?)
    confidence_score DESC, -- Sort term (ORDER BY confidence_score DESC)
    id,                 -- Output column
    name,               -- Output column
    subcategory,        -- Output column
    severity,           -- Output column
    location_count,     -- Output column (counter-cached)
    outlier_count       -- Output column (counter-cached)
);
```

**How it works**:
When the MCP tool executes:
```sql
SELECT id, name, category, subcategory, status, confidence_score, 
       severity, location_count, outlier_count
FROM patterns
WHERE category = 'authentication'
  AND status = 'approved'
ORDER BY confidence_score DESC
LIMIT 20;
```

The query planner uses `idx_patterns_listing` as a covering index — all requested columns are in the index. It never touches the `patterns` table. This is visible in `EXPLAIN QUERY PLAN` as `USING COVERING INDEX idx_patterns_listing`.

**Rationale**:
A covering index achieves the same performance as v1's PatternIndexView (instant listing without loading full pattern data) with zero maintenance overhead. No rebuild step, no staleness tracking, no separate storage. The index is automatically maintained by SQLite on every INSERT/UPDATE/DELETE.

**Evidence**:
- SQLite covering indexes: https://sqlite.org/queryplanner.html (DL-R2, DL-R5)
- SQLite query planner optimization: https://sqlite.org/optoverview.html (DL-R2)
- V1 PatternIndexView pattern (proven concept, native replacement)

**Implementation Notes**:
- The column order matters: filter columns first (category, status), sort column next (confidence_score), output columns last
- `confidence_score DESC` enables the query planner to deliver results in the correct order without a separate sort step
- This index adds ~50-100 bytes per pattern. For 1000 patterns, that's ~50-100KB — negligible
- Verify with `EXPLAIN QUERY PLAN` that the covering index is used for the primary list query

**Risks**:
- Index size grows with the number of output columns. If more columns are needed in the future, the index grows. Mitigation: only include columns that are actually used in list queries, not detail queries.

**Dependencies**:
- 08-storage (patterns table schema)
- 07-mcp (`drift_patterns_list` tool)

---

### IX2: Build Partial Indexes for Skewed Distributions

**Priority**: P1
**Effort**: Low
**Impact**: 3-10x smaller and faster indexes for the most frequently queried subsets

**Current State**:
V1 has no concept of partial indexes — all JSON indexes cover the full dataset. This means the FileIndex, CategoryIndex, etc. include every pattern regardless of status, even though most queries focus on approved or high-confidence patterns.

**Proposed Change**:
Build partial indexes that cover only the most frequently queried subsets of data. Drift's data has highly skewed distributions that make partial indexes extremely effective.

```sql
-- 1. Approved patterns only (most queried by MCP tools and quality gates)
-- Typically 10-30% of all patterns → 3-10x smaller than full index
CREATE INDEX idx_approved_patterns ON patterns(category, confidence_score DESC)
    WHERE status = 'approved';

-- 2. Entry point functions only (starting point for reachability queries)
-- Typically <5% of all functions → 20x+ smaller
CREATE INDEX idx_entry_points ON functions(file, name, return_type)
    WHERE is_entry_point = 1;

-- 3. High-confidence patterns only (quality gate focus)
-- Typically 30-50% of patterns → 2-3x smaller
CREATE INDEX idx_high_confidence ON patterns(category, status)
    WHERE confidence_score >= 0.85;

-- 4. Sensitive fields by sensitivity level (security query focus)
-- Small subset of all fields
CREATE INDEX idx_sensitive_pii ON sensitive_fields(table_name, field_name)
    WHERE sensitivity = 'PII';

CREATE INDEX idx_sensitive_credentials ON sensitive_fields(table_name, field_name)
    WHERE sensitivity = 'credentials';

-- 5. Active (non-ignored) patterns for general queries
CREATE INDEX idx_active_patterns ON patterns(category, name)
    WHERE status != 'ignored';

-- 6. Files with scan errors (drift doctor focus)
CREATE INDEX idx_files_with_errors ON file_metadata(path)
    WHERE error IS NOT NULL;

-- 7. Patterns with outliers (anomaly detection focus)
CREATE INDEX idx_patterns_with_outliers ON patterns(category, id)
    WHERE outlier_count > 0;
```

**Rationale**:
Partial indexes are one of SQLite's most powerful optimization features. They index only the rows that match a WHERE clause, resulting in smaller indexes that are faster to search and cheaper to maintain. Drift's data is naturally skewed: most queries focus on approved patterns, entry point functions, or sensitive fields — all small subsets of the total data.

**Evidence**:
- SQLite partial indexes: https://sqlite.org/partialindex.html (DL-R3)
- SQLite query planner uses partial indexes when WHERE clause implies index condition (DL-R3)

**Implementation Notes**:
- The query planner uses a partial index only when it can prove the query's WHERE clause implies the index's WHERE clause. The terms must match exactly — `WHERE status = 'approved'` in the query matches `WHERE status = 'approved'` in the index.
- For the `idx_approved_patterns` index, queries must include `AND status = 'approved'` to use it. MCP tools should always include this filter when querying approved patterns.
- Partial indexes are maintained automatically — no rebuild needed. They only index matching rows, so INSERT/UPDATE/DELETE of non-matching rows has zero index overhead.

**Risks**:
- Too many partial indexes can slow down writes. Mitigation: only create partial indexes for query patterns that are actually used by consumers. Monitor with `EXPLAIN QUERY PLAN`.
- Developers may forget to include the matching WHERE clause in queries. Mitigation: document required WHERE clauses alongside each partial index.

**Dependencies**:
- 08-storage (schema definition)
- 07-mcp (MCP tool queries must include matching WHERE clauses)
- 09-quality-gates (quality gate queries must include matching WHERE clauses)

---

### IX3: Build Expression Indexes on JSON Columns

**Priority**: P1
**Effort**: Low
**Impact**: Enables indexed lookups into JSON columns without normalization overhead

**Current State**:
V1 stores tags, decorators, parameters, and other flexible data as JSON. Filtering by tag requires loading the full pattern and parsing JSON in application code. No indexed access to JSON fields.

**Proposed Change**:
Add expression indexes on JSON columns that are used in WHERE clauses. Keep JSON for storage (read/written as a unit), but add indexed access for filtering.

```sql
-- Tag filtering for drift_patterns_list --tags
-- json_each() can't be indexed, but single-tag lookups can use instr()
CREATE INDEX idx_patterns_has_tag ON patterns(
    json_extract(tags, '$')
) WHERE tags IS NOT NULL;

-- For multi-tag filtering, normalize into a junction table
CREATE TABLE pattern_tags (
    pattern_id TEXT NOT NULL REFERENCES patterns(id) ON DELETE CASCADE,
    tag TEXT NOT NULL,
    PRIMARY KEY (pattern_id, tag)
) STRICT;

-- Index for "find all patterns with tag X"
CREATE INDEX idx_pattern_tags_tag ON pattern_tags(tag, pattern_id);

-- Contract mismatch type filtering
CREATE INDEX idx_contracts_mismatch_type ON contracts(
    json_extract(mismatches, '$[0].type')
) WHERE mismatches IS NOT NULL;
```

**Tag normalization strategy**:
```rust
// When inserting a pattern with tags:
pub fn insert_pattern_with_tags(conn: &Connection, pattern: &Pattern) -> Result<()> {
    // 1. Insert pattern (tags stored as JSON for full retrieval)
    conn.execute(
        "INSERT INTO patterns (..., tags) VALUES (..., ?)",
        params![serde_json::to_string(&pattern.tags)?],
    )?;
    
    // 2. Normalize tags into junction table for indexed queries
    let mut stmt = conn.prepare_cached(
        "INSERT OR IGNORE INTO pattern_tags (pattern_id, tag) VALUES (?, ?)"
    )?;
    for tag in &pattern.tags {
        stmt.execute(params![pattern.id, tag])?;
    }
    
    Ok(())
}
```

**Rationale**:
JSON columns are the right storage format for flexible metadata (tags, decorators, parameters) that is typically read/written as a unit. But when consumers need to filter by specific JSON values (e.g., "find all patterns tagged 'security'"), expression indexes or normalization provide O(log n) access instead of O(n) full-table scan.

**Evidence**:
- SQLite expression indexes: https://sqlite.org/expridx.html (DL-R4)
- JSON + generated columns: https://www.webpronews.com/sqlite-boosts-json-query-speed-with-virtual-generated-columns/ (DL-R4)
- JSON in relational databases: https://json-parser.net/blog/json-in-relational-databases (DL-R4)
- CHECK(json_valid()) for integrity: https://sqlite.org/expridx.html (DL-R4)

**Implementation Notes**:
- The `pattern_tags` junction table is the recommended approach for multi-tag filtering. Expression indexes on JSON arrays are limited to single-element lookups.
- Add `CHECK(json_valid(tags))` on the `patterns` table to prevent malformed JSON
- The dual storage (JSON column + junction table) means tags are stored twice. This is intentional — the JSON column is for full retrieval, the junction table is for indexed queries.
- Keep `decorators`, `parameters`, and other JSON columns as-is (no expression indexes) unless query patterns emerge that require indexed access.

**Risks**:
- Dual storage (JSON + junction table) creates a consistency risk. Mitigation: always update both in the same transaction. Add a reconciliation check in `drift doctor`.
- Expression indexes on complex JSON paths may not be used by the query planner if the query expression doesn't match exactly. Mitigation: use simple `json_extract()` paths and verify with `EXPLAIN QUERY PLAN`.

**Dependencies**:
- 08-storage (schema definition for pattern_tags)
- 03-detectors (tag assignment during detection)
- 07-mcp (`drift_patterns_list --tags` filter)

---

### IX4: Build Dimension-Replacement Indexes

**Priority**: P0
**Effort**: Low
**Impact**: Replaces v1's four JSON index files with native SQL indexes

**Current State**:
V1 maintains four JSON index files: FileIndex (file → patternIds), CategoryIndex (category → patternIds), TableIndex (table → accessPointIds), EntryPointIndex (entryPoint → reachable data). Each is rebuilt by the ViewMaterializer after scans.

**Proposed Change**:
Replace all four JSON indexes with SQL indexes that the query planner uses automatically. No rebuild step, no staleness tracking, no separate storage.

```sql
-- Replaces FileIndex (file → patternIds)
-- Used by drift_file_patterns MCP tool
CREATE INDEX idx_pattern_locations_file ON pattern_locations(file, pattern_id);

-- Replaces CategoryIndex (category → patternIds)
-- Used by drift_patterns_list --category
CREATE INDEX idx_patterns_category ON patterns(category, id);

-- Replaces TableIndex (table → accessPointIds, accessorIds)
-- Used by drift_security_summary --table
CREATE INDEX idx_data_access_table ON data_access_points(table_name, id);
CREATE INDEX idx_data_access_function ON data_access_points(function_id);

-- Replaces EntryPointIndex (entryPoint → reachable functions/tables/sensitive data)
-- Used by drift_impact_analysis MCP tool
-- Note: EntryPointIndex is replaced by SQL JOINs, not a single index
CREATE INDEX idx_functions_entry ON functions(is_entry_point, id)
    WHERE is_entry_point = 1;
CREATE INDEX idx_call_edges_caller ON call_edges(caller_id, callee_id);
CREATE INDEX idx_call_edges_callee ON call_edges(callee_id, caller_id);
```

**Query equivalents**:

```sql
-- FileIndex lookup: "Which patterns affect src/auth/login.ts?"
-- V1: FileIndex.files['src/auth/login.ts'] → patternId[]
-- V2:
SELECT DISTINCT p.id, p.name, p.category, p.status
FROM pattern_locations pl
JOIN patterns p ON p.id = pl.pattern_id
WHERE pl.file = 'src/auth/login.ts';

-- CategoryIndex lookup: "Which patterns are in 'authentication'?"
-- V1: CategoryIndex.categories['authentication'] → patternId[]
-- V2:
SELECT id, name, status, confidence_score
FROM patterns
WHERE category = 'authentication';

-- TableIndex lookup: "Who accesses the 'users' table?"
-- V1: TableIndex.tables['users'] → {accessPointIds, accessorIds}
-- V2:
SELECT dap.id, dap.function_id, f.name as function_name, dap.access_type
FROM data_access_points dap
JOIN functions f ON f.id = dap.function_id
WHERE dap.table_name = 'users';

-- EntryPointIndex lookup: "What can the /api/login endpoint reach?"
-- V1: EntryPointIndex.entryPoints['/api/login'] → {reachableFunctions, tables, sensitiveData}
-- V2: Recursive CTE for reachability (see call-graph category)
```

**Rationale**:
SQL indexes are automatically maintained by SQLite on every INSERT/UPDATE/DELETE. They never go stale, never need rebuilding, and never require separate storage. The query planner automatically selects the optimal index for each query. This eliminates ~440 lines of IndexStore code and the entire index rebuild step from the ViewMaterializer.

**Evidence**:
- SQLite query planner index selection: https://sqlite.org/queryplanner.html (DL-R2)
- SQLite optimizer overview: https://sqlite.org/optoverview.html (DL-R2)
- V1 IndexStore (4 index types, ~440 LOC — all replaced by SQL indexes)

**Implementation Notes**:
- The `idx_call_edges_caller` and `idx_call_edges_callee` indexes enable bidirectional traversal of the call graph — both "who calls this function?" and "what does this function call?"
- The EntryPointIndex replacement is the most complex — it requires a recursive CTE for reachability analysis. This is handled by the call-graph category (04), not the data lake.
- Composite indexes (e.g., `(file, pattern_id)`) enable both filtered lookups and JOIN optimization

**Risks**:
- The recursive CTE for entry point reachability may be slower than v1's pre-computed EntryPointIndex for deep call graphs. Mitigation: add a depth limit to the CTE and consider materializing reachability for entry points if performance is insufficient.

**Dependencies**:
- 08-storage (schema definition)
- 04-call-graph (reachability queries)
- 07-mcp (all MCP tools that use index lookups)


---

## Phase 3: Materialization Pipeline

### MP1: Build Explicit Post-Scan Refresh Pipeline

**Priority**: P0
**Effort**: Medium
**Impact**: Replaces v1's ViewMaterializer with a SQLite-native refresh pipeline

**Current State**:
V1's ViewMaterializer is a 590-line TypeScript class that runs a 10-step pipeline after each scan: rebuild stale views, rebuild all indexes, sync cross-domain stats, mark views fresh. Each step reads from raw stores and writes JSON files.

**Proposed Change**:
Build a Rust `RefreshPipeline` that runs after scan completion, refreshing Gold layer tables from Silver layer data. The pipeline is explicit (not trigger-based) to avoid overhead during bulk scan writes.

```rust
pub struct RefreshPipeline {
    conn: Connection,  // Uses the write connection
}

pub struct RefreshReport {
    pub tables_refreshed: Vec<RefreshResult>,
    pub total_duration: Duration,
    pub rows_affected: usize,
    pub errors: Vec<RefreshError>,
}

impl RefreshPipeline {
    pub fn refresh_all(&self) -> Result<RefreshReport> {
        let start = Instant::now();
        let mut report = RefreshReport::default();
        
        // Order matters: security before status (status reads security risk level)
        let steps: Vec<(&str, fn(&Connection) -> Result<RefreshResult>)> = vec![
            ("materialized_security", refresh_materialized_security),
            ("materialized_status", refresh_materialized_status),
            ("health_trends", append_health_trend),
            ("counter_caches", reconcile_counter_caches),
        ];
        
        let tx = self.conn.transaction_with_behavior(
            TransactionBehavior::Immediate
        )?;
        
        for (name, refresh_fn) in &steps {
            match refresh_fn(&tx) {
                Ok(result) => {
                    report.rows_affected += result.rows_affected;
                    report.tables_refreshed.push(result);
                }
                Err(e) => {
                    // Log error but continue — partial refresh is better than no refresh
                    report.errors.push(RefreshError {
                        table: name.to_string(),
                        error: e.to_string(),
                    });
                }
            }
        }
        
        tx.commit()?;
        report.total_duration = start.elapsed();
        Ok(report)
    }
    
    /// Selective refresh — only refresh tables affected by changed data
    pub fn refresh_selective(&self, changed_domains: &[Domain]) -> Result<RefreshReport> {
        let mut report = RefreshReport::default();
        let tx = self.conn.transaction_with_behavior(
            TransactionBehavior::Immediate
        )?;
        
        // Always refresh status (it aggregates everything)
        if changed_domains.contains(&Domain::Patterns) 
            || changed_domains.contains(&Domain::Security) {
            report.tables_refreshed.push(
                refresh_materialized_security(&tx)?
            );
        }
        
        // Status depends on everything
        report.tables_refreshed.push(
            refresh_materialized_status(&tx)?
        );
        
        // Trends only on full scans
        if changed_domains.contains(&Domain::Patterns) {
            report.tables_refreshed.push(
                append_health_trend(&tx)?
            );
        }
        
        tx.commit()?;
        Ok(report)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Domain {
    Patterns,
    CallGraph,
    Security,
    Contracts,
    DNA,
}
```

**Rationale**:
The refresh pipeline must be explicit (not trigger-based) because triggers fire on every individual INSERT/UPDATE/DELETE. During a bulk scan that inserts thousands of patterns, trigger-based materialization would fire thousands of times — catastrophic for performance. The explicit pipeline runs once after the scan completes, refreshing all Gold tables in a single transaction.

**Evidence**:
- Trigger overhead during bulk writes: https://madflex.de/SQLite-triggers-as-replacement-for-a-materialized-view/ (DL-R1)
- Kythe two-phase architecture (index → serve): https://www.kythe.io/docs/kythe-overview.html (DL-R9)
- CQRS batch refresh pattern (DL-R10)
- V1 ViewMaterializer (10-step pipeline — proven concept, native replacement)

**Implementation Notes**:
- The entire refresh runs in a single `BEGIN IMMEDIATE` transaction for atomicity
- Errors in individual refresh steps are logged but don't abort the pipeline — partial refresh is better than no refresh
- `refresh_selective()` enables faster refreshes when only specific domains changed (e.g., incremental scan that only touched pattern files)
- The `Domain` enum maps to the data domains that can change independently
- The refresh pipeline should emit timing telemetry for each step (see OP3)

**Risks**:
- If the refresh transaction is too large (many subqueries), it may hold the write lock for too long, blocking concurrent reads. Mitigation: WAL mode allows reads during writes. If refresh takes >1s, consider breaking into smaller transactions.
- Partial refresh (refresh_selective) may miss cross-domain dependencies. Mitigation: always refresh `materialized_status` since it aggregates all domains.

**Dependencies**:
- 25-services (scan pipeline calls refresh after completion)
- 08-storage (DatabaseManager provides write connection)
- GL1, GL2 (materialized tables that get refreshed)

---

### MP2: Build Delta-Aware Refresh for Incremental Scans

**Priority**: P1
**Effort**: High
**Impact**: Reduces refresh time from O(all data) to O(changed data) for incremental scans

**Current State**:
V1's ViewMaterializer rebuilds entire views even when only a few patterns changed. The "selective rebuild" only skips views that aren't stale — it doesn't rebuild a view partially. If the StatusView is stale, the entire StatusView is recomputed from all patterns.

**Proposed Change**:
For incremental scans (where only a subset of files changed), track which Silver-layer rows changed and use delta-aware refresh queries that only recompute affected portions of Gold-layer tables.

**Delta tracking approach**:
```sql
-- Track which patterns were modified in the current scan
-- This is a temporary table, created at scan start, dropped after refresh
CREATE TEMPORARY TABLE scan_delta (
    table_name TEXT NOT NULL,
    row_id TEXT NOT NULL,
    operation TEXT NOT NULL CHECK (operation IN ('insert', 'update', 'delete')),
    PRIMARY KEY (table_name, row_id)
);
```

**Delta-aware refresh for materialized_status**:
```rust
pub fn refresh_materialized_status_delta(
    conn: &Connection,
    delta: &ScanDelta,
) -> Result<RefreshResult> {
    // If patterns changed, recompute pattern counts
    if delta.has_changes("patterns") {
        conn.execute("
            UPDATE materialized_status SET
                total_patterns = (SELECT COUNT(*) FROM patterns),
                approved_patterns = (SELECT COUNT(*) FROM patterns WHERE status = 'approved'),
                discovered_patterns = (SELECT COUNT(*) FROM patterns WHERE status = 'discovered'),
                ignored_patterns = (SELECT COUNT(*) FROM patterns WHERE status = 'ignored'),
                category_counts = (SELECT json_group_object(category, cnt) FROM (
                    SELECT category, COUNT(*) as cnt FROM patterns GROUP BY category
                )),
                refreshed_at = datetime('now')
            WHERE id = 1
        ", [])?;
    }
    
    // If security data changed, recompute security fields
    if delta.has_changes("sensitive_fields") || delta.has_changes("security_violations") {
        conn.execute("
            UPDATE materialized_status SET
                security_risk_level = COALESCE(
                    (SELECT risk_level FROM materialized_security WHERE id = 1), 'low'
                ),
                security_violations = (SELECT COUNT(*) FROM security_violations),
                sensitive_exposures = (SELECT COUNT(DISTINCT field_name) FROM sensitive_fields),
                refreshed_at = datetime('now')
            WHERE id = 1
        ", [])?;
    }
    
    // Always update last scan info
    conn.execute("
        UPDATE materialized_status SET
            last_scan_at = (SELECT started_at FROM scan_history ORDER BY started_at DESC LIMIT 1),
            last_scan_duration_ms = (SELECT duration_ms FROM scan_history ORDER BY started_at DESC LIMIT 1),
            last_scan_files = (SELECT files_scanned FROM scan_history ORDER BY started_at DESC LIMIT 1),
            last_scan_patterns = (SELECT patterns_found FROM scan_history ORDER BY started_at DESC LIMIT 1),
            last_scan_incremental = (SELECT incremental FROM scan_history ORDER BY started_at DESC LIMIT 1),
            last_scan_changed_files = (SELECT changed_files FROM scan_history ORDER BY started_at DESC LIMIT 1),
            refreshed_at = datetime('now')
        WHERE id = 1
    ", [])?;
    
    Ok(RefreshResult { /* ... */ })
}
```

**Rationale**:
For large codebases, a full refresh after every incremental scan is wasteful. If only 5 files changed and only auth patterns were affected, there's no need to recompute security aggregations. Delta-aware refresh reduces refresh time proportionally to the amount of changed data, following Salsa's principle of minimal recomputation.

**Evidence**:
- Salsa incremental computation: https://salsa-rs.github.io/salsa/reference/algorithm.html (DL-R13)
- rust-analyzer durable incrementality: https://rust-analyzer.github.io/blog/2023/07/24/durable-incrementality.html (DL-R13)
- Glean derived fact recomputation: https://glean.software/docs/implementation/incrementality/ (DL-R8)
- Databricks medallion incremental processing (DL-R6)

**Implementation Notes**:
- The `scan_delta` temporary table is populated by the scan pipeline as it inserts/updates/deletes Silver-layer rows
- `ScanDelta::has_changes(table_name)` checks if any rows in the given table were modified
- For full scans (non-incremental), skip delta tracking and use the full refresh (MP1)
- Delta-aware refresh is an optimization — if it fails or produces incorrect results, fall back to full refresh
- Consider tracking delta at the domain level (patterns, security, callgraph) rather than per-table for simplicity

**Risks**:
- Delta tracking adds overhead to every write during scan. Mitigation: use a lightweight in-memory set (not a temp table) for tracking changed domains.
- Incorrect delta tracking could produce stale Gold-layer data. Mitigation: `drift doctor` reconciliation checks (OP2) detect and fix inconsistencies.

**Dependencies**:
- MP1 (full refresh as fallback)
- AD3 (ownership model for knowing which files changed)
- 25-services (scan pipeline populates delta)

---

### MP3: Build Health Trend Tracking

**Priority**: P1
**Effort**: Low
**Impact**: Enables trend visualization and "improving/stable/declining" health assessment

**Current State**:
V1's TrendsView stores health trend data as a JSON file. It's rebuilt by the ViewMaterializer after each scan. The trend data includes health score snapshots over time, enabling the "improving/stable/declining" assessment.

**Proposed Change**:
Build a `health_trends` table that appends a snapshot after each scan. This is an append-only Gold-layer table — never updated, only inserted into and periodically pruned.

```sql
CREATE TABLE health_trends (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Snapshot timestamp
    recorded_at TEXT NOT NULL DEFAULT (datetime('now')),
    scan_id TEXT,                            -- Links to scan_history
    -- Health metrics at this point in time
    health_score REAL NOT NULL,
    total_patterns INTEGER NOT NULL,
    approved_patterns INTEGER NOT NULL,
    discovered_patterns INTEGER NOT NULL,
    ignored_patterns INTEGER NOT NULL,
    -- Security metrics
    security_risk_level TEXT NOT NULL,
    security_violations INTEGER NOT NULL,
    -- Call graph metrics
    total_functions INTEGER NOT NULL DEFAULT 0,
    total_call_edges INTEGER NOT NULL DEFAULT 0,
    entry_points INTEGER NOT NULL DEFAULT 0,
    -- Contract metrics
    verified_contracts INTEGER NOT NULL DEFAULT 0,
    mismatched_contracts INTEGER NOT NULL DEFAULT 0,
    -- Computed trend
    trend TEXT NOT NULL DEFAULT 'stable'
        CHECK (trend IN ('improving', 'stable', 'declining'))
) STRICT;

-- Index for time-range queries (dashboard charts)
CREATE INDEX idx_health_trends_time ON health_trends(recorded_at DESC);

-- Index for scan correlation
CREATE INDEX idx_health_trends_scan ON health_trends(scan_id)
    WHERE scan_id IS NOT NULL;
```

**Append function** (called as part of refresh pipeline):
```rust
pub fn append_health_trend(conn: &Connection) -> Result<RefreshResult> {
    conn.execute("
        INSERT INTO health_trends (
            recorded_at, scan_id,
            health_score, total_patterns, approved_patterns, 
            discovered_patterns, ignored_patterns,
            security_risk_level, security_violations,
            total_functions, total_call_edges, entry_points,
            verified_contracts, mismatched_contracts,
            trend
        )
        SELECT
            datetime('now'),
            (SELECT id FROM scan_history ORDER BY started_at DESC LIMIT 1),
            COALESCE((SELECT AVG(confidence_score) FROM patterns WHERE status != 'ignored'), 0.0),
            (SELECT COUNT(*) FROM patterns),
            (SELECT COUNT(*) FROM patterns WHERE status = 'approved'),
            (SELECT COUNT(*) FROM patterns WHERE status = 'discovered'),
            (SELECT COUNT(*) FROM patterns WHERE status = 'ignored'),
            COALESCE((SELECT risk_level FROM materialized_security WHERE id = 1), 'low'),
            (SELECT COUNT(*) FROM security_violations),
            (SELECT COUNT(*) FROM functions),
            (SELECT COUNT(*) FROM call_edges),
            (SELECT COUNT(*) FROM functions WHERE is_entry_point = 1),
            (SELECT COUNT(*) FROM contracts WHERE status = 'verified'),
            (SELECT COUNT(*) FROM contracts WHERE status = 'mismatch'),
            -- Trend calculation
            CASE
                WHEN (SELECT health_score FROM health_trends ORDER BY recorded_at DESC LIMIT 1) IS NULL THEN 'stable'
                WHEN COALESCE((SELECT AVG(confidence_score) FROM patterns WHERE status != 'ignored'), 0.0)
                    > (SELECT health_score FROM health_trends ORDER BY recorded_at DESC LIMIT 1) + 0.02 THEN 'improving'
                WHEN COALESCE((SELECT AVG(confidence_score) FROM patterns WHERE status != 'ignored'), 0.0)
                    < (SELECT health_score FROM health_trends ORDER BY recorded_at DESC LIMIT 1) - 0.02 THEN 'declining'
                ELSE 'stable'
            END
    ", [])?;
    
    Ok(RefreshResult { /* ... */ })
}
```

**Rationale**:
Trend data is essential for the "improving/stable/declining" health assessment shown in `drift_status` and the dashboard. Without historical snapshots, there's no way to determine if the codebase is getting better or worse. The append-only pattern is simple, efficient, and naturally supports time-range queries for charts.

**Evidence**:
- V1 TrendsView (proven concept — health snapshots over time)
- Delta Lake time travel principles: https://www.databricks.com/blog/delta-lake-explained-boost-data-reliability-cloud-storage (DL-R15)

**Implementation Notes**:
- The trend calculation uses a ±0.02 threshold to avoid noise — small fluctuations don't change the trend
- The `scan_id` column links each trend entry to the scan that produced it, enabling "what changed in this scan?" queries
- Trend data should be pruned periodically (see OP1 retention policies)

**Risks**:
- Unbounded growth if retention policies aren't implemented. Mitigation: OP1 defines retention policies.
- The trend calculation is simplistic (current vs. previous). A more sophisticated approach would use a moving average over the last N scans.

**Dependencies**:
- MP1 (refresh pipeline calls append_health_trend)
- GL1 (materialized_status reads trend for health_trend field)
- OP1 (retention policies for trend data)


---

## Phase 4: Generated Columns and Derived Data

### GC1: Build Virtual Generated Columns for Confidence Classification

**Priority**: P1
**Effort**: Low
**Impact**: Eliminates application-level computation of derived fields, ensures consistency

**Current State**:
V1 computes `confidenceLevel` (high/medium/low/uncertain) in application code from `confidence_score`. This computation is duplicated across multiple consumers (MCP tools, CLI, quality gates). If the thresholds change, every consumer must be updated.

**Proposed Change**:
Add virtual generated columns to the `patterns` table that compute derived classifications from existing columns. Virtual columns are computed on read (no storage cost) and can be indexed.

```sql
-- Confidence level classification
ALTER TABLE patterns ADD COLUMN confidence_level TEXT
    GENERATED ALWAYS AS (
        CASE
            WHEN confidence_score >= 0.85 THEN 'high'
            WHEN confidence_score >= 0.70 THEN 'medium'
            WHEN confidence_score >= 0.50 THEN 'low'
            ELSE 'uncertain'
        END
    ) VIRTUAL;

-- Pattern age in days (for temporal confidence decay)
ALTER TABLE patterns ADD COLUMN age_days INTEGER
    GENERATED ALWAYS AS (
        CAST(julianday('now') - julianday(first_seen) AS INTEGER)
    ) VIRTUAL;

-- Is this pattern "actionable"? (approved + high confidence)
ALTER TABLE patterns ADD COLUMN is_actionable INTEGER
    GENERATED ALWAYS AS (
        CASE
            WHEN status = 'approved' AND confidence_score >= 0.70 THEN 1
            ELSE 0
        END
    ) VIRTUAL;

-- Severity rank for sorting (critical=0, warning=1, info=2, none=3)
ALTER TABLE patterns ADD COLUMN severity_rank INTEGER
    GENERATED ALWAYS AS (
        CASE severity
            WHEN 'critical' THEN 0
            WHEN 'warning' THEN 1
            WHEN 'info' THEN 2
            ELSE 3
        END
    ) VIRTUAL;
```

**Indexes on generated columns**:
```sql
-- Index for filtering by confidence level
CREATE INDEX idx_patterns_confidence_level ON patterns(confidence_level, category);

-- Index for actionable patterns (quality gate focus)
CREATE INDEX idx_patterns_actionable ON patterns(category, confidence_score DESC)
    WHERE is_actionable = 1;

-- Index for severity-based sorting
CREATE INDEX idx_patterns_severity ON patterns(severity_rank, confidence_score DESC);
```

**Rationale**:
Virtual generated columns centralize derived field computation in the schema, eliminating duplication across consumers. The thresholds are defined once in SQL and automatically applied to every query. Indexing generated columns provides the same performance as indexing regular columns — the index stores the computed value, so the column doesn't need to be recomputed for index lookups.

**Evidence**:
- SQLite generated columns: https://sqlite.org/gencol.html (DL-R11)
- Generated columns analysis: https://feeds.simonwillison.net/2024/May/8/modern-sqlite-generated-columns/ (DL-R11)
- Virtual columns with indexes — best of both worlds (DL-R11)

**Implementation Notes**:
- Virtual generated columns are computed on every read. For columns used in WHERE clauses, the index stores the computed value, so the computation only happens at index build time.
- `age_days` uses `julianday('now')` which changes every day. This means the index on `age_days` would need to be rebuilt daily. If age-based queries are rare, skip the index and compute in application code.
- Generated columns cannot reference other tables or use subqueries — they can only reference columns in the same row.
- Add generated columns via ALTER TABLE in a migration, not in the initial CREATE TABLE, to support incremental schema evolution.

**Risks**:
- `age_days` depends on `julianday('now')` which is non-deterministic. SQLite allows this for virtual columns but not stored columns. An index on `age_days` would be stale after midnight. Mitigation: don't index `age_days` — use it only for display, not filtering.
- Too many generated columns can slow down SELECT * queries. Mitigation: only add generated columns that are actually used by consumers.

**Dependencies**:
- 08-storage (schema migration)
- 07-mcp (MCP tools use confidence_level, is_actionable)
- 09-quality-gates (quality gates use is_actionable)

---

### GC2: Build Risk Score Generated Columns for Security Tables

**Priority**: P2
**Effort**: Low
**Impact**: Centralizes security risk scoring in the schema, enables indexed risk queries

**Current State**:
V1 computes per-table risk scores in the SecurityShardStore using a multi-factor formula: sensitivity × access factor × raw SQL penalty × violation penalty. This computation is in TypeScript application code.

**Proposed Change**:
Create a SQL view that computes per-table risk scores, and optionally a generated column on a security summary table.

```sql
-- Per-table risk score view (computed on read)
CREATE VIEW v_table_risk_scores AS
SELECT
    dap.table_name,
    -- Base sensitivity (max sensitivity weight across all sensitive fields for this table)
    COALESCE(MAX(
        CASE sf.sensitivity
            WHEN 'credentials' THEN 1.0
            WHEN 'PII' THEN 0.9
            WHEN 'health' THEN 0.9
            WHEN 'financial' THEN 0.85
            ELSE 0.5
        END
    ), 0.3) as base_sensitivity,
    -- Access factor (capped at 1.0)
    MIN(COUNT(DISTINCT dap.id) * 1.0 / 10.0, 1.0) as access_factor,
    -- Raw SQL penalty
    CASE WHEN SUM(CASE WHEN dap.is_raw_sql = 1 THEN 1 ELSE 0 END) > 0 THEN 0.2 ELSE 0.0 END as raw_sql_penalty,
    -- Violation penalty (capped at 0.3)
    MIN(COALESCE(sv.violation_count, 0) * 0.1, 0.3) as violation_penalty,
    -- Final risk score
    MIN(
        COALESCE(MAX(
            CASE sf.sensitivity
                WHEN 'credentials' THEN 1.0
                WHEN 'PII' THEN 0.9
                WHEN 'health' THEN 0.9
                WHEN 'financial' THEN 0.85
                ELSE 0.5
            END
        ), 0.3) * (
            0.5 
            + MIN(COUNT(DISTINCT dap.id) * 1.0 / 10.0, 1.0) * 0.3
            + CASE WHEN SUM(CASE WHEN dap.is_raw_sql = 1 THEN 1 ELSE 0 END) > 0 THEN 0.2 ELSE 0.0 END
            + MIN(COALESCE(sv.violation_count, 0) * 0.1, 0.3)
        ),
        1.0
    ) as risk_score
FROM data_access_points dap
LEFT JOIN sensitive_fields sf ON sf.table_name = dap.table_name
LEFT JOIN (
    SELECT table_name, COUNT(*) as violation_count
    FROM security_violations
    GROUP BY table_name
) sv ON sv.table_name = dap.table_name
GROUP BY dap.table_name;
```

**Rationale**:
Centralizing the risk score formula in SQL ensures consistency across all consumers. The view is computed on read, which is acceptable because security queries are less frequent than status queries. If performance becomes an issue, the view can be materialized into a table during the refresh pipeline.

**Evidence**:
- V1 SecurityShardStore.calculateRiskScore algorithm (preserved formula)
- Denormalization for read optimization: https://www.datacamp.com/tutorial/denormalization (DL-R7)
- SQL views for derived data: https://sqlite.org/queryplanner.html (DL-R2)

**Implementation Notes**:
- The risk score formula matches v1's algorithm exactly: `baseSensitivity * (0.5 + accessFactor * 0.3 + rawSqlPenalty + violationPenalty)`
- The view is used by `refresh_materialized_security()` (GL2) to populate the `top_risk_tables` JSON array
- If the view is too slow for large codebases (>100 tables), materialize it into a `table_risk_scores` table during the refresh pipeline

**Risks**:
- Complex SQL views can be hard to debug. Mitigation: test the view with known inputs and verify against v1's TypeScript implementation.

**Dependencies**:
- 05-analyzers (produces data_access_points, sensitive_fields, security_violations)
- GL2 (materialized_security uses this view)

---

## Phase 5: Cache Warming

### CW1: Build Startup Cache Warming for MCP Server

**Priority**: P1
**Effort**: Low
**Impact**: Eliminates cold-start latency for the first MCP query after process start

**Current State**:
V1's Data Lake has a cold cache problem: the first query after process start requires full JSON file I/O to populate in-memory caches. Subsequent queries are fast because the cache is warm. V2's SQLite page cache has the same issue — the first query reads from disk.

**Proposed Change**:
On MCP server startup, execute lightweight warming queries that pre-load the most frequently accessed data into SQLite's page cache.

```rust
pub fn warm_cache(conn: &Connection) -> Result<WarmingReport> {
    let start = Instant::now();
    let mut report = WarmingReport::default();
    
    // 1. Warm materialized_status (most frequently queried table)
    let _: Option<i64> = conn.query_row(
        "SELECT id FROM materialized_status WHERE id = 1",
        [],
        |row| row.get(0),
    ).optional()?;
    report.tables_warmed.push("materialized_status");
    
    // 2. Warm materialized_security
    let _: Option<i64> = conn.query_row(
        "SELECT id FROM materialized_security WHERE id = 1",
        [],
        |row| row.get(0),
    ).optional()?;
    report.tables_warmed.push("materialized_security");
    
    // 3. Warm the patterns covering index (touch first page)
    let _: Option<String> = conn.query_row(
        "SELECT id FROM patterns ORDER BY category, status, confidence_score DESC LIMIT 1",
        [],
        |row| row.get(0),
    ).optional()?;
    report.tables_warmed.push("patterns (covering index)");
    
    // 4. Warm the functions entry point index
    let _: Option<String> = conn.query_row(
        "SELECT id FROM functions WHERE is_entry_point = 1 LIMIT 1",
        [],
        |row| row.get(0),
    ).optional()?;
    report.tables_warmed.push("functions (entry points)");
    
    // 5. Warm recent health trends (for trend calculation)
    let _: Vec<f64> = conn.prepare(
        "SELECT health_score FROM health_trends ORDER BY recorded_at DESC LIMIT 5"
    )?.query_map([], |row| row.get(0))?
    .collect::<Result<Vec<_>, _>>()?;
    report.tables_warmed.push("health_trends (recent)");
    
    report.duration = start.elapsed();
    Ok(report)
}
```

**When to warm**:
- MCP server startup (before accepting first request)
- CLI command startup (before executing command) — optional, only for `drift status` and `drift patterns`
- After database restore (cache is cold after restore)

**Rationale**:
Cache warming is a well-established technique for eliminating cold-start latency. The warming queries are lightweight (single-row reads, LIMIT 1) and complete in <10ms for typical Drift databases. The benefit is that the first real MCP query hits warm cache instead of cold disk.

**Evidence**:
- Cache warming strategies: https://aerospike.com/blog/cache-warming-explained (DL-R14)
- Cache warming optimization: https://newsletter.scalablethread.com/p/how-to-optimize-performance-with (DL-R14)
- SQLite page cache behavior: https://www.powersync.com/blog/sqlite-optimizations-for-ultra-high-performance (DL-R12)

**Implementation Notes**:
- Warming queries should use the same indexes that real queries use, to ensure the right index pages are loaded
- The `LIMIT 1` queries load the first page of each index/table — enough to warm the B-tree root and first leaf pages
- Don't warm everything — only the most frequently accessed paths. Over-warming wastes memory and startup time.
- The warming report can be logged at debug level for performance monitoring

**Risks**:
- Warming queries load data that may not be needed (e.g., if the user runs `drift scan` instead of `drift status`). Mitigation: warming is fast (<10ms) and the loaded pages will be evicted by LRU if not used.
- OS-level filesystem cache may already provide warm reads. Mitigation: warming is still beneficial because it loads data into SQLite's page cache, which is faster than filesystem cache.

**Dependencies**:
- 07-mcp (MCP server startup calls warm_cache)
- 10-cli (CLI startup optionally calls warm_cache)
- 08-storage (DatabaseManager provides read connection)


---

## Phase 6: Incremental Invalidation

### II1: Build File-Based Dependency Tracking

**Priority**: P1
**Effort**: Medium
**Impact**: Enables precise invalidation — only re-derive data for changed files

**Current State**:
V1's ManifestStore tracks file hashes but doesn't track which derived data (views, indexes) depends on which files. When any file changes, all views are marked stale. This is a coarse-grained invalidation model that causes unnecessary recomputation.

**Proposed Change**:
Build a dependency tracking system that maps files to the derived data they produce. When a file changes, only its derived data is invalidated.

**The dependency graph**:
```
file_metadata.path (source)
  ├── pattern_locations.file = path     (patterns from this file)
  ├── functions.file = path             (functions defined in this file)
  ├── call_edges.caller_file = path     (call sites in this file)
  ├── data_access.file = path           (data access in this file)
  └── Gold layer (transitively affected)
      ├── materialized_status (if any patterns changed)
      ├── materialized_security (if any security data changed)
      └── health_trends (if any patterns changed)
```

**Implementation**:
```rust
pub struct DependencyTracker {
    /// Files that changed in the current scan
    changed_files: HashSet<String>,
    /// Domains affected by the changes
    affected_domains: HashSet<Domain>,
}

impl DependencyTracker {
    pub fn new() -> Self {
        Self {
            changed_files: HashSet::new(),
            affected_domains: HashSet::new(),
        }
    }
    
    /// Called by scanner when a file is identified as changed
    pub fn mark_file_changed(&mut self, path: &str) {
        self.changed_files.insert(path.to_string());
    }
    
    /// After scan, determine which domains were affected
    pub fn compute_affected_domains(&mut self, conn: &Connection) -> Result<()> {
        if self.changed_files.is_empty() {
            return Ok(());
        }
        
        // Check if any changed files had patterns
        let has_pattern_changes = conn.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM pattern_locations 
                WHERE file IN (SELECT value FROM json_each(?1))
            )",
            params![serde_json::to_string(&self.changed_files)?],
            |row| row.get::<_, bool>(0),
        )?;
        
        if has_pattern_changes {
            self.affected_domains.insert(Domain::Patterns);
        }
        
        // Check if any changed files had functions/call edges
        let has_callgraph_changes = conn.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM functions 
                WHERE file IN (SELECT value FROM json_each(?1))
            )",
            params![serde_json::to_string(&self.changed_files)?],
            |row| row.get::<_, bool>(0),
        )?;
        
        if has_callgraph_changes {
            self.affected_domains.insert(Domain::CallGraph);
        }
        
        // Check if any changed files had data access points
        let has_security_changes = conn.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM data_access_points 
                WHERE file IN (SELECT value FROM json_each(?1))
            )",
            params![serde_json::to_string(&self.changed_files)?],
            |row| row.get::<_, bool>(0),
        )?;
        
        if has_security_changes {
            self.affected_domains.insert(Domain::Security);
        }
        
        Ok(())
    }
    
    /// Get the set of affected domains for selective refresh
    pub fn affected_domains(&self) -> &HashSet<Domain> {
        &self.affected_domains
    }
}
```

**Integration with refresh pipeline**:
```rust
// In scan pipeline, after scan completion:
let tracker = scan_result.dependency_tracker;
tracker.compute_affected_domains(&conn)?;

if tracker.affected_domains().is_empty() {
    // No data changed — skip refresh entirely
    return Ok(ScanResult::NoChanges);
}

// Selective refresh based on affected domains
let report = refresh_pipeline.refresh_selective(
    &tracker.affected_domains().iter().cloned().collect::<Vec<_>>()
)?;
```

**Rationale**:
Fine-grained dependency tracking is the key to efficient incremental operations. Glean (Meta) and Salsa (rust-analyzer) both use dependency tracking to minimize recomputation. For Drift, the dependency graph is simple (file → Silver rows → Gold tables) and can be tracked with minimal overhead.

**Evidence**:
- Glean ownership-based invalidation: https://glean.software/docs/implementation/incrementality/ (DL-R8)
- Salsa red-green algorithm: https://salsa-rs.github.io/salsa/reference/algorithm.html (DL-R13)
- Salsa durability levels: https://rustc-dev-guide.rust-lang.org/queries/salsa.html (DL-R13)

**Implementation Notes**:
- The `DependencyTracker` is created at scan start and populated as the scanner processes files
- `compute_affected_domains()` runs after scan completion but before refresh — it checks which Silver tables have rows from changed files
- The `json_each()` approach for checking file membership is efficient for small sets (<100 files). For larger sets, use a temporary table.
- Domain-level tracking (not per-table) is sufficient for v2.0. Per-table tracking can be added later if needed.

**Risks**:
- Cross-file dependencies (e.g., a call edge spans two files) may be missed if only one file is in the changed set. Mitigation: when a file changes, also check if any call edges reference it as callee_file.
- The `json_each()` approach may be slow for very large changed file sets. Mitigation: use a temporary table for >100 files.

**Dependencies**:
- AD3 (ownership model)
- MP1, MP2 (refresh pipeline uses affected domains)
- 25-services (scan pipeline creates and populates DependencyTracker)

---

### II2: Build Reconciliation Checks for Data Integrity

**Priority**: P1
**Effort**: Medium
**Impact**: Safety net for denormalization — detects and fixes inconsistencies

**Current State**:
V1 has no reconciliation mechanism. If a counter cache, materialized view, or index becomes inconsistent with the source data, there's no way to detect or fix it. The only recovery is a full `drift scan --force`.

**Proposed Change**:
Build a comprehensive reconciliation system that compares denormalized/materialized data against computed values and fixes any inconsistencies. Exposed via `drift doctor` CLI command.

```rust
pub struct ReconciliationReport {
    pub checks: Vec<ReconciliationCheck>,
    pub total_inconsistencies: usize,
    pub auto_fixed: usize,
    pub duration: Duration,
}

pub struct ReconciliationCheck {
    pub name: String,
    pub status: CheckStatus,
    pub inconsistencies: usize,
    pub details: Vec<String>,
}

pub enum CheckStatus {
    Passed,
    Failed { auto_fixed: bool },
    Error(String),
}

pub fn run_reconciliation(conn: &Connection, auto_fix: bool) -> Result<ReconciliationReport> {
    let mut report = ReconciliationReport::default();
    
    // Check 1: Counter cache consistency (location_count)
    let location_mismatches: Vec<(String, i64, i64)> = conn.prepare("
        SELECT p.id, p.location_count, COUNT(pl.id) as actual_count
        FROM patterns p
        LEFT JOIN pattern_locations pl ON pl.pattern_id = p.id
        GROUP BY p.id
        HAVING p.location_count != COUNT(pl.id)
    ")?.query_map([], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?))
    })?.collect::<Result<Vec<_>, _>>()?;
    
    if !location_mismatches.is_empty() && auto_fix {
        conn.execute_batch("
            UPDATE patterns SET location_count = (
                SELECT COUNT(*) FROM pattern_locations WHERE pattern_id = patterns.id
            ) WHERE location_count != (
                SELECT COUNT(*) FROM pattern_locations WHERE pattern_id = patterns.id
            )
        ")?;
    }
    report.checks.push(ReconciliationCheck {
        name: "pattern location_count".into(),
        status: if location_mismatches.is_empty() { CheckStatus::Passed } 
                else { CheckStatus::Failed { auto_fixed: auto_fix } },
        inconsistencies: location_mismatches.len(),
        details: location_mismatches.iter().map(|(id, cached, actual)| 
            format!("{}: cached={}, actual={}", id, cached, actual)
        ).collect(),
    });
    
    // Check 2: Counter cache consistency (outlier_count)
    // Similar to Check 1 but for outlier_count
    
    // Check 3: Counter cache consistency (file_metadata.pattern_count)
    let file_pattern_mismatches: Vec<(String, i64, i64)> = conn.prepare("
        SELECT fm.path, fm.pattern_count, COUNT(pl.id) as actual_count
        FROM file_metadata fm
        LEFT JOIN pattern_locations pl ON pl.file = fm.path
        GROUP BY fm.path
        HAVING fm.pattern_count != COUNT(pl.id)
    ")?.query_map([], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?))
    })?.collect::<Result<Vec<_>, _>>()?;
    
    if !file_pattern_mismatches.is_empty() && auto_fix {
        conn.execute_batch("
            UPDATE file_metadata SET pattern_count = (
                SELECT COUNT(*) FROM pattern_locations WHERE file = file_metadata.path
            ) WHERE pattern_count != (
                SELECT COUNT(*) FROM pattern_locations WHERE file = file_metadata.path
            )
        ")?;
    }
    
    // Check 4: Materialized status consistency
    // Compare materialized_status fields against computed values
    
    // Check 5: Orphaned records (pattern_locations without patterns)
    let orphaned_locations: i64 = conn.query_row("
        SELECT COUNT(*) FROM pattern_locations pl
        WHERE NOT EXISTS (SELECT 1 FROM patterns p WHERE p.id = pl.pattern_id)
    ", [], |row| row.get(0))?;
    
    if orphaned_locations > 0 && auto_fix {
        conn.execute("
            DELETE FROM pattern_locations 
            WHERE NOT EXISTS (SELECT 1 FROM patterns WHERE id = pattern_locations.pattern_id)
        ", [])?;
    }
    
    // Check 6: Foreign key integrity
    // PRAGMA foreign_key_check
    
    // Check 7: File metadata staleness (files on disk not in file_metadata)
    // Walk filesystem and compare against file_metadata table
    
    // Check 8: Tag junction table consistency (pattern_tags vs patterns.tags JSON)
    
    Ok(report)
}
```

**Rationale**:
Denormalization (counter caches, materialized tables) trades write complexity for read speed. The inherent risk is data inconsistency — if the update logic has bugs, the denormalized data diverges from the source. Reconciliation checks are the safety net that detects and fixes these inconsistencies. This is a standard practice in database systems that use denormalization.

**Evidence**:
- Denormalization reconciliation: https://www.datacamp.com/tutorial/denormalization (DL-R7)
- Denormalization consistency risks: https://hypermode.com/blog/denormalize-database/ (DL-R7)
- SQLite foreign_key_check: https://www.sqlite.org/pragma.html#pragma_foreign_key_check
- SQLite integrity_check: https://www.sqlite.org/pragma.html#pragma_integrity_check

**Implementation Notes**:
- `drift doctor` runs all reconciliation checks and reports results
- `drift doctor --fix` runs checks and auto-fixes inconsistencies
- Reconciliation should also run after database restore and after schema migrations
- Each check is independent — a failure in one check doesn't prevent other checks from running
- The reconciliation queries use correlated subqueries which may be slow for very large datasets. For >10K patterns, consider using temporary tables for the comparison.

**Risks**:
- Auto-fix could mask bugs in the write pipeline. Mitigation: log all auto-fixes with details so developers can investigate the root cause.
- Reconciliation queries may be slow for large databases. Mitigation: add progress reporting and allow cancellation.

**Dependencies**:
- 10-cli (`drift doctor` command)
- GL1, GL2 (materialized tables to reconcile)
- GL3 (file_metadata counter caches to reconcile)
- IX3 (pattern_tags junction table to reconcile)

---

## Phase 7: Operational Safety

### OP1: Build Retention Policies for Trend and History Data

**Priority**: P1
**Effort**: Low
**Impact**: Prevents unbounded disk growth from append-only tables

**Current State**:
V1 has no retention policies. TrendsView, scan history, and health snapshots grow unbounded. Over months of active development, this accumulates significant data that is never pruned.

**Proposed Change**:
Build configurable retention policies for append-only tables. Policies are enforced during the refresh pipeline (after scan) and via `drift maintenance` CLI command.

```sql
-- Retention policy configuration (stored in drift.db)
CREATE TABLE retention_policies (
    table_name TEXT PRIMARY KEY,
    max_age_days INTEGER,           -- Delete entries older than N days
    max_count INTEGER,              -- Keep at most N entries
    last_pruned_at TEXT,
    rows_pruned_last INTEGER DEFAULT 0
) STRICT;

-- Default policies
INSERT INTO retention_policies (table_name, max_age_days, max_count) VALUES
    ('health_trends', 180, 500),        -- 6 months or 500 entries
    ('scan_history', 365, 1000),        -- 1 year or 1000 scans
    ('pattern_history', 90, NULL),      -- 90 days, no count limit
    ('query_telemetry', 30, 10000);     -- 30 days or 10K entries
```

**Pruning implementation**:
```rust
pub fn enforce_retention_policies(conn: &Connection) -> Result<RetentionReport> {
    let mut report = RetentionReport::default();
    
    let policies: Vec<RetentionPolicy> = conn.prepare(
        "SELECT table_name, max_age_days, max_count FROM retention_policies"
    )?.query_map([], |row| {
        Ok(RetentionPolicy {
            table_name: row.get(0)?,
            max_age_days: row.get(1)?,
            max_count: row.get(2)?,
        })
    })?.collect::<Result<Vec<_>, _>>()?;
    
    for policy in &policies {
        let mut pruned = 0;
        
        // Age-based pruning
        if let Some(max_age) = policy.max_age_days {
            let deleted = conn.execute(
                &format!(
                    "DELETE FROM {} WHERE recorded_at < datetime('now', '-{} days')",
                    policy.table_name, max_age
                ),
                [],
            )?;
            pruned += deleted;
        }
        
        // Count-based pruning (keep most recent N)
        if let Some(max_count) = policy.max_count {
            let deleted = conn.execute(
                &format!(
                    "DELETE FROM {} WHERE id NOT IN (
                        SELECT id FROM {} ORDER BY recorded_at DESC LIMIT {}
                    )",
                    policy.table_name, policy.table_name, max_count
                ),
                [],
            )?;
            pruned += deleted;
        }
        
        // Update policy metadata
        conn.execute(
            "UPDATE retention_policies SET last_pruned_at = datetime('now'), rows_pruned_last = ? WHERE table_name = ?",
            params![pruned, policy.table_name],
        )?;
        
        report.tables_pruned.push((policy.table_name.clone(), pruned));
    }
    
    report.total_pruned = report.tables_pruned.iter().map(|(_, n)| n).sum();
    Ok(report)
}
```

**Rationale**:
Append-only tables (health_trends, scan_history, pattern_history) grow without bound. For active projects with daily scans, this can accumulate thousands of entries over months. Retention policies prevent unbounded growth while preserving enough history for trend analysis and debugging.

**Evidence**:
- Delta Lake retention policies: https://www.databricks.com/blog/delta-lake-explained-boost-data-reliability-cloud-storage (DL-R15)
- V1 limitation L10: "No retention policies — views/indexes/shards grow unbounded"

**Implementation Notes**:
- Retention policies are enforced after the refresh pipeline completes (not during scan)
- The `drift maintenance` CLI command runs retention policies on demand
- After pruning, consider running `PRAGMA incremental_vacuum` to reclaim disk space
- Default policies are conservative — 6 months of trends, 1 year of scan history
- Users can customize policies via `drift config set retention.health_trends.max_age_days 365`

**Risks**:
- Aggressive pruning could delete data needed for long-term trend analysis. Mitigation: default policies are conservative, and users can customize.
- SQL injection risk from string formatting table names. Mitigation: validate table_name against a whitelist of known tables.

**Dependencies**:
- MP3 (health_trends table)
- 10-cli (`drift maintenance` command)
- 08-storage (retention_policies table in schema)

---

### OP2: Build Query Telemetry Persistence

**Priority**: P2
**Effort**: Low
**Impact**: Enables long-term query performance monitoring and optimization

**Current State**:
V1's QueryStats is in-memory only — hit counts and response times are lost on process restart. There's no way to analyze query patterns over time or identify performance regressions.

**Proposed Change**:
Build a lightweight telemetry table that records query performance metrics. Sampled (not every query) to minimize overhead.

```sql
CREATE TABLE query_telemetry (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recorded_at TEXT NOT NULL DEFAULT (datetime('now')),
    -- Query identification
    query_type TEXT NOT NULL,           -- 'status', 'patterns_list', 'file_patterns', etc.
    source TEXT NOT NULL,               -- 'mcp', 'cli', 'quality_gate'
    -- Performance metrics
    execution_time_us INTEGER NOT NULL, -- Microseconds
    rows_returned INTEGER,
    -- Query details (optional, for slow query analysis)
    filters TEXT,                       -- JSON: {category: 'auth', status: 'approved'}
    used_index TEXT,                    -- Which index was used (from EXPLAIN QUERY PLAN)
    -- Flags
    was_cache_hit INTEGER DEFAULT 0,    -- 1 if served from materialized table
    was_slow INTEGER DEFAULT 0          -- 1 if execution_time_us > threshold
) STRICT;

-- Index for time-range analysis
CREATE INDEX idx_telemetry_time ON query_telemetry(recorded_at DESC);

-- Index for slow query analysis
CREATE INDEX idx_telemetry_slow ON query_telemetry(query_type, execution_time_us DESC)
    WHERE was_slow = 1;
```

**Sampling strategy**:
```rust
pub struct TelemetryRecorder {
    sample_rate: f64,       // 0.0 to 1.0 (default: 0.1 = 10%)
    slow_threshold_us: u64, // Always record queries slower than this (default: 10000 = 10ms)
    rng: ThreadRng,
}

impl TelemetryRecorder {
    pub fn should_record(&mut self, execution_time_us: u64) -> bool {
        // Always record slow queries
        if execution_time_us >= self.slow_threshold_us {
            return true;
        }
        // Sample normal queries
        self.rng.gen::<f64>() < self.sample_rate
    }
    
    pub fn record(&self, conn: &Connection, entry: &TelemetryEntry) -> Result<()> {
        conn.execute(
            "INSERT INTO query_telemetry (
                query_type, source, execution_time_us, rows_returned,
                filters, used_index, was_cache_hit, was_slow
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                entry.query_type, entry.source, entry.execution_time_us,
                entry.rows_returned, entry.filters, entry.used_index,
                entry.was_cache_hit, entry.was_slow,
            ],
        )?;
        Ok(())
    }
}
```

**Rationale**:
Persistent telemetry enables data-driven optimization. Without it, performance regressions go undetected until users complain. With it, `drift doctor --performance` can identify slow queries, missing indexes, and degradation trends.

**Evidence**:
- V1 limitation L12: "No persistent telemetry — QueryStats is in-memory only"
- SQLite ultra-performance optimizations: https://www.powersync.com/blog/sqlite-optimizations-for-ultra-high-performance (DL-R12)

**Implementation Notes**:
- Sampling (10% default) keeps overhead minimal — most queries are not recorded
- Slow queries (>10ms) are always recorded for analysis
- The `filters` JSON column enables analysis of which query patterns are slowest
- Telemetry is subject to retention policies (OP1) — default 30 days
- `drift doctor --performance` analyzes telemetry to suggest index improvements

**Risks**:
- Telemetry writes add latency to queries. Mitigation: write telemetry asynchronously (fire-and-forget) or batch telemetry writes.
- Telemetry data could contain sensitive information (query filters). Mitigation: don't record actual data values, only filter types.

**Dependencies**:
- OP1 (retention policies for telemetry data)
- 10-cli (`drift doctor --performance` command)
- 07-mcp (MCP tools record telemetry)

---

### OP3: Build Data Integrity Validation on Startup

**Priority**: P1
**Effort**: Low
**Impact**: Detects corruption early, before it causes downstream failures

**Current State**:
V1 has no startup validation. Corrupt JSON files silently produce wrong results. There's no integrity check, no schema version validation, no foreign key verification.

**Proposed Change**:
Run a lightweight integrity check on database open, with a full check available via `drift doctor`.

```rust
pub enum ValidationLevel {
    Quick,  // Schema version + basic sanity (< 1ms)
    Normal, // Quick + foreign key check (< 100ms)
    Full,   // Normal + integrity_check + reconciliation (seconds)
}

pub fn validate_database(
    conn: &Connection, 
    level: ValidationLevel,
) -> Result<ValidationReport> {
    let mut report = ValidationReport::default();
    
    // Quick: Always run on startup
    // Check schema version matches expected
    let version: i32 = conn.pragma_query_value(
        None, "user_version", |row| row.get(0)
    )?;
    report.schema_version = version;
    report.expected_version = CURRENT_SCHEMA_VERSION;
    
    if version > CURRENT_SCHEMA_VERSION {
        return Err(DriftError::SchemaVersionTooNew {
            found: version,
            expected: CURRENT_SCHEMA_VERSION,
        });
    }
    
    // Check materialized tables exist and have data
    let has_status: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM materialized_status WHERE id = 1)",
        [], |row| row.get(0),
    )?;
    report.materialized_status_populated = has_status;
    
    if matches!(level, ValidationLevel::Quick) {
        return Ok(report);
    }
    
    // Normal: Foreign key check
    let fk_violations: Vec<FkViolation> = conn.prepare(
        "PRAGMA foreign_key_check"
    )?.query_map([], |row| {
        Ok(FkViolation {
            table: row.get(0)?,
            rowid: row.get(1)?,
            parent: row.get(2)?,
            fk_index: row.get(3)?,
        })
    })?.collect::<Result<Vec<_>, _>>()?;
    report.fk_violations = fk_violations;
    
    if matches!(level, ValidationLevel::Normal) {
        return Ok(report);
    }
    
    // Full: SQLite integrity check + reconciliation
    conn.pragma_query(None, "integrity_check", |row| {
        let result: String = row.get(0)?;
        if result != "ok" {
            report.integrity_errors.push(result);
        }
        Ok(())
    })?;
    
    // Run reconciliation checks (II2)
    report.reconciliation = Some(
        run_reconciliation(conn, false)?  // Don't auto-fix during validation
    );
    
    Ok(report)
}
```

**When to validate**:
| Event | Level | Rationale |
|-------|-------|-----------|
| Database open | Quick | Fast, catches version mismatches |
| After restore | Full | Verify restored data integrity |
| After migration | Normal | Verify FK integrity after schema changes |
| `drift doctor` | Full | Comprehensive check on demand |
| After crash recovery | Full | Detect corruption from incomplete writes |

**Rationale**:
Early detection of data corruption prevents cascading failures. A corrupt `materialized_status` table produces wrong health scores, which causes quality gates to make wrong decisions, which causes CI/CD pipelines to pass or fail incorrectly. Catching corruption at startup prevents this cascade.

**Evidence**:
- SQLite integrity_check: https://www.sqlite.org/pragma.html#pragma_integrity_check
- SQLite foreign_key_check: https://www.sqlite.org/pragma.html#pragma_foreign_key_check
- V1 limitation L15: "No data validation — corrupt JSON silently produces wrong results"
- Delta Lake schema enforcement: https://www.databricks.com/blog/delta-lake-explained-boost-data-reliability-cloud-storage (DL-R15)

**Implementation Notes**:
- Quick validation adds <1ms to startup — negligible
- Normal validation (FK check) takes <100ms for typical databases
- Full validation (integrity_check) can take seconds for large databases — only run on demand
- If schema version is too new (database from a newer Drift version), refuse to open with a clear error message
- If materialized tables are empty, trigger a refresh instead of failing

**Risks**:
- Full integrity_check on large databases can take several seconds. Mitigation: only run on demand (`drift doctor`), not on every startup.

**Dependencies**:
- 08-storage (DatabaseManager calls validate on open)
- II2 (reconciliation checks)
- 10-cli (`drift doctor` command)


---

## Phase 8: Consumer Migration

### CM1: Build MCP Tool Query Layer

**Priority**: P0
**Effort**: Medium
**Impact**: Every MCP tool must be updated to query SQLite instead of the v1 Data Lake

**Current State**:
V1's MCP tools query the Data Lake through the QueryEngine, which routes to views, indexes, shards, or raw data. Each tool receives a `PaginatedResult` with source tracking. The QueryEngine handles staleness checking, pagination, and stats.

**Proposed Change**:
Build a Rust query layer that MCP tools call via NAPI bindings. Each MCP tool maps to one or more SQL queries against Gold + Silver tables.

**Tool → Query mapping**:

| MCP Tool | V1 Data Source | V2 Query |
|----------|---------------|----------|
| `drift_status` | QueryEngine → StatusView | `SELECT * FROM materialized_status WHERE id = 1` |
| `drift_patterns_list` | QueryEngine → PatternIndexView or CategoryIndex | `SELECT ... FROM patterns WHERE category = ? AND status = ? ORDER BY confidence_score DESC LIMIT ? OFFSET ?` (uses covering index IX1) |
| `drift_file_patterns` | QueryEngine → FileIndex → PatternShardStore | `SELECT p.* FROM patterns p JOIN pattern_locations pl ON p.id = pl.pattern_id WHERE pl.file = ?` (uses IX4) |
| `drift_security_summary` | QueryEngine → SecuritySummaryView | `SELECT * FROM materialized_security WHERE id = 1` |
| `drift_code_examples` | QueryEngine → ExamplesStore | `SELECT * FROM pattern_examples WHERE pattern_id = ? ORDER BY quality_score DESC LIMIT ?` |
| `drift_pattern_detail` | QueryEngine → PatternShardStore | `SELECT * FROM patterns WHERE id = ?` + `SELECT * FROM pattern_locations WHERE pattern_id = ?` |
| `drift_impact_analysis` | QueryEngine → EntryPointIndex | Recursive CTE on `call_edges` (see 04-call-graph) |
| `drift_health_trends` | QueryEngine → TrendsView | `SELECT * FROM health_trends ORDER BY recorded_at DESC LIMIT ?` |

**NAPI binding interface**:
```rust
#[napi]
impl DriftDatabase {
    /// Instant status read from materialized table
    #[napi]
    pub fn get_status(&self) -> napi::Result<serde_json::Value> {
        let reader = self.manager.reader();
        let row = reader.query_row(
            "SELECT * FROM materialized_status WHERE id = 1",
            [],
            |row| MaterializedStatus::from_row(row),
        ).optional().map_err(to_napi_error)?;
        
        Ok(serde_json::to_value(&row).map_err(to_napi_error)?)
    }
    
    /// Paginated pattern listing using covering index
    #[napi]
    pub fn query_patterns(&self, opts: PatternQueryOptions) -> napi::Result<serde_json::Value> {
        let reader = self.manager.reader();
        let (sql, params) = build_pattern_query(&opts);
        let mut stmt = reader.prepare_cached(&sql).map_err(to_napi_error)?;
        
        let patterns: Vec<PatternSummary> = stmt.query_map(
            params_from_iter(params.iter()),
            |row| PatternSummary::from_row(row),
        ).map_err(to_napi_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(to_napi_error)?;
        
        Ok(serde_json::to_value(&PaginatedResult {
            items: patterns,
            has_more: patterns.len() > opts.limit.unwrap_or(50) as usize,
            // ... pagination metadata
        }).map_err(to_napi_error)?)
    }
}
```

**Rationale**:
MCP tools are the primary consumer of the data lake. Every tool must be updated to query SQLite directly instead of going through the v1 QueryEngine. The NAPI bindings provide type-safe, high-performance access from TypeScript to Rust-owned SQLite queries.

**Evidence**:
- V1 QueryEngine routing (proven query patterns, native replacement)
- SQLite query planner replaces manual routing: https://sqlite.org/queryplanner.html (DL-R2)
- Covering indexes for instant listing: https://sqlite.org/queryplanner.html (DL-R5)

**Implementation Notes**:
- Each MCP tool should use `prepare_cached()` for repeated queries
- Pagination uses keyset cursors (not OFFSET) for consistent performance
- The `drift_status` query is a single-row read from a materialized table — guaranteed <1ms
- The `drift_patterns_list` query uses the covering index (IX1) — no table access needed
- All queries go through `reader()` connections with `PRAGMA query_only = ON`

**Risks**:
- Breaking changes in MCP tool response format. Mitigation: maintain the same JSON response structure as v1 — the backend changes, not the API.
- Query performance regression for complex queries (impact analysis). Mitigation: benchmark against v1 and add materialization if needed.

**Dependencies**:
- 07-mcp (all MCP tools)
- 08-storage (NAPI bindings)
- IX1, IX4 (indexes that queries depend on)
- GL1, GL2 (materialized tables that queries read)

---

### CM2: Build CLI Command Query Updates

**Priority**: P1
**Effort**: Medium
**Impact**: All CLI commands that read data must be updated to use the new query layer

**Current State**:
V1's CLI commands (`drift status`, `drift patterns`, `drift security`, etc.) query the Data Lake through the same QueryEngine used by MCP tools. The CLI adds formatting (tables, colors, JSON output) on top of the query results.

**Proposed Change**:
CLI commands use the same NAPI bindings as MCP tools (CM1). The query layer is shared — only the presentation differs.

**CLI → Query mapping**:

| CLI Command | Query Method | Output Format |
|-------------|-------------|---------------|
| `drift status` | `get_status()` | Formatted table with health score, pattern counts, security risk |
| `drift patterns` | `query_patterns(opts)` | Table with id, name, category, status, confidence |
| `drift patterns --category auth` | `query_patterns({category: 'auth'})` | Filtered table |
| `drift security` | `get_security_summary()` | Security posture table |
| `drift doctor` | `validate_database(Full)` + `run_reconciliation(auto_fix)` | Diagnostic report |
| `drift doctor --fix` | `run_reconciliation(true)` | Fix report with changes made |
| `drift maintenance` | `enforce_retention_policies()` | Pruning report |
| `drift stats` | `get_status()` + file_metadata aggregations | Project statistics |

**Rationale**:
CLI and MCP tools share the same underlying queries. The only difference is presentation: MCP returns JSON for AI consumption, CLI formats for human consumption. Sharing the query layer ensures consistency and reduces code duplication.

**Evidence**:
- V1 CLI commands use QueryEngine (same query layer as MCP)
- CQRS read model serves multiple consumers: https://sqlite.org/queryplanner.html (DL-R10)

**Implementation Notes**:
- CLI commands should support `--json` flag for machine-readable output (same JSON as MCP)
- `drift doctor` is the primary diagnostic tool — it runs validation (OP3), reconciliation (II2), and performance analysis (OP2)
- `drift maintenance` runs retention policies (OP1) and optionally VACUUM
- All CLI queries go through the same `reader()` connection pool as MCP queries

**Risks**:
- CLI startup latency if cache warming (CW1) is enabled. Mitigation: make CLI cache warming optional and only enable for `drift status` and `drift patterns`.

**Dependencies**:
- CM1 (shared query layer)
- 10-cli (CLI command framework)
- II2, OP1, OP2, OP3 (diagnostic commands)

---

### CM3: Build Quality Gate Integration Updates

**Priority**: P1
**Effort**: Low
**Impact**: Quality gates must read from the new materialized tables

**Current State**:
V1's quality gates read health score and pattern compliance data from the Data Lake's StatusView and ManifestStore. The gates check thresholds (e.g., health score >= 70) and return pass/fail results.

**Proposed Change**:
Quality gates read from `materialized_status` and Silver-layer tables directly. The query interface is simplified because materialized tables provide instant access to pre-computed metrics.

```rust
pub struct QualityGateInput {
    pub health_score: f64,
    pub approved_ratio: f64,
    pub security_risk_level: String,
    pub security_violations: i64,
    pub pattern_compliance: PatternCompliance,
}

pub fn get_quality_gate_input(conn: &Connection) -> Result<QualityGateInput> {
    let status = conn.query_row(
        "SELECT health_score, approved_patterns, total_patterns, 
                security_risk_level, security_violations
         FROM materialized_status WHERE id = 1",
        [],
        |row| Ok(QualityGateInput {
            health_score: row.get(0)?,
            approved_ratio: if row.get::<_, i64>(2)? > 0 {
                row.get::<_, i64>(1)? as f64 / row.get::<_, i64>(2)? as f64
            } else { 0.0 },
            security_risk_level: row.get(3)?,
            security_violations: row.get(4)?,
            pattern_compliance: PatternCompliance::default(), // Computed separately
        }),
    )?;
    
    Ok(status)
}

pub fn check_pattern_compliance(
    conn: &Connection,
    baseline: &ComplianceBaseline,
) -> Result<PatternCompliance> {
    // Compare current pattern counts against baseline
    let current_approved: i64 = conn.query_row(
        "SELECT COUNT(*) FROM patterns WHERE status = 'approved'",
        [], |row| row.get(0),
    )?;
    
    let regression = current_approved < baseline.min_approved_patterns;
    
    Ok(PatternCompliance {
        current_approved,
        baseline_approved: baseline.min_approved_patterns,
        regression,
    })
}
```

**Rationale**:
Quality gates are the enforcement mechanism for CI/CD pipelines. They must read accurate, up-to-date data with minimal latency. Materialized tables provide both — the data is pre-computed (accurate) and read in <1ms (fast). The quality gate doesn't need to aggregate data itself; it just reads the pre-computed metrics and checks thresholds.

**Evidence**:
- V1 quality gates read from StatusView and ManifestStore
- Materialized tables for instant reads: https://madflex.de/SQLite-triggers-as-replacement-for-a-materialized-view/ (DL-R1)

**Implementation Notes**:
- Quality gates should fail gracefully if `materialized_status` is empty (first run before any scan)
- The compliance baseline is stored in the quality gate configuration, not in the data lake
- Quality gates run after the refresh pipeline completes, so materialized data is always current

**Risks**:
- If the refresh pipeline fails, quality gates read stale data. Mitigation: check `refreshed_at` timestamp and warn if data is older than the most recent scan.

**Dependencies**:
- 09-quality-gates (gate implementation)
- GL1 (materialized_status table)
- MP1 (refresh pipeline ensures data is current)


---

## Phase 9: Advanced Optimizations

### AO1: Build SQLite Performance Pragma Configuration

**Priority**: P0
**Effort**: Low
**Impact**: Foundation-level performance — every query benefits from correct pragma configuration

**Current State**:
V1's Rust `CallGraphDb` already uses WAL mode, NORMAL synchronous, and 256MB mmap. But these pragmas are only applied to the call graph database, not to the main `drift.db`. The TypeScript layer uses default SQLite settings.

**Proposed Change**:
Apply a comprehensive pragma configuration to every connection on open. This is defined in 08-storage (FA1) but is critical for data lake performance.

```sql
-- Applied to EVERY connection on open
PRAGMA journal_mode = WAL;          -- Write-ahead logging for concurrent reads
PRAGMA synchronous = NORMAL;        -- Safe with WAL, avoids fsync on every commit
PRAGMA foreign_keys = ON;           -- Enforce referential integrity
PRAGMA temp_store = 2;              -- Use memory for temp tables
PRAGMA cache_size = -64000;         -- 64MB page cache
PRAGMA mmap_size = 268435456;       -- 256MB memory-mapped I/O
PRAGMA busy_timeout = 5000;         -- 5s busy timeout before SQLITE_BUSY

-- Applied to READ connections only
PRAGMA query_only = ON;             -- Prevent accidental writes

-- Applied before closing connections
PRAGMA analysis_limit = 400;
PRAGMA optimize;                    -- Update query planner statistics
```

**Why these values matter for the data lake**:
- `cache_size = 64MB`: Keeps the most frequently accessed Gold-layer pages in memory. The `materialized_status` and `materialized_security` tables are tiny (<1KB each) and will always be in cache after the first read.
- `mmap_size = 256MB`: Memory-maps the database file for large sequential reads. Beneficial for covering index scans that read many index pages.
- `WAL mode`: Enables MCP tools to read while `drift scan` writes. Without WAL, readers would block during scan writes.
- `PRAGMA optimize` on close: Updates the query planner's statistics based on actual query patterns, improving future query plans.

**Rationale**:
These pragmas are the highest-leverage performance optimization in SQLite. WAL mode alone provides 2-20x improvement for concurrent workloads. Combined with appropriate cache size and mmap, they ensure that the data lake's Gold-layer queries run at memory speed, not disk speed.

**Evidence**:
- SQLite WAL mode: https://www.sqlite.org/wal.html
- SQLite ultra-performance optimizations: https://www.powersync.com/blog/sqlite-optimizations-for-ultra-high-performance (DL-R12)
- Database performance optimization: https://databurton.com/research/database-performance-optimization (DL-R12)

**Implementation Notes**:
- These pragmas are defined in 08-storage (FA1) and applied by `DatabaseManager`. Listed here because they directly impact data lake query performance.
- `PRAGMA optimize` should run on connection close, not on every query. It analyzes query patterns and updates statistics.
- `cache_size = -64000` uses negative value to specify KB (not pages). This is more portable across page sizes.

**Risks**:
- `mmap_size = 256MB` may be too large for memory-constrained environments. Mitigation: make configurable via `DatabaseConfig`.

**Dependencies**:
- 08-storage (DatabaseManager applies pragmas)

---

### AO2: Build EXPLAIN QUERY PLAN Validation Suite

**Priority**: P2
**Effort**: Medium
**Impact**: Ensures all critical queries use the intended indexes — prevents silent performance regressions

**Current State**:
V1 has no query plan validation. There's no way to verify that queries use the intended indexes or detect when a schema change causes a query plan regression.

**Proposed Change**:
Build a test suite that runs `EXPLAIN QUERY PLAN` on all critical queries and asserts that the expected indexes are used.

```rust
#[cfg(test)]
mod query_plan_tests {
    use super::*;
    
    fn setup_test_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        // Apply schema migrations
        initialize(&mut conn).unwrap();
        // Insert test data
        insert_test_patterns(&conn, 100);
        insert_test_functions(&conn, 50);
        conn
    }
    
    #[test]
    fn test_patterns_list_uses_covering_index() {
        let conn = setup_test_db();
        let plan = conn.query_row(
            "EXPLAIN QUERY PLAN 
             SELECT id, name, category, subcategory, status, confidence_score,
                    severity, location_count, outlier_count
             FROM patterns
             WHERE category = 'authentication' AND status = 'approved'
             ORDER BY confidence_score DESC
             LIMIT 20",
            [],
            |row| row.get::<_, String>(3),  // detail column
        ).unwrap();
        
        assert!(
            plan.contains("USING COVERING INDEX idx_patterns_listing"),
            "Expected covering index, got: {}", plan
        );
    }
    
    #[test]
    fn test_file_patterns_uses_file_index() {
        let conn = setup_test_db();
        let plan = conn.query_row(
            "EXPLAIN QUERY PLAN
             SELECT DISTINCT p.id FROM patterns p
             JOIN pattern_locations pl ON p.id = pl.pattern_id
             WHERE pl.file = 'src/auth/login.ts'",
            [],
            |row| row.get::<_, String>(3),
        ).unwrap();
        
        assert!(
            plan.contains("idx_pattern_locations_file"),
            "Expected file index, got: {}", plan
        );
    }
    
    #[test]
    fn test_approved_patterns_uses_partial_index() {
        let conn = setup_test_db();
        let plan = conn.query_row(
            "EXPLAIN QUERY PLAN
             SELECT id, category, confidence_score
             FROM patterns
             WHERE status = 'approved' AND category = 'authentication'
             ORDER BY confidence_score DESC",
            [],
            |row| row.get::<_, String>(3),
        ).unwrap();
        
        assert!(
            plan.contains("idx_approved_patterns"),
            "Expected partial index for approved patterns, got: {}", plan
        );
    }
    
    #[test]
    fn test_status_query_is_instant() {
        let conn = setup_test_db();
        // Populate materialized_status
        refresh_materialized_status(&conn).unwrap();
        
        let plan = conn.query_row(
            "EXPLAIN QUERY PLAN
             SELECT * FROM materialized_status WHERE id = 1",
            [],
            |row| row.get::<_, String>(3),
        ).unwrap();
        
        // Should use PRIMARY KEY lookup (not SCAN)
        assert!(
            plan.contains("SEARCH") && !plan.contains("SCAN"),
            "Expected SEARCH (not SCAN) for singleton table, got: {}", plan
        );
    }
}
```

**Rationale**:
Query plan validation is the only way to ensure that indexes are actually used by the queries they were designed for. Without it, a schema change or query modification could silently cause a full table scan instead of an index lookup — a performance regression that's invisible until users report slow queries.

**Evidence**:
- SQLite EXPLAIN QUERY PLAN: https://sqlite.org/queryplanner.html (DL-R2)
- SQLite optimizer overview: https://sqlite.org/optoverview.html (DL-R2)

**Implementation Notes**:
- Run these tests in CI to catch query plan regressions on every schema change
- The tests need representative data (not empty tables) because the query planner may choose different plans for empty vs. populated tables
- Focus on the most critical queries: status, patterns list, file patterns, security summary
- Use `EXPLAIN QUERY PLAN` (not `EXPLAIN`) — it shows the high-level plan, not the bytecode

**Risks**:
- Query plans may differ between SQLite versions. Mitigation: pin the SQLite version in the build and test against the same version.
- Test data distribution may not match production. Mitigation: use realistic test data with skewed distributions (many discovered patterns, few approved).

**Dependencies**:
- IX1, IX2, IX4 (indexes being validated)
- GL1, GL2 (materialized tables being validated)
- 08-storage (schema and test infrastructure)

---

### AO3: Build VACUUM and Checkpoint Strategy

**Priority**: P2
**Effort**: Low
**Impact**: Prevents WAL file growth and reclaims disk space after large deletions

**Current State**:
V1 has no VACUUM or checkpoint strategy. The WAL file can grow unbounded during long scan sessions. Deleted data (from retention policies) doesn't reclaim disk space.

**Proposed Change**:
Build an automated VACUUM and WAL checkpoint strategy.

```rust
pub fn maintenance_vacuum(conn: &Connection) -> Result<VacuumReport> {
    let size_before = get_db_size(conn)?;
    
    // Checkpoint WAL to main database
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
    
    // Incremental vacuum (if auto_vacuum is enabled)
    // This reclaims space from deleted pages without rewriting the entire file
    conn.execute_batch("PRAGMA incremental_vacuum(1000)")?;
    
    let size_after = get_db_size(conn)?;
    
    Ok(VacuumReport {
        size_before,
        size_after,
        reclaimed: size_before.saturating_sub(size_after),
    })
}

pub fn maintenance_full_vacuum(conn: &Connection) -> Result<VacuumReport> {
    // Full VACUUM rewrites the entire database file
    // Only run on explicit user request (drift maintenance --vacuum)
    let size_before = get_db_size(conn)?;
    conn.execute_batch("VACUUM")?;
    let size_after = get_db_size(conn)?;
    
    Ok(VacuumReport {
        size_before,
        size_after,
        reclaimed: size_before.saturating_sub(size_after),
    })
}
```

**Checkpoint strategy**:
- Auto-checkpoint every 1000 WAL pages (SQLite default, configured via `PRAGMA wal_autocheckpoint`)
- Explicit `PRAGMA wal_checkpoint(TRUNCATE)` after scan completion (resets WAL file to zero)
- `drift maintenance --vacuum` for full VACUUM on user request

**Rationale**:
WAL mode accumulates changes in the WAL file. Without checkpointing, the WAL file grows continuously during long scan sessions. After retention policy pruning (OP1), deleted pages aren't reclaimed until VACUUM runs. A checkpoint after scan completion keeps the WAL file small, and incremental vacuum reclaims space from deletions.

**Evidence**:
- Delta Lake file compaction (OPTIMIZE): https://www.databricks.com/blog/delta-lake-explained-boost-data-reliability-cloud-storage (DL-R15)
- SQLite WAL checkpoint: https://www.sqlite.org/wal.html
- SQLite VACUUM: https://www.sqlite.org/lang_vacuum.html

**Implementation Notes**:
- `PRAGMA wal_checkpoint(TRUNCATE)` is the most aggressive checkpoint mode — it copies all WAL content to the main database and truncates the WAL file to zero bytes
- Full VACUUM requires exclusive access (no concurrent readers). Only run on explicit user request.
- Enable `PRAGMA auto_vacuum = INCREMENTAL` in the initial schema to support incremental vacuum without full rewrite
- The checkpoint after scan should run after the refresh pipeline completes (all Gold-layer writes are done)

**Risks**:
- Full VACUUM on large databases can take seconds and blocks all access. Mitigation: only run on explicit user request, not automatically.
- `wal_checkpoint(TRUNCATE)` blocks writers briefly. Mitigation: run after scan completion when no writes are in progress.

**Dependencies**:
- 08-storage (DatabaseManager)
- OP1 (retention policies create deleted pages that need vacuuming)
- 10-cli (`drift maintenance --vacuum` command)

---

## Recommendation Summary

### By Priority

| Priority | Count | Recommendations |
|----------|-------|----------------|
| P0 (Build First) | 10 | AD1, AD2, AD3, GL1, GL2, GL3, IX1, IX4, MP1, CM1, AO1 |
| P1 (Important) | 13 | IX2, IX3, MP2, MP3, GC1, CW1, II1, II2, OP1, OP3, CM2, CM3 |
| P2 (Nice to Have) | 4 | GC2, OP2, AO2, AO3 |

### By Effort

| Effort | Count | Recommendations |
|--------|-------|----------------|
| Low | 16 | AD1, AD2, IX1, IX2, IX3, IX4, MP3, GC1, GC2, CW1, OP1, OP2, OP3, CM3, AO1, AO3 |
| Medium | 11 | AD3, GL1, GL2, GL3, MP1, MP2, II1, II2, CM1, CM2, AO2 |
| High | 1 | MP2 |

### By Phase

| Phase | Recommendations | Key Deliverable |
|-------|----------------|-----------------|
| Phase 0: Architectural Decisions | AD1, AD2, AD3 | Medallion architecture, CQRS, ownership model |
| Phase 1: Gold Layer Schema | GL1, GL2, GL3 | materialized_status, materialized_security, file_metadata |
| Phase 2: Index Strategy | IX1, IX2, IX3, IX4 | Covering indexes, partial indexes, expression indexes, dimension indexes |
| Phase 3: Materialization Pipeline | MP1, MP2, MP3 | Refresh pipeline, delta-aware refresh, health trends |
| Phase 4: Generated Columns | GC1, GC2 | confidence_level, risk scores |
| Phase 5: Cache Warming | CW1 | Startup warming queries |
| Phase 6: Incremental Invalidation | II1, II2 | Dependency tracking, reconciliation |
| Phase 7: Operational Safety | OP1, OP2, OP3 | Retention policies, telemetry, validation |
| Phase 8: Consumer Migration | CM1, CM2, CM3 | MCP tools, CLI commands, quality gates |
| Phase 9: Advanced Optimizations | AO1, AO2, AO3 | Pragmas, query plan validation, VACUUM |

### Cross-Category Dependencies

| This Category | Depends On | Nature of Dependency |
|--------------|-----------|---------------------|
| 24-data-lake | 08-storage | Schema definitions, DatabaseManager, NAPI bindings |
| 24-data-lake | 01-rust-core | Scanner populates file_metadata, produces Silver-layer data |
| 24-data-lake | 25-services | Scan pipeline triggers refresh, orchestrates incremental flow |
| 24-data-lake | 07-mcp | MCP tools consume Gold-layer data |
| 24-data-lake | 10-cli | CLI commands consume Gold-layer data, diagnostic tools |
| 24-data-lake | 09-quality-gates | Quality gates read materialized metrics |
| 24-data-lake | 03-detectors | Produces patterns in Silver layer |
| 24-data-lake | 04-call-graph | Produces functions/call_edges in Silver layer |
| 24-data-lake | 05-analyzers | Produces security data in Silver layer |

### V1 Elimination Summary

| V1 Component | Lines Eliminated | V2 Replacement |
|-------------|-----------------|----------------|
| QueryEngine | ~400 | SQLite query planner + covering indexes |
| ViewStore | ~430 | materialized_status + materialized_security tables |
| IndexStore | ~440 | SQL indexes (IX1, IX2, IX3, IX4) |
| PatternShardStore | ~430 | `WHERE category = ?` on patterns table |
| CallGraphShardStore | ~650 | `WHERE file = ?` on functions table |
| SecurityShardStore | ~660 | `WHERE table_name = ?` on data_access_points table |
| ExamplesStore | ~550 | `WHERE pattern_id = ?` on pattern_examples table |
| ViewMaterializer | ~590 | RefreshPipeline (MP1) |
| ManifestStore | ~420 | file_metadata table + materialized tables |
| Types | ~300 | Rust structs (type-safe at compile time) |
| **Total** | **~4,870** | **~800 lines Rust (refresh pipeline + queries + reconciliation)** |

### Open Questions Resolved

| # | Open Question (from RECAP) | Resolution |
|---|---------------------------|------------|
| 1 | Materialized view refresh strategy | Use regular tables with explicit refresh (MP1). Not triggers during bulk writes. Not regular views (too slow for complex aggregations). |
| 2 | Query routing necessity | SQLite query planner fully replaces manual routing for Silver-layer queries. Gold-layer queries go directly to materialized tables — no routing needed. |
| 3 | Telemetry persistence | Yes — persist to `query_telemetry` table with sampling (OP2). 10% sample rate, always record slow queries. |
| 4 | Retention policies | Time-based + count-based (OP1). 6 months / 500 entries for trends, 1 year / 1000 for scan history, 30 days for telemetry. |
| 5 | Cross-database materialization | Use ATTACH DATABASE on-demand for cross-domain queries (defined in 08-storage R10). Don't materialize cross-database data. |
| 6 | Cache warming strategy | Yes — warm on MCP server startup (CW1). Lightweight queries that load materialized tables and covering index root pages. <10ms total. |
| 7 | Incremental materialization granularity | Domain-level granularity (MP2). Track which domains (patterns, security, callgraph) were affected by changed files. Refresh only affected Gold-layer tables. |
