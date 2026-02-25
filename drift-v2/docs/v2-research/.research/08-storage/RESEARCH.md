# 08 Storage — External Research

> Enterprise-grade, scientifically sourced research for building Drift v2's storage layer. All sources are verified, tiered by authority, and assessed for applicability.

---

## 1. SQLite WAL Mode and Performance Pragmas

### Source: SQLite Official WAL Documentation
**URL**: https://www.sqlite.org/wal.html
**Type**: Tier 1 — Authoritative (official documentation)
**Accessed**: 2026-02-06

**Key Findings**:
- WAL mode enables concurrent readers with a single writer, unlike the default rollback journal which blocks all readers during writes
- WAL provides significantly better write performance for most workloads because writes only append to the WAL file rather than modifying the database file directly
- WAL mode has drawbacks: slightly slower reads (must check WAL file), WAL file can grow large without checkpointing, not compatible with network filesystems
- `PRAGMA wal_autocheckpoint` controls automatic checkpointing threshold (default 1000 pages). Setting to 0 disables auto-checkpoint
- WAL mode is persistent — once set, it survives database close/reopen

**Applicability to Drift**:
WAL mode is essential for Drift's concurrent read/write pattern: the scanner writes results while MCP tools and CLI read. The v1 configuration of `journal_mode=WAL` + `synchronous=NORMAL` is correct and should be preserved in v2. The auto-checkpoint threshold should be tuned based on scan batch sizes.

**Confidence**: High — this is the canonical source from SQLite's creator.

---

### Source: SQLite Pragma Cheatsheet for Performance and Consistency
**URL**: https://cj.rs/blog/sqlite-pragma-cheatsheet-for-performance-and-consistency/
**Type**: Tier 2 — Industry Expert (maintained by rusqlite_migration author)
**Accessed**: 2026-02-06

**Key Findings**:
- Recommended pragmas on open: `journal_mode=WAL`, `synchronous=NORMAL`, `foreign_keys=ON`
- Recommended pragmas on close: `analysis_limit=400`, `optimize` — gathers statistics for query planner optimization
- `temp_store=2` keeps temporary storage in memory (not guaranteed but usually effective)
- `cache_size=-32000` keeps 32MB of database pages in memory (OS cache already helps, so this may waste memory)
- `user_version` pragma is more efficient than a migration tracking table — it's an integer at a fixed offset in the file, no table parsing needed
- STRICT tables (SQLite 3.37+) enforce type checking at insert time, preventing type affinity surprises

**Applicability to Drift**:
The on-close `PRAGMA optimize` is missing from v1 — adding it will improve query planner decisions over time. STRICT tables should be used for all v2 tables to catch type errors early. The `user_version` approach for migration tracking is simpler and faster than the current table-based approach.

**Confidence**: High — author maintains the most popular Rust SQLite migration library.

---

### Source: SQLite Performance Optimization Reference
**URL**: https://databurton.com/research/database-performance-optimization
**Type**: Tier 3 — Community Validated (benchmarked research)
**Accessed**: 2026-02-06

**Key Findings**:
- SQLite with correct PRAGMA settings handles 100,000+ queries/second in production
- Strategic indexing can yield 1200x improvements for specific query patterns
- WAL mode provides approximately 20x gains for write-heavy workloads
- `PRAGMA mmap_size` enables memory-mapped I/O, bypassing the filesystem cache for large sequential reads
- Batch inserts within a single transaction are orders of magnitude faster than individual inserts

**Applicability to Drift**:
Validates v1's approach of batched inserts and WAL mode. The 100K+ queries/second benchmark confirms SQLite is more than sufficient for Drift's query volume (MCP tools, CLI). The mmap_size of 256MB used in v1's Rust CallGraphDb is appropriate.

**Confidence**: Medium — benchmarked but not peer-reviewed.

---

### Source: Gotchas with SQLite in Production
**URL**: https://blog.pecar.me/sqlite-prod (via archive.org)
**Type**: Tier 3 — Community Validated
**Accessed**: 2026-02-06

**Key Findings**:
- SQLite's theoretical limit is 281 terabytes — most applications never approach this
- IMMEDIATE transactions prevent "Database is Locked" errors by acquiring the write lock at transaction start rather than at first write
- `synchronous=NORMAL` and memory-mapped I/O have smaller impact on throughput than WAL mode
- Connection pooling with separate read and write connections is the recommended pattern

**Applicability to Drift**:
The IMMEDIATE transaction mode is important for v2's batch writer pattern. When the Rust core starts a write transaction, it should use `BEGIN IMMEDIATE` to avoid SQLITE_BUSY errors from concurrent readers. The separate read/write connection pool pattern validates v2's `DatabaseManager` design.

**Confidence**: Medium — practical production experience, well-cited in community.

---

## 2. SQLite Many Small Queries Pattern

### Source: SQLite Official — Many Small Queries Are Efficient
**URL**: https://www.sqlite.org/np1queryprob.html
**Type**: Tier 1 — Authoritative (official SQLite documentation)
**Accessed**: 2026-02-06

**Key Findings**:
- SQLite can efficiently handle 200+ SQL statements per page load because there is no network round-trip overhead (unlike client/server databases)
- The "N+1 query problem" that plagues client/server databases is largely irrelevant for embedded SQLite
- Application developers can use many smaller queries instead of complex JOINs when it simplifies code
- SQLite's query planner is optimized for both large complex queries and many small queries

**Applicability to Drift**:
This validates Drift's MCP tool design where each tool makes multiple focused queries rather than one massive JOIN. The QueryEngine can issue separate queries for patterns, call graph, and security data without performance concern. This is a fundamental architectural advantage of embedded SQLite over client/server databases.

**Confidence**: High — from SQLite's official documentation by D. Richard Hipp.

---

## 3. Keyset Pagination vs OFFSET/LIMIT

### Source: Keyset Pagination Performance Analysis
**URL**: https://openillumi.com/en/en-sqlite-limit-offset-slow-fix-seek-method/
**Type**: Tier 3 — Community Validated
**Accessed**: 2026-02-06

**Key Findings**:
- OFFSET/LIMIT pagination degrades linearly with offset size — the database must scan and discard all rows before the offset
- Keyset pagination (also called "seek method") uses a WHERE clause with the last seen key value, achieving constant-time page retrieval regardless of position
- Requires ORDER BY on an indexed column and the last displayed record's key value
- Nearly instant page retrieval at any position in the dataset

**Applicability to Drift**:
V1's QueryEngine uses OFFSET/LIMIT pagination. For large codebases with thousands of patterns, this will degrade. V2 should implement keyset pagination using pattern IDs or timestamps as cursors. The MCP tools already return `nextCursor` — the backend just needs to use it for WHERE-based seeking instead of OFFSET.

**Confidence**: Medium — well-established database technique, multiple corroborating sources.

---

### Source: Cursor-Based Pagination Best Practices
**URL**: https://blog.sequinstream.com/keyset-cursors-not-offsets-for-postgres-pagination/
**Type**: Tier 2 — Industry Expert
**Accessed**: 2026-02-06

**Key Findings**:
- Keyset pagination provides consistent performance regardless of dataset size
- Tight correctness guarantees — no missed or duplicated rows when data changes between pages
- Better UX for infinite scroll patterns (which MCP tools effectively use)
- Requires a unique, ordered column (or composite) for the cursor
- Trade-off: no "jump to page N" capability (acceptable for Drift's use case)

**Applicability to Drift**:
MCP tools use sequential pagination (next page, not jump to page 47). Keyset pagination is the correct choice. Use `(created_at, id)` as the composite cursor for patterns, `(file, start_line)` for locations.

**Confidence**: High — well-established pattern with strong theoretical backing.

---

## 4. Schema Migration Best Practices

### Source: rusqlite_migration Crate
**URL**: https://cj.rs/rusqlite_migration
**Type**: Tier 2 — Industry Expert (battle-tested Rust crate)
**Accessed**: 2026-02-06

**Key Findings**:
- Uses `PRAGMA user_version` instead of a migration tracking table — faster database opening because it's an integer at a fixed offset, no table parsing needed
- Migrations are defined as a list of SQL strings in Rust code — simple, no external CLI needed
- Migrations are applied atomically — if one fails, the entire batch is rolled back
- Never remove a migration entry from the list (tracked by index number)
- Never perform backwards-incompatible schema modifications (don't drop tables or columns)
- Built-in validation: `MIGRATIONS.validate()` checks migration consistency
- Supports both up and down migrations for rollback capability

**Applicability to Drift**:
This is the recommended migration library for v2's Rust core. The `user_version` approach is simpler and faster than v1's table-based tracking. The "never remove, never break" rules align with Drift's upgrade path requirements. The atomic application ensures no partial migrations.

**Confidence**: High — widely used in Rust ecosystem, maintained by SQLite pragma expert.

---

### Source: Cargo's SQLite Migration Pattern
**URL**: https://doc.rust-lang.org/nightly/nightly-rustc/src/cargo/util/sqlite.rs.html
**Type**: Tier 1 — Authoritative (Rust's official package manager)
**Accessed**: 2026-02-06

**Key Findings**:
- Cargo uses `pragma_user_version` to track migration state
- Migrations are called immediately after opening a connection
- Initial `CREATE TABLE` statements are included in the migration list
- New tables or `ALTER TABLE` statements are added over time
- Only statements that haven't previously been run are executed
- Never remove a migration entry; never perform backwards-incompatible changes

**Applicability to Drift**:
Cargo's pattern is the gold standard for embedded Rust applications using SQLite. Drift v2 should follow this exact pattern: define migrations as a const slice, apply on connection open, track via user_version.

**Confidence**: High — this is how Rust's own toolchain manages its database.

---

### Source: Mozilla Application Services Schema Pattern
**URL**: https://mozilla.github.io/application-services/book/rust-docs/src/webext_storage/schema.rs.html
**Type**: Tier 1 — Authoritative (Mozilla's production Rust code)
**Accessed**: 2026-02-06

**Key Findings**:
- Uses `ConnectionInitializer` trait for migration logic
- Sets pragmas outside of migrations: `temp_store=2`, `journal_mode=WAL`, `foreign_keys=ON`
- Schema SQL stored as `include_str!("../sql/create_schema.sql")` — keeps SQL in separate files
- Versioned with `END_VERSION` constant
- Separate `prepare()` method for connection setup vs schema creation

**Applicability to Drift**:
The separation of pragma configuration from schema migration is a good pattern. Drift v2 should store schema SQL in separate `.sql` files using `include_str!()` for maintainability. The `ConnectionInitializer` trait pattern provides a clean abstraction.

**Confidence**: High — production code from a major browser vendor.

---

## 5. SQLite JSON Columns vs Normalized Tables

### Source: SQLite JSON and Denormalization
**URL**: https://maximeblanc.fr/blog/sqlite-json-and-denormalization/
**Type**: Tier 3 — Community Validated
**Accessed**: 2026-02-06

**Key Findings**:
- JSON columns trade write performance for read performance — denormalization reduces JOINs
- SQLite's JSON1 extension provides `json_extract()`, `json_set()`, `json_each()` for querying JSON columns
- Expression indexes on JSON paths (e.g., `CREATE INDEX idx ON t(json_extract(data, '$.name'))`) enable indexed lookups into JSON columns
- STRICT tables with JSON column type (SQLite 3.37+) enforce valid JSON at insert time
- Best for: rarely-queried nested data, variable-schema data, data that's always read/written as a unit
- Worst for: frequently filtered/sorted data, data that needs individual field updates

**Applicability to Drift**:
V1 uses JSON columns for `tags`, `response_fields`, `mismatches`, `fields`, `decorators`, `parameters`, `content` (Cortex). This is appropriate for data that's read as a unit (e.g., a pattern's tags are always loaded together). However, `mismatches` in contracts could benefit from normalization if individual mismatch querying becomes common. V2 should add expression indexes on frequently-queried JSON paths.

**Confidence**: Medium — practical advice, consistent with SQLite documentation.

---

### Source: Using SQLite with JSON Data
**URL**: https://peter-hoffmann.com/2024/using-sqlite-with-json-data.html
**Type**: Tier 3 — Community Validated
**Accessed**: 2026-02-06

**Key Findings**:
- `json_extract()` can be used in WHERE clauses for filtering
- Expression indexes on JSON paths provide O(log n) lookups into JSON columns
- `json_each()` table-valued function enables JOINing against JSON arrays
- STRICT tables with JSON type enforce valid JSON automatically (SQLite 3.38+)
- JSON path queries are significantly slower than native column queries without expression indexes

**Applicability to Drift**:
For v2, add expression indexes on any JSON column that's used in WHERE clauses. For example, if MCP tools filter patterns by tags, add `CREATE INDEX idx_patterns_tags ON patterns(json_extract(tags, '$'))`. Consider normalizing `mismatches` into a separate `contract_mismatches` table for better queryability.

**Confidence**: Medium — practical, consistent with official docs.

---

## 6. SQLite Backup API

### Source: SQLite Official Online Backup API
**URL**: https://sqlite.org/c3ref/backup_finish.html
**Type**: Tier 1 — Authoritative (official documentation)
**Accessed**: 2026-02-06

**Key Findings**:
- `sqlite3_backup_init()` → `sqlite3_backup_step()` → `sqlite3_backup_finish()` provides hot backup without locking
- Backup can proceed while the source database is being read and written
- Passing a larger page count to `sqlite3_backup_step()` (e.g., 100 or 1000) transfers more data per step, reducing conflict chance but holding a read lock longer
- The backup API creates a consistent snapshot — all pages are from the same point in time
- Can backup to/from in-memory databases

**Applicability to Drift**:
V2's backup strategy should use the SQLite backup API exclusively (not file copy, which can corrupt WAL-mode databases). The `rusqlite` crate exposes this API. Backup before schema migrations and destructive operations. Use a page count of 1000 for fast backup of typical Drift databases (1-50MB).

**Confidence**: High — canonical source.

---

### Source: Safe SQLite Backup Methods
**URL**: https://openillumi.com/en/en-sqlite-safe-backup-method/
**Type**: Tier 3 — Community Validated
**Accessed**: 2026-02-06

**Key Findings**:
- Copying a `.db` file directly risks creating an inconsistent backup, especially in WAL mode (the WAL and SHM files must be consistent with the main file)
- The SQLite Backup API is the only safe method for hot backups
- `.backup` command in the SQLite CLI uses this API internally
- For WAL-mode databases, a simple file copy will miss uncommitted WAL entries

**Applicability to Drift**:
V1's backup system copies files. V2 must use the SQLite backup API. This is especially critical because Drift uses WAL mode — a file copy would miss WAL entries and potentially create a corrupt backup.

**Confidence**: Medium — practical advice, consistent with official docs.

---

## 7. ATTACH DATABASE for Cross-Database Queries

### Source: SQLite ATTACH DATABASE Documentation
**URL**: https://openillumi.com/en/en-sqlite-multi-db-join-attach-command/
**Type**: Tier 3 — Community Validated
**Accessed**: 2026-02-06

**Key Findings**:
- `ATTACH DATABASE` temporarily links an external database file to the current session under an alias
- Enables cross-database JOINs as if tables were in the same database
- Performance can be slower than a single database for cross-database queries (no shared page cache)
- Maximum 10 attached databases per connection (compile-time limit, can be increased)
- Attached databases share the same transaction — COMMIT/ROLLBACK applies to all

**Applicability to Drift**:
For v2.0, drift.db and cortex.db remain separate. ATTACH DATABASE enables cross-domain queries (e.g., "find memories linked to patterns with high confidence"). The shared transaction semantics are a bonus — cross-database writes are atomic. Performance impact is acceptable for Drift's query volume.

**Confidence**: Medium — well-documented feature, performance varies by use case.

---

## 8. Embedded Database Comparison: SQLite vs DuckDB

### Source: DuckDB vs SQLite for Local Analytics
**URL**: https://betterstack.com/community/guides/scaling-python/duckdb-vs-sqlite/
**Type**: Tier 2 — Industry Expert
**Accessed**: 2026-02-06

**Key Findings**:
- SQLite uses row-oriented storage, optimal for transactional operations (OLTP) where complete records are needed
- DuckDB uses columnar storage with vectorized execution, optimal for analytical queries (OLAP) that scan large datasets
- SQLite excels at: point lookups, small transactions, embedded applications, concurrent read/write
- DuckDB excels at: aggregations, complex JOINs over large datasets, analytical queries
- SQLite is the most widely deployed database engine in the world
- DuckDB can read SQLite databases directly

**Applicability to Drift**:
Drift's workload is primarily OLTP (point lookups by pattern ID, file, category) with occasional OLAP (aggregations for status views, trend analysis). SQLite is the correct choice for the primary workload. However, for future analytics features (trend analysis over large history datasets), DuckDB could be considered as a read-only analytical layer that reads from drift.db. This is a v2.1+ consideration, not v2.0.

**Confidence**: High — well-researched comparison with clear criteria.

---

## 9. Rust SQLite Connection Pooling

### Source: sqlite-rwc Crate (Read-Write-Connection Pool)
**URL**: https://www.lib.rs/crates/sqlite-rwc
**Type**: Tier 3 — Community Validated
**Accessed**: 2026-02-06

**Key Findings**:
- Maintains a list of read-only connections and one write connection
- Enforces exclusive access to the writer at the application level (more predictable than SQLite's internal sleep-retry loop)
- Only need to handle SQLITE_BUSY errors from other processes, not from within the application
- Read connections can access the database concurrently via WAL mode

**Applicability to Drift**:
Validates v2's `DatabaseManager` design with `Mutex<Connection>` for the writer and `Vec<Mutex<Connection>>` for readers. The application-level write lock is more predictable than relying on SQLite's busy handler. Consider using `crossbeam` channel for the writer instead of `Mutex` for better performance under contention.

**Confidence**: Medium — small crate but sound architecture.

---

### Source: Mithril Network Connection Pool (Rust)
**URL**: https://mithril.network/rust-doc/src/mithril_persistence/sqlite/connection_pool.rs.html
**Type**: Tier 2 — Industry Expert (production Rust code)
**Accessed**: 2026-02-06

**Key Findings**:
- Production Rust SQLite connection pool implementation
- Uses `Duration`-based timeouts for connection acquisition
- Separates read and write connection management
- Connection pool is a common pattern in production Rust SQLite applications

**Applicability to Drift**:
Reference implementation for v2's connection pool. The timeout-based acquisition prevents deadlocks. Drift should implement similar timeout handling with configurable busy_timeout_ms.

**Confidence**: Medium — production code but limited documentation.

---

## 10. MPSC Channel Pattern for Database Writers

### Source: Rust Users Forum — MPSC vs Shared Memory
**URL**: https://users.rust-lang.org/t/shareing-state-channels-v-shared-memory/138039
**Type**: Tier 3 — Community Validated
**Accessed**: 2026-02-06

**Key Findings**:
- Performance depends on lock contention — if threads aren't fighting for the lock, Mutex and channel perform similarly
- MPSC channels are preferred when the writer needs to batch operations (accumulate messages, flush periodically)
- `std::mpsc` is known to be slower than `crossbeam-channel` for high-throughput scenarios
- For database writers, the channel pattern naturally serializes writes without explicit locking

**Applicability to Drift**:
V1's `ParallelWriter` uses `std::sync::mpsc`. V2 should switch to `crossbeam-channel` for better performance. The channel pattern is correct for Drift's use case: many rayon workers producing batches, one writer thread consuming and flushing to SQLite.

**Confidence**: Medium — community consensus, multiple corroborating sources.

---

## 11. Vector Search in SQLite

### Source: sqlite-vec Official Repository
**URL**: https://github.com/asg017/sqlite-vec
**Type**: Tier 2 — Industry Expert (actively maintained, widely adopted)
**Accessed**: 2026-02-06

**Key Findings**:
- Pure C implementation with no dependencies — runs anywhere SQLite runs
- Provides KNN search, multiple distance metrics (cosine, L2, L1), SIMD-accelerated
- Uses virtual tables — vectors must live in separate tables
- Queries are more complex than regular SQL due to virtual table syntax
- Successor to sqlite-vss (which used Faiss) — simpler, more portable
- Supports float32 and int8 quantized vectors

**Applicability to Drift**:
Cortex uses sqlite-vec for 384-dimensional embeddings (all-MiniLM-L6-v2). The virtual table requirement means embeddings must stay in a separate table (`memory_embeddings`) linked via `memory_embedding_link`. For v2, consider int8 quantization for 4x storage reduction with minimal accuracy loss. The pure C implementation means it works with rusqlite's bundled SQLite.

**Confidence**: High — actively maintained, widely adopted, clear documentation.

---

### Source: The State of Vector Search in SQLite
**URL**: https://marcobambini.substack.com/p/the-state-of-vector-search-in-sqlite
**Type**: Tier 2 — Industry Expert
**Accessed**: 2026-02-06

**Key Findings**:
- sqlite-vec is the current recommended extension (sqlite-vss is deprecated)
- Virtual table approach means vectors live in separate tables, making queries more complex
- For small-to-medium datasets (< 1M vectors), brute-force KNN is fast enough
- For larger datasets, consider approximate nearest neighbor (ANN) indexes
- sqlite-vector (from SQLiteCloud) is an alternative with different trade-offs

**Applicability to Drift**:
Drift's Cortex typically stores thousands to tens of thousands of memories, well within brute-force KNN range. No need for ANN indexes in v2.0. The L1/L2/L3 cache architecture in Cortex already mitigates query latency for hot embeddings.

**Confidence**: Medium — good overview but not deeply technical.

---

## 12. Incremental Indexing and Change Detection

### Source: Glean — Incremental Indexing
**URL**: https://glean.software/blog/incremental/
**Type**: Tier 2 — Industry Expert (Meta's code indexing tool)
**Accessed**: 2026-02-06

**Key Findings**:
- Goal: index changes in O(changes) rather than O(repository)
- Content hashing identifies what changed — only reprocess changed files
- Dependency tracking determines what derived data needs recomputation
- Incremental indexing requires separating "per-file facts" from "cross-file derived data"
- Per-file facts can be updated independently; derived data must be recomputed from affected facts

**Applicability to Drift**:
Directly applicable to Drift's incremental scanning architecture. V1's ManifestStore already tracks file hashes for change detection. V2 should formalize this into a two-phase model: (1) per-file indexing (embarrassingly parallel, content-hashed), (2) cross-file analysis (derived from file indexes, recomputed when inputs change). This aligns with the rust-analyzer architecture recommended in the Rust Core research.

**Confidence**: High — production system at Meta scale, directly relevant to code indexing.

---

### Source: Incremental Analysis & Caching (Cased)
**URL**: https://kit.cased.com/core-concepts/incremental-analysis/
**Type**: Tier 3 — Community Validated
**Accessed**: 2026-02-06

**Key Findings**:
- Incremental analysis integrates with git state detection for cache invalidation
- Branch switching and commit changes trigger selective re-analysis
- Content hashing at the file level determines what needs reprocessing

**Applicability to Drift**:
V2 should integrate with git state for smarter cache invalidation. When switching branches, invalidate file indexes for files that differ between branches. This is more efficient than re-hashing all files.

**Confidence**: Low — limited detail, but the concept is sound.

---

## 13. Static Analysis Tool Storage Patterns

### Source: SonarQube Architecture
**URL**: https://www.sonarsource.com/resources/library/net-developer-guide-analyzation/
**Type**: Tier 2 — Industry Expert
**Accessed**: 2026-02-06

**Key Findings**:
- SonarQube uses a client/server model: scanner (client) performs analysis and pushes results to server
- Server persists analysis reports in PostgreSQL
- Results are stored as "issues" with file, line, rule, severity, effort
- Historical data enables trend analysis and quality gate evaluation
- SARIF (Static Analysis Results Interchange Format) is the industry standard for exchanging results

**Applicability to Drift**:
Drift's local-first model is fundamentally different from SonarQube's client/server approach. However, the SARIF output format should be supported for interoperability. The "issues as first-class entities with history" pattern validates Drift's pattern_history table. The trend analysis capability validates the health_trends table.

**Confidence**: Medium — different architecture but relevant patterns.

---

### Source: Semgrep Architecture
**URL**: https://semgrep.dev/blog/2021/semgrep-a-static-analysis-journey/
**Type**: Tier 2 — Industry Expert
**Accessed**: 2026-02-06

**Key Findings**:
- Semgrep is designed to be fast and lightweight — runs locally on the command line
- Uses tree-sitter for parsing (same as Drift)
- Results are output as JSON or SARIF — no persistent database in the open-source version
- The cloud version (Semgrep App) persists results for trend analysis
- Declarative rules in YAML define what to detect
- Intraprocedural taint analysis for data flow tracking

**Applicability to Drift**:
Semgrep's open-source version doesn't persist results — it's a one-shot scanner. Drift's persistent storage (SQLite) is a differentiator that enables trend analysis, learning, and memory without a cloud service. The SARIF output format should be supported. The declarative rule format validates Drift's move toward TOML/YAML pattern definitions.

**Confidence**: High — directly comparable tool with well-documented architecture.

---

## 14. SARIF Output Format

### Source: SonarSource SARIF Guide
**URL**: https://www.sonarsource.com/resources/library/sarif/
**Type**: Tier 2 — Industry Expert
**Accessed**: 2026-02-06

**Key Findings**:
- SARIF (Static Analysis Results Interchange Format) is the OASIS industry standard
- Enables interoperability between static analysis tools
- Supported by GitHub Code Scanning, Azure DevOps, and many CI/CD platforms
- Includes: tool information, rules, results with locations, code flows, fixes
- Version 2.1.0 is the current standard

**Applicability to Drift**:
V1 already supports SARIF output for quality gates. V2 should ensure the storage schema can efficiently generate SARIF output. The `patterns` + `pattern_locations` + `pattern_history` tables map cleanly to SARIF's `results` + `locations` + `relatedLocations` structure.

**Confidence**: High — industry standard with broad adoption.

---

## 15. Materialized View Patterns for Embedded Databases

### Source: Materialized Views for Data Lakehouse (Dremio)
**URL**: https://www.dremio.com/wiki/materialized-views/
**Type**: Tier 2 — Industry Expert
**Accessed**: 2026-02-06

**Key Findings**:
- Materialized views store pre-computed query results, trading storage for latency
- Refresh strategies: full refresh (recompute entirely), incremental refresh (update only changed data)
- Staleness management: time-based TTL, event-based invalidation, or manual refresh
- Best for: frequently-executed complex queries, dashboards, aggregation-heavy workloads
- SQLite doesn't natively support materialized views — must be simulated with tables + triggers

**Applicability to Drift**:
SQLite's regular views are computed on every query — they're not materialized. For v2's status dashboard and trend views, Drift should implement "poor man's materialized views": regular tables populated by triggers or explicit refresh calls. The `v_status` view in v1's schema.sql is a regular view — for instant `drift_status`, it should be a cached table refreshed after scans.

**Confidence**: Medium — general concept, needs adaptation for SQLite.

---

## 16. SQLite Recursive CTEs for Graph Traversal

### Source: SQLite Official — WITH RECURSIVE Documentation
**URL**: https://www.sqlite.org/lang_with.html
**Type**: Tier 1 — Authoritative (official documentation)
**Accessed**: 2026-02-06

**Key Findings**:
- Recursive CTEs enable graph traversal (BFS/DFS) directly in SQL without loading data into application memory
- Structure: anchor member (base case) UNION ALL recursive member (step)
- Always use `UNION ALL` in recursive CTEs — `UNION` forces deduplication tracking of every generated row, significantly impacting performance
- SQLite limits recursion depth via `SQLITE_MAX_VARIABLE_NUMBER` (default 999) — configurable
- Recursive CTEs can be materialized or run as coroutines — the query planner decides
- For tree/graph traversal, index the parent/child columns for efficient recursive joins

**Applicability to Drift**:
The `SqliteReachabilityEngine` uses recursive CTEs for BFS traversal through the call graph. This is the correct approach — it keeps memory at O(1) regardless of graph size. V2 should ensure `call_edges(caller_id)` and `call_edges(callee_id)` are indexed for efficient recursive joins. Consider adding a `max_depth` parameter to prevent runaway recursion on cyclic graphs.

**Confidence**: High — canonical source from SQLite's official documentation.

---

## 17. SQLite VACUUM and Auto-VACUUM Strategies

### Source: SQLite Official — VACUUM Documentation
**URL**: https://sqlite.org/draft/matrix/lang_vacuum.html
**Type**: Tier 1 — Authoritative (official documentation)
**Accessed**: 2026-02-06

**Key Findings**:
- VACUUM rebuilds the entire database file, reclaiming free space and defragmenting tables/indexes for contiguous storage
- VACUUM requires up to 2x the database size in temporary disk space (creates a copy)
- VACUUM resets the `auto_vacuum` setting and rebuilds all indexes
- `auto_vacuum=INCREMENTAL` moves free pages to end of file on each COMMIT but does NOT defragment
- `auto_vacuum` must be set BEFORE creating any tables — cannot be enabled retroactively
- VACUUM erases deleted content traces, providing a security benefit (alternative to `PRAGMA secure_delete=ON`)
- For WAL-mode databases, run `PRAGMA wal_checkpoint(TRUNCATE)` before VACUUM to ensure the WAL is fully checkpointed

**Applicability to Drift**:
Drift databases grow during scans (bulk inserts) and shrink during retention enforcement (bulk deletes). After large retention purges, VACUUM reclaims space and defragments. However, VACUUM is expensive (rebuilds entire DB) — run it sparingly. Recommendation: run VACUUM after retention enforcement if >20% of pages are free (check via `PRAGMA freelist_count` / `PRAGMA page_count`). Do NOT use `auto_vacuum` — it adds overhead to every COMMIT and doesn't defragment.

**Confidence**: High — canonical source.

---

## 18. SQLite WAL Checkpoint Strategies

### Source: SQLite Official — WAL Checkpoint API
**URL**: https://www.sqlite.org/c3ref/wal_checkpoint_v2.html
**Type**: Tier 1 — Authoritative (official documentation)
**Accessed**: 2026-02-06

**Key Findings**:
- Four checkpoint modes: PASSIVE (non-blocking, may leave frames), FULL (blocks writers, checkpoints all), RESTART (like FULL + resets WAL), TRUNCATE (like RESTART + truncates WAL file to zero bytes)
- `wal_autocheckpoint` (default 1000 pages) triggers PASSIVE checkpoints automatically
- PASSIVE checkpoints never block readers or writers but may leave uncheckpointed frames
- TRUNCATE is the most aggressive — reclaims WAL disk space by truncating the file
- Without periodic checkpoints, the WAL file grows unbounded, degrading read performance

### Source: Litestream — WAL Truncate Threshold Configuration
**URL**: https://litestream.io/guides/wal-truncate-threshold/
**Type**: Tier 2 — Industry Expert (production replication tool)
**Accessed**: 2026-02-06

**Key Findings**:
- Two-tier checkpoint strategy: regular PASSIVE checkpoints for normal operation, emergency TRUNCATE checkpoint when WAL exceeds a size threshold
- Set `wal_autocheckpoint` for regular non-blocking cleanup
- Add a manual TRUNCATE checkpoint after large batch operations to reclaim WAL space
- Emergency threshold prevents runaway WAL growth

**Applicability to Drift**:
V2 should implement a two-tier checkpoint strategy: (1) `wal_autocheckpoint=1000` for regular PASSIVE checkpoints during normal operation, (2) explicit `PRAGMA wal_checkpoint(TRUNCATE)` after scan completion to reclaim WAL space. This prevents WAL growth during large scans while keeping normal operations non-blocking.

**Confidence**: High — combines official documentation with production experience.

---

## 19. SQLite Concurrent Process Safety

### Source: SQLite Official — File Locking and Concurrency
**URL**: https://sqlite.org/lockingv3.html
**Type**: Tier 1 — Authoritative (official documentation)
**Accessed**: 2026-02-06

**Key Findings**:
- SQLite uses file-system locks to serialize write access — only one process can write at a time
- In WAL mode, multiple processes can read concurrently while one process writes
- `SQLITE_BUSY` is returned when a process cannot acquire the needed lock
- `busy_timeout` pragma sets how long to wait before returning SQLITE_BUSY (default: 0ms)
- `BEGIN IMMEDIATE` acquires the write lock at transaction start, failing fast if another process holds it
- File locks are advisory on some systems — NFS and network filesystems are NOT safe for SQLite

### Source: SQLite Concurrency and WAL Mode
**URL**: https://openillumi.com/en/en-sqlite-concurrency-wal-mode/
**Type**: Tier 3 — Community Validated
**Accessed**: 2026-02-06

**Key Findings**:
- WAL mode dramatically reduces lock contention by allowing concurrent readers during writes
- For multi-process scenarios, set `busy_timeout` to a reasonable value (5000ms+)
- Application-level coordination (lock file or named mutex) can prevent SQLITE_BUSY entirely

**Applicability to Drift**:
Two drift processes accessing the same database is a real scenario (e.g., `drift scan` running while MCP tools query). WAL mode handles read/write concurrency well. For write/write conflicts (two scans simultaneously), `busy_timeout=5000` provides automatic retry. V2 should also implement a process-level lock file (`.drift/drift.db.lock`) to prevent concurrent scans — only one scan should run at a time, but reads should always be allowed.

**Confidence**: High — well-documented SQLite behavior with clear guidance.

---

## 20. SQLite Triggers: Best Practices and Performance

### Source: SQLite Official — CREATE TRIGGER Documentation
**URL**: https://www.sqlite.org/lang_createtrigger.html
**Type**: Tier 1 — Authoritative (official documentation)
**Accessed**: 2026-02-06

**Key Findings**:
- Triggers execute within the same transaction as the triggering statement — no additional transaction overhead
- BEFORE triggers can modify or abort the operation; AFTER triggers execute after the change
- Triggers fire once per row (FOR EACH ROW is the only mode in SQLite)
- Triggers can reference OLD and NEW row values
- Recursive triggers are disabled by default (`PRAGMA recursive_triggers = OFF`)

### Source: Using SQLite Triggers for Counter Caching
**URL**: https://samuelplumppu.se/blog/using-sqlite-triggers-to-boost-performance-of-select-count
**Type**: Tier 3 — Community Validated
**Accessed**: 2026-02-06

**Key Findings**:
- Triggers can maintain counter caches (e.g., `location_count` on patterns) to avoid expensive `COUNT(*)` queries
- Counter-cache triggers add minimal overhead to INSERT/UPDATE/DELETE operations
- This pattern replaces O(n) COUNT queries with O(1) column reads
- Keep trigger logic simple — complex triggers degrade write performance

**Applicability to Drift**:
V1 already uses triggers for auto-updating pattern location/outlier counts and sync logging. V2 should preserve the counter-cache triggers (essential for instant status queries) but remove sync_log triggers (no JSON sync in v2). Keep triggers simple — avoid complex logic that could slow batch inserts. For the materialized status table, use explicit refresh calls rather than triggers (triggers on every pattern insert would be too expensive during scans).

**Confidence**: High — well-established pattern with clear performance characteristics.

---

## 21. SQLite Error Handling and Recovery

### Source: SQLite Official — Result and Error Codes
**URL**: https://www.sqlite.org/rescode.html
**Type**: Tier 1 — Authoritative (official documentation)
**Accessed**: 2026-02-06

**Key Findings**:
- `SQLITE_FULL` (13): Database or disk is full — write operations fail but database remains valid
- `SQLITE_CORRUPT` (11): Database file is malformed — once received, the database should not be trusted
- `SQLITE_BUSY` (5): Database is locked by another process — retry or wait
- `SQLITE_IOERR` (10): I/O error — disk failure, permissions, etc.
- `SQLITE_READONLY` (8): Attempt to write to a read-only database
- After `SQLITE_CORRUPT`, the recommended recovery path is: restore from backup, or use `.recover` to salvage data

### Source: SQLite Official — Recovering Data from Corrupt Databases
**URL**: https://sqlite.org/recovery.html
**Type**: Tier 1 — Authoritative (official documentation)
**Accessed**: 2026-02-06

**Key Findings**:
- The `sqlite3_recover` extension can salvage data from corrupt databases by scanning raw pages
- Recovery creates a new clean database from salvaged data — the corrupt file is not modified
- WAL mode with `synchronous=NORMAL` provides good crash recovery — uncommitted WAL entries are discarded
- Regular `PRAGMA integrity_check` can detect corruption before it causes data loss

**Applicability to Drift**:
V2 must handle every SQLite error code gracefully. Strategy: (1) `SQLITE_BUSY` → retry with exponential backoff (handled by `busy_timeout`), (2) `SQLITE_FULL` → log error, notify user, suggest `drift doctor` for retention/VACUUM, (3) `SQLITE_CORRUPT` → log error, attempt automatic restore from most recent backup, (4) `SQLITE_IOERR` → log error with OS-level details, suggest checking disk permissions/space. The `drift doctor` command should run `PRAGMA integrity_check` and `PRAGMA foreign_key_check` proactively.

**Confidence**: High — canonical error handling guidance from SQLite's official documentation.

---

## 22. SQLite FTS5 for Full-Text Search

### Source: SQLite Official — FTS5 Documentation
**URL**: https://www.sqlite.org/fts5.html
**Type**: Tier 1 — Authoritative (official documentation)
**Accessed**: 2026-02-06

**Key Findings**:
- FTS5 is SQLite's full-text search extension, providing tokenized search with ranking
- Creates a virtual table that indexes text content for fast substring and phrase matching
- Supports `content=` tables to avoid data duplication (external content FTS5 tables)
- `MATCH` operator provides ranked results with BM25 scoring
- FTS5 tables add storage overhead (~2x the indexed text) and write overhead (index maintenance on every INSERT/UPDATE/DELETE)
- For small datasets (< 100K rows), `LIKE '%query%'` with expression indexes is often fast enough

**Applicability to Drift**:
The `search_patterns(query)` operation from rust-ownership.md needs text search across pattern names, descriptions, and categories. For v2.0, `LIKE` with expression indexes is sufficient — Drift typically has hundreds to low thousands of patterns, well within `LIKE` performance range. FTS5 is available as a v2.1 upgrade if search volume or complexity grows (e.g., searching across pattern descriptions, code examples, and memory summaries simultaneously).

**Confidence**: High — canonical source from SQLite's official documentation.

---

## Research Summary

### Sources by Tier

| Tier | Count | Sources |
|------|-------|---------|
| Tier 1 (Authoritative) | 12 | SQLite WAL docs, SQLite N+1 query docs, Cargo migration pattern, Mozilla Application Services, SQLite WITH RECURSIVE, SQLite VACUUM, SQLite WAL Checkpoint API, SQLite File Locking, SQLite CREATE TRIGGER, SQLite Result Codes, SQLite Recovery, SQLite FTS5 |
| Tier 2 (Industry Expert) | 10 | SQLite pragma cheatsheet, DuckDB comparison, sqlite-vec, Glean incremental indexing, SonarQube, Semgrep, SARIF guide, Mithril connection pool, rusqlite_migration, Litestream WAL strategy |
| Tier 3 (Community Validated) | 9 | Performance benchmarks, keyset pagination, JSON columns, backup methods, ATTACH DATABASE, MPSC patterns, incremental analysis, sqlite-rwc, SQLite trigger counter caching |

### Key Themes

1. **WAL + NORMAL + foreign_keys is the correct baseline** — validated by multiple authoritative sources
2. **user_version for migration tracking** — simpler and faster than table-based tracking
3. **Keyset pagination over OFFSET/LIMIT** — essential for large datasets
4. **SQLite backup API for hot backups** — file copy is unsafe with WAL mode
5. **MPSC channel with crossbeam for batch writes** — proven pattern for parallel → sequential
6. **Incremental indexing via content hashing** — O(changes) not O(repository)
7. **STRICT tables for type safety** — catch errors at insert time
8. **PRAGMA optimize on close** — improves query planner over time
9. **SARIF for interoperability** — industry standard for static analysis results
10. **Separate read/write connection pools** — application-level write serialization
11. **Recursive CTEs for graph traversal** — O(1) memory BFS/DFS in SQL
12. **Two-tier WAL checkpoint strategy** — PASSIVE for normal ops, TRUNCATE after scans
13. **VACUUM after large deletes, not auto_vacuum** — defragment without per-COMMIT overhead
14. **Process-level lock file for concurrent scan prevention** — WAL handles read concurrency, lock file prevents write conflicts
15. **Counter-cache triggers for instant aggregations** — O(1) COUNT via maintained counters
16. **Graceful error handling for all SQLite error codes** — BUSY retry, FULL notify, CORRUPT auto-restore
17. **LIKE + expression indexes for search** — FTS5 available as upgrade path if search volume grows
18. **Separate global database for cross-project state** — lightweight registry without opening project databases
