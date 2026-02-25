# 08 Storage — Research Recap

## Executive Summary

Storage is Drift's persistence backbone — the layer that turns ephemeral analysis results into durable, queryable data. In v1, storage evolved organically into 6 fragmented backends (JSON files, SQLite unified store, Data Lake with materialized views/shards/indexes, Rust SQLite for call graphs, Cortex SQLite with vector embeddings, and hybrid bridge stores). This fragmentation created ~12,000 lines of storage code, 50+ JSON files in `.drift/`, three separate sync paths, and no transactional guarantees across domains. V2 consolidates everything into 2 Rust-managed SQLite databases: `drift.db` (all analysis data) and `cortex.db` (AI memory + vector embeddings).

The most architecturally creative element of v1 was the **Drift Lake** — an enterprise-grade data storage layer that pre-computed materialized views, sharded large datasets by dimension (category, file, table, pattern), maintained O(1) lookup indexes, and routed queries to the optimal data source automatically. While the Lake's JSON implementation is being replaced, its architectural concepts (pre-computation, selective loading, query routing, incremental materialization) are preserved in v2 as native SQLite views, indexes, and the query planner.

---

## Current Implementation

### Architecture: The 6 Backends

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        V1 STORAGE LANDSCAPE                             │
│                                                                         │
│  Backend 1: JSON File Storage (DEPRECATED)                              │
│  ├── packages/core/src/store/                                           │
│  ├── pattern-store.ts (1168 lines) — .drift/patterns/{status}/{cat}.json│
│  ├── contract-store.ts (~800 lines) — .drift/contracts/{status}/        │
│  ├── history-store.ts (~300 lines) — .drift/history/                    │
│  ├── cache-manager.ts (~400 lines) — .drift/cache/                      │
│  ├── project-registry.ts (~500 lines) — ~/.drift/registry.json          │
│  ├── project-config.ts (~200 lines) — .drift/config.json                │
│  ├── lock-file-manager.ts (~300 lines) — drift.lock                     │
│  └── schema-validator.ts (~200 lines) — JSON schema validation          │
│                                                                         │
│  Backend 2: SQLite Unified Store (KEEP — BECOMES FOUNDATION)            │
│  ├── packages/core/src/storage/                                         │
│  ├── schema.sql (899 lines) — 40+ tables, 50+ indexes, triggers, views │
│  ├── unified-store.ts (~400 lines) — lifecycle, transactions            │
│  ├── store-factory.ts (~250 lines) — auto-detect backend                │
│  ├── migration.ts (~500 lines) — JSON → SQLite migration                │
│  ├── sync-service.ts (~1142 lines) — bidirectional JSON↔SQLite sync     │
│  ├── hybrid-pattern-store.ts (~450 lines) — bridge layer                │
│  ├── hybrid-contract-store.ts (~350 lines) — bridge layer               │
│  └── repositories/ (9 repositories across all domains)                  │
│                                                                         │
│  Backend 3: Data Lake (DEPRECATED — REPLACE WITH DB VIEWS)              │
│  ├── packages/core/src/lake/                                            │
│  ├── manifest-store.ts (~420 lines) — .drift/manifest.json              │
│  ├── view-store.ts (~430 lines) — .drift/views/*.json                   │
│  ├── view-materializer.ts (~590 lines) — post-scan rebuild              │
│  ├── index-store.ts (~440 lines) — .drift/indexes/*.json                │
│  ├── query-engine.ts (~400 lines) — unified query routing               │
│  ├── pattern-shard-store.ts (~430 lines) — by category                  │
│  ├── callgraph-shard-store.ts (~650 lines) — by file                    │
│  ├── security-shard-store.ts (~660 lines) — by table                    │
│  └── examples-store.ts (~550 lines) — by pattern                        │
│                                                                         │
│  Backend 4: Rust SQLite (KEEP — EXPAND)                                 │
│  ├── crates/drift-core/src/call_graph/storage.rs — CallGraphDb          │
│  └── crates/drift-core/src/reachability/sqlite_engine.rs — read-only    │
│                                                                         │
│  Backend 5: Cortex Memory Storage (KEEP — CONSOLIDATE)                  │
│  ├── packages/cortex/src/storage/                                       │
│  ├── sqlite/schema.ts — Schema v5, 10+ tables                          │
│  ├── sqlite/storage.ts — Full IMemoryStorage implementation             │
│  ├── sqlite/client.ts — better-sqlite3 + sqlite-vec                     │
│  └── sqlite/migrations.ts — 5 schema versions                          │
│                                                                         │
│  Backend 6: Hybrid Stores (DEPRECATED — REMOVE)                         │
│  ├── hybrid-pattern-store.ts — reads SQLite, writes both                │
│  ├── hybrid-contract-store.ts — same bridge for contracts               │
│  └── sync-service.ts — 11 data domain sync                             │
└─────────────────────────────────────────────────────────────────────────┘
```

### Backend 1: JSON File Storage

The original persistence layer. Stores patterns as JSON files organized by `status/category.json` in `.drift/patterns/`. Features auto-save with 30s debouncing, timestamped `.backups/` directories, SHA-256 checksums for integrity, and pattern state transitions (discovered → approved/ignored).

**Fatal flaws**: O(n) reads (must parse entire category file to find one pattern), no concurrent access safety (advisory file locks only), no transactional guarantees (partial writes corrupt data), generates 50+ JSON files cluttering `.drift/`, no query optimization (all filtering in-memory after full load), version control noise (every scan changes dozens of files).

### Backend 2: SQLite Unified Store

The v1 SQLite foundation. 899-line schema with 40+ tables across 11 domains:

| Domain | Tables | Key Data |
|--------|--------|----------|
| Project metadata | 3 | project, config, feature_flags |
| Patterns | 4 | patterns, pattern_locations, pattern_variants, pattern_examples |
| Contracts | 2 | contracts, contract_frontends |
| Constraints | 1 | constraints |
| Boundaries | 3 | data_models, sensitive_fields, data_access_points |
| Environment | 2 | env_variables, env_access_points |
| Call graph | 3 | functions, function_calls, function_data_access |
| Audit & history | 4 | audit_snapshots, pattern_history, health_trends, scan_history |
| DNA | 3 | dna_profile, dna_genes, dna_mutations |
| Test topology | 2 | test_files, test_coverage |
| Other | 13 | constants, decisions, coupling, errors, wrappers, quality gates, learning, sync_log |

**Performance configuration**:
```sql
PRAGMA journal_mode = WAL;     -- Concurrent reads during writes
PRAGMA synchronous = NORMAL;   -- Balanced durability/speed
PRAGMA foreign_keys = ON;      -- Referential integrity
```

50+ indexes for common query patterns. Triggers for auto-updating pattern location/outlier counts and sync logging. 5 SQL views: `v_status`, `v_pattern_index`, `v_category_counts`, `v_file_patterns`, `v_security_summary`.

9 repository classes provide typed access: PatternRepository, ContractRepository, ConstraintRepository, BoundaryRepository, EnvironmentRepository, CallgraphRepository, AuditRepository, DNARepository, TestTopologyRepository.

### Backend 3: The Drift Lake (Data Lake)

The most architecturally creative subsystem. An enterprise-grade data storage layer sitting between raw analysis data and consumers (MCP tools, CLI), optimizing for instant responses to common queries.

**Core design principles**:
1. Pre-compute common queries as materialized views (instant `drift_status`)
2. Shard large datasets by category/file/table (load only what you need)
3. Index everything for O(1) lookups
4. Route queries to the optimal data source automatically
5. Rebuild only stale views after scans (incremental materialization)

**Architecture**:
```
┌─────────────────────────────────────────────────────────┐
│                    QueryEngine                           │
│  Routes to: Views → Indexes → Shards → Raw fallback     │
├──────────┬──────────┬──────────┬────────────────────────┤
│ ViewStore│ Index    │ Shard    │ Raw Data               │
│          │ Store    │ Stores   │ (injected loader)      │
│ status   │ file     │ pattern  │                        │
│ patterns │ category │ security │                        │
│ security │ table    │ callgrph │                        │
│ trends   │ entry    │ examples │                        │
├──────────┴──────────┴──────────┴────────────────────────┤
│              ViewMaterializer                            │
│  Rebuilds stale views + indexes after scans              │
├─────────────────────────────────────────────────────────┤
│              ManifestStore                               │
│  Quick-load index: all stats, file hashes, view status   │
└─────────────────────────────────────────────────────────┘
```


**Four view types** (pre-computed JSON files for instant responses):
- **StatusView**: Health score with trend, pattern counts by status/category, issue counts, security risk level, last scan info
- **PatternIndexView**: Lightweight pattern listing with id, name, category, status, confidence, location/outlier counts, SHA-256 locations hash for change detection
- **SecuritySummaryView**: Overall risk level, table/access-point/violation counts, top sensitive tables with risk scores
- **TrendsView**: Health trends over time with category-level breakdowns, regressions, improvements

**Four index types** (O(1) lookups without loading full data):
- **FileIndex**: `file → patternId[]` mapping
- **CategoryIndex**: `category → patternId[]` mapping
- **TableIndex**: `table → accessPointIds, accessorIds` mapping
- **EntryPointIndex**: `entryPoint → reachableFunctions, tables, sensitiveData` mapping

**Four shard stores** (partitioned data by dimension):
- **PatternShardStore**: Patterns by category at `.drift/lake/patterns/{category}.json`
- **CallGraphShardStore**: Call graph by file at `.drift/lake/callgraph/{fileHash}.json`
- **SecurityShardStore**: Security data by table at `.drift/lake/security/{table}.json`
- **ExamplesStore**: Code examples by pattern at `.drift/lake/examples/{patternId}.json`

**QueryEngine**: Unified query API that routes to optimal data source. Checks view staleness via ManifestStore before using views. Falls back through: Views → Indexes → Shards → Raw data. Tracks hit counts and response times per source. Supports pagination with cursors.

**ViewMaterializer**: Post-scan rebuild pipeline:
1. Determine stale views (markers or explicit list)
2. Rebuild StatusView from patterns + security + callgraph + contract stats
3. Rebuild PatternIndexView from patterns
4. Rebuild SecuritySummaryView from security shard index
5. Rebuild TrendsView from trend summary data
6. Rebuild all indexes (file, category, table, entry point)
7. Update ManifestStore stats
8. Sync callgraph and contract stats
9. Mark rebuilt views as fresh

**ManifestStore**: Quick-load index at `.drift/manifest.json`. Single file read gives all stats for `drift_status` without loading any other data. Tracks file hashes (SHA-256) for incremental scan support, view freshness status, and dirty state for save optimization.

**Disk layout**:
```
.drift/
  manifest.json                    # ManifestStore
  views/
    status.json                    # StatusView
    pattern-index.json             # PatternIndexView
    security-summary.json          # SecuritySummaryView
    trends.json                    # TrendsView
  indexes/
    by-file.json                   # FileIndex
    by-category.json               # CategoryIndex
    by-table.json                  # TableIndex
    by-entry-point.json            # EntryPointIndex
  lake/
    patterns/{category}.json       # PatternShardStore
    callgraph/index.json           # CallGraphShardStore index
    callgraph/entry-points.json    # Entry point data
    callgraph/{fileHash}.json      # Per-file call graph shards
    security/index.json            # SecurityShardStore index
    security/sensitive-fields.json # Sensitive field registry
    security/{tableName}.json      # Per-table security shards
    examples/index.json            # ExamplesStore index
    examples/{patternId}.json      # Per-pattern code examples
```

### Backend 4: Rust SQLite Storage

High-performance call graph persistence in Rust. Two components:

**CallGraphDb** (`crates/drift-core/src/call_graph/storage.rs`):
- Schema: `functions`, `call_edges`, `data_access`, `metadata` tables with comprehensive indexes
- WAL mode with 64MB cache (`PRAGMA cache_size = -64000`), 256MB mmap (`PRAGMA mmap_size = 268435456`)
- Batched inserts (1000 rows per transaction)
- `ParallelWriter`: Dedicated writer thread receives `FunctionBatch` messages from rayon workers via MPSC channel. Batches writes into transactions for performance.
- Read-only mode for query-only access
- Key operations: `open`, `open_readonly`, `insert_batch`, `insert_batches`, `resolve_calls`, `get_function`, `get_calls_from`, `get_callers`, `get_callers_by_name`, `get_data_access`, `get_table_accessors`, `get_entry_points`, `get_data_accessors`, `get_functions_in_file`, `get_stats`

**SqliteReachabilityEngine** (`crates/drift-core/src/reachability/sqlite_engine.rs`):
- Opens `callgraph.db` in read-only mode
- BFS traversal via SQL queries (not in-memory graph)
- O(1) memory regardless of codebase size
- Sensitive field classification (PII, financial, health, credentials)

### Backend 5: Cortex Memory Storage

Separate SQLite database (`cortex.db`) with `sqlite-vec` extension for vector operations.

**Schema (v5, 5 migrations)**:
- `memories` — 23 memory types, JSON content, bitemporal tracking (recorded_at, valid_from, valid_until), confidence, importance, access tracking, archival
- `memory_relationships` — Memory-to-memory edges with strength (supersedes, supports, contradicts, related, derived_from + 8 semantic types)
- `memory_patterns` / `memory_constraints` / `memory_files` / `memory_functions` — Cross-domain links
- `memory_embeddings` — 384-dimensional vectors via sqlite-vec virtual table
- `memory_embedding_link` — Maps memory IDs to embedding row IDs
- V2 tables: `causal_edges`, `session_contexts`, `memory_validation_history`, `memory_usage_history`, `memory_contradictions`, `consolidation_triggers`, `token_usage_snapshots`, `memory_clusters`
- 20+ indexes covering type, confidence, validity, importance, timestamps, links, relationships

**Embedding cache (3-tier)**:
- L1: In-memory LRU (~1000 entries, microsecond access)
- L2: SQLite persistent cache (millisecond access, survives restarts)
- L3: Precomputed embedding shards (zero-latency, loaded at startup)

**IMemoryStorage interface**: CRUD, bulk operations, query operations, vector similarity search, bitemporal queries, relationship management, link operations, aggregation, maintenance (vacuum, checkpoint).

### Backend 6: Hybrid Stores

Transitional bridge layer during Phase 3→4 migration. `HybridPatternStore` reads from SQLite, optionally writes to both SQLite + JSON. `HybridContractStore` same pattern for contracts. `SyncService` syncs 11 data domains from JSON → SQLite bidirectionally. Exists solely for backward compatibility during migration.

---

## Key Algorithms

### 1. Query Routing (Data Lake QueryEngine)
```
Query → Check ManifestStore.isViewStale(view)
  If fresh → Return from ViewStore (pre-computed)
  If stale → Check IndexStore (O(1) lookup)
    If available → Return from IndexStore
    If not → Load from ShardStore (partitioned)
      If not → Fall back to raw pattern loading
```
Every result includes `source` field indicating which path was used. Stats tracking records hit counts and response times per source.

### 2. Incremental Materialization (ViewMaterializer)
Views are only rebuilt when stale. Staleness is tracked per-view in ManifestStore with `invalidatedBy` reasons. After scan, only affected views are rebuilt. Cross-domain stat sync (callgraph, contracts) happens as part of materialization.

### 3. Content-Hash Change Detection (ManifestStore)
SHA-256 hashing of file contents for incremental scan support. `hasFileChanged(file, newHash)` compares stored vs new hash. Enables skip-unchanged-files optimization.

### 4. Shard Checksumming
All shards include SHA-256 checksums for change detection. `hasShardChanged(category, checksum)` compares stored vs new checksum. Prevents unnecessary shard rewrites.

### 5. MPSC Batch Writer (Rust CallGraphDb)
```
rayon worker threads → [FunctionBatch] → MPSC channel → dedicated writer thread
  Writer thread buffers batches
  When buffer reaches threshold (100) → flush as single transaction
  On shutdown → flush remaining buffer
```
This pattern serializes writes while allowing parallel parsing. Eliminates per-row transaction overhead.

### 6. Connection Pooling Strategy (V2 Target)
```
DatabaseManager {
  writer: Mutex<Connection>     — Single write connection (SQLite constraint)
  readers: Vec<Mutex<Connection>> — Pool of N read connections (WAL enables concurrent reads)
}
```
Write operations go through the single writer. Read operations round-robin across the reader pool.

---

## Data Models

### Pattern Storage Schema
```sql
patterns (id TEXT PK, category TEXT, subcategory TEXT, name TEXT, description TEXT,
  status TEXT [discovered|approved|ignored], detection_method TEXT, detector_id TEXT,
  pattern_id TEXT, confidence_frequency REAL, confidence_consistency REAL,
  confidence_age INT, confidence_spread INT, confidence_score REAL,
  confidence_level TEXT, severity TEXT, auto_fixable INT, first_seen TEXT,
  last_seen TEXT, source TEXT, tags TEXT [JSON], created_at TEXT, updated_at TEXT)

pattern_locations (id INT PK, pattern_id TEXT FK, file TEXT, line INT, column_num INT,
  is_outlier INT, confidence REAL, outlier_reason TEXT, created_at TEXT)

pattern_variants (id INT PK, pattern_id TEXT FK, scope TEXT [global|directory|file],
  scope_path TEXT, severity_override TEXT, enabled_override INT,
  threshold_override REAL, config_override TEXT [JSON], expires_at TEXT)

pattern_examples (id INT PK, pattern_id TEXT FK, file TEXT, code TEXT,
  line_start INT, line_end INT, is_positive INT, created_at TEXT)

pattern_history (id INT PK, pattern_id TEXT, action TEXT [created|updated|approved|ignored|deleted],
  old_value TEXT [JSON], new_value TEXT [JSON], created_at TEXT)
```

### Call Graph Storage Schema (Rust)
```sql
functions (id TEXT PK, name TEXT, file TEXT, start_line INT, end_line INT,
  is_entry_point BOOL, is_data_accessor BOOL, calls_json TEXT, data_access_json TEXT)
call_edges (caller_id TEXT, callee_id TEXT, callee_name TEXT, confidence REAL, line INT)
data_access (function_id TEXT, table_name TEXT, operation TEXT, fields_json TEXT, line INT)
metadata (key TEXT PK, value TEXT)
```

### Cortex Memory Schema
```sql
memories (id TEXT PK, type TEXT, content TEXT [JSON], summary TEXT,
  recorded_at TEXT, valid_from TEXT, valid_until TEXT, confidence REAL,
  importance TEXT, last_accessed TEXT, access_count INT, created_at TEXT,
  updated_at TEXT, created_by TEXT, tags TEXT [JSON], archived INT,
  archive_reason TEXT, superseded_by TEXT, supersedes TEXT, last_validated TEXT)

memory_embeddings — sqlite-vec virtual table (float[384])
```

### Data Lake Types
```typescript
DriftManifest { version, generatedAt, projectRoot, stats: ManifestStats,
  fileHashes: Record<string, string>, lastScan: LastScanInfo, views: ViewFreshness }

StatusView { generatedAt, health: { score, trend, factors },
  patterns: { total, approved, discovered, ignored, byCategory },
  issues: { critical, warnings, topIssues },
  security: { riskLevel, violations, sensitiveExposures }, lastScan }

DataLakeConfig { rootDir, enableSharding, shardThreshold, enableViews,
  enableIndexes, autoRebuild, viewTtlMs }
```

---

## Capabilities

### What Storage Can Do Today
1. **Multi-backend persistence**: Patterns, contracts, constraints, boundaries, environment, call graph, audit, DNA, test topology, constants, decisions, coupling, errors, wrappers, quality gates, learning data
2. **Pre-computed views**: Instant `drift_status` response via StatusView
3. **Sharded loading**: Load only the category/file/table you need
4. **O(1) index lookups**: File → patterns, category → patterns, table → access points, entry point → reachable data
5. **Query routing**: Automatic selection of optimal data source
6. **Incremental materialization**: Only rebuild stale views after scans
7. **Content-hash change detection**: Skip unchanged files during scans
8. **Hot backup**: SQLite backup API for consistent snapshots without downtime
9. **Schema migration**: Version-tracked migrations with rollback support
10. **Bitemporal queries**: Cortex memories with transaction time and valid time
11. **Vector similarity search**: 384-dimensional embeddings via sqlite-vec
12. **Cross-domain linking**: Memories linked to patterns, constraints, files, functions
13. **Parallel write pipeline**: MPSC channel pattern for rayon → SQLite writes
14. **WAL concurrent access**: Multiple readers during writes

### What Storage Cannot Do (Limitations)
1. **No single source of truth**: 6 backends with 3 sync paths create inconsistency risk
2. **No transactional guarantees across domains**: JSON writes can partially fail
3. **No incremental scanning at storage level**: Full rescan writes everything
4. **No real materialized views**: JSON "views" are manually rebuilt, not auto-refreshed
5. **No connection pooling**: Single connection per backend
6. **No prepared statement caching**: Each query re-parsed
7. **No keyset pagination**: Uses OFFSET/LIMIT which degrades at scale
8. **No write batching for patterns**: Individual inserts, not batch transactions
9. **No schema versioning in Rust**: Only TS has migration support
10. **No cross-database queries**: drift.db and cortex.db are isolated
11. **No compression**: JSON files stored uncompressed
12. **No retention policies**: History grows unbounded
13. **No data integrity validation**: No periodic consistency checks
14. **No telemetry on storage performance**: No query timing, cache hit rates

---

## Integration Points

| Connects To | How |
|---|---|
| **01-rust-core** | CallGraphDb and SqliteReachabilityEngine live in Rust core. V2: Rust owns all of drift.db |
| **02-parsers** | ParseResult feeds into storage via detectors and call graph builder |
| **03-detectors** | Detectors produce patterns → stored in patterns table / JSON shards |
| **04-call-graph** | Call graph stored in both Rust SQLite (callgraph.db) and TS shards (lake/callgraph/) |
| **05-analyzers** | Analyzer results stored across multiple domain tables |
| **06-cortex** | Separate cortex.db with its own schema, migrations, and sqlite-vec |
| **07-mcp** | MCP tools query storage for all responses. QueryEngine is the primary read path |
| **09-quality-gates** | SnapshotStore and GateRunStore use file-based JSON storage |
| **10-cli** | CLI commands read/write through storage layer |
| **18-constraints** | ConstraintStore uses file-based JSON in .drift/constraints/ |
| **20-contracts** | Dual storage: SQLite (primary) + JSON (legacy) |
| **21-security** | BoundaryStore persists access maps, models, sensitive fields |
| **24-data-lake** | The Lake IS a storage subsystem — views, indexes, shards, query engine |
| **25-services** | ScannerService writes results to storage after aggregation |
| **26-workspace** | WorkspaceManager orchestrates backup, migration, context loading |

---

## V2 Migration Status

### What Stays (Solid Foundation)
- SQLite unified schema (40+ tables, 50+ indexes, triggers, views)
- Rust CallGraphDb with ParallelWriter pattern
- Cortex SQLite with sqlite-vec
- Repository pattern for typed access
- WAL mode, NORMAL synchronous, foreign keys ON
- Backup API integration
- Content-hash change detection concept

### What Gets Removed (~6,410 lines)
- 17 JSON storage files (pattern-store, contract-store, history-store, schema-validator, hybrid stores, sync-service, all lake stores)
- All JSON files in `.drift/` (patterns/, contracts/, constraints/, boundaries/, environment/, audit/, dna/, test-topology/, lake/, views/, indexes/, history/, manifest.json)
- Hybrid bridge stores
- Bidirectional JSON↔SQLite sync

### What Gets Refactored
- store-factory.ts → SQLite-only (remove JSON/hybrid paths)
- cache-manager.ts → SQLite-backed cache (remove JSON persistence)
- project-registry.ts → SQLite table (remove ~/.drift/registry.json)
- query-engine.ts → Direct SQLite queries (remove JSON shard routing)
- Data Lake facade → Thin wrapper over UnifiedStore + SQLite views

### Ownership Transfer
- **Rust Core** owns drift.db: schema creation, migrations, all writes, WAL/pragma config, batch optimization, connection pooling
- **TypeScript** gets read-only access via NAPI bindings
- **Cortex** stays in TypeScript (owns cortex.db via better-sqlite3 + sqlite-vec)

---

## Detailed Component Audit

### UnifiedStore Lifecycle (`unified-store.ts`)

The `UnifiedStore` class manages the full SQLite lifecycle:
- `initialize()` — Opens connection, sets pragmas (WAL, NORMAL, foreign_keys), creates schema if needed, runs migrations
- `close()` — Closes connection gracefully
- `transaction(fn)` — Wraps operations in a transaction with automatic rollback on error
- `export()` — Exports all data as JSON (for backup/migration)
- `import(data)` — Imports JSON data into SQLite (for restore/migration)

### StoreFactory Auto-Detection (`store-factory.ts`)

`store-factory.ts` implements a 3-tier backend detection strategy:
1. Check for `drift.db` → use SQLite backend
2. Check for `.drift/patterns/` JSON files → use JSON backend
3. Default → create new SQLite backend

Supports `backend: 'auto' | 'sqlite' | 'json'` configuration. In `auto` mode, prefers SQLite if `drift.db` exists. The `hasJsonPatterns()` helper checks for any `.json` files in `.drift/patterns/`. V2 removes `'json'` and `'auto'` — always SQLite.

### SyncService 11 Data Domains (`sync-service.ts`)

The `SyncService` (~1142 lines) synchronizes 11 data domains bidirectionally between JSON and SQLite:

| # | Domain | JSON Source | SQLite Table(s) |
|---|--------|-------------|-----------------|
| 1 | Patterns | `.drift/patterns/{status}/{category}.json` | `patterns`, `pattern_locations` |
| 2 | Contracts | `.drift/contracts/{status}/contracts.json` | `contracts`, `contract_frontends` |
| 3 | Constraints | `.drift/constraints/{category}.json` | `constraints` |
| 4 | Boundaries | `.drift/boundaries/` | `data_models`, `sensitive_fields`, `data_access_points` |
| 5 | Environment | `.drift/environment/` | `env_variables`, `env_access_points` |
| 6 | Call Graph | `.drift/lake/callgraph/` | `functions`, `function_calls`, `function_data_access` |
| 7 | Audit | `.drift/audit/` | `audit_snapshots`, `pattern_history`, `health_trends` |
| 8 | DNA | `.drift/dna/` | `dna_profile`, `dna_genes`, `dna_mutations` |
| 9 | Test Topology | `.drift/test-topology/` | `test_files`, `test_coverage` |
| 10 | Scan History | `.drift/history/` | `scan_history` |
| 11 | Quality Gates | `.drift/quality-gates/` | `quality_gate_runs`, `quality_gate_snapshots` |

Each domain has `syncToSqlite()` and `syncFromSqlite()` methods. Sync triggers fire on INSERT/UPDATE/DELETE via the `sync_log` table.

### Project Metadata Tables

**`project` table**: `id TEXT PK`, `name TEXT`, `root_path TEXT`, `drift_version TEXT`, `schema_version TEXT`. Singleton row representing the current project.

**`config` table**: Key-value store for project configuration. `key TEXT PK`, `value TEXT` (JSON blob). Stores settings like `autoApproveThreshold`, `minOccurrences`, `severity` overrides.

**`feature_flags` table**: `feature TEXT PK`, `enabled INTEGER`, `config TEXT` (JSON). Controls feature toggles like `enableSharding`, `enableViews`, `enableIndexes`, `autoRebuild`. Used by the Data Lake and other subsystems to conditionally enable capabilities.

### Quality Gate Storage Tables

**`quality_gate_runs`**: `id TEXT PK`, `timestamp TEXT`, `branch TEXT`, `commit_sha TEXT`, `policy_id TEXT`, `passed INTEGER`, `score REAL`, `gates TEXT` (JSON — per-gate pass/fail/score), `violation_count INTEGER`, `execution_time_ms INTEGER`, `ci INTEGER`. Lightweight run summaries for trend analysis.

**`quality_gate_snapshots`**: `id TEXT PK`, `timestamp TEXT`, `branch TEXT`, `commit_sha TEXT`, `patterns TEXT` (JSON — per-pattern confidence/compliance/outlier counts), `constraints TEXT` (JSON — per-constraint pass/fail), `security TEXT` (JSON — access points, sensitive fields). Full health snapshots for regression detection.

V1 stores these as JSON files in `.drift/quality-gates/snapshots/{branch}/` and `.drift/quality-gates/history/runs/`. V2 moves them to SQLite tables.

### Learning Data Table

**`learned_patterns`**: Stores patterns that have been learned from user feedback (approvals, ignores). Tracks which patterns were auto-approved based on confidence thresholds, which were manually approved, and learning metadata. Used by the learning system to improve detection accuracy over time.

### source-of-truth.json

`.drift/source-of-truth.json` is a metadata file that records which storage backend is authoritative for each data domain. During the hybrid migration phase, it tracks whether JSON or SQLite is the "source of truth" for patterns, contracts, etc. V2 eliminates this file entirely — SQLite is always the source of truth.

### CallGraphShardStore Entry Point Type Inference

The `CallGraphShardStore.buildEntryPoints()` method classifies entry points by type:
- `api` — Express/Fastify/NestJS route handlers
- `handler` — Event handlers, middleware
- `controller` — MVC controller methods
- `route` — Route definitions
- `other` — Exported functions not matching above patterns

Classification uses function name patterns, decorator analysis, and file path heuristics.

### SecurityShardStore Analysis Methods

**`detectViolations(shard)`**: Auto-detects security violations within a table's access map:
- Unprotected access to sensitive data (no auth middleware in call chain)
- Missing authorization checks (direct DB access without role verification)
- Direct database access from route handlers (bypassing service layer)

**`calculateRiskScore(shard)`**: Per-table risk score based on:
- Sensitivity level of fields (PII=0.9, credentials=1.0, financial=0.85, health=0.9)
- Number of access points (more access = higher risk)
- Presence of raw SQL (higher risk than ORM)
- Violation count

**`calculateOverallRisk(index)`**: Aggregates per-table risk into overall risk level (low/medium/high/critical).

### ExamplesStore Extraction and Quality

**`extractExamples(pattern, options)`**: Reads source files at pattern locations, extracts code snippets with configurable context lines (default: 3). Options: `maxExamples` (default: 5), `contextLines` (default: 3), `minQuality` (default: 0.3), `maxFileSize` (default: 1MB).

**`calculateExampleQuality(example)`**: Scores examples by:
- Length (too short = low quality, too long = low quality)
- Content (has meaningful code vs. just whitespace/comments)
- Structure (complete statements vs. fragments)

### Cortex V2 Tables (Migrations 2-5)

Beyond the core `memories` and relationship tables, Cortex schema v5 includes:
- `causal_edges` — Causal graph edges between memories
- `session_contexts` — Session state persistence for multi-turn conversations
- `memory_validation_history` — Validation feedback tracking
- `memory_usage_history` — Effectiveness tracking (was this memory useful?)
- `memory_contradictions` — Detected contradictions between memories
- `consolidation_triggers` — Adaptive consolidation trigger conditions
- `token_usage_snapshots` — Token monitoring for context window management
- `memory_clusters` — Memory grouping for related memories

### Cortex Memory Types

The Cortex stores 9 core memory types in v1 (with 25 types planned for v2):
- Core v1: `core`, `tribal`, `procedural`, `semantic`, `episodic`, `incident`, `feedback`, `conversation`, `goal`
- V2 additions include: `workflow`, `skill`, `environment`, `entity`, `blocker`, and semantic subtypes

### Cortex Relationship Types (Full List)

Core (v1): `supersedes`, `supports`, `contradicts`, `related`, `derived_from`
Semantic (v2): `owns`, `affects`, `blocks`, `requires`, `references`, `learned_from`, `assigned_to`, `depends_on`

### DriftConfig and config.json

`drift.config.json` in project root controls runtime behavior:
```typescript
{
  severity?: Record<string, Severity>;  // Pattern severity overrides
  ignore?: string[];                     // Files/folders to ignore
  ai?: { provider, model };             // AI provider config
  ci?: { failOn, reportFormat };         // CI mode settings
  learning?: { autoApproveThreshold, minOccurrences };
  performance?: { maxWorkers, cacheEnabled, incrementalAnalysis };
}
```
Environment overrides: `DRIFT_AI_PROVIDER`, `DRIFT_AI_MODEL`, `DRIFT_CI_FAIL_ON`. The `config` table in SQLite mirrors these settings for programmatic access.

### Pattern ID Generation

Pattern IDs are 16-character hex strings derived from hashing `detectorId` (e.g., `"security/sql-injection"`) and `patternId` (e.g., `"security/sql-injection/property_access"`). The `patternId` suffix indicates match context type: `/unknown`, `/assignment`, `/conditional`, `/property_access`, `/import`, `/call`. A single detector can produce multiple patterns with different context suffixes.

### Confidence Thresholds

Confidence levels are classified from the composite `confidence_score`:
- `high`: score >= 0.85
- `medium`: score >= 0.70 and < 0.85
- `low`: score >= 0.50 and < 0.70
- `uncertain`: score < 0.50

These thresholds are used by the learning system (`autoApproveThreshold`) and quality gates.

### PatternFile Structure (JSON Shard Format)

Each category's JSON shard follows this structure (relevant for v1→v2 upgrade path):
```typescript
interface PatternFile {
  version: "2.0.0";
  category: string;
  patterns: Pattern[];
  lastUpdated: string;           // ISO-8601
  checksum: string;              // 16-char hex integrity hash
  patternCount: number;
  statusCounts: { discovered: number; approved: number; ignored: number; };
}
```

### Violation Data Model (Ephemeral — Not Stored)

The `Violation` type from `DetectionResult` is NOT persisted to storage. Violations are computed at detection time and surfaced through MCP tools and CLI in real-time. The data model:
```typescript
interface Violation {
  id: string;
  patternId: string;
  severity: 'error' | 'warning' | 'info' | 'hint';
  message: string;
  file: string;
  range: { start: {line, character}, end: {line, character} };
  expected: string;
  actual: string;
  quickFixes: QuickFix[];       // { title, edits: WorkspaceEdit[] }
}
```
Security violations (from `SecurityShardStore.detectViolations()`) are stored as counts in `materialized_security` and as JSON in `quality_gate_snapshots.security`. Individual violations are not stored as rows — they are recomputed from boundary data on demand.

### ContextLoader and WorkspaceContext Pre-Loading

The `ContextLoader` from `packages/core/src/workspace/` pre-loads workspace data for fast CLI/MCP access using a two-tier cache:
- **L1**: In-memory cache with TTL (default: 5 minutes)
- **L2**: Disk cache at `.drift/.context-cache.json`

The `WorkspaceContext` type aggregates:
```typescript
{
  project: { id, name, rootPath, driftPath, schemaVersion, driftVersion, lastScanAt, healthScore, languages, frameworks },
  lake: { available, patternSummary, callGraphSummary, boundarySummary, lastUpdatedAt },
  analysis: { callGraphBuilt, testTopologyBuilt, couplingBuilt, dnaProfileExists, memoryInitialized, constantsExtracted },
  loadedAt, validUntil
}
```

In v2, `.drift/.context-cache.json` is eliminated. The `WorkspaceContext` is served directly from `materialized_status` (R2) and `feature_flags` (R23) tables — no disk cache needed because SQLite reads are fast enough. The L1 in-memory cache can be preserved in the Rust `DatabaseManager` for sub-millisecond repeated access.

### Global Database (`~/.drift/global.db`)

The `project-registry.ts` currently stores a global project registry at `~/.drift/registry.json`. In v2, this moves to `~/.drift/global.db` — a SEPARATE SQLite database from the per-project `.drift/drift.db`. The `project_registry` table lives in `global.db`, not in `drift.db`. This enables multi-project switching without opening every project's database.

### Cortex Prepared Queries (`queries.ts`)

`packages/cortex/src/storage/sqlite/queries.ts` contains optimized SQL query builders for common Cortex operations. These are pre-built SQL strings for memory CRUD, relationship traversal, vector search, and bitemporal queries. In v2, these map to `prepare_cached()` calls in the Cortex TypeScript layer (Cortex stays TS-owned).

### Cortex Storage Factory (`factory.ts`)

`packages/cortex/src/storage/factory.ts` implements storage creation with auto-detection. Detects whether to use SQLite or in-memory storage based on environment. Creates and initializes the `SQLiteMemoryStorage` instance with sqlite-vec extension loading. In v2, the factory simplifies to always-SQLite (no in-memory fallback needed).

### Repository Interface Methods (types.ts)

`packages/core/src/storage/types.ts` (~500 lines) defines all DB types and repository interfaces. Key repository methods not fully enumerated above:

**PatternRepository** (most complex): `create`, `read`, `update`, `delete`, `exists`, `count`, `findByCategory`, `findByStatus`, `findByFile`, `findByConfidence`, `findByDetector`, `findByTag`, `findByDateRange`, `search` (15+ filter fields including category, status, confidence range, file, detector, tags, date range, severity, auto_fixable), `bulkCreate`, `bulkUpdate`, `bulkDelete`, `getAggregations` (counts by category, status, confidence level), `getLocationStats`, `getOutlierStats`.

**Other repositories**: All follow the same CRUD + query + aggregation pattern. The interface contract is preserved in v2 via NAPI bindings (R12).

### Consumer Updates Required for v2

Per `removal-plan.md`, these consumers need updating when storage changes:

**MCP Tools**: `drift_status` (manifest.json → materialized_status table), `drift_patterns_list` (pattern shards → patterns table), `drift_file_patterns` (file index → pattern_locations JOIN), `drift_security_summary` (security shards → materialized_security table), `drift_code_examples` (examples store → pattern_examples table).

**CLI Commands**: `drift scan` (write SQLite only), `drift status` (read from DB), `drift approve/ignore` (update SQLite only), `drift migrate-storage` → becomes `drift upgrade`, `drift backup` (use SQLite backup API).

**Detectors**: Interface unchanged — detectors return patterns, persistence layer changes underneath.

### BackupManager Enterprise Features

The `BackupManager` from `packages/core/src/workspace/` provides:
- SHA-256 checksum integrity verification per backup
- Gzip compression for JSON files (irrelevant in v2 — SQLite backup is a single file)
- 6 backup reasons: `version_upgrade`, `schema_migration`, `user_requested`, `pre_destructive_operation`, `scheduled`, `auto_save`
- `backup-manifest.json` with metadata (id, version, checksum, files list)
- Index file at `.drift-backups/index.json`
- Retention policy: default 10 backups max

In v2, backup simplifies to SQLite backup API (R8). The backup manifest concept is preserved as metadata in the backup filename and a `backup_history` entry. Gzip compression is unnecessary (SQLite files are already compact). The 6 backup reasons are preserved as an enum in the Rust `BackupManager`.

### SchemaMigrator v1 Lifecycle

The v1 `SchemaMigrator` from `packages/core/src/workspace/` manages:
- Built-in migrations: `1.0.0 → 1.1.0` (add pattern confidence breakdown), `1.1.0 → 2.0.0` (restructure lake, add memory system)
- Rollback in reverse order on failure
- Migration history in `.drift/migration-history.json`
- Version detection from `.drift/config.json`

In v2, this is entirely superseded by FA2 (`rusqlite_migration` with `user_version`). The v1 `SchemaMigrator` is only needed during `drift upgrade` (R21) to detect the v1 schema version and determine the upgrade path. After upgrade, it is removed.

### DataLake Facade Refactoring

The `packages/core/src/lake/index.ts` barrel export orchestrates all 8 JSON-based stores. In v2, this becomes a thin facade over `UnifiedStore` + SQLite views. Most methods become single SQL queries via NAPI bindings. The facade is not a separate recommendation because it's subsumed by R12 (NAPI bindings) — the TypeScript layer calls Rust directly instead of going through a Lake facade.

### migration.ts Temporary Keep Timeline

`packages/core/src/storage/migration.ts` (~500 lines) is kept temporarily for the `drift upgrade` command (R21). It is removed in v2.1 once the upgrade path is no longer needed (estimated: 6 months after v2.0 GA, or when v1 usage drops below a threshold). The removal is tracked as a v2.1 cleanup task.

---

## Open Questions

1. **Cortex consolidation timing**: ✅ ANSWERED in R10 — Separate cortex.db for v2.0, ATTACH DATABASE for cross-domain queries. Consolidate in v2.1+ once Rust core is stable.
2. **Migration rollback**: ✅ ANSWERED in FA2 — `rusqlite_migration` supports both up and down migrations. Auto-backup before migration (R8) provides safety net.
3. **Lock file format**: ✅ ANSWERED in R16 — TOML format, generated from DB, with `drift lock validate` for CI integration.
4. **Cloud sync**: OPEN — sync_log table repurposed for cloud sync only (v2.1+). Conflict resolution strategy (last-write-wins with vector clocks) deferred to cloud sync design phase.
5. **Quality gate storage**: ✅ ANSWERED in R21 — Migrated from JSON to SQLite tables (`quality_gate_runs`, `quality_gate_snapshots`) during `drift upgrade`.
6. **Constraint storage**: ✅ ANSWERED in R21 — Migrated from JSON to SQLite `constraints` table during `drift upgrade`.
7. **Cache TTL strategy**: ✅ ANSWERED in R15 — `cache_entries_max_age_hours: 24` default. Cache warming on cold start via materialized status table (R2) — no warm-up needed for the most common query.
8. **Database size limits**: ✅ ANSWERED in R22 — Monorepo support via `packages` table enables per-package analysis. SQLite handles databases up to 281TB. Retention policies (R15) and VACUUM (R17) keep size manageable.

---

## Quality Checklist

- [x] All files in category 08-storage have been read (overview.md, removal-plan.md, rust-ownership.md, sqlite-schema.md)
- [x] All related storage files across other categories read (24-data-lake/*, 04-call-graph/storage.md, 06-cortex/storage.md, 06-cortex/cache.md, 03-detectors/patterns/storage.md, 03-detectors/patterns/data-model.md, 20-contracts/storage.md, 09-quality-gates/store.md, 18-constraints/store.md, 26-workspace/overview.md, 25-services-layer/overview.md, 21-security/overview.md, 00-overview/data-models.md)
- [x] Architecture clearly described with diagrams
- [x] All 6 backends documented with file counts and line counts
- [x] Key algorithms documented (query routing, materialization, change detection, MPSC writer, connection pooling)
- [x] All data models listed with fields
- [x] Limitations honestly assessed (14 specific gaps)
- [x] Integration points mapped to 15 other categories
- [x] V2 migration status documented with ownership transfer
- [x] Open questions identified (8 specific questions)
- [x] **AUDIT PASS 2**: UnifiedStore lifecycle documented (initialize, close, transaction, export/import)
- [x] **AUDIT PASS 2**: StoreFactory auto-detection logic documented (3-tier detection)
- [x] **AUDIT PASS 2**: SyncService 11 data domains fully enumerated with JSON→SQLite mapping
- [x] **AUDIT PASS 2**: Project metadata tables documented (project, config, feature_flags)
- [x] **AUDIT PASS 2**: Quality gate tables documented (quality_gate_runs, quality_gate_snapshots)
- [x] **AUDIT PASS 2**: learned_patterns table and learning data flow documented
- [x] **AUDIT PASS 2**: source-of-truth.json purpose documented
- [x] **AUDIT PASS 2**: CallGraphShardStore entry point type inference documented (api, handler, controller, route, other)
- [x] **AUDIT PASS 2**: SecurityShardStore.detectViolations() and calculateRiskScore() documented
- [x] **AUDIT PASS 2**: ExamplesStore.extractExamples() and calculateExampleQuality() documented
- [x] **AUDIT PASS 2**: Cortex v2 tables documented (causal_edges, session_contexts, etc.)
- [x] **AUDIT PASS 2**: Cortex memory types and relationship types fully enumerated
- [x] **AUDIT PASS 2**: DriftConfig and config.json relationship to storage documented
- [x] **AUDIT PASS 3**: Pattern ID generation algorithm documented (16-char hex from detectorId + patternId, context suffixes)
- [x] **AUDIT PASS 3**: Confidence thresholds documented (high >= 0.85, medium >= 0.70, low >= 0.50, uncertain < 0.50)
- [x] **AUDIT PASS 3**: PatternFile JSON shard structure documented (version, category, patterns, checksum, statusCounts)
- [x] **AUDIT PASS 3**: Violation data model documented as EPHEMERAL (not stored — computed at detection time)
- [x] **AUDIT PASS 3**: ContextLoader and WorkspaceContext pre-loading documented with v2 replacement strategy
- [x] **AUDIT PASS 3**: Global database (~/.drift/global.db) for project_registry documented as SEPARATE from drift.db
- [x] **AUDIT PASS 3**: Cortex queries.ts (prepared SQL query builders) documented
- [x] **AUDIT PASS 3**: Cortex factory.ts (storage creation and auto-detection) documented
- [x] **AUDIT PASS 3**: Repository interface methods fully enumerated (PatternRepository 15+ filter fields, bulk ops, aggregations)
- [x] **AUDIT PASS 3**: Consumer updates enumerated (5 MCP tools, 5 CLI commands, detectors)
- [x] **AUDIT PASS 3**: BackupManager enterprise features documented (SHA-256, gzip, 6 reasons, manifest, index)
- [x] **AUDIT PASS 3**: SchemaMigrator v1 lifecycle documented (1.0.0→1.1.0→2.0.0, rollback, superseded by FA2)
- [x] **AUDIT PASS 3**: DataLake facade refactoring addressed (subsumed by R12 NAPI bindings)
- [x] **AUDIT PASS 3**: migration.ts temporary keep timeline documented (remove in v2.1, ~6 months after GA)
