# 24 Data Lake — Research Recap

## Executive Summary

The Data Lake is Drift's enterprise-grade query optimization layer — a pre-computation and selective-loading architecture (~4,570 lines of TypeScript across 11 source files) that sits between raw analysis data and consumers (MCP tools, CLI, dashboard), transforming expensive full-dataset queries into instant responses through materialized views, dimension-sharded storage, O(1) lookup indexes, and intelligent query routing. In v1, the entire layer is implemented as JSON files on disk with in-memory caching. V2 replaces the JSON implementation with native SQLite views, indexes, and materialized tables while preserving the architectural concepts that made the Data Lake effective: pre-computation of common queries, selective loading by dimension, incremental materialization, and graceful fallback when pre-computed data is stale.

The Data Lake is the most architecturally creative subsystem in Drift v1 — it solved real performance problems (instant `drift_status`, load-only-what-you-need for MCP tools, skip-unchanged-files for incremental scans) with a design that anticipated enterprise-scale needs. Its fatal flaw was the JSON implementation: no transactional guarantees, no concurrent access safety, no query optimization beyond pre-computation, and 30+ files cluttering `.drift/` with version control noise. V2 preserves the intelligence while eliminating the implementation debt.

---

## Current Implementation

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CONSUMERS                                            │
│  MCP Tools (drift_status, drift_patterns_list, drift_file_patterns,         │
│             drift_security_summary, drift_code_examples)                     │
│  CLI Commands (drift status, drift patterns, drift security)                 │
│  Dashboard (health overview, trend charts, pattern explorer)                 │
│  Quality Gates (health score input, regression baseline)                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                         QUERY ENGINE                                         │
│  QueryEngine (~400 LOC)                                                      │
│  Routes to optimal source: Views → Indexes → Shards → Raw fallback          │
│  Staleness checking via ManifestStore                                        │
│  Pagination with cursor support                                              │
│  Stats tracking (hit counts, response times per source)                      │
├──────────┬──────────────┬──────────────┬────────────────────────────────────┤
│ VIEW     │ INDEX        │ SHARD        │ RAW DATA                           │
│ STORE    │ STORE        │ STORES       │ (injected loader)                  │
│ (~430    │ (~440 LOC)   │ (~2,290 LOC) │                                    │
│  LOC)    │              │              │                                    │
│          │              │              │                                    │
│ status   │ by-file      │ pattern      │ PatternStore                       │
│ patterns │ by-category  │ callgraph    │ ContractStore                      │
│ security │ by-table     │ security     │ BoundaryStore                      │
│ trends   │ by-entry-pt  │ examples     │ CallGraphDb                        │
├──────────┴──────────────┴──────────────┴────────────────────────────────────┤
│                    VIEW MATERIALIZER (~590 LOC)                               │
│  10-step post-scan rebuild pipeline                                          │
│  Selective rebuild (stale views only)                                         │
│  Cross-domain stat sync (callgraph, contracts)                               │
│  Risk calculation (per-table and overall)                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                    MANIFEST STORE (~420 LOC)                                  │
│  Quick-load index: all stats in single file read                             │
│  File hash management (SHA-256 for incremental scans)                        │
│  View freshness tracking (stale/fresh/invalidatedBy)                         │
│  Dirty tracking for save optimization                                        │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Component Inventory

| Component | File | LOC (est.) | Purpose |
|-----------|------|-----------|---------|
| QueryEngine | `query-engine.ts` | ~400 | Unified query API with routing, pagination, stats |
| ViewStore | `view-store.ts` | ~430 | Pre-computed view CRUD with in-memory caching |
| IndexStore | `index-store.ts` | ~440 | O(1) lookup indexes with incremental update |
| PatternShardStore | `pattern-shard-store.ts` | ~430 | Patterns partitioned by category |
| CallGraphShardStore | `callgraph-shard-store.ts` | ~650 | Call graph partitioned by file hash |
| SecurityShardStore | `security-shard-store.ts` | ~660 | Security data partitioned by table name |
| ExamplesStore | `examples-store.ts` | ~550 | Code examples partitioned by pattern ID |
| ViewMaterializer | `view-materializer.ts` | ~590 | Post-scan view/index rebuild pipeline |
| ManifestStore | `manifest-store.ts` | ~420 | Quick-load stats index + file hashing + view freshness |
| Types | `types.ts` | ~300 | All type definitions (25+ interfaces) |
| Barrel Exports | `index.ts` | ~30 | Lake-prefixed exports to avoid naming conflicts |

**Total: ~4,900 lines across 11 files, 100% TypeScript**

### Disk Layout

```
.drift/
├── manifest.json                      # ManifestStore — single-read stats index
├── views/
│   ├── status.json                    # StatusView — health, patterns, issues, security
│   ├── pattern-index.json             # PatternIndexView — lightweight pattern listing
│   ├── security-summary.json          # SecuritySummaryView — security posture
│   └── trends.json                    # TrendsView — health trends over time
├── indexes/
│   ├── by-file.json                   # FileIndex — file → patternId[]
│   ├── by-category.json               # CategoryIndex — category → patternId[]
│   ├── by-table.json                  # TableIndex — table → accessPointIds
│   └── by-entry-point.json            # EntryPointIndex — entryPoint → reachable data
└── lake/
    ├── patterns/
    │   └── {category}.json            # PatternShardStore — one shard per category
    ├── callgraph/
    │   ├── index.json                 # CallGraphShardStore index
    │   ├── entry-points.json          # Aggregated entry point data
    │   └── {fileHash}.json            # Per-file call graph shards
    ├── security/
    │   ├── index.json                 # SecurityShardStore index
    │   ├── sensitive-fields.json      # Global sensitive field registry
    │   └── {tableName}.json           # Per-table security access maps
    └── examples/
        ├── index.json                 # ExamplesStore index
        └── {patternId}.json           # Per-pattern code examples
```

**File count**: 8 fixed files (manifest + 4 views + 4 indexes) + N dynamic files (shards per category/file/table/pattern). Typical project: 30-80 files total.

---

## Core Design Principles

### Principle 1: Pre-Compute Common Queries
The most frequently asked question is "what's the health status?" (`drift_status` MCP tool, `drift status` CLI). Instead of computing this from raw data on every request, the StatusView pre-computes health score, pattern counts, issue counts, and security risk level. One JSON file read → instant response.

### Principle 2: Shard by Dimension
Large datasets are partitioned by the dimension most commonly used for filtering:
- Patterns → by category (MCP tools typically query one category at a time)
- Call graph → by file (impact analysis starts from a specific file)
- Security → by table (security queries focus on specific database tables)
- Examples → by pattern (code examples are always requested per-pattern)

This means loading "all auth patterns" reads one ~10KB JSON file instead of parsing the entire pattern database.

### Principle 3: Index Everything for O(1) Lookups
Four index types enable instant lookups without loading full data:
- "Which patterns affect this file?" → FileIndex
- "Which patterns are in this category?" → CategoryIndex
- "Which functions access this table?" → TableIndex
- "What data can this entry point reach?" → EntryPointIndex

### Principle 4: Route Queries to Optimal Source
The QueryEngine checks data freshness before choosing a source:
1. **Views** (fastest) — if fresh, return pre-computed result
2. **Indexes** (fast) — if view is stale, use index for O(1) lookup
3. **Shards** (medium) — load specific partition
4. **Raw data** (slowest) — fall back to full data loading

### Principle 5: Rebuild Only What's Stale
After a scan, the ViewMaterializer checks which views were invalidated and rebuilds only those. A scan that only changes auth patterns doesn't need to rebuild the TrendsView.

---

## Key Algorithms

### Algorithm 1: Query Routing

```
function route(queryType, params):
  // Phase 1: Try pre-computed view
  if ManifestStore.isViewFresh(queryType):
    result = ViewStore.get(queryType)
    if result: return { data: result, source: 'view' }

  // Phase 2: Try index lookup
  if queryType has index equivalent:
    ids = IndexStore.lookup(params)
    if ids: return { data: resolve(ids), source: 'index' }

  // Phase 3: Try shard loading
  if queryType has shard dimension:
    shard = ShardStore.get(params.dimension)
    if shard: return { data: filter(shard, params), source: 'shard' }

  // Phase 4: Fall back to raw data
  rawData = rawPatternLoader(params)
  return { data: rawData, source: 'raw' }
```

Every result includes `source` and `executionTime` for monitoring query efficiency.

### Algorithm 2: Incremental Materialization

```
function materialize(patterns, securityData, options):
  staleViews = options.force
    ? ALL_VIEWS
    : ManifestStore.getStaleViews()

  results = []

  // Phase 1: Rebuild stale views
  if 'status' in staleViews:
    statusView = buildStatusView(patterns, securityData, callgraphStats, contractStats)
    ViewStore.save('status', statusView)
    results.push('status')

  if 'patternIndex' in staleViews:
    patternIndex = buildPatternIndexView(patterns)
    ViewStore.save('patternIndex', patternIndex)
    results.push('patternIndex')

  if 'securitySummary' in staleViews:
    securityView = buildSecuritySummaryView(securityData)
    ViewStore.save('securitySummary', securityView)
    results.push('securitySummary')

  if 'trends' in staleViews:
    trendsView = buildTrendsView(options.trendSummary)
    ViewStore.save('trends', trendsView)
    results.push('trends')

  // Phase 2: Rebuild all indexes
  IndexStore.rebuildAll(patterns, securityData)

  // Phase 3: Cross-domain stat sync
  syncCallGraphStats()
  syncContractStats()

  // Phase 4: Mark views fresh
  for view in results:
    ManifestStore.markViewFresh(view)

  ManifestStore.save()
  return { viewsRebuilt: results, duration: elapsed }
```

### Algorithm 3: Content-Hash Change Detection

```
function hasFileChanged(filePath):
  storedHash = ManifestStore.getFileHash(filePath)
  if !storedHash: return true  // New file

  currentHash = SHA256(readFile(filePath))
  return currentHash !== storedHash

function updateFileHash(filePath):
  hash = SHA256(readFile(filePath))
  ManifestStore.setFileHash(filePath, hash)
```

Used by the scanner to skip unchanged files during incremental scans. The manifest stores `Record<string, string>` mapping file paths to their SHA-256 hashes.

### Algorithm 4: Shard Checksumming

```
function hasShardChanged(category, newData):
  storedChecksum = shard.checksum
  newChecksum = SHA256(JSON.stringify(newData))
  return storedChecksum !== newChecksum

function saveShard(category, data):
  shard = {
    version: LAKE_VERSION,
    generatedAt: now(),
    checksum: SHA256(JSON.stringify(data)),
    data: data
  }
  writeFile(shardPath(category), JSON.stringify(shard))
```

Prevents unnecessary shard rewrites when data hasn't changed.

### Algorithm 5: Security Risk Scoring

```
function calculateTableRiskScore(tableInfo):
  sensitivityWeight = {
    PII: 0.9, credentials: 1.0, financial: 0.85, health: 0.9
  }

  baseSensitivity = max(sensitivityWeight[field.type] for field in tableInfo.sensitiveFields)
  accessFactor = min(tableInfo.accessPointCount / 10, 1.0)
  rawSqlPenalty = tableInfo.hasRawSql ? 0.2 : 0.0
  violationPenalty = min(tableInfo.violationCount * 0.1, 0.3)

  return clamp(baseSensitivity * (0.5 + accessFactor * 0.3 + rawSqlPenalty + violationPenalty), 0, 1)

function calculateOverallRisk(index):
  if any table has riskScore >= 0.8: return 'critical'
  if any table has riskScore >= 0.6: return 'high'
  if any table has riskScore >= 0.3: return 'medium'
  return 'low'
```

### Algorithm 6: Example Quality Scoring

```
function calculateExampleQuality(example):
  // Length score: prefer 5-50 lines
  lengthScore = example.lines < 3 ? 0.2
    : example.lines > 100 ? 0.3
    : example.lines <= 50 ? 1.0
    : 0.7

  // Content score: meaningful code vs whitespace/comments
  codeLines = example.lines.filter(isCodeLine)
  contentScore = codeLines.length / example.lines.length

  // Structure score: complete statements
  structureScore = hasCompleteStatements(example) ? 1.0 : 0.5

  return (lengthScore * 0.3 + contentScore * 0.4 + structureScore * 0.3)
```

### Algorithm 7: Entry Point Type Inference

```
function classifyEntryPoint(func):
  if matchesPattern(func.name, /^(get|post|put|delete|patch|handle)/i)
    && func.decorators.some(isRouteDecorator): return 'api'
  if matchesPattern(func.name, /^(handle|on|process)/i): return 'handler'
  if func.file.includes('/controllers/'): return 'controller'
  if func.decorators.some(isRouteDecorator): return 'route'
  if func.isExported && func.isEntryPoint: return 'other'
```

### Algorithm 8: View Freshness Lifecycle

```
State Machine:
  FRESH → markViewStale(reason) → STALE
  STALE → materialize() → FRESH
  STALE → markViewStale(newReason) → STALE (accumulates reasons)
  ANY → markAllViewsStale(reason) → ALL STALE

ViewMeta {
  generatedAt: ISO-8601 timestamp
  stale: boolean
  invalidatedBy?: string[]  // Accumulated reasons for staleness
}

Staleness triggers:
  - Pattern created/updated/deleted → status, patternIndex stale
  - Security data changed → securitySummary stale
  - Scan completed → all views stale (conservative)
  - Manual invalidation → specific view stale
```

---

## Data Models

### Manifest Types

```typescript
interface DriftManifest {
  version: string;                              // Lake version (e.g., "1.0")
  generatedAt: string;                          // ISO-8601
  projectRoot: string;                          // Absolute path
  stats: ManifestStats;                         // Aggregated statistics
  fileHashes: Record<string, string>;           // filePath → SHA-256
  lastScan: LastScanInfo;                       // Most recent scan metadata
  views: ViewFreshness;                         // Per-view staleness tracking
}

interface ManifestStats {
  patterns: PatternStats;                       // Pattern counts and distributions
  security: SecurityStats;                      // Security posture summary
  callGraph: CallGraphStats;                    // Call graph size metrics
  contracts: ContractStats;                     // Contract verification status
  dna: DNAStats;                                // Codebase DNA metrics
}

interface PatternStats {
  total: number;
  byCategory: Record<PatternCategory, number>; // 16 categories
  byStatus: Record<PatternStatus, number>;     // discovered/approved/ignored
  byConfidence: Record<ConfidenceLevel, number>; // high/medium/low/uncertain
  totalLocations: number;
  totalOutliers: number;
}
```

### View Types

```typescript
interface StatusView {
  generatedAt: string;
  health: {
    score: number;                              // 0-100
    trend: 'improving' | 'stable' | 'declining';
    factors: HealthFactor[];                    // Contributing factors
  };
  patterns: {
    total: number;
    approved: number;
    discovered: number;
    ignored: number;
    byCategory: Record<string, number>;
  };
  issues: {
    critical: number;
    warnings: number;
    topIssues: TopIssue[];                      // Most impactful issues
  };
  security: {
    riskLevel: 'low' | 'medium' | 'high' | 'critical';
    violations: number;
    sensitiveExposures: number;
  };
  lastScan: LastScanInfo;
}

interface PatternIndexView {
  generatedAt: string;
  total: number;
  patterns: PatternSummary[];                   // Lightweight listing
}

interface PatternSummary {
  id: string;
  name: string;
  category: PatternCategory;
  subcategory: string;
  status: PatternStatus;
  confidence: number;
  confidenceLevel: ConfidenceLevel;
  locationCount: number;
  outlierCount: number;
  severity: string;
  locationsHash: string;                        // SHA-256 for change detection
}
```

### Index Types

```typescript
interface FileIndex {
  generatedAt: string;
  checksum: string;                             // Index integrity hash
  total: number;                                // Total unique files
  files: Record<string, string[]>;              // filePath → patternId[]
}

interface CategoryIndex {
  generatedAt: string;
  checksum: string;
  total: number;                                // Total categories with data
  categories: Record<PatternCategory, string[]>; // category → patternId[]
}

interface TableIndex {
  generatedAt: string;
  checksum: string;
  tables: Record<string, {
    accessPointIds: string[];
    accessorIds: string[];
  }>;
}

interface EntryPointIndex {
  generatedAt: string;
  checksum: string;
  entryPoints: Record<string, {
    reachableFunctions: string[];
    tables: string[];
    sensitiveData: string[];
  }>;
}
```

### Shard Types

```typescript
interface Shard<T> {
  version: string;                              // Lake version
  generatedAt: string;                          // ISO-8601
  checksum: string;                             // SHA-256 of data
  data: T;
}

interface PatternShard extends Shard<PatternShardEntry[]> {
  category: PatternCategory;
}

interface PatternShardEntry {
  id: string;
  name: string;
  category: PatternCategory;
  subcategory: string;
  status: PatternStatus;
  confidence: number;
  confidenceLevel: ConfidenceLevel;
  severity: string;
  locations: PatternLocation[];
  outliers: PatternLocation[];
  metadata: PatternMetadata;
}
```

### Configuration

```typescript
interface DataLakeConfig {
  rootDir: string;                              // .drift/ directory path
  enableSharding: boolean;                      // Default: true
  shardThreshold: number;                       // Items before sharding activates
  enableViews: boolean;                         // Default: true
  enableIndexes: boolean;                       // Default: true
  autoRebuild: boolean;                         // Auto-rebuild stale views
  viewTtlMs: number;                            // View freshness TTL
}
```

### Query Types

```typescript
interface PaginationOptions {
  limit?: number;                               // Page size
  cursor?: string;                              // Keyset cursor
  offset?: number;                              // OFFSET-based (deprecated)
}

interface PaginatedResult<T> {
  items: T[];
  total: number;
  hasMore: boolean;
  nextCursor?: string;
  executionTime: number;                        // ms
  source: 'view' | 'index' | 'shard' | 'raw';  // Which data path was used
}

interface QueryStats {
  viewHits: number;
  indexHits: number;
  rawHits: number;
  shardHits: number;
  avgResponseTime: number;                      // ms
}
```

---

## Capabilities

### What the Data Lake Can Do Today

1. **Instant status response** — StatusView pre-computes health score, pattern counts, issue counts, security risk level. Single file read for `drift_status`.
2. **Selective loading by dimension** — Load only auth patterns (one shard), only one file's call graph (one shard), only one table's security data (one shard).
3. **O(1) index lookups** — File → patterns, category → patterns, table → access points, entry point → reachable data. No full-data scan needed.
4. **Intelligent query routing** — QueryEngine automatically selects the fastest data source based on freshness and availability.
5. **Incremental materialization** — Only stale views are rebuilt after scans. Fresh views are untouched.
6. **Content-hash change detection** — SHA-256 file hashing enables skip-unchanged-files optimization for incremental scans.
7. **Cross-domain statistics** — ManifestStore aggregates stats from patterns, security, call graph, contracts, and DNA into a single quick-load index.
8. **Security risk assessment** — Per-table and overall risk scoring based on sensitivity, access patterns, raw SQL usage, and violation counts.
9. **Code example extraction** — ExamplesStore extracts, scores, and caches code examples from pattern locations with configurable quality thresholds.
10. **Entry point classification** — CallGraphShardStore infers entry point types (api, handler, controller, route) from function metadata.
11. **Pagination with source tracking** — Every paginated result includes which data path was used and execution time.
12. **View freshness lifecycle** — Granular staleness tracking with accumulated invalidation reasons.

### What the Data Lake Cannot Do (Limitations)

1. **No transactional guarantees** — JSON file writes can partially fail, leaving views/indexes inconsistent with shards.
2. **No concurrent access safety** — Advisory file locks only. Race conditions when MCP reads during scan writes.
3. **No query optimization** — All filtering is in-memory after full JSON load. No B-tree indexes, no query planner.
4. **No cross-shard JOINs** — Querying patterns + security data requires loading both shard sets independently.
5. **No partial view updates** — Materialization rebuilds entire views, even if only one pattern changed.
6. **No compression** — JSON files stored as plain text. Larger disk footprint than necessary.
7. **No retention policies** — Views, indexes, and shards grow unbounded over time.
8. **No persistent telemetry** — QueryStats is in-memory only, lost on process restart.
9. **No data validation** — Corrupt JSON silently produces wrong results. No integrity checks.
10. **No write batching** — Each shard write is a separate file I/O operation.
11. **Process-local caching** — In-memory caches are not shared between CLI and MCP processes.
12. **Version control noise** — 30-80 JSON files in `.drift/` pollute git diffs.
13. **Cold cache penalty** — First query after process start requires full file I/O for cache warming.
14. **No streaming** — Large shards must be fully loaded into memory before filtering.

---

## Integration Points

| Upstream Producer | What It Provides | Lake Component |
|-------------------|-----------------|----------------|
| 03-detectors | Discovered patterns | PatternShardStore, ViewStore (StatusView, PatternIndexView) |
| 04-call-graph | Function relationships, entry points | CallGraphShardStore |
| 05-analyzers | Security boundaries, sensitive fields | SecurityShardStore |
| 13-advanced | DNA profile, mutations | ManifestStore (DNAStats) |
| 20-contracts | Contract verification results | ManifestStore (ContractStats) |
| 25-services | Scan completion trigger | ViewMaterializer |

| Downstream Consumer | What It Reads | Lake Component |
|---------------------|--------------|----------------|
| 07-mcp | drift_status, drift_patterns_list, drift_file_patterns, drift_security_summary, drift_code_examples | QueryEngine |
| 09-quality-gates | Health score, pattern compliance baseline | ViewStore (StatusView), ManifestStore |
| 10-cli | drift status, drift patterns, drift security | QueryEngine |
| 11-ide | Dashboard health overview, pattern explorer | QueryEngine |
| 21-security | Security posture overview | ViewStore (SecuritySummaryView) |
| 26-workspace | Context loading, workspace stats | ManifestStore |

---

## V2 Migration Status

### What Gets Eliminated (~4,570 lines)
- All 11 TypeScript source files in `packages/core/src/lake/`
- All JSON files in `.drift/views/`, `.drift/indexes/`, `.drift/lake/`
- `.drift/manifest.json`
- In-memory caching layer (replaced by SQLite page cache)
- JSON serialization/deserialization overhead
- File I/O for every read/write operation
- SHA-256 shard checksumming (replaced by SQLite row versioning)

### What Gets Preserved (Concepts → SQLite)

| V1 Concept | V2 Implementation |
|-----------|-------------------|
| ManifestStore (quick-load stats) | `materialized_status` table + cached Rust query |
| StatusView | `v_status` SQL view or materialized table |
| PatternIndexView | `v_pattern_index` SQL view |
| SecuritySummaryView | `materialized_security` table |
| TrendsView | `v_trends` SQL view over `health_trends` table |
| FileIndex | `idx_pattern_locations_file` SQL index |
| CategoryIndex | `idx_patterns_category` SQL index |
| TableIndex | SQL JOIN on `data_access_points` |
| EntryPointIndex | SQL JOIN on `functions` + `call_edges` + `data_access` |
| PatternShardStore | `SELECT * FROM patterns WHERE category = ?` |
| CallGraphShardStore | `SELECT * FROM functions WHERE file = ?` |
| SecurityShardStore | `SELECT * FROM data_access_points WHERE table_name = ?` |
| ExamplesStore | `SELECT * FROM pattern_examples WHERE pattern_id = ?` |
| QueryEngine routing | SQLite query planner (automatic) |
| ViewMaterializer | Explicit `REFRESH` calls + optional triggers |
| Content-hash detection | `file_metadata` table with content hashes |
| Pagination with cursors | Keyset pagination via `WHERE id > ? ORDER BY id LIMIT ?` |

### Ownership Transfer
- **Rust Core** owns all materialized tables and refresh logic
- **TypeScript** gets read-only access via NAPI bindings
- **SQLite query planner** replaces manual query routing
- **SQLite page cache** replaces in-memory JSON caches
- **SQLite WAL mode** replaces advisory file locks for concurrency

---

## Open Questions

1. **Materialized view refresh strategy** — SQLite doesn't natively support materialized views. Should v2 use regular tables with explicit refresh (more control, more code) or regular views (automatic, potentially slower for complex aggregations)?

2. **Query routing necessity** — Does the SQLite query planner fully replace manual routing, or are there cases where explicit routing to materialized tables vs. computed views is still needed for performance?

3. **Telemetry persistence** — Should query performance stats (hit counts, response times) be persisted to SQLite for long-term monitoring, or is in-memory tracking sufficient?

4. **Retention policies** — What retention strategy should v2 use for trend data, scan history, and health snapshots? Time-based (90 days)? Count-based (last 100 scans)? Size-based?

5. **Cross-database materialization** — Should materialized views that combine drift.db and cortex.db data (e.g., patterns linked to memories) use ATTACH DATABASE or application-level JOINs?

6. **Cache warming strategy** — Should v2 pre-warm the SQLite page cache on startup (e.g., `SELECT * FROM materialized_status`) or rely on lazy loading?

7. **Incremental materialization granularity** — Should materialized tables be refreshed per-domain (only pattern stats when patterns change) or always fully refreshed after scans?
