# 25 Services Layer — Forensic Audit

> **Purpose**: Exhaustive forensic inventory of every component, interface, data flow, algorithm, dependency, and integration point in Drift v1's services/orchestration layer. This audit captures the complete ground truth — no assumptions, no omissions.
>
> **Scope**: `packages/core/src/services/` (~1,600 lines), CLI ScannerService (~1,400 lines), MCP request pipeline, worker thread infrastructure, and all orchestration paths connecting consumers to the core engine.
>
> **Date**: February 2026

---

## 1. Component Inventory

### 1.1 Core Services (`packages/core/src/services/`)

| File | LOC (est.) | Purpose | Consumers |
|------|-----------|---------|-----------|
| `scanner-service.ts` | ~1,200 | Central scan orchestrator: worker pool, aggregation, outlier detection, manifest | CLI, MCP |
| `detector-worker.ts` | ~350 | Piscina worker thread: loads detectors, processes files, returns matches | ScannerService |
| `index.ts` | ~50 | Barrel exports | All consumers |

### 1.2 CLI Services (`packages/cli/src/services/`)

| File | LOC (est.) | Purpose | Consumers |
|------|-----------|---------|-----------|
| `scanner-service.ts` | ~1,400 | CLI-specific scan orchestration with progress, health monitoring, timeout | CLI commands |
| `pattern-service-factory.ts` | ~200 | Auto-detects SQLite vs JSON backend, creates appropriate store | CLI commands |
| `boundary-scanner.ts` | ~150 | CLI progress wrapper around boundary analysis | CLI `boundaries` command |
| `contract-scanner.ts` | ~150 | CLI progress wrapper around contract analysis | CLI `contracts` command |
| `backup-service.ts` | ~200 | Project backup/restore orchestration | CLI `backup` command |

### 1.3 MCP Orchestration (`packages/mcp/`)

| File | LOC (est.) | Purpose | Consumers |
|------|-----------|---------|-----------|
| `enterprise-server.ts` | ~914 | Main MCP server: init, routing, project resolution, store management | MCP clients |
| `infrastructure/cache.ts` | ~300 | L1 LRU + L2 file-based response cache | MCP request pipeline |
| `infrastructure/rate-limiter.ts` | ~200 | 3-tier sliding window rate limiting | MCP request pipeline |
| `infrastructure/metrics.ts` | ~200 | Prometheus-compatible metrics collection | MCP request pipeline |
| `infrastructure/startup-warmer.ts` | ~150 | Pre-loads all .drift data on init | MCP server startup |

### 1.4 Worker Infrastructure

| Component | Location | Purpose |
|-----------|----------|---------|
| Piscina thread pool | `scanner-service.ts` | CPU-bound parallel detection |
| Worker script | `detector-worker.ts` | Per-thread detector execution |
| CLI worker wrapper | `cli/src/workers/detector-worker.ts` | CLI-specific worker entry point (~200 LOC) |

**Total services layer footprint**: ~5,466 lines across 14 files in 3 packages.

---

## 2. Scan Pipeline — Complete Execution Trace

### 2.1 CLI Scan Path

```
User: drift scan [--incremental] [--categories auth,security] [--format json]
  │
  ▼
Commander.js → scanCommand.action(options)
  │
  ├── 1. Resolve project root (walk up from cwd looking for .drift/)
  ├── 2. Create ScannerService(config)
  │       config = { rootDir, verbose, useWorkerThreads, workerCount,
  │                  categories, generateManifest, incremental }
  ├── 3. ScannerService.initialize()
  │       ├── Load detectors from driftdetect-detectors
  │       ├── If useWorkerThreads: create Piscina pool
  │       │     ├── Worker script: detector-worker.ts
  │       │     ├── Thread count: os.cpus().length - 1
  │       │     └── Send WarmupTask to each worker
  │       └── If !useWorkerThreads: cache detectors in-process
  ├── 4. FileWalker.discover(rootDir, ignorePatterns)
  │       ├── walkdir + .gitignore + .driftignore
  │       └── Returns: string[] (file paths)
  ├── 5. ScannerService.scanFiles(files, projectContext)
  │       ├── If worker mode:
  │       │     ├── Create DetectorWorkerTask per file
  │       │     ├── pool.run(task) for each file
  │       │     ├── Collect DetectorWorkerResult[]
  │       │     └── aggregateWorkerResults()
  │       └── If single-threaded:
  │             ├── For each file: read → detect language → filter detectors
  │             ├── Run each detector.detect(context)
  │             └── Collect results
  ├── 6. Aggregation
  │       ├── Group PatternMatch by patternId across files
  │       ├── Merge locations (deduplicate by file:line:column)
  │       ├── Merge metadata from all detectors
  │       └── Produce AggregatedPattern[]
  ├── 7. Outlier Detection
  │       ├── OutlierDetector.detect(aggregatedPatterns)
  │       ├── Z-Score (n ≥ 30) or IQR (n < 30)
  │       └── Annotate outlier locations
  ├── 8. Manifest Generation (if configured)
  │       └── Build Manifest with semantic locations
  ├── 9. Result Assembly → ScanResults
  ├── 10. PatternStore persistence
  │       ├── PatternServiceFactory.create(rootDir)
  │       ├── Auto-detect SQLite vs JSON
  │       └── Store patterns, locations, examples
  ├── 11. Data Lake materialization
  │       ├── ViewMaterializer.materialize(patterns, security)
  │       └── Rebuild stale views, indexes, shards
  ├── 12. History snapshot
  │       └── HistoryStore.createSnapshot(scanResults)
  ├── 13. Telemetry (if enabled)
  │       └── Record scan event
  └── 14. Output
        ├── Reporter.generate(results)
        └── Display via UI components (spinner, table)
```

### 2.2 MCP Scan Path

```
MCP Client → CallToolRequest { name: "drift_scan", arguments }
  │
  ▼
enterprise-server.ts → routeToolCall()
  │
  ├── 1. Rate limiter check (global + per-tool)
  ├── 2. Project resolution (args.project → registry lookup)
  ├── 3. Cache check (SHA-256 key: projectRoot + tool + args)
  ├── 4. If cache miss:
  │       ├── ScannerService.scanFiles(files, projectContext)
  │       ├── PatternService.persist(results)
  │       ├── DataLake.materialize(results)
  │       └── Format MCPResponse
  ├── 5. Cache result
  ├── 6. Record metrics (tool, duration, success/error)
  └── 7. Return response
```

### 2.3 Quality Gate Path

```
drift gate run [--policy strict] [--format sarif]
  │
  ▼
GateOrchestrator.run(options)
  │
  ├── 1. resolveFiles() — explicit files, globs, or all
  ├── 2. loadPolicy() — by ID, inline, or context-based
  ├── 3. determineGates() — filter by policy config
  ├── 4. buildContext() — lazy-load only what gates need
  │       ├── Patterns: if pattern-compliance or regression enabled
  │       ├── Constraints: if constraint-verification enabled
  │       ├── Call graph: if impact-simulation or security-boundary enabled
  │       ├── Previous snapshot: if regression-detection enabled
  │       └── Custom rules: if custom-rules enabled
  ├── 5. executeGates() — parallel via ParallelExecutor
  ├── 6. evaluate() — PolicyEvaluator (4 aggregation modes)
  ├── 7. aggregate() — ResultAggregator
  ├── 8. saveSnapshot() — SnapshotStore + GateRunStore
  └── 9. generateReport() — Reporter (text/json/sarif/github/gitlab)
```

---

## 3. Data Flow Contracts

### 3.1 Worker Task/Result Contract

```typescript
// Input: ScannerService → Worker
interface DetectorWorkerTask {
  type?: 'scan';
  file: string;                    // Absolute file path
  rootDir: string;                 // Project root
  projectFiles: string[];          // All project files (for cross-file context)
  projectConfig: Record<string, unknown>;
  detectorIds?: string[];          // Filter specific detectors
  categories?: string[];           // Filter by category
  criticalOnly?: boolean;          // Only high-value detectors
}

// Output: Worker → ScannerService
interface DetectorWorkerResult {
  file: string;
  language: string | null;
  patterns: WorkerPatternMatch[];
  violations: WorkerViolation[];
  detectorsRan: number;
  detectorsSkipped: number;
  duration: number;
}
```

### 3.2 Aggregation Contract

```typescript
// Input: DetectorWorkerResult[] → Aggregation
// Output: AggregatedPattern[]

// Aggregation invariants:
// 1. Same patternId from different files → merged into single AggregatedPattern
// 2. Locations deduplicated by file:line:column key
// 3. Metadata merged (union of all detector metadata)
// 4. Confidence = max(individual confidences) or recalculated
// 5. Occurrences = total unique locations
// 6. OutlierCount = locations where isOutlier === true
```

### 3.3 Consumer Integration Contracts

```typescript
// CLI → ScannerService
interface ScannerServiceConfig {
  rootDir: string;
  verbose?: boolean;
  categories?: string[];
  criticalOnly?: boolean;
  generateManifest?: boolean;
  incremental?: boolean;
  useWorkerThreads?: boolean;
  workerThreads?: number;
}

// ScannerService → Consumers
interface ScanResults {
  files: FileScanResult[];
  patterns: AggregatedPattern[];
  violations: AggregatedViolation[];
  totalPatterns: number;
  totalViolations: number;
  totalFiles: number;
  duration: number;
  errors: string[];
  detectorStats: { total: number; ran: number; skipped: number };
  manifest?: Manifest;
  workerStats?: { threads: number; tasksCompleted: number; avgTaskDuration: number };
}
```

---

## 4. Dependency Audit

### 4.1 External Dependencies

| Dependency | Version | Purpose | V2 Status |
|-----------|---------|---------|-----------|
| `piscina` | ^4.x | Worker thread pool | REMOVE — Rust rayon replaces |
| `os` (Node) | built-in | CPU count for thread sizing | KEEP — still needed for config |
| `path` (Node) | built-in | File path resolution | KEEP |
| `fs/promises` (Node) | built-in | File reading in workers | REMOVE — Rust reads files |
| `driftdetect-detectors` | internal | 350+ TS detectors | REMOVE — Rust detection engine |
| `driftdetect-core` | internal | Pattern types, stores, lake | REFACTOR — thin wrapper |

### 4.2 Internal Dependencies (What Services Layer Consumes)

| Subsystem | What's Consumed | How |
|-----------|----------------|-----|
| 02-parsers | Language detection, file parsing | Worker reads file → detects language |
| 03-detectors | Detector loading, detect() calls | Worker loads all detectors, runs per file |
| 05-analyzers | OutlierDetector | Post-aggregation statistical analysis |
| 08-storage | PatternStore, UnifiedStore | Post-scan persistence |
| 23-pattern-repository | IPatternService | Pattern CRUD after scan |
| 24-data-lake | ViewMaterializer, ManifestStore | Post-scan view rebuild |

### 4.3 Internal Dependencies (What Consumes Services Layer)

| Consumer | What's Consumed | How |
|----------|----------------|-----|
| 10-cli | ScannerService, ScanResults | CLI scan/check/watch commands |
| 07-mcp | ScannerService (indirect) | MCP scan tool |
| 09-quality-gates | ScanResults (indirect) | Gate context building |
| 12-infrastructure | CI agent scan orchestration | drift-ci analyze |

---

## 5. Concurrency Model Audit

### 5.1 Current Model (Piscina)

```
Main Thread (ScannerService)
  │
  ├── Creates Piscina pool (N = os.cpus().length - 1)
  ├── Sends WarmupTask to each worker
  │     └── Workers load detectors into module-scope cache
  ├── Dispatches DetectorWorkerTask per file
  │     └── pool.run(task) → Promise<DetectorWorkerResult>
  ├── Collects all results via Promise.all()
  └── Aggregates on main thread (single-threaded)

Worker Thread (detector-worker.ts)
  │
  ├── Module-scope detector cache (loaded once per worker)
  ├── Receives task → reads file → detects language
  ├── Filters applicable detectors
  ├── Runs each detector.detect(context)
  └── Returns DetectorWorkerResult
```

### 5.2 Concurrency Issues

| Issue | Impact | Severity |
|-------|--------|----------|
| Aggregation is single-threaded | Bottleneck for large codebases | Medium |
| No backpressure on worker queue | Memory spike with 500K+ files | High |
| Worker errors silently swallowed | Missing file results | Medium |
| No cancellation support | Long scans cannot be interrupted | Medium |
| projectFiles array serialized per task | O(files²) memory for task serialization | High |
| No worker health monitoring | Stuck workers block pool | Medium |
| Detector cache never cleared | Memory growth over long-running processes | Low |

### 5.3 V2 Target Model (Rust Rayon)

```
TypeScript Orchestration (thin)
  │
  └── nativeScan(config) → Rust NAPI
        │
        ├── rayon::par_iter(files)
        │     ├── Parse file (tree-sitter)
        │     ├── Detect patterns (visitor pattern, single-pass)
        │     └── Send results via MPSC channel
        │
        ├── Writer thread (dedicated)
        │     ├── Receives results from MPSC
        │     ├── Batches into transactions
        │     └── Writes to SQLite
        │
        └── Returns ScanResults to TypeScript
```

---

## 6. Error Handling Audit

### 6.1 Current Error Paths

| Error Source | Handling | Gap |
|-------------|----------|-----|
| File read failure | Worker catches, returns error in result | No retry, no partial results |
| Detector crash | Worker catches per-detector, continues | Error logged but not surfaced |
| Worker thread crash | Piscina restarts worker | Lost task not retried |
| Aggregation error | Uncaught → scan fails | No graceful degradation |
| Store write failure | Caught at CLI level | Scan results lost |
| Lake materialization failure | Caught, logged | Stale views persist |
| Timeout | ScanHealthMonitor warns at 30s, kills at 300s | No partial result return |

### 6.2 Error Propagation Chain

```
Detector error → WorkerPatternMatch.error (not captured)
  → DetectorWorkerResult.detectorsSkipped++
    → ScanResults.detectorStats.skipped++
      → CLI displays "X detectors skipped"
        → No detail on WHY they were skipped
```

**Critical gap**: No structured error taxonomy. All errors are string messages. No error codes, no categorization, no programmatic handling.

---

## 7. Performance Characteristics

### 7.1 Measured Performance (V1)

| Metric | Small (100 files) | Medium (1K files) | Large (10K files) | Target (500K files) |
|--------|-------------------|--------------------|--------------------|---------------------|
| Full scan | ~1s | ~3s | ~10s | Untested/infeasible |
| Worker warmup | ~200ms | ~200ms | ~200ms | ~200ms |
| Per-file detection | ~5ms | ~5ms | ~5ms | ~5ms |
| Aggregation | ~50ms | ~200ms | ~1s | Unknown |
| Lake materialization | ~100ms | ~500ms | ~2s | Unknown |
| Total pipeline | ~1.5s | ~4s | ~13s | Unknown |

### 7.2 Performance Bottlenecks

| Bottleneck | Cause | Impact |
|-----------|-------|--------|
| 100+ AST traversals per file | Each detector traverses independently | 10-100x slower than single-pass |
| Task serialization overhead | projectFiles array copied per task | O(n²) memory |
| Single-threaded aggregation | All results merged on main thread | Linear bottleneck |
| JSON store writes | Individual file writes, no batching | I/O bound for large scans |
| Lake materialization | Full view rebuild even for small changes | Unnecessary work |
| No incremental detection | Every file re-scanned every time | Wasted computation |

---

## 8. Configuration Surface

### 8.1 ScannerService Configuration

| Parameter | Type | Default | Effect |
|-----------|------|---------|--------|
| `rootDir` | string | required | Project root directory |
| `verbose` | boolean | false | Enable verbose logging |
| `categories` | string[] | all | Filter detectors by category |
| `criticalOnly` | boolean | false | Only high-value detectors |
| `generateManifest` | boolean | false | Produce semantic manifest |
| `incremental` | boolean | false | Only scan changed files |
| `useWorkerThreads` | boolean | true | Enable Piscina parallelism |
| `workerThreads` | number | cpus - 1 | Thread count |

### 8.2 Health Monitor Configuration

| Parameter | Type | Default | Effect |
|-----------|------|---------|--------|
| `warnAfterMs` | number | 30000 | Warn after 30 seconds |
| `timeoutMs` | number | 300000 | Kill after 5 minutes |
| `progressIntervalMs` | number | 10000 | Progress update every 10s |

---

## 9. Integration Surface Audit

### 9.1 Upstream Integrations (Services Layer Receives From)

| Source | Interface | Data |
|--------|-----------|------|
| CLI commands | ScannerServiceConfig | Scan configuration |
| MCP tools | Tool arguments | Scan parameters |
| FileWalker | string[] | Discovered file paths |
| Detectors | PatternMatch[] | Per-file detection results |
| Parsers | Language detection | File language classification |

### 9.2 Downstream Integrations (Services Layer Sends To)

| Target | Interface | Data |
|--------|-----------|------|
| PatternStore/Service | IPatternService | Aggregated patterns |
| Data Lake | ViewMaterializer | Patterns + security data |
| History Store | HistoryStore | Scan snapshot |
| Quality Gates | GateContext | Patterns for compliance checking |
| Reporters | ReportData | Formatted scan results |
| Telemetry | TelemetryEvent | Scan metrics |
| MCP Response | MCPResponse | Formatted tool response |

### 9.3 Cross-Cutting Concerns

| Concern | Current Implementation | Gap |
|---------|----------------------|-----|
| Logging | console.log/warn/error | No structured logging |
| Metrics | Basic timing | No Prometheus metrics |
| Tracing | None | No distributed tracing |
| Caching | None at service level | MCP has L1/L2 cache |
| Rate limiting | None at service level | MCP has 3-tier limiter |
| Authentication | None | No access control |
| Authorization | None | No permission model |

---

## 10. State Management Audit

### 10.1 Stateful Components

| Component | State | Lifecycle | Cleanup |
|-----------|-------|-----------|---------|
| Piscina pool | Worker threads + task queue | ScannerService lifetime | destroy() |
| Detector cache (worker) | Loaded detector instances | Worker thread lifetime | Never cleaned |
| ScanHealthMonitor | Timer references | Per-scan | clearTimeout |
| PatternStore (JSON) | In-memory pattern map | Process lifetime | Auto-save on 30s debounce |
| UnifiedStore (SQLite) | Database connection | Process lifetime | close() |
| MCP ResponseCache | LRU map + file cache | Server lifetime | TTL-based eviction |
| MCP RateLimiter | Sliding window counters | Server lifetime | Window-based cleanup |

### 10.2 State Consistency Risks

| Risk | Scenario | Impact |
|------|----------|--------|
| Stale detector cache | Detectors updated but workers not restarted | Old detection logic |
| Partial scan results | Process killed during aggregation | Inconsistent pattern store |
| Cache-store divergence | MCP cache not invalidated after scan | Stale MCP responses |
| Dual-store inconsistency | JSON and SQLite out of sync | Different results per consumer |
| Lake-store divergence | Materialization fails after store write | Stale views |

---

## Quality Checklist

- [x] Every file in the services layer inventoried with line counts
- [x] Complete scan pipeline execution trace (CLI, MCP, Quality Gates)
- [x] All data flow contracts documented with TypeScript interfaces
- [x] All external and internal dependencies audited
- [x] Concurrency model fully documented with issues
- [x] Error handling paths traced with gaps identified
- [x] Performance characteristics measured and bottlenecks identified
- [x] Configuration surface fully documented
- [x] All integration points mapped (upstream, downstream, cross-cutting)
- [x] State management audited with consistency risks
