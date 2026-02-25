# 25 Services Layer — Master Recap

> **Purpose**: Complete synthesis of Drift v1's services/orchestration layer — the connective tissue between consumers (CLI, MCP, Quality Gates, IDE) and the core engine (parsers, detectors, analyzers, storage). This document captures every architectural decision, data flow, algorithm, integration point, and limitation in one authoritative reference for the v2 enterprise greenfield rebuild.
>
> **Scope**: ~5,500 lines across 14 files in 3 packages (core, cli, mcp), plus all orchestration paths, worker infrastructure, and consumer integration patterns.
>
> **Date**: February 2026

---

## 1. Executive Summary

The Services Layer is Drift's orchestration backbone — the system that coordinates scanning, detection, aggregation, persistence, materialization, and result delivery across all consumer surfaces. In v1, this layer evolved into a distributed orchestration system spanning three packages (`core/src/services/`, `cli/src/services/`, `mcp/`) with overlapping responsibilities, duplicated logic, and no unified service contract.

The layer's primary artifact is `ScannerService` (~1,200-1,400 LOC depending on package), which manages a Piscina worker thread pool for CPU-bound parallel detection, aggregates results across files, runs statistical outlier detection, and feeds results into the persistence and materialization pipeline. The MCP server adds enterprise infrastructure (caching, rate limiting, metrics, project resolution) on top of the same core scan pipeline.

**V1 Reality**: The services layer is a thin but critical orchestration shim. It doesn't contain business logic — it coordinates subsystems that do. Its value is in the pipeline sequencing, parallelism management, result aggregation, and consumer-specific formatting. Its weakness is the lack of a unified service contract, no incremental computation, no structured error handling, and tight coupling to the Piscina worker model that v2 eliminates entirely.

**V2 Vision**: The services layer becomes a ~100-line TypeScript wrapper around Rust NAPI calls. All computation (scanning, parsing, detection, aggregation, storage) moves to Rust. TypeScript retains orchestration concerns: argument parsing, progress reporting, output formatting, and consumer-specific adaptation (CLI spinners, MCP response envelopes, quality gate policy evaluation).

---

## 2. Architecture

### 2.1 V1 Architecture (Current)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CONSUMER LAYER                                       │
│                                                                              │
│  CLI Commands          MCP Server              Quality Gates    IDE/LSP      │
│  (drift scan,          (enterprise-server.ts)   (GateOrchestrator)           │
│   drift check,         87+ tools               6 gates                      │
│   drift watch)         Rate limiting            Policy engine               │
│                        Caching                  Reporters                    │
│                        Metrics                                              │
├──────────┬─────────────┬──────────────┬─────────────────────────────────────┤
│          │             │              │                                      │
│  CLI     │  MCP        │  Gate        │  Shared                             │
│  Scanner │  Request    │  Context     │  Infrastructure                     │
│  Service │  Pipeline   │  Builder     │                                     │
│  (~1400) │  (~914)     │  (~200)      │  PatternServiceFactory              │
│          │             │              │  BackupService                       │
│          │             │              │  BoundaryScanner                     │
│          │             │              │  ContractScanner                     │
├──────────┴─────────────┴──────────────┴─────────────────────────────────────┤
│                         CORE SCANNER SERVICE (~1200 LOC)                     │
│                                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │ Worker Pool  │  │ Aggregation  │  │   Outlier    │  │  Manifest    │    │
│  │ Management   │  │   Engine     │  │  Detection   │  │ Generation   │    │
│  │              │  │              │  │              │  │              │    │
│  │ Piscina      │  │ Group by     │  │ Z-Score      │  │ Semantic     │    │
│  │ Warmup       │  │ patternId    │  │ IQR          │  │ locations    │    │
│  │ Dispatch     │  │ Merge locs   │  │ Sensitivity  │  │              │    │
│  │ Collect      │  │ Dedup        │  │ adjustment   │  │              │    │
│  └──────┬───────┘  └──────────────┘  └──────────────┘  └──────────────┘    │
│         │                                                                    │
│  ┌──────▼───────────────────────────────────────────────────────────────┐    │
│  │                    DETECTOR WORKERS (Piscina threads)                 │    │
│  │                                                                      │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                 │    │
│  │  │  Worker 1   │  │  Worker 2   │  │  Worker N   │                 │    │
│  │  │             │  │             │  │             │                 │    │
│  │  │ Load dets   │  │ Load dets   │  │ Load dets   │                 │    │
│  │  │ Read file   │  │ Read file   │  │ Read file   │                 │    │
│  │  │ Detect lang │  │ Detect lang │  │ Detect lang │                 │    │
│  │  │ Run dets    │  │ Run dets    │  │ Run dets    │                 │    │
│  │  │ Return      │  │ Return      │  │ Return      │                 │    │
│  │  └─────────────┘  └─────────────┘  └─────────────┘                 │    │
│  └──────────────────────────────────────────────────────────────────────┘    │
├─────────────────────────────────────────────────────────────────────────────┤
│                         PERSISTENCE PIPELINE                                 │
│                                                                              │
│  PatternStore ──→ UnifiedStore ──→ DataLake ──→ HistoryStore                │
│  (JSON/SQLite)    (SQLite)         (Views/Shards) (Snapshots)               │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 V2 Target Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CONSUMER LAYER (TypeScript — stays)                  │
│                                                                              │
│  CLI Commands          MCP Server              Quality Gates    IDE/LSP      │
│  (thin wrappers)       (thin orchestration)    (policy engine)              │
├─────────────────────────────────────────────────────────────────────────────┤
│                         ORCHESTRATION SERVICE (~100 LOC TypeScript)          │
│                                                                              │
│  parse args → call Rust NAPI → format output                                │
│  progress reporting, cancellation, timeout                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                         RUST NAPI BOUNDARY                                   │
│                                                                              │
│  nativeScan(config) → ScanResults                                           │
│  nativeAnalyze(config, analyses[]) → AnalysisResults                        │
│  nativeQuery(query) → QueryResults                                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                         RUST ENGINE (all computation)                        │
│                                                                              │
│  Scanner ──→ Parser ──→ Detection Engine ──→ Aggregation ──→ Storage        │
│  (walkdir     (tree-     (single-pass         (parallel       (SQLite       │
│   + rayon)    sitter)     visitor)             merge)          WAL)          │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Core Components

### 3.1 ScannerService (Core — ~1,200 LOC)

The central orchestrator. Manages the complete scan lifecycle from worker pool creation through result assembly.

**Lifecycle**:
1. `constructor(config: ScannerServiceConfig)` — stores configuration
2. `initialize()` — loads detectors, creates worker pool, warms up workers
3. `scanFiles(files: string[], context: ProjectContext)` — executes scan pipeline
4. `destroy()` — shuts down worker pool, releases resources

**Worker Pool Management**:
- Creates Piscina pool with `detector-worker.ts` as worker script
- Thread count: `os.cpus().length - 1` (configurable via `workerThreads`)
- Warmup phase: sends `WarmupTask` to each worker, waits for all to complete
- Each worker loads all detectors once (cached in module scope)
- Graceful fallback to single-threaded mode if Piscina unavailable

**Aggregation Engine**:
- Groups `WorkerPatternMatch[]` by `patternId` across all files
- Merges locations with deduplication via `locationKey(file:line:column)`
- Semantic deduplication via `semanticLocationKey` (includes function/class context)
- Merges metadata from all detectors (union strategy)
- Calculates per-pattern occurrence counts and outlier counts

**Outlier Detection**:
- Post-aggregation statistical analysis on `AggregatedPattern[]`
- Z-Score method for n ≥ 30 samples: `|z| > threshold` (default 2.0)
- IQR method for n < 30 samples: value outside `Q1 - 1.5×IQR .. Q3 + 1.5×IQR`
- Sensitivity adjustment: `threshold × (1 + (1 - sensitivity))`
- Annotates outlier locations with `isOutlier: true` and `outlierReason`

**Configuration**:
```typescript
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
```

### 3.2 DetectorWorker (Core — ~350 LOC)

Worker thread entry point running in Piscina threads.

**Two Task Types**:
1. `WarmupTask` — preloads detectors, returns count and duration
2. `DetectorWorkerTask` — processes single file through all applicable detectors

**Processing Flow**:
```
Receive task
  → If warmup: load detectors from driftdetect-detectors, cache in module scope
  → If scan:
      1. Read file content from disk (fs.readFileSync)
      2. Detect language from file extension (25+ extensions supported)
      3. Load applicable detectors (from cache or fresh)
      4. Filter by categories/criticalOnly if specified
      5. Build DetectionContext { content, language, filePath, projectFiles, config }
      6. Run each detector.detect(context) → PatternMatch[]
      7. Collect all matches and violations
      8. Return DetectorWorkerResult
```

**Detector Caching**: Detectors loaded once per worker via `createAllDetectorsArray()`. Cached in module-scope variable. Subsequent tasks reuse same instances. Cache never cleared (memory growth risk in long-running processes).

**Language Detection**: Static map of file extension → language identifier. Supports: TypeScript (.ts, .tsx), JavaScript (.js, .jsx, .mjs, .cjs), Python (.py), Java (.java), C# (.cs), PHP (.php), Go (.go), Rust (.rs), C (.c, .h), C++ (.cpp, .hpp, .cc), Swift (.swift), Kotlin (.kt), Scala (.scala), CSS (.css), SCSS (.scss), LESS (.less), HTML (.html, .htm), Vue (.vue), Svelte (.svelte), JSON (.json), YAML (.yml, .yaml), Markdown (.md), SQL (.sql).

**Metadata Preservation**: All metadata from detectors preserved end-to-end:
- `endLine`/`endColumn` for full range highlighting in IDE
- `isOutlier`/`outlierReason` for deviation tracking
- `matchedText` for context display
- Custom `metadata` for detector-specific data (auth types, route info, etc.)

### 3.3 CLI ScannerService (~1,400 LOC)

Extended version of core ScannerService with CLI-specific concerns.

**Additional Features**:
- `ScanHealthMonitor`: warns after 30s, kills after 300s, progress every 10s
- Progress reporting via `ora` spinner
- Verbose mode with per-file timing
- `--incremental` flag support (content-hash based skip)
- `--ci` mode (JSON output, no interactive prompts)

**Post-Scan Pipeline** (CLI-specific):
```
ScanResults
  → PatternServiceFactory.create(rootDir) → PatternStore/UnifiedStore
  → ViewMaterializer.materialize(patterns, security)
  → HistoryStore.createSnapshot(results)
  → Telemetry.record(scanEvent)
  → Reporter.generate(results)
```

### 3.4 MCP Enterprise Server (~914 LOC)

The MCP server's orchestration layer — manages 9 stores, 87+ tools, request routing, caching, rate limiting, and multi-project resolution.

**Initialization Sequence (10 Steps)**:
1. Check storage backend (SQLite vs JSON)
2. Create PatternStore (async factory, auto-detects)
3. Create UnifiedStore (SQLite-backed)
4. Create legacy stores (DNA, Boundary, Contract, CallGraph, Env)
5. Create IPatternService wrapper
6. Create DataLake for optimized queries
7. Create ResponseCache (L1 LRU + L2 file)
8. Initialize Cortex (if cortex.db exists)
9. Warm up stores (async, non-blocking)
10. Build missing data in background (e.g., call graph)

**Request Pipeline (11 Steps)**:
1. Client connects (stdio or HTTP/SSE)
2. Receive CallToolRequest { name, arguments }
3. Rate limiter check (global: 100/min, expensive: 10/min, per-tool: configurable)
4. Project resolution (args.project → registry → fallback)
5. If different project: create temporary stores
6. Cache check (SHA-256 key: projectRoot + tool + args)
7. Route to category handler (switch cascade)
8. Handler executes, returns MCPResponse
9. Cache result (skip for mutations)
10. Record metrics (tool, duration, success/error)
11. Return response

**Dual-Path Pattern**: 10 tools have two implementations (legacy JSON + new SQLite). The `patternService` flag determines which path executes.

### 3.5 Quality Gate Orchestrator

The gate system's service layer — coordinates 6 specialized gates through a configurable policy engine.

**Execution Pipeline (9 Steps)**:
1. `resolveFiles()` — explicit files, glob patterns, or all
2. `loadPolicy()` — by ID, inline, or context-based matching
3. `determineGates()` — filter by policy configuration
4. `buildContext()` — lazy-load only what active gates need
5. `executeGates()` — parallel via ParallelExecutor
6. `evaluate()` — PolicyEvaluator with 4 aggregation modes
7. `aggregate()` — ResultAggregator combines gate results
8. `saveSnapshot()` — SnapshotStore + GateRunStore persistence
9. `generateReport()` — Reporter produces output format

**Lazy Context Loading**: Only loads data that active gates need:
- Patterns: if pattern-compliance or regression-detection enabled
- Constraints: if constraint-verification enabled
- Call graph: if impact-simulation or security-boundary enabled
- Previous snapshot: if regression-detection enabled
- Custom rules: if custom-rules enabled

### 3.6 Supporting Services

**PatternServiceFactory**: Auto-detects storage backend:
1. `.drift/drift.db` exists → SQLite (HybridPatternStore)
2. `.drift/patterns/*.json` exists → JSON (PatternStore)
3. Neither → default to SQLite (new projects)

**BoundaryScanner**: CLI progress wrapper around core boundary analysis. Adds spinner, timing, verbose output.

**ContractScanner**: CLI progress wrapper around core contract analysis. Same pattern as BoundaryScanner.

**BackupService**: Project backup/restore orchestration. Creates timestamped `.drift/backups/` directories.

---

## 4. Key Data Models

### 4.1 Scan Pipeline Types

```typescript
// Project context passed to every worker
interface ProjectContext {
  rootDir: string;
  files: string[];
  config: Record<string, unknown>;
}

// Worker warmup
interface WarmupTask {
  type: 'warmup';
  categories?: string[];
  criticalOnly?: boolean;
}
interface WarmupResult {
  type: 'warmup';
  detectorsLoaded: number;
  duration: number;
}

// Worker scan task
interface DetectorWorkerTask {
  type?: 'scan';
  file: string;
  rootDir: string;
  projectFiles: string[];
  projectConfig: Record<string, unknown>;
  detectorIds?: string[];
  categories?: string[];
  criticalOnly?: boolean;
}

// Worker scan result
interface DetectorWorkerResult {
  file: string;
  language: string | null;
  patterns: WorkerPatternMatch[];
  violations: WorkerViolation[];
  detectorsRan: number;
  detectorsSkipped: number;
  duration: number;
}

// Pattern match from worker
interface WorkerPatternMatch {
  patternId: string;
  detectorId: string;
  detectorName: string;
  detectorDescription: string;
  category: string;
  subcategory: string;
  confidence: number;
  location: {
    file: string;
    line: number;
    column: number;
    endLine?: number;
    endColumn?: number;
  };
  isOutlier?: boolean;
  outlierReason?: string;
  matchedText?: string;
  metadata?: Record<string, unknown>;
}

// Violation from worker
interface WorkerViolation {
  patternId: string;
  detectorId: string;
  category: string;
  severity: 'error' | 'warning' | 'info' | 'hint';
  file: string;
  line: number;
  column: number;
  message: string;
  explanation?: string;
  suggestedFix?: string;
}
```

### 4.2 Aggregated Types

```typescript
// Cross-file aggregated pattern
interface AggregatedPattern {
  patternId: string;
  detectorId: string;
  category: string;
  subcategory: string;
  name: string;
  description: string;
  locations: Array<{
    file: string;
    line: number;
    column: number;
    endLine?: number;
    endColumn?: number;
    isOutlier?: boolean;
    outlierReason?: string;
    matchedText?: string;
    confidence?: number;
  }>;
  confidence: number;
  occurrences: number;
  outlierCount: number;
  metadata?: Record<string, unknown>;
}

// Cross-file aggregated violation
interface AggregatedViolation {
  patternId: string;
  detectorId: string;
  category: string;
  severity: 'error' | 'warning' | 'info' | 'hint';
  file: string;
  line: number;
  column: number;
  message: string;
  explanation?: string;
  suggestedFix?: string;
}

// Final scan output
interface ScanResults {
  files: FileScanResult[];
  patterns: AggregatedPattern[];
  violations: AggregatedViolation[];
  totalPatterns: number;
  totalViolations: number;
  totalFiles: number;
  duration: number;
  errors: string[];
  detectorStats: {
    total: number;
    ran: number;
    skipped: number;
  };
  manifest?: Manifest;
  workerStats?: {
    threads: number;
    tasksCompleted: number;
    avgTaskDuration: number;
  };
}
```

### 4.3 MCP Types

```typescript
// Standard MCP response envelope
interface MCPResponse<T> {
  summary: string;
  data: T;
  pagination?: { cursor?: string; hasMore: boolean; total?: number };
  hints?: { nextActions?: string[]; relatedTools?: string[]; warnings?: string[] };
  meta: { requestId: string; durationMs: number; cached: boolean; tokenEstimate: number };
}

// MCP server configuration
interface EnterpriseMCPConfig {
  projectRoot: string;
  enableCache?: boolean;
  enableRateLimiting?: boolean;
  enableMetrics?: boolean;
  maxRequestsPerMinute?: number;
  usePatternService?: boolean;
  verbose?: boolean;
  skipWarmup?: boolean;
}
```

### 4.4 Quality Gate Types

```typescript
// Gate orchestrator input
interface QualityGateOptions {
  files?: string[];
  patterns?: string[];
  policy?: string | QualityPolicy;
  format?: 'json' | 'text' | 'sarif' | 'github' | 'gitlab';
  outputPath?: string;
  ci?: boolean;
  branch?: string;
  commitSha?: string;
  baselineBranch?: string;
  baselineCommit?: string;
  verbose?: boolean;
}

// Gate orchestrator output
interface QualityGateResult {
  passed: boolean;
  status: GateStatus;
  score: number;
  summary: string;
  gates: Record<GateId, GateResult>;
  violations: GateViolation[];
  warnings: string[];
  policy: { id: string; name: string };
  metadata: {
    executionTimeMs: number;
    filesChecked: number;
    gatesRun: GateId[];
    gatesSkipped: GateId[];
    timestamp: string;
    branch: string;
    commitSha?: string;
    ci: boolean;
  };
  exitCode: number;
}
```

---

## 5. Key Algorithms

### 5.1 Location Deduplication

Two strategies used during aggregation:

```typescript
// Standard deduplication — exact position match
function locationKey(loc: PatternLocation): string {
  return `${loc.file}:${loc.line}:${loc.column}`;
}

// Semantic deduplication — includes function/class context
function semanticLocationKey(loc: PatternLocation): string {
  return `${loc.file}:${loc.line}:${loc.column}:${loc.functionName}:${loc.className}`;
}

// Deduplication during merge
function addUniqueLocation(locations: PatternLocation[], newLoc: PatternLocation): void {
  const key = locationKey(newLoc);
  if (!existingKeys.has(key)) {
    existingKeys.add(key);
    locations.push(newLoc);
  }
}
```

### 5.2 Worker Distribution

```
1. Create Piscina pool with N workers (N = os.cpus().length - 1)
2. Send WarmupTask to each worker (loads detectors once per thread)
3. For each file:
     pool.run({ type: 'scan', file, rootDir, projectFiles, projectConfig, categories })
4. Workers:
     a. Filter applicable detectors by language + categories
     b. Run each detector.detect(context)
     c. Return DetectorWorkerResult
5. Main thread: Promise.all(workerPromises) → DetectorWorkerResult[]
6. Aggregate results via aggregateWorkerResults()
```

### 5.3 Scan Health Monitoring

```
ScanHealthMonitor:
  startTime = Date.now()
  
  setInterval(progressIntervalMs):
    elapsed = Date.now() - startTime
    log("Scanning... ${elapsed}ms elapsed, ${filesProcessed}/${totalFiles} files")
  
  setTimeout(warnAfterMs):
    log("Warning: scan taking longer than expected")
  
  setTimeout(timeoutMs):
    throw new Error("Scan timeout exceeded")
    
  On scan complete:
    clearAllTimers()
    log("Scan completed in ${duration}ms")
```

### 5.4 MCP Cache Key Generation

```typescript
function generateCacheKey(projectRoot: string, toolName: string, args: object): string {
  const sortedArgs = JSON.stringify(sortKeys(args));
  return SHA256(`${projectRoot}:${toolName}:${sortedArgs}`);
}
```

### 5.5 MCP Rate Limiting (Sliding Window)

```
3 tiers:
  Global:    100 requests / 60 seconds
  Expensive: 10 requests / 60 seconds (callgraph, code_examples, impact, security)
  Per-tool:  Configurable per tool

Algorithm:
  For each request:
    1. Remove expired entries from window
    2. Count remaining entries
    3. If count >= limit: reject with RATE_LIMITED error + retryAfterMs
    4. Else: add entry, allow request
```

### 5.6 Quality Gate Scoring

```
Per-gate scoring:
  penalty = Σ(error_violations × 10) + Σ(warning_violations × 3) + Σ(info_violations × 1)
  score = max(0, 100 - (penalty / maxPenalty) × 100)

Aggregation modes:
  'any':       any blocking gate failed → overall failed
  'all':       all gates must fail → overall failed
  'weighted':  score = Σ(gate.score × weight) / Σ(weight); passed = score >= minScore
  'threshold': score = avg(gate.scores); passed = score >= minScore
```

---

## 6. Integration Map

### 6.1 Complete Dependency Graph

```
                    ┌──────────────┐
                    │  10-cli      │
                    │  Commands    │
                    └──────┬───────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
              ▼            ▼            ▼
        ┌──────────┐ ┌──────────┐ ┌──────────┐
        │ CLI      │ │ MCP      │ │ Quality  │
        │ Scanner  │ │ Server   │ │ Gates    │
        │ Service  │ │          │ │          │
        └────┬─────┘ └────┬─────┘ └────┬─────┘
             │            │            │
             └────────────┼────────────┘
                          │
                    ┌─────▼──────┐
                    │   Core     │
                    │  Scanner   │
                    │  Service   │
                    └─────┬──────┘
                          │
          ┌───────────────┼───────────────┐
          │               │               │
          ▼               ▼               ▼
    ┌──────────┐   ┌──────────┐   ┌──────────┐
    │ Detector │   │ Outlier  │   │ Manifest │
    │ Workers  │   │ Detector │   │ Generator│
    │ (Piscina)│   │          │   │          │
    └────┬─────┘   └──────────┘   └──────────┘
         │
    ┌────▼─────┐
    │ 350+     │
    │ Detectors│
    │ (TS)     │
    └────┬─────┘
         │
    ┌────▼─────┐
    │ Parsers  │
    │ (Rust +  │
    │  TS)     │
    └──────────┘
```

### 6.2 Post-Scan Data Flow

```
ScanResults
  │
  ├──→ PatternStore/UnifiedStore (persistence)
  │      └──→ drift.db (SQLite)
  │
  ├──→ ViewMaterializer (data lake)
  │      ├──→ StatusView (health score)
  │      ├──→ PatternIndexView (lightweight listing)
  │      ├──→ SecuritySummaryView (security posture)
  │      ├──→ TrendsView (historical trends)
  │      └──→ Indexes (file, category, table, entry point)
  │
  ├──→ HistoryStore (snapshots)
  │      └──→ .drift/history/
  │
  ├──→ Telemetry (if enabled)
  │      └──→ Cloudflare Worker
  │
  └──→ Reporter (output)
         ├──→ TextReporter (terminal)
         ├──→ JsonReporter (CI/CD)
         ├──→ GitHubReporter (PR annotations)
         ├──→ GitLabReporter (MR annotations)
         └──→ SarifReporter (security tools)
```

### 6.3 Cross-Subsystem Integration Points

| Subsystem | Direction | Integration |
|-----------|-----------|-------------|
| 01-rust-core | Consumes | NAPI bindings for native scan, parse, analyze |
| 02-parsers | Consumes | Language detection, file parsing via detectors |
| 03-detectors | Consumes | 350+ detectors loaded and executed by workers |
| 04-call-graph | Consumes | Call graph data for quality gate context |
| 05-analyzers | Consumes | OutlierDetector for statistical analysis |
| 06-cortex | Consumes | Memory initialization in MCP server |
| 07-mcp | Consumed by | MCP server wraps scan pipeline |
| 08-storage | Consumes | Pattern persistence (SQLite + JSON) |
| 09-quality-gates | Consumed by | Gates consume scan results for compliance |
| 10-cli | Consumed by | CLI commands invoke scan pipeline |
| 12-infrastructure | Consumed by | CI agent invokes scan pipeline |
| 23-pattern-repository | Consumes | IPatternService for pattern CRUD |
| 24-data-lake | Consumes | ViewMaterializer for post-scan rebuild |
| 26-workspace | Consumes | Project context, backup orchestration |

---

## 7. Comprehensive Gap Analysis

### 7.1 Architectural Gaps

| Gap | Impact | Severity |
|-----|--------|----------|
| No unified service contract | CLI, MCP, Gates each have different scan interfaces | High |
| Duplicated ScannerService | Core (~1,200 LOC) and CLI (~1,400 LOC) overlap significantly | High |
| No service registry | Services discovered via imports, not registered centrally | Medium |
| No dependency injection | Hard-coded dependencies, difficult to test | Medium |
| No service lifecycle management | No startup/shutdown hooks, no health checks | Medium |
| No service versioning | Breaking changes affect all consumers simultaneously | Low |
| Tight coupling to Piscina | Worker model cannot be swapped without rewriting | High |
| No middleware pipeline | Cross-cutting concerns (logging, metrics, auth) handled ad-hoc | Medium |

### 7.2 Performance Gaps

| Gap | Impact | Severity |
|-----|--------|----------|
| No incremental scanning | Full rescan every time (10s for 10K files) | Critical |
| 100+ AST traversals per file | Each detector traverses independently | Critical |
| Single-threaded aggregation | Bottleneck for large codebases | High |
| O(n²) task serialization | projectFiles array copied per worker task | High |
| No backpressure | Memory spike with 500K+ files | High |
| No result streaming | All results buffered in memory before aggregation | Medium |
| No parallel persistence | Store writes are sequential | Medium |
| Full lake materialization | Rebuilds all views even for small changes | Medium |

### 7.3 Reliability Gaps

| Gap | Impact | Severity |
|-----|--------|----------|
| No structured error handling | String-based errors, no taxonomy | High |
| No retry logic | Failed file processing not retried | Medium |
| No partial result recovery | Process crash loses all scan results | High |
| No cancellation support | Long scans cannot be interrupted gracefully | Medium |
| No worker health monitoring | Stuck workers block entire pool | Medium |
| No circuit breaker | Cascading failures not prevented | Medium |
| Detector cache never cleared | Memory growth in long-running processes | Low |
| No idempotency | Re-running scan may produce different results | Medium |

### 7.4 Observability Gaps

| Gap | Impact | Severity |
|-----|--------|----------|
| No structured logging | console.log only, no log levels or correlation | High |
| No distributed tracing | Cannot trace request through pipeline | Medium |
| No service-level metrics | No latency histograms, error rates, throughput | Medium |
| No alerting | No automated alerts for degraded performance | Low |
| No profiling hooks | Cannot identify bottlenecks without manual instrumentation | Medium |

### 7.5 Security Gaps

| Gap | Impact | Severity |
|-----|--------|----------|
| No authentication | Any process can invoke services | Medium |
| No authorization | No permission model for operations | Medium |
| No input validation framework | Each service validates independently | Medium |
| No audit logging | No record of who scanned what when | Low |
| No rate limiting at service level | Only MCP has rate limiting | Low |

---

## 8. V1 Metrics Summary

| Metric | Value |
|--------|-------|
| Total services layer code | ~5,500 lines |
| Files across 3 packages | 14 |
| Worker threads (default) | os.cpus().length - 1 |
| Detectors loaded per worker | 350+ |
| Languages detected | 25+ extensions |
| MCP tools orchestrated | 87+ |
| Quality gates orchestrated | 6 |
| Output formats supported | 5 (text, json, sarif, github, gitlab) |
| Cache levels (MCP) | 2 (L1 LRU + L2 file) |
| Rate limit tiers (MCP) | 3 (global, expensive, per-tool) |
| Store backends managed | 9 (MCP server) |
| Scan timeout | 300 seconds |
| Scan warning threshold | 30 seconds |

---

## 9. V2 Migration Implications

### 9.1 What Gets Eliminated

| Component | LOC | Reason |
|-----------|-----|--------|
| Piscina worker pool | ~300 | Rust rayon replaces |
| detector-worker.ts | ~350 | Rust detection engine replaces |
| CLI worker wrapper | ~200 | Eliminated with Piscina |
| Worker warmup logic | ~100 | Rust static initialization |
| TS detector loading | ~200 | Rust loads detectors natively |
| Single-threaded fallback | ~150 | Rust always parallel |
| Aggregation engine (partial) | ~300 | Rust aggregates natively |
| Manifest generation | ~200 | SQLite stats replace |
| JSON store paths | ~200 | SQLite-only |
| Dual-path MCP handlers | ~500 | Single SQLite path |
| **Total eliminated** | **~2,500** | |

### 9.2 What Stays (TypeScript)

| Component | LOC | Reason |
|-----------|-----|--------|
| CLI argument parsing | ~200 | Presentation concern |
| Progress reporting (spinner, table) | ~300 | Terminal UI |
| Output formatting (reporters) | ~800 | Consumer-specific formatting |
| MCP response envelope | ~200 | Protocol formatting |
| MCP caching infrastructure | ~300 | Request-level optimization |
| MCP rate limiting | ~200 | Request-level protection |
| MCP metrics collection | ~200 | Observability |
| Quality gate policy engine | ~500 | Policy evaluation logic |
| Quality gate reporters | ~400 | Output formatting |
| **Total retained** | **~3,100** | |

### 9.3 What Gets Rebuilt (New in V2)

| Component | Purpose |
|-----------|---------|
| Unified ScanService | Single ~100 LOC wrapper around Rust NAPI |
| Structured error bridge | Rust errors → TypeScript error types |
| Progress streaming | Rust progress callbacks → TypeScript UI |
| Cancellation bridge | TypeScript cancellation → Rust revision counter |
| Batch NAPI API | Single NAPI call for multiple analyses |
| Service health checks | Startup/readiness/liveness probes |
| Structured logging | Correlation IDs, log levels, structured output |

---

## 10. Open Questions

1. **Should the services layer have a formal service registry?** V1 uses direct imports. V2 could use a registry pattern for testability and plugin support.

2. **Should scan results stream or batch?** V1 buffers all results. V2 could stream results as they complete for real-time progress in IDE.

3. **Should the MCP server share a process with CLI?** Currently separate processes with separate store instances. A shared daemon could eliminate cold-start overhead.

4. **Should quality gates run as part of the scan pipeline or separately?** Currently separate invocation. Integrated pipeline could reduce redundant data loading.

5. **Should the services layer support plugins?** Enterprise users may want custom analysis passes without forking.

6. **What's the right granularity for NAPI calls?** One mega-call (`nativeScan`) vs. many small calls (`nativeParse`, `nativeDetect`, `nativeAggregate`)?

7. **Should the services layer own the file walker?** Currently the CLI owns file discovery. Moving it to the service layer would unify the pipeline.

8. **How should progress be reported across the NAPI boundary?** Callbacks, channels, polling, or shared memory?

---

## Quality Checklist

- [x] All 14 files across 3 packages inventoried with line counts
- [x] Complete scan pipeline execution traces (CLI, MCP, Quality Gates)
- [x] All data flow contracts documented with TypeScript interfaces
- [x] All key algorithms documented
- [x] Complete integration map with dependency graph
- [x] Comprehensive gap analysis (architecture, performance, reliability, observability, security)
- [x] V1 metrics summarized
- [x] V2 migration implications documented (eliminated, retained, rebuilt)
- [x] Open questions identified
- [x] Cross-referenced with all adjacent category recaps
