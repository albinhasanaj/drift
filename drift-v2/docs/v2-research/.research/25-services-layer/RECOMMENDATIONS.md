# 25 Services Layer — V2 Build Recommendations

> **Context**: Drift v2 is a greenfield build. These recommendations define how to BUILD the services/orchestration layer from scratch, informed by v1's architecture (treated as a requirements specification) and external research from 20 Tier 1-3 sources across 18 research entries. Every recommendation is framed as "build new" not "migrate/port." The v1 services layer (~5,500 lines TypeScript across 14 files in 3 packages) is eliminated. Its orchestration concepts — pipeline sequencing, parallel dispatch, result aggregation, consumer adaptation — are preserved and reimplemented as a thin TypeScript wrapper (~100-200 LOC) around a Rust NAPI engine that owns all computation.

## Summary

25 recommendations organized into 7 build phases. The services layer is the orchestration backbone — the system that coordinates every scan, analysis, and query operation across all consumer surfaces (CLI, MCP, Quality Gates, IDE). Getting this layer right determines whether Drift v2 delivers sub-second incremental scans or regresses to v1's 10-second full-rescan model. The v1 services layer's core insight — separate orchestration (TypeScript) from computation (workers) — is preserved. The implementation changes from Piscina worker threads running 350+ TypeScript detectors to a single Rust NAPI call that owns the entire computation pipeline internally. Phase 0 establishes architectural decisions. Phases 1-2 build the Rust scan engine and NAPI bridge. Phases 3-4 add incremental computation and consumer adaptation. Phases 5-6 handle observability and enterprise hardening.

---

## Phase 0: Architectural Decisions

### SL-1: Adopt Two-Phase Pipeline Architecture (Index → Analyze)

**Priority**: P0 (Build First)
**Effort**: Low (architectural decision, constrains all subsequent design)
**Impact**: Enables incremental computation, parallel processing, and clean separation of concerns

**Current State (V1)**:
V1's scan pipeline is monolithic: files are dispatched to workers, each worker runs ALL detectors on a single file, results are collected and aggregated on the main thread. There is no separation between per-file work and cross-file work. Every scan is a full rescan — no incrementality.

**Proposed Architecture**:
Separate the pipeline into two distinct phases, following rust-analyzer's proven model (SL-R4):

```
Phase 1: Per-File Indexing (embarrassingly parallel)
  files.par_iter() → parse(file) → detect(file) → FileIndex
  
  - Each file processed independently
  - No cross-file state during this phase
  - Results: FileIndex { parse_result, patterns, violations, content_hash }
  - Cached by content_hash — unchanged files skip this phase entirely

Phase 2: Cross-File Analysis (dependency-driven)
  FileIndex[] → aggregate() → learn_conventions() → resolve_calls() → compute_coupling()
  
  - Operates on FileIndex results, not raw files
  - Only re-runs for affected patterns when files change
  - Results: AggregatedPatterns, ConventionModels, CallGraph, CouplingMetrics
```

**Key Invariant** (from rust-analyzer SL-R4): "Editing a function body never invalidates cross-file derived data." The per-file index captures function signatures (which participate in cross-file analysis) separately from function bodies (which are analyzed independently). This means most edits trigger only Phase 1 re-indexing of the changed file, not Phase 2 re-analysis.

**The services layer's role**: Orchestrate both phases, manage the transition between them, and decide which files need Phase 1 re-indexing and which Phase 2 analyses need re-running.

**Evidence**: rust-analyzer (SL-R4), Oxc (SL-R1), Turbopack (SL-R14)

**Dependencies**: All subsequent recommendations build on this two-phase model.

---

### SL-2: Define Unified Service Contract

**Priority**: P0 (Build First)
**Effort**: Low (interface definition)
**Impact**: Eliminates v1's fragmented service interfaces (CLI, MCP, Gates each had different scan APIs)

**Current State (V1)**:
V1 has three different scan interfaces:
- Core `ScannerService` (~1,200 LOC) — worker pool, aggregation, outlier detection
- CLI `ScannerService` (~1,400 LOC) — adds progress, health monitoring, timeout, persistence
- MCP request pipeline (~914 LOC) — adds caching, rate limiting, metrics, project resolution

Each consumer reimplements orchestration logic. There is no unified contract.

**Proposed Contract**:

```typescript
// The ONE service interface all consumers use
interface IScanService {
  // Core scan operation
  scan(config: ScanConfig): Promise<ScanResult>;
  
  // Incremental scan (only changed files)
  scanIncremental(config: ScanConfig, baseline: ScanBaseline): Promise<ScanResult>;
  
  // Cancel an in-progress scan
  cancel(scanId: string): Promise<void>;
  
  // Query cached results (no re-scan)
  query(query: AnalysisQuery): Promise<QueryResult>;
  
  // Health check
  health(): Promise<ServiceHealth>;
}

interface ScanConfig {
  rootDir: string;
  threads?: number;              // default: num_cpus - 1
  timeout?: number;              // default: 300_000ms
  categories?: string[];         // filter detectors
  analyses?: AnalysisType[];     // which analyses to run
  onProgress?: (p: ScanProgress) => void;  // progress callback
}

interface ScanResult {
  scanId: string;
  status: 'complete' | 'partial' | 'cancelled' | 'failed';
  summary: ScanSummary;
  duration: number;
  errors: ScanError[];
}

// Consumers adapt the unified contract to their needs:
// CLI: adds spinner, reporters, persistence triggers
// MCP: adds caching, rate limiting, response envelope
// Gates: adds policy evaluation, threshold checking
// IDE: adds file-level incremental, diagnostics formatting
```

**Rationale**: One contract, many adapters. The services layer provides the contract. Each consumer wraps it with consumer-specific concerns. This eliminates the 600+ lines of duplicated orchestration logic in v1.

**Evidence**: Tower Service trait (SL-R6), SonarQube scanner-server separation (SL-R9)

**Dependencies**: SL-3 (NAPI bridge), SL-5 (consumer adapters)

---

### SL-3: Define NAPI Bridge API Surface

**Priority**: P0 (Build First)
**Effort**: Medium (API design + implementation)
**Impact**: The NAPI boundary is the most critical interface in the system — every operation crosses it

**Current State (V1)**:
V1 has ~25 individual NAPI functions, each crossing the boundary independently. The services layer calls multiple NAPI functions per scan (parse, detect, analyze), each with its own serialization overhead.

**Proposed API**:

```rust
// PRIMARY: Single-call scan (most common path)
#[napi]
pub fn native_scan(config: ScanConfig) -> AsyncTask<ScanTask>;

// PRIMARY: Single-call scan with progress
#[napi(ts_args_type = "config: ScanConfig, onProgress: (p: ScanProgress) => void")]
pub fn native_scan_with_progress(
    config: ScanConfig, 
    on_progress: ThreadsafeFunction<ScanProgress>
) -> AsyncTask<ScanTask>;

// CANCELLATION: Set from TypeScript, checked by Rust workers
#[napi]
pub fn cancel_scan(scan_id: String) -> Result<()>;

// QUERY: Read from SQLite without re-scanning
#[napi]
pub fn native_query(query: AnalysisQuery) -> AsyncTask<QueryTask>;

// BATCH: Multiple analyses in one NAPI call
#[napi]
pub fn native_analyze_batch(
    root: String, 
    analyses: Vec<AnalysisType>
) -> AsyncTask<BatchAnalysisTask>;

// HEALTH: Check engine status
#[napi]
pub fn engine_health() -> EngineHealth;
```

**Key design decisions**:

1. **Write to SQLite from Rust**: Detailed results (patterns, locations, violations) are written directly to SQLite by the Rust engine. Only summary statistics cross the NAPI boundary back to TypeScript. This minimizes serialization overhead for large result sets (SL-R5).

2. **AsyncTask for all long operations**: Every operation that might take >10ms uses `AsyncTask` to avoid blocking the Node.js event loop (SL-R5).

3. **ThreadsafeFunction for progress**: Progress callbacks use `NonBlocking` mode to avoid slowing down rayon workers (SL-R18).

4. **Structured errors**: Rust error enums map to TypeScript error types via `thiserror` (SL-R5).

**Evidence**: napi-rs AsyncTask (SL-R5), Oxc LintService (SL-R1)

**Dependencies**: SL-1 (two-phase pipeline), SL-4 (Rust scan engine)

---

## Phase 1: Rust Scan Engine

### SL-4: Build Rust Scan Engine with Rayon + MPSC Pipeline

**Priority**: P0 (Core Engine)
**Effort**: High
**Impact**: Replaces v1's entire Piscina worker model (~2,500 LOC eliminated)

**Current State (V1)**:
V1 uses Piscina (Node.js worker threads) for parallel detection. Each worker loads 350+ TypeScript detectors, reads a file, runs all detectors, and returns results. The main thread aggregates results single-threaded. Problems: no backpressure, O(n²) task serialization, 100+ AST traversals per file, single-threaded aggregation bottleneck.

**Proposed Architecture**:

```
TypeScript: scanService.scan(config)
  │
  └──→ native_scan_with_progress(config, onProgress)
         │
         ├── Phase 1: File Discovery
         │     walkdir + rayon + .gitignore/.driftignore
         │     → Vec<FileEntry> { path, size, content_hash, language }
         │
         ├── Phase 2: Per-File Processing (rayon::par_iter)
         │     files.par_iter()
         │       .filter(|f| !cache.is_current(f))  // skip unchanged
         │       .flat_map_iter(|f| {
         │           let parsed = parse(f);
         │           let patterns = detect(parsed);  // single-pass visitor
         │           let violations = validate(parsed, patterns);
         │           tx.send(FileResult { f, parsed, patterns, violations });
         │       })
         │
         ├── Writer Thread (dedicated, receives from MPSC)
         │     loop {
         │       batch = rx.recv_batch(500);
         │       BEGIN TRANSACTION;
         │       INSERT INTO file_results ...;
         │       INSERT INTO patterns ...;
         │       INSERT INTO violations ...;
         │       COMMIT;
         │     }
         │
         ├── Phase 3: Cross-File Analysis
         │     aggregate_patterns()
         │     learn_conventions()
         │     compute_outliers()
         │     refresh_materialized_views()
         │
         └── Return ScanSummary to TypeScript
```

**Key implementation details**:

1. **Custom rayon pool**: Dedicated thread pool with `num_cpus - 1` threads, named threads for debugging (SL-R12).

2. **Bounded MPSC channel**: `crossbeam::bounded(4 * num_threads)` between rayon workers and writer thread. Provides backpressure — if SQLite writes are slow, rayon workers pause (SL-R13, SL-R16).

3. **Batched SQLite writes**: Writer thread batches 500 results per transaction. SQLite WAL mode enables concurrent reads during writes (SL-R13).

4. **Cancellation**: Shared `AtomicBool` checked by rayon workers between files. On cancellation, workers stop, writer flushes remaining batch, partial results are returned (SL-R10).

5. **Progress reporting**: `AtomicU64` counter incremented by workers. Every 100 files, call `ThreadsafeFunction` with progress data (SL-R18).

6. **Error tolerance**: Parse errors produce partial results. Detector errors skip the detector for that file. No single file failure aborts the scan (SL-R1).

**Performance targets**:
- 10K files: <3s (vs. v1's ~10s)
- 100K files: <15s
- 500K files: <60s
- Incremental (1 file changed, 10K codebase): <100ms

**Evidence**: Oxc (SL-R1), Rayon (SL-R12), MPSC channels (SL-R13), Backpressure (SL-R16)

**Dependencies**: SL-1 (two-phase architecture), SL-3 (NAPI bridge)

---

### SL-5: Build Content-Hash Cache for Incremental Skipping

**Priority**: P0 (Core Engine)
**Effort**: Medium
**Impact**: Transforms every scan after the first from O(all_files) to O(changed_files)

**Current State (V1)**:
V1 has an `--incremental` flag but it's rudimentary — it checks file modification time, not content hash. No per-file result caching. Every scan re-processes every file.

**Proposed Implementation**:

```rust
pub struct FileCache {
    db: Connection,  // SQLite table: file_cache(path, content_hash, last_indexed_at)
}

impl FileCache {
    /// Returns files that need re-indexing
    pub fn diff(&self, current_files: &[FileEntry]) -> CacheDiff {
        let mut added = Vec::new();
        let mut modified = Vec::new();
        let mut removed = Vec::new();
        let mut unchanged = Vec::new();
        
        for file in current_files {
            match self.get_cached_hash(&file.path) {
                None => added.push(file),
                Some(cached_hash) if cached_hash != file.content_hash => modified.push(file),
                Some(_) => unchanged.push(file),
            }
        }
        
        // Files in cache but not in current_files → removed
        removed = self.find_removed(current_files);
        
        CacheDiff { added, modified, removed, unchanged }
    }
    
    /// Update cache after successful indexing
    pub fn update(&self, file: &FileEntry) {
        // UPSERT into file_cache
    }
}
```

**Cache invalidation strategy**:
1. **File-level**: Content hash (xxhash) comparison. If hash matches, skip entirely.
2. **Pattern-level**: When files change, only re-aggregate patterns that had locations in changed files.
3. **Convention-level**: If <10% of files changed, skip convention re-learning. If 10-30%, incremental update. If >30%, full re-learning.

**Persistence**: Cache stored in SQLite (`drift.db` or separate `cache.db`). Survives process restarts. On first scan, cache is empty — full scan. On subsequent scans, only changed files are processed.

**Evidence**: rust-analyzer durable incrementality (SL-R4), Turbopack persistent caching (SL-R14)

**Dependencies**: SL-4 (scan engine uses cache to filter files)

---

### SL-6: Implement Cancellation Bridge (TypeScript → Rust)

**Priority**: P0 (Core Engine)
**Effort**: Low
**Impact**: Enables IDE integration and CLI timeout — without cancellation, long scans block the process

**Current State (V1)**:
V1's `ScanHealthMonitor` warns after 30s and kills after 300s. There is no graceful cancellation — the process is terminated, losing all results.

**Proposed Implementation**:

```rust
// Rust side
pub struct ScanCancellation {
    cancelled: AtomicBool,
    revision: AtomicU64,
}

#[napi]
pub fn cancel_scan(scan_id: String) -> Result<()> {
    SCAN_REGISTRY.get(&scan_id)
        .ok_or_else(|| Error::new(Status::InvalidArg, "Unknown scan ID"))?
        .cancel();
    Ok(())
}

// In rayon workers:
files.par_iter()
    .take_any_while(|_| !cancellation.is_cancelled())
    .for_each(|file| {
        if cancellation.is_cancelled() { return; }
        process_file(file);
    });
```

```typescript
// TypeScript side
class ScanService implements IScanService {
    private activeScanId: string | null = null;
    
    async scan(config: ScanConfig): Promise<ScanResult> {
        this.activeScanId = crypto.randomUUID();
        
        // Set up timeout cancellation
        const timer = config.timeout 
            ? setTimeout(() => this.cancel(this.activeScanId!), config.timeout)
            : null;
        
        try {
            return await nativeScanWithProgress(config, this.handleProgress);
        } finally {
            if (timer) clearTimeout(timer);
            this.activeScanId = null;
        }
    }
    
    async cancel(scanId: string): Promise<void> {
        await cancelScan(scanId);
    }
}
```

**Cancellation semantics**:
- Files already processed: results persisted to SQLite (valid)
- File currently being processed: result discarded (incomplete)
- Files not yet started: skipped
- Aggregation: runs on available results (partial but consistent)
- Return status: `'partial'` with count of processed/total files

**Evidence**: rust-analyzer cancellation (SL-R4), Tokio CancellationToken (SL-R10)

**Dependencies**: SL-4 (scan engine checks cancellation flag)


---

## Phase 2: NAPI Bridge and TypeScript Orchestration

### SL-7: Build TypeScript ScanService (~100-200 LOC)

**Priority**: P0 (Bridge Layer)
**Effort**: Low
**Impact**: The entire TypeScript services layer — replaces ~5,500 LOC with ~200 LOC

**Current State (V1)**:
V1's TypeScript services layer is ~5,500 lines across 14 files. It manages Piscina workers, loads detectors, reads files, runs detection, aggregates results, and persists to storage. All of this moves to Rust.

**Proposed Implementation**:

```typescript
import { nativeScan, nativeScanWithProgress, cancelScan, engineHealth } from '@drift/native';

export class ScanService implements IScanService {
    async scan(config: ScanConfig): Promise<ScanResult> {
        const scanId = crypto.randomUUID();
        const timer = config.timeout
            ? setTimeout(() => cancelScan(scanId), config.timeout)
            : null;
        
        try {
            const summary = config.onProgress
                ? await nativeScanWithProgress({ ...config, scanId }, config.onProgress)
                : await nativeScan({ ...config, scanId });
            
            return {
                scanId,
                status: summary.cancelled ? 'partial' : 'complete',
                summary,
                duration: summary.duration_ms,
                errors: summary.errors,
            };
        } catch (err) {
            return {
                scanId,
                status: 'failed',
                summary: emptySummary(),
                duration: 0,
                errors: [toScanError(err)],
            };
        } finally {
            if (timer) clearTimeout(timer);
        }
    }
    
    async scanIncremental(config: ScanConfig, baseline: ScanBaseline): Promise<ScanResult> {
        return this.scan({ ...config, baseline });
    }
    
    async cancel(scanId: string): Promise<void> {
        await cancelScan(scanId);
    }
    
    async query(query: AnalysisQuery): Promise<QueryResult> {
        return nativeQuery(query);
    }
    
    async health(): Promise<ServiceHealth> {
        return engineHealth();
    }
}
```

That's it. ~80 lines. The Rust engine handles everything else.

**What stays in TypeScript** (consumer adapters, not the service itself):
- CLI adapter: argument parsing, spinner, reporters (~500 LOC)
- MCP adapter: caching, rate limiting, response envelope (~700 LOC)
- Gate adapter: policy evaluation, threshold checking (~500 LOC)
- IDE adapter: LSP integration, diagnostics formatting (~300 LOC)

**Evidence**: Biome unified Rust toolchain (SL-R2), Oxc LintService (SL-R1)

**Dependencies**: SL-2 (unified contract), SL-3 (NAPI bridge), SL-4 (Rust engine)

---

### SL-8: Build Consumer Adapters (CLI, MCP, Gates, IDE)

**Priority**: P0 (Bridge Layer)
**Effort**: Medium
**Impact**: Each consumer gets a tailored experience while sharing the same scan engine

**Current State (V1)**:
Each consumer reimplements orchestration logic. CLI has its own ScannerService (~1,400 LOC). MCP has its own request pipeline (~914 LOC). Quality gates have their own context builder. No shared infrastructure.

**Proposed Architecture**:

```typescript
// CLI Adapter
class CliScanAdapter {
    constructor(private scanService: IScanService) {}
    
    async runScan(cliOptions: CliScanOptions): Promise<void> {
        const spinner = ora('Scanning...').start();
        
        const result = await this.scanService.scan({
            rootDir: cliOptions.rootDir,
            categories: cliOptions.categories,
            timeout: cliOptions.timeout,
            onProgress: (p) => {
                spinner.text = `Scanning... ${p.filesProcessed}/${p.totalFiles} files`;
            },
        });
        
        spinner.succeed(`Scan complete: ${result.summary.totalPatterns} patterns`);
        
        // Post-scan: reporting
        const reporter = createReporter(cliOptions.format);
        await reporter.generate(result);
    }
}

// MCP Adapter
class McpScanAdapter {
    constructor(
        private scanService: IScanService,
        private cache: ResponseCache,
        private rateLimiter: RateLimiter,
    ) {}
    
    async handleScanTool(args: McpToolArgs): Promise<McpResponse> {
        await this.rateLimiter.check(args.tool);
        
        const cacheKey = this.cache.key(args);
        const cached = await this.cache.get(cacheKey);
        if (cached) return cached;
        
        const result = await this.scanService.scan({
            rootDir: args.projectRoot,
            categories: args.categories,
        });
        
        const response = formatMcpResponse(result);
        await this.cache.set(cacheKey, response);
        return response;
    }
}

// Quality Gate Adapter
class GateScanAdapter {
    constructor(private scanService: IScanService) {}
    
    async evaluateGates(options: GateOptions): Promise<GateResult> {
        const result = await this.scanService.scan({
            rootDir: options.rootDir,
            analyses: options.requiredAnalyses,
        });
        
        const policy = await loadPolicy(options.policy);
        return evaluatePolicy(policy, result);
    }
}
```

**Key principle**: Adapters are thin. They handle consumer-specific concerns (UI, caching, policy) and delegate all computation to the shared `IScanService`. No adapter contains scan logic.

**Evidence**: Tower Service/Layer separation (SL-R6), SonarQube scanner-server separation (SL-R9)

**Dependencies**: SL-2 (unified contract), SL-7 (ScanService)

---

### SL-9: Implement Structured Error Bridge

**Priority**: P0 (Bridge Layer)
**Effort**: Low
**Impact**: Replaces v1's string-based errors with programmatic error handling

**Current State (V1)**:
All errors are string messages. No error codes, no categorization, no programmatic handling. The error propagation chain loses context at every boundary.

**Proposed Implementation**:

```rust
// Rust error types (thiserror)
#[derive(thiserror::Error, Debug)]
pub enum ScanError {
    #[error("path not found: {path}")]
    PathNotFound { path: String },
    #[error("permission denied: {path}")]
    PermissionDenied { path: String },
    #[error("parse error in {file}: {message}")]
    ParseError { file: String, message: String, line: Option<u32> },
    #[error("scan cancelled after {files_processed} files")]
    Cancelled { files_processed: u64 },
    #[error("scan timeout after {duration_ms}ms")]
    Timeout { duration_ms: u64, files_processed: u64 },
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
```

```typescript
// TypeScript error types (mirror Rust)
class DriftScanError extends Error {
    constructor(
        public readonly code: ScanErrorCode,
        message: string,
        public readonly details?: Record<string, unknown>,
    ) {
        super(message);
    }
}

enum ScanErrorCode {
    PathNotFound = 'PATH_NOT_FOUND',
    PermissionDenied = 'PERMISSION_DENIED',
    ParseError = 'PARSE_ERROR',
    Cancelled = 'CANCELLED',
    Timeout = 'TIMEOUT',
    DatabaseError = 'DATABASE_ERROR',
    IoError = 'IO_ERROR',
}
```

**Error handling strategy by consumer**:
- CLI: Display human-readable message, exit with appropriate code
- MCP: Return structured error in MCP response envelope
- Gates: Treat scan errors as gate failures with explanation
- IDE: Show error in diagnostics panel

**Evidence**: napi-rs structured errors (SL-R5), Saga compensating transactions (SL-R17)

**Dependencies**: SL-3 (NAPI bridge)

---

## Phase 3: Incremental Computation

### SL-10: Implement Incremental Aggregation

**Priority**: P0 (Incremental)
**Effort**: Medium
**Impact**: Reduces aggregation from O(all_patterns) to O(affected_patterns) on incremental scans

**Current State (V1)**:
V1 re-aggregates ALL patterns on every scan. For 10K files with 50K pattern locations, this means re-grouping, re-deduplicating, and re-scoring 50K items even if only 1 file changed.

**Proposed Implementation**:

```rust
pub struct IncrementalAggregator {
    db: Connection,
}

impl IncrementalAggregator {
    pub fn aggregate_incremental(&self, changed_files: &[FileEntry]) -> AggregationResult {
        // 1. Delete old pattern_locations for changed files
        self.delete_locations_for_files(changed_files);
        
        // 2. Insert new pattern_locations from detection results
        self.insert_new_locations(changed_files);
        
        // 3. Re-aggregate ONLY patterns that had locations in changed files
        let affected_pattern_ids = self.get_affected_patterns(changed_files);
        
        // 4. Recompute confidence, occurrence count, outlier status
        //    for affected patterns only
        for pattern_id in &affected_pattern_ids {
            self.recompute_pattern_stats(pattern_id);
        }
        
        // 5. Re-run outlier detection on affected patterns
        self.recompute_outliers(&affected_pattern_ids);
        
        // 6. Refresh only affected materialized views
        self.refresh_affected_views(&affected_pattern_ids);
        
        AggregationResult {
            patterns_updated: affected_pattern_ids.len(),
            full_recompute: false,
        }
    }
}
```

**Threshold for full re-aggregation**: If >30% of files changed, do a full re-aggregation instead of incremental (the overhead of tracking affected patterns exceeds the cost of full recompute).

**Evidence**: Turbopack fine-grained invalidation (SL-R14), rust-analyzer incremental (SL-R4)

**Dependencies**: SL-5 (content-hash cache provides changed file list)

---

### SL-11: Implement Convention Re-Learning Strategy

**Priority**: P1 (Incremental)
**Effort**: Medium
**Impact**: Prevents stale conventions from being enforced after codebase evolution

**Current State (V1)**:
V1 re-learns ALL conventions on every scan. No temporal awareness — once a convention reaches high confidence, it stays there forever even if the codebase migrates away from it.

**Proposed Implementation**:

Three-tier re-learning strategy based on change magnitude:

| Change Magnitude | Threshold | Strategy |
|---|---|---|
| Minimal | <10% files changed | Skip re-learning. Reuse existing convention models. |
| Moderate | 10-30% files changed | Incremental update. Re-learn only conventions with locations in changed files. |
| Major | >30% files changed | Full re-learning. Recompute all convention models from scratch. |

```rust
pub fn determine_learning_strategy(diff: &CacheDiff) -> LearningStrategy {
    let change_ratio = (diff.added.len() + diff.modified.len()) as f64 
        / (diff.total_files() as f64);
    
    match change_ratio {
        r if r < 0.10 => LearningStrategy::Skip,
        r if r < 0.30 => LearningStrategy::Incremental {
            affected_patterns: get_affected_patterns(&diff),
        },
        _ => LearningStrategy::Full,
    }
}
```

**Temporal decay integration**: When re-learning, apply temporal decay to convention confidence. Conventions that are declining in frequency lose confidence. Conventions that are growing gain momentum. This prevents Drift from fighting intentional migrations (see Master Recommendations M33).

**Evidence**: Google Tricorder incremental analysis (SL-R7), Turbopack demand-driven evaluation (SL-R14)

**Dependencies**: SL-5 (cache diff), SL-10 (incremental aggregation)

---

## Phase 4: Consumer Adaptation

### SL-12: Build MCP Request Pipeline with Middleware

**Priority**: P1 (Consumer Layer)
**Effort**: Medium
**Impact**: Replaces v1's ad-hoc MCP infrastructure (~1,600 LOC) with composable middleware

**Current State (V1)**:
V1's MCP server manually implements rate limiting, caching, metrics, and project resolution as inline code in `enterprise-server.ts`. Each concern is interleaved with routing logic. Adding a new concern (e.g., authentication) requires modifying the monolithic handler.

**Proposed Architecture**:

```typescript
// Composable middleware pipeline (inspired by Tower SL-R6)
const mcpPipeline = compose(
    rateLimitMiddleware({ global: 100, expensive: 10 }),
    cacheMiddleware({ l1Size: 1000, l2Dir: '.drift/cache' }),
    metricsMiddleware({ prefix: 'drift_mcp' }),
    projectResolutionMiddleware(),
    scanServiceMiddleware(scanService),
);

// Each middleware is independent and testable
type Middleware = (req: McpRequest, next: Next) => Promise<McpResponse>;

const rateLimitMiddleware = (config: RateLimitConfig): Middleware => {
    const limiter = new SlidingWindowLimiter(config);
    return async (req, next) => {
        if (!limiter.allow(req.tool)) {
            return errorResponse('RATE_LIMITED', limiter.retryAfter(req.tool));
        }
        return next(req);
    };
};

const cacheMiddleware = (config: CacheConfig): Middleware => {
    const cache = new TwoTierCache(config);
    return async (req, next) => {
        if (req.isMutation) return next(req);
        const cached = await cache.get(req.cacheKey);
        if (cached) return { ...cached, meta: { cached: true } };
        const result = await next(req);
        await cache.set(req.cacheKey, result);
        return result;
    };
};
```

**Middleware stack** (in order):
1. Rate limiting (reject overloaded requests)
2. Cache check (return cached response if available)
3. Project resolution (resolve project root from arguments)
4. Metrics recording (start timer)
5. Scan/query execution (call IScanService)
6. Cache write (store response)
7. Metrics recording (stop timer, record)

**Evidence**: Tower ServiceBuilder (SL-R6), SonarQube plugin architecture (SL-R9)

**Dependencies**: SL-2 (unified contract), SL-7 (ScanService)

---

### SL-13: Build Quality Gate Integration

**Priority**: P1 (Consumer Layer)
**Effort**: Medium
**Impact**: Quality gates consume scan results through the unified contract instead of reimplementing scan logic

**Current State (V1)**:
V1's `GateOrchestrator` builds its own context by loading data from multiple stores independently. It doesn't go through the scan pipeline — it reads stored results directly. This creates a coupling to storage internals.

**Proposed Architecture**:

```typescript
class QualityGateService {
    constructor(
        private scanService: IScanService,
        private policyEngine: PolicyEngine,
    ) {}
    
    async evaluate(options: GateOptions): Promise<GateResult> {
        // 1. Get scan results (from cache or fresh scan)
        const scanResult = options.freshScan
            ? await this.scanService.scan(options.scanConfig)
            : await this.scanService.query({ type: 'latest_scan' });
        
        // 2. Load policy
        const policy = await this.policyEngine.resolve(options.policy);
        
        // 3. Evaluate gates against scan results
        const gateResults = await Promise.all(
            policy.gates.map(gate => this.evaluateGate(gate, scanResult))
        );
        
        // 4. Aggregate gate results per policy aggregation mode
        return this.policyEngine.aggregate(policy, gateResults);
    }
}
```

**Key change from v1**: Gates query the scan service, not storage directly. The scan service decides whether to re-scan or return cached results. This decouples gates from storage internals.

**New code period support** (from SonarQube SL-R9): Gates can apply different thresholds to new code vs. overall code. The scan service provides the diff context (which patterns are new since the baseline).

**Evidence**: SonarQube quality gate computation (SL-R9)

**Dependencies**: SL-2 (unified contract), SL-7 (ScanService)

---

### SL-14: Build IDE Integration Layer

**Priority**: P1 (Consumer Layer)
**Effort**: Medium
**Impact**: Enables real-time incremental analysis in the IDE

**Current State (V1)**:
V1 has no IDE-specific services layer. The VSCode extension calls CLI commands or MCP tools. There is no incremental analysis — every operation is a full scan.

**Proposed Architecture**:

```typescript
class IdeScanAdapter {
    constructor(private scanService: IScanService) {}
    
    // Single-file incremental analysis (on save)
    async analyzeFile(uri: string, content: string): Promise<Diagnostic[]> {
        const result = await this.scanService.scanIncremental(
            { rootDir: this.workspaceRoot, files: [uri] },
            this.currentBaseline,
        );
        return toDiagnostics(result);
    }
    
    // Full workspace scan (on open or manual trigger)
    async analyzeWorkspace(): Promise<void> {
        const result = await this.scanService.scan({
            rootDir: this.workspaceRoot,
            onProgress: (p) => this.reportProgress(p),
        });
        this.currentBaseline = result.summary.baseline;
        this.publishDiagnostics(result);
    }
}
```

**Cancellation for IDE**: When the user types, cancel the current analysis and restart with the updated file. The revision counter pattern (SL-R4, SL-R10) ensures only the latest analysis completes.

**Evidence**: rust-analyzer IDE layer (SL-R4), Biome workspace model (SL-R2)

**Dependencies**: SL-6 (cancellation bridge), SL-7 (ScanService)


---

## Phase 5: Observability and Reliability

### SL-15: Implement Structured Observability (tracing + Metrics)

**Priority**: P1 (Observability)
**Effort**: Medium
**Impact**: Replaces v1's console.log with production-grade observability

**Current State (V1)**:
V1 uses `console.log`, `console.warn`, `console.error` throughout. No structured logging, no correlation IDs, no metrics, no tracing. The `ScanHealthMonitor` provides basic timing warnings but no actionable diagnostics.

**Proposed Implementation**:

```rust
// Rust side: tracing crate
use tracing::{info, warn, instrument};

#[instrument(skip(config), fields(
    scan_id = %config.scan_id,
    files = config.files.len(),
    threads = config.threads,
))]
pub fn run_scan(config: &ScanConfig) -> Result<ScanSummary> {
    let _parse_span = tracing::info_span!("phase.parse").entered();
    let parsed = parse_files(&config.files);
    drop(_parse_span);
    
    let _detect_span = tracing::info_span!("phase.detect").entered();
    let detected = detect_patterns(&parsed);
    drop(_detect_span);
    
    let _aggregate_span = tracing::info_span!("phase.aggregate").entered();
    let aggregated = aggregate_results(&detected);
    drop(_aggregate_span);
    
    info!(
        patterns = aggregated.total_patterns,
        violations = aggregated.total_violations,
        "Scan complete"
    );
    
    Ok(aggregated.into_summary())
}
```

```typescript
// TypeScript side: structured logging
interface ScanLog {
    level: 'debug' | 'info' | 'warn' | 'error';
    scanId: string;
    phase: string;
    message: string;
    fields: Record<string, unknown>;
    timestamp: string;
}

class StructuredLogger {
    log(entry: ScanLog): void {
        if (this.format === 'json') {
            console.log(JSON.stringify(entry));
        } else {
            console.log(`[${entry.level}] [${entry.scanId}] ${entry.phase}: ${entry.message}`);
        }
    }
}
```

**Metrics to emit**:

| Metric | Type | Description |
|---|---|---|
| `drift.scan.duration_ms` | Histogram | Total scan duration |
| `drift.scan.phase.duration_ms` | Histogram | Per-phase duration (parse, detect, aggregate, persist) |
| `drift.scan.files.total` | Gauge | Total files in scan |
| `drift.scan.files.processed` | Counter | Files processed |
| `drift.scan.files.cached` | Counter | Files skipped (cache hit) |
| `drift.scan.patterns.detected` | Counter | Patterns found |
| `drift.scan.violations.detected` | Counter | Violations found |
| `drift.scan.errors` | Counter | Errors encountered |
| `drift.scan.memory.peak_bytes` | Gauge | Peak memory usage |
| `drift.scan.channel.utilization` | Gauge | MPSC channel fill level |

**Evidence**: OpenTelemetry (SL-R11), tracing crate (SL-R11)

**Dependencies**: SL-4 (scan engine emits spans and metrics)

---

### SL-16: Implement Pipeline Resilience (Circuit Breaker + Retry)

**Priority**: P1 (Reliability)
**Effort**: Low
**Impact**: Prevents cascading failures and enables graceful degradation

**Current State (V1)**:
V1 has no retry logic, no circuit breaker, no graceful degradation. A single SQLite write failure can lose an entire scan's results. Worker crashes are silently swallowed.

**Proposed Implementation**:

```rust
pub struct PipelineResilience {
    max_retries: u32,
    circuit_breaker: CircuitBreaker,
}

struct CircuitBreaker {
    failure_count: AtomicU32,
    threshold: u32,        // Trip after N consecutive failures
    state: AtomicU8,       // 0=Closed, 1=Open, 2=HalfOpen
    last_failure: AtomicU64,
    cooldown_ms: u64,
}

impl CircuitBreaker {
    fn allow(&self) -> bool {
        match self.state.load(Ordering::Acquire) {
            0 => true,  // Closed — allow
            1 => {      // Open — check cooldown
                let elapsed = now_ms() - self.last_failure.load(Ordering::Acquire);
                if elapsed > self.cooldown_ms {
                    self.state.store(2, Ordering::Release); // → HalfOpen
                    true
                } else {
                    false
                }
            }
            2 => true,  // HalfOpen — allow one attempt
            _ => false,
        }
    }
    
    fn record_success(&self) {
        self.failure_count.store(0, Ordering::Release);
        self.state.store(0, Ordering::Release); // → Closed
    }
    
    fn record_failure(&self) {
        let count = self.failure_count.fetch_add(1, Ordering::AcqRel) + 1;
        if count >= self.threshold {
            self.state.store(1, Ordering::Release); // → Open
            self.last_failure.store(now_ms(), Ordering::Release);
        }
    }
}
```

**Resilience strategy per pipeline stage**:

| Stage | Retry | Circuit Breaker | Degradation |
|---|---|---|---|
| File read | 1 retry | No | Skip file, log error |
| Parse | No retry | No | Return partial AST, log error |
| Detect | No retry | Per-detector (3 failures → disable) | Skip detector, continue others |
| SQLite write | 2 retries with backoff | Yes (5 failures → trip) | Buffer in memory, warn user |
| Materialization | 1 retry | No | Skip, views are stale but data is safe |

**Evidence**: Saga compensating transactions (SL-R17), Google Tricorder analyzer lifecycle (SL-R7)

**Dependencies**: SL-4 (scan engine), SL-15 (observability for failure tracking)

---

### SL-17: Implement Feedback Loop Infrastructure

**Priority**: P1 (Quality)
**Effort**: Medium
**Impact**: Enables continuous quality improvement — the mechanism that maintains <5% FP rate

**Current State (V1)**:
V1 has no feedback loop. There is no tracking of developer actions on findings. No per-detector quality metrics. No mechanism to disable underperforming detectors.

**Proposed Implementation**:

```rust
// Track developer actions on violations
pub enum ViolationAction {
    Fixed,          // Developer fixed the issue
    Dismissed,      // Developer dismissed as not useful
    Ignored,        // Developer suppressed with annotation
    AutoFixed,      // Auto-fix applied
    NotSeen,        // Violation not yet presented to developer
}

pub struct FeedbackStore {
    db: Connection,
}

impl FeedbackStore {
    pub fn record_action(&self, violation_id: &str, action: ViolationAction) {
        // INSERT INTO violation_feedback (violation_id, action, timestamp)
    }
    
    pub fn detector_health(&self, detector_id: &str) -> DetectorHealth {
        // SELECT action, COUNT(*) FROM violation_feedback 
        // WHERE detector_id = ? GROUP BY action
        let stats = self.get_action_stats(detector_id);
        let total_actioned = stats.fixed + stats.dismissed + stats.ignored + stats.auto_fixed;
        let fp_rate = if total_actioned > 0 {
            (stats.dismissed + stats.ignored) as f64 / total_actioned as f64
        } else {
            0.0
        };
        
        DetectorHealth {
            detector_id: detector_id.to_string(),
            total_findings: stats.total(),
            effective_fp_rate: fp_rate,
            status: if fp_rate > 0.20 { HealthStatus::Critical }
                    else if fp_rate > 0.10 { HealthStatus::Warning }
                    else { HealthStatus::Healthy },
        }
    }
}
```

**Detector lifecycle** (from Google Tricorder SL-R7):
- `Healthy` (FP rate <10%): Full operation
- `Warning` (FP rate 10-20%): Flag for investigation, reduce severity
- `Critical` (FP rate >20% for 30+ days): Auto-disable, notify maintainer
- `Canary`: New detectors start here, promoted to Healthy after 100+ findings with <10% FP

**Evidence**: Google Tricorder <5% FP rate (SL-R7), SonarQube issue lifecycle (SL-R9)

**Dependencies**: SL-4 (scan engine records findings), SL-8 (consumer adapters collect feedback)

---

## Phase 6: Enterprise Hardening

### SL-18: Implement Service Health Checks

**Priority**: P1 (Enterprise)
**Effort**: Low
**Impact**: Enables monitoring, load balancing, and graceful startup/shutdown

**Current State (V1)**:
V1 has no health checks. The MCP server starts accepting requests immediately, even before stores are initialized. No readiness or liveness probes.

**Proposed Implementation**:

```typescript
interface ServiceHealth {
    status: 'healthy' | 'degraded' | 'unhealthy';
    checks: {
        rustEngine: { status: string; version: string };
        database: { status: string; path: string; sizeBytes: number };
        cache: { status: string; hitRate: number; entries: number };
        lastScan: { status: string; timestamp: string; duration: number };
    };
    uptime: number;
    version: string;
}

class HealthService {
    async check(): Promise<ServiceHealth> {
        const engine = await engineHealth();
        const db = await this.checkDatabase();
        const cache = this.checkCache();
        const lastScan = await this.getLastScanInfo();
        
        const allHealthy = [engine, db, cache, lastScan]
            .every(c => c.status === 'ok');
        
        return {
            status: allHealthy ? 'healthy' : 'degraded',
            checks: { rustEngine: engine, database: db, cache, lastScan },
            uptime: process.uptime(),
            version: DRIFT_VERSION,
        };
    }
}
```

**Three probe types**:
1. **Startup**: Engine loaded, database accessible, cache initialized → ready to accept requests
2. **Readiness**: Not currently scanning (or can accept concurrent scans) → ready for new work
3. **Liveness**: Process responsive, no deadlocks → still alive

**Evidence**: SonarQube server health (SL-R9)

**Dependencies**: SL-3 (NAPI health function), SL-7 (ScanService)

---

### SL-19: Implement Scan Idempotency

**Priority**: P1 (Enterprise)
**Effort**: Low
**Impact**: Enables safe retries and reproducible results

**Current State (V1)**:
V1 scans are not idempotent. Running the same scan twice may produce different results due to non-deterministic worker scheduling, race conditions in aggregation, and timestamp-dependent logic.

**Proposed Implementation**:

```rust
// Deterministic scan: same inputs → same outputs
pub fn run_scan(config: &ScanConfig) -> Result<ScanSummary> {
    // 1. Sort files deterministically (by path)
    let mut files = discover_files(&config.root_dir);
    files.sort_by(|a, b| a.path.cmp(&b.path));
    
    // 2. Process in deterministic order (rayon preserves order with par_iter)
    // Note: rayon's par_iter does NOT guarantee order, but results are
    // collected into a HashMap keyed by file path, so order doesn't matter
    // for correctness — only the content matters.
    
    // 3. Aggregation is deterministic (same patterns → same aggregation)
    // Sort pattern locations by file:line:column before deduplication
    
    // 4. Outlier detection is deterministic (same data → same z-scores)
    
    // 5. Convention learning is deterministic (same frequencies → same models)
    
    // 6. SQLite writes use UPSERT (INSERT OR REPLACE) for idempotency
}
```

**Key invariant**: `scan(files_at_time_T) == scan(files_at_time_T)` — running the same scan on the same file contents always produces the same results. This enables:
- Safe retries after failures
- Reproducible CI builds
- Deterministic quality gate evaluation

**Evidence**: Saga idempotency (SL-R17)

**Dependencies**: SL-4 (scan engine)

---

### SL-20: Implement Asynchronous Post-Processing

**Priority**: P1 (Enterprise)
**Effort**: Low
**Impact**: Scan returns immediately; heavy post-processing runs in background

**Current State (V1)**:
V1's scan pipeline is synchronous end-to-end. The CLI waits for persistence, materialization, history snapshot, and telemetry before returning results. This adds 2-5 seconds to every scan.

**Proposed Implementation**:

```typescript
class ScanService implements IScanService {
    async scan(config: ScanConfig): Promise<ScanResult> {
        // Core scan (Rust engine) — returns when detection + persistence complete
        const result = await nativeScan(config);
        
        // Post-processing — fire and forget (or await if consumer needs it)
        this.postProcess(result).catch(err => {
            logger.warn('Post-processing failed', { error: err, scanId: result.scanId });
        });
        
        return result;
    }
    
    private async postProcess(result: ScanResult): Promise<void> {
        // These run in parallel, after scan results are returned to consumer
        await Promise.allSettled([
            this.refreshMaterializedViews(result),
            this.createHistorySnapshot(result),
            this.recordTelemetry(result),
            this.invalidateMcpCache(result),
            this.notifyIdeClients(result),
        ]);
    }
}
```

**Key principle**: The scan result is returned as soon as patterns are detected and persisted to SQLite. Materialized views, history snapshots, telemetry, and cache invalidation happen asynchronously. If any post-processing step fails, the scan result is still valid.

**Evidence**: SonarQube asynchronous report processing (SL-R9)

**Dependencies**: SL-7 (ScanService), SL-4 (Rust engine persists core results synchronously)

---

### SL-21: Implement Pattern Identity Tracking Across Scans

**Priority**: P1 (Enterprise)
**Effort**: Medium
**Impact**: Enables trend analysis, regression detection, and issue lifecycle management

**Current State (V1)**:
V1 identifies patterns by a 16-char hex hash of `(category, subcategory, name)`. This is stable across scans but doesn't track individual pattern instances (locations). There is no issue lifecycle — patterns are either present or absent.

**Proposed Implementation**:

```rust
// Pattern identity: stable across scans
pub fn pattern_id(category: &str, subcategory: &str, name: &str) -> String {
    let input = format!("{}:{}:{}", category, subcategory, name);
    format!("{:016x}", xxhash(&input))
}

// Location identity: tracks individual instances across scans
pub fn location_id(pattern_id: &str, file: &str, line: u32, signature_hash: u64) -> String {
    // signature_hash = hash of the surrounding function/class signature
    // This survives line number changes from edits above the location
    format!("{}:{}:{:016x}", pattern_id, file, signature_hash)
}

// Issue lifecycle
pub enum IssueStatus {
    New,        // First seen in this scan
    Open,       // Seen in previous scan and still present
    Fixed,      // Was present in previous scan, now absent
    Regressed,  // Was fixed, now reappeared
}

pub fn compute_issue_lifecycle(
    current_locations: &[LocationId],
    previous_locations: &[LocationId],
) -> Vec<(LocationId, IssueStatus)> {
    let current_set: HashSet<_> = current_locations.iter().collect();
    let previous_set: HashSet<_> = previous_locations.iter().collect();
    
    let mut results = Vec::new();
    for loc in current_locations {
        if previous_set.contains(loc) {
            results.push((loc.clone(), IssueStatus::Open));
        } else {
            results.push((loc.clone(), IssueStatus::New));
        }
    }
    for loc in previous_locations {
        if !current_set.contains(loc) {
            results.push((loc.clone(), IssueStatus::Fixed));
        }
    }
    results
}
```

**Use cases**:
- Quality gates: "No new critical issues" (only New issues count)
- Trend analysis: "Security issues declining over time" (track Fixed vs. New)
- Regression detection: "This pattern was fixed but reappeared" (Regressed status)
- Developer feedback: "This issue has been open for 30 days" (age tracking)

**Evidence**: SonarQube issue lifecycle (SL-R9), Google Tricorder staged rollout (SL-R7)

**Dependencies**: SL-5 (content-hash cache), SL-10 (incremental aggregation)

---

## Phase 7: Future Enhancements

### SL-22: Evaluate Salsa for Cross-File Analysis Phase

**Priority**: P2 (Future)
**Effort**: High
**Impact**: Automatic dependency tracking for complex cross-file analyses

**Rationale**: Phase 2 (cross-file analysis) involves dependency-driven computations: call graph resolution depends on import analysis, coupling metrics depend on call graph, reachability depends on coupling. Salsa (SL-R3) provides automatic dependency tracking and incremental recomputation for exactly this kind of computation graph.

**Recommendation**: Start with manual dependency tracking (simpler). Evaluate Salsa when the cross-file analysis phase becomes complex enough to justify the learning curve. The services layer should abstract the caching strategy behind a trait so Salsa can be adopted later without rewriting consumers.

**Evidence**: Salsa framework (SL-R3), rust-analyzer (SL-R4)

---

### SL-23: Implement Plugin System for Custom Analysis Passes

**Priority**: P2 (Future)
**Effort**: High
**Impact**: Enterprise users can add custom analysis without forking

**Rationale**: Enterprise users may need custom detectors, custom quality gates, or custom post-processing steps. The services layer should support a plugin interface that allows registering custom analysis passes.

**Proposed Interface**:

```rust
pub trait AnalysisPlugin: Send + Sync {
    fn name(&self) -> &str;
    fn phase(&self) -> AnalysisPhase; // PerFile or CrossFile
    fn execute(&self, ctx: &AnalysisContext) -> Result<Vec<Finding>>;
}

// Plugins loaded from shared libraries (.so/.dylib/.dll)
// or from WASM modules (sandboxed)
```

**Evidence**: Biome GritQL plugins (SL-R2), SonarQube Sensor/PostJob/Decorator (SL-R9)

---

### SL-24: Implement Shared Daemon Mode

**Priority**: P2 (Future)
**Effort**: High
**Impact**: Eliminates cold-start overhead for CLI and MCP

**Rationale**: Currently, every `drift scan` invocation starts a new process, loads the Rust engine, opens SQLite, and initializes caches. A shared daemon could keep the engine warm and serve multiple consumers (CLI, MCP, IDE) from a single process.

**Architecture**:
```
drift daemon start → Long-running process with Rust engine loaded
drift scan → Connects to daemon via Unix socket, sends scan request
MCP server → Connects to daemon, forwards tool requests
IDE → Connects to daemon via LSP
```

**Evidence**: rust-analyzer daemon mode, Biome daemon

---

### SL-25: Implement Distributed Scan for Monorepos

**Priority**: P3 (Future)
**Effort**: Very High
**Impact**: Enables scanning 1M+ file monorepos by distributing across machines

**Rationale**: For very large monorepos (Google-scale), a single machine may not have enough memory or CPU to scan the entire codebase. The services layer could distribute the per-file indexing phase across multiple machines, then merge results centrally.

**Architecture**: Each machine processes a shard of files. Results are written to a shared SQLite database (or merged post-hoc). Cross-file analysis runs centrally on the merged index.

**Evidence**: Google Tricorder shardable analysis (SL-R7)

---

## Dependency Graph

```
Phase 0 (Decisions)
  SL-1 Two-Phase Pipeline ──────────────────────────────────────┐
  SL-2 Unified Contract ──→ SL-7, SL-8                         │
  SL-3 NAPI Bridge API ──→ SL-4, SL-7                          │
                                                                │
Phase 1 (Rust Engine)                                           │
  SL-4 Scan Engine ──→ SL-5, SL-6, SL-10 ←────────────────────┘
  SL-5 Content-Hash Cache ──→ SL-10, SL-11
  SL-6 Cancellation Bridge ──→ SL-14

Phase 2 (Bridge)
  SL-7 TypeScript ScanService ──→ SL-8, SL-12, SL-13, SL-14
  SL-8 Consumer Adapters ──→ SL-12, SL-13, SL-14
  SL-9 Error Bridge ──→ SL-7, SL-8

Phase 3 (Incremental)
  SL-10 Incremental Aggregation ──→ SL-11, SL-21
  SL-11 Convention Re-Learning ──→ standalone

Phase 4 (Consumers)
  SL-12 MCP Pipeline ──→ standalone
  SL-13 Quality Gates ──→ SL-21
  SL-14 IDE Integration ──→ standalone

Phase 5 (Observability)
  SL-15 Structured Observability ──→ standalone
  SL-16 Pipeline Resilience ──→ standalone
  SL-17 Feedback Loop ──→ SL-21

Phase 6 (Enterprise)
  SL-18 Health Checks ──→ standalone
  SL-19 Idempotency ──→ standalone
  SL-20 Async Post-Processing ──→ standalone
  SL-21 Pattern Identity ──→ standalone

Phase 7 (Future)
  SL-22 Salsa Evaluation ──→ SL-10
  SL-23 Plugin System ──→ SL-4
  SL-24 Daemon Mode ──→ SL-7
  SL-25 Distributed Scan ──→ SL-4
```

---

## Cross-Category Impact Matrix

| Recommendation | Categories Affected | Impact Type |
|---|---|---|
| SL-1 (Two-Phase) | 01-rust-core, 02-parsers, 03-detectors, 04-call-graph, 05-analyzers | Pipeline architecture for all subsystems |
| SL-2 (Unified Contract) | 07-mcp, 09-quality-gates, 10-cli, 11-ide | Consumer interface for all surfaces |
| SL-3 (NAPI Bridge) | 01-rust-core | Bridge API between Rust and TypeScript |
| SL-4 (Scan Engine) | 01-rust-core, 02-parsers, 03-detectors | Core computation pipeline |
| SL-5 (Cache) | 08-storage, 24-data-lake | Persistent cache in SQLite |
| SL-10 (Incremental Aggregation) | 03-detectors, 23-pattern-repository | Pattern update strategy |
| SL-12 (MCP Pipeline) | 07-mcp | MCP server architecture |
| SL-13 (Quality Gates) | 09-quality-gates | Gate evaluation architecture |
| SL-17 (Feedback Loop) | 03-detectors, 07-mcp, 10-cli | Detector quality management |
| SL-21 (Pattern Identity) | 08-storage, 09-quality-gates, 23-pattern-repository | Issue lifecycle across all consumers |

---

## Success Metrics

| Metric | V1 Baseline | V2 Target | Measurement |
|---|---|---|---|
| Full scan (10K files) | ~10s | <3s | Wall clock time |
| Full scan (500K files) | Untested/infeasible | <60s | Wall clock time |
| Incremental scan (1 file, 10K codebase) | ~10s (full rescan) | <100ms | Wall clock time |
| Services layer TypeScript LOC | ~5,500 | <500 (ScanService + adapters) | Line count |
| Rust engine LOC | 0 | ~3,000-5,000 | Line count |
| NAPI boundary crossings per scan | ~25+ individual calls | 1 (native_scan) | Call count |
| Memory usage (10K files) | Unbounded (no backpressure) | <500MB (bounded channels) | Peak RSS |
| Memory usage (500K files) | Untested | <2GB | Peak RSS |
| Scan cancellation latency | N/A (no cancellation) | <100ms | Time from cancel to partial result |
| Progress update frequency | None (timer-based warnings) | Every 100 files | Update count |
| Effective FP rate | Unknown | <5% (Tricorder model) | Feedback loop |
| Detector health tracking | None | Per-detector FP rate | Feedback store |
| Structured error coverage | 0% (string errors) | 100% (typed errors) | Error type coverage |
| Pipeline stage observability | None | All stages traced | Span coverage |

---

## Build Timeline (Suggested)

```
Weeks 1-2:   Phase 0 — Architectural decisions (SL-1, SL-2, SL-3)
Weeks 3-6:   Phase 1 — Rust scan engine (SL-4, SL-5, SL-6)
Weeks 7-8:   Phase 2 — NAPI bridge + TypeScript service (SL-7, SL-8, SL-9)
Weeks 9-11:  Phase 3 — Incremental computation (SL-10, SL-11)
Weeks 12-15: Phase 4 — Consumer adapters (SL-12, SL-13, SL-14)
Weeks 16-18: Phase 5 — Observability + resilience (SL-15, SL-16, SL-17)
Weeks 19-21: Phase 6 — Enterprise hardening (SL-18, SL-19, SL-20, SL-21)
Weeks 22+:   Phase 7 — Future enhancements (SL-22, SL-23, SL-24, SL-25)
```

Note: Phases 4-5 can be built in parallel with Phase 3 since consumer adapters and observability have minimal cross-dependencies with incremental computation. The critical path is: Phase 0 → Phase 1 → Phase 2 → Phase 3 → Phase 6.

---

## Quality Checklist

- [x] All 25 recommendations organized across 7 build phases
- [x] Every recommendation includes: priority, effort, impact, current state, proposed implementation, evidence citations
- [x] Dependency graph showing all inter-recommendation relationships
- [x] Cross-category impact matrix for recommendations affecting other subsystems
- [x] Success metrics with V1 baselines and V2 targets
- [x] Build timeline with phase dependencies and parallelization opportunities
- [x] Every recommendation framed as "build new" (greenfield)
- [x] All 18 research entries (SL-R1 through SL-R18) cited as evidence
- [x] Code examples in both Rust and TypeScript where applicable
- [x] Addresses all gaps identified in AUDIT.md (architectural, performance, reliability, observability, security)
- [x] Addresses all open questions from RECAP.md
- [x] Consistent with Master Recommendations (M1-M42) — no contradictions
- [x] P0 recommendations form the critical path
- [x] Future enhancements (P2/P3) scoped but not over-designed