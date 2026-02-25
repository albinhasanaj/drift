# NAPI Bridge (drift-napi) — V2 Implementation Prep

> Comprehensive build specification for Drift v2's NAPI bridge layer.
> Synthesized from: 03-NAPI-BRIDGE.md, DRIFT-V2-FULL-SYSTEM-AUDIT.md (Cat 01, A11, A21),
> DRIFT-V2-STACK-HIERARCHY.md (Level 0 Bedrock), PLANNING-DRIFT.md (D1-D7),
> 00-SCANNER-V2-PREP.md (§12 NAPI Interface), 01-PARSERS.md, 02-STORAGE-V2-PREP.md,
> 04-INFRASTRUCTURE.md, 05-CALL-GRAPH.md, existing cortex-napi implementation
> (crates/cortex/cortex-napi — 33 functions, 12 binding modules, 6 conversion modules),
> napi-rs v3 announcement (July 2025), v2→v3 migration guide, and ThreadsafeFunction v3 docs.
>
> Purpose: Everything needed to build drift-napi from scratch. Decisions resolved,
> inconsistencies flagged, interface contracts defined, build order specified.
> Generated: 2026-02-07

---

## 1. Architectural Position

The NAPI bridge is Level 0 Bedrock. It is the only door between Rust analysis and TypeScript
presentation. Every MCP tool call, every CLI command, every IDE action, every dashboard query
crosses this boundary. Without it, Rust computation is trapped — no MCP, no CLI, no VSCode, no LSP.

Per PLANNING-DRIFT.md D1: Drift is standalone. drift-napi depends only on drift-core.
Per PLANNING-DRIFT.md D4: The bridge crate (cortex-drift-napi) is separate and optional.

### What Lives Here
- All Rust analysis exposed to Node.js via napi-rs v3
- Singleton `DriftRuntime` owning all engines (scanner, parsers, detectors, call graph, etc.)
- ~40+ exported NAPI functions across ~15 binding modules
- Structured error propagation (Rust error enums → NAPI error codes)
- Async operations via `AsyncTask` for long-running analysis
- Progress callbacks via v3 `ThreadsafeFunction` for scan operations
- Batch API for multi-analysis single-call workflows
- Keyset pagination for all list operations
- Cancellation support via `AtomicBool`
- 7 native platform targets + wasm32 fallback

### What Does NOT Live Here
- cortex-napi (separate crate, Cortex standalone)
- cortex-drift-napi (bridge crate, optional, depends on both)
- Any analysis logic (lives in drift-core)
- Any TS orchestration logic (lives in packages/drift)
- sqlite-vec extension (Cortex only)

---

## 2. Core Library: napi-rs v3

### Why v3 Over v2

The existing cortex-napi uses napi-rs v2. Drift v2 uses napi-rs v3 (released July 2025).
This is a deliberate divergence — Cortex can migrate to v3 later, but Drift starts fresh on v3.

Key v3 improvements relevant to Drift:

1. **WebAssembly support** — Compile to `wasm32-wasip1-threads` with almost no code changes.
   Enables browser playgrounds (like Rolldown repl, Oxc playground), StackBlitz support,
   and fallback packages for unsupported platforms. This is how Rolldown and Oxc provide
   their playgrounds. For Drift, this means a `drift-napi-wasm` fallback package that works
   everywhere, even on platforms without pre-built native binaries.

2. **Lifetime safety** — v3 introduces Rust lifetimes to NAPI types. In v2, `JsObject` could
   escape its scope and be used after the underlying `napi_value` became invalid. v3 constrains
   this with lifetimes. Several v2 types (`JsObject`, `JsFunction`, `JsNull`, `JsBoolean`,
   `JsUndefined`, `JsBuffer`, `JsTypedArray`, `Ref`) are now behind a `compat-mode` feature
   flag. Drift v2 uses the new safe APIs exclusively — no `compat-mode`.

3. **Redesigned ThreadsafeFunction** — The v2 API was notoriously difficult because it leaked
   Node-API's complexity (ref/unref, acquire/release). v3 hides these concepts behind ownership
   semantics. Use `Arc<ThreadsafeFunction>` for multi-thread sharing. TypeScript type generation
   is now correct (v2 could only generate `(...args: any[]) => any`). This is critical for
   Drift's progress callbacks during scan operations.

4. **Cross-compilation improvements** — No more huge Docker images. Uses `cargo-zigbuild` or
   `@napi-rs/cross-toolchain` for GLIBC 2.17 support across all Linux targets. The `napi build
   --use-napi-cross` flag handles everything. Also integrates `cargo-xwin` for Windows targets.

5. **`#[napi(module_exports)]`** — Replaces `#[module_exports]` from compat-mode. Clean module
   initialization without the `compat-mode` feature flag.

6. **CLI rewrite** — `napi.name` → `napi.binaryName`, `napi.triples` → `napi.targets`,
   `--cargo-flags` removed (use `--` passthrough), `create-npm-dir` → `create-npm-dirs`.

### Cargo.toml Dependencies

```toml
[package]
name = "drift-napi"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
drift-core = { path = "../drift-core" }
napi = { version = "3", features = ["async", "serde-json"] }
napi-derive = "3"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tokio = { version = "1", features = ["rt", "macros"] }

[build-dependencies]
napi-build = "3"
```

Note: No `compat-mode` feature. Drift uses v3 APIs exclusively.

### build.rs

```rust
extern crate napi_build;

fn main() {
    napi_build::setup();
}
```

### package.json (napi config)

```json
{
  "name": "drift-napi",
  "napi": {
    "binaryName": "drift-napi",
    "targets": [
      "x86_64-apple-darwin",
      "aarch64-apple-darwin",
      "x86_64-unknown-linux-gnu",
      "x86_64-unknown-linux-musl",
      "aarch64-unknown-linux-gnu",
      "aarch64-unknown-linux-musl",
      "x86_64-pc-windows-msvc",
      "wasm32-wasip1-threads"
    ]
  }
}
```

8 targets: 7 native + wasm32 fallback (v3 addition).

---

## 3. Resolved Inconsistency: v2 vs v3 API Patterns

The existing 03-NAPI-BRIDGE.md research doc was written before the v3 migration guide was
available. Several code examples use v2 patterns that need updating.

### ThreadsafeFunction (v2 → v3)

**v2 pattern (from 03-NAPI-BRIDGE.md):**
```rust
// v2 — uses NonBlocking mode enum, complex API
pub fn scan_with_progress(
    root: String,
    options: ScanOptions,
    progress_callback: ThreadsafeFunction<ProgressUpdate, NonBlocking>,
) -> AsyncTask<ScanWithProgressTask> { ... }
```

**v3 pattern (corrected):**
```rust
use napi::bindgen_prelude::*;
use napi::threadsafe_function::ThreadsafeFunction;

/// Scan with progress reporting via ThreadsafeFunction.
/// The callback receives ProgressUpdate objects periodically.
/// Uses v3's ownership-based lifecycle (no manual ref/unref).
#[napi]
pub fn native_scan_with_progress(
    root: String,
    options: ScanOptions,
    on_progress: ThreadsafeFunction<ProgressUpdate, ()>,
) -> AsyncTask<ScanWithProgressTask> {
    let tsfn = Arc::new(on_progress);
    AsyncTask::new(ScanWithProgressTask { root, options, tsfn })
}
```

v3 changes:
- `NonBlocking` mode is no longer a generic parameter — it's the default behavior
- TypeScript types are correctly generated from `FnArgs` and `Return` generics
- Use `Arc<ThreadsafeFunction>` for sharing across threads (rayon workers)
- No manual `acquire()`/`release()` — ownership handles lifecycle

### JsObject / JsFunction Removal

v2 code using `JsObject` for complex return types must be replaced with serde-based
serialization in v3. This is already the pattern used by cortex-napi (all functions
return `serde_json::Value` or derive `#[napi(object)]` structs).

**v3 pattern — use `#[napi(object)]` structs:**
```rust
#[napi(object)]
pub struct ScanSummary {
    pub files_total: u32,
    pub files_added: u32,
    pub files_modified: u32,
    pub files_removed: u32,
    pub files_unchanged: u32,
    pub duration_ms: u32,
    pub status: String,
    pub languages: HashMap<String, u32>,
}
```

Or use `serde_json::Value` for dynamic/complex types (same as cortex-napi pattern).

---

## 4. Singleton Runtime Pattern (Proven by Cortex)

The cortex-napi implementation proves the singleton runtime pattern works well.
Drift follows the same architecture with `DriftRuntime` instead of `CortexRuntime`.

### Key Difference: Synchronous Core

Cortex uses `tokio` for async operations (embedding generation, cloud sync).
Drift's core is synchronous — `rayon` for parallelism, no async runtime needed
for the analysis pipeline. However, NAPI `AsyncTask` still needs a way to run
Rust code off the main thread.

**Decision**: Drift uses `rayon` internally (no tokio for core analysis).
`AsyncTask` runs Rust code on libuv's thread pool (not tokio). Only use tokio
if a specific subsystem needs it (e.g., HTTP transport for MCP server).

```rust
use std::sync::{Arc, OnceLock};

static RUNTIME: OnceLock<Arc<DriftRuntime>> = OnceLock::new();

pub struct DriftRuntime {
    pub db: DatabaseManager,
    pub config: DriftConfig,
    pub event_handlers: Vec<Arc<dyn DriftEventHandler>>,
    // No Mutex wrappers needed — DatabaseManager handles its own
    // write serialization internally (Mutex<Connection> for writer,
    // read pool for readers). Scanner/parsers/detectors are stateless
    // or use thread_local! storage.
}

pub fn initialize(opts: RuntimeOptions) -> napi::Result<()> {
    let runtime = DriftRuntime::new(opts)
        .map_err(|e| napi::Error::from_reason(format!("[INIT_ERROR] {e}")))?;
    RUNTIME.set(Arc::new(runtime)).map_err(|_| {
        napi::Error::from_reason("[ALREADY_INITIALIZED] Runtime already initialized")
    })
}

pub fn get() -> napi::Result<Arc<DriftRuntime>> {
    RUNTIME
        .get()
        .cloned()
        .ok_or_else(|| {
            napi::Error::from_reason(
                "[RUNTIME_NOT_INITIALIZED] Call driftInitialize() first"
            )
        })
}
```

### RuntimeOptions

```rust
#[derive(Default)]
pub struct RuntimeOptions {
    /// Path to drift.db. If None, uses default location (.drift/drift.db).
    pub db_path: Option<PathBuf>,
    /// Path to project root for scanning.
    pub project_root: Option<PathBuf>,
    /// TOML configuration string. If None, loads from drift.toml.
    pub config_toml: Option<String>,
    /// Whether to attach cortex.db for cross-DB queries (bridge mode).
    pub attach_cortex: bool,
}
```

### Why OnceLock (Not Mutex<Option<T>>)

Same reasoning as cortex-napi: `OnceLock` is lock-free after initialization.
The runtime is initialized once and read many times. `Mutex<Option<T>>` would
add unnecessary contention on every NAPI call.

---

## 5. The Core Principle: Minimize NAPI Boundary Crossing

This is the single most important architectural decision for drift-napi.
From audit A21 and the 03-NAPI-BRIDGE.md research:

**Rust does ALL heavy computation AND writes results to drift.db.**
**The NAPI return value is a lightweight summary, not the full result set.**
**TS queries drift.db via thin NAPI query functions for specific data.**

### Why This Matters

NAPI serialization is expensive for large data:
- Every Rust struct → JS object requires allocation + field-by-field copying
- Large `Vec<T>` creates GC pressure on the Node.js side
- For 100K patterns, serialization time can exceed computation time
- serde_json intermediate step adds another allocation layer

### The Two Function Categories

**Category 1: Command Functions (write-heavy, return summary)**
These perform analysis, write results to drift.db, and return a lightweight summary.
The summary is small enough that NAPI serialization overhead is negligible.

```rust
// Command: scan → write to drift.db → return summary
#[napi]
pub fn native_scan(root: String, options: ScanOptions) -> napi::Result<ScanSummary> { ... }

// Command: build call graph → write to drift.db → return stats
#[napi]
pub fn build_call_graph(root: String) -> napi::Result<CallGraphStats> { ... }

// Command: run quality gates → write to drift.db → return gate results
#[napi]
pub fn run_quality_gates(policy: String) -> napi::Result<GateResults> { ... }
```

**Category 2: Query Functions (read-only, return paginated data)**
These read from drift.db and return filtered, paginated results.
Result sets are bounded (max 50-100 items per page).

```rust
// Query: read patterns from drift.db with filters + pagination
#[napi]
pub fn query_patterns(filter: PatternFilter) -> napi::Result<PaginatedResult> { ... }

// Query: read call graph subgraph from drift.db
#[napi]
pub fn query_call_graph(function_id: String, depth: u32) -> napi::Result<CallGraphResult> { ... }

// Query: read violations from drift.db
#[napi]
pub fn query_violations(filter: ViolationFilter) -> napi::Result<PaginatedResult> { ... }
```

### What Crosses NAPI (lightweight summaries and queries)
- `ScanSummary` — counts, duration, status, language breakdown
- `PatternSummary` — id, name, category, confidence, location count
- `ViolationSummary` — pattern_id, file, line, severity, message, quick_fix
- `CallGraphSubset` — small subgraph for a specific query (max depth)
- `HealthScore` — single number + breakdown
- `GateResults` — pass/fail per gate + aggregate
- Paginated query results — max 50-100 items per page

### What Does NOT Cross NAPI (stays in Rust/SQLite)
- Full parse results (ASTs) — never leave Rust
- Raw detection matches — written directly to drift.db
- Complete call graph (100K+ edges) — in petgraph + drift.db
- All pattern locations — in drift.db, queried on demand
- Intermediate analysis state — ephemeral, Rust-only
- Tree-sitter `Tree` objects — not serializable, thread_local!


---

## 6. Error Propagation (Structured Error Codes)

### The Pattern (Proven by Cortex)

Cortex-napi's error handling pattern works well and Drift adopts it identically.
Rust error enums → structured NAPI error codes → TS client parses codes programmatically.

### Drift Error Code Registry

```rust
pub mod codes {
    // Lifecycle
    pub const INIT_ERROR: &str = "INIT_ERROR";
    pub const ALREADY_INITIALIZED: &str = "ALREADY_INITIALIZED";
    pub const RUNTIME_NOT_INITIALIZED: &str = "RUNTIME_NOT_INITIALIZED";
    pub const CONFIG_ERROR: &str = "CONFIG_ERROR";

    // Scanner
    pub const SCAN_ERROR: &str = "SCAN_ERROR";
    pub const SCAN_CANCELLED: &str = "SCAN_CANCELLED";
    pub const FILE_TOO_LARGE: &str = "FILE_TOO_LARGE";
    pub const PERMISSION_DENIED: &str = "PERMISSION_DENIED";

    // Parser
    pub const PARSE_ERROR: &str = "PARSE_ERROR";
    pub const UNSUPPORTED_LANGUAGE: &str = "UNSUPPORTED_LANGUAGE";
    pub const QUERY_COMPILATION: &str = "QUERY_COMPILATION";

    // Storage
    pub const STORAGE_ERROR: &str = "STORAGE_ERROR";
    pub const DB_BUSY: &str = "DB_BUSY";
    pub const DB_CORRUPT: &str = "DB_CORRUPT";
    pub const DB_DISK_FULL: &str = "DB_DISK_FULL";
    pub const MIGRATION_FAILED: &str = "MIGRATION_FAILED";
    pub const LOCK_POISONED: &str = "LOCK_POISONED";

    // Analysis
    pub const ANALYSIS_ERROR: &str = "ANALYSIS_ERROR";
    pub const CALL_GRAPH_ERROR: &str = "CALL_GRAPH_ERROR";
    pub const DETECTION_ERROR: &str = "DETECTION_ERROR";
    pub const BOUNDARY_ERROR: &str = "BOUNDARY_ERROR";
    pub const TAINT_ERROR: &str = "TAINT_ERROR";
    pub const CONSTRAINT_ERROR: &str = "CONSTRAINT_ERROR";

    // Query
    pub const NOT_FOUND: &str = "NOT_FOUND";
    pub const INVALID_CURSOR: &str = "INVALID_CURSOR";
    pub const INVALID_FILTER: &str = "INVALID_FILTER";

    // General
    pub const INTERNAL_ERROR: &str = "INTERNAL_ERROR";
    pub const CANCELLED: &str = "CANCELLED";
}
```

### Conversion Pattern

Each subsystem error enum converts to a structured NAPI error with a code prefix.
The TS client parses the code from the message format: `[ERROR_CODE] Human-readable message`.

```rust
use drift_core::errors::*;

pub fn to_napi_error(err: impl std::fmt::Display + DriftErrorCode) -> napi::Error {
    let code = err.error_code();
    napi::Error::new(
        napi::Status::GenericFailure,
        format!("[{}] {}", code, err),
    )
}

/// Trait implemented by all drift-core error enums.
pub trait DriftErrorCode {
    fn error_code(&self) -> &'static str;
}

impl DriftErrorCode for ScanError {
    fn error_code(&self) -> &'static str {
        match self {
            ScanError::Io { .. } => codes::SCAN_ERROR,
            ScanError::FileTooLarge { .. } => codes::FILE_TOO_LARGE,
            ScanError::PermissionDenied { .. } => codes::PERMISSION_DENIED,
            ScanError::Cancelled => codes::SCAN_CANCELLED,
            ScanError::Config { .. } => codes::CONFIG_ERROR,
            ScanError::Storage(_) => codes::STORAGE_ERROR,
        }
    }
}

impl DriftErrorCode for ParseError {
    fn error_code(&self) -> &'static str {
        match self {
            ParseError::UnsupportedLanguage { .. } => codes::UNSUPPORTED_LANGUAGE,
            ParseError::ParseFailed { .. } => codes::PARSE_ERROR,
            ParseError::QueryCompilation(_) => codes::QUERY_COMPILATION,
        }
    }
}

impl DriftErrorCode for StorageError {
    fn error_code(&self) -> &'static str {
        match self {
            StorageError::Busy => codes::DB_BUSY,
            StorageError::Corrupt(_) => codes::DB_CORRUPT,
            StorageError::DiskFull => codes::DB_DISK_FULL,
            StorageError::MigrationFailed { .. } => codes::MIGRATION_FAILED,
            StorageError::LockPoisoned => codes::LOCK_POISONED,
            StorageError::Sqlite(_) => codes::STORAGE_ERROR,
        }
    }
}
```

### TypeScript Client Error Parsing

Same pattern as cortex-napi's `CortexClient`:

```typescript
export class DriftError extends Error {
    constructor(
        public readonly code: string,
        message: string,
    ) {
        super(message);
        this.name = "DriftError";
    }
}

function parseNapiError(err: unknown): DriftError {
    const message = err instanceof Error ? err.message : String(err);
    const match = /^\[([A-Z_]+)\]\s*(.+)$/.exec(message);
    if (match) {
        return new DriftError(match[1], match[2]);
    }
    return new DriftError("UNKNOWN", message);
}
```

This enables programmatic error handling in TS:
```typescript
try {
    await drift.scan(root);
} catch (err) {
    if (err instanceof DriftError) {
        switch (err.code) {
            case "DB_BUSY": // retry
            case "SCAN_CANCELLED": // expected, ignore
            case "DB_CORRUPT": // suggest drift doctor
        }
    }
}
```

---

## 7. Async Operations & Progress Callbacks

### When to Use AsyncTask

Any operation that takes >10ms should be async to avoid blocking the Node.js event loop.
In practice, this means all command functions (scan, build call graph, run gates) are async.
Query functions can be sync if they hit indexed SQLite queries (<5ms).

### AsyncTask Pattern (v3)

```rust
use napi::bindgen_prelude::*;

pub struct ScanTask {
    root: String,
    options: ScanOptions,
}

#[napi]
impl Task for ScanTask {
    type Output = ScanSummary;
    type JsValue = ScanSummary;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        // Runs on libuv thread pool, NOT the main JS thread.
        // Safe to do heavy computation here.
        let rt = crate::runtime::get()?;
        let diff = drift_core::scanner::scan(
            &PathBuf::from(&self.root),
            &rt.config.scan,
            &rt.db,
            &NoOpEventHandler,
        ).map_err(to_napi_error)?;

        // Write results to drift.db (happens in Rust, not crossing NAPI)
        drift_core::storage::persist_scan_results(&rt.db, &diff)
            .map_err(to_napi_error)?;

        Ok(ScanSummary::from(diff))
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> napi::Result<Self::JsValue> {
        Ok(output)
    }
}

#[napi]
pub fn native_scan_async(root: String, options: ScanOptions) -> AsyncTask<ScanTask> {
    AsyncTask::new(ScanTask { root, options })
}
```

### Progress Callbacks via ThreadsafeFunction (v3)

For long-running operations (full scan of 100K files), report progress back to TS.
Uses v3's redesigned ThreadsafeFunction with proper ownership semantics.

```rust
use std::sync::Arc;
use napi::threadsafe_function::ThreadsafeFunction;

#[napi(object)]
pub struct ProgressUpdate {
    pub processed: u32,
    pub total: u32,
    pub phase: String,           // "discovery", "hashing", "parsing", "detection"
    pub current_file: Option<String>,
}

pub struct ScanWithProgressTask {
    root: String,
    options: ScanOptions,
    on_progress: Arc<ThreadsafeFunction<ProgressUpdate, ()>>,
}

#[napi]
impl Task for ScanWithProgressTask {
    type Output = ScanSummary;
    type JsValue = ScanSummary;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        let rt = crate::runtime::get()?;
        let tsfn = self.on_progress.clone();

        // Create a DriftEventHandler that forwards progress to the ThreadsafeFunction
        let progress_handler = NapiProgressHandler::new(tsfn);

        let diff = drift_core::scanner::scan(
            &PathBuf::from(&self.root),
            &rt.config.scan,
            &rt.db,
            &progress_handler,
        ).map_err(to_napi_error)?;

        drift_core::storage::persist_scan_results(&rt.db, &diff)
            .map_err(to_napi_error)?;

        Ok(ScanSummary::from(diff))
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> napi::Result<Self::JsValue> {
        Ok(output)
    }
}

/// Bridges DriftEventHandler → ThreadsafeFunction for progress reporting.
struct NapiProgressHandler {
    tsfn: Arc<ThreadsafeFunction<ProgressUpdate, ()>>,
}

impl NapiProgressHandler {
    fn new(tsfn: Arc<ThreadsafeFunction<ProgressUpdate, ()>>) -> Self {
        Self { tsfn }
    }
}

impl DriftEventHandler for NapiProgressHandler {
    fn on_scan_progress(&self, processed: usize, total: usize) {
        // Report every 100 files (from audit spec)
        if processed % 100 == 0 || processed == total {
            let update = ProgressUpdate {
                processed: processed as u32,
                total: total as u32,
                phase: "scanning".to_string(),
                current_file: None,
            };
            // Non-blocking: if JS callback queue is full, drop the update
            // rather than blocking the Rust thread
            let _ = self.tsfn.call(update);
        }
    }
}

#[napi]
pub fn native_scan_with_progress(
    root: String,
    options: ScanOptions,
    on_progress: ThreadsafeFunction<ProgressUpdate, ()>,
) -> AsyncTask<ScanWithProgressTask> {
    AsyncTask::new(ScanWithProgressTask {
        root,
        options,
        on_progress: Arc::new(on_progress),
    })
}
```

### Progress Reporting Frequency

From audit: report every 100 files via `AtomicU64` counter shared across rayon workers.
The `NapiProgressHandler` implements `DriftEventHandler` and checks modulo 100.
This keeps NAPI callback overhead negligible (<0.1% of scan time).

---

## 8. Cancellation Support

From audit A6/A21: rust-analyzer's revision counter pattern.

### Global Cancellation Flag

```rust
use std::sync::atomic::{AtomicBool, Ordering};

/// Global cancellation flag. Set by cancel_scan(), checked by scan workers.
static SCAN_CANCELLED: AtomicBool = AtomicBool::new(false);

/// Cancel a running scan operation.
/// Sets the global flag; rayon workers check between files.
#[napi]
pub fn cancel_scan() -> napi::Result<()> {
    SCAN_CANCELLED.store(true, Ordering::SeqCst);
    Ok(())
}

/// Reset cancellation flag. Called at the start of each new scan.
fn reset_cancellation() {
    SCAN_CANCELLED.store(false, Ordering::SeqCst);
}

/// Check if scan has been cancelled. Called between files in rayon par_iter.
pub fn is_cancelled() -> bool {
    SCAN_CANCELLED.load(Ordering::Relaxed)
}
```

### Cancellation Behavior

1. TS calls `cancel_scan()` → sets `AtomicBool` to true
2. Rayon workers check `is_cancelled()` between files
3. Already-processed files are persisted to drift.db
4. In-progress file is discarded (partial parse results dropped)
5. Scan returns with `status: "partial"` in `ScanSummary`
6. Next scan call resets the flag via `reset_cancellation()`

### Per-Operation Cancellation (Future Enhancement)

The global `AtomicBool` works for single-scan scenarios. For concurrent operations
(e.g., scan + call graph build), use a per-operation `CancellationToken`:

```rust
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self { cancelled: Arc::new(AtomicBool::new(false)) }
    }
    pub fn cancel(&self) { self.cancelled.store(true, Ordering::SeqCst); }
    pub fn is_cancelled(&self) -> bool { self.cancelled.load(Ordering::Relaxed) }
}
```

This is a future enhancement — start with the global flag for simplicity.


---

## 9. Batch API

From audit: `analyze_batch(root, analyses: Vec<AnalysisType>)` — multiple analyses in one
NAPI call with shared parsed results. This is critical for MCP workflows where `drift_context`
triggers several analyses that all need the same parsed ASTs.

### Why Batch Matters

Without batch: TS calls `scan()`, then `build_call_graph()`, then `detect_boundaries()`.
Each call re-parses files independently. For 10K files at ~6ms/file, that's 60s of redundant
parsing across 3 calls.

With batch: TS calls `analyze_batch(root, ["patterns", "call_graph", "boundaries"])`.
Rust parses files once, runs all requested analyses on the shared parse results, writes
everything to drift.db, returns a combined summary.

### Implementation

```rust
#[napi(string_enum)]
pub enum AnalysisType {
    Scan,
    Patterns,
    CallGraph,
    Boundaries,
    TestTopology,
    ErrorHandling,
    Constants,
    Environment,
    Wrappers,
    Taint,
    Coupling,
    Constraints,
    Contracts,
    Dna,
    Secrets,
}

#[napi(object)]
pub struct BatchOptions {
    pub root: String,
    pub analyses: Vec<AnalysisType>,
    pub incremental: Option<bool>,
    pub config_overrides: Option<serde_json::Value>,
}

#[napi(object)]
pub struct BatchResult {
    pub scan: Option<ScanSummary>,
    pub patterns: Option<PatternsSummary>,
    pub call_graph: Option<CallGraphStats>,
    pub boundaries: Option<BoundariesSummary>,
    pub test_topology: Option<TestTopologySummary>,
    pub error_handling: Option<ErrorHandlingSummary>,
    pub taint: Option<TaintSummary>,
    pub coupling: Option<CouplingSummary>,
    pub constraints: Option<ConstraintsSummary>,
    pub contracts: Option<ContractsSummary>,
    pub dna: Option<DnaSummary>,
    pub secrets: Option<SecretsSummary>,
    pub duration_ms: u32,
    pub status: String,
}

pub struct BatchTask {
    options: BatchOptions,
}

#[napi]
impl Task for BatchTask {
    type Output = BatchResult;
    type JsValue = BatchResult;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        let rt = crate::runtime::get()?;
        let root = PathBuf::from(&self.options.root);
        let mut result = BatchResult::default();
        let start = std::time::Instant::now();

        // Phase 1: Scan (always runs first — provides file list)
        let diff = drift_core::scanner::scan(
            &root, &rt.config.scan, &rt.db, &NoOpEventHandler,
        ).map_err(to_napi_error)?;

        if self.options.analyses.contains(&AnalysisType::Scan) {
            result.scan = Some(ScanSummary::from(&diff));
        }

        // Phase 2: Parse files that need analysis (shared across all analyses)
        let files_to_parse: Vec<_> = diff.added.iter()
            .chain(diff.modified.iter())
            .collect();
        let parse_results = drift_core::parser::parse_files(&files_to_parse)
            .map_err(to_napi_error)?;

        // Phase 3: Run requested analyses on shared parse results
        for analysis in &self.options.analyses {
            match analysis {
                AnalysisType::Patterns => {
                    let summary = drift_core::detectors::detect_all(
                        &parse_results, &rt.db,
                    ).map_err(to_napi_error)?;
                    result.patterns = Some(summary);
                }
                AnalysisType::CallGraph => {
                    let stats = drift_core::call_graph::build(
                        &parse_results, &rt.db,
                    ).map_err(to_napi_error)?;
                    result.call_graph = Some(stats);
                }
                AnalysisType::Boundaries => {
                    let summary = drift_core::boundaries::detect(
                        &parse_results, &rt.db,
                    ).map_err(to_napi_error)?;
                    result.boundaries = Some(summary);
                }
                // ... other analyses follow same pattern
                _ => {}
            }
        }

        result.duration_ms = start.elapsed().as_millis() as u32;
        result.status = "complete".to_string();
        Ok(result)
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> napi::Result<Self::JsValue> {
        Ok(output)
    }
}

#[napi]
pub fn analyze_batch(options: BatchOptions) -> AsyncTask<BatchTask> {
    AsyncTask::new(BatchTask { options })
}
```

### Batch Optimization: Shared Parse Cache

The batch API's primary optimization is parsing files once. The `parse_results` vector
is passed by reference to all analysis functions. Each analysis reads from the shared
parse results without re-parsing.

Secondary optimization: analyses that depend on each other can share intermediate results.
For example, if both `Boundaries` and `Taint` are requested, boundaries detection produces
a sink registry that taint analysis consumes directly (no round-trip through drift.db).

---

## 10. Complete NAPI Function Registry

### 10.1 Lifecycle Functions (3)

| Function | Sync/Async | Returns | Description |
|----------|-----------|---------|-------------|
| `drift_initialize(db_path?, project_root?, config_toml?, attach_cortex?)` | Sync | `void` | Initialize DriftRuntime singleton |
| `drift_shutdown()` | Sync | `void` | Graceful shutdown (flush caches, checkpoint WAL) |
| `drift_configure(config_toml?)` | Sync | `DriftConfig` | Get/update configuration |

### 10.2 Scanner Functions (4)

| Function | Sync/Async | Returns | Description |
|----------|-----------|---------|-------------|
| `native_scan(root, options)` | Async | `ScanSummary` | Full scan: discover, hash, diff, persist |
| `native_scan_with_progress(root, options, on_progress)` | Async | `ScanSummary` | Scan with progress callback |
| `cancel_scan()` | Sync | `void` | Cancel running scan |
| `query_changed_files(since?)` | Sync | `FileChange[]` | Query files changed since timestamp |

### 10.3 Parser Functions (3)

| Function | Sync/Async | Returns | Description |
|----------|-----------|---------|-------------|
| `parse_file(path, source)` | Sync | `ParseResult` | Parse single file (for IDE/LSP) |
| `parse_file_cached(path)` | Sync | `ParseResult` | Parse with cache lookup |
| `query_parse_stats()` | Sync | `ParseCacheStats` | Cache hit rate, entry count |

### 10.4 Detection Functions (4)

| Function | Sync/Async | Returns | Description |
|----------|-----------|---------|-------------|
| `detect_patterns(root, options)` | Async | `PatternsSummary` | Run all detectors |
| `query_patterns(filter)` | Sync | `PaginatedResult<PatternSummary>` | Query patterns with filters |
| `query_pattern_detail(id)` | Sync | `PatternDetail` | Full pattern with locations |
| `query_violations(filter)` | Sync | `PaginatedResult<ViolationSummary>` | Query violations |

### 10.5 Call Graph Functions (5)

| Function | Sync/Async | Returns | Description |
|----------|-----------|---------|-------------|
| `build_call_graph(root)` | Async | `CallGraphStats` | Build/rebuild call graph |
| `query_call_graph(function_id, depth)` | Sync | `CallGraphSubset` | Subgraph around function |
| `query_callers(function_id)` | Sync | `FunctionSummary[]` | Direct callers |
| `query_callees(function_id)` | Sync | `FunctionSummary[]` | Direct callees |
| `query_entry_points()` | Sync | `FunctionSummary[]` | All entry points |

### 10.6 Reachability & Impact Functions (5)

| Function | Sync/Async | Returns | Description |
|----------|-----------|---------|-------------|
| `analyze_reachability(source, target?)` | Sync | `ReachabilityResult` | Forward/inverse BFS |
| `analyze_impact(function_id)` | Sync | `ImpactResult` | Blast radius analysis |
| `find_dead_code()` | Async | `DeadCodeResult` | Unreachable functions |
| `find_path(source, target)` | Sync | `PathResult` | Path between two functions |
| `analyze_taint(function_id)` | Sync | `TaintResult` | Taint analysis from function |

### 10.7 Boundary & Security Functions (5)

| Function | Sync/Async | Returns | Description |
|----------|-----------|---------|-------------|
| `detect_boundaries(root)` | Async | `BoundariesSummary` | Data boundary detection |
| `query_boundaries(filter)` | Sync | `PaginatedResult<BoundarySummary>` | Query boundaries |
| `query_sensitive_fields(table?)` | Sync | `SensitiveField[]` | Sensitive field listing |
| `detect_secrets(root)` | Async | `SecretsSummary` | Enterprise secret detection |
| `query_security_summary()` | Sync | `SecuritySummary` | Materialized security view |

### 10.8 Test Topology Functions (4)

| Function | Sync/Async | Returns | Description |
|----------|-----------|---------|-------------|
| `analyze_test_topology(root)` | Async | `TestTopologySummary` | Full test analysis |
| `query_test_coverage(file?)` | Sync | `CoverageResult` | Coverage per file/function |
| `query_minimum_test_set(changed_files)` | Sync | `MinTestSetResult` | Tests to run for changes |
| `query_uncovered_functions()` | Sync | `UncoveredFunction[]` | High-risk untested functions |

### 10.9 Error Handling Functions (3)

| Function | Sync/Async | Returns | Description |
|----------|-----------|---------|-------------|
| `analyze_error_handling(root)` | Async | `ErrorHandlingSummary` | 4-phase error analysis |
| `query_error_gaps(severity?)` | Sync | `ErrorGap[]` | Error handling gaps |
| `query_error_boundaries()` | Sync | `ErrorBoundary[]` | Framework error boundaries |

### 10.10 Structural Analysis Functions (6)

| Function | Sync/Async | Returns | Description |
|----------|-----------|---------|-------------|
| `analyze_coupling(root)` | Async | `CouplingSummary` | Module coupling metrics |
| `analyze_constants(root)` | Async | `ConstantsSummary` | Magic numbers, env vars |
| `analyze_wrappers(root)` | Async | `WrappersSummary` | Wrapper function detection |
| `detect_constraints(root)` | Async | `ConstraintsSummary` | Constraint mining |
| `verify_constraints(changed_files?)` | Sync | `ConstraintVerificationResult` | Verify constraints |
| `analyze_contracts(root)` | Async | `ContractsSummary` | BE↔FE contract detection |

### 10.11 DNA & Audit Functions (4)

| Function | Sync/Async | Returns | Description |
|----------|-----------|---------|-------------|
| `analyze_dna(root)` | Async | `DnaProfile` | Codebase DNA fingerprint |
| `compare_dna(profile_a, profile_b)` | Sync | `DnaComparison` | Compare two profiles |
| `run_audit()` | Async | `AuditResult` | Health scoring + degradation |
| `query_health_trends(days?)` | Sync | `HealthTrend[]` | Historical health data |

### 10.12 Quality Gate Functions (3)

| Function | Sync/Async | Returns | Description |
|----------|-----------|---------|-------------|
| `run_quality_gates(policy?)` | Async | `GateResults` | Execute quality gates |
| `query_gate_history(limit?)` | Sync | `GateRun[]` | Gate run history |
| `preview_quality_gates(policy?)` | Async | `GateResults` | Dry-run (no persist) |

### 10.13 Batch & Utility Functions (4)

| Function | Sync/Async | Returns | Description |
|----------|-----------|---------|-------------|
| `analyze_batch(options)` | Async | `BatchResult` | Multi-analysis single call |
| `query_status()` | Sync | `MaterializedStatus` | Materialized status (singleton) |
| `backup_database(path?)` | Async | `BackupResult` | Hot backup via SQLite Backup API |
| `query_storage_stats()` | Sync | `StorageStats` | DB size, query count, cache stats |

### 10.14 Context Generation Functions (2)

| Function | Sync/Async | Returns | Description |
|----------|-----------|---------|-------------|
| `generate_context(focus, options)` | Sync | `ContextResult` | AI-ready context generation |
| `generate_package_context(package)` | Sync | `PackageContextResult` | Per-package context |

### Total: ~55 NAPI Functions

Organized into 14 binding modules, matching the cortex-napi pattern of one module per domain.


---

## 11. Keyset Pagination for All List Operations

All query functions that return lists use keyset pagination, not OFFSET/LIMIT.
This is consistent with the storage layer decision (02-STORAGE-V2-PREP.md §10).

### NAPI Types

```rust
#[napi(object)]
pub struct PaginationOptions {
    /// Opaque cursor from previous page's `next_cursor`. Null for first page.
    pub cursor: Option<String>,
    /// Maximum items per page. Default: 50, max: 100.
    pub limit: Option<u32>,
    /// Sort field. Default varies by query.
    pub sort_by: Option<String>,
    /// Sort direction. Default: "desc".
    pub sort_order: Option<String>,
}

#[napi(object)]
pub struct PaginatedResult {
    /// Items for this page (JSON array).
    pub items: serde_json::Value,
    /// Total count across all pages.
    pub total: u32,
    /// Whether more pages exist.
    pub has_more: bool,
    /// Opaque cursor for next page. Null if no more pages.
    pub next_cursor: Option<String>,
}
```

### Cursor Encoding

Cursors are Base64-encoded `(sort_value, id)` tuples, opaque to TS consumers.
The TS client passes the cursor back unchanged — it never needs to parse it.

```rust
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

fn encode_cursor(sort_value: &str, id: &str) -> String {
    let raw = format!("{}|{}", sort_value, id);
    URL_SAFE_NO_PAD.encode(raw.as_bytes())
}

fn decode_cursor(cursor: &str) -> napi::Result<(String, String)> {
    let bytes = URL_SAFE_NO_PAD.decode(cursor)
        .map_err(|_| napi::Error::from_reason("[INVALID_CURSOR] Malformed cursor"))?;
    let raw = String::from_utf8(bytes)
        .map_err(|_| napi::Error::from_reason("[INVALID_CURSOR] Invalid UTF-8"))?;
    let parts: Vec<&str> = raw.splitn(2, '|').collect();
    if parts.len() != 2 {
        return Err(napi::Error::from_reason("[INVALID_CURSOR] Missing separator"));
    }
    Ok((parts[0].to_string(), parts[1].to_string()))
}
```

### Example: query_patterns with Pagination

```rust
#[napi]
pub fn query_patterns(
    filter: PatternFilter,
    pagination: Option<PaginationOptions>,
) -> napi::Result<PaginatedResult> {
    let rt = crate::runtime::get()?;
    let page = pagination.unwrap_or_default();
    let limit = page.limit.unwrap_or(50).min(100) as usize;

    let cursor = page.cursor
        .as_deref()
        .map(decode_cursor)
        .transpose()?;

    let result = drift_core::storage::query_patterns(
        &rt.db,
        &filter.into(),
        cursor.as_ref(),
        limit,
    ).map_err(to_napi_error)?;

    Ok(PaginatedResult {
        items: serde_json::to_value(&result.items)
            .map_err(|e| napi::Error::from_reason(format!("[INTERNAL_ERROR] {e}")))?,
        total: result.total as u32,
        has_more: result.has_more,
        next_cursor: result.next_cursor,
    })
}
```

---

## 12. Type Conversion Strategy

### Approach: serde_json as Interchange Format

Same as cortex-napi: use `serde_json::Value` as the interchange format between Rust and JS.
napi-rs's `serde-json` feature handles `serde_json::Value ↔ JsObject` automatically.

For frequently-used types, use `#[napi(object)]` structs for better TypeScript type generation.
For complex/dynamic types, use `serde_json::Value`.

### Conversion Module Structure

```
crates/drift-napi/src/conversions/
├── mod.rs              # Re-exports
├── error_types.rs      # DriftError → napi::Error with codes
├── scan_types.rs       # ScanSummary, ScanOptions, ProgressUpdate
├── pattern_types.rs    # PatternSummary, PatternDetail, PatternFilter
├── violation_types.rs  # ViolationSummary, ViolationFilter
├── call_graph_types.rs # CallGraphStats, CallGraphSubset, FunctionSummary
├── boundary_types.rs   # BoundarySummary, SensitiveField
├── security_types.rs   # SecuritySummary, SecretsSummary
├── test_types.rs       # TestTopologySummary, CoverageResult
├── error_handling_types.rs  # ErrorHandlingSummary, ErrorGap
├── constraint_types.rs # ConstraintsSummary, ConstraintVerificationResult
├── contract_types.rs   # ContractsSummary
├── dna_types.rs        # DnaProfile, DnaComparison
├── gate_types.rs       # GateResults, GateRun
├── batch_types.rs      # BatchOptions, BatchResult
└── pagination_types.rs # PaginationOptions, PaginatedResult, cursor encoding
```

### #[napi(object)] vs serde_json::Value Decision Matrix

| Use `#[napi(object)]` | Use `serde_json::Value` |
|---|---|
| Fixed schema, always same fields | Variable schema across calls |
| Frequently used in TS (needs good types) | Rarely accessed fields |
| Small structs (<20 fields) | Large/nested structures |
| Return types of query functions | Metadata/config blobs |

Examples:
- `ScanSummary` → `#[napi(object)]` (fixed schema, used everywhere)
- `PatternSummary` → `#[napi(object)]` (fixed schema, MCP tools use it)
- `PatternDetail.metadata` → `serde_json::Value` (variable per pattern)
- `BatchResult` → `#[napi(object)]` with `Option<T>` fields

---

## 13. Platform Targets & Cross-Compilation

### 8 Build Targets

| Target | OS | Arch | Toolchain |
|--------|-----|------|-----------|
| `x86_64-apple-darwin` | macOS | Intel | Native (Xcode) |
| `aarch64-apple-darwin` | macOS | Apple Silicon | Native (Xcode) |
| `x86_64-unknown-linux-gnu` | Linux | x86_64 (glibc) | `@napi-rs/cross-toolchain` |
| `x86_64-unknown-linux-musl` | Linux | x86_64 (Alpine) | `cargo-zigbuild` |
| `aarch64-unknown-linux-gnu` | Linux | ARM64 (glibc) | `@napi-rs/cross-toolchain` |
| `aarch64-unknown-linux-musl` | Linux | ARM64 (Alpine) | `cargo-zigbuild` |
| `x86_64-pc-windows-msvc` | Windows | x86_64 | `cargo-xwin` |
| `wasm32-wasip1-threads` | Browser/WASI | WebAssembly | Native (v3 feature) |

### GLIBC Compatibility

v3's `@napi-rs/cross-toolchain` supports GLIBC 2.17 for all GNU Linux targets.
This covers: RHEL 7+, CentOS 7+, Ubuntu 14.04+, Debian 8+, Amazon Linux 2+.

### wasm32 Fallback Package

The wasm32 target is a v3 addition. It provides a fallback for platforms without
pre-built native binaries. Performance is ~2-5x slower than native, but functional.

This enables:
- Browser playgrounds (future: drift analysis in the browser)
- StackBlitz support (WebContainer environment)
- Unsupported platform fallback (e.g., FreeBSD, s390x)

### CI Build Matrix

```yaml
# GitHub Actions matrix
strategy:
  matrix:
    include:
      - target: x86_64-apple-darwin
        os: macos-latest
      - target: aarch64-apple-darwin
        os: macos-latest
      - target: x86_64-unknown-linux-gnu
        os: ubuntu-latest
        use-napi-cross: true
      - target: x86_64-unknown-linux-musl
        os: ubuntu-latest
        use-zigbuild: true
      - target: aarch64-unknown-linux-gnu
        os: ubuntu-latest
        use-napi-cross: true
      - target: aarch64-unknown-linux-musl
        os: ubuntu-latest
        use-zigbuild: true
      - target: x86_64-pc-windows-msvc
        os: ubuntu-latest
        use-xwin: true
      - target: wasm32-wasip1-threads
        os: ubuntu-latest
```

### npm Package Structure

```
drift-napi/
├── package.json          # Main package with optionalDependencies
├── index.js              # Platform detection + native module loading
├── index.d.ts            # Generated TypeScript declarations
└── npm/
    ├── darwin-arm64/     # @drift/napi-darwin-arm64
    ├── darwin-x64/       # @drift/napi-darwin-x64
    ├── linux-arm64-gnu/  # @drift/napi-linux-arm64-gnu
    ├── linux-arm64-musl/ # @drift/napi-linux-arm64-musl
    ├── linux-x64-gnu/    # @drift/napi-linux-x64-gnu
    ├── linux-x64-musl/   # @drift/napi-linux-x64-musl
    ├── win32-x64-msvc/   # @drift/napi-win32-x64-msvc
    └── wasm32/           # @drift/napi-wasm32 (fallback)
```

Each platform package contains the pre-built `.node` binary (or `.wasm` for wasm32).
The main package's `optionalDependencies` lists all platform packages.
At install time, npm/pnpm/yarn installs only the matching platform package.

---

## 14. TypeScript Bridge Layer (packages/drift)

### NativeBindings Interface

Following the cortex-napi pattern, the TS bridge defines a `NativeBindings` interface
that mirrors all NAPI function signatures:

```typescript
export interface NativeBindings {
    // Lifecycle
    driftInitialize(
        dbPath: string | null,
        projectRoot: string | null,
        configToml: string | null,
        attachCortex: boolean | null,
    ): void;
    driftShutdown(): void;
    driftConfigure(configToml: string | null): unknown;

    // Scanner
    nativeScan(root: string, options: unknown): Promise<unknown>;
    nativeScanWithProgress(
        root: string,
        options: unknown,
        onProgress: (update: unknown) => void,
    ): Promise<unknown>;
    cancelScan(): void;
    queryChangedFiles(since: number | null): unknown;

    // Detection
    detectPatterns(root: string, options: unknown): Promise<unknown>;
    queryPatterns(filter: unknown, pagination: unknown | null): unknown;
    queryPatternDetail(id: string): unknown;
    queryViolations(filter: unknown, pagination: unknown | null): unknown;

    // Call Graph
    buildCallGraph(root: string): Promise<unknown>;
    queryCallGraph(functionId: string, depth: number): unknown;
    queryCallers(functionId: string): unknown;
    queryCallees(functionId: string): unknown;
    queryEntryPoints(): unknown;

    // Reachability & Impact
    analyzeReachability(source: string, target: string | null): unknown;
    analyzeImpact(functionId: string): unknown;
    findDeadCode(): Promise<unknown>;
    findPath(source: string, target: string): unknown;
    analyzeTaint(functionId: string): unknown;

    // Boundaries & Security
    detectBoundaries(root: string): Promise<unknown>;
    queryBoundaries(filter: unknown, pagination: unknown | null): unknown;
    querySensitiveFields(table: string | null): unknown;
    detectSecrets(root: string): Promise<unknown>;
    querySecuritySummary(): unknown;

    // Test Topology
    analyzeTestTopology(root: string): Promise<unknown>;
    queryTestCoverage(file: string | null): unknown;
    queryMinimumTestSet(changedFiles: string[]): unknown;
    queryUncoveredFunctions(): unknown;

    // Error Handling
    analyzeErrorHandling(root: string): Promise<unknown>;
    queryErrorGaps(severity: string | null): unknown;
    queryErrorBoundaries(): unknown;

    // Structural Analysis
    analyzeCoupling(root: string): Promise<unknown>;
    analyzeConstants(root: string): Promise<unknown>;
    analyzeWrappers(root: string): Promise<unknown>;
    detectConstraints(root: string): Promise<unknown>;
    verifyConstraints(changedFiles: string[] | null): unknown;
    analyzeContracts(root: string): Promise<unknown>;

    // DNA & Audit
    analyzeDna(root: string): Promise<unknown>;
    compareDna(profileA: string, profileB: string): unknown;
    runAudit(): Promise<unknown>;
    queryHealthTrends(days: number | null): unknown;

    // Quality Gates
    runQualityGates(policy: string | null): Promise<unknown>;
    queryGateHistory(limit: number | null): unknown;
    previewQualityGates(policy: string | null): Promise<unknown>;

    // Batch & Utility
    analyzeBatch(options: unknown): Promise<unknown>;
    queryStatus(): unknown;
    backupDatabase(path: string | null): Promise<unknown>;
    queryStorageStats(): unknown;

    // Context Generation
    generateContext(focus: string, options: unknown): unknown;
    generatePackageContext(packageName: string): unknown;
}
```

### Module Loading

```typescript
let nativeModule: NativeBindings | null = null;

export function loadNativeModule(): NativeBindings {
    if (nativeModule) return nativeModule;

    try {
        // napi-rs generates the platform-specific require path
        nativeModule = require("drift-napi") as NativeBindings;
        return nativeModule;
    } catch (err) {
        throw new Error(
            `Failed to load drift-napi native module: ${err}. ` +
            `Ensure the correct platform package is installed.`
        );
    }
}
```

### DriftClient Wrapper

```typescript
export class DriftClient {
    private native: NativeBindings;

    private constructor(native: NativeBindings) {
        this.native = native;
    }

    static async initialize(opts: DriftInitOptions = {}): Promise<DriftClient> {
        const native = loadNativeModule();
        await wrap(() =>
            native.driftInitialize(
                opts.dbPath ?? null,
                opts.projectRoot ?? null,
                opts.configToml ?? null,
                opts.attachCortex ?? false,
            ),
        );
        return new DriftClient(native);
    }

    async scan(root: string, opts?: ScanOptions): Promise<ScanSummary> {
        return wrap(() => this.native.nativeScan(root, opts ?? {})) as Promise<ScanSummary>;
    }

    async scanWithProgress(
        root: string,
        opts: ScanOptions,
        onProgress: (update: ProgressUpdate) => void,
    ): Promise<ScanSummary> {
        return wrap(() =>
            this.native.nativeScanWithProgress(root, opts, onProgress),
        ) as Promise<ScanSummary>;
    }

    queryPatterns(filter?: PatternFilter, page?: PaginationOptions): PaginatedResult<PatternSummary> {
        return wrap(() =>
            this.native.queryPatterns(filter ?? {}, page ?? null),
        ) as PaginatedResult<PatternSummary>;
    }

    // ... all other methods follow same pattern
}
```


---

## 15. File Module Structure

```
crates/drift-napi/
├── Cargo.toml
├── build.rs                    # napi_build::setup()
├── package.json                # napi config (binaryName, targets)
├── src/
│   ├── lib.rs                  # Module declarations
│   ├── runtime.rs              # DriftRuntime singleton (OnceLock<Arc<T>>)
│   ├── bindings/
│   │   ├── mod.rs              # Re-exports all binding modules
│   │   ├── lifecycle.rs        # drift_initialize, drift_shutdown, drift_configure
│   │   ├── scanner.rs          # native_scan, native_scan_with_progress, cancel_scan
│   │   ├── parser.rs           # parse_file, parse_file_cached, query_parse_stats
│   │   ├── detection.rs        # detect_patterns, query_patterns, query_violations
│   │   ├── call_graph.rs       # build_call_graph, query_call_graph, query_callers/callees
│   │   ├── reachability.rs     # analyze_reachability, analyze_impact, find_dead_code
│   │   ├── boundaries.rs       # detect_boundaries, query_boundaries, query_sensitive_fields
│   │   ├── security.rs         # detect_secrets, query_security_summary
│   │   ├── test_topology.rs    # analyze_test_topology, query_test_coverage
│   │   ├── error_handling.rs   # analyze_error_handling, query_error_gaps
│   │   ├── structural.rs       # analyze_coupling, analyze_constants, analyze_wrappers
│   │   ├── constraints.rs      # detect_constraints, verify_constraints
│   │   ├── contracts.rs        # analyze_contracts
│   │   ├── dna.rs              # analyze_dna, compare_dna
│   │   ├── audit.rs            # run_audit, query_health_trends
│   │   ├── gates.rs            # run_quality_gates, query_gate_history
│   │   ├── batch.rs            # analyze_batch
│   │   ├── context.rs          # generate_context, generate_package_context
│   │   └── utility.rs          # query_status, backup_database, query_storage_stats
│   └── conversions/
│       ├── mod.rs              # Re-exports all conversion modules
│       ├── error_types.rs      # DriftError → napi::Error with codes
│       ├── scan_types.rs       # ScanSummary, ScanOptions, ProgressUpdate
│       ├── pattern_types.rs    # PatternSummary, PatternDetail, PatternFilter
│       ├── violation_types.rs  # ViolationSummary, ViolationFilter
│       ├── call_graph_types.rs # CallGraphStats, CallGraphSubset, FunctionSummary
│       ├── boundary_types.rs   # BoundarySummary, SensitiveField
│       ├── security_types.rs   # SecuritySummary, SecretsSummary
│       ├── test_types.rs       # TestTopologySummary, CoverageResult
│       ├── error_handling_types.rs  # ErrorHandlingSummary, ErrorGap
│       ├── constraint_types.rs # ConstraintsSummary, ConstraintVerificationResult
│       ├── contract_types.rs   # ContractsSummary
│       ├── dna_types.rs        # DnaProfile, DnaComparison
│       ├── gate_types.rs       # GateResults, GateRun
│       ├── batch_types.rs      # BatchOptions, BatchResult, AnalysisType
│       └── pagination_types.rs # PaginationOptions, PaginatedResult, cursor encode/decode
└── npm/                        # Platform-specific packages (generated by napi CLI)
    ├── darwin-arm64/
    ├── darwin-x64/
    ├── linux-arm64-gnu/
    ├── linux-arm64-musl/
    ├── linux-x64-gnu/
    ├── linux-x64-musl/
    ├── win32-x64-msvc/
    └── wasm32/
```

### Corresponding TS Bridge Structure

```
packages/drift/src/bridge/
├── index.ts            # loadNativeModule(), NativeBindings interface
├── client.ts           # DriftClient typed wrapper
├── types.ts            # All TypeScript types (mirrors Rust #[napi(object)] structs)
└── errors.ts           # DriftError class, parseNapiError()
```

---

## 16. Integration Points

### drift-napi → drift-core

drift-napi is a thin wrapper. All analysis logic lives in drift-core.
Each binding module calls drift-core functions and converts results.

```
bindings/scanner.rs    → drift_core::scanner::scan()
bindings/detection.rs  → drift_core::detectors::detect_all()
bindings/call_graph.rs → drift_core::call_graph::build()
bindings/boundaries.rs → drift_core::boundaries::detect()
bindings/security.rs   → drift_core::secrets::detect()
bindings/gates.rs      → drift_core::gates::evaluate()
bindings/batch.rs      → drift_core::{scanner, parser, detectors, call_graph, ...}
```

### drift-napi → drift.db

drift-napi does NOT access drift.db directly. It goes through drift-core's storage layer.
The `DriftRuntime` holds a `DatabaseManager` from drift-core, which manages connections.

### drift-napi → DriftEventHandler

The NAPI bridge creates event handler implementations that bridge Rust events to TS callbacks:
- `NapiProgressHandler` — forwards `on_scan_progress` to ThreadsafeFunction
- Future: `NapiEventForwarder` — forwards all events to a TS event emitter

### cortex-drift-napi (Optional Bridge)

When both Cortex and Drift are present, `cortex-drift-napi` provides combined bindings:
- `drift_why(pattern_id)` — synthesizes pattern data + causal memory
- `drift_memory_learn(correction, context)` — creates Cortex memory from Drift data
- `drift_grounding_check()` — validates Cortex memories against Drift scan results

This is a separate crate that depends on both `drift-napi` and `cortex-napi`.
It is NOT part of drift-napi itself (per D1: standalone independence).

---

## 17. Performance Considerations

### NAPI Serialization Overhead

Measured from cortex-napi experience:
- Small struct (10 fields): ~1-5µs per serialization
- Medium struct (50 fields): ~10-50µs
- Large array (1000 items × 10 fields): ~1-5ms
- Very large array (100K items): ~100-500ms (this is why we paginate)

### Mitigation Strategies

1. **Pagination** — All list queries return max 100 items. 100 × 10 fields = ~50µs.
2. **Summary returns** — Command functions return summaries (10-20 fields), not full results.
3. **Lazy loading** — TS queries for details on demand, not upfront.
4. **Batch API** — One NAPI call instead of N calls (avoids N × overhead).
5. **#[napi(object)]** — Direct struct mapping is faster than serde_json round-trip.

### Memory Considerations

- NAPI objects are allocated on the V8 heap (Node.js GC manages them)
- Large result sets create GC pressure — pagination prevents this
- Rust-side memory (parse cache, call graph) is managed by Rust (not GC'd)
- `DriftRuntime` lives for the process lifetime (no premature deallocation)

### Thread Safety

- `DriftRuntime` is `Send + Sync` (all fields are thread-safe)
- `DatabaseManager` handles its own locking (write Mutex, read pool)
- Tree-sitter parsers use `thread_local!` (not shared across threads)
- `AtomicBool` for cancellation (lock-free)
- `OnceLock` for runtime singleton (lock-free after init)

---

## 18. v1 Feature Verification — Complete Gap Analysis

Cross-referenced against all v1 documentation and the existing cortex-napi implementation
to ensure 100% feature coverage in v2.

### v1 NAPI Features (from v1 research docs)

| v1 Feature | v2 Status | v2 Location |
|-----------|-----------|-------------|
| `scan()` — basic scan returning results | **UPGRADED** — `native_scan()` writes to drift.db, returns summary | §10.2 |
| `scan_with_progress()` — progress callback | **UPGRADED** — v3 ThreadsafeFunction, cleaner API | §7 |
| `cancel_scan()` — cancellation | **KEPT** — AtomicBool pattern | §8 |
| Pattern query functions | **UPGRADED** — paginated, filtered, from drift.db | §10.4 |
| Call graph query functions | **UPGRADED** — paginated, from drift.db | §10.5 |
| Boundary detection | **KEPT** — async, writes to drift.db | §10.7 |
| Error propagation (string messages) | **UPGRADED** — structured error codes | §6 |
| Single-file parse for IDE | **KEPT** — `parse_file()` sync function | §10.3 |
| Worker thread pool (Piscina) | **DROPPED** — Rust rayon replaces TS workers | §4 (runtime) |
| JSON shard I/O | **DROPPED** — SQLite only | §5 (core principle) |
| Manifest generation | **DROPPED** — SQLite Gold layer replaces | §5 |

### v1 Features NOT in Original 03-NAPI-BRIDGE.md (Gaps Found & Resolved)

**1. Single-File Parse for IDE/LSP**
v1 exposed `parse_file()` for IDE integration (parse on keystroke).
v2 must keep this — LSP server needs sub-millisecond incremental parsing.
**Resolution**: Added `parse_file(path, source)` and `parse_file_cached(path)` to §10.3.

**2. Storage Statistics**
v1 exposed storage metrics (query count, cache hits, DB size).
**Resolution**: Added `query_storage_stats()` to §10.13.

**3. Configuration Query**
v1 allowed querying current configuration.
**Resolution**: Added `drift_configure(config_toml?)` to §10.1 (returns current config).

**4. Database Backup**
v1 had backup functionality.
**Resolution**: Added `backup_database(path?)` to §10.13.

**5. Health Trend History**
v1 tracked health over time.
**Resolution**: Added `query_health_trends(days?)` to §10.11.

**6. Context Generation**
v1 generated AI-ready context for MCP tools.
**Resolution**: Added `generate_context()` and `generate_package_context()` to §10.14.

**7. Quality Gate Preview (Dry-Run)**
v1 supported `--dry-run` mode for gates.
**Resolution**: Added `preview_quality_gates(policy?)` to §10.12.

**8. Minimum Test Set**
v1 computed which tests to run for changed files.
**Resolution**: Added `query_minimum_test_set(changed_files)` to §10.8.

**9. Dead Code Detection**
v1 found unreachable functions.
**Resolution**: Added `find_dead_code()` to §10.6.

**10. Constraint Verification (Change-Aware)**
v1 verified constraints against changed files only.
**Resolution**: Added `verify_constraints(changed_files?)` to §10.10.

### New v2 Features NOT in v1

| New Feature | Why | Location |
|------------|-----|----------|
| Batch API | Avoid redundant parsing across multiple analyses | §9 |
| Taint analysis | First-class security subsystem (AD11) | §10.6 |
| Secret detection | Enterprise-grade, 100+ patterns | §10.7 |
| DNA analysis | Codebase fingerprinting | §10.11 |
| Contract detection | BE↔FE matching | §10.10 |
| Coupling analysis | Module dependency metrics | §10.10 |
| Wrapper detection | Thin delegation patterns | §10.10 |
| wasm32 fallback | Browser/StackBlitz support (v3) | §13 |
| Structured error codes | Programmatic error handling | §6 |
| Keyset pagination | Constant-time page retrieval | §11 |

---

## 19. Relationship to cortex-napi (Existing Implementation)

### What Drift Copies from Cortex

| Pattern | Cortex Implementation | Drift Adoption |
|---------|----------------------|----------------|
| Singleton runtime | `OnceLock<Arc<CortexRuntime>>` | Identical: `OnceLock<Arc<DriftRuntime>>` |
| Error codes | `[ERROR_CODE] message` format | Identical format, different codes |
| Binding modules | 12 domain-specific modules | ~15 domain-specific modules |
| Conversion modules | 6 type conversion modules | ~16 type conversion modules |
| serde_json interchange | All functions use `serde_json::Value` | Same, plus `#[napi(object)]` for hot types |
| TS bridge | `NativeBindings` interface + `CortexClient` wrapper | Same pattern: `NativeBindings` + `DriftClient` |
| TS error parsing | Regex parse `[CODE] message` | Identical |

### What Drift Changes from Cortex

| Aspect | Cortex | Drift | Why |
|--------|--------|-------|-----|
| napi-rs version | v2 | v3 | WebAssembly, lifetime safety, better ThreadsafeFunction |
| Async runtime | tokio (for embeddings, cloud) | None (rayon for parallelism) | Drift's core is CPU-bound, not I/O-bound |
| Engine mutability | Many engines behind `Mutex` | Minimal Mutex (DB writer only) | Drift engines are stateless or thread_local |
| Data flow | Return results via NAPI | Write to drift.db, return summary | Drift has much larger result sets |
| Progress callbacks | Not used | ThreadsafeFunction v3 | Scans are long-running |
| Cancellation | Not needed | AtomicBool | Scans can be cancelled |
| Batch API | Not needed | analyze_batch() | Multiple analyses share parse results |
| Pagination | Not needed (small result sets) | Keyset pagination on all lists | Drift has 100K+ patterns/functions |

### Independence Guarantee (D1)

drift-napi does NOT import from cortex-napi or cortex-core. Period.
cortex-napi does NOT import from drift-napi or drift-core. Period.
The only cross-import point is `cortex-drift-napi` (the optional bridge crate).

---

## 20. Build Order

The NAPI bridge is built after drift-core's subsystems are functional.
It's a thin wrapper — each binding module is added as its corresponding
drift-core subsystem becomes available.

### Phase 1: Foundation (Week 1)
1. `Cargo.toml` + `build.rs` + `package.json` — napi-rs v3 scaffold
2. `runtime.rs` — DriftRuntime singleton with DatabaseManager
3. `conversions/error_types.rs` — Error code registry + conversion
4. `bindings/lifecycle.rs` — drift_initialize, drift_shutdown, drift_configure
5. Verify: TS can load native module, initialize, and get config

### Phase 2: Scanner Bindings (Week 2)
6. `conversions/scan_types.rs` — ScanSummary, ScanOptions, ProgressUpdate
7. `bindings/scanner.rs` — native_scan, native_scan_with_progress, cancel_scan
8. Verify: TS can trigger scan, receive progress, cancel, get summary

### Phase 3: Parser & Detection Bindings (Week 3)
9. `conversions/pattern_types.rs` + `violation_types.rs`
10. `bindings/parser.rs` — parse_file, parse_file_cached
11. `bindings/detection.rs` — detect_patterns, query_patterns, query_violations
12. `conversions/pagination_types.rs` — cursor encoding, PaginatedResult
13. Verify: TS can query patterns with pagination

### Phase 4: Call Graph & Analysis Bindings (Week 4)
14. `conversions/call_graph_types.rs`
15. `bindings/call_graph.rs` — build_call_graph, query functions
16. `bindings/reachability.rs` — analyze_reachability, analyze_impact, find_dead_code
17. Verify: TS can build call graph, query reachability

### Phase 5: Security & Boundary Bindings (Week 5)
18. `conversions/boundary_types.rs` + `security_types.rs`
19. `bindings/boundaries.rs` — detect_boundaries, query functions
20. `bindings/security.rs` — detect_secrets, query_security_summary
21. Verify: TS can detect boundaries, query sensitive fields

### Phase 6: Remaining Analysis Bindings (Week 6)
22. `bindings/test_topology.rs` + `error_handling.rs` + `structural.rs`
23. `bindings/constraints.rs` + `contracts.rs`
24. `bindings/dna.rs` + `audit.rs`
25. Verify: All analysis functions accessible from TS

### Phase 7: Enforcement & Utility Bindings (Week 7)
26. `bindings/gates.rs` — run_quality_gates, preview, history
27. `bindings/batch.rs` — analyze_batch
28. `bindings/context.rs` — generate_context, generate_package_context
29. `bindings/utility.rs` — query_status, backup_database, query_storage_stats
30. Verify: Full NAPI surface functional

### Phase 8: Cross-Compilation & Publishing (Week 8)
31. CI matrix for all 8 targets
32. npm package structure with platform-specific packages
33. wasm32 fallback verification
34. Performance benchmarks (NAPI serialization overhead)
35. Integration tests (TS → NAPI → Rust → drift.db → NAPI → TS)

---

## 21. Open Items / Decisions Still Needed

1. **Streaming for very large results**: The current design uses pagination for all lists.
   For operations that produce truly massive output (e.g., listing all 500K functions),
   should we add a streaming API using napi-rs `AsyncTask` with chunked results?
   Recommendation: Start with pagination. Add streaming only if pagination proves insufficient
   for specific MCP workflows.

2. **Hot configuration reload**: Currently `drift_configure()` returns an error if you try
   to change config after initialization (same as cortex-napi). Should Drift support
   hot-reloading config without restart? Recommendation: No. Require shutdown + reinitialize.
   Config changes affect too many subsystems (scanner threads, detector thresholds, DB pragmas).

3. **NAPI function naming convention**: Cortex uses `cortex_` prefix (e.g., `cortexMemoryCreate`).
   Drift uses `drift_` prefix for some functions and `native_` for others (from audit).
   Recommendation: Standardize on `drift_` prefix for all functions. Exception: `native_scan`
   and `native_scan_with_progress` keep the `native_` prefix for clarity (they're the primary
   compute-heavy entry points). All query functions use `query_` prefix.

4. **TypeScript type generation**: napi-rs v3 generates `.d.ts` files automatically from
   `#[napi(object)]` structs. Should we rely on auto-generation or maintain hand-written types?
   Recommendation: Use auto-generation as the source of truth. Hand-written types in
   `packages/drift/src/bridge/types.ts` re-export and extend the generated types with
   convenience methods and documentation.

5. **Error recovery for DB corruption**: If drift.db is corrupt, should `drift_initialize()`
   attempt auto-recovery (restore from backup) or fail with `DB_CORRUPT` and let TS handle it?
   Recommendation: Fail with `DB_CORRUPT`. TS layer (CLI/MCP) can suggest `drift doctor`
   which attempts backup restoration. Auto-recovery in the NAPI layer is too opaque.

6. **Concurrent operation support**: Can TS call `native_scan()` and `query_patterns()`
   simultaneously? Yes — scan runs on libuv thread pool (via AsyncTask), queries run on
   the main thread using read-only DB connections. WAL mode ensures readers don't block
   the writer. This is safe by design.

---

## 22. Summary of All Decisions

| Decision | Choice | Confidence | Source |
|----------|--------|------------|--------|
| NAPI library | napi-rs v3 | Very High | v3 announcement, migration guide |
| API philosophy | Compute + store in Rust, return summaries | Very High | 03-NAPI-BRIDGE.md, audit A21 |
| Runtime pattern | OnceLock<Arc<DriftRuntime>> singleton | Very High | Proven by cortex-napi |
| Error handling | Structured codes `[CODE] message` | Very High | Proven by cortex-napi |
| Async operations | AsyncTask for >10ms operations | High | 03-NAPI-BRIDGE.md |
| Progress callbacks | ThreadsafeFunction v3 every 100 files | High | v3 docs, audit |
| Batch API | Single NAPI call, shared parse results | High | Audit, MCP workflow needs |
| Cancellation | Global AtomicBool checked between files | High | Audit A6/A21 |
| Pagination | Keyset with Base64 cursors, max 100/page | High | 02-STORAGE-V2-PREP.md |
| Type conversion | serde_json + #[napi(object)] for hot types | High | cortex-napi pattern |
| Platform targets | 7 native + wasm32 fallback | High | v3 feature |
| Cross-compilation | @napi-rs/cross-toolchain + cargo-zigbuild | High | v3 docs |
| TS bridge | NativeBindings interface + DriftClient wrapper | Very High | cortex-napi pattern |
| Module structure | ~15 binding modules + ~16 conversion modules | High | cortex-napi pattern scaled |
| Naming convention | `drift_` prefix, `query_` for reads, `native_` for compute | Medium-High | Standardization |
| Independence | Zero imports from cortex-napi/cortex-core | Very High | D1, D4 |
| Total NAPI functions | ~55 across 14 domains | High | Complete registry §10 |
