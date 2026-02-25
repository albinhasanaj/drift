# NAPI Bridge — Research & Decision Guide

> System: Rust ↔ Node.js interface via napi-rs
> Hierarchy: Level 0 — Bedrock
> Dependencies: All Rust analysis systems
> Consumers: MCP server, CLI, VSCode extension, LSP server

---

## What This System Does

The NAPI bridge is the only door between Rust analysis and TypeScript presentation. Every MCP tool call, every CLI command, every IDE action crosses this boundary. Getting the API design right here determines the performance ceiling and developer experience of the entire TS layer.

---

## Key Library: NAPI-RS v3

[NAPI-RS v3](https://napi.rs/blog/announce-v3) was released in July 2025. Major improvements over v2:

### What's New in v3

1. **WebAssembly support** — Compile to wasm32-wasip1-threads with almost no code changes. Enables browser playgrounds, StackBlitz support, and fallback packages for unsupported platforms. This is how Rolldown and Oxc provide their playgrounds.

2. **Lifetime safety** — v3 introduces Rust lifetimes to NAPI types. In v2, `JsObject` could escape its scope and be used after the underlying `napi_value` became invalid. v3 constrains this with lifetimes.

3. **Redesigned ThreadsafeFunction** — The v2 API was notoriously difficult to use because it leaked Node-API's complexity. v3 provides a cleaner abstraction developed in collaboration with the Rolldown and Rspack teams.

4. **Cross-compilation improvements** — No more huge Docker images for cross-compilation. Uses `cargo-zigbuild` or native cross-compilation toolchains.

### Platform Targets (7)

| Target | OS | Arch |
|--------|-----|------|
| darwin-arm64 | macOS | Apple Silicon |
| darwin-x64 | macOS | Intel |
| linux-arm64-gnu | Linux | ARM64 (glibc) |
| linux-arm64-musl | Linux | ARM64 (Alpine) |
| linux-x64-gnu | Linux | x86_64 (glibc) |
| linux-x64-musl | Linux | x86_64 (Alpine) |
| win32-x64-msvc | Windows | x86_64 |

Plus wasm32 as a fallback for unsupported platforms.

---

## Key Decision: API Surface Design

### The Core Principle

From your audit (A21): "Primary: `native_scan()` and `native_scan_with_progress()` — single NAPI call owns entire computation. Write to SQLite from Rust (only summary crosses NAPI boundary)."

This is the critical insight: **minimize data crossing the NAPI boundary**. Rust should do all heavy computation AND write results to drift.db. The NAPI return value should be a lightweight summary, not the full result set.

### Anti-Pattern: Returning Large Data

```rust
// BAD: Serializing 100K patterns across NAPI boundary
#[napi]
pub fn scan(root: String) -> Vec<Pattern> {
    // ... returns massive Vec that must be serialized to JS objects
}
```

This is slow because:
- Every Rust struct must be converted to a JS object (allocation + copying)
- Large arrays create GC pressure on the Node.js side
- Serialization time can exceed computation time for large results

### Correct Pattern: Compute + Store in Rust, Return Summary

```rust
#[napi]
pub fn native_scan(root: String, options: ScanOptions) -> ScanSummary {
    // 1. Scan files (Rust)
    // 2. Parse ASTs (Rust)
    // 3. Run detectors (Rust)
    // 4. Write results to drift.db (Rust)
    // 5. Return lightweight summary
    ScanSummary {
        files_scanned: 10_000,
        patterns_found: 342,
        violations: 28,
        duration_ms: 2_500,
        status: "complete".to_string(),
    }
}
```

TS then queries drift.db (via NAPI query functions) for specific data as needed.

### Query Functions (Thin NAPI Wrappers)

For MCP tools and CLI commands that need specific data:

```rust
#[napi]
pub fn query_patterns(filter: PatternFilter) -> Vec<PatternSummary> {
    // Read from drift.db, return filtered results
    // These are small result sets (paginated, filtered)
}

#[napi]
pub fn query_call_graph(function_id: String, depth: u32) -> CallGraphResult {
    // BFS from function, return subgraph
}
```

---

## Key Decision: Async Operations

### When to Use AsyncTask

Any operation that takes >10ms should be async to avoid blocking the Node.js event loop:

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

    fn compute(&mut self) -> Result<Self::Output> {
        // Runs on libuv thread pool, not main thread
        perform_scan(&self.root, &self.options)
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

#[napi]
pub fn scan_async(root: String, options: ScanOptions) -> AsyncTask<ScanTask> {
    AsyncTask::new(ScanTask { root, options })
}
```

### Progress Callbacks via ThreadsafeFunction

For long-running operations (full scan), report progress back to TS:

```rust
#[napi]
pub fn scan_with_progress(
    root: String,
    options: ScanOptions,
    progress_callback: ThreadsafeFunction<ProgressUpdate, NonBlocking>,
) -> AsyncTask<ScanWithProgressTask> {
    // ...
}
```

The v3 ThreadsafeFunction is much cleaner than v2. Use `NonBlocking` mode — if the JS callback queue is full, the progress update is dropped rather than blocking the Rust thread.

Report progress every 100 files (from audit) via `AtomicU64` counter.

---

## Key Decision: Batch API

The audit mentions `analyze_batch(root, analyses: Vec<AnalysisType>)` — multiple analyses in one NAPI call with shared parsed results.

```rust
#[napi]
pub fn analyze_batch(root: String, analyses: Vec<String>) -> BatchResult {
    // Parse files once
    let parse_results = parse_all_files(&root);
    
    let mut result = BatchResult::default();
    
    for analysis in analyses {
        match analysis.as_str() {
            "patterns" => result.patterns = detect_patterns(&parse_results),
            "call_graph" => result.call_graph = build_call_graph(&parse_results),
            "boundaries" => result.boundaries = detect_boundaries(&parse_results),
            // ...
        }
    }
    
    result
}
```

This avoids re-parsing files when multiple analyses are requested (common in MCP workflows where `drift_context` triggers several analyses).

---

## Key Decision: Error Propagation

Rust errors should cross the NAPI boundary as structured objects, not opaque strings:

```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DriftError {
    #[error("Parse error in {file}: {message}")]
    ParseError { file: String, message: String },
    
    #[error("Storage error: {0}")]
    StorageError(#[from] rusqlite::Error),
    
    #[error("Scan cancelled")]
    Cancelled,
}

// Convert to NAPI error with structured info
impl From<DriftError> for napi::Error {
    fn from(err: DriftError) -> Self {
        let code = match &err {
            DriftError::ParseError { .. } => "PARSE_ERROR",
            DriftError::StorageError(_) => "STORAGE_ERROR",
            DriftError::Cancelled => "CANCELLED",
        };
        napi::Error::new(napi::Status::GenericFailure, format!("[{}] {}", code, err))
    }
}
```

TS side can parse the error code from the message prefix for programmatic handling.

---

## Key Decision: Cancellation

From audit A6/A21: global revision counter pattern from rust-analyzer.

```rust
use std::sync::atomic::{AtomicBool, Ordering};

#[napi]
pub fn cancel_scan(scan_id: String) {
    // Set the cancellation flag
    SCAN_CANCELLATION.store(true, Ordering::SeqCst);
}

// In scan loop:
fn process_file(file: &Path, cancelled: &AtomicBool) -> Result<()> {
    if cancelled.load(Ordering::Relaxed) {
        return Err(DriftError::Cancelled);
    }
    // ... process file
    Ok(())
}
```

TS calls `cancel_scan(scan_id)` → sets `AtomicBool` in Rust → rayon workers check between files → partial results returned with `status: 'partial'`. Already-processed files are persisted; in-progress file is discarded.

---

## Key Decision: Streaming for Large Results

For operations that return large result sets (e.g., listing all functions in a 100K-file codebase), use chunked streaming via napi-rs `AsyncTask`:

```rust
// Instead of returning Vec<Function> with 500K entries,
// return paginated results that TS can iterate:

#[napi]
pub fn query_functions(cursor: Option<String>, limit: u32) -> FunctionPage {
    FunctionPage {
        items: Vec<FunctionSummary>,  // max `limit` items
        next_cursor: Option<String>,  // null if no more pages
        total_count: u64,
    }
}
```

This keeps memory bounded on both sides of the NAPI boundary.

---

## Key Decision: What Crosses the Boundary

### Crosses NAPI (lightweight summaries and queries):
- `ScanSummary` (counts, duration, status)
- `PatternSummary` (id, name, category, confidence, location count)
- `ViolationSummary` (pattern_id, file, line, severity, message)
- `CallGraphSubset` (small subgraph for a specific query)
- `HealthScore` (single number + breakdown)
- Paginated query results (max 50-100 items per page)

### Does NOT cross NAPI (stays in Rust/SQLite):
- Full parse results (ASTs)
- Raw detection matches
- Complete call graph (100K+ edges)
- All pattern locations
- Intermediate analysis state

---

## Summary of Decisions

| Decision | Choice | Confidence |
|----------|--------|------------|
| NAPI library | napi-rs v3 | Very High |
| API philosophy | Compute + store in Rust, return summaries | Very High |
| Async | AsyncTask for >10ms operations | High |
| Progress | ThreadsafeFunction (NonBlocking) every 100 files | High |
| Batch API | Single NAPI call for multiple analyses, shared parse results | High |
| Error propagation | Structured error codes in NAPI error messages | High |
| Cancellation | AtomicBool checked between files | High |
| Large results | Keyset pagination, not full result sets | High |
| Platform targets | 7 native + wasm32 fallback | High |
