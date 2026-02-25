# Infrastructure (Error Handling, Tracing, Events, Config) — Research & Decision Guide

> Systems: thiserror, tracing, DriftEventHandler, Configuration
> Hierarchy: Level 0 — Bedrock (cross-cutting)
> Dependencies: None (these are the first things written)
> Consumers: Every system in the stack

---

## These are the systems that must exist before the first line of analysis code.

Per AD6, AD10, D5, and the hierarchy doc: error handling, observability, events, and configuration are foundational infrastructure. Retrofitting any of these is painful — they touch every function signature, every module boundary, every subsystem.

---

## 1. Error Handling (thiserror)

### The Approach: One Enum Per Subsystem, Not One Global Enum

From [Designing Error Types in Rust Applications](https://home.expurple.me/posts/designing-error-types-in-rust-applications/):

The common library pattern of one big `Error` enum per crate is wrong for applications. Key insight: "use an enum per function (or per module), instead of a global Error enum."

For Drift, the right granularity is **one error enum per subsystem**:

```rust
// scanner errors
#[derive(Error, Debug)]
pub enum ScanError {
    #[error("IO error scanning {path}: {source}")]
    Io { path: PathBuf, source: std::io::Error },
    
    #[error("File too large: {path} ({size} bytes, max {max})")]
    FileTooLarge { path: PathBuf, size: u64, max: u64 },
    
    #[error("Scan cancelled")]
    Cancelled,
}

// parser errors
#[derive(Error, Debug)]
pub enum ParseError {
    #[error("Unsupported language: {extension}")]
    UnsupportedLanguage { extension: String },
    
    #[error("Parse failed for {path}: {message}")]
    ParseFailed { path: PathBuf, message: String },
    
    #[error("Query compilation failed: {0}")]
    QueryCompilation(String),
}

// storage errors
#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Database busy (another operation in progress)")]
    Busy,
    
    #[error("Database corrupt: {0}")]
    Corrupt(String),
    
    #[error("Migration failed at version {version}: {message}")]
    MigrationFailed { version: u32, message: String },
    
    #[error("Disk full")]
    DiskFull,
    
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
}
```

### Why Not anyhow?

`anyhow` is for applications where you don't need to match on error variants — you just propagate and display. Drift needs structured errors because:
- NAPI bridge must convert errors to specific error codes for TS
- MCP tools need to return meaningful error responses
- Quality gates need to distinguish "scan failed" from "violations found"
- The event system (D5) needs to emit typed error events

`thiserror` for defining error types. `anyhow` nowhere in the codebase.

### Error Propagation Pattern

```rust
// Subsystem functions return their own error type
fn scan_directory(root: &Path) -> Result<ScanResult, ScanError> { ... }

// At module boundaries, convert to the parent's error type
impl From<ScanError> for PipelineError {
    fn from(err: ScanError) -> Self {
        PipelineError::Scan(err)
    }
}

// At the NAPI boundary, convert to napi::Error with error codes
impl From<PipelineError> for napi::Error {
    fn from(err: PipelineError) -> Self {
        let (code, msg) = match &err {
            PipelineError::Scan(ScanError::Cancelled) => ("CANCELLED", err.to_string()),
            PipelineError::Scan(_) => ("SCAN_ERROR", err.to_string()),
            PipelineError::Parse(_) => ("PARSE_ERROR", err.to_string()),
            PipelineError::Storage(StorageError::Busy) => ("DB_BUSY", err.to_string()),
            // ...
        };
        napi::Error::new(napi::Status::GenericFailure, format!("[{}] {}", code, msg))
    }
}
```

### Decision: thiserror with per-subsystem enums, structured NAPI error codes

---

## 2. Observability (tracing crate)

### Why tracing, Not log

The `tracing` crate provides structured, span-based instrumentation. Unlike `log` (which gives you flat text messages), `tracing` gives you:
- **Spans**: Hierarchical timing regions (a scan span contains parse spans which contain detect spans)
- **Structured fields**: Key-value pairs on every event, not just a format string
- **Subscriber-based**: Multiple outputs (console, file, OpenTelemetry) from the same instrumentation
- **Zero-cost when disabled**: Compile-time feature flags can remove all tracing

`tracing` is the de facto standard in the Rust ecosystem. Used by: tokio, hyper, axum, tower, tonic, and most production Rust services.

### Instrumentation Pattern

```rust
use tracing::{info, warn, instrument, Span};

#[instrument(skip(files), fields(file_count = files.len()))]
pub fn detect_patterns(files: &[ParseResult]) -> Vec<Pattern> {
    let mut patterns = Vec::new();
    
    for file in files {
        let _span = tracing::info_span!("detect_file", path = %file.path.display()).entered();
        
        let matches = run_detectors(file);
        info!(match_count = matches.len(), "detection complete");
        
        if matches.is_empty() {
            warn!("no patterns detected — check detector configuration");
        }
        
        patterns.extend(matches);
    }
    
    patterns
}
```

### Key Metrics to Instrument (from AD10)

| Metric | Where | Why |
|--------|-------|-----|
| `parse_time_per_language` | Parser | Identify slow grammars |
| `detection_time_per_category` | Detectors | Find expensive detectors |
| `cache_hit_rate` | Parse cache, query cache | Validate caching strategy |
| `napi_serialization_time` | NAPI bridge | Catch boundary bottlenecks |
| `mcp_response_time` | MCP server | User-facing latency |
| `batch_write_time` | Storage | Database write performance |
| `scan_files_per_second` | Scanner | Overall throughput |

### Configurable Log Levels

From AD10: `DRIFT_LOG=parser=debug,detector=info`

```rust
use tracing_subscriber::{EnvFilter, fmt};

fn init_tracing() {
    let filter = EnvFilter::try_from_env("DRIFT_LOG")
        .unwrap_or_else(|_| EnvFilter::new("drift=info"));
    
    fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .init();
}
```

### Optional OpenTelemetry (Enterprise)

For enterprise distributed tracing, add `tracing-opentelemetry` as an optional subscriber:

```rust
#[cfg(feature = "otel")]
fn init_otel() {
    use tracing_opentelemetry::OpenTelemetryLayer;
    // ... configure OTLP exporter
}
```

This is a feature flag — not compiled in for community builds.

### Decision: tracing crate with per-subsystem spans, EnvFilter for log levels, optional OpenTelemetry

---

## 3. Event System (DriftEventHandler trait)

### Per D5: Trait-Based with No-Op Defaults

This is the hook point that the bridge crate latches onto. Every subsystem that changes state should emit events.

```rust
pub trait DriftEventHandler: Send + Sync {
    // Scan lifecycle
    fn on_scan_started(&self, _root: &Path, _file_count: Option<usize>) {}
    fn on_scan_progress(&self, _processed: usize, _total: usize) {}
    fn on_scan_complete(&self, _results: &ScanResults) {}
    
    // Pattern lifecycle
    fn on_pattern_discovered(&self, _pattern: &Pattern) {}
    fn on_pattern_approved(&self, _pattern: &Pattern) {}
    fn on_pattern_ignored(&self, _pattern: &Pattern) {}
    fn on_pattern_merged(&self, _kept: &Pattern, _merged: &Pattern) {}
    
    // Violations
    fn on_violation_detected(&self, _violation: &Violation) {}
    fn on_violation_dismissed(&self, _violation: &Violation, _reason: &str) {}
    fn on_violation_fixed(&self, _violation: &Violation) {}
    
    // Enforcement
    fn on_gate_evaluated(&self, _gate: &str, _result: &GateResult) {}
    fn on_regression_detected(&self, _regression: &Regression) {}
    
    // Detector health
    fn on_detector_alert(&self, _detector_id: &str, _fp_rate: f64) {}
    fn on_detector_disabled(&self, _detector_id: &str, _reason: &str) {}
    
    // Errors
    fn on_error(&self, _error: &DriftError) {}
}
```

### Handler Registration

```rust
pub struct DriftEngine {
    event_handlers: Vec<Arc<dyn DriftEventHandler>>,
}

impl DriftEngine {
    pub fn register_handler(&mut self, handler: Arc<dyn DriftEventHandler>) {
        self.event_handlers.push(handler);
    }
    
    fn emit<F: Fn(&dyn DriftEventHandler)>(&self, f: F) {
        for handler in &self.event_handlers {
            f(handler.as_ref());
        }
    }
}
```

### Zero Overhead in Standalone Mode

When no handlers are registered (standalone Drift, no bridge), the `emit()` call iterates over an empty Vec — effectively zero cost. The compiler may even optimize it away.

When the bridge is active, it registers a handler that creates Cortex memories from Drift events. Drift doesn't know or care.

### Decision: Trait with no-op defaults, Vec<Arc<dyn Handler>> registration, synchronous dispatch

---

## 4. Configuration System

### Config File Format

The audit mentions `drift.config.json` / `.driftrc.json` / `.driftrc`. The appendix (A22) recommends TOML with layering.

**Recommendation: TOML** (`drift.toml`)

TOML is the Rust ecosystem standard (Cargo.toml). It's more readable than JSON for configuration, supports comments, and has excellent Rust support via `toml` + `serde`.

```toml
# drift.toml

[scan]
max_file_size = 1_048_576  # 1MB
threads = 0                 # 0 = auto-detect
extra_ignore = ["*.generated.ts", "vendor/"]

[analysis]
min_occurrences = 3
dominance_threshold = 0.60
min_files = 2

[quality_gates]
fail_on = "error"           # error | warning | info
required_gates = ["pattern_compliance", "security_boundaries"]

[mcp]
cache_ttl_seconds = 300
max_response_tokens = 8000

[backup]
max_operational = 5
max_daily = 7
```

### Config Resolution Order

```
CLI flags > env vars (DRIFT_*) > project config (drift.toml) > user config (~/.config/drift/drift.toml) > defaults
```

### Implementation

```rust
use serde::Deserialize;

#[derive(Deserialize, Default)]
pub struct DriftConfig {
    #[serde(default)]
    pub scan: ScanConfig,
    #[serde(default)]
    pub analysis: AnalysisConfig,
    #[serde(default)]
    pub quality_gates: GateConfig,
    // ...
}

pub fn load_config(root: &Path) -> DriftConfig {
    let project_config = root.join("drift.toml");
    let user_config = dirs::config_dir().map(|d| d.join("drift/drift.toml"));
    
    let mut config = DriftConfig::default();
    
    // Layer: user config
    if let Some(path) = user_config {
        if path.exists() {
            merge_config(&mut config, &path);
        }
    }
    
    // Layer: project config (overrides user)
    if project_config.exists() {
        merge_config(&mut config, &project_config);
    }
    
    // Layer: env vars (override everything)
    apply_env_overrides(&mut config);
    
    config
}
```

### Decision: TOML format, layered resolution (CLI > env > project > user > defaults)

---

## 5. Data Structures (AD12)

These are cross-cutting performance decisions that affect every system.

### FxHashMap

From the [Rust Performance Book](https://nnethercote.github.io/perf-book/hashing.html): switching from the default HashMap to FxHashMap gave speedups of up to 6% in rustc. Switching back to the default hasher resulted in slowdowns of 4-84%.

FxHash is a fast, non-cryptographic hasher from Firefox. It's NOT DoS-resistant (don't use for user-facing HashMaps), but for internal data structures it's significantly faster.

Use `rustc-hash` crate (provides `FxHashMap` and `FxHashSet`).

**When to use FxHashMap**: All internal hash maps (symbol tables, detector registries, resolution indexes).
**When NOT to use**: Anything exposed to untrusted input (but Drift doesn't have this — all data comes from the user's own codebase).

### SmallVec

`SmallVec<[T; N]>` stores up to N elements inline (on the stack) before falling back to heap allocation. Ideal for collections that are usually small.

From [Rust forum discussion](https://users.rust-lang.org/t/when-is-it-morally-correct-to-use-smallvec/46375): use SmallVec when you have collections that are typically 1-8 elements and are created/destroyed frequently.

Good candidates in Drift:
- `SmallVec<[PatternLocation; 4]>` — most patterns have <4 locations
- `SmallVec<[CallEdge; 8]>` — most functions call <8 other functions
- `SmallVec<[ImportInfo; 4]>` — most files have <4 imports from the same module

### BTreeMap

Use `BTreeMap` instead of `HashMap` when you need ordered iteration. Good for:
- Resolution indexes (sorted by confidence for priority resolution)
- Pattern aggregation (sorted by category)
- Any data that needs deterministic iteration order

### String Interning (lasso)

The `lasso` crate provides string interning with two modes:
- `ThreadedRodeo`: Thread-safe, mutable (for build/scan phase)
- `RodeoReader`: Immutable, contention-free (for query phase)

From [matklad's blog on fast Rust interners](https://matklad.github.io/2020/03/22/fast-simple-rust-interner.html): interning converts string comparisons to integer comparisons and reduces memory by deduplicating identical strings.

For Drift, the audit estimates 60-80% memory reduction from interning file paths and function names.

```rust
use lasso::{ThreadedRodeo, Spur};

// During scan (mutable, thread-safe)
let interner = ThreadedRodeo::default();
let key: Spur = interner.get_or_intern("src/main.ts");

// After scan (immutable, zero-contention reads)
let reader = interner.into_reader();
let name: &str = reader.resolve(&key);
```

Domain wrappers from the audit:
- `PathInterner`: normalizes `\` → `/` before interning
- `FunctionInterner`: supports `intern_qualified(class, method)` for `Class.method` names

### Decision: FxHashMap for all internal maps, SmallVec<[T; 4]> for small collections, BTreeMap for ordered data, lasso for string interning

---

## Summary of Decisions

| Decision | Choice | Confidence |
|----------|--------|------------|
| Error handling | thiserror, per-subsystem enums | Very High |
| Error propagation | Structured codes at NAPI boundary | High |
| Observability | tracing crate, per-subsystem spans | Very High |
| Log configuration | EnvFilter via DRIFT_LOG env var | High |
| OpenTelemetry | Optional feature flag for enterprise | Medium |
| Event system | DriftEventHandler trait, no-op defaults | High (per D5) |
| Event dispatch | Synchronous, Vec<Arc<dyn Handler>> | High |
| Config format | TOML (drift.toml) | High |
| Config layering | CLI > env > project > user > defaults | High |
| HashMap | FxHashMap (rustc-hash) for all internal maps | High |
| Small collections | SmallVec<[T; 4]> | Medium-High |
| Ordered maps | BTreeMap | High |
| String interning | lasso (ThreadedRodeo → RodeoReader) | High |
