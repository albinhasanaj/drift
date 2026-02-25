# Infrastructure — V2 Implementation Prep

> Comprehensive build specification for Drift v2's cross-cutting infrastructure layer.
> Synthesized from: 04-INFRASTRUCTURE.md (error handling, tracing, events, config, data structures),
> DRIFT-V2-FULL-SYSTEM-AUDIT.md (AD1-AD12, Cat 00, Appendix A1-A21),
> DRIFT-V2-STACK-HIERARCHY.md (Level 0 Bedrock + Level 6 Cross-Cutting),
> PLANNING-DRIFT.md (D1-D7), .research/12-infrastructure/RECOMMENDATIONS.md (FA1-FA3, R1-R22),
> 12-infrastructure/ research docs (overview, build-system, ci-cd, licensing, docker, telemetry,
> ci-agent, ai-providers, github-action, rust-build, cibench, galaxy, scripts),
> 00-SCANNER-V2-PREP.md, 02-STORAGE-V2-PREP.md, 03-NAPI-BRIDGE-V2-PREP.md (format reference),
> and internet validation of tooling choices.
>
> Purpose: Everything needed to build Drift v2's infrastructure from scratch. Every v1 feature
> accounted for. Every recommendation (FA1-FA3, R1-R22) integrated. Every v1 limitation resolved.
> Decisions resolved, inconsistencies flagged, build order specified.
>
> Generated: 2026-02-07

---

## 1. Architectural Position

Infrastructure is unique in the Drift hierarchy — it spans two levels simultaneously:

**Level 0 — Bedrock** (must exist before the first line of analysis code):
- Error handling (thiserror, per-subsystem enums)
- Observability (tracing crate, structured spans)
- Event system (DriftEventHandler trait, no-op defaults)
- Configuration system (TOML, layered resolution)
- Data structures (FxHashMap, SmallVec, BTreeMap, lasso)

**Level 6 — Cross-Cutting** (parallel to analysis, not blocking it):
- Build system (Cargo workspace, pnpm + Turborepo)
- CI/CD pipeline (Rust CI, supply chain security, testing)
- Cross-compilation (NAPI-RS v3, cargo-zigbuild, 8 platform targets)
- Docker deployment (multi-arch Alpine, pre-built binaries)
- Release orchestration (Changesets, release-plz, cross-registry)
- Licensing & feature gating (3 tiers, 16 features, JWT validation)
- Telemetry (Cloudflare Worker + D1, Rust events)
- CI agent (9 analysis passes, SARIF, incremental)
- AI providers (Anthropic, OpenAI, Ollama — stays TS)
- GitHub Action v2 (SARIF upload, split MCP)
- CIBench (4-level benchmark framework)
- Galaxy visualization (3D viz — stays TS/React)
- Developer experience (Justfile, pre-commit hooks, VS Code settings)
- Workspace management (init, switch, backup, migrate)

Per PLANNING-DRIFT.md D5: The event system is infrastructure, not a feature. It's the hook
point the bridge crate latches onto. Per AD6: error handling from the first line of code.
Per AD10: observability from the first line of code.

The Stack Hierarchy doc expanded Bedrock from 4 → 8 systems specifically because D5/AD6/AD10
require infrastructure to exist before any analysis code is written.

**Dependency truth**: Config + Error Handling + Tracing + Events → Scanner → Parsers → Storage → NAPI → everything else.

---

## 2. Error Handling System (thiserror)

### Decision: thiserror with per-subsystem enums, structured NAPI error codes
### Source: AD6, 04-INFRASTRUCTURE.md, NAPI-BRIDGE-V2-PREP.md


### Why thiserror, Not anyhow

`anyhow` is for applications where you don't need to match on error variants. Drift needs
structured errors because:
- NAPI bridge must convert errors to specific error codes for TypeScript
- MCP tools need to return meaningful error responses
- Quality gates need to distinguish "scan failed" from "violations found"
- The event system (D5) needs to emit typed error events

**Rule: `thiserror` for defining error types. `anyhow` nowhere in the codebase.**

### Per-Subsystem Error Enums

One error enum per subsystem, not one global enum. From the Rust application error design
pattern: "use an enum per function (or per module), instead of a global Error enum."

```rust
// ---- Scanner Errors ----
#[derive(Error, Debug)]
pub enum ScanError {
    #[error("IO error scanning {path}: {source}")]
    Io { path: PathBuf, source: std::io::Error },

    #[error("File too large: {path} ({size} bytes, max {max})")]
    FileTooLarge { path: PathBuf, size: u64, max: u64 },

    #[error("Permission denied: {path}")]
    PermissionDenied { path: PathBuf },

    #[error("Config error: {message}")]
    Config { message: String },

    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("Scan cancelled")]
    Cancelled,
}

// ---- Parser Errors ----
#[derive(Error, Debug)]
pub enum ParseError {
    #[error("Unsupported language: {extension}")]
    UnsupportedLanguage { extension: String },

    #[error("Parse failed for {path}: {message}")]
    ParseFailed { path: PathBuf, message: String },

    #[error("Query compilation failed: {0}")]
    QueryCompilation(String),

    #[error("Grammar not loaded: {language}")]
    GrammarNotLoaded { language: String },
}

// ---- Storage Errors ----
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

// ---- Detection Errors ----
#[derive(Error, Debug)]
pub enum DetectionError {
    #[error("Detector {id} failed: {message}")]
    DetectorFailed { id: String, message: String },

    #[error("Pattern definition invalid: {0}")]
    InvalidPattern(String),

    #[error("TOML parse error in {path}: {source}")]
    TomlParse { path: PathBuf, source: toml::de::Error },
}

// ---- Call Graph Errors ----
#[derive(Error, Debug)]
pub enum CallGraphError {
    #[error("Graph cycle detected: {path:?}")]
    CycleDetected { path: Vec<String> },

    #[error("Node not found: {name}")]
    NodeNotFound { name: String },

    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),
}

// ---- Pipeline Errors (aggregates subsystem errors) ----
#[derive(Error, Debug)]
pub enum PipelineError {
    #[error("Scan error: {0}")]
    Scan(#[from] ScanError),

    #[error("Parse error: {0}")]
    Parse(#[from] ParseError),

    #[error("Detection error: {0}")]
    Detection(#[from] DetectionError),

    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("Call graph error: {0}")]
    CallGraph(#[from] CallGraphError),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Pipeline cancelled")]
    Cancelled,
}
```

### Error Propagation Pattern

At module boundaries, convert to the parent's error type via `From`. At the NAPI boundary,
convert to `napi::Error` with structured error codes:

```rust
impl From<PipelineError> for napi::Error {
    fn from(err: PipelineError) -> Self {
        let (code, msg) = match &err {
            PipelineError::Scan(ScanError::Cancelled) => ("CANCELLED", err.to_string()),
            PipelineError::Scan(ScanError::Io { .. }) => ("SCAN_IO_ERROR", err.to_string()),
            PipelineError::Scan(_) => ("SCAN_ERROR", err.to_string()),
            PipelineError::Parse(ParseError::UnsupportedLanguage { .. }) =>
                ("UNSUPPORTED_LANGUAGE", err.to_string()),
            PipelineError::Parse(_) => ("PARSE_ERROR", err.to_string()),
            PipelineError::Storage(StorageError::Busy) => ("DB_BUSY", err.to_string()),
            PipelineError::Storage(StorageError::Corrupt(_)) => ("DB_CORRUPT", err.to_string()),
            PipelineError::Storage(StorageError::DiskFull) => ("DISK_FULL", err.to_string()),
            PipelineError::Storage(_) => ("STORAGE_ERROR", err.to_string()),
            PipelineError::Detection(_) => ("DETECTION_ERROR", err.to_string()),
            PipelineError::CallGraph(_) => ("CALL_GRAPH_ERROR", err.to_string()),
            PipelineError::Config(_) => ("CONFIG_ERROR", err.to_string()),
            PipelineError::Cancelled => ("CANCELLED", err.to_string()),
        };
        napi::Error::new(napi::Status::GenericFailure, format!("[{}] {}", code, msg))
    }
}
```

### NAPI Error Code Registry

All error codes that cross the NAPI boundary, for TypeScript consumption:

| Code | Subsystem | Meaning |
|------|-----------|---------|
| `SCAN_ERROR` | Scanner | General scan failure |
| `SCAN_IO_ERROR` | Scanner | File I/O error during scan |
| `CANCELLED` | Any | Operation cancelled by user |
| `UNSUPPORTED_LANGUAGE` | Parser | Language not supported |
| `PARSE_ERROR` | Parser | General parse failure |
| `DB_BUSY` | Storage | Database locked by another operation |
| `DB_CORRUPT` | Storage | Database integrity check failed |
| `DISK_FULL` | Storage | No disk space for write |
| `STORAGE_ERROR` | Storage | General storage failure |
| `DETECTION_ERROR` | Detection | Detector execution failure |
| `CALL_GRAPH_ERROR` | Call Graph | Graph operation failure |
| `CONFIG_ERROR` | Config | Invalid configuration |
| `LICENSE_ERROR` | Licensing | License validation failure |
| `GATE_FAILED` | Quality Gates | Quality gate check failed |

### Non-Fatal Error Collection

Errors at the file level are non-fatal. A single file failing to parse should not abort the
entire pipeline. Collect errors, continue processing, report at the end:

```rust
pub struct PipelineResult {
    pub patterns: Vec<Pattern>,
    pub violations: Vec<Violation>,
    pub errors: Vec<PipelineError>,  // Non-fatal errors collected during run
    pub stats: PipelineStats,
}
```

---

## 3. Observability System (tracing crate)

### Decision: tracing crate with per-subsystem spans, EnvFilter, optional OpenTelemetry
### Source: AD10, 04-INFRASTRUCTURE.md, R15

### Why tracing, Not log

The `tracing` crate provides structured, span-based instrumentation:
- **Spans**: Hierarchical timing regions (scan span → parse span → detect span)
- **Structured fields**: Key-value pairs on every event, not just format strings
- **Subscriber-based**: Multiple outputs (console, file, OpenTelemetry) from same instrumentation
- **Zero-cost when disabled**: Compile-time feature flags remove all tracing

`tracing` is the de facto Rust ecosystem standard. Used by tokio, hyper, axum, tower, tonic.

### Initialization

```rust
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

pub fn init_tracing() {
    let filter = EnvFilter::try_from_env("DRIFT_LOG")
        .unwrap_or_else(|_| EnvFilter::new("drift=info"));

    tracing_subscriber::registry()
        .with(fmt::layer()
            .with_target(true)
            .with_thread_ids(true)
            .with_file(true)
            .with_line_number(true))
        .with(filter)
        .init();
}
```

Configurable per-subsystem: `DRIFT_LOG=scanner=debug,parser=info,detector=warn`

### Instrumentation Pattern

```rust
use tracing::{info, warn, instrument, info_span};

#[instrument(skip(config, db), fields(root = %root.display()))]
pub fn scan(root: &Path, config: &ScanConfig, db: &DatabaseManager)
    -> Result<ScanDiff, ScanError>
{
    let _discovery = info_span!("discovery").entered();
    let files = discover_files(root, config)?;
    info!(file_count = files.len(), "discovery complete");

    let _processing = info_span!("processing").entered();
    let diff = compute_diff(files, db)?;
    info!(
        added = diff.added.len(),
        modified = diff.modified.len(),
        removed = diff.removed.len(),
        "diff complete"
    );

    Ok(diff)
}
```

### Key Metrics to Instrument (from AD10)

| Metric | Subsystem | Why |
|--------|-----------|-----|
| `scan_files_per_second` | Scanner | Overall throughput |
| `discovery_duration_ms` | Scanner | Phase 1 time |
| `hashing_duration_ms` | Scanner | Phase 2 time |
| `cache_hit_rate` | Scanner, Parser | Validate caching strategy |
| `parse_time_per_language` | Parser | Identify slow grammars |
| `detection_time_per_category` | Detectors | Find expensive detectors |
| `napi_serialization_time` | NAPI Bridge | Catch boundary bottlenecks |
| `mcp_response_time` | MCP Server | User-facing latency |
| `batch_write_time` | Storage | Database write performance |
| `call_graph_build_time` | Call Graph | Graph construction time |
| `confidence_compute_time` | Confidence | Bayesian scoring overhead |
| `gate_evaluation_time` | Quality Gates | Gate check latency |

### TypeScript Observability (pino)

For the TS orchestration layer (MCP server, CLI, CI agent):

```typescript
import pino from 'pino';

const logger = pino({
    level: process.env.LOG_LEVEL || 'info',
    transport: process.env.NODE_ENV === 'development'
        ? { target: 'pino-pretty' } : undefined,
});

logger.info({ fileCount: files.length, root }, 'starting scan');
```

### Optional OpenTelemetry (Enterprise Feature)

For enterprise distributed tracing, add `tracing-opentelemetry` as an optional subscriber:

```rust
#[cfg(feature = "otel")]
fn init_otel_layer() -> impl tracing_subscriber::Layer<impl tracing::Subscriber> {
    use tracing_opentelemetry::OpenTelemetryLayer;
    use opentelemetry_otlp::WithExportConfig;

    let tracer = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(opentelemetry_otlp::new_exporter().tonic())
        .install_batch(opentelemetry_sdk::runtime::Tokio)
        .expect("Failed to install OTLP tracer");

    OpenTelemetryLayer::new(tracer)
}
```

This is a feature flag — not compiled in for community builds. Gated behind
`gate:enterprise` license tier.

---

## 4. Event System (DriftEventHandler Trait)

### Decision: Trait with no-op defaults, Vec<Arc<dyn Handler>>, synchronous dispatch
### Source: D5, 04-INFRASTRUCTURE.md, Stack Hierarchy

Per D5: This is the hook point the bridge crate latches onto. Every subsystem that changes
state should emit events. If subsystems don't emit events from day one, you retrofit every
subsystem later.

### Full Trait Definition

```rust
pub trait DriftEventHandler: Send + Sync {
    // ---- Scan Lifecycle ----
    fn on_scan_started(&self, _root: &Path, _file_count: Option<usize>) {}
    fn on_scan_progress(&self, _processed: usize, _total: usize) {}
    fn on_scan_complete(&self, _results: &ScanDiff) {}
    fn on_scan_error(&self, _error: &ScanError) {}

    // ---- Pattern Lifecycle ----
    fn on_pattern_discovered(&self, _pattern: &Pattern) {}
    fn on_pattern_approved(&self, _pattern: &Pattern) {}
    fn on_pattern_ignored(&self, _pattern: &Pattern) {}
    fn on_pattern_merged(&self, _kept: &Pattern, _merged: &Pattern) {}

    // ---- Violations ----
    fn on_violation_detected(&self, _violation: &Violation) {}
    fn on_violation_dismissed(&self, _violation: &Violation, _reason: &str) {}
    fn on_violation_fixed(&self, _violation: &Violation) {}

    // ---- Enforcement ----
    fn on_gate_evaluated(&self, _gate: &str, _result: &GateResult) {}
    fn on_regression_detected(&self, _regression: &Regression) {}

    // ---- Detector Health ----
    fn on_detector_alert(&self, _detector_id: &str, _fp_rate: f64) {}
    fn on_detector_disabled(&self, _detector_id: &str, _reason: &str) {}

    // ---- Errors ----
    fn on_error(&self, _error: &PipelineError) {}
}
```

### Handler Registration and Dispatch

```rust
pub struct DriftEngine {
    event_handlers: Vec<Arc<dyn DriftEventHandler>>,
    // ... other fields
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

// Usage in subsystems:
self.emit(|h| h.on_scan_complete(&diff));
self.emit(|h| h.on_pattern_approved(&pattern));
self.emit(|h| h.on_gate_evaluated("pattern_compliance", &result));
```

### Zero Overhead in Standalone Mode

When no handlers are registered (standalone Drift, no bridge), the `emit()` call iterates
over an empty Vec — effectively zero cost. The compiler may optimize it away entirely.

When the bridge is active, it registers a handler that creates Cortex memories from Drift
events. Drift doesn't know or care.

### Bridge Event Mapping (for reference — implemented in cortex-drift-bridge)

| Drift Event | Cortex Memory Type | Notes |
|-------------|-------------------|-------|
| `on_pattern_approved` | `pattern_rationale` | Pattern → memory with confidence |
| `on_scan_complete` | Ground-truth validation | Compare scan results vs memories |
| `on_regression_detected` | `decision_context` | Regression → review memory |
| `on_violation_dismissed` | `constraint_override` | Dismissal reason → memory |
| `on_detector_disabled` | `anti_pattern` | Auto-disable → learning signal |

---

## 5. Configuration System

### Decision: TOML format (drift.toml), layered resolution
### Source: 04-INFRASTRUCTURE.md, A22, Scanner V2 Prep §7

### Config Resolution Order

```
CLI flags > env vars (DRIFT_*) > project config (drift.toml) > user config (~/.config/drift/drift.toml) > defaults
```

### Full Configuration Struct

```rust
use serde::Deserialize;

#[derive(Deserialize, Default, Debug, Clone)]
pub struct DriftConfig {
    #[serde(default)]
    pub scan: ScanConfig,
    #[serde(default)]
    pub analysis: AnalysisConfig,
    #[serde(default)]
    pub quality_gates: GateConfig,
    #[serde(default)]
    pub mcp: McpConfig,
    #[serde(default)]
    pub backup: BackupConfig,
    #[serde(default)]
    pub telemetry: TelemetryConfig,
    #[serde(default)]
    pub licensing: LicenseConfig,
}

#[derive(Deserialize, Default, Debug, Clone)]
pub struct ScanConfig {
    /// Maximum file size in bytes. Default: 1MB (1_048_576).
    pub max_file_size: Option<u64>,
    /// Number of threads. 0 = auto-detect via num_cpus.
    pub threads: Option<usize>,
    /// Additional ignore patterns beyond .gitignore/.driftignore.
    #[serde(default)]
    pub extra_ignore: Vec<String>,
    /// Follow symbolic links. Default: false.
    pub follow_symlinks: Option<bool>,
    /// Compute content hashes. Default: true.
    pub compute_hashes: Option<bool>,
    /// Force full rescan, skip mtime optimization. Default: false.
    pub force_full_scan: Option<bool>,
    /// Skip binary files. Default: true.
    pub skip_binary: Option<bool>,
    /// Hash algorithm. Default: "xxh3". Alternative: "blake3" (enterprise).
    pub hash_algorithm: Option<String>,
}

#[derive(Deserialize, Default, Debug, Clone)]
pub struct AnalysisConfig {
    /// Minimum occurrences for pattern discovery. Default: 3.
    pub min_occurrences: Option<u32>,
    /// Dominance threshold for convention detection. Default: 0.60.
    pub dominance_threshold: Option<f64>,
    /// Minimum files for pattern to be considered. Default: 2.
    pub min_files: Option<u32>,
    /// Re-learning threshold (% files changed to trigger full re-learn). Default: 0.10.
    pub relearn_threshold: Option<f64>,
}

#[derive(Deserialize, Default, Debug, Clone)]
pub struct GateConfig {
    /// Fail level: "error" | "warning" | "info". Default: "error".
    pub fail_on: Option<String>,
    /// Required gates to pass. Default: all gates.
    #[serde(default)]
    pub required_gates: Vec<String>,
    /// Minimum drift score to pass (0-100). Default: 70.
    pub min_score: Option<u32>,
}

#[derive(Deserialize, Default, Debug, Clone)]
pub struct McpConfig {
    /// Cache TTL in seconds. Default: 300.
    pub cache_ttl_seconds: Option<u64>,
    /// Maximum response tokens. Default: 8000.
    pub max_response_tokens: Option<u32>,
}

#[derive(Deserialize, Default, Debug, Clone)]
pub struct BackupConfig {
    /// Maximum operational backups. Default: 5.
    pub max_operational: Option<u32>,
    /// Maximum daily backups. Default: 7.
    pub max_daily: Option<u32>,
}

#[derive(Deserialize, Default, Debug, Clone)]
pub struct TelemetryConfig {
    /// Enable anonymous telemetry. Default: false.
    pub enabled: Option<bool>,
    /// Telemetry endpoint URL.
    pub endpoint: Option<String>,
}

#[derive(Deserialize, Default, Debug, Clone)]
pub struct LicenseConfig {
    /// License key (alternative to env var / file).
    pub key: Option<String>,
    /// Upgrade URL. Default: "https://driftscan.dev/pricing".
    pub upgrade_url: Option<String>,
}
```

### Example drift.toml

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
fail_on = "error"
required_gates = ["pattern_compliance", "security_boundaries"]
min_score = 70

[mcp]
cache_ttl_seconds = 300
max_response_tokens = 8000

[backup]
max_operational = 5
max_daily = 7

[telemetry]
enabled = false
```

### Config Loading Implementation

```rust
pub fn load_config(root: &Path, cli_overrides: Option<&CliArgs>) -> DriftConfig {
    let project_config = root.join("drift.toml");
    let user_config = dirs::config_dir().map(|d| d.join("drift/drift.toml"));

    let mut config = DriftConfig::default();

    // Layer 1: user config (lowest priority)
    if let Some(path) = user_config {
        if path.exists() {
            merge_toml_config(&mut config, &path);
        }
    }

    // Layer 2: project config (overrides user)
    if project_config.exists() {
        merge_toml_config(&mut config, &project_config);
    }

    // Layer 3: env vars (DRIFT_SCAN_MAX_FILE_SIZE, etc.)
    apply_env_overrides(&mut config);

    // Layer 4: CLI flags (highest priority)
    if let Some(cli) = cli_overrides {
        apply_cli_overrides(&mut config, cli);
    }

    config
}
```

### Config Validation

```rust
pub fn validate_config(config: &DriftConfig) -> Result<(), ConfigError> {
    if let Some(threshold) = config.analysis.dominance_threshold {
        if !(0.0..=1.0).contains(&threshold) {
            return Err(ConfigError::InvalidValue {
                field: "analysis.dominance_threshold".into(),
                message: "must be between 0.0 and 1.0".into(),
            });
        }
    }
    if let Some(score) = config.quality_gates.min_score {
        if score > 100 {
            return Err(ConfigError::InvalidValue {
                field: "quality_gates.min_score".into(),
                message: "must be between 0 and 100".into(),
            });
        }
    }
    Ok(())
}
```

---

## 6. Data Structures (AD12)

### Decision: FxHashMap, SmallVec<[T;4]>, BTreeMap, lasso string interning
### Source: AD12, 04-INFRASTRUCTURE.md

These are cross-cutting performance decisions that affect every system.

### FxHashMap (rustc-hash crate)

From the Rust Performance Book: switching from default HashMap to FxHashMap gave speedups
of up to 6% in rustc. FxHash is a fast, non-cryptographic hasher from Firefox.

**When to use**: All internal hash maps (symbol tables, detector registries, resolution indexes,
pattern maps, call graph adjacency).
**When NOT to use**: Anything exposed to untrusted input (but Drift doesn't have this — all
data comes from the user's own codebase).

```rust
use rustc_hash::{FxHashMap, FxHashSet};

// Symbol table
let mut symbols: FxHashMap<Spur, FunctionEntry> = FxHashMap::default();

// Detector registry
let mut detectors: FxHashMap<String, Box<dyn Detector>> = FxHashMap::default();

// Pattern index
let mut patterns: FxHashMap<PatternId, Pattern> = FxHashMap::default();
```

### SmallVec

`SmallVec<[T; N]>` stores up to N elements inline (stack) before falling back to heap.
Ideal for collections that are usually small and created/destroyed frequently.

```rust
use smallvec::SmallVec;

// Most patterns have <4 locations
pub locations: SmallVec<[PatternLocation; 4]>,

// Most functions call <8 other functions
pub call_edges: SmallVec<[CallEdge; 8]>,

// Most files have <4 imports from the same module
pub imports: SmallVec<[ImportInfo; 4]>,

// Most detectors produce <4 matches per file
pub matches: SmallVec<[PatternMatch; 4]>,
```

### BTreeMap

Use `BTreeMap` instead of `HashMap` when you need ordered iteration:
- Resolution indexes (sorted by confidence for priority resolution)
- Pattern aggregation (sorted by category for deterministic output)
- Any data that needs deterministic iteration order (test stability)

### String Interning (lasso crate)

The `lasso` crate provides string interning with two modes:
- `ThreadedRodeo`: Thread-safe, mutable (for build/scan phase)
- `RodeoReader`: Immutable, contention-free (for query phase)

Interning converts string comparisons to integer comparisons and reduces memory by
deduplicating identical strings. The audit estimates 60-80% memory reduction from
interning file paths and function names.

```rust
use lasso::{ThreadedRodeo, RodeoReader, Spur};

// During scan (mutable, thread-safe)
let interner = ThreadedRodeo::default();
let key: Spur = interner.get_or_intern("src/main.ts");

// After scan (immutable, zero-contention reads)
let reader: RodeoReader = interner.into_reader();
let name: &str = reader.resolve(&key);
```

### Domain Wrappers (from audit)

```rust
/// Normalizes path separators before interning
pub struct PathInterner {
    inner: ThreadedRodeo,
}

impl PathInterner {
    pub fn intern(&self, path: &str) -> Spur {
        let normalized = path.replace('\\', "/");
        self.inner.get_or_intern(&normalized)
    }
}

/// Supports qualified name interning (Class.method)
pub struct FunctionInterner {
    inner: ThreadedRodeo,
}

impl FunctionInterner {
    pub fn intern_qualified(&self, class: &str, method: &str) -> Spur {
        let qualified = format!("{}.{}", class, method);
        self.inner.get_or_intern(&qualified)
    }
}
```

### Cargo Dependencies for Data Structures

```toml
[workspace.dependencies]
rustc-hash = "2"
smallvec = { version = "1.13", features = ["serde"] }
lasso = { version = "0.7", features = ["multi-threaded", "serialize"] }
```


---

## 7. Build System

### Decision: Cargo workspace expansion (FA3) + pnpm 8 + Turborepo + Justfile
### Source: FA3, R5, R6, R22, build-system.md, rust-build.md

### Cargo Workspace (Rust Side)

v1 has 2 crates (`drift-core`, `drift-napi`). v2 expands to 5-6 crates with feature flags
for conditional compilation.

```toml
[workspace]
resolver = "2"
members = [
    "crates/drift-core",       # Core types, traits, errors, config
    "crates/drift-analysis",   # Parsers, detectors, call graph, boundaries
    "crates/drift-storage",    # SQLite persistence, migrations, batch writer
    "crates/drift-napi",       # NAPI-RS v3 bindings
    "crates/drift-bench",      # Benchmarks (criterion) — isolated from production
]

[workspace.package]
edition = "2021"
rust-version = "1.75"
license = "MIT"

[workspace.dependencies]
# Parsing
tree-sitter = "0.24"

# Storage
rusqlite = { version = "0.32", features = ["bundled"] }

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"

# Error handling & observability
thiserror = "2"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

# Performance
rustc-hash = "2"
smallvec = { version = "1.13", features = ["serde"] }
lasso = { version = "0.7", features = ["multi-threaded", "serialize"] }
rayon = "1.10"
xxhash-rust = { version = "0.8", features = ["xxh3"] }

# Graph
petgraph = "0.6"

# Caching
moka = { version = "0.12", features = ["sync"] }

# File system
ignore = "0.4"

# NAPI
napi = { version = "3", features = ["async", "serde-json"] }
napi-derive = "3"

[workspace.lints.clippy]
correctness = { level = "deny" }
suspicious = { level = "deny" }
perf = { level = "deny" }
style = { level = "warn" }
complexity = { level = "warn" }
unwrap_used = { level = "deny" }
panic = { level = "deny" }
expect_used = { level = "warn" }
```

### Feature Flags (drift-core/Cargo.toml)

```toml
[features]
default = ["cortex", "mcp"]
cortex = ["dep:drift-cortex-core"]
mcp = []
wasm = []
benchmark = ["dep:criterion"]
otel = ["dep:tracing-opentelemetry", "dep:opentelemetry-otlp"]
lang-python = ["dep:tree-sitter-python"]
lang-java = ["dep:tree-sitter-java"]
lang-rust = ["dep:tree-sitter-rust"]
full = ["cortex", "mcp", "lang-python", "lang-java", "lang-rust"]
```

### Crate Splitting Rationale

| Crate | Responsibility | Why Separate |
|-------|---------------|--------------|
| `drift-core` | Types, traits, errors, config, event system | Foundation — everything depends on this |
| `drift-analysis` | Parsers, detectors, call graph, boundaries, coupling | Separates parsing (fast, stateless) from persistence |
| `drift-storage` | SQLite, migrations, batch writer, CQRS | Schema changes don't recompile parsers |
| `drift-napi` | NAPI-RS v3 bindings | Bridge layer — depends on all above |
| `drift-bench` | Benchmarks (criterion) | Benchmark deps don't pollute production |

### Release Profile

```toml
[profile.release]
lto = true           # Link-time optimization
codegen-units = 1    # Single codegen unit for max optimization
opt-level = 3        # Maximum optimization
strip = "symbols"    # Strip debug symbols from release binaries
```

### pnpm Workspace (TypeScript Side)

v2 consolidates from 12 packages to a focused set:

```yaml
# pnpm-workspace.yaml
packages:
  - "packages/mcp"        # MCP server (drift-analysis + drift-memory)
  - "packages/cli"        # CLI commands, reporters, UI
  - "packages/ci"         # CI agent (PR analysis, GitHub/GitLab)
  - "packages/ai"         # AI provider abstraction (Anthropic, OpenAI, Ollama)
  - "packages/vscode"     # VSCode extension
  - "packages/lsp"        # LSP server
  - "packages/dashboard"  # Web dashboard (Vite + React + Tailwind)
  - "packages/galaxy"     # 3D visualization (Three.js)
  - "packages/cibench"    # Benchmark framework
```

### Turborepo Configuration

```json
{
  "$schema": "https://turbo.build/schema.json",
  "pipeline": {
    "build": {
      "dependsOn": ["^build"],
      "outputs": ["dist/**"],
      "cache": true
    },
    "typecheck": {
      "dependsOn": ["^build"],
      "cache": true
    },
    "lint": {
      "dependsOn": ["^build"],
      "cache": true
    },
    "test": {
      "dependsOn": ["build"],
      "outputs": ["coverage/**"],
      "cache": true
    }
  }
}
```

### Turborepo Remote Caching (R5)

40-70% CI build time reduction for TypeScript packages.

**Recommended**: GitHub Actions cache via `robobat/setup-turbo-cache` — zero external dependencies.

```yaml
- name: Setup Turbo Cache
  uses: robobat/setup-turbo-cache@v1
- name: Build affected packages
  run: pnpm turbo build --filter='...[HEAD^1]'
```

### Rust Compilation Caching — sccache (R6)

60-80% Rust compilation time reduction in CI.

```yaml
- name: Setup sccache
  uses: mozilla-actions/sccache-action@v0.0.6
  with:
    version: "v0.8.2"
- name: Configure Rust to use sccache
  env:
    SCCACHE_GHA_ENABLED: "true"
    RUSTC_WRAPPER: sccache
```

Why sccache over `actions/cache` on `target/`: sccache caches individual compilation units
(more granular), handles cache invalidation correctly, and doesn't cache 2-5GB of target/.

### Justfile (R22 — Task Runner)

```just
# Build everything
build: build-rust build-ts
build-rust:
    cargo build --workspace
build-ts:
    pnpm turbo build

# Check everything
check: check-rust check-ts
check-rust:
    cargo clippy --all-targets --all-features -- -D warnings
    cargo fmt --check
    cargo nextest run --all-features
check-ts:
    pnpm turbo lint test

# Benchmarks
bench:
    cargo bench --bench parsing --bench full_pipeline

# Release build
release:
    cargo build --workspace --release

# Development setup
setup-dev:
    @echo "Checking prerequisites..."
    node --version
    pnpm --version
    rustc --version
    pnpm install
    cargo build
    @echo "Development environment ready."
```

### TypeScript Configuration

Strict mode stays from v1 — all strict flags enabled:
- `strict`, `noImplicitAny`, `strictNullChecks`, `strictFunctionTypes`
- `noUnusedLocals`, `noUnusedParameters`, `exactOptionalPropertyTypes`
- `noImplicitReturns`, `noFallthroughCasesInSwitch`, `noUncheckedIndexedAccess`

Target: ES2022, Module: NodeNext, Module Resolution: NodeNext.

### ESLint

Flat config format. Key rules preserved from v1:
- `no-floating-promises: warn` — async safety
- `no-misused-promises: warn` — async safety
- `await-thenable: error` — async correctness
- `strict-boolean-expressions: warn` — truthiness bugs
- `eqeqeq: error` — strict equality

### Vitest

- Pool: `threads` (parallel)
- Timeout: 10s
- Coverage: v8 provider, 80% thresholds (statements, branches, functions, lines)

---

## 8. CI/CD Pipeline

### Decision: Rust CI as blocking gate (FA1) + supply chain security (FA2)
### Source: FA1, FA2, R1-R3, R12-R14, ci-cd.md

### v1 CI Debt (What's Wrong)

v1's `ci.yml` has critical issues:
- Build and test both use `continue-on-error: true` — failures don't block merges
- Lint is disabled entirely
- No Rust CI at all — zero clippy, zero fmt, zero Rust tests
- No dependency scanning, no SBOM, no provenance

v2 fixes all of this. Every check is blocking.

### Rust CI Pipeline (FA1 — P0)

```yaml
name: Rust CI
on:
  push:
    branches: [main]
    paths: ['crates/**', 'Cargo.toml', 'Cargo.lock']
  pull_request:
    branches: [main]
    paths: ['crates/**', 'Cargo.toml', 'Cargo.lock']

jobs:
  rust-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust stable
        uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy, rustfmt

      - name: Setup sccache
        uses: mozilla-actions/sccache-action@v0.0.6
      - name: Configure sccache
        run: echo "RUSTC_WRAPPER=sccache" >> $GITHUB_ENV

      # Stage 1: Format (fastest, fail-fast)
      - name: Check formatting
        run: cargo fmt --all --check

      # Stage 2: Lint
      - name: Clippy
        run: cargo clippy --workspace --all-targets --all-features -- -D warnings

      # Stage 3: Test
      - name: Install nextest
        uses: taiki-e/install-action@nextest
      - name: Run tests
        run: cargo nextest run --workspace --all-features --profile ci

      # Stage 4: Dependency audit
      - name: Install cargo-deny
        uses: taiki-e/install-action@cargo-deny
      - name: Check dependencies
        run: cargo deny check --all
```

### Supply Chain Security Pipeline (FA2 — P0)

4 pillars running on every PR and release:

**Pillar 1 — Dependency Auditing (every PR)**:
```yaml
# Rust
cargo deny check advisories
cargo deny check licenses
cargo deny check bans
cargo deny check sources
# TypeScript
pnpm audit --audit-level=high
```

**Pillar 2 — SBOM Generation (every release, R2)**:
```yaml
- name: Generate Rust SBOM
  run: cargo cyclonedx --format json --output-file drift-rust-sbom.cdx.json
- name: Generate npm SBOM
  run: npx @cyclonedx/cyclonedx-npm --output-file drift-npm-sbom.cdx.json
```

CycloneDX over SPDX: better tooling for both Rust and npm, explicitly accepted by EU CRA.
EU CRA compliance deadline: December 2027. Non-compliance risks EUR 15M fines.

**Pillar 3 — SLSA Level 3 Provenance (every release, R3)**:
```yaml
- name: Publish with provenance
  run: pnpm publish --provenance --access public
- name: Attest build provenance
  uses: actions/attest-build-provenance@v2
  with:
    subject-path: 'crates/drift-napi/artifacts/*.node'
```

**Pillar 4 — Automated Dependency Updates**:
```yaml
# .github/dependabot.yml
updates:
  - package-ecosystem: "cargo"
    schedule: { interval: "weekly" }
  - package-ecosystem: "npm"
    schedule: { interval: "weekly" }
  - package-ecosystem: "github-actions"
    schedule: { interval: "weekly" }
```

### cargo-deny Configuration (R1)

```toml
# deny.toml
[licenses]
allow = [
    "MIT", "Apache-2.0", "Apache-2.0 WITH LLVM-exception",
    "BSD-2-Clause", "BSD-3-Clause", "ISC", "Zlib",
    "Unicode-DFS-2016", "BSL-1.0", "CC0-1.0", "OpenSSL",
]
deny = ["AGPL-3.0", "GPL-3.0", "SSPL-1.0"]
copyleft = "deny"
confidence-threshold = 0.8

[bans]
multiple-versions = "warn"
wildcards = "deny"

[advisories]
vulnerability = "deny"
unmaintained = "warn"
yanked = "deny"

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
```

### cargo-nextest Configuration (R12)

```toml
# .config/nextest.toml
[profile.ci]
retries = 2
fail-fast = false
slow-timeout = { period = "30s", terminate-after = 2 }
status-level = "fail"
final-status-level = "flaky"

[profile.ci.junit]
path = "target/nextest/ci/junit.xml"
```

Why nextest over `cargo test`: parallel binary execution (3x faster), JUnit XML output,
built-in flaky retry, per-test isolation, `--partition` for CI runner splitting.

### Performance Regression Detection (R13)

**Tier 1 — Free (criterion-compare)**:
```yaml
- name: Run benchmarks
  run: cargo bench --bench parsing --bench full_pipeline -- --save-baseline pr
- name: Compare with main
  uses: boa-dev/criterion-compare-action@v3
  with:
    branchName: main
```

Statistical gating: GitHub-hosted runners have 2.66% coefficient of variation.
Minimum reliable gate on hosted runners is 10% regression threshold.

**Tier 2 — Precise (CodSpeed, future)**:
CodSpeed enables 5% detection with <1% variance. Optional upgrade path.

Benchmark targets: `parsing` (per-language), `full_pipeline` (end-to-end),
`detection` (pattern throughput), `call_graph` (graph building).

### E2E Integration Test Suite (R14)

End-to-end tests that exercise the complete pipeline:

| Scenario | What It Tests |
|----------|--------------|
| Full scan | Scan synthetic codebase → verify patterns → verify call graph → verify storage |
| MCP query | Start MCP server → send `drift_context` → verify response |
| Quality gate | Run `drift gate --ci` → verify pass/fail based on known violations |
| Incremental | Modify files → re-scan → verify only changed files re-analyzed |

Synthetic codebases: reuse v1's `generate-large-codebase.ts`, extended with known patterns,
violations, and call graph structures as ground truth.

### TypeScript CI Pipeline

```yaml
ts-check:
  runs-on: ubuntu-latest
  strategy:
    matrix:
      node-version: [18, 20, 22]
  steps:
    - uses: actions/checkout@v4
    - uses: pnpm/action-setup@v4
    - uses: actions/setup-node@v4
      with:
        node-version: ${{ matrix.node-version }}
        cache: 'pnpm'
    - run: pnpm install --frozen-lockfile
    - run: pnpm turbo build
    - run: pnpm turbo lint
    - run: pnpm turbo test
    - run: pnpm turbo typecheck
```

No `continue-on-error`. All checks blocking.


---

## 9. Cross-Compilation

### Decision: NAPI-RS v3 (R4) + cargo-zigbuild (R7) for 8 platform targets
### Source: R4, R7, R21, rust-build.md, native-build.yml

### NAPI-RS v3 Migration (R4 — P0)

Key benefits over v2:
1. **WebAssembly target**: Compile to `wasm32-wasip1-threads` with minimal code changes
2. **Lifetime safety**: Prevents `JsObject` from escaping scope — critical for long-running MCP
3. **ThreadsafeFunction redesign**: Simplifies async bridge between Rust analysis and Node.js
4. **Simplified cross-compilation**: No longer requires large Docker images for Linux targets

Migration steps:
1. Update `napi` and `napi-derive` to v3
2. Update `package.json` napi configuration to explicitly list targets
3. Replace deprecated `ThreadsafeFunction` usage with new API
4. Add `Reference` API for struct lifetime management
5. Add `wasm32-wasip1-threads` to target list

### Platform Target Matrix (7 native + 1 WASM)

| # | Host | Target | npm Package | Method |
|---|------|--------|-------------|--------|
| 1 | macOS | `x86_64-apple-darwin` | `@drift/native-darwin-x64` | Native |
| 2 | macOS | `aarch64-apple-darwin` | `@drift/native-darwin-arm64` | Native |
| 3 | Windows | `x86_64-pc-windows-msvc` | `@drift/native-win32-x64-msvc` | Native |
| 4 | Linux | `x86_64-unknown-linux-gnu` | `@drift/native-linux-x64-gnu` | NAPI-cross |
| 5 | Linux | `aarch64-unknown-linux-gnu` | `@drift/native-linux-arm64-gnu` | NAPI-cross |
| 6 | Linux | `x86_64-unknown-linux-musl` | `@drift/native-linux-x64-musl` | zigbuild |
| 7 | Linux | `aarch64-unknown-linux-musl` | `@drift/native-linux-arm64-musl` | zigbuild |
| 8 | Any | `wasm32-wasip1-threads` | `@drift/native-wasm32` | NAPI-RS v3 |

**New in v2**: Targets 6, 7 (musl via zigbuild) and 8 (WASM via NAPI-RS v3).
musl targets enable Alpine Linux support (smaller Docker images, common in enterprise K8s).

### cargo-zigbuild (R7 — P0)

Replaces Docker-based Rust compilation with host-side cross-compilation.
Bundles a complete C toolchain targeting musl libc. No Docker, no QEMU emulation.

Drift's Rust dependencies (`rusqlite` bundled SQLite, `tree-sitter` compiled from source)
are fully compatible with zigbuild.

```yaml
- name: Install cargo-zigbuild
  run: pip install cargo-zigbuild
- name: Build musl targets
  run: |
    cargo zigbuild --target x86_64-unknown-linux-musl --release
    cargo zigbuild --target aarch64-unknown-linux-musl --release
```

### Pre-Built Binary Distribution (R21)

```
@drift/native                    # Main package (detects platform, installs correct binary)
@drift/native-darwin-x64         # macOS Intel
@drift/native-darwin-arm64       # macOS Apple Silicon
@drift/native-win32-x64-msvc     # Windows x64
@drift/native-linux-x64-gnu      # Linux x64 (glibc)
@drift/native-linux-arm64-gnu    # Linux ARM64 (glibc)
@drift/native-linux-x64-musl     # Linux x64 (musl/Alpine) — NEW
@drift/native-linux-arm64-musl   # Linux ARM64 (musl/Alpine) — NEW
@drift/native-wasm32             # WebAssembly fallback — NEW
```

**Fallback chain**: Native binary → WASM (if available) → TypeScript-only mode (degraded).

### Cross-Compilation CI Workflow

```yaml
name: Native Build
on:
  push:
    branches: [main]
    paths: ['crates/**']
  pull_request:
    paths: ['crates/**']
  workflow_dispatch:
    inputs:
      publish_version:
        description: 'Version to publish'

jobs:
  build:
    strategy:
      matrix:
        include:
          - os: macos-latest
            target: x86_64-apple-darwin
            npm_dir: darwin-x64
          - os: macos-latest
            target: aarch64-apple-darwin
            npm_dir: darwin-arm64
          - os: windows-latest
            target: x86_64-pc-windows-msvc
            npm_dir: win32-x64-msvc
          - os: ubuntu-latest
            target: x86_64-unknown-linux-gnu
            npm_dir: linux-x64-gnu
            use_cross: true
          - os: ubuntu-latest
            target: aarch64-unknown-linux-gnu
            npm_dir: linux-arm64-gnu
            use_cross: true
          - os: ubuntu-latest
            target: x86_64-unknown-linux-musl
            npm_dir: linux-x64-musl
            use_zigbuild: true
          - os: ubuntu-latest
            target: aarch64-unknown-linux-musl
            npm_dir: linux-arm64-musl
            use_zigbuild: true
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          targets: ${{ matrix.target }}
      - name: Build (zigbuild)
        if: matrix.use_zigbuild
        run: |
          pip install cargo-zigbuild
          cargo zigbuild --target ${{ matrix.target }} --release -p drift-napi
      - name: Build (napi-cross)
        if: matrix.use_cross
        run: npx napi build --release --target ${{ matrix.target }}
      - name: Build (native)
        if: "!matrix.use_zigbuild && !matrix.use_cross"
        run: npx napi build --release --target ${{ matrix.target }}
      - uses: actions/upload-artifact@v4
        with:
          name: bindings-${{ matrix.npm_dir }}
          path: crates/drift-napi/*.node

  test:
    needs: build
    strategy:
      matrix:
        include:
          - os: macos-latest
            npm_dir: darwin-arm64
          - os: ubuntu-latest
            npm_dir: linux-x64-gnu
          - os: windows-latest
            npm_dir: win32-x64-msvc
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/download-artifact@v4
      - name: Verify bindings
        run: node -e "const n = require('./drift-napi'); console.log(n.version())"
```

---

## 10. Docker Deployment

### Decision: Multi-arch Alpine with pre-built binaries (R8)
### Source: R8, docker.md

### v1 Docker Issues

v1 Docker uses `node:20-slim`, compiles Rust inside Docker (slow), single-arch only,
no init process, no provenance.

### v2 Dockerfile

```dockerfile
FROM node:20-alpine AS base
RUN apk add --no-cache tini
RUN adduser -D -u 1001 drift

FROM base AS production
WORKDIR /app

# Copy package files for layer caching
COPY --chown=drift:drift package.json pnpm-lock.yaml ./
COPY --chown=drift:drift packages/ ./packages/
COPY --chown=drift:drift crates/drift-napi/npm/ ./crates/drift-napi/npm/

# Install production dependencies only
RUN corepack enable pnpm && pnpm install --prod --frozen-lockfile

# Configuration
ENV PORT=3000
ENV PROJECT_ROOT=/workspace
ENV ENABLE_CACHE=true
ENV NODE_ENV=production

# Security
USER drift
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget -qO- http://localhost:3000/health || exit 1

# Init process (proper signal handling, zombie reaping)
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "packages/mcp/dist/server.js"]
```

### Key Differences from v1

| Aspect | v1 | v2 |
|--------|----|----|
| Base image | `node:20-slim` (~200MB) | `node:20-alpine` (~40MB) |
| Rust compilation | Inside Docker (slow) | Pre-built binaries (fast) |
| Architecture | Single (amd64 only) | Multi-arch (amd64 + arm64) |
| Init process | None | `tini` (proper signal handling) |
| Provenance | None | SLSA attestation |
| SBOM | None | CycloneDX embedded |
| User | root | Non-root `drift` (uid 1001) |

### Multi-Arch Build

```yaml
- name: Build and push multi-arch
  uses: docker/build-push-action@v6
  with:
    platforms: linux/amd64,linux/arm64
    push: true
    provenance: true
    sbom: true
    tags: |
      ghcr.io/dadbodgeoff/drift:latest
      ghcr.io/dadbodgeoff/drift:${{ github.sha }}
```

### docker-compose.yml

```yaml
services:
  drift-mcp:
    image: ghcr.io/dadbodgeoff/drift:latest
    ports:
      - "${DRIFT_PORT:-3000}:3000"
    volumes:
      - "${PROJECT_PATH:-.}:/workspace:ro"
      - drift-cache:/workspace/.drift
    environment:
      - PORT=3000
      - PROJECT_ROOT=/workspace
      - NODE_OPTIONS=--max-old-space-size=4096
    deploy:
      resources:
        limits:
          memory: 4G
        reservations:
          memory: 1G

volumes:
  drift-cache:
```

Per D3: need to containerize both MCP servers independently. The drift-analysis server
runs standalone. The drift-memory server only starts when Cortex is detected.

---

## 11. Release Orchestration

### Decision: Changesets (R9) + release-plz (R10) + coordinated pipeline (R11)
### Source: R9, R10, R11, scripts.md

### Changesets for npm (R9)

Used by Turborepo, Radix, Chakra UI. Handles npm monorepo versioning with changelogs.

```yaml
- name: Create Release PR or Publish
  uses: changesets/action@v1
  with:
    publish: pnpm changeset publish
    version: pnpm changeset version
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
```

Internal dependency updates: when `drift-core` bumps, Changesets automatically bumps
all dependent packages.

### release-plz for Cargo (R10)

Rust-native equivalent of Changesets. Automated crate releases with changelogs.

```yaml
- name: Run release-plz
  uses: MarcoIeni/release-plz-action@v0.5
  with:
    command: release-pr
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}
```

### Coordinated Release Pipeline (R11)

Release order (dependencies flow left to right):

```
1. Rust crates (cargo):  drift-core → drift-analysis → drift-storage → drift-napi
2. Native binaries:      Build for 8 platforms → upload artifacts
3. npm packages:         @drift/native → core → detectors → cortex → mcp → cli
4. Docker image:         Build with pre-built binaries → push multi-arch
5. GitHub Release:       Create release with SBOMs, changelogs, binaries
```

**Trigger**: Manual dispatch with version bump type (patch/minor/major).
Automated for patch releases via Changesets + release-plz PRs.

**Rollback**: If any step fails, the workflow stops. npm packages can be unpublished
within 72 hours. Cargo crates can only be yanked — so cargo publishes first.

### Version Coordination

Shared `VERSION` file in workspace root as single source of truth.
Individual crate/package versions can diverge for independent releases.

### v1 publish.sh Replacement

v1's `scripts/publish.sh` is a manual bash script that publishes in dependency order.
v2 replaces this with the automated Changesets + release-plz pipeline.
The manual script is kept as `scripts/publish-emergency.sh` for break-glass scenarios.

---

## 12. Licensing & Feature Gating

### Decision: 3 tiers, 16 gated features, move JWT validation to Rust
### Source: licensing.md, R17

### Tier Structure (Preserved from v1)

| Tier | Level | What's Included |
|------|-------|-----------------|
| Community | 0 | All scanning, detection, analysis, CI, MCP, VSCode — everything core |
| Team | 1 | + policy engine, regression detection, custom rules, trends, exports |
| Enterprise | 2 | + multi-repo governance, team analytics, audit trails, impact simulation, security boundaries, integrations, self-hosted models, custom detectors, REST API |

### 16 Gated Features (Preserved from v1)

```rust
/// Team tier (level 1)
pub const GATE_POLICY_ENGINE: &str = "gate:policy-engine";
pub const GATE_REGRESSION_DETECTION: &str = "gate:regression-detection";
pub const GATE_CUSTOM_RULES: &str = "gate:custom-rules";
pub const DASHBOARD_TRENDS: &str = "dashboard:trends";
pub const DASHBOARD_EXPORT: &str = "dashboard:export";

/// Enterprise tier (level 2)
pub const GATE_IMPACT_SIMULATION: &str = "gate:impact-simulation";
pub const GATE_SECURITY_BOUNDARY: &str = "gate:security-boundary";
pub const GOVERNANCE_MULTI_REPO: &str = "governance:multi-repo";
pub const GOVERNANCE_TEAM_ANALYTICS: &str = "governance:team-analytics";
pub const GOVERNANCE_AUDIT_TRAIL: &str = "governance:audit-trail";
pub const INTEGRATION_WEBHOOKS: &str = "integration:webhooks";
pub const INTEGRATION_JIRA: &str = "integration:jira";
pub const INTEGRATION_SLACK: &str = "integration:slack";
pub const ADVANCED_SELF_HOSTED_MODELS: &str = "advanced:self-hosted-models";
pub const ADVANCED_CUSTOM_DETECTORS: &str = "advanced:custom-detectors";
pub const ADVANCED_API_ACCESS: &str = "advanced:api-access";
pub const DASHBOARD_TEAM_VIEW: &str = "dashboard:team-view";
```

### License Sources (Priority Order — Preserved from v1)

1. `DRIFT_LICENSE_KEY` environment variable
2. `.drift/license.key` file
3. `drift.toml` `licensing.key` field (was `.drift/config.json` in v1)
4. No license = community tier (always valid)

### v2 Enhancement: Rust-Side JWT Validation

v1 validates licenses entirely in TypeScript. v2 moves validation to Rust for tamper resistance.

```rust
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};

#[derive(Debug, Deserialize)]
pub struct LicenseClaims {
    pub tier: LicenseTier,
    pub org: String,
    pub seats: u32,
    pub features: Vec<String>,
    pub iat: u64,
    pub exp: u64,
    pub iss: String,
    pub ver: u32,
}

#[derive(Debug, Deserialize, PartialEq, PartialOrd)]
#[serde(rename_all = "lowercase")]
pub enum LicenseTier {
    Community = 0,
    Team = 1,
    Enterprise = 2,
}

pub fn validate_license(key: &str) -> Result<LicenseClaims, LicenseError> {
    // Try JWT first
    if let Ok(claims) = validate_jwt(key) {
        return Ok(claims);
    }
    // Fall back to simple key (prefix-based)
    validate_simple_key(key)
}

fn validate_jwt(token: &str) -> Result<LicenseClaims, LicenseError> {
    let decoding_key = DecodingKey::from_secret(PUBLIC_KEY);
    let validation = Validation::new(Algorithm::HS256);
    let token_data = decode::<LicenseClaims>(token, &decoding_key, &validation)
        .map_err(|e| LicenseError::InvalidToken(e.to_string()))?;

    // Check expiration with 30-day warning
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    if token_data.claims.exp < now {
        return Err(LicenseError::Expired);
    }

    Ok(token_data.claims)
}
```

### Feature Guard Patterns (Preserved from v1, Adapted for Rust)

```rust
/// Check if a feature is available at the current license tier
pub fn check_feature(license: &LicenseClaims, feature: &str) -> bool {
    license.features.contains(&feature.to_string())
}

/// Guard a function — returns GatedResult
pub fn guard_feature<T, F: FnOnce() -> T>(
    license: &LicenseClaims,
    feature: &str,
    f: F,
) -> Result<T, LicenseError> {
    if check_feature(license, feature) {
        Ok(f())
    } else {
        Err(LicenseError::FeatureNotLicensed {
            feature: feature.to_string(),
            current_tier: license.tier,
            required_tier: required_tier_for(feature),
            upgrade_url: "https://driftscan.dev/pricing".to_string(),
        })
    }
}
```

### Enterprise License Server (R17 — P2)

Optional server-side validation for enterprise:
- **Local validation** (default): JWT signature verification, expiry check, feature extraction — works offline
- **Server validation** (enterprise): Periodic check-in for seat counting, revocation, usage analytics
- **Grace period**: 7-day grace period if server unreachable
- **Infrastructure**: Cloudflare Worker (same as telemetry). 99.99% SLA.

---

## 13. Telemetry

### Decision: Cloudflare Worker + D1, expand with Rust events (R16)
### Source: R16, telemetry.md

### Existing Infrastructure (Preserved from v1)

The telemetry worker is independent of Drift core — no changes needed for v2 architecture.

- **Runtime**: Cloudflare Worker (TypeScript)
- **Storage**: D1 (SQLite)
- **Endpoints**: `POST /v1/events`, `GET /v1/health`, `GET /v1/stats`
- **Privacy**: Anonymous UUIDs, no source code, opt-in, disabled by default
- **Retention**: Raw events 90 days, aggregates indefinite
- **Cost**: Free tier covers ~1000 active users × 50 events/day

### Database Schema (Preserved)

4 tables: `events` (raw telemetry), `daily_stats` (aggregated metrics),
`pattern_signatures` (deduplicated for ML), `action_aggregates` (user action stats).

### v2 New Events (R16)

Expand telemetry to include Rust-side events:

| Event | Source | Data |
|-------|--------|------|
| `rust.scan.completed` | Scanner | Duration, file count, language distribution |
| `rust.parse.error` | Parser | Parser failures by language |
| `rust.analysis.completed` | Analysis | Call graph size, coupling metrics, boundary count |
| `napi.bridge.latency` | NAPI | Time spent crossing Rust-to-Node.js boundary |
| `rust.detection.completed` | Detectors | Pattern count, violation count, detector timings |
| `rust.gate.evaluated` | Quality Gates | Gate name, pass/fail, score |

### Telemetry Client (Rust Side)

```rust
pub struct TelemetryClient {
    endpoint: String,
    installation_id: String,
    drift_version: String,
    enabled: bool,
    buffer: Mutex<Vec<TelemetryEvent>>,
}

impl TelemetryClient {
    pub fn track(&self, event_type: &str, payload: serde_json::Value) {
        if !self.enabled { return; }
        let event = TelemetryEvent {
            event_type: event_type.to_string(),
            timestamp: Utc::now().to_rfc3339(),
            installation_id: self.installation_id.clone(),
            drift_version: self.drift_version.clone(),
            payload,
        };
        self.buffer.lock().unwrap().push(event);
    }

    pub fn flush(&self) {
        // Batch send buffered events to Cloudflare Worker
        // Max 100 events per batch
    }
}
```

### Privacy Controls

- `drift config set telemetry true` — opt in
- `drift config set telemetry false` — opt out (default)
- `DRIFT_TELEMETRY=false` — env var override
- All events anonymous, no PII, no source code

---

## 14. CI Agent

### Decision: Stays TypeScript, Rust-first analysis via NAPI (R18)
### Source: R18, ci-agent.md

### Architecture (Preserved from v1)

The CI agent (`packages/ci/`, published as `driftdetect-ci`) is an orchestration layer
that stays TypeScript. It calls Rust core for analysis via NAPI.

```
drift-ci CLI → PRAnalyzer → 9 analysis passes (via NAPI to Rust) → Reporters
```

### 9 Analysis Passes (Preserved)

| # | Pass | Weight | v2 Change |
|---|------|--------|-----------|
| 1 | Pattern matching | 30% | Rust-first via NAPI |
| 2 | Constraint verification | 25% | Rust-first via NAPI |
| 3 | Impact analysis | — | Rust call graph via NAPI |
| 4 | Security boundary scan | 20% | Rust boundary detection via NAPI |
| 5 | Test coverage analysis | 15% | Rust test topology via NAPI |
| 6 | Module coupling analysis | 10% | Rust coupling analysis via NAPI |
| 7 | Error handling analysis | — | Rust error handling via NAPI |
| 8 | Contract checking | — | Rust contract tracking via NAPI |
| 9 | Constants analysis | — | Rust constants detection via NAPI |

### 12 Pluggable Interfaces (Preserved)

`IPatternMatcher`, `IConstraintVerifier`, `IImpactAnalyzer`, `IBoundaryScanner`,
`ITestTopology`, `IModuleCoupling`, `IErrorHandling`, `IContractChecker`,
`IConstantsAnalyzer`, `IQualityGates`, `ITrendAnalyzer`, `ICortex`

### Scoring Algorithm (Preserved)

```
overallScore = patternScore × 0.30 + constraintScore × 0.25 +
               securityScore × 0.20 + testScore × 0.15 + couplingScore × 0.10
```

### v2 Enhancements (R18)

1. **Rust-first analysis**: CI agent calls Rust core directly via NAPI — no TS overhead for hot path
2. **SARIF output**: Generate SARIF 2.1.0 for GitHub Code Scanning integration
3. **Incremental analysis**: Only analyze changed files (git diff) — 10-100x faster for large repos
4. **Parallel file processing**: Rust's rayon handles parallelism, not TS worker threads

```yaml
- name: Run Drift analysis
  run: drift ci --format sarif --output drift-results.sarif
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: drift-results.sarif
```

### Heuristic Fallbacks (Preserved but Deprioritized)

v1 has 8 heuristic fallback functions for when Drift core isn't initialized.
These become less important as Rust core matures but are preserved for graceful degradation:
- `heuristicPatternMatch`, `heuristicConstraintVerify`, `heuristicImpactAnalysis`
- `heuristicBoundaryScan`, `heuristicTestCoverage`, `heuristicCouplingAnalysis`
- `heuristicErrorHandling`, `heuristicConstantsAnalysis`

### GitHub/GitLab Integration (Preserved)

- GitHub: Octokit — PR comments, check runs, inline review comments, commit status
- GitLab: MR comments
- SARIF: 2.1.0 output with severity mapping (critical/high → error, medium → warning, low → note)


---

## 15. AI Providers

### Decision: Stays TypeScript, 3 providers, expand with streaming + better context
### Source: ai-providers.md

### Architecture (Preserved from v1)

The AI provider package (`packages/ai/`, private `@drift/ai`) stays TypeScript.
It makes API calls to external services — no Rust benefit here.

### Provider Interface (Preserved)

```typescript
interface AIProvider {
    name: string;
    requiresApiKey: boolean;
    envKeyName: string;
    isConfigured(): boolean;
    explain(context: ExplainContext): Promise<ExplainResult>;
    generateFix(context: FixContext): Promise<FixResult>;
}
```

### 3 Providers (Preserved)

| Provider | Status | API Key Env |
|----------|--------|-------------|
| Anthropic (Claude) | Implemented | `ANTHROPIC_API_KEY` |
| OpenAI | Implemented | `OPENAI_API_KEY` |
| Ollama (local) | Implemented | None (local inference) |

### v2 Enhancements

1. **Streaming support**: Long explanations should stream for better UX
2. **Better context building**: Leverage Rust-parsed AST for more precise code snippets
3. **Token counting**: Use tiktoken or provider-specific tokenizers for accurate budgeting
4. **Additional providers** (future): Google Gemini, AWS Bedrock
5. **Context from drift.db**: AI context builder can query drift.db for pattern/violation
   context instead of re-analyzing

### Dependencies (Preserved)

- `driftdetect-core` (for types)
- Provider SDKs (Anthropic, OpenAI — via npm)

---

## 16. GitHub Action v2

### Decision: Update for split MCP + SARIF upload (R20)
### Source: R20, github-action.md

### v1 Action (Preserved Inputs/Outputs)

The composite GitHub Action (`actions/drift-action/`) installs `driftdetect-ci` and runs
PR analysis. v2 updates the internals while preserving backward compatibility.

### v2 Changes

1. Install `driftdetect` (CLI) instead of `driftdetect-ci` — CLI is primary entry point in v2
2. Support both `drift-analysis` and `drift-memory` server configurations
3. Add `drift gate --ci --format sarif` output for GitHub Code Scanning
4. Add artifact upload for SARIF results (enables GitHub Security tab)
5. Add caching for `.drift/` directory (scan results, pattern database)

### New Inputs (v2)

| Input | Default | Purpose |
|-------|---------|---------|
| `memory-enabled` | `false` | Include Cortex memory analysis |
| `sarif-upload` | `true` | Upload SARIF to GitHub Code Scanning |
| `fail-threshold` | `70` | Minimum drift score to pass |

### New Outputs (v2)

| Output | Description |
|--------|-------------|
| `sarif-file` | Path to generated SARIF file |
| `patterns-discovered` | Number of patterns found |
| `violations-count` | Number of violations |

### Preserved Inputs (from v1)

`github-token`, `fail-on-violation`, `post-comment`, `create-check`,
`pattern-check`, `impact-analysis`, `constraint-verification`, `security-boundaries`

### Preserved Outputs (from v1)

`status`, `summary`, `violations-count`, `drift-score`, `result-json`

### v2 Action Implementation

```yaml
# action.yml
name: 'Drift CI Analysis'
description: 'Run Drift pattern analysis on pull requests'
inputs:
  github-token:
    required: true
    default: ${{ github.token }}
  fail-on-violation:
    required: false
    default: 'false'
  sarif-upload:
    required: false
    default: 'true'
  fail-threshold:
    required: false
    default: '70'
  memory-enabled:
    required: false
    default: 'false'

runs:
  using: 'composite'
  steps:
    - uses: actions/setup-node@v4
      with:
        node-version: '20'
    - name: Install Drift
      run: npm install -g driftdetect@latest
      shell: bash
    - name: Cache .drift directory
      uses: actions/cache@v4
      with:
        path: .drift
        key: drift-${{ hashFiles('**/*.ts', '**/*.js', '**/*.py') }}
    - name: Run analysis
      run: drift ci --format sarif --output drift-results.sarif --threshold ${{ inputs.fail-threshold }}
      shell: bash
      env:
        GITHUB_TOKEN: ${{ inputs.github-token }}
    - name: Upload SARIF
      if: inputs.sarif-upload == 'true'
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: drift-results.sarif
```

---

## 17. CIBench (Codebase Intelligence Benchmark)

### Decision: Keep and extend (R19)
### Source: R19, cibench.md

### Architecture (Preserved from v1)

CIBench (`packages/cibench/`) is a novel 4-level benchmark framework. Stays TypeScript.

### 4-Level Scoring (Preserved)

```
CIBench Score = Σ(level_score × level_weight)

Level 1 (Perception):     30%  — Pattern recognition, call graph, data flow
Level 2 (Understanding):  35%  — Architectural intent, causal reasoning, uncertainty
Level 3 (Application):    25%  — Token efficiency, compositional reasoning, negative knowledge
Level 4 (Validation):     10%  — Human correlation
```

### Novel Features (Preserved)

- **Counterfactual evaluation**: "What would happen if we removed this function?"
- **Calibration measurement**: ECE/MCE for confidence calibration
- **Generative probes**: Open-ended questions scored against expected concepts
- **Adversarial robustness**: Misleading names, dead code, outdated comments
- **Negative knowledge**: Tests whether tools know what NOT to do

### v2 Enhancements (R19)

1. **CI integration**: Automated benchmark runs in CI pipeline
2. **Rust analysis benchmarks**: Parsing speed, call graph accuracy, detection throughput
3. **Extended corpus**: More languages (Python, Java, Go)
4. **Trend tracking**: Store results as CI artifacts, dashboard via GitHub Pages

```yaml
- name: Run CIBench suite
  run: drift bench --suite full --output cibench-results.json
- name: Upload results
  uses: actions/upload-artifact@v4
  with:
    name: cibench-${{ github.sha }}
    path: cibench-results.json
```

### Benchmark Protocol (Preserved)

8 tasks, scored 0-2 each (16 points max). Run WITH Drift vs WITHOUT Drift (baseline).
Expected: Drift 16/16, Baseline 8-11/16.
Key differentiator: Task 3 (missing auth) — grep can't find code that doesn't exist.

---

## 18. Galaxy Visualization

### Decision: Stays TypeScript/React, lowest priority
### Source: galaxy.md

### Architecture (Preserved from v1)

Galaxy (`packages/galaxy/`, published as `driftdetect-galaxy`) is a 3D visualization library.
Pure presentation — no analysis logic.

### Tech Stack (Preserved)

- React 18, Three.js 0.160, react-three-fiber 8
- @react-three/drei (helpers), @react-three/postprocessing (bloom)
- Zustand 4 (state management), jsfxr (procedural sound)

### v2 Changes

1. **Data source update**: Match v2 Rust output format (types from drift-napi)
2. **Performance**: Consider WebGPU path for large schemas (1000+ tables)
3. **Layout engine**: Could be optimized with WASM if needed (future)

No structural changes. Galaxy consumes data — it doesn't produce it.

---

## 19. Developer Experience

### Decision: Justfile + pre-commit hooks + VS Code settings (R22)
### Source: R22

### drift setup-dev Command

```bash
# Verify prerequisites
node --version    # >= 18.0.0
pnpm --version    # >= 8.0.0
rustc --version   # stable

# Install workspace dependencies
pnpm install

# Build Rust crates
cargo build --workspace

# Run initial scan (dogfooding)
drift scan .

# Verify NAPI bridge
node -e "const n = require('@drift/native'); console.log(n.version())"
```

### Pre-Commit Hooks (husky + lint-staged)

```json
{
    "*.rs": ["cargo fmt --check"],
    "*.ts": ["eslint --fix", "prettier --write"],
    "*.md": ["prettier --write"]
}
```

### VS Code Workspace Settings

```json
{
    "rust-analyzer.check.command": "clippy",
    "rust-analyzer.check.allTargets": true,
    "rust-analyzer.cargo.allFeatures": true,
    "editor.formatOnSave": true,
    "[rust]": { "editor.defaultFormatter": "rust-lang.rust-analyzer" },
    "[typescript]": { "editor.defaultFormatter": "esbenp.prettier-vscode" },
    "[json]": { "editor.defaultFormatter": "esbenp.prettier-vscode" }
}
```

### Engine Requirements

- Node.js >= 18.0.0
- pnpm >= 8.0.0
- Rust stable (>= 1.75)

---

## 20. Workspace Management

### Decision: Rust-side workspace lifecycle management
### Source: Full System Audit (Cat 00), D6, Storage V2 Prep

### Workspace Operations

| Operation | What It Does |
|-----------|-------------|
| `drift init` | Create `.drift/` directory, initialize `drift.db`, create default `drift.toml` |
| `drift init --template <name>` | Initialize with a preset configuration template |
| `drift switch <project>` | Switch active workspace (for multi-project setups) |
| `drift backup` | Create timestamped backup of `drift.db` |
| `drift backup --restore <file>` | Restore from backup |
| `drift migrate` | Run pending schema migrations on `drift.db` |
| `drift clean` | Remove cached data, keep configuration |
| `drift clean --all` | Remove everything in `.drift/` except `drift.toml` |

### .drift/ Directory Structure

```
.drift/
├── drift.db           # Main database (SQLite, WAL mode)
├── drift.db-wal       # WAL file (auto-managed)
├── drift.db-shm       # Shared memory (auto-managed)
├── drift.toml         # Project configuration (user-editable)
├── license.key        # License key (optional)
├── backups/           # Database backups
│   ├── operational/   # Last 5 operational backups
│   └── daily/         # Last 7 daily backups
└── cache/             # Transient cache (safe to delete)
    └── parse_cache/   # Moka-backed parse cache overflow
```

### Schema Migration System

```rust
pub struct Migration {
    pub version: u32,
    pub name: &'static str,
    pub up: &'static str,
    pub down: Option<&'static str>,
}

pub const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "initial_schema",
        up: include_str!("../migrations/001_initial.sql"),
        down: Some(include_str!("../migrations/001_initial_down.sql")),
    },
    // ... additional migrations
];

pub fn run_migrations(conn: &Connection) -> Result<u32, StorageError> {
    let current = get_current_version(conn)?;
    for migration in MIGRATIONS.iter().filter(|m| m.version > current) {
        conn.execute_batch(migration.up)?;
        set_version(conn, migration.version)?;
        tracing::info!(version = migration.version, name = migration.name, "migration applied");
    }
    Ok(MIGRATIONS.last().map(|m| m.version).unwrap_or(0))
}
```

### Backup Strategy

- **Operational backups**: Before destructive operations (migrate, clean). Keep last 5.
- **Daily backups**: Automatic on first scan of the day. Keep last 7.
- **Format**: Compressed SQLite backup via `VACUUM INTO`.

### Per D6: drift.db is Standalone

Every query works without cortex.db. ATTACH cortex.db is a read-only overlay managed
by the bridge crate at the workspace level, not by Drift's workspace management.

---

## 21. v1 Feature Verification — Complete Gap Analysis

Cross-referenced against all v1 infrastructure documentation:
- `.github/workflows/` (ci.yml, native-build.yml, release.yml)
- `packages/core/src/licensing/` (license-manager.ts, license-validator.ts, feature-guard.ts)
- `packages/ci/` (PRAnalyzer, providers, reporters, adapters)
- `packages/ai/` (providers, context, prompts, confirmation)
- `packages/galaxy/` (3D visualization)
- `packages/cibench/` (benchmark framework)
- `infrastructure/telemetry-worker/` (Cloudflare Worker)
- `actions/drift-action/` (GitHub Action)
- `scripts/` (publish, validate-docs, generate-large-codebase)
- `Dockerfile`, `docker-compose.yml`
- `crates/drift-core/`, `crates/drift-napi/`
- All 14 research docs in `12-infrastructure/`
- `.research/12-infrastructure/RECOMMENDATIONS.md` (25 recommendations)

### Build System Features

| v1 Feature | v2 Status | v2 Location |
|------------|-----------|-------------|
| pnpm 8 workspace (12 packages) | **KEPT** — consolidated to ~9 packages | §7 Build System |
| Turborepo pipeline (build, test, lint, typecheck) | **KEPT** — same pipeline config | §7 Build System |
| TypeScript strict mode (all flags) | **KEPT** — identical config | §7 Build System |
| ESLint flat config | **KEPT** — same rules | §7 Build System |
| Vitest (threads, v8 coverage, 80% thresholds) | **KEPT** — identical config | §7 Build System |
| Prettier (100 width, single quotes, trailing commas) | **KEPT** — identical config | §7 Build System |
| Path aliases (@drift/<name>) | **KEPT** — updated for consolidated packages | §7 Build System |
| Cargo workspace (2 crates) | **UPGRADED** — expanded to 5 crates + feature flags (FA3) | §7 Build System |
| Release profile (lto, codegen-units=1, opt-level=3) | **UPGRADED** — added strip="symbols" | §7 Build System |

### CI/CD Features

| v1 Feature | v2 Status | v2 Location |
|------------|-----------|-------------|
| ci.yml (build + test, Node 18/20/22 matrix) | **UPGRADED** — removed continue-on-error, all checks blocking | §8 CI/CD |
| ci.yml lint step | **FIXED** — was disabled in v1, now blocking | §8 CI/CD |
| native-build.yml (5 platform targets) | **UPGRADED** — 8 targets (+ musl + WASM) | §9 Cross-Compilation |
| native-build.yml test matrix | **KEPT** — 3 platform test matrix | §9 Cross-Compilation |
| native-build.yml publish job | **UPGRADED** — automated via release-plz | §11 Release |
| release.yml (manual dispatch, npm publish) | **UPGRADED** — coordinated cross-registry pipeline | §11 Release |
| drift-check.yml.template (user template) | **UPGRADED** — SARIF output, .drift caching | §16 GitHub Action |
| No Rust CI | **ADDED** — clippy + fmt + nextest as blocking gates (FA1) | §8 CI/CD |
| No dependency scanning | **ADDED** — cargo-deny + cargo-audit + pnpm audit (FA2, R1) | §8 CI/CD |
| No SBOM generation | **ADDED** — CycloneDX for Rust + npm (R2) | §8 CI/CD |
| No provenance attestation | **ADDED** — SLSA Level 3 via GitHub attestation (R3) | §8 CI/CD |
| No performance regression CI | **ADDED** — criterion-compare + statistical gating (R13) | §8 CI/CD |
| No E2E integration tests | **ADDED** — full pipeline test suite (R14) | §8 CI/CD |
| No automated dependency updates | **ADDED** — Dependabot for cargo + npm + actions | §8 CI/CD |

### Cross-Compilation & Docker Features

| v1 Feature | v2 Status | v2 Location |
|------------|-----------|-------------|
| 5 native platform targets | **UPGRADED** — 7 native + 1 WASM (8 total) | §9 Cross-Compilation |
| macOS x64 + arm64 | **KEPT** | §9 |
| Windows x64 | **KEPT** | §9 |
| Linux x64-gnu + arm64-gnu | **KEPT** | §9 |
| No Linux musl targets | **ADDED** — x64-musl + arm64-musl via zigbuild (R7) | §9 |
| No WASM target | **ADDED** — wasm32-wasip1-threads via NAPI-RS v3 (R4) | §9 |
| NAPI-RS v2 | **UPGRADED** — NAPI-RS v3 (R4) | §9 |
| Docker node:20-slim (~200MB) | **UPGRADED** — Alpine (~40MB), multi-arch (R8) | §10 Docker |
| Docker compiles Rust inside | **UPGRADED** — pre-built binaries (5-10x faster) | §10 Docker |
| Docker single-arch (amd64) | **UPGRADED** — multi-arch (amd64 + arm64) | §10 Docker |
| Docker no init process | **ADDED** — tini for signal handling | §10 Docker |
| Docker runs as root | **FIXED** — non-root user drift (uid 1001) | §10 Docker |
| Docker no provenance | **ADDED** — SLSA attestation + SBOM | §10 Docker |

### Release Features

| v1 Feature | v2 Status | v2 Location |
|------------|-----------|-------------|
| scripts/publish.sh (manual, dependency-ordered) | **UPGRADED** — automated Changesets + release-plz (R9, R10) | §11 Release |
| npm publish with --access public | **KEPT** — with --provenance added | §11 Release |
| No cargo publish | **ADDED** — release-plz for Cargo workspace (R10) | §11 Release |
| No cross-registry coordination | **ADDED** — orchestrated pipeline (R11) | §11 Release |
| No changelogs | **ADDED** — auto-generated by Changesets + release-plz | §11 Release |

### Licensing Features

| v1 Feature | v2 Status | v2 Location |
|------------|-----------|-------------|
| 3 license tiers (Community/Team/Enterprise) | **KEPT** — identical tier structure | §12 Licensing |
| 16 gated features | **KEPT** — all 16 features preserved | §12 Licensing |
| JWT license validation | **UPGRADED** — moved to Rust for tamper resistance | §12 Licensing |
| Simple key validation (prefix-based) | **KEPT** — fallback for simple keys | §12 Licensing |
| License sources (env, file, config) | **KEPT** — same priority order | §12 Licensing |
| LicenseManager singleton | **KEPT** — Rust equivalent | §12 Licensing |
| Feature guard patterns (7 patterns) | **KEPT** — adapted for Rust | §12 Licensing |
| 30-day expiration warning | **KEPT** | §12 Licensing |
| Upgrade URL | **KEPT** — made configurable via drift.toml | §12 Licensing |
| No license server | **ADDED** — optional server-side validation for enterprise (R17) | §12 Licensing |

### Telemetry Features

| v1 Feature | v2 Status | v2 Location |
|------------|-----------|-------------|
| Cloudflare Worker runtime | **KEPT** — independent, no changes | §13 Telemetry |
| D1 database (4 tables) | **KEPT** — schema preserved | §13 Telemetry |
| POST /v1/events (max 100/batch) | **KEPT** | §13 Telemetry |
| GET /v1/health, GET /v1/stats | **KEPT** | §13 Telemetry |
| Anonymous UUIDs, opt-in, 90-day retention | **KEPT** | §13 Telemetry |
| Pattern signature collection for ML | **KEPT** | §13 Telemetry |
| No Rust-side events | **ADDED** — 6 new Rust event types (R16) | §13 Telemetry |

### CI Agent Features

| v1 Feature | v2 Status | v2 Location |
|------------|-----------|-------------|
| PRAnalyzer (9 analysis passes) | **KEPT** — all 9 passes preserved | §14 CI Agent |
| 12 pluggable interfaces | **KEPT** — all 12 interfaces preserved | §14 CI Agent |
| Scoring algorithm (5 weighted components) | **KEPT** — identical weights | §14 CI Agent |
| GitHub provider (Octokit) | **KEPT** | §14 CI Agent |
| GitLab provider | **KEPT** | §14 CI Agent |
| SARIF 2.1.0 reporter | **KEPT** — enhanced with SARIF upload | §14 CI Agent |
| GitHub comment reporter | **KEPT** | §14 CI Agent |
| 8 heuristic fallbacks | **KEPT** — deprioritized as Rust matures | §14 CI Agent |
| TS-only analysis | **UPGRADED** — Rust-first via NAPI (R18) | §14 CI Agent |
| No incremental analysis | **ADDED** — git diff-based incremental (R18) | §14 CI Agent |
| No SARIF upload to GitHub Security | **ADDED** — codeql-action/upload-sarif (R18) | §14 CI Agent |

### AI Provider Features

| v1 Feature | v2 Status | v2 Location |
|------------|-----------|-------------|
| AIProvider interface (explain, generateFix) | **KEPT** | §15 AI Providers |
| Anthropic provider | **KEPT** | §15 |
| OpenAI provider | **KEPT** | §15 |
| Ollama provider (local) | **KEPT** | §15 |
| Context building (code extractor, sanitizer) | **KEPT** — enhanced with Rust AST | §15 |
| Prompt templates (explain, fix) | **KEPT** | §15 |
| Confirmation flow (consent, preview) | **KEPT** | §15 |

### GitHub Action Features

| v1 Feature | v2 Status | v2 Location |
|------------|-----------|-------------|
| Composite action (action.yml) | **KEPT** — updated internals | §16 GitHub Action |
| 8 inputs (github-token, fail-on-violation, etc.) | **KEPT** — all preserved | §16 |
| 5 outputs (status, summary, violations-count, etc.) | **KEPT** — all preserved | §16 |
| Installs driftdetect-ci | **UPGRADED** — installs driftdetect (CLI) | §16 |
| No SARIF upload | **ADDED** — SARIF upload to GitHub Code Scanning | §16 |
| No .drift caching | **ADDED** — actions/cache for .drift directory | §16 |

### CIBench Features

| v1 Feature | v2 Status | v2 Location |
|------------|-----------|-------------|
| 4-level scoring (Perception/Understanding/Application/Validation) | **KEPT** | §17 CIBench |
| Counterfactual evaluation | **KEPT** | §17 |
| Calibration measurement (ECE/MCE) | **KEPT** | §17 |
| Generative probes | **KEPT** | §17 |
| Adversarial robustness | **KEPT** | §17 |
| Negative knowledge | **KEPT** | §17 |
| 3 test corpora | **KEPT** — extended with more languages | §17 |
| 8-task benchmark protocol | **KEPT** | §17 |
| No CI integration | **ADDED** — automated benchmark runs (R19) | §17 |

### Galaxy Features

| v1 Feature | v2 Status | v2 Location |
|------------|-----------|-------------|
| 3D visualization (Three.js + react-three-fiber) | **KEPT** | §18 Galaxy |
| TablePlanet, FieldMoon, EntryPointStation nodes | **KEPT** | §18 |
| DataPathLane, TableRelationship connections | **KEPT** | §18 |
| Zustand state management | **KEPT** | §18 |
| Force-directed layout engine | **KEPT** | §18 |
| Procedural sound effects (jsfxr) | **KEPT** | §18 |

### Scripts & Automation Features

| v1 Feature | v2 Status | v2 Location |
|------------|-----------|-------------|
| publish.sh (dependency-ordered npm publish) | **UPGRADED** — automated pipeline, kept as emergency script | §11 Release |
| validate-docs.sh (CLI command validation) | **KEPT** — updated for v2 CLI commands | §19 Developer Experience |
| generate-large-codebase.ts (synthetic test data) | **KEPT** — extended for E2E tests (R14) | §8 CI/CD |
| transform-detector.ts | **DROPPED** — v2 detectors are Rust-native, no TS transform needed | N/A |

### Error Handling Features

| v1 Feature | v2 Status | v2 Location |
|------------|-----------|-------------|
| No structured error types in Rust | **ADDED** — thiserror per-subsystem enums (AD6) | §2 Error Handling |
| No NAPI error codes | **ADDED** — structured error code registry | §2 Error Handling |
| TS-side error handling only | **UPGRADED** — Rust-first with NAPI propagation | §2 Error Handling |

### Observability Features

| v1 Feature | v2 Status | v2 Location |
|------------|-----------|-------------|
| VERBOSE=true flag (minimal logging) | **UPGRADED** — tracing crate with per-subsystem spans (AD10) | §3 Observability |
| No structured logging | **ADDED** — structured key-value fields on every event | §3 Observability |
| No span-based timing | **ADDED** — hierarchical spans for performance measurement | §3 Observability |
| No configurable log levels | **ADDED** — DRIFT_LOG env var with EnvFilter | §3 Observability |
| No OpenTelemetry | **ADDED** — optional enterprise feature flag | §3 Observability |
| No TS structured logging | **ADDED** — pino for TS layer (R15) | §3 Observability |

### Configuration Features

| v1 Feature | v2 Status | v2 Location |
|------------|-----------|-------------|
| .drift/config.json | **UPGRADED** — drift.toml (TOML format) | §5 Configuration |
| .driftrc.json / .driftrc | **CONSOLIDATED** — single drift.toml | §5 Configuration |
| No layered config resolution | **ADDED** — CLI > env > project > user > defaults | §5 Configuration |
| No config validation | **ADDED** — validate_config() with typed errors | §5 Configuration |

### Data Structure Features

| v1 Feature | v2 Status | v2 Location |
|------------|-----------|-------------|
| Standard HashMap | **UPGRADED** — FxHashMap for all internal maps (AD12) | §6 Data Structures |
| Standard Vec for small collections | **UPGRADED** — SmallVec<[T;4]> where appropriate | §6 Data Structures |
| No string interning | **ADDED** — lasso (ThreadedRodeo/RodeoReader) for 60-80% memory reduction | §6 Data Structures |
| No ordered maps | **ADDED** — BTreeMap for deterministic iteration | §6 Data Structures |


---

## 22. Build Order

From RECOMMENDATIONS.md, 7 phases with duration estimates and dependencies.

### Phase 0 — Foundations (Before Code)

**Duration**: 1 week
**Recommendations**: FA1 (Rust CI) + FA2 (Supply chain) + FA3 (Workspace expansion)
**Deliverables**:
- CI pipeline (clippy + fmt + nextest as blocking gates)
- Cargo workspace structure (5 crates + feature flags)
- Clippy configuration (workspace lints)
- deny.toml (license + advisory + ban + source checks)
- nextest.toml (CI profile with retries + JUnit output)
- Dependabot configuration

**This phase also includes Level 0 Bedrock infrastructure**:
- `drift-core/src/errors/` — All subsystem error enums (thiserror)
- `drift-core/src/tracing.rs` — tracing init with EnvFilter
- `drift-core/src/events.rs` — DriftEventHandler trait with no-op defaults
- `drift-core/src/config/` — DriftConfig with TOML loading + layering
- `drift-core/src/data/` — FxHashMap re-exports, SmallVec type aliases, lasso interners

### Phase 1 — Supply Chain Security (Parallel with Phase 2)

**Duration**: 1 week
**Recommendations**: R1 (cargo-deny) + R2 (SBOM) + R3 (SLSA)
**Deliverables**:
- deny.toml fully configured
- SBOM generation (CycloneDX for Rust + npm)
- Provenance attestation (SLSA Level 3)

### Phase 2 — Build System (Parallel with Phase 1)

**Duration**: 2-3 weeks
**Recommendations**: R4 (NAPI-RS v3) + R5 (Turborepo cache) + R6 (sccache)
**Deliverables**:
- NAPI-RS v3 migration complete
- Turborepo remote caching enabled
- sccache configured for CI

### Phase 3 — Cross-Compilation & Docker

**Duration**: 2 weeks
**Dependencies**: R4 (NAPI-RS v3 for target list)
**Recommendations**: R7 (zigbuild) + R8 (Docker multi-arch)
**Deliverables**:
- 8-platform cross-compilation (7 native + WASM)
- Multi-arch Docker images (Alpine, pre-built binaries, tini)

### Phase 4 — Release Orchestration

**Duration**: 2 weeks
**Dependencies**: Phase 3 (binaries to publish)
**Recommendations**: R9 (Changesets) + R10 (release-plz) + R11 (cross-registry)
**Deliverables**:
- Automated npm releases via Changesets
- Automated cargo releases via release-plz
- Coordinated cross-registry release pipeline

### Phase 5 — Testing & Performance

**Duration**: 2-3 weeks
**Dependencies**: Phase 0 (CI pipeline), Phase 2 (build system)
**Recommendations**: R12 (nextest) + R13 (perf regression) + R14 (E2E tests)
**Deliverables**:
- nextest as default test runner
- Benchmark regression gating (criterion-compare)
- E2E integration test suite (4 scenarios)

### Phase 6 — Operational Infrastructure

**Duration**: 3-4 weeks
**Dependencies**: Phases 1-5
**Recommendations**: R15 (observability) + R16 (telemetry) + R17 (licensing) + R18 (CI agent) + R19 (CIBench)
**Deliverables**:
- Structured logging (tracing + pino)
- Telemetry expansion (6 Rust events)
- License server (Cloudflare Worker, enterprise)
- CI agent enhancement (Rust-first, SARIF, incremental)
- CIBench CI integration

### Phase 7 — Ecosystem & Distribution

**Duration**: 2-3 weeks
**Dependencies**: Phase 3 (binaries), Phase 4 (release pipeline)
**Recommendations**: R20 (GitHub Action) + R21 (pre-built binaries) + R22 (developer experience)
**Deliverables**:
- GitHub Action v2 (SARIF upload, .drift caching)
- Pre-built binary distribution (8 platform packages)
- Developer experience (Justfile, pre-commit hooks, VS Code settings, setup-dev)

### Dependency Graph

```
FA1 (Rust CI) ──────────> R1 (cargo-deny) ──> R2 (SBOM) ──> R3 (SLSA)
              ──────────> R12 (nextest)
              ──────────> R13 (Perf regression)

FA2 (Supply chain) ─────> R5 (Turborepo cache)
                    ────> R6 (sccache)

FA3 (Workspace) ────────> R4 (NAPI-RS v3) ──> R7 (zigbuild) ──> R8 (Docker)
                                                              ──> R21 (Binaries)

R12 (nextest) ──────────> R14 (E2E tests)
R13 (Perf regression) ──> R19 (CIBench CI)

R7 (zigbuild) ──────────> R8 (Docker) ──> R20 (GitHub Action)
R8 (Docker) ────────────> R11 (Cross-registry release)
R9 (Changesets) ────────> R11 (Cross-registry release)
R10 (release-plz) ──────> R11 (Cross-registry release)

R15 (Observability) ────> R18 (CI agent enhancement)
R18 (CI agent) ─────────> R20 (GitHub Action)
```

### Total Estimated Duration

Phases 0-2 run in parallel: ~3 weeks
Phases 3-4 sequential: ~4 weeks
Phases 5-7 partially parallel: ~5-6 weeks

**Total: ~12-13 weeks** for complete infrastructure buildout.

---

## 23. v1 Limitation Resolution Map

Every limitation identified in the v1 RECAP is addressed by a specific recommendation:

| # | v1 Limitation | Resolution | Recommendation |
|---|--------------|------------|----------------|
| 1 | No Rust CI integration | clippy + fmt + nextest as blocking gates | FA1, R12 |
| 2 | No multi-arch Docker | Pre-built binaries + multi-arch manifest | R7, R8 |
| 3 | No automated cross-publish | Changesets + release-plz + orchestration | R9, R10, R11 |
| 4 | No SBOM generation | CycloneDX SBOMs for Rust and npm | R2 |
| 5 | No dependency scanning | cargo-deny + cargo-audit + pnpm audit | R1, FA2 |
| 6 | No provenance attestation | SLSA Level 3 via GitHub attestation | R3 |
| 7 | No reproducible builds | Content-hash caching + provenance | R3, R6 |
| 8 | No performance regression CI | criterion-compare + statistical gating | R13 |
| 9 | No infrastructure-as-code | Docker, CI, configs all in repo | R8, FA2 |
| 10 | No observability stack | tracing + pino structured logging | R15 |
| 11 | No canary/staged releases | Changesets version PRs + manual approval | R9, R11 |
| 12 | No cross-registry coordination | Orchestrated release pipeline | R11 |
| 13 | No E2E integration tests | Full pipeline test suite | R14 |
| 14 | No license server | Optional server-side validation for enterprise | R17 |
| 15 | CI debt (continue-on-error, lint disabled) | Remove debt, all checks blocking | FA1, FA2 |
| 16 | No Rust workspace feature flags | Cargo features for conditional compilation | FA3 |
| 17 | No WASM target | NAPI-RS v3 WebAssembly support | R4 |
| 18 | Missing Linux musl target | cargo-zigbuild musl cross-compilation | R7, R21 |

**Result: All 18 v1 limitations resolved. Zero deferred.**

---

## 24. Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| NAPI-RS v3 migration breaks existing bindings | Medium | High | Migrate incrementally. Keep v2 fallback. Test all 8 targets. |
| cargo-zigbuild fails for tree-sitter C compilation | Low | High | Test zigbuild with all 10 grammars early. Fallback: `cross-rs`. |
| Changesets doesn't handle cargo versioning | Low | Medium | Use release-plz for cargo side. Shared `VERSION` file. |
| CodSpeed pricing doesn't fit budget | Medium | Low | Start with free criterion-compare. CodSpeed is optional upgrade. |
| E2E test corpus maintenance burden | Medium | Medium | Generate corpus programmatically. Pin expected results. |
| License server adds single point of failure | Low | High | 7-day grace period. Cloudflare Workers (99.99% SLA). |
| Reproducible builds fail due to non-deterministic deps | Medium | Medium | Pin versions via `Cargo.lock`. Use `--locked` flag. |
| GitHub-hosted runner benchmark noise | High | Medium | Use 10% regression threshold minimum on hosted runners. |
| SBOM tooling gaps between Rust and npm | Low | Medium | Use CycloneDX for both ecosystems (best cross-ecosystem support). |
| EU CRA compliance deadline (Dec 2027) | Low | Critical | SBOM + provenance built from Phase 1. Compliance by default. |

---

## 25. Open Items / Decisions Still Needed

1. **CodSpeed vs criterion-compare**: Start with free criterion-compare (R13 Tier 1).
   Evaluate CodSpeed when budget allows for 5% regression detection.

2. **Turborepo remote cache backend**: GitHub Actions cache (zero deps) vs self-hosted S3
   vs Vercel. Recommendation: start with GitHub Actions cache.

3. **Docker registry**: ghcr.io (GitHub Container Registry) vs Docker Hub.
   Recommendation: ghcr.io for tighter GitHub integration.

4. **License server implementation timeline**: R17 is P2. Build after core infrastructure
   is stable. Cloudflare Worker + D1 (same stack as telemetry).

5. **WASM target priority**: wasm32-wasip1-threads is available via NAPI-RS v3 but
   requires testing with all tree-sitter grammars. Build after native targets are stable.

6. **Galaxy WebGPU migration**: Only needed for 1000+ table schemas. Defer until
   performance data from real-world usage is available.

7. **Justfile vs Makefile**: Justfile is recommended (R22) for cleaner syntax and
   cross-platform support. If team prefers Make, the commands are identical.

8. **Pre-commit hook framework**: husky + lint-staged (npm) vs lefthook (Go, faster).
   Recommendation: husky for consistency with existing npm toolchain.

9. **Canary release channel**: Changesets supports canary releases via `--snapshot`.
   Decide whether to offer a canary npm tag for early adopters.

10. **Benchmark dashboard hosting**: GitHub Pages (free, simple) vs Cloudflare Pages
    (faster, more features). Recommendation: GitHub Pages for simplicity.

---

## 26. Recommendation Cross-Reference

Every recommendation from RECOMMENDATIONS.md mapped to its section in this document:

| Recommendation | Section | Status |
|---------------|---------|--------|
| FA1 — Rust CI Pipeline | §8 CI/CD Pipeline | Fully specified |
| FA2 — Supply Chain Security | §8 CI/CD Pipeline | Fully specified |
| FA3 — Cargo Workspace Expansion | §7 Build System | Fully specified |
| R1 — cargo-deny | §8 CI/CD Pipeline | Fully specified |
| R2 — SBOM Generation | §8 CI/CD Pipeline | Fully specified |
| R3 — SLSA Provenance | §8 CI/CD Pipeline | Fully specified |
| R4 — NAPI-RS v3 | §9 Cross-Compilation | Fully specified |
| R5 — Turborepo Remote Caching | §7 Build System | Fully specified |
| R6 — sccache | §7 Build System | Fully specified |
| R7 — cargo-zigbuild | §9 Cross-Compilation | Fully specified |
| R8 — Multi-Arch Docker | §10 Docker Deployment | Fully specified |
| R9 — Changesets | §11 Release Orchestration | Fully specified |
| R10 — release-plz | §11 Release Orchestration | Fully specified |
| R11 — Cross-Registry Pipeline | §11 Release Orchestration | Fully specified |
| R12 — cargo-nextest | §8 CI/CD Pipeline | Fully specified |
| R13 — Performance Regression | §8 CI/CD Pipeline | Fully specified |
| R14 — E2E Integration Tests | §8 CI/CD Pipeline | Fully specified |
| R15 — Structured Observability | §3 Observability System | Fully specified |
| R16 — Telemetry Expansion | §13 Telemetry | Fully specified |
| R17 — Licensing Enhancement | §12 Licensing & Feature Gating | Fully specified |
| R18 — CI Agent Enhancement | §14 CI Agent | Fully specified |
| R19 — CIBench CI Integration | §17 CIBench | Fully specified |
| R20 — GitHub Action v2 | §16 GitHub Action v2 | Fully specified |
| R21 — Pre-Built Binary Distribution | §9 Cross-Compilation | Fully specified |
| R22 — Developer Experience | §19 Developer Experience | Fully specified |

**Result: All 25 recommendations (FA1-FA3, R1-R22) integrated. Zero omitted.**

---

## 27. Architectural Decision Cross-Reference

| Decision | Source | Section |
|----------|--------|---------|
| AD6 — Structured Error Handling (thiserror) | Full System Audit | §2 Error Handling |
| AD10 — Observability-First (tracing) | Full System Audit | §3 Observability |
| AD12 — Performance Data Structures | Full System Audit | §6 Data Structures |
| D1 — Standalone Independence | PLANNING-DRIFT.md | §1 Architectural Position |
| D3 — Separate MCP Servers | PLANNING-DRIFT.md | §10 Docker (containerize independently) |
| D4 — Bridge Crate Architecture | PLANNING-DRIFT.md | §4 Event System (bridge mapping) |
| D5 — Trait-Based Event System | PLANNING-DRIFT.md | §4 Event System |
| D6 — Separate Databases with ATTACH | PLANNING-DRIFT.md | §20 Workspace Management |
| D7 — Grounding Feedback Loop | PLANNING-DRIFT.md | §4 Event System (bridge consumes events) |

---

*This document accounts for 100% of v1 infrastructure features. Every feature is either
KEPT (identical), UPGRADED (improved), ADDED (new capability), or DROPPED (with explicit
justification). All 25 recommendations integrated. All 18 v1 limitations resolved.
All architectural decisions cross-referenced.*

*Infrastructure is the operational backbone that makes Drift shippable, testable, and
deployable. Build it right from Phase 0 and every other system benefits.*
