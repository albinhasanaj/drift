# Drift V2 — Implementation Orchestration Plan

> The definitive build sequence for all ~55 systems in Drift V2.
> Every system accounted for. Every dependency honored. Every risk mitigated.
> Every decision from PLANNING-DRIFT.md (D1-D7) and DRIFT-V2-FULL-SYSTEM-AUDIT.md
> (AD1-AD12) structurally enforced by build order.
>
> This is not a code document. This is the reasoning behind *when* each system gets
> built, *why* that ordering is safe, and *what* breaks if you violate it.
>
> Source truth: 35 V2-PREP documents, DRIFT-V2-STACK-HIERARCHY.md,
> PLANNING-DRIFT.md, DRIFT-V2-FULL-SYSTEM-AUDIT.md, and the existing
> 21-crate Cortex codebase (plus test-fixtures) for proven patterns.
>
> Generated: 2026-02-08

---

## Table of Contents

1. Governing Principles (Why This Order)
2. The ~55-System Master Registry
3. Phase 0 — Crate Scaffold & Infrastructure Primitives
4. Phase 1 — Entry Pipeline (Scanner → Parsers → Storage → NAPI)
5. Phase 2 — Structural Skeleton (Analysis Engine, Call Graph, Detectors)
6. Phase 3 — Pattern Intelligence (Aggregation, Confidence, Outliers, Learning)
7. Phase 4 — Graph Intelligence (Reachability, Taint, Impact, Errors, Tests)
8. Phase 5 — Structural Intelligence (Coupling, Constraints, Contracts, DNA, Security)
9. Phase 6 — Enforcement (Rules, Gates, Policy, Audit, Feedback)
10. Phase 7 — Advanced & Capstone (Simulation, Decisions, Context, N+1)
11. Phase 8 — Presentation (MCP, CLI, CI Agent, Reporters)
12. Phase 9 — Bridge & Integration (Cortex-Drift Bridge, Grounding Loop)
13. Phase 10 — Polish & Ship (Workspace, Licensing, Docker, Telemetry, IDE)
14. Cross-Phase Dependency Matrix
15. Parallelization Map (What Can Run Simultaneously)
16. Risk Register & Mitigation
17. Unspecced Systems — When to Spec Them
18. Cortex Pattern Reuse Guide
19. Verification Gates (How to Know Each Phase Is Done)
20. Third Audit — V2-PREP Cross-Reference Gap Analysis

---

## 1. Governing Principles (Why This Order)

Seven decisions from PLANNING-DRIFT.md and twelve architectural decisions from the
full system audit constrain every ordering choice. Violating any of these creates
retroactive rework that touches dozens of function signatures.

### D1: Standalone Independence
Drift has zero imports from cortex-core. The entire build sequence completes without
Cortex existing. The bridge crate (Phase 9) is the only place both systems meet.
This means every phase from 0-8 can be built, tested, and shipped without any
Cortex dependency. If Cortex development stalls, Drift ships anyway.

### D4: Bridge Crate Is a Leaf
Nothing in Drift depends on cortex-drift-bridge. It depends on Drift. This is why
the bridge is Phase 9 — it consumes the complete Drift stack but nothing in Drift
needs to know it exists. The grounding feedback loop (D7) is the killer product
feature, but architecturally it's the last thing that needs to work.

### D5: DriftEventHandler From Day One
The trait-based event bus with no-op defaults must exist before the first line of
analysis code. Every subsystem emits typed events. In standalone mode these are
no-ops (zero overhead — empty Vec iteration). When the bridge is active, they
become Cortex memories. Retrofitting event emission later touches every function
signature in every subsystem. This is why it's Phase 0, not Phase 1.

### D6: Separate Databases
drift.db is fully self-contained. ATTACH cortex.db is an optional read-only overlay
that never appears on the critical path. Every query works without it. This means
storage (Phase 1) can be built and tested in complete isolation.

### AD6: thiserror From the First Line of Code
Per-subsystem structured error enums must exist before any analysis code. Every Rust
function returns typed errors. The NAPI bridge converts these to structured error
codes for TypeScript. Retrofitting touches every function signature. Phase 0.

### AD10: tracing From the First Line of Code
Structured spans with EnvFilter must exist before any analysis code. Without it,
you're debugging blind and can't measure performance targets (10K files <3s).
Span-based timing is how you find bottlenecks. Phase 0.

### AD1: Incremental-First
Three-layer content-hash skipping is not a feature — it's an architectural constraint.
L1 (file-level skip in scanner), L2 (pattern re-scoring in detectors), L3 (re-learning
threshold in conventions). Every system that processes files must respect content hashes
from day one. Building "full scan first, incremental later" creates a rewrite.

### AD4: Single-Pass Visitor Pattern
The unified analysis engine runs all detectors as visitors in a single AST traversal.
This is a 10-100x performance improvement over v1's multi-pass approach. It constrains
the detector system's interface — detectors must implement a visitor trait, not request
their own parse. This is why the analysis engine and detector system are built together
in Phase 2.

### AD8: Bayesian Confidence With Momentum
Beta distribution posterior replaces static scoring. This constrains every system that
consumes confidence scores (outliers, gates, audit, learning, grounding). The math must
be right before downstream consumers are built. Phase 3.

### AD11: Taint Analysis as First-Class Subsystem
Not an afterthought. Source/sink/sanitizer registry, TOML-configurable, per-framework
defaults. This is the #1 security improvement for v2 and the single biggest gap closure
from v1. It depends on the call graph and reachability engine. Phase 4.

### AD12: Performance Data Structures
FxHashMap (not HashMap), SmallVec (not Vec for small collections), BTreeMap (for ordered
iteration), lasso (string interning). These are Phase 0 infrastructure choices that
every subsequent system uses. Switching later means touching every data structure in
every file.

### The Meta-Principle: Dependency Truth
Nothing at Level N can function without Level N-1 being complete. The hierarchy is not
a suggestion — it's a structural constraint. If you build Level 2A (Pattern Intelligence)
before Level 1 (Structural Skeleton), you have nothing to score confidence on. If you
build Level 3 (Enforcement) before Level 2A, you have no confidence scores to gate on.

The build order follows the dependency graph exactly. Where the graph allows parallelism,
we exploit it. Where it doesn't, we respect it.

---

## 2. The ~55-System Master Registry

Every system in Drift V2, its V2-PREP status, its phase assignment, and its dependency count.

### Specced Systems (35 V2-PREP Documents)

| # | System | V2-PREP | Phase | Downstream Consumers | Net New? |
|---|--------|---------|-------|---------------------|----------|
| — | Configuration System | 04-INFRASTRUCTURE | 0 | ~35+ | No |
| — | thiserror Error Enums | 04-INFRASTRUCTURE | 0 | ~35+ | No |
| — | tracing Instrumentation | 04-INFRASTRUCTURE | 0 | ~35+ | No |
| — | DriftEventHandler Trait | 04-INFRASTRUCTURE | 0 | ~35+ | No |
| — | String Interning (lasso) | 04-INFRASTRUCTURE | 0 | ~15 | No |
| 00 | Scanner | 00-SCANNER | 1 | ~30+ | No |
| 01 | Tree-Sitter Parsers | 01-PARSERS | 1 | ~30+ | No |
| 02 | SQLite Storage (drift.db) | 02-STORAGE | 1 | ~30+ | No |
| 03 | NAPI Bridge (drift-napi) | 03-NAPI-BRIDGE | 1 | ~8 | No |
| 05 | Call Graph Builder | 05-CALL-GRAPH | 2 | ~20 | No |
| 06 | Unified Analysis Engine | 06-UNIFIED-ANALYSIS-ENGINE | 2 | ~10 | No |
| 06 | Detector System | 06-DETECTOR-SYSTEM (ref) | 2 | ~10 | No |
| 07 | Boundary Detection | 07-BOUNDARY-DETECTION | 2 | ~7 | No |
| 08 | Unified Language Provider | 08-UNIFIED-LANGUAGE-PROVIDER | 2 | ~6 | No |
| 09 | Quality Gates | 09-QUALITY-GATES | 6 | ~6 | No |
| 10 | Bayesian Confidence Scoring | 10-BAYESIAN-CONFIDENCE-SCORING | 3 | ~9-10 | No |
| 11 | Outlier Detection | 11-OUTLIER-DETECTION | 3 | ~6 | No |
| 12 | Pattern Aggregation | 12-PATTERN-AGGREGATION | 3 | ~6 | No |
| 13 | Learning System | 13-LEARNING-SYSTEM | 3 | ~5 | No |
| 14 | Reachability Analysis | 14-REACHABILITY-ANALYSIS | 4 | ~6 | No |
| 15 | Taint Analysis | 15-TAINT-ANALYSIS | 4 | ~6-7 | ⚡ Yes |
| 16 | Error Handling Analysis | 16-ERROR-HANDLING-ANALYSIS | 4 | ~5 | No |
| 17 | Impact Analysis | 17-IMPACT-ANALYSIS | 4 | ~5 | No |
| 18 | Test Topology | 18-TEST-TOPOLOGY | 4 | ~5 | No |
| 19 | Coupling Analysis | 19-COUPLING-ANALYSIS | 5 | ~5 | No |
| 20 | Constraint System | 20-CONSTRAINT-SYSTEM | 5 | ~4 | No |
| 21 | Contract Tracking | 21-CONTRACT-TRACKING | 5 | ~3 | No |
| 22 | Constants & Environment | 22-CONSTANTS-ENVIRONMENT | 5 | ~4 | No |
| 23 | Wrapper Detection | 23-WRAPPER-DETECTION | 5 | ~3 | No |
| 24 | DNA System | 24-DNA-SYSTEM | 5 | ~4 | No |
| 25 | Audit System | 25-AUDIT-SYSTEM | 6 | ~4 | No |
| 26 | OWASP/CWE Mapping | 26-OWASP-CWE-MAPPING | 5 | ~5 | No |
| 27 | Cryptographic Failure Detection | 27-CRYPTOGRAPHIC-FAILURE-DETECTION | 5 | ~4 | ⚡ Yes |
| — | Enterprise Secret Detection | 22-CONSTANTS-ENVIRONMENT (§24) | 5 | ~3 | No |
| 28 | Simulation Engine | 28-SIMULATION-ENGINE | 7 | 0 | ⚡ Yes |
| 29 | Decision Mining | 29-DECISION-MINING | 7 | 0 | No |
| 30 | Context Generation | 30-CONTEXT-GENERATION | 7 | 0 | No |
| 31 | Violation Feedback Loop | 31-VIOLATION-FEEDBACK-LOOP | 6 | ~4 | No |
| 32 | MCP Server | 32-MCP-SERVER | 8 | 0 | No |
| 33 | Workspace Management | 33-WORKSPACE-MANAGEMENT | 10 | 0 | No |
| 34 | CI Agent & GitHub Action | 34-CI-AGENT-GITHUB-ACTION | 8 | 0 | No |
| 34 | Cortex-Drift Bridge | 34-CORTEX-DRIFT-BRIDGE | 9 | 0 | No |

### Unspecced Systems (9 Systems — No V2-PREP Yet)

| System | Category | Phase | Why No Spec Yet | When to Spec |
|--------|----------|-------|----------------|--------------|
| CLI | Presentation | 8 | Pure consumer of NAPI. No novel algorithms. | Start of Phase 8 |
| VSCode Extension | Presentation | 10 | Editor integration. Depends on LSP + NAPI. | Start of Phase 10 |
| LSP Server | Presentation | 10 | IDE-agnostic. Depends on full analysis stack. | Start of Phase 10 |
| Dashboard | Presentation | 10 | Web viz. Pure consumer of drift.db. | Start of Phase 10 |
| Galaxy | Presentation | 10 | 3D viz. Stays TS/React. Lowest priority. | When desired |
| AI Providers | Cross-Cutting | 10 | Anthropic/OpenAI/Ollama. Stays TS. | When explain/fix ships |
| Docker Deployment | Cross-Cutting | 10 | Multi-arch Alpine. Needs HTTP MCP transport. | When containerization ships |
| Telemetry | Cross-Cutting | 10 | Cloudflare Worker + D1. Opt-in only. | Post-launch |
| CIBench | Cross-Cutting | 10 | 4-level benchmark framework. Isolated crate. | When benchmarking |

None of these 9 systems block the analysis pipeline. All are Level 5/6 presentation
or cross-cutting concerns. They consume the analysis stack — they don't feed it.


---

## 3. Phase 0 — Crate Scaffold & Infrastructure Primitives

**Goal**: Stand up the Cargo workspace and the four infrastructure primitives that
every subsequent system depends on. Nothing compiles without these.

**Estimated effort**: 1-2 weeks for one developer.

**Why this is first**: D5 (events from day one), AD6 (errors from day one), AD10
(tracing from day one), AD12 (performance data structures from day one). Every
function signature in every subsequent phase references these types. Getting them
wrong means touching every file later.

### 3.1 Cargo Workspace Scaffold

Create the 6-crate workspace structure per 04-INFRASTRUCTURE-V2-PREP §7:

```
crates/drift/
├── Cargo.toml              (workspace root)
├── drift-core/             (types, traits, errors, config, events, data structures)
├── drift-analysis/         (parsers, detectors, call graph, boundaries, all analysis)
├── drift-storage/          (SQLite persistence, migrations, batch writer, CQRS)
├── drift-context/          (context generation: tiktoken-rs, quick-xml, serde_yaml, glob, base64)
├── drift-napi/             (NAPI-RS v3 bindings, singleton runtime)
└── drift-bench/            (benchmarks, isolated from production)
```

Workspace-level `Cargo.toml` pins all shared dependencies:

```toml
[workspace]
members = [
    "drift-core",
    "drift-analysis",
    "drift-storage",
    "drift-context",      # 6th crate (OD-1 resolution)
    "drift-napi",
    "drift-bench",
]

[workspace.dependencies]
tree-sitter = "0.25"          # Was "0.24". 0.26.x exists but 0.25 safer for grammar compat
rusqlite = { version = "0.38", features = ["bundled", "backup", "blob"] }  # Was "0.32"
napi = { version = "3", features = ["async", "serde-json"] }
thiserror = "2"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
rustc-hash = "2"
smallvec = "1"                # Was "1.13". "1" resolves to latest 1.x
lasso = { version = "0.7", features = ["multi-threaded", "serialize"] }
rayon = "1.10"
xxhash-rust = { version = "0.8", features = ["xxh3"] }
petgraph = "0.8"              # Was "0.6". stable_graph is default feature
moka = { version = "0.12", features = ["sync"] }
ignore = "0.4"
crossbeam-channel = "0.5"     # Resolves to ≥0.5.15 (RUSTSEC-2025-0024 patched)
serde = { version = "1", features = ["derive"] }
serde_json = "1"
statrs = "0.18"               # Was "0.17" (implicit). 0.18.0 released Dec 2024
git2 = "0.20"                 # Was "0.19". Bundles libgit2 1.9
tiktoken-rs = "0.9"           # Was "0.6". Adds o200k_harmony, GPT-5 support
fd-lock = "4"                 # Was unspecified. Pin for workspace management

# drift-context dependencies (6th crate)
quick-xml = "0.37"
serde_yaml = "0.9"
glob = "0.3"
base64 = "0.22"

[profile.release]
lto = true
codegen-units = 1
opt-level = 3
strip = "symbols"
panic = "abort"               # Added per S1. Matches Cortex workspace
```

Feature flags: `default = ["full"]` for drift-analysis crate. `cortex` and `mcp` flags are optional, not default. Additional flags: `wasm`,
`benchmark`, `otel` (OpenTelemetry), per-language flags (`lang-python`, `lang-java`,
`lang-rust`, etc.), `full` (all languages + all features).

**Why separate crates**: Schema changes in drift-storage don't recompile parsers.
Benchmark dependencies in drift-bench don't pollute production. Context generation
dependencies (tiktoken-rs, quick-xml) are isolated in drift-context. NAPI bindings in
drift-napi are the bridge layer — they depend on everything above.

### 3.2 Configuration System (DriftConfig)

Per 04-INFRASTRUCTURE-V2-PREP §5. TOML-based with 4-layer resolution:
CLI flags > environment variables > project config (drift.toml) > user config
(~/.drift/config.toml) > compiled defaults.

Core config sections: `ScanConfig`, `AnalysisConfig`, `GateConfig`, `McpConfig`,
`BackupConfig`, `TelemetryConfig`, `LicenseConfig`. Validation at load time —
invalid config is a hard error, not a silent default.

Env var pattern: `DRIFT_SCAN_MAX_FILE_SIZE`, `DRIFT_LOG`, etc.

**Lives in**: `drift-core/src/config/`

**Why first**: Every system reads config. Scanner needs ignore patterns, detectors
need thresholds, storage needs pragma settings, quality gates need fail levels.
Must exist before first scan.

### 3.3 Error Handling (thiserror)

Per 04-INFRASTRUCTURE-V2-PREP §2. One error enum per subsystem:
`ScanError`, `ParseError`, `StorageError`, `DetectionError`, `CallGraphError`,
`PipelineError`, `TaintError`, `ConstraintError`, `BoundaryError`, `GateError`,
`ConfigError`, `NapiError`.

`DriftErrorCode` trait for NAPI conversion — every error enum implements it,
producing structured `[ERROR_CODE] message` strings. 14+ NAPI error codes:
`SCAN_ERROR`, `PARSE_ERROR`, `DB_BUSY`, `DB_CORRUPT`, `CANCELLED`,
`UNSUPPORTED_LANGUAGE`, `DETECTION_ERROR`, `CALL_GRAPH_ERROR`, `CONFIG_ERROR`,
`LICENSE_ERROR`, `GATE_FAILED`, `STORAGE_ERROR`, `DISK_FULL`, `MIGRATION_FAILED`.

Non-fatal error collection pattern: `PipelineResult.errors: Vec<PipelineError>`.
Analysis continues past non-fatal errors; fatal errors abort.

**Rule**: `thiserror` for defining error types. `anyhow` nowhere in the codebase.

**Lives in**: `drift-core/src/errors/`

### 3.4 Observability (tracing)

Per 04-INFRASTRUCTURE-V2-PREP §3. `tracing` crate with `EnvFilter` for per-subsystem
log levels: `DRIFT_LOG=scanner=debug,parser=info,storage=warn`.

12+ key metrics as structured span fields: `scan_files_per_second`, `cache_hit_rate`,
`parse_time_per_language`, `napi_serialization_time`, `detection_time_per_category`,
`batch_write_time`, `call_graph_build_time`, `confidence_compute_time`,
`gate_evaluation_time`, `mcp_response_time`, `discovery_duration`, `hashing_duration`.

Optional OpenTelemetry layer behind `otel` feature flag. `pino` for TS layer.

**Lives in**: `drift-core/src/tracing/`

### 3.5 Event System (DriftEventHandler)

Per 04-INFRASTRUCTURE-V2-PREP §4 and PLANNING-DRIFT.md D5. Trait with no-op defaults,
`Vec<Arc<dyn DriftEventHandler>>`, synchronous dispatch via `emit()` helper.

21 event methods covering the full lifecycle (per 34-CORTEX-DRIFT-BRIDGE-V2-PREP §6.1
complete mapping table):
- Scan: `on_scan_started`, `on_scan_progress`, `on_scan_complete`, `on_scan_error`
- Patterns: `on_pattern_discovered`, `on_pattern_approved`, `on_pattern_ignored`, `on_pattern_merged`
- Violations: `on_violation_detected`, `on_violation_dismissed`, `on_violation_fixed`
- Enforcement: `on_gate_evaluated`, `on_regression_detected`, `on_enforcement_changed`
- Constraints: `on_constraint_approved`, `on_constraint_violated`
- Decisions: `on_decision_mined`, `on_decision_reversed`, `on_adr_detected`
- Boundaries: `on_boundary_discovered`
- Detector health: `on_detector_alert`, `on_detector_disabled`
- Feedback: `on_feedback_abuse_detected`
- Errors: `on_error`

Zero overhead when no handlers registered (empty Vec iteration). In standalone mode,
these are no-ops. When the bridge is active (Phase 9), they become Cortex memories.

**Lives in**: `drift-core/src/events/`

### 3.6 Data Structures & String Interning

Per 04-INFRASTRUCTURE-V2-PREP §6 and AD12.

- `FxHashMap` / `FxHashSet` (from `rustc-hash`) — default hash map everywhere. 2-3x
  faster than `HashMap` for integer and small-key lookups.
- `SmallVec<[T; N]>` — for collections that are usually small (CWE IDs per detection,
  call arguments, etc.). Avoids heap allocation for the common case.
- `BTreeMap` — for ordered iteration (resolution strategies, sorted results).
- `lasso` — `ThreadedRodeo` for build/scan phase (thread-safe, mutable), `RodeoReader`
  for query phase (immutable, zero-contention). `PathInterner` normalizes path separators
  before interning. `FunctionInterner` supports qualified name interning (`Class.method`).
  60-80% memory reduction for file paths and function names.

**Lives in**: `drift-core/src/types/` (re-exports from crates)

### 3.7 Phase 0 Verification Gate

Phase 0 is complete when:
- [ ] `cargo build --workspace` succeeds with zero warnings
- [ ] `DriftConfig::load()` resolves 4 layers correctly
- [ ] Every error enum has a `DriftErrorCode` implementation
- [ ] `DRIFT_LOG=debug` produces structured span output
- [ ] `DriftEventHandler` trait compiles with no-op defaults
- [ ] `ThreadedRodeo` interns and resolves paths correctly
- [ ] All workspace dependencies are pinned at exact versions
- [ ] `cargo clippy --workspace` passes with zero warnings
- [ ] `panic = "abort"` set in release profile
- [ ] drift-context crate compiles and exports public types

**What you can't do yet**: Scan files, parse ASTs, persist data, call from TypeScript.
That's Phase 1.

---

## 4. Phase 1 — Entry Pipeline (Scanner → Parsers → Storage → NAPI)

**Goal**: Build the four bedrock systems that form the spine of the entire pipeline.
At the end of Phase 1, you can scan a real codebase, parse files into ASTs, persist
results to drift.db, and call it all from TypeScript.

**Estimated effort**: 2-3 weeks for one developer, or 1-2 weeks with two.

**Why this order**: Scanner discovers files → Parsers parse them → Storage persists
results → NAPI exposes it to TypeScript. Each system's output is the next system's
input. Integration testing is sequential (Scanner→Parsers→Storage→NAPI), but development of Storage and NAPI infrastructure can overlap with Scanner and Parsers.

### 4.1 Scanner (System 00)

Per 00-SCANNER-V2-PREP. The entry point to everything.

Core: `ignore` crate v0.4 (`WalkParallel` from ripgrep) for Phase 1 discovery.
`rayon` v1.10 for Phase 2 processing. xxh3 content hashing via `xxhash-rust` v0.8.

Two-level incremental detection: mtime comparison (catches ~95% unchanged) → content
hash for mtime-changed files. `.driftignore` support (gitignore syntax, hierarchical).
18 default ignores (node_modules, .git, dist, build, target, .next, .nuxt, __pycache__,
.pytest_cache, coverage, .nyc_output, vendor, .venv, venv, .tox, .mypy_cache, bin, obj).

Output: `ScanDiff` (added/modified/removed/unchanged) + `ScanStats` (timing, throughput).
`ScanEntry` per file: path, content_hash, mtime, size, language (detected from extension).

Cancellation via `AtomicBool`. Progress via `DriftEventHandler::on_scan_progress`.

Performance targets: 10K scan: <300ms Linux, <500ms macOS (APFS getdirentries64 bottleneck). 100K scan: <3s cold, <1.5s incremental (1% changed). Incremental (1 file) <100ms.

| Platform | 10K files | 100K cold | 100K incremental |
|----------|-----------|-----------|-----------------|
| Linux    | <300ms    | <3s       | <1.5s           |
| macOS    | <500ms    | <3s       | <1.5s           |

**Lives in**: `drift-analysis/src/scanner/`

**Why safe to build now**: Depends only on Phase 0 infrastructure (config, errors,
tracing, events). No analysis logic, no storage, no NAPI.

### 4.2 Tree-Sitter Parsers (System 01)

Per 01-PARSERS-V2-PREP. The single most critical system.

10 languages: TypeScript, JavaScript, Python, Java, C#, Go, Rust, Ruby, PHP, Kotlin.
Per-language tree-sitter grammars compiled via `build.rs` (static linking, no WASM).
`thread_local!` parser instances (tree-sitter `Parser` is not `Send`).

Canonical `ParseResult` reconciled across 30+ downstream consumer documents:
functions, classes, imports, exports, call_sites, decorators, inheritance,
access_modifiers, type_annotations, string_literals, numeric_literals,
error_handling_constructs, namespace/package info.

2 consolidated tree-sitter `Query` objects per language (structure + calls) — pre-compiled,
reused across files. Moka LRU parse cache (in-memory, TinyLFU admission) + SQLite
`parse_cache` table for persistence.

Error-tolerant parsing: partial results from ERROR nodes. Body hash + signature hash
for function-level change detection.

`LanguageParser` trait + `ParserManager` dispatcher + `define_parser!` macro for
mechanical language addition.

Performance: single-pass, shared results across all detectors per file.

**Lives in**: `drift-analysis/src/parsers/`

**Why safe to build now**: Depends on scanner (for file list) and Phase 0 infrastructure.
No downstream analysis logic needed.

### 4.3 SQLite Storage (System 02)

Per 02-STORAGE-V2-PREP. Where everything persists.

`rusqlite` v0.32+ with `bundled` feature. WAL mode, `PRAGMA synchronous=NORMAL`,
64MB page cache, 256MB mmap, `busy_timeout=5000`, `temp_store=MEMORY`,
`auto_vacuum=INCREMENTAL`, `foreign_keys=ON`.

Write-serialized + read-pooled: `Mutex<Connection>` writer, round-robin `ReadPool`
with `AtomicUsize` index, read connections with `SQLITE_OPEN_READ_ONLY`.

Medallion architecture: staging → normalized (source of truth) → materialized
(materialized views: `materialized_status`, `materialized_security`, `health_trends`).

Batch writer via `crossbeam-channel` bounded(1024) with dedicated writer thread,
`BEGIN IMMEDIATE` transactions, `prepare_cached()`, batch size 500, `recv_timeout(100ms)`.

Keyset pagination (not OFFSET/LIMIT) with composite cursor `(sort_column, id)`.

Schema migration via `rusqlite_migration` + `PRAGMA user_version`.

Start with the ~10-15 tables needed for Phase 1-2 (file_metadata, parse_cache,
functions, call_edges). Add tables incrementally as each phase ships. The full
schema is 40+ STRICT tables across 15 domains — don't create them all upfront.

**Lives in**: `drift-storage/src/`

**Why safe to build now**: Depends only on Phase 0 infrastructure. The connection
architecture, batch writer, and migration system are independent of what gets stored.

### 4.4 NAPI Bridge (System 03)

Per 03-NAPI-BRIDGE-V2-PREP. The only door between Rust and TypeScript.

napi-rs v3 (July 2025), no `compat-mode`. Singleton `DriftRuntime` via `OnceLock`
(lock-free after init). Two function categories: Command (write-heavy, return summary)
and Query (read-only, paginated, keyset cursors).

`AsyncTask` for >10ms operations (runs on libuv thread pool). v3 `ThreadsafeFunction`
with ownership-based lifecycle for progress callbacks.

Start with 3 core lifecycle functions: `drift_initialize()`, `drift_shutdown()`,
`drift_scan()`. Add binding modules incrementally as each phase ships. The full
bridge is ~40+ functions across ~15 modules — don't build them all upfront.

8 platform targets: x86_64/aarch64 macOS, x86_64/aarch64 Linux gnu/musl,
x86_64 Windows, wasm32-wasip1-threads fallback.

**Lives in**: `drift-napi/src/`

**Why safe to build now**: Depends on scanner, parsers, and storage being functional.
The singleton runtime pattern is proven by cortex-napi (33 functions, 12 modules).

### 4.5 Phase 1 Verification Gate

Phase 1 is complete when:
- [ ] `drift_initialize()` creates drift.db with correct PRAGMAs
- [ ] `drift_scan()` discovers files, computes hashes, returns `ScanDiff`
- [ ] Incremental scan correctly identifies added/modified/removed files
- [ ] All 10 language parsers produce valid `ParseResult` from test files
- [ ] Parse cache hits on second parse of unchanged file
- [ ] Batch writer persists file_metadata and parse results to drift.db
- [ ] `drift_shutdown()` cleanly closes all connections
- [ ] TypeScript can call all three functions and receive typed results
- [ ] Performance: 10K files scanned + parsed in <3s end-to-end

**What you can do now**: Scan a real codebase, parse every file, persist results,
call it from TypeScript. This is a working (if minimal) product.

**What you can't do yet**: Detect patterns, build call graphs, score confidence,
enforce quality gates. That's Phases 2-6.


---

## 5. Phase 2 — Structural Skeleton (Analysis Engine, Call Graph, Detectors)

**Goal**: Build the core analysis systems that produce the foundational data structures.
At the end of Phase 2, Drift can detect patterns across 16 categories, build a call
graph with 6 resolution strategies, detect data boundaries across 33+ ORMs, and
normalize ASTs across 9 languages.

**Estimated effort**: 3-4 weeks for core pipeline, but the full UAE (Unified Analysis
Engine + Detector System + GAST + ULP + per-language analyzers) spans 7 internal phases
totaling ~22-27 weeks per 06-UNIFIED-ANALYSIS-ENGINE-V2-PREP §18. The 3-4 week estimate
covers the Phase 2 deliverables (core pipeline + visitor engine + initial detectors);
the remaining UAE phases (GAST normalization, core analyzers, ULP, advanced features,
per-language analyzers) continue in parallel with Phases 3-5. Two parallel tracks
possible (see §15).

> ⚠️ **Build Estimate Warning**: The full UAE is the single largest system in Drift v2.
> 350+ detectors must be ported from v1 TypeScript to Rust. GAST normalization requires
> ~40-50 node types and 10 per-language normalizers. Plan for incremental delivery — ship
> core pipeline + 50-80 detectors in Phase 2, continue porting through Phases 3-5.

**Why now**: These are Level 1 systems. They consume ParseResult (Phase 1) and produce
the data that every Level 2+ system needs. Without them, there's nothing to score,
aggregate, or enforce.

### 5.1 String Interning Integration

While lasso is scaffolded in Phase 0, the actual integration into ParseResult and
all identifier-heavy paths happens here. `ThreadedRodeo` for the build/scan phase
(thread-safe writes during parallel parsing), frozen to `RodeoReader` for the query
phase (zero-contention reads during analysis).

Every file path, function name, class name, and pattern ID becomes a `Spur` handle.
This is what enables O(1) comparisons and 60-80% memory reduction.

### 5.2 Unified Analysis Engine (System 06)

Per 06-UNIFIED-ANALYSIS-ENGINE-V2-PREP. The core pattern detection pipeline.

4-phase per-file pipeline:
1. AST pattern detection via visitor pattern (single-pass, all detectors as visitors)
2. String extraction (literals, template strings, interpolations)
3. Regex on extracted strings (URL patterns, SQL patterns, secret patterns)
4. Resolution index building (6 strategies for cross-file symbol resolution)

GAST normalization layer (~40-50 node types, 10 per-language normalizers) for cross-language
analysis. This is what lets a "naming convention" detector work identically on TypeScript
and Python. Per 06-UAE-V2-PREP §Phase 3 (Weeks 5-8): normalizers for TS/JS, Python,
Java, C#, PHP, Go, Rust, C++, and a base normalizer.

`GASTNode::Other { kind: String, children: Vec<GASTNode> }` catch-all variant ensures
normalizers can pass through unrecognized constructs without data loss.

Declarative TOML pattern definitions (user-extensible without recompiling). Each
`CompiledQuery` carries `cwe_ids: SmallVec<[u32; 2]>` and `owasp: Option<Spur>`.

Incremental: processes only `ScanDiff.added + modified` files. Content-hash skip
for unchanged files.

**Lives in**: `drift-analysis/src/engine/`

### 5.3 Detector System (System 06 — Detectors)

Per 06-DETECTOR-SYSTEM.md. The trait-based detection framework.

16 categories: api, auth, components, config, contracts, data-access, documentation,
errors, logging, performance, security, structural, styling, testing, types, accessibility.

3 variants per category: Base (pattern matching), Learning (convention discovery),
Semantic (cross-file analysis). 350+ detectors total.

`Detector` trait: `detect(&self, ctx: &DetectionContext) -> Vec<PatternMatch>`.
Registry with category filtering, critical-only mode.

Each detector carries `cwe_ids` and `owasp` fields populated from the OWASP/CWE
mapping registry at detection time.

**Build strategy**: Start with 3-5 categories (security, structural, errors, testing,
data-access). These cover the highest-value detections. Add remaining categories
incrementally. The trait-based architecture means adding a detector is mechanical —
implement the trait, register it, done.

**Lives in**: `drift-analysis/src/detectors/`

### 5.4 Call Graph Builder (System 05)

Per 05-CALL-GRAPH-V2-PREP. The highest-leverage Level 1 system (~12 downstream consumers).

petgraph `StableGraph` in-memory + SQLite persistence. 6 resolution strategies:
1. Direct (exact name match within same file)
2. Method (class.method qualified lookup)
3. Constructor (new/init patterns)
4. Callback (closure/lambda parameter tracking)
5. Dynamic (string-based/reflection — lower confidence)
6. External (cross-module via import/export resolution)

Parallel extraction via rayon. `functions` + `call_edges` + `data_access` tables.

Memory estimates by codebase size (per 05-CALL-GRAPH-V2-PREP §3):
- 10K files (~50K functions): ~50MB total with indexes
- 50K files (~250K functions): ~250MB total
- 100K files (~500K functions): ~500MB total
- 500K+ files (~2.5M functions): Fallback to SQLite recursive CTE (O(1) memory, ~10x slower)

`in_memory_threshold` config (default 500K functions) triggers the SQLite CTE fallback.

> **CTE fallback performance note**: Use temp table for visited set instead of string-based
> cycle detection (`path NOT LIKE '%' || id || '%'`) — ~5x faster for dense graphs.
> CTE max_depth default = 5 (bounds combinatorial explosion for dense graphs).
> CTE fallback is ~10x slower than in-memory BFS for sparse graphs, up to 50-100x for
> highly connected graphs with many cycles. No global visited set in SQLite recursive CTEs.

Resolution rate target: 60-85% overall (varies by language: TS/JS 70-85%, Python 60-75%,
Java 75-85%, Go 70-80%, C/C++ 50-65%). Track per-language for observability.

DI injection framework support: 5 frameworks (FastAPI, Spring, NestJS, Laravel, ASP.NET)
at confidence 0.80.

Incremental: re-extract only changed files (O(edges_in_changed_file)), remove edges
for deleted files, re-resolve affected edges.

Entry point detection: 5 heuristic categories (exported functions, main/index files,
route handlers, test functions, CLI entry points).

**Lives in**: `drift-analysis/src/call_graph/`

### 5.5 Boundary Detection (System 07)

Per 07-BOUNDARY-DETECTION-V2-PREP. The foundation for all data access awareness.

Two-phase learn-then-detect architecture (proven by v1). 33+ ORM framework detection
across 9 languages (28 from v1 + 5 new: MikroORM, Kysely, sqlc, SQLBoiler, Qt SQL).
10 dedicated field extractors (7 from v1 + 3 new: EfCoreExtractor, HibernateExtractor,
EloquentExtractor).

Sensitive field detection: 4 categories (PII, Credentials, Financial, Health) with
~100+ patterns (3x v1's ~30). 6 formal false-positive filters. Confidence scoring
with 5 weighted factors.

**Lives in**: `drift-analysis/src/boundaries/`

### 5.6 Unified Language Provider (System 08)

Per 08-UNIFIED-LANGUAGE-PROVIDER-V2-PREP. The semantic bridge between raw parsing
and language-agnostic detection.

9 language normalizers (TS/JS, Python, Java, C#, PHP, Go, Rust, C++, base).
22 ORM/framework matchers. `UnifiedCallChain` universal representation.
12 semantic categories. Framework detection for 5+ framework pattern sets.

N+1 query detection module. Taint sink extraction module.

**Lives in**: `drift-analysis/src/language_provider/`

### 5.7 Phase 2 Parallelization

Two independent tracks are possible:

**Track A** (Analysis + Detection): Unified Analysis Engine → Detector System.
These are tightly coupled — the engine runs detectors as visitors.

**Track B** (Graph + Boundaries): Call Graph Builder + Boundary Detection +
Unified Language Provider. These depend on ParseResult but not on the detector system.

Track A and Track B can proceed in parallel. They converge at Phase 3 (Pattern
Intelligence), which needs both detected patterns and the call graph.

### 5.8 Phase 2 Verification Gate

Phase 2 is complete when:
- [ ] Analysis engine processes a real codebase through all 4 phases
- [ ] At least 5 detector categories produce valid `PatternMatch` results
- [ ] GAST normalization produces identical node types for equivalent TS/Python code
- [ ] `coverage_report()` per language (mandatory) — target ≥85% node coverage for P0 languages (TS, JS, Python)
- [ ] Call graph builds with all 6 resolution strategies
- [ ] Incremental call graph update correctly handles file changes
- [ ] Boundary detection identifies ORM patterns across at least 5 frameworks
- [ ] ULP normalizes call chains across at least 3 languages
- [ ] All results persist to drift.db via batch writer
- [ ] NAPI exposes `drift_analyze()` and `drift_call_graph()` to TypeScript
- [ ] Performance: 10K file codebase analyzed in <10s end-to-end

---

## 6. Phase 3 — Pattern Intelligence (Aggregation, Confidence, Outliers, Learning)

**Goal**: Build the four Level 2A systems that transform raw pattern detections into
ranked, scored, learned conventions. This is what makes Drift *Drift* — without these,
you have a scanner that finds things but can't rank, learn, or flag deviations.

**Estimated effort**: 3-4 weeks. Limited parallelism (see dependency chain below).

**Why now**: These consume detector output (Phase 2) and produce the scored patterns
that enforcement (Phase 6) needs. They're the numerical backbone of the entire system.

### 6.1 Dependency Chain Within Phase 3

This is the one phase where internal ordering matters significantly:

```
Detector System (Phase 2)
    │
    ├→ Pattern Aggregation (groups per-file matches into project-level patterns)
    │    │
    │    ├→ Bayesian Confidence Scoring (scores aggregated patterns)
    │    │    │
    │    │    ├→ Outlier Detection (uses confidence to set thresholds)
    │    │    │
    │    │    └→ Learning System (uses confidence for convention classification)
    │    │
    │    └→ Learning System (uses aggregated patterns for convention discovery)
```

Pattern Aggregation must come first — it turns thousands of scattered per-file matches
into coherent project-level Pattern entities. Confidence Scoring needs aggregated
patterns to compute posteriors. Outlier Detection needs confidence scores to set
thresholds. Learning needs both aggregation and confidence.

### 6.2 Pattern Aggregation & Deduplication (System 12)

Per 12-PATTERN-AGGREGATION-V2-PREP. The bridge between detection and intelligence.

7-phase pipeline:
1. Group by pattern ID (bucket per-file matches)
2. Cross-file merging (same pattern across files)
3. Jaccard similarity (0.85 threshold flags for review, 0.95 auto-merge)
4. MinHash LSH for approximate near-duplicate detection at scale (future: n > 50K)
5. Hierarchy building (parent-child pattern relationships)
6. Counter reconciliation (location_count, outlier_count caches)
7. Gold layer refresh (materialized views in drift.db)

Exact + semantic deduplication. Incremental: only re-aggregate patterns from changed files.

**Lives in**: `drift-analysis/src/patterns/aggregation/`

### 6.3 Bayesian Confidence Scoring (System 10)

Per 10-BAYESIAN-CONFIDENCE-SCORING-V2-PREP. The numerical backbone.

Beta distribution: `Beta(1+k, 1+n-k)` posterior. 5-factor model:
1. Frequency (how often the pattern appears)
2. Consistency (how uniformly across files)
3. Age (how long established — older = more confident)
4. Spread (how many files — wider = more confident)
5. Momentum (trend direction — rising/falling/stable)

Graduated tiers by credible interval width:
- Established (≥0.85) — high confidence, narrow interval
- Emerging (≥0.70) — growing adoption
- Tentative (≥0.50) — early signal
- Uncertain (<0.50) — insufficient data

Temporal decay: frequency decline → confidence reduction. Momentum tracking for
trend detection.

**Lives in**: `drift-analysis/src/patterns/confidence/`

### 6.4 Outlier Detection (System 11)

Per 11-OUTLIER-DETECTION-V2-PREP. The statistical backbone.

6 methods with automatic selection based on sample size:
1. Z-Score with iterative masking (n ≥ 30) — 3-iteration cap
2. Grubbs' test (10 ≤ n < 30) — single outlier in small samples
3. Generalized ESD / Rosner test (n ≥ 25, multiple outliers)
4. IQR with Tukey fences (supplementary, non-normal data)
5. Modified Z-Score / MAD (robust to extreme outliers)
6. Rule-based (always, for structural rules)

4 significance tiers: Critical, High, Moderate, Low.
Deviation scoring (normalized 0.0-1.0 severity).
Outlier-to-violation conversion pipeline.

T-distribution critical value computation via `statrs` crate.

**Lives in**: `drift-analysis/src/patterns/outliers/`

### 6.5 Learning System (System 13)

Per 13-LEARNING-SYSTEM-V2-PREP. What makes Drift self-configuring.

Bayesian convention discovery. 5 categories:
1. Universal (cross-project norms)
2. ProjectSpecific (local conventions)
3. Emerging (gaining adoption)
4. Legacy (declining usage)
5. Contested (inconsistent adoption — within 15% frequency)

Thresholds: minOccurrences=3, dominance=0.60, minFiles=2.
Automatic pattern promotion: discovered → approved when thresholds met.
Re-learning trigger: >10% files changed → full re-learn.

Dirichlet-Multinomial extension for multi-value conventions.
Convention scope system (project / directory / package).
Convention expiry & retention policies.

**Lives in**: `drift-analysis/src/patterns/learning/`

### 6.6 Phase 3 Verification Gate

Phase 3 is complete when:
- [ ] Pattern aggregation groups per-file matches into project-level patterns
- [ ] Jaccard similarity correctly flags near-duplicate patterns (0.85 threshold)
- [ ] Bayesian confidence produces Beta posteriors with correct tier classification
- [ ] Momentum tracking detects rising/falling/stable trends
- [ ] Outlier detection auto-selects correct method based on sample size
- [ ] Z-Score, Grubbs', and IQR methods produce correct outlier classifications on a reference dataset with known outliers (≥90% precision, ≥80% recall)
- [ ] Learning system discovers conventions with minOccurrences=3, dominance=0.60
- [ ] Convention categories (Universal/Emerging/Legacy/Contested) classify correctly
- [ ] All results persist to drift.db (patterns table with α, β, score columns)
- [ ] NAPI exposes pattern query functions with keyset pagination
- [ ] Performance: confidence scoring for 10K patterns in <500ms

---

## 7. Phase 4 — Graph Intelligence (Reachability, Taint, Impact, Errors, Tests)

**Goal**: Build the five Level 2B systems that consume the call graph. These represent
the security and structural intelligence that makes Drift enterprise-grade.

**Estimated effort**: 4-6 weeks. Highly parallelizable (see §15).

**Why now**: All five depend on the call graph (Phase 2). They don't depend on each
other (mostly). This is the widest parallelization opportunity in the entire build.

### 7.1 Why These Are All Parallel

Each of these systems:
- Reads the call graph (petgraph StableGraph or SQLite CTE fallback)
- Reads ParseResult for language-specific analysis
- Writes to its own set of drift.db tables
- Emits its own DriftEventHandler events
- Has zero dependency on the other four

The only soft dependency: Taint Analysis benefits from Reachability (for sensitivity
classification of taint paths). But taint can be built with a stub reachability
interface and integrated later. Impact Analysis benefits from Test Topology (for
coverage gap analysis). Same approach — build with stubs, integrate later.

### 7.2 Reachability Analysis (System 14)

Per 14-REACHABILITY-ANALYSIS-V2-PREP. The highest-leverage Level 2B system.

Forward/inverse BFS traversal on petgraph. Auto-select engine: petgraph for small
graphs (<10K nodes), SQLite recursive CTE for large graphs (>10K nodes).

Sensitivity classification: "Can user input reach this SQL query?" 4 categories
(Critical, High, Medium, Low) based on data sensitivity of reachable nodes.

Reachability caching with LRU + invalidation on graph changes.
Cross-service reachability for microservice boundaries.
Field-level data flow tracking.

**Lives in**: `drift-analysis/src/graph/reachability/`

### 7.3 Taint Analysis (System 15) — NET NEW

Per 15-TAINT-ANALYSIS-V2-PREP. The #1 security improvement for v2. No v1 equivalent.

Source/sink/sanitizer model. TOML-driven registry (extensible without code changes).

Phase 1: Intraprocedural (within-function dataflow tracking).
Phase 2: Interprocedural via function summaries (cross-function taint propagation).

17 sink types with CWE mappings (per 15-TAINT-ANALYSIS-V2-PREP §5 SinkType enum, plus XmlParsing and FileUpload):
SqlQuery (CWE-89), OsCommand (CWE-78), CodeExecution (CWE-94), FileWrite (CWE-22),
FileRead (CWE-22), HtmlOutput (CWE-79), HttpRedirect (CWE-601), HttpRequest (CWE-918),
Deserialization (CWE-502), LdapQuery (CWE-90), XpathQuery (CWE-643),
TemplateRender (CWE-1336), LogOutput (CWE-117), HeaderInjection (CWE-113),
RegexConstruction (CWE-1333), XmlParsing (CWE-611), FileUpload (CWE-434),
plus Custom(u32) for user-defined sinks.

Taint label propagation with sanitizer tracking. Framework-specific taint specifications.
SARIF code flow generation for taint paths.

**Why this is the biggest gap closure**: v1 has zero taint analysis. Every major SAST
tool (SonarQube, Checkmarx, Fortify, Semgrep) implements it. Without taint, Drift
can detect structural patterns but cannot answer "can untrusted user input reach this
dangerous operation without being sanitized?" — the question that matters most for security.

**Lives in**: `drift-analysis/src/graph/taint/`

### 7.4 Error Handling Analysis (System 16)

Per 16-ERROR-HANDLING-ANALYSIS-V2-PREP. 8-phase topology engine.

Phases: error type profiling → handler detection → propagation chain tracing via
call graph → unhandled path identification → gap analysis (empty catch, swallowed
errors, generic catches) → framework-specific analysis (20+ frameworks) →
CWE/OWASP A10:2025 mapping → remediation suggestions.

20+ framework support: Express, Koa, Hapi, Fastify, Django, Flask, Spring, ASP.NET,
Rails, Sinatra, Laravel, Phoenix, Gin, Echo, Actix, Rocket, NestJS, Next.js, Nuxt,
SvelteKit.

**Lives in**: `drift-analysis/src/graph/error_handling/`

### 7.5 Impact Analysis (System 17)

Per 17-IMPACT-ANALYSIS-V2-PREP. Blast radius + dead code + path finding.

Blast radius: transitive caller analysis via call graph BFS. Risk scoring per function
(5 factors: blast radius, sensitivity, test coverage, complexity, change frequency).

Dead code detection with 10 false-positive categories: entry points, event handlers,
reflection targets, dependency injection, test utilities, framework hooks,
decorators/annotations, interface implementations, conditional compilation, dynamic imports.

Dijkstra shortest path + K-shortest paths for impact visualization.

**Lives in**: `drift-analysis/src/graph/impact/`

### 7.6 Test Topology (System 18)

Per 18-TEST-TOPOLOGY-V2-PREP. Test intelligence across 45+ frameworks.

7-dimension quality scoring: coverage breadth, coverage depth, assertion density,
mock ratio, test isolation, test freshness, test stability.

24 test smell detectors (mystery guest, eager test, lazy test, assertion roulette, etc.).

Coverage mapping via call graph BFS (test function → tested functions).
Minimum test set computation via greedy set cover algorithm.

**Lives in**: `drift-analysis/src/graph/test_topology/`

### 7.7 Phase 4 Verification Gate

Phase 4 is complete when:
- [ ] Forward/inverse BFS produces correct reachability results
- [ ] Auto-select correctly chooses petgraph vs SQLite CTE based on graph size
- [ ] Taint analysis traces source→sink paths with sanitizer tracking
- [ ] At least 3 CWE categories (SQLi, XSS, command injection) produce valid findings
- [ ] SARIF code flows generated for taint paths
- [ ] Error handling analysis identifies unhandled error paths across call graph
- [ ] Framework-specific error boundaries detected for at least 5 frameworks
- [ ] Impact analysis computes blast radius with correct transitive closure
- [ ] Dead code detection correctly excludes all 10 false-positive categories
- [ ] Test topology maps test→source coverage via call graph
- [ ] All results persist to drift.db in their respective tables
- [ ] NAPI exposes analysis functions for all 5 systems
- [ ] All 5 systems complete on 10K-file codebase in <15s total


---

## 8. Phase 5 — Structural Intelligence (Coupling, Constraints, Contracts, DNA, Security)

**Goal**: Build the seven Level 2C systems and two Level 2D systems that provide
architecture health, contract verification, and the capstone DNA metric. These are
highly parallelizable — most depend on the call graph and detector system but not
on each other.

**Estimated effort**: 4-6 weeks for Phase 5 gate (all systems except Contract Tracking at MVP). Contract Tracking continues through Phases 6-8 (~20 weeks total). Constraint System and DNA System start 0-2 weeks after other P5 systems (waiting for P4). Maximum parallelism (up to 5 immediate tracks + 3 delayed tracks).

**Why now**: These consume call graph (Phase 2) and pattern data (Phase 3). They
produce the structural intelligence that enforcement (Phase 6) and advanced systems
(Phase 7) need. Most are independent of each other, making this the second-widest
parallelization opportunity.

### 8.1 Parallelization Within Phase 5

5 immediate tracks (zero cross-dependencies, can start as soon as Phase 2 completes):
- Coupling Analysis (reads call graph + imports)
- Contract Tracking (reads parsers + ULP)
- Constants & Environment (reads parsers + analysis engine)
- Wrapper Detection (reads call graph + parsers)
- Cryptographic Failure Detection (reads parsers + analysis engine) — NET NEW

3 delayed tracks (start 0-2 weeks after other P5 systems, waiting for Phase 4):
- Constraint System (benefits from nearly everything, but can start with parser-based
  constraints and add call-graph-based constraints incrementally)
- DNA System (capstone — consumes coupling, constraints, test topology, error handling,
  patterns, confidence, boundaries. Build the gene extractor framework first, add
  extractors as their data sources become available)
- OWASP/CWE Mapping (metadata enrichment layer, reads all security detectors — benefits from Phase 4 taint/reachability data)

### 8.2 Coupling Analysis (System 19)

Per 19-COUPLING-ANALYSIS-V2-PREP. Architecture health metrics.

10-phase pipeline: module boundary detection → import graph construction →
afferent/efferent counting → instability calculation → abstractness calculation →
distance from main sequence → Tarjan's SCC cycle detection → condensation graph →
zone classification (Zone of Pain, Zone of Uselessness, Main Sequence) →
cycle break suggestions → trend tracking.

Robert C. Martin metrics: Ce (efferent), Ca (afferent), I (instability = Ce/(Ce+Ca)),
A (abstractness), D (distance from main sequence = |A+I-1|).

Tarjan's SCC via `petgraph::algo::tarjan_scc` — proven pattern from cortex-causal.

**Lives in**: `drift-analysis/src/structural/coupling/`

### 8.3 Constraint System (System 20)

Per 20-CONSTRAINT-SYSTEM-V2-PREP. Architectural invariant enforcement.

12 invariant types: must_exist, must_not_exist, must_precede, must_follow,
must_colocate, must_separate, data_flow, naming_convention, dependency_direction,
layer_boundary, size_limit, complexity_limit.

4-stage pipeline: InvariantDetector → ConstraintSynthesizer → ConstraintStore →
ConstraintVerifier. AST-based verification (not regex — replaces v1's approach).

FreezingArchRule baseline: snapshot constraints at a point in time, fail on regression.
Constraint mining from existing code patterns.

**Lives in**: `drift-analysis/src/structural/constraints/`

### 8.4 Contract Tracking (System 21)

Per 21-CONTRACT-TRACKING-V2-PREP. Multi-protocol API contract verification.

7 paradigms (expanded from v1's REST-only): REST, GraphQL, gRPC, AsyncAPI,
tRPC (TypeScript-only), WebSocket, event-driven (Kafka, RabbitMQ, SNS/SQS, Redis pub/sub).
20+ backend framework extractors, 15+ frontend/consumer libraries.
Schema-first parsing (OpenAPI 3.0/3.1, GraphQL SDL, Protobuf, AsyncAPI 2.x/3.0).
Code-first extraction for frameworks without schema files.

93 v1 features inventoried — all preserved or enhanced. Zero feature loss.

BE↔FE matching via path similarity + schema compatibility scoring.
Breaking change classifier: 20+ change types across 4 severity levels
(breaking, deprecation, compatible, cosmetic), paradigm-specific rules.

7 mismatch types (replacing v1's simple field comparison): field missing, type mismatch,
required/optional mismatch, enum value mismatch, nested shape mismatch, array/scalar
mismatch, nullable mismatch.

Bayesian 7-signal confidence model (replacing v1's 2-signal formula
`score = match×0.6 + field×0.4`): path similarity, field overlap, type compatibility,
response shape match, temporal stability, cross-validation, consumer agreement.

Build estimate: ~12,000 LOC Rust, ~20 weeks across 20 internal phases.

**Lives in**: `drift-analysis/src/structural/contracts/`

### 8.5 Constants & Environment (System 22)

Per 22-CONSTANTS-ENVIRONMENT-V2-PREP. Secret detection + magic numbers + env vars.

13-phase unified pipeline (per §3 architecture):
1. Constant extraction from AST (9+ languages)
2. Magic number detection via AST (replaces v1 regex — scope-aware, context-aware)
3. Secret detection engine (150+ patterns for launch, 7 severity tiers: Critical/High/Medium/Low/Info/FP/Suppressed, with format validation as 3rd confidence signal — AWS AKIA*, GitHub ghp_*)
4. Inconsistency detection (fuzzy name matching, camelCase ↔ snake_case normalization)
5. Dead constant detection via call graph integration
6. Environment variable extraction (9+ languages, 15+ access methods)
7. .env file parsing (dotenv spec: .env, .env.local, .env.production, .env.*.local)
8. Missing variable detection (referenced in code but not in .env)
9. Framework-specific env detection (Next.js NEXT_PUBLIC_*, Vite VITE_*, Django DJANGO_*, Spring)
10. Sensitivity classification (4-tier)
11. Confidence scoring (Bayesian + Shannon entropy)
12. Health score calculation
13. Storage persistence

Shannon entropy scoring for high-entropy string detection (hybrid pattern + entropy
reduces FP vs pattern-only). V1 had 21 patterns across 3 severity tiers; v2 expands
to 150+ patterns across 7 severity tiers with entropy-based scoring and format validation as 3rd confidence signal.

CWE-798 (hardcoded credentials), CWE-321 (hardcoded crypto key),
CWE-547 (hardcoded security-relevant constant) mappings.

**Lives in**: `drift-analysis/src/structural/constants/`

### 8.6 Wrapper Detection (System 23)

Per 23-WRAPPER-DETECTION-V2-PREP. Thin delegation pattern detection.

16 WrapperCategory variants (v1 had 12, v2 adds Middleware, StateManagement split,
Testing, Internationalization): StateManagement, DataFetching, FormHandling, Routing,
Authentication, ErrorBoundary, Caching, Styling, Animation, Accessibility, Logging,
ApiClient, Middleware, Testing, Internationalization, Other.

8 framework detection patterns with 150+ primitive function signatures across 8 frameworks
(React, Vue, Angular, Svelte, SolidJS, Express, Next.js, TanStack Query).

Enhanced 7-signal confidence model (v1 used 5-signal base 0.6 + adjustments):
import match, name match, call-site match, export status, usage count, depth analysis,
framework specificity.

Multi-primitive detection: a single function can wrap multiple primitives from the same
category (e.g., auth + RBAC check = composite wrapper).

Wrapper health scoring (new in v2): consistency, coverage, abstraction depth → 0-100
score for quality gate integration.

RegexSet optimization for single-pass multi-pattern primitive matching.

Clustering for wrapper family identification. Security wrapper categories
(auth, validation, sanitization, encryption, access control) feed taint analysis
sanitizer registry.

**Lives in**: `drift-analysis/src/structural/wrappers/`

### 8.7 DNA System (System 24)

Per 24-DNA-SYSTEM-V2-PREP. The capstone metric.

10 gene extractors (6 frontend + 4 backend):
- Frontend: variant-handling, responsive-approach, state-styling, theming,
  spacing-philosophy, animation-approach
- Backend: api-response-format, error-response-format, logging-format, config-pattern

Health scoring formula (exact, per §11):
`healthScore = consistency(40%) + confidence(30%) + mutations(20%) + coverage(10%)`
where consistency = avg consistency across all genes, confidence = avg dominant allele
frequency, mutations = 1 - mutation_penalty, coverage = genes with dominant / total genes.
Output: 0-100 score, clamped.

Mutation detection between snapshots (SHA-256 mutation IDs). Impact classification:
high/medium/low. Configurable thresholds.

4-level AI context builder (per §output): overview (~2K tokens), standard (~6K),
deep (~12K), full (unlimited). Token-efficient AI injection for MCP tools.

RegexSet optimization for single-pass multi-pattern matching: all allele patterns for
a gene compiled into a `RegexSet` (10 genes × ~4 alleles × ~3 patterns = ~120 patterns
matched in a single pass per file, replacing v1's sequential per-pattern scanning).

**Build strategy**: Create the gene extractor framework and 3-4 extractors that depend
only on parsers (naming, imports, type usage, documentation). Add extractors that
depend on Phase 4/5 systems (coupling profile, security posture, test patterns) as
those systems ship. Estimated ~10 days.

**Lives in**: `drift-analysis/src/structural/dna/`

### 8.8 OWASP/CWE Mapping (System 26)

Per 26-OWASP-CWE-MAPPING-V2-PREP. Compliance metadata enrichment.

**Key insight**: This system is enrichment-only — it does NOT detect. It adds CWE/OWASP
metadata to existing findings from upstream detectors. If a CWE has no upstream detector,
the coverage calculator reports it as a gap — it does NOT attempt to detect it.

173 detector → CWE/OWASP mapping matrix. Compile-time `const` registries in Rust
(no runtime loading, no file parsing for base registry; user extensions via TOML).

Every security detector → CWE IDs. OWASP 2025 Top 10 coverage: 10/10 categories.
CWE Top 25 2025 coverage target: 20/25 fully detectable + 5/25 partially (memory safety CWEs — Rust mitigates).

`SecurityFinding` unified type: raw findings from all upstream subsystems (detector
violations, taint flows, secrets, error gaps, boundary violations) enriched with
CWE IDs, OWASP categories, severity, and compliance metadata.

`FindingEnrichmentPipeline`: enrich_detector_violation(), enrich_taint_flow(),
enrich_secret(), enrich_error_gap(), enrich_boundary_violation().

Wrapper → sanitizer bridge: security wrappers (auth, validation, sanitization,
encryption, access control) mapped to taint analysis sanitizer registry, enabling
taint analysis to recognize project-specific wrappers as sanitizers.

Wrapper bypass detection: identifies code paths that skip security wrappers.

Security posture score (composite 0-100). Compliance report generator.
SARIF taxonomy integration.

**Lives in**: `drift-analysis/src/structural/owasp_cwe/`

### 8.9 Cryptographic Failure Detection (System 27) — NET NEW

Per 27-CRYPTOGRAPHIC-FAILURE-DETECTION-V2-PREP. No v1 equivalent.

14 detection categories (per §6-19): WeakHash (MD5, SHA1), DeprecatedCipher (DES, 3DES,
RC4), HardcodedKey, EcbMode, StaticIv, InsufficientKeyLen (<2048 RSA, <256 ECC),
DisabledTls, InsecureRandom, JwtConfusion (alg=none), PlaintextPassword, WeakKdf,
MissingEncryption, CertPinningBypass, NonceReuse.

261 patterns across 12 languages (Python, JS/TS, Java, C#, Go, Ruby, PHP, Kotlin,
Swift, Rust, C/C++, Scala). TOML-based pattern definitions (extensible, user-customizable).

OWASP A04:2025 (Cryptographic Failures) coverage.
CWE-1439 category mapping (30+ member CWEs).

4-factor crypto-specific confidence scoring. Crypto health score calculator.
Remediation suggestion engine.

Build estimate: 5 weeks across 8 internal phases.

**Lives in**: `drift-analysis/src/structural/crypto/`

### 8.10 Phase 5 Verification Gate

Phase 5 is complete when:
- [ ] Coupling analysis produces Martin metrics and detects cycles via Tarjan's SCC
- [ ] Zone classification correctly identifies Zone of Pain / Uselessness / Main Sequence
- [ ] Constraint system verifies at least 6 of 12 invariant types
- [ ] AST-based constraint verification replaces v1 regex approach
- [ ] Contract tracking extracts endpoints from at least 5 REST frameworks
- [ ] Breaking change classifier detects field removal and type changes
- [ ] Secret detection identifies at least 50 pattern types with entropy scoring
- [ ] Magic number detection uses AST context (not regex)
- [ ] Wrapper detection identifies thin delegation patterns across 3+ frameworks
- [ ] DNA system produces health scores from at least 5 gene extractors
- [ ] OWASP/CWE mapping enriches findings with correct CWE IDs
- [ ] Crypto detection identifies weak hash and deprecated cipher usage
- [ ] All results persist to drift.db in their respective tables

---

## 9. Phase 6 — Enforcement (Rules, Gates, Policy, Audit, Feedback)

**Goal**: Build the five Level 3 systems that transform analysis into actionable
pass/fail decisions. This is where Drift goes from "informational" to "actionable."

**Estimated effort**: 2-3 weeks. Partial overlap: Level 0 (Rules Engine + Feedback Loop core), Level 1 (Quality Gates + SARIF), Level 2 (Policy Engine ∥ Audit System), Level 3 (integration).

**Why now**: Enforcement consumes everything from Phases 2-5. It produces the decisions
that presentation (Phase 8) displays. Without enforcement, Drift is a scanner that
finds things but never says "this should fail your build."

### 9.1 Dependency Chain Within Phase 6

```
Patterns + Outliers + Confidence (Phase 3)
    │
    ├→ Rules Engine Evaluator (maps patterns + outliers → violations)
    │    │
    │    ├→ Quality Gates (6 gates consume violations + all Level 2 data)
    │    │    │
    │    │    ├→ Policy Engine (aggregates gate results into pass/fail)
    │    │    │
    │    │    └→ Audit System (tracks health over time)
    │    │
    │    └→ Violation Feedback Loop (tracks developer actions on violations)
```

### 9.2 Rules Engine Evaluator

Pattern matcher → violations → severity assignment → quick fixes.
7 fix strategies: add import, rename, extract function, wrap in try/catch,
add type annotation, add test, add documentation.

Maps detected patterns + outliers to actionable violations with file/line/column
locations, severity levels (error/warning/info/hint), and auto-fix suggestions.

> **Spec coverage note**: Implemented within each gate's evaluate() method. See 09-QG-V2-PREP §5, §18, §24.

**Lives in**: `drift-analysis/src/enforcement/rules/`

### 9.3 Quality Gates (System 09)

Per 09-QUALITY-GATES-V2-PREP. The CI/CD enforcement layer.

6 gates:
1. Pattern compliance (are approved patterns followed?)
2. Constraint verification (are architectural constraints met?)
3. Security boundaries (are sensitive fields protected?)
4. Test coverage (is coverage above threshold?)
5. Error handling (are errors properly handled?)
6. Regression detection (has health score declined?)

DAG-based gate orchestrator (gates can depend on other gates).
7 reporters: SARIF 2.1.0, GitHub Code Quality, GitLab Code Quality, JUnit XML,
HTML, JSON, console. SonarQube Generic Issue Format (P2, post-launch).

Progressive enforcement: warn → error over time, configurable ramp-up.
New-code-first enforcement (SonarQube "Clean as You Code" pattern).

**Build the SARIF reporter early** — it's the key to GitHub Code Scanning integration
and the single most important output format for enterprise adoption.

**Lives in**: `drift-analysis/src/enforcement/gates/`

### 9.4 Policy Engine

4 built-in policies: strict, standard, lenient, custom.
4 aggregation modes: all-must-pass, any-must-pass, weighted, threshold.
Progressive enforcement ramp-up for new projects.

> **Spec coverage note**: Fully specified in 09-QG-V2-PREP §7. No separate spec needed.

**Lives in**: `drift-analysis/src/enforcement/policy/`

### 9.5 Audit System (System 25)

Per 25-AUDIT-SYSTEM-V2-PREP. The "your codebase is drifting" signal.

5-factor health scoring with configurable weights (defaults per §Phase 6, plan empirical validation via telemetry post-launch):
`health_score = (avgConfidence × 0.30 + approvalRatio × 0.20 + complianceRate × 0.20
+ crossValidationRate × 0.15 + duplicateFreeRate × 0.15) × 100`

Three-tier Jaccard duplicate detection thresholds:
- >0.95: auto-merge (safe to merge automatically)
- >0.90: recommend merge
- 0.85-0.90: needs human review

Degradation detection: health score declining over time, warning at -5 points / -5%
confidence, critical at -15 points / -15% confidence.

V2 additions (not in v1):
- Trend prediction via linear regression on `health_trends` table
- Anomaly detection via Z-score on audit metrics (health score, avg confidence,
  compliance rate, duplicate count)
- Per-category health breakdown (health scores per pattern category, 16 categories)
- Auto-merge threshold upgraded from 0.9 to 0.95
- Bayesian confidence integration (uses posterior instead of static confidence)

Auto-approve patterns meeting stability criteria (confidence ≥ 0.90, outlierRatio ≤ 0.50,
locations ≥ 3, no error-level issues).

**Lives in**: `drift-analysis/src/enforcement/audit/`

### 9.6 Violation Feedback Loop (System 31)

Per 31-VIOLATION-FEEDBACK-LOOP-V2-PREP. Self-healing analysis quality.

Tricorder-style false-positive tracking per detector. Metrics: FP rate, dismissal rate,
action rate. Auto-disable rule: >20% FP rate sustained for 30+ days → detector disabled.

Feeds back into confidence scoring (dismissed violations reduce pattern confidence).
Inline suppression system (`drift-ignore` comments).

**Lives in**: `drift-analysis/src/enforcement/feedback/`

### 9.7 Phase 6 Verification Gate

Phase 6 is complete when:
- [ ] Rules engine maps patterns + outliers to violations with severity and quick fixes
- [ ] All 6 quality gates evaluate correctly against test data
- [ ] DAG orchestrator respects gate dependencies
- [ ] SARIF 2.1.0 reporter produces valid SARIF with CWE/OWASP taxonomies
- [ ] Progressive enforcement transitions from warn → error correctly
- [ ] Policy engine aggregates gate results in all 4 modes
- [ ] Audit system computes 5-factor health score
- [ ] Degradation detection fires when health declines beyond threshold
- [ ] Feedback loop tracks FP rate and auto-disables noisy detectors
- [ ] All enforcement data persists to drift.db
- [ ] NAPI exposes `drift_check()` and `drift_audit()` to TypeScript


---

## 10. Phase 7 — Advanced & Capstone (Simulation, Decisions, Context, N+1)

**Goal**: Build the four Level 4 systems. These are high-value features built on top
of the full stack. Impressive but they're leaves — nothing else depends on them.

**Estimated effort**: 6-8 weeks with 4 parallel developers (bounded by Decision Mining at ~8 weeks). Per-system: Simulation ~6w, Decision Mining ~8w, Context Gen ~7w, N+1 ~2w. Fully parallelizable (all four are independent).

**Why now**: They consume the complete analysis stack (Phases 2-6) but nothing depends
on them. They can be built in any order, by different contributors, or deferred entirely
without affecting the core product.

### 10.1 Simulation Engine (System 28)

Per 28-SIMULATION-ENGINE-V2-PREP. Pre-flight speculative execution.

13 task categories: add feature, fix bug, refactor, migrate framework, add test,
security fix, performance optimization, dependency update, API change, database
migration, config change, documentation, infrastructure.

4 scorers: complexity, risk (blast radius + sensitivity), effort (LOC estimate +
dependency count), confidence (test coverage + constraint satisfaction).

Monte Carlo simulation for effort estimation with confidence intervals (P10/P50/P90).
15 strategy recommendations.

Hybrid architecture: Rust for heavy computation (impact analysis, pattern matching,
call graph traversal, coupling friction), TypeScript for orchestration (approach
generation, composite scoring, tradeoff generation, recommendation).

**Lives in**: `drift-analysis/src/advanced/simulation/` (Rust) +
`packages/drift/src/simulation/` (TS orchestration)

### 10.2 Decision Mining (System 29)

Per 29-DECISION-MINING-V2-PREP. Institutional knowledge extraction.

`git2` crate integration for commit history analysis. ADR detection in markdown files.
12 decision categories. Temporal correlation with pattern changes.

Hybrid Rust/TypeScript split: Rust for git2 high-performance pipeline and commit
analysis, TypeScript for ADR synthesis (AI-assisted).

**Lives in**: `drift-analysis/src/advanced/decisions/` (Rust) +
`packages/drift/src/decisions/` (TS)

### 10.3 Context Generation (System 30)

Per 30-CONTEXT-GENERATION-V2-PREP. AI-optimized context for MCP tools.

15 package manager support. Token budgeting with model-aware limits.
Intent-weighted context selection (different context for "fix bug" vs "add feature"
vs "understand code" vs "security audit").

Three-layer context depth: overview (~2K tokens), standard (~6K), deep (~12K).
Session-aware context deduplication (30-50% token savings on follow-ups).
Strategic content ordering (primacy-recency for transformer attention).

**Lives in**: `drift-analysis/src/advanced/context/`

### 10.4 N+1 Query Detection

Call graph + ORM pattern matching → loop-query anti-pattern detection.
8 ORM frameworks: ActiveRecord, Django ORM, SQLAlchemy, Hibernate, Entity Framework,
Prisma, Sequelize, TypeORM. GraphQL N+1 resolver detection.

Implementation split: detection logic in ULP (`n_plus_one.rs`), GraphQL N+1 in
contract tracking.

**Lives in**: `drift-analysis/src/language_provider/n_plus_one.rs`

### 10.5 Phase 7 Hybrid Architecture Risks

Simulation Engine and Decision Mining use hybrid Rust/TypeScript architectures. Key
integration risks:
- **NAPI v3 boundary**: All cross-language calls go through napi-rs v3. Prefer `async fn`
  over `AsyncTask` in v3 for cleaner ergonomics.
- **Testing strategy**: Rust unit tests for computation, TypeScript integration tests for
  orchestration, cross-boundary tests for serialization correctness.
- **Serialization overhead**: Measure serde_json serialization time for large result sets
  (simulation approaches, decision histories). Budget <5ms per NAPI call.
- **Lifecycle**: TypeScript orchestration layer must handle Rust panics gracefully
  (`panic = "abort"` means process termination — catch errors before they panic).

### 10.6 Phase 7 Verification Gate

Phase 7 is complete when:
- [ ] Simulation engine generates approaches for at least 5 task categories
- [ ] Monte Carlo produces P10/P50/P90 confidence intervals
- [ ] Decision mining extracts decisions in at least 5 of 12 categories
- [ ] ADR detection finds Architecture Decision Records in markdown
- [ ] Context generation produces token-budgeted output for 3 depth levels, token count within 5% of configured budget
- [ ] Intent-weighted scoring produces different context for different intents
- [ ] N+1 detection identifies loop-query patterns in at least 3 ORM frameworks
- [ ] Context gen <100ms full pipeline
- [ ] NAPI exposes Phase 7 functions
- [ ] All results persist to drift.db

---

## 11. Phase 8 — Presentation (MCP, CLI, CI Agent, Reporters)

**Goal**: Build the Level 5A presentation systems that make Drift usable. These are
how humans and AI agents consume Drift's analysis.

**Estimated effort**: 4-5 weeks for Phase 8 gate (MCP core + CLI + CI Agent). Full MCP completion: ~7 weeks per V2-PREP. Parallelizable (MCP, CLI, CI Agent are independent).

**Why now**: Everything from Phases 0-7 produces data in drift.db. Presentation systems
read that data and expose it through different interfaces. They're pure consumers.

### 11.1 MCP Server (System 32)

Per 32-MCP-SERVER-V2-PREP. How AI agents consume Drift.
MCP spec 2025-11-25 (adds CIMD, XAA, mandatory PKCE).

Split architecture: drift-analysis (~52 analysis tools: 3 MCP entry points + 49 via dispatch) vs drift-memory
(~33 memory tools: 3 entry points + 30 via dispatch, bridge-dependent, Phase 9). Progressive disclosure reduces token overhead ~81%.

Progressive disclosure with 3 entry points:
1. `drift_status` — overview, reads `materialized_status`, <1ms
2. `drift_context` — deep dive, intent-weighted, replaces 3-5 calls
3. `drift_scan` — trigger analysis

stdio transport (primary) + Streamable HTTP transport (Docker/containerized).
Token budgeting via `McpConfig.max_response_tokens` (default 8000).

**Lives in**: `packages/drift-mcp/`

### 11.2 CLI

48-65+ commands: `drift scan`, `drift check`, `drift status`, `drift patterns`,
`drift violations`, `drift impact`, `drift simulate`, `drift audit`, `drift setup`,
`drift doctor`, `drift export`, `drift explain`, `drift fix`.

Setup wizard for first-time configuration. `drift doctor` health checks.
Multiple output formats (table, JSON, SARIF).

**Spec when**: Start of Phase 8. No V2-PREP yet — pure consumer of NAPI, no novel
algorithms. The CLI is a thin wrapper around NAPI calls with output formatting.

**Lives in**: `packages/drift-cli/`

### 11.3 CI Agent & GitHub Action (System 34)

Per 34-CI-AGENT-GITHUB-ACTION-V2-PREP. Automated enforcement in CI/CD.

9 parallel analysis passes: scan, patterns, call graph, boundaries, security, tests,
errors, contracts, constraints.

PR-level incremental analysis (only changed files + transitive dependents).
SARIF upload to GitHub Code Scanning. PR comment generation.
Configurable fail conditions via policy engine.

**Lives in**: `packages/drift-ci/`

### 11.4 Quality Gate Reporters

8 output formats: SARIF 2.1.0, GitHub Code Quality, GitLab Code Quality, JUnit XML,
HTML, JSON, console, SonarQube Generic Issue Format (P2, post-launch). SARIF includes CWE + OWASP taxonomies.

**Note**: The SARIF reporter should be built in Phase 6 alongside quality gates (it's
the key to GitHub Code Scanning integration). The remaining 6 reporters can be built
here in Phase 8.

**Lives in**: `drift-analysis/src/enforcement/reporters/`

### 11.5 Phase 8 Verification Gate

Phase 8 is complete when:
- [ ] MCP server registers all drift-analysis tools via stdio transport
- [ ] `drift_status` returns overview in <1ms
- [ ] `drift_context` produces intent-weighted context with token budgeting
- [ ] CLI `drift scan` + `drift check` work end-to-end
- [ ] CI agent runs 9 analysis passes on a PR diff
- [ ] SARIF upload to GitHub Code Scanning succeeds
- [ ] PR comment generation produces readable summaries
- [ ] All 8 reporter formats produce valid output

---

## 12. Phase 9 — Bridge & Integration (Cortex-Drift Bridge, Grounding Loop)

**Goal**: Build the optional integration layer that connects Drift to Cortex. This is
architecturally a leaf (D4) but the killer product feature (D7).

**Estimated effort**: 3-5 weeks (1 dev), 2-3 weeks (2 devs). V2-PREP shows 8 internal phases totaling ~21-26 working days.

**Why last (for Drift)**: Per D1, Drift is complete without this. Per D4, nothing in
Drift depends on the bridge. The bridge depends on the complete Drift stack producing
clean data. Building it earlier means building against an unstable API.

### 12.1 Cortex-Drift Bridge (System 34)

Per 34-CORTEX-DRIFT-BRIDGE-V2-PREP. The only place both systems meet.

6 responsibilities:
1. **Event mapping**: Drift events → Cortex memories (21 event types, per §6.1)
   - `on_pattern_approved` → `PatternRationale` memory (confidence 0.8)
   - `on_pattern_discovered` → `Insight` memory (confidence 0.5)
   - `on_pattern_ignored` → `Feedback` memory (confidence 0.6)
   - `on_pattern_merged` → `DecisionContext` memory (confidence 0.7)
   - `on_scan_complete` → triggers grounding loop (no memory created)
   - `on_regression_detected` → `DecisionContext` memory (confidence 0.9)
   - `on_violation_detected` → no memory (too noisy)
   - `on_violation_dismissed` → `ConstraintOverride` memory (confidence 0.7)
   - `on_violation_fixed` → `Feedback` memory (confidence 0.8)
   - `on_gate_evaluated` → `DecisionContext` memory (confidence 0.6)
   - `on_detector_alert` → `Tribal` memory (confidence 0.6)
   - `on_detector_disabled` → `CodeSmell` memory (confidence 0.9)
   - `on_constraint_approved` → `ConstraintOverride` memory (confidence 0.8)
   - `on_constraint_violated` → `Feedback` memory (confidence 0.7)
   - `on_decision_mined` → `DecisionContext` memory (confidence 0.7)
   - `on_decision_reversed` → `DecisionContext` memory (confidence 0.8)
   - `on_adr_detected` → `DecisionContext` memory (confidence 0.9)
   - `on_boundary_discovered` → `Tribal` memory (confidence 0.6)
   - `on_enforcement_changed` → `DecisionContext` memory (confidence 0.8)
   - `on_feedback_abuse_detected` → `Tribal` memory (confidence 0.7)
   - `on_error` → no memory (logged only)
2. **Link translation**: Drift `PatternLink` → Cortex `EntityLink` (per D2)
   - 5 EntityLink constructors: from_pattern, from_constraint, from_detector,
     from_module, from_decision
3. **Grounding logic**: Compare Cortex memories against Drift scan results
4. **Grounding feedback loop**: The killer feature (D7)
5. **Intent extensions**: 10 code-specific intents registered as Cortex extensions
   (add_feature, fix_bug, refactor, review_code, debug, understand_code,
   security_audit, performance_audit, test_coverage, documentation)
6. **Combined MCP tools**: `drift_why`, `drift_memory_learn`, `drift_grounding_check`

### 12.2 Grounding Feedback Loop (D7)

The most valuable piece of the integration. No other AI memory system has this.

The loop:
1. Cortex stores a memory: "Team uses repository pattern for data access"
2. Drift scans and independently finds: 87% repository pattern usage
3. Bridge compares: memory is 87% grounded (high confidence justified)
4. Team refactors away from repository pattern
5. Next scan: only 45% repository pattern
6. Bridge detects drift: memory confidence should decrease
7. Cortex validation engine heals the memory or creates a contradiction

**Why this matters**: First AI memory system with empirically validated memory.
Beliefs checked against ground truth. Self-correcting without human intervention.

### 12.2.1 Groundability Classification (per §16)

13 of 23 Cortex memory types are groundable against Drift scan data:
- **Fully groundable** (6): PatternRationale, ConstraintOverride, DecisionContext,
  CodeSmell, Core, Semantic
- **Partially groundable** (7): Tribal, Decision, Insight, Entity, Feedback,
  Incident, Environment
- **Not groundable** (10): Procedural, Episodic, Reference, Preference, AgentSpawn,
  Goal, Workflow, Conversation, Meeting, Skill

### 12.2.2 Grounding Scheduling (per §17)

| Trigger | Scope | Frequency |
|---------|-------|-----------|
| Post-scan (incremental) | Affected memories only | Every scan |
| Post-scan (full) | All groundable memories | Every 10th scan |
| Scheduled | All groundable memories | Daily (configurable) |
| On-demand (MCP) | Specified memories | User-triggered |
| Memory creation | New memory only | On creation |
| Memory update | Updated memory only | On update |

Max 500 memories per grounding loop. Grounding score thresholds:
Validated ≥ 0.7, Partial ≥ 0.4, Weak ≥ 0.2, Invalidated < 0.2.

### 12.2.3 Evidence Weight Calibration (per §15)

10 evidence types with weights: PatternConfidence, PatternOccurrence, FalsePositiveRate,
ConstraintVerification, CouplingMetric, DnaHealth, TestCoverage, ErrorHandlingGaps,
DecisionEvidence, BoundaryData.

Confidence adjustment parameters: boost_delta=0.05, partial_penalty=0.05,
weak_penalty=0.15, invalidated_floor=0.1, contradiction_drop=0.3.

### 12.2.4 Bridge-Specific Storage (per §27)

4 bridge-specific SQLite tables:
1. `bridge_grounding_results` — one row per memory per grounding check (retention: 90 days Community, unlimited Enterprise)
2. `bridge_grounding_snapshots` — one row per grounding loop execution (retention: 365 days)
3. `bridge_event_log` — one row per event processed (retention: 30 days)
4. `bridge_metrics` — rolling window metrics (retention: 7 days)

### 12.2.5 NAPI Bridge Interface (per §21)

15 NAPI functions in cortex-drift-napi:
`bridge_initialize`, `bridge_shutdown`, `bridge_is_available`, `bridge_ground_memory`,
`bridge_ground_all`, `bridge_get_grounding_snapshot`, `bridge_get_grounding_history`,
`bridge_translate_links`, `bridge_memories_for_pattern`, `bridge_patterns_for_memory`,
`bridge_why`, `bridge_learn`, `bridge_grounding_check`, `bridge_get_metrics`,
`bridge_register_event_handler`.

### 12.2.6 License Gating (per §23)

3-tier license gating for bridge features:
- Community: event mapping (5 event types), basic grounding (manual only)
- Team: full event mapping (all 21 types), scheduled grounding, MCP tools
- Enterprise: full grounding loop, contradiction generation, cross-DB analytics

### 12.3 Database Integration

Per D6: `ATTACH DATABASE 'cortex.db' AS cortex READ ONLY`.
Cross-DB reads are same speed as same-DB reads. Indexes work across the boundary.
If cortex.db doesn't exist, ATTACH fails gracefully and bridge tools don't register.

### 12.4 Phase 9 Verification Gate

Phase 9 is complete when:
- [ ] Bridge crate compiles with both drift-core and cortex-core as dependencies
- [ ] Event mapping creates correct Cortex memory types from Drift events
- [ ] Link translation produces valid EntityLink from PatternLink
- [ ] Grounding logic computes grounding percentage for pattern memories
- [ ] Grounding feedback loop adjusts Cortex memory confidence based on scan results
- [ ] `drift_why` synthesizes pattern data + causal memory
- [ ] `drift_memory_learn` creates memory from Drift analysis
- [ ] ATTACH cortex.db works for cross-DB queries
- [ ] Graceful degradation when cortex.db doesn't exist

---

## 13. Phase 10 — Polish & Ship (Workspace, Licensing, Docker, Telemetry, IDE)

**Goal**: Build the remaining cross-cutting and presentation systems needed for a
shippable product. These are Level 6 infrastructure and lower-priority Level 5 systems.

**Estimated effort**: 4-6 weeks (5+ devs), 8-10 weeks (3 devs), 22-28 weeks (1 dev). Highly parallelizable.

P0 (ship-blocking): Workspace Management, Licensing, Docker.
P1 (high-value): VSCode Extension, LSP Server, AI Providers.
P2 (nice-to-have): Dashboard, Galaxy, Telemetry, CIBench.

### 13.1 Workspace Management (System 33)

Per 33-WORKSPACE-MANAGEMENT-V2-PREP. First thing that runs on every interaction.

drift.db lifecycle (create, open, migrate, backup, vacuum). Workspace detection.
`drift setup` wizard. `drift doctor` health checks. Hot backup via SQLite Backup API.
Process-level locking via `fd-lock`. Monorepo workspace detection.

**Note**: While this is "first thing that runs," the workspace management logic is
simple enough to stub during Phases 1-8 (just create drift.db with correct PRAGMAs).
The full workspace management system with backup, health checks, and monorepo support
is polish, not critical path.

### 13.2 Licensing & Feature Gating

3 tiers: Community (free, core analysis), Team (advanced + CI),
Enterprise (full stack + OWASP compliance + telemetry + blake3 + OpenTelemetry).
16 gated features. JWT validation. Graceful degradation.

### 13.3 Docker Deployment

Multi-arch Alpine images (amd64 + arm64). Pre-built native binaries.
HTTP/SSE MCP transport for containerized deployment.

### 13.4 Telemetry

Cloudflare Worker + D1 backend. Anonymous usage metrics. Opt-in only.

### 13.5 IDE Integration

VSCode Extension: inline violation highlighting, quick fix suggestions, pattern
explorer sidebar, health score status bar.

LSP Server: IDE-agnostic diagnostics, code actions, hover information.

Dashboard: Web visualization (Vite + React + Tailwind).

Galaxy: 3D codebase visualization (Three.js). Lowest priority.

### 13.6 AI Providers

Anthropic, OpenAI, Ollama abstraction layer. Powers `drift explain` and `drift fix`.
Stays in TypeScript.

### 13.7 CIBench

4-level benchmark framework: micro (criterion), component (integration), system
(end-to-end), regression (CI). Isolated in `drift-bench` crate.

### 13.8 Phase 10 Verification Gate

Phase 10 is complete when:
- [ ] `drift setup` wizard creates drift.toml and drift.db correctly
- [ ] `drift doctor` detects and reports common configuration issues
- [ ] Hot backup via SQLite Backup API completes for 100MB database in <5s
- [ ] `fd-lock` prevents concurrent drift.db access from multiple processes
- [ ] License validation correctly gates features per tier (Community/Team/Enterprise)
- [ ] Graceful degradation when license is missing or expired
- [ ] Docker multi-arch images (amd64 + arm64) build and run correctly
- [ ] HTTP/SSE MCP transport works in containerized deployment
- [ ] VSCode extension displays inline violations and quick fix suggestions
- [ ] LSP server provides diagnostics and code actions to non-VSCode editors
- [ ] CIBench 4-level benchmarks run in CI without regression
- [ ] All Phase 10 systems persist configuration to drift.db


---

## 14. Cross-Phase Dependency Matrix

This matrix shows exactly which phases each system depends on. If a cell is marked,
that phase must be complete before the system can be built.

```
System                          | P0 | P1 | P2 | P3 | P4 | P5 | P6 | P7 | P8 | P9
--------------------------------|----|----|----|----|----|----|----|----|----|----|
Configuration                   | ·  |    |    |    |    |    |    |    |    |
thiserror                       | ·  |    |    |    |    |    |    |    |    |
tracing                         | ·  |    |    |    |    |    |    |    |    |
DriftEventHandler               | ·  |    |    |    |    |    |    |    |    |
String Interning                | ·  |    |    |    |    |    |    |    |    |
Scanner                         | ·  | ·  |    |    |    |    |    |    |    |
Parsers                         | ·  | ·  |    |    |    |    |    |    |    |
Storage                         | ·  | ·  |    |    |    |    |    |    |    |
NAPI Bridge                     | ·  | ·  |    |    |    |    |    |    |    |
Unified Analysis Engine         | ·  | ·  | ·  |    |    |    |    |    |    |
Call Graph Builder              | ·  | ·  | ·  |    |    |    |    |    |    |
Detector System                 | ·  | ·  | ·  |    |    |    |    |    |    |
Boundary Detection              | ·  | ·  | ·  |    |    |    |    |    |    |
Unified Language Provider       | ·  | ·  | ·  |    |    |    |    |    |    |
Pattern Aggregation             | ·  | ·  | ·  | ·  |    |    |    |    |    |
Bayesian Confidence             | ·  | ·  | ·  | ·  |    |    |    |    |    |
Outlier Detection               | ·  | ·  | ·  | ·  |    |    |    |    |    |
Learning System                 | ·  | ·  | ·  | ·  |    |    |    |    |    |
Reachability Analysis           | ·  | ·  | ·  |    | ·  |    |    |    |    |
Taint Analysis                  | ·  | ·  | ·  |    | ·  |    |    |    |    |
Error Handling Analysis         | ·  | ·  | ·  |    | ·  |    |    |    |    |
Impact Analysis                 | ·  | ·  | ·  |    | ·  |    |    |    |    |
Test Topology                   | ·  | ·  | ·  |    | ·  |    |    |    |    |
Coupling Analysis               | ·  | ·  | ·  |    |    | ·  |    |    |    |
Constraint System               | ·  | ·  | ·  | ·  | ·  | ·  |    |    |    |
Contract Tracking               | ·  | ·  | ·  |    |    | ·  |    |    |    |
Constants & Environment         | ·  | ·  | ·  |    |    | ·  |    |    |    |
Wrapper Detection               | ·  | ·  | ·  |    |    | ·  |    |    |    |
DNA System                      | ·  | ·  | ·  | ·  | ·  | ·  |    |    |    |
OWASP/CWE Mapping               | ·  | ·  | ·  |    | ·  | ·  |    |    |    |
Crypto Failure Detection        | ·  | ·  | ·  |    |    | ·  |    |    |    |
Rules Engine                    | ·  | ·  | ·  | ·  |    |    | ·  |    |    |
Quality Gates                   | ·  | ·  | ·  | ·  | ·  | ·  | ·  |    |    |
Policy Engine                   | ·  | ·  | ·  | ·  | ·  | ·  | ·  |    |    |
Audit System                    | ·  | ·  | ·  | ·  | ·  | ·  | ·  |    |    |
Violation Feedback Loop         | ·  | ·  | ·  | ·  |    |    | ·  |    |    |
Simulation Engine               | ·  | ·  | ·  | ·  | ·  | ·  |    | ·  |    |
Decision Mining                 | ·  | ·  | ·  |    |    |    |    | ·  |    |
Context Generation              | ·  | ·  | ·  | ·  | ·  | ·  |    | ·  |    |
N+1 Query Detection             | ·  | ·  | ·  |    |    |    |    | ·  |    |
MCP Server                      | ·  | ·  |    |    |    |    |    |    | ·  |
CLI                             | ·  | ·  |    |    |    |    |    |    | ·  |
CI Agent & GitHub Action        | ·  | ·  |    |    |    |    | ·  |    | ·  |
Reporters (non-SARIF)           | ·  | ·  |    |    |    |    | ·  |    | ·  |
Cortex-Drift Bridge             | ·  | ·  | ·  | ·  | ·  | ·  | ·  |    |    | ·
Workspace Management            | ·  | ·  |    |    |    |    |    |    |    |
Licensing                       | ·  |    |    |    |    |    |    |    |    |
Docker                          | ·  | ·  |    |    |    |    |    |    | ·  |
Telemetry                       | ·  |    |    |    |    |    |    |    |    |
VSCode Extension                | ·  | ·  |    |    |    |    |    |    | ·  |
LSP Server                      | ·  | ·  |    |    |    |    |    |    | ·  |
Dashboard                       | ·  | ·  |    |    |    |    |    |    |    |
Galaxy                          | ·  | ·  |    |    |    |    |    |    |    |
AI Providers                    | ·  |    |    |    |    |    |    |    |    |
CIBench                         | ·  | ·  | ·  |    |    |    |    |    |    |
```

Legend: `·` = depends on this phase. Empty = no dependency.

> **Note on N+1 Query Detection**: Basic N+1 works with P2 ORM matchers. Advanced ORM
> coverage improves with P5 ULP matchers (soft/optional dependency, not required for core functionality).

---

## 15. Parallelization Map (What Can Run Simultaneously)

This is the maximum parallelism available at each phase. Use this to plan team
allocation and identify the critical path.

### Phase 0: Sequential (1 track)
Everything depends on everything else here. Config → errors → tracing → events → data structures.
One developer, 1-2 weeks.

### Phase 1: Sequential (1 track)
Scanner → Parsers → Storage → NAPI. Each system's output is the next system's input.
One developer, 2-3 weeks. Two developers can overlap (one on scanner+parsers, one on storage+NAPI).

### Phase 2: 2 parallel tracks
**Track A**: Unified Analysis Engine + Detector System (tightly coupled)
**Track B**: Call Graph Builder + Boundary Detection + Unified Language Provider
These converge at Phase 3.

> ⚠️ **Realistic Build Estimates from V2-PREP Documents**:
> - UAE full pipeline: 22-27 weeks across 7 internal phases (core pipeline Weeks 1-3,
>   visitor engine Weeks 3-5, GAST Weeks 5-8, core analyzers Weeks 8-12, ULP Weeks 12-15,
>   advanced Weeks 15-18, per-language analyzers Weeks 18-22). Only the core pipeline +
>   visitor engine (Weeks 1-5) are needed for Phase 2 deliverables.
> - Scanner: ~1,700 LOC, 6-9 days
> - Call Graph: 8 internal phases
> - Contract Tracking: ~12,000 LOC Rust, ~20 weeks across 20 internal phases
> - DNA System: ~10 days
> - Audit System: ~10 days
> - Crypto Detection: 5 weeks across 8 internal phases
>
> The Phase 2 "3-4 weeks" estimate covers the minimum viable deliverables. The full
> UAE/detector porting effort continues through Phases 3-5 in parallel.

### Phase 3: Limited parallelism (1-2 tracks)
Pattern Aggregation must come first. Then Confidence Scoring. Then Outlier Detection
and Learning System can be parallel. Internal dependency chain limits parallelism.

### Phase 4: 5 parallel tracks (maximum parallelism)
Reachability, Taint, Error Handling, Impact, Test Topology — all independent.
This is the widest parallelization opportunity. 5 developers can work simultaneously.

### Phase 5: 5 immediate + 3 delayed tracks (maximum parallelism)
Coupling, Contracts, Constants, Wrappers, Crypto — 5 immediate tracks (no Phase 4 dependency).
Constraints, DNA, OWASP/CWE — 3 delayed tracks starting after Phase 4.
DNA System starts with parser-only extractors, adds others incrementally.
This is the second-widest parallelization opportunity.

### Phase 6: Partial overlap (2-3 tracks)
Level 0: Rules Engine + Feedback Loop core (parallel).
Level 1: Quality Gates + SARIF (depends on Rules Engine).
Level 2: Policy Engine ∥ Audit System (parallel, depend on Gates).
Level 3: Integration testing.

### Phase 7: 4 parallel tracks
Simulation, Decision Mining, Context Generation, N+1 — all independent leaves.

### Phase 8: 3 parallel tracks
MCP Server, CLI, CI Agent — all independent presentation consumers.

### Phase 9: Sequential (1 track)
Bridge crate is a single system. One developer.

### Phase 10: 6 immediate + 3 delayed tracks
6 immediate tracks (Workspace, Licensing, Telemetry, Dashboard, Galaxy, CIBench) + 3 delayed tracks (Docker, VSCode, LSP require Phase 8). VSCode↔LSP share interface dependency.

### Critical Path (Longest Sequential Chain)

```
Phase 0 (1-2w) → Phase 1 (2-3w) → Phase 2 Track A (2w) → Phase 3 (3-4w) →
Phase 6 (2-3w) → Phase 8 (2w)
= 12-16 weeks optimistic, 16-21 weeks realistic (1.3x overconfidence correction) minimum for a shippable product
```

With parallelism, Phases 4 and 5 run alongside Phase 3 and 6, adding zero time
to the critical path if you have enough developers.

### Team Size Recommendations

| Team Size | Optimistic Timeline | Realistic (1.3x) | Strategy |
|-----------|----------|----------|----------|
| 1 developer | 6-8 months | 8-10 months | Sequential. Phases 0-1-2-3-6-8 first (critical path). Then 4-5-7 for depth. |
| 2 developers | 4-5 months | 5-6.5 months | Dev A: critical path (0-1-2A-3-6). Dev B: 2B-4-5. Converge at Phase 8. |
| 3-4 developers | 3-4 months | 4-5 months | Full parallelism in Phases 4 and 5. Critical path still 12-16 weeks. |
| 5+ developers | 2.5-3 months | 3-4 months | Maximum parallelism. Phases 4+5 complete in 4-6 weeks with 5 tracks. |

---

## 16. Risk Register & Mitigation

### R1: tree-sitter v0.25 Grammar Compatibility
**Risk**: Some language grammars may not be compatible with tree-sitter v0.25.
**Impact**: Blocks Phase 1 for affected languages.
**Mitigation**: Test all 10 grammars against v0.25 in Phase 0. Pin grammar versions
in `build.rs`. If a grammar is incompatible, ship without that language and add it
when the grammar updates.

### R2: napi-rs v3 Maturity
**Risk**: napi-rs v3 (July 2025) is newer than v2. Edge cases in ThreadsafeFunction,
WebAssembly support, or cross-compilation.
**Impact**: Blocks Phase 1 NAPI bridge.
**Mitigation**: The existing cortex-napi uses v2 patterns that map cleanly to v3.
Rolldown and Oxc are already shipping on v3. If v3 has issues, fall back to v2 with
`compat-mode` and migrate later.

### R3: Taint Analysis Complexity (NET NEW)
**Risk**: Taint analysis is the largest net-new system. Interprocedural analysis via
function summaries is algorithmically complex.
**Impact**: Phase 4 taint may take longer than estimated.
**Mitigation**: Ship Phase 1 (intraprocedural) first — it covers the most common
vulnerability patterns (within-function SQL injection, XSS). Phase 2 (interprocedural)
can ship incrementally. Semgrep's open-source taint mode is intraprocedural-only and
still catches most issues.

### R4: SQLite Performance at Scale
**Risk**: 40+ tables, 100K+ file codebases, complex cross-table queries.
**Impact**: Query performance degrades beyond targets.
**Mitigation**: Covering indexes (replaces v1 PatternIndexView), partial indexes
(3-10x smaller), keyset pagination (not OFFSET/LIMIT), WAL mode with 3-tier
checkpoint strategy. The existing Cortex storage layer handles similar scale.
Benchmark early in Phase 1.

### R5: Detector Count (350+)
**Risk**: Building 350+ detectors is a massive effort.
**Impact**: Phase 2 takes much longer than estimated.
**Mitigation**: Start with 50-80 high-value detectors across 5 categories. The
trait-based architecture means adding detectors is mechanical. Ship with core
detectors, add the long tail incrementally. v1 already has many detector
implementations that inform the v2 Rust ports.

### R6: Cross-Language GAST Normalization
**Risk**: Normalizing 10 languages into ~40-50 GAST node types may have edge cases
that produce incorrect cross-language analysis.
**Severity**: Medium-High.
**Impact**: False positives in cross-language detectors.
**Mitigation**: Start with 3-4 well-understood languages (TS/JS, Python, Java).
Add languages incrementally with per-language test suites. Mandatory `coverage_report()`
per language — target ≥85% node coverage for P0 languages. Semgrep's ast_generic
and YASA's UAST provide reference implementations.

### R7: Build Time
**Risk**: 5 crates + tree-sitter grammars + rusqlite bundled = long compile times.
**Impact**: Developer productivity during development.
**Mitigation**: `cargo-nextest` for parallel test execution. `sccache` for shared
compilation cache. Feature flags to compile only needed languages during development.
Release profile separate from dev profile.

### R8: UAE/GAST 22-27 Week Timeline
**Risk**: The Unified Analysis Engine is the single largest system in Drift v2. The
full pipeline (core + visitor + GAST + analyzers + ULP + per-language) spans 22-27 weeks
per 06-UAE-V2-PREP §18. 350+ detectors must be ported from TypeScript to Rust. GAST
normalization requires ~40-50 node types and 10 per-language normalizers.
**Impact**: Phase 2 deliverables ship on time but the full detector suite takes months.
**Mitigation**: Ship core pipeline + 50-80 high-value detectors in Phase 2 (Weeks 1-5).
Continue porting remaining detectors through Phases 3-5 in parallel. The trait-based
architecture means adding detectors is mechanical. Prioritize security, structural,
errors, testing, data-access categories first.

### R9: Contract Tracking Multi-Paradigm Scope
**Risk**: Contract tracking expanded from REST-only (v1) to 7 paradigms (REST, GraphQL,
gRPC, AsyncAPI, tRPC, WebSocket, event-driven). ~12,000 LOC Rust across 20 internal
phases, ~20 weeks estimated.
**Impact**: Phase 5 contract tracking takes significantly longer than other Phase 5 systems.
**Mitigation**: Ship REST + GraphQL first (highest value, most v1 coverage). Add gRPC,
AsyncAPI, tRPC, WebSocket, event-driven incrementally. Schema-first parsing is faster
to implement than code-first extraction.

### R10: macOS APFS Scanner Performance
**Risk**: APFS directory scanning is single-threaded at the kernel level (per
00-SCANNER-V2-PREP §18). Parallel walking helps with per-file work (hashing, metadata)
but not directory enumeration. This is a known limitation shared with ripgrep, fd,
and the `ignore` crate.
**Impact**: Scanner Phase 1 performance targets may be harder to hit on macOS.
**Mitigation**: This is a platform constraint, not a bug. Optimize per-file work
(hashing, metadata) to compensate. Content-hash incremental detection (mtime + xxh3)
minimizes re-scanning. Document the platform difference in performance expectations.

### R11: Cargo Dependency Version Inconsistencies
**Risk**: Bridge V2-PREP doc (34-CORTEX-DRIFT-BRIDGE-V2-PREP §4.2) specifies
`thiserror = "1"` and `rusqlite = "0.31"`, while the workspace Cargo.toml in Phase 0
specifies `thiserror = "2"`, `rusqlite = "0.38"`, `petgraph = "0.8"`, and `tree-sitter = "0.25"`.
**Severity**: Low (workspace dependency inheritance resolves conflicts).
**Impact**: Version mismatch between bridge crate and main workspace causes compilation
errors or trait incompatibilities.
**Mitigation**: The workspace Cargo.toml versions are authoritative. The bridge crate
must use the same versions. Workspace dependency inheritance ensures all crates use
consistent versions. Update bridge Cargo.toml to match workspace pins at build time.

### R17: SQLite Schema Complexity
**Risk**: drift.db grows to 55-65 tables with 180+ total objects (tables, indexes,
views, triggers).
**Impact**: Schema migration and validation overhead increases with each phase.
**Mitigation**: `rusqlite_migration` uses `user_version` (fast integer check). Cache
schema version in memory, skip full validation on match. Only run full migration check
on version mismatch.

### R18: Estimation Overconfidence
**Risk**: ~30% average overrun observed across V2-PREP build estimates.
**Impact**: Delivery timelines slip without buffer.
**Mitigation**: Apply 1.3x multiplier for planning. Critical path 12-16w → 16-21w.
1-dev timeline 6-8mo → 8-10mo. Build phase-level buffers into team commitments.

### R19: NAPI v2→v3 Divergence
**Risk**: Cortex uses napi v2; Drift targets v3 (3.8.x). `ThreadsafeFunction`,
`AsyncTask`, `Function`/`FunctionRef` APIs differ between versions.
**Impact**: Cortex patterns cannot be copied verbatim — adaptation required.
**Mitigation**: Create v2→v3 cheat sheet before Phase 1. Key differences:
ThreadsafeFunction (ownership-based in v3), AsyncTask (prefer `async fn` in v3),
Function/FunctionRef (new types in v3), error handling differences.

### R20: Parallel Dev Coordination
**Risk**: Phases 4-5 offer 5+7 parallel tracks. Communication overhead scales
quadratically with team size.
**Impact**: Integration conflicts, duplicated work, inconsistent patterns.
**Mitigation**: Freeze drift-core types before parallel tracks begin. Assign
integration lead for cross-system interfaces. Cap active parallel developers at
3-4 to balance throughput vs coordination cost.

---

## 17. Unspecced Systems — When to Spec Them

9 systems have no V2-PREP document. Here's when each needs a spec and why it's
safe to defer.

| System | When to Spec | Why Safe to Defer |
|--------|-------------|-------------------|
| **CLI** | Start of Phase 8 | Pure consumer of NAPI. No novel algorithms. The CLI is a thin wrapper around NAPI calls with output formatting. Spec it when you know the full NAPI surface area. |
| **VSCode Extension** | Start of Phase 10 | Editor integration. Depends on LSP + NAPI. The extension is a consumer of diagnostics and code actions. Spec it when the analysis stack is stable. |
| **LSP Server** | Start of Phase 10 | IDE-agnostic. Maps analysis results to LSP diagnostics, code actions, and hover info. Spec it alongside VSCode extension. |
| **Dashboard** | Start of Phase 10 | Web visualization (Vite + React + Tailwind). Pure consumer of drift.db. No novel algorithms. Spec it when you want a visual interface. |
| **Galaxy** | When desired | 3D codebase visualization (Three.js). Stays TS/React. Lowest structural priority. Impressive demo, zero analysis value. |
| **AI Providers** | When explain/fix ships | Anthropic/OpenAI/Ollama abstraction. Stays TS. Only needed for `drift explain` and `drift fix` commands. |
| **Docker** | When containerization ships | Multi-arch Alpine images. Needs HTTP MCP transport (not stdio). Spec it when you need containerized deployment. |
| **Telemetry** | Post-launch | Cloudflare Worker + D1. Opt-in only. Zero impact on analysis. Spec it when you have users to measure. |
| **CIBench** | When benchmarking | 4-level benchmark framework. Isolated crate. Spec it when you need regression benchmarks in CI. |

**Key insight**: None of these 9 systems feed the analysis pipeline. They all consume it.
Deferring their specs has zero impact on the core product. Spec them when their phase
approaches and the NAPI surface area they consume is stable.

---

## 18. Cortex Pattern Reuse Guide

The existing Cortex codebase (21 crates plus test-fixtures in `crates/cortex/`) provides proven patterns
for several Drift systems. Reuse these patterns — the architecture is deliberately
parallel per D1.

| Drift System | Cortex Reference | What to Reuse |
|-------------|-----------------|---------------|
| **Singleton Runtime** | `cortex-napi/src/runtime.rs` | `OnceLock` pattern for `DriftRuntime`. Same lifecycle (init/shutdown). |
| **NAPI Bindings** | `cortex-napi/src/bindings/` (14 modules: causal, cloud, consolidation, generation, health, learning, lifecycle, memory, multiagent, prediction, privacy, retrieval, session, temporal) | Module organization, `#[napi]` patterns, error conversion, `AsyncTask` usage. |
| **SQLite Storage** | `cortex-storage/src/pool/` | Write-serialized + read-pooled pattern. `tokio::sync::Mutex<Connection>` writer in Cortex (async runtime), round-robin `ReadPool`. Drift should use `std::sync::Mutex` since Drift has no async runtime. |
| **Batch Writer** | `cortex-storage/src/queries/` | `crossbeam-channel` bounded queue, dedicated writer thread, `prepare_cached()`. |
| **Health Monitoring** | `cortex-observability/src/health/` | `HealthChecker`, `HealthReporter`, `HealthSnapshot` patterns. Drift's audit system mirrors this. |
| **Degradation Tracking** | `cortex-observability/src/degradation/` | `DegradationTracker`, alert levels, recovery status. Drift's audit degradation mirrors this. |
| **Tarjan's SCC** | `cortex-causal/src/graph/dag_enforcement.rs` | `petgraph::algo::tarjan_scc` usage. Drift's coupling analysis uses the same algorithm. |
| **Similarity Scoring** | `cortex-consolidation/src/algorithms/similarity.rs` | Cosine similarity only. Drift must implement Jaccard from scratch or use a crate. |
| **Deduplication** | `cortex-retrieval/src/ranking/deduplication.rs` | Session-aware dedup patterns. Drift's pattern dedup mirrors this. |
| **Error Types** | `cortex-core/src/errors/` | `thiserror` enum patterns, error conversion traits. |
| **Audit Logging** | `cortex-storage/src/migrations/v006_audit_tables.rs` | Audit table schema, temporal event emission. |
| **NAPI Error Codes** | `cortex-napi/src/conversions/` | Error code conversion patterns, structured error messages. |
| **NAPI Conversions** | `cortex-napi/src/conversions/` (7 per-domain conversion files) | Per-domain type conversion patterns for NAPI boundary. |

**Rule**: Copy patterns, not code. Drift and Cortex are independent (D1). Don't create
a shared utility crate — that violates standalone independence. Instead, implement the
same patterns in drift-core with Drift-specific types.

### NAPI v2→v3 Adaptation Guide

Cortex uses napi v2; Drift targets v3 (3.8.x). Key differences to account for when
adapting Cortex patterns:
- **ThreadsafeFunction**: Ownership-based lifecycle in v3 (no manual ref counting).
- **AsyncTask**: Prefer `async fn` with `#[napi]` in v3 over explicit `AsyncTask` impl.
- **Function/FunctionRef**: New types in v3 replacing v2's `JsFunction` patterns.
- **Error handling**: v3 uses `napi::Error` directly; v2 used `napi::Result` with
  different conversion traits.

Create a v2→v3 cheat sheet before Phase 1 to accelerate NAPI development.

---

## 18.1 Per-Phase Performance Target Summary

Each V2-PREP document specifies detailed performance targets. Key targets by phase:

| Phase | System | Target | Source |
|-------|--------|--------|--------|
| 1 | Scanner | 10K files <300ms (Linux), <500ms (macOS), 100K files <3s cold / <1.5s incremental, incremental <100ms | 00-SCANNER §17 |
| 1 | Parsers | Parse 10K files <5s. Single-pass shared results, Moka LRU cache | 01-PARSERS |
| 1 | Storage | Batch write 500 rows/tx, keyset pagination, WAL mode | 02-STORAGE |
| 1 | NAPI | AsyncTask for >10ms ops, <1ms for sync queries | 03-NAPI |
| 2 | UAE | 10K file codebase analyzed <10s / <15s fallback end-to-end | 06-UAE |
| 2 | Call Graph | Build <5s for 10K files, BFS <5ms, SQLite CTE <50ms / <100ms fallback | 05-CALL-GRAPH |
| 3 | Confidence | 10K patterns scored <500ms | 10-BAYESIAN |
| 4 | Taint | Intraprocedural <1ms/function, interprocedural <100ms/function / <200ms fallback | 15-TAINT |
| 4 | Error Handling | <5ms per file topology construction | 16-ERROR |
| 5 | Coupling | <1s for 5K-module Tarjan SCC + Martin metrics | 19-COUPLING |
| 5 | Crypto | 261 pattern checks per file, short-circuit on import check | 27-CRYPTO |
| 5 | Wrappers | <2ms per file for 150+ pattern RegexSet | 23-WRAPPER |
| 5 | Contracts | Endpoint matching <1ms per pair, schema comparison <5ms | 21-CONTRACTS |
| 6 | Violation Feedback | FP rate <10% overall, with category-specific sub-targets | 31-FEEDBACK |
| 7 | Context Gen | <50ms standard, <100ms full pipeline | 30-CONTEXT |
| 7 | N+1 Detection | <10ms per query site | 08-ULP |
| 8 | MCP | drift_status <1ms, drift_context <100ms / <200ms fallback | 32-MCP |
| 9 | Bridge | Event mapping <5ms, grounding single <50ms, loop 500 <10s | 34-BRIDGE |
| 10 | Workspace | init <500ms, backup <5s for 100MB db | 33-WORKSPACE |

## 18.2 Per-Phase Storage Schema Progression

drift.db tables ship incrementally as each phase delivers:

| Phase | Tables Added | Cumulative |
|-------|-------------|------------|
| 1 | file_metadata, parse_cache, functions (core schema) | ~5-8 |
| 2 | call_edges, data_access, detections, boundaries, patterns | ~15-20 |
| 3 | pattern_confidence (α, β, score columns), outliers, conventions | ~22-25 |
| 4 | reachability_cache, taint_flows, error_gaps, impact_scores, test_coverage | ~30-35 |
| 5 | coupling_metrics, constraints, contracts, constants, secrets, wrappers, dna_genes, crypto_findings, owasp_findings | ~48-56 |
| 6 | violations, gate_results, audit_snapshots, health_trends, feedback | ~55-62 |
| 7 | simulations, decisions, context_cache | ~58-65 |
| 9 | bridge_grounding_results, bridge_grounding_snapshots, bridge_event_log, bridge_metrics (in bridge.db) | +4 bridge |

Full schema: 40+ STRICT tables across 15 domains in drift.db, plus 4 bridge tables.

## 18.3 Per-Phase NAPI Function Count Progression

| Phase | Functions Added | Cumulative | Key Functions |
|-------|---------------|------------|---------------|
| 1 | 3 | 3 | drift_initialize, drift_shutdown, drift_scan |
| 2 | 2-3 | 5-6 | drift_analyze, drift_call_graph, drift_boundaries |
| 3 | 3-4 | 8-10 | drift_patterns, drift_confidence, drift_outliers, drift_conventions |
| 4-5 | 8-12 | 16-22 | Per-system query functions |
| 6 | 3-4 | 19-26 | drift_check, drift_audit, drift_violations, drift_gates |
| 7 | 3-4 | 22-30 | drift_simulate, drift_decisions, drift_context |
| 8 | 5-8 | 27-38 | MCP tool handlers, CI agent functions |
| 9 | 15 | ~55 | bridge_* functions (see §12.2.5) |

Full NAPI surface: ~55 top-level exports across ~14 modules. Note: total per-system functions are ~70-85 when including internal dispatch functions.

---

## 19. Verification Gates (How to Know Each Phase Is Done)

Each phase has a verification gate (defined in the phase sections above). Here's the
meta-verification — how to know the entire build is on track.

### Milestone 1: "It Scans" (End of Phase 1)
You can scan a real codebase, parse every file, persist results, and call it from
TypeScript. This is a working (if minimal) product. ~4-6.5 weeks from start (with 1.3x).

### Milestone 2: "It Detects" (End of Phase 2)
You can detect patterns across 16 categories, build a call graph, and identify data
boundaries. Drift is now a useful analysis tool. ~8-12 weeks from start (with 1.3x).

### Milestone 3: "It Learns" (End of Phase 3)
Run on 3 test repos. Verify: (a) conventions discovered without config, (b) confidence
scores non-trivial, (c) ≥1 convention reaches 'Universal' per repo, (d) ≥1 genuine
outlier flagged per repo. ~12-17 weeks from start (with 1.3x).

### Milestone 4: "It Secures" (End of Phase 4)
Taint analysis, reachability, impact analysis, and test topology are working. Drift
is now enterprise-grade security tooling. ~13-19.5 weeks from start (with 1.3x, parallel with Phase 3).

### Phase 5→6 Precondition Gate

Before starting Phase 6, verify:
- [ ] Coupling metrics computed for ≥3 modules
- [ ] ≥1 constraint passing verification
- [ ] ≥1 API contract tracked
- [ ] DNA profile generated for ≥1 gene

### Milestone 5: "It Enforces" (End of Phase 6)
Quality gates produce pass/fail decisions. SARIF reports upload to GitHub Code Scanning.
Drift is now a CI/CD enforcement tool. ~16-22 weeks from start (with 1.3x).

### Milestone 6: "It Ships" (End of Phase 8)
MCP server, CLI, and CI agent are working. Drift is a shippable product. ~18-24 weeks
from start (with 1.3x).

### Milestone 7: "It Grounds" (End of Phase 9)
Create Cortex memory via bridge. Verify: (a) confidence updated from scan data,
(b) ≥1 grounding result per groundable type (13/23), (c) threshold tiers classify
correctly (≥0.7/≥0.4/≥0.2/<0.2). ~17-25 weeks from start (Phase 9 underestimate).

### Milestone 8: "It's Complete" (End of Phase 10)
All ~55 systems are built. IDE integration, Docker deployment, telemetry, licensing,
and benchmarking are in place. Drift V2 is enterprise-ready. ~18-26 weeks from start
(5+ devs), ~22-30 weeks (3 devs).

---

## Summary

~55 systems. 10 phases. 35 V2-PREP specs (all implementation-ready). 9 unspecced systems
(all presentation/cross-cutting, none blocking analysis). 2 net-new systems (Taint Analysis,
Cryptographic Failure Detection). 7 governing decisions (D1-D7) and 12 architectural
decisions (AD1-AD12) structurally enforced by build order.

Key amendments from V2-PREP cross-reference:
- 21 event types (not 16+) per bridge doc's complete mapping table
- 14 crypto detection categories (not 10) with 261 patterns across 12 languages
- 17 taint sink types (not 9) mapping to 15+ CWEs (added XmlParsing CWE-611, FileUpload CWE-434)
- 7 contract paradigms (not 4): REST, GraphQL, gRPC, AsyncAPI, tRPC, WebSocket, event-driven
- 16 wrapper categories (not 8 patterns) with 7-signal confidence model
- UAE full pipeline is 22-27 weeks across 7 internal phases (core deliverable in Weeks 1-5)
- Contract tracking is ~12,000 LOC / ~20 weeks across 20 internal phases
- 13 of 23 Cortex memory types are groundable against Drift scan data
- 15 bridge NAPI functions, 4 bridge-specific SQLite tables
- 5 new risks added: R8-R11 (UAE timeline, contract scope, macOS APFS, Cargo versions), R17-R20 (schema complexity, estimation overconfidence, NAPI v2→v3, parallel dev coordination)

Key amendments from third audit (V2-PREP exhaustive cross-reference, §20):
- drift-context added as 6th crate (30-CONTEXT-GENERATION specifies separate crate)
- MCP tool counts: ~52 analysis + ~33 memory internal tools (not ~20-25 + ~15-20)
- NAPI total: ~55 functions across 14 modules (§18.3 updated to reflect this)
- 5 new risks added: R12-R16 (tiktoken platform, feedback retention, MCP UX, simulation hybrid, workspace NAPI surface)
- Rules Engine + Policy Engine need spec coverage clarification (covered in 09-QG but listed as separate systems)
- License tier naming: Standardized to Community / Team / Enterprise throughout
- Quality Gates ↔ Violation Feedback circular dependency resolved via FeedbackStatsProvider trait
- Per-system build estimates from V2-PREP docs suggest Phase 7 and Phase 10 may be tighter than estimated
- File numbering conflict: 16-IMPACT-ANALYSIS-V2-PREP.md should be 17-IMPACT-ANALYSIS-V2-PREP.md
- 17 gaps identified, 5 high/medium severity requiring action before implementation starts

The critical path to a shippable product is 15 systems across Phases 0-1-2-3-6-8
(~18-26 weeks for one developer with 1.3x, ~13-18 weeks with two). Everything else adds depth
and breadth but doesn't block shipping.

The maximum parallelism is in Phases 4 (5 tracks) and 5 (7 tracks), where independent
analysis systems can be built simultaneously by different contributors.

The bridge (Phase 9) is the killer feature but architecturally the last thing that
needs to work. Drift ships without it. When it ships, it enables the first AI memory
system with empirically validated memory — beliefs checked against codebase ground truth.

Every phase has a verification gate. Every system has a V2-PREP spec (or a clear
"when to spec" timeline). Every dependency is honored. Every risk is mitigated.

Build it in order. Ship it in phases. Enterprise-grade from day one.

---

## 20. Third Audit — V2-PREP Cross-Reference Gap Analysis

> Generated: 2026-02-08 (Third re-audit)
> Method: Systematic read of all 35 V2-PREP documents cross-referenced against
> this orchestration plan. Gaps categorized by severity.

### 20.1 Crate Structure Discrepancy (RESOLVED)

The orchestration plan §3.1 now specifies a **6-crate** workspace:
`drift-core`, `drift-analysis`, `drift-storage`, `drift-context`, `drift-napi`, `drift-bench`.

`drift-context` isolates context generation dependencies (tiktoken-rs, quick-xml,
serde_yaml, glob, base64) that don't belong in drift-analysis.

### 20.2 File Numbering Conflict (DOCUMENTATION GAP)

Two V2-PREP files share the number 16:
- `16-ERROR-HANDLING-ANALYSIS-V2-PREP.md` — Error Handling Analysis (System 16)
- `16-IMPACT-ANALYSIS-V2-PREP.md` — Impact Analysis (also claims System 16)

The orchestration plan correctly assigns Error Handling = System 16, Impact = System 17.
But the filesystem has `16-IMPACT-ANALYSIS-V2-PREP.md` instead of `17-IMPACT-ANALYSIS-V2-PREP.md`.
The correct `17-IMPACT-ANALYSIS-V2-PREP.md` also exists separately.

**Action**: Verify `16-IMPACT-ANALYSIS-V2-PREP.md` is a duplicate/earlier version of
`17-IMPACT-ANALYSIS-V2-PREP.md` and remove or rename it to avoid confusion.

### 20.3 Missing Per-System NAPI Function Counts (DATA GAP)

The orchestration plan §18.3 gives approximate NAPI function counts per phase but
doesn't reconcile with the specific counts from each V2-PREP doc. Actual counts from
V2-PREP documents:

| System | NAPI Functions | Source |
|--------|---------------|--------|
| Scanner (00) | ~3 (scan lifecycle) | 00-SCANNER §21 |
| Parsers (01) | ~2-3 (parse, cache) | 01-PARSERS |
| Storage (02) | ~3-5 (init, migrate, backup) | 02-STORAGE |
| NAPI Bridge (03) | ~55 total across 14 modules | 03-NAPI §10 |
| Call Graph (05) | ~6-8 | 05-CALL-GRAPH |
| Error Handling (16) | 8 | 16-ERROR-HANDLING §25 |
| Impact Analysis (17) | 8 (all new, 0 in v1) | 17-IMPACT §19 |
| Coupling (19) | 8 (1 command + 7 queries) | 19-COUPLING §24 |
| Constants/Env (22) | 3 | 22-CONSTANTS §27 |
| DNA (24) | 4 (2 from v1 + 2 new) | 24-DNA §20 |
| Audit (25) | 2 | 25-AUDIT §22 |
| Simulation (28) | 11 (5 sim + 4 query + 2 utility) | 28-SIMULATION §20 |
| Context Gen (30) | 3 | 30-CONTEXT §22 |
| Violation Feedback (31) | 8 | 31-FEEDBACK §21 |
| Workspace (33) | 16 | 33-WORKSPACE §19 |
| Bridge (34) | 15 | 34-BRIDGE §21 |

**Total from V2-PREP docs: ~55 functions** (per 03-NAPI-BRIDGE-V2-PREP §10 master registry).
The §18.3 table now reflects ~55 top-level exports.

### 20.4 Missing Per-System Build Estimates (DATA GAP)

The orchestration plan gives phase-level estimates but doesn't include per-system build
estimates from the V2-PREP docs. Key estimates not reflected:

| System | Build Estimate | Source |
|--------|---------------|--------|
| Scanner (00) | ~1,700 LOC, 6-9 days | 00-SCANNER §21 |
| Context Generation (30) | ~7 weeks across 7 phases | 30-CONTEXT §25 |
| Violation Feedback (31) | ~5 weeks across 5 phases | 31-FEEDBACK §27 |
| MCP Server (32) | ~7 weeks across 7 phases | 32-MCP §build |
| Workspace Management (33) | ~5 weeks across 5 phases | 33-WORKSPACE §25 |
| Simulation Engine (28) | ~6 weeks across 8 phases | 28-SIMULATION §32 |
| Cryptographic Detection (27) | ~5 weeks across 8 phases | 27-CRYPTO §44 |
| Coupling Analysis (19) | ~4 phases | 19-COUPLING §31 |
| Outlier Detection (11) | ~4 phases | 11-OUTLIER §23 |

**Impact on timeline**: The Phase 7 estimate of "3-4 weeks" may be optimistic given
that Simulation alone is ~6 weeks and Context Generation is ~7 weeks. These are
parallelizable but the individual system estimates exceed the phase estimate.

Similarly, Phase 10 "4-6 weeks" may be tight given Workspace Management (~5 weeks)
and MCP Server (~7 weeks, though MCP is Phase 8).

### 20.5 Missing Per-System Storage Table Counts (DATA GAP)

The §18.2 schema progression table gives approximate cumulative counts. Actual table
counts from V2-PREP documents that should be verified against the progression:

| System | Tables | Source |
|--------|--------|--------|
| Coupling (19) | 6 tables | 19-COUPLING §24 (module_coupling, coupling_cycles, module_dependencies, coupling_snapshots, coupling_unused_exports, coupling_hotspots) |
| Contract Tracking (21) | 7 tables + 2 snapshot tables | 21-CONTRACT §34 (contracts, contract_operations, contract_types, contract_fields, contract_mismatches, contract_consumers, contract_breaking_changes, contract_snapshots, contract_changes) |
| DNA (24) | 6 tables | 24-DNA §17 (dna_profiles, dna_genes, dna_mutations, dna_evolution, dna_file_cache, dna_comparisons) |
| Audit (25) | 4 tables | 25-AUDIT §21 (audit_snapshots, audit_degradation_log, audit_recommendations, audit_duplicate_groups) |
| Crypto (27) | 3 tables | 27-CRYPTO §38 (crypto_findings, crypto_health, crypto_patterns_registry) |
| Learning (13) | 4 tables | 13-LEARNING §22 (learned_conventions, convention_scan_history, contested_conventions, convention_feedback) |
| Violation Feedback (31) | 5 tables | 31-FEEDBACK §11 (violation_feedback, pattern_suppressions, detector_health, pattern_directory_scores, enforcement_transitions) |
| ULP (08) | 4 tables | 08-ULP §11 (orm_patterns, file_semantics, function_semantics, decorator_cache) |
| MCP Server (32) | 3 tables | 32-MCP §feedback (feedback_examples, feedback_scores, curation_audit) |

**Revised cumulative**: Phase 5 alone adds ~30+ tables from coupling (6) + contracts (9)
+ DNA (6) + crypto (3) + constants/secrets + wrappers + OWASP. The §18.2 estimate has
been updated to ~48-56 cumulative at Phase 5.

### 20.6 Rules Engine & Policy Engine — Unspecced (COVERAGE GAP)

The orchestration plan §9.2 describes the Rules Engine Evaluator and §9.4 describes the
Policy Engine. Neither has a dedicated V2-PREP document. They are partially covered in
09-QUALITY-GATES-V2-PREP.md (§7 Policy Engine, §5 gate implementations that include
rule evaluation), but they are listed as separate systems in the dependency matrix (§14)
and parallelization map (§15).

**Recommendation**: Either:
1. Add them to the "Unspecced Systems" table (§17) with "When to Spec: Start of Phase 6"
2. Or note that they are covered within 09-QUALITY-GATES-V2-PREP.md and are not
   standalone systems requiring separate specs

The Policy Engine is TypeScript-side (per 09-QUALITY-GATES §7: `PolicyLoader` in TS
with YAML/JSON policy files). This should be noted in the orchestration plan since
most Phase 6 systems are Rust-first.

### 20.7 Missing Performance Targets From V2-PREP Docs (DATA GAP)

The §18.1 performance target table is incomplete. Additional targets from V2-PREP docs
not currently listed:

| Phase | System | Target | Source |
|-------|--------|--------|--------|
| 4 | Error Handling (16) | 8-phase topology per file | 16-ERROR §build |
| 4 | Impact Analysis (17) | 8 NAPI functions (all new) | 17-IMPACT §19 |
| 5 | Coupling (19) | Tarjan SCC + Martin metrics | 19-COUPLING §30 |
| 5 | Wrapper Detection (23) | RegexSet single-pass matching | 23-WRAPPER |
| 6 | Violation Feedback (31) | FP rate <10% overall, with category-specific sub-targets | 31-FEEDBACK §6 |
| 7 | Context Generation (30) | <50ms standard, <100ms full pipeline (25x v1) | 30-CONTEXT §perf |
| 10 | Workspace (33) | 16 NAPI functions, 5-week build | 33-WORKSPACE §19 |

### 20.8 Violation Feedback Loop Phase Assignment Clarification (ORDERING GAP)

The orchestration plan places Violation Feedback Loop in Phase 6 (§9.6). However,
31-VIOLATION-FEEDBACK-LOOP-V2-PREP §27 specifies a 5-week internal build order with
dependencies on:
- Bayesian Confidence (10) — Phase 3 (for α/β parameter access)
- Quality Gates (09) — Phase 6 (circular: gates consume FP rates, feedback consumes gate results)

The circular dependency between Quality Gates and Violation Feedback is noted in the
prep doc but not explicitly called out in the orchestration plan. The prep doc resolves
it via the `FeedbackStatsProvider` trait interface.

**Recommendation**: Add a note to §9.1 about the Quality Gates ↔ Violation Feedback
circular dependency and how it's resolved (trait-based interface decoupling).

### 20.9 MCP Server Tool Count Reconciliation (DATA GAP)

The orchestration plan §11.1 says "~52 analysis tools (3 MCP entry points + 49 via dispatch)" for drift-analysis and "~33 memory tools (3 entry points + 30 via dispatch)"
for drift-memory. Progressive disclosure reduces token overhead ~81%.

The progressive disclosure architecture means only 3+3 tools are registered as MCP tools,
but the internal tool catalog is much larger.

### 20.10 Context Generation Crate Dependencies (RESOLVED)

30-CONTEXT-GENERATION-V2-PREP §2 dependencies are now pinned in the workspace Cargo.toml:
`tiktoken-rs = "0.9"`, `quick-xml = "0.37"`, `serde_yaml = "0.9"`, `glob = "0.3"`,
`base64 = "0.22"`. These are isolated in the `drift-context` crate.

### 20.11 License Gating Tiers Inconsistency (MINOR GAP)

The orchestration plan §13.2 mentions 3 tiers: Community, Team, Enterprise.
This matches 31-VIOLATION-FEEDBACK-LOOP-V2-PREP §24 and 04-INFRASTRUCTURE-V2-PREP §license.

**Resolved**: Standardized on "Team" for the middle tier throughout the document.

### 20.12 Workspace Management Build Estimate vs Phase 10 (TIMELINE GAP)

33-WORKSPACE-MANAGEMENT-V2-PREP §25 specifies a 5-week build across 5 phases with
16 NAPI functions. The orchestration plan §13.1 describes it as "simple enough to stub
during Phases 1-8" which is correct for the critical path, but the full system is
substantial. The Phase 10 estimate of "4-6 weeks" for ALL remaining systems may be
tight if Workspace Management alone is 5 weeks.

### 20.13 Missing Risks From V2-PREP Docs (RISK GAP)

The risk register (§16) has R1-R11. Additional risks identified in V2-PREP docs:

**R12: Context Generation tiktoken-rs Platform Compatibility**
Per 30-CONTEXT §risks: tiktoken-rs may fail to initialize on some platforms.
Fallback chain: tiktoken-rs → splintr → character estimation with 20% safety margin.

**R13: Violation Feedback Indefinite Retention**
Per 31-FEEDBACK §risks: violation_feedback and enforcement_transitions tables grow
unbounded. May need archival strategy for very large projects (100K+ violations over years).

**R14: MCP Progressive Disclosure UX**
Per 32-MCP §risks: AI agents must learn the 3-tier pattern (drift_discover → drift_tool).
Some AI clients may not handle dynamic dispatch well. Fallback: register all tools
directly (at the cost of ~7K tokens).

**R15: Simulation Engine Hybrid Architecture**
Per 28-SIMULATION §risks: Hybrid Rust/TypeScript split (Rust for computation, TS for
orchestration) adds cross-boundary complexity. The 11 NAPI functions bridge the gap
but the orchestration layer in TS needs careful design.

**R16: Workspace Management 16 NAPI Functions**
Per 33-WORKSPACE §risks: 16 NAPI functions is the largest single-system NAPI surface
area. Testing all lifecycle operations (init, backup, restore, migrate, lock, gc,
export, import, reset, delete) across platforms is significant.

### 20.14 Missing Event Types in DriftEventHandler (MINOR GAP)

The orchestration plan §3.5 lists 21 event methods. The 31-VIOLATION-FEEDBACK-LOOP-V2-PREP
§12 adds event emission details for feedback-specific events that should be verified
against the 21-event list:
- `on_feedback_recorded` — not in the §3.5 list but implied by the feedback loop
- `on_enforcement_transition` — enforcement mode changes (warn→error) per §10

These may be covered by existing events (`on_enforcement_changed`) but should be
explicitly verified.

### 20.15 CI Agent Build Phase Discrepancy (MINOR GAP)

The orchestration plan places CI Agent in Phase 8 (§11.3). However,
34-CI-AGENT-GITHUB-ACTION-V2-PREP §31 references 04-INFRASTRUCTURE-V2-PREP §22 which
places CI Agent in "Phase 6 (Operational Infrastructure)." The orchestration plan's
Phase 8 assignment is correct (CI Agent is a presentation consumer), but the prep doc
references an older phase assignment.

### 20.16 Unaccounted Systems in Master Registry (COVERAGE GAP)

The Master Registry (§2) lists 35 specced + 9 unspecced = 44 systems, claiming ~55 total.
The remaining 16 are the Phase 0 infrastructure primitives (5) + Rules Engine + Policy
Engine + SARIF Reporter + other reporters (6) + N+1 Query Detection + Enterprise Secret
Detection + String Interning Integration = ~13-16 sub-systems.

The count of "~55 systems" should be verified — some of these are sub-components of
specced systems rather than independent systems. The distinction between "system" and
"sub-component" is not consistently applied.

### 20.17 Summary of Amendments Needed

| # | Gap | Severity | Action |
|---|-----|----------|--------|
| 20.1 | drift-context crate added to scaffold | Resolved | 6th crate added to §3.1 |
| 20.2 | Duplicate 16-IMPACT file | Low | Rename or remove duplicate file |
| 20.3 | NAPI counts updated | Resolved | §18.3 updated with per-system counts |
| 20.4 | Per-system build estimates missing | Medium | Add to phase sections or new §18.4 |
| 20.5 | Storage table counts updated | Resolved | §18.2 cumulative estimates revised |
| 20.6 | Rules/Policy Engine unspecced | Medium | Add to §17 or note coverage in QG spec |
| 20.7 | Performance targets incomplete | Low | Expand §18.1 table |
| 20.8 | QG↔Feedback circular dep | Medium | Add note to §9.1 |
| 20.9 | MCP tool counts updated | Resolved | §11.1 updated with actual v2 counts |
| 20.10 | Context gen dependencies pinned | Resolved | Added to workspace Cargo.toml |
| 20.11 | License tier naming standardized | Resolved | Standardized on "Team" |
| 20.12 | Workspace build estimate | Low | Note in §13.1 |
| 20.13 | Missing risks R12-R16 | Medium | Add to §16 |
| 20.14 | Missing event types | Low | Verify against 21-event list |
| 20.15 | CI Agent phase ref | Low | Note in §11.3 |
| 20.16 | ~55-system count verification | Low | Audit and clarify |
