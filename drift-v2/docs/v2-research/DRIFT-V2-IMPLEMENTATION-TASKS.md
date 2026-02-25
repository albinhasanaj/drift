# Drift V2 — Implementation Task Tracker

> **Source of Truth:** DRIFT-V2-IMPLEMENTATION-ORCHESTRATION.md + SCAFFOLD-DIRECTORY-PROMPT.md
> **Target Coverage:** ≥80% test coverage per crate (`cargo tarpaulin` or `cargo llvm-cov`)
> **Total Crates:** 6 Rust + 4 TypeScript packages + 1 bridge crate
> **Total Phases:** 11 (0–10)
> **Quality Gates:** 11 (QG-0 through QG-10)
> **Systems:** ~55 (35 specced via V2-PREP, 9 unspecced presentation/cross-cutting)
> **Rule:** No Phase N+1 begins until Phase N quality gate passes.
> **Verification:** This tracker accounts for 100% of all systems in the orchestration plan
>   and 100% of all files in the scaffold directory structure.
> **Cortex Pattern Reuse:** Copy patterns, not code. Drift and Cortex are independent (D1).

---

## How To Use This Document

- Agents: check off `[ ]` → `[x]` as you complete each task
- Every implementation task has a unique ID: `P{phase}-{system}-{number}`
- Every test task has a unique ID: `T{phase}-{system}-{number}`
- Quality gates are pass/fail — all criteria must pass before proceeding
- For behavioral details on any task → the corresponding V2-PREP document
- For file paths and structure → SCAFFOLD-DIRECTORY-PROMPT.md
- For build ordering rationale → DRIFT-V2-IMPLEMENTATION-ORCHESTRATION.md §1

---

## Progress Summary

| Phase | Description | Impl Tasks | Test Tasks | Status |
|-------|-------------|-----------|-----------|--------|
| 0 | Crate Scaffold & Infrastructure | 55 | 42 | ✅ Complete |
| 1 | Entry Pipeline | 76 | 69 | ✅ Complete |
| 2 | Structural Skeleton | 78 | 55 | ✅ Complete |
| 3 | Pattern Intelligence | 36 | 50 | ✅ Complete |
| 4 | Graph Intelligence | 39 | 47 | ⬜ Not Started |
| 5 | Structural Intelligence | 97 | 92 | ⬜ Not Started |
| 6 | Enforcement | 42 | 50 | ✅ Complete |
| 7 | Advanced & Capstone | 45 | 64 | ✅ Complete |
| 8 | Presentation | 45 | 37 | ⬜ Not Started |
| 9 | Bridge & Integration | 33 | 102 | ⬜ Not Started |
| 10 | Polish & Ship | 25 | 27 | ⬜ Not Started |
| **TOTAL** | | **571** | **635** | |

---

## Phase 0: Crate Scaffold & Infrastructure Primitives

> **Goal:** Stand up the Cargo workspace and the four infrastructure primitives that every subsequent system depends on.
> **Estimated effort:** 1–2 weeks (1 developer)
> **Governing decisions:** D5 (events from day one), AD6 (errors from day one), AD10 (tracing from day one), AD12 (performance data structures from day one)
> **Cortex reference:** `cortex-core/src/errors/`, `cortex-core/src/config/`

### 0A — Workspace Scaffold

- [x] `P0-WS-01` — Create `crates/drift/Cargo.toml` — workspace manifest with 6 members (`drift-core`, `drift-analysis`, `drift-storage`, `drift-context`, `drift-napi`, `drift-bench`), `[workspace.dependencies]` pinning all shared deps per §3.1 (tree-sitter 0.25, rusqlite 0.38, napi 3, thiserror 2, tracing 0.1, rustc-hash 2, smallvec 1, lasso 0.7, rayon 1.10, xxhash-rust 0.8, petgraph 0.8, moka 0.12, ignore 0.4, crossbeam-channel 0.5, serde 1, serde_json 1, statrs 0.18, git2 0.20, tiktoken-rs 0.9, fd-lock 4, quick-xml 0.37, serde_yaml 0.9, glob 0.3, base64 0.22), release profile (`lto=true`, `codegen-units=1`, `opt-level=3`, `strip="symbols"`, `panic="abort"`)
- [x] `P0-WS-02` — Create `crates/drift/.cargo/config.toml` — platform-specific linker settings (mold on Linux, default macOS/Windows)
- [x] `P0-WS-03` — Create `crates/drift/rustfmt.toml` — `max_width=100`, `edition="2021"`
- [x] `P0-WS-04` — Create `crates/drift/clippy.toml` — strict linting config
- [x] `P0-WS-05` — Create `crates/drift/deny.toml` — cargo-deny config for license and advisory auditing
- [x] `P0-WS-06` — Create stub `Cargo.toml` for each of the 6 crates with correct inter-crate dependencies: drift-core (no drift deps), drift-analysis → drift-core, drift-storage → drift-core, drift-context → drift-core, drift-napi → drift-analysis + drift-storage + drift-context + drift-core, drift-bench → drift-analysis + drift-storage + drift-core
- [x] `P0-WS-07` — Create `drift-core/src/lib.rs` with `#![allow(dead_code, unused)]` and `pub mod` declarations for config, errors, events, tracing, types, traits, constants
- [x] `P0-WS-08` — Create `drift-analysis/src/lib.rs` with `#![allow(dead_code, unused)]` and stub `pub mod` declarations for all 12 top-level modules (scanner, parsers, engine, detectors, call_graph, boundaries, language_provider, patterns, graph, structural, enforcement, advanced)
- [x] `P0-WS-09` — Create `drift-storage/src/lib.rs` with stub `pub mod` declarations (connection, batch, migrations, queries, pagination, materialized)
- [x] `P0-WS-10` — Create `drift-context/src/lib.rs` with stub `pub mod` declarations (generation, tokenization, formats, packages)
- [x] `P0-WS-11` — Create `drift-napi/src/lib.rs` with stub declarations + `drift-napi/build.rs` (napi-build)
- [x] `P0-WS-12` — Create `drift-bench/src/lib.rs` + `drift-bench/benches/` stubs

### 0B — Configuration System (DriftConfig) — `drift-core/src/config/`

> **V2-PREP:** 04-INFRASTRUCTURE §5. TOML-based, 4-layer resolution.

- [x] `P0-CFG-01` — Create `drift-core/src/config/mod.rs` — `pub mod` declarations + re-exports for all config types
- [x] `P0-CFG-02` — Create `drift-core/src/config/drift_config.rs` — `DriftConfig` top-level struct aggregating all sub-configs, 4-layer resolution: CLI flags > env vars > project config (`drift.toml`) > user config (`~/.drift/config.toml`) > compiled defaults. `DriftConfig::load()` method
- [x] `P0-CFG-03` — Create `drift-core/src/config/scan_config.rs` — `ScanConfig` (max_file_size, ignore_patterns, parallelism, incremental toggle, `.driftignore` path)
- [x] `P0-CFG-04` — Create `drift-core/src/config/analysis_config.rs` — `AnalysisConfig` (enabled_categories, detector_thresholds, gast_languages, incremental toggle)
- [x] `P0-CFG-05` — Create `drift-core/src/config/gate_config.rs` — `GateConfig` (enabled_gates, fail_level, progressive_enforcement, ramp_up_period)
- [x] `P0-CFG-06` — Create `drift-core/src/config/mcp_config.rs` — `McpConfig` (max_response_tokens default 8000, transport, enabled_tools)
- [x] `P0-CFG-07` — Create `drift-core/src/config/backup_config.rs` — `BackupConfig` (backup_interval, max_backups, backup_path)
- [x] `P0-CFG-08` — Create `drift-core/src/config/telemetry_config.rs` — `TelemetryConfig` (enabled, endpoint, anonymous_id)
- [x] `P0-CFG-09` — Create `drift-core/src/config/license_config.rs` — `LicenseConfig` (tier: Community/Team/Enterprise, jwt_path, feature_flags)

### 0C — Error Handling (thiserror) — `drift-core/src/errors/`

> **V2-PREP:** 04-INFRASTRUCTURE §2. One error enum per subsystem. `thiserror` only, zero `anyhow`.

- [x] `P0-ERR-01` — Create `drift-core/src/errors/mod.rs` — `pub mod` declarations + re-exports + `From` impls between sub-errors
- [x] `P0-ERR-02` — Create `drift-core/src/errors/error_code.rs` — `DriftErrorCode` trait for NAPI conversion, 14+ error codes: `SCAN_ERROR`, `PARSE_ERROR`, `DB_BUSY`, `DB_CORRUPT`, `CANCELLED`, `UNSUPPORTED_LANGUAGE`, `DETECTION_ERROR`, `CALL_GRAPH_ERROR`, `CONFIG_ERROR`, `LICENSE_ERROR`, `GATE_FAILED`, `STORAGE_ERROR`, `DISK_FULL`, `MIGRATION_FAILED`
- [x] `P0-ERR-03` — Create `drift-core/src/errors/scan_error.rs` — `ScanError` enum (IoError, PermissionDenied, Cancelled, MaxFileSizeExceeded, UnsupportedEncoding)
- [x] `P0-ERR-04` — Create `drift-core/src/errors/parse_error.rs` — `ParseError` enum (GrammarNotFound, TreeSitterError, Timeout, UnsupportedLanguage, PartialParse)
- [x] `P0-ERR-05` — Create `drift-core/src/errors/storage_error.rs` — `StorageError` enum (SqliteError, MigrationFailed, DbBusy, DbCorrupt, DiskFull, ConnectionPoolExhausted)
- [x] `P0-ERR-06` — Create `drift-core/src/errors/detection_error.rs` — `DetectionError` enum (InvalidPattern, QueryCompilationFailed, DetectorPanic, Timeout)
- [x] `P0-ERR-07` — Create `drift-core/src/errors/call_graph_error.rs` — `CallGraphError` enum (CycleDetected, ResolutionFailed, MemoryExceeded, CteFallbackFailed)
- [x] `P0-ERR-08` — Create `drift-core/src/errors/pipeline_error.rs` — `PipelineError` enum + `PipelineResult` struct with `errors: Vec<PipelineError>` for non-fatal error collection
- [x] `P0-ERR-09` — Create `drift-core/src/errors/taint_error.rs` — `TaintError` enum (InvalidSource, InvalidSink, PathTooLong, SummaryConflict)
- [x] `P0-ERR-10` — Create `drift-core/src/errors/constraint_error.rs` — `ConstraintError` enum (InvalidInvariant, VerificationFailed, ConflictingConstraints)
- [x] `P0-ERR-11` — Create `drift-core/src/errors/boundary_error.rs` — `BoundaryError` enum (UnknownOrm, ExtractionFailed, SensitiveFieldConflict)
- [x] `P0-ERR-12` — Create `drift-core/src/errors/gate_error.rs` — `GateError` enum (EvaluationFailed, DependencyNotMet, PolicyViolation)
- [x] `P0-ERR-13` — Create `drift-core/src/errors/config_error.rs` — `ConfigError` enum (FileNotFound, ParseError, ValidationFailed, InvalidValue)
- [x] `P0-ERR-14` — Create `drift-core/src/errors/napi_error.rs` — `NapiError` enum + conversion from all other error types to NAPI error codes

### 0D — Observability (tracing) — `drift-core/src/tracing/`

> **V2-PREP:** 04-INFRASTRUCTURE §3. `tracing` + `EnvFilter`. Optional OpenTelemetry behind `otel` feature flag.

- [x] `P0-TRC-01` — Create `drift-core/src/tracing/mod.rs` — `pub mod` declarations + re-exports
- [x] `P0-TRC-02` — Create `drift-core/src/tracing/setup.rs` — `init_tracing()` function, `EnvFilter` setup for per-subsystem log levels (`DRIFT_LOG=scanner=debug,parser=info,storage=warn`), optional `otel` feature flag for OpenTelemetry layer
- [x] `P0-TRC-03` — Create `drift-core/src/tracing/metrics.rs` — 12+ structured span field definitions: `scan_files_per_second`, `cache_hit_rate`, `parse_time_per_language`, `napi_serialization_time`, `detection_time_per_category`, `batch_write_time`, `call_graph_build_time`, `confidence_compute_time`, `gate_evaluation_time`, `mcp_response_time`, `discovery_duration`, `hashing_duration`

### 0E — Event System (DriftEventHandler) — `drift-core/src/events/`

> **V2-PREP:** 04-INFRASTRUCTURE §4 + PLANNING-DRIFT.md D5. Trait with no-op defaults, synchronous dispatch.

- [x] `P0-EVT-01` — Create `drift-core/src/events/mod.rs` — `pub mod` declarations + re-exports
- [x] `P0-EVT-02` — Create `drift-core/src/events/handler.rs` — `DriftEventHandler` trait with 24 event methods (all with no-op defaults): `on_scan_started`, `on_scan_progress`, `on_scan_complete`, `on_scan_error`, `on_pattern_discovered`, `on_pattern_approved`, `on_pattern_ignored`, `on_pattern_merged`, `on_violation_detected`, `on_violation_dismissed`, `on_violation_fixed`, `on_gate_evaluated`, `on_regression_detected`, `on_enforcement_changed`, `on_constraint_approved`, `on_constraint_violated`, `on_decision_mined`, `on_decision_reversed`, `on_adr_detected`, `on_boundary_discovered`, `on_detector_alert`, `on_detector_disabled`, `on_feedback_abuse_detected`, `on_error`
- [x] `P0-EVT-03` — Create `drift-core/src/events/dispatcher.rs` — `EventDispatcher` struct wrapping `Vec<Arc<dyn DriftEventHandler>>`, `emit()` helper for synchronous dispatch, zero overhead when no handlers registered
- [x] `P0-EVT-04` — Create `drift-core/src/events/types.rs` — Event payload types for all 24 events (ScanStartedEvent, ScanProgressEvent, PatternDiscoveredEvent, ViolationDetectedEvent, etc.)

### 0F — Data Structures & String Interning — `drift-core/src/types/`

> **V2-PREP:** 04-INFRASTRUCTURE §6 + AD12. FxHashMap, SmallVec, BTreeMap, lasso.

- [x] `P0-TYP-01` — Create `drift-core/src/types/mod.rs` — `pub mod` declarations + re-exports
- [x] `P0-TYP-02` — Create `drift-core/src/types/interning.rs` — `PathInterner` (normalizes path separators before interning), `FunctionInterner` (supports qualified name interning `Class.method`), `ThreadedRodeo` wrappers for build/scan phase, `RodeoReader` for query phase
- [x] `P0-TYP-03` — Create `drift-core/src/types/collections.rs` — `FxHashMap`, `FxHashSet` re-exports from `rustc-hash`, `SmallVec` type aliases for common sizes, `BTreeMap` re-export
- [x] `P0-TYP-04` — Create `drift-core/src/types/identifiers.rs` — `Spur`-based ID types: `FileId`, `FunctionId`, `PatternId`, `ClassId`, `ModuleId`, `DetectorId`

### 0G — Shared Traits — `drift-core/src/traits/`

- [x] `P0-TRT-01` — Create `drift-core/src/traits/mod.rs` — `pub mod` declarations + re-exports for shared traits used across crates
- [x] `P0-TRT-02` — Create `drift-core/src/traits/cancellation.rs` — `CancellationToken` trait wrapping `AtomicBool` for cooperative cancellation

### 0H — Constants — `drift-core/src/constants.rs`

- [x] `P0-CST-01` — Create `drift-core/src/constants.rs` — Shared constants: default thresholds, version strings, feature flag names, performance target values

### 0I — Test Fixtures — `test-fixtures/`

> **Why Phase 0:** Every phase from 1 onward references test fixtures for scanner input, parser validation, convention learning, taint analysis, and boundary detection. If these don't exist before Phase 1 begins, every test task blocks. This is foundational infrastructure, not test authoring.

- [x] `P0-FIX-01` — Create `test-fixtures/` directory scaffold with subdirectories per supported language: `typescript/`, `javascript/`, `python/`, `java/`, `csharp/`, `go/`, `rust/`, `ruby/`, `php/`, `kotlin/` — plus `malformed/`, `conventions/`, `orm/`, `taint/`, and a `README.md` documenting the fixture contract (what each subdirectory provides and how tests should reference them)
- [x] `P0-FIX-02` — Create reference source files for each of the 10 supported languages — each file must contain: named functions (≥5), classes with methods (≥2), import/export statements, call sites between functions, at least one known pattern (naming convention, error handling style), and inline comments marking expected parse results (`// EXPECT: function_count=5`) so tests can assert against them deterministically
- [x] `P0-FIX-03` — Create malformed/edge-case fixtures in `test-fixtures/malformed/`: files with syntax errors (unclosed braces, missing semicolons), binary files (`.png`, `.wasm`), 0-byte files, a file with 50,000 lines (large-file boundary), deeply nested directory (256 levels), Unicode filenames (CJK `测试.ts`, emoji `🚀.py`, RTL `بيانات.js`), symlink loops (`a → b → a`), and a read-only file (permissions `0o444`)
- [x] `P0-FIX-04` — Create taint analysis fixtures in `test-fixtures/taint/`: files with known source→sink paths for SQL injection (`req.query` → `db.query()`), XSS (`req.body` → `res.send()`), command injection (`userInput` → `exec()`), and path traversal (`req.params` → `fs.readFile()`) — each file annotated with `// TAINT: source=line:col sink=line:col` for deterministic assertion
- [x] `P0-FIX-05` — Create convention learning fixtures in `test-fixtures/conventions/`: 3 small synthetic repos (`repo-a/`, `repo-b/`, `repo-c/`) each with 8–12 files following a consistent naming convention (camelCase, snake_case, PascalCase respectively), consistent error handling pattern, and 1–2 deliberate outliers per repo so convention detection tests can verify both pattern recognition and outlier flagging
- [x] `P0-FIX-06` — Create ORM/boundary detection fixtures in `test-fixtures/orm/`: files using Sequelize (model definition + migration), Prisma (schema + client usage), Django (models.py + views.py), SQLAlchemy (declarative model + session usage), and ActiveRecord (model + migration) — each with known model names, field names, and at least one sensitive field (`password`, `ssn`, `email`) for boundary detection to flag

### Phase 0 Tests

#### Config — Correctness & Edge Cases
- [x] `T0-CFG-01` — Create `drift-core/tests/config_test.rs` — Test 4-layer config resolution (CLI > env > project > user > defaults)
- [x] `T0-CFG-02` — Test `DriftConfig::load()` with missing files (graceful fallback to defaults)
- [x] `T0-CFG-03` — Test env var override pattern (`DRIFT_SCAN_MAX_FILE_SIZE`)
- [x] `T0-CFG-04` — Test config with invalid TOML syntax returns `ConfigError::ParseError`, not panic
- [x] `T0-CFG-05` — Test config with valid TOML but invalid values (negative max_file_size, empty string for path) returns `ConfigError::ValidationFailed`
- [x] `T0-CFG-06` — Test config layer precedence: project-level `max_file_size=1MB` overridden by env `DRIFT_SCAN_MAX_FILE_SIZE=5MB` — env wins
- [x] `T0-CFG-07` — Test config with unrecognized keys is accepted (forward-compatible, no hard failure on unknown fields)
- [x] `T0-CFG-08` — Test config round-trip: load → serialize → load produces identical config
- [x] `T0-CFG-09` — Test config with Unicode paths in `drift.toml` (CJK directory names, emoji in project names)
- [x] `T0-CFG-10` — Test config with read-only filesystem for user config path (should not crash, should warn and continue)

#### Errors — Exhaustive Conversion & Display
- [x] `T0-ERR-01` — Create `drift-core/tests/errors_test.rs` — Test every error enum has `DriftErrorCode` implementation
- [x] `T0-ERR-02` — Test `From` conversions between sub-errors and top-level error
- [x] `T0-ERR-03` — Test NAPI error code string format `[ERROR_CODE] message`
- [x] `T0-ERR-04` — Test every error variant's `Display` impl produces a human-readable message (no `Debug` formatting leaking to users)
- [x] `T0-ERR-05` — Test `PipelineResult` accumulates multiple non-fatal errors and still returns partial results
- [x] `T0-ERR-06` — Test error chain preservation: `StorageError::SqliteError` wrapping a rusqlite error retains the original error via `source()`
- [x] `T0-ERR-07` — Test all 14 NAPI error codes are unique (no two error variants map to the same code)
- [x] `T0-ERR-08` — Test `NapiError` conversion from every other error type (exhaustive: Scan, Parse, Storage, Detection, CallGraph, Pipeline, Taint, Constraint, Boundary, Gate, Config)

#### Events — Dispatch Integrity
- [x] `T0-EVT-01` — Create `drift-core/tests/events_test.rs` — Test `DriftEventHandler` trait compiles with no-op defaults
- [x] `T0-EVT-02` — Test `EventDispatcher` with zero handlers (zero overhead)
- [x] `T0-EVT-03` — Test `EventDispatcher` with multiple handlers (all receive events in registration order)
- [x] `T0-EVT-04` — Test handler that panics does not crash the dispatcher or prevent subsequent handlers from firing
- [x] `T0-EVT-05` — Test event payload data integrity: emit `ScanProgressEvent` with specific fields, verify handler receives identical fields
- [x] `T0-EVT-06` — Test `EventDispatcher` is `Send + Sync` (required for multi-threaded analysis pipeline)

#### Types & Interning — Concurrency & Correctness
- [x] `T0-TYP-01` — Create `drift-core/tests/types_test.rs` — Test `ThreadedRodeo` interns and resolves paths correctly
- [x] `T0-TYP-02` — Test `PathInterner` normalizes path separators (Unix/Windows)
- [x] `T0-TYP-03` — Test `FunctionInterner` handles qualified names (`Class.method`)
- [x] `T0-TYP-04` — Test `Spur`-based ID types are distinct (no cross-type confusion)
- [x] `T0-TYP-05` — Test `ThreadedRodeo` under concurrent writes from 8 threads (rayon parallel iterator) — no data races, all strings resolvable after
- [x] `T0-TYP-06` — Test `PathInterner` with paths containing `..`, symlinks, trailing slashes — all normalize to canonical form
- [x] `T0-TYP-07` — Test interning the same string 10,000 times returns the same `Spur` every time (deduplication correctness)
- [x] `T0-TYP-08` — Test `RodeoReader` rejects writes after freeze (compile-time or runtime enforcement)
- [x] `T0-TYP-09` — Test `FxHashMap` with `Spur` keys produces correct lookups (hash collision behavior with interned keys)

#### Tracing — Observability
- [x] `T0-TRC-01` — Create `drift-core/tests/tracing_test.rs` — Test `DRIFT_LOG=debug` produces structured span output
- [x] `T0-TRC-02` — Test per-subsystem log level filtering (`scanner=debug,parser=warn` — scanner emits debug, parser suppresses debug)
- [x] `T0-TRC-03` — Test `init_tracing()` called twice does not panic or double-initialize (idempotent)
- [x] `T0-TRC-04` — Test invalid `DRIFT_LOG` value (e.g., `DRIFT_LOG=garbage`) falls back to default level, does not crash

#### Build & Lint
- [x] `T0-INT-01` — `cargo build --workspace` succeeds with zero warnings
- [x] `T0-INT-02` — `cargo clippy --workspace` passes with zero warnings
- [ ] `T0-INT-03` — `cargo deny check` passes
- [x] `T0-INT-04` — `cargo test --workspace` passes (all Phase 0 tests green)
- [ ] `T0-INT-05` — `cargo tarpaulin -p drift-core` reports ≥80% line coverage

### QG-0: Phase 0 Quality Gate

- [x] `cargo build --workspace` succeeds with zero warnings
- [x] `DriftConfig::load()` resolves 4 layers correctly
- [x] Every error enum has a `DriftErrorCode` implementation
- [x] `DRIFT_LOG=debug` produces structured span output
- [x] `DriftEventHandler` trait compiles with no-op defaults
- [x] `ThreadedRodeo` interns and resolves paths correctly
- [x] All workspace dependencies are pinned at exact versions
- [x] `cargo clippy --workspace` passes with zero warnings
- [x] `panic = "abort"` set in release profile
- [x] drift-context crate compiles and exports public types
- [x] drift-core has zero dependencies on other drift crates

---

## Phase 1: Entry Pipeline (Scanner → Parsers → Storage → NAPI)

> **Goal:** Build the four bedrock systems. At the end, you can scan a real codebase, parse files into ASTs, persist results to drift.db, and call it all from TypeScript.
> **Estimated effort:** 2–3 weeks (1 dev), 1–2 weeks (2 devs)
> **Build order:** Scanner → Parsers → Storage → NAPI (each system's output is the next system's input)
> **Cortex reference:** `cortex-napi/src/runtime.rs` (OnceLock singleton), `cortex-storage/src/pool/` (write-serialized + read-pooled)

### 1A — Scanner (System 00) — `drift-analysis/src/scanner/`

> **V2-PREP:** 00-SCANNER. `ignore` crate v0.4 (`WalkParallel`), `rayon` v1.10, xxh3 content hashing.
> **Performance targets:** 10K files <300ms Linux / <500ms macOS, 100K <3s cold / <1.5s incremental.

- [ ] `P1-SCN-01` — Create `drift-analysis/src/scanner/mod.rs` — `pub mod` declarations + re-exports
- [ ] `P1-SCN-02` — Create `drift-analysis/src/scanner/types.rs` — `ScanEntry` (path, content_hash, mtime, size, language), `ScanDiff` (added, modified, removed, unchanged), `ScanStats` (timing, throughput, file counts)
- [ ] `P1-SCN-03` — Create `drift-analysis/src/scanner/walker.rs` — `ignore::WalkParallel` integration, `.driftignore` support (gitignore syntax, hierarchical), 18 default ignores (node_modules, .git, dist, build, target, .next, .nuxt, __pycache__, .pytest_cache, coverage, .nyc_output, vendor, .venv, venv, .tox, .mypy_cache, bin, obj)
- [ ] `P1-SCN-04` — Create `drift-analysis/src/scanner/hasher.rs` — xxh3 content hashing via `xxhash-rust`, two-level incremental detection: mtime comparison (catches ~95%) → content hash for mtime-changed files
- [ ] `P1-SCN-05` — Create `drift-analysis/src/scanner/language_detect.rs` — Language detection from file extension, mapping to 10 supported languages (TypeScript, JavaScript, Python, Java, C#, Go, Rust, Ruby, PHP, Kotlin)
- [ ] `P1-SCN-06` — Create `drift-analysis/src/scanner/incremental.rs` — Incremental scan logic: compare current scan against previous `file_metadata` table, produce `ScanDiff`
- [ ] `P1-SCN-07` — Create `drift-analysis/src/scanner/cancellation.rs` — `AtomicBool`-based cancellation, progress via `DriftEventHandler::on_scan_progress`
- [ ] `P1-SCN-08` — Create `drift-analysis/src/scanner/scanner.rs` — Top-level `Scanner` struct orchestrating walker → hasher → language detect → incremental → diff, emitting `on_scan_started`, `on_scan_complete`, `on_scan_error` events

### 1B — Tree-Sitter Parsers (System 01) — `drift-analysis/src/parsers/`

> **V2-PREP:** 01-PARSERS. 10 languages, `thread_local!` parser instances, 2 consolidated queries per language.
> **Performance targets:** Parse 10K files <5s, single-pass shared results.

- [ ] `P1-PRS-01` — Create `drift-analysis/src/parsers/mod.rs` — `pub mod` declarations + re-exports
- [ ] `P1-PRS-02` — Create `drift-analysis/src/parsers/types.rs` — Canonical `ParseResult` struct: functions, classes, imports, exports, call_sites, decorators, inheritance, access_modifiers, type_annotations, string_literals, numeric_literals, error_handling_constructs, namespace/package info. Body hash + signature hash for function-level change detection
- [ ] `P1-PRS-03` — Create `drift-analysis/src/parsers/traits.rs` — `LanguageParser` trait: `parse(&self, source: &[u8], path: &Path) -> Result<ParseResult, ParseError>`, `language(&self) -> Language`, `queries(&self) -> &CompiledQueries`
- [ ] `P1-PRS-04` — Create `drift-analysis/src/parsers/manager.rs` — `ParserManager` dispatcher: routes files to correct language parser based on extension, manages `thread_local!` parser instances
- [ ] `P1-PRS-05` — Create `drift-analysis/src/parsers/cache.rs` — Moka LRU in-memory parse cache (TinyLFU admission) + SQLite `parse_cache` table for persistence, keyed by content hash
- [ ] `P1-PRS-06` — Create `drift-analysis/src/parsers/macros.rs` — `define_parser!` macro for mechanical language addition (reduces boilerplate per language)
- [ ] `P1-PRS-07` — Create `drift-analysis/src/parsers/queries.rs` — 2 consolidated tree-sitter `Query` objects per language (structure + calls), pre-compiled and reused across files
- [ ] `P1-PRS-08` — Create `drift-analysis/src/parsers/error_tolerant.rs` — Error-tolerant parsing: partial results from ERROR nodes, graceful degradation
- [ ] `P1-PRS-09` — Create `drift-analysis/src/parsers/languages/mod.rs` — `pub mod` declarations for all 10 languages
- [ ] `P1-PRS-10` — Create `drift-analysis/src/parsers/languages/typescript.rs` — TypeScript parser + queries
- [ ] `P1-PRS-11` — Create `drift-analysis/src/parsers/languages/javascript.rs` — JavaScript parser + queries
- [ ] `P1-PRS-12` — Create `drift-analysis/src/parsers/languages/python.rs` — Python parser + queries
- [ ] `P1-PRS-13` — Create `drift-analysis/src/parsers/languages/java.rs` — Java parser + queries
- [ ] `P1-PRS-14` — Create `drift-analysis/src/parsers/languages/csharp.rs` — C# parser + queries
- [ ] `P1-PRS-15` — Create `drift-analysis/src/parsers/languages/go.rs` — Go parser + queries
- [ ] `P1-PRS-16` — Create `drift-analysis/src/parsers/languages/rust.rs` — Rust parser + queries
- [ ] `P1-PRS-17` — Create `drift-analysis/src/parsers/languages/ruby.rs` — Ruby parser + queries
- [ ] `P1-PRS-18` — Create `drift-analysis/src/parsers/languages/php.rs` — PHP parser + queries
- [ ] `P1-PRS-19` — Create `drift-analysis/src/parsers/languages/kotlin.rs` — Kotlin parser + queries
- [ ] `P1-PRS-20` — Create `drift-analysis/build.rs` — tree-sitter grammar compilation for all 10 languages (static linking, no WASM)

### 1C — SQLite Storage (System 02) — `drift-storage/src/`

> **V2-PREP:** 02-STORAGE. WAL mode, write-serialized + read-pooled, batch writer, keyset pagination.
> **Cortex reference:** `cortex-storage/src/pool/` (Drift uses `std::sync::Mutex`, not `tokio::sync::Mutex`)

- [ ] `P1-STR-01` — Create `drift-storage/src/connection/mod.rs` — `pub mod` declarations
- [ ] `P1-STR-02` — Create `drift-storage/src/connection/pragmas.rs` — WAL mode, `PRAGMA synchronous=NORMAL`, 64MB page cache, 256MB mmap, `busy_timeout=5000`, `temp_store=MEMORY`, `auto_vacuum=INCREMENTAL`, `foreign_keys=ON`
- [ ] `P1-STR-03` — Create `drift-storage/src/connection/writer.rs` — `Mutex<Connection>` write serialization, `BEGIN IMMEDIATE` transactions, `prepare_cached()`
- [ ] `P1-STR-04` — Create `drift-storage/src/connection/pool.rs` — `ReadPool` with round-robin `AtomicUsize` index, read connections with `SQLITE_OPEN_READ_ONLY`
- [ ] `P1-STR-05` — Create `drift-storage/src/batch/mod.rs` — `pub mod` declarations
- [ ] `P1-STR-06` — Create `drift-storage/src/batch/commands.rs` — `BatchCommand` enum (InsertFileMetadata, InsertParseResult, InsertFunction, InsertCallEdge, etc.)
- [ ] `P1-STR-07` — Create `drift-storage/src/batch/writer.rs` — `crossbeam-channel` bounded(1024), dedicated writer thread, batch size 500, `recv_timeout(100ms)`, `prepare_cached()`
- [ ] `P1-STR-08` — Create `drift-storage/src/migrations/mod.rs` — `rusqlite_migration` + `PRAGMA user_version`, migration runner
- [ ] `P1-STR-09` — Create `drift-storage/src/migrations/v001_initial.rs` — Phase 1 tables: `file_metadata`, `parse_cache`, `functions` (core schema, ~5-8 tables)
- [ ] `P1-STR-10` — Create `drift-storage/src/queries/mod.rs` — `pub mod` declarations for all query modules
- [ ] `P1-STR-11` — Create `drift-storage/src/queries/files.rs` — `file_metadata` CRUD queries
- [ ] `P1-STR-12` — Create `drift-storage/src/queries/parse_cache.rs` — `parse_cache` queries (get by content hash, insert, invalidate)
- [ ] `P1-STR-13` — Create `drift-storage/src/queries/functions.rs` — `functions` table queries
- [ ] `P1-STR-14` — Create `drift-storage/src/pagination/mod.rs` — `pub mod` declarations
- [ ] `P1-STR-15` — Create `drift-storage/src/pagination/keyset.rs` — Keyset cursor pagination with composite cursor `(sort_column, id)`, no OFFSET/LIMIT
- [ ] `P1-STR-16` — Create `drift-storage/src/materialized/mod.rs` — Stub `pub mod` declarations for materialized views (populated in later phases)

### 1D — NAPI Bridge (System 03) — `drift-napi/src/`

> **V2-PREP:** 03-NAPI-BRIDGE. napi-rs v3, singleton `DriftRuntime` via `OnceLock`, `AsyncTask` for >10ms ops.
> **Cortex reference:** `cortex-napi/src/runtime.rs` (OnceLock pattern), `cortex-napi/src/conversions/` (error codes)
> **Note:** Create v2→v3 cheat sheet before starting (see §18 NAPI v2→v3 Adaptation Guide)

- [x] `P1-NAPI-01` — Create `drift-napi/src/runtime.rs` — `DriftRuntime` singleton via `OnceLock` (lock-free after init), holds write connection, read pool, config, event dispatcher
- [x] `P1-NAPI-02` — Create `drift-napi/src/conversions/mod.rs` — `pub mod` declarations
- [x] `P1-NAPI-03` — Create `drift-napi/src/conversions/error_codes.rs` — `DriftErrorCode` → NAPI error conversion, structured `[ERROR_CODE] message` strings for all 14+ error codes
- [x] `P1-NAPI-04` — Create `drift-napi/src/conversions/types.rs` — Rust ↔ JS type conversions (ScanDiff → JS object, ParseResult → JS object, etc.)
- [x] `P1-NAPI-05` — Create `drift-napi/src/bindings/mod.rs` — `pub mod` declarations for all binding modules
- [x] `P1-NAPI-06` — Create `drift-napi/src/bindings/lifecycle.rs` — `drift_initialize()` (creates drift.db, sets PRAGMAs, runs migrations, initializes runtime), `drift_shutdown()` (cleanly closes all connections, flushes batch writer)
- [x] `P1-NAPI-07` — Create `drift-napi/src/bindings/scanner.rs` — `drift_scan()` as `AsyncTask` (>10ms), returns `ScanDiff` + `ScanStats`, progress callback via v3 `ThreadsafeFunction`

### Phase 1 Tests

#### Scanner — Edge Cases & Adversarial Inputs
- [x] `T1-SCN-01` — Create `drift-analysis/tests/scanner_test.rs` — Test scanner discovers files in test fixture directory (baseline correctness)
- [x] `T1-SCN-02` — Test incremental scan correctly identifies added/modified/removed files across 3 consecutive scans (add→modify→delete cycle)
- [x] `T1-SCN-03` — Test `.driftignore` patterns exclude correct files, including nested `.driftignore` files (hierarchical override)
- [x] `T1-SCN-04` — Test cancellation via `AtomicBool` stops scan mid-walk — verify partial `ScanDiff` is returned (not empty, not full)
- [x] `T1-SCN-05` — Test language detection from file extensions for all 10 languages, plus unknown extensions return `None` (not panic)
- [x] `T1-SCN-06` — Test symlink loop detection: create `a/b → a` cycle, verify scanner terminates without stack overflow or infinite loop
- [x] `T1-SCN-07` — Test permission-denied files: create unreadable file (`chmod 000`), verify `ScanError::PermissionDenied` emitted and scan continues for remaining files
- [x] `T1-SCN-08` — Test 0-byte files: scanner includes them in results with `content_hash` of empty input (deterministic), `size=0`
- [x] `T1-SCN-09` — Test file modified mid-scan: create file, start scan, modify file during walk — verify no crash, result reflects either pre- or post-modification state (not corrupted)
- [x] `T1-SCN-10` — Test deeply nested directory (256 levels deep) — verify scanner handles without stack overflow
- [x] `T1-SCN-11` — Test empty directory produces `ScanDiff` with all counts at zero, no errors
- [x] `T1-SCN-12` — Test Unicode filenames (CJK characters, emoji, RTL text, combining diacriticals) — scanner discovers and hashes correctly
- [x] `T1-SCN-13` — Test filenames with special characters (spaces, `#`, `$`, `(`, `)`, `&`) — no shell injection or path parsing failures
- [x] `T1-SCN-14` — Test `.driftignore` with malformed patterns (unclosed brackets, invalid regex) — graceful skip with warning, not crash
- [x] `T1-SCN-15` — Test xxh3 content hash determinism: same file content on different paths produces identical hash
- [x] `T1-SCN-16` — Test mtime-based incremental detection: touch file without changing content → mtime changes → content hash compared → correctly classified as unchanged
- [x] `T1-SCN-17` — Test `on_scan_started`, `on_scan_progress`, `on_scan_complete` events fire in correct order with correct payload data
- [x] `T1-SCN-18` — Test `on_scan_error` fires for each permission-denied file with correct path in payload

#### Scanner — Concurrency & Performance
- [x] `T1-SCN-19` — Test parallel walker (`WalkParallel`) with 8 threads on 10K-file fixture — no data races (run under `--release` with thread sanitizer)
- [x] `T1-SCN-20` — Benchmark: 10K files scanned in <500ms (macOS), <300ms (Linux) — regression gate
- [x] `T1-SCN-21` — Test incremental scan of 10K files with 10 changed files completes in <100ms (not re-scanning unchanged)

#### Parsers — Correctness & Error Tolerance
- [x] `T1-PRS-01` — Create `drift-analysis/tests/parsers_test.rs` — Test all 10 language parsers produce valid `ParseResult` from reference test files (1 file per language, known expected output)
- [x] `T1-PRS-02` — Test parse cache hits on second parse of unchanged file — verify cache key is content hash, not path
- [x] `T1-PRS-03` — Test error-tolerant parsing: feed each parser a file with syntax errors (missing closing brace, unterminated string) — verify partial `ParseResult` returned with `functions.len() > 0`, not `Err`
- [x] `T1-PRS-04` — Test body hash + signature hash: modify function body only → body hash changes, signature hash unchanged. Modify function signature → both change
- [x] `T1-PRS-05` — Test `define_parser!` macro produces correct parser implementation for a test language
- [x] `T1-PRS-06` — Test parser with empty file (0 bytes) — returns empty `ParseResult`, not error
- [x] `T1-PRS-07` — Test parser with binary file (random bytes) — returns `ParseError::TreeSitterError`, not panic or hang
- [x] `T1-PRS-08` — Test parser with extremely long single line (1MB single line of code) — completes within timeout, no OOM
- [x] `T1-PRS-09` — Test parser with deeply nested AST (200+ nesting levels of `if` statements) — no stack overflow
- [x] `T1-PRS-10` — Test `thread_local!` parser instances: parse 100 files across 4 threads — each thread gets its own parser, no cross-thread contamination
- [x] `T1-PRS-11` — Test `ParserManager` routes `.ts`, `.tsx`, `.js`, `.jsx` correctly (TypeScript parser for TS/TSX, JavaScript for JS/JSX)
- [x] `T1-PRS-12` — Test `CompiledQueries` are reused across files (not recompiled per file) — measure query compilation count
- [x] `T1-PRS-13` — Test parse cache eviction: fill Moka cache to capacity, verify LRU entries evicted, new entries cached
- [x] `T1-PRS-14` — Test parse cache persistence: write to SQLite `parse_cache`, restart (new `ParserManager`), verify cache hit on same content hash
- [x] `T1-PRS-15` — Test Unicode source code: Python file with CJK variable names, Ruby file with emoji method names — parser extracts correct identifiers

#### Storage — WAL Corruption, Concurrency, Disk Pressure
- [x] `T1-STR-01` — Create `drift-storage/tests/connection_test.rs` — Test PRAGMAs set correctly on new database (WAL mode, synchronous=NORMAL, 64MB page cache, foreign_keys=ON)
- [x] `T1-STR-02` — Create `drift-storage/tests/batch_test.rs` — Test batch writer persists 500 rows in single transaction, verify row count matches
- [x] `T1-STR-03` — Create `drift-storage/tests/migration_test.rs` — Test migration from empty DB to v001 schema — verify all tables exist with correct columns
- [x] `T1-STR-04` — Create `drift-storage/tests/queries_test.rs` — Test keyset pagination: insert 1000 rows, paginate with page_size=100, verify 10 pages with correct ordering and no duplicates/gaps
- [x] `T1-STR-05` — Test read pool round-robin: issue 100 reads, verify distribution across pool connections (no single connection gets >60% of reads)
- [x] `T1-STR-06` — Test write serialization: spawn 8 threads each inserting 100 rows simultaneously — all 800 rows persisted, no `SQLITE_BUSY` errors (Mutex serialization works)
- [x] `T1-STR-07` — Test WAL corruption recovery: corrupt WAL file (truncate to half), reopen database — verify either recovery succeeds or `StorageError::DbCorrupt` returned (not silent data loss)
- [x] `T1-STR-08` — Test migration rollback on failure: create migration that fails mid-way (e.g., duplicate column), verify database state is unchanged (transaction rolled back)
- [x] `T1-STR-09` — Test `busy_timeout=5000`: hold write lock for 3s in one thread, attempt write in another — second write succeeds after wait (not immediate `SQLITE_BUSY`)
- [x] `T1-STR-10` — Test disk-full handling: set `PRAGMA max_page_count` to tiny value, attempt large insert — verify `StorageError::DiskFull` returned, not panic
- [x] `T1-STR-11` — Test `prepare_cached()` reuse: execute same query 1000 times, verify statement cache hit rate >99%
- [x] `T1-STR-12` — Test batch writer channel backpressure: send 2048 commands to bounded(1024) channel — verify producer blocks (not drops), all commands eventually processed
- [x] `T1-STR-13` — Test batch writer `recv_timeout(100ms)` flush: send 50 rows (below batch size 500), verify they're flushed within 200ms (timeout-triggered flush)
- [x] `T1-STR-14` — Test concurrent reader + writer: writer inserting continuously, 4 readers querying simultaneously — readers never see partial transactions (snapshot isolation via WAL)
- [x] `T1-STR-15` — Test `SQLITE_OPEN_READ_ONLY` enforcement: attempt write through read pool connection — verify error returned, not silent success
- [x] `T1-STR-16` — Test keyset pagination with composite cursor `(sort_column, id)`: insert rows with duplicate sort values, verify pagination doesn't skip or duplicate rows

#### NAPI Bridge — Lifecycle & Error Propagation
- [x] `T1-NAPI-01` — Create `drift-napi/tests/napi_test.rs` — Test `drift_initialize()` creates drift.db with correct PRAGMAs, returns success
- [x] `T1-NAPI-02` — Test `drift_scan()` returns typed `ScanDiff` to TypeScript with correct field types (not `any`)
- [x] `T1-NAPI-03` — Test `drift_shutdown()` cleanly closes all connections — subsequent `drift_scan()` returns `[SCAN_ERROR]` not segfault
- [x] `T1-NAPI-04` — Test double `drift_initialize()` is idempotent (OnceLock) — second call returns existing runtime, not error
- [x] `T1-NAPI-05` — Test `drift_scan()` after `drift_shutdown()` returns structured `[SCAN_ERROR]` error code, not panic or undefined behavior
- [x] `T1-NAPI-06` — Test `ThreadsafeFunction` progress callback: verify `on_scan_progress` fires from Rust worker thread and is received on JS main thread
- [x] `T1-NAPI-07` — Test error code propagation: trigger `ScanError::PermissionDenied` in Rust, verify TypeScript receives `[SCAN_ERROR] Permission denied: <path>` string
- [x] `T1-NAPI-08` — Test `AsyncTask` does not block Node.js event loop: start scan, verify setTimeout callback fires during scan (event loop not starved)

#### Integration & Performance Contracts
- [x] `T1-INT-01` — Integration: scan → parse → persist → query round-trip on 100-file test fixture — verify file count, function count, and content hashes match
- [x] `T1-INT-02` — Performance: 10K files scanned + parsed + persisted in <3s end-to-end (cold), <1.5s incremental (10 files changed)
- [x] `T1-INT-03` — Create `drift-analysis/benches/scanner_bench.rs` — Scanner benchmark (10K files, cold + incremental)
- [x] `T1-INT-04` — Create `drift-analysis/benches/parser_bench.rs` — Parser benchmark (per-language timing, 1000 files each)
- [x] `T1-INT-05` — Test data survives Rust→SQLite→Rust round-trip: insert `ParseResult` with Unicode function names, query back, verify byte-identical
- [x] `T1-INT-06` — Test data survives Rust→NAPI→JS round-trip: `ScanDiff` with 10K entries serialized to JS, verify no field truncation or type coercion
- [x] `T1-INT-07` — Memory pressure test: scan 100K-file fixture, verify RSS stays under 500MB (no unbounded growth from interning or caching)

#### Build & Coverage Gate
- [ ] `T1-INT-08` — `cargo tarpaulin -p drift-analysis -p drift-storage` reports ≥80% line coverage for Phase 1 code
- [x] `T1-INT-09` — `cargo clippy -p drift-analysis -p drift-storage -p drift-napi` passes with zero warnings

### QG-1: Phase 1 Quality Gate

- [x] `drift_initialize()` creates drift.db with correct PRAGMAs
- [x] `drift_scan()` discovers files, computes hashes, returns `ScanDiff`
- [x] Incremental scan correctly identifies added/modified/removed files
- [x] All 10 language parsers produce valid `ParseResult` from test files
- [x] Parse cache hits on second parse of unchanged file
- [x] Batch writer persists file_metadata and parse results to drift.db
- [x] `drift_shutdown()` cleanly closes all connections
- [x] TypeScript can call all three functions and receive typed results
- [x] Performance: 10K files scanned + parsed in <3s end-to-end

---

## Phase 2: Structural Skeleton (Analysis Engine, Call Graph, Detectors)

> **Goal:** Build the core analysis systems. At the end, Drift detects patterns across 16 categories, builds a call graph with 6 resolution strategies, detects data boundaries across 33+ ORMs, and normalizes ASTs across 9 languages.
> **Estimated effort:** 3–4 weeks for Phase 2 deliverables (core pipeline + visitor engine + initial detectors). Full UAE spans 22–27 weeks across 7 internal phases — remaining work continues in parallel with Phases 3–5.
> **Parallelization:** Track A (UAE + Detectors) ∥ Track B (Call Graph + Boundaries + ULP)
> **Cortex reference:** `cortex-causal/src/graph/dag_enforcement.rs` (Tarjan's SCC with petgraph)

### 2A — String Interning Integration

> While lasso is scaffolded in Phase 0, actual integration into ParseResult and all identifier-heavy paths happens here.

- [x] `P2-INT-01` — Integrate `ThreadedRodeo` into `ParseResult` — all file paths, function names, class names, pattern IDs become `Spur` handles
- [x] `P2-INT-02` — Implement `ThreadedRodeo` → `RodeoReader` freeze at scan→analysis boundary (thread-safe writes during parallel parsing, zero-contention reads during analysis)
- [x] `P2-INT-03` — Verify O(1) comparisons and measure memory reduction (target 60–80% for paths/names)

### 2B — Unified Analysis Engine (System 06) — `drift-analysis/src/engine/`

> **V2-PREP:** 06-UNIFIED-ANALYSIS-ENGINE. 4-phase per-file pipeline, single-pass visitor pattern (AD4).

- [x] `P2-UAE-01` — Create `drift-analysis/src/engine/mod.rs` — `pub mod` declarations + re-exports
- [x] `P2-UAE-02` — Create `drift-analysis/src/engine/types.rs` — `AnalysisResult`, `PatternMatch` (file, line, column, pattern_id, confidence, cwe_ids: SmallVec<[u32; 2]>, owasp: Option<Spur>), `AnalysisPhase` enum
- [x] `P2-UAE-03` — Create `drift-analysis/src/engine/visitor.rs` — Visitor trait for single-pass AST traversal (AD4), `VisitorContext` with shared state, `VisitorRegistry` for registering detector visitors
- [x] `P2-UAE-04` — Create `drift-analysis/src/engine/pipeline.rs` — 4-phase per-file pipeline: (1) AST pattern detection via visitor, (2) string extraction, (3) regex on extracted strings, (4) resolution index building
- [x] `P2-UAE-05` — Create `drift-analysis/src/engine/string_extraction.rs` — String literal extraction (literals, template strings, interpolations) for regex-based detection
- [x] `P2-UAE-06` — Create `drift-analysis/src/engine/regex_engine.rs` — Regex matching on extracted strings (URL patterns, SQL patterns, secret patterns)
- [x] `P2-UAE-07` — Create `drift-analysis/src/engine/resolution.rs` — Resolution index building: 6 strategies for cross-file symbol resolution (Direct, Method, Constructor, Callback, Dynamic, External)
- [x] `P2-UAE-08` — Create `drift-analysis/src/engine/incremental.rs` — Incremental analysis: process only `ScanDiff.added + modified` files, content-hash skip for unchanged
- [x] `P2-UAE-09` — Create `drift-analysis/src/engine/gast/mod.rs` — GAST (Generic AST) normalization layer module declarations
- [x] `P2-UAE-10` — Create `drift-analysis/src/engine/gast/types.rs` — ~40-50 GAST node types + `GASTNode::Other { kind: String, children: Vec<GASTNode> }` catch-all variant
- [x] `P2-UAE-11` — Create `drift-analysis/src/engine/gast/base_normalizer.rs` — Base normalizer with default behavior for all node types
- [x] `P2-UAE-12` — Create `drift-analysis/src/engine/gast/normalizers/mod.rs` — `pub mod` for 9 language normalizers
- [x] `P2-UAE-13` — Create `drift-analysis/src/engine/gast/normalizers/typescript.rs` — TS/JS GAST normalizer
- [x] `P2-UAE-14` — Create `drift-analysis/src/engine/gast/normalizers/python.rs` — Python GAST normalizer
- [x] `P2-UAE-15` — Create `drift-analysis/src/engine/gast/normalizers/java.rs` — Java GAST normalizer
- [x] `P2-UAE-16` — Create `drift-analysis/src/engine/gast/normalizers/csharp.rs` — C# GAST normalizer
- [x] `P2-UAE-17` — Create `drift-analysis/src/engine/gast/normalizers/go.rs` — Go GAST normalizer
- [x] `P2-UAE-18` — Create `drift-analysis/src/engine/gast/normalizers/rust_lang.rs` — Rust GAST normalizer
- [x] `P2-UAE-19` — Create `drift-analysis/src/engine/gast/normalizers/php.rs` — PHP GAST normalizer
- [x] `P2-UAE-20` — Create `drift-analysis/src/engine/gast/normalizers/ruby.rs` — Ruby GAST normalizer
- [x] `P2-UAE-21` — Create `drift-analysis/src/engine/gast/normalizers/cpp.rs` — C++ GAST normalizer
- [x] `P2-UAE-22` — Create `drift-analysis/src/engine/toml_patterns.rs` — Declarative TOML pattern definitions (user-extensible without recompiling), `CompiledQuery` with `cwe_ids` and `owasp` fields

### 2C — Detector System (System 06 — Detectors) — `drift-analysis/src/detectors/`

> **V2-PREP:** 06-DETECTOR-SYSTEM. 16 categories, 3 variants per category, 350+ detectors total.
> **Build strategy:** Start with 5 categories (security, data-access, errors, testing, structural). Add remaining incrementally.

- [x] `P2-DET-01` — Create `drift-analysis/src/detectors/mod.rs` — `pub mod` declarations for all 16 categories + traits + registry
- [x] `P2-DET-02` — Create `drift-analysis/src/detectors/traits.rs` — `Detector` trait: `detect(&self, ctx: &DetectionContext) -> Vec<PatternMatch>`, `category(&self) -> DetectorCategory`, `variant(&self) -> DetectorVariant` (Base/Learning/Semantic)
- [x] `P2-DET-03` — Create `drift-analysis/src/detectors/registry.rs` — `DetectorRegistry`: register detectors, filter by category, critical-only mode, enable/disable per detector
- [x] `P2-DET-04` — Create `drift-analysis/src/detectors/api/mod.rs` — API detector category (endpoint patterns, REST conventions, versioning)
- [x] `P2-DET-05` — Create `drift-analysis/src/detectors/auth/mod.rs` — Auth detector category (authentication patterns, authorization checks, session management)
- [x] `P2-DET-06` — Create `drift-analysis/src/detectors/components/mod.rs` — Components detector category (component patterns, composition, lifecycle)
- [x] `P2-DET-07` — Create `drift-analysis/src/detectors/config/mod.rs` — Config detector category (configuration patterns, env usage, feature flags)
- [x] `P2-DET-08` — Create `drift-analysis/src/detectors/contracts/mod.rs` — Contracts detector category (API contracts, interface compliance)
- [x] `P2-DET-09` — Create `drift-analysis/src/detectors/data_access/mod.rs` — Data access detector category (ORM patterns, query patterns, repository patterns)
- [x] `P2-DET-10` — Create `drift-analysis/src/detectors/documentation/mod.rs` — Documentation detector category (doc comments, README patterns, JSDoc/TSDoc)
- [x] `P2-DET-11` — Create `drift-analysis/src/detectors/errors/mod.rs` — Errors detector category (error handling patterns, try/catch, Result types)
- [x] `P2-DET-12` — Create `drift-analysis/src/detectors/logging/mod.rs` — Logging detector category (log levels, structured logging, log format)
- [x] `P2-DET-13` — Create `drift-analysis/src/detectors/performance/mod.rs` — Performance detector category (N+1, unnecessary allocations, hot paths)
- [x] `P2-DET-14` — Create `drift-analysis/src/detectors/security/mod.rs` — Security detector category (injection, XSS, CSRF, auth bypass, secrets)
- [x] `P2-DET-15` — Create `drift-analysis/src/detectors/structural/mod.rs` — Structural detector category (naming conventions, file organization, module patterns)
- [x] `P2-DET-16` — Create `drift-analysis/src/detectors/styling/mod.rs` — Styling detector category (CSS patterns, theme usage, design tokens)
- [x] `P2-DET-17` — Create `drift-analysis/src/detectors/testing/mod.rs` — Testing detector category (test patterns, assertion styles, mock usage)
- [x] `P2-DET-18` — Create `drift-analysis/src/detectors/types/mod.rs` — Types detector category (type annotation patterns, generics, type guards)
- [x] `P2-DET-19` — Create `drift-analysis/src/detectors/accessibility/mod.rs` — Accessibility detector category (ARIA patterns, semantic HTML, a11y)

### 2D — Call Graph Builder (System 05) — `drift-analysis/src/call_graph/`

> **V2-PREP:** 05-CALL-GRAPH. petgraph `StableGraph`, 6 resolution strategies, SQLite CTE fallback for >500K functions.
> **Performance targets:** Build <5s for 10K files, BFS <5ms, SQLite CTE <50ms.

- [x] `P2-CG-01` — Create `drift-analysis/src/call_graph/mod.rs` — `pub mod` declarations + re-exports
- [x] `P2-CG-02` — Create `drift-analysis/src/call_graph/types.rs` — `CallGraphNode` (function_id, file_id, name, kind), `CallGraphEdge` (caller, callee, resolution_strategy, confidence), `ResolutionStrategy` enum (Direct, Method, Constructor, Callback, Dynamic, External)
- [x] `P2-CG-03` — Create `drift-analysis/src/call_graph/builder.rs` — `CallGraphBuilder`: parallel extraction via rayon, builds petgraph `StableGraph`, populates `functions` + `call_edges` + `data_access` tables
- [x] `P2-CG-04` — Create `drift-analysis/src/call_graph/resolution.rs` — 6 resolution strategies implementation: Direct (exact name match), Method (class.method qualified), Constructor (new/init), Callback (closure/lambda), Dynamic (string-based/reflection, lower confidence), External (cross-module via import/export)
- [x] `P2-CG-05` — Create `drift-analysis/src/call_graph/traversal.rs` — Forward/inverse BFS traversal on petgraph, entry point detection (5 heuristic categories: exported functions, main/index files, route handlers, test functions, CLI entry points)
- [x] `P2-CG-06` — Create `drift-analysis/src/call_graph/cte_fallback.rs` — SQLite recursive CTE fallback for graphs >500K functions (`in_memory_threshold` config), temp table for visited set, `max_depth=5`
- [x] `P2-CG-07` — Create `drift-analysis/src/call_graph/incremental.rs` — Incremental update: re-extract only changed files, remove edges for deleted files, re-resolve affected edges
- [x] `P2-CG-08` — Create `drift-analysis/src/call_graph/di_support.rs` — DI injection framework support: 5 frameworks (FastAPI, Spring, NestJS, Laravel, ASP.NET) at confidence 0.80

### 2E — Boundary Detection (System 07) — `drift-analysis/src/boundaries/`

> **V2-PREP:** 07-BOUNDARY-DETECTION. 33+ ORM frameworks, 10 field extractors, sensitive field detection.

- [x] `P2-BND-01` — Create `drift-analysis/src/boundaries/mod.rs` — `pub mod` declarations + re-exports
- [x] `P2-BND-02` — Create `drift-analysis/src/boundaries/types.rs` — `Boundary`, `SensitiveField` (4 categories: PII, Credentials, Financial, Health), `OrmFramework` enum (33+ variants)
- [x] `P2-BND-03` — Create `drift-analysis/src/boundaries/detector.rs` — Two-phase learn-then-detect architecture, framework detection across 9 languages
- [x] `P2-BND-04` — Create `drift-analysis/src/boundaries/extractors/mod.rs` — `pub mod` declarations + extractor trait for all 10 field extractors
- [x] `P2-BND-05` — Create `drift-analysis/src/boundaries/extractors/sequelize.rs` — Sequelize field extractor
- [x] `P2-BND-06` — Create `drift-analysis/src/boundaries/extractors/typeorm.rs` — TypeORM field extractor
- [x] `P2-BND-07` — Create `drift-analysis/src/boundaries/extractors/prisma.rs` — Prisma field extractor
- [x] `P2-BND-08` — Create `drift-analysis/src/boundaries/extractors/django.rs` — Django ORM field extractor
- [x] `P2-BND-09` — Create `drift-analysis/src/boundaries/extractors/sqlalchemy.rs` — SQLAlchemy field extractor
- [x] `P2-BND-10` — Create `drift-analysis/src/boundaries/extractors/active_record.rs` — ActiveRecord field extractor
- [x] `P2-BND-11` — Create `drift-analysis/src/boundaries/extractors/mongoose.rs` — Mongoose field extractor
- [x] `P2-BND-12` — Create `drift-analysis/src/boundaries/extractors/ef_core.rs` — Entity Framework Core field extractor (new in v2)
- [x] `P2-BND-13` — Create `drift-analysis/src/boundaries/extractors/hibernate.rs` — Hibernate field extractor (new in v2)
- [x] `P2-BND-14` — Create `drift-analysis/src/boundaries/extractors/eloquent.rs` — Eloquent field extractor (new in v2)
- [x] `P2-BND-15` — Create `drift-analysis/src/boundaries/sensitive.rs` — Sensitive field detection: ~100+ patterns (3x v1), 6 formal false-positive filters, confidence scoring with 5 weighted factors

### 2F — Unified Language Provider (System 08) — `drift-analysis/src/language_provider/`

> **V2-PREP:** 08-UNIFIED-LANGUAGE-PROVIDER. 9 language normalizers, 22 ORM/framework matchers.

- [x] `P2-ULP-01` — Create `drift-analysis/src/language_provider/mod.rs` — `pub mod` declarations + re-exports
- [x] `P2-ULP-02` — Create `drift-analysis/src/language_provider/types.rs` — `UnifiedCallChain` universal representation, 12 semantic categories
- [x] `P2-ULP-03` — Create `drift-analysis/src/language_provider/normalizers.rs` — 9 language normalizers (TS/JS, Python, Java, C#, PHP, Go, Rust, C++, base)
- [x] `P2-ULP-04` — Create `drift-analysis/src/language_provider/framework_matchers.rs` — 22 ORM/framework matchers, framework detection for 5+ framework pattern sets
- [x] `P2-ULP-05` — Create `drift-analysis/src/language_provider/n_plus_one.rs` — N+1 query detection module (call graph + ORM pattern matching, 8 ORM frameworks)
- [x] `P2-ULP-06` — Create `drift-analysis/src/language_provider/taint_sinks.rs` — Taint sink extraction module (feeds Phase 4 taint analysis)

### 2G — Phase 2 Storage & NAPI Extensions

- [x] `P2-STR-01` — Create `drift-storage/src/migrations/v002_analysis.rs` — Phase 2 tables: `call_edges`, `data_access`, `detections`, `boundaries`, `patterns` (~15-20 cumulative)
- [x] `P2-STR-02` — Create `drift-storage/src/queries/call_edges.rs` — `call_edges` table queries (insert, query by caller/callee, delete by file)
- [x] `P2-STR-03` — Create `drift-storage/src/queries/detections.rs` — `detections` table queries
- [x] `P2-STR-04` — Create `drift-storage/src/queries/boundaries.rs` — `boundaries` table queries
- [x] `P2-NAPI-01` — Create `drift-napi/src/bindings/analysis.rs` — `drift_analyze()` (runs full analysis pipeline), `drift_call_graph()` (builds/queries call graph), `drift_boundaries()` (boundary detection)

### Phase 2 Tests

#### Analysis Engine — Pipeline Integrity & Malformed Input
- [x] `T2-UAE-01` — Create `drift-analysis/tests/engine_test.rs` — Test analysis engine processes test codebase through all 4 phases in correct order (visitor → string extraction → regex → resolution)
- [x] `T2-UAE-02` — Test GAST normalization produces identical node types for equivalent TS/Python code (e.g., `async function` in both languages → same GAST node)
- [x] `T2-UAE-03` — Test `coverage_report()` per language — target ≥85% node coverage for P0 languages (TS, JS, Python). Fail if coverage drops below threshold
- [x] `T2-UAE-04` — Test incremental analysis processes only changed files — modify 5 of 1000 files, verify only 5 re-analyzed
- [x] `T2-UAE-05` — Test TOML pattern definitions load and compile correctly, including user-defined custom patterns
- [x] `T2-UAE-06` — Test GAST `Other` catch-all variant passes through unrecognized AST constructs without data loss — verify round-trip: GAST→serialize→deserialize preserves `Other` nodes
- [x] `T2-UAE-07` — Test GAST normalization with malformed AST input (tree-sitter ERROR nodes) — normalizer produces partial GAST, not crash
- [x] `T2-UAE-08` — Test GAST language misdetection recovery: feed Python code to TypeScript normalizer — verify graceful failure with `ParseError::UnsupportedLanguage`, not panic
- [x] `T2-UAE-09` — Test visitor pattern single-pass guarantee: instrument visitor calls, verify each AST node visited exactly once (no double-visit, no skip)
- [x] `T2-UAE-10` — Test `VisitorRegistry` with 50 registered visitors — all fire on each node, no visitor starvation
- [x] `T2-UAE-11` — Test string extraction handles template literals with nested expressions (`${a + ${b}}`) — extracts both static and dynamic parts
- [x] `T2-UAE-12` — Test regex engine with catastrophic backtracking pattern (e.g., `(a+)+$` on `aaaaaaaaaaaaaaaaab`) — verify timeout fires, not CPU hang
- [x] `T2-UAE-13` — Test resolution index with 6 strategies: create test fixtures exercising Direct, Method, Constructor, Callback, Dynamic, External — verify each resolves correctly
- [x] `T2-UAE-14` — Test TOML pattern with invalid syntax returns `DetectionError::InvalidPattern` with line number, not generic parse error
- [x] `T2-UAE-15` — Test content-hash skip: analyze file, re-analyze without changes — verify zero work done on second pass (L2 incremental)

#### Detectors — False Positive Rate & Category Coverage
- [x] `T2-DET-01` — Create `drift-analysis/tests/detectors_test.rs` — Test at least 5 detector categories produce valid `PatternMatch` results on reference codebase
- [x] `T2-DET-02` — Test detector registry filters by category and critical-only mode — verify non-critical detectors excluded when `critical_only=true`
- [x] `T2-DET-03` — Test each detector carries `cwe_ids` and `owasp` fields — no detector produces a match with empty CWE mapping
- [x] `T2-DET-04` — Test detector that panics does not crash the analysis pipeline — verify `DetectionError::DetectorPanic` captured, remaining detectors continue
- [x] `T2-DET-05` — Test detector timeout: create slow detector (sleep 5s), set timeout to 100ms — verify `DetectionError::Timeout` returned, pipeline continues
- [x] `T2-DET-06` — Test detector enable/disable: disable security category, verify zero security matches produced
- [x] `T2-DET-07` — Test false-positive rate measurement: run security detectors on known-clean reference corpus (no vulnerabilities) — FP rate must be <10%
- [x] `T2-DET-08` — Test all 16 detector categories have at least 1 working detector registered (no empty categories)

#### Call Graph — Cycles, Scale, Resolution Fallback
- [x] `T2-CG-01` — Create `drift-analysis/tests/call_graph_test.rs` — Test call graph builds with all 6 resolution strategies on multi-language fixture
- [x] `T2-CG-02` — Test incremental call graph update: add file with new function, verify new edges added without full rebuild
- [x] `T2-CG-03` — Test SQLite CTE fallback produces same results as in-memory BFS for identical graph (correctness equivalence)
- [x] `T2-CG-04` — Test DI framework support: NestJS `@Injectable()` and Spring `@Autowired` resolve at confidence 0.80
- [x] `T2-CG-05` — Test entry point detection for all 5 heuristic categories (exported functions, main/index, route handlers, test functions, CLI entry points)
- [x] `T2-CG-06` — Test cycle handling: create A→B→C→A cycle, verify `CycleDetected` reported but graph still usable (not infinite loop in BFS)
- [x] `T2-CG-07` — Test disconnected components: graph with 3 isolated subgraphs — BFS from node in subgraph A does not reach subgraph B
- [x] `T2-CG-08` — Test resolution strategy fallback chain: when Direct fails, Method tried, then Constructor, etc. — verify fallback order and final confidence reflects strategy used
- [x] `T2-CG-09` — Test call graph with 50K functions: build completes in <5s, BFS completes in <5ms (performance contract)
- [x] `T2-CG-10` — Test incremental delete: remove file, verify all edges from/to that file's functions removed, no dangling references
- [x] `T2-CG-11` — Test Dynamic resolution (string-based/reflection) produces lower confidence (≤0.60) than Direct resolution (≥0.90)
- [x] `T2-CG-12` — Test empty codebase (0 files) produces empty graph, not error

#### Boundary Detection — ORM Coverage & Sensitive Field Accuracy
- [x] `T2-BND-01` — Create `drift-analysis/tests/boundaries_test.rs` — Test boundary detection identifies ORM patterns across at least 5 frameworks (Sequelize, Prisma, Django, SQLAlchemy, ActiveRecord)
- [x] `T2-BND-02` — Test sensitive field detection across all 4 categories (PII, Credentials, Financial, Health) — at least 3 patterns per category
- [x] `T2-BND-03` — Test false-positive filters: field named `password_reset_token_expiry` should NOT be flagged as credential (context-aware filtering)
- [x] `T2-BND-04` — Test unknown ORM framework returns `BoundaryError::UnknownOrm`, not crash — verify graceful degradation
- [x] `T2-BND-05` — Test confidence scoring: field named `ssn` in a `User` model scores higher than field named `id` in a `Config` model
- [x] `T2-BND-06` — Test all 10 field extractors produce valid output on their respective ORM's test fixtures

#### Language Provider — Cross-Language Normalization
- [x] `T2-ULP-01` — Create `drift-analysis/tests/language_provider_test.rs` — Test ULP normalizes call chains across at least 3 languages to identical `UnifiedCallChain`
- [x] `T2-ULP-02` — Test framework matcher identifies at least 5 ORM frameworks from import statements alone
- [x] `T2-ULP-03` — Test taint sink extraction produces valid sink definitions for Phase 4 consumption

#### Integration & Serialization Boundaries
- [x] `T2-INT-01` — Integration: scan → parse → analyze → call graph → persist round-trip — verify all data in drift.db
- [x] `T2-INT-02` — Performance: 10K file codebase analyzed in <10s end-to-end
- [x] `T2-INT-03` — Create `drift-analysis/benches/call_graph_bench.rs` — Call graph benchmark (build + BFS)
- [x] `T2-INT-04` — Test all results persist to drift.db via batch writer — verify row counts match analysis output
- [x] `T2-INT-05` — Test NAPI exposes `drift_analyze()` and `drift_call_graph()` to TypeScript with correct return types
- [x] `T2-INT-06` — Test string interning memory reduction: measure HashMap<String> vs Spur-based storage — target 60-80% reduction
- [x] `T2-INT-07` — Test `RodeoReader` freeze at scan→analysis boundary: writes during scan succeed, writes during analysis fail (compile-time or runtime)
- [x] `T2-INT-08` — Test analysis results survive Rust→SQLite→Rust round-trip with Unicode pattern names and CJK file paths
- [x] `T2-INT-09` — Test concurrent analysis of 100 files via rayon — no data races, all results collected

#### Build & Coverage Gate
- [x] `T2-INT-10` — `cargo tarpaulin -p drift-analysis` reports ≥80% line coverage for Phase 2 code
- [x] `T2-INT-11` — `cargo clippy -p drift-analysis` passes with zero warnings

### QG-2: Phase 2 Quality Gate

- [x] Analysis engine processes a real codebase through all 4 phases
- [x] At least 5 detector categories produce valid `PatternMatch` results
- [x] GAST normalization produces identical node types for equivalent TS/Python code
- [x] `coverage_report()` per language — target ≥85% node coverage for P0 languages
- [x] Call graph builds with all 6 resolution strategies
- [x] Incremental call graph update correctly handles file changes
- [x] Boundary detection identifies ORM patterns across at least 5 frameworks
- [x] ULP normalizes call chains across at least 3 languages
- [x] All results persist to drift.db via batch writer
- [x] NAPI exposes `drift_analyze()` and `drift_call_graph()` to TypeScript
- [x] Performance: 10K file codebase analyzed in <10s end-to-end

---

## Phase 3: Pattern Intelligence (Aggregation, Confidence, Outliers, Learning)

> **Goal:** Transform raw pattern detections into ranked, scored, learned conventions. This is what makes Drift *Drift*.
> **Estimated effort:** 3–4 weeks. Limited parallelism (internal dependency chain).
> **Internal ordering:** Pattern Aggregation → Bayesian Confidence → (Outlier Detection ∥ Learning System)
> **Key decision:** AD8 (Bayesian Confidence With Momentum) — Beta distribution posterior replaces static scoring.

### 3A — Pattern Aggregation & Deduplication (System 12) — `drift-analysis/src/patterns/aggregation/`

> **V2-PREP:** 12-PATTERN-AGGREGATION. 7-phase pipeline, Jaccard similarity, MinHash LSH.

- [x] `P3-AGG-01` — Create `drift-analysis/src/patterns/mod.rs` — `pub mod` declarations for aggregation, confidence, outliers, learning
- [x] `P3-AGG-02` — Create `drift-analysis/src/patterns/aggregation/mod.rs` — `pub mod` declarations + re-exports
- [x] `P3-AGG-03` — Create `drift-analysis/src/patterns/aggregation/types.rs` — `AggregatedPattern` (pattern_id, location_count, outlier_count, file_spread, hierarchy), `MergeCandidate`, `PatternHierarchy`
- [x] `P3-AGG-04` — Create `drift-analysis/src/patterns/aggregation/grouper.rs` — Phase 1-2: Group by pattern ID + cross-file merging
- [x] `P3-AGG-05` — Create `drift-analysis/src/patterns/aggregation/similarity.rs` — Phase 3-4: Jaccard similarity (0.85 threshold flags for review, 0.95 auto-merge), MinHash LSH for approximate near-duplicate detection at scale (n > 50K)
- [x] `P3-AGG-06` — Create `drift-analysis/src/patterns/aggregation/hierarchy.rs` — Phase 5: Parent-child pattern relationship building
- [x] `P3-AGG-07` — Create `drift-analysis/src/patterns/aggregation/reconciliation.rs` — Phase 6: Counter reconciliation (location_count, outlier_count caches)
- [x] `P3-AGG-08` — Create `drift-analysis/src/patterns/aggregation/gold_layer.rs` — Phase 7: Gold layer refresh (materialized views in drift.db)
- [x] `P3-AGG-09` — Create `drift-analysis/src/patterns/aggregation/incremental.rs` — Incremental: only re-aggregate patterns from changed files
- [x] `P3-AGG-10` — Create `drift-analysis/src/patterns/aggregation/pipeline.rs` — Top-level 7-phase aggregation pipeline orchestrator

### 3B — Bayesian Confidence Scoring (System 10) — `drift-analysis/src/patterns/confidence/`

> **V2-PREP:** 10-BAYESIAN-CONFIDENCE-SCORING. Beta distribution, 5-factor model, graduated tiers.

- [x] `P3-BAY-01` — Create `drift-analysis/src/patterns/confidence/mod.rs` — `pub mod` declarations + re-exports
- [x] `P3-BAY-02` — Create `drift-analysis/src/patterns/confidence/types.rs` — `ConfidenceScore` (alpha, beta, posterior_mean, credible_interval), `ConfidenceTier` enum (Established ≥0.85, Emerging ≥0.70, Tentative ≥0.50, Uncertain <0.50), `MomentumDirection` (Rising, Falling, Stable)
- [x] `P3-BAY-03` — Create `drift-analysis/src/patterns/confidence/beta.rs` — Beta distribution: `Beta(1+k, 1+n-k)` posterior computation via `statrs` crate, credible interval calculation
- [x] `P3-BAY-04` — Create `drift-analysis/src/patterns/confidence/factors.rs` — 5-factor model: Frequency, Consistency, Age, Spread, Momentum — each factor contributes to alpha/beta updates
- [x] `P3-BAY-05` — Create `drift-analysis/src/patterns/confidence/momentum.rs` — Momentum tracking: trend detection (rising/falling/stable), temporal decay (frequency decline → confidence reduction)
- [x] `P3-BAY-06` — Create `drift-analysis/src/patterns/confidence/scorer.rs` — Top-level `ConfidenceScorer`: takes aggregated patterns, computes Beta posteriors, assigns tiers

### 3C — Outlier Detection (System 11) — `drift-analysis/src/patterns/outliers/`

> **V2-PREP:** 11-OUTLIER-DETECTION. 6 methods with automatic selection based on sample size.

- [x] `P3-OUT-01` — Create `drift-analysis/src/patterns/outliers/mod.rs` — `pub mod` declarations + re-exports
- [x] `P3-OUT-02` — Create `drift-analysis/src/patterns/outliers/types.rs` — `OutlierResult`, `SignificanceTier` (Critical, High, Moderate, Low), `DeviationScore` (normalized 0.0-1.0)
- [x] `P3-OUT-03` — Create `drift-analysis/src/patterns/outliers/zscore.rs` — Z-Score with iterative masking (n ≥ 30, 3-iteration cap)
- [x] `P3-OUT-04` — Create `drift-analysis/src/patterns/outliers/grubbs.rs` — Grubbs' test (10 ≤ n < 30, single outlier in small samples), T-distribution critical values via `statrs`
- [x] `P3-OUT-05` — Create `drift-analysis/src/patterns/outliers/esd.rs` — Generalized ESD / Rosner test (n ≥ 25, multiple outliers)
- [x] `P3-OUT-06` — Create `drift-analysis/src/patterns/outliers/iqr.rs` — IQR with Tukey fences (supplementary, non-normal data)
- [x] `P3-OUT-07` — Create `drift-analysis/src/patterns/outliers/mad.rs` — Modified Z-Score / MAD (robust to extreme outliers)
- [x] `P3-OUT-08` — Create `drift-analysis/src/patterns/outliers/rule_based.rs` — Rule-based outlier detection (always active, for structural rules)
- [x] `P3-OUT-09` — Create `drift-analysis/src/patterns/outliers/selector.rs` — Auto-select method based on sample size (n ≥ 30 → Z-Score, 10 ≤ n < 30 → Grubbs', etc.)
- [x] `P3-OUT-10` — Create `drift-analysis/src/patterns/outliers/conversion.rs` — Outlier-to-violation conversion pipeline

### 3D — Learning System (System 13) — `drift-analysis/src/patterns/learning/`

> **V2-PREP:** 13-LEARNING-SYSTEM. Bayesian convention discovery, 5 categories, auto-promotion.

- [x] `P3-LRN-01` — Create `drift-analysis/src/patterns/learning/mod.rs` — `pub mod` declarations + re-exports
- [x] `P3-LRN-02` — Create `drift-analysis/src/patterns/learning/types.rs` — `Convention`, `ConventionCategory` enum (Universal, ProjectSpecific, Emerging, Legacy, Contested), `ConventionScope` (project, directory, package)
- [x] `P3-LRN-03` — Create `drift-analysis/src/patterns/learning/discovery.rs` — Bayesian convention discovery: thresholds minOccurrences=3, dominance=0.60, minFiles=2
- [x] `P3-LRN-04` — Create `drift-analysis/src/patterns/learning/promotion.rs` — Automatic pattern promotion: discovered → approved when thresholds met
- [x] `P3-LRN-05` — Create `drift-analysis/src/patterns/learning/relearning.rs` — Re-learning trigger: >10% files changed → full re-learn
- [x] `P3-LRN-06` — Create `drift-analysis/src/patterns/learning/dirichlet.rs` — Dirichlet-Multinomial extension for multi-value conventions
- [x] `P3-LRN-07` — Create `drift-analysis/src/patterns/learning/expiry.rs` — Convention expiry & retention policies

### 3E — Phase 3 Storage & NAPI Extensions

- [x] `P3-STR-01` — Create `drift-storage/src/migrations/v003_patterns.rs` — Phase 3 tables: `pattern_confidence` (α, β, score columns), `outliers`, `conventions` (~22-25 cumulative)
- [x] `P3-STR-02` — Create `drift-storage/src/queries/patterns.rs` — `patterns` + `pattern_confidence` queries (insert, update alpha/beta, query by tier, keyset pagination)
- [x] `P3-NAPI-01` — Create `drift-napi/src/bindings/patterns.rs` — `drift_patterns()`, `drift_confidence()`, `drift_outliers()`, `drift_conventions()` with keyset pagination

### Phase 3 Tests

#### Aggregation — Deduplication Correctness & Scale
- [x] `T3-AGG-01` — Create `drift-analysis/tests/aggregation_test.rs` — Test pattern aggregation groups per-file matches into project-level patterns with correct `location_count`
- [x] `T3-AGG-02` — Test Jaccard similarity correctly flags near-duplicate patterns: pairs at 0.86 flagged for review, pairs at 0.96 auto-merged, pairs at 0.50 left separate
- [x] `T3-AGG-03` — Test incremental re-aggregation only processes changed files — modify 5 of 1000 files, verify only affected patterns re-aggregated
- [x] `T3-AGG-04` — Test MinHash LSH produces same merge candidates as exact Jaccard for n=100 patterns (approximate correctness within 5% error)
- [x] `T3-AGG-05` — Test MinHash LSH scales: 50K patterns aggregated in <2s (exact Jaccard would be O(n²) = infeasible)
- [x] `T3-AGG-06` — Test hierarchy building: child pattern correctly linked to parent, verify parent's `location_count` includes children
- [x] `T3-AGG-07` — Test counter reconciliation: manually corrupt `location_count` cache, run reconciliation, verify corrected to match actual count
- [x] `T3-AGG-08` — Test gold layer refresh: verify materialized views in drift.db reflect latest aggregation state
- [x] `T3-AGG-09` — Test aggregation with zero patterns (empty codebase) — produces empty result, not error
- [x] `T3-AGG-10` — Test aggregation with 1 pattern (single occurrence) — correctly classified as single-instance, not merged with anything

#### Bayesian Confidence — Numerical Stability & Edge Cases
- [x] `T3-BAY-01` — Create `drift-analysis/tests/confidence_test.rs` — Test Bayesian confidence produces Beta posteriors with correct tier classification (Established ≥0.85, Emerging ≥0.70, Tentative ≥0.50, Uncertain <0.50)
- [x] `T3-BAY-02` — Test momentum tracking detects rising/falling/stable trends across 10 consecutive scans
- [x] `T3-BAY-03` — Test temporal decay reduces confidence on frequency decline — pattern not seen for 30 days drops at least 1 tier
- [x] `T3-BAY-04` — Test numerical stability with alpha near zero (α=0.001, β=1000) — no NaN, no Inf, no panic
- [x] `T3-BAY-05` — Test numerical stability with alpha near infinity (α=100000, β=1) — posterior mean approaches 1.0, credible interval narrows
- [x] `T3-BAY-06` — Test Beta distribution with α=β=1 (uniform prior) — posterior mean = 0.5, wide credible interval
- [x] `T3-BAY-07` — Test 5-factor model: verify each factor (Frequency, Consistency, Age, Spread, Momentum) independently affects alpha/beta — toggle each factor, verify score changes
- [x] `T3-BAY-08` — Test credible interval width decreases as sample size increases (more data → more certainty)
- [x] `T3-BAY-09` — Test tier boundary precision: pattern at exactly 0.85 posterior mean → Established, at 0.849 → Emerging (boundary correctness)
- [x] `T3-BAY-10` — Test confidence scoring with NaN/Inf input values — returns `DetectionError`, not propagated NaN

#### Outlier Detection — Statistical Correctness & Degenerate Distributions
- [x] `T3-OUT-01` — Create `drift-analysis/tests/outliers_test.rs` — Test outlier detection auto-selects correct method based on sample size (n≥30 → Z-Score, 10≤n<30 → Grubbs', etc.)
- [x] `T3-OUT-02` — Test Z-Score, Grubbs', and IQR methods produce correct outlier classifications on reference dataset (≥90% precision, ≥80% recall vs. known ground truth)
- [x] `T3-OUT-03` — Test outlier-to-violation conversion pipeline: outlier with `SignificanceTier::Critical` produces violation with `Severity::Error`
- [x] `T3-OUT-04` — Test degenerate distribution: all identical values (variance=0) — no division by zero, no false outliers flagged
- [x] `T3-OUT-05` — Test degenerate distribution: single value (n=1) — returns empty outlier set, not error
- [x] `T3-OUT-06` — Test degenerate distribution: two values (n=2) — Grubbs' test handles gracefully (insufficient data for meaningful test)
- [x] `T3-OUT-07` — Test Z-Score iterative masking: dataset with 3 outliers, verify all 3 detected within 3-iteration cap
- [x] `T3-OUT-08` — Test MAD (Modified Z-Score) robustness: dataset with 40% outliers — MAD still identifies them (unlike Z-Score which breaks down)
- [x] `T3-OUT-09` — Test Generalized ESD with known reference dataset (Rosner 1983 example) — verify identical outlier set
- [x] `T3-OUT-10` — Test rule-based outlier detection fires for structural rules regardless of sample size
- [x] `T3-OUT-11` — Test `DeviationScore` normalization: verify all scores in [0.0, 1.0] range, no negative values

#### Learning System — Convention Discovery & Lifecycle
- [x] `T3-LRN-01` — Create `drift-analysis/tests/learning_test.rs` — Test learning system discovers conventions with minOccurrences=3, dominance=0.60, minFiles=2
- [x] `T3-LRN-02` — Test convention categories (Universal/ProjectSpecific/Emerging/Legacy/Contested) classify correctly based on spread and consistency
- [x] `T3-LRN-03` — Test auto-promotion from discovered → approved when thresholds met (confidence ≥0.85, spread ≥5 files)
- [x] `T3-LRN-04` — Test re-learning trigger fires when >10% files changed — verify full re-learn executes, not incremental
- [x] `T3-LRN-05` — Test Dirichlet-Multinomial extension: multi-value convention (e.g., 3 naming styles) correctly identifies dominant style
- [x] `T3-LRN-06` — Test convention expiry: convention not seen for 90 days → marked as Legacy, not deleted
- [x] `T3-LRN-07` — Test contested convention: two patterns at 45%/55% dominance → classified as Contested, not auto-promoted
- [x] `T3-LRN-08` — Test convention scope: directory-scoped convention does not leak to sibling directories

#### Integration & Performance Contracts
- [x] `T3-INT-01` — Integration: detect → aggregate → score → classify round-trip on 3 real-world test repos
- [x] `T3-INT-02` — Test all results persist to drift.db (patterns table with α, β, score columns) — verify column types and constraints
- [x] `T3-INT-03` — Test NAPI exposes pattern query functions with keyset pagination — verify cursor-based navigation works
- [x] `T3-INT-04` — Performance: confidence scoring for 10K patterns in <500ms — regression gate
- [x] `T3-INT-05` — Create `drift-analysis/benches/confidence_bench.rs` — Confidence scoring benchmark (1K, 10K, 100K patterns)
- [x] `T3-INT-06` — Run on 3 test repos: verify ≥1 convention discovered per repo without any configuration
- [x] `T3-INT-07` — Run on 3 test repos: verify ≥1 convention reaches 'Universal' category per repo
- [x] `T3-INT-08` — Test aggregation + confidence pipeline is idempotent: run twice on same data, verify identical output
- [x] `T3-INT-09` — Memory pressure: score 100K patterns, verify RSS growth <50MB (no unbounded allocation per pattern)

#### Build & Coverage Gate
- [x] `T3-INT-10` — `cargo tarpaulin -p drift-analysis` reports ≥80% line coverage for Phase 3 code
- [x] `T3-INT-11` — `cargo clippy -p drift-analysis` passes with zero warnings

### QG-3: Phase 3 Quality Gate (Milestone 3: "It Learns")

- [x] Pattern aggregation groups per-file matches into project-level patterns
- [x] Jaccard similarity correctly flags near-duplicate patterns (0.85 threshold)
- [x] Bayesian confidence produces Beta posteriors with correct tier classification
- [x] Momentum tracking detects rising/falling/stable trends
- [x] Outlier detection auto-selects correct method based on sample size
- [x] Z-Score, Grubbs', and IQR methods produce correct outlier classifications (≥90% precision, ≥80% recall)
- [x] Learning system discovers conventions with minOccurrences=3, dominance=0.60
- [x] Convention categories classify correctly
- [x] All results persist to drift.db
- [x] NAPI exposes pattern query functions with keyset pagination
- [x] Performance: confidence scoring for 10K patterns in <500ms

---

## Phase 4: Graph Intelligence (Reachability, Taint, Impact, Errors, Tests)

> **Goal:** Build the five Level 2B systems that consume the call graph. Security and structural intelligence.
> **Estimated effort:** 4–6 weeks. Highly parallelizable — all 5 systems are independent.
> **Parallelization:** 5 parallel tracks (maximum parallelism opportunity). All read call graph, write to own tables.
> **Key decision:** AD11 (Taint Analysis as First-Class Subsystem) — #1 security improvement for v2.

### 4A — Reachability Analysis (System 14) — `drift-analysis/src/graph/reachability/`

> **V2-PREP:** 14-REACHABILITY-ANALYSIS. Forward/inverse BFS, auto-select engine, sensitivity classification.

- [x] `P4-RCH-01` — Create `drift-analysis/src/graph/mod.rs` — `pub mod` declarations for reachability, taint, error_handling, impact, test_topology
- [x] `P4-RCH-02` — Create `drift-analysis/src/graph/reachability/mod.rs` — `pub mod` declarations + re-exports
- [x] `P4-RCH-03` — Create `drift-analysis/src/graph/reachability/types.rs` — `ReachabilityResult`, `SensitivityCategory` (Critical, High, Medium, Low), `ReachabilityCache`
- [x] `P4-RCH-04` — Create `drift-analysis/src/graph/reachability/bfs.rs` — Forward/inverse BFS traversal on petgraph, auto-select: petgraph for <10K nodes, SQLite CTE for >10K
- [x] `P4-RCH-05` — Create `drift-analysis/src/graph/reachability/sensitivity.rs` — Sensitivity classification: "Can user input reach this SQL query?" based on data sensitivity of reachable nodes
- [x] `P4-RCH-06` — Create `drift-analysis/src/graph/reachability/cache.rs` — LRU reachability cache with invalidation on graph changes
- [x] `P4-RCH-07` — Create `drift-analysis/src/graph/reachability/cross_service.rs` — Cross-service reachability for microservice boundaries
- [x] `P4-RCH-08` — Create `drift-analysis/src/graph/reachability/field_flow.rs` — Field-level data flow tracking

### 4B — Taint Analysis (System 15) — NET NEW — `drift-analysis/src/graph/taint/`

> **V2-PREP:** 15-TAINT-ANALYSIS. Source/sink/sanitizer model, TOML-driven registry, 17 sink types.
> **This is the #1 security improvement for v2. No v1 equivalent.**
> **Performance targets:** Intraprocedural <1ms/function, interprocedural <100ms/function.

- [x] `P4-TNT-01` — Create `drift-analysis/src/graph/taint/mod.rs` — `pub mod` declarations + re-exports
- [x] `P4-TNT-02` — Create `drift-analysis/src/graph/taint/types.rs` — `TaintSource`, `TaintSink`, `TaintSanitizer`, `TaintFlow` (source → sink path with sanitizer tracking), `TaintLabel`, `SinkType` enum (17 variants: SqlQuery/CWE-89, OsCommand/CWE-78, CodeExecution/CWE-94, FileWrite/CWE-22, FileRead/CWE-22, HtmlOutput/CWE-79, HttpRedirect/CWE-601, HttpRequest/CWE-918, Deserialization/CWE-502, LdapQuery/CWE-90, XpathQuery/CWE-643, TemplateRender/CWE-1336, LogOutput/CWE-117, HeaderInjection/CWE-113, RegexConstruction/CWE-1333, XmlParsing/CWE-611, FileUpload/CWE-434, Custom(u32))
- [x] `P4-TNT-03` — Create `drift-analysis/src/graph/taint/registry.rs` — TOML-driven source/sink/sanitizer registry (extensible without code changes), per-framework defaults
- [x] `P4-TNT-04` — Create `drift-analysis/src/graph/taint/intraprocedural.rs` — Phase 1: Within-function dataflow tracking (covers most common vulnerability patterns)
- [x] `P4-TNT-05` — Create `drift-analysis/src/graph/taint/interprocedural.rs` — Phase 2: Cross-function taint propagation via function summaries
- [x] `P4-TNT-06` — Create `drift-analysis/src/graph/taint/propagation.rs` — Taint label propagation with sanitizer tracking, label merging at join points
- [x] `P4-TNT-07` — Create `drift-analysis/src/graph/taint/sarif.rs` — SARIF code flow generation for taint paths (source → intermediate → sink)
- [x] `P4-TNT-08` — Create `drift-analysis/src/graph/taint/framework_specs.rs` — Framework-specific taint specifications (Express, Django, Spring, etc.)

### 4C — Error Handling Analysis (System 16) — `drift-analysis/src/graph/error_handling/`

> **V2-PREP:** 16-ERROR-HANDLING-ANALYSIS. 8-phase topology engine, 20+ framework support.
> **Performance targets:** <5ms per file topology construction.

- [x] `P4-ERR-01` — Create `drift-analysis/src/graph/error_handling/mod.rs` — `pub mod` declarations + re-exports
- [x] `P4-ERR-02` — Create `drift-analysis/src/graph/error_handling/types.rs` — `ErrorType`, `ErrorHandler`, `PropagationChain`, `UnhandledPath`, `ErrorGap` (empty catch, swallowed errors, generic catches)
- [x] `P4-ERR-03` — Create `drift-analysis/src/graph/error_handling/profiler.rs` — Phase 1: Error type profiling (categorize error types per language)
- [x] `P4-ERR-04` — Create `drift-analysis/src/graph/error_handling/handler_detection.rs` — Phase 2: Handler detection (try/catch, Result, error callbacks)
- [x] `P4-ERR-05` — Create `drift-analysis/src/graph/error_handling/propagation.rs` — Phase 3: Propagation chain tracing via call graph
- [x] `P4-ERR-06` — Create `drift-analysis/src/graph/error_handling/gap_analysis.rs` — Phases 4-5: Unhandled path identification + gap analysis
- [x] `P4-ERR-07` — Create `drift-analysis/src/graph/error_handling/frameworks.rs` — Phase 6: Framework-specific analysis (20+ frameworks: Express, Koa, Hapi, Fastify, Django, Flask, Spring, ASP.NET, Rails, Sinatra, Laravel, Phoenix, Gin, Echo, Actix, Rocket, NestJS, Next.js, Nuxt, SvelteKit)
- [x] `P4-ERR-08` — Create `drift-analysis/src/graph/error_handling/cwe_mapping.rs` — Phase 7: CWE/OWASP A10:2025 mapping + remediation suggestions

### 4D — Impact Analysis (System 17) — `drift-analysis/src/graph/impact/`

> **V2-PREP:** 17-IMPACT-ANALYSIS. Blast radius, dead code detection, path finding.

- [x] `P4-IMP-01` — Create `drift-analysis/src/graph/impact/mod.rs` — `pub mod` declarations + re-exports
- [x] `P4-IMP-02` — Create `drift-analysis/src/graph/impact/types.rs` — `BlastRadius`, `RiskScore` (5 factors: blast radius, sensitivity, test coverage, complexity, change frequency), `DeadCodeResult`
- [x] `P4-IMP-03` — Create `drift-analysis/src/graph/impact/blast_radius.rs` — Transitive caller analysis via call graph BFS, risk scoring per function
- [x] `P4-IMP-04` — Create `drift-analysis/src/graph/impact/dead_code.rs` — Dead code detection with 10 false-positive categories: entry points, event handlers, reflection targets, DI, test utilities, framework hooks, decorators/annotations, interface implementations, conditional compilation, dynamic imports
- [x] `P4-IMP-05` — Create `drift-analysis/src/graph/impact/path_finding.rs` — Dijkstra shortest path + K-shortest paths for impact visualization

### 4E — Test Topology (System 18) — `drift-analysis/src/graph/test_topology/`

> **V2-PREP:** 18-TEST-TOPOLOGY. 7-dimension quality scoring, 24 test smell detectors, 45+ frameworks.

- [x] `P4-TST-01` — Create `drift-analysis/src/graph/test_topology/mod.rs` — `pub mod` declarations + re-exports
- [x] `P4-TST-02` — Create `drift-analysis/src/graph/test_topology/types.rs` — `TestQualityScore` (7 dimensions: coverage breadth, depth, assertion density, mock ratio, isolation, freshness, stability), `TestSmell` enum (24 variants)
- [x] `P4-TST-03` — Create `drift-analysis/src/graph/test_topology/coverage.rs` — Coverage mapping via call graph BFS (test function → tested functions)
- [x] `P4-TST-04` — Create `drift-analysis/src/graph/test_topology/smells.rs` — 24 test smell detectors (mystery guest, eager test, lazy test, assertion roulette, etc.)
- [x] `P4-TST-05` — Create `drift-analysis/src/graph/test_topology/quality_scorer.rs` — 7-dimension quality scoring aggregation
- [x] `P4-TST-06` — Create `drift-analysis/src/graph/test_topology/minimum_set.rs` — Minimum test set computation via greedy set cover algorithm
- [x] `P4-TST-07` — Create `drift-analysis/src/graph/test_topology/frameworks.rs` — 45+ test framework detection and classification

### 4F — Phase 4 Storage & NAPI Extensions

- [x] `P4-STR-01` — Create `drift-storage/src/migrations/v004_graph.rs` — Phase 4 tables: `reachability_cache`, `taint_flows`, `error_gaps`, `impact_scores`, `test_coverage` (~30-35 cumulative)
- [x] `P4-STR-02` — Create `drift-storage/src/queries/graph.rs` — Reachability, taint, error handling, impact, test topology queries
- [x] `P4-NAPI-01` — Create `drift-napi/src/bindings/graph.rs` — NAPI bindings for all 5 graph intelligence systems (reachability, taint, error handling, impact, test topology)

### Phase 4 Tests

#### Reachability — Graph Scale & Engine Selection
- [x] `T4-RCH-01` — Create `drift-analysis/tests/reachability_test.rs` — Test forward/inverse BFS produces correct reachability results on known graph (verify exact reachable set)
- [x] `T4-RCH-02` — Test auto-select correctly chooses petgraph for <10K nodes and SQLite CTE for >10K nodes — verify selection logic, not just result
- [x] `T4-RCH-03` — Test sensitivity classification: SQL query reachable from user input → Critical, SQL query reachable only from admin function → Medium
- [x] `T4-RCH-04` — Test reachability cache: query same node twice, second query hits cache (verify via timing or cache hit counter)
- [x] `T4-RCH-05` — Test cache invalidation: modify graph (add edge), verify cached results for affected nodes are invalidated
- [x] `T4-RCH-06` — Test graph with 100K+ nodes: BFS completes in <50ms, memory stays under 200MB (no O(n²) blowup)
- [x] `T4-RCH-07` — Test cross-service reachability: function in service A calls API endpoint in service B — reachability crosses boundary
- [x] `T4-RCH-08` — Test field-level data flow: `user.email` flows through 3 functions, verify field tracking preserved at each hop
- [x] `T4-RCH-09` — Test empty graph (0 nodes) — returns empty reachability set, not error
- [x] `T4-RCH-10` — Test disconnected node — reachability set contains only itself

#### Taint Analysis — Source/Sink/Sanitizer Correctness & CWE Coverage
- [x] `T4-TNT-01` — Create `drift-analysis/tests/taint_test.rs` — Test taint analysis traces source→sink paths with sanitizer tracking (sanitized path not reported as vulnerability)
- [x] `T4-TNT-02` — Test at least 3 CWE categories produce valid findings: SQLi/CWE-89 (user input → SQL query), XSS/CWE-79 (user input → HTML output), command injection/CWE-78 (user input → exec)
- [x] `T4-TNT-03` — Test SARIF code flows generated for taint paths — verify flow steps match actual source→sink path
- [x] `T4-TNT-04` — Test TOML-driven registry loads custom sources/sinks — add custom source, verify taint propagates from it
- [x] `T4-TNT-05` — Test intraprocedural taint <1ms/function, interprocedural <100ms/function — performance contracts
- [x] `T4-TNT-06` — Test sanitizer ordering: `sanitize(taint(input))` is clean, `taint(sanitize(input))` is tainted — order matters
- [x] `T4-TNT-07` — Test taint through collections: tainted value inserted into array/map, value read from array/map is tainted
- [x] `T4-TNT-08` — Test recursive function summaries: function A calls itself with tainted data — no infinite loop, taint correctly tracked
- [x] `T4-TNT-09` — Test taint path with 20+ hops — verify complete path reported, not truncated
- [x] `T4-TNT-10` — Test `TaintError::PathTooLong` fires at configurable max depth (default 50) — prevents runaway analysis
- [x] `T4-TNT-11` — Test false-positive: tainted value passed through known sanitizer (e.g., `escapeHtml()`) — no finding reported
- [x] `T4-TNT-12` — Test all 17 sink types have at least 1 test case exercising them

#### Error Handling Analysis — Framework Coverage & Gap Detection
- [x] `T4-ERR-01` — Create `drift-analysis/tests/error_handling_test.rs` — Test error handling analysis identifies unhandled error paths across call graph (function throws, caller doesn't catch)
- [x] `T4-ERR-02` — Test framework-specific error boundaries detected for at least 5 frameworks (React ErrorBoundary, Express error middleware, Django middleware, Spring @ExceptionHandler, ASP.NET ExceptionFilter)
- [x] `T4-ERR-03` — Test error propagation chain: A calls B calls C, C throws, B doesn't catch, A catches — verify gap reported at B, not at A
- [x] `T4-ERR-04` — Test empty catch blocks detected as anti-pattern (swallowed errors)
- [x] `T4-ERR-05` — Test async error handling: unhandled promise rejection detected, `.catch()` handler recognized as handled

#### Impact Analysis — Blast Radius & Dead Code
- [x] `T4-IMP-01` — Create `drift-analysis/tests/impact_test.rs` — Test impact analysis computes blast radius with correct transitive closure (change in A affects B, C, D via call chain)
- [x] `T4-IMP-02` — Test dead code detection correctly excludes all 10 false-positive categories (test helpers, plugin entry points, serialization callbacks, etc.)
- [x] `T4-IMP-03` — Test blast radius with circular dependency: A→B→C→A — verify finite blast radius (not infinite), all 3 nodes included
- [x] `T4-IMP-04` — Test impact scoring: change to function called by 100 callers scores higher than function called by 2 callers
- [x] `T4-IMP-05` — Test dead code detection with dynamic dispatch: function only called via reflection — not flagged as dead (Dynamic resolution)

#### Test Topology — Coverage Mapping & Smell Detection
- [x] `T4-TST-01` — Create `drift-analysis/tests/test_topology_test.rs` — Test topology maps test→source coverage via call graph (test function calls source function → coverage link)
- [x] `T4-TST-02` — Test 24 test smell detectors on reference test suite — verify at least 10 smells detected (empty test, assertion-free, sleep in test, etc.)
- [x] `T4-TST-03` — Test minimum test set computation: given 100 tests covering 50 functions, compute minimum set that covers all 50 — verify set is smaller than 100
- [x] `T4-TST-04` — Test topology with mock/stub detection: test using mock doesn't count as covering the real implementation

#### Integration & Cross-System Verification
- [x] `T4-INT-01` — Integration: all 5 systems complete on 10K-file codebase in <15s total
- [x] `T4-INT-02` — Test all results persist to drift.db in their respective tables — verify foreign key integrity
- [x] `T4-INT-03` — Test NAPI exposes analysis functions for all 5 systems with correct TypeScript types
- [x] `T4-INT-04` — Test all 5 systems handle empty call graph gracefully (no crash, empty results)
- [x] `T4-INT-05` — Test all 5 systems handle SQLite CTE fallback path — force CTE mode, verify results match petgraph mode
- [x] `T4-INT-06` — Test cross-service reachability across microservice boundaries with 3 services
- [x] `T4-INT-07` — Test minimum test set computation produces valid covering set (every source function covered by at least 1 test)
- [x] `T4-INT-08` — Test taint + reachability integration: taint path that is also reachable from public API → severity boosted
- [x] `T4-INT-09` — Test error handling + impact integration: unhandled error in high-impact function → Critical severity

#### Build & Coverage Gate
- [x] `T4-INT-10` — `cargo tarpaulin -p drift-analysis` reports ≥80% line coverage for Phase 4 code
- [x] `T4-INT-11` — `cargo clippy -p drift-analysis` passes with zero warnings

### QG-4: Phase 4 Quality Gate (Milestone 4: "It Secures")

- [x] Forward/inverse BFS produces correct reachability results
- [x] Auto-select correctly chooses petgraph vs SQLite CTE based on graph size
- [x] Taint analysis traces source→sink paths with sanitizer tracking
- [x] At least 3 CWE categories produce valid findings
- [x] SARIF code flows generated for taint paths
- [x] Error handling analysis identifies unhandled error paths across call graph
- [x] Framework-specific error boundaries detected for at least 5 frameworks
- [x] Impact analysis computes blast radius with correct transitive closure
- [x] Dead code detection correctly excludes all 10 false-positive categories
- [x] Test topology maps test→source coverage via call graph
- [x] All results persist to drift.db
- [x] NAPI exposes analysis functions for all 5 systems
- [x] All 5 systems complete on 10K-file codebase in <15s total

---

## Phase 5: Structural Intelligence (Coupling, Constraints, Contracts, DNA, Security)

> **Goal:** Build the seven Level 2C and two Level 2D systems. Architecture health, contract verification, DNA metric, and security enrichment.
> **Estimated effort:** 4–6 weeks for Phase 5 gate. Contract Tracking continues through Phases 6–8 (~20 weeks total).
> **Parallelization:** 5 immediate tracks (Coupling, Contracts, Constants, Wrappers, Crypto) + 3 delayed tracks (Constraints, DNA, OWASP/CWE — start after Phase 4).
> **Cortex reference:** `cortex-causal/src/graph/dag_enforcement.rs` (Tarjan's SCC)

### 5A — Coupling Analysis (System 19) — `drift-analysis/src/structural/coupling/`

> **V2-PREP:** 19-COUPLING-ANALYSIS. Robert C. Martin metrics, Tarjan's SCC, 10-phase pipeline.
> **Performance targets:** <1s for 5K-module Tarjan SCC + Martin metrics.

- [x] `P5-CPL-01` — Create `drift-analysis/src/structural/mod.rs` — `pub mod` declarations for coupling, constraints, contracts, constants, wrappers, dna, owasp_cwe, crypto
- [x] `P5-CPL-02` — Create `drift-analysis/src/structural/coupling/mod.rs` — `pub mod` declarations + re-exports
- [x] `P5-CPL-03` — Create `drift-analysis/src/structural/coupling/types.rs` — `CouplingMetrics` (Ce, Ca, I, A, D), `ZoneClassification` (Zone of Pain, Zone of Uselessness, Main Sequence), `CycleInfo`
- [x] `P5-CPL-04` — Create `drift-analysis/src/structural/coupling/import_graph.rs` — Module boundary detection + import graph construction
- [x] `P5-CPL-05` — Create `drift-analysis/src/structural/coupling/martin_metrics.rs` — Ce (efferent), Ca (afferent), I (instability = Ce/(Ce+Ca)), A (abstractness), D (distance from main sequence = |A+I-1|)
- [x] `P5-CPL-06` — Create `drift-analysis/src/structural/coupling/cycle_detection.rs` — Tarjan's SCC via `petgraph::algo::tarjan_scc`, condensation graph, cycle break suggestions
- [x] `P5-CPL-07` — Create `drift-analysis/src/structural/coupling/zones.rs` — Zone classification + trend tracking

### 5B — Constraint System (System 20) — `drift-analysis/src/structural/constraints/`

> **V2-PREP:** 20-CONSTRAINT-SYSTEM. 12 invariant types, 4-stage pipeline, FreezingArchRule.
> **Delayed track:** Benefits from Phase 4 data. Start with parser-based constraints, add call-graph-based incrementally.

- [x] `P5-CON-01` — Create `drift-analysis/src/structural/constraints/mod.rs` — `pub mod` declarations + re-exports
- [x] `P5-CON-02` — Create `drift-analysis/src/structural/constraints/types.rs` — `Constraint`, `InvariantType` enum (12 variants: must_exist, must_not_exist, must_precede, must_follow, must_colocate, must_separate, data_flow, naming_convention, dependency_direction, layer_boundary, size_limit, complexity_limit)
- [x] `P5-CON-03` — Create `drift-analysis/src/structural/constraints/detector.rs` — `InvariantDetector`: AST-based detection (not regex — replaces v1's approach)
- [x] `P5-CON-04` — Create `drift-analysis/src/structural/constraints/synthesizer.rs` — `ConstraintSynthesizer`: mine constraints from existing code patterns
- [x] `P5-CON-05` — Create `drift-analysis/src/structural/constraints/store.rs` — `ConstraintStore`: persistence and retrieval
- [x] `P5-CON-06` — Create `drift-analysis/src/structural/constraints/verifier.rs` — `ConstraintVerifier`: verify constraints against codebase
- [x] `P5-CON-07` — Create `drift-analysis/src/structural/constraints/freezing.rs` — `FreezingArchRule`: snapshot constraints at a point in time, fail on regression

### 5C — Contract Tracking (System 21) — `drift-analysis/src/structural/contracts/`

> **V2-PREP:** 21-CONTRACT-TRACKING. 7 paradigms, 20+ backend extractors, 93 v1 features preserved.
> **Build estimate:** ~12,000 LOC Rust, ~20 weeks across 20 internal phases.
> **Build strategy:** Ship REST + GraphQL first (highest value). Add gRPC, AsyncAPI, tRPC, WebSocket, event-driven incrementally.

- [x] `P5-CTR-01` — Create `drift-analysis/src/structural/contracts/mod.rs` — `pub mod` declarations + re-exports
- [x] `P5-CTR-02` — Create `drift-analysis/src/structural/contracts/types.rs` — `Contract`, `Endpoint`, `Paradigm` enum (REST, GraphQL, gRPC, AsyncAPI, tRPC, WebSocket, EventDriven), `MismatchType` enum (7 variants: field missing, type mismatch, required/optional, enum value, nested shape, array/scalar, nullable), `BreakingChange` (20+ change types, 4 severity levels)
- [x] `P5-CTR-03` — Create `drift-analysis/src/structural/contracts/schema_parsers/mod.rs` — `pub mod` declarations + shared schema parser trait
- [x] `P5-CTR-03a` — Create `drift-analysis/src/structural/contracts/schema_parsers/openapi.rs` — OpenAPI 3.0/3.1 schema parser
- [x] `P5-CTR-03b` — Create `drift-analysis/src/structural/contracts/schema_parsers/graphql.rs` — GraphQL SDL schema parser
- [x] `P5-CTR-03c` — Create `drift-analysis/src/structural/contracts/schema_parsers/protobuf.rs` — Protobuf schema parser (gRPC)
- [x] `P5-CTR-03d` — Create `drift-analysis/src/structural/contracts/schema_parsers/asyncapi.rs` — AsyncAPI 2.x/3.0 schema parser
- [x] `P5-CTR-04` — Create `drift-analysis/src/structural/contracts/extractors/mod.rs` — `pub mod` declarations + shared extractor trait
- [x] `P5-CTR-04a` — Create `drift-analysis/src/structural/contracts/extractors/express.rs` — Express endpoint extractor
- [x] `P5-CTR-04b` — Create `drift-analysis/src/structural/contracts/extractors/fastify.rs` — Fastify endpoint extractor
- [x] `P5-CTR-04c` — Create `drift-analysis/src/structural/contracts/extractors/nestjs.rs` — NestJS endpoint extractor
- [x] `P5-CTR-04d` — Create `drift-analysis/src/structural/contracts/extractors/django.rs` — Django endpoint extractor
- [x] `P5-CTR-04e` — Create `drift-analysis/src/structural/contracts/extractors/flask.rs` — Flask endpoint extractor
- [x] `P5-CTR-04f` — Create `drift-analysis/src/structural/contracts/extractors/spring.rs` — Spring endpoint extractor
- [x] `P5-CTR-04g` — Create `drift-analysis/src/structural/contracts/extractors/aspnet.rs` — ASP.NET endpoint extractor
- [x] `P5-CTR-04h` — Create `drift-analysis/src/structural/contracts/extractors/rails.rs` — Rails endpoint extractor
- [x] `P5-CTR-04i` — Create `drift-analysis/src/structural/contracts/extractors/laravel.rs` — Laravel endpoint extractor
- [x] `P5-CTR-04j` — Create `drift-analysis/src/structural/contracts/extractors/gin.rs` — Gin endpoint extractor
- [x] `P5-CTR-04k` — Create `drift-analysis/src/structural/contracts/extractors/actix.rs` — Actix endpoint extractor
- [x] `P5-CTR-04l` — Create `drift-analysis/src/structural/contracts/extractors/nextjs.rs` — Next.js API route extractor
- [x] `P5-CTR-04m` — Create `drift-analysis/src/structural/contracts/extractors/trpc.rs` — tRPC router extractor
- [x] `P5-CTR-04n` — Create `drift-analysis/src/structural/contracts/extractors/frontend.rs` — Frontend/consumer library extractors (fetch, axios, SWR, TanStack Query, Apollo, urql, etc.)
- [x] `P5-CTR-05` — Create `drift-analysis/src/structural/contracts/matching.rs` — BE↔FE matching via path similarity + schema compatibility scoring
- [x] `P5-CTR-06` — Create `drift-analysis/src/structural/contracts/breaking_changes.rs` — Breaking change classifier: 20+ change types, paradigm-specific rules
- [x] `P5-CTR-07` — Create `drift-analysis/src/structural/contracts/confidence.rs` — Bayesian 7-signal confidence model (path similarity, field overlap, type compatibility, response shape match, temporal stability, cross-validation, consumer agreement)

### 5D — Constants & Environment (System 22) — `drift-analysis/src/structural/constants/`

> **V2-PREP:** 22-CONSTANTS-ENVIRONMENT. 13-phase unified pipeline, 150+ secret patterns, Shannon entropy.

- [x] `P5-CST-01` — Create `drift-analysis/src/structural/constants/mod.rs` — `pub mod` declarations + re-exports
- [x] `P5-CST-02` — Create `drift-analysis/src/structural/constants/types.rs` — `Constant`, `Secret`, `MagicNumber`, `EnvVariable`, `SecretSeverity` (7 tiers: Critical, High, Medium, Low, Info, FP, Suppressed)
- [x] `P5-CST-03` — Create `drift-analysis/src/structural/constants/extractor.rs` — Phase 1: Constant extraction from AST (9+ languages)
- [x] `P5-CST-04` — Create `drift-analysis/src/structural/constants/magic_numbers.rs` — Phase 2: Magic number detection via AST (scope-aware, context-aware, replaces v1 regex)
- [x] `P5-CST-05` — Create `drift-analysis/src/structural/constants/secrets.rs` — Phase 3: Secret detection engine (150+ patterns, format validation as 3rd confidence signal — AWS AKIA*, GitHub ghp_*), CWE-798/CWE-321/CWE-547 mappings
- [x] `P5-CST-06` — Create `drift-analysis/src/structural/constants/entropy.rs` — Shannon entropy scoring for high-entropy string detection (hybrid pattern + entropy)
- [x] `P5-CST-07` — Create `drift-analysis/src/structural/constants/inconsistency.rs` — Phase 4: Inconsistency detection (fuzzy name matching, camelCase ↔ snake_case normalization)
- [x] `P5-CST-08` — Create `drift-analysis/src/structural/constants/dead_constants.rs` — Phase 5: Dead constant detection via call graph integration
- [x] `P5-CST-09` — Create `drift-analysis/src/structural/constants/env_extraction.rs` — Phases 6-9: Environment variable extraction (9+ languages, 15+ access methods), .env file parsing, missing variable detection, framework-specific env detection (Next.js NEXT_PUBLIC_*, Vite VITE_*, Django DJANGO_*, Spring)
- [x] `P5-CST-10` — Create `drift-analysis/src/structural/constants/sensitivity.rs` — Phase 10: 4-tier sensitivity classification
- [x] `P5-CST-11` — Create `drift-analysis/src/structural/constants/health.rs` — Phases 11-12: Confidence scoring (Bayesian + Shannon entropy) + health score calculation

### 5E — Wrapper Detection (System 23) — `drift-analysis/src/structural/wrappers/`

> **V2-PREP:** 23-WRAPPER-DETECTION. 16 categories, 150+ primitive signatures, 7-signal confidence.
> **Performance targets:** <2ms per file for 150+ pattern RegexSet.

- [x] `P5-WRP-01` — Create `drift-analysis/src/structural/wrappers/mod.rs` — `pub mod` declarations + re-exports
- [x] `P5-WRP-02` — Create `drift-analysis/src/structural/wrappers/types.rs` — `Wrapper`, `WrapperCategory` enum (16 variants: StateManagement, DataFetching, FormHandling, Routing, Authentication, ErrorBoundary, Caching, Styling, Animation, Accessibility, Logging, ApiClient, Middleware, Testing, Internationalization, Other), `WrapperHealth` (consistency, coverage, abstraction depth → 0-100)
- [x] `P5-WRP-03` — Create `drift-analysis/src/structural/wrappers/detector.rs` — 8 framework detection patterns with 150+ primitive function signatures across 8 frameworks (React, Vue, Angular, Svelte, SolidJS, Express, Next.js, TanStack Query)
- [x] `P5-WRP-04` — Create `drift-analysis/src/structural/wrappers/confidence.rs` — Enhanced 7-signal confidence model (import match, name match, call-site match, export status, usage count, depth analysis, framework specificity)
- [x] `P5-WRP-05` — Create `drift-analysis/src/structural/wrappers/multi_primitive.rs` — Multi-primitive detection (single function wrapping multiple primitives)
- [x] `P5-WRP-06` — Create `drift-analysis/src/structural/wrappers/regex_set.rs` — RegexSet optimization for single-pass multi-pattern primitive matching
- [x] `P5-WRP-07` — Create `drift-analysis/src/structural/wrappers/clustering.rs` — Clustering for wrapper family identification
- [x] `P5-WRP-08` — Create `drift-analysis/src/structural/wrappers/security.rs` — Security wrapper categories (auth, validation, sanitization, encryption, access control) → taint analysis sanitizer registry bridge

### 5F — DNA System (System 24) — `drift-analysis/src/structural/dna/`

> **V2-PREP:** 24-DNA-SYSTEM. 10 gene extractors, health scoring, mutation detection.
> **Delayed track:** Capstone metric. Build gene extractor framework first, add extractors as data sources ship.
> **Build estimate:** ~10 days.

- [x] `P5-DNA-01` — Create `drift-analysis/src/structural/dna/mod.rs` — `pub mod` declarations + re-exports
- [x] `P5-DNA-02` — Create `drift-analysis/src/structural/dna/types.rs` — `Gene`, `Allele`, `DnaProfile`, `Mutation`, `MutationImpact` (high/medium/low), `DnaHealthScore` (0-100)
- [x] `P5-DNA-03` — Create `drift-analysis/src/structural/dna/extractor.rs` — Gene extractor framework trait + registry
- [x] `P5-DNA-04` — Create `drift-analysis/src/structural/dna/extractors/mod.rs` — `pub mod` for 10 gene extractors
- [x] `P5-DNA-05` — Create `drift-analysis/src/structural/dna/extractors/variant_handling.rs` — Frontend gene: variant-handling patterns
- [x] `P5-DNA-06` — Create `drift-analysis/src/structural/dna/extractors/responsive_approach.rs` — Frontend gene: responsive-approach patterns
- [x] `P5-DNA-07` — Create `drift-analysis/src/structural/dna/extractors/state_styling.rs` — Frontend gene: state-styling patterns
- [x] `P5-DNA-08` — Create `drift-analysis/src/structural/dna/extractors/theming.rs` — Frontend gene: theming patterns
- [x] `P5-DNA-09` — Create `drift-analysis/src/structural/dna/extractors/spacing.rs` — Frontend gene: spacing-philosophy patterns
- [x] `P5-DNA-10` — Create `drift-analysis/src/structural/dna/extractors/animation.rs` — Frontend gene: animation-approach patterns
- [x] `P5-DNA-11` — Create `drift-analysis/src/structural/dna/extractors/api_response.rs` — Backend gene: api-response-format
- [x] `P5-DNA-12` — Create `drift-analysis/src/structural/dna/extractors/error_response.rs` — Backend gene: error-response-format
- [x] `P5-DNA-13` — Create `drift-analysis/src/structural/dna/extractors/logging_format.rs` — Backend gene: logging-format
- [x] `P5-DNA-14` — Create `drift-analysis/src/structural/dna/extractors/config_pattern.rs` — Backend gene: config-pattern
- [x] `P5-DNA-15` — Create `drift-analysis/src/structural/dna/health.rs` — Health scoring: `healthScore = consistency(40%) + confidence(30%) + mutations(20%) + coverage(10%)`, clamped 0-100
- [x] `P5-DNA-16` — Create `drift-analysis/src/structural/dna/mutations.rs` — Mutation detection between snapshots (SHA-256 mutation IDs), impact classification
- [x] `P5-DNA-17` — Create `drift-analysis/src/structural/dna/context_builder.rs` — 4-level AI context builder: overview (~2K tokens), standard (~6K), deep (~12K), full (unlimited)
- [x] `P5-DNA-18` — Create `drift-analysis/src/structural/dna/regex_set.rs` — RegexSet optimization: ~120 patterns matched in single pass per file

### 5G — OWASP/CWE Mapping (System 26) — `drift-analysis/src/structural/owasp_cwe/`

> **V2-PREP:** 26-OWASP-CWE-MAPPING. Enrichment-only (does NOT detect). 173 detector → CWE/OWASP mapping matrix.
> **Delayed track:** Benefits from Phase 4 taint/reachability data.

- [x] `P5-OWS-01` — Create `drift-analysis/src/structural/owasp_cwe/mod.rs` — `pub mod` declarations + re-exports
- [x] `P5-OWS-02` — Create `drift-analysis/src/structural/owasp_cwe/types.rs` — `SecurityFinding` unified type, `CweEntry`, `OwaspCategory`, `ComplianceReport`
- [x] `P5-OWS-03` — Create `drift-analysis/src/structural/owasp_cwe/registry.rs` — Compile-time `const` registries: 173 detector → CWE/OWASP mappings, OWASP 2025 Top 10 (10/10 coverage), CWE Top 25 2025 (20/25 fully + 5/25 partially). User extensions via TOML
- [x] `P5-OWS-04` — Create `drift-analysis/src/structural/owasp_cwe/enrichment.rs` — `FindingEnrichmentPipeline`: `enrich_detector_violation()`, `enrich_taint_flow()`, `enrich_secret()`, `enrich_error_gap()`, `enrich_boundary_violation()`
- [x] `P5-OWS-05` — Create `drift-analysis/src/structural/owasp_cwe/wrapper_bridge.rs` — Wrapper → sanitizer bridge: security wrappers mapped to taint analysis sanitizer registry + wrapper bypass detection
- [x] `P5-OWS-06` — Create `drift-analysis/src/structural/owasp_cwe/posture.rs` — Security posture score (composite 0-100), compliance report generator, SARIF taxonomy integration

### 5H — Cryptographic Failure Detection (System 27) — NET NEW — `drift-analysis/src/structural/crypto/`

> **V2-PREP:** 27-CRYPTOGRAPHIC-FAILURE-DETECTION. 14 detection categories, 261 patterns, 12 languages.
> **Build estimate:** 5 weeks across 8 internal phases.

- [x] `P5-CRY-01` — Create `drift-analysis/src/structural/crypto/mod.rs` — `pub mod` declarations + re-exports
- [x] `P5-CRY-02` — Create `drift-analysis/src/structural/crypto/types.rs` — `CryptoFinding`, `CryptoCategory` enum (14 variants: WeakHash, DeprecatedCipher, HardcodedKey, EcbMode, StaticIv, InsufficientKeyLen, DisabledTls, InsecureRandom, JwtConfusion, PlaintextPassword, WeakKdf, MissingEncryption, CertPinningBypass, NonceReuse)
- [x] `P5-CRY-03` — Create `drift-analysis/src/structural/crypto/patterns.rs` — 261 patterns across 12 languages (Python, JS/TS, Java, C#, Go, Ruby, PHP, Kotlin, Swift, Rust, C/C++, Scala), TOML-based definitions
- [x] `P5-CRY-04` — Create `drift-analysis/src/structural/crypto/detector.rs` — Detection engine with import-check short-circuit optimization, OWASP A04:2025 coverage, CWE-1439 category mapping
- [x] `P5-CRY-05` — Create `drift-analysis/src/structural/crypto/confidence.rs` — 4-factor crypto-specific confidence scoring
- [x] `P5-CRY-06` — Create `drift-analysis/src/structural/crypto/health.rs` — Crypto health score calculator
- [x] `P5-CRY-07` — Create `drift-analysis/src/structural/crypto/remediation.rs` — Remediation suggestion engine

### 5J — Module Decomposition Enhancement — `drift-analysis/src/structural/decomposition/`

> **Source:** SPECIFICATION-ENGINE-NOVEL-LOOP-ENHANCEMENT.md §Phase 5 Additions.
> **D1 compliance:** All types and algorithms live in `drift-analysis`. They accept priors as parameters but have ZERO knowledge of Cortex. In standalone mode, priors are empty and the algorithm falls back to standard decomposition. The bridge (Phase 9) retrieves priors from Cortex and passes them in.

- [x] `P5-DECOMP-11` — Add `DecompositionDecision` type in `drift-analysis` (no Cortex imports) — includes `BoundaryAdjustment` enum (Split, Merge, Reclassify), DNA similarity score, confidence, causal narrative
- [x] `P5-DECOMP-12` — Implement `decompose_with_priors(index, dna, priors)` — priors param is `&[DecompositionDecision]`, empty in standalone mode. Apply priors as boundary adjustments with weight = confidence × DNA similarity. Thresholds: Split ≥ 0.4, Merge ≥ 0.5, Reclassify ≥ 0.3. Re-score cohesion/coupling after adjustments
- [x] `P5-DECOMP-13` — Add `DecompositionPriorProvider` trait in `drift-core` with no-op default returning empty vec (same pattern as `DriftEventHandler`)
- [x] `P5-DECOMP-14` — Add `AppliedPrior` annotation to `LogicalModule` — records source project DNA hash, adjustment type, applied weight, and causal narrative for human review
- [x] `P5-DECOMP-15` — Storage: `decomposition_decisions` table in drift.db (Drift's own DB, not cortex.db) — stores boundary adjustments linked to DNA profile hashes for local persistence

### 5K — Phase 5 Storage & NAPI Extensions

- [x] `P5-STR-01` — Create `drift-storage/src/migrations/v005_structural.rs` — Phase 5 tables: `coupling_metrics`, `constraints`, `contracts`, `constants`, `secrets`, `wrappers`, `dna_genes`, `crypto_findings`, `owasp_findings`, `decomposition_decisions` (~49-57 cumulative)
- [x] `P5-STR-02` — Create `drift-storage/src/queries/structural.rs` — Coupling, constraints, contracts, constants, wrappers, DNA, OWASP, crypto, decomposition queries
- [x] `P5-NAPI-01` — Create `drift-napi/src/bindings/structural.rs` — NAPI bindings for all Phase 5 systems

### Phase 5 Tests

#### Coupling Analysis — Metric Correctness & Cycle Detection
- [x] `T5-CPL-01` — Create `drift-analysis/tests/coupling_test.rs` — Test Martin metrics (Ce, Ca, I, A, D) computed correctly on known module graph with hand-calculated expected values
- [x] `T5-CPL-02` — Test zone classification: module with high Ce + low Ca → Zone of Pain, module with low Ce + high Ca → Zone of Uselessness, module near I+A=1 → Main Sequence
- [x] `T5-CPL-03` — Test Tarjan's SCC on graph with 3 known cycles — verify all 3 cycles detected with correct member sets
- [x] `T5-CPL-04` — Test cycle break suggestions: for each detected cycle, verify at least 1 edge removal suggestion that would break the cycle
- [x] `T5-CPL-05` — Test coupling analysis on 5K-module graph completes in <1s (performance contract)
- [x] `T5-CPL-06` — Test trend tracking: compute metrics at T1 and T2, verify trend direction (improving/degrading) correctly identified
- [x] `T5-CPL-07` — Test single-module graph (no dependencies) — all metrics at zero/neutral, no crash

#### Constraints — Invariant Verification & Regression Detection
- [x] `T5-CON-01` — Create `drift-analysis/tests/constraints_test.rs` — Test at least 6 of 12 invariant types verified (must_exist, must_not_exist, must_precede, naming_convention, dependency_direction, layer_boundary)
- [x] `T5-CON-02` — Test AST-based constraint verification (not regex) — constraint on function naming convention uses AST function nodes, not string matching
- [x] `T5-CON-03` — Test FreezingArchRule: take baseline snapshot, introduce violation, verify regression detected
- [x] `T5-CON-04` — Test constraint synthesis: mine naming convention from 20 files following `camelCase`, verify convention synthesized automatically
- [x] `T5-CON-05` — Test conflicting constraints: `must_exist("foo")` + `must_not_exist("foo")` → `ConstraintError::ConflictingConstraints`
- [x] `T5-CON-06` — Test constraint verification with empty codebase — all `must_exist` constraints fail, all `must_not_exist` pass

#### Contracts — Endpoint Extraction & Breaking Change Detection
- [x] `T5-CTR-01` — Create `drift-analysis/tests/contracts_test.rs` — Test contract tracking extracts endpoints from at least 5 REST frameworks (Express, NestJS, Django, Spring, Rails)
- [x] `T5-CTR-02` — Test breaking change classifier: field removal → breaking, field addition → non-breaking, type change (string→number) → breaking, optional→required → breaking
- [x] `T5-CTR-03` — Test 7-signal Bayesian confidence model: verify each signal independently affects confidence score
- [x] `T5-CTR-04` — Test OpenAPI 3.1 schema parser: parse reference OpenAPI spec, verify all endpoints extracted with correct methods, paths, and parameter types
- [x] `T5-CTR-05` — Test GraphQL SDL parser: parse reference schema, verify all queries, mutations, and subscriptions extracted
- [x] `T5-CTR-06` — Test BE↔FE matching: Express endpoint `GET /api/users` matched to `fetch('/api/users')` call in frontend — verify match with confidence >0.8
- [x] `T5-CTR-07` — Test contract with no matching consumer — flagged as potentially unused, not error
- [x] `T5-CTR-08` — Test endpoint matching <1ms per pair (performance contract)

#### Constants & Secrets — Detection Accuracy & False Positive Control
- [x] `T5-CST-01` — Create `drift-analysis/tests/constants_test.rs` — Test secret detection identifies at least 50 pattern types with entropy scoring
- [x] `T5-CST-02` — Test magic number detection uses AST context: `const TIMEOUT = 3000` not flagged (named constant), bare `3000` in function call flagged
- [x] `T5-CST-03` — Test .env file parsing and missing variable detection: code references `process.env.API_KEY`, .env file missing `API_KEY` → flagged
- [x] `T5-CST-04` — Test framework-specific env detection: `NEXT_PUBLIC_*` in Next.js, `VITE_*` in Vite, `DJANGO_*` in Django, `spring.*` in Spring
- [x] `T5-CST-05` — Test secret detection false-positive rate <5% on reference corpus of 1000 files with known secrets and known non-secrets
- [x] `T5-CST-06` — Test Shannon entropy scoring: high-entropy string `aK3$mP9!xQ2@` scores higher than low-entropy `aaaaaaaaaa`
- [x] `T5-CST-07` — Test format validation: `AKIA` prefix for AWS keys, `ghp_` prefix for GitHub tokens — format match boosts confidence
- [x] `T5-CST-08` — Test dead constant detection: constant defined but never referenced → flagged via call graph integration
- [x] `T5-CST-09` — Test sensitivity classification: AWS secret key → Critical, generic API key → High, debug flag → Low

#### Wrappers — Framework Detection & Security Bridge
- [x] `T5-WRP-01` — Create `drift-analysis/tests/wrappers_test.rs` — Test wrapper detection across 3+ frameworks (React hooks, Vue composables, Express middleware)
- [x] `T5-WRP-02` — Test RegexSet single-pass performance: 150+ patterns matched in <2ms per file
- [x] `T5-WRP-03` — Test security wrapper → taint sanitizer bridge: auth wrapper registered as sanitizer, taint path through auth wrapper → clean
- [x] `T5-WRP-04` — Test wrapper bypass detection: code path that skips security wrapper → flagged as potential vulnerability
- [x] `T5-WRP-05` — Test multi-primitive detection: single function wrapping `useState` + `useEffect` → detected as composite wrapper
- [x] `T5-WRP-06` — Test wrapper health score: consistent wrapper usage across project → high score, inconsistent → low score

#### DNA — Gene Extraction & Mutation Detection
- [x] `T5-DNA-01` — Create `drift-analysis/tests/dna_test.rs` — Test DNA health scores from at least 5 gene extractors produce scores in [0, 100] range
- [x] `T5-DNA-02` — Test mutation detection between snapshots: change naming convention in 5 files → mutation detected with correct impact classification
- [x] `T5-DNA-03` — Test 4-level AI context builder token budgets: overview ~2K tokens (±10%), standard ~6K, deep ~12K, full unlimited
- [x] `T5-DNA-04` — Test health score formula: `consistency(40%) + confidence(30%) + mutations(20%) + coverage(10%)` — verify weights applied correctly
- [x] `T5-DNA-05` — Test RegexSet ~120 patterns in single pass per file — no per-pattern overhead
- [x] `T5-DNA-06` — Test mutation ID determinism: same mutation produces same SHA-256 ID across runs

#### Module Decomposition Enhancement — Prior Application, Scoring & Transfer
> **Source:** SPECIFICATION-ENGINE-TEST-PLAN.md §Phase 5 Tests.
> **File:** `drift-analysis/tests/decomposition_test.rs`
> **D1:** Zero Cortex imports. `DecompositionPriorProvider` uses no-op default.

##### Happy Path
- [x] `T5-DECOMP-01` — **6-signal decomposition produces valid modules.** Feed a synthetic `StructuralIndex` with 3 clear clusters (disjoint call graphs, separate tables, different conventions). Assert: 3 `LogicalModule`s returned, each with non-empty `files`, `public_interface`, `data_dependencies`. Cohesion > 0.5 for all, coupling < 0.3 for all
- [x] `T5-DECOMP-02` — **Public interface extraction is correct.** Create 2 modules where Module A calls 3 functions in Module B. Assert: those 3 functions appear in Module B's `public_interface` and NOT in `internal_functions`
- [x] `T5-DECOMP-03` — **Data dependencies extracted per module.** Module touches `users` (Read) and `orders` (ReadWrite) tables via Sequelize. Assert: `data_dependencies` contains both with correct `DataDependencyKind::Database`, correct operations, and `sensitive_fields` includes `email` from boundary detection
- [x] `T5-DECOMP-04` — **Convention profile populated.** Module uses camelCase naming, try/catch error handling, winston logging. Assert: `convention_profile` reflects all three
- [x] `T5-DECOMP-05` — **Module dependency graph is acyclic.** Decompose a codebase with 5 modules. Assert: the dependency graph between modules (from `ModuleDependency`) has no cycles. Verify with topological sort
- [x] `T5-DECOMP-06` — **`decompose_with_priors()` applies a Split prior.** Provide one `DecompositionDecision` with `BoundaryAdjustment::Split` at weight 0.6. Standard decomposition clusters auth+users together. Assert: after priors, auth and users are separate modules. `AppliedPrior` annotation present on both
- [x] `T5-DECOMP-07` — **`decompose_with_priors()` with empty priors equals standard decomposition.** Run both `decompose()` and `decompose_with_priors(index, dna, &[])`. Assert: identical output
- [x] `T5-DECOMP-08` — **`DecompositionPriorProvider` no-op default returns empty vec.** Instantiate the trait's default impl. Assert: `get_priors()` returns `Ok(vec![])`

##### Edge Cases
- [x] `T5-DECOMP-09` — **Single-file codebase → single module.** Index with 1 file, 1 function, 0 call edges. Assert: exactly 1 `LogicalModule` with cohesion 1.0, coupling 0.0
- [x] `T5-DECOMP-10` — **10,000-file codebase completes in < 10s.** Synthetic index with 10K files, 50K call edges, 200 tables. Assert: decomposition completes within time budget
- [x] `T5-DECOMP-11` — **All files in one SCC → single module.** Every function calls every other function (complete graph). Assert: 1 module, cohesion 1.0
- [x] `T5-DECOMP-12` — **Zero call edges → directory-based decomposition.** Index with files but no call edges. Assert: modules formed from directory structure signal alone
- [x] `T5-DECOMP-13` — **Prior with weight exactly at threshold (0.4 for Split).** Assert: prior IS applied (boundary inclusive). Prior at 0.399 → NOT applied
- [x] `T5-DECOMP-14` — **Prior references a module that doesn't exist in current decomposition.** Assert: prior is skipped gracefully, no panic, no corruption
- [x] `T5-DECOMP-15` — **Cohesion and coupling scores are always in [0.0, 1.0].** Generate 100 random decompositions with varying inputs. Assert: all scores clamped
- [x] `T5-DECOMP-16` — **DNA similarity of 0.0 → no priors applied.** Provide priors with DNA similarity 0.0 to current profile. Assert: zero priors applied, output equals standard decomposition

##### Adversarial
- [x] `T5-DECOMP-17` — **Module name with SQL injection payload.** File path contains `'; DROP TABLE modules; --`. Assert: module name is sanitized or escaped before storage. Query `decomposition_decisions` table — it still exists
- [x] `T5-DECOMP-18` — **Module name with 100KB Unicode string.** Assert: module name is truncated to reasonable length (≤ 1024 chars), no OOM
- [x] `T5-DECOMP-19` — **NaN in coupling metrics.** Inject NaN into a call edge weight. Assert: decomposition handles gracefully (skip edge or treat as 0.0), does not propagate NaN into cohesion/coupling scores
- [x] `T5-DECOMP-20` — **Negative confidence in prior.** `DecompositionDecision` with confidence -0.5. Assert: prior is rejected or clamped to 0.0, not applied with negative weight
- [x] `T5-DECOMP-21` — **Contradictory priors.** Two priors: one says Split(auth, users), other says Merge(auth, users), both weight 0.6. Assert: deterministic resolution (e.g., higher confidence wins, or first-wins), no infinite loop

##### Concurrency
- [x] `T5-DECOMP-22` — **Parallel decomposition of same index from 4 threads.** Assert: all 4 produce identical results, no data races
- [x] `T5-DECOMP-23` — **Decomposition while index is being updated.** One thread runs decomposition, another thread adds files to the index. Assert: decomposition either sees a consistent snapshot or returns an error — never a partial/torn read

##### Corruption Recovery
- [x] `T5-DECOMP-24` — **`decomposition_decisions` table missing.** Delete the table from drift.db, then call `decompose_with_priors()`. Assert: graceful fallback to standard decomposition (no priors), table is recreated on next write
- [x] `T5-DECOMP-25` — **Corrupted prior in `decomposition_decisions` table.** Insert a row with invalid JSON in the `adjustment` column. Assert: that row is skipped, valid rows still loaded, warning logged
- [x] `T5-DECOMP-26` — **Interrupted write to `decomposition_decisions`.** Simulate crash mid-transaction (write 3 of 5 decisions, then abort). Assert: table has 0 new rows (transaction rolled back), not 3 partial rows

##### Regression
- [x] `T5-DECOMP-27` — **Decomposition is deterministic.** Same input → same output, 10 consecutive runs. Assert: module IDs, file assignments, scores are byte-identical
- [x] `T5-DECOMP-28` — **Empty `public_interface` only when module has zero external callers.** If any function in the module is called from outside, `public_interface` must be non-empty
- [x] `T5-DECOMP-29` — **`estimated_complexity` matches sum of file line counts.** Assert: `estimated_complexity` equals total lines across all files in the module (±5% for comment stripping)

#### OWASP/CWE — Mapping Completeness & Enrichment
- [x] `T5-OWS-01` — Create `drift-analysis/tests/owasp_cwe_test.rs` — Test OWASP/CWE mapping enriches findings with correct CWE IDs (verify against known detector→CWE mapping table)
- [x] `T5-OWS-02` — Test security posture score computation: all gates passing → score near 100, critical findings → score drops proportionally
- [x] `T5-OWS-03` — Test OWASP 2025 Top 10 coverage: verify all 10 categories have at least 1 detector mapped
- [x] `T5-OWS-04` — Test CWE Top 25 2025 coverage: verify 20/25 fully mapped, 5/25 partially mapped
- [x] `T5-OWS-05` — Test wrapper bypass detection integration: security wrapper bypassed → enriched with CWE-862 (Missing Authorization)

#### Crypto — Detection Accuracy & Language Coverage
- [x] `T5-CRY-01` — Create `drift-analysis/tests/crypto_test.rs` — Test crypto detection identifies weak hash (MD5, SHA1) and deprecated cipher (DES, RC4) usage
- [x] `T5-CRY-02` — Test 261 patterns across at least 5 languages (Python, JS/TS, Java, Go, Rust) — verify no false negatives on OWASP test vectors
- [x] `T5-CRY-03` — Test import-check short-circuit: file with no crypto imports → skip all 261 patterns (performance optimization)
- [x] `T5-CRY-04` — Test all 14 crypto categories have at least 1 test case (WeakHash, DeprecatedCipher, HardcodedKey, EcbMode, StaticIv, InsufficientKeyLen, DisabledTls, InsecureRandom, JwtConfusion, PlaintextPassword, WeakKdf, MissingEncryption, CertPinningBypass, NonceReuse)
- [x] `T5-CRY-05` — Test crypto health score: project using only AES-256-GCM → high score, project using MD5 for password hashing → critical score
- [x] `T5-CRY-06` — Test remediation suggestions: MD5 usage → suggest SHA-256 or SHA-3, DES → suggest AES-256

#### Integration & Performance Contracts
- [x] `T5-INT-01` — Integration: all Phase 5 results persist to drift.db — verify all 9 tables created with correct schemas
- [x] `T5-INT-02` — Test NAPI exposes all Phase 5 query functions with correct TypeScript types
- [x] `T5-INT-03` — Test wrapper bypass detection identifies code paths skipping security wrappers (end-to-end with taint)
- [x] `T5-INT-04` — Test DNA RegexSet ~120 patterns in single pass per file — benchmark
- [x] `T5-INT-05` — Performance: coupling analysis <1s for 5K modules
- [x] `T5-INT-06` — Performance: contract endpoint matching <1ms per pair
- [x] `T5-INT-07` — Phase 5→6 precondition: coupling metrics computed for ≥3 modules, ≥1 constraint passing, ≥1 contract tracked, DNA profile for ≥1 gene
- [x] `T5-INT-08` — Test all Phase 5 systems handle empty codebase gracefully (no crash, sensible defaults)

#### Build & Coverage Gate
- [x] `T5-INT-09` — `cargo tarpaulin -p drift-analysis` reports ≥80% line coverage for Phase 5 code
- [x] `T5-INT-10` — `cargo clippy -p drift-analysis` passes with zero warnings

### QG-5: Phase 5 Quality Gate

- [x] Coupling analysis produces Martin metrics and detects cycles via Tarjan's SCC
- [x] Zone classification correctly identifies Zone of Pain / Uselessness / Main Sequence
- [x] Constraint system verifies at least 6 of 12 invariant types
- [x] Contract tracking extracts endpoints from at least 5 REST frameworks
- [x] Secret detection identifies at least 50 pattern types with entropy scoring
- [x] Magic number detection uses AST context (not regex)
- [x] Wrapper detection identifies thin delegation patterns across 3+ frameworks
- [x] DNA system produces health scores from at least 5 gene extractors
- [x] OWASP/CWE mapping enriches findings with correct CWE IDs
- [x] Crypto detection identifies weak hash and deprecated cipher usage
- [x] `decompose_with_priors()` produces valid modules and applies priors correctly
- [x] `DecompositionPriorProvider` no-op default returns empty vec (D1 compliance)
- [x] Decomposition is deterministic (same input → same output)
- [x] All results persist to drift.db in their respective tables

---

## Phase 6: Enforcement (Rules, Gates, Policy, Audit, Feedback)

> **Goal:** Transform analysis into actionable pass/fail decisions. Where Drift goes from "informational" to "actionable."
> **Estimated effort:** 2–3 weeks. Partial overlap: Level 0 (Rules + Feedback core), Level 1 (Gates + SARIF), Level 2 (Policy ∥ Audit), Level 3 (integration).
> **Internal ordering:** Rules Engine → Quality Gates → (Policy Engine ∥ Audit System), Feedback Loop parallel with Rules Engine.
> **Key output:** SARIF 2.1.0 reporter — build early, it's the key to GitHub Code Scanning integration.

### 6A — Rules Engine Evaluator — `drift-analysis/src/enforcement/rules/`

> **Spec coverage:** Implemented within each gate's evaluate() method. See 09-QG-V2-PREP §5, §18, §24.

- [x] `P6-RUL-01` — Create `drift-analysis/src/enforcement/mod.rs` — `pub mod` declarations for rules, gates, policy, audit, feedback, reporters
- [x] `P6-RUL-02` — Create `drift-analysis/src/enforcement/rules/mod.rs` — `pub mod` declarations + re-exports
- [x] `P6-RUL-03` — Create `drift-analysis/src/enforcement/rules/types.rs` — `Violation` (file, line, column, severity, pattern_id, message, quick_fix), `Severity` enum (Error, Warning, Info, Hint), `QuickFix`
- [x] `P6-RUL-04` — Create `drift-analysis/src/enforcement/rules/evaluator.rs` — Pattern matcher → violations → severity assignment, maps detected patterns + outliers to actionable violations
- [x] `P6-RUL-05` — Create `drift-analysis/src/enforcement/rules/quick_fixes.rs` — 7 fix strategies: add import, rename, extract function, wrap in try/catch, add type annotation, add test, add documentation
- [x] `P6-RUL-06` — Create `drift-analysis/src/enforcement/rules/suppression.rs` — Inline suppression system (`drift-ignore` comments)

### 6B — Quality Gates (System 09) — `drift-analysis/src/enforcement/gates/`

> **V2-PREP:** 09-QUALITY-GATES. 6 gates, DAG-based orchestrator, progressive enforcement.

- [x] `P6-GAT-01` — Create `drift-analysis/src/enforcement/gates/mod.rs` — `pub mod` declarations + re-exports
- [x] `P6-GAT-02` — Create `drift-analysis/src/enforcement/gates/types.rs` — `GateResult` (pass/fail/warn, violations, metrics), `GateConfig`, `GateDependency`
- [x] `P6-GAT-03` — Create `drift-analysis/src/enforcement/gates/orchestrator.rs` — DAG-based gate orchestrator (gates can depend on other gates), topological sort execution
- [x] `P6-GAT-04` — Create `drift-analysis/src/enforcement/gates/pattern_compliance.rs` — Gate 1: Are approved patterns followed?
- [x] `P6-GAT-05` — Create `drift-analysis/src/enforcement/gates/constraint_verification.rs` — Gate 2: Are architectural constraints met?
- [x] `P6-GAT-06` — Create `drift-analysis/src/enforcement/gates/security_boundaries.rs` — Gate 3: Are sensitive fields protected?
- [x] `P6-GAT-07` — Create `drift-analysis/src/enforcement/gates/test_coverage.rs` — Gate 4: Is coverage above threshold?
- [x] `P6-GAT-08` — Create `drift-analysis/src/enforcement/gates/error_handling.rs` — Gate 5: Are errors properly handled?
- [x] `P6-GAT-09` — Create `drift-analysis/src/enforcement/gates/regression.rs` — Gate 6: Has health score declined?
- [x] `P6-GAT-10` — Create `drift-analysis/src/enforcement/gates/progressive.rs` — Progressive enforcement: warn → error over time, configurable ramp-up, new-code-first enforcement

### 6C — Reporters — `drift-analysis/src/enforcement/reporters/`

> Build SARIF first (Phase 6). Remaining reporters in Phase 8.

- [x] `P6-RPT-01` — Create `drift-analysis/src/enforcement/reporters/mod.rs` — `pub mod` declarations + reporter trait
- [x] `P6-RPT-02` — Create `drift-analysis/src/enforcement/reporters/sarif.rs` — SARIF 2.1.0 reporter with CWE + OWASP taxonomies (key to GitHub Code Scanning)
- [x] `P6-RPT-03` — Create `drift-analysis/src/enforcement/reporters/json.rs` — JSON reporter
- [x] `P6-RPT-04` — Create `drift-analysis/src/enforcement/reporters/console.rs` — Console reporter (human-readable)

### 6D — Policy Engine — `drift-analysis/src/enforcement/policy/`

> **Spec coverage:** Fully specified in 09-QG-V2-PREP §7.

- [x] `P6-POL-01` — Create `drift-analysis/src/enforcement/policy/mod.rs` — `pub mod` declarations + re-exports
- [x] `P6-POL-02` — Create `drift-analysis/src/enforcement/policy/types.rs` — `Policy` (strict, standard, lenient, custom), `AggregationMode` (all-must-pass, any-must-pass, weighted, threshold)
- [x] `P6-POL-03` — Create `drift-analysis/src/enforcement/policy/engine.rs` — Policy engine: aggregate gate results per mode, progressive enforcement ramp-up for new projects

### 6E — Audit System (System 25) — `drift-analysis/src/enforcement/audit/`

> **V2-PREP:** 25-AUDIT-SYSTEM. 5-factor health scoring, degradation detection, trend prediction.
> **Cortex reference:** `cortex-observability/src/health/` (HealthChecker pattern), `cortex-observability/src/degradation/` (DegradationTracker)

- [x] `P6-AUD-01` — Create `drift-analysis/src/enforcement/audit/mod.rs` — `pub mod` declarations + re-exports
- [x] `P6-AUD-02` — Create `drift-analysis/src/enforcement/audit/types.rs` — `AuditSnapshot`, `HealthScore` (0-100), `DegradationAlert` (warning at -5 points, critical at -15 points)
- [x] `P6-AUD-03` — Create `drift-analysis/src/enforcement/audit/health_scorer.rs` — 5-factor health scoring: `health_score = (avgConfidence × 0.30 + approvalRatio × 0.20 + complianceRate × 0.20 + crossValidationRate × 0.15 + duplicateFreeRate × 0.15) × 100`
- [x] `P6-AUD-04` — Create `drift-analysis/src/enforcement/audit/degradation.rs` — Degradation detection: health score declining over time, per-category health breakdown (16 categories)
- [x] `P6-AUD-05` — Create `drift-analysis/src/enforcement/audit/trends.rs` — Trend prediction via linear regression on `health_trends` table, anomaly detection via Z-score
- [x] `P6-AUD-06` — Create `drift-analysis/src/enforcement/audit/deduplication.rs` — Three-tier Jaccard duplicate detection: >0.95 auto-merge, >0.90 recommend, 0.85-0.90 human review
- [x] `P6-AUD-07` — Create `drift-analysis/src/enforcement/audit/auto_approve.rs` — Auto-approve patterns meeting stability criteria (confidence ≥ 0.90, outlierRatio ≤ 0.50, locations ≥ 3)

### 6F — Violation Feedback Loop (System 31) — `drift-analysis/src/enforcement/feedback/`

> **V2-PREP:** 31-VIOLATION-FEEDBACK-LOOP. Tricorder-style FP tracking, auto-disable.

- [x] `P6-FBK-01` — Create `drift-analysis/src/enforcement/feedback/mod.rs` — `pub mod` declarations + re-exports
- [x] `P6-FBK-02` — Create `drift-analysis/src/enforcement/feedback/types.rs` — `FeedbackMetrics` (FP rate, dismissal rate, action rate), `FeedbackAction` (dismiss, fix, suppress, escalate)
- [x] `P6-FBK-03` — Create `drift-analysis/src/enforcement/feedback/tracker.rs` — Tricorder-style false-positive tracking per detector, auto-disable rule: >20% FP rate sustained for 30+ days → detector disabled
- [x] `P6-FBK-04` — Create `drift-analysis/src/enforcement/feedback/confidence_feedback.rs` — Feed back into confidence scoring (dismissed violations reduce pattern confidence)
- [x] `P6-FBK-05` — Create `drift-analysis/src/enforcement/feedback/stats_provider.rs` — `FeedbackStatsProvider` trait (resolves circular dependency with Quality Gates per §20 audit)

### 6G — Phase 6 Storage & NAPI Extensions

- [x] `P6-STR-01` — Create `drift-storage/src/migrations/v006_enforcement.rs` — Phase 6 tables: `violations`, `gate_results`, `audit_snapshots`, `health_trends`, `feedback` (~55-62 cumulative)
- [x] `P6-STR-02` — Create `drift-storage/src/queries/enforcement.rs` — Violations, gates, audit, feedback queries
- [x] `P6-STR-03` — Create `drift-storage/src/materialized/status.rs` — `materialized_status` view
- [x] `P6-STR-04` — Create `drift-storage/src/materialized/security.rs` — `materialized_security` view
- [x] `P6-STR-05` — Create `drift-storage/src/materialized/trends.rs` — `health_trends` view
- [x] `P6-NAPI-01` — Create `drift-napi/src/bindings/enforcement.rs` — `drift_check()`, `drift_audit()`, `drift_violations()`, `drift_gates()`
- [x] `P6-NAPI-02` — Create `drift-napi/src/bindings/feedback.rs` — Violation feedback functions (dismiss, fix, suppress)

### Phase 6 Tests

#### Rules Engine — Violation Mapping & Suppression
- [x] `T6-RUL-01` — Create `drift-analysis/tests/rules_test.rs` — Test rules engine maps patterns + outliers to violations with correct severity and quick fix suggestions
- [x] `T6-RUL-02` — Test inline suppression (`drift-ignore` comments): suppressed violation not reported, unsuppressed violation reported
- [x] `T6-RUL-03` — Test `drift-ignore` with specific rule ID: `// drift-ignore security/sql-injection` suppresses only that rule, not all security rules
- [x] `T6-RUL-04` — Test all 7 quick fix strategies produce syntactically valid code transformations (add import, rename, extract function, wrap in try/catch, add type annotation, add test, add documentation)
- [x] `T6-RUL-05` — Test violation deduplication: same pattern detected by 2 detectors → single violation (not duplicate)
- [x] `T6-RUL-06` — Test severity assignment: CWE-89 (SQL injection) → Error, naming convention → Warning, missing doc → Info

#### Quality Gates — DAG Orchestration & Progressive Enforcement
- [x] `T6-GAT-01` — Create `drift-analysis/tests/gates_test.rs` — Test all 6 quality gates evaluate correctly against test data (pattern compliance, constraint verification, security boundaries, test coverage, error handling, regression)
- [x] `T6-GAT-02` — Test DAG orchestrator respects gate dependencies: Gate 3 (security) depends on Gate 1 (patterns) — Gate 3 skipped if Gate 1 fails
- [x] `T6-GAT-03` — Test progressive enforcement transitions from warn → error correctly over configured ramp-up period
- [x] `T6-GAT-04` — Test DAG with circular dependency detection: Gate A depends on Gate B depends on Gate A → `GateError::DependencyNotMet` at startup, not infinite loop
- [x] `T6-GAT-05` — Test new-code-first enforcement: violation in new file → Error, same violation in existing file → Warning (during ramp-up)
- [x] `T6-GAT-06` — Test gate evaluation with zero violations — all gates pass, not error
- [x] `T6-GAT-07` — Test gate evaluation with 10K violations — completes in <100ms (performance contract)
- [x] `T6-GAT-08` — Test regression gate: health score drops from 85 to 70 → gate fails with specific degradation details

#### Reporters — Schema Validation & Format Correctness
- [x] `T6-RPT-01` — Create `drift-analysis/tests/reporters_test.rs` — Test SARIF 2.1.0 reporter produces valid SARIF with CWE + OWASP taxonomies
- [x] `T6-RPT-02` — Validate SARIF output against official SARIF 2.1.0 JSON schema (schema validation, not just structure check)
- [x] `T6-RPT-03` — Test SARIF with 0 violations produces valid empty SARIF (not malformed JSON)
- [x] `T6-RPT-04` — Test SARIF with 10K violations — file size reasonable (<50MB), generation time <5s
- [x] `T6-RPT-05` — Test JSON reporter produces valid JSON with all violation fields present
- [x] `T6-RPT-06` — Test console reporter produces human-readable output with color codes and file:line:column format
- [x] `T6-RPT-07` — Test SARIF code flows for taint paths: verify `threadFlows` contain correct step sequence from source to sink

#### Policy Engine — Aggregation Modes
- [x] `T6-POL-01` — Create `drift-analysis/tests/policy_test.rs` — Test policy engine aggregates gate results in all 4 modes (all-must-pass, any-must-pass, weighted, threshold)
- [x] `T6-POL-02` — Test `all-must-pass`: 5 gates pass + 1 fails → overall fail
- [x] `T6-POL-03` — Test `any-must-pass`: 5 gates fail + 1 passes → overall pass
- [x] `T6-POL-04` — Test `weighted`: gates with higher weight contribute more to overall score
- [x] `T6-POL-05` — Test `threshold`: overall score 79% with threshold 80% → fail, 80% → pass (boundary precision)
- [x] `T6-POL-06` — Test progressive enforcement ramp-up for new projects: first week all warnings, second week critical errors, fourth week full enforcement

#### Audit System — Health Scoring & Degradation Detection
- [x] `T6-AUD-01` — Create `drift-analysis/tests/audit_test.rs` — Test audit system computes 5-factor health score with correct weights (avgConfidence×0.30 + approvalRatio×0.20 + complianceRate×0.20 + crossValidationRate×0.15 + duplicateFreeRate×0.15)
- [x] `T6-AUD-02` — Test degradation detection: health score drops 5 points → warning alert, drops 15 points → critical alert
- [x] `T6-AUD-03` — Test trend prediction via linear regression: 5 declining data points → predict continued decline with confidence interval
- [x] `T6-AUD-04` — Test auto-approve patterns meeting stability criteria (confidence ≥0.90, outlierRatio ≤0.50, locations ≥3)
- [x] `T6-AUD-05` — Test three-tier Jaccard duplicate detection: >0.95 auto-merged, >0.90 recommended, 0.85-0.90 flagged for human review
- [x] `T6-AUD-06` — Test health score with all-zero inputs (new project, no data) — returns sensible default (not NaN, not 0)
- [x] `T6-AUD-07` — Test per-category health breakdown: 16 categories each with independent health score
- [x] `T6-AUD-08` — Test anomaly detection via Z-score: sudden spike in violations → anomaly flagged

#### Feedback Loop — FP Tracking & Auto-Disable
- [x] `T6-FBK-01` — Create `drift-analysis/tests/feedback_test.rs` — Test feedback loop tracks FP rate per detector: 5 dismissals out of 20 findings → 25% FP rate
- [x] `T6-FBK-02` — Test dismissed violations reduce pattern confidence — dismiss 10 violations for pattern X, verify X's confidence drops
- [x] `T6-FBK-03` — Test auto-disable rule: detector with >20% FP rate sustained for 30+ days → detector disabled automatically
- [x] `T6-FBK-04` — Test auto-disable does NOT fire for detector with >20% FP rate for only 15 days (sustained period not met)
- [x] `T6-FBK-05` — Test feedback abuse detection: 100 dismissals in 1 minute from same user → `on_feedback_abuse_detected` event fired
- [x] `T6-FBK-06` — Test `FeedbackStatsProvider` trait resolves circular dependency: gates can query feedback stats without importing feedback module directly

#### Integration & Performance Contracts
- [x] `T6-INT-01` — Integration: detect → aggregate → score → enforce → report round-trip on real test repo
- [x] `T6-INT-02` — Test all enforcement data persists to drift.db — verify `violations`, `gate_results`, `audit_snapshots`, `health_trends`, `feedback` tables populated
- [x] `T6-INT-03` — Test NAPI exposes `drift_check()` and `drift_audit()` to TypeScript with correct return types
- [x] `T6-INT-04` — Test materialized views refresh correctly after new violations inserted
- [x] `T6-INT-05` — Test SARIF upload to GitHub Code Scanning (mock HTTP endpoint) — verify correct headers and payload format
- [x] `T6-INT-06` — Performance: gate evaluation <100ms for 10K violations — regression gate
- [x] `T6-INT-07` — Test enforcement pipeline is idempotent: run twice on same data, verify identical violations and gate results

#### Build & Coverage Gate
- [x] `T6-INT-08` — `cargo tarpaulin -p drift-analysis` reports ≥80% line coverage for Phase 6 code
- [x] `T6-INT-09` — `cargo clippy -p drift-analysis` passes with zero warnings

### QG-6: Phase 6 Quality Gate (Milestone 5: "It Enforces")

- [x] Rules engine maps patterns + outliers to violations with severity and quick fixes
- [x] All 6 quality gates evaluate correctly against test data
- [x] DAG orchestrator respects gate dependencies
- [x] SARIF 2.1.0 reporter produces valid SARIF with CWE/OWASP taxonomies
- [x] Progressive enforcement transitions from warn → error correctly
- [x] Policy engine aggregates gate results in all 4 modes
- [x] Audit system computes 5-factor health score
- [x] Degradation detection fires when health declines beyond threshold
- [x] Feedback loop tracks FP rate and auto-disables noisy detectors
- [x] All enforcement data persists to drift.db
- [x] NAPI exposes `drift_check()` and `drift_audit()` to TypeScript

---

## Phase 7: Advanced & Capstone (Simulation, Decisions, Context, N+1)

> **Goal:** Build the four Level 4 leaf systems. High-value features built on the full stack.
> **Estimated effort:** 6–8 weeks with 4 parallel developers. Per-system: Simulation ~6w, Decision Mining ~8w, Context Gen ~7w, N+1 ~2w.
> **Parallelization:** 4 fully independent tracks. All are leaves — nothing depends on them.
> **Hybrid architecture:** Simulation and Decision Mining use Rust + TypeScript split.

### 7A — Simulation Engine (System 28) — `drift-analysis/src/advanced/simulation/` + `packages/drift/src/simulation/`

> **V2-PREP:** 28-SIMULATION-ENGINE. 13 task categories, 4 scorers, Monte Carlo, hybrid Rust/TS.

- [x] `P7-SIM-01` — Create `drift-analysis/src/advanced/mod.rs` — `pub mod` declarations for simulation, decisions, context
- [x] `P7-SIM-02` — Create `drift-analysis/src/advanced/simulation/mod.rs` — `pub mod` declarations + re-exports
- [x] `P7-SIM-03` — Create `drift-analysis/src/advanced/simulation/types.rs` — `SimulationTask` (13 categories: add feature, fix bug, refactor, migrate framework, add test, security fix, performance optimization, dependency update, API change, database migration, config change, documentation, infrastructure), `SimulationApproach`, `SimulationResult`, `ConfidenceInterval` (P10/P50/P90)
- [x] `P7-SIM-04` — Create `drift-analysis/src/advanced/simulation/scorers.rs` — 4 scorers: complexity, risk (blast radius + sensitivity), effort (LOC estimate + dependency count), confidence (test coverage + constraint satisfaction)
- [x] `P7-SIM-05` — Create `drift-analysis/src/advanced/simulation/monte_carlo.rs` — Monte Carlo simulation for effort estimation with P10/P50/P90 confidence intervals
- [x] `P7-SIM-06` — Create `drift-analysis/src/advanced/simulation/strategies.rs` — 15 strategy recommendations
- [x] `P7-SIM-07` — Create `packages/drift/src/simulation/index.ts` — TS orchestration exports
- [x] `P7-SIM-08` — Create `packages/drift/src/simulation/orchestrator.ts` — TS orchestration: approach generation, composite scoring, tradeoff generation, recommendation
- [x] `P7-SIM-09` — Create `packages/drift/src/simulation/approaches.ts` — Approach generation logic
- [x] `P7-SIM-10` — Create `packages/drift/src/simulation/scoring.ts` — Composite scoring logic

### 7B — Decision Mining (System 29) — `drift-analysis/src/advanced/decisions/` + `packages/drift/src/decisions/`

> **V2-PREP:** 29-DECISION-MINING. git2 integration, ADR detection, 12 decision categories, hybrid Rust/TS.

- [x] `P7-DEC-01` — Create `drift-analysis/src/advanced/decisions/mod.rs` — `pub mod` declarations + re-exports
- [x] `P7-DEC-02` — Create `drift-analysis/src/advanced/decisions/types.rs` — `Decision`, `DecisionCategory` enum (12 categories), `AdrRecord`, `TemporalCorrelation`
- [x] `P7-DEC-03` — Create `drift-analysis/src/advanced/decisions/git_analysis.rs` — `git2` crate integration for commit history analysis, high-performance pipeline
- [x] `P7-DEC-04` — Create `drift-analysis/src/advanced/decisions/adr_detection.rs` — ADR detection in markdown files
- [x] `P7-DEC-05` — Create `drift-analysis/src/advanced/decisions/categorizer.rs` — 12 decision category classification
- [x] `P7-DEC-06` — Create `drift-analysis/src/advanced/decisions/temporal.rs` — Temporal correlation with pattern changes
- [x] `P7-DEC-07` — Create `packages/drift/src/decisions/index.ts` — TS orchestration exports
- [x] `P7-DEC-08` — Create `packages/drift/src/decisions/adr_synthesis.ts` — ADR synthesis (AI-assisted)
- [x] `P7-DEC-09` — Create `packages/drift/src/decisions/categories.ts` — Decision category definitions

### 7C — Context Generation (System 30) — `drift-context/src/`

> **V2-PREP:** 30-CONTEXT-GENERATION. 15 package managers, token budgeting, intent-weighted selection.
> **Performance targets:** <50ms standard, <100ms full pipeline.

- [x] `P7-CTX-01` — Create `drift-context/src/generation/mod.rs` — `pub mod` declarations + re-exports
- [x] `P7-CTX-02` — Create `drift-context/src/generation/builder.rs` — Context builder: 3 depth levels (overview ~2K tokens, standard ~6K, deep ~12K)
- [x] `P7-CTX-03` — Create `drift-context/src/generation/intent.rs` — Intent-weighted selection (different context for fix_bug vs add_feature vs understand vs security_audit)
- [x] `P7-CTX-04` — Create `drift-context/src/generation/deduplication.rs` — Session-aware context deduplication (30-50% token savings on follow-ups)
- [x] `P7-CTX-05` — Create `drift-context/src/generation/ordering.rs` — Strategic content ordering (primacy-recency for transformer attention)
- [x] `P7-CTX-06` — Create `drift-context/src/tokenization/mod.rs` — `pub mod` declarations
- [x] `P7-CTX-07` — Create `drift-context/src/tokenization/budget.rs` — Token budgeting with model-aware limits
- [x] `P7-CTX-08` — Create `drift-context/src/tokenization/counter.rs` — `tiktoken-rs` wrapper for token counting
- [x] `P7-CTX-09` — Create `drift-context/src/formats/mod.rs` — `pub mod` declarations
- [x] `P7-CTX-10` — Create `drift-context/src/formats/xml.rs` — `quick-xml` output format
- [x] `P7-CTX-11` — Create `drift-context/src/formats/yaml.rs` — `serde_yaml` output format
- [x] `P7-CTX-12` — Create `drift-context/src/formats/markdown.rs` — Markdown output format
- [x] `P7-CTX-13` — Create `drift-context/src/packages/mod.rs` — `pub mod` declarations
- [x] `P7-CTX-14` — Create `drift-context/src/packages/manager.rs` — 15 package manager support

### 7D — N+1 Query Detection (Advanced)

> Already stubbed in Phase 2 ULP. This task completes the advanced detection.

- [x] `P7-N1-01` — Enhance `drift-analysis/src/language_provider/n_plus_one.rs` — Full N+1 detection for 8 ORM frameworks (ActiveRecord, Django ORM, SQLAlchemy, Hibernate, Entity Framework, Prisma, Sequelize, TypeORM)
- [x] `P7-N1-02` — Add GraphQL N+1 resolver detection in contract tracking module

### 7G — Specification Engine — `drift-context/src/specification/`

> **Source:** SPECIFICATION-ENGINE-NOVEL-LOOP-ENHANCEMENT.md §Phase 7 Additions.
> **D1 compliance:** The context engine accepts an optional `WeightOverride` via a trait. In standalone mode, static weights are used. The bridge (Phase 9) implements the trait and provides adaptive weights from Cortex Skill memories. Drift never imports from Cortex.

- [x] `P7-SPEC-09` — Add `AdaptiveWeightTable` type in `drift-context` (no Cortex imports) — includes `MigrationPath` key, per-section weights, failure distribution, sample size, last_updated timestamp
- [x] `P7-SPEC-10` — Add `WeightProvider` trait in `drift-core` with default returning static weights (`public_api: 2.0`, `data_model: 1.8`, `data_flow: 1.7`, `memories: 1.6`, `conventions: 1.5`, `constraints: 1.5`, `security: 1.4`, `error_handling: 1.3`, `test_topology: 1.2`, `dependencies: 1.0`, `entry_points: 0.8`)
- [x] `P7-SPEC-11` — Implement weight override in `ContextEngine` — calls `WeightProvider`, uses static weights if no provider registered. Negative weights clamped to 0.0, NaN replaced with static default. `SpecSection` enum with 11 variants (Overview, PublicApi, DataModel, DataFlow, BusinessLogic, Dependencies, Conventions, Security, Constraints, TestRequirements, MigrationNotes)
- [x] `P7-SPEC-12` — Add `MigrationPath` key type for weight table lookup in `drift-context` — keyed by `(source_language, target_language, source_framework, target_framework)`, `None` frameworks fall back to language-only lookup

### 7H — Phase 7 Storage & NAPI Extensions

- [x] `P7-STR-01` — Create `drift-storage/src/migrations/v007_advanced.rs` — Phase 7 tables: `simulations`, `decisions`, `context_cache`, `migration_projects`, `migration_modules`, `migration_corrections` (~61-68 cumulative)
- [x] `P7-STR-02` — Create `drift-storage/src/queries/advanced.rs` — Simulations, decisions, context, migration tracking queries
- [x] `P7-NAPI-01` — Create `drift-napi/src/bindings/advanced.rs` — `drift_simulate()`, `drift_decisions()`, `drift_context()`, `drift_generate_spec()`

### 7I — TypeScript Package Setup

- [x] `P7-TS-01` — Create `packages/drift/package.json` — Shared TS orchestration layer package config
- [x] `P7-TS-02` — Create `packages/drift/tsconfig.json` — TypeScript config
- [x] `P7-TS-03` — Create `packages/drift/src/index.ts` — Package entry point with re-exports

### Phase 7 Tests

#### Simulation Engine — Category Coverage & Statistical Validity
- [x] `T7-SIM-01` — Create `drift-analysis/tests/simulation_test.rs` — Test simulation generates approaches for at least 5 of 13 task categories (add feature, fix bug, refactor, security fix, performance optimization)
- [x] `T7-SIM-02` — Test Monte Carlo produces P10/P50/P90 confidence intervals — verify P10 < P50 < P90 (ordering invariant)
- [ ] `T7-SIM-03` — Test Rust↔TS serialization overhead <5ms per NAPI call for simulation results
- [x] `T7-SIM-04` — Test Monte Carlo with deterministic seed produces identical results across runs (reproducibility)
- [x] `T7-SIM-05` — Test all 4 scorers (complexity, risk, effort, confidence) produce scores in valid range [0.0, 1.0]
- [x] `T7-SIM-06` — Test simulation with zero historical data — produces estimates with wide confidence intervals (high uncertainty), not error
- [x] `T7-SIM-07` — Test simulation with contradictory signals (high complexity + high test coverage) — produces balanced score, not NaN

#### Decision Mining — Extraction Accuracy & Temporal Correlation
- [x] `T7-DEC-01` — Create `drift-analysis/tests/decisions_test.rs` — Test decision mining extracts decisions in at least 5 of 12 categories from reference codebase
- [x] `T7-DEC-02` — Test ADR detection finds Architecture Decision Records in markdown files (standard ADR format with Status, Context, Decision, Consequences)
- [x] `T7-DEC-03` — Test temporal correlation: decision made at commit T1, pattern change at commit T2 (T2 > T1) → correlation detected
- [x] `T7-DEC-04` — Test decision reversal detection: decision D1 at T1, contradicting decision D2 at T2 → reversal flagged
- [x] `T7-DEC-05` — Test decision mining with no decisions found — returns empty set, not error

#### Context Generation — Token Budget & Intent Weighting
- [x] `T7-CTX-01` — Create `drift-context/tests/context_test.rs` — Test context generation produces token-budgeted output for 3 depth levels: overview within 2K±10%, standard within 6K±5%, deep within 12K±5%
- [x] `T7-CTX-02` — Test intent-weighted scoring: `fix_bug` intent prioritizes error handling and test topology data, `security_audit` intent prioritizes taint and OWASP data
- [x] `T7-CTX-03` — Test session-aware deduplication: request context twice in same session → second response 30-50% smaller (no repeated information)
- [x] `T7-CTX-04` — Performance: context gen <100ms full pipeline — regression gate
- [x] `T7-CTX-05` — Test context with Unicode content (CJK code comments, emoji in strings) — token counting handles multi-byte correctly
- [x] `T7-CTX-06` — Test context generation with empty analysis data — produces minimal context with "no data available" indicators, not crash
- [x] `T7-CTX-07` — Test deduplication correctness: deduplicated context still contains all unique information (no data loss)
- [x] `T7-CTX-08` — Test all 3 output formats (XML, YAML, Markdown) produce valid output for same input data

#### N+1 Detection — ORM Coverage & False Positive Control
- [x] `T7-N1-01` — Test N+1 detection identifies loop-query patterns in at least 3 ORM frameworks (ActiveRecord, Django ORM, Sequelize)
- [x] `T7-N1-02` — Test GraphQL N+1 resolver detection: resolver that queries DB per item in list → flagged
- [x] `T7-N1-03` — Test N+1 false positive: batch query inside loop (e.g., `WHERE id IN (...)`) → NOT flagged (batch is intentional)
- [x] `T7-N1-04` — Performance: N+1 detection <10ms per query site — regression gate

#### Specification Engine — Spec Generation, Adaptive Weights & Migration Tracking
> **Source:** SPECIFICATION-ENGINE-TEST-PLAN.md §Phase 7 Tests.
> **File:** `drift-context/tests/specification_test.rs`
> **D1:** Zero Cortex imports. `WeightProvider` uses default (static weights).

##### Happy Path
- [x] `T7-SPEC-01` — **`ContextIntent::GenerateSpec` produces all 11 sections.** Create a `LogicalModule` with populated fields. Call `ContextEngine::generate()` with `GenerateSpec` intent. Assert: output contains all 11 section headers (Overview, Public API, Data Model, Data Flow, Business Logic, Dependencies, Conventions, Security, Constraints, Test Requirements, Migration Notes)
- [x] `T7-SPEC-02` — **Static weight table for `GenerateSpec` matches spec.** Assert: weight table has `public_api: 2.0`, `data_model: 1.8`, `data_flow: 1.7`, `memories: 1.6`, `conventions: 1.5`, `constraints: 1.5`, `security: 1.4`, `error_handling: 1.3`, `test_topology: 1.2`, `dependencies: 1.0`, `entry_points: 0.8`
- [x] `T7-SPEC-03` — **`SpecificationRenderer` formats Public API section correctly.** Module has 3 public functions with signatures and callers. Assert: rendered output contains a table with all 3 functions, no internal functions leak
- [x] `T7-SPEC-04` — **`SpecificationRenderer` formats Data Model section correctly.** Module touches 2 tables via Sequelize ORM. Assert: rendered output contains both tables, correct ORM attribution, correct operations, and sensitive fields flagged
- [x] `T7-SPEC-05` — **Business Logic section is marked as requiring human review.** Assert: Section 5 output contains the `⚠️` marker and explicit text indicating human verification is required
- [x] `T7-SPEC-06` — **`WeightProvider` default returns static weights.** Instantiate the trait's default impl. Call `get_weights(migration_path)`. Assert: returns the static weight table identical to `ContextIntent::GenerateSpec` defaults
- [x] `T7-SPEC-07` — **Spec generation with `WeightProvider` override applies custom weights.** Create a `WeightProvider` that returns `data_model: 2.4` (boosted). Generate spec. Assert: Data Model section receives proportionally more token budget than with static weights
- [x] `T7-SPEC-08` — **Migration tracking tables created on first use.** Call migration project CRUD on a fresh drift.db. Assert: `migration_projects`, `migration_modules`, `migration_corrections` tables exist with correct schemas

##### Edge Cases
- [x] `T7-SPEC-09` — **Module with zero public functions → Public API section says "No public interface detected."** Assert: section is present but explicitly states no public API, not an empty table
- [x] `T7-SPEC-10` — **Module with 500 public functions → section is truncated with count.** Assert: table shows top N functions (by call count) and a note: "Showing 50 of 500 public functions"
- [x] `T7-SPEC-11` — **Module with zero data dependencies → Data Model section says "No database access detected."** Assert: section present, explicit message, not empty
- [x] `T7-SPEC-12` — **`MigrationPath` with `None` frameworks → weight lookup still works.** Assert: `WeightProvider` returns weights (falls back to language-only lookup)
- [x] `T7-SPEC-13` — **`SpecSection` enum covers all 11 sections.** Assert: `SpecSection` has exactly 11 variants matching the template
- [x] `T7-SPEC-14` — **Spec generation with all weight overrides set to 0.0.** Assert: spec still generates (no division by zero), all sections present but with minimal content
- [x] `T7-SPEC-15` — **Migration module status transitions are enforced.** Assert: `pending → spec_generated → spec_reviewed → spec_approved → rebuilding → rebuilt → verified → complete` is the only valid forward path
- [x] `T7-SPEC-16` — **Spec generation for module with only convention data (no call graph, no data deps).** Assert: spec generates successfully with Overview, Conventions, and Migration Notes populated. Other sections contain "Insufficient data" messages

##### Adversarial
- [x] `T7-SPEC-17` — **Module name with markdown injection.** Module name is `## Injected Header\n\nMalicious content`. Assert: module name is escaped in the rendered spec. The output has exactly 11 `## ` headers
- [x] `T7-SPEC-18` — **Function signature with XSS payload in description.** Public function description contains `<script>alert('xss')</script>`. Assert: HTML is escaped or stripped in rendered output
- [x] `T7-SPEC-19` — **`AdaptiveWeightTable` with negative weights.** Weight table has `data_model: -1.5`. Assert: negative weights are clamped to 0.0 before use
- [x] `T7-SPEC-20` — **`AdaptiveWeightTable` with NaN weight.** Assert: NaN is replaced with the static default for that section
- [x] `T7-SPEC-21` — **`MigrationPath` with empty strings.** `source_language: ""`, `target_language: ""`. Assert: treated as unknown migration path, falls back to static weights. No panic
- [x] `T7-SPEC-22` — **Correction text with 1MB of content.** Assert: stored successfully, but rendered spec truncates the correction display to a reasonable length

##### Concurrency
- [x] `T7-SPEC-23` — **Parallel spec generation for 10 modules from same project.** Spawn 10 threads. Assert: all 10 complete without deadlock, each spec references only its own module's data, no cross-contamination
- [x] `T7-SPEC-24` — **Concurrent migration status updates.** 4 threads update different modules' statuses simultaneously. Assert: all updates succeed, no lost writes
- [x] `T7-SPEC-25` — **Spec generation while weight table is being updated.** Assert: spec generation sees a consistent snapshot of weights — either all old or all new, never a mix

##### Corruption Recovery
- [x] `T7-SPEC-26` — **`migration_projects` table missing.** Delete table from drift.db. Call `create_migration_project()`. Assert: table is recreated, project is created successfully
- [x] `T7-SPEC-27` — **`migration_modules` row with invalid status string.** Insert a row with `status = 'banana'`. Assert: reading the row returns an error for that row but doesn't crash the query
- [x] `T7-SPEC-28` — **Interrupted spec generation leaves no partial spec.** Simulate crash mid-render (after 6 of 11 sections). Assert: no partial spec is persisted. `migration_modules.status` remains `pending`
- [x] `T7-SPEC-29` — **Corrupted `AdaptiveWeightTable` JSON in drift.db.** Assert: weight loading falls back to static defaults with a warning, not a panic

##### Regression
- [x] `T7-SPEC-30` — **Spec generation is deterministic.** Same module, same weights, same data → same spec output, 10 consecutive runs. Assert: byte-identical output (excluding timestamps)
- [x] `T7-SPEC-31` — **Weight override does not mutate the static weight table.** Apply a `WeightProvider` override, generate spec, then generate another spec with default provider. Assert: second spec uses original static weights
- [x] `T7-SPEC-32` — **`SpecSection::BusinessLogic` always has the highest token budget among narrative sections.** Assert: regardless of weight configuration, BusinessLogic section receives at least 20% of the total narrative token budget
- [x] `T7-SPEC-33` — **Migration correction preserves original text verbatim.** Store a correction with `original_text` containing Unicode, newlines, and special characters. Read it back. Assert: byte-identical to input

#### Integration & Cross-System Verification
- [x] `T7-INT-01` — Integration: all Phase 7 results persist to drift.db — verify `simulations`, `decisions`, `context_cache` tables populated
- [ ] `T7-INT-02` — Test NAPI exposes `drift_simulate()`, `drift_decisions()`, `drift_context()` with correct TypeScript types
- [ ] `T7-INT-03` — Test TS orchestration layer handles Rust panics gracefully — panic in Rust → structured error in TypeScript, not process crash
- [ ] `T7-INT-04` — Test simulation + impact integration: simulation references impact analysis blast radius for risk scoring
- [ ] `T7-INT-05` — Test context generation + DNA integration: DNA health data included in context output

#### Build & Coverage Gate
- [ ] `T7-INT-06` — `cargo tarpaulin -p drift-analysis -p drift-context` reports ≥80% line coverage for Phase 7 code
- [x] `T7-INT-07` — `cargo clippy -p drift-analysis -p drift-context` passes with zero warnings

### QG-7: Phase 7 Quality Gate

- [x] Simulation engine generates approaches for at least 5 task categories
- [x] Monte Carlo produces P10/P50/P90 confidence intervals
- [x] Decision mining extracts decisions in at least 5 of 12 categories
- [x] ADR detection finds Architecture Decision Records in markdown
- [x] Context generation produces token-budgeted output for 3 depth levels (within 5% of budget)
- [x] Intent-weighted scoring produces different context for different intents
- [x] N+1 detection identifies loop-query patterns in at least 3 ORM frameworks
- [x] `ContextIntent::GenerateSpec` produces all 11 spec sections
- [x] `WeightProvider` default returns static weights (D1 compliance)
- [x] Spec generation with `WeightProvider` override applies custom weights correctly
- [x] Migration tracking tables created on first use with correct schemas
- [x] Spec generation is deterministic (same input → same output)
- [x] Context gen <100ms full pipeline
- [x] NAPI exposes Phase 7 functions
- [x] All results persist to drift.db

---

## Phase 8: Presentation (MCP, CLI, CI Agent, Reporters)

> **Goal:** Build the Level 5A presentation systems. How humans and AI agents consume Drift's analysis.
> **Estimated effort:** 4–5 weeks for Phase 8 gate. Full MCP: ~7 weeks. Parallelizable (MCP, CLI, CI Agent independent).
> **All are pure consumers of drift.db and NAPI.**

### 8A — MCP Server (System 32) — `packages/drift-mcp/`

> **V2-PREP:** 32-MCP-SERVER. MCP spec 2025-11-25, progressive disclosure, ~52 analysis tools.
> **Performance targets:** drift_status <1ms, drift_context <100ms.

- [x] `P8-MCP-01` — Create `packages/drift-mcp/package.json` — MCP server package config
- [x] `P8-MCP-02` — Create `packages/drift-mcp/tsconfig.json` — TypeScript config
- [x] `P8-MCP-03` — Create `packages/drift-mcp/src/index.ts` — Entry point
- [x] `P8-MCP-04` — Create `packages/drift-mcp/src/server.ts` — MCP server setup, stdio + HTTP transport
- [x] `P8-MCP-05` — Create `packages/drift-mcp/src/tools/index.ts` — Tool registration
- [x] `P8-MCP-06` — Create `packages/drift-mcp/src/tools/drift_status.ts` — `drift_status` tool: overview, reads `materialized_status`, <1ms
- [x] `P8-MCP-07` — Create `packages/drift-mcp/src/tools/drift_context.ts` — `drift_context` tool: deep dive, intent-weighted, replaces 3-5 calls
- [x] `P8-MCP-08` — Create `packages/drift-mcp/src/tools/drift_scan.ts` — `drift_scan` tool: trigger analysis
- [x] `P8-MCP-09` — Create `packages/drift-mcp/src/tools/drift_tool.ts` — Dynamic dispatch for ~49 internal tools (progressive disclosure reduces token overhead ~81%)
- [x] `P8-MCP-10` — Create `packages/drift-mcp/src/transport/index.ts` — Transport exports
- [x] `P8-MCP-11` — Create `packages/drift-mcp/src/transport/stdio.ts` — stdio transport (primary)
- [x] `P8-MCP-12` — Create `packages/drift-mcp/src/transport/http.ts` — Streamable HTTP transport (Docker/containerized)

### 8B — CLI — `packages/drift-cli/`

> **No V2-PREP yet.** Pure consumer of NAPI. Spec at start of Phase 8.

- [x] `P8-CLI-01` — Create `packages/drift-cli/package.json` — CLI package config
- [x] `P8-CLI-02` — Create `packages/drift-cli/tsconfig.json` — TypeScript config
- [x] `P8-CLI-03` — Create `packages/drift-cli/src/index.ts` — CLI entry point
- [x] `P8-CLI-04` — Create `packages/drift-cli/src/commands/index.ts` — Command registration
- [x] `P8-CLI-05` — Create `packages/drift-cli/src/commands/scan.ts` — `drift scan`
- [x] `P8-CLI-06` — Create `packages/drift-cli/src/commands/check.ts` — `drift check`
- [x] `P8-CLI-07` — Create `packages/drift-cli/src/commands/status.ts` — `drift status`
- [x] `P8-CLI-08` — Create `packages/drift-cli/src/commands/patterns.ts` — `drift patterns`
- [x] `P8-CLI-09` — Create `packages/drift-cli/src/commands/violations.ts` — `drift violations`
- [x] `P8-CLI-10` — Create `packages/drift-cli/src/commands/impact.ts` — `drift impact`
- [x] `P8-CLI-11` — Create `packages/drift-cli/src/commands/simulate.ts` — `drift simulate`
- [x] `P8-CLI-12` — Create `packages/drift-cli/src/commands/audit.ts` — `drift audit`
- [x] `P8-CLI-13` — Create `packages/drift-cli/src/commands/setup.ts` — `drift setup` (first-time wizard)
- [x] `P8-CLI-14` — Create `packages/drift-cli/src/commands/doctor.ts` — `drift doctor` (health checks)
- [x] `P8-CLI-15` — Create `packages/drift-cli/src/commands/export.ts` — `drift export`
- [x] `P8-CLI-16` — Create `packages/drift-cli/src/commands/explain.ts` — `drift explain`
- [x] `P8-CLI-17` — Create `packages/drift-cli/src/commands/fix.ts` — `drift fix`
- [x] `P8-CLI-18` — Create `packages/drift-cli/src/output/index.ts` — Output format registration
- [x] `P8-CLI-19` — Create `packages/drift-cli/src/output/table.ts` — Table output format
- [x] `P8-CLI-20` — Create `packages/drift-cli/src/output/json.ts` — JSON output format
- [x] `P8-CLI-21` — Create `packages/drift-cli/src/output/sarif.ts` — SARIF output format

### 8C — CI Agent & GitHub Action (System 34) — `packages/drift-ci/`

> **V2-PREP:** 34-CI-AGENT-GITHUB-ACTION. 9 parallel analysis passes, PR-level incremental.

- [x] `P8-CI-01` — Create `packages/drift-ci/package.json` — CI agent package config
- [x] `P8-CI-02` — Create `packages/drift-ci/tsconfig.json` — TypeScript config
- [x] `P8-CI-03` — Create `packages/drift-ci/action.yml` — GitHub Action definition
- [x] `P8-CI-04` — Create `packages/drift-ci/src/index.ts` — Entry point
- [x] `P8-CI-05` — Create `packages/drift-ci/src/agent.ts` — 9 parallel analysis passes: scan, patterns, call graph, boundaries, security, tests, errors, contracts, constraints
- [x] `P8-CI-06` — Create `packages/drift-ci/src/pr_comment.ts` — PR comment generation (readable summaries)
- [x] `P8-CI-07` — Create `packages/drift-ci/src/sarif_upload.ts` — SARIF upload to GitHub Code Scanning

### 8D — Remaining Reporters

- [x] `P8-RPT-01` — Create `drift-analysis/src/enforcement/reporters/github.rs` — GitHub Code Quality reporter
- [x] `P8-RPT-02` — Create `drift-analysis/src/enforcement/reporters/gitlab.rs` — GitLab Code Quality reporter
- [x] `P8-RPT-03` — Create `drift-analysis/src/enforcement/reporters/junit.rs` — JUnit XML reporter
- [x] `P8-RPT-04` — Create `drift-analysis/src/enforcement/reporters/html.rs` — HTML reporter
- [x] `P8-RPT-05` — Create `drift-analysis/src/enforcement/reporters/sonarqube.rs` — SonarQube Generic Issue Format reporter (P2, post-launch — deferred but tracked)

### Phase 8 Tests

#### MCP Server — Transport, Tool Registration & Token Efficiency
- [x] `T8-MCP-01` — Test MCP server registers all drift-analysis tools via stdio transport — verify tool list matches expected count
- [x] `T8-MCP-02` — Test `drift_status` returns overview in <1ms from materialized view (not full query)
- [x] `T8-MCP-03` — Test `drift_context` produces intent-weighted context with token budgeting — verify output size within budget
- [x] `T8-MCP-04` — Test progressive disclosure reduces token overhead: initial tool list ~81% smaller than exposing all ~52 tools individually
- [x] `T8-MCP-05` — Test MCP server handles malformed JSON-RPC request — returns proper error response, not crash
- [x] `T8-MCP-06` — Test MCP server handles unknown tool name — returns `MethodNotFound` error, not crash
- [x] `T8-MCP-07` — Test HTTP transport (Streamable HTTP) works in addition to stdio — same tools available on both transports
- [x] `T8-MCP-08` — Test MCP server handles concurrent requests (5 simultaneous tool calls) — all return correct results, no request mixing
- [x] `T8-MCP-09` — Test `drift_tool` dynamic dispatch routes to correct internal tool based on tool name parameter
- [x] `T8-MCP-10` — Test MCP server graceful shutdown: in-flight request completes before server exits

#### CLI — End-to-End Commands & Error Handling
- [x] `T8-CLI-01` — Test CLI `drift scan` + `drift check` work end-to-end on test fixture — exit code 0 for clean, non-zero for violations
- [x] `T8-CLI-02` — Test `drift setup` wizard creates drift.toml with sensible defaults and drift.db in correct location
- [x] `T8-CLI-03` — Test all output formats (table, JSON, SARIF) produce valid output for same violation set
- [x] `T8-CLI-04` — Test `drift scan` on empty directory — completes successfully with "0 files scanned" message, exit code 0
- [x] `T8-CLI-05` — Test `drift check` with no drift.db — helpful error message suggesting `drift setup`, not stack trace
- [x] `T8-CLI-06` — Test `drift doctor` detects missing drift.toml, outdated schema version, and corrupt drift.db
- [x] `T8-CLI-07` — Test `drift explain <violation-id>` produces human-readable explanation with remediation steps
- [x] `T8-CLI-08` — Test `drift export --format sarif` produces file that passes SARIF schema validation
- [x] `T8-CLI-09` — Test CLI with `--quiet` flag suppresses all output except errors and exit code
- [x] `T8-CLI-10` — Test CLI with invalid command — helpful usage message, not crash

#### CI Agent — PR Analysis & SARIF Upload
- [x] `T8-CI-01` — Test CI agent runs 9 analysis passes on a PR diff (scan, patterns, call graph, boundaries, security, tests, errors, contracts, constraints)
- [x] `T8-CI-02` — Test SARIF upload to GitHub Code Scanning succeeds (mock GitHub API endpoint) — verify correct authentication headers and payload
- [x] `T8-CI-03` — Test PR comment generation produces readable summaries with violation counts, severity breakdown, and trend indicators
- [x] `T8-CI-04` — Test CI agent with empty PR diff (no code changes) — completes quickly with "no changes to analyze" message
- [x] `T8-CI-05` — Test CI agent incremental mode: only analyzes files changed in PR, not entire codebase
- [x] `T8-CI-06` — Test CI agent timeout handling: analysis exceeding configured timeout → partial results reported, not hang

#### Reporters — Schema Validation & Edge Cases
- [x] `T8-RPT-01` — Test all 8 reporter formats (SARIF, JSON, console, GitHub Code Quality, GitLab Code Quality, JUnit XML, HTML, SonarQube) produce valid output
- [x] `T8-RPT-02` — Validate GitHub Code Quality format against GitHub's documented schema
- [x] `T8-RPT-03` — Validate JUnit XML format against JUnit schema — parseable by Jenkins, GitHub Actions, and other CI systems
- [x] `T8-RPT-04` — Test HTML reporter produces self-contained HTML (no external dependencies) that renders correctly
- [x] `T8-RPT-05` — Test all reporters with 0 violations — produce valid empty output (not malformed)
- [x] `T8-RPT-06` — Test all reporters with violations containing Unicode characters (CJK file paths, emoji in messages) — no encoding errors
- [x] `T8-RPT-07` — Test reporter with 50K violations — completes in <30s, output file size reasonable

#### Integration
- [x] `T8-INT-01` — Integration: full pipeline from scan → analyze → enforce → report → present via MCP + CLI + CI agent
- [x] `T8-INT-02` — Test MCP server + CLI produce consistent results for same codebase (no divergence between interfaces)

#### Build & Coverage Gate
- [x] `T8-INT-03` — TypeScript test suite passes with ≥80% coverage for MCP, CLI, and CI packages
- [x] `T8-INT-04` — `cargo clippy -p drift-analysis` passes with zero warnings for reporter code

### QG-8: Phase 8 Quality Gate (Milestone 6: "It Ships")

- [x] MCP server registers all drift-analysis tools via stdio transport
- [x] `drift_status` returns overview in <1ms
- [x] `drift_context` produces intent-weighted context with token budgeting
- [x] CLI `drift scan` + `drift check` work end-to-end
- [x] CI agent runs 9 analysis passes on a PR diff
- [x] SARIF upload to GitHub Code Scanning succeeds
- [x] PR comment generation produces readable summaries
- [x] All 8 reporter formats produce valid output

---

## Phase 9: Bridge & Integration (Cortex-Drift Bridge, Grounding Loop)

> **Goal:** Build the optional integration layer connecting Drift to Cortex. Architecturally a leaf (D4) but the killer product feature (D7).
> **Estimated effort:** 3–5 weeks (1 dev), 2–3 weeks (2 devs). 8 internal phases totaling ~21-26 working days.
> **Key insight:** Per D1, Drift is complete without this. Per D4, nothing in Drift depends on the bridge.
> **Cortex reference:** `cortex-core/src/memory/` (memory types), `cortex-core/src/traits/` (storage traits)

### 9A — Bridge Crate Setup — `crates/cortex-drift-bridge/`

> Separate crate outside the drift workspace. Depends on both drift-core and cortex-core.

- [x] `P9-BRG-01` — Create `crates/cortex-drift-bridge/Cargo.toml` — Dependencies on drift-core + cortex-core (workspace dependency versions)
- [x] `P9-BRG-02` — Create `crates/cortex-drift-bridge/src/lib.rs` — `pub mod` declarations for all bridge modules

### 9B — Event Mapping — `crates/cortex-drift-bridge/src/event_mapping/`

> 21 Drift event types → Cortex memory types with confidence mappings.

- [x] `P9-EVT-01` — Create `crates/cortex-drift-bridge/src/event_mapping/mod.rs` — `pub mod` declarations
- [x] `P9-EVT-02` — Create `crates/cortex-drift-bridge/src/event_mapping/mapper.rs` — 21 event types → Cortex memory types (on_pattern_approved → PatternRationale/0.8, on_pattern_discovered → Insight/0.5, on_scan_complete → triggers grounding, on_violation_detected → no memory, on_error → logged only, etc.)
- [x] `P9-EVT-03` — Create `crates/cortex-drift-bridge/src/event_mapping/memory_types.rs` — Memory type + confidence mappings for all 21 events

### 9C — Link Translation — `crates/cortex-drift-bridge/src/link_translation/`

- [x] `P9-LNK-01` — Create `crates/cortex-drift-bridge/src/link_translation/mod.rs` — `pub mod` declarations
- [x] `P9-LNK-02` — Create `crates/cortex-drift-bridge/src/link_translation/translator.rs` — Drift `PatternLink` → Cortex `EntityLink`, 5 constructors: from_pattern, from_constraint, from_detector, from_module, from_decision

### 9D — Grounding Logic — `crates/cortex-drift-bridge/src/grounding/`

> The killer feature (D7). First AI memory system with empirically validated memory.

- [x] `P9-GND-01` — Create `crates/cortex-drift-bridge/src/grounding/mod.rs` — `pub mod` declarations
- [x] `P9-GND-02` — Create `crates/cortex-drift-bridge/src/grounding/loop_runner.rs` — Grounding loop orchestration: compare Cortex memories against Drift scan results, max 500 memories per loop
- [x] `P9-GND-03` — Create `crates/cortex-drift-bridge/src/grounding/scorer.rs` — Grounding score computation, thresholds: Validated ≥0.7, Partial ≥0.4, Weak ≥0.2, Invalidated <0.2
- [x] `P9-GND-04` — Create `crates/cortex-drift-bridge/src/grounding/evidence.rs` — 10 evidence types with weights: PatternConfidence, PatternOccurrence, FalsePositiveRate, ConstraintVerification, CouplingMetric, DnaHealth, TestCoverage, ErrorHandlingGaps, DecisionEvidence, BoundaryData. Confidence adjustment: boost_delta=0.05, partial_penalty=0.05, weak_penalty=0.15, invalidated_floor=0.1, contradiction_drop=0.3
- [x] `P9-GND-05` — Create `crates/cortex-drift-bridge/src/grounding/scheduler.rs` — 6 trigger types: post-scan incremental (every scan), post-scan full (every 10th), scheduled (daily), on-demand (MCP), memory creation, memory update
- [x] `P9-GND-06` — Create `crates/cortex-drift-bridge/src/grounding/classification.rs` — 13 groundable memory types (6 fully: PatternRationale, ConstraintOverride, DecisionContext, CodeSmell, Core, Semantic; 7 partially: Tribal, Decision, Insight, Entity, Feedback, Incident, Environment)

### 9E — Bridge Storage — `crates/cortex-drift-bridge/src/storage/`

- [x] `P9-STR-01` — Create `crates/cortex-drift-bridge/src/storage/mod.rs` — `pub mod` declarations
- [x] `P9-STR-02` — Create `crates/cortex-drift-bridge/src/storage/tables.rs` — 4 bridge-specific SQLite tables: `bridge_grounding_results` (90 days Community, unlimited Enterprise), `bridge_grounding_snapshots` (365 days), `bridge_event_log` (30 days), `bridge_metrics` (7 days)

### 9F — License Gating — `crates/cortex-drift-bridge/src/license/`

- [x] `P9-LIC-01` — Create `crates/cortex-drift-bridge/src/license/mod.rs` — `pub mod` declarations
- [x] `P9-LIC-02` — Create `crates/cortex-drift-bridge/src/license/gating.rs` — 3-tier feature gating: Community (5 event types, manual grounding), Team (all 21 events, scheduled grounding, MCP tools), Enterprise (full grounding loop, contradiction generation, cross-DB analytics)

### 9G — Intent Extensions — `crates/cortex-drift-bridge/src/intents/`

- [x] `P9-INT-01` — Create `crates/cortex-drift-bridge/src/intents/mod.rs` — `pub mod` declarations
- [x] `P9-INT-02` — Create `crates/cortex-drift-bridge/src/intents/extensions.rs` — 10 code-specific intent extensions registered as Cortex extensions: add_feature, fix_bug, refactor, review_code, debug, understand_code, security_audit, performance_audit, test_coverage, documentation

### 9H — Database Integration

- [x] `P9-DB-01` — Implement `ATTACH DATABASE 'cortex.db' AS cortex READ ONLY` — cross-DB reads, graceful failure when cortex.db doesn't exist

### 9I — Bridge NAPI

- [x] `P9-NAPI-01` — Create bridge NAPI bindings: 15 functions — `bridge_initialize`, `bridge_shutdown`, `bridge_is_available`, `bridge_ground_memory`, `bridge_ground_all`, `bridge_get_grounding_snapshot`, `bridge_get_grounding_history`, `bridge_translate_links`, `bridge_memories_for_pattern`, `bridge_patterns_for_memory`, `bridge_why`, `bridge_learn`, `bridge_grounding_check`, `bridge_get_metrics`, `bridge_register_event_handler`

### 9J — Combined MCP Tools

- [x] `P9-MCP-01` — Implement `drift_why` — synthesizes pattern data + causal memory
- [x] `P9-MCP-02` — Implement `drift_memory_learn` — creates memory from Drift analysis
- [x] `P9-MCP-03` — Implement `drift_grounding_check` — on-demand grounding verification

### 9K — Specification Engine Bridge — `crates/cortex-drift-bridge/src/specification/`

> **Source:** SPECIFICATION-ENGINE-NOVEL-LOOP-ENHANCEMENT.md §Phase 9 Additions.
> **D4 compliance:** All Cortex interaction happens here. The bridge implements `DecompositionPriorProvider` (retrieves priors from Cortex) and `WeightProvider` (retrieves adaptive weights from Cortex Skill memories). It also handles all event→memory mapping and causal edge creation. Nothing in Drift depends on this crate — it's a leaf per D4.

- [x] `P9-BRIDGE-01` — Implement `SpecCorrection` → CausalEngine edge creation — bridge reads correction from drift.db, creates causal edge in cortex.db. `SpecCorrection` struct includes `correction_id`, `module_id`, `section: SpecSection`, `root_cause: CorrectionRootCause`, `upstream_modules`, `data_sources: Vec<DataSourceAttribution>`
- [x] `P9-BRIDGE-02` — Implement `CorrectionRootCause` classification in bridge — 7 variants: MissingCallEdge, MissingBoundary, WrongConvention, LlmHallucination, MissingDataFlow, MissingSensitiveField, DomainKnowledge. Each maps to a specific causal relation type and metadata
- [x] `P9-BRIDGE-03` — Implement `DataSourceAttribution` tracking in bridge — records which Drift system produced the data (call_graph, boundary, convention, etc.), confidence at generation time, and whether the data was correct
- [x] `P9-BRIDGE-04` — Bridge implements `DriftEventHandler::on_spec_corrected` → creates Feedback memory + causal edge in Cortex. Tags include module ID and spec section. Causal edge links to original spec's Insight memory
- [x] `P9-BRIDGE-05` — Bridge implements `DriftEventHandler::on_contract_verified` → creates VerificationFeedback in Cortex. Pass → positive Feedback memory with confidence boost. Fail → Feedback memory with `VerificationFeedback` metadata mapping failure to `SpecSection`, mismatch type, and severity
- [x] `P9-BRIDGE-06` — Bridge implements `WeightProvider` trait — reads Cortex Skill memories, computes adaptive weights using formula `adjusted_weight = base_weight × (1 + failure_rate × boost_factor)` where `boost_factor = 0.5`. Minimum sample size of 15-20 enforced. Weights stored as Skill memory with 365-day half-life
- [x] `P9-BRIDGE-07` — Bridge implements `DriftEventHandler::on_decomposition_adjusted` → creates DecisionContext memory in Cortex linked to DNA hash. Confidence 0.75 for single project. Confirmations increase confidence (≥ 0.85), rejections decrease (≤ 0.6)
- [x] `P9-BRIDGE-08` — Bridge implements `DecompositionPriorProvider` trait — queries Cortex for past decisions by DNA similarity (threshold ≥ 0.6), returns sorted by confidence descending. Consolidated semantic rules returned with higher confidence than episodic decisions
- [x] `P9-BRIDGE-09` — Implement causal narrative generation for spec explanations — bridge calls `CausalEngine.narrative()`, `trace_origins()`, `trace_effects()` to produce human-readable explanations of why a spec section was generated a particular way, with chain confidence scoring

### Phase 9 Tests

#### Event Mapping — Type Correctness & Confidence Values
- [x] `T9-EVT-01` — Create `crates/cortex-drift-bridge/tests/event_mapping_test.rs` — Test event mapping creates correct Cortex memory types from all 21 Drift event types
- [x] `T9-EVT-02` — Test confidence values match specification for all 21 event types (e.g., `on_pattern_approved` → 0.8, `on_pattern_discovered` → 0.5)
- [x] `T9-EVT-03` — Test events that should NOT create memories (e.g., `on_violation_detected`, `on_error`) produce no memory output
- [x] `T9-EVT-04` — Test event mapping with malformed event payload — returns error, not panic or corrupted memory

#### Link Translation — Constructor Coverage
- [x] `T9-LNK-01` — Create `crates/cortex-drift-bridge/tests/link_translation_test.rs` — Test link translation produces valid EntityLink from PatternLink for all 5 constructors (from_pattern, from_constraint, from_detector, from_module, from_decision)
- [x] `T9-LNK-02` — Test link translation with missing source data (e.g., pattern deleted between link creation and translation) — graceful degradation, not crash
- [x] `T9-LNK-03` — Test link translation round-trip: Drift PatternLink → Cortex EntityLink → query back → matches original

#### Grounding — Score Computation, Thresholds & Lifecycle
- [x] `T9-GND-01` — Create `crates/cortex-drift-bridge/tests/grounding_test.rs` — Test grounding logic computes grounding percentage for pattern memories against scan results
- [x] `T9-GND-02` — Test grounding feedback loop adjusts Cortex memory confidence: validated pattern → confidence boosted by 0.05, invalidated → confidence dropped by 0.15
- [x] `T9-GND-03` — Test grounding score thresholds: score 0.75 → Validated, 0.45 → Partial, 0.25 → Weak, 0.15 → Invalidated (boundary precision)
- [x] `T9-GND-04` — Test max 500 memories per grounding loop — 501st memory deferred to next loop, not dropped
- [x] `T9-GND-05` — Test all 13 groundable memory types classified correctly (6 fully groundable, 7 partially groundable)
- [x] `T9-GND-06` — Test 6 trigger types fire at correct intervals: post-scan incremental (every scan), post-scan full (every 10th), scheduled (daily), on-demand, memory creation, memory update
- [x] `T9-GND-07` — Test contradiction detection: Cortex memory says "always use camelCase", Drift scan shows 80% snake_case → contradiction flagged with confidence_drop=0.3
- [x] `T9-GND-08` — Test grounding with stale Cortex data: memory references pattern that no longer exists in Drift → Invalidated, not crash
- [x] `T9-GND-09` — Test all 10 evidence types contribute to grounding score with correct weights
- [x] `T9-GND-10` — Test invalidated_floor=0.1: even fully invalidated memory retains minimum 0.1 confidence (not zeroed out)

#### Database Integration — Cross-DB & Graceful Degradation
- [x] `T9-DB-01` — Test `ATTACH DATABASE 'cortex.db' AS cortex READ ONLY` works for cross-DB queries
- [x] `T9-DB-02` — Test graceful degradation when cortex.db doesn't exist — all Drift functions work normally, bridge functions return "unavailable" status
- [x] `T9-DB-03` — Test graceful degradation when cortex.db is locked by another process — bridge retries with backoff, eventually returns timeout error
- [x] `T9-DB-04` — Test cross-DB query with cortex.db containing incompatible schema version — returns version mismatch error, not corrupt data

#### License Gating — Tier Enforcement
- [x] `T9-LIC-01` — Test Community tier: only 5 event types mapped, manual grounding only — verify other events silently dropped
- [x] `T9-LIC-02` — Test Team tier: all 21 events, scheduled grounding, MCP tools — verify all features accessible
- [x] `T9-LIC-03` — Test Enterprise tier: full grounding loop, contradiction generation, cross-DB analytics — verify advanced features accessible
- [x] `T9-LIC-04` — Test tier upgrade: Community → Team — previously dropped events now processed on next scan

#### MCP Tools — Synthesis & Learning
- [x] `T9-MCP-01` — Test `drift_why` synthesizes pattern data + causal memory into coherent explanation
- [x] `T9-MCP-02` — Test `drift_memory_learn` creates memory from Drift analysis with correct type and confidence
- [x] `T9-MCP-03` — Test `drift_grounding_check` returns grounding status for specific memory with evidence breakdown

#### Specification Engine Bridge — Causal Corrections, Decomposition Transfer, Adaptive Weights
> **Source:** SPECIFICATION-ENGINE-TEST-PLAN.md §Phase 9 Tests + Integration Tests.
> **File:** `cortex-drift-bridge/tests/spec_bridge_test.rs`
> **D4:** This is the ONLY crate that imports both Drift and Cortex. All tests require both systems present.

##### 9A-Bridge. Causal Correction Graphs — Happy Path
- [x] `T9-BRIDGE-01` — **`SpecCorrection` creates a causal edge in CausalEngine.** Create a `SpecCorrection` with `root_cause: MissingCallEdge`. Bridge processes it. Assert: CausalEngine contains an edge from the upstream module's memory to the correction memory with relation `Caused`
- [x] `T9-BRIDGE-02` — **`CorrectionRootCause` classification maps to correct causal relation.** For each of the 7 variants, create a `SpecCorrection` and process it. Assert: each produces a causal edge with the correct relation type and metadata
- [x] `T9-BRIDGE-03` — **`DataSourceAttribution` tracking records which Drift system was wrong.** Assert: bridge stores attribution metadata on the causal edge, queryable later for system reliability analysis
- [x] `T9-BRIDGE-04` — **`DriftEventHandler::on_spec_corrected` creates Feedback memory + causal edge.** Fire the event with a business logic correction. Assert: (1) Feedback memory exists in cortex.db, (2) causal edge links it to the original spec's Insight memory, (3) tags include module ID and spec section
- [x] `T9-BRIDGE-05` — **`DriftEventHandler::on_contract_verified` (pass) creates positive Feedback memory.** Assert: Feedback memory created with positive sentiment, linked to the approved spec's Decision memory, confidence boost applied
- [x] `T9-BRIDGE-06` — **`DriftEventHandler::on_contract_verified` (fail) creates `VerificationFeedback` with section mapping.** Assert: Feedback memory created with metadata mapping the failure to `SpecSection::DataModel`, mismatch type recorded, severity recorded
- [x] `T9-BRIDGE-07` — **`DriftEventHandler::on_decomposition_adjusted` creates DecisionContext memory linked to DNA hash.** Human splits auth from users module. Assert: DecisionContext memory created with `BoundaryAdjustment::Split`, linked to DNA profile hash, confidence 0.75
- [x] `T9-BRIDGE-08` — **Causal narrative generation for spec explanation.** Create a chain of 3 corrections. Call bridge's `explain_spec_section()`. Assert: returns a narrative string that mentions upstream corrections, includes chain confidence, and is human-readable

##### 9B-Bridge. Causal Correction Graphs — Edge Cases
- [x] `T9-BRIDGE-09` — **Correction with zero upstream modules.** `SpecCorrection` with `upstream_modules: []` (pure domain knowledge). Assert: memory created with no causal edges to other modules, no panic
- [x] `T9-BRIDGE-10` — **Correction referencing a module that doesn't exist in drift.db.** Assert: bridge logs a warning, creates the correction memory without the invalid causal edge
- [x] `T9-BRIDGE-11` — **100 corrections for the same module.** Assert: all 100 create causal edges, narrative generation summarizes rather than listing all 100
- [x] `T9-BRIDGE-12` — **Correction chain depth of 20.** Assert: `trace_origins()` traverses the full chain, narrative generation includes a depth summary
- [x] `T9-BRIDGE-13` — **Two corrections with identical content but different modules.** Assert: two separate memories created, two separate causal edges, no deduplication
- [x] `T9-BRIDGE-14` — **`SpecSection` variant not in the weight table.** Assert: section is added to the table with the static default weight as baseline, then adjusted

##### 9C-Bridge. Decomposition Transfer — Happy Path
- [x] `T9-BRIDGE-15` — **Bridge `DecompositionPriorProvider` returns priors for DNA-similar project.** Store a DecisionContext memory linked to DNA profile A. Query with DNA profile B (similarity 0.78). Assert: returns the stored decision with `dna_similarity: 0.78`
- [x] `T9-BRIDGE-16` — **Bridge filters out low-similarity priors.** Store decisions for DNA profiles with similarities 0.3, 0.5, 0.6, 0.8. Assert: only 0.6 and 0.8 are returned (threshold is 0.6)
- [x] `T9-BRIDGE-17` — **Bridge returns consolidated semantic rules with higher confidence than episodic decisions.** Store 6 episodic DecisionContext memories for the same pattern. Trigger consolidation. Assert: returns the semantic rule with confidence > any individual episodic memory
- [x] `T9-BRIDGE-18` — **Prior confidence increases when human confirms.** Store a prior with confidence 0.75. Human confirms. Assert: confidence increases to ≥ 0.85
- [x] `T9-BRIDGE-19` — **Prior confidence decreases when human rejects.** Store a prior with confidence 0.75. Human rejects. Assert: confidence decreases to ≤ 0.6

##### 9D-Bridge. Decomposition Transfer — Edge Cases
- [x] `T9-BRIDGE-20` — **No priors exist in cortex.db.** Fresh Cortex database. Assert: `DecompositionPriorProvider` returns empty vec, no error
- [x] `T9-BRIDGE-21` — **1000 priors exist for the same DNA profile.** Assert: bridge returns all applicable priors, sorted by confidence descending
- [x] `T9-BRIDGE-22` — **DNA profile with all zero genes.** Assert: similarity to any stored profile is 0.0, no priors returned
- [x] `T9-BRIDGE-23` — **Cross-DB ATTACH query (drift.db ↔ cortex.db).** Assert: ATTACH works, query returns correct joined results, DETACH cleans up

##### 9E-Bridge. Adaptive Weights — Happy Path
- [x] `T9-BRIDGE-24` — **Bridge `WeightProvider` computes adaptive weights from verification failures.** Store 20 Feedback memories: 12 DataModel failures, 4 PublicApi, 2 Security, 2 Conventions. Assert: `data_model` weight is boosted most (≈ 2.34)
- [x] `T9-BRIDGE-25` — **Weight adjustment formula is correct.** For `data_model`: base 1.8, failure_rate 0.60, boost_factor 0.5. Assert: `adjusted = 1.8 × (1 + 0.60 × 0.5) = 2.34`
- [x] `T9-BRIDGE-26` — **Adaptive weights stored as Skill memory with 365-day half-life.** Assert: Skill memory exists in cortex.db with weight table, MigrationPath as key, and half-life of 365 days
- [x] `T9-BRIDGE-27` — **Adaptive weights decay over time.** Store Skill memory, advance time by 365 days. Assert: weights have decayed toward static defaults
- [x] `T9-BRIDGE-28` — **Minimum sample size enforced.** Store only 3 verification results (below 15-20 threshold). Assert: returns static weights with "insufficient sample size" note

##### 9F-Bridge. Adaptive Weights — Edge Cases
- [x] `T9-BRIDGE-29` — **All verification results are passes (zero failures).** 20 verifications, all pass. Assert: adaptive weights equal static weights. No division by zero
- [x] `T9-BRIDGE-30` — **All failures map to a single section.** Assert: that section is heavily boosted, all other weights unchanged. Total weight sum is reasonable
- [x] `T9-BRIDGE-31` — **Migration path with no stored Skill memory.** Assert: returns static defaults, no error
- [x] `T9-BRIDGE-32` — **Two migration paths with same languages but different frameworks.** Assert: separate weight tables, different adaptive weights

##### 9G-Bridge. Event→Memory Mapping — Adversarial
- [x] `T9-BRIDGE-33` — **`on_spec_corrected` with SQL injection in correction text.** Assert: correction stored safely (parameterized query), `memories` table still exists
- [x] `T9-BRIDGE-34` — **`on_contract_verified` with NaN severity score.** Assert: bridge rejects or clamps the severity, does not store NaN
- [x] `T9-BRIDGE-35` — **`on_decomposition_adjusted` with contradictory adjustment.** Assert: bridge detects the no-op, stores the confirmation (not a split)
- [x] `T9-BRIDGE-36` — **Rapid-fire events: 1000 corrections in 1 second.** Assert: all 1000 processed, causal graph has 1000 new nodes, total processing time < 10s
- [x] `T9-BRIDGE-37` — **Event with empty module_id.** Assert: event is rejected with a clear error, no empty-key memory created

##### 9H-Bridge. Concurrency
- [x] `T9-BRIDGE-38` — **Parallel `on_spec_corrected` and `on_contract_verified` for same module.** Assert: both memories created, both causal edges created, no deadlock
- [x] `T9-BRIDGE-39` — **Parallel `DecompositionPriorProvider` queries from 4 threads.** Assert: all 4 get consistent results, no torn reads
- [x] `T9-BRIDGE-40` — **Concurrent weight table read and write.** Assert: reader sees a consistent snapshot — either all old or all new weights
- [x] `T9-BRIDGE-41` — **Cross-DB ATTACH under concurrent access.** Two threads both ATTACH cortex.db simultaneously. Assert: both succeed, queries return correct results

##### 9I-Bridge. Corruption Recovery
- [x] `T9-BRIDGE-42` — **cortex.db is missing (Drift standalone mode).** Assert: all `DriftEventHandler` methods are no-ops, `DecompositionPriorProvider` returns empty vec, `WeightProvider` returns static defaults. No panics
- [x] `T9-BRIDGE-43` — **cortex.db exists but `memories` table is corrupted.** Assert: bridge catches the SQLite error, falls back to no-op behavior for affected operations
- [x] `T9-BRIDGE-44` — **Causal graph has a corrupted edge (invalid node reference).** Assert: traversal skips the dangling edge, narrative generation excludes it, no panic
- [x] `T9-BRIDGE-45` — **Interrupted `on_spec_corrected` leaves no partial state.** Assert: on restart, the orphaned Feedback memory is detected and either the causal edge is created retroactively or the memory is flagged as "unlinked"
- [x] `T9-BRIDGE-46` — **Skill memory with corrupted weight JSON.** Assert: `WeightProvider` falls back to static defaults with a warning

##### 9J-Bridge. Regression
- [x] `T9-BRIDGE-47` — **All 10 event→memory mappings from the Appendix are implemented.** For each row (spec generated→Insight, spec corrected→Feedback, spec corrected boundary→DecisionContext, spec approved→Decision, module boundary adjusted→DecisionContext, contract verify pass→Feedback, contract verify fail→Feedback, adaptive weight update→Skill, decomposition prior applied→Procedural, consolidation→Semantic), fire the event and assert the correct memory type is created
- [x] `T9-BRIDGE-48` — **Causal edge direction is always cause→effect, never reversed.** Create 10 corrections with known causal relationships. Assert: every edge points from cause to effect
- [x] `T9-BRIDGE-49` — **`WeightProvider` returns weights that sum to a reasonable total.** Assert: sum of all 11 weights is between 5.0 and 30.0. No single weight exceeds 5.0
- [x] `T9-BRIDGE-50` — **Bridge does not import from `drift-analysis` or `drift-context` internals.** Static analysis: bridge's `Cargo.toml` depends on `drift-core` (for traits) and `cortex-*` crates. NOT on `drift-analysis` or `drift-context` directly

#### End-to-End Specification Loop Integration Tests
> **Source:** SPECIFICATION-ENGINE-TEST-PLAN.md §Integration Tests.
> **File:** `cortex-drift-bridge/tests/spec_integration_test.rs`
> **Purpose:** Verify the three enhancements work together as a closed loop (Drift standalone → Bridge → Cortex → Bridge → Drift).

##### Full Loop — Happy Path
- [x] `TINT-LOOP-01` — **Complete correction→causal→narrative loop.** (1) Generate spec for Module A. (2) Human corrects business logic. (3) Bridge creates Feedback memory + causal edge. (4) Generate spec for Module B (same data dependencies). (5) Assert: Module B's spec includes a hint derived from Module A's correction, with causal narrative
- [x] `TINT-LOOP-02` — **Complete decomposition→transfer→confirmation loop.** (1) Decompose Project A, human splits auth from users. (2) Decompose Project B (similar DNA). Assert: suggests splitting. (3) Human confirms. Assert: confidence increases. (4) Decompose Project C. Assert: prior applied with higher confidence
- [x] `TINT-LOOP-03` — **Complete verification→weight→spec loop.** (1) Generate specs for 20 modules. (2) Simulate verification: 12 DataModel failures, 4 PublicApi, 4 passes. (3) Bridge computes adaptive weights. (4) Generate spec for Module 21. Assert: larger Data Model section than Module 1
- [x] `TINT-LOOP-04` — **All three enhancements compound on the same module.** Module X in Project B: decomposition priors, causal corrections, and adaptive weights all influence the spec. Assert: spec reflects all three, causal narrative explains all three sources

##### Full Loop — Edge Cases
- [x] `TINT-LOOP-05` — **First-ever project (empty Cortex).** No prior corrections, no decisions, no adaptive weights. Assert: full pipeline works with all defaults, identical to Drift standalone mode
- [x] `TINT-LOOP-06` — **Project with 100 modules, 500 corrections, 200 verifications.** Assert: all 100 specs generate in < 60s, causal graph has ≤ 500 nodes, no memory leaks (RSS < 500MB)
- [x] `TINT-LOOP-07` — **Bridge disabled mid-pipeline.** Generate specs 1-10 with bridge active. Disable bridge. Generate specs 11-20. Assert: modules 11-20 use static weights and no priors (graceful degradation)
- [x] `TINT-LOOP-08` — **Correction contradicts a prior.** Project A's prior says "merge auth+users." Project B's correction says "split auth from users." Assert: contradiction detected, prior confidence decreases, both stored for human resolution

##### Full Loop — Adversarial
- [x] `TINT-LOOP-09` — **Malicious project poisons the prior pool.** Project A stores 50 bogus decisions (confidence 0.99). Assert: human rejections decrease confidence rapidly, after 5 rejections bogus priors drop below threshold
- [x] `TINT-LOOP-10` — **Feedback loop amplification attack.** Create a cycle: verification failure → boost weight → over-emphasize section → different failure → repeat 10 iterations. Assert: weights are bounded (no single weight exceeds 5.0), system converges
- [x] `TINT-LOOP-11` — **Stale corrections from a deleted codebase.** Project A deleted from drift.db but corrections remain in cortex.db. Assert: stale corrections returned but flagged as "source project no longer available" with reduced confidence

##### Full Loop — Concurrency
- [x] `TINT-LOOP-12` — **Two projects decomposing simultaneously with shared priors.** Assert: both get the same priors, both apply independently, no interference
- [x] `TINT-LOOP-13` — **Spec generation and verification running in parallel for different modules.** Assert: no deadlock, spec generation sees consistent weight snapshot

##### Full Loop — Corruption Recovery
- [x] `TINT-LOOP-14` — **cortex.db corrupted mid-pipeline, then restored.** (1) Generate specs 1-5 with bridge. (2) Corrupt cortex.db. (3) Generate specs 6-10 → graceful fallback. (4) Restore cortex.db. (5) Generate specs 11-15 → bridge reconnects
- [x] `TINT-LOOP-15` — **drift.db and cortex.db have inconsistent state.** drift.db says Module A is `spec_approved`, cortex.db has no Decision memory. Assert: bridge detects inconsistency, logs warning, flags for re-approval

##### Full Loop — Regression
- [x] `TINT-LOOP-16` — **D1 compliance: Drift crates have zero Cortex imports.** Static analysis of all Drift crate Cargo.toml files. Assert: none list any `cortex-*` dependency
- [x] `TINT-LOOP-17` — **D4 compliance: Nothing depends on `cortex-drift-bridge`.** Assert: bridge appears only in workspace members list, never as a dependency of any other crate
- [x] `TINT-LOOP-18` — **Loop convergence: spec quality improves over 5 iterations.** Generate spec → correct → re-generate → correct → re-generate. Assert: correction count monotonically decreases
- [x] `TINT-LOOP-19` — **Memory type mapping is exhaustive.** For each of the 10 events in the Appendix table, assert: the bridge produces exactly the memory type specified. Cross-reference with `cortex-core`'s `MemoryType` enum

#### Integration & Performance Contracts
- [x] `T9-INT-01` — Performance: event mapping <5ms per event, grounding single memory <50ms, full loop (500 memories) <10s
- [x] `T9-INT-02` — Test bridge crate compiles with both drift-core and cortex-core as dependencies (no version conflicts)
- [x] `T9-INT-03` — Test bridge storage tables respect retention policies: Community 90 days, Enterprise unlimited

#### Build & Coverage Gate
- [x] `T9-INT-04` — `cargo tarpaulin -p cortex-drift-bridge` reports ≥80% line coverage
- [x] `T9-INT-05` — `cargo clippy -p cortex-drift-bridge` passes with zero warnings

### QG-9: Phase 9 Quality Gate (Milestone 7: "It Grounds")

- [x] Bridge crate compiles with both drift-core and cortex-core as dependencies
- [x] Event mapping creates correct Cortex memory types from Drift events
- [x] Link translation produces valid EntityLink from PatternLink
- [x] Grounding logic computes grounding percentage for pattern memories
- [x] Grounding feedback loop adjusts Cortex memory confidence based on scan results
- [x] `drift_why` synthesizes pattern data + causal memory
- [x] `drift_memory_learn` creates memory from Drift analysis
- [x] ATTACH cortex.db works for cross-DB queries
- [x] Graceful degradation when cortex.db doesn't exist
- [x] ≥1 grounding result per groundable type (13/23)
- [x] Threshold tiers classify correctly (≥0.7/≥0.4/≥0.2/<0.2)
- [x] `SpecCorrection` creates causal edges in CausalEngine (Enhancement 1)
- [x] Bridge `DecompositionPriorProvider` returns priors for DNA-similar projects (Enhancement 2)
- [x] Bridge `WeightProvider` computes adaptive weights from verification failures (Enhancement 3)
- [x] All 10 event→memory mappings from the Appendix are implemented
- [x] Causal narrative generation produces human-readable spec explanations
- [x] End-to-end loop: correction→causal→narrative produces improved specs
- [x] D1 compliance: Drift crates have zero Cortex imports
- [x] D4 compliance: Nothing depends on `cortex-drift-bridge`

---

## Phase 10: Polish & Ship (Workspace, Licensing, Docker, Telemetry, IDE)

> **Goal:** Build remaining cross-cutting and presentation systems for a shippable product.
> **Estimated effort:** 4–6 weeks (5+ devs), 8–10 weeks (3 devs), 22–28 weeks (1 dev). Highly parallelizable.
> **Priority:** P0 (ship-blocking): Workspace, Licensing, Docker. P1: VSCode, LSP, AI Providers. P2: Dashboard, Galaxy, Telemetry, CIBench.
> **No V2-PREP for most systems.** Spec each at start of Phase 10.

### 10A — Workspace Management (System 33)

> **V2-PREP:** 33-WORKSPACE-MANAGEMENT. drift.db lifecycle, workspace detection, backup, health checks.
> **Performance targets:** init <500ms, backup <5s for 100MB db.

- [ ] `P10-WS-01` — Create `drift-napi/src/bindings/workspace.rs` — 16 workspace management NAPI functions
- [ ] `P10-WS-02` — Implement drift.db lifecycle: create, open, migrate, backup, vacuum
- [ ] `P10-WS-03` — Implement workspace detection + monorepo support
- [ ] `P10-WS-04` — Implement `drift setup` wizard (creates drift.toml + drift.db)
- [ ] `P10-WS-05` — Implement `drift doctor` health checks
- [ ] `P10-WS-06` — Implement hot backup via SQLite Backup API
- [ ] `P10-WS-07` — Implement process-level locking via `fd-lock`

### 10B — Licensing & Feature Gating

- [ ] `P10-LIC-01` — Implement 3-tier licensing: Community (free, core analysis), Team (advanced + CI), Enterprise (full stack + OWASP compliance + telemetry)
- [ ] `P10-LIC-02` — Implement 16 gated features with JWT validation
- [ ] `P10-LIC-03` — Implement graceful degradation (missing/expired license)

### 10C — Docker Deployment

- [ ] `P10-DOC-01` — Create Dockerfile for multi-arch Alpine images (amd64 + arm64)
- [ ] `P10-DOC-02` — Pre-built native binaries for all 8 platform targets
- [ ] `P10-DOC-03` — HTTP/SSE MCP transport for containerized deployment

### 10D — Telemetry

- [ ] `P10-TEL-01` — Implement Cloudflare Worker + D1 backend for anonymous usage metrics
- [ ] `P10-TEL-02` — Implement opt-in only telemetry with anonymous_id

### 10E — IDE Integration

- [ ] `P10-IDE-01` — Create VSCode Extension: inline violation highlighting, quick fix suggestions
- [ ] `P10-IDE-02` — Create VSCode Extension: pattern explorer sidebar, health score status bar
- [ ] `P10-IDE-03` — Create LSP Server: IDE-agnostic diagnostics, code actions, hover information
- [ ] `P10-IDE-04` — Create Dashboard: Web visualization (Vite + React + Tailwind), pure consumer of drift.db
- [ ] `P10-IDE-05` — Create Galaxy: 3D codebase visualization (Three.js) — lowest priority

### 10F — AI Providers

- [ ] `P10-AI-01` — Implement Anthropic/OpenAI/Ollama abstraction layer (TypeScript)
- [ ] `P10-AI-02` — Power `drift explain` and `drift fix` commands

### 10G — CIBench

- [ ] `P10-BEN-01` — Implement 4-level benchmark framework in drift-bench: micro (criterion), component (integration), system (end-to-end), regression (CI)
- [ ] `P10-BEN-02` — Create `drift-bench/benches/end_to_end_bench.rs` — Full pipeline benchmark
- [ ] `P10-BEN-03` — Create `drift-bench/src/fixtures.rs` — Shared test fixtures and generators

### Phase 10 Tests

#### Workspace Management — Lifecycle & Concurrency
- [ ] `T10-WS-01` — Test `drift setup` wizard creates drift.toml and drift.db correctly with all required tables and PRAGMAs
- [ ] `T10-WS-02` — Test `drift doctor` detects and reports: missing drift.toml, outdated schema, corrupt drift.db, missing tree-sitter grammars, incompatible Node.js version
- [ ] `T10-WS-03` — Test hot backup via SQLite Backup API completes for 100MB database in <5s — verify backup is valid (can be opened and queried)
- [ ] `T10-WS-04` — Test `fd-lock` prevents concurrent drift.db access: start two drift processes on same workspace — second process gets lock error, not corruption
- [ ] `T10-WS-05` — Test workspace detection: monorepo with 3 packages, each gets own analysis scope
- [ ] `T10-WS-06` — Test drift.db migration from v001 to latest: create v001 database, run migrations, verify all tables present and data preserved
- [ ] `T10-WS-07` — Test `drift setup` on directory with existing drift.toml — prompts for overwrite confirmation, doesn't silently destroy config
- [ ] `T10-WS-08` — Test backup rotation: max_backups=3, create 5 backups — verify only 3 most recent retained

#### Licensing — Feature Gating & Graceful Degradation
- [ ] `T10-LIC-01` — Test license validation correctly gates all 16 features per tier (Community, Team, Enterprise)
- [ ] `T10-LIC-02` — Test graceful degradation when license is missing: core analysis works, gated features return "upgrade required" message (not crash)
- [ ] `T10-LIC-03` — Test expired license: features degrade gracefully with 7-day grace period, then hard gate
- [ ] `T10-LIC-04` — Test JWT validation: valid JWT → features unlocked, tampered JWT → rejected, expired JWT → grace period
- [ ] `T10-LIC-05` — Test license tier upgrade without restart: swap JWT file, verify new features available on next operation

#### Docker — Multi-Arch & Transport
- [ ] `T10-DOC-01` — Test Docker multi-arch images build for both amd64 and arm64 — verify both architectures produce working containers
- [ ] `T10-DOC-02` — Test HTTP/SSE MCP transport in containerized deployment — MCP client outside container can connect and call tools
- [ ] `T10-DOC-03` — Test Docker container starts with minimal config (just mount workspace) — drift.db created automatically
- [ ] `T10-DOC-04` — Test Docker container resource limits: 512MB RAM limit, verify OOM doesn't corrupt drift.db

#### IDE Integration — User-Facing Features
- [ ] `T10-IDE-01` — Test VSCode extension displays inline violations with correct severity icons and quick fix suggestions
- [ ] `T10-IDE-02` — Test LSP server provides diagnostics that match CLI `drift check` output (consistency between interfaces)
- [ ] `T10-IDE-03` — Test LSP code actions: quick fix applied via LSP produces same result as CLI `drift fix`

#### Benchmarks — Regression Detection
- [ ] `T10-BEN-01` — Test CIBench 4-level benchmarks (micro, component, system, regression) run without regression vs. baseline
- [ ] `T10-BEN-02` — Test end-to-end benchmark: full pipeline on 10K-file fixture completes within 2x of baseline (no catastrophic regression)
- [ ] `T10-BEN-03` — Test benchmark fixtures are deterministic: same fixture produces same results across runs

#### Build & Coverage Gate
- [ ] `T10-INT-01` — `cargo tarpaulin --workspace` reports ≥80% average line coverage across all Rust crates
- [ ] `T10-INT-02` — TypeScript test suite reports ≥80% coverage across all TS packages
- [ ] `T10-INT-03` — `cargo clippy --workspace` passes with zero warnings
- [ ] `T10-INT-04` — `cargo deny check` passes with zero advisories

### QG-10: Phase 10 Quality Gate (Milestone 8: "It's Complete")

- [ ] `drift setup` wizard creates drift.toml and drift.db correctly
- [ ] `drift doctor` detects and reports common configuration issues
- [ ] Hot backup via SQLite Backup API completes for 100MB database in <5s
- [ ] `fd-lock` prevents concurrent drift.db access
- [ ] License validation correctly gates features per tier
- [ ] Graceful degradation when license is missing or expired
- [ ] Docker multi-arch images build and run correctly
- [ ] HTTP/SSE MCP transport works in containerized deployment
- [ ] VSCode extension displays inline violations and quick fix suggestions
- [ ] LSP server provides diagnostics and code actions
- [ ] CIBench 4-level benchmarks run in CI without regression
- [ ] All Phase 10 systems persist configuration to drift.db

---

## Milestone Summary

| Milestone | Phase | Description | Timeline (1 dev, 1.3x) |
|-----------|-------|-------------|------------------------|
| M1: "It Scans" | End of P1 | Scan, parse, persist, call from TS | ~4–6.5 weeks |
| M2: "It Detects" | End of P2 | 16 detector categories, call graph, boundaries | ~8–12 weeks |
| M3: "It Learns" | End of P3 | Conventions discovered, confidence scored, outliers flagged | ~12–17 weeks |
| M4: "It Secures" | End of P4 | Taint analysis, reachability, impact, test topology | ~13–19.5 weeks |
| M5: "It Enforces" | End of P6 | Quality gates, SARIF, pass/fail decisions | ~16–22 weeks |
| M6: "It Ships" | End of P8 | MCP server, CLI, CI agent working | ~18–24 weeks |
| M7: "It Grounds" | End of P9 | Cortex bridge, grounding feedback loop | ~17–25 weeks |
| M8: "It's Complete" | End of P10 | All ~55 systems, IDE, Docker, telemetry | ~22–30 weeks |

## Critical Path

```
Phase 0 (1-2w) → Phase 1 (2-3w) → Phase 2 Track A (2w) → Phase 3 (3-4w) →
Phase 6 (2-3w) → Phase 8 (2w)
= 12-16 weeks optimistic, 16-21 weeks realistic (1.3x) for a shippable product
```

Phases 4 and 5 run alongside Phases 3 and 6, adding zero time to the critical path with sufficient developers.

## Team Size Recommendations

| Team Size | Optimistic | Realistic (1.3x) | Strategy |
|-----------|-----------|-------------------|----------|
| 1 dev | 6–8 months | 8–10 months | Sequential: P0→P1→P2→P3→P6→P8 first, then P4→P5→P7 for depth |
| 2 devs | 4–5 months | 5–6.5 months | Dev A: critical path (P0→P1→P2A→P3→P6). Dev B: P2B→P4→P5. Converge at P8 |
| 3–4 devs | 3–4 months | 4–5 months | Full parallelism in P4 and P5. Critical path still 12–16 weeks |
| 5+ devs | 2.5–3 months | 3–4 months | Maximum parallelism. P4+P5 complete in 4–6 weeks with 5 tracks |

## Risk Register Quick Reference

| Risk | Severity | Mitigation |
|------|----------|------------|
| R1: tree-sitter v0.25 grammar compat | Medium | Test all 10 grammars in P0, pin versions |
| R2: napi-rs v3 maturity | Medium | Fall back to v2 with compat-mode if needed |
| R3: Taint analysis complexity (NET NEW) | High | Ship intraprocedural first, interprocedural incrementally |
| R5: 350+ detector count | High | Start with 50-80 high-value, add long tail incrementally |
| R6: Cross-language GAST normalization | Medium-High | Start with 3-4 languages, mandatory coverage_report() |
| R8: UAE 22-27 week timeline | High | Ship core pipeline in P2, continue porting through P3-P5 |
| R9: Contract tracking 20-week scope | Medium | Ship REST + GraphQL first, add paradigms incrementally |
| R18: Estimation overconfidence (~30%) | Medium | Apply 1.3x multiplier for all planning |

---

> **Generated:** 2026-02-08
> **Source documents:** DRIFT-V2-IMPLEMENTATION-ORCHESTRATION.md, SCAFFOLD-DIRECTORY-PROMPT.md, SPECIFICATION-ENGINE-NOVEL-LOOP-ENHANCEMENT.md, SPECIFICATION-ENGINE-TEST-PLAN.md
> **Format reference:** CORTEX-TASK-TRACKER.md
> **Total:** 571 implementation tasks + 635 test tasks + 118 quality gate criteria = 1,324 checkboxes
> **Specification Engine Enhancement:** +18 impl tasks, +131 test tasks across Phases 5, 7, 9 (source: Novel Loop Enhancement + Test Plan)
