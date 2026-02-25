# Drift V2 — Production Test Suite Design

> **Source of truth:** Verified against actual source code in `crates/drift/`, `crates/cortex/`, `crates/cortex-drift-bridge/`, and the [CRITICAL-FLOW-MAP.md](./CRITICAL-FLOW-MAP.md) schema audit (DD-15/DD-16).

---

## Executive Summary

**What this document is:** The definitive specification for 225 production tests across 27 categories that must pass before Drift V2 ships to beta. Each test has a unique ID, precise pass/fail criteria, and line-verified source references.

**What this document is NOT:** A unit test plan. The ~4,500 existing unit/integration tests in the three Rust workspaces and six TS packages are foundational but test individual subsystems in isolation. This document specifies the *production boundary tests* — the tests that validate correctness at the seams where subsystems interact, where users/agents hit real entry points, and where the system must degrade gracefully under failure.

**Audience:**
- **Implementers** — Use the per-test specifications (Categories 1–27) to write each test. The Source Verification column tells you exactly which line of code to exercise.
- **Reviewers** — Use the Summary Matrix and Implementation Tracking Checklist to gauge progress. The Coverage Inventory shows what's already covered vs. what's net-new work.
- **CI engineers** — Use the CI Integration Plan to set up the test pipeline with correct parallelization, timing budgets, and gating strategy.

**Scope:** All 14 flows from [CRITICAL-FLOW-MAP.md](./CRITICAL-FLOW-MAP.md): Scanner, Parser, Detection Engine, Analysis Pipeline, Pattern Intelligence, Structural Analysis (10 subsystems), Graph Intelligence (5 subsystems), Enforcement Engine, Storage Layer, NAPI Bindings (109 total), Presentation Layer (MCP/CLI/CI), Cortex Memory System, Cortex-Drift Bridge, and Advanced Systems. Plus 5 cross-cutting categories: E2E Smoke, Graceful Degradation, Performance Budgets, Idempotency, and Production Hardening.

**Key numbers:**
- **225 tests** across **27 categories**
- **91 P0** (7 categories) → **110 P1** (10 categories) → **24 P2** (5 categories)
- Estimated implementation: **15–21 working days** (see Implementation Order)
- Existing coverage: **~35% partial** (see Coverage Inventory)

---

## Test Infrastructure Requirements

### Rust Test Framework

All Rust production tests live in `tests/` directories (integration tests, not unit tests) so they exercise the public API boundary of each crate.

| Requirement | Value |
|-------------|-------|
| **Framework** | `#[test]` + `#[tokio::test]` for async |
| **Assertion style** | `assert!`, `assert_eq!`, `assert!(matches!(...))` — no external crate |
| **Temp directories** | `tempfile::TempDir` for DB isolation — each test gets its own `drift.db` / `cortex.db` |
| **Concurrency tests** | `std::thread::spawn` + `Arc<Barrier>` for thread rendezvous |
| **Timing tests** | `std::time::Instant` with generous margins (2× expected for CI) |
| **Property tests** | `proptest` where marked (Cat 3, Cat 15) |

**Test file naming:** `production_cat{N}_test.rs` (e.g., `production_cat1_test.rs` for Category 1). This separates production tests from existing hardening/stress/unit tests for clear CI gating.

**Quality gates per test file:**
```bash
# Must pass before merge
cargo test -p <crate> --test production_cat<N>_test
cargo clippy -p <crate> --tests -- -D warnings
```

### TypeScript Test Framework

| Requirement | Value |
|-------------|-------|
| **Framework** | Vitest (already configured in all 6 packages) |
| **Assertion style** | `expect()` from Vitest |
| **NAPI mocking** | `setNapi(createStubNapi())` for tests that don't need the native binary |
| **NAPI real** | Load real `.node` binary for E2E tests (Cat 20, 23) |
| **MCP testing** | Direct function calls to tool handlers (not stdio transport) |
| **CLI testing** | `execa` or direct command import + `--help` parsing |

**Test file naming:** `production_cat{N}.test.ts` in the appropriate package's `tests/` directory.

### Required Build Artifacts

Before the production test suite can run in full:

| Artifact | Build Command | Required By |
|----------|--------------|-------------|
| `drift-napi` native binary | `cd crates/drift/drift-napi && napi build --release` | Cat 1, 20, 23, 24 |
| `cortex-napi` native binary | `cd crates/cortex/cortex-napi && napi build --release` | Cat 19, 23 |
| All TS packages compiled | `npm run build:ts` (root) | Cat 20 |
| `test-fixtures/` repo | Already exists at repo root | Cat 5, 9, 15, 16, 23 |
| Multi-language fixture repo | See Fixture Specifications below | Cat 15, 23 |

---

## Existing Coverage Inventory

The codebase already has **~4,565 Rust tests** and **~47 TS test files**. This inventory maps existing tests to production test categories to identify what's net-new work vs. what already has partial coverage.

### Coverage Heat Map

| Cat | Category | Prod Tests | Existing Test Files | Existing Coverage | Net-New Work |
|-----|----------|-----------|-------------------|-------------------|-------------|
| 1 | NAPI Threading | 11 | `drift-napi/tests/napi_test.rs` (8), `drift-napi-contracts/tests/loader.test.ts`, `stub_completeness.test.ts` | **~25%** — init, basic binding; missing: parallelism, cancellation, ThreadsafeFunction, camelCase fidelity | ~8 new tests |
| 2 | SQLite/WAL | 13 | `drift-storage/tests/connection_test.rs`, `batch_test.rs`, `drift_file_persistence_test.rs` | **~40%** — WAL, pragmas, batch basics; missing: backpressure, poison recovery, in-memory behavioral diff | ~7 new tests |
| 3 | Intelligence | 11 | `confidence_test.rs`, `outliers_test.rs`, `learning_test.rs`, `aggregation_test.rs`, `pattern_integration_test.rs` | **~60%** — Bayesian scoring, outlier ensemble, convention learning; missing: saturation, credible interval extremes, DataQuality | ~4 new tests |
| 4 | Bridge Grounding | 6 | `grounding_test.rs`, `enterprise_final_gaps_test.rs`, `link_translation_test.rs`, `enterprise_hardening_test.rs`, `enterprise_critical_infra_test.rs`, `enterprise_data_integrity_test.rs` (287 tests) | **~80%** — prepopulated vs fallback, atomic link removal, evidence types; missing: schema duplication verification | ~1 new test |
| 5 | Analysis Pipeline | 8 | `e2e_full_pipeline_test.rs` (132), `integration_test.rs`, `determinism_test.rs` | **~50%** — full pipeline, incremental; missing: phase ordering timing, L2 hash skip, language detection exhaustive | ~4 new tests |
| 6 | Enforcement Gates | 16 | `gates_test.rs`, `enforcement_hardening_test.rs`, `enforcement_integration_test.rs`, `policy_test.rs`, `feedback_test.rs`, `rules_test.rs`, `stress_enforcement_test.rs` | **~55%** — gate logic, policy modes, feedback; missing: suppression 4-format, quick-fix 7-lang, progressive 4-phase, abuse detection | ~7 new tests |
| 7 | BatchCommand | 5 | `batch_writer_completeness_test.rs` (22), `batch_test.rs` | **~70%** — all 33 data commands; missing: 13 unwired tables, Drop behavior | ~2 new tests |
| 8 | Migration/Schema | 6 | `migration_test.rs` | **~30%** — basic migration; missing: FK integrity, PART2, idempotent re-open, pragma verification | ~4 new tests |
| 9 | Incremental Scan | 10 | `scanner_test.rs`, `p0_stress_test.rs` | **~30%** — basic scan; missing: L2 skip, cancellation mid-walk/hash, event sequence, .driftignore | ~7 new tests |
| 10 | Reporter Formats | 10 | `reporters_test.rs`, `reporters_phase8_test.rs` | **~40%** — SARIF, JUnit fixes; missing: GitHub/GitLab annotations, HTML, all 8 via driftReport() | ~6 new tests |
| 11 | Contracts | 8 | `contracts_test.rs`, `contracts_extractors_test.rs`, `contracts_breaking_changes_test.rs`, `contracts_schema_parsers_test.rs`, `stress_contracts_test.rs` (55+15 adversarial) | **~80%** — adversarial tests cover most; missing: type mismatch E2E, empty batch | ~2 new tests |
| 12 | Event System | 4 | `events_test.rs` | **~15%** — basic handler; missing: full sequence, fan-out, progress frequency, error event | ~3 new tests |
| 13 | Retention | 4 | `retention_integration_test.rs` (8) | **~60%** — orphan cleanup, tier correctness; missing: self-bounding, tier assignment completeness | ~2 new tests |
| 14 | Configuration | 4 | `config_test.rs` | **~40%** — defaults; missing: TOML round-trip, extra_ignore, project root fallback | ~2 new tests |
| 15 | Parser | 10 | `parsers_test.rs`, `parser_extraction_completeness_test.rs`, `language_provider_test.rs` | **~35%** — basic parsing; missing: all 10 langs, cache hit/miss, error recovery, empty file, NAPI round-trip | ~6 new tests |
| 16 | Detection Engine | 7 | `detectors_test.rs`, `detector_parity_test.rs`, `engine_test.rs`, `owasp_cwe_test.rs` | **~40%** — detector execution, CWE mapping; missing: panic safety, learning 2-pass, all 16 categories fire, category filtering | ~4 new tests |
| 17 | Structural | 10 | `coupling_test.rs`, `wrappers_test.rs`, `crypto_test.rs`, `dna_test.rs`, `constants_test.rs`, `constraints_test.rs`, `decomposition_test.rs` + stress variants | **~50%** — individual subsystems; missing: Martin metrics formula, env 8-lang, secrets entropy, magic number named-vs-unnamed | ~5 new tests |
| 18 | Graph Intelligence | 11 | `call_graph_test.rs`, `call_graph_hardening_test.rs`, `taint_test.rs`, `error_handling_test.rs`, `impact_test.rs`, `test_topology_test.rs`, `reachability_test.rs`, `graph_integration_test.rs` + p4_stress_* (6 files) | **~45%** — individual subsystems; missing: all 6 resolution strategies, import-based fix validation, incremental rebuild, over-approximation guard | ~6 new tests |
| 19 | Cortex Memory | 12 | cortex-storage E2E (235), cortex-embeddings E2E (19), cortex-privacy E2E (28), cortex-prediction E2E (9), multiagent tests, decay tests, session tests | **~40%** — subsystem-level; missing: NAPI-level CRUD lifecycle, re-embed on update, namespace RBAC E2E, validation 4-dim | ~7 new tests |
| 20 | Presentation Layer | 12 | `drift-mcp/tests/` (19 files), `drift-cli/tests/` (3 files), `drift-ci/tests/` (4 files), `drift-napi-contracts/tests/` (6 files) | **~30%** — infrastructure modules, tool catalogs, NAPI alignment; missing: all 6 entry points E2E, `drift analyze` wiring, simulate/explain invalid args, CI 10-pass execution | ~8 new tests |
| 21 | Advanced Systems | 6 | `simulation_test.rs`, `decisions_test.rs`, `context_test.rs`, `specification_test.rs` | **~45%** — individual calls; missing: all 13 categories, Monte Carlo convergence, 5×3 intent/depth matrix | ~3 new tests |
| 22 | Production Hardening | 9 | None | **0%** — all net-new | 9 new tests |
| 23 | E2E Smoke | 6 | `e2e_full_pipeline_test.rs` (partial) | **~15%** — partial pipeline; missing: golden path with DB verification, incremental re-scan, deletion, empty repo, multi-lang, bridge E2E | ~5 new tests |
| 24 | Graceful Degradation | 7 | None | **0%** — all net-new | 7 new tests |
| 25 | Performance Budgets | 6 | `stress_test.rs`, `p0_stress_test.rs`, `p4_stress_*.rs` (timing assertions) | **~20%** — some timing in stress tests; missing: explicit budget gates with documented thresholds | ~5 new tests |
| 26 | Idempotency | 5 | `determinism_test.rs` (partial) | **~20%** — analysis determinism partial; missing: scanner sort, convention, enforcement, report stability | ~4 new tests |
| 27 | Bridge Expanded | 8 | Bridge tests (287 total) — partial | **~35%** — grounding, link translation; missing: all 10 evidence types E2E, causal narrative, batch grounding, NAPI exposure | ~5 new tests |

### Summary

| Metric | Value |
|--------|-------|
| **Total production tests specified** | 225 |
| **Already fully covered by existing tests** | ~35 (15%) |
| **Partially covered (need adaptation or expansion)** | ~68 (30%) |
| **Net-new tests to write** | ~122 (55%) |
| **Existing test files that map to production tests** | ~85 Rust + ~35 TS = ~120 files |
| **Existing test functions (all workspaces)** | ~4,565 Rust + ~950 TS ≈ 5,500 total |

### Existing Test File → Category Mapping (Key Files)

**Drift Analysis** (`crates/drift/drift-analysis/tests/` — 75 files, ~1,601 tests):

| Test File | Maps To Cat | Coverage Notes |
|-----------|-------------|----------------|
| `e2e_full_pipeline_test.rs` | 5, 11, 23 | 132 tests — broadest existing E2E but doesn't verify DB persistence |
| `enforcement_hardening_test.rs` | 6 | Gate logic, empty input behavior, progressive |
| `gates_test.rs` | 6 | Individual gate evaluation |
| `reporters_test.rs` + `reporters_phase8_test.rs` | 10 | SARIF, JUnit, SonarQube format fixes |
| `contracts_extractors_test.rs` | 11 | 14 extractors, 55 tests |
| `parsers_test.rs` | 15 | Parser basics, language detection |
| `detectors_test.rs` + `detector_parity_test.rs` | 16 | Detector output validation |
| `call_graph_test.rs` + `call_graph_hardening_test.rs` | 18 | Call graph resolution strategies |
| `taint_test.rs` | 18 | Taint analysis flows |
| `graph_integration_test.rs` | 18 | Cross-graph-subsystem integration |
| `scanner_test.rs` | 5, 9 | Incremental scan basics |
| `confidence_test.rs` + `learning_test.rs` + `outliers_test.rs` | 3 | Pattern intelligence subsystems |
| `simulation_test.rs` + `decisions_test.rs` | 21 | Advanced system basics |
| `determinism_test.rs` | 26 | Partial idempotency checks |

**Drift Storage** (`crates/drift/drift-storage/tests/` — 18 files, ~210 tests):

| Test File | Maps To Cat | Coverage Notes |
|-----------|-------------|----------------|
| `batch_writer_completeness_test.rs` | 7 | All 33 BatchCommand variants |
| `connection_test.rs` | 2 | Writer/reader pool basics |
| `drift_file_persistence_test.rs` | 2, 8 | WAL mode, pragmas, restart survival |
| `retention_integration_test.rs` | 13 | 4-tier retention with real schema |
| `migration_test.rs` | 8 | Basic migration run |
| `drift_edge_cases_test.rs` | 2 | SQL injection, Unicode, boundary values |

**Cortex-Drift Bridge** (`crates/cortex-drift-bridge/tests/` — 13 files, ~599 tests):

| Test File | Maps To Cat | Coverage Notes |
|-----------|-------------|----------------|
| `enterprise_final_gaps_test.rs` | 4, 27 | drift_db fallback, prepopulated priority, atomic links |
| `link_translation_test.rs` | 4, 27 | Cross-DB link resolution |
| `enterprise_hardening_test.rs` | 4 | 114 enterprise hardening tests |
| `enterprise_critical_infra_test.rs` | 4 | 77 critical infrastructure tests |

**TS Packages** (~47 test files):

| Test File | Maps To Cat | Coverage Notes |
|-----------|-------------|----------------|
| `drift-mcp/tests/infrastructure/*.test.ts` (8 files) | 20 | Cache, rate limiter, token estimator, etc. |
| `drift-mcp/tests/tools/*.test.ts` (6 files) | 20 | Tool catalog, discover, workflow |
| `drift-mcp/tests/integration/*.test.ts` (4 files) | 20 | Concurrent requests, full pipeline, parity |
| `drift-cli/tests/cli.test.ts` | 20 | Command parsing |
| `drift-ci/tests/ci_agent.test.ts` | 20 | CI agent pass execution |
| `drift-napi-contracts/tests/loader.test.ts` | 1 | Stub fallback, binary loading |

---

## Test Fixture Specifications

Production tests require specific fixture repos and data that may not exist yet. This section catalogs them.

### Fixture 1: Multi-Language Repo (`test-fixtures/multi-lang/`)

**Required by:** T15-02, T23-05, T17-09

| Language | File | Must Contain |
|----------|------|-------------|
| TypeScript | `src/auth.ts` | Functions, classes, imports, exports, decorators, call sites, string literals, error handling |
| JavaScript | `src/utils.js` | `eval()` call (for T16-07 CWE mapping), logging, REST endpoint |
| Python | `src/api.py` | `@api_view`, `os.environ`, try/except, dataclass |
| Java | `src/Service.java` | `@SuppressWarnings`, `System.getenv()`, generics, annotations |
| C# | `src/Controller.cs` | `Environment.GetEnvironmentVariable()`, async/await |
| Go | `src/handler.go` | `os.Getenv()`, `if err != nil`, goroutine |
| Rust | `src/lib.rs` | `std::env::var()`, `Result<T, E>`, trait impl |
| Ruby | `src/app.rb` | `ENV["KEY"]`, `rescue`, Rails `resources` |
| PHP | `src/index.php` | `getenv()`, `try/catch`, Laravel route |
| Kotlin | `src/Main.kt` | `@SuppressWarnings`, coroutine, data class |

### Fixture 2: Contract Extraction Repo (`test-fixtures/contracts/`)

**Required by:** T11-01 through T11-08

Must include:
- Express backend (`backend/express/`)
- Next.js API routes (`backend/nextjs/pages/api/`)
- tRPC server (`backend/trpc/`)
- Frontend React app with `fetch()` and `useMutation` calls (`frontend/`)
- Matching and disjoint API paths for mismatch testing

### Fixture 3: Large Synthetic Repo (`test-fixtures/large/`)

**Required by:** T1-02, T22-04, T25-01, T25-02

Generated via script (not committed to repo):
- **1,000 files** with valid syntax across 5 languages
- **10,000 functions** in a single file (for T1-02 buffer stress)
- **50,000 lines** in a single TS file (for T15-08)
- Consistent naming so scan results are deterministic

**Generator script:** `test-fixtures/generate_large_repo.sh` (to be created)

### Fixture 4: Taint/Security Repo (`test-fixtures/security/`)

**Required by:** T18-04, T18-05, T18-06, T17-06

Must include:
- `req.body` → intermediate functions → `db.query()` (3-hop taint chain)
- AWS secret key in a config file (for T17-06 entropy filtering)
- `MD5`, `SHA1`, `DES` usage (for T17-04 weak crypto)
- `eval(userInput)` (for T16-07 CWE-95)

### Fixture 5: Coupling/Graph Repo (`test-fixtures/graph/`)

**Required by:** T17-01, T17-02, T18-01, T18-09

Must include:
- Circular import chain A→B→C→A
- Function with 10 callers (for blast radius T18-08)
- Dead code function with 0 callers, NOT a route handler
- Route handler with 0 callers and `@Get` decorator (must NOT be flagged as dead)
- Same-file calls, imported calls, exported functions, DI-injected services

---

## Category 1: NAPI Memory & Threading Boundary

Because Rust's rayon and tokio run alongside the Node.js event loop, the biggest risk is thread-affinity and memory exhaustion.

| ID | Test | Parameter | Source Verification |
|----|------|-----------|---------------------|
| T1-01 | **Parallelism Ceiling** — Set `RAYON_NUM_THREADS` to 1, 4, 16, 32. Verify scanner.rs `par_iter()` (line 92) doesn't starve the Node.js event loop during Phase 2 classification. | Success if scan completes for each thread count without Node.js event loop stalls >500ms | `scanner.rs:92` uses `rayon::par_iter()` with `ScanConfig.threads` controlling `ignore::WalkBuilder.threads()` |
| T1-02 | **Buffer Transfer Stress** — Generate a file with 10,000 functions. Assert the NAPI bridge doesn't hit string/buffer limits when passing the massive `ParseResult` (18 fields including `Vec<FunctionInfo>`) from Rust to TypeScript. | Success if all 10,000 functions round-trip through NAPI without truncation or OOM | `ParseResult` has 18 fields; `FunctionInfo` has 18 fields each (verified DD02-E1) |
| T1-03 | **Cancellation Latency** — Trigger `ScanCancellation.cancel()` (using `AtomicBool` with `SeqCst` store in `cancellation.rs:25`) exactly 500ms into a heavy scan. | Success if process terminates in <100ms without orphaned SQLite handles | `cancellation.rs:25` stores `SeqCst`; walker checks `Relaxed` (line 90); scanner checks between phases (line 74, 94) |
| T1-04 | **OnceLock Double-Init Rejection** — Call `driftInitialize()` twice in the same process. | Must return `ALREADY_INITIALIZED` error code, not panic/deadlock | `runtime.rs:138` — `RUNTIME.set()` returns Err on second call |
| T1-05 | **BatchWriter Thread Survival** — Verify the `drift-batch-writer` thread (spawned in `writer.rs:80-83`) survives NAPI garbage collection cycles without being collected. | Thread must remain alive for entire runtime lifetime; `Drop` impl (line 116-121) only sends Shutdown | `writer.rs:80` — `thread::Builder::new().name("drift-batch-writer")` |
| T1-06 | **Concurrent NAPI Calls** — Fire 50 simultaneous `driftScan` + `driftAnalyze` + `driftCheck` calls from JS. | No deadlock on `DatabaseManager.writer` Mutex; read pool distributes correctly | `runtime.rs:29` — `db: DatabaseManager` has `Mutex<Connection>` writer + `ReadPool` readers |
| T1-07 | **AsyncTask Cancellation Propagation** — Start `driftScan` (returns `AsyncTask<ScanTask>`), then call `driftCancelScan()`. | `ScanCancellation.is_cancelled()` must propagate through the rayon `par_iter` (scanner.rs:94-96 returns `None`); Promise must resolve (not reject) with partial results | `scanner.rs:52` — `ScanTask` implements `Task` trait; cancellation via `AtomicBool` |
| T1-08 | **ThreadsafeFunction Progress Delivery** — Call `driftScanWithProgress` on a 500-file repo. Count progress callbacks received in JS. | Callbacks must fire from Rust worker thread to JS main thread without crash; count must be `ceil(500/100)` ≈ 5 progress events | `scanner.rs:99` — progress fires every 100 files via `ThreadsafeFunction<ProgressUpdate, ()>` |
| T1-09 | **NAPI Error Code Propagation** — Call `driftSimulate` with an invalid `task_category` string. | Must return structured `napi::Error` with descriptive message, not panic. Error must be catchable as JS exception. | `advanced.rs` — returns `Result<String>` which napi-rs converts to JS exception on Err |
| T1-10 | **snake_case → camelCase Binding Fidelity** — Load the native `.node` binary and enumerate all exported function names. | All 41 exports must be camelCase (e.g., `driftAnalyze`, NOT `drift_analyze`). Verified against `DRIFT_NAPI_METHOD_NAMES` array in `loader.ts`. | napi-rs v3 auto-converts; `loader.ts` validates all 40 method names at load time |
| T1-11 | **Stub Fallback on Missing Binary** — Call `loadNapi()` when no `.node` binary exists. | Must return `createStubNapi()` (not throw). All 40 stub methods must return safe empty defaults (empty arrays, false, void). | `loader.ts` — `loadNapi()` catches load failure, falls back to stub |

---

## Category 2: SQLite / WAL Concurrency

Drift V2 relies on a `BatchWriter` (bounded channel, 1024 capacity, 500-batch threshold) and a `ReadPool` (default 4 / max 8).

| ID | Test | Parameter | Source Verification |
|----|------|-----------|---------------------|
| T2-01 | **Write-Write Conflict** — Simulate two simultaneous `driftAnalyze` calls that both send BatchCommands. | System must serialize via BatchWriter's single channel; no SQLITE_BUSY because `with_immediate_transaction` acquires write lock at BEGIN (writer.rs) | `writer.rs:24` — `CHANNEL_BOUND: 1024`; `connection/writer.rs:17` — `BEGIN IMMEDIATE` |
| T2-02 | **WAL Checkpoint Pressure** — Run a scan that modifies 5,000 files, triggering 5,000 `UpsertFileMetadata` commands. Monitor `-wal` file size. | `-wal` must truncate after `DatabaseManager.checkpoint()` (PRAGMA wal_checkpoint(TRUNCATE)) | `connection/mod.rs:81-88` — `checkpoint()` calls `PRAGMA wal_checkpoint(TRUNCATE)` |
| T2-03 | **Retention Tier Logic** — Create a `file_metadata` entry, delete the file from disk, run scan. | Entry should appear in `ScanDiff.removed` (via `compute_diff` line 112-115), not be instantly purged | `incremental.rs:112-116` — files in cache but not on disk → `diff.removed` |
| T2-04 | **Channel Backpressure** — Flood the BatchWriter with >1024 commands without flushing. | Sender must block (bounded channel semantics); no data loss after channel drains | `writer.rs:24` — `bounded(CHANNEL_BOUND)` where `CHANNEL_BOUND = 1024` |
| T2-05 | **Batch Atomicity on Failure** — Inject a constraint violation mid-batch (e.g., duplicate PK). Verify the entire batch rolls back. | Buffer must be retained on rollback (line 180 iterates by reference, buffer only cleared after commit on line 323) | `writer.rs:178-180` — iterates `buffer.iter()` not consuming; line 323 — `buffer.clear()` only after `tx.commit()` |
| T2-06 | **Flush Timeout Drain** — Send 499 commands (below `BATCH_SIZE=500`), then wait >100ms. | Auto-flush must trigger on `FLUSH_TIMEOUT` (100ms) even though batch threshold not reached | `writer.rs:26` — `FLUSH_TIMEOUT: Duration::from_millis(100)`; line 145-148 — timeout path flushes non-empty buffer |
| T2-07 | **ReadPool Round-Robin Under Contention** — Spawn 8 concurrent read operations. | `AtomicUsize` round-robin (pool.rs:65) distributes across all 4 connections; no single-connection bottleneck | `pool.rs:65` — `fetch_add(1, Relaxed) % connections.len()` |
| T2-08 | **In-Memory BatchWriter Isolation** — In-memory mode: write via BatchWriter, read via `with_reader`. | Reads must NOT see batch writes (in-memory connections are separate DBs). This is a documented caveat. | `connection/mod.rs:97-98` — "batch writes won't be visible to the main writer — use only for testing" |
| T2-09 | **Writer Mutex Poison Recovery** — Panic inside `with_writer` closure. Subsequent `with_writer` call. | Must return `"write lock poisoned"` error, not hang | `connection/mod.rs:66-68` — `self.writer.lock().map_err(...)` |
| T2-10 | **ReadPool Poison Recovery** — Panic inside `with_reader` closure. Subsequent reads. | Must return `"read pool lock poisoned"` error for the poisoned slot; other slots continue working | `pool.rs:68-70` — per-connection `Mutex` means only one slot is poisoned |
| T2-11 | **Writer Pragma Verification** — After `DatabaseManager::open()`, query all 8 writer pragmas. | `journal_mode=wal`, `synchronous=1` (NORMAL), `foreign_keys=ON`, `cache_size=-64000`, `mmap_size=268435456`, `busy_timeout=5000`, `temp_store=2` (MEMORY), `auto_vacuum=2` (INCREMENTAL) | `pragmas.rs` — applies all 8 pragmas to writer connection |
| T2-12 | **Reader Pragma Isolation** — After open, query reader pragmas. | `query_only=ON`, `cache_size=-64000`, `mmap_size=268435456`, `busy_timeout=5000`. Writers must NOT have `query_only=ON`. | `pool.rs` — readers opened with `SQLITE_OPEN_READ_ONLY` + read pragmas |
| T2-13 | **File-Backed vs In-Memory Mode Behavioral Diff** — Run the same write+read sequence in both modes. | File-backed: BatchWriter writes visible to readers (WAL). In-memory: BatchWriter writes **invisible** to readers (separate DBs). Test must assert this documented caveat. | `connection/mod.rs:97-98` — in-memory caveat documented |

---

## Category 3: Intelligence Precision

Bayesian confidence scoring and DNA profiling are statistically driven — they can drift into inaccuracy.

| ID | Test | Parameter | Source Verification |
|----|------|-----------|---------------------|
| T3-01 | **Bayesian Convergence** — Feed `PatternIntelligencePipeline` 100 identical "False Positive" feedback loops via `InMemoryFeedbackStore.record()`. | `posterior_mean` must drop below `Uncertain` tier threshold (<0.50). Tier assignment: `types.rs:64-74` | `scorer.rs:151-157` — feedback adjustments applied as `(final_alpha + alpha_delta).max(0.01)`. Tiers: Established≥0.85, Emerging≥0.70, Tentative≥0.50, Uncertain<0.50 |
| T3-02 | **DNA Allele Consistency** — Use `GeneExtractorRegistry.with_all_extractors()` (10 extractors) to analyze a repo with 50% camelCase / 50% snake_case naming. | `dna_mutations` must flag both as inconsistent; dominant allele `frequency` ≥ 0.3 required for dominance (extractor.rs:84) | `extractor.rs:82-89` — dominant = highest frequency, must be ≥0.30; `consistency = alleles[0].frequency - alleles[1].frequency` (line 98-99) |
| T3-03 | **Taint Reachability Depth** — Set `max_depth` for `reachability_forward` to 5, 10, 50. | Execution time must scale linearly (not exponentially) when traversing the petgraph directed graph | `reachability/mod.rs` — auto-selects petgraph (<10K nodes) vs SQLite CTE (≥10K nodes) |
| T3-04 | **Confidence Tier Boundary Precision** — Create patterns with `posterior_mean` at exactly 0.50, 0.70, 0.85. | Must classify as Tentative, Emerging, Established respectively (no off-by-one at boundaries) | `types.rs:64-74` — `>=0.85` Established, `>=0.70` Emerging, `>=0.50` Tentative, `<0.50` Uncertain |
| T3-05 | **Temporal Decay Symmetry** — Score a pattern, then simulate 90 days of inactivity via `score_with_momentum`. | Both `alpha` AND `beta` must decay proportionally (preserving `posterior_mean` but widening credible interval) | `scorer.rs:216-222` — `score.alpha *= decay; score.beta *= decay;` then recomputes posterior_mean |
| T3-06 | **Feedback Loop Saturation** — Apply 10,000 dismiss feedback events to the same pattern. | `alpha` must never go below 0.01 (floor in scorer.rs:154); posterior_mean must not become NaN/Inf | `scorer.rs:154` — `.max(0.01)` floor on both alpha and beta after adjustment |
| T3-07 | **6-Factor Weight Invariant** — Verify that `WEIGHT_FREQUENCY + WEIGHT_CONSISTENCY + WEIGHT_AGE + WEIGHT_SPREAD + WEIGHT_MOMENTUM + WEIGHT_DATA_QUALITY == 1.0`. | Exact equality within f64 epsilon | `factors.rs:13-18` — 0.25 + 0.20 + 0.10 + 0.15 + 0.15 + 0.15 = 1.0 |
| T3-08 | **DataQuality Factor Impact** — Score the same pattern with `data_quality=0.3` vs `data_quality=0.9`. | Low quality must produce lower composite score; weight is 0.15 of total | `factors.rs:158-162` — clamped to [0.0, 1.0]; default is 0.7 |
| T3-09 | **Credible Interval Numerical Stability** — Compute CI with alpha=1e7, beta=1.0 (extreme skew). | Must return finite (low, high) values without NaN/Inf. Guard at beta.rs:77-81 | `beta.rs:77-81` — extreme values (>1e6) use mean±epsilon instead of inverse CDF |
| T3-10 | **Convention Persistence Across Runs** — Run pipeline twice with same matches using `InMemoryConventionStore`. | `scan_count` must increment; `discovery_date` preserved; `last_seen` updated | `pipeline.rs:266-282` — test already exists (PIT-INT-06) but needs DB-backed variant |
| T3-11 | **Outlier Detection Minimum Sample** — Feed outlier detector with <3 confidence values. | Must skip outlier detection (not crash); pipeline.rs line 117 filters `>=3` | `pipeline.rs:117` — `.filter(|p| p.confidence_values.len() >= 3)` |

---

## Category 4: Cross-System Bridge Grounding

The bridge between drift.db and cortex.db is the most complex inter-system link.

| ID | Test | Parameter | Source Verification |
|----|------|-----------|---------------------|
| T4-01 | **Link Translation — Broken Link** — Create a Cortex memory referencing a `file_id` in Drift. Delete that file's metadata. | Link translation must return "Broken Link" status, not null pointer/panic | Bridge `link_translation` module (tested in `link_translation_test.rs`) |
| T4-02 | **Grounding Score Weights** — Test all 10 evidence types. A change in `enforcement_status` (new violation) must trigger recalculation. | Grounding score must update for all associated memories within next loop iteration | Bridge `ground_single()` — Bug #6 fix ensured `_drift_db` parameter is not silently ignored |
| T4-03 | **Prepopulated vs Drift DB Fallback** — Provide `MemoryForGrounding` with some fields populated, others None, with drift_db available. | Prepopulated fields must take priority; missing fields must fall back to drift.db queries | Bug #6 fix: `collect_evidence()` uses HashSet of covered EvidenceTypes; pre-populated wins |
| T4-04 | **No Evidence Context = No Fallback** — Provide drift_db but no `evidence_context`. | Must return `InsufficientData`, not attempt DB queries | `enterprise_final_gaps_test.rs` — `no_evidence_context_means_no_fallback` |
| T4-05 | **Atomic Link Removal Race** — Concurrently call `remove_*_link` from 10 threads on the same link. | Must not crash or double-delete; SQL DELETE is idempotent | `link_ops.rs` — 4 atomic `remove_*_link` functions (P2-11/E-04 fix) |
| T4-06 | **Bridge Schema Triple-Duplication** — Verify `schema.rs`, `migrations.rs`, and `tables.rs` produce identical DDL. | Column names, types, and constraints must match across all 3 locations | Known tech debt: schema DDL is triple-duplicated |

---

## Category 5: Analysis Pipeline Integrity

The 4-phase analysis pipeline (AST → String → Regex → Resolution) has critical ordering and data flow dependencies.

| ID | Test | Parameter | Source Verification |
|----|------|-----------|---------------------|
| T5-01 | **Phase Ordering Invariant** — Run `analyze_file()` and verify phase_times_us[0..3] are all populated. | All 4 phases must execute in order; each must record non-zero timing | `pipeline.rs:58-86` — phases 1-4 with `Instant::now()` timing |
| T5-02 | **Resolution Index Accumulation** — Analyze 100 files via `analyze_files()`. Verify `ResolutionIndex` accumulates entries from ALL files, not just the last. | `resolution_entries` count must grow monotonically across files | `pipeline.rs:96-106` — single `resolution_index` shared across all files |
| T5-03 | **ParseResult Completeness Cascade** — Analyze a file where `ParseResult.functions` is empty. | Analysis must still complete (patterns, strings, regex all work); only resolution is degraded | `pipeline.rs:59` — `DetectionContext::from_parse_result()` should handle empty functions |
| T5-04 | **Incremental Skip Correctness** — Scan a repo, modify 1 file, re-scan. | `IncrementalAnalyzer.files_to_analyze()` must return only the 1 modified file + 0 added; unchanged files skipped | `engine/incremental.rs:33-43` — returns `added + modified` only |
| T5-05 | **Content Hash L2 Skip** — Touch file mtime without changing content. | mtime changes → triggers L2 content hash check → same hash → classified as `Unchanged` | `scanner/incremental.rs:46-84` — Level 1 fails, Level 2 compares content_hash |
| T5-06 | **File Removal Detection** — Delete a file between scans. | Must appear in `ScanDiff.removed`; `IncrementalAnalyzer.remove_files()` must clean up tracked hashes | `scanner/incremental.rs:112-116` — cache keys not in seen_paths → removed |
| T5-07 | **Deterministic Scan Output** — Scan the same directory twice. | `ScanDiff.added`, `.modified`, `.removed`, `.unchanged` must be sorted identically both times | `scanner/incremental.rs:118-122` — explicit `.sort()` on all 4 lists |
| T5-08 | **Language Detection Coverage** — Include files with all 18+ supported extensions. | Each must be classified with correct `Language` enum variant, not `None` | `language_detect.rs` — `Language::from_extension()` |

---

## Category 6: Enforcement Gate Orchestration

6 gates with DAG-based topological sort, 30s timeout, and dependency cascading.

| ID | Test | Parameter | Source Verification |
|----|------|-----------|---------------------|
| T6-01 | **Circular Dependency Detection** — Register gates with A→B→C→A cycle. | `topological_sort()` must return `"Circular dependency detected"` error | `orchestrator.rs:198-199` — `sorted.len() != self.gates.len()` check |
| T6-02 | **Dependency Cascade Skip** — Fail PatternCompliance gate. Verify dependent gates are skipped (not failed). | Skipped gates get `GateStatus::Skipped` with `passed=true` and message listing failed deps | `orchestrator.rs:85-97` — `deps_met` check; `GateResult::skipped()` |
| T6-03 | **Timeout Enforcement** — Create a gate that sleeps for 35s. | Orchestrator must mark it `GateStatus::Errored` with timeout message (30s default) | `orchestrator.rs:107-117` — checks `elapsed > self.gate_timeout` AFTER execution |
| T6-04 | **Empty GateInput — PatternCompliance** — Call orchestrator with default (empty) `GateInput`. | PatternCompliance must PASS (not skip); this is the only gate that passes on empty input | DD08-E1: PatternCompliance is unique — passes on empty; others skip |
| T6-05 | **Empty GateInput — Other 5 Gates** — Call each of SecurityBoundaries, TestCoverage, ErrorHandling, ConstraintVerification, Regression with empty input. | All 5 must return `Skipped` status (not silently pass) | Verified in enforcement hardening Phase A |
| T6-06 | **Progressive Enforcement** — Enable progressive config. Submit violations from both old and new files. | New-file violations must have severity downgraded; old-file violations unchanged | `orchestrator.rs:120-133` — checks `new_files` set; applies `progressive.effective_severity()` |
| T6-07 | **Baseline is_new Detection** — Provide `baseline_violations` set. Submit violations matching and not matching the baseline. | Matching violations: `is_new=false`; new violations: `is_new=true`; key format: `"file:line:rule_id"` | `orchestrator.rs:136-144` — checks `input.baseline_violations.contains(&key)` |
| T6-08 | **Gate Execution Timing** — Run all 6 gates. | Every `GateResult.execution_time_ms` must be >0 and reflect actual wall time | `orchestrator.rs:104` — `result.execution_time_ms = elapsed.as_millis() as u64` |
| T6-09 | **Custom Gate Registration** — Use `GateOrchestrator::with_gates()` to register a custom gate. | Custom gate must execute in topo-sorted order alongside built-in gates | `orchestrator.rs:42-48` — `with_gates()` accepts arbitrary `Vec<Box<dyn QualityGate>>` |
| T6-10 | **Suppression Format Coverage (4 formats)** — Create violations on lines with `// drift-ignore`, `# noqa`, `// eslint-disable-next-line`, and `@SuppressWarnings("rule")`. | All 4 formats must suppress their respective violations. Must work on BOTH current line (inline) and line above (next-line directive). | `suppression.rs` — `SuppressionChecker` checks 4 formats bidirectionally |
| T6-11 | **Suppression Rule-Specific Filtering** — Add `// drift-ignore rule_a` on a line with `rule_a` and `rule_b` violations. | Only `rule_a` suppressed; `rule_b` still reported. Bare `// drift-ignore` (no rule list) suppresses ALL rules on that line. | `suppression.rs` — parses optional comma-separated rule list after directive |
| T6-12 | **Quick-Fix Language Awareness** — Generate quick fixes for `WrapInTryCatch` in Python, Rust, Go, Java, Ruby, C#, and JS. | Each language must get its own template (try/except for Python, match/? for Rust, if err for Go, etc.) — NOT JS try/catch for all. | `quick_fixes.rs` — 7 language-specific templates per strategy |
| T6-13 | **Policy Engine — All 4 Aggregation Modes** — Evaluate the same gate results under AllMustPass, AnyMustPass, Weighted, and Threshold modes. | AllMustPass: 1 fail → overall fail. AnyMustPass: 1 pass → overall pass. Weighted: use PC:0.25/CV:0.20/SB:0.25/TC:0.15/EH:0.10/R:0.05 weights. Threshold: pass if score ≥ threshold. | `policy/engine.rs` — 4 `AggregationMode` variants; `policy/types.rs` — 3 presets (Strict/Standard/Lenient) |
| T6-14 | **FP Rate Auto-Disable** — Set FP rate to 25% for a pattern sustained over 30+ days (>10 findings). | `FeedbackTracker.is_detector_disabled()` must return true. `RulesEvaluator` must downgrade severity one level (Error→Warning). | `tracker.rs` — alert at 10% FP, auto-disable at 20% sustained 30d; `evaluator.rs` — FP downgrade |
| T6-15 | **Feedback Abuse Detection** — Record 50 dismiss actions from the same author within 1 hour. | Must flag the author as suspicious via abuse detection threshold. | `tracker.rs` — per-author dismiss timestamps, threshold window |
| T6-16 | **Progressive Enforcement 4-Phase Ramp** — Set `ramp_up_days=100`. Test at day 10 (10%), 30 (30%), 60 (60%), 100 (100%). | Day 10: all→Info. Day 30: Error→Warning, Warning→Info. Day 60: Error stays, Warning→Warning. Day 100: full enforcement. New files always get full enforcement. | `progressive.rs` — 4-phase ramp: <25%, <50%, <75%, ≥100% |

---

## Category 7: BatchCommand Coverage & WriteStats Accuracy

33 data-carrying + 2 control = 35 total BatchCommand variants. Each must round-trip through the writer.

| ID | Test | Parameter | Source Verification |
|----|------|-----------|---------------------|
| T7-01 | **All 33 Data Commands Round-Trip** — Send one of each data-carrying BatchCommand variant through BatchWriter. Verify WriteStats counters. | Every `WriteStats` field must be >0 for its corresponding command type | `writer.rs:30-65` — 33 counter fields in WriteStats |
| T7-02 | **Flush + Shutdown Control Commands** — Send Flush followed by Shutdown. | `flushes` counter must increment on Flush; Shutdown must drain buffer and join thread | `writer.rs:132-138` — Flush calls `flush_buffer`; `writer.rs:104-113` — Shutdown joins handle |
| T7-03 | **Mixed Batch Transaction** — Send 500 diverse commands (mix of UpsertFileMetadata, InsertFunctions, InsertDetections). | All must be committed in a single transaction (one `tx.commit()` call); WriteStats must sum correctly | `writer.rs:141-142` — triggers flush at `buffer.len() >= BATCH_SIZE` |
| T7-04 | **Drop Without Shutdown** — Drop BatchWriter without calling `shutdown()`. | `Drop` impl must send Shutdown signal; thread must not leak | `writer.rs:116-121` — `Drop` sends `BatchCommand::Shutdown` |
| T7-05 | **13 Unwired Tables** — Verify that constraints, constraint_verifications, test_coverage, audit_snapshots, health_trends, feedback, policy_results, simulations, decisions, context_cache, migration_projects, migration_modules, migration_corrections can be written directly (not via BatchWriter). | Direct SQL INSERT via `with_writer()` must succeed for all 13 tables | DD-15 finding: 13 tables have no BatchCommand variant |

---

## Category 8: Migration & Schema Evolution

7 migration files (v001–v007), v006 has PART2 split.

| ID | Test | Parameter | Source Verification |
|----|------|-----------|---------------------|
| T8-01 | **Fresh DB — All 45 Tables Created** — Open a fresh database. | All 45 tables must exist with correct column counts matching DD-15 audit (398 total columns) | `migrations/mod.rs` — runs v001 through v007 in order |
| T8-02 | **Idempotent Re-Open** — Open, close, re-open the same database. | No "table already exists" errors; migration system must detect already-applied migrations | `migrations/mod.rs` — `CREATE TABLE IF NOT EXISTS` or version tracking |
| T8-03 | **v006 PART2 Execution** — Verify both `MIGRATION_SQL` and `MIGRATION_SQL_PART2` from v006 run. | Tables from Part 1 (violations, gate_results) AND Part 2 (audit_snapshots through degradation_alerts) must all exist | `migrations/mod.rs` — explicitly executes `v006_enforcement::MIGRATION_SQL_PART2` |
| T8-04 | **Foreign Key Integrity** — Insert into `constraint_verifications` with invalid `constraint_id`. | Must fail (FK constraint violation) if foreign keys are enabled | v005: `constraint_verifications.constraint_id` → `constraints(id)` |
| T8-05 | **FK Cascade — migration_modules** — Delete a `migration_projects` row. | `migration_modules` rows referencing it must be handled (CASCADE or error depending on DDL) | v007: `migration_modules.project_id` → `migration_projects(id)` |
| T8-06 | **WAL Mode Verification** — After fresh `DatabaseManager::open()`. | `PRAGMA journal_mode` must return `wal` | `pragmas.rs` — applies WAL mode pragma |

---

## Category 9: Incremental Scan Precision

Two-level detection (mtime → content hash) determines what gets re-analyzed.

| ID | Test | Parameter | Source Verification |
|----|------|-----------|---------------------|
| T9-01 | **mtime Fast Path Hit Rate** — Scan a 1,000-file repo, no changes, re-scan. | `cache_hit_rate` must be ~1.0; `hashing_ms` should be near zero (no content reads) | `scanner.rs:136-144` — computes cache_hit_rate from Unchanged count |
| T9-02 | **mtime Change + Same Content** — Touch a file's mtime without modifying content. | L1 (mtime) fails → L2 (content hash) kicks in → classified as `Unchanged` (not Modified) | `incremental.rs:46-84` — Level 2 compares xxh3 hash |
| T9-03 | **force_full_scan Bypass** — Set `force_full_scan=true`. Scan unchanged repo. | ALL files must be classified as Added or Modified (mtime check bypassed); `cache_hit_rate` ~0.0 | `incremental.rs:46` — `if !force_full` check |
| T9-04 | **Large File Skip** — Set `max_file_size` to 100 bytes. Include a 1MB file. | Large file must be excluded by walker (line 59: `max_filesize` override) | `walker.rs:59` — `builder.max_filesize(Some(max_file_size))` |
| T9-05 | **Symlink Following** — Create symlinks in scan directory with `follow_symlinks=true`. | Walker must follow symlinks and discover target files | `walker.rs:50` — `builder.follow_links(follow_links)` |
| T9-06 | **.driftignore Respect** — Create `.driftignore` with patterns. | Walker must skip matching files (line 58: custom ignore filename) | `walker.rs:58` — `.add_custom_ignore_filename(".driftignore")` |
| T9-07 | **18 Default Ignore Patterns** — Include directories matching all 18 `DEFAULT_IGNORES`. | All 18 must be skipped (node_modules, .git, dist, build, target, .next, etc.) | `walker.rs:16-35` — `DEFAULT_IGNORES` constant with 18 entries |
| T9-08 | **Cancellation Mid-Walk** — Cancel during Phase 1 (file discovery). | Must return `partial_diff` with empty entries but preserve `discovery_ms` | `scanner.rs:74-76` — returns `partial_diff` on cancellation after discovery |
| T9-09 | **Cancellation Mid-Hash** — Cancel during Phase 2 (par_iter hashing). | `par_iter` filter_map returns `None` on cancellation (line 94-96); partial results collected | `scanner.rs:94-96` — `if self.cancellation.is_cancelled() { return None; }` |
| T9-10 | **Event Emission Sequence** — Verify DriftEventHandler receives events in order. | `on_scan_started` → `on_scan_progress(0, total)` → `on_scan_progress(N, total)` → `on_scan_complete` | `scanner.rs:52-55, 79-82, 99-103, 164-170` — event emission points |

---

## Category 10: Reporter Format Correctness

8 report formats, each with format-specific correctness requirements.

| ID | Test | Parameter | Source Verification |
|----|------|-----------|---------------------|
| T10-01 | **SARIF Taxonomy Placement** — Generate SARIF report with CWE and OWASP violations. | Taxonomies must be in `runs[0].taxonomies` and relationships in `rules[0].relationships` — NOT in `results[0].taxa` | Bug fix: `critical_sarif_both_cwe_and_owasp` corrected the path |
| T10-02 | **JUnit Error/Failure Semantics** — Generate JUnit report with both errors and failures. | Errors = infrastructure problems; Failures = assertion violations. These must NOT be swapped. | Bug fix in Phase C: JUnit errors/failures semantics were swapped |
| T10-03 | **SonarQube Rules Array** — Generate SonarQube report. | Must include `rules` array (required since SonarQube 10.3), not just issues | Known gap: SonarQube reporter was missing rules array |
| T10-04 | **Console Report Readability** — Generate console report for 50+ violations. | Must include severity counts, file grouping, and quick-fix suggestions | Reporter trait interface verified |
| T10-05 | **JSON Report Schema Stability** — Generate JSON report across two versions. | Output structure must be stable; field names must not change between runs | Regression guard for CI consumers |
| T10-06 | **GitHub Annotations Format** — Generate GitHub report with Error, Warning, Info, and Hint violations. | Error→`failure`, Warning→`warning`, Info/Hint→`notice`. `raw_details` must contain CWE+OWASP. | `github.rs` — Code Quality annotation format |
| T10-07 | **GitLab Code Quality Fingerprints** — Generate GitLab report with 2 violations on the same file:line but different rule_ids. | Fingerprints must differ (hash includes rule_id + file + line). Categories must be inferred from rule_id prefix. | `gitlab.rs` — fingerprint = hash(rule_id + file + line) for dedup |
| T10-08 | **HTML Report Generation** — Generate HTML report with mixed severity violations. | Must produce valid HTML with embedded CSS styling. Must be viewable in a browser. | `html.rs` — full HTML report with styling |
| T10-09 | **All 8 Formats via driftReport()** — Call `driftReport(format)` for each of: sarif, json, console, html, junit, sonarqube, github, gitlab. | Each must return non-empty string and not error. Reporter name must match format string. | `enforcement.rs` — `drift_report()` dispatches to `Reporter` trait implementations |
| T10-10 | **SARIF isNew Property** — Generate SARIF with both new and baseline violations. | `properties.isNew` must be `true` for new violations, `false` for baseline matches. Quick fixes must appear as `fixes[0].description`. | `sarif.rs` — properties include isNew; quick fixes as SARIF fix objects |

---

## Category 11: Contract Extraction Precision

14 endpoint extractors, 5/19 breaking change types, field extraction currently empty.

| ID | Test | Parameter | Source Verification |
|----|------|-----------|---------------------|
| T11-01 | **Next.js Backend Classification** — Extract contracts from Next.js API routes (`pages/api/` or `app/api/`). | Must classify as backend (`paradigm: "rest"`), not frontend. Next.js is in `backend_frameworks` array. | Bug #1 fix: added "nextjs" to `backend_frameworks` in `analysis.rs` and `structural.rs` |
| T11-02 | **Paradigm Classification** — Extract from Express, tRPC, and frontend files. | Express → `"express"`, tRPC → `"rpc"`, Frontend → `"frontend"` (NOT all `"rest"`) | Bug #2 fix: paradigm derived from framework name, not hardcoded |
| T11-03 | **Confidence from Field Quality** — Extract contracts with and without request/response fields. | Fields extracted → confidence 0.9; No fields → confidence 0.6 (NOT hardcoded 0.8) | Bug #3 fix: confidence varies based on field extraction quality |
| T11-04 | **Contract Upsert Idempotency** — Insert same contract ID twice. | `INSERT OR REPLACE` semantics → 1 row in `contracts` table | CT-ADV-13: Contract upsert produces 1 row |
| T11-05 | **Mismatch Accumulation** — Insert same mismatch twice. | `INSERT` (not upsert) semantics → 2 rows in `contract_mismatches` table | CT-ADV-14: Mismatches accumulate |
| T11-06 | **Empty Batch Commands** — Send empty Vec to `InsertContracts` and `InsertContractMismatches`. | Must not crash; WriteStats counters remain 0 | CT-ADV-15: Empty batch safety |
| T11-07 | **Disjoint BE/FE Paths** — Backend endpoints at `/api/users`, frontend calls to `/api/orders`. | Matching must produce 0 mismatches (no false positives from partial path overlap) | CT-ADV-09: Disjoint paths = 0 matches |
| T11-08 | **Type Mismatch Detection** — Backend field `age: number`, frontend field `age: string`. | Must detect and report `TypeMismatch` in `contract_mismatches` table | CT-ADV-04: Type mismatch detection |

---

## Category 12: Event System & DriftEventHandler

24 event methods on the `DriftEventHandler` trait; `EventDispatcher` fans out to multiple handlers.

| ID | Test | Parameter | Source Verification |
|----|------|-----------|---------------------|
| T12-01 | **Full Event Sequence** — Run a complete scan→analyze→check pipeline. Record all events. | Must observe the complete event sequence without gaps or duplicates | `DriftEventHandler` trait — 24 event methods (DD01-O5) |
| T12-02 | **EventDispatcher Fan-Out** — Register 3 handlers. Emit one event. | All 3 handlers must receive the event; order must be registration order | `EventDispatcher::new()` in `runtime.rs:120` |
| T12-03 | **Progress Event Frequency** — Scan 10,000 files. Count `on_scan_progress` calls. | Must fire every 100 files (scanner.rs:99 — `if count % 100 == 0`) | `scanner.rs:99` — modulo 100 progress emission |
| T12-04 | **Error Event on Walker Failure** — Point scanner at nonexistent directory. | `on_scan_error` must fire with descriptive message before returning Err | `scanner.rs:66-69` — emits `ScanErrorEvent` then returns Err |

---

## Category 13: Retention & Data Lifecycle

4-tier retention system (Current/orphan, Short 30d, Medium 90d, Long 365d).

| ID | Test | Parameter | Source Verification |
|----|------|-----------|---------------------|
| T13-01 | **constraint_verifications Column Name** — Run retention cleanup on `constraint_verifications` table. | Must use `verified_at` column (NOT `created_at`) for age calculation | Bug found and fixed: `retention.rs` line 128 was using wrong column |
| T13-02 | **Orphan Cleanup Atomicity** — Delete 1000 orphaned entries. Crash mid-delete. | Transaction must roll back cleanly; no partial cleanup | Retention operates within transactions |
| T13-03 | **Self-Bounding Tables** — Insert into `reachability_cache` (composite PK: source_node + direction). | `INSERT OR REPLACE` semantics must prevent unbounded growth | Self-bounding via PK uniqueness constraints |
| T13-04 | **Tier Assignment Coverage** — Verify every one of the 45 tables is assigned to exactly one retention tier. | No table orphaned from retention policy | DD09-O2: Full tier mapping documented |

---

## Category 14: Configuration & Initialization

`DriftConfig` loading, `ScanConfig` defaults, TOML parsing.

| ID | Test | Parameter | Source Verification |
|----|------|-----------|---------------------|
| T14-01 | **Default ScanConfig Values** — Create `ScanConfig::default()`. | `max_file_size` = 1MB (1_048_576), `threads` = 0 (auto), `incremental` = true | `scan_config.rs:36-48` — verified defaults |
| T14-02 | **Config TOML Round-Trip** — Serialize and deserialize `DriftConfig`. | All fields must survive round-trip without data loss | `DriftConfig::from_toml()` + `serde` |
| T14-03 | **Project Root Fallback** — Initialize runtime with no explicit config. | Must load from `project_root` if available, then fall back to `DriftConfig::default()` | `runtime.rs:56-61` — `DriftConfig::load(root, None).unwrap_or_default()` |
| T14-04 | **extra_ignore Patterns** — Set `extra_ignore = ["*.generated.ts"]`. | Walker must skip matching files in addition to DEFAULT_IGNORES and .driftignore | `walker.rs:73-76` — iterates `config.extra_ignore` |

---

## Summary Matrix

| # | Category | Tests | Priority | Existing Coverage | Gap |
|---|----------|-------|----------|-------------------|-----|
| 1 | NAPI Threading | 11 | P0 | Minimal (1 napi_test.rs) | **+5: AsyncTask cancel, ThreadsafeFunction, error codes, camelCase fidelity, stub fallback** |
| 2 | SQLite/WAL Concurrency | 13 | P0 | Partial (connection_test.rs, batch_test.rs) | **+3: Pragma verification, reader isolation, in-memory mode behavioral diff** |
| 3 | Intelligence Precision | 11 | P1 | Moderate (beta.rs unit tests, pipeline.rs) | Feedback saturation, temporal decay, tier boundaries |
| 4 | Bridge Grounding | 6 | P1 | Good (13 bridge test files) | Schema duplication verification |
| 5 | Analysis Pipeline | 8 | P1 | Moderate (e2e_full_pipeline_test.rs) | Phase ordering, incremental skip, L2 hash |
| 6 | Enforcement Gates | 16 | P0 | Good (enforcement hardening tests) | **+7: Suppression formats, quick-fix language, policy modes, FP auto-disable, feedback abuse, progressive ramp** |
| 7 | BatchCommand Coverage | 5 | P1 | Partial (batch_writer_completeness_test.rs) | 13 unwired tables, Drop behavior |
| 8 | Migration/Schema | 6 | P2 | Basic (migration_test.rs) | FK integrity, PART2, idempotent re-open |
| 9 | Incremental Scan | 10 | P1 | Basic (p0_stress_test.rs) | L2 skip, cancellation timing, event sequence |
| 10 | Reporter Formats | 10 | P1 | Partial (enforcement SARIF/JUnit fixes) | **+5: GitHub annotations, GitLab fingerprints, HTML, all 8 formats via driftReport(), SARIF isNew** |
| 11 | Contract Extraction | 8 | P1 | Good (132 e2e + 15 adversarial) | Next.js, paradigm, field quality |
| 12 | Event System | 4 | P2 | None | No event sequence tests exist |
| 13 | Retention | 4 | P2 | Partial (retention_integration_test.rs) | Column name, tier assignment coverage |
| 14 | Configuration | 4 | P2 | Basic (config_test.rs) | extra_ignore, TOML round-trip |
| **15** | **Parser Correctness** | **10** | **P0** | **None** | **ENTIRELY MISSING — 10 language parsers, ParseResult, cache, error recovery** |
| **16** | **Detection Engine** | **7** | **P0** | **None** | **ENTIRELY MISSING — 16 categories, panic safety, learning 2-pass, CWE mapping** |
| **17** | **Structural Analysis** | **10** | **P1** | **None (except contracts)** | **ENTIRELY MISSING — coupling, wrappers, crypto, DNA, secrets, magic numbers, env vars, decomposition** |
| **18** | **Graph Intelligence** | **11** | **P1** | **None** | **ENTIRELY MISSING — call graph 6 strategies, taint, error handling, impact, test topology** |
| **19** | **Cortex Memory System** | **12** | **P1** | **None** | **ENTIRELY MISSING — CRUD, embeddings, privacy, causal, decay, multi-agent, sessions, validation** |
| **20** | **Presentation Layer** | **12** | **P0** | **None** | **ENTIRELY MISSING — MCP 6 entry points, CLI 27 commands, CI 10 passes, cortex subcommands** |
| **21** | **Advanced Systems** | **6** | **P2** | **None** | **ENTIRELY MISSING — simulation, decision mining, context generation, spec gen** |
| **22** | **Production Hardening** | **9** | **P0** | **None** | **ENTIRELY MISSING — Appendix A gaps: double-build, re-read, timeout, memory, errors, delta alerts** |
| **23** | **E2E Smoke Tests** | **6** | **P0** | **None** | **ENTIRELY MISSING — golden path, incremental, deletion, empty repo, multi-lang, bridge E2E** |
| **24** | **Graceful Degradation** | **7** | **P0** | **None** | **ENTIRELY MISSING — no DB, corrupt DB, missing binary, channel full, concurrent shutdown** |
| **25** | **Performance Budgets** | **6** | **P1** | **None** | **ENTIRELY MISSING — timing gates for scan, analysis, parse, batch write, vector search, CI** |
| **26** | **Idempotency & Determinism** | **5** | **P1** | **None** | **ENTIRELY MISSING — analysis, scanner sort, convention, enforcement, report stability** |
| **27** | **Bridge Expanded** | **8** | **P1** | **Partial (Cat 4)** | **ENTIRELY MISSING — all 10 evidence types, causal narrative, link translation, batch grounding** |

**Total: 225 production tests across 27 categories.**

> **Gap closure: +129 new tests across 13 new categories, +15 tests added to 4 existing categories (was 81 in original Cats 1-14, now 96).** The original suite covered ~40% of the critical flow map (Flows 1, 5, 8-10 partially). The expanded 225 tests now cover all 14 flows, the presentation layer, the Cortex memory system, advanced systems, and cross-cutting concerns.

**Recommended implementation order:**

**Phase 1 — P0 Foundation (7 categories, 91 tests)**
1. **Cat 23: E2E Smoke** (6 tests) — Proves the golden path works end-to-end; baseline for everything else
2. **Cat 15 + 16: Parser + Detection** (17 tests) — These are upstream of EVERYTHING; if parse/detect is wrong, nothing downstream can be right
3. **Cat 1 + 2: NAPI Threading + SQLite** (24 tests) — Concurrency and storage are production-critical
4. **Cat 20: Presentation Layer** (12 tests) — Users/agents interact through MCP/CLI/CI; must work
5. **Cat 22 + 24: Production Hardening + Graceful Degradation** (16 tests) — Beta users WILL hit edge cases
6. **Cat 6: Enforcement Gates** (16 tests, expanded) — Quality gates are the primary output users see

**Phase 2 — P1 Depth (10 categories, 110 tests)**
7. **Cat 5 + 9: Pipeline + Incremental Scan** (18 tests) — Pipeline correctness and incremental precision
8. **Cat 17 + 18: Structural + Graph Intelligence** (21 tests) — 15 subsystems that feed enforcement
9. **Cat 3 + 10: Intelligence + Reporters** (21 tests) — Bayesian scoring and output format correctness
10. **Cat 19: Cortex Memory** (12 tests) — Full memory lifecycle
11. **Cat 7 + 11 + 4 + 27: BatchCommand + Contracts + Bridge** (27 tests) — Storage pipeline and cross-system
12. **Cat 25 + 26: Performance + Idempotency** (11 tests) — Regression gates and CI reproducibility

**Phase 3 — P2 Polish (5 categories, 24 tests)**
13. **Cat 8 + 12 + 13 + 14: Migration + Events + Retention + Config** (18 tests)
14. **Cat 21: Advanced Systems** (6 tests) — Simulation, decisions, context, spec gen

---

# GAP CLOSURE — Categories 15–27

> **Added by senior review.** The original 14 categories covered ~40% of the critical flow map. The following 13 categories close the remaining gaps: Parser, Detection Engine, Structural Analysis, Graph Intelligence, Cortex Memory, Presentation Layer, Advanced Systems, Production Hardening Gaps, E2E Smoke Tests, Graceful Degradation, Performance Budgets, Idempotency & Determinism, and Cortex-Drift Bridge (expanded).

---

## Category 15: Parser Correctness (Flow 2)

10 language-specific tree-sitter parsers producing the canonical `ParseResult` (18 fields). Parser errors cascade to every downstream system.

| ID | Test | Parameter | Source Verification |
|----|------|-----------|---------------------|
| T15-01 | **ParseResult Field Completeness — TypeScript** — Parse a TS file with functions, classes, imports, exports, decorators, call sites, string literals, error handling. | All 18 `ParseResult` fields must be populated (non-empty where applicable). `FunctionInfo` must have all 18 fields including `qualified_name`, `is_exported`, `is_async`, `body_hash`, `signature_hash`. | `parsers/types.rs` — ParseResult 18 fields; FunctionInfo 18 fields (DD02-E1) |
| T15-02 | **All 10 Language Parsers Return Valid Output** — Parse one representative file per language (TS, JS, Python, Java, C#, Go, Rust, Ruby, PHP, Kotlin). | Each must return `ParseResult` with `language` set correctly, `has_errors=false`, and `functions.len() > 0`. | `parsers/languages/` — 10 parser files, each implements `LanguageParser` trait |
| T15-03 | **Fallback Grammar Coverage** — Parse a C file, a C++ file, a Swift file, and a Scala file. | C/C++ must use C# grammar fallback. Swift/Scala must use Java grammar fallback. Must not panic; `has_errors` may be true but `ParseResult` must still be returned. | `manager.rs` — fallback grammars: C/C++→C#, Swift/Scala→Java |
| T15-04 | **Parse Cache Hit** — Parse the same file content twice via `ParserManager`. | Second call must return cached result (moka cache keyed by `content_hash`). `parse_time_us` on cache hit should be ~0. | `cache.rs` — moka-based parse cache keyed by content_hash |
| T15-05 | **Parse Cache Invalidation** — Parse file, modify content (different hash), re-parse. | Must return fresh `ParseResult` with new `content_hash`. Old cache entry must not be returned. | `cache.rs` — content_hash mismatch = cache miss |
| T15-06 | **Error Recovery** — Parse a file with syntax errors (missing closing brace). | `has_errors` must be `true`. `error_count > 0`. `error_ranges` must be non-empty. But `functions` and other fields must still be populated for the valid portions of the file. | tree-sitter error recovery — parser continues past errors |
| T15-07 | **Empty File** — Parse a 0-byte file. | Must return `ParseResult` with all Vec fields empty, `has_errors=false`, `content_hash` of empty string. Must not panic. | Edge case: empty source string |
| T15-08 | **Large File Performance** — Parse a 50,000-line TypeScript file. | Must complete in <5s. `parse_time_us` must be recorded. No OOM. | Performance regression gate |
| T15-09 | **ParseResult Round-Trip Through NAPI** — Parse a file in Rust, send `JsAnalysisResult` through NAPI to TS. | `matches` count, `file`, `language`, `analysis_time_us` must all survive the Rust→TS boundary without truncation. | `analysis.rs` — `JsAnalysisResult { file, language, matches, analysis_time_us }` |
| T15-10 | **Decorator Extraction** — Parse a NestJS file with `@Controller`, `@Get`, `@Post` decorators. | `decorators` Vec must contain entries with correct `name`, `arguments` (key/value pairs), and `raw_text`. | `types.rs:118-130` — `DecoratorInfo` with 4 fields |

---

## Category 16: Detection Engine (Flow 3)

16 detector categories, 3 detector variants, panic-safe execution via `catch_unwind`.

| ID | Test | Parameter | Source Verification |
|----|------|-----------|---------------------|
| T16-01 | **All 16 Detectors Fire** — Run `DetectorRegistry.run_all()` on a file containing patterns from every category (security eval, data access ORM, empty catch, test mock, naming convention, REST endpoint, auth JWT, component, config, contract, doc, logging, performance, styling, types, accessibility). | Must return ≥16 `PatternMatch` results, one per category. `detection_method` must be set. | `registry.rs` — `create_default_registry()` registers all 16 |
| T16-02 | **Detector Panic Safety** — Register a custom detector that panics inside `detect()`. | `catch_unwind()` must prevent crash. Other detectors must still run. Error must be logged. | `registry.rs` — wraps each `detector.detect(ctx)` in `catch_unwind()` |
| T16-03 | **Learning Detector 2-Pass** — Run a `LearningDetectorHandler` on 100 files. | Pass 1 (learn): accumulates patterns. Pass 2 (detect): uses learned patterns to detect deviations. Must produce different results than a single-pass Base detector. | `visitor.rs` — `LearningDetectorHandler` has `learn()` + `detect()` methods |
| T16-04 | **DetectionContext Construction** — Build `DetectionContext::from_parse_result()` with empty `ParseResult.functions`. | Must not panic. All borrowed slices must be valid (empty but not null). Downstream detectors accessing `ctx.functions` get empty slice. | `visitor.rs:20-30` — DetectionContext borrows from ParseResult |
| T16-05 | **PatternMatch Output Completeness** — Run security detector on a file with `eval()`. | `PatternMatch` must have all 10 fields: `file`, `line`, `column`, `pattern_id`, `confidence`, `category`, `detection_method`, `matched_text`, `cwe_ids`, `owasp`. | `engine/types.rs` — PatternMatch 10 fields |
| T16-06 | **Category Filtering** — Register all detectors, then filter to `critical_only=true`. | Only detectors where `is_critical()` returns true should run. Others must be skipped entirely. | `traits.rs` — `is_critical()` default false |
| T16-07 | **Security Detector CWE Mapping** — Run security detector on `eval(userInput)`. | `cwe_ids` must contain CWE-95 (eval injection). `owasp` must be non-empty. | `detectors/security/` — maps findings to CWE/OWASP |

---

## Category 17: Structural Analysis (Flow 6 — 9 untested subsystems)

10 structural subsystems; only contracts (Cat 11) was covered. These 9 remain.

| ID | Test | Parameter | Source Verification |
|----|------|-----------|---------------------|
| T17-01 | **Coupling — Martin Metrics** — Analyze a module with 5 imports (Ce=5) and 3 importers (Ca=3). | `instability = Ce/(Ce+Ca) = 0.625`. `distance = |abstractness + instability - 1|`. Must match Martin's formula. | `structural/coupling/` — `compute_martin_metrics()` |
| T17-02 | **Coupling — Cycle Detection** — Create imports A→B→C→A. | `detect_cycles()` must find the SCC {A,B,C}. `break_suggestions` must be non-empty. | `structural/coupling/` — strongly connected components |
| T17-03 | **Wrapper Detection Confidence** — Analyze a file wrapping `fetch()` in a custom `apiClient()`. | `WrapperDetector` must detect it with `confidence > 0.5`. Multi-primitive composite analysis must work when wrapping multiple primitives. | `structural/wrappers/` — `compute_confidence()` |
| T17-04 | **Crypto — Weak Algorithm Detection** — File using `MD5`, `SHA1`, `DES`. | Must detect all 3 as weak. Each must have `cwe_id` and `owasp` mappings. `confidence` must vary by severity. | `structural/crypto/` — `CryptoDetector::detect()` |
| T17-05 | **DNA — Naming Gene Consistency** — Repo with 50% camelCase, 50% snake_case files. | Gene must have 2 alleles. `consistency` = `freq[0] - freq[1]` ≈ 0. Dominant allele `frequency ≥ 0.30`. Mutations flagged for minority style. | `structural/dna/` — `GeneExtractorRegistry::with_all_extractors()` (11 extractors) |
| T17-06 | **Secrets — Entropy Filtering** — File with `AWS_KEY=AKIAIOSFODNN7EXAMPLE` and `name="hello"`. | AWS key detected (high entropy + known pattern). `"hello"` not flagged (low entropy). `redacted_value` must not contain full secret. | `structural/constants/secrets.rs` — Shannon entropy filter |
| T17-07 | **Magic Numbers** — File with `if (retries > 3)` and `const MAX_RETRIES = 3`. | `3` in the `if` flagged as magic number. `MAX_RETRIES = 3` NOT flagged (named constant). `suggested_name` populated. | `structural/constants/magic_numbers.rs` |
| T17-08 | **Constraint Verification** — Define `MustExist` constraint for `AuthMiddleware`. Analyze repo without it. | `ConstraintVerifier::verify_all()` must return `passed=false` with violation details. | `structural/constraints/` — 5 invariant types |
| T17-09 | **Env Variable Extraction — 8 Languages** — Files using `process.env.X` (JS), `os.environ["X"]` (Python), `std::env::var("X")` (Rust), `os.Getenv("X")` (Go), `System.getenv("X")` (Java), `ENV["X"]` (Ruby), `getenv("X")` (PHP), `Environment.GetEnvironmentVariable("X")` (C#). | All 8 must be extracted with correct `access_method` and `has_default` detection. | `structural/constants/env_extraction.rs` — 8 languages |
| T17-10 | **Decomposition Suggestions** — Analyze a monolith with high coupling between 3 modules. | `decompose_with_priors()` must suggest service boundaries. `confidence` must be >0. `narrative` must explain the reasoning. | `structural/decomposition/` — `decompose_with_priors()` |

---

## Category 18: Graph Intelligence (Flow 7 — 5 subsystems)

Call graph, taint analysis, error handling analysis, impact analysis, and test topology. All depend on call graph resolution quality.

| ID | Test | Parameter | Source Verification |
|----|------|-----------|---------------------|
| T18-01 | **Call Graph — All 6 Resolution Strategies** — Build call graph for a repo with same-file calls, imported calls, exported functions, DI-injected services, method calls, and fuzzy name matches. | Must produce edges with correct `ResolutionStrategy` and confidence: SameFile (0.95), Import-based, Export-based, DI, Method, Fuzzy (0.40). | `call_graph/resolution.rs` — 6 strategies; DD04-E1 confirms TWO separate resolution systems |
| T18-02 | **Call Graph — Import-Based Resolution** — File A imports `{foo}` from `./B`. File B exports `foo`. Call `foo()` in A. | Must create edge A→B:foo with Import-based strategy. Currently this is DEAD (specifiers always empty) — test validates the fix. | `call_graph/resolution.rs:81-107` — requires non-empty `ImportInfo.specifiers` |
| T18-03 | **Call Graph — Incremental Rebuild** — Build call graph, modify one file, rebuild. | Must NOT rebuild from scratch. Only edges involving the modified file should be updated. | `call_graph/builder.rs` — currently does full rebuild every time (known gap) |
| T18-04 | **Taint Analysis — Source→Sink Reachability** — Define `req.body` as source, `db.query()` as sink, with 3-hop path through intermediate functions. | Must find the taint flow with `path_length=3`. Must NOT flag sinks that are unreachable from sources. | `graph/taint/` — `TaintAnalyzer::analyze()` |
| T18-05 | **Taint — Over-Approximation Guard** — One function has a tainted var AND an untainted var. Both reach a sink. | Only the tainted var's flow should be reported. The untainted var must NOT appear in taint results. Known bug: ANY tainted var flags ALL sinks. | `graph/taint/` — over-approximation is a known gap |
| T18-06 | **Taint — Registry Pattern Matching** — Register source pattern `"open"`. File has `openDialog()` and `fs.open()`. | Only `fs.open()` should match (exact or method match). `openDialog()` must NOT match (substring false positive). | `graph/taint/registry.rs` — substring matching produces false positives |
| T18-07 | **Error Handling — Gap Detection** — Function with try/catch that catches generic `Exception` (not specific). | Must detect as error handling gap with appropriate severity. `gap_type` must distinguish catch-all vs missing-handler vs swallowed-error. | `graph/errors/` — `ErrorAnalyzer::analyze()` |
| T18-08 | **Impact — Blast Radius Scoring** — Delete a function called by 10 other functions. | `blast_radius` must be >0 and proportional to caller count. `risk_factors` must NOT all be hardcoded to 0.0. | `graph/impact/` — blast radius + risk factor calculation |
| T18-09 | **Impact — Dead Code Detection** — Function with 0 callers and not an entry point. | Must be flagged as dead code. Route handlers (decorated with `@Get`, `@app.route`, etc.) must NOT be flagged even with 0 callers. | `graph/impact/` — entry point detection excludes route handlers |
| T18-10 | **Test Topology — Quality Dimensions** — Analyze a test file with 5 test functions covering 3 source functions. | Must compute all 7 quality dimensions: `assertion_density`, `mock_ratio`, `test_smell_count`, `boundary_coverage`, `error_path_coverage`, `name_quality`, `isolation_score`. | `graph/test_topology/` — 7 quality dimensions |
| T18-11 | **Test Topology — test_smell_count Uses Call Graph** — Test function calls source function via call graph edge. | `count_source_calls` must use the call graph parameter, not ignore it. Test smell count must reflect actual test→source coupling. | Known gap: `count_source_calls` ignores call graph parameter |

---

## Category 19: Cortex Memory System (Flow 12)

21 crates, 68 NAPI bindings, 16 engines in `CortexRuntime`. Zero coverage in original test suite.

| ID | Test | Parameter | Source Verification |
|----|------|-----------|---------------------|
| T19-01 | **Memory CRUD Lifecycle** — Create, read, update, delete a memory via NAPI (`cortexMemoryCreate`, `cortexMemoryGet`, `cortexMemoryUpdate`, `cortexMemoryDelete`). | Each operation must succeed. After delete, get must return null/error. Audit log must have 4 entries. Temporal events emitted for each mutation. | `cortex-napi/src/bindings/memory.rs` — 4 CRUD bindings |
| T19-02 | **Re-Embed on Content Update** — Create memory, update with different content (different `content_hash`). | Must regenerate embedding. New embedding must differ from original. `content_hash` must change. | P2-15/D-03 fix: `cortex_memory_update` detects hash change and re-embeds |
| T19-03 | **Embedding Degradation Chain** — Disable primary embedding provider. | Must fall back through degradation chain (TF-IDF fallback). `embed_readonly()` must work. Embed result must be non-zero-dimension vector. | `cortex-embeddings/src/degradation.rs` — DegradationChain |
| T19-04 | **L2 Cache Persistence** — Create embedding, close runtime, reopen. | L2 SQLite cache must contain the embedding. Promotion to L1 on access must work. | Phase D fix: `L2SqliteCache` with WAL mode persistence |
| T19-05 | **Consolidation Eligibility** — Create Episodic and Procedural memories (eligible) and Semantic memories (not eligible). | Only Episodic + Procedural should appear in consolidation candidate list. | P2-9 fix: `CONSOLIDATION_ELIGIBLE` const = Episodic + Procedural |
| T19-06 | **Vector Search Correctness** — Insert 100 memories with embeddings. Search for nearest to a query vector. | Results must be sorted by cosine similarity descending. Zero-norm vectors must be skipped. Dimension mismatches must be filtered. | D-05/D-06 fix: pre-compute query norm, skip zero-similarity |
| T19-07 | **Privacy Sanitization** — Store memory with `AWS_SECRET_KEY=AKIA...` in content. | `cortexPrivacySanitize` must replace with placeholder. Overlapping matches must be deduped. Replacements must be applied in descending position order (no corruption). | E-06 fix: sort matches descending by start position |
| T19-08 | **Causal Graph Hydration** — Add causal edges A→B→C via `cortexCausalAddEdge`. Restart runtime. | Graph must be reconstructable from storage. Cycle detection must work post-hydration. Orphan nodes must be removable. | Phase C fix: hydrate causal graph from storage on init |
| T19-09 | **Decay Engine Scheduling** — Create memories with varying ages. Run `cortexDecayRun`. | Old memories (beyond retention window) must have confidence decreased. Very old memories must be archived. Active memories must be untouched. | Phase C: scheduled decay wired to engine |
| T19-10 | **Multi-Agent Namespace Isolation** — Agent A creates memory in namespace "team-alpha". Agent B (different namespace) attempts to read it. | Agent B must get permission denied. Agent A must succeed. RBAC: Agent scope = all 4 perms, Team = read+write, Project = read only. | `cortex-multiagent/src/namespace/permissions.rs` — scope-based RBAC |
| T19-11 | **Session Lifecycle** — Start session, record analytics (tokens, latency), end session. | `cortexSessionStart` → `cortexSessionEnd`. Token counts must be queryable. Session duration must be >0. | `cortex-napi/src/bindings/session.rs` |
| T19-12 | **Validation — 4 Dimensions** — Call `cortexValidationRun` on a memory with known issues. | Must return scores for all 4 validation dimensions. Each score must be in [0.0, 1.0]. | P1-12/E-02 fix: real 4-dimension validation in `validation.rs` |

---

## Category 20: Presentation Layer (Flow 11 — MCP, CLI, CI)

6 MCP entry points, 27 CLI commands, 10 CI passes. Zero coverage in original test suite.

| ID | Test | Parameter | Source Verification |
|----|------|-----------|---------------------|
| T20-01 | **MCP Server — All 6 Entry Points** — Call each MCP entry point: `drift_scan`, `drift_analyze`, `drift_check`, `drift_status`, `drift_discover`, `drift_workflow`. | Each must return valid MCP tool response (not throw). `drift_status` must return real counts (not hardcoded zeros). | `packages/drift-mcp/src/tools/index.ts` — 6 entry points registered |
| T20-02 | **MCP — drift_scan Triggers Analysis** — Call `drift_scan` via MCP. | Must call both `driftScan()` AND `driftAnalyze()` NAPI bindings. DB must contain analysis results after call, not just file counts. | Known P0 gap: MCP drift_scan only scans, doesn't analyze |
| T20-03 | **MCP — Cortex Tool Registration** — Start MCP server. List available tools. | Must include Cortex tools (not just Drift tools). Count must match actual registered tools (currently 40 Cortex tools). | `packages/drift-mcp/src/tools/cortex_tools.ts` — tool count comment says 40 |
| T20-04 | **MCP — Infrastructure Modules** — Exercise cache, rate limiter, token estimator, error handler, cursor manager, response builder, tool filter. | Each module must be instantiable and functional. Cache must hit on repeated calls. Rate limiter must reject excessive calls. | `packages/drift-mcp/src/` — 7 infrastructure modules |
| T20-05 | **CLI — All 27 Commands Parse** — Run `drift <command> --help` for each of the 27 commands. | Each must print help text and exit 0 (not crash). Commands: scan, analyze, check, status, audit, export, patterns, violations, explain, simulate, context, report, security, contracts, coupling, dna, impact, taint, test-quality, errors, gc, dismiss, fix, suppress, doctor, setup, cortex. | `packages/drift-cli/src/commands/` — 27 command files |
| T20-06 | **CLI — drift analyze Wiring** — Run `drift analyze` on a fixture repo. | Must invoke `driftAnalyze()` NAPI binding. Must persist results to `drift.db`. `drift status` afterward must show non-zero counts. | Known P0 gap: `drift analyze` command exists but must call real NAPI |
| T20-07 | **CLI — drift simulate Valid Category** — Run `drift simulate --category add_feature`. | Must pass valid category string to `driftSimulate()`. Must NOT pass invalid category `'general'`. | Known bug: CLI passes invalid category 'general' |
| T20-08 | **CLI — drift explain Valid Intent** — Run `drift explain <violation_id>`. | Must pass valid intent format to `driftContext()`. Must NOT pass `explain_violation:${id}` (invalid). | Known bug: CLI passes invalid intent format |
| T20-09 | **CI Agent — All 10 Passes Execute** — Run CI agent on a fixture repo. | All 10 passes must execute: detection, patterns, boundaries, call_graph, taint, errors, coupling, contracts, security, test_quality. | `packages/drift-ci/src/agent.ts` — 10 parallel passes |
| T20-10 | **CI Agent — Weighted Scoring** — Run CI agent. Verify final score computation. | Score = Σ(pass_score × weight). Weights must sum to 1.0. Score must be in [0, 100]. | `agent.ts` — weighted scoring formula |
| T20-11 | **CI Agent — async/await Correctness** — Run call_graph and boundaries passes. | Must not have async/await bugs (missing await on Promise). Results must be fully resolved. | Known bug: async/await issues in call_graph and boundaries passes |
| T20-12 | **CLI — Cortex Subcommands** — Run `drift cortex <sub>` for memory, search, predict, sanitize, cloud, session, restore, decay, time-travel. | Each must invoke the correct Cortex NAPI binding. Must not throw "command not found". | `packages/drift-cli/src/commands/cortex.ts` — 31 subcommand registrations |

---

## Category 21: Advanced Systems (Flow 14)

Simulation engine, decision mining, context generation, specification generation. Zero coverage in original suite.

| ID | Test | Parameter | Source Verification |
|----|------|-----------|---------------------|
| T21-01 | **Simulation — All 13 Task Categories** — Call `driftSimulate(category)` for each: add_feature, fix_bug, refactor, add_test, security_fix, performance, migration, dependency_update, documentation, deployment, monitoring, accessibility, api_change. | Each must return non-empty recommendation with `confidence` interval and `risk_assessment`. | `advanced/simulation/` — `StrategyRecommender::recommend()` with 13 categories |
| T21-02 | **Simulation — Monte Carlo Confidence** — Run simulation 1000 times for the same task. | Confidence interval [lower, upper] must narrow with more samples. Mean must converge. | `advanced/simulation/` — Monte Carlo confidence intervals |
| T21-03 | **Decision Mining — Git Log Parsing** — Run `driftDecisions` on a repo with 100+ commits. | Must parse commit messages, extract architectural decisions, group by pattern. Must handle up to 500 commits. | `advanced/decisions/` — `GitAnalyzer::analyze(path)` parses up to 500 commits |
| T21-04 | **Context Generation — 5 Intents × 3 Depths** — Call `driftContext(intent, depth)` for all 15 combinations. | Each must return non-empty sectioned output. Token count must increase with depth (Overview < Standard < Deep). | `advanced/context/` — 5 intents × 3 depths = 15 combinations |
| T21-05 | **Spec Generation** — Call `driftGenerateSpec(module, migration_path)` with source=TypeScript, target=Rust. | Must produce migration spec with source→target language mapping. Must not be empty. | `advanced/specifications/` — `SpecificationRenderer::render()` |
| T21-06 | **Context — Token Counting** — Generate context with depth=Deep for a large module. | `token_count` in output must be >0 and reflect actual content length. Must stay within configured token budget. | `advanced/context/` — token-counted sectioned output |

---

## Category 22: Production Hardening Gaps (Appendix A)

9 specific production issues documented in the critical flow map. Each needs a regression test.

| ID | Test | Parameter | Source Verification |
|----|------|-----------|---------------------|
| T22-01 | **A1: Call Graph Double-Build** — Profile `drift_analyze()` on a 1000-file repo. Count call graph construction invocations. | Step 3b and Step 6 must NOT both build from scratch. If cached, second build must be <10% of first build's time. | Appendix A1: `analysis.rs` line 923 rebuilds call graph |
| T22-02 | **A2: File Content Re-Read** — Profile `drift_analyze()`. Count `std::fs::read_to_string()` calls per file. | Each file should be read at most once (not per step). Steps 5b–5l must use cached content. | Appendix A2: Steps 5b–5l each re-read from disk |
| T22-03 | **A3: Pipeline Timeout** — Run `drift_analyze()` with a configurable timeout of 5s on a repo that would take 30s. | Must return partial results within 6s (timeout + grace). Must NOT hang. | Appendix A3: No pipeline timeout exists |
| T22-04 | **A4: Memory Pressure** — Run `drift_analyze()` on a 10,000-file repo. Monitor RSS memory. | `all_parse_results: Vec<ParseResult>` must not cause OOM. Memory must stay below 2GB for 10K files. | Appendix A4: Unbounded Vec<ParseResult> |
| T22-05 | **A5: Per-File Error Aggregation** — Run `drift_analyze()` on a repo where 5 files are unreadable (permission denied). | Return type must include `errors: Vec<FileError>` field. Must contain all 5 file errors. Pipeline must continue past failures. | Appendix A5: ~15 locations use `continue` with no aggregation |
| T22-06 | **A6: Degradation Alerts Delta** — Run analysis twice. Second run has worse scores. | Alerts must be based on delta from previous run (not just absolute threshold). Must load previous run's gate results. | Appendix A6: Only checks absolute thresholds |
| T22-07 | **A7: BatchWriter Mid-Pipeline Failure** — Inject writer failure at Step 5. | Steps 6-8 must either not run, or pipeline must surface the writer error in its return. Earlier data must not be silently lost. | Appendix A7: No transactional boundary across pipeline |
| T22-08 | **A8: data_access function_id FK** — Insert data_access rows. Join with functions table on function_id. | Join must produce correct results. `function_id` must be a real FK, not `line as i64` proxy. | Appendix A8: line number used as proxy for FK |
| T22-09 | **A9: CI Agent Pass Count** — Grep all comments in `agent.ts` and `index.ts` referencing pass count. | All must say "10" (not "9"). No inconsistency. | Appendix A9: Comments alternate between 9 and 10 |

---

## Category 23: End-to-End Smoke Tests

Full pipeline exercises from user entry point to database persistence to query output. These validate the entire stack works together.

| ID | Test | Parameter | Source Verification |
|----|------|-----------|---------------------|
| T23-01 | **scan → analyze → check → report (Golden Path)** — On `test-fixtures/` repo: call `driftScan`, then `driftAnalyze`, then `driftCheck`, then `driftReport("sarif")`. | Each step must succeed. `drift.db` must contain rows in `file_metadata`, `detections`, `pattern_confidence`, `violations`, `gate_results`. SARIF output must be valid JSON with >0 results. | Full pipeline E2E — the critical path for beta |
| T23-02 | **Incremental Re-Scan** — Run golden path. Add 1 file. Re-scan. | `ScanDiff.added` must contain exactly 1 file. `ScanDiff.modified` must be empty (no content change). Re-analysis must only process the new file. | Incremental pipeline correctness |
| T23-03 | **File Deletion Handling** — Run golden path. Delete 1 file from disk. Re-scan. | `ScanDiff.removed` must contain the deleted file. Its detections must be cleaned up (orphan cleanup). | `compute_diff()` — files in cache but not on disk → removed |
| T23-04 | **Empty Repo** — Run golden path on a repo with 0 source files (only `.gitignore`). | Must complete without error. All counts = 0. No violations. No crash. | Edge case: empty input |
| T23-05 | **Multi-Language Repo** — Run golden path on a repo with files in all 10 supported languages. | Each language must be detected. Parse results must have correct `language` field. Detectors must fire for each language's patterns. | Cross-language correctness |
| T23-06 | **Cortex Memory → Bridge → Drift Grounding** — Create a Cortex memory. Run bridge grounding against `drift.db` analysis data. | Grounding score must reflect evidence from drift.db. `evidence_types` must be populated (not all InsufficientData). | Bridge E2E: cortex.db ↔ drift.db interaction |

---

## Category 24: Graceful Degradation

What happens when components fail? Beta users will hit edge cases — the system must not crash.

| ID | Test | Parameter | Source Verification |
|----|------|-----------|---------------------|
| T24-01 | **No drift.db File** — Call `driftStatus()` before any scan. | Must return zeros (not crash). Must create `drift.db` on first write. | Runtime initialization must handle missing DB |
| T24-02 | **Corrupt drift.db** — Replace `drift.db` with random bytes. Call `driftScan()`. | Must detect corruption (`PRAGMA integrity_check` fails). Must return error, not panic. Ideally recreate DB. | SQLite integrity check |
| T24-03 | **Cortex Without Drift** — Initialize Cortex runtime without drift.db present. | All Cortex NAPI bindings must work independently. Bridge grounding must gracefully return InsufficientData (not crash). | `bridge_ground_memory()` — `drift_db: Option<&Connection>` parameter |
| T24-04 | **Parser Failure on One File** — Include a binary file (`.png`) that the parser can't handle. | Parser must return error for that file. All other files must still be parsed and analyzed. Pipeline continues. | Error recovery: `continue` on parse failure |
| T24-05 | **BatchWriter Channel Full** — Flood >1024 commands while writer thread is blocked. | Must not crash. Sender blocks until space available. No data loss. Timeout if channel blocked >5s. | `writer.rs:24` — `bounded(1024)` channel |
| T24-06 | **Native Binary Missing at Runtime** — Delete `.node` binary after initial load. Call a NAPI function. | Must return stub response (not crash process). `loadNapi()` error must be catchable. | `loader.ts` — stub fallback |
| T24-07 | **Concurrent Shutdown** — Call `driftShutdown()` while `driftAnalyze()` is running. | Must not deadlock. Analysis must be cancelled gracefully. BatchWriter must flush pending commands before shutdown. | `writer.rs:116-121` — Drop sends Shutdown command |

---

## Category 25: Performance Budgets

Timing and resource budgets that must not regress. These are gates, not functional tests.

| ID | Test | Parameter | Source Verification |
|----|------|-----------|---------------------|
| T25-01 | **Scan Budget — 1000 Files** — Scan a 1000-file repo. | Must complete in <10s. `ScanStats.discovery_ms + hashing_ms + diff_ms` must all be populated. | `types.rs:37-48` — ScanStats 10 fields |
| T25-02 | **Analysis Budget — 100 Files** — Run `drift_analyze()` on 100 files. | Must complete in <30s. Each of the 8 pipeline steps must record `step_time_ms`. No single step >50% of total. | `analysis.rs` — 8 major steps |
| T25-03 | **Parse Budget — Single File** — Parse a 10,000-line TS file. | Must complete in <2s. `parse_time_us` must be recorded. | Parser performance gate |
| T25-04 | **Batch Write Budget — 10,000 Commands** — Send 10K InsertDetection commands. | Must flush all within 5s. WriteStats must show 10,000 detections written. | `writer.rs` — batch + flush timeout |
| T25-05 | **Vector Search Budget — 10,000 Memories** — Insert 10K embeddings. Run nearest-neighbor search. | Must return results in <500ms. Must not scan all rows (early exit on zero-similarity). | D-05/D-06 fix: early exit optimizations |
| T25-06 | **CI Agent Budget — Full Run** — Run CI agent on test-fixtures. | Must complete all 10 passes in <60s. No pass may exceed 30s individually. | `agent.ts` — parallel pass execution |

---

## Category 26: Idempotency & Determinism

Running the same operation twice must produce identical results. Critical for CI reproducibility.

| ID | Test | Parameter | Source Verification |
|----|------|-----------|---------------------|
| T26-01 | **Analysis Idempotency** — Run `drift_analyze()` twice on the same repo without changes. | Second run must produce identical `detections`, `pattern_confidence`, `violations`, and `gate_results`. No ghost deltas. | Deterministic pipeline output |
| T26-02 | **Scanner Sorted Output** — Scan a repo with files in random filesystem order. Run twice. | `ScanDiff.added` must be sorted identically both times. | `scanner.rs` — sorted output documented |
| T26-03 | **Convention Discovery Determinism** — Run pattern intelligence on the same repo twice. | `conventions` must be identical: same `pattern_id`, `scope`, `frequency`, `is_contested`, `convergence_score`. | `learning/discovery.rs` — deterministic with same input |
| T26-04 | **Enforcement Determinism** — Run enforcement on identical input twice. | Gate results must have identical `score`, `status`, `violations_count`. Execution time may differ but status must not. | Enforcement must be deterministic given same GateInput |
| T26-05 | **Report Format Stability** — Generate SARIF for the same analysis results twice. | Output must be byte-identical (ignoring timestamps). Rule IDs, violation locations, severity must match exactly. | Reporter determinism for CI diffing |

---

## Category 27: Cortex-Drift Bridge (Expanded — Flow 13)

Category 4 covered basic grounding. These tests cover the remaining 14 bridge subsystems.

| ID | Test | Parameter | Source Verification |
|----|------|-----------|---------------------|
| T27-01 | **Evidence Collection — All 10 Types** — Ground a memory with a drift.db containing data for all 10 evidence types. | All 10 `EvidenceType` variants must be collected: `pattern_confidence`, `occurrence_rate`, `temporal_stability`, `cross_validation`, `file_coverage`, `detection_method_agreement`, `outlier_status`, `convention_alignment`, `enforcement_status`, `community_signal`. | `evidence/types.rs` — `EvidenceType` has `Hash` derive for HashSet |
| T27-02 | **drift_db Fallback Path** — Ground a memory with `MemoryForGrounding` having `None` fields but valid `drift_db` + `evidence_context`. | Must use slow path (query drift.db via `collect_one()`). Pre-populated fields must take priority over drift.db results when both exist. | Bug #6 fix: `ground_single()` now passes `_drift_db` instead of `None` |
| T27-03 | **Causal Narrative Generation** — Call `bridge_causal_narrative` with a memory that has drift analysis data. | Must return structured narrative (not empty string). Must reference actual drift findings. | `cortex-drift-bridge/src/narrative/` — causal narrative builder |
| T27-04 | **Link Translation — Memory↔Detection** — Create links between Cortex memories and Drift detections. Translate link IDs across databases. | Translated link must resolve to correct row in target DB. Broken links must be detected and flagged. | `cortex-drift-bridge/src/links/` — bidirectional link translation |
| T27-05 | **Atomic Link Removal** — Create 3 links of different types. Remove one atomically. | Only the targeted link must be removed. Other 2 must remain. Operation must be a single DELETE (not select-then-delete). | P2-11/E-04 fix: 4 atomic `remove_*_link` functions in `link_ops.rs` |
| T27-06 | **Bridge Schema Not Subject to Retention** — Insert `schema_version` in `bridge_metrics`. Wait past 7-day retention window. | `schema_version` must NOT be cleaned up by retention. | Known gap: `bridge_metrics` subject to 7-day retention cleanup |
| T27-07 | **Grounding Loop — Batch Processing** — Ground 50 memories in a single `bridge_ground_all()` call. | All 50 must be processed. Grounding scores must vary by evidence strength. No OOM on batch. | `loop_runner.rs` — `run()` iterates all pending memories |
| T27-08 | **Bridge NAPI Function Exposure** — Call all 20 bridge NAPI functions from TS via CortexClient. | All must be callable (not throw "function not found"). Return types must match TS declarations. | Known gap: 20 NAPI-ready functions + 6 MCP tool handlers with ZERO TS exposure |

---

## CI Integration Plan

### Pipeline Architecture

The 225 production tests run in 3 tiers with different triggers, timeouts, and parallelism.

```
┌─────────────────────────────────────────────────────────────────────┐
│                        CI PIPELINE                                   │
│                                                                      │
│  Tier 1: GATE (every PR, must pass to merge)                        │
│  ├─ Rust unit tests (cargo test --workspace)              ~5 min    │
│  ├─ Clippy (cargo clippy --all -- -D warnings)            ~2 min    │
│  ├─ TS typecheck (tsc --noEmit per package)               ~1 min    │
│  └─ Production Cats 23, 24 (smoke + degradation)          ~3 min    │
│                                                           ─────     │
│                                                           ~11 min   │
│                                                                      │
│  Tier 2: CORE (every PR, non-blocking advisory)                     │
│  ├─ Production Cats 1-2 (NAPI + SQLite)                   ~5 min    │
│  ├─ Production Cats 5-6 (Pipeline + Enforcement)          ~5 min    │
│  ├─ Production Cats 15-16 (Parser + Detection)            ~4 min    │
│  ├─ Production Cat 20 (Presentation Layer)                ~3 min    │
│  └─ Production Cat 22 (Production Hardening)              ~4 min    │
│                                                           ─────     │
│                                                           ~21 min   │
│                                                                      │
│  Tier 3: FULL (nightly + release branch, blocking)                  │
│  ├─ All 225 production tests                              ~45 min   │
│  ├─ Performance budgets (Cat 25)                          ~10 min   │
│  └─ Idempotency checks (Cat 26)                          ~5 min    │
│                                                           ─────     │
│                                                           ~60 min   │
└─────────────────────────────────────────────────────────────────────┘
```

### Parallelization Strategy

**Rust tests** — Group by crate to exploit `cargo test` parallel test runner:

| Group | Crate | Categories | Estimated Time |
|-------|-------|------------|----------------|
| **R1** | `drift-analysis` | 3, 5, 6, 10, 15, 16, 17, 18, 21, 26 | ~15 min |
| **R2** | `drift-storage` | 2, 7, 8, 13 | ~5 min |
| **R3** | `drift-napi` | 1, 22, 23, 25 | ~10 min (needs native binary) |
| **R4** | `drift-core` | 9, 12, 14 | ~3 min |
| **R5** | `cortex-*` | 19 | ~8 min |
| **R6** | `cortex-drift-bridge` | 4, 27 | ~5 min |

Groups R1–R6 run **in parallel** on CI. Total wall time: ~15 min (limited by R1).

**TS tests** — Group by package:

| Group | Package | Categories | Estimated Time |
|-------|---------|------------|----------------|
| **T1** | `drift-mcp` | 20 (MCP tests) | ~3 min |
| **T2** | `drift-cli` | 20 (CLI tests) | ~2 min |
| **T3** | `drift-ci` | 20 (CI agent tests) | ~3 min |
| **T4** | `drift-napi-contracts` | 1 (stub/loader) | ~1 min |

Groups T1–T4 run **in parallel**. Total wall time: ~3 min.

### Gating Strategy

| Event | Tier 1 (Gate) | Tier 2 (Core) | Tier 3 (Full) |
|-------|---------------|---------------|----------------|
| **PR opened/updated** | ✅ Required | ⚠️ Advisory | ❌ Not run |
| **Merge to main** | ✅ Required | ✅ Required | ❌ Not run |
| **Nightly (2 AM UTC)** | ✅ Required | ✅ Required | ✅ Required |
| **Release branch** | ✅ Required | ✅ Required | ✅ Required |
| **Manual trigger** | ✅ | ✅ | ✅ |

### Failure Response Protocol

| Tier | On Failure |
|------|-----------|
| **Tier 1** | PR cannot merge. Author must fix immediately. |
| **Tier 2** | PR can merge but generates Slack alert to `#drift-ci`. Author must fix within 24h. |
| **Tier 3** | Release blocked. On-call engineer triages within 4h. If flaky (passes on retry), file issue and allow release. |

### Environment Variables for CI

```bash
# Required for native binary tests
DRIFT_NAPI_BINARY_PATH=/path/to/drift.node
CORTEX_NAPI_BINARY_PATH=/path/to/cortex.node

# Required for performance budget tests (Cat 25)
DRIFT_PERF_CI=1              # Enables 2× timing margins for CI
DRIFT_PERF_BUDGET_SCAN=10000 # ms, scan 1000 files
DRIFT_PERF_BUDGET_ANALYZE=30000 # ms, analyze 100 files
DRIFT_PERF_BUDGET_PARSE=2000 # ms, parse single 10K-line file

# Required for large repo tests (Cat 22)
DRIFT_LARGE_FIXTURE_PATH=/tmp/drift-large-fixture
```

### GitHub Actions Workflow Sketch

```yaml
# .github/workflows/production-tests.yml
name: Production Test Suite
on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: '0 2 * * *'  # nightly 2 AM UTC

jobs:
  build-native:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build drift-napi
        run: cd crates/drift/drift-napi && napi build --release
      - name: Build cortex-napi
        run: cd crates/cortex/cortex-napi && napi build --release
      - uses: actions/upload-artifact@v4
        with:
          name: native-binaries
          path: |
            crates/drift/drift-napi/*.node
            crates/cortex/cortex-napi/*.node

  tier1-gate:
    needs: build-native
    strategy:
      matrix:
        group: [smoke-rust, smoke-ts]
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@v4
      - uses: actions/download-artifact@v4
      - name: Run Tier 1 tests
        run: |
          cargo test -p drift-napi --test production_cat23_test
          cargo test -p drift-napi --test production_cat24_test

  tier2-core:
    needs: build-native
    if: github.event_name != 'pull_request' || github.event.action == 'ready_for_review'
    strategy:
      matrix:
        group: [R1, R2, R3, R4, R5, R6, T1, T2, T3, T4]
    runs-on: ubuntu-latest
    timeout-minutes: 25

  tier3-full:
    needs: [tier1-gate, tier2-core]
    if: github.event_name == 'schedule' || startsWith(github.ref, 'refs/heads/release/')
    runs-on: ubuntu-latest
    timeout-minutes: 75
```

---

## Implementation Tracking Checklist

Track progress per test. Mark `[x]` when a test is implemented, passing, and reviewed.

### Phase 1 — P0 Foundation (91 tests, 7 categories)

#### Cat 23: E2E Smoke (6 tests) — Target crate: `drift-napi`
- [ ] T23-01 — Golden path (scan → analyze → check → report)
- [ ] T23-02 — Incremental re-scan
- [ ] T23-03 — File deletion handling
- [ ] T23-04 — Empty repo
- [ ] T23-05 — Multi-language repo
- [ ] T23-06 — Cortex → Bridge → Drift grounding

#### Cat 15: Parser Correctness (10 tests) — Target crate: `drift-analysis`
- [ ] T15-01 — ParseResult field completeness (TypeScript)
- [ ] T15-02 — All 10 language parsers return valid output
- [ ] T15-03 — Fallback grammar coverage (C, C++, Swift, Scala)
- [ ] T15-04 — Parse cache hit
- [ ] T15-05 — Parse cache invalidation
- [ ] T15-06 — Error recovery (syntax errors)
- [ ] T15-07 — Empty file
- [ ] T15-08 — Large file performance (50K lines)
- [ ] T15-09 — ParseResult round-trip through NAPI
- [ ] T15-10 — Decorator extraction (NestJS)

#### Cat 16: Detection Engine (7 tests) — Target crate: `drift-analysis`
- [ ] T16-01 — All 16 detectors fire
- [ ] T16-02 — Detector panic safety
- [ ] T16-03 — Learning detector 2-pass
- [ ] T16-04 — DetectionContext construction with empty functions
- [ ] T16-05 — PatternMatch output completeness
- [ ] T16-06 — Category filtering (critical_only)
- [ ] T16-07 — Security detector CWE mapping

#### Cat 1: NAPI Threading (11 tests) — Target crate: `drift-napi` + `drift-napi-contracts`
- [ ] T1-01 — Parallelism ceiling (rayon thread counts)
- [ ] T1-02 — Buffer transfer stress (10K functions)
- [ ] T1-03 — Cancellation latency
- [ ] T1-04 — OnceLock double-init rejection
- [ ] T1-05 — BatchWriter thread survival
- [ ] T1-06 — Concurrent NAPI calls (50 simultaneous)
- [ ] T1-07 — AsyncTask cancellation propagation
- [ ] T1-08 — ThreadsafeFunction progress delivery
- [ ] T1-09 — NAPI error code propagation
- [ ] T1-10 — snake_case → camelCase binding fidelity
- [ ] T1-11 — Stub fallback on missing binary

#### Cat 2: SQLite/WAL Concurrency (13 tests) — Target crate: `drift-storage`
- [ ] T2-01 — Write-write conflict serialization
- [ ] T2-02 — WAL checkpoint pressure (5K files)
- [ ] T2-03 — Retention tier logic
- [ ] T2-04 — Channel backpressure (>1024 commands)
- [ ] T2-05 — Batch atomicity on failure
- [ ] T2-06 — Flush timeout drain (<500 commands)
- [ ] T2-07 — ReadPool round-robin under contention
- [ ] T2-08 — In-memory BatchWriter isolation
- [ ] T2-09 — Writer mutex poison recovery
- [ ] T2-10 — ReadPool poison recovery
- [ ] T2-11 — Writer pragma verification (8 pragmas)
- [ ] T2-12 — Reader pragma isolation
- [ ] T2-13 — File-backed vs in-memory mode behavioral diff

#### Cat 20: Presentation Layer (12 tests) — Target packages: `drift-mcp`, `drift-cli`, `drift-ci`
- [ ] T20-01 — MCP server all 6 entry points
- [ ] T20-02 — MCP drift_scan triggers analysis
- [ ] T20-03 — MCP Cortex tool registration
- [ ] T20-04 — MCP infrastructure modules
- [ ] T20-05 — CLI all 27 commands parse
- [ ] T20-06 — CLI drift analyze wiring
- [ ] T20-07 — CLI drift simulate valid category
- [ ] T20-08 — CLI drift explain valid intent
- [ ] T20-09 — CI agent all 10 passes execute
- [ ] T20-10 — CI agent weighted scoring
- [ ] T20-11 — CI agent async/await correctness
- [ ] T20-12 — CLI cortex subcommands

#### Cat 22: Production Hardening (9 tests) — Target crate: `drift-napi`
- [ ] T22-01 — Call graph double-build detection
- [ ] T22-02 — File content re-read profiling
- [ ] T22-03 — Pipeline timeout (5s configurable)
- [ ] T22-04 — Memory pressure (10K files, <2GB RSS)
- [ ] T22-05 — Per-file error aggregation
- [ ] T22-06 — Degradation alerts delta-based
- [ ] T22-07 — BatchWriter mid-pipeline failure
- [ ] T22-08 — data_access function_id FK
- [ ] T22-09 — CI agent pass count consistency

#### Cat 24: Graceful Degradation (7 tests) — Target crate: `drift-napi` + `drift-storage`
- [ ] T24-01 — No drift.db file (returns zeros)
- [ ] T24-02 — Corrupt drift.db (detect + error, not panic)
- [ ] T24-03 — Cortex without drift (InsufficientData)
- [ ] T24-04 — Parser failure on binary file
- [ ] T24-05 — BatchWriter channel full (no crash)
- [ ] T24-06 — Native binary missing at runtime
- [ ] T24-07 — Concurrent shutdown (no deadlock)

#### Cat 6: Enforcement Gates (16 tests) — Target crate: `drift-analysis`
- [ ] T6-01 — Circular dependency detection
- [ ] T6-02 — Dependency cascade skip
- [ ] T6-03 — Timeout enforcement (30s)
- [ ] T6-04 — Empty GateInput — PatternCompliance passes
- [ ] T6-05 — Empty GateInput — other 5 gates skip
- [ ] T6-06 — Progressive enforcement
- [ ] T6-07 — Baseline is_new detection
- [ ] T6-08 — Gate execution timing
- [ ] T6-09 — Custom gate registration
- [ ] T6-10 — Suppression format coverage (4 formats)
- [ ] T6-11 — Suppression rule-specific filtering
- [ ] T6-12 — Quick-fix language awareness (7 languages)
- [ ] T6-13 — Policy engine all 4 aggregation modes
- [ ] T6-14 — FP rate auto-disable
- [ ] T6-15 — Feedback abuse detection
- [ ] T6-16 — Progressive enforcement 4-phase ramp

### Phase 2 — P1 Depth (110 tests, 10 categories)

#### Cat 5: Analysis Pipeline (8 tests) — Target crate: `drift-analysis`
- [ ] T5-01 — Phase ordering invariant
- [ ] T5-02 — Resolution index accumulation
- [ ] T5-03 — ParseResult completeness cascade
- [ ] T5-04 — Incremental skip correctness
- [ ] T5-05 — Content hash L2 skip
- [ ] T5-06 — File removal detection
- [ ] T5-07 — Deterministic scan output
- [ ] T5-08 — Language detection coverage (18+ extensions)

#### Cat 9: Incremental Scan (10 tests) — Target crate: `drift-analysis` + `drift-core`
- [ ] T9-01 — mtime fast path hit rate
- [ ] T9-02 — mtime change + same content (L2 hash)
- [ ] T9-03 — force_full_scan bypass
- [ ] T9-04 — Large file skip (max_file_size)
- [ ] T9-05 — Symlink following
- [ ] T9-06 — .driftignore respect
- [ ] T9-07 — 18 default ignore patterns
- [ ] T9-08 — Cancellation mid-walk
- [ ] T9-09 — Cancellation mid-hash
- [ ] T9-10 — Event emission sequence

#### Cat 17: Structural Analysis (10 tests) — Target crate: `drift-analysis`
- [ ] T17-01 — Coupling Martin metrics
- [ ] T17-02 — Coupling cycle detection
- [ ] T17-03 — Wrapper detection confidence
- [ ] T17-04 — Crypto weak algorithm detection
- [ ] T17-05 — DNA naming gene consistency
- [ ] T17-06 — Secrets entropy filtering
- [ ] T17-07 — Magic numbers (named vs unnamed)
- [ ] T17-08 — Constraint verification (MustExist)
- [ ] T17-09 — Env variable extraction (8 languages)
- [ ] T17-10 — Decomposition suggestions

#### Cat 18: Graph Intelligence (11 tests) — Target crate: `drift-analysis`
- [ ] T18-01 — Call graph all 6 resolution strategies
- [ ] T18-02 — Call graph import-based resolution
- [ ] T18-03 — Call graph incremental rebuild
- [ ] T18-04 — Taint source→sink reachability (3-hop)
- [ ] T18-05 — Taint over-approximation guard
- [ ] T18-06 — Taint registry pattern matching
- [ ] T18-07 — Error handling gap detection
- [ ] T18-08 — Impact blast radius scoring
- [ ] T18-09 — Impact dead code detection
- [ ] T18-10 — Test topology 7 quality dimensions
- [ ] T18-11 — Test topology count_source_calls uses call graph

#### Cat 3: Intelligence Precision (11 tests) — Target crate: `drift-analysis`
- [ ] T3-01 — Bayesian convergence (100 FP feedback)
- [ ] T3-02 — DNA allele consistency
- [ ] T3-03 — Taint reachability depth scaling
- [ ] T3-04 — Confidence tier boundary precision
- [ ] T3-05 — Temporal decay symmetry
- [ ] T3-06 — Feedback loop saturation (10K events)
- [ ] T3-07 — 6-factor weight invariant (sum=1.0)
- [ ] T3-08 — DataQuality factor impact
- [ ] T3-09 — Credible interval numerical stability
- [ ] T3-10 — Convention persistence across runs
- [ ] T3-11 — Outlier detection minimum sample (<3)

#### Cat 10: Reporter Formats (10 tests) — Target crate: `drift-analysis`
- [ ] T10-01 — SARIF taxonomy placement
- [ ] T10-02 — JUnit error/failure semantics
- [ ] T10-03 — SonarQube rules array
- [ ] T10-04 — Console report readability
- [ ] T10-05 — JSON report schema stability
- [ ] T10-06 — GitHub annotations format
- [ ] T10-07 — GitLab code quality fingerprints
- [ ] T10-08 — HTML report generation
- [ ] T10-09 — All 8 formats via driftReport()
- [ ] T10-10 — SARIF isNew property

#### Cat 19: Cortex Memory System (12 tests) — Target crate: `cortex-napi` + `cortex-*`
- [ ] T19-01 — Memory CRUD lifecycle (create/read/update/delete)
- [ ] T19-02 — Re-embed on content update
- [ ] T19-03 — Embedding degradation chain
- [ ] T19-04 — L2 cache persistence (restart survival)
- [ ] T19-05 — Consolidation eligibility (Episodic + Procedural)
- [ ] T19-06 — Vector search correctness
- [ ] T19-07 — Privacy sanitization (overlapping matches)
- [ ] T19-08 — Causal graph hydration (restart)
- [ ] T19-09 — Decay engine scheduling
- [ ] T19-10 — Multi-agent namespace isolation (RBAC)
- [ ] T19-11 — Session lifecycle
- [ ] T19-12 — Validation 4 dimensions

#### Cat 7: BatchCommand Coverage (5 tests) — Target crate: `drift-storage`
- [ ] T7-01 — All 33 data commands round-trip
- [ ] T7-02 — Flush + shutdown control commands
- [ ] T7-03 — Mixed batch transaction (500 commands)
- [ ] T7-04 — Drop without shutdown (thread safety)
- [ ] T7-05 — 13 unwired tables direct write

#### Cat 11: Contract Extraction (8 tests) — Target crate: `drift-analysis`
- [ ] T11-01 — Next.js backend classification
- [ ] T11-02 — Paradigm classification (express/trpc/frontend)
- [ ] T11-03 — Confidence from field quality
- [ ] T11-04 — Contract upsert idempotency
- [ ] T11-05 — Mismatch accumulation
- [ ] T11-06 — Empty batch commands
- [ ] T11-07 — Disjoint BE/FE paths (0 false positives)
- [ ] T11-08 — Type mismatch detection

#### Cat 4: Bridge Grounding (6 tests) — Target crate: `cortex-drift-bridge`
- [ ] T4-01 — Link translation broken link
- [ ] T4-02 — Grounding score weights (10 evidence types)
- [ ] T4-03 — Prepopulated vs drift DB fallback
- [ ] T4-04 — No evidence context = no fallback
- [ ] T4-05 — Atomic link removal race (10 threads)
- [ ] T4-06 — Bridge schema triple-duplication

#### Cat 27: Bridge Expanded (8 tests) — Target crate: `cortex-drift-bridge`
- [ ] T27-01 — Evidence collection all 10 types
- [ ] T27-02 — drift_db fallback path
- [ ] T27-03 — Causal narrative generation
- [ ] T27-04 — Link translation memory↔detection
- [ ] T27-05 — Atomic link removal
- [ ] T27-06 — Bridge schema not subject to retention
- [ ] T27-07 — Grounding loop batch processing (50 memories)
- [ ] T27-08 — Bridge NAPI function exposure (20 functions)

#### Cat 25: Performance Budgets (6 tests) — Target crate: `drift-napi` + `drift-analysis`
- [ ] T25-01 — Scan budget 1000 files (<10s)
- [ ] T25-02 — Analysis budget 100 files (<30s)
- [ ] T25-03 — Parse budget single file (<2s)
- [ ] T25-04 — Batch write budget 10K commands (<5s)
- [ ] T25-05 — Vector search budget 10K memories (<500ms)
- [ ] T25-06 — CI agent budget full run (<60s)

#### Cat 26: Idempotency & Determinism (5 tests) — Target crate: `drift-analysis` + `drift-napi`
- [ ] T26-01 — Analysis idempotency (double-run identical)
- [ ] T26-02 — Scanner sorted output
- [ ] T26-03 — Convention discovery determinism
- [ ] T26-04 — Enforcement determinism
- [ ] T26-05 — Report format stability

### Phase 3 — P2 Polish (24 tests, 5 categories)

#### Cat 8: Migration & Schema (6 tests) — Target crate: `drift-storage`
- [ ] T8-01 — Fresh DB all 45 tables created
- [ ] T8-02 — Idempotent re-open
- [ ] T8-03 — v006 PART2 execution
- [ ] T8-04 — Foreign key integrity (constraint_verifications)
- [ ] T8-05 — FK cascade (migration_modules)
- [ ] T8-06 — WAL mode verification

#### Cat 12: Event System (4 tests) — Target crate: `drift-core`
- [ ] T12-01 — Full event sequence (scan→analyze→check)
- [ ] T12-02 — EventDispatcher fan-out (3 handlers)
- [ ] T12-03 — Progress event frequency (every 100 files)
- [ ] T12-04 — Error event on walker failure

#### Cat 13: Retention & Data Lifecycle (4 tests) — Target crate: `drift-storage`
- [ ] T13-01 — constraint_verifications column name (verified_at)
- [ ] T13-02 — Orphan cleanup atomicity
- [ ] T13-03 — Self-bounding tables (INSERT OR REPLACE)
- [ ] T13-04 — Tier assignment coverage (all 45 tables)

#### Cat 14: Configuration (4 tests) — Target crate: `drift-core`
- [ ] T14-01 — Default ScanConfig values
- [ ] T14-02 — Config TOML round-trip
- [ ] T14-03 — Project root fallback
- [ ] T14-04 — extra_ignore patterns

#### Cat 21: Advanced Systems (6 tests) — Target crate: `drift-analysis` + `drift-context`
- [ ] T21-01 — Simulation all 13 task categories
- [ ] T21-02 — Simulation Monte Carlo convergence
- [ ] T21-03 — Decision mining git log parsing
- [ ] T21-04 — Context generation 5×3 matrix
- [ ] T21-05 — Spec generation (TS→Rust)
- [ ] T21-06 — Context token counting

---

## Cross-Reference Verification Matrix

Every flow from [CRITICAL-FLOW-MAP.md](./CRITICAL-FLOW-MAP.md) must have at least one production test. This matrix proves completeness.

| Flow | Critical Flow Map Section | Primary Categories | Test Count | Coverage |
|------|--------------------------|-------------------|-----------|----------|
| 1 | Scanner (§2) | Cat 9, 5, 23 | 24 | ✅ Full — discovery, classification, diff, persistence, cancellation |
| 2 | Parser (§3) | Cat 15 | 10 | ✅ Full — all 10 languages, cache, error recovery, NAPI round-trip |
| 3 | Detection Engine (§4) | Cat 16 | 7 | ✅ Full — all 16 categories, panic safety, learning, CWE |
| 4 | Analysis Pipeline (§5) | Cat 5, 22, 23 | 23 | ✅ Full — phase ordering, resolution, incremental, timeout, memory |
| 5 | Pattern Intelligence (§6) | Cat 3 | 11 | ✅ Full — Bayesian, outliers, conventions, feedback, momentum |
| 6 | Structural Analysis (§7) | Cat 11, 17 | 18 | ✅ Full — all 10 subsystems (coupling, wrappers, crypto, DNA, secrets, constants, constraints, env, contracts, decomposition) |
| 7 | Graph Intelligence (§8) | Cat 18 | 11 | ✅ Full — call graph, taint, error handling, impact, test topology, reachability |
| 8 | Enforcement Engine (§9) | Cat 6, 10 | 26 | ✅ Full — 6 gates, policy, reporters, feedback, suppression, progressive, quick-fix |
| 9 | Storage Layer (§10) | Cat 2, 7, 8, 13 | 28 | ✅ Full — WAL, BatchWriter, migrations, retention, pragmas, pool |
| 10 | NAPI Bindings (§11) | Cat 1, 15, 20 | 33 | ✅ Full — threading, cancellation, stub fallback, camelCase, error codes |
| 11 | Presentation Layer (§12) | Cat 20 | 12 | ✅ Full — MCP 6 entry points, CLI 27 commands, CI 10 passes |
| 12 | Cortex Memory (§13) | Cat 19 | 12 | ✅ Full — CRUD, embeddings, privacy, causal, decay, multi-agent, sessions |
| 13 | Bridge (§14) | Cat 4, 27 | 14 | ✅ Full — 10 evidence types, link translation, narrative, batch, NAPI |
| 14 | Advanced Systems (§15) | Cat 21 | 6 | ✅ Full — simulation, decisions, context, spec gen |
| — | Cross-cutting | Cat 22, 23, 24, 25, 26 | 33 | ✅ Full — E2E smoke, degradation, performance, idempotency, hardening |
| | **TOTAL** | **27 categories** | **225** | **All 14 flows + 5 cross-cutting = complete** |

### Appendix A Gaps → Test Mapping

Every production hardening gap from CRITICAL-FLOW-MAP.md Appendix A has a corresponding test:

| Gap | Description | Test ID |
|-----|------------|---------|
| A1 | Call graph built twice | T22-01 |
| A2 | File content re-read from disk | T22-02 |
| A3 | No pipeline timeout | T22-03 |
| A4 | No memory pressure monitoring | T22-04 |
| A5 | Per-file errors silently swallowed | T22-05 |
| A6 | Degradation alerts simplistic | T22-06 |
| A7 | BatchWriter failure mid-pipeline | T22-07 |
| A8 | data_access function_id FK proxy | T22-08 |
| A9 | CI agent pass count inconsistency | T22-09 |

**All 9 Appendix A gaps are covered by Category 22.**

---

*Document version: 2.0 | 225 tests, 27 categories, 14 flows verified | Last updated: 2025-02-10*
