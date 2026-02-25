# Drift V2 + Cortex — Full System Audit & Implementation Plan

> **Auditor:** Cascade  
> **Date:** 2025-02-09 (verified 2025-02-09)  
> **Scope:** Every layer from Rust analysis engine → NAPI → TS packages → CLI/MCP/CI  
> **Goal:** 100% feature coverage — every Rust capability accessible to users via CLI, agents via MCP, and CI pipelines  
> **Verification:** Cross-checked every Rust `#[napi]` function against TS interface, MCP catalog, CLI commands, and CI passes

---

## Executive Summary

**The Rust engine is powerful and largely functional. The presentation layer is architecturally complete but has critical gaps that prevent users and agents from accessing ~40% of capabilities.**

### What's Built & Working
| Layer | Status | Details |
|-------|--------|---------|
| **Rust Analysis Engine** | ✅ ~90% functional | 1,808+ tests pass, clippy clean. Scanner, parsers, detection, patterns, enforcement, contracts, call graph, boundaries, structural analysis, advanced systems all implemented. |
| **drift-storage** | ✅ Functional | WAL mode, batch writer, read pool, 39 tables, 7 migrations, retention, keyset pagination. |
| **drift-napi (40 functions)** | ✅ All 40 wired to real code | Lifecycle(4), Scanner(3), Analysis(3), Patterns(4), Graph(5), Structural(9), Enforcement(5), Feedback(3), Advanced(4). Zero stubs remaining. |
| **drift-napi-contracts** | ⚠️ 38 of 40 | Single source of truth but missing `driftGC` and `drift_report`. Stub, loader, validation, 6 test files. |
| **drift-mcp** | ✅ Architecturally complete | 6 entry points, 37 internal tools, 7 infrastructure modules, stdio+HTTP transport. |
| **drift-cli** | ✅ 13 commands registered | scan, check, status, patterns, violations, impact, simulate, audit, setup, doctor, export, explain, fix. |
| **drift-ci** | ✅ 9-pass parallel agent | scan, patterns, call_graph, boundaries, security, tests, errors, contracts, constraints. SARIF + PR comment. |
| **Cortex** | ✅ 6 hardening phases complete | Embeddings, storage, privacy, prediction, temporal, observability all hardened. 81 E2E tests. |

### What's Broken / Missing (The Gaps)

| # | Severity | Gap | Impact |
|---|----------|-----|--------|
| 1 | **P0** | **No `drift analyze` in CLI** — scan only persists file metadata, not analysis results | User runs `drift scan` → gets file counts. No detections, patterns, violations, call graph, or boundaries persisted. Every query returns empty. |
| 2 | **P0** | **MCP `drift_scan` only calls `driftScan()`, not `drift_analyze()`** | Agent scans project but gets zero analysis results. All 30+ internal tools return empty data. |
| 3 | **P0** | **CLI has no `analyze` command** | 13 commands exist but none triggers the full analysis pipeline (`drift_analyze()`). |
| 4 | **P0** | **`drift_status` returns hardcoded `fileCount: 0`, `patternCount: 0`** | Status tool never queries actual file/pattern counts from DB. |
| 5 | **P1** | **MCP `drift_scan` doesn't run analysis after scan** | Scan and analyze are separate NAPI calls. MCP only calls scan. |
| 6 | **P1** | **CI agent `scan` pass doesn't trigger analysis** | Same issue — `driftScan()` only persists file metadata. |
| 7 | **P1** | **CLI `check` reads violations from DB but nothing writes them** | `drift_check` queries `violations` table, but no CLI command populates it. |
| 8 | **P1** | **CLI `export` reads violations from DB but nothing writes them** | Same root cause as #7. |
| 9 | **P1** | **`drift_report()` NAPI exists but no CLI/MCP tool exposes it** | 8-format report generation (SARIF, JSON, HTML, JUnit, SonarQube, console, GitHub, GitLab) is built but inaccessible. |
| 10 | **P1** | **MCP infrastructure layer created but never used by tool handlers** | `InfrastructureLayer` (cache, rate limiter, token estimator, error handler, cursor manager, response builder, tool filter) is instantiated in `server.ts` but zero tool handlers receive or use it. |
| 11 | **P1** | **CLI `setup` command creates config but doesn't run initial scan+analyze** | User runs `drift setup` → gets drift.toml but no data. Must manually run scan + (missing) analyze. |
| 12 | **P1** | **No `drift-napi` native binary build pipeline** | `loadNapi()` does `require('drift-napi')` but there's no `napi build` script, no `cargo-cp-artifact`, no platform-specific binary distribution. Falls back to stub silently. |
| 13 | **P2** | **MCP HTTP transport incomplete** | `createHttpTransport()` returns a `StreamableHTTPServerTransport` but no HTTP server is started. Comment says "HTTP server would be started here". |
| 14 | **P2** | **CLI output formatters don't handle all result types** | `formatOutput()` does JSON.stringify for json format, basic table for table format. No SARIF formatter for most commands. |
| 15 | **P2** | **CLI `simulate` passes `'general'` as category** | Rust expects specific categories (add_feature, fix_bug, etc.). CLI hardcodes `'general'` which will error. |
| 16 | **P2** | **CLI `explain` uses `drift_context` with violation ID as intent** | Passes `explain_violation:${id}` as intent. Rust only accepts 5 intents (fix_bug, add_feature, understand_code, security_audit, generate_spec). Will error. |
| 17 | **P2** | **MCP `drift_status` doesn't query file count or pattern count** | Returns `fileCount: 0, patternCount: 0` always. Should query `count_files()` and detection counts. |
| 18 | **P2** | **MCP `drift_scan` doesn't return pattern/violation counts** | Returns `patternsDetected: 0` always. Should run analyze after scan. |
| 19 | **P2** | **CI agent `call_graph` and `boundaries` passes call async NAPI as sync** | `napi.drift_call_graph()` and `napi.drift_boundaries()` return Promises but CI agent doesn't await them properly in the pass result. |
| 20 | **P2** | **No workspace-level `package.json` or build orchestration** | 6 TS packages with no root workspace config, no `npm workspaces`, no build order. |
| 21 | **P2** | **Docker setup incomplete** | `docker/Dockerfile` and `docker-compose.yml` exist but reference unclear build targets. |
| 22 | **P2** | **Cortex TS tools not exposed via MCP** | 40 Cortex tools exist in `packages/cortex/src/tools/` but no MCP entry point for Cortex memory operations. |
| 23 | **P2** | **CLI `impact` passes `functionId` where Rust expects `root` path** | `impact.ts` calls `drift_impact_analysis(functionId)` but Rust expects a project root directory path. Wrong argument semantics. |
| 24 | **P2** | **CLI `patterns` ignores its `[path]` argument** | Accepts `[path]` but calls `napi.drift_patterns()` with no arguments. Path is never used. |
| 25 | **P2** | **MCP `drift_explain` tool has same invalid-intent bug as CLI** | `drift_tool.ts:220` passes arbitrary query string as intent to `drift_context()`. Rust only accepts 5 valid intents. |
| 26 | **P2** | **MCP `drift_security_summary` and `drift_owasp` are duplicates** | Both call `drift_owasp_analysis()` with identical parameters. Redundant tools in catalog. |
| 27 | **P2** | **Cortex bridge has 20 NAPI-ready functions without `#[napi]` wrappers** | `cortex-drift-bridge/src/napi/functions.rs` has 20 functions but no cortex-drift-napi crate wraps them with `#[napi]` macros. |
| 28 | **P3** | **`drift_patterns()` returns empty when no category filter** | Code has `Ok(Vec::new())` fallback when no category specified. Should query all detections. |
| 29 | **P3** | **`drift_call_graph()` returns hardcoded `entry_points: 0`** | Queries function/edge counts from DB but doesn't compute entry points. |
| 30 | **P3** | **`drift_decomposition()` uses coupling metrics as proxy** | No real module decomposition — reuses coupling data. |
| 31 | **P3** | **Graph NAPI functions do raw SQL instead of using query modules** | `drift_taint_analysis`, `drift_error_handling`, `drift_impact_analysis`, `drift_test_topology`, `drift_wrapper_detection`, `drift_crypto_analysis` all have inline SQL instead of using `drift_storage::queries::*`. |
| 32 | **P3** | **CI agent `call_graph`/`boundaries` passes store unresolved Promises** | `napi.drift_call_graph()` returns Promise but result is assigned without `await`. Pass always "passes" but `data` is a Promise object, not actual results. |

---

## Layer-by-Layer Audit

### Layer 1: Rust NAPI Bindings (40 functions)

All 40 NAPI functions are implemented and wired to real Rust code. **Zero stubs remain.**

| Module | Functions | Status | Notes |
|--------|-----------|--------|-------|
| `lifecycle.rs` | `driftInitialize`, `driftShutdown`, `driftIsInitialized`, `driftGC` | ✅ Real | 4 functions. `driftGC` **missing from TS interface** (accepts short/medium/long_days retention overrides) |
| `scanner.rs` | `driftScan`, `driftScanWithProgress`, `driftCancelScan` | ✅ Real | Persists file metadata + deletions via BatchWriter |
| `analysis.rs` | `drift_analyze`, `drift_call_graph`, `drift_boundaries` | ✅ Real | `drift_analyze` is the **critical pipeline** — parses, detects, persists detections/functions/boundaries/call edges/patterns/outliers/conventions |
| `patterns.rs` | `drift_patterns`, `drift_confidence`, `drift_outliers`, `drift_conventions` | ✅ Real | Read from DB. `drift_patterns` has empty-result bug when no category. |
| `graph.rs` | `drift_reachability`, `drift_taint_analysis`, `drift_error_handling`, `drift_impact_analysis`, `drift_test_topology` | ✅ Real | All read from DB via raw SQL (should use query modules) |
| `structural.rs` | 9 functions | ✅ Real | `drift_contract_tracking` does live file walking + extraction. Others read from DB. |
| `enforcement.rs` | `drift_check`, `drift_audit`, `drift_violations`, `drift_report`, `drift_gates` | ✅ Real | 5 functions. `drift_report` generates 8 formats. **`drift_report` missing from TS interface.** |
| `feedback.rs` | `drift_dismiss_violation`, `drift_fix_violation`, `drift_suppress_violation` | ✅ Real | Write to DB |
| `advanced.rs` | `drift_simulate`, `drift_decisions`, `drift_context`, `drift_generate_spec` | ✅ Real | Pure computation, no DB dependency |

**Finding: `driftGC` (lifecycle.rs:83-120) exists in Rust but is NOT in the `DriftNapi` interface. Accepts `short_days`, `medium_days`, `long_days` params.**

**Finding: `drift_report` (enforcement.rs:193-328) exists in Rust but is NOT in the `DriftNapi` interface. Accepts `format: String` (sarif/json/html/junit/sonarqube/console/github/gitlab).**

**TS interface declares 38 methods. Rust has 40. Delta = `driftGC` + `drift_report`.**

### Layer 2: NAPI Contracts Package (`packages/drift-napi-contracts/`)

| Component | Status | Notes |
|-----------|--------|-------|
| `interface.ts` — 38 method signatures | ✅ Complete | Missing `driftGC` and `drift_report` |
| `stub.ts` — 38 stub implementations | ✅ Complete | All return structurally valid typed data |
| `loader.ts` — singleton with fallback | ✅ Complete | Validates all 38 functions present |
| `validation.ts` — 6 validators | ✅ Complete | Scan, context, simulate, reachability, root, feedback |
| `types/` — 9 type definition files | ✅ Complete | Scanner, lifecycle, analysis, patterns, graph, structural, enforcement |
| Tests — 6 test files | ✅ Complete | Interface alignment, loader, stub completeness, stub coverage, validation, validation coverage |

**Gaps:**
1. Missing `driftGC` in interface (exists in Rust)
2. Missing `drift_report` in interface (exists in Rust)
3. Validators exist but **no tool handler calls them** — validation is dead code

### Layer 3: MCP Server (`packages/drift-mcp/`)

| Component | Status | Notes |
|-----------|--------|-------|
| 6 entry points registered | ✅ | `drift_status`, `drift_context`, `drift_scan`, `drift_tool`, `drift_discover`, `drift_workflow` |
| 37 internal tools in catalog | ✅ | All wired to NAPI calls (2 duplicates: `drift_security_summary` = `drift_owasp`) |
| Infrastructure layer (7 modules) | ⚠️ Built but unused | Cache, rate limiter, token estimator, error handler, cursor manager, response builder, tool filter — instantiated but never passed to handlers |
| stdio transport | ✅ | Works via `@modelcontextprotocol/sdk` |
| HTTP transport | ⚠️ Incomplete | Transport created but no HTTP server started |
| Tests — 17 test files | ✅ | In `tests/` directory |

**Critical MCP Gaps:**
1. **`drift_scan` only scans, doesn't analyze** — agent gets file counts but zero analysis data
2. **`drift_status` returns `fileCount: 0, patternCount: 0`** — never queries DB
3. **No `drift_report` tool** — 8-format report generation inaccessible
4. **No `driftGC` tool** — garbage collection inaccessible
5. **Infrastructure layer dead code** — cache/rate limiter/token estimator never used
6. **No Cortex tools exposed** — 40 Cortex memory tools exist but aren't in MCP catalog
7. **`drift_explain` passes arbitrary string as intent** — same invalid-intent bug as CLI `explain`
8. **`drift_security_summary` duplicates `drift_owasp`** — both call `drift_owasp_analysis()` identically

### Layer 4: CLI (`packages/drift-cli/`)

| Command | NAPI Call | Status | Issue |
|---------|-----------|--------|-------|
| `scan` | `driftScan()` | ✅ Works | Only persists file metadata, not analysis |
| `check` | `drift_check()` | ⚠️ Empty | Reads violations from DB but nothing writes them |
| `status` | `drift_audit()` + `drift_violations()` | ⚠️ Empty | Same — no data in DB |
| `patterns` | `drift_patterns()` | ⚠️ Empty | No data + empty-result bug when no category + ignores `[path]` argument |
| `violations` | `drift_violations()` | ⚠️ Empty | No data in violations table |
| `impact` | `drift_impact_analysis()` | ⚠️ Broken | Passes `functionId` arg where Rust expects `root` directory path |
| `simulate` | `drift_simulate()` | ⚠️ Broken | Passes `'general'` as category — Rust rejects it |
| `audit` | `drift_audit()` | ⚠️ Empty | No data |
| `setup` | File creation | ✅ Works | But doesn't trigger scan+analyze |
| `doctor` | Health checks | ✅ Works | Checks drift.toml, .drift dir, drift.db, Node.js, NAPI |
| `export` | `drift_violations()` | ⚠️ Empty | No data |
| `explain` | `drift_context()` | ⚠️ Broken | Passes invalid intent `explain_violation:${id}` |
| `fix` | `drift_fix_violation()` | ✅ Works | Writes to DB correctly |

**Missing CLI Commands:**
1. **`drift analyze`** — THE critical missing command. Must call `drift_analyze()`.
2. **`drift report`** — Should call `drift_report(format)` for SARIF/JSON/HTML/JUnit/etc.
3. **`drift security`** — Should call `drift_owasp_analysis()` + `drift_crypto_analysis()`
4. **`drift contracts`** — Should call `drift_contract_tracking()`
5. **`drift coupling`** — Should call `drift_coupling_analysis()`
6. **`drift dna`** — Should call `drift_dna_analysis()`
7. **`drift context`** — Should call `drift_context()` with proper intents
8. **`drift dismiss`** — Should call `drift_dismiss_violation()`
9. **`drift suppress`** — Should call `drift_suppress_violation()`
10. **`drift gc`** — Should call `driftGC()`

### Layer 5: CI Agent (`packages/drift-ci/`)

| Pass | NAPI Call | Status | Issue |
|------|-----------|--------|-------|
| `scan` | `driftScan()` | ⚠️ Partial | Only file metadata, no analysis |
| `patterns` | `drift_patterns()` | ⚠️ Empty | No data + empty-result bug |
| `call_graph` | `drift_call_graph()` | ⚠️ Async issue | Returns Promise, not awaited correctly |
| `boundaries` | `drift_boundaries()` | ⚠️ Async issue | Returns Promise, not awaited correctly |
| `security` | `drift_owasp_analysis()` | ⚠️ Empty | No violations in DB |
| `tests` | `drift_test_topology()` | ⚠️ Empty | No test quality data |
| `errors` | `drift_error_handling()` | ⚠️ Empty | No error gaps data |
| `contracts` | `drift_contract_tracking()` | ✅ Works | Does live file walking |
| `constraints` | `drift_constraint_verification()` | ⚠️ Empty | No constraints defined |

**Critical CI Gaps:**
1. **No `drift_analyze()` call** — scan pass should trigger full analysis
2. **Async/await bugs** — `call_graph` and `boundaries` passes don't await Promises
3. **No enforcement pass** — should run `drift_check()` after analysis
4. **SARIF output reads empty violations** — nothing populates the violations table

### Layer 6: Native Binary Distribution

| Component | Status | Notes |
|-----------|--------|-------|
| `cargo build` for drift-napi | ✅ Compiles | `napi-rs` generates `.node` binary |
| Platform binaries (macOS/Linux/Windows) | ❌ Missing | No `napi build` script, no `@napi-rs/cli`, no platform matrix |
| npm publish pipeline | ❌ Missing | No `prepublishOnly` script, no platform-specific packages |
| `require('drift-napi')` resolution | ❌ Fails | No published `drift-napi` package → always falls back to stub |

**This is the root cause of why everything returns empty in production: the native binary is never loaded, so all calls go to the stub which returns empty data.**

### Layer 7: Cortex Integration

| Component | Status | Notes |
|-----------|--------|-------|
| Cortex Rust crates (14 crates) | ✅ Hardened | All 6 phases complete, 81 E2E tests |
| Cortex NAPI bindings | ✅ Wired | `cortex-napi/src/bindings/` |
| Cortex TS bridge | ✅ Wired | `packages/cortex/src/bridge/` |
| Cortex TS tools (40 tools) | ✅ Built | `packages/cortex/src/tools/` |
| Cortex → MCP exposure | ❌ Missing | No MCP entry point for Cortex operations |
| Cortex → CLI exposure | ❌ Missing | No CLI commands for Cortex |
| Cortex-Drift bridge (20 functions) | ✅ Built | `cortex-drift-bridge/src/napi/functions.rs` — bridge_status, ground_memory, ground_all, grounding_history, translate_link, translate_constraint_link, event_mappings, groundability, license_check, intents, adaptive_weights, spec_correction, contract_verified, decomposition_adjusted, explain_spec, counterfactual, intervention, health, unified_narrative, prune_causal |
| Cortex-Drift bridge → NAPI wrappers | ❌ Missing | Functions are NAPI-ready but no crate wraps them with `#[napi]` macros |

---

## Hardening Completion Status

Cross-reference of all hardening efforts and their current status:

| Hardening | Doc | Status | Impact on This Audit |
|-----------|-----|--------|---------------------|
| **Pattern Intelligence** | `PATTERN-INTELLIGENCE-HARDENING-TASKS.md` | ✅ All 5 phases complete | 195 tests. Confidence, aggregation, outliers, learning, pipeline all hardened. NAPI bindings wired to storage queries. |
| **Enforcement Engine** | `ENFORCEMENT-ENGINE-HARDENING-TASKS.md` | ✅ All 5 phases complete | Gates, rules, reporters, feedback, NAPI all hardened. `drift_report()` added. 16 new tests. |
| **Contract Extraction** | `CONTRACT-EXTRACTION-HARDENING-TASKS.md` | ✅ All 5 phases complete | All 10 extractors, 4 schema parsers, field extraction, breaking changes, NAPI wiring. 1,808 tests pass. |
| **Call Graph & Graph Intelligence** | `CALL-GRAPH-AND-GRAPH-INTELLIGENCE-HARDENING-TASKS.md` | ✅ All 5 phases complete | Resolution, entry points, taint, impact, coupling, integration. 74 test tasks. |
| **Cortex Memory System** | `CORTEX-HARDENING-TASKS.md` | ✅ All 6 phases complete | Persistence, connections, engines, embeddings, TS tools, observability. 81 E2E tests. |
| **Detector Parity** | `DETECTOR-PARITY-HARDENING-TASKS.md` | ❌ Not started | Parser extraction (imports, exports, decorators, qualified names) needed for call graph resolution in production. 6 phases, ~50 tasks. |
| **Storage** | `STORAGE-HARDENING-TASKS.md` | ❌ Not started | Scan→storage pipeline wiring, NAPI stub replacement, missing query modules. 5 phases, 90 tasks. |
| **Presentation Layer** | `PRESENTATION-LAYER-HARDENING-TASKS.md` | ❌ Not started | MCP/CLI/CI fixes. 5 phases, 263 tasks. **This audit supersedes/refines it.** |

**Key dependency:** Detector Parity Phase A (parser extraction) is a prerequisite for call graph resolution to work in production. Without it, cross-file edges are limited to same-file and fuzzy matching.

---

## Full NAPI → Interface Coverage Matrix

Every Rust `#[napi]` function mapped to its exposure in TS contracts, MCP, CLI, and CI:

| # | Rust NAPI Function | TS Contracts | MCP Tool(s) | CLI Command | CI Pass |
|---|-------------------|-------------|-------------|-------------|--------|
| 1 | `driftInitialize` | ✅ | ✅ (server.ts) | ✅ (setup, index.ts) | ✅ (index.ts) |
| 2 | `driftShutdown` | ✅ | ✅ (server.ts) | ✅ (index.ts) | ✅ (index.ts) |
| 3 | `driftIsInitialized` | ✅ | ✅ (drift_status) | ✅ (doctor) | ❌ |
| 4 | **`driftGC`** | **❌ MISSING** | **❌** | **❌** | **❌** |
| 5 | `driftScan` | ✅ | ✅ (drift_scan) | ✅ (scan) | ✅ (scan pass) |
| 6 | `driftScanWithProgress` | ✅ | ✅ (drift_scan_progress) | ❌ | ❌ |
| 7 | `driftCancelScan` | ✅ | ✅ (drift_cancel_scan) | ❌ | ❌ |
| 8 | `drift_analyze` | ✅ | **❌ NOT CALLED** | **❌ NO COMMAND** | **❌ NOT CALLED** |
| 9 | `drift_call_graph` | ✅ | ✅ (drift_callers) | ❌ | ⚠️ (no await) |
| 10 | `drift_boundaries` | ✅ | ❌ | ❌ | ⚠️ (no await) |
| 11 | `drift_patterns` | ✅ | ✅ (drift_patterns_list, drift_similar) | ✅ (patterns) | ✅ (patterns pass) |
| 12 | `drift_confidence` | ✅ | ❌ | ❌ | ❌ |
| 13 | `drift_outliers` | ✅ | ✅ (drift_outliers) | ❌ | ❌ |
| 14 | `drift_conventions` | ✅ | ✅ (drift_conventions) | ❌ | ❌ |
| 15 | `drift_reachability` | ✅ | ✅ (drift_reachability) | ❌ | ❌ |
| 16 | `drift_taint_analysis` | ✅ | ✅ (drift_taint) | ❌ | ❌ |
| 17 | `drift_error_handling` | ✅ | ✅ (drift_error_handling) | ❌ | ✅ (errors pass) |
| 18 | `drift_impact_analysis` | ✅ | ✅ (drift_impact_analysis) | ⚠️ (wrong arg) | ❌ |
| 19 | `drift_test_topology` | ✅ | ✅ (drift_test_topology) | ❌ | ✅ (tests pass) |
| 20 | `drift_coupling_analysis` | ✅ | ✅ (drift_coupling) | ❌ | ❌ |
| 21 | `drift_constraint_verification` | ✅ | ✅ (drift_constraints) | ❌ | ✅ (constraints pass) |
| 22 | `drift_contract_tracking` | ✅ | ✅ (drift_contracts) | ❌ | ✅ (contracts pass) |
| 23 | `drift_constants_analysis` | ✅ | ✅ (drift_constants) | ❌ | ❌ |
| 24 | `drift_wrapper_detection` | ✅ | ✅ (drift_wrappers) | ❌ | ❌ |
| 25 | `drift_dna_analysis` | ✅ | ✅ (drift_dna_profile) | ❌ | ❌ |
| 26 | `drift_owasp_analysis` | ✅ | ✅ (drift_owasp, drift_security_summary) | ❌ | ✅ (security pass) |
| 27 | `drift_crypto_analysis` | ✅ | ✅ (drift_crypto) | ❌ | ❌ |
| 28 | `drift_decomposition` | ✅ | ✅ (drift_decomposition) | ❌ | ❌ |
| 29 | `drift_check` | ✅ | ✅ (drift_prevalidate, drift_validate_change) | ✅ (check) | ❌ |
| 30 | `drift_audit` | ✅ | ✅ (drift_audit, drift_trends) | ✅ (audit, status) | ❌ |
| 31 | `drift_violations` | ✅ | ✅ (drift_suggest_changes) | ✅ (violations, status, export) | ❌ |
| 32 | **`drift_report`** | **❌ MISSING** | **❌** | **❌** | **❌** |
| 33 | `drift_gates` | ✅ | ✅ (drift_quality_gate) | ❌ | ❌ |
| 34 | `drift_dismiss_violation` | ✅ | ✅ (drift_dismiss) | ❌ | ❌ |
| 35 | `drift_fix_violation` | ✅ | ✅ (drift_fix) | ✅ (fix) | ❌ |
| 36 | `drift_suppress_violation` | ✅ | ✅ (drift_suppress) | ❌ | ❌ |
| 37 | `drift_simulate` | ✅ | ✅ (drift_simulate) | ⚠️ (bad category) | ❌ |
| 38 | `drift_decisions` | ✅ | ✅ (drift_decisions) | ❌ | ❌ |
| 39 | `drift_context` | ✅ | ✅ (drift_context entry) | ⚠️ (explain—bad intent) | ❌ |
| 40 | `drift_generate_spec` | ✅ | ✅ (drift_generate_spec) | ❌ | ❌ |

**Coverage summary:**
- **TS Contracts:** 38/40 (missing `driftGC`, `drift_report`)
- **MCP:** 35/40 exposed (missing `driftGC`, `drift_report`, `drift_analyze`, `drift_boundaries`, `drift_confidence`)
- **CLI:** 13/40 exposed (3 broken: `impact`, `simulate`, `explain`)
- **CI:** 9/40 exposed (2 have async bugs: `call_graph`, `boundaries`)

---

## The Critical Path: What Blocks Everything

```
                    ┌─────────────────────┐
                    │  Native Binary Build │  ← P0: Without this, stub returns empty
                    │  (napi-rs platform)  │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │  drift analyze      │  ← P0: Without this, DB is empty
                    │  (CLI + MCP + CI)   │
                    └──────────┬──────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
    ┌─────────▼──────┐ ┌──────▼──────┐ ┌───────▼──────┐
    │  CLI commands   │ │  MCP tools  │ │  CI passes   │
    │  read real data │ │  return data│ │  find issues │
    └────────────────┘ └─────────────┘ └──────────────┘
```

---

## Implementation Plan

### Phase 1: Native Binary Build Pipeline (P0, 2-3 days)

**Goal:** `loadNapi()` loads real Rust binary instead of falling back to stub.

| # | Task | File(s) | Details |
|---|------|---------|---------|
| 1.1 | Add `@napi-rs/cli` to drift-napi | `crates/drift/drift-napi/Cargo.toml`, new `package.json` | Configure napi-rs build with `napi build --platform` |
| 1.2 | Create `napi build` script | `crates/drift/drift-napi/package.json` | `"build": "napi build --release"` |
| 1.3 | Create platform-specific npm packages | `npm/darwin-arm64/`, `npm/darwin-x64/`, `npm/linux-x64-gnu/` | Standard napi-rs platform package layout |
| 1.4 | Wire `drift-napi` as dependency in contracts loader | `packages/drift-napi-contracts/src/loader.ts` | Ensure `require('drift-napi')` resolves to built binary |
| 1.5 | Add workspace-level build orchestration | Root `package.json` | `npm workspaces` config, build order: napi → contracts → mcp/cli/ci |
| 1.6 | Verify: `loadNapi()` returns real binary, not stub | Integration test | Call `driftInitialize()` + `driftIsInitialized()` → true |

**Quality Gate:** `loadNapi().driftIsInitialized()` returns `true` after `driftInitialize()`.

### Phase 2: The Analyze Pipeline (P0, 2-3 days)

**Goal:** `drift analyze` populates the DB so all downstream queries return real data.

| # | Task | File(s) | Details |
|---|------|---------|---------|
| 2.1 | Add `analyze` CLI command | `packages/drift-cli/src/commands/analyze.ts` | Calls `drift_analyze()`, displays results |
| 2.2 | Register `analyze` in CLI index | `packages/drift-cli/src/commands/index.ts` | Import + register |
| 2.3 | Wire `drift_scan` MCP to call `drift_analyze()` after scan | `packages/drift-mcp/src/tools/drift_scan.ts` | After `driftScan()`, call `drift_analyze()` |
| 2.4 | Wire CI `scan` pass to call `drift_analyze()` after scan | `packages/drift-ci/src/agent.ts` | In scan pass, add `await napi.drift_analyze()` |
| 2.5 | Add `drift_report` to NAPI contracts | `packages/drift-napi-contracts/src/interface.ts` | Add method signature |
| 2.6 | Add `driftGC` to NAPI contracts | `packages/drift-napi-contracts/src/interface.ts` | Add method signature |
| 2.7 | Update stub with `drift_report` + `driftGC` | `packages/drift-napi-contracts/src/stub.ts` | Add stub implementations |
| 2.8 | Update method count + names array | `packages/drift-napi-contracts/src/interface.ts` | 38 → 40 |

**Quality Gate:** `drift scan . && drift analyze` → `drift violations .` returns real violations.

### Phase 3: Fix Broken CLI Commands (P1, 1-2 days)

**Goal:** All 13 existing CLI commands work correctly.

| # | Task | File(s) | Details |
|---|------|---------|---------|
| 3.1 | Fix `simulate` — use valid category | `packages/drift-cli/src/commands/simulate.ts` | Parse task description to infer category, or accept `--category` flag |
| 3.2 | Fix `explain` — use valid intent | `packages/drift-cli/src/commands/explain.ts` | Use `understand_code` intent + pass violation context as `dataJson` |
| 3.3 | Fix `impact` — pass root path not functionId | `packages/drift-cli/src/commands/impact.ts` | Change arg semantics or add `--function` flag for function-level impact |
| 3.4 | Fix `patterns` — use path argument | `packages/drift-cli/src/commands/patterns.ts` | Pass `path` to NAPI call or remove unused `[path]` arg |
| 3.5 | Fix `setup` — run scan+analyze after init | `packages/drift-cli/src/commands/setup.ts` | After creating config, offer to run initial scan+analyze |
| 3.6 | Fix `check` — run analyze if DB empty | `packages/drift-cli/src/commands/check.ts` | Detect empty DB, suggest running `drift analyze` first |
| 3.7 | Fix `export` — add SARIF format via `drift_report` | `packages/drift-cli/src/commands/export.ts` | When format=sarif, call `drift_report('sarif')` |

**Quality Gate:** All 13 CLI commands produce meaningful output on a real project.

### Phase 4: Add Missing CLI Commands (P1, 2-3 days)

**Goal:** Every NAPI capability accessible via CLI.

| # | Task | File(s) | Details |
|---|------|---------|---------|
| 4.1 | `drift report` command | `commands/report.ts` | `--format sarif\|json\|html\|junit\|sonarqube\|console\|github\|gitlab` |
| 4.2 | `drift security` command | `commands/security.ts` | Calls `drift_owasp_analysis()` + `drift_crypto_analysis()` |
| 4.3 | `drift contracts` command | `commands/contracts.ts` | Calls `drift_contract_tracking()` |
| 4.4 | `drift coupling` command | `commands/coupling.ts` | Calls `drift_coupling_analysis()` |
| 4.5 | `drift dna` command | `commands/dna.ts` | Calls `drift_dna_analysis()` |
| 4.6 | `drift context` command | `commands/context.ts` | `--intent fix_bug\|add_feature\|understand_code\|security_audit\|generate_spec --depth overview\|standard\|deep` |
| 4.7 | `drift dismiss` command | `commands/dismiss.ts` | `drift dismiss <violationId> --reason "..."` |
| 4.8 | `drift suppress` command | `commands/suppress.ts` | `drift suppress <violationId> --reason "..."` |
| 4.9 | `drift gc` command | `commands/gc.ts` | Calls `driftGC()` with optional retention overrides |
| 4.10 | `drift taint` command | `commands/taint.ts` | Calls `drift_taint_analysis()` |
| 4.11 | `drift test-quality` command | `commands/test_quality.ts` | Calls `drift_test_topology()` |
| 4.12 | `drift errors` command | `commands/errors.ts` | Calls `drift_error_handling()` |
| 4.13 | Register all new commands | `commands/index.ts` | Import + register all |

**Quality Gate:** `drift --help` shows all commands. Each produces output on a real project.

### Phase 5: Fix MCP Server (P1, 2-3 days)

**Goal:** Agent gets real data from every MCP tool.

| # | Task | File(s) | Details |
|---|------|---------|---------|
| 5.1 | Fix `drift_status` — query real counts | `tools/drift_status.ts` | Query `count_files()`, detection count, pattern count from DB |
| 5.2 | Fix `drift_scan` — run analyze after scan | `tools/drift_scan.ts` | Call `drift_analyze()` after `driftScan()`, return real counts |
| 5.3 | Add `drift_report` internal tool | `tools/drift_tool.ts` | Wire to `drift_report(format)` |
| 5.4 | Add `drift_gc` internal tool | `tools/drift_tool.ts` | Wire to `driftGC()` |
| 5.5 | Wire infrastructure layer to tool handlers | `tools/drift_tool.ts`, all handlers | Pass `InfrastructureLayer` to handlers, use cache/rate limiter/token estimator |
| 5.6 | Add `drift_analyze` internal tool | `tools/drift_tool.ts` | Separate from scan — allows re-analysis without re-scanning |
| 5.7 | Fix HTTP transport | `transport/http.ts` | Start actual HTTP server with express or node:http |
| 5.8 | Add Cortex tools to MCP catalog | `tools/drift_tool.ts` | Expose key Cortex operations (memory search, store, link, gc) |

**Quality Gate:** MCP agent can scan → analyze → query all 30+ tools with real data.

### Phase 6: Fix CI Agent (P1, 1-2 days)

**Goal:** CI pipeline produces real analysis results.

| # | Task | File(s) | Details |
|---|------|---------|---------|
| 6.1 | Add `drift_analyze()` call after scan | `src/agent.ts` | In scan pass, call `await napi.drift_analyze()` |
| 6.2 | Fix async/await in call_graph pass | `src/agent.ts` | `await napi.drift_call_graph()` |
| 6.3 | Fix async/await in boundaries pass | `src/agent.ts` | `await napi.drift_boundaries()` |
| 6.4 | Add enforcement pass | `src/agent.ts` | New pass calling `drift_check()` after analysis |
| 6.5 | Fix SARIF output | `src/index.ts` | Call `drift_report('sarif')` instead of manual violation conversion |
| 6.6 | Add `drift_analyze` pass | `src/agent.ts` | Separate analysis pass that runs after scan |

**Quality Gate:** `drift-ci analyze --path .` produces real SARIF with violations.

### Phase 7: Rust NAPI Bug Fixes (P2, 1-2 days)

**Goal:** Fix data quality issues in NAPI layer.

| # | Task | File(s) | Details |
|---|------|---------|---------|
| 7.1 | Fix `drift_patterns()` empty result | `bindings/patterns.rs` | Query all detections when no category filter |
| 7.2 | Fix `drift_call_graph()` entry_points | `bindings/analysis.rs` | Compute entry points from stored data |
| 7.3 | Move inline SQL to query modules | `bindings/graph.rs` | Use `drift_storage::queries::*` instead of raw SQL |
| 7.4 | Fix `drift_status` MCP to query file count | `drift_status.ts` | Add `count_files` query |
| 7.5 | Add `drift_report` + `driftGC` to contracts | `interface.ts`, `stub.ts` | Update to 40 methods |

**Quality Gate:** All NAPI functions return correct, non-empty data after analysis.

### Phase 8: Build & Distribution (P2, 2-3 days)

**Goal:** Users can `npm install @drift/cli` and it works.

| # | Task | File(s) | Details |
|---|------|---------|---------|
| 8.1 | Root workspace `package.json` | Root `package.json` | `"workspaces": ["packages/*"]` |
| 8.2 | Build order script | Root `package.json` | `napi build` → `contracts build` → `mcp/cli/ci build` |
| 8.3 | Platform binary CI | `.github/workflows/build.yml` | Build napi binary for macOS arm64/x64, Linux x64, Windows x64 |
| 8.4 | npm publish workflow | `.github/workflows/publish.yml` | Publish all packages to npm |
| 8.5 | Docker image | `docker/Dockerfile` | Multi-stage: Rust build → Node.js runtime |
| 8.6 | MCP server config examples | `docs/mcp-config.md` | Claude Desktop, Cursor, Kiro config examples |

**Quality Gate:** `npm install -g @drift/cli && drift scan . && drift analyze && drift check` works on a fresh machine.

### Phase 9: Integration Testing (P2, 2-3 days)

**Goal:** End-to-end tests proving the full pipeline works.

| # | Task | File(s) | Details |
|---|------|---------|---------|
| 9.1 | CLI E2E test | `packages/drift-cli/tests/e2e.test.ts` | `drift setup` → `drift scan` → `drift analyze` → `drift check` → `drift violations` → `drift export --format sarif` |
| 9.2 | MCP E2E test | `packages/drift-mcp/tests/e2e.test.ts` | Connect via stdio → `drift_scan` → `drift_tool(violations)` → verify non-empty |
| 9.3 | CI E2E test | `packages/drift-ci/tests/e2e.test.ts` | `drift-ci analyze --path ./test-fixtures` → verify SARIF output |
| 9.4 | Cross-interface parity test | `tests/parity.test.ts` | Same project → CLI/MCP/CI produce identical violation counts |
| 9.5 | Stub fallback test | `tests/stub_fallback.test.ts` | Without native binary, all interfaces degrade gracefully |

**Quality Gate:** All E2E tests pass on CI.

---

## Summary Statistics

| Metric | Count |
|--------|-------|
| **Total findings** | **32** (4 P0, 8 P1, 15 P2, 5 P3) |
| **Total implementation tasks** | **64** |
| **Total test tasks** | **5 E2E suites** |
| **P0 tasks (blocks everything)** | **14** (Phase 1 + 2) |
| **P1 tasks (user-facing)** | **32** (Phase 3 + 4 + 5 + 6) |
| **P2 tasks (quality + distribution)** | **18** (Phase 7 + 8 + 9) |
| **Rust NAPI functions** | **40** (TS contracts has 38) |
| **MCP tools** | **6 entry points + 37 internal** (35/40 NAPI covered) |
| **CLI commands** | **13** (3 broken, 10+ missing) |
| **CI passes** | **9** (2 async bugs, no analyze call) |
| **Cortex TS tools** | **40** (0 exposed via Drift MCP) |
| **Cortex bridge functions** | **20** (0 wrapped with #[napi]) |
| **Hardening efforts complete** | **5 of 8** |
| **Estimated working days** | **15-21 days** |
| **With 2 engineers** | **10-14 days** |

## Critical Path

```
Phase 1 (2-3d) → Phase 2 (2-3d) → {Phase 3, 4, 5, 6 parallel} (3-4d) → Phase 7 (1-2d) → Phase 8 (2-3d) → Phase 9 (2-3d)
```

**Minimum viable: Phase 1 + 2 = 4-6 days** — after this, `drift scan && drift analyze && drift check` works with real data.

---

## Key File Reference

### Rust NAPI (ground truth)
- `crates/drift/drift-napi/src/bindings/*.rs` — 9 modules, 40 `#[napi]` functions
- `crates/drift/drift-napi/src/runtime.rs` — OnceLock singleton, DatabaseManager, BatchWriter

### TS Contracts (single source of truth)
- `packages/drift-napi-contracts/src/interface.ts` — 38 method signatures (should be 40)
- `packages/drift-napi-contracts/src/stub.ts` — fallback implementation
- `packages/drift-napi-contracts/src/loader.ts` — singleton loader

### MCP Server
- `packages/drift-mcp/src/server.ts` — server creation
- `packages/drift-mcp/src/tools/drift_tool.ts` — 37 internal tools (2 duplicates)
- `packages/drift-mcp/src/tools/index.ts` — 6 entry points
- `packages/drift-mcp/src/infrastructure/index.ts` — 7 infrastructure modules (unused)

### CLI
- `packages/drift-cli/src/commands/*.ts` — 13 commands
- `packages/drift-cli/src/output/*.ts` — table, json, sarif formatters

### CI
- `packages/drift-ci/src/agent.ts` — 9 parallel passes
- `packages/drift-ci/src/pr_comment.ts` — PR comment generation
- `packages/drift-ci/src/sarif_upload.ts` — SARIF file writing + GitHub upload

### Storage
- `crates/drift/drift-storage/` — 39 tables, batch writer, read pool, retention
- `crates/drift/drift-analysis/` — all analysis engines

### Cortex
- `crates/cortex/` — 14 Rust crates, all hardened
- `packages/cortex/src/tools/` — 40 TS tools
- `crates/cortex-drift-bridge/` — Cortex↔Drift integration
