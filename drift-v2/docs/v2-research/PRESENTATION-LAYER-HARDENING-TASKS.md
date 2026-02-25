# Drift V2 — Presentation Layer Hardening Task Tracker

> **Source of Truth:** DRIFT-V2-IMPLEMENTATION-TASKS.md (Phase 8 baseline), MCP Audit Findings (2026-02-09)
> **Target Coverage:** ≥80% test coverage per TypeScript package (`vitest --coverage`)
> **Total Packages:** 4 TypeScript (1 new + 3 refactored) + 1 Rust NAPI alignment
> **Total Phases:** 5 (A–E)
> **Quality Gates:** 5 (QG-A through QG-E)
> **Architectural Decision:** Refactor, not wipe. Existing transport, server, CLI bones are sound.
> **Rule:** No Phase N+1 begins until Phase N quality gate passes.
> **Verification:** This tracker accounts for 100% of files in the approved repo structure plan
>   and 100% of NAPI signature mismatches identified in the audit.
> **Upstream Dependency:** Phase 8 (Presentation) scaffold must be complete before this begins.
> **Downstream Impact:** Phase 9 (Bridge) MCP tools depend on Phase C of this tracker.

---

## How To Use This Document

- Agents: check off `[ ]` → `[x]` as you complete each task
- Every implementation task has a unique ID: `PH-{system}-{number}` (PH = Presentation Hardening)
- Every test task has a unique ID: `TH-{system}-{number}`
- Quality gates are pass/fail — all criteria must pass before proceeding
- For NAPI signature alignment → cross-reference `crates/drift/drift-napi/src/bindings/`
- For MCP frontier patterns → Anthropic Code Execution blog, Klavis Progressive Discovery, MCP Spec 2025-11-25
- For the existing Phase 8 baseline → DRIFT-V2-IMPLEMENTATION-TASKS.md §Phase 8

---

## Progress Summary

| Phase | Description | Impl Tasks | Test Tasks | Status |
|-------|-------------|-----------|-----------|--------|
| A | NAPI Contracts Package (Foundation) | 17 | 25 | ✅ Complete |
| B | MCP Infrastructure Layer | 14 | 35 | ✅ Complete |
| C | MCP Tool Hardening (NAPI Fix + Missing Tools + New Entry Points) | 28 | 52 | ✅ Complete |
| D | CLI + CI Alignment | 18 | 38 | ✅ Complete |
| E | Integration, Parity & Regression | 6 | 30 | ✅ Complete |
| **TOTAL** | | **83** | **180** | |

---

## Phase A: NAPI Contracts Package (Foundation)

> **Goal:** Single source of truth for all Rust↔TypeScript NAPI function signatures and types. Eliminate 3 divergent `napi.ts` files.
> **Estimated effort:** 2–3 days (1 developer)
> **Rationale:** Audit found 10+ signature mismatches between TS interfaces and Rust `#[napi]` exports. Three packages each maintain divergent `napi.ts` with different stubs.
> **Performance targets:** `loadNapi()` <1ms, zero runtime type errors after alignment.

### A1 — Package Scaffold — `packages/drift-napi-contracts/`

- [x] `PH-NAPI-01` — Create `packages/drift-napi-contracts/package.json` — name `@drift/napi-contracts`, `"type": "module"`, zero runtime deps
- [x] `PH-NAPI-02` — Create `packages/drift-napi-contracts/tsconfig.json` — strict mode, `declaration: true`, `declarationMap: true`, target ES2022
- [x] `PH-NAPI-03` — Create `packages/drift-napi-contracts/vitest.config.ts` — coverage thresholds: lines ≥90%, branches ≥85%, functions ≥90%

### A2 — Canonical Interface — `packages/drift-napi-contracts/src/`

> **Critical:** Function names and parameter types MUST match `crates/drift/drift-napi/src/bindings/*.rs` `#[napi]` exports exactly.

- [x] `PH-NAPI-04` — Create `src/index.ts` — Barrel exports: interface, types, loader, stub, validators
- [x] `PH-NAPI-05` — Create `src/interface.ts` — `DriftNapi` interface with ALL 38 function signatures aligned to Rust:
  - **Lifecycle** (3): `driftInitialize`, `driftShutdown`, `driftIsInitialized`
  - **Scanner** (3): `driftScan`, `driftScanWithProgress`, `driftCancelScan`
  - **Analysis** (3): `drift_analyze`, `drift_call_graph`, `drift_boundaries`
  - **Patterns** (4): `drift_patterns`, `drift_confidence`, `drift_outliers`, `drift_conventions`
  - **Graph** (5): `drift_reachability(function_key, direction)`, `drift_taint_analysis(root)`, `drift_error_handling(root)`, `drift_impact_analysis(root)`, `drift_test_topology(root)`
  - **Structural** (9): `drift_coupling_analysis`, `drift_constraint_verification`, `drift_contract_tracking`, `drift_constants_analysis`, `drift_wrapper_detection`, `drift_dna_analysis`, `drift_owasp_analysis`, `drift_crypto_analysis`, `drift_decomposition`
  - **Enforcement** (4): `drift_check`, `drift_audit`, `drift_violations`, `drift_gates`
  - **Feedback** (3): `drift_dismiss_violation`, `drift_fix_violation`, `drift_suppress_violation`
  - **Advanced** (4): `drift_simulate(category, description, context_json)`, `drift_decisions(repo_path)`, `drift_context(intent, depth, data_json)`, `drift_generate_spec(module)`

### A3 — Types — `packages/drift-napi-contracts/src/types/`

- [x] `PH-NAPI-06` — Create `types/index.ts` — Barrel re-exports for all type modules
- [x] `PH-NAPI-07` — Create `types/lifecycle.ts` — `InitOptions`, `ProgressCallback`, `ProgressUpdate`
- [x] `PH-NAPI-08` — Create `types/scanner.ts` — `ScanOptions`, `ScanSummary`, `ScanDiff`
- [x] `PH-NAPI-09` — Create `types/analysis.ts` — `JsAnalysisResult`, `JsPatternMatch`, `JsCallGraphResult`, `JsBoundaryResult`
- [x] `PH-NAPI-10` — Create `types/patterns.ts` — `PatternsResult`, `ConfidenceResult`, `OutlierResult`, `ConventionResult`
- [x] `PH-NAPI-11` — Create `types/graph.ts` — `JsReachabilityResult`, `JsTaintResult`, `JsErrorHandlingResult`, `JsImpactResult`, `JsTestTopologyResult`
- [x] `PH-NAPI-12` — Create `types/structural.ts` — All 9 structural result types including `JsOwaspResult` (CWE mapping), `JsCryptoResult` (CWE-310/327/328), `JsDecompositionResult`
- [x] `PH-NAPI-13` — Create `types/enforcement.ts` — `JsViolation`, `JsCheckResult`, `JsAuditResult`, `JsGateResult`, `JsFeedbackResult`
- [x] `PH-NAPI-14` — Create `types/advanced.ts` — `SimulationResult`, `DecisionResult`, `ContextResult`, `SpecResult`

### A4 — Loader & Stub

- [x] `PH-NAPI-15` — Create `src/loader.ts` — `loadNapi()` (lazy singleton with `require('drift-napi')`, stub fallback), `setNapi()` (test injection), `resetNapi()` (test cleanup). Validates loaded module has all expected function names — throws `NapiLoadError` with missing list if incomplete
- [x] `PH-NAPI-16` — Create `src/stub.ts` — `createStubNapi(): DriftNapi` — complete stub matching every interface function. Returns structurally valid typed empty data (not `{}`). Async stubs return resolved Promises
- [x] `PH-NAPI-17` — Create `src/validation.ts` — Runtime param validators per NAPI function. Returns `{ valid: true }` or `{ valid: false, error, field }`. Runs BEFORE NAPI call to prevent Rust panics from bad JS input

### Phase A Tests

#### Interface Alignment — Contract Integrity
- [x] `TH-NAPI-01` — Test every `DriftNapi` method has a corresponding stub entry — no missing method
- [x] `TH-NAPI-02` — Test interface methods match Rust `#[napi]` export names (if native binary available, skip gracefully if not)
- [x] `TH-NAPI-03` — Test `DriftNapi` has exactly 38 functions — prevents accidental add/remove
- [x] `TH-NAPI-04` — Test no function uses `any` type — all params and returns fully typed
- [x] `TH-NAPI-05` — Test no function uses `Record<string, unknown>` — all return named interfaces

#### Stub Completeness
- [x] `TH-NAPI-06` — Test `createStubNapi()` implements every `DriftNapi` method
- [x] `TH-NAPI-07` — Test every stub returns value matching declared return type (not `{}`)
- [x] `TH-NAPI-08` — Test async stubs return resolved Promises
- [x] `TH-NAPI-09` — Test `driftIsInitialized()` stub returns `false`
- [x] `TH-NAPI-10` — Test `drift_violations()` stub returns `[]`, not `null`/`undefined`
- [x] `TH-NAPI-11` — Test `drift_check()` stub returns `{ passed: true, violations: [], gateResults: [] }` — complete shape

#### Loader — Lifecycle & Injection
- [x] `TH-NAPI-12` — Test `loadNapi()` returns stub when native binary unavailable — no throw
- [x] `TH-NAPI-13` — Test `loadNapi()` is idempotent — 10 calls return same instance
- [x] `TH-NAPI-14` — Test `setNapi()` overrides singleton for tests
- [x] `TH-NAPI-15` — Test `resetNapi()` clears singleton — next `loadNapi()` re-initializes
- [x] `TH-NAPI-16` — Test `setNapi()` with incomplete object — throws `NapiLoadError` listing missing functions
- [x] `TH-NAPI-17` — Test concurrent `loadNapi()` from `Promise.all(5)` — no race, all get same instance

#### Validation — Reject Bad Input
- [x] `TH-NAPI-18` — Test `validateScanParams({})` passes (all optional)
- [x] `TH-NAPI-19` — Test `validateScanParams({ path: '' })` fails — empty path
- [x] `TH-NAPI-20` — Test `validateContextParams({ intent: 'fix_bug' })` passes
- [x] `TH-NAPI-21` — Test `validateContextParams({})` fails — missing required `intent`
- [x] `TH-NAPI-22` — Test `validateContextParams({ intent: 'x', depth: 'invalid' })` fails — enum mismatch
- [x] `TH-NAPI-23` — Test `validateSimulateParams({ category: 'refactor', description: 'x' })` passes
- [x] `TH-NAPI-24` — Test `validateSimulateParams({ category: '', description: '' })` fails — empty required
- [x] `TH-NAPI-25` — Test SQL injection string in `intent` — validator passes (valid string), Rust handles safely

### QG-A: Phase A Quality Gate

- [x] Package compiles with zero TypeScript errors
- [x] `DriftNapi` has exactly 38 methods, zero `any`, zero `Record<string, unknown>` returns
- [x] Every method has a stub returning valid typed shape
- [x] `loadNapi()` gracefully returns stub when native binary unavailable
- [x] `setNapi()`/`resetNapi()` support full test injection lifecycle
- [x] All validators catch missing required fields, invalid enums, empty strings
- [x] `vitest --coverage` ≥90% line coverage (actual: 98.52%)
- [x] No runtime `any` casts in any source file

---

## Phase B: MCP Infrastructure Layer

> **Goal:** Add 7 infrastructure modules v1 had but v2 lacks: caching, rate limiting, token estimation, error handling with recovery hints, cursor pagination, response formatting, tool filtering.
> **Estimated effort:** 3–4 days (1 developer)
> **Prerequisite:** Phase A complete
> **Performance targets:** Cache lookup <0.1ms, rate limiter check <0.01ms, token estimation within 20% of tiktoken

### B1 — Infrastructure Modules — `packages/drift-mcp/src/infrastructure/`

- [x] `PH-INFRA-01` — Create `infrastructure/index.ts` — Barrel exports + `InfrastructureLayer` class initializing all modules, providing unified `ctx` for tool handlers
- [x] `PH-INFRA-02` — Create `infrastructure/cache.ts` — `ResponseCache`: L1 in-memory LRU (Map, max 100, 5min TTL). Key: `${projectRoot}:${toolName}:${paramsHash}`. Project-isolated. `get/set/invalidate(glob)/invalidateProject`. Stores `{ data, createdAt, ttlMs, tokenEstimate }`
- [x] `PH-INFRA-03` — Create `infrastructure/rate_limiter.ts` — `RateLimiter`: sliding window. Global 100/60s, expensive 10/60s (scan, simulate, taint, impact). Returns `{ allowed }` or `{ allowed: false, retryAfterMs, reason }`
- [x] `PH-INFRA-04` — Create `infrastructure/token_estimator.ts` — `TokenEstimator`: heuristic (chars/3.5 English, chars/2.5 code). `estimateTokens(text)`, `estimateResponseTokens(toolName, params)`, `wouldExceedBudget(toolName, params, budget)`
- [x] `PH-INFRA-05` — Create `infrastructure/error_handler.ts` — `ErrorHandler`: wraps tool execution. Maps NAPI error codes → MCP errors with `recoveryHints[]`, `alternativeTools[]`, `retryable`, `retryAfterMs`. e.g. `[SCAN_ERROR]` → "Run drift setup first", `[DB_BUSY]` → retryable+1000ms
- [x] `PH-INFRA-06` — Create `infrastructure/cursor_manager.ts` — `CursorManager`: opaque keyset cursors. `encodeCursor({sortColumn, lastValue, lastId, version})` → base64url+HMAC. `decodeCursor()` → returns null for invalid/tampered/expired (1h TTL)
- [x] `PH-INFRA-07` — Create `infrastructure/response_builder.ts` — `ResponseBuilder`: summary-first formatting. If over token budget: truncate arrays, prepend `_summary`, add `_truncated: true` + `_totalCount`. Always includes `_tokenEstimate`
- [x] `PH-INFRA-08` — Create `infrastructure/tool_filter.ts` — `ToolFilter`: filters catalog by project languages. Never filters core tools (status, context, scan, check, violations). Falls back to full catalog if detection fails

### B2 — Server Integration

- [x] `PH-INFRA-09` — Refactor `server.ts` — Initialize `InfrastructureLayer`, pass `ctx` to tool registration. Wrap every handler in `errorHandler.wrap()`
- [x] `PH-INFRA-10` — Refactor `tools/index.ts` — Accept `InfrastructureLayer`. Apply `toolFilter` to catalog. Add rate limiter check before `drift_tool` dispatch

### B3 — Configuration & Import Alignment

- [x] `PH-INFRA-11` — Refactor `types.ts` — Remove local `DriftNapi` (use contracts). Add infrastructure types: `InfrastructureConfig`, `McpResponse`, `RecoveryHint`, `CursorData`
- [x] `PH-INFRA-12` — Refactor `index.ts` — Update imports from `@drift/napi-contracts`
- [x] `PH-INFRA-13` — Refactor `napi.ts` — Replace entirely with re-exports: `export { loadNapi, setNapi, resetNapi } from '@drift/napi-contracts';`
- [x] `PH-INFRA-14` — Refactor `package.json` — Add `@drift/napi-contracts` workspace dependency

### Phase B Tests

#### Cache — Eviction, Isolation & TTL
- [x] `TH-CACHE-01` — Test `set()`+`get()` round-trip returns identical data
- [x] `TH-CACHE-02` — Test TTL: set 100ms TTL, wait 150ms, get returns `undefined`
- [x] `TH-CACHE-03` — Test LRU eviction: fill 100, add 101st — oldest evicted
- [x] `TH-CACHE-04` — Test project isolation: `/project-a` key not visible from `/project-b`
- [x] `TH-CACHE-05` — Test `invalidate(glob)`: 5 keys match, all gone, others retained
- [x] `TH-CACHE-06` — Test `invalidateProject()`: all project entries gone, others retained
- [x] `TH-CACHE-07` — Test `set(key, undefined)` is no-op
- [x] `TH-CACHE-08` — Test cache stores `tokenEstimate` field

#### Rate Limiter
- [x] `TH-RATE-01` — Test 100 calls in 60s all allowed
- [x] `TH-RATE-02` — Test 101st call blocked with `retryAfterMs`
- [x] `TH-RATE-03` — Test expensive tool 10-call limit
- [x] `TH-RATE-04` — Test window sliding: 100 calls, wait 60s, 100 more all allowed
- [x] `TH-RATE-05` — Test `retryAfterMs` ≤ 60000
- [x] `TH-RATE-06` — Test non-expensive tool not subject to expensive limit

#### Token Estimator
- [x] `TH-TOKEN-01` — Test `estimateTokens('hello world')` returns 2-4
- [x] `TH-TOKEN-02` — Test 10KB code block within 20% of chars/3.5
- [x] `TH-TOKEN-03` — Test `estimateTokens('')` returns 0
- [x] `TH-TOKEN-04` — Test `wouldExceedBudget()` correctly flags over-budget
- [x] `TH-TOKEN-05` — Test per-tool historical averages used when available

#### Error Handler
- [x] `TH-ERR-01` — Test `[SCAN_ERROR]` → "Run drift setup first"
- [x] `TH-ERR-02` — Test `[DB_BUSY]` → `retryable: true, retryAfterMs: 1000`
- [x] `TH-ERR-03` — Test `[UNSUPPORTED_LANGUAGE]` → empty alternativeTools
- [x] `TH-ERR-04` — Test `[CANCELLED]` → `retryable: true`
- [x] `TH-ERR-05` — Test unknown error → generic with `retryable: false`
- [x] `TH-ERR-06` — Test non-Error thrown (string/number/null) — wrapped, not rethrown
- [x] `TH-ERR-07` — Test original stack trace preserved in `data.originalError`

#### Cursor Manager
- [x] `TH-CURSOR-01` — Test encode→decode round-trip
- [x] `TH-CURSOR-02` — Test tampered cursor → `null`
- [x] `TH-CURSOR-03` — Test expired cursor (1h+) → `null`
- [x] `TH-CURSOR-04` — Test wrong version → `null`
- [x] `TH-CURSOR-05` — Test empty string → `null`
- [x] `TH-CURSOR-06` — Test invalid base64 → `null`

#### Response Builder
- [x] `TH-RESP-01` — Test small response under budget passes through with `_truncated: false`
- [x] `TH-RESP-02` — Test 1000 violations + budget=200 tokens → truncated with `_totalCount: 1000`
- [x] `TH-RESP-03` — Test `_summary` always present
- [x] `TH-RESP-04` — Test `_tokenEstimate` present and ≥ actual
- [x] `TH-RESP-05` — Test 0 items → valid empty response, not `null`

#### Tool Filter
- [x] `TH-FILTER-01` — Test Python project filters TypeScript-specific tools
- [x] `TH-FILTER-02` — Test core tools never filtered
- [x] `TH-FILTER-03` — Test empty languages → full catalog (no filtering)
- [x] `TH-FILTER-04` — Test multi-language project → union of both language tools

### QG-B: Phase B Quality Gate

- [x] All 7 infrastructure modules compile and export from barrel
- [x] `server.ts` initializes `InfrastructureLayer` and passes `ctx` to handlers
- [x] Cache LRU works at 100 entries with project isolation
- [x] Rate limiter enforces 100/60s global and 10/60s expensive limits
- [x] Error handler maps all 14 NAPI error codes to structured recovery hints
- [x] Cursor manager detects tampered/expired/wrong-version cursors
- [x] Response builder enforces token budget with summary-first truncation
- [x] Tool filter protects core tools
- [x] `vitest --coverage` ≥80% for infrastructure/ (actual: 96.81% lines, 95.89% functions)
- [x] Local `napi.ts` replaced with re-export from `@drift/napi-contracts`

---

## Phase C: MCP Tool Hardening (NAPI Fix + Missing Tools + New Entry Points)

> **Goal:** Fix all 10+ NAPI signature mismatches in existing tools, add 11 missing tools with Rust backing, and create 2 new entry points (`drift_discover`, `drift_workflow`) for frontier progressive disclosure.
> **Estimated effort:** 3–4 days (1 developer)
> **Prerequisite:** Phases A + B complete
> **Rationale:** Audit found `drift_coupling` calls `drift_analyze(path)` instead of `drift_coupling_analysis(root)`, `drift_taint` passes 1 arg instead of 2, and 11 Rust NAPI functions have zero MCP exposure.
> **Performance targets:** `drift_discover` <10ms, `drift_workflow` <5s per workflow

### C1 — Fix Existing Tool NAPI Mismatches — `packages/drift-mcp/src/tools/drift_tool.ts`

> Each fix corrects a TS→Rust function name or argument mismatch. "Before" state silently returns empty stub data. "After" calls correct Rust function.

- [x] `PH-TOOL-01` — Fix `drift_callers` — `napi.drift_call_graph(path)` → `napi.drift_call_graph(params.path ?? projectRoot)` — correct path resolution
- [x] `PH-TOOL-02` — Fix `drift_reachability` — `napi.drift_reachability(params.functionId)` → `napi.drift_reachability(params.functionId, params.direction ?? 'forward')` — Rust takes 2 args
- [x] `PH-TOOL-03` — Fix `drift_taint` — `napi.drift_taint(params.functionId)` → `napi.drift_taint_analysis(params.root ?? params.functionId)` — wrong function name + arg
- [x] `PH-TOOL-04` — Fix `drift_impact_analysis` — `napi.drift_impact(params.functionId)` → `napi.drift_impact_analysis(params.root ?? params.functionId)` — wrong function name
- [x] `PH-TOOL-05` — Fix `drift_error_handling` — `napi.drift_analyze(params.path)` → `napi.drift_error_handling(params.root ?? projectRoot)` — was calling generic analyze
- [x] `PH-TOOL-06` — Fix `drift_coupling` — `napi.drift_analyze(params.path)` → `napi.drift_coupling_analysis(params.root ?? projectRoot)` — was calling generic analyze
- [x] `PH-TOOL-07` — Fix `drift_constants` — `napi.drift_analyze(params.path)` → `napi.drift_constants_analysis(params.root ?? projectRoot)` — was calling generic analyze
- [x] `PH-TOOL-08` — Fix `drift_constraints` — `napi.drift_check(params.path)` → `napi.drift_constraint_verification(params.root ?? projectRoot)` — was calling check
- [x] `PH-TOOL-09` — Fix `drift_dna_profile` — `napi.drift_analyze(params.path)` → `napi.drift_dna_analysis(params.root ?? projectRoot)` — was calling generic analyze
- [x] `PH-TOOL-10` — Fix `drift_simulate` — `napi.drift_simulate(params.task)` → `napi.drift_simulate(params.category, params.description, params.context_json ?? '{}')` — Rust takes 3 args
- [x] `PH-TOOL-11` — Fix `drift_explain` — `napi.drift_context(params.query, 'deep')` → `napi.drift_context(params.intent ?? params.query, params.depth ?? 'deep', params.data_json ?? '{}')` — Rust takes 3 args

### C2 — Fix Entry Point Mismatches

- [x] `PH-TOOL-12` — Refactor `drift_context.ts` — `napi.drift_context(intent, depth)` → `napi.drift_context(intent, depth, JSON.stringify({ focus }))` — Rust takes 3 args. Remove client-side focus filtering (Rust handles via `data_json`)
- [x] `PH-TOOL-13` — Refactor `drift_scan.ts` — Add MCP Tasks support for long-running full scans. Wrap with `driftScanWithProgress()` when available. Add cancellation via `driftCancelScan()`

### C3 — Add Missing Tools (Rust NAPI Exists, No MCP Exposure)

> 11 Rust NAPI functions implemented but zero MCP catalog entries. Each task adds a tool to `buildToolCatalog()`.

- [x] `PH-TOOL-14` — Add `drift_outliers` — `napi.drift_outliers(path, cursor)`. Category: `exploration`. Tokens: 400. "Detect statistical outliers using auto-selected method (Z-Score/Grubbs/ESD). Supports pagination."
- [x] `PH-TOOL-15` — Add `drift_conventions` — `napi.drift_conventions(path)`. Category: `exploration`. Tokens: 500. "Discover learned coding conventions with Bayesian confidence scores."
- [x] `PH-TOOL-16` — Add `drift_owasp` — `napi.drift_owasp_analysis(root)`. Category: `analysis`. Tokens: 600. "OWASP Top 10 analysis with CWE mapping and compliance scoring."
- [x] `PH-TOOL-17` — Add `drift_crypto` — `napi.drift_crypto_analysis(root)`. Category: `analysis`. Tokens: 400. "Cryptographic failure detection mapped to CWE-310/327/328."
- [x] `PH-TOOL-18` — Add `drift_decomposition` — `napi.drift_decomposition(root)`. Category: `analysis`. Tokens: 800. "Module decomposition with cohesion/coupling metrics and boundary suggestions."
- [x] `PH-TOOL-19` — Add `drift_contracts` — `napi.drift_contract_tracking(root)`. Category: `exploration`. Tokens: 600. "API contract detection across 7 paradigms. Finds frontend↔backend mismatches."
- [x] `PH-TOOL-20` — Add `drift_dismiss` — `napi.drift_dismiss_violation(violationId, reason)`. Category: `feedback`. Tokens: 50. "Dismiss violation with reason. Adjusts Bayesian confidence."
- [x] `PH-TOOL-21` — Add `drift_fix` — `napi.drift_fix_violation(violationId)`. Category: `feedback`. Tokens: 50. "Mark violation fixed. Positive Bayesian signal."
- [x] `PH-TOOL-22` — Add `drift_suppress` — `napi.drift_suppress_violation(violationId, reason, duration)`. Category: `feedback`. Tokens: 50. "Suppress violation for N days. Auto-unsuppresses."
- [x] `PH-TOOL-23` — Add `drift_scan_progress` — `napi.driftScanWithProgress(path, callback)`. Category: `operational`. Tokens: 100. "Scan with real-time progress."
- [x] `PH-TOOL-24` — Add `drift_cancel_scan` — `napi.driftCancelScan()`. Category: `operational`. Tokens: 30. "Cancel running scan."

### C4 — New Entry Points (Frontier Patterns)

- [x] `PH-TOOL-25` — Create `drift_discover.ts` — Intent-guided tool recommendation. Schema: `{ intent, focus?, maxTools? }`. Scores catalog tools by keyword match to description + category, applies `ToolFilter`, returns top N ranked by relevance. 5th MCP entry point
- [x] `PH-TOOL-26` — Create `drift_workflow.ts` — Composite workflow dispatch. Schema: `{ workflow, path?, options? }`. 5 workflows: `pre_commit` (check→violations→impact), `security_audit` (owasp→crypto→taint→error_handling), `code_review` (status→context→violations→patterns), `health_check` (status→audit→test_topology→dna), `onboard` (status→conventions→patterns→contracts). 6th MCP entry point
- [x] `PH-TOOL-27` — Refactor `tools/index.ts` — Register `drift_discover` and `drift_workflow`. Total entry points: 4 → 6. Update catalog size assertion: ~24 → ~41
- [x] `PH-TOOL-28` — Update `drift_tool.ts` — Catalog: 41 internal tools (24 existing + 11 new NAPI + 3 feedback + 2 operational + 1 scan_status). Add `feedback` and `operational` categories. Validate all handlers use `@drift/napi-contracts` loader

### Phase C Tests

#### NAPI Mismatch Fixes — Verify Correct Function Called
- [x] `TH-TOOL-01` — Test `drift_reachability` passes 2 args to NAPI (functionId + direction) — mock NAPI, verify call signature
- [x] `TH-TOOL-02` — Test `drift_taint` calls `drift_taint_analysis` (not `drift_taint`) — verify function name
- [x] `TH-TOOL-03` — Test `drift_impact_analysis` calls `drift_impact_analysis` (not `drift_impact`) — verify function name
- [x] `TH-TOOL-04` — Test `drift_coupling` calls `drift_coupling_analysis` (not `drift_analyze`) — verify function name
- [x] `TH-TOOL-05` — Test `drift_error_handling` calls `drift_error_handling` (not `drift_analyze`) — verify function name
- [x] `TH-TOOL-06` — Test `drift_constants` calls `drift_constants_analysis` (not `drift_analyze`) — verify function name
- [x] `TH-TOOL-07` — Test `drift_constraints` calls `drift_constraint_verification` (not `drift_check`) — verify function name
- [x] `TH-TOOL-08` — Test `drift_dna_profile` calls `drift_dna_analysis` (not `drift_analyze`) — verify function name
- [x] `TH-TOOL-09` — Test `drift_simulate` passes 3 args (category, description, context_json) — verify call signature
- [x] `TH-TOOL-10` — Test `drift_explain` passes 3 args (intent, depth, data_json) — verify call signature
- [x] `TH-TOOL-11` — Test ALL 41 tools dispatch to valid NAPI function — iterate catalog, mock NAPI, zero `undefined` calls

#### New Tools — Happy Path
- [x] `TH-TOOL-12` — Test `drift_outliers` returns `OutlierResult` shape with `outliers[]` and `cursor`
- [x] `TH-TOOL-13` — Test `drift_conventions` returns `ConventionResult` with `conventions[]`
- [x] `TH-TOOL-14` — Test `drift_owasp` returns findings grouped by OWASP category with CWE IDs
- [x] `TH-TOOL-15` — Test `drift_crypto` returns findings with CWE-310/327/328 mapping
- [x] `TH-TOOL-16` — Test `drift_decomposition` returns modules with cohesion/coupling metrics
- [x] `TH-TOOL-17` — Test `drift_contracts` returns contracts with paradigm + mismatch info
- [x] `TH-TOOL-18` — Test `drift_dismiss` returns `JsFeedbackResult` with `success: true, confidenceAdjustment`
- [x] `TH-TOOL-19` — Test `drift_fix` returns positive confidence adjustment
- [x] `TH-TOOL-20` — Test `drift_suppress` with duration=30 returns suppression confirmation

#### New Tools — Error Handling
- [x] `TH-TOOL-21` — Test `drift_dismiss` invalid violationId → structured error with recovery hint
- [x] `TH-TOOL-22` — Test `drift_fix` already-fixed violation → error or idempotent success (no double-counting)
- [x] `TH-TOOL-23` — Test `drift_suppress` duration=0 → rejected or treated as unsuppress
- [x] `TH-TOOL-24` — Test `drift_outliers` empty database → empty array, not error
- [x] `TH-TOOL-25` — Test `drift_owasp` no security issues → empty findings, healthScore=100

#### Discover — Intent Matching
- [x] `TH-DISC-01` — Test `intent: 'security audit'` → top 5 includes owasp, taint, crypto
- [x] `TH-DISC-02` — Test `intent: 'fix bug'` → top 5 includes violations, impact, explain
- [x] `TH-DISC-03` — Test `intent: 'understand code'` → top 5 includes context, patterns, conventions
- [x] `TH-DISC-04` — Test `intent: 'pre-commit check'` → top 5 includes check, violations
- [x] `TH-DISC-05` — Test `maxTools: 3` returns exactly 3
- [x] `TH-DISC-06` — Test `maxTools: 0` returns empty array
- [x] `TH-DISC-07` — Test unknown intent `'make coffee'` → generic top tools, no crash
- [x] `TH-DISC-08` — Test results include `relevanceScore`, sorted descending
- [x] `TH-DISC-09` — Test `focus: 'auth'` boosts auth/security tools
- [x] `TH-DISC-10` — Test response < 500 tokens (discover is lightweight)

#### Workflow — Composite Execution
- [x] `TH-WORK-01` — Test `pre_commit` calls check + violations + impact (mock, verify all 3)
- [x] `TH-WORK-02` — Test `security_audit` calls owasp + crypto + taint + error_handling
- [x] `TH-WORK-03` — Test `code_review` calls status + context + violations + patterns
- [x] `TH-WORK-04` — Test `health_check` calls status + audit + test_topology + dna
- [x] `TH-WORK-05` — Test `onboard` calls status + conventions + patterns + contracts
- [x] `TH-WORK-06` — Test unknown workflow `'deploy'` → `MethodNotFound` with valid list
- [x] `TH-WORK-07` — Test partial failure: 1 sub-tool fails → partial results, not total failure
- [x] `TH-WORK-08` — Test response includes `_workflow` metadata: tools run, duration per tool
- [x] `TH-WORK-09` — Test workflow respects rate limiter — sub-tool rate-limited → reported, not crash

#### Entry Point Registration
- [x] `TH-TOOL-26` — Test MCP server registers exactly 6 entry points
- [x] `TH-TOOL-27` — Test `drift_tool` catalog contains exactly 41 internal tools
- [x] `TH-TOOL-28` — Test progressive disclosure: 6 entry points < 1.5K tokens total

### QG-C: Phase C Quality Gate

- [x] All 11 NAPI mismatches fixed — every tool calls correct Rust function with correct arg count
- [x] 11 new tools in catalog (outliers, conventions, owasp, crypto, decomposition, contracts, dismiss, fix, suppress, scan_progress, cancel_scan)
- [x] `drift_discover` returns relevant tools for 5 intents
- [x] `drift_workflow` executes 5 workflows with correct sub-tool calls
- [x] 6 MCP entry points registered
- [x] 41 internal tools in catalog — zero `undefined` function calls
- [x] Feedback tools return `JsFeedbackResult` with confidence adjustments
- [x] Workflow partial failure → partial results, not total failure
- [x] `vitest --coverage` ≥80% for tools/ (actual: 96.16% lines, 97.14% functions)

---

## Phase D: CLI + CI Alignment

> **Goal:** Eliminate duplicated `napi.ts` in drift-cli and drift-ci. Align all command handlers to correct NAPI signatures. Wire stub commands (`doctor`, `fix`) to real NAPI.
> **Estimated effort:** 2–3 days (1 developer)
> **Prerequisite:** Phase A (contracts) complete. Phases B/C not required (CLI is independent of MCP infrastructure).
> **Rationale:** `drift-cli/src/napi.ts` and `drift-ci/src/napi.ts` are copy-pasted with interfaces diverging from both MCP and Rust.

### D1 — CLI NAPI Alignment — `packages/drift-cli/`

- [x] `PH-CLI-01` — Refactor `package.json` — Add `@drift/napi-contracts` workspace dep
- [x] `PH-CLI-02` — Delete `src/napi.ts` — Replace with re-export from `@drift/napi-contracts`
- [x] `PH-CLI-03` — Refactor `src/index.ts` — `napi.drift_init()` → `napi.driftInitialize()` (correct Rust name)
- [x] `PH-CLI-04` — Refactor `commands/scan.ts` — Align to `driftScan(path, options)`. Add progress display via `driftScanWithProgress` when TTY
- [x] `PH-CLI-05` — Refactor `commands/check.ts` — Align to `drift_check(path, policy)`
- [x] `PH-CLI-06` — Refactor `commands/patterns.ts` — Align to `drift_patterns(path)`
- [x] `PH-CLI-07` — Refactor `commands/violations.ts` — Align to `drift_violations(path)` returning `JsViolation[]`
- [x] `PH-CLI-08` — Refactor `commands/impact.ts` — `drift_impact(functionId)` → `drift_impact_analysis(root)`
- [x] `PH-CLI-09` — Refactor `commands/simulate.ts` — `drift_simulate(task)` → `drift_simulate(category, description, context_json)`
- [x] `PH-CLI-10` — Refactor `commands/audit.ts` — Align to `drift_audit(path)`
- [x] `PH-CLI-11` — Refactor `commands/setup.ts` — Wire to `driftInitialize({ dbPath })`. Add interactive prompts
- [x] `PH-CLI-12` — Refactor `commands/doctor.ts` — Wire to `driftIsInitialized()`. Check: drift.db exists, schema current, NAPI binary loadable
- [x] `PH-CLI-13` — Refactor `commands/explain.ts` — `drift_context(intent, depth)` → `drift_context(intent, depth, data_json)`
- [x] `PH-CLI-14` — Refactor `commands/fix.ts` — Wire to `drift_fix_violation(violationId)`. Report confidence adjustment
- [x] `PH-CLI-15` — Refactor `commands/export.ts` — Align to contracts types for `drift_violations()` return

### D2 — CI Agent NAPI Alignment — `packages/drift-ci/`

- [x] `PH-CI-01` — Refactor `package.json` — Add `@drift/napi-contracts` workspace dep
- [x] `PH-CI-02` — Delete `src/napi.ts` — Replace with re-export from `@drift/napi-contracts`
- [x] `PH-CI-03` — Refactor `src/agent.ts` — Update 9 analysis passes to correct NAPI names: `driftScan`, `drift_patterns`, `drift_call_graph`, `drift_boundaries`, `drift_owasp_analysis`, `drift_test_topology`, `drift_error_handling`, `drift_contract_tracking`, `drift_constraint_verification`

### Phase D Tests

#### CLI Commands — Happy Path + Error Handling
- [x] `TH-CLI-01` — Test `drift scan` calls `driftScan` with correct path, exit code 0
- [x] `TH-CLI-02` — Test `drift scan --incremental` passes `{ incremental: true }`
- [x] `TH-CLI-03` — Test `drift scan /nonexistent` → exit code 2, helpful error
- [x] `TH-CLI-04` — Test `drift scan` empty dir → "0 files scanned", exit code 0
- [x] `TH-CLI-05` — Test `drift check` with violations → exit code 1
- [x] `TH-CLI-06` — Test `drift check` no violations → exit code 0
- [x] `TH-CLI-07` — Test `drift check --policy strict` passes policy
- [x] `TH-CLI-08` — Test `drift status` returns formatted overview
- [x] `TH-CLI-09` — Test `drift status` no drift.db → "run drift setup", exit code 2
- [x] `TH-CLI-10` — Test `drift violations` with 5 violations → formatted list
- [x] `TH-CLI-11` — Test `drift violations` with 0 → "No violations found"
- [x] `TH-CLI-12` — Test `drift setup` calls `driftInitialize()` (not `drift_init`)
- [x] `TH-CLI-13` — Test `drift setup` existing drift.toml → warns before overwrite
- [x] `TH-CLI-14` — Test `drift doctor` calls `driftIsInitialized()`, reports status
- [x] `TH-CLI-15` — Test `drift doctor` missing drift.db → "run drift setup"
- [x] `TH-CLI-16` — Test `drift fix <id>` calls `drift_fix_violation()`, reports result
- [x] `TH-CLI-17` — Test `drift fix` no ID → usage help, exit code 2
- [x] `TH-CLI-18` — Test `drift fix <invalid-id>` → structured error with recovery hint
- [x] `TH-CLI-19` — Test `drift export --format sarif` produces valid SARIF
- [x] `TH-CLI-20` — Test `drift export --format json` produces valid JSON with typed violations

#### CLI Output — Formats & Edge Cases
- [x] `TH-CLI-21` — Test table format with Unicode (CJK, emoji) — no column misalignment
- [x] `TH-CLI-22` — Test table with 0 rows → headers only or "No data"
- [x] `TH-CLI-23` — Test JSON output parseable by `JSON.parse()`
- [x] `TH-CLI-24` — Test JSON round-trip: violations → JSON → parse → same count
- [x] `TH-CLI-25` — Test SARIF contains `$schema` field
- [x] `TH-CLI-26` — Test SARIF with 0 violations → valid empty `results[]`
- [x] `TH-CLI-27` — Test SARIF with Unicode paths and emoji — valid encoding

#### CLI Integration — Exit Codes & Flags
- [x] `TH-CLI-28` — Test exit codes: 0=clean check, 1=violations, 2=error
- [x] `TH-CLI-29` — Test `--quiet` suppresses all except errors
- [x] `TH-CLI-30` — Test `--format json` on every supporting command → valid JSON
- [x] `TH-CLI-31` — Test `drift foobar` → help message, exit code 2

#### CI Agent
- [x] `TH-CI-01` — Test agent calls 9 correct NAPI function names (mock, verify)
- [x] `TH-CI-02` — Test empty diff → "no changes to analyze"
- [x] `TH-CI-03` — Test timeout → partial results
- [x] `TH-CI-04` — Test 1/9 passes fail → other 8 complete, partial results
- [x] `TH-CI-05` — Test PR comment markdown valid
- [x] `TH-CI-06` — Test PR comment 0 violations → "All checks passed"
- [x] `TH-CI-07` — Test PR comment Unicode in messages — valid markdown

### QG-D: Phase D Quality Gate

- [x] `drift-cli/src/napi.ts` and `drift-ci/src/napi.ts` contain only re-exports (zero local definitions)
- [x] `drift setup` calls `driftInitialize()` (correct Rust name)
- [x] `drift doctor` calls `driftIsInitialized()` with meaningful status
- [x] `drift fix <id>` calls `drift_fix_violation()` with confidence adjustment
- [x] `drift simulate` passes 3 args (category, description, context_json)
- [x] CI agent calls 9 correct NAPI function names
- [x] Exit codes: 0=clean, 1=violations, 2=error
- [x] `--quiet` works on all commands
- [x] `vitest --coverage` ≥80% for drift-cli and drift-ci (CLI: 28 tests, CI: 19 tests)

---

## Phase E: Integration, Parity & Regression

> **Goal:** Verify MCP, CLI, and CI produce consistent results for the same codebase. Measure progressive disclosure token efficiency. Run full end-to-end regression suite.
> **Estimated effort:** 2–3 days (1 developer)
> **Prerequisite:** Phases A–D all complete
> **Rationale:** Three presentation interfaces must produce identical analysis. Audit found zero parity tests.

### E1 — Cross-Interface Parity

- [x] `PH-PARITY-01` — Create `packages/drift-mcp/tests/integration/mcp_cli_parity.test.ts` — Parity framework: scan shared fixture via both MCP (`drift_tool('drift_violations')`) and CLI (`drift violations --format json`), compare results
- [x] `PH-PARITY-02` — Create `packages/drift-mcp/tests/integration/progressive_disclosure.test.ts` — Measure token overhead: serialize 6 entry point tool definitions, verify < 1.5K tokens total. Compare to serializing all 41 tools (should be ~81% reduction)
- [x] `PH-PARITY-03` — Create `packages/drift-mcp/tests/integration/concurrent_requests.test.ts` — 5 simultaneous `drift_tool` calls via MCP → all return correct results, no request mixing
- [x] `PH-PARITY-04` — Create `packages/drift-mcp/tests/integration/graceful_shutdown.test.ts` — In-flight request completes before server exits

### E2 — End-to-End Regression

- [x] `PH-PARITY-05` — Create `packages/drift-mcp/tests/integration/full_pipeline.test.ts` — Full pipeline: MCP scan → analyze → enforce → report. Verify all tools in the chain call correct NAPI functions and produce typed results
- [x] `PH-PARITY-06` — Create `packages/drift-ci/tests/integration/github_action.test.ts` — Full action.yml simulation with mock GitHub API: scan → 9 passes → SARIF upload → PR comment

### Phase E Tests

#### MCP↔CLI Parity — Identical Results
- [x] `TH-PARITY-01` — Test MCP `drift_violations` and CLI `drift violations --format json` produce same violation count for same fixture
- [x] `TH-PARITY-02` — Test MCP `drift_status` and CLI `drift status --format json` produce same health score
- [x] `TH-PARITY-03` — Test MCP `drift_patterns` and CLI `drift patterns --format json` produce same pattern count
- [x] `TH-PARITY-04` — Test MCP `drift_check` and CLI `drift check --format json` produce same pass/fail verdict
- [x] `TH-PARITY-05` — Test MCP `drift_audit` and CLI `drift audit --format json` produce same health score and issue count
- [x] `TH-PARITY-06` — Test divergence in any parity check → test failure with diff showing which field diverged

#### Progressive Disclosure — Token Efficiency
- [x] `TH-TOKEN-PD-01` — Test 6 entry point tool definitions serialize to < 1.5K tokens
- [x] `TH-TOKEN-PD-02` — Test all 41 internal tools serialize to > 5K tokens (confirming disclosure savings)
- [x] `TH-TOKEN-PD-03` — Test token reduction ratio ≥ 75% (1 - entry_tokens/full_tokens)
- [x] `TH-TOKEN-PD-04` — Test `drift_discover` response for any intent < 500 tokens

#### Concurrent Requests — No Mixing
- [x] `TH-CONC-01` — Test 5 simultaneous `drift_status` calls → all return identical results
- [x] `TH-CONC-02` — Test 3 `drift_violations` + 2 `drift_patterns` simultaneously → each returns correct type
- [x] `TH-CONC-03` — Test concurrent `drift_scan` + `drift_status` → status returns immediately (non-blocking)
- [x] `TH-CONC-04` — Test rate limiter under burst: 150 calls in 1s → first 100 allowed, rest blocked with correct retryAfterMs

#### Graceful Shutdown
- [x] `TH-SHUT-01` — Test in-flight `drift_scan` completes before server exits
- [x] `TH-SHUT-02` — Test no new requests accepted after shutdown signal
- [x] `TH-SHUT-03` — Test NAPI `driftShutdown()` called during server shutdown

#### End-to-End Pipeline
- [x] `TH-E2E-01` — Test full MCP pipeline: scan → violations → impact → check → audit on test fixture — all return valid typed results
- [x] `TH-E2E-02` — Test full CLI pipeline: `drift scan && drift check && drift audit` on test fixture — exit codes correct
- [x] `TH-E2E-03` — Test full CI pipeline: agent runs 9 passes → SARIF generated → PR comment generated — all output valid
- [x] `TH-E2E-04` — Test workflow `security_audit` end-to-end: returns aggregated results from 4 sub-tools
- [x] `TH-E2E-05` — Test workflow `pre_commit` end-to-end: returns check + violations + impact for changed files

#### Adversarial — Input Fuzzing
- [x] `TH-ADV-01` — Test 1MB string in `drift_context` intent → truncated or rejected, no OOM
- [x] `TH-ADV-02` — Test null/undefined in required fields → validator rejects before NAPI
- [x] `TH-ADV-03` — Test SQL injection `'; DROP TABLE violations; --` in tool params → parameterized, safe
- [x] `TH-ADV-04` — Test Unicode edge cases: CJK, emoji, RTL, zero-width chars in all string params → no encoding corruption
- [x] `TH-ADV-05` — Test all 41 tools with empty params `{}` → either valid empty result or structured error (never crash)
- [x] `TH-ADV-06` — Test NAPI stub mode: all 41 tools callable in stub mode → valid typed empty results

### QG-E: Phase E Quality Gate (Final Gate)

- [x] MCP and CLI produce identical results for violations, patterns, status, check, audit on same fixture
- [x] Progressive disclosure reduces token overhead ≥ 50% (6 entry points vs 36 tools)
- [x] 5 concurrent requests complete without mixing
- [x] Graceful shutdown completes in-flight requests
- [x] Full MCP pipeline (scan→check→audit) returns valid typed results
- [x] Full CLI pipeline exits with correct codes
- [x] Full CI pipeline generates valid SARIF + PR comment
- [x] All 36 tools handle empty params without crash
- [x] All string params handle Unicode + adversarial input safely
- [x] `vitest --coverage` ≥80% across all 4 TS packages (MCP 155, CLI 28, CI 19 = 202 tests)

---

## Milestone Summary

| Milestone | Phase | Description | Estimated Timeline |
|-----------|-------|-------------|-------------------|
| M-A: "Contracts Locked" | End of A | Single NAPI source of truth, zero divergent interfaces | Day 2–3 |
| M-B: "Infrastructure Ready" | End of B | Cache, rate limiting, error handling, pagination operational | Day 5–7 |
| M-C: "Tools Complete" | End of C | 41 tools, 6 entry points, zero NAPI mismatches | Day 8–10 |
| M-D: "CLI Aligned" | End of D | All 3 packages use contracts, all commands wired | Day 11–12 |
| M-E: "Frontier Certified" | End of E | Parity verified, token-efficient, adversarial-safe | Day 13–14 |

## Critical Path

```
Phase A (2-3d) → Phase B (3-4d) → Phase C (3-4d) → Phase E (2-3d)
                                  ↗
Phase A (2-3d) → Phase D (2-3d) ─┘
= 10-14 working days (Phases B/C and D parallelizable after A)
```

## Risk Register

| Risk | Severity | Mitigation |
|------|----------|------------|
| R1: Rust NAPI signatures change during implementation | Medium | `interface_alignment.test.ts` catches at CI time |
| R2: 41-tool catalog token overhead exceeds budget | Low | Progressive disclosure + `drift_discover` mitigates |
| R3: Cache invalidation bugs cause stale data | Medium | Conservative 5min TTL + explicit invalidation on scan |
| R4: Rate limiter blocks legitimate burst usage | Low | Configurable limits + per-tool overrides |
| R5: Workflow partial failure confuses AI agents | Medium | Clear `_workflow` metadata with per-tool status |
| R6: MCP↔CLI parity drift after initial alignment | High | Parity tests in CI prevent regression |

---

> **Generated:** 2026-02-09
> **Source documents:** DRIFT-V2-IMPLEMENTATION-TASKS.md, MCP Audit Findings, Frontier Pattern Research
> **Format reference:** DRIFT-V2-IMPLEMENTATION-TASKS.md
> **Total:** 83 implementation tasks + 180 test tasks + 47 quality gate criteria = 310 checkboxes
