# Drift V2 — Call Graph & Graph Intelligence Layer Hardening Task Tracker

> **Source of Truth:** Deep audit of `crates/drift/drift-analysis/src/call_graph/`, `graph/`, `structural/coupling/`, `engine/resolution.rs`
> **Target:** The call graph produces a connected, accurate function-level dependency graph. All 5 downstream graph intelligence systems (taint, reachability, impact, test topology, coupling) operate on real data instead of hollow shells.
> **Crate:** `crates/drift/drift-analysis/`
> **Total Phases:** 5 (A–E)
> **Quality Gates:** 5 (QG-A through QG-E)
> **Architectural Decision:** The type system and module architecture are sound — CallGraph, FunctionNode, CallEdge, Resolution, TaintFlow, BlastRadius, CoverageMapping are all correctly designed. The problems are: (1) upstream parser fields are empty so resolution strategies have no data to work with, (2) several resolution strategies are never invoked, (3) downstream consumers trust sparse graphs and produce systematically wrong results.
> **Dependency:** Phase A of DETECTOR-PARITY-HARDENING-TASKS.md (parser extraction) MUST land first — it fixes the upstream data that this tracker's Phase A wires into the call graph.
> **Rule:** No Phase N+1 begins until Phase N quality gate passes.
> **Rule:** All changes must compile with `cargo clippy --workspace -- -D warnings` clean.
> **Rule:** Every impl task has a corresponding test task. No untested code.
> **Verification:** This tracker accounts for 100% of gaps identified in the call graph and graph intelligence audit.

---

## How To Use This Document

- Agents: check off `[ ]` → `[x]` as you complete each task
- Every implementation task has a unique ID: `CG-{system}-{number}` (CG = Call Graph)
- Every test task has a unique ID: `CT-{system}-{number}` (CT = Call Graph Test)
- Quality gates are pass/fail — all criteria must pass before proceeding
- For call graph types → cross-reference `crates/drift/drift-analysis/src/call_graph/types.rs`
- For resolution → cross-reference `crates/drift/drift-analysis/src/call_graph/resolution.rs`
- For taint types → cross-reference `crates/drift/drift-analysis/src/graph/taint/types.rs`

---

## Progress Summary

| Phase | Description | Impl Tasks | Test Tasks | Status |
|-------|-------------|-----------|-----------|--------|
| A | Call Graph Resolution Completeness | 12 | 18 | ✅ Complete |
| B | Entry Point & Dead Code Accuracy | 8 | 12 | ✅ Complete |
| C | Taint Analysis Precision | 10 | 14 | ✅ Complete |
| D | Impact, Coverage & Coupling Accuracy | 8 | 10 | ✅ Complete |
| E | Cross-System Integration & Regression | 6 | 20 | ✅ Complete |
| **TOTAL** | | **44** | **74** | **✅ All Complete** |

---

## Audit Findings Reference

### Root Cause

The call graph builder (`call_graph/builder.rs`) constructs edges by resolving call sites to callee functions through a 5-strategy fallback chain (`resolution.rs`). Three of the five strategies depend on `ParseResult` fields that the detector parity audit **confirmed are always empty/default**:

- **`import.specifiers`** — always `SmallVec::new()` → Import-based resolution is dead
- **`func.is_exported`** — always `false` → Export index is empty, export-based resolution is dead
- **`func.qualified_name`** — always `None` for non-class-method functions → Method resolution only works inside class bodies
- **`func.decorators`** — always `Vec::new()` → Route handler entry point detection is dead
- **`import.source`** — contains full statement text, not module path → DI framework detection and coupling graph are distorted

This means **only 2 of 6 resolution strategies can ever fire**: SameFile (0.95) and Fuzzy (0.40, only when exactly 1 global match). The call graph is a collection of isolated per-file clusters with almost no cross-file edges. Everything downstream — taint, reachability, blast radius, dead code, test coverage, coupling — operates on this hollow graph.

### Resolution Strategy Status (line-verified)

| Strategy | Confidence | Location | Status | Root Cause |
|----------|-----------|----------|--------|------------|
| SameFile | 0.95 | `resolution.rs:51-64` | ✅ Works | No external dependency |
| MethodCall | 0.90 | `resolution.rs:67-78` | ⚠️ Partial | Only works for methods inside `extract_class()` bodies (L370). Standalone functions have `qualified_name: None` (L287) |
| DiInjection | 0.80 | `di_support.rs:93-104` | ❌ Dead | `resolve_di_injection()` is never called from `builder.rs`. Framework detection depends on broken imports/decorators |
| ImportBased | 0.75 | `resolution.rs:81-107` | ❌ Dead | Iterates `import.specifiers` at L89 — always empty (`mod.rs:480`) |
| ExportBased | 0.60 | `resolution.rs:110-121` | ❌ Dead | Looks up `export_index` built from `func.is_exported` — always false (`mod.rs:296,336`) |
| Fuzzy | 0.40 | `resolution.rs:124-135` | ⚠️ Partial | Only matches when exactly 1 global function has the name. Common names (`get`, `set`, `init`, `run`) produce multiple matches → no resolution |

### Cascade Impact Map

Every system below the call graph is degraded. Here's how:

| System | File | Consumed Data | Degradation |
|--------|------|---------------|-------------|
| **Taint (interprocedural)** | `graph/taint/interprocedural.rs` | Call graph edges for BFS | Cross-file taint flows invisible — only intraprocedural findings work |
| **Reachability** | `graph/reachability/bfs.rs` | Call graph edges for BFS | Reachable sets are artificially small — limited to same-file functions |
| **Blast Radius** | `graph/impact/blast_radius.rs` | Inverse BFS on call graph | All blast radii systematically underestimated. Risk factors hardcoded to 0.0 (L27-30) |
| **Dead Code** | `graph/impact/dead_code.rs` | Incoming edge count | Massive false positives — every cross-file-called function appears dead |
| **Unreachable Code** | `graph/impact/dead_code.rs:41-86` | BFS from entry points | Entry points are crippled (no route handlers, no exported funcs) → nearly everything appears unreachable |
| **Test Coverage** | `graph/test_topology/coverage.rs` | Outgoing BFS from test functions | Coverage appears minimal — tests can only "reach" same-file source functions |
| **Test Smells** | `graph/test_topology/smells.rs:173` | `count_source_calls` takes CallGraph | **Never uses the graph** — counts raw call sites instead |
| **Coupling Metrics** | `structural/coupling/import_graph.rs` | `import.source` for module edges | Import sources contain full statement text, not module paths → distorted graph |
| **Cycle Detection** | `structural/coupling/cycle_detection.rs` | Import graph edges | Operates on distorted import graph → may find phantom cycles or miss real ones |
| **Resolution Index** | `engine/resolution.rs:174-192` | `import.specifiers`, `is_exported` | Import entries never created (empty specifiers). External strategy never fires (is_exported=false) |

### Self-Contained Graph Layer Issues (independent of parser extraction)

These issues exist in the graph layer itself and will NOT be fixed by the detector parity hardening:

| Issue | Location | Description |
|-------|----------|-------------|
| DI resolution never called | `builder.rs` — missing call | `di_support.rs:93-104` defines `resolve_di_injection()` but `builder.rs:105-127` never invokes it |
| Blast radius risk factors all 0.0 | `blast_radius.rs:27-30` | Sensitivity, test coverage, complexity, change frequency all hardcoded to 0.0 |
| Taint over-approximation | `intraprocedural.rs:238` | `!tainted_vars.is_empty()` — if ANY var is tainted, ALL sinks are flagged |
| Taint source mis-attribution | `intraprocedural.rs:117` | Always picks `func_sources.first()` — wrong source when multiple exist |
| Incremental is full rebuild | `incremental.rs:65` | `update()` calls `self.builder.build(all_results)` — no incremental benefit |
| Taint registry over-matching | `registry.rs:96-99` | Bidirectional `contains()` — "open" matches openDialog, openMenu. "h" (Rails) matches everything |
| Entry point heuristics miss route handlers | `traversal.rs:80-110` | Depends on `func.decorators` which are always empty |
| Test smell ignores graph | `smells.rs:173-184` | `count_source_calls()` accepts `&CallGraph` but never uses it |
| Interprocedural path clone is O(n²) | `interprocedural.rs:217` | `path_nodes.clone()` in BFS loop — exponential for deep chains |
| CTE fallback MAX_DEPTH=5 | `cte_fallback.rs:10` | Hardcoded depth limit of 5 for large graphs — misses deeper call chains |
| `has_conditionals` is a stub | `smells.rs:155-159` | Returns `func.end_line - func.line > 20` instead of checking AST for if/switch/match |

### Taint Registry Pattern Matching False Positives (confirmed)

| Pattern | Sink Type | False Positive Example | Why |
|---------|-----------|----------------------|-----|
| `"open"` | FileRead | `openDialog()`, `openMenu()` | Substring match |
| `"system"` | OsCommand | `fileSystem.read()` | Substring match |
| `"exec"` | OsCommand | `execute()`, `executor.submit()` | Substring match |
| `"render"` | TemplateRender | `renderButton()`, `shouldRender` | Substring match |
| `"redirect"` | HttpRedirect | `redirectLogger.info()` | Substring match |
| `"fetch"` | HttpRequest | `fetchUser()` (same-origin) | Substring match |
| `"h"` (Rails) | HtmlEscape sanitizer | Literally every expression | Single char match |
| `"upload"` | FileUpload | `uploadProgressBar`, `isUploading` | Substring match |

---

## Phase A: Call Graph Resolution Completeness

> **Goal:** Wire all 6 resolution strategies into the call graph builder so that cross-file edges are actually created. This is the highest-multiplier work — it directly increases the graph's edge count by an estimated 5-10x, which cascades to every downstream system.
> **Depends on:** Detector Parity Phase A (parser extraction must populate `import.specifiers`, `is_exported`, `qualified_name`, `decorators` first)
> **Estimated effort:** 2–3 days
> **Files:** `call_graph/builder.rs`, `call_graph/resolution.rs`, `call_graph/di_support.rs`
> **Performance target:** Build time <5s for 10K files. Resolution rate >60% (currently estimated <15%).

### A1 — Wire Import-Based Resolution (resolution.rs:81-107)

Once Detector Parity DP-IMPORT-01/02 lands, `import.specifiers` will be populated. The resolution code is correct — it just has no data. But there are refinement opportunities:

- [x] `CG-RES-01` — **Improve import-based callee lookup** — Currently (L93-98) matches `spec.name` against `name_index` and prefers keys containing `import.source`. After DP-IMPORT-01, `import.source` will be a module path (e.g., `react`, `flask`). Improve the matching: resolve the module path to an actual file path using the file tree, then prefer functions from that file. Fallback: prefix match on the module path against file paths.
- [x] `CG-RES-02` — **Handle default imports** — If a specifier has no `name` but the import is a default import (e.g., `import React from 'react'`), resolve the callee to the default export of the source module. Add a check: if `spec.name == "default"` or `import.specifiers.len() == 0 && callee_name == alias`, resolve via the export index for that module.
- [x] `CG-RES-03` — **Handle namespace imports** — `import * as utils from './utils'` means `utils.foo()` should resolve. When `call_site.receiver == Some("utils")` and an import has `alias == "utils"`, resolve `callee_name` from the source module's functions.

### A2 — Wire Export-Based Resolution (resolution.rs:110-121)

Once Detector Parity DP-FUNC-01 lands, `func.is_exported` will be populated. The resolution code is correct but too conservative:

- [x] `CG-RES-04` — **Allow multi-match with disambiguation** — Currently returns `None` if `keys.len() != 1` (L116). Improve: when multiple exported functions share a name, disambiguate by (1) checking if the caller file imports from any of the exporters' files, (2) preferring the same-language match, (3) preferring the closest directory match. Only fall through to Fuzzy if no disambiguation succeeds.

### A3 — Wire DI Resolution into the Builder (builder.rs — missing)

- [x] `CG-RES-05` — **Call `resolve_di_injection` from the build loop** — After import-based resolution fails and before export-based, try DI resolution. In `builder.rs` after line 113, add: if DI frameworks have been detected for this file's language, check if the callee name matches an injected type and resolve via `di_support::resolve_di_injection()`.
- [x] `CG-RES-06` — **Fix DI framework detection** — `detect_di_frameworks()` (di_support.rs:57-81) checks `imp.source.contains(src)` and `func.decorators`. After Detector Parity fixes imports/decorators, this will work. But also add: check `class.decorators` (not just `func.decorators`) for class-level DI annotations like `@Injectable`, `@Component`, `@Service`.
- [x] `CG-RES-07` — **Add constructor injection resolution** — For Spring `@Autowired` constructor params and NestJS constructor injection, parse constructor parameter types and resolve them to provider classes. In `builder.rs`, when processing a class constructor's parameters, check each parameter type against the class name index.

### A4 — Wire Method Resolution for Standalone Functions (resolution.rs:67-78)

- [x] `CG-RES-08` — **Build qualified names for module-level functions** — In `builder.rs` Phase 1 (L47-61), when creating `FunctionNode`, populate `qualified_name` as `module_path.function_name` (e.g., `utils.formatDate`). Use the file's import-resolved module name, not the full file path.
- [x] `CG-RES-09` — **Enhance method resolution with import context** — When `call_site.receiver == Some(r)` and `r` matches an import alias or class name, resolve `r.method()` by looking up `r` in the import specifiers → find the source module → find `method` in that module. This chains import resolution with method resolution.

### A5 — Improve Fuzzy Resolution (resolution.rs:124-135)

- [x] `CG-RES-10` — **Add language-scoped fuzzy matching** — Currently returns None if `keys.len() != 1`. Improve: filter candidates by language first. If a TypeScript file calls `useState`, prefer TypeScript/JavaScript candidates over Java or Go ones. Only match within the same language family.
- [x] `CG-RES-11` — **Exclude common false-positive names from fuzzy** — Names like `get`, `set`, `run`, `init`, `start`, `stop`, `open`, `close`, `read`, `write`, `create`, `update`, `delete`, `find`, `filter`, `map`, `reduce`, `forEach` are too common. Maintain a blocklist of names that should never use Fuzzy resolution.

### A6 — Resolution Statistics & Diagnostics

- [x] `CG-RES-12` — **Emit resolution diagnostics** — Add a `ResolutionDiagnostics` struct that tracks: total call sites attempted, resolved by each strategy, unresolved, resolution rate per language. Log a warning if resolution rate < 30% for any language (indicates missing parser data). Add to `CallGraphStats`.

### Phase A Tests

#### Import-Based Resolution
- [x] `CT-RES-01` — TS: `import { useState } from 'react'` → call to `useState()` resolves via ImportBased
- [x] `CT-RES-02` — Python: `from flask import Flask` → call to `Flask()` resolves via ImportBased
- [x] `CT-RES-03` — Go: `import "net/http"` → call to `http.ListenAndServe()` resolves via ImportBased
- [x] `CT-RES-04` — Java: `import java.util.List` → call to `List.of()` resolves via ImportBased
- [x] `CT-RES-05` — Default import: `import React from 'react'` → `React.createElement()` resolves

#### Export-Based Resolution
- [x] `CT-RES-06` — TS: `export function getUser()` in file A → call to `getUser()` in file B resolves via ExportBased
- [x] `CT-RES-07` — Go: `func GetUser()` (uppercase) → cross-file call resolves as exported
- [x] `CT-RES-08` — Multi-match disambiguation: two files export `getUser`, caller imports from one → correct one chosen

#### DI Resolution
- [x] `CT-RES-09` — NestJS: `@Injectable() class UserService` + constructor injection → resolves via DiInjection
- [x] `CT-RES-10` — Spring: `@Autowired UserRepository repo` → resolves to `UserRepository` class
- [x] `CT-RES-11` — FastAPI: `Depends(get_db)` → resolves to `get_db` function

#### Method Resolution
- [x] `CT-RES-12` — TS: `utils.formatDate()` where `utils` is imported → resolves `formatDate` in source module
- [x] `CT-RES-13` — Python: `self.helper()` inside class method → resolves to `helper` method on same class

#### Fuzzy Resolution
- [x] `CT-RES-14` — Language-scoped: TS calls `processData`, only one TS `processData` exists → resolves
- [x] `CT-RES-15` — Blocklist: call to `get()` does NOT fuzzy-resolve to unrelated `get()` in another file

#### Diagnostics
- [x] `CT-RES-16` — Resolution rate >60% on a 10-file TypeScript project with imports
- [x] `CT-RES-17` — Resolution rate >50% on a mixed-language project (TS + Python)
- [x] `CT-RES-18` — Warning emitted when resolution rate < 30%

### Quality Gate A (QG-A)

```
MUST PASS before Phase B begins:
- [x] Import-based resolution fires on at least 5 languages (TS, Python, Java, Go, Rust)
- [x] Export-based resolution fires when is_exported=true
- [x] DI resolution fires for at least 2 DI frameworks (NestJS, Spring)
- [x] Resolution rate >50% on reference test fixtures
- [x] Fuzzy blocklist prevents resolution of common names (get, set, run, etc.)
- [x] Resolution diagnostics emitted and available in CallGraphStats
- [x] cargo clippy --workspace -- -D warnings passes
- [x] cargo test -p drift-analysis passes (all existing tests still green)
- [x] Build time <5s for 10K-function synthetic test (no regression)
```

---

## Phase B: Entry Point & Dead Code Accuracy

> **Goal:** Fix entry point detection so it correctly identifies exported functions, route handlers, and framework entry points. Fix dead code detection so it doesn't mass-flag every cross-file function.
> **Depends on:** Phase A (call graph must have cross-file edges for accurate dead code detection)
> **Estimated effort:** 1.5–2 days
> **Files:** `call_graph/traversal.rs`, `graph/impact/dead_code.rs`, `graph/impact/blast_radius.rs`

### B1 — Fix Entry Point Detection (traversal.rs:80-110)

- [x] `CG-EP-01` — **Wire decorator-based route handler detection** — After Detector Parity DP-FUNC-04 lands, `func.decorators` will be populated. `mark_entry_points()` at L85-96 already checks decorators — verify it fires after the upstream fix and add coverage for: `@app.route` (Flask), `@GetMapping`/`@PostMapping` (Spring), `@Get`/`@Post` (NestJS), `@api_view` (DRF), `#[get("/")]` (Actix/Rocket), `@RequestMapping` (Spring).
- [x] `CG-EP-02` — **Wire is_exported-based entry point detection** — `is_entry_point()` at L115 checks `node.is_exported`. After Detector Parity DP-FUNC-01 lands, this will work. Verify with tests that exported functions in all 10 languages are detected as entry points.
- [x] `CG-EP-03` — **Add framework main function patterns** — Expand `is_entry_point()` at L123: add `app` (Express/Flask), `createApp` (Vue), `createServer` (Node), `Application` (Spring Boot), `WebApplication.CreateBuilder` (ASP.NET), `gin.Default` (Gin). Also detect `if __name__ == "__main__":` blocks in Python.
- [x] `CG-EP-04` — **Add GraphQL resolver detection** — Functions named `Query.*`, `Mutation.*`, `Subscription.*` or decorated with `@Query`, `@Mutation`, `@ResolveField` should be entry points. These are invisible to the current heuristics.

### B2 — Fix Dead Code False Positives (dead_code.rs)

- [x] `CG-DC-01` — **Gate dead code detection on resolution rate** — Before running dead code detection, check `CallGraphStats.resolution_rate`. If < 40%, emit a warning that dead code results may have high false positive rates due to low resolution, and mark all results with `confidence: Low`.
- [x] `CG-DC-02` — **Add decorator-based exclusion** — `check_exclusions()` at L89 has 10 categories but none check decorators. Add: if the function has any decorator from a known set (route decorators, DI decorators, event handlers, scheduled tasks), exclude it. Decorator categories: `@route`, `@app.*`, `@Controller`, `@Scheduled`, `@EventListener`, `@Subscribe`, `@Cron`, `@celery_app.task`.
- [x] `CG-DC-03` — **Add override/implementation exclusion** — Functions that implement an interface method or override a parent class method are not dead even if they have 0 callers (they're called polymorphically). Check `func.qualified_name` patterns and class `implements` list.
- [x] `CG-DC-04` — **Add confidence scoring to dead code results** — Currently `is_dead` is binary. Add `confidence: f32` based on: number of resolution strategies that failed, whether the function is in a file with many unresolved calls, whether the function name is common.

### Phase B Tests

- [x] `CT-EP-01` — Express route handler `app.get('/users', getUsers)` → `getUsers` marked as entry point
- [x] `CT-EP-02` — Flask `@app.route('/users')` → decorated function marked as entry point
- [x] `CT-EP-03` — Spring `@GetMapping("/users")` → method marked as entry point
- [x] `CT-EP-04` — Exported TS function → entry point
- [x] `CT-EP-05` — Go uppercase function → entry point
- [x] `CT-EP-06` — Rust `pub fn` → entry point
- [x] `CT-DC-01` — Cross-file imported function NOT flagged as dead code
- [x] `CT-DC-02` — @Scheduled function NOT flagged as dead code
- [x] `CT-DC-03` — Interface implementation NOT flagged as dead code
- [x] `CT-DC-04` — Dead code confidence < 0.5 when resolution rate < 40%
- [x] `CT-DC-05` — Actually dead function (no callers, no exclusions) correctly flagged with high confidence
- [x] `CT-DC-06` — Resolution rate warning emitted when < 40%

### Quality Gate B (QG-B)

```
MUST PASS before Phase C begins:
- [x] Route handlers for Express, Flask, Spring detected as entry points
- [x] Exported functions for all 10 languages detected as entry points
- [x] Dead code false positives reduced by >50% on reference fixture
- [x] Dead code results include confidence scores
- [x] Resolution rate warning emitted when graph is sparse
- [x] cargo clippy clean, cargo test green
```

---

## Phase C: Taint Analysis Precision

> **Goal:** Fix false positives in intraprocedural taint, enable real interprocedural taint flows, and harden the taint registry pattern matching.
> **Depends on:** Phase A (interprocedural taint needs cross-file call graph edges)
> **Estimated effort:** 2–3 days
> **Files:** `graph/taint/intraprocedural.rs`, `graph/taint/interprocedural.rs`, `graph/taint/registry.rs`, `graph/taint/propagation.rs`

### C1 — Fix Taint Over-Approximation (intraprocedural.rs:224-238)

- [x] `CG-TAINT-01` — **Replace conservative taint-reaches-sink check** — `check_taint_reaches_sink()` at L238 returns `true` if ANY variable is tainted (`!tainted_vars.is_empty()`). Replace with: check if the call's arguments or receiver contain a tainted variable. For each argument position, check if the argument expression matches a tainted variable name. This requires adding argument text to `CallSite` or doing a second AST pass for argument resolution.
- [x] `CG-TAINT-02` — **Fix taint source mis-attribution** — At L117, `func_sources.first()` always picks the first source. Replace with: find the source whose taint label is present in `tainted_vars` for the receiver or arguments of the sink call. If multiple sources flow to the same sink, create one `TaintFlow` per source.
- [x] `CG-TAINT-03` — **Track taint through variable assignments** — Currently taint is only introduced from sources and parameters. Add: when a call site returns a value assigned to a variable (detected via parent `variable_declarator` / `assignment_expression` node), and the call's arguments include a tainted variable, propagate taint to the assigned variable. This requires tracking assignment targets in the parse phase.

### C2 — Fix Taint Registry Pattern Matching (registry.rs:95-119)

- [x] `CG-TAINT-04` — **Replace substring matching with structured matching** — `match_source()`, `match_sink()`, `match_sanitizer()` all use bidirectional `contains()`. Replace with: (1) exact match on full expression, (2) prefix match on `receiver.method` patterns (e.g., `res.send` matches `res.send` but not `process.send`), (3) for method-only patterns (e.g., `exec`), require that it matches the `callee_name` exactly, not a substring of a larger name. Never match single-char patterns like `h`.
- [x] `CG-TAINT-05` — **Add language-scoped patterns** — Source/sink patterns should be language-aware. Express patterns should only match in JS/TS files. Django patterns should only match in Python. Add `language: Option<Language>` to `SourcePattern`, `SinkPattern`, `SanitizerPattern`. Filter by language during matching.
- [x] `CG-TAINT-06` — **Add argument-position-aware sink matching** — `db.query(sql)` is a sink because argument 0 is a SQL string. But `db.query(preparedStmt, [params])` is safe because argument 0 is a prepared statement. Add `tainted_argument_positions: Option<Vec<usize>>` to `SinkPattern` to specify which arguments must be tainted for the sink to trigger.

### C3 — Fix Interprocedural Taint Efficiency (interprocedural.rs)

- [x] `CG-TAINT-07` — **Replace path cloning with path references** — At L217, `path_nodes.clone()` inside the BFS loop creates O(n²) memory. Replace with: maintain a parent-pointer array (`parent: Vec<Option<NodeIndex>>`) during BFS, and reconstruct paths lazily only when a sink is found.
- [x] `CG-TAINT-08` — **Add function summary caching** — `build_function_summaries()` at L52-66 rebuilds summaries for all functions every time. Cache summaries keyed by `(file, function_name, body_hash)`. Only rebuild when `body_hash` changes.
- [x] `CG-TAINT-09` — **Improve interprocedural source-to-sink attribution** — At L142-146, `source_summary.internal_sources.first()` picks the first source. Track which specific taint labels flow through which call edges. When a function summary says `returns_taint: true`, propagate the specific taint label (not just a boolean).

### C4 — Add Framework-Specific Taint Rules

- [x] `CG-TAINT-10` — **Add sanitizer-aware framework specs** — Several framework specs (fastify, koa, gin, actix) only define sources but no sinks or sanitizers. Add: Fastify `reply.send()` → HtmlOutput sink, `reply.redirect()` → HttpRedirect sink. Koa `ctx.body =` → HtmlOutput sink. Gin `c.JSON()` / `c.HTML()` → HtmlOutput sink. Actix `HttpResponse::Ok().body()` → HtmlOutput sink. Also add their respective sanitizers.

### Phase C Tests

#### Taint Precision
- [x] `CT-TAINT-01` — Function with tainted `req.query` but `db.query(unrelatedVar)` → NOT flagged (no false positive)
- [x] `CT-TAINT-02` — Function with tainted `req.query` and `db.query(req.query)` → flagged correctly
- [x] `CT-TAINT-03` — Two sources in one function → each sink attributed to correct source
- [x] `CT-TAINT-04` — Taint through assignment: `const sql = req.query.q; db.query(sql)` → flagged

#### Registry Precision
- [x] `CT-TAINT-05` — `openDialog()` does NOT match `"open"` FileRead sink
- [x] `CT-TAINT-06` — `fileSystem.read()` does NOT match `"system"` OsCommand sink
- [x] `CT-TAINT-07` — `res.send(data)` correctly matches `"res.send"` HtmlOutput sink
- [x] `CT-TAINT-08` — Express patterns do NOT fire in Python files
- [x] `CT-TAINT-09` — Django patterns do NOT fire in TypeScript files

#### Interprocedural
- [x] `CT-TAINT-10` — Cross-file taint: source in file A, sink in file B linked via import → flow detected
- [x] `CT-TAINT-11` — Sanitizer in intermediate function breaks the flow → `is_sanitized: true`
- [x] `CT-TAINT-12` — Deep call chain (depth 10) completes without OOM or timeout
- [x] `CT-TAINT-13` — Summary cache hit on unchanged function (body_hash stable)
- [x] `CT-TAINT-14` — Framework specs for Fastify, Koa, Gin, Actix produce valid sink matches

### Quality Gate C (QG-C)

```
MUST PASS before Phase D begins:
- [x] Taint false positive rate reduced by >50% on reference fixture
- [x] Cross-file taint flow detected for at least 3 frameworks (Express, Django, Spring)
- [x] Registry never matches single-char patterns
- [x] Language-scoped patterns prevent cross-language false positives
- [x] Interprocedural memory usage <100MB for 1000-function graph
- [x] cargo clippy clean, cargo test green
```

---

## Phase D: Impact, Coverage & Coupling Accuracy

> **Goal:** Fix blast radius scoring, test coverage mapping, and coupling metrics to produce accurate results on a connected call graph.
> **Depends on:** Phase A (graph connectivity) and Phase B (entry points)
> **Estimated effort:** 1.5–2 days
> **Files:** `graph/impact/blast_radius.rs`, `graph/test_topology/coverage.rs`, `graph/test_topology/smells.rs`, `structural/coupling/import_graph.rs`, `call_graph/incremental.rs`

### D1 — Fix Blast Radius Scoring (blast_radius.rs:25-31)

- [x] `CG-IMPACT-01` — **Populate risk score factors** — Replace the 4 hardcoded `0.0` values at L27-30 with real data: (1) `sensitivity` = whether the function touches auth/crypto/PII detectors, (2) `test_coverage` = whether the function is covered by any test (from test topology), (3) `complexity` = cyclomatic complexity from the parse result or function body size, (4) `change_frequency` = leave as 0.0 with a TODO for git history integration.
- [x] `CG-IMPACT-02` — **Add cross-file blast radius** — Current blast radius only counts transitive callers. Add: also count the number of distinct files affected (`unique_files_affected: u32`). A function called from 5 functions in 5 different files has higher blast than one called from 5 functions in 1 file.

### D2 — Fix Test Coverage Mapping (coverage.rs, smells.rs)

- [x] `CG-COV-01` — **Wire test topology through connected graph** — `compute_coverage()` does BFS from test functions. Once Phase A lands cross-file edges, test coverage will automatically improve. Add a diagnostic: `cross_file_coverage_count` that counts how many source functions are covered via cross-file edges (should be >0 after Phase A).
- [x] `CG-COV-02` — **Fix count_source_calls to use call graph** — `smells.rs:173` accepts `&CallGraph` but counts raw call sites. Fix: look up the test function in the call graph, get its outgoing edges, count how many are non-test source functions. This makes "Eager Test" and "Lazy Test" detection accurate.
- [x] `CG-COV-03` — **Fix has_conditionals stub** — `smells.rs:155-159` is a line-count heuristic. Replace with: check the parse result for `if`, `switch`, `match`, `case` call sites or error handling within the function's line range. If the function's AST has conditional nodes, return true.

### D3 — Fix Coupling Metrics (import_graph.rs)

- [x] `CG-COUP-01` — **Feed resolved module paths into import graph** — `ImportGraphBuilder.add_file()` takes `imports: &[String]`. After Detector Parity DP-IMPORT-01 fixes `import.source` to be module paths, the caller must pass these module paths (not raw statement text). Verify the integration point and add a test.
- [x] `CG-COUP-02` — **Feed abstract type counts from parse results** — `set_type_counts()` needs `abstract_count` and `total_count`. Populate from `ClassInfo`: count classes where `is_abstract == true` or `class_kind == Interface/Trait` as abstract. Count all classes/structs/enums/interfaces as total.

### D4 — Fix Incremental Call Graph

- [x] `CG-INCR-01` — **Implement true incremental update** — `incremental.rs:65` does a full rebuild. Replace with: (1) remove nodes/edges for changed files, (2) re-extract functions and call sites for changed files only, (3) re-resolve only call sites in changed files + call sites in other files that pointed to changed files. Use `signature_hash` and `body_hash` to detect actual changes.

### Phase D Tests

- [x] `CT-IMPACT-01` — Blast radius includes sensitivity factor from auth detector match
- [x] `CT-IMPACT-02` — Blast radius includes test coverage factor from test topology
- [x] `CT-IMPACT-03` — `unique_files_affected` correctly counts distinct files
- [x] `CT-COV-01` — Cross-file test coverage detected (test in file A covers function in file B)
- [x] `CT-COV-02` — `count_source_calls` uses call graph edges (not raw call sites)
- [x] `CT-COV-03` — `has_conditionals` detects `if` statement in function body
- [x] `CT-COUP-01` — Module paths (not statement text) used in import graph
- [x] `CT-COUP-02` — Abstract type counts populated from ClassInfo
- [x] `CT-INCR-01` — Single-file change updates only affected edges (not full rebuild)
- [x] `CT-INCR-02` — Unchanged file's edges preserved after incremental update

### Quality Gate D (QG-D)

```
MUST PASS before Phase E begins:
- [x] Blast radius risk scores have at least 2 non-zero factors
- [x] Cross-file test coverage >0 on reference fixture
- [x] count_source_calls uses the call graph (no raw call site counting)
- [x] Coupling metrics receive module paths, not statement text
- [x] Incremental update for 1-file change <100ms (not full rebuild)
- [x] cargo clippy clean, cargo test green
```

---

## Phase E: Cross-System Integration & Regression

> **Goal:** Verify that the full pipeline — parse → call graph → {taint, reachability, impact, test topology, coupling} — produces correct, consistent results end-to-end. Validate performance. Catch regressions.
> **Depends on:** Phases A–D complete
> **Estimated effort:** 2–3 days
> **Files:** All files in `call_graph/`, `graph/`, `structural/coupling/`, `engine/`

### E1 — End-to-End Integration Tests

- [x] `CG-E2E-01` — **Express app integration test** — Parse a 5-file Express app (routes, controllers, services, models, middleware). Verify: call graph has cross-file edges, taint flows from req.query through controller to db.query are detected, route handlers are entry points, dead code excludes route handlers, test topology maps test files to source files.
- [x] `CG-E2E-02` — **Django app integration test** — Parse a 5-file Django app (views, models, forms, serializers, urls). Same verification as above for Python.
- [x] `CG-E2E-03` — **Spring Boot integration test** — Parse a 5-file Spring Boot app (controller, service, repository, entity, config). Verify DI resolution resolves @Autowired dependencies.
- [x] `CG-E2E-04` — **Multi-language integration test** — Parse a project with both TS and Python files. Verify that language-scoped patterns don't cross-fire. Verify resolution stays within language boundaries.

### E2 — Performance Regression Tests

- [x] `CG-PERF-01` — **Call graph build benchmark** — 10K functions across 500 files. Build time <5s. Resolution rate >50%.
- [x] `CG-PERF-02` — **Taint analysis benchmark** — 1K functions with 50 sources and 50 sinks. Interprocedural analysis <10s. Memory <200MB.

### Phase E Tests

#### End-to-End
- [x] `CT-E2E-01` — Express: req.query → controller.getUser → db.query → TaintFlow with CWE-89
- [x] `CT-E2E-02` — Express: req.query → escapeHtml → res.send → TaintFlow with is_sanitized=true
- [x] `CT-E2E-03` — Django: request.GET → view → cursor.execute → TaintFlow with CWE-89
- [x] `CT-E2E-04` — Spring: @RequestParam → service.process → jdbcTemplate.query → TaintFlow
- [x] `CT-E2E-05` — Express app: route handler detected as entry point
- [x] `CT-E2E-06` — Express app: dead code detection excludes route handlers and imported functions
- [x] `CT-E2E-07` — Express app: blast radius of service function includes controller callers
- [x] `CT-E2E-08` — Express app: test file covers source functions via cross-file edges
- [x] `CT-E2E-09` — Coupling: modules have Ce/Ca > 0 (not all isolated)
- [x] `CT-E2E-10` — Multi-language: Express patterns don't fire on Python files

#### Performance
- [x] `CT-PERF-01` — 10K function call graph build <5s
- [x] `CT-PERF-02` — Resolution rate >50% on reference fixture
- [x] `CT-PERF-03` — Interprocedural taint on 1K functions <10s
- [x] `CT-PERF-04` — Memory usage <200MB for 1K function interprocedural taint
- [x] `CT-PERF-05` — BFS traversal (forward + inverse) <5ms each
- [x] `CT-PERF-06` — No regression: parse throughput still ~1ms per file
- [x] `CT-PERF-07` — Incremental update for 1 changed file <100ms
- [x] `CT-PERF-08` — Coupling analysis for 50-module graph <500ms
- [x] `CT-PERF-09` — Dead code analysis for 10K functions <2s
- [x] `CT-PERF-10` — Test topology coverage mapping for 5K functions <3s

### Quality Gate E (QG-E) — Final

```
MUST PASS for call graph hardening to be complete:
- [x] Express E2E: cross-file taint flow detected with correct CWE
- [x] Django E2E: cross-file taint flow detected with correct CWE
- [x] Spring E2E: DI resolution + taint flow detected
- [x] Route handlers are entry points across all tested frameworks
- [x] Dead code false positive rate <20% on reference fixture
- [x] Blast radius has ≥2 non-zero risk factors
- [x] Test coverage includes cross-file coverage
- [x] Coupling Ce/Ca > 0 for multi-module projects
- [x] Resolution rate >50% across all test fixtures
- [x] All CT-PERF-* benchmarks pass
- [x] cargo clippy --workspace -- -D warnings passes
- [x] cargo test -p drift-analysis passes (all existing + new tests green)
- [x] No parse throughput regression (still ~1ms per file)
```

---

## Dependency Graph

```
DETECTOR-PARITY Phase A (parser extraction)
        │
        ▼
   ┌────────────┐
   │  Phase A   │  Call Graph Resolution Completeness
   │  (2-3 days)│  Wire all 6 strategies, fix resolution
   └────────────┘
        │
        ├──────────────────┐
        ▼                  ▼
   ┌────────────┐    ┌────────────┐
   │  Phase B   │    │  Phase C   │  (B and C can parallelize)
   │ Entry Point│    │   Taint    │
   │ & Dead Code│    │ Precision  │
   │ (1.5-2 d)  │    │ (2-3 days) │
   └────────────┘    └────────────┘
        │                  │
        └──────┬───────────┘
               ▼
         ┌────────────┐
         │  Phase D   │  Impact, Coverage, Coupling
         │ (1.5-2 d)  │
         └────────────┘
               │
               ▼
         ┌────────────┐
         │  Phase E   │  Integration & Regression
         │ (2-3 days) │
         └────────────┘
```

**Critical path:** Detector Parity A → Phase A (2-3d) → Phase D (1.5-2d) → Phase E (2-3d) = 6-8 days after parser extraction.
**With parallelization:** B+C can run alongside each other after A. Total: 8-11 working days after parser extraction lands.
