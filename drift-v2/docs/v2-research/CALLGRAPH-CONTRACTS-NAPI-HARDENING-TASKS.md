# Call Graph Resolution, Contract Extraction & NAPI Hardening Tasks

**Audit Date:** 2026-02-10
**Auditor:** Code-level audit (not document-level)
**Scope:** 3 systems — call graph resolution, contract field extraction, `drift_contract_tracking()` NAPI
**Method:** Every finding verified against actual source code with line numbers

---

## Executive Summary

The previous audit document (`CALL-GRAPH-AND-GRAPH-INTELLIGENCE-HARDENING-TASKS.md`) was written **before** the call graph hardening and contract extraction hardening were implemented. This audit examines the **current state of the code** post-hardening to determine what is actually fixed vs what remains broken.

### Verdict

| System | Old Audit Claim | Actual Current State | Severity |
|--------|----------------|---------------------|----------|
| Call graph resolution | "Only 2 of 6 strategies fire" | **FIXED.** All 6 strategies are wired and tested. Parser populates imports, exports, decorators, call_sites for all 10 languages. | ✅ Resolved |
| Contract field extraction | "All 14 extractors produce empty fields" | **PARTIALLY FIXED.** 10/14 extractors have `extract_with_context()` implementations. But the NAPI binding calls `extract_all()` not `extract_all_with_context()`, so fields are **always empty in production**. | 🔴 P0 |
| `drift_contract_tracking()` NAPI | "Hardcoded empty stub" | **NO LONGER A STUB** — it walks files, extracts endpoints, runs BE↔FE matching. But it calls `extract_all()` (no fields), doesn't parse files (no `ParseResult`), and doesn't persist to storage. | 🔴 P0 |

**Bottom line:** The call graph is fixed. The contract system has the right architecture but a **single-line bug** (`extract_all` → `extract_all_with_context`) plus 3 structural gaps prevent it from working end-to-end.

---

## Section A: Call Graph Resolution — VERIFIED FIXED

### A.1: Resolution Strategies (All 6 Wired)

**File:** `drift-analysis/src/call_graph/resolution.rs:104-145`

The `resolve_call()` function chains all 5 standard strategies in order:
1. **SameFile** (0.95) — `resolve_same_file()` at line 148-161 ✅
2. **MethodCall** (0.90) — `resolve_method_call()` at line 165-216, enhanced with CG-RES-09 import alias resolution ✅
3. **ImportBased** (0.75) — `resolve_import_based()` at line 222-299, with CG-RES-01/02/03 (module path matching, default imports, namespace imports) ✅
4. **ExportBased** (0.60) — `resolve_export_based()` at line 333+ ✅
5. **Fuzzy** (0.40) — `resolve_fuzzy()` at line 380+ ✅

**File:** `drift-analysis/src/call_graph/builder.rs:146-196`

6. **DiInjection** (0.80) — `di_support::resolve_di_injection()` called as fallback after standard chain at line 186-196 ✅

### A.2: Parser Field Population (All Fields Populated)

**File:** `drift-analysis/src/parsers/languages/mod.rs`

The tree-sitter parser populates ALL required fields:
- **imports** — `extract_import()` at line 777-944, handles JS/TS, Python, Java/Kotlin, Rust, C#, Go, PHP, Ruby (via `require` call detection at line 228-279) ✅
- **exports** — `extract_export()` at line 994-1005 ✅
- **call_sites** — `extract_call_site()` at line 1007-1036, with receiver extraction for method calls ✅
- **decorators** — `extract_decorator()` called at line 315-317, linked to functions via `extract_decorators_for_node()` at line 551 ✅
- **is_exported** — `detect_is_exported()` at line 542, language-aware (pub for Rust, export for JS/TS, capitalized for Go) ✅
- **qualified_name** — built in `CallGraphBuilder` at line 52-54 via `module_name_from_file()` ✅

**Verification:** `parser_extraction_completeness_test.rs` confirms imports are non-empty for all 10 languages (TS, JS, Python, Java, Go, Rust, C#, Ruby, PHP, Kotlin). Tests pass.

### A.3: Builder Indices (All 4 Populated)

**File:** `drift-analysis/src/call_graph/builder.rs:106-144`

- `name_index` — populated from `pr.functions` and `class.methods` ✅
- `qualified_index` — populated from `func.qualified_name` and `module_name.function_name` ✅
- `export_index` — populated from `func.is_exported` and `method.is_exported || class.is_exported` ✅
- `language_index` — populated from `pr.language.name()` ✅

### A.4: DI Framework Detection

**File:** `drift-analysis/src/call_graph/di_support.rs:22-104`

5 frameworks defined (NestJS, Spring, FastAPI, Laravel, ASP.NET). Detection checks both imports and decorators. Resolution via `resolve_di_injection()` at line 93-104.

### A.5: Remaining Call Graph Issues (P2/P3 — Non-Blocking)

| ID | Issue | Severity | Location | Impact |
|----|-------|----------|----------|--------|
| CG-R-01 | `resolve_di_injection` only matches exact single-key names — no type hierarchy resolution | P3 | `di_support.rs:98-101` | DI resolution won't fire for interfaces with multiple implementations |
| CG-R-02 | `resolve_export_based` requires same language — cross-language resolution impossible | P3 | `resolution.rs` export_based fn | Polyglot repos won't get cross-language edges |
| CG-R-03 | `ResolutionDiagnostics` warnings logged but not persisted to storage | P3 | `builder.rs:220-222` | No observability on resolution quality per scan |

**Conclusion: The call graph audit document was stale. The code is fixed. No P0/P1 issues remain.**

---

## Section B: Contract Field Extraction — 2 P0 BUGS FOUND

### B.1: [P0] `drift_contract_tracking()` calls `extract_all()` instead of `extract_all_with_context()`

**File:** `drift-napi/src/bindings/structural.rs:206`
```rust
let results = registry.extract_all(&content, &file_path);
```

**Should be:**
```rust
let results = registry.extract_all_with_context(&content, &file_path, Some(&parse_result));
```

**Root cause:** The NAPI binding was wired to the old `extract_all()` method which calls `extract()` (no `ParseResult`). The `extract_all_with_context()` method exists at `extractors/mod.rs:76-91` and is tested, but **never called from production code**.

**Impact cascade:**
1. All 14 extractors produce `request_fields: vec![]` and `response_fields: vec![]`
2. `field_overlap()` in `matching.rs:148-157` always returns 0.0
3. `type_compatibility()` in `matching.rs:73-84` always returns 0.0 (total=0)
4. `response_shape_match()` in `matching.rs:103-113` always returns 1.0 (both empty)
5. `detect_mismatches()` in `matching.rs:159-241` never fires any mismatch (no fields to compare)
6. 6 of 7 mismatch types never fire: FieldMissing, TypeMismatch, RequiredOptional, Nullable, ArrayScalar (only path-based matching works)
7. All 10 breaking change types that depend on fields never fire in `breaking_changes.rs:43-119`
8. Confidence scoring degraded — only 2 of 5 signals populated (path_similarity + method_match)

### B.2: [P0] `drift_contract_tracking()` doesn't parse files — no `ParseResult` available

**File:** `drift-napi/src/bindings/structural.rs:203-206`
```rust
if let Ok(content) = std::fs::read_to_string(&file_path) {
    let results = registry.extract_all(&content, &file_path);
```

Even if we fix B.1 to call `extract_all_with_context()`, there's no `ParseResult` to pass. The function reads raw file content but never parses it through the `ParserManager`. It needs to:
1. Detect language from file extension
2. Parse with `ParserManager` to get `ParseResult`
3. Pass `Some(&parse_result)` to `extract_all_with_context()`

### B.3: [P1] 4 of 14 extractors missing `extract_with_context()` implementation

These extractors fall back to the default trait implementation (no fields):

| Extractor | File | Framework |
|-----------|------|-----------|
| `RailsExtractor` | `extractors/rails.rs` | Rails |
| `LaravelExtractor` | `extractors/laravel.rs` | Laravel |
| `NextJsExtractor` | `extractors/nextjs.rs` | Next.js |
| `TrpcExtractor` | `extractors/trpc.rs` | tRPC |

The 10 extractors WITH `extract_with_context()`:
Express, Fastify (via default), NestJS, Django, Flask, Spring, ASP.NET, Actix, Gin, Frontend

### B.4: [P1] No contract extraction step in `drift_analyze()` pipeline

**File:** `drift-napi/src/bindings/analysis.rs`

The analysis pipeline has steps 5a through 5k covering coupling, wrappers, crypto, DNA, secrets, constants, constraints, env variables, data access, OWASP, and decomposition — but **zero contract extraction steps**. This means:

1. The `contracts` table (migrated in `v005_structural.rs:58-67`) is never written to
2. The `contract_mismatches` table (migrated in `v005_structural.rs:74-82`) is never written to
3. No `InsertContracts` or `InsertContractMismatches` `BatchCommand` variants exist
4. `drift_contract_tracking()` does its own file walking (duplicating scan logic) instead of using cached `ParseResult`s from the pipeline

### B.5: [P2] `drift_contract_tracking()` doesn't persist results to storage

**File:** `drift-napi/src/bindings/structural.rs:182-267`

The function extracts endpoints and runs matching, but results are only returned to the caller — never written to the `contracts` or `contract_mismatches` tables. This means:
- Repeated calls re-extract everything from scratch (no caching)
- Other NAPI functions that query storage (e.g., `drift_status`) can't report contract data
- CI agent's contract pass results are ephemeral

### B.6: [P2] Confidence scoring degraded without fields

**File:** `matching.rs:33-70`

The `compute_match_confidence()` function has 5 signals with weights:
| Signal | Weight | Works Without Fields? |
|--------|--------|----------------------|
| path_similarity | 3.0 | ✅ Yes |
| method_match | 1.0 | ✅ Yes |
| field_overlap | 1.0 | ❌ Always 0.0 |
| type_compatibility | 1.0 | ❌ Always 0.0 |
| response_shape_match | 1.0 | ⚠️ Always 1.0 (both empty = match) |

Total signals = 7.0, but effective = 5.0 (path×3 + method + shape_match). The inflated `response_shape_match` (1.0 when both sides have 0 fields) artificially boosts confidence for non-matching endpoints.

### B.7: [P3] `extract_with_context` line offset may miss functions

**File:** `extractors/mod.rs:185-197`

`find_function_at_line()` uses `ep.line.saturating_sub(1)` to find the function at the endpoint's line. But endpoint lines come from regex matching on raw content (1-indexed line numbers from `enumerate()` + 1), while `ParseResult` function lines come from tree-sitter (0-indexed `row`). The off-by-one may cause misses at file boundaries.

---

## Section C: `drift_contract_tracking()` NAPI — NOT A STUB, BUT BROKEN

### C.1: Current State (Line-Verified)

**File:** `drift-napi/src/bindings/structural.rs:182-267`

The function is **real code**, not a stub:
- ✅ Creates `ExtractorRegistry` (line 187)
- ✅ Walks source files with extension filtering (line 203)
- ✅ Skips `node_modules`, `.git`, `target`, etc. (line 286)
- ✅ Calls `extract_all()` on each file (line 206)
- ✅ Runs `match_contracts()` for BE↔FE matching (line 250)
- ✅ Returns `JsContractResult` with endpoints, mismatches, counts (line 261-266)
- ✅ Has proper `JsFieldSpec`, `JsEndpoint`, `JsContractMismatch` types (lines 142-180)

### C.2: What's Broken

| ID | Bug | Severity | Fix |
|----|-----|----------|-----|
| C-01 | Calls `extract_all()` not `extract_all_with_context()` | P0 | Change line 206 |
| C-02 | No `ParseResult` — files read as raw strings, never parsed | P0 | Add `ParserManager` + parse each file |
| C-03 | Results not persisted to `contracts`/`contract_mismatches` tables | P1 | Add storage writes after extraction |
| C-04 | Not integrated into `drift_analyze()` pipeline | P1 | Add Step 5-contracts to analysis.rs |
| C-05 | Own file walker duplicates scan logic | P2 | Reuse `all_parse_results` from pipeline |
| C-06 | `paradigm_count` always 0 or 1 (line 264) | P3 | Count distinct paradigms properly |

### C.3: TS-Side Callers (All Affected)

Every TS caller receives endpoints with empty fields:

| Caller | File | Line |
|--------|------|------|
| CLI `contracts` command | `drift-cli/src/commands/contracts.ts:18` | `napi.driftContractTracking(path)` |
| MCP `drift_contracts` tool | `drift-mcp/src/tools/drift_tool.ts:320` | `loadNapi().driftContractTracking(...)` |
| CI agent contracts pass | `drift-ci/src/agent.ts:207` | `napi.driftContractTracking(config.path)` |

---

## Section D: Downstream Impact Analysis

### D.1: Systems That Work Correctly Today

| System | Status | Evidence |
|--------|--------|----------|
| Call graph resolution (all 6 strategies) | ✅ Working | `coverage_engine_test.rs` tests all 6 |
| Parser field population (10 languages) | ✅ Working | `parser_extraction_completeness_test.rs` |
| DI framework detection | ✅ Working | `e2e_di_framework_detection` test |
| Endpoint extraction (regex-based) | ✅ Working | 36 extractor tests pass |
| Breaking change detection (code) | ✅ Working | 15 breaking change tests pass |
| BE↔FE matching (code) | ✅ Working | Matching tests pass with hand-crafted fields |

### D.2: Systems Broken Due to Contract Field Gap

| System | Impact | Root Cause |
|--------|--------|------------|
| Contract mismatch detection (production) | 6/7 mismatch types never fire | B.1: `extract_all()` → empty fields |
| Breaking change detection (production) | 10/10 field-level types never fire | B.1: no fields to compare |
| Confidence scoring | 3/5 signals dead | B.6: field_overlap, type_compat always 0 |
| `contracts` table | Always empty | B.4: no write path from pipeline |
| `contract_mismatches` table | Always empty | B.4 + B.5: no write path |
| `drift_status` contract counts | Always 0 | Reads from empty tables |
| CI agent contract pass | Always passes | No mismatches detected (no fields) |

### D.3: Systems NOT Affected

| System | Why Unaffected |
|--------|---------------|
| Call graph | Independent of contracts |
| Pattern intelligence | Independent of contracts |
| Enforcement engine | Reads violations, not contracts |
| Coupling analysis | Independent |
| DNA profiling | Independent |
| Taint analysis | Uses call graph, not contracts |

---

## Section E: Implementation Plan

### Phase 1: Fix `drift_contract_tracking()` (P0, 1 day)

| Task ID | Description | File | Lines | Test |
|---------|-------------|------|-------|------|
| CT-FIX-01 | Add `ParserManager` to `drift_contract_tracking()`, parse each file to get `ParseResult` | `structural.rs:182-267` | ~15 lines added | Parse real TS/Python/Java files, verify `ParseResult` has functions |
| CT-FIX-02 | Change `registry.extract_all()` → `registry.extract_all_with_context(&content, &file_path, Some(&pr))` | `structural.rs:206` | 1 line change | Verify endpoints have non-empty `request_fields` for typed handlers |
| CT-FIX-03 | Fix `response_shape_match` to return 0.0 (not 1.0) when both sides have 0 fields | `matching.rs:103-113` | 2 lines | Test: empty fields → 0.0, not 1.0 |
| CT-TEST-01 | Integration test: parse Express+NestJS+Spring source → endpoints have fields | New test file | ~80 lines | Verify `request_fields.len() > 0` for typed handlers |
| CT-TEST-02 | Integration test: BE↔FE matching with real parsed fields → mismatches detected | New test file | ~60 lines | Verify FieldMissing, TypeMismatch fire |
| CT-TEST-03 | Integration test: confidence scoring with fields vs without → higher confidence with fields | New test file | ~40 lines | Verify 5/5 signals populated |

### Phase 2: Add Missing `extract_with_context()` Implementations (P1, 0.5 day)

| Task ID | Description | File | Lines | Test |
|---------|-------------|------|-------|------|
| CT-EXT-01 | Add `extract_with_context()` to `RailsExtractor` | `extractors/rails.rs` | ~20 lines | Rails handler with typed params → fields populated |
| CT-EXT-02 | Add `extract_with_context()` to `LaravelExtractor` | `extractors/laravel.rs` | ~20 lines | Laravel controller with typed params → fields populated |
| CT-EXT-03 | Add `extract_with_context()` to `NextJsExtractor` | `extractors/nextjs.rs` | ~20 lines | Next.js route handler with typed params → fields populated |
| CT-EXT-04 | Add `extract_with_context()` to `TrpcExtractor` | `extractors/trpc.rs` | ~20 lines | tRPC procedure with input schema → fields populated |
| CT-TEST-04 | Test all 14 extractors produce non-empty fields with typed source | New test | ~100 lines | Each extractor with realistic typed source |

### Phase 3: Wire Contracts into `drift_analyze()` Pipeline (P1, 1 day)

| Task ID | Description | File | Lines | Test |
|---------|-------------|------|-------|------|
| CT-PIPE-01 | Add `InsertContracts` BatchCommand variant + `ContractInsertRow` type | `batch/commands.rs` | ~20 lines | Compile check |
| CT-PIPE-02 | Add `InsertContractMismatches` BatchCommand variant + `ContractMismatchInsertRow` type | `batch/commands.rs` | ~15 lines | Compile check |
| CT-PIPE-03 | Add handler for `InsertContracts` in `BatchWriter` | `batch/writer.rs` | ~30 lines | BatchWriter test |
| CT-PIPE-04 | Add handler for `InsertContractMismatches` in `BatchWriter` | `batch/writer.rs` | ~25 lines | BatchWriter test |
| CT-PIPE-05 | Add Step 5-contracts to `drift_analyze()`: extract endpoints with context from cached `ParseResult`s, run matching, persist to storage | `analysis.rs` | ~60 lines | E2E: `drift_analyze()` → contracts table non-empty |
| CT-PIPE-06 | Remove duplicate file walking from `drift_contract_tracking()` — read from storage instead | `structural.rs:182-267` | Rewrite ~40 lines | `drift_contract_tracking()` returns stored data |
| CT-TEST-05 | BatchWriter test for `InsertContracts` | `batch_writer_completeness_test.rs` | ~20 lines | Roundtrip insert + query |
| CT-TEST-06 | BatchWriter test for `InsertContractMismatches` | `batch_writer_completeness_test.rs` | ~20 lines | Roundtrip insert + query |
| CT-TEST-07 | E2E: `drift_analyze()` on Express+React project → contracts + mismatches in DB | New test | ~80 lines | Verify tables populated |

### Phase 4: Fix Line Offset & Edge Cases (P2-P3, 0.5 day)

| Task ID | Description | File | Lines | Test |
|---------|-------------|------|-------|------|
| CT-EDGE-01 | Fix `find_function_at_line()` off-by-one between regex line numbers and tree-sitter row numbers | `extractors/mod.rs:185-197` | ~5 lines | Test: function at line 0 and last line of file |
| CT-EDGE-02 | Fix `paradigm_count` to count distinct paradigms (REST, GraphQL, gRPC, etc.) not just 0/1 | `structural.rs:264` | ~5 lines | Test: mixed REST + GraphQL → paradigm_count=2 |
| CT-EDGE-03 | Add `WriteStats` counters for contracts and contract_mismatches | `batch/writer.rs` | ~10 lines | Stats test |
| CT-TEST-08 | Edge case: file with 0 functions but valid route annotations → graceful empty fields | New test | ~30 lines | No panic, empty fields |
| CT-TEST-09 | Edge case: 1000+ endpoints performance test (< 5s) | New test | ~40 lines | Benchmark |

---

## Section F: Dependency Graph

```
Phase 1 (P0, 1d) ─── CT-FIX-01, CT-FIX-02, CT-FIX-03
    │
    ├── Phase 2 (P1, 0.5d) ─── CT-EXT-01..04 (can start after Phase 1)
    │
    └── Phase 3 (P1, 1d) ─── CT-PIPE-01..06 (can start after Phase 1)
            │
            └── Phase 4 (P2, 0.5d) ─── CT-EDGE-01..03 (after Phase 3)
```

**Phases 2 and 3 are parallelizable after Phase 1.**

**Critical path:** Phase 1 (1d) → Phase 3 (1d) → Phase 4 (0.5d) = **2.5 working days**
**With parallelism:** Phase 1 (1d) → {Phase 2 || Phase 3} (1d) → Phase 4 (0.5d) = **2.5 working days**
**Total with testing:** 3 working days

---

## Section G: Summary Statistics

| Metric | Count |
|--------|-------|
| **Total findings** | 13 (3 P0, 4 P1, 3 P2, 3 P3) |
| **Call graph findings** | 3 (all P3 — non-blocking) |
| **Contract extraction findings** | 7 (2 P0, 2 P1, 2 P2, 1 P3) |
| **NAPI binding findings** | 3 (1 P0, 1 P1, 1 P3) |
| **Implementation tasks** | 15 |
| **Test tasks** | 9 |
| **Total tasks** | 24 |
| **Estimated effort** | 3 working days |
| **Files to modify** | 6 source + 2 test files |

---

## Section H: Key File Reference

| File | Role | Lines |
|------|------|-------|
| `drift-napi/src/bindings/structural.rs` | NAPI binding — **primary fix target** | 828 |
| `drift-napi/src/bindings/analysis.rs` | Analysis pipeline — add contract step | ~1100 |
| `drift-analysis/src/structural/contracts/extractors/mod.rs` | Extractor trait + registry + helpers | 228 |
| `drift-analysis/src/structural/contracts/matching.rs` | BE↔FE matching + confidence | 249 |
| `drift-analysis/src/structural/contracts/breaking_changes.rs` | Breaking change classifier | 296 |
| `drift-analysis/src/structural/contracts/types.rs` | Endpoint, FieldSpec, Contract types | 183 |
| `drift-storage/src/batch/commands.rs` | BatchCommand variants — add 2 new | ~300 |
| `drift-storage/src/batch/writer.rs` | BatchWriter handlers — add 2 new | ~400 |
| `drift-storage/src/queries/structural.rs` | Contract storage queries (exist, unused) | ~1000 |
| `drift-storage/src/migrations/v005_structural.rs` | Table schemas (already migrated) | 245 |
| `drift-analysis/src/structural/contracts/extractors/rails.rs` | Missing `extract_with_context` | 156 |
| `drift-analysis/src/structural/contracts/extractors/laravel.rs` | Missing `extract_with_context` | ~80 |
| `drift-analysis/src/structural/contracts/extractors/nextjs.rs` | Missing `extract_with_context` | ~100 |
| `drift-analysis/src/structural/contracts/extractors/trpc.rs` | Missing `extract_with_context` | ~80 |

---

## Section I: Verification Commands

```bash
# After Phase 1:
cargo test -p drift-analysis --test contracts_extractors_test -- --nocapture
cargo test -p drift-napi --lib -- --nocapture
cargo clippy -p drift-napi -- -D warnings

# After Phase 2:
cargo test -p drift-analysis --test contracts_extractors_test -- extract_with_context --nocapture

# After Phase 3:
cargo test -p drift-storage --test batch_writer_completeness_test -- contract --nocapture
cargo test -p drift-napi --lib -- --nocapture
cargo clippy --all -- -D warnings

# Full verification:
cargo test --workspace -- --nocapture 2>&1 | tail -5
cargo clippy --all -- -D warnings
```

---

## Section J: What the Old Audit Documents Got Wrong

### CALL-GRAPH-AND-GRAPH-INTELLIGENCE-HARDENING-TASKS.md

| Old Claim | Reality |
|-----------|---------|
| "Only 2 of 6 strategies fire (SameFile, Fuzzy)" | **All 6 fire.** Import-based, export-based, method call, and DI resolution are all wired in `resolution.rs` and `builder.rs`. |
| "Import-based resolution dead (specifiers always empty)" | **Fixed.** `extract_import_specifiers_recursive()` at `mod.rs:948-991` populates specifiers for JS/TS/Python/Java/Rust/C#/Go/PHP/Kotlin. |
| "Export-based resolution dead (is_exported always false)" | **Fixed.** `detect_is_exported()` at `mod.rs:542` handles pub (Rust), export (JS/TS), capitalized (Go), public (Java/C#). |
| "DI resolution never called from builder.rs" | **Fixed.** `builder.rs:186-196` calls `di_support::resolve_di_injection()` as fallback after standard chain. |
| "Decorators always empty" | **Fixed.** `extract_decorators_for_node()` at `mod.rs:551` links decorators from previous siblings. |

**Root cause of stale document:** The audit was written before the call graph hardening and parser extraction work landed. An agent later audited the document instead of the code.

### CONTRACT-EXTRACTION-HARDENING-TASKS.md

| Old Claim | Reality |
|-----------|---------|
| "drift_contract_tracking() is a hardcoded empty stub" | **No longer true.** It's real code that walks files, extracts endpoints, and runs matching. But it has the `extract_all()` bug. |
| "All 14 extractors produce empty fields" | **Partially true.** 10/14 have `extract_with_context()` implementations, but the NAPI never calls it. |
| "Phase C (Field Extraction via ParseResult) not done" | **Done for 10/14 extractors.** `extract_with_context()` exists with `params_to_fields()`, `return_type_to_fields()`, `find_function_at_line()`, `extract_decorator_fields()`. |
| "Phase E (NAPI Wiring) not done" | **Partially done.** NAPI is wired to real extraction + matching, but calls wrong method. |
