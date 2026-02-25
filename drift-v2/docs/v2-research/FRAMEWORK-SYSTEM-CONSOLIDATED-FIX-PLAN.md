# Framework System — Consolidated Fix Plan

**Date:** 2026-02-10
**Input:** 3 audit reports (Parity, Best Practices, Enterprise Integration)
**Status:** Plan only — no code written yet

---

## Source Reports

| Report | Scope | Key Metric |
|--------|-------|------------|
| V1-V2 Parity | Pattern coverage | 87% parity (133 ✅, 4 ⚠️, 24 ❌) |
| Best Practices Validation | Design choices vs industry | 3 ✅ Aligned, 4 ⚠️ Improve |
| Enterprise Integration | Pipeline wiring & infrastructure | 17 gaps (3 P0, 5 P1, 6 P2, 3 P3) |

---

## Cross-Report Deduplication

Several findings appear in multiple reports. Deduplicated here to avoid double-counting effort:

| Finding | Appears In | Canonical ID |
|---------|-----------|--------------|
| FrameworkLearner unwired | Parity §4, BP §3, EIA-01/02/03 | **FIX-01** |
| OWASP 2017→2021 stale | BP Step 5, EIA-07 | **FIX-02** |
| TypeScript types/ category missing | Parity §5 (7 ❌), BP Step 7 | **FIX-03** |
| Warp patterns missing | Parity §2.2 (❌), BP Step 6 | **FIX-04** |
| detect_signals dead code | EIA-22, EIA-08, EIA-20 | **FIX-05** |
| file_patterns + type_annotations predicates | BP Step 2 | **FIX-06** |

---

## Phased Implementation Plan

### Phase 1: Correctness (P0) — 3 days

These are correctness issues. The system produces wrong or incomplete results without them.

| ID | Description | Source | Files to Modify | Effort |
|----|-------------|--------|-----------------|--------|
| **FIX-01** | Wire `FrameworkLearner` into `drift_analyze()` pipeline | EIA-01/02/03 | `analysis.rs` (insert Step 2c), `learner.rs` (verify API) | 1.5d |
| **FIX-02a** | Update OWASP 2017→2021 in TOML packs | BP Step 5 | `security.toml`, `data_access.toml` | 0.25d |
| **FIX-02b** | Add missing CWE IDs to security-relevant patterns | BP Step 5 | `security.toml`, `auth.toml` | 0.25d |
| **FIX-07** | Bad regex kills entire pack → skip per-pattern | EIA-12 | `loader.rs` (change `compile_spec` to `filter_map`) | 0.25d |
| **FIX-08** | Unknown language silently dropped → emit warning | EIA-13 | `loader.rs` (add `eprintln!` in `filter_map`) | 0.1d |
| **FIX-09** | Empty regex `""` matches everything → reject | EIA-14 | `loader.rs` (`compile_regexes`) | 0.1d |
| **FIX-10** | Add timing instrumentation for framework steps | EIA-09/10/11 | `analysis.rs` (3 `Instant::now()` + `eprintln!`) | 0.1d |

**Phase 1 detail for FIX-01 (FrameworkLearner wiring):**
- Insertion point: after Step 2b (line 311), before Step 3 (line 314)
- Need to clone packs or load twice (learner mutates state)
- Requires reconstructing `DetectionContext` from cached `all_parse_results` + `file_contents`
- Two loops: learn pass (all files) → detect pass (all files)
- Results merge into `detection_rows` + `all_matches` (same as matcher)
- Alternative: register into `VisitorRegistry` and use `DetectionEngine.run_learning_pass()` — cleaner but requires refactoring per-file loop to collect contexts

**Phase 1 tests:**
- FIX-01: Framework learning produces deviation matches for synthetic TOML packs with known frequencies
- FIX-01: Learning matches appear in `all_matches` and reach `PatternIntelligencePipeline`
- FIX-01: Learning matches are persisted as `DetectionRow` with `detection_method = "LearningDeviation"`
- FIX-07: Pack with 1 bad regex pattern compiles remaining patterns successfully
- FIX-08: Pack with `languages = ["fortran"]` logs warning, pack runs with empty language list
- FIX-09: Pattern with `content_patterns = [""]` is rejected during compilation

---

### Phase 2: Coverage Gaps (P1) — 4 days

These close the biggest user-visible gaps from the parity report.

| ID | Description | Source | Files to Modify | Effort |
|----|-------------|--------|-----------------|--------|
| **FIX-03** | Build `typescript_types.toml` (~10 patterns) | Parity ❌×7, BP Step 7 | New file: `packs/typescript_types.toml`, `registry.rs` | 1.5d |
| **FIX-06** | Add `type_annotations` + `file_patterns` predicates | BP Step 2 | `types.rs`, `loader.rs`, `matcher.rs` | 1d |
| **FIX-04** | Add 4 Warp patterns to `rust_frameworks.toml` | Parity ❌, BP Step 6 | `rust_frameworks.toml` | 0.25d |
| **FIX-11** | Add missing patterns with existing predicates | BP Step 2, Parity ❌ | Multiple TOML packs | 1d |

**FIX-11 breakdown (patterns expressible with existing predicates):**
- `config/environment-detection` → `content_patterns` in `config.toml` for `NODE_ENV`, `RAILS_ENV`, etc.
- `styling/class-naming` (BEM) → `content_patterns` in `styling.toml`
- `types/interface-vs-type` → `content_patterns` + learning in `typescript_types.toml`
- `types/type-assertions` → `content_patterns` in `typescript_types.toml`
- `types/utility-types` → `content_patterns` in `typescript_types.toml`

**FIX-06 detail (new predicates):**
- `type_annotations`: matches against `ParseResult.type_annotations` (if field exists) or `content_patterns` regex against `: any`, `: string`, etc.
- `file_patterns`: glob match on `ParseResult.file` path. Already have `DetectSignal::FilePattern` — expose as match predicate.

**Phase 2 tests:**
- FIX-03: typescript_types.toml loads, each pattern matches synthetic TS code
- FIX-06: `file_patterns` predicate matches `.d.ts` files, `types/` directories
- FIX-06: `type_annotations` predicate matches `: any`, `: unknown` in function signatures
- FIX-04: Warp patterns match `warp::path()`, `warp::Filter`, `warp::reject`

---

### Phase 3: Infrastructure (P1) — 3.5 days

Enterprise integration gaps — diagnostics, storage, and pack management.

| ID | Description | Source | Files to Modify | Effort |
|----|-------------|--------|-----------------|--------|
| **FIX-12** | Create `FrameworkDiagnostics` struct | EIA-16 | New in `frameworks/mod.rs` or `frameworks/diagnostics.rs` | 0.5d |
| **FIX-13** | Wire diagnostics into matcher + registry + analysis.rs | EIA-16/17 | `matcher.rs`, `registry.rs`, `analysis.rs` | 0.5d |
| **FIX-14** | Add detection query functions | EIA-06 | `drift-storage/src/queries/detections.rs` | 0.5d |
| **FIX-15** | Add CWE/OWASP query functions | EIA-07 | `drift-storage/src/queries/detections.rs` | 0.5d |
| **FIX-05a** | Evaluate `detect_signals` to determine active frameworks | EIA-22 | `matcher.rs` or `registry.rs` | 0.5d |
| **FIX-05b** | Persist framework detection summary | EIA-08 | `analysis.rs`, potentially new table/BatchCommand | 0.5d |
| **FIX-16** | Pack enable/disable via config | EIA-20 | `registry.rs`, `ScanConfig` or new `FrameworkConfig` | 0.5d |

**FIX-12 struct definition:**
```rust
pub struct FrameworkDiagnostics {
    pub builtin_packs_loaded: usize,
    pub builtin_packs_skipped: usize,
    pub custom_packs_loaded: usize,
    pub custom_packs_skipped: usize,
    pub total_patterns_compiled: usize,
    pub patterns_skipped: usize,
    pub files_processed: usize,
    pub files_matched: usize,
    pub total_hits: usize,
    pub hits_per_category: HashMap<String, usize>,
    pub hits_per_pack: HashMap<String, usize>,
    pub frameworks_detected: Vec<String>,
    pub learning_deviations: usize,
    pub load_time: Duration,
    pub match_time: Duration,
}
```

**FIX-14/15 new query functions:**
- `get_detections_by_method(conn, "TomlPattern") -> Vec<DetectionRow>`
- `get_detections_by_pattern_prefix(conn, "spring/") -> Vec<DetectionRow>`
- `get_detections_by_cwe(conn, 89) -> Vec<DetectionRow>`
- `get_detections_by_owasp(conn, "A03:2021") -> Vec<DetectionRow>`

**Phase 3 tests:**
- FIX-12/13: `FrameworkDiagnostics` populated correctly after analysis run
- FIX-14: Query by `detection_method = "TomlPattern"` returns only framework detections
- FIX-15: Query by CWE-89 returns SQL injection detections
- FIX-05a: `detect_signals` correctly identifies frameworks from imports/dependencies
- FIX-16: Disabled pack is not loaded by registry

---

### Phase 4: Performance (P2) — 3 days

Optimization for enterprise-scale repos (10K+ files).

| ID | Description | Source | Files to Modify | Effort |
|----|-------------|--------|-----------------|--------|
| **FIX-17** | `RegexSet` for `content_patterns` — O(lines × 1) instead of O(lines × patterns) | BP Step 4 | `loader.rs`, `matcher.rs` | 1.5d |
| **FIX-18** | Aho-Corasick for literal predicates (imports, decorators, extends, etc.) | BP Step 4 | `loader.rs`, `matcher.rs` | 1d |
| **FIX-19** | Per-file match limit (default 100) | BP Step 4 | `matcher.rs` | 0.25d |
| **FIX-05c** | Use `detect_signals` to skip irrelevant packs per-project | EIA-22 | `matcher.rs`, `analysis.rs` | 0.25d |

**FIX-17 detail:**
- At compile time: build one `RegexSet` per language from all content_patterns across all packs
- At match time: run RegexSet once per line → get set of matching pattern indices → map back to pattern IDs
- Expected: ~3-5x speedup on content_pattern matching

**Phase 4 tests:**
- FIX-17: RegexSet produces identical results to per-pattern iteration (equivalence test)
- FIX-17: Benchmark showing speedup on 100-line file with 80 patterns
- FIX-19: File with 200 matches produces at most 100 results

---

### Phase 5: Enhancements (P2-P3) — 4 days

Nice-to-have improvements. Can be deferred without impacting correctness or coverage.

| ID | Description | Source | Files to Modify | Effort |
|----|-------------|--------|-----------------|--------|
| **FIX-20** | Learning signal types: `frequency`, `presence`, `co-occurrence` | BP Step 3 | `types.rs`, `learner.rs` | 2d |
| **FIX-21** | JSON Schema for custom pack validation | BP Step 1 | New file + docs | 1d |
| **FIX-22** | Pack versioning (`version` field in TOML) | EIA-21 | `types.rs`, `loader.rs` | 0.25d |
| **FIX-23** | `drift validate-pack <file.toml>` CLI command | EIA-23 | `packages/drift-cli/src/commands/` | 0.5d |
| **FIX-24** | Framework-specific degradation alerts | EIA-19 | `analysis.rs` Step 8 | 0.25d |

---

## Dependency Graph

```
Phase 1 (Correctness, 3d)
  FIX-01 (FrameworkLearner) ──┐
  FIX-02a/b (OWASP/CWE)      │  no deps, all parallel
  FIX-07/08/09 (error handling)│
  FIX-10 (timing)             │
                              │
Phase 2 (Coverage, 4d)       │  depends on nothing (can parallel with Phase 1)
  FIX-06 (new predicates) ───┤
  FIX-03 (TS types) ─────────┤─ depends on FIX-06 for file_patterns + type_annotations
  FIX-04 (Warp) ─────────────┤
  FIX-11 (missing patterns) ──┘
                              
Phase 3 (Infrastructure, 3.5d)  depends on FIX-01 for learning diagnostics
  FIX-12/13 (diagnostics) ───┤─ after FIX-01
  FIX-14/15 (storage queries) │  no deps
  FIX-05a/b (detect_signals) ─┤  no deps
  FIX-16 (pack enable/disable)┘  no deps

Phase 4 (Performance, 3d)       depends on nothing
  FIX-17 (RegexSet) ─────────┤
  FIX-18 (Aho-Corasick) ─────┤
  FIX-19 (match limit) ──────┤
  FIX-05c (pack filtering) ──┘─ depends on FIX-05a

Phase 5 (Enhancements, 4d)      depends on FIX-01 for learning infra
  FIX-20 (signal types) ─────┤─ after FIX-01
  FIX-21 (JSON Schema) ──────┤  no deps
  FIX-22 (versioning) ────────┤  no deps
  FIX-23 (validate-pack CLI) ─┤  no deps
  FIX-24 (degradation alerts) ┘─ after FIX-01
```

---

## Execution Strategy

### With 1 engineer (serial): 17.5 days total
- Phase 1: Days 1-3
- Phase 2: Days 4-7
- Phase 3: Days 8-10.5
- Phase 4: Days 10.5-13.5
- Phase 5: Days 13.5-17.5

### With 2 engineers (parallel): 10-12 days
- **Engineer A:** Phase 1 → Phase 3 → Phase 5 (FIX-20/24)
- **Engineer B:** Phase 2 → Phase 4 → Phase 5 (FIX-21/22/23)

### Minimum Viable (P0 + P1 only): 10.5 days
- Phase 1 (3d) + Phase 2 (4d) + Phase 3 (3.5d)
- Skips performance optimization and enhancements
- Delivers: correct learning, full coverage, proper diagnostics, queryable storage

### Emergency Fix (P0 only): 3 days
- Phase 1 only
- Delivers: working FrameworkLearner, correct OWASP/CWE, resilient error handling, timing

---

## Consolidated Gap Count

| Category | P0 | P1 | P2 | P3 | Total |
|----------|----|----|----|----|-------|
| (A) Data not computed | 1 | 0 | 0 | 0 | 1 |
| (B) Data not stored | 1 | 2 | 1 | 0 | 4 |
| (C) Missing monitoring/logging | 0 | 1 | 4 | 0 | 5 |
| (D) Missing error handling | 0 | 2 | 1 | 0 | 3 |
| (E) Missing enterprise | 0 | 1 | 1 | 3 | 5 |
| (F) Coverage gaps | 0 | 4 | 0 | 0 | 4 |
| (G) Performance | 0 | 0 | 3 | 0 | 3 |
| (H) Correctness (OWASP/CWE) | 1 | 0 | 0 | 0 | 1 |
| **Total** | **3** | **10** | **10** | **3** | **26** |

---

## Files Impact Summary

| File | Phase(s) | Changes |
|------|----------|---------|
| `analysis.rs` | 1, 3 | Wire learner (Step 2c), diagnostics, detect_signals, timing |
| `loader.rs` | 1, 2, 4 | Per-pattern error recovery, new predicates, RegexSet/AC compilation, empty regex check |
| `matcher.rs` | 2, 3, 4 | New predicates, diagnostics accumulation, RegexSet/AC matching, match limit |
| `learner.rs` | 1 | Verify API, potentially add diagnostics |
| `registry.rs` | 1, 2, 3 | Per-pack error tracking, register new pack, pack enable/disable, detect_signals |
| `types.rs` | 2, 5 | New predicate fields, version field, signal types |
| `security.toml` | 1 | OWASP update, CWE additions |
| `auth.toml` | 1 | CWE additions |
| `config.toml` | 2 | Environment detection patterns |
| `styling.toml` | 2 | BEM class naming patterns |
| `rust_frameworks.toml` | 2 | Warp patterns |
| `typescript_types.toml` | 2 | NEW — ~10 patterns |
| `detections.rs` (storage) | 3 | 4 new query functions |
| `frameworks/diagnostics.rs` | 3 | NEW — FrameworkDiagnostics struct |

---

## Quality Gates

Each phase must pass before proceeding:

| Phase | Gate |
|-------|------|
| 1 | `cargo test -p drift-analysis` (all existing + new framework learning tests pass), `cargo clippy -p drift-analysis -p drift-napi -- -D warnings` clean |
| 2 | New predicate tests pass, typescript_types.toml loads with 10+ patterns, Warp patterns match |
| 3 | Storage query tests pass (roundtrip: write detection → query by method/CWE), diagnostics struct populated |
| 4 | Equivalence test: RegexSet results == per-pattern results for all 261 patterns. Benchmark shows measurable improvement. |
| 5 | Learning signal types produce correct output for `frequency`/`presence`/`co-occurrence` scenarios |
