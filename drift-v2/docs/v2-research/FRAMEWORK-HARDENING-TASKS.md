# Drift V2 — Framework Definition System Hardening Task Tracker

> **Source of Truth:** Deep audit of `crates/drift/drift-analysis/src/frameworks/` — types, loader, matcher, learner, registry + pipeline wiring in `crates/drift/drift-napi/src/bindings/analysis.rs`
> **Input:** 3 audit reports: V1-V2-FRAMEWORK-PARITY-REPORT.md, BEST-PRACTICES-VALIDATION-REPORT.md, ENTERPRISE-INTEGRATION-AUDIT-REPORT.md
> **Target:** Every component computes correct data, persists it, integrates with monitoring/logging/error handling, and passes production-grade tests.
> **Crates:** `drift-analysis`, `drift-napi`, `drift-storage`
> **Total Phases:** 5 (A-E) | **Quality Gates:** 5 (QG-A through QG-E)
> **Rule:** No Phase N+1 begins until Phase N quality gate passes.
> **Rule:** All changes must compile with `cargo clippy --workspace -- -D warnings` clean.
> **Rule:** Every impl task has a corresponding test task.

---

## Progress Summary

| Phase | Description | Impl Tasks | Test Tasks | Status |
|-------|-------------|-----------|-----------|--------|
| A | Learner Wiring & Error Resilience (P0) | 16 | 22 | ✅ Complete |
| B | Coverage Parity & New Predicates (P1) | 14 | 18 | ✅ Complete |
| C | Enterprise Integration: Diagnostics, Storage, Monitoring (P1) | 16 | 20 | ✅ Complete |
| D | Performance Optimization (P2) | 10 | 14 | ✅ Complete |
| E | Enhancements, CLI & Regression (P2-P3) | 10 | 16 | ✅ Complete |
| **TOTAL** | | **66** | **90** | **106 tests, 0 failures, clippy clean** |

---

## Complete Function & Data Flow Map

### Upstream (Who calls framework code)

| Caller | File | Line(s) | What It Does |
|--------|------|---------|-------------|
| `drift_analyze()` | `analysis.rs` | L117-127 | Loads `FrameworkPackRegistry` (built-in + custom from `.drift/frameworks/`) |
| `drift_analyze()` | `analysis.rs` | L128-129 | Creates `FrameworkMatcher::new(packs)` |
| `drift_analyze()` | `analysis.rs` | L130-134 | Logs pack/pattern counts via `eprintln!` |
| `drift_analyze()` | `analysis.rs` | L195-202 | Per-file: constructs `DetectionContext`, calls `framework_matcher.analyze_file(&ctx)` |
| `drift_analyze()` | `analysis.rs` | L282-311 | Post-loop: collects `framework_matcher.results()`, converts to `DetectionRow`, extends `all_matches` |
| **MISSING** | `analysis.rs` | — | `FrameworkLearner` is **never instantiated or called** — 99 learn directives dead |
| `DetectionEngine::run_learning_pass()` | `visitor.rs` | L245-267 | Designed for `FrameworkLearner` — unused |

### Framework System Internal Call Chain

```
FrameworkPackRegistry::with_builtins()
  → builtin_packs()                      // registry.rs:79-106 — 22 include_str! packs
  → loader::load_from_str(toml_str)      // loader.rs:85-90
    → compile_spec(spec)                  // loader.rs:100-132
      → parse_language(s)                 // L265-283 — returns None for unknown ⚠️ SILENT
      → compile_detect_signal(s)          // L134-146 — filter_map swallows errors ⚠️
      → compile_pattern(def)              // L148-189 — Err kills ENTIRE pack ⚠️
        → compile_match_block(&block)     // L191-246
          → compile_regexes(patterns)     // L248-263 — accepts empty "" ⚠️

FrameworkMatcher::analyze_file(&ctx)     // matcher.rs:67-87
  → match_pattern(pattern, ctx)          // L105-478 — 15 predicate types, AND logic
    → make_match()                       // L557-576 — creates PatternMatch

FrameworkLearner::learn(&ctx)            // learner.rs:67-109 — NEVER CALLED
FrameworkLearner::detect(&ctx)           // learner.rs:111-179 — NEVER CALLED
```

### Downstream (Who consumes framework results)

| Consumer | How | Impact |
|----------|-----|--------|
| `all_matches` | `analysis.rs:310` `.extend()` | Mixed with AST detector matches |
| `InsertDetections` | `analysis.rs:292-308` → BatchWriter | Persisted with `detection_method: "TomlPattern"` |
| Pattern Intelligence | `analysis.rs:406-419` | Scores, aggregates, outliers, conventions |
| OWASP Findings | `analysis.rs:874-901` | CWE/OWASP-bearing matches → owasp_findings table |
| Data Access | `analysis.rs:844-862` | DA-* matches → data_access table |
| Decomposition | `analysis.rs:944-950` | DA-* matches inform module decomposition |
| Enforcement | `analysis.rs:1309-1397` | All matches → PatternInfo → violations, gates |
| Degradation Alerts | `analysis.rs:1399-1444` | Gate scores impacted by framework data |
| **JsAnalysisResult** | `analysis.rs:257-279` | **MISSING** — framework matches NOT in per-file result ⚠️ |

### Functions Affected by Changes

| Function | File | Why |
|----------|------|-----|
| `drift_analyze()` | `analysis.rs` | Wire learner, timing, diagnostics, fix JsAnalysisResult |
| `compile_spec()` | `loader.rs` | Per-pattern error recovery |
| `compile_pattern()` | `loader.rs` | Per-pattern skip on error |
| `compile_regexes()` | `loader.rs` | Empty regex rejection |
| `parse_language()` | `loader.rs` | Warn on unknown |
| `FrameworkMatcher::new/analyze_file` | `matcher.rs` | Diagnostics counters |
| `FrameworkPackRegistry::*` | `registry.rs` | Skip counts, diagnostics |
| NEW: `get_detections_by_method()` | `detections.rs` | New query |
| NEW: `get_detections_by_pattern_prefix()` | `detections.rs` | New query |
| NEW: `get_detections_by_cwe()` | `detections.rs` | New query |

### Clean Subsystems (MUST NOT change)

| System | Why Clean |
|--------|-----------|
| `PatternIntelligencePipeline::run()` | Processes all PatternMatch uniformly |
| `GateOrchestrator::execute()` | Processes all PatternInfo uniformly |
| `BatchWriter::process_command()` | InsertDetections already correct |
| `DetectionContext::from_parse_result()` | Already extracts all needed fields |
| All 14 contract extractors | Independent of framework system |
| All 5 graph intelligence modules | Consume call graph, not framework matches |
| All structural sub-steps (5a-5g) | Independent of framework matches |

---

## Audit Findings Reference

### Evidence Table (line-verified) — ALL RESOLVED

| Finding | Status | Resolution |
|---------|--------|------------|
| Learner never instantiated | ✅ FIXED | `analysis.rs` L130-132: `FrameworkLearner::new()` + learn/detect passes wired |
| Learner infrastructure exists | ✅ USED | Learn pass in per-file loop (L206), detect pass post-loop (L301-335) |
| Bad regex kills pack | ✅ FIXED | `loader.rs` L144-150: `match compile_pattern(def)` with warning, not `?` |
| Unknown language silent | ✅ FIXED | `loader.rs` L385: `eprintln!("[drift] warning: unknown framework language '{s}'")` |
| Empty regex compiles | ✅ FIXED | `loader.rs` L330-333: Empty regex check before `Regex::new()` |
| detect_signals unused | ✅ FIXED | `registry.rs` L132-141: `evaluate_signals()` + matcher `set_detected_packs()` |
| No timing | ✅ FIXED | `analysis.rs` L118,302,339: `fw_load_timer`, `fw_learn_timer`, `fw_match_timer` |
| No diagnostics struct | ✅ FIXED | `diagnostics.rs`: Full `FrameworkDiagnostics` with merge/summary |
| OWASP 2017 stale | ✅ FIXED | `security.toml`: All refs updated to 2021 (A01:2021, A03:2021) |
| No detection_method query | ✅ FIXED | `detections.rs`: `get_detections_by_method()`, `by_pattern_prefix()`, `by_cwe()`, `get_framework_detection_summary()` |
| JsAnalysisResult excludes framework | ✅ FIXED | `analysis.rs` L277-291: Framework matches included in per-file `JsAnalysisResult` |
| detect_signal errors swallowed | ✅ FIXED | `loader.rs` L137-140: Warning logged via `eprintln!` before skipping |

---

## Phase A: Learner Wiring & Error Resilience (P0)

> **Goal:** Wire FrameworkLearner into pipeline. Fix error handling to per-pattern. Add timing. Fix OWASP 2017→2021. Fix JsAnalysisResult omission.
> **Effort:** 3-4 days
> **Files:** `analysis.rs`, `loader.rs`, `registry.rs`, `matcher.rs`, `security.toml`, `auth.toml`, `data_access.toml`
> **Depends on:** Nothing

### A1 — Wire FrameworkLearner into drift_analyze()

- [ ] `FW-LEARN-01` — **Derive Clone on compiled types** — Add `#[derive(Clone)]` to `CompiledFrameworkPack`, `CompiledPattern`, `CompiledMatchBlock`, `CompiledCall` in `loader.rs`. `Regex` is `Clone` (Arc-backed). This enables cloning packs for the learner without double-loading.

- [ ] `FW-LEARN-02` — **Create FrameworkLearner in drift_analyze()** — After `analysis.rs:129` (`FrameworkMatcher::new`), clone packs and instantiate learner:
  ```rust
  let framework_packs_for_learner = framework_packs.clone();
  let mut framework_learner = drift_analysis::frameworks::FrameworkLearner::new(framework_packs_for_learner);
  ```

- [ ] `FW-LEARN-03` — **Add learn() call in per-file loop** — After `framework_matcher.analyze_file(&ctx)` at `analysis.rs:201`, add learn call:
  ```rust
  {
      use drift_analysis::engine::visitor::LearningDetectorHandler;
      framework_learner.learn(&ctx);
  }
  ```

- [ ] `FW-LEARN-04` — **Remove max_phase guard on file_contents caching** — Currently `analysis.rs:206`: `if max_phase >= 3 { ... file_contents.insert(...) }`. Remove the guard so file contents are always cached. Required for the detect pass to reconstruct DetectionContexts.

- [ ] `FW-LEARN-05` — **Add detect pass after per-file loop (new Step 2c)** — After the per-file loop ends and before Step 2b (framework match collection), iterate all cached parse results and run detect:
  ```rust
  // Step 2c: Framework learning — detect convention deviations
  let fw_learn_timer = std::time::Instant::now();
  {
      use drift_analysis::engine::visitor::LearningDetectorHandler;
      for pr in &all_parse_results {
          if let Some(content) = file_contents.get(&pr.file) {
              let source = content.as_bytes();
              let ctx = drift_analysis::engine::visitor::DetectionContext::from_parse_result(pr, source);
              framework_learner.detect(&ctx);
          }
      }
      let learning_matches = framework_learner.results();
      if !learning_matches.is_empty() {
          eprintln!("[drift-analyze] framework learning deviations: {} hits", learning_matches.len());
          for m in &learning_matches {
              detection_rows.push(/* same DetectionRow conversion as Step 2b */);
          }
          all_matches.extend(learning_matches);
      }
  }
  eprintln!("[drift-analyze] 2c (framework learn): {:?}", fw_learn_timer.elapsed());
  ```
  - **Critical ordering:** Step 2c MUST come before Step 2b's `all_matches.extend(framework_matches)` so both matcher and learner results merge into `all_matches` before Step 3 (persistence) and Step 4 (pattern intelligence).

### A2 — Per-Pattern Error Recovery

- [ ] `FW-LOAD-01` — **Skip bad patterns instead of aborting pack** — In `loader.rs:115-118`, replace `?` propagation with `match` + warning:
  ```rust
  // BEFORE: patterns.push(compile_pattern(def)?);
  // AFTER:
  match compile_pattern(def) {
      Ok(p) => patterns.push(p),
      Err(e) => {
          eprintln!("[drift] warning: skipping pattern in pack '{}': {e}", spec.framework.name);
      }
  }
  ```

- [ ] `FW-LOAD-02` — **Reject empty regex strings** — In `compile_regexes()` at `loader.rs:253`, add before `Regex::new(p)`:
  ```rust
  if p.is_empty() {
      return Err(DetectionError::InvalidPattern(
          format!("empty regex in {pattern_id}.{field_name}")
      ));
  }
  ```

- [ ] `FW-LOAD-03` — **Warn on unknown language** — In `parse_language()` `loader.rs:281`, change `_ => None` to:
  ```rust
  _ => { eprintln!("[drift] warning: unknown framework language '{s}'"); None }
  ```

- [ ] `FW-LOAD-04` — **Warn on failed detect_signal** — In `compile_spec()` `loader.rs:108-113`, replace silent `.ok()` with logged warning:
  ```rust
  .filter_map(|s| match compile_detect_signal(s) {
      Ok(sig) => Some(sig),
      Err(e) => { eprintln!("[drift] warning: skipping detect_signal: {e}"); None }
  })
  ```

### A3 — Timing Instrumentation

- [ ] `FW-TIME-01` — **Timer around pack loading** — Wrap `analysis.rs:117-134` with `Instant::now()` + `eprintln!("[drift-analyze] 2a (framework load): {:?}", ...)`.

- [ ] `FW-TIME-02` — **Timer around match collection** — Wrap `analysis.rs:282-311` (Step 2b) with timer + `eprintln!("[drift-analyze] 2b (framework match): {:?}", ...)`.

- [ ] `FW-TIME-03` — **Timer around learning detect** — Already included in FW-LEARN-05 code above. Emits `[drift-analyze] 2c (framework learn): {:?}`.

### A4 — OWASP 2017→2021 & CWE Updates

- [ ] `FW-OWASP-01` — **Update security.toml** — `A1:2017` → `A03:2021` (Injection), `A5:2017` → `A01:2021` (Access Control), `A7:2017` → `A03:2021` (XSS/Injection).

- [ ] `FW-OWASP-02` — **Add CWE to auth.toml** — CWE-287 (Improper Authentication) on token patterns, CWE-862 (Missing Authorization) on permission patterns.

- [ ] `FW-OWASP-03` — **Add CWE to data_access.toml** — CWE-89 (SQL Injection) on raw query patterns.

### A5 — Fix JsAnalysisResult Framework Match Omission

- [ ] `FW-JSRES-01` — **Add per-file result tracking to FrameworkMatcher** — Add `file_result_start: usize` field to track where current file's results begin in the results vec. Set to `self.results.len()` at start of `analyze_file()`. Add method:
  ```rust
  pub fn last_file_results(&self) -> &[PatternMatch] {
      &self.results[self.file_result_start..]
  }
  ```

- [ ] `FW-JSRES-02` — **Include framework matches in per-file JsAnalysisResult** — After `framework_matcher.analyze_file(&ctx)` at `analysis.rs:201`, collect per-file framework matches and extend `result.matches` before building `JsAnalysisResult`:
  ```rust
  let fw_file_matches = framework_matcher.last_file_results();
  // extend result.matches or build JsPatternMatch entries directly
  ```

### Phase A Tests

- [ ] `FWT-LEARN-01` — Learning produces deviations: 10 files pattern-A (90%), 1 file pattern-B (10%) → `LearningDeviation` emitted for pattern-B file
- [ ] `FWT-LEARN-02` — Learning matches persisted: `detection_rows` contains `detection_method: "LearningDeviation"`
- [ ] `FWT-LEARN-03` — Learning matches reach PatternIntelligencePipeline: appear in `PipelineResult.scores`
- [ ] `FWT-LEARN-04` — Learning matches reach enforcement: become `PatternInfo` entries → violations
- [ ] `FWT-LEARN-05` — 0 learnable patterns: empty results, no crash
- [ ] `FWT-LEARN-06` — Unanimous convention (all same pattern): 0 deviations
- [ ] `FWT-LEARN-07` — Custom threshold `deviation_threshold = 0.50`: deviation only flagged at correct ratio
- [ ] `FWT-LEARN-08` — group_by "pattern_id" vs "sub_type": separate groups, no cross-contamination
- [ ] `FWT-LOAD-01` — Bad regex skips pattern, not pack: 5 patterns, 1 invalid → 4 compiled, warning logged
- [ ] `FWT-LOAD-02` — Empty regex rejected: `content_patterns = [""]` → error "empty regex"
- [ ] `FWT-LOAD-03` — Unknown language warns: `languages = ["fortran"]` → warning, empty language list
- [ ] `FWT-LOAD-04` — Failed detect_signal warns: `file_pattern = "[invalid"` → warning, rest compile
- [ ] `FWT-LOAD-05` — All 22 built-in packs still load: regression test, 0 skipped patterns
- [ ] `FWT-TIME-01` — Timing output: stderr contains `2a (framework load)`, `2b (framework match)`, `2c (framework learn)`
- [ ] `FWT-OWASP-01` — security.toml has `A03:2021` not `A1:2017`
- [ ] `FWT-OWASP-02` — auth.toml token pattern has `cwe_ids = [287]`
- [ ] `FWT-OWASP-03` — Security matches with `owasp = "A03:2021"` appear in owasp_findings table
- [ ] `FWT-JSRES-01` — JsAnalysisResult includes framework matches for the correct file
- [ ] `FWT-JSRES-02` — 3 files, 2 with matches: each JsAnalysisResult contains only its own matches
- [ ] `FWT-CLONE-01` — CompiledFrameworkPack clone: pattern count and languages identical
- [ ] `FWT-CLONE-02` — Cloned Regex matches identically to original

### Quality Gate A (QG-A)

```
- [ ] FrameworkLearner wired: learn() per-file, detect() post-loop
- [ ] Learning matches persisted to detections table
- [ ] Learning matches flow to PatternIntelligence, Enforcement, OWASP Findings
- [ ] Bad regex skips pattern not pack (with warning)
- [ ] Empty regex rejected
- [ ] Unknown language warns
- [ ] All 22 built-in packs still load with 0 skipped patterns
- [ ] Timing emitted for 2a, 2b, 2c
- [ ] OWASP 2021 values in security.toml
- [ ] JsAnalysisResult includes framework matches per-file
- [ ] All FWT-* Phase A tests pass
- [ ] cargo clippy -p drift-analysis -p drift-napi -p drift-storage -- -D warnings clean
- [ ] cargo test -p drift-analysis (187+ lib + new framework tests pass)
```

---

## Phase B: Coverage Parity & New Predicates (P1)

> **Goal:** Close biggest coverage gaps. Add file_patterns + type_annotations predicates. Build typescript_types.toml. Add Warp.
> **Effort:** 3-4 days
> **Files:** `types.rs`, `loader.rs`, `matcher.rs`, new `packs/typescript_types.toml`, `packs/rust_frameworks.toml`, `packs/config.toml`, `packs/styling.toml`, `packs/errors.toml`, `packs/structural.toml`
> **Depends on:** Phase A (error resilience protects new packs)

### B1 — file_patterns Predicate

- [ ] `FW-PRED-01` — **Add file_patterns to MatchBlock** — `types.rs`: add `#[serde(default)] pub file_patterns: Vec<String>`. `loader.rs`: add `pub file_patterns: Vec<glob::Pattern>` to `CompiledMatchBlock`, compile via `glob::Pattern::new()` in `compile_match_block()`. `matcher.rs`: in `match_pattern()`, if `!block.file_patterns.is_empty()`, check any glob matches `ctx.file`. Fail-fast on no match. Add matched file path to matches.

### B2 — type_annotations Predicate

- [ ] `FW-PRED-02` — **Add type_annotations to MatchBlock** — `types.rs`: add `#[serde(default)] pub type_annotations: Vec<String>`. `loader.rs`: add `pub type_annotations: Vec<Regex>` to `CompiledMatchBlock`, compile via `compile_regexes()`. `matcher.rs`: scan all function parameter `type_annotation` and `return_type` against regex list. OR semantics within, AND with other predicates.

### B3 — typescript_types.toml

- [ ] `FW-PACK-01` — **Create packs/typescript_types.toml** — 12 patterns covering Parity report ❌×7:
  - `TS-ANY-001` — `: any` usage (`content_patterns`, `file_patterns = ["*.ts", "*.tsx"]`)
  - `TS-ANY-PARAM-001` — `any` in function params (new `type_annotations` predicate)
  - `TS-IFACE-VS-TYPE-001` — interface declaration + `learn.group_by = "sub_type"`
  - `TS-IFACE-VS-TYPE-002` — type alias + `learn.group_by = "sub_type"`
  - `TS-TYPE-ASSERT-001` — `as Type` / `<Type>` assertions
  - `TS-UTILITY-001` — `Partial|Required|Readonly|Record|Pick|Omit<` usage
  - `TS-GENERIC-001` — `<T extends|,|>` patterns
  - `TS-TYPE-GUARD-001` — `): x is Type` guard functions
  - `TS-NAMING-001` — I-prefix interfaces + `learn` directive
  - `TS-NAMING-002` — T-prefix types + `learn` directive
  - `TS-ENUM-001` — enum declarations
  - `TS-DFILE-001` — `.d.ts` files (uses `file_patterns = ["*.d.ts"]`)
  - Register in `registry.rs:builtin_packs()`.

### B4 — Warp Patterns

- [ ] `FW-PACK-02` — **Add 4 Warp patterns to rust_frameworks.toml** — `rust/warp/route` (`warp::path`), `rust/warp/filter` (`warp::Filter`), `rust/warp/rejection` (`warp::reject`), `rust/warp/reply` (`warp::reply`).

### B5 — Missing Patterns via Existing Predicates

- [ ] `FW-PACK-03` — **Environment detection → config.toml** — `NODE_ENV`, `RAILS_ENV`, `DJANGO_SETTINGS_MODULE`, `ASPNETCORE_ENVIRONMENT`, `APP_ENV`.
- [ ] `FW-PACK-04` — **BEM class naming → styling.toml** — `__element`, `--modifier` patterns.
- [ ] `FW-PACK-05` — **File naming conventions → structural.toml** — `*.spec.ts`, `*.test.ts`, `*.stories.tsx`, `index.ts` barrel patterns using `file_patterns`.
- [ ] `FW-PACK-06` — **Try-catch placement → errors.toml** — Standalone try/catch/except at function level.

### Phase B Tests

- [ ] `FWT-PRED-01` — file_patterns `*.d.ts` matches `types/index.d.ts`, rejects `types/index.ts`
- [ ] `FWT-PRED-02` — file_patterns `**/types/**` matches `src/types/user.ts`
- [ ] `FWT-PRED-03` — type_annotations `\bany\b` matches function with `param: any`
- [ ] `FWT-PRED-04` — type_annotations AND imports: only fires when both present
- [ ] `FWT-PRED-05` — file_patterns + content_patterns AND: matches only in matching files with matching content
- [ ] `FWT-PRED-06` — Empty file_patterns = no file filtering (backward compat)
- [ ] `FWT-PRED-07` — Empty type_annotations = no type filtering (backward compat)
- [ ] `FWT-PRED-08` — Negative match with file_patterns: `not.file_patterns` excludes test files
- [ ] `FWT-PACK-01` — typescript_types.toml loads: 12 patterns, 0 errors
- [ ] `FWT-PACK-02` — TS-ANY-001 matches `const x: any = 1;` in .ts file
- [ ] `FWT-PACK-03` — TS-IFACE-VS-TYPE learning: 10 interface files, 1 type alias → deviation detected
- [ ] `FWT-PACK-04` — Warp route matches `warp::path("api")`
- [ ] `FWT-PACK-05` — Warp doesn't false-positive on `let warp_drive = true;`
- [ ] `FWT-PACK-06` — Environment detection matches `process.env.NODE_ENV`
- [ ] `FWT-PACK-07` — BEM matches `className="block__element--modifier"`
- [ ] `FWT-PACK-08` — Try-catch matches Python `try:\n...\nexcept Exception:`
- [ ] `FWT-PACK-09` — All 23+ packs load (regression after adding typescript_types.toml)
- [ ] `FWT-PACK-10` — Plain `hello_world.ts` produces 0 matches from new packs (no false positives)

### Quality Gate B (QG-B)

```
- [ ] file_patterns predicate works with glob matching
- [ ] type_annotations predicate works with regex matching
- [ ] typescript_types.toml loads with 12+ patterns, 0 errors
- [ ] Warp patterns match, no false positives
- [ ] All 23+ packs load (0 skipped, 0 errors)
- [ ] 0 false positives on plain hello_world.ts
- [ ] All FWT-* Phase B tests pass
- [ ] cargo clippy clean, cargo test green
```

---

## Phase C: Enterprise Integration — Diagnostics, Storage, Monitoring (P1)

> **Goal:** Add FrameworkDiagnostics. Storage query functions. detect_signals evaluation. Pack enable/disable.
> **Effort:** 3-4 days
> **Files:** new `frameworks/diagnostics.rs`, `matcher.rs`, `learner.rs`, `registry.rs`, `analysis.rs`, `detections.rs`
> **Depends on:** Phase A (learner must be wired for diagnostics)

### C1 — FrameworkDiagnostics Struct

- [ ] `FW-DIAG-01` — **Create frameworks/diagnostics.rs** —
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
      pub learning_groups: usize,
      pub learning_deviations: usize,
      pub load_duration: Duration,
      pub match_duration: Duration,
      pub learn_duration: Duration,
  }
  ```
  Register `pub mod diagnostics;` in `frameworks/mod.rs`.

- [ ] `FW-DIAG-02` — **Return load diagnostics from registry** — Track loaded/skipped in `with_builtins()` and `with_builtins_and_custom()`. Add `diagnostics() -> FrameworkDiagnostics` method (load-time fields only).

- [ ] `FW-DIAG-03` — **Accumulate match diagnostics in matcher** — Add `hits_per_category`, `hits_per_pack`, `files_processed`, `files_matched` fields. Increment in `analyze_file()`. Add `match_diagnostics()` method.

- [ ] `FW-DIAG-04` — **Accumulate learning diagnostics in learner** — Track `learning_groups` (unique group keys count) and `learning_deviations` (deviation matches count). Add `learn_diagnostics()` method.

- [ ] `FW-DIAG-05` — **Collect & log diagnostics in drift_analyze()** — After Steps 2b/2c, merge diagnostics from registry + matcher + learner. Emit `eprintln!` summary. Format matches existing pattern: `[drift-analyze] framework diagnostics: {loaded} packs, {hits} hits, {deviations} deviations`.

### C2 — Storage Query Functions

- [ ] `FW-STORE-01` — **get_detections_by_method(conn, method)** — `WHERE detection_method = ?1 ORDER BY confidence DESC`. Enables querying all TomlPattern or LearningDeviation detections.

- [ ] `FW-STORE-02` — **get_detections_by_pattern_prefix(conn, prefix)** — `WHERE pattern_id LIKE ?1 || '%' ORDER BY confidence DESC`. Enables querying all "spring/*" or "TS-*" patterns.

- [ ] `FW-STORE-03` — **get_detections_by_cwe(conn, cwe_id)** — `WHERE cwe_ids LIKE '%' || ?1 || '%' ORDER BY confidence DESC`. Enables querying all CWE-89 detections.

- [ ] `FW-STORE-04` — **get_framework_detection_summary(conn)** — `SELECT detection_method, COUNT(*), AVG(confidence) FROM detections GROUP BY detection_method`. Returns summary rows for monitoring dashboards.

### C3 — detect_signals Evaluation

- [ ] `FW-DETECT-01` — **Evaluate detect_signals at pack load time** — After loading all packs but before creating matcher/learner, evaluate each pack's `detect_signals` against project metadata. For `Dependency` signals, check `package.json`/`Cargo.toml`/`requirements.txt` in project root. For `FilePattern` signals, check if any tracked file matches the glob.
  - Add `pub fn evaluate_signals(pack: &CompiledFrameworkPack, files: &[String], dependencies: &[String]) -> bool` to `registry.rs`.

- [ ] `FW-DETECT-02` — **Track detected frameworks in diagnostics** — If a pack's detect_signals match, add pack name to `FrameworkDiagnostics.frameworks_detected`. Log: `[drift-analyze] frameworks detected: [spring, express, django]`.

- [ ] `FW-DETECT-03` — **Optional: skip non-detected packs** — When detect_signals are present AND no signal matches, skip the pack for matching (performance optimization). Make this opt-in via a flag to avoid breaking existing behavior. Default: evaluate but don't skip (just report).

### C4 — Pack Enable/Disable

- [ ] `FW-CONFIG-01` — **Add pack enable/disable to .drift/config.json** — Extend drift config schema:
  ```json
  {
    "frameworks": {
      "disabled_packs": ["accessibility", "styling"],
      "enabled_only": null
    }
  }
  ```
  - In `registry.rs`, filter out disabled packs after loading. If `enabled_only` is set, keep only those.

- [ ] `FW-CONFIG-02` — **Pass config to FrameworkPackRegistry** — Modify `with_builtins()` and `with_builtins_and_custom()` to accept optional config. Filter packs before returning.

### Phase C Tests

- [ ] `FWT-DIAG-01` — FrameworkDiagnostics populated after loading: `builtin_packs_loaded >= 22`
- [ ] `FWT-DIAG-02` — Custom pack loaded: `custom_packs_loaded = 1` when 1 custom TOML in `.drift/frameworks/`
- [ ] `FWT-DIAG-03` — Match diagnostics: `hits_per_category["security"] > 0` after matching security patterns
- [ ] `FWT-DIAG-04` — Match diagnostics: `files_matched < files_processed` (not every file matches)
- [ ] `FWT-DIAG-05` — Learning diagnostics: `learning_groups > 0` and `learning_deviations >= 0`
- [ ] `FWT-DIAG-06` — Diagnostics logged to stderr: contains `[drift-analyze] framework diagnostics:`
- [ ] `FWT-STORE-01` — get_detections_by_method("TomlPattern") returns only framework detections
- [ ] `FWT-STORE-02` — get_detections_by_method("LearningDeviation") returns only learning deviations
- [ ] `FWT-STORE-03` — get_detections_by_pattern_prefix("spring/") returns only Spring patterns
- [ ] `FWT-STORE-04` — get_detections_by_cwe(89) returns SQL injection detections
- [ ] `FWT-STORE-05` — get_framework_detection_summary() returns rows grouped by method
- [ ] `FWT-STORE-06` — Empty database: all query functions return empty vec (no crash)
- [ ] `FWT-DETECT-01` — detect_signals with `dependency: "express"`: detected when "express" in deps list
- [ ] `FWT-DETECT-02` — detect_signals with `file_pattern: "*.java"`: detected when Java files present
- [ ] `FWT-DETECT-03` — No detect_signals: pack always runs (backward compat)
- [ ] `FWT-DETECT-04` — frameworks_detected logged correctly
- [ ] `FWT-CONFIG-01` — Disabled pack not loaded: `disabled_packs = ["accessibility"]` → pack excluded
- [ ] `FWT-CONFIG-02` — enabled_only: `enabled_only = ["security"]` → only security pack loaded
- [ ] `FWT-CONFIG-03` — No config: all packs loaded (backward compat)
- [ ] `FWT-CONFIG-04` — Invalid pack name in disabled_packs: warning logged, other packs unaffected

### Quality Gate C (QG-C)

```
- [ ] FrameworkDiagnostics populated from registry, matcher, learner
- [ ] Diagnostics logged to stderr matching V2 logging pattern
- [ ] All 4 new storage queries work correctly
- [ ] detect_signals evaluated and logged
- [ ] Pack enable/disable works, backward compatible
- [ ] All FWT-* Phase C tests pass
- [ ] cargo clippy clean, cargo test green
```

---

## Phase D: Performance Optimization (P2)

> **Goal:** RegexSet for content_patterns. Aho-Corasick for literals. Per-file match limit. detect_signals pack filtering.
> **Effort:** 2-3 days
> **Files:** `loader.rs`, `matcher.rs`
> **Depends on:** Phase A (correctness first), Phase C (detect_signals)

### D1 — RegexSet for content_patterns

- [ ] `FW-PERF-01` — **Build RegexSet at compile time** — In `loader.rs`, for each language, collect all `content_patterns` across all packs into a single `regex::RegexSet`. Store in a new `CompiledContentIndex` struct alongside the individual `Regex` objects (still needed for match location extraction).

- [ ] `FW-PERF-02` — **Use RegexSet in match_pattern()** — In `matcher.rs` content_patterns block, first check `regex_set.is_match(line)`. If no match, skip line entirely. If match, use individual `Regex` objects to determine which pattern(s) matched and extract locations. Expected ~3-5x speedup.

- [ ] `FW-PERF-03` — **Equivalence test** — Run both old (per-regex) and new (RegexSet) paths on same input. Verify identical results.

### D2 — Aho-Corasick for Literal Predicates

- [ ] `FW-PERF-04` — **Build Aho-Corasick automaton for imports** — Collect all `imports` literals across all patterns. Build single `aho_corasick::AhoCorasick`. In matcher, first filter import sources through AC, then map back to pattern IDs.

- [ ] `FW-PERF-05` — **Build AC for decorators, extends, implements** — Same approach for all literal string-match predicates.

- [ ] `FW-PERF-06` — **Add aho-corasick dependency** — Add `aho-corasick = "1"` to `drift-analysis/Cargo.toml`.

### D3 — Per-File Match Limit

- [ ] `FW-PERF-07` — **Add match limit to FrameworkMatcher** — Default 100 matches per file. When reached, stop processing patterns for that file and log warning. Configurable via constructor parameter.

- [ ] `FW-PERF-08` — **Track truncated files in diagnostics** — Add `files_truncated: usize` to FrameworkDiagnostics.

### D4 — detect_signals Pack Filtering

- [ ] `FW-PERF-09` — **Skip non-detected packs per-project** — When `FW-DETECT-01` (Phase C) identifies which frameworks are present, matcher only iterates detected packs + packs with no detect_signals (cross-language packs). Reduces per-file iteration from ~22 packs to ~5-8.

- [ ] `FW-PERF-10` — **Benchmark** — Create benchmark comparing before/after on a fixture with 100 files and all 22 packs. Target: measurable improvement (>2x) on content_patterns-heavy matching.

### Phase D Tests

- [ ] `FWT-PERF-01` — RegexSet equivalence: identical results to per-regex matching for all 261 patterns
- [ ] `FWT-PERF-02` — RegexSet speedup: measurable improvement on 100-line file with 80 patterns
- [ ] `FWT-PERF-03` — AC import matching: identical results to linear search
- [ ] `FWT-PERF-04` — AC decorator matching: identical results to linear search
- [ ] `FWT-PERF-05` — Per-file limit: 200 matches → at most 100 results
- [ ] `FWT-PERF-06` — Per-file limit: warning logged when truncated
- [ ] `FWT-PERF-07` — Per-file limit: files_truncated incremented in diagnostics
- [ ] `FWT-PERF-08` — Per-file limit 0 = unlimited (configurable)
- [ ] `FWT-PERF-09` — Pack filtering: non-detected pack skipped when detect_signals present
- [ ] `FWT-PERF-10` — Pack filtering: cross-language packs (no detect_signals) always run
- [ ] `FWT-PERF-11` — Benchmark: >2x improvement on content_patterns matching
- [ ] `FWT-PERF-12` — All 22 packs: identical results before/after optimization (regression)
- [ ] `FWT-PERF-13` — Empty file: 0 matches, no crash (boundary)
- [ ] `FWT-PERF-14` — Binary file (invalid UTF-8): content_patterns gracefully handle lossy conversion

### Quality Gate D (QG-D)

```
- [ ] RegexSet produces identical results to per-regex (equivalence proven)
- [ ] AC produces identical results to linear search (equivalence proven)
- [ ] Per-file limit works with configurable threshold
- [ ] Pack filtering reduces iteration count
- [ ] Benchmark shows measurable improvement
- [ ] All FWT-* Phase D tests pass
- [ ] cargo clippy clean, cargo test green
```

---

## Phase E: Enhancements, CLI & Regression (P2-P3)

> **Goal:** Learning signal types. Pack versioning. JSON Schema validation. validate-pack CLI. Framework degradation alerts. Full regression.
> **Effort:** 3-4 days
> **Files:** `types.rs`, `learner.rs`, `loader.rs`, `analysis.rs`, new CLI command
> **Depends on:** Phase A (learner), Phase C (diagnostics)

### E1 — Learning Signal Types

- [ ] `FW-SIGNAL-01` — **Add "frequency" signal type** — In `learner.rs`, when `learn_signal = "frequency"`, track raw frequency counts per group. In detect pass, flag patterns below the 10th percentile frequency (unusually rare usage).

- [ ] `FW-SIGNAL-02` — **Add "presence" signal type** — Track file-level presence/absence per group. Flag patterns present in <5% of files when the group overall appears in >50% of files.

- [ ] `FW-SIGNAL-03` — **Add "co_occurrence" signal type** — Track which patterns co-occur in the same file. Flag files where expected co-occurring patterns are missing (e.g., DI constructor present but no DI field).

### E2 — Pack Versioning

- [ ] `FW-VER-01` — **Add version field to FrameworkMeta** — `types.rs`: add `pub version: Option<String>` to `FrameworkMeta`. `loader.rs`: pass through to `CompiledFrameworkPack`. Log version in diagnostics.

- [ ] `FW-VER-02` — **Emit version in diagnostics** — Include pack versions in `FrameworkDiagnostics`. Enable tracking which pack version produced which detections.

### E3 — JSON Schema Validation

- [ ] `FW-SCHEMA-01` — **Generate JSON Schema for FrameworkSpec** — Use `schemars` crate to derive JSON Schema from `FrameworkSpec`. Write to `docs/framework-pack-schema.json`. Custom pack authors can validate their TOML against this schema.

- [ ] `FW-SCHEMA-02` — **Add schemars derive to types.rs** — Add `#[derive(schemars::JsonSchema)]` to `FrameworkSpec`, `PatternDef`, `MatchBlock`, `LearnDirective`, `FrameworkMeta`, `DetectSignal`.

### E4 — validate-pack CLI Command

- [ ] `FW-CLI-01` — **Add `drift validate-pack <file.toml>` command** — In `packages/drift-cli/src/commands/`, add a command that loads a TOML file via `FrameworkPackRegistry::load_single()`, reports any errors, and prints pack summary (name, language count, pattern count).

### E5 — Framework Degradation Alerts

- [ ] `FW-DEGRADE-01` — **Add framework-specific degradation alerts** — In `analysis.rs` Step 8, after existing degradation logic, check if framework detection count dropped significantly between runs. If current framework hits < 50% of previous run's hits for the same pack, emit a degradation alert with `alert_type: "framework_detection_drop"`.

### E6 — Full Regression Suite

- [ ] `FW-REG-01` — **E2E: full pipeline with framework data** — Parse real test-fixtures repo through full pipeline. Verify framework detections appear in detections table, pattern intelligence scores them, enforcement processes them, OWASP enrichment works.

- [ ] `FW-REG-02` — **E2E: custom pack loading** — Create temp `.drift/frameworks/custom.toml`. Run pipeline. Verify custom pack patterns match and appear in results alongside built-in patterns.

### Phase E Tests

- [ ] `FWT-SIGNAL-01` — "frequency" signal: rare pattern flagged (below 10th percentile)
- [ ] `FWT-SIGNAL-02` — "frequency" signal: common pattern NOT flagged
- [ ] `FWT-SIGNAL-03` — "presence" signal: pattern in <5% of files flagged
- [ ] `FWT-SIGNAL-04` — "co_occurrence" signal: missing co-occurring pattern flagged
- [ ] `FWT-SIGNAL-05` — Unknown signal type: warning logged, no crash
- [ ] `FWT-VER-01` — Pack with `version = "1.0.0"`: version appears in diagnostics
- [ ] `FWT-VER-02` — Pack without version: `None` in diagnostics (backward compat)
- [ ] `FWT-SCHEMA-01` — JSON Schema validates a correct TOML-converted-to-JSON pack
- [ ] `FWT-SCHEMA-02` — JSON Schema rejects pack with missing required `framework.name`
- [ ] `FWT-CLI-01` — `validate-pack` on valid pack: prints summary, exit 0
- [ ] `FWT-CLI-02` — `validate-pack` on invalid pack: prints error, exit 1
- [ ] `FWT-CLI-03` — `validate-pack` on nonexistent file: prints error, exit 1
- [ ] `FWT-DEGRADE-01` — Detection count drop >50%: degradation alert emitted
- [ ] `FWT-DEGRADE-02` — Detection count stable: no alert
- [ ] `FWT-REG-01` — E2E: framework data flows through entire pipeline (detections → PI → enforcement → OWASP)
- [ ] `FWT-REG-02` — E2E: custom pack loaded and matched alongside built-ins

### Quality Gate E (QG-E)

```
- [ ] frequency/presence/co_occurrence signal types produce correct output
- [ ] Pack versioning tracked in diagnostics
- [ ] JSON Schema generated and validates correct packs
- [ ] validate-pack CLI works for valid and invalid packs
- [ ] Framework degradation alerts fire on detection count drops
- [ ] E2E regression: full pipeline with framework data, all downstream consumers verified
- [ ] All FWT-* Phase E tests pass
- [ ] cargo clippy clean across all crates
- [ ] ZERO regressions on existing 187+ lib tests and 48 integration tests
```

---

## Dependency Graph

```
Phase A (P0, 3-4d) — no deps
  FW-LEARN-01..05   FrameworkLearner wiring
  FW-LOAD-01..04    Error resilience
  FW-TIME-01..03    Timing
  FW-OWASP-01..03   OWASP/CWE
  FW-JSRES-01..02   JsAnalysisResult fix

Phase B (P1, 3-4d) — depends on A
  FW-PRED-01..02    New predicates
  FW-PACK-01..06    New packs and patterns

Phase C (P1, 3-4d) — depends on A
  FW-DIAG-01..05    Diagnostics
  FW-STORE-01..04   Storage queries
  FW-DETECT-01..03  detect_signals
  FW-CONFIG-01..02  Pack config

Phase D (P2, 2-3d) — depends on A, C
  FW-PERF-01..10    Performance optimization

Phase E (P2-P3, 3-4d) — depends on A, C
  FW-SIGNAL-01..03  Learning signals
  FW-VER-01..02     Versioning
  FW-SCHEMA-01..02  JSON Schema
  FW-CLI-01         CLI command
  FW-DEGRADE-01     Degradation alerts
  FW-REG-01..02     E2E regression
```

### Parallelization

- **B and C are independent** — can run in parallel after A completes
- **D depends on both A and C** — must wait for detect_signals (C3)
- **E depends on A and C** — can start after both complete

### Critical Path

```
A (3-4d) → B (3-4d) → QG-B
         → C (3-4d) → D (2-3d) → QG-D
                     → E (3-4d) → QG-E
```

**Serial:** 15-19 days | **2 engineers:** 10-13 days | **P0+P1 only (A+B+C):** 9-12 days | **P0 only (A):** 3-4 days

---

## Execution Strategy

### With 1 Engineer (serial): 15-19 days
- Days 1-4: Phase A
- Days 5-8: Phase B
- Days 9-12: Phase C
- Days 13-15: Phase D
- Days 16-19: Phase E

### With 2 Engineers (parallel): 10-13 days
- **Eng A:** Phase A → Phase C → Phase E (FW-SIGNAL, FW-DEGRADE, FW-REG)
- **Eng B:** (waits for A) Phase B → Phase D → Phase E (FW-VER, FW-SCHEMA, FW-CLI)

### Minimum Viable (P0+P1): 9-12 days serial
- Phase A (3-4d) + Phase B (3-4d) + Phase C (3-4d)
- Delivers: working learner, full coverage, diagnostics, queryable storage

### Emergency (P0 only): 3-4 days
- Phase A only
- Delivers: working FrameworkLearner, correct OWASP/CWE, resilient errors, timing

---

## Files Impact Summary

| File | Phase(s) | Type of Change |
|------|----------|---------------|
| `loader.rs` | A, B, D | Clone derives, error recovery, empty regex, unknown lang, RegexSet/AC compilation |
| `matcher.rs` | A, B, C, D | JsResult tracking, new predicates, diagnostics, RegexSet/AC matching, match limit |
| `learner.rs` | C | Diagnostics accumulation |
| `registry.rs` | A, B, C | Skip counts, new pack registration, detect_signals, config, diagnostics |
| `types.rs` | B, E | file_patterns, type_annotations, version field |
| `analysis.rs` | A, C, E | Learner wiring (Step 2c), timing, diagnostics, file_contents guard, JsResult fix, degradation |
| `frameworks/mod.rs` | C | Register diagnostics module |
| `frameworks/diagnostics.rs` | C | NEW — FrameworkDiagnostics struct |
| `packs/security.toml` | A | OWASP 2021 update |
| `packs/auth.toml` | A | CWE additions |
| `packs/data_access.toml` | A | CWE additions |
| `packs/typescript_types.toml` | B | NEW — 12 patterns |
| `packs/rust_frameworks.toml` | B | 4 Warp patterns |
| `packs/config.toml` | B | Environment detection |
| `packs/styling.toml` | B | BEM patterns |
| `packs/errors.toml` | B | Try-catch pattern |
| `packs/structural.toml` | B | File naming patterns |
| `detections.rs` | C | 4 new query functions |
| `drift-cli/src/commands/` | E | validate-pack command |

---

## Verification Commands

```bash
# Per-phase quality gate
cargo test -p drift-analysis --test frameworks_test
cargo test -p drift-analysis --lib
cargo test -p drift-storage
cargo clippy -p drift-analysis -p drift-napi -p drift-storage -- -D warnings

# Full regression (run before each phase merge)
cargo test -p drift-analysis
cargo test -p drift-napi
cargo test -p drift-storage
cargo clippy --workspace -- -D warnings
```
