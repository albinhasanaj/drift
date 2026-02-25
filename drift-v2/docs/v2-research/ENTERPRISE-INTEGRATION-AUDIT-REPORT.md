# Enterprise Integration Audit Report — Framework Definition System

> **Auditor:** Cascade (automated deep audit)  
> **Date:** 2026-02-10  
> **Scope:** `crates/drift/drift-analysis/src/frameworks/` (5 files, 1,240 lines) + pipeline wiring in `crates/drift/drift-napi/src/bindings/analysis.rs` (lines 117–311)  
> **Prior audits referenced:** V1-V2 Parity Report (87% parity), Best Practices Validation (3 ✅, 4 ⚠️)

---

## Executive Summary

The TOML-driven framework definition system is **architecturally sound** — 22 packs, 261 patterns, 15 predicate types, compiled regexes, language pre-filtering — but its enterprise integration is **shallow**. Of 7 audit dimensions, only 2 are fully integrated (storage persistence, enforcement input). The remaining 5 have material gaps:

| Dimension | Status | Severity |
|-----------|--------|----------|
| FrameworkLearner wiring | ❌ Completely unwired | P0 |
| Storage queryability | ⚠️ Write-only for CWE/OWASP | P1 |
| Logging & timing | ⚠️ Missing elapsed time | P2 |
| Error handling | ⚠️ 2 silent failures | P1 |
| Diagnostics & observability | ❌ No FrameworkDiagnostics | P1 |
| Enforcement integration | ✅ Works (via PatternInfo) | — |
| Enterprise features | ⚠️ 4 missing | P1–P3 |

**Total gaps found:** 17 (3 P0, 5 P1, 6 P2, 3 P3)  
**Estimated remediation:** 4–6 working days

---

## Step 1: FrameworkLearner Is Completely Unwired (P0)

### Current State

`FrameworkLearner` at `frameworks/learner.rs:19-193` implements `LearningDetectorHandler` with a full two-pass system:
- **Learn pass** (`learn()`, line 67): iterates all packs, filters by language, matches patterns with `has_learn=true`, accumulates frequency counts per group key.
- **Detect pass** (`detect()`, line 111): computes dominant pattern per group, flags deviations where non-dominant patterns exceed `(1.0 - threshold)` ratio.
- **Output**: `PatternMatch` with `DetectionMethod::LearningDeviation` and `/deviation` suffixed pattern IDs.

**Confirmed unwired:** Grep for `FrameworkLearner`, `framework_learner`, `learning_pass`, `learner` in `crates/drift/drift-napi/src/` returns **0 results**. The `analysis.rs` pipeline:
- Line 129: Creates `FrameworkMatcher` only — no `FrameworkLearner`.
- Lines 196-202: Calls `framework_matcher.analyze_file(&ctx)` in the per-file loop — no learning pass.
- The `DetectionEngine.run_learning_pass()` method exists at `visitor.rs:245-267` and is fully functional, but is never called from `analysis.rs`.

**99 `[patterns.learn]` directives across the TOML packs are dead code.**

### Gaps Found

- **EIA-01 [P0]**: `FrameworkLearner` never instantiated in `drift_analyze()`.
  - File: `analysis.rs` — no reference to `FrameworkLearner` anywhere in the 1,547-line file.
  - Compare with: `PatternIntelligencePipeline` at line 410, which IS instantiated and run.

- **EIA-02 [P0]**: Framework learning results never persisted.
  - The `FrameworkLearner.results()` method (line 182) returns `Vec<PatternMatch>` with `DetectionMethod::LearningDeviation`, but these never reach `detection_rows` or `all_matches`.
  - Compare with: Framework matcher results at lines 282-311, which ARE merged into `detection_rows` + `all_matches`.

- **EIA-03 [P0]**: No interaction between `FrameworkLearner` and `PatternIntelligencePipeline`.
  - The existing `PatternIntelligencePipeline` (line 410) receives framework matcher results via `all_matches` (line 310) and processes them through Bayesian scoring, outlier detection, and convention discovery. However, `FrameworkLearner` deviation matches would provide a **separate, complementary signal** — framework-specific convention violations — that the generic pipeline doesn't compute.
  - The pipeline's convention discovery groups by `pattern_id` prefix, while `FrameworkLearner` groups by `learn.group_by` directives (sub_type, pattern_id, decorator, call, function_name). These are different grouping strategies.

### Recommended Fix — Concrete Wiring Plan

**Insertion point:** After Step 2b (line 311, after framework matcher results are collected) and before Step 3 (line 314, batch persistence).

```rust
// Step 2c: Framework learning pass (two-pass convention deviation detection)
let framework_learning_matches = {
    let learner_packs = framework_registry_clone; // Need to clone packs or re-load
    let mut framework_learner = drift_analysis::frameworks::FrameworkLearner::new(learner_packs);
    
    use drift_analysis::engine::visitor::LearningDetectorHandler;
    
    // Learning pass: accumulate frequencies across ALL files
    for file_meta in &files {
        // ... reconstruct DetectionContext for each file (reuse cached parse_results) ...
        let ctx = /* from all_parse_results + file_contents */;
        framework_learner.learn(&ctx);
    }
    
    // Detection pass: flag deviations
    for file_meta in &files {
        let ctx = /* same contexts */;
        framework_learner.detect(&ctx);
    }
    
    framework_learner.results()
};

if !framework_learning_matches.is_empty() {
    eprintln!(
        "[drift-analyze] framework learning deviations: {} hits",
        framework_learning_matches.len(),
    );
    // Add to detection_rows for persistence (same pattern as Step 2b)
    for m in &framework_learning_matches {
        detection_rows.push(/* same DetectionRow mapping */);
    }
    all_matches.extend(framework_learning_matches);
}
```

**Key design decisions:**
1. `FrameworkLearner` needs its own copy of the packs (learner mutates internal state). Either clone before `into_packs()` or load twice.
2. The learning pass requires iterating ALL files twice (learn + detect). This means storing `DetectionContext` objects or reconstructing them from `all_parse_results` + `file_contents`.
3. Results should merge into both `detection_rows` (storage) and `all_matches` (downstream pattern intelligence + enforcement).

**Alternative:** Register `FrameworkLearner` into the `VisitorRegistry` as a `LearningDetectorHandler` and call `DetectionEngine.run_learning_pass()`. This is architecturally cleaner but requires refactoring the per-file loop in `analysis.rs` to collect `DetectionContext` objects, since `run_learning_pass()` expects `&[DetectionContext]`.

### Effort
2 days (1 day implementation, 1 day testing). Requires storing or reconstructing `DetectionContext` for all files.

---

## Step 2: Storage Verification — Is Framework Data Queryable?

### Current State

Framework matches flow through `analysis.rs` lines 292-308 into `DetectionRow` structs and are persisted via `BatchCommand::InsertDetections`.

### Gaps Found

- **EIA-04 [P2]**: `detection_method` format inconsistency.
  - Framework matches: `format!("{:?}", m.detection_method)` → `"TomlPattern"` (line 300).
  - Non-framework matches: Same format at line 227 → produces `"AstVisitor"`, `"StringMatch"`, `"RegexMatch"`, `"Resolution"`.
  - **Verdict:** Consistent. Both use `Debug` formatting of the `DetectionMethod` enum. ✅ No issue.

- **EIA-05 [P2]**: `category` format uses Debug formatting.
  - Line 298: `format!("{:?}", m.category)` produces `"Security"`, `"Auth"`, `"DataAccess"`, etc.
  - Same pattern at line 225 for non-framework matches. ✅ Consistent.

- **EIA-06 [P1]**: **No query function for `detection_method` filtering.**
  - `drift-storage/src/queries/detections.rs` has only 5 functions:
    - `insert_detections()` (line 24)
    - `get_detections_by_file()` (line 50)
    - `get_detections_by_category()` (line 89)
    - `query_all_detections()` (line 128)
    - `count_detections()` (line 176)
    - `delete_detections_by_file()` (line 167)
  - **Missing:** `get_detections_by_method(conn, "TomlPattern")` — users cannot isolate framework-specific findings.
  - **Missing:** `get_detections_by_pattern_id(conn, "spring/di/constructor-injection")` — users cannot query by framework pattern ID.
  - Compare with: `enforcement.rs` which has `query_violations_by_file()`, `query_violations_by_pattern()`.

- **EIA-07 [P1]**: **CWE/OWASP data is write-only.**
  - CWE IDs are stored as comma-separated string in `cwe_ids` column (line 302-304).
  - OWASP category stored in `owasp` column (line 306).
  - **No query function filters by CWE or OWASP.** The data is persisted but never read back.
  - The SARIF reporter (line 123 of `sarif.rs`) reads CWE/OWASP from `Violation` objects, NOT from the `detections` table. The path is: `all_matches` → `GateInputBuilder.patterns()` → `GateOrchestrator.execute()` → `Violation` (with `cwe_id` and `owasp_category` fields).
  - So framework CWE/OWASP data DOES reach SARIF output — via the enforcement pipeline, not via direct DB queries. ✅ Partially OK.

- **EIA-08 [P2]**: **No framework-level detection summary.**
  - Individual pattern matches are stored (e.g., "spring/di/constructor-injection found at file:line").
  - But there is no "this project uses Spring Boot, Express, and Django" summary persisted.
  - The `detect_signals` field on TOML packs (`CompiledDetectSignal` enum: Import, FilePattern, Decorator, Dependency) is **compiled but never evaluated**. The `CompiledFrameworkPack.detect_signals` field (line 25 of `loader.rs`) is populated during loading but `matcher.rs` never checks it.
  - Compare with: `BoundaryRow` has a `framework` field (line 345 of `analysis.rs`). Boundaries store which frameworks were detected.

### Recommended Fix

1. Add `get_detections_by_method(conn, method)` and `get_detections_by_pattern_prefix(conn, prefix)` to `detections.rs`.
2. Add `get_detections_by_cwe(conn, cwe_id)` for CWE-based queries.
3. Add a `frameworks_detected` table or a summary row in an existing table to persist framework detection results from `detect_signals`.
4. Wire `detect_signals` evaluation in `matcher.rs` or `analysis.rs`.

### Effort
1 day (3 new query functions + detect_signals wiring).

---

## Step 3: Logging & Timing Audit

### Current State

The pipeline has a consistent timing pattern for every step:

| Step | Log Line | Timing |
|------|----------|--------|
| Step 4 | `analysis.rs:498` | `"step 4 (pattern intelligence): {:?}"` ✅ |
| Step 5a | `analysis.rs:540` | `"5a (coupling): {:?}"` ✅ |
| Step 5b | `analysis.rs:573` | `"5b (wrappers): {:?}"` ✅ |
| Step 5c-5k | Lines 606–985 | Each has timing ✅ |
| Step 6-8 | Lines 1093–1447 | Each phase has timing ✅ |
| **Step 2a** | `analysis.rs:130-134` | Pack count + pattern count ✅ **No elapsed time** ❌ |
| **Step 2 (per-file)** | `analysis.rs:196-202` | **No timing at all** ❌ |
| **Step 2b** | `analysis.rs:287-289` | Hit count ✅ **No elapsed time** ❌ |

### Gaps Found

- **EIA-09 [P2]**: **No elapsed time for framework pack loading** (lines 117-134).
  - TOML parsing + regex compilation for 22 packs / 261 patterns happens here.
  - Compare with: Step 4 at line 498 measures pipeline elapsed time.

- **EIA-10 [P2]**: **No elapsed time for per-file framework matching** (lines 196-202).
  - `framework_matcher.analyze_file(&ctx)` runs 261 patterns against each file's ParseResult.
  - This time is NOT included in `analysis_time_us` (which only measures `analysis_pipeline.analyze_file()`).
  - Compare with: Every Step 5 sub-step has its own `step_timer`.

- **EIA-11 [P2]**: **No elapsed time for Step 2b collection** (lines 282-311).
  - The hit collection + detection row creation + `all_matches.extend()` loop.

### Recommended Fix

Add timing in the existing format:

```rust
// Before line 117:
let framework_timer = std::time::Instant::now();

// After line 134 (existing pack log):
eprintln!("[drift-analyze] step 2a (framework load): {:?}", framework_timer.elapsed());

// Before line 196 (inside per-file loop), accumulate:
let fw_match_start = std::time::Instant::now();
// ... framework_matcher.analyze_file(&ctx); ...
fw_match_total += fw_match_start.elapsed();

// After line 311 (end of Step 2b):
eprintln!("[drift-analyze] step 2b (framework match): {:?} ({} hits)", fw_match_total, framework_matches.len());
```

### Effort
0.5 days (6 lines of code).

---

## Step 4: Error Handling Audit

### Current State

The framework system uses `DetectionError` from `drift-core` consistently. `loader.rs` returns `Result<CompiledFrameworkPack, DetectionError>`. The registry catches errors per-pack and logs warnings.

### Gaps Found

- **EIA-12 [P1]**: **Built-in pack with bad regex skips the ENTIRE pack, not just the bad pattern.**
  - `registry.rs:24-27`: If `loader::load_from_str(toml_str)` fails (including regex compilation), the entire pack is skipped:
    ```rust
    Err(e) => eprintln!("[drift] warning: failed to load built-in pack '{name}': {e}"),
    ```
  - Root cause: `compile_pattern()` at `loader.rs:148` returns `Result`, and `compile_spec()` at line 116 uses `?` — one bad pattern fails the entire pack.
  - Compare with: The TOML pattern loader could use `filter_map` to skip individual bad patterns instead of propagating the error.
  - **Impact:** A single typo in one regex within `security.toml` (e.g., `content_patterns = ["[invalid"]`) would silently disable ALL 22 security patterns in that pack.

- **EIA-13 [P1]**: **Unsupported language string silently dropped.**
  - `loader.rs:265-283`: `parse_language()` returns `Option<Language>`. For unsupported languages (e.g., "fortran"), `filter_map` at line 105 silently drops them.
  - If a TOML pack declares `languages = ["fortran"]`, the compiled pack will have `languages: vec![]`, meaning `matcher.rs:70` (`!pack.languages.contains(&ctx.language)`) will skip the pack for ALL files. The entire pack becomes dead code with no warning.
  - Compare with: `compile_pattern()` at line 149 does error on unknown `category` strings with `DetectionError::InvalidPattern`. Languages should follow the same pattern.

- **EIA-14 [P2]**: **Empty regex `""` matches everything.**
  - `content_patterns = [""]` compiles to `Regex::new("")` which succeeds and matches every position in every string. This would cause every line in every file to generate a match.
  - `compile_regexes()` at line 248 does not validate against empty patterns.
  - **Impact:** Massive false positive flood + performance degradation.

- **EIA-15 [P3]**: **Custom pack TOML parse errors include good context.**
  - `registry.rs:44`: Error format includes `{e}` from `DetectionError::InvalidPattern(format!("TOML parse error: {e}"))`.
  - The `toml` crate's error type includes line/column/field context. ✅ Adequate.

### Recommended Fix

1. Change `compile_spec()` to use `filter_map` for individual patterns:
   ```rust
   let mut patterns = Vec::new();
   for def in spec.patterns {
       match compile_pattern(def) {
           Ok(p) => patterns.push(p),
           Err(e) => eprintln!("[drift] warning: skipping pattern: {e}"),
       }
   }
   ```
2. Add a warning when `parse_language()` returns `None`:
   ```rust
   .filter_map(|s| {
       let lang = parse_language(s);
       if lang.is_none() {
           eprintln!("[drift] warning: unknown language '{s}', ignoring");
       }
       lang
   })
   ```
3. Reject empty regex patterns in `compile_regexes()`.

### Effort
0.5 days.

---

## Step 5: Diagnostics & Observability

### Current State

V2's pattern intelligence subsystem has rich diagnostic structs:
- `LearningDiagnostics` in `patterns/learning/types.rs` — tracks observation counts, promotion decisions, convergence scores.
- `OutlierDiagnostics` in `patterns/outliers/` — tracks method used, normality check results.
- `PipelineResult` in `patterns/pipeline.rs` — aggregates all diagnostics from all subsystems, includes a `diagnostics: LearningDiagnostics` field.
- `AnalysisPipeline` tracks `analysis_time_us` per file.

The framework system has **zero diagnostics**.

### Gaps Found

- **EIA-16 [P1]**: **No `FrameworkDiagnostics` struct.**
  - No reporting of:
    - How many packs loaded (built-in vs custom), how many skipped
    - How many patterns compiled successfully vs failed
    - How many files processed, how many matched
    - Matches per pack/category breakdown
    - Which frameworks detected (via `detect_signals`)
    - Learning pass stats (deviation counts, group sizes, dominant ratios)
    - Total matching time
  - Compare with: `PipelineResult` at `pipeline.rs:25-38` which includes `scores`, `outliers`, `conventions`, `promoted_count`, `diagnostics`.

- **EIA-17 [P2]**: **Framework results are invisible in `PipelineResult`.**
  - Framework matcher results ARE included in `all_matches` (line 310) which feeds into `PatternIntelligencePipeline.run()` (line 419). So framework patterns DO appear in `PipelineResult.scores`, `outliers`, and `conventions`.
  - **However:** There is no way to distinguish framework-originated patterns from engine-originated patterns in the pipeline output. A pattern like `spring/di/constructor-injection` shows up alongside `DA-RAW-001` with no provenance tag.
  - Compare with: `DetectionRow.detection_method` stores `"TomlPattern"` which could be used for filtering, but `PipelineResult` doesn't carry detection_method.

- **EIA-18 [P2]**: **`drift_report()` doesn't expose framework detection data.**
  - The `drift_report()` NAPI binding generates reports from `GateResult` objects (violations + gate scores). Framework detections reach violations via the enforcement pipeline. But there's no "framework summary" section in any report format.
  - Compare with: `JsBoundaryResult.frameworks_detected` at `analysis.rs:54` which explicitly lists detected frameworks.

### Recommended Fix

Define a `FrameworkDiagnostics` struct:

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

Wire it:
1. `FrameworkPackRegistry` tracks loaded/skipped counts.
2. `FrameworkMatcher` accumulates hits_per_category/pack.
3. Return `FrameworkDiagnostics` from `analysis.rs` alongside `JsAnalysisResult`.
4. Include in `PipelineResult` or as a top-level field in `JsAnalysisResult`.

### Effort
1 day.

---

## Step 6: Enforcement Integration

### Current State

Framework patterns flow into enforcement via the `GateInputBuilder` at `analysis.rs:1317-1340`:

```rust
for m in &all_matches {
    let entry = pattern_map.entry(m.pattern_id.clone()).or_insert_with(|| RulesPatternInfo {
        pattern_id: m.pattern_id.clone(),
        category: format!("{:?}", m.category),
        confidence: m.confidence as f64,
        locations: Vec::new(),
        outliers: Vec::new(),
        cwe_ids: m.cwe_ids.to_vec(),
        owasp_categories: m.owasp.as_ref().map(|o| vec![o.clone()]).unwrap_or_default(),
    });
    entry.locations.push(PatternLocation { ... });
}
```

Since framework matches are in `all_matches` (merged at line 310), they ARE included in `GateInput.patterns`.

### Audit Matrix

| Enforcement Feature | Framework Integration | Notes |
|---|---|---|
| Gate evaluation | ✅ Works | Framework patterns reach all 6 gates via `GateInput.patterns` |
| Pattern compliance gate | ✅ Works | Counts total patterns including framework-originated |
| Security boundaries gate | ✅ Works | CWE IDs from framework patterns flow through `PatternInfo.cwe_ids` |
| Policy engine | ✅ Works | Policies reference `pattern_id`; framework IDs like `spring/di/field-injection` are valid |
| SARIF reporter | ✅ Works | CWE/OWASP from violations propagate to SARIF taxonomies (`sarif.rs:121-217`) |
| SonarQube reporter | ✅ Works | Pattern IDs used as rule IDs |
| JUnit reporter | ✅ Works | Violations include framework pattern messages |
| Degradation alerts | ⚠️ Indirect | Step 8 (lines 1399-1444) checks gate scores/violation counts, not framework patterns directly |
| Progressive enforcement | ✅ Works | `is_new` detection applies to framework violations same as any other |
| Suppression | ✅ Works | `// noqa`, `@SuppressWarnings` etc. apply to framework violations by line |

### Gaps Found

- **EIA-19 [P3]**: **No framework-specific degradation alerts.**
  - Step 8 creates alerts for `gate_score_low` and `violation_count_high` but not "new framework detected" or "framework pattern count changed significantly."
  - This is a nice-to-have, not a correctness issue.

### Effort
N/A (enforcement integration is functional).

---

## Step 7: Missing Enterprise Features

### Gaps Found

- **EIA-20 [P1]**: **No pack enable/disable mechanism.**
  - There is no way to disable a specific built-in pack without removing it from `registry.rs`. A project using only Python might want to disable `spring.toml`, `aspnet.toml`, `rails.toml` to reduce noise and improve performance.
  - Compare with: Enforcement gates can be enabled/disabled via `PolicyConfig`. A similar `FrameworkConfig { disabled_packs: Vec<String> }` is needed.
  - **Impact:** 261 patterns run against every file regardless of project language mix. Wasted computation.

- **EIA-21 [P3]**: **No pack versioning.**
  - Built-in packs have no `version` field in the TOML schema (`FrameworkMeta` at `types.rs:19-29`). If patterns change between Drift versions, there's no way to track which version produced a detection.
  - Compare with: `drift-storage` migrations track schema versions. Detection rows should include pack version.
  - **Impact:** Low for now; becomes important for reproducible CI builds.

- **EIA-22 [P2]**: **`detect_signals` never evaluated.**
  - The `FrameworkMeta.detect_by` field is compiled into `CompiledDetectSignal` variants (Import, FilePattern, Decorator, Dependency) at `loader.rs:134-146`, stored in `CompiledFrameworkPack.detect_signals` (line 25). But **no code ever checks these signals**.
  - The detection signals are meant to answer "is this framework used in this project?" (e.g., if `package.json` contains `"express"` dependency). This information could:
    - Enable per-project pack filtering (only run Express patterns if Express is detected)
    - Power the "frameworks_detected" summary (EIA-08)
    - Improve performance by skipping irrelevant packs
  - **Impact:** Performance waste + missing feature.

- **EIA-23 [P3]**: **No `drift validate-pack` CLI command.**
  - Users creating custom packs in `.drift/frameworks/` have no way to validate them before running analysis. A malformed pack silently fails at runtime (logged as warning).
  - Compare with: `drift check` validates enforcement policies.
  - **Impact:** Poor developer experience for custom pack authors.

### Recommended Fix

1. **Pack enable/disable (P1, 1 day):** Add `disabled_packs: Vec<String>` to `ScanConfig` or a new `FrameworkConfig`. Filter in `FrameworkPackRegistry::with_builtins()`.
2. **detect_signals evaluation (P2, 0.5 day):** Add `evaluate_signals(parse_results: &[ParseResult]) -> Vec<String>` to `FrameworkPackRegistry`. Run it before per-file matching to filter packs.
3. **Pack versioning (P3, 0.5 day):** Add optional `version` field to `FrameworkMeta`. Include in `DetectionRow` metadata.
4. **validate-pack CLI (P3, 0.5 day):** Add `drift validate-pack <file.toml>` that calls `loader::load_from_file()` and reports success/failure with details.

### Effort
2.5 days total for all 4 features.

---

## Final Action Plan

| Priority | Gap ID | Description | Category | Effort | Dependency |
|---|---|---|---|---|---|
| **P0** | EIA-01 | FrameworkLearner never instantiated | (A) Data not computed | 1.5d | None |
| **P0** | EIA-02 | Learning results never persisted | (B) Data not stored | 0.5d | EIA-01 |
| **P0** | EIA-03 | No interaction with PatternIntelligencePipeline | (A) Data not computed | — | Included in EIA-01 |
| **P1** | EIA-06 | No detection_method/pattern_id query functions | (B) Data not stored | 0.5d | None |
| **P1** | EIA-07 | CWE/OWASP data write-only in detections table | (B) Data not stored | 0.5d | None |
| **P1** | EIA-12 | Bad regex kills entire pack | (D) Missing error handling | 0.25d | None |
| **P1** | EIA-13 | Unknown language silently dropped | (D) Missing error handling | 0.25d | None |
| **P1** | EIA-16 | No FrameworkDiagnostics struct | (C) Missing monitoring | 1d | None |
| **P1** | EIA-20 | No pack enable/disable mechanism | (E) Missing enterprise | 1d | None |
| **P2** | EIA-08 | No framework detection summary | (B) Data not stored | 0.5d | EIA-22 |
| **P2** | EIA-09 | No elapsed time for pack loading | (C) Missing logging | 0.1d | None |
| **P2** | EIA-10 | No elapsed time for per-file matching | (C) Missing logging | 0.1d | None |
| **P2** | EIA-11 | No elapsed time for Step 2b | (C) Missing logging | 0.1d | None |
| **P2** | EIA-14 | Empty regex matches everything | (D) Missing error handling | 0.1d | None |
| **P2** | EIA-17 | Framework results invisible in PipelineResult | (C) Missing monitoring | 0.5d | EIA-16 |
| **P2** | EIA-22 | detect_signals never evaluated | (E) Missing enterprise | 0.5d | None |
| **P3** | EIA-19 | No framework-specific degradation alerts | (E) Missing enterprise | 0.5d | EIA-01 |
| **P3** | EIA-21 | No pack versioning | (E) Missing enterprise | 0.5d | None |
| **P3** | EIA-23 | No validate-pack CLI command | (E) Missing enterprise | 0.5d | None |

### Categories
- **(A)** Data not being computed — 3 gaps
- **(B)** Data not being stored — 4 gaps
- **(C)** Missing monitoring/logging — 5 gaps
- **(D)** Missing error handling — 3 gaps
- **(E)** Missing enterprise integration — 4 gaps

### Critical Path

```
EIA-01 (FrameworkLearner wiring, 2d)
  → EIA-02 (persist learning results, included)
  → EIA-03 (pipeline interaction, included)

EIA-12 + EIA-13 + EIA-14 (error handling, 0.5d) — parallelizable
EIA-06 + EIA-07 (storage queries, 1d) — parallelizable
EIA-09 + EIA-10 + EIA-11 (timing, 0.3d) — parallelizable
EIA-16 + EIA-17 (diagnostics, 1.5d) — parallelizable after EIA-01
EIA-20 (pack enable/disable, 1d) — parallelizable
EIA-22 (detect_signals, 0.5d) → EIA-08 (framework summary, 0.5d)
```

**Total: 4–6 working days.** With 2 engineers: 3–4 days (EIA-01 is the critical path; everything else parallelizes).

---

## Appendix: File Reference

| File | Lines | Role |
|------|-------|------|
| `frameworks/mod.rs` | 23 | Module declarations + re-exports |
| `frameworks/types.rs` | 151 | FrameworkSpec, PatternDef, MatchBlock, LearnDirective serde types |
| `frameworks/loader.rs` | 284 | TOML → CompiledFrameworkPack (regex pre-compiled at load time) |
| `frameworks/matcher.rs` | 587 | FrameworkMatcher implements FileDetectorHandler, 15 predicate types |
| `frameworks/learner.rs` | 218 | FrameworkLearner implements LearningDetectorHandler (UNWIRED) |
| `frameworks/registry.rs` | 107 | Built-in packs (include_str!) + custom .drift/frameworks/ loading |
| `analysis.rs:117-134` | 18 | Pack loading + registry creation |
| `analysis.rs:196-202` | 7 | Per-file framework matching |
| `analysis.rs:282-311` | 30 | Result collection + detection row persistence |
| `detections.rs` | 180 | 5 query functions (none filter by detection_method/CWE/OWASP) |
| `visitor.rs:96-113` | 18 | LearningDetectorHandler trait definition |
| `visitor.rs:245-267` | 23 | DetectionEngine.run_learning_pass() (functional but uncalled) |
| `pipeline.rs:25-38` | 14 | PipelineResult with LearningDiagnostics (framework has no equivalent) |
