# Prompt 3: Enterprise Integration Audit — "Does It Follow Our Patterns?"

**Context:** Two prior audits have been completed:
- **Parity Report** (`V1-V2-FRAMEWORK-PARITY-REPORT.md`): 87% parity, 133/161 ✅, 24 ❌, 4 ⚠️
- **Best Practices Validation** (`BEST-PRACTICES-VALIDATION-REPORT.md`): 3 ✅ Aligned, 4 ⚠️ Improve. Key action items: OWASP 2017→2021, `typescript_types.toml`, `file_patterns` + `type_annotations` predicates, RegexSet optimization, Warp patterns, learning signal types.

This audit checks whether the framework system integrates properly with V2's **existing enterprise infrastructure**: storage, monitoring, logging, error handling, enforcement, diagnostics, and observability — patterns that have been carefully built across every other subsystem.

---

## Task

Audit the framework definition system (`crates/drift/drift-analysis/src/frameworks/`) and its pipeline wiring (`crates/drift/drift-napi/src/bindings/analysis.rs` lines 117-311) against every enterprise pattern established in V2. For each finding, cite the exact file and line number, and compare against an existing subsystem that does it correctly.

---

## Step 1: FrameworkLearner Is Completely Unwired (P0)

**Known gap discovered during code review:** The `FrameworkLearner` (`frameworks/learner.rs`) implements `LearningDetectorHandler` with a full two-pass learning system (learn pass → detect pass → emit `LearningDeviation` matches). However, **it is never instantiated or called anywhere in `drift_analyze()`**.

The parity report says 99 `[patterns.learn]` directives exist across the TOML packs. The best practices report says the learning system is "ahead of industry norms" and "a differentiator." But **none of it runs**.

**Audit this:**
1. Confirm `FrameworkLearner` is not referenced in `analysis.rs` (grep for `FrameworkLearner`, `framework_learner`, `learning_pass`, `learner`).
2. Check how the existing `PatternIntelligencePipeline` learning/convention discovery works (`src/patterns/learning/discovery.rs`, `src/patterns/pipeline.rs`). Does framework data reach it via `all_matches`?
3. Determine: should `FrameworkLearner` run as a **separate learning pass** (like V1's per-detector learning handlers), or should framework matches flow through the existing `PatternIntelligencePipeline` convention discovery (which already runs at Step 4)?
4. If `FrameworkLearner` should run separately: where in the pipeline should it go? After Step 2b (framework matching) and before Step 4 (pattern intelligence)? Or after Step 4?
5. What data would the `FrameworkLearner` produce that `PatternIntelligencePipeline` doesn't already? (Answer: deviation-specific matches with `DetectionMethod::LearningDeviation` and `/deviation` suffixed pattern IDs.)

**Produce:** A concrete wiring plan with the exact insertion point in `analysis.rs`, what to instantiate, what to call, and what to persist.

---

## Step 2: Storage Verification — Is Framework Data Queryable?

Framework matches are persisted as `DetectionRow` via `BatchCommand::InsertDetections` (analysis.rs lines 292-308). Verify the storage path is complete:

1. **Check `DetectionRow` field mapping:**
   - `detection_method` is `format!("{:?}", m.detection_method)` — this produces `"TomlPattern"`. Is this consistent with how other detection methods are stored? Check `analysis.rs` lines 219-250 (the non-framework detection row creation) for comparison.
   - `category` is `format!("{:?}", m.category)` — this produces e.g. `"Security"`, `"Auth"`. Verify it matches the enum variant names stored by other detectors.
   - `cwe_ids` is serialized as comma-separated string. Is this the same format used elsewhere?
   - `owasp` is stored as `Option<String>`. Check: are the stale `A1:2017` values (flagged in best practices report Step 5) going to pollute the database?

2. **Check queryability:**
   - Can users query detections by `detection_method = 'TomlPattern'` to isolate framework-specific findings? Check `drift-storage/src/queries/` for detection query functions.
   - Is there any query that filters by CWE ID or OWASP category? If not, the CWE/OWASP data we store is write-only (persisted but never read).
   - Can enforcement gates reference framework pattern IDs? Check `drift-analysis/src/enforcement/` for how pattern IDs are consumed.

3. **Missing framework-level metadata:**
   - The system stores individual pattern matches but **not** which frameworks were detected. There's no "this project uses Spring Boot, Express, and Django" summary.
   - Check: does `detect_signals` (framework detection via imports/dependencies) ever run? Or is it only defined in the TOML schema but never evaluated?
   - Compare with how the boundary detection module stores framework information (`BoundaryRow` has a `framework` field at `analysis.rs` line 345).

**Produce:** A list of storage gaps with recommended fixes (new query functions, new table/columns, or new BatchCommand variants).

---

## Step 3: Logging & Timing Audit

V2's pipeline has a consistent logging pattern. Compare the framework step against other steps:

**Existing patterns (in `analysis.rs`):**
- Step 4: `eprintln!("[drift-analyze] step 4 (pattern intelligence): {:?}", phase_timer.elapsed());` (line 498)
- Step 5a: `eprintln!("[drift-analyze] 5a (coupling): {:?}", step_timer.elapsed());` (line 540)
- Step 5b-5k: Each has a similar timing log
- Step 6-8: Each phase has timing

**Framework step (lines 117-311):**
- Line 130-134: Logs `"framework packs loaded: N packs, N patterns"` ✅
- Line 287-289: Logs `"framework patterns matched: N hits"` ✅
- **Missing:** No elapsed time measurement for framework loading or matching
- **Missing:** No per-file timing contribution (other detectors contribute to `analysis_time_us`)

**Audit:**
1. Add `Instant::now()` before framework pack loading (line 117) and log elapsed after line 134.
2. Add timing around the per-file `framework_matcher.analyze_file()` call (line 201) and accumulate into a total.
3. Add timing for Step 2b collection (lines 282-311).
4. Check: does the framework matching time get included in the `JsAnalysisResult.analysis_time_us` field? (Likely no — it runs separately from `analysis_pipeline.analyze_file()`.)

**Produce:** The exact `eprintln!` lines to add, matching the existing format.

---

## Step 4: Error Handling Audit

**Check graceful degradation:**

1. **Built-in pack with invalid regex:** `loader.rs` compiles regexes during `load_from_str()`. If a built-in pack has a bad regex, `registry.rs` line 26 logs a warning and skips the entire pack. **Question:** Should it skip only the bad pattern, not the entire pack? Check how the `engine/toml_patterns.rs` (the existing TOML pattern loader) handles this — does it skip per-pattern or per-file?

2. **Custom pack from `.drift/frameworks/` with malformed TOML:** `registry.rs` lines 43-48 catch this and log a warning. **Question:** Should the warning include the parse error details? Currently it does (`{e}` in the format string). Verify the error type provides useful context (line number, field name).

3. **Custom pack with unsupported language string:** What happens if a user writes `languages = ["fortran"]`? Does `Language::from_str("fortran")` return an error, or silently produce a value that never matches? Trace through `loader.rs` language parsing.

4. **Empty `content_patterns` match:** If a pattern has `content_patterns = [""]` (empty regex), does the regex crate produce an error or a match-everything regex? This could cause every line in every file to match.

5. **Compare with V2's error handling patterns:**
   - `drift-analysis/src/enforcement/` uses `DetectionError` consistently
   - `drift-analysis/src/patterns/pipeline.rs` uses `Result<PipelineResult, DetectionError>`
   - `drift-analysis/src/structural/contracts/` uses `anyhow::Result`
   - What does `frameworks/loader.rs` use? Is it consistent?

**Produce:** A list of error handling gaps with severity (P0 = crashes pipeline, P1 = silent data loss, P2 = poor DX).

---

## Step 5: Diagnostics & Observability

V2's pattern intelligence subsystem has rich diagnostic structs. Check whether the framework system follows this pattern:

1. **Existing diagnostic patterns:**
   - `LearningDiagnostics` in `patterns/learning/types.rs` — tracks observation counts, promotion decisions, convergence scores
   - `OutlierDiagnostics` in `patterns/outliers/` — tracks method used, normality check results
   - `PipelineResult` in `patterns/pipeline.rs` — aggregates all diagnostics from all subsystems
   - `AnalysisPipeline` tracks `analysis_time_us` per file

2. **Framework system has NO diagnostics struct.** There is no `FrameworkDiagnostics` that reports:
   - How many packs were loaded (built-in vs custom)
   - How many patterns compiled successfully vs failed
   - How many files were processed
   - How many matches per pack/category
   - Which frameworks were detected (via `detect_signals`)
   - Learning pass results (deviation counts, group statistics)
   - Total matching time

3. **Check if framework results appear in any existing diagnostic output:**
   - Does `PipelineResult` include framework-originated matches in its `scores` / `outliers` / `conventions`?
   - Does the `drift_report()` NAPI binding include framework detection data?
   - Does the SARIF reporter include framework pattern IDs in its output?

**Produce:** A `FrameworkDiagnostics` struct definition with all fields, plus where to wire it (return from `FrameworkMatcher`, aggregate in `analysis.rs`, include in `PipelineResult` or a new top-level diagnostic).

---

## Step 6: Enforcement Integration

V2 has a complete enforcement engine (6 gates, policy engine, SARIF/JUnit/SonarQube reporters). Check framework pattern integration:

1. **Can enforcement gates evaluate framework patterns?**
   - Check `enforcement/evaluator.rs` — does it filter by `detection_method`? If so, are `"TomlPattern"` detections included or excluded?
   - Check `enforcement/gates/` — do any gates reference specific pattern ID prefixes? Framework patterns use IDs like `spring/auth/pre-authorize`, `SEC-SQLI-RAW-001`. Are these compatible with gate pattern matching?

2. **Can users write policies referencing framework patterns?**
   - Check `enforcement/policy/engine.rs` — how does `PolicyEngine` resolve pattern IDs to violations?
   - Example use case: "All Spring services must use constructor injection, not field injection." This requires a policy that says: if `spring/di/field-injection` is detected, emit a violation. Is this expressible?

3. **Are framework patterns in report output?**
   - Check `enforcement/reporters/sarif.rs` — does it include CWE/OWASP data from detection rows? Framework patterns have CWE IDs and OWASP refs.
   - Check `enforcement/reporters/sonarqube.rs` — does it include framework pattern IDs as rule IDs?

4. **Are framework patterns included in degradation alerts?**
   - Check `analysis.rs` Step 8 (degradation alerts) — does it consume framework matches?

**Produce:** A matrix of enforcement features × framework integration status (✅ works / ⚠️ partial / ❌ not wired).

---

## Step 7: Missing Enterprise Features

Cross-reference against enterprise features built into other V2 subsystems:

1. **Pack enable/disable:** Is there a way to disable a specific built-in pack without removing it? Compare with how enforcement gates can be enabled/disabled via policy config.

2. **Pack versioning:** Built-in packs have no version field. If a pack's patterns change between drift versions, there's no way to track which version produced a detection. Compare with `drift-storage` migrations which track schema versions.

3. **MCP server exposure:** Check `packages/drift-mcp/` — can the MCP server return framework detection results? The `drift_scan` MCP tool triggers scanning. Does `drift_analyze` have an MCP tool? Can agents query framework findings?

4. **CI agent integration:** Check `packages/drift-ci/src/` — does the CI agent run `drift_analyze()`? If so, do framework results appear in CI output? Are there framework-specific CI checks (e.g., "fail if SQL injection patterns detected")?

5. **Incremental analysis:** When a file changes, does the framework matcher re-run only for that file? Or does it re-run all 261 patterns against all files? Compare with how the call graph handles incremental updates.

6. **Custom pack validation CLI command:** Is there a `drift validate-pack <file.toml>` command for users to test their custom packs before running analysis? Compare with `drift check` for enforcement policies.

**Produce:** A prioritized gap list (P0-P3) with effort estimates.

---

## Output Format

For each of the 7 steps, produce:

```
## Step N: [Title]

### Current State
[What exists today — cite exact files and line numbers]

### Gaps Found
- **[Gap ID] [Severity]**: [Description]
  - File: [path:line]
  - Compare with: [existing subsystem that does it right]

### Recommended Fix
[Specific action]

### Effort
[Days]
```

Then produce a **final action plan**:

| Priority | Gap ID | Description | Category | Effort | Dependency |
|---|---|---|---|---|---|
| P0 | ... | ... | A/B/C/D/E | ... | ... |

Categories:
- **(A)** Data not being computed
- **(B)** Data not being stored
- **(C)** Missing monitoring/logging
- **(D)** Missing error handling
- **(E)** Missing enterprise integration

Sort by priority, then by category.
