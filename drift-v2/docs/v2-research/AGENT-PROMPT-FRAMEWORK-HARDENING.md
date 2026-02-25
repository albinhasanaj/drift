# Agent Prompt: Framework Definition System Hardening

## Your Mission

You are performing a phased hardening of **the TOML-driven framework definition system** in Drift V2. This system replaces V1's 441 hand-written TypeScript detector files with 22 declarative TOML packs containing 261 patterns across 16 categories and 14 languages. The framework system lives in `crates/drift/drift-analysis/src/frameworks/` (6 source files) and is wired into the analysis pipeline at `crates/drift/drift-napi/src/bindings/analysis.rs`.

A comprehensive audit has already been completed across 3 reports (V1 Parity, Best Practices, Enterprise Integration). **You are not auditing. You are implementing fixes and writing tests.** The audit found the system is architecturally sound but has critical wiring gaps: the `FrameworkLearner` is completely dead code (99 learn directives produce zero output), error handling kills entire packs on one bad regex, there's no timing or diagnostics, OWASP references are stale, and framework matches are invisible in the per-file JS results.

**Your job is to wire everything together, harden the error handling, close coverage gaps, and prove it works with tests that expose real bugs — not happy-path confirmation.**

**Speed does not matter. Correctness does. Every test must target a specific failure mode. Do not write tests that only confirm the happy path.**

---

## Documents You MUST Read Before Writing Any Code

Read these in order. Do not skip any. They are your ground truth.

1. **`docs/v2-research/FRAMEWORK-HARDENING-TASKS.md`** — The implementation spec: 156 tasks (66 impl + 90 test) across 5 phases (A–E) with exact file paths, line numbers, code snippets, audit cross-references, dependency graph, and critical path. **This is your work order.**

2. **`docs/v2-research/V1-V2-FRAMEWORK-PARITY-REPORT.md`** — The parity audit: 87% coverage (133 ✅, 4 ⚠️, 24 ❌). Shows exactly which V1 patterns have no V2 equivalent. You will close the biggest gaps in Phase B.

3. **`docs/v2-research/ENTERPRISE-INTEGRATION-AUDIT-REPORT.md`** — The enterprise integration audit: 17 gaps (3 P0, 5 P1, 6 P2, 3 P3). Shows where the framework system fails to meet V2's existing monitoring, logging, error handling, and storage patterns.

4. **`crates/drift/drift-napi/src/bindings/analysis.rs`** — The 1,547-line analysis pipeline orchestrator. Every framework fix touches this file or something it calls. Understand the full pipeline flow before changing anything. Key lines:
   - **L117-134:** Framework pack loading + matcher creation (Step 2a)
   - **L195-202:** Per-file framework matcher invocation
   - **L206-210:** File contents caching (`if max_phase >= 3` guard — you will remove this)
   - **L257-279:** Per-file `JsAnalysisResult` construction (**excludes framework matches** — you will fix this)
   - **L282-311:** Post-loop framework match collection (Step 2b)
   - **L406-419:** Pattern intelligence receives `all_matches` (includes framework data)
   - **L874-901:** OWASP findings enrichment (receives CWE/OWASP from framework matches)
   - **L1309-1397:** Enforcement pipeline (receives framework data via `all_matches`)

5. **All 6 framework source files:**
   - `src/frameworks/types.rs` — TOML serde schema (151 lines)
   - `src/frameworks/loader.rs` — Compilation from TOML → compiled regexes (284 lines)
   - `src/frameworks/matcher.rs` — `FileDetectorHandler` implementation (587 lines)
   - `src/frameworks/learner.rs` — `LearningDetectorHandler` implementation (218 lines) — **NEVER CALLED**
   - `src/frameworks/registry.rs` — Pack loading: 22 built-in + custom from `.drift/frameworks/` (107 lines)
   - `src/frameworks/mod.rs` — Module re-exports (23 lines)

After reading all documents, you should be able to answer:
- Why does `FrameworkLearner` exist but produce zero output?
- What happens when one pattern in a TOML pack has an invalid regex?
- Why don't framework matches appear in `JsAnalysisResult.matches`?
- Which OWASP references in `security.toml` are stale?
- Where in `analysis.rs` would you insert the learning detect pass (Step 2c)?

If you cannot answer all 5, re-read the documents.

---

## Phase Execution Order

Execute phases in this exact order. Do not skip ahead. Each phase has a **gate** — you must pass the gate before moving to the next phase.

### Phase A: Learner Wiring & Error Resilience (P0 — start here)

**Goal:** Wire the FrameworkLearner into the pipeline. Fix all error handling to be per-pattern. Add timing. Fix OWASP 2017→2021. Fix JsAnalysisResult framework match omission.

**Files you will modify:**
- `crates/drift/drift-analysis/src/frameworks/loader.rs` — Add `#[derive(Clone)]` to compiled types, per-pattern error recovery, empty regex rejection, unknown language warning, detect_signal warning
- `crates/drift/drift-analysis/src/frameworks/matcher.rs` — Add `file_result_start` field + `last_file_results()` method for per-file tracking
- `crates/drift/drift-analysis/src/frameworks/packs/security.toml` — OWASP 2017→2021
- `crates/drift/drift-analysis/src/frameworks/packs/auth.toml` — Add CWE IDs
- `crates/drift/drift-analysis/src/frameworks/packs/data_access.toml` — Add CWE IDs
- `crates/drift/drift-napi/src/bindings/analysis.rs` — Wire FrameworkLearner (new Step 2c), remove `max_phase >= 3` guard on file_contents, include framework matches in JsAnalysisResult, add timing instrumentation

**Implementation tasks:** `FW-LEARN-01` through `FW-LEARN-05`, `FW-LOAD-01` through `FW-LOAD-04`, `FW-TIME-01` through `FW-TIME-03`, `FW-OWASP-01` through `FW-OWASP-03`, `FW-JSRES-01` through `FW-JSRES-02` in the spec. (16 tasks total)

**Tests you will write (22 tests):** `FWT-LEARN-01` through `FWT-LEARN-08`, `FWT-LOAD-01` through `FWT-LOAD-05`, `FWT-TIME-01`, `FWT-OWASP-01` through `FWT-OWASP-03`, `FWT-JSRES-01` through `FWT-JSRES-02`, `FWT-CLONE-01` through `FWT-CLONE-02`.

**Testing philosophy for this phase:**
- `FWT-LEARN-01`: Create 2 synthetic TOML packs with `learn.group_by = "sub_type"`, simulate 10 files with pattern-A (90%) and 1 file with pattern-B (10%). Verify `FrameworkLearner.detect()` emits a `LearningDeviation` match for the minority file. Not just "does it run" — verify the specific pattern_id contains `/deviation` suffix and `detection_method == LearningDeviation`.
- `FWT-LEARN-05`: Pack with NO `[patterns.learn]` directives: verify `FrameworkLearner.results()` is empty, no crash, no spurious output.
- `FWT-LEARN-06`: ALL files use the same pattern (unanimous): verify ZERO deviations emitted (dominant ratio = 1.0).
- `FWT-LOAD-01`: **This is the critical resilience test.** Pack with 5 patterns where 1 has regex `"[invalid"`. Verify the OTHER 4 patterns compile successfully, the bad one is skipped, and a warning containing the pattern ID is logged. The pack must NOT be killed entirely.
- `FWT-LOAD-02`: Pattern with `content_patterns = [""]`. Verify the pattern is REJECTED — empty regex matches every line, which is always wrong.
- `FWT-LOAD-05`: **Regression gate.** After all error handling changes, verify all 22 built-in packs still load with 0 skipped patterns. If this fails, you introduced a bug.
- `FWT-JSRES-01`: Parse a file with a known framework pattern (e.g., `import express from 'express'` against the express pack). Verify the `JsAnalysisResult.matches` for that file contains the framework match. This test FAILS today — framework matches are missing from per-file results.
- `FWT-OWASP-03`: After updating security.toml, match a CSRF pattern and verify the resulting detection has `owasp = "A01:2021"` (not the old `A5:2017`). Then verify it flows through to the `owasp_findings` table enrichment at `analysis.rs:874-901`.

**Critical implementation detail for FW-LEARN-05 (detect pass):**
The detect pass must iterate `all_parse_results` and reconstruct `DetectionContext` from cached `file_contents`. This requires `file_contents` to be populated even at `max_phase < 3`. You MUST remove the `if max_phase >= 3` guard at `analysis.rs:206-210` first (`FW-LEARN-04`). The detect pass goes BEFORE Step 2b (framework match collection at L282) so both matcher and learner results merge into `all_matches` before persistence and pattern intelligence.

**Gate:**
```bash
cargo test -p drift-analysis --test frameworks_test
cargo test -p drift-analysis --lib
cargo clippy -p drift-analysis -p drift-napi -p drift-storage -- -D warnings
```
All existing 187+ lib tests must still pass. All new FWT-* tests pass. Zero clippy warnings.

---

### Phase B: Coverage Parity & New Predicates (P1)

**Goal:** Add `file_patterns` and `type_annotations` match predicates. Build `typescript_types.toml` (12 patterns). Add Warp patterns. Close remaining coverage gaps.

**Files you will modify:**
- `crates/drift/drift-analysis/src/frameworks/types.rs` — Add `file_patterns` and `type_annotations` fields to `MatchBlock`
- `crates/drift/drift-analysis/src/frameworks/loader.rs` — Compile new fields: `glob::Pattern` for file_patterns, `Regex` for type_annotations
- `crates/drift/drift-analysis/src/frameworks/matcher.rs` — Add matching logic for both new predicates (AND semantics with existing predicates)
- `crates/drift/drift-analysis/src/frameworks/packs/typescript_types.toml` — NEW: 12 patterns
- `crates/drift/drift-analysis/src/frameworks/packs/rust_frameworks.toml` — 4 Warp patterns
- `crates/drift/drift-analysis/src/frameworks/packs/config.toml` — Environment detection
- `crates/drift/drift-analysis/src/frameworks/packs/styling.toml` — BEM class naming
- `crates/drift/drift-analysis/src/frameworks/packs/errors.toml` — Try-catch placement
- `crates/drift/drift-analysis/src/frameworks/packs/structural.toml` — File naming conventions
- `crates/drift/drift-analysis/src/frameworks/registry.rs` — Register `typescript_types.toml`

**Implementation tasks:** `FW-PRED-01` through `FW-PRED-02`, `FW-PACK-01` through `FW-PACK-06` in the spec. (14 tasks total)

**Tests you will write (18 tests):** `FWT-PRED-01` through `FWT-PRED-08`, `FWT-PACK-01` through `FWT-PACK-10`.

**Testing philosophy for this phase:**
- `FWT-PRED-01`: `file_patterns = ["*.d.ts"]` MUST match `types/index.d.ts` and MUST NOT match `types/index.ts`. Glob matching, not substring.
- `FWT-PRED-04`: Pattern requiring BOTH `type_annotations = ["\\bany\\b"]` AND `imports = ["express"]`: fires ONLY when both are present. This tests AND semantics.
- `FWT-PACK-05`: `let warp_drive = true;` must NOT match Warp patterns. The regex must require `warp::path`, not bare `warp`.
- `FWT-PACK-10`: **False positive gate.** Run matcher against a plain `hello_world.ts` with no framework code. Verify ZERO matches from all new packs. If this fails, your patterns are too broad.

**Gate:**
```bash
cargo test -p drift-analysis --test frameworks_test
cargo test -p drift-analysis --lib
cargo clippy -p drift-analysis -- -D warnings
```
All 23+ packs load with 0 skipped patterns. All new predicate tests pass. Zero false positives on hello_world.ts.

---

### Phase C: Enterprise Integration — Diagnostics, Storage, Monitoring (P1)

**Goal:** Add `FrameworkDiagnostics` struct. Add 4 storage query functions. Evaluate `detect_signals`. Add pack enable/disable config.

**Files you will modify:**
- `crates/drift/drift-analysis/src/frameworks/diagnostics.rs` — NEW: `FrameworkDiagnostics` struct
- `crates/drift/drift-analysis/src/frameworks/mod.rs` — Register diagnostics module
- `crates/drift/drift-analysis/src/frameworks/matcher.rs` — Accumulate hit counters
- `crates/drift/drift-analysis/src/frameworks/learner.rs` — Accumulate learning counters
- `crates/drift/drift-analysis/src/frameworks/registry.rs` — Track load/skip counts, detect_signals evaluation, config filtering
- `crates/drift/drift-napi/src/bindings/analysis.rs` — Collect and log diagnostics
- `crates/drift/drift-storage/src/queries/detections.rs` — 4 new query functions

**Implementation tasks:** `FW-DIAG-01` through `FW-DIAG-05`, `FW-STORE-01` through `FW-STORE-04`, `FW-DETECT-01` through `FW-DETECT-03`, `FW-CONFIG-01` through `FW-CONFIG-02`. (16 tasks total)

**Tests you will write (20 tests):** `FWT-DIAG-01` through `FWT-DIAG-06`, `FWT-STORE-01` through `FWT-STORE-06`, `FWT-DETECT-01` through `FWT-DETECT-04`, `FWT-CONFIG-01` through `FWT-CONFIG-04`.

**Testing philosophy for this phase:**
- `FWT-STORE-01`: Insert 5 detections with `detection_method = "TomlPattern"` and 5 with `"AstVisitor"`. Query by method "TomlPattern". Verify exactly 5 returned. This tests the new query function.
- `FWT-STORE-06`: **Empty database.** Call all 4 new query functions on an empty DB. All must return empty vec, no crash, no SQL error.
- `FWT-CONFIG-03`: **Backward compatibility.** No config file present at all. Verify ALL packs load (same as before config was added). This must not be a regression.
- `FWT-DIAG-04`: After matching, `files_matched` must be LESS than `files_processed` (not every file has framework patterns). This tests that counters aren't just mirroring each other.

**Gate:**
```bash
cargo test -p drift-analysis --test frameworks_test
cargo test -p drift-storage
cargo clippy -p drift-analysis -p drift-napi -p drift-storage -- -D warnings
```

---

### Phase D: Performance Optimization (P2)

**Goal:** RegexSet for content_patterns. Aho-Corasick for literal predicates. Per-file match limit. detect_signals pack filtering.

**Files you will modify:**
- `crates/drift/drift-analysis/src/frameworks/loader.rs` — Build `RegexSet` and `AhoCorasick` automata at compile time
- `crates/drift/drift-analysis/src/frameworks/matcher.rs` — Use RegexSet/AC for fast-path, per-file match limit

**Implementation tasks:** `FW-PERF-01` through `FW-PERF-10`. (10 tasks total)

**Tests you will write (14 tests):** `FWT-PERF-01` through `FWT-PERF-14`.

**Testing philosophy for this phase:**
- `FWT-PERF-01`: **Equivalence test.** This is the most important test. Run ALL 261+ patterns against a diverse multi-language fixture using BOTH the old per-regex path and the new RegexSet path. Results must be IDENTICAL. If they differ on even 1 match, the optimization is wrong.
- `FWT-PERF-12`: **Full regression.** All 22+ packs against the same fixture as before optimization. Identical results. Zero regressions.
- `FWT-PERF-14`: **Binary file.** Feed a file with invalid UTF-8 bytes. Verify content_patterns handles `String::from_utf8_lossy` gracefully — no panic, no crash.

**Gate:**
```bash
cargo test -p drift-analysis --test frameworks_test
cargo test -p drift-analysis --lib
cargo clippy -p drift-analysis -- -D warnings
```
Equivalence tests prove identical results. Benchmark shows measurable improvement.

---

### Phase E: Enhancements, CLI & Regression (P2-P3)

**Goal:** Learning signal types (frequency/presence/co_occurrence). Pack versioning. JSON Schema. validate-pack CLI. Framework degradation alerts. Full E2E regression.

**Files you will modify:**
- `crates/drift/drift-analysis/src/frameworks/types.rs` — Add `version` field
- `crates/drift/drift-analysis/src/frameworks/learner.rs` — Signal type dispatch
- `crates/drift/drift-analysis/src/frameworks/loader.rs` — Pass version through
- `crates/drift/drift-napi/src/bindings/analysis.rs` — Degradation alerts
- `packages/drift-cli/src/commands/` — validate-pack command

**Implementation tasks:** `FW-SIGNAL-01` through `FW-SIGNAL-03`, `FW-VER-01` through `FW-VER-02`, `FW-SCHEMA-01` through `FW-SCHEMA-02`, `FW-CLI-01`, `FW-DEGRADE-01`, `FW-REG-01` through `FW-REG-02`. (10 tasks total)

**Tests you will write (16 tests):** `FWT-SIGNAL-01` through `FWT-SIGNAL-05`, `FWT-VER-01` through `FWT-VER-02`, `FWT-SCHEMA-01` through `FWT-SCHEMA-02`, `FWT-CLI-01` through `FWT-CLI-03`, `FWT-DEGRADE-01` through `FWT-DEGRADE-02`, `FWT-REG-01` through `FWT-REG-02`.

**Testing philosophy for this phase:**
- `FWT-SIGNAL-05`: Unknown `learn.signal = "nonexistent"`. Verify warning logged, no crash, no output. Graceful degradation.
- `FWT-REG-01`: **This is the capstone E2E test.** Parse real code through the full pipeline (parse → detect → framework match → framework learn → persist → pattern intelligence → enforcement → OWASP enrichment). Verify framework detections appear in the detections table, get scored by pattern intelligence, are processed by enforcement gates, and security patterns with CWE/OWASP appear in owasp_findings. This tests the ENTIRE downstream chain.
- `FWT-REG-02`: Create a temp `.drift/frameworks/custom.toml` with 1 pattern. Run pipeline. Verify custom pack pattern matches appear alongside built-in patterns in the same results. Custom packs must not shadow or break built-in packs.

**Gate:**
```bash
cargo test -p drift-analysis
cargo test -p drift-napi
cargo test -p drift-storage
cargo clippy --workspace -- -D warnings
```
ZERO regressions across all 187+ lib tests and 48+ integration tests.

---

## Architecture Constraints

These are non-negotiable. Violating any will break the system.

1. **`PatternMatch` is the universal output type.** All framework matches (both matcher and learner) must produce `PatternMatch` structs with correct `detection_method` (`TomlPattern` or `LearningDeviation`), `category`, `cwe_ids`, and `owasp` fields. Downstream consumers (pattern intelligence, enforcement, OWASP enrichment) process ALL `PatternMatch` types uniformly.

2. **`all_matches` is the single merge point.** Framework matcher results AND learner results must both flow into `all_matches` (via `.extend()`) BEFORE Step 3 (persistence) and Step 4 (pattern intelligence). Do not create separate pipelines.

3. **`DetectionRow` is the storage format.** When persisting to the detections table, `detection_method` is `format!("{:?}", m.detection_method)` — i.e., `"TomlPattern"` or `"LearningDeviation"` as strings. `cwe_ids` is a comma-separated string or None. Match the exact format used at `analysis.rs:220-236`.

4. **`DetectionContext::from_parse_result(pr, source)` reconstructs context.** The learning detect pass needs contexts for all files. Reconstruct from `all_parse_results` + `file_contents`. Source bytes come from `content.as_bytes()`. Do NOT re-read files from disk.

5. **Timing follows the existing pattern.** Every pipeline step uses `let step_timer = std::time::Instant::now();` at the start and `eprintln!("[drift-analyze] STEP_NAME: {:?}", step_timer.elapsed());` at the end. Framework steps must use `2a`, `2b`, `2c` labels.

6. **Logging follows the `[drift]` and `[drift-analyze]` prefixes.** Load-time warnings use `[drift] warning: ...`. Pipeline timing uses `[drift-analyze] ...`. Match the existing patterns exactly.

7. **`cargo clippy --workspace -- -D warnings` must be clean after every phase.** No `#[allow(dead_code)]`, no `#[allow(unused)]`. Fix the code, don't suppress the warning.

8. **Do not change public trait signatures.** `FileDetectorHandler`, `LearningDetectorHandler`, and `DetectorHandler` traits in `visitor.rs` are stable. Add methods to your own structs, not to these traits.

---

## Testing Standards

Every test you write must meet ALL of these criteria:

### What Makes a Good Test
- **Targets a specific failure mode** — not "does it work?" but "does it fail correctly when X happens?"
- **Has a clear assertion** — not `assert!(result.is_ok())` but `assert_eq!(pack.patterns.len(), 4)` with a message
- **Tests the boundary, not the interior** — call the public API, verify the observable output
- **Includes negative cases** — what happens with empty input? Bad regex? Unknown language? Unanimous convention?

### What Makes a Bad Test (do NOT write these)
- Tests that only verify the happy path with perfect input
- Tests that assert `is_ok()` without checking the actual value
- Tests that are really testing TOML parsing, not framework matching
- Tests that create unrealistic inputs no real codebase would have

### Specific Test Patterns Required
- **Error resilience:** Create a pack with 1 bad pattern among 4 good ones. Verify 4 compile, 1 skipped. The pack LIVES.
- **Regression gates:** After every change, verify all 22+ built-in packs still load with 0 skipped patterns.
- **False positive gates:** Run all new patterns against trivial code. Verify 0 matches.
- **Learning convention detection:** Create files with known frequency distributions. Verify deviations detected at the correct threshold.
- **Downstream flow verification:** Framework matches must appear in `all_matches`, detection_rows, pattern intelligence, and enforcement. Test the chain, not just the node.

---

## Subsystems That Are Clean (do NOT modify their internals)

- **PatternIntelligencePipeline** (`patterns/pipeline.rs`) — Processes all `PatternMatch` uniformly
- **GateOrchestrator** (enforcement gates) — Processes all `PatternInfo` uniformly
- **BatchWriter** (`drift-storage/src/batch/`) — `InsertDetections` handler already correct
- **All 14 contract extractors** — Independent of framework system
- **All 5 graph intelligence modules** — Consume call graph, not framework matches
- **All structural sub-steps** (5a-5g in analysis.rs) — Independent of framework matches
- **ParseResult / DetectionContext** — Already extracts all fields framework system needs

You will USE these subsystems (the learning detect pass needs `DetectionContext`, matches flow to `PatternIntelligencePipeline`, etc.) but do not modify their internals.

---

## How to Verify Your Work

After each phase, run:

```bash
# Framework-specific tests
cargo test -p drift-analysis --test frameworks_test

# Full lib tests (must not regress)
cargo test -p drift-analysis --lib

# Storage tests (Phase C)
cargo test -p drift-storage

# Clippy (zero warnings required)
cargo clippy -p drift-analysis -p drift-napi -p drift-storage -- -D warnings

# Full regression (before phase merge)
cargo test -p drift-analysis
cargo test -p drift-napi
cargo test -p drift-storage
cargo clippy --workspace -- -D warnings
```

If any test fails, fix it before moving to the next phase. Do not accumulate broken tests.

---

## Critical Questions You Must Be Able to Answer After Each Phase

### After Phase A:
- Does `FrameworkLearner::learn()` get called for every file in the per-file loop?
- Does `FrameworkLearner::detect()` get called for every file in the post-loop detect pass?
- Do learning deviation matches appear in `detection_rows` with `detection_method = "LearningDeviation"`?
- Do learning matches flow to `all_matches` and reach pattern intelligence and enforcement?
- Does `JsAnalysisResult.matches` now include framework matches for each file?
- What happens when a TOML pack has 1 invalid regex among 5 patterns?

### After Phase B:
- Does `file_patterns = ["*.d.ts"]` match only `.d.ts` files?
- Does `type_annotations = ["\\bany\\b"]` match function parameters with `: any`?
- How many patterns are in `typescript_types.toml`? (Must be 12+)
- Does a plain `hello_world.ts` produce 0 framework matches? (False positive gate)

### After Phase C:
- Does `FrameworkDiagnostics` contain real values for `builtin_packs_loaded`, `total_hits`, and `learning_deviations`?
- Does `get_detections_by_method("TomlPattern")` return only framework detections?
- Does `get_detections_by_cwe(89)` return SQL injection detections?
- Does a disabled pack get excluded from matching?

### After Phase D:
- Are RegexSet results IDENTICAL to per-regex results? (Equivalence must be proven)
- Does Aho-Corasick produce identical results to linear search?
- Does the per-file match limit truncate at 100 with a warning?

### After Phase E:
- Does a `frequency` signal flag unusually rare patterns?
- Does `drift validate-pack valid.toml` exit 0? `invalid.toml` exit 1?
- Does the E2E regression test prove framework data flows through ALL downstream consumers?
