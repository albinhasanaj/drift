# Drift V2 — Enforcement Engine & Rule System Hardening Task Tracker

> **Source of Truth:** Deep audit of `crates/drift/drift-analysis/src/enforcement/` — gates, rules, policy, reporters, audit, feedback
> **Target:** Every gate fires on real data, every reporter produces valid output, the feedback loop closes, and the NAPI layer exposes real results instead of stubs.
> **Crate:** `crates/drift/drift-analysis/`
> **Total Phases:** 5 (A–E)
> **Quality Gates:** 5 (QG-A through QG-E)
> **Architectural Decision:** The architecture is sound — types, traits, enums, orchestrator DAG, policy aggregation modes, reporter trait, feedback loop types are all correctly designed. The problems are: (1) gates consume `GateInput` fields that are never populated by any caller, (2) NAPI bindings are hardcoded stubs returning empty results, (3) reporters have minor format deviations from official schemas, (4) the deduplication engine uses a count-ratio proxy instead of real Jaccard similarity, (5) the feedback loop is self-contained but not wired into the confidence scoring system.
> **Dependency:** Detector Parity Phase A (parser extraction) should land first. Call Graph hardening (✅ Complete) provides graph data.
> **Rule:** No Phase N+1 begins until Phase N quality gate passes.
> **Rule:** All changes must compile with `cargo clippy --workspace -- -D warnings` clean.
> **Rule:** Every impl task has a corresponding test task. No untested code.
> **Verification:** This tracker accounts for 100% of the 40 files in the enforcement subsystem.

---

## Progress Summary

| Phase | Description | Impl Tasks | Test Tasks | Status |
|-------|-------------|-----------|-----------|--------|
| A | Gate Wiring & Input Population | 14 | 18 | Not Started |
| B | Rules, Policy & Suppression Hardening | 10 | 14 | Not Started |
| C | Reporter Format Correctness | 12 | 16 | Not Started |
| D | Audit & Feedback Loop Closure | 10 | 14 | Not Started |
| E | NAPI Integration, Downstream Wiring & Regression | 8 | 16 | Not Started |
| **TOTAL** | | **54** | **78** | |

---

## Audit Findings Reference

### Root Cause

The enforcement engine is **architecturally complete** but has a **wiring gap**: no caller constructs a populated `GateInput` and feeds it to the `GateOrchestrator`. The NAPI bindings (`drift-napi/src/bindings/enforcement.rs`) define 4 functions (`drift_check`, `drift_audit`, `drift_violations`, `drift_gates`) that all return **hardcoded empty/default values** without calling any enforcement logic.

This means: (1) every gate silently passes on empty input, (2) no violations are ever produced, (3) no reports are ever generated, (4) the feedback loop never fires, (5) the audit system scores 30.0 (empty default).

### Evidence Table (line-verified)

| Finding | Location | Current Behavior | Should Be |
|---------|----------|-----------------|-----------|
| `drift_check()` returns hardcoded empty | `drift-napi/bindings/enforcement.rs:76-83` | `overall_passed: true, gates: Vec::new()` | Call `GateOrchestrator::execute()` with populated `GateInput` |
| `drift_audit()` returns hardcoded default | `drift-napi/bindings/enforcement.rs:87-102` | `health_score: 100.0`, all zeros | Call `HealthScorer::compute()` with real data |
| `drift_violations()` returns empty vec | `drift-napi/bindings/enforcement.rs:106-108` | `Ok(Vec::new())` | Call `RulesEvaluator::evaluate()` |
| `drift_gates()` returns empty vec | `drift-napi/bindings/enforcement.rs:112-114` | `Ok(Vec::new())` | Return `GateOrchestrator::execute()` results |
| `GateInput` fields never populated | `gates/types.rs:163-175` | All fields `Default` (empty vecs, None) | Pipeline must populate from analysis results |
| `test_coverage` gate silently passes on None | `gates/test_coverage.rs:26-31` | Returns `pass` score 100 | Should return `skipped` status |
| `constraint_verification` passes on empty | `gates/constraint_verification.rs:60-64` | Score 100 on empty | Should return `skipped` |
| `error_handling` passes on empty | `gates/error_handling.rs:56-60` | Score 100 on empty | Should return `skipped` |
| Progressive enforcement not wired | `gates/progressive.rs` | Exists but no gate calls `effective_severity()` | Orchestrator should apply progressive severity |
| `is_new` always false | `rules/evaluator.rs:56` | `is_new: false` hardcoded | Compare against baseline |
| Quick fixes are language-blind | `rules/quick_fixes.rs:88-89` | JS-only `try/catch` for all languages | Language-aware templates |
| Suppression misses `# noqa` / `eslint-disable` | `rules/suppression.rs:50` | Only `drift-ignore` | Support `# noqa`, `eslint-disable`, `@SuppressWarnings` |
| Policy `check_required_gates` wrong default | `policy/engine.rs:66` | `map_or(true, ...)` — missing gate = pass | Missing required gate should fail |
| SonarQube reporter uses deprecated format | `reporters/sonarqube.rs:60-108` | No `rules` array, no `cleanCodeAttribute` | Add per SonarQube 10.3+ spec |
| JUnit `errors`/`failures` swapped | `reporters/junit.rs:82-84,97-101` | `failures`=Errors, `errors`=Warnings | JUnit convention is reversed |
| SARIF taxonomies at wrong level | `reporters/sarif.rs:239` | `taxonomies` at run level only | Also need `tool.driver.supportedTaxonomies` |
| Deduplication uses count proxy | `audit/deduplication.rs:69-88` | `min_count / max_count` ratio | Use `jaccard_from_sets()` with actual location sets |
| Confidence feedback not wired | `feedback/confidence_feedback.rs:15-57` | Returns deltas but no caller applies them | Wire into `patterns/confidence/` |
| `FeedbackStatsProvider` only has NoOp | `feedback/stats_provider.rs:24-42` | Always returns 0.0 | `FeedbackTracker` should implement the trait |
| No gate uses `FeedbackStatsProvider` | All gate files | No import | Gates should use FP rates to adjust severity |

### Upstream Data Dependencies

| Gate | Consumed Field | Upstream Source | Status |
|------|---------------|----------------|--------|
| PatternCompliance | `patterns` | patterns/ aggregation | Not audited |
| ConstraintVerification | `constraints` | structural/constraints/ | Not audited |
| SecurityBoundaries | `security_findings` | graph/taint/ + detector CWE | CG ✅, DP Not Started |
| TestCoverage | `test_coverage` | graph/test_topology/ | CG ✅ |
| ErrorHandling | `error_gaps` | graph/error_handling/ + parser | DP Not Started |
| Regression | `previous/current_health_score` | audit/health_scorer + persistence | Functional but needs snapshots |

### Downstream Consumer Status

| Consumer | Location | Status |
|----------|----------|--------|
| NAPI bindings | `drift-napi/bindings/enforcement.rs` | ❌ 4 stub functions |
| NAPI contracts (TS) | `drift-napi-contracts/src/types/enforcement.ts` | ✅ Types aligned |
| MCP tools | `drift-mcp/src/infrastructure/` | ⚠️ Depends on NAPI stubs |
| CLI | `drift-cli/src/index.ts` | ⚠️ Uses NAPI stubs |
| CI | `drift-ci/tests/ci_agent.test.ts` | ⚠️ Tests against stubs |
| Bridge | `cortex-drift-bridge/src/event_mapping/mapper.rs` | ⚠️ Maps enforcement events but receives empty data |

### What Works Today vs. What Doesn't

**Functional (~60% structurally):** Gate orchestrator DAG, rules evaluator, suppression (drift-ignore only), policy engine (4 modes), console/JSON/HTML/GitHub/GitLab reporters, health scorer, degradation detector, trend analyzer, auto-approver, feedback tracker.

**Broken/Stubbed:** NAPI bindings (hardcoded empty), all gates (silently pass on empty input), progressive enforcement (unwired), SonarQube reporter (deprecated format), JUnit reporter (swapped semantics), deduplication (proxy), confidence feedback (unwired), stats provider (NoOp only).

**Bottom line: 0% produces real output today because the NAPI layer is stubbed and no caller populates `GateInput`.**

---

## Phase A: Gate Wiring & Input Population

> **Goal:** Wire the analysis pipeline to populate `GateInput` with real data, fix gates that silently pass on empty input, wire progressive enforcement.
> **Estimated effort:** 3–4 days
> **Depends on:** Detector Parity Phase A, Call Graph hardening (✅ Complete)

### A1 — Create `GateInput` Builder

- [ ] `EF-GATE-01` — **Create `GateInputBuilder`** in `gates/types.rs` — Takes analysis pipeline output and populates all 10 `GateInput` fields: patterns from aggregation, constraints from structural, security_findings from taint+CWE, test_coverage from topology, error_gaps from error analysis, health scores from audit snapshots.
- [ ] `EF-GATE-02` — **Map taint flows to `SecurityFindingInput`** — Each `TaintFlow` → `SecurityFindingInput` with file, line, description, severity, cwe_ids, owasp_categories.
- [ ] `EF-GATE-03` — **Map error handling gaps to `ErrorGapInput`** — `has_body==false` → `gap_type="empty_catch"`, `caught_type==None` → `gap_type="generic_catch"`.
- [ ] `EF-GATE-04` — **Map test topology to `TestCoverageInput`** — `overall_coverage` = % source functions covered, `threshold` from policy config, `uncovered_files` = files with 0 coverage.

### A2 — Fix Gates That Silently Pass

- [ ] `EF-GATE-05` — **TestCoverage: return `skipped` when no data** — `test_coverage.rs:23-31`: return `GateResult::skipped()` instead of `pass` when `None`.
- [ ] `EF-GATE-06` — **ConstraintVerification: return `skipped` when empty** — `constraint_verification.rs:60-64`.
- [ ] `EF-GATE-07` — **ErrorHandling: return `skipped` when empty** — `error_handling.rs:56-60`.
- [ ] `EF-GATE-08` — **SecurityBoundaries: return `skipped` when empty** — `security_boundaries.rs:96-100`.

### A3 — Wire Progressive Enforcement

- [ ] `EF-GATE-09` — **Add `ProgressiveConfig` to orchestrator** — After each gate produces violations, apply `effective_severity()`. Detect new files via `input.files` vs `input.all_files`.
- [ ] `EF-GATE-10` — **Wire progressive into policy** — During ramp-up, use lower threshold.

### A4 — Add `is_new` Detection & Regression Enhancement

- [ ] `EF-GATE-11` — **Detect new violations via baseline** — Add `baseline_violations: HashSet<String>` to `GateInput`. Mark `is_new = true` for violations not in baseline.
- [ ] `EF-GATE-12` — **Enhance regression gate** — Also fail on new Error-severity violations, not just health score delta.

### A5 — Fix Orchestrator Edge Cases

- [ ] `EF-GATE-13` — **Avoid cloning `predecessor_results`** — `orchestrator.rs:72-73`: use `Arc<HashMap>` or reference.
- [ ] `EF-GATE-14` — **Add gate execution timeout** — Default 30s, return `errored` on timeout.

### Phase A Tests

- [ ] `EFT-GATE-01` — Builder populates `security_findings` from 3 taint flows
- [ ] `EFT-GATE-02` — Builder populates `error_gaps` from 2 empty catch blocks
- [ ] `EFT-GATE-03` — Builder populates `test_coverage` from topology
- [ ] `EFT-GATE-04` — TestCoverage returns `Skipped` when no data
- [ ] `EFT-GATE-05` — ConstraintVerification returns `Skipped` when empty
- [ ] `EFT-GATE-06` — ErrorHandling returns `Skipped` when empty
- [ ] `EFT-GATE-07` — SecurityBoundaries returns `Skipped` when empty
- [ ] `EFT-GATE-08` — Progressive downgrades Error → Info in week 1
- [ ] `EFT-GATE-09` — Progressive preserves Error after ramp-up
- [ ] `EFT-GATE-10` — Progressive applies full severity to new files
- [ ] `EFT-GATE-11` — `is_new` correctly marks violations not in baseline
- [ ] `EFT-GATE-12` — Regression gate fails on new Error violations
- [ ] `EFT-GATE-13` — Regression gate passes when only existing violations remain
- [ ] `EFT-GATE-14` — Orchestrator executes 6 gates in dependency order
- [ ] `EFT-GATE-15` — Orchestrator skips dependent gate when dependency fails
- [ ] `EFT-GATE-16` — Orchestrator detects circular dependency
- [ ] `EFT-GATE-17` — Gate timeout returns `Errored` status
- [ ] `EFT-GATE-18` — Full pipeline: populated `GateInput` → 6 gate results with real scores

### Quality Gate A (QG-A)

```
MUST PASS before Phase B begins:
- [ ] GateInputBuilder produces non-empty GateInput from synthetic analysis results
- [ ] At least 3 gates return non-pass status when given real findings
- [ ] TestCoverage/ConstraintVerification/ErrorHandling return Skipped on empty input
- [ ] Progressive enforcement modifies severity during ramp-up
- [ ] is_new correctly identifies new violations vs. baseline
- [ ] cargo clippy --workspace -- -D warnings passes
- [ ] cargo test -p drift-analysis passes
```

---

## Phase B: Rules, Policy & Suppression Hardening

> **Goal:** Fix rules evaluator `is_new`, language-aware quick fixes, expanded suppression, policy edge case.
> **Estimated effort:** 2–3 days
> **Depends on:** Phase A

### B1 — Fix Rules Evaluator

- [ ] `EF-RULE-01` — **Wire `is_new` from baseline** — `evaluator.rs:56`: add `baseline_violation_ids: HashSet<String>` to `RulesInput`, mark `is_new = !baseline.contains(&id)`.
- [ ] `EF-RULE-02` — **Populate `end_line`/`end_column`** — From pattern's known span when available.
- [ ] `EF-RULE-03` — **Integrate FP rates into severity** — If FP rate > 20%, downgrade severity by one level.

### B2 — Language-Aware Quick Fixes

- [ ] `EF-RULE-04` — **Add language parameter** — Python: `try/except`, Rust: `match`, Go: `if err != nil`, Java: `try/catch(Exception)`.
- [ ] `EF-RULE-05` — **Security fix: parameterized queries** — New `UseParameterizedQuery` strategy for taint/security category.

### B3 — Expand Suppression

- [ ] `EF-RULE-06` — **Support `# noqa`** (Python/flake8)
- [ ] `EF-RULE-07` — **Support `// eslint-disable-next-line`** (JS/TS)
- [ ] `EF-RULE-08` — **Support `@SuppressWarnings`** (Java/Kotlin)

### B4 — Fix Policy Engine

- [ ] `EF-RULE-09` — **Fix missing required gate** — `engine.rs:66`: change `map_or(true, ...)` to `map_or(false, ...)`.
- [ ] `EF-RULE-10` — **Add TOML policy loading** — `Policy::from_toml()` for `.drift/policy.toml`.

### Phase B Tests

- [ ] `EFT-RULE-01` — `is_new` true for new violations, false for existing
- [ ] `EFT-RULE-02` — `end_line` populated when span available
- [ ] `EFT-RULE-03` — Severity downgraded when FP rate > 20%
- [ ] `EFT-RULE-04` — Python quick fix → `try/except` template
- [ ] `EFT-RULE-05` — Rust quick fix → `match` template
- [ ] `EFT-RULE-06` — Go quick fix → `if err != nil` template
- [ ] `EFT-RULE-07` — Security fix → parameterized query suggestion
- [ ] `EFT-RULE-08` — `# noqa` suppresses violation (Python)
- [ ] `EFT-RULE-09` — `eslint-disable-next-line` suppresses (JS/TS)
- [ ] `EFT-RULE-10` — `@SuppressWarnings` suppresses (Java)
- [ ] `EFT-RULE-11` — Missing required gate causes policy failure
- [ ] `EFT-RULE-12` — Policy loads from TOML config
- [ ] `EFT-RULE-13` — Dedup keeps highest severity for same file:line:rule_id
- [ ] `EFT-RULE-14` — Suppressed violations excluded from gate failure count

### Quality Gate B (QG-B)

```
MUST PASS before Phase C begins:
- [ ] is_new correctly marks new violations
- [ ] Quick fixes produce language-appropriate templates for ≥4 languages
- [ ] Suppression works for drift-ignore, # noqa, eslint-disable-next-line
- [ ] Missing required gate causes policy failure
- [ ] cargo clippy clean, cargo test green
```

---

## Phase C: Reporter Format Correctness

> **Goal:** Fix all reporter format deviations from official schemas.
> **Estimated effort:** 2–3 days
> **Depends on:** Phase A (reporters need non-empty results)

### C1 — Fix SARIF Reporter

- [ ] `EF-RPT-01` — **Fix taxonomy placement** — Add `tool.driver.supportedTaxonomies` references alongside run-level `taxonomies`.
- [ ] `EF-RPT-02` — **Add `partialFingerprints`** — For GitHub Code Scanning deduplication.
- [ ] `EF-RPT-03` — **Add `relatedLocations` for taint flows** — Show source → sink path.

### C2 — Fix JUnit Reporter

- [ ] `EF-RPT-04` — **Fix `errors`/`failures` semantics** — `junit.rs:82-84,92-101`: swap mapping to match JUnit convention.
- [ ] `EF-RPT-05` — **Add `system-out`/`system-err`** — Gate summary in `system-out`, violation details in `system-err`.

### C3 — Fix SonarQube Reporter

- [ ] `EF-RPT-06` — **Add `rules` array** — Required since SonarQube 10.3. Include `cleanCodeAttribute` and `impacts`.
- [ ] `EF-RPT-07` — **Map to 10.3+ impact format** — Replace deprecated `severity` with `impacts` on rules.
- [ ] `EF-RPT-08` — **Verify `ruleId` alignment** — Each issue must reference a rule from the `rules` array.

### C4 — Enhance Other Reporters

- [ ] `EF-RPT-09` — **Console: `NO_COLOR` env var support** — Wire `use_color` to `NO_COLOR` per no-color.org.
- [ ] `EF-RPT-10` — **JSON: add `quick_fix` to output** — Currently omitted from violation JSON.
- [ ] `EF-RPT-11` — **HTML: severity filter buttons** — JS toggle for Error/Warning/Info/Hint rows.
- [ ] `EF-RPT-12` — **HTML: timestamp and project info** — Add to header for traceability.

### Phase C Tests

- [ ] `EFT-RPT-01` — SARIF validates against 2.1.0 schema
- [ ] `EFT-RPT-02` — SARIF has `supportedTaxonomies` + run-level `taxonomies`
- [ ] `EFT-RPT-03` — SARIF results have `partialFingerprints`
- [ ] `EFT-RPT-04` — SARIF taint violations have `relatedLocations`
- [ ] `EFT-RPT-05` — JUnit `failures` = Error-severity count
- [ ] `EFT-RPT-06` — JUnit `errors` = Warning-severity count
- [ ] `EFT-RPT-07` — JUnit XML validates against XSD
- [ ] `EFT-RPT-08` — SonarQube has `rules` array with `cleanCodeAttribute`
- [ ] `EFT-RPT-09` — SonarQube issues reference valid `ruleId`
- [ ] `EFT-RPT-10` — Console respects `NO_COLOR`
- [ ] `EFT-RPT-11` — JSON includes `quick_fix`
- [ ] `EFT-RPT-12` — HTML has severity filter buttons
- [ ] `EFT-RPT-13` — GitLab has all required fields
- [ ] `EFT-RPT-14` — GitHub has all required fields
- [ ] `EFT-RPT-15` — All 8 reporters produce non-empty output for 3-violation input
- [ ] `EFT-RPT-16` — All 8 reporters handle empty results gracefully

### Quality Gate C (QG-C)

```
MUST PASS before Phase D begins:
- [ ] SARIF validates against official schema
- [ ] JUnit errors/failures match convention
- [ ] SonarQube includes rules array (10.3+ format)
- [ ] All 8 reporters produce valid output
- [ ] cargo clippy clean, cargo test green
```

---

## Phase D: Audit & Feedback Loop Closure

> **Goal:** Fix deduplication, wire feedback into confidence scoring, implement FeedbackStatsProvider, connect gates to feedback.
> **Estimated effort:** 2–3 days
> **Depends on:** Phase A

### D1 — Fix Deduplication

- [ ] `EF-AUD-01` — **Use real Jaccard in `detect()`** — `deduplication.rs:69-88`: add `location_keys: Vec<String>` to `PatternAuditData`, use `jaccard_from_sets()`.
- [ ] `EF-AUD-02` — **Merge transitive groups** — Union-find to merge overlapping duplicate groups.

### D2 — Wire Feedback into Confidence

- [ ] `EF-AUD-03` — **Create `apply_feedback_to_confidence()`** — Takes `FeedbackRecord` + mutable Bayesian params, applies deltas.
- [ ] `EF-AUD-04` — **Wire into patterns/confidence/** — `FeedbackTracker::record()` also updates pattern confidence.
- [ ] `EF-AUD-05` — **Add confidence decay** — Patterns not seen in 30+ days get decayed confidence.

### D3 — Implement FeedbackStatsProvider

- [ ] `EF-AUD-06` — **Implement trait on `FeedbackTracker`** — Map `fp_rate_for_detector()`, `is_detector_disabled()`, etc.
- [ ] `EF-AUD-07` — **Add pattern-level FP tracking** — `pattern_metrics: HashMap<String, FeedbackMetrics>` alongside detector metrics.

### D4 — Connect Gates to Feedback

- [ ] `EF-AUD-08` — **Add `FeedbackStatsProvider` to `GateInput`** — Pass `Arc<dyn FeedbackStatsProvider>` so gates can query FP rates.
- [ ] `EF-AUD-09` — **SecurityBoundaries: skip disabled detectors** — If `is_detector_disabled(detector_id)`, exclude findings from that detector.
- [ ] `EF-AUD-10` — **PatternCompliance: adjust severity by FP rate** — If pattern's FP rate > 15%, downgrade outlier severity by one level.

### Phase D Tests

- [ ] `EFT-AUD-01` — Real Jaccard: identical location sets → similarity 1.0
- [ ] `EFT-AUD-02` — Real Jaccard: disjoint sets → similarity 0.0
- [ ] `EFT-AUD-03` — Transitive merge: A↔B, B↔C → single group [A,B,C]
- [ ] `EFT-AUD-04` — Feedback Fix action increases alpha by 1.0
- [ ] `EFT-AUD-05` — Feedback Dismiss(FalsePositive) increases beta by 0.5
- [ ] `EFT-AUD-06` — Confidence decays after 30 days without sighting
- [ ] `EFT-AUD-07` — `FeedbackTracker` implements `FeedbackStatsProvider` correctly
- [ ] `EFT-AUD-08` — Pattern-level FP rate tracked separately from detector
- [ ] `EFT-AUD-09` — Gate receives `FeedbackStatsProvider` and queries FP rate
- [ ] `EFT-AUD-10` — SecurityBoundaries skips findings from disabled detector
- [ ] `EFT-AUD-11` — PatternCompliance downgrades severity for high-FP patterns
- [ ] `EFT-AUD-12` — Auto-disable triggers at >20% FP sustained 30 days
- [ ] `EFT-AUD-13` — Abuse detection flags >100 dismissals in 60 seconds
- [ ] `EFT-AUD-14` — Health score changes when feedback updates confidence

### Quality Gate D (QG-D)

```
MUST PASS before Phase E begins:
- [ ] Deduplication uses real Jaccard similarity
- [ ] Feedback actions update pattern confidence (loop closed)
- [ ] FeedbackTracker implements FeedbackStatsProvider
- [ ] At least 1 gate uses FP rates to adjust behavior
- [ ] cargo clippy clean, cargo test green
```

---

## Phase E: NAPI Integration, Downstream Wiring & Regression

> **Goal:** Replace NAPI stubs with real enforcement calls, verify downstream consumers, E2E tests.
> **Estimated effort:** 2–3 days
> **Depends on:** Phases A–D complete
> **Files:** `drift-napi/bindings/enforcement.rs`, downstream TS packages

### E1 — Replace NAPI Stubs

- [ ] `EF-NAPI-01` — **Wire `drift_check()`** — `enforcement.rs:76-83`: call `GateInputBuilder::build()` → `GateOrchestrator::execute()` → `PolicyEngine::evaluate()`. Map `GateResult` → `JsGateResult`. Generate SARIF via `SarifReporter` and attach to `sarif` field.
- [ ] `EF-NAPI-02` — **Wire `drift_audit()`** — `enforcement.rs:87-102`: call `HealthScorer::compute()` with real `PatternAuditData`. Map `HealthBreakdown` → `JsHealthBreakdown`. Run `TrendAnalyzer` and `DegradationDetector`.
- [ ] `EF-NAPI-03` — **Wire `drift_violations()`** — `enforcement.rs:106-108`: call `RulesEvaluator::evaluate()`, map `Violation` → `JsViolation`.
- [ ] `EF-NAPI-04` — **Wire `drift_gates()`** — `enforcement.rs:112-114`: return real `GateResult` list from orchestrator.

### E2 — Add Reporter Selection to NAPI

- [ ] `EF-NAPI-05` — **Add `format` parameter to `drift_check()`** — Accept format string ("sarif", "json", "junit", etc.) and return the formatted report in `JsCheckResult`. Default to SARIF for `sarif` field, but allow override.
- [ ] `EF-NAPI-06` — **Add `drift_report()` NAPI function** — New function that takes format name and returns formatted report string. Enables CLI/MCP to request any format.

### E3 — End-to-End Integration Tests

- [ ] `EF-NAPI-07` — **E2E: TypeScript project** — Parse a 5-file TS project → build call graph → run taint analysis → populate GateInput → execute gates → generate SARIF → verify: at least 1 gate has non-100 score, SARIF contains violations with CWE IDs, console output shows pass/fail.
- [ ] `EF-NAPI-08` — **E2E: Python project** — Same as above for a Flask app. Verify: taint flow from `request.args` → `cursor.execute` produces SecurityBoundaries gate failure.

### Phase E Tests

- [ ] `EFT-NAPI-01` — `drift_check()` returns non-empty `gates` array
- [ ] `EFT-NAPI-02` — `drift_check()` returns `overall_passed: false` when security gate fails
- [ ] `EFT-NAPI-03` — `drift_check()` returns valid SARIF in `sarif` field
- [ ] `EFT-NAPI-04` — `drift_audit()` returns non-zero `health_score`
- [ ] `EFT-NAPI-05` — `drift_audit()` returns populated `breakdown` fields
- [ ] `EFT-NAPI-06` — `drift_violations()` returns non-empty violation list
- [ ] `EFT-NAPI-07` — `drift_gates()` returns 6 gate results
- [ ] `EFT-NAPI-08` — `drift_report("json")` returns valid JSON
- [ ] `EFT-NAPI-09` — `drift_report("junit")` returns valid JUnit XML
- [ ] `EFT-NAPI-10` — `drift_report("sonarqube")` returns valid SonarQube format
- [ ] `EFT-NAPI-11` — E2E TS: taint flow → security gate failure → SARIF with CWE
- [ ] `EFT-NAPI-12` — E2E Python: Flask taint → security gate failure
- [ ] `EFT-NAPI-13` — E2E: progressive enforcement active → violations downgraded in week 1
- [ ] `EFT-NAPI-14` — E2E: feedback dismiss → confidence decreases → health score changes
- [ ] `EFT-NAPI-15` — E2E: all 8 reporters produce valid output for real analysis
- [ ] `EFT-NAPI-16` — Performance: full enforcement pipeline <500ms for 100-file project

### Quality Gate E (QG-E)

```
MUST PASS for enforcement hardening to be complete:
- [ ] drift_check() returns real gate results (not stubs)
- [ ] drift_audit() returns real health scores
- [ ] drift_violations() returns real violations
- [ ] SARIF output from drift_check() validates against schema
- [ ] E2E: taint flow → security gate failure → SARIF with CWE
- [ ] All 8 reporters produce valid output on real analysis
- [ ] Performance: <500ms for 100-file project
- [ ] cargo clippy clean, cargo test green
```

---

## Dependency Graph

```
Detector Parity Phase A (parser extraction) ──┐
                                               ├──► Phase A (Gate Wiring)
Call Graph Hardening (✅ Complete) ────────────┘        │
                                                       ├──► Phase B (Rules/Policy)
                                                       │        │
                                                       ├──► Phase C (Reporters) ←── parallelizable with B
                                                       │
                                                       └──► Phase D (Audit/Feedback) ←── parallelizable with B/C
                                                                │
                                                                └──► Phase E (NAPI/E2E)
```

**Critical path:** A(3-4d) → B(2-3d) → E(2-3d) = **7-10 working days**
**With parallelization:** A(3-4d) → {B, C, D in parallel}(2-3d) → E(2-3d) = **7-10 working days**

---

## Answers to Critical Questions

1. **How many gates actually fire vs. silently pass?** — **0 of 6 gates fire today.** All receive empty `GateInput` and return `pass` with score 100. After Phase A, all 6 will fire on real data.

2. **Which reporters produce valid output?** — **5 of 8 are valid** (console, JSON, HTML, GitHub, GitLab). SARIF has minor taxonomy placement issue. JUnit has swapped errors/failures semantics. SonarQube uses deprecated pre-10.3 format missing required `rules` array.

3. **Is the progressive gate (ratchet) functional?** — **No.** `ProgressiveEnforcement` exists with correct logic but no gate calls `effective_severity()`. After Phase A, it will be wired into the orchestrator.

4. **Does the feedback loop close?** — **No.** `ConfidenceFeedback` computes Bayesian deltas but no caller applies them to pattern confidence. `FeedbackStatsProvider` only has a NoOp implementation. After Phase D, the loop will close: feedback → confidence update → health score change → gate behavior change.

5. **What percentage is functional vs. scaffolding?** — **~60% structurally functional, 0% produces real output.** The architecture is sound. The gap is purely wiring: populating `GateInput`, replacing NAPI stubs, and connecting the feedback loop.
