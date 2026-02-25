# Agent Prompt: Enforcement Engine & Rule System Hardening

## Your Mission

You are performing a deep audit and hardening of **`crates/drift/drift-analysis/src/enforcement/`** — Drift V2's enforcement engine. This is the **largest subsystem** (44 items across 6 sub-modules) and it is where ALL analysis becomes actionable output. Every detector finding, taint flow, dead code flag, breaking change, and pattern violation must pass through enforcement to become a rule violation, a gate failure, or a report. If enforcement is misconfigured, references nonexistent data, or silently passes everything, the entire analysis pipeline produces nothing the user can act on.

**Speed does not matter. Thoroughness does. Do not fabricate findings. Every claim must have a file path and line number.**

---

## Context: What Has Already Been Audited

Three prior hardening audits establish the upstream data quality. You MUST read all three before starting:

1. **`docs/v2-research/DETECTOR-PARITY-HARDENING-TASKS.md`** — Parser extraction audit. Found that `import.specifiers`, `func.is_exported`, `func.decorators`, `class.implements`, and many other `ParseResult` fields are always empty/default. Detectors have language bias (JS/TS-centric).

2. **`docs/v2-research/CALL-GRAPH-AND-GRAPH-INTELLIGENCE-HARDENING-TASKS.md`** — Call graph audit. Found that 4 of 6 resolution strategies are dead. Entry points miss route handlers. Dead code massively over-reports. Taint over-approximates. Blast radius factors are hardcoded to 0.0.

3. **`docs/v2-research/CONTRACT-EXTRACTION-HARDENING-TASKS.md`** — API contract audit (may or may not exist yet — if it does, read it. If not, note that the contracts subsystem has not been audited and its outputs may also be hollow).

Your subsystem (`enforcement/`) consumes the OUTPUTS of all three upstream systems. You must trace exactly what data each gate, rule, and reporter expects, and whether that data currently exists.

---

## Your Subsystem: Complete File Inventory (44 items — account for 100%)

You must read and audit EVERY file listed below. No exceptions. Check off each as you read it.

### Root
- [ ] `enforcement/mod.rs` — Module root, public exports, top-level orchestration

### Gates (10 files) — CI/CD quality gates that pass/fail
- [ ] `enforcement/gates/mod.rs` — Gate module exports
- [ ] `enforcement/gates/types.rs` — Gate result types, pass/fail/warn enums
- [ ] `enforcement/gates/orchestrator.rs` — Gate execution orchestrator (runs all gates in order)
- [ ] `enforcement/gates/security_boundaries.rs` — Security boundary enforcement (taint, CWE)
- [ ] `enforcement/gates/test_coverage.rs` — Test coverage thresholds
- [ ] `enforcement/gates/regression.rs` — Regression detection (new violations in changed files)
- [ ] `enforcement/gates/pattern_compliance.rs` — Pattern/convention compliance
- [ ] `enforcement/gates/constraint_verification.rs` — Architectural constraint checks
- [ ] `enforcement/gates/error_handling.rs` — Error handling quality gates
- [ ] `enforcement/gates/progressive.rs` — Progressive enforcement (ratchet — only fail on NEW violations)

### Rules (5 files) — Rule definition, evaluation, suppression
- [ ] `enforcement/rules/mod.rs` — Rule module exports
- [ ] `enforcement/rules/types.rs` — Rule types, severity levels, violation structs
- [ ] `enforcement/rules/evaluator.rs` — Rule evaluation engine
- [ ] `enforcement/rules/suppression.rs` — Inline suppression (// drift-ignore, # noqa, etc.)
- [ ] `enforcement/rules/quick_fixes.rs` — Auto-fix suggestions for violations

### Policy (3 files) — Policy engine for org-level configuration
- [ ] `enforcement/policy/mod.rs` — Policy module exports
- [ ] `enforcement/policy/types.rs` — Policy types, org config, team overrides
- [ ] `enforcement/policy/engine.rs` — Policy evaluation engine

### Reporters (9 files) — Output format generators
- [ ] `enforcement/reporters/mod.rs` — Reporter dispatch
- [ ] `enforcement/reporters/console.rs` — Terminal/CLI output
- [ ] `enforcement/reporters/json.rs` — JSON output
- [ ] `enforcement/reporters/html.rs` — HTML report generation
- [ ] `enforcement/reporters/sarif.rs` — SARIF (Static Analysis Results Interchange Format) for GitHub
- [ ] `enforcement/reporters/junit.rs` — JUnit XML for CI systems
- [ ] `enforcement/reporters/sonarqube.rs` — SonarQube import format
- [ ] `enforcement/reporters/github.rs` — GitHub PR annotations
- [ ] `enforcement/reporters/gitlab.rs` — GitLab code quality format

### Audit (7 files) — Health scoring, deduplication, trends
- [ ] `enforcement/audit/mod.rs` — Audit module exports
- [ ] `enforcement/audit/types.rs` — Audit types
- [ ] `enforcement/audit/health_scorer.rs` — Codebase health scoring algorithm
- [ ] `enforcement/audit/deduplication.rs` — Finding deduplication logic
- [ ] `enforcement/audit/degradation.rs` — Quality degradation detection
- [ ] `enforcement/audit/trends.rs` — Trend analysis over time
- [ ] `enforcement/audit/auto_approve.rs` — Auto-approval for low-risk changes

### Feedback (4 files) — Confidence feedback loop
- [ ] `enforcement/feedback/mod.rs` — Feedback module exports
- [ ] `enforcement/feedback/types.rs` — Feedback types
- [ ] `enforcement/feedback/tracker.rs` — Tracks user feedback on findings (true/false positive)
- [ ] `enforcement/feedback/confidence_feedback.rs` — Updates confidence scores based on feedback
- [ ] `enforcement/feedback/stats_provider.rs` — Provides statistics for feedback calibration

---

## Audit Procedure (follow this exactly)

### Step 1: Read the Reference Documents
Read all existing hardening documents in full. Internalize the format, evidence standards, and phased approach.

### Step 2: Read the Types First
Start with EVERY `types.rs` file in the subsystem (there are 5 of them):
- `gates/types.rs`
- `rules/types.rs`
- `policy/types.rs`
- `audit/types.rs`
- `feedback/types.rs`

Then read `enforcement/mod.rs`. Map every struct, enum, and trait. These define the data model. You need to know what a "complete" enforcement result looks like.

### Step 3: Trace ALL Upstream Dependencies (what feeds INTO enforcement)
Enforcement is the TERMINAL consumer of the analysis pipeline. It consumes outputs from EVERY other subsystem. For each gate, rule evaluator, and reporter, identify EXACTLY which upstream types it imports and uses:

| Upstream System | Expected Data | Files to Check |
|----------------|---------------|----------------|
| `parsers/types.rs` | `ParseResult`, `FunctionInfo`, `ClassInfo`, `ImportInfo` | All gates |
| `call_graph/types.rs` | `CallGraph`, `FunctionNode`, `CallEdge`, `CallGraphStats` | security_boundaries, test_coverage |
| `graph/taint/types.rs` | `TaintFlow`, `TaintSource`, `TaintSink`, `TaintAnalysisResult` | security_boundaries |
| `graph/impact/` | `BlastRadius`, dead code results | regression, test_coverage |
| `graph/test_topology/` | `CoverageMapping`, test smell results | test_coverage |
| `structural/contracts/` | `ApiContract`, `BreakingChange` | pattern_compliance, regression |
| `structural/coupling/types.rs` | `CouplingMetrics`, `CycleInfo` | constraint_verification |
| `patterns/` | Aggregated findings, confidence scores | rules/evaluator, audit/health_scorer |
| `engine/types.rs` | `AnalysisResult`, detector matches | rules/evaluator, reporters |

For EACH import, check: Does the upstream system actually produce this data correctly? Cross-reference with the prior audit findings.

### Step 4: Trace ALL Downstream Consumers (what enforcement FEEDS)
Enforcement is near the end of the pipeline, but its outputs feed:
- **NAPI bindings** — `crates/drift/drift-napi/src/bindings/` — does the NAPI layer expose gate results, violations, reports?
- **MCP tools** — `packages/drift-mcp/src/tools/` — does MCP expose enforcement results?
- **CLI** — `packages/drift-cli/src/` — does CLI format enforcement output?
- **CI** — `packages/drift-ci/src/` — does CI consume gate pass/fail?
- **Bridge** — `crates/cortex-drift-bridge/` — does the bridge forward enforcement data to cortex?

### Step 5: Deep-Audit Each Sub-Module

#### Gates (the critical path)
For each gate, answer:
1. What upstream data does it consume?
2. Is that data currently populated (cross-ref prior audits)?
3. What thresholds/configs does it use? Are they hardcoded or configurable?
4. Does the gate actually fail when it should? Or does it always pass because the input data is empty/default?
5. Does the progressive gate (ratchet) correctly compare against a baseline?

#### Rules
1. How are rules defined? TOML? Code? Both?
2. What violations can the evaluator detect?
3. Does suppression (`// drift-ignore`) actually work? Does it parse inline comments?
4. Are quick fixes actually applicable, or are they placeholder suggestions?

#### Policy
1. Is the policy engine wired into the gate orchestrator?
2. Can teams actually configure policies, or is it hardcoded?
3. Are there default policies, or is it empty without explicit config?

#### Reporters
For each of the 8 reporters:
1. Does it produce valid output for its format? (Valid SARIF, valid JUnit XML, etc.)
2. Does it include all violation fields (file, line, rule, severity, message, fix suggestion)?
3. Does it handle edge cases (empty results, very large results, unicode)?
4. **Research if needed**: Look up the SARIF, JUnit, SonarQube, and GitLab code quality schemas online to verify the reporter produces valid output.

#### Audit
1. Is the health scorer calibrated? What factors does it weight?
2. Does deduplication correctly identify duplicate findings across different detectors?
3. Does trend analysis have access to historical data, or does it only work on current snapshot?
4. What criteria does auto_approve use? Is it too aggressive or too conservative?

#### Feedback
1. Is the feedback loop connected? Can user feedback actually update confidence scores?
2. Does stats_provider have access to historical feedback data?
3. Is confidence_feedback integrated into the confidence scoring in `patterns/confidence/`?

### Step 6: Research If Needed
Use online search to verify output format correctness:
- **SARIF 2.1.0 schema** — verify the sarif reporter produces valid SARIF
- **JUnit XML schema** — verify junit reporter produces valid JUnit
- **SonarQube Generic Issue Import format** — verify sonarqube reporter format
- **GitLab Code Quality report format** — verify gitlab reporter format
- **GitHub Check Annotations API** — verify github reporter produces valid annotations

### Step 7: Create the Hardening Document
Produce `docs/v2-research/ENFORCEMENT-ENGINE-HARDENING-TASKS.md` following EXACTLY the format of the reference documents:

1. **Progress Summary Table** — phases, impl tasks, test tasks, status
2. **Audit Findings Reference** — root cause, line-verified evidence table, cascade impact
3. **Phased Fix Plan** with unique task IDs:
   - `EF-{subsystem}-{number}` for impl tasks
   - `EFT-{subsystem}-{number}` for test tasks
   - Suggested phases: A=Gates, B=Rules+Policy, C=Reporters, D=Audit+Feedback, E=Integration
4. **Quality gates per phase**
5. **Dependency graph**

---

## Critical Questions Your Audit Must Answer

1. **If I run the enforcement pipeline on a real codebase today, how many gates actually fire vs. silently pass?**
2. **Which reporters produce valid output and which produce empty/malformed output?**
3. **Is the progressive gate (ratchet) functional? Can it actually detect regressions?**
4. **Does the feedback loop actually close? Can user feedback improve future results?**
5. **What percentage of the enforcement system is functional vs. scaffolding?**

---

## Quality Criteria for Your Output

Your hardening document MUST:
- [ ] Account for all 44 items in the file inventory (no file unread)
- [ ] Map every upstream data dependency for every gate
- [ ] Cross-reference each dependency against the prior audit confirmed-broken lists
- [ ] Identify which gates are functional vs. always-pass due to empty input
- [ ] Verify reporter output format correctness (research schemas online)
- [ ] Identify all downstream consumers (NAPI, MCP, CLI, CI, Bridge)
- [ ] Include line-verified evidence for every finding
- [ ] Produce a phased plan with impl tasks, test tasks, quality gates
- [ ] Not fabricate any findings — only report what the code shows
