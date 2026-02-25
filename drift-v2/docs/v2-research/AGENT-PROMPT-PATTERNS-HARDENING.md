# Agent Prompt: Pattern Intelligence Layer Hardening (Aggregation, Confidence, Outliers, Learning)

## Your Mission

You are performing a deep audit and hardening of **`crates/drift/drift-analysis/src/patterns/`** — Drift V2's pattern intelligence layer. This is the subsystem that transforms raw detector findings, taint flows, and structural violations into **ranked, scored, filtered, and learned insights**. It has 4 sub-modules (37 items total): aggregation (9), confidence (6), outliers (10), and learning (7). This is what makes Drift feel intelligent vs. noisy — if confidence is miscalibrated, high-signal findings get buried and noise bubbles up. If aggregation drops cross-file patterns, the most important multi-file issues are invisible. If learning never converges, the system can't adapt to a codebase.

**Speed does not matter. Thoroughness does. Do not fabricate findings. Every claim must have a file path and line number.**

---

## Context: What Has Already Been Audited

Four prior hardening audits establish the upstream data quality. You MUST read all that exist before starting:

1. **`docs/v2-research/DETECTOR-PARITY-HARDENING-TASKS.md`** — Parser extraction audit. Found `import.specifiers`, `func.is_exported`, `func.decorators`, `class.implements`, and many other `ParseResult` fields are always empty/default. Detectors have JS/TS language bias.

2. **`docs/v2-research/CALL-GRAPH-AND-GRAPH-INTELLIGENCE-HARDENING-TASKS.md`** — Call graph audit. Found that 4 of 6 resolution strategies are dead. Taint over-approximates (any tainted var flags all sinks). Blast radius risk factors all hardcoded to 0.0. Resolution confidence systematically deflated.

3. **`docs/v2-research/CONTRACT-EXTRACTION-HARDENING-TASKS.md`** — API contract audit (may or may not exist yet — read if present).

4. **`docs/v2-research/ENFORCEMENT-ENGINE-HARDENING-TASKS.md`** — Enforcement engine audit (may or may not exist yet — read if present).

Your subsystem (`patterns/`) sits BETWEEN the analysis layer and the enforcement layer. It consumes raw findings from detectors, taint, call graph, and contracts — then produces scored, aggregated, filtered output that enforcement consumes. If the inputs are degraded (and they are), you must understand how that degradation propagates through pattern intelligence.

---

## Your Subsystem: Complete File Inventory (37 items — account for 100%)

You must read and audit EVERY file listed below. No exceptions. Check off each as you read it.

### Root
- [ ] `patterns/mod.rs` — Module root, public exports

### Aggregation (9 files) — Combines findings across files and detectors
- [ ] `patterns/aggregation/mod.rs` — Aggregation module exports
- [ ] `patterns/aggregation/types.rs` — Aggregation types (AggregatedFinding, FindingGroup, etc.)
- [ ] `patterns/aggregation/pipeline.rs` — Aggregation pipeline (the main orchestrator)
- [ ] `patterns/aggregation/grouper.rs` — Groups findings by category, file, severity, etc.
- [ ] `patterns/aggregation/hierarchy.rs` — Hierarchical grouping (file → module → package → repo)
- [ ] `patterns/aggregation/similarity.rs` — Similarity detection between findings
- [ ] `patterns/aggregation/gold_layer.rs` — Gold layer: canonical, deduplicated, scored findings
- [ ] `patterns/aggregation/incremental.rs` — Incremental aggregation for changed files
- [ ] `patterns/aggregation/reconciliation.rs` — Reconciliation between old and new findings

### Confidence (6 files) — Scores how certain each finding is
- [ ] `patterns/confidence/mod.rs` — Confidence module exports
- [ ] `patterns/confidence/types.rs` — Confidence types (ConfidenceScore, ConfidenceFactor, etc.)
- [ ] `patterns/confidence/scorer.rs` — Main confidence scoring algorithm
- [ ] `patterns/confidence/factors.rs` — Individual confidence factors (resolution confidence, detector reliability, language support, etc.)
- [ ] `patterns/confidence/beta.rs` — Beta distribution for Bayesian confidence updates
- [ ] `patterns/confidence/momentum.rs` — Confidence momentum (smoothing over time)

### Outliers (10 files) — Statistical outlier detection
- [ ] `patterns/outliers/mod.rs` — Outlier module exports
- [ ] `patterns/outliers/types.rs` — Outlier types (Outlier, OutlierResult, etc.)
- [ ] `patterns/outliers/selector.rs` — Algorithm selector (chooses best outlier method for data shape)
- [ ] `patterns/outliers/zscore.rs` — Z-score outlier detection
- [ ] `patterns/outliers/iqr.rs` — Interquartile range outlier detection
- [ ] `patterns/outliers/mad.rs` — Median absolute deviation outlier detection
- [ ] `patterns/outliers/grubbs.rs` — Grubbs' test for outliers
- [ ] `patterns/outliers/esd.rs` — Generalized ESD (extreme Studentized deviate) test
- [ ] `patterns/outliers/rule_based.rs` — Rule-based outlier detection (non-statistical)
- [ ] `patterns/outliers/conversion.rs` — Converts analysis results to outlier-compatible numeric series

### Learning (7 files) — Learns patterns from codebase history
- [ ] `patterns/learning/mod.rs` — Learning module exports
- [ ] `patterns/learning/types.rs` — Learning types (LearnedPattern, PatternState, etc.)
- [ ] `patterns/learning/discovery.rs` — Pattern discovery (finds new patterns)
- [ ] `patterns/learning/promotion.rs` — Pattern promotion (promotes discovered patterns to enforced rules)
- [ ] `patterns/learning/expiry.rs` — Pattern expiry (retires patterns that no longer apply)
- [ ] `patterns/learning/relearning.rs` — Pattern relearning (re-evaluates expired patterns)
- [ ] `patterns/learning/dirichlet.rs` — Dirichlet distribution for multi-category pattern priors

---

## Audit Procedure (follow this exactly)

### Step 1: Read the Reference Documents
Read all existing hardening documents in full. Internalize the format, evidence standards, and phased approach.

### Step 2: Read ALL Types Files First
There are 4 `types.rs` files (one per sub-module). Read them all before anything else:
- `aggregation/types.rs`
- `confidence/types.rs`
- `outliers/types.rs`
- `learning/types.rs`

Then read `patterns/mod.rs`. Map every struct, enum, and trait. These define the data model.

### Step 3: Trace ALL Upstream Dependencies (what feeds INTO patterns)

Patterns consumes raw findings from the entire analysis layer. For each sub-module, identify EXACTLY which upstream types it imports and uses:

| Upstream System | Expected Data | Which patterns/ file consumes it |
|----------------|---------------|----------------------------------|
| `engine/types.rs` | `AnalysisResult`, detector matches, match confidence | aggregation, confidence |
| `call_graph/types.rs` | `CallGraph`, resolution confidence (0.40-0.95) | confidence/factors |
| `graph/taint/types.rs` | `TaintFlow`, `TaintAnalysisResult` | aggregation, confidence |
| `graph/impact/` | `BlastRadius`, dead code results | aggregation, confidence |
| `graph/test_topology/` | `CoverageMapping`, smell results | aggregation |
| `structural/contracts/` | `BreakingChange`, contract confidence | aggregation, confidence |
| `structural/coupling/` | `CouplingMetrics`, `CycleInfo` | aggregation, outliers |
| `parsers/types.rs` | `ParseResult` metadata (language, error_count, file) | grouper, hierarchy |

For EACH import, cross-reference with the prior audits. The critical question: **Is confidence scoring calibrated against actual upstream data quality, or against theoretical perfect data?** If confidence factors assume resolution confidence is 0.75-0.95 but it's actually 0.40 or zero for most calls, all confidence scores are inflated.

### Step 4: Trace ALL Downstream Consumers (what patterns FEEDS)

The patterns layer outputs scored, aggregated, filtered findings. Find every consumer:
- `enforcement/rules/evaluator.rs` — Does it consume aggregated findings?
- `enforcement/gates/` — Do gates use confidence scores for thresholds?
- `enforcement/audit/health_scorer.rs` — Does health scoring use aggregated data?
- `enforcement/reporters/` — Do reporters include confidence scores?
- NAPI bindings — Are aggregated findings exposed via NAPI?
- MCP tools — Does MCP expose pattern data?
- Bridge — Does cortex-drift-bridge consume pattern intelligence output?

### Step 5: Deep-Audit Each Sub-Module

#### Aggregation
For each file, answer:
1. What is the aggregation pipeline's phases? Are any phases stubs?
2. Does the grouper correctly group across files, or only within files?
3. Does similarity detection use content hashing, string similarity, or both?
4. Does the gold layer actually deduplicate, or does it pass everything through?
5. Does incremental aggregation work, or does it rebuild from scratch (like the call graph)?
6. Does reconciliation correctly track finding identity across runs (same finding in two analyses)?

#### Confidence
This is the MOST CRITICAL sub-module for output quality. Answer:
1. What factors feed into the confidence score? List every factor.
2. What are the weights? Are they hardcoded, configurable, or learned?
3. Does the scorer consume resolution confidence from the call graph? (If so, it's consuming 0.40/0.95 only — most calls unresolved)
4. Does the beta distribution model have correct priors? Are the alpha/beta parameters calibrated or defaults?
5. Does momentum smoothing work? Does it have access to historical scores, or only current?
6. **Is there a feedback loop?** Does `enforcement/feedback/confidence_feedback.rs` actually feed back into this scorer?

#### Outliers
For each statistical method, answer:
1. Does the implementation match the mathematical specification? (Research the formulas if needed)
2. What data gets converted to numeric series via `conversion.rs`? (Function sizes? Finding counts? Complexity metrics?)
3. Does the selector choose the right algorithm for the data distribution?
4. Are the critical values correct for Grubbs' and ESD tests? (These depend on sample size and significance level — verify the tables or formulas)
5. Does rule_based outlier detection duplicate or complement the statistical methods?

#### Learning
For each file, answer:
1. Does pattern discovery find real patterns, or is it finding noise?
2. What are the promotion criteria? How many observations before a pattern is promoted?
3. Do expired patterns actually get re-evaluated, or is expiry permanent?
4. Is the Dirichlet distribution correctly implemented? Are the concentration parameters calibrated?
5. Does learning have access to persistent storage, or is it in-memory only (reset every run)?

### Step 6: Research If Needed
Use online search to verify mathematical correctness:
- **Grubbs' test** — critical values table, assumptions (normality required)
- **Generalized ESD** — verify the iterative procedure and critical value formula
- **MAD (Median Absolute Deviation)** — verify the consistency constant (1.4826 for normal)
- **Beta distribution** — verify the Bayesian update rule for confidence
- **Dirichlet distribution** — verify the conjugate prior update for multinomial data
- **IQR method** — verify the 1.5×IQR and 3×IQR thresholds
- **Z-score** — verify assumptions and threshold choices (typically 2σ or 3σ)

### Step 7: Create the Hardening Document
Produce `docs/v2-research/PATTERN-INTELLIGENCE-HARDENING-TASKS.md` following EXACTLY the format of the reference documents:

1. **Progress Summary Table** — phases, impl tasks, test tasks, status
2. **Audit Findings Reference** — root cause, line-verified evidence table, cascade impact
3. **Phased Fix Plan** with unique task IDs:
   - `PI-{subsystem}-{number}` for impl tasks (PI = Pattern Intelligence)
   - `PIT-{subsystem}-{number}` for test tasks
   - Suggested phases: A=Confidence Calibration, B=Aggregation Pipeline, C=Outlier Accuracy, D=Learning Loop, E=Integration
4. **Quality gates per phase**
5. **Dependency graph**

---

## Critical Questions Your Audit Must Answer

1. **Is confidence scoring calibrated against actual data quality, or against theoretical perfect data?** If a finding has resolution confidence 0.40 (Fuzzy), does the confidence scorer know that, or does it assume 0.75+ (ImportBased)?

2. **Does the aggregation pipeline produce gold-layer findings, or pass-through raw data?** Is there actual deduplication, merging, and ranking?

3. **Are the statistical outlier methods mathematically correct?** Wrong critical values in Grubbs' or ESD would silently produce wrong results with no visible errors.

4. **Does learning persist across runs?** If it's in-memory only, it rediscovers the same patterns every time and never converges.

5. **Is there a closed feedback loop between enforcement feedback and confidence scoring?** If user marks a finding as false positive, does that actually lower similar findings' confidence in future runs?

6. **What percentage of this subsystem is functional vs. scaffolding?** Can any of the 4 sub-modules run end-to-end and produce correct output today?

---

## Upstream Data Quality Summary (from prior audits)

| Data Source | Quality | Impact on Patterns |
|------------|---------|-------------------|
| Detector matches | Partial — JS/TS-centric, 10 languages claimed but gaps | Aggregation groups findings that may be incomplete for non-JS languages |
| Resolution confidence | Broken — mostly 0.40 (Fuzzy) or unresolved | Confidence scorer may be inflating scores if it assumes 0.75+ |
| Taint flows | Over-approximated — any tainted var flags all sinks | Aggregation counts inflated. Confidence should penalize but may not. |
| Dead code | Over-reported — cross-file functions falsely flagged | Outlier detection on dead code counts is based on inflated numbers |
| Blast radius | Underestimated — risk factors all 0.0 | Confidence factors based on blast radius are nonfunctional |
| Test coverage | Underestimated — only same-file coverage | Coverage-based confidence factors are deflated |
| Breaking changes | Unknown — contracts subsystem not yet audited | May be empty or hollow |
| Coupling metrics | Distorted — import.source contains statement text | Outlier detection on coupling metrics operates on wrong data |

---

## Quality Criteria for Your Output

Your hardening document MUST:
- [ ] Account for all 37 items in the file inventory (no file unread)
- [ ] Map every upstream data dependency for every sub-module
- [ ] Cross-reference each dependency against the prior audit confirmed-broken lists
- [ ] Verify mathematical correctness of statistical methods (research formulas)
- [ ] Determine if confidence scoring is calibrated against actual vs. theoretical data
- [ ] Determine if learning persists across runs
- [ ] Determine if the feedback loop is closed
- [ ] Identify all downstream consumers (enforcement, NAPI, MCP, CLI, CI, Bridge)
- [ ] Include line-verified evidence for every finding
- [ ] Produce a phased plan with impl tasks, test tasks, quality gates
- [ ] Not fabricate any findings — only report what the code shows
