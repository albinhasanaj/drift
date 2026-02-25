# Drift CLI & NAPI Deep Dive

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         drift-cli (TypeScript)                                │
│  Commands: scan, analyze, check, status, report, patterns, violations, etc.   │
└─────────────────────────────────┬───────────────────────────────────────────┘
                                  │
                                  │ loadNapi() → @drift/napi-contracts
                                  │
┌─────────────────────────────────▼───────────────────────────────────────────┐
│                    drift-napi (Rust NAPI-RS bindings)                         │
│  crates/drift/drift-napi/src/bindings/*.rs                                   │
└─────────────────────────────────┬───────────────────────────────────────────┘
                                  │
          ┌───────────────────────┼───────────────────────┐
          │                       │                       │
          ▼                       ▼                       ▼
┌─────────────────┐┌─────────────────────┐┌─────────────────────┐
│ drift-analysis  ││ drift-storage       ││ cortex-drift-bridge │
│ (engine)        ││ (drift.db)          ││ (bridge.db)         │
└─────────────────┘└─────────────────────┘└─────────────────────┘
```

## Data Flow: Scan → Analyze → Check

### 1. scan (driftScan)

**CLI:** `drift scan [paths...]`  
**NAPI:** `driftScan(root, options)` → `ScanTask` (AsyncTask)  
**Storage:** `file_metadata` table, `scan_history` table

**Flow:**
1. Scanner reads files from disk (respects globs from drift.toml or CLI flags)
2. Compares with cached `file_metadata` from drift.db (content hash, mtime)
3. Emits `ScanDiff` (added, modified, removed, unchanged)
4. `persist_scan_diff()` writes to drift.db via BatchWriter
5. `insert_scan_start` + `update_scan_complete` in scan_history
6. Returns `ScanSummary` (filesTotal, filesAdded, etc.)

**Key:** Scan does NOT run pattern detection. It only tracks file metadata.

---

### 2. analyze (driftAnalyze)

**CLI:** `drift analyze [path]`  
**NAPI:** `driftAnalyze(max_phase?)` → `Vec<JsAnalysisResult>`  
**Phases:** 1–5 (max_phase defaults to 5)

**Phase 1 — Parse + Detect:**
- Read `file_metadata` from drift.db (files tracked by scan)
- For each file: parse (tree-sitter), run AnalysisPipeline (AST visitors), framework matcher
- Persist: `detections`, `functions` via BatchWriter

**Phase 2 — Cross-file:**
- Boundary detection → `boundaries` table
- Call graph → `call_edges` table

**Phase 3 — Pattern intelligence + structural:**
- PatternIntelligencePipeline (Bayesian confidence) → `pattern_confidence`, `outlier_detections`, `conventions`
- 5a: Coupling → `coupling_metrics`, `coupling_cycles`
- 5b: Wrappers → `wrappers`
- 5c: Crypto → `crypto_findings`
- 5d: DNA → `dna_genes`, `dna_mutations`
- 5e: Secrets → `secrets`
- 5f: Constants → `constants`
- 5g: Constraint verification → `constraint_verifications`
- 5h: Env vars → `env_variables`
- 5i: Data access → `data_access`
- 5j: OWASP → `owasp_findings`
- 5k: Decomposition → `decomposition_decisions`
- 5l: Contracts → `contracts`, `contract_mismatches`

**Phase 4 — Graph intelligence:**
- 6a: Taint → `taint_flows`
- 6b: Error handling → `error_gaps`
- 6c: Impact → `impact_scores`
- 6d: Test topology → `test_quality`
- 6e: Reachability → `reachability_cache`

**Phase 5 — Enforcement:**
- GateOrchestrator executes 6 gates (pattern-compliance, constraint-verification, security-boundaries, test-coverage, error-handling, regression)
- Persist: `violations`, `gate_results`
- Degradation alerts → `degradation_alerts`
- BW-EVT-08: Auto-grounding on bridge memories (if bridge initialized)

**Key:** Gates run ONLY during analyze. Check/status/report only READ from DB.

---

### 3. check (driftCheck)

**CLI:** `drift check [path]`  
**NAPI:** `driftCheck(root)` → `JsCheckResult`

**Flow:**
1. `query_all_violations()` — read from `violations` table
2. `query_gate_results()` — read from `gate_results` table (ORDER BY run_at DESC)
3. Returns combined result (no gate execution)

**Gate results query:** Returns ALL rows, no deduplication. Each analyze run INSERTs new rows. Historical runs accumulate → duplicate gate entries when displaying.

---

### 4. status (driftAudit + driftViolations)

**CLI:** `drift status`  
**NAPI:** `driftAudit()` + `driftViolations()` merged

**driftAudit:** Reads from `degradation_alerts`, `pattern_confidence`, `feedback`, `gate_results`, `violations` to compute health_score, breakdown, trend.

**Health score formula (PH2-13):**
```
health_score = (avg_confidence*20 + approval_ratio*20 + compliance_rate*20 + cross_validation_rate*20 + 20)*clamp - alerts*2
```

---

### 5. report (driftReport)

**CLI:** `drift report` **Option:** `-r, --report-format` (NOT `--format`)  
**NAPI:** `driftReport(format)` → string

**Formats:** sarif, json, html, junit, sonarqube, console, github, gitlab

**Note:** Use `-r, --report-format` not `--format`. Other commands use `-f, --format`.

---

## CLI Command → NAPI Mapping

| CLI Command | NAPI Function(s) | Storage / Source |
|-------------|------------------|------------------|
| scan | driftScan | file_metadata, scan_history |
| analyze | driftAnalyze | All tables (full pipeline) |
| check | driftCheck | violations, gate_results |
| status | driftAudit, driftViolations | violations, gate_results, degradation_alerts, pattern_confidence, feedback |
| report | driftReport | violations, gate_results |
| patterns | driftPatterns | detections |
| violations | driftViolations | violations |
| security | driftOwaspFindings | owasp_findings |
| contracts | driftContractAnalysis | contracts, contract_mismatches |
| coupling | driftCouplingAnalysis | coupling_metrics, coupling_cycles |
| dna | driftDnaAnalysis | dna_genes, dna_mutations |
| taint | driftTaintAnalysis | taint_flows |
| errors | driftErrorHandling | error_gaps |
| test-quality | driftTestTopology | test_quality |
| impact | driftImpactAnalysis | impact_scores |
| simulate | driftSimulate | (no storage; uses Monte Carlo) |
| context | driftContext | (no storage; uses data_json) |
| audit | driftAudit | Same as status |
| export | driftReport | violations, gate_results |
| gc | driftGC | Retention cleanup |
| setup | driftInitialize, driftScan, driftAnalyze | Creates .drift, drift.toml, .cortex |
| doctor | (checks) | drift.toml, .drift, drift.db, NAPI |

---

## Gate System

**6 gates:**
- pattern-compliance
- constraint-verification
- security-boundaries
- test-coverage
- error-handling
- regression

**Gate input:** Built from `files` + `patterns` (from detect matches). Each gate may need:
- PatternCompliance: patterns
- ConstraintVerification: constraints (from DB) + invariant detector
- SecurityBoundaries: boundaries (from DB)
- TestCoverage: test_quality (from DB)
- ErrorHandling: error_gaps (from DB)
- Regression: previous health score

**Skip conditions:** "No data available" when the corresponding table is empty or not populated by analyze.

---

## Gate Results Duplication

**Query:** `SELECT ... FROM gate_results ORDER BY run_at DESC`

- No `LIMIT` or `GROUP BY gate_id`
- Each analyze run INSERTs 6 new rows (one per gate)
- Query returns ALL historical rows
- **Fix:** Add `LIMIT 6` or `DISTINCT ON (gate_id)` or dedupe by gate_id (latest run_at only)

---

## Context Command

**Valid intents:** `fix_bug`, `add_feature`, `understand_code`, `security_audit`, `generate_spec`  
**Valid depths:** `overview`, `standard`, `deep`

**NAPI:** `driftContext(intent, depth, data_json)` — expects exact intent string, not free-form.

---

## Simulate Command

**Valid task categories:** add_feature, fix_bug, refactor, migrate_framework, add_test, security_fix, performance_optimization, dependency_update, api_change, database_migration, config_change, documentation, infrastructure

**NAPI:** `driftSimulate(task_category, task_description, context_json)` — StrategyRecommender returns approaches with Monte Carlo confidence.

---

## Storage Tables (drift.db)

| Table | Populated by |
|-------|--------------|
| file_metadata | scan |
| detections | analyze Phase 1 |
| functions | analyze Phase 1 |
| boundaries | analyze Phase 2 |
| call_edges | analyze Phase 2 |
| pattern_confidence | analyze Phase 3 |
| outlier_detections | analyze Phase 3 |
| conventions | analyze Phase 3 |
| coupling_metrics | analyze Phase 3 |
| coupling_cycles | analyze Phase 3 |
| wrappers | analyze Phase 3 |
| crypto_findings | analyze Phase 3 |
| dna_genes | analyze Phase 3 |
| dna_mutations | analyze Phase 3 |
| secrets | analyze Phase 3 |
| constants | analyze Phase 3 |
| constraint_verifications | analyze Phase 3 |
| env_variables | analyze Phase 3 |
| data_access | analyze Phase 3 |
| owasp_findings | analyze Phase 3 |
| decomposition_decisions | analyze Phase 3 |
| contracts | analyze Phase 3 |
| contract_mismatches | analyze Phase 3 |
| taint_flows | analyze Phase 4 |
| error_gaps | analyze Phase 4 |
| impact_scores | analyze Phase 4 |
| test_quality | analyze Phase 4 |
| reachability_cache | analyze Phase 4 |
| violations | analyze Phase 5 |
| gate_results | analyze Phase 5 |
| degradation_alerts | analyze Phase 5 |
| gate_results (run_at) | No truncation — accumulates |

---

## Upstream/Downstream Dependencies

```
scan ───► file_metadata ───► analyze (reads files)
                                 │
                                 ├──► Phase 1: detections, functions
                                 ├──► Phase 2: boundaries, call_edges
                                 ├──► Phase 3: 12+ structural tables
                                 ├──► Phase 4: taint, errors, impact, test_quality
                                 └──► Phase 5: violations, gate_results
                                                      │
check ───────────────────────────────────────────────┘
status ──────────────────────────────────────────────┘
report ───────────────────────────────────────────────┘
violations ────────────────────────────────────────────┘
```

## Configuration

- **drift.toml:** `[scan]` include/exclude, `[gates]` thresholds, `[policy]` mode
- **drift.toml:** Loaded by `DriftRuntime` at init
- **Project root:** `.drift/drift.db`, `.drift/bridge.db`, `.cortex/cortex.db` (cortex uses separate dir)

---

## Violations vs Detections

- **Detections:** Pattern matches from analyze (AST + framework). Stored in `detections` table.
- **Violations:** Produced by gates when they fail. A gate evaluates patterns/boundaries/etc. and emits `Violation` structs. Stored in `violations` table.

**Empty violations:** Possible when (a) all gates passed, or (b) gates that produce violations were skipped (e.g. SecurityBoundaries skipped when no boundaries data).

---

## NAPI Bindings Summary

| Module | File | Exports |
|--------|------|---------|
| lifecycle | lifecycle.rs | driftInitialize, driftShutdown, driftIsInitialized, driftGC |
| scanner | scanner.rs | driftScan, driftScanWithProgress, driftCancelScan, driftScanHistory |
| analysis | analysis.rs | driftAnalyze, driftCallGraph, driftValidatePack, driftBoundaries |
| patterns | patterns.rs | driftPatterns, driftConfidence, driftOutliers, driftConventions |
| graph | graph.rs | driftReachability, driftTaintAnalysis, driftErrorHandling, driftImpactAnalysis, driftTestTopology |
| structural | structural.rs | driftCouplingAnalysis, driftConstraintVerification, driftContractAnalysis, driftConstants, driftWrappers, driftDnaAnalysis, driftOwaspFindings, driftCryptoFindings, driftDecompositionAnalysis |
| enforcement | enforcement.rs | driftCheck, driftAudit, driftViolations, driftReport, driftGates |
| feedback | feedback.rs | driftFix, driftDismiss, driftSuppress, driftExplain |
| advanced | advanced.rs | driftSimulate, driftDecisions, driftContext, driftGenerateSpec |
| bridge | bridge.rs | 21 bridge-related functions |
| cloud | cloud.rs | driftCloudSync, driftCloudStatus |
