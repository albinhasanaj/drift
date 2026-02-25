# Production Hardening Plan — Three Critical Gaps

> Comprehensive audit and fix plan for the three honest gaps that separate Drift V2 from production-readiness.

---

## Executive Summary

The NAPI layer reads real data from drift.db. The storage layer has 39 tables across 7 migrations, a WAL-mode writer, batch writer, and read pool. But three gaps prevent production use:

| Gap | Root Cause | Impact | Fix Effort |
|-----|-----------|--------|------------|
| **Pipeline not populated** | `drift_analyze()` returns `Vec::new()` — analysis results never written to storage | All 35+ tables except `file_metadata` are permanently empty | 3–4 days |
| **Feedback loop open** | Only `InMemoryFeedbackStore` exists — no `DbFeedbackStore` bridges `feedback` table → scorer | User actions (dismiss/fix/suppress) write to DB but have zero effect on confidence | 1 day |
| **No retention on drift.db** | GC only handles `workspace_events` — 38 other tables grow unbounded | Disk usage grows linearly with scan count; no TTL, no pruning | 1–2 days |

**Total: 5–7 working days to close all three gaps.**

---

## Gap 1: Pipeline Wired But Not Populated

### What Works Today

- **Scanner → Storage ✅**: `scanner.rs:69` calls `persist_scan_diff()` which sends `BatchCommand::UpsertFileMetadata` and `BatchCommand::DeleteFileMetadata` through the batch writer. File metadata flows scan → storage correctly.
- **NAPI reads ✅**: All 22+ NAPI bindings read from drift.db via `rt.db.with_reader()`. Enforcement, patterns, graph, structural — they all query real tables.
- **BatchWriter instantiated ✅**: `runtime.rs:118` creates `BatchWriter::new(batch_conn)` on the runtime singleton.
- **BatchCommand enum has 13 variants** covering file metadata, parse cache, functions, call edges, detections, boundaries, confidence, outliers, conventions, scan history, and data access.

### What's Broken

**`drift_analyze()` at `analysis.rs:86-93` returns an empty Vec:**
```rust
pub async fn drift_analyze() -> napi::Result<Vec<JsAnalysisResult>> {
    let _rt = runtime::get()?;
    // Phase 2 analysis pipeline would run here.
    // For now, return empty results
    Ok(Vec::new())
}
```

This means the entire analysis pipeline (parse → detect → call graph → boundaries → patterns → graph intelligence → structural intelligence) never runs from NAPI, and therefore **no analysis results ever reach storage**.

### Complete Inventory of Empty Tables

Every table below has a schema, a query module, and an NAPI binding that reads from it — but nothing writes to it:

| Migration | Table | What Should Write | BatchCommand Exists? |
|-----------|-------|-------------------|---------------------|
| v001 | `parse_cache` | Parser pipeline | ✅ `InsertParseCache` |
| v001 | `functions` | Parser pipeline | ✅ `InsertFunctions` |
| v001 | `scan_history` | Scanner | ✅ `InsertScanHistory` |
| v002 | `call_edges` | Call graph builder | ✅ `InsertCallEdges` |
| v002 | `data_access` | Data access detector | ✅ `InsertDataAccess` |
| v002 | `detections` | Analysis engine | ✅ `InsertDetections` |
| v002 | `boundaries` | Boundary detector | ✅ `InsertBoundaries` |
| v003 | `pattern_confidence` | Confidence scorer | ✅ `InsertPatternConfidence` |
| v003 | `outliers` | Outlier detector | ✅ `InsertOutliers` |
| v003 | `conventions` | Convention learner | ✅ `InsertConventions` |
| v004 | `reachability_cache` | Reachability engine | ❌ No BatchCommand |
| v004 | `taint_flows` | Taint analyzer | ❌ No BatchCommand |
| v004 | `error_gaps` | Error handling analyzer | ❌ No BatchCommand |
| v004 | `impact_scores` | Impact analyzer | ❌ No BatchCommand |
| v004 | `test_coverage` | Test topology | ❌ No BatchCommand |
| v004 | `test_quality` | Test topology | ❌ No BatchCommand |
| v005 | `coupling_metrics` | Coupling analyzer | ❌ No BatchCommand |
| v005 | `coupling_cycles` | Coupling analyzer | ❌ No BatchCommand |
| v005 | `constraints` | Constraint system | ❌ No BatchCommand |
| v005 | `constraint_verifications` | Constraint verifier | ❌ No BatchCommand |
| v005 | `contracts` | Contract tracker | ❌ No BatchCommand |
| v005 | `contract_mismatches` | Contract matcher | ❌ No BatchCommand |
| v005 | `constants` | Constants analyzer | ❌ No BatchCommand |
| v005 | `secrets` | Secret detector | ❌ No BatchCommand |
| v005 | `env_variables` | Env extractor | ❌ No BatchCommand |
| v005 | `wrappers` | Wrapper detector | ❌ No BatchCommand |
| v005 | `dna_genes` | DNA system | ❌ No BatchCommand |
| v005 | `dna_mutations` | DNA system | ❌ No BatchCommand |
| v005 | `crypto_findings` | Crypto detector | ❌ No BatchCommand |
| v005 | `owasp_findings` | OWASP enricher | ❌ No BatchCommand |
| v005 | `decomposition_decisions` | Decomposer | ❌ No BatchCommand |
| v006 | `violations` | Enforcement engine | ❌ No BatchCommand |
| v006 | `gate_results` | Gate evaluator | ❌ No BatchCommand |
| v006 | `audit_snapshots` | Audit system | ❌ No BatchCommand |
| v006 | `health_trends` | Health tracker | ❌ No BatchCommand |
| v006 | `feedback` | Feedback handler | Direct write (not batched) ✅ |
| v006 | `policy_results` | Policy engine | ❌ No BatchCommand |
| v006 | `degradation_alerts` | Degradation detector | ❌ No BatchCommand |
| v007 | `simulations` | Simulation engine | ❌ No BatchCommand |
| v007 | `decisions` | Decision miner | ❌ No BatchCommand |
| v007 | `context_cache` | Context engine | ❌ No BatchCommand |
| v007 | `migration_projects` | Migration tracker | ❌ No BatchCommand |
| v007 | `migration_modules` | Migration tracker | ❌ No BatchCommand |
| v007 | `migration_corrections` | Migration tracker | ❌ No BatchCommand |

**Summary: 10 of 44 tables have BatchCommands. Only 1 table (`file_metadata`) actually receives production writes.**

### Fix Plan — Gap 1

#### 1A. Implement `drift_analyze()` orchestration (P0, 2 days)

**File: `drift-napi/src/bindings/analysis.rs`**

Replace the empty stub with a real orchestration pipeline:

```
drift_analyze() should:
1. Get runtime, read all file_metadata from DB
2. For each changed file: parse → cache parse result
3. Run analysis engine (single-pass visitor + detectors) on parse results
4. Build call graph from function + call edge data
5. Run boundary detection
6. Run pattern aggregation → confidence scoring → outlier detection → convention learning
7. Persist ALL results via batch_writer
8. Return summary to TypeScript
```

This requires:
- A new `AnalysisPipeline` struct in `drift-analysis` that orchestrates steps 2–6
- The pipeline accepts `&DriftRuntime` (or `&DatabaseManager` + `&BatchWriter`) to read cached data and write results
- Each subsystem already has the analysis logic — the missing piece is the orchestration + persistence glue

#### 1B. Add missing BatchCommands for v004–v007 tables (P0, 1 day)

Add ~20 new `BatchCommand` variants to `batch/commands.rs`:
- `InsertReachabilityCache`, `InsertTaintFlows`, `InsertErrorGaps`
- `InsertImpactScores`, `InsertTestCoverage`, `InsertTestQuality`
- `InsertCouplingMetrics`, `InsertCouplingCycles`
- `InsertConstraints`, `InsertConstraintVerifications`
- `InsertContracts`, `InsertContractMismatches`
- `InsertConstants`, `InsertSecrets`, `InsertEnvVariables`
- `InsertWrappers`, `InsertDnaGenes`, `InsertDnaMutations`
- `InsertCryptoFindings`, `InsertOwaspFindings`
- `InsertViolations`, `InsertGateResults`
- `InsertDegradationAlerts`, `InsertAuditSnapshots`

Each variant needs a corresponding handler in `batch/writer.rs`.

#### 1C. Wire structural intelligence persistence (P1, 1 day)

`drift_contract_tracking()` at `structural.rs:172` is unique — it runs the extractor live from the filesystem rather than reading from storage. This is the **only** NAPI binding that runs analysis inline. All others just read from DB.

Decision: Either:
- **(A)** Make `drift_contract_tracking()` also persist its results (so subsequent calls read from cache), or
- **(B)** Move contract extraction into the `drift_analyze()` pipeline and make the NAPI binding a pure DB read

Recommendation: **(B)** — consistent with every other binding.

---

## Gap 2: Feedback Loop Is Open

### What Works Today

- **Feedback writes to DB ✅**: `feedback.rs:31-108` has three NAPI functions (`drift_dismiss_violation`, `drift_fix_violation`, `drift_suppress_violation`) that all call `insert_feedback()` writing to the `feedback` table.
- **ConfidenceScorer supports feedback ✅**: `scorer.rs:80-103` has `FeedbackStore` trait and `with_feedback_store()` method. The scorer correctly applies `(alpha_delta, beta_delta)` adjustments at `scorer.rs:150-157`.
- **InMemoryFeedbackStore works ✅**: Tests at `scorer.rs:442-514` prove the math is correct — 5 FP dismissals lower confidence, 5 Fix actions raise it, WontFix is neutral.

### What's Broken

1. **No `DbFeedbackStore` implementation exists.** The only implementation of `FeedbackStore` is `InMemoryFeedbackStore` (in-memory HashMap). There is no implementation that reads from the `feedback` table in drift.db.

2. **No `query_feedback_by_pattern()` query exists.** Storage has `query_feedback_by_detector()` but NOT by pattern_id. The `FeedbackStore` trait needs adjustments by `pattern_id`, not `detector_id`.

3. **Scorer is never constructed with a feedback store in production.** No code path constructs `ConfidenceScorer::new(...).with_feedback_store(...)` outside of test code.

4. **Feedback rows write `pattern_id: String::new()`**: In `feedback.rs:36`, the pattern_id is always empty string because the NAPI binding only receives `violation_id`, not the pattern that produced the violation.

### The Complete Break Chain

```
User dismisses violation → drift_dismiss_violation() 
  → insert_feedback(violation_id, pattern_id="", action="dismiss")
  → feedback table row created ✅
  
Next analysis run → ConfidenceScorer::new(config)  [NO feedback store attached]
  → score() at line 151: self.feedback_store is None
  → feedback adjustments: ZERO
  → confidence unchanged ❌
```

### Fix Plan — Gap 2

#### 2A. Add `query_feedback_by_pattern()` to storage (P0, 2 hours)

**File: `drift-storage/src/queries/enforcement.rs`**

```rust
pub fn query_feedback_by_pattern(
    conn: &Connection,
    pattern_id: &str,
) -> Result<Vec<FeedbackRow>, StorageError>
```

Also add `query_feedback_grouped_by_pattern()` that returns aggregated (alpha_delta, beta_delta) per pattern using the `ConfidenceFeedback` mapping:
- `action = "dismiss"` → `(0.0, 0.5)` (FP: increase beta)
- `action = "fix"` → `(1.0, 0.0)` (TP: increase alpha)
- `action = "suppress"` → `(0.0, 0.0)` (neutral)
- `action = "escalate"` → `(1.5, 0.0)` (strong TP signal)

#### 2B. Implement `DbFeedbackStore` (P0, 2 hours)

**New file: `drift-napi/src/feedback_store.rs`** (or in `drift-storage/src/`)

```rust
pub struct DbFeedbackStore {
    db: Arc<DatabaseManager>,
}

impl FeedbackStore for DbFeedbackStore {
    fn get_adjustments(&self, pattern_id: &str) -> Vec<(f64, f64)> {
        self.db.with_reader(|conn| {
            query_feedback_grouped_by_pattern(conn, pattern_id)
        }).unwrap_or_default()
    }
}
```

#### 2C. Wire feedback store into analysis pipeline (P0, 1 hour)

When constructing `ConfidenceScorer` inside the analysis pipeline (from 1A):
```rust
let feedback_store = DbFeedbackStore::new(rt.db.clone());
let scorer = ConfidenceScorer::new(config)
    .with_feedback_store(Box::new(feedback_store));
```

#### 2D. Populate `pattern_id` in feedback writes (P1, 1 hour)

**File: `drift-napi/src/bindings/feedback.rs`**

Currently, `drift_dismiss_violation()` receives only `violation_id`. It needs to:
1. Look up the violation in the `violations` table to get its `pattern_id`
2. Write `pattern_id` into the feedback row

```rust
// Before insert_feedback, resolve pattern_id from violation
let pattern_id = rt.db.with_reader(|conn| {
    drift_storage::queries::enforcement::get_violation_pattern_id(conn, &input.violation_id)
}).map_err(storage_err)?.unwrap_or_default();
```

#### 2E. Add integration test (P0, 1 hour)

Test the full round-trip:
1. Insert a violation with `pattern_id = "test-pattern"`
2. Call `drift_dismiss_violation(violation_id)` 5 times
3. Construct scorer with `DbFeedbackStore`
4. Score `"test-pattern"` — verify confidence is lower than without feedback

---

## Gap 3: No Retention Policy on drift.db

### What Works Today

- **Bridge has 4-table retention ✅**: `retention.rs` applies cleanup for `bridge_event_log` (30d), `bridge_metrics` (7d), `bridge_grounding_snapshots` (365d), `bridge_grounding_results` (90d Community / unlimited Enterprise).
- **Workspace GC exists ✅**: `gc.rs` handles `workspace_events` (configurable retention, default 90d), incremental vacuum, and orphaned cache files.
- **GC is exposed via lifecycle ✅** (or at least accessible — `drift_shutdown()` does WAL checkpoint).

### What's Broken

**38 of 39 data tables in drift.db have no retention policy.** The only table with cleanup is `workspace_events` (via `gc.rs`). Everything else grows unbounded:

| Growth Pattern | Tables | Risk |
|---------------|--------|------|
| **Grows per scan** | `file_metadata`, `parse_cache`, `scan_history` | `scan_history` is append-only, unbounded |
| **Grows per analysis** | `detections`, `functions`, `call_edges`, `boundaries`, `data_access` | Each full analysis appends; no dedup/replace |
| **Grows per pattern run** | `pattern_confidence`, `outliers`, `conventions` | `pattern_confidence` uses UPSERT (bounded); `outliers` appends |
| **Grows per structural run** | All v005 tables (15 tables) | Each run appends new rows |
| **Grows per enforcement run** | `violations`, `gate_results`, `audit_snapshots`, `health_trends`, `policy_results`, `degradation_alerts` | All append-only |
| **Grows per user action** | `feedback` | Append-only, no cleanup |
| **Grows per advanced op** | `simulations`, `decisions`, `context_cache`, `migration_*` | All append-only |

### Severity Assessment

For a project scanned daily:
- `detections`: ~1000 rows/scan × 365 days = 365K rows/year
- `violations`: Similar growth
- `scan_history`: 365 rows/year (small but unbounded)
- `audit_snapshots`, `health_trends`: Append per audit run
- `context_cache`: Grows per MCP/CLI context generation

**Without retention, drift.db will reach 100MB+ within months on active projects.**

### Fix Plan — Gap 3

#### 3A. Define retention tiers (P0, design decision)

Proposed retention policy for drift.db tables:

| Tier | Retention | Tables | Rationale |
|------|-----------|--------|-----------|
| **Current** | Keep latest only | `file_metadata`, `functions`, `call_edges`, `coupling_metrics`, `constraints`, `contracts`, `wrappers`, `dna_genes`, `constants`, `env_variables`, `impact_scores`, `reachability_cache`, `pattern_confidence` | These represent current state; old rows are stale after re-analysis |
| **Short** | 30 days | `detections`, `outliers`, `violations`, `gate_results`, `error_gaps`, `taint_flows`, `crypto_findings`, `owasp_findings`, `secrets`, `degradation_alerts`, `policy_results` | Findings from recent scans; older ones are superseded |
| **Medium** | 90 days | `scan_history`, `audit_snapshots`, `health_trends`, `feedback`, `constraint_verifications`, `contract_mismatches`, `dna_mutations`, `coupling_cycles`, `test_coverage`, `test_quality`, `decomposition_decisions` | Trend data needed for history/momentum |
| **Long** | 365 days | `parse_cache`, `context_cache`, `simulations`, `decisions` | Cache/history that's useful but not critical |
| **Permanent** | No cleanup | `boundaries`, `conventions`, `migration_projects`, `migration_modules`, `migration_corrections` | Learned knowledge; deletion loses institutional memory |

#### 3B. Implement `apply_retention()` for drift.db (P0, 4 hours)

**New file: `drift-storage/src/retention.rs`**

```rust
pub struct RetentionPolicy {
    pub short_days: u32,    // default 30
    pub medium_days: u32,   // default 90
    pub long_days: u32,     // default 365
}

pub fn apply_retention(conn: &Connection, policy: &RetentionPolicy) -> Result<RetentionReport, StorageError> {
    // For "current" tables: DELETE WHERE file NOT IN (SELECT path FROM file_metadata)
    // For "short" tables: DELETE WHERE created_at < now - short_days
    // For "medium" tables: DELETE WHERE created_at < now - medium_days
    // For "long" tables: DELETE WHERE created_at < now - long_days
    // Return counts of deleted rows per table
}
```

Key considerations:
- **"Current" tier uses referential cleanup**, not time-based: delete detections/functions/etc. for files no longer in `file_metadata` (removed from project)
- **Time-based tiers** require `created_at` columns — verify all tables have them (most do from migrations)
- **Run inside a transaction** to avoid partial cleanup
- **Follow with incremental vacuum** to reclaim space

#### 3C. Wire retention into GC (P0, 1 hour)

**File: `drift-core/src/workspace/gc.rs`**

Extend `garbage_collect()` to call `apply_retention()` after workspace_events cleanup:

```rust
// After existing workspace_events cleanup:
let retention_report = drift_storage::retention::apply_retention(conn, &RetentionPolicy::default())?;
report.tables_cleaned = retention_report.total_deleted;
```

#### 3D. Add configurable retention to DriftConfig (P1, 1 hour)

**File: `drift-core/src/config/mod.rs`**

```toml
[retention]
short_days = 30
medium_days = 90
long_days = 365
```

Allow users to override retention periods. Enterprise users might want longer retention.

#### 3E. Expose retention via NAPI (P1, 1 hour)

**File: `drift-napi/src/bindings/lifecycle.rs`**

Add `drift_gc()` NAPI function:
```rust
#[napi(js_name = "driftGC")]
pub fn drift_gc(retention_days: Option<u32>, dry_run: Option<bool>) -> napi::Result<JsGCReport>
```

#### 3F. Auto-retention on shutdown (P2, 30 min)

Optionally run lightweight retention during `drift_shutdown()` to keep drift.db trimmed without requiring explicit GC calls.

---

## Implementation Order

```
Week 1:
  Day 1-2: Gap 1A — Implement drift_analyze() orchestration pipeline
  Day 2-3: Gap 1B — Add missing BatchCommands for v004-v007 tables
  Day 3:   Gap 2A+2B — DbFeedbackStore + query_feedback_by_pattern
  
Week 2:
  Day 4:   Gap 2C+2D — Wire feedback store + populate pattern_id
  Day 5:   Gap 3B+3C — Implement and wire retention policy
  Day 5:   Gap 1C — Wire structural intelligence persistence
  Day 6:   Gap 3D+3E — Config + NAPI exposure
  Day 6:   Gap 2E + integration tests for all three gaps
  Day 7:   Gap 3F + final verification + cleanup
```

## Verification Criteria

### Gap 1 — Pipeline Populated
- [ ] `drift_analyze()` returns non-empty results for test fixtures
- [ ] `detections` table has rows after analysis
- [ ] `functions` table has rows after analysis
- [ ] `pattern_confidence` table has rows after analysis
- [ ] All 13 existing BatchCommands fire during a full analysis run
- [ ] New BatchCommands for v004-v007 tables fire correctly

### Gap 2 — Feedback Loop Closed
- [ ] `DbFeedbackStore` reads from `feedback` table
- [ ] 5 dismiss actions on same pattern measurably lower confidence score
- [ ] 5 fix actions on same pattern measurably raise confidence score
- [ ] `pattern_id` is populated in feedback rows (not empty string)
- [ ] Round-trip test: write feedback → re-score → verify delta

### Gap 3 — Retention Policy Active
- [ ] `apply_retention()` deletes rows older than configured threshold
- [ ] "Current" tier cleanup removes orphaned rows for deleted files
- [ ] `drift_gc()` NAPI function returns accurate report
- [ ] `GCReport` includes per-table deletion counts
- [ ] Incremental vacuum runs after retention cleanup
- [ ] drift.db size stays bounded over 30+ simulated daily scans
