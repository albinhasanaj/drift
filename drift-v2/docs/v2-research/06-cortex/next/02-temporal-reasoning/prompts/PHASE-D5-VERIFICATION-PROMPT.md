# Phase D5 Prompt — Task Tracker Verification

You are performing the verification audit for the cortex temporal reasoning task tracker. Read these files first:

- `TEMPORAL-TASK-TRACKER.md` (all sections — Phases A through D4, Golden Fixtures, QG-T4)
- `TEMPORAL-IMPLEMENTATION-SPEC.md` (all sections — especially Complete File Inventory, Recommendation Coverage Matrix, Property-Based Tests, Benchmark Targets, Stress Tests)
- `FILE-MAP.md` (all sections — every new and modified file)

**Purpose:** This is NOT an implementation phase. This is a verification audit that cross-references the task tracker against the implementation spec and file map to confirm 100% coverage. The output is a `TASK-TRACKER-VERIFICATION.md` document (placed alongside the task tracker) that proves every spec item is accounted for — or identifies gaps.

**Reference:** Follow the exact pattern established by `01-multi-agent-memory/TASK-TRACKER-VERIFICATION.md`.

## What You're Verifying

The TEMPORAL-TASK-TRACKER.md must account for 100% of:

1. **All new files** (spec says 91) — every file in the spec's "Complete File Inventory → New Files by Crate" must have a corresponding task ID
2. **All modified files** (spec says 31) — every file in the spec's "Complete File Inventory → Modified Files by Crate" must have a corresponding task ID
3. **All 12 property-based tests** — every property in the spec's "Property-Based Tests (Complete List)" table must have a corresponding test task
4. **All 17 benchmark targets** — every benchmark in the spec's "Benchmark Targets (Complete)" table must have a corresponding test task
5. **All 5 stress tests** — every stress test in the spec's "Stress Tests" table must have a corresponding test task
6. **All 13 golden fixtures** — every fixture in the spec's "Golden Test Fixtures" section must have a corresponding task
7. **All 7 quality gates** (QG-T0 through QG-T4, plus QG-T3a through QG-T3d) — every gate must be defined with pass/fail criteria
8. **All 18 recommendations** (TR1-TR18) — every recommendation must be covered by at least one task
9. **All 11 cross-reference corrections** (CR1-CR11) — every correction must be covered by at least one task
10. **All enterprise requirements** — logging, error handling, performance targets, backward compatibility

## Verification Procedure

For each category above, produce a checklist with:
- `[x]` if the item is accounted for in the task tracker (cite the task ID)
- `[ ]` if the item is MISSING from the task tracker (flag as a gap)

### Step 1: New File Coverage (91 files)

Walk through each crate section in the spec's file inventory. For every new file listed, find the corresponding task ID in the task tracker. Group by crate:

- **cortex-temporal** (51 files): 40 src + 10 tests + 1 bench
- **cortex-core** (10-11 files): 8 models + 1 error + 1 trait + 1 config
- **cortex-storage** (6-7 files): 1 migration + 5-6 query modules
- **cortex-causal** (1 file): temporal_graph.rs
- **cortex-napi** (2 files): bindings + conversions
- **test-fixtures** (13 files): golden JSON fixtures
- **TypeScript** (8 files): 5 MCP tools + 3 CLI commands

**Watch for discrepancies** between the spec's file count and the actual task tracker count. The spec says 91 new files — verify the actual count. Note: the spec has a known inconsistency where cortex-core lists "10 files" in the heading but actually has 11 (temporal_config.rs is listed separately under config). Similarly, cortex-storage lists "7 files" in the heading but the actual list has 6. Document any discrepancies.

### Step 2: Modified File Coverage (31 files)

Walk through each crate section in the spec's modified file inventory. For every modified file listed, find the corresponding task ID. Group by crate:

- **cortex-core** (5 files): models/mod.rs, errors/mod.rs, errors/cortex_error.rs, traits/mod.rs, config/mod.rs
- **cortex-storage** (7 files): migrations/mod.rs, queries/mod.rs, memory_crud.rs, audit_ops.rs, link_ops.rs, version_ops.rs — note: the spec says 7 but only lists 6 in the "Modified Files" section; the 7th is queries/mod.rs which has multiple modifications across phases
- **cortex-causal** (2 files): graph/mod.rs, graph/sync.rs
- **cortex-validation** (2 files): engine.rs, dimensions/temporal.rs
- **cortex-observability** (3 files): reporter.rs, subsystem_checks.rs, recommendations.rs
- **cortex-consolidation** (2 files): engine.rs, pipeline/phase6_pruning.rs
- **cortex-decay** (1 file): engine.rs
- **cortex-reclassification** (1 file): engine.rs
- **cortex-retrieval** (2 files): scorer.rs, ranking/mod.rs
- **cortex-napi** (2 files): bindings/mod.rs, conversions/mod.rs
- **Workspace** (1 file): Cargo.toml
- **TypeScript** (4-5 files): bridge/types.ts, bridge/client.ts, tools/index.ts, cli/index.ts, tests/bridge.test.ts

**Watch for discrepancies**: The spec says 31 modified files but the TypeScript section lists 5 files (including bridge.test.ts) while the heading says 4. Document any discrepancies.

### Step 3: Property-Based Test Coverage (12 tests)

The spec defines exactly 12 property-based tests in the "Property-Based Tests (Complete List)" table. Verify each has a corresponding test task:

| # | Property | Expected Task ID Pattern |
|---|----------|--------------------------|
| 1 | Replay consistency | `TTA-19` |
| 2 | Snapshot + replay == full replay | `TTA-13` |
| 3 | Temporal monotonicity | `TTA-20` |
| 4 | Diff symmetry | `TTB-24` |
| 5 | Diff identity | `TTB-23` |
| 6 | AS OF current == current | `TTB-22` |
| 7 | KSI bounds [0.0, 1.0] | `TTD1-02` |
| 8 | Evidence freshness bounds [0.0, 1.0] | `TTD1-09` |
| 9 | Epistemic ordering | `TTD2-10` |
| 10 | Temporal referential integrity | `TTB-25` |
| 11 | Event count conservation | `TTA-21` |
| 12 | Confidence aggregation bounds | `TTD2-09` |

Verify all 12 are present. Also check for additional property tests in the task tracker that go beyond the spec's 12 (e.g., `TTB-26` temporal bounds, `TTC-12` temporal causal at current, `TTC-13` graph reconstruction monotonicity).

### Step 4: Benchmark Target Coverage (17 benchmarks)

The spec defines exactly 17 benchmark targets. Verify each has a corresponding test task:

| Benchmark | Target | Phase | Expected Task ID |
|-----------|--------|-------|------------------|
| Event append (single) | < 0.1ms | A | `TTA-22` |
| Event append (batch of 100) | < 5ms | A | `TTA-23` |
| Reconstruction 50 events | < 5ms | A | `TTA-24` |
| Reconstruction snapshot + 10 events | < 1ms | A | `TTA-25` |
| Snapshot creation (single) | < 2ms | A | `TTA-26` |
| Snapshot batch (100 memories) | < 200ms | A | `TTA-27` |
| Point-in-time single memory | < 5ms cold, < 1ms warm | B | `TTB-27` |
| Point-in-time all 10K memories | < 500ms cold, < 50ms warm | B | `TTB-28` |
| Range query Overlaps | < 50ms | B | `TTB-30` |
| Temporal diff | < 1s cold, < 100ms warm | B | `TTB-29` |
| Decision replay | < 200ms warm | C | `TTC-14` |
| Temporal causal traversal | < 20ms warm | C | `TTC-15` |
| Graph reconstruction 1K edges | < 10ms cold, < 2ms warm | C | `TTC-16` |
| KSI computation 10K memories | < 100ms | D1 | `TTD1-18` |
| Full drift metrics 10K memories | < 500ms | D1 | `TTD1-19` |
| Evidence freshness single memory | < 1ms | D1 | `TTD1-20` |
| Alert evaluation (100 metrics) | < 10ms | D1 | `TTD1-21` |

### Step 5: Stress Test Coverage (5 tests)

The spec defines 5 stress tests. Verify each is accounted for in the task tracker (likely in the Golden Fixtures / Test Files section or the QG-T4 section):

| Stress Test | Scale | Target |
|-------------|-------|--------|
| High-volume event append | 100K events sequential | < 10s |
| Reconstruction under load | 10K memories | < 50ms |
| Concurrent reads during writes | 10 readers + 1 writer, 10K ops | No deadlocks |
| Drift computation large dataset | 10K memories, 100K events | < 500ms |
| Compaction under load | 500K events | < 30s |

### Step 6: Golden Fixture Coverage (13 fixtures)

Verify all 13 golden fixtures from the spec are in the task tracker:

**Reconstruction** (5): reconstruction_simple, reconstruction_with_snapshot, reconstruction_branching, reconstruction_late_arrival, reconstruction_correction
**Diff** (3): diff_sprint_boundary, diff_empty, diff_major_refactor
**Replay** (2): replay_auth_decision, replay_with_hindsight
**Drift** (3): drift_stable, drift_erosion, drift_explosion

### Step 7: Quality Gate Coverage (7 gates)

Verify all quality gates are defined with complete pass/fail criteria:

| Gate | Phase | Key Criteria |
|------|-------|-------------|
| QG-T0 | A | All TTA-* pass, coverage ≥80% event_store + snapshot, benchmarks established |
| QG-T1 | B | All TTB-* pass, coverage ≥80% query + dual_time, benchmarks established |
| QG-T2 | C | All TTC-* pass, coverage ≥80% replay + temporal_causal + temporal_graph |
| QG-T3a | D1 | All TTD1-* pass, coverage ≥80% drift modules |
| QG-T3b | D2 | All TTD2-* pass, coverage ≥80% epistemic + views |
| QG-T3c | D3 | All TTD3-* pass, cargo test for retrieval/validation/observability |
| QG-T3d | D4 | All TTD4-* pass, cargo check cortex-napi, vitest passes |
| QG-T4 | Final | All TT-INT-* + TT-FINAL-* pass, full workspace green |

Note: That's 8 gates total (QG-T0 through QG-T4 = 5, plus QG-T3a through QG-T3d = 4, but QG-T3a-d are sub-gates of the D phase). The task tracker header says 7 quality gates. Verify the actual count and document any discrepancy.

### Step 8: Recommendation Coverage (TR1-TR18 + CR1-CR11)

Cross-reference the spec's "Recommendation Coverage Matrix" against the task tracker. For each recommendation, identify at least one task that covers it:

**TR1** (Event Store) → Phase A tasks PTA-TEMP-04 through PTA-TEMP-09, PTA-STOR-03 through PTA-STOR-09
**TR2** (Snapshots) → Phase A tasks PTA-TEMP-10 through PTA-TEMP-15
**TR3** (Query Algebra) → Phase B tasks PTB-TEMP-01 through PTB-TEMP-05, Phase C tasks PTC-TEMP-01 through PTC-TEMP-02
**TR4** (Dual-Time) → Phase B tasks PTB-TEMP-06 through PTB-TEMP-09
**TR5** (Temporal Integrity) → Phase B task PTB-TEMP-05 (integrity.rs)
**TR6** (Drift Metrics) → Phase D1 tasks PTD1-TEMP-02 through PTD1-TEMP-03
**TR7** (Drift Alerting) → Phase D1 task PTD1-TEMP-04, Phase D3 tasks PTD3-OBS-01 through PTD3-OBS-03
**TR8** (Drift Snapshots) → Phase D1 task PTD1-TEMP-05
**TR9** (Materialized Views) → Phase D2 tasks PTD2-TEMP-05 through PTD2-TEMP-08
**TR10** (Temporal Causal) → Phase C tasks PTC-CAUSAL-01 through PTC-CAUSAL-02
**TR11** (Epistemic) → Phase D2 tasks PTD2-TEMP-01 through PTD2-TEMP-04, Phase D3 task PTD3-VALID-01
**TR12** (Evolution Patterns) → Phase D1 task PTD1-TEMP-06
**TR13** (Retrieval Boosting) → Phase D3 tasks PTD3-RET-01 through PTD3-RET-02
**TR14** (Crate Architecture) → Phase A tasks PTA-WS-01, PTA-TEMP-01 through PTA-TEMP-03
**TR15** (Existing Crate Changes) → Spread across all phases (mutation wiring, NAPI, TypeScript)
**TR16** (Migration Path) → Enforced by phase ordering
**TR17** (Testing) → All TT* test tasks + golden fixtures + benchmarks
**TR18** (Backward Compat) → Enforced by additive-only design
**CR1** (Graphiti Correction) → Documentation only, no task needed
**CR2** (Schema Versioning) → PTA-TEMP-08 (upcaster.rs), PTA-CORE-01 (schema_version field)
**CR3** (Idempotent Recording) → PTA-STOR-06 through PTA-STOR-09, PTA-CAUSAL-01
**CR4** (Compaction) → PTA-TEMP-09 (compaction.rs), PTA-TEMP-14 (retention.rs)
**CR5** (Concurrency) → PTA-TEMP-03 (engine.rs with writer + readers)
**CR6** (Coverage Ratio Deferred) → Documentation only, no task needed
**CR7** (Competitors Update) → Documentation only, no task needed
**CR8** (Scorer Correction) → PTD3-RET-01 (additive, not multiplicative)
**CR9** (Codebase Verification) → Documentation only, no task needed
**CR10** (Event Ordering) → PTA-TEMP-05 (append.rs with AUTOINCREMENT + Mutex)
**CR11** (Replay Verification) → PTA-TEMP-07 (replay.rs, excluded last_accessed/access_count)

### Step 9: Task Count Verification

Produce a summary table of implementation tasks and test tasks per phase. Compare against the task tracker's own "Progress Summary" table. Flag any count mismatches.

Expected counts from the task tracker header:
- Total New Files: 91
- Total Modified Files: 31
- Total Touched: 122
- Total Phases: 4 (A-D, with D split into D1-D4)
- Quality Gates: 7 (QG-T0 through QG-T4, plus QG-T3a through QG-T3d)
- Property-Based Tests: 12
- Benchmark Targets: 17

### Step 10: Current Implementation Status Audit

Cross-reference the task tracker's checkbox status against the actual codebase. For each phase marked as complete (✅), verify that the corresponding files actually exist on disk. For phases marked as not started (⬜), confirm no files exist yet.

**Known status from task tracker Progress Summary:**
- Phase A: ⬜ Not Started (0/40 impl, 0/27 tests)
- Phase B: ⬜ Not Started (0/15 impl, 0/30 tests)
- Phase C: ✅ Complete (7/7 impl, 16/16 tests)
- Phase D1: ✅ Complete (12/12 impl, 21/21 tests)
- Phase D2: ✅ Complete (14/14 impl, 15/15 tests)
- Phase D3: ✅ Complete (7/7 impl, 12/12 tests)
- Phase D4: ✅ Complete (17/17 impl, 11/11 tests)
- Golden Fixtures + Test Files: ⬜ Not Started (0/24)
- Quality Gates: ⬜ Not Started (0/14 impl, 0/16 tests)

**Anomaly to investigate**: Phases C through D4 are marked complete, but Phases A and B are not started. The task tracker states "No Phase N+1 begins until Phase N quality gate passes." This means either:
1. The checkboxes are aspirational (marking what the prompts cover, not what's implemented), OR
2. Phases A and B were implemented outside the task tracker, OR
3. The phase ordering rule was violated

Investigate by checking whether the cortex-temporal crate files exist on disk and whether the Phase A/B files (event_store, snapshot, query, dual_time) are present.

## Output Format

Produce a `TASK-TRACKER-VERIFICATION.md` file with:

1. **Executive Summary** — one paragraph: verified or gaps found
2. **File Coverage Verification** — new files (91) and modified files (31) with task ID citations
3. **Test Coverage Verification** — property tests (12), benchmarks (17), stress tests (5), golden fixtures (13)
4. **Quality Gate Verification** — all 7-8 gates with criteria
5. **Recommendation Coverage** — TR1-TR18 + CR1-CR11
6. **Task Count Verification** — summary table with actual vs expected counts
7. **Implementation Status Audit** — codebase vs task tracker checkbox alignment
8. **Spec Discrepancies** — any inconsistencies between the spec, file map, and task tracker (file counts, missing files, extra files)
9. **Conclusion** — VERIFIED or GAPS FOUND, with specific remediation items if gaps exist

## Critical Details

- **Be exhaustive** — check every single file, every single test, every single recommendation. No shortcuts.
- **Cite task IDs** — every verification item must reference the specific task ID that covers it.
- **Document discrepancies** — the spec has known inconsistencies in file counts (e.g., cortex-core says "10 files" but has 11). Document these, don't silently ignore them.
- **Check the Progress Summary** — the task tracker's own progress table at the bottom must be consistent with the actual checkbox counts. Recount if needed.
- **Flag the A/B anomaly** — the fact that C-D4 are complete but A-B are not started is a significant finding that must be documented and explained.
- **Compare FILE-MAP.md against the spec** — the FILE-MAP and the spec should list the same files. If they diverge, document which is authoritative.
