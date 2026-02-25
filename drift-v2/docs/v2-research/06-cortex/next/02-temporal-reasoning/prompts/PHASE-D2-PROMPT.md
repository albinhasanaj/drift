# Phase D2 Prompt — Epistemic Status + Materialized Views

You are implementing Phase D2 of the cortex temporal reasoning addition. Read these files first:

- `TEMPORAL-TASK-TRACKER.md` (Phase D2 section, tasks `PTD2-*` and tests `TTD2-*`)
- `TEMPORAL-IMPLEMENTATION-SPEC.md`
- `FILE-MAP.md`

**Prerequisite:** QG-T3a has passed — Phase D1's drift metrics, alerting, evidence freshness, and pattern detection are fully operational. All `TTD1-*` tests pass.

## What This Phase Builds

This phase adds the epistemic status model and materialized temporal views. 14 impl tasks, 15 tests. Specifically:

1. **cortex-core**: 2 new model files + modify `models/mod.rs`:
   - `epistemic_status.rs` — `EpistemicStatus` enum with per-variant metadata:
     - `Conjecture { source: String, created_at: DateTime<Utc> }`
     - `Provisional { evidence_count: u32, last_validated: DateTime<Utc> }`
     - `Verified { verified_by: Vec<String>, verified_at: DateTime<Utc>, evidence_refs: Vec<String> }`
     - `Stale { was_verified_at: DateTime<Utc>, staleness_detected_at: DateTime<Utc>, reason: String }`
     - `AggregationStrategy` enum: `WeightedAverage` (mean) and `GodelTNorm` (min operator)
   - `materialized_view.rs` — `MaterializedTemporalView` struct (view_id, label, timestamp, memory_count, snapshot_ids, drift_snapshot_id, created_by, auto_refresh)
2. **cortex-storage**: 1 new query module (`view_ops.rs`) + modify `queries/mod.rs` — raw SQL: `insert_materialized_view`, `get_view_by_label`, `list_views`, `delete_view`
3. **cortex-temporal epistemic module** (4 new files):
   - `epistemic/mod.rs` — module declarations + re-exports
   - `epistemic/status.rs` — `determine_initial_status(source: &EventActor) -> EpistemicStatus`: ALL new memories start as `Conjecture` regardless of source (user, agent, system)
   - `epistemic/transitions.rs` — 3 transition functions with strict validation:
     - `promote_to_provisional(current, evidence_count)` — only valid from `Conjecture`. Any other source state → `TemporalError::InvalidEpistemicTransition`
     - `promote_to_verified(current, verified_by, evidence_refs)` — only valid from `Provisional`. Conjecture→Verified is REJECTED (no skipping steps). Stale→Verified is REJECTED.
     - `demote_to_stale(current, reason)` — only valid from `Verified`. Conjecture→Stale is REJECTED. Provisional→Stale is REJECTED. No backward transitions except Verified→Stale.
   - `epistemic/aggregation.rs` — `aggregate_confidence(evidences, strategy)`:
     - `WeightedAverage`: `sum / len` (existing approach, default)
     - `GodelTNorm`: `min` operator — a single weak evidence (0.3) drags aggregate to 0.3 regardless of how many strong sources exist. Conservative, appropriate for high-stakes contexts. From TS11 (FPF paper).
     - Configurable via `TemporalConfig.confidence_aggregation`.
4. **cortex-temporal views module** (4 new files):
   - `views/mod.rs` — module declarations + re-exports
   - `views/create.rs` — `create_materialized_view(writer, reader, label, timestamp)`:
     1. Reconstruct all active memories at timestamp via `reconstruct_all_at`
     2. Create snapshots for each memory (reason: `OnDemand`)
     3. Compute drift metrics at that point (2-week window)
     4. Store drift snapshot, associate with view
     5. Store view via `view_ops::insert_materialized_view`
   - `views/query.rs` — `get_view()`, `list_views()`, `diff_views(label_a, label_b)` — diff_views is an instant diff between two pre-computed views, delegates to `query_diff` with the two view timestamps
   - `views/auto_refresh.rs` — `AutoRefreshScheduler`:
     - `should_create_view()` → `Option<String>`: returns a label (e.g., "auto-2026-02-07") if elapsed > `materialized_view_auto_interval_days` (default: 14 days)
     - Skips creation if no events since last view (`has_changes_since_last_view()` checks event count)
     - Returns `None` if interval not elapsed or no changes
5. **cortex-temporal engine update**: implement `create_view` and `get_view` methods on `TemporalEngine` (previously returned not-yet-implemented error)

## Critical Implementation Details

- **Epistemic status is orthogonal to confidence** — a memory can have high confidence (0.9) but be a Conjecture (no one verified it). A memory can have moderate confidence (0.6) but be Verified (multiple people confirmed it).
- **Valid promotion paths are strictly enforced**:
  - Conjecture → Provisional → Verified (only forward, no skipping)
  - Verified → Stale (only degradation path, via evidence decay)
  - Conjecture → Verified: **REJECTED** with `InvalidEpistemicTransition`
  - Verified → Provisional: **REJECTED** with `InvalidEpistemicTransition`
  - Provisional → Stale: **REJECTED** — Stale only comes from Verified
- **GodelTNorm aggregation = min**: `[0.9, 0.3, 0.8]` → `0.3`. This prevents the "many weak signals = strong signal" fallacy.
- **Confidence aggregation bounds [0.0, 1.0]** for both strategies — property test this.
- **Materialized view creation is expensive** — it reconstructs all memories and creates snapshots. This is intentional — views are created infrequently (every 2 weeks or on-demand).
- **diff_views is cheap** — it delegates to the existing diff engine with two timestamps. The views just provide convenient named time points.
- **Auto-refresh skips when no changes** — if zero events have been recorded since the last auto-created view, `should_create_view()` returns `None` even if the interval has elapsed. No point snapshotting identical state.

## Reference Crate Patterns

For epistemic transitions, look at how `cortex-validation/src/dimensions/` validates dimension scores with strict pass/fail criteria — similar pattern of strict state machine transitions with error on invalid paths.

For materialized views, look at how `cortex-consolidation/src/scheduling/` manages periodic tasks — similar pattern of interval-based scheduling with skip-if-no-work logic.

## Task Checklist

Check off tasks in `TEMPORAL-TASK-TRACKER.md` as you complete them: `PTD2-CORE-01` through `PTD2-CORE-03`, `PTD2-STOR-01` through `PTD2-STOR-02`, `PTD2-TEMP-01` through `PTD2-TEMP-09`, and all `TTD2-*` tests.

## Quality Gate QG-T3b Must Pass

- All `TTD2-*` tests pass
- Coverage ≥80% for cortex-temporal epistemic modules
- Coverage ≥80% for cortex-temporal views modules
