# Phase B Prompt — Temporal Queries

You are implementing Phase B of the cortex temporal reasoning addition. Read these files first:

- `TEMPORAL-TASK-TRACKER.md` (Phase B section, tasks `PTB-*` and tests `TTB-*`)
- `TEMPORAL-IMPLEMENTATION-SPEC.md`
- `FILE-MAP.md`

**Prerequisite:** QG-T0 has passed — Phase A's event store foundation is fully operational. The `cortex-temporal` crate exists with working event append, snapshot creation, and state reconstruction. All `TTA-*` tests pass, `cargo test --workspace` is green, and coverage ≥80% on all Phase A modules.

## What This Phase Builds

This phase adds the temporal query algebra and dual-time enforcement layer. 15 impl tasks, 30 tests. Specifically:

1. **cortex-core**: 2 new model files (`temporal_query.rs`, `temporal_diff.rs`) + modify `models/mod.rs` for re-exports — these define `AsOfQuery`, `TemporalRangeQuery` (4 Allen's interval modes: Overlaps/Contains/StartedDuring/EndedDuring), `TemporalDiffQuery`, `DiffScope` (4 variants), `DecisionReplayQuery`, `TemporalCausalQuery`, `TemporalDiff`, `MemoryModification`, `ConfidenceShift`, `DiffStats`
2. **cortex-storage**: 1 new query module (`temporal_ops.rs`) + modify `queries/mod.rs` — raw SQL: `get_memories_valid_at()`, `get_memories_in_range()`, `get_memories_modified_between()` using the temporal indexes created in v014
3. **cortex-temporal query module** (5 new files):
   - `query/mod.rs` — `TemporalQueryDispatcher` routes `TemporalQuery` enum to correct handler
   - `query/as_of.rs` — `execute_as_of()`: bitemporal filter (`transaction_time <= S AND valid_time <= V AND valid_until > V`), uses `reconstruct_all_at`, applies integrity filter
   - `query/range.rs` — `execute_range()`: 4 modes (Overlaps, Contains, StartedDuring, EndedDuring), optimized via temporal indexes on memories table
   - `query/diff.rs` — `execute_diff()`: event-range optimization (O(events_in_range) not O(total_memories×2)), computes `DiffStats` (net_change, confidence_trend, churn_rate)
   - `query/integrity.rs` — `enforce_temporal_integrity()`: filters dangling refs (linked_patterns, linked_files, linked_functions, superseded_by), temporal join constraint for relationships
4. **cortex-temporal dual_time module** (4 new files):
   - `dual_time/mod.rs` — module declarations + re-exports
   - `dual_time/validation.rs` — `validate_transaction_time_immutability()` rejects transaction_time updates, `validate_temporal_bounds()` enforces valid_time <= valid_until
   - `dual_time/correction.rs` — `apply_temporal_correction()`: closes old record, creates corrected version, sets supersedes/superseded_by
   - `dual_time/late_arrival.rs` — `handle_late_arriving_fact()`: sets transaction_time=now, valid_time=past, validates valid_time < transaction_time
5. **cortex-temporal engine update**: implement `query_as_of`, `query_range`, `query_diff` methods on `TemporalEngine` (previously returned not-yet-implemented error)

## Critical Implementation Details

- **AS OF current time must equal current state** — this is the fundamental correctness invariant. `query_as_of(now())` returns the same results as a normal query.
- **Diff is event-range optimized** — query events between time_a and time_b, group by memory_id, classify as created/archived/modified. Do NOT reconstruct full state at both times and compare (that's O(total_memories×2)).
- **Diff identity**: `diff(T, T)` must return an empty diff for any T.
- **Diff symmetry**: `diff(A,B).created == diff(B,A).archived`.
- **Temporal integrity** is applied automatically by all query types — no returned memory should reference a non-existent memory at the query time. If memory A references memory B, and B didn't exist at the query time, the reference is stripped from A's result.
- **transaction_time is immutable** — any attempt to modify it must return `TemporalError::ImmutableFieldViolation`.
- **Temporal bounds**: `valid_time > valid_until` must return `TemporalError::InvalidTemporalBounds`.
- **Temporal correction** creates a new version — the old record is closed (valid_until set), the new record is created with corrected times, and supersedes/superseded_by links are set.
- **Late-arriving facts**: transaction_time = now (when we learned it), valid_time = past (when it was actually true). Validate that valid_time < transaction_time.

## Reference Crate Patterns

Match existing patterns exactly. Look at how `cortex-retrieval/src/ranking/` organizes its query modules, and how `cortex-causal/src/inference/` dispatches to strategy handlers. The query dispatcher pattern should follow the same approach.

## Task Checklist

Check off tasks in `TEMPORAL-TASK-TRACKER.md` as you complete them: `PTB-STOR-01` through `PTB-STOR-02`, `PTB-TEMP-01` through `PTB-TEMP-10`, `PTB-CORE-01` through `PTB-CORE-03`, and all `TTB-*` tests.

## Quality Gate QG-T1 Must Pass

- All `TTB-*` tests pass
- `cargo test -p cortex-temporal` — zero failures
- `cargo test --workspace` — zero regressions
- Coverage ≥80% for cortex-temporal query modules
- Coverage ≥80% for cortex-temporal dual_time modules
- Benchmark baselines established: point-in-time single memory < 5ms cold / < 1ms warm, point-in-time all 10K memories < 500ms cold / < 50ms warm, temporal diff < 1s cold / < 100ms warm, range query Overlaps < 50ms
