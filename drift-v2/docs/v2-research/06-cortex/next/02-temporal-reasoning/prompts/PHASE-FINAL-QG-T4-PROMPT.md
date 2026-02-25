# Final Integration Prompt — QG-T4 Quality Gate

You are running the final integration quality gate (QG-T4) for the cortex temporal reasoning addition. Read these files first:

- `TEMPORAL-TASK-TRACKER.md` (QG-T4 section, tasks `TT-INT-*` and `TT-FINAL-*`, plus Golden Fixtures `PTF-*`)
- `TEMPORAL-IMPLEMENTATION-SPEC.md`
- `FILE-MAP.md`

**Prerequisite:** QG-T3d has passed — all four phases (A through D4) are complete. All `TTA-*`, `TTB-*`, `TTC-*`, `TTD1-*`, `TTD2-*`, `TTD3-*`, `TTD4-*` tests pass. `cargo test --workspace` is green.

## What This Phase Builds

This is the capstone validation phase. No new feature code — only golden test fixtures, integration test files, property test infrastructure, benchmark harness, and end-to-end validation. 24 fixture/test-file tasks + 16 final check tasks.

### 1. Golden Test Fixtures (13 JSON files)

Create all fixtures in `crates/cortex/test-fixtures/golden/temporal/`. Each is a JSON file with known inputs and expected outputs, following the pattern established by `test-fixtures/golden/consolidation/`.

**Temporal Reconstruction Fixtures** (5):
- `reconstruction_simple.json` — 10 events, 1 memory, expected state at 3 time points
- `reconstruction_with_snapshot.json` — 50 events + 1 snapshot, expected state at 5 time points
- `reconstruction_branching.json` — consolidation + reclassification events
- `reconstruction_late_arrival.json` — late-arriving fact (valid_time < transaction_time)
- `reconstruction_correction.json` — temporal correction (old record closed, new created)

**Temporal Diff Fixtures** (3):
- `diff_sprint_boundary.json` — sprint-12 vs sprint-14, expected diff
- `diff_empty.json` — same time point, expected empty diff
- `diff_major_refactor.json` — before/after refactor, expected counts

**Decision Replay Fixtures** (2):
- `replay_auth_decision.json` — auth decision context
- `replay_with_hindsight.json` — decision + contradicting knowledge

**Drift Detection Fixtures** (3):
- `drift_stable.json` — stable KB, KSI ≈ 1.0, no alerts
- `drift_erosion.json` — declining confidence, expected alert
- `drift_explosion.json` — creation spike, expected alert

### 2. Test Entry Points (11 files)

Create all test files in `crates/cortex/cortex-temporal/tests/`:
- `temporal_test.rs` — event store + snapshot + reconstruction tests
- `query_test.rs` — all 5 query type tests
- `drift_test.rs` — drift metrics + alerting tests
- `epistemic_test.rs` — epistemic status transition tests
- `golden_test.rs` — golden fixture validation (loads each JSON, runs scenario, asserts expected output)
- `stress_test.rs` — high-volume + concurrent tests (100K events sequential, 10K memories reconstruction, concurrent read/write, drift on large dataset, compaction under load)
- `coverage_test.rs` — public API surface coverage (follows pattern from cortex-causal/tests/coverage_test.rs)
- `property_tests.rs` — entry point for proptest module
- `property/mod.rs` — module declarations
- `property/temporal_properties.rs` — all 12 property-based tests:
  1. Replay consistency (replay(events) == apply_one_by_one(events))
  2. Snapshot + replay == full replay
  3. Temporal monotonicity (event_ids strictly increasing)
  4. Diff symmetry (diff(A,B).created == diff(B,A).archived)
  5. Diff identity (diff(T,T) == empty)
  6. AS OF current == current state
  7. KSI bounds [0.0, 1.0]
  8. Evidence freshness bounds [0.0, 1.0]
  9. Epistemic ordering (only valid promotion paths)
  10. Temporal referential integrity (no dangling refs at any time T)
  11. Event count conservation (appended == queryable)
  12. Confidence aggregation bounds [0.0, 1.0] for both strategies
- `benches/temporal_bench.rs` — all 17 benchmark targets (event append single/batch, reconstruction cold/warm, snapshot single/batch, point-in-time single/all, range query, temporal diff, decision replay, temporal causal, graph reconstruction, KSI, full drift, evidence freshness, alert evaluation)

### 3. End-to-End Integration Tests (9 tests)

These test cross-crate flows that span the entire temporal system:

- `TT-INT-01` — Full lifecycle: create memory → mutate 20 times → reconstruct at 5 time points → all correct
- `TT-INT-02` — Cross-crate event flow: decay engine decays → event recorded → temporal query sees decay
- `TT-INT-03` — Consolidation temporal trail: consolidate 3 memories → events for all 3 → replay shows consolidation
- `TT-INT-04` — Validation → epistemic promotion: validate → status promoted → retrieval score changes
- `TT-INT-05` — Drift metrics end-to-end: create/archive/modify → metrics reflect → alerts fire
- `TT-INT-06` — Decision replay end-to-end: create decision → add context → replay → context matches
- `TT-INT-07` — NAPI round-trip all 10 functions: TypeScript → Rust → TypeScript
- `TT-INT-08` — MCP tools all 5 functional: each returns valid response
- `TT-INT-09` — CLI commands all 3 functional: each produces output

### 4. Final Checks (7 checks)

- `TT-FINAL-01` — `cargo test --workspace` passes with zero failures
- `TT-FINAL-02` — `cargo tarpaulin -p cortex-temporal --ignore-tests` reports ≥80% overall coverage
- `TT-FINAL-03` — `cargo bench -p cortex-temporal` — all 17 benchmarks within target
- `TT-FINAL-04` — `cargo clippy -p cortex-temporal` — zero warnings
- `TT-FINAL-05` — `cargo clippy --workspace` — zero new warnings from temporal changes
- `TT-FINAL-06` — Storage overhead within bounds: 10K memories, 6 months → total temporal storage < 500MB
- `TT-FINAL-07` — `vitest run` in packages/cortex — all tests pass including temporal

## Critical Implementation Details

- **Golden fixtures must be deterministic** — use fixed timestamps, fixed UUIDs, fixed content. No randomness in fixture data. The expected outputs must be exactly reproducible.
- **Property tests use proptest with 256 iterations default** — configurable via `PROPTEST_CASES` env var. CI should use 1024.
- **Stress tests have explicit scale targets** — 100K events sequential < 10s, 10K memories reconstruction < 50ms, concurrent 10 readers + 1 writer with 10K operations must not deadlock.
- **Benchmark targets are hard limits** — if any benchmark exceeds its target, investigate before proceeding. The targets are based on the implementation spec's performance analysis.
- **Coverage is measured per-module** — `cargo tarpaulin -p cortex-temporal --ignore-tests` must report ≥80% line coverage. Test code itself doesn't count toward coverage.
- **Storage overhead check** — create a test that inserts 10K memories with 6 months of simulated events, measures total DB size, asserts < 500MB.

## Task Checklist

Check off tasks in `TEMPORAL-TASK-TRACKER.md` as you complete them: all `PTF-GOLD-*`, `PTF-TEST-*`, `TT-INT-*`, and `TT-FINAL-*` tasks.

## Quality Gate QG-T4 Must Pass

All of the above. This is the final gate. When QG-T4 passes, the temporal reasoning system is complete and ready for integration into the main development branch.
