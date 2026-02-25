# Phase D3 Prompt — Existing Crate Integration

You are implementing Phase D3 of the cortex temporal reasoning addition. Read these files first:

- `TEMPORAL-TASK-TRACKER.md` (Phase D3 section, tasks `PTD3-*` and tests `TTD3-*`)
- `TEMPORAL-IMPLEMENTATION-SPEC.md`
- `FILE-MAP.md`

**Prerequisite:** QG-T3b has passed — Phase D2's epistemic status model and materialized views are fully operational. All `TTD2-*` tests pass.

## What This Phase Builds

This phase integrates temporal reasoning into 3 existing crates. 0 new files, 7 modified files, 7 impl tasks, 12 tests. This is a pure integration phase — no new cortex-temporal code, only wiring temporal capabilities into existing subsystems.

### 1. cortex-retrieval: Temporal Scoring Factors (TR13, CR8)

**Modified files**: `src/ranking/scorer.rs`, `src/ranking/mod.rs`

Add 2 new additive scoring factors to the existing 8-factor scorer. Redistribute weights to maintain sum = 1.0:

```
Existing weights (redistributed):
    semantic_similarity:  0.22  (was 0.25)
    keyword_match:        0.13  (was 0.15)
    file_proximity:       0.10  (unchanged)
    pattern_alignment:    0.08  (was 0.10)
    recency:              0.10  (unchanged)
    confidence:           0.10  (unchanged)
    importance:           0.08  (was 0.10)
    intent_type_match:    0.08  (was 0.10)

New temporal weights:
    evidence_freshness:   0.06  (new — direct value from compute_evidence_freshness [0.0, 1.0])
    epistemic_status:     0.05  (new — Verified=1.0, Provisional=0.7, Conjecture=0.4, Stale=0.2)

Total: 1.00
```

- **All 10 weights must sum to exactly 1.0** — assert this in tests.
- **Verified memory must score higher than Conjecture** — same memory, different epistemic status, Verified wins.
- **Fresh evidence must rank above stale evidence** — same memory, different freshness, fresh wins.
- **CR8**: These are additive factors, NOT multiplicative. They add `weight × factor_value` to the total score, same as all existing factors.

### 2. cortex-validation: Epistemic Promotion (TR11)

**Modified files**: `src/engine.rs`, `src/dimensions/temporal.rs`

- After validation pass (all 4 dimensions pass): trigger epistemic promotion. If currently Conjecture → promote to Provisional. If Provisional + user confirmation → promote to Verified.
- **Validation failure does NOT demote** — epistemic status only degrades via evidence decay (Verified → Stale), never via validation failure. A Provisional memory that fails validation stays Provisional.
- Add temporal consistency check in `dimensions/temporal.rs`: referenced memories must have existed when the referencing memory was created. This is a new validation dimension check, not a separate validation pass.

### 3. cortex-observability: Drift in Health Reports (TR7)

**Modified files**: `src/health/reporter.rs`, `src/health/subsystem_checks.rs`, `src/health/recommendations.rs`

- `reporter.rs` — add `drift_summary: Option<DriftSummary>` to `HealthSnapshot`. `DriftSummary` contains: active_alerts count, overall_ksi, overall_efi, trend indicators (improving/stable/declining for each metric).
- `subsystem_checks.rs` — add `check_temporal(snapshot) -> SubsystemHealth`. Checks: event store health (events being recorded), snapshot freshness (snapshots not stale), drift alert count (not too many active alerts).
- `recommendations.rs` — add 3 temporal-specific recommendations:
  - "Run snapshot compaction" if events > threshold
  - "Review stale evidence" if EFI < 0.5
  - "Investigate knowledge churn" if KSI < 0.3

## Critical Implementation Details

- **No existing test regressions** — this is the highest risk phase because you're modifying 3 established crates. Run `cargo test -p cortex-retrieval`, `cargo test -p cortex-validation`, `cargo test -p cortex-observability` after each modification. All existing tests must continue to pass.
- **Weight redistribution must be backward-compatible** — the relative ordering of existing factors should be preserved. Semantic similarity is still the highest-weighted factor. The redistribution reduces each existing weight slightly to make room for the 2 new factors.
- **Epistemic promotion is automatic when `epistemic_auto_promote` is true** (default) — the validation engine checks this config flag before promoting.
- **DriftSummary is Optional** — if the temporal system hasn't been initialized yet (no drift snapshots exist), `drift_summary` is `None`. Health reports must handle this gracefully.
- **Temporal subsystem check is additive** — it's a new subsystem alongside existing checks (storage, embeddings, etc.). It doesn't replace or modify any existing subsystem check.

## Reference Crate Patterns

For scorer weight changes, look at the existing `ScorerWeights` struct in `cortex-retrieval/src/ranking/mod.rs` — add 2 new fields with defaults, update the `Default` impl.

For observability integration, look at how existing subsystem checks are structured in `cortex-observability/src/health/subsystem_checks.rs` — each check returns a `SubsystemHealth` with status + message. Follow the same pattern for `check_temporal`.

## Task Checklist

Check off tasks in `TEMPORAL-TASK-TRACKER.md` as you complete them: `PTD3-RET-01` through `PTD3-RET-02`, `PTD3-VALID-01` through `PTD3-VALID-02`, `PTD3-OBS-01` through `PTD3-OBS-03`, and all `TTD3-*` tests.

## Quality Gate QG-T3c Must Pass

- All `TTD3-*` tests pass
- `cargo test -p cortex-retrieval` — zero failures
- `cargo test -p cortex-validation` — zero failures
- `cargo test -p cortex-observability` — zero failures
- `cargo test --workspace` — zero regressions
