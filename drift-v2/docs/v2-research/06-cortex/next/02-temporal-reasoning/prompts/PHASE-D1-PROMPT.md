# Phase D1 Prompt — Drift Metrics + Alerting

You are implementing Phase D1 of the cortex temporal reasoning addition. Read these files first:

- `TEMPORAL-TASK-TRACKER.md` (Phase D1 section, tasks `PTD1-*` and tests `TTD1-*`)
- `TEMPORAL-IMPLEMENTATION-SPEC.md`
- `FILE-MAP.md`

**Prerequisite:** QG-T2 has passed — Phase C's decision replay and temporal causal graph reconstruction are fully operational. All `TTC-*` tests pass, `cargo test --workspace` is green, and coverage ≥80% on all Phase C modules.

## What This Phase Builds

This phase adds the drift detection engine: 5 metrics, alerting with dampening, time-series storage, and evolution pattern detection. 12 impl tasks, 21 tests. Specifically:

1. **cortex-core**: 2 new model files + modify `models/mod.rs`:
   - `drift_snapshot.rs` — `DriftSnapshot` struct (timestamp, window, type_metrics, module_metrics, global), `TypeDriftMetrics` (count, avg_confidence, ksi, contradiction_density, consolidation_efficiency, evidence_freshness_index), `ModuleDriftMetrics` (memory_count, coverage_ratio, avg_confidence, churn_rate), `GlobalDriftMetrics` (total/active/archived memories, avg_confidence, overall_ksi, overall_contradiction_density, overall_evidence_freshness)
   - `drift_alert.rs` — `DriftAlert` struct (severity, category, message, affected_memories, recommended_action, detected_at), `AlertSeverity` enum (Info/Warning/Critical), `DriftAlertCategory` enum (6 variants: KnowledgeChurn, ConfidenceErosion, ContradictionSpike, StaleEvidence, KnowledgeExplosion, CoverageGap)
2. **cortex-storage**: 1 new query module (`drift_ops.rs`) + modify `queries/mod.rs` — raw SQL: `insert_drift_snapshot`, `get_drift_snapshots(from, to)`, `get_latest_drift_snapshot`
3. **cortex-temporal drift module** (6 new files):
   - `drift/mod.rs` — module declarations + re-exports
   - `drift/metrics.rs` — 5 drift metrics:
     - **KSI** (Knowledge Stability Index): `1.0 - (created + archived + modified) / (2 * total_at_start)`, clamped [0.0, 1.0]. KSI=1.0 means perfectly stable. Per-type KSI is critical — episodic KSI is naturally low, core KSI should be high.
     - **Confidence Trajectory**: sample avg confidence at N points across window, returns `Vec<f64>`. Rising = validated, falling = decaying, flat = stagnant.
     - **Contradiction Density**: `new_contradictions / total_memories`. < 0.02 healthy, > 0.10 needs attention.
     - **Consolidation Efficiency**: `semantic_created / episodic_archived`. > 0.5 good, < 0.2 poor.
     - **`compute_all_metrics()`** assembles a full `DriftSnapshot`.
   - `drift/evidence_freshness.rs` — per-evidence-type freshness factors:
     - File link: content_hash match → 1.0, mismatch → 0.5
     - Pattern link: active → 1.0, inactive → 0.3
     - Supporting memory: that memory's confidence value
     - User validation: exponential decay with half-life 90 days: `exp(-days/90 * 0.693)`
     - Aggregation: product of all factors (Π). Empty evidence → 1.0.
     - `compute_evidence_freshness_index()` = average freshness across all active memories.
   - `drift/alerting.rs` — `evaluate_drift_alerts(snapshot, config, recent_alerts)`:
     - 6 alert categories with configurable thresholds from `TemporalConfig`
     - KSI thresholds vary by type: Core/Tribal use `alert_ksi_threshold` (0.3), Semantic uses 0.5, episodic types use 0.2
     - Confidence erosion: fires after `alert_confidence_erosion_windows` (2) consecutive declining windows
     - Contradiction spike: fires when density > `alert_contradiction_density_threshold` (0.10) — severity Critical
     - Stale evidence: fires for high-importance memories when freshness < `alert_evidence_freshness_threshold` (0.5)
     - Knowledge explosion: fires when creation rate > baseline + `alert_explosion_sigma` (3.0) × stddev
     - **Alert dampening**: cooldown per category + affected entity dedup. Warning cooldown: 24h. Critical cooldown: 1h. Check `recent_alerts` before firing.
   - `drift/snapshots.rs` — `store_drift_snapshot()`, `get_drift_snapshots()`, `get_latest_drift_snapshot()`. Snapshot frequency: hourly (lightweight counters), daily (full metrics), weekly (comprehensive with trends).
   - `drift/patterns.rs` — 4 evolution pattern detectors:
     - `detect_crystallization()` — tracks lifecycle: episodic → semantic → validated → stable confidence. Returns time-to-crystallization and current stage.
     - `detect_erosion()` — confidence trajectory negative for 2+ consecutive windows, citations going stale. Returns affected memories + recommended action.
     - `detect_explosion()` — memory creation rate > 3σ above rolling average. Returns rate, baseline, recommendation to trigger consolidation.
     - `detect_conflict_wave()` — contradiction density spikes > 2× baseline, concentrated in specific area. Returns hotspot + recommendation for targeted validation.
4. **cortex-temporal engine update**: implement `compute_drift_metrics` and `get_drift_alerts` methods on `TemporalEngine` (previously returned not-yet-implemented error)

## Critical Implementation Details

- **KSI = 1.0 for a stable dataset** — if nothing changed in the window, KSI must be exactly 1.0. If `total_at_start == 0`, return 1.0 (no memories = perfectly stable).
- **KSI per type is independent** — changing only episodic memories must NOT affect core KSI.
- **KSI bounds are [0.0, 1.0]** — use `.clamp(0.0, 1.0)` after computation.
- **Evidence freshness bounds are [0.0, 1.0]** — product aggregation naturally stays in bounds when all factors are in [0.0, 1.0], but clamp defensively.
- **Evidence freshness = 1.0 when no evidence exists** — empty factors list returns 1.0 (assume fresh).
- **Alert dampening is critical** — without it, the same alert fires every computation cycle. The `recent_alerts` parameter carries previously fired alerts. Check category + affected entity + timestamp against cooldown window.
- **Critical alerts have shorter cooldown** (1h vs 24h for warnings) — this is intentional. Critical issues need faster re-notification.
- **Drift snapshot round-trip must be lossless** — store as JSON via `serde_json::to_string`, retrieve and deserialize, must equal original.
- **Pattern detection returns `Option`** — `None` means the pattern was not detected. Each pattern returns a detection result struct + recommended action string.

## Reference Crate Patterns

For the metrics module, look at how `cortex-decay/src/formula.rs` computes decay factors — similar mathematical computation with bounds checking. For alerting, look at how `cortex-validation/src/engine.rs` evaluates dimension scores and produces results — similar threshold-based evaluation with multiple categories.

For drift snapshots storage, follow the exact same pattern as `cortex-storage/src/queries/audit_ops.rs` — raw SQL insert/query with JSON serialization.

## Task Checklist

Check off tasks in `TEMPORAL-TASK-TRACKER.md` as you complete them: `PTD1-CORE-01` through `PTD1-CORE-03`, `PTD1-STOR-01` through `PTD1-STOR-02`, `PTD1-TEMP-01` through `PTD1-TEMP-07`, and all `TTD1-*` tests.

## Quality Gate QG-T3a Must Pass

- All `TTD1-*` tests pass
- Coverage ≥80% for cortex-temporal drift/metrics.rs
- Coverage ≥80% for cortex-temporal drift/evidence_freshness.rs
- Coverage ≥80% for cortex-temporal drift/alerting.rs
- Coverage ≥80% for cortex-temporal drift/snapshots.rs
- Coverage ≥80% for cortex-temporal drift/patterns.rs
- Benchmark baselines established: KSI computation 10K memories < 100ms, full drift metrics 10K memories < 500ms, evidence freshness single memory < 1ms, alert evaluation (100 metrics) < 10ms
