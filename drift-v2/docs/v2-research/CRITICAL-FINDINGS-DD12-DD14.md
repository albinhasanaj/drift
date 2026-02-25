# Critical Findings: DD-12, DD-13, DD-14 Audit

> Audited: 2025-02-10 | Scope: §13 Cortex, §14 Bridge, §15 Advanced
> Source of truth: actual source code vs claims in `CRITICAL-FLOW-MAP.md`

---

## Summary

| ID | Section | Errors Found | Confirmed Correct | Severity |
|----|---------|-------------|-------------------|----------|
| DD-12 | §13 Cortex | 6 | 5 | **2 P0, 2 P1, 2 P2** |
| DD-13 | §14 Bridge | 2 | 6 | **1 P0, 1 P2** |
| DD-14 | §15 Advanced | 3 | 5 | **1 P1, 2 P2** |
| **Total** | | **11 errors** | **16 confirmed** | **2 P0, 3 P1, 4 P2** |

---

## DD-12: §13 Cortex Memory System

### DD-12-E1 [P0] — Crate count is wrong: 21 cortex-* crates, not 20

**Doc claims (line 61, 696):** "21 crates (20 cortex-* crates + test-fixtures)"

**Actual (Cargo.toml lines 3-26):** 22 workspace members = **21 cortex-\* crates** + test-fixtures:

```
cortex-core, cortex-tokens, cortex-storage, cortex-embeddings, cortex-privacy,
cortex-compression, cortex-decay, cortex-causal, cortex-retrieval, cortex-validation,
cortex-learning, cortex-consolidation, cortex-prediction, cortex-session,
cortex-reclassification, cortex-observability, cortex-cloud, cortex-temporal,
cortex-napi, cortex-crdt, cortex-multiagent
```

That's 21 cortex-* crates, not 20. The doc's math is off by 1.

**Fix:** Change "21 crates (20 cortex-* crates + test-fixtures)" → "22 workspace members (21 cortex-* crates + test-fixtures)"

---

### DD-12-E2 [P0] — CortexRuntime struct has 2 phantom engines + 1 missing engine

**Doc claims (lines 700-716):** CortexRuntime contains 16 engines including `RetrievalEngine`, `GenerationEngine`, and `SessionEngine`.

**Actual (`cortex-napi/src/runtime.rs` lines 36-53):**

```rust
pub struct CortexRuntime {
    pub storage: Arc<StorageEngine>,          // ✓
    pub embeddings: Mutex<EmbeddingEngine>,   // ✓
    pub compression: CompressionEngine,       // ← NOT LISTED IN DOC
    pub causal: CausalEngine,                 // ✓
    pub decay: DecayEngine,                   // ✓
    pub validation: ValidationEngine,         // ✓
    pub learning: Mutex<LearningEngine>,      // ✓
    pub consolidation: Mutex<ConsolidationEngine>, // ✓
    pub prediction: PredictionEngine<Arc<StorageEngine>>, // ✓
    pub session: SessionManager,              // ← Doc says "SessionEngine"
    pub privacy: PrivacyEngine,               // ✓
    pub observability: Mutex<ObservabilityEngine>, // ✓
    pub cloud: Option<Mutex<CloudEngine>>,    // ← Doc omits Option<>
    pub temporal: TemporalEngine,             // ✓
    pub multiagent: Mutex<MultiAgentEngine>,  // ✓
    pub config: CortexConfig,                 // ← Not an engine, not listed
}
```

| Engine in Doc | In Struct? | Issue |
|---------------|-----------|-------|
| RetrievalEngine | **NO** | Not a field. Created on-the-fly in `retrieval.rs` NAPI via `RetrievalEngine::new(&rt.storage, &rt.compression, ...)` |
| GenerationEngine | **NO** | Not a field. `generation.rs` NAPI creates `RetrievalEngine` inline |
| SessionEngine | **WRONG NAME** | Actual type is `SessionManager`, not `SessionEngine` |
| CompressionEngine | **MISSING FROM DOC** | IS a field (`compression: CompressionEngine`) but not listed |
| CloudEngine | **INCOMPLETE** | Is `Option<Mutex<CloudEngine>>`, doc doesn't mention it's optional |

**Fix:** Remove RetrievalEngine and GenerationEngine from the diagram. Add CompressionEngine. Fix SessionEngine → SessionManager. Note CloudEngine is Optional. The runtime has **15 fields** (14 engines/managers + config), not 16 engines.

---

### DD-12-E3 [P1] — NAPI module description table has inaccuracies

**Doc claims (lines 629-649):** Cortex NAPI has 68 functions across 17 modules.

**Actual count by `#[napi]` annotation per module:**

| Module | Doc Description | Actual #[napi] Count | Doc Implied Count | Match? |
|--------|----------------|---------------------|-------------------|--------|
| lifecycle.rs | configure, shutdown, isInitialized | 3 | 3 | ✓ |
| memory.rs | create, get, update, delete, search, list, bulkInsert | **9** (create, get, update, delete, search, list, archive, restore) | 7 | **✗** (doc says bulkInsert, actual has archive+restore instead; no bulkInsert) |
| causal.rs | addEdge, getGraph, infer | **5** (infer_cause, traverse, get_why, counterfactual, intervention) | 3 | **✗** |
| cloud.rs | sync, resolveConflict, getStatus | 3 | 3 | ✓ |
| consolidation.rs | run, getStats | **3** (consolidate, get_metrics, get_status) | 2 | **✗** |
| decay.rs | run, getSchedule, preview | **1** (run only) | 3 | **✗** |
| embeddings.rs | embed, reembed, search | **1** (reembed only) | 3 | **✗** |
| generation.rs | summarize, generateInsights | **2** (build_context, track_outcome) | 2 | ✓ count, **✗** names |
| health.rs | getSnapshot, getDashboard | **3** (get_health, get_metrics, get_degradations) | 2 | **✗** |
| learning.rs | recordInteraction, getPatterns | **4** (analyze_correction, learn, get_validation_candidates, process_feedback) | 2 | **✗** |
| multiagent.rs | register, deregister, sync, namespace, permissions, trust, projections, provenance, deltaQueue | **12** (register, deregister, get, list, create_namespace, share_memory, create_projection, retract, get_provenance, trace_cross_agent, get_trust, sync_agents) | 9 | **✗** |
| prediction.rs | predict, getAccuracy | **3** (predict, preload, get_cache_stats) | 2 | **✗** |
| privacy.rs | sanitize, getReport | **2** (sanitize, get_pattern_stats) | 2 | ✓ count, **✗** names |
| retrieval.rs | retrieve, getRelevant | **3** (retrieve, search, get_context) | 2 | **✗** |
| session.rs | create, end, getAnalytics | **4** (create, get, cleanup, analytics) | 3 | **✗** |
| temporal.rs | getTimeline, getDiff, getAlerts, timeTravel, getCausal, getViews | **10** (query_as_of, query_range, query_diff, replay_decision, query_temporal_causal, get_drift_metrics, get_drift_alerts, create_materialized_view, get_materialized_view, list_materialized_views) | 6 | **✗** |
| validation.rs | run (4-dimension validation) | 1 | 1 | ✓ |

**Actual total: 69 `#[napi]` functions** (3+9+5+3+3+1+1+2+3+4+12+3+2+3+4+10+1)

**Doc claims 68.** Off by 1. But more importantly, **the per-module function names/counts in the table are mostly wrong** — only 4 of 17 modules have correct counts.

---

### DD-12-E4 [P1] — Doc says "17 modules" but lists 17 correctly

**Actual (`bindings/mod.rs`):** 17 `pub mod` declarations. **Confirmed correct.**

However, the doc at line 42 says "17 modules" — this matches.

---

### DD-12-E5 [P2] — Lifecycle: init/shutdown verified correct

**Doc description:** OnceLock singleton, initialize(), get(), is_initialized().

**Actual (`runtime.rs` lines 30, 187-207):**
- `static RUNTIME: OnceLock<Arc<CortexRuntime>>` ✓
- `pub fn initialize(opts: RuntimeOptions) -> napi::Result<()>` ✓
- `pub fn get() -> napi::Result<Arc<CortexRuntime>>` ✓
- `pub fn is_initialized() -> bool` ✓

**Confirmed correct.**

---

### DD-12-E6 [P2] — Missing "no shutdown function" note

The doc describes a shutdown lifecycle but `runtime.rs` has **no `shutdown()` function** at the global singleton level. `cortex_shutdown()` in `lifecycle.rs` calls `rt.storage.pool().checkpoint()` but does NOT drop the runtime or reset the OnceLock. The runtime persists until process exit.

This is likely intentional (OnceLock cannot be reset), but the doc should note this.

---

### DD-12 Confirmed Correct

| Claim | Status |
|-------|--------|
| OnceLock singleton pattern | ✓ Confirmed |
| EmbeddingEngine 3-tier cache (L1→L2→L3) | ✓ Confirmed (runtime.rs:84-87 uses new_with_db_path for file-backed) |
| ConsolidationEngine episodic + procedural | ✓ Confirmed (runtime.rs:110-112) |
| Multi-agent RBAC, namespaces, trust, delta queue | ✓ Confirmed (12 NAPI functions) |
| Temporal bitemporal storage | ✓ Confirmed (10 NAPI functions, query_as_of with system_time+valid_time) |

---

## DD-13: §14 Cortex-Drift Bridge

### DD-13-E1 [P0] — Evidence type names are completely wrong

**Doc claims (line 762):** 10 evidence types:
> pattern_confidence, occurrence_rate, temporal_stability, cross_validation, file_coverage, detection_method_agreement, outlier_status, convention_alignment, enforcement_status, community_signal

**Actual (`grounding/evidence/types.rs` lines 7-28):**

```rust
pub enum EvidenceType {
    PatternConfidence,      // ← Doc: "pattern_confidence" ≈ match
    PatternOccurrence,      // ← Doc: "occurrence_rate" ≈ match
    FalsePositiveRate,      // ← Doc says "temporal_stability" — WRONG
    ConstraintVerification, // ← Doc says "cross_validation" — WRONG
    CouplingMetric,         // ← Doc says "file_coverage" — WRONG
    DnaHealth,              // ← Doc says "detection_method_agreement" — WRONG
    TestCoverage,           // ← Doc says "outlier_status" — WRONG
    ErrorHandlingGaps,      // ← Doc says "convention_alignment" — WRONG
    DecisionEvidence,       // ← Doc says "enforcement_status" — WRONG
    BoundaryData,           // ← Doc says "community_signal" — WRONG
}
```

**Only 2 of 10 names approximately match.** The remaining 8 are entirely fabricated names that do not exist anywhere in the codebase. This is a **P0 factual error** — anyone relying on this list for audit/implementation would be working with phantom concepts.

**Fix:** Replace the entire list with the actual enum variants.

---

### DD-13-E2 [P2] — Bridge doc says "15 subsystems" but lib.rs module list has 15 + lib.rs claims are correct

**Actual (`src/` directory listing):** 15 subdirectories matching the doc exactly:
causal, config, errors, event_mapping, grounding, health, intents, license, link_translation, napi, query, specification, storage, tools, types

**Confirmed correct.** The lib.rs module doc comments at lines 7-21 also match.

---

### DD-13 Confirmed Correct

| Claim | Status |
|-------|--------|
| 15 subsystem paths | ✓ Confirmed (all 15 directories exist) |
| 20 NAPI-ready functions | ✓ Confirmed (functions.rs has exactly 20 numbered functions) |
| 6 MCP tool handlers | ✓ Confirmed (tools/mod.rs: drift_why, drift_memory_learn, drift_grounding_check, drift_counterfactual, drift_intervention, drift_health) |
| Grounding pipeline: GroundingLoopRunner → ground_single/run | ✓ Confirmed (functions.rs:38, 52) |
| BridgeRuntime with drift_db, cortex_db, bridge_db | ✓ Confirmed (lib.rs:49-55) |
| Evidence has 10 types | ✓ Count correct, **names wrong** (DD-13-E1) |

---

## DD-14: §15 Advanced Systems

### DD-14-E1 [P1] — Decision mining: doc says "500 commits" but default is 1000

**Doc claims (line 781):** "Parses git log (up to 500 commits)"

**Actual:**
- `GitAnalyzer::new()` default: `max_commits: 1000` (`git_analysis.rs` line 20)
- `drift_decisions()` NAPI: `GitAnalyzer::new().with_max_commits(500)` (`advanced.rs` line 69)

The default struct is 1000. The NAPI binding overrides to 500. The doc is **technically correct for the NAPI call path** but misleading — it describes this as the GitAnalyzer behavior, not the NAPI override. Anyone calling `GitAnalyzer::new()` directly would get 1000.

**Fix:** Clarify: "NAPI binding limits to 500 commits (default 1000)".

---

### DD-14-E2 [P2] — Decision mining: doc says "GitAnalyzer" flow name is correct but category count is wrong

**Doc claims (line 780-782):** Describes `GitAnalyzer::analyze(path)` flow.

**Actual:** The doc doesn't mention the category count, but the code says **12 decision categories** (`decisions/mod.rs` line 3, `types.rs` line 5):
Architecture, Technology, Pattern, Convention, Security, Performance, Testing, Deployment, DataModel, ApiDesign, ErrorHandling, Documentation

This is 12, not mentioned in the doc's §15. The §15 description is sparse — it only shows the API shape, not the internal detail. **Not wrong, but incomplete.**

---

### DD-14-E3 [P2] — Context engine: doc says "ContextEngine::generate(intent, depth, analysis_data)" — correct but location is misleading

**Doc claims (lines 786-791):** Shows `ContextEngine` in the "Advanced Systems" flow.

**Actual:** `ContextEngine` is in `drift-context` crate (`drift-context/src/generation/builder.rs`), NOT in `drift-analysis/src/advanced/`. The doc groups it under "Advanced Systems" but the actual code is in a separate crate. The NAPI binding in `advanced.rs` imports from `drift_context::generation::builder::*`, confirming the cross-crate dependency.

**Not a factual error in the flow description, but architecturally misleading** — suggests context generation lives alongside simulation/decisions when it's a separate crate.

---

### DD-14 Confirmed Correct

| Claim | Status |
|-------|--------|
| 13 task categories (simulation) | ✓ Confirmed exactly (types.rs: AddFeature through Infrastructure) |
| Monte Carlo confidence intervals | ✓ Confirmed (monte_carlo.rs: P10/P50/P90) |
| StrategyRecommender::recommend(task) | ✓ Confirmed (advanced.rs:57-58) |
| 5 intents: FixBug, AddFeature, UnderstandCode, SecurityAudit, GenerateSpec | ✓ Confirmed exactly (intent.rs:9-15) |
| 3 depths: Overview, Standard, Deep | ✓ Confirmed exactly (builder.rs:16-22) |
| SpecificationRenderer::render(module, migration) | ✓ Confirmed (renderer.rs:34-60, 11 sections) |
| Token-counted sectioned output | ✓ Confirmed (renderer.rs:52-53) |
| source→target language/framework | ✓ Confirmed (advanced.rs:144-149, MigrationPath) |

---

## Corrections Required in CRITICAL-FLOW-MAP.md

### Must-Fix (P0)

| ID | Line(s) | Current | Should Be |
|----|---------|---------|-----------|
| DD-12-E1 | 61, 696 | "21 crates (20 cortex-* crates + test-fixtures)" | "22 workspace members (21 cortex-* crates + test-fixtures)" |
| DD-12-E2 | 700-716 | Lists RetrievalEngine, GenerationEngine, SessionEngine | Remove RetrievalEngine & GenerationEngine (not runtime fields). Add CompressionEngine. Fix SessionEngine → SessionManager. Note CloudEngine is Optional. |
| DD-13-E1 | 762 | 8 of 10 evidence type names are fabricated | Replace with actual: PatternConfidence, PatternOccurrence, FalsePositiveRate, ConstraintVerification, CouplingMetric, DnaHealth, TestCoverage, ErrorHandlingGaps, DecisionEvidence, BoundaryData |

### Should-Fix (P1)

| ID | Line(s) | Current | Should Be |
|----|---------|---------|-----------|
| DD-12-E3 | 629-649 | Per-module function names/counts mostly wrong | Update table with actual function names (see detailed breakdown above) |
| DD-14-E1 | 781 | "up to 500 commits" | "NAPI limits to 500 commits (GitAnalyzer default: 1000)" |

### Nice-to-Fix (P2)

| ID | Line(s) | Current | Should Be |
|----|---------|---------|-----------|
| DD-12-E6 | - | No mention of shutdown limitation | Note: OnceLock cannot be reset; `cortex_shutdown()` checkpoints WAL but doesn't drop runtime |
| DD-14-E2 | 780-782 | No category count mentioned | Note: 12 decision categories |
| DD-14-E3 | 786-791 | Context engine shown under "Advanced" | Note: ContextEngine lives in drift-context crate, not drift-analysis/advanced |
| DD-12-E3 (count) | 629 | "68 functions" | Actual count: 69 `#[napi]` functions |

---

## Appendix: Full Cortex NAPI Function Inventory (69 functions)

| Module | Count | Functions |
|--------|-------|-----------|
| lifecycle | 3 | cortex_initialize, cortex_shutdown, cortex_configure |
| memory | 9 | cortex_memory_create, _get, _update, _delete, _search, _list, _archive, _restore + (update includes re-embed) |
| causal | 5 | cortex_causal_infer_cause, _traverse, _get_why, _counterfactual, _intervention |
| cloud | 3 | cortex_cloud_sync, _get_status, _resolve_conflict |
| consolidation | 3 | cortex_consolidation_consolidate, _get_metrics, _get_status |
| decay | 1 | cortex_decay_run |
| embeddings | 1 | cortex_reembed |
| generation | 2 | cortex_generation_build_context, _track_outcome |
| health | 3 | cortex_health_get_health, _get_metrics, _get_degradations |
| learning | 4 | cortex_learning_analyze_correction, _learn, _get_validation_candidates, _process_feedback |
| multiagent | 12 | cortex_multiagent_register_agent, _deregister_agent, _get_agent, _list_agents, _create_namespace, _share_memory, _create_projection, _retract_memory, _get_provenance, _trace_cross_agent, _get_trust, _sync_agents |
| prediction | 3 | cortex_prediction_predict, _preload, _get_cache_stats |
| privacy | 2 | cortex_privacy_sanitize, _get_pattern_stats |
| retrieval | 3 | cortex_retrieval_retrieve, _search, _get_context |
| session | 4 | cortex_session_create, _get, _cleanup, _analytics |
| temporal | 10 | cortex_temporal_query_as_of, _query_range, _query_diff, _replay_decision, _query_temporal_causal, _get_drift_metrics, _get_drift_alerts, _create_materialized_view, _get_materialized_view, _list_materialized_views |
| validation | 1 | cortex_validation_run |
| **Total** | **69** | |
