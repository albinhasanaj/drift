# Cortex Stubs, Mocks, TODOs & Deferred Work — Complete Audit

> Generated: 2026-02-10
> Scope: All Cortex Rust crates (`crates/cortex/`), cortex-drift-bridge (`crates/cortex-drift-bridge/`), TS packages (`packages/cortex/`, `packages/drift-mcp/`)
> Method: Full-text search for TODO/FIXME/HACK/stub/mock/placeholder/phase 2/unimplemented/todo!/not yet + manual line-by-line review of every orchestrator, pipeline, NAPI binding, engine, and TS bridge function
> False-positive elimination: Every finding verified upstream + downstream to confirm real gap vs intentional design

---

## Executive Summary

The Cortex codebase is **substantially complete**. Zero `todo!()` or `unimplemented!()` macros exist. Zero hardcoded NAPI stubs remain (all 68 bindings across 17 modules call real engine code). The 6-phase consolidation pipeline, 2-stage retrieval pipeline, temporal engine, causal engine, learning engine, and validation engine are all fully wired.

**15 real findings** across 3 severity levels:
- **P1 (7):** Real stubs or unimplemented features that affect functionality
- **P2 (5):** Design-intentional gaps or incomplete wiring that reduce quality
- **P3 (3):** Dead code / unused fields behind `#[allow(dead_code)]`

**17 false positives eliminated** — items that look like stubs but are correct by design (privacy replacement placeholders, test mocks, migration scaffolds, intentional no-ops, etc.)

---

## Orchestrators Inventory

All orchestrators verified complete:

| Orchestrator | Location | Status |
|---|---|---|
| **CortexRuntime** | `cortex-napi/src/runtime.rs` | Complete — 15 engines wired, OnceLock singleton |
| **ConsolidationEngine** | `cortex-consolidation/src/engine.rs` | Complete — 6-phase pipeline, storage persistence, auto-tuning |
| **Consolidation Pipeline** | `cortex-consolidation/src/pipeline/mod.rs` | Complete — all 6 phases (selection→clustering→recall→abstraction→integration→pruning) |
| **RetrievalEngine** | `cortex-retrieval/src/engine.rs` | Complete — 2-stage pipeline (hybrid search→rank→compress) |
| **GenerationOrchestrator** | `cortex-retrieval/src/generation/mod.rs` | Complete — validation→context→provenance→feedback |
| **CloudEngine** | `cortex-cloud/src/engine.rs` | Complete for API key auth — quota→auth→replay→push/pull→conflict |
| **SyncManager** | `cortex-cloud/src/sync/mod.rs` | Complete — push→pull→delta→conflict resolution |
| **MultiAgentEngine** | `cortex-multiagent/src/engine.rs` | **Partial** — detect_consensus is stub (see F-03) |
| **DeltaSyncEngine** | `cortex-multiagent/src/sync/protocol.rs` | **Partial** — acknowledge_sync is no-op (see F-04) |
| **CrossNamespaceConsolidator** | `cortex-multiagent/src/consolidation/cross_namespace.rs` | Complete — gathers→consensus→archive |
| **ObservabilityEngine** | `cortex-observability/src/engine.rs` | Complete — health→metrics→degradation→query_log |
| **TemporalEngine** | `cortex-temporal/src/engine.rs` | Complete — as_of→range→diff→replay→causal→drift→views |
| **LearningEngine** | `cortex-learning/src/engine.rs` | Complete — analyze→dedup→categorize→extract→persist |
| **ValidationEngine** | `cortex-validation/src/engine.rs` | Complete — 4-dimension validation |
| **AutoRefreshScheduler** | `cortex-temporal/src/views/auto_refresh.rs` | Complete — interval→change detection→label generation |

---

## Findings

### P1 — Real Stubs / Not Yet Implemented

#### F-01: OAuth authentication flow not implemented
- **File:** `cortex-cloud/src/auth/login_flow.rs:43-57, 62-74`
- **What:** `authenticate()` and `refresh()` both return `CloudError::AuthFailed` for the `AuthMethod::OAuth` variant with messages "OAuth flow not yet implemented" and "OAuth token refresh not yet implemented"
- **Upstream:** `CloudEngine.connect()` → `AuthManager.login()` → `LoginFlow.authenticate()`
- **Downstream:** Any consumer enabling cloud with OAuth config gets immediate auth failure
- **Impact:** Cloud sync limited to API key auth only. Browser-based OAuth (client_id, auth_url, token_url) is structurally defined but non-functional.

#### F-02: Cloud sync for remote agents not implemented
- **File:** `cortex-multiagent/src/sync/cloud_integration.rs:33-43`
- **What:** `CloudSyncAdapter::sync_via_cloud()` returns `MultiAgentError::SyncFailed("cloud sync not yet available")`
- **Comment:** "Currently returns an error as cloud sync requires the full cortex-cloud integration (Phase D)"
- **Upstream:** `detect_sync_mode()` routes to Cloud when target agent isn't in local registry
- **Downstream:** Multi-agent sync between separate Cortex instances always fails
- **Impact:** Multi-agent sync works only for agents in the same SQLite DB (local transport)

#### F-03: `detect_consensus` is a Phase D stub
- **File:** `cortex-multiagent/src/engine.rs:185-202`
- **What:** `IMultiAgentEngine::detect_consensus()` returns `Ok(Vec::new())` unconditionally
- **Comment:** "Phase D stub" — "the full pipeline requires an embedding engine which is injected at a higher level"
- **Upstream:** The actual `ConsensusDetector` exists and works in `cortex-multiagent/src/consolidation/consensus.rs`
- **Downstream:** NAPI consumers calling via the trait always get empty results
- **Impact:** Consensus detection capability exists but is unreachable from the engine's trait implementation. Needs embedding provider injection.

#### F-04: `acknowledge_sync` doesn't persist peer clock
- **File:** `cortex-multiagent/src/sync/protocol.rs:220-232`
- **What:** `DeltaSyncEngine::acknowledge_sync()` only logs and returns `Ok(())`
- **Comment:** "In a full implementation, this would persist the peer's clock for future delta computation. For now, the ack is logged."
- **Impact:** After each sync round, the peer's vector clock state is lost. Next sync may re-send already-applied deltas.

#### F-05: Namespace filtering in temporal diff is a no-op
- **File:** `cortex-temporal/src/query/diff.rs:501-504`
- **What:** `DiffScope::Namespace(_ns)` match arm passes all results through unfiltered
- **Comment:** "Namespace filtering is for multi-agent support (Phase D+)"
- **Upstream:** `cortex_temporal_query_diff` NAPI binding passes scope from caller
- **Impact:** Multi-agent temporal diffs don't filter by namespace — all namespaces mixed together

#### F-06: Health contradiction counts hardcoded to 0
- **File:** `cortex-napi/src/bindings/health.rs:88-89`
- **What:** `contradiction_count: 0` and `unresolved_contradictions: 0` in `HealthSnapshot`
- **Comment:** "Real contradiction detection requires validation engine"
- **Upstream:** ValidationEngine exists and CAN detect contradictions via `validate_basic()`
- **Impact:** Health reports always show 0 contradictions regardless of actual memory state. Causal subsystem health check (which thresholds on `unresolved_contradictions > 10`) can never trigger.

#### F-07: Privacy health check is hardcoded healthy
- **File:** `cortex-observability/src/health/subsystem_checks.rs:94-101`
- **What:** `check_privacy()` always returns `HealthStatus::Healthy`
- **Comment:** "placeholder for PII scan results"
- **Impact:** No degradation alerts for privacy engine failures or high false-positive rates

---

### P2 — Design-Intentional Gaps (Reduced Quality)

#### F-08: `cortex_health_get_metrics` returns incomplete metrics
- **File:** `cortex-napi/src/bindings/health.rs:109-116`
- **What:** Builds JSON manually with only `session_count` and `causal_stats`, ignoring the full `MetricsCollector` which tracks retrieval, consolidation, storage, embedding, and session metrics
- **Comment:** "MetricsCollector doesn't derive Serialize, so we build JSON manually"
- **Fact check:** `MetricsCollector` now derives `Serialize` (fixed in Phase F: `cortex-observability/src/metrics/mod.rs:19`)
- **Impact:** 5 of 6 metric domains not exposed to NAPI consumers

#### F-09: Embedding cache hit rate is a binary heuristic
- **File:** `cortex-napi/src/bindings/health.rs:55-63`
- **What:** `if emb.active_provider() == "tfidf" { 0.0 } else { 1.0 }` — not real cache statistics
- **Upstream:** L2SqliteCache has real hit/miss tracking
- **Impact:** Health report shows 0% or 100% cache hit rate, never intermediate values

#### F-10: ONNX `embed_batch` is sequential
- **File:** `cortex-embeddings/src/providers/onnx_provider.rs:192-194`
- **What:** Batch embedding calls `infer()` in a loop instead of batched tensor inference
- **Comment:** "Sequential inference — batch padding optimization is future work"
- **Impact:** Linear slowdown for batch embeddings. Functionally correct but O(n) instead of O(1) for GPU batching.

#### F-11: No real LLM polisher for consolidation
- **File:** `cortex-consolidation/src/llm_polish.rs:64-71`
- **What:** `NoOpPolisher` is the only `LlmPolisher` implementation. Trait exists but no concrete LLM-backed impl.
- **Upstream:** `ConsolidationEngine` doesn't accept an LlmPolisher — pipeline uses rule-based abstraction only
- **Impact:** Consolidated summaries are mechanical concatenations, never LLM-refined

#### F-12: No real LLM extractor for learning
- **File:** `cortex-learning/src/extraction/llm_enhanced.rs:11-18`
- **What:** `NoOpExtractor` is the only `LlmExtractor` implementation. Trait exists but no concrete impl.
- **Upstream:** `LearningEngine::new()` and `with_storage()` both hardcode `NoOpExtractor`
- **Impact:** Principle extraction from corrections is rule-based only (regex/keyword matching)

---

### P3 — Dead Code / Unused Fields

#### F-13: MultiAgentEngine `readers` and `config` unused
- **File:** `cortex-multiagent/src/engine.rs:25-28`
- **What:** Both fields annotated `#[allow(dead_code)]`. All operations route through `writer`.
- **Impact:** `readers` ReadPool never used for read operations (potential perf gap for read-heavy multi-agent queries). `config` never consulted at runtime.

#### F-14: TemporalEngine `config` unused
- **File:** `cortex-temporal/src/engine.rs:29-30`
- **What:** `#[allow(dead_code)]` on `config: TemporalConfig`
- **Impact:** Temporal config parameters (e.g., `materialized_view_auto_interval_days`) stored but potentially not wired to all code paths

#### F-15: TrustScorer `config` unused
- **File:** `cortex-multiagent/src/trust/scorer.rs:29-30`
- **What:** `#[allow(dead_code)]` on `config: MultiAgentConfig`
- **Impact:** Trust scoring thresholds from config potentially not applied

---

## Verified False Positives (NOT Issues)

| Pattern | Location | Why it's NOT a problem |
|---|---|---|
| `[AWS_KEY]`, `[JWT]`, etc. | `cortex-privacy/src/patterns/secrets.rs` | Sanitization replacement strings — this IS the feature |
| `setup_mock_drift_db()` | Bridge test files | Standard test infrastructure |
| `createStubNativeModule()` | `packages/cortex/src/bridge/stub.ts` | Intentional fallback when native binary unavailable |
| `createStubNapi()` | `packages/drift-mcp/tests/` | Test infrastructure from `@drift/napi-contracts` |
| `placeholder_memory()` | `cortex-drift-bridge/src/specification/events.rs` | Creates minimal BaseMemory for causal edges — correct |
| `v013_placeholder.rs` | `cortex-storage/src/migrations/` | Intentional no-op to close v012→v014 numbering gap (fixed F-04) |
| "Future migrations go here" | `cortex-drift-bridge/src/storage/migrations.rs:87-92` | Normal migration scaffold pattern |
| `NoOp` in `causal/sync.rs` | Comment says "Previously was a no-op stub" | Already fixed (C-03) |
| `V1IdentityUpcaster` | `cortex-temporal/src/event_store/upcaster.rs` | By-design no-op for initial schema version |
| "deferred" in consolidation | `pipeline/phase2_clustering.rs`, `phase3_recall_gate.rs` | Refers to clusters deferred by recall gate — correct behavior |
| `"hack"` in categorizer | `cortex-learning/src/analysis/categorizer.rs:190` | String literal for code smell detection |
| Weight matrix "hardcoded" | `cortex-retrieval/src/intent/weight_matrix.rs` | Documented design: "can be overridden via TOML config" |
| `vec![]` in NAPI bindings | `prediction.rs`, `retrieval.rs`, `multiagent.rs` | Default empty vectors for optional parameters |
| `looks_like_placeholder()` | `cortex-privacy/src/context_scoring.rs` | Detects placeholder values like "your_api_key" to reduce FPs |
| "Phase D/E" in test comments | Multiple test files | Labels indicating which hardening phase the test covers |
| `#[allow(dead_code)]` in tests | `cortex-retrieval/tests/property/` | Helper functions for property testing |
| `DedupAction::Noop` | `cortex-learning/src/engine.rs` | Enum variant for "no action needed" — correct dedup result |

---

## Implementation Plan

### Phase A: Multi-Agent Completeness (P1, 5 impl + 8 test)

| ID | Task | File(s) | Est |
|---|---|---|---|
| **A-01** | Wire `detect_consensus` to real `ConsensusDetector` — inject embedding provider from runtime | `cortex-multiagent/src/engine.rs` | 2h |
| **A-02** | Persist peer vector clock in `acknowledge_sync` — store in `delta_queue` or new `peer_clocks` table | `cortex-multiagent/src/sync/protocol.rs` | 3h |
| **A-03** | Implement namespace filtering in temporal diff | `cortex-temporal/src/query/diff.rs:501-504` | 1h |
| **A-04** | Route multi-agent reads through `readers` pool (remove `#[allow(dead_code)]` on `readers`) | `cortex-multiagent/src/engine.rs` | 2h |
| **A-05** | Wire `config` fields to runtime behavior in MultiAgentEngine, TemporalEngine, TrustScorer (remove `#[allow(dead_code)]`) | 3 files | 2h |
| **A-T01** | Test: detect_consensus returns real clusters when memories have high similarity | | 1h |
| **A-T02** | Test: acknowledge_sync persists clock, subsequent sync doesn't re-send applied deltas | | 1h |
| **A-T03** | Test: temporal diff with namespace scope only returns memories from that namespace | | 30m |
| **A-T04** | Test: multi-agent reads go through read pool (file-backed mode) | | 30m |
| **A-T05** | Test: config thresholds affect trust scoring behavior | | 30m |
| **A-T06** | Test: config affects temporal engine behavior (e.g., drift_detection_window_hours) | | 30m |
| **A-T07** | Test: detect_consensus returns empty when multi-agent disabled | | 30m |
| **A-T08** | Test: peer clock persists across restart (file-backed) | | 30m |

**Quality gate:** `cargo test -p cortex-multiagent -p cortex-temporal && cargo clippy --all -- -D warnings`

---

### Phase B: Health & Observability Accuracy (P1/P2, 5 impl + 6 test)

| ID | Task | File(s) | Est |
|---|---|---|---|
| **B-01** | Wire contradiction counts from ValidationEngine into HealthSnapshot | `cortex-napi/src/bindings/health.rs:88-89` | 2h |
| **B-02** | Implement privacy health check using PrivacyEngine degradation stats | `cortex-observability/src/health/subsystem_checks.rs:94-101` | 1h |
| **B-03** | Replace manual JSON in `cortex_health_get_metrics` with `serde_json::to_value(&obs.metrics)` (MetricsCollector already derives Serialize) | `cortex-napi/src/bindings/health.rs:109-116` | 30m |
| **B-04** | Replace binary embedding cache hit rate heuristic with real L2SqliteCache stats | `cortex-napi/src/bindings/health.rs:55-63` | 1h |
| **B-05** | Expose EmbeddingEngine cache stats (hits/misses/rate) via a public method | `cortex-embeddings/src/engine.rs` | 1h |
| **B-T01** | Test: contradiction_count > 0 when contradictory memories exist | | 1h |
| **B-T02** | Test: privacy health degrades when degradation tracker has events | | 30m |
| **B-T03** | Test: get_metrics returns all 5 metric domains | | 30m |
| **B-T04** | Test: cache hit rate is between 0.0-1.0, not just 0 or 1 | | 30m |
| **B-T05** | Test: causal health triggers Degraded at >10 unresolved contradictions | | 30m |
| **B-T06** | Test: metrics snapshot includes embedding, retrieval, consolidation stats | | 30m |

**Quality gate:** `cargo test -p cortex-napi -p cortex-observability && cargo clippy --all -- -D warnings`

---

### Phase C: Cloud & OAuth (P1, 3 impl + 5 test)

| ID | Task | File(s) | Est |
|---|---|---|---|
| **C-01** | Implement OAuth browser-based login flow (local HTTP callback server, browser open, code exchange) | `cortex-cloud/src/auth/login_flow.rs:43-57` | 6h |
| **C-02** | Implement OAuth token refresh via refresh_token grant | `cortex-cloud/src/auth/login_flow.rs:62-74` | 2h |
| **C-03** | Wire `CloudSyncAdapter::sync_via_cloud()` to CloudEngine's HTTP push/pull | `cortex-multiagent/src/sync/cloud_integration.rs:33-43` | 4h |
| **C-T01** | Test: OAuth authenticate() returns valid token (mock HTTP server) | | 2h |
| **C-T02** | Test: OAuth refresh() returns new token using refresh_token | | 1h |
| **C-T03** | Test: OAuth failure propagates correctly (bad client_id, unreachable auth_url) | | 1h |
| **C-T04** | Test: sync_via_cloud pushes deltas via HTTP, pulls remote deltas | | 2h |
| **C-T05** | Test: sync_via_cloud falls back to offline mode on network failure | | 1h |

**Quality gate:** `cargo test -p cortex-cloud -p cortex-multiagent && cargo clippy --all -- -D warnings`

**Note:** Phase C is the heaviest lift and is **parallelizable** with A and B. OAuth may be deprioritized if API key auth is sufficient for current use cases.

---

### Phase D: Performance & Polish (P2, 3 impl + 3 test)

| ID | Task | File(s) | Est |
|---|---|---|---|
| **D-01** | Implement batched ONNX inference with tensor padding | `cortex-embeddings/src/providers/onnx_provider.rs:192-194` | 4h |
| **D-02** | Add `LlmPolisher` constructor injection to ConsolidationEngine (keep NoOp as default) | `cortex-consolidation/src/engine.rs` + `llm_polish.rs` | 2h |
| **D-03** | Add `LlmExtractor` constructor injection to LearningEngine (keep NoOp as default) | `cortex-learning/src/engine.rs` | 1h |
| **D-T01** | Benchmark: batched embed_batch(100) < 2x single embed() time | | 1h |
| **D-T02** | Test: ConsolidationEngine with custom polisher uses it, without uses NoOp | | 30m |
| **D-T03** | Test: LearningEngine with custom extractor uses it, without uses NoOp | | 30m |

**Quality gate:** `cargo test -p cortex-embeddings -p cortex-consolidation -p cortex-learning && cargo clippy --all -- -D warnings`

---

## Dependency Graph

```
Phase A (Multi-Agent)     ─┐
Phase B (Health/Obs)      ─┼─→ All independent, parallelizable
Phase C (Cloud/OAuth)     ─┘
         ↓
Phase D (Performance)     ─→ Independent, lowest priority
```

## Summary Stats

| Metric | Count |
|---|---|
| Total findings | 15 |
| P1 (real stubs) | 7 |
| P2 (quality gaps) | 5 |
| P3 (dead code) | 3 |
| False positives eliminated | 17 |
| Implementation tasks | 16 |
| Test tasks | 22 |
| Total tasks | 38 |
| Orchestrators audited | 15 |
| Orchestrators fully complete | 13 |
| Orchestrators with gaps | 2 (MultiAgentEngine, DeltaSyncEngine) |

## Critical Path

- **Phase A + B (parallel):** 2-3 working days
- **Phase C (OAuth + cloud sync):** 3-5 working days (parallelizable with A+B)
- **Phase D (perf polish):** 1-2 working days
- **Total with 1 engineer:** 6-10 working days
- **Total with 2 engineers:** 4-7 working days
- **Minimum viable (A+B only):** 2-3 working days

## Key File Reference

| File | Findings |
|---|---|
| `cortex-multiagent/src/engine.rs` | F-03 (detect_consensus stub), F-13 (dead_code readers/config) |
| `cortex-multiagent/src/sync/protocol.rs` | F-04 (acknowledge_sync no-op) |
| `cortex-multiagent/src/sync/cloud_integration.rs` | F-02 (cloud sync stub) |
| `cortex-cloud/src/auth/login_flow.rs` | F-01 (OAuth not implemented) |
| `cortex-temporal/src/query/diff.rs` | F-05 (namespace filter no-op) |
| `cortex-napi/src/bindings/health.rs` | F-06 (contradiction=0), F-08 (incomplete metrics), F-09 (binary cache rate) |
| `cortex-observability/src/health/subsystem_checks.rs` | F-07 (privacy always healthy) |
| `cortex-embeddings/src/providers/onnx_provider.rs` | F-10 (sequential batch) |
| `cortex-consolidation/src/llm_polish.rs` | F-11 (NoOpPolisher only) |
| `cortex-learning/src/extraction/llm_enhanced.rs` | F-12 (NoOpExtractor only) |
| `cortex-temporal/src/engine.rs` | F-14 (dead_code config) |
| `cortex-multiagent/src/trust/scorer.rs` | F-15 (dead_code config) |
