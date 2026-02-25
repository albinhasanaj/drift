# Cortex Stub, Mock, Deferred & Orchestrator Audit

> **Date:** 2026-02-10
> **Scope:** All Cortex Rust crates (`crates/cortex/*`), TS package (`packages/cortex/`), bridge (`crates/cortex-drift-bridge/`)
> **Method:** Exhaustive grep + manual file review of every hit for: TODO, FIXME, HACK, XXX, stub, mock, fake, placeholder, hardcoded, no-op, noop, phase, "not yet implemented", unimplemented!, dead_code, workaround, temporary

---

## Executive Summary

The Cortex system has **17 deferred-work findings** across 4 severity levels and **19 orchestrators** identified. The Rust engine layer is ~95% real — most prior audit findings have been fixed. The remaining gaps cluster in three areas:

1. **LLM integration points** — Two trait-based extension points (extraction, polish) ship only with NoOp implementations
2. **Cloud/multi-agent sync** — OAuth and cloud-transport paths return errors; consensus detection is stubbed
3. **Background scheduling** — Runtime claims "background task scheduler" but has none; consolidation triggers exist but are never evaluated

The TS stub module (`stub.ts`, 68 methods) remains the active runtime fallback since no native binary is distributed.

---

## Findings by Severity

### P0 — Stubs That Block Core Functionality (5 findings)

| ID | Location | Description |
|----|----------|-------------|
| **S-01** | `cortex-multiagent/src/engine.rs:185-202` | **`detect_consensus()` is a Phase D stub.** Comment says "Phase D stub", always returns `Ok(Vec::new())`. `ConsensusDetector` exists in `cortex-multiagent::consolidation` but isn't wired because it needs an embedding engine injected at the engine level. |
| **S-02** | `cortex-multiagent/src/sync/cloud_integration.rs:33-43` | **`sync_via_cloud()` returns error.** "cloud sync not yet available — target agent is remote or deregistered". Cloud transport infrastructure (HttpClient, SyncManager, push/pull/delta) exists in `cortex-cloud` but isn't bridged to multi-agent sync. |
| **S-03** | `cortex-cloud/src/auth/login_flow.rs:47-57, 68-74` | **OAuth `authenticate()` and `refresh()` return errors.** "OAuth flow not yet implemented — use API key auth". The `AuthMethod::OAuth` enum variant exists but both code paths return `CloudError::AuthFailed`. |
| **S-04** | `cortex-embeddings/src/providers/mod.rs:46-50` | **API embedding provider always falls back to TF-IDF.** `create_provider("api")` immediately warns "API provider requires runtime configuration" and returns `TfIdfFallback`. The `ApiProvider` struct is fully implemented (231 lines, with retry, backoff, reqwest) but `create_provider` never constructs it because `EmbeddingConfig` lacks the API key field. |
| **S-05** | `packages/cortex/src/bridge/stub.ts` (412 lines) | **Complete 68-method TS stub is the active runtime.** Every method returns empty/zero/null data. `loadNativeModule()` in `index.ts:159-174` catches the missing native binary and falls back to this stub. Since no `drift-cortex-napi` binary is built/distributed, **this is the production experience**. |

### P1 — No-Op Implementations (8 findings)

| ID | Location | Description |
|----|----------|-------------|
| **S-06** | `cortex-learning/src/extraction/llm_enhanced.rs:12-18` | **`NoOpExtractor` always used.** `LearningEngine::new()` and `with_storage()` both hardcode `Box::new(NoOpExtractor)`. The `LlmExtractor` trait exists with `extract()` returning `Option<String>`, but no real implementation is provided. Rule-based extraction works as fallback. |
| **S-07** | `cortex-consolidation/src/llm_polish.rs:64-71` | **`NoOpPolisher` always used.** Consolidation summaries are never LLM-polished. The `LlmPolisher` trait exists with `polish()` returning `Option<String>`, and `PolishTracker` tracks rates, but `NoOpPolisher` is the only implementation. |
| **S-08** | `cortex-napi/src/runtime.rs` (entire file) | **No background task scheduler exists.** Module-level comments (line 1, lib.rs:4) claim "background task scheduler (tokio)" but the runtime has NO `tokio::spawn`, NO periodic tasks, NO timer-based scheduling. Consolidation triggers (`scheduling/triggers.rs`) and throttle (`scheduling/throttle.rs`) are fully implemented but never evaluated. Consolidation only runs on explicit NAPI call. |
| **S-09** | `cortex-retrieval/Cargo.toml:23` | **Reranker feature never enabled.** `reranker = ["fastembed"]` exists but is not in `default` features. `RankingPipeline` always uses the no-op passthrough `rerank()`. Cross-encoder re-ranking code is fully implemented (78 lines) but dormant. |
| **S-10** | `cortex-multiagent/src/engine.rs:25-28` | **`readers` and `config` fields are dead code.** Both marked `#[allow(dead_code)]`. The engine routes ALL operations through `writer`, never using the read pool. `config` is only checked in the stubbed `detect_consensus()`. |
| **S-11** | `cortex-multiagent/src/trust/scorer.rs:29-30` | **`TrustScorer.config` is dead code.** Marked `#[allow(dead_code)]`. The config is stored but never read. |
| **S-12** | `cortex-temporal/src/engine.rs:29-30` | **`TemporalEngine.config` is dead code.** Marked `#[allow(dead_code)]`. Only `drift_detection_window_hours` is used from `config` (via clone in constructor), the field itself is never referenced. |
| **S-13** | `cortex-napi/src/bindings/multiagent.rs:374` | **Sync errors always empty.** `errors: vec![]` is hardcoded in the sync result JSON. Real sync errors from `DeltaSyncEngine::initiate_sync` aren't propagated to the caller. |

### P2 — Deferred Work / Placeholders (4 findings)

| ID | Location | Description |
|----|----------|-------------|
| **S-14** | `cortex-storage/src/migrations/v013_placeholder.rs` | **Placeholder migration.** No-op migration to close the v012→v014 numbering gap. Intentional and documented (F-04), but the gap should be used for real schema work or formally marked as reserved. |
| **S-15** | `cortex-drift-bridge/src/specification/events.rs:284-291` | **Placeholder memories for causal edges.** `create_placeholder_memory()` creates synthetic `BaseMemory` objects with fake content ("Placeholder for module {id}") for causal edge endpoints. These enter the real causal graph and could pollute queries. |
| **S-16** | `cortex-napi/src/bindings/prediction.rs:34-51` | **`preload` just re-runs `predict`.** `cortex_prediction_preload()` calls the same `predict()` with `recent_queries: vec![]` and `current_intent: None`. No actual cache warming or preloading behavior. The stub and real NAPI return identical shapes. |
| **S-17** | `cortex-drift-bridge/src/grounding/scheduler.rs:22-65` | **`GroundingScheduler` never wired to timer.** Tracks scan counts and determines trigger types, but nothing calls `should_ground()` on a schedule. Only used reactively when manually invoked. |

### Pre-existing Test Failures (not from this audit)

| Crate | Test | Status |
|-------|------|--------|
| cortex-privacy | `slack_bot_token_sanitized` | Failing |
| cortex-retrieval | `scorer_weights_still_sum_to_one` | Failing |
| cortex-retrieval | `t5_ret_06_higher_importance_ranks_above` | Failing |

---

## Complete Orchestrator Inventory (19 found)

### Tier 1: Top-Level Orchestrators

| # | Name | Location | Scope |
|---|------|----------|-------|
| 1 | **CortexRuntime** | `cortex-napi/src/runtime.rs` | Central singleton owning all 15 engines. OnceLock-guarded, initialized once via NAPI. |
| 2 | **ConsolidationEngine** | `cortex-consolidation/src/engine.rs` | 6-phase pipeline orchestrator with single-execution guard, quality metrics, and auto-tuning. |
| 3 | **MultiAgentEngine** | `cortex-multiagent/src/engine.rs` | Orchestrates registry, namespace, projection, share, trust, sync. `detect_consensus` stubbed. |
| 4 | **RetrievalEngine** | `cortex-retrieval/src/engine.rs` | Orchestrates expand → search → rank → budget pack → compress. |
| 5 | **SyncManager** | `cortex-cloud/src/sync/mod.rs` | Bidirectional sync: push → pull → conflict resolution via HttpClient. |
| 6 | **GroundingLoopRunner** | `cortex-drift-bridge/src/grounding/loop_runner.rs` | Orchestrates classify → collect evidence → score → adjust for memory grounding. |

### Tier 2: Subsystem Orchestrators

| # | Name | Location | Scope |
|---|------|----------|-------|
| 7 | **ConsolidationPipeline** | `cortex-consolidation/src/pipeline/mod.rs` | `run_pipeline()` — the actual 6-phase execution function (selection → clustering → recall gate → abstraction → integration → pruning). |
| 8 | **RankingPipeline** | `cortex-retrieval/src/ranking/mod.rs` | Score → rerank → deduplicate pipeline. |
| 9 | **ValidationEngine** | `cortex-validation/src/engine.rs` | 4-dimension validation: temporal, contradiction, confidence, structural. |
| 10 | **EmbeddingEngine** | `cortex-embeddings/src/engine.rs` | Multi-provider embedding with L1/L2/L3 cache and degradation chain. |
| 11 | **DegradationChain** | `cortex-embeddings/src/degradation.rs` | Provider fallback chain: ONNX → API → Ollama → TF-IDF. |
| 12 | **CausalEngine** | `cortex-causal/src/engine.rs` | Causal graph operations, inference, narrative generation. |
| 13 | **TemporalEngine** | `cortex-temporal/src/engine.rs` | Temporal queries, drift metrics, materialized views. |
| 14 | **PredictionEngine** | `cortex-prediction/src/engine.rs` | Prediction with adaptive caching and signal aggregation. |
| 15 | **DecayEngine** | `cortex-decay/src/engine.rs` | Confidence decay processing across memories. |
| 16 | **LearningEngine** | `cortex-learning/src/engine.rs` | Correction analysis, dedup, principle extraction. |

### Tier 3: Specialized Orchestrators

| # | Name | Location | Scope |
|---|------|----------|-------|
| 17 | **CrossNamespaceConsolidator** | `cortex-multiagent/src/consolidation/cross_namespace.rs` | Cross-namespace consolidation with consensus detection across agent namespaces. |
| 18 | **BridgeEventHandler** | `cortex-drift-bridge/src/event_mapping/mapper.rs` | Maps 18 drift scan events to memory creation operations. |
| 19 | **GroundingScheduler** | `cortex-drift-bridge/src/grounding/scheduler.rs` | Determines when/what to ground (scan-triggered, memory-triggered, on-demand). Not wired to timer. |

### Orchestrator Wiring Status

| Orchestrator | Wired to Runtime? | Called by NAPI? | Background? | Status |
|-------------|-------------------|-----------------|-------------|--------|
| CortexRuntime | ✅ (is runtime) | ✅ | N/A | **Working** |
| ConsolidationEngine | ✅ | ✅ `cortexConsolidationConsolidate` | ❌ No scheduler | **Manual-only** |
| MultiAgentEngine | ✅ | ✅ 12 bindings | N/A | **Partial** (consensus stub) |
| RetrievalEngine | ✅ | ✅ 3 bindings | N/A | **Working** |
| SyncManager | ✅ via CloudEngine | ✅ `cortexCloudSync` | ❌ | **Working** (API key only) |
| GroundingLoopRunner | ❌ | ❌ | ❌ | **Bridge-only** |
| ConsolidationPipeline | ✅ via engine | ✅ | ❌ | **Working** |
| RankingPipeline | ✅ via retrieval | ✅ | N/A | **Working** (no reranker) |
| ValidationEngine | ✅ | ✅ `cortexValidationRun` | N/A | **Working** |
| EmbeddingEngine | ✅ | ✅ `cortexReembed` | N/A | **Working** |
| CausalEngine | ✅ | ✅ 5 bindings | N/A | **Working** |
| TemporalEngine | ✅ | ✅ 10 bindings | N/A | **Working** |
| PredictionEngine | ✅ | ✅ 3 bindings | N/A | **Working** |
| DecayEngine | ✅ | ✅ `cortexDecayRun` | ❌ No scheduler | **Manual-only** |
| LearningEngine | ✅ | ✅ 4 bindings | N/A | **Working** |
| CrossNamespaceConsolidator | ❌ | ❌ | ❌ | **Library-only** |
| BridgeEventHandler | ❌ | ❌ | ❌ | **Bridge-only** |
| GroundingScheduler | ❌ | ❌ | ❌ | **Unwired** |

---

## Implementation Plan

### Phase A: Wire Stubbed Orchestrators (P0, 3-4 days)

| Task | ID | File(s) | Description | Test |
|------|----|---------|-------------|------|
| Wire consensus detection | SA-01 | `cortex-multiagent/src/engine.rs` | Inject `Arc<dyn IEmbeddingProvider>` into `MultiAgentEngine`, wire `detect_consensus()` to `ConsensusDetector` with real similarity function from embeddings. Remove "Phase D stub" comment. | Consensus on 3 agents with overlapping memories returns non-empty clusters. |
| Wire cloud sync transport | SA-02 | `cortex-multiagent/src/sync/cloud_integration.rs`, `cortex-cloud/src/engine.rs` | Bridge `sync_via_cloud()` to `CloudEngine::sync()` via the `SyncManager`. Requires passing `HttpClient` and `ConflictResolver` from cloud engine. | Cloud sync with mock HTTP server returns `SyncReport` with pushed/pulled counts. |
| Wire API embedding provider | SA-03 | `cortex-embeddings/src/providers/mod.rs`, `cortex-core/src/config/embedding_config.rs` | Add `api_key: Option<String>` to `EmbeddingConfig`. When `provider = "api"` and key is present, construct `ApiProvider` instead of falling back to TF-IDF. | `create_provider("api")` with valid key returns `ApiProvider`, without key returns TF-IDF. |
| Propagate sync errors | SA-04 | `cortex-napi/src/bindings/multiagent.rs:371-376` | Replace `errors: vec![]` with actual error collection from `sync_with_counts()`. If sync partially fails, include error descriptions in the result. | Sync with invalid agent returns non-empty `errors` array. |
| Remove dead_code allows | SA-05 | `cortex-multiagent/src/engine.rs:25-28`, `trust/scorer.rs:29-30`, `cortex-temporal/src/engine.rs:29-30` | Route MultiAgentEngine read operations through `readers` pool. Use `config` in `TrustScorer` for configurable trust decay. Use `config` in `TemporalEngine` directly. Remove all `#[allow(dead_code)]`. | Read operations (list_agents, get_agent, get_provenance) use read pool. Clippy clean with no dead_code allows. |

### Phase B: Background Scheduling (P0, 2-3 days)

| Task | ID | File(s) | Description | Test |
|------|----|---------|-------------|------|
| Add tokio runtime to CortexRuntime | SB-01 | `cortex-napi/src/runtime.rs` | Add `tokio::runtime::Handle` field. Create a multi-threaded tokio runtime on init for background tasks. | Runtime initializes with active tokio handle. |
| Wire consolidation scheduler | SB-02 | `cortex-napi/src/runtime.rs`, `cortex-consolidation/src/scheduling/` | Spawn a background task that periodically calls `evaluate_triggers()` with real signals from storage (memory count, avg confidence, etc.). When triggers fire, call `consolidation.consolidate()`. Respect `ThrottleConfig`. | After inserting 100+ episodic memories, background consolidation fires within 6h simulated time. |
| Wire decay scheduler | SB-03 | `cortex-napi/src/runtime.rs`, `cortex-decay/` | Spawn a background task that runs decay on a configurable interval (default 24h). | Decay runs automatically, archiving memories below threshold. |
| Wire grounding scheduler | SB-04 | `cortex-napi/src/runtime.rs`, `cortex-drift-bridge/src/grounding/scheduler.rs` | Wire `GroundingScheduler` to fire after scan events. Requires bridge integration into runtime. | `should_ground()` returns true after configured scan count, triggering grounding loop. |
| Update module docs | SB-05 | `cortex-napi/src/lib.rs`, `cortex-napi/src/runtime.rs` | Update module-level comments to accurately describe what background scheduling exists vs doesn't. | Doc comments match reality. |

### Phase C: LLM Integration Points (P1, 2-3 days)

| Task | ID | File(s) | Description | Test |
|------|----|---------|-------------|------|
| LLM extractor trait wiring | SC-01 | `cortex-learning/src/engine.rs`, `cortex-napi/src/runtime.rs` | Add `set_llm_extractor()` to `LearningEngine`. Wire runtime to check for `CORTEX_LLM_ENDPOINT` env var and, if present, create an HTTP-based `LlmExtractor` implementation. | With mock LLM server, `LearningEngine` produces LLM-extracted principles. Without server, falls back to rule-based. |
| LLM polisher trait wiring | SC-02 | `cortex-consolidation/src/engine.rs`, `cortex-napi/src/runtime.rs` | Add `set_llm_polisher()` to `ConsolidationEngine`. Wire runtime to create HTTP-based `LlmPolisher` when endpoint is available. | With mock LLM server, consolidated summaries are polished. `PolishTracker` records polished count > 0. |
| HTTP LLM client implementation | SC-03 | `cortex-learning/src/extraction/llm_enhanced.rs` (new impl), `cortex-consolidation/src/llm_polish.rs` (new impl) | Implement `HttpLlmExtractor` and `HttpLlmPolisher` that POST to a configurable endpoint. Include timeout, retry, and graceful fallback. | HTTP extractor calls endpoint, parses response. Timeout returns None (fallback). |
| Config for LLM endpoints | SC-04 | `cortex-core/src/config/mod.rs` | Add `LlmConfig { endpoint: Option<String>, timeout_ms: u64, max_retries: u32 }` to `CortexConfig`. | Config round-trips through TOML serialization. |

### Phase D: OAuth & Cloud Hardening (P1, 2-3 days)

| Task | ID | File(s) | Description | Test |
|------|----|---------|-------------|------|
| Implement OAuth login flow | SD-01 | `cortex-cloud/src/auth/login_flow.rs` | Implement the 4-step OAuth flow: start local HTTP server → open browser to `auth_url` → receive callback with code → exchange code at `token_url`. Use `tokio` + `hyper` for the local server. | With mock OAuth server, `authenticate()` returns valid `AuthToken`. |
| Implement OAuth token refresh | SD-02 | `cortex-cloud/src/auth/login_flow.rs` | POST to `token_url` with `grant_type=refresh_token`. Parse response into `AuthToken`. | Refresh with valid token returns new token. Refresh with expired token returns error. |
| Wire token expiry to auto-refresh | SD-03 | `cortex-cloud/src/auth/token_manager.rs` | Check token expiry before each sync. If expired and refresh_token available, call `refresh()`. If refresh fails, re-authenticate. | Token auto-refreshes when expired. Failed refresh triggers full re-auth. |

### Phase E: Cleanup & Polish (P2, 1-2 days)

| Task | ID | File(s) | Description | Test |
|------|----|---------|-------------|------|
| Real prediction preload | SE-01 | `cortex-napi/src/bindings/prediction.rs:34-51` | Implement actual preloading: predict top-N memory IDs, then pre-fetch their embeddings into L1 cache and load their full content into a warm cache. Return preloaded count. | `preload()` warms cache; subsequent `predict()` has higher cache hit rate. |
| Fix placeholder memories | SE-02 | `cortex-drift-bridge/src/specification/events.rs:284-291` | Replace `create_placeholder_memory()` with a lookup-or-skip approach: if the upstream module already has a memory, use it; otherwise, create a lightweight `CausalNode` without polluting the memory store. | Causal edges don't create fake memories. Graph queries don't return "Placeholder for module" content. |
| Use v013 migration slot | SE-03 | `cortex-storage/src/migrations/v013_placeholder.rs` | If there's pending schema work (e.g., new indexes, new columns), use this slot. Otherwise, add a comment explaining it's permanently reserved. | Migration runs clean, version 13 is no longer a no-op. |
| Fix pre-existing test failures | SE-04 | `cortex-privacy/`, `cortex-retrieval/` | Fix the 3 pre-existing test failures: `slack_bot_token_sanitized`, `scorer_weights_still_sum_to_one`, `t5_ret_06_higher_importance_ranks_above`. | All 3 tests pass. Zero test failures across entire cortex workspace. |
| Enable reranker by default | SE-05 | `cortex-retrieval/Cargo.toml` | Add `reranker` to `default` features. Ensure `fastembed` downloads the cross-encoder model on first use. Add model path configuration. | Retrieval uses cross-encoder reranking. Search quality improves on benchmark. |

---

## Dependency Graph

```
Phase A (Wire Stubs) ─────────┐
                               ├──→ Phase E (Cleanup)
Phase B (Background Sched) ───┘
                                    
Phase C (LLM Integration) ────────→ Phase E (Cleanup)

Phase D (OAuth/Cloud) ─────────────→ Phase E (Cleanup)
```

- **Phase A** and **Phase B** are independent and can be parallelized
- **Phase C** and **Phase D** are independent and can be parallelized
- **Phase E** depends on A+B (for scheduler tests) and touches cleanup across all phases

---

## Summary Stats

| Metric | Count |
|--------|-------|
| **Total findings** | 17 |
| P0 (stubs blocking functionality) | 5 |
| P1 (no-op / limited) | 8 |
| P2 (deferred / placeholder) | 4 |
| **Total orchestrators** | 19 |
| Orchestrators fully wired | 12 |
| Orchestrators partially wired | 3 |
| Orchestrators unwired | 4 |
| **Implementation tasks** | 22 impl |
| **Estimated duration** | 10-15 working days (6-9 with 2 engineers) |
| **Pre-existing test failures** | 3 |

---

## Key File Reference

### Rust — Stubs & Deferred Work
- `crates/cortex/cortex-multiagent/src/engine.rs` — Phase D stub (S-01), dead code (S-10)
- `crates/cortex/cortex-multiagent/src/sync/cloud_integration.rs` — Cloud sync stub (S-02)
- `crates/cortex/cortex-cloud/src/auth/login_flow.rs` — OAuth stub (S-03)
- `crates/cortex/cortex-embeddings/src/providers/mod.rs` — API provider fallback (S-04)
- `crates/cortex/cortex-learning/src/extraction/llm_enhanced.rs` — NoOpExtractor (S-06)
- `crates/cortex/cortex-consolidation/src/llm_polish.rs` — NoOpPolisher (S-07)
- `crates/cortex/cortex-napi/src/runtime.rs` — No background scheduler (S-08)
- `crates/cortex/cortex-napi/src/bindings/multiagent.rs` — Empty errors (S-13)
- `crates/cortex/cortex-napi/src/bindings/prediction.rs` — Fake preload (S-16)
- `crates/cortex/cortex-storage/src/migrations/v013_placeholder.rs` — Placeholder migration (S-14)

### Rust — Orchestrators
- `crates/cortex/cortex-napi/src/runtime.rs` — CortexRuntime
- `crates/cortex/cortex-consolidation/src/engine.rs` — ConsolidationEngine
- `crates/cortex/cortex-consolidation/src/pipeline/mod.rs` — Pipeline orchestrator
- `crates/cortex/cortex-multiagent/src/engine.rs` — MultiAgentEngine
- `crates/cortex/cortex-retrieval/src/engine.rs` — RetrievalEngine
- `crates/cortex/cortex-retrieval/src/ranking/mod.rs` — RankingPipeline
- `crates/cortex/cortex-cloud/src/sync/mod.rs` — SyncManager
- `crates/cortex/cortex-validation/src/engine.rs` — ValidationEngine
- `crates/cortex/cortex-embeddings/src/engine.rs` — EmbeddingEngine
- `crates/cortex/cortex-causal/src/engine.rs` — CausalEngine
- `crates/cortex/cortex-temporal/src/engine.rs` — TemporalEngine
- `crates/cortex/cortex-prediction/src/engine.rs` — PredictionEngine
- `crates/cortex/cortex-decay/src/engine.rs` — DecayEngine
- `crates/cortex/cortex-learning/src/engine.rs` — LearningEngine
- `crates/cortex/cortex-multiagent/src/consolidation/cross_namespace.rs` — CrossNamespaceConsolidator

### TypeScript — Stubs
- `packages/cortex/src/bridge/stub.ts` — Complete 68-method stub (S-05)
- `packages/cortex/src/bridge/index.ts` — loadNativeModule fallback logic

### Bridge — Orchestrators & Deferred
- `crates/cortex-drift-bridge/src/grounding/loop_runner.rs` — GroundingLoopRunner
- `crates/cortex-drift-bridge/src/grounding/scheduler.rs` — GroundingScheduler (unwired)
- `crates/cortex-drift-bridge/src/event_mapping/mapper.rs` — BridgeEventHandler
- `crates/cortex-drift-bridge/src/specification/events.rs` — Placeholder memories (S-15)
