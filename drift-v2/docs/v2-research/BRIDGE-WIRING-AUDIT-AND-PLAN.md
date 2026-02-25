# Cortex-Drift Bridge: Complete Audit & Wiring Plan

> **Status:** Audit complete. All 15 modules, 49 source files, 804 tests, 0 failures, clippy clean.
> **Problem:** The bridge is a fully functional Rust engine with **ZERO presentation layer exposure**. None of the 20 NAPI functions, 6 MCP tool handlers, or the BridgeRuntime are callable from TypeScript, CLI, or MCP.

---

## Part 1: What the Bridge Does (Feature Inventory)

### 1.1 Architecture Overview

The bridge sits between two systems:
- **Drift** (code analysis engine) — scans code, detects patterns, enforces gates, stores results in `drift.db`
- **Cortex** (memory engine) — stores memories with typed content, confidence, causal edges, embeddings

The bridge's job: **translate Drift analysis events into Cortex memories, then ground those memories against real Drift evidence to validate or invalidate them.**

```
Drift Events → [Bridge Event Mapper] → Cortex Memories (bridge_memories)
                                              ↓
                                    [Grounding Loop]
                                        ↓        ↓
                            drift.db evidence  → Score + Verdict
                                                    ↓
                                        Confidence Adjustment
                                        Contradiction Memory
                                        Causal Edge
```

### 1.2 Module Inventory (15 modules, 49 source files)

| Module | Files | Purpose |
|--------|-------|---------|
| `event_mapping/` | 5 | 21 Drift events → Cortex memories, dedup, builder pattern |
| `grounding/` | 8 | Evidence collection (12 types), scoring (4 verdicts), loop runner, contradiction gen, classification, scheduling |
| `causal/` | 6 | Typed edge creation, counterfactual ("what if removed?"), intervention ("what if changed?"), pruning, unified narrative |
| `specification/` | 7 | Spec corrections, adaptive weights with decay, decomposition priors, attribution stats |
| `storage/` | 5 | 5 SQLite tables, migrations, PRAGMAs, retention, CRUD |
| `config/` | 6 | BridgeConfig, GroundingConfig, EventConfig, EvidenceConfig, validation |
| `errors/` | 5 | BridgeError (10 variants), ErrorContext, ErrorChain, RecoveryAction |
| `health/` | 5 | Per-subsystem checks, readiness probes, degradation tracking |
| `license/` | 4 | 3-tier gating (Community/Team/Enterprise), 25-feature matrix, usage tracking |
| `intents/` | 3 | 10 code intents, 10 analytical intents, intent→data source resolver |
| `link_translation/` | 2 | Drift PatternLink/ConstraintLink → Cortex EntityLink (5 constructors, round-trip) |
| `napi/` | 2 | 20 NAPI-ready functions (return `serde_json::Value`) |
| `query/` | 4 | ATTACH lifecycle, 12 drift queries, cortex queries, cross-DB ops |
| `tools/` | 6 | 6 MCP tool handlers (why, learn, grounding_check, counterfactual, intervention, health) |
| `types/` | 5 | GroundingResult, GroundingVerdict, GroundingSnapshot, ConfidenceAdjustment, GroundingDataSource |

### 1.3 Event Mapping System (21 Events)

The bridge maps 21 Drift lifecycle events to Cortex memories:

| # | Event | Memory Type | Confidence | Importance |
|---|-------|-------------|------------|------------|
| 1 | `on_pattern_approved` | PatternRationale | 0.8 | High |
| 2 | `on_pattern_discovered` | Insight | 0.5 | Normal |
| 3 | `on_pattern_ignored` | Feedback | 0.6 | Normal |
| 4 | `on_pattern_merged` | DecisionContext | 0.7 | Normal |
| 5 | `on_scan_complete` | *(triggers grounding)* | — | — |
| 6 | `on_regression_detected` | DecisionContext | 0.9 | Critical |
| 7 | `on_violation_detected` | *(no memory — too noisy)* | — | — |
| 8 | `on_violation_dismissed` | ConstraintOverride | 0.7 | Normal |
| 9 | `on_violation_fixed` | Feedback | 0.8 | Normal |
| 10 | `on_gate_evaluated` | DecisionContext | 0.6 | Normal |
| 11 | `on_detector_alert` | Tribal | 0.6 | Normal |
| 12 | `on_detector_disabled` | CodeSmell | 0.9 | High |
| 13 | `on_constraint_approved` | ConstraintOverride | 0.8 | High |
| 14 | `on_constraint_violated` | Feedback | 0.7 | Normal |
| 15 | `on_decision_mined` | DecisionContext | 0.7 | Normal |
| 16 | `on_decision_reversed` | DecisionContext | 0.8 | High |
| 17 | `on_adr_detected` | DecisionContext | 0.9 | High |
| 18 | `on_boundary_discovered` | Tribal | 0.6 | Normal |
| 19 | `on_enforcement_changed` | DecisionContext | 0.8 | High |
| 20 | `on_feedback_abuse_detected` | Tribal | 0.7 | High |
| 21 | `on_error` | *(logged only)* | — | — |

**License gating:** Community tier gets 5 events (#1, #2, #8, #9, #12). Team/Enterprise get all 21.

### 1.4 Grounding System (12 Evidence Types)

The grounding loop collects evidence from `drift.db` and computes a score:

| Evidence Type | Weight | Source Table |
|--------------|--------|-------------|
| PatternConfidence | 0.18 | `pattern_confidence.posterior_mean` |
| PatternOccurrence | 0.13 | `detections` COUNT(DISTINCT file) ratio |
| FalsePositiveRate | 0.09 | `feedback` dismiss/total ratio |
| ConstraintVerification | 0.09 | `constraint_verifications` latest |
| CouplingMetric | 0.07 | `coupling_metrics.instability` |
| DnaHealth | 0.07 | `dna_genes` AVG(confidence*consistency) |
| TestCoverage | 0.09 | `test_quality.overall_score` |
| ErrorHandlingGaps | 0.06 | `error_gaps` COUNT |
| DecisionEvidence | 0.07 | `decisions.confidence` |
| BoundaryData | 0.05 | `boundaries.confidence` |
| TaintAnalysis | 0.05 | `taint_flows` risk score |
| CallGraphCoverage | 0.05 | `call_edges` non-fuzzy ratio |

**Verdicts (4 thresholds):**
- **Validated** (≥0.7): Boost confidence (+delta)
- **Partial** (≥0.4): Small penalty
- **Weak** (≥0.2): Moderate penalty
- **Invalidated** (<0.2): Large drop + contradiction memory

**Special verdicts:** NotGroundable (10 memory types can't be grounded), InsufficientData (no evidence found)

**Groundability:** 6 fully groundable types (PatternRationale, ConstraintOverride, DecisionContext, CodeSmell, Core, Semantic), 7 partially groundable, 10 not groundable.

### 1.5 Causal Intelligence System

| Capability | Function | Description |
|-----------|----------|-------------|
| Edge creation | `add_correction_edge()` | Links spec corrections to upstream modules |
| Edge creation | `add_grounding_edge()` | Links grounding results to memories (Supports/Contradicts) |
| Counterfactual | `what_if_removed()` | "What if this memory didn't exist?" — downstream impact |
| Intervention | `what_if_changed()` | "If we change this, what breaks?" — propagation graph |
| Pruning | `prune_weak_edges()` | Remove edges below strength threshold |
| Narrative | `build_narrative()` | Unified explanation: origins + effects + sections |
| Markdown | `render_markdown()` | Render narrative to markdown |

### 1.6 Specification System

| Feature | Description |
|---------|-------------|
| Spec Corrections | Process corrections with root cause analysis, create causal edges to upstream modules |
| Adaptive Weights | Compute weights from verification feedback, persist as Skill memory, decay over time |
| Decomposition Priors | Query bridge_memories for prior adjustments (Split/Merge/Reclassify), structured JSON parsing |
| Attribution Stats | Per-system accuracy metrics from data source attribution |

### 1.7 Storage Layer (5 Tables)

| Table | Purpose | Retention |
|-------|---------|-----------|
| `bridge_memories` | Persisted Cortex memories created by the bridge | Unlimited |
| `bridge_grounding_results` | Per-memory grounding scores + evidence | 90d Community, unlimited Enterprise |
| `bridge_grounding_snapshots` | Loop-level stats (validated/partial/weak/invalidated counts) | 365d |
| `bridge_event_log` | Event processing audit trail | 30d |
| `bridge_metrics` | Key-value metrics (usage counts, attribution accuracy, etc.) | 7d |

Plus: `bridge_schema_version` single-row table for migration tracking (immune to retention).

### 1.8 License & Feature Matrix (25 Features)

3 tiers: Community (free), Team, Enterprise.
- **Community:** Basic event mapping (5 events), basic grounding (100 memories, metered), causal edges (metered), drift_why, drift_memory_learn, drift_grounding_check (metered), drift_health
- **Team:** All 21 events, full grounding (500), counterfactual, intervention, unified narrative, adaptive weights, data retention
- **Enterprise:** Unlimited grounding, causal pruning, weight persistence, cross-DB analytics

### 1.9 MCP Tool Handlers (6 Tools)

| Tool | Purpose |
|------|---------|
| `drift_why` | "Why does this pattern/violation/constraint exist?" — queries memories + grounding history + causal narrative |
| `drift_memory_learn` | Create a Feedback memory from user correction |
| `drift_grounding_check` | Ground a single memory on-demand, return detailed verdict + evidence |
| `drift_counterfactual` | "What if this memory didn't exist?" |
| `drift_intervention` | "If we change this, what breaks?" |
| `drift_health` | Bridge health status (available/degraded/unavailable per subsystem) |

### 1.10 The 20 NAPI Functions

| # | Function | Needs DB | Description |
|---|----------|----------|-------------|
| 1 | `bridge_status` | No | Bridge availability, license tier, grounding enabled |
| 2 | `bridge_ground_memory` | drift+bridge | Ground a single memory |
| 3 | `bridge_ground_all` | drift+bridge | Run full grounding loop |
| 4 | `bridge_grounding_history` | bridge | Get grounding history for a memory |
| 5 | `bridge_translate_link` | No | Pattern → EntityLink |
| 6 | `bridge_translate_constraint_link` | No | Constraint → EntityLink |
| 7 | `bridge_event_mappings` | No | Return all 21 event mappings |
| 8 | `bridge_groundability` | No | Classify memory type groundability |
| 9 | `bridge_license_check` | No | Check feature at tier |
| 10 | `bridge_intents` | No | Return all 10 code intents |
| 11 | `bridge_adaptive_weights` | No | Compute weights from feedback |
| 12 | `bridge_spec_correction` | bridge+causal | Process a spec correction |
| 13 | `bridge_contract_verified` | bridge | Process a contract verification |
| 14 | `bridge_decomposition_adjusted` | bridge | Process a decomposition adjustment |
| 15 | `bridge_explain_spec` | causal | Generate causal explanation |
| 16 | `bridge_counterfactual` | causal | "What if removed?" |
| 17 | `bridge_intervention` | causal | "What if changed?" |
| 18 | `bridge_health` | cortex+drift+causal | Bridge health check |
| 19 | `bridge_unified_narrative` | causal | Full causal narrative |
| 20 | `bridge_prune_causal` | causal | Prune weak edges |

---

## Part 2: What's Wired vs. What's Dead

### Current State: ZERO TS Exposure

| Layer | Status |
|-------|--------|
| 20 Rust NAPI functions | Built, tested (804 tests) — **NOT wrapped with `#[napi]`** |
| 6 MCP tool handlers | Built — **NOT callable from TS** |
| BridgeRuntime | Built — **NOT instantiated from any TS code** |
| BridgeEventHandler (implements DriftEventHandler) | Built — **NOT wired into drift_analyze() pipeline** |
| drift-napi exports | 40 functions — **0 bridge functions** |
| cortex-napi exports | 68 functions — **0 bridge functions** |
| drift-mcp tools | 91 tools — **0 bridge tools** |
| drift-cli commands | 30+ subcommands — **0 bridge subcommands** |
| drift-ci passes | 10 passes — **0 bridge passes** |

### The Gap Chain

```
BridgeRuntime (Rust)     → NOT instantiated by any NAPI crate
  → BridgeEventHandler   → NOT wired into drift_analyze() or drift_scan()
  → GroundingLoopRunner  → NOT triggered after scan/analyze
  → bridge_*() functions → NOT wrapped with #[napi] macros
  → drift_*() tools      → NOT registered as MCP tools
  → No CLI commands      → User can't interact with bridge at all
```

---

## Part 3: Implementation Plan

### Phase 1: NAPI Wiring (Foundation) — 3-4 days

Wire the 20 bridge functions into `drift-napi` so they're callable from TypeScript.

**Why drift-napi and not a separate crate:** The bridge needs access to both `drift.db` (already opened by DriftRuntime) and `bridge.db`/`cortex.db`. Adding bridge functions to drift-napi lets them share the existing DriftRuntime connection pool.

| Task | Description | Files |
|------|-------------|-------|
| PH1-01 | Add `cortex-drift-bridge` as dependency to `drift-napi/Cargo.toml` | `drift-napi/Cargo.toml` |
| PH1-02 | Add `cortex-causal` as dependency to `drift-napi/Cargo.toml` | `drift-napi/Cargo.toml` |
| PH1-03 | Create `drift-napi/src/bindings/bridge.rs` — 20 `#[napi]` wrapper functions | NEW file |
| PH1-04 | Add `BridgeRuntime` to `DriftRuntime` struct (initialized during `driftInitialize()`) | `drift-napi/src/runtime.rs` |
| PH1-05 | Open `bridge.db` alongside `drift.db` during initialization | `drift-napi/src/runtime.rs` |
| PH1-06 | Register `bridge.rs` module in `drift-napi/src/bindings/mod.rs` | `drift-napi/src/bindings/mod.rs` |
| PH1-07 | Add 20 bridge function signatures to `packages/drift-napi-contracts/src/interface.ts` | contracts interface |
| PH1-08 | Add 20 bridge function stubs to `packages/drift-napi-contracts/src/stub.ts` | contracts stub |
| PH1-09 | Build native binary, verify 20 new exports appear in camelCase | build + verify |
| PH1-10 | Verify `driftBridgeStatus()` returns real data from binary | integration test |

**Quality gate:** `npx napi build --platform && node -e "const n = require('./drift-napi.darwin-arm64.node'); console.log(n.driftBridgeStatus())"` returns real JSON.

### Phase 2: Event Pipeline Wiring — 2-3 days

Wire the BridgeEventHandler into the drift analysis pipeline so events actually fire.

| Task | Description | Files |
|------|-------------|-------|
| PH2-01 | Instantiate `BridgeEventHandler` in `DriftRuntime` (with bridge_db connection) | `drift-napi/src/runtime.rs` |
| PH2-02 | Wire `BridgeEventHandler` into `drift_analyze()` — fire events after each analysis step | `drift-napi/src/bindings/analysis.rs` |
| PH2-03 | Fire `on_pattern_discovered` for each pattern found during analysis | `analysis.rs` |
| PH2-04 | Fire `on_scan_complete` at end of scan | `scanner.rs` |
| PH2-05 | Fire `on_gate_evaluated` for each gate result | `analysis.rs` step 7 |
| PH2-06 | Fire `on_boundary_discovered` for each boundary found | `analysis.rs` step 3a |
| PH2-07 | Fire `on_regression_detected` when degradation alerts are generated | `analysis.rs` step 8 |
| PH2-08 | Trigger grounding loop after `on_scan_complete` fires | `analysis.rs` or `scanner.rs` |
| PH2-09 | Add `driftBridgeGroundAll()` NAPI call after analysis completes | `analysis.rs` |
| PH2-10 | Verify bridge_memories table populated after `drift scan && drift analyze` | integration test |

**Quality gate:** After `drift scan . && drift analyze`, `bridge_memories` table has rows, `bridge_grounding_results` has scores.

### Phase 3: CLI Commands — 2-3 days

Add `drift bridge` subcommand group to the CLI.

| Task | Description |
|------|-------------|
| PH3-01 | `drift bridge status` — calls `driftBridgeStatus()`, shows license tier, availability, grounding config |
| PH3-02 | `drift bridge health` — calls `driftBridgeHealth()`, shows per-subsystem status |
| PH3-03 | `drift bridge memories [--type] [--limit]` — list bridge_memories with grounding verdicts |
| PH3-04 | `drift bridge ground [--memory-id]` — ground a single memory or all memories on-demand |
| PH3-05 | `drift bridge why <entity-type> <entity-id>` — "Why does this exist?" (calls drift_why tool) |
| PH3-06 | `drift bridge learn <entity-type> <entity-id> <correction>` — create learning memory |
| PH3-07 | `drift bridge events` — list all 21 event mappings with tier info |
| PH3-08 | `drift bridge intents` — list all 20 intents (10 analytical + 10 code) |
| PH3-09 | `drift bridge history <memory-id>` — grounding score history over time |
| PH3-10 | `drift bridge counterfactual <memory-id>` — "What if this didn't exist?" |
| PH3-11 | `drift bridge intervention <memory-id>` — "What if this changed?" |
| PH3-12 | `drift bridge narrative <memory-id>` — unified causal narrative (markdown) |
| PH3-13 | `drift bridge prune [--threshold 0.3]` — prune weak causal edges |
| PH3-14 | `drift bridge simulate` — synthesize events from current drift.db data, run full pipeline, report results |

**The `simulate` command is the key integration test:**
1. Read patterns from drift.db → synthesize `on_pattern_discovered` events
2. Read boundaries → synthesize `on_boundary_discovered` events
3. Run all events through BridgeEventHandler
4. Trigger grounding loop
5. Report: memories created, grounding scores, causal edges, contradictions

### Phase 4: MCP Tool Registration — 1-2 days

Register the 6 bridge tool handlers in the drift MCP server.

| Task | Description |
|------|-------------|
| PH4-01 | Add `drift_bridge_status` tool to MCP tool catalog | `drift-mcp/src/tools/` |
| PH4-02 | Add `drift_bridge_why` tool (wraps `driftBridgeWhy()`) | MCP tool |
| PH4-03 | Add `drift_bridge_learn` tool (wraps `driftBridgeMemoryLearn()`) | MCP tool |
| PH4-04 | Add `drift_bridge_ground` tool (wraps `driftBridgeGroundMemory()`) | MCP tool |
| PH4-05 | Add `drift_bridge_health` tool (wraps `driftBridgeHealth()`) | MCP tool |
| PH4-06 | Add `drift_bridge_counterfactual` tool | MCP tool |
| PH4-07 | Add `drift_bridge_intervention` tool | MCP tool |
| PH4-08 | Add `drift_bridge_narrative` tool | MCP tool |
| PH4-09 | Wire grounding into MCP `drift_scan` flow (auto-ground after scan+analyze) | MCP handler |
| PH4-10 | Update MCP tool count comments and catalog | MCP registry |

### Phase 5: CI Agent + Integration Testing — 2-3 days

| Task | Description |
|------|-------------|
| PH5-01 | Add bridge pass to CI agent (after analyze pass) | `drift-ci/src/index.ts` |
| PH5-02 | CI agent reports grounding snapshot in output | CI output |
| PH5-03 | Create E2E test: scan → analyze → bridge events → ground → verify | test file |
| PH5-04 | Create E2E test: learn correction → re-ground → verify confidence change | test file |
| PH5-05 | Create E2E test: counterfactual/intervention on bridge memories | test file |
| PH5-06 | Parity verification: all 20 NAPI functions callable from CLI, MCP, and CI | checklist |
| PH5-07 | Performance benchmark: grounding loop on 500+ memories | benchmark |
| PH5-08 | Add `--bridge` flag to `drift analyze` to enable/disable bridge pipeline | CLI flag |

---

## Part 4: Dependency Graph & Critical Path

```
Phase 1 (NAPI Wiring)          ← MUST be first
    ↓
Phase 2 (Event Pipeline)       ← Depends on Phase 1
    ↓
Phase 3 (CLI) ─────────────── ← Depends on Phase 1
    ↓                              (parallel with Phase 2)
Phase 4 (MCP) ─────────────── ← Depends on Phase 1
    ↓
Phase 5 (CI + E2E)            ← Depends on all above
```

**Critical path:** Phase 1 (3-4d) → Phase 2 (2-3d) → Phase 5 (2-3d) = **7-10 working days**
**With parallelism:** Phase 3 and Phase 4 can run alongside Phase 2 after Phase 1 lands.

**Minimum viable (bridge works end-to-end):** Phase 1 + Phase 2 = **5-7 days**
After this: `drift scan . && drift analyze` populates bridge_memories, grounding runs, confidence adjusts.

---

## Part 5: What's NOT In Scope

These are already built and tested (804 tests confirm). This plan is purely about **wiring** — connecting the working Rust engine to the TS presentation layer.

- No changes to grounding logic, scoring, or thresholds
- No changes to event mapping or memory creation
- No changes to causal edge builder or narrative
- No changes to storage schema or retention
- No changes to license gating or feature matrix
- No changes to evidence collection queries
- No new Rust source files in cortex-drift-bridge (except test files)

---

## Summary Stats

| Metric | Value |
|--------|-------|
| Source files | 49 |
| Source modules | 15 |
| NAPI functions | 20 |
| MCP tool handlers | 6 |
| Event mappings | 21 |
| Evidence types | 12 |
| License features | 25 |
| Code intents | 10 + 10 analytical |
| Storage tables | 5 |
| Existing tests | 804 |
| Plan tasks | 52 (impl) |
| Estimated time | 7-10 working days (5-7 minimum viable) |
