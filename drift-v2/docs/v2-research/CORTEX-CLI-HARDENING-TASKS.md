# Cortex CLI & Surface Area Hardening Tasks

> **Generated:** 2026-02-01 | **Status:** Draft | **Scope:** All Cortex accessibility gaps

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│  User-Facing Layers                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │
│  │  drift CLI   │  │  MCP Server  │  │   CI Agent   │              │
│  │  30 cortex   │  │  61 cortex   │  │  0 cortex    │              │
│  │  14 bridge   │  │  12 bridge   │  │  1 bridge    │              │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘              │
│         │                 │                 │                       │
│  ┌──────▼─────────────────▼─────────────────▼──────┐               │
│  │              TypeScript Bridge                    │               │
│  │  CortexClient (68 methods) + BridgeNAPI (20 fn) │               │
│  └──────────────────────┬────────────────────────────┘               │
│                         │                                           │
│  ┌──────────────────────▼────────────────────────────┐               │
│  │              Rust NAPI Layer                       │               │
│  │  cortex-napi (68 fns) + cortex-drift-bridge (20) │               │
│  └──────────────────────┬────────────────────────────┘               │
│                         │                                           │
│  ┌──────────────────────▼────────────────────────────┐               │
│  │              Cortex Rust Engine                    │               │
│  │  17 modules: memory, retrieval, causal, learning, │               │
│  │  consolidation, embeddings, decay, health,        │               │
│  │  generation, prediction, privacy, cloud, session, │               │
│  │  validation, temporal, multi-agent, observability │               │
│  └───────────────────────────────────────────────────┘               │
└─────────────────────────────────────────────────────────────────────┘
```

## Current State Summary

| Layer | Count | Coverage | Gap |
|---|---|---|---|
| Rust Engine (NAPI) | 68 functions | 100% | 0 |
| TS Bridge (CortexClient) | 68 methods | 100% | 0 |
| MCP Tools (cortex_tools.ts) | 61 tools | ~97% | 2 NAPI fns unreachable |
| MCP Server (drift-mcp) | 61 cortex + 12 bridge | 100% registered | 0 |
| CLI (drift cortex) | 30 subcommands | ~68% | 14 capabilities missing |
| CI Agent | 0 cortex passes | 0% | 2-3 passes needed |
| Build Chain | CI builds; local skips | ~90% | 1 local build fix |
| First-Run UX | No .cortex/ init | 0% | 1 fix in setup.ts |

---

## Verified Gap Inventory

### GAP-01: CI Agent Has Zero Cortex Passes (P1)

**Location:** `packages/drift-ci/src/agent.ts`
**Current state:** 10 analysis passes + 1 optional bridge pass. Zero Cortex integration.
**Passes today:** scan, patterns, call_graph, boundaries, security, tests, errors, contracts, constraints, enforcement, bridge.

**What's missing:**
- `cortex_health` pass — run `cortexHealthGetHealth()` + `cortexHealthGetDegradations()`, fail if degradations exceed threshold
- `cortex_validation` pass — run `cortexValidationRun()`, report candidate memories needing attention
- (Optional) `cortex_drift` pass — run `cortexTemporalGetDriftMetrics()` + `cortexTemporalGetDriftAlerts()`, report knowledge drift

**Impact:** CI has no visibility into Cortex memory health, even when Cortex is initialized.

### GAP-02: `drift setup` Does Not Create .cortex/ Directory (P1)

**Location:** `packages/drift-cli/src/commands/setup.ts`
**Current state:** Creates `.drift/` directory and `drift.db` via `driftInitialize()`. Does not touch Cortex at all.

**What's missing:**
- Create `.cortex/` directory alongside `.drift/`
- Call `cortexInitialize()` to create `cortex.db`
- Print Cortex status after initialization

**Impact:** First-time users get zero Cortex functionality until they manually initialize.

### GAP-03: 2 NAPI Functions Have No MCP Tool Wrapper (P1)

**Completely unreachable via MCP:**

| NAPI Function | CortexClient Method | MCP Tool | CLI |
|---|---|---|---|
| `cortexLearningAnalyzeCorrection` | `analyzeCorrection()` | **NONE** | **NONE** |
| `cortexConfigure` | `configure()` | **NONE** | **NONE** |

**Note:** Several other NAPI functions are *composited* into existing MCP tools (e.g., `cortexHealthGetDegradations` is bundled into `cortex_status`, `cortexConsolidationGetStatus` into `cortex_status`, `cortexHealthGetMetrics` and `cortexConsolidationGetMetrics` into `cortex_metrics`). These are reachable but not independently addressable.

### GAP-04: Local Build Chain Skips cortex-napi (P2)

**Location:** `package.json` (root)
**Current state:**
```json
"build": "npm run build:napi && npm run build:ts"
```
- `build:napi` only builds `drift-napi` (in `crates/drift/drift-napi`)
- `build:cortex-napi` exists as a standalone script but is NOT included in `build`
- CI **does** build cortex-napi (confirmed in `.github/workflows/ci.yml` lines 183-198)

**Impact:** Local `npm run build` produces no cortex-napi binary. Developers must manually run `npm run build:cortex-napi`.

### GAP-05: 14 CLI Subcommands Missing for Existing MCP Tool Capabilities (P3)

The following MCP tools have no CLI equivalent under `drift cortex`:

#### Temporal (6 missing)

| MCP Tool | What It Does | CLI Equivalent |
|---|---|---|
| `cortex_time_range` | Query memories valid during a time range | **NONE** |
| `cortex_temporal_causal` | Temporal-aware causal traversal | **NONE** |
| `cortex_view_create` | Create materialized knowledge snapshot | **NONE** |
| `cortex_view_get` | Get a materialized view by label | **NONE** |
| `cortex_view_list` | List all materialized views | **NONE** |
| `cortex_knowledge_health` | Knowledge drift metrics + alerts | **NONE** |

#### Multi-Agent (8 missing)

| MCP Tool | What It Does | CLI Equivalent |
|---|---|---|
| `cortex_agent_register` | Register new AI agent | **NONE** |
| `cortex_agent_deregister` | Deregister agent | **NONE** |
| `cortex_agent_get` | Get agent details | **NONE** |
| `cortex_agent_share` | Share memory to namespace | **NONE** |
| `cortex_agent_retract` | Retract shared memory | **NONE** |
| `cortex_agent_sync` | Sync between agents | **NONE** |
| `cortex_agent_trust` | Get trust scores | **NONE** |
| `cortex_agent_project` | Create projection | **NONE** |

**Existing CLI commands that partially cover multi-agent:**
- `drift cortex agents` — list agents (wraps `cortex_agent_list`)
- `drift cortex namespaces` — list/create namespaces (wraps `cortex_agent_namespace`)
- `drift cortex provenance <id>` — provenance + cross-agent trace (wraps `cortex_agent_provenance`)

### GAP-06: MCP→Bridge Event Gap (P2 — Design)

**Description:** When memories are created via Cortex MCP tools, the bridge grounding loop is not notified. Cortex and bridge operate as independent systems with no cross-event propagation.

**Impact:** Memories created via `cortex_memory_add` won't appear in bridge grounding snapshots until the next manual `drift bridge ground` or CI bridge pass.

**Resolution options:**
1. Fire a bridge event on cortex memory mutations (requires cross-crate wiring)
2. Have bridge grounding pull from cortex.db as an evidence source (already partially done)
3. Accept as design limitation — document it

---

## Implementation Plan

### Phase 1: First-Run UX + Build Chain (P1-P2) — ~1 day

| Task ID | Description | File | Priority |
|---|---|---|---|
| CH-01 | Add `.cortex/` dir creation to `drift setup` | `packages/drift-cli/src/commands/setup.ts` | P1 |
| CH-02 | Call `cortexInitialize()` during setup with cortex.db in `.cortex/` | `packages/drift-cli/src/commands/setup.ts` | P1 |
| CH-03 | Print Cortex init status after setup | `packages/drift-cli/src/commands/setup.ts` | P1 |
| CH-04 | Add `build:cortex-napi` to root `build` script | `package.json` | P2 |
| CH-T01 | Test: `drift setup` creates `.cortex/` directory | `packages/drift-cli/tests/` | P1 |
| CH-T02 | Test: `drift setup` initializes cortex.db | `packages/drift-cli/tests/` | P1 |
| CH-T03 | Test: `npm run build` includes cortex-napi | CI verification | P2 |

### Phase 2: CI Agent Cortex Passes (P1) — ~2 days

| Task ID | Description | File | Priority |
|---|---|---|---|
| CH-05 | Add `cortex_health` pass to `buildPasses()` | `packages/drift-ci/src/agent.ts` | P1 |
| CH-06 | Add `cortex_validation` pass to `buildPasses()` | `packages/drift-ci/src/agent.ts` | P1 |
| CH-07 | Add `cortexEnabled` flag to `CiAgentConfig` (default: `true`) | `packages/drift-ci/src/agent.ts` | P1 |
| CH-08 | Add `--no-cortex` flag to CI CLI entry point | `packages/drift-ci/src/index.ts` | P1 |
| CH-09 | Add `cortexSummary` to `AnalysisResult` interface | `packages/drift-ci/src/agent.ts` | P1 |
| CH-10 | (Optional) Add `cortex_drift` pass for knowledge drift alerting | `packages/drift-ci/src/agent.ts` | P2 |
| CH-11 | Update pass count comment: "11 passes" → "13 passes" | `packages/drift-ci/src/agent.ts` | P1 |
| CH-12 | Wire cortex pass results into PR comment output | `packages/drift-ci/src/index.ts` | P1 |
| CH-T04 | Test: cortex_health pass returns valid PassResult | `packages/drift-ci/tests/` | P1 |
| CH-T05 | Test: cortex_validation pass returns valid PassResult | `packages/drift-ci/tests/` | P1 |
| CH-T06 | Test: `--no-cortex` skips cortex passes | `packages/drift-ci/tests/` | P1 |
| CH-T07 | Test: cortex passes gracefully skip when Cortex not initialized | `packages/drift-ci/tests/` | P1 |
| CH-T08 | Test: cortexSummary populated in AnalysisResult | `packages/drift-ci/tests/` | P1 |
| CH-T09 | Test: pass count assertions updated (11→13) | `packages/drift-ci/tests/` | P1 |

### Phase 3: Missing MCP Tool Wrappers (P1) — ~0.5 day

| Task ID | Description | File | Priority |
|---|---|---|---|
| CH-13 | Add `cortex_analyze_correction` MCP tool | `packages/drift-mcp/src/tools/cortex_tools.ts` | P1 |
| CH-14 | Add `cortex_configure` MCP tool | `packages/drift-mcp/src/tools/cortex_tools.ts` | P1 |
| CH-15 | Add both to `CORTEX_CACHEABLE_TOOLS` or `CORTEX_MUTATION_TOOLS` set | `packages/drift-mcp/src/tools/cortex_tools.ts` | P1 |
| CH-16 | Update tool count comment: "61 Cortex MCP tools" → "63" | `packages/drift-mcp/src/tools/cortex_tools.ts` | P1 |
| CH-T10 | Test: cortex_analyze_correction handler returns LearningResult | MCP tests | P1 |
| CH-T11 | Test: cortex_configure handler returns config JSON | MCP tests | P1 |

### Phase 4: Missing CLI Subcommands — Temporal (P3) — ~1 day

| Task ID | Description | File | Priority |
|---|---|---|---|
| CH-17 | `drift cortex time-range` — query by time window | `packages/drift-cli/src/commands/cortex.ts` | P3 |
| CH-18 | `drift cortex temporal-causal` — temporal causal traversal | `packages/drift-cli/src/commands/cortex.ts` | P3 |
| CH-19 | `drift cortex view-create` — create materialized view | `packages/drift-cli/src/commands/cortex.ts` | P3 |
| CH-20 | `drift cortex view-get` — get materialized view | `packages/drift-cli/src/commands/cortex.ts` | P3 |
| CH-21 | `drift cortex view-list` — list materialized views | `packages/drift-cli/src/commands/cortex.ts` | P3 |
| CH-22 | `drift cortex knowledge-health` — drift metrics + alerts | `packages/drift-cli/src/commands/cortex.ts` | P3 |
| CH-T12 | Test: all 6 temporal subcommands registered | `packages/drift-cli/tests/` | P3 |
| CH-T13 | Test: each subcommand calls correct CortexClient method | `packages/drift-cli/tests/` | P3 |

### Phase 5: Missing CLI Subcommands — Multi-Agent (P3) — ~1 day

| Task ID | Description | File | Priority |
|---|---|---|---|
| CH-23 | `drift cortex agent-register` — register agent | `packages/drift-cli/src/commands/cortex.ts` | P3 |
| CH-24 | `drift cortex agent-deregister` — deregister agent | `packages/drift-cli/src/commands/cortex.ts` | P3 |
| CH-25 | `drift cortex agent-get` — get agent details | `packages/drift-cli/src/commands/cortex.ts` | P3 |
| CH-26 | `drift cortex agent-share` — share memory | `packages/drift-cli/src/commands/cortex.ts` | P3 |
| CH-27 | `drift cortex agent-retract` — retract memory | `packages/drift-cli/src/commands/cortex.ts` | P3 |
| CH-28 | `drift cortex agent-sync` — sync agents | `packages/drift-cli/src/commands/cortex.ts` | P3 |
| CH-29 | `drift cortex agent-trust` — trust scores | `packages/drift-cli/src/commands/cortex.ts` | P3 |
| CH-30 | `drift cortex agent-project` — create projection | `packages/drift-cli/src/commands/cortex.ts` | P3 |
| CH-T14 | Test: all 8 multi-agent subcommands registered | `packages/drift-cli/tests/` | P3 |
| CH-T15 | Test: each subcommand calls correct CortexClient method | `packages/drift-cli/tests/` | P3 |

### Phase 6: MCP→Bridge Event Gap (P2 — Design Decision) — ~1 day

| Task ID | Description | File | Priority |
|---|---|---|---|
| CH-31 | Design decision: choose resolution approach (see GAP-06 options) | Architecture doc | P2 |
| CH-32 | Implement chosen approach | TBD based on decision | P2 |
| CH-T16 | Test: cortex memory mutation triggers bridge awareness | TBD | P2 |

---

## Full CLI Parity Matrix

### Existing CLI Subcommands (30)

| # | CLI Command | MCP Tool(s) | CortexClient Method(s) |
|---|---|---|---|
| 1 | `cortex status` | `cortex_status` | `healthReport()`, `consolidationStatus()`, `degradations()` |
| 2 | `cortex search <query>` | `cortex_memory_search` | `memorySearch()` |
| 3 | `cortex get <id>` | `cortex_memory_get` | `memoryGet()` |
| 4 | `cortex list` | `cortex_memory_list` | `memoryList()` |
| 5 | `cortex delete <id>` | `cortex_memory_delete` | `memoryDelete()` |
| 6 | `cortex restore <id>` | `cortex_memory_restore` | `memoryRestore()` |
| 7 | `cortex add <type>` | `cortex_memory_add` | `memoryCreate()` |
| 8 | `cortex why <id>` | `cortex_why` | `causalGetWhy()` |
| 9 | `cortex explain <id>` | `cortex_explain` | `causalGetWhy()` + `causalTraverse()` |
| 10 | `cortex learn <correction>` | `cortex_learn` | `learn()` |
| 11 | `cortex predict` | `cortex_predict` | `predict()` |
| 12 | `cortex sanitize <text>` | `cortex_privacy_sanitize` | `sanitize()` |
| 13 | `cortex cloud-sync` | `cortex_cloud_sync` | `cloudSync()` |
| 14 | `cortex cloud-status` | `cortex_cloud_status` | `cloudStatus()` |
| 15 | `cortex session-create` | `cortex_session_create` | `sessionCreate()` |
| 16 | `cortex time-travel` | `cortex_time_travel` | `queryAsOf()` |
| 17 | `cortex gc` | `cortex_gc` | `decayRun()`, `sessionCleanup()` |
| 18 | `cortex consolidate` | `cortex_consolidate` | `consolidate()` |
| 19 | `cortex export` | `cortex_export` | `memoryList()` |
| 20 | `cortex agents` | `cortex_agent_list` | `listAgents()` |
| 21 | `cortex import <file>` | `cortex_import` | `memoryCreate()` (loop) |
| 22 | `cortex metrics` | `cortex_metrics` | `consolidationMetrics()`, `healthMetrics()`, `cacheStats()` |
| 23 | `cortex reembed` | `cortex_reembed` | `reembed()` |
| 24 | `cortex timeline` | `cortex_knowledge_timeline` | via tool registry |
| 25 | `cortex diff` | `cortex_time_diff` | `queryDiff()` |
| 26 | `cortex replay <id>` | `cortex_time_replay` | `replayDecision()` |
| 27 | `cortex namespaces` | `cortex_agent_namespace` | `createNamespace()`, `listAgents()` |
| 28 | `cortex provenance <id>` | `cortex_agent_provenance` | `getProvenance()`, `traceCrossAgent()` |
| 29 | `cortex decay` | — | `decayRun()` |
| 30 | `cortex validate` | `cortex_validate_system` | `validationRun()` |

### Missing CLI Subcommands (14)

| # | Proposed CLI Command | MCP Tool | CortexClient Method |
|---|---|---|---|
| 31 | `cortex time-range` | `cortex_time_range` | `queryRange()` |
| 32 | `cortex temporal-causal` | `cortex_temporal_causal` | `queryTemporalCausal()` |
| 33 | `cortex view-create` | `cortex_view_create` | `createMaterializedView()` |
| 34 | `cortex view-get` | `cortex_view_get` | `getMaterializedView()` |
| 35 | `cortex view-list` | `cortex_view_list` | `listMaterializedViews()` |
| 36 | `cortex knowledge-health` | `cortex_knowledge_health` | `getDriftMetrics()`, `getDriftAlerts()` |
| 37 | `cortex agent-register` | `cortex_agent_register` | `registerAgent()` |
| 38 | `cortex agent-deregister` | `cortex_agent_deregister` | `deregisterAgent()` |
| 39 | `cortex agent-get` | `cortex_agent_get` | `getAgent()` |
| 40 | `cortex agent-share` | `cortex_agent_share` | `shareMemory()` |
| 41 | `cortex agent-retract` | `cortex_agent_retract` | `retractMemory()` |
| 42 | `cortex agent-sync` | `cortex_agent_sync` | `syncAgents()` |
| 43 | `cortex agent-trust` | `cortex_agent_trust` | `getTrust()` |
| 44 | `cortex agent-project` | `cortex_agent_project` | `createProjection()` |

---

## Full MCP Tool Inventory (61)

### All registered tools with cache classification:

| Category | Tool Name | Cache | Mutation |
|---|---|---|---|
| **Memory (9)** | `cortex_memory_add` | | ✓ |
| | `cortex_memory_search` | ✓ | |
| | `cortex_memory_get` | ✓ | |
| | `cortex_memory_update` | | ✓ |
| | `cortex_memory_delete` | | ✓ |
| | `cortex_memory_list` | ✓ | |
| | `cortex_memory_link` | | ✓ |
| | `cortex_memory_unlink` | | ✓ |
| | `cortex_memory_restore` | | ✓ |
| **Retrieval (3)** | `cortex_context` | ✓ | |
| | `cortex_search` | ✓ | |
| | `cortex_related` | ✓ | |
| **Causal (5)** | `cortex_why` | ✓ | |
| | `cortex_explain` | ✓ | |
| | `cortex_counterfactual` | ✓ | |
| | `cortex_intervention` | ✓ | |
| | `cortex_causal_infer` | ✓ | |
| **Learning (3)** | `cortex_learn` | | ✓ |
| | `cortex_feedback` | | ✓ |
| | `cortex_validate` | ✓ | |
| **Generation (2)** | `cortex_gen_context` | ✓ | |
| | `cortex_gen_outcome` | | ✓ |
| **System (8)** | `cortex_status` | ✓ | |
| | `cortex_metrics` | ✓ | |
| | `cortex_consolidate` | | ✓ |
| | `cortex_validate_system` | ✓ | |
| | `cortex_gc` | | ✓ |
| | `cortex_export` | ✓ | |
| | `cortex_import` | | ✓ |
| | `cortex_reembed` | | ✓ |
| **Privacy (2)** | `cortex_privacy_sanitize` | | ✓ |
| | `cortex_privacy_stats` | ✓ | |
| **Cloud (3)** | `cortex_cloud_sync` | | ✓ |
| | `cortex_cloud_status` | ✓ | |
| | `cortex_cloud_resolve` | | ✓ |
| **Session (3)** | `cortex_session_create` | | ✓ |
| | `cortex_session_get` | ✓ | |
| | `cortex_session_analytics` | ✓ | |
| **Prediction (2)** | `cortex_predict` | ✓ | |
| | `cortex_preload` | ✓ | |
| **Temporal (10)** | `cortex_time_travel` | ✓ | |
| | `cortex_time_diff` | ✓ | |
| | `cortex_time_replay` | ✓ | |
| | `cortex_knowledge_health` | ✓ | |
| | `cortex_knowledge_timeline` | ✓ | |
| | `cortex_time_range` | ✓ | |
| | `cortex_temporal_causal` | ✓ | |
| | `cortex_view_create` | | ✓ |
| | `cortex_view_get` | ✓ | |
| | `cortex_view_list` | ✓ | |
| **Multi-Agent (11)** | `cortex_agent_register` | | ✓ |
| | `cortex_agent_share` | | ✓ |
| | `cortex_agent_project` | | ✓ |
| | `cortex_agent_provenance` | ✓ | |
| | `cortex_agent_trust` | ✓ | |
| | `cortex_agent_deregister` | | ✓ |
| | `cortex_agent_get` | ✓ | |
| | `cortex_agent_list` | ✓ | |
| | `cortex_agent_namespace` | | ✓ |
| | `cortex_agent_retract` | | ✓ |
| | `cortex_agent_sync` | | ✓ |

**Total: 61 tools (35 cacheable, 26 mutations)**

### Missing MCP tools (2)

| NAPI Function | CortexClient Method | Proposed Tool Name |
|---|---|---|
| `cortexLearningAnalyzeCorrection` | `analyzeCorrection()` | `cortex_analyze_correction` |
| `cortexConfigure` | `configure()` | `cortex_configure` |

---

## NAPI → CortexClient → MCP → CLI Coverage Matrix

| NAPI Function | Client | MCP | CLI | Gap |
|---|---|---|---|---|
| `cortexInitialize` | ✓ | — | via setup | — |
| `cortexShutdown` | ✓ | — | — | lifecycle only |
| `cortexConfigure` | ✓ | **NONE** | **NONE** | **GAP-03** |
| `cortexMemoryCreate` | ✓ | ✓ | ✓ add | — |
| `cortexMemoryGet` | ✓ | ✓ | ✓ get | — |
| `cortexMemoryUpdate` | ✓ | ✓ | — | — (MCP-only) |
| `cortexMemoryDelete` | ✓ | ✓ | ✓ delete | — |
| `cortexMemorySearch` | ✓ | ✓ | ✓ search | — |
| `cortexMemoryList` | ✓ | ✓ | ✓ list | — |
| `cortexMemoryArchive` | ✓ | via delete | via delete | — |
| `cortexMemoryRestore` | ✓ | ✓ | ✓ restore | — |
| `cortexRetrievalRetrieve` | ✓ | via context | — | — |
| `cortexRetrievalSearch` | ✓ | ✓ | via search | — |
| `cortexRetrievalGetContext` | ✓ | ✓ | — | — |
| `cortexCausalInferCause` | ✓ | ✓ | — | — |
| `cortexCausalTraverse` | ✓ | ✓ | via explain | — |
| `cortexCausalGetWhy` | ✓ | ✓ | ✓ why | — |
| `cortexCausalCounterfactual` | ✓ | ✓ | — | — |
| `cortexCausalIntervention` | ✓ | ✓ | — | — |
| `cortexLearningAnalyzeCorrection` | ✓ | **NONE** | **NONE** | **GAP-03** |
| `cortexLearningLearn` | ✓ | ✓ | ✓ learn | — |
| `cortexLearningGetValidationCandidates` | ✓ | ✓ | — | — |
| `cortexLearningProcessFeedback` | ✓ | ✓ | — | — |
| `cortexConsolidationConsolidate` | ✓ | ✓ | ✓ consolidate | — |
| `cortexConsolidationGetMetrics` | ✓ | via metrics | ✓ metrics | — |
| `cortexConsolidationGetStatus` | ✓ | via status | ✓ status | — |
| `cortexReembed` | ✓ | ✓ | ✓ reembed | — |
| `cortexDecayRun` | ✓ | via gc | ✓ decay/gc | — |
| `cortexHealthGetHealth` | ✓ | via status | ✓ status | — |
| `cortexHealthGetMetrics` | ✓ | via metrics | ✓ metrics | — |
| `cortexHealthGetDegradations` | ✓ | via status | ✓ status | — |
| `cortexGenerationBuildContext` | ✓ | ✓ | — | — |
| `cortexGenerationTrackOutcome` | ✓ | ✓ | — | — |
| `cortexPredictionPredict` | ✓ | ✓ | ✓ predict | — |
| `cortexPredictionPreload` | ✓ | ✓ | — | — |
| `cortexPredictionGetCacheStats` | ✓ | via metrics | ✓ metrics | — |
| `cortexPrivacySanitize` | ✓ | ✓ | ✓ sanitize | — |
| `cortexPrivacyGetPatternStats` | ✓ | ✓ | — | — |
| `cortexCloudSync` | ✓ | ✓ | ✓ cloud-sync | — |
| `cortexCloudGetStatus` | ✓ | ✓ | ✓ cloud-status | — |
| `cortexCloudResolveConflict` | ✓ | ✓ | — | — |
| `cortexSessionCreate` | ✓ | ✓ | ✓ session-create | — |
| `cortexSessionGet` | ✓ | ✓ | — | — |
| `cortexSessionCleanup` | ✓ | via gc | ✓ gc | — |
| `cortexSessionAnalytics` | ✓ | ✓ | — | — |
| `cortexValidationRun` | ✓ | ✓ | ✓ validate | — |
| `cortexTemporalQueryAsOf` | ✓ | ✓ | ✓ time-travel | — |
| `cortexTemporalQueryRange` | ✓ | ✓ | **NONE** | **GAP-05** |
| `cortexTemporalQueryDiff` | ✓ | ✓ | ✓ diff | — |
| `cortexTemporalReplayDecision` | ✓ | ✓ | ✓ replay | — |
| `cortexTemporalQueryTemporalCausal` | ✓ | ✓ | **NONE** | **GAP-05** |
| `cortexTemporalGetDriftMetrics` | ✓ | via health | **NONE** | **GAP-05** |
| `cortexTemporalGetDriftAlerts` | ✓ | via health | **NONE** | **GAP-05** |
| `cortexTemporalCreateMaterializedView` | ✓ | ✓ | **NONE** | **GAP-05** |
| `cortexTemporalGetMaterializedView` | ✓ | ✓ | **NONE** | **GAP-05** |
| `cortexTemporalListMaterializedViews` | ✓ | ✓ | **NONE** | **GAP-05** |
| `cortexMultiagentRegisterAgent` | ✓ | ✓ | **NONE** | **GAP-05** |
| `cortexMultiagentDeregisterAgent` | ✓ | ✓ | **NONE** | **GAP-05** |
| `cortexMultiagentGetAgent` | ✓ | ✓ | **NONE** | **GAP-05** |
| `cortexMultiagentListAgents` | ✓ | ✓ | ✓ agents | — |
| `cortexMultiagentCreateNamespace` | ✓ | ✓ | ✓ namespaces | — |
| `cortexMultiagentShareMemory` | ✓ | ✓ | **NONE** | **GAP-05** |
| `cortexMultiagentCreateProjection` | ✓ | ✓ | **NONE** | **GAP-05** |
| `cortexMultiagentRetractMemory` | ✓ | ✓ | **NONE** | **GAP-05** |
| `cortexMultiagentGetProvenance` | ✓ | ✓ | ✓ provenance | — |
| `cortexMultiagentTraceCrossAgent` | ✓ | ✓ | ✓ provenance | — |
| `cortexMultiagentGetTrust` | ✓ | ✓ | **NONE** | **GAP-05** |
| `cortexMultiagentSyncAgents` | ✓ | ✓ | **NONE** | **GAP-05** |

---

## Effort Estimate

| Phase | Tasks | Tests | Estimated Time |
|---|---|---|---|
| Phase 1: First-Run UX + Build Chain | 4 impl | 3 tests | ~1 day |
| Phase 2: CI Agent Cortex Passes | 8 impl | 6 tests | ~2 days |
| Phase 3: Missing MCP Tools | 4 impl | 2 tests | ~0.5 day |
| Phase 4: CLI — Temporal | 6 impl | 2 tests | ~1 day |
| Phase 5: CLI — Multi-Agent | 8 impl | 2 tests | ~1 day |
| Phase 6: MCP→Bridge Event Gap | 2 impl | 1 test | ~1 day |
| **Total** | **32 impl** | **16 tests** | **~6.5 days** |

**Critical path:** Phase 1 + Phase 2 + Phase 3 = **~3.5 days** (all P1 work)

**Parallelizable:** Phase 4 ∥ Phase 5 (independent CLI additions)

---

## Post-Completion Target State

| Layer | Before | After |
|---|---|---|
| CLI subcommands | 30 | 44 |
| MCP tools | 61 | 63 |
| CI passes | 11 (0 cortex) | 13 (2 cortex) |
| Build chain | CI-only cortex-napi | CI + local |
| First-run UX | No cortex init | Auto cortex init |
| NAPI coverage | 66/68 reachable | 68/68 reachable |
