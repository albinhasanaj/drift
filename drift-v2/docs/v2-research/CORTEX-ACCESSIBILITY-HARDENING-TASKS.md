# Cortex Accessibility Hardening — Implementation Tracker

> **Source of Truth:** Full audit of `crates/cortex/cortex-napi/src/bindings/*.rs` (17 modules, 68 exported `#[napi]` functions), `packages/cortex/src/` (bridge + 40 tools + 20 CLI commands), `packages/drift-mcp/src/` (6 MCP entry points + ~41 internal tools), `packages/drift-cli/src/` (26 CLI commands), `crates/cortex-drift-bridge/src/` (20 NAPI-ready bridge functions + 6 MCP tool handlers)
> **Core Finding:** The Cortex Rust engine is fully functional with 68 NAPI bindings wired to real code. The TS bridge (`CortexClient`) exposes all 68. The internal tool layer covers 40 of them. **But ZERO Cortex capabilities are accessible via the drift MCP server or drift CLI** — they exist only in the standalone `packages/cortex` package which has no MCP server and no integration with other packages. Additionally, the `cortex-drift-bridge` crate has 20 NAPI-ready functions and 6 MCP tool handlers with ZERO TypeScript exposure.
> **Total Phases:** 5 (A–E)
> **Quality Gates:** 5 (QG-A through QG-E)
> **Rule:** No Phase N+1 begins until Phase N quality gate passes.

---

## How To Use This Document

- Agents: check off `[ ]` → `[x]` as you complete each task
- Every implementation task has a unique ID: `CX-{system}-{number}` (CX = Cortex Accessibility)
- Every test task has a unique ID: `CT-{system}-{number}` (CT = Cortex Test)
- Quality gates are pass/fail — all criteria must pass before proceeding
- For NAPI ground truth → `crates/cortex/cortex-napi/src/bindings/*.rs`
- For TS bridge ground truth → `packages/cortex/src/bridge/client.ts`
- For tool ground truth → `packages/cortex/src/tools/index.ts`

---

## Executive Summary

### What Exists (Working)

| Layer | Count | Status |
|-------|-------|--------|
| **Rust NAPI bindings** (`cortex-napi/src/bindings/`) | 68 functions across 17 modules | ✅ All wired to real engines |
| **TS NativeBindings interface** (`bridge/index.ts`) | 68 function signatures | ✅ Matches Rust exports |
| **CortexClient methods** (`bridge/client.ts`) | 68 typed async methods | ✅ All delegate to NAPI |
| **MCP Tool definitions** (`tools/`) | 40 tools in 9 categories | ✅ All call CortexClient |
| **CLI commands** (`cli/`) | 20 commands | ✅ All call CortexClient |
| **CLI binary entry** (`package.json` bin) | `drift-cortex` | ✅ Declared |
| **Test coverage** (`tests/`) | 7 test files (bridge + 5 tools + 2 CLI) | ✅ Mocked NAPI |
| **Vitest config** | 80% coverage thresholds | ✅ Configured |
| **Workspace membership** | In root `workspaces` array | ✅ Present |

### What's Inaccessible (The Gap)

| Gap | Impact | Severity |
|-----|--------|----------|
| **No Cortex MCP server** — `packages/cortex` has tools but no MCP server binary. The drift MCP server (`packages/drift-mcp`) has zero Cortex integration. | AI agents via MCP cannot access ANY of the 40 Cortex tools | **P0** |
| **No `drift-cortex-napi` native binary** — `packages/cortex/package.json` lists `drift-cortex-napi` as optionalDependency but no such package exists. No Cargo.toml builds it. `loadNativeModule()` throws (no stub fallback). | **Nothing works** — every CortexClient call will throw | **P0** |
| **`build:cortex` omitted from build chain** — Root `package.json` `build:ts` runs contracts→core→cli→mcp→ci but **skips cortex**. `npm run build` never builds cortex. | Cortex TS never compiles in CI/CD | **P0** |
| **No `cortex` subcommand in drift CLI** — `packages/drift-cli` has 26 commands, none invoke Cortex. | Users running `drift` cannot access Cortex | **P0** |
| **drift MCP `drift_tool` catalog has 0 Cortex tools** — All ~41 internal tools are drift-analysis only | AI agents using drift MCP get zero memory capabilities | **P1** |
| **No Cortex NAPI contracts package** — drift has `@drift/napi-contracts`, Cortex has none. Each consumer re-declares types. | Type drift between consumers | **P1** |
| **CortexClient not importable from drift packages** — No dependency from `drift-mcp`/`drift-cli` → `@drift/cortex` | Cannot wire without adding dependency | **P1** |
| **`cortex-drift-bridge` 20 functions + 6 tools completely inaccessible** — `crates/cortex-drift-bridge/src/napi/functions.rs` has 20 NAPI-ready bridge functions (grounding, licensing, link translation, causal narrative, spec corrections). `tools/` has 6 MCP handlers. No TS bindings exist for any of them. | Bridge-specific features (grounding, licensing, unified narrative) invisible to users/agents | **P1** |
| **CI agent has 0 Cortex passes** — 10 passes use `@drift/napi-contracts` only, zero Cortex integration | CI never validates memory system health | **P1** |
| **21 NAPI capabilities have no tool wrapper** — See detailed matrix below | AI agents miss 21 capabilities even if MCP server existed | **P2** |
| **7 CLI commands missing** — See detailed matrix below | Users miss 7 capabilities even if binary existed | **P2** |
| **Session management not exposed via any tool** — 4 session NAPI functions have no tool or CLI | Sessions are invisible to users/agents | **P2** |
| **Cloud sync not exposed via any tool** — 3 cloud NAPI functions have no tool or CLI | Cloud features are invisible | **P2** |
| **Privacy not exposed via any tool** — 2 privacy NAPI functions have no tool or CLI | Sanitization is invisible | **P2** |

---

## Complete Capability Matrix

### Legend
- ✅ = Exists and works
- ❌ = Missing entirely
- 🔧 = Exists but needs fixes
- N/A = Not applicable for this layer

### Layer 1: Rust NAPI → TS Bridge (All 68 Functions)

All 68 NAPI functions have matching `NativeBindings` entries and `CortexClient` methods. **This layer is 100% complete.**

### Layer 2: TS Tools (40 of 65 user-facing covered → 21 gaps, 3 lifecycle N/A)

| # | NAPI Function | CortexClient Method | MCP Tool | Gap? |
|---|--------------|-------------------|----------|------|
| | **Lifecycle (3)** | | | |
| 1 | `cortex_initialize` | `initialize()` | N/A (internal) | — |
| 2 | `cortex_shutdown` | `shutdown()` | N/A (internal) | — |
| 3 | `cortex_configure` | `configure()` | N/A (internal) | — |
| | **Memory CRUD (8)** | | | |
| 4 | `cortex_memory_create` | `memoryCreate()` | `drift_memory_add` | ✅ |
| 5 | `cortex_memory_get` | `memoryGet()` | `drift_memory_get` | ✅ |
| 6 | `cortex_memory_update` | `memoryUpdate()` | `drift_memory_update` | ✅ |
| 7 | `cortex_memory_delete` | `memoryDelete()` | `drift_memory_delete` | ✅ |
| 8 | `cortex_memory_search` | `memorySearch()` | `drift_memory_search` | ✅ |
| 9 | `cortex_memory_list` | `memoryList()` | `drift_memory_list` | ✅ |
| 10 | `cortex_memory_archive` | `memoryArchive()` | (via `drift_cortex_gc`) | ✅ |
| 11 | `cortex_memory_restore` | `memoryRestore()` | ❌ **No tool** | **GAP** |
| | **Retrieval (3)** | | | |
| 12 | `cortex_retrieval_retrieve` | `retrieve()` | `drift_context` | ✅ |
| 13 | `cortex_retrieval_search` | `search()` | `drift_search` | ✅ |
| 14 | `cortex_retrieval_get_context` | `getContext()` | (via `drift_context`) | ✅ |
| | **Causal (5)** | | | |
| 15 | `cortex_causal_infer_cause` | `causalInfer()` | ❌ **No tool** | **GAP** |
| 16 | `cortex_causal_traverse` | `causalTraverse()` | `drift_related` | ✅ |
| 17 | `cortex_causal_get_why` | `causalGetWhy()` | `drift_why` | ✅ |
| 18 | `cortex_causal_counterfactual` | `causalCounterfactual()` | `drift_counterfactual` | ✅ |
| 19 | `cortex_causal_intervention` | `causalIntervention()` | `drift_intervention` | ✅ |
| | **Learning (4)** | | | |
| 20 | `cortex_learning_analyze_correction` | `analyzeCorrection()` | `drift_memory_learn` | ✅ |
| 21 | `cortex_learning_learn` | `learn()` | (alias of above) | ✅ |
| 22 | `cortex_learning_get_validation_candidates` | `getValidationCandidates()` | `drift_validate` | ✅ |
| 23 | `cortex_learning_process_feedback` | `processFeedback()` | `drift_feedback` | ✅ |
| | **Consolidation (3)** | | | |
| 24 | `cortex_consolidation_consolidate` | `consolidate()` | `drift_cortex_consolidate` | ✅ |
| 25 | `cortex_consolidation_get_metrics` | `consolidationMetrics()` | `drift_cortex_metrics` | ✅ |
| 26 | `cortex_consolidation_get_status` | `consolidationStatus()` | `drift_cortex_status` | ✅ |
| | **Embeddings (1)** | | | |
| 27 | `cortex_reembed` | `reembed()` | `drift_cortex_reembed` | ✅ |
| | **Decay (1)** | | | |
| 28 | `cortex_decay_run` | `decayRun()` | (via `drift_cortex_gc`) | ✅ |
| | **Health (3)** | | | |
| 29 | `cortex_health_get_health` | `healthReport()` | `drift_cortex_status` | ✅ |
| 30 | `cortex_health_get_metrics` | `healthMetrics()` | `drift_cortex_metrics` | ✅ |
| 31 | `cortex_health_get_degradations` | `degradations()` | `drift_cortex_status` | ✅ |
| | **Generation (2)** | | | |
| 32 | `cortex_generation_build_context` | `buildGenerationContext()` | `drift_gen_context` | ✅ |
| 33 | `cortex_generation_track_outcome` | `trackOutcome()` | `drift_gen_outcome` | ✅ |
| | **Prediction (3)** | | | |
| 34 | `cortex_prediction_predict` | `predict()` | `drift_predict` | ✅ |
| 35 | `cortex_prediction_preload` | `preload()` | `drift_preload` | ✅ |
| 36 | `cortex_prediction_get_cache_stats` | `cacheStats()` | `drift_cortex_metrics` | ✅ |
| | **Privacy (2)** | | | |
| 37 | `cortex_privacy_sanitize` | `sanitize()` | ❌ **No tool** | **GAP** |
| 38 | `cortex_privacy_get_pattern_stats` | `patternStats()` | ❌ **No tool** | **GAP** |
| | **Cloud (3)** | | | |
| 39 | `cortex_cloud_sync` | `cloudSync()` | ❌ **No tool** | **GAP** |
| 40 | `cortex_cloud_get_status` | `cloudStatus()` | ❌ **No tool** | **GAP** |
| 41 | `cortex_cloud_resolve_conflict` | `cloudResolveConflict()` | ❌ **No tool** | **GAP** |
| | **Session (4)** | | | |
| 42 | `cortex_session_create` | `sessionCreate()` | ❌ **No tool** | **GAP** |
| 43 | `cortex_session_get` | `sessionGet()` | ❌ **No tool** | **GAP** |
| 44 | `cortex_session_cleanup` | `sessionCleanup()` | (via `drift_cortex_gc`) | ✅ |
| 45 | `cortex_session_analytics` | `sessionAnalytics()` | ❌ **No tool** | **GAP** |
| | **Validation (1)** | | | |
| 46 | `cortex_validation_run` | `validationRun()` | `drift_cortex_validate` | ✅ |
| | **Temporal (10)** | | | |
| 47 | `cortex_temporal_query_as_of` | `queryAsOf()` | `drift_time_travel` | ✅ |
| 48 | `cortex_temporal_query_range` | `queryRange()` | ❌ **No tool** | **GAP** |
| 49 | `cortex_temporal_query_diff` | `queryDiff()` | `drift_time_diff` | ✅ |
| 50 | `cortex_temporal_replay_decision` | `replayDecision()` | `drift_time_replay` | ✅ |
| 51 | `cortex_temporal_query_temporal_causal` | `queryTemporalCausal()` | ❌ **No tool** | **GAP** |
| 52 | `cortex_temporal_get_drift_metrics` | `getDriftMetrics()` | `drift_knowledge_health` | ✅ |
| 53 | `cortex_temporal_get_drift_alerts` | `getDriftAlerts()` | `drift_knowledge_health` | ✅ |
| 54 | `cortex_temporal_create_materialized_view` | `createMaterializedView()` | ❌ **No tool** | **GAP** |
| 55 | `cortex_temporal_get_materialized_view` | `getMaterializedView()` | ❌ **No tool** | **GAP** |
| 56 | `cortex_temporal_list_materialized_views` | `listMaterializedViews()` | ❌ **No tool** | **GAP** |
| | **Multi-Agent (12)** | | | |
| 57 | `cortex_multiagent_register_agent` | `registerAgent()` | `drift_agent_register` | ✅ |
| 58 | `cortex_multiagent_deregister_agent` | `deregisterAgent()` | ❌ **No tool** | **GAP** |
| 59 | `cortex_multiagent_get_agent` | `getAgent()` | ❌ **No tool** | **GAP** |
| 60 | `cortex_multiagent_list_agents` | `listAgents()` | ❌ **No tool** | **GAP** |
| 61 | `cortex_multiagent_create_namespace` | `createNamespace()` | ❌ **No tool** | **GAP** |
| 62 | `cortex_multiagent_share_memory` | `shareMemory()` | `drift_agent_share` | ✅ |
| 63 | `cortex_multiagent_create_projection` | `createProjection()` | `drift_agent_project` | ✅ |
| 64 | `cortex_multiagent_retract_memory` | `retractMemory()` | ❌ **No tool** | **GAP** |
| 65 | `cortex_multiagent_get_provenance` | `getProvenance()` | `drift_agent_provenance` | ✅ |
| 66 | `cortex_multiagent_trace_cross_agent` | `traceCrossAgent()` | `drift_agent_provenance` | ✅ |
| 67 | `cortex_multiagent_get_trust` | `getTrust()` | `drift_agent_trust` | ✅ |
| 68 | `cortex_multiagent_sync_agents` | `syncAgents()` | ❌ **No tool** | **GAP** |

### Tool Gap Summary: 21 NAPI functions without dedicated MCP tools

| Category | Missing Tool | NAPI Function |
|----------|-------------|--------------|
| Memory | `drift_memory_restore` | `cortex_memory_restore` |
| Causal | `drift_causal_infer` | `cortex_causal_infer_cause` |
| Privacy | `drift_privacy_sanitize` | `cortex_privacy_sanitize` |
| Privacy | `drift_privacy_stats` | `cortex_privacy_get_pattern_stats` |
| Cloud | `drift_cloud_sync` | `cortex_cloud_sync` |
| Cloud | `drift_cloud_status` | `cortex_cloud_get_status` |
| Cloud | `drift_cloud_resolve` | `cortex_cloud_resolve_conflict` |
| Session | `drift_session_create` | `cortex_session_create` |
| Session | `drift_session_get` | `cortex_session_get` |
| Session | `drift_session_analytics` | `cortex_session_analytics` |
| Temporal | `drift_time_range` | `cortex_temporal_query_range` |
| Temporal | `drift_temporal_causal` | `cortex_temporal_query_temporal_causal` |
| Temporal | `drift_view_create` | `cortex_temporal_create_materialized_view` |
| Temporal | `drift_view_get` | `cortex_temporal_get_materialized_view` |
| Temporal | `drift_view_list` | `cortex_temporal_list_materialized_views` |
| Multi-Agent | `drift_agent_deregister` | `cortex_multiagent_deregister_agent` |
| Multi-Agent | `drift_agent_get` | `cortex_multiagent_get_agent` |
| Multi-Agent | `drift_agent_list` | `cortex_multiagent_list_agents` |
| Multi-Agent | `drift_agent_namespace` | `cortex_multiagent_create_namespace` |
| Multi-Agent | `drift_agent_retract` | `cortex_multiagent_retract_memory` |
| Multi-Agent | `drift_agent_sync` | `cortex_multiagent_sync_agents` |

### Layer 3: CLI Commands (20 of 27 needed → 7 gaps)

| # | CLI Command | CortexClient Method | Status |
|---|------------|-------------------|--------|
| 1 | `status` | `healthReport()` + `consolidationStatus()` + `degradations()` | ✅ |
| 2 | `search <query>` | `search()` | ✅ |
| 3 | `why <file|pattern>` | `causalGetWhy()` | ✅ |
| 4 | `explain <memory-id>` | `memoryGet()` + `causalGetWhy()` + `causalTraverse()` | ✅ |
| 5 | `add <type>` | `memoryCreate()` | ✅ |
| 6 | `learn` | `learn()` | ✅ |
| 7 | `consolidate` | `consolidate()` | ✅ |
| 8 | `validate` | `validationRun()` | ✅ |
| 9 | `export` | `memoryList()` | ✅ |
| 10 | `import <file>` | `memoryCreate()` | ✅ |
| 11 | `gc` | `decayRun()` + `sessionCleanup()` + `memoryArchive()` | ✅ |
| 12 | `metrics` | `consolidationMetrics()` + `healthMetrics()` + `cacheStats()` | ✅ |
| 13 | `reembed` | `reembed()` | ✅ |
| 14 | `timeline` | `getDriftMetrics()` | ✅ |
| 15 | `diff` | `queryDiff()` | ✅ |
| 16 | `replay <id>` | `replayDecision()` | ✅ |
| 17 | `agents <sub>` | `registerAgent()` + `listAgents()` + `deregisterAgent()` + `getAgent()` | ✅ |
| 18 | `namespaces <sub>` | `createNamespace()` + `listAgents()` | ✅ |
| 19 | `provenance <id>` | `getProvenance()` + `traceCrossAgent()` | ✅ |
| 20 | `predict` | ❌ **Missing** | **GAP** |
| 21 | `sanitize` | ❌ **Missing** | **GAP** |
| 22 | `cloud` | ❌ **Missing** | **GAP** |
| 23 | `session` | ❌ **Missing** | **GAP** |
| 24 | `restore <id>` | ❌ **Missing** | **GAP** |
| 25 | `decay` | ❌ **Missing** (standalone, not just via gc) | **GAP** |
| 26 | `time-travel` | ❌ **Missing** | **GAP** |

### Layer 4: External Accessibility (0% — The Critical Gap)

| System | Cortex Integration | Status |
|--------|-------------------|--------|
| **drift MCP server** (`packages/drift-mcp`) | 0 Cortex tools registered | ❌ **ZERO** |
| **drift CLI** (`packages/drift-cli`) | 0 `cortex` subcommands | ❌ **ZERO** |
| **drift CI** (`packages/drift-ci`) | 0 Cortex passes | ❌ **ZERO** |
| **Cortex MCP server** | Does not exist | ❌ **MISSING** |
| **Cortex CLI binary** | `bin` declared but `drift-cortex-napi` missing → throws at runtime | ❌ **BROKEN** |
| **cortex-drift-bridge TS bindings** | 20 NAPI-ready functions + 6 MCP tools, 0 TS exposure | ❌ **ZERO** |

### Bugs / Stubs Found During Audit

| # | Location | Issue | Severity |
|---|----------|-------|----------|
| B1 | `package.json:24` (root) | `build:ts` script runs `contracts→core→cli→mcp→ci` but **omits `build:cortex`**. `npm run build` never compiles cortex TS | P0 |
| B2 | `packages/cortex/package.json:19-21` | `optionalDependencies: { "drift-cortex-napi": "*" }` — this package doesn't exist anywhere. No Cargo.toml builds it. No napi-rs config. | P0 |
| B3 | `packages/cortex/src/bridge/index.ts:158-173` | `loadNativeModule()` throws on failure — **no stub fallback** unlike drift's `loadNapi()`. Every CortexClient call will throw without native binary. | P0 |
| B4 | `packages/cortex/src/tools/temporal/drift_knowledge_timeline.ts:81` | Calls `getDriftMetrics(windowHours)` in a loop but always gets the same current snapshot — doesn't actually query historical data at different timestamps | P2 |
| B5 | `packages/cortex/src/tools/multiagent/drift_agent_project.ts:109-116` | Hardcoded `AgentId { 0: "" }` and scope parsing for source/target — doesn't parse URI into proper NamespaceId fields | P2 |
| B6 | `packages/cortex/src/index.ts:4` | Comment says "33 MCP tools" — should be 40 | P3 |
| B7 | `packages/cortex/package.json:4` | Description says "33 MCP tools" — should be 40 | P3 |
| B8 | `crates/cortex/cortex-napi/src/lib.rs:9` | Comment says "12 domain-specific NAPI binding modules (33 exported functions)" — should be 17 modules, 68 functions | P3 |
| B9 | `crates/cortex-drift-bridge/src/napi/functions.rs:1` | Comment says "15 NAPI-ready bridge functions" — actually 20 functions in file | P3 |
| B10 | `packages/cortex/src/tools/index.ts:2` | Comment says "40 MCP tools" — correct today, but should be updated after Phase B to 61 | P3 |

---

## Progress Summary

| Phase | Description | Impl Tasks | Test Tasks | Status |
|-------|-------------|-----------|-----------|--------|
| A | Cortex MCP Server (expose 40+ tools via MCP) | 12 | 18 | ⬜ Not Started |
| B | Missing Tool Definitions (fill 21 tool gaps) | 21 | 21 | ⬜ Not Started |
| C | Cortex CLI Binary + drift CLI Integration | 14 | 14 | ⬜ Not Started |
| D | Bug Fixes + Tool Registry + Docs | 14 | 10 | ⬜ Not Started |
| E | Integration Testing + Parity Verification | 5 | 20 | ⬜ Not Started |
| **TOTAL** | | **66** | **83** | |

---

## Phase A: Cortex MCP Server (Foundation)

> **Goal:** Create a working MCP server that exposes all Cortex tools to AI agents. This is the #1 blocker — without it, zero Cortex capabilities are accessible via MCP.
> **Estimated effort:** 3–4 days (1 developer)
> **Rationale:** The drift MCP server (`packages/drift-mcp`) uses `@drift/napi-contracts` for drift-analysis NAPI bindings. The Cortex system has its own NAPI bindings in `packages/cortex/src/bridge/`. We need a Cortex MCP server that either: (a) extends the drift MCP server with Cortex tools, or (b) is a standalone server. Option (a) is preferred — unified `drift` MCP server with Cortex as an additional tool category.
> **Architecture Decision:** Integrate into the existing `drift-mcp` server as a new tool category (`cortex_*`), using `CortexClient` from `@drift/cortex`. This avoids users needing 2 MCP servers.

### A1 — Add `@drift/cortex` Dependency to `drift-mcp`

- [ ] `CX-MCP-01` — Add `@drift/cortex` as a dependency in `packages/drift-mcp/package.json`
- [ ] `CX-MCP-02` — Create `packages/drift-mcp/src/cortex.ts` — Cortex initialization helper:
  - Import `CortexClient` from `@drift/cortex`
  - `initCortex(dbPath?: string)` — lazy singleton CortexClient init
  - `getCortex()` — return initialized client or throw
  - `shutdownCortex()` — graceful shutdown
- [ ] `CX-MCP-03` — Wire Cortex init/shutdown into `packages/drift-mcp/src/server.ts`:
  - Call `initCortex()` during `createDriftMcpServer()` after NAPI init
  - Call `shutdownCortex()` in `close()` method
  - Pass cortex db path from config (default: `.cortex/cortex.db`)

### A2 — Register Cortex Tools in drift MCP Server

- [ ] `CX-MCP-04` — Create `packages/drift-mcp/src/tools/cortex_tools.ts` — Tool registration module:
  - Import all 40 tool factories from `@drift/cortex` (`registerTools`, `listTools`, `callTool`)
  - `registerCortexTools(server, infra, catalog)` — register Cortex as a new `drift_tool` category
  - Map each Cortex tool name to `drift_tool` dispatch (e.g., `drift_tool({ tool: "cortex_memory_add", params: {...} })`)

- [ ] `CX-MCP-05` — Add Cortex tool entries to `buildToolCatalog()` in `drift_tool.ts`:
  - Add 40+ Cortex tools with category `"cortex"`:
    - **Memory (8):** `cortex_memory_add`, `cortex_memory_search`, `cortex_memory_get`, `cortex_memory_update`, `cortex_memory_delete`, `cortex_memory_list`, `cortex_memory_link`, `cortex_memory_unlink`
    - **Retrieval (3):** `cortex_context`, `cortex_search`, `cortex_related`
    - **Why (4):** `cortex_why`, `cortex_explain`, `cortex_counterfactual`, `cortex_intervention`
    - **Learning (3):** `cortex_learn`, `cortex_feedback`, `cortex_validate`
    - **Generation (2):** `cortex_gen_context`, `cortex_gen_outcome`
    - **System (8):** `cortex_status`, `cortex_metrics`, `cortex_consolidate`, `cortex_validate_system`, `cortex_gc`, `cortex_export`, `cortex_import`, `cortex_reembed`
    - **Prediction (2):** `cortex_predict`, `cortex_preload`
    - **Temporal (5):** `cortex_time_travel`, `cortex_time_diff`, `cortex_time_replay`, `cortex_knowledge_health`, `cortex_knowledge_timeline`
    - **Multi-Agent (5):** `cortex_agent_register`, `cortex_agent_share`, `cortex_agent_project`, `cortex_agent_provenance`, `cortex_agent_trust`
  - Each handler: `async (p) => { const client = getCortex(); return toolFactory(client).handler(p); }`

- [ ] `CX-MCP-06` — Add `"cortex"` to `CACHEABLE_TOOLS` set for read-only Cortex tools:
  - `cortex_status`, `cortex_metrics`, `cortex_search`, `cortex_why`, `cortex_explain`, `cortex_related`, `cortex_time_travel`, `cortex_time_diff`, `cortex_knowledge_health`, `cortex_knowledge_timeline`, `cortex_agent_provenance`, `cortex_agent_trust`

- [ ] `CX-MCP-07` — Add `"cortex"` to `MUTATION_TOOLS` set for write Cortex tools:
  - `cortex_memory_add`, `cortex_memory_update`, `cortex_memory_delete`, `cortex_memory_link`, `cortex_memory_unlink`, `cortex_learn`, `cortex_consolidate`, `cortex_gc`, `cortex_import`, `cortex_reembed`, `cortex_agent_register`

### A3 — Update Discovery + Workflow

- [ ] `CX-MCP-08` — Update `drift_discover` in `drift_discover.ts` to include Cortex tools in keyword matching
- [ ] `CX-MCP-09` — Add `cortex_health_check` workflow to `drift_workflow.ts`:
  - Steps: `cortex_status` → `cortex_validate_system` → `cortex_knowledge_health`
  - Provides single-call health assessment of the Cortex memory system
- [ ] `CX-MCP-10` — Add `cortex_onboard` workflow to `drift_workflow.ts`:
  - Steps: `cortex_memory_add` (create welcome memory) → `cortex_predict` → `cortex_status`
  - First-use workflow for new Cortex instances

### A4 — MCP Config Update

- [ ] `CX-MCP-11` — Add `cortexDbPath` and `cortexEnabled` to `McpConfig` in `types.ts`
- [ ] `CX-MCP-12` — Update `docs/mcp-config.md` with Cortex MCP configuration documentation

### Phase A Tests

#### Cortex Integration in MCP Server
- [ ] `CT-MCP-01` — Test `initCortex()` creates CortexClient with in-memory DB (no file needed for testing)
- [ ] `CT-MCP-02` — Test `getCortex()` throws before `initCortex()` is called
- [ ] `CT-MCP-03` — Test `shutdownCortex()` is idempotent (double-call doesn't throw)
- [ ] `CT-MCP-04` — Test Cortex tools appear in `buildToolCatalog()` — verify all 40 tool names present
- [ ] `CT-MCP-05` — Test `drift_tool({ tool: "cortex_memory_add", params: {...} })` creates a memory
- [ ] `CT-MCP-06` — Test `drift_tool({ tool: "cortex_search", params: { query: "test" } })` returns results
- [ ] `CT-MCP-07` — Test `drift_tool({ tool: "cortex_status" })` returns health report
- [ ] `CT-MCP-08` — Test cache is populated for `cortex_status` (read-only)
- [ ] `CT-MCP-09` — Test cache is invalidated after `cortex_memory_add` (mutation)
- [ ] `CT-MCP-10` — Test `drift_discover({ intent: "memory" })` includes Cortex tools in results
- [ ] `CT-MCP-11` — Test `drift_discover({ intent: "agent" })` returns multi-agent Cortex tools
- [ ] `CT-MCP-12` — Test `cortex_health_check` workflow runs all 3 steps
- [ ] `CT-MCP-13` — Test unknown Cortex tool name returns clear error with available list
- [ ] `CT-MCP-14` — Test Cortex tools work when `cortexEnabled: false` → returns "Cortex not enabled" error
- [ ] `CT-MCP-15` — Test rate limiter applies to Cortex tools
- [ ] `CT-MCP-16` — Test response builder applies token budgeting to large Cortex responses
- [ ] `CT-MCP-17` — Test error handler wraps Cortex errors with structured error format
- [ ] `CT-MCP-18` — Test server close() calls shutdownCortex() + driftShutdown()

### Quality Gate A (QG-A)

```
QG-A criteria (ALL must pass):
1. drift MCP server starts with cortexEnabled: true — no errors
2. drift_tool({ tool: "cortex_status" }) returns valid health JSON
3. drift_tool({ tool: "cortex_memory_add", params: { ... } }) creates and retrieves a memory
4. drift_discover({ intent: "memory" }) includes at least 5 cortex tools
5. All 18 CT-MCP tests pass
6. tsc --noEmit clean on packages/drift-mcp
```

---

## Phase B: Missing Tool Definitions (Fill 21 Tool Gaps)

> **Goal:** Create tool definitions for the 21 NAPI functions that have CortexClient methods but no MCP tool wrapper. After this, every Cortex capability is accessible via tools.
> **Estimated effort:** 2–3 days (1 developer)
> **Rationale:** 21 of 55 NAPI functions have working CortexClient methods but no tool wrapper. AI agents can't use capabilities they can't discover.
> **Architecture Decision:** All new tools follow the existing pattern in `packages/cortex/src/tools/` — factory function returning `McpToolDefinition`.

### B1 — Memory Tools

- [ ] `CX-TOOL-01` — Create `tools/memory/drift_memory_restore.ts`:
  - Input: `{ memory_id: string }`
  - Calls `client.memoryRestore(id)`
  - Returns `{ memory_id, status: "restored" }`

### B2 — Causal Tools

- [ ] `CX-TOOL-02` — Create `tools/why/drift_causal_infer.ts`:
  - Input: `{ source_memory_id: string, target_memory_id: string }`
  - Calls `client.memoryGet()` for both, then `client.causalInfer(source, target)`
  - Returns `InferenceResult` with strength, suggested_relation, above_threshold

### B3 — Privacy Tools

- [ ] `CX-TOOL-03` — Create `tools/system/drift_privacy_sanitize.ts`:
  - Input: `{ text: string }`
  - Calls `client.sanitize(text)`
  - Returns `{ sanitized_text, redaction_count, redactions }`

- [ ] `CX-TOOL-04` — Create `tools/system/drift_privacy_stats.ts`:
  - Input: `{}`
  - Calls `client.patternStats()`
  - Returns `{ failure_count, has_failures, failures }`

### B4 — Cloud Tools

- [ ] `CX-TOOL-05` — Create `tools/system/drift_cloud_sync.ts`:
  - Input: `{}`
  - Calls `client.cloudSync()`
  - Returns sync result with pushed/pulled/conflicts counts

- [ ] `CX-TOOL-06` — Create `tools/system/drift_cloud_status.ts`:
  - Input: `{}`
  - Calls `client.cloudStatus()`
  - Returns `{ status, is_online, offline_queue_length }`

- [ ] `CX-TOOL-07` — Create `tools/system/drift_cloud_resolve.ts`:
  - Input: `{ memory_id: string, resolution: "local_wins" | "remote_wins" | "last_write_wins" | "crdt_merge" | "manual" }`
  - Calls `client.cloudResolveConflict(memoryId, resolution)`
  - Returns resolution result

### B5 — Session Tools

- [ ] `CX-TOOL-08` — Create `tools/system/drift_session_create.ts`:
  - Input: `{ session_id?: string }`
  - Calls `client.sessionCreate(sessionId)`
  - Returns `{ session_id }`

- [ ] `CX-TOOL-09` — Create `tools/system/drift_session_get.ts`:
  - Input: `{ session_id: string }`
  - Calls `client.sessionGet(sessionId)`
  - Returns full session context

- [ ] `CX-TOOL-10` — Create `tools/system/drift_session_analytics.ts`:
  - Input: `{ session_id: string }`
  - Calls `client.sessionAnalytics(sessionId)`
  - Returns `SessionAnalytics` with token counts, query counts, loaded memory/pattern/file counts

### B6 — Temporal Tools

- [ ] `CX-TOOL-11` — Create `tools/temporal/drift_time_range.ts`:
  - Input: `{ from: string, to: string, mode: "overlaps" | "contains" | "started_during" | "ended_during" }`
  - Calls `client.queryRange(from, to, mode)`
  - Returns memories valid during the range

- [ ] `CX-TOOL-12` — Create `tools/temporal/drift_temporal_causal.ts`:
  - Input: `{ memory_id: string, as_of: string, direction: "forward" | "backward" | "both", depth?: number }`
  - Calls `client.queryTemporalCausal(memoryId, asOf, direction, depth ?? 5)`
  - Returns temporal causal traversal result

- [ ] `CX-TOOL-13` — Create `tools/temporal/drift_view_create.ts`:
  - Input: `{ label: string, timestamp: string }`
  - Calls `client.createMaterializedView(label, timestamp)`
  - Returns the created view

- [ ] `CX-TOOL-14` — Create `tools/temporal/drift_view_get.ts`:
  - Input: `{ label: string }`
  - Calls `client.getMaterializedView(label)`
  - Returns the view or null

- [ ] `CX-TOOL-15` — Create `tools/temporal/drift_view_list.ts`:
  - Input: `{}`
  - Calls `client.listMaterializedViews()`
  - Returns all materialized views

### B7 — Multi-Agent Tools

- [ ] `CX-TOOL-16` — Create `tools/multiagent/drift_agent_deregister.ts`:
  - Input: `{ agent_id: string }`
  - Calls `client.deregisterAgent(agentId)`
  - Returns `{ agent_id, status: "deregistered" }`

- [ ] `CX-TOOL-17` — Create `tools/multiagent/drift_agent_get.ts`:
  - Input: `{ agent_id: string }`
  - Calls `client.getAgent(agentId)`
  - Returns agent registration or "not found"

- [ ] `CX-TOOL-18` — Create `tools/multiagent/drift_agent_list.ts`:
  - Input: `{ status_filter?: "active" | "idle" | "deregistered" }`
  - Calls `client.listAgents(statusFilter)`
  - Returns array of agent registrations

- [ ] `CX-TOOL-19` — Create `tools/multiagent/drift_agent_namespace.ts`:
  - Input: `{ scope: "agent" | "team" | "project", name: string, owner: string }`
  - Calls `client.createNamespace(scope, name, owner)`
  - Returns `{ namespace_uri }`

- [ ] `CX-TOOL-20` — Create `tools/multiagent/drift_agent_retract.ts`:
  - Input: `{ memory_id: string, namespace: string, agent_id: string }`
  - Calls `client.retractMemory(memoryId, namespace, agentId)`
  - Returns `{ memory_id, status: "retracted" }`

- [ ] `CX-TOOL-21` — Create `tools/multiagent/drift_agent_sync.ts`:
  - Input: `{ source_agent: string, target_agent: string }`
  - Calls `client.syncAgents(sourceAgent, targetAgent)`
  - Returns sync result with applied/buffered counts

### Phase B Tests

- [ ] `CT-TOOL-01` — Test `drift_memory_restore` round-trips: archive → restore → verify not archived
- [ ] `CT-TOOL-02` — Test `drift_causal_infer` returns valid InferenceResult with strength > 0
- [ ] `CT-TOOL-03` — Test `drift_privacy_sanitize` redacts email addresses
- [ ] `CT-TOOL-04` — Test `drift_privacy_stats` returns pattern failure info
- [ ] `CT-TOOL-05` — Test `drift_cloud_sync` returns error when cloud not enabled
- [ ] `CT-TOOL-06` — Test `drift_cloud_status` returns error when cloud not enabled
- [ ] `CT-TOOL-07` — Test `drift_cloud_resolve` validates resolution strategy enum
- [ ] `CT-TOOL-08` — Test `drift_session_create` returns valid session ID
- [ ] `CT-TOOL-09` — Test `drift_session_get` returns session after creation
- [ ] `CT-TOOL-10` — Test `drift_session_analytics` returns token counts
- [ ] `CT-TOOL-11` — Test `drift_time_range` returns memories in time window
- [ ] `CT-TOOL-12` — Test `drift_temporal_causal` validates direction enum
- [ ] `CT-TOOL-13` — Test `drift_view_create` creates and retrieves a view
- [ ] `CT-TOOL-14` — Test `drift_view_get` returns null for nonexistent label
- [ ] `CT-TOOL-15` — Test `drift_view_list` returns all created views
- [ ] `CT-TOOL-16` — Test `drift_agent_deregister` validates non-empty agent_id
- [ ] `CT-TOOL-17` — Test `drift_agent_get` returns null for nonexistent agent
- [ ] `CT-TOOL-18` — Test `drift_agent_list` with and without status filter
- [ ] `CT-TOOL-19` — Test `drift_agent_namespace` validates scope enum
- [ ] `CT-TOOL-20` — Test `drift_agent_retract` validates non-empty fields
- [ ] `CT-TOOL-21` — Test `drift_agent_sync` validates non-empty agent IDs

### Quality Gate B (QG-B)

```
QG-B criteria (ALL must pass):
1. Tool count in registerTools() is 61 (was 40 + 21 new)
2. All 21 CT-TOOL tests pass
3. Every CortexClient method has at least one tool that calls it
4. tsc --noEmit clean on packages/cortex
5. No duplicate tool names in registry
```

---

## Phase C: Cortex CLI Binary + drift CLI Integration

> **Goal:** Make Cortex accessible from the command line — both as standalone `drift-cortex` binary and as `drift cortex <command>` subcommand.
> **Estimated effort:** 2–3 days (1 developer)
> **Rationale:** `packages/cortex/src/cli/index.ts` has 20 working commands but no binary entry point. `packages/drift-cli` has 26 commands but zero Cortex integration.

### C1 — Build Chain + Native Binary Fix

> **Note:** `bin`, `build` script, shebang, and workspace entry already exist. The real blockers are the missing native binary and the build chain omission.

- [ ] `CX-CLI-01` — Add `build:cortex` to root `package.json` `build:ts` script chain: `"npm run build:contracts && npm run build:core && npm run build:cli && npm run build:mcp && npm run build:ci && npm run build:cortex"`
- [ ] `CX-CLI-02` — Add stub fallback to `packages/cortex/src/bridge/index.ts` `loadNativeModule()` — when native binary not found, fall back to a `createStubNativeModule()` that returns structurally valid empty data (matching drift's pattern in `@drift/napi-contracts`). This unblocks development and testing without the native binary.
- [ ] `CX-CLI-03` — Create `packages/cortex/src/bridge/stub.ts` — complete stub implementing every `NativeBindings` method with structurally valid typed returns (not `{}`). Async stubs return resolved Promises.
- [ ] `CX-CLI-04` — Document native binary build requirements in `packages/cortex/README.md` — how to build `drift-cortex-napi` from `crates/cortex/cortex-napi` using napi-rs

### C2 — Integration into drift CLI

- [ ] `CX-CLI-05` — Add `@drift/cortex` as dependency in `packages/drift-cli/package.json`
- [ ] `CX-CLI-06` — Create `packages/drift-cli/src/commands/cortex.ts`:
  - `registerCortexCommand(program: Command)` — adds `drift cortex <subcommand>` umbrella command
  - Delegates to `@drift/cortex` CLI modules:
    - `drift cortex status` → `statusCommand(client)`
    - `drift cortex search <query>` → `searchCommand(client, query)`
    - `drift cortex why <file>` → `whyCommand(client, file)`
    - `drift cortex explain <id>` → `explainCommand(client, id)`
    - `drift cortex add <type>` → `addCommand(client, ...)`
    - `drift cortex learn` → `learnCommand(client, ...)`
    - `drift cortex consolidate` → `consolidateCommand(client, ...)`
    - `drift cortex validate` → `validateCommand(client, ...)`
    - `drift cortex export` → `exportCommand(client, ...)`
    - `drift cortex import <file>` → `importCommand(client, ...)`
    - `drift cortex gc` → `gcCommand(client, ...)`
    - `drift cortex metrics` → `metricsCommand(client, ...)`
    - `drift cortex reembed` → `reembedCommand(client, ...)`
    - `drift cortex timeline` → `timelineCommand(client, ...)`
    - `drift cortex diff` → `diffCommand(client, ...)`
    - `drift cortex replay <id>` → `replayCommand(client, ...)`
    - `drift cortex agents <sub>` → `agentsCommand(client, ...)`
    - `drift cortex namespaces <sub>` → `namespacesCommand(client, ...)`
    - `drift cortex provenance <id>` → `provenanceCommand(client, ...)`
- [ ] `CX-CLI-07` — Register cortex command in `packages/drift-cli/src/commands/index.ts`:
  - Import `registerCortexCommand`
  - Add to `registerAllCommands()` in "Advanced" section

### C3 — Missing CLI Commands in Cortex Package

- [ ] `CX-CLI-08` — Create `packages/cortex/src/cli/predict.ts`:
  - `predictCommand(client, activeFiles?, recentQueries?, intent?)` — calls `client.predict()`
  - Output: predicted memory IDs, confidence
- [ ] `CX-CLI-09` — Create `packages/cortex/src/cli/sanitize.ts`:
  - `sanitizeCommand(client, text)` — calls `client.sanitize(text)`
  - Output: sanitized text, redaction count
- [ ] `CX-CLI-10` — Create `packages/cortex/src/cli/cloud.ts`:
  - `cloudCommand(client, sub, flags)` — subcommands: sync, status
  - `sync`: calls `client.cloudSync()`
  - `status`: calls `client.cloudStatus()`
- [ ] `CX-CLI-11` — Create `packages/cortex/src/cli/session.ts`:
  - `sessionCommand(client, sub, args, flags)` — subcommands: create, get, analytics, cleanup
- [ ] `CX-CLI-12` — Create `packages/cortex/src/cli/restore.ts`:
  - `restoreCommand(client, memoryId)` — calls `client.memoryRestore(id)`
- [ ] `CX-CLI-13` — Create `packages/cortex/src/cli/decay.ts`:
  - `decayCommand(client)` — calls `client.decayRun()`, prints processed/archived/updated counts
- [ ] `CX-CLI-14` — Create `packages/cortex/src/cli/time-travel.ts`:
  - `timeTravelCommand(client, systemTime, validTime, filter?)` — calls `client.queryAsOf()`

### Phase C Tests

- [ ] `CT-CLI-01` — Test `drift-cortex status` outputs JSON health report
- [ ] `CT-CLI-02` — Test `drift-cortex search "test"` outputs search results
- [ ] `CT-CLI-03` — Test `drift-cortex help` lists all commands
- [ ] `CT-CLI-04` — Test `drift cortex status` via drift CLI integration works
- [ ] `CT-CLI-05` — Test `drift cortex search "test"` via drift CLI works
- [ ] `CT-CLI-06` — Test `drift-cortex predict` outputs predicted memory IDs
- [ ] `CT-CLI-07` — Test `drift-cortex sanitize "email@example.com"` redacts email
- [ ] `CT-CLI-08` — Test `drift-cortex cloud status` returns cloud status or "not enabled"
- [ ] `CT-CLI-09` — Test `drift-cortex session create` returns session ID
- [ ] `CT-CLI-10` — Test `drift-cortex restore <id>` restores archived memory
- [ ] `CT-CLI-11` — Test `drift-cortex decay` outputs decay statistics
- [ ] `CT-CLI-12` — Test `drift-cortex time-travel <sys> <valid>` returns memories
- [ ] `CT-CLI-13` — Test unknown command prints help with exit code 1
- [ ] `CT-CLI-14` — Test `drift cortex` (no subcommand) prints cortex help

### Quality Gate C (QG-C)

```
QG-C criteria (ALL must pass):
1. `drift-cortex status` runs and outputs valid JSON
2. `drift cortex status` runs via drift CLI
3. All 7 new CLI commands work (predict, sanitize, cloud, session, restore, decay, time-travel)
4. All 14 CT-CLI tests pass
5. tsc --noEmit clean on packages/cortex and packages/drift-cli
6. `drift-cortex help` lists all 27 commands (20 original + 7 new)
```

---

## Phase D: Bug Fixes + Tool Registry Update

> **Goal:** Fix all bugs found during audit and update tool registry metadata.
> **Estimated effort:** 1–2 days (1 developer)

### D1 — Bug Fixes

- [ ] `CX-FIX-01` — Fix B6: `packages/cortex/src/index.ts:4` comment: "33 MCP tools" → "61 MCP tools"
- [ ] `CX-FIX-02` — Fix B7: `packages/cortex/package.json:4` description: "33 MCP tools" → "61 MCP tools"
- [ ] `CX-FIX-03` — Fix B8: `crates/cortex/cortex-napi/src/lib.rs:9` comment: "12 domain-specific NAPI binding modules (33 exported functions)" → "17 modules (68 functions)"
- [ ] `CX-FIX-04` — Fix B9: `crates/cortex-drift-bridge/src/napi/functions.rs:1` comment: "15 NAPI-ready bridge functions" → "20 functions"
- [ ] `CX-FIX-05` — Fix B4: `drift_knowledge_timeline` (`tools/temporal/drift_knowledge_timeline.ts:81`):
  - Currently calls `getDriftMetrics(windowHours)` in a loop, always gets the same current snapshot
  - Fix: Use `queryRange()` or `queryAsOf()` to get actual historical snapshots at each timestamp
  - OR: Clearly document that this tool shows projected metrics per-window, not actual historical data
- [ ] `CX-FIX-06` — Fix B5: `drift_agent_project` (`tools/multiagent/drift_agent_project.ts:109-116`):
  - Hardcoded `AgentId { 0: "" }` and wrong scope parsing
  - Fix: Parse `source_namespace` and `target_namespace` URIs into proper `NamespaceId` fields using URI pattern `{scope}://{name}/`
- [ ] `CX-FIX-07` — Fix B10: tool count in `tools/index.ts:69` comment: update "All 40 tool factory functions" → "All 61 tool factory functions" after Phase B

### D2 — Tool Registry Update

- [ ] `CX-FIX-08` — Update `packages/cortex/src/tools/index.ts`:
  - Add all 21 new tool imports from Phase B
  - Add all 21 factories to `TOOL_FACTORIES` array
  - Verify no duplicate tool names
- [ ] `CX-FIX-09` — Update `packages/cortex/src/cli/index.ts`:
  - Add 7 new command imports (predict, sanitize, cloud, session, restore, decay, time-travel)
  - Add switch cases for all 7 new commands
  - Update help text to include new commands

### D3 — Types Export Update

- [ ] `CX-FIX-10` — Update `packages/cortex/src/index.ts` exports:
  - Add any new types introduced in Phase B tools
  - Add Temporal types: `MaterializedTemporalView`, `TemporalDiff` (verify all used types are exported)
- [ ] `CX-FIX-11` — Verify temporal types in `packages/cortex/src/bridge/types.ts`:
  - `MaterializedTemporalView`, `DriftSnapshot`, `DriftAlert`, `TemporalDiff`, `DecisionReplay`
  - Verify all types referenced by tools actually exist in types.ts
- [ ] `CX-FIX-12` — Verify multi-agent types in exports:
  - `AgentRegistration`, `AgentTrust`, `ProvenanceRecord`, `ProvenanceHop`, `CrossAgentTrace`, `ProjectionConfig`, `ProjectionFilter`, `MultiAgentSyncResult`

### D4 — Documentation

- [ ] `CX-FIX-13` — Create `packages/cortex/README.md`:
  - Architecture overview (Rust → NAPI → TS Bridge → Tools → CLI/MCP)
  - Quick start: `drift cortex status`, `drift cortex search "auth"`, `drift cortex add`
  - Full tool catalog table (61 tools with descriptions)
  - CLI command reference (27 commands)
- [ ] `CX-FIX-14` — Update `docs/mcp-config.md`:
  - Add Cortex MCP configuration section
  - Document `cortexEnabled`, `cortexDbPath` config options
  - List all Cortex tool names available via `drift_tool`

### Phase D Tests

- [ ] `CT-FIX-01` — Test `drift_knowledge_timeline` returns different data for different time ranges (verifies B4 fix)
- [ ] `CT-FIX-02` — Test `drift_agent_project` correctly parses namespace URIs (verifies B5 fix)
- [ ] `CT-FIX-03` — Test tool count is exactly 61 after all additions
- [ ] `CT-FIX-04` — Test no duplicate tool names in registry
- [ ] `CT-FIX-05` — Test all 61 tools have non-empty description and inputSchema
- [ ] `CT-FIX-06` — Test all types referenced by tools are properly exported from index.ts
- [ ] `CT-FIX-07` — Test CLI help text lists all 27 commands
- [ ] `CT-FIX-08` — Test CLI `--help` for each new command shows correct usage
- [ ] `CT-FIX-09` — Test Cortex MCP config defaults: cortexEnabled=true, cortexDbPath=".cortex/cortex.db"
- [ ] `CT-FIX-10` — Test Cortex MCP config override: custom dbPath is used

### Quality Gate D (QG-D)

```
QG-D criteria (ALL must pass):
1. All 10 CT-FIX tests pass
2. tsc --noEmit clean on all modified packages
3. All stale comments updated (tool counts, module counts)
4. README.md exists with accurate tool/command counts
5. No TypeScript `any` types in new code
```

---

## Phase E: Integration Testing + Parity Verification

> **Goal:** End-to-end verification that every Cortex capability is accessible from both MCP and CLI. Adversarial edge-case testing.
> **Estimated effort:** 2–3 days (1 developer)

### E1 — MCP ↔ CLI Parity Tests

- [ ] `CX-E2E-01` — Parity test: Create memory via MCP tool → retrieve via CLI → verify identical
- [ ] `CX-E2E-02` — Parity test: Create memory via CLI → search via MCP tool → verify found
- [ ] `CX-E2E-03` — Parity test: MCP `cortex_status` and CLI `drift-cortex status` return same health data
- [ ] `CX-E2E-04` — Parity test: MCP `cortex_time_diff` and CLI `drift-cortex diff` return same diff
- [ ] `CX-E2E-05` — Parity test: MCP `cortex_agent_register` + CLI `drift-cortex agents list` shows agent

### E2 — Full NAPI Coverage Verification

- [ ] `CT-E2E-01` — Verify every CortexClient method is called by at least one tool (automated check)
- [ ] `CT-E2E-02` — Verify every CortexClient method is callable from CLI (automated check)
- [ ] `CT-E2E-03` — Verify NativeBindings interface has exactly 55 methods matching NAPI bindings
- [ ] `CT-E2E-04` — Verify tool registry has exactly 61 tools with unique names

### E3 — Adversarial / Edge Case Tests

- [ ] `CT-E2E-05` — Test empty string inputs to all tools → graceful errors, not panics
- [ ] `CT-E2E-06` — Test extremely long strings (10KB) to memory tools → handles gracefully
- [ ] `CT-E2E-07` — Test Unicode inputs (emoji, CJK, RTL) to all text-accepting tools
- [ ] `CT-E2E-08` — Test invalid ISO 8601 timestamps to temporal tools → clear error messages
- [ ] `CT-E2E-09` — Test invalid namespace URIs to multi-agent tools → clear error messages
- [ ] `CT-E2E-10` — Test calling tools before Cortex initialization → "not initialized" error
- [ ] `CT-E2E-11` — Test concurrent tool calls (10 parallel memory creates) → no data corruption
- [ ] `CT-E2E-12` — Test tool call after shutdown → "not initialized" error

### E4 — Performance Verification

- [ ] `CT-E2E-13` — Test MCP `cortex_status` response < 100ms (read-only, should be fast)
- [ ] `CT-E2E-14` — Test MCP `cortex_search` response < 500ms for 1000-memory DB
- [ ] `CT-E2E-15` — Test CLI `drift-cortex status` completes < 2s (includes init + shutdown)
- [ ] `CT-E2E-16` — Test tool catalog build < 10ms (61 tools should be instant)

### E5 — Token Efficiency Tests

- [ ] `CT-E2E-17` — Test `cortex_status` response fits within 500 tokens
- [ ] `CT-E2E-18` — Test `cortex_search` with 100 results is truncated by response builder
- [ ] `CT-E2E-19` — Test `drift_discover({ intent: "cortex" })` returns ≤10 tools (not all 61)
- [ ] `CT-E2E-20` — Test `drift_tool({ tool: "cortex_capabilities" })` returns categorized list < 1000 tokens

### Quality Gate E (QG-E) — Final

```
QG-E criteria (ALL must pass):
1. All 20 CT-E2E tests pass
2. All 5 CX-E2E parity tests pass
3. 100% of CortexClient methods accessible via MCP (verified by CT-E2E-01)
4. 100% of CortexClient methods accessible via CLI (verified by CT-E2E-02)
5. Zero TypeScript compilation errors across all packages
6. No test regressions in existing drift-mcp or drift-cli test suites
7. Performance targets met (QG-E 13-16)
```

---

## Dependency Graph

```
Phase A (MCP Server)  ──→  Phase B (Tool Gaps)  ──→  Phase D (Fixes)  ──→  Phase E (Integration)
                                                          ↑
Phase C (CLI Binary)  ─────────────────────────────────────┘
```

- **A and C are independent** — can be parallelized
- **B depends on nothing** — tool definitions are standalone, but should come after A for testing convenience
- **D depends on B and C** — fixes affect tools and CLI
- **E depends on all** — integration tests verify everything

**Critical path:** A(3-4d) → B(2-3d) → D(1-2d) → E(2-3d) = **8-12 working days**
**With 2 engineers (A||C):** **6-9 working days**

---

## Summary Statistics

| Metric | Count |
|--------|-------|
| **NAPI Functions (Rust)** | 68 (65 user-facing + 3 lifecycle) |
| **CortexClient Methods (TS)** | 68 |
| **Existing Tools** | 40 |
| **New Tools (Phase B)** | 21 |
| **Final Tool Count** | 61 |
| **Existing CLI Commands** | 20 |
| **New CLI Commands (Phase C)** | 7 |
| **Final CLI Command Count** | 27 |
| **Implementation Tasks** | 66 |
| **Test Tasks** | 83 |
| **Total Tasks** | 149 |
| **Bugs Found** | 10 |
| **Bridge Functions (inaccessible)** | 20 + 6 MCP tools |
| **Quality Gates** | 5 |

---

## Key File Reference

| File | Role |
|------|------|
| `crates/cortex/cortex-napi/src/bindings/*.rs` | Rust NAPI ground truth (68 functions) |
| `packages/cortex/src/bridge/index.ts` | NativeBindings interface (68 signatures) |
| `packages/cortex/src/bridge/client.ts` | CortexClient (68 typed methods) |
| `packages/cortex/src/bridge/types.ts` | All TypeScript types |
| `packages/cortex/src/tools/index.ts` | Tool registry (40 → 61) |
| `packages/cortex/src/cli/index.ts` | CLI entry point (20 → 27 commands) |
| `packages/drift-mcp/src/server.ts` | MCP server (add Cortex init) |
| `packages/drift-mcp/src/tools/drift_tool.ts` | Tool catalog (add 40+ Cortex tools) |
| `packages/drift-mcp/src/tools/index.ts` | Tool registration |
| `packages/drift-cli/src/commands/index.ts` | CLI command registration (add cortex) |
| `crates/cortex-drift-bridge/src/napi/functions.rs` | 20 bridge NAPI-ready functions (inaccessible) |
| `crates/cortex-drift-bridge/src/tools/` | 6 bridge MCP tool handlers (inaccessible) |
| `packages/cortex/package.json` | Has `bin`, build, optionalDeps (drift-cortex-napi missing) |
| `package.json` (root) | Workspace config, build chain (cortex omitted from build:ts) |
| `packages/drift-ci/src/agent.ts` | CI agent (10 passes, 0 Cortex) |
| `packages/cortex/tests/` | 7 test files (bridge + 5 tools + 2 CLI, all mocked NAPI) |
