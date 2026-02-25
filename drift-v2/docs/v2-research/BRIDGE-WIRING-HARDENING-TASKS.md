# Cortex-Drift Bridge Wiring — Implementation Tracker

> **Source of Truth:** `crates/cortex-drift-bridge/src/` (15 modules, 49 files, 804 tests), `crates/drift/drift-napi/src/` (runtime + 9 binding modules), `packages/drift-napi-contracts/src/interface.ts` (41 methods), `packages/drift-mcp/src/tools/drift_tool.ts` (~91 internal tools), `packages/drift-cli/src/commands/` (27 commands)
> **Core Finding:** The bridge is a fully functional Rust engine (804 tests, 0 failures, clippy clean) with **ZERO presentation layer exposure**. None of the 20 NAPI functions, 6 MCP tool handlers, or BridgeRuntime are callable from TypeScript, CLI, or MCP. This tracker wires the engine to every user/agent surface.
> **Total Phases:** 5 (A–E)
> **Quality Gates:** 5 (QG-A through QG-E)
> **Rule:** No Phase N+1 begins until Phase N quality gate passes.
> **Upstream Dependency:** All 5 phases of BRIDGE-CORRELATION-HARDENING-TASKS.md must be complete (they are: 804 tests, 0 failures).
> **Downstream Impact:** Enables `drift bridge` CLI, bridge MCP tools, bridge CI pass, and auto-grounding after `drift analyze`.

---

## How To Use This Document

- Agents: check off `[ ]` → `[x]` as you complete each task
- Every implementation task has a unique ID: `BW-{system}-{number}` (BW = Bridge Wiring)
- Every test task has a unique ID: `BT-{system}-{number}` (BT = Bridge Test)
- Quality gates are pass/fail — all criteria must pass before proceeding
- For Rust NAPI ground truth → `crates/drift/drift-napi/src/bindings/*.rs`
- For bridge function signatures → `crates/cortex-drift-bridge/src/napi/functions.rs`
- For DriftRuntime → `crates/drift/drift-napi/src/runtime.rs`
- For TS contracts → `packages/drift-napi-contracts/src/interface.ts`
- For MCP tool catalog → `packages/drift-mcp/src/tools/drift_tool.ts`
- For CLI commands → `packages/drift-cli/src/commands/index.ts`

---

## Progress Summary

| Phase | Description | Impl Tasks | Test Tasks | Status |
|-------|-------------|-----------|-----------|--------|
| A | NAPI Bridge Bindings (Foundation) | 16 | 18 | ✅ Complete |
| B | Event Pipeline Wiring | 12 | 14 | ✅ Complete |
| C | CLI Bridge Commands | 16 | 20 | ✅ Complete |
| D | MCP Bridge Tools | 12 | 16 | ✅ Complete |
| E | CI Agent + Integration Testing | 8 | 22 | ✅ Complete |
| **TOTAL** | | **64** | **90** | |

---

## Executive Summary

### What Exists (Working — Rust Layer)

| Component | Count | Status |
|-----------|-------|--------|
| **Bridge modules** | 15 | ✅ All compile, 804 tests pass |
| **NAPI-ready functions** (`napi/functions.rs`) | 20 | ✅ Return `serde_json::Value`, tested |
| **MCP tool handlers** (`tools/`) | 6 | ✅ why, learn, grounding_check, counterfactual, intervention, health |
| **Event mappings** | 21 | ✅ Drift event → Cortex memory with confidence/importance |
| **Evidence types** | 12 | ✅ Weighted, query real drift-storage schema |
| **Grounding verdicts** | 4 | ✅ Validated/Partial/Weak/Invalidated with confidence adjustment |
| **License features** | 25 | ✅ Community/Team/Enterprise 3-tier gating |
| **Causal intelligence** | 5 ops | ✅ Edges, counterfactual, intervention, pruning, narrative |
| **Storage tables** | 5 | ✅ bridge_memories, grounding_results, snapshots, event_log, metrics |
| **Intents** | 20 | ✅ 10 code + 10 analytical with data source resolver |

### What's Inaccessible (The Gap)

| Gap | Impact | Severity |
|-----|--------|----------|
| **20 bridge functions not in drift-napi** — `functions.rs` has 20 NAPI-ready functions but drift-napi has 0 bridge bindings | No bridge function callable from TS | **P0** |
| **BridgeRuntime not in DriftRuntime** — `DriftRuntime` has db, batch_writer, config, dispatcher but no bridge | Bridge never initialized | **P0** |
| **bridge.db never opened** — DriftRuntime opens drift.db only | No bridge storage | **P0** |
| **BridgeEventHandler not in analyze pipeline** — `drift_analyze()` fires 0 bridge events | No memories created from analysis | **P0** |
| **0 bridge CLI commands** — `drift-cli` has 27 commands, 0 bridge | Users can't interact with bridge | **P1** |
| **0 bridge MCP tools** — `drift_tool` catalog has ~91 tools, 0 bridge | Agents can't use bridge | **P1** |
| **0 bridge CI passes** — CI agent has 9 passes, 0 bridge | CI doesn't validate memory system | **P1** |
| **No auto-grounding after analyze** — grounding loop never triggered | Memories never grounded against evidence | **P1** |
| **No bridge functions in napi-contracts** — `DriftNapi` interface has 41 methods, 0 bridge | No TS type safety for bridge | **P1** |

### The 20 Bridge Functions to Wire

| # | Function | Category | Needs DB | Description |
|---|----------|----------|----------|-------------|
| 1 | `bridge_status` | Status | No | Bridge availability, license tier, grounding enabled |
| 2 | `bridge_ground_memory` | Grounding | drift+bridge | Ground a single memory against drift.db evidence |
| 3 | `bridge_ground_all` | Grounding | drift+bridge | Run full grounding loop on all memories |
| 4 | `bridge_grounding_history` | Grounding | bridge | Get grounding score history for a memory |
| 5 | `bridge_translate_link` | Links | No | Pattern → EntityLink translation |
| 6 | `bridge_translate_constraint_link` | Links | No | Constraint → EntityLink translation |
| 7 | `bridge_event_mappings` | Events | No | Return all 21 event mappings with tier info |
| 8 | `bridge_groundability` | Grounding | No | Classify memory type groundability (Full/Partial/Not) |
| 9 | `bridge_license_check` | License | No | Check if feature allowed at current tier |
| 10 | `bridge_intents` | Intents | No | Return all 20 intents (10 code + 10 analytical) |
| 11 | `bridge_adaptive_weights` | Spec | No | Compute adaptive weights from verification feedback |
| 12 | `bridge_spec_correction` | Spec | bridge+causal | Process a spec correction with root cause analysis |
| 13 | `bridge_contract_verified` | Spec | bridge | Process a contract verification event |
| 14 | `bridge_decomposition_adjusted` | Spec | bridge | Process a decomposition adjustment event |
| 15 | `bridge_explain_spec` | Causal | causal | Generate causal explanation for a spec section |
| 16 | `bridge_counterfactual` | Causal | causal | "What if this memory didn't exist?" |
| 17 | `bridge_intervention` | Causal | causal | "If we change this, what breaks?" |
| 18 | `bridge_health` | Health | cortex+drift+causal | Bridge health check (available/degraded/unavailable) |
| 19 | `bridge_unified_narrative` | Causal | causal | Full causal narrative with markdown rendering |
| 20 | `bridge_prune_causal` | Causal | causal | Prune weak causal edges below threshold |

---

## Phase A: NAPI Bridge Bindings (Foundation)

> **Goal:** Wire 20 bridge functions into `drift-napi` so they're callable from TypeScript. Add `BridgeRuntime` to `DriftRuntime`. Open `bridge.db` alongside `drift.db`.
> **Estimated effort:** 3–4 days (1 developer)
> **Prerequisite:** None (bridge crate already compiles and passes 804 tests)
> **Rationale:** Every downstream phase (CLI, MCP, CI, event pipeline) depends on these NAPI bindings existing. This is the foundation — without it, nothing else can be built. The bridge needs access to both `drift.db` (already opened by DriftRuntime) and `bridge.db` (new). Adding bridge functions to drift-napi lets them share the existing DriftRuntime connection pool.
> **Performance targets:** `driftBridgeStatus()` < 1ms, `driftBridgeGroundMemory()` < 50ms per memory, `driftBridgeHealth()` < 5ms.
> **Architecture decision:** Add bridge bindings to `drift-napi` (not a separate crate) because the bridge needs the `drift.db` connection already owned by `DriftRuntime`. This avoids cross-process DB sharing.

### A1 — Cargo Dependencies

- [x] `BW-NAPI-01` — Add `cortex-drift-bridge` as dependency in `crates/drift/drift-napi/Cargo.toml`:
  ```toml
  cortex-drift-bridge = { path = "../../cortex-drift-bridge" }
  ```
- [x] `BW-NAPI-02` — Add `cortex-causal` as dependency in `crates/drift/drift-napi/Cargo.toml`:
  ```toml
  cortex-causal = { path = "../../cortex/cortex-causal" }
  ```
  (Required for `CausalEngine` parameter in bridge functions)
- [x] `BW-NAPI-03` — Add `cortex-core` as dependency in `crates/drift/drift-napi/Cargo.toml`:
  ```toml
  cortex-core = { path = "../../cortex/cortex-core" }
  ```
  (Required for `MemoryType`, `BaseMemory` types used by bridge)

### A2 — BridgeRuntime in DriftRuntime

- [x] `BW-NAPI-04` — Add bridge fields to `DriftRuntime` struct in `crates/drift/drift-napi/src/runtime.rs`:
  - `bridge_db: Option<rusqlite::Connection>` — bridge.db connection
  - `bridge_config: cortex_drift_bridge::config::BridgeConfig` — bridge configuration
  - `causal_engine: Option<cortex_causal::CausalEngine>` — causal graph (in-memory)
  - `bridge_initialized: bool` — whether bridge is ready

- [x] `BW-NAPI-05` — Add `bridge_db_path` to `RuntimeOptions`:
  - `bridge_db_path: Option<PathBuf>` — defaults to `.drift/bridge.db` (sibling of `drift.db`)

- [x] `BW-NAPI-06` — Wire bridge initialization into `DriftRuntime::new()`:
  - Open `bridge.db` at `{project_root}/.drift/bridge.db` (or custom path)
  - Run bridge migrations: `cortex_drift_bridge::storage::migrate(&bridge_db)`
  - Create bridge tables: `cortex_drift_bridge::storage::create_bridge_tables(&bridge_db)`
  - Initialize `CausalEngine::new()` (in-memory)
  - Load `BridgeConfig` from `DriftConfig` bridge section (or defaults)
  - Set `bridge_initialized = true`
  - **Non-fatal on failure** — if bridge init fails, log warning and set `bridge_initialized = false`. DriftRuntime still works for all non-bridge operations.

### A3 — Bridge Binding Module

- [x] `BW-NAPI-07` — Create `crates/drift/drift-napi/src/bindings/bridge.rs`:
  - 20 `#[napi]` functions, each:
    1. Calls `runtime::get()` to get `DriftRuntime`
    2. Checks `runtime.bridge_initialized` — returns error if false
    3. Delegates to corresponding function in `cortex_drift_bridge::napi::functions`
    4. Returns `serde_json::Value` (already the return type of all 20 bridge functions)
  - Function naming convention: `drift_bridge_status`, `drift_bridge_ground_memory`, etc. (camelCase NAPI export: `driftBridgeStatus`, `driftBridgeGroundMemory`)

- [x] `BW-NAPI-08` — Register bridge module in `crates/drift/drift-napi/src/bindings/mod.rs`:
  - Add `pub mod bridge;` to module list

### A4 — TypeScript Contracts

- [x] `BW-NAPI-09` — Add 20 bridge function signatures to `packages/drift-napi-contracts/src/interface.ts`:
  - Add new section `// ─── Bridge (20) — bridge.rs ─────────────────────────────────`
  - All functions return `BridgeResult` (JSON object) or specific typed results
  - Example signatures:
    - `driftBridgeStatus(): BridgeStatusResult`
    - `driftBridgeGroundMemory(memoryId: string, memoryType: string): BridgeGroundingResult`
    - `driftBridgeGroundAll(): BridgeGroundingSnapshot`
    - `driftBridgeHealth(): BridgeHealthResult`
    - `driftBridgeCounterfactual(memoryId: string): CounterfactualResult`
    - etc.
  - Update method count comment: `41 methods` → `61 methods`

- [x] `BW-NAPI-10` — Create `packages/drift-napi-contracts/src/types/bridge.ts`:
  - `BridgeStatusResult` — `{ available, licenseTier, groundingEnabled, eventCount, memoryCount }`
  - `BridgeGroundingResult` — `{ memoryId, verdict, groundingScore, previousScore, scoreDelta, confidenceAdjustment, evidence[], generatesContradiction, durationMs }`
  - `BridgeGroundingSnapshot` — `{ totalChecked, validated, partial, weak, invalidated, avgScore, errorCount, triggerType }`
  - `BridgeHealthResult` — `{ status, ready, subsystemChecks[], degradationReasons[] }`
  - `CounterfactualResult` — `{ affectedCount, affectedIds[], maxDepth, summary }`
  - `InterventionResult` — `{ impactedCount, impactedIds[], maxDepth, summary }`
  - `UnifiedNarrativeResult` — `{ memoryId, sections[], upstream[], downstream[], markdown }`
  - `EventMapping` — `{ eventType, memoryType, confidence, importance, triggersGrounding, minTier }`
  - `GroundabilityResult` — `{ memoryType, groundability, reason }`
  - `IntentResolution` — `{ dataSources[], depth, tokenBudget }`
  - `BridgeLicenseResult` — `{ feature, allowed, requiredTier, currentTier }`

- [x] `BW-NAPI-11` — Add bridge type exports to `packages/drift-napi-contracts/src/types/index.ts`

- [x] `BW-NAPI-12` — Add 20 bridge function stubs to `packages/drift-napi-contracts/src/stub.ts`:
  - Each stub returns structurally valid typed data (not `{}`)
  - `driftBridgeStatus` → `{ available: false, licenseTier: 'Community', groundingEnabled: false, eventCount: 0, memoryCount: 0 }`
  - `driftBridgeGroundMemory` → `{ memoryId: '', verdict: 'InsufficientData', groundingScore: 0, ... }`
  - etc.

### A5 — Validation & Verification

- [x] `BW-NAPI-13` — Add `validateBridgeGroundParams` to `packages/drift-napi-contracts/src/validation.ts`:
  - Validates `memoryId` is non-empty string
  - Validates `memoryType` is valid enum value
  - Returns `{ valid, error?, field? }`

- [x] `BW-NAPI-14` — Add `validateBridgeCounterfactualParams` to `packages/drift-napi-contracts/src/validation.ts`:
  - Validates `memoryId` is non-empty string

- [x] `BW-NAPI-15` — Update method count assertion in contracts tests:
  - `DriftNapi` has exactly `61` functions (was 41)
  - Stub has exactly `61` implementations
  - Loader validates all 61 functions present

- [x] `BW-NAPI-16` — Verify Rust builds: `cargo build -p drift-napi` compiles with bridge deps

### Phase A Tests

#### Bridge NAPI Binding Smoke Tests
- [x] `BT-NAPI-01` — Test `driftBridgeStatus()` returns `BridgeStatusResult` shape with `available: true` after init
- [x] `BT-NAPI-02` — Test `driftBridgeStatus()` before init returns error (bridge not initialized)
- [x] `BT-NAPI-03` — Test `driftBridgeHealth()` returns all 3 subsystem checks (cortex_db, drift_db, causal_engine)
- [x] `BT-NAPI-04` — Test `driftBridgeEventMappings()` returns exactly 21 event mappings
- [x] `BT-NAPI-05` — Test `driftBridgeIntents()` returns exactly 20 intents (10 code + 10 analytical)
- [x] `BT-NAPI-06` — Test `driftBridgeLicenseCheck("grounding_basic", "Community")` returns `allowed: true`
- [x] `BT-NAPI-07` — Test `driftBridgeLicenseCheck("counterfactual", "Community")` returns `allowed: false`
- [x] `BT-NAPI-08` — Test `driftBridgeGroundability("PatternRationale")` returns `Full`
- [x] `BT-NAPI-09` — Test `driftBridgeGroundability("Feedback")` returns `NotGroundable`
- [x] `BT-NAPI-10` — Test `driftBridgeTranslateLink(patternId, patternName, 0.8)` returns `EntityLink` with `entity_type: "drift_pattern"`

#### Contract Alignment Tests
- [x] `BT-NAPI-11` — Test `DriftNapi` interface has exactly 61 methods — prevents accidental add/remove
- [x] `BT-NAPI-12` — Test every bridge method has a corresponding stub entry — no missing method
- [x] `BT-NAPI-13` — Test every bridge stub returns value matching declared return type (not `{}`)
- [x] `BT-NAPI-14` — Test `validateBridgeGroundParams({ memoryId: '' })` fails — empty ID
- [x] `BT-NAPI-15` — Test `validateBridgeGroundParams({ memoryId: 'abc-123', memoryType: 'PatternRationale' })` passes

#### Runtime Lifecycle Tests
- [x] `BT-NAPI-16` — Test `DriftRuntime` opens bridge.db alongside drift.db during init
- [x] `BT-NAPI-17` — Test bridge init failure (bad path) → DriftRuntime still works, bridge_initialized = false
- [x] `BT-NAPI-18` — Test bridge.db has all 5 bridge tables after init (bridge_memories, bridge_grounding_results, bridge_grounding_snapshots, bridge_event_log, bridge_metrics)

### QG-A: Phase A Quality Gate

```
QG-A criteria (ALL must pass):
1. cargo build -p drift-napi compiles clean (bridge deps resolved)
2. cargo clippy -p drift-napi -- -D warnings passes
3. DriftNapi interface has exactly 61 methods (41 drift + 20 bridge)
4. Every bridge method has stub returning valid typed shape
5. driftBridgeStatus() returns real data after initialization
6. bridge.db created with 5 tables during DriftRuntime init
7. Bridge init failure is non-fatal — DriftRuntime continues working
8. All 18 BT-NAPI tests pass
9. vitest --coverage ≥90% for bridge types/stubs in napi-contracts
```

---

## Phase B: Event Pipeline Wiring

> **Goal:** Wire `BridgeEventHandler` into the `drift_analyze()` pipeline so Drift analysis events automatically create Cortex memories, then trigger the grounding loop to validate them against real evidence.
> **Estimated effort:** 2–3 days (1 developer)
> **Prerequisite:** Phase A complete (bridge bindings exist, bridge.db opens)
> **Rationale:** Without this, the bridge is passive — it can only be used on-demand via CLI/MCP. With event pipeline wiring, every `drift scan && drift analyze` automatically populates the memory system and grounds it. This is the bridge's raison d'être.
> **Performance targets:** Event handler overhead < 5ms per event (non-blocking), grounding loop < 200ms for 100 memories, total pipeline overhead < 500ms added to `drift_analyze()`.

### B1 — BridgeEventHandler in DriftRuntime

- [x] `BW-EVT-01` — Add `bridge_event_handler: Option<cortex_drift_bridge::event_mapping::BridgeEventHandler>` to `DriftRuntime`:
  - Initialized during `DriftRuntime::new()` after bridge_db is opened
  - Uses `bridge_db` connection for memory persistence
  - Uses `bridge_config.license_tier` for event filtering
  - Uses `bridge_config.event_config` for per-event enable/disable

- [x] `BW-EVT-02` — Add `bridge_deduplicator: Option<cortex_drift_bridge::event_mapping::EventDeduplicator>` to `DriftRuntime`:
  - 60s TTL, 10,000 capacity (matching bridge defaults)
  - Prevents duplicate memories from repeated analysis runs

### B2 — Wire Events into drift_analyze()

> Each event maps to a specific step in the analysis pipeline (`crates/drift/drift-napi/src/bindings/analysis.rs`). Events fire AFTER the analysis step persists its data to drift.db, so the bridge can query fresh evidence.

- [x] `BW-EVT-03` — Fire `on_pattern_discovered` after Step 4 (pattern intelligence):
  - For each new pattern detected in `drift_analyze()` Step 4
  - `entity_id = pattern_id`, includes pattern name and confidence
  - Creates `Insight` memory (confidence 0.5, importance Normal)

- [x] `BW-EVT-04` — Fire `on_boundary_discovered` after Step 3a (boundary detection):
  - For each boundary found in `drift_analyze()` Step 3a
  - `entity_id = boundary module path`
  - Creates `Tribal` memory (confidence 0.6, importance Normal)

- [x] `BW-EVT-05` — Fire `on_gate_evaluated` after Step 7 (enforcement):
  - For each gate result in `drift_analyze()` Step 7
  - `entity_id = gate_name`, includes passed/failed status
  - Creates `DecisionContext` memory (confidence 0.6, importance Normal)

- [x] `BW-EVT-06` — Fire `on_regression_detected` after Step 8 (degradation alerts):
  - For each degradation alert generated in Step 8
  - `entity_id = metric_name`, includes severity
  - Creates `DecisionContext` memory (confidence 0.9, importance Critical)

- [x] `BW-EVT-07` — Fire `on_scan_complete` at end of `drift_analyze()`:
  - After all analysis steps complete
  - Triggers grounding loop (see B3)
  - Includes scan summary (file count, pattern count, violation count)

### B3 — Auto-Grounding After Analysis

- [x] `BW-EVT-08` — Trigger grounding loop after `on_scan_complete`:
  - Query `bridge_memories` for all ungrounded or stale memories
  - Create `MemoryForGrounding` structs from bridge_memories rows
  - Call `GroundingLoopRunner::run()` with `drift_db` + `bridge_db`
  - Record `GroundingSnapshot` to bridge_grounding_snapshots
  - Trigger type: `PostScanFull` (first run) or `PostScanIncremental` (subsequent)

- [x] `BW-EVT-09` — Add `driftBridgeGroundAfterAnalyze()` NAPI function:
  - Convenience function combining: query memories → ground all → return snapshot
  - Called from TS layer after `drift_analyze()` completes
  - Returns `BridgeGroundingSnapshot` with counts and avg score

### B4 — TS Integration

- [x] `BW-EVT-10` — Add `driftBridgeGroundAfterAnalyze` to `DriftNapi` interface in contracts:
  - Signature: `driftBridgeGroundAfterAnalyze(): BridgeGroundingSnapshot`
  - Add stub returning empty snapshot
  - Update method count: 61 → 62

- [x] `BW-EVT-11` — Wire auto-grounding into MCP `drift_scan` flow:
  - After `driftScan()` + `driftAnalyze()`, call `driftBridgeGroundAfterAnalyze()`
  - Include grounding snapshot in scan response: `{ ..scanResult, bridgeGrounding: snapshot }`

- [x] `BW-EVT-12` — Wire auto-grounding into CLI `drift analyze` command:
  - After `driftAnalyze()` completes, call `driftBridgeGroundAfterAnalyze()`
  - Print summary: `"Bridge: {N} memories grounded — {validated} validated, {partial} partial, {weak} weak, {invalidated} invalidated (avg score: {avg})"`

### Phase B Tests

#### Event Firing Tests
- [x] `BT-EVT-01` — Test `drift_analyze()` fires `on_pattern_discovered` for each detected pattern
- [x] `BT-EVT-02` — Test `drift_analyze()` fires `on_boundary_discovered` for each boundary
- [x] `BT-EVT-03` — Test `drift_analyze()` fires `on_gate_evaluated` for each gate
- [x] `BT-EVT-04` — Test `drift_analyze()` fires `on_scan_complete` exactly once at end
- [x] `BT-EVT-05` — Test `on_regression_detected` fires for degradation alerts only (not normal results)
- [x] `BT-EVT-06` — Test duplicate events within 60s TTL are deduplicated (same pattern analyzed twice)

#### Memory Creation Tests
- [x] `BT-EVT-07` — Test bridge_memories table has rows after `drift_analyze()` completes
- [x] `BT-EVT-08` — Test each created memory has correct `memory_type`, `confidence`, `importance`
- [x] `BT-EVT-09` — Test event_log table records each fired event
- [x] `BT-EVT-10` — Test Community tier only creates memories for 5 allowed events

#### Grounding Integration Tests
- [x] `BT-EVT-11` — Test grounding loop runs after `on_scan_complete` and produces non-zero scores
- [x] `BT-EVT-12` — Test `driftBridgeGroundAfterAnalyze()` returns valid `BridgeGroundingSnapshot`
- [x] `BT-EVT-13` — Test grounding scores are written to bridge_grounding_results
- [x] `BT-EVT-14` — Test confidence adjustments applied to bridge_memories after grounding

### QG-B: Phase B Quality Gate

```
QG-B criteria (ALL must pass):
1. drift_analyze() on a real codebase creates ≥1 bridge memory
2. bridge_event_log has event entries after analysis
3. Grounding loop fires after scan_complete and produces snapshot
4. bridge_grounding_results has scores after grounding
5. Memory confidence values differ from initial after grounding (adjustments applied)
6. Event deduplication works — running drift_analyze() twice doesn't double memories
7. Community tier filtering limits events to 5 types
8. Total pipeline overhead < 500ms for 100 memories
9. All 14 BT-EVT tests pass
10. cargo clippy -p drift-napi -- -D warnings passes
```

---

## Phase C: CLI Bridge Commands

> **Goal:** Add `drift bridge` subcommand group to the CLI with 16 commands covering status, grounding, causal analysis, learning, and simulation.
> **Estimated effort:** 2–3 days (1 developer)
> **Prerequisite:** Phase A complete (NAPI bindings exist). Phase B recommended but not required (CLI commands work with manual grounding even without auto-pipeline).
> **Rationale:** Users need CLI access to inspect bridge state, manually trigger grounding, explore causal relationships, and teach the system via corrections. The `drift bridge simulate` command is the key integration test — it synthesizes the full pipeline in one shot.
> **Performance targets:** All read-only commands < 100ms, `ground` < 5s for 500 memories, `simulate` < 10s.

### C1 — Command Scaffold

- [x] `BW-CLI-01` — Create `packages/drift-cli/src/commands/bridge.ts`:
  - `registerBridgeCommand(program: Command)` — adds `drift bridge <subcommand>` umbrella command
  - Umbrella help text: "Cortex-Drift bridge: memory grounding, causal intelligence, and learning"
  - All subcommands call `loadNapi()` and check `driftBridgeStatus().available` before proceeding

- [x] `BW-CLI-02` — Register bridge command in `packages/drift-cli/src/commands/index.ts`:
  - Import `registerBridgeCommand`
  - Add to `registerAllCommands()` in "Advanced" section (after cortex, before validate-pack)

### C2 — Status & Health Commands

- [x] `BW-CLI-03` — Implement `drift bridge status`:
  - Calls `driftBridgeStatus()`
  - Output: license tier, bridge availability, grounding enabled, memory count, event count
  - JSON format: `--format json` outputs raw `BridgeStatusResult`
  - Table format: colored status indicators (green=available, yellow=degraded, red=unavailable)

- [x] `BW-CLI-04` — Implement `drift bridge health`:
  - Calls `driftBridgeHealth()`
  - Output: per-subsystem status table (cortex_db, drift_db, bridge_db, causal_engine)
  - Shows degradation reasons if status is "degraded"

### C3 — Grounding Commands

- [x] `BW-CLI-05` — Implement `drift bridge ground [--memory-id <id>]`:
  - Without `--memory-id`: calls `driftBridgeGroundAll()` → prints snapshot summary
  - With `--memory-id`: calls `driftBridgeGroundMemory(id, type)` → prints detailed verdict + evidence
  - `--format json` for machine-readable output

- [x] `BW-CLI-06` — Implement `drift bridge memories [--type <type>] [--limit <n>] [--verdict <verdict>]`:
  - Queries bridge_memories with optional type/verdict filter
  - Output: table with id, type, summary (truncated), confidence, last grounding verdict
  - Default limit: 20

- [x] `BW-CLI-07` — Implement `drift bridge history <memory-id> [--limit <n>]`:
  - Calls `driftBridgeGroundingHistory(memoryId, limit)`
  - Output: table with timestamp, grounding score, classification, delta from previous

### C4 — Causal Intelligence Commands

- [x] `BW-CLI-08` — Implement `drift bridge why <entity-type> <entity-id>`:
  - Wraps `drift_why` MCP tool handler via NAPI
  - Output: related memories, grounding history, causal narrative
  - `entity-type`: pattern, violation, constraint, decision, boundary

- [x] `BW-CLI-09` — Implement `drift bridge counterfactual <memory-id>`:
  - Calls `driftBridgeCounterfactual(memoryId)`
  - Output: affected count, affected IDs, max depth, summary

- [x] `BW-CLI-10` — Implement `drift bridge intervention <memory-id>`:
  - Calls `driftBridgeIntervention(memoryId)`
  - Output: impacted count, impacted IDs, max depth, summary

- [x] `BW-CLI-11` — Implement `drift bridge narrative <memory-id>`:
  - Calls `driftBridgeUnifiedNarrative(memoryId)`
  - Output: rendered markdown (sections, upstream origins, downstream effects)

- [x] `BW-CLI-12` — Implement `drift bridge prune [--threshold <0.3>]`:
  - Calls `driftBridgePruneCausal(threshold)`
  - Output: number of weak edges removed

### C5 — Learning & Exploration Commands

- [x] `BW-CLI-13` — Implement `drift bridge learn <entity-type> <entity-id> <correction> [--category <cat>]`:
  - Wraps `drift_memory_learn` tool handler
  - Creates Feedback memory from user correction
  - Output: memory_id created, confirmation

- [x] `BW-CLI-14` — Implement `drift bridge events [--tier <tier>]`:
  - Calls `driftBridgeEventMappings()`
  - Output: table of all 21 event mappings with tier requirements
  - Filter by tier shows only events available at that tier

- [x] `BW-CLI-15` — Implement `drift bridge intents`:
  - Calls `driftBridgeIntents()`
  - Output: table of all 20 intents with data sources and depth

### C6 — Simulation Command (Integration Test via CLI)

- [x] `BW-CLI-16` — Implement `drift bridge simulate`:
  - **The key integration test command.** Synthesizes the full pipeline:
    1. Read patterns from drift.db → synthesize `on_pattern_discovered` events
    2. Read boundaries from drift.db → synthesize `on_boundary_discovered` events
    3. Read gate results from drift.db → synthesize `on_gate_evaluated` events
    4. Run all events through BridgeEventHandler (creates memories)
    5. Trigger grounding loop (validates memories against evidence)
    6. Report results:
       - Memories created: count by type
       - Grounding snapshot: validated/partial/weak/invalidated
       - Confidence adjustments: avg delta, max boost, max penalty
       - Causal edges created: count
       - Contradictions generated: count
  - `--dry-run` flag: show what would be created without persisting
  - `--tier <tier>` flag: simulate with different license tier

### Phase C Tests

#### Command Registration Tests
- [x] `BT-CLI-01` — Test `drift bridge` (no subcommand) prints bridge help with all subcommands listed
- [x] `BT-CLI-02` — Test `drift bridge foobar` → "Unknown command", exit code 2
- [x] `BT-CLI-03` — Test all 14 bridge subcommands registered and accessible

#### Status & Health Tests
- [x] `BT-CLI-04` — Test `drift bridge status` outputs formatted status with license tier
- [x] `BT-CLI-05` — Test `drift bridge status --format json` outputs valid JSON matching `BridgeStatusResult`
- [x] `BT-CLI-06` — Test `drift bridge health` lists all subsystem checks
- [x] `BT-CLI-07` — Test `drift bridge status` before init → "Bridge not initialized, run drift setup"

#### Grounding Tests
- [x] `BT-CLI-08` — Test `drift bridge ground` calls `driftBridgeGroundAll()` and prints snapshot
- [x] `BT-CLI-09` — Test `drift bridge ground --memory-id abc` calls `driftBridgeGroundMemory("abc", ...)`
- [x] `BT-CLI-10` — Test `drift bridge memories` returns formatted table with columns
- [x] `BT-CLI-11` — Test `drift bridge memories --type PatternRationale` filters correctly
- [x] `BT-CLI-12` — Test `drift bridge history <id>` returns grounding score history

#### Causal & Learning Tests
- [x] `BT-CLI-13` — Test `drift bridge counterfactual <id>` returns impact analysis
- [x] `BT-CLI-14` — Test `drift bridge intervention <id>` returns propagation analysis
- [x] `BT-CLI-15` — Test `drift bridge narrative <id>` renders markdown output
- [x] `BT-CLI-16` — Test `drift bridge learn pattern p1 "too noisy"` creates Feedback memory
- [x] `BT-CLI-17` — Test `drift bridge events` lists all 21 event mappings
- [x] `BT-CLI-18` — Test `drift bridge intents` lists all 20 intents

#### Simulation Tests
- [x] `BT-CLI-19` — Test `drift bridge simulate --dry-run` shows plan without persisting
- [x] `BT-CLI-20` — Test `drift bridge simulate` creates memories and runs grounding (end-to-end)

### QG-C: Phase C Quality Gate

```
QG-C criteria (ALL must pass):
1. drift bridge status runs and outputs valid status
2. drift bridge health shows per-subsystem checks
3. drift bridge ground runs grounding loop and prints snapshot
4. drift bridge simulate creates memories and grounds them (full pipeline)
5. All 14 bridge subcommands respond to --help
6. --format json works for status, ground, memories, events, intents
7. All 20 BT-CLI tests pass
8. tsc --noEmit clean on packages/drift-cli
9. Command count in index.ts updated (27 → 28 with bridge umbrella)
```

---

## Phase D: MCP Bridge Tools

> **Goal:** Register bridge capabilities as tools in the drift MCP server so AI agents can access grounding, causal intelligence, learning, and bridge health via `drift_tool`.
> **Estimated effort:** 1–2 days (1 developer)
> **Prerequisite:** Phase A complete (NAPI bindings exist)
> **Rationale:** AI agents using the drift MCP server currently have zero access to the bridge's memory grounding, causal analysis, and learning capabilities. These are high-value agent tools — `drift_bridge_why` explains why patterns exist, `drift_bridge_learn` teaches the system, and `drift_bridge_ground` validates memories against evidence.
> **Performance targets:** All bridge tools < 200ms response. Cache read-only tools (status, health, events, intents, groundability).

### D1 — Register Bridge Tools in Catalog

- [x] `BW-MCP-01` — Add bridge tools to `buildToolCatalog()` in `packages/drift-mcp/src/tools/drift_tool.ts`:
  - **Status (2):**
    - `drift_bridge_status` — "Bridge availability, license tier, grounding config" — category: `discovery`, tokens: ~200
    - `drift_bridge_health` — "Bridge health: per-subsystem availability" — category: `discovery`, tokens: ~200
  - **Grounding (4):**
    - `drift_bridge_ground` — "Ground a memory against drift.db evidence" — category: `analysis`, tokens: ~400
    - `drift_bridge_ground_all` — "Run full grounding loop on all memories" — category: `analysis`, tokens: ~300
    - `drift_bridge_memories` — "List bridge memories with grounding verdicts" — category: `exploration`, tokens: ~500
    - `drift_bridge_grounding_history` — "Grounding score history for a memory" — category: `exploration`, tokens: ~300
  - **Causal (4):**
    - `drift_bridge_why` — "Why does this pattern/violation/constraint exist?" — category: `analysis`, tokens: ~600
    - `drift_bridge_counterfactual` — "What if this memory didn't exist?" — category: `analysis`, tokens: ~400
    - `drift_bridge_intervention` — "If we change this, what breaks?" — category: `analysis`, tokens: ~400
    - `drift_bridge_narrative` — "Full causal narrative with upstream/downstream" — category: `analysis`, tokens: ~800
  - **Learning (1):**
    - `drift_bridge_learn` — "Teach the system: create correction memory" — category: `feedback`, tokens: ~100
  - **Reference (1):**
    - `drift_bridge_events` — "List all 21 event→memory mappings" — category: `exploration`, tokens: ~400

- [x] `BW-MCP-02` — Add bridge tools to `CACHEABLE_TOOLS` set:
  - `drift_bridge_status`, `drift_bridge_health`, `drift_bridge_events`, `drift_bridge_grounding_history`, `drift_bridge_memories`

- [x] `BW-MCP-03` — Add bridge tools to `MUTATION_TOOLS` set:
  - `drift_bridge_ground`, `drift_bridge_ground_all`, `drift_bridge_learn`

### D2 — Wire Handlers to NAPI

- [x] `BW-MCP-04` — Wire `drift_bridge_status` handler: `async () => napi.driftBridgeStatus()`
- [x] `BW-MCP-05` — Wire `drift_bridge_health` handler: `async () => napi.driftBridgeHealth()`
- [x] `BW-MCP-06` — Wire `drift_bridge_ground` handler: `async (p) => napi.driftBridgeGroundMemory(p.memoryId, p.memoryType)`
- [x] `BW-MCP-07` — Wire `drift_bridge_ground_all` handler: `async () => napi.driftBridgeGroundAll()`
- [x] `BW-MCP-08` — Wire `drift_bridge_why` handler: `async (p) => napi.driftBridgeExplainSpec(`${entityType}:${entityId}`)`
- [x] `BW-MCP-09` — Wire `drift_bridge_learn` handler: `async (p) => napi.driftBridgeSpecCorrection(JSON.stringify({...}))`

### D3 — Discovery & Workflow Integration

- [x] `BW-MCP-10` — Update `drift_discover` intent matching in `packages/drift-mcp/src/tools/drift_discover.ts`:
  - `intent: "memory"` or `intent: "grounding"` → boost bridge tools
  - `intent: "why"` or `intent: "causal"` → boost `drift_bridge_why`, `drift_bridge_narrative`
  - `intent: "learn"` or `intent: "teach"` → boost `drift_bridge_learn`

- [x] `BW-MCP-11` — Add `bridge_health_check` workflow to `packages/drift-mcp/src/tools/drift_workflow.ts`:
  - Steps: `drift_bridge_status` → `drift_bridge_health` → `drift_bridge_ground_all`
  - "Single-call bridge health assessment with auto-grounding"

- [x] `BW-MCP-12` — Update tool catalog comment with new count:
  - Update from `~91 internal tools` to `~103 internal tools` (91 + 12 bridge)

### Phase D Tests

#### Tool Registration Tests
- [x] `BT-MCP-01` — Test all 12 bridge tools appear in `buildToolCatalog()` — verify names present
- [x] `BT-MCP-02` — Test `drift_tool({ tool: "drift_bridge_status" })` returns valid `BridgeStatusResult`
- [x] `BT-MCP-03` — Test `drift_tool({ tool: "drift_bridge_health" })` returns subsystem checks
- [x] `BT-MCP-04` — Test `drift_tool({ tool: "drift_bridge_events" })` returns 21 event mappings
- [x] `BT-MCP-05` — Test `drift_tool({ tool: "drift_bridge_learn", params: { entityType: "pattern", entityId: "p1", correction: "too noisy" } })` creates memory

#### Caching & Rate Limiting Tests
- [x] `BT-MCP-06` — Test `drift_bridge_status` is cached (2nd call returns cached result)
- [x] `BT-MCP-07` — Test `drift_bridge_learn` invalidates cache (mutation tool)
- [x] `BT-MCP-08` — Test `drift_bridge_ground_all` is rate-limited (expensive tool)

#### Discovery & Workflow Tests
- [x] `BT-MCP-09` — Test `drift_discover({ intent: "memory" })` includes bridge tools in results
- [x] `BT-MCP-10` — Test `drift_discover({ intent: "grounding" })` boosts `drift_bridge_ground`
- [x] `BT-MCP-11` — Test `drift_discover({ intent: "why" })` includes `drift_bridge_why`
- [x] `BT-MCP-12` — Test `bridge_health_check` workflow runs all 3 steps

#### Error Handling Tests
- [x] `BT-MCP-13` — Test bridge tool called before bridge init → structured error with "run drift setup"
- [x] `BT-MCP-14` — Test invalid memory_id to `drift_bridge_ground` → structured error
- [x] `BT-MCP-15` — Test unknown bridge tool → "not found" error with available bridge tools list
- [x] `BT-MCP-16` — Test response builder applies token budgeting to large `drift_bridge_memories` response

### QG-D: Phase D Quality Gate

```
QG-D criteria (ALL must pass):
1. 12 bridge tools registered in catalog
2. drift_tool({ tool: "drift_bridge_status" }) returns valid JSON
3. drift_tool({ tool: "drift_bridge_learn", ... }) creates memory
4. drift_discover({ intent: "memory" }) includes bridge tools
5. bridge_health_check workflow completes all 3 steps
6. Caching works for read-only bridge tools
7. Mutations invalidate cache
8. All 16 BT-MCP tests pass
9. tsc --noEmit clean on packages/drift-mcp
10. Tool catalog count updated in comments
```

---

## Phase E: CI Agent + Integration Testing

> **Goal:** Add a bridge pass to the CI agent and create comprehensive end-to-end tests verifying the full pipeline: scan → analyze → events → memories → grounding → verdicts.
> **Estimated effort:** 2–3 days (1 developer)
> **Prerequisite:** All previous phases complete
> **Rationale:** The CI agent runs on every PR. Adding a bridge pass ensures the memory system is validated continuously. E2E tests verify the complete pipeline works end-to-end, not just individual functions in isolation.
> **Performance targets:** Bridge CI pass < 5s, full E2E pipeline < 15s.

### E1 — CI Agent Bridge Pass

- [x] `BW-CI-01` — Add bridge pass to CI agent in `packages/drift-ci/src/agent.ts`:
  - After existing 9 analysis passes, add `bridge` pass:
    1. Call `napi.driftBridgeStatus()` — verify bridge is available
    2. Call `napi.driftBridgeGroundAfterAnalyze()` — run grounding
    3. Include snapshot in pass result: memories created, grounding distribution, avg score

- [x] `BW-CI-02` — Add bridge summary to CI PR comment output:
  - Section: "### 🧠 Memory Grounding"
  - Content: `{validated} validated, {partial} partial, {weak} weak, {invalidated} invalidated (avg {avgScore})`
  - Show badge: ✅ if avg score ≥ 0.5, ⚠️ if < 0.5, ❌ if < 0.2

- [x] `BW-CI-03` — Add `--bridge` flag to `drift analyze` CLI command:
  - Default: `true` (bridge runs with analyze)
  - `--no-bridge` disables bridge pipeline (for faster CI on non-critical branches)
  - Respects `DRIFT_BRIDGE_ENABLED=false` env var

### E2 — End-to-End Pipeline Tests

- [x] `BW-E2E-01` — Create E2E test: scan → analyze → verify memories created:
  - Scan a test fixture project (use `test-fixtures/` directory)
  - Run `driftAnalyze()`
  - Verify `bridge_memories` table has rows
  - Verify `bridge_event_log` has entries
  - Verify each memory has correct type and confidence

- [x] `BW-E2E-02` — Create E2E test: ground → verify scores:
  - After analyze, call `driftBridgeGroundAll()`
  - Verify `bridge_grounding_results` has scores for each memory
  - Verify scores are in [0.0, 1.0] range
  - Verify verdicts match threshold rules (≥0.7 = Validated, etc.)

- [x] `BW-E2E-03` — Create E2E test: learn correction → re-ground → verify change:
  - Create a Feedback memory via `driftBridgeMemoryLearn()`
  - Run grounding
  - Verify the Feedback memory is classified as `NotGroundable`
  - Verify it was logged in bridge_event_log

- [x] `BW-E2E-04` — Create E2E test: counterfactual + intervention on bridge memories:
  - After creating memories via analyze
  - Call `driftBridgeCounterfactual(memoryId)` → verify `affectedCount ≥ 0`
  - Call `driftBridgeIntervention(memoryId)` → verify `impactedCount ≥ 0`

- [x] `BW-E2E-05` — Create E2E test: full simulate pipeline:
  - Run `drift bridge simulate` equivalent via NAPI
  - Verify: memories created > 0, grounding ran, snapshot has non-zero counts

### E3 — Cross-Interface Parity Tests

- [x] `BW-PARITY-01` — Parity: `driftBridgeStatus()` via NAPI = `drift bridge status --format json` via CLI
- [x] `BW-PARITY-02` — Parity: `driftBridgeHealth()` via NAPI = `drift_tool({ tool: "drift_bridge_health" })` via MCP
- [x] `BW-PARITY-03` — Parity: `driftBridgeGroundAll()` via NAPI = `drift bridge ground` via CLI = `drift_tool({ tool: "drift_bridge_ground_all" })` via MCP — all return same snapshot shape

### Phase E Tests

#### CI Agent Tests
- [x] `BT-CI-01` — Test CI agent bridge pass calls `driftBridgeStatus()` and `driftBridgeGroundAfterAnalyze()`
- [x] `BT-CI-02` — Test CI agent bridge pass handles bridge not initialized gracefully (skip, not fail)
- [x] `BT-CI-03` — Test CI PR comment includes "Memory Grounding" section
- [x] `BT-CI-04` — Test `--no-bridge` flag skips bridge pass
- [x] `BT-CI-05` — Test `DRIFT_BRIDGE_ENABLED=false` env var skips bridge

#### E2E Pipeline Tests
- [x] `BT-E2E-01` — Test full pipeline: scan → analyze → memories → ground → verify (test-fixtures)
- [x] `BT-E2E-02` — Test grounding scores are in valid range [0.0, 1.0]
- [x] `BT-E2E-03` — Test confidence adjustments change memory confidence (not static)
- [x] `BT-E2E-04` — Test event deduplication: analyze twice → memory count doesn't double
- [x] `BT-E2E-05` — Test learn correction creates Feedback memory with correct tags
- [x] `BT-E2E-06` — Test counterfactual returns valid result for real memory
- [x] `BT-E2E-07` — Test intervention returns valid result for real memory
- [x] `BT-E2E-08` — Test simulate creates memories and runs grounding (end-to-end)

#### Adversarial Tests
- [x] `BT-E2E-09` — Test empty project (0 files) → bridge creates 0 memories, no crash
- [x] `BT-E2E-10` — Test bridge with corrupted drift.db → graceful degradation, not panic
- [x] `BT-E2E-11` — Test concurrent grounding (2 parallel `driftBridgeGroundAll()`) → no data corruption
- [x] `BT-E2E-12` — Test Unicode in entity IDs and correction text → handled correctly
- [x] `BT-E2E-13` — Test grounding with 500+ memories → completes within 5s

#### Performance Tests
- [x] `BT-E2E-14` — Test `driftBridgeStatus()` < 1ms
- [x] `BT-E2E-15` — Test `driftBridgeHealth()` < 5ms
- [x] `BT-E2E-16` — Test `driftBridgeGroundMemory()` < 50ms per memory
- [x] `BT-E2E-17` — Test `driftBridgeGroundAll()` < 200ms for 100 memories

#### Parity Tests
- [x] `BT-E2E-18` — Parity: NAPI status = CLI status JSON = MCP status response
- [x] `BT-E2E-19` — Parity: NAPI ground_all snapshot = CLI ground snapshot = MCP ground_all response
- [x] `BT-E2E-20` — Parity: All 20 bridge NAPI functions accessible from CLI
- [x] `BT-E2E-21` — Parity: All 12 bridge MCP tools dispatch to valid NAPI functions
- [x] `BT-E2E-22` — Parity: CI bridge pass produces same grounding snapshot as manual `drift bridge ground`

### QG-E: Phase E Quality Gate (Final)

```
QG-E criteria (ALL must pass):
1. CI agent bridge pass runs and produces grounding snapshot
2. CI PR comment includes "Memory Grounding" section with badge
3. --no-bridge flag skips bridge cleanly
4. Full E2E pipeline: scan → analyze → memories → ground → verify passes on test-fixtures
5. Grounding with 500+ memories completes within 5s
6. Event deduplication prevents double-counting on re-analyze
7. Concurrent grounding produces no data corruption
8. All 22 BT-E2E tests pass
9. All 3 BW-PARITY tests pass
10. All 3 BW-E2E implementation tests pass
11. Zero test regressions in existing drift-cli, drift-mcp, drift-ci test suites
12. cargo clippy -p drift-napi -- -D warnings passes
13. tsc --noEmit clean on all modified packages
```

---

## Dependency Graph

```
Phase A (NAPI Bindings)
    ↓
    ├──→ Phase B (Event Pipeline)  ──→  Phase E (CI + E2E)
    │                                        ↑
    ├──→ Phase C (CLI Commands)  ────────────┘
    │                                        ↑
    └──→ Phase D (MCP Tools)  ───────────────┘
```

- **A must be first** — everything depends on NAPI bindings
- **B, C, D are independent of each other** — can be parallelized after A
- **E depends on all** — integration tests verify everything

**Critical path:** A(3-4d) → B(2-3d) → E(2-3d) = **7-10 working days**
**With 2 engineers (C||D after A):** **6-8 working days**
**Minimum viable (bridge works end-to-end):** A + B = **5-7 working days** — after this, `drift scan && drift analyze` creates memories, runs grounding, adjusts confidence.

---

## Summary Statistics

| Metric | Count |
|--------|-------|
| **Bridge NAPI functions** | 20 |
| **Bridge MCP tools** | 12 |
| **Bridge CLI commands** | 16 (14 subcommands + simulate + umbrella) |
| **Event mappings wired** | 21 |
| **Evidence types** | 12 |
| **DriftNapi methods (after)** | 62 (was 41) |
| **MCP tool catalog (after)** | ~103 (was ~91) |
| **CLI commands (after)** | 28 (was 27) |
| **Implementation tasks** | 64 |
| **Test tasks** | 90 |
| **Total tasks** | 154 |
| **Quality gates** | 5 |
| **Estimated days (1 engineer)** | 10-15 |
| **Estimated days (2 engineers)** | 7-10 |
| **Minimum viable (A + B)** | 5-7 |

---

## Key File Reference

| File | Role | Changes |
|------|------|---------|
| `crates/drift/drift-napi/Cargo.toml` | NAPI crate deps | Add cortex-drift-bridge, cortex-causal, cortex-core |
| `crates/drift/drift-napi/src/runtime.rs` | DriftRuntime singleton | Add bridge_db, bridge_config, causal_engine, bridge_initialized |
| `crates/drift/drift-napi/src/bindings/mod.rs` | Binding modules | Add `pub mod bridge;` |
| `crates/drift/drift-napi/src/bindings/bridge.rs` | **NEW** — 20 `#[napi]` bridge functions | Create with 20 wrapper functions |
| `crates/drift/drift-napi/src/bindings/analysis.rs` | Analysis pipeline | Add event firing after each step |
| `crates/cortex-drift-bridge/src/napi/functions.rs` | 20 NAPI-ready bridge functions (Rust) | No changes — already complete |
| `crates/cortex-drift-bridge/src/tools/` | 6 MCP tool handlers (Rust) | No changes — already complete |
| `packages/drift-napi-contracts/src/interface.ts` | DriftNapi interface | Add 20 bridge method signatures (41→62) |
| `packages/drift-napi-contracts/src/types/bridge.ts` | **NEW** — bridge TypeScript types | Create with all bridge result types |
| `packages/drift-napi-contracts/src/stub.ts` | NAPI stubs | Add 20 bridge stubs |
| `packages/drift-napi-contracts/src/validation.ts` | Parameter validators | Add bridge validators |
| `packages/drift-mcp/src/tools/drift_tool.ts` | MCP tool catalog | Add 12 bridge tools (~91→~103) |
| `packages/drift-mcp/src/tools/drift_discover.ts` | Intent-guided discovery | Add bridge tool boosting |
| `packages/drift-mcp/src/tools/drift_workflow.ts` | Composite workflows | Add bridge_health_check workflow |
| `packages/drift-cli/src/commands/bridge.ts` | **NEW** — bridge CLI commands | Create with 16 subcommands |
| `packages/drift-cli/src/commands/index.ts` | Command registration | Add registerBridgeCommand |
| `packages/drift-ci/src/agent.ts` | CI agent | Add bridge pass (10th pass) |
