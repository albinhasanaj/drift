# Phase D4 Prompt — NAPI Bindings + TypeScript MCP Tools + CLI

You are implementing Phase D4 of the cortex temporal reasoning addition. Read these files first:

- `TEMPORAL-TASK-TRACKER.md` (Phase D4 section, tasks `PTD4-*` and tests `TTD4-*`)
- `TEMPORAL-IMPLEMENTATION-SPEC.md`
- `FILE-MAP.md`

**Prerequisite:** QG-T3c has passed — Phase D3's integration with cortex-retrieval, cortex-validation, and cortex-observability is complete. All `TTD3-*` tests pass, all 3 modified crates pass their test suites, `cargo test --workspace` is green.

## What This Phase Builds

This phase exposes the full temporal API to TypeScript via NAPI bindings, creates 5 MCP tools, and adds 3 CLI commands. 17 impl tasks, 11 tests. This is the developer-facing layer.

### 1. cortex-napi: Temporal Bindings (Rust → JS)

**New files**: `src/bindings/temporal.rs`, `src/conversions/temporal_types.rs`
**Modified files**: `src/bindings/mod.rs`, `src/conversions/mod.rs`

#### `bindings/temporal.rs` — 10 `#[napi]` functions:

```rust
#[napi] query_as_of(system_time: String, valid_time: String, filter: Option<String>) -> Vec<NapiBaseMemory>
#[napi] query_range(from: String, to: String, mode: String) -> Vec<NapiBaseMemory>
#[napi] query_diff(time_a: String, time_b: String, scope: Option<String>) -> NapiTemporalDiff
#[napi] replay_decision(decision_id: String, budget: Option<u32>) -> NapiDecisionReplay
#[napi] query_temporal_causal(memory_id: String, as_of: String, direction: String, depth: u32) -> NapiTraversalResult
#[napi] get_drift_metrics(window_hours: Option<u32>) -> NapiDriftSnapshot
#[napi] get_drift_alerts() -> Vec<NapiDriftAlert>
#[napi] create_materialized_view(label: String, timestamp: String) -> NapiMaterializedView
#[napi] get_materialized_view(label: String) -> Option<NapiMaterializedView>
#[napi] list_materialized_views() -> Vec<NapiMaterializedView>
```

All time parameters are ISO 8601 strings (parsed to `DateTime<Utc>` in Rust). This matches the existing NAPI pattern where complex types are serialized as JSON strings.

#### `conversions/temporal_types.rs` — 8 NAPI-friendly type wrappers:

- `NapiMemoryEvent`, `NapiDriftSnapshot`, `NapiDriftAlert`, `NapiTemporalDiff`, `NapiDecisionReplay`, `NapiMaterializedView`, `NapiHindsightItem`, `NapiDiffStats`
- Each has `From<RustType>` and `Into<RustType>` implementations
- **Type conversions must be lossless** — Rust → NAPI → Rust round-trip preserves all fields

### 2. TypeScript Bridge

**Modified files**: `packages/cortex/src/bridge/types.ts`, `packages/cortex/src/bridge/client.ts`

#### `types.ts` — Add TypeScript interfaces:

`TemporalDiff`, `DiffStats`, `DecisionReplay`, `HindsightItem`, `DriftSnapshot`, `DriftAlert`, `MaterializedTemporalView`, `EpistemicStatus`, `AsOfQuery`, `TemporalRangeQuery`, `TemporalDiffQuery`, `DecisionReplayQuery`, `TemporalCausalQuery`

#### `client.ts` — Add 10 temporal methods to the bridge client:

`queryAsOf`, `queryRange`, `queryDiff`, `replayDecision`, `queryTemporalCausal`, `getDriftMetrics`, `getDriftAlerts`, `createMaterializedView`, `getMaterializedView`, `listMaterializedViews`

### 3. TypeScript MCP Tools (5 new tools)

**New files** in `packages/cortex/src/tools/temporal/`:
**Modified**: `packages/cortex/src/tools/index.ts` — register all 5 new tools

#### `drift_time_travel.ts` — Point-in-time knowledge query
- Input: `system_time` (ISO 8601), `valid_time` (ISO 8601), optional `filter` (types/tags/files)
- Output: `memories[]`, `count`, `query_time_ms`
- Calls `bridge.queryAsOf()`

#### `drift_time_diff.ts` — Compare knowledge between two times
- Input: `time_a` (ISO 8601), `time_b` (ISO 8601), optional `scope` (all/types/files/namespace)
- Output: `diff` (TemporalDiff), `summary` (human-readable string)
- Calls `bridge.queryDiff()`

#### `drift_time_replay.ts` — Replay decision context
- Input: `decision_memory_id`, optional `budget` (default: 2000 tokens)
- Output: `replay` (DecisionReplay), `hindsight_summary` (human-readable string)
- Calls `bridge.replayDecision()`

#### `drift_knowledge_health.ts` — Drift metrics dashboard
- Input: optional `window_hours` (default: 168 = 1 week)
- Output: `metrics` (DriftSnapshot), `alerts` (DriftAlert[]), `summary` (human-readable string)
- Calls `bridge.getDriftMetrics()` + `bridge.getDriftAlerts()`

#### `drift_knowledge_timeline.ts` — Knowledge evolution visualization
- Input: `from` (ISO 8601), `to` (ISO 8601), optional `granularity` (hourly/daily/weekly, default: daily)
- Output: `snapshots` (DriftSnapshot[]), `trend` (ksi_trend, confidence_trend, freshness_trend)
- Calls `bridge.getDriftMetrics()` for each time point in the range

### 4. TypeScript CLI Commands (3 new commands)

**New files** in `packages/cortex/src/cli/`:
**Modified**: `packages/cortex/src/cli/index.ts` — register timeline, diff, replay commands

#### `timeline.ts` — `drift cortex timeline`
- Options: `--from` (default: 30 days ago), `--to` (default: now), `--type`, `--module`
- Output: table showing KSI, confidence, contradiction density, EFI over time

#### `diff.ts` — `drift cortex diff`
- Options: `--from` (required), `--to` (required), `--scope`
- Output: structured diff with created/archived/modified counts + stats

#### `replay.ts` — `drift cortex replay <decision-id>`
- Options: `--budget` (default: 2000)
- Output: decision context reconstruction + hindsight analysis

### 5. TypeScript Tests

**Modified**: `packages/cortex/tests/bridge.test.ts` — add test cases for all 10 temporal bridge methods

## Critical Implementation Details

- **Match existing NAPI patterns exactly** — look at `cortex-napi/src/bindings/` for how existing bindings are structured. Each `#[napi]` function follows the same pattern: parse string inputs → call Rust engine → convert result to NAPI type → return.
- **Match existing MCP tool patterns exactly** — look at existing tools in `packages/cortex/src/tools/` for the tool definition structure (name, description, input schema, handler function).
- **Match existing CLI patterns exactly** — look at existing commands in `packages/cortex/src/cli/` for the command definition structure (name, description, options, handler).
- **All 10 NAPI functions must compile** — `cargo check -p cortex-napi` exits 0. This is the first validation step.
- **ISO 8601 string parsing** — all time parameters come in as strings from TypeScript. Parse with `DateTime::parse_from_rfc3339()` or `chrono::DateTime<Utc>` parsing. Return meaningful errors on parse failure.
- **MCP tool summaries are human-readable** — the `summary` field in tool outputs should be a concise, readable string that an agent or developer can understand without parsing the full data structure.
- **Bridge test suite must pass** — `vitest run` in `packages/cortex` must pass with all temporal tests green.

## Reference Crate Patterns

For NAPI bindings, look at existing files in `cortex-napi/src/bindings/` and `cortex-napi/src/conversions/` — follow the exact same patterns for struct definitions, `#[napi]` attributes, and `From`/`Into` implementations.

For MCP tools, look at existing tools in `packages/cortex/src/tools/` — follow the same tool registration pattern, input schema definition, and handler structure.

For CLI commands, look at existing commands in `packages/cortex/src/cli/` — follow the same command registration, option parsing, and output formatting patterns.

## Task Checklist

Check off tasks in `TEMPORAL-TASK-TRACKER.md` as you complete them: `PTD4-NAPI-01` through `PTD4-NAPI-04`, `PTD4-TS-01` through `PTD4-TS-02`, `PTD4-MCP-01` through `PTD4-MCP-06`, `PTD4-CLI-01` through `PTD4-CLI-04`, `PTD4-TEST-01`, and all `TTD4-*` tests.

## Quality Gate QG-T3d Must Pass

- All `TTD4-*` tests pass
- `cargo check -p cortex-napi` exits 0
- Coverage ≥80% for cortex-napi bindings/temporal.rs
- Coverage ≥80% for cortex-napi conversions/temporal_types.rs
- `vitest run` in packages/cortex passes
