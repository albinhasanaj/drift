# @drift/cortex

Cortex persistent memory system — 61 MCP tools + 27 CLI commands over Rust NAPI bindings.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Consumers (MCP Server / drift CLI / drift-cortex CLI)  │
├─────────────────────────────────────────────────────────┤
│  Tools Layer     — 61 MCP tool definitions (9 categories)│
│  CLI Layer       — 27 commands (drift-cortex binary)     │
├─────────────────────────────────────────────────────────┤
│  CortexClient    — 68 typed async methods                │
│  NativeBindings  — 68 NAPI function signatures           │
├─────────────────────────────────────────────────────────┤
│  Stub Fallback   — structurally valid stubs for dev/test │
├─────────────────────────────────────────────────────────┤
│  Rust NAPI       — cortex-napi (17 modules, 68 exports)  │
│  Rust Engines    — cortex-core, storage, embeddings, etc.│
└─────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# Via drift CLI (recommended)
drift cortex status              # Health dashboard
drift cortex search "auth"       # Hybrid semantic + keyword search
drift cortex add episodic --summary "Found auth bug" --content '{"type":"episodic","data":{"interaction":"debugging","context":"auth module","outcome":"fixed"}}'

# Via standalone binary
drift-cortex status
drift-cortex search "auth"
```

## Tool Catalog (61 tools)

| Category | Tools | Count |
|----------|-------|-------|
| **Memory** | `drift_memory_add`, `drift_memory_search`, `drift_memory_get`, `drift_memory_update`, `drift_memory_delete`, `drift_memory_list`, `drift_memory_link`, `drift_memory_unlink`, `drift_memory_restore` | 9 |
| **Retrieval** | `drift_context`, `drift_search`, `drift_related` | 3 |
| **Causal** | `drift_why`, `drift_explain`, `drift_counterfactual`, `drift_intervention`, `drift_causal_infer` | 5 |
| **Learning** | `drift_memory_learn`, `drift_feedback`, `drift_validate` | 3 |
| **Generation** | `drift_gen_context`, `drift_gen_outcome` | 2 |
| **System** | `drift_cortex_status`, `drift_cortex_metrics`, `drift_cortex_consolidate`, `drift_cortex_validate`, `drift_cortex_gc`, `drift_cortex_export`, `drift_cortex_import`, `drift_cortex_reembed`, `drift_privacy_sanitize`, `drift_privacy_stats`, `drift_cloud_sync`, `drift_cloud_status`, `drift_cloud_resolve`, `drift_session_create`, `drift_session_get`, `drift_session_analytics` | 16 |
| **Prediction** | `drift_predict`, `drift_preload` | 2 |
| **Temporal** | `drift_time_travel`, `drift_time_diff`, `drift_time_replay`, `drift_knowledge_health`, `drift_knowledge_timeline`, `drift_time_range`, `drift_temporal_causal`, `drift_view_create`, `drift_view_get`, `drift_view_list` | 10 |
| **Multi-Agent** | `drift_agent_register`, `drift_agent_share`, `drift_agent_project`, `drift_agent_provenance`, `drift_agent_trust`, `drift_agent_deregister`, `drift_agent_get`, `drift_agent_list`, `drift_agent_namespace`, `drift_agent_retract`, `drift_agent_sync` | 11 |

## CLI Command Reference (27 commands)

| Command | Description |
|---------|-------------|
| `status` | Health dashboard (subsystem status, metrics, degradations) |
| `search <query>` | Hybrid semantic + keyword search |
| `why <file\|pattern>` | Causal narrative for a file or pattern |
| `explain <memory-id>` | Full memory with causal chain |
| `add <type>` | Create a new memory |
| `learn` | Learn from a correction |
| `consolidate` | Run memory consolidation |
| `validate` | Run 4-dimension validation |
| `export` | Export memories as JSON |
| `import <file>` | Import memories from JSON |
| `gc` | Garbage collection (decay + cleanup + archive) |
| `metrics` | System metrics (consolidation, health, cache) |
| `reembed` | Re-embed memories with current provider |
| `timeline` | Knowledge evolution over time |
| `diff` | Compare knowledge between two times |
| `replay <id>` | Replay a decision with historical context |
| `agents <sub>` | Manage agents (list/register/deregister/info) |
| `namespaces <sub>` | Manage namespaces (list/create/permissions) |
| `provenance <id>` | Show provenance chain |
| `predict` | Predict needed memories for current task |
| `sanitize <text>` | Redact sensitive data |
| `cloud <sub>` | Cloud sync (sync/status/resolve) |
| `session <sub>` | Session management (create/get/analytics/cleanup) |
| `restore <id>` | Restore an archived memory |
| `decay` | Run confidence decay |
| `time-travel` | Point-in-time knowledge query |
| `help` | Show help |

## MCP Access

All 61 tools are accessible via the drift MCP server's `drift_tool` dispatch:

```json
{ "tool": "drift_tool", "params": { "tool": "cortex_status" } }
{ "tool": "drift_tool", "params": { "tool": "cortex_memory_add", "params": { ... } } }
```

Tools are prefixed with `cortex_` in the MCP catalog (e.g., `cortex_status`, `cortex_memory_add`).

## Building the Native Binary

The native NAPI binary is built from `crates/cortex/cortex-napi` using napi-rs:

```bash
cd crates/cortex/cortex-napi
npm run build          # Release build
npm run build:debug    # Debug build
```

This produces `drift-cortex-napi` — a platform-specific `.node` file. When the native binary is unavailable, CortexClient falls back to a structurally valid stub that returns empty data, enabling development and testing without Rust compilation.

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `CORTEX_DB_PATH` | `.cortex/cortex.db` | Path to Cortex SQLite database |
| `CORTEX_ENABLED` | `true` | Enable/disable Cortex in MCP server |

## Development

```bash
npm install                    # Install dependencies
npm run build                  # Compile TypeScript
npm run test                   # Run tests
npm run test:coverage          # Run with coverage
npx tsc --noEmit               # Type check only
```
