# Drift MCP Server — Configuration Guide

## Overview

Drift exposes an MCP (Model Context Protocol) server that allows AI agents to analyze codebases. It supports both **stdio** and **HTTP** transports.

---

## Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "drift": {
      "command": "node",
      "args": [
        "/path/to/driftv2/packages/drift-mcp/dist/index.js",
        "--project-root",
        "/path/to/your/project"
      ]
    }
  }
}
```

## Cursor

Add to `.cursor/mcp.json` in your project root:

```json
{
  "mcpServers": {
    "drift": {
      "command": "node",
      "args": [
        "/path/to/driftv2/packages/drift-mcp/dist/index.js",
        "--project-root",
        "."
      ]
    }
  }
}
```

## Windsurf (Cascade)

Add to `.windsurf/mcp.json`:

```json
{
  "mcpServers": {
    "drift": {
      "command": "node",
      "args": [
        "/path/to/driftv2/packages/drift-mcp/dist/index.js",
        "--project-root",
        "."
      ]
    }
  }
}
```

## Docker (HTTP transport)

```bash
docker compose up drift-mcp
```

Then configure your MCP client to connect to `http://localhost:3100`.

## Available Tools

The MCP server exposes 6 entry-point tools:

| Tool | Description |
|------|-------------|
| `drift_scan` | Scan + analyze a project (populates DB) |
| `drift_status` | Get project health overview |
| `drift_tool` | Access ~70 internal analysis + cortex tools |
| `drift_discover` | List available analysis capabilities |
| `drift_workflow` | Run multi-step analysis workflows |
| `drift_explain` | Get AI-ready context for code understanding |

### Internal Tools (via `drift_tool`)

Pass `{ "tool": "<name>", ... }` to `drift_tool`:

- **Analysis:** `violations`, `patterns`, `call_graph`, `boundaries`, `check`, `gates`, `audit`
- **Security:** `owasp`, `crypto`, `taint`, `security_summary`
- **Structural:** `coupling`, `contracts`, `constraints`, `decomposition`, `wrappers`, `dna`
- **Graph:** `reachability`, `impact`, `error_handling`, `test_topology`
- **Advanced:** `simulate`, `decisions`, `context`, `generate_spec`
- **Feedback:** `dismiss`, `fix`, `suppress`
- **Operational:** `report`, `export`, `gc`, `status`

### Cortex Tools (via `drift_tool`)

Pass `{ "tool": "cortex_<name>", ... }` to `drift_tool`:

- **Memory:** `cortex_memory_add`, `cortex_memory_search`, `cortex_memory_get`, `cortex_memory_update`, `cortex_memory_delete`, `cortex_memory_list`, `cortex_memory_link`, `cortex_memory_unlink`
- **Retrieval:** `cortex_context`, `cortex_search`, `cortex_related`
- **Causal:** `cortex_why`, `cortex_explain`, `cortex_counterfactual`, `cortex_intervention`
- **Learning:** `cortex_learn`, `cortex_feedback`, `cortex_validate`
- **Generation:** `cortex_gen_context`, `cortex_gen_outcome`
- **Prediction:** `cortex_predict`, `cortex_preload`
- **Temporal:** `cortex_time_travel`, `cortex_time_diff`, `cortex_time_replay`, `cortex_knowledge_health`, `cortex_knowledge_timeline`
- **Multi-Agent:** `cortex_agent_register`, `cortex_agent_share`, `cortex_agent_project`, `cortex_agent_provenance`, `cortex_agent_trust`
- **System:** `cortex_status`, `cortex_metrics`, `cortex_consolidate`, `cortex_validate_system`, `cortex_gc`, `cortex_export`, `cortex_import`, `cortex_reembed`

### Cortex Workflows (via `drift_workflow`)

| Workflow | Steps |
|----------|-------|
| `cortex_health_check` | `cortex_status` → `cortex_validate_system` → `cortex_knowledge_health` |
| `cortex_onboard` | `cortex_memory_add` → `cortex_predict` → `cortex_status` |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DRIFT_TRANSPORT` | `stdio` | Transport: `stdio` or `http` |
| `DRIFT_PORT` | `3100` | HTTP port (when using http transport) |
| `DRIFT_LOG_LEVEL` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `DRIFT_DB_PATH` | `.drift/drift.db` | Path to SQLite database |
| `CORTEX_DB_PATH` | `.cortex/cortex.db` | Path to Cortex SQLite database |
| `CORTEX_ENABLED` | `true` | Enable/disable Cortex memory system |
