# MAPhase D3 — MCP Tools + CLI Commands

> **ULTRA THINK. Quality over speed. No shortcuts. Enterprise-grade perfection.**
> Your boss audits every line through Codex. Make him stop needing to.

You are implementing Phase D3 of the Cortex multi-agent memory addition. This phase creates the user-facing MCP tools and CLI commands. Read these files first:

- `MULTIAGENT-TASK-TRACKER.md` (Phase D3 section, tasks `PMD3-*` and tests `TMD3-*`)
- `MULTIAGENT-IMPLEMENTATION-SPEC.md` (full behavioral spec)
- `FILE-MAP.md` (complete file inventory with per-file details)

**Prerequisite:** QG-MA3b has passed — Phase D2's NAPI bindings and TypeScript bridge are fully operational. All 12 multi-agent functions are accessible from TypeScript with full type safety. All `TMD2-*` tests pass, `vitest run` is green, and coverage ≥80% on NAPI code.

---

## What This Phase Builds

Phase D3 creates 5 MCP tools and 3 CLI commands that expose multi-agent operations to end users and AI agents. 10 impl tasks, 7 tests.

### 1. MCP Tools (`packages/cortex/src/tools/multiagent/`) — 5 Tools

Each tool follows the MCP tool specification pattern used by existing Cortex tools.

**`drift_agent_register.ts`** — Register a new agent
```
Input:  { name: string, capabilities: string[] }
Output: { agent: AgentRegistration }
```
- Validates name is non-empty
- Validates capabilities are valid strings
- Returns full registration including generated agent_id and namespace

**`drift_agent_share.ts`** — Share memory to another namespace
```
Input:  { memory_id: string, target_namespace: string, agent_id: string }
Output: { success: boolean, provenance_hop: ProvenanceHop }
```
- Validates namespace URI format
- Validates memory exists
- Returns provenance hop recording the share action

**`drift_agent_project.ts`** — Create a memory projection
```
Input:  { source_namespace: string, target_namespace: string, filter: ProjectionFilter, compression_level: number, live: boolean }
Output: { projection_id: string }
```
- Validates filter structure
- Validates compression_level in [0, 3]
- Returns projection ID for future reference

**`drift_agent_provenance.ts`** — Query provenance chain
```
Input:  { memory_id: string, max_depth?: number }
Output: { provenance: ProvenanceRecord, cross_agent_trace?: CrossAgentTrace }
```
- Default max_depth: 10
- Validates max_depth > 0
- Returns full provenance chain + optional cross-agent trace

**`drift_agent_trust.ts`** — Query trust scores
```
Input:  { agent_id: string, target_agent?: string }
Output: { trust: AgentTrust | AgentTrust[] }
```
- If target_agent provided: returns single trust record
- If omitted: returns all trust records for agent_id

### 2. CLI Commands (`packages/cortex/src/cli/`) — 3 Commands

**`agents.ts`** — `drift cortex agents`
```
Subcommands:
  list        List all registered agents
  register    Register a new agent
  deregister  Deregister an agent
  info        Show agent details

Options:
  --status <status>           Filter by status (active/idle/deregistered)
  --capabilities <caps...>    Capabilities for registration
  --format <format>           Output format (table/json), default: table
```

**`namespaces.ts`** — `drift cortex namespaces`
```
Subcommands:
  list         List all namespaces
  create       Create a new namespace
  permissions  Show/modify namespace permissions

Options:
  --scope <scope>    Filter by scope (agent/team/project)
  --agent <agent>    Filter by agent
  --format <format>  Output format (table/json), default: table
```

**`provenance.ts`** — `drift cortex provenance <memory-id>`
```
Options:
  --depth <depth>    Max traversal depth, default: 10
  --format <format>  Output format (text/json), default: text

Text output example:
  Memory abc123 — Provenance Chain
  ├─ Created by agent-alpha (Human) at 2026-01-15T10:00:00Z
  ├─ Shared to team://backend/ by agent-alpha at 2026-01-15T11:00:00Z
  ├─ Validated by agent-beta at 2026-01-16T09:00:00Z [confidence +0.1]
  └─ Used in decision by agent-gamma at 2026-01-17T14:00:00Z [confidence +0.05]
  Chain confidence: 0.95
```

### 3. Tool Registration

**`packages/cortex/src/tools/index.ts`** — Register all 5 new tools
**`packages/cortex/src/cli/index.ts`** — Register agents, namespaces, provenance commands

---

## Critical Implementation Details

### MCP Tool Pattern

Follow existing Cortex MCP tools exactly. Look at:
- `packages/cortex/src/tools/` for the tool definition pattern
- Each tool exports a definition object with name, description, inputSchema, and handler
- Handler receives validated input, calls bridge client, returns structured output

### CLI Output Formatting

- `table` format: Use aligned columns with headers. Follow existing CLI output patterns.
- `json` format: Pretty-printed JSON with 2-space indent.
- `text` format (provenance only): Tree-style output with Unicode box-drawing characters.

### Input Validation

All MCP tools validate inputs before calling the bridge:
```typescript
if (!input.name || input.name.trim().length === 0) {
  throw new Error('Agent name is required and cannot be empty');
}
```

### Error Messages

Error messages must be user-facing and actionable:
- ❌ `"NAPI error: MultiAgentError::AgentNotFound(abc123)"`
- ✅ `"Agent 'abc123' not found. Use 'drift cortex agents list' to see registered agents."`

---

## Reference Patterns

- **MCP tools**: Follow existing tools in `packages/cortex/src/tools/`
- **CLI commands**: Follow existing commands in `packages/cortex/src/cli/`
- **Tool registration**: Follow `packages/cortex/src/tools/index.ts`
- **CLI registration**: Follow `packages/cortex/src/cli/index.ts`

---

## Task Checklist

Check off tasks in `MULTIAGENT-TASK-TRACKER.md` as you complete them:

**MCP Tools**: `PMD3-MCP-01` through `PMD3-MCP-06`
**CLI Commands**: `PMD3-CLI-01` through `PMD3-CLI-04`
**Tests**: All `TMD3-MCP-*` (4), `TMD3-CLI-*` (3)

---

## Quality Gate: QG-MA3c

Before proceeding to the Final phase, ALL of these must pass:

### Tests
- [ ] All 7 `TMD3-*` tests pass
- [ ] All 5 MCP tools functional (return valid responses)
- [ ] All 3 CLI commands functional (produce output)
- [ ] `vitest run` in packages/cortex passes

### Functionality
- [ ] `drift cortex agents list` shows registered agents
- [ ] `drift cortex namespaces list` shows namespaces
- [ ] `drift cortex provenance <id>` shows provenance chain
- [ ] Each MCP tool handles errors gracefully with user-friendly messages

### Enterprise
- [ ] All tools have descriptions and examples
- [ ] All CLI commands have help text
- [ ] All error messages are actionable
- [ ] Input validation covers edge cases (empty strings, invalid UUIDs, etc.)

---

## Common Pitfalls to Avoid

- ❌ **Don't forget to register tools/commands** — they won't be discoverable
- ❌ **Don't expose raw Rust errors to users** — wrap in user-friendly messages
- ❌ **Don't skip input validation** — MCP tools receive arbitrary input
- ❌ **Don't hardcode output formats** — respect the --format flag
- ✅ **Do test with invalid inputs** — empty strings, missing fields, bad UUIDs
- ✅ **Do provide examples in tool descriptions** — helps AI agents use the tools correctly
- ✅ **Do test CLI output formatting** — table alignment, JSON validity, tree rendering

---

## Success Criteria

Phase D3 is complete when:

1. ✅ All 10 implementation tasks completed
2. ✅ All 7 tests pass
3. ✅ QG-MA3c quality gate passes
4. ✅ All 5 MCP tools return valid responses
5. ✅ All 3 CLI commands produce formatted output
6. ✅ Error messages are user-friendly and actionable

**You'll know it works when:** An AI agent can call `drift_agent_register` to create a new agent, `drift_agent_share` to share knowledge, `drift_agent_provenance` to trace where knowledge came from, and `drift_agent_trust` to check trust scores — all through the MCP tool interface. A human can run `drift cortex agents list` and see all registered agents in a formatted table.

---

## Next Steps After Phase D3

Once QG-MA3c passes, proceed to **MAPhase Final: Golden Fixtures + QG-MA4**, which creates golden test fixtures, runs end-to-end integration tests, and validates the complete multi-agent system.
