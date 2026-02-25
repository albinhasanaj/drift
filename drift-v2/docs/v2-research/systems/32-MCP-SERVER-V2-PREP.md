# MCP Server (Split Architecture, Progressive Disclosure, Packs) — V2 Implementation Prep

> Comprehensive build specification for Drift v2's MCP server layer — the presentation
> boundary between Rust analysis and AI agent consumption via the Model Context Protocol.
>
> Synthesized from: 07-mcp/ (overview.md, server.md, infrastructure.md, tools-inventory.md,
> tools-by-category.md, curation.md, feedback-and-packs.md, testing.md),
> DRIFT-V2-FULL-SYSTEM-AUDIT.md (Cat 07, AD5), DRIFT-V2-STACK-HIERARCHY.md (Level 5A/5B),
> PLANNING-DRIFT.md (D1, D3, D4), 03-NAPI-BRIDGE-V2-PREP.md (§10 NAPI Function Registry,
> §14 TS Bridge Layer), 30-CONTEXT-GENERATION-V2-PREP.md (§1 Architectural Position),
> 06-cortex/mcp-tools.md (33 memory tools), existing v1 implementation
> (packages/mcp/ — ~90 source files, 10 tool categories, 87+ tools, enterprise-server.ts
> ~914 lines), MCP specification 2025-06-18 (structured tool output, elicitation, resource
> links, OAuth Resource Servers), MCP specification 2025-11-25 (authorization spec update,
> Client ID Metadata Documents), @modelcontextprotocol/sdk TypeScript SDK, and
> cortex-napi reference implementation (33 functions, 12 binding modules).
>
> Purpose: Everything needed to build the v2 MCP server from scratch. Split architecture
> resolved, progressive disclosure designed, tool consolidation mapped, pack system specified,
> infrastructure contracts defined, build order specified. Zero feature loss from v1.
> Generated: 2026-02-08

---

## 1. Architectural Position

The MCP server is Level 5 Presentation — the topmost layer in Drift's stack hierarchy.
It is how AI agents consume Drift. Every pattern query, every security check, every
context request, every memory operation flows through MCP tool calls. Without it, Drift's
analysis is trapped in drift.db with no AI-facing interface.

Per PLANNING-DRIFT.md D1: Drift is standalone. The MCP server depends only on drift-napi
(for Rust analysis) and optionally on cortex-napi (for memory operations).

Per PLANNING-DRIFT.md D3: Separate MCP servers. Drift has `drift_*` tools, Cortex has
`cortex_*` tools. If you're not using one system, you don't burn ~5-8K tokens loading
its tool definitions into the AI's context window.

Per DRIFT-V2-FULL-SYSTEM-AUDIT.md AD5: Split MCP server architecture with progressive
disclosure. 3 entry points per server, not all tools upfront. Reduces startup cost from
~8K to ~1.5K tokens per server.

Per DRIFT-V2-STACK-HIERARCHY.md: Level 5A (drift-analysis) is standalone. Level 5B
(drift-memory + bridge tools) is optional, only when Cortex is detected.

### What Lives Here

- **drift-analysis MCP server** — ~20-25 tools, read-only drift.db, `drift_*` namespace
- **drift-memory MCP server** — ~15-20 tools, read/write cortex.db + read drift.db,
  `drift_memory_*` namespace (optional, only when Cortex detected)
- **Bridge tools** — `drift_why`, `drift_memory_learn` — conditionally registered when
  both systems present (per D4)
- Progressive disclosure with 3 entry points per server
- Tool routing, caching, rate limiting, metrics, token estimation
- Pack manager for task-oriented tool bundles
- Feedback system for example quality reinforcement learning
- Curation system with anti-hallucination verification
- Consistent JSON response schemas across all tools
- Keyset pagination with cursor support for all list operations
- MCP spec 2025-06-18 compliance (structured output, elicitation, resource links)
- Streamable HTTP transport (replaces legacy SSE)

### What Does NOT Live Here

- Any analysis logic (lives in drift-core, accessed via drift-napi)
- Any memory logic (lives in cortex-core, accessed via cortex-napi)
- Bridge crate logic (lives in cortex-drift-bridge)
- SQLite schema/migrations (lives in drift-core storage)
- NAPI bindings (lives in drift-napi / cortex-napi)
- CLI commands (lives in packages/drift-cli)
- VSCode extension (lives in packages/drift-vscode)
- LSP server (lives in packages/drift-lsp)

---

## 2. The v1 Problem This Solves

### v1 Architecture (Single Monolithic Server)

v1 has one MCP server (`packages/mcp/`) with 87+ tools across 10 categories, all registered
at startup. This creates several problems:

1. **Token bloat** — All 87 tool definitions load into the AI's context window (~8K+ tokens).
   Most sessions use 5-10 tools. The other 77 are wasted context.

2. **Dual-path complexity** — 10+ tools have two implementations (JSON store vs SQLite).
   Every tool handler has `if (patternService) { ... } else { ... }` branching.

3. **Monolithic routing** — `routeToolCall()` is a cascade of switch statements across
   all categories. Adding a tool means touching the central router.

4. **No separation of concerns** — Memory tools (Cortex-dependent) are mixed with analysis
   tools (standalone). If Cortex isn't available, 33 tools silently fail.

5. **No progressive disclosure** — AI sees all tools immediately. No guidance on which
   tools to start with or how to drill down.

6. **Pack system is afterthought** — Packs exist but aren't integrated into tool discovery.
   AI doesn't know packs exist unless explicitly told.

### v2 Architecture (Split + Progressive Disclosure)

v2 solves all of these:

1. **Two servers** — drift-analysis (~20-25 tools, ~1.5K tokens) and drift-memory
   (~15-20 tools, ~1.5K tokens). Only load what you need.

2. **SQLite-only** — Dual-path eliminated. All tools query drift.db via NAPI. No JSON stores.

3. **Category-based routing** — Each tool category is a self-contained module with its own
   router. Central router delegates to category routers.

4. **Clean separation** — Memory tools live in drift-memory server. Analysis tools live in
   drift-analysis server. Bridge tools are conditionally registered.

5. **Progressive disclosure** — 3 entry points per server. AI starts with meta-tools,
   discovers specific tools on demand.

6. **Integrated packs** — Pack system is first-class. `drift_discover` returns available
   packs. AI can request a pack to get a curated tool subset.

---

## 3. Split Server Architecture (D3)

### Server 1: drift-analysis (~20-25 tools)

**Purpose**: Read-only analysis of drift.db. Pure Drift, no Cortex dependency.
**Namespace**: `drift_*`
**Token cost**: ~1.5K tokens for tool definitions (with progressive disclosure)
**Data access**: Read-only drift.db via drift-napi

#### Entry Points (Progressive Disclosure — 3 Meta-Tools)

These are the only tools visible at startup. Each returns a curated response AND
a `nextActions` hint telling the AI which specific tools to call next.

| Entry Point | Purpose | Returns |
|-------------|---------|---------|
| `drift_context` | Curated context for any task | Patterns, call graph, boundaries, DNA, guidance + `nextActions` |
| `drift_discover` | Health check + capability listing | Status, available tools, available packs, language detection |
| `drift_tool` | Dynamic tool invocation | Executes any registered tool by name + args |

**How progressive disclosure works:**

```
1. AI connects to drift-analysis server
2. Server registers 3 tools: drift_context, drift_discover, drift_tool
3. AI calls drift_discover → gets status + full tool catalog + pack catalog
4. AI calls drift_context(intent="fix_bug", focus="auth") → gets curated context
5. Response includes nextActions: ["drift_callers", "drift_impact_analysis"]
6. AI calls drift_tool(name="drift_callers", args={function: "validateToken"})
7. drift_tool dispatches to the callers handler internally
```

**Why `drift_tool` instead of registering all tools:**

- Registering 25 tools = ~5-8K tokens in context window
- Registering 3 tools + `drift_tool` = ~1.5K tokens
- `drift_tool` accepts `{name: string, args: object}` — the AI discovers available
  tools via `drift_discover` and invokes them through `drift_tool`
- This is the progressive disclosure pattern from AD5

#### Full Tool Catalog (Available via drift_tool)

These tools are NOT registered as MCP tools. They are internal handlers invoked
through `drift_tool`. The AI discovers them via `drift_discover`.

**Orchestration (2)**
| Tool | Purpose | Token Cost |
|------|---------|------------|
| `drift_context` | Curated context for any task (also a direct entry point) | ~1000-3000 |
| `drift_package_context` | Monorepo package-specific context | ~1000-3000 |

**Discovery (3)**
| Tool | Purpose | Token Cost |
|------|---------|------------|
| `drift_status` | Health snapshot (patterns, violations, storage) | ~200 |
| `drift_capabilities` | Full tool listing with descriptions | ~500 |
| `drift_projects` | Multi-project management (list, switch, add, remove) | ~300 |

**Surgical (12)**
| Tool | Purpose | Token Cost |
|------|---------|------------|
| `drift_signature` | Function/class signature lookup | ~100-300 |
| `drift_callers` | Who calls this function | ~200-500 |
| `drift_type` | Type definition expansion | ~200-500 |
| `drift_imports` | Import resolution for a symbol | ~100-200 |
| `drift_prevalidate` | Quick pre-write validation | ~300-800 |
| `drift_similar` | Find similar code patterns | ~500-1500 |
| `drift_recent` | Recent changes in an area | ~300-600 |
| `drift_dependencies` | Check installed packages | ~200-400 |
| `drift_test_template` | Generate test template | ~500-1000 |
| `drift_middleware` | Middleware chain analysis | ~300-600 |
| `drift_hooks` | Hook/lifecycle detection | ~300-600 |
| `drift_errors` | Error pattern lookup | ~300-600 |

**Exploration (5)**
| Tool | Purpose | Token Cost |
|------|---------|------------|
| `drift_patterns_list` | List patterns with filters + pagination | ~500-1500 |
| `drift_security_summary` | Security posture overview | ~800-2000 |
| `drift_contracts_list` | API contracts listing + pagination | ~500-1500 |
| `drift_env` | Environment variable analysis | ~500-1500 |
| `drift_trends` | Pattern trends over time | ~500-1500 |

**Detail (8)**
| Tool | Purpose | Token Cost |
|------|---------|------------|
| `drift_pattern_get` | Full pattern details | ~1000-3000 |
| `drift_code_examples` | Real code snippets from patterns | ~2000-5000 |
| `drift_files_list` | List files with pattern info | ~500-1500 |
| `drift_file_patterns` | All patterns in a specific file | ~1000-2500 |
| `drift_impact_analysis` | Change blast radius | ~1000-3000 |
| `drift_reachability` | Data flow reachability | ~1000-3000 |
| `drift_dna_profile` | Styling DNA profile | ~800-2000 |
| `drift_wrappers` | Framework wrapper detection | ~500-1500 |

**Analysis (9 core + 8 language-specific)**
| Tool | Purpose | Token Cost |
|------|---------|------------|
| `drift_coupling` | Module coupling analysis | ~1000-2500 |
| `drift_test_topology` | Test coverage analysis | ~1000-2500 |
| `drift_error_handling` | Error handling gaps | ~800-2000 |
| `drift_quality_gate` | Quality gate checks | ~1500-4000 |
| `drift_constants` | Constants/secrets analysis | ~800-2000 |
| `drift_constraints` | Constraint verification | ~800-2000 |
| `drift_audit` | Full pattern audit | ~1000-3000 |
| `drift_decisions` | Decision mining | ~800-2000 |
| `drift_simulate` | Speculative execution | ~2000-5000 |
| `drift_typescript` | TypeScript-specific analysis | ~800-2000 |
| `drift_python` | Python-specific analysis | ~800-2000 |
| `drift_java` | Java-specific analysis | ~800-2000 |
| `drift_php` | PHP-specific analysis | ~800-2000 |
| `drift_go` | Go-specific analysis | ~800-2000 |
| `drift_rust` | Rust-specific analysis | ~800-2000 |
| `drift_cpp` | C++-specific analysis | ~800-2000 |
| `drift_wpf` | WPF/XAML-specific analysis | ~800-2000 |

**Generation (3)**
| Tool | Purpose | Token Cost |
|------|---------|------------|
| `drift_explain` | Comprehensive code explanation | ~2000-5000 |
| `drift_validate_change` | Validate code against patterns | ~1000-3000 |
| `drift_suggest_changes` | Suggest pattern-aligned changes | ~1000-3000 |

**Setup (2)**
| Tool | Purpose | Token Cost |
|------|---------|------------|
| `drift_setup` | Initialize Drift in a project | ~500-1000 |
| `drift_telemetry` | Telemetry status/enable/disable | ~200 |

**Curation (1 with 6 actions)**
| Tool | Purpose | Token Cost |
|------|---------|------------|
| `drift_curate` | Review, verify, approve, ignore, bulk-approve, audit | ~500-2000 |

**Total: ~52 internal tools** (3 registered as MCP tools + 49 via drift_tool)

#### Language-Specific Tool Filtering

Language tools are only available if the language is detected in the project.
`drift_discover` returns the filtered tool list based on detected languages.

Detection uses the same heuristics as v1:
- Config files: `tsconfig.json` → TypeScript, `Cargo.toml` → Rust, etc.
- File extensions: `.ts`/`.tsx`, `.py`, `.java`, `.go`, `.rs`, `.php`, `.cpp`, `.xaml`
- Scanning is shallow (project root + 1 level) for speed

### Server 2: drift-memory (~15-20 tools) — Optional

**Purpose**: Read/write access to cortex.db + read access to drift.db.
**Namespace**: `drift_memory_*`
**Token cost**: ~1.5K tokens for tool definitions (with progressive disclosure)
**Data access**: Read/write cortex.db via cortex-napi, read-only drift.db via drift-napi
**Availability**: Only starts when Cortex is detected (cortex.db exists or config flag)

#### Entry Points (Progressive Disclosure — 3 Meta-Tools)

| Entry Point | Purpose | Returns |
|-------------|---------|---------|
| `drift_memory_context` | Relevant memories for current task | Memories, causal links, tribal knowledge |
| `drift_memory_manage` | Memory CRUD operations | Create, update, delete, archive, restore |
| `drift_memory_discover` | Memory system health + capabilities | Status, memory counts, available operations |

#### Full Tool Catalog (Available via drift_memory_manage)

**Core Operations (7)**
| Tool | Purpose |
|------|---------|
| `drift_memory_status` | Memory system health snapshot |
| `drift_memory_add` | Add new memory with auto causal inference |
| `drift_memory_get` | Get memory by ID |
| `drift_memory_update` | Update existing memory |
| `drift_memory_delete` | Soft delete memory |
| `drift_memory_search` | Semantic search with session deduplication |
| `drift_memory_query` | Rich graph queries |

**Context & Retrieval (3)**
| Tool | Purpose |
|------|---------|
| `drift_why` | Complete "why" context (tribal knowledge + patterns + decisions + causal) |
| `drift_memory_for_context` | Get memories for current context |
| `drift_memory_explain` | Explain memory reasoning |

**Learning & Feedback (2)**
| Tool | Purpose |
|------|---------|
| `drift_memory_learn` | Learn from corrections |
| `drift_memory_feedback` | Process feedback on memories |

**Validation & Health (8)**
| Tool | Purpose |
|------|---------|
| `drift_memory_validate` | Trigger memory validation |
| `drift_memory_consolidate` | Trigger consolidation |
| `drift_memory_health` | Comprehensive health report |
| `drift_memory_predict` | Predict memory effectiveness |
| `drift_memory_conflicts` | Find conflicting memories |
| `drift_memory_contradictions` | Find contradicting memories |
| `drift_memory_warnings` | Get active warnings |
| `drift_memory_suggest` | Get memory suggestions |

**Visualization (1)**
| Tool | Purpose |
|------|---------|
| `drift_memory_graph` | Visualize memory graph |

**Import/Export (2)**
| Tool | Purpose |
|------|---------|
| `drift_memory_import` | Import memories from JSON |
| `drift_memory_export` | Export memories to JSON |

**Specialized Memory Types (9)**
| Tool | Purpose |
|------|---------|
| `drift_memory_agent_spawn` | Create agent spawn memory |
| `drift_memory_entity` | Create entity memory |
| `drift_memory_goal` | Create goal memory |
| `drift_memory_workflow` | Create workflow memory |
| `drift_memory_incident` | Create incident memory |
| `drift_memory_meeting` | Create meeting memory |
| `drift_memory_skill` | Create skill memory |
| `drift_memory_conversation` | Create conversation memory |
| `drift_memory_environment` | Create environment memory |

**Total: ~33 internal tools** (3 registered as MCP tools + 30 via drift_memory_manage)

### Bridge Tools (Conditional — D4)

When both Cortex and Drift are detected, the drift-analysis server conditionally
registers additional bridge tools. These are NOT a third server — they augment
drift-analysis with cross-system capabilities.

| Tool | Purpose | Registered On |
|------|---------|---------------|
| `drift_why` | Synthesize pattern data + causal memory | drift-analysis (conditional) |
| `drift_memory_learn` | Create Cortex memory from Drift correction | drift-analysis (conditional) |
| `drift_grounding_check` | Validate memories against scan results | drift-analysis (conditional) |

**Detection mechanism** (per PLANNING-DRIFT.md Q3):
1. Check config flag: `cortex.enabled` in drift.toml
2. Auto-detect fallback: check for `cortex.db` file in `.drift/memory/`
3. Try to load cortex-napi bindings (graceful failure if not available)

```typescript
function detectCortex(config: DriftConfig): boolean {
    // 1. Explicit config
    if (config.cortex?.enabled === true) return true;
    if (config.cortex?.enabled === false) return false;

    // 2. Auto-detect cortex.db
    const cortexDbPath = path.join(config.projectRoot, '.drift', 'memory', 'cortex.db');
    if (fs.existsSync(cortexDbPath)) return true;

    // 3. Try loading NAPI bindings
    try {
        require('cortex-napi');
        return true;
    } catch {
        return false;
    }
}
```


---

## 4. Progressive Disclosure Design (AD5)

### The Problem with Flat Tool Lists

v1 registers all 87 tools at startup. The AI's context window receives:
- 87 tool definitions × ~80 tokens each = ~7,000 tokens
- Most sessions use 5-10 tools
- 90% of tool definitions are wasted context

MCP clients (Claude Desktop, Cursor, Kiro, Windsurf) list all tools from all servers.
With 87 tools, the AI spends significant reasoning capacity just parsing the tool list.

### The Solution: 3-Tier Progressive Disclosure

Each server exposes exactly 3 MCP tools. All other tools are accessible through
a dynamic dispatch tool (`drift_tool` / `drift_memory_manage`).

**Tier 1 — Entry Points (3 tools, ~500 tokens)**
Registered as MCP tools. Visible immediately. Designed to be self-explanatory.

**Tier 2 — Tool Catalog (discovered via entry points)**
Returned by `drift_discover` / `drift_memory_discover`. Full list of available tools
with descriptions, parameter schemas, and token cost estimates.

**Tier 3 — Tool Execution (via dynamic dispatch)**
`drift_tool` / `drift_memory_manage` accepts `{name, args}` and dispatches internally.

### drift_context — The Primary Entry Point

This is the most important tool. One call replaces 3-5 discovery calls.

```typescript
// MCP Tool Definition (registered at startup)
{
    name: "drift_context",
    description: "Get curated, AI-optimized context for your current task. " +
        "Returns patterns, architecture, security boundaries, and guidance " +
        "tailored to your intent. Start here — one call replaces 3-5 lookups.",
    inputSchema: {
        type: "object",
        properties: {
            intent: {
                type: "string",
                enum: ["add_feature", "fix_bug", "refactor", "security_audit",
                       "understand_code", "add_test", "review_pr"],
                description: "What you're trying to do"
            },
            focus: {
                type: "string",
                description: "Area of interest (file, module, function, concept)"
            },
            activeFile: {
                type: "string",
                description: "Currently open file path (optional)"
            },
            depth: {
                type: "string",
                enum: ["overview", "standard", "deep"],
                description: "Context depth: overview (~2K tokens), standard (~6K), deep (~12K)"
            },
            maxTokens: {
                type: "number",
                description: "Maximum response tokens (default: 6000)"
            }
        },
        required: ["intent", "focus"]
    }
}
```

**Response structure:**
```typescript
interface DriftContextResponse {
    summary: string;                    // 1-2 sentence overview
    patterns: PatternContext[];         // Relevant patterns with confidence
    architecture: ArchitectureContext;  // Call graph, boundaries, coupling
    security: SecurityContext;          // Boundaries, sensitive fields, secrets
    guidance: GuidanceContext;          // Insights, warnings, suggestions
    dna: DnaContext;                    // Codebase style fingerprint
    memory?: MemoryContext;            // Cortex memories (if available)
    nextActions: NextAction[];         // Suggested next tools to call
    meta: ResponseMeta;               // Duration, token estimate, freshness
}

interface NextAction {
    tool: string;                      // e.g., "drift_callers"
    args: Record<string, unknown>;     // Pre-filled arguments
    reason: string;                    // Why this action is suggested
    priority: "high" | "medium" | "low";
}
```

### drift_discover — The Capability Explorer

```typescript
{
    name: "drift_discover",
    description: "Discover Drift capabilities, project health, available tools, " +
        "and analysis packs. Use this to understand what's available before " +
        "diving into specific analysis.",
    inputSchema: {
        type: "object",
        properties: {
            section: {
                type: "string",
                enum: ["all", "status", "tools", "packs", "languages"],
                description: "What to discover (default: all)"
            }
        }
    }
}
```

**Response structure:**
```typescript
interface DriftDiscoverResponse {
    status: ProjectStatus;             // Health snapshot
    tools: ToolCatalog;                // All available tools with schemas
    packs: PackCatalog;                // Available analysis packs
    languages: DetectedLanguage[];     // Detected project languages
    meta: ResponseMeta;
}

interface ToolCatalog {
    categories: ToolCategory[];        // Grouped by category
    totalTools: number;
    filteredByLanguage: string[];      // Tools hidden due to language detection
}

interface ToolCategory {
    name: string;                      // "surgical", "exploration", etc.
    description: string;
    tools: ToolDefinition[];
}

interface ToolDefinition {
    name: string;
    description: string;
    inputSchema: object;               // JSON Schema for parameters
    tokenCost: string;                 // "~200-500"
    category: string;
    requiresAnalysis: boolean;         // Needs drift scan first?
}
```

### drift_tool — The Dynamic Dispatcher

```typescript
{
    name: "drift_tool",
    description: "Execute any Drift analysis tool by name. Use drift_discover " +
        "to see available tools and their parameters.",
    inputSchema: {
        type: "object",
        properties: {
            name: {
                type: "string",
                description: "Tool name (e.g., 'drift_callers', 'drift_impact_analysis')"
            },
            args: {
                type: "object",
                description: "Tool-specific arguments (see drift_discover for schemas)"
            }
        },
        required: ["name"]
    }
}
```

**Implementation:**
```typescript
async function handleDriftTool(
    name: string,
    args: Record<string, unknown>,
    context: ServerContext,
): Promise<MCPResponse> {
    // 1. Validate tool exists
    const tool = context.toolRegistry.get(name);
    if (!tool) {
        return errorResponse("TOOL_NOT_FOUND", `Unknown tool: ${name}`, {
            hint: "Use drift_discover to see available tools",
            similar: context.toolRegistry.fuzzyMatch(name, 3),
        });
    }

    // 2. Validate args against schema
    const validation = validateArgs(args, tool.inputSchema);
    if (!validation.valid) {
        return errorResponse("INVALID_ARGUMENT", validation.message, {
            schema: tool.inputSchema,
        });
    }

    // 3. Check rate limits
    if (!context.rateLimiter.allow(name)) {
        return errorResponse("RATE_LIMITED", "Too many requests", {
            retryAfterMs: context.rateLimiter.retryAfter(name),
        });
    }

    // 4. Check cache
    const cacheKey = context.cache.key(context.projectRoot, name, args);
    const cached = context.cache.get(cacheKey);
    if (cached) return cached;

    // 5. Execute tool handler
    const result = await tool.handler(args, context);

    // 6. Cache result
    context.cache.set(cacheKey, result, tool.cacheTtl);

    // 7. Record metrics
    context.metrics.record(name, result.meta.durationMs, true);

    return result;
}
```

### Token Budget Comparison: v1 vs v2

| Metric | v1 (Monolithic) | v2 (Progressive) | Savings |
|--------|-----------------|-------------------|---------|
| Tool definitions at startup | ~7,000 tokens | ~500 tokens | 93% |
| First useful call | 1 call (but AI must parse 87 tools) | 1 call (drift_context) | Same |
| Full tool discovery | Already loaded | 1 additional call (drift_discover) | +1 call |
| Typical session (5-10 tools) | ~7,000 tokens wasted | ~500 + ~200 per tool call | 85%+ |

---

## 5. MCP Protocol Compliance (2025-06-18 + 2025-11-25)

### Spec Version Targeting

v2 targets MCP specification 2025-06-18 as the baseline, with 2025-11-25 authorization
enhancements. Key features to implement:

### 5.1 Structured Tool Output (2025-06-18)

v1 returns all tool results as `{type: "text", text: JSON.stringify(result)}`.
v2 uses structured tool output for machine-parseable responses.

```typescript
// v1 pattern (text-only)
return {
    content: [{ type: "text", text: JSON.stringify(result) }]
};

// v2 pattern (structured output)
return {
    content: [
        { type: "text", text: result.summary },  // Human-readable summary
    ],
    structuredContent: {
        type: "object",
        value: result,  // Machine-parseable structured data
    },
};
```

**Why this matters**: AI agents can parse structured output directly without
JSON.parse() on text content. Reduces parsing errors and enables typed tool chains.

### 5.2 Elicitation Support (2025-06-18)

Servers can request additional information from users during interactions.
This is valuable for:

- `drift_setup` — Ask user for project configuration preferences
- `drift_curate` — Ask user to confirm pattern approval
- `drift_quality_gate` — Ask user which policy to apply
- `drift_memory_add` — Ask user for memory classification

```typescript
// Example: drift_setup requesting project type
const response = await server.elicitation.create({
    message: "What type of project is this?",
    requestedSchema: {
        type: "object",
        properties: {
            projectType: {
                type: "string",
                enum: ["web-app", "api", "library", "cli", "monorepo"],
                description: "Project type for optimal configuration"
            },
            languages: {
                type: "array",
                items: { type: "string" },
                description: "Primary languages used"
            }
        }
    }
});
```

### 5.3 Resource Links in Tool Results (2025-06-18)

Tool results can include links to MCP resources, enabling drill-down navigation.

```typescript
// drift_patterns_list returns resource links for each pattern
return {
    content: [{ type: "text", text: summary }],
    resourceLinks: patterns.map(p => ({
        uri: `drift://patterns/${p.id}`,
        name: p.name,
        description: `${p.category} pattern (${p.confidence}% confidence)`,
        mimeType: "application/json",
    })),
};
```

### 5.4 Streamable HTTP Transport (2025-03-26+)

v1 uses two transports: stdio and HTTP/SSE.
v2 replaces HTTP/SSE with Streamable HTTP (bidirectional streaming over single connection).

```typescript
// v1 transports
// bin/server.ts — stdio (stdin/stdout)
// bin/http-server.ts — HTTP + SSE (GET /sse, POST /message)

// v2 transports
// bin/server.ts — stdio (unchanged, primary for IDE integration)
// bin/http-server.ts — Streamable HTTP (single POST endpoint with streaming)
```

Streamable HTTP advantages:
- Single connection (no separate SSE endpoint)
- Bidirectional streaming (server can push, client can push)
- Better proxy/load balancer compatibility
- Simpler deployment (one endpoint, not two)

### 5.5 OAuth Resource Server Classification (2025-06-18)

MCP servers are classified as OAuth Resource Servers. This enables:
- Protected resource metadata for authorization server discovery
- RFC 8707 Resource Indicators for token scoping
- Standardized authentication flow for enterprise deployments

```typescript
// Server capability declaration
{
    capabilities: {
        tools: { listChanged: true },
        resources: { subscribe: true },
        // NEW: OAuth resource server metadata
        authorization: {
            protectedResourceMetadata: {
                resource: "https://drift.example.com/mcp",
                authorizationServers: ["https://auth.example.com"],
                bearerMethodsSupported: ["header"],
                scopesSupported: ["drift:read", "drift:write", "drift:admin"],
            }
        }
    }
}
```

### 5.6 Title Field for Human-Friendly Display (2025-06-18)

Tools now have a `title` field for display purposes, separate from `name` (programmatic).

```typescript
{
    name: "drift_context",
    title: "Get Drift Context",  // NEW: human-friendly display name
    description: "Get curated, AI-optimized context for your current task.",
    inputSchema: { ... }
}
```

### 5.7 _meta Field on All Interface Types (2025-06-18)

All MCP interface types can include a `_meta` field for protocol-level metadata.

```typescript
// Tool result with _meta
return {
    content: [{ type: "text", text: summary }],
    _meta: {
        progressToken: "scan-progress-123",
        cached: true,
        freshness: "stale",  // Custom metadata
    }
};
```

---

## 6. Infrastructure Layer

### 6.1 Response Cache

Multi-level caching with project-isolated keys and category-aware TTLs.

**Architecture:**
```
L1: In-memory LRU (200 entries, category-specific TTL)
L2: File-based (optional, 1-hour TTL, persistent across restarts)
```

**Category TTLs:**
| Category | TTL | Rationale |
|----------|-----|-----------|
| Surgical (callers, signature, type) | 5 min | Changes with code edits |
| Exploration (patterns_list, security) | 10 min | Changes with scans |
| Detail (pattern_get, code_examples) | 15 min | Stable between scans |
| Analysis (coupling, test_topology) | 30 min | Expensive, rarely changes |
| Discovery (status, capabilities) | 1 min | Should be fresh |
| Context (drift_context) | 5 min | Intent-dependent |

**Cache key generation:**
```typescript
function cacheKey(projectRoot: string, tool: string, args: unknown): string {
    const normalized = JSON.stringify(sortKeys(args));
    return createHash('sha256')
        .update(`${projectRoot}:${tool}:${normalized}`)
        .digest('hex');
}
```

**Invalidation triggers:**
- `drift scan` completes → invalidate all categories
- `drift_curate action=approve` → invalidate patterns + exploration
- Project switch → invalidate all
- Manual: `drift_tool({name: "drift_cache_clear"})` → clear all

### 6.2 Rate Limiter

Sliding window rate limiting with 3 tiers.

```typescript
interface RateLimiterConfig {
    global: { maxRequests: 120, windowMs: 60_000 };
    expensive: { maxRequests: 15, windowMs: 60_000 };
    perTool: Map<string, { maxRequests: number, windowMs: number }>;
}
```

**Expensive tools** (rate-limited more aggressively):
```typescript
const EXPENSIVE_TOOLS = [
    "drift_code_examples",      // Reads many files
    "drift_impact_analysis",    // Full graph traversal
    "drift_simulate",           // Speculative execution
    "drift_quality_gate",       // Runs all gates
    "drift_coupling",           // Full module analysis
    "drift_test_topology",      // Full test analysis
    "drift_explain",            // AI-powered (may call LLM)
];
```

**Rate limit response:**
```typescript
{
    error: {
        code: "RATE_LIMITED",
        message: "Too many requests for drift_code_examples",
        data: {
            retryAfterMs: 12000,
            limit: 15,
            remaining: 0,
            resetAt: "2026-02-08T12:00:12Z",
        }
    }
}
```

### 6.3 Metrics Collector

Prometheus-compatible metrics for monitoring and debugging.

```typescript
interface MetricsSnapshot {
    requests: {
        total: number;
        byTool: Map<string, number>;
        byCategory: Map<string, number>;
        errors: number;
        cached: number;
    };
    latency: {
        p50: number;
        p95: number;
        p99: number;
        byTool: Map<string, { p50: number; p95: number; p99: number }>;
    };
    cache: {
        hits: number;
        misses: number;
        hitRate: number;
        size: number;
    };
    tokens: {
        totalEstimated: number;
        byTool: Map<string, number>;
    };
}
```

### 6.4 Token Estimator

Heuristic token counting for response budgeting. v2 upgrades from pure heuristic
to tiktoken-rs-backed estimation when available (via NAPI), with heuristic fallback.

```typescript
class TokenEstimator {
    // Primary: tiktoken-rs via NAPI (accurate BPE counting)
    // Fallback: heuristic (chars / 4 for English, chars / 3 for code)
    estimate(text: string): number {
        try {
            return this.native.countTokens(text);  // tiktoken-rs
        } catch {
            return this.heuristic(text);
        }
    }

    private heuristic(text: string): number {
        const codeRatio = this.detectCodeRatio(text);
        const charsPerToken = 4 - codeRatio;  // 4 for prose, 3 for code
        return Math.ceil(text.length / charsPerToken);
    }
}
```

### 6.5 Cursor Manager

Opaque, versioned, time-limited pagination cursors. Same design as v1 but with
HMAC signing for tamper detection.

```typescript
interface CursorData {
    lastId?: string;
    lastScore?: number;
    lastTimestamp?: string;
    offset?: number;
    queryHash: string;          // Prevents cursor reuse across different queries
    createdAt: number;
    version: number;            // Forward compatibility
}

class CursorManager {
    private secret: string;     // HMAC signing key (generated at startup)

    encode(data: CursorData): string {
        const payload = Buffer.from(JSON.stringify(data)).toString('base64url');
        const signature = createHmac('sha256', this.secret)
            .update(payload)
            .digest('base64url');
        return `${payload}.${signature}`;
    }

    decode(cursor: string): CursorData {
        const [payload, signature] = cursor.split('.');
        const expected = createHmac('sha256', this.secret)
            .update(payload)
            .digest('base64url');
        if (signature !== expected) {
            throw new DriftError("INVALID_CURSOR", "Cursor signature mismatch");
        }
        const data = JSON.parse(Buffer.from(payload, 'base64url').toString());
        if (Date.now() - data.createdAt > 3600_000) {
            throw new DriftError("INVALID_CURSOR", "Cursor expired (1 hour limit)");
        }
        return data;
    }
}
```

### 6.6 Response Builder

Consistent response formatting with summary-first design and token budgets.

```typescript
class ResponseBuilder<T> {
    private summary: string = "";
    private data: T | null = null;
    private pagination: PaginationInfo | null = null;
    private nextActions: NextAction[] = [];
    private warnings: string[] = [];
    private meta: Partial<ResponseMeta> = {};

    withSummary(s: string): this { this.summary = s; return this; }
    withData(d: T): this { this.data = d; return this; }
    withPagination(p: PaginationInfo): this { this.pagination = p; return this; }
    withNextActions(a: NextAction[]): this { this.nextActions = a; return this; }
    withWarning(w: string): this { this.warnings.push(w); return this; }

    build(startTime: number): MCPToolResponse {
        const durationMs = Date.now() - startTime;
        const result = {
            summary: this.summary,
            data: this.data,
            ...(this.pagination && { pagination: this.pagination }),
            ...(this.nextActions.length && { nextActions: this.nextActions }),
            ...(this.warnings.length && { warnings: this.warnings }),
            meta: {
                durationMs,
                tokenEstimate: estimateTokens(this.data),
                cached: false,
                ...this.meta,
            },
        };

        // Structured output for MCP 2025-06-18
        return {
            content: [{ type: "text", text: this.summary }],
            structuredContent: { type: "object", value: result },
        };
    }
}
```

### 6.7 Error Handler

Structured errors with recovery hints for AI agents.

```typescript
class DriftError extends Error {
    constructor(
        public readonly code: string,
        message: string,
        public readonly data?: {
            hint?: string;
            alternativeTools?: string[];
            retryAfterMs?: number;
            command?: string;
            similar?: string[];
        },
    ) {
        super(message);
        this.name = "DriftError";
    }
}

// Error code registry
const ERROR_CODES = {
    // Client errors
    INVALID_ARGUMENT: "Invalid parameter value",
    MISSING_REQUIRED_PARAM: "Required parameter missing",
    TOOL_NOT_FOUND: "Unknown tool name",
    PATTERN_NOT_FOUND: "Invalid pattern ID",
    FILE_NOT_FOUND: "File doesn't exist",
    INVALID_CURSOR: "Expired or invalid pagination cursor",

    // Server errors
    SCAN_REQUIRED: "No scan data — run drift scan first",
    STORE_UNAVAILABLE: "Store not initialized",
    CALLGRAPH_NOT_BUILT: "Call graph not built — run drift callgraph build",
    DNA_NOT_ANALYZED: "DNA not analyzed — run drift dna scan",
    CORTEX_UNAVAILABLE: "Cortex not available — memory tools disabled",

    // Rate limiting
    RATE_LIMITED: "Too many requests — wait and retry",

    // Internal
    INTERNAL_ERROR: "Internal server error",
    NAPI_ERROR: "Native module error",
} as const;

function errorResponse(code: string, message: string, data?: object): MCPToolResponse {
    return {
        content: [{
            type: "text",
            text: `Error [${code}]: ${message}`,
        }],
        isError: true,
        structuredContent: {
            type: "object",
            value: { code, message, ...data },
        },
    };
}
```

### 6.8 Project Resolver

Multi-project resolution with security checks.

```typescript
class ProjectResolver {
    private registry: ProjectRegistry;

    async resolve(
        args: Record<string, unknown>,
        config: ServerConfig,
    ): Promise<string> {
        // 1. Explicit project parameter
        if (args.project) {
            return this.resolveByName(args.project as string);
        }

        // 2. Active project from registry
        const active = this.registry.getActive();
        if (active) return active.root;

        // 3. Fall back to config.projectRoot
        return config.projectRoot;
    }

    private resolveByName(name: string): string {
        // Exact match → ID match → path match → fuzzy match
        const project = this.registry.findByName(name)
            ?? this.registry.findById(name)
            ?? this.registry.findByPath(name)
            ?? this.registry.fuzzyFind(name);

        if (!project) {
            throw new DriftError("PROJECT_NOT_FOUND", `Unknown project: ${name}`, {
                similar: this.registry.suggest(name, 3),
            });
        }

        return project.root;
    }
}
```

**Path traversal prevention** (critical security):
```typescript
function validateProjectPath(requestedPath: string, projectRoot: string): string {
    const resolved = path.resolve(projectRoot, requestedPath);
    const normalized = path.normalize(resolved);
    if (!normalized.startsWith(path.normalize(projectRoot))) {
        throw new DriftError("INVALID_ARGUMENT",
            `Path traversal detected: ${requestedPath} is outside project root`);
    }
    return normalized;
}
```

### 6.9 Tool Filter

Auto-detects project languages and filters tools to only expose relevant ones.

```typescript
interface LanguageDetection {
    language: string;
    confidence: "high" | "medium" | "low";
    evidence: string[];  // ["tsconfig.json found", "42 .ts files"]
}

class ToolFilter {
    private detectedLanguages: LanguageDetection[] = [];

    async detect(projectRoot: string): Promise<LanguageDetection[]> {
        // Shallow scan: project root + 1 level
        // Check config files first (high confidence)
        // Then file extensions (medium confidence)
        // Cache result for session lifetime
    }

    filter(tools: ToolDefinition[]): ToolDefinition[] {
        const detected = new Set(this.detectedLanguages.map(l => l.language));
        return tools.filter(tool => {
            if (!tool.languageSpecific) return true;  // Core tools always available
            return detected.has(tool.language!);
        });
    }
}
```

**Language detection matrix** (preserved from v1):

| Language | Config Files | Extensions |
|----------|-------------|------------|
| TypeScript | `tsconfig.json` | `.ts`, `.tsx` |
| Python | `pyproject.toml`, `setup.py`, `requirements.txt` | `.py` |
| Java | `pom.xml`, `build.gradle` | `.java` |
| Go | `go.mod` | `.go` |
| Rust | `Cargo.toml` | `.rs` |
| PHP | `composer.json` | `.php` |
| C++ | `CMakeLists.txt`, `Makefile` | `.cpp`, `.h` |
| C# | `*.csproj`, `*.sln` | `.cs` |
| WPF | — | `.xaml` |

### 6.10 Startup Warmer

Pre-loads data on server initialization so tools work immediately.

```typescript
interface WarmupResult {
    success: boolean;
    duration: number;
    loaded: {
        patterns: number;
        callGraph: boolean;
        boundaries: boolean;
        env: number;
        dna: boolean;
        contracts: number;
        history: number;
        coupling: boolean;
        errorHandling: boolean;
        testTopology: boolean;
    };
    errors: string[];
}

async function warmupStores(native: NativeBindings): Promise<WarmupResult> {
    const start = Date.now();
    const result: WarmupResult = { success: true, duration: 0, loaded: {}, errors: [] };

    // v2: Single NAPI call to check materialized status
    try {
        const status = native.queryStatus();
        result.loaded = {
            patterns: status.patternCount,
            callGraph: status.callGraphBuilt,
            boundaries: status.boundariesDetected,
            env: status.envVarCount,
            dna: status.dnaAnalyzed,
            contracts: status.contractCount,
            history: status.historySnapshots,
            coupling: status.couplingAnalyzed,
            errorHandling: status.errorHandlingAnalyzed,
            testTopology: status.testTopologyAnalyzed,
        };
    } catch (err) {
        result.errors.push(`Warmup failed: ${err}`);
        result.success = false;
    }

    result.duration = Date.now() - start;
    return result;
}
```

v2 warmup is much simpler than v1 because:
- No JSON store loading (SQLite-only)
- No dual-path initialization
- Single NAPI call to `queryStatus()` checks all materialized views
- Background data building handled by Rust (not TS)


---

## 7. Pack System (Task-Oriented Tool Bundles)

### The Problem

Even with progressive disclosure, AI agents don't know which tools are relevant for
a specific workflow. A security audit needs different tools than a refactoring session.
The AI must either:
1. Call `drift_discover` and reason about 50+ tools (expensive)
2. Call `drift_context` and hope the `nextActions` cover everything (incomplete)

### The Solution: Packs

Packs are pre-defined bundles of tools + configuration for common workflows.
They reduce cognitive load for the AI and ensure complete coverage for specific tasks.

### Pack Definition

```typescript
interface PackDefinition {
    name: string;                      // "security-audit"
    title: string;                     // "Security Audit Pack"
    description: string;               // Human-readable description
    version: string;                   // Semver
    categories: string[];              // Pattern categories to include
    tools: string[];                   // Tool names in execution order
    patterns?: string[];               // Optional pattern name filters
    config: PackConfig;                // Pack-specific configuration
    triggers?: PackTrigger[];          // Auto-suggest conditions
}

interface PackConfig {
    maxExamples: number;               // Max code examples per pattern
    contextLines: number;              // Lines of context around examples
    minConfidence: number;             // Minimum pattern confidence (default: 0.5)
    includeDeprecated: boolean;        // Include deprecated patterns (default: false)
    depth: "overview" | "standard" | "deep";  // Context depth
    maxTokens: number;                 // Total token budget for pack
}

interface PackTrigger {
    type: "intent" | "file" | "keyword";
    value: string;                     // Intent name, file pattern, or keyword
}
```

### Built-In Packs

#### 1. Security Audit Pack
```typescript
{
    name: "security-audit",
    title: "Security Audit",
    description: "Complete security posture analysis: boundaries, secrets, " +
        "sensitive fields, reachability, taint analysis, OWASP mapping",
    tools: [
        "drift_security_summary",      // Overview
        "drift_patterns_list",         // Security patterns (filtered)
        "drift_reachability",          // Data flow analysis
        "drift_constraints",           // Security constraints
        "drift_quality_gate",          // Security gate results
    ],
    categories: ["security", "data-access", "authentication", "authorization"],
    config: {
        maxExamples: 3,
        contextLines: 5,
        minConfidence: 0.6,
        includeDeprecated: false,
        depth: "deep",
        maxTokens: 12000,
    },
    triggers: [
        { type: "intent", value: "security_audit" },
        { type: "keyword", value: "security" },
        { type: "keyword", value: "vulnerability" },
    ],
}
```

#### 2. Refactoring Pack
```typescript
{
    name: "refactoring",
    title: "Refactoring Assistant",
    description: "Architecture analysis for safe refactoring: coupling, " +
        "impact analysis, test coverage, constraints, contracts",
    tools: [
        "drift_coupling",             // Module dependencies
        "drift_impact_analysis",      // Blast radius
        "drift_test_topology",        // Test coverage
        "drift_constraints",          // Constraints to preserve
        "drift_contracts_list",       // API contracts to maintain
        "drift_wrappers",             // Wrapper patterns
    ],
    categories: ["architecture", "coupling", "contracts"],
    config: {
        maxExamples: 2,
        contextLines: 3,
        minConfidence: 0.5,
        includeDeprecated: false,
        depth: "standard",
        maxTokens: 8000,
    },
    triggers: [
        { type: "intent", value: "refactor" },
        { type: "keyword", value: "refactor" },
        { type: "keyword", value: "restructure" },
    ],
}
```

#### 3. Bug Fix Pack
```typescript
{
    name: "bug-fix",
    title: "Bug Fix Assistant",
    description: "Targeted analysis for bug fixing: callers, error handling, " +
        "recent changes, test templates, impact analysis",
    tools: [
        "drift_callers",              // Who calls the buggy function
        "drift_error_handling",       // Error handling gaps
        "drift_recent",               // Recent changes in the area
        "drift_impact_analysis",      // What else might be affected
        "drift_test_template",        // Generate regression test
        "drift_prevalidate",          // Validate fix before writing
    ],
    categories: ["error-handling", "testing"],
    config: {
        maxExamples: 3,
        contextLines: 5,
        minConfidence: 0.4,
        includeDeprecated: false,
        depth: "standard",
        maxTokens: 8000,
    },
    triggers: [
        { type: "intent", value: "fix_bug" },
        { type: "keyword", value: "bug" },
        { type: "keyword", value: "error" },
        { type: "keyword", value: "fix" },
    ],
}
```

#### 4. Code Review Pack
```typescript
{
    name: "code-review",
    title: "Code Review Assistant",
    description: "Pattern compliance, quality gates, DNA alignment, " +
        "constraint verification for PR review",
    tools: [
        "drift_prevalidate",           // Quick validation
        "drift_quality_gate",          // Gate results
        "drift_dna_profile",           // Style alignment
        "drift_constraints",           // Constraint compliance
        "drift_patterns_list",         // Relevant patterns
        "drift_validate_change",       // Validate against patterns
    ],
    categories: ["quality", "style", "constraints"],
    config: {
        maxExamples: 2,
        contextLines: 3,
        minConfidence: 0.6,
        includeDeprecated: false,
        depth: "standard",
        maxTokens: 6000,
    },
    triggers: [
        { type: "intent", value: "review_pr" },
        { type: "keyword", value: "review" },
        { type: "keyword", value: "PR" },
    ],
}
```

#### 5. New Feature Pack
```typescript
{
    name: "new-feature",
    title: "New Feature Assistant",
    description: "Architecture context for adding features: patterns, " +
        "similar code, imports, middleware, hooks, DNA alignment",
    tools: [
        "drift_context",              // Full context
        "drift_similar",              // Similar existing code
        "drift_imports",              // Import patterns
        "drift_middleware",            // Middleware chain
        "drift_hooks",                // Hook patterns
        "drift_dna_profile",          // Style to follow
        "drift_suggest_changes",      // Suggested approach
    ],
    categories: ["architecture", "patterns", "style"],
    config: {
        maxExamples: 3,
        contextLines: 5,
        minConfidence: 0.5,
        includeDeprecated: false,
        depth: "deep",
        maxTokens: 10000,
    },
    triggers: [
        { type: "intent", value: "add_feature" },
        { type: "keyword", value: "feature" },
        { type: "keyword", value: "implement" },
        { type: "keyword", value: "add" },
    ],
}
```

#### 6. Understanding Pack
```typescript
{
    name: "understand",
    title: "Codebase Understanding",
    description: "Deep codebase exploration: DNA, patterns, architecture, " +
        "decisions, trends, coupling",
    tools: [
        "drift_context",              // Overview
        "drift_dna_profile",          // Codebase fingerprint
        "drift_coupling",             // Architecture
        "drift_decisions",            // Decision history
        "drift_trends",               // Pattern trends
        "drift_patterns_list",        // All patterns
    ],
    categories: ["architecture", "patterns", "decisions"],
    config: {
        maxExamples: 5,
        contextLines: 7,
        minConfidence: 0.3,
        includeDeprecated: true,
        depth: "deep",
        maxTokens: 12000,
    },
    triggers: [
        { type: "intent", value: "understand_code" },
        { type: "keyword", value: "understand" },
        { type: "keyword", value: "explain" },
        { type: "keyword", value: "architecture" },
    ],
}
```

### Custom Packs

Users can define custom packs in `.drift/packs/` as JSON files:

```json
{
    "name": "my-api-review",
    "title": "API Review Pack",
    "description": "Custom pack for reviewing API changes",
    "version": "1.0.0",
    "tools": [
        "drift_contracts_list",
        "drift_security_summary",
        "drift_prevalidate",
        "drift_quality_gate"
    ],
    "categories": ["api", "security", "contracts"],
    "config": {
        "maxExamples": 3,
        "contextLines": 5,
        "minConfidence": 0.6,
        "depth": "standard",
        "maxTokens": 8000
    }
}
```

### Pack Manager

```typescript
class PackManager {
    private builtIn: Map<string, PackDefinition>;
    private custom: Map<string, PackDefinition>;
    private cache: Map<string, PackResult>;
    private usage: PackUsageTracker;

    constructor(projectRoot: string) {
        this.builtIn = loadBuiltInPacks();
        this.custom = loadCustomPacks(path.join(projectRoot, '.drift', 'packs'));
    }

    // Get all available packs
    list(): PackSummary[] {
        return [...this.builtIn.values(), ...this.custom.values()]
            .map(p => ({
                name: p.name,
                title: p.title,
                description: p.description,
                toolCount: p.tools.length,
                categories: p.categories,
                isCustom: this.custom.has(p.name),
            }));
    }

    // Suggest packs based on intent/context
    suggest(intent?: string, keywords?: string[]): SuggestedPack[] {
        const suggestions: SuggestedPack[] = [];
        for (const pack of [...this.builtIn.values(), ...this.custom.values()]) {
            if (!pack.triggers) continue;
            for (const trigger of pack.triggers) {
                if (trigger.type === "intent" && trigger.value === intent) {
                    suggestions.push({
                        name: pack.name,
                        title: pack.title,
                        description: pack.description,
                        reason: `Matches intent: ${intent}`,
                        confidence: 0.9,
                    });
                }
                if (trigger.type === "keyword" && keywords?.some(k =>
                    k.toLowerCase().includes(trigger.value.toLowerCase())
                )) {
                    suggestions.push({
                        name: pack.name,
                        title: pack.title,
                        description: pack.description,
                        reason: `Matches keyword: ${trigger.value}`,
                        confidence: 0.7,
                    });
                }
            }
        }
        return dedup(suggestions).sort((a, b) => b.confidence - a.confidence);
    }

    // Execute a pack (run all tools in sequence)
    async execute(
        packName: string,
        context: ServerContext,
        args?: Record<string, unknown>,
    ): Promise<PackResult> {
        const pack = this.builtIn.get(packName) ?? this.custom.get(packName);
        if (!pack) throw new DriftError("PACK_NOT_FOUND", `Unknown pack: ${packName}`);

        // Check cache
        const cacheKey = this.cacheKey(packName, args);
        const cached = this.cache.get(cacheKey);
        if (cached && !this.isStale(cached)) return cached;

        // Execute tools in order
        const results: Map<string, unknown> = new Map();
        let totalTokens = 0;

        for (const toolName of pack.tools) {
            if (totalTokens >= pack.config.maxTokens) break;

            const tool = context.toolRegistry.get(toolName);
            if (!tool) continue;

            const toolArgs = { ...args, ...this.packArgsForTool(pack, toolName) };
            const result = await tool.handler(toolArgs, context);
            results.set(toolName, result);
            totalTokens += result.meta?.tokenEstimate ?? 0;
        }

        const packResult: PackResult = {
            pack: pack.name,
            results,
            totalTokens,
            fromCache: false,
            generatedAt: new Date().toISOString(),
        };

        this.cache.set(cacheKey, packResult);
        this.usage.track(packName);
        return packResult;
    }
}
```

### Pack Integration with drift_discover

When AI calls `drift_discover`, the response includes available packs:

```typescript
{
    status: { ... },
    tools: { ... },
    packs: {
        available: [
            {
                name: "security-audit",
                title: "Security Audit",
                description: "Complete security posture analysis",
                toolCount: 5,
                categories: ["security", "data-access"],
                suggested: true,
                suggestReason: "Security patterns detected in project",
            },
            // ... other packs
        ],
        custom: [
            {
                name: "my-api-review",
                title: "API Review Pack",
                description: "Custom pack for reviewing API changes",
                toolCount: 4,
            }
        ],
        usage: "Use drift_tool({name: 'drift_pack', args: {pack: 'security-audit'}}) to execute"
    }
}
```

### Pack Execution via drift_tool

```typescript
// AI executes a pack
drift_tool({
    name: "drift_pack",
    args: {
        pack: "security-audit",
        focus: "auth",
        maxTokens: 8000,
    }
})

// Returns combined results from all pack tools
{
    summary: "Security audit of auth module: 3 boundaries detected, " +
        "2 sensitive fields, 1 constraint violation",
    data: {
        pack: "security-audit",
        results: {
            drift_security_summary: { ... },
            drift_patterns_list: { ... },
            drift_reachability: { ... },
            drift_constraints: { ... },
            drift_quality_gate: { ... },
        },
        totalTokens: 7200,
    },
    nextActions: [
        { tool: "drift_code_examples", args: { pattern: "auth-boundary" }, reason: "See examples" },
    ],
    meta: { durationMs: 450, tokenEstimate: 7200 }
}
```


---

## 8. Feedback System (Reinforcement Learning for Example Quality)

### Purpose

Tracks user feedback on pattern examples to improve future suggestions.
A reinforcement learning loop that boosts good examples and penalizes bad ones.

### How It Works

When AI shows a code example from a pattern, the user can rate it:

| Rating | Score Delta | Description |
|--------|------------|-------------|
| `good` | +0.1 | Example was helpful and accurate |
| `bad` | -0.15 | Example was wrong or misleading |
| `irrelevant` | -0.05 | Example was correct but not useful for the task |

**Asymmetric scoring**: Bad examples are penalized more than good examples are boosted.
This is intentional — one bad example erodes trust more than one good example builds it.

### Directory-Level Propagation

30% of file-level delta propagates to the directory score. This means:
- If `src/auth/login.ts` gets a `bad` rating (-0.15), `src/auth/` gets -0.045
- If multiple files in a directory are bad, the directory score drops faster
- This helps identify "noisy" directories that produce poor examples

### File Exclusion

Files are excluded from future examples when:
- `boost < -0.5` AND `confidence > 0.5`
- This means consistently bad examples from a file get it removed
- Confidence threshold prevents premature exclusion from few ratings

### Score → Multiplier Conversion

```
multiplier = 1 + (boost × 0.7)
// Range: 0.3 (heavily penalized) to 1.7 (heavily boosted)
```

When selecting examples for a pattern, each file's base relevance score is
multiplied by this feedback multiplier. Files with negative feedback sink
to the bottom; files with positive feedback rise to the top.

### Types

```typescript
interface ExampleFeedback {
    patternId: string;
    patternName: string;
    category: string;
    file: string;
    line: number;
    rating: "good" | "bad" | "irrelevant";
    reason?: string;
    timestamp: string;
}

interface LocationScore {
    file: string;
    boost: number;          // Cumulative score (-1.0 to +1.0 range)
    confidence: number;     // Based on feedback count (0.0 to 1.0)
    feedbackCount: number;
    lastFeedback: string;   // ISO timestamp
}

interface FeedbackStats {
    totalFeedback: number;
    goodExamples: number;
    badExamples: number;
    irrelevantExamples: number;
    topGoodPatterns: Array<{ pattern: string; count: number }>;
    topBadPatterns: Array<{ pattern: string; count: number }>;
    topBadFiles: Array<{ file: string; count: number }>;
    excludedFiles: number;
}
```

### Storage

v1 stores feedback in JSON files (`.drift/feedback/`).
v2 stores feedback in drift.db (feedback table + scores table).

```sql
CREATE TABLE IF NOT EXISTS feedback_examples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern_id TEXT NOT NULL,
    pattern_name TEXT NOT NULL,
    category TEXT NOT NULL,
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    rating TEXT NOT NULL CHECK (rating IN ('good', 'bad', 'irrelevant')),
    reason TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (pattern_id) REFERENCES patterns(id)
) STRICT;

CREATE TABLE IF NOT EXISTS feedback_scores (
    file TEXT PRIMARY KEY,
    boost REAL NOT NULL DEFAULT 0.0,
    confidence REAL NOT NULL DEFAULT 0.0,
    feedback_count INTEGER NOT NULL DEFAULT 0,
    last_feedback TEXT NOT NULL,
    excluded INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE INDEX idx_feedback_pattern ON feedback_examples(pattern_id);
CREATE INDEX idx_feedback_file ON feedback_examples(file);
CREATE INDEX idx_feedback_rating ON feedback_examples(rating);
CREATE INDEX idx_scores_excluded ON feedback_scores(excluded) WHERE excluded = 1;
```

### NAPI Functions

```typescript
// In drift-napi
recordFeedback(feedback: ExampleFeedback): void;
queryFeedbackStats(): FeedbackStats;
queryFileScore(file: string): LocationScore | null;
queryExcludedFiles(): string[];
```

### MCP Integration

Feedback is collected via `drift_tool`:

```typescript
drift_tool({
    name: "drift_feedback",
    args: {
        patternId: "auth-middleware-pattern",
        file: "src/auth/middleware.ts",
        line: 42,
        rating: "good",
        reason: "Clear example of the middleware chain pattern"
    }
})
```

---

## 9. Curation System (Anti-Hallucination Verification)

### Purpose

Pattern approval workflow with anti-hallucination verification. When an AI agent
wants to approve a pattern, it must provide evidence (files, snippets, reasoning)
that the curation system verifies against actual code before allowing approval.

This prevents AI from approving patterns based on hallucinated evidence.

### The Curation Flow

```
1. AI calls drift_curate action="review" patternId="..."
   → Returns pattern details + evidence requirements for its confidence level

2. AI gathers evidence (reads files, finds snippets)

3. AI calls drift_curate action="verify" patternId="..." evidence={files, snippets, reasoning}
   → Verifier reads actual files, checks claims
   → Returns VerificationResult with score and canApprove flag

4. If canApprove=true:
   AI calls drift_curate action="approve" patternId="..." evidence={...}
   → Pattern status changes to "approved"
   → Audit record created
   → DriftEventHandler.on_pattern_approved() emitted (D5)

5. If canApprove=false:
   Response includes approvalRequirements explaining what's missing
```

### Evidence Requirements

Scale with pattern confidence level:

| Confidence | Min Verified Files | Require Snippets | Reasoning |
|-----------|-------------------|-------------------|-----------|
| High (≥0.85) | 1 | No | Optional |
| Medium (≥0.70) | 2 | Yes | Required |
| Low (≥0.50) | 3 | Yes | Required (detailed) |
| Uncertain (<0.50) | 3 | Yes | Required (comprehensive) |

### Verification Algorithm

For each claimed file:
1. Read the actual file from disk (via NAPI for speed)
2. Check if pattern locations reference this file
3. If locations found, verify line numbers are within file bounds
4. If snippets provided, check if any snippet appears in file content (fuzzy match)
5. Mark as verified if locations match OR snippets found

**Verification score:**
```
verificationScore = verifiedChecks / totalChecks
```

| Score | Status |
|-------|--------|
| ≥ 0.80 | `verified` |
| ≥ 0.50 | `partial` |
| < 0.50 | `failed` |

**Approval blocked if any of:**
- Verified file count < minimum for confidence level
- Snippets required but not provided
- Verification score below minimum (configurable, default 0.50)
- Reasoning missing or too short (< 20 chars)

### Types

```typescript
interface CurationEvidence {
    files: string[];               // Files where pattern appears
    snippets?: string[];           // Code snippets as evidence
    reasoning: string;             // Why this pattern should be approved
}

interface VerificationResult {
    verified: boolean;
    patternId: string;
    patternName: string;
    confidence: number;
    evidenceChecks: EvidenceCheck[];
    verificationScore: number;
    verificationStatus: "verified" | "partial" | "failed";
    canApprove: boolean;
    approvalRequirements?: string[];
}

interface EvidenceCheck {
    file: string;
    claimed: boolean;              // Was this file claimed by AI?
    verified: boolean;             // Does evidence check out?
    matchedLines?: number[];
    snippet?: string;              // Actual code from file
    error?: string;
}
```

### Curation Actions (6)

| Action | Purpose | Returns |
|--------|---------|---------|
| `review` | Get pattern details + evidence requirements | Pattern info + requirements |
| `verify` | Verify AI-claimed evidence against actual code | VerificationResult |
| `approve` | Approve pattern (requires prior verification) | Approval confirmation |
| `ignore` | Ignore pattern (mark as not relevant) | Confirmation |
| `bulk_approve` | Approve multiple patterns at once | Batch results |
| `audit` | Run pattern audit (health check) | Audit results |

### Audit Trail

All curation decisions are persisted for accountability:

```sql
CREATE TABLE IF NOT EXISTS curation_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('approve', 'ignore', 'reject')),
    evidence_json TEXT,            -- JSON blob of CurationEvidence
    verification_score REAL,
    verification_status TEXT,
    actor TEXT NOT NULL DEFAULT 'ai',  -- 'ai' or 'human'
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (pattern_id) REFERENCES patterns(id)
) STRICT;

CREATE INDEX idx_curation_pattern ON curation_audit(pattern_id);
CREATE INDEX idx_curation_action ON curation_audit(action);
CREATE INDEX idx_curation_created ON curation_audit(created_at);
```

---

## 10. Server Implementation

### 10.1 Entry Points

#### stdio Transport (Primary — IDE Integration)

```typescript
// bin/drift-analysis-server.ts
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createAnalysisServer } from "../src/analysis-server.js";

async function main() {
    const projectRoot = resolveProjectRoot(process.argv);
    const server = await createAnalysisServer({ projectRoot });
    const transport = new StdioServerTransport();
    await server.connect(transport);
}

main().catch(console.error);
```

```typescript
// bin/drift-memory-server.ts
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createMemoryServer } from "../src/memory-server.js";

async function main() {
    const projectRoot = resolveProjectRoot(process.argv);
    const server = await createMemoryServer({ projectRoot });
    const transport = new StdioServerTransport();
    await server.connect(transport);
}

main().catch(console.error);
```

#### Streamable HTTP Transport (Containerized Deployment)

```typescript
// bin/drift-http-server.ts
import { createServer } from "http";
import { StreamableHTTPServerTransport }
    from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { createAnalysisServer } from "../src/analysis-server.js";
import { createMemoryServer } from "../src/memory-server.js";

async function main() {
    const config = loadHttpConfig();
    const analysisServer = await createAnalysisServer(config);
    const memoryServer = config.cortexEnabled
        ? await createMemoryServer(config)
        : null;

    const httpServer = createServer(async (req, res) => {
        // Health check
        if (req.url === "/health" && req.method === "GET") {
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ status: "ok" }));
            return;
        }

        // Route to appropriate MCP server based on path
        if (req.url?.startsWith("/analysis")) {
            const transport = new StreamableHTTPServerTransport("/analysis");
            await analysisServer.connect(transport);
            await transport.handleRequest(req, res);
        } else if (req.url?.startsWith("/memory") && memoryServer) {
            const transport = new StreamableHTTPServerTransport("/memory");
            await memoryServer.connect(transport);
            await transport.handleRequest(req, res);
        } else {
            res.writeHead(404);
            res.end("Not found");
        }
    });

    httpServer.listen(config.port, () => {
        console.log(`Drift MCP HTTP server listening on port ${config.port}`);
        console.log(`  Analysis: http://localhost:${config.port}/analysis`);
        if (memoryServer) {
            console.log(`  Memory:   http://localhost:${config.port}/memory`);
        }
    });
}

main().catch(console.error);
```

#### Project Root Resolution

Same priority as v1, preserved exactly:

```typescript
function resolveProjectRoot(argv: string[]): string {
    // 1. Explicit path argument
    if (argv[2]) return path.resolve(argv[2]);

    // 2. Active project from ~/.drift/projects.json
    const active = getActiveProject();
    if (active) return active;

    // 3. Auto-detect: walk up from cwd looking for project markers
    const markers = [
        ".git", "package.json", "Cargo.toml", "go.mod", "pom.xml",
        "build.gradle", "pyproject.toml", "setup.py", "composer.json",
        "*.csproj", "*.sln", "Gemfile", "CMakeLists.txt",
    ];
    const detected = walkUpForMarker(process.cwd(), markers);
    if (detected) return detected;

    // 4. Fall back to cwd
    return process.cwd();
}
```

### 10.2 Analysis Server Creation

```typescript
interface AnalysisServerConfig {
    projectRoot: string;
    enableCache?: boolean;              // Default: true
    enableRateLimiting?: boolean;       // Default: true
    enableMetrics?: boolean;            // Default: true
    maxRequestsPerMinute?: number;      // Default: 120
    verbose?: boolean;
    skipWarmup?: boolean;               // Default: false
}

async function createAnalysisServer(
    config: AnalysisServerConfig,
): Promise<Server> {
    const server = new Server(
        { name: "drift-analysis", version: "2.0.0" },
        {
            capabilities: {
                tools: { listChanged: true },
                resources: { subscribe: true },
            },
        },
    );

    // 1. Load native module
    const native = loadNativeModule();  // drift-napi

    // 2. Initialize Drift runtime
    native.driftInitialize(
        path.join(config.projectRoot, ".drift", "drift.db"),
        config.projectRoot,
        null,  // Use default config
        detectCortex(config),  // ATTACH cortex.db if available
    );

    // 3. Create infrastructure
    const cache = config.enableCache !== false
        ? new ResponseCache({ l1MaxSize: 200 })
        : null;
    const rateLimiter = config.enableRateLimiting !== false
        ? new RateLimiter({ global: { maxRequests: config.maxRequestsPerMinute ?? 120 } })
        : null;
    const metrics = config.enableMetrics !== false
        ? new MetricsCollector()
        : null;
    const cursorManager = new CursorManager();
    const tokenEstimator = new TokenEstimator(native);
    const packManager = new PackManager(config.projectRoot);
    const projectResolver = new ProjectResolver(config.projectRoot);
    const toolFilter = new ToolFilter();

    // 4. Detect languages
    const languages = await toolFilter.detect(config.projectRoot);

    // 5. Build tool registry
    const toolRegistry = buildAnalysisToolRegistry(native, {
        cache, rateLimiter, metrics, cursorManager,
        tokenEstimator, packManager, projectResolver, toolFilter,
        languages,
    });

    // 6. Warmup
    if (config.skipWarmup !== true) {
        const warmup = await warmupStores(native);
        if (config.verbose) {
            console.error(`Warmup: ${warmup.duration}ms, patterns: ${warmup.loaded.patterns}`);
        }
    }

    // 7. Register MCP handlers
    server.setRequestHandler("tools/list", async () => ({
        tools: getEntryPointTools(languages),  // Only 3 tools
    }));

    server.setRequestHandler("tools/call", async (request) => {
        const { name, arguments: args } = request.params;
        const startTime = Date.now();

        try {
            switch (name) {
                case "drift_context":
                    return await handleDriftContext(args, toolRegistry, native);
                case "drift_discover":
                    return await handleDriftDiscover(args, toolRegistry, packManager, languages);
                case "drift_tool":
                    return await handleDriftTool(args.name, args.args, {
                        native, toolRegistry, cache, rateLimiter,
                        metrics, cursorManager, tokenEstimator,
                        projectResolver, projectRoot: config.projectRoot,
                    });
                default:
                    return errorResponse("TOOL_NOT_FOUND", `Unknown tool: ${name}`, {
                        hint: "Available tools: drift_context, drift_discover, drift_tool",
                    });
            }
        } catch (err) {
            if (err instanceof DriftError) {
                return errorResponse(err.code, err.message, err.data);
            }
            metrics?.recordError(name, "INTERNAL_ERROR");
            return errorResponse("INTERNAL_ERROR", String(err));
        } finally {
            metrics?.record(name, Date.now() - startTime, true);
        }
    });

    // 8. Detect Cortex and conditionally register bridge tools
    if (detectCortex(config)) {
        registerBridgeTools(server, native, toolRegistry);
    }

    return server;
}
```

### 10.3 Memory Server Creation

```typescript
async function createMemoryServer(
    config: AnalysisServerConfig,
): Promise<Server> {
    const server = new Server(
        { name: "drift-memory", version: "2.0.0" },
        {
            capabilities: {
                tools: { listChanged: true },
            },
        },
    );

    // 1. Load native modules
    const cortexNative = loadCortexNativeModule();  // cortex-napi
    const driftNative = loadNativeModule();          // drift-napi (for read-only drift.db)

    // 2. Initialize Cortex runtime
    cortexNative.cortexInitialize(
        path.join(config.projectRoot, ".drift", "memory", "cortex.db"),
        null,  // Use default config
        false, // Cloud disabled by default
    );

    // 3. Create infrastructure (lighter than analysis server)
    const cache = new ResponseCache({ l1MaxSize: 100 });
    const rateLimiter = new RateLimiter({ global: { maxRequests: 60 } });
    const metrics = new MetricsCollector();

    // 4. Build memory tool registry
    const toolRegistry = buildMemoryToolRegistry(cortexNative, driftNative, {
        cache, rateLimiter, metrics,
    });

    // 5. Register MCP handlers (3 entry points)
    server.setRequestHandler("tools/list", async () => ({
        tools: getMemoryEntryPointTools(),
    }));

    server.setRequestHandler("tools/call", async (request) => {
        const { name, arguments: args } = request.params;
        switch (name) {
            case "drift_memory_context":
                return await handleMemoryContext(args, toolRegistry, cortexNative);
            case "drift_memory_manage":
                return await handleMemoryManage(args, toolRegistry, cortexNative);
            case "drift_memory_discover":
                return await handleMemoryDiscover(args, toolRegistry, cortexNative);
            default:
                return errorResponse("TOOL_NOT_FOUND", `Unknown tool: ${name}`);
        }
    });

    return server;
}
```


---

## 11. Tool Registry Architecture

### Category-Based Registration

Each tool category is a self-contained module with its own handler functions.
The central registry aggregates all categories.

```typescript
interface ToolHandler {
    name: string;
    title: string;
    description: string;
    inputSchema: object;
    category: string;
    tokenCost: string;
    cacheTtl: number;                  // ms, 0 = no cache
    expensive: boolean;                // Subject to expensive rate limit
    languageSpecific?: boolean;
    language?: string;
    requiresAnalysis: boolean;         // Needs drift scan first?
    handler: (args: Record<string, unknown>, ctx: ServerContext) => Promise<MCPToolResponse>;
}

class ToolRegistry {
    private tools: Map<string, ToolHandler> = new Map();
    private categories: Map<string, ToolHandler[]> = new Map();

    register(tool: ToolHandler): void {
        this.tools.set(tool.name, tool);
        const cat = this.categories.get(tool.category) ?? [];
        cat.push(tool);
        this.categories.set(tool.category, cat);
    }

    get(name: string): ToolHandler | undefined {
        return this.tools.get(name);
    }

    list(filter?: ToolFilter): ToolHandler[] {
        let tools = [...this.tools.values()];
        if (filter) {
            tools = filter.filter(tools);
        }
        return tools;
    }

    fuzzyMatch(name: string, limit: number): string[] {
        // Levenshtein distance matching for "did you mean?" suggestions
        return [...this.tools.keys()]
            .map(k => ({ name: k, distance: levenshtein(name, k) }))
            .sort((a, b) => a.distance - b.distance)
            .slice(0, limit)
            .map(m => m.name);
    }

    byCategory(): Map<string, ToolHandler[]> {
        return new Map(this.categories);
    }
}
```

### Tool Registration by Category

```typescript
function buildAnalysisToolRegistry(
    native: NativeBindings,
    infra: InfrastructureContext,
): ToolRegistry {
    const registry = new ToolRegistry();

    // Register all categories
    registerOrchestrationTools(registry, native, infra);
    registerDiscoveryTools(registry, native, infra);
    registerSurgicalTools(registry, native, infra);
    registerExplorationTools(registry, native, infra);
    registerDetailTools(registry, native, infra);
    registerAnalysisTools(registry, native, infra);
    registerGenerationTools(registry, native, infra);
    registerSetupTools(registry, native, infra);
    registerCurationTools(registry, native, infra);
    registerUtilityTools(registry, native, infra);

    // Filter by detected languages
    // (language-specific tools only if language detected)

    return registry;
}
```

### Example: Surgical Tool Registration

```typescript
function registerSurgicalTools(
    registry: ToolRegistry,
    native: NativeBindings,
    infra: InfrastructureContext,
): void {
    registry.register({
        name: "drift_callers",
        title: "Find Callers",
        description: "Find all functions that call a given function",
        inputSchema: {
            type: "object",
            properties: {
                function: { type: "string", description: "Function name or ID" },
                depth: { type: "number", description: "Max call depth (default: 1)" },
            },
            required: ["function"],
        },
        category: "surgical",
        tokenCost: "~200-500",
        cacheTtl: 300_000,  // 5 min
        expensive: false,
        requiresAnalysis: true,
        handler: async (args, ctx) => {
            const functionId = args.function as string;
            const depth = (args.depth as number) ?? 1;

            const callers = native.queryCallers(functionId);
            if (!callers || callers.length === 0) {
                return new ResponseBuilder()
                    .withSummary(`No callers found for ${functionId}`)
                    .withData({ callers: [], function: functionId })
                    .withNextActions([
                        { tool: "drift_callees", args: { function: functionId },
                          reason: "Check what this function calls instead", priority: "medium" },
                    ])
                    .build(Date.now());
            }

            return new ResponseBuilder()
                .withSummary(`Found ${callers.length} callers of ${functionId}`)
                .withData({ callers, function: functionId, depth })
                .withNextActions([
                    { tool: "drift_impact_analysis", args: { function: functionId },
                      reason: "See full blast radius", priority: "high" },
                    { tool: "drift_signature", args: { function: callers[0].name },
                      reason: "Inspect top caller", priority: "medium" },
                ])
                .build(Date.now());
        },
    });

    registry.register({
        name: "drift_signature",
        title: "Function Signature",
        description: "Get the full signature of a function or class",
        inputSchema: {
            type: "object",
            properties: {
                function: { type: "string", description: "Function or class name" },
                includeBody: { type: "boolean", description: "Include function body (default: false)" },
            },
            required: ["function"],
        },
        category: "surgical",
        tokenCost: "~100-300",
        cacheTtl: 300_000,
        expensive: false,
        requiresAnalysis: true,
        handler: async (args, ctx) => {
            const result = native.queryCallGraph(args.function as string, 0);
            return new ResponseBuilder()
                .withSummary(`Signature for ${args.function}`)
                .withData(result)
                .build(Date.now());
        },
    });

    // ... register remaining 10 surgical tools
}
```

---

## 12. Response Schema Contracts

### Universal Response Envelope

Every tool response follows the same envelope structure:

```typescript
interface MCPToolResponse {
    // MCP protocol fields
    content: Array<{ type: "text"; text: string }>;
    structuredContent?: {
        type: "object";
        value: DriftResponse;
    };
    isError?: boolean;
    resourceLinks?: ResourceLink[];
    _meta?: Record<string, unknown>;
}

interface DriftResponse<T = unknown> {
    summary: string;                    // 1-2 sentence human-readable summary
    data: T;                            // Tool-specific payload
    pagination?: PaginationInfo;        // Present for list operations
    nextActions?: NextAction[];         // Suggested follow-up tools
    warnings?: string[];                // Non-fatal warnings
    meta: ResponseMeta;                 // Timing, tokens, freshness
}

interface PaginationInfo {
    total: number;
    hasMore: boolean;
    nextCursor: string | null;
    pageSize: number;
}

interface NextAction {
    tool: string;
    args: Record<string, unknown>;
    reason: string;
    priority: "high" | "medium" | "low";
}

interface ResponseMeta {
    durationMs: number;
    tokenEstimate: number;
    cached: boolean;
    freshness: "fresh" | "stale" | "unknown";
    dataAge?: string;                   // ISO timestamp of last scan
}
```

### Consistent Error Response

```typescript
interface DriftErrorResponse {
    code: string;                       // Error code from registry
    message: string;                    // Human-readable message
    hint?: string;                      // Recovery suggestion
    alternativeTools?: string[];        // Tools that might help
    retryAfterMs?: number;             // For rate limiting
    command?: string;                   // CLI command to fix
    similar?: string[];                 // For TOOL_NOT_FOUND
}
```

### Pagination Contract

All list operations use keyset pagination:

```typescript
// Request
{
    cursor?: string;                    // Opaque cursor from previous page
    limit?: number;                     // Max items (default: 50, max: 100)
    sortBy?: string;                    // Sort field
    sortOrder?: "asc" | "desc";        // Sort direction (default: "desc")
}

// Response includes pagination info
{
    data: { items: T[], ... },
    pagination: {
        total: 342,
        hasMore: true,
        nextCursor: "eyJsYXN0SWQiOiIxMjMiLCJsYXN0U2NvcmUiOjAuODV9",
        pageSize: 50,
    }
}
```

---

## 13. File Module Structure

```
packages/drift-mcp/
├── package.json
├── tsconfig.json
├── bin/
│   ├── drift-analysis-server.ts       # stdio entry point (drift-analysis)
│   ├── drift-memory-server.ts         # stdio entry point (drift-memory)
│   └── drift-http-server.ts           # Streamable HTTP entry point (both servers)
├── src/
│   ├── analysis-server.ts             # createAnalysisServer()
│   ├── memory-server.ts               # createMemoryServer()
│   ├── tool-registry.ts               # ToolRegistry class
│   ├── tools/
│   │   ├── index.ts                   # Barrel exports
│   │   ├── orchestration/
│   │   │   ├── context.ts             # drift_context handler
│   │   │   ├── package-context.ts     # drift_package_context handler
│   │   │   └── index.ts              # registerOrchestrationTools()
│   │   ├── discovery/
│   │   │   ├── status.ts             # drift_status handler
│   │   │   ├── capabilities.ts       # drift_capabilities handler
│   │   │   ├── projects.ts           # drift_projects handler
│   │   │   └── index.ts             # registerDiscoveryTools()
│   │   ├── surgical/
│   │   │   ├── callers.ts            # drift_callers handler
│   │   │   ├── signature.ts          # drift_signature handler
│   │   │   ├── type.ts               # drift_type handler
│   │   │   ├── imports.ts            # drift_imports handler
│   │   │   ├── prevalidate.ts        # drift_prevalidate handler
│   │   │   ├── similar.ts            # drift_similar handler
│   │   │   ├── recent.ts             # drift_recent handler
│   │   │   ├── dependencies.ts       # drift_dependencies handler
│   │   │   ├── test-template.ts      # drift_test_template handler
│   │   │   ├── middleware.ts         # drift_middleware handler
│   │   │   ├── hooks.ts              # drift_hooks handler
│   │   │   ├── errors.ts             # drift_errors handler
│   │   │   └── index.ts             # registerSurgicalTools()
│   │   ├── exploration/
│   │   │   ├── patterns-list.ts      # drift_patterns_list handler
│   │   │   ├── security-summary.ts   # drift_security_summary handler
│   │   │   ├── contracts-list.ts     # drift_contracts_list handler
│   │   │   ├── env.ts                # drift_env handler
│   │   │   ├── trends.ts             # drift_trends handler
│   │   │   └── index.ts             # registerExplorationTools()
│   │   ├── detail/
│   │   │   ├── pattern-get.ts        # drift_pattern_get handler
│   │   │   ├── code-examples.ts      # drift_code_examples handler
│   │   │   ├── files-list.ts         # drift_files_list handler
│   │   │   ├── file-patterns.ts      # drift_file_patterns handler
│   │   │   ├── impact-analysis.ts    # drift_impact_analysis handler
│   │   │   ├── reachability.ts       # drift_reachability handler
│   │   │   ├── dna-profile.ts        # drift_dna_profile handler
│   │   │   ├── wrappers.ts           # drift_wrappers handler
│   │   │   └── index.ts             # registerDetailTools()
│   │   ├── analysis/
│   │   │   ├── coupling.ts           # drift_coupling handler
│   │   │   ├── test-topology.ts      # drift_test_topology handler
│   │   │   ├── error-handling.ts     # drift_error_handling handler
│   │   │   ├── quality-gate.ts       # drift_quality_gate handler
│   │   │   ├── constants.ts          # drift_constants handler
│   │   │   ├── constraints.ts        # drift_constraints handler
│   │   │   ├── audit.ts              # drift_audit handler
│   │   │   ├── decisions.ts          # drift_decisions handler
│   │   │   ├── simulate.ts           # drift_simulate handler
│   │   │   ├── languages/
│   │   │   │   ├── typescript.ts     # drift_typescript handler
│   │   │   │   ├── python.ts         # drift_python handler
│   │   │   │   ├── java.ts           # drift_java handler
│   │   │   │   ├── php.ts            # drift_php handler
│   │   │   │   ├── go.ts             # drift_go handler
│   │   │   │   ├── rust.ts           # drift_rust handler
│   │   │   │   ├── cpp.ts            # drift_cpp handler
│   │   │   │   └── wpf.ts           # drift_wpf handler
│   │   │   └── index.ts             # registerAnalysisTools()
│   │   ├── generation/
│   │   │   ├── explain.ts            # drift_explain handler
│   │   │   ├── validate-change.ts    # drift_validate_change handler
│   │   │   ├── suggest-changes.ts    # drift_suggest_changes handler
│   │   │   └── index.ts             # registerGenerationTools()
│   │   ├── setup/
│   │   │   ├── handler.ts            # drift_setup handler
│   │   │   ├── telemetry.ts          # drift_telemetry handler
│   │   │   └── index.ts             # registerSetupTools()
│   │   ├── curation/
│   │   │   ├── handler.ts            # drift_curate handler (6 actions)
│   │   │   ├── verifier.ts           # Anti-hallucination evidence verification
│   │   │   ├── types.ts              # CurationEvidence, VerificationResult
│   │   │   └── index.ts             # registerCurationTools()
│   │   ├── memory/
│   │   │   ├── status.ts             # drift_memory_status handler
│   │   │   ├── add.ts                # drift_memory_add handler
│   │   │   ├── get.ts                # drift_memory_get handler
│   │   │   ├── update.ts             # drift_memory_update handler
│   │   │   ├── delete.ts             # drift_memory_delete handler
│   │   │   ├── search.ts             # drift_memory_search handler
│   │   │   ├── query.ts              # drift_memory_query handler
│   │   │   ├── why.ts                # drift_why handler (bridge tool)
│   │   │   ├── for-context.ts        # drift_memory_for_context handler
│   │   │   ├── explain.ts            # drift_memory_explain handler
│   │   │   ├── learn.ts              # drift_memory_learn handler
│   │   │   ├── feedback.ts           # drift_memory_feedback handler
│   │   │   ├── validate.ts           # drift_memory_validate handler
│   │   │   ├── consolidate.ts        # drift_memory_consolidate handler
│   │   │   ├── health.ts             # drift_memory_health handler
│   │   │   ├── predict.ts            # drift_memory_predict handler
│   │   │   ├── conflicts.ts          # drift_memory_conflicts handler
│   │   │   ├── contradictions.ts     # drift_memory_contradictions handler
│   │   │   ├── warnings.ts           # drift_memory_warnings handler
│   │   │   ├── suggest.ts            # drift_memory_suggest handler
│   │   │   ├── graph.ts              # drift_memory_graph handler
│   │   │   ├── import.ts             # drift_memory_import handler
│   │   │   ├── export.ts             # drift_memory_export handler
│   │   │   ├── agent-spawn.ts        # drift_memory_agent_spawn handler
│   │   │   ├── entity.ts             # drift_memory_entity handler
│   │   │   ├── goal.ts               # drift_memory_goal handler
│   │   │   ├── workflow.ts           # drift_memory_workflow handler
│   │   │   ├── incident.ts           # drift_memory_incident handler
│   │   │   ├── meeting.ts            # drift_memory_meeting handler
│   │   │   ├── skill.ts              # drift_memory_skill handler
│   │   │   ├── conversation.ts       # drift_memory_conversation handler
│   │   │   ├── environment.ts        # drift_memory_environment handler
│   │   │   └── index.ts             # registerMemoryTools()
│   │   └── utility/
│   │       ├── pack.ts               # drift_pack handler
│   │       ├── feedback.ts           # drift_feedback handler
│   │       ├── cache-clear.ts        # drift_cache_clear handler
│   │       └── index.ts             # registerUtilityTools()
│   ├── infrastructure/
│   │   ├── index.ts                   # Barrel exports
│   │   ├── cache.ts                   # ResponseCache (L1 LRU + L2 file)
│   │   ├── rate-limiter.ts            # RateLimiter (sliding window, 3 tiers)
│   │   ├── metrics.ts                 # MetricsCollector (Prometheus-compatible)
│   │   ├── token-estimator.ts         # TokenEstimator (tiktoken-rs + heuristic)
│   │   ├── cursor-manager.ts          # CursorManager (HMAC-signed, versioned)
│   │   ├── response-builder.ts        # ResponseBuilder (fluent API)
│   │   ├── error-handler.ts           # DriftError, error codes, errorResponse()
│   │   ├── project-resolver.ts        # ProjectResolver (multi-project, security)
│   │   ├── startup-warmer.ts          # warmupStores() (single NAPI call)
│   │   └── tool-filter.ts            # ToolFilter (language detection + filtering)
│   ├── packs/
│   │   ├── index.ts                   # PackManager class
│   │   ├── built-in/
│   │   │   ├── security-audit.ts      # Security audit pack definition
│   │   │   ├── refactoring.ts         # Refactoring pack definition
│   │   │   ├── bug-fix.ts             # Bug fix pack definition
│   │   │   ├── code-review.ts         # Code review pack definition
│   │   │   ├── new-feature.ts         # New feature pack definition
│   │   │   └── understand.ts         # Understanding pack definition
│   │   └── loader.ts                 # Custom pack loader (.drift/packs/)
│   ├── feedback/
│   │   ├── index.ts                   # FeedbackManager class
│   │   ├── scorer.ts                  # Score calculation + propagation
│   │   └── types.ts                  # ExampleFeedback, LocationScore, FeedbackStats
│   ├── bridge/
│   │   ├── index.ts                   # Bridge tool registration
│   │   ├── detection.ts              # Cortex detection logic
│   │   └── tools.ts                  # drift_why, drift_memory_learn, drift_grounding_check
│   └── types/
│       ├── index.ts                   # Barrel exports
│       ├── responses.ts               # DriftResponse, MCPToolResponse, ResponseMeta
│       ├── pagination.ts              # PaginationInfo, PaginationOptions
│       ├── tools.ts                   # ToolHandler, ToolDefinition, ToolCategory
│       └── packs.ts                  # PackDefinition, PackResult, PackConfig
├── __tests__/
│   ├── analysis-server.test.ts        # Server initialization tests
│   ├── memory-server.test.ts          # Memory server tests
│   ├── progressive-disclosure.test.ts # Progressive disclosure flow tests
│   ├── tool-registry.test.ts          # Registry tests
│   ├── pack-manager.test.ts           # Pack system tests
│   ├── feedback.test.ts               # Feedback system tests
│   ├── curation.test.ts               # Curation verification tests
│   ├── cache.test.ts                  # Cache tests
│   ├── rate-limiter.test.ts           # Rate limiter tests
│   ├── cursor-manager.test.ts         # Cursor tests
│   ├── project-resolver.test.ts       # Project resolution + path traversal tests
│   ├── tool-filter.test.ts            # Language detection tests
│   └── integration/
│       ├── full-flow.test.ts          # End-to-end MCP flow tests
│       └── bridge-tools.test.ts      # Bridge tool integration tests
└── README.md
```

---

## 14. Integration Points

### drift-mcp → drift-napi

All analysis tools call drift-napi functions. The MCP server is a thin routing +
formatting layer. No analysis logic lives in TypeScript.

```
tools/surgical/callers.ts      → native.queryCallers()
tools/surgical/signature.ts    → native.queryCallGraph()
tools/exploration/patterns.ts  → native.queryPatterns()
tools/detail/impact.ts         → native.analyzeImpact()
tools/analysis/coupling.ts     → native.analyzeCoupling()
tools/analysis/quality-gate.ts → native.runQualityGates()
tools/orchestration/context.ts → native.generateContext()
```

### drift-mcp → cortex-napi (Optional)

Memory tools call cortex-napi functions. Only when Cortex is detected.

```
tools/memory/add.ts            → cortexNative.cortexMemoryCreate()
tools/memory/search.ts         → cortexNative.cortexRetrievalSearch()
tools/memory/why.ts            → cortexNative.cortexRetrievalRetrieve() + native.queryPatterns()
```

### drift-mcp → drift.db (Indirect)

The MCP server NEVER accesses drift.db directly. All data access goes through
drift-napi, which goes through drift-core's storage layer.

### drift-mcp → .drift/ (Direct)

The MCP server reads/writes a few files directly:
- `.drift/packs/` — Custom pack definitions (JSON)
- `~/.drift/projects.json` — Project registry
- `.drift/config.json` — Tool filter overrides

### drift-mcp → MCP SDK

Uses `@modelcontextprotocol/sdk` for protocol handling:
- `Server` class for server creation
- `StdioServerTransport` for stdio transport
- `StreamableHTTPServerTransport` for HTTP transport
- Tool registration via `setRequestHandler("tools/list", ...)`
- Tool execution via `setRequestHandler("tools/call", ...)`


---

## 15. Workflow Tools (Composite Operations)

### Purpose

Some common workflows require calling 3-5 tools in sequence. Workflow tools
combine these into a single call, reducing round-trips and ensuring consistent
context across the sub-operations.

### drift_analyze_function (Workflow)

Combines: signature + callers + callees + impact + test coverage

```typescript
registry.register({
    name: "drift_analyze_function",
    title: "Analyze Function",
    description: "Complete analysis of a function: signature, callers, callees, " +
        "impact radius, and test coverage in one call",
    inputSchema: {
        type: "object",
        properties: {
            function: { type: "string", description: "Function name or ID" },
            depth: { type: "number", description: "Call graph depth (default: 2)" },
        },
        required: ["function"],
    },
    category: "workflow",
    tokenCost: "~1500-4000",
    cacheTtl: 300_000,
    expensive: true,
    requiresAnalysis: true,
    handler: async (args, ctx) => {
        const fn = args.function as string;
        const depth = (args.depth as number) ?? 2;

        const [signature, callers, callees, impact, coverage] = await Promise.all([
            ctx.native.queryCallGraph(fn, 0),
            ctx.native.queryCallers(fn),
            ctx.native.queryCallees(fn),
            ctx.native.analyzeImpact(fn),
            ctx.native.queryTestCoverage(fn),
        ]);

        return new ResponseBuilder()
            .withSummary(`Analysis of ${fn}: ${callers.length} callers, ` +
                `${callees.length} callees, impact radius ${impact.affectedCount}`)
            .withData({ signature, callers, callees, impact, coverage })
            .withNextActions([
                { tool: "drift_reachability", args: { source: fn },
                  reason: "Trace data flow", priority: "medium" },
                { tool: "drift_test_template", args: { function: fn },
                  reason: "Generate test", priority: "low" },
            ])
            .build(Date.now());
    },
});
```

### drift_security_deep (Workflow)

Combines: security_summary + boundaries + sensitive_fields + secrets + constraints

```typescript
registry.register({
    name: "drift_security_deep",
    title: "Deep Security Analysis",
    description: "Complete security analysis: boundaries, sensitive fields, " +
        "secrets, constraints, and reachability in one call",
    inputSchema: {
        type: "object",
        properties: {
            focus: { type: "string", description: "Area to focus on (optional)" },
        },
    },
    category: "workflow",
    tokenCost: "~3000-8000",
    cacheTtl: 600_000,
    expensive: true,
    requiresAnalysis: true,
    handler: async (args, ctx) => {
        const [summary, boundaries, fields, constraints] = await Promise.all([
            ctx.native.querySecuritySummary(),
            ctx.native.queryBoundaries({ focus: args.focus }),
            ctx.native.querySensitiveFields(null),
            ctx.native.verifyConstraints(null),
        ]);

        return new ResponseBuilder()
            .withSummary(`Security analysis: ${boundaries.total} boundaries, ` +
                `${fields.length} sensitive fields, ` +
                `${constraints.violations} constraint violations`)
            .withData({ summary, boundaries, sensitiveFields: fields, constraints })
            .build(Date.now());
    },
});
```

---

## 16. Testing Strategy

### Test Categories

#### 1. Unit Tests (per module)
- Tool handler tests (mock NAPI, verify response structure)
- Infrastructure tests (cache, rate limiter, cursor manager)
- Pack manager tests (loading, suggestion, execution)
- Feedback scorer tests (score calculation, propagation, exclusion)
- Curation verifier tests (evidence checking, approval requirements)

#### 2. Integration Tests
- Full server creation + tool execution flow
- Progressive disclosure flow (discover → context → tool)
- Pack execution flow (discover packs → execute pack)
- Bridge tool registration (with/without Cortex)
- Multi-project switching
- Cache invalidation on scan

#### 3. Security Tests (Critical — Preserved from v1)
- Path traversal prevention in drift_setup
- Path traversal prevention in project resolver
- Rate limiting enforcement
- Cursor tampering detection (HMAC verification)
- Invalid tool name handling

#### 4. Protocol Compliance Tests
- MCP 2025-06-18 structured output format
- Tool list response format
- Error response format
- Pagination cursor format
- Resource link format

### Test Framework

```typescript
// vitest for all tests
// @modelcontextprotocol/sdk/test for MCP protocol testing

import { describe, it, expect, beforeEach, vi } from "vitest";
import { createAnalysisServer } from "../src/analysis-server.js";

describe("Progressive Disclosure", () => {
    let server: Server;

    beforeEach(async () => {
        server = await createAnalysisServer({
            projectRoot: "/tmp/test-project",
            skipWarmup: true,
        });
    });

    it("should register exactly 3 tools", async () => {
        const response = await server.handleRequest("tools/list", {});
        expect(response.tools).toHaveLength(3);
        expect(response.tools.map(t => t.name)).toEqual([
            "drift_context",
            "drift_discover",
            "drift_tool",
        ]);
    });

    it("drift_discover should return full tool catalog", async () => {
        const response = await server.handleRequest("tools/call", {
            name: "drift_discover",
            arguments: { section: "tools" },
        });
        const data = JSON.parse(response.content[0].text);
        expect(data.tools.totalTools).toBeGreaterThan(40);
    });

    it("drift_tool should dispatch to internal handlers", async () => {
        const response = await server.handleRequest("tools/call", {
            name: "drift_tool",
            arguments: {
                name: "drift_status",
                args: {},
            },
        });
        expect(response.isError).toBeFalsy();
    });

    it("drift_tool should return error for unknown tools", async () => {
        const response = await server.handleRequest("tools/call", {
            name: "drift_tool",
            arguments: {
                name: "drift_nonexistent",
                args: {},
            },
        });
        expect(response.isError).toBe(true);
        const error = JSON.parse(response.content[0].text);
        expect(error.code).toBe("TOOL_NOT_FOUND");
        expect(error.similar).toBeDefined();
    });
});

describe("Path Traversal Prevention", () => {
    it("should reject paths outside project root", async () => {
        const response = await server.handleRequest("tools/call", {
            name: "drift_tool",
            arguments: {
                name: "drift_setup",
                args: { project: "../../etc/passwd" },
            },
        });
        expect(response.isError).toBe(true);
        expect(response.content[0].text).toContain("Path traversal detected");
    });
});

describe("Cursor Tampering", () => {
    it("should reject tampered cursors", async () => {
        const response = await server.handleRequest("tools/call", {
            name: "drift_tool",
            arguments: {
                name: "drift_patterns_list",
                args: { cursor: "tampered-cursor-value" },
            },
        });
        expect(response.isError).toBe(true);
        expect(response.content[0].text).toContain("INVALID_CURSOR");
    });
});
```

---

## 17. Build Order

### Phase 1: Foundation (Week 1)

1. **Package scaffolding** — `packages/drift-mcp/` with tsconfig, package.json, vitest config
2. **Types** — All response types, tool types, pack types, pagination types
3. **Infrastructure** — Error handler, response builder, token estimator
4. **Tool registry** — ToolRegistry class with registration + dispatch

### Phase 2: Core Server (Week 2)

5. **Analysis server** — `createAnalysisServer()` with 3 entry points
6. **drift_discover** — Full tool catalog + pack catalog
7. **drift_tool** — Dynamic dispatch with validation + caching + rate limiting
8. **drift_context** — Context generation (calls drift-napi `generateContext()`)

### Phase 3: Tool Categories (Week 3-4)

9. **Surgical tools** (12) — Thin wrappers around drift-napi query functions
10. **Exploration tools** (5) — Paginated list operations
11. **Detail tools** (8) — Deep inspection handlers
12. **Analysis tools** (9 + 8 language) — Heavy analysis handlers
13. **Generation tools** (3) — AI-powered handlers
14. **Setup + Curation** (3) — Setup wizard + anti-hallucination

### Phase 4: Infrastructure (Week 4-5)

15. **Cache** — L1 LRU + L2 file with category TTLs
16. **Rate limiter** — Sliding window, 3 tiers
17. **Metrics** — Prometheus-compatible counters + histograms
18. **Cursor manager** — HMAC-signed keyset pagination
19. **Tool filter** — Language detection + filtering
20. **Project resolver** — Multi-project + path traversal prevention
21. **Startup warmer** — Single NAPI call warmup

### Phase 5: Pack System (Week 5)

22. **Pack definitions** — 6 built-in packs
23. **Pack manager** — Loading, suggestion, execution, caching
24. **Custom pack loader** — `.drift/packs/` JSON loading
25. **Pack integration** — drift_discover + drift_pack handler

### Phase 6: Feedback + Memory (Week 6)

26. **Feedback system** — Score tracking, propagation, exclusion
27. **Memory server** — `createMemoryServer()` with 3 entry points
28. **Memory tools** (33) — All Cortex memory tool handlers
29. **Bridge tools** — drift_why, drift_memory_learn, drift_grounding_check
30. **Bridge detection** — Cortex availability detection

### Phase 7: Transport + Testing (Week 7)

31. **Streamable HTTP transport** — HTTP server with both servers
32. **Unit tests** — All modules
33. **Integration tests** — Full flow tests
34. **Security tests** — Path traversal, cursor tampering, rate limiting
35. **Protocol compliance tests** — MCP 2025-06-18 format validation

---

## 18. v1 Feature Verification — Complete Gap Analysis

Cross-referenced against all v1 documentation, the existing MCP server implementation
(packages/mcp/ — ~90 source files), and the full system audit to ensure 100% feature
coverage in v2.

### v1 MCP Features → v2 Status

| v1 Feature | v2 Status | v2 Location |
|-----------|-----------|-------------|
| 87+ tools across 10 categories | **PRESERVED** — All tools available via drift_tool | §3 |
| Enterprise server (enterprise-server.ts) | **SPLIT** — Two servers (analysis + memory) | §3, §10 |
| stdio transport | **KEPT** — Unchanged | §10.1 |
| HTTP/SSE transport | **UPGRADED** — Streamable HTTP (2025-03-26+) | §5.4, §10.1 |
| Tool routing (routeToolCall switch cascade) | **UPGRADED** — Category-based registry | §11 |
| Dual-path (JSON + SQLite) | **DROPPED** — SQLite-only via NAPI | §2 |
| Response cache (L1 LRU + L2 file) | **KEPT** — Same architecture, category TTLs | §6.1 |
| Rate limiter (3 tiers) | **KEPT** — Same architecture | §6.2 |
| Metrics collector | **KEPT** — Same architecture | §6.3 |
| Token estimator (heuristic) | **UPGRADED** — tiktoken-rs via NAPI + heuristic fallback | §6.4 |
| Cursor manager (opaque, versioned) | **UPGRADED** — HMAC signing added | §6.5 |
| Response builder (fluent API) | **KEPT** — Same pattern | §6.6 |
| Error handler (structured codes) | **KEPT** — Same pattern, expanded codes | §6.7 |
| Project resolver (multi-project) | **KEPT** — Same resolution strategy | §6.8 |
| Startup warmer | **SIMPLIFIED** — Single NAPI call | §6.10 |
| Tool filter (language detection) | **KEPT** — Same detection matrix | §6.9 |
| Pack manager (custom packs) | **UPGRADED** — 6 built-in packs, suggestion engine | §7 |
| Feedback system (reinforcement learning) | **UPGRADED** — SQLite storage, NAPI integration | §8 |
| Curation system (anti-hallucination) | **KEPT** — Same verification algorithm | §9 |
| drift_context (meta-tool) | **KEPT** — Primary entry point | §4 |
| drift_package_context | **KEPT** — Available via drift_tool | §3 |
| drift_status | **KEPT** — Available via drift_tool | §3 |
| drift_capabilities | **KEPT** — Available via drift_tool | §3 |
| drift_projects (multi-project) | **KEPT** — Available via drift_tool | §3 |
| drift_setup (project init) | **KEPT** — Available via drift_tool | §3 |
| drift_telemetry | **KEPT** — Available via drift_tool | §3 |
| drift_curate (6 actions) | **KEPT** — Available via drift_tool | §3, §9 |
| 12 surgical tools | **KEPT** — All available via drift_tool | §3 |
| 5 exploration tools | **KEPT** — All available via drift_tool | §3 |
| 8 detail tools | **KEPT** — All available via drift_tool | §3 |
| 9 core analysis tools | **KEPT** — All available via drift_tool | §3 |
| 8 language-specific tools | **KEPT** — Filtered by detection | §3 |
| 3 generation tools | **KEPT** — All available via drift_tool | §3 |
| 33 memory tools | **KEPT** — All in drift-memory server | §3 |
| drift_why (bridge tool) | **KEPT** — Conditional registration | §3 |
| drift_memory_learn (bridge tool) | **KEPT** — Conditional registration | §3 |
| Path traversal prevention | **KEPT** — Critical security test | §6.8 |
| Cortex facade pattern | **KEPT** — Memory tools call cortex-napi | §14 |
| Dynamic project resolution | **KEPT** — Same strategy | §6.8 |
| Background data building | **SIMPLIFIED** — Rust handles via NAPI | §6.10 |
| CORS support (HTTP) | **KEPT** — In Streamable HTTP server | §10.1 |
| Graceful shutdown | **KEPT** — Both servers | §10.1 |
| Health endpoint (HTTP) | **KEPT** — GET /health | §10.1 |

### v1 Features NOT in Original 07-mcp/ Research (Gaps Found & Resolved)

**1. Workflow Tools**
v1 has no composite tools. AI must call 3-5 tools sequentially for common workflows.
**Resolution**: Added workflow tools (drift_analyze_function, drift_security_deep) in §15.

**2. Pack Execution via MCP**
v1 packs exist but aren't executable through MCP tools.
**Resolution**: Added drift_pack handler in §7 (execute pack via drift_tool).

**3. Structured Tool Output**
v1 returns all results as text/JSON strings.
**Resolution**: Added MCP 2025-06-18 structured output support in §5.1.

**4. Elicitation Support**
v1 has no server-initiated user prompts.
**Resolution**: Added elicitation support for setup/curation in §5.2.

**5. Resource Links**
v1 has no resource link support in tool results.
**Resolution**: Added resource links for pattern drill-down in §5.3.

**6. HMAC Cursor Signing**
v1 cursors are unsigned (tamper-vulnerable).
**Resolution**: Added HMAC signing to cursor manager in §6.5.

**7. tiktoken-rs Token Counting**
v1 uses pure heuristic (chars/4).
**Resolution**: Added tiktoken-rs via NAPI with heuristic fallback in §6.4.

**8. Bridge Tool: drift_grounding_check**
v1 has no explicit grounding check tool.
**Resolution**: Added drift_grounding_check as conditional bridge tool in §3.

### New v2 Features NOT in v1

| New Feature | Why | Location |
|------------|-----|----------|
| Split server architecture | Token savings, clean separation (D3) | §3 |
| Progressive disclosure (3 entry points) | 93% token reduction at startup (AD5) | §4 |
| drift_tool dynamic dispatch | Enables progressive disclosure | §4 |
| 6 built-in packs | Task-oriented tool bundles | §7 |
| Pack suggestion engine | Auto-suggest packs based on intent | §7 |
| Workflow tools | Composite operations (3-5 tools in 1 call) | §15 |
| Structured tool output | MCP 2025-06-18 compliance | §5.1 |
| Elicitation support | Server-initiated user prompts | §5.2 |
| Resource links | Drill-down navigation | §5.3 |
| Streamable HTTP transport | Replaces SSE (2025-03-26+) | §5.4 |
| OAuth Resource Server | Enterprise auth (2025-06-18) | §5.5 |
| HMAC cursor signing | Tamper detection | §6.5 |
| tiktoken-rs token counting | Accurate BPE counting | §6.4 |
| drift_grounding_check | Memory validation bridge tool | §3 |
| nextActions in responses | Guided tool discovery | §4, §12 |
| Fuzzy tool name matching | "Did you mean?" suggestions | §11 |

### Dropped v1 Features (Intentional)

| Dropped Feature | Why | Replacement |
|----------------|-----|-------------|
| Dual-path (JSON + SQLite) | SQLite-only in v2 | All tools use NAPI → drift.db |
| 9 separate store constructors | Single NAPI initialization | native.driftInitialize() |
| routeToolCall switch cascade | Category-based registry | ToolRegistry.get() |
| Legacy JSON stores (DNA, Boundary, etc.) | SQLite-only | UnifiedStore via NAPI |
| SyncService (JSON↔SQLite) | No JSON stores | N/A |
| ManifestStore | SQLite Gold layer | Materialized views in drift.db |
| HistoryStore (JSON) | SQLite | history table in drift.db |

---

## 19. Configuration

### MCP Client Configuration (Claude Desktop, Cursor, Kiro)

```json
{
    "mcpServers": {
        "drift-analysis": {
            "command": "npx",
            "args": ["drift-mcp", "analysis", "/path/to/project"],
            "env": {
                "DRIFT_LOG": "info"
            }
        },
        "drift-memory": {
            "command": "npx",
            "args": ["drift-mcp", "memory", "/path/to/project"],
            "env": {
                "DRIFT_LOG": "info"
            }
        }
    }
}
```

### Server Configuration (drift.toml)

```toml
[mcp]
# Analysis server
analysis_cache_enabled = true
analysis_cache_l1_size = 200
analysis_rate_limit = 120          # requests per minute
analysis_verbose = false

# Memory server
memory_enabled = true              # Auto-detect Cortex
memory_rate_limit = 60

# HTTP server
http_port = 3000
http_cors_origins = ["*"]

[mcp.packs]
# Custom pack directory
custom_dir = ".drift/packs"
# Disable specific built-in packs
disabled = []

[cortex]
enabled = "auto"                   # "auto", true, false
db_path = ".drift/memory/cortex.db"
```

### Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `DRIFT_LOG` | Log level per subsystem | `info` |
| `DRIFT_MCP_PORT` | HTTP server port | `3000` |
| `DRIFT_MCP_CACHE` | Enable/disable cache | `true` |
| `DRIFT_MCP_RATE_LIMIT` | Global rate limit | `120` |
| `DRIFT_PROJECT_ROOT` | Override project root | Auto-detect |

---

## 20. Performance Targets

| Metric | Target | Rationale |
|--------|--------|-----------|
| Tool definition loading | <100ms | Server startup speed |
| drift_context response | <200ms | Primary entry point, must be fast |
| drift_discover response | <50ms | Catalog is pre-built |
| Surgical tool response | <50ms | Indexed SQLite queries |
| Exploration tool response | <100ms | Paginated queries |
| Detail tool response | <200ms | May read files |
| Analysis tool response | <2000ms | Heavy computation (via NAPI) |
| Pack execution | <3000ms | Multiple tools in sequence |
| Cache hit response | <5ms | In-memory LRU |
| Rate limit check | <1ms | In-memory sliding window |
| Token estimation | <10ms | tiktoken-rs or heuristic |
| Cursor encode/decode | <1ms | Base64 + HMAC |

### Memory Targets

| Metric | Target | Rationale |
|--------|--------|-----------|
| Server idle memory | <50MB | Lightweight process |
| Cache memory (L1) | <20MB | 200 entries × ~100KB avg |
| Per-request memory | <5MB | Bounded by pagination |
| Peak memory (pack execution) | <100MB | Multiple tool results |

---

## 21. Resolved Inconsistencies

### Inconsistency 1: Tool Count (87 vs 56 vs 50+)

Different docs cite different tool counts:
- 07-mcp/overview.md: "50+ tools"
- 07-mcp/tools-inventory.md: "~87 tool files"
- DRIFT-V2-FULL-SYSTEM-AUDIT.md: "56+ tools"

**Resolution**: v1 has ~87 tool files but some are shared handlers. Unique tool names
(MCP tool definitions) total ~56. v2 preserves all ~56 unique tools, accessible via
drift_tool. The 87 file count includes index.ts files, types, and shared utilities.

### Inconsistency 2: Progressive Disclosure Entry Points

DRIFT-V2-FULL-SYSTEM-AUDIT.md AD5 says "3 entry points per server":
- drift-analysis: `drift_context`, `drift_discover`, `drift_tool`
- drift-memory: `drift_memory_context`, `drift_memory_manage`, `drift_memory_discover`

DRIFT-V2-STACK-HIERARCHY.md says different names:
- drift-analysis: `drift_context`, `drift_discover`, `drift_tool`
- drift-memory: `drift_memory_context`, `drift_memory_manage`, `drift_memory_discover`

**Resolution**: Names are consistent. Both docs agree. Adopted as-is.

### Inconsistency 3: Memory Server Tool Count

DRIFT-V2-STACK-HIERARCHY.md says "~15-20 tools" for drift-memory.
06-cortex/mcp-tools.md lists 33 memory tools.

**Resolution**: The 33 tools are the full catalog. The "~15-20" refers to the
most commonly used subset. v2 preserves all 33, accessible via drift_memory_manage.

### Inconsistency 4: Pack System Scope

07-mcp/feedback-and-packs.md describes packs as pattern bundles (categories + examples).
DRIFT-V2-FULL-SYSTEM-AUDIT.md describes packs as tool bundles (subsets for workflows).

**Resolution**: v2 packs are tool bundles (§7). Pattern filtering is a pack config
option (categories, minConfidence), not the primary purpose. This aligns with AD5's
goal of reducing context window cost.

### Inconsistency 5: Cortex Detection Mechanism

PLANNING-DRIFT.md Q3 lists three options: config flag, cortex.db file, NAPI bindings.
No resolution was recorded.

**Resolution**: v2 uses all three in priority order (§3): config flag → cortex.db
file detection → NAPI binding load attempt. This provides explicit control with
automatic fallback.
