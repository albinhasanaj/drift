# 07 MCP Server — Recommendations for V2

> **Purpose**: Concrete, actionable recommendations for the Drift v2 MCP server rebuild, grounded in the RECAP (v1 state) and RESEARCH (external best practices). Each recommendation includes priority, effort, evidence, and cross-subsystem impact.
>
> **Inputs**: 07-mcp/RECAP.md, 07-mcp/RESEARCH.md, MASTER_RECOMMENDATIONS.md
>
> **Date**: February 2026

---

## Executive Summary

The MCP server is Drift's value delivery layer — it's where all offline indexing becomes useful to AI agents. V1 built a solid foundation (enterprise infrastructure, anti-hallucination curation, progressive disclosure) but suffers from tool sprawl (87+ tools), protocol stagnation (missing Resources, Prompts, Elicitation), no authentication, and a dual-path storage architecture that doubles maintenance. V2 rebuilds the MCP server as a modern, spec-compliant orchestration layer with aggressive tool consolidation (~25-35 tools), full MCP 2025-11-25 spec compliance, OAuth 2.1 authorization, OpenTelemetry observability, and a composition framework that enables workflow-oriented tools. The server remains 100% TypeScript — it's orchestration, not computation.

These 18 recommendations are organized into 4 phases aligned with the master build plan. They complement (not duplicate) the 42 master recommendations — these are MCP-specific concerns that the master plan references but doesn't detail.

---

## Phase A: Protocol & Architecture (Weeks 1-4)

### R1: Full MCP 2025-11-25 Spec Compliance

**Priority**: P0 | **Effort**: High | **Impact**: Unlocks Resources, Prompts, Elicitation, Tool Annotations, Streamable HTTP

V1 implements only the Tools primitive from the MCP spec. V2 must implement the full spec:

**Tools** (carry forward from v1):
- All tools include annotations: `readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`
- Most Drift tools are read-only — annotate them as such to enable auto-approval in IDE clients
- Write tools: `drift_curate(approve)`, `drift_memory_*` mutations, `drift_setup`, `drift_projects(register/switch)`

**Resources** (new in v2):
- `drift://patterns/{id}` — Pattern data as browsable resources
- `drift://patterns?category={cat}` — Pattern listings by category
- `drift://callgraph/{function}` — Call graph data for a function
- `drift://boundaries/{module}` — Security boundary data
- `drift://status` — Project health status
- `drift://conventions` — Active conventions summary
- Resource subscriptions: notify clients when pattern data changes (after scan)

**Prompts** (new in v2):
- `security-audit` — Structured security review workflow with tool sequence
- `code-review` — Pattern compliance check for a file or PR
- `refactor-plan` — Impact analysis + coupling + test coverage for a refactor
- `onboarding` — Project overview + key patterns + conventions for new team members
- `debug-issue` — Callers + impact + error handling for debugging
- Each prompt packages the right context and tool recommendations

**Elicitation** (new in v2):
- Curation workflow: server asks AI for evidence files, snippets, reasoning
- Project setup: server asks for project configuration preferences
- Ambiguous queries: server asks for clarification when tool parameters are unclear

**Streamable HTTP** (replaces SSE):
- Single endpoint for all communication (replaces v1's separate GET /sse + POST /message)
- Works with standard HTTP infrastructure (load balancers, CDNs, serverless)
- Backward compatibility with SSE clients during transition period

**Evidence**: MCP Specification 2025-11-25 [Source 1], MCP Transports [Source 2], WorkOS MCP Features Guide [Source 24].

---

### R2: Tool Consolidation — From 87+ to ~30 Tools

**Priority**: P0 | **Effort**: High | **Impact**: 60-70% token reduction, better AI tool selection, simpler maintenance

V1's 87+ tools far exceed the 10-15 tool sweet spot for AI agent performance. Consolidate using action parameters and workflow-oriented design.

**Consolidation Strategy**:

| V1 Category | V1 Count | V2 Approach | V2 Count |
|-------------|----------|-------------|----------|
| Orchestration | 2 | Keep as-is (entry points) | 2 |
| Discovery | 3 | Merge status + capabilities → `drift_discover` | 2 |
| Setup | 2 | Merge → `drift_setup` with actions | 1 |
| Curation | 1 (6 actions) | Keep as-is (already consolidated) | 1 |
| Surgical | 12 | Group by data type: `drift_lookup` (signature, type, imports), `drift_callers`, `drift_validate`, `drift_find` (similar, recent, dependencies) | 4 |
| Exploration | 5 | Merge → `drift_browse` with `type` parameter (patterns, security, contracts, env, trends) | 1 |
| Detail | 8 | Merge → `drift_inspect` with `type` parameter (pattern, examples, files, impact, reachability, dna, wrappers) | 1 |
| Analysis | 18 | Merge core → `drift_analyze` with `type` parameter; merge language → `drift_language` with `language` parameter | 2 |
| Generation | 3 | Merge → `drift_generate` with `action` parameter | 1 |
| Memory | 33 | Merge → `drift_memory` with `action` parameter (crud, search, health, learn, export) | 1 |

**V2 Tool Surface (~16 core tools)**:
1. `drift_context` — Meta-tool, curated context for any task
2. `drift_package_context` — Monorepo package context
3. `drift_discover` — Status, capabilities, projects (action parameter)
4. `drift_setup` — Project initialization and telemetry
5. `drift_curate` — Pattern curation with anti-hallucination (6 actions)
6. `drift_lookup` — Precision lookups: signature, type, imports (type parameter)
7. `drift_callers` — Who calls this function (keep separate — most frequently called)
8. `drift_validate` — Pre-write validation and change validation
9. `drift_find` — Similar code, recent changes, dependencies (type parameter)
10. `drift_browse` — Filtered listing: patterns, security, contracts, env, trends
11. `drift_inspect` — Deep inspection: pattern details, examples, impact, reachability
12. `drift_analyze` — Heavy analysis: coupling, test topology, errors, quality, audit
13. `drift_language` — Language-specific analysis (language parameter)
14. `drift_generate` — AI-powered: explain, suggest, validate changes
15. `drift_memory` — Full Cortex memory system (action parameter)
16. `drift_security` — Dedicated security tool: boundaries, reachability, taint (new)

**Dynamic Tool Groups** (progressive discovery):
- "security" group: drift_context, drift_security, drift_browse(security), drift_inspect(reachability), drift_analyze(quality)
- "review" group: drift_context, drift_browse(patterns), drift_validate, drift_analyze(coupling)
- "debug" group: drift_context, drift_callers, drift_inspect(impact), drift_find(recent)

**Evidence**: Tadata 10-15 tool sweet spot [Source 6], Anthropic 72K token overhead for 50+ tools [Source 10], IBM Workflow-Oriented Tools [Source 5], Joseph Velliah 73% reduction case study [Source 7].

---

### R3: Layered Server Architecture with Middleware Pipeline

**Priority**: P0 | **Effort**: Medium | **Impact**: Replaces switch cascade, enables cross-cutting concerns, simplifies extension

Replace v1's monolithic `routeToolCall()` switch cascade with a layered middleware pipeline:

```
Request → Auth → RateLimit → Validate → Cache → Route → Execute → Format → Metrics → Response
```

**Middleware Stack**:
```typescript
interface ToolMiddleware {
  name: string;
  priority: number;
  execute(ctx: ToolContext, next: () => Promise<ToolResponse>): Promise<ToolResponse>;
}

interface ToolContext {
  tool: ToolDefinition;
  args: Record<string, unknown>;
  project: ProjectContext;
  session: SessionContext;
  user?: UserContext;        // For authenticated HTTP transport
  traceId: string;           // OpenTelemetry trace ID
  parentSpanId?: string;
}
```

**Built-in Middleware** (in order):
1. `AuthMiddleware` — OAuth token validation (HTTP only, skip for stdio)
2. `RateLimitMiddleware` — Token-bucket rate limiting with headers
3. `InputValidationMiddleware` — Schema validation, path traversal prevention, length limits
4. `CacheMiddleware` — Check cache, serve if hit, populate on miss
5. `ProjectResolutionMiddleware` — Resolve project context, create temporary stores if needed
6. `ToolRouter` — Dispatch to handler based on tool name (registry lookup, not switch cascade)
7. `ResponseFormatterMiddleware` — Apply token budgets, summary-first formatting
8. `MetricsMiddleware` — Record OpenTelemetry spans, counters, histograms
9. `AuditMiddleware` — Log tool invocation for compliance (HTTP only)

**Benefits over v1**:
- O(1) tool routing via registry map instead of O(n) switch cascade
- Cross-cutting concerns (auth, validation, caching) applied uniformly
- New middleware added without modifying existing code
- Middleware can be conditionally enabled (e.g., auth only for HTTP)
- Each middleware is independently testable

**Evidence**: IBM MCP Gateway pattern [Source 5], Bix-Tech security architecture [Source 13], Zeo state management [Source 11].

---

### R4: Unified Store Initialization via Rust NAPI

**Priority**: P0 | **Effort**: Low | **Impact**: Eliminates 9 store constructors, simplifies initialization, removes dual-path

V1 initializes 9 separate stores with complex error handling. V2 collapses to a single Rust NAPI initialization:

```typescript
// V1: 9 store constructors, dual-path logic, warmup sequence
const pattern = await createPatternStore(root);
const unified = new UnifiedStore(root);
const dna = new DNAStore(root);
// ... 6 more stores

// V2: Single NAPI call, SQLite-only
const db = await DriftNapi.initialize(projectRoot);
// db exposes: patterns, callGraph, boundaries, env, dna, contracts, coupling, etc.
```

**What this eliminates**:
- Dual-path storage (JSON + SQLite) → SQLite-only via Rust
- 9 store constructors → 1 NAPI initialization
- Startup warmup → Rust manages DB lifecycle, lazy loading
- PatternService vs PatternStore branching → single API
- DataLake → queries go directly to Rust

**What stays in TypeScript**:
- Cortex memory (separate SQLite DB, TS-managed)
- Response cache (in-memory, TS-managed)
- Project registry (JSON file, TS-managed)

**Cross-subsystem impact**: Depends on Master Recommendation M38 (N-API Bridge). The MCP server is the primary consumer of the NAPI bridge.

---

## Phase B: Infrastructure & Security (Weeks 5-8)

### R5: OAuth 2.1 Authorization for HTTP Transport

**Priority**: P1 | **Effort**: Medium | **Impact**: Enterprise deployment readiness, multi-user support

Implement OAuth 2.1 authorization for the Streamable HTTP transport:

**Scope Hierarchy**:
```
drift:read          — All read-only tools (browse, inspect, analyze, lookup, callers)
drift:write         — Write tools (curate approve, memory mutations)
drift:admin         — Administrative tools (setup, project management)
drift:security      — Security-specific tools (boundaries, reachability, taint)
drift:memory        — Memory system access (Cortex operations)
```

**Implementation**:
- MCP server acts as OAuth Resource Server (per spec)
- Supports external identity providers (Auth0, Okta, Keycloak) via standard OAuth flows
- PKCE mandatory for all clients
- Short-lived access tokens (15 min) with refresh tokens (24 hours)
- Token introspection endpoint for real-time revocation
- Per-tool scope checking in AuthMiddleware

**stdio transport**: Implicit authentication (same machine trust). No OAuth overhead for IDE integration.

**Evidence**: MCP Authorization Spec [Source 3], WorkOS MCP Auth Guide [Source 28], OAuth 2.1 Best Practices [Source 27].

---

### R6: OpenTelemetry Observability

**Priority**: P1 | **Effort**: Medium | **Impact**: Replaces custom metrics, enables distributed tracing, standard tooling

Replace v1's custom Prometheus-style MetricsCollector with OpenTelemetry:

**Traces**:
- Each tool call is a span: tool name, duration, args (sanitized), result size, cache hit/miss
- Session-level trace ID correlates multi-tool workflows
- Parent-child spans for composed tools (e.g., `drift_context` → internal queries)
- Error spans with structured error codes and recovery hints

**Metrics**:
- `drift.mcp.tool.calls` (counter: tool, status, cached)
- `drift.mcp.tool.duration` (histogram: tool)
- `drift.mcp.tool.tokens` (histogram: tool, direction=request|response)
- `drift.mcp.cache.operations` (counter: operation=hit|miss|invalidate)
- `drift.mcp.rate_limit.rejections` (counter: tier)
- `drift.mcp.auth.events` (counter: event=success|failure|expired)

**Logs**:
- Structured JSON logs with trace ID correlation
- Log levels: error (tool failures), warn (rate limits, cache misses), info (tool calls), debug (internal routing)

**Export**:
- OTLP exporter for standard backends (Grafana, Datadog, New Relic, Jaeger)
- Console exporter for development
- Configurable via environment variables (`OTEL_EXPORTER_OTLP_ENDPOINT`)

**Evidence**: VictoriaMetrics AI Observability [Source 19], Maxim AI Observability [Source 20], OpenTelemetry standard.

---

### R7: Enhanced Caching with TinyLFU and Semantic Keys

**Priority**: P1 | **Effort**: Medium | **Impact**: Higher cache hit rates, semantic deduplication, stampede prevention

Upgrade v1's simple LRU cache:

**L1 Cache (In-Memory)**:
- TinyLFU admission policy (better hit rates than pure LRU for skewed access patterns)
- 1000 entries (up from v1's 100)
- 10-minute TTL (up from v1's 5 minutes)
- Stale-while-revalidate for expensive tools (serve stale, refresh in background)

**Semantic Cache Keys**:
- Normalize semantically equivalent queries: "who calls function X?" and "callers of X" should hit the same cache entry
- Key structure: `project_hash:tool:normalized_args_hash`
- Argument normalization: sort keys, trim whitespace, lowercase enum values, resolve path aliases

**Cache Stampede Prevention**:
- Lock-based: for expensive tools (impact analysis, quality gate), only one request computes; others wait
- Probabilistic early expiration: refresh cache entries before TTL expires based on access frequency

**Cache Invalidation**:
- Event-based: invalidate on scan completion, pattern approval, memory mutation
- Scoped: invalidate only affected tool categories (e.g., scan → invalidate pattern tools, not memory tools)
- Project-isolated: invalidation scoped to the affected project

**Evidence**: API Caching Strategies [Source 25], LLM Cost Optimization [Source 15], Moka TinyLFU (from MASTER_RESEARCH).

---

### R8: Centralized Input Validation Middleware

**Priority**: P1 | **Effort**: Low | **Impact**: Eliminates per-tool validation, prevents path traversal across all tools

V1 only validates paths for `drift_setup`. V2 validates all inputs centrally:

**Validation Rules**:
- **Path parameters**: Canonicalize, reject `..`, `~`, absolute paths, validate against project root
- **String parameters**: Length limit (10KB default, configurable per tool), UTF-8 validation
- **Enum parameters**: Validate against allowed values from tool schema
- **Numeric parameters**: Range validation (e.g., maxTokens: 100-100000)
- **Array parameters**: Length limit, element validation
- **Pattern IDs**: Format validation (16-char hex), existence check (optional, configurable)

**Implementation**: Single `InputValidationMiddleware` that reads validation rules from tool definitions. No per-tool validation code needed.

**Evidence**: OWASP Input Validation guidelines, v1 path traversal gap analysis [RECAP Security Gaps].

---

## Phase C: Tool Quality & Intelligence (Weeks 9-14)

### R9: Composition Framework for Workflow Tools

**Priority**: P0 | **Effort**: High | **Impact**: Enables workflow-oriented tools, reduces AI round-trips by 3-5x

Formalize the composition pattern used by `drift_context` into a reusable framework:

**Composition Definition**:
```typescript
interface ComposedTool {
  name: string;
  description: string;
  annotations: ToolAnnotations;
  inputSchema: JSONSchema;
  steps: CompositionStep[];
  outputMerger: (results: StepResult[]) => ToolResponse;
}

interface CompositionStep {
  tool: string;                    // Internal tool to call
  args: (input: any, prev: StepResult[]) => Record<string, unknown>;
  condition?: (input: any, prev: StepResult[]) => boolean;  // Skip if false
  parallel?: boolean;              // Can run in parallel with other parallel steps
  required?: boolean;              // Fail composition if this step fails (default: true)
}
```

**Composed Tools for V2**:
1. `drift_context` (carry forward) — Patterns + call graph + boundaries + DNA + Cortex
2. `drift_security_audit` (new) — Security summary + boundary analysis + reachability + taint findings + secret detection
3. `drift_refactor_plan` (new) — Coupling analysis + impact analysis + callers + test topology + affected tests
4. `drift_code_review` (new) — Pattern compliance + quality gate + error handling + convention check
5. `drift_debug_context` (new) — Callers + impact + error handling + recent changes + related patterns

**Benefits**:
- AI makes 1 call instead of 3-5, saving ~2000-5000 tokens per workflow
- Server-side parallelism (steps marked `parallel: true` run concurrently)
- Consistent error handling across composed steps
- Cacheable as a unit (composition result cached, not individual steps)

**Evidence**: IBM Workflow-Oriented Tools [Source 5], Hackteam Tool Composition [Source 10], Context Window Management [Source 14].

---

### R10: Enhanced Anti-Hallucination Curation System

**Priority**: P1 | **Effort**: Medium | **Impact**: Extends verification beyond patterns to all AI claims

V1's curation system verifies AI evidence for pattern approval. V2 extends this to a general-purpose verification framework:

**Verification Types**:
1. **Pattern Verification** (carry forward): Check claimed files/snippets against actual code
2. **Symbol Verification** (new): Check claimed function/class names against parsed symbol table
3. **Relationship Verification** (new): Check claimed call relationships against call graph
4. **Convention Verification** (new): Check claimed conventions against detected patterns
5. **Security Verification** (new): Check claimed vulnerabilities against actual code paths

**Hallucination Classification** (from CodeHalu research):
- Mapping hallucinations: Wrong API/function names → verify against symbol table
- Naming hallucinations: Invented identifiers → verify against parsed codebase
- Resource hallucinations: Non-existent files/modules → verify against filesystem
- Logic hallucinations: Incorrect control flow → verify against call graph + AST

**Verification Metrics**:
- Track verification pass rate per AI model/agent
- Track hallucination type distribution
- Alert on declining verification rates
- Feed metrics into feedback loop for tool response optimization

**Evidence**: EviBound Framework [Source 16], CodeHalu [Source 17], Maxim Hallucination Detection [Source 18].

---

### R11: Comprehensive Feedback Loop (Google Tricorder Model)

**Priority**: P1 | **Effort**: Medium | **Impact**: Continuous quality improvement, builds developer trust

Extend v1's example-only feedback to cover all tool responses:

**Feedback Signals**:

*Explicit*:
- Every tool response includes feedback mechanism: useful / not useful / partially useful
- Reason field for "not useful" (wrong data, too verbose, missing context, irrelevant)
- Fix application tracking: was the suggested fix applied?

*Implicit* (from AI agent behavior):
- Tool response → task completion = positive signal
- Tool response → same tool re-called with different params = negative signal (unhelpful response)
- Tool response → different tool called immediately = neutral (possible wrong tool choice)
- Tool response → no further calls = ambiguous (could be success or abandonment)

**Health Metrics**:
- Effective FP rate per tool: `(not_useful) / (useful + not_useful + partial)`
- Target: <5% effective FP rate (Google Tricorder standard)
- Auto-alert at >10% FP rate
- Auto-disable at >20% FP rate sustained for 30+ days

**Feedback Storage**:
- SQLite table: `tool_feedback(id, tool, rating, reason, implicit_signal, session_id, timestamp)`
- Aggregated daily: per-tool, per-category, per-project
- Exposed via `drift_discover(action=health)` for transparency

**Evidence**: Google Tricorder [Source 29], RLHF for Tool Quality [Section 10.2 of RESEARCH].

---

### R12: Token-Accurate Response Budgeting

**Priority**: P1 | **Effort**: Low | **Impact**: Accurate token estimation, better context window utilization

Replace v1's heuristic token estimator with accurate counting:

**Implementation**:
- Use `tiktoken` (or `js-tiktoken` for Node.js) for accurate token counting
- Support multiple tokenizer models (cl100k_base for GPT-4, claude tokenizer for Claude)
- Default to cl100k_base if model unknown
- Cache tokenizer instances (expensive to initialize)

**Response Budget Enforcement**:
```typescript
interface TokenBudget {
  maxTokens: number;           // Caller-specified limit
  reservedForMeta: number;     // ~100 tokens for summary, pagination, hints
  availableForData: number;    // maxTokens - reservedForMeta
  currentUsage: number;        // Running count during response construction
}
```

**Progressive Truncation**:
1. Full response fits within budget → return as-is
2. Over budget → truncate data arrays (keep first N items)
3. Still over → summarize instead of listing (e.g., "47 patterns found, showing top 10")
4. Include `truncated: true` and `totalAvailable: N` in response metadata

**Evidence**: Context Window Management [Source 14], LLM Cost Optimization [Source 15].

---

### R13: Dynamic Tool Filtering with Task Context

**Priority**: P1 | **Effort**: Medium | **Impact**: Reduces tool schema overhead by 50-70% per session

V1 filters tools by detected language. V2 adds task-based filtering:

**Filtering Layers**:
1. **Language filter** (carry forward): Only show language-specific tools for detected languages
2. **Task filter** (new): Based on `drift_context` intent parameter, surface only relevant tools
3. **Capability filter** (new): Only show tools whose data prerequisites are met (e.g., hide `drift_callers` if call graph not built)
4. **Permission filter** (new): Only show tools the authenticated user has access to (HTTP transport)

**Task → Tool Mapping**:
| Task Intent | Tools Surfaced |
|-------------|---------------|
| security_audit | drift_context, drift_security, drift_browse, drift_inspect, drift_analyze |
| fix_bug | drift_context, drift_callers, drift_find, drift_inspect, drift_lookup |
| refactor | drift_context, drift_analyze, drift_callers, drift_inspect, drift_validate |
| add_feature | drift_context, drift_browse, drift_lookup, drift_validate, drift_generate |
| add_test | drift_context, drift_analyze(test_topology), drift_find, drift_generate |
| understand_code | drift_context, drift_browse, drift_inspect, drift_callers, drift_generate |

**Implementation**: `tools/list` response is dynamically generated based on active filters. Full catalog available via `drift_discover(action=capabilities, filter=none)`.

**Evidence**: IBM Progressive Tool Discovery [Source 5], Lunar.dev Tool Overload [Source 8], Tadata Tool Count [Source 6].

---

## Phase D: Enterprise & Ecosystem (Weeks 15-20)

### R14: Multi-Project Architecture with Connection Pooling

**Priority**: P1 | **Effort**: Medium | **Impact**: Fast project switching, reduced memory usage

V1 creates temporary stores for each project switch. V2 uses connection pooling:

**Connection Pool**:
```typescript
interface ProjectPool {
  maxConnections: number;        // Default: 5 (most recent projects)
  evictionPolicy: 'lru';        // Evict least recently used
  idleTimeoutMs: number;        // Close idle connections after 30 min
  warmOnSwitch: boolean;        // Pre-warm new project data
}
```

**Project Context**:
```typescript
interface ProjectContext {
  root: string;
  name: string;
  db: DriftNapiConnection;      // Rust NAPI connection (pooled)
  cortex?: CortexConnection;    // Memory system (optional)
  languages: Language[];         // Detected languages
  lastAccessed: number;
  cacheNamespace: string;       // Project-isolated cache prefix
}
```

**Benefits**:
- Project switch: O(1) if in pool (vs v1's O(n) store reconstruction)
- Memory bounded: pool evicts idle projects
- Cache isolation: each project has its own cache namespace
- Warm switching: pre-load data for recently accessed projects

---

### R15: Tool Versioning and Deprecation Workflow

**Priority**: P2 | **Effort**: Low | **Impact**: Backward-compatible evolution, graceful tool retirement

**Versioning**:
- Tool names include optional version suffix: `drift_context` (latest), `drift_context_v1` (legacy)
- `tools/list` returns latest versions by default; `includeDeprecated=true` shows all
- Version negotiation at connection time via capability exchange

**Deprecation Workflow**:
1. Mark tool as deprecated with `deprecatedAt`, `replacedBy`, `removalDate`
2. Deprecated tools return `X-Drift-Deprecated: true` header and `hints.warnings` in response
3. Log deprecation warnings in metrics
4. After grace period (configurable, default 90 days), remove tool from `tools/list`
5. Removed tools return structured error with migration guidance

**Evidence**: Lunar.dev MCP Governance [Source 9], Workato Composable Architecture [Source 12].

---

### R16: Batch Tool Execution

**Priority**: P2 | **Effort**: Medium | **Impact**: Reduces round-trip latency for multi-tool workflows

Leverage JSON-RPC batching from the MCP spec:

**Server-Side Optimization**:
- Batch requests share a single project context resolution
- Batch requests share a single cache lookup pass
- Independent tools within a batch execute in parallel
- Dependent tools execute sequentially (detected via declared dependencies)

**Batch Response**:
- Individual results returned as JSON-RPC batch response
- Each result includes its own `meta` (duration, cached, tokenEstimate)
- Batch-level `meta` includes total duration and aggregate token count

**Example**:
```json
[
  {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "drift_browse", "arguments": {"type": "security"}}, "id": 1},
  {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "drift_browse", "arguments": {"type": "patterns", "category": "auth"}}, "id": 2},
  {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "drift_analyze", "arguments": {"type": "quality"}}, "id": 3}
]
```

**Evidence**: MCP JSON-RPC Batching [Source 1], LLM Cost Optimization [Source 15].

---

### R17: Usage Analytics and Tool Health Dashboard

**Priority**: P2 | **Effort**: Low | **Impact**: Data-driven tool consolidation, identifies unused tools

**Tracked Metrics**:
- Tool call frequency (per tool, per project, per session)
- Tool call sequences (which tools are called together?)
- Tool response usefulness (from feedback loop)
- Tool error rates and common error types
- Average response time and token usage per tool
- Cache hit rates per tool

**Health Dashboard** (exposed via `drift_discover(action=health)`):
```typescript
interface ToolHealth {
  tool: string;
  callCount30d: number;
  avgDurationMs: number;
  avgTokens: number;
  cacheHitRate: number;
  errorRate: number;
  feedbackScore: number;        // 0-1, from feedback loop
  status: 'healthy' | 'degraded' | 'unhealthy';
}
```

**Automated Actions**:
- Tools with 0 calls in 90 days → candidate for deprecation
- Tools with >20% error rate → alert, investigate
- Tools with <0.3 feedback score → alert, investigate
- Tools with >95% cache hit rate → consider pre-computing

---

### R18: Comprehensive Test Suite

**Priority**: P1 | **Effort**: High | **Impact**: From ~5% to >80% test coverage

V1 has only 5 test files for ~90 source files. V2 builds testing from the ground up:

**Test Categories**:

1. **Unit Tests** (per tool handler):
   - Every tool handler has at least 3 tests: happy path, error case, edge case
   - Mock NAPI layer for isolated testing
   - Snapshot tests for response format consistency

2. **Integration Tests** (full request flow):
   - End-to-end: client → transport → middleware → handler → response
   - Both stdio and Streamable HTTP transports
   - Multi-project switching scenarios
   - Cache behavior (hit, miss, invalidation)

3. **Security Tests**:
   - Path traversal prevention for ALL tools with path parameters
   - OAuth token validation and scope enforcement
   - Rate limiting behavior under load
   - Input validation for malformed requests

4. **Performance Tests**:
   - Response time benchmarks per tool (P50, P95, P99)
   - Cache hit rate under realistic workloads
   - Memory usage under sustained load
   - Concurrent request handling

5. **Contract Tests**:
   - Tool response schemas match declared output schemas
   - Pagination cursor round-trip (encode → decode → same results)
   - Error response format consistency
   - MCP spec compliance (JSON-RPC format, required fields)

**Target**: >80% line coverage, 100% coverage for security-critical paths.

**Evidence**: V1 testing gap analysis [RECAP Testing Gaps], Google Tricorder testing methodology [Source 29].

---

## Dependency Graph

```
Phase A (Protocol & Architecture)
  R1 (Spec Compliance) ──→ R2 (Tool Consolidation)
  R2 (Tool Consolidation) ──→ R9 (Composition Framework)
  R3 (Middleware Pipeline) ──→ R5 (OAuth), R6 (OTel), R7 (Cache), R8 (Validation)
  R4 (Unified Store) ──→ depends on Master M38 (N-API Bridge)

Phase B (Infrastructure & Security)
  R5 (OAuth) ──→ R13 (Permission Filter)
  R6 (OTel) ──→ R17 (Usage Analytics)
  R7 (Cache) ──→ R14 (Connection Pooling)
  R8 (Validation) ──→ standalone

Phase C (Tool Quality & Intelligence)
  R9 (Composition) ──→ R2 (uses consolidated tools)
  R10 (Anti-Hallucination) ──→ R11 (feeds into feedback loop)
  R11 (Feedback Loop) ──→ R17 (feeds into analytics)
  R12 (Token Budgeting) ──→ standalone
  R13 (Dynamic Filtering) ──→ R2 (filters consolidated tools)

Phase D (Enterprise & Ecosystem)
  R14 (Connection Pooling) ──→ R4 (uses unified store)
  R15 (Versioning) ──→ R2 (versions consolidated tools)
  R16 (Batch Execution) ──→ R3 (uses middleware pipeline)
  R17 (Usage Analytics) ──→ R6 (uses OTel data)
  R18 (Test Suite) ──→ ALL (tests everything)
```

---

## Cross-Subsystem Impact Matrix

| Recommendation | Master Recommendations Affected | Impact Type |
|---|---|---|
| R1 (Spec Compliance) | M38 (N-API Bridge) | Resources/Prompts need data from Rust |
| R2 (Tool Consolidation) | M39 (Fixes) | Fixes exposed through consolidated tools |
| R4 (Unified Store) | M38 (N-API Bridge) | Primary consumer of NAPI bridge |
| R5 (OAuth) | M40 (Feedback Loop) | Auth context for per-user feedback |
| R9 (Composition) | M27 (Taint), M31 (Impact) | Composed security/refactor tools use taint + impact |
| R10 (Anti-Hallucination) | M40 (Feedback Loop) | Verification metrics feed feedback |
| R11 (Feedback Loop) | M40 (Feedback Loop) | MCP-specific implementation of master feedback |
| R13 (Dynamic Filtering) | M36 (OWASP) | Security tools surfaced for security tasks |

---

## Success Metrics

| Metric | V1 Baseline | V2 Target | Measurement |
|---|---|---|---|
| Tool count | 87+ | ~30 | tools/list response |
| Tool schema token overhead | ~72K (estimated) | <15K | Tokenize tools/list response |
| Capabilities listing tokens | ~7000 | <2000 | drift_discover response size |
| MCP spec primitives used | 1 (Tools) | 4 (Tools, Resources, Prompts, Elicitation) | Spec compliance audit |
| Transport protocols | 2 (stdio + SSE) | 2 (stdio + Streamable HTTP) | Transport support |
| Authentication | None | OAuth 2.1 (HTTP) | Security audit |
| Test coverage | ~5% | >80% | Coverage report |
| Cache hit rate | Unknown | >60% | OTel metrics |
| Tool response P95 latency | Unknown | <200ms (read), <500ms (analysis) | OTel metrics |
| Effective FP rate | Unknown | <5% | Feedback loop |
| Observability | Custom Prometheus | OpenTelemetry | Instrumentation audit |
| Input validation coverage | 1 tool (drift_setup) | 100% of tools | Security audit |
| Hallucination verification types | 1 (pattern) | 5 (pattern, symbol, relationship, convention, security) | Verification system |

---

## Quality Checklist

- [x] 18 recommendations organized across 4 phases
- [x] Every recommendation includes priority, effort, impact, and evidence
- [x] Tool consolidation strategy with specific V1→V2 mapping
- [x] Full MCP 2025-11-25 spec compliance addressed (Resources, Prompts, Elicitation, Annotations, Streamable HTTP)
- [x] Security addressed (OAuth 2.1, input validation, path traversal, audit logging)
- [x] Observability addressed (OpenTelemetry replacing custom metrics)
- [x] Anti-hallucination system extended with hallucination classification
- [x] Feedback loop implements Google Tricorder model
- [x] Dependency graph showing inter-recommendation relationships
- [x] Cross-subsystem impact matrix linking to master recommendations
- [x] Success metrics with V1 baselines and V2 targets
- [x] All recommendations grounded in research sources (32 sources from RESEARCH.md)
- [x] Enterprise concerns addressed (multi-user, multi-project, connection pooling, versioning)
- [x] No duplication with master recommendations — MCP-specific concerns only
