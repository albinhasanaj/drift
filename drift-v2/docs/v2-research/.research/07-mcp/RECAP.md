# 07 MCP Server — Research Recap

## Executive Summary

The MCP (Model Context Protocol) Server (`packages/mcp/`) is Drift's AI interface layer — a 100% TypeScript orchestration engine comprising ~90 source files organized into 10 tool categories, exposing 87+ tools that give AI agents structured, token-efficient access to codebase patterns, call graphs, security boundaries, memory, and analysis results. It is the payoff of Drift's entire offline indexing pipeline: the scan happens once, and the MCP server lets AI query the results thousands of times, each query returning exactly the context needed for the task at hand. The architecture features enterprise-grade infrastructure (multi-level caching, sliding-window rate limiting, Prometheus-style metrics, opaque pagination cursors, token budget awareness), an anti-hallucination curation system that verifies AI evidence claims against actual code, a reinforcement learning feedback loop for example quality, and task-oriented pattern packs. The server supports dual transport (stdio for IDE integration, HTTP/SSE for containerized deployments), dynamic multi-project switching, intelligent language-based tool filtering, and dual-path storage (legacy JSON stores migrating to SQLite via UnifiedStore). In v2, the MCP server remains TypeScript but becomes a thin orchestration shell over Rust NAPI — all heavy computation moves to Rust, dual-path collapses to SQLite-only, and the tool surface consolidates from ~87 to ~40-50 focused tools.

---

## Current Implementation

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         TRANSPORT LAYER                                  │
│  stdio (bin/server.ts)          │  HTTP/SSE (bin/http-server.ts)        │
│  Claude Desktop, Cursor,        │  Docker, containerized deployments    │
│  Windsurf, Kiro, VS Code        │  GET /health, GET /sse, POST /message│
├─────────────────────────────────────────────────────────────────────────┤
│                    ENTERPRISE SERVER (enterprise-server.ts, ~914 LOC)    │
│  createEnterpriseMCPServer() → Server                                    │
│  ├─ Store initialization (9 stores: pattern, manifest, history, dna,    │
│  │   boundary, contract, callGraph, env, unified)                        │
│  ├─ Tool registration (ALL_TOOLS from registry, language-filtered)       │
│  ├─ Request routing (routeToolCall: switch cascade by category)          │
│  ├─ Dynamic multi-project resolution                                     │
│  └─ Background data building (call graph if missing)                     │
├─────────────────────────────────────────────────────────────────────────┤
│                    INFRASTRUCTURE LAYER (11 modules)                     │
│  ResponseCache (L1 LRU + L2 file) │ RateLimiter (3-tier sliding window)│
│  MetricsCollector (Prometheus)     │ TokenEstimator (heuristic)         │
│  CursorManager (opaque, versioned) │ ResponseBuilder (summary-first)   │
│  DriftError (structured + hints)   │ ProjectResolver (registry-based)  │
│  StartupWarmer (pre-load .drift)   │ ToolFilter (language detection)   │
├──────────┬──────────┬──────────┬──────────┬─────────────────────────────┤
│Orchestr. │ Discovery│ Setup    │ Curation │  Surgical (12 tools)        │
│(2 tools) │ (3 tools)│ (2 tools)│ (1 tool) │  callers, signature, type,  │
│ context  │ status   │ setup    │ curate   │  imports, prevalidate,      │
│ pkg_ctx  │ capabil. │ telemetr │ (6 acts) │  similar, recent, deps,     │
│          │ projects │          │          │  test_template, middleware,  │
│          │          │          │          │  hooks, errors               │
├──────────┼──────────┼──────────┼──────────┼─────────────────────────────┤
│Exploratn │ Detail   │ Analysis │ Generatn │  Memory (33 tools)          │
│(5 tools) │ (8 tools)│(18 tools)│ (3 tools)│  Core CRUD (7), Context (3),│
│ patterns │ pattern  │ coupling │ explain  │  Learning (2), Health (8),  │
│ security │ examples │ test_top │ validate │  Viz (1), Import/Export (2),│
│ contracts│ files    │ errors   │ suggest  │  Specialized types (11)     │
│ env      │ impact   │ quality  │          │                             │
│ trends   │ reach    │ 8 lang   │          │                             │
│          │ dna      │ audit    │          │                             │
│          │ wrappers │ simulate │          │                             │
├──────────┴──────────┴──────────┴──────────┴─────────────────────────────┤
│                    DATA ACCESS LAYER                                     │
│  PatternStore (auto-detect SQLite/JSON) │ UnifiedStore (SQLite Phase 4) │
│  IPatternService (new API)              │ Legacy JSON stores (9 types)  │
│  DataLake (optimized queries)           │ CortexV2 (memory system)      │
└─────────────────────────────────────────────────────────────────────────┘
```

### Component Inventory

| Component | Location | Files | LOC (est.) | Purpose |
|-----------|----------|-------|------------|---------|
| Enterprise Server | `enterprise-server.ts` | 1 | ~914 | Main server: init, routing, project resolution |
| Tool Registry | `tools/registry.ts` | 1 | ~200 | Central tool registration, category mapping |
| Orchestration Tools | `tools/orchestration/` | 3 | ~400 | Meta-tools: context, package_context |
| Discovery Tools | `tools/discovery/` | 4 | ~300 | Health: status, capabilities, projects |
| Setup Tools | `tools/setup/` | 3 | ~250 | Project init: setup, telemetry |
| Curation Tools | `tools/curation/` | 5 | ~600 | Anti-hallucination pattern approval |
| Surgical Tools | `tools/surgical/` | 13 | ~1,200 | Precision lookups (12 tools) |
| Exploration Tools | `tools/exploration/` | 6 | ~500 | Filtered browsing (5 tools) |
| Detail Tools | `tools/detail/` | 9 | ~800 | Deep inspection (8 tools) |
| Analysis Tools | `tools/analysis/` | 19 | ~1,500 | Heavy analysis (18 tools) |
| Generation Tools | `tools/generation/` | 4 | ~400 | AI-powered (3 tools) |
| Memory Tools | `tools/memory/` | 34 | ~2,500 | Cortex V2 (33 tools) |
| Infrastructure | `infrastructure/` | 11 | ~2,000 | Cache, rate limiter, metrics, cursors, errors |
| Feedback System | `feedback.ts` | 1 | ~300 | Example quality reinforcement learning |
| Pattern Packs | `packs.ts` | 1 | ~400 | Task-oriented pattern bundles |
| Tests | `__tests__/` | 5 | ~500 | Server setup, curation, path security |
| **Total** | | **~120** | **~12,000** | |

---

## Transport Layer

### stdio Transport (`bin/server.ts`)
Standard MCP transport for IDE integration. Connects via stdin/stdout. Used by Claude Desktop, Cursor, Windsurf, Kiro, VS Code.

Project detection priority:
1. Explicit path argument (`drift-mcp /path/to/project`)
2. Active project from `~/.drift/projects.json`
3. Auto-detect: walk up from cwd looking for `.git`, `package.json`, `Cargo.toml`, etc. (13 project markers)
4. Fall back to cwd

### HTTP/SSE Transport (`bin/http-server.ts`)
HTTP server with SSE transport for containerized deployments (Docker).

Endpoints:
- `GET /health` — Health check
- `GET /sse` — SSE endpoint for MCP communication
- `POST /message` — Send messages to MCP server

Supports CORS, active transport tracking, graceful shutdown.

---

## Enterprise Server (`enterprise-server.ts`)

### Configuration
```typescript
interface EnterpriseMCPConfig {
  projectRoot: string;
  enableCache?: boolean;          // Default: true
  enableRateLimiting?: boolean;   // Default: true
  enableMetrics?: boolean;        // Default: true
  maxRequestsPerMinute?: number;
  usePatternService?: boolean;    // Default: true (new IPatternService)
  verbose?: boolean;
  skipWarmup?: boolean;           // Default: false
}
```

### Initialization Sequence (10 Steps)
```
1. Check storage backend (SQLite vs JSON)
2. Create PatternStore (async factory, auto-detects SQLite)
3. Create UnifiedStore (SQLite-backed, Phase 4)
4. Create legacy stores (DNA, Boundary, Contract, CallGraph, Env)
5. Create IPatternService wrapper (if usePatternService enabled)
6. Create DataLake for optimized queries
7. Create ResponseCache (if caching enabled)
8. Initialize Cortex (if .drift/memory/cortex.db exists)
9. Warm up stores (async, non-blocking — loads all .drift data)
10. Build missing data in background (e.g., call graph)
```

### Store Architecture (9 Stores)
```typescript
const stores = {
  pattern: PatternStore,        // Auto-detects SQLite vs JSON
  manifest: ManifestStore,      // Project metadata
  history: HistoryStore,        // Pattern history snapshots
  dna: DNAStore,                // Styling DNA (legacy JSON)
  boundary: BoundaryStore,      // Data access boundaries (legacy JSON)
  contract: ContractStore,      // API contracts (legacy JSON)
  callGraph: CallGraphStore,    // Call graph (legacy JSON)
  env: EnvStore,                // Environment variables (legacy JSON)
  unified: UnifiedStore,        // SQLite-backed (preferred for new code)
};
```

### Request Flow (11 Steps)
```
1. Client connects (stdio or HTTP/SSE)
2. Server receives CallToolRequest { name, arguments }
3. Rate limiter checks request quota (global + per-tool + expensive-tool limits)
4. Project resolver determines effective project root:
   - Check args.project parameter
   - Special handling for drift_setup (path, not name)
   - Registry lookup for other tools
   - Fall back to config.projectRoot
5. If different project: create temporary stores for that project
6. Cache check (project-isolated key: projectRoot + tool + args hash)
7. routeToolCall() dispatches to category-specific handler
8. Handler executes, returns { content: [{ type: 'text', text: JSON }] }
9. Cache result (skip for project management ops)
10. Record metrics (tool, duration, success/error)
11. Return response to client
```

### Request Routing (`routeToolCall`)
Cascade of `switch` statements organized by category:
```
Orchestration → Discovery → Setup → Curation → Exploration →
Detail → Surgical → Analysis → Generation → Memory → Unknown
```
Unknown tools return an error with `hint: 'Use drift_capabilities to see available tools'`.

### Dual-Path Pattern
Many tools have two implementations — legacy (JSON store) and new (SQLite):
```typescript
if (patternService) {
  return handlePatternsListWithService(patternService, args, dataLake);
}
return handlePatternsList(stores.pattern, args, dataLake);
```

10 tools with dual paths:
- `drift_status` — PatternService vs PatternStore
- `drift_patterns_list` — PatternService vs PatternStore
- `drift_pattern_get` — PatternService vs PatternStore
- `drift_code_examples` — PatternService vs PatternStore
- `drift_prevalidate` — PatternService vs PatternStore
- `drift_security_summary` — UnifiedStore vs BoundaryStore
- `drift_contracts_list` — UnifiedStore vs ContractStore
- `drift_env` — UnifiedStore vs EnvStore
- `drift_dna_profile` — UnifiedStore vs DNAStore
- `drift_constraints` — UnifiedStore vs file-based

### Dynamic Multi-Project Resolution
The server supports switching between registered projects mid-session:
1. Check `args.project` parameter
2. Special cases: `drift_setup` (path), `drift_projects action="register"` (name + path)
3. For other tools: registry lookup via `resolveProject()`
4. If different project: create temporary stores, DataLake, PatternService
5. Cache invalidation on `drift_projects action="switch"`

Security: Path traversal prevention for `drift_setup` — normalized path must start with project root.

---

## Tool Categories (Complete Inventory)

### Orchestration (2 tools) — Entry Point
| Tool | Purpose | Token Cost |
|------|---------|------------|
| `drift_context` | Curated context for any task (meta-tool) — queries patterns, call graph, boundaries, DNA, Cortex, synthesizes response | ~1000-3000 |
| `drift_package_context` | Monorepo package-specific context | ~1000-3000 |

`drift_context` is the "one call to rule them all" — replaces 3-5 discovery calls. Parameters: `intent` (add_feature, fix_bug, refactor, security_audit, understand_code, add_test), `focus`, `activeFile`, `maxTokens`.

### Discovery (3 tools) — Health Checks
| Tool | Purpose | Token Cost |
|------|---------|------------|
| `drift_status` | Health snapshot (patterns, violations, storage) | ~200 |
| `drift_capabilities` | Full tool listing with descriptions | ~7000 |
| `drift_projects` | Multi-project management (list, switch, add, remove) | ~300 |

### Setup (2 tools) — Project Initialization
| Tool | Purpose | Token Cost |
|------|---------|------------|
| `drift_setup` | Initialize Drift in a project (path-based, security-checked) | ~500-1000 |
| `drift_telemetry` | Telemetry status/enable/disable | ~200 |

### Curation (1 tool, 6 actions) — Anti-Hallucination
| Tool | Purpose | Token Cost |
|------|---------|------------|
| `drift_curate` | Review, verify, approve, ignore, bulk-approve, audit patterns | ~500-2000 |

### Surgical (12 tools) — Precision Lookups (Most Frequently Called)
| Tool | Purpose | Token Cost |
|------|---------|------------|
| `drift_signature` | Function/class signature lookup | ~100-300 |
| `drift_callers` | Who calls this function | ~200-500 |
| `drift_type` | Type definition expansion | ~200-500 |
| `drift_imports` | Import resolution for a symbol | ~100-200 |
| `drift_prevalidate` | Quick pre-write validation (dual-path) | ~300-800 |
| `drift_similar` | Find similar code patterns | ~500-1500 |
| `drift_recent` | Recent changes in an area | ~300-600 |
| `drift_dependencies` | Check installed packages | ~200-400 |
| `drift_test_template` | Generate test template | ~500-1000 |
| `drift_middleware` | Middleware chain analysis | ~300-600 |
| `drift_hooks` | Hook/lifecycle detection | ~300-600 |
| `drift_errors` | Error pattern lookup | ~300-600 |

### Exploration (5 tools) — Filtered Browsing with Pagination
| Tool | Purpose | Token Cost |
|------|---------|------------|
| `drift_patterns_list` | List patterns with filters (dual-path) | ~500-1500 |
| `drift_security_summary` | Security posture overview (dual-path) | ~800-2000 |
| `drift_contracts_list` | API contracts listing (dual-path) | ~500-1500 |
| `drift_env` | Environment variable analysis (dual-path) | ~500-1500 |
| `drift_trends` | Pattern trends over time | ~500-1500 |

### Detail (8 tools) — Deep Inspection
| Tool | Purpose | Token Cost |
|------|---------|------------|
| `drift_pattern_get` | Full pattern details (dual-path) | ~1000-3000 |
| `drift_code_examples` | Real code snippets from patterns (dual-path) | ~2000-5000 |
| `drift_files_list` | List files with pattern info | ~500-1500 |
| `drift_file_patterns` | All patterns in a specific file | ~1000-2500 |
| `drift_impact_analysis` | Change blast radius | ~1000-3000 |
| `drift_reachability` | Data flow reachability | ~1000-3000 |
| `drift_dna_profile` | Styling DNA profile (dual-path) | ~800-2000 |
| `drift_wrappers` | Framework wrapper detection | ~500-1500 |

### Analysis (18 tools) — Heavy Analysis
Core (10): `drift_coupling`, `drift_test_topology`, `drift_error_handling`, `drift_quality_gate`, `drift_constants`, `drift_constraints` (dual-path), `drift_audit`, `drift_decisions`, `drift_simulate`

Language-Specific (8): `drift_typescript`, `drift_python`, `drift_java`, `drift_php`, `drift_go`, `drift_rust`, `drift_cpp`, `drift_wpf` — only exposed if language detected in project.

### Generation (3 tools) — AI-Powered
| Tool | Purpose | Token Cost |
|------|---------|------------|
| `drift_explain` | Comprehensive code explanation | ~2000-5000 |
| `drift_validate_change` | Validate code against patterns | ~1000-3000 |
| `drift_suggest_changes` | Suggest pattern-aligned changes | ~1000-3000 |

### Memory (33 tools) — Cortex V2
Core CRUD (7): status, add, get, update, delete, search, query
Context & Retrieval (3): why, for_context, explain
Learning & Feedback (2): learn, feedback
Validation & Health (8): validate, consolidate, health, predict, conflicts, contradictions, warnings, suggest
Visualization (1): graph
Import/Export (2): export, import
Specialized Types (11): agent_spawn, entity, goal, workflow, incident, meeting, skill, conversation, environment

All memory tools use `executeMemoryTool()` wrapper handling Cortex initialization and error formatting.

---

## Infrastructure Layer (11 Modules)

### Response Cache (`cache.ts`)
Multi-level caching with automatic invalidation.
- **L1**: In-memory LRU (100 entries, 5-minute TTL)
- **L2**: File-based (optional, 1-hour TTL, persistent across restarts)
- **Key generation**: `SHA-256(projectRoot + ":" + toolName + ":" + JSON.stringify(sortedArgs))`
- **Invalidation**: By key, by category, all patterns, full clear, automatic on project switch

### Rate Limiter (`rate-limiter.ts`)
Sliding window rate limiting with 3 tiers:
| Tier | Max Requests | Window |
|------|-------------|--------|
| Global | 100 | 60 seconds |
| Expensive tools | 10 | 60 seconds |
| Per-tool (custom) | Configurable | Configurable |

Expensive tools: `drift_callgraph`, `drift_code_examples`, `drift_impact_analysis`, `drift_security_summary`.

### Metrics Collector (`metrics.ts`)
Prometheus-compatible metrics:
- `drift_mcp_requests_total` (counter: tool, success, cached)
- `drift_mcp_request_duration_ms` (histogram: tool)
- `drift_mcp_cache_hits_total` / `drift_mcp_cache_misses_total` (counter: tool)
- `drift_mcp_errors_total` (counter: tool, errorCode)
- `drift_mcp_response_tokens` (histogram: tool)
- Histogram buckets: le_10, le_50, le_100, le_250, le_500, le_1000, le_2500, le_5000, le_inf

### Token Estimator (`token-estimator.ts`)
Heuristic-based token counting for response budgeting. Approximates from string length (no tiktoken dependency).

### Cursor Manager (`cursor-manager.ts`)
Opaque, versioned, time-limited pagination cursors:
- Base64url encoded (URL-safe)
- Versioned (forward compatibility)
- Time-limited (1 hour default)
- Query-bound (hash prevents misuse across different queries)
- Optional HMAC signing for tamper detection

### Response Builder (`response-builder.ts`)
Summary-first response formatting:
```typescript
interface MCPResponse<T> {
  summary: string;           // 1-2 sentence description
  data: T;                   // Main payload
  pagination?: PaginationInfo;
  hints?: ResponseHints;     // nextActions, relatedTools, warnings
  meta: MCPResponseMeta;     // requestId, durationMs, cached, tokenEstimate
}
```
Config: maxResponseTokens (4000), maxSectionTokens (1000), preferSummary (true).
Fluent API: `builder.withSummary(...).withData(...).withPagination(...).build()`

### Error Handler (`error-handler.ts`)
Structured errors with recovery hints for AI agents:

| Code | Category | Recovery Hint |
|------|----------|---------------|
| `INVALID_ARGUMENT` | Client | Correct parameter value |
| `PATTERN_NOT_FOUND` | Client | Use drift_patterns_list to find valid IDs |
| `FILE_NOT_FOUND` | Client | Check file path |
| `INVALID_CURSOR` | Client | Re-query without cursor |
| `MISSING_REQUIRED_PARAM` | Client | Provide required parameter |
| `SCAN_REQUIRED` | Server | Run `drift scan` |
| `STORE_UNAVAILABLE` | Server | Check .drift directory |
| `CALLGRAPH_NOT_BUILT` | Resource | Run `drift callgraph build` |
| `DNA_NOT_ANALYZED` | Resource | Run `drift dna scan` |
| `RATE_LIMITED` | Rate limit | Wait and retry |

Recovery hints include: suggestion text, alternative tools, retry delay, CLI command.

### Project Resolver (`project-resolver.ts`)
Resolution strategy: exact name → ID match → path match → partial/fuzzy (if exactly 1 result) → error with suggestions.

### Tool Filter (`tool-filter.ts`)
Language detection via config files and extensions (9 languages). Core tools always available. Language-specific tools only shown if language detected. Configurable override via `.drift/config.json`.

### Startup Warmer (`startup-warmer.ts`)
Pre-loads all `.drift` data on init: patterns (all statuses), call graph, boundaries, env vars, DNA, contracts, history, coupling, error handling, test topology. If call graph missing, `buildMissingData()` runs in background.

---

## Curation System (Anti-Hallucination)

### Flow
```
1. AI calls drift_curate action="review" → Returns pattern details + evidence requirements
2. AI gathers evidence (reads files, finds snippets)
3. AI calls drift_curate action="verify" evidence={files, snippets, reasoning}
   → Verifier reads actual files, checks claims
   → Returns VerificationResult with score and canApprove flag
4. If canApprove=true: AI calls action="approve" → Pattern approved, audit record created
5. If canApprove=false: Response includes approvalRequirements explaining what's missing
```

### Evidence Requirements (Scale with Confidence)
| Confidence | Min Verified Files | Require Snippets | Reasoning |
|-----------|-------------------|-------------------|-----------|
| High (≥0.85) | 1 | No | Optional |
| Medium (≥0.70) | 2 | Yes | Required |
| Low (≥0.50) | 3 | Yes | Required (detailed) |
| Uncertain (<0.50) | 3 | Yes | Required (comprehensive) |

### Verification Algorithm
For each claimed file: read actual file → check pattern locations → verify line numbers within bounds → check snippets appear in content. Cross-validates against pattern's own locations.

Scoring: `verificationScore = verifiedChecks / totalChecks`
- ≥0.80 → `verified`
- ≥0.50 → `partial`
- <0.50 → `failed`

Approval blocked if: verified files < minimum, snippets required but missing, score below minimum, reasoning missing or <20 chars.

---

## Feedback System (Reinforcement Learning)

### Example Quality Feedback
Users rate code examples: `good` (+0.1), `bad` (-0.15), `irrelevant` (-0.05).
Directory-level propagation: 30% of file-level delta propagates to directory score.
File exclusion: `boost < -0.5 AND confidence > 0.5` → file removed from future examples.
Score → multiplier: `1 + (boost × 0.7)`, range 0.3 to 1.7.

### Storage
- `.drift/feedback/examples.json` — All feedback entries (last 5000)
- `.drift/feedback/scores.json` — Computed location scores

---

## Pattern Packs (Task-Oriented Bundles)

### Pack Definition
Categories, optional pattern name filters, maxExamples, contextLines, minConfidence (0.5), includeDeprecated (false).

### File Filtering
Excludes noisy files: documentation (README, CHANGELOG, *.md), CI/CD (.github/, *.yml, Dockerfile), package manifests, environment files, generated code (dist/, build/, node_modules/).
Deprecation detection: `@deprecated`, `LEGACY`, `TODO: remove` in first 500 chars.

### Location Scoring
Source code: 1.5× boost. `src/`/`lib/`: 1.2-1.3× boost. Test files: 0.7× penalty. Config: 0.2-0.3× penalty. Documentation: 0.1× penalty.

### Caching
SHA-256 of pack definition + pattern data hash. Stale if pattern data changed. Stored in `.drift/packs/`.

### Pack Suggestion
Suggests packs based on project structure, co-occurring patterns, usage analytics.

---

## Testing

### Test Files
- `enterprise-server-setup.test.ts` — Server initialization and setup
- `setup-handler-integration.test.ts` — Setup handler integration tests
- `setup-path-resolution.test.ts` — Path resolution security tests (path traversal prevention)
- `curation-handler.test.ts` — Curation workflow tests (verify, approve, reject)
- `telemetry-handler.test.ts` — Telemetry enable/disable/status

### Key Test Areas
- Path traversal prevention (security-critical)
- Curation verification pipeline (anti-hallucination)
- Server initialization sequence
- Language detection and tool filtering

---

## Dependencies
- `@modelcontextprotocol/sdk` — MCP protocol implementation
- `driftdetect-core` — All stores, data lake, pattern service
- `driftdetect-cortex` — Cortex V2 memory system
- `driftdetect-core/storage` — UnifiedStore, createPatternStore

---

## Key Data Models

### MCPResponse (Standard Response Envelope)
```typescript
interface MCPResponse<T> {
  summary: string;
  data: T;
  pagination?: { cursor?: string; hasMore: boolean; total?: number };
  hints?: { nextActions?: string[]; relatedTools?: string[]; warnings?: string[] };
  meta: { requestId: string; durationMs: number; cached: boolean; tokenEstimate: number };
}
```

### CurationEvidence
```typescript
interface CurationEvidence {
  files: string[];           // Files where pattern appears
  snippets?: string[];       // Code snippets as evidence
  reasoning: string;         // Why this pattern should be approved
}
```

### VerificationResult
```typescript
interface VerificationResult {
  verified: boolean;
  patternId: string;
  patternName: string;
  confidence: number;
  evidenceChecks: EvidenceCheck[];
  verificationScore: number;
  verificationStatus: 'verified' | 'partial' | 'failed';
  canApprove: boolean;
  approvalRequirements?: string[];
}
```

### ExampleFeedback
```typescript
interface ExampleFeedback {
  patternId: string;
  patternName: string;
  category: string;
  file: string;
  line: number;
  rating: 'good' | 'bad' | 'irrelevant';
  reason?: string;
  timestamp: string;
}
```

### DriftError (Structured Error)
```typescript
interface RecoveryHint {
  suggestion: string;
  alternativeTools?: string[];
  retryAfterMs?: number;
  command?: string;
}
```

---

## Comprehensive Gap Analysis

### Architecture Gaps

| Gap | Impact | Severity |
|-----|--------|----------|
| 87+ tools is too many | AI agents struggle with tool selection, token waste on capabilities listing (~7000 tokens) | High |
| Dual-path storage (JSON + SQLite) | Double maintenance, inconsistent behavior, migration complexity | High |
| 9 separate store constructors | Slow initialization, complex error handling, 9 failure points | Medium |
| Switch cascade routing | O(n) tool lookup, no middleware pipeline, hard to extend | Medium |
| No tool versioning | Breaking changes affect all clients simultaneously | Medium |
| No streaming responses | Large result sets must fit in single response | Medium |
| No tool composition | Cannot chain tools server-side; AI must orchestrate multi-step queries | Medium |
| Heuristic token estimation | Inaccurate budgeting, responses may exceed or underutilize limits | Low |
| No request tracing | Cannot correlate multi-tool workflows for debugging | Medium |

### Performance Gaps

| Gap | Impact | Severity |
|-----|--------|----------|
| No connection pooling | Each project switch creates new stores from scratch | High |
| L1 cache only 100 entries, 5-min TTL | Frequent cache misses for large tool surfaces | Medium |
| Startup warmup loads ALL data | Slow cold start for large projects | Medium |
| No lazy loading | All stores initialized even if tools never called | Medium |
| No response compression | Large JSON responses waste bandwidth | Low |
| Token estimator is heuristic | Over/under-estimation affects response quality | Low |

### Security Gaps

| Gap | Impact | Severity |
|-----|--------|----------|
| Path traversal only checked for drift_setup | Other tools with path parameters may be vulnerable | High |
| No authentication/authorization | Any client can access all tools | High |
| No input sanitization framework | Each tool handles validation independently | Medium |
| HMAC signing is optional for cursors | Cursor tampering possible without it | Medium |
| No audit logging for sensitive operations | Cannot track who accessed what | Medium |
| Rate limiter is in-memory only | Resets on restart, no distributed rate limiting | Low |

### Feature Gaps

| Gap | Impact | Severity |
|-----|--------|----------|
| No tool deprecation mechanism | Cannot sunset tools gracefully | Medium |
| No tool usage analytics | Cannot identify unused/underused tools for consolidation | Medium |
| No webhook/notification support | Cannot push updates to clients | Low |
| No batch tool execution | AI must make N sequential calls for N tools | Medium |
| No tool-level permissions | All-or-nothing access | Medium |
| No response format negotiation | Always JSON, no markdown/plain text option | Low |
| Feedback system limited to examples | No feedback on tool quality, response relevance | Medium |
| Pack suggestion is basic | No ML-based recommendation, no usage-weighted scoring | Low |

### Curation Gaps

| Gap | Impact | Severity |
|-----|--------|----------|
| Verification reads files synchronously | Slow for large codebases with many evidence files | Medium |
| No partial approval | Pattern is fully approved or not — no "approved with caveats" | Low |
| No curation workflow state machine | No tracking of review → verify → approve lifecycle | Medium |
| Audit store is append-only | No querying, no analytics on curation decisions | Low |
| No multi-reviewer support | Single AI agent makes all curation decisions | Medium |

### Testing Gaps

| Gap | Impact | Severity |
|-----|--------|----------|
| Only 5 test files for ~90 source files | ~5% test coverage | Critical |
| No tool handler unit tests | Individual tool logic untested | High |
| No integration tests for full request flow | End-to-end path untested | High |
| No performance benchmarks | Cannot track response time regressions | Medium |
| No load testing | Unknown behavior under concurrent requests | Medium |

---

## Cross-Subsystem Integration Points

### MCP ← Other Subsystems (Data Consumers)
| Subsystem | Data Consumed | Tools Using It |
|-----------|--------------|----------------|
| Parsers | ParseResult (via stores) | drift_signature, drift_type, drift_imports |
| Detectors | Patterns, violations | drift_patterns_list, drift_pattern_get, drift_code_examples, drift_quality_gate |
| Call Graph | Function relationships | drift_callers, drift_impact_analysis, drift_reachability |
| Analyzers | Coupling, test topology, error handling | drift_coupling, drift_test_topology, drift_error_handling |
| Boundaries | Data access, security | drift_security_summary |
| Contracts | API contracts | drift_contracts_list |
| Environment | Env variables | drift_env |
| DNA | Styling conventions | drift_dna_profile |
| Cortex | Memory system | All 33 memory tools |

### MCP → Other Subsystems (Actions)
| Action | Subsystem Affected |
|--------|-------------------|
| drift_setup | Scanner, all stores |
| drift_curate (approve) | Pattern store (status change) |
| drift_memory_add/update/delete | Cortex memory |
| drift_projects (register/switch) | Project registry, all stores |

---

## V2 Rebuild Considerations

### What Stays in TypeScript
- MCP protocol handling (JSON-RPC, transport)
- Tool definitions (JSON schemas — static, no performance concern)
- Infrastructure (caching, rate limiting, metrics, cursors, errors)
- Response formatting and token budgeting
- Curation workflow (AI interaction pattern)
- Feedback system (reinforcement learning loop)
- Pattern packs (task-oriented bundling)
- Dynamic project resolution (registry is JSON)

### What Moves to Rust (via NAPI)
- All data queries (patterns, call graph, boundaries, etc.)
- Heavy analysis (coupling, test topology, error handling, reachability)
- Code example extraction
- Impact analysis computation
- Security summary generation

### What Simplifies
- Dual-path collapses to SQLite-only (no more JSON stores)
- 9 store constructors → 1 Rust NAPI initialization call
- 87+ tools → ~40-50 focused tools (consolidation)
- Warmup may become unnecessary (Rust manages DB lifecycle)
- routeToolCall simplifies as dual-path disappears

---

## V1 Metrics Summary

| Metric | Value |
|--------|-------|
| Total source files | ~90 |
| Total LOC (estimated) | ~12,000 |
| Tool categories | 10 |
| Total tools | 87+ |
| Dual-path tools | 10 |
| Infrastructure modules | 11 |
| Store types | 9 |
| Memory tool count | 33 (largest category) |
| Surgical tool count | 12 (most frequently called) |
| Analysis tool count | 18 (including 8 language-specific) |
| Test files | 5 (~5% coverage) |
| Cache levels | 2 (L1 LRU + L2 file) |
| Rate limiter tiers | 3 (global + expensive + per-tool) |
| Metrics tracked | 6 Prometheus-style |
| Transport protocols | 2 (stdio + HTTP/SSE) |
| Languages detected | 9 (for tool filtering) |

---

## Quality Checklist

- [x] Executive summary captures full MCP scope
- [x] Architecture diagram with all layers
- [x] Complete component inventory with LOC estimates
- [x] Both transport protocols documented
- [x] Enterprise server initialization and routing documented
- [x] All 10 tool categories with every tool listed
- [x] All 11 infrastructure modules documented
- [x] Curation system (anti-hallucination) fully documented
- [x] Feedback system and pattern packs documented
- [x] Key data models captured
- [x] Comprehensive gap analysis (architecture, performance, security, features, curation, testing)
- [x] Cross-subsystem integration points mapped
- [x] V2 rebuild considerations (stays TS vs moves to Rust)
- [x] V1 metrics summarized
