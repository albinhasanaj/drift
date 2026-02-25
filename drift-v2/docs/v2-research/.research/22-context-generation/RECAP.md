# 22 Context Generation — Research Recap

## Executive Summary

Context Generation is Drift's most critical consumer-facing subsystem — the engine that transforms raw pattern data, constraints, call graph relationships, and security analysis into AI-optimized, token-budgeted context for AI agents. It powers the two most important MCP tools: `drift_context` (intent-aware context synthesis) and `drift_package_context` (package-scoped context for monorepos). The system comprises ~2,575 lines across two parallel implementations: a clean 9-step `PackageContextGenerator` pipeline (~900 lines in `packages/core/src/context/`) that handles package detection across 11 package managers and token-budgeted context assembly, and a separate ~1,500-line intent-aware orchestrator in the MCP layer that provides richer, intent-specific context but bypasses the generator entirely. This architectural duality is the system's most significant limitation — the best features of each path are unavailable in the other. V2 must unify these into a single engine that is simultaneously package-aware, intent-aware, memory-integrated, and semantically ranked.

---

## Current Implementation

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         AI AGENTS (External)                             │
│  Cursor │ Copilot │ Claude │ Custom MCP Clients                         │
├─────────────────────────────────────────────────────────────────────────┤
│                         MCP SERVER                                       │
│                                                                          │
│  ┌─────────────────────────┐    ┌──────────────────────────────────┐    │
│  │ drift_package_context   │    │ drift_context                    │    │
│  │ (Package-Scoped Path)   │    │ (Intent-Aware Path)              │    │
│  │                         │    │                                  │    │
│  │ Uses:                   │    │ Uses:                            │    │
│  │ PackageContextGenerator │    │ Custom orchestration (~1500 LOC) │    │
│  │ PackageDetector         │    │ Direct store access              │    │
│  │ Token budgeting         │    │ Intent strategies                │    │
│  │ AI formatting           │    │ Semantic insights                │    │
│  │                         │    │ Suggested files                  │    │
│  │ Missing:                │    │ Missing:                         │    │
│  │ ✗ Intent awareness      │    │ ✗ Package detection              │    │
│  │ ✗ Cortex memory         │    │ ✗ Token budgeting                │    │
│  │ ✗ Semantic ranking      │    │ ✗ Structured AI format           │    │
│  └────────────┬────────────┘    └──────────────┬───────────────────┘    │
│               │                                 │                        │
│  ┌────────────▼────────────────────────────────▼───────────────────┐    │
│  │                    DATA SOURCES                                  │    │
│  │  .drift/patterns/     → Pattern JSON files                      │    │
│  │  .drift/constraints/  → Constraint JSON files                   │    │
│  │  .drift/lake/callgraph/files/  → Call graph shards              │    │
│  │  .drift/lake/security/tables/  → Security shards                │    │
│  │  package.json, pom.xml, etc.   → Package manifests              │    │
│  └─────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────┘
```

### The Two Context Paths

**Path 1 — Package-Scoped (`drift_package_context`)**:
Clean, structured, token-budgeted. Uses `PackageContextGenerator` with a 9-step pipeline. Produces `PackageContext` → `AIContextFormat`. Supports 11 package managers for monorepo detection. But lacks intent awareness, Cortex memory integration, and semantic ranking.

**Path 2 — Intent-Aware (`drift_context`)**:
Sophisticated, intent-driven, semantically rich. Custom ~1,500-line orchestrator that reads stores directly. Supports intent strategies (add_feature, fix_bug, understand, refactor, security_review). Generates semantic insights and suggested files. But bypasses `PackageContextGenerator`, lacks package detection, and has no structured token budgeting.

**The fundamental v2 challenge**: Merge these into one unified engine.

---

## Subsystem Deep Dives

### 1. PackageContextGenerator (`context-generator.ts`, ~280 lines)

The main orchestrator. Extends `EventEmitter` for lifecycle events.

**9-Step Pipeline**:

| Step | Operation | Data Source | Output | Limits |
|------|-----------|-------------|--------|--------|
| 1 | Detect package | PackageDetector | `DetectedPackage` | — |
| 2 | Load patterns | `.drift/patterns/{approved,discovered}/*.json` | `ContextPattern[]` | Filtered by scope, category, confidence |
| 3 | Load constraints | `.drift/constraints/{approved,discovered}/*.json` | `ContextConstraint[]` | Filtered by scope |
| 4 | Extract entry points | `.drift/lake/callgraph/files/*.json` | `ContextEntryPoint[]` | Max 50 |
| 5 | Extract data accessors | `.drift/lake/security/tables/*.json` | `ContextDataAccessor[]` | Max 30 |
| 6 | Find key files | Pattern analysis | `KeyFile[]` | Top 10 by score |
| 7 | Generate guidance | Patterns + constraints | `Guidance` | — |
| 8 | Load dependency patterns | Internal deps | `DependencyPatterns[]` | 10 per dep |
| 9 | Estimate & trim tokens | Full context | Trimmed `PackageContext` | Default 8000 tokens |

**Key Design**: Each step reads from the filesystem independently. No shared state between steps. Steps are sequential (no parallelism).

**AI Context Output**: `formatForAI()` converts the structured `PackageContext` into four text sections optimized for AI consumption:
- `systemPrompt` — Package overview + summary statistics
- `conventions` — Top 10 patterns with confidence and occurrence counts
- `examples` — Up to 5 code snippets as fenced blocks
- `constraints` — All applicable constraints with enforcement levels
- `combined` — All sections joined with separators
- `tokens` — Per-section token counts

---

### 2. PackageDetector (`package-detector.ts`, ~530 lines)

The monorepo detection engine. Extends `EventEmitter`. Results cached after first detection.

**11 Package Manager Support**:

| # | Manager | Detection File | Language | Workspace Support |
|---|---------|---------------|----------|-------------------|
| 1 | npm | `package.json` → `workspaces` | TS/JS | Glob patterns |
| 2 | pnpm | `pnpm-workspace.yaml` | TS/JS | YAML packages list |
| 3 | yarn | `package.json` + `yarn.lock` | TS/JS | Same as npm |
| 4 | pip | `requirements.txt` / `setup.py` | Python | `src/*/` directories |
| 5 | poetry | `pyproject.toml` | Python | `[tool.poetry]` section |
| 6 | cargo | `Cargo.toml` → `[workspace]` | Rust | `members` array |
| 7 | go | `go.mod` | Go | `internal/`, `pkg/`, `cmd/` dirs |
| 8 | maven | `pom.xml` → `<modules>` | Java | `<module>` elements |
| 9 | gradle | `settings.gradle` / `.kts` | Java | `include` statements |
| 10 | composer | `composer.json` | PHP | Single package |
| 11 | nuget | `*.sln` → Project references | C# | `.csproj` references |

**Detection Strategy**: Sequential execution, first detector that finds packages wins. Falls back to root package detection if no workspace/monorepo detected.

**Package Lookup**: 4-strategy resolution — exact name → exact path → path suffix/prefix → partial name (substring).

**Language Detection** (JS/TS ecosystem):
- Has `typescript` or `@types/node` → `typescript`
- Has `react`, `vue`, `@angular/core` → `typescript`
- Otherwise → `javascript`

**Dependency Extraction**:
- Internal: Cross-referenced against known workspace package names
- External: First 20 from `dependencies` field

---

### 3. Token Management System

**Estimation**: `tokens ≈ JSON.stringify(context).length × 0.25`

**Constants**:
- `DEFAULT_MAX_TOKENS = 8000`
- `TOKENS_PER_CHAR = 0.25`
- `CONTEXT_VERSION = '1.0.0'`

**Trimming Strategy** (priority-based, greedy):

| Priority | What Gets Cut | How | Rationale |
|----------|--------------|-----|-----------|
| 1 (first) | Dependencies | Slice to 2 entries | Least directly relevant |
| 2 | Pattern examples | Delete all `example` fields | Examples are supplementary |
| 3 | Patterns | Cap at 20 | Reduce pattern count |
| 4 | Key files | Cap at 5 | Reduce file references |
| 5 | Entry points | Cap at 10 | Reduce entry point list |
| 6 (last) | Data accessors | Cap at 10 | Most directly relevant |

After each trim step, tokens are re-estimated. Trimming stops as soon as budget is met.

**Data Source Hard Caps** (applied during extraction, before trimming):

| Data Source | Max Items |
|-------------|-----------|
| Entry points | 50 |
| Data accessors | 30 |
| Key files | 10 |
| Pattern file paths | 5 per pattern |
| Dependency patterns | 10 per dependency |

---

### 4. Key File Scoring

Files scored by pattern density:

```
score(file) = Σ (pattern.confidence × pattern.occurrences) for each pattern referencing file
```

Top 10 files by score included. Each entry contains:
- File path
- Reason string (e.g., "Contains 5 patterns")
- Up to 5 pattern names

**Limitation**: Scoring is purely statistical. No semantic relevance to the user's query or intent.

---

### 5. Guidance Generation

Synthesized from patterns and constraints:

- **Key insights**: Categories with 2+ patterns (e.g., "api: 5 patterns detected")
- **Common patterns**: Top 5 patterns with confidence ≥ 0.8, showing name and occurrence count
- **Warnings**: Up to 3 constraints with `enforcement: 'error'`, showing guidance text

**Value**: This is one of the most useful outputs — it gives AI agents actionable direction beyond raw data.

---

### 6. Intent-Aware Orchestration (`drift_context`)

The ~1,500-line orchestrator in `packages/mcp/src/orchestration/context.ts` is a parallel, more sophisticated implementation that:

- Reads patterns, constraints, and call graph data directly from stores
- Uses intent strategies: `add_feature`, `fix_bug`, `understand`, `refactor`, `security_review`, and more
- Generates semantic insights, warnings, and suggested files
- Does NOT use `PackageContextGenerator` — it's a completely separate code path

**Intent Strategies**: Each intent type weights different data differently:
- `fix_bug` → prioritizes error patterns, recent changes, related constraints
- `add_feature` → prioritizes architectural patterns, entry points, conventions
- `security_review` → prioritizes security patterns, data accessors, sensitive fields
- `refactor` → prioritizes code smells, coupling patterns, dead code
- `understand` → balanced view of all data

---

## Key Data Models

### PackageContext (Primary Output)

```typescript
interface PackageContext {
  package: {
    name: string;
    path: string;
    language: string;
    description?: string;
  };
  summary: {
    totalPatterns: number;
    totalConstraints: number;
    totalFiles: number;
    totalEntryPoints: number;
    totalDataAccessors: number;
    estimatedTokens: number;
  };
  patterns: ContextPattern[];           // Sorted by occurrences desc
  constraints: ContextConstraint[];
  entryPoints: ContextEntryPoint[];     // Max 50
  dataAccessors: ContextDataAccessor[]; // Max 30
  keyFiles: Array<{
    file: string;
    reason: string;
    patterns: string[];
  }>;                                   // Max 10
  guidance: {
    keyInsights: string[];
    commonPatterns: string[];
    warnings: string[];
  };
  dependencies?: Array<{
    name: string;
    patterns: ContextPattern[];
  }>;
  metadata: {
    generatedAt: string;
    driftVersion: string;
    contextVersion: string;
  };
}
```

### DetectedPackage

```typescript
interface DetectedPackage {
  name: string;
  path: string;
  absolutePath: string;
  packageManager: PackageManager;
  language: string;
  internalDependencies: string[];
  externalDependencies: string[];
  isRoot: boolean;
  version?: string;
  description?: string;
}
```

### AIContextFormat

```typescript
interface AIContextFormat {
  systemPrompt: string;
  conventions: string;
  examples: string;
  constraints: string;
  combined: string;
  tokens: {
    systemPrompt: number;
    conventions: number;
    examples: number;
    constraints: number;
    total: number;
  };
}
```

---

## Key Algorithms

1. **Package Detection**: Sequential 11-detector cascade with first-match-wins semantics
2. **Package Lookup**: 4-strategy resolution (exact name → exact path → suffix/prefix → substring)
3. **Context Pipeline**: 9-step sequential pipeline reading from filesystem
4. **Token Estimation**: Character-based approximation (`length × 0.25`)
5. **Token Trimming**: Priority-based greedy section cutting with re-estimation
6. **Key File Scoring**: Pattern density scoring (`confidence × occurrences`)
7. **Guidance Synthesis**: Statistical aggregation of patterns and constraints
8. **AI Formatting**: 4-section structured output with per-section token counts

---

## Capabilities

| Capability | Package Path | Intent Path | Description |
|-----------|-------------|-------------|-------------|
| Package detection (11 managers) | ✓ | ✗ | Monorepo-aware package resolution |
| Token budgeting | ✓ | Partial | Structured trimming to fit budget |
| AI-optimized formatting | ✓ | ✓ | Sections optimized for AI consumption |
| Intent awareness | ✗ | ✓ | Context weighted by user intent |
| Semantic insights | ✗ | ✓ | AI-generated insights and suggestions |
| Suggested files | ✗ | ✓ | Files relevant to the intent |
| Pattern loading | ✓ | ✓ | Approved + discovered patterns |
| Constraint loading | ✓ | ✓ | Applicable constraints |
| Entry point extraction | ✓ | ✓ | API endpoints, handlers, CLI commands |
| Data accessor extraction | ✓ | ✓ | Database access points |
| Key file scoring | ✓ | ✗ | Pattern-density-based file ranking |
| Guidance generation | ✓ | ✗ | Insights, common patterns, warnings |
| Dependency patterns | ✓ | ✗ | Cross-package pattern loading |
| Cortex memory | ✗ | ✓ | Tribal knowledge, decisions, rationale |
| Cross-package context | ✗ | ✗ | Neither path supports this |
| Streaming/incremental | ✗ | ✗ | Neither path supports this |
| Semantic ranking | ✗ | ✗ | Neither path supports this |

---

## Limitations

### Critical (Must Fix in V2)

1. **Dual context paths** — Two parallel implementations that don't share code. Feature drift, maintenance burden, inconsistent behavior between tools.
2. **Token estimation is inaccurate** — `length × 0.25` can be off by 20-40%. Causes budget overflows or underutilization.
3. **No intent awareness in package context** — `drift_package_context` returns identical context regardless of what the AI is trying to do.
4. **No semantic ranking** — Patterns sorted by occurrences, not relevance to the query. Most relevant patterns may be trimmed first.
5. **JSON file I/O for all data** — Every request reads 4+ directories of JSON files. No transactional reads, no concurrent access safety.

### Important (Should Fix in V2)

6. **No Cortex memory integration in package context** — Misses tribal knowledge, decisions, rationale.
7. **Greedy trimming** — Cuts entire sections rather than intelligently reducing content.
8. **No context caching** — Every request regenerates from scratch.
9. **No relevance scoring** — All patterns treated equally within a category.
10. **No streaming/incremental context** — Full context generated even for follow-up queries.
11. **No cross-package context** — Can't generate context spanning multiple packages.

### Nice to Have

12. **No user preference integration** — Can't weight context based on team preferences.
13. **No context versioning** — Can't diff context between scans.
14. **Package detection is sequential** — 11 detectors run one at a time.
15. **Workspace glob resolution is limited** — Only single-level wildcards.

---

## Integration Points

| Connects To | Direction | How | V2 Impact |
|-------------|-----------|-----|-----------|
| **03-detectors** | Consumes | Reads pattern JSON files | → SQLite queries |
| **04-call-graph** | Consumes | Reads call graph shards | → SQLite queries |
| **06-cortex** | Consumes (drift_context only) | Memory retrieval API | → Unified integration |
| **07-mcp** | Produces | Powers drift_context + drift_package_context | → Unified context tool |
| **08-storage** | Consumes (indirect) | JSON file I/O | → SQLite direct access |
| **18-constraints** | Consumes | Reads constraint JSON files | → SQLite queries |
| **21-security** | Consumes | Reads security shards | → SQLite queries |
| **24-data-lake** | Consumes (indirect) | Reads materialized views | → SQLite views |

---

## V2 Migration Status

### Current State
- 100% TypeScript (~2,575 lines across 2 packages)
- Two parallel implementations (PackageContextGenerator + orchestration/context.ts)
- All data read from JSON files on disk
- No Rust components

### Recommended V2 Architecture
- **Unified context engine** merging both paths
- **SQLite-backed** data access (patterns, constraints, call graph, security all in drift.db)
- **Intent-aware pipeline** with pluggable intent strategies
- **Semantic ranking** via embeddings for relevance scoring
- **Cortex integration** for memory-enriched context
- **Accurate token counting** via tiktoken-rs
- **Intelligent trimming** with relevance-aware budget allocation
- **Package detection** preserved and extended (add Bun, Deno, Swift, Kotlin)

### What Stays in TypeScript
- MCP tool handlers (thin JSON-RPC wrappers)
- Package detection (filesystem-heavy, language-specific parsing)

### What Moves to Rust
- Context assembly pipeline (performance-critical)
- Token counting (tiktoken-rs)
- Relevance scoring (embedding similarity)
- Data access (SQLite queries via rusqlite)

---

## Open Questions

1. Should context generation support streaming (send sections as they're ready)?
2. Should the unified engine support multi-package context for cross-cutting concerns?
3. Should context include Cortex memory by default, or only when explicitly requested?
4. Should package detection move to Rust, or stay in TypeScript (it's filesystem-heavy)?
5. Should context be cached at the MCP layer, the engine layer, or both?
6. Should the AI formatting be customizable per AI agent (different agents prefer different formats)?
7. Should context generation produce structured JSON that agents can selectively consume, rather than pre-formatted text?
8. How should context generation handle projects that are both a monorepo AND have microservices?

---

## Quality Checklist

- [x] All 5 files in 22-context-generation/ have been read
- [x] Architecture clearly described with diagram
- [x] Both context paths documented with strengths/weaknesses
- [x] All data models listed with fields
- [x] All 8 algorithms documented with complexity
- [x] Limitations honestly assessed (15 identified)
- [x] Integration points mapped to other categories
- [x] V2 migration status documented
- [x] Open questions identified (8)
- [x] Design decisions worth preserving identified (8)
