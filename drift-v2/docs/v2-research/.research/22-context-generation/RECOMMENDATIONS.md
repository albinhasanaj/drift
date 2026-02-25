# 22 Context Generation — V2 Recommendations

> Concrete improvement recommendations for Drift v2's context generation system.
> Derived from v1 forensic audit, recap, and external research (R1-R22).
> Date: February 2026

---

## CG1: Unified Context Engine — Merge Dual Paths

**Priority**: P0 (Critical)
**Effort**: High
**Impact**: Eliminates the most significant architectural debt
**Evidence**: Audit L1, R3 (Anthropic), R22 (Least Context principle)

**Current State**:
Two parallel implementations that don't share code:
- `PackageContextGenerator` (280 LOC) — package-scoped, token-budgeted, no intent
- `orchestration/context.ts` (1,500 LOC) — intent-aware, no package detection

**Proposed Change**:
Merge into a single `ContextEngine` with unified pipeline:

```
Input: ContextRequest {
  package?: string,        // Package scope (optional)
  intent?: ContextIntent,  // What the agent is trying to do
  query?: string,          // Natural language query
  maxTokens: number,       // Token budget
  session?: SessionId,     // For deduplication
  depth?: ContextDepth,    // overview | standard | deep
  scope?: ContextScope,    // package | cross-package | repo
}
```

Pipeline stages:
1. **Resolve scope** — Package detection + scope expansion (cross-package if needed)
2. **Gather candidates** — Collect patterns, constraints, entry points, data accessors, memories from SQLite
3. **Score** — Compute relevance score per candidate (CG3)
4. **Rank** — Sort by composite score, apply intent weighting (CG2)
5. **Budget** — Allocate tokens per section, trim to fit (CG6)
6. **Format** — Produce AI-optimized output with section boundaries (CG12)
7. **Track** — Record what was sent for session deduplication (CG7)

Both MCP tools (`drift_context`, `drift_package_context`) call the same engine with different default parameters. `drift_package_context` sets `scope: 'package'` and omits intent. `drift_context` sets intent and allows broader scope.

**Risks**: Large refactor touching the two most important MCP tools. Requires careful migration to avoid breaking existing agent workflows.
**Dependencies**: CG2, CG3, CG5, CG6


---

## CG2: Intent-Weighted Scoring

**Priority**: P0 (Critical)
**Effort**: Medium
**Impact**: Context relevance improves dramatically — right patterns for the right task
**Evidence**: Audit L4, R3 (Anthropic — "isolate and route"), R8 (OpenAI — "shaped by what the model needs"), R22 (Least Context principle)

**Current State**:
`drift_package_context` returns identical context regardless of what the AI agent is trying to do. `drift_context` has intent strategies but they're in a separate 1,500-line orchestrator that bypasses the generator.

**Proposed Change**:
Implement intent-weighted scoring in the unified engine. Each intent type defines weight multipliers for different data categories:

```
IntentWeights = {
  add_feature: {
    architectural_patterns: 1.5,
    entry_points: 1.3,
    conventions: 1.2,
    constraints: 1.0,
    security: 0.8,
    data_accessors: 0.7,
  },
  fix_bug: {
    error_patterns: 1.5,
    recent_changes: 1.3,
    constraints: 1.2,
    data_accessors: 1.1,
    entry_points: 0.9,
    conventions: 0.7,
  },
  security_review: {
    security_patterns: 2.0,
    data_accessors: 1.8,
    constraints: 1.5,
    entry_points: 1.0,
    conventions: 0.5,
    architectural_patterns: 0.5,
  },
  refactor: {
    architectural_patterns: 1.5,
    conventions: 1.3,
    coupling_patterns: 1.3,
    constraints: 1.0,
    entry_points: 0.8,
    data_accessors: 0.5,
  },
  understand: {
    // Balanced — all categories weighted equally at 1.0
    // This is the default when no intent is specified
  },
}
```

**Scoring formula**:
```
final_score(item) = base_relevance_score(item) × intent_weight(item.category, intent)
```

When no intent is provided (e.g., `drift_package_context`), all weights default to 1.0 — equivalent to the current behavior but with proper relevance scoring (CG3) instead of occurrence-based sorting.

**Risks**: Weight tuning requires iteration. Initial weights are heuristic — should be validated against golden dataset tests (CG18).
**Dependencies**: CG1 (unified engine), CG3 (base relevance scoring)


---

## CG3: Semantic Relevance Scoring

**Priority**: P0 (Critical)
**Effort**: High
**Impact**: Replaces occurrence-based sorting with actual relevance — the single biggest quality improvement
**Evidence**: Audit L7/L14, R1 (context rot — low similarity hurts), R4 (Cursor — 12.5% accuracy improvement from semantic search), R5 (Augment — 70.6% SWE-bench from context quality), R6 (NVIDIA — two-stage retrieval)

**Current State**:
Patterns sorted by `occurrences` descending. No relevance to the user's query or intent. A pattern that appears 50 times but is irrelevant to the current task ranks above a pattern that appears 3 times but is exactly what the agent needs.

**Proposed Change**:
Implement a composite relevance scoring system with two stages:

**Stage 1 — Fast Candidate Scoring** (all candidates):
```
base_score(item) = (
  confidence × 0.30 +
  category_match × 0.25 +
  file_proximity × 0.20 +
  recency × 0.15 +
  importance × 0.10
)
```

Where:
- `confidence`: Pattern/constraint confidence score (0.0-1.0)
- `category_match`: 1.0 if item category matches intent's priority categories, 0.5 otherwise
- `file_proximity`: Cosine similarity between item's file paths and the query's file context (if provided). Falls back to 0.5 if no file context.
- `recency`: `1.0 / (1.0 + days_since_last_update / 30.0)` — recently updated items score higher
- `importance`: Normalized occurrence count: `min(1.0, occurrences / max_occurrences)`

**Stage 2 — Semantic Re-Ranking** (top-K candidates, K=50):
When Cortex embeddings are available (CG8), compute embedding similarity between the query and each candidate's content:
```
reranked_score(item) = base_score(item) × 0.6 + embedding_similarity(query, item) × 0.4
```

When embeddings are unavailable, skip Stage 2 and use base_score directly. This is the graceful degradation path (CG16).

**Two-stage rationale** (R6): Stage 1 is O(N) with simple arithmetic — fast enough for all candidates. Stage 2 requires embedding lookups — only feasible for top-K. This mirrors NVIDIA's recommended bi-encoder → cross-encoder pipeline.

**Risks**: Embedding similarity requires Cortex integration (CG8). Without it, scoring is metadata-only — still better than occurrence sorting but less precise.
**Dependencies**: CG8 (Cortex integration for embeddings), CG2 (intent weights applied after base scoring)


---

## CG4: Layered Context Depth

**Priority**: P0 (Critical)
**Effort**: Medium
**Impact**: Implements progressive disclosure — agents get focused context first, details on demand
**Evidence**: R13 (Inkeep — attention budgets, progressive disclosure), R22 (Progressive Enrichment principle), R2 (LangChain — tiered compression), R18 (Agenta — intelligent truncation)

**Current State**:
Context generation produces a single monolithic output. Every request gets the same level of detail regardless of whether the agent needs a quick overview or a deep dive.

**Proposed Change**:
Introduce three context depth levels, selectable via `ContextRequest.depth`:

**Layer: overview (~2K tokens)**
```
Contents:
  - Package name, language, description
  - Top 5 patterns (name + one-line summary only)
  - Critical constraints (enforcement='error' only)
  - Key insight summary (3 bullets max)
  - Package dependency list (names only)

Use case: Initial orientation, quick reference, multi-package scanning
```

**Layer: standard (~6K tokens, default)**
```
Contents:
  - Everything in overview
  - Full pattern list (top 20 by relevance score, with confidence + occurrences)
  - All applicable constraints with guidance text
  - Top 10 entry points with types
  - Top 5 key files with pattern associations
  - Guidance section (insights, common patterns, warnings)
  - Cortex memories relevant to scope (top 5)

Use case: Most agent interactions — feature work, bug fixes, code review
```

**Layer: deep (~12K tokens)**
```
Contents:
  - Everything in standard
  - Code examples for top patterns (fenced blocks)
  - Data accessor details with table names and sensitivity flags
  - Dependency patterns from internal packages
  - Full entry point list (up to 50)
  - Extended Cortex memories (top 15)
  - File-level detail for key files (imports, exports, function signatures)

Use case: Deep investigation, security review, major refactoring
```

**Invariant**: `tokens(overview) < tokens(standard) < tokens(deep)`. Overview is always a strict subset of standard, which is a strict subset of deep. This is testable (CG18).

**Implementation**: The engine generates the deep layer internally, then filters down based on requested depth. This ensures consistency — overview never contains something that standard doesn't.

**Risks**: Agents may not know which depth to request. Default to `standard` and let the agent escalate to `deep` if needed.
**Dependencies**: CG1 (unified engine), CG6 (budget allocation per layer)


---

## CG5: Accurate BPE Token Counting

**Priority**: P0 (Critical)
**Effort**: Low
**Impact**: Eliminates 20-40% budget estimation error — prevents both truncation and waste
**Evidence**: Audit L3, R7 (tiktoken-rs, splintr, bpe crate — exact BPE counting in Rust)

**Current State**:
Token estimation uses `JSON.stringify(context).length × 0.25`. This character-based approximation can be off by 20-40% depending on content type. Code tokenizes differently than prose — identifiers, operators, and whitespace patterns produce different token counts than the 4-chars-per-token assumption.

**Proposed Change**:
Replace character-based estimation with actual BPE tokenization using Rust crates.

**Primary**: `tiktoken-rs` — exact match for OpenAI models (cl100k_base for GPT-4, o200k_base for GPT-4o).

**Alternative**: `bpe` crate — novel algorithms, faster than tiktoken for batch operations.

**High-performance option**: `splintr` — ~111 MB/s batch throughput vs ~9 MB/s for tiktoken (12x faster). Use for bulk operations like scanning all patterns.

**Model-aware counting**:
```
TokenCounter {
  // Select tokenizer based on consuming model
  fn count(text: &str, model: ModelFamily) -> usize

  // Cached counting — patterns/constraints don't change between requests
  fn count_cached(text: &str, content_hash: u64, model: ModelFamily) -> usize

  // Batch counting for multiple items
  fn count_batch(items: &[&str], model: ModelFamily) -> Vec<usize>
}

ModelFamily:
  - OpenAI (cl100k_base or o200k_base)
  - Anthropic (claude tokenizer)
  - Generic (cl100k_base fallback — reasonable approximation for most models)
```

**Cache strategy**: Store token counts per `(content_hash, model_family)` pair. Patterns and constraints are immutable between scans — their token counts can be pre-computed during indexing and stored in SQLite alongside the content. Only re-count when content changes (detected via hash).

**Fallback**: If no Rust tokenizer is available (e.g., pure TypeScript environment during migration), fall back to `js-tiktoken` or `gpt-tokenizer` npm packages. If those are unavailable, fall back to `length / 4` with a 20% safety margin (`length / 4 × 0.8` as effective budget).

**Risks**: Minimal — well-maintained crates with production usage. The main risk is model-specific tokenizer drift (new models with new tokenizers), mitigated by the Generic fallback.
**Dependencies**: Category 01 (Rust core — crate dependency)


---

## CG6: Intelligent Budget Allocation

**Priority**: P0 (Critical)
**Effort**: Medium
**Impact**: Replaces greedy section-cutting with proportional, relevance-aware trimming
**Evidence**: Audit L5, R1 (context rot — every token must earn its place), R13 (attention budgets), R18 (intelligent truncation)

**Current State**:
Greedy trimming cuts entire sections in priority order: dependencies first, then examples, then patterns, then key files, then entry points, then data accessors. This is crude — it can eliminate all code examples even when one critical example would be more valuable than 10 low-relevance patterns.

**Proposed Change**:
Implement proportional budget allocation with relevance-aware trimming.

**Step 1 — Section budget allocation**:
Allocate the total token budget across sections based on depth and intent:

```
Standard depth (6K tokens) default allocation:
  system_prompt:   600 tokens (10%)
  patterns:       2400 tokens (40%)
  constraints:     900 tokens (15%)
  entry_points:    600 tokens (10%)
  key_files:       600 tokens (10%)
  guidance:        600 tokens (10%)
  memories:        300 tokens (5%)
```

Intent modifies allocation. Example for `security_review`:
```
  system_prompt:   600 tokens (10%)
  patterns:       1800 tokens (30%)  — reduced
  constraints:    1200 tokens (20%)  — increased
  entry_points:    600 tokens (10%)
  key_files:       300 tokens (5%)   — reduced
  guidance:        600 tokens (10%)
  memories:        300 tokens (5%)
  data_accessors:  600 tokens (10%)  — added/increased
```

**Step 2 — Within-section trimming**:
Within each section, items are sorted by their relevance score (CG3). Trimming removes the lowest-scored items first. Items are never partially trimmed — either the full item fits or it's excluded.

**Step 3 — Redistribution**:
If a section uses fewer tokens than allocated (e.g., only 3 constraints exist, using 400 of 900 allocated tokens), the surplus is redistributed to the highest-demand section (typically patterns).

**Invariant**: `sum(section_budgets) <= total_budget`. No section budget is negative. Verified by property-based tests (CG18).

**Risks**: Allocation percentages are heuristic. Need golden dataset validation to tune.
**Dependencies**: CG5 (accurate token counting), CG3 (relevance scores for within-section trimming)


---

## CG7: Session-Aware Context Deduplication

**Priority**: P1 (Important)
**Effort**: Medium
**Impact**: 30-50% token reduction on follow-up requests within a session
**Evidence**: R8 (OpenAI — session memory, deduplication), R14 (Manus — compaction of stale results), R15 (LangChain — context isolation)

**Current State**:
Every `drift_context` or `drift_package_context` call generates full context from scratch. If an agent calls the tool 3 times in a conversation, it receives the same patterns 3 times, wasting tokens and contributing to context rot (R1).

**Proposed Change**:
Track what context has been delivered per session and deliver only deltas on subsequent requests.

**Session tracking**:
```
SessionContextTracker {
  session_id: SessionId,
  delivered: HashMap<ContentHash, DeliveredItem>,
  // DeliveredItem = { item_id, content_hash, delivered_at, depth }
}
```

**First request in session**: Full context generation (no deduplication).

**Subsequent requests in session**:
1. Generate full candidate list as normal
2. For each candidate, check if `content_hash` exists in `delivered`
3. If delivered AND content hasn't changed: replace with compact reference
   ```
   [Previously delivered: pattern "api-error-handling" — see turn 1]
   ```
4. If delivered BUT content changed (new scan since delivery): include full item with `[Updated]` marker
5. If not delivered: include full item

**Session lifecycle**: Sessions expire after 30 minutes of inactivity. Session state is in-memory only (not persisted to SQLite) — it's cheap to regenerate.

**Different intent in same session**: If the agent changes intent (e.g., from `understand` to `fix_bug`), items that were delivered but are now higher-priority get re-delivered with the new intent's context framing. Items that were delivered and are now lower-priority get compacted.

**Token savings estimate**: Based on typical agent workflows (3-5 context requests per session), expect 30-50% token reduction on requests 2+.

**Risks**: Session tracking adds memory overhead. Mitigated by 30-minute expiry and in-memory-only storage.
**Dependencies**: CG1 (unified engine — session tracking integrated into pipeline step 7)

---

## CG8: Cortex Memory Integration

**Priority**: P1 (Important)
**Effort**: Medium
**Impact**: Enriches context with tribal knowledge, decisions, and rationale — currently missing from package context
**Evidence**: Audit L15, R3 (Anthropic — "extract high-quality memories"), R19 (Particula — four-layer memory architecture), R11 (ACE — evolving playbook)

**Current State**:
`drift_context` (intent-aware path) integrates Cortex memories. `drift_package_context` does not. After unification (CG1), the engine needs a clean integration point for Cortex.

**Proposed Change**:
Add a Cortex retrieval step to the unified pipeline, between "Gather candidates" and "Score":

```
Pipeline: Resolve scope -> Gather candidates -> [Retrieve memories] -> Score -> Rank -> Budget -> Format -> Track
```

**Memory retrieval query**:
```
CortexQuery {
  scope: package_name or file_paths,
  intent: current_intent,
  types: [semantic, tribal, decision],  // Memory types to retrieve
  limit: depth_based,                    // overview=3, standard=5, deep=15
  min_confidence: 0.5,
  exclude_archived: true,
}
```

**Memory integration into context**:
Memories are treated as a separate section in the AI context output:
```
## Tribal Knowledge & Decisions

- [decision] Always use idempotency keys for payment API calls (confidence: 0.92)
  Files: src/payments/api.ts, src/checkout/service.ts

- [tribal] The legacy auth module has a race condition under high load — use the new AuthV2 service
  Files: src/auth/legacy.ts, src/auth/v2.ts

- [convention] Team prefers explicit error types over generic Error throws
```

**Scoring integration**: Cortex memories participate in the same relevance scoring as patterns and constraints (CG3). Memory confidence maps to the `confidence` component. Memory importance maps to the `importance` component. Memory recency uses `last_accessed_at` instead of `updated_at`.

**Fallback**: If Cortex is unavailable (not initialized, database locked, etc.), skip the memory retrieval step entirely. Context generation works without memories — they're an enrichment, not a requirement (CG16).

**Risks**: Cortex retrieval adds latency (~5-50ms depending on memory count). Mitigated by the fast retrieval path (FTS5 + sqlite-vec, per Cortex CX1).
**Dependencies**: Cortex CX1 (hybrid search), Cortex CX2 (code-specific embeddings)


---

## CG9: Extended Package Manager Support

**Priority**: P1 (Important)
**Effort**: Low
**Impact**: Supports modern runtimes (Bun, Deno) and additional ecosystems (Swift, Kotlin)
**Evidence**: Audit D1 (11-language detection is a differentiator), R10 (Bun/Deno workspace support, package_manager_detector_rs)

**Current State**:
PackageDetector supports 11 package managers: npm, pnpm, yarn, pip, poetry, cargo, go, maven, gradle, composer, nuget. Missing: Bun, Deno, Swift Package Manager, Kotlin/Gradle KTS (distinct from Java Gradle).

**Proposed Change**:
Add 4 new package manager detectors:

| # | Manager | Detection File | Language | Workspace Support |
|---|---------|---------------|----------|-------------------|
| 12 | Bun | `bun.lockb` or `bun.lock` | TS/JS | `package.json` workspaces (same as npm) |
| 13 | Deno | `deno.json` / `deno.jsonc` + `deno.lock` | TS/JS | `deno.json` → `workspace` field |
| 14 | Swift PM | `Package.swift` | Swift | `Package.swift` → `dependencies` + targets |
| 15 | Kotlin | `build.gradle.kts` + `settings.gradle.kts` | Kotlin | `include` statements (same as Gradle but `.kts`) |

**Detection order update**:
Insert Bun after yarn (position 4) — detected by `bun.lockb`/`bun.lock` presence.
Insert Deno after Bun (position 5) — detected by `deno.json`/`deno.jsonc`.
Swift and Kotlin added before the root package fallback.

**Rust implementation consideration**: Use `package_manager_detector_rs` crate as a reference for lock file detection heuristics. Don't take a hard dependency — Drift's detector does more (workspace detection, dependency extraction) than the crate provides.

**Risks**: Minimal — additive change. Existing detectors unaffected.
**Dependencies**: None — can be implemented independently.

---

## CG10: Package Dependency Graph

**Priority**: P1 (Important)
**Effort**: Medium
**Impact**: Enables cross-package context, affected-package analysis, and smarter dependency pattern loading
**Evidence**: R9 (Nx — project graph, affected analysis), R5 (Augment — semantic dependency graphs), R17 (knowledge graphs for issue resolution)

**Current State**:
PackageDetector detects packages and extracts `internalDependencies` (cross-referenced against workspace package names). But this data is flat — there's no graph structure. Dependency pattern loading (pipeline step 8) loads patterns from direct dependencies only, with no transitive awareness.

**Proposed Change**:
Build a `PackageDependencyGraph` from detected packages:

```
PackageDependencyGraph {
  nodes: HashMap<PackageName, PackageNode>,
  edges: Vec<DependencyEdge>,
}

PackageNode {
  package: DetectedPackage,
  depth: usize,  // Distance from root
}

DependencyEdge {
  from: PackageName,
  to: PackageName,
  dep_type: DependencyType,  // direct | dev | peer | transitive
}
```

**Use cases enabled**:

1. **Cross-package context**: When generating context for package A, include patterns from packages A depends on, weighted by dependency distance:
   ```
   dep_weight(distance) = 1.0 / (1.0 + distance)
   // Direct dep: 0.5, transitive (depth 2): 0.33, etc.
   ```

2. **Affected context invalidation**: When patterns change in a shared library, invalidate cached context for all dependent packages (Nx-style affected analysis).

3. **Multi-package context**: For cross-cutting changes, generate context spanning multiple related packages by walking the dependency graph.

**Graph construction**: Built during package detection (cached alongside `MonorepoStructure`). Updated when packages are re-detected. Stored in-memory — the graph is small (typically <100 nodes) and fast to rebuild.

**Risks**: Circular dependencies in package graphs (A depends on B depends on A). Handle by detecting cycles during graph construction and breaking them at the `dev` dependency edge.
**Dependencies**: Category 04 (call graph — package-level edges could feed into this graph)


---

## CG11: SQLite-Backed Data Access

**Priority**: P0 (Critical)
**Effort**: Medium
**Impact**: Eliminates JSON file I/O bottleneck, enables transactional reads, concurrent access, and query-level filtering
**Evidence**: Audit L2, R4 (Cursor — indexed retrieval), R12 (DeepCode — structured indexing)

**Current State**:
Every context generation request reads 4+ directories of JSON files:
- `.drift/patterns/approved/*.json` + `.drift/patterns/discovered/*.json`
- `.drift/constraints/approved/*.json` + `.drift/constraints/discovered/*.json`
- `.drift/lake/callgraph/files/*.json`
- `.drift/lake/security/tables/*.json`

This is the primary performance bottleneck. On cold cache, a medium project (20 packages) takes ~300ms just for file I/O. No transactional consistency — files can change mid-read.

**Proposed Change**:
Replace all JSON file reads with SQLite queries against `drift.db`:

```sql
-- Patterns for a package (replaces readdir + readFile + JSON.parse × N)
SELECT id, name, category, confidence, occurrences, example, files
FROM patterns
WHERE package_scope = ?
  AND status IN ('approved', 'discovered')
  AND confidence >= ?
ORDER BY confidence DESC, occurrences DESC;

-- Constraints for a package
SELECT id, name, category, enforcement, condition, guidance
FROM constraints
WHERE package_scope = ?
  AND status IN ('approved', 'discovered');

-- Entry points for a package
SELECT name, file, type, method, path
FROM functions
WHERE package_path LIKE ?
  AND type IN ('api_endpoint', 'event_handler', 'cli_command')
LIMIT 50;

-- Data accessors for a package
SELECT name, file, tables, accesses_sensitive
FROM data_access_points
WHERE package_path LIKE ?
LIMIT 30;
```

**Performance impact**:
- JSON file I/O (20 packages): ~300ms → SQLite indexed queries: ~5ms
- Transactional consistency: all data from a single snapshot
- Concurrent reads: multiple context requests can run simultaneously (WAL mode)
- Query-level filtering: confidence threshold, category filter, and limit applied at the database level — no need to load everything and filter in memory

**Index requirements**:
```sql
CREATE INDEX idx_patterns_package ON patterns(package_scope, status, confidence);
CREATE INDEX idx_constraints_package ON constraints(package_scope, status);
CREATE INDEX idx_functions_package_type ON functions(package_path, type);
CREATE INDEX idx_data_access_package ON data_access_points(package_path);
```

**Migration path**: During the transition period, support both JSON and SQLite backends behind a `DataAccessor` trait. The trait has two implementations: `JsonFileAccessor` (v1 compatibility) and `SqliteAccessor` (v2). The unified engine (CG1) uses the trait, unaware of the backend.

**Risks**: Requires all upstream categories (detectors, call graph, security) to write to SQLite. This is already planned as part of the v2 storage migration (Category 08).
**Dependencies**: Category 08 (storage — SQLite schema), Category 24 (data lake — materialized views)

---

## CG12: Model-Aware Context Formatting

**Priority**: P1 (Important)
**Effort**: Low
**Impact**: Optimizes context structure for different AI model families
**Evidence**: R21 (Phil Schmid — format matters, XML tags vs markdown), R2 (LangChain — model profiles), R7 (model-specific tokenizers)

**Current State**:
`formatForAI()` produces a single format: markdown-style text with `---` separators. All AI agents receive the same format regardless of which model they're using.

**Proposed Change**:
Support multiple output formats optimized for different model families:

**Format: markdown (default)**
```markdown
## Package: auth-service (TypeScript)
15 patterns | 8 constraints | 12 entry points

## Conventions
1. **api-error-handling** (confidence: 0.95, seen 23 times)
   Always use structured error responses with error codes...

## Constraints
- [ERROR] Never store plaintext passwords — use bcrypt with cost factor 12+
...
```

**Format: xml (optimized for Claude)**
```xml
<context package="auth-service" language="typescript">
  <patterns count="15">
    <pattern name="api-error-handling" confidence="0.95" occurrences="23">
      Always use structured error responses with error codes...
    </pattern>
  </patterns>
  <constraints count="8">
    <constraint enforcement="error" name="no-plaintext-passwords">
      Never store plaintext passwords — use bcrypt with cost factor 12+
    </constraint>
  </constraints>
</context>
```

**Format: json (structured, for programmatic consumption)**
```json
{
  "package": "auth-service",
  "language": "typescript",
  "patterns": [...],
  "constraints": [...],
  "entryPoints": [...],
  "metadata": { "tokens": 5200, "depth": "standard", "intent": "fix_bug" }
}
```

**Model detection**: The MCP protocol doesn't expose which model the client is using. Instead, allow the format to be specified in the tool call parameters. Default to `markdown`. Agents that know they're running on Claude can request `xml`.

**Risks**: Minimal — additive feature. Markdown remains the default.
**Dependencies**: CG1 (unified engine — format selection in pipeline step 6)


---

## CG13: Freshness Indicators

**Priority**: P1 (Important)
**Effort**: Low
**Impact**: Agents know how stale context data is — prevents acting on outdated information
**Evidence**: R20 (Comet — freshness matters, stale context can be worse than no context), R22 (Context Versioning principle)

**Current State**:
Context output includes `metadata.generatedAt` but no information about when the underlying data was last updated. An agent has no way to know if the patterns it's seeing are from a scan 5 minutes ago or 5 days ago.

**Proposed Change**:
Add freshness metadata to context output at multiple levels:

**Context-level freshness**:
```
metadata: {
  generatedAt: "2026-02-06T14:30:00Z",
  dataFreshness: {
    patterns: { lastScanAt: "2026-02-06T14:00:00Z", ageMinutes: 30 },
    constraints: { lastScanAt: "2026-02-06T14:00:00Z", ageMinutes: 30 },
    callGraph: { lastScanAt: "2026-02-05T22:00:00Z", ageMinutes: 990 },
    security: { lastScanAt: "2026-02-04T10:00:00Z", ageMinutes: 2910 },
    cortexMemories: { lastAccessAt: "2026-02-06T14:25:00Z", ageMinutes: 5 },
  },
  staleness: "partial",  // fresh | partial | stale
}
```

**Staleness classification**:
- `fresh`: All data sources updated within 1 hour
- `partial`: Some data sources updated within 1 hour, others older
- `stale`: All data sources older than 24 hours

**Item-level freshness** (optional, for `deep` depth):
Each pattern/constraint includes `lastUpdatedAt` so agents can assess individual item freshness.

**Guidance integration**: When data is stale, add a warning to the guidance section:
```
⚠️ Call graph data is 16 hours old. Recent code changes may not be reflected.
   Run `drift scan` to refresh.
```

**Risks**: Minimal — metadata-only addition. No impact on context content.
**Dependencies**: None — can be implemented independently using existing scan timestamps.

---

## CG14: Incremental Context Invalidation

**Priority**: P1 (Important)
**Effort**: Medium
**Impact**: Only regenerates context sections affected by data changes — reduces redundant computation
**Evidence**: R4 (Cursor — Merkle tree change detection), R9 (Nx — affected analysis)

**Current State**:
No caching of context results. Every request regenerates everything from scratch. Even if only one pattern changed since the last request, the entire pipeline runs again.

**Proposed Change**:
Implement content-hash-based invalidation for context sections:

**Content hashing**:
```
SectionHash {
  patterns_hash: u64,      // Hash of all pattern IDs + content hashes in scope
  constraints_hash: u64,   // Hash of all constraint IDs + content hashes in scope
  entry_points_hash: u64,  // Hash of entry point data in scope
  data_accessors_hash: u64,// Hash of data accessor data in scope
  memories_hash: u64,      // Hash of Cortex memory IDs + confidence values
  composite_hash: u64,     // Combined hash of all sections
}
```

**Cache structure**:
```
ContextCache {
  key: (package_scope, intent, depth, composite_hash),
  value: GeneratedContext,
  created_at: Instant,
  ttl: Duration,  // 5 minutes default
}
```

**Invalidation flow**:
1. Before generating context, compute `SectionHash` for the current request scope
2. Check cache for matching `(scope, intent, depth, composite_hash)`
3. If cache hit: return cached context immediately
4. If cache miss: generate fresh context, store in cache

**Partial invalidation**: If only `patterns_hash` changed but other hashes match, regenerate only the patterns section and merge with cached sections. This is an optimization — full regeneration is the safe fallback.

**Cache eviction**: LRU with 100-entry cap. TTL of 5 minutes ensures freshness. Cache is in-memory only — not persisted across restarts.

**Risks**: Cache coherence — if upstream data changes between hash computation and context generation, the cache could serve stale data. Mitigated by short TTL (5 minutes) and hash-based keys (any data change produces a different hash).
**Dependencies**: CG11 (SQLite access — content hashes available from database)


---

## CG15: Context Quality Feedback Loop

**Priority**: P2 (Nice to have)
**Effort**: High
**Impact**: Context generation improves over time based on actual agent outcomes
**Evidence**: R11 (ACE — self-improving context), R20 (Comet — governance, track what helped)

**Current State**:
No feedback mechanism. Context generation has no way to know if the patterns it included were helpful or if the agent needed something that was trimmed.

**Proposed Change**:
Implement an optional feedback signal from AI agents back to the context engine:

**Feedback schema**:
```
ContextFeedback {
  context_id: ContextId,       // Links to the generated context
  session_id: SessionId,
  helpful_items: Vec<ItemId>,  // Patterns/constraints the agent found useful
  missing_items: Vec<String>,  // Free-text: what the agent wished it had
  outcome: Outcome,            // success | partial | failure
  timestamp: DateTime,
}
```

**Feedback integration**:
- Items marked `helpful` get a relevance boost in future scoring (CG3): `boost = 0.1 × helpful_count`
- Items consistently NOT marked helpful (delivered 10+ times, never marked helpful) get a relevance penalty: `penalty = -0.05`
- `missing_items` are logged for human review — they may indicate gaps in pattern detection or constraint coverage

**MCP tool**: Add a `drift_context_feedback` tool that agents can call after using context:
```
drift_context_feedback({
  context_id: "ctx_abc123",
  helpful: ["pattern-api-error-handling", "constraint-no-plaintext-passwords"],
  missing: ["I needed information about the rate limiting middleware"],
  outcome: "success"
})
```

**Privacy**: Feedback is stored locally in `drift.db`. No data leaves the user's machine. Feedback is per-project, not cross-project.

**Risks**: Agents may not provide feedback consistently. The system must work well without any feedback (feedback is a bonus, not a requirement). Risk of feedback gaming — an agent could mark everything as helpful. Mitigated by requiring `outcome` to correlate with actual task completion.
**Dependencies**: CG1 (unified engine — context_id tracking), CG3 (relevance scoring — feedback modifies scores)

---

## CG16: Graceful Degradation

**Priority**: P0 (Critical)
**Effort**: Medium
**Impact**: Context generation never fails completely — always produces useful output
**Evidence**: R22 (Graceful Degradation principle), Cortex CX18 (degradation matrix pattern)

**Current State**:
Basic try/catch error handling. If pattern loading fails, the entire context generation fails. No structured degradation.

**Proposed Change**:
Define fallback behavior for every component that can fail. Context generation should always produce output — degraded quality is better than no context.

**Degradation Matrix**:

| Component | Failure Mode | Fallback | User Impact |
|---|---|---|---|
| SQLite database | Connection failure or corruption | Fall back to JSON file reads (v1 path) if available. If both fail, return minimal context with package info only. | Reduced data freshness, slower I/O. |
| Pattern loading | No patterns found or query error | Return context without patterns section. Add guidance warning: "Pattern data unavailable — run drift scan." | Agent misses conventions but gets constraints, entry points, etc. |
| Constraint loading | Query error | Return context without constraints section. Add guidance warning. | Agent misses constraints but gets patterns, entry points, etc. |
| Call graph data | Missing or corrupt | Return context without entry points. Add guidance warning. | Agent misses entry points but gets patterns, constraints. |
| Security data | Missing or corrupt | Return context without data accessors. Add guidance warning. | Agent misses security info but gets everything else. |
| Cortex memories | Cortex unavailable | Skip memory retrieval entirely. No warning needed — memories are enrichment. | Context works without tribal knowledge. |
| Token counting | Tokenizer unavailable | Fall back to character estimation with 20% safety margin. | Budget slightly less accurate but functional. |
| Package detection | No packages detected | Use root directory as single package. | Context scoped to entire repo instead of package. |
| Semantic scoring | Embeddings unavailable | Use metadata-only scoring (CG3 Stage 1 only). | Ranking less precise but still relevance-based. |
| Session tracking | Session state lost | Generate full context (no deduplication). | Slightly more tokens but correct content. |

**Implementation pattern**: Each pipeline step returns `Result<T, ContextWarning>` where `ContextWarning` is non-fatal. Warnings accumulate and are included in the context output's guidance section. The pipeline continues through all steps regardless of individual failures.

```rust
struct PipelineResult<T> {
    data: T,
    warnings: Vec<ContextWarning>,
}

enum ContextWarning {
    DataSourceUnavailable { source: &'static str, reason: String },
    FallbackUsed { component: &'static str, fallback: &'static str },
    DataStale { source: &'static str, age_minutes: u64 },
}
```

Every degradation is logged and surfaced in context output.

**Risks**: Minimal — strictly improves reliability.
**Dependencies**: None


---

## CG17: Strategic Content Ordering

**Priority**: P1 (Important)
**Effort**: Low
**Impact**: Improves AI attention allocation to the most important items
**Evidence**: R6 (NVIDIA — primacy-recency effect, "lost in the middle"), R1 (context rot — position matters)

**Current State**:
Patterns sorted by occurrences descending. No strategic ordering of sections or items within sections. Items in the middle of the context receive less attention from transformer models (the "lost in the middle" problem documented in R6).

**Proposed Change**:
Apply primacy-recency ordering to maximize AI attention on the most important items:

**Item ordering within sections**:
```
Position 1 (first):     Highest relevance score item
Position 2 (second):    Third highest relevance score
...
Position N-1 (second-to-last): Fourth highest relevance score
Position N (last):       Second highest relevance score
```

The most relevant item goes first (primacy). The second-most relevant goes last (recency). Everything else fills the middle in descending order. This ensures the two most important items occupy the positions that receive the most attention.

**Section ordering** (within the combined context output):
```
1. System prompt (always first — sets the frame)
2. Critical constraints (enforcement='error' — must not be missed)
3. Top patterns (highest relevance — the core conventions)
4. Entry points (structural orientation)
5. Guidance (insights, common patterns, warnings)
6. Key files (reference material)
7. Examples (supplementary — can be skimmed)
8. Cortex memories (enrichment — most recent/relevant last for recency)
```

**Risks**: Minimal — ordering change only. Content unchanged.
**Dependencies**: CG3 (relevance scores determine ordering)

---

## CG18: Testing Strategy

**Priority**: P0 (Critical)
**Effort**: Medium
**Impact**: Proves correctness across all configurations — prevents regressions
**Evidence**: Cortex CX17 (multi-layer testing pattern)

**Layer 1 — Property-Based Tests (proptest)**:

Every subsystem has invariants that must hold for all inputs:

| Subsystem | Properties |
|---|---|
| Token counting | `count(a + b) <= count(a) + count(b) + 1`. `count("") == 0`. Cached count equals uncached count. |
| Budget allocation | `sum(section_budgets) <= total_budget`. No section budget is negative. Redistribution never exceeds total. |
| Trimming | `output_tokens <= maxTokens`. Higher-scored items survive over lower-scored items. Trimming is deterministic. |
| Relevance scoring | `score` in `[0.0, 2.0]` (base max 1.0 × intent weight max 2.0). Intent weight changes ranking order. Same inputs produce same scores. |
| Package detection | Deterministic — same filesystem produces same packages. Root fallback always returns >= 1 package. |
| Session dedup | Second request tokens < first request tokens (same scope, same session). Third request tokens <= second request tokens. |
| Layered context | `tokens(overview) < tokens(standard) < tokens(deep)`. Overview is a subset of standard. Standard is a subset of deep. |
| Freshness | `staleness` classification is consistent with individual source ages. `fresh` implies all sources < 1 hour. |
| Degradation | Every component failure produces a `ContextWarning`, not a panic. Output is always non-empty. |

**Layer 2 — Golden Dataset Tests**:

Curated test fixtures with known expected outputs:

- 5 package detection scenarios: npm monorepo, Python poetry workspace, Go modules, mixed polyglot, single package root fallback
- 5 context generation scenarios: one per intent type (`add_feature`, `fix_bug`, `understand`, `refactor`, `security_review`) with known expected top patterns for each
- 3 trimming scenarios: over budget by 10%, 50%, 200% — verify correct items survive
- 3 session deduplication scenarios: first request (full), follow-up same intent (delta), follow-up different intent (re-prioritized)
- 3 depth scenarios: overview, standard, deep for the same package — verify subset relationships

Golden datasets live in `crates/context/test-fixtures/` and are version-controlled.

**Layer 3 — Performance Benchmarks (criterion)**:

| Benchmark | Target |
|---|---|
| Package detection (20 packages) | < 100ms |
| Context generation (standard depth, 50 patterns) | < 50ms |
| Token counting (10KB context) | < 1ms |
| Relevance scoring (100 candidates) | < 5ms |
| Semantic re-ranking (50 candidates) | < 20ms |
| SQLite query (patterns for 1 package) | < 2ms |
| Full pipeline (detect + generate + format) | < 100ms |

Benchmarks run in CI. Regressions > 20% fail the build.

**Layer 4 — Integration Tests**:

- Full pipeline: detect packages → generate context → verify token budget → verify format correctness
- Multi-intent: generate context for same package with different intents → verify different top patterns
- Session flow: 3 sequential requests → verify deduplication → verify token savings
- Degradation: disable each data source one at a time → verify context still generates with appropriate warnings
- Cross-package: generate context spanning 2 dependent packages → verify dependency patterns included


---

## Summary

### Priority Distribution

| Priority | Count | Recommendations |
|----------|-------|-----------------|
| P0 (Critical) | 9 | CG1, CG2, CG3, CG4, CG5, CG6, CG11, CG16, CG18 |
| P1 (Important) | 8 | CG7, CG8, CG9, CG10, CG12, CG13, CG14, CG17 |
| P2 (Nice to have) | 1 | CG15 |

### Implementation Order

**Phase 1 — Foundation** (no dependencies, can be built independently):
- CG5 (accurate token counting)
- CG11 (SQLite data access)
- CG16 (graceful degradation)
- CG9 (new package managers)

**Phase 2 — Core Engine** (the main architectural work):
- CG1 (unified context engine)
- CG2 (intent-weighted scoring)
- CG3 (semantic relevance scoring)
- CG4 (layered context depth)
- CG6 (intelligent budget allocation)

**Phase 3 — Enrichment** (builds on the core engine):
- CG8 (Cortex memory integration)
- CG10 (package dependency graph)
- CG12 (model-aware formatting)
- CG13 (freshness indicators)
- CG17 (strategic content ordering)

**Phase 4 — Optimization** (performance and efficiency):
- CG7 (session-aware deduplication)
- CG14 (incremental context invalidation)

**Phase 5 — Learning** (feedback-driven improvement):
- CG15 (context quality feedback loop)

**Phase 0 — Continuous** (runs throughout all phases):
- CG18 (testing — property-based tests written alongside each recommendation's implementation, golden datasets after Phase 2, benchmarks after Phase 3)

### Cross-Category Dependencies

| Recommendation | Depends On |
|----------------|------------|
| CG3 (semantic scoring) | Cortex CX2 (embedding model) |
| CG8 (Cortex integration) | Cortex CX1 (hybrid search) |
| CG11 (SQLite access) | Category 08 (storage), Category 24 (data lake) |
| CG5 (token counting) | Category 01 (Rust core — crate dependency) |
| CG10 (dependency graph) | Category 04 (call graph — package-level edges) |

### Key Metrics for Success

1. **Context relevance**: 80%+ patterns rated helpful by AI agents (measured via CG15 feedback, when available)
2. **Token efficiency**: >70% useful tokens ratio (tokens that contribute to task completion vs total tokens delivered)
3. **Generation latency**: <50ms for standard depth on a medium project (20 packages, 50 patterns)
4. **Budget accuracy**: <5% error between estimated and actual token count (currently 20-40% with character estimation)
5. **Session savings**: 30-50% token reduction on follow-up requests within a session
6. **Degradation coverage**: 100% of failure modes have defined fallback behavior — zero unhandled panics in context generation