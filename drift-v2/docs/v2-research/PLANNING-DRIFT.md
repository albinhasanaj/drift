# Drift + Cortex Integration — Planning Document

> Running stash of all decisions made during R&D planning conversations.
> This is the source of truth for architectural direction before implementation specs are written.
> Last updated: 2026-02-07

---

## Foundational Principle

Cortex and Drift are two standalone systems that live in the same repo but have zero dependency on each other unless the user opts into both. When both are present, a bridge crate provides the integration layer.

---

## Decision 1: Standalone Independence

**Status: AGREED**

- Cortex works by itself. No Drift dependency. Full memory system experience.
- Drift works by itself. No Cortex dependency. Full scanning/indexing/MCP experience without memory.
- When both are present, shared logic lives in a bridge crate — neither system imports from the other directly.

---

## Decision 2: Memory Types Stay in cortex-core, Links Become Generic

**Status: AGREED**

- All 23 memory types remain in cortex-core. They're general-purpose categories, not Drift-specific.
  - `pattern_rationale`, `decision_context`, `constraint_override` work for any system with patterns/decisions/constraints.
  - `code_smell` could be renamed to `anti_pattern` for generality.
- The Drift-specific **linking types** (`PatternLink`, `ConstraintLink`, `FunctionLink`) move behind a feature flag or into the bridge crate.
- cortex-core gets a generic `EntityLink` system:
  ```rust
  pub struct EntityLink {
      pub entity_type: String,      // "pattern", "constraint", "function", "jira_ticket", etc.
      pub entity_id: String,
      pub metadata: serde_json::Value,
      pub strength: f64,
  }
  ```
- The bridge crate provides typed convenience wrappers that produce `EntityLink` values with known `entity_type` strings (e.g., `PatternLink` → `EntityLink { entity_type: "drift_pattern", ... }`).
- `FileLink` with citations (line_start, line_end, content_hash) stays in cortex-core — it's useful for any code-aware system, not Drift-specific.

---

## Decision 3: Separate MCP Servers

**Status: AGREED**

- Cortex has its own MCP server with `cortex_*` namespaced tools.
- Drift has its own MCP server with `drift_*` namespaced tools.
- If you're not using one system, you don't burn ~5-8K tokens loading its tool definitions into the context window.
- MCP clients (Claude, Cursor, etc.) already support multiple servers. The AI sees a unified tool list regardless.
- Each server should have a "meta-tool" that reduces individual tool calls:
  - Drift: `drift_context` (already exists — one call replaces 3-5 discovery calls)
  - Cortex: `cortex_context` (to be designed — one call for "give me everything relevant")
- Expected total: ~75+ tools across both servers once complete.

### Bridge Tools (When Both Systems Present)

- The Drift MCP server detects if Cortex is available at startup.
- If yes, it conditionally registers bridge tools (`drift_why`, `drift_memory_learn`, etc.) that need both systems.
- If no, those tools simply don't appear.
- This keeps it to two servers (not three) while enabling the combined experience.

---

## Decision 4: Bridge Crate Architecture (Not Feature Flags)

**Status: AGREED**

- A dedicated `cortex-drift-bridge` crate handles all integration.
- No scattered `#[cfg(feature = "drift-integration")]` across 19 crates.
- The bridge crate is the ONLY place that imports from both `cortex-core` and `drift-core`.

### Repo Structure

```
crates/
├── cortex/                    # Cortex standalone (the brain)
│   ├── cortex-core/           # Pure types, traits, errors (NO Drift knowledge)
│   ├── cortex-storage/        # SQLite persistence
│   ├── cortex-embeddings/     # Embedding providers
│   ├── cortex-causal/         # Causal reasoning
│   ├── cortex-retrieval/      # Hybrid search, ranking
│   ├── cortex-temporal/       # Temporal reasoning
│   ├── cortex-*/              # All other crates...
│   └── cortex-napi/           # NAPI bindings (standalone)
│
├── drift/                     # Drift standalone (the scanner)
│   ├── drift-core/            # Parsers, call graph, boundaries
│   └── drift-napi/            # NAPI bindings
│
└── cortex-drift/              # The bridge (optional, depends on both)
    ├── cortex-drift-bridge/   # Event mapping, link translation, intent extension
    ├── cortex-drift-napi/     # Combined NAPI bindings
    └── cortex-drift-mcp/      # Combined MCP tools (drift_why, drift_memory_*)
```

### Bridge Crate Responsibilities

1. **Event mapping**: Drift events → Cortex memories (e.g., `pattern:approved` → `pattern_rationale` memory)
2. **Link translation**: Drift `PatternLink` → Cortex `EntityLink`
3. **Grounding logic**: Compare Cortex memories against Drift scan results for validation
4. **Combined MCP tools**: Tools that need both systems (drift_why, drift_memory_learn)
5. **Intent extensions**: Code-specific intents (add_feature, fix_bug, refactor, etc.) registered as extensions to Cortex's intent system
6. **Grounding feedback loop**: The killer integration (see Decision 7)

### Analogy

Like `serde` (standalone) → `serde_json` (bridge to JSON) → `serde_yaml` (bridge to YAML). `serde` itself knows nothing about JSON. Cortex itself knows nothing about Drift.

---

## Decision 5: Trait-Based Event System

**Status: AGREED**

- In-process trait-based event bus with typed events. Not a message queue (overkill), not raw EventEmitter (too loose).
- Default method implementations are no-ops — handlers only implement what they care about.

### Cortex Side

```rust
// In cortex-core
pub trait CortexEventHandler: Send + Sync {
    fn on_memory_created(&self, memory: &BaseMemory) {}
    fn on_memory_updated(&self, memory: &BaseMemory, changes: &MemoryDiff) {}
    fn on_memory_archived(&self, memory_id: &str) {}
    fn on_consolidation_complete(&self, result: &ConsolidationResult) {}
    fn on_contradiction_detected(&self, contradiction: &Contradiction) {}
    // ... etc
}
```

- Cortex holds a `Vec<Arc<dyn CortexEventHandler>>`.
- When something happens, it iterates and calls handlers.
- If no handlers registered (standalone mode), zero overhead.

### Drift Side

```rust
// In drift-core
pub trait DriftEventHandler: Send + Sync {
    fn on_pattern_approved(&self, pattern: &Pattern) {}
    fn on_scan_complete(&self, results: &ScanResults) {}
    fn on_regression_detected(&self, regression: &Regression) {}
    // ... etc
}
```

### Bridge Implements Both

```rust
// In cortex-drift-bridge
struct DriftEventHandler { cortex_client: CortexClient }
impl DriftEventHandler for ... {
    fn on_pattern_approved(&self, pattern: &Pattern) {
        // Create a pattern_rationale memory in Cortex
    }
    fn on_scan_complete(&self, results: &ScanResults) {
        // Ground-truth validate Cortex memories against scan results
    }
}

struct CortexEventHandlerImpl { drift_client: DriftClient }
impl CortexEventHandler for ... {
    fn on_memory_created(&self, memory: &BaseMemory) {
        // If memory is linked to files, tell Drift to check those files
    }
}
```

---

## Decision 6: Separate Databases with ATTACH for Cross-DB Queries

**Status: AGREED**

- `cortex.db` — owned by Cortex, full read/write
- `drift.db` — owned by Drift, full read/write
- Either can exist without the other. Deleting one doesn't break the other.

### Cross-DB Query Strategy

- SQLite `ATTACH DATABASE` used when both are present.
- Cortex optionally ATTACHes `drift.db` as **read-only** when bridge is active.
- Drift optionally ATTACHes `cortex.db` as **read-only** when bridge is active.
- Cross-DB queries are **always reads**. Writes go to the owning database only.

### Performance Characteristics (Verified)

- **ATTACH itself**: ~1ms, done once at startup. Negligible.
- **Cross-DB reads**: Same speed as same-DB reads. SQLite treats attached databases as additional schemas. Query planner optimizes across them. Indexes work across the boundary.
- **Cross-DB writes**: NOT supported in a single transaction (each DB has its own WAL). Not needed — each system writes to its own DB.
- **Memory mapping**: Both databases mmap'd independently (256MB each). Hot data from both lives in memory.

### sqlite-vec Consideration

- `sqlite-vec` extension is loaded per-connection.
- If Drift's connections ATTACH cortex.db and need vector search, they'd need sqlite-vec loaded too.
- For simple joins (memory metadata, links, confidence scores), no extension needed.
- Recommendation: Drift connections do NOT load sqlite-vec. If Drift needs vector search results from Cortex, it goes through the bridge crate's API, not raw SQL.

### Graceful Degradation

- If `drift.db` doesn't exist, Cortex's ATTACH fails gracefully and cross-DB queries return empty results.
- If `cortex.db` doesn't exist, Drift's ATTACH fails gracefully and bridge tools don't register.

---

## Decision 7: Grounding Feedback Loop (The Killer Feature)

**Status: AGREED — Needs full spec**

This is the most valuable piece of the integration. No other AI memory system has this.

### The Loop

1. Cortex stores a memory: "Team uses repository pattern for data access"
2. Drift scans the codebase and independently finds: 87% of data access uses repository pattern
3. Bridge compares: memory is 87% grounded (high confidence justified)
4. Later, team refactors away from repository pattern
5. Drift's next scan: only 45% repository pattern now
6. Bridge detects drift: memory confidence should decrease, or memory should be flagged for review
7. Cortex's validation engine picks this up and either heals the memory or creates a contradiction

### Why This Matters

- First AI memory system with **empirically validated memory** — beliefs checked against ground truth
- Critical for early-stage algorithm tuning — you can measure precision/recall of the memory system against actual codebase state
- The feedback loop enables self-correcting memory without human intervention
- Drift scanning becomes grounding for project-stored memory, ensuring the system learns and heals properly

### Needs Specced

- Exact grounding metrics (how to compare a memory's claims against scan results)
- Confidence adjustment formulas (how much to boost/penalize based on grounding)
- Which memory types are groundable (pattern_rationale yes, episodic probably not)
- Frequency of grounding checks (every scan? scheduled? on-demand?)
- How contradictions from grounding differ from contradictions from other sources

---

## Open Questions (Not Yet Decided)

### Q1: Cortex Intent System Extensibility
- The 7 domain-agnostic intents (create, investigate, decide, recall, learn, summarize, compare) stay in cortex-core.
- The 3 universal intents (spawn_agent, execute_workflow, track_progress) stay in cortex-core.
- The 8 code-specific intents (add_feature, fix_bug, refactor, etc.) — do these stay in cortex-core or move to the bridge?
- Leaning: Keep them in cortex-core. They're useful for any code-aware memory system, not just Drift.

### Q2: Cortex MCP Tool Design
- Need to design the `cortex_*` tool namespace for standalone Cortex.
- The 33 existing tools are `drift_memory_*` prefixed — need renaming.
- Need to design `cortex_context` meta-tool.

### Q3: Drift MCP Server — Cortex Detection
- How does the Drift MCP server detect Cortex availability at startup?
- Options: check for cortex.db file, try to load NAPI bindings, config flag
- Leaning: Config flag with auto-detection fallback.

### Q4: Bridge Crate — Build/Package Strategy
- How is the bridge crate distributed? Always built? Conditionally compiled?
- If someone installs "just Drift," does the bridge crate exist but do nothing?
- Or is it a separate optional install?

### Q5: Migration Path for Existing Cortex
- Current cortex-core has Drift-specific types baked in.
- What's the migration path to generic EntityLink?
- How do existing cortex.db databases migrate?

---

## Context: What Each System Is

### Cortex (The Brain)
19-crate Rust workspace. Persistent AI memory system with:
- 23 typed memories with confidence scoring and bitemporal tracking
- Causal inference graphs with narrative generation
- Multi-factor decay with type-specific half-lives
- HDBSCAN-based consolidation (episodic → semantic)
- 4-dimension validation with automatic healing
- Contradiction detection and propagation
- Temporal reasoning with point-in-time reconstruction and decision replay
- Multi-agent memory sharing via CRDTs (research phase)
- Adaptive topology with self-organizing knowledge graphs (research phase)
- Hybrid retrieval (FTS5 + sqlite-vec + RRF fusion)
- 3-tier embedding cache (L1 in-memory, L2 SQLite, L3 precomputed)
- ONNX-based local embedding generation (Jina Code v2, 1024-dim)

### Drift (The Scanner)
Codebase convention discovery and indexing system with:
- Tree-sitter AST parsing across 10 languages
- 350+ detectors across 16 categories discovering conventions
- Statistical confidence scoring (frequency, consistency, age, spread)
- Call graph with reachability and impact analysis
- Data boundary detection (28+ ORMs, sensitive field classification)
- Quality gates for CI/CD enforcement
- 50+ MCP tools for AI consumption
- Offline indexing + online querying architecture
- v2 vision: all analysis in Rust, TS as thin orchestration layer

### The Bridge (The Glue)
When both are present:
- Drift scanning grounds Cortex memories against codebase reality
- Cortex provides living memory that replaces static AGENTS.md
- Combined tools like `drift_why` synthesize pattern data + causal memory
- Event-driven: Drift events create/validate Cortex memories automatically
- Grounding feedback loop enables empirically validated AI memory
