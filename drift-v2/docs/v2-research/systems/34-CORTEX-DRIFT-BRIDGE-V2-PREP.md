# Cortex-Drift Bridge (Event Mapping, Grounding Loop) — V2 Implementation Prep

> Comprehensive build specification for the cortex-drift-bridge crate — the optional
> integration layer that connects Drift's static analysis engine to Cortex's persistent
> memory system, enabling empirically validated AI memory through event-driven memory
> creation and the grounding feedback loop.
>
> Synthesized from: PLANNING-DRIFT.md (D1-D7 — all 7 foundational decisions),
> DRIFT-V2-STACK-HIERARCHY.md (Level 5B Bridge-Dependent Presentation),
> DRIFT-V2-FULL-SYSTEM-AUDIT.md (Cross-Cutting: Bridge section, AD9, P1),
> 04-INFRASTRUCTURE-V2-PREP.md (§4 DriftEventHandler trait, Bridge Event Mapping table),
> 03-NAPI-BRIDGE-V2-PREP.md (§4 Singleton Runtime, §5 NAPI boundary principle, §10 Function
> Registry — template for this document's structure),
> 02-STORAGE-V2-PREP.md (drift.db schema, ATTACH pattern, WAL mode),
> 31-VIOLATION-FEEDBACK-LOOP-V2-PREP.md (§22 Cortex Bridge Integration, feedback→memory
> mapping, grounding loop consumption),
> 20-CONSTRAINT-SYSTEM-V2-PREP.md (§12.4 Cortex Bridge Integration, constraint→memory),
> 29-DECISION-MINING-V2-PREP.md (§17 decision→memory, §21 event mapping),
> 19-COUPLING-ANALYSIS-V2-PREP.md (§23 Cortex Grounding D7, coupling snapshot),
> 07-BOUNDARY-DETECTION-V2-PREP.md (Bridge Consumption, boundary→memory),
> 32-MCP-SERVER-V2-PREP.md (§3 Bridge Tools, drift_why/drift_memory_learn/drift_grounding_check),
> 09-QUALITY-GATES-V2-PREP.md (gate evaluation events),
> 25-AUDIT-SYSTEM-V2-PREP.md (health score integration),
> 13-LEARNING-SYSTEM-V2-PREP.md (convention feedback integration),
> 24-DNA-SYSTEM-V2-PREP.md (DNA health as grounding signal),
> 12-PATTERN-AGGREGATION-V2-PREP.md (pattern lifecycle events),
> cortex-core/src/memory/ (23 MemoryType variants, BaseMemory, TypedContent, links),
> cortex-core/src/traits/ (ICausalStorage, IRetriever, ILearner, ICompressor),
> cortex-core/src/models/ (EntityLink per D2),
> 06-cortex/validation.md (4-dimension validation engine, healing strategies),
> 06-cortex/overview.md (Cortex architecture, memory lifecycle),
> Sadowski et al. "Lessons from Building Static Analysis Tools at Google" (CACM 2018),
> Semgrep Assistant Memories (2025 — AI-powered FP triage with organizational memory),
> EverMemOS (2026 — self-organizing memory OS, episodic→semantic consolidation),
> RTInsights "Why Agentic AI Needs Event-Driven Architecture" (Jan 2026),
> Unite.AI "From LLM Commoditization to the Age of Agentic Memory" (Jan 2026).
>
> Purpose: Everything needed to build cortex-drift-bridge from scratch. All 6 bridge
> responsibilities fully specified. All event mappings defined. Grounding feedback loop
> algorithm complete. All Rust types defined. All integration points documented. Every
> architectural decision resolved. Zero feature loss. The killer integration feature
> of the entire Drift+Cortex product — empirically validated AI memory.
> Generated: 2026-02-08

---

## Table of Contents

1. Architectural Position
2. Foundational Decisions Summary (D1-D7)
3. V1 Feature Inventory — Complete Preservation Matrix
4. V2 Architecture — Bridge Crate Design
5. Core Data Model (Rust Types)
6. Responsibility 1: Event Mapping (Drift Events → Cortex Memories)
7. Responsibility 2: Link Translation (PatternLink → EntityLink)
8. Responsibility 3: Grounding Logic (Memory Validation Against Scan Results)
9. Responsibility 4: Grounding Feedback Loop (The Killer Feature)
10. Responsibility 5: Intent Extensions (Code-Specific Intents)
11. Responsibility 6: Combined MCP Tools (drift_why, drift_memory_learn, drift_grounding_check)
12. Database Integration (ATTACH Pattern, Cross-DB Queries)
13. DriftEventHandler Implementation (Bridge Side)
14. CortexEventHandler Implementation (Bridge Side)
15. Grounding Metrics & Confidence Adjustment Algorithms
16. Groundability Classification (Which Memory Types Are Groundable)
17. Grounding Scheduling & Frequency
18. Contradiction Generation from Grounding
19. Error Handling & Graceful Degradation
20. Bridge Runtime & Initialization
21. NAPI Bridge Interface (cortex-drift-napi)
22. Configuration (drift.toml [bridge] Section)
23. License Gating — Tier Mapping
24. Observability & Tracing
25. Integration with Upstream Systems (All Event Sources)
26. Integration with Downstream Consumers
27. Storage Schema (Bridge-Specific Tables)
28. Performance Targets & Benchmarks
29. File / Module Structure
30. Build Order & Dependency Chain
31. Resolved Inconsistencies
32. V1 Feature Verification — Complete Gap Analysis
33. Research Grounding — External Sources

---

## 1. Architectural Position

The cortex-drift-bridge is Level 5B (Bridge-Dependent Presentation) in Drift's stack
hierarchy. It is structurally optional but strategically critical — the single most
valuable feature of the Drift+Cortex integration. No other AI memory system has
empirically validated memory where beliefs are checked against ground truth.

Per PLANNING-DRIFT.md D1: Drift is standalone. Cortex is standalone. Neither imports
from the other. The bridge is the ONLY crate that imports from both.

Per PLANNING-DRIFT.md D4: Bridge crate is a leaf, not a spine. Nothing in Drift or
Cortex depends on it. It depends on both drift-core and cortex-core.

Per DRIFT-V2-STACK-HIERARCHY.md:
> Bridge crate is a leaf, not a spine (D4) — cortex-drift-bridge depends on both
> drift-core and cortex-core but nothing in Drift depends on it. This makes the entire
> bridge + grounding loop (D7) a Level 5 system — high value, zero structural importance
> to Drift's own hierarchy.

Per DRIFT-V2-FULL-SYSTEM-AUDIT.md:
> cortex-drift-bridge (Rust) — Event mapping: Drift events → Cortex memories
> (pattern:approved → pattern_rationale memory). Link translation: Drift PatternLink →
> Cortex EntityLink. Grounding logic: Compare Cortex memories against Drift scan results.

### What Lives Here

- Event mapping engine (Drift events → Cortex memories, 20+ event types)
- Link translation layer (Drift-specific links → generic Cortex EntityLink)
- Grounding logic engine (compare memories against scan results)
- Grounding feedback loop (confidence adjustment, contradiction generation)
- Groundability classifier (which memory types can be empirically validated)
- Grounding scheduler (frequency, triggers, incremental grounding)
- Combined MCP tool handlers (drift_why, drift_memory_learn, drift_grounding_check)
- Intent extensions (code-specific intents for Cortex's intent system)
- Cross-DB query layer (ATTACH drift.db ↔ cortex.db)
- Bridge runtime initialization and lifecycle management
- Bridge-specific SQLite tables (grounding_results, grounding_history)
- Bridge-specific error types and graceful degradation
- Bridge-specific tracing spans and metrics

### What Does NOT Live Here

- Any Drift analysis logic (lives in drift-core)
- Any Cortex memory logic (lives in cortex-core and other cortex-* crates)
- DriftEventHandler trait definition (lives in drift-core, per D5)
- CortexEventHandler trait definition (lives in cortex-core)
- drift.db schema/migrations (lives in drift-core storage)
- cortex.db schema/migrations (lives in cortex-core storage)
- MCP server infrastructure (lives in packages/mcp)
- CLI commands (lives in packages/cli)
- NAPI bridge for Drift standalone (lives in drift-napi)
- NAPI bridge for Cortex standalone (lives in cortex-napi)

### Upstream Dependencies (What Bridge Consumes)

| System | Crate | What It Provides | How Bridge Uses It |
|--------|-------|-----------------|-------------------|
| DriftEventHandler | drift-core | Typed event trait with no-op defaults | Bridge implements this trait |
| CortexEventHandler | cortex-core | Typed event trait with no-op defaults | Bridge implements this trait |
| Pattern data | drift-core | Patterns, confidence, locations | Grounding comparison source |
| Violation data | drift-core | Violations, feedback, FP rates | Grounding validation signal |
| Call graph | drift-core | Function edges, reachability | Impact-aware grounding |
| Coupling data | drift-core | Module metrics, cycles, zones | Architecture grounding signal |
| DNA data | drift-core | Health scores, gene profiles | Codebase health grounding |
| Constraint data | drift-core | Active constraints, verification | Constraint grounding signal |
| Test topology | drift-core | Coverage data, test mappings | Test coverage grounding |
| BaseMemory | cortex-core | Memory struct, 23 types | Memory creation target |
| TypedContent | cortex-core | Content variants per type | Memory content creation |
| EntityLink | cortex-core | Generic entity linking | Link translation target |
| Validation engine | cortex-core | 4-dimension validation | Grounding feeds validation |
| Contradiction detection | cortex-core | Conflict identification | Grounding generates contradictions |
| drift.db | drift-core | SQLite database (ATTACH) | Read-only scan data source |
| cortex.db | cortex-core | SQLite database (ATTACH) | Read/write memory target |

### Downstream Consumers (What Depends on Bridge)

| System | What It Consumes | How It Uses Bridge |
|--------|-----------------|-------------------|
| drift-analysis MCP | Bridge tools (conditional) | drift_why, drift_memory_learn, drift_grounding_check |
| drift-memory MCP | Memory operations | Read/write Cortex memories with Drift context |
| cortex-drift-napi | Bridge NAPI functions | Exposes bridge to Node.js |
| cortex-drift-mcp | Combined MCP tools | Tools needing both systems |

---

## 2. Foundational Decisions Summary (D1-D7)

Every design choice in this document traces back to one of these 7 decisions from
PLANNING-DRIFT.md. Referenced throughout as D1-D7.

| Decision | Title | Impact on Bridge |
|----------|-------|-----------------|
| D1 | Standalone Independence | Bridge is optional. Neither system imports from the other. |
| D2 | Memory Types in cortex-core, Links Become Generic | Bridge translates Drift links → EntityLink |
| D3 | Separate MCP Servers | Bridge tools register conditionally on drift-analysis server |
| D4 | Bridge Crate Architecture (Not Feature Flags) | Single crate, only cross-import point |
| D5 | Trait-Based Event System | Bridge implements DriftEventHandler + CortexEventHandler |
| D6 | Separate Databases with ATTACH | Cross-DB reads via ATTACH, writes to owning DB only |
| D7 | Grounding Feedback Loop | The killer feature — empirically validated memory |

### D7 Elaboration (The Core Value Proposition)

From PLANNING-DRIFT.md D7:
> 1. Cortex stores a memory: "Team uses repository pattern for data access"
> 2. Drift scans the codebase and independently finds: 87% of data access uses repository pattern
> 3. Bridge compares: memory is 87% grounded (high confidence justified)
> 4. Later, team refactors away from repository pattern
> 5. Drift's next scan: only 45% repository pattern now
> 6. Bridge detects drift: memory confidence should decrease, or memory should be flagged for review
> 7. Cortex's validation engine picks this up and either heals the memory or creates a contradiction

This is the first AI memory system with empirically validated memory. No competitor has this.
The bridge crate is where this happens.

---

## 3. V1 Feature Inventory — Complete Preservation Matrix

The bridge crate is a v2 design artifact — it does not exist in v1. However, v1 has
scattered integration points between Cortex and Drift that must be preserved and unified.

### 3.1 V1 Integration Points (Scattered Across Codebase)

| v1 Feature | v1 Location | v2 Status | v2 Location |
|-----------|-------------|-----------|-------------|
| Pattern→memory creation | packages/cortex/ inline | **UNIFIED** — Bridge event handler | §6 |
| PatternLink type | cortex-core/src/memory/links.rs | **UPGRADED** — EntityLink translation | §7 |
| ConstraintLink type | cortex-core/src/memory/links.rs | **UPGRADED** — EntityLink translation | §7 |
| FunctionLink type | cortex-core/src/memory/links.rs | **KEPT** — stays in cortex-core (generic) | §7 |
| FileLink type | cortex-core/src/memory/links.rs | **KEPT** — stays in cortex-core (generic) | §7 |
| PatternRationaleContent | cortex-core/src/memory/types/ | **KEPT** — bridge creates these | §6 |
| ConstraintOverrideContent | cortex-core/src/memory/types/ | **KEPT** — bridge creates these | §6 |
| DecisionContextContent | cortex-core/src/memory/types/ | **KEPT** — bridge creates these | §6 |
| CodeSmellContent | cortex-core/src/memory/types/ | **KEPT** — bridge creates these | §6 |
| drift_why MCP tool | packages/mcp/ | **UPGRADED** — conditional bridge tool | §11 |
| Memory-pattern linking | packages/cortex/ | **UPGRADED** — EntityLink system | §7 |
| Validation engine | packages/cortex/src/validation/ | **UPGRADED** — grounding feeds validation | §9 |
| Citation validation | packages/cortex/src/validation/ | **UPGRADED** — grounding enhances staleness | §9 |
| Pattern alignment check | packages/cortex/src/validation/ | **UPGRADED** — grounding replaces heuristic | §9 |

### 3.2 New V2 Features (Not in V1)

| Feature | Why New | Section |
|---------|---------|---------|
| Grounding feedback loop | D7 — the killer feature | §9 |
| Grounding confidence adjustment | Empirical memory validation | §15 |
| Groundability classification | Not all memories are groundable | §16 |
| Grounding scheduling | Frequency and trigger management | §17 |
| Contradiction from grounding | Grounding detects memory drift | §18 |
| drift_grounding_check MCP tool | Explicit grounding validation | §11 |
| drift_memory_learn MCP tool | Learn from Drift corrections | §11 |
| EntityLink translation | D2 — generic linking system | §7 |
| CortexEventHandler bridge impl | Bidirectional event flow | §14 |
| Cross-DB ATTACH queries | D6 — separate databases | §12 |
| Bridge-specific SQLite tables | Grounding history persistence | §27 |
| Intent extensions | Code-specific intents for Cortex | §10 |
| Event-driven memory creation | D5 — 20+ event types mapped | §6 |

---

## 4. V2 Architecture — Bridge Crate Design

### 4.1 Crate Position in Workspace

```
crates/
├── cortex/                    # Cortex standalone (19 crates)
│   ├── cortex-core/           # Types, traits, errors (NO Drift knowledge)
│   ├── cortex-storage/        # SQLite persistence
│   ├── cortex-embeddings/     # Embedding providers
│   └── cortex-napi/           # NAPI bindings (standalone)
│
├── drift/                     # Drift standalone
│   ├── drift-core/            # ALL analysis in Rust
│   └── drift-napi/            # NAPI bindings (standalone)
│
└── cortex-drift/              # The bridge (optional, depends on both)
    ├── cortex-drift-bridge/   # THIS CRATE — event mapping, grounding, links
    ├── cortex-drift-napi/     # Combined NAPI bindings
    └── cortex-drift-mcp/      # Combined MCP tools (TS)
```

### 4.2 Cargo.toml

```toml
[package]
name = "cortex-drift-bridge"
version = "0.1.0"
edition = "2021"
description = "Integration bridge between Cortex memory and Drift analysis"

[dependencies]
# Both systems — this is the ONLY crate that imports both
cortex-core = { path = "../../cortex/cortex-core" }
drift-core = { path = "../../drift/drift-core" }

# Storage (for cross-DB ATTACH queries)
rusqlite = { version = "0.31", features = ["bundled", "column_decltype"] }

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# Error handling (per AD6)
thiserror = "1"

# Observability (per AD10)
tracing = "0.1"

# Time handling
chrono = { version = "0.4", features = ["serde"] }

# Hashing for content comparison
xxhash-rust = { version = "0.8", features = ["xxh3"] }
blake3 = "1"

# UUID generation for grounding result IDs
uuid = { version = "1", features = ["v4"] }
```

### 4.3 Design Principles

1. **Leaf, not spine** — Nothing depends on this crate. It depends on both systems.
2. **Event-driven** — All integration flows through trait implementations, not polling.
3. **Read from drift.db, write to cortex.db** — Never write to drift.db from bridge.
4. **Graceful degradation** — If either system is unavailable, bridge degrades silently.
5. **Zero overhead when inactive** — If bridge is not initialized, no cost to either system.
6. **Synchronous dispatch** — Event handlers are synchronous (per D5). No async runtime.
7. **Idempotent operations** — Re-processing the same event produces the same result.


---

## 5. Core Data Model (Rust Types)

### 5.1 Bridge Error Types (per AD6)

```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum BridgeError {
    #[error("Cortex unavailable: {reason}")]
    CortexUnavailable { reason: String },

    #[error("Drift unavailable: {reason}")]
    DriftUnavailable { reason: String },

    #[error("ATTACH failed for {db_path}: {source}")]
    AttachFailed {
        db_path: String,
        source: rusqlite::Error,
    },

    #[error("Grounding failed for memory {memory_id}: {reason}")]
    GroundingFailed { memory_id: String, reason: String },

    #[error("Event mapping failed: {event_type} → {memory_type}: {reason}")]
    EventMappingFailed {
        event_type: String,
        memory_type: String,
        reason: String,
    },

    #[error("Link translation failed: {source_type} → EntityLink: {reason}")]
    LinkTranslationFailed {
        source_type: String,
        reason: String,
    },

    #[error("Cross-DB query failed: {query}: {source}")]
    CrossDbQueryFailed {
        query: String,
        source: rusqlite::Error,
    },

    #[error("Memory creation failed: {memory_type}: {reason}")]
    MemoryCreationFailed {
        memory_type: String,
        reason: String,
    },

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Storage error: {0}")]
    Storage(#[from] rusqlite::Error),

    #[error("Cortex error: {0}")]
    Cortex(#[from] cortex_core::CortexError),
}

pub type BridgeResult<T> = Result<T, BridgeError>;
```

### 5.2 Grounding Types

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Result of grounding a single memory against Drift scan data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroundingResult {
    /// Unique ID for this grounding check.
    pub id: String,
    /// The memory being grounded.
    pub memory_id: String,
    /// Memory type (for filtering/reporting).
    pub memory_type: cortex_core::MemoryType,
    /// The grounding verdict.
    pub verdict: GroundingVerdict,
    /// Grounding score: 0.0 (completely ungrounded) to 1.0 (fully grounded).
    pub grounding_score: f64,
    /// Previous grounding score (for trend detection).
    pub previous_score: Option<f64>,
    /// Score delta (current - previous). Negative = drifting.
    pub score_delta: Option<f64>,
    /// Confidence adjustment to apply to the memory.
    pub confidence_adjustment: ConfidenceAdjustment,
    /// Evidence supporting the grounding verdict.
    pub evidence: Vec<GroundingEvidence>,
    /// Which Drift data sources were consulted.
    pub data_sources: Vec<GroundingDataSource>,
    /// Whether a contradiction should be generated.
    pub generates_contradiction: bool,
    /// Timestamp of this grounding check.
    pub checked_at: DateTime<Utc>,
    /// Duration of the grounding check in milliseconds.
    pub duration_ms: u32,
}

/// Grounding verdict — the outcome of comparing memory against reality.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GroundingVerdict {
    /// Memory is strongly supported by Drift data (score >= 0.7).
    Validated,
    /// Memory is partially supported (0.4 <= score < 0.7).
    Partial,
    /// Memory is weakly supported (0.2 <= score < 0.4).
    Weak,
    /// Memory is contradicted by Drift data (score < 0.2).
    Invalidated,
    /// Memory type is not groundable (episodic, preference, etc.).
    NotGroundable,
    /// Insufficient Drift data to ground this memory.
    InsufficientData,
    /// Grounding check failed (error during comparison).
    Error,
}

/// How to adjust memory confidence based on grounding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceAdjustment {
    /// The adjustment mode.
    pub mode: AdjustmentMode,
    /// The target confidence value (for Set mode).
    pub target_value: Option<f64>,
    /// The delta to apply (for Boost/Penalize mode).
    pub delta: Option<f64>,
    /// Reason for the adjustment.
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdjustmentMode {
    /// No change — memory is well-grounded.
    NoChange,
    /// Boost confidence — memory is better grounded than expected.
    Boost,
    /// Penalize confidence — memory is less grounded than expected.
    Penalize,
    /// Set to specific value — strong grounding signal overrides.
    Set,
    /// Flag for review — grounding is ambiguous.
    FlagForReview,
}

/// Evidence supporting a grounding verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroundingEvidence {
    /// What type of evidence this is.
    pub evidence_type: EvidenceType,
    /// Human-readable description.
    pub description: String,
    /// The Drift data point (e.g., pattern confidence, FP rate).
    pub drift_value: f64,
    /// The Cortex memory claim (e.g., expected confidence).
    pub memory_claim: Option<f64>,
    /// How strongly this evidence supports/contradicts the memory.
    pub weight: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceType {
    /// Pattern confidence from Drift's Bayesian scoring.
    PatternConfidence,
    /// Pattern occurrence rate (% of files matching).
    PatternOccurrence,
    /// False positive rate from violation feedback.
    FalsePositiveRate,
    /// Constraint verification result.
    ConstraintVerification,
    /// Coupling metric snapshot.
    CouplingMetric,
    /// DNA health score.
    DnaHealth,
    /// Test coverage data.
    TestCoverage,
    /// Error handling gap count.
    ErrorHandlingGaps,
    /// Decision mining evidence.
    DecisionEvidence,
    /// Boundary detection data.
    BoundaryData,
}

/// Which Drift data source was consulted for grounding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GroundingDataSource {
    Patterns,
    Violations,
    ViolationFeedback,
    Constraints,
    CallGraph,
    Coupling,
    Dna,
    TestTopology,
    ErrorHandling,
    Boundaries,
    Decisions,
    Secrets,
}

/// Snapshot of grounding state across all groundable memories.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroundingSnapshot {
    /// Total memories checked.
    pub total_checked: u32,
    /// Memories validated (score >= 0.7).
    pub validated: u32,
    /// Memories partially grounded (0.4-0.7).
    pub partial: u32,
    /// Memories weakly grounded (0.2-0.4).
    pub weak: u32,
    /// Memories invalidated (score < 0.2).
    pub invalidated: u32,
    /// Memories not groundable.
    pub not_groundable: u32,
    /// Memories with insufficient data.
    pub insufficient_data: u32,
    /// Average grounding score across all groundable memories.
    pub avg_grounding_score: f64,
    /// Memories that generated contradictions.
    pub contradictions_generated: u32,
    /// Memories flagged for review.
    pub flagged_for_review: u32,
    /// Timestamp of this snapshot.
    pub checked_at: DateTime<Utc>,
    /// Total duration in milliseconds.
    pub duration_ms: u32,
}
```

### 5.3 Event Mapping Types

```rust
/// Configuration for how a Drift event maps to a Cortex memory.
#[derive(Debug, Clone)]
pub struct EventMapping {
    /// The Drift event type (e.g., "on_pattern_approved").
    pub event_type: &'static str,
    /// The target Cortex memory type.
    pub memory_type: cortex_core::MemoryType,
    /// Initial confidence for the created memory.
    pub initial_confidence: f64,
    /// Importance level for the created memory.
    pub importance: cortex_core::Importance,
    /// Whether this mapping is enabled by default.
    pub enabled_by_default: bool,
    /// Description for logging/debugging.
    pub description: &'static str,
}

/// Result of processing a Drift event through the bridge.
#[derive(Debug, Clone)]
pub struct EventProcessingResult {
    /// The event that was processed.
    pub event_type: String,
    /// Whether a memory was created.
    pub memory_created: bool,
    /// The created memory ID (if any).
    pub memory_id: Option<String>,
    /// The memory type (if created).
    pub memory_type: Option<cortex_core::MemoryType>,
    /// Any links created.
    pub links_created: Vec<String>,
    /// Processing duration in microseconds.
    pub duration_us: u64,
    /// Error (if processing failed but was non-fatal).
    pub error: Option<String>,
}
```

### 5.4 Link Translation Types

```rust
/// Generic entity link (per D2 — lives in cortex-core).
/// Bridge creates these from Drift-specific link types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityLink {
    pub entity_type: String,
    pub entity_id: String,
    pub metadata: serde_json::Value,
    pub strength: f64,
}

/// Convenience constructors for bridge-created EntityLinks.
impl EntityLink {
    /// Create from a Drift PatternLink.
    pub fn from_pattern(pattern_id: &str, pattern_name: &str, confidence: f64) -> Self {
        Self {
            entity_type: "drift_pattern".to_string(),
            entity_id: pattern_id.to_string(),
            metadata: serde_json::json!({
                "pattern_name": pattern_name,
                "source": "drift",
            }),
            strength: confidence,
        }
    }

    /// Create from a Drift ConstraintLink.
    pub fn from_constraint(constraint_id: &str, constraint_name: &str) -> Self {
        Self {
            entity_type: "drift_constraint".to_string(),
            entity_id: constraint_id.to_string(),
            metadata: serde_json::json!({
                "constraint_name": constraint_name,
                "source": "drift",
            }),
            strength: 1.0,
        }
    }

    /// Create from a Drift detector reference.
    pub fn from_detector(detector_id: &str, category: &str) -> Self {
        Self {
            entity_type: "drift_detector".to_string(),
            entity_id: detector_id.to_string(),
            metadata: serde_json::json!({
                "category": category,
                "source": "drift",
            }),
            strength: 1.0,
        }
    }

    /// Create from a Drift coupling module reference.
    pub fn from_module(module_path: &str, instability: f64) -> Self {
        Self {
            entity_type: "drift_module".to_string(),
            entity_id: module_path.to_string(),
            metadata: serde_json::json!({
                "instability": instability,
                "source": "drift",
            }),
            strength: 1.0 - instability, // More stable = stronger link
        }
    }

    /// Create from a Drift decision reference.
    pub fn from_decision(decision_id: &str, category: &str) -> Self {
        Self {
            entity_type: "drift_decision".to_string(),
            entity_id: decision_id.to_string(),
            metadata: serde_json::json!({
                "category": category,
                "source": "drift",
            }),
            strength: 1.0,
        }
    }
}
```


---

## 6. Responsibility 1: Event Mapping (Drift Events → Cortex Memories)

This is the bridge's primary function: when something happens in Drift, create a
corresponding memory in Cortex. The bridge implements `DriftEventHandler` and translates
each event into a `BaseMemory` with appropriate `TypedContent`, links, and metadata.

### 6.1 Complete Event Mapping Table

Every Drift event that creates a Cortex memory. Sourced from 04-INFRASTRUCTURE-V2-PREP.md §4,
31-VIOLATION-FEEDBACK-LOOP-V2-PREP.md §22, 20-CONSTRAINT-SYSTEM-V2-PREP.md §12.4,
29-DECISION-MINING-V2-PREP.md §21, 07-BOUNDARY-DETECTION-V2-PREP.md Bridge Consumption.

| # | Drift Event | Cortex Memory Type | Initial Confidence | Content Type | Description |
|---|------------|-------------------|-------------------|-------------|-------------|
| 1 | `on_pattern_approved` | `PatternRationale` | 0.8 | PatternRationaleContent | Pattern approved → why it exists |
| 2 | `on_pattern_discovered` | `Insight` | 0.5 | CoreContent | New pattern found (low confidence until approved) |
| 3 | `on_pattern_ignored` | `Feedback` | 0.6 | FeedbackContent | Pattern explicitly ignored (learning signal) |
| 4 | `on_pattern_merged` | `DecisionContext` | 0.7 | DecisionContextContent | Two patterns merged (architectural decision) |
| 5 | `on_scan_complete` | — (triggers grounding) | — | — | Does not create memory; triggers grounding loop |
| 6 | `on_regression_detected` | `DecisionContext` | 0.9 | DecisionContextContent | Regression → review memory with high confidence |
| 7 | `on_violation_detected` | — (no memory) | — | — | Too noisy; only dismissals/fixes create memories |
| 8 | `on_violation_dismissed` | `ConstraintOverride` | 0.7 | ConstraintOverrideContent | Dismissal reason → override memory |
| 9 | `on_violation_fixed` | `Feedback` | 0.8 | FeedbackContent | Fix confirms pattern validity (positive signal) |
| 10 | `on_gate_evaluated` | `DecisionContext` | 0.6 | DecisionContextContent | Gate pass/fail → enforcement decision record |
| 11 | `on_detector_alert` | `Tribal` | 0.6 | TribalContent | Detector health warning (institutional knowledge) |
| 12 | `on_detector_disabled` | `CodeSmell` | 0.9 | CodeSmellContent | Auto-disabled detector → anti-pattern signal |
| 13 | `on_constraint_approved` | `ConstraintOverride` | 0.8 | ConstraintOverrideContent | Constraint approved → enforcement memory |
| 14 | `on_constraint_violated` | `Feedback` | 0.7 | FeedbackContent | Constraint violation → review signal |
| 15 | `on_decision_mined` | `DecisionContext` | 0.7 | DecisionContextContent | Mined decision → ADR memory |
| 16 | `on_decision_reversed` | `DecisionContext` | 0.8 | DecisionContextContent | Decision reversal → linked to original |
| 17 | `on_adr_detected` | `DecisionContext` | 0.9 | DecisionContextContent | Detected ADR document → high confidence |
| 18 | `on_boundary_discovered` | `Tribal` | 0.6 | TribalContent | Data boundary → institutional knowledge |
| 19 | `on_enforcement_changed` | `DecisionContext` | 0.8 | DecisionContextContent | Enforcement mode transition |
| 20 | `on_feedback_abuse_detected` | `Tribal` | 0.7 | TribalContent | Abuse pattern → team knowledge |
| 21 | `on_error` | — (no memory) | — | — | Errors are logged, not memorized |

### 6.2 Event Handler Implementation

```rust
use cortex_core::{BaseMemory, MemoryType, TypedContent, Importance, Confidence};
use cortex_core::memory::types::*;
use cortex_core::memory::links::*;
use drift_core::events::*;
use tracing::{info, warn, instrument};

/// The bridge's implementation of DriftEventHandler.
/// Creates Cortex memories from Drift events.
pub struct BridgeEventHandler {
    /// Client for creating memories in Cortex.
    cortex_writer: CortexWriter,
    /// Configuration for event mapping.
    config: BridgeConfig,
    /// Metrics collector.
    metrics: BridgeMetrics,
}

impl DriftEventHandler for BridgeEventHandler {
    #[instrument(skip(self, pattern), fields(pattern_id = %pattern.id))]
    fn on_pattern_approved(&self, pattern: &Pattern) {
        if !self.config.event_mapping.pattern_approved {
            return;
        }

        let memory = BaseMemory {
            memory_type: MemoryType::PatternRationale,
            content: TypedContent::PatternRationale(PatternRationaleContent {
                pattern_name: pattern.name.clone(),
                rationale: format!(
                    "Pattern '{}' approved with {:.0}% confidence across {} files. \
                     Category: {}. {} occurrences detected.",
                    pattern.name,
                    pattern.confidence.score * 100.0,
                    pattern.confidence.file_count,
                    pattern.category,
                    pattern.confidence.conforming,
                ),
                business_context: format!(
                    "Detected by {} detector(s). Dominant convention in {} \
                     ({}% of relevant files).",
                    pattern.detector_ids.len(),
                    pattern.category,
                    (pattern.confidence.score * 100.0) as u32,
                ),
                examples: pattern.locations.iter()
                    .take(3)
                    .map(|loc| format!("{}:{}", loc.file, loc.line))
                    .collect(),
            }),
            summary: format!("Pattern: {} ({})", pattern.name, pattern.category),
            confidence: Confidence::new(0.8),
            importance: Importance::High,
            linked_patterns: vec![PatternLink {
                pattern_id: pattern.id.clone(),
                pattern_name: pattern.name.clone(),
            }],
            linked_files: pattern.locations.iter()
                .take(5)
                .map(|loc| FileLink {
                    file_path: loc.file.clone(),
                    line_start: Some(loc.line),
                    line_end: None,
                    content_hash: None,
                })
                .collect(),
            entity_links: vec![
                EntityLink::from_pattern(&pattern.id, &pattern.name, pattern.confidence.score),
            ],
            metadata: serde_json::json!({
                "source": "drift_bridge",
                "event": "pattern_approved",
                "drift_confidence": pattern.confidence.score,
                "drift_category": pattern.category,
                "drift_file_count": pattern.confidence.file_count,
            }),
            ..Default::default()
        };

        match self.cortex_writer.create_memory(memory) {
            Ok(id) => {
                info!(memory_id = %id, "Created pattern_rationale memory from pattern approval");
                self.metrics.record_event_mapped("on_pattern_approved", true);
            }
            Err(e) => {
                warn!(error = %e, "Failed to create memory from pattern approval");
                self.metrics.record_event_mapped("on_pattern_approved", false);
            }
        }
    }

    #[instrument(skip(self, results))]
    fn on_scan_complete(&self, results: &ScanDiff) {
        if !self.config.grounding.enabled {
            return;
        }

        // Scan complete triggers the grounding loop — not memory creation.
        // See §9 for the full grounding feedback loop.
        info!(
            added = results.added.len(),
            modified = results.modified.len(),
            removed = results.removed.len(),
            "Scan complete — triggering grounding loop"
        );

        if let Err(e) = self.trigger_grounding(results) {
            warn!(error = %e, "Grounding loop failed after scan complete");
        }
    }

    #[instrument(skip(self, regression))]
    fn on_regression_detected(&self, regression: &Regression) {
        if !self.config.event_mapping.regression_detected {
            return;
        }

        let memory = BaseMemory {
            memory_type: MemoryType::DecisionContext,
            content: TypedContent::DecisionContext(DecisionContextContent {
                decision: format!(
                    "Regression detected: pattern '{}' compliance dropped from \
                     {:.0}% to {:.0}%",
                    regression.pattern_name,
                    regression.previous_score * 100.0,
                    regression.current_score * 100.0,
                ),
                context: format!(
                    "Detected during scan at {}. {} files affected. \
                     This may indicate an intentional architectural change \
                     or an unintended drift from established conventions.",
                    regression.detected_at,
                    regression.affected_files.len(),
                ),
                adr_link: None,
                trade_offs: vec![
                    format!("Previous: {:.0}% compliance", regression.previous_score * 100.0),
                    format!("Current: {:.0}% compliance", regression.current_score * 100.0),
                    format!("Delta: {:.0}%", (regression.current_score - regression.previous_score) * 100.0),
                ],
            }),
            summary: format!("Regression: {} dropped to {:.0}%",
                regression.pattern_name, regression.current_score * 100.0),
            confidence: Confidence::new(0.9),
            importance: Importance::Critical,
            entity_links: vec![
                EntityLink::from_pattern(
                    &regression.pattern_id,
                    &regression.pattern_name,
                    regression.current_score,
                ),
            ],
            metadata: serde_json::json!({
                "source": "drift_bridge",
                "event": "regression_detected",
                "previous_score": regression.previous_score,
                "current_score": regression.current_score,
                "affected_files": regression.affected_files.len(),
            }),
            ..Default::default()
        };

        match self.cortex_writer.create_memory(memory) {
            Ok(id) => info!(memory_id = %id, "Created decision_context from regression"),
            Err(e) => warn!(error = %e, "Failed to create memory from regression"),
        }
    }

    #[instrument(skip(self, violation), fields(pattern_id = %violation.pattern_id))]
    fn on_violation_dismissed(&self, violation: &Violation, reason: &str) {
        if !self.config.event_mapping.violation_dismissed {
            return;
        }

        let memory = BaseMemory {
            memory_type: MemoryType::ConstraintOverride,
            content: TypedContent::ConstraintOverride(ConstraintOverrideContent {
                constraint_name: violation.pattern_id.clone(),
                override_reason: reason.to_string(),
                approved_by: String::new(), // Populated by caller if available
                scope: format!("{}:{}", violation.file, violation.line),
                expiry: None,
            }),
            summary: format!("Dismissed: {} in {}", violation.pattern_id, violation.file),
            confidence: Confidence::new(0.7),
            importance: Importance::Medium,
            linked_files: vec![FileLink {
                file_path: violation.file.clone(),
                line_start: Some(violation.line),
                line_end: None,
                content_hash: None,
            }],
            metadata: serde_json::json!({
                "source": "drift_bridge",
                "event": "violation_dismissed",
                "pattern_id": violation.pattern_id,
                "reason": reason,
                "severity": violation.severity,
            }),
            ..Default::default()
        };

        match self.cortex_writer.create_memory(memory) {
            Ok(id) => info!(memory_id = %id, "Created constraint_override from dismissal"),
            Err(e) => warn!(error = %e, "Failed to create memory from dismissal"),
        }
    }

    #[instrument(skip(self), fields(detector_id = %detector_id))]
    fn on_detector_disabled(&self, detector_id: &str, reason: &str) {
        if !self.config.event_mapping.detector_disabled {
            return;
        }

        let memory = BaseMemory {
            memory_type: MemoryType::CodeSmell,
            content: TypedContent::CodeSmell(CodeSmellContent {
                smell_name: format!("Auto-disabled detector: {}", detector_id),
                description: format!(
                    "Detector '{}' was auto-disabled: {}. Patterns from this \
                     detector should be treated with lower confidence.",
                    detector_id, reason
                ),
                bad_example: format!("Detector {} producing >20% false positives", detector_id),
                good_example: "Healthy detectors maintain <5% false positive rate".to_string(),
                severity: "high".to_string(),
            }),
            summary: format!("Detector disabled: {}", detector_id),
            confidence: Confidence::new(0.9),
            importance: Importance::High,
            entity_links: vec![
                EntityLink::from_detector(detector_id, "auto_disabled"),
            ],
            metadata: serde_json::json!({
                "source": "drift_bridge",
                "event": "detector_disabled",
                "detector_id": detector_id,
                "reason": reason,
            }),
            ..Default::default()
        };

        match self.cortex_writer.create_memory(memory) {
            Ok(id) => info!(memory_id = %id, "Created code_smell from detector disable"),
            Err(e) => warn!(error = %e, "Failed to create memory from detector disable"),
        }
    }

    // Remaining event handlers follow the same pattern.
    // Each maps to the table in §6.1 with appropriate TypedContent.
    // Events marked "no memory" in §6.1 are no-ops in the bridge handler.

    fn on_scan_started(&self, _root: &Path, _file_count: Option<usize>) {}
    fn on_scan_progress(&self, _processed: usize, _total: usize) {}
    fn on_scan_error(&self, _error: &ScanError) {}
    fn on_pattern_discovered(&self, pattern: &Pattern) {
        // Creates Insight memory with low confidence (0.5)
        // Only if config.event_mapping.pattern_discovered is true
        self.map_pattern_discovered(pattern);
    }
    fn on_pattern_ignored(&self, pattern: &Pattern) {
        self.map_pattern_ignored(pattern);
    }
    fn on_pattern_merged(&self, kept: &Pattern, merged: &Pattern) {
        self.map_pattern_merged(kept, merged);
    }
    fn on_violation_detected(&self, _violation: &Violation) {} // Too noisy
    fn on_violation_fixed(&self, violation: &Violation) {
        self.map_violation_fixed(violation);
    }
    fn on_gate_evaluated(&self, gate: &str, result: &GateResult) {
        self.map_gate_evaluated(gate, result);
    }
    fn on_detector_alert(&self, detector_id: &str, fp_rate: f64) {
        self.map_detector_alert(detector_id, fp_rate);
    }
    fn on_error(&self, _error: &PipelineError) {} // Logged, not memorized
}
```

### 6.3 Event Mapping Configuration

Each event mapping can be individually enabled/disabled in drift.toml:

```toml
[bridge.event_mapping]
# Which events create Cortex memories. All default to true.
pattern_approved = true
pattern_discovered = false  # Disabled by default (too noisy for large codebases)
pattern_ignored = true
pattern_merged = true
regression_detected = true
violation_dismissed = true
violation_fixed = true
gate_evaluated = false      # Disabled by default (frequent, low signal)
detector_alert = true
detector_disabled = true
constraint_approved = true
constraint_violated = true
decision_mined = true
decision_reversed = true
adr_detected = true
boundary_discovered = false # Disabled by default (high volume)
enforcement_changed = true
feedback_abuse_detected = true
```


---

## 7. Responsibility 2: Link Translation (PatternLink → EntityLink)

Per PLANNING-DRIFT.md D2: Memory types stay in cortex-core, but Drift-specific linking
types (PatternLink, ConstraintLink) move behind the bridge. cortex-core gets a generic
`EntityLink` system. The bridge provides typed convenience wrappers.

### 7.1 Translation Matrix

| Drift Link Type | EntityLink entity_type | Strength Derivation | Metadata |
|----------------|----------------------|--------------------|---------| 
| PatternLink | `drift_pattern` | Pattern confidence score | pattern_name, source |
| ConstraintLink | `drift_constraint` | 1.0 (binary: active or not) | constraint_name, source |
| FunctionLink | — (stays in cortex-core) | — | — |
| FileLink | — (stays in cortex-core) | — | — |
| Detector reference | `drift_detector` | 1.0 | category, source |
| Module reference | `drift_module` | 1.0 - instability | instability, source |
| Decision reference | `drift_decision` | 1.0 | category, source |
| Boundary reference | `drift_boundary` | Boundary confidence | framework, sensitivity |
| DNA gene reference | `drift_gene` | Gene health score | gene_type, source |

### 7.2 Translation Engine

```rust
/// Translates Drift-specific link types to generic Cortex EntityLinks.
pub struct LinkTranslator;

impl LinkTranslator {
    /// Translate a Drift PatternLink to a Cortex EntityLink.
    pub fn translate_pattern(link: &PatternLink, confidence: f64) -> EntityLink {
        EntityLink::from_pattern(&link.pattern_id, &link.pattern_name, confidence)
    }

    /// Translate a Drift ConstraintLink to a Cortex EntityLink.
    pub fn translate_constraint(link: &ConstraintLink) -> EntityLink {
        EntityLink::from_constraint(&link.constraint_id, &link.constraint_name)
    }

    /// Batch translate all links from a Drift entity to Cortex EntityLinks.
    pub fn translate_all(
        patterns: &[PatternLink],
        constraints: &[ConstraintLink],
        pattern_confidences: &std::collections::HashMap<String, f64>,
    ) -> Vec<EntityLink> {
        let mut links = Vec::with_capacity(patterns.len() + constraints.len());

        for p in patterns {
            let confidence = pattern_confidences
                .get(&p.pattern_id)
                .copied()
                .unwrap_or(0.5);
            links.push(Self::translate_pattern(p, confidence));
        }

        for c in constraints {
            links.push(Self::translate_constraint(c));
        }

        links
    }

    /// Create EntityLinks from Drift scan data for a specific file.
    /// Used when creating memories that reference Drift analysis results.
    pub fn links_for_file(
        file_path: &str,
        drift_db: &rusqlite::Connection,
    ) -> BridgeResult<Vec<EntityLink>> {
        let mut links = Vec::new();

        // Patterns affecting this file
        let mut stmt = drift_db.prepare(
            "SELECT p.id, p.name, p.confidence_score
             FROM patterns p
             JOIN pattern_locations pl ON p.id = pl.pattern_id
             WHERE pl.file_path = ?1
             AND p.status = 'approved'"
        )?;
        let pattern_links = stmt.query_map([file_path], |row| {
            Ok(EntityLink::from_pattern(
                &row.get::<_, String>(0)?,
                &row.get::<_, String>(1)?,
                row.get::<_, f64>(2)?,
            ))
        })?;
        for link in pattern_links {
            links.push(link?);
        }

        // Active constraints for this file
        let mut stmt = drift_db.prepare(
            "SELECT c.id, c.name
             FROM constraints c
             WHERE c.status = 'approved'
             AND (c.scope_files LIKE '%' || ?1 || '%'
                  OR c.scope_type = 'global')"
        )?;
        let constraint_links = stmt.query_map([file_path], |row| {
            Ok(EntityLink::from_constraint(
                &row.get::<_, String>(0)?,
                &row.get::<_, String>(1)?,
            ))
        })?;
        for link in constraint_links {
            links.push(link?);
        }

        Ok(links)
    }
}
```

### 7.3 Backward Compatibility

FileLink and FunctionLink stay in cortex-core — they're generic enough for any
code-aware system. The bridge does NOT translate these; it uses them directly when
creating memories with file/function references.

PatternLink and ConstraintLink structs also stay in cortex-core for backward
compatibility, but new bridge code should prefer EntityLink for all Drift-specific
references. The old link types are used only when populating the `linked_patterns`
and `linked_constraints` fields on BaseMemory (which cortex-core still expects).

---

## 8. Responsibility 3: Grounding Logic (Memory Validation Against Scan Results)

The grounding engine is the core algorithm that compares a Cortex memory's claims
against Drift's empirical scan data. This is the computational heart of D7.

### 8.1 Grounding Algorithm Overview

For each groundable memory:
1. Extract the memory's claims (what it asserts about the codebase)
2. Query drift.db for relevant empirical data
3. Compare claims against data using type-specific comparison functions
4. Compute a grounding score (0.0 to 1.0)
5. Determine verdict (Validated/Partial/Weak/Invalidated)
6. Calculate confidence adjustment
7. Generate contradiction if score dropped significantly

### 8.2 Grounding Engine

```rust
use tracing::{info, warn, instrument, info_span};

pub struct GroundingEngine {
    /// Read-only connection to drift.db (via ATTACH or direct open).
    drift_db: rusqlite::Connection,
    /// Read/write connection to cortex.db.
    cortex_db: rusqlite::Connection,
    /// Bridge-specific tables (grounding_results, grounding_history).
    bridge_db: rusqlite::Connection,
    /// Configuration.
    config: GroundingConfig,
    /// Metrics.
    metrics: BridgeMetrics,
}

impl GroundingEngine {
    /// Ground a single memory against Drift scan data.
    #[instrument(skip(self, memory), fields(memory_id = %memory.id, memory_type = ?memory.memory_type))]
    pub fn ground_memory(&self, memory: &BaseMemory) -> BridgeResult<GroundingResult> {
        let start = std::time::Instant::now();

        // Step 1: Check if this memory type is groundable
        let groundability = classify_groundability(&memory.memory_type);
        if groundability == Groundability::NotGroundable {
            return Ok(GroundingResult {
                id: uuid::Uuid::new_v4().to_string(),
                memory_id: memory.id.clone(),
                memory_type: memory.memory_type,
                verdict: GroundingVerdict::NotGroundable,
                grounding_score: 0.0,
                previous_score: None,
                score_delta: None,
                confidence_adjustment: ConfidenceAdjustment {
                    mode: AdjustmentMode::NoChange,
                    target_value: None,
                    delta: None,
                    reason: "Memory type is not groundable".to_string(),
                },
                evidence: vec![],
                data_sources: vec![],
                generates_contradiction: false,
                checked_at: Utc::now(),
                duration_ms: start.elapsed().as_millis() as u32,
            });
        }

        // Step 2: Get previous grounding score (for trend detection)
        let previous = self.get_previous_grounding(&memory.id)?;

        // Step 3: Collect evidence from Drift data sources
        let evidence = self.collect_evidence(memory)?;

        if evidence.is_empty() {
            return Ok(GroundingResult {
                id: uuid::Uuid::new_v4().to_string(),
                memory_id: memory.id.clone(),
                memory_type: memory.memory_type,
                verdict: GroundingVerdict::InsufficientData,
                grounding_score: 0.0,
                previous_score: previous.map(|p| p.grounding_score),
                score_delta: None,
                confidence_adjustment: ConfidenceAdjustment {
                    mode: AdjustmentMode::NoChange,
                    target_value: None,
                    delta: None,
                    reason: "Insufficient Drift data for grounding".to_string(),
                },
                evidence: vec![],
                data_sources: vec![],
                generates_contradiction: false,
                checked_at: Utc::now(),
                duration_ms: start.elapsed().as_millis() as u32,
            });
        }

        // Step 4: Compute grounding score from evidence
        let grounding_score = self.compute_grounding_score(&evidence);

        // Step 5: Determine verdict
        let verdict = self.score_to_verdict(grounding_score);

        // Step 6: Calculate confidence adjustment
        let score_delta = previous.map(|p| grounding_score - p.grounding_score);
        let confidence_adjustment = self.compute_confidence_adjustment(
            grounding_score,
            score_delta,
            &verdict,
            memory.confidence.value(),
        );

        // Step 7: Check if contradiction should be generated
        let generates_contradiction = self.should_generate_contradiction(
            grounding_score,
            score_delta,
            &verdict,
        );

        let data_sources: Vec<GroundingDataSource> = evidence.iter()
            .map(|e| match e.evidence_type {
                EvidenceType::PatternConfidence | EvidenceType::PatternOccurrence =>
                    GroundingDataSource::Patterns,
                EvidenceType::FalsePositiveRate => GroundingDataSource::ViolationFeedback,
                EvidenceType::ConstraintVerification => GroundingDataSource::Constraints,
                EvidenceType::CouplingMetric => GroundingDataSource::Coupling,
                EvidenceType::DnaHealth => GroundingDataSource::Dna,
                EvidenceType::TestCoverage => GroundingDataSource::TestTopology,
                EvidenceType::ErrorHandlingGaps => GroundingDataSource::ErrorHandling,
                EvidenceType::DecisionEvidence => GroundingDataSource::Decisions,
                EvidenceType::BoundaryData => GroundingDataSource::Boundaries,
            })
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        let result = GroundingResult {
            id: uuid::Uuid::new_v4().to_string(),
            memory_id: memory.id.clone(),
            memory_type: memory.memory_type,
            verdict,
            grounding_score,
            previous_score: previous.map(|p| p.grounding_score),
            score_delta,
            confidence_adjustment,
            evidence,
            data_sources,
            generates_contradiction,
            checked_at: Utc::now(),
            duration_ms: start.elapsed().as_millis() as u32,
        };

        // Persist grounding result
        self.persist_grounding_result(&result)?;

        Ok(result)
    }

    /// Collect evidence from all relevant Drift data sources for a memory.
    fn collect_evidence(&self, memory: &BaseMemory) -> BridgeResult<Vec<GroundingEvidence>> {
        let mut evidence = Vec::new();

        match memory.memory_type {
            MemoryType::PatternRationale => {
                evidence.extend(self.collect_pattern_evidence(memory)?);
            }
            MemoryType::ConstraintOverride => {
                evidence.extend(self.collect_constraint_evidence(memory)?);
            }
            MemoryType::DecisionContext => {
                evidence.extend(self.collect_decision_evidence(memory)?);
            }
            MemoryType::CodeSmell => {
                evidence.extend(self.collect_detector_evidence(memory)?);
            }
            MemoryType::Tribal => {
                evidence.extend(self.collect_tribal_evidence(memory)?);
            }
            MemoryType::Core => {
                // Core memories can be grounded against multiple sources
                evidence.extend(self.collect_pattern_evidence(memory)?);
                evidence.extend(self.collect_coupling_evidence(memory)?);
                evidence.extend(self.collect_dna_evidence(memory)?);
            }
            MemoryType::Semantic => {
                evidence.extend(self.collect_pattern_evidence(memory)?);
                evidence.extend(self.collect_constraint_evidence(memory)?);
            }
            _ => {} // Other types handled by groundability classifier
        }

        Ok(evidence)
    }

    /// Collect pattern-related evidence from drift.db.
    fn collect_pattern_evidence(
        &self,
        memory: &BaseMemory,
    ) -> BridgeResult<Vec<GroundingEvidence>> {
        let mut evidence = Vec::new();

        // Find patterns linked to this memory via entity_links
        for link in &memory.entity_links {
            if link.entity_type == "drift_pattern" {
                // Query pattern confidence from drift.db
                let result = self.drift_db.query_row(
                    "SELECT confidence_score, conforming_count, violating_count,
                            file_count, status
                     FROM patterns WHERE id = ?1",
                    [&link.entity_id],
                    |row| Ok((
                        row.get::<_, f64>(0)?,
                        row.get::<_, u32>(1)?,
                        row.get::<_, u32>(2)?,
                        row.get::<_, u32>(3)?,
                        row.get::<_, String>(4)?,
                    )),
                );

                if let Ok((confidence, conforming, violating, file_count, status)) = result {
                    let total = conforming + violating;
                    let occurrence_rate = if total > 0 {
                        conforming as f64 / total as f64
                    } else {
                        0.0
                    };

                    evidence.push(GroundingEvidence {
                        evidence_type: EvidenceType::PatternConfidence,
                        description: format!(
                            "Pattern '{}' has {:.0}% confidence ({} conforming, {} violating)",
                            link.entity_id, confidence * 100.0, conforming, violating
                        ),
                        drift_value: confidence,
                        memory_claim: Some(link.strength),
                        weight: 0.6, // Pattern confidence is strong evidence
                    });

                    evidence.push(GroundingEvidence {
                        evidence_type: EvidenceType::PatternOccurrence,
                        description: format!(
                            "Pattern occurs in {:.0}% of relevant files ({} files)",
                            occurrence_rate * 100.0, file_count
                        ),
                        drift_value: occurrence_rate,
                        memory_claim: None,
                        weight: 0.4,
                    });

                    // Check FP rate from violation feedback
                    if let Ok(fp_rate) = self.get_pattern_fp_rate(&link.entity_id) {
                        evidence.push(GroundingEvidence {
                            evidence_type: EvidenceType::FalsePositiveRate,
                            description: format!(
                                "Pattern has {:.1}% false positive rate",
                                fp_rate * 100.0
                            ),
                            drift_value: 1.0 - fp_rate, // Invert: low FP = high grounding
                            memory_claim: None,
                            weight: 0.3,
                        });
                    }
                }
            }
        }

        // Also search by pattern name in memory content (fuzzy matching)
        if evidence.is_empty() {
            evidence.extend(self.fuzzy_match_patterns(memory)?);
        }

        Ok(evidence)
    }

    /// Get false positive rate for a pattern from violation feedback.
    fn get_pattern_fp_rate(&self, pattern_id: &str) -> BridgeResult<f64> {
        let result = self.drift_db.query_row(
            "SELECT
                CAST(SUM(CASE WHEN action = 'dismissed' THEN 1 ELSE 0 END) AS REAL) /
                CAST(COUNT(*) AS REAL) as fp_rate
             FROM violation_feedback
             WHERE pattern_id = ?1
             AND acted_at > datetime('now', '-30 days')
             HAVING COUNT(*) >= 10",
            [pattern_id],
            |row| row.get::<_, f64>(0),
        )?;
        Ok(result)
    }
}
```


---

## 9. Responsibility 4: Grounding Feedback Loop (The Killer Feature)

This is the most valuable piece of the integration. Per PLANNING-DRIFT.md D7:
> First AI memory system with empirically validated memory — beliefs checked against
> ground truth. Critical for early-stage algorithm tuning — you can measure
> precision/recall of the memory system against actual codebase state.

### 9.1 The Complete Loop

```
┌─────────────────────────────────────────────────────────────────┐
│                    GROUNDING FEEDBACK LOOP                       │
│                                                                 │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐ │
│  │  Cortex   │    │  Drift   │    │  Bridge  │    │  Cortex  │ │
│  │  Memory   │───▶│  Scan    │───▶│ Compare  │───▶│ Validate │ │
│  │  Store    │    │  Results │    │ & Score  │    │ & Heal   │ │
│  └──────────┘    └──────────┘    └──────────┘    └──────────┘ │
│       │                                               │        │
│       │              FEEDBACK CYCLE                    │        │
│       └───────────────────────────────────────────────┘        │
│                                                                 │
│  Phase 1: Memory exists with confidence C                       │
│  Phase 2: Drift scans independently, writes to drift.db         │
│  Phase 3: Bridge reads drift.db, compares against memory claims │
│  Phase 4: Bridge adjusts memory confidence or flags for review  │
│  Phase 5: Cortex validation engine processes adjustments        │
│  Phase 6: If contradiction detected, Cortex heals or archives   │
│  Phase 7: Next scan cycle repeats from Phase 2                  │
└─────────────────────────────────────────────────────────────────┘
```

### 9.2 Loop Execution

```rust
impl GroundingEngine {
    /// Execute the full grounding loop for all groundable memories.
    /// Called after on_scan_complete or on-demand via drift_grounding_check.
    #[instrument(skip(self))]
    pub fn execute_grounding_loop(&self) -> BridgeResult<GroundingSnapshot> {
        let start = std::time::Instant::now();
        let _span = info_span!("grounding_loop").entered();

        // Phase 1: Fetch all groundable memories from cortex.db
        let memories = self.fetch_groundable_memories()?;
        info!(memory_count = memories.len(), "Fetched groundable memories");

        let mut snapshot = GroundingSnapshot {
            total_checked: memories.len() as u32,
            ..Default::default()
        };

        // Phase 2: Ground each memory
        for memory in &memories {
            match self.ground_memory(memory) {
                Ok(result) => {
                    // Phase 3: Update snapshot counters
                    match result.verdict {
                        GroundingVerdict::Validated => snapshot.validated += 1,
                        GroundingVerdict::Partial => snapshot.partial += 1,
                        GroundingVerdict::Weak => snapshot.weak += 1,
                        GroundingVerdict::Invalidated => snapshot.invalidated += 1,
                        GroundingVerdict::NotGroundable => snapshot.not_groundable += 1,
                        GroundingVerdict::InsufficientData => snapshot.insufficient_data += 1,
                        GroundingVerdict::Error => {}
                    }

                    // Phase 4: Apply confidence adjustment to Cortex memory
                    if result.confidence_adjustment.mode != AdjustmentMode::NoChange {
                        self.apply_confidence_adjustment(
                            &memory.id,
                            &result.confidence_adjustment,
                        )?;
                    }

                    // Phase 5: Generate contradiction if needed
                    if result.generates_contradiction {
                        self.generate_contradiction(memory, &result)?;
                        snapshot.contradictions_generated += 1;
                    }

                    // Phase 6: Flag for review if needed
                    if result.confidence_adjustment.mode == AdjustmentMode::FlagForReview {
                        snapshot.flagged_for_review += 1;
                    }
                }
                Err(e) => {
                    warn!(
                        memory_id = %memory.id,
                        error = %e,
                        "Failed to ground memory"
                    );
                }
            }
        }

        // Compute average grounding score
        let groundable_count = snapshot.validated + snapshot.partial
            + snapshot.weak + snapshot.invalidated;
        if groundable_count > 0 {
            let total_score: f64 = self.sum_recent_grounding_scores()?;
            snapshot.avg_grounding_score = total_score / groundable_count as f64;
        }

        snapshot.checked_at = Utc::now();
        snapshot.duration_ms = start.elapsed().as_millis() as u32;

        // Persist snapshot
        self.persist_grounding_snapshot(&snapshot)?;

        info!(
            validated = snapshot.validated,
            partial = snapshot.partial,
            weak = snapshot.weak,
            invalidated = snapshot.invalidated,
            contradictions = snapshot.contradictions_generated,
            duration_ms = snapshot.duration_ms,
            "Grounding loop complete"
        );

        Ok(snapshot)
    }

    /// Fetch all memories that can be empirically validated.
    fn fetch_groundable_memories(&self) -> BridgeResult<Vec<BaseMemory>> {
        let groundable_types = GROUNDABLE_MEMORY_TYPES
            .iter()
            .map(|t| format!("'{}'", serde_json::to_string(t).unwrap_or_default().trim_matches('"')))
            .collect::<Vec<_>>()
            .join(",");

        let query = format!(
            "SELECT id, memory_type, content, summary, confidence, importance,
                    metadata, entity_links, linked_patterns, linked_constraints,
                    linked_files, linked_functions, created_at, updated_at
             FROM memories
             WHERE memory_type IN ({})
             AND confidence > 0.1
             AND archived = 0
             ORDER BY updated_at DESC
             LIMIT ?1",
            groundable_types
        );

        let mut stmt = self.cortex_db.prepare(&query)?;
        let memories = stmt.query_map(
            [self.config.grounding.max_memories_per_loop as i64],
            |row| {
                // Deserialize BaseMemory from row
                Ok(deserialize_memory_from_row(row)?)
            },
        )?;

        let mut result = Vec::new();
        for memory in memories {
            match memory {
                Ok(m) => result.push(m),
                Err(e) => warn!(error = %e, "Failed to deserialize memory for grounding"),
            }
        }

        Ok(result)
    }

    /// Apply a confidence adjustment to a Cortex memory.
    fn apply_confidence_adjustment(
        &self,
        memory_id: &str,
        adjustment: &ConfidenceAdjustment,
    ) -> BridgeResult<()> {
        match adjustment.mode {
            AdjustmentMode::NoChange => Ok(()),
            AdjustmentMode::Boost => {
                let delta = adjustment.delta.unwrap_or(0.05);
                self.cortex_db.execute(
                    "UPDATE memories SET confidence = MIN(1.0, confidence + ?1),
                     updated_at = datetime('now')
                     WHERE id = ?2",
                    rusqlite::params![delta, memory_id],
                )?;
                info!(memory_id, delta, "Boosted memory confidence");
                Ok(())
            }
            AdjustmentMode::Penalize => {
                let delta = adjustment.delta.unwrap_or(0.1);
                self.cortex_db.execute(
                    "UPDATE memories SET confidence = MAX(0.0, confidence - ?1),
                     updated_at = datetime('now')
                     WHERE id = ?2",
                    rusqlite::params![delta, memory_id],
                )?;
                info!(memory_id, delta, "Penalized memory confidence");
                Ok(())
            }
            AdjustmentMode::Set => {
                let target = adjustment.target_value.unwrap_or(0.5);
                self.cortex_db.execute(
                    "UPDATE memories SET confidence = ?1,
                     updated_at = datetime('now')
                     WHERE id = ?2",
                    rusqlite::params![target, memory_id],
                )?;
                info!(memory_id, target, "Set memory confidence");
                Ok(())
            }
            AdjustmentMode::FlagForReview => {
                self.cortex_db.execute(
                    "UPDATE memories SET
                     metadata = json_set(metadata, '$.grounding_review', 'pending'),
                     updated_at = datetime('now')
                     WHERE id = ?1",
                    [memory_id],
                )?;
                info!(memory_id, "Flagged memory for grounding review");
                Ok(())
            }
        }
    }
}
```

### 9.3 Grounding Trigger Points

The grounding loop can be triggered by:

| Trigger | When | Scope |
|---------|------|-------|
| `on_scan_complete` | After every Drift scan | All groundable memories |
| `drift_grounding_check` MCP tool | On-demand by AI agent | Specific memory or all |
| Scheduled (cron-style) | Configurable interval | All groundable memories |
| Memory creation | When bridge creates a memory | Just the new memory |
| Manual CLI | `drift bridge ground` | All or filtered |

### 9.4 Incremental Grounding

Full grounding of all memories on every scan is expensive. Incremental grounding
only re-grounds memories affected by the scan:

```rust
impl GroundingEngine {
    /// Incremental grounding: only re-ground memories affected by changed files.
    pub fn incremental_ground(&self, scan_diff: &ScanDiff) -> BridgeResult<GroundingSnapshot> {
        let changed_files: Vec<&str> = scan_diff.added.iter()
            .chain(scan_diff.modified.iter())
            .chain(scan_diff.removed.iter())
            .map(|f| f.path.as_str())
            .collect();

        // Find memories linked to changed files
        let affected_memories = self.find_memories_linked_to_files(&changed_files)?;

        // Also find memories linked to patterns in changed files
        let pattern_ids = self.find_patterns_in_files(&changed_files)?;
        let pattern_memories = self.find_memories_linked_to_patterns(&pattern_ids)?;

        // Deduplicate
        let mut all_memories = affected_memories;
        for m in pattern_memories {
            if !all_memories.iter().any(|existing| existing.id == m.id) {
                all_memories.push(m);
            }
        }

        info!(
            affected_memories = all_memories.len(),
            changed_files = changed_files.len(),
            "Incremental grounding: {} memories affected by {} changed files",
            all_memories.len(),
            changed_files.len(),
        );

        // Ground only affected memories
        self.ground_memories(&all_memories)
    }
}
```

---

## 10. Responsibility 5: Intent Extensions (Code-Specific Intents)

Per PLANNING-DRIFT.md D4: The bridge provides code-specific intents registered as
extensions to Cortex's intent system. Cortex has 7 domain-agnostic intents + 3
universal intents. The bridge adds code-specific intents that leverage Drift data.

### 10.1 Code-Specific Intent Registry

| Intent | Description | Drift Data Used | Cortex Data Used |
|--------|------------|----------------|-----------------|
| `add_feature` | Adding a new feature to the codebase | Patterns, constraints, call graph | Related memories, decisions |
| `fix_bug` | Fixing a bug | Error handling gaps, test topology | Incident memories, procedural |
| `refactor` | Refactoring code | Coupling, DNA, patterns | Pattern rationales, decisions |
| `review_code` | Code review context | Violations, constraints, boundaries | Tribal knowledge, conventions |
| `debug` | Debugging an issue | Call graph, reachability, taint | Episodic memories, incidents |
| `optimize` | Performance optimization | Call graph hotspots, coupling | Performance memories |
| `secure` | Security hardening | Taint, boundaries, secrets | Security decisions, overrides |
| `test` | Writing tests | Test topology, coverage gaps | Testing conventions |
| `document` | Writing documentation | DNA, patterns, decisions | Decision context, rationales |
| `migrate` | Migration/upgrade | Contracts, boundaries, coupling | Migration memories |

### 10.2 Intent Extension Implementation

```rust
use cortex_core::intent::Intent;

/// Register code-specific intents with Cortex's intent system.
pub fn register_code_intents(intent_registry: &mut IntentRegistry) {
    intent_registry.register(Intent {
        name: "add_feature".to_string(),
        description: "Adding a new feature — retrieves relevant patterns, \
                      constraints, and architectural context".to_string(),
        retrieval_strategy: RetrievalStrategy::Composite {
            strategies: vec![
                RetrievalStrategy::ByType(vec![
                    MemoryType::PatternRationale,
                    MemoryType::ConstraintOverride,
                    MemoryType::DecisionContext,
                    MemoryType::Tribal,
                ]),
                RetrievalStrategy::ByEntityLink("drift_pattern".to_string()),
                RetrievalStrategy::Semantic { query_boost: 1.2 },
            ],
        },
        context_enrichment: vec![
            ContextEnrichment::DriftPatterns,
            ContextEnrichment::DriftConstraints,
            ContextEnrichment::DriftCallGraph,
        ],
    });

    intent_registry.register(Intent {
        name: "fix_bug".to_string(),
        description: "Fixing a bug — retrieves error handling context, \
                      test coverage, and incident history".to_string(),
        retrieval_strategy: RetrievalStrategy::Composite {
            strategies: vec![
                RetrievalStrategy::ByType(vec![
                    MemoryType::Incident,
                    MemoryType::Procedural,
                    MemoryType::CodeSmell,
                ]),
                RetrievalStrategy::ByFile,
                RetrievalStrategy::Semantic { query_boost: 1.0 },
            ],
        },
        context_enrichment: vec![
            ContextEnrichment::DriftErrorHandling,
            ContextEnrichment::DriftTestTopology,
            ContextEnrichment::DriftCallGraph,
        ],
    });

    // ... remaining intents follow same pattern
}
```

---

## 11. Responsibility 6: Combined MCP Tools

Per PLANNING-DRIFT.md D3 and 32-MCP-SERVER-V2-PREP.md §3: When both Cortex and Drift
are detected, the drift-analysis server conditionally registers bridge tools. These
are NOT a third server — they augment drift-analysis with cross-system capabilities.

### 11.1 Bridge Tool Specifications

#### drift_why

Synthesizes pattern data from Drift with causal memory from Cortex to answer
"why does this pattern/convention exist?"

```typescript
// Tool definition (registered on drift-analysis server, conditional)
{
    name: "drift_why",
    description: "Explain why a pattern, convention, or architectural decision exists. " +
        "Combines Drift's empirical analysis with Cortex's institutional memory.",
    inputSchema: {
        type: "object",
        properties: {
            query: {
                type: "string",
                description: "What to explain (pattern name, file path, convention)"
            },
            file: {
                type: "string",
                description: "Optional file path for context-specific explanation"
            },
            depth: {
                type: "string",
                enum: ["brief", "detailed", "comprehensive"],
                default: "detailed",
                description: "Level of detail in the explanation"
            }
        },
        required: ["query"]
    }
}
```

Implementation flow:
1. Query drift.db for pattern data matching the query
2. Query cortex.db for related memories (pattern_rationale, decision_context, tribal)
3. Query Cortex causal graph for causal chains
4. Synthesize a unified explanation combining empirical data + institutional knowledge
5. Include grounding score if available (how well the explanation matches reality)

#### drift_memory_learn

Creates a Cortex memory from a Drift correction or observation.

```typescript
{
    name: "drift_memory_learn",
    description: "Learn from a Drift analysis result and store as Cortex memory. " +
        "Use when you discover something about the codebase that should be remembered.",
    inputSchema: {
        type: "object",
        properties: {
            content: {
                type: "string",
                description: "What to remember about the codebase"
            },
            memory_type: {
                type: "string",
                enum: ["pattern_rationale", "tribal", "decision_context",
                       "constraint_override", "procedural", "core"],
                default: "tribal",
                description: "Type of memory to create"
            },
            linked_patterns: {
                type: "array",
                items: { type: "string" },
                description: "Drift pattern IDs to link to this memory"
            },
            linked_files: {
                type: "array",
                items: { type: "string" },
                description: "File paths to link to this memory"
            },
            confidence: {
                type: "number",
                minimum: 0.0,
                maximum: 1.0,
                default: 0.7,
                description: "Initial confidence (0.0-1.0)"
            }
        },
        required: ["content"]
    }
}
```

Implementation flow:
1. Create BaseMemory with specified type and content
2. Translate linked_patterns to EntityLinks via LinkTranslator
3. Create FileLinks for linked_files
4. Enrich with Drift context (pattern confidence, constraint status)
5. Store in cortex.db
6. Immediately ground the new memory against drift.db

#### drift_grounding_check

Validates Cortex memories against Drift scan results. The explicit MCP interface
to the grounding engine.

```typescript
{
    name: "drift_grounding_check",
    description: "Validate Cortex memories against Drift's empirical scan data. " +
        "Shows which memories are supported by codebase reality and which have drifted.",
    inputSchema: {
        type: "object",
        properties: {
            memory_id: {
                type: "string",
                description: "Specific memory ID to check (omit for all groundable memories)"
            },
            memory_type: {
                type: "string",
                description: "Filter by memory type"
            },
            include_evidence: {
                type: "boolean",
                default: true,
                description: "Include detailed evidence in results"
            },
            apply_adjustments: {
                type: "boolean",
                default: false,
                description: "Actually apply confidence adjustments (false = dry run)"
            }
        }
    }
}
```

Implementation flow:
1. If memory_id specified, ground that single memory
2. If memory_type specified, ground all memories of that type
3. If neither, execute full grounding loop
4. Return GroundingSnapshot with per-memory results
5. If apply_adjustments=true, apply confidence changes to cortex.db
6. If apply_adjustments=false, return what would change (dry run)


---

## 12. Database Integration (ATTACH Pattern, Cross-DB Queries)

Per PLANNING-DRIFT.md D6: Separate databases with ATTACH for cross-DB queries.
The bridge manages the ATTACH lifecycle and provides cross-DB query utilities.

### 12.1 ATTACH Strategy

```rust
pub struct DatabaseBridge {
    /// Connection to cortex.db (read/write — bridge creates memories here).
    cortex_conn: rusqlite::Connection,
    /// Connection to drift.db (read-only — bridge reads scan data).
    drift_conn: rusqlite::Connection,
    /// Whether drift.db is ATTACHed to cortex_conn for cross-DB queries.
    drift_attached: bool,
    /// Whether cortex.db is ATTACHed to drift_conn for cross-DB queries.
    cortex_attached: bool,
}

impl DatabaseBridge {
    pub fn new(cortex_db_path: &Path, drift_db_path: &Path) -> BridgeResult<Self> {
        let cortex_conn = rusqlite::Connection::open(cortex_db_path)?;
        let drift_conn = rusqlite::Connection::open_with_flags(
            drift_db_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;

        // Apply standard pragmas
        for conn in [&cortex_conn, &drift_conn] {
            conn.execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA synchronous = NORMAL;
                 PRAGMA mmap_size = 268435456;
                 PRAGMA busy_timeout = 5000;"
            )?;
        }

        let mut bridge = Self {
            cortex_conn,
            drift_conn,
            drift_attached: false,
            cortex_attached: false,
        };

        // ATTACH drift.db to cortex connection (read-only)
        bridge.attach_drift(drift_db_path)?;

        // ATTACH cortex.db to drift connection (read-only)
        bridge.attach_cortex(cortex_db_path)?;

        Ok(bridge)
    }

    fn attach_drift(&mut self, drift_db_path: &Path) -> BridgeResult<()> {
        match self.cortex_conn.execute(
            &format!("ATTACH DATABASE '{}' AS drift_db", drift_db_path.display()),
            [],
        ) {
            Ok(_) => {
                self.drift_attached = true;
                info!("ATTACHed drift.db to cortex connection");
                Ok(())
            }
            Err(e) => {
                warn!(error = %e, "Failed to ATTACH drift.db — cross-DB queries unavailable");
                // Graceful degradation: bridge works without ATTACH
                Ok(())
            }
        }
    }

    fn attach_cortex(&mut self, cortex_db_path: &Path) -> BridgeResult<()> {
        match self.drift_conn.execute(
            &format!("ATTACH DATABASE '{}' AS cortex_db", cortex_db_path.display()),
            [],
        ) {
            Ok(_) => {
                self.cortex_attached = true;
                info!("ATTACHed cortex.db to drift connection");
                Ok(())
            }
            Err(e) => {
                warn!(error = %e, "Failed to ATTACH cortex.db — cross-DB queries unavailable");
                Ok(())
            }
        }
    }

    /// Cross-DB query: find memories linked to Drift patterns.
    /// Uses ATTACH to join across databases in a single query.
    pub fn memories_for_pattern(&self, pattern_id: &str) -> BridgeResult<Vec<BaseMemory>> {
        if !self.drift_attached {
            // Fallback: query cortex.db only, filter by entity_links JSON
            return self.memories_for_pattern_fallback(pattern_id);
        }

        let query = "
            SELECT m.id, m.memory_type, m.content, m.summary, m.confidence
            FROM memories m
            WHERE m.entity_links LIKE '%drift_pattern%'
            AND m.entity_links LIKE ?1
            AND m.archived = 0
            ORDER BY m.confidence DESC
            LIMIT 20
        ";

        let pattern_filter = format!("%{}%", pattern_id);
        let mut stmt = self.cortex_conn.prepare(query)?;
        let memories = stmt.query_map([&pattern_filter], |row| {
            Ok(deserialize_memory_summary(row)?)
        })?;

        let mut result = Vec::new();
        for m in memories {
            result.push(m?);
        }
        Ok(result)
    }

    /// Cross-DB query: find Drift patterns for a memory's linked files.
    pub fn patterns_for_memory_files(
        &self,
        memory: &BaseMemory,
    ) -> BridgeResult<Vec<PatternSummary>> {
        if !self.cortex_attached {
            return Ok(vec![]);
        }

        let file_paths: Vec<&str> = memory.linked_files.iter()
            .map(|f| f.file_path.as_str())
            .collect();

        if file_paths.is_empty() {
            return Ok(vec![]);
        }

        let placeholders = file_paths.iter()
            .enumerate()
            .map(|(i, _)| format!("?{}", i + 1))
            .collect::<Vec<_>>()
            .join(",");

        let query = format!(
            "SELECT DISTINCT p.id, p.name, p.category, p.confidence_score, p.status
             FROM drift_db.patterns p
             JOIN drift_db.pattern_locations pl ON p.id = pl.pattern_id
             WHERE pl.file_path IN ({})
             AND p.status = 'approved'
             ORDER BY p.confidence_score DESC",
            placeholders
        );

        let mut stmt = self.drift_conn.prepare(&query)?;
        let params: Vec<&dyn rusqlite::types::ToSql> = file_paths.iter()
            .map(|p| p as &dyn rusqlite::types::ToSql)
            .collect();

        let patterns = stmt.query_map(params.as_slice(), |row| {
            Ok(PatternSummary {
                id: row.get(0)?,
                name: row.get(1)?,
                category: row.get(2)?,
                confidence: row.get(3)?,
                status: row.get(4)?,
            })
        })?;

        let mut result = Vec::new();
        for p in patterns {
            result.push(p?);
        }
        Ok(result)
    }
}
```

### 12.2 Graceful Degradation

Per D6: If either database doesn't exist, ATTACH fails gracefully and cross-DB
queries return empty results. The bridge continues to function with reduced capability.

| Scenario | Behavior |
|----------|----------|
| Both DBs present | Full bridge functionality |
| drift.db missing | No grounding, no pattern evidence, event mapping still works |
| cortex.db missing | No memory creation, bridge is effectively disabled |
| ATTACH fails | Fallback to separate queries (slower but functional) |
| drift.db locked | Retry with busy_timeout, then skip grounding this cycle |
| cortex.db locked | Retry with busy_timeout, then queue memory creation |

---

## 13. DriftEventHandler Implementation (Bridge Side)

The bridge's DriftEventHandler is the primary integration point. It's registered
with Drift's engine at initialization and receives all Drift lifecycle events.

### 13.1 Registration

```rust
impl BridgeRuntime {
    /// Register the bridge's event handler with Drift's engine.
    pub fn register_with_drift(&self, drift_engine: &mut DriftEngine) {
        let handler = Arc::new(BridgeEventHandler {
            cortex_writer: self.cortex_writer.clone(),
            config: self.config.clone(),
            metrics: self.metrics.clone(),
        });

        drift_engine.register_handler(handler);
        info!("Bridge event handler registered with Drift engine");
    }
}
```

### 13.2 Thread Safety

The BridgeEventHandler must be `Send + Sync` (required by the DriftEventHandler trait).
All internal state is either:
- `Arc<T>` for shared ownership (CortexWriter, BridgeConfig)
- Immutable after initialization (event mapping configuration)
- Thread-safe by design (SQLite connections with WAL mode)

The CortexWriter uses an internal `Mutex<Connection>` for write serialization,
matching the pattern from cortex-core's storage layer.

---

## 14. CortexEventHandler Implementation (Bridge Side)

The bridge also implements CortexEventHandler to react to Cortex events that
should trigger Drift actions. This is the reverse direction of the event flow.

### 14.1 Cortex → Drift Event Mapping

| Cortex Event | Bridge Action | Description |
|-------------|--------------|-------------|
| `on_memory_created` | Check file links | If memory links to files, suggest Drift re-scan |
| `on_memory_updated` | Re-ground | If memory content changed, re-ground against Drift |
| `on_memory_archived` | Clean up links | Remove stale EntityLinks to Drift entities |
| `on_consolidation_complete` | Re-ground consolidated | Ground newly consolidated memories |
| `on_contradiction_detected` | Check Drift data | If contradiction involves Drift-linked memories, provide evidence |

### 14.2 Implementation

```rust
impl cortex_core::traits::CortexEventHandler for BridgeCortexHandler {
    fn on_memory_created(&self, memory: &BaseMemory) {
        // If the new memory has file links, check if Drift has data for those files
        if !memory.linked_files.is_empty() {
            let file_paths: Vec<&str> = memory.linked_files.iter()
                .map(|f| f.file_path.as_str())
                .collect();

            // Enrich the memory with Drift entity links
            if let Ok(links) = self.enrich_with_drift_links(&file_paths) {
                if !links.is_empty() {
                    // Update memory with Drift entity links
                    let _ = self.cortex_writer.add_entity_links(&memory.id, &links);
                    info!(
                        memory_id = %memory.id,
                        link_count = links.len(),
                        "Enriched new memory with Drift entity links"
                    );
                }
            }
        }
    }

    fn on_memory_updated(&self, memory: &BaseMemory, _changes: &MemoryDiff) {
        // Re-ground the updated memory if it has Drift entity links
        if memory.entity_links.iter().any(|l| l.entity_type.starts_with("drift_")) {
            if let Ok(result) = self.grounding_engine.ground_memory(memory) {
                if result.confidence_adjustment.mode != AdjustmentMode::NoChange {
                    let _ = self.grounding_engine.apply_confidence_adjustment(
                        &memory.id,
                        &result.confidence_adjustment,
                    );
                }
            }
        }
    }

    fn on_contradiction_detected(&self, contradiction: &Contradiction) {
        // If either memory in the contradiction has Drift links,
        // provide Drift evidence to help resolve it
        for memory_id in &contradiction.memory_ids {
            if let Ok(evidence) = self.get_drift_evidence_for_memory(memory_id) {
                if !evidence.is_empty() {
                    let _ = self.cortex_writer.add_contradiction_evidence(
                        &contradiction.id,
                        &evidence,
                    );
                    info!(
                        contradiction_id = %contradiction.id,
                        evidence_count = evidence.len(),
                        "Added Drift evidence to contradiction"
                    );
                }
            }
        }
    }
}
```

---

## 15. Grounding Metrics & Confidence Adjustment Algorithms

### 15.1 Grounding Score Computation

The grounding score is a weighted average of all evidence items:

```rust
impl GroundingEngine {
    /// Compute grounding score from collected evidence.
    /// Score range: 0.0 (completely ungrounded) to 1.0 (fully grounded).
    fn compute_grounding_score(&self, evidence: &[GroundingEvidence]) -> f64 {
        if evidence.is_empty() {
            return 0.0;
        }

        let total_weight: f64 = evidence.iter().map(|e| e.weight).sum();
        if total_weight == 0.0 {
            return 0.0;
        }

        let weighted_sum: f64 = evidence.iter()
            .map(|e| e.drift_value * e.weight)
            .sum();

        (weighted_sum / total_weight).clamp(0.0, 1.0)
    }

    /// Convert grounding score to verdict.
    fn score_to_verdict(&self, score: f64) -> GroundingVerdict {
        let thresholds = &self.config.grounding.thresholds;
        if score >= thresholds.validated {       // default: 0.7
            GroundingVerdict::Validated
        } else if score >= thresholds.partial {  // default: 0.4
            GroundingVerdict::Partial
        } else if score >= thresholds.weak {     // default: 0.2
            GroundingVerdict::Weak
        } else {
            GroundingVerdict::Invalidated
        }
    }

    /// Compute confidence adjustment based on grounding results.
    fn compute_confidence_adjustment(
        &self,
        grounding_score: f64,
        score_delta: Option<f64>,
        verdict: &GroundingVerdict,
        current_confidence: f64,
    ) -> ConfidenceAdjustment {
        match verdict {
            GroundingVerdict::Validated => {
                // Well-grounded: small boost if confidence is lower than grounding suggests
                if current_confidence < grounding_score - 0.1 {
                    ConfidenceAdjustment {
                        mode: AdjustmentMode::Boost,
                        target_value: None,
                        delta: Some(0.05),
                        reason: format!(
                            "Memory is well-grounded ({:.0}%) but confidence ({:.0}%) is low",
                            grounding_score * 100.0, current_confidence * 100.0
                        ),
                    }
                } else {
                    ConfidenceAdjustment {
                        mode: AdjustmentMode::NoChange,
                        target_value: None,
                        delta: None,
                        reason: format!(
                            "Memory is well-grounded ({:.0}%)",
                            grounding_score * 100.0
                        ),
                    }
                }
            }
            GroundingVerdict::Partial => {
                // Partially grounded: flag for review if significant drop
                if let Some(delta) = score_delta {
                    if delta < -0.2 {
                        // Significant drop — flag for review
                        return ConfidenceAdjustment {
                            mode: AdjustmentMode::FlagForReview,
                            target_value: None,
                            delta: None,
                            reason: format!(
                                "Grounding dropped {:.0}% (from {:.0}% to {:.0}%)",
                                delta.abs() * 100.0,
                                (grounding_score - delta) * 100.0,
                                grounding_score * 100.0,
                            ),
                        };
                    }
                }
                ConfidenceAdjustment {
                    mode: AdjustmentMode::Penalize,
                    target_value: None,
                    delta: Some(0.05),
                    reason: format!(
                        "Memory is partially grounded ({:.0}%)",
                        grounding_score * 100.0
                    ),
                }
            }
            GroundingVerdict::Weak => {
                ConfidenceAdjustment {
                    mode: AdjustmentMode::Penalize,
                    target_value: None,
                    delta: Some(0.15),
                    reason: format!(
                        "Memory is weakly grounded ({:.0}%) — significant divergence from codebase reality",
                        grounding_score * 100.0
                    ),
                }
            }
            GroundingVerdict::Invalidated => {
                ConfidenceAdjustment {
                    mode: AdjustmentMode::Set,
                    target_value: Some(grounding_score.max(0.1)), // Never set to 0
                    delta: None,
                    reason: format!(
                        "Memory is invalidated ({:.0}%) — codebase reality contradicts this memory",
                        grounding_score * 100.0
                    ),
                }
            }
            _ => ConfidenceAdjustment {
                mode: AdjustmentMode::NoChange,
                target_value: None,
                delta: None,
                reason: "Not applicable".to_string(),
            },
        }
    }

    /// Determine if a contradiction should be generated.
    fn should_generate_contradiction(
        &self,
        grounding_score: f64,
        score_delta: Option<f64>,
        verdict: &GroundingVerdict,
    ) -> bool {
        match verdict {
            // Always generate contradiction for invalidated memories
            GroundingVerdict::Invalidated => true,
            // Generate contradiction if score dropped dramatically
            GroundingVerdict::Weak | GroundingVerdict::Partial => {
                if let Some(delta) = score_delta {
                    delta < -0.3 // 30%+ drop triggers contradiction
                } else {
                    false
                }
            }
            _ => false,
        }
    }
}
```

### 15.2 Evidence Weight Calibration

Evidence weights are calibrated based on reliability and relevance:

| Evidence Type | Default Weight | Rationale |
|--------------|---------------|-----------|
| PatternConfidence | 0.6 | Bayesian posterior — most reliable signal |
| PatternOccurrence | 0.4 | Raw occurrence rate — good supporting signal |
| FalsePositiveRate | 0.3 | Inverted FP rate — developer feedback signal |
| ConstraintVerification | 0.5 | Binary pass/fail — strong signal |
| CouplingMetric | 0.3 | Architectural metric — moderate signal |
| DnaHealth | 0.4 | Composite health — good aggregate signal |
| TestCoverage | 0.3 | Coverage data — moderate signal |
| ErrorHandlingGaps | 0.2 | Gap count — weak individual signal |
| DecisionEvidence | 0.4 | Mined decisions — good supporting signal |
| BoundaryData | 0.3 | Boundary detection — moderate signal |


---

## 16. Groundability Classification (Which Memory Types Are Groundable)

Not all 23 memory types can be empirically validated against Drift scan data.
Episodic memories ("we had a meeting about X") can't be checked against code.
Pattern rationales ("we use repository pattern") can.

### 16.1 Groundability Matrix

| Memory Type | Category | Groundable | Grounding Strategy | Data Sources |
|------------|----------|-----------|-------------------|-------------|
| Core | Domain-agnostic | **Yes** | Multi-source fuzzy match | Patterns, coupling, DNA |
| Tribal | Domain-agnostic | **Partial** | Pattern + convention match | Patterns, constraints |
| Procedural | Domain-agnostic | **No** | Process knowledge, not code state | — |
| Semantic | Domain-agnostic | **Yes** | Pattern + constraint match | Patterns, constraints |
| Episodic | Domain-agnostic | **No** | Event memory, not code state | — |
| Decision | Domain-agnostic | **Partial** | Decision mining match | Decisions, patterns |
| Insight | Domain-agnostic | **Partial** | Pattern evidence match | Patterns |
| Reference | Domain-agnostic | **No** | External reference, not code state | — |
| Preference | Domain-agnostic | **No** | User preference, not code state | — |
| PatternRationale | Code-specific | **Yes** | Direct pattern confidence match | Patterns, violations, FP rate |
| ConstraintOverride | Code-specific | **Yes** | Constraint verification match | Constraints, violations |
| DecisionContext | Code-specific | **Yes** | Decision mining + pattern match | Decisions, patterns, coupling |
| CodeSmell | Code-specific | **Yes** | Detector health + FP rate | Violations, detector health |
| AgentSpawn | Universal | **No** | Agent lifecycle, not code state | — |
| Entity | Universal | **Partial** | Entity existence in code | Call graph, parsers |
| Goal | Universal | **No** | Aspirational, not current state | — |
| Feedback | Universal | **Partial** | Feedback validity check | Violations, patterns |
| Workflow | Universal | **No** | Process definition, not code state | — |
| Conversation | Universal | **No** | Chat history, not code state | — |
| Incident | Universal | **Partial** | Error handling gap correlation | Error handling, test topology |
| Meeting | Universal | **No** | Meeting notes, not code state | — |
| Skill | Universal | **No** | Capability description, not code state | — |
| Environment | Universal | **Partial** | Environment variable match | Constants, environment analysis |

### 16.2 Groundable Types Constant

```rust
/// Memory types that can be empirically validated against Drift scan data.
pub const GROUNDABLE_MEMORY_TYPES: &[MemoryType] = &[
    // Fully groundable (direct Drift data match)
    MemoryType::PatternRationale,
    MemoryType::ConstraintOverride,
    MemoryType::DecisionContext,
    MemoryType::CodeSmell,
    MemoryType::Core,
    MemoryType::Semantic,
    // Partially groundable (some evidence available)
    MemoryType::Tribal,
    MemoryType::Decision,
    MemoryType::Insight,
    MemoryType::Entity,
    MemoryType::Feedback,
    MemoryType::Incident,
    MemoryType::Environment,
];

/// Classification of how well a memory type can be grounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Groundability {
    /// Direct empirical validation possible (pattern confidence, constraint verification).
    Full,
    /// Some evidence available but not definitive (fuzzy matching, partial data).
    Partial,
    /// Cannot be empirically validated against code analysis data.
    NotGroundable,
}

pub fn classify_groundability(memory_type: &MemoryType) -> Groundability {
    match memory_type {
        MemoryType::PatternRationale
        | MemoryType::ConstraintOverride
        | MemoryType::DecisionContext
        | MemoryType::CodeSmell
        | MemoryType::Core
        | MemoryType::Semantic => Groundability::Full,

        MemoryType::Tribal
        | MemoryType::Decision
        | MemoryType::Insight
        | MemoryType::Entity
        | MemoryType::Feedback
        | MemoryType::Incident
        | MemoryType::Environment => Groundability::Partial,

        _ => Groundability::NotGroundable,
    }
}
```

---

## 17. Grounding Scheduling & Frequency

### 17.1 Scheduling Strategy

| Trigger | Scope | Frequency | Rationale |
|---------|-------|-----------|-----------|
| Post-scan (incremental) | Affected memories only | Every scan | Low cost, high relevance |
| Post-scan (full) | All groundable memories | Every 10th scan | Catch drift in unaffected memories |
| Scheduled | All groundable memories | Daily (configurable) | Background maintenance |
| On-demand (MCP) | Specified memories | User-triggered | Explicit validation request |
| Memory creation | New memory only | On creation | Immediate grounding of new knowledge |
| Memory update | Updated memory only | On update | Re-validate after content change |

### 17.2 Scheduling Implementation

```rust
pub struct GroundingScheduler {
    /// Counter for scan-triggered grounding.
    scan_count: std::sync::atomic::AtomicU32,
    /// Last full grounding timestamp.
    last_full_grounding: std::sync::Mutex<Option<DateTime<Utc>>>,
    /// Configuration.
    config: GroundingScheduleConfig,
}

#[derive(Debug, Clone)]
pub struct GroundingScheduleConfig {
    /// Run incremental grounding after every scan. Default: true.
    pub incremental_after_scan: bool,
    /// Run full grounding every N scans. Default: 10.
    pub full_grounding_interval: u32,
    /// Run full grounding if more than N hours since last. Default: 24.
    pub full_grounding_max_hours: u32,
    /// Maximum memories to ground per loop. Default: 500.
    pub max_memories_per_loop: u32,
    /// Skip grounding if scan changed fewer than N files. Default: 0 (always ground).
    pub min_changed_files: u32,
}

impl Default for GroundingScheduleConfig {
    fn default() -> Self {
        Self {
            incremental_after_scan: true,
            full_grounding_interval: 10,
            full_grounding_max_hours: 24,
            max_memories_per_loop: 500,
            min_changed_files: 0,
        }
    }
}

impl GroundingScheduler {
    /// Determine what type of grounding to run after a scan.
    pub fn should_ground(&self, scan_diff: &ScanDiff) -> GroundingAction {
        let changed_files = scan_diff.added.len() + scan_diff.modified.len()
            + scan_diff.removed.len();

        if changed_files < self.config.min_changed_files as usize {
            return GroundingAction::Skip;
        }

        let count = self.scan_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Check if full grounding is due
        if count % self.config.full_grounding_interval == 0 {
            return GroundingAction::Full;
        }

        // Check time-based full grounding
        if let Ok(last) = self.last_full_grounding.lock() {
            if let Some(last_time) = *last {
                let hours_since = (Utc::now() - last_time).num_hours();
                if hours_since >= self.config.full_grounding_max_hours as i64 {
                    return GroundingAction::Full;
                }
            } else {
                // Never run full grounding — do it now
                return GroundingAction::Full;
            }
        }

        if self.config.incremental_after_scan {
            GroundingAction::Incremental
        } else {
            GroundingAction::Skip
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroundingAction {
    /// Skip grounding this cycle.
    Skip,
    /// Incremental: only ground memories affected by changed files.
    Incremental,
    /// Full: ground all groundable memories.
    Full,
}
```

---

## 18. Contradiction Generation from Grounding

When grounding detects that a memory's claims are contradicted by Drift scan data,
the bridge generates a Cortex contradiction. This feeds into Cortex's existing
contradiction detection and resolution system.

### 18.1 Contradiction Types from Grounding

| Scenario | Contradiction Type | Resolution Strategy |
|----------|-------------------|-------------------|
| Pattern compliance dropped >30% | `grounding_drift` | Flag for review, suggest memory update |
| Pattern was removed/ignored | `grounding_invalidated` | Archive memory or create replacement |
| Constraint no longer verified | `grounding_constraint_fail` | Flag constraint override for review |
| Detector was disabled | `grounding_detector_disabled` | Lower confidence on related memories |
| DNA health score diverged | `grounding_health_drift` | Flag for architectural review |

### 18.2 Contradiction Generation

```rust
impl GroundingEngine {
    /// Generate a Cortex contradiction from a grounding result.
    fn generate_contradiction(
        &self,
        memory: &BaseMemory,
        result: &GroundingResult,
    ) -> BridgeResult<()> {
        let contradiction_content = format!(
            "Grounding contradiction: Memory '{}' (type: {:?}) has grounding score {:.0}% \
             (verdict: {:?}). {}",
            memory.summary,
            memory.memory_type,
            result.grounding_score * 100.0,
            result.verdict,
            result.confidence_adjustment.reason,
        );

        let evidence_summary: Vec<String> = result.evidence.iter()
            .map(|e| format!("- {}: {:.0}% (weight: {:.1})", e.description, e.drift_value * 100.0, e.weight))
            .collect();

        // Create contradiction in cortex.db
        self.cortex_db.execute(
            "INSERT INTO contradictions (id, memory_ids, description, evidence,
             severity, status, detected_by, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 'pending', 'grounding_loop', datetime('now'))",
            rusqlite::params![
                uuid::Uuid::new_v4().to_string(),
                serde_json::to_string(&[&memory.id]).unwrap_or_default(),
                contradiction_content,
                serde_json::to_string(&evidence_summary).unwrap_or_default(),
                if result.grounding_score < 0.1 { "severe" } else { "moderate" },
            ],
        )?;

        info!(
            memory_id = %memory.id,
            grounding_score = result.grounding_score,
            "Generated grounding contradiction"
        );

        Ok(())
    }
}
```

---

## 19. Error Handling & Graceful Degradation

The bridge must never crash either system. All errors are caught, logged, and
degraded gracefully. This is critical because the bridge is optional — a bridge
failure should not affect Drift scanning or Cortex memory operations.

### 19.1 Error Handling Strategy

| Error Category | Strategy | User Impact |
|---------------|----------|-------------|
| Cortex DB unavailable | Disable memory creation, log warning | No memories created from events |
| Drift DB unavailable | Disable grounding, log warning | No grounding checks |
| ATTACH fails | Fallback to separate queries | Slower cross-DB queries |
| Memory creation fails | Log error, continue processing | Single memory missed |
| Grounding fails for one memory | Log error, continue loop | One memory not grounded |
| Event handler panics | Catch at dispatch boundary | Event silently dropped |
| Configuration invalid | Use defaults, log warning | Default behavior |
| Disk full | Stop writes, log critical | No new memories until space freed |

### 19.2 Panic Safety

The bridge event handler must never panic, as it runs inside Drift's event dispatch loop.
All handler methods use `catch_unwind` at the boundary:

```rust
impl DriftEventHandler for SafeBridgeEventHandler {
    fn on_pattern_approved(&self, pattern: &Pattern) {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.inner.on_pattern_approved(pattern);
        }));

        if let Err(e) = result {
            tracing::error!(
                "Bridge event handler panicked on on_pattern_approved: {:?}",
                e
            );
        }
    }

    // ... same pattern for all event methods
}
```

---

## 20. Bridge Runtime & Initialization

### 20.1 BridgeRuntime

```rust
use std::sync::{Arc, OnceLock};

static BRIDGE_RUNTIME: OnceLock<Arc<BridgeRuntime>> = OnceLock::new();

pub struct BridgeRuntime {
    /// Database bridge (manages ATTACH lifecycle).
    pub db: DatabaseBridge,
    /// Grounding engine.
    pub grounding: GroundingEngine,
    /// Event handler (implements DriftEventHandler).
    pub event_handler: Arc<SafeBridgeEventHandler>,
    /// Cortex event handler (implements CortexEventHandler).
    pub cortex_handler: Arc<BridgeCortexHandler>,
    /// Link translator.
    pub link_translator: LinkTranslator,
    /// Grounding scheduler.
    pub scheduler: GroundingScheduler,
    /// Configuration.
    pub config: BridgeConfig,
    /// Metrics.
    pub metrics: BridgeMetrics,
}

pub struct BridgeInitOptions {
    /// Path to cortex.db.
    pub cortex_db_path: PathBuf,
    /// Path to drift.db.
    pub drift_db_path: PathBuf,
    /// Bridge configuration (from drift.toml [bridge] section).
    pub config: Option<BridgeConfig>,
}

impl BridgeRuntime {
    pub fn initialize(opts: BridgeInitOptions) -> BridgeResult<()> {
        let config = opts.config.unwrap_or_default();

        // Initialize database bridge
        let db = DatabaseBridge::new(&opts.cortex_db_path, &opts.drift_db_path)?;

        // Create bridge-specific tables
        db.create_bridge_tables()?;

        // Initialize grounding engine
        let grounding = GroundingEngine::new(
            db.drift_conn_clone()?,
            db.cortex_conn_clone()?,
            db.bridge_conn_clone()?,
            config.grounding.clone(),
        );

        // Initialize event handlers
        let cortex_writer = CortexWriter::new(db.cortex_conn_clone()?);
        let event_handler = Arc::new(SafeBridgeEventHandler::new(
            BridgeEventHandler {
                cortex_writer: cortex_writer.clone(),
                config: config.clone(),
                metrics: BridgeMetrics::new(),
            },
        ));

        let cortex_handler = Arc::new(BridgeCortexHandler::new(
            cortex_writer,
            grounding.clone(),
        ));

        let runtime = BridgeRuntime {
            db,
            grounding,
            event_handler,
            cortex_handler,
            link_translator: LinkTranslator,
            scheduler: GroundingScheduler::new(config.grounding.schedule.clone()),
            config,
            metrics: BridgeMetrics::new(),
        };

        BRIDGE_RUNTIME.set(Arc::new(runtime)).map_err(|_| {
            BridgeError::Config("Bridge runtime already initialized".to_string())
        })?;

        info!("Bridge runtime initialized");
        Ok(())
    }

    pub fn get() -> BridgeResult<Arc<BridgeRuntime>> {
        BRIDGE_RUNTIME
            .get()
            .cloned()
            .ok_or_else(|| BridgeError::Config(
                "Bridge runtime not initialized. Call bridge_initialize() first.".to_string()
            ))
    }

    /// Check if the bridge is available (both systems detected).
    pub fn is_available() -> bool {
        BRIDGE_RUNTIME.get().is_some()
    }
}
```

### 20.2 Detection Logic

The bridge is initialized only when both Cortex and Drift are detected:

```rust
/// Detect if both systems are available and initialize the bridge.
pub fn try_initialize_bridge(
    project_root: &Path,
    config: &DriftConfig,
) -> Option<Arc<BridgeRuntime>> {
    // Check config flag
    if config.bridge.as_ref().map_or(false, |b| !b.enabled) {
        info!("Bridge disabled by configuration");
        return None;
    }

    // Detect cortex.db
    let cortex_db_path = project_root.join(".drift").join("memory").join("cortex.db");
    if !cortex_db_path.exists() {
        info!("cortex.db not found — bridge not available");
        return None;
    }

    // Detect drift.db
    let drift_db_path = project_root.join(".drift").join("drift.db");
    if !drift_db_path.exists() {
        info!("drift.db not found — bridge not available");
        return None;
    }

    // Initialize bridge
    match BridgeRuntime::initialize(BridgeInitOptions {
        cortex_db_path,
        drift_db_path,
        config: config.bridge.clone(),
    }) {
        Ok(()) => {
            info!("Bridge initialized — Cortex + Drift integration active");
            BridgeRuntime::get().ok()
        }
        Err(e) => {
            warn!(error = %e, "Failed to initialize bridge — running without integration");
            None
        }
    }
}
```


---

## 21. NAPI Bridge Interface (cortex-drift-napi)

The bridge exposes its functionality to Node.js via a separate NAPI crate.
This follows the same patterns as drift-napi (§3 of 03-NAPI-BRIDGE-V2-PREP.md).

### 21.1 NAPI Function Registry

| Function | Sync/Async | Returns | Description |
|----------|-----------|---------|-------------|
| `bridge_initialize(cortex_db, drift_db, config?)` | Sync | `void` | Initialize bridge runtime |
| `bridge_shutdown()` | Sync | `void` | Graceful shutdown |
| `bridge_is_available()` | Sync | `bool` | Check if bridge is active |
| `bridge_ground_memory(memory_id)` | Async | `GroundingResult` | Ground single memory |
| `bridge_ground_all(options?)` | Async | `GroundingSnapshot` | Full grounding loop |
| `bridge_get_grounding_snapshot()` | Sync | `GroundingSnapshot` | Latest snapshot |
| `bridge_get_grounding_history(memory_id, limit?)` | Sync | `GroundingResult[]` | History for memory |
| `bridge_translate_links(pattern_links, constraint_links)` | Sync | `EntityLink[]` | Translate links |
| `bridge_memories_for_pattern(pattern_id)` | Sync | `MemorySummary[]` | Cross-DB query |
| `bridge_patterns_for_memory(memory_id)` | Sync | `PatternSummary[]` | Cross-DB query |
| `bridge_why(query, file?, depth?)` | Async | `WhyResult` | drift_why implementation |
| `bridge_learn(content, type?, links?)` | Async | `LearnResult` | drift_memory_learn impl |
| `bridge_grounding_check(memory_id?, type?, apply?)` | Async | `GroundingSnapshot` | drift_grounding_check |
| `bridge_get_metrics()` | Sync | `BridgeMetrics` | Bridge health metrics |
| `bridge_register_event_handler()` | Sync | `void` | Register with Drift engine |

### 21.2 Cargo.toml (cortex-drift-napi)

```toml
[package]
name = "cortex-drift-napi"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
cortex-drift-bridge = { path = "../cortex-drift-bridge" }
cortex-core = { path = "../../cortex/cortex-core" }
drift-core = { path = "../../drift/drift-core" }
napi = { version = "3", features = ["async", "serde-json"] }
napi-derive = "3"
serde = { version = "1", features = ["derive"] }
serde_json = "1"

[build-dependencies]
napi-build = "3"
```

### 21.3 Key NAPI Implementations

```rust
use napi_derive::napi;
use napi::bindgen_prelude::*;
use cortex_drift_bridge::*;

#[napi]
pub fn bridge_initialize(
    cortex_db_path: String,
    drift_db_path: String,
    config_json: Option<String>,
) -> napi::Result<()> {
    let config = config_json
        .map(|json| serde_json::from_str::<BridgeConfig>(&json))
        .transpose()
        .map_err(|e| napi::Error::from_reason(format!("[CONFIG_ERROR] {e}")))?;

    BridgeRuntime::initialize(BridgeInitOptions {
        cortex_db_path: PathBuf::from(cortex_db_path),
        drift_db_path: PathBuf::from(drift_db_path),
        config,
    }).map_err(|e| napi::Error::from_reason(format!("[BRIDGE_INIT_ERROR] {e}")))
}

#[napi]
pub fn bridge_is_available() -> bool {
    BridgeRuntime::is_available()
}

#[napi(object)]
pub struct NapiGroundingResult {
    pub id: String,
    pub memory_id: String,
    pub memory_type: String,
    pub verdict: String,
    pub grounding_score: f64,
    pub previous_score: Option<f64>,
    pub score_delta: Option<f64>,
    pub generates_contradiction: bool,
    pub evidence: serde_json::Value,
    pub duration_ms: u32,
}

pub struct GroundMemoryTask {
    memory_id: String,
}

#[napi]
impl Task for GroundMemoryTask {
    type Output = NapiGroundingResult;
    type JsValue = NapiGroundingResult;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        let rt = BridgeRuntime::get()
            .map_err(|e| napi::Error::from_reason(format!("[BRIDGE_NOT_INITIALIZED] {e}")))?;

        let memory = rt.db.get_memory(&self.memory_id)
            .map_err(|e| napi::Error::from_reason(format!("[MEMORY_NOT_FOUND] {e}")))?;

        let result = rt.grounding.ground_memory(&memory)
            .map_err(|e| napi::Error::from_reason(format!("[GROUNDING_ERROR] {e}")))?;

        Ok(NapiGroundingResult {
            id: result.id,
            memory_id: result.memory_id,
            memory_type: format!("{:?}", result.memory_type),
            verdict: format!("{:?}", result.verdict),
            grounding_score: result.grounding_score,
            previous_score: result.previous_score,
            score_delta: result.score_delta,
            generates_contradiction: result.generates_contradiction,
            evidence: serde_json::to_value(&result.evidence).unwrap_or_default(),
            duration_ms: result.duration_ms,
        })
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> napi::Result<Self::JsValue> {
        Ok(output)
    }
}

#[napi]
pub fn bridge_ground_memory(memory_id: String) -> AsyncTask<GroundMemoryTask> {
    AsyncTask::new(GroundMemoryTask { memory_id })
}
```

---

## 22. Configuration (drift.toml [bridge] Section)

```toml
[bridge]
# Enable/disable the bridge. Default: true (auto-detect).
enabled = true

# Cortex database path. Default: .drift/memory/cortex.db
cortex_db_path = ".drift/memory/cortex.db"

# Drift database path. Default: .drift/drift.db
drift_db_path = ".drift/drift.db"

[bridge.event_mapping]
# Which Drift events create Cortex memories. See §6.3 for full list.
pattern_approved = true
pattern_discovered = false
pattern_ignored = true
pattern_merged = true
regression_detected = true
violation_dismissed = true
violation_fixed = true
gate_evaluated = false
detector_alert = true
detector_disabled = true
constraint_approved = true
constraint_violated = true
decision_mined = true
decision_reversed = true
adr_detected = true
boundary_discovered = false
enforcement_changed = true
feedback_abuse_detected = true

[bridge.grounding]
# Enable/disable the grounding feedback loop. Default: true.
enabled = true

# Maximum memories to ground per loop. Default: 500.
max_memories_per_loop = 500

# Grounding score thresholds.
[bridge.grounding.thresholds]
validated = 0.7     # Score >= this = Validated
partial = 0.4       # Score >= this = Partial
weak = 0.2          # Score >= this = Weak
                    # Score < weak = Invalidated

# Confidence adjustment parameters.
[bridge.grounding.adjustments]
boost_delta = 0.05          # Confidence boost for well-grounded memories
partial_penalty = 0.05      # Penalty for partially grounded
weak_penalty = 0.15         # Penalty for weakly grounded
invalidated_floor = 0.1     # Minimum confidence for invalidated memories
contradiction_drop = 0.3    # Score drop that triggers contradiction

[bridge.grounding.schedule]
# Run incremental grounding after every scan. Default: true.
incremental_after_scan = true
# Run full grounding every N scans. Default: 10.
full_grounding_interval = 10
# Run full grounding if more than N hours since last. Default: 24.
full_grounding_max_hours = 24
# Skip grounding if scan changed fewer than N files. Default: 0.
min_changed_files = 0

[bridge.intents]
# Enable code-specific intent extensions. Default: true.
enabled = true
# Which intents to register. Default: all.
intents = ["add_feature", "fix_bug", "refactor", "review_code", "debug",
           "optimize", "secure", "test", "document", "migrate"]

[bridge.mcp_tools]
# Enable bridge MCP tools. Default: true.
enabled = true
# Which tools to register. Default: all.
tools = ["drift_why", "drift_memory_learn", "drift_grounding_check"]
```

---

## 23. License Gating — Tier Mapping

| Feature | Community | Pro | Enterprise |
|---------|-----------|-----|-----------|
| Event mapping (basic: 5 events) | ✅ | ✅ | ✅ |
| Event mapping (full: 21 events) | ❌ | ✅ | ✅ |
| Link translation | ✅ | ✅ | ✅ |
| Grounding (manual, on-demand) | ✅ | ✅ | ✅ |
| Grounding (automatic, post-scan) | ❌ | ✅ | ✅ |
| Grounding (scheduled) | ❌ | ❌ | ✅ |
| Contradiction generation | ❌ | ✅ | ✅ |
| drift_why MCP tool | ✅ | ✅ | ✅ |
| drift_memory_learn MCP tool | ❌ | ✅ | ✅ |
| drift_grounding_check MCP tool | ✅ | ✅ | ✅ |
| Intent extensions | ❌ | ✅ | ✅ |
| Cross-DB ATTACH queries | ✅ | ✅ | ✅ |
| Grounding history (30 days) | ✅ | ✅ | ✅ |
| Grounding history (unlimited) | ❌ | ❌ | ✅ |
| Bridge metrics/observability | ❌ | ✅ | ✅ |
| Custom event mappings | ❌ | ❌ | ✅ |

Community tier gets the core value: basic event mapping, link translation, manual
grounding, and the drift_why tool. Pro unlocks automatic grounding and full event
mapping. Enterprise adds scheduled grounding, unlimited history, and custom mappings.

---

## 24. Observability & Tracing

Per AD10: Observability from the first line of code. The bridge emits structured
tracing events for all operations.

### 24.1 Key Metrics

| Metric | Subsystem | Why |
|--------|-----------|-----|
| `bridge.event_mapped_total` | Event Mapping | Count of events successfully mapped to memories |
| `bridge.event_mapped_errors` | Event Mapping | Count of event mapping failures |
| `bridge.event_mapping_duration_us` | Event Mapping | Per-event mapping latency |
| `bridge.grounding_score` | Grounding | Per-memory grounding score (histogram) |
| `bridge.grounding_duration_ms` | Grounding | Per-memory grounding latency |
| `bridge.grounding_loop_duration_ms` | Grounding | Full loop latency |
| `bridge.grounding_memories_checked` | Grounding | Memories checked per loop |
| `bridge.grounding_contradictions` | Grounding | Contradictions generated per loop |
| `bridge.confidence_adjustments` | Grounding | Adjustments applied per loop |
| `bridge.cross_db_query_duration_ms` | Database | Cross-DB query latency |
| `bridge.attach_status` | Database | ATTACH success/failure |
| `bridge.link_translations` | Links | Link translations per event |
| `bridge.memory_creations` | Memory | Memories created per event type |
| `bridge.memory_creation_errors` | Memory | Memory creation failures |

### 24.2 Tracing Spans

```rust
// Top-level spans
#[instrument(name = "bridge.event_handler")]
fn on_pattern_approved(&self, pattern: &Pattern) { ... }

#[instrument(name = "bridge.grounding_loop")]
fn execute_grounding_loop(&self) -> BridgeResult<GroundingSnapshot> { ... }

#[instrument(name = "bridge.ground_memory")]
fn ground_memory(&self, memory: &BaseMemory) -> BridgeResult<GroundingResult> { ... }

// Nested spans
let _evidence = info_span!("bridge.collect_evidence").entered();
let _score = info_span!("bridge.compute_score").entered();
let _adjust = info_span!("bridge.apply_adjustment").entered();
```


---

## 25. Integration with Upstream Systems (All Event Sources)

Every Drift subsystem that emits events via DriftEventHandler is an upstream source
for the bridge. This section maps each subsystem to the events it emits and how the
bridge consumes them.

### 25.1 Event Source Matrix

| Drift Subsystem | V2-Prep Doc | Events Emitted | Bridge Consumption |
|----------------|-------------|---------------|-------------------|
| Scanner | 00-SCANNER-V2-PREP | on_scan_started, on_scan_progress, on_scan_complete, on_scan_error | Triggers grounding loop on scan_complete |
| Pattern Aggregation | 12-PATTERN-AGGREGATION-V2-PREP | on_pattern_discovered, on_pattern_approved, on_pattern_ignored, on_pattern_merged | Creates PatternRationale, Insight, Feedback, DecisionContext memories |
| Violation Feedback | 31-VIOLATION-FEEDBACK-LOOP-V2-PREP | on_violation_detected, on_violation_dismissed, on_violation_fixed, on_enforcement_changed, on_feedback_abuse_detected | Creates ConstraintOverride, Feedback, DecisionContext, Tribal memories |
| Quality Gates | 09-QUALITY-GATES-V2-PREP | on_gate_evaluated, on_regression_detected | Creates DecisionContext memories |
| Detector Health | 31-VIOLATION-FEEDBACK-LOOP-V2-PREP | on_detector_alert, on_detector_disabled | Creates Tribal, CodeSmell memories |
| Constraint System | 20-CONSTRAINT-SYSTEM-V2-PREP | on_constraint_approved, on_constraint_violated | Creates ConstraintOverride, Feedback memories |
| Decision Mining | 29-DECISION-MINING-V2-PREP | on_decision_mined, on_decision_reversed, on_adr_detected | Creates DecisionContext memories |
| Boundary Detection | 07-BOUNDARY-DETECTION-V2-PREP | on_boundary_discovered | Creates Tribal memories |
| Error Handling | 16-ERROR-HANDLING-ANALYSIS-V2-PREP | (via pipeline error events) | Provides error handling gap evidence for grounding |
| Coupling Analysis | 19-COUPLING-ANALYSIS-V2-PREP | (via scan complete) | Provides coupling snapshot for grounding |
| DNA System | 24-DNA-SYSTEM-V2-PREP | (via scan complete) | Provides DNA health score for grounding |
| Test Topology | 18-TEST-TOPOLOGY-V2-PREP | (via scan complete) | Provides test coverage for grounding |

### 25.2 Cortex Upstream Sources

| Cortex Subsystem | Events Emitted | Bridge Consumption |
|-----------------|---------------|-------------------|
| Memory Creation | on_memory_created | Enriches with Drift entity links |
| Memory Update | on_memory_updated | Re-grounds updated memory |
| Memory Archive | on_memory_archived | Cleans up stale entity links |
| Consolidation | on_consolidation_complete | Re-grounds consolidated memories |
| Contradiction | on_contradiction_detected | Provides Drift evidence for resolution |

---

## 26. Integration with Downstream Consumers

### 26.1 MCP Server Integration

The drift-analysis MCP server detects the bridge at startup and conditionally
registers bridge tools:

```typescript
// In packages/mcp/src/servers/analysis/index.ts
import { bridgeIsAvailable, registerBridgeTools } from '../bridge';

export function createAnalysisServer(config: DriftConfig): McpServer {
    const server = new McpServer({ name: "drift-analysis" });

    // Register standard Drift tools...
    registerAnalysisTools(server);

    // Conditionally register bridge tools
    if (bridgeIsAvailable()) {
        registerBridgeTools(server);
        logger.info("Bridge tools registered: drift_why, drift_memory_learn, drift_grounding_check");
    }

    return server;
}
```

### 26.2 CLI Integration

```
drift bridge status          # Show bridge status (available/unavailable, grounding stats)
drift bridge ground          # Run full grounding loop
drift bridge ground <id>     # Ground specific memory
drift bridge history <id>    # Show grounding history for memory
drift bridge metrics         # Show bridge metrics
drift bridge why <query>     # CLI version of drift_why
drift bridge learn <content> # CLI version of drift_memory_learn
```

### 26.3 Cortex Validation Engine Integration

The bridge feeds grounding results into Cortex's existing 4-dimension validation
engine (06-cortex/validation.md). Specifically:

- **Pattern Alignment dimension**: Grounding replaces the heuristic pattern alignment
  check with empirical data from Drift. Instead of guessing if a memory aligns with
  patterns, the bridge provides actual pattern confidence scores.

- **Citation Validation dimension**: Grounding enhances citation validation by checking
  if linked files still contain the patterns/conventions the memory describes.

- **Contradiction Detection dimension**: Grounding generates contradictions when
  memories diverge from codebase reality, feeding directly into Cortex's contradiction
  resolution system.

---

## 27. Storage Schema (Bridge-Specific Tables)

The bridge creates its own tables in a separate bridge.db (or in cortex.db under
a `bridge_` prefix). These persist grounding results and history.

### 27.1 Tables

```sql
-- Grounding results (one row per memory per grounding check)
CREATE TABLE bridge_grounding_results (
    id TEXT PRIMARY KEY,
    memory_id TEXT NOT NULL,
    memory_type TEXT NOT NULL,
    verdict TEXT NOT NULL,           -- Validated, Partial, Weak, Invalidated, etc.
    grounding_score REAL NOT NULL,
    previous_score REAL,
    score_delta REAL,
    confidence_adjustment_mode TEXT NOT NULL,
    confidence_adjustment_delta REAL,
    confidence_adjustment_reason TEXT NOT NULL,
    generates_contradiction INTEGER NOT NULL DEFAULT 0,
    evidence TEXT NOT NULL,          -- JSON array of GroundingEvidence
    data_sources TEXT NOT NULL,      -- JSON array of GroundingDataSource
    checked_at TEXT NOT NULL DEFAULT (datetime('now')),
    duration_ms INTEGER NOT NULL
) STRICT;

CREATE INDEX idx_grounding_memory ON bridge_grounding_results(memory_id);
CREATE INDEX idx_grounding_verdict ON bridge_grounding_results(verdict);
CREATE INDEX idx_grounding_checked ON bridge_grounding_results(checked_at);
CREATE INDEX idx_grounding_score ON bridge_grounding_results(grounding_score);

-- Grounding snapshots (one row per grounding loop execution)
CREATE TABLE bridge_grounding_snapshots (
    id INTEGER PRIMARY KEY,
    total_checked INTEGER NOT NULL,
    validated INTEGER NOT NULL,
    partial INTEGER NOT NULL,
    weak INTEGER NOT NULL,
    invalidated INTEGER NOT NULL,
    not_groundable INTEGER NOT NULL,
    insufficient_data INTEGER NOT NULL,
    avg_grounding_score REAL NOT NULL,
    contradictions_generated INTEGER NOT NULL,
    flagged_for_review INTEGER NOT NULL,
    checked_at TEXT NOT NULL DEFAULT (datetime('now')),
    duration_ms INTEGER NOT NULL,
    trigger TEXT NOT NULL             -- 'scan_complete', 'scheduled', 'manual', 'memory_created'
) STRICT;

CREATE INDEX idx_snapshot_checked ON bridge_grounding_snapshots(checked_at);

-- Event mapping log (one row per event processed)
CREATE TABLE bridge_event_log (
    id INTEGER PRIMARY KEY,
    event_type TEXT NOT NULL,
    memory_type TEXT,
    memory_id TEXT,
    success INTEGER NOT NULL,
    error TEXT,
    duration_us INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

CREATE INDEX idx_event_log_type ON bridge_event_log(event_type);
CREATE INDEX idx_event_log_created ON bridge_event_log(created_at);

-- Bridge metrics (rolling window)
CREATE TABLE bridge_metrics (
    id INTEGER PRIMARY KEY,
    metric_name TEXT NOT NULL,
    metric_value REAL NOT NULL,
    recorded_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

CREATE INDEX idx_metrics_name ON bridge_metrics(metric_name);
CREATE INDEX idx_metrics_recorded ON bridge_metrics(recorded_at);
```

### 27.2 Retention Policy

| Table | Retention | Rationale |
|-------|-----------|-----------|
| bridge_grounding_results | 90 days (Community), unlimited (Enterprise) | Historical grounding data |
| bridge_grounding_snapshots | 365 days | Trend analysis |
| bridge_event_log | 30 days | Debugging, not long-term |
| bridge_metrics | 7 days | Rolling window metrics |

---

## 28. Performance Targets & Benchmarks

| Operation | Target | Rationale |
|-----------|--------|-----------|
| Event mapping (single event → memory) | <5ms | Must not slow Drift event dispatch |
| Link translation (batch of 100) | <1ms | Pure data transformation |
| Grounding (single memory) | <50ms | Includes drift.db query + scoring |
| Grounding loop (500 memories) | <10s | Background operation, not blocking |
| Cross-DB ATTACH | <1ms | One-time at startup |
| Cross-DB query (simple join) | <5ms | Same as single-DB query |
| Bridge initialization | <100ms | Includes ATTACH + table creation |
| drift_why MCP tool | <200ms | User-facing, includes both DB queries |
| drift_grounding_check (single) | <100ms | User-facing |
| drift_grounding_check (all) | <30s | Background, up to 500 memories |

### 28.1 Benchmark Strategy

```rust
#[cfg(test)]
mod benchmarks {
    use criterion::{criterion_group, criterion_main, Criterion};

    fn bench_event_mapping(c: &mut Criterion) {
        // Setup: create bridge with mock DBs
        c.bench_function("event_mapping_pattern_approved", |b| {
            b.iter(|| handler.on_pattern_approved(&test_pattern))
        });
    }

    fn bench_grounding_single(c: &mut Criterion) {
        c.bench_function("grounding_single_memory", |b| {
            b.iter(|| engine.ground_memory(&test_memory))
        });
    }

    fn bench_grounding_loop(c: &mut Criterion) {
        // Setup: 500 groundable memories, populated drift.db
        c.bench_function("grounding_loop_500", |b| {
            b.iter(|| engine.execute_grounding_loop())
        });
    }

    fn bench_link_translation(c: &mut Criterion) {
        c.bench_function("link_translation_100", |b| {
            b.iter(|| LinkTranslator::translate_all(&patterns, &constraints, &confidences))
        });
    }

    criterion_group!(benches,
        bench_event_mapping,
        bench_grounding_single,
        bench_grounding_loop,
        bench_link_translation,
    );
    criterion_main!(benches);
}
```

---

## 29. File / Module Structure

```
crates/cortex-drift/
├── cortex-drift-bridge/
│   ├── Cargo.toml
│   ├── src/
│   │   ├── lib.rs                      # Module declarations, public API
│   │   ├── runtime.rs                  # BridgeRuntime singleton (OnceLock<Arc<T>>)
│   │   ├── config.rs                   # BridgeConfig, GroundingConfig, EventMappingConfig
│   │   ├── errors.rs                   # BridgeError enum (thiserror)
│   │   ├── events/
│   │   │   ├── mod.rs                  # Re-exports
│   │   │   ├── drift_handler.rs        # DriftEventHandler implementation
│   │   │   ├── cortex_handler.rs       # CortexEventHandler implementation
│   │   │   ├── mapping.rs              # Event → Memory mapping logic
│   │   │   └── safe_handler.rs         # Panic-safe wrapper
│   │   ├── grounding/
│   │   │   ├── mod.rs                  # Re-exports
│   │   │   ├── engine.rs              # GroundingEngine (core algorithm)
│   │   │   ├── evidence.rs            # Evidence collection per data source
│   │   │   ├── scoring.rs             # Grounding score computation
│   │   │   ├── adjustment.rs          # Confidence adjustment algorithms
│   │   │   ├── contradiction.rs       # Contradiction generation
│   │   │   ├── scheduler.rs           # Grounding scheduling
│   │   │   ├── groundability.rs       # Memory type groundability classification
│   │   │   └── fuzzy.rs              # Fuzzy matching for unlinked memories
│   │   ├── links/
│   │   │   ├── mod.rs                  # Re-exports
│   │   │   ├── translator.rs          # LinkTranslator (PatternLink → EntityLink)
│   │   │   └── entity_link.rs         # EntityLink convenience constructors
│   │   ├── database/
│   │   │   ├── mod.rs                  # Re-exports
│   │   │   ├── bridge.rs             # DatabaseBridge (ATTACH lifecycle)
│   │   │   ├── cross_query.rs        # Cross-DB query utilities
│   │   │   ├── schema.rs             # Bridge-specific table creation
│   │   │   └── writer.rs             # CortexWriter (memory creation)
│   │   ├── intents/
│   │   │   ├── mod.rs                  # Re-exports
│   │   │   └── code_intents.rs        # Code-specific intent registration
│   │   ├── mcp/
│   │   │   ├── mod.rs                  # Re-exports
│   │   │   ├── why.rs                 # drift_why implementation
│   │   │   ├── learn.rs              # drift_memory_learn implementation
│   │   │   └── grounding_check.rs    # drift_grounding_check implementation
│   │   ├── metrics.rs                  # BridgeMetrics
│   │   └── types.rs                    # All bridge-specific types
│   ├── benches/
│   │   └── bridge_bench.rs            # Criterion benchmarks
│   └── tests/
│       ├── event_mapping_test.rs      # Event → memory mapping tests
│       ├── grounding_test.rs          # Grounding algorithm tests
│       ├── link_translation_test.rs   # Link translation tests
│       ├── cross_db_test.rs           # Cross-DB query tests
│       ├── degradation_test.rs        # Graceful degradation tests
│       └── integration_test.rs        # Full bridge integration tests
│
├── cortex-drift-napi/
│   ├── Cargo.toml
│   ├── build.rs
│   ├── package.json
│   └── src/
│       ├── lib.rs                      # Module declarations
│       ├── runtime.rs                  # NAPI runtime wrapper
│       └── bindings/
│           ├── mod.rs                  # Re-exports
│           ├── lifecycle.rs           # bridge_initialize, bridge_shutdown
│           ├── grounding.rs           # bridge_ground_memory, bridge_ground_all
│           ├── links.rs              # bridge_translate_links
│           ├── queries.rs            # bridge_memories_for_pattern, etc.
│           ├── tools.rs              # bridge_why, bridge_learn, bridge_grounding_check
│           └── metrics.rs            # bridge_get_metrics
│
└── cortex-drift-mcp/                  # TS package
    └── (see 32-MCP-SERVER-V2-PREP.md §3 for bridge tool registration)
```


---

## 30. Build Order & Dependency Chain

The bridge is the last thing built — it depends on both systems being complete.

### 30.1 Prerequisites

| Prerequisite | Crate | Status | Why Needed |
|-------------|-------|--------|-----------|
| cortex-core types | cortex-core | ✅ Built | BaseMemory, MemoryType, TypedContent, links |
| cortex-core traits | cortex-core | ✅ Built | CortexEventHandler |
| cortex storage | cortex-core | ✅ Built | cortex.db schema, memory CRUD |
| drift-core types | drift-core | 🔨 Building | Pattern, Violation, ScanDiff, Regression |
| drift-core traits | drift-core | 🔨 Building | DriftEventHandler |
| drift-core storage | drift-core | 🔨 Building | drift.db schema, pattern/violation tables |
| drift-core scanner | drift-core | 🔨 Building | ScanDiff for grounding triggers |
| drift-core detectors | drift-core | 🔨 Building | Pattern data for grounding |
| drift-core feedback | drift-core | 🔨 Building | Violation feedback for FP rates |
| drift-core constraints | drift-core | 🔨 Building | Constraint verification for grounding |
| drift-core coupling | drift-core | 🔨 Building | Coupling snapshots for grounding |
| drift-core DNA | drift-core | 🔨 Building | DNA health for grounding |

### 30.2 Build Phases

```
Phase 1: Foundation (no bridge dependency)
├── cortex-core types + traits          ✅ Complete
├── drift-core types + traits           🔨 In progress
├── drift-core DriftEventHandler        🔨 In progress
└── drift-core storage (drift.db)       🔨 In progress

Phase 2: Core Bridge (minimal viable bridge)
├── BridgeError types                   → errors.rs
├── BridgeConfig                        → config.rs
├── DatabaseBridge (ATTACH)             → database/bridge.rs
├── LinkTranslator                      → links/translator.rs
├── BridgeEventHandler (5 core events)  → events/drift_handler.rs
│   ├── on_pattern_approved → PatternRationale
│   ├── on_scan_complete → trigger grounding
│   ├── on_regression_detected → DecisionContext
│   ├── on_violation_dismissed → ConstraintOverride
│   └── on_detector_disabled → CodeSmell
├── BridgeRuntime                       → runtime.rs
└── Tests: event mapping, link translation, degradation

Phase 3: Grounding Engine
├── Groundability classifier            → grounding/groundability.rs
├── Evidence collection (patterns)      → grounding/evidence.rs
├── Grounding score computation         → grounding/scoring.rs
├── Confidence adjustment               → grounding/adjustment.rs
├── GroundingEngine.ground_memory()     → grounding/engine.rs
├── GroundingEngine.execute_loop()      → grounding/engine.rs
├── Grounding scheduler                 → grounding/scheduler.rs
├── Bridge-specific tables              → database/schema.rs
└── Tests: grounding algorithm, scoring, scheduling

Phase 4: Contradiction & Healing
├── Contradiction generation            → grounding/contradiction.rs
├── CortexEventHandler implementation   → events/cortex_handler.rs
├── Cortex validation integration       → (feeds into cortex-core validation)
└── Tests: contradiction generation, bidirectional events

Phase 5: Extended Events
├── Remaining 16 event mappings         → events/mapping.rs
│   ├── on_pattern_discovered → Insight
│   ├── on_pattern_ignored → Feedback
│   ├── on_pattern_merged → DecisionContext
│   ├── on_violation_fixed → Feedback
│   ├── on_gate_evaluated → DecisionContext
│   ├── on_detector_alert → Tribal
│   ├── on_constraint_approved → ConstraintOverride
│   ├── on_constraint_violated → Feedback
│   ├── on_decision_mined → DecisionContext
│   ├── on_decision_reversed → DecisionContext
│   ├── on_adr_detected → DecisionContext
│   ├── on_boundary_discovered → Tribal
│   ├── on_enforcement_changed → DecisionContext
│   └── on_feedback_abuse_detected → Tribal
├── Extended evidence collection        → grounding/evidence.rs
│   ├── Coupling evidence
│   ├── DNA evidence
│   ├── Test topology evidence
│   ├── Error handling evidence
│   ├── Constraint evidence
│   └── Decision evidence
└── Tests: all event mappings, all evidence types

Phase 6: MCP Tools & Intents
├── drift_why implementation            → mcp/why.rs
├── drift_memory_learn implementation   → mcp/learn.rs
├── drift_grounding_check implementation → mcp/grounding_check.rs
├── Code-specific intents               → intents/code_intents.rs
└── Tests: MCP tool handlers, intent registration

Phase 7: NAPI Bridge
├── cortex-drift-napi bindings          → cortex-drift-napi/
├── TypeScript bridge layer             → (in packages/drift)
└── Tests: NAPI function tests

Phase 8: Observability & Polish
├── BridgeMetrics                       → metrics.rs
├── Tracing spans                       → (throughout)
├── Benchmarks                          → benches/bridge_bench.rs
├── License gating                      → (throughout)
└── Integration tests                   → tests/integration_test.rs
```

---

## 31. Resolved Inconsistencies

Issues found across research documents, resolved here.

### 31.1 Memory Type for Detector Disabled

**Inconsistency**: 04-INFRASTRUCTURE-V2-PREP.md maps `on_detector_disabled` to
`anti_pattern`, but cortex-core's MemoryType enum has `CodeSmell`, not `AntiPattern`.
PLANNING-DRIFT.md D2 mentions renaming `code_smell` to `anti_pattern` for generality.

**Resolution**: Use `MemoryType::CodeSmell` (the actual enum variant). The rename to
`anti_pattern` is a future consideration per D2, not yet implemented. The bridge uses
the existing type and creates CodeSmellContent with anti-pattern semantics.

### 31.2 Bridge Tool Registration Location

**Inconsistency**: PLANNING-DRIFT.md D3 says bridge tools register on drift-analysis
server. 32-MCP-SERVER-V2-PREP.md confirms this. But some docs suggest a third MCP server.

**Resolution**: Per D3, bridge tools register conditionally on the drift-analysis server.
There is NO third MCP server. Two servers only: drift-analysis (standalone + conditional
bridge tools) and drift-memory (Cortex-dependent).

### 31.3 EntityLink Location

**Inconsistency**: PLANNING-DRIFT.md D2 says EntityLink moves to cortex-core. But the
current cortex-core has PatternLink/ConstraintLink/FileLink/FunctionLink, not EntityLink.

**Resolution**: EntityLink is a new type to be added to cortex-core as part of the D2
implementation. Until then, the bridge defines EntityLink locally and the cortex-core
migration happens separately. The bridge's EntityLink is designed to match the planned
cortex-core EntityLink exactly, so migration is a simple re-export.

### 31.4 Grounding Frequency

**Inconsistency**: PLANNING-DRIFT.md D7 lists "every scan? scheduled? on-demand?" as
open questions. Various v2-prep docs assume different frequencies.

**Resolution**: All three. Incremental grounding after every scan (low cost), full
grounding every 10th scan or 24 hours (medium cost), on-demand via MCP tool (user
controlled). Configurable in drift.toml [bridge.grounding.schedule].

### 31.5 Cross-DB Write Direction

**Inconsistency**: Some docs imply the bridge writes to drift.db.

**Resolution**: Per D6, the bridge NEVER writes to drift.db. It reads from drift.db
(via ATTACH or direct connection) and writes to cortex.db (memories, contradictions)
and bridge.db (grounding results, metrics). Drift owns drift.db exclusively.

### 31.6 CortexEventHandler Trait

**Inconsistency**: PLANNING-DRIFT.md D5 shows a CortexEventHandler trait, but the
current cortex-core doesn't define one.

**Resolution**: CortexEventHandler is a new trait to be added to cortex-core, following
the same pattern as DriftEventHandler (no-op defaults, Vec<Arc<dyn Handler>>). The
bridge implements it for bidirectional event flow. Until cortex-core adds the trait,
the bridge defines it locally.

---

## 32. V1 Feature Verification — Complete Gap Analysis

### 32.1 Features Preserved

| V1 Feature | V2 Status | Notes |
|-----------|-----------|-------|
| Pattern→memory creation | ✅ Preserved | Now event-driven via DriftEventHandler |
| PatternLink type | ✅ Preserved | Translated to EntityLink, original kept for compat |
| ConstraintLink type | ✅ Preserved | Translated to EntityLink, original kept for compat |
| FileLink type | ✅ Preserved | Stays in cortex-core unchanged |
| FunctionLink type | ✅ Preserved | Stays in cortex-core unchanged |
| PatternRationaleContent | ✅ Preserved | Bridge creates these from pattern events |
| ConstraintOverrideContent | ✅ Preserved | Bridge creates these from violation/constraint events |
| DecisionContextContent | ✅ Preserved | Bridge creates these from regression/decision events |
| CodeSmellContent | ✅ Preserved | Bridge creates these from detector disable events |
| drift_why MCP tool | ✅ Preserved | Upgraded with grounding data |
| Memory-pattern linking | ✅ Preserved | Upgraded to EntityLink system |
| Validation engine integration | ✅ Preserved | Upgraded with grounding-fed validation |
| Citation validation | ✅ Preserved | Enhanced by grounding |
| Pattern alignment check | ✅ Preserved | Replaced by empirical grounding |

### 32.2 Features Added (V2 Only)

| Feature | Justification |
|---------|--------------|
| Grounding feedback loop | D7 — the killer feature |
| 21 event mappings (was ~5 ad-hoc) | D5 — systematic event-driven architecture |
| EntityLink translation | D2 — generic linking system |
| CortexEventHandler (reverse flow) | Bidirectional integration |
| Cross-DB ATTACH queries | D6 — separate databases |
| Grounding scheduling | Automated maintenance |
| Contradiction from grounding | Self-healing memory |
| drift_grounding_check MCP tool | Explicit validation interface |
| drift_memory_learn MCP tool | Learn from corrections |
| Code-specific intents (10) | Enriched retrieval for code tasks |
| Bridge-specific persistence | Grounding history, metrics |
| License gating (3 tiers) | Commercial viability |
| Observability (tracing) | AD10 compliance |

### 32.3 Zero Feature Loss Verification

Every v1 integration point between Cortex and Drift is accounted for in v2.
No functionality is removed. All v1 capabilities are either preserved as-is or
upgraded with additional capabilities. The bridge crate unifies what was previously
scattered across multiple packages into a single, well-defined integration layer.

---

## 33. Research Grounding — External Sources

### 33.1 Primary Sources (Internal)

| Source | Contribution |
|--------|-------------|
| PLANNING-DRIFT.md (D1-D7) | All 7 foundational decisions |
| DRIFT-V2-STACK-HIERARCHY.md | Level 5B positioning, dependency truth |
| DRIFT-V2-FULL-SYSTEM-AUDIT.md | Bridge section, AD9, build order |
| 04-INFRASTRUCTURE-V2-PREP.md §4 | DriftEventHandler trait, event mapping table |
| 03-NAPI-BRIDGE-V2-PREP.md | Document structure template, NAPI patterns |
| 31-VIOLATION-FEEDBACK-LOOP-V2-PREP.md §22 | Feedback→memory mapping, grounding consumption |
| 20-CONSTRAINT-SYSTEM-V2-PREP.md §12.4 | Constraint→memory mapping |
| 29-DECISION-MINING-V2-PREP.md §17, §21 | Decision→memory mapping |
| 19-COUPLING-ANALYSIS-V2-PREP.md §23 | Coupling snapshot for grounding |
| 07-BOUNDARY-DETECTION-V2-PREP.md | Boundary→memory mapping |
| 32-MCP-SERVER-V2-PREP.md §3 | Bridge tool specifications |
| 06-cortex/validation.md | 4-dimension validation engine |
| 06-cortex/overview.md | Cortex architecture, memory lifecycle |
| cortex-core/src/memory/ | 23 MemoryType variants, BaseMemory, TypedContent |

### 33.2 External Sources

| Source | Year | Contribution |
|--------|------|-------------|
| [Sadowski et al. "Lessons from Building Static Analysis Tools at Google"](https://cacm.acm.org/magazines/2018/4/226371-lessons-from-building-static-analysis-tools-at-google/fulltext) | 2018 | Tricorder FP rate management, developer feedback loops |
| [Semgrep Assistant Memories](https://semgrep.dev/docs/semgrep-assistant/overview/) | 2025 | AI-powered FP triage with organizational memory |
| [EverMemOS](https://www.cnhinews.com/news/article_d10fc609-10d3-5923-b4d7-44cbda43d3fc.html) | 2026 | Self-organizing memory OS, episodic→semantic consolidation |
| [RTInsights "Why Agentic AI Needs Event-Driven Architecture"](https://www.rtinsights.com/beware-the-distributed-monolith-why-agentic-ai-needs-event-driven-architecture-to-avoid-a-repeat-of-the-microservices-disaster/) | 2026 | Event-driven architecture for AI agent systems |
| [Unite.AI "From LLM Commoditization to the Age of Agentic Memory"](https://www.unite.ai/2026-predictions-from-llm-commoditization-to-the-age-of-agentic-memory/) | 2026 | Agentic memory as competitive differentiator |
| [Towards Execution-Grounded Automated AI Research](https://arxiviq.substack.com/p/towards-execution-grounded-automated) | 2026 | Execution-grounded feedback loops for AI systems |
| [The Ralph Wiggum Loop](https://beuke.org/ralph-wiggum-loop/) | 2026 | Iterative agent feedback pattern |

Content was rephrased for compliance with licensing restrictions.

### 33.3 Key Insight from External Research

The bridge's grounding feedback loop is architecturally novel. While systems like
Semgrep Assistant Memories (2025) and EverMemOS (2026) provide AI memory persistence,
none implement empirical validation of memory claims against static analysis ground
truth. The closest analog is Google's Tricorder system, which uses developer feedback
to validate analysis quality — but Tricorder validates the analysis, not the memory.
The bridge inverts this: it uses analysis to validate the memory.

This positions the Drift+Cortex integration as the first system where AI memory is
not just persistent but empirically validated — beliefs are checked against codebase
reality on every scan cycle. This is the competitive moat.

---

*This document is the complete build specification for cortex-drift-bridge. All 6
bridge responsibilities are fully specified. All event mappings are defined. The
grounding feedback loop algorithm is complete. All Rust types are defined. All
integration points are documented. Every architectural decision is resolved.
Zero feature loss from v1. The killer integration feature — empirically validated
AI memory — is ready to build.*

*Build order: Phase 1 (foundation) → Phase 2 (core bridge) → Phase 3 (grounding) →
Phase 4 (contradictions) → Phase 5 (extended events) → Phase 6 (MCP tools) →
Phase 7 (NAPI) → Phase 8 (polish).*

*Drift computes. Bridge consumes. Cortex remembers. Reality validates.*
