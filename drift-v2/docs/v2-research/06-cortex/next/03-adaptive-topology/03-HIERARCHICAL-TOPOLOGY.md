# Hierarchical Topology & Topic Taxonomies

## Why Hierarchy?

Flat community detection gives us clusters, but developers think hierarchically:
project → module → feature → implementation detail. We need to automatically discover
and maintain this hierarchy from the memory graph.

---

## Hierarchical Community Detection

### Recursive Leiden

Run Leiden at multiple resolutions to get nested communities:

1. **Level 0 (coarsest)**: 3-5 top-level domains (e.g., "Backend", "Frontend", "DevOps")
2. **Level 1**: 10-20 modules within each domain (e.g., "Auth", "Payments", "API")
3. **Level 2**: 30-50 features within each module (e.g., "OAuth flow", "JWT validation")
4. **Level 3 (finest)**: Individual memory clusters

The Leiden algorithm's aggregation phase naturally produces this hierarchy — each
aggregation step creates a coarser level.

### Resolution Parameter

Leiden's resolution parameter γ controls granularity:
- γ < 1: fewer, larger communities (coarse)
- γ = 1: standard modularity optimization
- γ > 1: more, smaller communities (fine)

Run at multiple γ values: [0.25, 0.5, 1.0, 2.0] to get 4 hierarchy levels.

---

## Automatic Taxonomy Construction

Research on automatic taxonomy construction from text corpora provides algorithms
for building hierarchical topic structures.

### GraBTax Approach (adapted)

The GraBTax algorithm constructs topic-dependent taxonomies by:
1. Extracting topical terms and relationships from a corpus
2. Constructing a weighted graph of topics and associations
3. Using subsumption relations to build hierarchy (general → specific)

Source: [GraBTax — arXiv:1307.1718](https://ar5iv.labs.arxiv.org/html/1307.1718)

### Adapted for Cortex

Instead of extracting terms from text, we use our existing structure:

1. **Tags as topics**: Memory tags form the initial topic vocabulary
2. **Co-occurrence as association**: Tags that frequently co-occur are related
3. **Subsumption from hierarchy**: If all memories tagged "OAuth" are also tagged "Auth",
   then "OAuth" is a subtopic of "Auth"
4. **Embedding-based generality**: More general concepts have embeddings closer to the
   centroid of their subtopics

### Subsumption Detection

```rust
fn is_subtopic(candidate: &str, parent: &str, memories: &[BaseMemory]) -> bool {
    let candidate_set: HashSet<MemoryId> = memories.iter()
        .filter(|m| m.tags.contains(candidate))
        .map(|m| m.id.clone())
        .collect();
    
    let parent_set: HashSet<MemoryId> = memories.iter()
        .filter(|m| m.tags.contains(parent))
        .map(|m| m.id.clone())
        .collect();
    
    // candidate is a subtopic of parent if most candidate memories are also in parent
    let overlap = candidate_set.intersection(&parent_set).count();
    let ratio = overlap as f64 / candidate_set.len() as f64;
    
    ratio > 0.7 && candidate_set.len() < parent_set.len()
}
```

---

## Knowledge Tree Structure

```rust
struct KnowledgeTree {
    root: KnowledgeNode,
}

struct KnowledgeNode {
    /// Auto-generated or tag-derived label
    label: String,
    /// Community ID at this level
    community_id: Option<CommunityId>,
    /// Memories directly in this node (not in children)
    direct_memories: Vec<MemoryId>,
    /// Total memories in this subtree
    total_memories: usize,
    /// Average confidence in this subtree
    avg_confidence: f64,
    /// Children (subtopics)
    children: Vec<KnowledgeNode>,
    /// Depth in the tree (0 = root)
    depth: usize,
    /// Associated files
    files: Vec<String>,
    /// Health score for this subtree
    health: SubtreeHealth,
}

struct SubtreeHealth {
    /// Are memories in this subtree well-maintained?
    avg_confidence: f64,
    /// How many memories are stale (low confidence, old)?
    stale_count: usize,
    /// How many contradictions exist in this subtree?
    contradiction_count: usize,
    /// Coverage: memories per file in this subtree
    coverage_ratio: f64,
    /// Is this subtree growing, stable, or shrinking?
    trend: GrowthTrend,
}

enum GrowthTrend {
    Growing { rate: f64 },  // memories/week
    Stable,
    Shrinking { rate: f64 },
}
```

### Example Knowledge Tree

```
Project: my-app (847 memories)
├── Backend (412 memories, avg conf: 0.78)
│   ├── Auth (89 memories, avg conf: 0.85) ← healthy
│   │   ├── OAuth (34 memories)
│   │   ├── JWT (28 memories)
│   │   └── Session Management (27 memories)
│   ├── Payments (12 memories, avg conf: 0.45) ← KNOWLEDGE GAP
│   │   └── Stripe Integration (12 memories)
│   ├── API (156 memories, avg conf: 0.72)
│   │   ├── REST Endpoints (89 memories)
│   │   ├── GraphQL (42 memories)
│   │   └── Rate Limiting (25 memories)
│   └── Database (155 memories, avg conf: 0.81)
│       ├── Migrations (67 memories)
│       ├── Query Optimization (48 memories)
│       └── Connection Pooling (40 memories)
├── Frontend (298 memories, avg conf: 0.71)
│   ├── Components (134 memories)
│   ├── State Management (89 memories)
│   └── Routing (75 memories)
└── DevOps (137 memories, avg conf: 0.68)
    ├── CI/CD (78 memories)
    ├── Monitoring (34 memories)
    └── Infrastructure (25 memories)
```

---

## Navigable Knowledge Map

The hierarchy enables navigation-style queries:

```rust
enum NavigationQuery {
    /// "What do we know about auth?"
    BrowseTopic { path: Vec<String> },
    /// "Show me the top-level knowledge domains"
    ListDomains,
    /// "What's under Backend > API?"
    ListChildren { path: Vec<String> },
    /// "Where does memory M fit in the hierarchy?"
    LocateMemory { memory_id: MemoryId },
    /// "What topics are related to Auth?"
    RelatedTopics { path: Vec<String> },
}
```

This is exposed through MCP tools and CLI, giving developers a way to explore
their knowledge base like a file system.

---

## Hierarchy Maintenance

The hierarchy is not static — it evolves as memories are created, consolidated,
and archived.

### Rebuild Triggers

- **Periodic**: Full rebuild weekly (Leiden is fast enough)
- **Incremental**: On significant graph changes (>10% of edges modified)
- **On-demand**: User requests a refresh

### Incremental Updates

For small changes (new memory added, memory archived), we can update the hierarchy
incrementally:

1. Determine which community the new/removed memory belongs to
2. Recalculate community metadata (label, confidence, health)
3. Check if the community should split or merge
4. Update the tree structure

Full Leiden re-run only needed when incremental updates accumulate beyond a threshold.
