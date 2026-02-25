# Self-Organizing Knowledge Networks

## Scale-Free Networks

Real-world knowledge networks are not random — they exhibit scale-free properties where
a few "hub" nodes have many connections while most nodes have few. This follows a
power-law degree distribution: P(k) ~ k^(-γ), typically with γ between 2 and 3.

### The Barabási-Albert Model

Scale-free networks emerge from two mechanisms:
1. **Growth**: New nodes are continuously added to the network
2. **Preferential attachment**: New nodes prefer to connect to already well-connected nodes

In Cortex terms:
- New memories are continuously created (growth)
- New memories naturally link to important, well-connected memories (preferential attachment)
- Result: some memories become "hub" concepts that connect many others

Source: [Bianconi-Barabási model — Wikipedia](https://en.wikipedia.org/wiki/Bianconi%E2%80%93Barab%C3%A1si_model)

### Why This Matters for Cortex

If our knowledge graph is scale-free (which it likely is), then:
- **Hub identification** is critical: hubs are the most important memories
- **Hub failure** is catastrophic: if a hub memory is archived or contradicted, many
  dependent memories lose context
- **Bridge nodes** connect different knowledge domains — they're the cross-cutting concerns
- **Small-world property**: any two memories are connected by a short path through hubs

---

## Agentic Self-Organizing Knowledge Networks (2025)

A landmark paper from Buehler (2025) demonstrates that when an LLM iteratively builds
a knowledge graph through a feedback-driven loop, the resulting network spontaneously
organizes into a scale-free structure with:

- **Hub formation**: Highly connected concept nodes emerge naturally
- **Stable modularity**: Distinct knowledge clusters form and stabilize
- **Bridging nodes**: Nodes that link disparate clusters, enabling cross-domain reasoning
- **Open-ended growth**: New nodes and edges continue appearing without saturation

Key finding: The system organizes information without explicit clustering algorithms.
The structure emerges from the iterative reasoning process itself.

Source: [arXiv:2502.13025](https://arxiv.org/abs/2502.13025) — Buehler, 2025

### Application to Cortex

Cortex already has the iterative loop:
- Memories are created → linked → consolidated → validated → decayed
- Causal inference adds edges based on semantic similarity, temporal proximity, etc.
- Consolidation merges related memories, creating new hub-like semantic memories

What we're missing: explicit detection and tracking of the emergent structure.
We need to measure and leverage what's already forming organically.

---

## Self-Organized Criticality in Knowledge Networks (2025)

A follow-up paper demonstrates that self-organizing knowledge graphs evolve toward a
"critical state" that sustains continuous discovery. Key findings:

- **Critical Discovery Parameter (D ≈ -0.03)**: A dimensionless parameter that stabilizes,
  indicating the system maintains a consistent excess of semantic entropy over structural
  entropy
- **~12% "surprising" edges**: Links between semantically distant concepts that drive
  cross-domain innovation
- **Scale-free + small-world**: The topology exhibits both properties simultaneously
- **Negative cross-correlation**: When structural entropy increases, semantic entropy
  decreases, and vice versa — the system self-regulates

Source: [arXiv:2503.18852](https://arxiv.org/abs/2503.18852) — 2025

### Application to Cortex

We can compute these metrics for our knowledge graph:
- **Structural entropy** (Von Neumann graph entropy): measures topological complexity
- **Semantic entropy** (embedding diversity): measures content diversity
- **Critical Discovery Parameter**: if D stabilizes near -0.03, our graph is healthy
- **Surprising edge fraction**: if <5%, the graph is too insular; if >20%, too noisy

These become health metrics in our observability system.

---

## Centrality Measures for Knowledge Importance

### Degree Centrality
Number of connections. Simple but effective for identifying hubs.
In Cortex: memories with many relationships, links, and causal edges.

### Betweenness Centrality
How often a node lies on the shortest path between other nodes. Identifies bridges
that connect different knowledge domains.
In Cortex: memories that connect auth knowledge to security knowledge, for example.

### PageRank
Recursive importance: a node is important if important nodes point to it.
In Cortex: a memory is important if other important memories reference it.
This is more nuanced than our current `importance` field (which is manually set).

### Eigenvector Centrality
Similar to PageRank but considers the quality of connections, not just quantity.
In Cortex: a memory connected to high-confidence memories is more important than
one connected to low-confidence memories.

Source: [Cambridge Intelligence — Centrality Measures](https://cambridge-intelligence.com/keylines-faqs-social-network-analysis/)

### Bridgeness Score
Specifically designed to distinguish bridges from hubs (betweenness conflates them).
A bridge connects communities; a hub is central within a community.

Source: [Detecting Global Bridges in Networks](https://www.researchgate.net/publication/278029981_Detecting_global_bridges_in_networks)

---

## Computed Importance vs. Declared Importance

Currently, Cortex has a manually-set `importance` field (low/normal/high/critical).
With topology analysis, we can compute importance from the graph structure:

```rust
struct ComputedImportance {
    /// Manual importance (user-set)
    declared: Importance,
    /// PageRank-derived importance
    pagerank: f64,
    /// Betweenness centrality (bridge score)
    betweenness: f64,
    /// Eigenvector centrality (quality-weighted connections)
    eigenvector: f64,
    /// Combined score
    composite: f64,
}

// Composite = 0.3 × declared_weight + 0.3 × pagerank + 0.2 × betweenness + 0.2 × eigenvector
```

This composite score feeds into:
- Retrieval ranking (more important memories rank higher)
- Decay resistance (more important memories decay slower)
- Consolidation priority (more important clusters consolidate first)
- Archival protection (high composite score = harder to archive)
