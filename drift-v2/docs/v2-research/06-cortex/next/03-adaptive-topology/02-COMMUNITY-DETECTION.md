# Community Detection Algorithms

## What is Community Detection?

Community detection identifies groups of nodes that are more densely connected to each
other than to the rest of the network. In Cortex terms: clusters of memories that form
coherent knowledge domains.

---

## The Leiden Algorithm (Recommended)

The Leiden algorithm is the state-of-the-art for community detection, improving on the
widely-used Louvain method. It optimizes modularity — a measure of how well a network
is divided into communities.

### Why Leiden over Louvain?

Louvain has two known issues:
1. **Poorly connected communities**: Louvain can produce communities that are internally
   disconnected (nodes in the same community with no path between them)
2. **Resolution limit**: Small communities can be missed when the network is large

Leiden fixes both by adding a refinement phase that ensures all communities are
well-connected.

Source: [Leiden Algorithm — WikiMili](https://wikimili.com/en/Leiden_algorithm)

### Algorithm Overview

1. **Local moving phase**: Each node is moved to the community that maximizes modularity
2. **Refinement phase**: Communities are refined to ensure internal connectivity
3. **Aggregation phase**: Communities become super-nodes, edges between communities
   become weighted edges between super-nodes
4. **Repeat** until modularity converges

Complexity: O(n log n) for sparse graphs — fast enough for our scale.

Source: [Fast Leiden Algorithm — ACM](https://dl.acm.org/doi/fullHtml/10.1145/3673038.3673146)

---

## Modularity Function for Cortex

Standard modularity measures edge density within vs. between communities. For Cortex,
we need a weighted, multi-relational modularity:

### Edge Weights

Not all relationships are equal. Weight the edges:

| Relationship Type | Weight | Rationale |
|---|---|---|
| causal (caused, enabled) | 1.0 | Strongest signal of relatedness |
| supports | 0.8 | Strong agreement |
| contradicts | 0.6 | Still related, just opposing |
| derived_from | 0.7 | Direct lineage |
| references | 0.4 | Weak reference |
| shared_file | 0.5 | Co-location signal |
| shared_pattern | 0.6 | Shared abstraction |
| embedding_similarity > 0.8 | 0.3 | Semantic relatedness |

### Multi-Relational Modularity

```
Q = (1/2m) Σ_ij [A_ij - (k_i × k_j)/(2m)] × δ(c_i, c_j)

Where:
  A_ij = weighted adjacency (sum of edge weights between i and j)
  k_i = weighted degree of node i
  m = total edge weight
  c_i = community assignment of node i
  δ = 1 if same community, 0 otherwise
```

---

## Dynamic Community Detection

Knowledge graphs evolve over time. Communities form, merge, split, and dissolve.
We need to track community evolution, not just detect communities at a single point.

### Temporal Community Tracking

Research on tracking communities in evolving networks shows that combining spatial
structure (GCN) with temporal dynamics (GRU) effectively captures community evolution.

Source: [GTENN — arXiv:2501.12208](https://arxiv.org/abs/2501.12208)

For Cortex, a simpler approach:

1. Run Leiden periodically (daily or on significant graph changes)
2. Match new communities to previous communities using Jaccard similarity
3. Track community lifecycle events:

```rust
enum CommunityEvent {
    /// New community formed
    Formed { community_id: CommunityId, members: Vec<MemoryId> },
    /// Community grew (new members added)
    Grew { community_id: CommunityId, new_members: Vec<MemoryId> },
    /// Community shrank (members left or archived)
    Shrank { community_id: CommunityId, lost_members: Vec<MemoryId> },
    /// Two communities merged
    Merged { from: Vec<CommunityId>, into: CommunityId },
    /// Community split into multiple
    Split { from: CommunityId, into: Vec<CommunityId> },
    /// Community dissolved (all members archived or reassigned)
    Dissolved { community_id: CommunityId },
}
```

### Community Matching Between Runs

```
match_communities(old_communities, new_communities):
    for each new_community N:
        for each old_community O:
            jaccard = |N ∩ O| / |N ∪ O|
            if jaccard > 0.5:
                N is a continuation of O
            elif jaccard > 0.2:
                N partially overlaps O (possible merge/split)
    
    unmatched new = Formed events
    unmatched old = Dissolved events
    multiple matches = Merged or Split events
```

---

## Community Metadata

Each detected community gets rich metadata:

```rust
struct KnowledgeCommunity {
    id: CommunityId,
    /// Auto-generated label from most frequent terms/tags
    label: String,
    /// Member memories
    members: Vec<MemoryId>,
    /// Hub memories (highest degree within community)
    hubs: Vec<MemoryId>,
    /// Bridge memories (connect this community to others)
    bridges: Vec<MemoryId>,
    /// Dominant memory types in this community
    dominant_types: Vec<(MemoryType, f64)>,
    /// Average confidence of members
    avg_confidence: f64,
    /// Internal modularity (how tightly connected)
    internal_density: f64,
    /// External connections (how connected to other communities)
    external_connections: usize,
    /// Files most associated with this community
    associated_files: Vec<String>,
    /// When this community first formed
    formed_at: DateTime<Utc>,
    /// Stability score (how much has membership changed recently)
    stability: f64,
}
```

### Auto-Labeling Communities

Generate human-readable labels from community content:

1. Extract TF-IDF key terms from all member memories' content
2. Find most common tags across members
3. Find most common linked files/patterns
4. Combine: "Auth & Security (12 memories, 3 patterns)"

This reuses our existing TF-IDF implementation from cortex-consolidation.

---

## Integration with Retrieval

Community structure improves retrieval:

1. **Community-aware search**: When searching, boost results from the same community
   as the query context
2. **Community expansion**: If results are sparse, expand to neighboring communities
3. **Cross-community bridging**: Highlight bridge memories that connect the query's
   community to other relevant communities
4. **Community-based budget allocation**: Allocate more token budget to the most
   relevant community, less to peripheral communities
