# Mapping Adaptive Topology to Existing Cortex Architecture

## New Crate

### cortex-topology
Owns: community detection (Leiden), hierarchical clustering, knowledge tree construction,
centrality computation, gap detection, hotspot tracking, workflow discovery,
self-pruning topology maintenance.

Dependencies: cortex-core, cortex-storage, cortex-causal, cortex-embeddings,
cortex-observability

External deps: petgraph (already in workspace via cortex-causal), possibly
`leiden` or custom Leiden implementation

---

## Changes to Existing Crates

### cortex-core
- Add `CommunityId` type
- Add models: `KnowledgeCommunity`, `KnowledgeTree`, `KnowledgeNode`, `SubtreeHealth`
- Add models: `KnowledgeGap`, `StructuralHole`, `AttentionHotspot`, `DiscoveredWorkflow`
- Add models: `ComputedImportance` (PageRank + betweenness + eigenvector)
- Add `ITopologyEngine` trait to traits module
- Add `TopologyConfig` to config module (Leiden resolution params, rebuild frequency,
  gap thresholds, hotspot thresholds)

### cortex-storage
- New migration: `v015_topology_tables.rs`
  - `knowledge_communities` table (id, label, members JSON, hubs, bridges, metadata)
  - `knowledge_tree` table (node_id, parent_id, label, depth, community_id, stats)
  - `computed_importance` table (memory_id, pagerank, betweenness, eigenvector, composite)
  - `knowledge_gaps` table (target, severity, missing_types, suggestions)
  - `attention_hotspots` table (target, temperature, trend, last_updated)
  - `discovered_workflows` table (type_sequence, occurrence_count, confidence)
- New query module: `queries/topology_ops.rs`

### cortex-causal
- Expose graph structure for centrality computation
- New method: `get_adjacency_matrix()` — for Leiden input
- New method: `get_edge_weights()` — weighted adjacency for modularity

### cortex-retrieval
- Community-aware search boosting
- Cross-community bridge highlighting in results
- Community-based budget allocation in generation context

### cortex-consolidation
- Community-aware consolidation: prefer consolidating within communities
- Cross-community consolidation creates bridge memories

### cortex-observability
- New metrics: community count, avg community size, modularity score
- New metrics: gap count by severity, hotspot count
- New health check: topology health (is the graph well-structured?)
- Topology metrics in health report

### cortex-decay
- Computed importance feeds into decay resistance
- Hub memories get additional decay protection
- Bridge memories get additional decay protection

### cortex-napi
- New binding module: `bindings/topology.rs`
  - getKnowledgeTree, getCommunities, getCommunity
  - getGaps, getHotspots, getWorkflows
  - getComputedImportance, getCentrality
  - rebuildTopology, refreshHotspots

### packages/cortex (TypeScript)
- New MCP tools:
  - `drift_topology_tree` — browse knowledge hierarchy
  - `drift_topology_gaps` — show knowledge gaps
  - `drift_topology_hotspots` — show attention heat map
  - `drift_topology_communities` — list knowledge communities
  - `drift_topology_importance` — computed importance for a memory
- New CLI commands:
  - `drift cortex tree` — print knowledge tree
  - `drift cortex gaps` — list knowledge gaps
  - `drift cortex hotspots` — show hotspot map

---

## Computation Schedule

Topology analysis is computationally heavier than other Cortex operations. Schedule:

| Operation | Frequency | Estimated Time (10K memories) |
|---|---|---|
| Leiden community detection | Daily or on 10% graph change | ~500ms |
| Centrality computation (PageRank) | Daily | ~200ms |
| Centrality computation (betweenness) | Weekly | ~2s |
| Knowledge tree construction | After Leiden runs | ~100ms |
| Gap detection | Daily | ~300ms |
| Hotspot calculation | Hourly | ~50ms |
| Workflow discovery | Weekly | ~1s |
| Full topology rebuild | Weekly | ~5s total |

All operations run in background, never blocking foreground queries.

---

## Migration Path

### Phase A: Community Detection
1. Implement Leiden algorithm (or integrate existing Rust implementation)
2. Build community detection on top of cortex-causal's graph
3. Implement community metadata computation
4. Store communities in new table

### Phase B: Hierarchy + Centrality
1. Implement multi-resolution Leiden for hierarchy
2. Build knowledge tree from hierarchical communities
3. Implement PageRank, betweenness, eigenvector centrality
4. Compute and store `ComputedImportance` for all memories

### Phase C: Gap Detection + Hotspots
1. Implement coverage ratio calculation
2. Implement structural hole detection
3. Implement orphan detection
4. Implement attention hotspot tracking
5. Wire gap alerts into observability

### Phase D: Self-Organization
1. Implement workflow discovery
2. Implement topology-aware retrieval boosting
3. Implement topology-aware decay resistance
4. Implement self-pruning (weak edges, isolated nodes)
5. Wire computed importance into existing ranking/decay systems

---

## Backward Compatibility

- All existing functionality works without topology analysis
- Topology is computed in background and cached
- If topology hasn't been computed yet, all queries fall back to current behavior
- Computed importance supplements (doesn't replace) declared importance
- Community labels are auto-generated but can be overridden by users
- No changes to existing APIs — topology is additive only
