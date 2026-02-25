# Cortex Next: Three Features to Best-in-Class

> These three features transform Cortex from an excellent single-agent memory system
> into the definitive AI-to-human knowledge persistence platform.

## Build Order

| # | Feature | New Crates | Differentiation | Research Depth |
|---|---------|-----------|-----------------|----------------|
| 1 | [Multi-Agent Memory](./01-multi-agent-memory/) | cortex-multiagent, cortex-crdt | Highest — nobody has this | CRDT theory, BMAM, LatentMem |
| 2 | [Temporal Reasoning](./02-temporal-reasoning/) | cortex-temporal | High — builds on existing bitemporal | XTDB, event sourcing, temporal DB theory |
| 3 | [Adaptive Topology](./03-adaptive-topology/) | cortex-topology | Deepest moat — most research-heavy | Scale-free networks, Leiden, SOC theory |

## Why This Order

1. **Multi-Agent first**: The market is moving to multi-agent fast (Gartner: 60% of
   enterprise AI workloads will use multi-agent by 2027). First mover advantage is real.
   Also unblocks the most new use cases.

2. **Temporal Reasoning second**: Builds on existing bitemporal fields and versioning
   system. Moderate implementation effort with high value — decision replay alone is
   a killer feature for regulated environments.

3. **Adaptive Topology third**: Most research-heavy, requires the other two to be
   maximally useful (temporal topology evolution needs temporal reasoning; multi-agent
   topology needs multi-agent memory). Creates the deepest long-term moat.

## Total New Crates: 4

- `cortex-crdt` — CRDT primitives (G-Counter, LWW-Register, OR-Set, etc.)
- `cortex-multiagent` — Namespace management, projections, trust, provenance
- `cortex-temporal` — Event store, temporal queries, drift detection
- `cortex-topology` — Community detection, hierarchy, gaps, hotspots

## Total New Storage Migrations: 3

- `v013_multiagent_tables.rs`
- `v014_temporal_tables.rs`
- `v015_topology_tables.rs`

## Research Sources Summary

### Multi-Agent Memory
- BMAM (arXiv:2601.20465) — brain-inspired multi-agent memory subsystems
- LatentMem (HuggingFace 2602.03036) — customizable agent-specific memory
- MIRIX (arXiv:2507.07957) — six-type multi-agent memory system
- Mem0 (arXiv:2504.19413) — production-ready long-term memory with graph
- CRDT theory (ACM 10.1145/3695249) — conflict-free replicated data types
- Delta-state CRDTs (arXiv:1410.2803) — efficient state-based convergence

### Temporal Reasoning
- XTDB v2 — bitemporal SQL database design patterns
- Bitemporal consistency patterns — temporal referential integrity
- Event sourcing with SQLite — append-only event stores
- Complementary Learning Systems — hippocampus-neocortex memory consolidation
- T-GRAG (arXiv:2508.01680) — temporal knowledge graph for retrieval

### Adaptive Topology
- Self-Organizing Knowledge Networks (arXiv:2502.13025) — scale-free emergence
- Self-Organized Criticality (arXiv:2503.18852) — critical discovery parameter
- Leiden algorithm — state-of-the-art community detection
- LeanRAG (arXiv:2508.10391) — semantic aggregation + hierarchical retrieval
- Knowledge Graph Completion — gap detection and link prediction
- GraBTax (arXiv:1307.1718) — automatic taxonomy construction
