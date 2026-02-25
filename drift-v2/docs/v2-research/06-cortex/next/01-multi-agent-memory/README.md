# Feature 1: Multi-Agent Memory Sharing & Collaboration Protocol

> Status: Research Phase
> Priority: #1 (highest differentiation, market moving fast)
> Estimated New Crates: 2 (cortex-multiagent, cortex-crdt)
> Dependencies: cortex-core, cortex-storage, cortex-cloud, cortex-session

## The Problem

Cortex is currently a single-agent brain. One agent, one memory store, one namespace.
But the future of AI is multi-agent: agents spawning agents, teams of specialized agents
collaborating on the same codebase, and orchestrators coordinating swarms.

Without shared memory:
- Agent A learns a pattern, Agent B repeats the same mistake
- Two agents working on the same module create contradictory memories
- No provenance chain when Agent B acts on knowledge from Agent A
- Spawned sub-agents start from zero context every time

## What This Enables

- Agents share selective memory slices in real-time
- Knowledge converges across agents without coordination overhead
- Full provenance: trace any decision through the agent collaboration chain
- Spawned agents inherit relevant context from their parent

## Research Documents

| File | Topic |
|------|-------|
| [01-PRIOR-ART.md](./01-PRIOR-ART.md) | Existing systems: BMAM, LatentMem, MIRIX, Mem0, Blackboard |
| [02-CRDT-FOUNDATIONS.md](./02-CRDT-FOUNDATIONS.md) | CRDT theory for conflict-free memory convergence |
| [03-NAMESPACE-DESIGN.md](./03-NAMESPACE-DESIGN.md) | Memory namespace architecture and projection model |
| [04-PROVENANCE-CHAINS.md](./04-PROVENANCE-CHAINS.md) | Causal provenance across agent boundaries |
| [05-CORTEX-MAPPING.md](./05-CORTEX-MAPPING.md) | How this maps to existing Cortex architecture |
