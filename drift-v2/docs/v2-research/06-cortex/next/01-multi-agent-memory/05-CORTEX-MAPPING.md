# Mapping Multi-Agent Memory to Existing Cortex Architecture

## New Crates

### cortex-multiagent
Owns: namespace management, projection engine, subscription system, trust scoring,
cross-agent provenance, agent registry.

Dependencies: cortex-core, cortex-storage, cortex-session, cortex-causal

### cortex-crdt
Owns: CRDT implementations (G-Counter, LWW-Register, MV-Register, OR-Set, LWW-Map),
delta encoding/decoding, vector clocks, merge engine.

Dependencies: cortex-core (types only)

---

## Changes to Existing Crates

### cortex-core
- Add `AgentId` type (UUID-based)
- Add `NamespaceId` type (URI-based: `agent://`, `team://`, `project://`)
- Add `ProvenanceRecord`, `ProvenanceHop`, `ProvenanceAction` to models
- Add `CrossAgentRelation` to memory/relationships
- Extend `BaseMemory` with `namespace: NamespaceId` and `provenance: ProvenanceRecord`
- Add `IMultiAgentStorage` trait to traits module
- Add `MultiAgentConfig` to config module

### cortex-storage
- New migration: `v013_multiagent_tables.rs`
  - `agent_registry` table (agent_id, name, namespace, created_at, trust_score)
  - `memory_namespaces` table (namespace_id, type, owner_agent, permissions)
  - `memory_projections` table (source_ns, target_ns, filter_json, compression, live)
  - `provenance_log` table (memory_id, hop_index, agent_id, action, timestamp)
  - `agent_trust` table (agent_id, target_agent_id, trust_score, evidence_json)
  - `delta_queue` table (delta_id, source_agent, target_agent, delta_json, applied)
- New query module: `queries/multiagent_ops.rs`
- Extend `memory_crud.rs` with namespace-aware queries

### cortex-cloud
- Extend sync protocol to include agent identity
- Delta sync now carries agent provenance
- Conflict resolution considers agent trust scores

### cortex-session
- SessionContext gains `agent_id` field
- Session dedup is now per-agent within a namespace

### cortex-causal
- Extend CausalEdge with optional `source_agent` field
- New traversal: `trace_cross_agent` — follows provenance across agent boundaries
- New narrative template: cross-agent causal chains

### cortex-consolidation
- Cross-namespace consolidation: memories from multiple agents about the same topic
  can be consolidated into a team/project namespace memory
- Consensus detection: 3+ agents with similar memories → high-confidence team knowledge

### cortex-validation
- Cross-agent contradiction detection: Agent A says X, Agent B says not-X
- Trust-weighted contradiction resolution: higher-trust agent's memory wins by default

### cortex-napi
- New binding module: `bindings/multiagent.rs`
  - registerAgent, getAgentInfo, listAgents
  - createNamespace, shareMemory, projectMemories, retractMemory
  - getProvenance, traceCrossAgent
  - getTrust, updateTrust

### packages/cortex (TypeScript)
- New MCP tools:
  - `drift_agent_register` — register a new agent
  - `drift_agent_share` — share memory to namespace
  - `drift_agent_project` — create live projection
  - `drift_agent_provenance` — get provenance chain
  - `drift_agent_trust` — get/set trust scores

---

## Migration Path

### Phase A: Foundation (cortex-crdt + cortex-core changes)
1. Implement CRDT primitives in cortex-crdt
2. Add AgentId, NamespaceId, ProvenanceRecord to cortex-core
3. Add namespace field to BaseMemory (default: `agent://default/`)
4. All existing memories get default namespace — zero breaking changes

### Phase B: Storage + Namespace (cortex-storage + cortex-multiagent)
1. Run migration v013
2. Implement namespace-aware queries
3. Implement projection engine
4. Implement delta queue

### Phase C: Integration (all other crates)
1. Extend causal graph with cross-agent relations
2. Extend consolidation with cross-namespace merging
3. Extend validation with cross-agent contradiction detection
4. Wire up NAPI bindings and TypeScript tools

### Phase D: Trust + Provenance
1. Implement trust scoring
2. Implement provenance tracking
3. Implement correction propagation
4. Add audit trail entries

---

## Backward Compatibility

- Single-agent deployments work exactly as before
- Default namespace `agent://default/` is created automatically
- All existing APIs continue to work without namespace parameter
- Multi-agent features are opt-in: only activated when a second agent registers
- No performance overhead for single-agent: namespace checks are O(1) string comparison
