# Causal Provenance Across Agent Boundaries

## The Problem

When Agent B makes a decision based on knowledge that originated from Agent A, we need
to trace that lineage. This is critical for:

1. **Debugging**: "Why did the code reviewer miss this?" → trace back to which agent's
   memory influenced the review
2. **Trust calibration**: If Agent A's memories are frequently wrong, downstream agents
   should discount knowledge from that source
3. **Accountability**: In regulated environments, every AI decision needs an audit trail
4. **Learning**: If a decision was wrong, propagate the correction back through the chain

---

## Provenance Model

### ProvenanceRecord

```rust
struct ProvenanceRecord {
    /// The memory this provenance is about
    memory_id: MemoryId,
    /// Where this memory originated
    origin: ProvenanceOrigin,
    /// Chain of transformations this memory went through
    chain: Vec<ProvenanceHop>,
    /// Confidence in the provenance chain itself
    chain_confidence: f64,
}

enum ProvenanceOrigin {
    /// Created directly by a human
    Human { user_id: String },
    /// Created by an agent from scratch
    AgentCreated { agent_id: AgentId, session_id: String },
    /// Derived from other memories
    Derived { source_memories: Vec<MemoryId> },
    /// Imported from external source
    Imported { source: String },
    /// Received via projection from another agent
    Projected { source_agent: AgentId, source_memory: MemoryId },
}

struct ProvenanceHop {
    /// Agent that performed this transformation
    agent_id: AgentId,
    /// What happened
    action: ProvenanceAction,
    /// When
    timestamp: DateTime<Utc>,
    /// Confidence delta from this hop
    confidence_delta: f64,
}

enum ProvenanceAction {
    Created,
    SharedTo { target: NamespaceId },
    ProjectedTo { target: NamespaceId, compression: CompressionLevel },
    MergedWith { other_memory: MemoryId },
    ConsolidatedFrom { source_memories: Vec<MemoryId> },
    ValidatedBy { result: ValidationResult },
    UsedInDecision { decision_memory: MemoryId },
    CorrectedBy { correction: MemoryId },
    ReclassifiedFrom { old_type: MemoryType },
}
```

---

## Cross-Agent Causal Graph Extension

Our existing causal graph (cortex-causal) tracks relationships between memories within
a single agent. We extend this across agent boundaries:

### New Relation Types

```rust
enum CrossAgentRelation {
    /// Agent B's memory was informed by Agent A's memory
    InformedBy { source_agent: AgentId },
    /// Agent B's decision was based on Agent A's knowledge
    DecisionBasedOn { source_agent: AgentId },
    /// Two agents independently arrived at the same conclusion
    IndependentCorroboration { agents: Vec<AgentId> },
    /// Agent B contradicts Agent A's memory
    CrossAgentContradiction { contradicting_agent: AgentId },
    /// Agent B refined/improved Agent A's memory
    Refinement { original_agent: AgentId },
}
```

### Causal Chain Visualization

```
Agent A (Developer)          Agent B (Reviewer)         Agent C (Security)
    |                            |                          |
    M1: "auth uses bcrypt"       |                          |
    |                            |                          |
    |---[projected to B]-------->|                          |
    |                            M2: "reviewed auth,        |
    |                                bcrypt is correct"     |
    |                            |                          |
    |                            |---[projected to C]------>|
    |                            |                          M3: "bcrypt config
    |                            |                               needs work factor
    |                            |                               upgrade to 12"
    |                            |                          |
    |<---[correction propagated]-|<---[correction]----------|
    |                            |                          |
    M1': "auth uses bcrypt       |                          |
          (work factor 12)"      |                          |

Provenance chain for M3:
  M1 (Agent A, created) → M2 (Agent B, informed_by M1) → M3 (Agent C, refined M2)

If M1 was wrong (bcrypt wasn't actually used):
  Correction propagates: M1 invalidated → M2 invalidated → M3 invalidated
  All three agents' confidence in these memories drops
```

---

## Trust Scoring Across Agents

### Agent Trust Model

Each agent maintains a trust score for every other agent it interacts with:

```rust
struct AgentTrust {
    agent_id: AgentId,
    /// Overall trust score (0.0 - 1.0)
    trust_score: f64,
    /// Per-domain trust (agent might be great at auth, bad at perf)
    domain_trust: HashMap<String, f64>,
    /// Evidence for trust calculation
    evidence: TrustEvidence,
}

struct TrustEvidence {
    /// Memories received from this agent that were later validated
    validated_count: u64,
    /// Memories received that were later contradicted
    contradicted_count: u64,
    /// Memories received that were useful (accessed, used in decisions)
    useful_count: u64,
    /// Total memories received
    total_received: u64,
}
```

### Trust Calculation

```
trust_score = (validated + useful) / (total_received + 1)
            × (1 - contradicted / (total_received + 1))
```

Trust score modulates the confidence of projected memories:

```
effective_confidence = memory.confidence × source_agent_trust
```

If Agent A has trust 0.8 and shares a memory with confidence 0.9, the receiving
agent sees effective confidence of 0.72.

---

## Correction Propagation

When a memory is corrected, the correction propagates through the provenance chain:

1. Agent C corrects M3 → creates correction record
2. System traces provenance: M3 was refined from M2 (Agent B)
3. Agent B receives correction signal for M2
4. Agent B's validation engine re-evaluates M2
5. If M2 is also wrong, traces to M1 (Agent A)
6. Agent A receives correction signal for M1
7. Trust scores updated: Agent A's trust decreases slightly

### Propagation Dampening

Corrections don't propagate at full strength — they dampen with distance:

```
correction_strength(hop) = base_strength × 0.7^hop
```

- Direct correction: 100% strength
- 1 hop away: 70% strength
- 2 hops away: 49% strength
- 3+ hops: below threshold, logged but not auto-applied

This prevents a single correction from cascading through the entire knowledge graph.

---

## Audit Trail

Every cross-agent interaction is logged to the audit system:

```rust
struct CrossAgentAuditEntry {
    timestamp: DateTime<Utc>,
    source_agent: AgentId,
    target_agent: AgentId,
    action: CrossAgentAction,
    memories_involved: Vec<MemoryId>,
    provenance_chain_length: usize,
    trust_score_at_time: f64,
}
```

This extends our existing audit_ops (Phase 2) with cross-agent entries, stored in the
same audit_log table with an additional `source_agent` and `target_agent` column.
