# Prior Art: Multi-Agent Memory Systems

## 1. Blackboard Architecture (Classic AI, 1980s)

The original multi-agent shared memory pattern. A central "blackboard" acts as a shared
repository where independent knowledge sources post partial solutions, suggestions, and
information. Each knowledge source monitors the blackboard and contributes when it can.

Relevance to Cortex:
- Proves the pattern works for heterogeneous agents with different specializations
- Limitation: single centralized store creates a bottleneck
- Limitation: no conflict resolution — last write wins
- We need: decentralized convergence, not centralized coordination

Source: [Blackboard system — Wikipedia](https://en.wikipedia.org/wiki/Blackboard_system)

---

## 2. BMAM: Brain-inspired Multi-Agent Memory (2026)

Decomposes agent memory into functionally specialized subsystems rather than a single
unstructured store. Inspired by cognitive memory systems, BMAM separates memory into
episodic, semantic, salience-aware, and control-oriented components operating at
complementary time scales.

Key findings:
- Achieves 78.45% accuracy on LoCoMo long-horizon benchmark
- The hippocampus-inspired episodic subsystem is critical for temporal reasoning
- Addresses "soul erosion" — the loss of behavioral consistency across sessions
- Organizes episodic memories along explicit timelines

Relevance to Cortex:
- Cortex already has this decomposition (23 memory types, episodic→semantic consolidation)
- BMAM validates our architecture but is single-agent only
- We extend this to multi-agent: each agent has its own BMAM-like subsystems,
  with selective sharing between them

Source: [arXiv:2601.20465](https://arxiv.org/abs/2601.20465) — Li et al., 2026

---

## 3. LatentMem: Customizing Latent Memory for Multi-Agent Systems (2026)

A learnable multi-agent memory framework that customizes agent-specific memories through
latent representations. Improves performance in multi-agent systems without modifying
underlying frameworks.

Key insight: Each agent needs a personalized view of shared knowledge, not a copy of
everything. LatentMem achieves this through learned latent projections.

Relevance to Cortex:
- Validates the "memory projection" concept — agents don't share everything
- Our approach: explicit namespace + projection rules instead of learned latent vectors
- More interpretable, auditable, and controllable for developer-facing systems

Source: [HuggingFace Papers](https://huggingface.co/papers/2602.03036) — 2026

---

## 4. LatentMAS: Latent Collaboration in Multi-Agent Systems (2025)

From Princeton/UIUC/Stanford. Enables multi-agent systems to collaborate purely within
continuous latent space via shared KV-caches. Each agent generates latent thoughts through
last-layer hidden states, then transfers information layer-wise via shared latent working
memory.

Key insight: Communication doesn't have to be text. Latent representations are more
efficient for agent-to-agent knowledge transfer.

Relevance to Cortex:
- Interesting for future optimization but too coupled to specific LLM architectures
- Cortex operates at a higher abstraction level (structured memories, not KV-caches)
- Our approach: structured memory sharing with explicit semantics

Source: [arXiv:2511.20639](https://arxiv.org/abs/2511.20639) — 2025

---

## 5. MIRIX: Multi-Agent Memory System for LLM-Based Agents (2025)

Six distinct memory types: Core, Episodic, Semantic, Procedural, Resource Memory, and
Knowledge Vault. Coupled with a multi-agent framework that dynamically controls and
coordinates updates and retrieval.

Relevance to Cortex:
- Very similar type decomposition to Cortex (we have 23 types vs their 6)
- Their multi-agent coordination is the piece we're missing
- Key difference: MIRIX is LLM-native, Cortex is code-native with richer type system

Source: [arXiv:2507.07957](https://arxiv.org/abs/2507.07957) — 2025

---

## 6. Mem0 with Graph Memory (2025)

Mem0 achieves 26% improvement over OpenAI's memory via dynamic extraction, consolidation,
and retrieval. Graph memory variant captures relational structures between conversational
elements. 91% lower p95 latency and 90%+ token cost savings vs full-context.

Relevance to Cortex:
- Mem0 is single-agent, single-user focused
- No multi-agent sharing protocol
- No causal provenance
- No typed memory system (everything is flat key-value or graph triples)
- Cortex already exceeds Mem0's architecture in depth; multi-agent is the gap

Source: [arXiv:2504.19413](https://arxiv.org/abs/2504.19413) — Chhikara et al., 2025

---

## 7. RoboMemory: Brain-inspired Multi-memory for Embodied Systems (2025)

Unifies Spatial, Temporal, Episodic, and Semantic memory under a parallelized architecture.
Key innovation: all four memory modules update concurrently, with a working memory module
that dynamically composes relevant knowledge for planning.

Relevance to Cortex:
- The "working memory" concept maps to our SessionContext + PredictionEngine
- Parallel update architecture is relevant for multi-agent: each agent's memory
  subsystems update independently, then sync

Source: [arXiv:2508.01415](https://arxiv.org/abs/2508.01415) — 2025

---

## 8. MemOS: Memory Operating System for AI Agents (2025)

Positions itself as a memory manager (not just a store). Exposes a unified API for write,
search, merge, and revise operations while keeping personality and identity stable across
runs.

Relevance to Cortex:
- The "memory OS" framing is exactly right
- MemOS is single-agent; we extend to multi-agent OS
- Their merge semantics are basic; we need CRDT-based convergence

Source: [TestingCatalog](https://testingcatalog.com/memos-2-0-brings-open-source-memory-os-to-ai-agents/) — 2025

---

## Gap Analysis: What Nobody Has

| Capability | Blackboard | BMAM | LatentMem | MIRIX | Mem0 | MemOS | Cortex (current) | Cortex (proposed) |
|---|---|---|---|---|---|---|---|---|
| Typed memory (>6 types) | ✗ | ✗ | ✗ | ✓ (6) | ✗ | ✗ | ✓ (23) | ✓ (23) |
| Multi-agent sharing | ✓ (central) | ✗ | ✓ (latent) | ✓ (basic) | ✗ | ✗ | ✗ | ✓ (CRDT) |
| Conflict-free convergence | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ |
| Causal provenance | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ (single) | ✓ (cross-agent) |
| Memory projection/filtering | ✗ | ✗ | ✓ | ✗ | ✗ | ✗ | ✗ | ✓ |
| Namespace isolation | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ |
| Code-aware memory | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ | ✓ |

The combination of CRDT-based convergence + typed memory + causal provenance + namespace
isolation is completely novel. No existing system has this.
