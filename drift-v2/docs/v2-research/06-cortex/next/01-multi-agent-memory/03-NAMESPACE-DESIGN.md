# Memory Namespace Architecture & Projection Model

## Core Concept: Memory Namespaces

Each agent operates within a namespace — a logical partition of the memory space.
Namespaces provide isolation by default and sharing by explicit declaration.

```
┌─────────────────────────────────────────────────┐
│                 Shared Namespace                 │
│  (memories explicitly shared by any agent)       │
├────────────────┬────────────────┬───────────────┤
│  Agent A       │  Agent B       │  Agent C      │
│  Namespace     │  Namespace     │  Namespace    │
│                │                │               │
│  Private       │  Private       │  Private      │
│  memories      │  memories      │  memories     │
│                │                │               │
│  Projected →   │  ← Subscribed  │  Projected →  │
│  views         │     views      │  views        │
└────────────────┴────────────────┴───────────────┘
```

---

## Namespace Hierarchy

### Level 1: Agent Namespace (Private)
- Default home for all memories created by an agent
- Only the owning agent can read/write
- Decay, consolidation, validation run independently
- Example: `agent://code-reviewer-1/`

### Level 2: Team Namespace (Shared)
- Explicitly shared memories visible to all agents in a team
- CRDT-based convergence for concurrent modifications
- Example: `team://backend-squad/`

### Level 3: Project Namespace (Global)
- Project-wide knowledge: patterns, constraints, tribal knowledge
- All agents can read; write requires explicit share action
- Example: `project://my-app/`

### Namespace Addressing

```
namespace://scope/path

Examples:
  agent://reviewer-1/memories/m-abc123
  team://backend/patterns/auth-pattern
  project://my-app/tribal/never-use-orm-x
```

---

## Memory Projection

A projection is a filtered, compressed view of one namespace exposed to another.
Think of it as a database view — read-only, filtered, potentially compressed.

### Projection Definition

```rust
struct MemoryProjection {
    /// Source namespace
    source: NamespaceId,
    /// Target namespace (who can see this)
    target: NamespaceId,
    /// Filter: which memories to include
    filter: ProjectionFilter,
    /// Compression: what level to expose at
    compression_level: CompressionLevel,
    /// Whether the projection auto-updates
    live: bool,
}

struct ProjectionFilter {
    /// Include only these memory types
    memory_types: Option<Vec<MemoryType>>,
    /// Minimum confidence threshold
    min_confidence: Option<f64>,
    /// Minimum importance level
    min_importance: Option<Importance>,
    /// Only memories linked to these files
    linked_files: Option<Vec<String>>,
    /// Only memories with these tags
    tags: Option<Vec<String>>,
    /// Custom predicate (for advanced filtering)
    predicate: Option<String>,
}
```

### Projection Examples

**"Share my auth knowledge with the security reviewer"**
```rust
MemoryProjection {
    source: "agent://developer-1",
    target: "agent://security-reviewer",
    filter: ProjectionFilter {
        tags: Some(vec!["auth", "security", "authentication"]),
        min_confidence: Some(0.5),
        ..Default::default()
    },
    compression_level: CompressionLevel::L2, // summaries + examples
    live: true, // auto-update as I learn more
}
```

**"Give the spawned sub-agent context about this module"**
```rust
MemoryProjection {
    source: "agent://orchestrator",
    target: "agent://sub-agent-42",
    filter: ProjectionFilter {
        linked_files: Some(vec!["src/payments/**"]),
        min_importance: Some(Importance::Normal),
        ..Default::default()
    },
    compression_level: CompressionLevel::L3, // full context
    live: false, // snapshot at spawn time
}
```

---

## Share Semantics

### Share Actions

| Action | Semantics | CRDT Behavior |
|--------|-----------|---------------|
| `share(memory, namespace)` | Copy memory to target namespace | Delta sent to target |
| `project(filter, namespace)` | Create live filtered view | Subscription established |
| `promote(memory)` | Move from agent → team/project | Memory gets new namespace prefix |
| `retract(memory, namespace)` | Remove from shared namespace | Tombstone in OR-Set |

### Share vs. Project vs. Promote

- **Share**: One-time copy. Target gets a snapshot. No further updates.
- **Project**: Live view. Target sees updates as they happen. Read-only.
- **Promote**: Move ownership. Memory leaves agent namespace, enters team/project.
  Original agent retains a reference (like a symlink).

---

## Subscription Model

Agents subscribe to projections. When the source namespace changes, deltas flow
to subscribers automatically.

```
Agent A creates memory M1 (tagged "auth")
  → M1 matches Agent B's subscription filter (tags contains "auth")
  → Delta for M1 sent to Agent B's namespace (compressed to L2)
  → Agent B's retrieval engine can now find M1

Agent A updates M1's content
  → Delta for M1.content sent to Agent B
  → Agent B's copy updated via CRDT merge

Agent A archives M1
  → Archive delta sent to Agent B
  → Agent B's copy also archived
```

### Subscription Backpressure

If Agent B is busy and can't process deltas fast enough:
1. Deltas are queued (bounded queue, configurable size)
2. If queue fills, switch to periodic full-state sync (less frequent, larger)
3. Agent B can request a "catch-up" sync at any time

---

## Access Control

### Permission Model

```rust
enum NamespacePermission {
    /// Can read memories in this namespace
    Read,
    /// Can write/update memories in this namespace
    Write,
    /// Can share memories from this namespace to others
    Share,
    /// Can manage permissions for this namespace
    Admin,
}

struct NamespaceACL {
    namespace: NamespaceId,
    grants: Vec<(AgentId, Vec<NamespacePermission>)>,
}
```

### Default Permissions

- Agent namespace: owner has all permissions, others have none
- Team namespace: all team members have Read + Write, creator has Admin
- Project namespace: all agents have Read, explicit grant for Write

---

## Conflict Resolution at Namespace Boundaries

When the same logical knowledge exists in multiple namespaces (e.g., Agent A and Agent B
both learn "never use ORM X"), we need to detect and merge:

1. **Dedup detection**: Embedding similarity > 0.9 across namespaces → candidate duplicate
2. **Merge strategy**: If both are in the same team/project namespace, CRDT merge
3. **Confidence boost**: Multiple agents independently learning the same thing → consensus
   boost (+0.2, matching our existing contradiction/consensus system)
4. **Provenance preservation**: Merged memory retains provenance from all contributing agents

This directly extends our existing consolidation pipeline (Phase 8) to work across
namespace boundaries.
