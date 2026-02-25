# MAPhase B — Storage + Namespaces + Projections

> **ULTRA THINK. Quality over speed. No shortcuts. Enterprise-grade perfection.**
> Your boss audits every line through Codex. Make him stop needing to.

You are implementing Phase B of the Cortex multi-agent memory addition. This phase adds persistence, namespace isolation, and the sharing/projection layer. Read these files first:

- `MULTIAGENT-TASK-TRACKER.md` (Phase B section, tasks `PMB-*` and tests `TMB-*`)
- `MULTIAGENT-IMPLEMENTATION-SPEC.md` (full behavioral spec)
- `FILE-MAP.md` (complete file inventory with per-file details)

**Prerequisite:** QG-MA0 has passed — Phase A's CRDT foundation is fully operational. The `cortex-crdt` crate exists with working GCounter, LWWRegister, MVRegister, ORSet, MaxRegister, VectorClock, MemoryCRDT, MergeEngine, and CausalGraphCRDT. All `TMA-CRDT-*` tests pass, all 19 property tests pass, `cargo test --workspace` is green, and coverage ≥80% on all Phase A modules. The `cortex-core` models (agent, namespace, provenance, cross_agent), error types, trait, and config are all in place.

---

## What This Phase Builds

Phase B adds SQLite persistence for multi-agent data, namespace management with permissions, memory projections with filtering, and share/promote/retract operations. 17 impl tasks, 29 tests. Specifically:

### 1. cortex-storage: Migration + Query Modules (~6 tasks)

**Migration v015** (`cortex-storage/src/migrations/v015_multiagent_tables.rs`):
8 new tables + 2 altered tables + 9 indexes:
- `agent_registry` — agent_id PK, name, namespace, capabilities JSON, parent_agent, registered_at, last_active, status + indexes on status, parent
- `memory_namespaces` — namespace_id PK, scope, name, owner, created_at
- `namespace_permissions` — (namespace_id, agent_id) composite PK, permissions JSON, granted_by, granted_at
- `memory_projections` — projection_id PK, source/target namespace, filter JSON, compression_level, live, created_at, created_by + indexes on source, target
- `provenance_log` — hop_id PK, memory_id, agent_id, action, timestamp, confidence_delta, metadata JSON, hop_index + indexes on memory_id, agent_id
- `agent_trust` — (agent_id, target_agent) composite PK, overall_trust, domain_trust JSON, evidence JSON, last_updated
- `delta_queue` — delta_id PK, target_agent, delta JSON, created_at, applied, applied_at + indexes on (target+applied), created_at
- ALTER TABLE memories: ADD namespace_id DEFAULT 'agent://default/', ADD source_agent DEFAULT 'default' + indexes

**Query Module** (`cortex-storage/src/queries/multiagent_ops.rs`):
Raw SQL operations — no business logic. 25+ functions covering:
- Agent registry CRUD (6 functions)
- Namespace CRUD (4 functions)
- Permission CRUD (4 functions)
- Projection CRUD (4 functions)
- Provenance operations (3 functions)
- Trust operations (4 functions)
- Delta queue operations (5 functions)

**Memory CRUD Extensions** (`cortex-storage/src/queries/memory_crud.rs`):
- Extend `create_memory()` to include namespace_id and source_agent
- Extend `get_memory()` to return namespace_id and source_agent
- Add `get_memories_by_namespace()`, `get_memories_by_agent()`

**Memory Query Extensions** (`cortex-storage/src/queries/memory_query.rs`):
- Add optional `namespace_filter: Option<NamespaceId>` to search queries
- When Some → add WHERE namespace_id = ? clause using index
- When None → search all namespaces (backward compatible)

### 2. cortex-multiagent: New Crate Setup + Core Modules (~11 tasks)

**Crate Setup** (`cortex-multiagent/`):
- Cargo.toml with deps: cortex-core, cortex-crdt, cortex-storage, chrono, serde, serde_json, tokio, uuid, dashmap, thiserror, tracing, rusqlite
- lib.rs with module declarations and re-exports

**Engine** (`cortex-multiagent/src/engine.rs`):
- `MultiAgentEngine` struct (writer: Arc<WriteConnection>, readers: Arc<ReadPool>, config: MultiAgentConfig)
- Implements `IMultiAgentEngine` — Phase B methods: register_agent, deregister_agent, get_agent, list_agents, create_namespace, check_permission, share_memory, create_projection
- Other methods return not-yet-implemented error (Phase C/D)

**Registry Module** (`cortex-multiagent/src/registry/`):
- `AgentRegistry` — register, deregister, get_agent, list_agents, update_last_active, mark_idle
- `spawn.rs` — spawn_agent (creates child with parent reference), deregister_spawned (with optional memory promotion)
- Registration creates agent + default namespace. Deregistration archives namespace, preserves provenance.

**Namespace Module** (`cortex-multiagent/src/namespace/`):
- `NamespaceManager` — create, get, list, delete namespaces
- `NamespacePermissionManager` — grant, revoke, check, get_acl
- `addressing.rs` — URI parsing/formatting: `{scope}://{name}/`
- Default permissions per scope: Agent → all, Team → read+write, Project → read

**Projection Module** (`cortex-multiagent/src/projection/`):
- `ProjectionEngine` — create, delete, get, list projections + filter evaluation
- `SubscriptionManager` — subscribe, unsubscribe, push_delta, drain_queue (for live projections)
- `BackpressureController` — queue > 80% → Batched mode, < 50% → Streaming mode
- `compression.rs` — delegates to cortex-compression L0-L3

**Share Module** (`cortex-multiagent/src/share/`):
- `share()` — copy memory to target namespace with provenance hop
- `promote()` — move memory to target namespace, update namespace field
- `retract()` — tombstone memory in target namespace
- All operations check permissions first, record provenance hops

---

## Critical Implementation Details

### Migration Backward Compatibility

The v015 migration MUST be backward compatible:
- `ALTER TABLE memories ADD COLUMN namespace_id TEXT NOT NULL DEFAULT 'agent://default/'`
- `ALTER TABLE memories ADD COLUMN source_agent TEXT NOT NULL DEFAULT 'default'`
- Existing memories get default values automatically
- All existing queries continue to work (new columns have defaults)

### Namespace URI Format

```
agent://default/          ← default namespace (backward compat)
agent://{agent_id}/       ← agent-private namespace
team://{team_name}/       ← team-shared namespace
project://{project_name}/ ← project-wide namespace
```

Parsing is case-insensitive for scope, case-preserving for name. Invalid URIs return `MultiAgentError::InvalidNamespaceUri`.

### Permission Model

```
Agent scope:   Owner gets all permissions (Read, Write, Share, Admin)
Team scope:    Members get Read + Write by default
Project scope: Members get Read by default
```

Permission checks are on the hot path — consider DashMap caching for frequently checked permissions.

### Projection Filter Evaluation

All filter conditions are AND-ed:
```rust
fn evaluate_filter(memory: &BaseMemory, filter: &ProjectionFilter) -> bool {
    filter.memory_types.as_ref().map_or(true, |types| types.contains(&memory.memory_type))
    && filter.min_confidence.map_or(true, |min| memory.confidence.value >= min)
    && filter.min_importance.map_or(true, |min| memory.importance >= min)
    && filter.tags.as_ref().map_or(true, |tags| tags.iter().any(|t| memory.tags.contains(t)))
    && filter.max_age_days.map_or(true, |days| /* check age */)
    // ... etc
}
```

### Share vs Promote Semantics

- **Share** = copy. Original stays in source namespace. Copy gets new ID + provenance hop (SharedTo).
- **Promote** = move. Memory's namespace field changes. Provenance hop (ProjectedTo) recorded.
- **Retract** = soft-delete in target namespace. Memory archived in target, preserved in source.

---

## Reference Crate Patterns

- **Migration**: Follow `cortex-storage/src/migrations/v013_*.rs` pattern — single function that takes `&Connection`, runs SQL in a transaction, returns `Result<()>`
- **Query module**: Follow `cortex-storage/src/queries/memory_crud.rs` — raw SQL with parameterized queries, no business logic, clear function names
- **Engine pattern**: Follow `cortex-retrieval/src/engine.rs` — struct with writer/reader connections, methods that orchestrate submodules
- **Module organization**: Follow `cortex-causal/src/graph/` — `mod.rs` with declarations + re-exports, one file per concern

---

## Task Checklist

Check off tasks in `MULTIAGENT-TASK-TRACKER.md` as you complete them:

**Storage**: `PMB-STOR-01` through `PMB-STOR-06`
**Multi-Agent Crate**: `PMB-MA-01` through `PMB-MA-17`
**Tests**: All `TMB-REG-*` (6), `TMB-NS-*` (7), `TMB-PROJ-*` (8), `TMB-SHARE-*` (5), `TMB-STOR-*` (5), `TMB-INT-*` (1), `TMB-TEST-*` (3)

---

## Quality Gate: QG-MA1

Before proceeding to Phase C, ALL of these must pass:

### Tests
- [ ] All 29 `TMB-*` tests pass
- [ ] `cargo test -p cortex-multiagent` — zero failures
- [ ] `cargo test -p cortex-storage` — zero failures
- [ ] `cargo test --workspace` — zero regressions

### Coverage
- [ ] Coverage ≥80% for cortex-multiagent registry modules
- [ ] Coverage ≥80% for cortex-multiagent namespace modules
- [ ] Coverage ≥80% for cortex-multiagent projection modules
- [ ] Coverage ≥80% for cortex-multiagent share modules
- [ ] Coverage ≥80% for cortex-storage multiagent_ops.rs

### Build Quality
- [ ] `cargo check -p cortex-multiagent` exits 0
- [ ] `cargo clippy -p cortex-multiagent` — zero warnings
- [ ] Migration v015 tested on fresh DB and upgrade path

### Enterprise
- [ ] All public APIs have doc comments
- [ ] All errors use CortexResult<T> with specific variants
- [ ] All DB operations use parameterized queries (no SQL injection)
- [ ] All permission checks happen before operations, not after

---

## Common Pitfalls to Avoid

- ❌ **Don't forget to register v015 in the migration runner** — the migration won't run otherwise
- ❌ **Don't use string concatenation for SQL** — always use parameterized queries
- ❌ **Don't check permissions after the operation** — always check before
- ❌ **Don't forget default namespace creation on agent registration** — every agent gets `agent://{agent_id}/`
- ❌ **Don't forget to preserve provenance on deregistration** — provenance is append-only, never deleted
- ✅ **Do test the upgrade path** — existing DB with memories → run v015 → memories have default namespace/agent
- ✅ **Do log all permission checks** — critical for debugging access issues
- ✅ **Do use transactions for multi-step operations** — share = copy + provenance hop must be atomic

---

## Success Criteria

Phase B is complete when:

1. ✅ All 17 implementation tasks completed
2. ✅ All 29 tests pass
3. ✅ Coverage ≥80% on all Phase B modules
4. ✅ QG-MA1 quality gate passes
5. ✅ Zero regressions in existing workspace tests
6. ✅ Migration tested on fresh DB and upgrade path
7. ✅ All public APIs documented

**You'll know it works when:** An agent can register, create memories in its namespace, share a memory to a team namespace (with permission check), and another agent can see the shared memory through a projection with filtering.

---

## Next Steps After Phase B

Once QG-MA1 passes, proceed to **MAPhase C: Delta Sync + Trust + Provenance**, which adds provenance tracking, evidence-based trust scoring, and delta-state CRDT synchronization with causal delivery.
