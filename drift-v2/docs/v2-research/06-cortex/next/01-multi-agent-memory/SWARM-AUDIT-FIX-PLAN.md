# Swarm Audit Fix Plan

All findings from `swarm_simulation_test.rs` with root causes and exact fixes.

---

## FIX-01: Permission Escalation (SECURITY — P0)

**Finding:** `NamespacePermissionManager::grant()` never checks if the `granted_by` agent has `Admin` permission. Any agent can call `grant()` with themselves as granter and escalate to full admin.

**Root cause:** `permissions.rs` line ~25 — `grant()` accepts `granted_by: &AgentId` but only uses it as metadata for the DB row. No authorization check.

**File:** `cortex-multiagent/src/namespace/permissions.rs`

**Fix:** Add an authorization guard at the top of `grant()`:

```rust
pub fn grant(
    conn: &Connection,
    namespace_id: &NamespaceId,
    agent_id: &AgentId,
    permissions: &[NamespacePermission],
    granted_by: &AgentId,
) -> CortexResult<()> {
    // NEW: Verify granter has Admin permission on this namespace.
    if !Self::check(conn, namespace_id, granted_by, NamespacePermission::Admin)? {
        return Err(MultiAgentError::PermissionDenied {
            agent: granted_by.0.clone(),
            namespace: namespace_id.to_uri(),
            permission: "admin".to_string(),
        }.into());
    }
    // ... rest of existing code
}
```

**Also fix `revoke()`** — add the same admin check with a `revoked_by` parameter.

**Test update:** SWARM-03 assertion should flip to expect the escalation to fail.

---

## FIX-02: Self-Trust Evidence (SECURITY — P0)

**Finding:** An agent can record trust evidence about itself (`agent_id == target_agent`), inflating its own trust score.

**Root cause:** `evidence.rs` — `record_validation()`, `record_contradiction()`, `record_usage()` all accept any agent_id/target_agent pair with no self-referential guard.

**File:** `cortex-multiagent/src/trust/evidence.rs`

**Fix:** Add a guard at the top of each `record_*` method:

```rust
pub fn record_validation(
    conn: &Connection,
    agent_id: &AgentId,
    target_agent: &AgentId,
    memory_id: &str,
) -> CortexResult<()> {
    // NEW: Prevent self-trust manipulation.
    if agent_id == target_agent {
        return Err(cortex_core::CortexError::ValidationError(
            "agent cannot record trust evidence about itself".to_string(),
        ));
    }
    // ... rest of existing code
}
```

Apply the same guard to `record_contradiction()` and `record_usage()`.

---

## FIX-03: Missing `Retracted` Provenance Action (BUG — P0)

**Finding:** `retract()` in `share/actions.rs` writes `"retracted"` to the DB, but `ProvenanceAction` enum has no `Retracted` variant. `str_to_action()` falls back to `Created`, corrupting the provenance chain.

**Root cause:** Two-part mismatch:
1. `cortex-core/src/models/provenance.rs` — `ProvenanceAction` enum is missing a `Retracted` variant.
2. `cortex-multiagent/src/provenance/tracker.rs` — `str_to_action()` has no `"retracted"` arm, falls back to `Created`.

**Files:**
- `cortex-core/src/models/provenance.rs`
- `cortex-multiagent/src/provenance/tracker.rs`
- `cortex-multiagent/src/share/actions.rs`

**Fix:**

Step 1 — Add variant to enum in `provenance.rs`:
```rust
pub enum ProvenanceAction {
    // ... existing variants ...
    /// Memory was retracted (archived/tombstoned).
    Retracted,
}
```

Step 2 — Add mapping in `tracker.rs`:
```rust
// In action_to_str:
ProvenanceAction::Retracted => "retracted",

// In str_to_action:
"retracted" => ProvenanceAction::Retracted,
```

Step 3 — Update `retract()` in `share/actions.rs` to use the typed action through `ProvenanceTracker::record_hop()` instead of raw `record_provenance()` with a string, OR keep the string but ensure it matches.

---

## FIX-04: Spawn Trust Inheritance Not Wired (BUG — P1)

**Finding:** `spawn_agent()` creates the child agent but never calls `bootstrap_from_parent()` to inherit trust. The `SpawnConfig.trust_discount` field is ignored.

**Root cause:** `spawn.rs` — `spawn_agent()` only does: validate parent → insert agent → create namespace → grant permissions. No trust bootstrapping step.

**File:** `cortex-multiagent/src/registry/spawn.rs`

**Fix:** After creating the agent, bootstrap trust from parent:

```rust
pub fn spawn_agent(
    conn: &Connection,
    config: &SpawnConfig,
    name: &str,
    capabilities: Vec<String>,
) -> CortexResult<AgentRegistration> {
    let parent = multiagent_ops::get_agent(conn, &config.parent_agent.0)?
        .ok_or_else(|| MultiAgentError::AgentNotFound(config.parent_agent.0.clone()))?;

    // ... existing agent creation code ...

    // NEW: Bootstrap trust inheritance from parent.
    // For each agent that has a trust relationship with the parent,
    // create a discounted trust record for the child.
    let parent_id_clone = config.parent_agent.clone();
    let child_id_clone = agent_id.clone();
    let discount = config.trust_discount;

    // Get all trust records where parent is the target.
    // For each observer → parent trust, create observer → child trust.
    use crate::trust::bootstrap::bootstrap_from_parent;
    use crate::trust::scorer::TrustScorer;

    let trust_rows = multiagent_ops::list_trust_for_target(conn, &parent_id_clone.0)?;
    for row in trust_rows {
        let observer = AgentId::from(row.agent_id.as_str());
        let parent_trust = TrustScorer::get_trust(conn, &observer, &parent_id_clone)?;
        let child_trust = bootstrap_from_parent(&parent_trust, &child_id_clone, discount);
        TrustScorer::update_trust(conn, &child_trust)?;
    }

    // ... rest of existing code ...
}
```

**Note:** This requires adding a `list_trust_for_target()` query to `multiagent_ops.rs` if it doesn't exist. If that's too invasive, a simpler approach: just bootstrap a default trust record for the child with `parent_trust * discount` using the parent's overall trust as a starting point.

---

## FIX-05: Delta Queue Backpressure Not Enforced (BUG — P1)

**Finding:** `DeltaQueue::enqueue()` accepts unlimited deltas despite `MultiAgentConfig.delta_queue_max_size = 10_000`. The config value is never checked.

**Root cause:** `delta_queue.rs` — `enqueue()` has no access to `MultiAgentConfig` and performs no size check before inserting.

**File:** `cortex-multiagent/src/sync/delta_queue.rs`

**Fix:** Add a `pending_count` check before enqueuing:

```rust
pub fn enqueue(
    conn: &Connection,
    source_agent: &str,
    target_agent: &str,
    memory_id: &str,
    delta_json: &str,
    clock: &VectorClock,
    max_queue_size: usize,  // NEW parameter
) -> CortexResult<()> {
    // NEW: Backpressure check.
    let pending = multiagent_ops::pending_delta_count(conn, target_agent)?;
    if pending >= max_queue_size {
        return Err(MultiAgentError::SyncFailed(format!(
            "delta queue for agent {} is full ({} pending, max {})",
            target_agent, pending, max_queue_size
        )).into());
    }
    // ... rest of existing code
}
```

**Alternative (less breaking):** Add a separate `enqueue_checked()` method and keep `enqueue()` as-is for backward compat. The engine layer (`MultiAgentEngine`) should call the checked version.

---

## FIX-06: Namespace Name Validation (VALIDATION — P1)

**Finding:** Namespace names accept spaces, unicode, and 10K+ character strings with no validation.

**Root cause:** `addressing.rs` — `parse()` only checks for empty name and valid scope prefix. No character or length validation.

**File:** `cortex-multiagent/src/namespace/addressing.rs`

**Fix:** Add validation after extracting the name:

```rust
pub fn parse(uri: &str) -> CortexResult<NamespaceId> {
    // ... existing parsing ...

    if name.is_empty() {
        return Err(MultiAgentError::InvalidNamespaceUri(...));
    }

    // NEW: Validate namespace name.
    if name.len() > 256 {
        return Err(MultiAgentError::InvalidNamespaceUri(format!(
            "namespace name too long ({} chars, max 256): {uri}", name.len()
        )).into());
    }
    if !name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.') {
        return Err(MultiAgentError::InvalidNamespaceUri(format!(
            "namespace name contains invalid characters (allowed: alphanumeric, -, _, .): {uri}"
        )).into());
    }

    // ... rest of existing code
}
```

---

## FIX-07: Agent Name Validation (VALIDATION — P1)

**Finding:** Agent names accept 10K+ character strings with no length limit.

**Root cause:** `agent_registry.rs` — `register()` only checks `name.is_empty()`. No length or character validation.

**File:** `cortex-multiagent/src/registry/agent_registry.rs`

**Fix:** Add validation after the empty check:

```rust
if name.is_empty() {
    return Err(...);
}
// NEW: Validate agent name length and characters.
if name.len() > 256 {
    return Err(MultiAgentError::InvalidNamespaceUri(
        format!("agent name too long ({} chars, max 256)", name.len()),
    ).into());
}
if !name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.') {
    return Err(MultiAgentError::InvalidNamespaceUri(
        "agent name contains invalid characters".to_string(),
    ).into());
}
```

**Note:** Consider adding a dedicated `InvalidAgentName` error variant to `MultiAgentError` instead of reusing `InvalidNamespaceUri`.

---

## FIX-08: Project Namespace Default Permissions (DESIGN — P2)

**Finding:** Project-scoped namespaces only grant `read` to the owner by default. The owner can't write to their own project namespace without an explicit grant.

**Root cause:** `namespace/manager.rs` — `create_namespace()` has:
```rust
NamespaceScope::Project(_) => vec!["read"],
```

**File:** `cortex-multiagent/src/namespace/manager.rs`

**Fix:** Grant the owner full permissions on project namespaces too:

```rust
let default_perms = match &namespace.scope {
    NamespaceScope::Agent(_) => vec!["read", "write", "share", "admin"],
    NamespaceScope::Team(_) => vec!["read", "write", "share", "admin"],  // owner gets full
    NamespaceScope::Project(_) => vec!["read", "write", "share", "admin"],  // owner gets full
};
```

The scope-based restriction should apply to OTHER agents joining the namespace, not the owner. The owner should always have full control.

---

## FIX-09: Namespace Deletion Error Message (UX — P2)

**Finding:** Deleting a namespace with dependent projections fails with a raw SQLite FK constraint error instead of a user-friendly message.

**Root cause:** `namespace/manager.rs` — `delete_namespace()` calls `multiagent_ops::delete_namespace()` which hits a SQLite FK violation. The error propagates as a raw `StorageError`.

**File:** `cortex-multiagent/src/namespace/manager.rs`

**Fix:** Check for dependent projections before deleting:

```rust
pub fn delete_namespace(conn: &Connection, namespace_id: &NamespaceId) -> CortexResult<()> {
    let uri = namespace_id.to_uri();
    multiagent_ops::get_namespace(conn, &uri)?
        .ok_or_else(|| MultiAgentError::NamespaceNotFound(uri.clone()))?;

    // NEW: Check for dependent projections.
    let projections = multiagent_ops::list_projections(conn, &uri)?;
    if !projections.is_empty() {
        return Err(MultiAgentError::InvalidNamespaceUri(format!(
            "cannot delete namespace {uri}: {} dependent projection(s) exist",
            projections.len()
        )).into());
    }

    multiagent_ops::delete_namespace(conn, &uri)?;
    info!(namespace = %uri, "namespace deleted");
    Ok(())
}
```

---

## FIX-10: Cloud Sync Stub (INCOMPLETE — P2)

**Finding:** `CloudSyncAdapter::sync_via_cloud()` always returns an error. Deregistered agents are detected as `Local` transport.

**Root cause:** `cloud_integration.rs` — `sync_via_cloud()` is a stub that returns `Err`. `detect_sync_mode()` checks if the agent exists in the DB (deregistered agents still exist).

**File:** `cortex-multiagent/src/sync/cloud_integration.rs`

**Fix (deregistered agent detection):**

```rust
pub fn detect_sync_mode(
    conn: &Connection,
    target_agent: &AgentId,
) -> CortexResult<SyncTransport> {
    let agent = multiagent_ops::get_agent(conn, &target_agent.0)?;
    let mode = match agent {
        Some(row) if !row.status.starts_with("deregistered") => SyncTransport::Local,
        _ => SyncTransport::Cloud,
    };
    Ok(mode)
}
```

**Fix (cloud sync):** This is a larger feature. For now, improve the error message to be actionable:

```rust
pub fn sync_via_cloud(...) -> CortexResult<()> {
    Err(MultiAgentError::SyncFailed(
        "cloud sync not yet available — target agent is remote or deregistered".to_string(),
    ).into())
}
```

---

## FIX-11: Causal Delivery Permissiveness (DESIGN — P3)

**Finding:** `can_apply_clock()` allows `delta_val == local_val + 1` for ALL agents in the clock, not just the source agent. The doc comment says "source agent must be exactly local + 1, others must be ≤ local" but the code doesn't distinguish source from others.

**Root cause:** `causal_delivery.rs` — the check `delta_val > local_val + 1` is applied uniformly to all agents. There's no `source_agent` parameter to distinguish the source's clock entry.

**File:** `cortex-multiagent/src/sync/causal_delivery.rs`

**Fix:** This is actually correct for the CRDT model being used. The `> local + 1` check means "at most 1 ahead" which is the standard vector clock causal delivery check. The doc comment is misleading. Fix the doc comment:

```rust
/// Check if a delta can be applied given the local clock.
///
/// For each agent in the delta clock, the delta's value must be at most
/// `local + 1`. If any agent's value exceeds `local + 1`, we're missing
/// intermediate deltas and must buffer.
///
/// This allows concurrent deltas (where multiple agents are each 1 ahead)
/// to be applied, which is correct for CRDT convergence.
```

---

## FIX-12: GCounter Initialization Multiplication (DESIGN — P3)

**Finding:** `from_base_memory()` initializes the GCounter by calling `gc.increment(agent_id)` N times where N = `memory.access_count`. When 5 agents each create a CRDT from the same base memory, each agent's counter starts at N. After merge, the total is `5 * N` instead of `N`.

**Root cause:** `memory_crdt.rs` line ~188 — the loop `for _ in 0..memory.access_count { gc.increment(agent_id); }` attributes the entire base access_count to the creating agent.

**File:** `cortex-crdt/src/memory/memory_crdt.rs`

**Fix:** This is actually correct CRDT semantics — each agent independently observes the base state and records it under their own counter. The "multiplication" is expected because GCounter merge takes per-agent max, and each agent independently claims the base count. However, if the intent is that the base access_count should be shared, use a different initialization:

```rust
access_count: {
    let mut gc = GCounter::new();
    // Only set 1 for the creating agent, not the full base count.
    // The base access_count is a snapshot, not per-agent attribution.
    gc.increment(agent_id);
    gc
},
```

**Decision needed:** Is the current behavior intentional? If multiple agents create CRDTs from the same base memory, the access_count will inflate. If this is a "fork" scenario (each agent gets their own copy), the current behavior is correct. If it's a "shared view" scenario, the fix above is needed. Document the decision either way.

---

## Execution Order

| Priority | Fix | Effort | Risk | Status |
|----------|-----|--------|------|--------|
| P0 | FIX-01: Permission escalation guard | Small | Low | ✅ DONE |
| P0 | FIX-02: Self-trust guard | Small | Low | ✅ DONE |
| P0 | FIX-03: Add `Retracted` provenance action | Small | Low | ✅ DONE |
| P1 | FIX-04: Wire spawn trust inheritance | Medium | Medium | ✅ DONE |
| P1 | FIX-05: Delta queue backpressure | Small | Low | ✅ DONE |
| P1 | FIX-06: Namespace name validation | Small | Low | ✅ DONE |
| P1 | FIX-07: Agent name validation | Small | Low | ✅ DONE |
| P2 | FIX-08: Project namespace owner permissions | Small | Low | ✅ DONE |
| P2 | FIX-09: Namespace deletion error message | Small | Low | ✅ DONE |
| P2 | FIX-10: Cloud sync deregistered agent detection | Small | Low | ✅ DONE |
| P3 | FIX-11: Causal delivery doc comment | Trivial | None | ✅ DONE |
| P3 | FIX-12: GCounter initialization decision | Trivial | None | ✅ DONE (shared view) |

---

## Implementation Summary (2026-02-07)

All 12 fixes implemented. `cargo check --tests -p cortex-multiagent -p cortex-crdt -p cortex-core` passes with zero errors and zero warnings.

### Files Modified (Source — 12 files)

- `cortex-multiagent/src/namespace/permissions.rs` — FIX-01: admin guard on grant() + revoke()
- `cortex-multiagent/src/trust/evidence.rs` — FIX-02: self-trust guard on all record_* methods
- `cortex-core/src/models/provenance.rs` — FIX-03: added Retracted variant
- `cortex-multiagent/src/provenance/tracker.rs` — FIX-03: action_to_str/str_to_action/origin_from_action mappings
- `cortex-multiagent/src/registry/spawn.rs` — FIX-04: trust inheritance + FIX-07: name validation
- `cortex-multiagent/src/sync/delta_queue.rs` — FIX-05: max_queue_size parameter + backpressure check
- `cortex-multiagent/src/namespace/addressing.rs` — FIX-06: length + character validation
- `cortex-multiagent/src/registry/agent_registry.rs` — FIX-07: length + character validation
- `cortex-multiagent/src/namespace/manager.rs` — FIX-08: owner gets full perms + FIX-09: projection check before delete
- `cortex-multiagent/src/sync/cloud_integration.rs` — FIX-10: deregistered = Cloud + better error msg
- `cortex-multiagent/src/sync/causal_delivery.rs` — FIX-11: corrected doc comment
- `cortex-crdt/src/memory/memory_crdt.rs` — FIX-12: shared view init (1 per agent, not N)

### Files Modified (Tests — 7 files)

- `cortex-multiagent/tests/swarm_simulation_test.rs` — updated 10 test assertions
- `cortex-multiagent/tests/coverage_test.rs` — updated revoke() + enqueue() signatures
- `cortex-multiagent/tests/namespace_test.rs` — updated revoke() signature
- `cortex-multiagent/tests/sync_test.rs` — updated enqueue() signatures
- `cortex-multiagent/tests/stress_test.rs` — updated enqueue() signature
- `cortex-multiagent/tests/integration_final_test.rs` — updated enqueue() signatures
- `cortex-crdt/tests/memory_crdt_test.rs` — updated access_count merge assertion

### Design Decisions

- FIX-01: `revoke()` now takes a `revoked_by` parameter (breaking API change, 3 callers updated)
- FIX-05: `enqueue()` now takes `max_queue_size` parameter (0 = unlimited for backward compat)
- FIX-07: Reused `InvalidNamespaceUri` error variant for agent name validation (pragmatic, avoids new variant)
- FIX-08: All namespace scopes give owner full permissions; scope restrictions apply to OTHER agents joining
- FIX-12: Chose "shared view" semantics — base access_count is a snapshot, each agent starts at 1
