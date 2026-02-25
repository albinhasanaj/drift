//! Production Category 19: Cortex Memory System — T19-10 (Multi-Agent Namespace Isolation)
//!
//! Agent A creates memory in namespace "team-alpha". Agent B (different namespace)
//! attempts to read it. Agent B must get permission denied. Agent A must succeed.
//! RBAC: Agent scope = all 4 perms, Team = read+write, Project = read only.

use cortex_core::models::namespace::{NamespaceId, NamespacePermission, NamespaceScope};
use cortex_storage::StorageEngine;

use cortex_multiagent::namespace::manager::NamespaceManager;
use cortex_multiagent::namespace::permissions::NamespacePermissionManager;
use cortex_multiagent::registry::AgentRegistry;

fn storage() -> StorageEngine {
    StorageEngine::open_in_memory().expect("open in-memory storage")
}

// ── T19-10: Multi-Agent Namespace Isolation ────────────────────────────────
// Agent A creates memory in namespace "team-alpha". Agent B (different namespace)
// attempts to read it. Agent B must get permission denied.

#[test]
fn t19_10_multiagent_namespace_isolation() {
    let store = storage();

    store.pool().writer.with_conn_sync(|conn| {
        // Register two agents.
        let agent_a = AgentRegistry::register(conn, "agent-alpha", vec!["memory".into()])?;
        let agent_b = AgentRegistry::register(conn, "agent-beta", vec!["memory".into()])?;

        let agent_a_id = agent_a.agent_id.clone();
        let agent_b_id = agent_b.agent_id.clone();

        // Create namespace "team-alpha" owned by Agent A (Team scope → read+write).
        let ns_alpha = NamespaceId {
            scope: NamespaceScope::Team("alpha".into()),
            name: "alpha".into(),
        };
        NamespaceManager::create_namespace(conn, &ns_alpha, &agent_a_id)?;

        // Agent A (owner) should have read permission (implicit via ownership).
        let a_can_read = NamespacePermissionManager::check(
            conn,
            &ns_alpha,
            &agent_a_id,
            NamespacePermission::Read,
        )?;
        assert!(a_can_read, "Owner Agent A should have read permission on team-alpha");

        // Agent A (owner) should have write permission.
        let a_can_write = NamespacePermissionManager::check(
            conn,
            &ns_alpha,
            &agent_a_id,
            NamespacePermission::Write,
        )?;
        assert!(a_can_write, "Owner Agent A should have write permission on team-alpha");

        // Agent B should NOT have read permission on Agent A's namespace.
        let b_can_read = NamespacePermissionManager::check(
            conn,
            &ns_alpha,
            &agent_b_id,
            NamespacePermission::Read,
        )?;
        assert!(
            !b_can_read,
            "Agent B should NOT have read permission on team-alpha"
        );

        // Agent B should NOT have write permission.
        let b_can_write = NamespacePermissionManager::check(
            conn,
            &ns_alpha,
            &agent_b_id,
            NamespacePermission::Write,
        )?;
        assert!(
            !b_can_write,
            "Agent B should NOT have write permission on team-alpha"
        );

        // Verify scope-based default permissions:
        // Agent scope: owner gets all 4 permissions.
        let ns_agent = NamespaceId {
            scope: NamespaceScope::Agent("personal".into()),
            name: "personal".into(),
        };
        NamespaceManager::create_namespace(conn, &ns_agent, &agent_a_id)?;

        let a_agent_admin = NamespacePermissionManager::check(
            conn,
            &ns_agent,
            &agent_a_id,
            NamespacePermission::Admin,
        )?;
        assert!(a_agent_admin, "Agent scope owner should have Admin");
        let a_agent_share = NamespacePermissionManager::check(
            conn,
            &ns_agent,
            &agent_a_id,
            NamespacePermission::Share,
        )?;
        assert!(a_agent_share, "Agent scope owner should have Share");

        // Project scope: owner gets read only.
        let ns_project = NamespaceId {
            scope: NamespaceScope::Project("global".into()),
            name: "global".into(),
        };
        NamespaceManager::create_namespace(conn, &ns_project, &agent_a_id)?;

        // Owner still has implicit admin via ownership, so check non-owner.
        // Agent B has no permissions on the project namespace.
        let b_project_read = NamespacePermissionManager::check(
            conn,
            &ns_project,
            &agent_b_id,
            NamespacePermission::Read,
        )?;
        assert!(
            !b_project_read,
            "Non-owner Agent B should NOT have read on project namespace"
        );

        Ok(())
    })
    .unwrap();
}
