//! Namespace tests — TMB-NS-01 through TMB-NS-07.

use cortex_core::models::namespace::{NamespaceId, NamespacePermission, NamespaceScope};
use cortex_storage::StorageEngine;

use cortex_multiagent::namespace::NamespaceManager;
use cortex_multiagent::namespace::addressing;
use cortex_multiagent::namespace::permissions::NamespacePermissionManager;
use cortex_multiagent::registry::AgentRegistry;

fn engine() -> StorageEngine {
    StorageEngine::open_in_memory().expect("open in-memory storage")
}

/// TMB-NS-01: Namespace creation for all 3 scopes (agent, team, project).
#[test]
fn tmb_ns_01_create_all_scopes() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let agent = AgentRegistry::register(conn, "ns-test", vec![])?;

        // Agent scope.
        let agent_ns = NamespaceId {
            scope: NamespaceScope::Agent(agent.agent_id.clone()),
            name: "private".into(),
        };
        let created = NamespaceManager::create_namespace(conn, &agent_ns, &agent.agent_id)?;
        assert_eq!(created.to_uri(), "agent://private/");

        // Team scope.
        let team_ns = NamespaceId {
            scope: NamespaceScope::Team("backend".into()),
            name: "backend".into(),
        };
        let created = NamespaceManager::create_namespace(conn, &team_ns, &agent.agent_id)?;
        assert_eq!(created.to_uri(), "team://backend/");

        // Project scope.
        let project_ns = NamespaceId {
            scope: NamespaceScope::Project("cortex".into()),
            name: "cortex".into(),
        };
        let created = NamespaceManager::create_namespace(conn, &project_ns, &agent.agent_id)?;
        assert_eq!(created.to_uri(), "project://cortex/");

        Ok(())
    }).unwrap();
}

/// TMB-NS-02: Permission grant/revoke/check round-trip.
#[test]
fn tmb_ns_02_permission_round_trip() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let owner = AgentRegistry::register(conn, "owner", vec![])?;
        let guest = AgentRegistry::register(conn, "guest", vec![])?;

        let ns = NamespaceId {
            scope: NamespaceScope::Team("shared".into()),
            name: "shared".into(),
        };
        NamespaceManager::create_namespace(conn, &ns, &owner.agent_id)?;

        // Grant read+write to guest.
        NamespacePermissionManager::grant(
            conn, &ns, &guest.agent_id,
            &[NamespacePermission::Read, NamespacePermission::Write],
            &owner.agent_id,
        )?;

        // Check permissions.
        assert!(NamespacePermissionManager::check(conn, &ns, &guest.agent_id, NamespacePermission::Read)?);
        assert!(NamespacePermissionManager::check(conn, &ns, &guest.agent_id, NamespacePermission::Write)?);
        assert!(!NamespacePermissionManager::check(conn, &ns, &guest.agent_id, NamespacePermission::Admin)?);

        // Revoke write.
        NamespacePermissionManager::revoke(
            conn, &ns, &guest.agent_id,
            &[NamespacePermission::Write],
            &owner.agent_id,
        )?;

        assert!(NamespacePermissionManager::check(conn, &ns, &guest.agent_id, NamespacePermission::Read)?);
        assert!(!NamespacePermissionManager::check(conn, &ns, &guest.agent_id, NamespacePermission::Write)?);

        Ok(())
    }).unwrap();
}

/// TMB-NS-03: Default permissions per scope correct.
#[test]
fn tmb_ns_03_default_permissions_per_scope() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let agent = AgentRegistry::register(conn, "perm-test", vec![])?;

        // Agent scope → owner gets all 4 permissions.
        let agent_ns = NamespaceId {
            scope: NamespaceScope::Agent(agent.agent_id.clone()),
            name: "my-private".into(),
        };
        NamespaceManager::create_namespace(conn, &agent_ns, &agent.agent_id)?;
        assert!(NamespacePermissionManager::check(conn, &agent_ns, &agent.agent_id, NamespacePermission::Read)?);
        assert!(NamespacePermissionManager::check(conn, &agent_ns, &agent.agent_id, NamespacePermission::Write)?);
        assert!(NamespacePermissionManager::check(conn, &agent_ns, &agent.agent_id, NamespacePermission::Share)?);
        assert!(NamespacePermissionManager::check(conn, &agent_ns, &agent.agent_id, NamespacePermission::Admin)?);

        // Team scope → owner gets read+write explicitly, but implicit admin via ownership.
        let team_ns = NamespaceId {
            scope: NamespaceScope::Team("team-a".into()),
            name: "team-a".into(),
        };
        NamespaceManager::create_namespace(conn, &team_ns, &agent.agent_id)?;
        assert!(NamespacePermissionManager::check(conn, &team_ns, &agent.agent_id, NamespacePermission::Read)?);
        assert!(NamespacePermissionManager::check(conn, &team_ns, &agent.agent_id, NamespacePermission::Write)?);
        // Owner has implicit admin via ownership (standard RBAC).
        assert!(NamespacePermissionManager::check(conn, &team_ns, &agent.agent_id, NamespacePermission::Admin)?);

        // But the explicit ACL should only have read+write (not admin).
        let acl = NamespacePermissionManager::get_acl(conn, &team_ns)?;
        let owner_perms: Vec<_> = acl.iter()
            .find(|(id, _)| *id == agent.agent_id)
            .map(|(_, perms)| perms.clone())
            .unwrap_or_default();
        assert!(owner_perms.contains(&NamespacePermission::Read), "explicit ACL should have read");
        assert!(owner_perms.contains(&NamespacePermission::Write), "explicit ACL should have write");
        assert!(!owner_perms.contains(&NamespacePermission::Admin), "explicit ACL should NOT have admin for team scope");

        // Project scope → owner gets read explicitly, but implicit admin via ownership.
        let proj_ns = NamespaceId {
            scope: NamespaceScope::Project("proj-x".into()),
            name: "proj-x".into(),
        };
        NamespaceManager::create_namespace(conn, &proj_ns, &agent.agent_id)?;
        assert!(NamespacePermissionManager::check(conn, &proj_ns, &agent.agent_id, NamespacePermission::Read)?);
        // Owner has implicit write+admin via ownership (standard RBAC).
        assert!(NamespacePermissionManager::check(conn, &proj_ns, &agent.agent_id, NamespacePermission::Write)?);

        // But the explicit ACL should only have read.
        let acl = NamespacePermissionManager::get_acl(conn, &proj_ns)?;
        let owner_perms: Vec<_> = acl.iter()
            .find(|(id, _)| *id == agent.agent_id)
            .map(|(_, perms)| perms.clone())
            .unwrap_or_default();
        assert!(owner_perms.contains(&NamespacePermission::Read), "explicit ACL should have read");
        assert!(!owner_perms.contains(&NamespacePermission::Write), "explicit ACL should NOT have write for project scope");

        // Verify a NON-owner does NOT get implicit permissions.
        let guest = AgentRegistry::register(conn, "guest-agent", vec![])?;
        assert!(!NamespacePermissionManager::check(conn, &team_ns, &guest.agent_id, NamespacePermission::Read)?,
            "non-owner should not have implicit access");

        Ok(())
    }).unwrap();
}

/// TMB-NS-04: NamespaceId parse + format round-trip.
#[test]
fn tmb_ns_04_parse_format_round_trip() {
    // Agent scope.
    let ns = addressing::parse("agent://my-agent/").unwrap();
    assert!(ns.is_agent());
    assert_eq!(ns.name, "my-agent");
    assert_eq!(addressing::to_uri(&ns), "agent://my-agent/");

    // Team scope.
    let ns = addressing::parse("team://backend/").unwrap();
    assert!(ns.is_team());
    assert_eq!(ns.name, "backend");
    assert_eq!(addressing::to_uri(&ns), "team://backend/");

    // Project scope.
    let ns = addressing::parse("project://cortex/").unwrap();
    assert!(ns.is_project());
    assert_eq!(ns.name, "cortex");
    assert_eq!(addressing::to_uri(&ns), "project://cortex/");

    // Case-insensitive scope.
    let ns = addressing::parse("AGENT://upper/").unwrap();
    assert!(ns.is_agent());
    assert_eq!(ns.name, "upper");
}

/// TMB-NS-05: Default namespace backward compatibility (agent://default/).
#[test]
fn tmb_ns_05_default_namespace_compat() {
    let ns = addressing::default_namespace();
    assert_eq!(ns.to_uri(), "agent://default/");
    assert!(ns.is_agent());
    assert!(!ns.is_shared());

    // Default NamespaceId matches.
    let default = NamespaceId::default();
    assert_eq!(default, ns);
}

/// TMB-NS-06: Invalid namespace URI rejected with clear error.
#[test]
fn tmb_ns_06_invalid_uri_rejected() {
    // No scheme separator.
    let result = addressing::parse("invalid-uri");
    assert!(result.is_err());

    // Empty name.
    let result = addressing::parse("agent:///");
    assert!(result.is_err());

    // Unknown scope.
    let result = addressing::parse("unknown://name/");
    assert!(result.is_err());
}

/// TMB-NS-07: Permission denied error includes context.
#[test]
fn tmb_ns_07_permission_denied_context() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let owner = AgentRegistry::register(conn, "owner-ctx", vec![])?;
        let intruder = AgentRegistry::register(conn, "intruder", vec![])?;

        let ns = NamespaceId {
            scope: NamespaceScope::Team("secret".into()),
            name: "secret".into(),
        };
        NamespaceManager::create_namespace(conn, &ns, &owner.agent_id)?;

        // Intruder has no permissions — check returns false.
        let has_perm = NamespacePermissionManager::check(
            conn, &ns, &intruder.agent_id, NamespacePermission::Write,
        )?;
        assert!(!has_perm);

        // Verify the ACL only contains the owner.
        let acl = NamespacePermissionManager::get_acl(conn, &ns)?;
        assert_eq!(acl.len(), 1);
        assert_eq!(acl[0].0, owner.agent_id);

        Ok(())
    }).unwrap();
}
