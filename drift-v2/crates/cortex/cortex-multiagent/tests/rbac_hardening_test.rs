//! RBAC hardening tests — dedicated regression coverage for the implicit owner
//! admin model and all permission boundary conditions.
//!
//! These tests exercise the security-critical invariants introduced when
//! `NamespacePermissionManager::check()` was updated to grant implicit admin
//! (and therefore all permissions) to namespace owners.

use cortex_core::models::namespace::{NamespaceId, NamespacePermission, NamespaceScope};
use cortex_storage::StorageEngine;

use cortex_multiagent::namespace::NamespaceManager;
use cortex_multiagent::namespace::permissions::NamespacePermissionManager;
use cortex_multiagent::registry::AgentRegistry;

fn engine() -> StorageEngine {
    StorageEngine::open_in_memory().expect("open in-memory storage")
}

const ALL_PERMS: [NamespacePermission; 4] = [
    NamespacePermission::Read,
    NamespacePermission::Write,
    NamespacePermission::Share,
    NamespacePermission::Admin,
];

// ---------------------------------------------------------------------------
// 1. Owner implicit permissions — all scopes, all permission types
// ---------------------------------------------------------------------------

/// RBAC-01: Agent-scope owner has all 4 permissions (explicit + implicit).
#[test]
fn rbac_01_agent_scope_owner_all_perms() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let owner = AgentRegistry::register(conn, "rbac01-owner", vec![])?;
        let ns = NamespaceId {
            scope: NamespaceScope::Agent(owner.agent_id.clone()),
            name: "rbac01".into(),
        };
        NamespaceManager::create_namespace(conn, &ns, &owner.agent_id)?;

        for perm in &ALL_PERMS {
            assert!(
                NamespacePermissionManager::check(conn, &ns, &owner.agent_id, *perm)?,
                "agent-scope owner must have {:?}",
                perm
            );
        }
        Ok(())
    })
    .unwrap();
}

/// RBAC-02: Team-scope owner has all 4 permissions via implicit admin,
/// even though explicit ACL only has read+write.
#[test]
fn rbac_02_team_scope_owner_implicit_admin() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let owner = AgentRegistry::register(conn, "rbac02-owner", vec![])?;
        let ns = NamespaceId {
            scope: NamespaceScope::Team("rbac02-team".into()),
            name: "rbac02-team".into(),
        };
        NamespaceManager::create_namespace(conn, &ns, &owner.agent_id)?;

        // All 4 permissions should pass check() via ownership.
        for perm in &ALL_PERMS {
            assert!(
                NamespacePermissionManager::check(conn, &ns, &owner.agent_id, *perm)?,
                "team-scope owner must have {:?} (implicit)",
                perm
            );
        }

        // But explicit ACL should only show read+write.
        let acl = NamespacePermissionManager::get_acl(conn, &ns)?;
        let explicit: Vec<_> = acl
            .iter()
            .find(|(id, _)| *id == owner.agent_id)
            .map(|(_, p)| p.clone())
            .unwrap_or_default();
        assert!(explicit.contains(&NamespacePermission::Read));
        assert!(explicit.contains(&NamespacePermission::Write));
        assert!(!explicit.contains(&NamespacePermission::Share));
        assert!(!explicit.contains(&NamespacePermission::Admin));

        Ok(())
    })
    .unwrap();
}

/// RBAC-03: Project-scope owner has all 4 permissions via implicit admin,
/// even though explicit ACL only has read.
#[test]
fn rbac_03_project_scope_owner_implicit_admin() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let owner = AgentRegistry::register(conn, "rbac03-owner", vec![])?;
        let ns = NamespaceId {
            scope: NamespaceScope::Project("rbac03-proj".into()),
            name: "rbac03-proj".into(),
        };
        NamespaceManager::create_namespace(conn, &ns, &owner.agent_id)?;

        for perm in &ALL_PERMS {
            assert!(
                NamespacePermissionManager::check(conn, &ns, &owner.agent_id, *perm)?,
                "project-scope owner must have {:?} (implicit)",
                perm
            );
        }

        let acl = NamespacePermissionManager::get_acl(conn, &ns)?;
        let explicit: Vec<_> = acl
            .iter()
            .find(|(id, _)| *id == owner.agent_id)
            .map(|(_, p)| p.clone())
            .unwrap_or_default();
        assert!(explicit.contains(&NamespacePermission::Read));
        assert!(!explicit.contains(&NamespacePermission::Write));
        assert!(!explicit.contains(&NamespacePermission::Share));
        assert!(!explicit.contains(&NamespacePermission::Admin));

        Ok(())
    })
    .unwrap();
}

// ---------------------------------------------------------------------------
// 2. Non-owner denial — hard negative tests
// ---------------------------------------------------------------------------

/// RBAC-04: A non-owner with NO ACL entries is denied every permission type.
#[test]
fn rbac_04_non_owner_no_acl_denied_all() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let owner = AgentRegistry::register(conn, "rbac04-owner", vec![])?;
        let stranger = AgentRegistry::register(conn, "rbac04-stranger", vec![])?;

        let ns = NamespaceId {
            scope: NamespaceScope::Team("rbac04-team".into()),
            name: "rbac04-team".into(),
        };
        NamespaceManager::create_namespace(conn, &ns, &owner.agent_id)?;

        for perm in &ALL_PERMS {
            assert!(
                !NamespacePermissionManager::check(conn, &ns, &stranger.agent_id, *perm)?,
                "non-owner without ACL must be denied {:?}",
                perm
            );
        }
        Ok(())
    })
    .unwrap();
}

/// RBAC-05: Non-owner with explicit Read grant gets Read only, nothing else.
#[test]
fn rbac_05_non_owner_explicit_read_only() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let owner = AgentRegistry::register(conn, "rbac05-owner", vec![])?;
        let guest = AgentRegistry::register(conn, "rbac05-guest", vec![])?;

        let ns = NamespaceId {
            scope: NamespaceScope::Team("rbac05-team".into()),
            name: "rbac05-team".into(),
        };
        NamespaceManager::create_namespace(conn, &ns, &owner.agent_id)?;
        NamespacePermissionManager::grant(
            conn,
            &ns,
            &guest.agent_id,
            &[NamespacePermission::Read],
            &owner.agent_id,
        )?;

        assert!(NamespacePermissionManager::check(
            conn,
            &ns,
            &guest.agent_id,
            NamespacePermission::Read
        )?);
        assert!(!NamespacePermissionManager::check(
            conn,
            &ns,
            &guest.agent_id,
            NamespacePermission::Write
        )?);
        assert!(!NamespacePermissionManager::check(
            conn,
            &ns,
            &guest.agent_id,
            NamespacePermission::Share
        )?);
        assert!(!NamespacePermissionManager::check(
            conn,
            &ns,
            &guest.agent_id,
            NamespacePermission::Admin
        )?);

        Ok(())
    })
    .unwrap();
}

/// RBAC-06: Non-owner with explicit Admin gets all 4 via the ACL check fast-path.
#[test]
fn rbac_06_non_owner_explicit_admin_gets_all() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let owner = AgentRegistry::register(conn, "rbac06-owner", vec![])?;
        let admin_guest = AgentRegistry::register(conn, "rbac06-admin", vec![])?;

        let ns = NamespaceId {
            scope: NamespaceScope::Team("rbac06-team".into()),
            name: "rbac06-team".into(),
        };
        NamespaceManager::create_namespace(conn, &ns, &owner.agent_id)?;
        NamespacePermissionManager::grant(
            conn,
            &ns,
            &admin_guest.agent_id,
            &ALL_PERMS,
            &owner.agent_id,
        )?;

        for perm in &ALL_PERMS {
            assert!(
                NamespacePermissionManager::check(
                    conn,
                    &ns,
                    &admin_guest.agent_id,
                    *perm
                )?,
                "non-owner with explicit admin must have {:?}",
                perm
            );
        }
        Ok(())
    })
    .unwrap();
}

// ---------------------------------------------------------------------------
// 3. Grant/Revoke authorization — who can manage permissions
// ---------------------------------------------------------------------------

/// RBAC-07: Team-scope owner (no explicit admin) can grant permissions.
#[test]
fn rbac_07_team_owner_can_grant_without_explicit_admin() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let owner = AgentRegistry::register(conn, "rbac07-owner", vec![])?;
        let guest = AgentRegistry::register(conn, "rbac07-guest", vec![])?;

        let ns = NamespaceId {
            scope: NamespaceScope::Team("rbac07-team".into()),
            name: "rbac07-team".into(),
        };
        NamespaceManager::create_namespace(conn, &ns, &owner.agent_id)?;

        // Owner has only read+write in ACL, but implicit admin via ownership.
        let result = NamespacePermissionManager::grant(
            conn,
            &ns,
            &guest.agent_id,
            &[NamespacePermission::Read, NamespacePermission::Write],
            &owner.agent_id,
        );
        assert!(result.is_ok(), "owner must be able to grant");

        assert!(NamespacePermissionManager::check(
            conn,
            &ns,
            &guest.agent_id,
            NamespacePermission::Read
        )?);
        assert!(NamespacePermissionManager::check(
            conn,
            &ns,
            &guest.agent_id,
            NamespacePermission::Write
        )?);

        Ok(())
    })
    .unwrap();
}

/// RBAC-08: Team-scope owner can revoke permissions without explicit admin.
#[test]
fn rbac_08_team_owner_can_revoke_without_explicit_admin() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let owner = AgentRegistry::register(conn, "rbac08-owner", vec![])?;
        let guest = AgentRegistry::register(conn, "rbac08-guest", vec![])?;

        let ns = NamespaceId {
            scope: NamespaceScope::Team("rbac08-team".into()),
            name: "rbac08-team".into(),
        };
        NamespaceManager::create_namespace(conn, &ns, &owner.agent_id)?;
        NamespacePermissionManager::grant(
            conn,
            &ns,
            &guest.agent_id,
            &[NamespacePermission::Read],
            &owner.agent_id,
        )?;
        assert!(NamespacePermissionManager::check(
            conn,
            &ns,
            &guest.agent_id,
            NamespacePermission::Read
        )?);

        let result = NamespacePermissionManager::revoke(
            conn,
            &ns,
            &guest.agent_id,
            &[NamespacePermission::Read],
            &owner.agent_id,
        );
        assert!(result.is_ok(), "owner must be able to revoke");

        assert!(!NamespacePermissionManager::check(
            conn,
            &ns,
            &guest.agent_id,
            NamespacePermission::Read
        )?);

        Ok(())
    })
    .unwrap();
}

/// RBAC-09: Non-owner without admin permission cannot grant.
#[test]
fn rbac_09_non_owner_no_admin_cannot_grant() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let owner = AgentRegistry::register(conn, "rbac09-owner", vec![])?;
        let reader = AgentRegistry::register(conn, "rbac09-reader", vec![])?;
        let target = AgentRegistry::register(conn, "rbac09-target", vec![])?;

        let ns = NamespaceId {
            scope: NamespaceScope::Team("rbac09-team".into()),
            name: "rbac09-team".into(),
        };
        NamespaceManager::create_namespace(conn, &ns, &owner.agent_id)?;

        // Give reader only Read permission.
        NamespacePermissionManager::grant(
            conn,
            &ns,
            &reader.agent_id,
            &[NamespacePermission::Read],
            &owner.agent_id,
        )?;

        // Reader tries to grant — must fail.
        let result = NamespacePermissionManager::grant(
            conn,
            &ns,
            &target.agent_id,
            &[NamespacePermission::Read],
            &reader.agent_id,
        );
        assert!(
            result.is_err(),
            "non-owner without admin must not be able to grant"
        );

        Ok(())
    })
    .unwrap();
}

/// RBAC-10: Non-owner without admin permission cannot revoke.
#[test]
fn rbac_10_non_owner_no_admin_cannot_revoke() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let owner = AgentRegistry::register(conn, "rbac10-owner", vec![])?;
        let reader = AgentRegistry::register(conn, "rbac10-reader", vec![])?;
        let guest = AgentRegistry::register(conn, "rbac10-guest", vec![])?;

        let ns = NamespaceId {
            scope: NamespaceScope::Team("rbac10-team".into()),
            name: "rbac10-team".into(),
        };
        NamespaceManager::create_namespace(conn, &ns, &owner.agent_id)?;
        NamespacePermissionManager::grant(
            conn,
            &ns,
            &reader.agent_id,
            &[NamespacePermission::Read],
            &owner.agent_id,
        )?;
        NamespacePermissionManager::grant(
            conn,
            &ns,
            &guest.agent_id,
            &[NamespacePermission::Read],
            &owner.agent_id,
        )?;

        // Reader tries to revoke guest — must fail.
        let result = NamespacePermissionManager::revoke(
            conn,
            &ns,
            &guest.agent_id,
            &[NamespacePermission::Read],
            &reader.agent_id,
        );
        assert!(
            result.is_err(),
            "non-owner without admin must not be able to revoke"
        );

        // Guest still has the permission.
        assert!(NamespacePermissionManager::check(
            conn,
            &ns,
            &guest.agent_id,
            NamespacePermission::Read
        )?);

        Ok(())
    })
    .unwrap();
}

/// RBAC-11: Non-owner WITH explicit Admin CAN grant.
#[test]
fn rbac_11_non_owner_with_admin_can_grant() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let owner = AgentRegistry::register(conn, "rbac11-owner", vec![])?;
        let delegated_admin = AgentRegistry::register(conn, "rbac11-admin", vec![])?;
        let target = AgentRegistry::register(conn, "rbac11-target", vec![])?;

        let ns = NamespaceId {
            scope: NamespaceScope::Team("rbac11-team".into()),
            name: "rbac11-team".into(),
        };
        NamespaceManager::create_namespace(conn, &ns, &owner.agent_id)?;

        // Owner delegates admin to another agent.
        NamespacePermissionManager::grant(
            conn,
            &ns,
            &delegated_admin.agent_id,
            &[NamespacePermission::Admin],
            &owner.agent_id,
        )?;

        // Delegated admin grants read to target.
        let result = NamespacePermissionManager::grant(
            conn,
            &ns,
            &target.agent_id,
            &[NamespacePermission::Read],
            &delegated_admin.agent_id,
        );
        assert!(result.is_ok(), "delegated admin must be able to grant");

        assert!(NamespacePermissionManager::check(
            conn,
            &ns,
            &target.agent_id,
            NamespacePermission::Read
        )?);

        Ok(())
    })
    .unwrap();
}

// ---------------------------------------------------------------------------
// 4. Edge cases and boundary conditions
// ---------------------------------------------------------------------------

/// RBAC-12: After namespace deletion, check() returns false (no implicit admin
/// from a deleted namespace). Must revoke all explicit ACL entries first since
/// the permissions table has a FK constraint to the namespace table.
#[test]
fn rbac_12_deleted_namespace_no_implicit_admin() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let owner = AgentRegistry::register(conn, "rbac12-owner", vec![])?;
        let ns = NamespaceId {
            scope: NamespaceScope::Agent(owner.agent_id.clone()),
            name: "rbac12".into(),
        };
        NamespaceManager::create_namespace(conn, &ns, &owner.agent_id)?;

        // Owner has admin.
        assert!(NamespacePermissionManager::check(
            conn,
            &ns,
            &owner.agent_id,
            NamespacePermission::Admin
        )?);

        // Clean up: revoke all explicit permissions before deleting namespace
        // (FK constraint: permissions → namespace).
        NamespacePermissionManager::revoke(
            conn,
            &ns,
            &owner.agent_id,
            &ALL_PERMS,
            &owner.agent_id,
        )?;

        // Delete the namespace.
        NamespaceManager::delete_namespace(conn, &ns)?;

        // After deletion, check should return false (namespace row gone,
        // ownership lookup yields None).
        assert!(
            !NamespacePermissionManager::check(
                conn,
                &ns,
                &owner.agent_id,
                NamespacePermission::Admin
            )?,
            "deleted namespace must not grant implicit admin"
        );
        // Verify all permission types are denied.
        for perm in &ALL_PERMS {
            assert!(
                !NamespacePermissionManager::check(conn, &ns, &owner.agent_id, *perm)?,
                "deleted namespace must deny {:?}",
                perm
            );
        }

        Ok(())
    })
    .unwrap();
}

/// RBAC-13: check() fast-path — explicit ACL hit returns true without
/// needing the ownership lookup. Verified by checking a non-owner who has
/// an explicit grant on a namespace.
#[test]
fn rbac_13_check_fast_path_explicit_acl() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let owner = AgentRegistry::register(conn, "rbac13-owner", vec![])?;
        let guest = AgentRegistry::register(conn, "rbac13-guest", vec![])?;

        let ns = NamespaceId {
            scope: NamespaceScope::Team("rbac13-team".into()),
            name: "rbac13-team".into(),
        };
        NamespaceManager::create_namespace(conn, &ns, &owner.agent_id)?;
        NamespacePermissionManager::grant(
            conn,
            &ns,
            &guest.agent_id,
            &[NamespacePermission::Read, NamespacePermission::Write],
            &owner.agent_id,
        )?;

        // These should hit the explicit ACL fast-path (no ownership lookup needed).
        assert!(NamespacePermissionManager::check(
            conn,
            &ns,
            &guest.agent_id,
            NamespacePermission::Read
        )?);
        assert!(NamespacePermissionManager::check(
            conn,
            &ns,
            &guest.agent_id,
            NamespacePermission::Write
        )?);

        // These should fail — guest has no Share/Admin in ACL and is not owner.
        assert!(!NamespacePermissionManager::check(
            conn,
            &ns,
            &guest.agent_id,
            NamespacePermission::Share
        )?);
        assert!(!NamespacePermissionManager::check(
            conn,
            &ns,
            &guest.agent_id,
            NamespacePermission::Admin
        )?);

        Ok(())
    })
    .unwrap();
}

/// RBAC-14: Revoking the owner's explicit permissions does NOT remove their
/// implicit admin via ownership.
#[test]
fn rbac_14_revoke_owner_explicit_keeps_implicit() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let owner = AgentRegistry::register(conn, "rbac14-owner", vec![])?;
        let ns = NamespaceId {
            scope: NamespaceScope::Team("rbac14-team".into()),
            name: "rbac14-team".into(),
        };
        NamespaceManager::create_namespace(conn, &ns, &owner.agent_id)?;

        // Owner starts with explicit read+write.
        assert!(NamespacePermissionManager::check(
            conn,
            &ns,
            &owner.agent_id,
            NamespacePermission::Read
        )?);

        // Revoke all explicit permissions from the owner.
        NamespacePermissionManager::revoke(
            conn,
            &ns,
            &owner.agent_id,
            &[NamespacePermission::Read, NamespacePermission::Write],
            &owner.agent_id,
        )?;

        // Explicit ACL is now empty for owner.
        let acl = NamespacePermissionManager::get_acl(conn, &ns)?;
        let owner_explicit: Vec<_> = acl
            .iter()
            .find(|(id, _)| *id == owner.agent_id)
            .map(|(_, p)| p.clone())
            .unwrap_or_default();
        assert!(
            owner_explicit.is_empty(),
            "explicit ACL should be empty after full revoke"
        );

        // But owner still has implicit permissions via ownership.
        for perm in &ALL_PERMS {
            assert!(
                NamespacePermissionManager::check(conn, &ns, &owner.agent_id, *perm)?,
                "owner must retain implicit {:?} after explicit revoke",
                perm
            );
        }

        Ok(())
    })
    .unwrap();
}

/// RBAC-15: Grant + revoke round-trip across all permission types on all scopes.
#[test]
fn rbac_15_grant_revoke_full_matrix() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let owner = AgentRegistry::register(conn, "rbac15-owner", vec![])?;
        let guest = AgentRegistry::register(conn, "rbac15-guest", vec![])?;

        let scopes = vec![
            NamespaceId {
                scope: NamespaceScope::Agent(owner.agent_id.clone()),
                name: "rbac15-agent".into(),
            },
            NamespaceId {
                scope: NamespaceScope::Team("rbac15-team".into()),
                name: "rbac15-team".into(),
            },
            NamespaceId {
                scope: NamespaceScope::Project("rbac15-proj".into()),
                name: "rbac15-proj".into(),
            },
        ];

        for ns in &scopes {
            NamespaceManager::create_namespace(conn, ns, &owner.agent_id)?;

            // Grant all 4 to guest.
            NamespacePermissionManager::grant(
                conn,
                ns,
                &guest.agent_id,
                &ALL_PERMS,
                &owner.agent_id,
            )?;
            for perm in &ALL_PERMS {
                assert!(
                    NamespacePermissionManager::check(conn, ns, &guest.agent_id, *perm)?,
                    "guest should have {:?} on {}",
                    perm,
                    ns.to_uri()
                );
            }

            // Revoke all 4.
            NamespacePermissionManager::revoke(
                conn,
                ns,
                &guest.agent_id,
                &ALL_PERMS,
                &owner.agent_id,
            )?;
            for perm in &ALL_PERMS {
                assert!(
                    !NamespacePermissionManager::check(conn, ns, &guest.agent_id, *perm)?,
                    "guest should NOT have {:?} on {} after revoke",
                    perm,
                    ns.to_uri()
                );
            }
        }
        Ok(())
    })
    .unwrap();
}

/// RBAC-16: Project-scope owner can manage permissions despite only having
/// explicit "read" in ACL.
#[test]
fn rbac_16_project_owner_manages_permissions() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let owner = AgentRegistry::register(conn, "rbac16-owner", vec![])?;
        let guest = AgentRegistry::register(conn, "rbac16-guest", vec![])?;

        let ns = NamespaceId {
            scope: NamespaceScope::Project("rbac16-proj".into()),
            name: "rbac16-proj".into(),
        };
        NamespaceManager::create_namespace(conn, &ns, &owner.agent_id)?;

        // Project owner only has explicit "read", but should still be able to
        // grant+revoke via implicit ownership admin.
        let grant_result = NamespacePermissionManager::grant(
            conn,
            &ns,
            &guest.agent_id,
            &[NamespacePermission::Read, NamespacePermission::Write],
            &owner.agent_id,
        );
        assert!(
            grant_result.is_ok(),
            "project owner must be able to grant via implicit admin"
        );

        assert!(NamespacePermissionManager::check(
            conn,
            &ns,
            &guest.agent_id,
            NamespacePermission::Write
        )?);

        let revoke_result = NamespacePermissionManager::revoke(
            conn,
            &ns,
            &guest.agent_id,
            &[NamespacePermission::Write],
            &owner.agent_id,
        );
        assert!(
            revoke_result.is_ok(),
            "project owner must be able to revoke via implicit admin"
        );

        assert!(!NamespacePermissionManager::check(
            conn,
            &ns,
            &guest.agent_id,
            NamespacePermission::Write
        )?);

        Ok(())
    })
    .unwrap();
}

/// RBAC-17: Multiple agents on the same namespace — each has isolated permissions.
#[test]
fn rbac_17_multi_agent_isolation() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let owner = AgentRegistry::register(conn, "rbac17-owner", vec![])?;
        let alice = AgentRegistry::register(conn, "rbac17-alice", vec![])?;
        let bob = AgentRegistry::register(conn, "rbac17-bob", vec![])?;

        let ns = NamespaceId {
            scope: NamespaceScope::Team("rbac17-team".into()),
            name: "rbac17-team".into(),
        };
        NamespaceManager::create_namespace(conn, &ns, &owner.agent_id)?;

        // Alice gets read+write, Bob gets read only.
        NamespacePermissionManager::grant(
            conn,
            &ns,
            &alice.agent_id,
            &[NamespacePermission::Read, NamespacePermission::Write],
            &owner.agent_id,
        )?;
        NamespacePermissionManager::grant(
            conn,
            &ns,
            &bob.agent_id,
            &[NamespacePermission::Read],
            &owner.agent_id,
        )?;

        // Alice can write, Bob cannot.
        assert!(NamespacePermissionManager::check(
            conn,
            &ns,
            &alice.agent_id,
            NamespacePermission::Write
        )?);
        assert!(!NamespacePermissionManager::check(
            conn,
            &ns,
            &bob.agent_id,
            NamespacePermission::Write
        )?);

        // Revoking Alice's write doesn't affect Bob's read.
        NamespacePermissionManager::revoke(
            conn,
            &ns,
            &alice.agent_id,
            &[NamespacePermission::Write],
            &owner.agent_id,
        )?;
        assert!(NamespacePermissionManager::check(
            conn,
            &ns,
            &bob.agent_id,
            NamespacePermission::Read
        )?);

        Ok(())
    })
    .unwrap();
}

/// RBAC-18: check() on a non-existent namespace returns false (not an error).
#[test]
fn rbac_18_nonexistent_namespace_returns_false() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let agent = AgentRegistry::register(conn, "rbac18-agent", vec![])?;
        let ns = NamespaceId {
            scope: NamespaceScope::Team("does-not-exist".into()),
            name: "does-not-exist".into(),
        };

        // Should return false, not error.
        let result =
            NamespacePermissionManager::check(conn, &ns, &agent.agent_id, NamespacePermission::Read)?;
        assert!(!result, "non-existent namespace must return false");

        Ok(())
    })
    .unwrap();
}
