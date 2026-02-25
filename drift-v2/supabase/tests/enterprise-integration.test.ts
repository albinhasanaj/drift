/**
 * Phase G2: Enterprise Feature Integration Tests
 * CT0-G-11: SCIM + webhook + audit cross-feature
 * CT0-G-12: Team + IP allowlist cross-feature
 * CT0-G-13: Full enterprise lifecycle flow
 *
 * These tests verify Phase D (SCIM), Phase E (Webhooks), and Phase F
 * (Audit/Teams/IP) work together as a coherent enterprise platform.
 *
 * Test environment: Supabase CLI local dev (supabase start).
 */

import {
  assertEquals,
  assertExists,
  assert,
} from "https://deno.land/std@0.208.0/assert/mod.ts";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "http://localhost:54321";
const SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";

const SCIM_USERS_URL = Deno.env.get("SUPABASE_FUNCTIONS_URL")
  ? `${Deno.env.get("SUPABASE_FUNCTIONS_URL")}/scim-users`
  : "http://localhost:54321/functions/v1/scim-users";
const WEBHOOKS_URL = Deno.env.get("SUPABASE_FUNCTIONS_URL")
  ? `${Deno.env.get("SUPABASE_FUNCTIONS_URL")}/webhooks`
  : "http://localhost:54321/functions/v1/webhooks";
const TEAMS_URL = Deno.env.get("SUPABASE_FUNCTIONS_URL")
  ? `${Deno.env.get("SUPABASE_FUNCTIONS_URL")}/teams`
  : "http://localhost:54321/functions/v1/teams";
const INVITATIONS_URL = Deno.env.get("SUPABASE_FUNCTIONS_URL")
  ? `${Deno.env.get("SUPABASE_FUNCTIONS_URL")}/invitations`
  : "http://localhost:54321/functions/v1/invitations";
const SETTINGS_URL = Deno.env.get("SUPABASE_FUNCTIONS_URL")
  ? `${Deno.env.get("SUPABASE_FUNCTIONS_URL")}/settings`
  : "http://localhost:54321/functions/v1/settings";
const AUDIT_URL = Deno.env.get("SUPABASE_FUNCTIONS_URL")
  ? `${Deno.env.get("SUPABASE_FUNCTIONS_URL")}/audit`
  : "http://localhost:54321/functions/v1/audit";
const MEMBERS_URL = Deno.env.get("SUPABASE_FUNCTIONS_URL")
  ? `${Deno.env.get("SUPABASE_FUNCTIONS_URL")}/members`
  : "http://localhost:54321/functions/v1/members";

const adminHeaders = {
  "Content-Type": "application/json",
  apikey: SERVICE_ROLE_KEY,
  Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
};

async function setupEnterpriseTenant(name: string): Promise<{
  tenantId: string;
  userId: string;
  jwt: string;
  email: string;
  scimToken: string;
}> {
  // Create tenant
  const tenantRes = await fetch(`${SUPABASE_URL}/rest/v1/tenants`, {
    method: "POST",
    headers: { ...adminHeaders, Prefer: "return=representation" },
    body: JSON.stringify({ name, email: `${name}@enterprise.com`, plan: "enterprise" }),
  });
  const tenantData = await tenantRes.json();
  const tenant = Array.isArray(tenantData) ? tenantData[0] : tenantData;

  // Create user
  const email = `${name}-owner-${Date.now()}@enterprise.com`;
  const { createClient } = await import("https://esm.sh/@supabase/supabase-js@2");
  const supabase = createClient(SUPABASE_URL, SERVICE_ROLE_KEY, {
    auth: { autoRefreshToken: false, persistSession: false },
  });

  const { data: authUser } = await supabase.auth.admin.createUser({
    email, password: "enterprise-test-123!", email_confirm: true,
  });
  const userId = authUser!.user!.id;

  // Map user to tenant as owner
  await fetch(`${SUPABASE_URL}/rest/v1/rpc/set_tenant_context`, {
    method: "POST", headers: adminHeaders,
    body: JSON.stringify({ p_tenant_id: tenant.id }),
  });
  await fetch(`${SUPABASE_URL}/rest/v1/user_tenant_mappings`, {
    method: "POST", headers: adminHeaders,
    body: JSON.stringify({ user_id: userId, tenant_id: tenant.id, role: "owner", active: true }),
  });

  // Create subscription
  await fetch(`${SUPABASE_URL}/rest/v1/subscriptions`, {
    method: "POST", headers: adminHeaders,
    body: JSON.stringify({ tenant_id: tenant.id, plan: "enterprise", seat_limit: 100 }),
  });

  // Create SCIM token
  const rawToken = crypto.randomUUID();
  const encoder = new TextEncoder();
  const hashBuffer = await crypto.subtle.digest("SHA-256", encoder.encode(rawToken));
  const hashHex = Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  await fetch(`${SUPABASE_URL}/rest/v1/scim_tokens`, {
    method: "POST", headers: adminHeaders,
    body: JSON.stringify({
      tenant_id: tenant.id,
      token_hash: hashHex,
      name: "integration-test",
      created_by: userId,
    }),
  });

  // Sign in
  const { data: session } = await supabase.auth.signInWithPassword({
    email, password: "enterprise-test-123!",
  });

  return {
    tenantId: tenant.id,
    userId,
    jwt: session!.session!.access_token,
    email,
    scimToken: rawToken,
  };
}

// ── CT0-G-11: SCIM + webhook + audit cross-feature integration ──

Deno.test("CT0-G-11: SCIM provision → audit entry exists → webhook registered for events", async () => {
  const ctx = await setupEnterpriseTenant("ct0g11");

  // 1. Register a webhook endpoint for scan.completed
  const webhookRes = await fetch(`${WEBHOOKS_URL}/api/v1/webhooks`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${ctx.jwt}` },
    body: JSON.stringify({
      url: "https://httpbin.org/post",
      event_types: ["scan.completed"],
    }),
  });
  assertEquals(webhookRes.status, 201);
  const webhook = await webhookRes.json();
  assertExists(webhook.id);

  // 2. SCIM provision a user
  const scimRes = await fetch(`${SCIM_USERS_URL}/scim/v2/Users`, {
    method: "POST",
    headers: {
      "Content-Type": "application/scim+json",
      Authorization: `Bearer ${ctx.scimToken}`,
    },
    body: JSON.stringify({
      schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
      userName: `scim-${Date.now()}@enterprise.com`,
      name: { givenName: "Test", familyName: "User" },
      emails: [{ value: `scim-${Date.now()}@enterprise.com`, primary: true }],
      active: true,
    }),
  });
  // Accept 201 or 200 (some SCIM impls return 200)
  assert([200, 201].includes(scimRes.status), `SCIM provision status: ${scimRes.status}`);
  await scimRes.json();

  // 3. Verify audit log has SCIM provisioning entry
  const auditRes = await fetch(
    `${SUPABASE_URL}/rest/v1/cloud_audit_log?tenant_id=eq.${ctx.tenantId}&action=like.scim.*&order=created_at.desc&limit=5`,
    { headers: adminHeaders },
  );
  const auditEntries = await auditRes.json();
  assert(auditEntries.length >= 1, "Should have at least 1 SCIM audit entry");

  // 4. Verify webhook endpoint is still registered and visible
  const listWebhooks = await fetch(`${WEBHOOKS_URL}/api/v1/webhooks`, {
    headers: { Authorization: `Bearer ${ctx.jwt}` },
  });
  assertEquals(listWebhooks.status, 200);
  const webhookList = await listWebhooks.json();
  const found = webhookList.data.find((w: Record<string, unknown>) => w.id === webhook.id);
  assertExists(found, "Webhook should still be registered after SCIM operations");
});

// ── CT0-G-12: Team + IP allowlist cross-feature integration ──

Deno.test("CT0-G-12: Team with IP allowlist — CIDR enforcement verified via RPC", async () => {
  const ctx = await setupEnterpriseTenant("ct0g12");

  // 1. Create team
  const teamRes = await fetch(`${TEAMS_URL}/api/v1/teams`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${ctx.jwt}` },
    body: JSON.stringify({ name: "Eng-Restricted", description: "IP-restricted team" }),
  });
  assertEquals(teamRes.status, 201);
  const team = await teamRes.json();

  // 2. Create project and assign to team
  await fetch(`${SUPABASE_URL}/rest/v1/rpc/set_tenant_context`, {
    method: "POST", headers: adminHeaders,
    body: JSON.stringify({ p_tenant_id: ctx.tenantId }),
  });
  const projRes = await fetch(`${SUPABASE_URL}/rest/v1/projects`, {
    method: "POST",
    headers: { ...adminHeaders, Prefer: "return=representation" },
    body: JSON.stringify({ tenant_id: ctx.tenantId, name: "restricted-proj" }),
  });
  const projData = await projRes.json();
  const project = Array.isArray(projData) ? projData[0] : projData;

  const assignRes = await fetch(`${TEAMS_URL}/api/v1/teams/${team.id}/projects`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${ctx.jwt}` },
    body: JSON.stringify({ project_id: project.id }),
  });
  assertEquals(assignRes.status, 201);

  // 3. Add IP allowlist entry: 10.0.0.0/8
  const ipRes = await fetch(`${SETTINGS_URL}/api/v1/settings/ip-allowlist`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${ctx.jwt}` },
    body: JSON.stringify({ cidr: "10.0.0.0/8", description: "Internal only" }),
  });
  assertEquals(ipRes.status, 201);

  // 4. Verify 10.1.2.3 matches (in 10.0.0.0/8)
  const checkAllowed = await fetch(`${SUPABASE_URL}/rest/v1/rpc/check_ip_allowlist`, {
    method: "POST", headers: adminHeaders,
    body: JSON.stringify({ p_tenant_id: ctx.tenantId, p_client_ip: "10.1.2.3" }),
  });
  const allowedBody = await checkAllowed.json();
  assert(allowedBody.length > 0, "10.1.2.3 should be allowed (in 10.0.0.0/8)");

  // 5. Verify 192.168.1.1 is blocked (not in 10.0.0.0/8)
  const checkBlocked = await fetch(`${SUPABASE_URL}/rest/v1/rpc/check_ip_allowlist`, {
    method: "POST", headers: adminHeaders,
    body: JSON.stringify({ p_tenant_id: ctx.tenantId, p_client_ip: "192.168.1.1" }),
  });
  const blockedBody = await checkBlocked.json();
  assertEquals(blockedBody.length, 0, "192.168.1.1 should be blocked");

  // 6. Verify team + project assignment persists
  const teamDetails = await fetch(`${TEAMS_URL}/api/v1/teams/${team.id}`, {
    headers: { Authorization: `Bearer ${ctx.jwt}` },
  });
  assertEquals(teamDetails.status, 200);
  const details = await teamDetails.json();
  assertEquals(details.projects.length, 1);
});

// ── CT0-G-13: Full enterprise lifecycle flow ──

Deno.test("CT0-G-13: Full enterprise lifecycle — invite → team → webhook → audit → IP → transfer", async () => {
  const ctx = await setupEnterpriseTenant("ct0g13");

  // ─ 1. Invite member by email ─
  const inviteEmail = `invited-${Date.now()}@enterprise.com`;
  const inviteRes = await fetch(`${INVITATIONS_URL}/api/v1/invitations`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${ctx.jwt}` },
    body: JSON.stringify({ email: inviteEmail, role: "admin" }),
  });
  assertEquals(inviteRes.status, 201);
  const invitation = await inviteRes.json();

  // Accept invitation (get token from DB)
  const tokenRes = await fetch(
    `${SUPABASE_URL}/rest/v1/invitations?id=eq.${invitation.id}&select=token`,
    { headers: adminHeaders },
  );
  const tokenData = await tokenRes.json();
  const token = tokenData[0].token;

  const acceptRes = await fetch(
    `${INVITATIONS_URL}/api/v1/invitations/${token}/accept`,
    { method: "POST", headers: { "Content-Type": "application/json" } },
  );
  assertEquals(acceptRes.status, 200);
  const accepted = await acceptRes.json();
  assertEquals(accepted.accepted, true);
  const newUserId = accepted.user_id;

  // ─ 2. Create team and add the new member ─
  const teamRes = await fetch(`${TEAMS_URL}/api/v1/teams`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${ctx.jwt}` },
    body: JSON.stringify({ name: "Platform", description: "Platform team" }),
  });
  assertEquals(teamRes.status, 201);
  const team = await teamRes.json();

  await fetch(`${TEAMS_URL}/api/v1/teams/${team.id}/members`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${ctx.jwt}` },
    body: JSON.stringify({ user_id: newUserId }),
  });

  // ─ 3. Register webhook for scan.completed ─
  const webhookRes = await fetch(`${WEBHOOKS_URL}/api/v1/webhooks`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${ctx.jwt}` },
    body: JSON.stringify({
      url: "https://httpbin.org/post",
      event_types: ["scan.completed"],
    }),
  });
  assertEquals(webhookRes.status, 201);
  await webhookRes.json();

  // ─ 4. Create project and assign to team ─
  await fetch(`${SUPABASE_URL}/rest/v1/rpc/set_tenant_context`, {
    method: "POST", headers: adminHeaders,
    body: JSON.stringify({ p_tenant_id: ctx.tenantId }),
  });
  const projRes = await fetch(`${SUPABASE_URL}/rest/v1/projects`, {
    method: "POST",
    headers: { ...adminHeaders, Prefer: "return=representation" },
    body: JSON.stringify({ tenant_id: ctx.tenantId, name: "lifecycle-proj" }),
  });
  const projData = await projRes.json();
  const project = Array.isArray(projData) ? projData[0] : projData;

  await fetch(`${TEAMS_URL}/api/v1/teams/${team.id}/projects`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${ctx.jwt}` },
    body: JSON.stringify({ project_id: project.id }),
  });

  // ─ 5. Add IP allowlist ─
  const ipRes = await fetch(`${SETTINGS_URL}/api/v1/settings/ip-allowlist`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${ctx.jwt}` },
    body: JSON.stringify({ cidr: "172.16.0.0/12", description: "Corporate VPN" }),
  });
  assertEquals(ipRes.status, 201);

  // ─ 6. Transfer ownership to the invited admin ─
  const transferRes = await fetch(
    `${SETTINGS_URL}/api/v1/settings/transfer-ownership`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${ctx.jwt}` },
      body: JSON.stringify({ new_owner_id: newUserId }),
    },
  );
  assertEquals(transferRes.status, 200);
  const transfer = await transferRes.json();
  assertEquals(transfer.transferred, true);

  // ─ 7. Verify audit log has ALL events in chronological order ─
  const auditRes = await fetch(
    `${SUPABASE_URL}/rest/v1/cloud_audit_log?tenant_id=eq.${ctx.tenantId}&order=created_at.asc`,
    { headers: adminHeaders },
  );
  const allAudit = await auditRes.json();

  // Should have: invitation.created, invitation.accepted, team.created,
  // team.member_added, webhook.registered, team.project_assigned,
  // ip_allowlist.added, ownership.transferred_from, ownership.transferred_to
  const actions = allAudit.map((e: Record<string, unknown>) => e.action);
  assert(actions.includes("invitation.created"), "Missing invitation.created audit");
  assert(actions.includes("invitation.accepted"), "Missing invitation.accepted audit");
  assert(actions.includes("team.created"), "Missing team.created audit");
  assert(actions.includes("team.member_added"), "Missing team.member_added audit");
  assert(actions.includes("webhook.registered"), "Missing webhook.registered audit");
  assert(actions.includes("team.project_assigned"), "Missing team.project_assigned audit");
  assert(actions.includes("ip_allowlist.added"), "Missing ip_allowlist.added audit");
  assert(actions.includes("ownership.transferred_from"), "Missing ownership.transferred_from audit");
  assert(actions.includes("ownership.transferred_to"), "Missing ownership.transferred_to audit");

  // Verify chronological order — each event after the previous
  for (let i = 1; i < allAudit.length; i++) {
    assert(
      allAudit[i].created_at >= allAudit[i - 1].created_at,
      `Audit entries should be chronological: ${allAudit[i - 1].action} → ${allAudit[i].action}`,
    );
  }

  // ─ 8. Verify seat count reflects all members ─
  // We need the new owner's JWT for this, but we can check via admin
  const memberCount = await fetch(
    `${SUPABASE_URL}/rest/v1/user_tenant_mappings?tenant_id=eq.${ctx.tenantId}&active=eq.true&select=user_id`,
    { headers: adminHeaders },
  );
  const members = await memberCount.json();
  assert(members.length >= 2, "Should have at least 2 members (owner + invited)");

  // ─ 9. Verify IP allowlist enforcement ─
  const checkVpn = await fetch(`${SUPABASE_URL}/rest/v1/rpc/check_ip_allowlist`, {
    method: "POST", headers: adminHeaders,
    body: JSON.stringify({ p_tenant_id: ctx.tenantId, p_client_ip: "172.20.1.5" }),
  });
  const vpnBody = await checkVpn.json();
  assert(vpnBody.length > 0, "172.20.1.5 should match 172.16.0.0/12");

  const checkExternal = await fetch(`${SUPABASE_URL}/rest/v1/rpc/check_ip_allowlist`, {
    method: "POST", headers: adminHeaders,
    body: JSON.stringify({ p_tenant_id: ctx.tenantId, p_client_ip: "8.8.8.8" }),
  });
  const extBody = await checkExternal.json();
  assertEquals(extBody.length, 0, "8.8.8.8 should NOT match 172.16.0.0/12");

  // ─ 10. Verify ownership roles are correct ─
  const oldOwnerRole = await fetch(
    `${SUPABASE_URL}/rest/v1/user_tenant_mappings?user_id=eq.${ctx.userId}&tenant_id=eq.${ctx.tenantId}`,
    { headers: adminHeaders },
  );
  const oldOwnerData = await oldOwnerRole.json();
  assertEquals(oldOwnerData[0].role, "admin", "Old owner should be admin");

  const newOwnerRole = await fetch(
    `${SUPABASE_URL}/rest/v1/user_tenant_mappings?user_id=eq.${newUserId}&tenant_id=eq.${ctx.tenantId}`,
    { headers: adminHeaders },
  );
  const newOwnerData = await newOwnerRole.json();
  assertEquals(newOwnerData[0].role, "owner", "New owner should be owner");
});
