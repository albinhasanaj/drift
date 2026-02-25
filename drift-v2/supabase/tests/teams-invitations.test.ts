/**
 * Phase F: Team Management + Invitations + Ownership tests
 * Covers: CT0-F-05 (team CRUD round-trip), CT0-F-06 (team-scoped access),
 *         CT0-F-07 (invitation flow), CT0-F-08 (invitation expiry),
 *         CT0-F-09 (seat limit), CT0-F-14 (ownership transfer)
 *
 * Test environment: Supabase CLI local dev (supabase start).
 */

import {
  assertEquals,
  assertExists,
  assert,
  assertNotEquals,
} from "https://deno.land/std@0.208.0/assert/mod.ts";

const TEAMS_URL = Deno.env.get("SUPABASE_FUNCTIONS_URL")
  ? `${Deno.env.get("SUPABASE_FUNCTIONS_URL")}/teams`
  : "http://localhost:54321/functions/v1/teams";
const INVITATIONS_URL = Deno.env.get("SUPABASE_FUNCTIONS_URL")
  ? `${Deno.env.get("SUPABASE_FUNCTIONS_URL")}/invitations`
  : "http://localhost:54321/functions/v1/invitations";
const MEMBERS_URL = Deno.env.get("SUPABASE_FUNCTIONS_URL")
  ? `${Deno.env.get("SUPABASE_FUNCTIONS_URL")}/members`
  : "http://localhost:54321/functions/v1/members";
const SETTINGS_URL = Deno.env.get("SUPABASE_FUNCTIONS_URL")
  ? `${Deno.env.get("SUPABASE_FUNCTIONS_URL")}/settings`
  : "http://localhost:54321/functions/v1/settings";
const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "http://localhost:54321";
const SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";

async function setupTestContext(name: string, role = "owner"): Promise<{
  tenantId: string;
  userId: string;
  jwt: string;
  email: string;
}> {
  const headers = {
    "Content-Type": "application/json",
    apikey: SERVICE_ROLE_KEY,
    Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
  };

  const tenantRes = await fetch(`${SUPABASE_URL}/rest/v1/tenants`, {
    method: "POST",
    headers: { ...headers, Prefer: "return=representation" },
    body: JSON.stringify({ name, email: `${name}@test.com`, plan: "enterprise" }),
  });
  const tenantData = await tenantRes.json();
  const tenant = Array.isArray(tenantData) ? tenantData[0] : tenantData;

  const email = `${name}-${Date.now()}@test.com`;
  const { createClient } = await import("https://esm.sh/@supabase/supabase-js@2");
  const supabase = createClient(SUPABASE_URL, SERVICE_ROLE_KEY, {
    auth: { autoRefreshToken: false, persistSession: false },
  });

  const { data: authUser } = await supabase.auth.admin.createUser({
    email, password: "test-password-123!", email_confirm: true,
  });
  const userId = authUser!.user!.id;

  await fetch(`${SUPABASE_URL}/rest/v1/rpc/set_tenant_context`, {
    method: "POST", headers,
    body: JSON.stringify({ p_tenant_id: tenant.id }),
  });

  await fetch(`${SUPABASE_URL}/rest/v1/user_tenant_mappings`, {
    method: "POST", headers,
    body: JSON.stringify({ user_id: userId, tenant_id: tenant.id, role, active: true }),
  });

  const { data: session } = await supabase.auth.signInWithPassword({
    email, password: "test-password-123!",
  });

  return { tenantId: tenant.id, userId, jwt: session!.session!.access_token, email };
}

/** Add another user to an existing tenant */
async function addUserToTenant(tenantId: string, role: string): Promise<{
  userId: string;
  jwt: string;
  email: string;
}> {
  const headers = {
    "Content-Type": "application/json",
    apikey: SERVICE_ROLE_KEY,
    Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
  };

  const email = `extra-${Date.now()}-${Math.random().toString(36).slice(2)}@test.com`;
  const { createClient } = await import("https://esm.sh/@supabase/supabase-js@2");
  const supabase = createClient(SUPABASE_URL, SERVICE_ROLE_KEY, {
    auth: { autoRefreshToken: false, persistSession: false },
  });

  const { data: authUser } = await supabase.auth.admin.createUser({
    email, password: "test-password-123!", email_confirm: true,
  });
  const userId = authUser!.user!.id;

  await fetch(`${SUPABASE_URL}/rest/v1/rpc/set_tenant_context`, {
    method: "POST", headers,
    body: JSON.stringify({ p_tenant_id: tenantId }),
  });

  await fetch(`${SUPABASE_URL}/rest/v1/user_tenant_mappings`, {
    method: "POST", headers,
    body: JSON.stringify({ user_id: userId, tenant_id: tenantId, role, active: true }),
  });

  const { data: session } = await supabase.auth.signInWithPassword({
    email, password: "test-password-123!",
  });

  return { userId, jwt: session!.session!.access_token, email };
}

/** Create a project in a tenant */
async function createProject(tenantId: string): Promise<string> {
  const headers = {
    "Content-Type": "application/json",
    apikey: SERVICE_ROLE_KEY,
    Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
  };

  await fetch(`${SUPABASE_URL}/rest/v1/rpc/set_tenant_context`, {
    method: "POST", headers,
    body: JSON.stringify({ p_tenant_id: tenantId }),
  });

  const res = await fetch(`${SUPABASE_URL}/rest/v1/projects`, {
    method: "POST",
    headers: { ...headers, Prefer: "return=representation" },
    body: JSON.stringify({ tenant_id: tenantId, name: `proj-${Date.now()}` }),
  });
  const data = await res.json();
  const project = Array.isArray(data) ? data[0] : data;
  return project.id;
}

// ── CT0-F-05: Team CRUD round-trip ──

Deno.test("CT0-F-05: Create team → add members → assign projects → verify", async () => {
  const ctx = await setupTestContext("ct0f05");
  const user2 = await addUserToTenant(ctx.tenantId, "member");
  const user3 = await addUserToTenant(ctx.tenantId, "member");
  const proj1 = await createProject(ctx.tenantId);
  const proj2 = await createProject(ctx.tenantId);

  // Create team
  const createRes = await fetch(`${TEAMS_URL}/api/v1/teams`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${ctx.jwt}` },
    body: JSON.stringify({ name: "Engineering", description: "Eng team" }),
  });
  assertEquals(createRes.status, 201);
  const team = await createRes.json();
  assertExists(team.id);
  assertEquals(team.name, "Engineering");

  // Add 3 members (owner + 2 extra)
  for (const uid of [ctx.userId, user2.userId, user3.userId]) {
    const addRes = await fetch(`${TEAMS_URL}/api/v1/teams/${team.id}/members`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${ctx.jwt}` },
      body: JSON.stringify({ user_id: uid }),
    });
    assertEquals(addRes.status, 201);
    await addRes.json();
  }

  // Assign 2 projects
  for (const pid of [proj1, proj2]) {
    const assignRes = await fetch(`${TEAMS_URL}/api/v1/teams/${team.id}/projects`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${ctx.jwt}` },
      body: JSON.stringify({ project_id: pid }),
    });
    assertEquals(assignRes.status, 201);
    await assignRes.json();
  }

  // Get team details
  const getRes = await fetch(`${TEAMS_URL}/api/v1/teams/${team.id}`, {
    headers: { Authorization: `Bearer ${ctx.jwt}` },
  });
  assertEquals(getRes.status, 200);
  const details = await getRes.json();
  assertEquals(details.members.length, 3, "Should have 3 members");
  assertEquals(details.projects.length, 2, "Should have 2 projects");

  // List teams
  const listRes = await fetch(`${TEAMS_URL}/api/v1/teams`, {
    headers: { Authorization: `Bearer ${ctx.jwt}` },
  });
  assertEquals(listRes.status, 200);
  const listBody = await listRes.json();
  const found = listBody.data.find((t: Record<string, unknown>) => t.id === team.id);
  assertExists(found);
});

// ── CT0-F-06: Team-scoped access — Non-admin cannot create team ──

Deno.test("CT0-F-06: Member role cannot create/delete teams → 403", async () => {
  const ctx = await setupTestContext("ct0f06");
  const member = await addUserToTenant(ctx.tenantId, "member");

  // Member tries to create team → 403
  const createRes = await fetch(`${TEAMS_URL}/api/v1/teams`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${member.jwt}` },
    body: JSON.stringify({ name: "Unauthorized Team" }),
  });
  assertEquals(createRes.status, 403);
  await createRes.json();
});

// ── CT0-F-07: Invitation flow end-to-end ──

Deno.test("CT0-F-07: Invite by email → accept with token → user in tenant", async () => {
  const ctx = await setupTestContext("ct0f07");

  // Create subscription for seat limit
  const headers = {
    "Content-Type": "application/json",
    apikey: SERVICE_ROLE_KEY,
    Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
  };
  await fetch(`${SUPABASE_URL}/rest/v1/rpc/set_tenant_context`, {
    method: "POST", headers,
    body: JSON.stringify({ p_tenant_id: ctx.tenantId }),
  });
  await fetch(`${SUPABASE_URL}/rest/v1/subscriptions`, {
    method: "POST", headers,
    body: JSON.stringify({ tenant_id: ctx.tenantId, plan: "enterprise", seat_limit: 50 }),
  });

  const inviteEmail = `invitee-${Date.now()}@test.com`;

  // Create invitation
  const inviteRes = await fetch(`${INVITATIONS_URL}/api/v1/invitations`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${ctx.jwt}` },
    body: JSON.stringify({ email: inviteEmail, role: "member" }),
  });
  assertEquals(inviteRes.status, 201);
  const invitation = await inviteRes.json();
  assertExists(invitation.id);
  assertEquals(invitation.email, inviteEmail);
  assertEquals(invitation.role, "member");

  // Get the token from DB (not exposed via API — only in the email link)
  const tokenRes = await fetch(
    `${SUPABASE_URL}/rest/v1/invitations?id=eq.${invitation.id}&select=token`,
    { headers },
  );
  const tokenData = await tokenRes.json();
  const token = tokenData[0].token;
  assertExists(token);

  // Accept invitation
  const acceptRes = await fetch(
    `${INVITATIONS_URL}/api/v1/invitations/${token}/accept`,
    { method: "POST", headers: { "Content-Type": "application/json" } },
  );
  assertEquals(acceptRes.status, 200);
  const acceptBody = await acceptRes.json();
  assertEquals(acceptBody.accepted, true);
  assertEquals(acceptBody.role, "member");
  assertExists(acceptBody.user_id);

  // Verify user is in tenant
  const mappingRes = await fetch(
    `${SUPABASE_URL}/rest/v1/user_tenant_mappings?tenant_id=eq.${ctx.tenantId}&user_id=eq.${acceptBody.user_id}`,
    { headers },
  );
  const mappings = await mappingRes.json();
  assertEquals(mappings.length, 1, "User should be in tenant");
  assertEquals(mappings[0].role, "member");
});

// ── CT0-F-08: Invitation expiry ──

Deno.test("CT0-F-08: Expired invitation → 410 Gone", async () => {
  const ctx = await setupTestContext("ct0f08");
  const headers = {
    "Content-Type": "application/json",
    apikey: SERVICE_ROLE_KEY,
    Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
  };

  await fetch(`${SUPABASE_URL}/rest/v1/rpc/set_tenant_context`, {
    method: "POST", headers,
    body: JSON.stringify({ p_tenant_id: ctx.tenantId }),
  });

  // Insert an already-expired invitation directly
  const token = crypto.randomUUID();
  await fetch(`${SUPABASE_URL}/rest/v1/invitations`, {
    method: "POST", headers,
    body: JSON.stringify({
      tenant_id: ctx.tenantId,
      email: "expired@test.com",
      role: "member",
      invited_by: ctx.userId,
      token,
      expires_at: new Date(Date.now() - 60 * 60 * 1000).toISOString(), // 1h ago
    }),
  });

  // Try to accept
  const acceptRes = await fetch(
    `${INVITATIONS_URL}/api/v1/invitations/${token}/accept`,
    { method: "POST", headers: { "Content-Type": "application/json" } },
  );
  assertEquals(acceptRes.status, 410, "Expired invitation should return 410");
  await acceptRes.json();
});

// ── CT0-F-09: Seat limit enforcement ──

Deno.test("CT0-F-09: Seat limit reached → 402 on next invite", async () => {
  const ctx = await setupTestContext("ct0f09");
  const headers = {
    "Content-Type": "application/json",
    apikey: SERVICE_ROLE_KEY,
    Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
  };

  await fetch(`${SUPABASE_URL}/rest/v1/rpc/set_tenant_context`, {
    method: "POST", headers,
    body: JSON.stringify({ p_tenant_id: ctx.tenantId }),
  });

  // Set seat limit to 2 (owner counts as 1)
  await fetch(`${SUPABASE_URL}/rest/v1/subscriptions`, {
    method: "POST", headers,
    body: JSON.stringify({ tenant_id: ctx.tenantId, plan: "free", seat_limit: 2 }),
  });

  // Add one more member to fill it (owner=1, +1=2)
  await addUserToTenant(ctx.tenantId, "member");

  // Now at 2/2 seats. Next invite should fail.
  const inviteRes = await fetch(`${INVITATIONS_URL}/api/v1/invitations`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${ctx.jwt}` },
    body: JSON.stringify({ email: "over-limit@test.com", role: "member" }),
  });
  assertEquals(inviteRes.status, 402, "Should return 402 when seat limit reached");
  const body = await inviteRes.json();
  assert(body.error.includes("Seat limit"), "Error should mention seat limit");
});

// ── CT0-F-14: Ownership transfer ──

Deno.test("CT0-F-14: Transfer ownership → new=owner, old=admin, audit entries", async () => {
  const ctx = await setupTestContext("ct0f14");
  const newOwner = await addUserToTenant(ctx.tenantId, "admin");

  // Transfer
  const transferRes = await fetch(
    `${SETTINGS_URL}/api/v1/settings/transfer-ownership`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${ctx.jwt}` },
      body: JSON.stringify({ new_owner_id: newOwner.userId }),
    },
  );
  assertEquals(transferRes.status, 200);
  const transferBody = await transferRes.json();
  assertEquals(transferBody.transferred, true);
  assertEquals(transferBody.old_owner.new_role, "admin");
  assertEquals(transferBody.new_owner.new_role, "owner");

  // Verify roles in DB
  const headers = {
    "Content-Type": "application/json",
    apikey: SERVICE_ROLE_KEY,
    Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
  };

  await fetch(`${SUPABASE_URL}/rest/v1/rpc/set_tenant_context`, {
    method: "POST", headers,
    body: JSON.stringify({ p_tenant_id: ctx.tenantId }),
  });

  const oldOwnerRes = await fetch(
    `${SUPABASE_URL}/rest/v1/user_tenant_mappings?user_id=eq.${ctx.userId}&tenant_id=eq.${ctx.tenantId}`,
    { headers },
  );
  const oldOwner = await oldOwnerRes.json();
  assertEquals(oldOwner[0].role, "admin", "Old owner should now be admin");

  const newOwnerRes = await fetch(
    `${SUPABASE_URL}/rest/v1/user_tenant_mappings?user_id=eq.${newOwner.userId}&tenant_id=eq.${ctx.tenantId}`,
    { headers },
  );
  const newOwnerData = await newOwnerRes.json();
  assertEquals(newOwnerData[0].role, "owner", "New owner should now be owner");

  // Verify audit entries
  const auditRes = await fetch(
    `${SUPABASE_URL}/rest/v1/cloud_audit_log?tenant_id=eq.${ctx.tenantId}&action=in.(ownership.transferred_from,ownership.transferred_to)`,
    { headers },
  );
  const auditEntries = await auditRes.json();
  assert(auditEntries.length >= 2, "Should have 2 ownership audit entries");

  const actions = auditEntries.map((e: Record<string, unknown>) => e.action);
  assert(actions.includes("ownership.transferred_from"));
  assert(actions.includes("ownership.transferred_to"));
});

// ── Seat count endpoint ──

Deno.test("Members count endpoint returns correct counts", async () => {
  const ctx = await setupTestContext("ct0f-members-count");
  const headers = {
    "Content-Type": "application/json",
    apikey: SERVICE_ROLE_KEY,
    Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
  };

  await fetch(`${SUPABASE_URL}/rest/v1/rpc/set_tenant_context`, {
    method: "POST", headers,
    body: JSON.stringify({ p_tenant_id: ctx.tenantId }),
  });

  await fetch(`${SUPABASE_URL}/rest/v1/subscriptions`, {
    method: "POST", headers,
    body: JSON.stringify({ tenant_id: ctx.tenantId, plan: "team", seat_limit: 10 }),
  });

  const res = await fetch(`${MEMBERS_URL}/api/v1/members/count`, {
    headers: { Authorization: `Bearer ${ctx.jwt}` },
  });
  assertEquals(res.status, 200);
  const body = await res.json();
  assertEquals(body.active, 1, "Should have 1 active member (owner)");
  assertEquals(body.seat_limit, 10);
  assertEquals(body.remaining, 9);
});
