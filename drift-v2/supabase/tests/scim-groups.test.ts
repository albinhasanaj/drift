/**
 * SCIM /Groups endpoint tests
 * Covers: CT0-D-05 (group creates team), CT0-D-06 (membership syncs)
 *
 * Test environment: Supabase CLI local dev (supabase start).
 * Real Postgres + GoTrue + RLS — no mocks.
 */

import {
  assertEquals,
  assertExists,
  assert,
} from "https://deno.land/std@0.208.0/assert/mod.ts";

const GROUPS_URL = Deno.env.get("SUPABASE_FUNCTIONS_URL") ??
  "http://localhost:54321/functions/v1/scim-groups";
const USERS_URL = Deno.env.get("SUPABASE_FUNCTIONS_URL") ??
  "http://localhost:54321/functions/v1/scim-users";
const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "http://localhost:54321";
const SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";

const SCIM_GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group";
const SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User";
const SCIM_PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const SCIM_LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse";

/** Helper: create tenant + SCIM token */
async function setupTestTenant(name: string): Promise<{
  tenantId: string;
  scimToken: string;
}> {
  const headers = {
    "Content-Type": "application/json",
    apikey: SERVICE_ROLE_KEY,
    Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
  };

  const { data: tenant } = await fetch(`${SUPABASE_URL}/rest/v1/tenants`, {
    method: "POST",
    headers: { ...headers, Prefer: "return=representation" },
    body: JSON.stringify({
      name,
      email: `${name}@test.com`,
      plan: "enterprise",
    }),
  }).then((r) =>
    r.json().then((data) => ({ data: Array.isArray(data) ? data[0] : data }))
  );

  const rawToken = crypto.randomUUID() + "-" + crypto.randomUUID();
  const encoder = new TextEncoder();
  const hashBuffer = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode(rawToken),
  );
  const tokenHash = Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  await fetch(`${SUPABASE_URL}/rest/v1/rpc/set_tenant_context`, {
    method: "POST",
    headers,
    body: JSON.stringify({ p_tenant_id: tenant.id }),
  });

  await fetch(`${SUPABASE_URL}/rest/v1/scim_tokens`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      tenant_id: tenant.id,
      token_hash: tokenHash,
      description: `Test token for ${name}`,
      created_by: "00000000-0000-0000-0000-000000000000",
    }),
  });

  return { tenantId: tenant.id, scimToken: rawToken };
}

/** Helper: create a SCIM user and return its ID */
async function createTestUser(
  token: string,
  email: string,
): Promise<string> {
  const res = await fetch(`${USERS_URL}/scim/v2/Users`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/scim+json",
    },
    body: JSON.stringify({
      schemas: [SCIM_USER_SCHEMA],
      userName: email,
      emails: [{ value: email, type: "work", primary: true }],
      active: true,
    }),
  });
  const body = await res.json();
  return body.id;
}

/** Helper: cleanup auth user */
async function cleanupUser(userId: string): Promise<void> {
  try {
    await fetch(`${SUPABASE_URL}/auth/v1/admin/users/${userId}`, {
      method: "DELETE",
      headers: {
        apikey: SERVICE_ROLE_KEY,
        Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
      },
    });
  } catch {
    // Best-effort cleanup
  }
}

// ── CT0-D-05: POST /scim/v2/Groups → teams row created ──

Deno.test("CT0-D-05: SCIM create group creates teams row", async () => {
  const { tenantId, scimToken } = await setupTestTenant("ct0d05");
  const groupName = `Engineering-${Date.now()}`;

  const res = await fetch(`${GROUPS_URL}/scim/v2/Groups`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${scimToken}`,
      "Content-Type": "application/scim+json",
    },
    body: JSON.stringify({
      schemas: [SCIM_GROUP_SCHEMA],
      displayName: groupName,
    }),
  });

  assertEquals(res.status, 201);
  assertEquals(res.headers.get("content-type"), "application/scim+json");
  assertExists(res.headers.get("location"));

  const body = await res.json();

  // Verify SCIM Group resource shape
  assert(body.schemas?.includes(SCIM_GROUP_SCHEMA));
  assertExists(body.id);
  assertEquals(body.displayName, groupName);
  assertExists(body.meta);
  assertEquals(body.meta.resourceType, "Group");
  assertExists(body.meta.created);
  assertExists(body.meta.location);

  // Verify teams table row exists
  const teamRes = await fetch(
    `${SUPABASE_URL}/rest/v1/teams?id=eq.${body.id}&tenant_id=eq.${tenantId}`,
    {
      headers: {
        apikey: SERVICE_ROLE_KEY,
        Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
      },
    },
  );
  const teams = await teamRes.json();
  assertEquals(teams.length, 1);
  assertEquals(teams[0].name, groupName);
  assertEquals(teams[0].tenant_id, tenantId);
});

// ── CT0-D-06: Group membership syncs via PATCH ──

Deno.test("CT0-D-06: SCIM PATCH add member creates team_memberships row", async () => {
  const { tenantId, scimToken } = await setupTestTenant("ct0d06");
  const ts = Date.now();

  // Create a user first
  const userEmail = `ct0d06-user-${ts}@test.com`;
  const userId = await createTestUser(scimToken, userEmail);
  assertExists(userId);

  // Create a group
  const groupName = `DevOps-${ts}`;
  const groupRes = await fetch(`${GROUPS_URL}/scim/v2/Groups`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${scimToken}`,
      "Content-Type": "application/scim+json",
    },
    body: JSON.stringify({
      schemas: [SCIM_GROUP_SCHEMA],
      displayName: groupName,
    }),
  });
  assertEquals(groupRes.status, 201);
  const group = await groupRes.json();

  // PATCH: add member to group
  const patchRes = await fetch(
    `${GROUPS_URL}/scim/v2/Groups/${group.id}`,
    {
      method: "PATCH",
      headers: {
        Authorization: `Bearer ${scimToken}`,
        "Content-Type": "application/scim+json",
      },
      body: JSON.stringify({
        schemas: [SCIM_PATCH_SCHEMA],
        Operations: [
          {
            op: "add",
            path: "members",
            value: [{ value: userId }],
          },
        ],
      }),
    },
  );
  assertEquals(patchRes.status, 200);

  const updatedGroup = await patchRes.json();
  assert(
    updatedGroup.members?.some(
      (m: { value: string }) => m.value === userId,
    ),
    "Updated group should contain the added member",
  );

  // Verify team_memberships row in database
  const membershipRes = await fetch(
    `${SUPABASE_URL}/rest/v1/team_memberships?team_id=eq.${group.id}&user_id=eq.${userId}`,
    {
      headers: {
        apikey: SERVICE_ROLE_KEY,
        Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
      },
    },
  );
  const memberships = await membershipRes.json();
  assertEquals(memberships.length, 1, "team_memberships row should exist");
  assertEquals(memberships[0].team_id, group.id);
  assertEquals(memberships[0].user_id, userId);

  // Verify GET group includes member
  const getRes = await fetch(
    `${GROUPS_URL}/scim/v2/Groups/${group.id}`,
    {
      headers: { Authorization: `Bearer ${scimToken}` },
    },
  );
  assertEquals(getRes.status, 200);
  const getBody = await getRes.json();
  assert(
    getBody.members?.some((m: { value: string }) => m.value === userId),
    "GET group should include added member",
  );

  await cleanupUser(userId);
});

// ── Additional: Group list returns correct data ──

Deno.test("SCIM list groups returns correct count and shape", async () => {
  const { scimToken } = await setupTestTenant("ct0d-grplist");
  const ts = Date.now();

  // Create 3 groups
  for (let i = 1; i <= 3; i++) {
    await fetch(`${GROUPS_URL}/scim/v2/Groups`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${scimToken}`,
        "Content-Type": "application/scim+json",
      },
      body: JSON.stringify({
        schemas: [SCIM_GROUP_SCHEMA],
        displayName: `Team-${i}-${ts}`,
      }),
    });
  }

  const listRes = await fetch(`${GROUPS_URL}/scim/v2/Groups`, {
    headers: { Authorization: `Bearer ${scimToken}` },
  });
  assertEquals(listRes.status, 200);

  const body = await listRes.json();
  assert(body.schemas?.includes(SCIM_LIST_SCHEMA));
  assertEquals(body.totalResults, 3);
  assertEquals(body.Resources.length, 3);
});
