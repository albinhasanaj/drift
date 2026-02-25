/**
 * SCIM /Users endpoint tests
 * Covers: CT0-D-01 (provisioning), CT0-D-02 (deprovisioning),
 *         CT0-D-03 (filter), CT0-D-04 (pagination), CT0-D-08 (tenant isolation)
 *
 * Test environment: Supabase CLI local dev (supabase start).
 * Real Postgres + GoTrue + RLS — no mocks.
 */

import {
  assertEquals,
  assertExists,
  assert,
} from "https://deno.land/std@0.208.0/assert/mod.ts";

const BASE_URL = Deno.env.get("SUPABASE_FUNCTIONS_URL") ??
  "http://localhost:54321/functions/v1/scim-users";
const ADMIN_URL = Deno.env.get("SUPABASE_FUNCTIONS_URL") ??
  "http://localhost:54321/functions/v1/scim-admin";
const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "http://localhost:54321";
const SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";

const SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User";
const SCIM_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error";
const SCIM_LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const SCIM_PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

/** Helper: create a tenant and SCIM token for testing */
async function setupTestTenant(name: string): Promise<{
  tenantId: string;
  scimToken: string;
}> {
  const headers = {
    "Content-Type": "application/json",
    apikey: SERVICE_ROLE_KEY,
    Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
  };

  // Create tenant
  const { data: tenant } = await fetch(
    `${SUPABASE_URL}/rest/v1/tenants`,
    {
      method: "POST",
      headers: { ...headers, Prefer: "return=representation" },
      body: JSON.stringify({
        name,
        email: `${name}@test.com`,
        plan: "enterprise",
      }),
    },
  ).then((r) => r.json().then((data) => ({ data: Array.isArray(data) ? data[0] : data })));

  // Create SCIM token directly (bypass JWT auth for test setup)
  const rawToken = crypto.randomUUID() + "-" + crypto.randomUUID();
  const encoder = new TextEncoder();
  const hashBuffer = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode(rawToken),
  );
  const tokenHash = Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  // Set tenant context before inserting
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

/** Helper: SCIM POST /Users */
async function createScimUser(
  token: string,
  userData: {
    userName: string;
    givenName?: string;
    familyName?: string;
    externalId?: string;
  },
): Promise<Response> {
  return fetch(`${BASE_URL}/scim/v2/Users`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/scim+json",
    },
    body: JSON.stringify({
      schemas: [SCIM_USER_SCHEMA],
      userName: userData.userName,
      name: {
        givenName: userData.givenName ?? "Test",
        familyName: userData.familyName ?? "User",
      },
      emails: [{ value: userData.userName, type: "work", primary: true }],
      active: true,
      ...(userData.externalId && { externalId: userData.externalId }),
    }),
  });
}

/** Helper: validate SCIM error response shape */
async function assertScimError(
  res: Response,
  expectedStatus: number,
  expectedScimType?: string,
): Promise<void> {
  assertEquals(res.status, expectedStatus);
  assertEquals(res.headers.get("content-type"), "application/scim+json");
  const body = await res.json();
  assert(body.schemas?.includes(SCIM_ERROR_SCHEMA), "Error must have SCIM error schema");
  assertEquals(body.status, String(expectedStatus));
  assertExists(body.detail);
  if (expectedScimType) {
    assertEquals(body.scimType, expectedScimType);
  }
}

/** Helper: cleanup — delete auth user after test */
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

// ── CT0-D-01: POST /scim/v2/Users → user in Auth + user_tenant_mappings row ──

Deno.test("CT0-D-01: SCIM create user provisions in Auth + mapping", async () => {
  const { tenantId, scimToken } = await setupTestTenant("ct0d01");

  const res = await createScimUser(scimToken, {
    userName: `ct0d01-${Date.now()}@test.com`,
  });

  assertEquals(res.status, 201);
  assertEquals(res.headers.get("content-type"), "application/scim+json");
  assertExists(res.headers.get("location"));

  const body = await res.json();

  // Verify SCIM User resource shape
  assert(body.schemas?.includes(SCIM_USER_SCHEMA));
  assertExists(body.id);
  assertExists(body.userName);
  assertEquals(body.active, true);
  assertExists(body.meta);
  assertEquals(body.meta.resourceType, "User");
  assertExists(body.meta.created);
  assertExists(body.meta.lastModified);
  assertExists(body.meta.location);

  // Verify user exists in Auth
  const authRes = await fetch(
    `${SUPABASE_URL}/auth/v1/admin/users/${body.id}`,
    {
      headers: {
        apikey: SERVICE_ROLE_KEY,
        Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
      },
    },
  );
  assertEquals(authRes.status, 200);

  // Verify user_tenant_mappings row
  const mappingRes = await fetch(
    `${SUPABASE_URL}/rest/v1/user_tenant_mappings?user_id=eq.${body.id}&tenant_id=eq.${tenantId}`,
    {
      headers: {
        apikey: SERVICE_ROLE_KEY,
        Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
      },
    },
  );
  const mappings = await mappingRes.json();
  assertEquals(mappings.length, 1);
  assertEquals(mappings[0].role, "member");
  assertEquals(mappings[0].active, true);

  await cleanupUser(body.id);
});

// ── CT0-D-02: Deprovisioning revokes ALL access ──

Deno.test("CT0-D-02: SCIM PATCH active:false deprovisions completely", async () => {
  const { tenantId, scimToken } = await setupTestTenant("ct0d02");
  const email = `ct0d02-${Date.now()}@test.com`;

  // Step 1: Create user
  const createRes = await createScimUser(scimToken, { userName: email });
  assertEquals(createRes.status, 201);
  const user = await createRes.json();
  const userId = user.id;

  // Step 2: Create an API key for this user
  await fetch(`${SUPABASE_URL}/rest/v1/rpc/set_tenant_context`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      apikey: SERVICE_ROLE_KEY,
      Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
    },
    body: JSON.stringify({ p_tenant_id: tenantId }),
  });

  await fetch(`${SUPABASE_URL}/rest/v1/api_keys`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      apikey: SERVICE_ROLE_KEY,
      Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
    },
    body: JSON.stringify({
      tenant_id: tenantId,
      key_hash: "test-key-hash-" + Date.now(),
      name: "test-key",
      created_by: userId,
    }),
  });

  // Step 3: PATCH active:false (deprovisioning)
  const patchRes = await fetch(`${BASE_URL}/scim/v2/Users/${userId}`, {
    method: "PATCH",
    headers: {
      Authorization: `Bearer ${scimToken}`,
      "Content-Type": "application/scim+json",
    },
    body: JSON.stringify({
      schemas: [SCIM_PATCH_SCHEMA],
      Operations: [{ op: "replace", path: "active", value: false }],
    }),
  });
  assertEquals(patchRes.status, 200);
  const patchedUser = await patchRes.json();
  assertEquals(patchedUser.active, false);

  // Verify Step 2: Auth user is banned
  const authRes = await fetch(
    `${SUPABASE_URL}/auth/v1/admin/users/${userId}`,
    {
      headers: {
        apikey: SERVICE_ROLE_KEY,
        Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
      },
    },
  );
  const authUser = await authRes.json();
  assertExists(authUser.banned_until, "User should be banned");

  // Verify Step 3: API keys revoked
  const keysRes = await fetch(
    `${SUPABASE_URL}/rest/v1/api_keys?created_by=eq.${userId}&tenant_id=eq.${tenantId}&revoked_at=is.null`,
    {
      headers: {
        apikey: SERVICE_ROLE_KEY,
        Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
      },
    },
  );
  const activeKeys = await keysRes.json();
  assertEquals(activeKeys.length, 0, "All API keys should be revoked");

  // Verify Step 5: Mapping deactivated
  const mappingRes = await fetch(
    `${SUPABASE_URL}/rest/v1/user_tenant_mappings?user_id=eq.${userId}&tenant_id=eq.${tenantId}`,
    {
      headers: {
        apikey: SERVICE_ROLE_KEY,
        Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
      },
    },
  );
  const mappings = await mappingRes.json();
  assertEquals(mappings[0].active, false, "Mapping should be inactive");
  assertExists(
    mappings[0].deprovisioned_at,
    "deprovisioned_at should be set",
  );

  // Verify Step 6: Audit log entry
  const auditRes = await fetch(
    `${SUPABASE_URL}/rest/v1/cloud_audit_log?resource_id=eq.${userId}&action=eq.user.deprovisioned`,
    {
      headers: {
        apikey: SERVICE_ROLE_KEY,
        Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
      },
    },
  );
  const auditLogs = await auditRes.json();
  assert(auditLogs.length >= 1, "Audit log entry for deprovisioning must exist");
  assertEquals(auditLogs[0].action, "user.deprovisioned");

  await cleanupUser(userId);
});

// ── CT0-D-03: GET /Users with filter ──

Deno.test("CT0-D-03: SCIM filter userName eq returns correct user", async () => {
  const { scimToken } = await setupTestTenant("ct0d03");
  const ts = Date.now();
  const userIds: string[] = [];

  // Create 5 users
  for (let i = 1; i <= 5; i++) {
    const res = await createScimUser(scimToken, {
      userName: `ct0d03-user${i}-${ts}@test.com`,
    });
    assertEquals(res.status, 201);
    const body = await res.json();
    userIds.push(body.id);
  }

  // Filter for user3
  const targetEmail = `ct0d03-user3-${ts}@test.com`;
  const filterRes = await fetch(
    `${BASE_URL}/scim/v2/Users?filter=${encodeURIComponent(`userName eq "${targetEmail}"`)}`,
    {
      headers: { Authorization: `Bearer ${scimToken}` },
    },
  );
  assertEquals(filterRes.status, 200);

  const body = await filterRes.json();
  assert(body.schemas?.includes(SCIM_LIST_SCHEMA));
  assertEquals(body.Resources.length, 1);
  assertEquals(body.Resources[0].userName, targetEmail);

  // Cleanup
  for (const id of userIds) await cleanupUser(id);
});

// ── CT0-D-04: Pagination ──

Deno.test("CT0-D-04: SCIM pagination returns correct page", async () => {
  const { scimToken } = await setupTestTenant("ct0d04");
  const ts = Date.now();
  const userIds: string[] = [];

  // Create 25 users
  for (let i = 1; i <= 25; i++) {
    const res = await createScimUser(scimToken, {
      userName: `ct0d04-user${String(i).padStart(2, "0")}-${ts}@test.com`,
    });
    if (res.status === 201) {
      const body = await res.json();
      userIds.push(body.id);
    }
  }

  // Get first page: startIndex=1, count=10
  const pageRes = await fetch(
    `${BASE_URL}/scim/v2/Users?startIndex=1&count=10`,
    {
      headers: { Authorization: `Bearer ${scimToken}` },
    },
  );
  assertEquals(pageRes.status, 200);

  const body = await pageRes.json();
  assert(body.schemas?.includes(SCIM_LIST_SCHEMA));
  assertEquals(body.totalResults, 25);
  assertEquals(body.startIndex, 1);
  assert(body.Resources.length <= 10);
  assert(body.itemsPerPage <= 10);

  // Cleanup
  for (const id of userIds) await cleanupUser(id);
});

// ── CT0-D-08: Tenant isolation ──

Deno.test("CT0-D-08: Cross-tenant SCIM access returns 404", async () => {
  // Setup two tenants
  const tenantA = await setupTestTenant("ct0d08-a");
  const tenantB = await setupTestTenant("ct0d08-b");

  // Create user in tenant A
  const email = `ct0d08-${Date.now()}@test.com`;
  const createRes = await createScimUser(tenantA.scimToken, {
    userName: email,
  });
  assertEquals(createRes.status, 201);
  const userA = await createRes.json();

  // Attempt to GET user from tenant B's SCIM token → must be 404 (not 403)
  const getRes = await fetch(`${BASE_URL}/scim/v2/Users/${userA.id}`, {
    headers: { Authorization: `Bearer ${tenantB.scimToken}` },
  });
  assertEquals(
    getRes.status,
    404,
    "Cross-tenant GET must return 404, not 403",
  );

  // Attempt to PATCH user from tenant B's token → must be 404
  const patchRes = await fetch(`${BASE_URL}/scim/v2/Users/${userA.id}`, {
    method: "PATCH",
    headers: {
      Authorization: `Bearer ${tenantB.scimToken}`,
      "Content-Type": "application/scim+json",
    },
    body: JSON.stringify({
      schemas: [SCIM_PATCH_SCHEMA],
      Operations: [{ op: "replace", path: "active", value: false }],
    }),
  });
  assertEquals(
    patchRes.status,
    404,
    "Cross-tenant PATCH must return 404, not 403",
  );

  // Attempt to DELETE user from tenant B's token → must be 404
  const deleteRes = await fetch(`${BASE_URL}/scim/v2/Users/${userA.id}`, {
    method: "DELETE",
    headers: { Authorization: `Bearer ${tenantB.scimToken}` },
  });
  assertEquals(
    deleteRes.status,
    404,
    "Cross-tenant DELETE must return 404, not 403",
  );

  await cleanupUser(userA.id);
});

// ── Additional: Uniqueness (409 on duplicate userName) ──

Deno.test("SCIM create duplicate userName returns 409 uniqueness", async () => {
  const { scimToken } = await setupTestTenant("ct0d-dup");
  const email = `ct0d-dup-${Date.now()}@test.com`;

  const res1 = await createScimUser(scimToken, { userName: email });
  assertEquals(res1.status, 201);
  const user1 = await res1.json();

  // Second create with same email → should be 409
  const res2 = await createScimUser(scimToken, { userName: email });
  assertEquals(res2.status, 409);
  const errBody = await res2.json();
  assert(errBody.schemas?.includes(SCIM_ERROR_SCHEMA));
  assertEquals(errBody.scimType, "uniqueness");

  await cleanupUser(user1.id);
});
