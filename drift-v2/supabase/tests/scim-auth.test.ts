/**
 * SCIM Bearer Token Authentication tests
 * Covers: CT0-D-07 (auth enforcement: no token, invalid, revoked, valid)
 *
 * Test environment: Supabase CLI local dev (supabase start).
 * Real Postgres + GoTrue + RLS — no mocks.
 */

import {
  assertEquals,
  assertExists,
  assert,
} from "https://deno.land/std@0.208.0/assert/mod.ts";

const USERS_URL = Deno.env.get("SUPABASE_FUNCTIONS_URL") ??
  "http://localhost:54321/functions/v1/scim-users";
const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "http://localhost:54321";
const SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";

const SCIM_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error";

/** Helper: create tenant + SCIM token */
async function setupTestTenant(name: string): Promise<{
  tenantId: string;
  scimToken: string;
  tokenId: string;
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

  const tokenRes = await fetch(`${SUPABASE_URL}/rest/v1/scim_tokens`, {
    method: "POST",
    headers: { ...headers, Prefer: "return=representation" },
    body: JSON.stringify({
      tenant_id: tenant.id,
      token_hash: tokenHash,
      description: `Test token for ${name}`,
      created_by: "00000000-0000-0000-0000-000000000000",
    }),
  });
  const tokenData = await tokenRes.json();
  const tokenId = Array.isArray(tokenData) ? tokenData[0].id : tokenData.id;

  return { tenantId: tenant.id, scimToken: rawToken, tokenId };
}

/** Helper: assert SCIM 401 error response */
async function assert401(res: Response): Promise<void> {
  assertEquals(res.status, 401);
  assertEquals(res.headers.get("content-type"), "application/scim+json");
  const body = await res.json();
  assert(
    body.schemas?.includes(SCIM_ERROR_SCHEMA),
    "401 must return SCIM error schema",
  );
  assertEquals(body.status, "401");
  assertExists(body.detail);
}

// ── CT0-D-07: Bearer token auth enforcement ──

Deno.test("CT0-D-07a: No token → 401", async () => {
  const res = await fetch(`${USERS_URL}/scim/v2/Users`, {
    method: "GET",
    // No Authorization header
  });
  await assert401(res);
});

Deno.test("CT0-D-07b: Invalid token → 401", async () => {
  const res = await fetch(`${USERS_URL}/scim/v2/Users`, {
    method: "GET",
    headers: {
      Authorization: "Bearer this-is-not-a-valid-token",
    },
  });
  await assert401(res);
});

Deno.test("CT0-D-07c: Revoked token → 401", async () => {
  const { scimToken, tokenId } = await setupTestTenant("ct0d07c");

  // Verify valid token works first
  const validRes = await fetch(`${USERS_URL}/scim/v2/Users`, {
    method: "GET",
    headers: { Authorization: `Bearer ${scimToken}` },
  });
  assertEquals(validRes.status, 200, "Valid token should return 200");
  await validRes.json(); // consume body

  // Revoke the token
  await fetch(
    `${SUPABASE_URL}/rest/v1/scim_tokens?id=eq.${tokenId}`,
    {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
        apikey: SERVICE_ROLE_KEY,
        Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
      },
      body: JSON.stringify({ revoked_at: new Date().toISOString() }),
    },
  );

  // Now the revoked token should fail
  const revokedRes = await fetch(`${USERS_URL}/scim/v2/Users`, {
    method: "GET",
    headers: { Authorization: `Bearer ${scimToken}` },
  });
  await assert401(revokedRes);
});

Deno.test("CT0-D-07d: Valid token → 200", async () => {
  const { scimToken } = await setupTestTenant("ct0d07d");

  const res = await fetch(`${USERS_URL}/scim/v2/Users`, {
    method: "GET",
    headers: { Authorization: `Bearer ${scimToken}` },
  });
  assertEquals(res.status, 200);

  const body = await res.json();
  assertExists(body.schemas);
  assertExists(body.totalResults);
  assertExists(body.Resources);
});

// ── Additional: Empty Bearer header → 401 ──

Deno.test("Empty Bearer value → 401", async () => {
  const res = await fetch(`${USERS_URL}/scim/v2/Users`, {
    method: "GET",
    headers: { Authorization: "Bearer " },
  });
  await assert401(res);
});

// ── Additional: Wrong auth scheme → 401 ──

Deno.test("Basic auth scheme → 401 (must be Bearer)", async () => {
  const res = await fetch(`${USERS_URL}/scim/v2/Users`, {
    method: "GET",
    headers: { Authorization: "Basic dXNlcjpwYXNz" },
  });
  await assert401(res);
});
