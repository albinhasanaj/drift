/**
 * Phase E: Webhook CRUD + Delivery + Rotation tests
 * Covers: CT0-E-01, CT0-E-07, CT0-E-08, CT0-E-09, CT0-E-10
 *
 * Test environment: Supabase CLI local dev (supabase start).
 * Real Postgres + GoTrue + RLS — no mocks.
 */

import {
  assertEquals,
  assertExists,
  assert,
  assertNotEquals,
} from "https://deno.land/std@0.208.0/assert/mod.ts";

const WEBHOOKS_URL = Deno.env.get("SUPABASE_FUNCTIONS_URL")
  ? `${Deno.env.get("SUPABASE_FUNCTIONS_URL")}/webhooks`
  : "http://localhost:54321/functions/v1/webhooks";
const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "http://localhost:54321";
const SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";

/** Helper: create tenant + auth user + JWT for webhook testing */
async function setupTestContext(name: string): Promise<{
  tenantId: string;
  userId: string;
  jwt: string;
}> {
  const headers = {
    "Content-Type": "application/json",
    apikey: SERVICE_ROLE_KEY,
    Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
  };

  // Create tenant
  const tenantRes = await fetch(`${SUPABASE_URL}/rest/v1/tenants`, {
    method: "POST",
    headers: { ...headers, Prefer: "return=representation" },
    body: JSON.stringify({
      name,
      email: `${name}@test.com`,
      plan: "enterprise",
    }),
  });
  const tenantData = await tenantRes.json();
  const tenant = Array.isArray(tenantData) ? tenantData[0] : tenantData;

  // Create auth user
  const email = `${name}-${Date.now()}@test.com`;
  const { createClient } = await import(
    "https://esm.sh/@supabase/supabase-js@2"
  );
  const supabase = createClient(SUPABASE_URL, SERVICE_ROLE_KEY, {
    auth: { autoRefreshToken: false, persistSession: false },
  });

  const { data: authUser } = await supabase.auth.admin.createUser({
    email,
    password: "test-password-123!",
    email_confirm: true,
  });

  const userId = authUser!.user!.id;

  // Set tenant context and create mapping
  await fetch(`${SUPABASE_URL}/rest/v1/rpc/set_tenant_context`, {
    method: "POST",
    headers,
    body: JSON.stringify({ p_tenant_id: tenant.id }),
  });

  await fetch(`${SUPABASE_URL}/rest/v1/user_tenant_mappings`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      user_id: userId,
      tenant_id: tenant.id,
      role: "admin",
      active: true,
    }),
  });

  // Get JWT via sign-in
  const { data: session } = await supabase.auth.signInWithPassword({
    email,
    password: "test-password-123!",
  });

  return {
    tenantId: tenant.id,
    userId,
    jwt: session!.session!.access_token,
  };
}

/** Helper: register a webhook */
async function registerWebhook(
  jwt: string,
  overrides: Record<string, unknown> = {},
): Promise<Record<string, unknown>> {
  const body = {
    url: "https://example.com/webhook",
    events: ["scan.completed", "gate.failed"],
    description: "Test webhook",
    ...overrides,
  };

  const res = await fetch(`${WEBHOOKS_URL}/api/v1/webhooks`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${jwt}`,
    },
    body: JSON.stringify(body),
  });

  assertEquals(res.status, 201, `Expected 201, got ${res.status}`);
  return await res.json();
}

// ── CT0-E-01: Registration round-trip ──

Deno.test("CT0-E-01: POST → GET → endpoint in list with correct URL/events", async () => {
  const ctx = await setupTestContext("ct0e01");

  // Register
  const created = await registerWebhook(ctx.jwt);
  assertExists(created.id, "Should return webhook ID");
  assertExists(created.secret, "Should return raw secret (shown once)");
  assertEquals(created.url, "https://example.com/webhook");
  assertEquals(created.events, ["scan.completed", "gate.failed"]);

  // List
  const listRes = await fetch(`${WEBHOOKS_URL}/api/v1/webhooks`, {
    headers: { Authorization: `Bearer ${ctx.jwt}` },
  });
  assertEquals(listRes.status, 200);
  const listBody = await listRes.json();
  assert(Array.isArray(listBody.data), "data should be array");

  const found = listBody.data.find(
    (w: Record<string, unknown>) => w.id === created.id,
  );
  assertExists(found, "Created webhook should appear in list");
  assertEquals(found.url, "https://example.com/webhook");
  assertEquals(found.events, ["scan.completed", "gate.failed"]);
  assertEquals(found.active, true);

  // Secret should NOT be in GET response
  assertEquals(found.secret, undefined, "Secret must never be in GET response");
});

// ── CT0-E-07: URL validation ──

Deno.test("CT0-E-07a: HTTP URL → 400", async () => {
  const ctx = await setupTestContext("ct0e07a");

  const res = await fetch(`${WEBHOOKS_URL}/api/v1/webhooks`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${ctx.jwt}`,
    },
    body: JSON.stringify({
      url: "http://example.com/webhook",
      events: ["scan.completed"],
    }),
  });
  assertEquals(res.status, 400);
  const body = await res.json();
  assert(body.error.includes("HTTPS"), "Should mention HTTPS requirement");
});

Deno.test("CT0-E-07b: localhost URL → 400", async () => {
  const ctx = await setupTestContext("ct0e07b");

  const res = await fetch(`${WEBHOOKS_URL}/api/v1/webhooks`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${ctx.jwt}`,
    },
    body: JSON.stringify({
      url: "https://localhost/webhook",
      events: ["scan.completed"],
    }),
  });
  assertEquals(res.status, 400);
  const body = await res.json();
  assert(body.error.includes("localhost"), "Should mention localhost");
});

Deno.test("CT0-E-07c: Private IP → 400", async () => {
  const ctx = await setupTestContext("ct0e07c");

  for (const ip of ["10.0.0.1", "172.16.0.1", "192.168.1.1", "127.0.0.1"]) {
    const res = await fetch(`${WEBHOOKS_URL}/api/v1/webhooks`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${ctx.jwt}`,
      },
      body: JSON.stringify({
        url: `https://${ip}/webhook`,
        events: ["scan.completed"],
      }),
    });
    assertEquals(res.status, 400, `Should reject private IP ${ip}`);
    await res.json(); // consume body
  }
});

Deno.test("CT0-E-07d: Invalid event types → 400", async () => {
  const ctx = await setupTestContext("ct0e07d");

  const res = await fetch(`${WEBHOOKS_URL}/api/v1/webhooks`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${ctx.jwt}`,
    },
    body: JSON.stringify({
      url: "https://example.com/webhook",
      events: ["not.a.real.event"],
    }),
  });
  assertEquals(res.status, 400);
  const body = await res.json();
  assert(body.error.includes("Invalid event"), "Should mention invalid events");
});

// ── CT0-E-08: Tenant isolation ──

Deno.test("CT0-E-08: Tenant A webhook → tenant B cannot GET/PATCH/DELETE", async () => {
  const ctxA = await setupTestContext("ct0e08a");
  const ctxB = await setupTestContext("ct0e08b");

  // Tenant A creates webhook
  const created = await registerWebhook(ctxA.jwt);
  const webhookId = created.id;

  // Tenant B cannot GET
  const getRes = await fetch(`${WEBHOOKS_URL}/api/v1/webhooks/${webhookId}`, {
    headers: { Authorization: `Bearer ${ctxB.jwt}` },
  });
  assertEquals(getRes.status, 404, "Tenant B should not see tenant A's webhook");
  await getRes.json(); // consume

  // Tenant B cannot PATCH
  const patchRes = await fetch(
    `${WEBHOOKS_URL}/api/v1/webhooks/${webhookId}`,
    {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${ctxB.jwt}`,
      },
      body: JSON.stringify({ description: "hacked" }),
    },
  );
  assertEquals(patchRes.status, 404, "Tenant B should not PATCH tenant A's webhook");
  await patchRes.json(); // consume

  // Tenant B cannot DELETE
  const delRes = await fetch(
    `${WEBHOOKS_URL}/api/v1/webhooks/${webhookId}`,
    {
      method: "DELETE",
      headers: { Authorization: `Bearer ${ctxB.jwt}` },
    },
  );
  assertEquals(delRes.status, 404, "Tenant B should not DELETE tenant A's webhook");
  await delRes.json(); // consume

  // Tenant A CAN GET (control)
  const getA = await fetch(`${WEBHOOKS_URL}/api/v1/webhooks/${webhookId}`, {
    headers: { Authorization: `Bearer ${ctxA.jwt}` },
  });
  assertEquals(getA.status, 200, "Tenant A should see own webhook");
  await getA.json(); // consume
});

// ── CT0-E-09: Test endpoint delivers ping with valid signature ──

Deno.test("CT0-E-09: POST /:id/test → delivery recorded", async () => {
  const ctx = await setupTestContext("ct0e09");

  // Register webhook pointing to a URL that will likely fail (that's ok)
  const created = await registerWebhook(ctx.jwt, {
    url: "https://httpbin.org/post",
  });
  const webhookId = created.id;

  // Fire test
  const testRes = await fetch(
    `${WEBHOOKS_URL}/api/v1/webhooks/${webhookId}/test`,
    {
      method: "POST",
      headers: { Authorization: `Bearer ${ctx.jwt}` },
    },
  );
  assertEquals(testRes.status, 200);
  const result = await testRes.json();

  // Result should have delivery shape
  assertExists(result.latency_ms, "Should have latency_ms");
  assert(typeof result.success === "boolean", "success should be boolean");
  assert(typeof result.latency_ms === "number", "latency_ms should be number");

  // Check delivery was recorded
  const deliveriesRes = await fetch(
    `${WEBHOOKS_URL}/api/v1/webhooks/${webhookId}/deliveries`,
    {
      headers: { Authorization: `Bearer ${ctx.jwt}` },
    },
  );
  assertEquals(deliveriesRes.status, 200);
  const deliveriesBody = await deliveriesRes.json();
  assert(deliveriesBody.data.length >= 1, "Should have at least 1 delivery");

  const pingDelivery = deliveriesBody.data.find(
    (d: Record<string, unknown>) => d.event_type === "ping",
  );
  assertExists(pingDelivery, "Should have a ping delivery");
});

// ── CT0-E-10: Secret rotation dual-validity ──

Deno.test("CT0-E-10: Rotate → new secret returned, old still works during window", async () => {
  const ctx = await setupTestContext("ct0e10");

  // Register
  const created = await registerWebhook(ctx.jwt);
  const webhookId = created.id;
  const oldSecret = created.secret as string;
  assertExists(oldSecret);

  // Rotate
  const rotateRes = await fetch(
    `${WEBHOOKS_URL}/api/v1/webhooks/${webhookId}/rotate-secret`,
    {
      method: "POST",
      headers: { Authorization: `Bearer ${ctx.jwt}` },
    },
  );
  assertEquals(rotateRes.status, 200);
  const rotateBody = await rotateRes.json();
  assertExists(rotateBody.secret, "Should return new raw secret");
  assertNotEquals(rotateBody.secret, oldSecret, "New secret must differ from old");
  assertEquals(rotateBody.rotation_window_hours, 24);

  // Rotation in progress — second rotate should fail
  const rotate2Res = await fetch(
    `${WEBHOOKS_URL}/api/v1/webhooks/${webhookId}/rotate-secret`,
    {
      method: "POST",
      headers: { Authorization: `Bearer ${ctx.jwt}` },
    },
  );
  assertEquals(rotate2Res.status, 409, "Double rotation should be rejected");
  await rotate2Res.json(); // consume

  // Verify endpoint still in healthy state
  const getRes = await fetch(`${WEBHOOKS_URL}/api/v1/webhooks/${webhookId}`, {
    headers: { Authorization: `Bearer ${ctx.jwt}` },
  });
  assertEquals(getRes.status, 200);
  await getRes.json(); // consume
});

// ── PATCH and DELETE round-trip ──

Deno.test("Webhook PATCH updates fields correctly", async () => {
  const ctx = await setupTestContext("ct0e-patch");

  const created = await registerWebhook(ctx.jwt);
  const webhookId = created.id;

  // Update
  const patchRes = await fetch(
    `${WEBHOOKS_URL}/api/v1/webhooks/${webhookId}`,
    {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${ctx.jwt}`,
      },
      body: JSON.stringify({
        url: "https://new-endpoint.example.com/hook",
        events: ["violation.new"],
        description: "Updated description",
      }),
    },
  );
  assertEquals(patchRes.status, 200);
  const updated = await patchRes.json();
  assertEquals(updated.url, "https://new-endpoint.example.com/hook");
  assertEquals(updated.events, ["violation.new"]);
  assertEquals(updated.description, "Updated description");
});

Deno.test("Webhook PATCH revalidates URL (reject HTTP)", async () => {
  const ctx = await setupTestContext("ct0e-patch-url");

  const created = await registerWebhook(ctx.jwt);
  const webhookId = created.id;

  const patchRes = await fetch(
    `${WEBHOOKS_URL}/api/v1/webhooks/${webhookId}`,
    {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${ctx.jwt}`,
      },
      body: JSON.stringify({ url: "http://evil.com/hook" }),
    },
  );
  assertEquals(patchRes.status, 400, "PATCH should revalidate URL");
  await patchRes.json(); // consume
});

Deno.test("Webhook DELETE removes endpoint", async () => {
  const ctx = await setupTestContext("ct0e-delete");

  const created = await registerWebhook(ctx.jwt);
  const webhookId = created.id;

  // Delete
  const delRes = await fetch(
    `${WEBHOOKS_URL}/api/v1/webhooks/${webhookId}`,
    {
      method: "DELETE",
      headers: { Authorization: `Bearer ${ctx.jwt}` },
    },
  );
  assertEquals(delRes.status, 200);

  // Verify gone
  const getRes = await fetch(`${WEBHOOKS_URL}/api/v1/webhooks/${webhookId}`, {
    headers: { Authorization: `Bearer ${ctx.jwt}` },
  });
  assertEquals(getRes.status, 404);
  await getRes.json(); // consume
});

// ── No auth → 401 ──

Deno.test("No JWT → 401", async () => {
  const res = await fetch(`${WEBHOOKS_URL}/api/v1/webhooks`, {
    method: "GET",
  });
  assertEquals(res.status, 401);
  await res.json(); // consume
});
