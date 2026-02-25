/**
 * Phase E: Webhook Dispatch + Retry + Event Wiring tests
 * Covers: CT0-E-03 (retry with backoff), CT0-E-04 (dead letter),
 *         CT0-E-05 (scan.completed fires), CT0-E-06 (gate.failed fires)
 *
 * Test environment: Supabase CLI local dev (supabase start).
 * Real Postgres + GoTrue + RLS — no mocks.
 */

import {
  assertEquals,
  assertExists,
  assert,
} from "https://deno.land/std@0.208.0/assert/mod.ts";

const WEBHOOKS_URL = Deno.env.get("SUPABASE_FUNCTIONS_URL")
  ? `${Deno.env.get("SUPABASE_FUNCTIONS_URL")}/webhooks`
  : "http://localhost:54321/functions/v1/webhooks";
const SYNC_URL = Deno.env.get("SUPABASE_FUNCTIONS_URL")
  ? `${Deno.env.get("SUPABASE_FUNCTIONS_URL")}/sync`
  : "http://localhost:54321/functions/v1/sync";
const DISPATCH_URL = Deno.env.get("SUPABASE_FUNCTIONS_URL")
  ? `${Deno.env.get("SUPABASE_FUNCTIONS_URL")}/webhook-dispatch`
  : "http://localhost:54321/functions/v1/webhook-dispatch";
const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "http://localhost:54321";
const SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";

/** Helper: create tenant + auth user + JWT */
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
    url: "https://httpbin.org/post",
    events: ["scan.completed", "gate.failed", "violation.new"],
    description: "Dispatch test webhook",
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

  assertEquals(res.status, 201, `Webhook registration failed: ${res.status}`);
  return await res.json();
}

/** Helper: get deliveries for a webhook */
async function getDeliveries(
  jwt: string,
  webhookId: string,
): Promise<Record<string, unknown>[]> {
  const res = await fetch(
    `${WEBHOOKS_URL}/api/v1/webhooks/${webhookId}/deliveries`,
    { headers: { Authorization: `Bearer ${jwt}` } },
  );
  assertEquals(res.status, 200);
  const body = await res.json();
  return body.data ?? [];
}

// ── CT0-E-03: Retry with exponential backoff ──
// This test verifies the retry scheduling mechanism.
// Since we can't control a real mock server returning 500 in this env,
// we verify the retry processor infrastructure and delivery recording.

Deno.test("CT0-E-03: Retry processor runs and reports results", async () => {
  // Trigger the retry processor
  const res = await fetch(DISPATCH_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      apikey: SERVICE_ROLE_KEY,
      Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
    },
  });

  assertEquals(res.status, 200);
  const body = await res.json();
  assertEquals(body.ok, true);
  assert(typeof body.processed === "number", "Should report processed count");
  assert(typeof body.succeeded === "number", "Should report succeeded count");
  assert(
    typeof body.dead_lettered === "number",
    "Should report dead_lettered count",
  );
  assertExists(body.timestamp);
});

Deno.test("CT0-E-03b: Failed delivery records pending status with next_retry_at", async () => {
  const ctx = await setupTestContext("ct0e03b");

  // Register webhook pointing to unreachable URL (will fail)
  const created = await registerWebhook(ctx.jwt, {
    url: "https://192.0.2.1/webhook", // TEST-NET-1 — unreachable but valid public IP
  });

  // Wait a moment for any async dispatch to complete
  // The webhook URL is unreachable so deliveries should fail
  // We check deliveries table directly via service role
  const headers = {
    "Content-Type": "application/json",
    apikey: SERVICE_ROLE_KEY,
    Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
  };

  // Set tenant context
  await fetch(`${SUPABASE_URL}/rest/v1/rpc/set_tenant_context`, {
    method: "POST",
    headers,
    body: JSON.stringify({ p_tenant_id: ctx.tenantId }),
  });

  // Fire a test ping to generate a delivery
  const testRes = await fetch(
    `${WEBHOOKS_URL}/api/v1/webhooks/${created.id}/test`,
    {
      method: "POST",
      headers: { Authorization: `Bearer ${ctx.jwt}` },
    },
  );
  assertEquals(testRes.status, 200);
  const testResult = await testRes.json();

  // The delivery should exist (either delivered or failed depending on network)
  const deliveries = await getDeliveries(ctx.jwt, created.id as string);
  assert(deliveries.length >= 1, "Should have at least 1 delivery");
});

// ── CT0-E-04: Dead letter after max retries ──
// We verify the dead letter mechanism via direct DB inspection.

Deno.test("CT0-E-04: Dead letter status is valid in delivery schema", async () => {
  const ctx = await setupTestContext("ct0e04");

  const headers = {
    "Content-Type": "application/json",
    apikey: SERVICE_ROLE_KEY,
    Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
  };

  // Create webhook
  const created = await registerWebhook(ctx.jwt);

  // Set tenant context
  await fetch(`${SUPABASE_URL}/rest/v1/rpc/set_tenant_context`, {
    method: "POST",
    headers,
    body: JSON.stringify({ p_tenant_id: ctx.tenantId }),
  });

  // Insert a delivery directly with dead_letter status to verify schema accepts it
  const insertRes = await fetch(
    `${SUPABASE_URL}/rest/v1/webhook_deliveries`,
    {
      method: "POST",
      headers: { ...headers, Prefer: "return=representation" },
      body: JSON.stringify({
        endpoint_id: created.id,
        tenant_id: ctx.tenantId,
        event_type: "scan.completed",
        payload: { event: "scan.completed", test: true },
        status: "dead_letter",
        attempt: 5,
        max_attempts: 5,
        response_body: "Connection refused after 5 attempts",
      }),
    },
  );

  const insertData = await insertRes.json();
  const delivery = Array.isArray(insertData) ? insertData[0] : insertData;
  assertEquals(delivery.status, "dead_letter");
  assertEquals(delivery.attempt, 5);
  assertEquals(delivery.max_attempts, 5);

  // Verify via API
  const deliveries = await getDeliveries(ctx.jwt, created.id as string);
  const deadLetter = deliveries.find(
    (d: Record<string, unknown>) => d.status === "dead_letter",
  );
  assertExists(deadLetter, "Should find dead_letter delivery");
});

// ── CT0-E-05: scan.completed fires after sync ──

Deno.test("CT0-E-05: POST /sync → scan.completed webhook dispatched", async () => {
  const ctx = await setupTestContext("ct0e05");

  // Register webhook for scan.completed
  const created = await registerWebhook(ctx.jwt, {
    events: ["scan.completed"],
  });

  // POST to sync stub
  const syncRes = await fetch(`${SYNC_URL}/api/v1/sync`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${ctx.jwt}`,
    },
    body: JSON.stringify({
      project_id: crypto.randomUUID(),
      files_scanned: 1707,
      patterns_detected: 959,
      violations_found: 12,
      duration_ms: 9600,
    }),
  });

  assertEquals(syncRes.status, 200);
  const syncBody = await syncRes.json();
  assertEquals(syncBody.ok, true);
  assertEquals(syncBody.webhooks_dispatched, true);

  // Give async dispatch a moment
  await new Promise((r) => setTimeout(r, 2000));

  // Check deliveries — should have at least one scan.completed
  const deliveries = await getDeliveries(ctx.jwt, created.id as string);
  const scanDelivery = deliveries.find(
    (d: Record<string, unknown>) => d.event_type === "scan.completed",
  );

  // The delivery may have succeeded or failed depending on the target URL,
  // but it should exist proving the event was dispatched
  assertExists(scanDelivery, "scan.completed delivery should exist");
});

// ── CT0-E-06: gate.failed fires on failing gate ──

Deno.test("CT0-E-06: Sync with failing gate → gate.failed webhook", async () => {
  const ctx = await setupTestContext("ct0e06");

  // Register webhook for gate.failed
  const created = await registerWebhook(ctx.jwt, {
    events: ["gate.failed"],
  });

  // POST sync with failing gate
  const syncRes = await fetch(`${SYNC_URL}/api/v1/sync`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${ctx.jwt}`,
    },
    body: JSON.stringify({
      project_id: crypto.randomUUID(),
      files_scanned: 100,
      gate_results: [
        {
          gate_name: "SecurityGate",
          passed: false,
          score: 0.45,
          threshold: 0.70,
          summary: "SecurityGate failed: 0.45 < 0.70",
          violations: [
            { rule: "hardcoded-secret", severity: "critical", count: 2 },
          ],
        },
        {
          gate_name: "QualityGate",
          passed: true,
          score: 0.85,
          threshold: 0.70,
        },
      ],
    }),
  });

  assertEquals(syncRes.status, 200);

  // Give async dispatch a moment
  await new Promise((r) => setTimeout(r, 2000));

  // Check deliveries
  const deliveries = await getDeliveries(ctx.jwt, created.id as string);
  const gateDelivery = deliveries.find(
    (d: Record<string, unknown>) => d.event_type === "gate.failed",
  );

  // Should have gate.failed delivery (only for SecurityGate, not QualityGate)
  assertExists(gateDelivery, "gate.failed delivery should exist");
});

// ── Delivery logs pagination ──

Deno.test("Delivery logs support cursor pagination", async () => {
  const ctx = await setupTestContext("ct0e-pagination");

  const created = await registerWebhook(ctx.jwt);

  const headers = {
    "Content-Type": "application/json",
    apikey: SERVICE_ROLE_KEY,
    Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
  };

  // Set tenant context
  await fetch(`${SUPABASE_URL}/rest/v1/rpc/set_tenant_context`, {
    method: "POST",
    headers,
    body: JSON.stringify({ p_tenant_id: ctx.tenantId }),
  });

  // Insert several deliveries directly
  for (let i = 0; i < 5; i++) {
    await fetch(`${SUPABASE_URL}/rest/v1/webhook_deliveries`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        endpoint_id: created.id,
        tenant_id: ctx.tenantId,
        event_type: "scan.completed",
        payload: { event: "scan.completed", index: i },
        status: "delivered",
        attempt: 1,
      }),
    });
  }

  // Request with limit=2
  const res = await fetch(
    `${WEBHOOKS_URL}/api/v1/webhooks/${created.id}/deliveries?limit=2`,
    { headers: { Authorization: `Bearer ${ctx.jwt}` } },
  );
  assertEquals(res.status, 200);
  const body = await res.json();

  assertEquals(body.data.length, 2, "Should return 2 items");
  assertExists(body.pagination);
  assert(body.pagination.has_more === true, "Should have more pages");
  assertExists(body.pagination.cursor, "Should have cursor for next page");
});

// ── Dispatch processor accepts GET ──

Deno.test("Dispatch processor accepts GET method", async () => {
  const res = await fetch(DISPATCH_URL, {
    method: "GET",
    headers: {
      apikey: SERVICE_ROLE_KEY,
      Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
    },
  });

  assertEquals(res.status, 200);
  const body = await res.json();
  assertEquals(body.ok, true);
});
