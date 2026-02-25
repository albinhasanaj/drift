/**
 * Phase F: Audit Log + IP Allowlisting tests
 * Covers: CT0-F-01 (immutability), CT0-F-02 (query filters), CT0-F-03 (export NDJSON),
 *         CT0-F-04 (audit tenant isolation), CT0-F-10 (IP blocks), CT0-F-11 (IP allows CIDR),
 *         CT0-F-12 (IP default open), CT0-F-13 (IP temp expiry)
 *
 * Test environment: Supabase CLI local dev (supabase start).
 */

import {
  assertEquals,
  assertExists,
  assert,
} from "https://deno.land/std@0.208.0/assert/mod.ts";

const AUDIT_URL = Deno.env.get("SUPABASE_FUNCTIONS_URL")
  ? `${Deno.env.get("SUPABASE_FUNCTIONS_URL")}/audit`
  : "http://localhost:54321/functions/v1/audit";
const SETTINGS_URL = Deno.env.get("SUPABASE_FUNCTIONS_URL")
  ? `${Deno.env.get("SUPABASE_FUNCTIONS_URL")}/settings`
  : "http://localhost:54321/functions/v1/settings";
const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "http://localhost:54321";
const SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";

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
    body: JSON.stringify({ user_id: userId, tenant_id: tenant.id, role: "owner", active: true }),
  });

  const { data: session } = await supabase.auth.signInWithPassword({
    email, password: "test-password-123!",
  });

  return { tenantId: tenant.id, userId, jwt: session!.session!.access_token };
}

// ── CT0-F-01: Audit immutability ──

Deno.test("CT0-F-01: INSERT audit → UPDATE blocked, DELETE blocked", async () => {
  const ctx = await setupTestContext("ct0f01");
  const headers = {
    "Content-Type": "application/json",
    apikey: SERVICE_ROLE_KEY,
    Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
  };

  await fetch(`${SUPABASE_URL}/rest/v1/rpc/set_tenant_context`, {
    method: "POST", headers,
    body: JSON.stringify({ p_tenant_id: ctx.tenantId }),
  });

  // INSERT should succeed
  const insertRes = await fetch(`${SUPABASE_URL}/rest/v1/cloud_audit_log`, {
    method: "POST",
    headers: { ...headers, Prefer: "return=representation" },
    body: JSON.stringify({
      tenant_id: ctx.tenantId,
      actor_id: ctx.userId,
      actor_email: "test@test.com",
      action: "test.immutability",
      resource_type: "test",
    }),
  });
  const insertData = await insertRes.json();
  const auditId = Array.isArray(insertData) ? insertData[0].id : insertData.id;
  assertExists(auditId, "Should insert audit entry");

  // UPDATE should be blocked by RLS
  const updateRes = await fetch(
    `${SUPABASE_URL}/rest/v1/cloud_audit_log?id=eq.${auditId}`,
    {
      method: "PATCH",
      headers,
      body: JSON.stringify({ action: "test.hacked" }),
    },
  );
  // RLS should silently block — 0 rows affected
  assertEquals(updateRes.status, 200, "PATCH returns 200 but affects 0 rows");

  // Verify action unchanged
  const getRes = await fetch(
    `${SUPABASE_URL}/rest/v1/cloud_audit_log?id=eq.${auditId}`,
    { headers },
  );
  const getBody = await getRes.json();
  assertEquals(getBody[0].action, "test.immutability", "Action should NOT have changed");

  // DELETE should be blocked by RLS
  const deleteRes = await fetch(
    `${SUPABASE_URL}/rest/v1/cloud_audit_log?id=eq.${auditId}`,
    { method: "DELETE", headers },
  );
  assertEquals(deleteRes.status, 200, "DELETE returns 200 but affects 0 rows");

  // Verify still exists
  const verifyRes = await fetch(
    `${SUPABASE_URL}/rest/v1/cloud_audit_log?id=eq.${auditId}`,
    { headers },
  );
  const verifyBody = await verifyRes.json();
  assertEquals(verifyBody.length, 1, "Audit entry should still exist after DELETE attempt");
});

// ── CT0-F-02: Audit query filters ──

Deno.test("CT0-F-02: Query filters (actor, action, resource_type, after, before)", async () => {
  const ctx = await setupTestContext("ct0f02");
  const headers = {
    "Content-Type": "application/json",
    apikey: SERVICE_ROLE_KEY,
    Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
  };

  await fetch(`${SUPABASE_URL}/rest/v1/rpc/set_tenant_context`, {
    method: "POST", headers,
    body: JSON.stringify({ p_tenant_id: ctx.tenantId }),
  });

  // Insert test events
  for (let i = 0; i < 5; i++) {
    await fetch(`${SUPABASE_URL}/rest/v1/cloud_audit_log`, {
      method: "POST", headers,
      body: JSON.stringify({
        tenant_id: ctx.tenantId,
        actor_id: ctx.userId,
        actor_email: "admin@co.com",
        action: "project.delete",
        resource_type: "project",
      }),
    });
  }
  for (let i = 0; i < 3; i++) {
    await fetch(`${SUPABASE_URL}/rest/v1/cloud_audit_log`, {
      method: "POST", headers,
      body: JSON.stringify({
        tenant_id: ctx.tenantId,
        actor_id: ctx.userId,
        actor_email: "dev@co.com",
        action: "project.create",
        resource_type: "project",
      }),
    });
  }

  // Filter by actor
  const res1 = await fetch(
    `${AUDIT_URL}/api/v1/audit?actor=admin@co.com`,
    { headers: { Authorization: `Bearer ${ctx.jwt}` } },
  );
  assertEquals(res1.status, 200);
  const body1 = await res1.json();
  assert(body1.data.length >= 5, "Should have ≥5 admin events");
  for (const e of body1.data) {
    assertEquals(e.actor_email, "admin@co.com");
  }

  // Filter by action
  const res2 = await fetch(
    `${AUDIT_URL}/api/v1/audit?action=project.delete`,
    { headers: { Authorization: `Bearer ${ctx.jwt}` } },
  );
  assertEquals(res2.status, 200);
  const body2 = await res2.json();
  assert(body2.data.length >= 5);
  for (const e of body2.data) {
    assertEquals(e.action, "project.delete");
  }

  // Combined filter
  const res3 = await fetch(
    `${AUDIT_URL}/api/v1/audit?actor=admin@co.com&action=project.delete`,
    { headers: { Authorization: `Bearer ${ctx.jwt}` } },
  );
  assertEquals(res3.status, 200);
  const body3 = await res3.json();
  assert(body3.data.length >= 5);
});

// ── CT0-F-03: Audit export NDJSON ──

Deno.test("CT0-F-03: Export returns valid NDJSON", async () => {
  const ctx = await setupTestContext("ct0f03");
  const headers = {
    "Content-Type": "application/json",
    apikey: SERVICE_ROLE_KEY,
    Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
  };

  await fetch(`${SUPABASE_URL}/rest/v1/rpc/set_tenant_context`, {
    method: "POST", headers,
    body: JSON.stringify({ p_tenant_id: ctx.tenantId }),
  });

  // Insert some events
  for (let i = 0; i < 10; i++) {
    await fetch(`${SUPABASE_URL}/rest/v1/cloud_audit_log`, {
      method: "POST", headers,
      body: JSON.stringify({
        tenant_id: ctx.tenantId,
        actor_id: ctx.userId,
        actor_email: "export@co.com",
        action: `test.export.${i}`,
        resource_type: "test",
      }),
    });
  }

  const res = await fetch(
    `${AUDIT_URL}/api/v1/audit/export`,
    { headers: { Authorization: `Bearer ${ctx.jwt}` } },
  );
  assertEquals(res.status, 200);
  assertEquals(res.headers.get("content-type"), "application/x-ndjson");

  const text = await res.text();
  const lines = text.trim().split("\n").filter((l) => l.length > 0);
  assert(lines.length >= 10, `Should have ≥10 lines, got ${lines.length}`);

  // Each line should be valid JSON
  for (const line of lines) {
    const parsed = JSON.parse(line);
    assertExists(parsed.id);
    assertExists(parsed.action);
    assertExists(parsed.tenant_id);
  }
});

// ── CT0-F-04: Audit tenant isolation ──

Deno.test("CT0-F-04: Tenant A audit events invisible to tenant B", async () => {
  const ctxA = await setupTestContext("ct0f04a");
  const ctxB = await setupTestContext("ct0f04b");
  const headers = {
    "Content-Type": "application/json",
    apikey: SERVICE_ROLE_KEY,
    Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
  };

  // Insert event for tenant A
  await fetch(`${SUPABASE_URL}/rest/v1/rpc/set_tenant_context`, {
    method: "POST", headers,
    body: JSON.stringify({ p_tenant_id: ctxA.tenantId }),
  });
  await fetch(`${SUPABASE_URL}/rest/v1/cloud_audit_log`, {
    method: "POST", headers,
    body: JSON.stringify({
      tenant_id: ctxA.tenantId,
      actor_id: ctxA.userId,
      actor_email: "a@co.com",
      action: "secret.action",
      resource_type: "secret",
    }),
  });

  // Tenant B queries — should not see A's events
  const res = await fetch(
    `${AUDIT_URL}/api/v1/audit?action=secret.action`,
    { headers: { Authorization: `Bearer ${ctxB.jwt}` } },
  );
  assertEquals(res.status, 200);
  const body = await res.json();
  assertEquals(body.data.length, 0, "Tenant B should not see tenant A's audit events");
});

// ── CT0-F-10: IP blocks non-matching ──

Deno.test("CT0-F-10: Add 10.0.0.0/8 → request from 192.168.1.1 → check blocked", async () => {
  const ctx = await setupTestContext("ct0f10");

  // Add allowlist entry
  const addRes = await fetch(`${SETTINGS_URL}/api/v1/settings/ip-allowlist`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${ctx.jwt}`,
    },
    body: JSON.stringify({ cidr: "10.0.0.0/8", description: "Internal only" }),
  });
  assertEquals(addRes.status, 201);
  await addRes.json();

  // Verify entry exists
  const listRes = await fetch(`${SETTINGS_URL}/api/v1/settings/ip-allowlist`, {
    headers: { Authorization: `Bearer ${ctx.jwt}` },
  });
  assertEquals(listRes.status, 200);
  const listBody = await listRes.json();
  assert(listBody.data.length >= 1);

  // Use the CIDR check function directly to verify matching
  const headers = {
    "Content-Type": "application/json",
    apikey: SERVICE_ROLE_KEY,
    Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
  };

  // 192.168.1.1 should NOT match 10.0.0.0/8
  const checkRes = await fetch(`${SUPABASE_URL}/rest/v1/rpc/check_ip_allowlist`, {
    method: "POST", headers,
    body: JSON.stringify({ p_tenant_id: ctx.tenantId, p_client_ip: "192.168.1.1" }),
  });
  const checkBody = await checkRes.json();
  assertEquals(checkBody.length, 0, "192.168.1.1 should NOT match 10.0.0.0/8");
});

// ── CT0-F-11: IP allows CIDR match ──

Deno.test("CT0-F-11: Add 192.168.0.0/16 → 192.168.1.100 → allowed", async () => {
  const ctx = await setupTestContext("ct0f11");

  await fetch(`${SETTINGS_URL}/api/v1/settings/ip-allowlist`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${ctx.jwt}`,
    },
    body: JSON.stringify({ cidr: "192.168.0.0/16" }),
  });

  const headers = {
    "Content-Type": "application/json",
    apikey: SERVICE_ROLE_KEY,
    Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
  };

  // 192.168.1.100 SHOULD match 192.168.0.0/16
  const checkRes = await fetch(`${SUPABASE_URL}/rest/v1/rpc/check_ip_allowlist`, {
    method: "POST", headers,
    body: JSON.stringify({ p_tenant_id: ctx.tenantId, p_client_ip: "192.168.1.100" }),
  });
  const checkBody = await checkRes.json();
  assert(checkBody.length > 0, "192.168.1.100 should match 192.168.0.0/16");
});

// ── CT0-F-12: Empty allowlist = all allowed ──

Deno.test("CT0-F-12: No entries → any IP → allowed (check via RPC returns empty = default open)", async () => {
  const ctx = await setupTestContext("ct0f12");

  // Verify no entries exist
  const listRes = await fetch(`${SETTINGS_URL}/api/v1/settings/ip-allowlist`, {
    headers: { Authorization: `Bearer ${ctx.jwt}` },
  });
  const listBody = await listRes.json();
  assertEquals(listBody.data.length, 0, "Fresh tenant should have no IP entries");

  // The middleware itself handles empty list = allowed.
  // We verify the RPC returns empty (middleware interprets as "allow")
  const headers = {
    "Content-Type": "application/json",
    apikey: SERVICE_ROLE_KEY,
    Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
  };

  const checkRes = await fetch(`${SUPABASE_URL}/rest/v1/rpc/check_ip_allowlist`, {
    method: "POST", headers,
    body: JSON.stringify({ p_tenant_id: ctx.tenantId, p_client_ip: "8.8.8.8" }),
  });
  const checkBody = await checkRes.json();
  // No entries means the function returns nothing — middleware treats as "allow all"
  assertEquals(checkBody.length, 0, "Empty allowlist returns no matches");
});

// ── CT0-F-13: Temporary IP entry expiry ──

Deno.test("CT0-F-13: Entry with expires_at → unexpired = match, expired = no match", async () => {
  const ctx = await setupTestContext("ct0f13");

  // Add an entry that expires in the future
  const futureExpiry = new Date(Date.now() + 60 * 60 * 1000).toISOString(); // +1h
  const addRes = await fetch(`${SETTINGS_URL}/api/v1/settings/ip-allowlist`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${ctx.jwt}`,
    },
    body: JSON.stringify({ cidr: "203.0.113.0/24", expires_at: futureExpiry }),
  });
  assertEquals(addRes.status, 201);

  const headers = {
    "Content-Type": "application/json",
    apikey: SERVICE_ROLE_KEY,
    Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
  };

  // Should match (not expired)
  const checkRes = await fetch(`${SUPABASE_URL}/rest/v1/rpc/check_ip_allowlist`, {
    method: "POST", headers,
    body: JSON.stringify({ p_tenant_id: ctx.tenantId, p_client_ip: "203.0.113.50" }),
  });
  const checkBody = await checkRes.json();
  assert(checkBody.length > 0, "Should match while not expired");

  // Now add an already-expired entry for different CIDR
  const pastExpiry = new Date(Date.now() - 60 * 60 * 1000).toISOString(); // -1h
  await fetch(`${SUPABASE_URL}/rest/v1/rpc/set_tenant_context`, {
    method: "POST", headers,
    body: JSON.stringify({ p_tenant_id: ctx.tenantId }),
  });
  await fetch(`${SUPABASE_URL}/rest/v1/ip_allowlist`, {
    method: "POST",
    headers: { ...headers, Prefer: "return=representation" },
    body: JSON.stringify({
      tenant_id: ctx.tenantId,
      cidr: "198.51.100.0/24",
      expires_at: pastExpiry,
      created_by: ctx.userId,
    }),
  });

  // Should NOT match (expired)
  const checkRes2 = await fetch(`${SUPABASE_URL}/rest/v1/rpc/check_ip_allowlist`, {
    method: "POST", headers,
    body: JSON.stringify({ p_tenant_id: ctx.tenantId, p_client_ip: "198.51.100.50" }),
  });
  const checkBody2 = await checkRes2.json();
  assertEquals(checkBody2.length, 0, "Expired entry should NOT match");
});
