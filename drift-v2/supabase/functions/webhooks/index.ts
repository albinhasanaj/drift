// Phase E: Webhook CRUD API (CP0-E-02, E-10, E-11, E-12)
// JWT auth. Routes: register, list, get, update, delete, delivery logs, test, rotate-secret.

import { Hono } from "https://deno.land/x/hono@v3.12.0/mod.ts";
import { createAdminClient } from "../shared/supabase.ts";
import { setTenantContext } from "../shared/tenant-context.ts";
import { logAuditEvent, extractRequestContext } from "../shared/audit.ts";
import { validateWebhookUrl } from "../shared/url-validator.ts";
import {
  generateWebhookSecret,
  sha256Hash,
} from "../shared/webhook-signature.ts";
import { deliverTestEvent } from "../shared/webhook-dispatch.ts";
import { WEBHOOK_EVENT_TYPES } from "../shared/webhook-types.ts";

const app = new Hono();

// ── JWT Auth middleware ──

interface AuthContext {
  tenantId: string;
  userId: string;
  email: string;
}

async function authenticateJwt(req: Request): Promise<AuthContext> {
  const authHeader = req.headers.get("authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    throw new HttpError(401, "Missing or invalid Authorization header");
  }

  const token = authHeader.slice(7);
  const supabase = createAdminClient();
  const { data, error } = await supabase.auth.getUser(token);

  if (error || !data?.user) {
    throw new HttpError(401, "Invalid or expired JWT");
  }

  // Get tenant mapping
  const { data: mapping } = await supabase
    .from("user_tenant_mappings")
    .select("tenant_id, role")
    .eq("user_id", data.user.id)
    .eq("active", true)
    .limit(1)
    .single();

  if (!mapping) {
    throw new HttpError(403, "User is not a member of any tenant");
  }

  return {
    tenantId: mapping.tenant_id,
    userId: data.user.id,
    email: data.user.email ?? "",
  };
}

// ── POST /api/v1/webhooks — Register webhook (CP0-E-02) ──

app.post("/api/v1/webhooks", async (c) => {
  const req = c.req.raw;
  const auth = await authenticateJwt(req);
  const supabase = createAdminClient();
  await setTenantContext(supabase, auth.tenantId);
  const { ipAddress, userAgent } = extractRequestContext(req);

  const body = await c.req.json();

  // Validate url
  if (!body.url || typeof body.url !== "string") {
    throw new HttpError(400, "url is required and must be a string");
  }
  const urlValidation = validateWebhookUrl(body.url);
  if (!urlValidation.valid) {
    throw new HttpError(400, urlValidation.error!);
  }

  // Validate events
  if (!body.events || !Array.isArray(body.events) || body.events.length === 0) {
    throw new HttpError(400, "events is required and must be a non-empty array");
  }
  const invalidEvents = body.events.filter(
    (e: string) => !WEBHOOK_EVENT_TYPES.includes(e as typeof WEBHOOK_EVENT_TYPES[number]),
  );
  if (invalidEvents.length > 0) {
    throw new HttpError(
      400,
      `Invalid event types: ${invalidEvents.join(", ")}. Valid: ${WEBHOOK_EVENT_TYPES.join(", ")}`,
    );
  }

  // Generate secret
  const rawSecret = generateWebhookSecret();
  const secretHash = await sha256Hash(rawSecret);

  // Insert endpoint
  const { data: endpoint, error: insertErr } = await supabase
    .from("webhook_endpoints")
    .insert({
      tenant_id: auth.tenantId,
      url: body.url,
      secret_hash: secretHash,
      events: body.events,
      description: body.description ?? "",
      created_by: auth.userId,
    })
    .select("id, url, events, description, active, created_at")
    .single();

  if (insertErr || !endpoint) {
    console.error("Webhook insert failed:", insertErr?.message);
    throw new HttpError(500, "Failed to create webhook endpoint");
  }

  // Audit
  await logAuditEvent(supabase, {
    tenantId: auth.tenantId,
    actorId: auth.userId,
    actorEmail: auth.email,
    action: "webhook.registered",
    resourceType: "webhook",
    resourceId: endpoint.id,
    metadata: { url: body.url, events: body.events },
    ipAddress,
    userAgent,
  });

  return c.json(
    {
      id: endpoint.id,
      url: endpoint.url,
      events: endpoint.events,
      description: endpoint.description,
      active: endpoint.active,
      created_at: endpoint.created_at,
      secret: rawSecret, // Shown ONCE — never retrievable again
    },
    201,
  );
});

// ── GET /api/v1/webhooks — List webhooks for tenant ──

app.get("/api/v1/webhooks", async (c) => {
  const req = c.req.raw;
  const auth = await authenticateJwt(req);
  const supabase = createAdminClient();
  await setTenantContext(supabase, auth.tenantId);

  const { data: endpoints, error } = await supabase
    .from("webhook_endpoints")
    .select(
      "id, url, events, description, active, consecutive_failures, created_by, created_at, updated_at",
    )
    .eq("tenant_id", auth.tenantId)
    .order("created_at", { ascending: false });

  if (error) {
    console.error("Webhook list failed:", error.message);
    throw new HttpError(500, "Failed to list webhooks");
  }

  return c.json({ data: endpoints ?? [] });
});

// ── GET /api/v1/webhooks/:id — Get webhook details ──

app.get("/api/v1/webhooks/:id", async (c) => {
  const req = c.req.raw;
  const auth = await authenticateJwt(req);
  const supabase = createAdminClient();
  await setTenantContext(supabase, auth.tenantId);

  const webhookId = c.req.param("id");

  const { data: endpoint, error } = await supabase
    .from("webhook_endpoints")
    .select(
      "id, url, events, description, active, consecutive_failures, created_by, created_at, updated_at",
    )
    .eq("id", webhookId)
    .eq("tenant_id", auth.tenantId)
    .single();

  if (error || !endpoint) {
    throw new HttpError(404, "Webhook endpoint not found");
  }

  // Include recent deliveries
  const { data: recentDeliveries } = await supabase
    .from("webhook_deliveries")
    .select(
      "id, event_type, status, status_code, attempt, latency_ms, created_at, delivered_at",
    )
    .eq("endpoint_id", webhookId)
    .eq("tenant_id", auth.tenantId)
    .order("created_at", { ascending: false })
    .limit(10);

  return c.json({
    ...endpoint,
    recent_deliveries: recentDeliveries ?? [],
  });
});

// ── PATCH /api/v1/webhooks/:id — Update webhook ──

app.patch("/api/v1/webhooks/:id", async (c) => {
  const req = c.req.raw;
  const auth = await authenticateJwt(req);
  const supabase = createAdminClient();
  await setTenantContext(supabase, auth.tenantId);
  const { ipAddress, userAgent } = extractRequestContext(req);

  const webhookId = c.req.param("id");
  const body = await c.req.json();

  // Verify ownership
  const { data: existing, error: findErr } = await supabase
    .from("webhook_endpoints")
    .select("id")
    .eq("id", webhookId)
    .eq("tenant_id", auth.tenantId)
    .single();

  if (findErr || !existing) {
    throw new HttpError(404, "Webhook endpoint not found");
  }

  const updates: Record<string, unknown> = {
    updated_at: new Date().toISOString(),
  };

  // Validate and apply URL update
  if (body.url !== undefined) {
    if (typeof body.url !== "string") {
      throw new HttpError(400, "url must be a string");
    }
    const urlValidation = validateWebhookUrl(body.url);
    if (!urlValidation.valid) {
      throw new HttpError(400, urlValidation.error!);
    }
    updates.url = body.url;
  }

  // Validate and apply events update
  if (body.events !== undefined) {
    if (!Array.isArray(body.events) || body.events.length === 0) {
      throw new HttpError(400, "events must be a non-empty array");
    }
    const invalidEvents = body.events.filter(
      (e: string) => !WEBHOOK_EVENT_TYPES.includes(e as typeof WEBHOOK_EVENT_TYPES[number]),
    );
    if (invalidEvents.length > 0) {
      throw new HttpError(400, `Invalid event types: ${invalidEvents.join(", ")}`);
    }
    updates.events = body.events;
  }

  if (body.description !== undefined) {
    updates.description = body.description;
  }

  if (body.active !== undefined) {
    updates.active = body.active;
    // Reset failures when re-enabling
    if (body.active === true) {
      updates.consecutive_failures = 0;
    }
  }

  const { data: updated, error: updateErr } = await supabase
    .from("webhook_endpoints")
    .update(updates)
    .eq("id", webhookId)
    .eq("tenant_id", auth.tenantId)
    .select(
      "id, url, events, description, active, consecutive_failures, created_at, updated_at",
    )
    .single();

  if (updateErr || !updated) {
    console.error("Webhook update failed:", updateErr?.message);
    throw new HttpError(500, "Failed to update webhook endpoint");
  }

  // Audit
  await logAuditEvent(supabase, {
    tenantId: auth.tenantId,
    actorId: auth.userId,
    actorEmail: auth.email,
    action: "webhook.updated",
    resourceType: "webhook",
    resourceId: webhookId,
    metadata: { updates: body },
    ipAddress,
    userAgent,
  });

  return c.json(updated);
});

// ── DELETE /api/v1/webhooks/:id — Delete webhook ──

app.delete("/api/v1/webhooks/:id", async (c) => {
  const req = c.req.raw;
  const auth = await authenticateJwt(req);
  const supabase = createAdminClient();
  await setTenantContext(supabase, auth.tenantId);
  const { ipAddress, userAgent } = extractRequestContext(req);

  const webhookId = c.req.param("id");

  // Verify ownership
  const { data: existing, error: findErr } = await supabase
    .from("webhook_endpoints")
    .select("id, url")
    .eq("id", webhookId)
    .eq("tenant_id", auth.tenantId)
    .single();

  if (findErr || !existing) {
    throw new HttpError(404, "Webhook endpoint not found");
  }

  // Delete (cascade deletes deliveries)
  const { error: deleteErr } = await supabase
    .from("webhook_endpoints")
    .delete()
    .eq("id", webhookId)
    .eq("tenant_id", auth.tenantId);

  if (deleteErr) {
    console.error("Webhook delete failed:", deleteErr.message);
    throw new HttpError(500, "Failed to delete webhook endpoint");
  }

  // Audit
  await logAuditEvent(supabase, {
    tenantId: auth.tenantId,
    actorId: auth.userId,
    actorEmail: auth.email,
    action: "webhook.deleted",
    resourceType: "webhook",
    resourceId: webhookId,
    metadata: { url: existing.url },
    ipAddress,
    userAgent,
  });

  return c.json({ deleted: true }, 200);
});

// ── GET /api/v1/webhooks/:id/deliveries — Delivery logs (CP0-E-10) ──

app.get("/api/v1/webhooks/:id/deliveries", async (c) => {
  const req = c.req.raw;
  const auth = await authenticateJwt(req);
  const supabase = createAdminClient();
  await setTenantContext(supabase, auth.tenantId);

  const webhookId = c.req.param("id");

  // Verify ownership
  const { data: existing } = await supabase
    .from("webhook_endpoints")
    .select("id")
    .eq("id", webhookId)
    .eq("tenant_id", auth.tenantId)
    .single();

  if (!existing) {
    throw new HttpError(404, "Webhook endpoint not found");
  }

  // Parse pagination
  const cursor = c.req.query("cursor");
  const limit = Math.min(100, Math.max(1, parseInt(c.req.query("limit") ?? "50")));
  const eventType = c.req.query("event_type");
  const status = c.req.query("status");

  let query = supabase
    .from("webhook_deliveries")
    .select(
      "id, event_type, status, status_code, response_body, attempt, max_attempts, latency_ms, created_at, delivered_at, next_retry_at",
      { count: "exact" },
    )
    .eq("endpoint_id", webhookId)
    .eq("tenant_id", auth.tenantId)
    .order("created_at", { ascending: false })
    .limit(limit + 1); // Fetch one extra to determine has_more

  if (eventType) {
    query = query.eq("event_type", eventType);
  }
  if (status) {
    query = query.eq("status", status);
  }
  if (cursor) {
    query = query.lt("created_at", cursor);
  }

  const { data: deliveries, count: totalCount, error } = await query;

  if (error) {
    console.error("Delivery list failed:", error.message);
    throw new HttpError(500, "Failed to list deliveries");
  }

  const items = deliveries ?? [];
  const hasMore = items.length > limit;
  const pageItems = hasMore ? items.slice(0, limit) : items;
  const nextCursor = hasMore && pageItems.length > 0
    ? pageItems[pageItems.length - 1].created_at
    : null;

  return c.json({
    data: pageItems,
    pagination: {
      cursor: nextCursor,
      has_more: hasMore,
      total: totalCount ?? 0,
    },
  });
});

// ── POST /api/v1/webhooks/:id/test — Test endpoint (CP0-E-11) ──

app.post("/api/v1/webhooks/:id/test", async (c) => {
  const req = c.req.raw;
  const auth = await authenticateJwt(req);
  const supabase = createAdminClient();
  await setTenantContext(supabase, auth.tenantId);
  const { ipAddress, userAgent } = extractRequestContext(req);

  const webhookId = c.req.param("id");

  // Verify ownership and get URL
  const { data: endpoint } = await supabase
    .from("webhook_endpoints")
    .select("id, url")
    .eq("id", webhookId)
    .eq("tenant_id", auth.tenantId)
    .single();

  if (!endpoint) {
    throw new HttpError(404, "Webhook endpoint not found");
  }

  // Synchronous test delivery
  const result = await deliverTestEvent(
    supabase,
    auth.tenantId,
    webhookId,
    endpoint.url,
  );

  // Audit
  await logAuditEvent(supabase, {
    tenantId: auth.tenantId,
    actorId: auth.userId,
    actorEmail: auth.email,
    action: "webhook.tested",
    resourceType: "webhook",
    resourceId: webhookId,
    metadata: { success: result.success, status_code: result.status_code },
    ipAddress,
    userAgent,
  });

  return c.json(result);
});

// ── POST /api/v1/webhooks/:id/rotate-secret — Secret rotation (CP0-E-12) ──

app.post("/api/v1/webhooks/:id/rotate-secret", async (c) => {
  const req = c.req.raw;
  const auth = await authenticateJwt(req);
  const supabase = createAdminClient();
  await setTenantContext(supabase, auth.tenantId);
  const { ipAddress, userAgent } = extractRequestContext(req);

  const webhookId = c.req.param("id");

  // Verify ownership
  const { data: endpoint } = await supabase
    .from("webhook_endpoints")
    .select("id, secret_hash_new")
    .eq("id", webhookId)
    .eq("tenant_id", auth.tenantId)
    .single();

  if (!endpoint) {
    throw new HttpError(404, "Webhook endpoint not found");
  }

  // Check if rotation already in progress
  if (endpoint.secret_hash_new) {
    throw new HttpError(
      409,
      "Secret rotation already in progress. Wait for the 24h window to complete.",
    );
  }

  // Generate new secret
  const newRawSecret = generateWebhookSecret();
  const newSecretHash = await sha256Hash(newRawSecret);

  // Store new secret hash, mark rotation start
  const { error: updateErr } = await supabase
    .from("webhook_endpoints")
    .update({
      secret_hash_new: newSecretHash,
      secret_rotated_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    })
    .eq("id", webhookId)
    .eq("tenant_id", auth.tenantId);

  if (updateErr) {
    console.error("Secret rotation failed:", updateErr.message);
    throw new HttpError(500, "Failed to rotate secret");
  }

  // Audit
  await logAuditEvent(supabase, {
    tenantId: auth.tenantId,
    actorId: auth.userId,
    actorEmail: auth.email,
    action: "webhook.secret_rotated",
    resourceType: "webhook",
    resourceId: webhookId,
    metadata: { rotation_started: true },
    ipAddress,
    userAgent,
  });

  return c.json({
    secret: newRawSecret, // Shown ONCE
    rotation_window_hours: 24,
    message:
      "New secret generated. Both old and new secrets are valid for 24 hours. After 24h, only the new secret will work.",
  });
});

// ── Error handling ──

class HttpError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

Deno.serve(async (req) => {
  try {
    return await app.fetch(req);
  } catch (err) {
    if (err instanceof HttpError) {
      return new Response(
        JSON.stringify({ error: err.message }),
        {
          status: err.status,
          headers: { "Content-Type": "application/json" },
        },
      );
    }
    console.error("Unhandled error in webhooks:", err);
    return new Response(
      JSON.stringify({ error: "Internal server error" }),
      {
        status: 500,
        headers: { "Content-Type": "application/json" },
      },
    );
  }
});
