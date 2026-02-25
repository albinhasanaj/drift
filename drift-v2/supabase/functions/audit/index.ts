// Phase F1: Audit Log Query + Export API (CP0-F-03, CP0-F-04)
// JWT auth. Cursor-based pagination, 5 filter types, NDJSON export.

import { Hono } from "https://deno.land/x/hono@v3.12.0/mod.ts";
import { createAdminClient } from "../shared/supabase.ts";
import { setTenantContext } from "../shared/tenant-context.ts";

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

// ── GET /api/v1/audit — Query audit log (CP0-F-03) ──

app.get("/api/v1/audit", async (c) => {
  const req = c.req.raw;
  const auth = await authenticateJwt(req);
  const supabase = createAdminClient();
  await setTenantContext(supabase, auth.tenantId);

  // Parse filters
  const actor = c.req.query("actor");
  const action = c.req.query("action");
  const resourceType = c.req.query("resource_type");
  const after = c.req.query("after");
  const before = c.req.query("before");
  const cursor = c.req.query("cursor");
  const limit = Math.min(200, Math.max(1, parseInt(c.req.query("limit") ?? "100")));

  // Build query (parameterized — no string concatenation)
  let query = supabase
    .from("cloud_audit_log")
    .select("*")
    .eq("tenant_id", auth.tenantId)
    .order("created_at", { ascending: false })
    .limit(limit + 1);

  if (actor) query = query.eq("actor_email", actor);
  if (action) query = query.eq("action", action);
  if (resourceType) query = query.eq("resource_type", resourceType);
  if (after) query = query.gt("created_at", after);
  if (before) query = query.lt("created_at", before);
  if (cursor) query = query.lt("id", cursor);

  const { data: events, error } = await query;

  if (error) {
    console.error("Audit query failed:", error.message);
    throw new HttpError(500, "Failed to query audit log");
  }

  const items = events ?? [];
  const hasMore = items.length > limit;
  const pageItems = hasMore ? items.slice(0, limit) : items;
  const nextCursor = hasMore && pageItems.length > 0
    ? pageItems[pageItems.length - 1].id
    : null;

  return c.json({
    data: pageItems,
    pagination: {
      cursor: nextCursor,
      has_more: hasMore,
    },
  });
});

// ── GET /api/v1/audit/export — NDJSON export (CP0-F-04) ──

app.get("/api/v1/audit/export", async (c) => {
  const req = c.req.raw;
  const auth = await authenticateJwt(req);
  const supabase = createAdminClient();
  await setTenantContext(supabase, auth.tenantId);

  const actor = c.req.query("actor");
  const action = c.req.query("action");
  const resourceType = c.req.query("resource_type");
  const after = c.req.query("after");
  const before = c.req.query("before");

  const MAX_EXPORT_ROWS = 10000;
  const BATCH_SIZE = 500;

  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    async start(controller) {
      let cursorId: string | undefined;
      let total = 0;

      while (total < MAX_EXPORT_ROWS) {
        let query = supabase
          .from("cloud_audit_log")
          .select("*")
          .eq("tenant_id", auth.tenantId)
          .order("created_at", { ascending: false })
          .limit(BATCH_SIZE);

        if (actor) query = query.eq("actor_email", actor);
        if (action) query = query.eq("action", action);
        if (resourceType) query = query.eq("resource_type", resourceType);
        if (after) query = query.gt("created_at", after);
        if (before) query = query.lt("created_at", before);
        if (cursorId) query = query.lt("id", cursorId);

        const { data, error } = await query;
        if (error || !data?.length) break;

        for (const row of data) {
          controller.enqueue(encoder.encode(JSON.stringify(row) + "\n"));
          total++;
          if (total >= MAX_EXPORT_ROWS) break;
        }

        cursorId = data[data.length - 1].id;
        if (data.length < BATCH_SIZE) break;
      }

      controller.close();
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "application/x-ndjson",
      "Transfer-Encoding": "chunked",
    },
  });
});

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
        { status: err.status, headers: { "Content-Type": "application/json" } },
      );
    }
    console.error("Unhandled error in audit:", err);
    return new Response(
      JSON.stringify({ error: "Internal server error" }),
      { status: 500, headers: { "Content-Type": "application/json" } },
    );
  }
});
