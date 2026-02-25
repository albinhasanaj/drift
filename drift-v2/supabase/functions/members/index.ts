// Phase F2: Seat Management API (CP0-F-12)
// JWT auth. Member list + seat count.

import { Hono } from "https://deno.land/x/hono@v3.12.0/mod.ts";
import { createAdminClient } from "../shared/supabase.ts";
import { setTenantContext } from "../shared/tenant-context.ts";

const app = new Hono();

interface AuthContext {
  tenantId: string;
  userId: string;
  email: string;
  role: string;
}

async function authenticateJwt(req: Request): Promise<AuthContext> {
  const authHeader = req.headers.get("authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    throw new HttpError(401, "Missing or invalid Authorization header");
  }
  const token = authHeader.slice(7);
  const supabase = createAdminClient();
  const { data, error } = await supabase.auth.getUser(token);
  if (error || !data?.user) throw new HttpError(401, "Invalid or expired JWT");

  const { data: mapping } = await supabase
    .from("user_tenant_mappings")
    .select("tenant_id, role")
    .eq("user_id", data.user.id)
    .eq("active", true)
    .limit(1)
    .single();
  if (!mapping) throw new HttpError(403, "User is not a member of any tenant");

  return {
    tenantId: mapping.tenant_id,
    userId: data.user.id,
    email: data.user.email ?? "",
    role: mapping.role,
  };
}

// ── GET /api/v1/members — Paginated member list ──

app.get("/api/v1/members", async (c) => {
  const auth = await authenticateJwt(c.req.raw);
  const supabase = createAdminClient();
  await setTenantContext(supabase, auth.tenantId);

  const limit = Math.min(100, Math.max(1, parseInt(c.req.query("limit") ?? "50")));
  const cursor = c.req.query("cursor");

  let query = supabase
    .from("user_tenant_mappings")
    .select("user_id, role, active, created_at")
    .eq("tenant_id", auth.tenantId)
    .eq("active", true)
    .order("created_at", { ascending: false })
    .limit(limit + 1);

  if (cursor) query = query.lt("created_at", cursor);

  const { data: members, error } = await query;
  if (error) throw new HttpError(500, "Failed to list members");

  const items = members ?? [];
  const hasMore = items.length > limit;
  const pageItems = hasMore ? items.slice(0, limit) : items;

  return c.json({
    data: pageItems,
    pagination: {
      has_more: hasMore,
      cursor: hasMore && pageItems.length > 0
        ? pageItems[pageItems.length - 1].created_at
        : null,
    },
  });
});

// ── GET /api/v1/members/count — Seat count ──

app.get("/api/v1/members/count", async (c) => {
  const auth = await authenticateJwt(c.req.raw);
  const supabase = createAdminClient();
  await setTenantContext(supabase, auth.tenantId);

  const { count: activeCount } = await supabase
    .from("user_tenant_mappings")
    .select("*", { count: "exact", head: true })
    .eq("tenant_id", auth.tenantId)
    .eq("active", true);

  const { count: pendingInvites } = await supabase
    .from("invitations")
    .select("*", { count: "exact", head: true })
    .eq("tenant_id", auth.tenantId)
    .is("accepted_at", null)
    .gt("expires_at", new Date().toISOString());

  const { data: subscription } = await supabase
    .from("subscriptions")
    .select("seat_limit")
    .eq("tenant_id", auth.tenantId)
    .single();

  const seatLimit = subscription?.seat_limit ?? 5;
  const active = activeCount ?? 0;
  const pending = pendingInvites ?? 0;

  return c.json({
    active,
    pending_invites: pending,
    seat_limit: seatLimit,
    remaining: Math.max(0, seatLimit - active - pending),
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
    console.error("Unhandled error in members:", err);
    return new Response(
      JSON.stringify({ error: "Internal server error" }),
      { status: 500, headers: { "Content-Type": "application/json" } },
    );
  }
});
