// Phase F2/F3: Settings API (CP0-F-13, CP0-F-15, CP0-F-17)
// Ownership transfer + IP allowlist CRUD + emergency reset.

import { Hono } from "https://deno.land/x/hono@v3.12.0/mod.ts";
import { createAdminClient } from "../shared/supabase.ts";
import { setTenantContext } from "../shared/tenant-context.ts";
import { logAuditEvent, extractRequestContext } from "../shared/audit.ts";

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

function requireRole(auth: AuthContext, ...roles: string[]) {
  if (!roles.includes(auth.role)) {
    throw new HttpError(403, `Requires role: ${roles.join(" or ")}`);
  }
}

// ══════════════════════════════════════════════════
// Ownership Transfer (CP0-F-13)
// ══════════════════════════════════════════════════

app.post("/api/v1/settings/transfer-ownership", async (c) => {
  const req = c.req.raw;
  const auth = await authenticateJwt(req);
  requireRole(auth, "owner");
  const supabase = createAdminClient();
  await setTenantContext(supabase, auth.tenantId);
  const { ipAddress, userAgent } = extractRequestContext(req);

  const body = await c.req.json();
  if (!body.new_owner_id) throw new HttpError(400, "new_owner_id is required");

  // Verify new owner is an active member
  const { data: newOwnerMapping } = await supabase
    .from("user_tenant_mappings")
    .select("user_id, role")
    .eq("user_id", body.new_owner_id)
    .eq("tenant_id", auth.tenantId)
    .eq("active", true)
    .single();

  if (!newOwnerMapping) {
    throw new HttpError(404, "New owner is not an active member of this tenant");
  }

  if (newOwnerMapping.user_id === auth.userId) {
    throw new HttpError(400, "Cannot transfer ownership to yourself");
  }

  // Atomic transfer: old owner → admin, new owner → owner
  // Update old owner role
  const { error: err1 } = await supabase
    .from("user_tenant_mappings")
    .update({ role: "admin" })
    .eq("user_id", auth.userId)
    .eq("tenant_id", auth.tenantId);

  if (err1) throw new HttpError(500, "Failed to update old owner role");

  // Update new owner role
  const { error: err2 } = await supabase
    .from("user_tenant_mappings")
    .update({ role: "owner" })
    .eq("user_id", body.new_owner_id)
    .eq("tenant_id", auth.tenantId);

  if (err2) {
    // Rollback old owner
    await supabase
      .from("user_tenant_mappings")
      .update({ role: "owner" })
      .eq("user_id", auth.userId)
      .eq("tenant_id", auth.tenantId);
    throw new HttpError(500, "Failed to update new owner role");
  }

  // Update tenant owner_id
  await supabase
    .from("tenants")
    .update({ owner_id: body.new_owner_id })
    .eq("id", auth.tenantId);

  // Audit both
  await logAuditEvent(supabase, {
    tenantId: auth.tenantId,
    actorId: auth.userId,
    actorEmail: auth.email,
    action: "ownership.transferred_from",
    resourceType: "tenant",
    resourceId: auth.tenantId,
    metadata: { new_owner_id: body.new_owner_id },
    ipAddress,
    userAgent,
  });

  await logAuditEvent(supabase, {
    tenantId: auth.tenantId,
    actorId: body.new_owner_id,
    actorEmail: auth.email,
    action: "ownership.transferred_to",
    resourceType: "tenant",
    resourceId: auth.tenantId,
    metadata: { old_owner_id: auth.userId },
    ipAddress,
    userAgent,
  });

  return c.json({
    transferred: true,
    old_owner: { user_id: auth.userId, new_role: "admin" },
    new_owner: { user_id: body.new_owner_id, new_role: "owner" },
  });
});

// ══════════════════════════════════════════════════
// IP Allowlist CRUD (CP0-F-15)
// ══════════════════════════════════════════════════

// ── POST /api/v1/settings/ip-allowlist — Add CIDR entry ──

app.post("/api/v1/settings/ip-allowlist", async (c) => {
  const req = c.req.raw;
  const auth = await authenticateJwt(req);
  requireRole(auth, "owner", "admin");
  const supabase = createAdminClient();
  await setTenantContext(supabase, auth.tenantId);
  const { ipAddress, userAgent } = extractRequestContext(req);

  const body = await c.req.json();
  if (!body.cidr || typeof body.cidr !== "string") {
    throw new HttpError(400, "cidr is required (e.g., '10.0.0.0/8')");
  }

  // Reject overly broad CIDRs
  if (body.cidr === "0.0.0.0/0" || body.cidr === "::/0") {
    throw new HttpError(400, "Cannot add 0.0.0.0/0 — that allows all IPs, defeating the purpose");
  }

  // Use Postgres to validate CIDR format (cast will fail if invalid)
  const { data: entry, error } = await supabase
    .from("ip_allowlist")
    .insert({
      tenant_id: auth.tenantId,
      cidr: body.cidr,
      description: body.description ?? "",
      expires_at: body.expires_at ?? null,
      created_by: auth.userId,
    })
    .select("id, cidr, description, expires_at, created_at")
    .single();

  if (error || !entry) {
    if (error?.message?.includes("invalid input syntax")) {
      throw new HttpError(400, "Invalid CIDR format");
    }
    throw new HttpError(500, "Failed to add IP allowlist entry");
  }

  await logAuditEvent(supabase, {
    tenantId: auth.tenantId,
    actorId: auth.userId,
    actorEmail: auth.email,
    action: "ip_allowlist.added",
    resourceType: "ip_allowlist",
    resourceId: entry.id,
    metadata: { cidr: body.cidr, expires_at: body.expires_at ?? null },
    ipAddress,
    userAgent,
  });

  return c.json(entry, 201);
});

// ── GET /api/v1/settings/ip-allowlist — List entries ──

app.get("/api/v1/settings/ip-allowlist", async (c) => {
  const auth = await authenticateJwt(c.req.raw);
  requireRole(auth, "owner", "admin");
  const supabase = createAdminClient();
  await setTenantContext(supabase, auth.tenantId);

  const { data: entries, error } = await supabase
    .from("ip_allowlist")
    .select("id, cidr, description, expires_at, created_by, created_at")
    .eq("tenant_id", auth.tenantId)
    .order("created_at", { ascending: false });

  if (error) throw new HttpError(500, "Failed to list IP allowlist");
  return c.json({ data: entries ?? [] });
});

// ── DELETE /api/v1/settings/ip-allowlist/:id — Remove entry ──

app.delete("/api/v1/settings/ip-allowlist/:id", async (c) => {
  const req = c.req.raw;
  const auth = await authenticateJwt(req);
  requireRole(auth, "owner", "admin");
  const supabase = createAdminClient();
  await setTenantContext(supabase, auth.tenantId);
  const { ipAddress, userAgent } = extractRequestContext(req);

  const entryId = c.req.param("id");

  const { data: existing } = await supabase
    .from("ip_allowlist")
    .select("id, cidr")
    .eq("id", entryId)
    .eq("tenant_id", auth.tenantId)
    .single();

  if (!existing) throw new HttpError(404, "IP allowlist entry not found");

  const { error } = await supabase
    .from("ip_allowlist")
    .delete()
    .eq("id", entryId);

  if (error) throw new HttpError(500, "Failed to remove IP allowlist entry");

  await logAuditEvent(supabase, {
    tenantId: auth.tenantId,
    actorId: auth.userId,
    actorEmail: auth.email,
    action: "ip_allowlist.removed",
    resourceType: "ip_allowlist",
    resourceId: entryId,
    metadata: { cidr: existing.cidr },
    ipAddress,
    userAgent,
  });

  return c.json({ removed: true });
});

// ── DELETE /api/v1/settings/ip-allowlist — Emergency reset (CP0-F-18 API) ──

app.delete("/api/v1/settings/ip-allowlist", async (c) => {
  const req = c.req.raw;
  const auth = await authenticateJwt(req);
  requireRole(auth, "owner");
  const supabase = createAdminClient();
  await setTenantContext(supabase, auth.tenantId);
  const { ipAddress, userAgent } = extractRequestContext(req);

  const body = await c.req.json().catch(() => ({}));

  // Require email confirmation for emergency reset
  if (body.confirm_email !== auth.email) {
    throw new HttpError(
      400,
      "Emergency reset requires confirm_email matching your account email",
    );
  }

  const { error } = await supabase
    .from("ip_allowlist")
    .delete()
    .eq("tenant_id", auth.tenantId);

  if (error) throw new HttpError(500, "Failed to reset IP allowlist");

  await logAuditEvent(supabase, {
    tenantId: auth.tenantId,
    actorId: auth.userId,
    actorEmail: auth.email,
    action: "ip_allowlist.emergency_reset",
    resourceType: "ip_allowlist",
    resourceId: auth.tenantId,
    metadata: { reset: true },
    ipAddress,
    userAgent,
  });

  return c.json({ reset: true, message: "All IP allowlist entries removed" });
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
    console.error("Unhandled error in settings:", err);
    return new Response(
      JSON.stringify({ error: "Internal server error" }),
      { status: 500, headers: { "Content-Type": "application/json" } },
    );
  }
});
