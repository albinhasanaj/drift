import { Hono } from "https://deno.land/x/hono@v3.12.0/mod.ts";
import { createAdminClient } from "../shared/supabase.ts";
import { setTenantContext } from "../shared/tenant-context.ts";
import { logAuditEvent, extractRequestContext } from "../shared/audit.ts";
import { hashToken } from "../shared/scim-auth.ts";
import { ScimError } from "../shared/scim-errors.ts";

const app = new Hono();

/**
 * Authenticate a JWT-based request (not SCIM token).
 * Used for token management endpoints — only admin users can manage SCIM tokens.
 *
 * @returns { userId, email, tenantId, role }
 */
async function authenticateJwtRequest(
  req: Request,
): Promise<{
  userId: string;
  email: string;
  tenantId: string;
  role: string;
}> {
  const authHeader = req.headers.get("Authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    throw new ScimError(401, "Missing or invalid Authorization header");
  }

  const jwt = authHeader.slice(7);
  const supabase = createAdminClient();

  // Verify the JWT and get user
  const {
    data: { user },
    error,
  } = await supabase.auth.getUser(jwt);

  if (error || !user) {
    throw new ScimError(401, "Invalid or expired JWT");
  }

  // Get tenant mapping to determine role
  const { data: mappings } = await supabase
    .from("user_tenant_mappings")
    .select("tenant_id, role")
    .eq("user_id", user.id)
    .eq("active", true);

  if (!mappings || mappings.length === 0) {
    throw new ScimError(403, "User not associated with any tenant");
  }

  // Use first active tenant (future: support tenant selection header)
  const mapping = mappings[0];

  return {
    userId: user.id,
    email: user.email ?? "",
    tenantId: mapping.tenant_id,
    role: mapping.role,
  };
}

/**
 * Enforce admin-only access.
 * Only 'owner' and 'admin' roles can manage SCIM tokens.
 */
function requireAdmin(role: string): void {
  if (role !== "owner" && role !== "admin") {
    throw new ScimError(
      403,
      "Only tenant owners and admins can manage SCIM tokens",
    );
  }
}

// ── POST /api/v1/settings/scim — Create SCIM Token ──

app.post("/api/v1/settings/scim", async (c) => {
  const req = c.req.raw;
  const auth = await authenticateJwtRequest(req);
  requireAdmin(auth.role);

  const supabase = createAdminClient();
  await setTenantContext(supabase, auth.tenantId);
  const { ipAddress, userAgent } = extractRequestContext(req);

  const body = await c.req.json();
  const description = body.description ?? "";

  // Generate a secure random token
  const rawToken = crypto.randomUUID() + "-" + crypto.randomUUID();
  const tokenHash = await hashToken(rawToken);

  const { data: token, error } = await supabase
    .from("scim_tokens")
    .insert({
      tenant_id: auth.tenantId,
      token_hash: tokenHash,
      description,
      created_by: auth.userId,
    })
    .select("id, description, created_at")
    .single();

  if (error) {
    console.error("SCIM token creation failed:", error.message);
    throw new ScimError(500, "Failed to create SCIM token");
  }

  await logAuditEvent(supabase, {
    tenantId: auth.tenantId,
    actorId: auth.userId,
    actorEmail: auth.email,
    action: "scim_token.created",
    resourceType: "scim_token",
    resourceId: token.id,
    metadata: { description },
    ipAddress,
    userAgent,
  });

  // Return raw token ONCE — it cannot be retrieved again
  return new Response(
    JSON.stringify({
      id: token.id,
      token: rawToken,
      description: token.description,
      created_at: token.created_at,
      warning:
        "Store this token securely. It cannot be retrieved again after this response.",
    }),
    {
      status: 201,
      headers: { "Content-Type": "application/json" },
    },
  );
});

// ── GET /api/v1/settings/scim — List SCIM Tokens ──

app.get("/api/v1/settings/scim", async (c) => {
  const req = c.req.raw;
  const auth = await authenticateJwtRequest(req);
  requireAdmin(auth.role);

  const supabase = createAdminClient();
  await setTenantContext(supabase, auth.tenantId);

  const { data: tokens, error } = await supabase
    .from("scim_tokens")
    .select("id, description, created_at, revoked_at, last_used_at, created_by")
    .eq("tenant_id", auth.tenantId)
    .order("created_at", { ascending: false });

  if (error) {
    console.error("SCIM token list failed:", error.message);
    throw new ScimError(500, "Failed to list SCIM tokens");
  }

  // Never return raw tokens or hashes
  return new Response(
    JSON.stringify({
      tokens: (tokens ?? []).map((t) => ({
        id: t.id,
        description: t.description,
        created_at: t.created_at,
        revoked_at: t.revoked_at,
        last_used_at: t.last_used_at,
        active: t.revoked_at === null,
      })),
    }),
    {
      status: 200,
      headers: { "Content-Type": "application/json" },
    },
  );
});

// ── DELETE /api/v1/settings/scim/:id — Revoke SCIM Token ──

app.delete("/api/v1/settings/scim/:id", async (c) => {
  const req = c.req.raw;
  const auth = await authenticateJwtRequest(req);
  requireAdmin(auth.role);

  const supabase = createAdminClient();
  await setTenantContext(supabase, auth.tenantId);
  const { ipAddress, userAgent } = extractRequestContext(req);

  const tokenId = c.req.param("id");

  const { data: token, error: fetchErr } = await supabase
    .from("scim_tokens")
    .select("id, revoked_at")
    .eq("id", tokenId)
    .eq("tenant_id", auth.tenantId)
    .single();

  if (fetchErr || !token) {
    throw new ScimError(404, "SCIM token not found");
  }

  if (token.revoked_at) {
    // Already revoked — idempotent
    return new Response(JSON.stringify({ message: "Token already revoked" }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }

  const { error: revokeErr } = await supabase
    .from("scim_tokens")
    .update({ revoked_at: new Date().toISOString() })
    .eq("id", tokenId)
    .eq("tenant_id", auth.tenantId);

  if (revokeErr) {
    console.error("SCIM token revocation failed:", revokeErr.message);
    throw new ScimError(500, "Failed to revoke token");
  }

  await logAuditEvent(supabase, {
    tenantId: auth.tenantId,
    actorId: auth.userId,
    actorEmail: auth.email,
    action: "scim_token.revoked",
    resourceType: "scim_token",
    resourceId: tokenId,
    ipAddress,
    userAgent,
  });

  return new Response(JSON.stringify({ message: "Token revoked" }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
});

// ── Error handling wrapper ──

Deno.serve(async (req) => {
  try {
    return await app.fetch(req);
  } catch (err) {
    if (err instanceof ScimError) {
      return err.toResponse();
    }
    console.error("Unhandled error in scim-admin:", err);
    return new Response(
      JSON.stringify({ error: "Internal server error" }),
      {
        status: 500,
        headers: { "Content-Type": "application/json" },
      },
    );
  }
});
