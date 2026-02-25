// Phase F2: Invitation Flow API (CP0-F-11)
// JWT auth. Create, list, accept (token auth), revoke, resend.

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

// ── POST /api/v1/invitations — Create invitation ──

app.post("/api/v1/invitations", async (c) => {
  const req = c.req.raw;
  const auth = await authenticateJwt(req);
  requireRole(auth, "owner", "admin");
  const supabase = createAdminClient();
  await setTenantContext(supabase, auth.tenantId);
  const { ipAddress, userAgent } = extractRequestContext(req);

  const body = await c.req.json();
  if (!body.email || typeof body.email !== "string") {
    throw new HttpError(400, "email is required");
  }

  // Check seat limit (CP0-F-12 integration)
  const { count: activeMembers } = await supabase
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
  const totalUsed = (activeMembers ?? 0) + (pendingInvites ?? 0);

  if (totalUsed >= seatLimit) {
    throw new HttpError(402, `Seat limit reached (${totalUsed}/${seatLimit}). Upgrade your plan.`);
  }

  // Check for existing pending invitation
  const { data: existingInvite } = await supabase
    .from("invitations")
    .select("id")
    .eq("tenant_id", auth.tenantId)
    .eq("email", body.email)
    .is("accepted_at", null)
    .gt("expires_at", new Date().toISOString())
    .limit(1)
    .single();

  if (existingInvite) {
    throw new HttpError(409, "A pending invitation already exists for this email");
  }

  // Generate unique token
  const token = crypto.randomUUID();

  const { data: invitation, error } = await supabase
    .from("invitations")
    .insert({
      tenant_id: auth.tenantId,
      email: body.email,
      role: body.role ?? "member",
      team_id: body.team_id ?? null,
      invited_by: auth.userId,
      token,
    })
    .select("id, email, role, team_id, expires_at, created_at")
    .single();

  if (error || !invitation) {
    throw new HttpError(500, "Failed to create invitation");
  }

  await logAuditEvent(supabase, {
    tenantId: auth.tenantId,
    actorId: auth.userId,
    actorEmail: auth.email,
    action: "invitation.created",
    resourceType: "invitation",
    resourceId: invitation.id,
    metadata: { email: body.email, role: body.role ?? "member" },
    ipAddress,
    userAgent,
  });

  return c.json(invitation, 201);
});

// ── GET /api/v1/invitations — List pending invitations ──

app.get("/api/v1/invitations", async (c) => {
  const auth = await authenticateJwt(c.req.raw);
  requireRole(auth, "owner", "admin");
  const supabase = createAdminClient();
  await setTenantContext(supabase, auth.tenantId);

  const { data: invitations, error } = await supabase
    .from("invitations")
    .select("id, email, role, team_id, expires_at, accepted_at, created_at")
    .eq("tenant_id", auth.tenantId)
    .order("created_at", { ascending: false });

  if (error) throw new HttpError(500, "Failed to list invitations");
  return c.json({ data: invitations ?? [] });
});

// ── POST /api/v1/invitations/:token/accept — Accept invitation (public, token auth) ──

app.post("/api/v1/invitations/:token/accept", async (c) => {
  const inviteToken = c.req.param("token");
  const supabase = createAdminClient();

  // Lookup invitation by token (no tenant context needed — token is unique)
  const { data: invitation, error } = await supabase
    .from("invitations")
    .select("id, tenant_id, email, role, team_id, expires_at, accepted_at")
    .eq("token", inviteToken)
    .single();

  if (error || !invitation) {
    throw new HttpError(404, "Invitation not found");
  }

  // Check not already accepted
  if (invitation.accepted_at) {
    throw new HttpError(410, "Invitation has already been accepted");
  }

  // Check not expired
  if (new Date(invitation.expires_at) < new Date()) {
    throw new HttpError(410, "Invitation has expired");
  }

  // Set tenant context for further operations
  await setTenantContext(supabase, invitation.tenant_id);

  // Check if user exists by email
  const { data: existingUsers } = await supabase.auth.admin.listUsers();
  const existingUser = existingUsers?.users?.find(
    (u) => u.email === invitation.email,
  );

  let userId: string;

  if (existingUser) {
    userId = existingUser.id;
  } else {
    // Create user
    const { data: newUser, error: createErr } =
      await supabase.auth.admin.createUser({
        email: invitation.email,
        email_confirm: true,
      });
    if (createErr || !newUser?.user) {
      throw new HttpError(500, "Failed to create user account");
    }
    userId = newUser.user.id;
  }

  // Add user to tenant
  await supabase.from("user_tenant_mappings").upsert({
    user_id: userId,
    tenant_id: invitation.tenant_id,
    role: invitation.role,
    active: true,
  });

  // Add to team if specified
  if (invitation.team_id) {
    await supabase.from("team_memberships").upsert({
      team_id: invitation.team_id,
      user_id: userId,
      role: "member",
    });
  }

  // Mark invitation as accepted
  await supabase
    .from("invitations")
    .update({ accepted_at: new Date().toISOString() })
    .eq("id", invitation.id);

  await logAuditEvent(supabase, {
    tenantId: invitation.tenant_id,
    actorId: userId,
    actorEmail: invitation.email,
    action: "invitation.accepted",
    resourceType: "invitation",
    resourceId: invitation.id,
    metadata: { role: invitation.role, team_id: invitation.team_id },
  });

  return c.json({
    accepted: true,
    tenant_id: invitation.tenant_id,
    role: invitation.role,
    user_id: userId,
  });
});

// ── DELETE /api/v1/invitations/:id — Revoke invitation ──

app.delete("/api/v1/invitations/:id", async (c) => {
  const req = c.req.raw;
  const auth = await authenticateJwt(req);
  requireRole(auth, "owner", "admin");
  const supabase = createAdminClient();
  await setTenantContext(supabase, auth.tenantId);
  const { ipAddress, userAgent } = extractRequestContext(req);

  const invitationId = c.req.param("id");

  const { data: existing } = await supabase
    .from("invitations")
    .select("id, email")
    .eq("id", invitationId)
    .eq("tenant_id", auth.tenantId)
    .single();

  if (!existing) throw new HttpError(404, "Invitation not found");

  const { error } = await supabase
    .from("invitations")
    .delete()
    .eq("id", invitationId);

  if (error) throw new HttpError(500, "Failed to revoke invitation");

  await logAuditEvent(supabase, {
    tenantId: auth.tenantId,
    actorId: auth.userId,
    actorEmail: auth.email,
    action: "invitation.revoked",
    resourceType: "invitation",
    resourceId: invitationId,
    metadata: { email: existing.email },
    ipAddress,
    userAgent,
  });

  return c.json({ revoked: true });
});

// ── POST /api/v1/invitations/:id/resend — Resend invitation ──

app.post("/api/v1/invitations/:id/resend", async (c) => {
  const req = c.req.raw;
  const auth = await authenticateJwt(req);
  requireRole(auth, "owner", "admin");
  const supabase = createAdminClient();
  await setTenantContext(supabase, auth.tenantId);
  const { ipAddress, userAgent } = extractRequestContext(req);

  const invitationId = c.req.param("id");

  const { data: existing } = await supabase
    .from("invitations")
    .select("id, email, accepted_at")
    .eq("id", invitationId)
    .eq("tenant_id", auth.tenantId)
    .single();

  if (!existing) throw new HttpError(404, "Invitation not found");
  if (existing.accepted_at) throw new HttpError(410, "Invitation already accepted");

  // Reset expiration
  await supabase
    .from("invitations")
    .update({
      expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
    })
    .eq("id", invitationId);

  await logAuditEvent(supabase, {
    tenantId: auth.tenantId,
    actorId: auth.userId,
    actorEmail: auth.email,
    action: "invitation.resent",
    resourceType: "invitation",
    resourceId: invitationId,
    metadata: { email: existing.email },
    ipAddress,
    userAgent,
  });

  // NOTE: Actual email sending would be done via Resend/Postmark integration.
  // For now, the invitation token-based accept flow still works.
  return c.json({ resent: true });
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
    console.error("Unhandled error in invitations:", err);
    return new Response(
      JSON.stringify({ error: "Internal server error" }),
      { status: 500, headers: { "Content-Type": "application/json" } },
    );
  }
});
