// Phase F2: Team CRUD + Membership + Project Assignment API
// (CP0-F-08, CP0-F-09, CP0-F-10)
// JWT auth. Admin/owner for mutations, any member for reads.

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

// ── POST /api/v1/teams — Create team (CP0-F-08) ──

app.post("/api/v1/teams", async (c) => {
  const req = c.req.raw;
  const auth = await authenticateJwt(req);
  requireRole(auth, "owner", "admin");
  const supabase = createAdminClient();
  await setTenantContext(supabase, auth.tenantId);
  const { ipAddress, userAgent } = extractRequestContext(req);

  const body = await c.req.json();
  if (!body.name || typeof body.name !== "string") {
    throw new HttpError(400, "name is required");
  }

  const { data: team, error } = await supabase
    .from("teams")
    .insert({
      tenant_id: auth.tenantId,
      name: body.name,
      description: body.description ?? null,
    })
    .select("id, name, description, created_at")
    .single();

  if (error || !team) {
    if (error?.code === "23505") throw new HttpError(409, "Team name already exists");
    throw new HttpError(500, "Failed to create team");
  }

  await logAuditEvent(supabase, {
    tenantId: auth.tenantId,
    actorId: auth.userId,
    actorEmail: auth.email,
    action: "team.created",
    resourceType: "team",
    resourceId: team.id,
    metadata: { name: body.name },
    ipAddress,
    userAgent,
  });

  return c.json(team, 201);
});

// ── GET /api/v1/teams — List teams ──

app.get("/api/v1/teams", async (c) => {
  const auth = await authenticateJwt(c.req.raw);
  const supabase = createAdminClient();
  await setTenantContext(supabase, auth.tenantId);

  const { data: teams, error } = await supabase
    .from("teams")
    .select("id, name, description, created_at")
    .eq("tenant_id", auth.tenantId)
    .order("name");

  if (error) throw new HttpError(500, "Failed to list teams");
  return c.json({ data: teams ?? [] });
});

// ── GET /api/v1/teams/:id — Team details + members ──

app.get("/api/v1/teams/:id", async (c) => {
  const auth = await authenticateJwt(c.req.raw);
  const supabase = createAdminClient();
  await setTenantContext(supabase, auth.tenantId);

  const teamId = c.req.param("id");
  const { data: team, error } = await supabase
    .from("teams")
    .select("id, name, description, created_at")
    .eq("id", teamId)
    .single();

  if (error || !team) throw new HttpError(404, "Team not found");

  const { data: members } = await supabase
    .from("team_memberships")
    .select("user_id, role, created_at")
    .eq("team_id", teamId);

  const { data: projects } = await supabase
    .from("team_projects")
    .select("project_id, assigned_by, assigned_at")
    .eq("team_id", teamId);

  return c.json({ ...team, members: members ?? [], projects: projects ?? [] });
});

// ── PATCH /api/v1/teams/:id — Update team ──

app.patch("/api/v1/teams/:id", async (c) => {
  const req = c.req.raw;
  const auth = await authenticateJwt(req);
  requireRole(auth, "owner", "admin");
  const supabase = createAdminClient();
  await setTenantContext(supabase, auth.tenantId);
  const { ipAddress, userAgent } = extractRequestContext(req);

  const teamId = c.req.param("id");
  const body = await c.req.json();

  const updates: Record<string, unknown> = {};
  if (body.name !== undefined) updates.name = body.name;
  if (body.description !== undefined) updates.description = body.description;

  const { data: updated, error } = await supabase
    .from("teams")
    .update(updates)
    .eq("id", teamId)
    .select("id, name, description, created_at")
    .single();

  if (error || !updated) throw new HttpError(404, "Team not found");

  await logAuditEvent(supabase, {
    tenantId: auth.tenantId,
    actorId: auth.userId,
    actorEmail: auth.email,
    action: "team.updated",
    resourceType: "team",
    resourceId: teamId,
    metadata: updates,
    ipAddress,
    userAgent,
  });

  return c.json(updated);
});

// ── DELETE /api/v1/teams/:id — Delete team ──

app.delete("/api/v1/teams/:id", async (c) => {
  const req = c.req.raw;
  const auth = await authenticateJwt(req);
  requireRole(auth, "owner", "admin");
  const supabase = createAdminClient();
  await setTenantContext(supabase, auth.tenantId);
  const { ipAddress, userAgent } = extractRequestContext(req);

  const teamId = c.req.param("id");

  const { data: existing } = await supabase
    .from("teams")
    .select("id, name")
    .eq("id", teamId)
    .single();
  if (!existing) throw new HttpError(404, "Team not found");

  const { error } = await supabase.from("teams").delete().eq("id", teamId);
  if (error) throw new HttpError(500, "Failed to delete team");

  await logAuditEvent(supabase, {
    tenantId: auth.tenantId,
    actorId: auth.userId,
    actorEmail: auth.email,
    action: "team.deleted",
    resourceType: "team",
    resourceId: teamId,
    metadata: { name: existing.name },
    ipAddress,
    userAgent,
  });

  return c.json({ deleted: true });
});

// ── POST /api/v1/teams/:id/members — Add member (CP0-F-09) ──

app.post("/api/v1/teams/:id/members", async (c) => {
  const req = c.req.raw;
  const auth = await authenticateJwt(req);
  requireRole(auth, "owner", "admin");
  const supabase = createAdminClient();
  await setTenantContext(supabase, auth.tenantId);
  const { ipAddress, userAgent } = extractRequestContext(req);

  const teamId = c.req.param("id");
  const body = await c.req.json();

  if (!body.user_id) throw new HttpError(400, "user_id is required");

  const { error } = await supabase.from("team_memberships").insert({
    team_id: teamId,
    user_id: body.user_id,
    role: body.role ?? "member",
  });

  if (error) {
    if (error.code === "23505") throw new HttpError(409, "User is already a member");
    if (error.code === "23503") throw new HttpError(404, "Team or user not found");
    throw new HttpError(500, "Failed to add member");
  }

  await logAuditEvent(supabase, {
    tenantId: auth.tenantId,
    actorId: auth.userId,
    actorEmail: auth.email,
    action: "team.member_added",
    resourceType: "team_membership",
    resourceId: teamId,
    metadata: { user_id: body.user_id, role: body.role ?? "member" },
    ipAddress,
    userAgent,
  });

  return c.json({ added: true }, 201);
});

// ── GET /api/v1/teams/:id/members — List members ──

app.get("/api/v1/teams/:id/members", async (c) => {
  const auth = await authenticateJwt(c.req.raw);
  const supabase = createAdminClient();
  await setTenantContext(supabase, auth.tenantId);

  const teamId = c.req.param("id");
  const { data: members, error } = await supabase
    .from("team_memberships")
    .select("user_id, role, created_at")
    .eq("team_id", teamId);

  if (error) throw new HttpError(500, "Failed to list members");
  return c.json({ data: members ?? [] });
});

// ── PATCH /api/v1/teams/:id/members/:user_id — Change role ──

app.patch("/api/v1/teams/:id/members/:user_id", async (c) => {
  const req = c.req.raw;
  const auth = await authenticateJwt(req);
  requireRole(auth, "owner", "admin");
  const supabase = createAdminClient();
  await setTenantContext(supabase, auth.tenantId);
  const { ipAddress, userAgent } = extractRequestContext(req);

  const teamId = c.req.param("id");
  const userId = c.req.param("user_id");
  const body = await c.req.json();

  if (!body.role) throw new HttpError(400, "role is required");

  const { error } = await supabase
    .from("team_memberships")
    .update({ role: body.role })
    .eq("team_id", teamId)
    .eq("user_id", userId);

  if (error) throw new HttpError(500, "Failed to update role");

  await logAuditEvent(supabase, {
    tenantId: auth.tenantId,
    actorId: auth.userId,
    actorEmail: auth.email,
    action: "team.member_role_changed",
    resourceType: "team_membership",
    resourceId: teamId,
    metadata: { user_id: userId, new_role: body.role },
    ipAddress,
    userAgent,
  });

  return c.json({ updated: true });
});

// ── DELETE /api/v1/teams/:id/members/:user_id — Remove member ──

app.delete("/api/v1/teams/:id/members/:user_id", async (c) => {
  const req = c.req.raw;
  const auth = await authenticateJwt(req);
  requireRole(auth, "owner", "admin");
  const supabase = createAdminClient();
  await setTenantContext(supabase, auth.tenantId);
  const { ipAddress, userAgent } = extractRequestContext(req);

  const teamId = c.req.param("id");
  const userId = c.req.param("user_id");

  const { error } = await supabase
    .from("team_memberships")
    .delete()
    .eq("team_id", teamId)
    .eq("user_id", userId);

  if (error) throw new HttpError(500, "Failed to remove member");

  await logAuditEvent(supabase, {
    tenantId: auth.tenantId,
    actorId: auth.userId,
    actorEmail: auth.email,
    action: "team.member_removed",
    resourceType: "team_membership",
    resourceId: teamId,
    metadata: { user_id: userId },
    ipAddress,
    userAgent,
  });

  return c.json({ removed: true });
});

// ── POST /api/v1/teams/:id/projects — Assign project (CP0-F-10) ──

app.post("/api/v1/teams/:id/projects", async (c) => {
  const req = c.req.raw;
  const auth = await authenticateJwt(req);
  requireRole(auth, "owner", "admin");
  const supabase = createAdminClient();
  await setTenantContext(supabase, auth.tenantId);
  const { ipAddress, userAgent } = extractRequestContext(req);

  const teamId = c.req.param("id");
  const body = await c.req.json();

  if (!body.project_id) throw new HttpError(400, "project_id is required");

  const { error } = await supabase.from("team_projects").insert({
    team_id: teamId,
    project_id: body.project_id,
    assigned_by: auth.userId,
  });

  if (error) {
    if (error.code === "23505") throw new HttpError(409, "Project already assigned");
    if (error.code === "23503") throw new HttpError(404, "Team or project not found");
    throw new HttpError(500, "Failed to assign project");
  }

  await logAuditEvent(supabase, {
    tenantId: auth.tenantId,
    actorId: auth.userId,
    actorEmail: auth.email,
    action: "team.project_assigned",
    resourceType: "team_project",
    resourceId: teamId,
    metadata: { project_id: body.project_id },
    ipAddress,
    userAgent,
  });

  return c.json({ assigned: true }, 201);
});

// ── GET /api/v1/teams/:id/projects — List assigned projects ──

app.get("/api/v1/teams/:id/projects", async (c) => {
  const auth = await authenticateJwt(c.req.raw);
  const supabase = createAdminClient();
  await setTenantContext(supabase, auth.tenantId);

  const teamId = c.req.param("id");
  const { data: projects, error } = await supabase
    .from("team_projects")
    .select("project_id, assigned_by, assigned_at")
    .eq("team_id", teamId);

  if (error) throw new HttpError(500, "Failed to list projects");
  return c.json({ data: projects ?? [] });
});

// ── DELETE /api/v1/teams/:id/projects/:project_id — Unassign project ──

app.delete("/api/v1/teams/:id/projects/:project_id", async (c) => {
  const req = c.req.raw;
  const auth = await authenticateJwt(req);
  requireRole(auth, "owner", "admin");
  const supabase = createAdminClient();
  await setTenantContext(supabase, auth.tenantId);
  const { ipAddress, userAgent } = extractRequestContext(req);

  const teamId = c.req.param("id");
  const projectId = c.req.param("project_id");

  const { error } = await supabase
    .from("team_projects")
    .delete()
    .eq("team_id", teamId)
    .eq("project_id", projectId);

  if (error) throw new HttpError(500, "Failed to unassign project");

  await logAuditEvent(supabase, {
    tenantId: auth.tenantId,
    actorId: auth.userId,
    actorEmail: auth.email,
    action: "team.project_unassigned",
    resourceType: "team_project",
    resourceId: teamId,
    metadata: { project_id: projectId },
    ipAddress,
    userAgent,
  });

  return c.json({ unassigned: true });
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
    console.error("Unhandled error in teams:", err);
    return new Response(
      JSON.stringify({ error: "Internal server error" }),
      { status: 500, headers: { "Content-Type": "application/json" } },
    );
  }
});
