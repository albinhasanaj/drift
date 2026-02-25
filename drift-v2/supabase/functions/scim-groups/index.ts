import { Hono } from "https://deno.land/x/hono@v3.12.0/mod.ts";
import { createAdminClient } from "../shared/supabase.ts";
import { authenticateScimRequest } from "../shared/scim-auth.ts";
import { setTenantContext } from "../shared/tenant-context.ts";
import { logAuditEvent, extractRequestContext } from "../shared/audit.ts";
import {
  ScimError,
  invalidSyntax,
  invalidValue,
  invalidPath,
  notFound,
  scimResponse,
  createdResponse,
  noContentResponse,
} from "../shared/scim-errors.ts";
import {
  SCIM_SCHEMAS,
  buildScimGroup,
  buildListResponse,
  type ScimGroupMember,
  type ScimPatchRequest,
  type ScimPatchOperation,
  type ScimGroup,
} from "../shared/scim-types.ts";

const app = new Hono();

function getBaseUrl(req: Request): string {
  const url = new URL(req.url);
  return `${url.protocol}//${url.host}`;
}

/**
 * Resolve IdP group name to Drift role via scim_group_mappings.
 * Default: 'member' if no mapping exists.
 */
async function resolveGroupRole(
  supabase: ReturnType<typeof createAdminClient>,
  tenantId: string,
  groupName: string,
): Promise<string> {
  const { data } = await supabase
    .from("scim_group_mappings")
    .select("drift_role")
    .eq("tenant_id", tenantId)
    .ilike("idp_group_name", groupName)
    .single();
  return data?.drift_role ?? "member";
}

/**
 * Load group members from team_memberships, enriched with user display names.
 */
async function loadGroupMembers(
  supabase: ReturnType<typeof createAdminClient>,
  teamId: string,
  baseUrl: string,
): Promise<ScimGroupMember[]> {
  const { data: memberships } = await supabase
    .from("team_memberships")
    .select("user_id")
    .eq("team_id", teamId);

  if (!memberships || memberships.length === 0) return [];

  const members: ScimGroupMember[] = [];
  for (const m of memberships) {
    const { data: userData } = await supabase.auth.admin.getUserById(
      m.user_id,
    );
    members.push({
      value: m.user_id,
      display:
        userData?.user?.user_metadata?.display_name ??
        userData?.user?.email ??
        "",
      $ref: `${baseUrl}/scim/v2/Users/${m.user_id}`,
    });
  }
  return members;
}

// ── POST /scim/v2/Groups — Create Group (CP0-D-08) ──

app.post("/scim/v2/Groups", async (c) => {
  const req = c.req.raw;
  const auth = await authenticateScimRequest(req);
  const supabase = createAdminClient();
  await setTenantContext(supabase, auth.tenantId);
  const { ipAddress, userAgent } = extractRequestContext(req);

  const body = await c.req.json();

  if (!body.schemas || !body.schemas.includes(SCIM_SCHEMAS.GROUP)) {
    throw invalidSyntax("Request must include Group schema");
  }

  if (!body.displayName || typeof body.displayName !== "string") {
    throw invalidValue("displayName is required");
  }

  const now = new Date().toISOString();

  // Create team
  const { data: team, error: teamErr } = await supabase
    .from("teams")
    .insert({
      tenant_id: auth.tenantId,
      name: body.displayName,
      description: `SCIM-provisioned group`,
      scim_external_id: body.externalId ?? null,
    })
    .select("id, created_at")
    .single();

  if (teamErr) {
    if (teamErr.message?.includes("duplicate") || teamErr.code === "23505") {
      throw new ScimError(
        409,
        `Group '${body.displayName}' already exists in this tenant.`,
        "uniqueness",
      );
    }
    console.error("Team creation failed:", teamErr.message);
    throw new ScimError(500, "Failed to create group");
  }

  // Add initial members if provided
  const members: ScimGroupMember[] = [];
  if (body.members && Array.isArray(body.members)) {
    for (const member of body.members) {
      if (!member.value) continue;

      // Verify user belongs to tenant
      const { data: mapping } = await supabase
        .from("user_tenant_mappings")
        .select("user_id")
        .eq("user_id", member.value)
        .eq("tenant_id", auth.tenantId)
        .single();

      if (!mapping) continue; // Silently skip users not in tenant

      const role = await resolveGroupRole(
        supabase,
        auth.tenantId,
        body.displayName,
      );

      await supabase.from("team_memberships").insert({
        team_id: team.id,
        user_id: member.value,
        role: role === "lead" || role === "member" ? role : "member",
      });

      const { data: userData } = await supabase.auth.admin.getUserById(
        member.value,
      );
      members.push({
        value: member.value,
        display:
          userData?.user?.user_metadata?.display_name ??
          userData?.user?.email ??
          "",
        $ref: `${getBaseUrl(req)}/scim/v2/Users/${member.value}`,
      });
    }
  }

  await logAuditEvent(supabase, {
    tenantId: auth.tenantId,
    actorId: auth.tokenId,
    actorEmail: "scim-token",
    action: "group.created",
    resourceType: "team",
    resourceId: team.id,
    metadata: {
      displayName: body.displayName,
      memberCount: members.length,
    },
    ipAddress,
    userAgent,
  });

  return createdResponse(
    buildScimGroup({
      id: team.id,
      displayName: body.displayName,
      members,
      createdAt: team.created_at ?? now,
      lastModified: team.created_at ?? now,
      baseUrl: getBaseUrl(req),
    }),
    `${getBaseUrl(req)}/scim/v2/Groups/${team.id}`,
  );
});

// ── GET /scim/v2/Groups — List Groups ──

app.get("/scim/v2/Groups", async (c) => {
  const req = c.req.raw;
  const auth = await authenticateScimRequest(req);
  const supabase = createAdminClient();
  await setTenantContext(supabase, auth.tenantId);

  const startIndex = Math.max(1, parseInt(c.req.query("startIndex") ?? "1"));
  const count = Math.min(
    200,
    Math.max(1, parseInt(c.req.query("count") ?? "100")),
  );
  const offset = startIndex - 1;

  const { data: teams, count: totalCount, error } = await supabase
    .from("teams")
    .select("id, name, created_at, scim_external_id", { count: "exact" })
    .eq("tenant_id", auth.tenantId)
    .order("created_at", { ascending: true })
    .range(offset, offset + count - 1);

  if (error) {
    console.error("Teams query failed:", error.message);
    throw new ScimError(500, "Failed to query groups");
  }

  const groups: ScimGroup[] = [];
  for (const team of teams ?? []) {
    const members = await loadGroupMembers(
      supabase,
      team.id,
      getBaseUrl(req),
    );
    groups.push(
      buildScimGroup({
        id: team.id,
        displayName: team.name,
        members,
        createdAt: team.created_at,
        lastModified: team.created_at,
        baseUrl: getBaseUrl(req),
      }),
    );
  }

  return scimResponse(
    buildListResponse({
      resources: groups,
      totalResults: totalCount ?? 0,
      startIndex,
      itemsPerPage: groups.length,
    }),
  );
});

// ── GET /scim/v2/Groups/:id — Get Single Group ──

app.get("/scim/v2/Groups/:id", async (c) => {
  const req = c.req.raw;
  const auth = await authenticateScimRequest(req);
  const supabase = createAdminClient();
  await setTenantContext(supabase, auth.tenantId);

  const teamId = c.req.param("id");

  const { data: team, error } = await supabase
    .from("teams")
    .select("id, name, created_at")
    .eq("id", teamId)
    .eq("tenant_id", auth.tenantId)
    .single();

  if (error || !team) {
    throw notFound();
  }

  const members = await loadGroupMembers(supabase, team.id, getBaseUrl(req));

  return scimResponse(
    buildScimGroup({
      id: team.id,
      displayName: team.name,
      members,
      createdAt: team.created_at,
      lastModified: team.created_at,
      baseUrl: getBaseUrl(req),
    }),
  );
});

// ── PATCH /scim/v2/Groups/:id — Update Group (CP0-D-09) ──

app.patch("/scim/v2/Groups/:id", async (c) => {
  const req = c.req.raw;
  const auth = await authenticateScimRequest(req);
  const supabase = createAdminClient();
  await setTenantContext(supabase, auth.tenantId);
  const { ipAddress, userAgent } = extractRequestContext(req);

  const teamId = c.req.param("id");
  const body: ScimPatchRequest = await c.req.json();

  if (!body.schemas || !body.schemas.includes(SCIM_SCHEMAS.PATCH_OP)) {
    throw invalidSyntax("Request must include PatchOp schema");
  }

  // Verify group belongs to tenant
  const { data: team, error: teamErr } = await supabase
    .from("teams")
    .select("id, name")
    .eq("id", teamId)
    .eq("tenant_id", auth.tenantId)
    .single();

  if (teamErr || !team) {
    throw notFound();
  }

  for (const op of body.Operations) {
    validateGroupPatchOp(op);

    if (op.path === "displayName" && op.op === "replace") {
      await supabase
        .from("teams")
        .update({ name: op.value as string })
        .eq("id", teamId)
        .eq("tenant_id", auth.tenantId);
    } else if (op.path === "members" && op.op === "add") {
      const membersToAdd = Array.isArray(op.value)
        ? op.value
        : [op.value];
      for (const member of membersToAdd) {
        const userId =
          typeof member === "string" ? member : member?.value;
        if (!userId) continue;

        // Verify user belongs to tenant
        const { data: mapping } = await supabase
          .from("user_tenant_mappings")
          .select("user_id")
          .eq("user_id", userId)
          .eq("tenant_id", auth.tenantId)
          .single();

        if (!mapping) continue; // Silently skip users not in tenant

        const role = await resolveGroupRole(
          supabase,
          auth.tenantId,
          team.name,
        );

        // Upsert membership (idempotent)
        await supabase.from("team_memberships").upsert(
          {
            team_id: teamId,
            user_id: userId,
            role: role === "lead" || role === "member" ? role : "member",
          },
          { onConflict: "team_id,user_id" },
        );
      }
    } else if (op.path?.startsWith("members") && op.op === "remove") {
      // Parse path: members[value eq "user-uuid"]
      const match = op.path.match(
        /members\[value\s+eq\s+"([^"]+)"\]/,
      );
      if (match) {
        await supabase
          .from("team_memberships")
          .delete()
          .eq("team_id", teamId)
          .eq("user_id", match[1]);
      }
    } else if (op.path === "members" && op.op === "remove") {
      // Remove specific members from value
      const membersToRemove = Array.isArray(op.value)
        ? op.value
        : op.value
          ? [op.value]
          : [];
      for (const member of membersToRemove) {
        const userId =
          typeof member === "string" ? member : member?.value;
        if (!userId) continue;
        await supabase
          .from("team_memberships")
          .delete()
          .eq("team_id", teamId)
          .eq("user_id", userId);
      }
    }
  }

  await logAuditEvent(supabase, {
    tenantId: auth.tenantId,
    actorId: auth.tokenId,
    actorEmail: "scim-token",
    action: "group.updated",
    resourceType: "team",
    resourceId: teamId,
    metadata: {
      operations: body.Operations.map((o) => ({
        op: o.op,
        path: o.path,
      })),
    },
    ipAddress,
    userAgent,
  });

  // Return updated group
  const { data: updatedTeam } = await supabase
    .from("teams")
    .select("id, name, created_at")
    .eq("id", teamId)
    .eq("tenant_id", auth.tenantId)
    .single();

  if (!updatedTeam) throw notFound();

  const members = await loadGroupMembers(
    supabase,
    updatedTeam.id,
    getBaseUrl(req),
  );

  return scimResponse(
    buildScimGroup({
      id: updatedTeam.id,
      displayName: updatedTeam.name,
      members,
      createdAt: updatedTeam.created_at,
      lastModified: new Date().toISOString(),
      baseUrl: getBaseUrl(req),
    }),
  );
});

// ── DELETE /scim/v2/Groups/:id — Delete Group ──

app.delete("/scim/v2/Groups/:id", async (c) => {
  const req = c.req.raw;
  const auth = await authenticateScimRequest(req);
  const supabase = createAdminClient();
  await setTenantContext(supabase, auth.tenantId);
  const { ipAddress, userAgent } = extractRequestContext(req);

  const teamId = c.req.param("id");

  const { data: team, error } = await supabase
    .from("teams")
    .select("id, name")
    .eq("id", teamId)
    .eq("tenant_id", auth.tenantId)
    .single();

  if (error || !team) {
    throw notFound();
  }

  // Delete team (CASCADE deletes team_memberships)
  await supabase
    .from("teams")
    .delete()
    .eq("id", teamId)
    .eq("tenant_id", auth.tenantId);

  await logAuditEvent(supabase, {
    tenantId: auth.tenantId,
    actorId: auth.tokenId,
    actorEmail: "scim-token",
    action: "group.deleted",
    resourceType: "team",
    resourceId: teamId,
    metadata: { displayName: team.name },
    ipAddress,
    userAgent,
  });

  return noContentResponse();
});

// ── Helpers ──

function validateGroupPatchOp(op: ScimPatchOperation): void {
  const validOps = ["add", "remove", "replace"];
  if (!validOps.includes(op.op)) {
    throw invalidValue(
      `Unsupported operation: '${op.op}'. Supported: ${validOps.join(", ")}`,
    );
  }

  const validPaths = ["displayName", "members"];
  if (
    op.path &&
    !validPaths.some((p) => op.path!.startsWith(p))
  ) {
    throw invalidPath(
      `Unsupported path: '${op.path}'. Supported: ${validPaths.join(", ")}`,
    );
  }
}

// ── Error handling wrapper ──

Deno.serve(async (req) => {
  try {
    return await app.fetch(req);
  } catch (err) {
    if (err instanceof ScimError) {
      return err.toResponse();
    }
    console.error("Unhandled error in scim-groups:", err);
    return new ScimError(500, "Internal server error").toResponse();
  }
});
