import { Hono } from "https://deno.land/x/hono@v3.12.0/mod.ts";
import { createAdminClient } from "../shared/supabase.ts";
import { authenticateScimRequest } from "../shared/scim-auth.ts";
import { setTenantContext } from "../shared/tenant-context.ts";
import { logAuditEvent, extractRequestContext } from "../shared/audit.ts";
import { deprovisionUser, reprovisionUser } from "../shared/deprovision.ts";
import {
  ScimError,
  invalidSyntax,
  invalidValue,
  invalidPath,
  uniquenessConflict,
  notFound,
  scimResponse,
  createdResponse,
  noContentResponse,
} from "../shared/scim-errors.ts";
import {
  SCIM_SCHEMAS,
  buildScimUser,
  buildListResponse,
  parseScimFilter,
  type ScimPatchRequest,
  type ScimPatchOperation,
  type ScimUser,
} from "../shared/scim-types.ts";

const app = new Hono();

/** Get the base URL for Location headers */
function getBaseUrl(req: Request): string {
  const url = new URL(req.url);
  return `${url.protocol}//${url.host}`;
}

// ── POST /scim/v2/Users — Create User (CP0-D-03) ──

app.post("/scim/v2/Users", async (c) => {
  const req = c.req.raw;
  const auth = await authenticateScimRequest(req);
  const supabase = createAdminClient();
  await setTenantContext(supabase, auth.tenantId);
  const { ipAddress, userAgent } = extractRequestContext(req);

  const body = await c.req.json();

  // Validate schemas
  if (
    !body.schemas ||
    !body.schemas.includes(SCIM_SCHEMAS.USER)
  ) {
    throw invalidSyntax("Request must include User schema");
  }

  // Validate required fields
  const userName = body.userName;
  if (!userName || typeof userName !== "string") {
    throw invalidValue("userName is required and must be a string");
  }

  const emails = body.emails;
  if (!emails || !Array.isArray(emails) || emails.length === 0) {
    throw invalidValue("At least one email is required");
  }
  const primaryEmail =
    emails.find((e: { primary?: boolean }) => e.primary)?.value ??
    emails[0]?.value;
  if (!primaryEmail) {
    throw invalidValue("Email value is required");
  }

  // Check uniqueness within tenant
  const { data: existing } = await supabase
    .from("user_tenant_mappings")
    .select("user_id")
    .eq("tenant_id", auth.tenantId)
    .or(
      `scim_external_id.eq.${body.externalId ?? ""},user_id.in.(select user_id from auth.users where email = '${primaryEmail}')`,
    )
    .limit(1);

  // Simpler uniqueness check: query by email via admin API
  const { data: existingUsers } = await supabase.auth.admin.listUsers({
    page: 1,
    perPage: 1,
  });

  // Check if user with this email already exists in this tenant
  const { data: existingMapping } = await supabase
    .from("user_tenant_mappings")
    .select("user_id")
    .eq("tenant_id", auth.tenantId)
    .limit(1000);

  if (existingMapping) {
    for (const mapping of existingMapping) {
      const { data: userData } = await supabase.auth.admin.getUserById(
        mapping.user_id,
      );
      if (userData?.user?.email === primaryEmail) {
        throw uniquenessConflict(
          `User with userName '${primaryEmail}' already exists in this tenant.`,
        );
      }
    }
  }

  // Create Supabase Auth user
  const { data: authUser, error: authErr } =
    await supabase.auth.admin.createUser({
      email: primaryEmail,
      email_confirm: true,
      user_metadata: {
        given_name: body.name?.givenName ?? "",
        family_name: body.name?.familyName ?? "",
        display_name:
          body.displayName ??
          [body.name?.givenName, body.name?.familyName]
            .filter(Boolean)
            .join(" ") ??
          "",
        scim_external_id: body.externalId,
      },
    });

  if (authErr || !authUser?.user) {
    if (authErr?.message?.includes("already been registered")) {
      throw uniquenessConflict(
        `User with userName '${primaryEmail}' already exists.`,
      );
    }
    console.error("Auth user creation failed:", authErr?.message);
    throw new ScimError(500, "Failed to create user");
  }

  const userId = authUser.user.id;
  const now = new Date().toISOString();

  // Insert user_tenant_mappings row
  const { error: mappingErr } = await supabase
    .from("user_tenant_mappings")
    .insert({
      user_id: userId,
      tenant_id: auth.tenantId,
      role: "member",
      active: true,
      scim_external_id: body.externalId ?? null,
    });

  if (mappingErr) {
    // Rollback: delete the auth user
    await supabase.auth.admin.deleteUser(userId);
    console.error("Mapping insert failed:", mappingErr.message);
    throw new ScimError(500, "Failed to create user mapping");
  }

  // Audit log
  await logAuditEvent(supabase, {
    tenantId: auth.tenantId,
    actorId: auth.tokenId,
    actorEmail: "scim-token",
    action: "user.provisioned",
    resourceType: "user",
    resourceId: userId,
    metadata: { userName: primaryEmail, externalId: body.externalId },
    ipAddress,
    userAgent,
  });

  const scimUser = buildScimUser({
    id: userId,
    userName: primaryEmail,
    externalId: body.externalId,
    givenName: body.name?.givenName,
    familyName: body.name?.familyName,
    displayName: body.displayName,
    email: primaryEmail,
    active: true,
    createdAt: now,
    lastModified: now,
    baseUrl: getBaseUrl(req),
  });

  return createdResponse(
    scimUser,
    `${getBaseUrl(req)}/scim/v2/Users/${userId}`,
  );
});

// ── GET /scim/v2/Users — List/Filter (CP0-D-04) ──

app.get("/scim/v2/Users", async (c) => {
  const req = c.req.raw;
  const auth = await authenticateScimRequest(req);
  const supabase = createAdminClient();
  await setTenantContext(supabase, auth.tenantId);

  // Parse pagination (SCIM uses 1-based startIndex)
  const startIndex = Math.max(1, parseInt(c.req.query("startIndex") ?? "1"));
  const count = Math.min(200, Math.max(1, parseInt(c.req.query("count") ?? "100")));
  const filterStr = c.req.query("filter") ?? null;

  const filter = parseScimFilter(filterStr);

  // Get all mappings for this tenant
  let query = supabase
    .from("user_tenant_mappings")
    .select("user_id, role, active, scim_external_id, created_at, deprovisioned_at", { count: "exact" })
    .eq("tenant_id", auth.tenantId);

  // Apply SCIM filter on active field directly
  if (filter && filter.attribute === "active") {
    query = query.eq("active", filter.value === "true");
  }

  if (filter && filter.attribute === "externalId") {
    query = query.eq("scim_external_id", filter.value);
  }

  // Apply pagination (convert 1-based to 0-based offset)
  const offset = startIndex - 1;
  query = query.range(offset, offset + count - 1);
  query = query.order("created_at", { ascending: true });

  const { data: mappings, count: totalCount, error: queryErr } = await query;

  if (queryErr) {
    console.error("Mapping query failed:", queryErr.message);
    throw new ScimError(500, "Failed to query users");
  }

  // Enrich with auth user data
  const users: ScimUser[] = [];
  for (const mapping of mappings ?? []) {
    const { data: userData } = await supabase.auth.admin.getUserById(
      mapping.user_id,
    );
    if (!userData?.user) continue;

    const user = userData.user;

    // Apply userName/emails filter against auth user data
    if (filter) {
      if (filter.attribute === "userName" && user.email !== filter.value) {
        continue;
      }
      if (
        filter.attribute === "emails.value" &&
        user.email !== filter.value
      ) {
        continue;
      }
    }

    users.push(
      buildScimUser({
        id: user.id,
        userName: user.email ?? "",
        externalId: mapping.scim_external_id,
        givenName: user.user_metadata?.given_name,
        familyName: user.user_metadata?.family_name,
        displayName: user.user_metadata?.display_name,
        email: user.email ?? "",
        active: mapping.active,
        createdAt: user.created_at,
        lastModified: user.updated_at ?? user.created_at,
        baseUrl: getBaseUrl(req),
      }),
    );
  }

  // For userName/email filters, totalResults should reflect filtered count
  const effectiveTotal =
    filter &&
    (filter.attribute === "userName" || filter.attribute === "emails.value")
      ? users.length
      : (totalCount ?? 0);

  return scimResponse(
    buildListResponse({
      resources: users,
      totalResults: effectiveTotal,
      startIndex,
      itemsPerPage: users.length,
    }),
  );
});

// ── GET /scim/v2/Users/:id — Get Single User ──

app.get("/scim/v2/Users/:id", async (c) => {
  const req = c.req.raw;
  const auth = await authenticateScimRequest(req);
  const supabase = createAdminClient();
  await setTenantContext(supabase, auth.tenantId);

  const userId = c.req.param("id");

  // Get mapping (RLS ensures tenant isolation)
  const { data: mapping, error: mappingErr } = await supabase
    .from("user_tenant_mappings")
    .select("user_id, role, active, scim_external_id, created_at")
    .eq("user_id", userId)
    .eq("tenant_id", auth.tenantId)
    .single();

  if (mappingErr || !mapping) {
    throw notFound();
  }

  // Get auth user data
  const { data: userData } = await supabase.auth.admin.getUserById(userId);
  if (!userData?.user) {
    throw notFound();
  }

  const user = userData.user;
  return scimResponse(
    buildScimUser({
      id: user.id,
      userName: user.email ?? "",
      externalId: mapping.scim_external_id,
      givenName: user.user_metadata?.given_name,
      familyName: user.user_metadata?.family_name,
      displayName: user.user_metadata?.display_name,
      email: user.email ?? "",
      active: mapping.active,
      createdAt: user.created_at,
      lastModified: user.updated_at ?? user.created_at,
      baseUrl: getBaseUrl(req),
    }),
  );
});

// ── PATCH /scim/v2/Users/:id — Update via PatchOp (CP0-D-05) ──

app.patch("/scim/v2/Users/:id", async (c) => {
  const req = c.req.raw;
  const auth = await authenticateScimRequest(req);
  const supabase = createAdminClient();
  await setTenantContext(supabase, auth.tenantId);
  const { ipAddress, userAgent } = extractRequestContext(req);

  const userId = c.req.param("id");
  const body: ScimPatchRequest = await c.req.json();

  // Validate PatchOp schema
  if (
    !body.schemas ||
    !body.schemas.includes(SCIM_SCHEMAS.PATCH_OP)
  ) {
    throw invalidSyntax("Request must include PatchOp schema");
  }

  if (!body.Operations || !Array.isArray(body.Operations)) {
    throw invalidSyntax("Operations array is required");
  }

  // Verify user belongs to tenant
  const { data: mapping, error: mappingErr } = await supabase
    .from("user_tenant_mappings")
    .select("user_id, active, scim_external_id")
    .eq("user_id", userId)
    .eq("tenant_id", auth.tenantId)
    .single();

  if (mappingErr || !mapping) {
    throw notFound();
  }

  // Process each operation
  const authUpdates: Record<string, unknown> = {};
  const metadataUpdates: Record<string, unknown> = {};

  for (const op of body.Operations) {
    validatePatchOp(op);

    switch (op.path) {
      case "active": {
        const active = op.value === true || op.value === "true";
        if (!active) {
          // CRITICAL PATH: deprovisioning
          await deprovisionUser(supabase, {
            userId,
            tenantId: auth.tenantId,
            actorId: auth.tokenId,
            actorEmail: "scim-token",
            ipAddress,
            userAgent,
          });
        } else {
          // Reprovision
          await reprovisionUser(supabase, {
            userId,
            tenantId: auth.tenantId,
            actorId: auth.tokenId,
            actorEmail: "scim-token",
            ipAddress,
            userAgent,
          });
        }
        break;
      }
      case "name.givenName":
        metadataUpdates.given_name = op.value;
        break;
      case "name.familyName":
        metadataUpdates.family_name = op.value;
        break;
      case "displayName":
        metadataUpdates.display_name = op.value;
        break;
      case "emails":
      case "emails[type eq \"work\"].value": {
        const emailValue =
          typeof op.value === "string"
            ? op.value
            : Array.isArray(op.value)
              ? op.value[0]?.value
              : (op.value as { value?: string })?.value;
        if (emailValue) {
          authUpdates.email = emailValue;
        }
        break;
      }
      case "externalId":
        await supabase
          .from("user_tenant_mappings")
          .update({ scim_external_id: op.value })
          .eq("user_id", userId)
          .eq("tenant_id", auth.tenantId);
        break;
      default:
        throw invalidPath(
          `Unsupported path: ${op.path}`,
        );
    }
  }

  // Apply auth updates if any
  if (Object.keys(authUpdates).length > 0 || Object.keys(metadataUpdates).length > 0) {
    const updatePayload: Record<string, unknown> = { ...authUpdates };
    if (Object.keys(metadataUpdates).length > 0) {
      updatePayload.user_metadata = metadataUpdates;
    }
    await supabase.auth.admin.updateUserById(userId, updatePayload);

    // Audit log for non-deprovisioning updates
    await logAuditEvent(supabase, {
      tenantId: auth.tenantId,
      actorId: auth.tokenId,
      actorEmail: "scim-token",
      action: "user.updated",
      resourceType: "user",
      resourceId: userId,
      metadata: { updates: { ...authUpdates, ...metadataUpdates } },
      ipAddress,
      userAgent,
    });
  }

  // Return updated user
  const { data: updatedUser } = await supabase.auth.admin.getUserById(userId);
  const { data: updatedMapping } = await supabase
    .from("user_tenant_mappings")
    .select("active, scim_external_id, created_at")
    .eq("user_id", userId)
    .eq("tenant_id", auth.tenantId)
    .single();

  if (!updatedUser?.user || !updatedMapping) {
    throw notFound();
  }

  const user = updatedUser.user;
  return scimResponse(
    buildScimUser({
      id: user.id,
      userName: user.email ?? "",
      externalId: updatedMapping.scim_external_id,
      givenName: user.user_metadata?.given_name,
      familyName: user.user_metadata?.family_name,
      displayName: user.user_metadata?.display_name,
      email: user.email ?? "",
      active: updatedMapping.active,
      createdAt: user.created_at,
      lastModified: user.updated_at ?? user.created_at,
      baseUrl: getBaseUrl(req),
    }),
  );
});

// ── PUT /scim/v2/Users/:id — Full Replace ──

app.put("/scim/v2/Users/:id", async (c) => {
  const req = c.req.raw;
  const auth = await authenticateScimRequest(req);
  const supabase = createAdminClient();
  await setTenantContext(supabase, auth.tenantId);
  const { ipAddress, userAgent } = extractRequestContext(req);

  const userId = c.req.param("id");
  const body = await c.req.json();

  // Verify user belongs to tenant
  const { data: mapping, error: mappingErr } = await supabase
    .from("user_tenant_mappings")
    .select("user_id")
    .eq("user_id", userId)
    .eq("tenant_id", auth.tenantId)
    .single();

  if (mappingErr || !mapping) {
    throw notFound();
  }

  const primaryEmail =
    body.emails?.find((e: { primary?: boolean }) => e.primary)?.value ??
    body.emails?.[0]?.value ??
    body.userName;

  // Update auth user
  await supabase.auth.admin.updateUserById(userId, {
    email: primaryEmail,
    user_metadata: {
      given_name: body.name?.givenName ?? "",
      family_name: body.name?.familyName ?? "",
      display_name: body.displayName ?? "",
      scim_external_id: body.externalId,
    },
  });

  // Update mapping
  await supabase
    .from("user_tenant_mappings")
    .update({
      scim_external_id: body.externalId ?? null,
      active: body.active !== false,
    })
    .eq("user_id", userId)
    .eq("tenant_id", auth.tenantId);

  // Handle deprovisioning if active=false
  if (body.active === false) {
    await deprovisionUser(supabase, {
      userId,
      tenantId: auth.tenantId,
      actorId: auth.tokenId,
      actorEmail: "scim-token",
      ipAddress,
      userAgent,
    });
  }

  // Audit log
  await logAuditEvent(supabase, {
    tenantId: auth.tenantId,
    actorId: auth.tokenId,
    actorEmail: "scim-token",
    action: "user.replaced",
    resourceType: "user",
    resourceId: userId,
    ipAddress,
    userAgent,
  });

  // Return updated user
  const { data: updatedUser } = await supabase.auth.admin.getUserById(userId);
  const { data: updatedMapping } = await supabase
    .from("user_tenant_mappings")
    .select("active, scim_external_id, created_at")
    .eq("user_id", userId)
    .eq("tenant_id", auth.tenantId)
    .single();

  if (!updatedUser?.user || !updatedMapping) {
    throw notFound();
  }

  const user = updatedUser.user;
  return scimResponse(
    buildScimUser({
      id: user.id,
      userName: user.email ?? "",
      externalId: updatedMapping.scim_external_id,
      givenName: user.user_metadata?.given_name,
      familyName: user.user_metadata?.family_name,
      displayName: user.user_metadata?.display_name,
      email: user.email ?? "",
      active: updatedMapping.active,
      createdAt: user.created_at,
      lastModified: user.updated_at ?? user.created_at,
      baseUrl: getBaseUrl(req),
    }),
  );
});

// ── DELETE /scim/v2/Users/:id — Delete (CP0-D-06) ──

app.delete("/scim/v2/Users/:id", async (c) => {
  const req = c.req.raw;
  const auth = await authenticateScimRequest(req);
  const supabase = createAdminClient();
  await setTenantContext(supabase, auth.tenantId);
  const { ipAddress, userAgent } = extractRequestContext(req);

  const userId = c.req.param("id");

  // Verify user belongs to tenant
  const { data: mapping, error: mappingErr } = await supabase
    .from("user_tenant_mappings")
    .select("user_id")
    .eq("user_id", userId)
    .eq("tenant_id", auth.tenantId)
    .single();

  if (mappingErr || !mapping) {
    throw notFound();
  }

  // Soft-delete via deprovisioning (never hard-delete)
  await deprovisionUser(supabase, {
    userId,
    tenantId: auth.tenantId,
    actorId: auth.tokenId,
    actorEmail: "scim-token",
    ipAddress,
    userAgent,
  });

  return noContentResponse();
});

// ── Helpers ──

function validatePatchOp(op: ScimPatchOperation): void {
  const validOps = ["add", "remove", "replace"];
  if (!validOps.includes(op.op)) {
    throw invalidValue(
      `Unsupported operation: '${op.op}'. Supported: ${validOps.join(", ")}`,
    );
  }
  if (op.op !== "remove" && op.value === undefined) {
    throw invalidValue(`Value is required for '${op.op}' operation`);
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
    console.error("Unhandled error in scim-users:", err);
    return new ScimError(500, "Internal server error").toResponse();
  }
});
