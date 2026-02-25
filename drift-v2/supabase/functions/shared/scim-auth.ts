import { createAdminClient } from "./supabase.ts";
import { setTenantContext } from "./tenant-context.ts";
import { unauthorized } from "./scim-errors.ts";
import type { ScimAuthContext } from "./scim-types.ts";

/**
 * Authenticate a SCIM request using Bearer token.
 *
 * SCIM tokens are separate from user JWTs:
 * - Long-lived, per-tenant, admin-created
 * - Stored as SHA-256 hashes (raw token NEVER stored)
 * - Looked up in scim_tokens table
 *
 * Also sets the tenant context for RLS enforcement.
 *
 * @returns { tenantId, tokenId } on success
 * @throws ScimError(401) on failure
 */
export async function authenticateScimRequest(
  req: Request,
): Promise<ScimAuthContext> {
  const authHeader = req.headers.get("Authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    throw unauthorized("Missing or invalid Authorization header");
  }

  const rawToken = authHeader.slice(7); // Strip "Bearer "
  if (!rawToken) {
    throw unauthorized("Empty bearer token");
  }

  // SHA-256 hash the raw token
  const encoder = new TextEncoder();
  const data = encoder.encode(rawToken);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const tokenHash = hashArray.map((b) => b.toString(16).padStart(2, "0")).join(
    "",
  );

  // Look up token in database
  const supabase = createAdminClient();

  const { data: tokenRow, error } = await supabase
    .from("scim_tokens")
    .select("id, tenant_id")
    .eq("token_hash", tokenHash)
    .is("revoked_at", null)
    .single();

  if (error || !tokenRow) {
    throw unauthorized("Invalid or revoked SCIM token");
  }

  // Set tenant context for all subsequent RLS-filtered queries
  await setTenantContext(supabase, tokenRow.tenant_id);

  // Fire-and-forget: update last_used_at
  supabase
    .from("scim_tokens")
    .update({ last_used_at: new Date().toISOString() })
    .eq("id", tokenRow.id)
    .then(({ error: updateErr }) => {
      if (updateErr) {
        console.error("Failed to update last_used_at:", updateErr.message);
      }
    });

  return {
    tenantId: tokenRow.tenant_id,
    tokenId: tokenRow.id,
  };
}

/**
 * SHA-256 hash a raw token string.
 * Used by both scim-auth (verification) and scim-admin (creation).
 */
export async function hashToken(rawToken: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(rawToken);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}
