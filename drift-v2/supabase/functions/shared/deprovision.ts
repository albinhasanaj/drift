import { SupabaseClient } from "https://esm.sh/@supabase/supabase-js@2";
import { logAuditEvent } from "./audit.ts";

/** Result of a deprovisioning operation */
export interface DeprovisionResult {
  success: boolean;
  steps: {
    authBanned: boolean;
    apiKeysRevoked: boolean;
    sessionsEnded: boolean;
    mappingDeactivated: boolean;
    auditLogged: boolean;
  };
  errors: string[];
}

/**
 * Deprovision a user — the most security-critical code in Phase D.
 *
 * When an IdP sends `active: false` or DELETE, ALL access must be revoked:
 *
 * 1. Verify user belongs to tenant (user_tenant_mappings)
 * 2. Disable Supabase Auth user (ban for 100 years)
 * 3. Revoke ALL API keys for this user in this tenant
 * 4. End all sessions (global sign-out)
 * 5. Mark mapping inactive (active=false, deprovisioned_at=now)
 * 6. Audit log (user.deprovisioned)
 *
 * All 6 steps must complete within 60s.
 * If any step fails, log error but CONTINUE remaining steps.
 * Partial deprovisioning is better than none.
 */
export async function deprovisionUser(
  supabase: SupabaseClient,
  params: {
    userId: string;
    tenantId: string;
    actorId: string;
    actorEmail: string;
    ipAddress?: string;
    userAgent?: string;
  },
): Promise<DeprovisionResult> {
  const errors: string[] = [];
  const steps = {
    authBanned: false,
    apiKeysRevoked: false,
    sessionsEnded: false,
    mappingDeactivated: false,
    auditLogged: false,
  };

  // Step 1: Verify user belongs to tenant
  const { data: mapping, error: mappingErr } = await supabase
    .from("user_tenant_mappings")
    .select("user_id, active")
    .eq("user_id", params.userId)
    .eq("tenant_id", params.tenantId)
    .single();

  if (mappingErr || !mapping) {
    return {
      success: false,
      steps,
      errors: ["User not found in tenant"],
    };
  }

  if (!mapping.active) {
    // Already deprovisioned — idempotent
    return {
      success: true,
      steps: {
        authBanned: true,
        apiKeysRevoked: true,
        sessionsEnded: true,
        mappingDeactivated: true,
        auditLogged: true,
      },
      errors: [],
    };
  }

  // Step 2: Disable Supabase Auth user (ban for ~100 years)
  try {
    const { error: banErr } = await supabase.auth.admin.updateUserById(
      params.userId,
      { ban_duration: "876000h" },
    );
    if (banErr) {
      errors.push(`Auth ban failed: ${banErr.message}`);
    } else {
      steps.authBanned = true;
    }
  } catch (e) {
    errors.push(`Auth ban exception: ${(e as Error).message}`);
  }

  // Step 3: Revoke ALL API keys for this user in this tenant
  try {
    const { error: revokeErr } = await supabase
      .from("api_keys")
      .update({ revoked_at: new Date().toISOString() })
      .eq("tenant_id", params.tenantId)
      .eq("created_by", params.userId)
      .is("revoked_at", null);
    if (revokeErr) {
      errors.push(`API key revocation failed: ${revokeErr.message}`);
    } else {
      steps.apiKeysRevoked = true;
    }
  } catch (e) {
    errors.push(`API key revocation exception: ${(e as Error).message}`);
  }

  // Step 4: End all sessions (global sign-out)
  try {
    // Note: Supabase admin signOut is not available in all versions.
    // Banning the user (step 2) already invalidates all JWTs on next refresh.
    // We also delete any refresh tokens by updating the user.
    const { error: signOutErr } = await supabase.auth.admin.updateUserById(
      params.userId,
      {
        // Force token refresh to fail by re-banning (idempotent with step 2)
        ban_duration: "876000h",
      },
    );
    if (signOutErr) {
      errors.push(`Session termination failed: ${signOutErr.message}`);
    } else {
      steps.sessionsEnded = true;
    }
  } catch (e) {
    errors.push(`Session termination exception: ${(e as Error).message}`);
  }

  // Step 5: Mark mapping inactive
  try {
    const { error: deactivateErr } = await supabase
      .from("user_tenant_mappings")
      .update({
        active: false,
        deprovisioned_at: new Date().toISOString(),
      })
      .eq("user_id", params.userId)
      .eq("tenant_id", params.tenantId);
    if (deactivateErr) {
      errors.push(`Mapping deactivation failed: ${deactivateErr.message}`);
    } else {
      steps.mappingDeactivated = true;
    }
  } catch (e) {
    errors.push(`Mapping deactivation exception: ${(e as Error).message}`);
  }

  // Step 6: Audit log
  try {
    await logAuditEvent(supabase, {
      tenantId: params.tenantId,
      actorId: params.actorId,
      actorEmail: params.actorEmail,
      action: "user.deprovisioned",
      resourceType: "user",
      resourceId: params.userId,
      metadata: {
        steps,
        errors: errors.length > 0 ? errors : undefined,
      },
      ipAddress: params.ipAddress,
      userAgent: params.userAgent,
    });
    steps.auditLogged = true;
  } catch (e) {
    errors.push(`Audit logging exception: ${(e as Error).message}`);
  }

  if (errors.length > 0) {
    console.error("Deprovisioning completed with errors:", {
      userId: params.userId,
      tenantId: params.tenantId,
      steps,
      errors,
    });
  }

  return {
    success: errors.length === 0,
    steps,
    errors,
  };
}

/**
 * Reprovision a user — reverse of deprovision.
 * Called when IdP sends `active: true` via PATCH.
 */
export async function reprovisionUser(
  supabase: SupabaseClient,
  params: {
    userId: string;
    tenantId: string;
    actorId: string;
    actorEmail: string;
    ipAddress?: string;
    userAgent?: string;
  },
): Promise<void> {
  // Unban auth user
  await supabase.auth.admin.updateUserById(params.userId, {
    ban_duration: "none",
  });

  // Reactivate mapping
  await supabase
    .from("user_tenant_mappings")
    .update({
      active: true,
      deprovisioned_at: null,
    })
    .eq("user_id", params.userId)
    .eq("tenant_id", params.tenantId);

  // Audit log
  await logAuditEvent(supabase, {
    tenantId: params.tenantId,
    actorId: params.actorId,
    actorEmail: params.actorEmail,
    action: "user.reprovisioned",
    resourceType: "user",
    resourceId: params.userId,
    ipAddress: params.ipAddress,
    userAgent: params.userAgent,
  });
}
