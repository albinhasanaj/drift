import { SupabaseClient } from "https://esm.sh/@supabase/supabase-js@2";

/** Parameters for logging an audit event */
export interface AuditEventParams {
  tenantId: string;
  actorId: string;
  actorEmail: string;
  action: string;
  resourceType: string;
  resourceId?: string;
  metadata?: Record<string, unknown>;
  ipAddress?: string;
  userAgent?: string;
}

/**
 * Log an immutable audit event to cloud_audit_log.
 * This table has no UPDATE/DELETE policies — entries are permanent.
 *
 * Every SCIM mutation (POST, PATCH, PUT, DELETE) MUST call this.
 * Reused by Phase E (Webhooks) and Phase F (Audit API).
 */
export async function logAuditEvent(
  supabase: SupabaseClient,
  params: AuditEventParams,
): Promise<void> {
  const { error } = await supabase.from("cloud_audit_log").insert({
    tenant_id: params.tenantId,
    actor_id: params.actorId,
    actor_email: params.actorEmail,
    action: params.action,
    resource_type: params.resourceType,
    resource_id: params.resourceId ?? null,
    metadata: params.metadata ?? null,
    ip_address: params.ipAddress ?? null,
    user_agent: params.userAgent ?? null,
  });

  if (error) {
    // Audit logging failures must not break the main operation.
    // Log server-side but do not throw.
    console.error("Failed to log audit event:", error.message, {
      action: params.action,
      resourceType: params.resourceType,
      resourceId: params.resourceId,
    });
  }
}

/**
 * Extract client IP and User-Agent from a Request for audit logging.
 */
export function extractRequestContext(req: Request): {
  ipAddress: string | undefined;
  userAgent: string | undefined;
} {
  return {
    ipAddress:
      req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ??
      req.headers.get("x-real-ip") ??
      undefined,
    userAgent: req.headers.get("user-agent") ?? undefined,
  };
}
