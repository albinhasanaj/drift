// Phase F3: IP Allowlist Enforcement Middleware (CP0-F-16, CP0-F-17)
// Per-tenant CIDR-based access control. Empty allowlist = all IPs allowed.
// Uses Postgres inet operator via check_ip_allowlist() RPC.

import { SupabaseClient } from "https://esm.sh/@supabase/supabase-js@2";

export interface IpCheckResult {
  allowed: boolean;
  reason?: string;
}

/**
 * Enforce IP allowlist for a tenant.
 * Empty allowlist = all IPs allowed (default open).
 * Supabase internal requests bypass the check.
 */
export async function enforceIpAllowlist(
  supabase: SupabaseClient,
  tenantId: string,
  clientIp: string,
  req?: Request,
): Promise<IpCheckResult> {
  // Dashboard bypass (CP0-F-17): Supabase internal requests
  if (req) {
    const internalHeader = req.headers.get("x-supabase-internal");
    if (internalHeader === "true") {
      return { allowed: true };
    }
  }

  // Check bypass env var for Supabase infra IPs
  const bypassCidrs = Deno.env.get("SUPABASE_INTERNAL_IPS");
  if (bypassCidrs && clientIp) {
    const cidrs = bypassCidrs.split(",").map((c) => c.trim());
    for (const cidr of cidrs) {
      if (cidr === clientIp) return { allowed: true };
    }
  }

  // Check if tenant has any allowlist entries
  const { data: entries, error: listErr } = await supabase
    .from("ip_allowlist")
    .select("id")
    .eq("tenant_id", tenantId)
    .limit(1);

  if (listErr) {
    console.error("IP allowlist check failed:", listErr.message);
    // Fail open on errors to avoid lockout
    return { allowed: true };
  }

  // Empty allowlist = all IPs allowed (default open)
  if (!entries || entries.length === 0) {
    return { allowed: true };
  }

  // Use Postgres CIDR matching function
  const { data: match, error: matchErr } = await supabase.rpc(
    "check_ip_allowlist",
    {
      p_tenant_id: tenantId,
      p_client_ip: clientIp,
    },
  );

  if (matchErr) {
    console.error("IP allowlist CIDR check failed:", matchErr.message);
    // Fail open on errors
    return { allowed: true };
  }

  if (match && match.length > 0) {
    return { allowed: true };
  }

  return {
    allowed: false,
    reason: `IP ${clientIp} is not in the allowlist for this tenant`,
  };
}

/**
 * Extract client IP from request headers.
 */
export function getClientIp(req: Request): string {
  return (
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ??
    req.headers.get("x-real-ip") ??
    "0.0.0.0"
  );
}
