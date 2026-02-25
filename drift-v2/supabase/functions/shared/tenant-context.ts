import { SupabaseClient } from "https://esm.sh/@supabase/supabase-js@2";

/**
 * Set the tenant context for RLS enforcement.
 * Calls SET LOCAL app.tenant_id via the set_tenant_context() SQL function.
 * Must be called at the start of every SCIM request handler.
 *
 * SET LOCAL scopes the setting to the current transaction only,
 * so it cannot leak to other requests.
 */
export async function setTenantContext(
  supabase: SupabaseClient,
  tenantId: string,
): Promise<void> {
  const { error } = await supabase.rpc("set_tenant_context", {
    p_tenant_id: tenantId,
  });
  if (error) {
    console.error("Failed to set tenant context:", error.message);
    throw new Error("Failed to set tenant context");
  }
}
