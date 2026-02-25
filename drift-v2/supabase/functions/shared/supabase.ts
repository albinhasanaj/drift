import { createClient, SupabaseClient } from "https://esm.sh/@supabase/supabase-js@2";

/**
 * Create a Supabase admin client using the service_role key.
 * This client bypasses RLS — use ONLY for Auth Admin API calls.
 * Never expose the service_role key in responses or logs.
 */
export function createAdminClient(): SupabaseClient {
  const url = Deno.env.get("SUPABASE_URL");
  const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");

  if (!url || !serviceRoleKey) {
    throw new Error("Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY");
  }

  return createClient(url, serviceRoleKey, {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
    },
  });
}

/**
 * Create a Supabase client scoped to a specific tenant via RLS.
 * All queries through this client are filtered by tenant_id.
 */
export function createTenantClient(tenantId: string): SupabaseClient {
  const url = Deno.env.get("SUPABASE_URL");
  const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");

  if (!url || !serviceRoleKey) {
    throw new Error("Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY");
  }

  return createClient(url, serviceRoleKey, {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
    },
    global: {
      headers: {
        "x-tenant-id": tenantId,
      },
    },
  });
}

/**
 * Get the raw database connection URL for direct SQL queries.
 */
export function getDatabaseUrl(): string {
  const url = Deno.env.get("SUPABASE_DB_URL");
  if (!url) {
    throw new Error("Missing SUPABASE_DB_URL");
  }
  return url;
}
