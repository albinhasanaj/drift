// Phase E: Webhook Dispatch Processor (CP0-E-04, CP0-E-05)
// Edge Function that processes pending webhook retries.
// Designed to be called on a schedule (e.g., every 10s via pg_cron or external cron).
// Also callable manually via POST for immediate retry processing.

import { createAdminClient } from "../shared/supabase.ts";
import { processRetries } from "../shared/webhook-dispatch.ts";

Deno.serve(async (req) => {
  try {
    // Only allow POST (manual trigger) or invocation from scheduler
    if (req.method !== "POST" && req.method !== "GET") {
      return new Response(
        JSON.stringify({ error: "Method not allowed" }),
        { status: 405, headers: { "Content-Type": "application/json" } },
      );
    }

    const supabase = createAdminClient();

    const result = await processRetries(supabase);

    return new Response(
      JSON.stringify({
        ok: true,
        processed: result.processed,
        succeeded: result.succeeded,
        dead_lettered: result.dead_lettered,
        timestamp: new Date().toISOString(),
      }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    );
  } catch (err) {
    console.error("Webhook dispatch processor error:", err);
    return new Response(
      JSON.stringify({ error: "Internal server error" }),
      { status: 500, headers: { "Content-Type": "application/json" } },
    );
  }
});
