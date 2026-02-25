// Phase E: Webhook Dispatch Helper (CP0-E-07/E-08/E-09)
// Fire-and-forget helper that dispatches webhook events to matching endpoints.
// Never blocks the caller. Errors are logged, not thrown.

import { SupabaseClient } from "https://esm.sh/@supabase/supabase-js@2";
import type { WebhookPayload } from "./webhook-types.ts";
import {
  signWebhookPayload,
  generateWebhookSecret,
  sha256Hash,
} from "./webhook-signature.ts";
import {
  DELIVERY_TIMEOUT_MS,
  RETRY_BACKOFF_MS,
  MAX_RETRY_ATTEMPTS,
  CIRCUIT_BREAKER_THRESHOLD,
} from "./webhook-types.ts";

/**
 * Dispatch a webhook event to all matching endpoints for a tenant.
 * This is fire-and-forget — it never throws and never blocks the caller.
 *
 * @param supabase - Supabase client (with tenant context already set)
 * @param tenantId - Tenant ID for endpoint lookup
 * @param payload - Event payload to deliver
 */
export async function dispatchWebhookEvent(
  supabase: SupabaseClient,
  tenantId: string,
  payload: WebhookPayload,
): Promise<void> {
  try {
    const eventType = payload.event;

    // Find matching active endpoints
    const { data: endpoints, error } = await supabase
      .from("webhook_endpoints")
      .select("id, url, secret_hash, secret_hash_new, secret_rotated_at, events, consecutive_failures")
      .eq("tenant_id", tenantId)
      .eq("active", true)
      .contains("events", [eventType]);

    if (error) {
      console.error("Failed to query webhook endpoints:", error.message);
      return;
    }

    if (!endpoints || endpoints.length === 0) return;

    // Dispatch to each endpoint (all in parallel, fire-and-forget)
    const deliveryPromises = endpoints.map((endpoint) =>
      deliverToEndpoint(supabase, tenantId, endpoint, payload).catch((err) => {
        console.error(
          `Webhook delivery failed for endpoint ${endpoint.id}:`,
          err.message,
        );
      })
    );

    // Don't await — fire and forget
    Promise.allSettled(deliveryPromises).catch(() => {});
  } catch (err) {
    console.error("dispatchWebhookEvent failed:", (err as Error).message);
  }
}

/**
 * Deliver a webhook payload to a single endpoint.
 * Records the delivery attempt in webhook_deliveries.
 */
async function deliverToEndpoint(
  supabase: SupabaseClient,
  tenantId: string,
  endpoint: {
    id: string;
    url: string;
    secret_hash: string;
    secret_hash_new: string | null;
    secret_rotated_at: string | null;
    events: string[];
    consecutive_failures: number;
  },
  payload: WebhookPayload,
): Promise<void> {
  const idempotencyKey = crypto.randomUUID();
  const payloadString = JSON.stringify(payload);

  // Derive signing secret from endpoint ID + master key
  // This avoids storing raw secrets — we derive them deterministically
  const signingSecret = await deriveSigningSecret(endpoint.id);
  let signingSecretNew: string | undefined;

  // During rotation window, also sign with new secret
  if (endpoint.secret_hash_new && endpoint.secret_rotated_at) {
    const rotatedAt = new Date(endpoint.secret_rotated_at).getTime();
    const now = Date.now();
    const twentyFourHours = 24 * 60 * 60 * 1000;
    if (now - rotatedAt < twentyFourHours) {
      signingSecretNew = await deriveSigningSecret(endpoint.id + ":new");
    }
  }

  // Sign the payload
  const headers = await signWebhookPayload(
    signingSecret,
    payloadString,
    idempotencyKey,
    payload.event,
    signingSecretNew,
  );

  const startTime = Date.now();
  let statusCode: number | null = null;
  let responseBody: string | null = null;
  let success = false;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(
      () => controller.abort(),
      DELIVERY_TIMEOUT_MS,
    );

    const response = await fetch(endpoint.url, {
      method: "POST",
      headers,
      body: payloadString,
      signal: controller.signal,
    });

    clearTimeout(timeout);
    statusCode = response.status;

    // Truncate response body to 1KB
    const body = await response.text();
    responseBody = body.length > 1024 ? body.slice(0, 1024) : body;

    success = statusCode >= 200 && statusCode < 300;
  } catch (err) {
    responseBody = (err as Error).message?.slice(0, 1024) ?? "Delivery failed";
  }

  const latencyMs = Date.now() - startTime;

  if (success) {
    // Record successful delivery
    await supabase.from("webhook_deliveries").insert({
      endpoint_id: endpoint.id,
      tenant_id: tenantId,
      event_type: payload.event,
      payload,
      idempotency_key: idempotencyKey,
      status: "delivered",
      status_code: statusCode,
      response_body: responseBody,
      attempt: 1,
      delivered_at: new Date().toISOString(),
      latency_ms: latencyMs,
    });

    // Reset consecutive failures on success
    if (endpoint.consecutive_failures > 0) {
      await supabase
        .from("webhook_endpoints")
        .update({ consecutive_failures: 0, updated_at: new Date().toISOString() })
        .eq("id", endpoint.id);
    }
  } else {
    // Record failed delivery with retry
    const nextRetryAt = new Date(Date.now() + RETRY_BACKOFF_MS[0]).toISOString();

    await supabase.from("webhook_deliveries").insert({
      endpoint_id: endpoint.id,
      tenant_id: tenantId,
      event_type: payload.event,
      payload,
      idempotency_key: idempotencyKey,
      status: "pending",
      status_code: statusCode,
      response_body: responseBody,
      attempt: 1,
      next_retry_at: nextRetryAt,
      latency_ms: latencyMs,
    });

    // Increment consecutive failures
    const newFailures = endpoint.consecutive_failures + 1;
    const updates: Record<string, unknown> = {
      consecutive_failures: newFailures,
      updated_at: new Date().toISOString(),
    };

    // Circuit breaker: disable after threshold
    if (newFailures >= CIRCUIT_BREAKER_THRESHOLD) {
      updates.active = false;
      console.warn(
        `Circuit breaker triggered for endpoint ${endpoint.id}: ${newFailures} consecutive failures`,
      );
    }

    await supabase
      .from("webhook_endpoints")
      .update(updates)
      .eq("id", endpoint.id);
  }
}

/**
 * Process pending retries for webhook deliveries.
 * Called by the webhook-dispatch Edge Function on a schedule.
 */
export async function processRetries(
  supabase: SupabaseClient,
): Promise<{ processed: number; succeeded: number; dead_lettered: number }> {
  let processed = 0;
  let succeeded = 0;
  let deadLettered = 0;

  // Fetch deliveries ready for retry
  const { data: pendingDeliveries, error } = await supabase
    .from("webhook_deliveries")
    .select(
      "id, endpoint_id, tenant_id, event_type, payload, idempotency_key, attempt, max_attempts",
    )
    .eq("status", "pending")
    .lte("next_retry_at", new Date().toISOString())
    .order("next_retry_at", { ascending: true })
    .limit(100);

  if (error || !pendingDeliveries) {
    console.error("Failed to fetch pending retries:", error?.message);
    return { processed, succeeded, dead_lettered: deadLettered };
  }

  for (const delivery of pendingDeliveries) {
    processed++;

    // Get the endpoint
    const { data: endpoint } = await supabase
      .from("webhook_endpoints")
      .select("id, url, secret_hash, secret_hash_new, secret_rotated_at, active")
      .eq("id", delivery.endpoint_id)
      .single();

    if (!endpoint || !endpoint.active) {
      // Endpoint deleted or disabled — dead letter
      await supabase
        .from("webhook_deliveries")
        .update({ status: "dead_letter" })
        .eq("id", delivery.id);
      deadLettered++;
      continue;
    }

    // Attempt delivery
    const payloadString = JSON.stringify(delivery.payload);
    const signingSecret = await deriveSigningSecret(endpoint.id);
    let signingSecretNew: string | undefined;
    if (endpoint.secret_hash_new && endpoint.secret_rotated_at) {
      const rotatedAt = new Date(endpoint.secret_rotated_at).getTime();
      if (Date.now() - rotatedAt < 24 * 60 * 60 * 1000) {
        signingSecretNew = await deriveSigningSecret(endpoint.id + ":new");
      }
    }

    const headers = await signWebhookPayload(
      signingSecret,
      payloadString,
      delivery.idempotency_key,
      delivery.event_type,
      signingSecretNew,
    );

    const startTime = Date.now();
    let statusCode: number | null = null;
    let responseBody: string | null = null;
    let success = false;

    try {
      const controller = new AbortController();
      const timeout = setTimeout(
        () => controller.abort(),
        DELIVERY_TIMEOUT_MS,
      );

      const response = await fetch(endpoint.url, {
        method: "POST",
        headers,
        body: payloadString,
        signal: controller.signal,
      });

      clearTimeout(timeout);
      statusCode = response.status;
      const body = await response.text();
      responseBody = body.length > 1024 ? body.slice(0, 1024) : body;
      success = statusCode >= 200 && statusCode < 300;
    } catch (err) {
      responseBody = (err as Error).message?.slice(0, 1024) ?? "Retry failed";
    }

    const latencyMs = Date.now() - startTime;
    const newAttempt = delivery.attempt + 1;

    if (success) {
      await supabase
        .from("webhook_deliveries")
        .update({
          status: "delivered",
          status_code: statusCode,
          response_body: responseBody,
          attempt: newAttempt,
          delivered_at: new Date().toISOString(),
          latency_ms: latencyMs,
          next_retry_at: null,
        })
        .eq("id", delivery.id);

      // Reset consecutive failures
      await supabase
        .from("webhook_endpoints")
        .update({ consecutive_failures: 0, updated_at: new Date().toISOString() })
        .eq("id", endpoint.id);

      succeeded++;
    } else if (newAttempt >= delivery.max_attempts) {
      // Max retries exhausted — dead letter
      await supabase
        .from("webhook_deliveries")
        .update({
          status: "dead_letter",
          status_code: statusCode,
          response_body: responseBody,
          attempt: newAttempt,
          latency_ms: latencyMs,
          next_retry_at: null,
        })
        .eq("id", delivery.id);

      deadLettered++;
    } else {
      // Schedule next retry with exponential backoff
      const backoffIndex = Math.min(
        newAttempt - 1,
        RETRY_BACKOFF_MS.length - 1,
      );
      const nextRetryAt = new Date(
        Date.now() + RETRY_BACKOFF_MS[backoffIndex],
      ).toISOString();

      await supabase
        .from("webhook_deliveries")
        .update({
          status: "pending",
          status_code: statusCode,
          response_body: responseBody,
          attempt: newAttempt,
          latency_ms: latencyMs,
          next_retry_at: nextRetryAt,
        })
        .eq("id", delivery.id);

      // Increment consecutive failures
      await supabase.rpc("increment_webhook_failures", {
        p_endpoint_id: endpoint.id,
      }).catch(() => {
        // Fallback if RPC not available
        supabase
          .from("webhook_endpoints")
          .update({
            consecutive_failures: (endpoint as Record<string, unknown>).consecutive_failures as number + 1 || 1,
            updated_at: new Date().toISOString(),
          })
          .eq("id", endpoint.id);
      });
    }
  }

  return { processed, succeeded, dead_lettered: deadLettered };
}

/**
 * Deliver a test (ping) event synchronously and return the result.
 */
export async function deliverTestEvent(
  supabase: SupabaseClient,
  tenantId: string,
  endpointId: string,
  url: string,
): Promise<{
  success: boolean;
  status_code: number | null;
  latency_ms: number;
  response_body: string | null;
}> {
  const payload: WebhookPayload = {
    event: "ping",
    webhook_id: endpointId,
    message: "This is a test webhook delivery from Drift.",
    timestamp: new Date().toISOString(),
  };

  const idempotencyKey = crypto.randomUUID();
  const payloadString = JSON.stringify(payload);
  const signingSecret = await deriveSigningSecret(endpointId);

  const headers = await signWebhookPayload(
    signingSecret,
    payloadString,
    idempotencyKey,
    "ping",
  );

  const startTime = Date.now();
  let statusCode: number | null = null;
  let responseBody: string | null = null;
  let success = false;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(
      () => controller.abort(),
      DELIVERY_TIMEOUT_MS,
    );

    const response = await fetch(url, {
      method: "POST",
      headers,
      body: payloadString,
      signal: controller.signal,
    });

    clearTimeout(timeout);
    statusCode = response.status;
    const body = await response.text();
    responseBody = body.length > 1024 ? body.slice(0, 1024) : body;
    success = statusCode >= 200 && statusCode < 300;
  } catch (err) {
    responseBody = (err as Error).message?.slice(0, 1024) ?? "Test delivery failed";
  }

  const latencyMs = Date.now() - startTime;

  // Record the test delivery
  await supabase.from("webhook_deliveries").insert({
    endpoint_id: endpointId,
    tenant_id: tenantId,
    event_type: "ping",
    payload,
    idempotency_key: idempotencyKey,
    status: success ? "delivered" : "failed",
    status_code: statusCode,
    response_body: responseBody,
    attempt: 1,
    delivered_at: success ? new Date().toISOString() : null,
    latency_ms: latencyMs,
  });

  return { success, status_code: statusCode, latency_ms: latencyMs, response_body: responseBody };
}

/**
 * Derive a signing secret from an endpoint ID + master key.
 * Uses HMAC-SHA256(master_key, endpoint_id) to avoid storing raw secrets.
 */
async function deriveSigningSecret(endpointId: string): Promise<string> {
  const masterKey = Deno.env.get("WEBHOOK_SIGNING_MASTER_KEY") ?? "drift-webhook-default-key";
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(masterKey),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(endpointId),
  );
  return Array.from(new Uint8Array(signature))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
