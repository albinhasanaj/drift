// Phase E: Sync Endpoint Stub (CP0-E-07, E-08, E-09)
// Minimal stub that accepts sync payloads and fires webhook events.
// Full sync implementation is Phase 1's scope — this stub exists so
// webhook event wiring can be tested end-to-end.

import { Hono } from "https://deno.land/x/hono@v3.12.0/mod.ts";
import { createAdminClient } from "../shared/supabase.ts";
import { setTenantContext } from "../shared/tenant-context.ts";
import { logAuditEvent, extractRequestContext } from "../shared/audit.ts";
import { dispatchWebhookEvent } from "../shared/webhook-dispatch.ts";
import type {
  ScanCompletedPayload,
  GateFailedPayload,
  ViolationNewPayload,
} from "../shared/webhook-types.ts";

const app = new Hono();

interface AuthContext {
  tenantId: string;
  userId: string;
  email: string;
}

async function authenticateJwt(req: Request): Promise<AuthContext> {
  const authHeader = req.headers.get("authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    throw new HttpError(401, "Missing or invalid Authorization header");
  }

  const token = authHeader.slice(7);
  const supabase = createAdminClient();
  const { data, error } = await supabase.auth.getUser(token);

  if (error || !data?.user) {
    throw new HttpError(401, "Invalid or expired JWT");
  }

  const { data: mapping } = await supabase
    .from("user_tenant_mappings")
    .select("tenant_id, role")
    .eq("user_id", data.user.id)
    .eq("active", true)
    .limit(1)
    .single();

  if (!mapping) {
    throw new HttpError(403, "User is not a member of any tenant");
  }

  return {
    tenantId: mapping.tenant_id,
    userId: data.user.id,
    email: data.user.email ?? "",
  };
}

// ── POST /api/v1/sync — Sync endpoint stub ──
// Accepts scan results and fires webhook events.
// Phase 1 will replace this with the full sync engine.

app.post("/api/v1/sync", async (c) => {
  const req = c.req.raw;
  const auth = await authenticateJwt(req);
  const supabase = createAdminClient();
  await setTenantContext(supabase, auth.tenantId);
  const { ipAddress, userAgent } = extractRequestContext(req);

  const body = await c.req.json();

  // Validate minimum required fields
  const projectId = body.project_id;
  if (!projectId) {
    throw new HttpError(400, "project_id is required");
  }

  const timestamp = new Date().toISOString();

  // ── Fire scan.completed (CP0-E-07) ──
  const scanPayload: ScanCompletedPayload = {
    event: "scan.completed",
    project_id: projectId,
    scan_id: body.scan_id ?? crypto.randomUUID(),
    files_scanned: body.files_scanned ?? 0,
    patterns_detected: body.patterns_detected ?? 0,
    violations_found: body.violations_found ?? 0,
    duration_ms: body.duration_ms ?? 0,
    timestamp,
  };
  // Fire-and-forget — never blocks sync
  dispatchWebhookEvent(supabase, auth.tenantId, scanPayload);

  // ── Fire gate.failed for failing gates (CP0-E-08) ──
  if (body.gate_results && Array.isArray(body.gate_results)) {
    for (const gate of body.gate_results) {
      if (gate.passed === false) {
        const gatePayload: GateFailedPayload = {
          event: "gate.failed",
          project_id: projectId,
          gate_name: gate.gate_name ?? "UnknownGate",
          score: gate.score ?? 0,
          threshold: gate.threshold ?? 0,
          summary:
            gate.summary ??
            `${gate.gate_name} failed: ${gate.score} < ${gate.threshold}`,
          violations: gate.violations ?? [],
          timestamp,
        };
        dispatchWebhookEvent(supabase, auth.tenantId, gatePayload);
      }
    }
  }

  // ── Fire violation.new for new critical/high violations (CP0-E-09) ──
  if (body.new_violations && Array.isArray(body.new_violations)) {
    for (const violation of body.new_violations) {
      if (
        violation.severity === "critical" ||
        violation.severity === "high"
      ) {
        const violationPayload: ViolationNewPayload = {
          event: "violation.new",
          project_id: projectId,
          rule_id: violation.rule_id ?? "unknown",
          severity: violation.severity,
          file_path: violation.file_path ?? "",
          line: violation.line ?? 0,
          message: violation.message ?? "",
          timestamp,
        };
        dispatchWebhookEvent(supabase, auth.tenantId, violationPayload);
      }
    }
  }

  // Audit
  await logAuditEvent(supabase, {
    tenantId: auth.tenantId,
    actorId: auth.userId,
    actorEmail: auth.email,
    action: "sync.pushed",
    resourceType: "project",
    resourceId: projectId,
    metadata: {
      files_scanned: body.files_scanned,
      violations_found: body.violations_found,
    },
    ipAddress,
    userAgent,
  });

  return c.json({
    ok: true,
    project_id: projectId,
    scan_id: scanPayload.scan_id,
    webhooks_dispatched: true,
    timestamp,
  });
});

class HttpError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

Deno.serve(async (req) => {
  try {
    return await app.fetch(req);
  } catch (err) {
    if (err instanceof HttpError) {
      return new Response(
        JSON.stringify({ error: err.message }),
        {
          status: err.status,
          headers: { "Content-Type": "application/json" },
        },
      );
    }
    console.error("Unhandled error in sync:", err);
    return new Response(
      JSON.stringify({ error: "Internal server error" }),
      {
        status: 500,
        headers: { "Content-Type": "application/json" },
      },
    );
  }
});
