// Phase E: Webhook & Event Notification System (CP0-E-06)
// TypeScript types for all 8 event payloads (7 core + ping)

// ── Valid event types ──

export const WEBHOOK_EVENT_TYPES = [
  "scan.completed",
  "gate.failed",
  "violation.new",
  "grounding.degraded",
  "apikey.expiring",
  "sync.failed",
  "project.created",
  "project.deleted",
  "ping",
] as const;

export type WebhookEventType = (typeof WEBHOOK_EVENT_TYPES)[number];

// ── Event payloads ──

export interface ScanCompletedPayload {
  event: "scan.completed";
  project_id: string;
  scan_id: string;
  files_scanned: number;
  patterns_detected: number;
  violations_found: number;
  duration_ms: number;
  timestamp: string;
}

export interface GateFailedPayload {
  event: "gate.failed";
  project_id: string;
  gate_name: string;
  score: number;
  threshold: number;
  summary: string;
  violations: Array<{
    rule: string;
    severity: string;
    count: number;
  }>;
  timestamp: string;
}

export interface ViolationNewPayload {
  event: "violation.new";
  project_id: string;
  rule_id: string;
  severity: string;
  file_path: string;
  line: number;
  message: string;
  timestamp: string;
}

export interface GroundingDegradedPayload {
  event: "grounding.degraded";
  project_id: string;
  memory_id: string;
  memory_type: string;
  old_score: number;
  new_score: number;
  threshold: number;
  timestamp: string;
}

export interface ApiKeyExpiringPayload {
  event: "apikey.expiring";
  tenant_id: string;
  key_name: string;
  key_id: string;
  expires_at: string;
  days_remaining: number;
  timestamp: string;
}

export interface SyncFailedPayload {
  event: "sync.failed";
  project_id: string;
  error: string;
  retry_count: number;
  last_attempt_at: string;
  timestamp: string;
}

export interface ProjectLifecyclePayload {
  event: "project.created" | "project.deleted";
  project_id: string;
  project_name: string;
  tenant_id: string;
  actor_id: string;
  timestamp: string;
}

export interface PingPayload {
  event: "ping";
  webhook_id: string;
  message: string;
  timestamp: string;
}

export type WebhookPayload =
  | ScanCompletedPayload
  | GateFailedPayload
  | ViolationNewPayload
  | GroundingDegradedPayload
  | ApiKeyExpiringPayload
  | SyncFailedPayload
  | ProjectLifecyclePayload
  | PingPayload;

// ── Webhook endpoint resource ──

export interface WebhookEndpoint {
  id: string;
  tenant_id: string;
  url: string;
  events: string[];
  description: string;
  active: boolean;
  consecutive_failures: number;
  created_by: string;
  created_at: string;
  updated_at: string;
}

// ── Webhook delivery resource ──

export interface WebhookDelivery {
  id: string;
  endpoint_id: string;
  tenant_id: string;
  event_type: string;
  payload: Record<string, unknown>;
  idempotency_key: string;
  status: "pending" | "delivered" | "failed" | "dead_letter";
  status_code: number | null;
  response_body: string | null;
  attempt: number;
  max_attempts: number;
  next_retry_at: string | null;
  delivered_at: string | null;
  latency_ms: number | null;
  created_at: string;
}

// ── Delivery result (returned by test endpoint) ──

export interface DeliveryResult {
  success: boolean;
  status_code: number | null;
  latency_ms: number;
  response_body: string | null;
}

// ── Retry backoff schedule (ms) ──

export const RETRY_BACKOFF_MS = [1000, 2000, 4000, 8000, 16000] as const;
export const MAX_RETRY_ATTEMPTS = 5;
export const CIRCUIT_BREAKER_THRESHOLD = 50;
export const DELIVERY_TIMEOUT_MS = 10_000;
export const SIGNATURE_TOLERANCE_SECONDS = 300;
export const ROTATION_WINDOW_HOURS = 24;
