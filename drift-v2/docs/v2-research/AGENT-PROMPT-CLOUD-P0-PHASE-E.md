# Agent Prompt: Cloud P0 Phase E — Webhook & Event Notification System (Enterprise GAP-02)

## Your Mission

You are building a complete webhook infrastructure so enterprise customers receive real-time notifications for CI/CD integration, alerting, and third-party orchestration. **Without webhooks, customers must poll** — unacceptable for CI/CD pipelines needing instant gate failure alerts.

This phase is **Supabase Edge Functions (Deno/TypeScript)** — no Rust. It builds on Phase D's Supabase project structure. Phase D's `shared/` helpers (`supabase.ts`, `audit.ts`, `tenant-context.ts`) are reused.

When this phase is done:
- **Webhook CRUD API** — register, list, update, delete endpoints with event subscriptions
- **HMAC-SHA256 signed deliveries** — Stripe-pattern signatures on every payload
- **Retry with exponential backoff** — 5xx/timeout → 5 retries (1s/2s/4s/8s/16s), then dead letter
- **7 event types wired** — `scan.completed`, `gate.failed`, `violation.new`, `grounding.degraded`, `apikey.expiring`, `sync.failed`, `project.created`/`project.deleted`
- **Delivery logs API** — paginated history per endpoint
- **Test endpoint** — `POST /api/v1/webhooks/:id/test` sends `ping` synchronously
- **Secret rotation** — 24h dual-validity window

**Reliability does not matter more than security. Secrets SHA-256 hashed. URLs validated (HTTPS, no localhost/private IPs). RLS on every table.**

---

## Documents You MUST Read Before Writing Any Code

1. **`docs/v2-research/CLOUD-P0-IMPLEMENTATION-PLAN.md`** — Phase E (lines ~369-427). 12 impl tasks (CP0-E-01 to E-12) + 10 tests + Quality Gate.
2. **`docs/v2-research/BRIDGE-CLOUD-READINESS-TRACKER.md`** — GAP-02 (lines ~1022-1069). Webhook table schema, event catalog, missing infrastructure.
3. **Stripe Webhook Signature Pattern** — `X-Drift-Signature: t=timestamp,v1=HMAC-SHA256(secret, timestamp.payload)`. 5-min timestamp tolerance. Constant-time comparison.
4. **`supabase/functions/shared/`** — Phase D helpers. Reuse `supabase.ts`, `audit.ts`, `tenant-context.ts`.
5. **`supabase/migrations/`** — 4 migrations from Phase D. Your webhook migrations follow same naming.

After reading, you should answer:
- What 7 event types? (`scan.completed`, `gate.failed`, `violation.new`, `grounding.degraded`, `apikey.expiring`, `sync.failed`, `project.created`/`project.deleted`)
- How are secrets stored? (SHA-256 hash. Raw shown once.)
- How does HMAC signing work? (`HMAC-SHA256(secret, timestamp + "." + payload)`, 5-min tolerance, constant-time compare)
- Retry policy? (5 retries: 1s→2s→4s→8s→16s, then dead letter. Circuit breaker at 50 consecutive failures.)
- Secret rotation? (Both old+new valid 24h, then old deleted.)

---

## Phase Execution Order

### Sub-Phase E1: Webhook Infrastructure (CP0-E-01, CP0-E-02, CP0-E-03)

**Goal:** Tables, registration API, signature generation.

**New files:**
```
supabase/
├── migrations/
│   └── 20260211000004_webhooks.sql
├── functions/
│   ├── shared/
│   │   ├── webhook-signature.ts    # HMAC-SHA256 sign + verify
│   │   ├── webhook-types.ts        # TS types for webhook resources
│   │   └── url-validator.ts        # HTTPS-only, no private IPs
│   ├── webhooks/index.ts           # CRUD API (Hono, JWT auth)
│   └── webhook-dispatch/index.ts   # Async dispatch + retry
└── tests/
    ├── webhook-crud.test.ts
    ├── webhook-signature.test.ts
    └── webhook-dispatch.test.ts
```

#### Migration: `20260211000004_webhooks.sql` (CP0-E-01)

```sql
-- Reference table: supported event types
CREATE TABLE IF NOT EXISTS webhook_event_types (
    event_type TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    payload_schema JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO webhook_event_types (event_type, description) VALUES
    ('scan.completed', 'Scan finished with summary statistics'),
    ('gate.failed', 'Quality gate failed'),
    ('violation.new', 'New critical/high violation detected'),
    ('grounding.degraded', 'Memory grounding score dropped below threshold'),
    ('apikey.expiring', 'API key approaching expiration'),
    ('sync.failed', 'Cloud sync failed after retries'),
    ('project.created', 'New project registered'),
    ('project.deleted', 'Project deleted'),
    ('ping', 'Test event for webhook verification')
ON CONFLICT (event_type) DO NOTHING;

-- Webhook endpoints
CREATE TABLE IF NOT EXISTS webhook_endpoints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    secret_hash TEXT NOT NULL,
    secret_hash_new TEXT,              -- Rotation: new secret (24h dual-validity)
    secret_rotated_at TIMESTAMPTZ,
    events TEXT[] NOT NULL,
    description TEXT DEFAULT '',
    active BOOLEAN NOT NULL DEFAULT true,
    consecutive_failures INT NOT NULL DEFAULT 0,
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE webhook_endpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_endpoints FORCE ROW LEVEL SECURITY;
CREATE POLICY webhook_endpoints_tenant_isolation ON webhook_endpoints
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_webhook_endpoints_tenant ON webhook_endpoints(tenant_id);
CREATE INDEX idx_webhook_endpoints_active ON webhook_endpoints(tenant_id, active) WHERE active = true;

-- Webhook deliveries
CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id UUID NOT NULL REFERENCES webhook_endpoints(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL,
    event_type TEXT NOT NULL,
    payload JSONB NOT NULL,
    idempotency_key UUID NOT NULL DEFAULT gen_random_uuid(),
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'delivered', 'failed', 'dead_letter')),
    status_code INT,
    response_body TEXT,                -- Truncated to 1KB
    attempt INT NOT NULL DEFAULT 0,
    max_attempts INT NOT NULL DEFAULT 5,
    next_retry_at TIMESTAMPTZ,
    delivered_at TIMESTAMPTZ,
    latency_ms INT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE webhook_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_deliveries FORCE ROW LEVEL SECURITY;
CREATE POLICY webhook_deliveries_tenant_isolation ON webhook_deliveries
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_webhook_deliveries_endpoint ON webhook_deliveries(endpoint_id);
CREATE INDEX idx_webhook_deliveries_retry ON webhook_deliveries(next_retry_at)
    WHERE status = 'pending' AND next_retry_at IS NOT NULL;
```

#### Webhook CRUD API (CP0-E-02) — `webhooks/index.ts`

**JWT auth** (not SCIM tokens). Routes:

| Method | Path | Action |
|--------|------|--------|
| `POST` | `/api/v1/webhooks` | Register (url, events[], description) |
| `GET` | `/api/v1/webhooks` | List for tenant |
| `GET` | `/api/v1/webhooks/:id` | Details + recent deliveries |
| `PATCH` | `/api/v1/webhooks/:id` | Update URL/events/active/description |
| `DELETE` | `/api/v1/webhooks/:id` | Delete + cascade deliveries |
| `GET` | `/api/v1/webhooks/:id/deliveries` | Paginated delivery logs (CP0-E-10) |
| `POST` | `/api/v1/webhooks/:id/test` | Sync ping delivery (CP0-E-11) |
| `POST` | `/api/v1/webhooks/:id/rotate-secret` | Secret rotation (CP0-E-12) |

**POST /api/v1/webhooks flow:**
1. Validate JWT → `tenantId`, `userId`
2. Validate body: `url` (HTTPS required), `events` (non-empty, all valid types), `description`
3. URL validation via `validateWebhookUrl()` — reject HTTP, localhost, private IPs
4. Validate events against `webhook_event_types` table
5. Generate secret: `crypto.randomUUID() + "-" + crypto.randomUUID()`
6. Store SHA-256 hash in `secret_hash`
7. Insert `webhook_endpoints` row
8. `logAuditEvent()` action `webhook.registered`
9. Return 201 + webhook ID + raw secret (shown once)

#### Signature Generation (CP0-E-03) — `shared/webhook-signature.ts`

Stripe pattern:
- `signWebhookPayload(secret, payload, webhookId)` → `{ "X-Drift-Signature": "t=epoch,v1=hmac", "X-Drift-Timestamp": "epoch", "X-Drift-Webhook-Id": "uuid" }`
- `verifyWebhookSignature(secret, payload, signatureHeader, tolerance=300s)` → boolean
- Constant-time comparison via `timingSafeEqual()`
- During rotation: sign with both old and new secrets → `t=epoch,v1=hmac_old,v2=hmac_new`

#### URL Validator — `shared/url-validator.ts`

- HTTPS only (reject `http://`)
- Block: `localhost`, `127.0.0.1`, `0.0.0.0`, `::1`
- Block private: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`
- Parse with `new URL()` — reject invalid

**Gate:** Registration creates endpoint. Secret returned once. URL validation rejects HTTP/localhost/private.

---

### Sub-Phase E2: Dispatch Engine (CP0-E-04, CP0-E-05)

**Goal:** Async delivery with retry and dead letter.

**File:** `supabase/functions/webhook-dispatch/index.ts`

**Dispatch flow:**
1. Query matching endpoints: `WHERE tenant_id = $1 AND active = true AND $2 = ANY(events)`
2. For each: serialize payload → sign HMAC → POST to URL (10s timeout) → record delivery
3. On 2xx: `status = 'delivered'`, record `status_code`, `latency_ms`
4. On 5xx/timeout: schedule retry, increment `attempt`
5. Circuit breaker: 50 consecutive failures → `active = false`, audit `webhook.circuit_broken`

**Secret storage for signing:** Add `encrypted_secret BYTEA` to `webhook_endpoints` (AES-256-GCM with `SUPABASE_WEBHOOK_ENCRYPTION_KEY` env var). Decrypt at dispatch time. Alternative: derive with `HMAC-SHA256(master_key, endpoint_id)`.

**Retry (CP0-E-05):**
- Backoff: `[1000, 2000, 4000, 8000, 16000]` ms
- After max attempts → `status = 'dead_letter'`
- Retries processed by pg_cron job (every 10s) calling the dispatch function, or query `WHERE status='pending' AND next_retry_at <= now()`

**Gate:** Failed deliveries retried. After 5 failures → dead letter.

---

### Sub-Phase E3: Event Wiring (CP0-E-06 through CP0-E-09)

**Goal:** Wire 7 core events to dispatch.

**File:** `supabase/functions/shared/webhook-dispatch.ts` — `dispatchWebhookEvent(supabase, tenantId, payload)` helper. Always fire-and-forget.

**File:** `supabase/functions/shared/webhook-types.ts` — TypeScript interfaces for all 8 event payloads (7 core + ping).

**Event catalog (CP0-E-06):** `ScanCompletedPayload`, `GateFailedPayload`, `ViolationNewPayload`, `GroundingDegradedPayload`, `ApiKeyExpiringPayload`, `SyncFailedPayload`, `ProjectLifecyclePayload`, `PingPayload`

**Wiring into sync (CP0-E-07, E-08, E-09):**
- Create minimal `supabase/functions/sync/index.ts` if it doesn't exist
- After sync upsert: `dispatchWebhookEvent()` for `scan.completed`
- Check gate results: fire `gate.failed` for each failing gate
- Check violations: fire `violation.new` for new critical/high violations
- **Dispatch is fire-and-forget** — sync never blocks on webhooks

**Gate:** Sync → matching webhooks fire. Payloads match schemas.

---

### Sub-Phase E4: Delivery Logs, Test, Rotation (CP0-E-10, E-11, E-12)

**Delivery logs (E-10):** `GET /api/v1/webhooks/:id/deliveries` — cursor pagination, filters by `event_type`/`status`, ordered by `created_at DESC`.

**Test endpoint (E-11):** `POST /api/v1/webhooks/:id/test` — synchronous `ping` delivery. Returns `{ success, status_code, latency_ms, response_body }`. Real HMAC signing.

**Secret rotation (E-12):** `POST /api/v1/webhooks/:id/rotate-secret`
1. Generate new secret, store hash in `secret_hash_new`, set `secret_rotated_at = now()`
2. During 24h: sign with both (`v1=old, v2=new`)
3. pg_cron at 24h: `secret_hash = secret_hash_new`, clear `secret_hash_new`
4. Return raw new secret (once). Audit: `webhook.secret_rotated`

---

## Tests (10 tests)

| ID | Test | Proves |
|----|------|--------|
| CT0-E-01 | POST → GET → endpoint in list with correct URL/events | Registration round-trip |
| CT0-E-02 | Register → trigger → capture delivery → verify HMAC matches | Signature verification |
| CT0-E-03 | Mock server returns 500 → verify 5 retries with backoff timing | Retry with backoff |
| CT0-E-04 | 5 consecutive 500s → status=`dead_letter`, no more retries | Dead letter |
| CT0-E-05 | Register for `scan.completed` → POST /sync → webhook fires | scan.completed wired |
| CT0-E-06 | Sync with failing gate → `gate.failed` webhook with name+score | gate.failed wired |
| CT0-E-07 | `http://` → 400. `https://localhost` → 400. Private IP → 400. | URL validation |
| CT0-E-08 | Tenant A webhook → tenant B cannot GET/PATCH/DELETE | Tenant isolation |
| CT0-E-09 | POST /:id/test → mock receives ping with valid signature | Test endpoint |
| CT0-E-10 | Rotate → old valid → new valid → after 24h old invalid | Secret rotation |

---

## Testing Standards

### What Makes a Good Test
- **Tests security boundaries** — cross-tenant access, URL validation, SSRF prevention
- **Verifies signature correctness** — independently recompute HMAC and compare byte-for-byte
- **Exercises retry lifecycle** — mock 500s → verify 5 attempts → dead letter → no 6th attempt
- **Uses real Supabase local dev** — real Postgres + RLS, not mocks

### What Makes a Bad Test
- Mocks the dispatch engine instead of testing real HTTP delivery
- Skips RLS by using service_role for assertions
- Only checks registration without verifying delivery
- Tests Hono routing instead of webhook reliability

### Required Patterns
- **Tenant isolation:** Every CRUD test includes cross-tenant assertion
- **Signature correctness:** CT0-E-02 recomputes HMAC independently
- **Retry timing:** CT0-E-03 checks `next_retry_at` values match backoff schedule
- **Dead letter finality:** CT0-E-04 verifies no new attempts after dead letter
- **URL validation exhaustive:** Test HTTP, localhost, 127.0.0.1, 10.x, 172.16.x, 192.168.x → all rejected
- **Audit verification:** Every mutation test checks `cloud_audit_log` entry

---

## Architecture Constraints

1. **Secrets stored hashed/encrypted.** Never plaintext. Raw shown once at registration.
2. **RLS on `webhook_endpoints` and `webhook_deliveries`.** ENABLE + FORCE + tenant policy.
3. **`SET LOCAL app.tenant_id` per request.** Every handler.
4. **HTTPS-only URLs.** No HTTP, localhost, private IPs. Prevents SSRF.
5. **HMAC-SHA256 on every delivery.** Stripe `t=timestamp,v1=hmac` pattern. 5-min tolerance. Constant-time compare.
6. **Delivery never blocks trigger.** Always async fire-and-forget.
7. **Circuit breaker at 50 failures.** Admin re-enables via PATCH.
8. **Dead letter after 5 retries.** No infinite loops.
9. **Audit every mutation.** Register, update, delete, rotate, circuit-break.
10. **Idempotency key on every delivery.** `X-Drift-Webhook-Id` UUID.

---

## Forbidden Actions

1. **Do NOT store raw secrets.** Hash or encrypt only.
2. **Do NOT allow HTTP URLs.** HTTPS only, no exceptions.
3. **Do NOT allow localhost/private IP URLs.** SSRF prevention.
4. **Do NOT block sync on webhook delivery.** Always fire-and-forget.
5. **Do NOT retry indefinitely.** 5 max, then dead letter.
6. **Do NOT expose secrets in GET responses.** Metadata only.
7. **Do NOT skip URL validation on PATCH.** Re-validate updated URLs.
8. **Do NOT use MD5/SHA-1.** HMAC-SHA256 only.
9. **Do NOT expose internal errors in payloads.** Generic messages only.
10. **Do NOT modify Rust crates.** Pure TypeScript/Deno/SQL.

---

## Effort Estimate

| Sub-Phase | Tasks | Effort | Key Risk |
|-----------|-------|--------|----------|
| E1: Infrastructure | CP0-E-01 to E-03 | 0.5-1d | Secret storage design |
| E2: Dispatch Engine | CP0-E-04, E-05 | 0.5-1d | Retry processor mechanism |
| E3: Event Wiring | CP0-E-06 to E-09 | 0.5-1d | Sync endpoint may need stub |
| E4: Logs+Test+Rotation | CP0-E-10 to E-12 | 0.5d | Dual-validity window |
| Tests | CT0-E-01 to E-10 | 0.5d | Mock server for deliveries |
| **Total** | **12 impl + 10 test** | **2-3 days** | |

**Dependencies:** Phase D complete (Supabase project + shared helpers). Phase 1 sync endpoint soft dependency (stub if needed).

---

## Subsystems That Are Clean (do NOT modify)

- **All Rust crates** — no Rust in Phase E
- **Phase D files** — `scim-users/`, `scim-groups/`, `scim-admin/`, `scim-auth.ts`, `scim-errors.ts`, `scim-types.ts`, `deprovision.ts` — do not modify
- **Phase D migrations** — `20260211000000` through `20260211000003` — do not modify
- **`packages/drift-cli/`**, **`packages/drift-mcp/`** — server-side only
- You MAY import: `shared/audit.ts`, `shared/supabase.ts`, `shared/tenant-context.ts`

---

## Verification Commands

```bash
# Migration applies:
supabase db reset
# Expected: 0 errors, webhook tables created

# RLS policies exist + forced:
psql "$SUPABASE_DB_URL" -c "SELECT tablename, policyname FROM pg_policies WHERE tablename IN ('webhook_endpoints','webhook_deliveries');"
psql "$SUPABASE_DB_URL" -c "SELECT relname, relforcerowsecurity FROM pg_class WHERE relname IN ('webhook_endpoints','webhook_deliveries');"

# Event types seeded:
psql "$SUPABASE_DB_URL" -c "SELECT count(*) FROM webhook_event_types;"
# Expected: 9

# Edge Functions compile:
supabase functions serve
# Expected: webhooks, webhook-dispatch registered

# No secrets in plaintext:
grep -rn "secret" supabase/migrations/ | grep -v "hash\|encrypt\|_hash\|SHA"

# HMAC-SHA256 used:
grep -rn "SHA-256\|HMAC" supabase/functions/shared/webhook-signature.ts

# Audit on mutations:
grep -rn "logAuditEvent" supabase/functions/webhooks/

# No service_role in source:
grep -rn "SUPABASE_SERVICE_ROLE_KEY" supabase/functions/ | grep -v "Deno.env.get"

# Full tests:
cd supabase && deno test tests/ --allow-net --allow-env
# Expected: 10 Phase E + 14 Phase D = 24 tests, 0 failures
```

---

## Critical Questions Per Sub-Phase

### After E1:
- How are secrets stored? (SHA-256 hash or AES-256-GCM encrypted. Never raw.)
- What URLs are rejected? (HTTP, localhost, private IPs)
- How many event types seeded? (9)

### After E2:
- What happens on failure? (5 retries: 1s→2s→4s→8s→16s. Then dead letter.)
- Circuit breaker? (50 consecutive failures → deactivated)
- Does delivery block sync? (Never — fire-and-forget)

### After E3:
- Which events fire after sync? (`scan.completed` always, `gate.failed` per failing gate, `violation.new` per new critical/high)
- Cross-tenant? (No — RLS enforced)

### After E4:
- Rotation window? (24h dual-validity)
- Test endpoint return? (`{ success, status_code, latency_ms, response_body }`)

---

## Quality Gate (QG-E) — All Must Pass

- [ ] Webhook CRUD API works (register, list, update, delete)
- [ ] HMAC-SHA256 signature on every delivery
- [ ] Retry with exponential backoff (5 attempts)
- [ ] Dead letter for permanently failed deliveries
- [ ] `scan.completed`, `gate.failed`, `violation.new` events wired
- [ ] Delivery logs queryable (`GET /api/v1/webhooks/:id/deliveries`)
- [ ] Test endpoint works (`POST /:id/test` → ping delivered)
- [ ] Secret rotation with 24h dual-validity
- [ ] URL validation blocks HTTP/localhost/private IPs
- [ ] Tenant isolation on all new tables
- [ ] All 10 Phase E tests pass
- [ ] Audit log for all webhook mutations
- [ ] Circuit breaker at 50 consecutive failures
- [ ] RLS enabled + forced on all new tables
- [ ] No secrets stored in plaintext

---

## Appendix A: Webhook Payload Schema Reference

### scan.completed

```json
{
  "event": "scan.completed",
  "project_id": "uuid",
  "scan_id": "uuid",
  "files_scanned": 1707,
  "patterns_detected": 959,
  "violations_found": 12,
  "duration_ms": 9600,
  "timestamp": "2026-02-11T12:00:00Z"
}
```

### gate.failed

```json
{
  "event": "gate.failed",
  "project_id": "uuid",
  "gate_name": "SecurityGate",
  "score": 0.45,
  "threshold": 0.70,
  "summary": "SecurityGate failed: 0.45 < 0.70 (3 critical violations)",
  "violations": [
    { "rule": "hardcoded-secret", "severity": "critical", "count": 2 },
    { "rule": "sql-injection", "severity": "critical", "count": 1 }
  ],
  "timestamp": "2026-02-11T12:00:00Z"
}
```

### violation.new

```json
{
  "event": "violation.new",
  "project_id": "uuid",
  "rule_id": "hardcoded-secret",
  "severity": "critical",
  "file_path": "src/config/database.ts",
  "line": 42,
  "message": "Hardcoded database password detected",
  "timestamp": "2026-02-11T12:00:00Z"
}
```

### grounding.degraded

```json
{
  "event": "grounding.degraded",
  "project_id": "uuid",
  "memory_id": "uuid",
  "memory_type": "Observation",
  "old_score": 0.72,
  "new_score": 0.31,
  "threshold": 0.50,
  "timestamp": "2026-02-11T12:00:00Z"
}
```

### apikey.expiring

```json
{
  "event": "apikey.expiring",
  "tenant_id": "uuid",
  "key_name": "CI Pipeline Key",
  "key_id": "uuid",
  "expires_at": "2026-02-18T12:00:00Z",
  "days_remaining": 7,
  "timestamp": "2026-02-11T12:00:00Z"
}
```

### sync.failed

```json
{
  "event": "sync.failed",
  "project_id": "uuid",
  "error": "Connection timeout after 30s",
  "retry_count": 3,
  "last_attempt_at": "2026-02-11T11:55:00Z",
  "timestamp": "2026-02-11T12:00:00Z"
}
```

### project.created / project.deleted

```json
{
  "event": "project.created",
  "project_id": "uuid",
  "project_name": "drift-monorepo",
  "tenant_id": "uuid",
  "actor_id": "uuid",
  "timestamp": "2026-02-11T12:00:00Z"
}
```

### ping (test event)

```json
{
  "event": "ping",
  "webhook_id": "uuid",
  "message": "This is a test webhook delivery from Drift.",
  "timestamp": "2026-02-11T12:00:00Z"
}
```

### Delivery Headers

| Header | Value | Purpose |
|--------|-------|---------|
| `Content-Type` | `application/json` | JSON payload |
| `X-Drift-Signature` | `t=1707660000,v1=abc123...` | HMAC-SHA256 signature |
| `X-Drift-Timestamp` | `1707660000` | Unix epoch seconds |
| `X-Drift-Webhook-Id` | `uuid` | Idempotency key |
| `X-Drift-Event` | `scan.completed` | Event type |
| `User-Agent` | `Drift-Webhooks/1.0` | Identifies Drift |

---

## Appendix B: Webhook Secret Lifecycle

```
Registration:
  POST /api/v1/webhooks
       │
       ▼
  Generate secret = UUID + "-" + UUID
       │
       ├──── SHA-256 hash ──→ DB: secret_hash (permanent)
       │
       └──── Raw secret ───→ Response: shown ONCE, never retrievable

Dispatch (signing):
  dispatchWebhookEvent()
       │
       ▼
  Decrypt encrypted_secret (AES-256-GCM)
  OR derive via HMAC-SHA256(master_key, endpoint_id)
       │
       ▼
  HMAC-SHA256(secret, timestamp + "." + payload)
       │
       ▼
  X-Drift-Signature: t=epoch,v1=hmac_hex

Rotation:
  POST /api/v1/webhooks/:id/rotate-secret
       │
       ▼
  Generate new secret
  DB: secret_hash_new = SHA-256(new), secret_rotated_at = now()
       │
       ▼ 0-24h window:
       │  Deliveries signed with BOTH secrets
       │  X-Drift-Signature: t=epoch,v1=hmac_old,v2=hmac_new
       │  Consumer checks v1 (existing) then v2 (after updating)
       ▼
  pg_cron at 24h:
       secret_hash = secret_hash_new
       secret_hash_new = NULL
       secret_rotated_at = NULL
```

---

## Appendix C: Cross-Phase Dependency Map

```
Phase E (Webhook & Event Notification)
│
├── HARD DEPENDS ON ─────────────────────────────────────────────────
│   ├── tenants              ← Phase D prerequisite migration (20260211000000)
│   ├── set_tenant_context() ← Phase D prerequisite migration (20260211000000)
│   ├── cloud_audit_log      ← Phase D placeholder migration (20260211000003)
│   ├── shared/audit.ts      ← Phase D shared helpers
│   ├── shared/supabase.ts   ← Phase D shared helpers
│   └── shared/tenant-context.ts ← Phase D shared helpers
│
├── SOFT DEPENDS ON (stub if missing) ───────────────────────────────
│   └── POST /api/v1/sync   ← Phase 1 (Cloud Infrastructure)
│       If sync endpoint doesn't exist, create minimal stub
│       that accepts payloads and fires webhook events.
│       Full sync implementation is Phase 1's scope.
│
├── PRODUCES (consumed by later phases) ─────────────────────────────
│   ├── webhook_endpoints    → Phase F (audit log can trigger webhooks)
│   ├── webhook_deliveries   → Phase G (integration tests verify end-to-end)
│   ├── dispatchWebhookEvent() → Phase F (team changes fire webhooks)
│   │                          → Phase G (test full event → webhook flow)
│   └── webhook-signature.ts → Phase G (verify signatures in integration tests)
│
└── INDEPENDENT OF ──────────────────────────────────────────────────
    ├── Phase A (Drift storage traits) — no Rust code in Phase E
    ├── Phase B (Drift engine + NAPI) — no Rust code in Phase E
    ├── Phase C (Bridge storage) — no Rust code in Phase E
    └── Phase D (SCIM) — Phase E does not modify SCIM endpoints.
                          Phase D's deprovision() writes to audit log;
                          Phase E can subscribe to audit log events for
                          webhook dispatch, but this is optional.
```

**Key decision:** Phase E does NOT fire webhooks from Phase D's SCIM operations retroactively. If SCIM event webhooks are desired (e.g., `user.deprovisioned`), that wiring happens in Phase G or a future iteration. Phase E focuses on the 7 core events listed in GAP-02.

**If Phase 1 sync endpoint doesn't exist:** Create a minimal `supabase/functions/sync/index.ts` that accepts a POST body with scan summary and fires `dispatchWebhookEvent()`. This stub will be replaced by the full sync implementation in Phase 1.

---

## Appendix D: Implementation Plan Cross-Reference

Every task ID from `CLOUD-P0-IMPLEMENTATION-PLAN.md` Phase E, mapped to this prompt:

### Implementation Tasks

| Plan ID | Task | Prompt Section | Status |
|---------|------|----------------|--------|
| CP0-E-01 | `webhook_endpoints` + `webhook_deliveries` migration | Sub-Phase E1: Migration | Covered |
| CP0-E-02 | Webhook registration API (CRUD) | Sub-Phase E1: CRUD API | Covered |
| CP0-E-03 | HMAC-SHA256 signature module | Sub-Phase E1: Signature Generation | Covered |
| CP0-E-04 | Async dispatch engine | Sub-Phase E2: Dispatch Engine | Covered |
| CP0-E-05 | Retry with exponential backoff + dead letter | Sub-Phase E2: Retry Logic | Covered |
| CP0-E-06 | Event catalog with typed payloads | Sub-Phase E3: Event Catalog | Covered |
| CP0-E-07 | Wire `scan.completed` event | Sub-Phase E3: Event Wiring | Covered |
| CP0-E-08 | Wire `gate.failed` event | Sub-Phase E3: Event Wiring | Covered |
| CP0-E-09 | Wire `violation.new` event | Sub-Phase E3: Event Wiring | Covered |
| CP0-E-10 | Delivery logs API | Sub-Phase E4: Delivery Logs | Covered |
| CP0-E-11 | Test endpoint (`POST /:id/test`) | Sub-Phase E4: Test Endpoint | Covered |
| CP0-E-12 | Secret rotation with dual-validity | Sub-Phase E4: Secret Rotation | Covered |

### Test Tasks

| Plan ID | Test | Prompt Section | Status |
|---------|------|----------------|--------|
| CT0-E-01 | Webhook registration + list round-trip | Tests: CT0-E-01 | Covered |
| CT0-E-02 | HMAC signature verification | Tests: CT0-E-02 | Covered |
| CT0-E-03 | Retry with exponential backoff timing | Tests: CT0-E-03 | Covered |
| CT0-E-04 | Dead letter after max retries | Tests: CT0-E-04 | Covered |
| CT0-E-05 | scan.completed fires on sync | Tests: CT0-E-05 | Covered |
| CT0-E-06 | gate.failed fires on failing gate | Tests: CT0-E-06 | Covered |
| CT0-E-07 | URL validation rejects HTTP/localhost/private | Tests: CT0-E-07 | Covered |
| CT0-E-08 | Tenant isolation on webhook CRUD | Tests: CT0-E-08 | Covered |
| CT0-E-09 | Test endpoint delivers ping with valid sig | Tests: CT0-E-09 | Covered |
| CT0-E-10 | Secret rotation dual-validity lifecycle | Tests: CT0-E-10 | Covered |

### Quality Gate Items

| QG Item | Prompt Coverage |
|---------|-----------------|
| Webhook CRUD works | Sub-Phase E1 |
| HMAC-SHA256 on every delivery | Sub-Phase E1: webhook-signature.ts |
| Retry with backoff | Sub-Phase E2: Retry Logic |
| Dead letter queue | Sub-Phase E2: Retry Logic |
| Core events wired | Sub-Phase E3 |
| Delivery logs queryable | Sub-Phase E4: Delivery Logs |
| Test endpoint works | Sub-Phase E4: Test Endpoint |
| Secret rotation | Sub-Phase E4: Secret Rotation |
| URL validation | Sub-Phase E1: url-validator.ts |
| Tenant isolation | Migration RLS + Tests CT0-E-08 |
| All 10 tests pass | Tests section |
| Audit log entries | Architecture Constraint #9 |
| Circuit breaker | Sub-Phase E2: Dispatch Engine |
| RLS enabled + forced | Migration + Verification Commands |
| No plaintext secrets | Architecture Constraint #1 + Grep Commands |

### Tracker Cross-Reference

| Tracker Ref | Tracker Section | Plan Phase |
|-------------|-----------------|------------|
| GAP-02 | §11b (line ~1022) | Phase E (this phase) |
| P6-06 | §8 Phase 6b (line ~845) | CP0-E-01 (tables) |
| P6-07 | §8 Phase 6b (line ~846) | CP0-E-02 (CRUD API) |
| P6-08 | §8 Phase 6b (line ~847) | CP0-E-03 (signatures) |
| P6-09 | §8 Phase 6b (line ~848) | CP0-E-04 to E-05 (dispatch + retry) |
| P6-10 | §8 Phase 6b (line ~849) | CP0-E-06 to E-09 (event wiring) |

**Coverage: 12/12 impl tasks + 10/10 test tasks + 15/15 QG items + 6/6 tracker refs = 100%**
