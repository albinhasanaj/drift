# Agent Prompt: Cloud P0 Phase F — Audit Log API, Team Management & IP Allowlisting (Enterprise GAP-03/04/05)

## Your Mission

You are implementing the final three enterprise P0 gaps that block SOC 2 compliance and enterprise buyer evaluation:

1. **Audit Log API (GAP-03)** — Searchable, exportable, SIEM-ready audit trail. Blocks SOC 2 CC7.1 (Monitoring & Detection).
2. **Team Management (GAP-04)** — Org hierarchy with teams, invitations, seat limits, and ownership transfer.
3. **IP Allowlisting (GAP-05)** — Per-tenant CIDR-based API access control. Blocks SOC 2 CC6.1 (Logical Access Controls).

This phase is **Supabase Edge Functions (Deno/TypeScript) + PostgreSQL** — no Rust except for a single CLI command (CP0-F-18). It builds on Phase D's Supabase project and Phase E's webhook infrastructure.

When this phase is done:
- **Audit log is immutable** — INSERT-only, no UPDATE/DELETE. RLS-enforced tenant isolation.
- **Audit query API** — cursor-based pagination + 5 filter types + JSON Lines export for SIEM
- **Team hierarchy** — Org → Teams → Projects with team-scoped access via RLS
- **Invitation flow** — email invite → accept → join tenant with role
- **Seat enforcement** — plan-based seat limits return 402 when exceeded
- **IP allowlisting** — CIDR-based, with temporary entries and CLI escape hatch
- **Ownership transfer** — atomic org ownership transfer with audit trail

**Phase D created placeholder tables for `teams`, `team_memberships`, and `cloud_audit_log`.** Phase F will `ALTER TABLE` these with additional columns, constraints, and indexes. The existing `CREATE TABLE IF NOT EXISTS` + `ALTER TABLE` pattern ensures safe ordering.

---

## Documents You MUST Read Before Writing Any Code

1. **`docs/v2-research/CLOUD-P0-IMPLEMENTATION-PLAN.md`** — Phase F (lines ~431-507). 18 impl tasks (CP0-F-01 to F-18) + 14 tests + Quality Gate.
2. **`docs/v2-research/BRIDGE-CLOUD-READINESS-TRACKER.md`** — GAP-03 (lines ~1071-1109), GAP-04 (lines ~1111-1162), GAP-05 (lines ~1164-1185). Table schemas and missing features.
3. **`supabase/migrations/20260211000003_phase_f_placeholders.sql`** — Phase D created placeholder `teams`, `team_memberships`, `cloud_audit_log`. Study what exists before ALTERing.
4. **`supabase/functions/shared/audit.ts`** — Phase D created `logAuditEvent()`. Phase F enhances this and builds the query/export API on top.
5. **`supabase/functions/shared/`** — Reuse `supabase.ts`, `tenant-context.ts`. Phase E's `webhook-dispatch.ts` can be imported to fire webhooks on team/audit events.

After reading, you should answer:
- What immutability guarantees does the audit log need? (INSERT-only. RLS policies block UPDATE/DELETE for all non-superusers.)
- What are the 5 audit query filters? (`actor`, `action`, `resource_type`, `after`, `before`)
- What tables does Phase D's placeholder migration already create? (`teams`, `team_memberships`, `cloud_audit_log` — all with RLS)
- What columns need to be added to placeholder tables? (`teams`: `team_projects` relation. `team_memberships`: already complete. `cloud_audit_log`: indexes + partition hint.)
- What is the IP allowlist default behavior? (Empty list = all IPs allowed. No lockout on fresh setup.)
- What SOC 2 controls does this phase address? (CC7.1 for audit, CC6.1 for IP allowlisting)

---

## Phase Execution Order

Phase F has three independent sub-phases (F1, F2, F3) that can run in parallel. Within each, tasks are sequential.

### Sub-Phase F1: Audit Log API (CP0-F-01 through CP0-F-06)

**Goal:** Enhance the placeholder audit log table, build query/export APIs, add retention and Realtime.

#### Migration: Audit Log Enhancements (CP0-F-01)

**File:** `supabase/migrations/20260211000005_audit_log_enhancements.sql`

Phase D's placeholder migration (`20260211000003`) already created `cloud_audit_log` with RLS + immutability policies. This migration adds performance indexes and optional partitioning.

```sql
-- Performance indexes (idempotent — IF NOT EXISTS)
CREATE INDEX IF NOT EXISTS idx_audit_tenant_created ON cloud_audit_log(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_tenant_actor ON cloud_audit_log(tenant_id, actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_tenant_action ON cloud_audit_log(tenant_id, action);
CREATE INDEX IF NOT EXISTS idx_audit_tenant_resource ON cloud_audit_log(tenant_id, resource_type);

-- Verify immutability policies exist (from Phase D placeholder)
-- If running without Phase D, create them:
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE tablename = 'cloud_audit_log' AND policyname = 'audit_no_update'
    ) THEN
        EXECUTE 'CREATE POLICY audit_no_update ON cloud_audit_log FOR UPDATE USING (false)';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE tablename = 'cloud_audit_log' AND policyname = 'audit_no_delete'
    ) THEN
        EXECUTE 'CREATE POLICY audit_no_delete ON cloud_audit_log FOR DELETE USING (false)';
    END IF;
END
$$;
```

#### Audit Event Wiring (CP0-F-02)

Phase D already created `shared/audit.ts` with `logAuditEvent()`. Verify it covers:
- `tenant_id`, `actor_id`, `actor_email`, `action`, `resource_type`, `resource_id`, `metadata`, `ip_address`, `user_agent`
- IP from `X-Forwarded-For` header
- User agent from `User-Agent` header
- `action` follows `resource.verb` convention: `project.delete`, `apikey.create`, `webhook.register`, etc.

If `logAuditEvent()` is missing any fields, enhance it. **Do not rewrite** — extend.

Ensure ALL mutating handlers across all Edge Functions call `logAuditEvent()`:
- Phase D: SCIM endpoints (already wired)
- Phase E: Webhook endpoints (already wired)
- Phase F: Team, invitation, IP allowlist, settings endpoints (wire in this phase)

#### Audit Query API (CP0-F-03)

**File:** `supabase/functions/audit/index.ts` (NEW — Hono router, JWT auth)

**Route:** `GET /api/v1/audit`

- Cursor-based pagination: `?cursor=<uuid>&limit=100` (max 200)
- Filters:
  - `?actor=user@email.com` — filter by `actor_email`
  - `?action=project.delete` — filter by `action`
  - `?resource_type=project` — filter by `resource_type`
  - `?after=2026-01-01T00:00:00Z` — `created_at > after`
  - `?before=2026-02-01T00:00:00Z` — `created_at < before`
- All filters are ANDed
- Response: `{ data: AuditEvent[], pagination: { cursor: string | null, has_more: boolean } }`
- Ordered by `created_at DESC`

```typescript
// Query construction (parameterized — NO string concatenation)
let query = supabase
  .from("cloud_audit_log")
  .select("*")
  .order("created_at", { ascending: false })
  .limit(limit + 1);  // +1 to detect has_more

if (actor) query = query.eq("actor_email", actor);
if (action) query = query.eq("action", action);
if (resourceType) query = query.eq("resource_type", resourceType);
if (after) query = query.gt("created_at", after);
if (before) query = query.lt("created_at", before);
if (cursor) query = query.lt("id", cursor);
```

#### Audit Export API (CP0-F-04)

**Route:** `GET /api/v1/audit/export`

- Same filters as query API
- Returns JSON Lines (NDJSON): one JSON object per line
- `Content-Type: application/x-ndjson`
- Streams response (not buffered) for large exports
- Max 10,000 rows per export (prevent abuse)

```typescript
// Streaming NDJSON response
const encoder = new TextEncoder();
const stream = new ReadableStream({
  async start(controller) {
    let cursor: string | undefined;
    let total = 0;
    while (total < 10000) {
      const { data } = await fetchBatch(cursor, 500);
      if (!data?.length) break;
      for (const row of data) {
        controller.enqueue(encoder.encode(JSON.stringify(row) + "\n"));
        total++;
      }
      cursor = data[data.length - 1].id;
    }
    controller.close();
  }
});
return new Response(stream, {
  headers: { "Content-Type": "application/x-ndjson" }
});
```

#### Audit Retention (CP0-F-05)

**File:** `supabase/migrations/20260211000006_audit_retention.sql`

```sql
-- Retention policy function
CREATE OR REPLACE FUNCTION cleanup_expired_audit_logs()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    plan_record RECORD;
BEGIN
    -- Free: 30 days
    DELETE FROM cloud_audit_log
    WHERE created_at < now() - interval '30 days'
    AND tenant_id IN (SELECT id FROM tenants WHERE plan = 'free');

    -- Pro: 1 year
    DELETE FROM cloud_audit_log
    WHERE created_at < now() - interval '1 year'
    AND tenant_id IN (SELECT id FROM tenants WHERE plan = 'pro');

    -- Team: 2 years
    DELETE FROM cloud_audit_log
    WHERE created_at < now() - interval '2 years'
    AND tenant_id IN (SELECT id FROM tenants WHERE plan = 'team');

    -- Enterprise: no automatic cleanup (custom retention)
END;
$$;

-- Schedule daily cleanup via pg_cron (if available)
-- SELECT cron.schedule('audit-log-retention', '0 3 * * *', 'SELECT cleanup_expired_audit_logs()');
```

#### Audit Realtime (CP0-F-06)

Enterprise tenants subscribe to `audit:{tenant_id}` Realtime channel. Supabase Realtime automatically broadcasts INSERT events on tables with Realtime enabled.

```sql
-- Enable Realtime on cloud_audit_log (add to migration)
ALTER PUBLICATION supabase_realtime ADD TABLE cloud_audit_log;
```

**Gate:** Audit query returns filtered results. Export streams NDJSON. Immutability verified (UPDATE/DELETE blocked).

---

### Sub-Phase F2: Team & Organization Management (CP0-F-07 through CP0-F-13)

**Goal:** Team hierarchy, invitations, seat management, ownership transfer.

#### Migration: Team Enhancements + New Tables (CP0-F-07)

**File:** `supabase/migrations/20260211000007_teams_full.sql`

Phase D placeholders created `teams` and `team_memberships`. This migration adds `team_projects`, `invitations`, and enhances existing tables.

```sql
-- ── Team Projects (NEW) ──
CREATE TABLE IF NOT EXISTS team_projects (
    team_id UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    assigned_by UUID NOT NULL,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (team_id, project_id)
);
ALTER TABLE team_projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE team_projects FORCE ROW LEVEL SECURITY;
CREATE POLICY team_projects_isolation ON team_projects
    USING (team_id IN (
        SELECT id FROM teams WHERE tenant_id = current_setting('app.tenant_id', true)::UUID
    ));

-- ── Invitations (NEW) ──
CREATE TABLE IF NOT EXISTS invitations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'member'
        CHECK (role IN ('admin', 'member', 'viewer')),
    team_id UUID REFERENCES teams(id) ON DELETE SET NULL,
    invited_by UUID NOT NULL,
    token TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL DEFAULT now() + interval '7 days',
    accepted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE invitations FORCE ROW LEVEL SECURITY;
CREATE POLICY invitations_tenant_isolation ON invitations
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_invitations_token ON invitations(token);
CREATE INDEX idx_invitations_tenant ON invitations(tenant_id);

-- ── Subscriptions (for seat limits) ──
CREATE TABLE IF NOT EXISTS subscriptions (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    plan TEXT NOT NULL DEFAULT 'free'
        CHECK (plan IN ('free', 'pro', 'team', 'enterprise')),
    seat_limit INT NOT NULL DEFAULT 5,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE subscriptions FORCE ROW LEVEL SECURITY;
CREATE POLICY subscriptions_isolation ON subscriptions
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
```

#### Team CRUD API (CP0-F-08)

**File:** `supabase/functions/teams/index.ts` (NEW — Hono router, JWT auth)

| Method | Path | Action | Auth |
|--------|------|--------|------|
| `POST` | `/api/v1/teams` | Create team | admin/owner |
| `GET` | `/api/v1/teams` | List teams for tenant | any member |
| `GET` | `/api/v1/teams/:id` | Team details + members | team member |
| `PATCH` | `/api/v1/teams/:id` | Update name/description | admin/owner/lead |
| `DELETE` | `/api/v1/teams/:id` | Delete (cascade memberships + projects) | admin/owner |

Every mutation calls `logAuditEvent()` with appropriate `team.created`, `team.updated`, `team.deleted` actions.

#### Team Membership Management (CP0-F-09)

| Method | Path | Action | Auth |
|--------|------|--------|------|
| `POST` | `/api/v1/teams/:id/members` | Add member (by user_id or email) | admin/owner/lead |
| `DELETE` | `/api/v1/teams/:id/members/:user_id` | Remove member | admin/owner/lead |
| `PATCH` | `/api/v1/teams/:id/members/:user_id` | Change role (lead/member) | admin/owner |
| `GET` | `/api/v1/teams/:id/members` | List with roles | team member |

#### Team-Project Assignment (CP0-F-10)

| Method | Path | Action | Auth |
|--------|------|--------|------|
| `POST` | `/api/v1/teams/:id/projects` | Assign project to team | admin/owner |
| `DELETE` | `/api/v1/teams/:id/projects/:project_id` | Unassign | admin/owner |
| `GET` | `/api/v1/teams/:id/projects` | List assigned projects | team member |

**RLS policy for project-scoped access:** Team members can only access projects assigned to their teams:

```sql
-- Add to project-scoped tables (scan_results, patterns, etc.)
-- This is a reference policy — adapt per table
CREATE POLICY project_team_access ON projects
    USING (
        id IN (
            SELECT project_id FROM team_projects
            WHERE team_id IN (
                SELECT team_id FROM team_memberships
                WHERE user_id = auth.uid()
            )
        )
        OR tenant_id IN (
            SELECT tenant_id FROM user_tenant_mappings
            WHERE user_id = auth.uid() AND role IN ('owner', 'admin')
        )
    );
```

#### Invitation Flow (CP0-F-11)

**File:** `supabase/functions/invitations/index.ts` (NEW — Hono router, JWT auth)

| Method | Path | Action | Auth |
|--------|------|--------|------|
| `POST` | `/api/v1/invitations` | Create invitation (email, role, team_id?) | admin/owner |
| `GET` | `/api/v1/invitations` | List pending invitations | admin/owner |
| `POST` | `/api/v1/invitations/:token/accept` | Accept invitation | public (token auth) |
| `DELETE` | `/api/v1/invitations/:id` | Revoke invitation | admin/owner |
| `POST` | `/api/v1/invitations/:id/resend` | Resend email | admin/owner |

**POST /api/v1/invitations flow:**
1. Validate JWT → admin/owner only
2. Check seat limit: `SELECT count(*) FROM user_tenant_mappings WHERE tenant_id = $1 AND active = true` + pending invitations. If ≥ `seat_limit` → 402.
3. Generate unique token: `crypto.randomUUID()`
4. Insert invitation row
5. Send email via Resend/Postmark (or queue for email service)
6. `logAuditEvent()` action `invitation.created`

**POST /api/v1/invitations/:token/accept flow:**
1. Lookup token → get invitation
2. Check not expired (`expires_at > now()`)
3. Check not already accepted (`accepted_at IS NULL`)
4. If user exists (by email) → add to tenant via `user_tenant_mappings`
5. If user doesn't exist → create via `auth.admin.createUser()` + add mapping
6. If `team_id` specified → add to team via `team_memberships`
7. Set `accepted_at = now()`
8. `logAuditEvent()` action `invitation.accepted`

#### Seat Management (CP0-F-12)

**File:** `supabase/functions/members/index.ts` (NEW)

| Method | Path | Action |
|--------|------|--------|
| `GET` | `/api/v1/members` | Paginated member list with roles, last_active |
| `GET` | `/api/v1/members/count` | `{ active, pending_invites, seat_limit, remaining }` |

#### Ownership Transfer (CP0-F-13)

**File:** `supabase/functions/settings/index.ts` (NEW or extend)

**Route:** `POST /api/v1/settings/transfer-ownership`

1. Validate JWT → current owner only
2. Validate `new_owner_id` is an active member of the tenant
3. In a single transaction:
   - `UPDATE tenants SET owner_id = new_owner_id`
   - `UPDATE user_tenant_mappings SET role = 'admin' WHERE user_id = old_owner AND tenant_id = $1`
   - `UPDATE user_tenant_mappings SET role = 'owner' WHERE user_id = new_owner AND tenant_id = $1`
4. `logAuditEvent()` twice: for old owner (`ownership.transferred_from`) and new owner (`ownership.transferred_to`)

**Gate:** Teams CRUD works. Invitations flow end-to-end. Seat limits enforced. Ownership transfer atomic.

---

### Sub-Phase F3: IP Allowlisting (CP0-F-14 through CP0-F-18)

**Goal:** Per-tenant CIDR-based access control with enforcement middleware.

#### Migration: IP Allowlist (CP0-F-14)

**File:** `supabase/migrations/20260211000008_ip_allowlist.sql`

```sql
CREATE TABLE IF NOT EXISTS ip_allowlist (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    cidr INET NOT NULL,                -- Postgres native CIDR type
    description TEXT DEFAULT '',
    expires_at TIMESTAMPTZ,           -- NULL = permanent
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE ip_allowlist ENABLE ROW LEVEL SECURITY;
ALTER TABLE ip_allowlist FORCE ROW LEVEL SECURITY;
CREATE POLICY ip_allowlist_tenant_isolation ON ip_allowlist
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE INDEX idx_ip_allowlist_tenant ON ip_allowlist(tenant_id);
```

#### IP Allowlist CRUD (CP0-F-15)

**File:** `supabase/functions/settings/ip-allowlist.ts` (NEW)

| Method | Path | Action | Auth |
|--------|------|--------|------|
| `POST` | `/api/v1/settings/ip-allowlist` | Add CIDR entry | admin/owner |
| `GET` | `/api/v1/settings/ip-allowlist` | List entries | admin/owner |
| `DELETE` | `/api/v1/settings/ip-allowlist/:id` | Remove entry | admin/owner |

**POST validation:**
- Validate CIDR format (use Postgres `inet` cast to verify)
- Validate not overly broad (reject `0.0.0.0/0` — that would allow everything anyway)
- `logAuditEvent()` action `ip_allowlist.added`

#### IP Enforcement Middleware (CP0-F-16)

**File:** `supabase/functions/shared/ip-allowlist-middleware.ts` (NEW)

```typescript
export async function enforceIpAllowlist(
  supabase: SupabaseClient,
  tenantId: string,
  clientIp: string
): Promise<{ allowed: boolean; reason?: string }> {
  // 1. Check if tenant has any allowlist entries
  const { data: entries } = await supabase
    .from("ip_allowlist")
    .select("id, cidr, expires_at")
    .eq("tenant_id", tenantId);

  // Empty allowlist = all IPs allowed (default open)
  if (!entries?.length) return { allowed: true };

  // 2. Check if client IP matches any active entry
  // Use Postgres INET operator for CIDR matching
  const { data: match } = await supabase.rpc("check_ip_allowlist", {
    p_tenant_id: tenantId,
    p_client_ip: clientIp,
  });

  if (match && match.length > 0) return { allowed: true };

  return {
    allowed: false,
    reason: `IP ${clientIp} is not in the allowlist for this tenant`,
  };
}
```

**Postgres function for CIDR matching:**

```sql
-- Add to migration
CREATE OR REPLACE FUNCTION check_ip_allowlist(p_tenant_id UUID, p_client_ip TEXT)
RETURNS TABLE(id UUID)
LANGUAGE sql
SECURITY DEFINER
STABLE
AS $$
    SELECT id FROM ip_allowlist
    WHERE tenant_id = p_tenant_id
    AND p_client_ip::inet <<= cidr
    AND (expires_at IS NULL OR expires_at > now());
$$;
```

**Integration:** Import `enforceIpAllowlist` in every Edge Function's middleware chain. Run AFTER JWT auth (need tenant_id) but BEFORE business logic.

#### Supabase Dashboard Bypass (CP0-F-17)

Internal Supabase IPs bypass allowlist checks. Implement by:
- Checking `X-Supabase-Internal` header (set by Supabase infrastructure)
- Or maintaining a `SUPABASE_INTERNAL_IPS` env var with bypass CIDRs
- Dashboard requests from Supabase infra are never blocked

#### CLI Escape Hatch (CP0-F-18)

**File:** `packages/drift-cli/src/commands/cloud.ts` (modify)

Add `drift cloud ip-allowlist reset` command:
1. Requires owner auth (JWT)
2. Prompts for email confirmation: "Type your email to confirm IP allowlist reset"
3. Calls `DELETE FROM ip_allowlist WHERE tenant_id = $1` (via API endpoint)
4. `logAuditEvent()` action `ip_allowlist.emergency_reset`

**Gate:** Allowlist blocks non-matching IPs. Empty list = all allowed. CIDR matching works. CLI escape hatch clears lockout.

---

## Tests (14 tests)

| ID | Test | Proves |
|----|------|--------|
| CT0-F-01 | INSERT audit → UPDATE same row → blocked (RLS). DELETE → blocked. | Audit immutability |
| CT0-F-02 | Insert 100 events → query `?actor=admin@co.com&action=project.delete` → only matches | Audit query filters |
| CT0-F-03 | Insert 50 events → `GET /export` → valid NDJSON, 50 lines, each JSON-parseable | Audit export |
| CT0-F-04 | Tenant A audit events invisible to tenant B | Audit tenant isolation |
| CT0-F-05 | Create team → add 3 members → assign 2 projects → members access projects | Team CRUD round-trip |
| CT0-F-06 | User NOT in team → access team project → 403 | Team-scoped access |
| CT0-F-07 | Invite by email → accept with token → user in tenant with correct role | Invitation flow |
| CT0-F-08 | Create invitation → mock time > 7 days → accept → 410 Gone | Invitation expiry |
| CT0-F-09 | 4 active + invite → success (5/5). Invite another → 402 | Seat limit |
| CT0-F-10 | Add `10.0.0.0/8` → request from `192.168.1.1` → 403 | IP blocks non-match |
| CT0-F-11 | Add `192.168.0.0/16` → request from `192.168.1.100` → allowed | IP allows CIDR match |
| CT0-F-12 | No entries → any IP → allowed | IP default open |
| CT0-F-13 | Entry with `expires_at = now()+1h` → allowed → mock +2h → blocked | IP temp entry expiry |
| CT0-F-14 | Transfer ownership → new=owner, old=admin, audit entries for both | Ownership transfer |

---

## Testing Standards

### What Makes a Good Test
- **Tests immutability enforcement** — not just "can I insert?" but "UPDATE/DELETE blocked by RLS?"
- **Tests authorization boundaries** — non-admin cannot create teams, non-owner cannot transfer ownership
- **Tests CIDR matching precision** — `10.0.0.0/8` matches `10.255.255.255` but not `11.0.0.1`
- **Tests edge cases** — expired invitation, seat limit boundary, empty allowlist
- **Uses real Supabase local dev** — real Postgres, real RLS, real INET operators

### What Makes a Bad Test
- Tests that skip RLS by using service_role for everything
- Tests that only check happy path without authorization checks
- Tests that mock Postgres CIDR matching instead of using real `inet` operators
- Tests that create test data without verifying cleanup

### Required Patterns
- **Audit immutability:** CT0-F-01 must use a non-superuser connection and verify the actual RLS policy blocks UPDATE/DELETE
- **Tenant isolation:** CT0-F-04 must set two different tenant contexts and verify zero cross-visibility
- **CIDR precision:** CT0-F-10/11 must use Postgres `inet` operator, not JavaScript string matching
- **Seat limits:** CT0-F-09 must test the exact boundary (n-1 OK, n+1 blocked)
- **Ownership atomicity:** CT0-F-14 must verify the transfer is a single transaction (old and new roles change together)
- **Audit trail:** Every mutation test must verify `cloud_audit_log` entry

---

## Architecture Constraints

1. **Audit log is INSERT-only.** RLS policies `FOR UPDATE USING (false)` and `FOR DELETE USING (false)`. Retention cleanup uses `SECURITY DEFINER` function that bypasses RLS.
2. **RLS on ALL new tables.** `ENABLE` + `FORCE` + tenant isolation policy on `team_projects`, `invitations`, `subscriptions`, `ip_allowlist`.
3. **`SET LOCAL app.tenant_id` per request.** Every handler.
4. **CIDR matching uses Postgres `inet` type.** Not JavaScript string parsing. `client_ip::inet <<= cidr` is the operator.
5. **Empty IP allowlist = all IPs allowed.** Default open. No lockout on fresh setup.
6. **Seat limits checked on invitation, not on login.** Existing members are never locked out — only new invitations are blocked.
7. **Invitation tokens are single-use.** `accepted_at IS NOT NULL` prevents reuse.
8. **Ownership transfer is atomic.** Single transaction: old owner → admin, new owner → owner.
9. **Audit every mutation.** All POST/PATCH/DELETE handlers call `logAuditEvent()`.
10. **Phase D placeholder tables preserved.** Use `ALTER TABLE` and `CREATE TABLE IF NOT EXISTS`, not `DROP TABLE`.

---

## Forbidden Actions

1. **Do NOT drop Phase D placeholder tables.** ALTER only.
2. **Do NOT allow UPDATE/DELETE on `cloud_audit_log`.** Immutability is non-negotiable.
3. **Do NOT implement CIDR matching in JavaScript.** Use Postgres `inet` operators.
4. **Do NOT lock out all IPs.** Empty allowlist = default open.
5. **Do NOT allow non-owners to transfer ownership.**
6. **Do NOT expose invitation tokens in list responses.** Token is only in the email link.
7. **Do NOT skip seat limit check on invitation create.**
8. **Do NOT modify Phase D or Phase E files.** Import shared helpers only.
9. **Do NOT use string concatenation in SQL queries.** Parameterized queries only.
10. **Do NOT modify any Rust crates** (except the single CLI command CP0-F-18).

---

## Effort Estimate

| Sub-Phase | Tasks | Effort | Key Risk |
|-----------|-------|--------|----------|
| F1: Audit Log API | CP0-F-01 to F-06 | 1-1.5d | NDJSON streaming, Realtime setup |
| F2: Team Management | CP0-F-07 to F-13 | 1.5-2d | Team-scoped RLS complexity |
| F3: IP Allowlisting | CP0-F-14 to F-18 | 0.5-1d | CIDR matching, CLI command |
| Tests | CT0-F-01 to F-14 | 0.5-1d | Mock time for expiry tests |
| **Total** | **18 impl + 14 test** | **3-4 days** | |

**Dependencies:** Phase D complete (placeholder tables + shared helpers). Phase E complete (webhook dispatch — optional for team event webhooks).

---

## Subsystems That Are Clean (do NOT modify)

- **All Rust crates** — except `packages/drift-cli/src/commands/cloud.ts` for CP0-F-18
- **Phase D files** — SCIM endpoints, shared SCIM helpers, migrations 000-003
- **Phase E files** — Webhook endpoints, dispatch engine, signature module
- You MAY import: `shared/audit.ts`, `shared/supabase.ts`, `shared/tenant-context.ts`, `shared/webhook-dispatch.ts`

---

## Verification Commands

```bash
# Migrations apply:
supabase db reset
# Expected: 0 errors, all tables created

# Audit immutability policies:
psql "$SUPABASE_DB_URL" -c "SELECT policyname FROM pg_policies WHERE tablename = 'cloud_audit_log' AND policyname LIKE 'audit_no_%';"
# Expected: audit_no_update, audit_no_delete

# RLS forced on all new tables:
psql "$SUPABASE_DB_URL" -c "
  SELECT relname, relforcerowsecurity FROM pg_class
  WHERE relname IN ('team_projects','invitations','subscriptions','ip_allowlist','cloud_audit_log');"
# Expected: all relforcerowsecurity = true

# CIDR matching function exists:
psql "$SUPABASE_DB_URL" -c "SELECT proname FROM pg_proc WHERE proname = 'check_ip_allowlist';"
# Expected: 1 row

# Audit logging on all mutations:
grep -rn "logAuditEvent" supabase/functions/teams/ supabase/functions/invitations/ supabase/functions/settings/ supabase/functions/members/ supabase/functions/audit/
# Expected: 1+ per file

# No raw SQL concatenation:
grep -rn "\\$\\{" supabase/functions/ | grep -i "select\|insert\|update\|delete" | grep -v "test"
# Expected: 0 matches (all parameterized)

# Full tests:
cd supabase && deno test tests/ --allow-net --allow-env
# Expected: 14 Phase F + 10 Phase E + 14 Phase D = 38 tests, 0 failures
```

---

## Critical Questions Per Sub-Phase

### After F1 (Audit):
- Can a non-superuser UPDATE/DELETE audit rows? (No — RLS blocks.)
- What are the 5 query filters? (`actor`, `action`, `resource_type`, `after`, `before`)
- What format is the export? (JSON Lines / NDJSON)
- What retention applies to Free tier? (30 days)

### After F2 (Teams):
- Can a user access a project not assigned to their team? (No — RLS blocks.)
- What happens when seat limit is reached? (402 Payment Required on invite.)
- Is ownership transfer atomic? (Yes — single transaction.)
- Are expired invitations rejectable? (Yes — 410 Gone.)

### After F3 (IP Allowlist):
- What happens with an empty allowlist? (All IPs allowed.)
- How is CIDR matching done? (Postgres `inet` operator `<<=`, not JavaScript.)
- Can a locked-out admin recover? (Yes — CLI `drift cloud ip-allowlist reset`.)
- Do temporary entries expire? (Yes — `expires_at` checked on every request.)

---

## Quality Gate (QG-F) — All Must Pass

- [ ] `cloud_audit_log` immutable (no UPDATE/DELETE for non-superusers)
- [ ] Audit query API with cursor pagination + 5 filter types
- [ ] Audit export in JSON Lines format (SIEM-ready)
- [ ] Team CRUD with membership + project assignment
- [ ] Invitation flow end-to-end (invite → email → accept → member)
- [ ] Seat limit enforcement returns 402 when exceeded
- [ ] IP allowlist blocks non-matching IPs, allows matching CIDRs
- [ ] IP allowlist empty = default open
- [ ] Temporary IP entries expire correctly
- [ ] CLI escape hatch for IP allowlist lockout recovery
- [ ] Tenant isolation on all new tables
- [ ] All 14 Phase F tests pass

---

## Appendix A: Audit Event Action Catalog

All `action` values used in `cloud_audit_log`. Follow `resource.verb` convention.

### Phase D (SCIM) Actions
| Action | Resource Type | Description |
|--------|--------------|-------------|
| `scim.user_provisioned` | user | SCIM user created via IdP |
| `scim.user_deprovisioned` | user | SCIM user deactivated |
| `scim.user_updated` | user | SCIM user attributes changed |
| `scim.group_created` | team | SCIM group created |
| `scim.group_updated` | team | SCIM group membership changed |
| `scim.group_deleted` | team | SCIM group removed |
| `scim.token_created` | scim_token | SCIM bearer token generated |
| `scim.token_revoked` | scim_token | SCIM bearer token revoked |

### Phase E (Webhook) Actions
| Action | Resource Type | Description |
|--------|--------------|-------------|
| `webhook.registered` | webhook | Webhook endpoint created |
| `webhook.updated` | webhook | Webhook endpoint modified |
| `webhook.deleted` | webhook | Webhook endpoint removed |
| `webhook.secret_rotated` | webhook | Webhook secret rotated |
| `webhook.circuit_broken` | webhook | Endpoint deactivated after 50 failures |

### Phase F (This Phase) Actions
| Action | Resource Type | Description |
|--------|--------------|-------------|
| `team.created` | team | Team created |
| `team.updated` | team | Team name/description changed |
| `team.deleted` | team | Team deleted |
| `team.member_added` | team_membership | User added to team |
| `team.member_removed` | team_membership | User removed from team |
| `team.member_role_changed` | team_membership | Member role updated |
| `team.project_assigned` | team_project | Project assigned to team |
| `team.project_unassigned` | team_project | Project unassigned from team |
| `invitation.created` | invitation | Invitation sent |
| `invitation.accepted` | invitation | Invitation accepted |
| `invitation.revoked` | invitation | Invitation revoked |
| `invitation.resent` | invitation | Invitation email resent |
| `ownership.transferred_from` | tenant | Old owner → admin |
| `ownership.transferred_to` | tenant | New owner → owner |
| `ip_allowlist.added` | ip_allowlist | CIDR entry added |
| `ip_allowlist.removed` | ip_allowlist | CIDR entry removed |
| `ip_allowlist.emergency_reset` | ip_allowlist | All entries cleared via CLI |

---

## Appendix B: Table Schema Reference

### New Tables Created in Phase F

**`team_projects`** — Links teams to projects for team-scoped access control.

| Column | Type | Constraints |
|--------|------|-------------|
| `team_id` | UUID | FK → teams(id) ON DELETE CASCADE |
| `project_id` | UUID | FK → projects(id) ON DELETE CASCADE |
| `assigned_by` | UUID | NOT NULL |
| `assigned_at` | TIMESTAMPTZ | DEFAULT now() |
| **PK** | (team_id, project_id) | |

**`invitations`** — Email invitations to join a tenant.

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | UUID | PK, DEFAULT gen_random_uuid() |
| `tenant_id` | UUID | FK → tenants(id) ON DELETE CASCADE |
| `email` | TEXT | NOT NULL |
| `role` | TEXT | CHECK IN ('admin','member','viewer') |
| `team_id` | UUID | FK → teams(id) ON DELETE SET NULL |
| `invited_by` | UUID | NOT NULL |
| `token` | TEXT | UNIQUE, NOT NULL |
| `expires_at` | TIMESTAMPTZ | DEFAULT now() + 7 days |
| `accepted_at` | TIMESTAMPTZ | NULL until accepted |
| `created_at` | TIMESTAMPTZ | DEFAULT now() |

**`subscriptions`** — Per-tenant plan and seat limits.

| Column | Type | Constraints |
|--------|------|-------------|
| `tenant_id` | UUID | PK, FK → tenants(id) ON DELETE CASCADE |
| `plan` | TEXT | CHECK IN ('free','pro','team','enterprise') |
| `seat_limit` | INT | DEFAULT 5 |
| `created_at` | TIMESTAMPTZ | DEFAULT now() |
| `updated_at` | TIMESTAMPTZ | DEFAULT now() |

**`ip_allowlist`** — Per-tenant CIDR-based access control.

| Column | Type | Constraints |
|--------|------|-------------|
| `id` | UUID | PK, DEFAULT gen_random_uuid() |
| `tenant_id` | UUID | FK → tenants(id) ON DELETE CASCADE |
| `cidr` | INET | NOT NULL (Postgres native CIDR) |
| `description` | TEXT | DEFAULT '' |
| `expires_at` | TIMESTAMPTZ | NULL = permanent |
| `created_by` | UUID | NOT NULL |
| `created_at` | TIMESTAMPTZ | DEFAULT now() |

### Tables Modified from Phase D Placeholders

**`teams`** — No schema change. Phase D placeholder already has required columns.
**`team_memberships`** — No schema change. Phase D placeholder already has required columns.
**`cloud_audit_log`** — No schema change. Phase F adds indexes only.

---

## Appendix C: Cross-Phase Dependency Map

```
Phase F (Audit Log API + Team Management + IP Allowlisting)
│
├── HARD DEPENDS ON ─────────────────────────────────────────────────
│   ├── tenants              ← Phase D prerequisite migration (20260211000000)
│   ├── projects             ← Phase D prerequisite migration (20260211000000)
│   ├── user_tenant_mappings ← Phase D prerequisite migration (20260211000000)
│   ├── set_tenant_context() ← Phase D prerequisite migration (20260211000000)
│   ├── teams (placeholder)  ← Phase D placeholder migration (20260211000003)
│   ├── team_memberships     ← Phase D placeholder migration (20260211000003)
│   ├── cloud_audit_log      ← Phase D placeholder migration (20260211000003)
│   ├── shared/audit.ts      ← Phase D shared helpers
│   ├── shared/supabase.ts   ← Phase D shared helpers
│   └── shared/tenant-context.ts ← Phase D shared helpers
│
├── SOFT DEPENDS ON (optional integration) ──────────────────────────
│   └── shared/webhook-dispatch.ts ← Phase E
│       Can fire webhooks on team events (team.created, etc.)
│       If Phase E not complete, skip webhook dispatch.
│
├── PRODUCES (consumed by later phases) ─────────────────────────────
│   ├── team_projects          → Phase G (integration tests)
│   ├── invitations            → Phase G (full enterprise flow test)
│   ├── subscriptions          → Phase G (seat limit verification)
│   ├── ip_allowlist           → Phase G (IP + team integration test)
│   ├── check_ip_allowlist()   → Phase G (CIDR matching verification)
│   ├── GET /api/v1/audit      → Phase G (audit query integration test)
│   ├── GET /api/v1/audit/export → Phase G (SIEM export verification)
│   └── enforceIpAllowlist()   → Phase G (middleware integration test)
│
└── INDEPENDENT OF ──────────────────────────────────────────────────
    ├── Phase A (Drift storage traits) — no Rust code
    ├── Phase B (Drift engine + NAPI) — no Rust code
    ├── Phase C (Bridge storage) — no Rust code
    └── Phase D (SCIM) — F uses D's tables but doesn't modify D's code
```

**Key decisions:**
- Phase D's placeholder tables are preserved. Phase F uses `ALTER TABLE` and `CREATE TABLE IF NOT EXISTS`.
- Phase F's audit log enhancements add indexes only — the table structure from Phase D is sufficient.
- IP allowlist uses Postgres native `INET` type and `<<=` operator for CIDR matching.
- CLI escape hatch (CP0-F-18) is the only non-Supabase file — modifies `packages/drift-cli/src/commands/cloud.ts`.

---

## Appendix D: Implementation Plan Cross-Reference

### Implementation Tasks

| Plan ID | Task | Prompt Section | Status |
|---------|------|----------------|--------|
| CP0-F-01 | `cloud_audit_log` enhancements (indexes, immutability) | Sub-Phase F1: Migration | Covered |
| CP0-F-02 | Wire audit events into all mutating handlers | Sub-Phase F1: Audit Wiring | Covered |
| CP0-F-03 | Audit query API (pagination + filters) | Sub-Phase F1: Query API | Covered |
| CP0-F-04 | Audit export API (JSON Lines / NDJSON) | Sub-Phase F1: Export API | Covered |
| CP0-F-05 | Configurable audit retention per plan | Sub-Phase F1: Retention | Covered |
| CP0-F-06 | Supabase Realtime for live audit stream | Sub-Phase F1: Realtime | Covered |
| CP0-F-07 | Teams + team_projects + invitations tables | Sub-Phase F2: Migration | Covered |
| CP0-F-08 | Team CRUD API | Sub-Phase F2: Team CRUD | Covered |
| CP0-F-09 | Team membership management | Sub-Phase F2: Membership | Covered |
| CP0-F-10 | Team-project assignment + RLS | Sub-Phase F2: Project Assignment | Covered |
| CP0-F-11 | Invitation flow (email → accept → join) | Sub-Phase F2: Invitations | Covered |
| CP0-F-12 | Seat management | Sub-Phase F2: Seat Management | Covered |
| CP0-F-13 | Ownership transfer | Sub-Phase F2: Ownership Transfer | Covered |
| CP0-F-14 | `ip_allowlist` table | Sub-Phase F3: Migration | Covered |
| CP0-F-15 | IP allowlist CRUD API | Sub-Phase F3: CRUD | Covered |
| CP0-F-16 | IP enforcement middleware | Sub-Phase F3: Middleware | Covered |
| CP0-F-17 | Supabase dashboard bypass | Sub-Phase F3: Dashboard Bypass | Covered |
| CP0-F-18 | CLI escape hatch (`drift cloud ip-allowlist reset`) | Sub-Phase F3: CLI Escape | Covered |

### Test Tasks

| Plan ID | Test | Prompt Section | Status |
|---------|------|----------------|--------|
| CT0-F-01 | Audit immutability (UPDATE/DELETE blocked) | Tests: CT0-F-01 | Covered |
| CT0-F-02 | Audit query with filters | Tests: CT0-F-02 | Covered |
| CT0-F-03 | Audit export NDJSON format | Tests: CT0-F-03 | Covered |
| CT0-F-04 | Audit tenant isolation | Tests: CT0-F-04 | Covered |
| CT0-F-05 | Team CRUD round-trip | Tests: CT0-F-05 | Covered |
| CT0-F-06 | Team-scoped project access | Tests: CT0-F-06 | Covered |
| CT0-F-07 | Invitation flow complete | Tests: CT0-F-07 | Covered |
| CT0-F-08 | Invitation expiry | Tests: CT0-F-08 | Covered |
| CT0-F-09 | Seat limit enforcement | Tests: CT0-F-09 | Covered |
| CT0-F-10 | IP blocks non-matching | Tests: CT0-F-10 | Covered |
| CT0-F-11 | IP allows CIDR match | Tests: CT0-F-11 | Covered |
| CT0-F-12 | IP empty = all allowed | Tests: CT0-F-12 | Covered |
| CT0-F-13 | IP temp entry expires | Tests: CT0-F-13 | Covered |
| CT0-F-14 | Ownership transfer atomic | Tests: CT0-F-14 | Covered |

### Quality Gate Items

| QG Item | Prompt Coverage |
|---------|-----------------|
| Audit immutable | Sub-Phase F1 + CT0-F-01 |
| Audit query + 5 filters | Sub-Phase F1: Query API + CT0-F-02 |
| Audit export NDJSON | Sub-Phase F1: Export + CT0-F-03 |
| Team CRUD + membership + projects | Sub-Phase F2 + CT0-F-05/06 |
| Invitation flow e2e | Sub-Phase F2: Invitations + CT0-F-07 |
| Seat limit 402 | Sub-Phase F2: Seat Management + CT0-F-09 |
| IP blocks non-match | Sub-Phase F3 + CT0-F-10 |
| IP empty = open | Sub-Phase F3 + CT0-F-12 |
| IP temp entries expire | Sub-Phase F3 + CT0-F-13 |
| CLI escape hatch | Sub-Phase F3: CLI + CT0-F-18 |
| Tenant isolation all tables | RLS policies + CT0-F-04 |
| All 14 tests pass | Tests section |

### Tracker Cross-Reference

| Tracker Ref | Tracker Section | Plan Phase |
|-------------|-----------------|------------|
| GAP-03 | §11a (line ~1071) | Phase F: F1 (Audit) |
| GAP-04 | §11a (line ~1111) | Phase F: F2 (Teams) |
| GAP-05 | §11a (line ~1164) | Phase F: F3 (IP Allowlist) |
| P6-11 | §8 Phase 6c | CP0-F-07 to F-13 (Teams) |
| P6-12 | §8 Phase 6c | CP0-F-08 (Team CRUD) |
| P6-13 | §8 Phase 6c | CP0-F-11 (Invitations) |
| P6-14 | §8 Phase 6c | CP0-F-12 (Seat mgmt) |
| P6-15 | §8 Phase 6c | CP0-F-01 to F-06 (Audit) |
| P6-16 | §8 Phase 6c | CP0-F-03 (Audit query) |
| P6-17 | §8 Phase 6c | CP0-F-04 (Audit export) |
| P6-18 | §8 Phase 6c | CP0-F-14 to F-18 (IP) |

**Coverage: 18/18 impl tasks + 14/14 test tasks + 12/12 QG items + 11/11 tracker refs = 100%**
