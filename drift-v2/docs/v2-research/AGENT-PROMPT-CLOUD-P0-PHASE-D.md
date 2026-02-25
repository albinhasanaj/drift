# Agent Prompt: Cloud P0 Phase D — SCIM Provisioning (Enterprise GAP-01)

## Your Mission

You are implementing SCIM 2.0 provisioning endpoints (RFC 7644) as Supabase Edge Functions so that enterprise identity providers (Okta, Azure AD, OneLogin) can automatically provision and deprovision Drift users. **Without SCIM, enterprise procurement rejects the product** — terminated employees retain Drift access until manually revoked.

This phase is entirely **Supabase Edge Functions (Deno/TypeScript)** — no Rust code. It is independent of Phases A-C and can run in parallel as long as a Supabase project is provisioned.

When this phase is done:
- **SCIM `/Users` CRUD** — IdPs can create, read, update, deactivate, and delete Drift users
- **SCIM `/Groups` CRUD** — IdP groups map to Drift teams with configurable role mapping
- **Deprovisioning within 60s** — `active: false` → Auth disabled, API keys revoked, sessions ended, audit logged
- **SCIM bearer token auth** — separate from user JWTs, one per tenant, admin-only creation
- **Okta/Azure AD conformance** — passes standard SCIM test harnesses

**This is greenfield work.** No existing SCIM infrastructure exists in the codebase.

**Speed does not matter. Security does. Every endpoint must enforce tenant isolation. Every mutation must produce an audit log entry. Every error must return a valid SCIM error schema (RFC 7644 §3.12).**

---

## Documents You MUST Read Before Writing Any Code

1. **`docs/v2-research/CLOUD-P0-IMPLEMENTATION-PLAN.md`** — Phase D section (lines ~313-365). 10 impl tasks (CP0-D-01 to D-10) + 8 test tasks + Quality Gate.

2. **`docs/v2-research/BRIDGE-CLOUD-READINESS-TRACKER.md`** — Sections 3c (Cloud Schema, ~303-345), 5a (Auth, ~440-450), 5c (Tenant Isolation, ~463-471), 6e (API Tech Stack, ~577-587), Section 11a GAP-01 (~1007-1020).

3. **RFC 7644 (SCIM Protocol)** — §3 (Protocol), §3.4 (Querying), §3.5 (Modifying), §3.12 (Errors).

4. **RFC 7643 (SCIM Core Schema)** — §4.1 (User resource), §4.2 (Group resource).

5. **`drift/skills/supabase-auth/SKILL.md`** — Supabase Auth patterns reference.

After reading all five, you should be able to answer:
- What is the SCIM User resource schema? (Answer: `id`, `userName`, `name.givenName`, `name.familyName`, `emails[].value`, `active`, `displayName`, `meta`)
- What is the SCIM error response format? (Answer: `{ "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"], "status": "400", "scimType": "invalidValue", "detail": "..." }`)
- How does SCIM pagination work? (Answer: `startIndex` (1-based) + `count`. Response: `totalResults`, `itemsPerPage`, `startIndex`, `Resources[]`)
- How does SCIM PatchOp work? (Answer: `{ "schemas": ["...PatchOp"], "Operations": [{ "op": "replace", "path": "active", "value": false }] }`)
- Where does Supabase store users? (Answer: `auth.users` managed by GoTrue. Custom data in `user_tenant_mappings`.)
- How is tenant isolation enforced? (Answer: RLS + `SET LOCAL app.tenant_id` per transaction in Edge Functions.)

---

## Decision Gate: WorkOS vs. Hand-Rolled SCIM (CP0-D-01)

**Before writing any code**, evaluate WorkOS vs. hand-rolling SCIM.

- **WorkOS:** Unified SSO+SCIM service. Handles conformance automatically. Per-connection pricing. Vendor lock-in.
- **Hand-rolled:** Full control, no per-connection cost, more code (~500-800 lines).

Write decision in `docs/adr/ADR-001-scim-provider.md` (NEW). The rest of this prompt assumes hand-rolled. If WorkOS is chosen, adapt to be a thin webhook receiver.

---

## Phase Execution Order

### Sub-Phase D1: SCIM Infrastructure (CP0-D-01, CP0-D-02)

**Goal:** Supabase project structure, SCIM token table, auth middleware.

**Project structure to create:**

```
supabase/
├── config.toml
├── migrations/
│   ├── 20260211000001_scim_tokens.sql
│   └── 20260211000002_scim_group_mappings.sql
├── functions/
│   ├── shared/
│   │   ├── supabase.ts          # Admin client (service_role)
│   │   ├── scim-auth.ts         # Bearer token middleware
│   │   ├── scim-errors.ts       # RFC 7644 §3.12 error helpers
│   │   ├── scim-types.ts        # TS types for SCIM resources
│   │   ├── audit.ts             # Audit log helper (reused by Phase E/F)
│   │   ├── tenant-context.ts    # SET LOCAL app.tenant_id helper
│   │   └── deprovision.ts       # Deprovisioning logic (6 steps)
│   ├── scim-users/index.ts      # SCIM /Users (Hono router)
│   ├── scim-groups/index.ts     # SCIM /Groups (Hono router)
│   └── scim-admin/index.ts      # Token management (JWT auth)
└── tests/
    ├── scim-users.test.ts
    ├── scim-groups.test.ts
    └── scim-auth.test.ts
```

#### Migration: `scim_tokens`

```sql
CREATE TABLE IF NOT EXISTS scim_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,           -- SHA-256 of bearer token
    description TEXT DEFAULT '',
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,            -- NULL = active
    last_used_at TIMESTAMPTZ,
    UNIQUE (tenant_id, token_hash)
);
ALTER TABLE scim_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY scim_tokens_tenant_isolation ON scim_tokens
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
```

#### Migration: `scim_group_mappings`

```sql
CREATE TABLE IF NOT EXISTS scim_group_mappings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    idp_group_name TEXT NOT NULL,
    drift_role TEXT NOT NULL DEFAULT 'member'
        CHECK (drift_role IN ('owner', 'admin', 'member', 'viewer')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, idp_group_name)
);
ALTER TABLE scim_group_mappings ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_group_mappings FORCE ROW LEVEL SECURITY;
CREATE POLICY scim_group_mappings_tenant_isolation ON scim_group_mappings
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
```

#### SCIM Auth Middleware (`shared/scim-auth.ts`)

- Extract `Authorization: Bearer <token>` header
- SHA-256 hash the raw token
- Look up `scim_tokens` WHERE `token_hash` = hash AND `revoked_at IS NULL`
- Return `{ tenantId, tokenId }` or throw 401 with SCIM error schema
- Fire-and-forget update of `last_used_at`

#### SCIM Error Helpers (`shared/scim-errors.ts`)

- `ScimError` class with `status`, `scimType`, `detail`, `toResponse()` method
- Response Content-Type: `application/scim+json`
- Error types: `invalidFilter`, `uniqueness`, `invalidSyntax`, `invalidPath`, `noTarget`, `invalidValue`

#### SCIM Types (`shared/scim-types.ts`)

- `ScimUser` — full RFC 7643 §4.1 User resource
- `ScimGroup` — full RFC 7643 §4.2 Group resource
- `ScimListResponse<T>` — paginated list envelope
- `ScimPatchOp` — PatchOp request body

#### Tenant Context (`shared/tenant-context.ts`)

- `setTenantContext(supabase, tenantId)` — calls `SET LOCAL app.tenant_id` via RPC
- SQL function: `CREATE FUNCTION set_tenant_context(p_tenant_id UUID) RETURNS void AS $$ BEGIN PERFORM set_config('app.tenant_id', p_tenant_id::text, true); END; $$`

**Gate:** `supabase start` + `supabase db reset` + `supabase functions serve` — no errors.

---

### Sub-Phase D2: SCIM `/Users` Endpoint (CP0-D-03 through CP0-D-07)

**Goal:** Full SCIM User CRUD with deprovisioning.

**File:** `supabase/functions/scim-users/index.ts` (Hono router)

#### Route Table

| Method | Path | Action |
|--------|------|--------|
| `POST` | `/scim/v2/Users` | Auth Admin `createUser()` + `user_tenant_mappings` insert |
| `GET` | `/scim/v2/Users` | List/filter with `startIndex`+`count`, `filter=userName eq "x"` |
| `GET` | `/scim/v2/Users/:id` | Single user lookup |
| `PATCH` | `/scim/v2/Users/:id` | PatchOp: `replace` on `active`, `name`, `emails`, `displayName` |
| `PUT` | `/scim/v2/Users/:id` | Full replace |
| `DELETE` | `/scim/v2/Users/:id` | Soft-delete via deprovisioning |

#### POST /scim/v2/Users — Create (CP0-D-03)

1. Validate SCIM token → get `tenantId`
2. Validate required fields (`userName`, `emails`)
3. Check uniqueness within tenant (`user_tenant_mappings`)
4. Create Supabase Auth user via Admin API (`supabase.auth.admin.createUser()`)
5. Insert `user_tenant_mappings` row (role=`member`, `scim_external_id`)
6. `logAuditEvent()` with action `user.provisioned`
7. Return 201 + SCIM User resource + `Location` header

#### GET /scim/v2/Users — List/Filter (CP0-D-04)

- Parse `startIndex` (1-based, default 1) and `count` (default 100, max 200)
- Parse SCIM filter: support `userName eq "x"`, `emails.value eq "x"`, `externalId eq "x"`, `active eq true/false`
- Query `user_tenant_mappings` with RLS + filter + range
- Enrich with `auth.users` data via Admin API
- Return `ScimListResponse<ScimUser>`

#### PATCH /scim/v2/Users/:id — Update (CP0-D-05)

- Validate PatchOp schema
- For each operation:
  - `path=active, value=false` → **call `deprovisionUser()`** (the critical path)
  - `path=active, value=true` → reprovision (unban + reactivate mapping)
  - `path=name.*` / `displayName` → `auth.admin.updateUserById()`
  - `path=emails` → update primary email via Admin API
- Return updated SCIM User resource

#### DELETE /scim/v2/Users/:id — Delete (CP0-D-06)

- Call `deprovisionUser()` (soft-delete, not hard-delete)
- Return 204 No Content

#### Deprovisioning Logic — `shared/deprovision.ts` (CP0-D-07)

**The most security-critical code in Phase D.** When IdP sends `active: false` or DELETE:

1. **Verify user belongs to tenant** — query `user_tenant_mappings`
2. **Disable Supabase Auth user** — `admin.updateUserById(userId, { ban_duration: "876000h" })`
3. **Revoke ALL API keys** — `UPDATE api_keys SET revoked_at=now() WHERE tenant_id=X AND created_by=userId`
4. **End all sessions** — `admin.signOut(userId, "global")`
5. **Mark mapping inactive** — `UPDATE user_tenant_mappings SET active=false, deprovisioned_at=now()`
6. **Audit log** — `logAuditEvent()` with action `user.deprovisioned`

**All 6 steps must complete within 60s.** If any step fails, log error but continue remaining steps (partial deprovisioning > none).

**Gate:** Create user → PATCH `active:false` → verify auth banned + keys revoked + sessions ended.

---

### Sub-Phase D3: SCIM `/Groups` Endpoint (CP0-D-08, CP0-D-09)

**Goal:** Map IdP groups to Drift teams.

**File:** `supabase/functions/scim-groups/index.ts`

If Phase F `teams`/`team_memberships` tables don't exist, create minimal placeholders in a migration.

| Method | Path | Action |
|--------|------|--------|
| `POST` | `/scim/v2/Groups` | `teams` insert |
| `GET` | `/scim/v2/Groups` | List groups |
| `GET` | `/scim/v2/Groups/:id` | Get group + members |
| `PATCH` | `/scim/v2/Groups/:id` | PatchOp: `add`/`remove` members, `replace` displayName |
| `DELETE` | `/scim/v2/Groups/:id` | Cascade delete team + memberships |

**Group-to-role mapping (CP0-D-09):** Query `scim_group_mappings` for `tenant_id` + `idp_group_name` (case-insensitive). Default: all groups → `member` role.

**PATCH members:** For `add` operations, verify each user belongs to tenant before inserting `team_memberships`. For `remove`, delete matching rows.

**Gate:** Create group → add member via PATCH → verify `team_memberships` row.

---

### Sub-Phase D4: Token Management + Conformance (CP0-D-02 partial, CP0-D-10)

**File:** `supabase/functions/scim-admin/index.ts` — uses **JWT auth** (not SCIM tokens).

- `POST /api/v1/settings/scim` — Create SCIM token. Admin-only. Generate `crypto.randomUUID()` token, store SHA-256 hash. Return raw token once.
- `GET /api/v1/settings/scim` — List tokens (metadata only, never raw token).
- `DELETE /api/v1/settings/scim/:id` — Revoke (set `revoked_at`).

**Conformance (CP0-D-10):** Run Okta SCIM test harness + Azure AD SCIM validator. Document supported vs. optional features.

---

## Tests You Will Write (8 tests)

| ID | Test | What It Proves |
|----|------|----------------|
| CT0-D-01 | POST /scim/v2/Users → user in Auth + `user_tenant_mappings` row | Provisioning works |
| CT0-D-02 | Create → PATCH `active:false` → Auth banned, keys revoked, sessions ended, audit logged | **Deprovisioning revokes ALL access** |
| CT0-D-03 | Create 5 users → GET with `filter=userName eq "user3@..."` → 1 result | SCIM filter works |
| CT0-D-04 | Create 25 users → GET `startIndex=1&count=10` → `totalResults=25`, 10 resources | Pagination works |
| CT0-D-05 | POST /scim/v2/Groups → `teams` row created | Group creates team |
| CT0-D-06 | Create group+user → PATCH add member → `team_memberships` row with correct role | Membership syncs |
| CT0-D-07 | No token→401, invalid→401, revoked→401, valid→200 | Bearer token auth enforced |
| CT0-D-08 | Tenant A user, tenant B SCIM token → 404 on GET and PATCH | **Tenant isolation** |

**Test environment:** Supabase CLI local dev (`supabase start`). Deno test runner. Real Postgres + GoTrue + RLS.

**CT0-D-02 is the most critical test** — proves deprovisioning works (the reason SCIM exists).
**CT0-D-08 is the security test** — proves RLS blocks cross-tenant access.

---

## Architecture Constraints

1. **SCIM tokens ≠ user JWTs.** Long-lived, SHA-256 hashed, one per tenant, admin-only creation.
2. **RLS on every table.** `ENABLE` + `FORCE` + tenant isolation policy. No exceptions.
3. **`SET LOCAL app.tenant_id` per request.** Every handler calls `setTenantContext()` before any query.
4. **Deprovisioning = soft-delete.** Ban auth + revoke keys + end sessions + mark inactive. Never hard-delete. GDPR erasure is separate.
5. **Audit every mutation.** Every POST/PATCH/PUT/DELETE → `cloud_audit_log` entry.
6. **SCIM error schema compliance.** RFC 7644 §3.12 format. Content-Type: `application/scim+json`.
7. **No source code in SCIM payloads.** Only user identity data.
8. **Admin API via service_role key.** `SUPABASE_SERVICE_ROLE_KEY` from `Deno.env.get()` only. Never in responses or logs.

---

## Forbidden Actions

1. **Do NOT expose service_role key** in responses, logs, or error messages.
2. **Do NOT store raw SCIM tokens.** SHA-256 hashes only.
3. **Do NOT allow non-admin SCIM token creation.** Privilege escalation risk.
4. **Do NOT skip `setTenantContext()`.** Missing = zero tenant isolation.
5. **Do NOT return database errors in SCIM responses.** Generic SCIM errors only; log details server-side.
6. **Do NOT implement SCIM password management.** IdP manages passwords.
7. **Do NOT hard-delete on SCIM DELETE.** Always soft-delete.
8. **Do NOT bypass Supabase Auth Admin API.** All user creation through GoTrue.
9. **Do NOT modify any Rust crates.** Phase D is pure TypeScript/Deno/SQL.

---

## Effort Estimate

| Sub-Phase | Tasks | Effort | Key Risk |
|-----------|-------|--------|----------|
| D1: Infrastructure | CP0-D-01, D-02 | 0.5-1d | WorkOS decision may need stakeholder input |
| D2: SCIM /Users | CP0-D-03 to D-07 | 1-1.5d | Deprovisioning has 6 atomic steps |
| D3: SCIM /Groups | CP0-D-08, D-09 | 0.5-1d | Phase F table dependency |
| D4: Token Mgmt + Conformance | CP0-D-02, D-10 | 0.5d | Okta/Azure AD test harness edge cases |
| Tests | CT0-D-01 to D-08 | 0.5d | Local Supabase dev setup |
| **Total** | **10 impl + 8 test** | **2-3 days** | |

**Dependencies:** Supabase project provisioned. Phase F (Teams) soft dependency — create placeholder tables if needed.

---

## Subsystems That Are Clean (do NOT modify)

- **All Rust crates** — `drift-*`, `cortex-*`, `cortex-drift-bridge`
- **`packages/drift-cli/`** — SCIM is server-side only
- **`packages/drift-mcp/`** — SCIM not exposed via MCP
- **Supabase Auth GoTrue internals** — use Admin API only
- **`drift/skills/supabase-auth/`** — reference only

---

## Verification Commands

```bash
supabase start && supabase db reset          # Migrations apply cleanly
supabase functions serve                      # Edge Functions start

# Test SCIM /Users create:
curl -s -X POST http://localhost:54321/functions/v1/scim-users/scim/v2/Users \
  -H "Authorization: Bearer <test-token>" \
  -H "Content-Type: application/scim+json" \
  -d '{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"test@example.com","emails":[{"value":"test@example.com","primary":true}],"active":true}'
# Expected: 201

# RLS policies exist:
psql "$SUPABASE_DB_URL" -c "SELECT tablename, policyname FROM pg_policies WHERE tablename IN ('scim_tokens','scim_group_mappings');"
# Expected: 1+ policy per table

# No service_role key in source:
grep -rn "SUPABASE_SERVICE_ROLE_KEY" supabase/functions/ | grep -v "Deno.env.get"
# Expected: 0 matches

# Full tests:
cd supabase && deno test tests/ --allow-net --allow-env
# Expected: 8 tests, 0 failures
```

---

## Critical Questions Per Sub-Phase

### After D1:
- How are SCIM tokens stored? (SHA-256 hash only)
- Is RLS enabled on `scim_tokens`? (Yes — ENABLE + FORCE + policy)
- How does SCIM auth differ from JWT auth? (Long-lived bearer token vs. short-lived JWT)

### After D2:
- What happens on `PATCH active:false`? (6-step deprovisioning: ban, revoke keys, end sessions, mark inactive, audit)
- Can a deprovisioned user still make API calls? (No — auth banned + keys revoked + sessions ended)
- Does POST /Users check uniqueness within tenant? (Yes — `user_tenant_mappings` query)

### After D3:
- How are IdP groups mapped to Drift roles? (`scim_group_mappings` table, default=member)
- What happens if a user in group PATCH doesn't belong to the tenant? (Silently skipped)

### After D4:
- Can a `member` create SCIM tokens? (No — admin role check enforced)
- Is the raw token ever stored? (No — only SHA-256 hash)

---

## Quality Gate (QG-D) — All Must Pass

- [ ] SCIM `/Users` CRUD works (create, get, list with filter, update via PatchOp, delete)
- [ ] SCIM `/Groups` CRUD works (create, get, list, update membership, delete)
- [ ] Deprovisioning revokes all access within 60s (Auth banned, API keys revoked, sessions ended)
- [ ] SCIM bearer token auth enforced on all `/scim/v2/*` endpoints
- [ ] Tenant isolation verified — cross-tenant SCIM access returns 404
- [ ] Okta SCIM test harness passes (or Azure AD SCIM validator)
- [ ] All 8 Phase D tests pass
- [ ] Audit log entries created for all provisioning/deprovisioning events
- [ ] RLS enabled + forced on all new tables
- [ ] No service_role key exposed in code, logs, or responses
- [ ] SCIM error responses comply with RFC 7644 §3.12

---

## Testing Standards

Every test you write must meet ALL of these criteria.

### What Makes a Good Test
- **Tests the security boundary** — not "does create work?" but "can tenant A's SCIM token access tenant B's users?"
- **Has concrete assertions on response shape** — not `assert(res.ok)` but `assert.equal(res.status, 201)` + `assert(body.schemas.includes('urn:ietf:params:scim:schemas:core:2.0:User'))` + `assert(body.id)`
- **Exercises RFC compliance** — Content-Type is `application/scim+json`, pagination uses 1-based `startIndex`, error responses include `schemas` array
- **Targets a specific failure mode** — deprovisioning test verifies ALL 6 revocation steps completed, not just "no error"
- **Uses real Supabase local dev** — tests run against `supabase start` (real Postgres + GoTrue + RLS), not mocks

### What Makes a Bad Test (do NOT write these)
- Tests that mock Supabase Auth responses — you MUST test against real GoTrue
- Tests that skip RLS by using the `service_role` key for assertions — use anon/SCIM-token-scoped queries
- Tests that only check HTTP status codes without verifying response body shape
- Tests that create test data without cleaning it up (each test must be isolated)
- Tests that test Hono routing instead of SCIM compliance (router is trivial — security is not)

### Specific Test Patterns Required
- **Tenant isolation:** Every CRUD test must include a cross-tenant assertion. Create user in tenant A → attempt access from tenant B's SCIM token → must return 404 (not 403 — SCIM spec says resources not in scope are "not found", not "forbidden").
- **Deprovisioning completeness:** CT0-D-02 must verify ALL 6 steps: (1) `auth.users` banned, (2) `api_keys` revoked, (3) sessions cleared, (4) `user_tenant_mappings.active` = false, (5) `user_tenant_mappings.deprovisioned_at` set, (6) `cloud_audit_log` entry with action `user.deprovisioned`.
- **SCIM error format:** Every 4xx response must have `schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"]`, `status` as string, and `detail` message. Validate with a shared assertion helper.
- **Pagination boundary:** Test with exactly 0, 1, `count`, and `count+1` resources to catch off-by-one errors. Verify `totalResults` is accurate, `startIndex` is 1-based, `itemsPerPage` matches actual `Resources.length`.
- **Idempotency:** Creating the same `userName` twice in the same tenant must return 409 Conflict with `scimType: "uniqueness"` — not a duplicate row.
- **PatchOp validation:** PATCH with invalid `op` (e.g., `"op": "delete"`) must return 400 with `scimType: "invalidValue"`. PATCH with invalid `path` must return 400 with `scimType: "invalidPath"`.

---

## How to Verify Your Work

After each sub-phase, run these commands. Do not proceed to the next sub-phase if any fail.

```bash
# ── Sub-Phase D1: Infrastructure ──

# Migrations apply cleanly:
supabase start && supabase db reset
# Expected: 0 errors, both scim_tokens and scim_group_mappings tables created

# RLS policies exist:
psql "$SUPABASE_DB_URL" -c "SELECT tablename, policyname FROM pg_policies WHERE tablename IN ('scim_tokens','scim_group_mappings');"
# Expected: 1+ policy per table (tenant_isolation)

# RLS is FORCED (not just enabled):
psql "$SUPABASE_DB_URL" -c "SELECT relname, relforcerowsecurity FROM pg_class WHERE relname IN ('scim_tokens','scim_group_mappings');"
# Expected: relforcerowsecurity = true for both

# Edge Functions compile:
supabase functions serve
# Expected: scim-users, scim-groups, scim-admin all registered

# set_tenant_context SQL function exists:
psql "$SUPABASE_DB_URL" -c "SELECT proname FROM pg_proc WHERE proname = 'set_tenant_context';"
# Expected: 1 row

# ── Sub-Phase D2: SCIM /Users ──

# Create user returns 201 with SCIM schema:
curl -s -o /dev/null -w "%{http_code}" -X POST \
  http://localhost:54321/functions/v1/scim-users/scim/v2/Users \
  -H "Authorization: Bearer <test-token>" \
  -H "Content-Type: application/scim+json" \
  -d '{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"test@example.com","emails":[{"value":"test@example.com","primary":true}],"active":true}'
# Expected: 201

# Deprovisioning works (create → deactivate → verify ban):
# Run CT0-D-02 test in isolation

# ── Sub-Phase D3: SCIM /Groups ──

# Teams table exists (or placeholder):
psql "$SUPABASE_DB_URL" -c "SELECT count(*) FROM information_schema.tables WHERE table_name = 'teams';"
# Expected: 1

# Create group returns 201:
curl -s -o /dev/null -w "%{http_code}" -X POST \
  http://localhost:54321/functions/v1/scim-groups/scim/v2/Groups \
  -H "Authorization: Bearer <test-token>" \
  -H "Content-Type: application/scim+json" \
  -d '{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Engineering"}'
# Expected: 201

# ── Sub-Phase D4: Token Management + Conformance ──

# Token creation requires JWT auth (not SCIM token):
curl -s -o /dev/null -w "%{http_code}" -X POST \
  http://localhost:54321/functions/v1/scim-admin/api/v1/settings/scim \
  -H "Authorization: Bearer <user-jwt>" \
  -H "Content-Type: application/json" \
  -d '{"description":"Okta production"}'
# Expected: 201 (with admin JWT), 403 (with member JWT)

# ── Full Test Suite ──
cd supabase && deno test tests/ --allow-net --allow-env
# Expected: 8 tests, 0 failures
```

---

## Verification Grep Commands

After all implementation is complete, these static analysis checks confirm security compliance:

```bash
# No service_role key hardcoded anywhere:
grep -rn "SUPABASE_SERVICE_ROLE_KEY" supabase/functions/ | grep -v "Deno.env.get"
# Expected: 0 matches

# No raw SQL concatenation (SQL injection risk):
grep -rn "INSERT INTO.*\${" supabase/functions/ | grep -v ".test."
# Expected: 0 matches (all queries must use parameterized $1, $2, ...)

# No raw token storage (must be hashed):
grep -rn "token_hash\|token" supabase/migrations/ | grep -v "sha256\|SHA-256\|hash\|_hash\|HASH"
# Verify: every token column is a hash, never raw

# All tables have RLS enabled:
psql "$SUPABASE_DB_URL" -c "
  SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity 
  FROM pg_class c 
  JOIN pg_namespace n ON n.oid = c.relnamespace 
  WHERE n.nspname = 'public' 
    AND c.relname IN ('scim_tokens','scim_group_mappings','teams','team_memberships','cloud_audit_log')
    AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity);
"
# Expected: 0 rows (all tables have both RLS enabled AND forced)

# SCIM error schema used in all error paths:
grep -rn "ScimError\|scimError\|application/scim+json" supabase/functions/scim-*/
# Expected: multiple matches in each scim-* function

# Audit logging on every mutation handler:
grep -rn "logAuditEvent" supabase/functions/scim-*/
# Expected: 1+ match per POST/PATCH/PUT/DELETE handler

# Content-Type set on all SCIM responses:
grep -rn "application/scim+json" supabase/functions/scim-*/
# Expected: set in all SCIM response helpers

# No localhost/private IP in URL validation:
grep -rn "localhost\|127\.0\.0\|10\.0\.0\|192\.168\|172\.16" supabase/functions/ | grep -v test | grep -v "\.md"
# Expected: only in URL validation deny list, not in any hardcoded URLs
```

---

## Appendix A: SCIM Resource Schema Reference

### SCIM User Resource (RFC 7643 §4.1)

```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "id": "uuid-from-supabase-auth",
  "externalId": "idp-external-id",
  "userName": "user@example.com",
  "name": {
    "givenName": "Jane",
    "familyName": "Doe",
    "formatted": "Jane Doe"
  },
  "displayName": "Jane Doe",
  "emails": [
    {
      "value": "user@example.com",
      "type": "work",
      "primary": true
    }
  ],
  "active": true,
  "meta": {
    "resourceType": "User",
    "created": "2026-02-11T12:00:00Z",
    "lastModified": "2026-02-11T12:00:00Z",
    "location": "https://api.drift.dev/scim/v2/Users/uuid"
  }
}
```

**Required fields on POST:** `userName`, `emails` (at least one with `primary: true`)
**Required fields on response:** `id`, `userName`, `meta`, `schemas`
**Fields we support for PATCH:** `active`, `name.givenName`, `name.familyName`, `displayName`, `emails`
**Fields we do NOT support:** `password`, `phoneNumbers`, `photos`, `addresses`, `entitlements`, `roles`, `x509Certificates`

### SCIM Group Resource (RFC 7643 §4.2)

```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
  "id": "team-uuid",
  "displayName": "Engineering",
  "members": [
    {
      "value": "user-uuid",
      "display": "Jane Doe",
      "$ref": "https://api.drift.dev/scim/v2/Users/user-uuid"
    }
  ],
  "meta": {
    "resourceType": "Group",
    "created": "2026-02-11T12:00:00Z",
    "lastModified": "2026-02-11T12:00:00Z",
    "location": "https://api.drift.dev/scim/v2/Groups/team-uuid"
  }
}
```

### SCIM List Response

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
  "totalResults": 25,
  "itemsPerPage": 10,
  "startIndex": 1,
  "Resources": [ /* array of User or Group resources */ ]
}
```

### SCIM PatchOp Request

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [
    { "op": "replace", "path": "active", "value": false },
    { "op": "replace", "path": "name.givenName", "value": "Janet" },
    { "op": "add", "path": "members", "value": [{ "value": "user-uuid" }] },
    { "op": "remove", "path": "members[value eq \"user-uuid\"]" }
  ]
}
```

**Supported `op` values:** `add`, `remove`, `replace`
**Unsupported (return 400 `invalidValue`):** `move`, `copy`, `test`

### SCIM Error Response (RFC 7644 §3.12)

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
  "status": "409",
  "scimType": "uniqueness",
  "detail": "User with userName 'user@example.com' already exists in this tenant."
}
```

**Error type mapping:**

| HTTP Status | `scimType` | When |
|-------------|------------|------|
| 400 | `invalidFilter` | Malformed `filter` query parameter |
| 400 | `invalidSyntax` | Request body fails JSON schema validation |
| 400 | `invalidValue` | Field value out of range or wrong type |
| 400 | `invalidPath` | PatchOp `path` doesn't match any attribute |
| 401 | *(none)* | Missing or invalid SCIM bearer token |
| 403 | *(none)* | Valid token but insufficient permissions |
| 404 | *(none)* | Resource not found (or not in tenant scope — same response) |
| 409 | `uniqueness` | Duplicate `userName` within tenant |
| 413 | `tooLarge` | Bulk request exceeds limit |
| 429 | *(none)* | Rate limited |
| 500 | *(none)* | Internal server error (log details, generic response) |

---

## Appendix B: Prerequisite & Placeholder Tables

Phase D assumes several tables exist from Phase 1 (Cloud Infrastructure) and Phase F (Teams). If running in parallel with Phases A-C, create these as prerequisite migrations **before** SCIM migrations.

### Prerequisite Migration: `20260211000000_base_cloud_tables.sql`

These tables MUST exist before SCIM endpoints can function. If Phase 1 has already created them, skip this migration.

```sql
-- ── Tenants (Phase 1 / P1-07) ──
CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    plan TEXT NOT NULL DEFAULT 'free'
        CHECK (plan IN ('free', 'pro', 'team', 'enterprise')),
    owner_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenants_isolation ON tenants
    USING (id = current_setting('app.tenant_id', true)::UUID);

-- ── User-Tenant Mappings (Phase 1 / P1-07) ──
CREATE TABLE IF NOT EXISTS user_tenant_mappings (
    user_id UUID NOT NULL,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    role TEXT NOT NULL DEFAULT 'member'
        CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
    active BOOLEAN NOT NULL DEFAULT true,
    scim_external_id TEXT,
    deprovisioned_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, tenant_id)
);
ALTER TABLE user_tenant_mappings ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_tenant_mappings FORCE ROW LEVEL SECURITY;
CREATE POLICY utm_isolation ON user_tenant_mappings
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);

-- ── Projects (Phase 1 / P1-07) ──
CREATE TABLE IF NOT EXISTS projects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE projects FORCE ROW LEVEL SECURITY;
CREATE POLICY projects_isolation ON projects
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);

-- ── API Keys (Phase 1 / P1-07) ──
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    key_hash TEXT NOT NULL,
    name TEXT NOT NULL,
    scopes TEXT[] NOT NULL DEFAULT '{}',
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ
);
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY api_keys_isolation ON api_keys
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);

-- ── Tenant context helper function ──
CREATE OR REPLACE FUNCTION set_tenant_context(p_tenant_id UUID) 
RETURNS void 
LANGUAGE plpgsql 
SECURITY DEFINER
AS $$ 
BEGIN 
    PERFORM set_config('app.tenant_id', p_tenant_id::text, true); 
END; 
$$;
```

### Placeholder Migration: `20260211000003_phase_f_placeholders.sql`

Phase D's `/Groups` endpoint maps IdP groups to Drift teams. If Phase F hasn't run yet, create minimal placeholder tables. Phase F will `ALTER` these with additional columns/constraints.

```sql
-- ── Teams (Phase F / CP0-F-07 — placeholder) ──
CREATE TABLE IF NOT EXISTS teams (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    scim_external_id TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);
ALTER TABLE teams ENABLE ROW LEVEL SECURITY;
ALTER TABLE teams FORCE ROW LEVEL SECURITY;
CREATE POLICY teams_isolation ON teams
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);

-- ── Team Memberships (Phase F / CP0-F-07 — placeholder) ──
CREATE TABLE IF NOT EXISTS team_memberships (
    team_id UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id UUID NOT NULL,
    role TEXT NOT NULL DEFAULT 'member'
        CHECK (role IN ('lead', 'member')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (team_id, user_id)
);
ALTER TABLE team_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE team_memberships FORCE ROW LEVEL SECURITY;
CREATE POLICY team_memberships_isolation ON team_memberships
    USING (team_id IN (
        SELECT id FROM teams WHERE tenant_id = current_setting('app.tenant_id', true)::UUID
    ));

-- ── Cloud Audit Log (Phase F / CP0-F-01 — placeholder) ──
CREATE TABLE IF NOT EXISTS cloud_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    actor_id UUID NOT NULL,
    actor_email TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    metadata JSONB,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE cloud_audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_audit_log FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_tenant_isolation ON cloud_audit_log
    USING (tenant_id = current_setting('app.tenant_id', true)::UUID);
CREATE POLICY audit_no_update ON cloud_audit_log FOR UPDATE USING (false);
CREATE POLICY audit_no_delete ON cloud_audit_log FOR DELETE USING (false);
```

**Migration ordering:**
```
20260211000000_base_cloud_tables.sql       ← Prerequisites (tenants, users, projects, api_keys)
20260211000001_scim_tokens.sql             ← Phase D (this phase)
20260211000002_scim_group_mappings.sql     ← Phase D (this phase)
20260211000003_phase_f_placeholders.sql    ← Placeholders for Phase F tables
```

---

## Appendix C: SCIM Compliance Matrix

### Okta SCIM 2.0 Required Features

| Feature | RFC Ref | Status | Notes |
|---------|---------|--------|-------|
| **POST /Users** (create) | §3.3 | MUST implement | Maps to `auth.admin.createUser()` |
| **GET /Users/:id** (read) | §3.4.1 | MUST implement | |
| **GET /Users** (list) | §3.4.2 | MUST implement | With `startIndex` + `count` pagination |
| **PATCH /Users/:id** (update) | §3.5.2 | MUST implement | PatchOp: `replace` on `active`, `name`, `emails` |
| **PUT /Users/:id** (replace) | §3.5.1 | SHOULD implement | Full resource replace |
| **DELETE /Users/:id** | §3.6 | SHOULD implement | Soft-delete via deprovisioning |
| **filter=userName eq "x"** | §3.4.2.2 | MUST implement | Okta requires this for user matching |
| **filter=externalId eq "x"** | §3.4.2.2 | SHOULD implement | Azure AD uses this |
| **POST /Groups** (create) | §3.3 | MUST for group push | |
| **PATCH /Groups/:id** (members) | §3.5.2 | MUST for group push | `add`/`remove` members |
| **Bearer token auth** | — | MUST implement | Long-lived, per-tenant, admin-managed |
| **Content-Type: application/scim+json** | §3.1 | MUST on all responses | |
| **Error schema** | §3.12 | MUST on all errors | `schemas` + `status` + `detail` |
| **Meta resource** | §3.1 | MUST on all resources | `resourceType`, `created`, `lastModified`, `location` |

### Azure AD Additional Requirements

| Feature | Status | Notes |
|---------|--------|-------|
| **`externalId` support** | MUST implement | Azure AD maps users by `externalId`, not `userName` |
| **Bulk operations** (`POST /Bulk`) | NOT implementing | Optional in RFC — Okta doesn't use it |
| **Password sync** | NOT implementing | IdP manages passwords |
| **Schema discovery** (`GET /Schemas`) | SHOULD implement | Returns supported resource schemas |
| **Service provider config** (`GET /ServiceProviderConfig`) | SHOULD implement | Advertises supported features |
| **Resource types** (`GET /ResourceTypes`) | SHOULD implement | Advertises User + Group support |

### Discovery Endpoints (nice-to-have, aids conformance testing)

Add these to `scim-users/index.ts` or a dedicated `scim-discovery/index.ts`:

```json
// GET /scim/v2/ServiceProviderConfig
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
  "patch": { "supported": true },
  "bulk": { "supported": false },
  "filter": { "supported": true, "maxResults": 200 },
  "changePassword": { "supported": false },
  "sort": { "supported": false },
  "etag": { "supported": false },
  "authenticationSchemes": [{
    "type": "oauthbearertoken",
    "name": "OAuth Bearer Token",
    "description": "SCIM bearer token authentication"
  }]
}

// GET /scim/v2/ResourceTypes
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
  "totalResults": 2,
  "Resources": [
    { "id": "User", "name": "User", "endpoint": "/Users", "schema": "urn:ietf:params:scim:schemas:core:2.0:User" },
    { "id": "Group", "name": "Group", "endpoint": "/Groups", "schema": "urn:ietf:params:scim:schemas:core:2.0:Group" }
  ]
}
```

---

## Appendix D: Cross-Phase Dependency Map

Phase D has soft dependencies on tables from other phases. This map shows exactly which tables are needed, where they come from, and what to do if the source phase hasn't run yet.

```
Phase D (SCIM Provisioning)
│
├── HARD DEPENDS ON ─────────────────────────────────────────────────
│   ├── tenants             ← Phase 1 (P1-07) OR Appendix B prerequisite migration
│   ├── user_tenant_mappings ← Phase 1 (P1-07) OR Appendix B prerequisite migration
│   ├── api_keys            ← Phase 1 (P1-07) OR Appendix B prerequisite migration
│   └── set_tenant_context()← Phase 1 (P1-07) OR Appendix B prerequisite migration
│
├── SOFT DEPENDS ON (create placeholders if missing) ────────────────
│   ├── teams               ← Phase F (CP0-F-07) OR Appendix B placeholder migration
│   ├── team_memberships    ← Phase F (CP0-F-07) OR Appendix B placeholder migration
│   └── cloud_audit_log     ← Phase F (CP0-F-01) OR Appendix B placeholder migration
│
├── PRODUCES (consumed by later phases) ─────────────────────────────
│   ├── scim_tokens         → Phase E (webhook SCIM events), Phase G (integration tests)
│   ├── scim_group_mappings → Phase F (team management), Phase G (integration tests)
│   └── deprovision()       → Phase E (webhook dispatch: user.deprovisioned event)
│
└── INDEPENDENT OF ──────────────────────────────────────────────────
    ├── Phase A (Drift storage traits) — no Rust code in Phase D
    ├── Phase B (Drift engine + NAPI) — no Rust code in Phase D
    ├── Phase C (Bridge storage) — no Rust code in Phase D
    └── Phase E (Webhooks) — Phase D emits audit events but does NOT dispatch webhooks
                              (webhook dispatch is Phase E's responsibility;
                               Phase D only writes to cloud_audit_log)
```

**Key decision:** Phase D's `deprovisionUser()` writes to `cloud_audit_log` but does NOT emit a `user.deprovisioned` webhook. That webhook wiring happens in Phase E (CP0-E-07 through CP0-E-09). Phase D prepares for it by structuring the audit log entry so Phase E can subscribe to it, but Phase D itself has zero webhook code.

**If Phase 1 hasn't run:** Use the prerequisite migration in Appendix B. All tables use `CREATE TABLE IF NOT EXISTS` so they're safe to re-run after Phase 1 adds the full versions.

**If Phase F hasn't run:** Use the placeholder migration in Appendix B. Tables have `IF NOT EXISTS` and minimal columns. Phase F will `ALTER TABLE` to add additional columns, constraints, and indexes.

---

## Appendix E: Implementation Plan Cross-Reference

Every task ID from `CLOUD-P0-IMPLEMENTATION-PLAN.md` Phase D, mapped to this prompt:

### Implementation Tasks

| Plan ID | Task | Prompt Section | Status |
|---------|------|----------------|--------|
| CP0-D-01 | Decision gate: WorkOS vs. hand-rolled SCIM | Decision Gate section | Covered |
| CP0-D-02 | SCIM bearer token infrastructure | Sub-Phase D1 + Sub-Phase D4 | Covered |
| CP0-D-03 | POST /scim/v2/Users (create) | Sub-Phase D2: POST /scim/v2/Users | Covered |
| CP0-D-04 | GET /scim/v2/Users (list/filter) | Sub-Phase D2: GET /scim/v2/Users | Covered |
| CP0-D-05 | PATCH /scim/v2/Users/:id (update) | Sub-Phase D2: PATCH /scim/v2/Users/:id | Covered |
| CP0-D-06 | DELETE /scim/v2/Users/:id | Sub-Phase D2: DELETE /scim/v2/Users/:id | Covered |
| CP0-D-07 | Deprovisioning logic (6 steps) | Sub-Phase D2: shared/deprovision.ts | Covered |
| CP0-D-08 | SCIM /Groups CRUD | Sub-Phase D3 | Covered |
| CP0-D-09 | Group-to-role mapping | Sub-Phase D3: scim_group_mappings | Covered |
| CP0-D-10 | Conformance validation (Okta/Azure AD) | Sub-Phase D4 | Covered |

### Test Tasks

| Plan ID | Test | Prompt Section | Status |
|---------|------|----------------|--------|
| CT0-D-01 | SCIM create user → Auth + mapping exists | Tests: CT0-D-01 | Covered |
| CT0-D-02 | Deactivate → all access revoked | Tests: CT0-D-02 | Covered |
| CT0-D-03 | List with filter | Tests: CT0-D-03 | Covered |
| CT0-D-04 | Pagination correctness | Tests: CT0-D-04 | Covered |
| CT0-D-05 | Group creates team | Tests: CT0-D-05 | Covered |
| CT0-D-06 | Group membership syncs | Tests: CT0-D-06 | Covered |
| CT0-D-07 | Bearer token auth enforced | Tests: CT0-D-07 | Covered |
| CT0-D-08 | Tenant isolation | Tests: CT0-D-08 | Covered |

### Quality Gate Items

| QG Item | Prompt Coverage |
|---------|-----------------|
| SCIM `/Users` CRUD works | Sub-Phase D2 |
| SCIM `/Groups` CRUD works | Sub-Phase D3 |
| Deprovisioning within 60s | Sub-Phase D2: deprovision.ts |
| Bearer token auth enforced | Sub-Phase D1: scim-auth.ts |
| Tenant isolation verified | Tests: CT0-D-08, Grep commands |
| Okta/Azure AD conformance | Sub-Phase D4, Appendix C |
| All 8 tests pass | Tests section |
| Audit log entries created | Sub-Phase D2: step 6 of deprovisioning + all mutation handlers |
| RLS enabled + forced | Migrations (ENABLE + FORCE), Grep commands |
| No service_role key exposed | Forbidden Actions #1, Grep commands |
| SCIM error compliance | Sub-Phase D1: scim-errors.ts, Appendix A error table |

### Tracker Cross-Reference

| Tracker Ref | Tracker Section | Plan Phase |
|-------------|-----------------|------------|
| GAP-01 | §11a (line ~1007) | Phase D (this phase) |
| P6-01 | §8 Phase 6a (line ~837) | CP0-D-01 |
| P6-02 | §8 Phase 6a (line ~838) | CP0-D-03 through D-06 |
| P6-03 | §8 Phase 6a (line ~839) | CP0-D-08 |
| P6-04 | §8 Phase 6a (line ~840) | CP0-D-07 |
| P6-05 | §8 Phase 6a (line ~841) | CP0-D-10 |

**Coverage: 10/10 impl tasks + 8/8 test tasks + 11/11 QG items + 6/6 tracker refs = 100%**
