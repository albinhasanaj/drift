# ADR-001: SCIM Provider — Hand-Rolled vs. WorkOS

## Status

**Accepted** — 2026-02-11

## Context

Enterprise identity providers (Okta, Azure AD, OneLogin) require SCIM 2.0 endpoints (RFC 7644) for automated user provisioning and deprovisioning. Drift needs SCIM to pass enterprise procurement security questionnaires.

Two options were evaluated:

### Option A: WorkOS

- **Pros:** Unified SSO+SCIM service, handles conformance automatically, pre-built IdP integrations, reduces implementation to a thin webhook receiver (~100 lines).
- **Cons:** Per-connection pricing ($25–$125/connection/month at scale), vendor lock-in on a critical security path, adds external dependency for user lifecycle management, requires routing auth through WorkOS instead of Supabase Auth for enterprise tier.

### Option B: Hand-Rolled SCIM (Supabase Edge Functions)

- **Pros:** Full control over implementation, zero per-connection cost, no vendor dependency, consistent auth stack (Supabase Auth for all tiers), ~500-800 lines of code across 3 Edge Functions + shared helpers.
- **Cons:** Must implement and maintain RFC 7644 compliance, must pass Okta/Azure AD conformance testing ourselves, slightly higher initial effort (2-3 days vs. 1 day).

## Decision

**Hand-rolled SCIM on Supabase Edge Functions.**

### Rationale

1. **Cost:** At 100 enterprise connections, WorkOS costs $2,500-$12,500/month. Hand-rolled costs $0 incremental (already on Supabase Pro).
2. **Auth consistency:** Keeping all user management in Supabase Auth avoids a split-brain auth architecture where Free/Pro users are in GoTrue and Enterprise users are in WorkOS.
3. **Control:** Deprovisioning is the most security-critical flow in the enterprise product. Owning it end-to-end ensures we can audit, extend, and debug without vendor support tickets.
4. **Scope:** SCIM 2.0 `/Users` and `/Groups` CRUD is well-specified (RFC 7644). The implementation is bounded (~800 lines) and testable against standard conformance harnesses.
5. **Reversibility:** If hand-rolled maintenance becomes burdensome, migrating to WorkOS later is straightforward — the SCIM token and user mapping tables remain the same, only the Edge Function handlers change.

## Consequences

- We own SCIM conformance testing (Okta SCIM test harness + Azure AD SCIM validator).
- We must maintain RFC 7644 compliance as IdPs update their SCIM clients.
- No SSO bundling — SSO remains via Supabase Auth SAML (separate from SCIM).
- Future option to add WorkOS as an alternative Enterprise-tier SCIM provider behind feature flag.
