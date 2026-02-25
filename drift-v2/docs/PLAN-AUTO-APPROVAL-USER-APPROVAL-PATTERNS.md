# Plan: Auto-Approval + User Approval for Patterns

> **Objective:** Add pattern-level auto-approval (above threshold) and user approval (below threshold) to the drift v2 build, ensuring 100% end-to-end functionality with zero code changes in this document — **plan only**.

---

## Executive Summary

**Current state:** The `AutoApprover` exists in `drift-analysis` but is never invoked. `drift_audit` computes `auto_approved_count` and `needs_review_count` from **violation feedback** (fix/suppress counts), not from **pattern classification**. No CLI or NAPI exists for user approval of patterns; `PatternStatus` exists in types but has no storage backing.

**Target state:** Patterns meeting confidence/outlier/location criteria are auto-approved; patterns below threshold require user approval. User approval persists to storage and flows through audit, report, MCP, and CI.

---

## 1. Upstream Data Flow

### 1.1 Where Patterns Come From

| Source | Table | Fields Used | Notes |
|-------|-------|-------------|-------|
| Confidence | `pattern_confidence` | `pattern_id`, `posterior_mean`, `alpha`, `beta`, `tier`, `momentum` | Single row per pattern |
| Locations | `detections` | `pattern_id`, `file`, `line`, `category` | Aggregate COUNT by pattern_id for `location_count` |
| Outliers | `outliers` | `pattern_id` | Aggregate COUNT by pattern_id for `outlier_count` |
| Conventions | `conventions` | `pattern_id`, `category`, `scope`, `promotion_status` | For name/category fallback |
| Call graph | `call_edges` | `caller_id`, `callee_id` | Need join via `functions` to check if pattern’s locations appear in graph |
| Constraints | `constraint_verifications` | per-constraint | For `constraint_issues`; may be optional initially |

**Gap:** No `status` column. `pattern_confidence` has no `status`. `conventions` has `promotion_status` (discovered/candidate/promoted) but that is convention-level, not pattern-level.

### 1.2 PatternAuditData Requirements

`PatternAuditData` (in `audit/types.rs`) requires:

| Field | Source | Migration / Query |
|-------|--------|-------------------|
| `id` | pattern_id | From pattern_confidence or detections GROUP BY |
| `name` | pattern_id (or conventions.name) | May derive from pattern_id initially |
| `category` | detections.category or conventions | Use first detection’s category |
| `status` | **NEW** | Add `pattern_status` table or column |
| `confidence` | pattern_confidence.posterior_mean | Existing |
| `location_count` | COUNT(detections) GROUP BY pattern_id | New query |
| `outlier_count` | COUNT(outliers) GROUP BY pattern_id | New query |
| `in_call_graph` | Join detections → functions → call_edges | Can default false initially |
| `constraint_issues` | Join constraint_verifications | Can default 0 initially |
| `has_error_issues` | Severity of violations where pattern_id matches | Optional; can default false |
| `locations` | file:line from detections | For Jaccard deduplication |

---

## 2. Storage Schema Changes

### 2.1 New Migration: `pattern_status` Table

**Rationale:** Research docs (02-STORAGE-V2-PREP, 12-PATTERN-AGGREGATION-V2-PREP) describe a `patterns` table with `status`. The current schema has `pattern_confidence`, `detections`, `outliers`, `conventions` but no pattern-level status. A minimal add is a `pattern_status` table.

**Migration file:** `v008_pattern_status.rs` (or append to v007_advanced if appropriate)

```sql
-- Pattern status for approval workflow (discovered | approved | ignored)
CREATE TABLE IF NOT EXISTS pattern_status (
    pattern_id TEXT PRIMARY KEY,
    status TEXT NOT NULL CHECK(status IN ('discovered','approved','ignored')),
    approved_by TEXT,
    approved_at INTEGER,
    reason TEXT,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX IF NOT EXISTS idx_pattern_status_status ON pattern_status(status);
```

**Default:** New patterns not in `pattern_status` are treated as `discovered`.

### 2.2 Alternative: Add Column to Existing Table

If `pattern_confidence` is the canonical pattern table, add:

```sql
ALTER TABLE pattern_confidence ADD COLUMN status TEXT DEFAULT 'discovered' CHECK(status IN ('discovered','approved','ignored'));
```

**Recommendation:** Prefer `pattern_status` table to avoid migration churn on `pattern_confidence` and keep status separate from confidence lifecycle.

---

## 3. Query Layer

### 3.1 New Queries

| Query | Location | Purpose |
|-------|----------|---------|
| `query_patterns_for_audit` | `drift-storage/queries/patterns.rs` or new `audit.rs` | Build `PatternAuditData[]` from pattern_confidence + detections + outliers + pattern_status |
| `upsert_pattern_status` | `drift-storage/queries/patterns.rs` | Set status for a pattern (approve/ignore) |
| `query_pattern_status` | Same | Get status for pattern_id(s) |

### 3.2 query_patterns_for_audit Logic

Pseudocode:

```
FOR each pattern_id IN (SELECT DISTINCT pattern_id FROM pattern_confidence
                        UNION SELECT DISTINCT pattern_id FROM detections):
  confidence = pattern_confidence.posterior_mean OR 0.0
  location_count = COUNT(detections WHERE pattern_id)
  outlier_count = COUNT(outliers WHERE pattern_id)
  status = pattern_status.status OR 'discovered'
  locations = [(file, line) from detections WHERE pattern_id]
  ...
  EMIT PatternAuditData
```

---

## 4. Auto-Approval Wiring

### 4.1 In drift_audit (NAPI)

**Current (enforcement.rs:183–187):**

```rust
let auto_approved_count = feedback_stats.fix_count + feedback_stats.suppress_count;
let needs_review_count = count_needs_review(conn);
```

**Target:**

1. Call `query_patterns_for_audit(conn)` → `Vec<PatternAuditData>`.
2. Call `AutoApprover::classify(&patterns)` → `(auto_approved, needs_review, likely_fp)`.
3. For each `auto_approved` pattern_id: `upsert_pattern_status(conn, pattern_id, "approved", source="auto")`.
4. Set `auto_approved_count = auto_approved.len()`, `needs_review_count = needs_review.len()`.

**Idempotency:** Auto-approve only updates status from `discovered` → `approved`. User-approved patterns are not overwritten.

### 4.2 Extend JsAuditResult (Optional)

Add `likely_fp_count` to `JsAuditResult` for UI/reporting; contracts already support additional fields.

---

## 5. User Approval Path

### 5.1 NAPI: drift_approve_pattern

**Signature:**

```rust
#[napi]
pub fn drift_approve_pattern(root: String, pattern_id: String, action: String) -> napi::Result<JsFeedbackResult>
```

**Actions:** `approve`, `ignore`.

**Behavior:** `upsert_pattern_status(conn, pattern_id, action)`.

### 5.2 NAPI: drift_pattern_status (Read)

```rust
#[napi]
pub fn drift_pattern_status(root: String, pattern_id: Option<String>) -> napi::Result<serde_json::Value>
```

Returns status for one pattern or all patterns (with status filter).

### 5.3 CLI: drift approve

**Command:**

```
drift approve <pattern_id> [--ignore]
drift approve --pattern <id> --action approve|ignore
```

Calls `drift_approve_pattern` via NAPI.

### 5.4 CLI: drift curate (Future)

Research (32-MCP-SERVER-V2-PREP) defines `drift_curate` with 6 actions: review, verify, approve, ignore, bulk-approve, audit. Phase 1 can implement only `approve` and `ignore`; `review`/`verify`/`bulk-approve` can follow.

---

## 6. Downstream Consumers

### 6.1 drift_audit

- Uses `query_patterns_for_audit` (which reads `pattern_status`).
- `auto_approved_count` and `needs_review_count` from `AutoApprover::classify`.
- Health score continues to use `approval_ratio` from `HealthScorer::compute` (which uses `status`).

### 6.2 drift_report

- Consumes violations + gate results. Pattern status does not change report format but may affect which patterns are considered “enforced” in future iterations.

### 6.3 drift_patterns (NAPI)

- Today returns detections. Consider adding `status` to each pattern in the response when pattern_id is present in `pattern_status`.

### 6.4 MCP: drift_tool

- Add `drift_approve_pattern` and `drift_pattern_status` to the tool catalog.
- Register in `MUTATION_TOOLS` for cache invalidation.

### 6.5 MCP: drift_curate (Planned)

- Implement `drift_curate` handler with `action=approve` and `action=ignore` delegating to `drift_approve_pattern`.

### 6.6 Cortex-Bridge

- If bridge correlates patterns with memories, ensure it reads `pattern_status` when joining drift data.

### 6.7 CI (drift-ci)

- No direct change. CI uses `drift_check` and `drift_audit`; improved audit counts are reflected automatically.

---

## 7. Edge Cases & Guarantees

### 7.1 Confidence Updates

- Confidence is updated by the feedback loop (fix/dismiss/suppress) → Bayesian update.
- Auto-approve runs at audit time with current confidence. If confidence later drops below 0.90, the pattern remains `approved` unless a separate “revoke” flow is added (out of scope for Phase 1).

### 7.2 Feedback Loop Interaction

- Violation feedback (fix, dismiss, suppress) updates `pattern_confidence` (alpha/beta).
- Pattern approval (`pattern_status`) is independent. Both feed into the audit: confidence affects classification; status affects `approval_ratio`.

### 7.3 Orphan Patterns

- Patterns in `pattern_confidence` with no detections: `location_count = 0` → fail `min_locations >= 3` → go to `needs_review` or `likely_fp`.

### 7.4 Concurrent Writes

- User approves pattern A while auto-approve runs. Use `INSERT OR REPLACE` / `upsert` with `updated_at`; last write wins. User approval should take precedence: if status is already `approved` by user, do not overwrite with auto.

### 7.5 Migration Safety

- New migration adds tables/columns. Existing DBs run migration on next open. No data loss.

---

## 8. Build & CI Integration

### 8.1 Rust

- `cargo check`, `cargo clippy`, `cargo test` in `crates/drift`. New code in `drift-storage`, `drift-napi`, `drift-analysis` must pass.

### 8.2 TypeScript

- `drift-napi-contracts`: Add types for `drift_approve_pattern`, `drift_pattern_status` if needed.
- `drift-cli`: New `approve` command.
- `drift-mcp`: New tool handlers.
- All must pass `npx vitest run` and `npx tsc --noEmit`.

### 8.3 NAPI Build

- `npx napi build` must succeed for all targets. No new native APIs beyond new NAPI functions.

### 8.4 Tests

| Layer | Test |
|-------|------|
| drift-storage | Migration applies; `query_patterns_for_audit` returns correct shape; `upsert_pattern_status` round-trip |
| drift-analysis | `AutoApprover::classify` with real `PatternAuditData` (existing tests) |
| drift-napi | `drift_audit` returns auto_approved_count from classifier; `drift_approve_pattern` persists |
| drift-cli | `drift approve <id>` exits 0 and updates status |
| drift-mcp | `drift_tool` with `drift_approve_pattern` succeeds |

---

## 9. Implementation Order

| Phase | Task | Deps |
|-------|------|------|
| 1 | Migration `pattern_status` | - |
| 2 | `query_patterns_for_audit`, `upsert_pattern_status`, `query_pattern_status` | 1 |
| 3 | Wire `AutoApprover::classify` in `drift_audit`; persist auto-approved status | 2 |
| 4 | NAPI `drift_approve_pattern`, `drift_pattern_status` | 2 |
| 5 | CLI `drift approve` | 4 |
| 6 | MCP `drift_approve_pattern`, `drift_pattern_status` in drift_tool | 4 |
| 7 | Contracts, tests, CI | 3–6 |

---

## 10. Success Criteria

- [ ] `drift audit` shows `auto_approved_count` and `needs_review_count` from `AutoApprover::classify` (not from feedback_stats).
- [ ] Patterns meeting 0.90 confidence, ≤0.50 outlier ratio, ≥3 locations, no error issues are auto-approved and appear in `pattern_status`.
- [ ] `drift approve <pattern_id>` and `drift approve <pattern_id> --ignore` persist to `pattern_status`.
- [ ] `drift audit` health score reflects `approval_ratio` from pattern status.
- [ ] MCP `drift_tool` can approve/ignore patterns.
- [ ] All CI jobs pass (rust-check, ts-check, napi-build).
- [ ] No regressions in `drift check`, `drift report`, `drift violations`, `drift gates`.

---

## 11. References

- `crates/drift/drift-analysis/src/enforcement/audit/auto_approve.rs` — AutoApprover
- `crates/drift/drift-analysis/src/enforcement/audit/types.rs` — PatternAuditData, PatternStatus
- `crates/drift/drift-napi/src/bindings/enforcement.rs` — drift_audit
- `crates/drift/drift-storage/src/queries/patterns.rs` — pattern_confidence, outliers, conventions
- `crates/drift/drift-storage/src/queries/detections.rs` — detections
- `docs/v2-research/systems/25-AUDIT-SYSTEM-V2-PREP.md` — Audit pipeline design
- `docs/v2-research/systems/32-MCP-SERVER-V2-PREP.md` — drift_curate
- `docs/v2-research/ENFORCEMENT-ENGINE-HARDENING-TASKS.md` — EF-NAPI-02, EF-AUD-01
