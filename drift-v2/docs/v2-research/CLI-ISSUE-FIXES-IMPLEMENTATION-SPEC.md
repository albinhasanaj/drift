# Drift CLI — Issue Fixes Implementation Specification

> **Version:** 1.1.0
> **Status:** COMPLETE — AWAITING APPROVAL
> **Last Updated:** 2026-02-12
> **Scope:** 12 CLI issues across cortex, enforcement, bridge, and cloud subsystems
> **Estimated Effort:** 8–12 hours (implementation + per-fix testing)
> **Affects:** `packages/drift-cli`, `crates/drift/drift-napi`, `crates/drift/drift-storage`, `crates/cortex-drift-bridge`, `packages/cortex`

## What This Document Is

This is the single source of truth for fixing 12 known issues in the Drift CLI. Each fix includes root cause analysis, upstream and downstream connection mapping, exact file locations with line references, proposed implementation, and a verification gate. An agent reading this document should be able to implement every fix, understand every connection, and know why every decision was made.

No fix is speculative. Every root cause was traced through the TypeScript CLI layer, across the NAPI bridge, and into the Rust storage/analysis/enforcement code where applicable.

---

## Table of Contents

1. [Cortex: `.cortex/` Directory Not Auto-Created](#fix-01-cortex-cortex-directory-not-auto-created)
2. [Report: No `--format` Option](#fix-02-report-no---format-option)
3. [Cortex Subcommands: Inconsistent `--format` Support](#fix-03-cortex-subcommands-inconsistent---format-support)
4. [Check / Report: Duplicate Gate Entries](#fix-04-check--report-duplicate-gate-entries)
5. [Check: Many Gates Skipped — No Data Available](#fix-05-check-many-gates-skipped--no-data-available)
6. [Status: False Degradation Alerts](#fix-06-status-false-degradation-alerts)
7. [Status: `healthScore` Always 0](#fix-07-status-healthscore-always-0)
8. [Violations: Empty Array](#fix-08-violations-empty-array)
9. [Context: Intent Must Be Exact Enum](#fix-09-context-intent-must-be-exact-enum)
10. [Cortex Add: Content Format Error](#fix-10-cortex-add-content-format-error)
11. [Bridge Health: `ready: false`](#fix-11-bridge-health-ready-false)
12. [Cloud: Not Configured](#fix-12-cloud-not-configured)
13. [Priority Matrix & Implementation Order](#priority-matrix--implementation-order)
14. [Dependency Graph](#dependency-graph)
15. [Verification Protocol](#verification-protocol)
16. [Risk Assessment](#risk-assessment)
17. [Rollback Plan](#rollback-plan)
18. [Codebase Accuracy Notes](#codebase-accuracy-notes)
19. [Files Modified Summary](#files-modified-summary)

---

## Fix 01: Cortex `.cortex/` Directory Not Auto-Created

**Severity:** HIGH — Blocks all cortex subcommands on first use.

**Symptom:** `Error: Storage error: SQLite error: unable to open database file: .cortex/cortex.db`

### Upstream Connections

| Source | Location | Role |
|--------|----------|------|
| `drift setup` | `packages/drift-cli/src/commands/setup.ts:81–95` | **Only** code path that creates `.cortex/` via `fs.mkdirSync()` |
| `getCortex()` | `packages/drift-cli/src/commands/cortex.ts:13–19` | Entry point for all cortex subcommands; defaults `dbPath` to `.cortex/cortex.db` |
| `CortexClient.initialize()` | `packages/cortex/src/bridge/client.ts:99–108` | Calls Rust `cortexInitialize()` with the path |
| `cortex_initialize()` | `crates/cortex/cortex-napi/src/bindings/lifecycle.rs` | Creates `CortexRuntime` with `StorageEngine` |
| `StorageEngine` | `crates/cortex/cortex-napi/src/runtime.rs` | Opens SQLite — fails if parent directory doesn't exist |

### Downstream Connections

| Consumer | Impact |
|----------|--------|
| `cortex status` | Fails — cannot query health without DB |
| `cortex add` | Fails — cannot create memories |
| `cortex list`, `cortex search`, `cortex predict` | Fail — cannot query DB |
| Bridge health (`bridge.ts`) | Reports `ready: false` (see Fix 11) |
| Bridge initialization (`lib.rs:98–103`) | Enters "degraded mode" when `.cortex/cortex.db` missing |

### Root Cause

`getCortex()` passes `.cortex/cortex.db` to `CortexClient.initialize()` without ensuring the parent directory exists. The Rust `StorageEngine` calls `rusqlite::Connection::open()` which requires the parent directory to exist. Only `drift setup` creates this directory, but cortex commands don't require prior setup.

### Proposed Fix

**File:** `packages/drift-cli/src/commands/cortex.ts`

Add directory auto-creation to `getCortex()`:

```typescript
import * as fs from 'fs';
import * as path from 'path';

let cortexClient: CortexClient | null = null;

async function getCortex(dbPath?: string): Promise<CortexClient> {
  if (cortexClient) return cortexClient;

  const resolvedPath = dbPath ?? '.cortex/cortex.db';
  const dir = path.dirname(resolvedPath);

  // Ensure parent directory exists (mirrors setup.ts:82–84)
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  cortexClient = await CortexClient.initialize({
    dbPath: resolvedPath,
  });
  return cortexClient;
}
```

**Why this approach:**
- Mirrors the pattern already established in `setup.ts:82–84`.
- `{ recursive: true }` is idempotent — safe if directory already exists.
- Does not remove or change the `setup.ts` code — belt-and-suspenders.
- `path.dirname()` works correctly for both relative and absolute `dbPath` values.

### Verification Gate

```
1. Delete `.cortex/` directory entirely
2. Run `drift cortex status` — should succeed (creates .cortex/, initializes DB, returns health)
3. Run `drift cortex list` — should return empty array, not an error
4. Confirm `drift setup` still works (creates .cortex/ if missing, skips if exists)
```

---

## Fix 02: Report: No `--format` Option

**Severity:** LOW — Confusing UX but not blocking.

**Symptom:** `error: unknown option '--format'`

### Upstream Connections

| Source | Location | Role |
|--------|----------|------|
| `report.ts` | `packages/drift-cli/src/commands/report.ts:17` | Defines `-r, --report-format <format>` (not `--format`) |
| `napi.driftReport()` | `crates/drift/drift-napi/src/bindings/enforcement.rs:248–278` | Rust-side report generation, accepts format string |
| Other commands | `check.ts:15`, `status.ts:14`, `scan.ts:16`, `context.ts:23` | All use `-f, --format <format>` — the expected convention |

### Downstream Connections

| Consumer | Impact |
|----------|--------|
| Users running `drift report --format json` | Get `unknown option` error instead of a report |
| CI scripts | May rely on `--format` for consistent output parsing |
| Documentation | Inconsistency confuses new users |

### Root Cause

`report.ts` uses `--report-format` because it supports 8 specialized report formats (`sarif, json, html, junit, sonarqube, console, github, gitlab`) distinct from the standard display formats (`table, json, sarif`). However, `json` appears in both sets, and users expect the familiar `-f, --format` flag.

### Proposed Fix

**File:** `packages/drift-cli/src/commands/report.ts`

Add `-f, --format` as a synonym that maps to the same option:

```typescript
program
  .command('report')
  .description('Generate a report from stored violations')
  .option('-f, --format <format>', `Report format: ${VALID_FORMATS.join(', ')}`, 'console')
  .option('-r, --report-format <format>', `(alias) Report format: ${VALID_FORMATS.join(', ')}`)
  .option('-o, --output <file>', 'Write output to file instead of stdout')
  .option('-q, --quiet', 'Suppress all output except errors')
  .action(async (opts: { format: string; reportFormat?: string; output?: string; quiet?: boolean }) => {
    const napi = loadNapi();
    // --report-format takes precedence if both provided
    const selectedFormat = opts.reportFormat ?? opts.format;
    try {
      if (!VALID_FORMATS.includes(selectedFormat as typeof VALID_FORMATS[number])) {
        process.stderr.write(`Invalid format '${selectedFormat}'. Valid: ${VALID_FORMATS.join(', ')}\n`);
        process.exitCode = 2;
        return;
      }
      const result = napi.driftReport(selectedFormat);
      if (opts.output) {
        const fs = await import('fs');
        fs.writeFileSync(opts.output, result, 'utf-8');
        if (!opts.quiet) {
          process.stdout.write(`Report written to ${opts.output}\n`);
        }
      } else if (!opts.quiet) {
        process.stdout.write(result);
        process.stdout.write('\n');
      }
    } catch (err) {
      process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
      process.exitCode = 2;
    }
  });
```

**Why this approach:**
- `-f, --format` becomes the primary flag — matches every other command.
- `--report-format` kept as alias for backward compatibility.
- `--report-format` takes precedence when both are provided (explicit intent).
- The valid format set remains unchanged (`sarif, json, html, junit, sonarqube, console, github, gitlab`).

### Verification Gate

```
1. `drift report --format json` — should produce JSON report
2. `drift report --report-format json` — should produce same JSON report (backward compat)
3. `drift report` — should default to `console`
4. `drift report --format invalid` — should show valid formats error
```

---

## Fix 03: Cortex Subcommands: Inconsistent `--format` Support

**Severity:** LOW — Cosmetic consistency issue.

**Symptom:** `cortex list --format json` → `error: unknown option '--format'`

### Upstream Connections

| Source | Location | Role |
|--------|----------|------|
| `cortex.ts` (all subcommands) | `packages/drift-cli/src/commands/cortex.ts:27–220` | Output via raw `JSON.stringify()`. `status` declares `-f, --format` but **ignores it** — always writes JSON. Other subcommands have no format option at all. |
| `formatOutput()` | `packages/drift-cli/src/output/index.ts` | Shared formatter used by `check`, `status`, `scan`, etc. |
| Output formatters | `packages/drift-cli/src/output/table.ts`, `json.ts`, `sarif.ts` | Table, JSON, SARIF renderers |

### Downstream Connections

| Consumer | Impact |
|----------|--------|
| `cortex status` | Always JSON, no table view |
| `cortex list` | Always JSON, no table view |
| `cortex search` | Always JSON, no table view |
| `cortex predict` | Always JSON, no table view |
| User scripts | Cannot switch between table (human) and json (machine) output |

### Root Cause

Cortex subcommands were implemented with direct `JSON.stringify()` calls instead of using the shared `formatOutput()` pipeline from `packages/drift-cli/src/output/index.ts`. Notably, `cortex status` already declares the `-f, --format` option (line 33) but never reads the value — its action handler unconditionally writes `JSON.stringify(...)`. The other subcommands (`list`, `search`, `predict`, `add`, etc.) lack the option entirely.

### Proposed Fix

**File:** `packages/drift-cli/src/commands/cortex.ts`

1. Add import at top:

```typescript
import { formatOutput, type OutputFormat } from '../output/index.js';
```

2. Wire the existing `--format` option on `status` (currently declared but ignored) and add `--format` to each remaining subcommand. Route all through `formatOutput()`. Example for `status`:

```typescript
cortex
  .command('status')
  .description('Show Cortex health dashboard')
  .option('-f, --format <format>', 'Output format: table, json', 'json')
  .action(async (opts: { db?: string; format: OutputFormat }) => {
    const client = await getCortex(opts.db);
    const [health, consolidation, degradations] = await Promise.all([
      client.healthReport(),
      client.consolidationStatus(),
      client.degradations(),
    ]);
    const result = {
      health,
      consolidation,
      degradation_count: degradations.length,
      degradations,
    };
    process.stdout.write(formatOutput(result, opts.format));
  });
```

3. Apply same pattern to `list`, `search`, `predict` subcommands. Default remains `json` (cortex data is deeply nested — table is secondary).

**Subcommands to update:**

| Subcommand | Default Format | Notes |
|------------|---------------|-------|
| `status` | `json` | Complex nested health data |
| `list` | `json` | Array of memories |
| `search` | `json` | Ranked results with scores |
| `predict` | `json` | Prediction with confidence |

### Verification Gate

```
1. `drift cortex status` — defaults to JSON (unchanged behavior)
2. `drift cortex status --format table` — produces table output
3. `drift cortex list --format json` — no error, produces JSON
4. `drift cortex search "test" --format table` — produces table output
```

---

## Fix 04: Check / Report: Duplicate Gate Entries

**Severity:** HIGH — Corrupts gate counts, distorts health score, inflates check output.

**Symptom:** Each gate (e.g., `security-boundaries`, `constraint-verification`, `pattern-compliance`) appears 2–4 times in `drift check` output.

### Upstream Connections

| Source | Location | Role |
|--------|----------|------|
| `gate_results` DDL | `crates/drift/drift-storage/src/migrations/v006_enforcement.rs:34–47` | Schema: `id INTEGER PRIMARY KEY AUTOINCREMENT` — **no UNIQUE on `gate_id`** |
| `insert_gate_result()` | `crates/drift/drift-storage/src/queries/enforcement.rs:167–177` | Uses `INSERT INTO` (not `INSERT OR REPLACE`) — appends every run |
| `GateOrchestrator` | `crates/drift/drift-analysis/src/enforcement/gates/orchestrator.rs` | Runs 6 gates per `drift analyze`; results inserted via `insert_gate_result()` |
| `drift analyze` | `crates/drift/drift-napi/src/bindings/analysis.rs:1478–1607` | Calls orchestrator on every invocation — inserts 6 new rows each time |

### Downstream Connections

| Consumer | Location | Impact |
|----------|----------|--------|
| `query_gate_results()` | `crates/drift/drift-storage/src/queries/enforcement.rs:179–207` | Returns **all** rows: `SELECT ... FROM gate_results ORDER BY run_at DESC` — no dedup |
| `drift_check()` | `crates/drift/drift-napi/src/bindings/enforcement.rs:96–128` | Maps all rows to `JsGateResult[]` — users see N copies of each gate |
| `drift_audit()` | `crates/drift/drift-napi/src/bindings/enforcement.rs:164–172` | Computes `cross_validation_rate` as `passed / total` — **diluted by duplicates** |
| `drift_report()` | `crates/drift/drift-napi/src/bindings/enforcement.rs:258–277` | Converts all rows to `GateResult` structs for reporters |
| `storage_to_gate_results()` | `crates/drift/drift-napi/src/bindings/enforcement.rs:281–284` | Utility that converts all gate rows — inherits the duplication |
| Health score (Fix 07) | `crates/drift/drift-napi/src/bindings/enforcement.rs:191–197` | `cross_validation_rate` feeds into health formula |

### Root Cause

Two-part failure:

1. **Schema**: `gate_results` has no `UNIQUE` constraint on `gate_id`. Each `drift analyze` inserts 6 new rows, so after N runs the table has 6×N rows.

2. **Query**: `query_gate_results()` returns `SELECT ... FROM gate_results ORDER BY run_at DESC` with no filtering — every historical row comes back.

### Proposed Fix

**Approach A (Query-side fix — recommended):** Modify `query_gate_results()` to return only the latest result per gate. This preserves history for future trend analysis while fixing all downstream consumers.

**File:** `crates/drift/drift-storage/src/queries/enforcement.rs` — function `query_gate_results()` (line 179)

Change the SQL from:

```sql
SELECT gate_id, status, passed, score, summary, violation_count, warning_count,
       execution_time_ms, details, error, run_at
FROM gate_results ORDER BY run_at DESC
```

To:

```sql
SELECT gate_id, status, passed, score, summary, violation_count, warning_count,
       execution_time_ms, details, error, run_at
FROM gate_results
WHERE id IN (
    SELECT id FROM gate_results AS gr2
    WHERE gr2.gate_id = gate_results.gate_id
    ORDER BY gr2.run_at DESC
    LIMIT 1
)
ORDER BY gate_id
```

**Alternatively** (cleaner, if SQLite version supports window functions — it does since 3.25.0):

```sql
SELECT gate_id, status, passed, score, summary, violation_count, warning_count,
       execution_time_ms, details, error, run_at
FROM (
    SELECT *, ROW_NUMBER() OVER (PARTITION BY gate_id ORDER BY run_at DESC) AS rn
    FROM gate_results
) WHERE rn = 1
ORDER BY gate_id
```

**Additionally**, add a `query_gate_history()` function for when trend data is needed:

```rust
pub fn query_gate_history(
    conn: &Connection,
    gate_id: &str,
    limit: u32,
) -> Result<Vec<GateResultRow>, StorageError> {
    // Returns historical runs for a specific gate, ordered newest-first
    let mut stmt = conn.prepare_cached(
        "SELECT gate_id, status, passed, score, summary, violation_count, warning_count,
                execution_time_ms, details, error, run_at
         FROM gate_results WHERE gate_id = ?1 ORDER BY run_at DESC LIMIT ?2"
    ).map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    // ... row mapping unchanged
}
```

**Why this approach:**
- Fixes all 4 downstream consumers (`drift_check`, `drift_audit`, `drift_report`, `storage_to_gate_results`) with a single query change.
- Preserves historical gate data for future trend features.
- No schema migration needed — backward compatible.
- Window functions are available in the minimum SQLite version bundled with `rusqlite`.

### Verification Gate

```
1. Run `drift scan && drift analyze` three times
2. `drift check --format json` — each gate appears exactly once (6 total, not 18)
3. `drift status --format json` — cross_validation_rate reflects only latest run
4. Query DB directly: `SELECT COUNT(*) FROM gate_results` — still has all rows (history preserved)
```

---

## Fix 05: Check: Many Gates Skipped — No Data Available

**Severity:** MEDIUM — Gates report misleading "skipped" status.

**Symptom:** `security-boundaries`, `constraint-verification`, `error-handling`, `test-coverage`, `regression` → "No data available" / "No architectural constraints defined"

### Upstream Connections

| Gate | Data Source | Populating Command | Status |
|------|------------|-------------------|--------|
| `pattern-compliance` | `detections` table | `drift scan && drift analyze` | **Works** — only gate with data after basic pipeline |
| `constraint-verification` | `architectural_constraints` table/config | User-defined constraints in `drift.toml` | **Empty** — no constraints defined by default |
| `security-boundaries` | `security_findings` table | `drift security` | **Empty** — requires separate security scan |
| `test-coverage` | `test_quality` data | `drift test-quality` | **Empty** — requires separate test analysis |
| `error-handling` | `error_handling_gaps` table | `drift errors` | **Empty** — requires separate error analysis |
| `regression` | Historical scan data (2+ snapshots) | `drift scan` (run 2+ times) | **Empty** — requires historical baseline |

### Downstream Connections

| Consumer | Impact |
|----------|--------|
| `drift check` output | 5 of 6 gates show "No data available" — appears broken |
| `cross_validation_rate` (Fix 07) | Only 1/6 gates has data → rate is artificially low |
| `healthScore` (Fix 07) | Low `cross_validation_rate` drags health score down |
| CI integration | Gates pass trivially when empty — false sense of security |

### Root Cause

The 6-gate system is designed for a full analysis pipeline (`scan → analyze → security → test-quality → errors`), but the typical user only runs `scan && analyze`. Five of six gates have no data, and their "skipped" status is not clearly communicated.

### Proposed Fix

**Two-part fix:** Better messaging + smarter gate exclusion.

**Part A — Actionable error messages in gate output:**

**File:** `crates/drift/drift-analysis/src/enforcement/gates/orchestrator.rs`

When a gate has no data, include guidance in the `summary` field:

| Gate | Current Summary | Proposed Summary |
|------|----------------|------------------|
| `security-boundaries` | "No data available" | "No security data. Run `drift security` to enable this gate." |
| `constraint-verification` | "No architectural constraints defined" | "No constraints defined. Add `[constraints]` to drift.toml to enable this gate." |
| `test-coverage` | "No data available" | "No test data. Run `drift test-quality` to enable this gate." |
| `error-handling` | "No data available" | "No error analysis data. Run `drift errors` to enable this gate." |
| `regression` | "No data available" | "No historical baseline. Run `drift scan` again to enable regression detection." |

**Part B — Exclude empty gates from pass/fail and cross-validation:**

**File:** `crates/drift/drift-napi/src/bindings/enforcement.rs`

In `drift_check()` (line 113), exclude gates with no data from `overall_passed`:

```rust
// Current (line 113):
let overall_passed = js_gates.iter().all(|g| g.passed);

// Proposed:
let active_gates: Vec<&JsGateResult> = js_gates.iter()
    .filter(|g| g.status != "skipped" && g.status != "no_data")
    .collect();
let overall_passed = active_gates.is_empty() || active_gates.iter().all(|g| g.passed);
```

In `drift_audit()` (lines 168–172), exclude empty gates from `cross_validation_rate`:

```rust
// Current (lines 168–172):
let cross_validation_rate = if gates.is_empty() {
    0.0
} else {
    gates.iter().filter(|g| g.passed).count() as f64 / gates.len() as f64
};

// Proposed:
let active_gates: Vec<&GateResultRow> = gates.iter()
    .filter(|g| g.status != "skipped" && g.status != "no_data")
    .collect();
let cross_validation_rate = if active_gates.is_empty() {
    1.0 // No gates evaluated → no violations → compliant
} else {
    active_gates.iter().filter(|g| g.passed).count() as f64 / active_gates.len() as f64
};
```

**Why this approach:**
- Part A: Users learn how to fix skipped gates without reading docs.
- Part B: Empty gates don't artificially drag down health score or pass/fail. A project with only `pattern-compliance` active gets evaluated on that alone.
- The `1.0` default for no active gates is intentional: if no gates can run, there are no failures.

### Verification Gate

```
1. `drift scan && drift analyze && drift check` — only pattern-compliance evaluates; others show guidance messages
2. `drift check --format json` — overall_passed reflects only active gates
3. `drift security && drift check` — security-boundaries now evaluates alongside pattern-compliance
4. Health score accounts for only active gates
```

---

## Fix 06: Status: False Degradation Alerts

**Severity:** MEDIUM — Misleading alerts inflate degradation count and suppress health score.

**Symptom:** Many `"Framework pack X detection count dropped from A to B (67% decrease)"` alerts.

### Upstream Connections

| Source | Location | Role |
|--------|----------|------|
| Degradation detector | `crates/drift/drift-analysis/src/enforcement/audit/degradation.rs` | Compares current vs previous audit snapshots |
| `audit_snapshots` table | `crates/drift/drift-storage/src/migrations/v006_enforcement.rs:53–66` | Stores snapshots with `created_at` timestamp |
| `degradation_alerts` table | `crates/drift/drift-storage/src/migrations/v006_enforcement.rs:114–123` | Accumulates alerts with **no expiry** |
| `drift scan` | `crates/drift/drift-napi/src/bindings/analysis.rs:1504–1607` | Triggers degradation comparison during pipeline |
| `query_recent_degradation_alerts()` | `crates/drift/drift-storage/src/queries/enforcement.rs:543–635` | Returns recent alerts (last N rows) |

### Downstream Connections

| Consumer | Location | Impact |
|----------|----------|--------|
| `drift_audit()` | `enforcement.rs:135–139` | Loads alerts → passes to `alert_messages` |
| Health score penalty | `enforcement.rs:200–204` | Each alert deducts 2 points: `health_score -= alerts.len() * 2.0` |
| Trend calculation | `enforcement.rs:151` | Any alerts → `trend = "degrading"` |
| `drift status` output | `packages/drift-cli/src/commands/status.ts` | Displays alerts and degrading trend |

### Root Cause

Three contributing factors:

1. **Scope mismatch**: Scanning a subdirectory produces fewer detections than a full-project scan. The degradation comparator sees the count drop and raises an alert. There is no `scan_scope` qualifier to distinguish partial from full scans.

2. **Alert accumulation**: `degradation_alerts` is append-only. Old alerts persist indefinitely, even after the situation resolves on a subsequent full scan.

3. **Unbounded penalty**: Each alert deducts 2 points with no cap. 20 stale alerts = -40 points, enough to zero out an otherwise healthy score.

### Proposed Fix

**Three-part fix:**

**Part A — Clear stale alerts on successful scan:**

**File:** `crates/drift/drift-napi/src/bindings/analysis.rs` (in the scan/analyze pipeline)

After a successful full scan completes, clear alerts whose metric has recovered:

```rust
// After successful analyze with no new degradation detected:
rt.storage.with_writer(|conn| {
    drift_storage::queries::enforcement::clear_recovered_alerts(conn)
})?;
```

**File:** `crates/drift/drift-storage/src/queries/enforcement.rs`

Add cleanup function:

```rust
pub fn clear_recovered_alerts(conn: &Connection) -> Result<u64, StorageError> {
    let deleted = conn.execute(
        "DELETE FROM degradation_alerts WHERE created_at < unixepoch() - 86400",
        [],
    ).map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    Ok(deleted as u64)
}
```

**Part B — Cap degradation penalty on health score:**

**File:** `crates/drift/drift-napi/src/bindings/enforcement.rs` (lines 200–204)

```rust
// Current:
let health_score = if !alerts.is_empty() {
    (health_score - alerts.len() as f64 * 2.0).max(0.0)
} else {
    health_score
};

// Proposed — cap at 20 points max deduction:
let alert_penalty = (alerts.len() as f64 * 2.0).min(20.0);
let health_score = if !alerts.is_empty() {
    (health_score - alert_penalty).max(0.0)
} else {
    health_score
};
```

**Part C — Add scope-awareness to degradation comparison:**

**File:** `crates/drift/drift-analysis/src/enforcement/audit/degradation.rs`

When comparing snapshots, skip the framework detection count comparison if the current scan path differs from the previous scan path. This requires storing `scan_root` in `audit_snapshots`:

**File:** `crates/drift/drift-storage/src/migrations/` — new migration

```sql
ALTER TABLE audit_snapshots ADD COLUMN scan_root TEXT DEFAULT '';
```

Then in the degradation comparator, only compare snapshots with matching `scan_root`.

**Why this approach:**
- Part A: TTL-based cleanup prevents infinite alert accumulation. 24h is conservative.
- Part B: Immediate relief — even with stale alerts, health can't drop more than 20 points.
- Part C: Root cause fix — prevents false alerts from scope mismatch. Requires migration but is backward compatible (defaults to empty string, matching old rows against each other).

### Verification Gate

```
1. Run `drift scan && drift analyze` — note alert count
2. Run again immediately — alert count should not increase (no actual degradation)
3. After 24h (or manual time adjustment), stale alerts should be cleared
4. Health score penalty capped at 20 even with many alerts
```

---

## Fix 07: Status: `healthScore` Always 0

**Severity:** HIGH — Primary health metric is unusable.

**Symptom:** `healthScore: 0` despite `complianceRate: 1`.

### Upstream Connections

The health score formula in `crates/drift/drift-napi/src/bindings/enforcement.rs:191–204`:

```
health_score = (avg_confidence × 20) + (approval_ratio × 20) + (compliance_rate × 20)
             + (cross_validation_rate × 20) + (duplicate_free_rate × 20)
```

| Factor | Source | Fresh Project Value | Why |
|--------|--------|-------------------|-----|
| `avg_confidence` | `patterns.query_all_confidence()` | **0.0** | Patterns exist but no Bayesian confidence computed yet |
| `approval_ratio` | `feedback_stats` (fix/escalate count) | **0.0** | No user feedback given |
| `compliance_rate` | `suppressed / total violations` | **1.0** if no violations, **0.0** if violations exist but none suppressed | Only factor with data |
| `cross_validation_rate` | Gate results `passed / total` | **0.0** or diluted by duplicates (Fix 04) | Gates skipped (Fix 05) or duplicated |
| `duplicate_free_rate` | Hardcoded placeholder | **1.0** | Always contributes 20 points |
| Degradation penalty | `alerts.len() × 2.0` | **−N×2** (unbounded) | False alerts (Fix 06) |

**Typical fresh-project calculation:**

```
health = (0.0 × 20) + (0.0 × 20) + (1.0 × 20) + (0.0 × 20) + (1.0 × 20) = 40
minus degradation penalty: 40 - (20 alerts × 2.0) = 0
```

### Downstream Connections

| Consumer | Impact |
|----------|--------|
| `drift status` output | Shows `healthScore: 0` — suggests project is broken |
| CI integration | Health-based gates would always fail |
| `trend` field | Always "degrading" due to alerts |
| User trust | Undermines confidence in the tool |

### Root Cause

The formula weights all 5 factors equally (20 points each), but 3 factors (`avg_confidence`, `approval_ratio`, `cross_validation_rate`) require significant user interaction or specialized commands to populate. On a fresh project, only `compliance_rate` (20 pts) and `duplicate_free_rate` (20 pts) contribute, giving a base of 40 — which is then wiped out by false degradation alerts.

### Proposed Fix

**File:** `crates/drift/drift-napi/src/bindings/enforcement.rs` (lines 145–204)

Replace fixed-weight formula with adaptive weighted average that excludes uncomputed factors:

```rust
// Build factor list — only include factors that have data
let mut factors: Vec<(f64, &str)> = Vec::new();

if !confidence_scores.is_empty() {
    factors.push((avg_confidence, "avg_confidence"));
}
if feedback_stats.total_count > 0 {
    factors.push((approval_ratio, "approval_ratio"));
}
// compliance_rate always has data (violations table always exists)
factors.push((compliance_rate, "compliance_rate"));

let active_gates: Vec<&GateResultRow> = gates.iter()
    .filter(|g| g.status != "skipped" && g.status != "no_data")
    .collect();
if !active_gates.is_empty() {
    let cvr = active_gates.iter().filter(|g| g.passed).count() as f64
            / active_gates.len() as f64;
    factors.push((cvr, "cross_validation_rate"));
}

// duplicate_free_rate always included (placeholder = 1.0)
factors.push((1.0, "duplicate_free_rate"));

// Weighted average of available factors
let health_score = if factors.is_empty() {
    50.0 // Neutral score when no data at all
} else {
    let sum: f64 = factors.iter().map(|(v, _)| v).sum();
    (sum / factors.len() as f64 * 100.0).clamp(0.0, 100.0)
};

// Cap degradation penalty at 20 points (see Fix 06)
let alert_penalty = (alerts.len() as f64 * 2.0).min(20.0);
let health_score = if !alerts.is_empty() {
    (health_score - alert_penalty).max(0.0)
} else {
    health_score
};
```

Also add a `data_completeness` field to `JsAuditResult`:

```rust
#[napi(object)]
pub struct JsAuditResult {
    pub health_score: f64,
    pub breakdown: JsHealthBreakdown,
    pub trend: String,
    pub degradation_alerts: Vec<String>,
    pub auto_approved_count: u32,
    pub needs_review_count: u32,
    pub data_completeness: f64, // 0.0–1.0: fraction of health factors with data
}
```

Compute it as:

```rust
let max_factors = 5;
let data_completeness = factors.len() as f64 / max_factors as f64;
```

**Fresh-project calculation with this fix:**

```
Factors with data: compliance_rate (1.0), duplicate_free_rate (1.0)
health = (1.0 + 1.0) / 2 × 100 = 100
with capped penalty: 100 - min(alert_count × 2, 20) = 80 (worst case)
data_completeness = 2/5 = 0.40
```

**Why this approach:**
- Uncomputed factors don't drag the score down — the score reflects reality.
- `data_completeness` tells users how much of the health picture is filled in, without penalizing them.
- As users run more commands (security, test-quality, provide feedback), factors activate and the score becomes more nuanced.
- The `50.0` neutral fallback is conservative — never seen in practice (compliance_rate always exists).

### Verification Gate

```
1. Fresh project: `drift scan && drift analyze && drift status --format json`
   - healthScore >= 80 (compliance 1.0 + dup-free 1.0)
   - data_completeness = 0.40
2. After `drift security`: data_completeness increases
3. After user feedback: approval_ratio activates, score adjusts
4. Score never exceeds 100 or drops below 0
```

---

## Fix 08: Violations: Empty Array

**Severity:** LOW — May be expected behavior; needs better messaging.

**Symptom:** `drift violations` returns `[]`.

### Upstream Connections

| Source | Location | Role |
|--------|----------|------|
| Violation generation | `crates/drift/drift-napi/src/bindings/analysis.rs:1478–1481` | Creates violations during `drift analyze` when patterns match rules |
| Rule engine | `crates/drift/drift-analysis/src/enforcement/rules/` | Defines rules that patterns must match to generate violations |
| `ViolationInsertRow` | `crates/drift/drift-storage/src/batch/commands.rs:304–323` | Batch insert structure |
| `insert_violations()` | `crates/drift/drift-storage/src/batch/writer.rs:834–859` | Writes to `violations` table |
| `drift violations` CLI | `packages/drift-cli/src/commands/violations.ts` | Calls `napi.driftViolations()` |

### Downstream Connections

| Consumer | Impact |
|----------|--------|
| `drift check` | All gates pass trivially |
| `drift report` | Empty report |
| `compliance_rate` | Becomes 1.0 (no violations = fully compliant) |
| CI pipelines | No violations detected → always green |

### Root Cause

Violations require three conditions to be met:
1. Rules must be defined (in framework packs or `drift.toml`)
2. Patterns must be detected by `drift scan`
3. `drift analyze` must run the rule engine to match patterns against rules

If no rules are configured (the default), no violations are generated regardless of scan findings. This may be expected for new projects but is confusing without guidance.

### Proposed Fix

**File:** `packages/drift-cli/src/commands/violations.ts`

Add diagnostic messaging when violations array is empty:

```typescript
.action(async (path: string | undefined, opts: { format: OutputFormat; quiet?: boolean }) => {
  const napi = loadNapi();
  const violationsPath = path ?? process.cwd();

  try {
    const result = napi.driftViolations(violationsPath);

    if (result.length === 0 && !opts.quiet) {
      process.stderr.write(
        'No violations found. This may mean:\n' +
        '  (a) Your code is fully compliant\n' +
        '  (b) No rules are configured — check drift.toml [rules] section\n' +
        '  (c) Analysis has not been run — try `drift scan && drift analyze`\n\n',
      );
    }

    if (!opts.quiet) {
      process.stdout.write(formatOutput(result, opts.format));
    }
  } catch (err) {
    process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
    process.exitCode = 2;
  }
});
```

**Why this approach:**
- Matches the existing hint pattern in `check.ts:26–30`.
- Guides users without assuming the result is wrong.
- Uses `stderr` for diagnostic so piped output stays clean.
- No Rust changes needed.

### Verification Gate

```
1. `drift violations` on project with no analyze → shows diagnostic hint
2. `drift violations` on project with analyze but no rules → shows diagnostic hint
3. `drift violations` on project with violations → shows violations, no hint
4. `drift violations --quiet` → no diagnostic, just output
```

---

## Fix 09: Context: Intent Must Be Exact Enum

**Severity:** LOW — Friction for new users but clear error message.

**Symptom:** `Invalid intent 'add new api endpoint'. Valid: fix_bug, add_feature, understand_code, security_audit, generate_spec`

### Upstream Connections

| Source | Location | Role |
|--------|----------|------|
| `VALID_INTENTS` | `packages/drift-cli/src/commands/context.ts:11–13` | Defines enum: `fix_bug, add_feature, understand_code, security_audit, generate_spec` |
| Intent validation | `context.ts:29–32` | Strict exact-match check |
| `napi.driftContext()` | `crates/drift/drift-napi/src/bindings/` | Rust side expects exact enum string |

### Downstream Connections

| Consumer | Impact |
|----------|--------|
| Users typing natural language | Get rejected with error |
| MCP/AI integration | AI always sends exact enum (not affected) |
| Scripts/CI | Would use exact enum (not affected) |

### Root Cause

The intent system maps to different context generation strategies with different weights. The 5 intents are not arbitrary labels — each triggers a specific weighting in the Rust context engine. Free-form text cannot be directly mapped without ambiguity.

### Proposed Fix

**File:** `packages/drift-cli/src/commands/context.ts`

Add fuzzy intent matching with keyword-to-intent mapping:

```typescript
const VALID_INTENTS = [
  'fix_bug', 'add_feature', 'understand_code', 'security_audit', 'generate_spec',
] as const;

const INTENT_KEYWORDS: Record<string, typeof VALID_INTENTS[number]> = {
  'fix': 'fix_bug',
  'bug': 'fix_bug',
  'debug': 'fix_bug',
  'repair': 'fix_bug',
  'patch': 'fix_bug',
  'add': 'add_feature',
  'feature': 'add_feature',
  'new': 'add_feature',
  'create': 'add_feature',
  'implement': 'add_feature',
  'build': 'add_feature',
  'understand': 'understand_code',
  'read': 'understand_code',
  'explore': 'understand_code',
  'learn': 'understand_code',
  'how': 'understand_code',
  'what': 'understand_code',
  'security': 'security_audit',
  'audit': 'security_audit',
  'vulnerability': 'security_audit',
  'vuln': 'security_audit',
  'spec': 'generate_spec',
  'specification': 'generate_spec',
  'document': 'generate_spec',
  'docs': 'generate_spec',
};

function resolveIntent(raw: string): typeof VALID_INTENTS[number] | null {
  // Exact match first
  if (VALID_INTENTS.includes(raw as typeof VALID_INTENTS[number])) {
    return raw as typeof VALID_INTENTS[number];
  }

  // Keyword matching — find best match from input words
  const words = raw.toLowerCase().replace(/[^a-z0-9_\s]/g, '').split(/\s+/);
  const matches = new Map<typeof VALID_INTENTS[number], number>();

  for (const word of words) {
    const mapped = INTENT_KEYWORDS[word];
    if (mapped) {
      matches.set(mapped, (matches.get(mapped) ?? 0) + 1);
    }
  }

  if (matches.size === 0) return null;

  // Return intent with most keyword hits
  return [...matches.entries()].sort((a, b) => b[1] - a[1])[0][0];
}
```

Then in the action handler:

```typescript
.action(async (intent: string, opts: { depth: string; data: string; format: OutputFormat; quiet?: boolean }) => {
  const napi = loadNapi();
  try {
    const resolved = resolveIntent(intent);
    if (!resolved) {
      process.stderr.write(
        `Could not resolve intent '${intent}'.\n` +
        `Valid intents: ${VALID_INTENTS.join(', ')}\n` +
        `Tip: Use keywords like "fix", "add", "understand", "security", or "spec".\n`,
      );
      process.exitCode = 2;
      return;
    }

    if (resolved !== intent) {
      process.stderr.write(`Resolved intent: '${intent}' → '${resolved}'\n`);
    }

    if (!VALID_DEPTHS.includes(opts.depth as typeof VALID_DEPTHS[number])) {
      process.stderr.write(`Invalid depth '${opts.depth}'. Valid: ${VALID_DEPTHS.join(', ')}\n`);
      process.exitCode = 2;
      return;
    }

    const result = await napi.driftContext(resolved, opts.depth, opts.data);
    if (!opts.quiet) {
      process.stdout.write(formatOutput(result, opts.format));
    }
  } catch (err) {
    process.stderr.write(`Error: ${err instanceof Error ? err.message : err}\n`);
    process.exitCode = 2;
  }
});
```

**Why this approach:**
- Exact match still works — no breaking change.
- Keyword matching handles common natural language ("add new api endpoint" → `add_feature` via "add" + "new" keywords).
- Tells the user what it resolved to — transparent, no magic.
- Falls back to a clear error with guidance if nothing matches.
- Stateless — no AI/ML needed, just a lookup table.

### Verification Gate

```
1. `drift context fix_bug` — works unchanged (exact match)
2. `drift context "add new api endpoint"` — resolves to add_feature, shows resolution message
3. `drift context "fix the login bug"` — resolves to fix_bug
4. `drift context "xyzzy"` — shows error with guidance
```

---

## Fix 10: Cortex Add: Content Format Error

**Severity:** MEDIUM — Blocks memory creation with cryptic error.

**Symptom:** `Error: Failed to deserialize BaseMemory: missing field 'type'`

### Upstream Connections

| Source | Location | Role |
|--------|----------|------|
| CLI `cortex add` | `packages/drift-cli/src/commands/cortex.ts:126–149` | Parses `--content <json>`, passes to `callTool()` |
| `drift_memory_add` tool | `packages/cortex/src/tools/drift_memory_add.ts:65–91` | Constructs `BaseMemory` object, passes `content` field directly |
| `client.memoryCreate()` | `packages/cortex/src/bridge/client.ts:123–125` | Calls NAPI `cortexMemoryCreate()` |
| `cortex_memory_create()` | `crates/cortex/cortex-napi/src/bindings/memory.rs:12–18` | Deserializes full `BaseMemory` from JSON |
| `memory_from_json()` | `crates/cortex/cortex-napi/src/conversions/memory_types.rs:15–18` | `serde_json::from_value::<BaseMemory>()` — error originates here |
| `TypedContent` enum | `crates/cortex/cortex-core/src/memory/base.rs:12–44` | `#[serde(tag = "type", content = "data")]` — requires `type` discriminator |

### Downstream Connections

| Consumer | Impact |
|----------|--------|
| Users trying to add memories | Blocked by cryptic serde error |
| MCP tools creating memories | Same path, same error if format wrong |
| Documentation | Expected format not documented in CLI help |

### Root Cause

The `TypedContent` Rust enum uses serde's `tag = "type"` attribute, requiring the JSON to include:

```json
{ "type": "episodic", "data": { ... } }
```

But users naturally provide:

```json
{ "interaction": "...", "context": "...", "outcome": "..." }
```

The CLI has the `<type>` argument (e.g., `cortex add episodic --summary "..." --content '{...}'`) which contains the same value needed for the `type` field inside `content`, but the tool handler doesn't bridge this gap.

### Proposed Fix

**Two-part fix: auto-wrap + validation.**

**Part A — Auto-wrap content:**

**File:** `packages/drift-cli/src/commands/cortex.ts` (in the `add` action, around line 138)

```typescript
.action(async (type: string, opts) => {
  const client = await getCortex(opts.db);
  const { registerTools, callTool } = await import('@drift/cortex');
  const registry = registerTools(client);

  let content = JSON.parse(opts.content);

  // Auto-wrap: if content lacks 'type' field, wrap with the memory type argument
  if (!content.type) {
    content = { type, data: content };
  }

  const result = await callTool(registry, 'drift_memory_add', {
    memory_type: type,
    summary: opts.summary,
    content,
    tags: opts.tags?.split(',') ?? [],
  });
  // ...
```

**Part B — Better error message in Rust:**

**File:** `crates/cortex/cortex-napi/src/conversions/memory_types.rs` (lines 15–18)

```rust
pub fn memory_from_json(value: serde_json::Value) -> napi::Result<BaseMemory> {
    serde_json::from_value(value.clone()).map_err(|e| {
        let hint = if e.to_string().contains("missing field") {
            format!(
                "\nHint: The 'content' field must be {{\"type\":\"<memory_type>\",\"data\":{{...}}}}. \
                 Example: {{\"type\":\"episodic\",\"data\":{{\"interaction\":\"...\"}}}}"
            )
        } else {
            String::new()
        };
        napi::Error::from_reason(format!("Failed to deserialize BaseMemory: {e}{hint}"))
    })
}
```

**Part C — Update CLI help text:**

**File:** `packages/drift-cli/src/commands/cortex.ts` (add command definition)

```typescript
cortex
  .command('add <type>')
  .description('Add a memory to Cortex. Content auto-wrapped with type if needed.')
  .requiredOption('--summary <text>', 'Memory summary')
  .requiredOption(
    '--content <json>',
    'Memory content as JSON. Can be {"type":"episodic","data":{...}} or just the data object.',
  )
```

**Why this approach:**
- Auto-wrap eliminates the common failure case — the `type` argument already provides the discriminator value.
- If the user provides `{"type":"episodic","data":{...}}` explicitly, the auto-wrap is skipped (it sees `content.type` exists).
- Better Rust error message catches any edge cases the TypeScript validation misses.
- Updated help text documents both accepted formats.

### Verification Gate

```
1. `drift cortex add episodic --summary "test" --content '{"interaction":"test"}'`
   - Auto-wraps to {"type":"episodic","data":{"interaction":"test"}} — succeeds
2. `drift cortex add episodic --summary "test" --content '{"type":"episodic","data":{"interaction":"test"}}'`
   - Already wrapped — passes through unchanged — succeeds
3. `drift cortex add episodic --summary "test" --content 'invalid'`
   - JSON parse error — clear error message
```

---

## Fix 11: Bridge Health: `ready: false`

**Severity:** MEDIUM — Bridge reports non-functional despite healthy subsystems.

**Symptom:** `ready: false` despite `bridge_store`, `drift_db`, `causal_engine` all healthy.

### Upstream Connections

| Source | Location | Role |
|--------|----------|------|
| `is_ready()` | `crates/cortex-drift-bridge/src/health/readiness.rs:30–34` | Returns `true` only if `cortex_db` subsystem is healthy |
| `check_cortex_db()` | `crates/cortex-drift-bridge/src/health/checks.rs:35–48` | Returns unhealthy if cortex DB connection is `None` |
| Bridge init | `crates/cortex-drift-bridge/src/lib.rs:98–103` | Skips cortex DB if `.cortex/cortex.db` doesn't exist on disk |
| Stub fallback | `packages/drift-napi-contracts/src/stub.ts:602` | Returns `ready: false` unconditionally |

### Downstream Connections

| Consumer | Impact |
|----------|--------|
| `drift bridge health` CLI | Shows `ready: false` |
| MCP server startup | May skip bridge tools if not ready |
| CI integration | Bridge-dependent features marked unavailable |

### Root Cause

`is_ready()` is gated solely on `cortex_db` being healthy:

```rust
pub fn is_ready(checks: &[SubsystemCheck]) -> bool {
    checks.iter().any(|c| c.name == "cortex_db" && c.healthy)
}
```

But `cortex_db` is only initialized when `.cortex/cortex.db` exists on disk. This is a direct consequence of Fix 01 — without `.cortex/`, the bridge is never ready.

### Proposed Fix

**Two-part fix: tiered readiness + auto-creation coupling.**

**Part A — Tiered readiness model:**

**File:** `crates/cortex-drift-bridge/src/health/readiness.rs`

Replace binary `is_ready()` with tiered readiness:

```rust
#[derive(Debug, Clone, Serialize)]
pub struct ReadinessState {
    pub ready: bool,           // Core bridge functional
    pub cortex_ready: bool,    // Cortex memory system available
    pub degraded: bool,        // Some subsystems unhealthy
    pub message: String,
}

pub fn evaluate_readiness(checks: &[SubsystemCheck]) -> ReadinessState {
    let core_healthy = checks.iter()
        .filter(|c| c.name == "bridge_store" || c.name == "drift_db")
        .all(|c| c.healthy);

    let cortex_healthy = checks.iter()
        .any(|c| c.name == "cortex_db" && c.healthy);

    let all_healthy = checks.iter().all(|c| c.healthy);

    ReadinessState {
        ready: core_healthy,                    // Bridge works without cortex
        cortex_ready: cortex_healthy,           // Cortex integration available
        degraded: core_healthy && !all_healthy, // Some non-critical subsystem down
        message: if !core_healthy {
            "Core bridge subsystems unhealthy".to_string()
        } else if !cortex_healthy {
            "Bridge ready. Cortex not initialized — run `drift setup` or any `drift cortex` command.".to_string()
        } else {
            "All subsystems healthy".to_string()
        },
    }
}
```

**Part B — Wire auto-creation from Fix 01:**

With Fix 01 in place, running any `drift cortex` command will auto-create `.cortex/`. The bridge can then detect this on the next health check. No additional wiring needed — Fix 01 is the root fix, this Fix makes the bridge resilient to the transition period.

**Part C — Update bridge health NAPI binding:**

Expose the tiered readiness through the existing health endpoint so the CLI and MCP can display it:

```rust
// In the health response struct, add:
pub cortex_ready: bool,
pub message: String,
```

**Why this approach:**
- The bridge is genuinely functional without cortex — it can still do bridge_store and drift_db operations.
- Tiered readiness communicates exactly what's available vs. what's missing.
- `cortex_ready: false` with `ready: true` is informational, not an error.
- Pairs naturally with Fix 01 — once a user runs any cortex command, `cortex_ready` flips to `true`.

### Verification Gate

```
1. Without .cortex/: `drift bridge health` → ready: true, cortex_ready: false, message explains
2. After `drift cortex status`: `drift bridge health` → ready: true, cortex_ready: true
3. With drift.db missing: `drift bridge health` → ready: false (actual error)
```

---

## Fix 12: Cloud: Not Configured

**Severity:** LOW — Expected state, but confusing messaging.

**Symptom:** `authenticated: false, configured: false, supabaseUrl: —`

### Upstream Connections

| Source | Location | Role |
|--------|----------|------|
| Cloud config loading | `packages/drift-cli/src/commands/cloud.ts:112–122` | Reads `~/.drift/cloud-config.json` |
| Config constants | `packages/drift/src/cloud/config.ts` | Defines `CLOUD_CONFIG_PATH`, `CLOUD_CREDENTIALS_PATH` |
| Credentials loading | `packages/drift/src/cloud/auth.ts` | `loadCredentials()` reads `~/.drift/cloud-credentials.json` |
| Config structure | `packages/drift/src/cloud/config.ts` | `supabaseUrl`, `supabaseAnonKey`, `projectId`, `tenantId` |

### Downstream Connections

| Consumer | Impact |
|----------|--------|
| `drift cloud status` | Shows unconfigured state |
| `drift cloud sync` | Fails with "not configured" |
| All cloud features | Disabled until login/configure |

### Root Cause

This is **expected behavior** — cloud features are opt-in and require explicit setup. The issue is that:

1. The error message ("Not configured. Run `drift cloud login` first.") doesn't explain the full setup flow.
2. Users might look for `.env` or `.env.cloud` files (common patterns) but the config is at `~/.drift/cloud-config.json`.
3. No `--help` text explains the cloud setup workflow.

### Proposed Fix

**File:** `packages/drift-cli/src/commands/cloud.ts`

Improve the status command output when not configured:

```typescript
// In the cloud status action, when not configured:
if (!config) {
  process.stderr.write(
    'Cloud sync is not configured.\n\n' +
    'To set up cloud sync:\n' +
    '  1. drift cloud login          — authenticate with your account\n' +
    '  2. drift cloud configure      — set up project sync\n' +
    '  3. drift cloud status         — verify configuration\n\n' +
    'Configuration is stored in:\n' +
    `  Config:      ~/.drift/cloud-config.json\n` +
    `  Credentials: ~/.drift/cloud-credentials.json\n\n` +
    'Note: Cloud features are optional. Drift works fully offline.\n',
  );
  process.exitCode = 1;
  return;
}
```

Also update the cloud command description:

```typescript
program
  .command('cloud')
  .description('Cloud sync operations. Run `drift cloud login` to get started.')
```

**Why this approach:**
- No functional change — cloud still requires explicit setup.
- Clear 3-step guidance replaces terse "not configured" message.
- Tells users where config files live (prevents looking for `.env`).
- Reassures that cloud is optional.

### Verification Gate

```
1. `drift cloud status` without config → shows setup guide
2. `drift cloud login` → authenticates (if Supabase credentials available)
3. `drift cloud status` after login → shows actual status
```

---

## Priority Matrix & Implementation Order

| Fix | Severity | Effort | Est. Time | Dependencies | Order |
|-----|----------|--------|-----------|-------------|-------|
| **01** — `.cortex/` auto-create | HIGH | Small (5 lines TS) | 15 min | None | **1st** |
| **04** — Duplicate gate entries | HIGH | Small (SQL change) | 30 min | None | **2nd** |
| **06** — False degradation alerts | MEDIUM | Medium (Rust + migration) | 2–3 hr | None | **3rd** |
| **07** — healthScore always 0 | HIGH | Medium (Rust formula) | 1–2 hr | Depends on 04, 05, 06 | **4th** |
| **05** — Gates skipped messaging | MEDIUM | Medium (Rust + TS) | 1–2 hr | Depends on 04 | **5th** |
| **11** — Bridge ready: false | MEDIUM | Medium (Rust struct change) | 1–2 hr | Depends on 01 | **6th** |
| **10** — Cortex add content | MEDIUM | Small (TS + Rust hint) | 30 min | Depends on 01 | **7th** |
| **03** — Cortex `--format` | LOW | Small (TS only) | 30 min | None | **8th** |
| **02** — Report `--format` | LOW | Small (TS only) | 15 min | None | **9th** |
| **09** — Context intent matching | LOW | Small (TS only) | 30 min | None | **10th** |
| **08** — Violations empty hint | LOW | Small (TS only) | 15 min | None | **11th** |
| **12** — Cloud messaging | LOW | Small (TS only) | 15 min | None | **12th** |

**Total estimated effort: 8–12 hours** (includes testing per fix; excludes code review).

### Rationale

1. **Fix 01 first**: Unblocks all cortex commands and is a prerequisite for fixes 10 and 11.
2. **Fix 04 second**: Single SQL change fixes duplicate gates everywhere — prerequisite for accurate health scoring (07) and gate messaging (05).
3. **Fix 06 third**: Clears stale alerts that suppress health score — must land before 07 to avoid masking the formula fix.
4. **Fix 07 fourth**: With duplicates fixed (04), alerts capped (06), and gates filtered (05), the new formula produces meaningful scores.
5. **Fixes 05, 11, 10**: Medium-priority items that depend on earlier fixes.
6. **Fixes 03, 02, 09, 08, 12**: Low-priority UX improvements, all independent, all TypeScript-only.

---

## Dependency Graph

```
Fix 01 (.cortex/ auto-create)
├──→ Fix 11 (bridge readiness)
└──→ Fix 10 (cortex add format)

Fix 04 (duplicate gates) ──→ Fix 05 (gates skipped) ──┐
                                                        ├──→ Fix 07 (healthScore)
Fix 06 (degradation alerts) ───────────────────────────┘

Fix 02 (report --format)     — independent
Fix 03 (cortex --format)     — independent
Fix 08 (violations hint)     — independent
Fix 09 (context intent)      — independent
Fix 12 (cloud messaging)     — independent
```

---

## Verification Protocol

After all 12 fixes are implemented, run the following end-to-end sequence:

### Phase 1: Clean Slate

```bash
rm -rf .drift/ .cortex/
```

### Phase 2: Core Pipeline

```bash
drift cortex status              # Fix 01: should auto-create .cortex/, return health
drift scan                       # Populate file_metadata
drift analyze                    # Populate patterns, run gates
drift scan && drift analyze      # Second run — gates should NOT duplicate (Fix 04)
```

### Phase 3: Check & Status

```bash
drift check --format json        # Fix 04: 6 gates max, Fix 05: skipped gates show guidance
drift status --format json        # Fix 07: healthScore > 0, Fix 06: alerts capped
drift violations                  # Fix 08: empty hint with guidance
drift report --format json        # Fix 02: --format works
```

### Phase 4: Cortex

```bash
drift cortex add episodic \
  --summary "test memory" \
  --content '{"interaction":"test","outcome":"success"}'  # Fix 10: auto-wraps content
drift cortex list --format json   # Fix 03: --format works
drift cortex search "test" --format table  # Fix 03: table output
```

### Phase 5: Bridge & Context

```bash
drift bridge health               # Fix 11: ready: true, cortex_ready: true
drift context "add new api"       # Fix 09: resolves to add_feature
drift cloud status                # Fix 12: shows setup guide
```

### Expected Final State

| Metric | Before | After |
|--------|--------|-------|
| `cortex status` without setup | ERROR | Works (auto-creates .cortex/) |
| Gate count in `drift check` | 6×N (duplicated) | 6 (deduplicated) |
| `healthScore` on fresh project | 0 | 80–100 |
| `data_completeness` | N/A | 0.40 (2/5 factors active) |
| Bridge `ready` | false | true |
| Bridge `cortex_ready` | false | true (after any cortex command) |
| Degradation alert penalty | Unbounded | Capped at 20 |
| `cortex add` with bare content | ERROR | Auto-wrapped |
| `drift report --format json` | ERROR | Works |
| `drift context "fix bug"` | ERROR | Resolves to fix_bug |

---

## Risk Assessment

| Fix | Risk Level | Primary Risk | Mitigation |
|-----|-----------|-------------|------------|
| **01** | LOW | `mkdirSync` could fail if parent path is read-only | `recursive: true` handles nested creation; wraps in try/catch at caller |
| **02** | LOW | Backward-incompatible if scripts pass both `--format` and `--report-format` | `--report-format` takes precedence — existing scripts unaffected |
| **03** | LOW | Table output for deeply nested cortex data may render poorly | Default remains `json`; table is opt-in |
| **04** | LOW | Window function performance on large `gate_results` tables | `idx_gate_results_gate` index covers the `PARTITION BY`; sub-ms for realistic table sizes (<10K rows) |
| **05** | LOW | `1.0` default for `cross_validation_rate` when no gates are active could mask problems | Paired with `data_completeness` to communicate that no gates were evaluated |
| **06** | MEDIUM | 24h TTL for alert cleanup could discard alerts that should persist | TTL is conservative; real degradations will re-fire on the next scan cycle |
| **06** (migration) | MEDIUM | `ALTER TABLE ADD COLUMN` on `audit_snapshots` | SQLite supports this natively without table rebuild; default value ensures backward compat |
| **07** | LOW | Adaptive weighting may produce unexpectedly high scores when few factors are active | `data_completeness` field communicates this transparently; scores are clamped to 0–100 |
| **08** | LOW | Diagnostic hint may be shown when empty violations is correct behavior | Uses `stderr` and only shows when `--quiet` is not set; does not affect exit code |
| **09** | LOW | Ambiguous keyword input could resolve to wrong intent | Resolution is logged to `stderr` so users can verify; exact match still takes priority |
| **10** | LOW | Auto-wrap could mask incorrect `type` argument (e.g., `cortex add semantic` with `{"type":"episodic","data":{}}`) | If `content.type` exists, auto-wrap is skipped — explicit values always win |
| **11** | MEDIUM | Downstream consumers that check `ready` field may need updating for the new `cortex_ready` field | `ready` field semantics broaden (core health only), which is a net improvement; `cortex_ready` is additive |
| **12** | LOW | None — purely informational output change | No functional behavior changes |

### Risk Summary

- **No fix carries HIGH risk.** All changes are backward-compatible or additive.
- The highest-risk changes are in Fix 06 (Rust migration + TTL logic) and Fix 11 (readiness semantic change). Both are mitigated by incremental rollout and independent commits.
- All Rust changes are behind the existing NAPI boundary — TypeScript consumers see the same shapes with better values.

---

## Rollback Plan

Each fix is committed independently. Rollback is per-commit `git revert`.

| Fix | Rollback Complexity | Notes |
|-----|-------------------|-------|
| **01** | Trivial | Revert single TS file; behavior returns to error-on-missing-dir |
| **02** | Trivial | Revert single TS file; `--format` flag removed, `--report-format` restored as primary |
| **03** | Trivial | Revert single TS file; cortex subcommands return to raw JSON |
| **04** | Trivial | Revert SQL query; all historical rows returned again (duplicates resume) |
| **05** | Trivial | Revert Rust + TS; empty gates resume silent skip |
| **06** | **Requires care** | The `ALTER TABLE` migration is not reversible via revert. The added `scan_root` column persists but is harmless (defaults to empty string). TTL cleanup and penalty cap revert cleanly. |
| **07** | Trivial | Revert Rust formula; health returns to fixed 5-factor weighting |
| **08** | Trivial | Revert single TS file; empty violations return silently |
| **09** | Trivial | Revert single TS file; strict enum matching restored |
| **10** | Trivial | Revert TS auto-wrap + Rust hint; bare content returns to serde error |
| **11** | Moderate | Revert Rust struct change; bridge readiness returns to `cortex_db`-gated binary check. Downstream consumers referencing `cortex_ready` will need updating. |
| **12** | Trivial | Revert single TS file; terse "not configured" message restored |

### Migration Rollback Note (Fix 06)

The `scan_root TEXT DEFAULT ''` column added to `audit_snapshots` cannot be removed by SQLite `ALTER TABLE`. If Fix 06 is rolled back:
- The column remains but is unused — no functional impact.
- Future migrations should account for the column's existence.
- A full rollback would require `CREATE TABLE ... AS SELECT` to rebuild without the column, which is not recommended in production.

---

## Codebase Accuracy Notes

The following corrections were applied to this spec after verifying against the actual source code:

| Section | Original Claim | Corrected |
|---------|---------------|-----------|
| Fix 03, Upstream | "`cortex.ts` — no format option" | `cortex status` declares `-f, --format` but ignores it (always writes JSON). Other subcommands truly lack the option. |
| Fix 10, Upstream | `crates/cortex/cortex-napi/src/bindings/memory_types.rs` | Actual path: `crates/cortex/cortex-napi/src/conversions/memory_types.rs` |
| Fix 10, Upstream | Lines `16–19` | Actual lines: `15–18` |

---

## Files Modified Summary

| File | Fixes | Language |
|------|-------|----------|
| `packages/drift-cli/src/commands/cortex.ts` | 01, 03, 10 | TypeScript |
| `packages/drift-cli/src/commands/report.ts` | 02 | TypeScript |
| `packages/drift-cli/src/commands/context.ts` | 09 | TypeScript |
| `packages/drift-cli/src/commands/violations.ts` | 08 | TypeScript |
| `packages/drift-cli/src/commands/cloud.ts` | 12 | TypeScript |
| `crates/drift/drift-storage/src/queries/enforcement.rs` | 04, 06 | Rust |
| `crates/drift/drift-napi/src/bindings/enforcement.rs` | 05, 06, 07 | Rust |
| `crates/drift/drift-analysis/src/enforcement/gates/orchestrator.rs` | 05 | Rust |
| `crates/drift/drift-analysis/src/enforcement/audit/degradation.rs` | 06 | Rust |
| `crates/cortex-drift-bridge/src/health/readiness.rs` | 11 | Rust |
| `crates/cortex/cortex-napi/src/conversions/memory_types.rs` | 10 | Rust |

**Total: 11 files across 5 packages/crates. 7 TypeScript files, 4 Rust files.**

---

> **Next step:** Approve this spec, then implement in the order defined by the [Priority Matrix](#priority-matrix--implementation-order). Each fix should be committed independently to allow isolated verification and rollback. See [Rollback Plan](#rollback-plan) for per-fix revert guidance. Estimated total effort: **8–12 hours**.
