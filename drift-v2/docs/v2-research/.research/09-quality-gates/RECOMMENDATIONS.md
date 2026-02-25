# 09 Quality Gates — V2 Recommendations

> Enterprise-grade recommendations for the v2 rebuild of Drift's quality gates system, synthesized from the v1 recap and targeted research across 15+ authoritative sources. Each recommendation is backed by cited evidence and considers full-circle impact on the pipeline.

---

## Summary

The v2 quality gates system should evolve from a batch CI enforcement layer into a multi-stage, incremental, developer-friendly quality platform. The core architectural shifts are:

1. **New-code-first philosophy** — Focus enforcement on changed code, not the entire codebase (SonarQube's "Clean as You Code")
2. **Progressive enforcement** — Monitor → Comment → Block per pattern, not binary blocking per gate (Semgrep's three-mode model)
3. **Incremental execution** — Cache gate results, skip unchanged inputs, branch-based caching (SonarQube's incremental analysis)
4. **Rich output** — Full SARIF 2.1.0 with baselineState, codeFlows, fixes, and CWE taxonomies (OASIS standard)
5. **Policy-as-code** — Declarative, versioned, composable policies with inheritance (OPA principles)
6. **Developer feedback loop** — False-positive tracking, violation dismissal, automatic confidence adjustment (Google Tricorder)
7. **Multi-stage enforcement** — Pre-commit, PR, post-merge, scheduled — each with appropriate latency and scope (DevSecOps best practice)

---

## Recommendations

### R1: Adopt New-Code-First Enforcement Philosophy

**Priority**: P0 (Architectural — changes how all gates evaluate)
**Effort**: Medium
**Impact**: Developer experience, adoption, false-positive reduction

**Current State**:
Pattern compliance gate checks ALL patterns against ALL files. A codebase with 50 pre-existing violations will fail the gate even if the developer's change introduced zero new violations.

**Proposed Change**:
Default all gates to evaluate only changed files (the "new code period"). Provide an explicit `fullScan` mode for scheduled audits.

Gate behavior by mode:
- **PR mode** (default): Evaluate only files in the diff. Violations are "new" (introduced by this change) or "existing" (pre-existing). Only new violations can block.
- **Full scan mode**: Evaluate all files. Used for scheduled audits and baseline establishment.
- **Regression mode**: Compare current state against baseline. Used for post-merge checks.

**Rationale**:
SonarQube's "Clean as You Code" philosophy (QG-R1) is the industry standard. Developers should not be blocked by pre-existing issues they didn't introduce. This dramatically reduces false positives and improves adoption.

**Evidence**:
- SonarQube "Clean as You Code" (QG-R1): Focus on new code metrics
- Google Tricorder (QG-R5): <10% false-positive rate required for adoption
- Meta Fix Fast (QG-R4): Shift detection left, reduce noise

**Implementation Notes**:
- The orchestrator needs a `mode` parameter: `pr | full | regression | pre-commit`
- PR mode requires knowing which files changed (from git diff or CI environment)
- Each gate's `execute()` method receives `changedFiles` and `allFiles` separately
- Violations include a `isNew: boolean` field indicating whether the developer introduced them
- Violations include an `author?: string` field populated via git blame (when available) for accountability
- Policy can configure: `blockOnNewOnly: true` (default) or `blockOnAll: false`

**Risks**:
- Pre-existing violations may never get fixed if only new violations block
- Mitigation: Scheduled full-scan audits with degradation tracking catch long-term drift

**Dependencies**:
- 10-cli: `drift gate run` needs `--mode` flag
- 12-infrastructure: CI integration needs to pass changed file list
- 07-mcp: `drift_quality_gate` tool needs mode parameter


---

### R2: Implement Progressive Enforcement (Monitor → Comment → Block)

**Priority**: P0 (Architectural — changes how violations are surfaced)
**Effort**: Medium
**Impact**: Developer experience, gradual rollout, reduced noise

**Current State**:
Gates are binary: blocking or non-blocking. A newly discovered pattern immediately produces blocking violations if the gate is set to blocking. No way to gradually introduce enforcement.

**Proposed Change**:
Add a three-mode enforcement model at the per-pattern level:

| Mode | Behavior | Use Case |
|------|----------|----------|
| `monitor` | Tracked internally, not in gate results | Newly discovered patterns being validated |
| `comment` | Appears in PR comments, doesn't block | Patterns with medium confidence being socialized |
| `block` | Appears in PR comments AND blocks merge | High-confidence approved patterns |

**Automatic promotion rules** (configurable):
```yaml
promotion:
  monitor_to_comment:
    minConfidence: 0.70
    minLocations: 5
    minAge: 7d
  comment_to_block:
    minConfidence: 0.85
    minLocations: 10
    minAge: 30d
    maxFalsePositiveRate: 0.10
```

**Rationale**:
Semgrep's three-mode policy (QG-R3) is the industry standard for progressive enforcement. Google Tricorder (QG-R5) enforces a <10% false-positive rate. Combining these: patterns start in monitor mode, get promoted based on confidence and false-positive rate, and only block when they've proven reliable.

**Evidence**:
- Semgrep three-mode policies (QG-R3): Monitor, Comment, Block
- Google Tricorder (QG-R5): Automatic demotion of noisy checks
- SonarQube (QG-R1): Quality gate conditions focus on validated metrics

**Implementation Notes**:
- Pattern model gains an `enforcementMode: 'monitor' | 'comment' | 'block'` field
- Pattern compliance gate filters violations by enforcement mode
- Promotion engine runs during audit (scheduled), not during gate execution
- Demotion: if false-positive rate exceeds threshold, automatically demote from block → comment
- Policy can override per-pattern enforcement: `gates.pattern-compliance.minEnforcementMode: 'comment'`

**Risks**:
- Automatic promotion could promote a bad pattern to blocking
- Mitigation: Require manual approval for block promotion (configurable)

**Dependencies**:
- 03-detectors: Pattern model needs `enforcementMode` field
- 23-pattern-repository: Storage needs to persist enforcement mode
- 07-mcp: MCP tools should expose enforcement mode

---

### R3: Implement Incremental Gate Execution with Caching

**Priority**: P0 (Performance — critical for CI speed)
**Effort**: High
**Impact**: CI execution time reduction from seconds to milliseconds for small changes

**Current State**:
All enabled gates run every time. No caching of gate results. Same files re-analyzed on every run.

**Proposed Change**:
Three-tier caching strategy inspired by SonarQube's incremental analysis (QG-R2):

**Tier 1 — Gate-level input hashing**:
```
gateInputHash = hash(changedFiles + patternState + constraintState + callGraphState + policyConfig)
if gateInputHash === previousRunHash → skip gate, reuse previous result
```

**Tier 2 — Per-file result caching**:
For pattern compliance and custom rules, cache per-file evaluation results:
```
fileResultHash = hash(fileContent + applicablePatterns + gateConfig)
if fileResultHash === cachedHash → reuse cached violations for this file
```

**Tier 3 — Branch-based cache management**:
- Each branch maintains a gate result cache
- PR analysis downloads the target branch's cache as baseline
- Branch analysis uploads updated cache after completion
- Inactive branches (>7 days) have caches pruned

**Rationale**:
SonarQube's incremental analysis (QG-R2) demonstrates that caching can reduce analysis time by 80-95% for small changes. For Drift, where most PRs change <50 files out of thousands, this means gate execution drops from seconds to milliseconds.

**Evidence**:
- SonarQube incremental analysis (QG-R2): Two-tier caching with branch management
- CodeScene delta analysis (QG-R7): Delta-only analysis for fast CI feedback
- DevSecOps latency requirements (QG-R14): PR checks must complete in <2 minutes

**Implementation Notes**:
- Cache storage: SQLite table in drift.db (not JSON files — needs fast lookup)
- Cache key: composite hash of all gate inputs
- Cache invalidation: any input change invalidates the cache for that gate
- Parallel execution: cached gates return immediately, only uncached gates execute
- Cache warming: first run on a new branch populates the cache

**Risks**:
- Stale cache could produce incorrect results
- Mitigation: Conservative invalidation — any doubt → re-execute
- Cache corruption could block CI
- Mitigation: Fail-open — if cache is unreadable, run all gates normally

**Dependencies**:
- 08-storage: Cache tables in drift.db
- 04-call-graph: Call graph state hash for cache invalidation
- 03-detectors: Pattern state hash for cache invalidation

---

### R4: Produce Rich SARIF 2.1.0 Output

**Priority**: P0 (Enterprise integration — required for GitHub Code Scanning)
**Effort**: Medium
**Impact**: Enterprise CI integration, compliance reporting, IDE integration

**Current State**:
SARIF reporter maps violations to basic SARIF results with ruleId, level, locations, and message. No baselineState, no codeFlows, no fixes, no taxonomies.

**Proposed Change**:
Produce full SARIF 2.1.0 output leveraging all relevant properties:

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "drift",
        "version": "2.0.0",
        "rules": [/* per-gate rules with CWE/OWASP taxonomy refs */],
        "taxonomies": [
          { "name": "CWE", "guid": "..." },
          { "name": "OWASP", "guid": "..." }
        ]
      }
    },
    "results": [{
      "ruleId": "security-boundary/unauthorized-access",
      "level": "error",
      "message": { "text": "..." },
      "locations": [/* exact code locations */],
      "baselineState": "new",           // NEW: new/unchanged/updated/absent
      "codeFlows": [/* call chain */],  // NEW: for security boundary
      "fixes": [/* quick fix */],       // NEW: proposed code changes
      "suppressions": [/* dismissed */] // NEW: audit trail
    }]
  }]
}
```

**Key additions**:
1. `baselineState`: Mark each result as new/unchanged/updated/absent relative to previous scan
2. `codeFlows`: For security boundary violations, include the call chain from data access to entry point
3. `fixes`: Include quick fix suggestions as SARIF fix objects (maps to Drift's QuickFix system)
4. `taxonomies`: Map security violations to CWE IDs and OWASP Top 10 categories
5. `suppressions`: Track dismissed violations with reason and timestamp

**Rationale**:
SARIF 2.1.0 (QG-R8) is the OASIS standard consumed by GitHub Code Scanning, VS Code, and enterprise compliance tools. Rich SARIF output transforms Drift from a basic quality checker into an enterprise security intelligence platform.

**Evidence**:
- SARIF 2.1.0 specification (QG-R8): Full property support
- GitHub Code Scanning (QG-R11): SARIF upload with inline annotations
- OWASP SPVS (QG-R9): Compliance reporting requires standardized output

**Implementation Notes**:
- `baselineState` requires comparing current results against previous SARIF output or snapshot
- `codeFlows` requires call graph data from the security boundary gate
- `fixes` maps directly to Drift's existing QuickFix system
- CWE mapping: maintain a mapping table from Drift security patterns to CWE IDs
- OWASP mapping: maintain a mapping table from Drift security categories to OWASP Top 10

**Risks**:
- Rich SARIF output is larger — may hit GitHub's 10MB SARIF upload limit for large codebases
- Mitigation: Configurable detail level (basic/standard/full)

**Dependencies**:
- 21-security: CWE/OWASP mapping for security violations
- 05-analyzers: Quick fix data for SARIF fixes
- 04-call-graph: Call chain data for SARIF codeFlows

---

### R5: Implement Policy-as-Code with Inheritance and Versioning

**Priority**: P1 (Enterprise — required for governance)
**Effort**: Medium
**Impact**: Policy management, team governance, compliance

**Current State**:
4 hardcoded built-in policies. Custom policies are JSON files with no inheritance, no versioning, no YAML support.

**Proposed Change**:
Declarative policy system with inheritance, versioning, and multiple formats:

```yaml
# .drift/policies/team-policy.yaml
apiVersion: drift/v1
kind: QualityPolicy
metadata:
  name: team-standard
  version: "1.2.0"
  description: "Team standard policy"
extends: drift:default  # Inherit from built-in default
scope:
  branches: ["main", "release/*"]
overrides:
  gates:
    pattern-compliance:
      minComplianceRate: 85  # Override default 80
    regression-detection:
      blocking: true         # Promote from warning to blocking
      maxConfidenceDrop: 3   # Tighter than default 5
  aggregation:
    requiredGates: ["pattern-compliance", "security-boundary"]
```

**Key features**:
1. **Inheritance**: `extends: drift:default` — override only what differs
2. **Versioning**: `apiVersion` and `version` fields with migration support
3. **YAML support**: YAML in addition to JSON (YAML is more human-friendly for policies)
4. **Policy packs**: Installable policy bundles (e.g., `drift:owasp-security`, `drift:react-best-practices`)
5. **Schema validation**: JSON Schema for policy files with helpful error messages
6. **Policy diffing**: `drift policy diff team-standard drift:default` shows what's overridden

**Rationale**:
OPA's policy-as-code principles (QG-R6) demonstrate that declarative, versioned, composable policies are the enterprise standard. Drift v1's hardcoded policies don't scale to organizations with multiple teams and different quality standards.

**Evidence**:
- OPA policy-as-code (QG-R6): Declarative, versioned, composable
- Semgrep policy management (QG-R3): Per-rule configuration with API
- Enterprise tiering (QG-R12): Custom policies are a Team/Enterprise feature

**Implementation Notes**:
- PolicyLoader gains YAML parsing (use `js-yaml` or similar)
- Inheritance resolution: deep merge with override semantics
- Policy packs: npm packages containing policy YAML files
- Schema validation: JSON Schema generated from TypeScript types
- Migration: `apiVersion` field enables schema evolution

**Risks**:
- Policy inheritance can create confusing behavior (which setting is active?)
- Mitigation: `drift policy resolve team-standard` shows the fully resolved policy

**Dependencies**:
- 10-cli: `drift policy` subcommand for management
- 12-infrastructure: Policy pack distribution via npm

---

### R6: Add Developer Feedback Loop for Violations

**Priority**: P1 (Adoption — critical for developer trust)
**Effort**: Medium
**Impact**: False-positive reduction, pattern confidence improvement, developer satisfaction

**Current State**:
No mechanism for developers to provide feedback on violations. No false-positive tracking. No automatic confidence adjustment based on feedback.

**Proposed Change**:
Implement a violation feedback system that feeds back into pattern confidence:

**Feedback actions** (available in PR comments, CLI, IDE):
| Action | Effect |
|--------|--------|
| `fix` | Developer fixes the violation → confirms pattern validity → +0.02 confidence |
| `dismiss:false-positive` | Pattern incorrectly flagged this code → -0.05 confidence, track FP |
| `dismiss:wont-fix` | Valid violation but intentional deviation → create exception, no confidence change |
| `dismiss:not-applicable` | Pattern doesn't apply to this context → -0.02 confidence |

**Automatic demotion**:
```
if falsePositiveRate(pattern, last30days) > 0.10:
  demote pattern from block → comment
  log warning: "Pattern {name} demoted due to {rate}% false-positive rate"
  
if falsePositiveRate(pattern, last30days) > 0.25:
  demote pattern from comment → monitor
  log warning: "Pattern {name} suspended due to {rate}% false-positive rate"
```

**Feedback storage**:
```sql
CREATE TABLE violation_feedback (
  id TEXT PRIMARY KEY,
  violation_id TEXT NOT NULL,
  pattern_id TEXT NOT NULL,
  action TEXT NOT NULL,  -- fix, dismiss:false-positive, dismiss:wont-fix, dismiss:not-applicable
  reason TEXT,
  author TEXT,
  timestamp TEXT NOT NULL,
  file TEXT NOT NULL,
  line INTEGER NOT NULL
);
```

**Rationale**:
Google Tricorder (QG-R5) demonstrates that feedback loops are essential for maintaining analysis quality. Tools without feedback mechanisms accumulate false positives until developers ignore all results. Meta Fix Fast (QG-R4) shows that signal quality degrades without active noise management.

**Evidence**:
- Google Tricorder (QG-R5): "Not useful" / "Please fix" buttons, <10% FP rate enforcement
- Meta Fix Fast (QG-R4): Signal prioritization and noise reduction
- Enterprise practices (QG-R15): False-positive management is #1 adoption factor

**Implementation Notes**:
- Feedback stored in drift.db (new table)
- GitHub/GitLab reporters include feedback action links in PR comments
- CLI: `drift gate dismiss <violation-id> --reason false-positive`
- IDE: Quick action on violation diagnostic
- Feedback aggregation runs during audit (not during gate execution)
- SARIF suppressions populated from feedback data

**Risks**:
- Developers may dismiss valid violations to unblock PRs
- Mitigation: Dismissals require a reason; patterns with high dismiss rates are flagged for review
- Dismissal abuse detection: if one author dismisses >50% of violations, flag for team review

**Dependencies**:
- 08-storage: New violation_feedback table
- 03-detectors: Pattern confidence adjustment from feedback
- 06-cortex: Feedback can create tribal knowledge memories ("this pattern doesn't apply to X because...")
- 11-ide: IDE integration for feedback actions

---

### R7: Support Multi-Stage Enforcement

**Priority**: P1 (Developer experience — shift left)
**Effort**: Medium
**Impact**: Earlier detection, faster feedback, reduced CI load

**Current State**:
Quality gates run only in CI (post-push). No pre-commit or IDE integration.

**Proposed Change**:
Support 4 enforcement stages with appropriate scope and latency:

| Stage | Trigger | Scope | Latency Target | Policy Preset |
|-------|---------|-------|----------------|---------------|
| Pre-commit | Git hook | Changed files only | <5 seconds | `pre-commit` (pattern compliance only) |
| PR check | CI push | Changed files + affected files | <30 seconds | Branch-appropriate (relaxed/default/strict) |
| Post-merge | CI merge | Full scan | <2 minutes | `default` with regression detection |
| Scheduled audit | Cron | Full scan + degradation | <5 minutes | `strict` with full audit |

**Pre-commit hook** (new):
```bash
# .drift/hooks/pre-commit
drift gate run --mode pre-commit --files $(git diff --cached --name-only)
```

**Stage-specific optimizations**:
- Pre-commit: Only pattern compliance, no call graph loading, no snapshot comparison
- PR check: Incremental (cached), parallel gates, changed files + 1-hop affected files
- Post-merge: Full scan, snapshot creation, regression detection against previous main
- Scheduled: Full audit with degradation tracking, health score calculation, trend analysis

**Rationale**:
DevSecOps best practices (QG-R14) mandate multi-stage enforcement. Meta Fix Fast (QG-R4) demonstrates that defects caught in IDE take minutes to fix vs days in production. Shifting quality gates left reduces both fix time and CI load.

**Evidence**:
- DevSecOps multi-stage gates (QG-R14): Pre-commit, PR, post-merge, scheduled
- Meta Fix Fast (QG-R4): Exponential cost increase with pipeline stage
- SonarQube incremental analysis (QG-R2): Different analysis depth per stage

**Implementation Notes**:
- `drift gate run --mode <stage>` selects the appropriate preset
- Pre-commit hook generated by `drift init` or `drift hooks install`
- IDE integration via LSP: run pattern compliance on file save
- Stage presets are built-in policies that can be overridden

**Risks**:
- Pre-commit hooks can slow down developer workflow if too slow
- Mitigation: Strict <5s timeout, fail-open on timeout

**Dependencies**:
- 10-cli: `drift hooks install` command
- 11-ide: LSP integration for real-time gate feedback
- 12-infrastructure: Pre-commit hook distribution

---

### R8: Add JUnit XML and HTML Reporters

**Priority**: P1 (CI integration — universal compatibility)
**Effort**: Low
**Impact**: CI system compatibility, trend visualization, standalone reports

**Current State**:
5 reporters: text, JSON, SARIF, GitHub, GitLab. No JUnit XML (universal CI format) or HTML (standalone reports).

**Proposed Change**:
Add two new reporters:

**JUnit XML Reporter**:
```xml
<testsuites name="drift-quality-gates" tests="6" failures="2" time="1.234">
  <testsuite name="pattern-compliance" tests="1" failures="1" time="0.456">
    <testcase name="pattern-compliance" classname="drift.gates">
      <failure type="GateFailed" message="Score: 72/100 (threshold: 80)">
        3 violations found:
        - src/auth/login.ts:42 — Missing auth middleware (error)
        - src/api/users.ts:15 — Non-standard route structure (warning)
        - src/utils/db.ts:88 — Unapproved query pattern (warning)
      </failure>
    </testcase>
  </testsuite>
  <testsuite name="security-boundary" tests="1" failures="1" time="0.234">
    <testcase name="security-boundary" classname="drift.gates">
      <failure type="GateFailed" message="Score: 60/100 (threshold: 70)">
        1 violation found:
        - src/api/admin.ts:23 — Unauthorized access to users table (error)
      </failure>
    </testcase>
  </testsuite>
  <!-- ... passed gates as passing testcases ... -->
</testsuites>
```

**HTML Reporter**:
- Standalone HTML file with embedded CSS (no external dependencies)
- Summary dashboard: overall score, per-gate results, violation count
- Expandable violation details with code snippets
- Trend chart (if historical data available)
- Exportable (can be attached to CI artifacts)

**Rationale**:
JUnit XML (QG-R13) is the universal CI test report format supported by Jenkins, GitLab CI, CircleCI, Azure DevOps, and virtually every CI system. HTML reports provide standalone, shareable quality summaries for stakeholders who don't use CI dashboards.

**Evidence**:
- JUnit XML universality (QG-R13): Every major CI system supports it
- SARIF complementarity (QG-R8): SARIF for code scanning, JUnit for CI dashboards

**Implementation Notes**:
- JUnit XML: Map each gate to a `<testsuite>`, each gate result to a `<testcase>`
- HTML: Use a template engine or string concatenation (no framework dependency)
- Both reporters follow the existing `BaseReporter` pattern
- Multiple reporters can run simultaneously: `--format sarif,junit,html`

**Risks**:
- Minimal — additive change, no impact on existing reporters

**Dependencies**:
- None — self-contained addition

---

### R9: Implement Gate Dependency Graph and Priority Ordering

**Priority**: P1 (Architecture — enables optimization)
**Effort**: Medium
**Impact**: Execution efficiency, early termination, resource optimization

**Current State**:
ParallelExecutor runs all gates in a single parallel group. No dependency ordering. No early termination.

**Proposed Change**:
Implement a gate dependency graph with topological execution:

```
Gate Dependencies:
  pattern-compliance    → (none)
  constraint-verification → (none)
  regression-detection  → pattern-compliance (needs current compliance data)
  impact-simulation     → (none)
  security-boundary     → impact-simulation (can reuse affected function set)
  custom-rules          → (none)

Execution Groups:
  Group 1 (parallel): pattern-compliance, constraint-verification, impact-simulation, custom-rules
  Group 2 (parallel): regression-detection, security-boundary
```

**Early termination**:
```
if policy.earlyTermination === true:
  if any required gate in Group 1 fails:
    skip Group 2
    return failed result immediately
```

**Gate priority** (configurable):
```yaml
gates:
  security-boundary:
    priority: 1  # Run first
  pattern-compliance:
    priority: 2
  # ... lower priority gates run later
```

**Rationale**:
Running all gates when a critical gate has already failed wastes CI time. Gate dependencies enable data sharing (regression-detection can use pattern-compliance results instead of re-computing). Priority ordering lets security-critical gates run first.

**Evidence**:
- DevSecOps multi-stage gates (QG-R14): Different checks at different stages
- Meta Fix Fast (QG-R4): Prioritize actionable signals
- SonarQube (QG-R1): Quality gate evaluation is ordered

**Implementation Notes**:
- Gates declare dependencies: `static dependencies: GateId[] = ['pattern-compliance']`
- ParallelExecutor builds a DAG and executes in topological order
- Dependent gates receive predecessor results in their `GateInput`
- Early termination is opt-in via policy configuration
- Default: no early termination (preserve fail-safe behavior)

**Risks**:
- Gate dependencies create coupling between gate implementations
- Mitigation: Dependencies are optional — gates must work without predecessor data

**Dependencies**:
- None — internal to quality gates subsystem

---

### R10: Migrate Persistence from JSON Files to SQLite

**Priority**: P1 (Scalability — required for enterprise)
**Effort**: Medium
**Impact**: Query performance, storage efficiency, concurrent access

**Current State**:
Snapshots stored as JSON files (`.drift/quality-gates/snapshots/{branch}/{id}.json`). Run history as JSON files. Audit data as JSON files. Max 50 snapshots/branch, 100 runs total.

**Proposed Change**:
Migrate all quality gate persistence to SQLite tables in drift.db:

```sql
-- Gate run history
CREATE TABLE gate_runs (
  id TEXT PRIMARY KEY,
  timestamp TEXT NOT NULL,
  branch TEXT NOT NULL,
  commit_sha TEXT,
  policy_id TEXT NOT NULL,
  passed INTEGER NOT NULL,
  score REAL NOT NULL,
  violation_count INTEGER NOT NULL,
  execution_time_ms INTEGER NOT NULL,
  ci INTEGER NOT NULL DEFAULT 0,
  gate_results TEXT NOT NULL,  -- JSON blob of per-gate results
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_gate_runs_branch ON gate_runs(branch, timestamp DESC);
CREATE INDEX idx_gate_runs_timestamp ON gate_runs(timestamp DESC);

-- Health snapshots
CREATE TABLE health_snapshots (
  id TEXT PRIMARY KEY,
  timestamp TEXT NOT NULL,
  branch TEXT NOT NULL,
  commit_sha TEXT,
  patterns_snapshot TEXT NOT NULL,    -- JSON blob
  constraints_snapshot TEXT NOT NULL, -- JSON blob
  security_snapshot TEXT NOT NULL,    -- JSON blob
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_snapshots_branch ON health_snapshots(branch, timestamp DESC);

-- Audit history
CREATE TABLE audit_history (
  id TEXT PRIMARY KEY,
  timestamp TEXT NOT NULL,
  health_score REAL NOT NULL,
  avg_confidence REAL NOT NULL,
  approval_ratio REAL NOT NULL,
  compliance_rate REAL NOT NULL,
  pattern_count INTEGER NOT NULL,
  duplicate_groups INTEGER NOT NULL,
  false_positive_count INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_audit_timestamp ON audit_history(timestamp DESC);

-- Violation feedback
CREATE TABLE violation_feedback (
  id TEXT PRIMARY KEY,
  violation_id TEXT NOT NULL,
  pattern_id TEXT NOT NULL,
  action TEXT NOT NULL,
  reason TEXT,
  author TEXT,
  file TEXT NOT NULL,
  line INTEGER NOT NULL,
  timestamp TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_feedback_pattern ON violation_feedback(pattern_id);
CREATE INDEX idx_feedback_timestamp ON violation_feedback(timestamp DESC);

-- Gate result cache
CREATE TABLE gate_cache (
  cache_key TEXT PRIMARY KEY,
  gate_id TEXT NOT NULL,
  branch TEXT NOT NULL,
  result TEXT NOT NULL,  -- JSON blob of GateResult
  input_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT
);
CREATE INDEX idx_cache_branch ON gate_cache(branch);
CREATE INDEX idx_cache_expires ON gate_cache(expires_at);
```

**Rationale**:
JSON file storage doesn't scale for enterprise use cases with thousands of runs across hundreds of branches. SQLite provides indexed queries, concurrent read access (WAL mode), atomic writes, and efficient storage. This aligns with the v2 storage consolidation strategy (2 databases: drift.db + cortex.db).

**Evidence**:
- SonarQube (QG-R2): Server-side analysis cache in database
- V2 storage strategy (from Master Recommendations CR5): SQLite WAL mode as default
- Enterprise scale requirements (QG-R15): Thousands of runs need efficient querying

**Implementation Notes**:
- Migration: On first run, import existing JSON files into SQLite tables
- Retention: SQL-based retention (`DELETE FROM gate_runs WHERE timestamp < datetime('now', '-90 days')`)
- Queries: Trend analysis becomes SQL queries instead of file iteration
- Concurrent access: WAL mode enables reads during writes

**Risks**:
- Migration from JSON to SQLite could lose data if interrupted
- Mitigation: Keep JSON files as backup until migration is confirmed successful

**Dependencies**:
- 08-storage: Tables added to drift.db schema
- 24-data-lake: Gate run data available for materialized views

---

### R11: Hotspot-Aware Violation Scoring

**Priority**: P2 (Intelligence — improves signal quality)
**Effort**: Medium
**Impact**: Violation prioritization, developer focus, noise reduction

**Current State**:
All violations weighted equally regardless of code location. A violation in a rarely-touched utility file has the same impact as a violation in a frequently-changed authentication module.

**Proposed Change**:
Weight violation severity by file change frequency (hotspot score):

```
hotspotScore = changeFrequency(file, last90days) / maxChangeFrequency
adjustedPenalty = basePenalty × (1 + hotspotScore × hotspotMultiplier)
```

Where `hotspotMultiplier` is configurable (default: 0.5, meaning hotspot violations are up to 1.5× more impactful).

**Hotspot data sources**:
- Git log: `git log --format='%H' --follow -- <file>` → count commits in last 90 days
- Author count: files touched by many authors are higher risk
- Recent churn: files with high recent churn (lines added + removed) are higher risk

**Rationale**:
CodeScene's behavioral analysis (QG-R7) demonstrates that code quality issues in frequently-changed code have disproportionate impact on development velocity and defect rates. Prioritizing violations in hotspots focuses developer attention where it matters most.

**Evidence**:
- CodeScene behavioral analysis (QG-R7): Hotspot-driven prioritization
- Meta Fix Fast (QG-R4): Prioritize by actionability and impact
- Code quality research (QG-R10): Non-linear relationship between code quality and business impact

**Implementation Notes**:
- Hotspot data computed during scan phase (git log analysis)
- Stored in drift.db as file-level metrics
- Gate scoring formula gains a hotspot multiplier
- Configurable: `gates.pattern-compliance.hotspotMultiplier: 0.5`
- Disabled by default in `ci-fast` policy (no git history needed)

**Risks**:
- Git history analysis adds latency to gate execution
- Mitigation: Hotspot data computed during scan (not during gate execution), cached in drift.db

**Dependencies**:
- 01-rust-core: Git history analysis (could be a new Rust analyzer)
- 08-storage: File-level hotspot metrics in drift.db

---

### R12: Align Security Gates with OWASP/CWE Standards

**Priority**: P2 (Enterprise compliance — required for security-conscious organizations)
**Effort**: Medium
**Impact**: Compliance reporting, security audit readiness, enterprise sales

**Current State**:
Security boundary gate uses heuristic auth detection (function name matching). No CWE mapping. No OWASP Top 10 alignment.

**Proposed Change**:
Map all security-related gate violations to CWE IDs and OWASP Top 10 categories:

| Drift Security Check | CWE ID | OWASP Category |
|---------------------|--------|----------------|
| Unauthorized data access | CWE-862 (Missing Authorization) | A01:2021 Broken Access Control |
| Unprotected sensitive data | CWE-311 (Missing Encryption) | A02:2021 Cryptographic Failures |
| Hardcoded secrets | CWE-798 (Hard-coded Credentials) | A07:2021 Identification Failures |
| SQL injection patterns | CWE-89 (SQL Injection) | A03:2021 Injection |
| Missing input validation | CWE-20 (Improper Input Validation) | A03:2021 Injection |
| Insecure configuration | CWE-16 (Configuration) | A05:2021 Security Misconfiguration |
| Missing auth middleware | CWE-306 (Missing Authentication) | A07:2021 Identification Failures |

**SARIF integration**: CWE and OWASP references included in SARIF taxonomies (see R4).

**Compliance report**: New reporter that produces a compliance summary:
```
OWASP Top 10 Coverage Report
─────────────────────────────
A01 Broken Access Control    ✅ Covered (3 checks, 0 violations)
A02 Cryptographic Failures   ✅ Covered (2 checks, 1 violation)
A03 Injection                ✅ Covered (4 checks, 0 violations)
A04 Insecure Design          ⚠️ Partial (1 check)
A05 Security Misconfiguration ✅ Covered (3 checks, 0 violations)
A06 Vulnerable Components    ❌ Not covered (use dependency scanner)
A07 Identification Failures  ✅ Covered (2 checks, 0 violations)
A08 Software/Data Integrity  ⚠️ Partial (1 check)
A09 Logging Failures         ✅ Covered (2 checks, 0 violations)
A10 SSRF                     ❌ Not covered (requires runtime analysis)
```

**Rationale**:
OWASP SPVS (QG-R9) provides a tiered security framework that maps to Drift's tier structure. Enterprise customers require CWE/OWASP mapping for compliance reporting and security audits.

**Evidence**:
- OWASP SPVS (QG-R9): Three maturity levels for pipeline security
- SARIF taxonomies (QG-R8): CWE and OWASP as standard taxonomies
- Enterprise requirements (QG-R15): Compliance reporting for security audits

**Implementation Notes**:
- CWE mapping table: pattern category → CWE ID (maintained as data, not code)
- OWASP mapping table: CWE ID → OWASP Top 10 category
- Compliance reporter: new reporter type producing coverage summary
- SARIF enhancement: taxonomies section with CWE/OWASP references

**Risks**:
- CWE mapping requires security expertise to get right
- Mitigation: Start with high-confidence mappings, expand over time

**Dependencies**:
- 21-security: Security pattern → CWE mapping
- 03-detectors: Security detector categories aligned with CWE

---

### R13: Add Gate Timeout and Partial Failure Recovery

**Priority**: P2 (Reliability — prevents CI hangs)
**Effort**: Low
**Impact**: CI reliability, graceful degradation

**Current State**:
No per-gate timeout. A slow gate blocks the entire pipeline. No checkpoint/resume for interrupted runs.

**Proposed Change**:

**Per-gate timeout**:
```yaml
gates:
  impact-simulation:
    timeout: 30s  # Kill after 30 seconds
  security-boundary:
    timeout: 60s
  pattern-compliance:
    timeout: 15s
```

Default timeout: 30 seconds per gate. Configurable per gate in policy.

**Timeout behavior**: Gate returns `status: 'errored'` with `error: 'Timeout after 30s'`. Fail-safe design preserved — errored gates don't block (unless policy overrides).

**Partial failure recovery**:
- After each gate completes, save intermediate result to cache
- If orchestrator crashes, next run can resume from last completed gate
- Checkpoint stored in gate_cache table (R10)

**Rationale**:
In CI environments, a hanging gate can block the entire pipeline for minutes or hours. Per-gate timeouts with fail-safe behavior ensure that infrastructure issues don't block deployments.

**Evidence**:
- Fail-safe design (existing v1 principle): Errored gates don't block
- DevSecOps latency requirements (QG-R14): PR checks must complete in <2 minutes
- SonarQube (QG-R2): Analysis cache enables partial result reuse

**Implementation Notes**:
- Use `Promise.race([gate.execute(input), timeout(ms)])` for timeout
- Timeout returns a synthetic GateResult with status 'errored'
- Checkpoint: save each gate result to SQLite as it completes
- Resume: on startup, check for incomplete runs and resume from last checkpoint

**Risks**:
- Aggressive timeouts could cause gates to always timeout on large codebases
- Mitigation: Default timeouts are generous (30s); configurable per policy

**Dependencies**:
- None — internal to quality gates subsystem

---

### R14: Custom Rule Expansion — AST and Call Graph Conditions

**Priority**: P2 (Extensibility — power user feature)
**Effort**: Medium
**Impact**: Custom enforcement capabilities, enterprise flexibility

**Current State**:
Custom rules support 6 condition types: file-pattern, content-pattern, dependency, naming, structure, composite. No AST-based or call-graph-based conditions.

**Proposed Change**:
Add 3 new condition types:

**AST condition** (tree-sitter query):
```yaml
- id: no-direct-db-access
  name: "No direct database access in controllers"
  condition:
    type: ast-query
    query: '(call_expression function: (member_expression object: (identifier) @obj) (#match? @obj "^(db|prisma|sequelize)$"))'
    scope:
      files: "src/controllers/**"
    mustNot: true
  severity: error
  message: "Controllers must not access the database directly. Use a service layer."
```

**Call graph condition**:
```yaml
- id: no-controller-to-controller
  name: "Controllers must not call other controllers"
  condition:
    type: call-graph
    source: { pattern: "src/controllers/**" }
    target: { pattern: "src/controllers/**" }
    mustNot: true
  severity: error
  message: "Controllers should not call other controllers. Extract shared logic to a service."
```

**Metric condition**:
```yaml
- id: max-function-complexity
  name: "Function cyclomatic complexity limit"
  condition:
    type: metric
    metric: cyclomatic-complexity
    threshold: 15
    scope:
      files: "src/**"
  severity: warning
  message: "Function complexity exceeds 15. Consider refactoring."
```

**Rationale**:
The existing 6 condition types cover basic checks but can't express architectural constraints (e.g., "controllers must not access the database directly") or complexity limits. AST and call graph conditions enable powerful custom enforcement without modifying Drift's source code.

**Evidence**:
- Semgrep custom rules (QG-R3): AST-based pattern matching for custom enforcement
- CodeQL (QG-R5 context): Query-based code analysis for security and quality
- OPA policy-as-code (QG-R6): Declarative rules with rich condition types

**Implementation Notes**:
- AST condition: Delegate to tree-sitter query engine (already in Rust core)
- Call graph condition: Query call graph for paths matching source/target patterns
- Metric condition: Query analyzer results for metric values
- All new conditions work within the existing composite condition system (AND/OR/NOT)

**Risks**:
- AST queries are language-specific — users need tree-sitter knowledge
- Mitigation: Provide a library of common AST query templates

**Dependencies**:
- 01-rust-core: Tree-sitter query execution for AST conditions
- 04-call-graph: Path queries for call graph conditions
- 05-analyzers: Metric queries for metric conditions

---

## Supplementary Recommendations (Post-Audit)

> The following recommendations were added after a systematic coverage audit (see AUDIT.md) identified gaps in the original 14 recommendations. These close the remaining holes needed for a clean v2 recreation.

---

### R15: Structured Violation Explanation Format

**Priority**: P1 (Developer experience — core to adoption)
**Effort**: Low
**Impact**: Developer understanding, fix speed, reduced support burden

**Current State**:
GateViolation has `message: string` and `suggestion?: string`. No structured format for explaining WHY a violation exists, WHAT the expected pattern is, HOW to fix it, or what the IMPACT of not fixing it is. Developers see "Missing auth middleware" but don't know why it matters or what to do.

**Proposed Change**:
Extend GateViolation with a structured explanation:

```typescript
interface ViolationExplanation {
  why: string;           // "This endpoint accesses the users table which contains PII"
  expected: string;      // "All routes accessing protected tables must use authenticate() middleware"
  howToFix: string;      // "Add authenticate() middleware before the route handler"
  impact: string;        // "Without auth, any unauthenticated request can read user PII"
  learnMore?: string;    // URL to pattern documentation or CWE reference
  relatedPatterns?: string[]; // Pattern IDs that define the expected behavior
}

interface GateViolation {
  // ... existing fields ...
  explanation?: ViolationExplanation;
}
```

**Rationale**:
Enterprise static analysis best practices (QG-R15) identify explanation quality as critical for adoption. Google Tricorder (QG-R5) found that developers ignore tools they don't understand. The CMU SEI research on static analysis alert prioritization confirms that actionability depends on developers understanding what to do about an alert.

**Evidence**:
- Enterprise practices (QG-R15): Explanation quality drives adoption
- Google Tricorder (QG-R5): Developers ignore opaque warnings
- CMU SEI (new research): Alert actionability requires clear remediation guidance

**Implementation Notes**:
- Each gate populates explanation from pattern metadata + gate context
- Pattern compliance: explanation comes from pattern description + rationale
- Security boundary: explanation includes the unauthorized call chain
- Regression detection: explanation shows before/after comparison
- SARIF reporter maps `howToFix` to SARIF `fixes`, `learnMore` to `helpUri`

**Risks**:
- Generating good explanations requires rich pattern metadata
- Mitigation: Start with template-based explanations, improve over time

**Dependencies**:
- 03-detectors: Pattern metadata must include rationale and documentation links
- 06-cortex: Pattern rationale memories can enrich explanations

---

### R16: Violation Prioritization Algorithm

**Priority**: P1 (Developer experience — reduces noise, focuses attention)
**Effort**: Medium
**Impact**: Developer productivity, signal-to-noise ratio, fix rate

**Current State**:
Violations are sorted by severity (errors first) but otherwise unordered. A violation in a rarely-touched utility file has the same priority as a violation in a hot-path authentication module. No consideration of whether the developer introduced the violation, how confident the pattern is, or how easy the fix is.

**Proposed Change**:
Implement a multi-factor prioritization score for each violation:

```
priorityScore = severity × 0.30
              + isNew × 0.25
              + patternConfidence × 0.15
              + hotspotScore × 0.15
              + fixDifficulty × 0.10
              + authorMatch × 0.05
```

Where:
- `severity`: error=1.0, warning=0.6, info=0.3, hint=0.1
- `isNew`: 1.0 if introduced by this change, 0.3 if pre-existing
- `patternConfidence`: pattern's confidence score (0.0-1.0)
- `hotspotScore`: file change frequency normalized to 0.0-1.0 (from R11)
- `fixDifficulty`: inverse of estimated fix complexity (1.0=trivial, 0.2=complex)
- `authorMatch`: 1.0 if current author introduced it (via git blame), 0.5 otherwise

Violations sorted by priorityScore descending. Top N violations highlighted as "Fix These First."

**Rationale**:
Meta Fix Fast (QG-R4) demonstrates that signal volume overwhelms developers — prioritization is essential. The CMU SEI research on static analysis alert prioritization uses automated classification to help auditors address large volumes of alerts efficiently. CodeScene (QG-R7) proves that hotspot-aware prioritization focuses attention where it matters most.

**Evidence**:
- Meta Fix Fast (QG-R4): Signal aggregation and prioritization
- CMU SEI: Automated alert classification and prioritization for static analysis
- CodeScene (QG-R7): Hotspot-driven prioritization
- Google Tricorder (QG-R5): Actionability determines adoption

**Implementation Notes**:
- Priority score computed during ResultAggregator phase (after all gates complete)
- `isNew` requires baseline comparison (from R1 new-code-first mode)
- `authorMatch` requires git blame data (optional — graceful degradation if unavailable)
- `fixDifficulty` estimated from violation type (naming=easy, architecture=hard)
- Reporters show violations in priority order with score indicator
- SARIF `rank` property populated from priorityScore

**Risks**:
- Priority formula may not match team preferences
- Mitigation: Weights are configurable in policy

**Dependencies**:
- R1: isNew field from new-code-first mode
- R11: hotspotScore from hotspot-aware scoring
- 01-rust-core: Git blame integration for author attribution

---

### R17: Dry-Run / Preview Mode

**Priority**: P2 (Developer experience — preview before commit)
**Effort**: Low
**Impact**: Developer confidence, reduced CI failures, faster iteration

**Current State**:
No way to preview what gates would check without actually running them and persisting results. Developers must push code and wait for CI to discover violations.

**Proposed Change**:
Add a `--dry-run` flag that runs gates but does NOT persist results or affect baselines:

```bash
# Preview what gates would check on staged files
drift gate run --dry-run --files $(git diff --cached --name-only)

# Preview with specific policy
drift gate run --dry-run --policy strict

# Preview showing only new violations (combined with R1)
drift gate run --dry-run --mode pr --new-only
```

**Dry-run behavior**:
- Gates execute normally and produce violations
- Snapshot is NOT saved (no baseline pollution)
- Run history is NOT recorded
- Exit code is informational (always 0 unless --strict-dry-run)
- Output includes "DRY RUN — results not persisted" banner
- Cache IS populated (so subsequent real runs benefit)

**Rationale**:
SonarQube historically had a "preview mode" that ran analysis without publishing results to the server (deprecated in favor of SonarLint IDE integration). Terraform's `plan` command is the gold standard for preview-before-apply. Developers need to validate their changes locally before pushing to CI.

**Evidence**:
- SonarQube preview mode (historical): Local analysis without server publish
- Terraform plan: Preview infrastructure changes before applying
- DevSecOps shift-left (QG-R14): Earlier feedback reduces fix cost

**Implementation Notes**:
- Add `dryRun: boolean` to QualityGateOptions
- Orchestrator skips steps 8 (save snapshot) and 8b (save run history) when dryRun=true
- All other steps execute normally
- Pre-commit hook (R7) uses dry-run by default
- IDE integration (R7) uses dry-run for real-time feedback

**Risks**:
- Developers may rely on dry-run and skip CI gates
- Mitigation: Dry-run results include a warning that they may differ from CI (different baseline, different file set)

**Dependencies**:
- R7: Pre-commit hook uses dry-run mode
- 10-cli: `--dry-run` flag on `drift gate run`

---

### R18: Webhook and Notification System

**Priority**: P2 (Enterprise — CI/CD integration)
**Effort**: Low
**Impact**: Enterprise workflow integration, team awareness, incident response

**Current State**:
PolicyActions has `onPass`, `onFail`, `onWarn` hooks defined in the type system but no implementation for external notifications. No way to send Slack messages, trigger PagerDuty incidents, or call arbitrary webhooks when gates pass or fail.

**Proposed Change**:
Implement a notification system triggered by gate results:

```yaml
# In policy definition
actions:
  onFail:
    - type: webhook
      url: "https://hooks.slack.com/services/T.../B.../xxx"
      method: POST
      headers:
        Content-Type: application/json
      body: |
        {
          "text": "🚨 Quality gate FAILED on {{branch}} (score: {{score}})",
          "blocks": [
            {
              "type": "section",
              "text": { "type": "mrkdwn", "text": "{{summary}}" }
            }
          ]
        }
    - type: webhook
      url: "https://events.pagerduty.com/v2/enqueue"
      method: POST
      body: |
        {
          "routing_key": "{{env.PAGERDUTY_KEY}}",
          "event_action": "trigger",
          "payload": {
            "summary": "Quality gate failed: {{summary}}",
            "severity": "{{status}}"
          }
        }
  onPass:
    - type: webhook
      url: "https://hooks.slack.com/services/T.../B.../xxx"
      body: |
        { "text": "✅ Quality gate passed on {{branch}} (score: {{score}})" }
```

**Template variables**: `{{branch}}`, `{{commitSha}}`, `{{score}}`, `{{status}}`, `{{summary}}`, `{{violationCount}}`, `{{gatesRun}}`, `{{gatesFailed}}`, `{{executionTimeMs}}`, `{{env.VAR_NAME}}`.

**Rationale**:
Enterprise CI/CD pipelines require external notifications for team awareness and incident response. Every major CI system (Jenkins, GitLab, GitHub Actions) supports webhook notifications. Quality gate failures on protected branches should trigger immediate team notification.

**Evidence**:
- Industry standard: CI/CD webhook notifications are universal
- Enterprise requirements (QG-R12): Team/Enterprise tiers need governance features
- DevSecOps (QG-R14): Pipeline events should trigger appropriate responses

**Implementation Notes**:
- NotificationEngine processes PolicyActions after gate evaluation
- Template engine replaces `{{variables}}` with result data
- `{{env.VAR_NAME}}` reads from environment (secrets not stored in policy)
- HTTP client with timeout (5s), retry (1 attempt), and fail-open (notification failure doesn't block gate result)
- Notification is fire-and-forget — never blocks the pipeline

**Risks**:
- Webhook URLs may contain secrets
- Mitigation: Use `{{env.VAR_NAME}}` for secrets; never log webhook URLs

**Dependencies**:
- R5: Policy-as-code supports actions section
- 12-infrastructure: CI environment provides webhook secrets

---

### R19: Reporter Plugin Architecture

**Priority**: P2 (Extensibility — enterprise customization)
**Effort**: Low
**Impact**: Enterprise flexibility, custom output formats, ecosystem growth

**Current State**:
5 hardcoded reporters (text, JSON, SARIF, GitHub, GitLab). Adding a new format requires modifying Drift source code. No plugin mechanism.

**Proposed Change**:
Implement a reporter plugin system:

```typescript
// Reporter interface (already exists — just needs to be public)
interface Reporter {
  readonly id: string;
  readonly format: string;
  generate(result: QualityGateResult, options?: ReporterOptions): string;
  write(report: string, options?: ReporterOptions): Promise<void>;
}

// Plugin registration
// .drift/plugins/reporters/confluence-reporter.js
module.exports = {
  id: 'confluence',
  format: 'confluence',
  generate(result, options) {
    // Return Confluence wiki markup
    return `h1. Quality Gate Report\n...`;
  }
};
```

**Plugin discovery**:
1. Built-in reporters (text, JSON, SARIF, GitHub, GitLab, JUnit XML, HTML)
2. Project-level plugins: `.drift/plugins/reporters/*.js`
3. npm packages: `drift-reporter-*` (discovered via package.json)

**Usage**: `drift gate run --format confluence` or `--format custom:./my-reporter.js`

**Rationale**:
Enterprise customers need custom output formats for internal dashboards, Confluence pages, Jira tickets, custom compliance reports, and proprietary CI systems. A plugin architecture enables this without forking Drift.

**Evidence**:
- ESLint formatter plugins: Established pattern for extensible reporting
- Enterprise requirements (QG-R12): Custom formats for governance
- Reporter interface already exists — just needs to be exposed

**Implementation Notes**:
- Reporter interface is already well-defined — just expose it publicly
- Plugin loader: dynamic import from configured paths
- Validation: plugin must implement Reporter interface
- Built-in reporters remain the default — plugins are additive

**Risks**:
- Plugin code runs in the same process — security concern
- Mitigation: Plugins are local files, not remote code; same trust model as .drift config

**Dependencies**:
- None — self-contained addition

---

## Recommendation Summary

| # | Recommendation | Priority | Effort | Key Evidence |
|---|---------------|----------|--------|-------------|
| R1 | New-code-first enforcement | P0 | Medium | SonarQube "Clean as You Code" (QG-R1) |
| R2 | Progressive enforcement (Monitor/Comment/Block) | P0 | Medium | Semgrep three-mode policies (QG-R3) |
| R3 | Incremental gate execution with caching | P0 | High | SonarQube incremental analysis (QG-R2) |
| R4 | Rich SARIF 2.1.0 output | P0 | Medium | OASIS SARIF standard (QG-R8) |
| R5 | Policy-as-code with inheritance | P1 | Medium | OPA principles (QG-R6) |
| R6 | Developer feedback loop | P1 | Medium | Google Tricorder (QG-R5) |
| R7 | Multi-stage enforcement | P1 | Medium | DevSecOps best practices (QG-R14) |
| R8 | JUnit XML and HTML reporters | P1 | Low | Universal CI compatibility (QG-R13) |
| R9 | Gate dependency graph | P1 | Medium | Execution optimization |
| R10 | SQLite persistence migration | P1 | Medium | Enterprise scalability |
| R15 | Structured violation explanations | P1 | Low | CMU SEI, Google Tricorder (QG-R5, QG-R15) |
| R16 | Violation prioritization algorithm | P1 | Medium | Meta Fix Fast (QG-R4), CMU SEI |
| R11 | Hotspot-aware scoring | P2 | Medium | CodeScene behavioral analysis (QG-R7) |
| R12 | OWASP/CWE alignment | P2 | Medium | OWASP SPVS (QG-R9) |
| R13 | Gate timeout and recovery | P2 | Low | CI reliability |
| R14 | Custom rule expansion | P2 | Medium | Semgrep/CodeQL extensibility |
| R17 | Dry-run / preview mode | P2 | Low | SonarQube preview, Terraform plan |
| R18 | Webhook and notification system | P2 | Low | Enterprise CI/CD standard practice |
| R19 | Reporter plugin architecture | P2 | Low | ESLint formatter plugins |

---

## V2 Build Phases for Quality Gates

```
Phase 1 — Foundation (with core engine):
  • Gate interface with new-code-first mode (R1)
  • Progressive enforcement model (R2)
  • Structured violation explanations (R15)
  • SQLite persistence (R10)
  • Base gate with timeout (R13)
  • Dry-run mode (R17)

Phase 2 — Core Gates:
  • Pattern compliance gate (with incremental caching — R3)
  • Constraint verification gate
  • Custom rules gate (with AST/call-graph conditions — R14)
  • Regression detection gate (with statistical significance)
  • Violation prioritization algorithm (R16)

Phase 3 — Advanced Gates:
  • Impact simulation gate (calls Rust for call graph traversal)
  • Security boundary gate (with CWE mapping — R12)
  • Gate dependency graph (R9)

Phase 4 — Policy Engine:
  • Policy-as-code with YAML + inheritance (R5)
  • Multi-stage enforcement presets (R7)
  • Webhook/notification system (R18)
  • Policy packs

Phase 5 — Reporters:
  • Rich SARIF 2.1.0 (R4)
  • JUnit XML + HTML (R8)
  • GitHub/GitLab with feedback actions (R6)
  • Reporter plugin architecture (R19)

Phase 6 — Intelligence:
  • Developer feedback loop (R6)
  • Hotspot-aware scoring (R11)
  • Automatic promotion/demotion engine (R2)
  • OWASP compliance reporter (R12)
```

---

## Cross-Category Impact Analysis

| Category | Impact from Quality Gates V2 |
|----------|------------------------------|
| **01-rust-core** | Git blame integration for author attribution (R16); git history for hotspot scoring (R11) |
| **03-detectors** | Pattern model gains `enforcementMode` field (R2); confidence adjusted by feedback (R6); pattern metadata needs rationale for explanations (R15) |
| **04-call-graph** | Call graph queries used by impact simulation, security boundary, and custom rules (R14) |
| **05-analyzers** | Rules engine integration; metric queries for custom rules (R14) |
| **06-cortex** | Pattern rationale memories enrich violation explanations (R15); feedback creates tribal knowledge (R6) |
| **07-mcp** | `drift_quality_gate` tool gains mode parameter (R1); feedback actions (R6); dry-run support (R17) |
| **08-storage** | New SQLite tables for gate runs, snapshots, feedback, cache (R10) |
| **10-cli** | `drift gate run --mode`, `--dry-run`, `drift policy`, `drift hooks install` commands (R1, R5, R7, R17) |
| **11-ide** | LSP integration for real-time gate feedback; feedback actions in editor (R6, R7) |
| **12-infrastructure** | GitHub Action for SARIF upload; pre-commit hook distribution; webhook secrets (R4, R7, R18) |
| **21-security** | CWE/OWASP mapping for security violations (R12) |
| **23-pattern-repository** | Enforcement mode persistence; feedback-driven confidence updates (R2, R6) |

---

## Quality Checklist

- [x] Each recommendation has cited evidence from research phase
- [x] Priorities justified (P0 = architectural/blocking, P1 = important, P2 = enhancement)
- [x] Effort assessed for each recommendation
- [x] Risks identified with mitigations for every recommendation
- [x] Implementation notes are actionable (not vague)
- [x] Cross-category dependencies documented for every recommendation
- [x] Build phases defined with dependency ordering
- [x] Full-circle impact analysis: how each recommendation affects the rest of the pipeline
- [x] Enterprise-grade considerations addressed (OWASP, SARIF, multi-repo, compliance, webhooks)
- [x] Developer experience prioritized (feedback loops, noise reduction, progressive enforcement, explanations, prioritization, dry-run)
- [x] Preserves what works (fail-safe design, parallel execution, policy engine structure)
- [x] 19 recommendations covering architecture, performance, integration, intelligence, DX, and reliability
- [x] Post-audit supplementary recommendations close all critical gaps (R15-R19)
- [x] All 20 v1 limitations addressed or explicitly deferred with rationale
- [x] All 12 open questions resolved or addressed
- [x] Coverage audit document (AUDIT.md) provides full traceability
