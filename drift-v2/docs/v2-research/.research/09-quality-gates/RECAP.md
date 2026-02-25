# 09 Quality Gates — Research Recap

## Executive Summary

Quality Gates (`packages/core/src/quality-gates/`, ~30 TypeScript files across 6 subdirectories) is Drift's CI/CD enforcement layer — the system that transforms offline convention discovery into actionable pass/fail decisions for pull requests and deployments. It orchestrates 6 specialized gates (pattern compliance, constraint verification, regression detection, impact simulation, security boundary, custom rules) through a configurable policy engine with 4 built-in policies, executes them in parallel, aggregates results via 4 aggregation modes, persists snapshots for regression baselines, and produces reports in 5 output formats (text, JSON, SARIF, GitHub, GitLab). Tightly coupled with the Audit System (`packages/core/src/audit/`), which provides pattern validation, duplicate detection, cross-validation, health scoring, and degradation tracking — the feedback loop that tells users "your codebase is drifting." Together, these systems form Layer 4 (Enforcement) of Drift's architecture, sitting between the Intelligence layer (detectors, analyzers, Cortex) and the Presentation layer (CLI, MCP, IDE).

---

## Current Implementation

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         PRESENTATION LAYER                              │
│  CLI (drift gate run) │ MCP (drift_quality_gate) │ CI Pipelines        │
├─────────────────────────────────────────────────────────────────────────┤
│                         GATE ORCHESTRATOR                               │
│  GateOrchestrator → PolicyLoader → GateRegistry → ParallelExecutor     │
│  → PolicyEvaluator → ResultAggregator → SnapshotStore → Reporter       │
├──────────┬──────────┬──────────┬──────────┬──────────┬──────────┬──────┤
│ Pattern  │Constraint│Regression│ Impact   │ Security │ Custom   │ Audit│
│Compliance│Verificatn│Detection │Simulation│ Boundary │ Rules    │Engine│
│          │          │          │          │          │          │      │
│ Patterns │Constraint│ Snapshot │Call Graph │Call Graph│ Rule     │Health│
│ Outliers │ Verifier │ Compare  │Reachablty│Data Flow │ Evaluator│Score │
├──────────┴──────────┴──────────┴──────────┴──────────┴──────────┴──────┤
│                         POLICY ENGINE                                   │
│  4 Built-in Policies │ Custom Policies │ Scope Matching │ Aggregation  │
├─────────────────────────────────────────────────────────────────────────┤
│                         REPORTERS                                       │
│  Text │ JSON │ SARIF │ GitHub PR │ GitLab MR │ (extensible)            │
├─────────────────────────────────────────────────────────────────────────┤
│                         PERSISTENCE                                     │
│  SnapshotStore (branch-based) │ GateRunStore (history) │ AuditStore    │
└─────────────────────────────────────────────────────────────────────────┘
```

### Component Inventory

| Component | Location | Purpose |
|-----------|----------|---------|
| `orchestrator/gate-orchestrator.ts` | Orchestrator | Main execution pipeline — coordinates entire quality gate flow |
| `orchestrator/gate-registry.ts` | Registry | Gate registration, lazy instantiation, singleton pattern |
| `orchestrator/parallel-executor.ts` | Executor | Concurrent gate execution (currently single parallel group) |
| `orchestrator/result-aggregator.ts` | Aggregator | Combines gate results into final QualityGateResult |
| `gates/base-gate.ts` | Base Gate | Abstract base with error handling, scoring, fail-safe design |
| `gates/pattern-compliance/` | Gate 1 | Pattern compliance checking — approved patterns followed? |
| `gates/constraint-verification/` | Gate 2 | Architectural constraint satisfaction |
| `gates/regression-detection/` | Gate 3 | Confidence/compliance regression vs baseline |
| `gates/impact-simulation/` | Gate 4 | Blast radius analysis via call graph |
| `gates/security-boundary/` | Gate 5 | Unauthorized data access detection |
| `gates/custom-rules/` | Gate 6 | User-defined rules (6 condition types) |
| `policy/policy-loader.ts` | Policy | Multi-source policy loading with context matching |
| `policy/policy-evaluator.ts` | Policy | 4 aggregation modes for pass/fail determination |
| `policy/default-policies.ts` | Policy | 4 built-in policies (default, strict, relaxed, ci-fast) |
| `reporters/text-reporter.ts` | Reporter | Terminal-friendly output |
| `reporters/json-reporter.ts` | Reporter | Machine-readable JSON |
| `reporters/sarif-reporter.ts` | Reporter | SARIF for GitHub Code Scanning |
| `reporters/github-reporter.ts` | Reporter | GitHub PR markdown comments |
| `reporters/gitlab-reporter.ts` | Reporter | GitLab MR markdown comments |
| `store/snapshot-store.ts` | Persistence | Branch-based health snapshots (max 50/branch) |
| `store/gate-run-store.ts` | Persistence | Run history for trends (max 100 runs) |
| `types.ts` | Types | ~1300 lines, 40+ interfaces |
| `audit/audit-engine.ts` | Audit | Pattern validation, dedup, cross-validation, health scoring |
| `audit/audit-store.ts` | Audit | Audit persistence, degradation tracking, 90-day history |


---

## Subsystem Deep Dives

### 1. Gate Orchestrator (`orchestrator/`)

**Purpose**: Coordinates the entire quality gate pipeline from file resolution through report generation.

**GateOrchestrator** — Main entry point. Constructor takes `projectRoot` string.

**Execution Pipeline (9 steps)**:
```
1. resolveFiles()       — Resolve file list (explicit files, glob patterns, or all)
2. loadPolicy()         — Load policy via PolicyLoader (by ID, inline, or context-based)
3. determineGates()     — Filter gates based on policy (enabled, not skipped)
4. buildContext()       — Lazy-load only what gates need:
                          • Patterns: if pattern-compliance or regression-detection enabled
                          • Constraints: if constraint-verification enabled
                          • Call graph: if impact-simulation or security-boundary enabled
                          • Previous snapshot: if regression-detection enabled
                          • Custom rules: if custom-rules enabled
5. executeGates()       — Run gates via ParallelExecutor
6. evaluate()           — Evaluate results against policy via PolicyEvaluator
7. aggregate()          — Combine into final QualityGateResult via ResultAggregator
8. saveSnapshot()       — Persist snapshot + run history
9. generateReport()     — Produce output via selected Reporter
```

**QualityGateOptions** (input):
```typescript
{
  files?: string[];              // Specific files to check
  patterns?: string[];           // Glob patterns for files
  policy?: string | QualityPolicy; // Policy ID, inline object, or undefined for default
  format?: OutputFormat;         // json, text, sarif, github, gitlab
  outputPath?: string;           // Write report to file
  ci?: boolean;                  // CI mode (affects exit codes)
  branch?: string;               // Current branch
  commitSha?: string;            // Current commit
  baselineBranch?: string;       // Branch to compare against
  baselineCommit?: string;       // Commit to compare against
  verbose?: boolean;
}
```

**GateRegistry** — Singleton pattern. 6 built-in gates registered lazily via dynamic import. Supports custom gate registration: `registry.register('my-gate', (context) => new MyGate(context))`.

**ParallelExecutor** — Currently runs all gates in a single parallel group (no dependency ordering). Fail-safe: errored gates return `passed: true`. Future: dependency graph support planned (regression-detection may depend on pattern-compliance; security-boundary may depend on impact-simulation).

**ResultAggregator** — Collects all violations sorted by severity (errors first), collects warnings, determines gates run vs skipped, sets exit code (0=passed, 1=failed).

---

### 2. The 6 Quality Gates (`gates/`)

**Base Gate** (`base-gate.ts`) — Abstract base class providing:
- Execution wrapper with error handling and timing
- Config validation interface
- Score calculation: `score = max(0, 100 - (penalty / maxPenalty) × 100)`
  - Error violations: 10 penalty points
  - Warning violations: 3 penalty points
  - Info violations: 1 penalty point
- Status determination: failed/warned/passed
- Helper methods: createPassed/createFailed/createWarned/createSkipped/createError
- Violation ID generation: `{gateId}-{file}-{line}-{ruleId}`
- **Fail-safe design**: Errored gates return `passed: true` — they don't block

#### Gate 1: Pattern Compliance (`pattern-compliance`)
**What**: Are approved patterns being followed? Are there new outliers?
**Default**: Blocking
**Config**: minComplianceRate (80%), maxNewOutliers (0), categories (all), minPatternConfidence (0.7), approvedOnly (true)
**Algorithm**:
1. Filter patterns by config (categories, confidence, approved-only)
2. Calculate compliance rate per pattern: `locations / (locations + outliers)`
3. Detect new outliers (outliers in changed files not in previous snapshot)
4. Evaluate thresholds: compliance rate vs minimum, new outliers vs maximum
5. Generate violations for non-compliant patterns and new outliers
**Score**: Based on overall compliance rate across all patterns

#### Gate 2: Constraint Verification (`constraint-verification`)
**What**: Do code changes satisfy architectural constraints?
**Default**: Blocking
**Config**: enforceApproved (true), enforceDiscovered (false), minConfidence (0.9), categories (all)
**Algorithm**:
1. Filter constraints by status (approved, optionally discovered), confidence, categories
2. For each constraint, find applicable files from changed file set
3. Verify each constraint against applicable files using ConstraintVerifier
4. Collect violations with severity from constraint enforcement level

#### Gate 3: Regression Detection (`regression-detection`)
**What**: Has pattern confidence or compliance dropped vs baseline?
**Default**: Warning only
**Config**: maxConfidenceDrop (5%), maxComplianceDrop (10%), maxNewOutliersPerPattern (3), criticalCategories (['auth', 'security']), baseline ('branch-base' | 'previous-run' | 'snapshot')
**Algorithm**:
1. Load baseline snapshot (previous run on same branch, or branch-base)
2. Compare current patterns against baseline:
   - Confidence drops per pattern
   - Compliance rate drops per pattern
   - New outlier counts per pattern
3. Classify regression severity:
   - Critical: confidence drop > 2× threshold, or in critical category
   - High: confidence drop > threshold
   - Medium: compliance drop > threshold
   - Low: new outliers > threshold
4. Calculate per-category deltas and overall delta
5. Generate violations for regressions exceeding thresholds
**Positive signals**: Patterns that improved (confidence up, outliers down) are reported

#### Gate 4: Impact Simulation (`impact-simulation`)
**What**: How large is the blast radius of the change?
**Default**: Warning only
**Config**: maxFilesAffected (20), maxFunctionsAffected (50), maxEntryPointsAffected (10), maxFrictionScore (60), analyzeSensitiveData (true)
**Algorithm**:
1. For each changed file, find functions in the call graph
2. Trace callers (reverse reachability) to find affected functions
3. Identify affected entry points (API handlers, exported functions)
4. If analyzeSensitiveData: trace data access paths through affected functions
5. Calculate friction score:
   ```
   frictionScore = (filesAffected/maxFiles × 25) + (functionsAffected/maxFunctions × 25)
                 + (entryPointsAffected/maxEntryPoints × 30) + (sensitiveDataPaths × 20)
   ```
6. Classify breaking risk: critical (>80), high (>60), medium (>40), low

#### Gate 5: Security Boundary (`security-boundary`)
**What**: Is sensitive data accessed without authentication? Unauthorized access paths?
**Default**: Blocking
**Config**: allowNewSensitiveAccess (false), protectedTables (['users', 'payments', 'credentials', 'tokens']), maxDataFlowDepth (5), requiredAuthPatterns (['authenticate', 'authorize', 'checkAuth', 'requireAuth'])
**Algorithm**:
1. For each changed file, detect data access points (table/field access)
2. Filter for protected tables
3. For each access point, check if auth exists in the call chain:
   - Walk callers up the call graph
   - Look for functions matching requiredAuthPatterns
   - Track depth of auth check
4. Identify unauthorized paths (data access without auth in call chain)
5. Check for new sensitive data access (not in previous snapshot)

#### Gate 6: Custom Rules (`custom-rules`)
**What**: User-defined rules with 6 condition types
**Default**: Disabled
**Config**: ruleFiles (paths to rule JSON), inlineRules (inline definitions), useBuiltInRules (false)
**6 Condition Types**:
| Type | What It Checks |
|------|---------------|
| `file-pattern` | Files matching glob must/must-not exist |
| `content-pattern` | File content must/must-not match regex |
| `dependency` | Package must/must-not be in dependencies |
| `naming` | Files/functions must follow naming convention |
| `structure` | Directory must contain required files |
| `composite` | AND/OR/NOT combinations of other conditions |

**Built-in Rules** (when useBuiltInRules: true):
- No `console.log` in production code
- No `TODO`/`FIXME` in committed code
- Test files must exist for source files
- No hardcoded secrets (API keys, passwords)

---

### 3. Policy Engine (`policy/`)

**Purpose**: Controls which gates run, their thresholds, blocking behavior, and how results aggregate.

**PolicyLoader** — Multi-source resolution:
1. Inline QualityPolicy object (passed directly)
2. Built-in policy by ID (default, strict, relaxed, ci-fast)
3. Custom policy from `.drift/quality-gates/policies/custom/{id}.json`
4. Context-based matching (branch, paths, author)
5. Fallback to `default` policy

**Context-Based Matching** — Policies ranked by scope specificity:
- Branch patterns: +10 specificity
- Path patterns: +5
- Author patterns: +3
- Include file patterns: +2
- Exclude file patterns: +1
Most specific matching policy wins.

**PolicyEvaluator** — 4 Aggregation Modes:

| Mode | Logic | Use Case |
|------|-------|----------|
| `any` (default) | Any blocking gate failure = overall failure | Most common CI pattern |
| `all` | All gates must fail for overall failure | Lenient mode |
| `weighted` | Weighted average of gate scores vs minScore (default 70) | Nuanced scoring |
| `threshold` | Average of all gate scores vs minScore (default 70) | Simple threshold |

**Required Gates**: Specified in `aggregation.requiredGates`. Always block regardless of aggregation mode.

**4 Built-in Policies**:

| Policy | Scope | Key Settings |
|--------|-------|-------------|
| `default` | All branches | Compliance+constraints block (80% min), regression+impact warn, security blocks |
| `strict` | main, master, release/* | Everything blocks, 90% compliance, 0.8 confidence, 2% max confidence drop |
| `relaxed` | feature/*, fix/*, chore/* | 70% compliance, 3 outliers allowed, constraints warn, regression skipped |
| `ci-fast` | Any | Only pattern compliance (70%), everything else skipped |

**QualityPolicy Structure**:
```typescript
{
  id: string;
  name: string;
  description: string;
  version: string;
  scope: PolicyScope;           // branches, paths, authors, include/exclude files
  gates: PolicyGateConfigs;     // Per-gate config or 'skip'
  aggregation: AggregationConfig; // mode, requiredGates, weights, minScore
  actions: PolicyActions;       // onPass, onFail, onWarn hooks
  metadata: { createdAt, updatedAt };
}
```

---

### 4. Reporters (`reporters/`)

**Purpose**: Transform QualityGateResult into various output formats.

**Reporter Interface**: `generate(result, options) → string` + `write(report, options) → Promise<void>`

| Reporter | Format | Use Case |
|----------|--------|----------|
| Text | Terminal | Human-readable: status, per-gate summary, top violations, timing |
| JSON | API | Full QualityGateResult serialized — CI pipelines, dashboards |
| SARIF | Compliance | Static Analysis Results Interchange Format — GitHub Code Scanning, VS Code SARIF Viewer |
| GitHub | PR | Markdown PR comment: status badge, score, gate table, expandable violations |
| GitLab | MR | Markdown MR comment: similar to GitHub format |

**ReporterOptions**: outputPath, verbose, includeDetails, maxViolations

**SARIF Mapping**: Gate violations → SARIF results with ruleId, level (error→error, warning→warning, info→note), locations (file+line), message.

---

### 5. Persistence (`store/`)

**SnapshotStore** — Branch-based health snapshots for regression detection.
- Storage: `.drift/quality-gates/snapshots/{branch}/{snapshot-id}.json`
- Branch names sanitized (slashes → dashes)
- Retention: Max 50 snapshots per branch (configurable)
- Methods: save, getLatest, getByCommit, getByBranch

**HealthSnapshot Structure**:
```typescript
{
  id: string;
  timestamp: string;
  branch: string;
  commitSha?: string;
  patterns: PatternHealthSnapshot;     // Per-pattern confidence, compliance, outlier counts
  constraints: ConstraintHealthSnapshot; // Per-constraint pass/fail status
  security: SecurityHealthSnapshot;     // Data access points, sensitive fields
}
```

**GateRunStore** — Run history for trend analysis and auditing.
- Storage: `.drift/quality-gates/history/runs/run-{timestamp}.json`
- Retention: Max 100 runs (configurable)
- Lightweight summaries (not full results) — suitable for trend charts

**GateRunRecord**:
```typescript
{
  id: string;                          // "run-{timestamp}"
  timestamp: string;
  branch: string;
  commitSha?: string;
  policyId: string;
  passed: boolean;
  score: number;
  gates: Record<GateId, { passed: boolean; score: number }>;
  violationCount: number;
  executionTimeMs: number;
  ci: boolean;
}
```

---

### 6. Audit System (`audit/`)

**Purpose**: Pattern validation, deduplication detection, cross-validation, health scoring, and degradation tracking. The feedback loop that tells users "your codebase is drifting."

**AuditEngine** — Core engine running full audits on discovered patterns.

**Audit Pipeline**:
1. Filter patterns by category (optional)
2. Detect duplicates (Jaccard similarity on file:line location sets)
3. Cross-validate patterns (call graph, constraints, test coverage)
4. Generate per-pattern recommendations
5. Calculate health score
6. Build summary

**Duplicate Detection**:
```
similarity = |intersection(locationsA, locationsB)| / |union(locationsA, locationsB)|
```
- Threshold: 0.85 (configurable)
- Only compares patterns in same category
- Recommendation: merge if similarity > 0.9, else review

**Cross-Validation**:
- Orphan patterns: patterns with no locations
- High outlier ratio: outliers > 50% of total (configurable)
- Low confidence approved: approved patterns with confidence < 0.5
- Constraint alignment score: `1 - (issue_count / total_patterns)`

**Recommendation Engine**:
| Recommendation | Criteria |
|---|---|
| `auto-approve` | confidence ≥ 0.90 AND outlierRatio ≤ 0.50 AND locations ≥ 3 AND no error-level issues |
| `review` | confidence ≥ 0.70 (but doesn't meet auto-approve) |
| `likely-false-positive` | confidence < 0.70 OR outlierRatio > 0.50 |
Duplicate group membership downgrades `auto-approve` to `review`.

**Health Score** (0-100, weighted combination):
```
score = (avgConfidence × 0.30 + approvalRatio × 0.20 + complianceRate × 0.20
       + crossValidationRate × 0.15 + duplicateFreeRate × 0.15) × 100
```
- avgConfidence: average pattern confidence
- approvalRatio: approved / total patterns
- complianceRate: locations / (locations + outliers)
- crossValidationRate: patterns in call graph / total
- duplicateFreeRate: 1 - (patterns in duplicate groups / total)

**AuditStore** — Persistence and degradation tracking:
```
.drift/audit/
├── latest.json           # Current audit state
├── snapshots/            # Historical audits (30-day retention)
│   └── YYYY-MM-DD.json
└── degradation.json      # Quality trends
```

**Degradation Tracking** — Compares audits over time:
| Alert | Warning Threshold | Critical Threshold |
|---|---|---|
| Health drop | -5 points | -15 points |
| Confidence drop | -5% | -15% |
| New false positives | > 5 | > 10 |
| Duplicate increase | > 3 groups | — |

**Trends** (7-day rolling average vs previous 7 days):
- Health trend: improving / stable / declining (±2 point threshold)
- Confidence trend: improving / stable / declining (±2% threshold)
- Pattern growth: healthy / rapid (>5/day) / stagnant (<0.5/day)
- History retention: 90 days of daily entries

---

## Key Data Models

### Core Types

```typescript
// Gate IDs
type GateId = 'pattern-compliance' | 'constraint-verification' | 'regression-detection'
            | 'impact-simulation' | 'security-boundary' | 'custom-rules';

// Gate Statuses
type GateStatus = 'passed' | 'failed' | 'warned' | 'skipped' | 'errored';

// Output Formats
type OutputFormat = 'json' | 'text' | 'sarif' | 'github' | 'gitlab';

// Gate Interface
interface Gate {
  readonly id: GateId;
  readonly name: string;
  readonly description: string;
  execute(input: GateInput): Promise<GateResult>;
  validateConfig(config: GateConfig): { valid: boolean; errors: string[] };
  getDefaultConfig(): GateConfig;
}

// GateInput — What each gate receives
interface GateInput {
  files: string[];                    // Files to check
  config: GateConfig;                 // Gate-specific configuration
  context: GateContext;               // Shared context (patterns, constraints, call graph)
  previousSnapshot?: HealthSnapshot;  // For regression detection
}

// GateContext — Shared context loaded by orchestrator
interface GateContext {
  projectRoot: string;
  patterns: Pattern[];
  constraints: Constraint[];
  callGraph?: CallGraph;
  customRules?: CustomRule[];
}

// GateResult — What each gate produces
interface GateResult {
  gateId: GateId;
  gateName: string;
  status: GateStatus;
  passed: boolean;
  score: number;                      // 0-100
  summary: string;
  violations: GateViolation[];
  warnings: string[];
  executionTimeMs: number;
  details: Record<string, unknown>;   // Gate-specific details
  error?: string;
}

// GateViolation — Individual violation
interface GateViolation {
  id: string;                         // "{gateId}-{file}-{line}-{ruleId}"
  gateId: GateId;
  ruleId: string;
  severity: 'error' | 'warning' | 'info' | 'hint';
  message: string;
  file: string;
  line: number;
  column?: number;
  endLine?: number;
  endColumn?: number;
  suggestion?: string;
  details?: Record<string, unknown>;
}

// QualityGateResult — Final aggregated output
interface QualityGateResult {
  passed: boolean;
  status: GateStatus;
  score: number;
  summary: string;
  gates: Record<GateId, GateResult>;
  violations: GateViolation[];
  warnings: string[];
  policy: { id: string; name: string };
  metadata: {
    executionTimeMs: number;
    filesChecked: number;
    gatesRun: GateId[];
    gatesSkipped: GateId[];
    timestamp: string;
    branch: string;
    commitSha?: string;
    ci: boolean;
  };
  exitCode: number;
}
```

### Per-Gate Detail Types

```typescript
// Pattern Compliance
interface PatternComplianceDetails {
  totalPatterns: number;
  checkedPatterns: number;
  complianceRate: number;
  newOutliers: number;
  outlierDetails: OutlierDetail[];
  byCategory: Record<string, { patterns: number; compliance: number }>;
}

// Regression Detection
interface RegressionDetectionDetails {
  baselineSource: string;
  regressions: PatternRegression[];
  improvements: PatternImprovement[];
  categoryDeltas: Record<string, number>;
  overallDelta: number;
}
interface PatternRegression {
  patternId: string; patternName: string; category: string;
  previousConfidence: number; currentConfidence: number; confidenceDelta: number;
  previousCompliance: number; currentCompliance: number; complianceDelta: number;
  newOutliers: number; severity: 'critical' | 'high' | 'medium' | 'low';
}

// Impact Simulation
interface ImpactSimulationDetails {
  filesAffected: number; functionsAffected: number; entryPointsAffected: number;
  sensitiveDataPaths: SensitiveDataPath[]; frictionScore: number;
  breakingRisk: 'critical' | 'high' | 'medium' | 'low'; affectedFiles: AffectedFile[];
}

// Security Boundary
interface SecurityBoundaryDetails {
  dataAccessPoints: DataAccessPoint[]; unauthorizedPaths: UnauthorizedPath[];
  newSensitiveAccess: number; protectedTablesAccessed: string[]; authCoverage: number;
}

// Custom Rules
interface CustomRulesDetails {
  totalRules: number; rulesEvaluated: number;
  rulesPassed: number; rulesFailed: number; results: RuleResult[];
}
```

### Custom Rule Condition Types
```typescript
type RuleCondition =
  | FilePatternCondition      // Glob matching on file paths
  | ContentPatternCondition   // Regex matching on file content
  | DependencyCondition       // Package dependency checks
  | NamingCondition           // Naming convention enforcement
  | StructureCondition        // Directory structure requirements
  | CompositeCondition;       // AND/OR/NOT combinations
```

### Audit Types
```typescript
interface AuditConfig {
  autoApproveThreshold: 0.90;
  reviewThreshold: 0.70;
  duplicateSimilarityThreshold: 0.85;
  minLocationsForEstablished: 3;
  maxOutlierRatio: 0.5;
}

interface HealthScore {
  score: number;                // 0-100
  avgConfidence: number;
  approvalRatio: number;
  complianceRate: number;
  crossValidationRate: number;
  duplicateFreeRate: number;
}

interface DegradationAlert {
  type: 'health_drop' | 'confidence_drop' | 'false_positives' | 'duplicate_increase';
  severity: 'warning' | 'critical';
  threshold: number;
  actual: number;
}
```

---

## Key Algorithms

### 1. Gate Scoring (O(v) per gate, where v = violation count)
```
penalty = Σ(error_violations × 10) + Σ(warning_violations × 3) + Σ(info_violations × 1)
score = max(0, 100 - (penalty / maxPenalty) × 100)
```
Status: score < threshold → failed; score < threshold + margin → warned; else → passed

### 2. Pattern Compliance Rate (O(p) where p = patterns)
```
per_pattern_compliance = locations / (locations + outliers)
overall_compliance = Σ(per_pattern_compliance) / pattern_count
```

### 3. Regression Severity Classification (O(p) where p = patterns)
```
For each pattern:
  confidenceDelta = current.confidence - baseline.confidence
  complianceDelta = current.compliance - baseline.compliance
  
  if confidenceDelta > 2× threshold OR category in criticalCategories → Critical
  elif confidenceDelta > threshold → High
  elif complianceDelta > threshold → Medium
  elif newOutliers > threshold → Low
```

### 4. Friction Score (O(f × d) where f = functions, d = call depth)
```
frictionScore = (filesAffected/maxFiles × 25) + (functionsAffected/maxFunctions × 25)
              + (entryPointsAffected/maxEntryPoints × 30) + (sensitiveDataPaths × 20)
breakingRisk = critical (>80) | high (>60) | medium (>40) | low
```

### 5. Security Boundary Check (O(a × d) where a = access points, d = call depth)
```
For each data access point in changed files:
  if table in protectedTables:
    Walk callers up call graph (max depth = maxDataFlowDepth)
    if no function matches requiredAuthPatterns → unauthorized path
    if access not in previous snapshot → new sensitive access
```

### 6. Policy Aggregation (O(g) where g = gates)
```
Mode 'any':     any gate.status === 'failed' → overall failed
Mode 'all':     any gate.passed → overall passed
Mode 'weighted': score = Σ(gate.score × weight) / Σ(weight); passed = score >= minScore
Mode 'threshold': score = avg(gate.scores); passed = score >= minScore
Required gates always block regardless of mode.
```

### 7. Health Score (O(p) where p = patterns)
```
score = (avgConfidence × 0.30 + approvalRatio × 0.20 + complianceRate × 0.20
       + crossValidationRate × 0.15 + duplicateFreeRate × 0.15) × 100
```

### 8. Duplicate Detection (O(p² × l) where p = patterns per category, l = locations)
```
For each pair of patterns in same category:
  jaccard = |intersection(locationsA, locationsB)| / |union(locationsA, locationsB)|
  if jaccard > 0.85 → duplicate group
  if jaccard > 0.90 → recommend merge
  else → recommend review
```

### 9. Degradation Tracking (O(h) where h = history entries)
```
7-day rolling average vs previous 7-day rolling average:
  healthDelta = current7dayAvg - previous7dayAvg
  if healthDelta < -15 → critical alert
  elif healthDelta < -5 → warning alert
  
  trend = improving (delta > +2) | stable (|delta| ≤ 2) | declining (delta < -2)
```

---

## Capabilities

### What It Can Do Today

1. **6 Specialized Gates**: Pattern compliance, constraint verification, regression detection, impact simulation, security boundary, custom rules — each independently configurable
2. **Configurable Policy Engine**: 4 built-in policies with context-aware selection (branch, path, author matching)
3. **4 Aggregation Modes**: any, all, weighted, threshold — covering all common CI patterns
4. **5 Output Formats**: Text, JSON, SARIF, GitHub PR, GitLab MR — enterprise CI integration
5. **Fail-Safe Design**: Errored gates don't block — prevents infrastructure failures from blocking deployments
6. **Parallel Execution**: All gates run concurrently
7. **Snapshot-Based Regression**: Branch-based health snapshots enable regression detection across time
8. **Lazy Context Loading**: Only loads data that active gates need (patterns, constraints, call graph)
9. **Custom Gate Registration**: Extensible via `registry.register()` for user-defined gates
10. **License Gating**: Enterprise features gated by tier (Community, Team, Enterprise)
11. **Audit System**: Pattern validation, duplicate detection, cross-validation, health scoring
12. **Degradation Tracking**: 90-day history with 7-day rolling averages, automated alerts
13. **Auto-Approve Recommendations**: Patterns meeting quality thresholds recommended for auto-approval
14. **MCP Integration**: Exposed via `drift_quality_gate` tool for AI-assisted quality checks
15. **CLI Integration**: `drift gate run` with full option set

### Limitations

1. **File-Based Persistence**: Snapshots and run history stored as JSON files — won't scale for enterprise with thousands of runs
2. **No Gate Dependencies**: ParallelExecutor runs all gates in one group — no dependency graph for gate ordering
3. **No Incremental Gate Execution**: All enabled gates run every time — no skipping gates whose inputs haven't changed
4. **No Caching**: Gate results not cached — same files re-analyzed on every run
5. **No Partial Failure Recovery**: If orchestrator crashes mid-run, no checkpoint/resume
6. **No Multi-Repo Support**: Quality gates operate on a single project — no cross-repo policy enforcement
7. **No Policy Inheritance**: Custom policies can't extend built-in policies with overrides
8. **JSON-Only Custom Policies**: No YAML support for custom policy definitions
9. **No Policy Versioning**: No migration path when policy schema changes
10. **No Gate Timeout**: Individual gates have no timeout — a slow gate blocks the entire pipeline
11. **No Violation Deduplication Across Gates**: Same file/line can produce violations from multiple gates
12. **No Historical Trend Visualization**: Run history stored but no built-in trend analysis beyond degradation alerts
13. **No Webhook/Notification Support**: No way to trigger external notifications on gate pass/fail
14. **No Dry-Run Mode**: Can't preview what gates would check without actually running them
15. **No Gate Priority/Ordering**: Can't specify "run security first, skip rest if it fails"
16. **Audit Duplicate Detection is O(p²)**: Quadratic complexity for patterns in same category — slow for large pattern sets
17. **No Custom Reporter Plugin System**: Can't add new output formats without modifying source
18. **Security Boundary Gate is Heuristic**: Auth detection via function name matching — no actual auth flow analysis
19. **Custom Rules Limited to 6 Condition Types**: No AST-based conditions, no call-graph-based conditions
20. **No Baseline Management UI**: Snapshots managed automatically — no way to manually set/reset baselines

---

## Integration Points

| Connects To | Direction | How |
|-------------|-----------|-----|
| **03-detectors** | Consumes | Patterns (the central entity) — compliance checking, regression baselines |
| **04-call-graph** | Consumes | Call graph for impact simulation and security boundary analysis |
| **05-analyzers** | Consumes | Rules engine for pattern evaluation; constraint verifier |
| **18-constraints** | Consumes | Architectural constraints for constraint verification gate |
| **21-security** | Consumes | Security boundary data, sensitive field detection |
| **08-storage** | Consumes | Pattern storage, constraint storage, call graph storage |
| **10-cli** | Consumed by | `drift gate run` command wraps orchestrator |
| **12-infrastructure** | Consumed by | CI/CD pipelines consume gate results |
| **07-mcp** | Consumed by | `drift_quality_gate` MCP tool exposes gate functionality |
| **11-ide** | Consumed by | VSCode extension shows gate results in editor |

### Critical Dependency Chain
```
03-detectors → patterns → 09-quality-gates (pattern compliance, regression)
04-call-graph → reachability → 09-quality-gates (impact simulation, security boundary)
18-constraints → constraints → 09-quality-gates (constraint verification)
21-security → boundaries → 09-quality-gates (security boundary)
09-quality-gates → violations → 10-cli, 12-infrastructure, 07-mcp, 11-ide
```

Quality gates is a **pure consumer** of upstream analysis and a **pure producer** of enforcement decisions. Any change to pattern schema, call graph API, constraint format, or security boundary data has direct impact on gate implementations.

---

## V2 Migration Status

### Current State: 100% TypeScript

```
TypeScript (~30 files)
├── Orchestrator (pipeline coordination)
├── 6 Gate implementations
├── Policy engine (4 built-in + custom)
├── 5 Reporters
├── 2 Stores (snapshots + run history)
├── Audit engine + audit store
└── ~1300 lines of types
```

### What Should Move to Rust

| Component | Rationale | Priority |
|-----------|-----------|----------|
| Pattern compliance analysis | Hot path — iterates all patterns × files | P1 |
| Security boundary traversal | Call graph walking is performance-critical | P1 |
| Impact simulation traversal | Call graph reachability is performance-critical | P1 |
| Duplicate detection (audit) | O(p²) Jaccard similarity — benefits from Rust perf | P2 |
| Health score calculation | Pure math — trivial port | P2 |

### What Stays in TypeScript

| Component | Rationale |
|-----------|-----------|
| GateOrchestrator | Pure coordination logic |
| PolicyLoader/Evaluator | Configuration logic |
| All Reporters | Output formatting |
| SnapshotStore/GateRunStore | File I/O |
| AuditStore | File I/O |
| Custom Rules evaluator | Regex/glob — could go either way |
| GateRegistry | Registration/instantiation |
| ResultAggregator | Simple aggregation |

### Architectural Decisions Pending

1. **Gate dependency graph**: Should gates declare dependencies for ordered execution?
2. **Incremental gates**: How to skip gates whose inputs haven't changed?
3. **Storage migration**: Should snapshots/history move from JSON files to SQLite?
4. **Policy inheritance**: Should custom policies extend built-in policies?
5. **Gate timeout**: Should individual gates have configurable timeouts?
6. **Multi-repo**: How should quality gates work across multiple repositories?
7. **Baseline management**: Should users be able to manually set/reset regression baselines?

---

## Open Questions

1. **Gate dependencies**: Should regression-detection depend on pattern-compliance results? Should security-boundary depend on impact-simulation?
2. **Incremental execution**: Can we hash gate inputs and skip gates whose inputs haven't changed since last run?
3. **Storage scalability**: At what point should JSON file storage migrate to SQLite for snapshots and run history?
4. **Policy YAML**: Should custom policies support YAML in addition to JSON?
5. **Custom reporters**: Should there be a plugin system for adding output formats?
6. **Gate timeouts**: What's a reasonable default timeout per gate? Should it be configurable?
7. **Violation deduplication**: Should violations from multiple gates for the same file/line be deduplicated?
8. **Webhook integration**: Should quality gates support webhook notifications for pass/fail events?
9. **Dry-run mode**: Should there be a way to preview gate execution without actually running?
10. **AST-based custom rules**: Should custom rules support tree-sitter query conditions?
11. **Call-graph-based custom rules**: Should custom rules support "function X must not call function Y" conditions?
12. **Audit health score weights**: Are the current weights (0.30/0.20/0.20/0.15/0.15) optimal?

---

## Quality Checklist

- [x] All 8 files in 09-quality-gates/ have been read (overview, gates, orchestrator, policy, reporters, store, types, audit)
- [x] Architecture clearly described with diagram
- [x] All 6 gates documented with algorithms and configs
- [x] All 9 key algorithms documented with complexity analysis
- [x] All data models listed with field descriptions (40+ interfaces)
- [x] Policy engine fully documented (4 modes, 4 built-in policies, context matching)
- [x] Audit system fully documented (duplicate detection, cross-validation, health scoring, degradation)
- [x] 20 limitations honestly assessed
- [x] 10 integration points mapped to other categories
- [x] V2 migration status documented with Rust/TS split rationale
- [x] 12 open questions identified
- [x] Critical dependency chain documented
