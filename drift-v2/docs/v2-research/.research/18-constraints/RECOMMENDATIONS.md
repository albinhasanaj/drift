# 18 Constraints — V2 Recommendations

> Enterprise-grade recommendations for rebuilding Drift's constraint system from the ground up. Every recommendation is backed by cited evidence from the research phase, prioritized for implementation, and assessed for cross-category impact.

---

## Summary

The v1 constraint system has the right conceptual foundation — learned invariants, confidence scoring, lifecycle management, change-aware verification — but the implementation has critical gaps that prevent enterprise adoption. The v2 rebuild should focus on 5 strategic pillars:

1. **AST-based verification in Rust** — Replace regex-based code element extraction with Rust parser AST, eliminating duplicate work and enabling accurate structural verification
2. **Declarative constraint format** — TOML/YAML constraint definitions that are version-controlled, human-readable, and shareable across projects
3. **Baseline management (FreezingArchRule)** — Enable incremental adoption on legacy codebases by freezing existing violations
4. **Developer feedback loop** — Track false positives per constraint, auto-adjust confidence, auto-disable noisy constraints
5. **Constraint conflict resolution** — Specificity-based precedence, contradiction detection, and inheritance model

These 5 pillars address the top barriers to enterprise adoption identified in the research: accuracy (pillar 1), usability (pillar 2), legacy compatibility (pillar 3), trust (pillar 4), and scalability (pillar 5).

---

## Recommendations

### R1: AST-Based Constraint Verification in Rust

**Priority**: P0 (Critical — blocks accurate verification)
**Effort**: High
**Impact**: Verification accuracy improves from ~70% (regex) to ~98% (AST), verification speed improves 10-50x

**Current State**:
The ConstraintVerifier extracts code elements (functions, classes, entry points, imports) using language-specific regex patterns. This duplicates work already done by the Rust parser, misses complex patterns (nested functions, arrow functions, destructured exports), and cannot verify structural properties (AST containment, call ordering).

**Proposed Change**:
Verification should operate on the Rust parser's ParseResult directly. Each constraint predicate type maps to a specific verification strategy:

```
Predicate Type → Verification Strategy → Data Source
─────────────────────────────────────────────────────
Function       → ParseResult.functions   → Rust parser
Class          → ParseResult.classes     → Rust parser
Entry Point    → ParseResult.functions + decorators → Rust parser
Naming         → ParseResult.* names     → Rust parser
File Structure → Filesystem check        → Rust scanner
must_precede   → Call graph path query   → Rust call graph
must_follow    → Call graph path query   → Rust call graph
data_flow      → Taint analysis          → Rust data flow (new)
must_wrap      → AST containment check   → Rust parser AST
must_colocate  → File path comparison    → Rust scanner
must_separate  → File path comparison    → Rust scanner
cardinality    → Count query on AST      → Rust parser
```

**Rationale**:
The verifier currently cannot verify 4 of 12 invariant types (must_precede, must_follow, data_flow, must_wrap) because it lacks access to call graph and AST structure. Moving to Rust parser output enables all 12 types.

**Evidence**:
- §1.1 (ArchUnit): Operates on compiled bytecode (structured representation), not source text
- §9.1 (Semgrep): Operates on ast_generic (unified AST), not regex
- §9.2 (YASA): Unified AST enables language-agnostic analysis at 100M+ lines scale
- §3.1 (Semgrep rules): Pattern matching against AST is more accurate than regex

**Implementation Notes**:
- Create `ConstraintVerifierRust` in `crates/drift-core/src/constraints/`
- Accept `ParseResult` + `Constraint[]` as input, return `VerificationResult`
- Expose via NAPI: `verify_constraints(parse_result, constraints) -> VerificationResult`
- For call graph predicates (must_precede, must_follow), accept `CallGraphDb` handle
- For data flow predicates, integrate with the taint analysis engine (when available)

**Risks**:
- Tight coupling between constraints and parser output format — mitigate with stable ParseResult interface
- Call graph predicates require call graph to be built first — verification order dependency
- Data flow predicates depend on taint analysis (not yet implemented) — implement as "skip" until available

**Dependencies**:
- 02-parsers: ParseResult must include all fields needed for predicate evaluation
- 04-call-graph: Call graph must be queryable for path analysis
- 01-rust-core: NAPI bridge must support constraint verification function

---

### R2: Declarative Constraint Format (TOML/YAML)

**Priority**: P0 (Critical — enables version control, sharing, and user-defined constraints)
**Effort**: Medium
**Impact**: Constraints become first-class project artifacts, shareable across teams and projects

**Current State**:
Constraints are stored as internal JSON in `.drift/constraints/`. They are machine-generated, not human-readable, and cannot be manually authored or version-controlled meaningfully. The `custom` status exists but there's no user-facing format for defining custom constraints.

**Proposed Change**:
Introduce a TOML-based constraint definition format (`.drift/constraints.toml` or `drift-constraints.toml` at project root) that supports both auto-discovered and user-defined constraints:

```toml
# drift-constraints.toml — Version-controlled architectural constraints

[settings]
auto_approve_threshold = 0.95
enforcement_default = "warning"
baseline_file = ".drift/constraint-baselines.json"

# User-defined constraint
[[constraints]]
id = "auth-before-data"
name = "Authentication must precede data access"
category = "security"
type = "must_precede"
language = "all"
enforcement = "error"
description = "All API endpoints must verify authentication before accessing data stores"

[constraints.scope]
files = ["src/api/**/*", "src/controllers/**/*"]
entry_points = true

[constraints.predicate]
before = { decorators = ["@Auth", "@Authenticated", "@RequiresAuth"] }
after = { calls = ["*.repository.*", "*.service.find*", "*.service.get*", "db.*"] }

[constraints.rationale]
text = "Unauthenticated data access is a critical security vulnerability (OWASP A01)"
adr = "docs/adr/003-auth-middleware.md"

# Layer dependency constraint
[[constraints]]
id = "layer-separation"
name = "Controllers must not access repositories directly"
category = "structural"
type = "must_not_have"
language = "all"
enforcement = "error"

[constraints.scope]
files = ["src/controllers/**/*"]

[constraints.predicate]
imports = { pattern = "**/repositories/**" }

# Naming convention constraint
[[constraints]]
id = "service-naming"
name = "Service classes must end with 'Service'"
category = "structural"
type = "naming"
language = "all"
enforcement = "warning"

[constraints.scope]
directories = ["src/services/"]

[constraints.predicate]
classes = { pattern = "*Service" }
```

**Rationale**:
- SonarQube's Architecture as Code (§1.3) validates YAML/JSON for constraint specification at enterprise scale
- Semgrep's YAML rules (§3.1) prove that declarative constraint formats are more accessible than programmatic APIs
- OPA's policy-as-code principle (§6.1) establishes that policies should be data, not code — loadable, updatable, and versionable independently
- Version-controlled constraints enable code review of architectural decisions, audit trails, and cross-project sharing

**Evidence**:
- §1.3 (SonarQube): YAML/JSON architecture files, version-controlled alongside code
- §3.1 (Semgrep): YAML rules with paths, patterns, and fix suggestions
- §6.1 (OPA): Policies as data, template/instance pattern
- §3.2 (Dicto): Near-natural-language constraint specification

**Implementation Notes**:
- Parse TOML at startup, merge with auto-discovered constraints from InvariantDetector
- User-defined constraints always take precedence over auto-discovered ones (specificity rule)
- Support `include` directives for splitting large constraint files: `include = ["constraints/security.toml"]`
- Validate constraint definitions at parse time — report errors with line numbers
- TOML chosen over YAML for: (1) No indentation sensitivity, (2) Better type safety, (3) Rust ecosystem support (toml crate)

**Risks**:
- Format migration — existing JSON constraints need a migration path
- Complexity — TOML can become verbose for complex predicates. Mitigate with constraint templates.
- Learning curve — users need to learn the constraint schema. Mitigate with `drift constraints init` scaffolding command.

**Dependencies**:
- 10-cli: `drift constraints init` command to scaffold constraint files
- 07-mcp: MCP tools should expose constraint definitions for AI agents to read/suggest
- 12-infrastructure: TOML parsing in Rust (toml crate, already in ecosystem)

---

### R3: Baseline Management (FreezingArchRule Pattern)

**Priority**: P0 (Critical — enables adoption on legacy codebases)
**Effort**: Medium
**Impact**: Removes the #1 barrier to constraint adoption on existing projects

**Current State**:
When a constraint is approved, ALL existing violations are immediately reported. On a legacy codebase with hundreds of violations, this makes constraint adoption impractical — CI/CD would fail on every build.

**Proposed Change**:
Implement a baseline system inspired by ArchUnit's FreezingArchRule:

1. When a constraint is first approved, snapshot all current violations as the baseline
2. On subsequent verifications, only report violations NOT in the baseline (new violations)
3. When a baseline violation is fixed, remove it from the baseline (ratchet effect — can never regress)
4. Store baselines in `.drift/constraint-baselines.json` (version-controlled)
5. Provide CLI commands: `drift constraints baseline create`, `drift constraints baseline update`, `drift constraints baseline diff`

```
Baseline Flow:
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│ Approve       │────▶│ Snapshot      │────▶│ Store         │
│ Constraint    │     │ Violations    │     │ Baseline      │
└──────────────┘     └──────────────┘     └──────┬───────┘
                                                  │
┌──────────────┐     ┌──────────────┐     ┌──────▼───────┐
│ Report ONLY   │◀────│ Filter Out    │◀────│ Verify       │
│ New Violations│     │ Baseline      │     │ Code Change  │
└──────────────┘     └──────────────┘     └──────────────┘
                                                  │
                     ┌──────────────┐     ┌──────▼───────┐
                     │ Remove Fixed  │◀────│ Detect Fixed │
                     │ From Baseline │     │ Violations   │
                     └──────────────┘     └──────────────┘
```

**Rationale**:
ArchUnit's FreezingArchRule is the single most important pattern for enterprise constraint adoption. Without baseline management, teams cannot introduce constraints on existing codebases without fixing all violations first — which is impractical for large projects.

**Evidence**:
- §8.2 (ArchUnit FreezingArchRule): Records existing violations as baseline, only fails on new violations, ratchet effect prevents regression
- §2.1 (Architecture erosion survey): "Architecture erosion is inevitable in long-lived systems. The goal is not to prevent all erosion but to detect it early and manage it systematically."
- §5.1 (Evolutionary architecture): "Start with the most important characteristics and add fitness functions incrementally."

**Implementation Notes**:
- Baseline format: `{ constraintId: string, violations: { file: string, line: number, hash: string }[] }`
- Use content hash of violation context (surrounding lines) for stable identification across line number changes
- Baseline update should be atomic — either all changes apply or none
- CLI: `drift constraints baseline create` — snapshot current violations for all approved constraints
- CLI: `drift constraints baseline update` — remove fixed violations (ratchet)
- CLI: `drift constraints baseline diff` — show what's changed since baseline
- Quality gate integration: baseline-aware verification returns only new violations

**Risks**:
- Baseline staleness — if code is refactored significantly, baseline violations may no longer match. Mitigate with content-hash-based matching.
- Baseline gaming — developers could add violations to the baseline to avoid fixing them. Mitigate with baseline review in code review process.
- Storage growth — baselines grow with constraint count. Mitigate with periodic baseline compaction.

**Dependencies**:
- 09-quality-gates: Constraint verification gate must be baseline-aware
- 10-cli: New baseline management commands
- 08-storage: Baseline storage (JSON file or SQLite table)

---

### R4: Developer Feedback Loop

**Priority**: P1 (Important — drives constraint quality and trust)
**Effort**: Medium
**Impact**: Enables <5% effective false-positive rate, auto-refinement of constraints

**Current State**:
No mechanism for developers to provide feedback on constraint violations. No tracking of false positives. No auto-adjustment of constraint confidence based on developer actions.

**Proposed Change**:
Implement a feedback system inspired by Google's Tricorder:

1. Every constraint violation includes a "dismiss" action with reason categories: `false_positive`, `wont_fix`, `not_applicable`, `already_fixed`
2. Feedback is stored per-constraint and aggregated into an effective false-positive rate
3. Constraints with >10% effective false-positive rate are automatically demoted from `error` to `warning`
4. Constraints with >25% effective false-positive rate are flagged for review
5. Feedback feeds back into constraint confidence: `adjusted_confidence = base_confidence × (1 - false_positive_rate)`

```
Feedback Flow:
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│ Violation     │────▶│ Developer     │────▶│ Store         │
│ Reported      │     │ Action        │     │ Feedback      │
└──────────────┘     └──────────────┘     └──────┬───────┘
                                                  │
┌──────────────┐     ┌──────────────┐     ┌──────▼───────┐
│ Auto-Demote   │◀────│ Calculate     │◀────│ Aggregate    │
│ if FP > 10%   │     │ FP Rate       │     │ Per-Constraint│
└──────────────┘     └──────────────┘     └──────────────┘
```

**Rationale**:
Google's Tricorder maintains <5% effective false-positive rate through developer feedback. Without feedback, constraint quality degrades over time as codebases evolve, leading to "alert fatigue" and eventual abandonment of the constraint system.

**Evidence**:
- §10.2 (Tricorder): <5% effective FP rate via "Not useful" button, high FP rates → analyzer disabled
- §2.2 (Erosion prevention): "Tools that only report violations without explaining WHY see low adoption"
- §5.1 (Fitness functions): Graduated scoring (0-100) is more useful than binary pass/fail

**Implementation Notes**:
- Feedback storage: SQLite table `constraint_feedback` (constraint_id, file, line, action, reason, timestamp, user)
- Effective FP rate: `dismissals / (dismissals + fixes)` over rolling 30-day window
- Auto-demotion thresholds: configurable in `drift-constraints.toml` settings
- CLI: `drift constraints feedback <constraint-id> <action> [reason]`
- MCP: `drift_constraint_feedback` tool for AI agents to report false positives
- IDE: Inline action on violation diagnostics (dismiss with reason)
- Cortex integration: feedback stored as `feedback` memories for learning

**Risks**:
- Feedback gaming — developers dismiss valid violations to avoid fixing them. Mitigate with team-level (not user-level) feedback aggregation.
- Cold start — new constraints have no feedback data. Use confidence score as initial proxy.
- Feedback volume — high-violation constraints generate lots of feedback. Aggregate efficiently.

**Dependencies**:
- 08-storage: Feedback table in drift.db
- 06-cortex: Feedback as learning signals
- 07-mcp: Feedback tool for AI agents
- 11-ide: Inline dismiss actions

---

### R5: Constraint Conflict Resolution & Inheritance

**Priority**: P1 (Important — prevents contradictory constraints)
**Effort**: Medium
**Impact**: Enables hierarchical constraint management, prevents logical contradictions

**Current State**:
No conflict detection. Contradictory constraints can coexist (e.g., "must_have auth" and "must_not_have auth" for overlapping scopes). No inheritance model — constraints cannot be defined at package level and inherited by sub-packages.

**Proposed Change**:
Implement a specificity-based conflict resolution model with inheritance:

**Specificity Calculation**:
```
specificity = scope_score + status_score + confidence_score

scope_score:
  file-specific (exact path)     = 100
  directory-specific (glob)      = 50
  project-wide (no scope)        = 10

status_score:
  custom (user-defined)          = 30
  approved (user-approved)       = 20
  discovered (auto-detected)     = 10

confidence_score:
  confidence × 10                = 0-10
```

**Conflict Detection**:
1. Pairwise comparison of constraints with overlapping scopes
2. Two constraints conflict if: same scope overlap + opposite invariant types (must_have vs must_not_have for same property)
3. Ordering constraint cycles detected via Tarjan's SCC on constraint dependency graph
4. Conflicts flagged with resolution suggestion (higher specificity wins)

**Inheritance Model**:
```
project-root/
├── drift-constraints.toml          # Project-level constraints (inherited by all)
├── src/
│   ├── api/
│   │   └── drift-constraints.toml  # API-specific constraints (override project)
│   └── services/
│       └── drift-constraints.toml  # Service-specific constraints (override project)
```

- Child constraints inherit parent constraints
- Child constraints can override parent constraints (higher specificity)
- Child constraints can add new constraints
- Child constraints CANNOT remove parent constraints (only override enforcement level)

**Evidence**:
- §7.1 (CSS specificity): Well-understood precedence model, familiar to developers
- §7.2 (Contradiction detection): Pairwise comparison + cycle detection for ordering constraints
- §1.3 (SonarQube): Hierarchical groups with nested perspectives
- §1.4 (Sonargraph): Strict/relaxed layering with transitive dependencies
- §6.1 (OPA): Template/instance pattern with hierarchical policy evaluation

**Implementation Notes**:
- Conflict detection runs at constraint load time (startup), not verification time
- Conflicts are reported as warnings, not errors — the system still functions with conflicts
- Specificity calculation is deterministic — same constraints always resolve the same way
- Inheritance resolution: walk up directory tree, merge constraint files, apply specificity
- Store resolved constraint set in memory for fast verification

**Risks**:
- Complexity — inheritance + specificity can be hard to debug. Mitigate with `drift constraints explain <constraint-id>` command showing resolution chain.
- Performance — pairwise conflict detection is O(N²). Mitigate with scope-based partitioning.
- Unexpected overrides — child constraints silently overriding parent constraints. Mitigate with explicit override syntax.

**Dependencies**:
- 10-cli: `drift constraints explain` command
- 08-storage: Resolved constraint cache

---

### R6: Migrate Constraint Storage to SQLite

**Priority**: P1 (Important — enables indexing, transactions, concurrent access)
**Effort**: Medium
**Impact**: Eliminates file-based storage limitations, enables efficient querying

**Current State**:
Constraints stored as JSON files in `.drift/constraints/`. No ACID transactions, no concurrent access safety, linear scan for ID lookups (O(N)), no indexes on status/language/confidence, no versioning.

**Proposed Change**:
Migrate constraint storage to SQLite (drift.db), with the following schema:

```sql
-- Core constraint table
CREATE TABLE constraints (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  category TEXT NOT NULL,
  invariant_type TEXT NOT NULL,
  predicate_json TEXT NOT NULL,
  scope_json TEXT NOT NULL,
  confidence REAL NOT NULL DEFAULT 0.0,
  conforming_count INTEGER NOT NULL DEFAULT 0,
  violating_count INTEGER NOT NULL DEFAULT 0,
  enforcement_level TEXT NOT NULL DEFAULT 'warning',
  status TEXT NOT NULL DEFAULT 'discovered',
  language TEXT NOT NULL DEFAULT 'all',
  source_type TEXT NOT NULL,
  source_ids_json TEXT,
  evidence_json TEXT,
  rationale TEXT,
  adr_link TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  last_verified TEXT,
  approved_by TEXT,
  approved_at TEXT,
  version INTEGER NOT NULL DEFAULT 1
);

-- Indexes for common queries
CREATE INDEX idx_constraints_category ON constraints(category);
CREATE INDEX idx_constraints_status ON constraints(status);
CREATE INDEX idx_constraints_language ON constraints(language);
CREATE INDEX idx_constraints_confidence ON constraints(confidence);
CREATE INDEX idx_constraints_enforcement ON constraints(enforcement_level);

-- Constraint version history
CREATE TABLE constraint_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  constraint_id TEXT NOT NULL REFERENCES constraints(id),
  version INTEGER NOT NULL,
  change_type TEXT NOT NULL, -- 'created', 'updated', 'approved', 'ignored', 'deleted'
  old_values_json TEXT,
  new_values_json TEXT,
  changed_at TEXT NOT NULL,
  changed_by TEXT
);

-- Violation baselines
CREATE TABLE constraint_baselines (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  constraint_id TEXT NOT NULL REFERENCES constraints(id),
  file TEXT NOT NULL,
  line INTEGER NOT NULL,
  context_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  fixed_at TEXT,
  UNIQUE(constraint_id, file, context_hash)
);

-- Developer feedback
CREATE TABLE constraint_feedback (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  constraint_id TEXT NOT NULL REFERENCES constraints(id),
  file TEXT NOT NULL,
  line INTEGER NOT NULL,
  action TEXT NOT NULL, -- 'false_positive', 'wont_fix', 'not_applicable', 'fixed'
  reason TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX idx_feedback_constraint ON constraint_feedback(constraint_id);

-- Scope index for fast file-to-constraint lookup
CREATE TABLE constraint_scope_index (
  constraint_id TEXT NOT NULL REFERENCES constraints(id),
  scope_pattern TEXT NOT NULL,
  scope_type TEXT NOT NULL, -- 'file', 'directory', 'function', 'class'
  PRIMARY KEY(constraint_id, scope_pattern)
);

CREATE INDEX idx_scope_pattern ON constraint_scope_index(scope_pattern);
```

**Rationale**:
File-based JSON storage doesn't scale for enterprise codebases with thousands of constraints. SQLite provides ACID transactions, concurrent read access (WAL mode), efficient indexing, and versioning — all missing from the current implementation.

**Evidence**:
- §8.1 (Master Research, SQLite WAL): WAL mode enables concurrent reads during writes
- §1.1 (ArchUnit): FreezingArchRule uses pluggable violation stores — SQLite is a natural backend
- §6.1 (OPA): Decision logging requires structured storage for audit trails

**Implementation Notes**:
- Tables added to drift.db (not a separate database)
- Migration from JSON: one-time import script reads `.drift/constraints/` and inserts into SQLite
- TOML-defined constraints (R2) are the source of truth for user-defined constraints; SQLite stores the merged/resolved set
- Version history enables "what changed" queries for audit and debugging
- Scope index enables O(1) lookup of constraints applicable to a file path

**Risks**:
- Migration complexity — existing JSON constraints must be preserved during migration
- Schema evolution — constraint schema may change; use versioned migrations
- Dual source of truth — TOML files + SQLite. Resolution: TOML is authoritative for user-defined, SQLite is authoritative for discovered.

**Dependencies**:
- 08-storage: Schema additions to drift.db
- 01-rust-core: Rust-side constraint queries via rusqlite

---

### R7: Constraint Templates for Reusable Patterns

**Priority**: P1 (Important — reduces boilerplate, enables sharing)
**Effort**: Medium
**Impact**: Common constraint patterns become one-liners, shareable across projects

**Current State**:
Every constraint is fully specified with all fields. Common patterns (layer separation, naming conventions, auth requirements) must be written from scratch each time.

**Proposed Change**:
Introduce constraint templates — parameterized constraint definitions that can be instantiated with project-specific values:

```toml
# Built-in templates (shipped with Drift)
# Usage in drift-constraints.toml:

[[constraints]]
template = "layer-separation"
params.upper_layer = "controllers"
params.lower_layer = "repositories"
enforcement = "error"

[[constraints]]
template = "naming-convention"
params.directory = "src/services/"
params.suffix = "Service"
params.target = "classes"
enforcement = "warning"

[[constraints]]
template = "auth-before-access"
params.auth_decorators = ["@Auth", "@Authenticated"]
params.data_patterns = ["*.repository.*", "db.*"]
enforcement = "error"

[[constraints]]
template = "test-coverage"
params.source_dir = "src/"
params.test_dir = "tests/"
params.min_coverage = 0.8
enforcement = "warning"
```

**Built-in Templates** (shipped with Drift v2):

| Template | Category | Invariant Type | Parameters |
|----------|----------|---------------|------------|
| `layer-separation` | structural | must_not_have | upper_layer, lower_layer |
| `naming-convention` | structural | naming | directory, suffix/prefix, target |
| `auth-before-access` | security | must_precede | auth_decorators, data_patterns |
| `test-coverage` | test | must_have | source_dir, test_dir, min_coverage |
| `error-handling` | error | must_wrap | target_patterns, wrapper (try/catch) |
| `no-direct-db` | data | must_not_have | controller_dir, db_patterns |
| `input-validation` | validation | must_precede | validation_patterns, handler_patterns |
| `logging-required` | logging | must_have | target_functions, log_patterns |
| `no-circular-deps` | structural | must_not_have | (auto-detected from module graph) |
| `api-response-format` | api | must_have | endpoint_patterns, response_type |

**Evidence**:
- §6.1 (OPA): Constraint templates define schema and logic, constraints instantiate with parameters
- §3.2 (Dicto): Rule templates provide extensibility without changing core language
- §1.3 (SonarQube): Perspectives and groups provide reusable architectural patterns

**Implementation Notes**:
- Templates stored as TOML files in `crates/drift-core/src/constraints/templates/`
- Template resolution at startup: expand template + params → full Constraint object
- Custom templates: users can define templates in `.drift/constraint-templates/`
- Template validation: check that all required params are provided, types match
- Template versioning: templates have version numbers, constraint files reference template version

**Risks**:
- Template proliferation — too many templates become hard to discover. Mitigate with `drift constraints templates list`.
- Template versioning — template changes can break existing constraint files. Mitigate with semantic versioning.
- Over-abstraction — templates that are too generic lose specificity. Keep templates focused on common patterns.

**Dependencies**:
- 10-cli: `drift constraints templates list/show` commands
- 07-mcp: Template discovery tool for AI agents

---

### R8: Incremental Constraint Verification

**Priority**: P1 (Important — performance for CI/CD)
**Effort**: Medium
**Impact**: Verification time proportional to change size, not codebase size

**Current State**:
Change-aware verification (`verifyChange()`) only checks changed lines, but still evaluates ALL constraints for the file. No scope-based filtering to skip irrelevant constraints.

**Proposed Change**:
Three-level incremental verification:

**Level 1 (File-level)** — Already implemented:
- Only verify files that changed (content-hash comparison)
- Skip unchanged files entirely

**Level 2 (Constraint-level)** — New:
- Maintain a scope index mapping file paths to applicable constraints
- When a file changes, look up only applicable constraints via scope index
- Skip constraints whose scope doesn't match the changed file
- Expected reduction: 80-90% of constraints skipped for typical file changes

**Level 3 (Predicate-level)** — Future:
- Track which code elements each constraint depends on
- When a file changes, determine which code elements changed (functions added/removed/modified)
- Only re-evaluate predicates that depend on changed elements
- Expected reduction: additional 50-70% of predicate evaluations skipped

**Evidence**:
- §8.1 (Google/SonarQube): Three levels of incrementality — file, analysis, result
- §1.1 (ArchUnit): Constraint evaluation only on affected code
- §5.2 (Fitness functions): Must be fast (sub-minute) for CI integration

**Implementation Notes**:
- Scope index: SQLite table `constraint_scope_index` (R6) enables O(1) lookup
- Level 2 implementation: `getApplicableConstraints(filePath) → Constraint[]` using scope index
- Level 3 requires ParseResult diffing: compare old and new ParseResult to identify changed elements
- Cache verification results per (file_hash, constraint_id) pair — skip if both unchanged
- Invalidation: when a constraint definition changes, invalidate all cached results for that constraint

**Risks**:
- Cross-file constraints (must_colocate, must_separate) need special handling — they depend on multiple files
- Scope index maintenance — must be updated when constraints change
- Cache invalidation complexity — constraint changes, file changes, and template changes all invalidate differently

**Dependencies**:
- 08-storage: Scope index table, verification result cache
- 01-rust-core: Content-hash-based change detection
- 25-services-layer: Integration with scan pipeline for incremental verification

---

### R9: Enhanced Invariant Mining with Temporal Analysis

**Priority**: P1 (Important — improves constraint quality)
**Effort**: Medium
**Impact**: Detects strengthening/weakening invariants, prevents stale constraints

**Current State**:
Invariant detection is point-in-time — it analyzes the current codebase state without considering how patterns have evolved. A pattern that was dominant 6 months ago but is being replaced by a new pattern still generates a high-confidence constraint.

**Proposed Change**:
Add temporal analysis to invariant mining:

1. **Momentum scoring**: Track conforming/violating counts over time. Calculate momentum:
   ```
   momentum = (current_conforming_ratio - previous_conforming_ratio) / time_delta
   ```
   - Positive momentum → pattern is strengthening → boost confidence
   - Negative momentum → pattern is weakening → reduce confidence
   - Near-zero momentum → pattern is stable → maintain confidence

2. **Trend detection**: Identify constraints whose violation count is increasing over time. Flag these for review — they may represent intentional architectural changes (migrations).

3. **Negative invariant mining**: Detect patterns that are consistently AVOIDED — things the codebase never does. These become `must_not_have` constraints. Example: "No file in `src/services/` imports from `src/controllers/`" — if this holds across 100% of files, it's a strong negative invariant.

4. **Cross-language invariant detection**: Identify invariants that hold across multiple languages. Example: "All API handlers (TypeScript, Python, Java) have error handling" — a cross-language constraint.

**Evidence**:
- §5.2 (Temporal decay): "A scoring system that doesn't account for temporal change reports stale conventions as high-confidence"
- §4.1 (Daikon): Confidence increases with observation count, not just ratio
- §4.2 (Specification mining): Relevance filtering reduces output by 90%+ while retaining useful invariants
- §2.2 (Erosion prevention): Temporal dimension — erosion accelerates over time if unchecked

**Implementation Notes**:
- Store historical conforming/violating counts in `constraint_history` table (R6)
- Momentum calculation runs during constraint synthesis, not verification
- Negative invariant mining: scan for patterns with 0 violations across all files in scope
- Cross-language detection: group constraints by category + invariant type, check if same invariant holds across multiple languages
- Threshold for negative invariants: must hold across 100% of files with minimum 10 files in scope

**Risks**:
- Historical data cold start — no history for new projects. Use current state as baseline.
- Momentum noise — small codebases have high variance. Require minimum 50 files for momentum scoring.
- Negative invariant false positives — "never done" doesn't mean "shouldn't be done." Require high file count threshold.

**Dependencies**:
- 08-storage: Historical count storage
- 03-detectors: Pattern history data for temporal analysis

---

### R10: Auto-Fix Implementation

**Priority**: P2 (Nice to have — reduces developer effort)
**Effort**: High
**Impact**: Automated remediation for common constraint violations

**Current State**:
The `autoFix` field exists on `ConstraintEnforcement` but is never implemented. No constraint violations have automated fixes.

**Proposed Change**:
Implement auto-fix for constraint types where fixes are deterministic:

| Constraint Type | Auto-Fix Strategy | Example |
|----------------|-------------------|---------|
| `naming` | Rename file/function/class | `userController.ts` → `UserController.ts` |
| `must_have` (decorator) | Add missing decorator | Add `@Auth()` to undecorated endpoint |
| `must_wrap` (try/catch) | Wrap in error handler | Wrap async handler in try/catch |
| `must_have` (import) | Add missing import | Add `import { Logger } from './logger'` |
| `structure` (missing file) | Create file from template | Create `index.ts` in module directory |

**Evidence**:
- §10.2 (Tricorder): Google applies ~3,000 automated fixes per day. Suggested fixes are critical for adoption.
- §3.1 (Semgrep): `fix` field in rules enables auto-remediation

**Implementation Notes**:
- Fixes defined in constraint templates (R7) as `fix` field
- Fix application via Rust AST manipulation (tree-sitter edit API)
- Fixes are suggested, not auto-applied — developer must confirm
- Fix preview: show diff before applying
- MCP integration: `drift_constraint_fix` tool for AI agents to apply fixes

**Risks**:
- Incorrect fixes — auto-generated code may not compile. Mitigate with syntax validation after fix.
- Context-insensitive fixes — template-based fixes don't understand surrounding code. Mitigate with conservative fix strategies.
- Fix conflicts — multiple fixes on the same file may conflict. Apply sequentially with re-parse between fixes.

**Dependencies**:
- 02-parsers: Tree-sitter edit API for AST manipulation
- 07-mcp: Fix suggestion and application tools
- 11-ide: Quick-fix actions in IDE diagnostics

---

### R11: Constraint Visualization & Reporting

**Priority**: P2 (Nice to have — improves understanding)
**Effort**: Low-Medium
**Impact**: Makes constraint system visible and understandable

**Current State**:
Constraints are only visible through CLI commands and MCP tools. No visualization of constraint relationships, coverage, or violation trends.

**Proposed Change**:
Add constraint visualization capabilities:

1. **Constraint coverage map**: Which files/directories are covered by which constraints. Identify uncovered areas.
2. **Violation trend chart**: Violations over time per constraint. Shows whether constraints are being adopted or ignored.
3. **Constraint dependency graph**: Which constraints depend on which data sources (patterns, call graph, boundaries). Shows the constraint supply chain.
4. **Constraint health dashboard**: Per-constraint metrics — confidence, violation count, false-positive rate, momentum.

**Evidence**:
- §1.2 (dependency-cruiser): Visualization output (DOT graphs) valuable for understanding violations
- §1.4 (Sonargraph): "Exceptional dependency visualization capabilities"
- §5.1 (Fitness functions): Trend tracking enables proactive management

**Implementation Notes**:
- Coverage map: generate from scope index, output as JSON for IDE/dashboard consumption
- Trend chart: query `constraint_history` table, output as time-series JSON
- Dependency graph: static analysis of constraint definitions, output as DOT/JSON
- Health dashboard: aggregate metrics from constraints + feedback + baselines tables
- All outputs as JSON — rendering is the responsibility of CLI/IDE/dashboard

**Risks**:
- Information overload — too many metrics. Focus on the 4 most actionable.
- Maintenance burden — visualizations need updating as constraint system evolves.

**Dependencies**:
- 11-ide: Dashboard rendering
- 10-cli: Report generation commands

---

### R12: Constraint-Aware Context Generation

**Priority**: P2 (Nice to have — improves AI agent experience)
**Effort**: Low
**Impact**: AI agents receive constraint context when generating code

**Current State**:
Context generation (category 22) allocates 20% of token budget to constraints. But constraint context is basic — just the constraint name and description.

**Proposed Change**:
Enrich constraint context for AI agents:

1. Include constraint predicates in context — AI agents need to know WHAT the constraint checks, not just that it exists
2. Include violation examples — show the AI what violations look like so it can avoid them
3. Include fix suggestions — give the AI the fix template so it can apply it proactively
4. Include rationale — explain WHY the constraint exists so the AI can make informed decisions
5. Priority-based inclusion — include security constraints first, then structural, then naming

**Evidence**:
- §10.2 (Tricorder): "Understandable, actionable, <10% effective false positives" — AI agents need the same qualities
- §10.1 (ADRs): Rationale documentation improves decision quality

**Implementation Notes**:
- Extend constraint gatherer in context generation to include predicate, examples, fix, rationale
- Token budget: security constraints get 40% of constraint budget, structural 30%, other 30%
- Compression: use Cortex compression levels — Level 1 for most constraints, Level 2 for high-priority
- Cache constraint context per file — constraints don't change between requests

**Risks**:
- Token bloat — rich constraint context may exceed budget. Mitigate with compression and priority-based inclusion.

**Dependencies**:
- 22-context-generation: Enhanced constraint gatherer
- 06-cortex: Constraint rationale retrieval

---

## Implementation Phases

### Phase 1: Foundation (Weeks 1-3)
- R1: AST-based verification in Rust (core engine)
- R6: SQLite storage migration (schema + migration script)
- R2: TOML constraint format (parser + merger)

### Phase 2: Enterprise Adoption (Weeks 4-6)
- R3: Baseline management (FreezingArchRule)
- R5: Conflict resolution & inheritance
- R8: Incremental verification (Level 2)

### Phase 3: Intelligence (Weeks 7-9)
- R4: Developer feedback loop
- R9: Temporal analysis & negative invariant mining
- R7: Constraint templates

### Phase 4: Polish (Weeks 10-12)
- R10: Auto-fix implementation
- R11: Visualization & reporting
- R12: Constraint-aware context generation

---

## Target Metrics

| Metric | V1 | V2 Target | Evidence |
|--------|-----|-----------|----------|
| Verifiable invariant types | 8/12 | 12/12 | R1 (AST + call graph) |
| Verification accuracy | ~70% (regex) | ~98% (AST) | R1 |
| Verification speed (per file) | ~50ms | <5ms | R1 (Rust) |
| Effective false-positive rate | Unknown | <5% | R4 (Tricorder) |
| Constraint format | Internal JSON | TOML (version-controlled) | R2 |
| Legacy codebase adoption | Impractical | Baseline-enabled | R3 |
| Conflict detection | None | Automatic | R5 |
| Incremental verification | File-level only | Constraint-level | R8 |
| Auto-fix coverage | 0% | 40% of constraint types | R10 |
| Constraint templates | 0 | 10+ built-in | R7 |

---

## Risk Register

| Risk | Probability | Impact | Mitigation |
|------|------------|--------|------------|
| ParseResult interface instability | Medium | High | Define stable constraint-facing interface subset |
| Call graph not available at verification time | Medium | High | Graceful degradation — skip ordering constraints |
| TOML format too verbose for complex predicates | Low | Medium | Support tree-sitter query syntax for advanced predicates |
| Baseline gaming by developers | Low | Medium | Team-level aggregation, code review of baseline changes |
| Template proliferation | Low | Low | Curated built-in set, community review for additions |
| SQLite migration data loss | Low | High | Backup JSON before migration, rollback capability |

---

## Cross-Category Impact Matrix

| Category | Impact from Constraints V2 | Action Required |
|----------|---------------------------|-----------------|
| 01-rust-core | New Rust module for constraint verification | Add `constraints/` to drift-core |
| 02-parsers | ParseResult consumed by constraint verifier | Ensure stable interface |
| 04-call-graph | Path queries for ordering constraints | Expose path query API |
| 06-cortex | Constraint rationales, feedback as memories | Add constraint memory types |
| 07-mcp | New constraint tools (feedback, fix, explain) | Add 3-5 new MCP tools |
| 08-storage | New SQLite tables (constraints, baselines, feedback) | Schema migration |
| 09-quality-gates | Baseline-aware constraint verification gate | Update gate implementation |
| 10-cli | New commands (baseline, feedback, templates, explain) | Add 8-10 new commands |
| 11-ide | Inline constraint diagnostics, quick-fix actions | Add diagnostic provider |
| 22-context-gen | Enriched constraint context for AI agents | Update constraint gatherer |

---

## Quality Checklist

- [x] Each recommendation has clear rationale
- [x] Evidence is cited for each recommendation (25+ sources)
- [x] Priorities are justified (P0 = blocks enterprise adoption, P1 = important for quality, P2 = nice to have)
- [x] Effort is assessed (Low/Medium/High)
- [x] Risks are identified for each recommendation
- [x] Implementation notes are actionable
- [x] Dependencies on other categories are noted
- [x] Cross-category impacts are mapped
- [x] Implementation phases are sequenced with dependencies
- [x] Target metrics have v1 baselines and v2 targets
- [x] Risk register covers top 6 risks with mitigations
