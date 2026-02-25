# 21 Security — Research Recap

## Executive Summary

Security in Drift v1 is a cross-cutting concern spanning 6+ categories, anchored by a two-phase learn-then-detect pipeline in Category 21 (boundaries), augmented by 21 secret detection patterns in Rust Core (Category 01), 39 security/auth detectors in TypeScript (Category 03), forward/inverse reachability analysis through the call graph (Categories 01/04), a 10-pattern privacy sanitizer in Cortex (Category 06), and a single Enterprise-only security boundary quality gate (Category 09). The system supports 28+ ORM frameworks across 8 languages, 7 dedicated field extractors, 4-tier security prioritization, and boundary rule enforcement — but has critical gaps in taint analysis, OWASP/CWE coverage (5/10 and 6.5/25 respectively), secret detection breadth (21 patterns vs industry 500+), cryptographic failure detection, SSRF detection, and cross-service security analysis. All security detectors are TypeScript with zero Rust implementation, creating a significant performance bottleneck for enterprise-scale codebases.

---

## Current Implementation

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        MCP EXPOSURE LAYER                               │
│  drift_security_summary │ drift_reachability │ drift_boundaries         │
├─────────────────────────────────────────────────────────────────────────┤
│                        QUALITY GATES                                    │
│  Security Boundary Gate (Enterprise only) — sensitive data + auth check │
├─────────────────────────────────────────────────────────────────────────┤
│                        PRIORITIZATION & ENFORCEMENT                     │
│  SecurityPrioritizer (4 tiers) │ BoundaryRules │ BoundaryViolation      │
├──────────┬──────────┬──────────┬────────────────────────────────────────┤
│ Boundary │ Sensitive│ Reachab. │   Security Detectors (TS)              │
│ Scanner  │ Field    │ Engine   │   7 security × 3 variants = 21         │
│ (learn + │ Detector │ (fwd +   │   6 auth × 3 variants = 18             │
│  detect) │ (Rust)   │  inverse)│   Framework extensions (Laravel,       │
│          │          │          │   ASP.NET, Spring, Go, Rust, C++)      │
├──────────┴──────────┴──────────┴────────────────────────────────────────┤
│                        DATA ACCESS LEARNING                             │
│  DataAccessLearner │ 7 Field Extractors │ TableNameValidator            │
│  Learns: frameworks, tables, naming conventions, variable patterns      │
├─────────────────────────────────────────────────────────────────────────┤
│                        SECRET DETECTION (Rust)                          │
│  SecretDetector (21 patterns) │ ConstantsAnalyzer │ Entropy check       │
│  Critical(7) │ High(8) │ Medium(5) │ Placeholder filtering             │
├─────────────────────────────────────────────────────────────────────────┤
│                        RUST CORE                                        │
│  DataAccessDetector │ SensitiveFieldDetector │ ReachabilityEngine       │
│  (AST-based)        │ (pattern-based)        │ (in-memory + SQLite)     │
├─────────────────────────────────────────────────────────────────────────┤
│                        CORTEX PRIVACY                                   │
│  PII Sanitizer (5 patterns) │ Secret Sanitizer (5 patterns)            │
│  Redaction: [EMAIL] [PHONE] [SSN] [API_KEY] [AWS_KEY] [JWT] etc.      │
├─────────────────────────────────────────────────────────────────────────┤
│                        STORAGE                                          │
│  BoundaryStore (TS) │ drift.db (Rust) │ cortex.db (TS)                 │
└─────────────────────────────────────────────────────────────────────────┘
```

### Component Inventory

| Component | Language | Location | Purpose |
|-----------|----------|----------|---------|
| BoundaryScanner | TS | `core/src/boundaries/boundary-scanner.ts` | Two-phase learn-then-detect entry point |
| DataAccessLearner | TS | `core/src/boundaries/data-access-learner.ts` | Learns ORM frameworks, tables, naming conventions |
| BoundaryStore | TS | `core/src/boundaries/boundary-store.ts` | Persistence, access maps, rules, violation checking |
| SecurityPrioritizer | TS | `core/src/boundaries/security-prioritizer.ts` | 4-tier risk classification |
| TableNameValidator | TS | `core/src/boundaries/table-name-validator.ts` | Filters noise from detected table names |
| 7 Field Extractors | TS | `core/src/boundaries/field-extractors/` | Prisma, Django, SQLAlchemy, Supabase, GORM, Diesel, Raw SQL |
| DataAccessDetector | Rust | `drift-core/src/boundaries/detector.rs` | AST-based data access detection |
| SensitiveFieldDetector | Rust | `drift-core/src/boundaries/sensitive.rs` | PII/credential/financial/health detection |
| SecretDetector | Rust | `drift-core/src/constants/secrets.rs` | 21 regex patterns for hardcoded secrets |
| ReachabilityEngine | Rust | `drift-core/src/reachability/engine.rs` | Forward/inverse reachability (in-memory) |
| SQLiteReachabilityEngine | Rust | `drift-core/src/reachability/sqlite_engine.rs` | Forward/inverse reachability (large codebases) |
| Security Detectors (21) | TS | `detectors/src/security/` | CSRF, CSP, input sanitization, rate limiting, secret mgmt, SQLi, XSS |
| Auth Detectors (18) | TS | `detectors/src/auth/` | Audit logging, middleware, permissions, RBAC, resource ownership, tokens |
| Privacy Sanitizer | TS | `cortex/privacy/` | 10 PII/secret patterns with redaction |
| Security Boundary Gate | TS | `quality-gates/` | CI/CD enforcement (Enterprise only) |

---

## Key Algorithms

### 1. Learn-Then-Detect Pipeline (Heart of Security Analysis)

**Phase 1 — LEARN** (per codebase, cached):
```
For each source file:
  1. Detect ORM frameworks via import/decorator/usage patterns
  2. Extract table names from model definitions
  3. Record table access with file and framework
  4. Learn variable-to-table patterns (userRepo → users)
  5. Detect naming convention (snake_case, camelCase, PascalCase, mixed)
After all files:
  6. Finalize learning (calculate conventions)
  7. Build variable inference rules
Output: LearnedDataAccessConventions { frameworks, tableNamingConvention, knownTables, variablePatterns }
```

**Phase 2 — DETECT** (per file):
```
For each source file:
  1. Check if data access file (ORM patterns present)
  2. Run ORM-specific field extractors → ORMModel[]
  3. Extract data access points (table, fields, operation, confidence) → DataAccessPoint[]
  4. Detect sensitive fields → SensitiveField[]
Output: BoundaryScanResult { accessPoints, models, sensitiveFields, stats }
```

### 2. Confidence Breakdown (Data Access Detection)

```
confidence = Σ(factor × weight)

Factors:
  tableNameFound:    0.3 weight  — Was a table name identified?
  fieldsFound:       0.2 weight  — Were specific fields extracted?
  operationClear:    0.2 weight  — Is the operation type (read/write/delete) clear?
  frameworkMatched:   0.2 weight  — Was an ORM framework identified?
  fromLiteral:       0.1 weight  — Was the table name from a string literal?
```

### 3. Sensitive Field Detection (Rust)

Pattern-based with specificity scoring:
```
For each field name in ORM model:
  Match against category patterns:
    PII:         ssn(0.95), social_security(0.95), date_of_birth(0.9), email(0.65), ...
    Credentials: password_hash(0.95), api_key(0.9), access_token(0.85), password(0.75), ...
    Financial:   credit_card(0.95), cvv(0.95), bank_account(0.9), salary(0.85), ...
    Health:      medical_record(0.95), diagnosis(0.9), prescription(0.9), ...

  Apply false positive filtering:
    - Function names containing sensitive words → reduce confidence
    - Import statements → reduce confidence
    - Comments → reduce confidence
    - Mock/test/dummy prefixed → reduce confidence
    - health_check / health_endpoint → not health data
```

### 4. Secret Detection (Rust — 21 Patterns)

```
For each source line (parallel via rayon):
  Match against 21 regex patterns (Critical/High/Medium severity)
  
  Confidence scoring:
    base = severity_to_base(severity)  // Critical=0.9, High=0.8, Medium=0.6
    + 0.05 if high entropy (≥3 of: uppercase, lowercase, digit, special)
    + 0.05 if length > 30 chars
    confidence = min(base + adjustments, 1.0)
  
  Placeholder filtering:
    Skip if contains: example, placeholder, your_, xxx, todo, changeme, replace
    Skip if exact match: "password", "secret"
    Skip if all-X or all-* strings
  
  Value masking:
    if len ≤ 8: mask entirely
    else: show first min(4, len/4) + "..." + last min(4, len/4)
```

### 5. Security Prioritization (4 Tiers)

```
Tier 1 (Critical): Direct access to credentials, financial data
Tier 2 (High):     PII access, health data
Tier 3 (Medium):   General data access with sensitive fields
Tier 4 (Low):      Standard data access

Output: SecuritySummary { countsByTier, topRisks, recommendations }
```

### 6. Reachability Analysis (Rust)

```
Forward reachability (BFS from function):
  Start at function X
  Follow call graph edges (calls)
  At each node, check for data access points
  Record: path, depth, sensitive fields accessed
  
Inverse reachability (BFS from data):
  Start at sensitive data Y (table/field)
  Follow call graph edges (called_by) in reverse
  Record: all functions that can transitively reach Y
  
Both variants: in-memory (fast, small codebases) + SQLite (scalable, large codebases)
```

### 7. Boundary Rule Enforcement

```
For each DataAccessPoint:
  Match against BoundaryRules:
    rule.table matches accessPoint.table?
    accessPoint.file in rule.allowedFiles? (glob matching)
    accessPoint.file NOT in rule.deniedFiles?
    accessPoint.operation in rule.allowedOperations?
    If rule.requireAuth: is auth middleware present in call chain?
  
  Violations:
    unauthorized_file:      File not in allowedFiles
    unauthorized_operation:  Operation not in allowedOperations
    missing_auth:           requireAuth=true but no auth in call chain
```

---

## Data Models

### Core Security Types

```typescript
// Data Access Point — Where code touches data
DataAccessPoint {
  id: string;
  table: string;
  fields: string[];
  operation: DataOperation;        // read | write | delete | unknown
  file: string;
  line: number;
  column: number;
  context: string;                 // Surrounding code
  confidence: number;              // 0.0-1.0
  confidenceBreakdown?: ConfidenceBreakdown;
  framework: ORMFramework;         // 28+ supported
  language: string;
}

// Sensitive Field — PII/credential/financial/health data
SensitiveField {
  field: string;
  table: string | null;
  sensitivityType: SensitivityType;  // pii | credentials | financial | health | unknown
  file: string;
  line: number;
  confidence: number;
}

// ORM Model — Extracted model definition
ORMModel {
  name: string;
  tableName: string | null;
  fields: string[];
  file: string;
  line: number;
  framework: ORMFramework;
  confidence: number;
}

// Boundary Rule — Access control definition
BoundaryRule {
  table: string;
  allowedFiles: string[];          // Glob patterns
  deniedFiles?: string[];
  allowedOperations?: DataOperation[];
  requireAuth?: boolean;
}

// Boundary Violation — Rule breach
BoundaryViolation {
  rule: BoundaryRule;
  accessPoint: DataAccessPoint;
  violationType: 'unauthorized_file' | 'unauthorized_operation' | 'missing_auth';
  message: string;
  severity: 'error' | 'warning';
}

// Secret Candidate — Detected hardcoded secret
SecretCandidate {
  name: string;
  masked_value: string;
  secret_type: string;
  severity: SecretSeverity;        // Critical | High | Medium | Low | Info
  file: string;
  line: number;
  confidence: number;
  reason: string;
}

// Data Access Map — Aggregate view
DataAccessMap {
  projectRoot: string;
  tables: Map<string, TableAccessInfo>;
  files: Map<string, FileAccessInfo>;
  models: ORMModel[];
  sensitiveFields: SensitiveField[];
  stats: AccessMapStats;
}
```

### Rust Types (Parallel Definitions)

```rust
// Rust DataAccessPoint — simpler, no confidence breakdown
struct DataAccessPoint {
    table: String,
    operation: DataOperation,      // Read | Write | Delete
    fields: Vec<String>,
    file: String,
    line: u32,
    confidence: f32,
    framework: Option<String>,
}

// Rust SensitiveField
struct SensitiveField {
    field: String,
    table: Option<String>,
    sensitivity_type: SensitivityType,  // Pii | Credentials | Financial | Health
    file: String,
    line: u32,
    confidence: f32,
}

// Rust ORMModel
struct ORMModel {
    name: String,
    table_name: String,
    fields: Vec<String>,
    file: String,
    line: u32,
    framework: String,
    confidence: f32,
}
```

### Type Parity Issues
- Rust types lack `ConfidenceBreakdown` (simpler scoring)
- Rust `DataAccessPoint` has no `id`, `column`, `context`, or `language` fields
- Rust `DataOperation` has no `unknown` variant
- TypeScript has `BoundaryRule` and `BoundaryViolation` — no Rust equivalent
- No unified type ownership — both sides define independently

---

## ORM Framework Support (28+)

| Language | Frameworks | Field Extractor |
|----------|-----------|-----------------|
| C# | EF Core, Dapper | ❌ |
| Python | Django, SQLAlchemy, Tortoise, Peewee | Django ✅, SQLAlchemy ✅ |
| TypeScript/JS | Prisma, TypeORM, Sequelize, Drizzle, Knex, Mongoose, Supabase | Prisma ✅, Supabase ✅ |
| Java | Spring Data, Hibernate, jOOQ, MyBatis | ❌ |
| PHP | Eloquent, Doctrine | ❌ |
| Go | GORM, sqlx, Ent, Bun | GORM ✅ |
| Rust | Diesel, SeaORM, tokio-postgres, rusqlite | Diesel ✅ |
| Generic | Raw SQL | Raw SQL ✅ |

**Gap**: 7 extractors cover 7 of 28+ frameworks. 21+ frameworks have no dedicated field extraction — they rely on generic pattern matching.

---

## Security Detector Coverage by Language

| Language | Security Detectors | Auth Detectors | Framework Extensions |
|----------|-------------------|----------------|---------------------|
| TypeScript/JS | 7 (all types) | 6 (all types) | — |
| Python | 7 (all types) | 6 (all types) | Django (contracts only) |
| Java | 7 (all types) | 6 (all types) | Spring (12 categories) |
| C# | 7 (all types) | 6 (all types) | ASP.NET (11 categories) |
| PHP | 7 (all types) | 6 (all types) | Laravel (12 categories) |
| Go | — | 1 (middleware) | Go (api+auth+errors) |
| Rust | — | 1 (middleware) | Rust (api+auth+errors) |
| C++ | — | 1 (middleware) | C++ (api+auth+errors) |
| C | — | — | — |

**Gap**: Go, Rust, C++, and C have minimal or no security detector coverage.

---

## MCP Security Tools

| Tool | Purpose | Response |
|------|---------|----------|
| `drift_security_summary` | Security posture overview | Tier counts, top risks, recommendations |
| `drift_reachability` | Forward/inverse data reachability | Call paths, sensitive field access |
| `drift_boundaries` | Data access map and boundary rules | Tables, files, models, sensitive fields |

**Gap**: No MCP tools for secret scan results, OWASP coverage, security violations, or taint analysis.

---

## Integration Points

| Connects To | Direction | How |
|-------------|-----------|-----|
| **01-rust-core** | Foundation | DataAccessDetector, SensitiveFieldDetector, SecretDetector, ReachabilityEngine |
| **02-parsers** | Consumes | AST input for data access detection, ORM model extraction |
| **03-detectors** | Parallel | 39 security/auth detectors run alongside boundary scanning |
| **04-call-graph** | Consumes | Reachability analysis traverses call graph for data flow |
| **05-analyzers** | Consumes | Unified language provider's 20 ORM matchers feed boundary detection |
| **06-cortex** | Produces | Privacy sanitizer protects sensitive data in memories |
| **07-mcp** | Produces | 3 security tools expose findings to AI agents |
| **08-storage** | Produces | BoundaryStore persists access maps, rules, violations |
| **09-quality-gates** | Produces | Security Boundary Gate enforces access control in CI/CD |
| **22-context-generation** | Produces | Security context feeds AI context generation |

### Critical Dependency Chain
```
02-parsers → 21-security (AST input)
04-call-graph → 21-security (reachability traversal)
21-security → 07-mcp (AI agent exposure)
21-security → 09-quality-gates (CI/CD enforcement)
21-security → 06-cortex (privacy protection)
21-security → 22-context-generation (security context for AI)
```

---

## V2 Migration Status

### Already in Rust
- DataAccessDetector (basic AST-based detection)
- SensitiveFieldDetector (pattern-based with specificity scoring)
- SecretDetector (21 patterns with confidence scoring)
- ReachabilityEngine (forward/inverse, in-memory + SQLite)
- Environment sensitivity classification

### Must Migrate TS → Rust
| Component | Priority | Rationale |
|-----------|----------|-----------|
| BoundaryScanner (learn-then-detect) | P0 | Core pipeline, I/O + regex heavy |
| DataAccessLearner | P0 | Learning phase is I/O bound, benefits from rayon |
| 7 Field Extractors | P1 | ORM-specific parsing, move to tree-sitter AST |
| SecurityPrioritizer | P1 | Pure logic, straightforward port |
| TableNameValidator | P1 | Validation logic, straightforward port |
| BoundaryStore | P2 | File I/O, may stay TS |
| Security Detectors (21) | P1 | Performance-critical, visitor pattern in Rust |
| Auth Detectors (18) | P1 | Performance-critical, visitor pattern in Rust |

### Must Build New in Rust
| Component | Priority | Rationale |
|-----------|----------|-----------|
| Taint analysis engine | P1 | Foundation for injection detection |
| Expanded secret detection (100+ patterns) | P0 | Enterprise requirement |
| CWE ID mapping system | P1 | Compliance reporting |
| Cryptographic pattern detection | P1 | OWASP A02 coverage |
| SSRF detection | P1 | OWASP A10 coverage |
| Unsafe ORM API detection | P1 | Raw SQL bypass patterns |
| Cross-service reachability | P2 | Microservice security |
| Security event logging detection | P2 | OWASP A09 coverage |

### Stays in TypeScript
- MCP security tools (thin JSON-RPC wrappers)
- Quality gate orchestration (thin wrapper calling Rust)
- Cortex privacy sanitizer (memory system stays TS)

---

## Limitations (Complete Inventory)

### Critical
1. **No taint analysis** — Cannot track data from user input (source) to SQL query (sink)
2. **Secret detection too narrow** — 21 patterns vs GitGuardian's 500+
3. **OWASP coverage ~5/10** — A02, A04, A06, A08, A10 uncovered
4. **CWE coverage ~6.5/25** — Most require data flow analysis
5. **All security detectors are TS** — Zero Rust, massive performance gap

### High
6. **No unsafe ORM API detection** — `$queryRaw`, `extra()`, `textual()` not flagged
7. **No cryptographic failure detection** — Weak algorithms, missing encryption
8. **No SSRF detection** — Server-side request forgery invisible
9. **No cross-service reachability** — Microservice boundaries not tracked
10. **Privacy patterns critically insufficient** — 10 patterns in Cortex

### Medium
11. **No encryption-at-rest detection** — Sensitive fields stored unencrypted not flagged
12. **No security event logging detection** — Missing audit trails not detected
13. **No insecure deserialization detection** — Untrusted data deserialization not flagged
14. **Security gate Enterprise-only** — Community/Team users have no CI security
15. **21+ ORMs lack dedicated field extractors** — Generic pattern matching only

### Low
16. **No path traversal detection** — File path manipulation not detected
17. **No command injection detection** — OS command construction not analyzed
18. **No race condition detection** — Concurrent access patterns not analyzed
19. **No code injection detection** — eval(), exec() patterns not systematically detected
20. **Type parity issues** — Rust and TS types defined independently

---

## Open Questions

1. **Taint analysis scope**: Intraprocedural only (within function) or interprocedural (across call graph)?
2. **Secret detection strategy**: Build 500+ patterns in-house or integrate with GitGuardian/TruffleHog?
3. **OWASP A04 (Insecure Design)**: Can architectural constraints (Category 18) address this?
4. **Security gate tiering**: Should basic security gates be available in Community tier?
5. **Cross-service reachability**: How to detect microservice API boundaries without runtime data?
6. **Cryptographic detection**: Pattern-based (detect weak algorithms) or data-flow-based (track crypto usage)?
7. **SARIF integration**: Should security findings produce SARIF output for GitHub Code Scanning?
8. **Sensitive data lineage**: Should Drift track the full lifecycle of sensitive data (creation → storage → access → deletion)?
9. **Compliance frameworks**: Beyond OWASP/CWE, should Drift map to SOC 2, GDPR, HIPAA, PCI-DSS?
10. **AI-assisted security**: Should Cortex memories include security-specific knowledge (vulnerability patterns, remediation guidance)?

---

## Quality Checklist

- [x] All primary security source files read (4 files in 21-security/)
- [x] All security-adjacent categories audited (01, 03, 04, 06, 07, 09)
- [x] Architecture clearly described with diagram
- [x] All 7 key algorithms documented
- [x] All data models listed with field descriptions
- [x] ORM framework support inventoried (28+ frameworks, 7 extractors)
- [x] Security detector coverage mapped by language
- [x] MCP security tools documented
- [x] Integration points mapped across 10 categories
- [x] V2 migration status documented with priorities
- [x] 20 limitations honestly assessed across 4 severity levels
- [x] 10 open questions identified
- [x] OWASP Top 10 coverage audited (5/10)
- [x] CWE/SANS Top 25 coverage audited (6.5/25)
