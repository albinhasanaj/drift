# 03 Detectors — V2 Recommendations

## Summary

12 recommendations organized by priority, synthesized from comprehensive analysis of Drift's 350+ detector system and external research from 20+ authoritative sources. The recommendations address the five most critical gaps: performance (single-pass traversal, incremental detection), architecture (generic AST, visitor pattern), statistical rigor (confidence decay, outlier thresholds), security coverage (OWASP/CWE alignment), and developer experience (feedback loops, effective false-positive tracking). Combined, these changes would transform Drift's detector system from a capable TypeScript prototype into an enterprise-grade, Rust-powered analysis engine suitable for million-line codebases.

---

## Recommendations

### R1: Single-Pass Visitor Pattern for Detection

**Priority**: P0 (Critical)
**Effort**: High
**Impact**: 10-100x detection performance improvement; eliminates redundant AST traversals

**Current State**:
Each detector independently traverses the AST for every file. With 100+ enabled detectors, this means 100+ traversals of the same AST per file. For a 10,000-file codebase, that's 1,000,000+ AST traversals.

**Proposed Change**:
Adopt ESLint's visitor pattern: traverse each file's AST once, notifying all interested detectors per node type. Detectors register interest in specific node types (e.g., `try_statement`, `call_expression`, `function_declaration`). The engine traverses once and dispatches to all registered handlers.

```
Current:  O(files × detectors × AST_nodes)
Proposed: O(files × AST_nodes × handlers_per_node)
```

Since most detectors only care about a few node types, `handlers_per_node` is typically 2-5, vs. traversing the entire tree 100+ times.

**Implementation in Rust**:
```rust
struct DetectionEngine {
    handlers: HashMap<NodeType, Vec<Box<dyn DetectorHandler>>>,
}

trait DetectorHandler {
    fn node_types(&self) -> &[NodeType];
    fn on_enter(&mut self, node: &Node, ctx: &DetectionContext);
    fn on_exit(&mut self, node: &Node, ctx: &DetectionContext);
    fn results(&self) -> Vec<PatternMatch>;
}
```

**Rationale**:
ESLint processes millions of files daily with this pattern. Google's Tricorder uses a similar approach. This is the single most impactful performance optimization, independent of the Rust migration.

**Evidence**:
- ESLint architecture (R5): Single-pass traversal with visitor pattern
- Google Tricorder (R1): Shardable, incremental analysis at scale
- Semgrep (R2): Single-pass matching against generic AST

**Risks**:
- Requires refactoring all 350+ detectors to the handler interface
- Some detectors need full-file context (not just per-node) — need a "file-level" handler variant
- Learning detectors need a two-pass approach (learn pass + detect pass) — the visitor pattern applies to the detect pass

**Dependencies**:
- 02-parsers: AST must provide node type information compatible with handler registration
- 01-rust-core: Rust unified analyzer should adopt this pattern first, then TS detectors migrate incrementally

---

### R2: Incremental Detection with Content-Hash Skipping

**Priority**: P0 (Critical)
**Effort**: Medium
**Impact**: 10-100x faster for typical development workflows (few files changed)

**Current State**:
Every `drift scan` re-analyzes all files. No change detection. Content hashing infrastructure exists but isn't used for detection skipping.

**Proposed Change**:
Three-layer incremental detection:

**Layer 1 — File-level skip** (Easy, immediate):
```
if file.contentHash === previousScan.contentHash:
  reuse previous detection results for this file
  skip detection entirely
```

**Layer 2 — Pattern-level re-scoring** (Medium):
```
When files change:
  Re-detect only changed files
  Re-aggregate only patterns that had locations in changed files
  Re-score only affected patterns
  Keep all other pattern scores unchanged
```

**Layer 3 — Convention re-learning** (Hard):
```
Track convention stability across scans
If <10% of files changed: skip re-learning, reuse conventions
If 10-30% changed: incremental re-learning (update distributions)
If >30% changed: full re-learning
```

**Rationale**:
Google, CodeQL, and SonarQube all use incremental analysis as a core strategy. For typical development (1-10 files changed), this reduces scan time from seconds/minutes to milliseconds.

**Evidence**:
- Google SWE Book (R1, R4): "Focus analyses on files affected by a pending code change"
- CodeQL Incremental (R4): "Reuses previously computed analysis results"
- SonarQube (R4): "Analysis cache mechanism that reuses previous results"

**Implementation Notes**:
- Store per-file detection results in SQLite (keyed by file path + content hash)
- On scan: compare content hashes, skip unchanged files, re-detect changed files
- Merge new results with cached results
- Invalidate pattern scores that reference changed files

**Risks**:
- Cross-file patterns (e.g., import ordering consistency) may produce stale results if only some files are re-analyzed
- Convention learning depends on project-wide statistics — incremental updates may drift from full-scan results
- Need a "force full scan" escape hatch

**Dependencies**:
- 08-storage: Need a detection result cache table in SQLite
- 25-services-layer: Scan pipeline must support incremental mode

---

### R3: Temporal Confidence Decay and Momentum Scoring

**Priority**: P0 (Critical)
**Effort**: Medium
**Impact**: Eliminates stale convention enforcement; enables graceful convention migration

**Current State**:
Drift's confidence scoring uses four factors: frequency (0.4), consistency (0.3), age (0.15), spread (0.15). The age factor scales linearly from 0.1 to 1.0 over 30 days, then stays at 1.0 forever. There is no decay mechanism. Once a pattern reaches high confidence, it stays there even if the team is actively migrating away from that convention.

**Proposed Change**:
Add two new mechanisms:

**1. Temporal Decay**: Reduce confidence when a pattern's frequency declines across consecutive scans.
```
decayFactor = currentFrequency / previousFrequency
if decayFactor < 1.0:
  ageFactor = ageFactor × decayFactor
```

**2. Momentum Signal**: Add a fifth scoring factor that captures the trend direction.
```
momentum = (currentFrequency - previousFrequency) / max(previousFrequency, 0.01)
momentumNormalized = clamp((momentum + 1) / 2, 0, 1)
```

**Revised weight distribution**:
```
score = frequency × 0.30 + consistency × 0.25 + ageFactor × 0.10 + spread × 0.15 + momentum × 0.20
```

Momentum gets 0.20 weight because convention migration is a critical enterprise scenario. The age factor drops from 0.15 to 0.10 because momentum subsumes some of its purpose.

**Scenario — Convention Migration**:
- Scan 1: Old pattern at 80% frequency, new pattern at 20%. Old = high confidence, new = low.
- Scan 2: Old at 60%, new at 40%. Old's momentum is negative (-0.25), new's is positive (+1.0). Old's confidence drops, new's rises.
- Scan 3: Old at 30%, new at 70%. Crossover. New pattern becomes dominant. Old pattern's violations are suppressed.

Without momentum, Drift would flag the new pattern as violations through all three scans, fighting the team's intentional migration.

**Rationale**:
Software designs decay over time (Izurieta & Bieman, 2007). Conventions evolve. A scoring system that doesn't account for temporal change will enforce stale conventions and frustrate developers during migrations.

**Evidence**:
- Izurieta & Bieman (R6): "Software designs decay as systems evolve" — decay indices measure pattern erosion
- ACM Convention Consistency paper (R6): Consistency is temporal — it changes as projects evolve
- Google Tricorder (R1): Focus on newly introduced warnings, not legacy issues

**Risks**:
- Momentum can be noisy for small codebases (few files changing can swing percentages dramatically)
- Need minimum sample size before momentum kicks in (suggest: momentum only active after 3+ scans with 50+ files)
- Weight rebalancing changes existing confidence scores — need migration strategy

**Dependencies**:
- 08-storage: Need to store per-pattern frequency history across scans (new table: `pattern_scan_history`)
- 23-pattern-repository: Pattern abstraction layer must support historical frequency queries

---

### R4: Generic AST Normalization Layer for Language-Agnostic Detection

**Priority**: P1 (Important)
**Effort**: High
**Impact**: Reduces detector codebase by 50-70%; enables write-once-run-everywhere detection rules

**Current State**:
Drift has per-language AST queries in Rust (~30 patterns across 9 languages) and per-language detectors in TypeScript (350+ files). Many detectors are language-specific variants of the same concept (e.g., `try-catch` detection exists separately for JavaScript, Python, Java, Go, Rust, C++). The same logical pattern is implemented 6+ times with language-specific syntax.

**Proposed Change**:
Introduce a Generic AST (GAST) normalization layer between tree-sitter parsing and detection, inspired by Semgrep's `ast_generic`:

```
Source Code → tree-sitter → Language-Specific CST → GAST Normalizer → Generic AST → Detectors
```

The GAST would normalize common constructs:
```rust
enum GASTNode {
    Function { name: String, params: Vec<Param>, body: Block, is_async: bool, decorators: Vec<Decorator> },
    Class { name: String, extends: Option<String>, implements: Vec<String>, members: Vec<Member> },
    TryCatch { try_block: Block, catch_clauses: Vec<CatchClause>, finally_block: Option<Block> },
    Call { callee: Expr, args: Vec<Expr>, is_await: bool },
    Import { source: String, specifiers: Vec<ImportSpec>, is_type_only: bool },
    Route { method: HttpMethod, path: String, handler: Expr },
    // ... ~30 normalized node types covering 80% of detection needs
}
```

**Implementation Strategy**:
1. Define ~30 GAST node types covering the most common detection targets
2. Write per-language normalizers (tree-sitter CST → GAST) for each of the 10 languages
3. Migrate detectors from language-specific to GAST-based, starting with the most duplicated patterns
4. Keep language-specific detectors for truly language-unique patterns (e.g., PHP attributes, Rust lifetimes)

**Rationale**:
Semgrep's generic AST enables 30+ language support with a single rule engine. Drift's current approach of per-language detectors doesn't scale — adding a new language requires writing 100+ new detectors. With GAST, adding a language requires only a normalizer (~500-1000 lines), and all existing detectors work automatically.

**Evidence**:
- Semgrep `ast_generic` (R2): "A generic AST to factorize similar analysis on different programming languages"
- Semgrep architecture (R2): "New languages only need a parser + AST translator, not new analysis logic"
- Tree-sitter queries (R10): Cross-language queries are possible but require careful design

**Risks**:
- Information loss: normalization discards language-specific details. Some detectors need those details.
- Impedance mismatch: not all constructs normalize cleanly (e.g., Python's `with` statement vs. Java's try-with-resources)
- Large upfront investment: 10 normalizers + GAST type system + detector migration
- Mitigation: Keep a "raw AST" escape hatch for detectors that need language-specific access

**Dependencies**:
- 02-parsers: Parsers must produce CSTs with enough detail for normalization
- 01-rust-core: GAST types defined in Rust, exposed via NAPI
- All framework detectors: Must be audited for language-specific dependencies before migration

---

### R5: Effective False-Positive Tracking and Feedback Loop

**Priority**: P1 (Important)
**Effort**: Medium
**Impact**: Continuous improvement of detector quality; builds developer trust; enables data-driven detector tuning

**Current State**:
Drift has no mechanism to track whether developers act on violations. There is no feedback loop between violation consumers and detector authors. The "Not useful" rate is unknown. Detectors cannot be tuned based on real-world effectiveness.

**Proposed Change**:
Implement Google Tricorder's feedback model adapted for Drift:

**1. Violation Action Tracking**:
```typescript
enum ViolationAction {
  Fixed,          // Developer fixed the violation
  Dismissed,      // Developer explicitly dismissed
  Ignored,        // Developer saw but took no action
  AutoFixed,      // Quick fix was applied
  NotSeen,        // Violation was never displayed to developer
}
```

**2. Effective False-Positive Rate per Detector**:
```
effectiveFPRate = (dismissed + ignored) / (fixed + dismissed + ignored + autoFixed)
```

**3. Detector Health Dashboard**:
- Track effective FP rate per detector over time
- Alert when a detector's FP rate exceeds 10% (Google's threshold)
- Auto-disable detectors that exceed 20% FP rate for 30+ days
- Surface "most useful" and "least useful" detectors

**4. MCP Integration**:
Expose detector health metrics via MCP tools so AI agents can prioritize high-confidence detectors and skip unreliable ones.

**Rationale**:
Google's #1 lesson: "Focus on developer happiness." Tricorder maintains <5% effective FP rate by aggressively tracking and tuning. Without this feedback loop, Drift's detectors will accumulate false positives over time, eroding developer trust.

**Evidence**:
- Google Tricorder (R1): "Not useful" button, <5% effective FP rate, analyzers disabled if they don't improve
- Google SWE Book (R1): "An issue is an 'effective false positive' if developers did not take some positive action after seeing the issue"

**Implementation Notes**:
- IDE integration: Track when violations are displayed, fixed, or dismissed in VSCode
- CLI integration: Track when `drift fix` is run and which violations are addressed
- CI integration: Track which violations block PRs vs. are overridden
- Store action data in `violation_actions` table in drift.db

**Risks**:
- Privacy concerns: tracking developer actions requires clear opt-in
- Data sparsity: small teams may not generate enough feedback for statistical significance
- Feedback delay: violations may be fixed days after being reported

**Dependencies**:
- 11-ide: VSCode extension must report violation actions
- 10-cli: CLI must track fix/dismiss actions
- 07-mcp: MCP tools should expose detector health metrics
- 08-storage: New `violation_actions` and `detector_health` tables

---

### R6: Outlier Detection Statistical Refinements

**Priority**: P1 (Important)
**Effort**: Low
**Impact**: Reduces false-positive outlier flags by ~30-50%; improves statistical rigor for enterprise credibility

**Design for Fresh Build**:

The outlier detection system should be built from scratch with these refinements baked in from day one, rather than using the v1 thresholds:

**1. Raise Z-Score Threshold to 2.5**:
The v1 system uses |z| > 2.0, which flags ~4.6% of normally distributed data as outliers. For code conventions, this is too aggressive — it generates noise. NIST recommends |z| > 3.0 for general outlier detection. A threshold of 2.5 (~1.2% flagged) balances sensitivity with precision for code pattern analysis.

**2. Minimum Sample Size of 10 (not 3)**:
With n=3, any single unusual value creates an outlier. This is statistically meaningless. Set the floor at 10 data points before any outlier detection runs. For samples between 10-30, use IQR (which is already the plan). For n ≥ 30, use Z-score.

**3. Add Grubbs' Test for Small Samples (10 ≤ n < 30)**:
Grubbs' test is specifically designed for outlier detection in small samples. It accounts for sample size in the critical value calculation, unlike raw IQR which uses a fixed multiplier regardless of n. Implementation is straightforward:
```rust
fn grubbs_test(values: &[f64], alpha: f64) -> Vec<usize> {
    let n = values.len() as f64;
    let mean = values.iter().sum::<f64>() / n;
    let std_dev = (values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (n - 1.0)).sqrt();
    let t_crit = t_distribution_critical(alpha / (2.0 * n), n - 2.0);
    let grubbs_crit = ((n - 1.0) / n.sqrt()) * (t_crit.powi(2) / (n - 2.0 + t_crit.powi(2))).sqrt();
    
    values.iter().enumerate()
        .filter(|(_, v)| ((*v - mean) / std_dev).abs() > grubbs_crit)
        .map(|(i, _)| i)
        .collect()
}
```

**4. Iterative Outlier Detection**:
Both Z-score and IQR suffer from "masking" — one extreme outlier can hide others by inflating the standard deviation. Build iterative detection from the start:
```
loop:
  detect outliers
  if no new outliers found: break
  remove detected outliers from dataset
  recalculate statistics
  detect again
```
Cap iterations at 3 to prevent over-removal.

**5. Significance Tiers (Revised)**:
```
|z| > 3.5 → critical (architectural violation — likely intentional deviation or bug)
|z| > 3.0 → high (strong deviation — worth investigating)
|z| > 2.5 → moderate (mild deviation — informational)
Below 2.5 → not flagged
```

**Rationale**:
NIST's statistical handbook is the definitive reference for outlier detection methodology. The v1 thresholds were reasonable starting points but too aggressive for production use where false positives erode trust.

**Evidence**:
- NIST/SEMATECH e-Handbook (R7): Standard Z-score threshold is |z| > 3.0
- Grubbs (R7): Grubbs' test is the standard for small-sample outlier detection
- Google Tricorder (R1): <10% effective false-positive rate is the target

**Risks**:
- Higher thresholds mean some real outliers go undetected (acceptable trade-off for trust)
- Grubbs' test requires a t-distribution lookup table or approximation function
- Iterative detection adds computational cost (mitigated by the 3-iteration cap)

**Dependencies**:
- None — this is a self-contained statistical module

---

### R7: OWASP/CWE-Aligned Security Detection Categories

**Priority**: P1 (Important)
**Effort**: High
**Impact**: Enterprise compliance readiness; maps detectors to industry-standard vulnerability classifications

**Design for Fresh Build**:

Instead of the v1 approach of 7 ad-hoc security detectors, design the security detection category from scratch around OWASP Top 10 and CWE/SANS Top 25 coverage:

**OWASP Top 10 (2021) Detector Mapping**:

| OWASP | Category | Detectors to Build | Priority |
|-------|----------|-------------------|----------|
| A01: Broken Access Control | auth | permission-checks, rbac-patterns, resource-ownership, path-traversal, cors-misconfiguration | P0 |
| A02: Cryptographic Failures | security | weak-crypto-algorithms, hardcoded-keys, insecure-random, missing-encryption, weak-hashing | P0 |
| A03: Injection | security | sql-injection, xss-prevention, command-injection, ldap-injection, template-injection | P0 |
| A04: Insecure Design | structural | missing-rate-limiting, missing-input-validation, trust-boundary-violations | P1 |
| A05: Security Misconfiguration | config | debug-mode-enabled, default-credentials, unnecessary-features, missing-security-headers | P1 |
| A06: Vulnerable Components | dependencies | (defer to Snyk/Dependabot — out of scope for static analysis) | P2 |
| A07: Auth Failures | auth | weak-password-policy, missing-mfa-check, session-fixation, credential-stuffing-vectors | P0 |
| A08: Integrity Failures | security | insecure-deserialization, unsigned-data-acceptance, ci-cd-integrity-gaps | P1 |
| A09: Logging Failures | logging | missing-security-logging, pii-in-logs, insufficient-audit-trail | P1 |
| A10: SSRF | security | ssrf-detection, url-from-user-input, dns-rebinding-vectors | P0 |

**CWE ID Tagging**:
Every security detector should tag its findings with the relevant CWE ID(s):
```rust
struct SecurityFinding {
    pattern: PatternMatch,
    cwe_ids: Vec<u32>,        // e.g., [89] for SQL injection (CWE-89)
    owasp_category: String,   // e.g., "A03:2021"
    severity: SecuritySeverity,
    cvss_estimate: Option<f32>, // Optional CVSS v3.1 base score estimate
}
```

This enables:
- Compliance reporting ("Show me all CWE-89 findings")
- OWASP coverage dashboards ("Which Top 10 categories are we detecting?")
- Integration with vulnerability management tools that speak CWE/CVSS

**New Security Detectors Not in V1**:
1. `weak-crypto-algorithms` — Detects MD5, SHA1, DES, RC4, ECB mode usage
2. `insecure-random` — Detects Math.random(), random.random() in security contexts
3. `command-injection` — Detects exec(), system(), child_process with user input
4. `ssrf-detection` — Detects URL construction from user-controlled input
5. `path-traversal` — Detects file path construction from user input
6. `insecure-deserialization` — Detects pickle.loads(), JSON.parse() of untrusted data
7. `missing-security-headers` — Detects missing CSP, HSTS, X-Frame-Options
8. `cors-misconfiguration` — Detects Access-Control-Allow-Origin: *

**Rationale**:
Enterprise customers require OWASP/CWE compliance reporting. Building the security category around these standards from day one avoids a painful retrofit later. Every major SAST tool (Semgrep, SonarQube, Checkmarx, Fortify) maps findings to CWE IDs.

**Evidence**:
- OWASP Top 10 (R9): Industry-standard vulnerability classification
- CWE/SANS Top 25 (R9): Most dangerous software weaknesses
- Semgrep (R2): Maps all rules to CWE IDs for compliance

**Risks**:
- Some OWASP categories (A04: Insecure Design, A06: Vulnerable Components) are hard to detect statically
- CWE mapping requires domain expertise to get right — incorrect mappings undermine credibility
- CVSS estimation is inherently imprecise without runtime context

**Dependencies**:
- 21-security: Security boundary detection feeds into several of these detectors
- 04-call-graph: SSRF and injection detection benefit from data flow through call chains
- 09-quality-gates: Security findings should integrate with gate enforcement

---

### R8: Contract Detection Expansion — GraphQL, gRPC, and Schema-First

**Priority**: P1 (Important)
**Effort**: High
**Impact**: Covers the three dominant API paradigms; enables full-stack contract verification

**Design for Fresh Build**:

Build the contract detection system to support three API paradigms from the start, not just REST:

**1. REST Contracts (Existing Concept, Refined)**:
- Backend endpoint extraction (Express, FastAPI, Spring, Laravel, Django, ASP.NET, Go, Rust, C++)
- Frontend API call extraction (fetch, axios, custom clients)
- OpenAPI/Swagger spec parsing as first-class contract source
- Path similarity matching with version-awareness (/v1/users vs /v2/users)
- Breaking change classification: breaking | non-breaking | deprecation

**2. GraphQL Contracts (New)**:
```rust
struct GraphQLContract {
    schema_source: SchemaSource,  // .graphql file, code-first, or introspection
    types: Vec<GraphQLType>,
    queries: Vec<GraphQLOperation>,
    mutations: Vec<GraphQLOperation>,
    subscriptions: Vec<GraphQLOperation>,
}

enum SchemaSource {
    SchemaFile(PathBuf),      // schema.graphql, *.gql
    CodeFirst(PathBuf),       // type-graphql, nexus, pothos definitions
    Introspection(String),    // Introspection query result
}
```
- Detect schema ↔ resolver mismatches
- Detect frontend query ↔ schema mismatches (fields requested but not in schema)
- Detect N+1 patterns in resolvers (resolver calls DB per item without batching)

**3. gRPC/Protobuf Contracts (New)**:
```rust
struct GrpcContract {
    proto_file: PathBuf,
    services: Vec<GrpcService>,
    messages: Vec<ProtobufMessage>,
}
```
- Parse .proto files for service and message definitions
- Detect client ↔ server message mismatches
- Detect breaking changes in proto evolution (field number reuse, type changes)

**4. Unified Contract Model**:
All three paradigms normalize to a common contract representation:
```rust
struct ApiContract {
    paradigm: ApiParadigm,        // REST | GraphQL | gRPC
    operations: Vec<ApiOperation>,
    types: Vec<ApiType>,
    source: ContractSource,       // Schema file | Code extraction | Both
}

struct ApiOperation {
    name: String,
    method: Option<HttpMethod>,   // REST only
    path: Option<String>,         // REST only
    input_type: Option<ApiType>,
    output_type: Option<ApiType>,
    is_deprecated: bool,
}
```

This unified model enables cross-paradigm analysis: "Does the REST endpoint return the same user fields as the GraphQL query?"

**Rationale**:
Enterprise codebases increasingly use multiple API paradigms. A contract detection system that only understands REST misses GraphQL (used by GitHub, Shopify, Meta) and gRPC (used by Google, Netflix, Uber). Building all three from the start avoids architectural constraints that make adding them later painful.

**Evidence**:
- OpenAPI Specification (R8): Industry standard for REST contracts
- GraphQL Specification: https://spec.graphql.org/ — formal specification for GraphQL
- Protocol Buffers Language Guide: https://protobuf.dev/programming-guides/proto3/ — gRPC contract format

**Risks**:
- GraphQL schema extraction from code-first frameworks (type-graphql, nexus) is complex
- Protobuf parsing requires a dedicated parser (consider `prost` crate in Rust)
- Unified model may lose paradigm-specific nuances

**Dependencies**:
- 02-parsers: Need GraphQL and Protobuf parsers (tree-sitter-graphql exists; protobuf needs custom parsing)
- 07-mcp: MCP tools should expose contract data for AI consumption
- 20-contracts: This IS the contracts category — coordinate closely

---

### R9: Graduated Convention Learning with Bayesian Confidence

**Priority**: P1 (Important)
**Effort**: Medium
**Impact**: More nuanced convention detection; eliminates arbitrary 60% threshold; better handles mixed-convention codebases

**Design for Fresh Build**:

Replace the binary ValueDistribution (dominant at 60% or not) with a graduated Bayesian model:

**1. Convention Strength as Continuous Score**:
Instead of a hard threshold, every convention gets a strength score:
```rust
struct ConventionStrength {
    value: String,                    // The convention value (e.g., "camelCase")
    frequency: f64,                   // 0.0-1.0 — proportion of files using this
    file_count: usize,                // Absolute count
    confidence: f64,                  // Bayesian posterior probability
    trend: ConventionTrend,           // Rising | Stable | Declining
    category: ConventionCategory,     // Universal | ProjectSpecific | Emerging | Legacy
}

enum ConventionCategory {
    Universal,       // >90% frequency, seen across many projects
    ProjectSpecific, // >60% frequency, specific to this project
    Emerging,        // <60% but rising trend
    Legacy,          // Was dominant, now declining
    Contested,       // Two or more conventions at similar frequency (40-60% each)
}
```

**2. Bayesian Posterior for Confidence**:
Use a Beta-Binomial model where each file is a Bernoulli trial:
```
Prior: Beta(α=1, β=1)  — uniform prior (no assumption)
Posterior: Beta(α + successes, β + failures)
  where successes = files matching convention
        failures = files not matching convention

confidence = posterior_mean = (α + successes) / (α + β + total_files)
```

This naturally handles small samples (few files → wide posterior → low confidence) and large samples (many files → narrow posterior → high confidence) without arbitrary thresholds.

**3. Contested Convention Handling**:
When two conventions are close in frequency (e.g., 45% camelCase vs 40% PascalCase), the v1 system would pick neither (both below 60%) or pick one arbitrarily. The new system:
- Detects the contested state explicitly
- Reports both conventions with their strengths
- Generates an "inconsistency" finding rather than violations against either convention
- Suggests the team make a deliberate choice

**4. Minimum Evidence Requirements**:
```rust
struct LearningConfig {
    min_files: usize,           // 5 (up from 2)
    min_occurrences: usize,     // 10 (up from 3)
    min_confidence: f64,        // 0.7 (Bayesian posterior)
    contested_threshold: f64,   // 0.15 — if top two conventions are within 15%, flag as contested
}
```

**Rationale**:
The Naturalize paper (Allamanis et al., 2014) demonstrated that statistical models of code conventions are effective. Drift's v1 approach is a simplified version. A Bayesian model is more principled, handles uncertainty naturally, and avoids the arbitrary 60% threshold that doesn't account for sample size.

**Evidence**:
- Allamanis et al. (R3): Statistical models effectively capture coding conventions
- Hindle et al. (R11): Software is natural and predictable — statistical approaches work
- ACM Convention Consistency paper (R6): Convention consistency is a measurable quality dimension

**Risks**:
- Bayesian model is harder to explain to developers than "60% threshold"
- Need clear UX for "contested" conventions — developers must understand what it means
- Beta-Binomial assumes independence between files (may not hold for generated code)

**Dependencies**:
- 07-mcp: Convention strength data should be exposed via MCP for AI context
- 09-quality-gates: Gates need to understand convention categories (don't enforce "contested" conventions)

---

### R10: Suggested Fixes as First-Class Output

**Priority**: P1 (Important)
**Effort**: Medium
**Impact**: Dramatically increases developer adoption; reduces cost of addressing violations to near-zero for auto-fixable issues

**Design for Fresh Build**:

Google's data shows developers apply automated fixes ~3,000 times per day on Tricorder. Fixes are not optional — they are a core output of the analysis system. Build the detector system with fixes as a first-class concept from day one:

**1. Fix Categories**:
```rust
enum FixKind {
    /// Exact text replacement — high confidence, safe to auto-apply
    TextEdit { range: Range, new_text: String },
    
    /// Multi-location edit — all edits must be applied together
    MultiEdit { edits: Vec<TextEdit>, description: String },
    
    /// Rename — symbol rename across files
    Rename { old_name: String, new_name: String, scope: RenameScope },
    
    /// Import addition/removal
    ImportChange { action: ImportAction, module: String, specifiers: Vec<String> },
    
    /// Structural — move code, extract function, etc.
    Structural { description: String, edits: Vec<TextEdit> },
    
    /// Suggestion — human must decide, AI can help
    Suggestion { description: String, options: Vec<FixOption> },
}

struct Fix {
    kind: FixKind,
    confidence: f64,          // How confident we are this fix is correct
    is_safe: bool,            // Can be auto-applied without review
    description: String,      // Human-readable explanation
    detector_id: String,      // Which detector generated this fix
}
```

**2. Fix Generation Contract**:
Every detector must implement:
```rust
trait Detector {
    fn detect(&self, ctx: &DetectionContext) -> DetectionResult;
    
    /// Optional but strongly encouraged — detectors without fixes
    /// are flagged in the detector health dashboard
    fn generate_fix(&self, violation: &Violation, ctx: &DetectionContext) -> Option<Fix>;
    
    /// Percentage of violations this detector can auto-fix
    fn fix_coverage(&self) -> f64;
}
```

**3. Fix Safety Levels**:
```
Level 1 — Auto-apply: Pure formatting, naming convention alignment, import ordering
Level 2 — Apply with review: Code structure changes, pattern migration
Level 3 — Suggestion only: Architectural changes, security fixes that may change behavior
```

**4. Batch Fix Application**:
```
drift fix --auto          # Apply all Level 1 fixes
drift fix --review        # Apply Level 1+2 with diff preview
drift fix --category=security  # Fix only security violations
drift fix --detector=structural/file-naming  # Fix specific detector
```

**Rationale**:
Google found that suggested fixes are the single most effective way to increase developer adoption of static analysis. A violation without a fix is a complaint; a violation with a fix is a gift. Building fixes as first-class from the start ensures every detector author thinks about remediation, not just detection.

**Evidence**:
- Google Tricorder (R1): "Anything that can be fixed automatically should be fixed automatically"
- Google SWE Book (R1): "Automated fixes serve as additional documentation" and "reduce the cost to addressing static analysis issues"
- Semgrep (R2): AST-based autofix for precise code transformations

**Risks**:
- Incorrect fixes are worse than no fixes — they introduce bugs
- Fix confidence scoring is critical — only auto-apply when confidence is very high
- Multi-file fixes (e.g., rename) require transactional semantics

**Dependencies**:
- 11-ide: VSCode extension must support fix preview and application
- 10-cli: CLI must support batch fix application
- 07-mcp: MCP tools should expose available fixes for AI-assisted remediation

---

### R11: Framework Detection as Composable Middleware

**Priority**: P2 (Nice to have for initial release, important for ecosystem growth)
**Effort**: Medium
**Impact**: Enables community-contributed framework support; reduces framework detector maintenance burden

**Design for Fresh Build**:

Instead of the v1 approach of embedding framework detectors within each category (leading to 60+ framework-specific files scattered across the codebase), design framework support as a composable middleware layer:

**1. Framework Detection Phase**:
Before running detectors, identify which frameworks are in use:
```rust
struct ProjectFrameworks {
    detected: Vec<FrameworkInfo>,
    confidence: HashMap<String, f64>,
}

struct FrameworkInfo {
    name: String,              // "spring-boot", "laravel", "react", etc.
    version: Option<String>,
    language: Language,
    evidence: Vec<FrameworkEvidence>,  // What triggered detection
}

enum FrameworkEvidence {
    PackageJson { dependency: String, version: String },
    ImportStatement { module: String, file: String },
    ConfigFile { path: String },
    DirectoryStructure { pattern: String },
    FileContent { pattern: String, file: String },
}
```

**2. Framework Middleware**:
Framework support is a middleware that enriches the detection context:
```rust
trait FrameworkMiddleware {
    fn framework_id(&self) -> &str;
    fn detect_framework(&self, project: &ProjectContext) -> Option<FrameworkInfo>;
    fn enrich_context(&self, ctx: &mut DetectionContext, framework: &FrameworkInfo);
    fn additional_patterns(&self) -> Vec<PatternDefinition>;
    fn node_type_mappings(&self) -> HashMap<String, String>;  // Framework-specific → generic
}
```

The middleware enriches the detection context with framework-specific knowledge:
- Spring's `@GetMapping` → generic route pattern
- Laravel's `Route::get()` → generic route pattern
- Django's `path()` → generic route pattern

This means the core route detector works for all frameworks — the middleware normalizes framework idioms to generic patterns.

**3. Framework Plugin System**:
```
drift-framework-spring/     — Spring Boot middleware
drift-framework-laravel/    — Laravel middleware
drift-framework-django/     — Django middleware
drift-framework-react/      — React middleware
drift-framework-express/    — Express middleware
...
```

Each plugin is a separate crate/package that implements `FrameworkMiddleware`. This enables:
- Community contributions without touching core code
- Independent versioning and release cycles
- Optional installation (don't load Spring middleware for a Python project)

**4. Coverage Expansion Plan**:

| Tier | Frameworks | Rationale |
|------|-----------|-----------|
| Tier 1 (Launch) | React, Express, Spring Boot, Django, Laravel | Most popular per language |
| Tier 2 (3 months) | Vue, Angular, FastAPI, ASP.NET, Next.js, Nest.js | Strong enterprise adoption |
| Tier 3 (6 months) | Svelte, Remix, Gin, Axum, Phoenix, Rails | Growing ecosystems |
| Community | Everything else | Plugin system enables community contributions |

**Rationale**:
The v1 approach of 60+ framework-specific files scattered across 12 categories is unmaintainable. A middleware architecture centralizes framework knowledge, reduces duplication, and enables community growth. ESLint's plugin ecosystem proves this model works at scale.

**Evidence**:
- ESLint plugin architecture (R5): Extensible plugin system enables community contributions
- Semgrep (R2): Language-agnostic core with per-language plugins

**Risks**:
- Middleware abstraction may not capture all framework-specific nuances
- Plugin API stability is critical — breaking changes affect all framework plugins
- Community contributions require review and quality standards

**Dependencies**:
- 02-parsers: Framework detection needs access to package manifests and config files
- 12-infrastructure: Plugin distribution and versioning infrastructure

---

### R12: Detector Testing and Validation Framework

**Priority**: P2 (Nice to have for launch, critical for long-term quality)
**Effort**: Medium
**Impact**: Ensures detector correctness; enables confident refactoring; provides regression protection

**Design for Fresh Build**:

Build a dedicated testing framework for detectors that goes beyond unit tests:

**1. Snapshot Testing with Annotated Fixtures**:
Each detector gets a fixture directory with annotated source files:
```
tests/fixtures/security/sql-injection/
├── vulnerable.ts          # Files with known vulnerabilities
├── safe.ts                # Files that should NOT trigger
├── edge-cases.ts          # Tricky cases
└── expected.json          # Expected detection results
```

Fixture files use inline annotations:
```typescript
// @drift-expect: sql-injection, confidence>=0.8, cwe=89
const query = `SELECT * FROM users WHERE id = ${userId}`;

// @drift-expect: none
const query = db.query('SELECT * FROM users WHERE id = ?', [userId]);
```

**2. Cross-Language Parity Testing**:
For detectors that should work across languages, test the same logical pattern in all supported languages:
```
tests/fixtures/errors/try-catch/
├── typescript.ts
├── python.py
├── java.java
├── go.go
├── rust.rs
└── expected.json          # Same expected patterns for all languages
```

This catches language-specific regressions and validates the GAST normalization layer (R4).

**3. False-Positive Regression Tests**:
Maintain a corpus of known false positives that have been fixed:
```
tests/false-positives/
├── security/sql-injection/
│   ├── fp-001-template-literal.ts    # Was flagged, shouldn't be
│   ├── fp-002-orm-query.py           # Was flagged, shouldn't be
│   └── manifest.json                 # Metadata about each FP
```

Every CI run verifies these files produce zero findings. If a code change reintroduces a known FP, the test fails.

**4. Confidence Calibration Tests**:
Verify that confidence scores are well-calibrated:
```rust
#[test]
fn confidence_calibration() {
    // Patterns with confidence 0.9 should be correct ~90% of the time
    let results = run_detector_on_corpus("calibration-corpus/");
    let high_confidence = results.iter().filter(|r| r.confidence >= 0.85);
    let true_positive_rate = high_confidence.filter(|r| r.is_true_positive).count() as f64
        / high_confidence.count() as f64;
    assert!(true_positive_rate >= 0.85, "High-confidence findings should be ≥85% accurate");
}
```

**5. Performance Benchmarks**:
Each detector has a performance budget:
```rust
#[bench]
fn sql_injection_detector_10k_files(b: &mut Bencher) {
    let corpus = load_benchmark_corpus("10k-mixed-language");
    b.iter(|| {
        let detector = SqlInjectionDetector::new();
        for file in &corpus {
            detector.detect(file);
        }
    });
    // Assert: < 100ms for 10,000 files
}
```

**Rationale**:
Google's Tricorder requires <10% effective false-positive rate for every analyzer. This is only achievable with rigorous testing. Building the testing framework alongside the detectors (not after) ensures quality from day one.

**Evidence**:
- Google Tricorder (R1): Analyzers must produce <10% effective false positives
- Semgrep (R2): Extensive test corpus for each rule with true/false positive annotations
- Google SWE Book (R1): "We only deploy analysis tools with low false-positive rates"

**Risks**:
- Maintaining test fixtures is ongoing work — needs to be part of the detector contribution process
- Calibration corpus requires manual labeling of true/false positives
- Performance benchmarks may be flaky on different hardware

**Dependencies**:
- 12-infrastructure: CI must run detector tests and benchmarks
- 17-test-topology: Test framework detection can validate the testing framework itself

---

## Recommendation Priority Matrix

| # | Recommendation | Priority | Effort | Category |
|---|---------------|----------|--------|----------|
| R1 | Single-Pass Visitor Pattern | P0 | High | Architecture |
| R2 | Incremental Detection | P0 | Medium | Performance |
| R3 | Temporal Confidence Decay + Momentum | P0 | Medium | Algorithm |
| R4 | Generic AST Normalization Layer | P1 | High | Architecture |
| R5 | Effective False-Positive Tracking | P1 | Medium | Developer Experience |
| R6 | Outlier Detection Refinements | P1 | Low | Algorithm |
| R7 | OWASP/CWE Security Alignment | P1 | High | Security |
| R8 | Contract Detection Expansion | P1 | High | API |
| R9 | Bayesian Convention Learning | P1 | Medium | Algorithm |
| R10 | Suggested Fixes as First-Class | P1 | Medium | Developer Experience |
| R11 | Framework Middleware Architecture | P2 | Medium | Architecture |
| R12 | Detector Testing Framework | P2 | Medium | Reliability |

## Implementation Order (Fresh Build)

Since this is a greenfield build, the implementation order matters for foundation-laying:

```
Phase 1 — Core Engine (Weeks 1-4):
  R1: Visitor pattern detection engine (this IS the engine — build it first)
  R6: Outlier detection with correct thresholds (pure math, no dependencies)
  R3: Confidence scoring with decay + momentum (pure math, no dependencies)
  R9: Bayesian convention learning (core algorithm)

Phase 2 — Detection Infrastructure (Weeks 5-8):
  R4: Generic AST normalization layer (depends on parsers being ready)
  R2: Incremental detection (depends on storage layer)
  R12: Testing framework (build alongside first detectors)

Phase 3 — Detector Categories (Weeks 9-16):
  R7: Security detectors with OWASP/CWE mapping (highest-value category)
  R10: Fix generation for each detector (build fixes alongside detectors)
  R8: Contract detection (REST first, then GraphQL, then gRPC)

Phase 4 — Ecosystem (Weeks 17-20):
  R11: Framework middleware system + Tier 1 frameworks
  R5: Feedback loop integration (needs IDE + CLI integration)
```

## Cross-Category Impact Analysis

| Recommendation | Categories Affected | Impact Type |
|---------------|-------------------|-------------|
| R1 (Visitor) | 01-rust-core, 02-parsers | Requires AST traversal API changes |
| R2 (Incremental) | 08-storage, 25-services | New cache tables, pipeline changes |
| R3 (Decay) | 08-storage, 23-pattern-repo | New history tables, query changes |
| R4 (GAST) | 01-rust-core, 02-parsers | New normalization layer between parsing and detection |
| R5 (Feedback) | 07-mcp, 10-cli, 11-ide | New tracking endpoints in all presentation layers |
| R7 (Security) | 09-quality-gates, 21-security | Security findings feed gates and security analysis |
| R8 (Contracts) | 02-parsers, 07-mcp, 20-contracts | New parsers (GraphQL, protobuf), new MCP tools |
| R9 (Bayesian) | 07-mcp, 09-quality-gates | Convention data format changes affect consumers |
| R10 (Fixes) | 10-cli, 11-ide, 07-mcp | Fix application in all presentation layers |
| R11 (Frameworks) | 02-parsers, 12-infrastructure | Plugin loading, framework detection |

## Quality Checklist

- [x] 12 recommendations documented
- [x] Each recommendation has clear rationale with cited evidence
- [x] All recommendations framed for greenfield build (no migration constraints)
- [x] Priorities justified (P0 = foundational engine, P1 = core features, P2 = ecosystem)
- [x] Effort assessed for each recommendation
- [x] Risks identified for each recommendation
- [x] Cross-category dependencies mapped for each recommendation
- [x] Implementation order accounts for dependency chains
- [x] Rust implementation sketches provided where applicable
- [x] Cross-category impact analysis completed
- [x] All 12 research sources referenced across recommendations
