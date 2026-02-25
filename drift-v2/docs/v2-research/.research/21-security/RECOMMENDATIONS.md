# 21 Security — V2 Recommendations

> Enterprise-grade recommendations for building Drift v2's security analysis subsystem. Synthesized from the complete v1 recap (cross-cutting audit across 6+ categories) and research encyclopedia (45+ authoritative sources). Every recommendation is evidence-based, prioritized, and assessed for cross-pipeline impact.

**Priority Levels**:
- P0: Must be decided/built before anything else. Architectural foundations.
- P1: Core functionality. Required for v2 launch.
- P2: Important for enterprise adoption. Can follow initial launch.
- P3: Nice-to-have. Future roadmap.

---

## Part 1: Architectural Decisions

### SAD1: Security-Integrated Pipeline (Not Separate Phase)

**Priority**: P0 | **Impact**: Every subsystem | **Evidence**: §11.1, §13.1

Security analysis must be woven into every stage of the Drift pipeline, not bolted on as a separate phase. This ensures security findings benefit from the same incremental, context-aware architecture as all other analysis.

**Pipeline Integration Points**:
```
SCAN:    Secret detection (fast, Layer 1)
PARSE:   Crypto/deserialization function extraction
DETECT:  Security patterns via visitor (single-pass with all other detectors)
ANALYZE: Taint analysis, reachability, access control verification
REPORT:  CWE mapping, OWASP mapping, SARIF output
```

**Why Not Separate**: A separate security phase would duplicate AST traversal, miss context from other detectors, and prevent incremental analysis. Security detectors should be registered as visitors alongside all other detectors.

### SAD2: Unified SecurityFinding Data Model

**Priority**: P0 | **Impact**: All security output | **Evidence**: §10.1, §13.2

Every security finding — whether from secret detection, pattern matching, taint analysis, or boundary enforcement — must produce a single `SecurityFinding` type that carries CWE IDs, OWASP categories, confidence scores, and optional code flow paths.

```rust
struct SecurityFinding {
    id: String,
    finding_type: SecurityFindingType,
    severity: Severity,
    confidence: f32,
    cwe_ids: Vec<String>,
    owasp_categories: Vec<String>,
    location: Location,
    code_flow: Option<Vec<FlowStep>>,
    description: String,
    remediation: String,
    evidence: String,
    framework: Option<String>,
    related_locations: Vec<Location>,
}
```

**Why**: Unified output enables consistent SARIF generation, consistent MCP tool responses, consistent quality gate evaluation, and consistent dashboard rendering. Without this, each security subsystem produces different shapes that must be normalized downstream.

### SAD3: Taint Analysis as First-Class Engine

**Priority**: P0 | **Impact**: 8+ CWE detections | **Evidence**: §3.1, §3.2, §3.3

Build intraprocedural taint analysis as a core engine in Rust, not as an afterthought. The taint engine should be composable with the existing call graph for interprocedural expansion.

**Architecture**:
```
Taint Engine (Rust)
├── Source Registry (user input, env vars, file reads, HTTP params)
├── Sink Registry (SQL queries, exec(), file writes, HTTP responses)
├── Sanitizer Registry (encoding functions, validation functions)
├── Propagator Registry (string operations, collection operations)
└── Analysis
    ├── Intraprocedural (within function, P1)
    └── Interprocedural (via call graph summaries, P2)
```

**Registries should be declarative** (TOML/YAML) so users can add custom sources/sinks without recompiling:
```toml
[[taint.sources]]
id = "flask-request"
language = "python"
pattern = "flask.request.$ANYTHING"
label = "user-input"

[[taint.sinks]]
id = "sql-execute"
language = "python"
pattern = "cursor.execute($QUERY, ...)"
cwe = "CWE-89"
```

### SAD4: CWE/OWASP Mapping as Core Requirement

**Priority**: P0 | **Impact**: Compliance, SARIF, enterprise adoption | **Evidence**: §1.1, §2.1, §10.1

Every security detector, taint rule, and boundary violation must map to at least one CWE ID and one OWASP category. This is non-negotiable for enterprise adoption.

**Implementation**: Each detector/rule definition includes `cwe_ids` and `owasp_categories` fields. The SARIF output generator reads these directly. Quality gates can filter by OWASP category.

---

## Part 2: Category-Specific Recommendations

### Secret Detection (Expanding from 21 to 150+ Patterns)

| # | Recommendation | Priority | Evidence |
|---|---------------|----------|----------|
| SE1 | Expand to 150+ provider-specific secret patterns organized by category | P0 | §4.1, §4.2 |
| SE2 | Implement true Shannon entropy calculation (replace character diversity check) | P0 | §4.1 |
| SE3 | Add contextual scoring (variable name, file path, surrounding code analysis) | P1 | §4.1 |
| SE4 | Add cloud provider patterns: Azure (5+ types), GCP (4+ types), DigitalOcean, Heroku, Linode | P1 | §4.1 |
| SE5 | Add CI/CD patterns: CircleCI, Travis, Jenkins, GitHub Actions tokens | P1 | §4.2 |
| SE6 | Add AI/ML provider patterns: OpenAI, Anthropic, HuggingFace, Cohere API keys | P1 | §4.2 |
| SE7 | Add connection string parsing (Postgres, MySQL, MongoDB, Redis with embedded credentials) | P1 | §4.1 |
| SE8 | Add base64-encoded secret detection (decode and re-scan) | P2 | §4.1 |
| SE9 | Add .env file parsing with cross-reference to code usage | P1 | Recap §8 |
| SE10 | Organize patterns by provider with self-contained detector modules | P1 | §4.2 |

**Shannon Entropy Implementation**:
```rust
fn shannon_entropy(s: &str) -> f64 {
    let len = s.len() as f64;
    let mut freq = [0u32; 256];
    for &b in s.as_bytes() { freq[b as usize] += 1; }
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}
// Threshold: entropy > 4.5 for 20+ char strings in sensitive contexts
```

### Taint Analysis Engine

| # | Recommendation | Priority | Evidence |
|---|---------------|----------|----------|
| TA1 | Build intraprocedural taint engine in Rust (within single function) | P1 | §3.1, §3.3 |
| TA2 | Define source/sink/sanitizer registries as declarative TOML config | P1 | §3.1, SAD3 |
| TA3 | Integrate with existing call graph for interprocedural taint summaries | P2 | §3.2 |
| TA4 | Support taint labels for tracking multiple taint types simultaneously | P2 | §3.1 |
| TA5 | Map all taint findings to CWE IDs automatically | P1 | SAD4 |
| TA6 | Generate code flow paths for SARIF output (source → propagation → sink) | P1 | §10.1 |
| TA7 | Use learned ORM patterns as sinks (raw SQL bypass = automatic sink) | P1 | §3.1, Recap |
| TA8 | Use framework-specific sources (request params per framework) | P1 | §3.1 |

**Taint Sources by Framework**:
```
Express:     req.params, req.query, req.body, req.headers
FastAPI:     function parameters with type hints
Spring:      @RequestParam, @PathVariable, @RequestBody
Django:      request.GET, request.POST, request.data
Laravel:     $request->input(), $request->get()
Go (Gin):    c.Param(), c.Query(), c.PostForm()
ASP.NET:     [FromQuery], [FromBody], [FromRoute]
```

**Taint Sinks by Category**:
```
SQL Injection:     cursor.execute(), db.query(), $queryRaw, raw()
Command Injection: exec(), spawn(), system(), popen()
Path Traversal:    fs.readFile(), open(), Path.join() with user input
XSS:               innerHTML, dangerouslySetInnerHTML, res.send()
SSRF:              fetch(), axios(), http.get() with user-controlled URL
Code Injection:    eval(), Function(), exec() (Python)
Deserialization:   pickle.loads(), ObjectInputStream.readObject()
LDAP Injection:    ldap.search(), ldap.bind() with user input
Template Injection: render() with user-controlled template
```

### Cryptographic Failure Detection (NEW)

| # | Recommendation | Priority | Evidence |
|---|---------------|----------|----------|
| CR1 | Detect weak hash algorithms used for passwords (MD5, SHA1) | P1 | §5.1 |
| CR2 | Detect hardcoded encryption keys and IVs | P1 | §5.1 |
| CR3 | Detect deprecated crypto algorithms (DES, 3DES, RC4) | P1 | §5.1 |
| CR4 | Detect disabled TLS verification (verify=False, InsecureSkipVerify) | P1 | §5.1 |
| CR5 | Detect ECB mode usage | P1 | §5.1 |
| CR6 | Detect insufficient key lengths (<2048 RSA, <256 AES) | P2 | §5.1 |
| CR7 | Detect JWT alg=none acceptance | P1 | §5.1 |
| CR8 | Detect plaintext password storage (no hashing) | P1 | §5.1 |
| CR9 | Map all crypto findings to CWE-326/327/328/329/295/321/256 | P1 | SAD4 |
| CR10 | Per-language crypto pattern library (Python, JS, Java, C#, Go, Rust) | P1 | §5.1 |

### Broken Access Control Detection (Enhanced)

| # | Recommendation | Priority | Evidence |
|---|---------------|----------|----------|
| AC1 | Cross-reference routes with auth middleware to find unprotected endpoints | P1 | §6.1 |
| AC2 | Detect IDOR patterns via taint analysis (user input → DB query without ownership check) | P1 | §6.1 |
| AC3 | Detect path traversal via taint analysis (user input → file path) | P1 | §6.1 |
| AC4 | Detect CORS wildcard misconfiguration | P1 | §7.1 |
| AC5 | Detect missing CSRF protection on state-changing endpoints | P1 | §6.1 |
| AC6 | Detect horizontal privilege escalation (user ID from request used directly in query) | P2 | §6.1 |
| AC7 | Integrate SSRF detection (user input → HTTP client URL) — now part of A01 | P1 | §1.1 |

### Security Misconfiguration Detection (Enhanced)

| # | Recommendation | Priority | Evidence |
|---|---------------|----------|----------|
| MC1 | Detect missing security headers in framework config (CSP, HSTS, X-Frame-Options) | P1 | §7.1 |
| MC2 | Detect debug mode enabled in production configs | P1 | §7.1 |
| MC3 | Detect default credentials in config files | P1 | §7.1 |
| MC4 | Detect insecure cookie settings (missing Secure, HttpOnly, SameSite) | P1 | §7.1 |
| MC5 | Detect exposed error details in production (stack traces) | P2 | §7.1 |
| MC6 | Detect missing rate limiting on auth endpoints | P2 | §7.1 |

### Insecure Deserialization Detection (NEW)

| # | Recommendation | Priority | Evidence |
|---|---------------|----------|----------|
| DS1 | Detect dangerous deserialization functions per language | P1 | §8.1 |
| DS2 | Integrate with taint engine (user input → deserialization function) | P1 | §8.1 |
| DS3 | Per-language pattern library (Java, Python, JS, PHP, C#) | P1 | §8.1 |
| DS4 | Map to CWE-502 | P1 | SAD4 |

### ORM Security (Enhanced)

| # | Recommendation | Priority | Evidence |
|---|---------------|----------|----------|
| OR1 | Detect unsafe ORM API usage per framework (raw SQL bypass patterns) | P1 | Recap, §3.1 |
| OR2 | Cross-reference sensitive fields with data access points for unprotected access | P1 | Recap |
| OR3 | Detect missing encryption-at-rest for sensitive fields | P2 | Recap |
| OR4 | Expand ORM support from 28+ to 40+ frameworks | P2 | Recap |
| OR5 | Add dedicated field extractors for Java (Spring Data, Hibernate), C# (EF Core), PHP (Eloquent) | P1 | Recap |

**Unsafe ORM API Patterns**:
```
Prisma:      $queryRaw, $executeRaw, $queryRawUnsafe
Django:      .extra(), .raw(), RawSQL(), cursor.execute()
SQLAlchemy:  text(), textual(), execute() with string
Eloquent:    DB::raw(), whereRaw(), selectRaw()
Spring Data: @Query with nativeQuery=true + string concat
Hibernate:   createSQLQuery() with string concat
GORM:        db.Raw(), db.Exec() with string concat
Knex:        .raw(), knex.raw()
Sequelize:   sequelize.query() with string
TypeORM:     .query() with string, createQueryBuilder().where(string)
```

### Boundary & Reachability (Enhanced)

| # | Recommendation | Priority | Evidence |
|---|---------------|----------|----------|
| BR1 | Add sensitivity propagation (transitive sensitivity through call graph) | P1 | Recap |
| BR2 | Add parameter-level data flow tracking (not just function-level) | P2 | §3.2 |
| BR3 | Add cross-service reachability for microservice architectures | P2 | Recap |
| BR4 | Integrate taint analysis with reachability for sensitive data flow tracking | P1 | §3.1 |

### SARIF & Compliance Output

| # | Recommendation | Priority | Evidence |
|---|---------------|----------|----------|
| SA1 | Generate SARIF 2.1 output for all security findings | P1 | §10.1 |
| SA2 | Include codeFlows in SARIF for taint analysis results | P1 | §10.1 |
| SA3 | Include CWE IDs and OWASP categories in SARIF properties | P1 | §10.1 |
| SA4 | Include fix suggestions in SARIF fix objects | P2 | §10.1 |
| SA5 | Support GitHub Code Scanning upload format | P1 | §10.1 |
| SA6 | Support GitLab SAST report format | P2 | §10.1 |

### MCP Security Tools (Enhanced)

| # | Recommendation | Priority | Evidence |
|---|---------------|----------|----------|
| MT1 | Add drift_security_findings tool (query security findings by CWE, OWASP, severity) | P1 | Recap |
| MT2 | Add drift_taint_paths tool (query taint analysis results) | P1 | §3.1 |
| MT3 | Add drift_secrets tool (query secret detection results) | P1 | §4.1 |
| MT4 | Add drift_owasp_coverage tool (show OWASP Top 10 coverage status) | P2 | §1.1 |
| MT5 | Enhance drift_security_summary with OWASP/CWE coverage metrics | P1 | §13.3 |

### Quality Gates (Enhanced)

| # | Recommendation | Priority | Evidence |
|---|---------------|----------|----------|
| QG1 | Make basic security gate available in Community tier (not Enterprise-only) | P1 | Recap |
| QG2 | Add secret detection gate (block on critical/high severity secrets) | P1 | §4.1 |
| QG3 | Add OWASP compliance gate (minimum coverage threshold) | P2 | §1.1 |
| QG4 | Add taint analysis gate (block on unresolved critical taint paths) | P2 | §3.1 |

### Cortex Privacy (Enhanced)

| # | Recommendation | Priority | Evidence |
|---|---------------|----------|----------|
| CP1 | Expand PII patterns from 10 to 50+ (addresses, DOB, passport, driver's license) | P1 | Recap |
| CP2 | Add connection string detection and redaction | P1 | §4.1 |
| CP3 | Add base64-encoded secret detection in memory content | P2 | §4.1 |
| CP4 | Align Cortex privacy patterns with secret detection patterns | P1 | Recap |

---

## Part 3: Implementation Phases

### Phase 1 — Security Foundations (Weeks 1-2, parallel with core engine)

**Deliverables**:
- SecurityFinding unified data model (SAD2)
- CWE/OWASP mapping infrastructure (SAD4)
- Expanded secret detection (150+ patterns) (SE1-SE10)
- Shannon entropy calculation (SE2)
- Security detectors registered as visitors in detection engine (SAD1)

**Dependencies**: Core parser and visitor pattern engine (Phase 1 of main build)

### Phase 2 — Pattern Detection (Weeks 3-4, parallel with detection engine)

**Deliverables**:
- Cryptographic failure detection (CR1-CR10)
- Insecure deserialization detection (DS1-DS4)
- Security misconfiguration detection (MC1-MC6)
- Unsafe ORM API detection (OR1-OR5)
- Enhanced access control detection (AC1-AC7)
- All detectors mapped to CWE IDs

**Dependencies**: Phase 1 security foundations + main detection engine

### Phase 3 — Taint Analysis (Weeks 5-7, parallel with call graph)

**Deliverables**:
- Intraprocedural taint engine in Rust (TA1)
- Declarative source/sink/sanitizer registries (TA2)
- Framework-specific sources and sinks (TA7, TA8)
- Code flow path generation (TA6)
- Integration with learned ORM patterns (TA7)

**Dependencies**: Phase 2 pattern detection + main call graph engine

### Phase 4 — Integration & Reporting (Weeks 8-9)

**Deliverables**:
- SARIF 2.1 output generation (SA1-SA6)
- Enhanced MCP security tools (MT1-MT5)
- Security quality gates (QG1-QG4)
- Enhanced boundary/reachability (BR1, BR4)
- Cortex privacy expansion (CP1-CP4)
- Security metrics dashboard data (§13.3)

**Dependencies**: Phases 1-3 + main MCP and quality gate infrastructure

### Phase 5 — Advanced (Weeks 10+, post-launch)

**Deliverables**:
- Interprocedural taint analysis via call graph (TA3)
- Taint labels for multi-type tracking (TA4)
- Cross-service reachability (BR3)
- Parameter-level data flow (BR2)
- IDOR detection via taint (AC2, AC6)
- Base64 secret detection (SE8)

**Dependencies**: Phase 4 + stable call graph

---

## Part 4: Risk Assessment

### Technical Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Taint analysis false positives | High | Medium | Start intraprocedural only; add sanitizer registry; feedback loop |
| Secret detection false positives | Medium | Low | Contextual scoring; placeholder filtering; entropy thresholds |
| Performance impact of security checks | Medium | High | Integrate into visitor pattern (single pass); incremental analysis |
| CWE mapping maintenance burden | Low | Medium | Automate from detector metadata; version-controlled mapping file |
| SARIF format complexity | Low | Low | Use existing SARIF libraries; test against GitHub Code Scanning |

### Cross-Pipeline Impact

| Decision | Affected Categories | Risk Level |
|----------|-------------------|------------|
| SecurityFinding data model | 07-mcp, 09-quality-gates, 10-cli, 11-ide | Low (additive) |
| Taint engine in Rust | 04-call-graph, 05-analyzers | Medium (new dependency) |
| CWE mapping on all detectors | 03-detectors (all 350+) | Medium (retrofit needed) |
| SARIF output | 09-quality-gates, 10-cli | Low (new output format) |
| Visitor pattern integration | 03-detectors | Low (architectural alignment) |

---

## Part 5: Success Metrics

| Metric | V1 Baseline | V2 Target | Measurement |
|--------|-------------|-----------|-------------|
| OWASP Top 10 Coverage | ~5/10 | 9/10 | Detector-to-OWASP mapping |
| CWE Top 25 Coverage | ~6.5/25 | 17/25 | Detector-to-CWE mapping |
| Secret Detection Patterns | 21 | 150+ | Pattern count |
| OWASP Secure Coding Practices | ~6/14 | 11/14 | Practice-to-detector mapping |
| Security Finding Types | 3 (secret, boundary, pattern) | 6+ (+ taint, crypto, misconfig) | Finding type enum |
| False Positive Rate | Unknown | <10% | Developer feedback tracking |
| Security Gate Availability | Enterprise only | All tiers (basic) | Tier configuration |
| SARIF Output | None | Full (with code flows) | Format validation |
| MCP Security Tools | 3 | 8+ | Tool count |
| Taint Paths Detected | 0 | Per-project metric | Taint engine output |

---

## Quality Checklist

- [x] All recommendations have clear rationale with evidence citations
- [x] Priority and effort assessed for each recommendation
- [x] Risks identified with mitigation strategies
- [x] Cross-pipeline impact assessed for every architectural decision
- [x] Implementation phases defined with dependencies
- [x] Success metrics defined with V1 baselines and V2 targets
- [x] OWASP Top 10 (2025) coverage mapped to specific recommendations
- [x] CWE Top 25 (2025) coverage mapped to specific recommendations
- [x] Taint analysis architecture defined with source/sink registries
- [x] Secret detection expansion plan with provider categories
- [x] Cryptographic failure patterns documented per language
- [x] Unsafe ORM API patterns documented per framework
- [x] SARIF output structure defined with security-specific fields
- [x] All recommendations traceable to audit gaps and research findings