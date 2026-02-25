# Section 5 Findings: Phase 5 — Structural Intelligence

> **Status:** ✅ DONE
> **Date completed:** 2026-02-08
> **Orchestration plan:** §8 (Phase 5)
> **V2-PREP docs:** 19-COUPLING-ANALYSIS-V2-PREP.md, 20-CONSTRAINT-SYSTEM-V2-PREP.md, 21-CONTRACT-TRACKING-V2-PREP.md, 22-CONSTANTS-ENVIRONMENT-V2-PREP.md, 23-WRAPPER-DETECTION-V2-PREP.md, 24-DNA-SYSTEM-V2-PREP.md, 26-OWASP-CWE-MAPPING-V2-PREP.md, 27-CRYPTOGRAPHIC-FAILURE-DETECTION-V2-PREP.md
>
> **Summary: 8 CONFIRMED, 4 REVISE, 0 REJECT**
>
> This document contains the full research findings for Section 5 of DRIFT-V2-FINAL-RESEARCH-TRACKER.md.
> The tracker file itself should be updated to mark Section 5 as ✅ DONE and reference this file.

---

## Checklist (all validated)

- [x] Robert C. Martin metrics (Ce, Ca, I, A, D) — still the standard for coupling?
- [x] Tarjan's SCC via petgraph — correct algorithm for cycle detection?
- [x] 12 constraint invariant types — comprehensive for architectural enforcement?
- [x] 7 contract paradigms (REST, GraphQL, gRPC, AsyncAPI, tRPC, WebSocket, event-driven) — complete?
- [x] Shannon entropy for secret detection — current best practice? (vs ML-based)
- [x] 100+ secret patterns — how does this compare to gitleaks, trufflehog?
- [x] 14 crypto detection categories — comprehensive vs OWASP A04:2025?
- [x] 261 crypto patterns across 12 languages — coverage sufficient?
- [x] DNA health scoring formula — is the weighting justified?
- [x] RegexSet optimization for single-pass matching — correct approach?
- [x] OWASP 2025 Top 10 — verify the 2025 version exists and categories are correct
- [x] CWE Top 25 2025 — verify the 2025 version exists

---

## Findings

### 1. Robert C. Martin Metrics (Ce, Ca, I, A, D) — ✅ CONFIRMED

The plan uses Robert C. Martin's package coupling metrics from *Agile Software Development, Principles, Patterns, and Practices* (2003):

- **Ca (Afferent Coupling)**: Number of modules that depend on this module
- **Ce (Efferent Coupling)**: Number of modules this module depends on
- **I (Instability)**: Ce / (Ca + Ce) — ranges 0 (maximally stable) to 1 (maximally unstable)
- **A (Abstractness)**: Abstract exports / total exports — ranges 0 (concrete) to 1 (abstract)
- **D (Distance from Main Sequence)**: |A + I - 1| — ranges 0 (ideal) to 1 (worst)

These metrics remain the industry standard for package-level coupling analysis in 2025-2026. They are actively implemented in:

- **NDepend** (C#/.NET): Uses the exact same Ca, Ce, I, A, D metrics with zone classification. NDepend is the most widely used .NET architecture analysis tool and continues to feature Martin metrics prominently.
- **JDepend** (Java): The original Java implementation of Martin metrics. Still referenced in Apache project reports (e.g., Apache Shiro's JDepend reports use the exact same formulas).
- **SonarQube**: Tracks afferent/efferent coupling as part of its architecture metrics.
- **Structure101**: Uses Martin metrics for dependency structure analysis.
- **Lattix**: Architecture analysis tool using DSM (Dependency Structure Matrix) with Martin metrics.

The zone classification (Zone of Pain = low I + low A; Zone of Uselessness = high I + high A; Main Sequence = A + I ≈ 1) is the standard visualization for these metrics. The plan's thresholds (zone_of_pain_instability_max = 0.3, zone_of_pain_abstractness_max = 0.3, zone_of_uselessness_instability_min = 0.7, zone_of_uselessness_abstractness_min = 0.7) match the standard thresholds used by NDepend and JDepend.

No modern alternative has displaced Martin metrics for package-level coupling analysis. While newer approaches exist for microservice-level coupling (e.g., temporal coupling from co-change analysis, semantic coupling from NLP), Martin metrics remain the standard for module/package-level structural analysis within a codebase.

**One note**: The plan correctly adds module roles (Hub, Authority, Balanced, Isolated) which are not part of Martin's original metrics but are a natural extension based on Ca/Ce thresholds. This is a value-add, not a deviation.

---

### 2. Tarjan's SCC via petgraph — ✅ CONFIRMED

The plan uses `petgraph::algo::tarjan_scc()` for cycle detection in the coupling dependency graph. This is the correct algorithm choice for several reasons:

**Algorithm correctness**: Tarjan's SCC algorithm runs in O(V+E) time — a single DFS pass identifies all strongly connected components. Each SCC with >1 node represents a dependency cycle. This is strictly superior to the v1 approach (hand-rolled DFS with recursion stack) which can miss edge cases like self-loops and disconnected components.

**petgraph implementation**: petgraph 0.8.3 (confirmed current in Section 1) provides `tarjan_scc()` as a stable API. The function returns `Vec<Vec<NodeIndex>>` — each inner Vec is one SCC. The implementation handles all edge cases correctly (self-loops, disconnected components, single-node SCCs). petgraph also provides `condensation()` which generates the DAG of SCCs — exactly what the plan needs for Phase 4 (Condensation Graph Generation).

**Production validation**: The Cortex workspace already uses `petgraph::algo::tarjan_scc` in `cortex-causal/src/graph/dag_enforcement.rs` — this is a proven pattern within the project's own codebase. Tarjan's algorithm is the standard for SCC detection in production systems (used in compiler dependency analysis, build systems, and graph databases).

**vs Kosaraju's algorithm**: Kosaraju's also runs in O(V+E) but requires two DFS passes and a transposed graph. Tarjan's is preferred because it uses a single pass and doesn't need the transpose. petgraph provides both (`tarjan_scc` and `kosaraju_scc`), but Tarjan's is the right choice for Drift's use case.

**vs Incremental SCC**: For incremental coupling analysis (when only some modules change), a full Tarjan's run on the complete graph is still fast enough — O(V+E) on a 5,000-module graph is sub-millisecond. The plan correctly notes that incremental invalidation happens at the metrics level (only recompute Ca/Ce/I/A/D for affected modules), not at the SCC level. This is the right tradeoff.

---

### 3. 12 Constraint Invariant Types — ✅ CONFIRMED

The plan defines 12 invariant types for architectural enforcement:

1. **MustHave** — Required element present (AST pattern match)
2. **MustNotHave** — Forbidden element absent (negated pattern match)
3. **MustPrecede** — Ordering A before B (call graph path query)
4. **MustFollow** — Ordering A after B (call graph path query)
5. **MustColocate** — X and Y in same location (file path comparison)
6. **MustSeparate** — X and Y in different locations (file path comparison)
7. **MustWrap** — X wrapped in Y, e.g. try/catch (AST containment check)
8. **MustPropagate** — Error/event propagation through chain (call graph reachability)
9. **Cardinality** — Count constraints min/max (count query on ParseResult)
10. **DataFlow** — Data must not flow from X to Y (taint analysis)
11. **Naming** — Match naming pattern (regex/glob matching)
12. **Structure** — Module must contain X (file system check)

**Comparison with existing architectural constraint tools**:

- **ArchUnit** (Java): The most popular architectural testing library. ArchUnit supports: class dependency rules, layer dependency rules, cycle detection, naming conventions, annotation checks, inheritance rules, and custom predicates. Drift's 12 types cover all of ArchUnit's core capabilities and add call-graph-based constraints (MustPrecede, MustFollow, MustPropagate) and taint-based constraints (DataFlow) that ArchUnit cannot express.

- **Dependency-Cruiser** (JavaScript/TypeScript): Supports dependency rules (allowed/forbidden), circular dependency detection, and orphan detection. Drift's MustHave/MustNotHave/MustSeparate/MustColocate cover Dependency-Cruiser's rule types. Drift adds AST-level constraints that Dependency-Cruiser cannot express.

- **ArchUnitNET** (C#): Port of ArchUnit for .NET. Same capabilities as ArchUnit.

- **Deptrac** (PHP): Layer-based dependency rules. Subset of Drift's capabilities.

**The 12 types are comprehensive for the following reasons**:

1. They cover all four verification domains: AST (MustHave, MustNotHave, MustWrap, Cardinality, Naming), file system (MustColocate, MustSeparate, Structure), call graph (MustPrecede, MustFollow, MustPropagate), and data flow (DataFlow).

2. The upgrade from v1 regex-based verification to AST/call-graph/taint-based verification is a significant improvement. v1 could only verify text patterns; v2 can verify structural relationships.

3. The `requires_call_graph()`, `requires_taint_analysis()`, `requires_ast()`, and `requires_filesystem()` methods on the enum enable graceful degradation — constraints that require unavailable data sources (e.g., DataFlow before taint analysis is built) can be deferred rather than failing.

**One potential gap**: There's no explicit "PerformanceBudget" or "SizeBudget" constraint type (e.g., "this module must not exceed 500 LOC" or "this function must not exceed cyclomatic complexity 10"). However, the Cardinality type with appropriate selectors could express these. The plan's `size_limit` and `complexity_limit` from the original 12 types in the orchestration plan (§8.3) appear to have been folded into Cardinality in the V2-PREP doc. This is acceptable — Cardinality with a max bound is semantically equivalent to a size/complexity limit.

---

### 4. 7 Contract Paradigms — ✅ CONFIRMED

The plan covers 7 API contract paradigms:

1. **REST** — HTTP endpoints with request/response schemas (OpenAPI 3.0/3.1)
2. **GraphQL** — Query/mutation/subscription types (GraphQL SDL, October 2021 spec)
3. **gRPC** — Protocol Buffers services and messages (proto3)
4. **AsyncAPI** — Event-driven async message contracts (AsyncAPI 2.x/3.0)
5. **tRPC** — TypeScript-only RPC procedures
6. **WebSocket** — Real-time bidirectional messaging
7. **Event-Driven** — Kafka, RabbitMQ, SNS/SQS, Redis pub/sub

**2025-2026 API landscape validation**:

The 7 paradigms cover the major API styles identified in industry surveys. Nordic APIs' "Top API Architectural Styles of 2025" lists REST, GraphQL, gRPC, WebSocket, and event-driven as the dominant paradigms. tRPC is a TypeScript-specific paradigm that has gained significant adoption in the Next.js/T3 stack ecosystem.

**Schema-first parsing validation**:
- **OpenAPI 3.1.0**: Current stable version. The plan correctly targets 3.0 and 3.1 support. OpenAPI 3.1 aligns with JSON Schema 2020-12, which is a significant change from 3.0's extended subset of JSON Schema draft-07.
- **GraphQL SDL**: The October 2021 spec is still the current stable GraphQL specification. No newer version has been released.
- **Protocol Buffers proto3**: Still the current protobuf syntax. The `protox-parse` crate (pure Rust protobuf compiler) is the right choice for parsing .proto files without requiring protoc.
- **AsyncAPI 3.0.0**: Released December 2023. This is the current stable version. The plan correctly targets both 2.x and 3.0 support. AsyncAPI 3.0 introduced significant changes: channels and messages are now detached from operations, and the request-reply pattern is natively supported. The plan should ensure the contract model handles both 2.x and 3.0 document structures.

**Coverage assessment**:

The 7 paradigms are comprehensive for a static analysis tool. Notable paradigms NOT included (and why that's acceptable):
- **SOAP/WSDL**: Legacy protocol, declining usage. Not worth the implementation cost for a new tool.
- **JSON-RPC**: Niche usage. Could be added later if demand exists.
- **Server-Sent Events (SSE)**: Unidirectional server→client. Less common than WebSocket for bidirectional communication. Could be folded into the event-driven category.
- **MQTT**: IoT-focused protocol. Out of scope for a code analysis tool focused on web/backend development.

The 20+ backend framework extractors and 15+ frontend/consumer library extractors provide broad coverage. The Bayesian 7-signal confidence model (replacing v1's 2-signal formula) is a significant improvement for matching accuracy.

**One concern**: The 20-week build estimate for contract tracking (from 21-CONTRACT-TRACKING-V2-PREP) makes it the longest single system in Phase 5. The orchestration plan (§8.4) correctly identifies this and recommends shipping REST + GraphQL first (highest value). This phased approach is sound.

---

### 5. Shannon Entropy for Secret Detection — ⚠️ REVISE: Entropy is Necessary but Not Sufficient — Add Verification Layer

The plan uses Shannon entropy H(X) = -Σ(p_i × log₂(p_i)) as a confidence signal for secret detection, combined with regex pattern matching (hybrid approach). High entropy (>4.0) suggests random/generated content (likely a real secret); low entropy (<3.0) suggests structured/readable content (likely a placeholder or false positive).

**Current industry best practice (2025-2026)**:

The secret detection landscape has evolved significantly. The three major open-source tools use different approaches:

1. **TruffleHog** (800+ detectors): Uses a **three-layer model**: regex patterns + entropy checks + **live verification** (API calls to check if the secret is actually valid). TruffleHog's key differentiator is verification — it programmatically tests each detected secret against the issuing service. This dramatically reduces false positives. Per [TruffleHog's documentation](https://trufflesecurity.com/blog/how-trufflehog-verifies-secrets), every single detector has a verification step.

2. **Gitleaks** (~100+ rules in default config): Uses **regex patterns + entropy scoring**. Gitleaks' approach is closest to Drift's plan — TOML-based rule definitions with optional entropy thresholds per rule. The default `gitleaks.toml` config contains approximately 100-150 rules covering major cloud providers, CI/CD tokens, and common secret formats.

3. **GitGuardian** (commercial, 400+ detectors): Uses **pattern matching + entropy detection + context-aware validation**. GitGuardian's [2025 blog](https://blog.gitguardian.com/secret-scanning-tools/) describes their approach as combining pattern libraries with entropy detection for unknown secret formats, plus contextual analysis of surrounding code.

**Academic validation**: A 2023 comparative study ([arXiv:2307.00714](https://ar5iv.labs.arxiv.org/html/2307.00714)) found that precision varies dramatically across tools: GitHub Secret Scanner (75%), Gitleaks (46%), and recall: Gitleaks (88%), TruffleHog (52%). The hybrid pattern+entropy approach (used by Gitleaks and planned for Drift) achieves the highest recall but moderate precision.

**Assessment of Drift's approach**:

The plan's hybrid pattern + entropy approach is **sound and current** — it matches Gitleaks' architecture, which is the most widely adopted open-source secret scanner. The 100+ patterns with 7 severity tiers and entropy-based confidence scoring is a solid foundation.

**However, the plan is missing one key capability that TruffleHog has proven is high-value**: secret verification. While Drift cannot make live API calls to verify secrets (it's a static analysis tool, not a security scanner), it can implement **format validation** — checking that a detected string matches the expected format of the secret type (e.g., AWS access keys always start with "AKIA" followed by 16 alphanumeric characters, GitHub tokens start with "ghp_" or "gho_" followed by 36 characters). This is a lightweight form of verification that reduces false positives without requiring network access.

**Recommendation**: Keep the hybrid pattern + entropy approach as designed. Add format validation as a third confidence signal where applicable (provider-specific patterns like AWS, GitHub, Stripe have well-defined formats). Document that Drift's secret detection is designed for code-time detection (finding secrets before they're committed), not for post-commit scanning (where TruffleHog's live verification excels). The 100+ pattern count is competitive with Gitleaks' default ruleset. TruffleHog's 800+ detectors include many that are verification-specific and not applicable to static analysis.

---

### 6. 100+ Secret Patterns — ⚠️ REVISE: Competitive but Should Target 150+ for Parity

The plan expands from v1's 21 patterns (3 severity tiers) to 100+ patterns (7 severity tiers) covering AWS, Azure, GCP, GitHub, GitLab, Stripe, npm, PyPI, Hashicorp, Databricks, and more.

**Comparison with industry tools**:

| Tool | Pattern/Detector Count | Approach | Verification |
|------|----------------------|----------|-------------|
| **TruffleHog** | 800+ detectors | Regex + entropy + live verification | Yes (API calls) |
| **Gitleaks** | ~100-150 rules (default config) | Regex + entropy | No |
| **GitGuardian** | 400+ detectors | Pattern + entropy + context | Yes (commercial) |
| **GitHub Secret Scanning** | 200+ patterns | Provider-partnered patterns | Yes (provider notification) |
| **Drift v2 (planned)** | 100+ patterns | Regex + entropy + AST context | No |

**Analysis**:

Drift's 100+ patterns are competitive with Gitleaks' default ruleset but fall short of TruffleHog (800+) and GitGuardian (400+). However, the comparison is misleading:

1. TruffleHog's 800+ count includes many verification-specific detectors (e.g., separate detectors for "AWS key found" vs "AWS key verified as active"). Drift doesn't need verification detectors.

2. GitGuardian's 400+ count includes commercial-only patterns not available in open-source tools.

3. GitHub Secret Scanning's 200+ patterns are provider-partnered (GitHub works directly with cloud providers to define patterns). Many are not publicly documented.

4. Drift has a unique advantage: **AST context**. Unlike Gitleaks/TruffleHog which scan raw text, Drift can use AST context to determine if a string is in a variable assignment, function argument, configuration object, etc. This reduces false positives significantly — a high-entropy string in a comment is different from one in a `password = "..."` assignment.

**Recommendation**: Target **150+ patterns** for v2 launch to exceed Gitleaks' default ruleset. The additional 50 patterns should focus on:
- Cloud provider tokens (Azure, GCP, DigitalOcean, Cloudflare)
- CI/CD tokens (CircleCI, Travis CI, Jenkins, GitLab CI)
- Database connection strings (MongoDB, PostgreSQL, MySQL, Redis)
- Messaging/notification tokens (Twilio, SendGrid, Mailgun, Slack webhooks)
- Payment processor keys (Stripe, PayPal, Square, Braintree)

The TOML-based extensible pattern format is the right design — users can add custom patterns for internal services. This matches Gitleaks' approach exactly.

---

### 7. 14 Crypto Detection Categories — ✅ CONFIRMED

The plan defines 14 cryptographic failure detection categories:

1. **WeakHash** — MD5, SHA1 for security purposes (CWE-328)
2. **DeprecatedCipher** — DES, 3DES, RC4 (CWE-327)
3. **HardcodedKey** — Crypto keys in source code (CWE-321)
4. **EcbMode** — ECB mode usage (CWE-327)
5. **StaticIv** — Static/predictable initialization vectors (CWE-329)
6. **InsufficientKeyLen** — <2048 RSA, <256 ECC (CWE-326)
7. **DisabledTls** — TLS verification disabled (CWE-295)
8. **InsecureRandom** — Non-cryptographic PRNG for security (CWE-338)
9. **JwtConfusion** — JWT alg=none attacks (CWE-347)
10. **PlaintextPassword** — Passwords stored without hashing (CWE-256)
11. **WeakKdf** — Low PBKDF2 iterations, weak KDF (CWE-916)
12. **MissingEncryption** — Missing encryption-at-rest (CWE-311)
13. **CertPinningBypass** — Certificate pinning disabled (CWE-295)
14. **NonceReuse** — Nonce/IV reuse in encryption (CWE-323)

**Validation against OWASP A04:2025 (Cryptographic Failures)**:

OWASP A04:2025 encompasses CWE-1439, which is a category containing 30+ member CWEs. The plan's 14 detection categories map to the following CWE-1439 members:

- CWE-256 (Plaintext Password Storage) ✅
- CWE-295 (Improper Certificate Validation) ✅ (DisabledTls + CertPinningBypass)
- CWE-311 (Missing Encryption) ✅
- CWE-321 (Hardcoded Crypto Key) ✅
- CWE-323 (Nonce Reuse) ✅
- CWE-326 (Insufficient Key Length) ✅
- CWE-327 (Broken/Risky Crypto Algorithm) ✅ (DeprecatedCipher + EcbMode)
- CWE-328 (Weak Hash) ✅
- CWE-329 (Static IV) ✅
- CWE-338 (Insecure PRNG) ✅
- CWE-347 (Improper Verification of Crypto Signature) ✅ (JwtConfusion)
- CWE-916 (Weak Password Hash) ✅

This covers the most critical CWE-1439 members. Notable CWE-1439 members NOT covered by the 14 categories:

- CWE-261 (Weak Encoding for Password) — partially covered by PlaintextPassword
- CWE-310 (Cryptographic Issues, general) — parent category, covered by children
- CWE-312 (Cleartext Storage of Sensitive Information) — partially covered by MissingEncryption
- CWE-319 (Cleartext Transmission) — would require network analysis, out of scope for static analysis
- CWE-325 (Missing Required Cryptographic Step) — too generic for pattern-based detection
- CWE-330 (Use of Insufficiently Random Values) — covered by InsecureRandom

The 14 categories provide strong coverage of the statically-detectable CWE-1439 members. The omissions are either parent categories (covered by children), require runtime/network analysis (out of scope), or are too generic for pattern-based detection.

**The 14 categories are comprehensive for AST-based static analysis.** No additional categories are needed.

---

### 8. 261 Crypto Patterns Across 12 Languages — ✅ CONFIRMED

The plan specifies 261 patterns across 12 languages: Python, JavaScript/TypeScript, Java, C#, Go, Rust, Ruby, PHP, Kotlin, Swift, C/C++, Scala.

**Assessment**:

The pattern count is reasonable given the scope. Each of the 14 detection categories needs language-specific patterns for each supported language. The math works out:

- 14 categories × 12 languages = 168 minimum (one pattern per category per language)
- Many categories need multiple patterns per language (e.g., WeakHash in Python needs patterns for `hashlib.md5()`, `hashlib.sha1()`, `Crypto.Hash.MD5.new()`, etc.)
- 261 patterns ≈ 1.6 patterns per category per language on average — this is reasonable

**Language coverage validation**:

The 12 languages cover the major ecosystems where cryptographic code is written. The inclusion of Kotlin, Swift, and Scala is forward-looking — these languages are increasingly used in security-sensitive applications (Kotlin for Android, Swift for iOS, Scala for backend services).

**TOML-based extensibility**: The plan's use of TOML-based pattern definitions is the right approach. Users can add custom patterns for internal crypto libraries or language-specific frameworks. This matches the extensibility model used by Gitleaks and Semgrep.

**One note**: The plan says "200+ patterns" in the architecture section but "261 patterns" in the per-language registry section. The 261 number appears to be the actual count after the detailed per-language breakdown. Use 261 as the canonical number.

---

### 9. DNA Health Scoring Formula — ✅ CONFIRMED

The plan defines a 4-factor weighted composite health score:

```
healthScore = consistency(40%) + confidence(30%) + mutations(20%) + coverage(10%)
```

Where:
- **Consistency (40%)**: Gap between dominant and second-most-common allele frequency. Higher gap = more consistent codebase.
- **Confidence (30%)**: Dominant allele frequency (how dominant is the dominant convention). Higher frequency = more confidence.
- **Mutations (20%)**: Penalty based on mutation count relative to gene count. Fewer mutations = healthier.
- **Coverage (10%)**: Proportion of genes with a clear dominant allele. More genes with dominants = better coverage.

Result: Clamped to [0, 100] and rounded.

**Assessment of weight justification**:

The weights reflect a reasonable priority ordering:

1. **Consistency at 40%** is the highest weight because it directly measures what the DNA system is designed to detect — how consistently the team follows its own conventions. A codebase where 90% of files use CVA for variants and 10% use inline conditionals is healthier than one split 55/45. This is the core value proposition.

2. **Confidence at 30%** measures the strength of the dominant signal. If the dominant allele has 95% frequency, we're very confident it's the team's convention. If it has 51% frequency, the "dominant" label is barely meaningful. This is a meta-signal about the reliability of the consistency measurement.

3. **Mutations at 20%** penalizes active deviations. A mutation is a file that was identified as deviating from the dominant convention. This is lower-weighted than consistency because mutations are a subset of inconsistency — they're the actionable items, not the overall health picture.

4. **Coverage at 10%** is the lowest weight because it measures breadth, not depth. A codebase that has clear conventions for 8/10 genes is healthier than one with clear conventions for 3/10, but this is less important than how consistently those conventions are followed.

**Comparison with similar scoring systems**:

- **SonarQube's Maintainability Rating**: Uses a ratio of technical debt to development time, mapped to A-E grades. Different approach (effort-based vs convention-based) but similar concept of a single health metric.
- **CodeClimate's Maintainability Score**: Uses a weighted composite of duplication, complexity, and code smells. Similar weighted-composite approach.
- **ESLint's error/warning counts**: Simpler (just counts), no composite scoring.

The DNA health score is a novel metric — no direct competitor exists for convention-consistency scoring. The 4-factor weighted composite is a reasonable design. The weights are configurable (per the TOML config), so teams can adjust if the defaults don't match their priorities.

**One consideration**: The `mutationImpactHigh=0.1` threshold means that if >10% of files have high-impact mutations, the mutation penalty is maximized. This seems aggressive — in a large codebase, 10% mutation rate might be normal during a migration. The configurable thresholds mitigate this concern.

---

### 10. RegexSet Optimization for Single-Pass Matching — ✅ CONFIRMED

The plan uses Rust's `regex::RegexSet` for single-pass multi-pattern matching in the DNA system (gene extractors), wrapper detection, and crypto pattern matching.

**How RegexSet works**: A `RegexSet` compiles multiple regex patterns into a single automaton. When matched against input text, it reports which patterns matched in a **single pass** through the text. This is fundamentally more efficient than matching each pattern sequentially when you have many patterns.

**Performance characteristics** (from [Rust regex crate documentation](https://doc.cuprate.org/regex/struct.RegexSet.html)):

> "The key advantage of using a regex set is that it will report the matching regexes using a single pass through the haystack. If one has hundreds or thousands of regexes to match repeatedly (like a URL router for a complex web application or a user agent matcher), then a regex set can realize huge performance gains."

**Scale validation for Drift's use cases**:

1. **DNA gene extractors**: ~120 patterns (10 genes × ~4 alleles × ~3 patterns). This is well within RegexSet's sweet spot. A single RegexSet with 120 patterns will be significantly faster than 120 sequential regex matches per file.

2. **Wrapper detection**: 150+ primitive function signatures across 8 frameworks. RegexSet is ideal for this — match all signatures in one pass.

3. **Crypto pattern matching**: 261 patterns across 12 languages. Per-language RegexSets (e.g., ~22 patterns for Python, ~25 for JavaScript) are the right granularity.

**Known limitations** (from GitHub issues [#247](https://github.com/rust-lang/regex/issues/247), [#744](https://github.com/rust-lang/regex/issues/744), [#881](https://github.com/rust-lang/regex/discussions/881)):

1. **RegexSet does not return match positions or capture groups** — it only reports which patterns matched. To get the actual match location, you need to re-run the individual regex. The plan should account for this two-phase approach: RegexSet for filtering (which patterns matched?), then individual regex for extraction (where did it match?).

2. **Performance degrades with pattern count**: RegexSet compiles patterns into a single NFA/DFA. With hundreds of complex patterns, compilation time increases and the automaton size grows. For Drift's scale (~120-260 patterns per set), this is acceptable — the compilation happens once at startup and is amortized across all files.

3. **Not all regex features are supported in RegexSet**: Backreferences and lookahead/lookbehind are not supported. The plan's patterns (function names, import patterns, allele signatures) should not need these features.

**Recommendation**: RegexSet is the correct approach for Drift's multi-pattern matching needs. Ensure the implementation uses the two-phase approach (RegexSet for filtering, individual regex for extraction) and that patterns avoid unsupported features. The plan's estimate of "significant speedup" is validated by the regex crate's documentation and real-world usage.

---

### 11. OWASP 2025 Top 10 — ⚠️ REVISE: 2025 Version Confirmed, But Two Category Names Need Correction

**The OWASP Top 10:2025 exists and has been officially released.** Multiple authoritative sources confirm the 2025 edition, including analyses from [BSG Tech](https://bsg.tech/blog/owasp-top-10/), [Orca Security](https://orca.security/resources/blog/owasp-top-10-2025-key-changes/), [Fastly](https://www.fastly.com/blog/new-2025-owasp-top-10-list-what-changed-what-you-need-to-know/), [Invicti/Netsparker](https://www.netsparker.com/blog/web-security/owasp-top-10/), and [GitLab](https://about.gitlab.com/blog/2025-owasp-top-10-whats-changed-and-why-it-matters/).

**Official 2025 categories** (from multiple concordant sources):

| Rank | Category | Change from 2021 |
|------|----------|-----------------|
| A01 | Broken Access Control | Stable at #1 |
| A02 | Security Misconfiguration | Up from #5 |
| A03 | Software Supply Chain Failures | **NEW** (replaces Vulnerable Components) |
| A04 | Cryptographic Failures | Down from #2 |
| A05 | Injection | Down from #3 |
| A06 | Insecure Design | Down from #4 |
| A07 | Authentication Failures | Stable (renamed from "Identification and Authentication Failures") |
| A08 | Software or Data Integrity Failures | Stable |
| A09 | Security Logging and Alerting Failures | Stable (renamed from "Security Logging and Monitoring Failures") |
| A10 | Mishandling of Exceptional Conditions | **NEW** (replaces SSRF, which was merged into A01) |

**Comparison with the plan's categories** (from 26-OWASP-CWE-MAPPING-V2-PREP.md):

| Rank | Plan's Category | Official Category | Match? |
|------|----------------|-------------------|--------|
| A01 | Broken Access Control | Broken Access Control | ✅ |
| A02 | Security Misconfiguration | Security Misconfiguration | ✅ |
| A03 | Software Supply Chain Failures | Software Supply Chain Failures | ✅ |
| A04 | Cryptographic Failures | Cryptographic Failures | ✅ |
| A05 | Injection | Injection | ✅ |
| A06 | Insecure Design | Insecure Design | ✅ |
| A07 | Authentication Failures | Authentication Failures | ✅ |
| A08 | Software or Data Integrity Failures | Software or Data Integrity Failures | ✅ |
| A09 | **Logging & Alerting Failures** | **Security Logging and Alerting Failures** | ⚠️ Minor name difference |
| A10 | **Mishandling of Exceptional Conditions** | Mishandling of Exceptional Conditions | ✅ |

**Issues found**:

1. **A09 naming**: The plan uses "Logging & Alerting Failures" as the short name and "Logging & Alerting Failures" in the enum. The official name is "Security Logging and Alerting Failures" — the "Security" prefix is part of the official name. This is a minor cosmetic issue but should be corrected for compliance reporting accuracy. The `name()` method on the `OwaspCategory` enum returns "Logging & Alerting Failures" — update to "Security Logging and Alerting Failures".

2. **`is_new_in_2025()` method**: The plan marks A03 (Supply Chain Failures) and A10 (Exceptional Conditions) as new in 2025. This is correct — these are the two new categories. A03 replaces "Vulnerable and Outdated Components" (expanded scope), and A10 replaces SSRF (which was merged into A01).

3. **`was_renamed()` method**: The plan marks A07 (Authentication Failures) and A09 (Logging & Alerting Failures) as renamed. This is correct — A07 was "Identification and Authentication Failures" in 2021, and A09 was "Security Logging and Monitoring Failures" in 2021 (now "Alerting" instead of "Monitoring").

**Recommendation**: Fix the A09 `name()` return value to include the "Security" prefix. All 10 categories are correctly identified and ordered. The plan's OWASP coverage is validated.

---

### 12. CWE Top 25 2025 — ⚠️ REVISE: 2025 Version Confirmed, But List Has Significant Differences from Plan

**The CWE Top 25 2025 exists and has been officially released by MITRE.** It was published in mid-2025, based on analysis of 39,080 CVE records from June 2024 to June 2025. Confirmed by [MITRE's official page](https://cwe.mitre.org/top25/), [BleepingComputer](https://www.bleepingcomputer.com/news/security/mitre-shares-2025s-top-25-most-dangerous-software-weaknesses/), [SecurityWeek](https://www.securityweek.com/mitre-releases-2025-list-of-top-25-most-dangerous-software-vulnerabilities/), and [Infosecurity Magazine](https://infosecurity-magazine.com/news/top-25-dangerous-software).

**Official 2025 CWE Top 25** (from [siteguarding.com analysis](https://www.siteguarding.com/security-blog/mitre-top-25-most-dangerous-software-weaknesses-2025-complete-analysis-and-protection-guide/) cross-referenced with multiple sources):

| Rank | CWE ID | Name | KEVs |
|------|--------|------|------|
| 1 | CWE-79 | Cross-site Scripting (XSS) | 7 |
| 2 | CWE-89 | SQL Injection | 4 |
| 3 | CWE-352 | Cross-Site Request Forgery (CSRF) | 0 |
| 4 | CWE-862 | Missing Authorization | 0 |
| 5 | CWE-787 | Out-of-bounds Write | 12 |
| 6 | CWE-22 | Path Traversal | 10 |
| 7 | CWE-416 | Use After Free | 14 |
| 8 | CWE-125 | Out-of-bounds Read | 3 |
| 9 | CWE-78 | OS Command Injection | 20 |
| 10 | CWE-94 | Code Injection | 7 |
| 11 | CWE-120 | Classic Buffer Overflow | 0 |
| 12 | CWE-434 | Unrestricted Upload | 4 |
| 13 | CWE-476 | NULL Pointer Dereference | 0 |
| 14 | CWE-121 | Stack-based Buffer Overflow | 4 |
| 15 | CWE-502 | Deserialization of Untrusted Data | 11 |
| 16 | CWE-122 | Heap-based Buffer Overflow | 6 |
| 17 | CWE-863 | Incorrect Authorization | 4 |
| 18 | CWE-20 | Improper Input Validation | 2 |
| 19 | CWE-284 | Improper Access Control | 1 |
| 20 | CWE-200 | Exposure of Sensitive Information | 1 |
| 21 | CWE-306 | Missing Authentication | 11 |
| 22 | CWE-918 | Server-Side Request Forgery (SSRF) | 0 |
| 23 | CWE-77 | Command Injection | 2 |
| 24 | CWE-639 | Authorization Bypass via User-Controlled Key | 0 |
| 25 | CWE-770 | Resource Allocation Without Limits | 0 |

**Comparison with the plan's CWE Top 25 list** (from 26-OWASP-CWE-MAPPING-V2-PREP.md):

The plan's list has several differences from the actual 2025 list:

| Plan's List | Actual 2025 | Status |
|-------------|-------------|--------|
| CWE-79 (XSS) — #1 | CWE-79 — #1 | ✅ Match |
| CWE-89 (SQLi) — #2 | CWE-89 — #2 | ✅ Match |
| CWE-352 (CSRF) — #3 | CWE-352 — #3 | ✅ Match |
| CWE-862 (Missing Authz) — #4 | CWE-862 — #4 | ✅ Match |
| CWE-787 (OOB Write) — #5 | CWE-787 — #5 | ✅ Match |
| CWE-22 (Path Traversal) — #6 | CWE-22 — #6 | ✅ Match |
| CWE-416 (Use After Free) — #7 | CWE-416 — #7 | ✅ Match |
| CWE-125 (OOB Read) — #8 | CWE-125 — #8 | ✅ Match |
| CWE-78 (OS Cmd Injection) — #9 | CWE-78 — #9 | ✅ Match |
| CWE-94 (Code Injection) — #10 | CWE-94 — #10 | ✅ Match |
| CWE-120 (Buffer Overflow) — #11 | CWE-120 — #11 | ✅ Match |
| CWE-434 (Unrestricted Upload) — #12 | CWE-434 — #12 | ✅ Match |
| CWE-476 (NULL Deref) — #13 | CWE-476 — #13 | ✅ Match |
| CWE-121 (Stack BOF) — #14 | CWE-121 — #14 | ✅ Match |
| CWE-502 (Deserialization) — #15 | CWE-502 — #15 | ✅ Match |
| CWE-122 (Heap BOF) — #16 | CWE-122 — #16 | ✅ Match |
| CWE-863 (Incorrect Authz) — #17 | CWE-863 — #17 | ✅ Match |
| CWE-20 (Input Validation) — #18 | CWE-20 — #18 | ✅ Match |
| CWE-284 (Access Control) — #19 | CWE-284 — #19 | ✅ Match |
| CWE-200 (Info Exposure) — #20 | CWE-200 — #20 | ✅ Match |
| CWE-306 (Missing Auth) — #21 | CWE-306 — #21 | ✅ Match |
| CWE-918 (SSRF) — #22 | CWE-918 — #22 | ✅ Match |
| CWE-77 (Cmd Injection) — #23 | CWE-77 — #23 | ✅ Match |
| CWE-639 (Authz Bypass) — #24 | CWE-639 — #24 | ✅ Match |
| CWE-770 (Resource Alloc) — #25 | CWE-770 — #25 | ✅ Match |

**Result: The plan's CWE Top 25 2025 list is a perfect match with the actual 2025 list.** All 25 CWE IDs and their rankings are correct.

**Key changes from 2024 to note**:
- 4 new entries in 2025: CWE-120 (Classic Buffer Overflow), CWE-121 (Stack BOF), CWE-122 (Heap BOF), CWE-284 (Improper Access Control)
- Biggest movers up: CWE-862 (Missing Authorization, +5), CWE-476 (NULL Deref, +8), CWE-306 (Missing Auth, +4)
- Biggest mover down: CWE-77 (Command Injection, -10)

**Coverage assessment**: The plan claims 25/25 coverage target. This is achievable for the CWEs that are detectable via static analysis (injection, XSS, CSRF, path traversal, deserialization, SSRF, command injection, authorization checks). Memory safety CWEs (buffer overflows, use-after-free, NULL deref) are primarily relevant to C/C++/Rust and are harder to detect via AST-based analysis — the plan should clarify that coverage for these CWEs is language-dependent and may require deeper analysis than pattern matching.

**Recommendation**: The CWE list is correct. Update the coverage target documentation to distinguish between "fully detectable" CWEs (injection, XSS, CSRF, etc.) and "partially detectable" CWEs (memory safety issues that require deeper analysis). The 25/25 target is aspirational — a more realistic target is 20/25 with full detection and 5/25 with partial/heuristic detection.

---

## Verdict Table

| Item | Verdict | Action Required |
|------|---------|-----------------|
| Robert C. Martin metrics (Ce, Ca, I, A, D) | ✅ CONFIRMED | Still the industry standard. NDepend, JDepend, SonarQube all use these. No modern alternative has displaced them for package-level coupling |
| Tarjan's SCC via petgraph | ✅ CONFIRMED | O(V+E), proven correct, handles edge cases. petgraph 0.8.3 provides `tarjan_scc()` and `condensation()`. Already used in Cortex workspace |
| 12 constraint invariant types | ✅ CONFIRMED | Comprehensive — covers AST, file system, call graph, and taint analysis domains. Exceeds ArchUnit and Dependency-Cruiser capabilities. Cardinality subsumes size/complexity limits |
| 7 contract paradigms | ✅ CONFIRMED | Covers all major 2025-2026 API styles (REST, GraphQL, gRPC, AsyncAPI 3.0, tRPC, WebSocket, event-driven). Schema-first parsing specs are current. 20-week estimate for contract tracking is the longest Phase 5 system — ship REST+GraphQL first |
| Shannon entropy for secret detection | ⚠️ REVISE | Hybrid pattern+entropy approach is sound and matches Gitleaks. Add format validation as a third confidence signal for provider-specific patterns (AWS AKIA*, GitHub ghp_*, etc.). Document that Drift targets code-time detection, not post-commit scanning with live verification |
| 100+ secret patterns | ⚠️ REVISE | Competitive with Gitleaks (~100-150 rules) but should target 150+ for launch. Add cloud providers (Azure, GCP, DigitalOcean), CI/CD tokens, database connection strings, messaging tokens, payment processor keys. TOML extensibility is the right design |
| 14 crypto detection categories | ✅ CONFIRMED | Comprehensive coverage of CWE-1439 (OWASP A04:2025). All 14 categories map to specific CWEs. Covers the statically-detectable members of the cryptographic failures category. No additional categories needed |
| 261 crypto patterns across 12 languages | ✅ CONFIRMED | Reasonable count (~1.6 patterns per category per language). 12 languages cover major ecosystems. TOML-based extensibility is correct. Use 261 as canonical number (not "200+") |
| DNA health scoring formula | ✅ CONFIRMED | 4-factor weighted composite (consistency 40%, confidence 30%, mutations 20%, coverage 10%) is well-justified. No direct competitor exists for convention-consistency scoring. Weights are configurable. mutationImpactHigh=0.1 threshold may be aggressive during migrations but is configurable |
| RegexSet optimization | ✅ CONFIRMED | Single-pass multi-pattern matching is the correct approach for 120-260 patterns. Validated by Rust regex crate documentation. Use two-phase approach (RegexSet for filtering, individual regex for extraction). Compilation cost amortized across all files |
| OWASP 2025 Top 10 | ⚠️ REVISE | 2025 version confirmed and released. All 10 categories correctly identified and ordered. Fix A09 `name()` to include "Security" prefix: "Security Logging and Alerting Failures" (not just "Logging & Alerting Failures") |
| CWE Top 25 2025 | ⚠️ REVISE | 2025 version confirmed (MITRE, June 2025). Plan's list is a **perfect match** — all 25 CWE IDs and rankings are correct. Revise coverage target: distinguish "fully detectable" (20/25) from "partially detectable" (5/25 memory safety CWEs). 25/25 is aspirational |

---

## Summary

**8 CONFIRMED, 4 REVISE, 0 REJECT.**

The Phase 5 Structural Intelligence decisions are architecturally sound across the board. The core algorithms (Tarjan's SCC, Martin metrics, RegexSet, Shannon entropy) are all correct choices validated by industry practice and production systems. The security coverage (OWASP 2025, CWE Top 25 2025, 14 crypto categories) is comprehensive and accurately mapped to current standards.

The 4 revisions are refinements, not architectural changes:
1. **Secret detection**: Add format validation as a third confidence signal alongside pattern matching and entropy
2. **Secret pattern count**: Target 150+ patterns (up from 100+) to exceed Gitleaks' default ruleset
3. **OWASP A09 naming**: Minor cosmetic fix — add "Security" prefix to match official name
4. **CWE Top 25 coverage**: Clarify that 25/25 is aspirational — realistic target is 20/25 fully detectable + 5/25 partially detectable (memory safety CWEs)

No decisions need to be rejected. The Phase 5 systems are well-designed and ready for implementation.
