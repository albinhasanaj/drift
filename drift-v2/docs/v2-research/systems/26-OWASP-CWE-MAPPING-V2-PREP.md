# OWASP/CWE Mapping & Wrapper Detection — V2 Implementation Prep

> Comprehensive build specification for Drift v2's OWASP/CWE Mapping and Security
> Wrapper Detection subsystem (System 26). Synthesized from:
> DRIFT-V2-STACK-HIERARCHY.md (Level 2D — Security Intelligence: "OWASP/CWE Mapping:
> Every security detector → CWE IDs, OWASP 2025 (9/10 target). Metadata enrichment.
> Enterprise compliance. Doesn't change what gets detected."),
> 06-DETECTOR-SYSTEM.md (16 detection categories, 18 security detectors, CWE/OWASP
> fields on Violation struct, TOML pattern definitions with cwe_ids/owasp fields),
> 06-UNIFIED-ANALYSIS-ENGINE-V2-PREP.md (Detection struct: cwe_ids SmallVec<[u32; 2]>,
> owasp Option<Spur>, CompiledQuery with cwe_ids/owasp, TOML cwe_ids/owasp fields),
> 22-CONSTANTS-ENVIRONMENT-V2-PREP.md (§7.3 CWE/OWASP Mapping for secrets: CWE-798,
> CWE-321, CWE-547, CWE-312, CWE-522 → A02:2025, A07:2025; SecretPattern struct with
> cwe_id/owasp_id fields; SecretCandidate with cwe_id/owasp_id),
> 15-TAINT-ANALYSIS-V2-PREP.md (§27 CWE/OWASP Mapping: SinkType enum with 13 CWE
> mappings — CWE-89 SQLi, CWE-78 OS Command, CWE-94 Code Injection, CWE-22 Path
> Traversal, CWE-79 XSS, CWE-601 Open Redirect, CWE-918 SSRF, CWE-502 Deserialization,
> CWE-90 LDAP, CWE-643 XPath, CWE-1336 Template, CWE-117 Log Injection),
> 07-BOUNDARY-DETECTION-V2-PREP.md (sensitive field detection: PII, Credentials,
> Financial, Health categories; 33+ ORM frameworks; boundary violation types),
> 16-ERROR-HANDLING-ANALYSIS-V2-PREP.md (error gap types with CWE mapping, OWASP
> A10:2025 Mishandling of Exceptional Conditions alignment),
> 20-CONSTRAINT-SYSTEM-V2-PREP.md (business_context field: "OWASP A01 compliance
> requirement"; security constraint category),
> 21-security/overview.md (Security Analysis Pipeline: boundary scanner, sensitive
> field detector, reachability engine, security prioritizer; 4-tier classification),
> 05-analyzers/wrappers-analysis.md (TS wrapper detection: 6 categories, ~20
> primitives, clustering, primitive registries, export documentation),
> 01-rust-core/wrappers.md (Rust WrapperInfo, confidence scoring, primitive registry),
> .research/21-security/RECAP.md (v1 gaps: OWASP coverage ~5/10, CWE coverage ~6.5/25,
> no CWE/OWASP mapping, no command injection, no SSRF, no insecure deserialization,
> no weak crypto detection),
> .research/21-security/RESEARCH.md (§5 Cryptographic Failure Detection OWASP A04,
> §6 Broken Access Control OWASP A01, §7 Security Misconfiguration OWASP A02,
> §8 Insecure Deserialization OWASP A08, §9 Supply Chain OWASP A03, SARIF output
> with CWE/OWASP properties),
> .research/21-security/RECOMMENDATIONS.md (SAD1-SAD4, SE1-SE10, TA1-TA8),
> .research/21-security/AUDIT.md (No CWE/OWASP mapping, secret detection too narrow,
> no cryptographic failure detection, no SSRF detection),
> .research/09-quality-gates/RECOMMENDATIONS.md (SARIF CWE/OWASP taxonomy table:
> CWE-862→A01, CWE-311→A02, CWE-798→A07, CWE-89→A03, CWE-20→A03, CWE-16→A05,
> CWE-306→A07),
> .research/19-error-handling/RECOMMENDATIONS.md (error gap CWE mapping, OWASP
> A10:2025 alignment),
> .research/MASTER_RECAP.md (v1 gaps: no OWASP/CWE mapping, no command injection
> OWASP A03, no SSRF OWASP A10, no insecure deserialization OWASP A08, no weak
> crypto OWASP A02),
> cortex-core/src/intent/taxonomy.rs (Intent::SecurityAudit),
> cortex-core/src/intent/weights.rs (SecurityAudit → ConstraintOverride 2.0x,
> Tribal 2.0x boost),
> cortex-privacy/src/context_scoring.rs (sensitive variable detection, confidence
> adjustment),
> OWASP Top 10:2025 RC1 (A01 Broken Access Control, A02 Security Misconfiguration,
> A03 Software Supply Chain Failures, A04 Cryptographic Failures, A05 Injection,
> A06 Insecure Design, A07 Authentication Failures, A08 Software/Data Integrity
> Failures, A09 Logging & Alerting Failures, A10 Mishandling of Exceptional
> Conditions — https://owasp.org/Top10/),
> CWE Top 25 2025 (CWE-79 XSS, CWE-89 SQLi, CWE-352 CSRF, CWE-862 Missing
> Authorization, CWE-787 Out-of-bounds Write, CWE-22 Path Traversal, CWE-416
> Use After Free, CWE-125 Out-of-bounds Read, CWE-78 OS Command Injection,
> CWE-94 Code Injection, CWE-120 Classic Buffer Overflow, CWE-434 Unrestricted
> Upload, CWE-476 NULL Pointer Dereference, CWE-121 Stack-based Buffer Overflow,
> CWE-502 Deserialization, CWE-122 Heap-based Buffer Overflow, CWE-863 Incorrect
> Authorization, CWE-20 Improper Input Validation, CWE-284 Improper Access Control,
> CWE-200 Exposure of Sensitive Information, CWE-306 Missing Authentication,
> CWE-918 SSRF, CWE-77 Command Injection, CWE-639 Authorization Bypass via
> User-Controlled Key, CWE-770 Resource Allocation Without Limits —
> https://cwe.mitre.org/top25/),
> SARIF v2.1.0 specification (taxonomies, CWE/OWASP tool components),
> 03-NAPI-BRIDGE-V2-PREP.md (command/query pattern, napi-rs v3),
> 02-STORAGE-V2-PREP.md (drift.db schema, batch writer, medallion architecture),
> 04-INFRASTRUCTURE-V2-PREP.md (thiserror, tracing, FxHashMap, SmallVec, lasso),
> 22-DNA-SYSTEM-V2-PREP.md (security_patterns gene extractor consumes OWASP data),
> 19-COUPLING-ANALYSIS-V2-PREP.md (document template pattern),
> PLANNING-DRIFT.md (D1-D7).
>
> Purpose: Everything needed to build the OWASP/CWE Mapping & Wrapper Detection
> subsystem from scratch. This is the DEDICATED deep-dive — the 06-DETECTOR-SYSTEM
> doc covers the trait-based detector framework; the 15-TAINT-ANALYSIS doc covers
> taint-specific CWE mappings; the 22-CONSTANTS-ENVIRONMENT doc covers secret-specific
> CWE mappings; this document covers the UNIFIED mapping registry that connects ALL
> security detectors to their CWE/OWASP identifiers, the wrapper detection engine
> that identifies security-relevant framework wrappers, the compliance reporting
> engine that generates OWASP/CWE coverage reports, the SARIF taxonomy integration,
> the security posture scoring system, and the full integration with every security-
> producing subsystem in Drift.
> Every v1 feature accounted for. Zero feature loss. Every mapping specified.
> Every type defined. Every integration point documented. Every architectural
> decision resolved.
> Generated: 2026-02-08

---

## Table of Contents

1. Architectural Position
2. V1 Complete Feature Inventory
3. V2 Architecture — Unified OWASP/CWE Mapping & Wrapper Detection Engine
4. Core Data Model (Rust Types)
5. OWASP Top 10:2025 Complete Registry
6. CWE Top 25 2025 Complete Registry
7. Extended CWE Registry (Beyond Top 25)
8. Detector → CWE/OWASP Mapping Matrix (All 16 Categories)
9. Taint Sink → CWE Mapping (13 Sink Types)
10. Secret Pattern → CWE/OWASP Mapping (100+ Patterns)
11. Error Gap → CWE/OWASP Mapping
12. Boundary Violation → CWE/OWASP Mapping
13. Security Wrapper Detection Engine
14. Wrapper Primitive Registry (Security-Focused)
15. Wrapper Clustering & Classification
16. Wrapper Confidence Scoring
17. OWASP Coverage Calculator
18. CWE Coverage Calculator
19. Security Posture Score (Composite 0-100)
20. Compliance Report Generator
21. SARIF Taxonomy Integration
22. SARIF CWE Tool Component
23. SARIF OWASP Tool Component
24. Finding Enrichment Pipeline
25. Cross-Subsystem Finding Aggregation
26. Incremental Mapping (Content-Hash Aware)
27. Integration with Detector System
28. Integration with Taint Analysis
29. Integration with Constants & Environment (Secrets)
30. Integration with Error Handling Analysis
31. Integration with Boundary Detection
32. Integration with Quality Gates (Security Gate)
33. Integration with DNA System (Security Gene)
34. Integration with Constraint System
35. Integration with Cortex Grounding (D7)
36. Storage Schema (drift.db Security Mapping Tables)
37. NAPI Interface
38. MCP Tool Interface (drift_security — 8 Actions)
39. CLI Interface (drift security — 8 Subcommands)
40. Event Interface
41. Tracing & Observability
42. Performance Targets & Benchmarks
43. Build Order & Dependencies
44. V1 → V2 Feature Cross-Reference
45. Inconsistencies & Decisions
46. Risk Register

---

## 1. Architectural Position

OWASP/CWE Mapping & Wrapper Detection is **Level 2D — Security Intelligence** in the
Drift v2 stack hierarchy. It is the metadata enrichment layer that transforms raw
security detections from across the entire Drift analysis pipeline into standards-
compliant, enterprise-auditable security findings with CWE identifiers, OWASP
categories, severity classifications, and compliance coverage metrics.

Per DRIFT-V2-STACK-HIERARCHY.md:

> OWASP/CWE Mapping: Every security detector → CWE IDs, OWASP 2025 (9/10 target).
> Metadata enrichment. Enterprise compliance. Doesn't change what gets detected.

Per .research/21-security/AUDIT.md:

> No CWE/OWASP mapping — Cannot produce compliance reports.

Per .research/MASTER_RECAP.md:

> v1 gaps: No OWASP/CWE mapping, no command injection (OWASP A03), no SSRF
> (OWASP A10), no insecure deserialization (OWASP A08), no weak crypto (OWASP A02).

### Core Thesis

This subsystem does NOT detect new vulnerabilities. It enriches existing detections
from 6+ upstream subsystems (Detector System, Taint Analysis, Constants/Environment,
Error Handling, Boundary Detection, Wrapper Detection) with standardized security
metadata. The key insight: security findings are scattered across multiple subsystems
in Drift — a SQL injection finding comes from taint analysis, a hardcoded secret comes
from constants analysis, a missing auth check comes from the detector system, an error
handling gap comes from error handling analysis. Without a unified mapping layer, there
is no way to answer "what is our OWASP A05 (Injection) coverage?" because injection
findings live in 3 different subsystems.

The wrapper detection component identifies security-relevant framework wrappers —
functions that wrap security primitives (auth middleware, input sanitizers, output
encoders, crypto functions, CSRF token generators). These wrappers are critical for
taint analysis (sanitizer recognition), constraint verification (auth-before-access),
and security posture scoring (are security primitives consistently wrapped?).

### What Lives Here

- OWASP Top 10:2025 complete registry (10 categories, 248 mapped CWEs)
- CWE Top 25 2025 complete registry (25 weaknesses with scores)
- Extended CWE registry (~120 CWEs relevant to static analysis)
- Detector → CWE/OWASP mapping matrix (all 16 detector categories)
- Taint sink → CWE mapping (13 sink types)
- Secret pattern → CWE/OWASP mapping (100+ patterns)
- Error gap → CWE/OWASP mapping (12 gap types)
- Boundary violation → CWE/OWASP mapping (3 violation types)
- Security wrapper detection engine (auth, sanitization, crypto, CSRF, headers)
- Wrapper primitive registry (security-focused, per-framework)
- Wrapper clustering & classification (5 security wrapper categories)
- Wrapper confidence scoring (4-factor weighted)
- OWASP coverage calculator (10/10 target, per-category detection count)
- CWE coverage calculator (25/25 target for Top 25, extended coverage)
- Security posture score (composite 0-100, multi-factor)
- Compliance report generator (OWASP summary, CWE summary, gap analysis)
- SARIF taxonomy integration (CWE + OWASP tool components)
- Finding enrichment pipeline (attach CWE/OWASP to raw findings)
- Cross-subsystem finding aggregation (unified security finding view)
- Incremental mapping (content-hash aware, only re-map changed findings)

### What Does NOT Live Here

- Vulnerability detection (lives in Detector System, Taint Analysis, etc.)
- Secret detection (lives in Constants & Environment — §22)
- Taint analysis engine (lives in Taint Analysis — §15)
- Error handling analysis (lives in Error Handling Analysis — §16)
- Boundary detection (lives in Boundary Detection — §07)
- Quality gate evaluation (lives in Quality Gates — Level 3)
- MCP tool routing (lives in MCP Server — Level 5)
- SARIF file generation (lives in Quality Gate Reporters — Level 5)

### Upstream Dependencies (What This System Consumes)

| System | What It Provides | How Mapping Uses It |
|--------|-----------------|---------------------|
| Detector System (06) | Violations with detector IDs | Map detector ID → CWE/OWASP |
| Taint Analysis (15) | TaintFlow with SinkType | Map SinkType → CWE |
| Constants/Environment (22) | SecretCandidate with pattern ID | Map pattern → CWE/OWASP |
| Error Handling (16) | ErrorGap with gap type | Map gap type → CWE/OWASP |
| Boundary Detection (07) | BoundaryViolation with type | Map violation type → CWE/OWASP |
| Wrapper Detection (this) | WrapperInfo with primitive | Classify security wrappers |
| Parsers (01) | ParseResult with functions, decorators | Wrapper detection input |
| Call Graph (05) | Function edges, usage counts | Wrapper usage analysis |

### Downstream Consumers (What Depends on This System)

| Consumer | What It Reads | How It Uses Mappings |
|---------|--------------|---------------------|
| Quality Gates | OWASP coverage score, CWE findings | Security gate evaluation |
| SARIF Reporter | CWE/OWASP taxonomies, enriched findings | SARIF output generation |
| MCP Tools | Security posture, OWASP coverage, CWE list | drift_security_* tools |
| CLI | Security reports, compliance status | drift security commands |
| DNA System | Security wrapper gene data | security_patterns gene extractor |
| Constraint System | Security wrapper constraints | auth-before-access verification |
| Taint Analysis | Security wrapper → sanitizer mapping | Sanitizer registry enrichment |
| Context Generation | Security posture context | AI-ready security summaries |
| Cortex Bridge (D7) | Security posture signals | Grounding signal comparison |

---

## 2. V1 Complete Feature Inventory

### 2.1 V1 Security Features (What Exists Today)

| v1 Feature | v1 Implementation | v1 Location | Status |
|-----------|-------------------|-------------|--------|
| Sensitive field detection | Rust pattern matching, 4 categories | cortex-privacy, drift-core/boundaries | EXISTS |
| Boundary scanning | TS two-phase learn-then-detect | packages/core/src/boundaries/ | EXISTS |
| Security prioritization | TS 4-tier classification | packages/core/src/boundaries/ | EXISTS |
| ORM framework detection | TS + Rust, 28 frameworks | boundaries/ + unified-provider/ | EXISTS |
| Wrapper detection (basic) | Rust single-file, 6 categories | crates/drift-core/src/wrappers/ | EXISTS |
| Wrapper clustering | TS cross-file grouping | packages/core/src/wrappers/ | EXISTS |
| Wrapper primitive registry | TS expanded per-framework | packages/core/src/wrappers/primitives/ | EXISTS |
| Wrapper documentation export | TS markdown generation | packages/core/src/wrappers/export/ | EXISTS |
| SecurityAudit intent | Rust intent taxonomy | cortex-core/src/intent/taxonomy.rs | EXISTS |
| Security weight boosting | Rust 2.0x for constraints/tribal | cortex-core/src/intent/weights.rs | EXISTS |
| Sensitive variable context | Rust confidence adjustment | cortex-privacy/src/context_scoring.rs | EXISTS |
| Security synonym expansion | Rust "sec" → security/vulnerability/etc | cortex-retrieval/src/expansion/ | EXISTS |

### 2.2 V1 Security Gaps (What's Missing)

| v1 Gap | Impact | v2 Resolution | v2 Section |
|--------|--------|---------------|------------|
| No CWE/OWASP mapping | Cannot produce compliance reports | Full CWE/OWASP registry | §5-§8 |
| OWASP coverage ~5/10 | Missing A02, A03, A04, A06, A08 | 10/10 OWASP coverage | §5, §17 |
| CWE coverage ~6.5/25 | Most require data flow analysis | 25/25 CWE Top 25 target | §6, §18 |
| No SARIF CWE/OWASP taxonomy | Cannot integrate with GitHub Code Scanning | Full SARIF taxonomy | §21-§23 |
| No security posture score | No single metric for security health | Composite 0-100 score | §19 |
| No compliance reporting | No OWASP/CWE gap analysis | Full compliance reports | §20 |
| No cross-subsystem aggregation | Security findings scattered | Unified finding view | §25 |
| Wrapper detection TS-only clustering | Performance gap, no Rust clustering | Full Rust clustering | §15 |
| No security wrapper classification | Wrappers not categorized by security role | 5 security categories | §14 |
| No wrapper → sanitizer mapping | Taint analysis can't recognize wrappers | Wrapper-sanitizer bridge | §28 |

### 2.3 V1 → V2 Feature Preservation Matrix

| v1 Feature | v2 Status | v2 Location | Notes |
|-----------|-----------|-------------|-------|
| Sensitive field detection (4 categories) | **KEPT** | Boundary Detection §07 | Unchanged, consumed by mapping |
| Boundary scanning (learn-then-detect) | **KEPT** | Boundary Detection §07 | Unchanged, consumed by mapping |
| Security prioritization (4 tiers) | **UPGRADED** | §19 Security Posture Score | Expanded to composite score |
| ORM framework detection (28→33) | **UPGRADED** | Boundary Detection §07 | 5 new frameworks |
| Wrapper detection (basic, 6 categories) | **UPGRADED** | §13 Wrapper Detection Engine | Full Rust, security-focused |
| Wrapper clustering (TS cross-file) | **REPLACED** | §15 Wrapper Clustering | Rust, call-graph-aware |
| Wrapper primitive registry (per-framework) | **UPGRADED** | §14 Wrapper Primitive Registry | Security-focused expansion |
| Wrapper documentation export | **KEPT** | §15 Wrapper Clustering | Markdown + JSON output |
| SecurityAudit intent | **KEPT** | cortex-core (unchanged) | Consumed by mapping |
| Security weight boosting | **KEPT** | cortex-core (unchanged) | Consumed by mapping |
| Sensitive variable context | **KEPT** | cortex-privacy (unchanged) | Consumed by mapping |
| Security synonym expansion | **KEPT** | cortex-retrieval (unchanged) | Consumed by mapping |

**Zero feature loss confirmed.** Every v1 security feature is preserved or upgraded.

---

## 3. V2 Architecture — Unified OWASP/CWE Mapping & Wrapper Detection Engine

### 3.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    OWASP/CWE Mapping Engine                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
│  │ OWASP 2025   │  │ CWE Top 25   │  │ Extended CWE Registry    │  │
│  │ Registry     │  │ 2025 Registry│  │ (~120 CWEs)              │  │
│  │ (10 cats)    │  │ (25 entries) │  │                          │  │
│  └──────┬───────┘  └──────┬───────┘  └────────────┬─────────────┘  │
│         │                 │                        │                │
│  ┌──────▼─────────────────▼────────────────────────▼─────────────┐  │
│  │              Mapping Matrix (Detector → CWE/OWASP)            │  │
│  │  173 detectors × CWE IDs × OWASP categories                  │  │
│  └──────────────────────────┬────────────────────────────────────┘  │
│                             │                                       │
│  ┌──────────────────────────▼────────────────────────────────────┐  │
│  │              Finding Enrichment Pipeline                       │  │
│  │  Raw Finding → + CWE IDs → + OWASP Cat → + Severity → Done   │  │
│  └──────────────────────────┬────────────────────────────────────┘  │
│                             │                                       │
│  ┌──────────┐  ┌────────────▼───┐  ┌─────────────┐  ┌───────────┐ │
│  │ OWASP    │  │ Cross-Subsystem│  │ Security    │  │ SARIF     │ │
│  │ Coverage  │  │ Aggregation    │  │ Posture     │  │ Taxonomy  │ │
│  │ Calculator│  │ (Unified View) │  │ Score (0-100│  │ Generator │ │
│  └──────────┘  └────────────────┘  └─────────────┘  └───────────┘ │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│                    Wrapper Detection Engine                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
│  │ Security     │  │ Wrapper      │  │ Wrapper → Sanitizer      │  │
│  │ Primitive    │  │ Clustering   │  │ Bridge (feeds taint)     │  │
│  │ Registry     │  │ Engine       │  │                          │  │
│  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.2 Data Flow

```
Detector System ──→ Violations ──┐
Taint Analysis ───→ TaintFlows ──┤
Constants/Env ────→ Secrets ─────┤
Error Handling ───→ ErrorGaps ───┼──→ Finding Enrichment ──→ Enriched Findings
Boundary Det. ────→ Violations ──┤                              │
Wrapper Det. ─────→ WrapperInfo ─┘                              │
                                                                 ▼
                                                    ┌────────────────────┐
                                                    │ drift.db           │
                                                    │ security_findings  │
                                                    │ owasp_coverage     │
                                                    │ cwe_coverage       │
                                                    │ security_wrappers  │
                                                    └────────┬───────────┘
                                                             │
                                              ┌──────────────┼──────────────┐
                                              ▼              ▼              ▼
                                         Quality Gates   SARIF Reporter   MCP/CLI
```

### 3.3 Design Principles

1. **Enrichment, not detection**: This system adds metadata to existing findings.
   It never creates new findings. If a CWE has no upstream detector, the coverage
   calculator reports it as a gap — it does NOT attempt to detect it.

2. **Single source of truth**: The mapping matrix is the ONE place where detector
   IDs map to CWE/OWASP. No other subsystem maintains its own mapping. Other
   subsystems may carry `cwe_ids` and `owasp` fields on their types (for efficiency),
   but those values originate from this registry.

3. **Compile-time registry**: The OWASP and CWE registries are `const` arrays in
   Rust. No runtime loading, no file parsing, no database queries for the base
   registry. User extensions (custom CWE mappings) load from TOML at startup.

4. **Wrapper detection is security-scoped**: The general wrapper detection engine
   (from v1) detects ALL wrappers (React hooks, fetch APIs, etc.). This subsystem
   focuses specifically on SECURITY wrappers — functions that wrap auth, sanitization,
   crypto, CSRF, and security header primitives. General wrapper detection remains
   in the Unified Analysis Engine.


---

## 4. Core Data Model (Rust Types)

### 4.1 OWASP Category

```rust
/// OWASP Top 10:2025 category identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OwaspCategory {
    /// A01:2025 — Broken Access Control
    A01BrokenAccessControl,
    /// A02:2025 — Security Misconfiguration
    A02SecurityMisconfiguration,
    /// A03:2025 — Software Supply Chain Failures
    A03SupplyChainFailures,
    /// A04:2025 — Cryptographic Failures
    A04CryptographicFailures,
    /// A05:2025 — Injection
    A05Injection,
    /// A06:2025 — Insecure Design
    A06InsecureDesign,
    /// A07:2025 — Authentication Failures
    A07AuthenticationFailures,
    /// A08:2025 — Software or Data Integrity Failures
    A08IntegrityFailures,
    /// A09:2025 — Logging & Alerting Failures
    A09LoggingAlertingFailures,
    /// A10:2025 — Mishandling of Exceptional Conditions
    A10ExceptionalConditions,
}

impl OwaspCategory {
    pub const COUNT: usize = 10;

    pub const ALL: [OwaspCategory; 10] = [
        Self::A01BrokenAccessControl,
        Self::A02SecurityMisconfiguration,
        Self::A03SupplyChainFailures,
        Self::A04CryptographicFailures,
        Self::A05Injection,
        Self::A06InsecureDesign,
        Self::A07AuthenticationFailures,
        Self::A08IntegrityFailures,
        Self::A09LoggingAlertingFailures,
        Self::A10ExceptionalConditions,
    ];

    /// OWASP identifier string (e.g., "A01:2025").
    pub fn id(&self) -> &'static str {
        match self {
            Self::A01BrokenAccessControl => "A01:2025",
            Self::A02SecurityMisconfiguration => "A02:2025",
            Self::A03SupplyChainFailures => "A03:2025",
            Self::A04CryptographicFailures => "A04:2025",
            Self::A05Injection => "A05:2025",
            Self::A06InsecureDesign => "A06:2025",
            Self::A07AuthenticationFailures => "A07:2025",
            Self::A08IntegrityFailures => "A08:2025",
            Self::A09LoggingAlertingFailures => "A09:2025",
            Self::A10ExceptionalConditions => "A10:2025",
        }
    }

    /// Human-readable name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::A01BrokenAccessControl => "Broken Access Control",
            Self::A02SecurityMisconfiguration => "Security Misconfiguration",
            Self::A03SupplyChainFailures => "Software Supply Chain Failures",
            Self::A04CryptographicFailures => "Cryptographic Failures",
            Self::A05Injection => "Injection",
            Self::A06InsecureDesign => "Insecure Design",
            Self::A07AuthenticationFailures => "Authentication Failures",
            Self::A08IntegrityFailures => "Software or Data Integrity Failures",
            Self::A09LoggingAlertingFailures => "Logging & Alerting Failures",
            Self::A10ExceptionalConditions => "Mishandling of Exceptional Conditions",
        }
    }

    /// Whether this category is new in 2025 (vs 2021).
    pub fn is_new_in_2025(&self) -> bool {
        matches!(
            self,
            Self::A03SupplyChainFailures | Self::A10ExceptionalConditions
        )
    }

    /// Whether this category was renamed from 2021.
    pub fn was_renamed(&self) -> bool {
        matches!(
            self,
            Self::A07AuthenticationFailures | Self::A09LoggingAlertingFailures
        )
    }
}
```

### 4.2 CWE Entry

```rust
/// A single CWE weakness entry.
#[derive(Debug, Clone)]
pub struct CweEntry {
    /// CWE numeric identifier (e.g., 79 for CWE-79).
    pub id: u32,
    /// Short name (e.g., "Cross-site Scripting").
    pub name: &'static str,
    /// Full CWE title.
    pub title: &'static str,
    /// CWE Top 25 2025 rank (None if not in Top 25).
    pub top25_rank: Option<u8>,
    /// CWE Top 25 2025 score (None if not in Top 25).
    pub top25_score: Option<f32>,
    /// Number of KEV (Known Exploited Vulnerabilities) CVEs.
    pub kev_cves: u32,
    /// OWASP categories this CWE maps to.
    pub owasp_categories: &'static [OwaspCategory],
    /// Whether Drift can detect this CWE via static analysis.
    pub drift_detectable: bool,
    /// Which Drift subsystem(s) detect this CWE.
    pub drift_detectors: &'static [&'static str],
    /// Detection method: Pattern, Taint, Structural, or NotDetectable.
    pub detection_method: CweDetectionMethod,
}

/// How Drift detects a given CWE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CweDetectionMethod {
    /// AST pattern matching (detector system).
    Pattern,
    /// Data flow / taint analysis.
    Taint,
    /// Structural analysis (call graph, coupling, etc.).
    Structural,
    /// Configuration analysis (.env, config files).
    Configuration,
    /// Dependency/supply chain analysis.
    SupplyChain,
    /// Multiple methods combined.
    Composite,
    /// Cannot be detected via static analysis alone.
    NotDetectable,
}
```

### 4.3 Security Finding (Unified)

```rust
/// A unified security finding that aggregates detections from all subsystems.
/// This is the enriched output — raw findings + CWE/OWASP metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFinding {
    /// Unique finding ID (deterministic: hash of source + file + line + cwe).
    pub id: u64,
    /// Source subsystem that produced this finding.
    pub source: FindingSource,
    /// Original finding ID from the source subsystem.
    pub source_finding_id: u64,
    /// CWE identifiers (primary + related).
    pub cwe_ids: SmallVec<[u32; 2]>,
    /// Primary CWE (the most specific match).
    pub primary_cwe: u32,
    /// OWASP categories this finding maps to.
    pub owasp_categories: SmallVec<[OwaspCategory; 1]>,
    /// Severity: Critical, High, Medium, Low, Info.
    pub severity: FindingSeverity,
    /// Confidence score (0.0-1.0) from the source detector.
    pub confidence: f32,
    /// File path where the finding was detected.
    pub file: Spur,
    /// Line number (1-indexed).
    pub line: u32,
    /// Column number (0-indexed).
    pub column: u32,
    /// End line (for multi-line findings).
    pub end_line: Option<u32>,
    /// End column.
    pub end_column: Option<u32>,
    /// Human-readable message.
    pub message: String,
    /// Detector ID (e.g., "security/xss-prevention", "taint/sql-injection").
    pub detector_id: Spur,
    /// Suggested fix (if available).
    pub fix: Option<Fix>,
    /// Code flow (for taint findings — source → propagation → sink).
    pub code_flow: Option<Vec<CodeFlowStep>>,
    /// Whether this finding is in a security wrapper (reduces severity).
    pub in_security_wrapper: bool,
    /// Content hash of the file at detection time (for incremental).
    pub content_hash: u64,
    /// Timestamp of detection.
    pub detected_at: i64,
}

/// Source subsystem that produced a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FindingSource {
    /// Detector system (pattern-based).
    Detector,
    /// Taint analysis (data flow).
    Taint,
    /// Constants/environment (secret detection).
    Secret,
    /// Error handling analysis (error gaps).
    ErrorHandling,
    /// Boundary detection (unauthorized access).
    Boundary,
    /// Wrapper detection (missing security wrapper).
    Wrapper,
}

/// Finding severity aligned with SARIF levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum FindingSeverity {
    /// Informational — no immediate risk.
    Info,
    /// Low — minor security concern.
    Low,
    /// Medium — moderate risk, should be addressed.
    Medium,
    /// High — significant risk, address promptly.
    High,
    /// Critical — immediate risk, must be addressed.
    Critical,
}

/// A step in a taint code flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeFlowStep {
    pub file: String,
    pub line: u32,
    pub column: u32,
    pub message: String,
    pub kind: CodeFlowStepKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CodeFlowStepKind {
    Source,
    Propagation,
    Sanitizer,
    Sink,
}
```

### 4.4 Security Wrapper Types

```rust
/// A detected security wrapper function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityWrapper {
    /// Unique wrapper ID (hash of file + function name).
    pub id: u64,
    /// Function name.
    pub function_name: Spur,
    /// File path.
    pub file: Spur,
    /// Line number.
    pub line: u32,
    /// Security wrapper category.
    pub category: SecurityWrapperCategory,
    /// The primitive(s) this function wraps.
    pub wrapped_primitives: SmallVec<[Spur; 2]>,
    /// Framework the primitive belongs to.
    pub framework: Option<Spur>,
    /// Confidence score (0.0-1.0).
    pub confidence: f32,
    /// Number of call sites using this wrapper.
    pub usage_count: u32,
    /// Whether this wrapper is exported (available to other modules).
    pub is_exported: bool,
    /// Whether this wrapper is a sanitizer (for taint analysis).
    pub is_sanitizer: bool,
    /// The taint labels this wrapper sanitizes (if is_sanitizer).
    pub sanitizes_labels: SmallVec<[TaintLabel; 1]>,
    /// Content hash of the file at detection time.
    pub content_hash: u64,
}

/// Security wrapper categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SecurityWrapperCategory {
    /// Authentication wrappers (login, session, token verification).
    Authentication,
    /// Authorization wrappers (permission checks, RBAC, ACL).
    Authorization,
    /// Input sanitization wrappers (XSS prevention, SQL escaping, etc.).
    InputSanitization,
    /// Cryptographic wrappers (hashing, encryption, signing).
    Cryptography,
    /// Security header wrappers (CSP, HSTS, CORS, CSRF tokens).
    SecurityHeaders,
}

impl SecurityWrapperCategory {
    pub const ALL: [SecurityWrapperCategory; 5] = [
        Self::Authentication,
        Self::Authorization,
        Self::InputSanitization,
        Self::Cryptography,
        Self::SecurityHeaders,
    ];

    /// OWASP categories this wrapper category helps mitigate.
    pub fn mitigates_owasp(&self) -> &'static [OwaspCategory] {
        match self {
            Self::Authentication => &[
                OwaspCategory::A07AuthenticationFailures,
            ],
            Self::Authorization => &[
                OwaspCategory::A01BrokenAccessControl,
            ],
            Self::InputSanitization => &[
                OwaspCategory::A05Injection,
            ],
            Self::Cryptography => &[
                OwaspCategory::A04CryptographicFailures,
            ],
            Self::SecurityHeaders => &[
                OwaspCategory::A02SecurityMisconfiguration,
            ],
        }
    }
}
```

### 4.5 OWASP/CWE Coverage Report

```rust
/// OWASP coverage report for the analyzed codebase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwaspCoverageReport {
    /// Per-category coverage details.
    pub categories: [OwaspCategoryCoverage; 10],
    /// Overall OWASP coverage score (0.0-1.0).
    pub overall_coverage: f32,
    /// Number of categories with at least one detector.
    pub categories_covered: u8,
    /// Number of categories with zero detectors.
    pub categories_uncovered: u8,
    /// Total findings across all categories.
    pub total_findings: u32,
    /// Total critical findings.
    pub critical_findings: u32,
    /// Timestamp of report generation.
    pub generated_at: i64,
}

/// Coverage details for a single OWASP category.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwaspCategoryCoverage {
    /// OWASP category.
    pub category: OwaspCategory,
    /// Number of Drift detectors that map to this category.
    pub detector_count: u16,
    /// Number of CWEs in this category that Drift can detect.
    pub detectable_cwes: u16,
    /// Total CWEs mapped to this category.
    pub total_cwes: u16,
    /// Number of findings in this category for the current codebase.
    pub finding_count: u32,
    /// Number of critical findings.
    pub critical_count: u32,
    /// Number of high findings.
    pub high_count: u32,
    /// Coverage depth: None, Shallow (pattern only), Deep (taint + pattern).
    pub depth: CoverageDepth,
    /// Whether security wrappers exist for this category.
    pub has_wrappers: bool,
    /// Number of security wrappers for this category.
    pub wrapper_count: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoverageDepth {
    /// No detection capability for this category.
    None,
    /// Pattern-based detection only (higher false positive rate).
    Shallow,
    /// Pattern + taint/data flow analysis (lower false positive rate).
    Deep,
    /// Full coverage: pattern + taint + structural + configuration.
    Full,
}

/// CWE coverage report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CweCoverageReport {
    /// Per-CWE coverage for Top 25.
    pub top25: [CweEntryCoverage; 25],
    /// Extended CWE coverage (beyond Top 25).
    pub extended: Vec<CweEntryCoverage>,
    /// Number of Top 25 CWEs Drift can detect.
    pub top25_covered: u8,
    /// Total CWEs Drift can detect.
    pub total_covered: u16,
    /// Total CWEs in registry.
    pub total_registered: u16,
}

/// Coverage for a single CWE.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CweEntryCoverage {
    pub cwe_id: u32,
    pub name: String,
    pub detectable: bool,
    pub detection_method: CweDetectionMethod,
    pub finding_count: u32,
    pub detector_ids: Vec<String>,
}
```


---

## 5. OWASP Top 10:2025 Complete Registry

The OWASP Top 10:2025 RC1 (released November 6, 2025) is the authoritative list.
Two new categories (A03 Supply Chain, A10 Exceptional Conditions), one consolidation
(SSRF → A01), two renames (A07 Authentication Failures, A09 Logging & Alerting).

### 5.1 Complete OWASP 2025 Registry

```rust
pub const OWASP_2025_REGISTRY: [OwaspRegistryEntry; 10] = [
    OwaspRegistryEntry {
        category: OwaspCategory::A01BrokenAccessControl,
        id: "A01:2025",
        name: "Broken Access Control",
        description: "Users can access data or functions they shouldn't. Includes \
            horizontal/vertical privilege escalation, IDOR, forced browsing, SSRF \
            (consolidated from 2021 A10).",
        change_from_2021: "Still #1. Now includes SSRF (was separate A10:2021).",
        primary_cwes: &[862, 284, 285, 639, 352, 918, 22, 425, 863],
        drift_coverage: CoverageDepth::Deep,
        drift_detectors: &[
            "auth/permission-checks",
            "auth/rbac-patterns",
            "auth/cors-config",
            "auth/csrf-protection",
            "security/authorization",
            "security/path-traversal",
            "security/ssrf",
            "security/cors-misconfiguration",
            "security/open-redirect",
        ],
    },
    OwaspRegistryEntry {
        category: OwaspCategory::A02SecurityMisconfiguration,
        id: "A02:2025",
        name: "Security Misconfiguration",
        description: "Failures in securely configuring applications, frameworks, \
            servers, cloud services, or containers. Default credentials, open \
            storage, missing headers, verbose errors.",
        change_from_2021: "Rises from #5 to #2. Almost every app tested had \
            at least one misconfiguration.",
        primary_cwes: &[16, 611, 1004, 614, 693, 1021, 942],
        drift_coverage: CoverageDepth::Shallow,
        drift_detectors: &[
            "config/debug-mode",
            "config/secrets-handling",
            "security/missing-security-headers",
            "security/cors-misconfiguration",
            "logging/sensitive-data",
        ],
    },
    OwaspRegistryEntry {
        category: OwaspCategory::A03SupplyChainFailures,
        id: "A03:2025",
        name: "Software Supply Chain Failures",
        description: "Compromises in dependencies, build pipelines, repositories, \
            or distribution channels. Expands 2021 'Vulnerable and Outdated \
            Components' to full supply chain.",
        change_from_2021: "NEW in 2025. Expands A06:2021 (Vulnerable Components).",
        primary_cwes: &[829, 426, 494, 1104, 937],
        drift_coverage: CoverageDepth::Shallow,
        drift_detectors: &[
            "security/dependency-audit",
        ],
    },
    OwaspRegistryEntry {
        category: OwaspCategory::A04CryptographicFailures,
        id: "A04:2025",
        name: "Cryptographic Failures",
        description: "Incorrect, weak, or missing use of cryptography. Poor key \
            management, broken protocols, hardcoded keys.",
        change_from_2021: "Falls from #2 to #4.",
        primary_cwes: &[327, 328, 330, 311, 312, 321, 326, 916],
        drift_coverage: CoverageDepth::Deep,
        drift_detectors: &[
            "security/weak-crypto",
            "security/insecure-random",
            "security/encryption",
            "security/hardcoded-secrets",
            "config/secrets-handling",
        ],
    },
    OwaspRegistryEntry {
        category: OwaspCategory::A05Injection,
        id: "A05:2025",
        name: "Injection",
        description: "Untrusted input interpreted as code/commands. SQL, NoSQL, \
            OS, LDAP, Expression Language, XSS, template injection.",
        change_from_2021: "Falls from #3 to #5. Still one of the most tested \
            categories with many associated CVEs.",
        primary_cwes: &[79, 89, 78, 77, 94, 90, 643, 1336, 917],
        drift_coverage: CoverageDepth::Deep,
        drift_detectors: &[
            "security/xss-prevention",
            "security/input-validation",
            "security/output-encoding",
            "security/command-injection",
            "security/template-injection",
            "data-access/sql-injection",
            "data-access/parameterization",
        ],
    },
    OwaspRegistryEntry {
        category: OwaspCategory::A06InsecureDesign,
        id: "A06:2025",
        name: "Insecure Design",
        description: "Flaws at the architectural/design level, independent of \
            implementation bugs. Missing threat modeling, insecure flows.",
        change_from_2021: "Falls from #4 to #6.",
        primary_cwes: &[209, 256, 501, 522, 602, 656, 799, 840],
        drift_coverage: CoverageDepth::Shallow,
        drift_detectors: &[
            "structural/layer-violations",
            "structural/dependency-direction",
        ],
    },
    OwaspRegistryEntry {
        category: OwaspCategory::A07AuthenticationFailures,
        id: "A07:2025",
        name: "Authentication Failures",
        description: "Problems with authentication mechanisms — login, session \
            management, password reset, MFA flows, token handling.",
        change_from_2021: "Same position (#7). Renamed from 'Identification and \
            Authentication Failures'.",
        primary_cwes: &[287, 256, 257, 306, 384, 613, 640, 798],
        drift_coverage: CoverageDepth::Deep,
        drift_detectors: &[
            "auth/password-policy",
            "auth/mfa-checks",
            "auth/credential-storage",
            "auth/session-management",
            "auth/token-handling",
            "auth/oauth-patterns",
            "security/authentication",
            "security/hardcoded-secrets",
        ],
    },
    OwaspRegistryEntry {
        category: OwaspCategory::A08IntegrityFailures,
        id: "A08:2025",
        name: "Software or Data Integrity Failures",
        description: "Failures to verify integrity & authenticity of code, \
            configuration, or data. Insecure deserialization, unsigned updates.",
        change_from_2021: "Same category, same ranking (#8). Complements A03.",
        primary_cwes: &[345, 353, 426, 494, 502, 565, 784, 829],
        drift_coverage: CoverageDepth::Shallow,
        drift_detectors: &[
            "security/insecure-deserialization",
        ],
    },
    OwaspRegistryEntry {
        category: OwaspCategory::A09LoggingAlertingFailures,
        id: "A09:2025",
        name: "Logging & Alerting Failures",
        description: "Missing, incomplete, or un-actionable logging. Lack of \
            alerting on important security events.",
        change_from_2021: "Renamed from 'Security Logging and Monitoring Failures'. \
            Emphasizes alerting is critical.",
        primary_cwes: &[117, 223, 532, 778],
        drift_coverage: CoverageDepth::Deep,
        drift_detectors: &[
            "logging/sensitive-data",
            "logging/audit-trail",
            "logging/log-levels",
            "logging/structured-logging",
            "logging/error-context",
        ],
    },
    OwaspRegistryEntry {
        category: OwaspCategory::A10ExceptionalConditions,
        id: "A10:2025",
        name: "Mishandling of Exceptional Conditions",
        description: "Issues from poor error/exception handling, failing open, \
            incorrect logic around abnormal system states. Catching all exceptions \
            and returning success, suppressing security errors.",
        change_from_2021: "NEW in 2025. Formalizes bugs previously spread across \
            other categories.",
        primary_cwes: &[252, 248, 280, 390, 392, 394, 395, 396, 397, 754, 755, 756],
        drift_coverage: CoverageDepth::Deep,
        drift_detectors: &[
            "errors/empty-catch",
            "errors/swallowed-errors",
            "errors/error-propagation",
            "errors/error-recovery",
            "errors/graceful-degradation",
            "errors/unhandled-rejection",
        ],
    },
];

/// Registry entry for a single OWASP category.
pub struct OwaspRegistryEntry {
    pub category: OwaspCategory,
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub change_from_2021: &'static str,
    pub primary_cwes: &'static [u32],
    pub drift_coverage: CoverageDepth,
    pub drift_detectors: &'static [&'static str],
}
```

### 5.2 OWASP 2025 vs 2021 Migration Map

| 2021 Category | 2021 Rank | 2025 Category | 2025 Rank | Change |
|--------------|-----------|---------------|-----------|--------|
| A01 Broken Access Control | #1 | A01 Broken Access Control | #1 | Same (+ SSRF absorbed) |
| A05 Security Misconfiguration | #5 | A02 Security Misconfiguration | #2 | ↑3 |
| A06 Vulnerable Components | #6 | A03 Supply Chain Failures | #3 | NEW (expanded) |
| A02 Cryptographic Failures | #2 | A04 Cryptographic Failures | #4 | ↓2 |
| A03 Injection | #3 | A05 Injection | #5 | ↓2 |
| A04 Insecure Design | #4 | A06 Insecure Design | #6 | ↓2 |
| A07 Identification & Auth | #7 | A07 Authentication Failures | #7 | Renamed |
| A08 Software/Data Integrity | #8 | A08 Software/Data Integrity | #8 | Same |
| A09 Logging & Monitoring | #9 | A09 Logging & Alerting | #9 | Renamed |
| A10 SSRF | #10 | (absorbed into A01) | — | Removed |
| — | — | A10 Exceptional Conditions | #10 | NEW |

### 5.3 Drift OWASP Coverage Target: 10/10

| OWASP Category | v1 Coverage | v2 Target | v2 Depth | Key Detectors |
|---------------|-------------|-----------|----------|---------------|
| A01 Broken Access Control | Partial | **Full** | Deep | auth/*, security/authorization, taint/ssrf |
| A02 Security Misconfiguration | None | **Full** | Shallow | config/*, security/headers |
| A03 Supply Chain Failures | None | **Partial** | Shallow | security/dependency-audit |
| A04 Cryptographic Failures | None | **Full** | Deep | security/weak-crypto, secrets |
| A05 Injection | Partial | **Full** | Deep | taint/*, security/xss, sql-injection |
| A06 Insecure Design | None | **Partial** | Shallow | structural/layer-violations |
| A07 Authentication Failures | Partial | **Full** | Deep | auth/*, security/authentication |
| A08 Integrity Failures | None | **Partial** | Shallow | security/insecure-deserialization |
| A09 Logging & Alerting | None | **Full** | Deep | logging/* |
| A10 Exceptional Conditions | None | **Full** | Deep | errors/* |

**v1: ~5/10 (partial coverage on 5 categories, zero on 5)**
**v2: 10/10 (full or partial coverage on all 10 categories)**

---

## 6. CWE Top 25 2025 Complete Registry

The CWE Top 25 2025 (published June 2025 by MITRE) is based on analysis of 39,080
CVE records from June 2024 to June 2025.

### 6.1 Complete CWE Top 25 2025 Registry

```rust
pub const CWE_TOP25_2025: [CweEntry; 25] = [
    CweEntry {
        id: 79,
        name: "Cross-site Scripting",
        title: "Improper Neutralization of Input During Web Page Generation",
        top25_rank: Some(1),
        top25_score: Some(60.38),
        kev_cves: 7,
        owasp_categories: &[OwaspCategory::A05Injection],
        drift_detectable: true,
        drift_detectors: &["security/xss-prevention", "taint/html-output"],
        detection_method: CweDetectionMethod::Taint,
    },
    CweEntry {
        id: 89,
        name: "SQL Injection",
        title: "Improper Neutralization of Special Elements in SQL Command",
        top25_rank: Some(2),
        top25_score: Some(28.72),
        kev_cves: 4,
        owasp_categories: &[OwaspCategory::A05Injection],
        drift_detectable: true,
        drift_detectors: &["data-access/sql-injection", "taint/sql-query"],
        detection_method: CweDetectionMethod::Taint,
    },
    CweEntry {
        id: 352,
        name: "Cross-Site Request Forgery",
        title: "Cross-Site Request Forgery (CSRF)",
        top25_rank: Some(3),
        top25_score: Some(13.64),
        kev_cves: 0,
        owasp_categories: &[OwaspCategory::A01BrokenAccessControl],
        drift_detectable: true,
        drift_detectors: &["auth/csrf-protection"],
        detection_method: CweDetectionMethod::Pattern,
    },
    CweEntry {
        id: 862,
        name: "Missing Authorization",
        title: "Missing Authorization",
        top25_rank: Some(4),
        top25_score: Some(13.28),
        kev_cves: 0,
        owasp_categories: &[OwaspCategory::A01BrokenAccessControl],
        drift_detectable: true,
        drift_detectors: &["auth/permission-checks", "security/authorization"],
        detection_method: CweDetectionMethod::Structural,
    },
    CweEntry {
        id: 787,
        name: "Out-of-bounds Write",
        title: "Out-of-bounds Write",
        top25_rank: Some(5),
        top25_score: Some(12.68),
        kev_cves: 12,
        owasp_categories: &[OwaspCategory::A06InsecureDesign],
        drift_detectable: false,
        drift_detectors: &[],
        detection_method: CweDetectionMethod::NotDetectable,
    },
    CweEntry {
        id: 22,
        name: "Path Traversal",
        title: "Improper Limitation of a Pathname to a Restricted Directory",
        top25_rank: Some(6),
        top25_score: Some(8.99),
        kev_cves: 10,
        owasp_categories: &[
            OwaspCategory::A01BrokenAccessControl,
            OwaspCategory::A05Injection,
        ],
        drift_detectable: true,
        drift_detectors: &["security/path-traversal", "taint/file-read", "taint/file-write"],
        detection_method: CweDetectionMethod::Taint,
    },
    CweEntry {
        id: 416,
        name: "Use After Free",
        title: "Use After Free",
        top25_rank: Some(7),
        top25_score: Some(8.47),
        kev_cves: 14,
        owasp_categories: &[OwaspCategory::A06InsecureDesign],
        drift_detectable: false,
        drift_detectors: &[],
        detection_method: CweDetectionMethod::NotDetectable,
    },
    CweEntry {
        id: 125,
        name: "Out-of-bounds Read",
        title: "Out-of-bounds Read",
        top25_rank: Some(8),
        top25_score: Some(7.88),
        kev_cves: 3,
        owasp_categories: &[OwaspCategory::A06InsecureDesign],
        drift_detectable: false,
        drift_detectors: &[],
        detection_method: CweDetectionMethod::NotDetectable,
    },
    CweEntry {
        id: 78,
        name: "OS Command Injection",
        title: "Improper Neutralization of Special Elements in OS Command",
        top25_rank: Some(9),
        top25_score: Some(7.85),
        kev_cves: 20,
        owasp_categories: &[OwaspCategory::A05Injection],
        drift_detectable: true,
        drift_detectors: &["security/command-injection", "taint/os-command"],
        detection_method: CweDetectionMethod::Taint,
    },
    CweEntry {
        id: 94,
        name: "Code Injection",
        title: "Improper Control of Generation of Code",
        top25_rank: Some(10),
        top25_score: Some(7.57),
        kev_cves: 7,
        owasp_categories: &[OwaspCategory::A05Injection],
        drift_detectable: true,
        drift_detectors: &["taint/code-execution"],
        detection_method: CweDetectionMethod::Taint,
    },
    CweEntry {
        id: 120,
        name: "Classic Buffer Overflow",
        title: "Buffer Copy without Checking Size of Input",
        top25_rank: Some(11),
        top25_score: Some(6.96),
        kev_cves: 0,
        owasp_categories: &[OwaspCategory::A06InsecureDesign],
        drift_detectable: false,
        drift_detectors: &[],
        detection_method: CweDetectionMethod::NotDetectable,
    },
    CweEntry {
        id: 434,
        name: "Unrestricted Upload",
        title: "Unrestricted Upload of File with Dangerous Type",
        top25_rank: Some(12),
        top25_score: Some(6.87),
        kev_cves: 4,
        owasp_categories: &[OwaspCategory::A05Injection],
        drift_detectable: true,
        drift_detectors: &["security/input-validation"],
        detection_method: CweDetectionMethod::Pattern,
    },
    CweEntry {
        id: 476,
        name: "NULL Pointer Dereference",
        title: "NULL Pointer Dereference",
        top25_rank: Some(13),
        top25_score: Some(6.41),
        kev_cves: 0,
        owasp_categories: &[OwaspCategory::A10ExceptionalConditions],
        drift_detectable: false,
        drift_detectors: &[],
        detection_method: CweDetectionMethod::NotDetectable,
    },
    CweEntry {
        id: 121,
        name: "Stack-based Buffer Overflow",
        title: "Stack-based Buffer Overflow",
        top25_rank: Some(14),
        top25_score: Some(5.75),
        kev_cves: 4,
        owasp_categories: &[OwaspCategory::A06InsecureDesign],
        drift_detectable: false,
        drift_detectors: &[],
        detection_method: CweDetectionMethod::NotDetectable,
    },
    CweEntry {
        id: 502,
        name: "Deserialization of Untrusted Data",
        title: "Deserialization of Untrusted Data",
        top25_rank: Some(15),
        top25_score: Some(5.23),
        kev_cves: 11,
        owasp_categories: &[
            OwaspCategory::A08IntegrityFailures,
            OwaspCategory::A05Injection,
        ],
        drift_detectable: true,
        drift_detectors: &["security/insecure-deserialization", "taint/deserialization"],
        detection_method: CweDetectionMethod::Composite,
    },
    CweEntry {
        id: 122,
        name: "Heap-based Buffer Overflow",
        title: "Heap-based Buffer Overflow",
        top25_rank: Some(16),
        top25_score: Some(5.21),
        kev_cves: 6,
        owasp_categories: &[OwaspCategory::A06InsecureDesign],
        drift_detectable: false,
        drift_detectors: &[],
        detection_method: CweDetectionMethod::NotDetectable,
    },
    CweEntry {
        id: 863,
        name: "Incorrect Authorization",
        title: "Incorrect Authorization",
        top25_rank: Some(17),
        top25_score: Some(4.14),
        kev_cves: 4,
        owasp_categories: &[OwaspCategory::A01BrokenAccessControl],
        drift_detectable: true,
        drift_detectors: &["auth/permission-checks", "auth/rbac-patterns"],
        detection_method: CweDetectionMethod::Structural,
    },
    CweEntry {
        id: 20,
        name: "Improper Input Validation",
        title: "Improper Input Validation",
        top25_rank: Some(18),
        top25_score: Some(4.09),
        kev_cves: 2,
        owasp_categories: &[OwaspCategory::A05Injection],
        drift_detectable: true,
        drift_detectors: &["security/input-validation"],
        detection_method: CweDetectionMethod::Pattern,
    },
    CweEntry {
        id: 284,
        name: "Improper Access Control",
        title: "Improper Access Control",
        top25_rank: Some(19),
        top25_score: Some(4.07),
        kev_cves: 1,
        owasp_categories: &[OwaspCategory::A01BrokenAccessControl],
        drift_detectable: true,
        drift_detectors: &["security/authorization", "auth/permission-checks"],
        detection_method: CweDetectionMethod::Structural,
    },
    CweEntry {
        id: 200,
        name: "Exposure of Sensitive Information",
        title: "Exposure of Sensitive Information to an Unauthorized Actor",
        top25_rank: Some(20),
        top25_score: Some(4.01),
        kev_cves: 1,
        owasp_categories: &[
            OwaspCategory::A01BrokenAccessControl,
            OwaspCategory::A04CryptographicFailures,
        ],
        drift_detectable: true,
        drift_detectors: &["logging/sensitive-data", "data-access/sensitive-data"],
        detection_method: CweDetectionMethod::Pattern,
    },
    CweEntry {
        id: 306,
        name: "Missing Authentication",
        title: "Missing Authentication for Critical Function",
        top25_rank: Some(21),
        top25_score: Some(3.47),
        kev_cves: 11,
        owasp_categories: &[OwaspCategory::A07AuthenticationFailures],
        drift_detectable: true,
        drift_detectors: &["security/authentication", "auth/permission-checks"],
        detection_method: CweDetectionMethod::Structural,
    },
    CweEntry {
        id: 918,
        name: "Server-Side Request Forgery",
        title: "Server-Side Request Forgery (SSRF)",
        top25_rank: Some(22),
        top25_score: Some(3.36),
        kev_cves: 0,
        owasp_categories: &[OwaspCategory::A01BrokenAccessControl],
        drift_detectable: true,
        drift_detectors: &["security/ssrf", "taint/http-request"],
        detection_method: CweDetectionMethod::Taint,
    },
    CweEntry {
        id: 77,
        name: "Command Injection",
        title: "Improper Neutralization of Special Elements in a Command",
        top25_rank: Some(23),
        top25_score: Some(3.15),
        kev_cves: 2,
        owasp_categories: &[OwaspCategory::A05Injection],
        drift_detectable: true,
        drift_detectors: &["security/command-injection", "taint/os-command"],
        detection_method: CweDetectionMethod::Taint,
    },
    CweEntry {
        id: 639,
        name: "Authorization Bypass via User-Controlled Key",
        title: "Authorization Bypass Through User-Controlled Key",
        top25_rank: Some(24),
        top25_score: Some(2.62),
        kev_cves: 0,
        owasp_categories: &[OwaspCategory::A01BrokenAccessControl],
        drift_detectable: true,
        drift_detectors: &["auth/permission-checks"],
        detection_method: CweDetectionMethod::Structural,
    },
    CweEntry {
        id: 770,
        name: "Resource Allocation Without Limits",
        title: "Allocation of Resources Without Limits or Throttling",
        top25_rank: Some(25),
        top25_score: Some(2.54),
        kev_cves: 0,
        owasp_categories: &[OwaspCategory::A02SecurityMisconfiguration],
        drift_detectable: true,
        drift_detectors: &["api/rate-limiting"],
        detection_method: CweDetectionMethod::Pattern,
    },
];
```

### 6.2 CWE Top 25 Drift Detectability Summary

| Rank | CWE | Name | Detectable | Method | Notes |
|------|-----|------|-----------|--------|-------|
| 1 | CWE-79 | XSS | ✅ | Taint | Pattern + taint for deep detection |
| 2 | CWE-89 | SQL Injection | ✅ | Taint | Pattern + taint for deep detection |
| 3 | CWE-352 | CSRF | ✅ | Pattern | Missing CSRF token detection |
| 4 | CWE-862 | Missing Authorization | ✅ | Structural | Auth decorator/middleware check |
| 5 | CWE-787 | Out-of-bounds Write | ❌ | N/A | Memory safety — requires runtime |
| 6 | CWE-22 | Path Traversal | ✅ | Taint | User input → file path |
| 7 | CWE-416 | Use After Free | ❌ | N/A | Memory safety — requires runtime |
| 8 | CWE-125 | Out-of-bounds Read | ❌ | N/A | Memory safety — requires runtime |
| 9 | CWE-78 | OS Command Injection | ✅ | Taint | User input → exec/system |
| 10 | CWE-94 | Code Injection | ✅ | Taint | User input → eval |
| 11 | CWE-120 | Classic Buffer Overflow | ❌ | N/A | Memory safety — requires runtime |
| 12 | CWE-434 | Unrestricted Upload | ✅ | Pattern | File type validation check |
| 13 | CWE-476 | NULL Pointer Deref | ❌ | N/A | Requires type-state analysis |
| 14 | CWE-121 | Stack Buffer Overflow | ❌ | N/A | Memory safety — requires runtime |
| 15 | CWE-502 | Deserialization | ✅ | Composite | Pattern + taint |
| 16 | CWE-122 | Heap Buffer Overflow | ❌ | N/A | Memory safety — requires runtime |
| 17 | CWE-863 | Incorrect Authorization | ✅ | Structural | RBAC pattern analysis |
| 18 | CWE-20 | Improper Input Validation | ✅ | Pattern | Missing validation detection |
| 19 | CWE-284 | Improper Access Control | ✅ | Structural | Access control pattern analysis |
| 20 | CWE-200 | Sensitive Info Exposure | ✅ | Pattern | PII in logs, error messages |
| 21 | CWE-306 | Missing Authentication | ✅ | Structural | Missing auth middleware |
| 22 | CWE-918 | SSRF | ✅ | Taint | User input → HTTP request |
| 23 | CWE-77 | Command Injection | ✅ | Taint | User input → command |
| 24 | CWE-639 | Auth Bypass via User Key | ✅ | Structural | IDOR pattern detection |
| 25 | CWE-770 | Resource Allocation | ✅ | Pattern | Rate limiting detection |

**Detectable: 18/25 (72%)** — The 7 undetectable CWEs are all memory safety issues
(buffer overflows, use-after-free, null pointer dereference) that require runtime
analysis or type-state tracking beyond static analysis capabilities. This is consistent
with industry SAST tools (Semgrep, SonarQube, CodeQL all have similar limitations).


---

## 7. Extended CWE Registry (Beyond Top 25)

Beyond the Top 25, Drift maps ~95 additional CWEs that are detectable via static
analysis. These are organized by OWASP category for efficient lookup.

### 7.1 Extended CWE Entries by OWASP Category

```rust
/// Extended CWE entries beyond Top 25, organized by OWASP category.
/// These are CWEs that Drift can detect but are not in the Top 25.
pub const EXTENDED_CWE_REGISTRY: &[CweEntry] = &[
    // === A01: Broken Access Control ===
    CweEntry { id: 285, name: "Improper Authorization", drift_detectable: true,
        drift_detectors: &["auth/permission-checks"], detection_method: CweDetectionMethod::Structural, .. },
    CweEntry { id: 425, name: "Direct Request (Forced Browsing)", drift_detectable: true,
        drift_detectors: &["auth/permission-checks"], detection_method: CweDetectionMethod::Structural, .. },
    CweEntry { id: 601, name: "Open Redirect", drift_detectable: true,
        drift_detectors: &["security/open-redirect", "taint/http-redirect"], detection_method: CweDetectionMethod::Taint, .. },
    CweEntry { id: 942, name: "Permissive Cross-domain Policy", drift_detectable: true,
        drift_detectors: &["security/cors-misconfiguration"], detection_method: CweDetectionMethod::Pattern, .. },

    // === A02: Security Misconfiguration ===
    CweEntry { id: 16, name: "Configuration", drift_detectable: true,
        drift_detectors: &["config/debug-mode", "config/default-values"], detection_method: CweDetectionMethod::Configuration, .. },
    CweEntry { id: 611, name: "XXE (XML External Entity)", drift_detectable: true,
        drift_detectors: &["security/input-validation"], detection_method: CweDetectionMethod::Pattern, .. },
    CweEntry { id: 693, name: "Protection Mechanism Failure", drift_detectable: true,
        drift_detectors: &["security/missing-security-headers"], detection_method: CweDetectionMethod::Pattern, .. },
    CweEntry { id: 1004, name: "Sensitive Cookie Without HttpOnly", drift_detectable: true,
        drift_detectors: &["auth/session-management"], detection_method: CweDetectionMethod::Pattern, .. },
    CweEntry { id: 614, name: "Sensitive Cookie Without Secure", drift_detectable: true,
        drift_detectors: &["auth/session-management"], detection_method: CweDetectionMethod::Pattern, .. },
    CweEntry { id: 1021, name: "Improper Restriction of Rendered UI Layers", drift_detectable: true,
        drift_detectors: &["security/missing-security-headers"], detection_method: CweDetectionMethod::Pattern, .. },

    // === A04: Cryptographic Failures ===
    CweEntry { id: 311, name: "Missing Encryption of Sensitive Data", drift_detectable: true,
        drift_detectors: &["security/encryption"], detection_method: CweDetectionMethod::Pattern, .. },
    CweEntry { id: 312, name: "Cleartext Storage of Sensitive Info", drift_detectable: true,
        drift_detectors: &["security/hardcoded-secrets"], detection_method: CweDetectionMethod::Pattern, .. },
    CweEntry { id: 321, name: "Use of Hard-coded Cryptographic Key", drift_detectable: true,
        drift_detectors: &["security/hardcoded-secrets"], detection_method: CweDetectionMethod::Pattern, .. },
    CweEntry { id: 326, name: "Inadequate Encryption Strength", drift_detectable: true,
        drift_detectors: &["security/weak-crypto"], detection_method: CweDetectionMethod::Pattern, .. },
    CweEntry { id: 327, name: "Use of Broken Crypto Algorithm", drift_detectable: true,
        drift_detectors: &["security/weak-crypto"], detection_method: CweDetectionMethod::Pattern, .. },
    CweEntry { id: 328, name: "Use of Weak Hash", drift_detectable: true,
        drift_detectors: &["security/weak-crypto"], detection_method: CweDetectionMethod::Pattern, .. },
    CweEntry { id: 330, name: "Use of Insufficiently Random Values", drift_detectable: true,
        drift_detectors: &["security/insecure-random"], detection_method: CweDetectionMethod::Pattern, .. },
    CweEntry { id: 547, name: "Use of Hard-coded Security-relevant Constant", drift_detectable: true,
        drift_detectors: &["security/hardcoded-secrets"], detection_method: CweDetectionMethod::Pattern, .. },
    CweEntry { id: 798, name: "Use of Hard-coded Credentials", drift_detectable: true,
        drift_detectors: &["security/hardcoded-secrets", "config/secrets-handling"], detection_method: CweDetectionMethod::Pattern, .. },
    CweEntry { id: 916, name: "Use of Password Hash With Insufficient Effort", drift_detectable: true,
        drift_detectors: &["security/weak-crypto"], detection_method: CweDetectionMethod::Pattern, .. },

    // === A05: Injection (beyond Top 25) ===
    CweEntry { id: 90, name: "LDAP Injection", drift_detectable: true,
        drift_detectors: &["taint/ldap-query"], detection_method: CweDetectionMethod::Taint, .. },
    CweEntry { id: 117, name: "Log Injection", drift_detectable: true,
        drift_detectors: &["taint/log-output", "logging/sensitive-data"], detection_method: CweDetectionMethod::Taint, .. },
    CweEntry { id: 643, name: "XPath Injection", drift_detectable: true,
        drift_detectors: &["taint/xpath-query"], detection_method: CweDetectionMethod::Taint, .. },
    CweEntry { id: 917, name: "Expression Language Injection", drift_detectable: true,
        drift_detectors: &["taint/code-execution"], detection_method: CweDetectionMethod::Taint, .. },
    CweEntry { id: 1336, name: "Template Injection", drift_detectable: true,
        drift_detectors: &["security/template-injection", "taint/template-render"], detection_method: CweDetectionMethod::Taint, .. },

    // === A07: Authentication Failures (beyond Top 25) ===
    CweEntry { id: 256, name: "Plaintext Storage of Password", drift_detectable: true,
        drift_detectors: &["auth/credential-storage"], detection_method: CweDetectionMethod::Pattern, .. },
    CweEntry { id: 257, name: "Storing Passwords in Recoverable Format", drift_detectable: true,
        drift_detectors: &["auth/credential-storage"], detection_method: CweDetectionMethod::Pattern, .. },
    CweEntry { id: 287, name: "Improper Authentication", drift_detectable: true,
        drift_detectors: &["security/authentication"], detection_method: CweDetectionMethod::Structural, .. },
    CweEntry { id: 384, name: "Session Fixation", drift_detectable: true,
        drift_detectors: &["auth/session-management"], detection_method: CweDetectionMethod::Pattern, .. },
    CweEntry { id: 522, name: "Insufficiently Protected Credentials", drift_detectable: true,
        drift_detectors: &["auth/credential-storage", "security/hardcoded-secrets"], detection_method: CweDetectionMethod::Pattern, .. },
    CweEntry { id: 613, name: "Insufficient Session Expiration", drift_detectable: true,
        drift_detectors: &["auth/session-management"], detection_method: CweDetectionMethod::Pattern, .. },
    CweEntry { id: 640, name: "Weak Password Recovery", drift_detectable: true,
        drift_detectors: &["auth/password-policy"], detection_method: CweDetectionMethod::Pattern, .. },

    // === A08: Integrity Failures (beyond Top 25) ===
    CweEntry { id: 345, name: "Insufficient Verification of Data Authenticity", drift_detectable: true,
        drift_detectors: &["security/insecure-deserialization"], detection_method: CweDetectionMethod::Pattern, .. },
    CweEntry { id: 494, name: "Download of Code Without Integrity Check", drift_detectable: true,
        drift_detectors: &["security/dependency-audit"], detection_method: CweDetectionMethod::SupplyChain, .. },

    // === A09: Logging & Alerting (beyond Top 25) ===
    CweEntry { id: 223, name: "Omission of Security-relevant Information", drift_detectable: true,
        drift_detectors: &["logging/audit-trail"], detection_method: CweDetectionMethod::Pattern, .. },
    CweEntry { id: 532, name: "Insertion of Sensitive Info into Log File", drift_detectable: true,
        drift_detectors: &["logging/sensitive-data"], detection_method: CweDetectionMethod::Pattern, .. },
    CweEntry { id: 778, name: "Insufficient Logging", drift_detectable: true,
        drift_detectors: &["logging/audit-trail", "logging/log-levels"], detection_method: CweDetectionMethod::Pattern, .. },

    // === A10: Exceptional Conditions (beyond Top 25) ===
    CweEntry { id: 248, name: "Uncaught Exception", drift_detectable: true,
        drift_detectors: &["errors/unhandled-rejection"], detection_method: CweDetectionMethod::Pattern, .. },
    CweEntry { id: 252, name: "Unchecked Return Value", drift_detectable: true,
        drift_detectors: &["errors/swallowed-errors"], detection_method: CweDetectionMethod::Pattern, .. },
    CweEntry { id: 280, name: "Improper Handling of Insufficient Permissions", drift_detectable: true,
        drift_detectors: &["errors/error-recovery"], detection_method: CweDetectionMethod::Pattern, .. },
    CweEntry { id: 390, name: "Detection of Error Condition Without Action", drift_detectable: true,
        drift_detectors: &["errors/empty-catch"], detection_method: CweDetectionMethod::Pattern, .. },
    CweEntry { id: 392, name: "Missing Report of Error Condition", drift_detectable: true,
        drift_detectors: &["errors/swallowed-errors"], detection_method: CweDetectionMethod::Pattern, .. },
    CweEntry { id: 394, name: "Unexpected Status Code or Return Value", drift_detectable: true,
        drift_detectors: &["errors/error-propagation"], detection_method: CweDetectionMethod::Pattern, .. },
    CweEntry { id: 395, name: "Use of NullPointerException Catch", drift_detectable: true,
        drift_detectors: &["errors/empty-catch"], detection_method: CweDetectionMethod::Pattern, .. },
    CweEntry { id: 396, name: "Declaration of Catch for Generic Exception", drift_detectable: true,
        drift_detectors: &["errors/try-catch"], detection_method: CweDetectionMethod::Pattern, .. },
    CweEntry { id: 397, name: "Declaration of Throws for Generic Exception", drift_detectable: true,
        drift_detectors: &["errors/error-types"], detection_method: CweDetectionMethod::Pattern, .. },
    CweEntry { id: 754, name: "Improper Check for Unusual Conditions", drift_detectable: true,
        drift_detectors: &["errors/error-recovery"], detection_method: CweDetectionMethod::Pattern, .. },
    CweEntry { id: 755, name: "Improper Handling of Exceptional Conditions", drift_detectable: true,
        drift_detectors: &["errors/graceful-degradation"], detection_method: CweDetectionMethod::Pattern, .. },
    CweEntry { id: 756, name: "Missing Custom Error Page", drift_detectable: true,
        drift_detectors: &["errors/error-boundary"], detection_method: CweDetectionMethod::Pattern, .. },
];
```

### 7.2 Total CWE Coverage Summary

| Category | Top 25 CWEs | Extended CWEs | Total Detectable | Total Registered |
|----------|-------------|---------------|-----------------|-----------------|
| A01 Broken Access Control | 6 | 4 | 10 | 10 |
| A02 Security Misconfiguration | 1 | 6 | 7 | 7 |
| A03 Supply Chain Failures | 0 | 0 | 0 | 5 |
| A04 Cryptographic Failures | 0 | 10 | 10 | 10 |
| A05 Injection | 7 | 5 | 12 | 12 |
| A06 Insecure Design | 0 | 0 | 0 | 8 |
| A07 Authentication Failures | 1 | 7 | 8 | 8 |
| A08 Integrity Failures | 1 | 2 | 3 | 8 |
| A09 Logging & Alerting | 0 | 3 | 3 | 4 |
| A10 Exceptional Conditions | 0 | 11 | 11 | 12 |
| **Total** | **18** | **48** | **64** | **84** |

**Total registered CWEs: ~120 (Top 25 + Extended)**
**Total detectable CWEs: ~64 (53% of registered)**
**Not detectable: ~56 (memory safety, runtime-only, design-level)**

---

## 8. Detector → CWE/OWASP Mapping Matrix (All 16 Categories)

This is the master mapping matrix. Every detector in the Drift system maps to zero
or more CWE IDs and zero or more OWASP categories. Detectors with no security
relevance map to empty arrays.

### 8.1 Security-Relevant Detector Mappings

```rust
/// Master mapping: detector ID → (CWE IDs, OWASP categories).
/// Only security-relevant detectors are listed. Non-security detectors
/// (components/naming, styling/*, etc.) have empty mappings.
pub const DETECTOR_MAPPING: &[DetectorMapping] = &[
    // === Category 2: API ===
    DetectorMapping { detector_id: "api/rate-limiting", cwe_ids: &[770],
        owasp: &[OwaspCategory::A02SecurityMisconfiguration] },
    DetectorMapping { detector_id: "api/request-validation", cwe_ids: &[20],
        owasp: &[OwaspCategory::A05Injection] },
    DetectorMapping { detector_id: "api/authentication", cwe_ids: &[287, 306],
        owasp: &[OwaspCategory::A07AuthenticationFailures] },

    // === Category 3: Auth ===
    DetectorMapping { detector_id: "auth/permission-checks", cwe_ids: &[862, 863, 284, 639, 425],
        owasp: &[OwaspCategory::A01BrokenAccessControl] },
    DetectorMapping { detector_id: "auth/rbac-patterns", cwe_ids: &[863, 285],
        owasp: &[OwaspCategory::A01BrokenAccessControl] },
    DetectorMapping { detector_id: "auth/session-management", cwe_ids: &[384, 613, 1004, 614],
        owasp: &[OwaspCategory::A07AuthenticationFailures] },
    DetectorMapping { detector_id: "auth/token-handling", cwe_ids: &[287],
        owasp: &[OwaspCategory::A07AuthenticationFailures] },
    DetectorMapping { detector_id: "auth/password-policy", cwe_ids: &[521, 640],
        owasp: &[OwaspCategory::A07AuthenticationFailures] },
    DetectorMapping { detector_id: "auth/mfa-checks", cwe_ids: &[308],
        owasp: &[OwaspCategory::A07AuthenticationFailures] },
    DetectorMapping { detector_id: "auth/credential-storage", cwe_ids: &[256, 257, 522],
        owasp: &[OwaspCategory::A07AuthenticationFailures] },
    DetectorMapping { detector_id: "auth/oauth-patterns", cwe_ids: &[287],
        owasp: &[OwaspCategory::A07AuthenticationFailures] },
    DetectorMapping { detector_id: "auth/cors-config", cwe_ids: &[942, 346],
        owasp: &[OwaspCategory::A01BrokenAccessControl, OwaspCategory::A02SecurityMisconfiguration] },
    DetectorMapping { detector_id: "auth/csrf-protection", cwe_ids: &[352],
        owasp: &[OwaspCategory::A01BrokenAccessControl] },

    // === Category 5: Config ===
    DetectorMapping { detector_id: "config/secrets-handling", cwe_ids: &[798, 547, 312],
        owasp: &[OwaspCategory::A04CryptographicFailures, OwaspCategory::A07AuthenticationFailures] },
    DetectorMapping { detector_id: "config/debug-mode", cwe_ids: &[16, 489],
        owasp: &[OwaspCategory::A02SecurityMisconfiguration] },

    // === Category 7: Data Access ===
    DetectorMapping { detector_id: "data-access/sql-injection", cwe_ids: &[89],
        owasp: &[OwaspCategory::A05Injection] },
    DetectorMapping { detector_id: "data-access/sensitive-data", cwe_ids: &[200, 312],
        owasp: &[OwaspCategory::A01BrokenAccessControl, OwaspCategory::A04CryptographicFailures] },
    DetectorMapping { detector_id: "data-access/parameterization", cwe_ids: &[89],
        owasp: &[OwaspCategory::A05Injection] },

    // === Category 10: Logging ===
    DetectorMapping { detector_id: "logging/sensitive-data", cwe_ids: &[532, 117, 200],
        owasp: &[OwaspCategory::A09LoggingAlertingFailures] },
    DetectorMapping { detector_id: "logging/audit-trail", cwe_ids: &[223, 778],
        owasp: &[OwaspCategory::A09LoggingAlertingFailures] },

    // === Category 12: Security (all 18 detectors) ===
    DetectorMapping { detector_id: "security/xss-prevention", cwe_ids: &[79],
        owasp: &[OwaspCategory::A05Injection] },
    DetectorMapping { detector_id: "security/input-validation", cwe_ids: &[20, 434],
        owasp: &[OwaspCategory::A05Injection] },
    DetectorMapping { detector_id: "security/output-encoding", cwe_ids: &[79, 116],
        owasp: &[OwaspCategory::A05Injection] },
    DetectorMapping { detector_id: "security/dependency-audit", cwe_ids: &[829, 1104, 937],
        owasp: &[OwaspCategory::A03SupplyChainFailures] },
    DetectorMapping { detector_id: "security/hardcoded-secrets", cwe_ids: &[798, 321, 547, 312],
        owasp: &[OwaspCategory::A04CryptographicFailures, OwaspCategory::A07AuthenticationFailures] },
    DetectorMapping { detector_id: "security/encryption", cwe_ids: &[311, 326],
        owasp: &[OwaspCategory::A04CryptographicFailures] },
    DetectorMapping { detector_id: "security/authentication", cwe_ids: &[287, 306],
        owasp: &[OwaspCategory::A07AuthenticationFailures] },
    DetectorMapping { detector_id: "security/authorization", cwe_ids: &[862, 863, 284],
        owasp: &[OwaspCategory::A01BrokenAccessControl] },
    DetectorMapping { detector_id: "security/weak-crypto", cwe_ids: &[327, 328, 330, 326, 916],
        owasp: &[OwaspCategory::A04CryptographicFailures] },
    DetectorMapping { detector_id: "security/insecure-random", cwe_ids: &[330],
        owasp: &[OwaspCategory::A04CryptographicFailures] },
    DetectorMapping { detector_id: "security/command-injection", cwe_ids: &[78, 77],
        owasp: &[OwaspCategory::A05Injection] },
    DetectorMapping { detector_id: "security/ssrf", cwe_ids: &[918],
        owasp: &[OwaspCategory::A01BrokenAccessControl] },
    DetectorMapping { detector_id: "security/path-traversal", cwe_ids: &[22],
        owasp: &[OwaspCategory::A01BrokenAccessControl, OwaspCategory::A05Injection] },
    DetectorMapping { detector_id: "security/insecure-deserialization", cwe_ids: &[502],
        owasp: &[OwaspCategory::A08IntegrityFailures] },
    DetectorMapping { detector_id: "security/missing-security-headers", cwe_ids: &[693, 1021],
        owasp: &[OwaspCategory::A02SecurityMisconfiguration] },
    DetectorMapping { detector_id: "security/cors-misconfiguration", cwe_ids: &[942, 346],
        owasp: &[OwaspCategory::A02SecurityMisconfiguration] },
    DetectorMapping { detector_id: "security/template-injection", cwe_ids: &[1336],
        owasp: &[OwaspCategory::A05Injection] },
    DetectorMapping { detector_id: "security/open-redirect", cwe_ids: &[601],
        owasp: &[OwaspCategory::A01BrokenAccessControl] },

    // === Category 9: Errors (maps to A10:2025) ===
    DetectorMapping { detector_id: "errors/empty-catch", cwe_ids: &[390, 395],
        owasp: &[OwaspCategory::A10ExceptionalConditions] },
    DetectorMapping { detector_id: "errors/swallowed-errors", cwe_ids: &[252, 392],
        owasp: &[OwaspCategory::A10ExceptionalConditions] },
    DetectorMapping { detector_id: "errors/error-propagation", cwe_ids: &[394],
        owasp: &[OwaspCategory::A10ExceptionalConditions] },
    DetectorMapping { detector_id: "errors/error-recovery", cwe_ids: &[280, 754],
        owasp: &[OwaspCategory::A10ExceptionalConditions] },
    DetectorMapping { detector_id: "errors/graceful-degradation", cwe_ids: &[755],
        owasp: &[OwaspCategory::A10ExceptionalConditions] },
    DetectorMapping { detector_id: "errors/unhandled-rejection", cwe_ids: &[248],
        owasp: &[OwaspCategory::A10ExceptionalConditions] },
    DetectorMapping { detector_id: "errors/try-catch", cwe_ids: &[396],
        owasp: &[OwaspCategory::A10ExceptionalConditions] },
    DetectorMapping { detector_id: "errors/error-types", cwe_ids: &[397],
        owasp: &[OwaspCategory::A10ExceptionalConditions] },
    DetectorMapping { detector_id: "errors/error-boundary", cwe_ids: &[756],
        owasp: &[OwaspCategory::A10ExceptionalConditions] },
];

/// A single detector → CWE/OWASP mapping entry.
pub struct DetectorMapping {
    pub detector_id: &'static str,
    pub cwe_ids: &'static [u32],
    pub owasp: &'static [OwaspCategory],
}
```

### 8.2 Mapping Statistics

| Metric | Count |
|--------|-------|
| Total detectors with CWE mappings | 47 |
| Total detectors without CWE mappings | 126 (non-security) |
| Total unique CWE IDs mapped | 64 |
| Total OWASP categories covered | 10/10 |
| Detectors mapping to A01 (Access Control) | 11 |
| Detectors mapping to A02 (Misconfiguration) | 5 |
| Detectors mapping to A03 (Supply Chain) | 1 |
| Detectors mapping to A04 (Crypto) | 7 |
| Detectors mapping to A05 (Injection) | 10 |
| Detectors mapping to A06 (Insecure Design) | 2 |
| Detectors mapping to A07 (Authentication) | 10 |
| Detectors mapping to A08 (Integrity) | 1 |
| Detectors mapping to A09 (Logging) | 2 |
| Detectors mapping to A10 (Exceptions) | 9 |


---

## 9. Taint Sink → CWE Mapping (13 Sink Types)

The taint analysis subsystem (§15) defines 13 sink types. Each maps to a specific CWE.
This mapping is consumed by the finding enrichment pipeline to attach CWE/OWASP
metadata to taint findings.

```rust
/// Taint sink type → CWE/OWASP mapping.
/// Source: 15-TAINT-ANALYSIS-V2-PREP.md §4 SinkType enum.
pub const TAINT_SINK_MAPPING: &[TaintSinkMapping] = &[
    TaintSinkMapping { sink: SinkType::SqlQuery, cwe_id: 89,
        owasp: OwaspCategory::A05Injection, severity: FindingSeverity::Critical,
        description: "SQL Injection — untrusted input reaches SQL query" },
    TaintSinkMapping { sink: SinkType::OsCommand, cwe_id: 78,
        owasp: OwaspCategory::A05Injection, severity: FindingSeverity::Critical,
        description: "OS Command Injection — untrusted input reaches system command" },
    TaintSinkMapping { sink: SinkType::CodeExecution, cwe_id: 94,
        owasp: OwaspCategory::A05Injection, severity: FindingSeverity::Critical,
        description: "Code Injection — untrusted input reaches eval/exec" },
    TaintSinkMapping { sink: SinkType::FileWrite, cwe_id: 22,
        owasp: OwaspCategory::A01BrokenAccessControl, severity: FindingSeverity::High,
        description: "Path Traversal (write) — untrusted input in file write path" },
    TaintSinkMapping { sink: SinkType::FileRead, cwe_id: 22,
        owasp: OwaspCategory::A01BrokenAccessControl, severity: FindingSeverity::High,
        description: "Path Traversal (read) — untrusted input in file read path" },
    TaintSinkMapping { sink: SinkType::HtmlOutput, cwe_id: 79,
        owasp: OwaspCategory::A05Injection, severity: FindingSeverity::High,
        description: "Cross-Site Scripting — untrusted input in HTML output" },
    TaintSinkMapping { sink: SinkType::HttpRedirect, cwe_id: 601,
        owasp: OwaspCategory::A01BrokenAccessControl, severity: FindingSeverity::Medium,
        description: "Open Redirect — untrusted input in redirect URL" },
    TaintSinkMapping { sink: SinkType::HttpRequest, cwe_id: 918,
        owasp: OwaspCategory::A01BrokenAccessControl, severity: FindingSeverity::High,
        description: "SSRF — untrusted input in outbound HTTP request URL" },
    TaintSinkMapping { sink: SinkType::Deserialization, cwe_id: 502,
        owasp: OwaspCategory::A08IntegrityFailures, severity: FindingSeverity::Critical,
        description: "Insecure Deserialization — untrusted data deserialized" },
    TaintSinkMapping { sink: SinkType::LdapQuery, cwe_id: 90,
        owasp: OwaspCategory::A05Injection, severity: FindingSeverity::High,
        description: "LDAP Injection — untrusted input in LDAP query" },
    TaintSinkMapping { sink: SinkType::XpathQuery, cwe_id: 643,
        owasp: OwaspCategory::A05Injection, severity: FindingSeverity::High,
        description: "XPath Injection — untrusted input in XPath query" },
    TaintSinkMapping { sink: SinkType::TemplateRender, cwe_id: 1336,
        owasp: OwaspCategory::A05Injection, severity: FindingSeverity::Critical,
        description: "Template Injection — untrusted input in template rendering" },
    TaintSinkMapping { sink: SinkType::LogOutput, cwe_id: 117,
        owasp: OwaspCategory::A09LoggingAlertingFailures, severity: FindingSeverity::Medium,
        description: "Log Injection — untrusted input in log output" },
];

pub struct TaintSinkMapping {
    pub sink: SinkType,
    pub cwe_id: u32,
    pub owasp: OwaspCategory,
    pub severity: FindingSeverity,
    pub description: &'static str,
}
```

---

## 10. Secret Pattern → CWE/OWASP Mapping (100+ Patterns)

The constants/environment subsystem (§22) defines 100+ secret detection patterns.
Each pattern maps to a CWE and OWASP category. The mapping is defined in the
SecretPattern struct (§22 §7.1) and consumed by this subsystem for unified reporting.

### 10.1 Secret Type → CWE/OWASP Summary

| Secret Type | CWE | OWASP | Severity |
|------------|-----|-------|----------|
| Hardcoded credentials (passwords, tokens) | CWE-798 | A04:2025, A07:2025 | Critical |
| Hardcoded cryptographic key | CWE-321 | A04:2025 | Critical |
| Security-relevant constant | CWE-547 | A04:2025 | High |
| Cleartext password in source | CWE-312 | A04:2025 | Critical |
| Insufficiently protected credentials | CWE-522 | A07:2025 | High |
| API key in source code | CWE-798 | A04:2025 | High |
| Connection string with credentials | CWE-798 | A04:2025 | Critical |
| Private key in source code | CWE-321 | A04:2025 | Critical |
| OAuth client secret | CWE-798 | A07:2025 | High |
| JWT secret/signing key | CWE-321 | A04:2025 | Critical |

### 10.2 Provider-Specific Secret Patterns (Sample)

| Provider | Pattern | CWE | OWASP |
|----------|---------|-----|-------|
| AWS | `AKIA[0-9A-Z]{16}` | CWE-798 | A04:2025 |
| AWS | `aws_secret_access_key` | CWE-798 | A04:2025 |
| GCP | `AIza[0-9A-Za-z_-]{35}` | CWE-798 | A04:2025 |
| Azure | `DefaultEndpointsProtocol=` | CWE-798 | A04:2025 |
| GitHub | `gh[ps]_[A-Za-z0-9_]{36}` | CWE-798 | A04:2025 |
| Stripe | `sk_live_[0-9a-zA-Z]{24}` | CWE-798 | A04:2025 |
| Slack | `xox[baprs]-[0-9a-zA-Z-]+` | CWE-798 | A04:2025 |
| SendGrid | `SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}` | CWE-798 | A04:2025 |
| Twilio | `SK[0-9a-fA-F]{32}` | CWE-798 | A04:2025 |
| npm | `npm_[A-Za-z0-9]{36}` | CWE-798 | A04:2025 |
| PyPI | `pypi-[A-Za-z0-9_-]{100,}` | CWE-798 | A04:2025 |
| Generic private key | `-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----` | CWE-321 | A04:2025 |
| Generic password | `password\s*[:=]\s*['"][^'"]+['"]` | CWE-798 | A07:2025 |

---

## 11. Error Gap → CWE/OWASP Mapping

The error handling analysis subsystem (§16) detects error handling gaps. Each gap
type maps to CWE/OWASP identifiers, with A10:2025 (Mishandling of Exceptional
Conditions) as the primary OWASP category.

```rust
/// Error gap type → CWE/OWASP mapping.
/// Source: 16-ERROR-HANDLING-ANALYSIS-V2-PREP.md, .research/19-error-handling/RECOMMENDATIONS.md.
pub const ERROR_GAP_MAPPING: &[ErrorGapMapping] = &[
    ErrorGapMapping { gap_type: ErrorGapType::EmptyCatch,
        cwe_ids: &[390, 395], owasp: OwaspCategory::A10ExceptionalConditions,
        severity: FindingSeverity::Medium,
        description: "Empty catch block — error detected but no action taken" },
    ErrorGapMapping { gap_type: ErrorGapType::SwallowedError,
        cwe_ids: &[252, 392], owasp: OwaspCategory::A10ExceptionalConditions,
        severity: FindingSeverity::Medium,
        description: "Error caught but not logged, re-thrown, or handled" },
    ErrorGapMapping { gap_type: ErrorGapType::GenericCatch,
        cwe_ids: &[396], owasp: OwaspCategory::A10ExceptionalConditions,
        severity: FindingSeverity::Low,
        description: "Catch block catches generic Exception instead of specific type" },
    ErrorGapMapping { gap_type: ErrorGapType::GenericThrow,
        cwe_ids: &[397], owasp: OwaspCategory::A10ExceptionalConditions,
        severity: FindingSeverity::Low,
        description: "Method declares throws generic Exception" },
    ErrorGapMapping { gap_type: ErrorGapType::UnhandledRejection,
        cwe_ids: &[248], owasp: OwaspCategory::A10ExceptionalConditions,
        severity: FindingSeverity::High,
        description: "Promise rejection not handled — may crash process" },
    ErrorGapMapping { gap_type: ErrorGapType::FailOpen,
        cwe_ids: &[280, 636], owasp: OwaspCategory::A10ExceptionalConditions,
        severity: FindingSeverity::Critical,
        description: "Error causes security check to be bypassed (fail-open)" },
    ErrorGapMapping { gap_type: ErrorGapType::InformationDisclosure,
        cwe_ids: &[209, 200], owasp: OwaspCategory::A10ExceptionalConditions,
        severity: FindingSeverity::Medium,
        description: "Error message exposes sensitive information (stack trace, DB schema)" },
    ErrorGapMapping { gap_type: ErrorGapType::SensitiveDataInLog,
        cwe_ids: &[532], owasp: OwaspCategory::A09LoggingAlertingFailures,
        severity: FindingSeverity::Medium,
        description: "Sensitive data included in error log output" },
    ErrorGapMapping { gap_type: ErrorGapType::MissingErrorBoundary,
        cwe_ids: &[756], owasp: OwaspCategory::A10ExceptionalConditions,
        severity: FindingSeverity::Low,
        description: "No error boundary for component tree — unhandled errors crash UI" },
    ErrorGapMapping { gap_type: ErrorGapType::UncheckedReturnValue,
        cwe_ids: &[252], owasp: OwaspCategory::A10ExceptionalConditions,
        severity: FindingSeverity::Medium,
        description: "Return value from security-critical function not checked" },
    ErrorGapMapping { gap_type: ErrorGapType::ImproperRecovery,
        cwe_ids: &[754, 755], owasp: OwaspCategory::A10ExceptionalConditions,
        severity: FindingSeverity::Medium,
        description: "Error recovery does not restore system to safe state" },
    ErrorGapMapping { gap_type: ErrorGapType::MissingRetry,
        cwe_ids: &[754], owasp: OwaspCategory::A10ExceptionalConditions,
        severity: FindingSeverity::Low,
        description: "Transient failure not retried — may cause cascading failure" },
];

pub struct ErrorGapMapping {
    pub gap_type: ErrorGapType,
    pub cwe_ids: &'static [u32],
    pub owasp: OwaspCategory,
    pub severity: FindingSeverity,
    pub description: &'static str,
}
```

---

## 12. Boundary Violation → CWE/OWASP Mapping

The boundary detection subsystem (§07) detects unauthorized data access. Each
violation type maps to CWE/OWASP identifiers.

```rust
/// Boundary violation type → CWE/OWASP mapping.
pub const BOUNDARY_VIOLATION_MAPPING: &[BoundaryViolationMapping] = &[
    BoundaryViolationMapping {
        violation_type: BoundaryViolationType::UnauthorizedFile,
        cwe_ids: &[862, 284],
        owasp: OwaspCategory::A01BrokenAccessControl,
        severity: FindingSeverity::High,
        description: "Code accesses data table from unauthorized file/module",
    },
    BoundaryViolationMapping {
        violation_type: BoundaryViolationType::UnauthorizedOperation,
        cwe_ids: &[863, 285],
        owasp: OwaspCategory::A01BrokenAccessControl,
        severity: FindingSeverity::High,
        description: "Code performs unauthorized operation (e.g., write to read-only table)",
    },
    BoundaryViolationMapping {
        violation_type: BoundaryViolationType::MissingAuth,
        cwe_ids: &[306, 287],
        owasp: OwaspCategory::A07AuthenticationFailures,
        severity: FindingSeverity::Critical,
        description: "Data access without required authentication middleware",
    },
    BoundaryViolationMapping {
        violation_type: BoundaryViolationType::SensitiveDataExposure,
        cwe_ids: &[200, 312],
        owasp: OwaspCategory::A04CryptographicFailures,
        severity: FindingSeverity::High,
        description: "Sensitive data (PII, credentials, financial) accessed without protection",
    },
    BoundaryViolationMapping {
        violation_type: BoundaryViolationType::UnsafeOrmApi,
        cwe_ids: &[89],
        owasp: OwaspCategory::A05Injection,
        severity: FindingSeverity::High,
        description: "Raw SQL bypass used instead of parameterized ORM API",
    },
];

pub struct BoundaryViolationMapping {
    pub violation_type: BoundaryViolationType,
    pub cwe_ids: &'static [u32],
    pub owasp: OwaspCategory,
    pub severity: FindingSeverity,
    pub description: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundaryViolationType {
    UnauthorizedFile,
    UnauthorizedOperation,
    MissingAuth,
    SensitiveDataExposure,
    UnsafeOrmApi,
}
```


---

## 13. Security Wrapper Detection Engine

The security wrapper detection engine identifies functions that wrap security
primitives. This is critical for three downstream consumers:

1. **Taint analysis**: Security wrappers that sanitize input must be recognized
   as sanitizers, otherwise taint analysis produces false positives.
2. **Constraint verification**: The `auth-before-access` constraint type needs
   to know which functions are auth wrappers.
3. **Security posture scoring**: Consistent use of security wrappers indicates
   mature security practices.

### 13.1 Detection Algorithm

```rust
/// Security wrapper detection engine.
pub struct SecurityWrapperDetector {
    /// Registry of known security primitives per framework.
    primitive_registry: SecurityPrimitiveRegistry,
    /// Call graph for cross-file usage analysis.
    call_graph: Option<Arc<CallGraphDb>>,
    /// String interner for memory-efficient storage.
    interner: Arc<ThreadedRodeo>,
}

impl SecurityWrapperDetector {
    /// Detect security wrappers in a single file's ParseResult.
    ///
    /// Algorithm:
    /// 1. For each function in ParseResult.functions:
    ///    a. Extract all call sites within the function body
    ///    b. Check each call site against the security primitive registry
    ///    c. If a call site matches a security primitive:
    ///       - Check if the function is a "thin wrapper" (delegates to primitive
    ///         with minimal additional logic)
    ///       - Calculate confidence based on 4 factors (§16)
    ///       - Classify the wrapper category (§14)
    ///       - Determine if the wrapper is a sanitizer (for taint)
    ///    d. If the function wraps multiple primitives from the same category,
    ///       it's a "composite wrapper" (e.g., auth + RBAC check)
    /// 2. If call graph is available:
    ///    a. Count usage sites for each detected wrapper
    ///    b. Detect "orphan wrappers" (defined but never used)
    ///    c. Detect "bypass patterns" (direct primitive use alongside wrapper)
    pub fn detect_in_file(
        &self,
        parse_result: &ParseResult,
        file_path: Spur,
    ) -> Vec<SecurityWrapper> {
        let mut wrappers = Vec::new();

        for function in &parse_result.functions {
            let mut matched_primitives = SmallVec::<[SecurityPrimitiveMatch; 2]>::new();

            for call_site in &function.call_sites {
                if let Some(primitive) = self.primitive_registry.lookup(&call_site.callee) {
                    matched_primitives.push(SecurityPrimitiveMatch {
                        primitive,
                        call_site: call_site.clone(),
                    });
                }
            }

            if matched_primitives.is_empty() {
                continue;
            }

            // Determine wrapper category from matched primitives
            let category = self.classify_category(&matched_primitives);
            let confidence = self.calculate_confidence(function, &matched_primitives);
            let is_sanitizer = self.is_sanitizer(category, &matched_primitives);
            let sanitizes_labels = if is_sanitizer {
                self.infer_sanitized_labels(category, &matched_primitives)
            } else {
                SmallVec::new()
            };

            let usage_count = self.call_graph.as_ref()
                .map(|cg| cg.callers_of(&function.name).len() as u32)
                .unwrap_or(0);

            wrappers.push(SecurityWrapper {
                id: hash_wrapper_id(file_path, &function.name),
                function_name: self.interner.get_or_intern(&function.name),
                file: file_path,
                line: function.line,
                category,
                wrapped_primitives: matched_primitives.iter()
                    .map(|m| self.interner.get_or_intern(m.primitive.name))
                    .collect(),
                framework: matched_primitives.first()
                    .and_then(|m| m.primitive.framework)
                    .map(|f| self.interner.get_or_intern(f)),
                confidence,
                usage_count,
                is_exported: function.is_exported,
                is_sanitizer,
                sanitizes_labels,
                content_hash: parse_result.content_hash,
            });
        }

        wrappers
    }
}
```

### 13.2 Thin Wrapper Detection

A function is a "thin wrapper" if it primarily delegates to a security primitive
with minimal additional logic. The heuristic:

```rust
/// Determine if a function is a thin wrapper around a security primitive.
/// Thin wrappers have:
/// - 1-3 security primitive calls
/// - Total function body ≤ 20 AST nodes (excluding the primitive calls)
/// - No complex control flow (no loops, limited branching)
fn is_thin_wrapper(function: &FunctionInfo, primitives: &[SecurityPrimitiveMatch]) -> bool {
    let primitive_count = primitives.len();
    let total_statements = function.statement_count;
    let has_loops = function.has_loops;

    // Thin wrapper: few statements beyond the primitive calls
    primitive_count >= 1
        && primitive_count <= 3
        && total_statements <= 20
        && !has_loops
}
```

### 13.3 Bypass Pattern Detection

When a security wrapper exists but code also calls the primitive directly, that's
a "bypass pattern" — a potential security concern.

```rust
/// Detect bypass patterns: direct primitive use alongside wrapper existence.
/// Returns files/functions that call the primitive directly instead of using
/// the wrapper.
pub fn detect_bypass_patterns(
    &self,
    wrappers: &[SecurityWrapper],
    call_graph: &CallGraphDb,
) -> Vec<BypassPattern> {
    let mut bypasses = Vec::new();

    for wrapper in wrappers {
        for primitive in &wrapper.wrapped_primitives {
            // Find all callers of the primitive
            let primitive_callers = call_graph.callers_of(primitive);
            // Find all callers of the wrapper
            let wrapper_callers = call_graph.callers_of(&wrapper.function_name);

            // Callers that use the primitive directly but NOT the wrapper
            for caller in &primitive_callers {
                if !wrapper_callers.contains(caller) && caller != &wrapper.function_name {
                    bypasses.push(BypassPattern {
                        wrapper_id: wrapper.id,
                        primitive: *primitive,
                        bypassing_function: *caller,
                        severity: FindingSeverity::Medium,
                    });
                }
            }
        }
    }

    bypasses
}
```

---

## 14. Wrapper Primitive Registry (Security-Focused)

The security primitive registry defines known security-relevant functions/methods
per framework. This is the lookup table for wrapper detection.

### 14.1 Registry Structure

```rust
pub struct SecurityPrimitiveRegistry {
    /// Primitives indexed by function name for O(1) lookup.
    by_name: FxHashMap<String, SecurityPrimitive>,
    /// Primitives indexed by framework for framework-specific queries.
    by_framework: FxHashMap<String, Vec<SecurityPrimitive>>,
}

#[derive(Debug, Clone)]
pub struct SecurityPrimitive {
    /// Function/method name (e.g., "bcrypt.hash", "jwt.verify").
    pub name: &'static str,
    /// Security wrapper category.
    pub category: SecurityWrapperCategory,
    /// Framework this primitive belongs to (e.g., "express", "django").
    pub framework: Option<&'static str>,
    /// Language this primitive is for.
    pub language: Language,
    /// Whether this primitive is a sanitizer (for taint analysis).
    pub is_sanitizer: bool,
    /// Taint labels this primitive sanitizes (if is_sanitizer).
    pub sanitizes: &'static [TaintLabel],
}
```

### 14.2 Authentication Primitives

| Framework | Primitive | Language | Notes |
|-----------|----------|----------|-------|
| Express/Passport | `passport.authenticate` | TS/JS | Auth middleware |
| Express/Passport | `passport.use` | TS/JS | Strategy registration |
| Express | `express-jwt` | TS/JS | JWT middleware |
| NestJS | `@UseGuards(AuthGuard)` | TS | Decorator-based auth |
| NestJS | `@Auth()` | TS | Custom auth decorator |
| Spring | `@PreAuthorize` | Java | Method-level auth |
| Spring | `@Secured` | Java | Role-based auth |
| Spring | `SecurityContextHolder.getContext` | Java | Auth context access |
| Django | `@login_required` | Python | View auth decorator |
| Django | `@permission_required` | Python | Permission decorator |
| Django | `authenticate()` | Python | Auth function |
| FastAPI | `Depends(get_current_user)` | Python | Dependency injection auth |
| Laravel | `Auth::check()` | PHP | Auth facade |
| Laravel | `->middleware('auth')` | PHP | Route middleware |
| ASP.NET | `[Authorize]` | C# | Auth attribute |
| ASP.NET | `User.Identity.IsAuthenticated` | C# | Auth check |
| Go/Gin | `gin.BasicAuth()` | Go | Basic auth middleware |
| Axum | `Extension<Claims>` | Rust | JWT claims extraction |
| Actix | `HttpRequest::extensions()` | Rust | Auth extension |

### 14.3 Input Sanitization Primitives

| Framework | Primitive | Language | Sanitizes |
|-----------|----------|----------|-----------|
| DOMPurify | `DOMPurify.sanitize` | TS/JS | XSS (CWE-79) |
| validator.js | `validator.escape` | TS/JS | XSS (CWE-79) |
| validator.js | `validator.isEmail` | TS/JS | Input validation |
| express-validator | `body().trim().escape()` | TS/JS | XSS (CWE-79) |
| helmet | `helmet()` | TS/JS | Security headers |
| csurf | `csurf()` | TS/JS | CSRF (CWE-352) |
| Spring | `HtmlUtils.htmlEscape` | Java | XSS (CWE-79) |
| Spring | `@Valid` | Java | Input validation |
| Django | `escape()` | Python | XSS (CWE-79) |
| Django | `mark_safe()` | Python | Explicit safe marking |
| Bleach | `bleach.clean` | Python | XSS (CWE-79) |
| Laravel | `e()` | PHP | XSS (CWE-79) |
| html/template | `template.HTMLEscapeString` | Go | XSS (CWE-79) |
| ammonia | `ammonia::clean` | Rust | XSS (CWE-79) |

### 14.4 Cryptographic Primitives

| Framework | Primitive | Language | Notes |
|-----------|----------|----------|-------|
| bcrypt | `bcrypt.hash` / `bcrypt.compare` | TS/JS | Password hashing |
| argon2 | `argon2.hash` / `argon2.verify` | TS/JS | Password hashing |
| crypto | `crypto.createCipheriv` | TS/JS | Symmetric encryption |
| crypto | `crypto.randomBytes` | TS/JS | Secure random |
| jsonwebtoken | `jwt.sign` / `jwt.verify` | TS/JS | JWT operations |
| Spring Security | `BCryptPasswordEncoder` | Java | Password hashing |
| JCA | `MessageDigest.getInstance("SHA-256")` | Java | Hashing |
| Django | `make_password` / `check_password` | Python | Password hashing |
| cryptography | `Fernet.encrypt` | Python | Symmetric encryption |
| Laravel | `Hash::make` / `Hash::check` | PHP | Password hashing |
| bcrypt (Go) | `bcrypt.GenerateFromPassword` | Go | Password hashing |
| ring | `ring::digest::digest` | Rust | Hashing |
| argon2 | `argon2::hash_encoded` | Rust | Password hashing |

### 14.5 Security Header Primitives

| Framework | Primitive | Language | Headers Set |
|-----------|----------|----------|-------------|
| helmet | `helmet()` | TS/JS | CSP, HSTS, X-Frame, etc. |
| Express | `res.setHeader('Content-Security-Policy', ...)` | TS/JS | CSP |
| Spring | `HttpSecurity.headers()` | Java | All security headers |
| Django | `SecurityMiddleware` | Python | HSTS, X-Frame, etc. |
| Laravel | `->header('X-Frame-Options', 'DENY')` | PHP | X-Frame-Options |
| Gin | `secure.New()` | Go | Security headers middleware |
| Actix | `actix_web::middleware::DefaultHeaders` | Rust | Custom headers |

---

## 15. Wrapper Clustering & Classification

### 15.1 Clustering Algorithm

Security wrappers are clustered by category and framework to identify patterns:

```rust
/// Cluster security wrappers by category and framework.
pub fn cluster_wrappers(wrappers: &[SecurityWrapper]) -> Vec<WrapperCluster> {
    let mut clusters: FxHashMap<(SecurityWrapperCategory, Option<Spur>), Vec<&SecurityWrapper>> =
        FxHashMap::default();

    for wrapper in wrappers {
        clusters
            .entry((wrapper.category, wrapper.framework))
            .or_default()
            .push(wrapper);
    }

    clusters.into_iter().map(|((category, framework), members)| {
        let total_usage: u32 = members.iter().map(|w| w.usage_count).sum();
        let avg_confidence: f32 = members.iter().map(|w| w.confidence).sum::<f32>()
            / members.len() as f32;
        let exported_count = members.iter().filter(|w| w.is_exported).count();
        let sanitizer_count = members.iter().filter(|w| w.is_sanitizer).count();

        WrapperCluster {
            category,
            framework,
            wrapper_count: members.len() as u16,
            total_usage,
            avg_confidence,
            exported_count: exported_count as u16,
            sanitizer_count: sanitizer_count as u16,
            consistency_score: calculate_consistency(&members),
            wrappers: members.iter().map(|w| w.id).collect(),
        }
    }).collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrapperCluster {
    pub category: SecurityWrapperCategory,
    pub framework: Option<Spur>,
    pub wrapper_count: u16,
    pub total_usage: u32,
    pub avg_confidence: f32,
    pub exported_count: u16,
    pub sanitizer_count: u16,
    /// How consistently the wrappers are used (0.0-1.0).
    /// 1.0 = all code uses wrappers, 0.0 = all code bypasses wrappers.
    pub consistency_score: f32,
    pub wrappers: Vec<u64>,
}

/// Calculate wrapper usage consistency.
/// consistency = wrapper_usage / (wrapper_usage + direct_primitive_usage)
fn calculate_consistency(wrappers: &[&SecurityWrapper]) -> f32 {
    // This requires call graph data to count direct primitive usage
    // vs wrapper usage. If call graph unavailable, return 0.5 (unknown).
    // Full implementation uses bypass pattern detection from §13.3.
    0.5 // Placeholder — real implementation uses call graph
}
```

### 15.2 Wrapper Documentation Export

```rust
/// Generate wrapper documentation (markdown format).
/// Preserves v1 feature: packages/core/src/wrappers/export/
pub fn export_wrapper_docs(clusters: &[WrapperCluster], wrappers: &[SecurityWrapper]) -> String {
    let mut doc = String::with_capacity(4096);
    doc.push_str("# Security Wrappers\n\n");

    for cluster in clusters {
        doc.push_str(&format!("## {} Wrappers", cluster.category.name()));
        if let Some(fw) = cluster.framework {
            doc.push_str(&format!(" ({})", fw));
        }
        doc.push_str("\n\n");
        doc.push_str(&format!("- **Count**: {}\n", cluster.wrapper_count));
        doc.push_str(&format!("- **Total Usage**: {} call sites\n", cluster.total_usage));
        doc.push_str(&format!("- **Consistency**: {:.0}%\n", cluster.consistency_score * 100.0));
        doc.push_str(&format!("- **Sanitizers**: {}\n\n", cluster.sanitizer_count));

        for wrapper_id in &cluster.wrappers {
            if let Some(w) = wrappers.iter().find(|w| w.id == *wrapper_id) {
                doc.push_str(&format!("### `{}`\n", w.function_name));
                doc.push_str(&format!("- File: `{}`:{}\n", w.file, w.line));
                doc.push_str(&format!("- Confidence: {:.2}\n", w.confidence));
                doc.push_str(&format!("- Usage: {} call sites\n", w.usage_count));
                if w.is_sanitizer {
                    doc.push_str("- **Sanitizer**: Yes\n");
                }
                doc.push('\n');
            }
        }
    }

    doc
}
```

---

## 16. Wrapper Confidence Scoring

### 16.1 Four-Factor Confidence Model

```rust
/// Calculate confidence score for a security wrapper detection.
/// 4 factors, weighted sum, clamped to [0.0, 1.0].
pub fn calculate_wrapper_confidence(
    function: &FunctionInfo,
    matched_primitives: &[SecurityPrimitiveMatch],
    call_graph: Option<&CallGraphDb>,
) -> f32 {
    // Factor 1: Primitive match strength (0.35 weight)
    // How clearly does the function call a known security primitive?
    let primitive_strength = if matched_primitives.len() == 1 {
        0.9 // Single clear primitive call
    } else if matched_primitives.len() <= 3 {
        0.8 // Composite wrapper (multiple related primitives)
    } else {
        0.5 // Too many primitives — might not be a wrapper
    };

    // Factor 2: Naming signal (0.25 weight)
    // Does the function name suggest security purpose?
    let name_lower = function.name.to_lowercase();
    let naming_signal = if SECURITY_NAME_PATTERNS.iter().any(|p| name_lower.contains(p)) {
        0.9
    } else if GENERIC_WRAPPER_PATTERNS.iter().any(|p| name_lower.contains(p)) {
        0.6
    } else {
        0.3
    };

    // Factor 3: Thin wrapper signal (0.20 weight)
    // Is this a thin delegation wrapper?
    let thin_signal = if is_thin_wrapper(function, matched_primitives) {
        0.9
    } else {
        0.5 // Thicker wrapper — still valid but less certain
    };

    // Factor 4: Usage signal (0.20 weight)
    // Is this wrapper actually used by other code?
    let usage_signal = match call_graph {
        Some(cg) => {
            let callers = cg.callers_of(&function.name).len();
            if callers >= 5 { 1.0 }
            else if callers >= 2 { 0.8 }
            else if callers >= 1 { 0.6 }
            else { 0.3 } // Defined but unused — suspicious
        }
        None => 0.5, // No call graph — neutral
    };

    let score = primitive_strength * 0.35
        + naming_signal * 0.25
        + thin_signal * 0.20
        + usage_signal * 0.20;

    score.clamp(0.0, 1.0)
}

/// Security-related function name patterns.
const SECURITY_NAME_PATTERNS: &[&str] = &[
    "auth", "authenticate", "authorize", "verify", "validate",
    "sanitize", "escape", "encode", "encrypt", "decrypt",
    "hash", "sign", "check_permission", "require_auth",
    "csrf", "cors", "helmet", "guard", "protect",
    "middleware", "interceptor", "filter",
];

/// Generic wrapper name patterns (lower confidence).
const GENERIC_WRAPPER_PATTERNS: &[&str] = &[
    "wrap", "wrapper", "proxy", "delegate", "handle",
    "process", "execute", "run", "invoke",
];
```


---

## 17. OWASP Coverage Calculator

### 17.1 Algorithm

```rust
/// Calculate OWASP Top 10:2025 coverage for the analyzed codebase.
pub fn calculate_owasp_coverage(
    findings: &[SecurityFinding],
    wrappers: &[SecurityWrapper],
    registry: &OwaspRegistry,
) -> OwaspCoverageReport {
    let mut categories = [OwaspCategoryCoverage::default(); 10];

    for (i, owasp_entry) in registry.entries.iter().enumerate() {
        let cat = owasp_entry.category;

        // Count detectors that map to this category
        let detector_count = DETECTOR_MAPPING.iter()
            .filter(|m| m.owasp.contains(&cat))
            .count() as u16;

        // Count detectable CWEs in this category
        let detectable_cwes = CWE_TOP25_2025.iter()
            .chain(EXTENDED_CWE_REGISTRY.iter())
            .filter(|c| c.owasp_categories.contains(&cat) && c.drift_detectable)
            .count() as u16;

        let total_cwes = owasp_entry.primary_cwes.len() as u16;

        // Count findings in this category
        let cat_findings: Vec<&SecurityFinding> = findings.iter()
            .filter(|f| f.owasp_categories.contains(&cat))
            .collect();

        let finding_count = cat_findings.len() as u32;
        let critical_count = cat_findings.iter()
            .filter(|f| f.severity == FindingSeverity::Critical)
            .count() as u32;
        let high_count = cat_findings.iter()
            .filter(|f| f.severity == FindingSeverity::High)
            .count() as u32;

        // Determine coverage depth
        let has_taint = cat_findings.iter().any(|f| f.source == FindingSource::Taint);
        let has_pattern = cat_findings.iter().any(|f| f.source == FindingSource::Detector);
        let has_structural = cat_findings.iter()
            .any(|f| f.source == FindingSource::Boundary || f.source == FindingSource::Wrapper);

        let depth = if has_taint && has_pattern && has_structural {
            CoverageDepth::Full
        } else if has_taint && has_pattern {
            CoverageDepth::Deep
        } else if has_pattern || has_structural {
            CoverageDepth::Shallow
        } else {
            CoverageDepth::None
        };

        // Check for security wrappers
        let cat_wrappers: Vec<&SecurityWrapper> = wrappers.iter()
            .filter(|w| w.category.mitigates_owasp().contains(&cat))
            .collect();

        categories[i] = OwaspCategoryCoverage {
            category: cat,
            detector_count,
            detectable_cwes,
            total_cwes,
            finding_count,
            critical_count,
            high_count,
            depth,
            has_wrappers: !cat_wrappers.is_empty(),
            wrapper_count: cat_wrappers.len() as u16,
        };
    }

    let categories_covered = categories.iter()
        .filter(|c| c.detector_count > 0)
        .count() as u8;

    let total_findings: u32 = categories.iter().map(|c| c.finding_count).sum();
    let critical_findings: u32 = categories.iter().map(|c| c.critical_count).sum();

    OwaspCoverageReport {
        categories,
        overall_coverage: categories_covered as f32 / 10.0,
        categories_covered,
        categories_uncovered: 10 - categories_covered,
        total_findings,
        critical_findings,
        generated_at: chrono::Utc::now().timestamp(),
    }
}
```

---

## 18. CWE Coverage Calculator

```rust
/// Calculate CWE Top 25 coverage for the analyzed codebase.
pub fn calculate_cwe_coverage(
    findings: &[SecurityFinding],
) -> CweCoverageReport {
    let mut top25 = [CweEntryCoverage::default(); 25];

    for (i, cwe) in CWE_TOP25_2025.iter().enumerate() {
        let finding_count = findings.iter()
            .filter(|f| f.cwe_ids.contains(&cwe.id))
            .count() as u32;

        let detector_ids: Vec<String> = cwe.drift_detectors.iter()
            .map(|d| d.to_string())
            .collect();

        top25[i] = CweEntryCoverage {
            cwe_id: cwe.id,
            name: cwe.name.to_string(),
            detectable: cwe.drift_detectable,
            detection_method: cwe.detection_method,
            finding_count,
            detector_ids,
        };
    }

    let extended: Vec<CweEntryCoverage> = EXTENDED_CWE_REGISTRY.iter()
        .map(|cwe| {
            let finding_count = findings.iter()
                .filter(|f| f.cwe_ids.contains(&cwe.id))
                .count() as u32;
            CweEntryCoverage {
                cwe_id: cwe.id,
                name: cwe.name.to_string(),
                detectable: cwe.drift_detectable,
                detection_method: cwe.detection_method,
                finding_count,
                detector_ids: cwe.drift_detectors.iter().map(|d| d.to_string()).collect(),
            }
        })
        .collect();

    let top25_covered = top25.iter().filter(|c| c.detectable).count() as u8;
    let total_covered = top25_covered as u16
        + extended.iter().filter(|c| c.detectable).count() as u16;
    let total_registered = 25 + extended.len() as u16;

    CweCoverageReport {
        top25,
        extended,
        top25_covered,
        total_covered,
        total_registered,
    }
}
```

---

## 19. Security Posture Score (Composite 0-100)

The security posture score is a single composite metric that summarizes the
security health of the analyzed codebase. It is consumed by quality gates,
MCP tools, CLI, and the DNA system's security gene.

### 19.1 Scoring Formula

```rust
/// Calculate the security posture score (0-100).
///
/// Formula:
///   score = 100 - penalty_critical * W_CRITICAL
///              - penalty_high * W_HIGH
///              - penalty_medium * W_MEDIUM
///              - penalty_low * W_LOW
///              + bonus_wrappers * W_WRAPPERS
///              + bonus_coverage * W_COVERAGE
///
/// Clamped to [0, 100].
pub fn calculate_security_posture(
    findings: &[SecurityFinding],
    owasp_coverage: &OwaspCoverageReport,
    wrapper_clusters: &[WrapperCluster],
    total_files: u32,
) -> SecurityPostureScore {
    // Penalty weights per finding severity (per 1000 files)
    const W_CRITICAL: f32 = 5.0;  // Each critical finding costs 5 points
    const W_HIGH: f32 = 2.0;      // Each high finding costs 2 points
    const W_MEDIUM: f32 = 0.5;    // Each medium finding costs 0.5 points
    const W_LOW: f32 = 0.1;       // Each low finding costs 0.1 points

    // Bonus weights
    const W_WRAPPERS: f32 = 10.0;  // Up to 10 points for wrapper consistency
    const W_COVERAGE: f32 = 10.0;  // Up to 10 points for OWASP coverage

    let scale = 1000.0 / total_files.max(1) as f32;

    let critical_count = findings.iter()
        .filter(|f| f.severity == FindingSeverity::Critical).count() as f32;
    let high_count = findings.iter()
        .filter(|f| f.severity == FindingSeverity::High).count() as f32;
    let medium_count = findings.iter()
        .filter(|f| f.severity == FindingSeverity::Medium).count() as f32;
    let low_count = findings.iter()
        .filter(|f| f.severity == FindingSeverity::Low).count() as f32;

    let penalty = (critical_count * W_CRITICAL
        + high_count * W_HIGH
        + medium_count * W_MEDIUM
        + low_count * W_LOW) * scale;

    // Wrapper consistency bonus (average across all clusters)
    let wrapper_bonus = if wrapper_clusters.is_empty() {
        0.0
    } else {
        let avg_consistency: f32 = wrapper_clusters.iter()
            .map(|c| c.consistency_score)
            .sum::<f32>() / wrapper_clusters.len() as f32;
        avg_consistency * W_WRAPPERS
    };

    // OWASP coverage bonus
    let coverage_bonus = owasp_coverage.overall_coverage * W_COVERAGE;

    let score = (100.0 - penalty + wrapper_bonus + coverage_bonus).clamp(0.0, 100.0);

    let grade = match score as u32 {
        90..=100 => SecurityGrade::A,
        80..=89 => SecurityGrade::B,
        70..=79 => SecurityGrade::C,
        60..=69 => SecurityGrade::D,
        _ => SecurityGrade::F,
    };

    SecurityPostureScore {
        score: score as u8,
        grade,
        critical_findings: critical_count as u32,
        high_findings: high_count as u32,
        medium_findings: medium_count as u32,
        low_findings: low_count as u32,
        owasp_coverage: owasp_coverage.overall_coverage,
        wrapper_consistency: wrapper_bonus / W_WRAPPERS,
        top_risks: extract_top_risks(findings, 5),
        generated_at: chrono::Utc::now().timestamp(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPostureScore {
    pub score: u8,
    pub grade: SecurityGrade,
    pub critical_findings: u32,
    pub high_findings: u32,
    pub medium_findings: u32,
    pub low_findings: u32,
    pub owasp_coverage: f32,
    pub wrapper_consistency: f32,
    pub top_risks: Vec<TopRisk>,
    pub generated_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityGrade { A, B, C, D, F }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopRisk {
    pub cwe_id: u32,
    pub cwe_name: String,
    pub finding_count: u32,
    pub max_severity: FindingSeverity,
    pub owasp_category: OwaspCategory,
}
```

---

## 20. Compliance Report Generator

```rust
/// Generate a compliance report summarizing OWASP/CWE coverage and findings.
pub fn generate_compliance_report(
    owasp_coverage: &OwaspCoverageReport,
    cwe_coverage: &CweCoverageReport,
    posture: &SecurityPostureScore,
    findings: &[SecurityFinding],
) -> ComplianceReport {
    ComplianceReport {
        summary: ComplianceSummary {
            security_grade: posture.grade,
            security_score: posture.score,
            owasp_categories_covered: owasp_coverage.categories_covered,
            owasp_categories_total: 10,
            cwe_top25_covered: cwe_coverage.top25_covered,
            cwe_top25_total: 25,
            total_findings: findings.len() as u32,
            critical_findings: posture.critical_findings,
            high_findings: posture.high_findings,
        },
        owasp_details: owasp_coverage.categories.iter().map(|c| {
            OwaspComplianceDetail {
                category: c.category,
                status: if c.finding_count == 0 && c.detector_count > 0 {
                    ComplianceStatus::Pass
                } else if c.critical_count > 0 {
                    ComplianceStatus::CriticalFail
                } else if c.high_count > 0 {
                    ComplianceStatus::Fail
                } else if c.finding_count > 0 {
                    ComplianceStatus::Warning
                } else {
                    ComplianceStatus::NotAssessed
                },
                finding_count: c.finding_count,
                detector_count: c.detector_count,
                depth: c.depth,
            }
        }).collect(),
        cwe_gaps: cwe_coverage.top25.iter()
            .filter(|c| !c.detectable)
            .map(|c| CweGap {
                cwe_id: c.cwe_id,
                name: c.name.clone(),
                reason: "Requires runtime analysis (memory safety)".to_string(),
            })
            .collect(),
        top_risks: posture.top_risks.clone(),
        generated_at: chrono::Utc::now().timestamp(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub summary: ComplianceSummary,
    pub owasp_details: Vec<OwaspComplianceDetail>,
    pub cwe_gaps: Vec<CweGap>,
    pub top_risks: Vec<TopRisk>,
    pub generated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceSummary {
    pub security_grade: SecurityGrade,
    pub security_score: u8,
    pub owasp_categories_covered: u8,
    pub owasp_categories_total: u8,
    pub cwe_top25_covered: u8,
    pub cwe_top25_total: u8,
    pub total_findings: u32,
    pub critical_findings: u32,
    pub high_findings: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComplianceStatus {
    Pass,
    Warning,
    Fail,
    CriticalFail,
    NotAssessed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwaspComplianceDetail {
    pub category: OwaspCategory,
    pub status: ComplianceStatus,
    pub finding_count: u32,
    pub detector_count: u16,
    pub depth: CoverageDepth,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CweGap {
    pub cwe_id: u32,
    pub name: String,
    pub reason: String,
}
```


---

## 21. SARIF Taxonomy Integration

SARIF v2.1.0 supports taxonomies — external classification systems that tools can
reference. Drift uses two taxonomies: CWE and OWASP. This enables GitHub Code
Scanning, Azure DevOps, and other SARIF consumers to display CWE/OWASP metadata
alongside findings.

### 21.1 SARIF Taxonomy Structure

```rust
/// Generate SARIF taxonomy for CWE.
pub fn generate_cwe_taxonomy() -> SarifToolComponent {
    SarifToolComponent {
        name: "CWE".to_string(),
        version: "4.16".to_string(), // CWE version
        organization: "MITRE".to_string(),
        short_description: "Common Weakness Enumeration".to_string(),
        download_uri: "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip".to_string(),
        information_uri: "https://cwe.mitre.org/".to_string(),
        is_comprehensive: false, // Drift doesn't cover all CWEs
        taxa: CWE_TOP25_2025.iter()
            .chain(EXTENDED_CWE_REGISTRY.iter())
            .map(|cwe| SarifTaxon {
                id: format!("CWE-{}", cwe.id),
                name: cwe.name.to_string(),
                short_description: cwe.title.to_string(),
                help_uri: format!("https://cwe.mitre.org/data/definitions/{}.html", cwe.id),
            })
            .collect(),
    }
}

/// Generate SARIF taxonomy for OWASP Top 10:2025.
pub fn generate_owasp_taxonomy() -> SarifToolComponent {
    SarifToolComponent {
        name: "OWASP".to_string(),
        version: "2025".to_string(),
        organization: "OWASP Foundation".to_string(),
        short_description: "OWASP Top 10 Web Application Security Risks".to_string(),
        download_uri: "https://owasp.org/Top10/".to_string(),
        information_uri: "https://owasp.org/Top10/".to_string(),
        is_comprehensive: true, // Drift covers all 10 categories
        taxa: OWASP_2025_REGISTRY.iter()
            .map(|entry| SarifTaxon {
                id: entry.id.to_string(),
                name: entry.name.to_string(),
                short_description: entry.description.to_string(),
                help_uri: format!("https://owasp.org/Top10/{}/", entry.id),
            })
            .collect(),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SarifToolComponent {
    pub name: String,
    pub version: String,
    pub organization: String,
    #[serde(rename = "shortDescription")]
    pub short_description: String,
    #[serde(rename = "downloadUri")]
    pub download_uri: String,
    #[serde(rename = "informationUri")]
    pub information_uri: String,
    #[serde(rename = "isComprehensive")]
    pub is_comprehensive: bool,
    pub taxa: Vec<SarifTaxon>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SarifTaxon {
    pub id: String,
    pub name: String,
    #[serde(rename = "shortDescription")]
    pub short_description: String,
    #[serde(rename = "helpUri")]
    pub help_uri: String,
}
```

### 21.2 SARIF Result Properties

Each SARIF result (finding) includes CWE/OWASP references in its `properties` bag:

```json
{
  "ruleId": "security/xss-prevention",
  "level": "error",
  "message": { "text": "Potential XSS: user input reaches innerHTML without sanitization" },
  "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "src/app.ts" }, "region": { "startLine": 42 } } }],
  "codeFlows": [{ "threadFlows": [{ "locations": [
    { "location": { "message": { "text": "User input from req.query.name" } } },
    { "location": { "message": { "text": "Flows to innerHTML assignment" } } }
  ] }] }],
  "taxa": [
    { "toolComponent": { "name": "CWE" }, "id": "CWE-79" },
    { "toolComponent": { "name": "OWASP" }, "id": "A05:2025" }
  ],
  "properties": {
    "cwe": ["CWE-79"],
    "owasp": ["A05:2025"],
    "confidence": 0.92,
    "source": "taint",
    "securitySeverity": "8.1"
  }
}
```

---

## 22. SARIF CWE Tool Component

The CWE tool component is included in every SARIF output file. It defines the
CWE taxonomy so SARIF consumers can resolve CWE references.

```rust
/// Attach CWE taxonomy to SARIF run.
pub fn attach_cwe_taxonomy(sarif_run: &mut SarifRun) {
    sarif_run.taxonomies.push(generate_cwe_taxonomy());
}
```

---

## 23. SARIF OWASP Tool Component

```rust
/// Attach OWASP taxonomy to SARIF run.
pub fn attach_owasp_taxonomy(sarif_run: &mut SarifRun) {
    sarif_run.taxonomies.push(generate_owasp_taxonomy());
}
```

---

## 24. Finding Enrichment Pipeline

The finding enrichment pipeline is the core of this subsystem. It takes raw
findings from upstream subsystems and attaches CWE/OWASP metadata.

### 24.1 Pipeline Architecture

```rust
/// The finding enrichment pipeline.
/// Takes raw findings from all upstream subsystems and produces
/// enriched SecurityFinding instances with CWE/OWASP metadata.
pub struct FindingEnrichmentPipeline {
    /// Detector → CWE/OWASP mapping (compile-time registry).
    detector_mapping: &'static [DetectorMapping],
    /// Taint sink → CWE mapping.
    taint_mapping: &'static [TaintSinkMapping],
    /// Secret pattern → CWE mapping.
    secret_mapping: &'static [SecretPatternMapping],
    /// Error gap → CWE mapping.
    error_mapping: &'static [ErrorGapMapping],
    /// Boundary violation → CWE mapping.
    boundary_mapping: &'static [BoundaryViolationMapping],
    /// Security wrapper index (for in_security_wrapper flag).
    wrapper_index: FxHashMap<Spur, Vec<SecurityWrapper>>,
    /// String interner.
    interner: Arc<ThreadedRodeo>,
}

impl FindingEnrichmentPipeline {
    /// Enrich a detector violation with CWE/OWASP metadata.
    pub fn enrich_detector_violation(&self, violation: &Violation) -> SecurityFinding {
        let mapping = self.detector_mapping.iter()
            .find(|m| m.detector_id == violation.detector_id);

        let (cwe_ids, owasp_categories) = match mapping {
            Some(m) => (
                SmallVec::from_slice(m.cwe_ids),
                SmallVec::from_iter(m.owasp.iter().copied()),
            ),
            None => (SmallVec::new(), SmallVec::new()),
        };

        let primary_cwe = cwe_ids.first().copied().unwrap_or(0);
        let severity = self.determine_severity(&cwe_ids, violation.severity);
        let in_wrapper = self.is_in_security_wrapper(violation.file, violation.line);

        SecurityFinding {
            id: hash_finding_id(FindingSource::Detector, violation.file, violation.line, primary_cwe),
            source: FindingSource::Detector,
            source_finding_id: violation.id,
            cwe_ids,
            primary_cwe,
            owasp_categories,
            severity,
            confidence: violation.confidence,
            file: violation.file,
            line: violation.line,
            column: violation.column,
            end_line: violation.end_line,
            end_column: violation.end_column,
            message: violation.message.clone(),
            detector_id: self.interner.get_or_intern(&violation.detector_id),
            fix: violation.fix.clone(),
            code_flow: None,
            in_security_wrapper: in_wrapper,
            content_hash: violation.content_hash,
            detected_at: chrono::Utc::now().timestamp(),
        }
    }

    /// Enrich a taint flow with CWE/OWASP metadata.
    pub fn enrich_taint_flow(&self, flow: &TaintFlow) -> SecurityFinding {
        let mapping = self.taint_mapping.iter()
            .find(|m| m.sink == flow.sink_type);

        let (cwe_id, owasp, severity) = match mapping {
            Some(m) => (m.cwe_id, m.owasp, m.severity),
            None => (0, OwaspCategory::A05Injection, FindingSeverity::Medium),
        };

        SecurityFinding {
            id: hash_finding_id(FindingSource::Taint, flow.sink_file, flow.sink_line, cwe_id),
            source: FindingSource::Taint,
            source_finding_id: flow.id,
            cwe_ids: smallvec![cwe_id],
            primary_cwe: cwe_id,
            owasp_categories: smallvec![owasp],
            severity,
            confidence: flow.confidence,
            file: flow.sink_file,
            line: flow.sink_line,
            column: flow.sink_column,
            end_line: None,
            end_column: None,
            message: format!("Taint flow: {} → {}", flow.source_description, flow.sink_description),
            detector_id: self.interner.get_or_intern(&format!("taint/{}", flow.sink_type.as_str())),
            fix: None,
            code_flow: Some(flow.steps.iter().map(|s| CodeFlowStep {
                file: s.file.to_string(),
                line: s.line,
                column: s.column,
                message: s.message.clone(),
                kind: s.kind,
            }).collect()),
            in_security_wrapper: false,
            content_hash: flow.content_hash,
            detected_at: chrono::Utc::now().timestamp(),
        }
    }

    /// Enrich a secret candidate with CWE/OWASP metadata.
    pub fn enrich_secret(&self, secret: &SecretCandidate) -> SecurityFinding {
        let cwe_id = secret.cwe_id.as_deref()
            .and_then(|s| s.strip_prefix("CWE-"))
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(798); // Default to CWE-798

        let owasp = if cwe_id == 522 {
            OwaspCategory::A07AuthenticationFailures
        } else {
            OwaspCategory::A04CryptographicFailures
        };

        SecurityFinding {
            id: hash_finding_id(FindingSource::Secret, secret.file, secret.line, cwe_id),
            source: FindingSource::Secret,
            source_finding_id: secret.id,
            cwe_ids: smallvec![cwe_id],
            primary_cwe: cwe_id,
            owasp_categories: smallvec![owasp],
            severity: if secret.confidence > 0.8 { FindingSeverity::Critical } else { FindingSeverity::High },
            confidence: secret.confidence,
            file: secret.file,
            line: secret.line,
            column: 0,
            end_line: None,
            end_column: None,
            message: secret.reason.clone(),
            detector_id: self.interner.get_or_intern("secret/detection"),
            fix: Some(Fix {
                description: "Move secret to environment variable or secrets manager".to_string(),
                ..Default::default()
            }),
            code_flow: None,
            in_security_wrapper: false,
            content_hash: secret.content_hash,
            detected_at: chrono::Utc::now().timestamp(),
        }
    }

    /// Check if a location is inside a security wrapper function.
    fn is_in_security_wrapper(&self, file: Spur, line: u32) -> bool {
        self.wrapper_index.get(&file)
            .map(|wrappers| wrappers.iter().any(|w| {
                // Simple heuristic: if the finding is within the wrapper function's
                // line range, it's "inside" the wrapper. This reduces severity
                // because the wrapper is intentionally handling security.
                line >= w.line && line <= w.line + 50 // Approximate function end
            }))
            .unwrap_or(false)
    }
}
```

---

## 25. Cross-Subsystem Finding Aggregation

### 25.1 Aggregation Engine

```rust
/// Aggregate findings from all upstream subsystems into a unified view.
pub struct FindingAggregator {
    pipeline: FindingEnrichmentPipeline,
}

impl FindingAggregator {
    /// Aggregate all security findings from all sources.
    pub fn aggregate(
        &self,
        violations: &[Violation],
        taint_flows: &[TaintFlow],
        secrets: &[SecretCandidate],
        error_gaps: &[ErrorGap],
        boundary_violations: &[BoundaryViolation],
    ) -> Vec<SecurityFinding> {
        let mut findings = Vec::with_capacity(
            violations.len() + taint_flows.len() + secrets.len()
            + error_gaps.len() + boundary_violations.len()
        );

        // Enrich detector violations (only security-relevant ones)
        for v in violations {
            if self.pipeline.has_cwe_mapping(&v.detector_id) {
                findings.push(self.pipeline.enrich_detector_violation(v));
            }
        }

        // Enrich taint flows
        for flow in taint_flows {
            findings.push(self.pipeline.enrich_taint_flow(flow));
        }

        // Enrich secrets
        for secret in secrets {
            findings.push(self.pipeline.enrich_secret(secret));
        }

        // Enrich error gaps
        for gap in error_gaps {
            findings.push(self.pipeline.enrich_error_gap(gap));
        }

        // Enrich boundary violations
        for bv in boundary_violations {
            findings.push(self.pipeline.enrich_boundary_violation(bv));
        }

        // Deduplicate: same file + line + CWE from different sources
        // Keep the highest-confidence finding.
        self.deduplicate(&mut findings);

        // Sort by severity (critical first), then by file, then by line
        findings.sort_by(|a, b| {
            b.severity.cmp(&a.severity)
                .then_with(|| a.file.cmp(&b.file))
                .then_with(|| a.line.cmp(&b.line))
        });

        findings
    }

    /// Deduplicate findings: same file + line + primary CWE.
    /// Keeps the finding with highest confidence.
    fn deduplicate(&self, findings: &mut Vec<SecurityFinding>) {
        let mut seen: FxHashMap<(Spur, u32, u32), usize> = FxHashMap::default();
        let mut to_remove = Vec::new();

        for (i, finding) in findings.iter().enumerate() {
            let key = (finding.file, finding.line, finding.primary_cwe);
            if let Some(&existing_idx) = seen.get(&key) {
                if findings[existing_idx].confidence < finding.confidence {
                    to_remove.push(existing_idx);
                    seen.insert(key, i);
                } else {
                    to_remove.push(i);
                }
            } else {
                seen.insert(key, i);
            }
        }

        to_remove.sort_unstable();
        for idx in to_remove.into_iter().rev() {
            findings.swap_remove(idx);
        }
    }
}
```

---

## 26. Incremental Mapping (Content-Hash Aware)

The mapping engine supports incremental operation. When files change, only the
findings for changed files are re-enriched.

```rust
/// Incremental mapping: only re-enrich findings for changed files.
pub fn incremental_enrich(
    aggregator: &FindingAggregator,
    changed_files: &FxHashSet<Spur>,
    previous_findings: &[SecurityFinding],
    new_violations: &[Violation],
    new_taint_flows: &[TaintFlow],
    new_secrets: &[SecretCandidate],
    new_error_gaps: &[ErrorGap],
    new_boundary_violations: &[BoundaryViolation],
) -> Vec<SecurityFinding> {
    // Keep findings for unchanged files
    let mut findings: Vec<SecurityFinding> = previous_findings.iter()
        .filter(|f| !changed_files.contains(&f.file))
        .cloned()
        .collect();

    // Re-enrich findings for changed files
    let changed_violations: Vec<&Violation> = new_violations.iter()
        .filter(|v| changed_files.contains(&v.file))
        .collect();
    let changed_taint: Vec<&TaintFlow> = new_taint_flows.iter()
        .filter(|f| changed_files.contains(&f.sink_file))
        .collect();
    let changed_secrets: Vec<&SecretCandidate> = new_secrets.iter()
        .filter(|s| changed_files.contains(&s.file))
        .collect();

    // Aggregate only changed findings
    let new_findings = aggregator.aggregate(
        &changed_violations.iter().map(|v| (*v).clone()).collect::<Vec<_>>(),
        &changed_taint.iter().map(|f| (*f).clone()).collect::<Vec<_>>(),
        &changed_secrets.iter().map(|s| (*s).clone()).collect::<Vec<_>>(),
        new_error_gaps,
        new_boundary_violations,
    );

    findings.extend(new_findings);
    findings
}
```


---

## 27. Integration with Detector System

The detector system (§06) is the primary producer of security findings. Integration:

1. **Violation struct carries CWE/OWASP fields**: The `Violation` struct in the
   detector system already has `cwe_ids: SmallVec<[u32; 2]>` and `owasp: Option<Spur>`
   fields (per 06-UNIFIED-ANALYSIS-ENGINE-V2-PREP.md). These are populated from the
   TOML pattern definitions or from the compile-time mapping in this subsystem.

2. **TOML pattern definitions include CWE/OWASP**: Custom TOML patterns can specify
   `cwe_ids = [89]` and `owasp = "A05:2025"` (per 06-UNIFIED-ANALYSIS-ENGINE-V2-PREP.md
   §TOML format). The mapping engine validates these against the registry.

3. **Compile-time fallback**: If a TOML pattern doesn't specify CWE/OWASP, the
   mapping engine uses the compile-time `DETECTOR_MAPPING` table to attach metadata
   based on the detector ID.

---

## 28. Integration with Taint Analysis

The taint analysis subsystem (§15) produces `TaintFlow` findings. Integration:

1. **SinkType → CWE mapping**: Each `SinkType` maps to a CWE via `TAINT_SINK_MAPPING`.
2. **Sanitizer recognition**: Security wrappers detected by this subsystem that are
   classified as sanitizers are registered in the taint analysis sanitizer registry.
3. **Code flow preservation**: Taint findings include source → propagation → sink
   code flows, which are preserved in the enriched `SecurityFinding`.

---

## 29. Integration with Constants & Environment (Secrets)

The constants/environment subsystem (§22) produces `SecretCandidate` findings.
Integration:

1. **SecretPattern → CWE/OWASP**: Each secret pattern already carries `cwe_id` and
   `owasp_id` fields (per §22 §7.1). The enrichment pipeline reads these directly.
2. **Provider-specific patterns**: Cloud provider patterns (AWS, GCP, Azure, etc.)
   all map to CWE-798 (hardcoded credentials) and A04:2025 (Cryptographic Failures).

---

## 30. Integration with Error Handling Analysis

The error handling analysis subsystem (§16) produces `ErrorGap` findings. Integration:

1. **ErrorGapType → CWE/OWASP**: Each gap type maps via `ERROR_GAP_MAPPING`.
2. **A10:2025 alignment**: Error handling gaps are the primary source of findings
   for the new OWASP A10:2025 (Mishandling of Exceptional Conditions) category.
3. **Fail-open detection**: The most critical error gap — `FailOpen` — maps to
   CWE-280 and is classified as Critical severity.

---

## 31. Integration with Boundary Detection

The boundary detection subsystem (§07) produces `BoundaryViolation` findings.
Integration:

1. **BoundaryViolationType → CWE/OWASP**: Each violation type maps via
   `BOUNDARY_VIOLATION_MAPPING`.
2. **Sensitive data exposure**: Boundary violations involving sensitive fields
   (PII, credentials, financial, health) are mapped to CWE-200 and A01:2025.
3. **Unsafe ORM API**: Raw SQL bypass patterns map to CWE-89 and A05:2025.

---

## 32. Integration with Quality Gates (Security Gate)

The quality gates subsystem (Level 3) consumes security findings for the security
gate evaluation. Integration:

1. **Security gate threshold**: The security gate can be configured with thresholds
   per OWASP category (e.g., "zero critical findings in A01, A05, A07").
2. **OWASP coverage requirement**: The gate can require minimum OWASP coverage
   (e.g., "at least 8/10 categories covered").
3. **Security posture score**: The gate can require minimum security posture score
   (e.g., "score ≥ 70 to pass").

```rust
/// Security gate configuration.
pub struct SecurityGateConfig {
    /// Maximum allowed critical findings (0 = zero tolerance).
    pub max_critical: u32,
    /// Maximum allowed high findings.
    pub max_high: u32,
    /// Minimum OWASP coverage (0.0-1.0).
    pub min_owasp_coverage: f32,
    /// Minimum security posture score (0-100).
    pub min_posture_score: u8,
    /// Per-OWASP-category thresholds (optional).
    pub category_thresholds: FxHashMap<OwaspCategory, CategoryThreshold>,
    /// Whether to block on findings in security wrappers.
    pub block_on_wrapper_findings: bool,
}

pub struct CategoryThreshold {
    pub max_critical: u32,
    pub max_high: u32,
    pub required: bool, // If true, this category must have detectors
}
```

---

## 33. Integration with DNA System (Security Gene)

The DNA system (§22) includes a `security_patterns` gene extractor. Integration:

1. **Security wrapper data → gene**: The wrapper clusters feed the security gene
   extractor. Dominant allele = most common security wrapper pattern.
2. **OWASP coverage → gene metadata**: The OWASP coverage score is included in
   the DNA profile as a security health signal.
3. **Security posture → health factor**: The security posture score contributes
   to the overall DNA health score.

---

## 34. Integration with Constraint System

The constraint system (§20) includes a `security` constraint category. Integration:

1. **auth-before-access constraints**: Security wrappers classified as
   `Authentication` or `Authorization` are used to verify `must_precede`
   constraints (e.g., "auth middleware must precede data access").
2. **Business context**: Constraints can reference OWASP categories in their
   `business_context` field (e.g., "OWASP A01 compliance requirement").

---

## 35. Integration with Cortex Grounding (D7)

Per PLANNING-DRIFT.md D7, Drift computes security signals independently. The
optional Cortex bridge can compare Drift's security posture against Cortex
memories for grounding.

1. **Security posture signal**: The security posture score (0-100) is a grounding
   signal the bridge can compare against Cortex security-related memories.
2. **OWASP coverage signal**: The OWASP coverage (0.0-1.0) is another grounding
   signal.
3. **SecurityAudit intent**: Cortex's `Intent::SecurityAudit` (with 2.0x boost
   for ConstraintOverride and Tribal memories) aligns with this subsystem's output.

---

## 36. Storage Schema (drift.db Security Mapping Tables)

### 36.1 Tables

```sql
-- Unified security findings (enriched with CWE/OWASP)
CREATE TABLE IF NOT EXISTS security_findings (
    id INTEGER PRIMARY KEY,
    source TEXT NOT NULL,           -- 'detector', 'taint', 'secret', 'error', 'boundary', 'wrapper'
    source_finding_id INTEGER NOT NULL,
    primary_cwe INTEGER NOT NULL,
    cwe_ids TEXT NOT NULL,          -- JSON array: [79, 116]
    owasp_categories TEXT NOT NULL, -- JSON array: ["A05:2025"]
    severity TEXT NOT NULL,         -- 'critical', 'high', 'medium', 'low', 'info'
    confidence REAL NOT NULL,
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    col INTEGER NOT NULL DEFAULT 0,
    end_line INTEGER,
    end_col INTEGER,
    message TEXT NOT NULL,
    detector_id TEXT NOT NULL,
    has_fix INTEGER NOT NULL DEFAULT 0,
    has_code_flow INTEGER NOT NULL DEFAULT 0,
    in_security_wrapper INTEGER NOT NULL DEFAULT 0,
    content_hash INTEGER NOT NULL,
    detected_at INTEGER NOT NULL,
    UNIQUE(source, file, line, primary_cwe)
);

CREATE INDEX idx_security_findings_file ON security_findings(file);
CREATE INDEX idx_security_findings_cwe ON security_findings(primary_cwe);
CREATE INDEX idx_security_findings_severity ON security_findings(severity);
CREATE INDEX idx_security_findings_owasp ON security_findings(owasp_categories);

-- Security wrappers
CREATE TABLE IF NOT EXISTS security_wrappers (
    id INTEGER PRIMARY KEY,
    function_name TEXT NOT NULL,
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    category TEXT NOT NULL,         -- 'authentication', 'authorization', etc.
    wrapped_primitives TEXT NOT NULL, -- JSON array
    framework TEXT,
    confidence REAL NOT NULL,
    usage_count INTEGER NOT NULL DEFAULT 0,
    is_exported INTEGER NOT NULL DEFAULT 0,
    is_sanitizer INTEGER NOT NULL DEFAULT 0,
    sanitizes_labels TEXT,          -- JSON array (if is_sanitizer)
    content_hash INTEGER NOT NULL,
    UNIQUE(file, function_name)
);

CREATE INDEX idx_security_wrappers_category ON security_wrappers(category);
CREATE INDEX idx_security_wrappers_file ON security_wrappers(file);

-- OWASP coverage snapshots (for temporal tracking)
CREATE TABLE IF NOT EXISTS owasp_coverage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    category TEXT NOT NULL,         -- 'A01:2025', 'A02:2025', etc.
    detector_count INTEGER NOT NULL,
    detectable_cwes INTEGER NOT NULL,
    finding_count INTEGER NOT NULL,
    critical_count INTEGER NOT NULL,
    high_count INTEGER NOT NULL,
    depth TEXT NOT NULL,            -- 'none', 'shallow', 'deep', 'full'
    has_wrappers INTEGER NOT NULL DEFAULT 0,
    wrapper_count INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);

CREATE INDEX idx_owasp_coverage_scan ON owasp_coverage(scan_id);

-- Security posture history (for trend tracking)
CREATE TABLE IF NOT EXISTS security_posture (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    score INTEGER NOT NULL,
    grade TEXT NOT NULL,
    critical_findings INTEGER NOT NULL,
    high_findings INTEGER NOT NULL,
    medium_findings INTEGER NOT NULL,
    low_findings INTEGER NOT NULL,
    owasp_coverage REAL NOT NULL,
    wrapper_consistency REAL NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE INDEX idx_security_posture_scan ON security_posture(scan_id);

-- Wrapper bypass patterns
CREATE TABLE IF NOT EXISTS wrapper_bypasses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    wrapper_id INTEGER NOT NULL REFERENCES security_wrappers(id),
    primitive TEXT NOT NULL,
    bypassing_function TEXT NOT NULL,
    bypassing_file TEXT NOT NULL,
    severity TEXT NOT NULL,
    content_hash INTEGER NOT NULL,
    UNIQUE(wrapper_id, bypassing_function, bypassing_file)
);
```

---

## 37. NAPI Interface

### 37.1 Exported Functions

```rust
/// Query security findings with filters.
#[napi]
pub async fn query_security_findings(
    filters: SecurityFindingFilters,
) -> napi::Result<SecurityFindingsResult> { ... }

/// Get OWASP coverage report.
#[napi]
pub async fn get_owasp_coverage() -> napi::Result<OwaspCoverageReport> { ... }

/// Get CWE coverage report.
#[napi]
pub async fn get_cwe_coverage() -> napi::Result<CweCoverageReport> { ... }

/// Get security posture score.
#[napi]
pub async fn get_security_posture() -> napi::Result<SecurityPostureScore> { ... }

/// Get compliance report.
#[napi]
pub async fn get_compliance_report() -> napi::Result<ComplianceReport> { ... }

/// Query security wrappers.
#[napi]
pub async fn query_security_wrappers(
    filters: SecurityWrapperFilters,
) -> napi::Result<SecurityWrappersResult> { ... }

/// Get wrapper bypass patterns.
#[napi]
pub async fn get_wrapper_bypasses() -> napi::Result<Vec<BypassPattern>> { ... }

/// Get SARIF taxonomies (CWE + OWASP).
#[napi]
pub fn get_sarif_taxonomies() -> napi::Result<Vec<SarifToolComponent>> { ... }
```

### 37.2 Filter Types

```rust
#[napi(object)]
pub struct SecurityFindingFilters {
    pub file: Option<String>,
    pub severity: Option<String>,
    pub cwe_id: Option<u32>,
    pub owasp_category: Option<String>,
    pub source: Option<String>,
    pub cursor: Option<String>,
    pub limit: Option<u32>,
}

#[napi(object)]
pub struct SecurityWrapperFilters {
    pub file: Option<String>,
    pub category: Option<String>,
    pub framework: Option<String>,
    pub is_sanitizer: Option<bool>,
    pub cursor: Option<String>,
    pub limit: Option<u32>,
}
```


---

## 38. MCP Tool Interface (drift_security — 8 Actions)

### 38.1 Tool: drift_security

| Action | Description | Token Cost |
|--------|-------------|------------|
| `overview` | Security posture score, grade, top risks, OWASP coverage summary | ~800 |
| `owasp` | Full OWASP Top 10:2025 coverage report with per-category details | ~1500 |
| `cwe` | CWE Top 25 coverage report with detectability matrix | ~2000 |
| `findings` | Security findings with filters (file, severity, CWE, OWASP) | ~1000-3000 |
| `compliance` | Full compliance report (OWASP + CWE + gaps + risks) | ~2500 |
| `wrappers` | Security wrapper inventory with clusters and bypass patterns | ~1000-2000 |
| `sarif` | Generate SARIF output with CWE/OWASP taxonomies | ~3000-5000 |
| `trend` | Security posture trend over last N scans | ~800 |

### 38.2 Progressive Disclosure

```
drift_security overview     → "Score: 78/100 (C). 3 critical, 12 high. A01: 5 findings, A05: 8 findings."
drift_security owasp        → Full OWASP breakdown with per-category depth and wrapper status
drift_security findings     → Detailed findings with CWE IDs, code flows, fix suggestions
drift_security compliance   → Enterprise compliance report with gap analysis
```

### 38.3 Example MCP Response (overview)

```json
{
  "security_posture": {
    "score": 78,
    "grade": "C",
    "critical_findings": 3,
    "high_findings": 12,
    "medium_findings": 28,
    "low_findings": 45
  },
  "owasp_coverage": {
    "covered": 9,
    "total": 10,
    "uncovered": ["A03:2025 (Supply Chain)"],
    "top_categories": [
      { "id": "A05:2025", "name": "Injection", "findings": 8, "depth": "deep" },
      { "id": "A01:2025", "name": "Broken Access Control", "findings": 5, "depth": "deep" },
      { "id": "A10:2025", "name": "Exceptional Conditions", "findings": 15, "depth": "deep" }
    ]
  },
  "top_risks": [
    { "cwe": "CWE-79", "name": "XSS", "count": 5, "severity": "high" },
    { "cwe": "CWE-89", "name": "SQL Injection", "count": 3, "severity": "critical" },
    { "cwe": "CWE-798", "name": "Hardcoded Credentials", "count": 3, "severity": "critical" }
  ],
  "wrapper_summary": {
    "total_wrappers": 12,
    "categories": ["authentication", "input_sanitization", "cryptography"],
    "consistency": 0.73,
    "bypasses": 4
  }
}
```

---

## 39. CLI Interface (drift security — 8 Subcommands)

```
drift security                    # Default: overview (posture score + top risks)
drift security overview           # Security posture score, grade, OWASP summary
drift security owasp              # OWASP Top 10:2025 coverage report
drift security cwe                # CWE Top 25 coverage report
drift security findings [--file] [--severity] [--cwe] [--owasp]  # Filtered findings
drift security compliance         # Full compliance report
drift security wrappers           # Security wrapper inventory
drift security trend [--scans N]  # Security posture trend
drift security sarif [--output]   # Generate SARIF file
```

### 39.1 Example CLI Output (overview)

```
Security Posture: 78/100 (C)

  Critical: 3    High: 12    Medium: 28    Low: 45

OWASP Top 10:2025 Coverage: 9/10
  ✅ A01 Broken Access Control      5 findings (deep)
  ✅ A02 Security Misconfiguration  2 findings (shallow)
  ❌ A03 Supply Chain Failures      0 findings (no detectors)
  ✅ A04 Cryptographic Failures     3 findings (deep)
  ✅ A05 Injection                  8 findings (deep)
  ✅ A06 Insecure Design            1 finding  (shallow)
  ✅ A07 Authentication Failures    4 findings (deep)
  ✅ A08 Integrity Failures         1 finding  (shallow)
  ✅ A09 Logging & Alerting         6 findings (deep)
  ✅ A10 Exceptional Conditions    15 findings (deep)

Top Risks:
  1. CWE-79  XSS                    5 findings (high)
  2. CWE-89  SQL Injection          3 findings (critical)
  3. CWE-798 Hardcoded Credentials  3 findings (critical)

Security Wrappers: 12 detected, 73% consistency, 4 bypasses
```

---

## 40. Event Interface

```rust
/// Events emitted by the OWASP/CWE mapping subsystem.
/// Per D5: all state-changing events emit via DriftEventHandler.
pub trait SecurityMappingEvents {
    /// Emitted when security findings are enriched after a scan.
    fn on_security_findings_enriched(&self, count: u32, critical: u32, high: u32);

    /// Emitted when security posture score changes significantly (±5 points).
    fn on_security_posture_changed(&self, old_score: u8, new_score: u8, grade: SecurityGrade);

    /// Emitted when a new security wrapper is detected.
    fn on_security_wrapper_detected(&self, wrapper: &SecurityWrapper);

    /// Emitted when a wrapper bypass pattern is detected.
    fn on_wrapper_bypass_detected(&self, bypass: &BypassPattern);

    /// Emitted when OWASP coverage changes (category gained/lost).
    fn on_owasp_coverage_changed(&self, old_covered: u8, new_covered: u8);
}
```

---

## 41. Tracing & Observability

```rust
// All operations use tracing spans for observability.
// Key spans:
#[tracing::instrument(skip(findings, wrappers))]
pub fn calculate_owasp_coverage(...) { ... }

#[tracing::instrument(skip(violations, taint_flows, secrets))]
pub fn aggregate_findings(...) { ... }

#[tracing::instrument(skip(parse_result))]
pub fn detect_security_wrappers(...) { ... }

// Key metrics (emitted via tracing):
// - security.findings.total (gauge)
// - security.findings.critical (gauge)
// - security.posture.score (gauge)
// - security.owasp.coverage (gauge, 0.0-1.0)
// - security.wrappers.count (gauge)
// - security.wrappers.bypasses (gauge)
// - security.enrichment.duration_ms (histogram)
// - security.wrapper_detection.duration_ms (histogram)
```

---

## 42. Performance Targets & Benchmarks

| Operation | Target | Notes |
|-----------|--------|-------|
| Finding enrichment (per finding) | < 1μs | Compile-time registry lookup |
| Wrapper detection (per file) | < 500μs | Single-pass AST traversal |
| OWASP coverage calculation | < 10ms | Aggregate over all findings |
| CWE coverage calculation | < 5ms | Aggregate over all findings |
| Security posture calculation | < 5ms | Composite score from aggregates |
| Compliance report generation | < 20ms | Combines OWASP + CWE + posture |
| SARIF taxonomy generation | < 1ms | Static registry serialization |
| Full aggregation (10K findings) | < 100ms | Enrich + deduplicate + sort |
| Incremental enrichment (100 changed files) | < 10ms | Only re-enrich changed |
| Wrapper bypass detection (1K wrappers) | < 50ms | Call graph traversal |

### Memory Budget

| Data Structure | Estimated Size | Notes |
|---------------|---------------|-------|
| OWASP registry (10 entries) | ~2 KB | Static, compile-time |
| CWE Top 25 registry | ~5 KB | Static, compile-time |
| Extended CWE registry (~95 entries) | ~15 KB | Static, compile-time |
| Detector mapping (~47 entries) | ~3 KB | Static, compile-time |
| SecurityFinding (per instance) | ~256 bytes | Heap-allocated strings |
| SecurityWrapper (per instance) | ~128 bytes | Spur-interned strings |
| 10K findings in memory | ~2.5 MB | Typical large codebase |
| 1K wrappers in memory | ~128 KB | Typical large codebase |

---

## 43. Build Order & Dependencies

### 43.1 Build Order

```
Phase 1 (can build immediately — no upstream dependencies):
  1. OWASP 2025 registry (const arrays)
  2. CWE Top 25 + Extended registry (const arrays)
  3. Detector → CWE/OWASP mapping matrix (const arrays)
  4. Taint sink → CWE mapping (const arrays)
  5. Error gap → CWE mapping (const arrays)
  6. Boundary violation → CWE mapping (const arrays)
  7. Security wrapper primitive registry (const arrays)
  8. Core types (SecurityFinding, SecurityWrapper, etc.)

Phase 2 (requires Phase 1):
  9. Finding enrichment pipeline
  10. Security wrapper detection engine
  11. Wrapper confidence scoring
  12. Wrapper clustering

Phase 3 (requires Phase 2):
  13. OWASP coverage calculator
  14. CWE coverage calculator
  15. Security posture score
  16. Cross-subsystem finding aggregation
  17. Incremental mapping

Phase 4 (requires Phase 3):
  18. Compliance report generator
  19. SARIF taxonomy integration
  20. Wrapper bypass detection

Phase 5 (requires Phase 4):
  21. Storage schema (drift.db tables)
  22. NAPI interface
  23. MCP tool interface
  24. CLI interface
  25. Event interface
```

### 43.2 Crate Dependencies

```toml
[dependencies]
# From drift-core (internal)
drift-core = { path = "../drift-core" }  # ParseResult, FunctionInfo, CallSite

# External
serde = { version = "1", features = ["derive"] }
serde_json = "1"
smallvec = { version = "1", features = ["serde"] }
rustc-hash = "2"          # FxHashMap
lasso = "0.7"             # ThreadedRodeo string interning
chrono = "0.4"
tracing = "0.1"
```

---

## 44. V1 → V2 Feature Cross-Reference

| # | v1 Feature | v2 Feature | Section | Status |
|---|-----------|-----------|---------|--------|
| 1 | Sensitive field detection (4 categories) | Consumed by boundary violation mapping | §12 | KEPT |
| 2 | Boundary scanning (learn-then-detect) | Consumed by finding aggregation | §25 | KEPT |
| 3 | Security prioritization (4 tiers) | Replaced by security posture score | §19 | UPGRADED |
| 4 | ORM framework detection (28 frameworks) | Consumed by boundary detection | §31 | KEPT |
| 5 | Wrapper detection (basic, 6 categories) | Security wrapper detection engine | §13 | UPGRADED |
| 6 | Wrapper clustering (TS cross-file) | Rust wrapper clustering | §15 | REPLACED |
| 7 | Wrapper primitive registry | Security primitive registry | §14 | UPGRADED |
| 8 | Wrapper documentation export | Wrapper docs export (markdown) | §15.2 | KEPT |
| 9 | SecurityAudit intent | Consumed by Cortex grounding | §35 | KEPT |
| 10 | Security weight boosting | Consumed by Cortex grounding | §35 | KEPT |
| 11 | Sensitive variable context | Consumed by secret enrichment | §29 | KEPT |
| 12 | Security synonym expansion | Consumed by retrieval | §35 | KEPT |
| 13 | — (gap) | OWASP Top 10:2025 registry | §5 | NEW |
| 14 | — (gap) | CWE Top 25 2025 registry | §6 | NEW |
| 15 | — (gap) | Extended CWE registry (~95 CWEs) | §7 | NEW |
| 16 | — (gap) | Detector → CWE/OWASP mapping matrix | §8 | NEW |
| 17 | — (gap) | Taint sink → CWE mapping | §9 | NEW |
| 18 | — (gap) | Secret → CWE/OWASP mapping | §10 | NEW |
| 19 | — (gap) | Error gap → CWE/OWASP mapping | §11 | NEW |
| 20 | — (gap) | Boundary violation → CWE/OWASP mapping | §12 | NEW |
| 21 | — (gap) | OWASP coverage calculator | §17 | NEW |
| 22 | — (gap) | CWE coverage calculator | §18 | NEW |
| 23 | — (gap) | Security posture score (0-100) | §19 | NEW |
| 24 | — (gap) | Compliance report generator | §20 | NEW |
| 25 | — (gap) | SARIF CWE/OWASP taxonomy | §21-§23 | NEW |
| 26 | — (gap) | Finding enrichment pipeline | §24 | NEW |
| 27 | — (gap) | Cross-subsystem aggregation | §25 | NEW |
| 28 | — (gap) | Incremental mapping | §26 | NEW |
| 29 | — (gap) | Wrapper bypass detection | §13.3 | NEW |
| 30 | — (gap) | Wrapper → sanitizer bridge | §28 | NEW |
| 31 | — (gap) | Security gate integration | §32 | NEW |
| 32 | — (gap) | DNA security gene integration | §33 | NEW |

**v1 features preserved: 12/12 (100%)**
**v2 new features: 20**
**Total v2 features: 32**

---

## 45. Inconsistencies & Decisions

### 45.1 Resolved Inconsistencies

| # | Inconsistency | Resolution |
|---|--------------|------------|
| 1 | 06-DETECTOR-SYSTEM.md references "OWASP A01/A07" but uses 2021 numbering in some places | **Decision**: Use 2025 numbering exclusively. A01:2025 = Broken Access Control, A07:2025 = Authentication Failures. The 2021→2025 migration map (§5.2) handles backward compatibility. |
| 2 | 22-CONSTANTS-ENVIRONMENT references "A02:2025" for secrets but some secrets map to A07:2025 | **Decision**: CWE-798 (hardcoded credentials) maps to BOTH A04:2025 (Cryptographic Failures) and A07:2025 (Authentication Failures). CWE-522 (insufficiently protected credentials) maps to A07:2025 only. The mapping matrix (§8) is authoritative. |
| 3 | 15-TAINT-ANALYSIS references "OWASP A03 Injection" and "A10 SSRF" using 2021 numbering | **Decision**: In 2025, Injection is A05:2025 and SSRF is absorbed into A01:2025. The taint sink mapping (§9) uses 2025 numbering. |
| 4 | Wrapper detection exists in both Rust (basic) and TS (full) in v1 | **Decision**: v2 unifies in Rust. Security wrapper detection (this subsystem) handles security-specific wrappers. General wrapper detection (React hooks, fetch APIs) remains in the Unified Analysis Engine. |
| 5 | DRIFT-V2-STACK-HIERARCHY says "9/10 target" for OWASP coverage | **Decision**: v2 achieves 10/10 OWASP category coverage (all 10 categories have at least one detector). A03 (Supply Chain) has shallow coverage (dependency-audit only). The "9/10" was a conservative estimate. |
| 6 | Multiple subsystems carry CWE/OWASP fields on their types | **Decision**: This is intentional for efficiency. The mapping registry (this subsystem) is the source of truth. Other subsystems populate their CWE/OWASP fields from this registry at detection time. No subsystem maintains its own independent mapping. |

### 45.2 Open Questions

| # | Question | Proposed Answer | Impact |
|---|---------|----------------|--------|
| 1 | Should OWASP 2021 mappings be maintained alongside 2025? | Yes, as a compatibility layer. Some enterprise compliance tools still reference 2021. Add `owasp_2021: Option<&'static str>` to CweEntry. | Low — additive field |
| 2 | Should custom CWE mappings be user-configurable via TOML? | Yes. Users can add `[security.cwe_mappings]` in drift.toml to map custom detectors to CWEs. | Medium — TOML parsing |
| 3 | Should the security posture score formula be configurable? | Yes. Weights (W_CRITICAL, W_HIGH, etc.) should be configurable in drift.toml. | Low — config field |

---

## 46. Risk Register

| # | Risk | Likelihood | Impact | Mitigation |
|---|------|-----------|--------|------------|
| 1 | OWASP 2025 changes before final release (currently RC1) | Medium | Low | Registry is a const array — easy to update. Monitor OWASP for final release. |
| 2 | CWE Top 25 2026 changes rankings | Certain | Low | Registry versioned. Add 2026 when published. Keep 2025 as fallback. |
| 3 | False positive rate in wrapper detection | Medium | Medium | Conservative confidence thresholds (≥0.6 to report). Bypass detection helps identify inconsistencies. |
| 4 | Memory safety CWEs (7/25) not detectable | Certain | Low | Clearly documented as "requires runtime analysis." Not a Drift limitation — industry-wide SAST limitation. |
| 5 | SARIF taxonomy format changes | Low | Medium | SARIF v2.1.0 is stable. Monitor for v2.2.0. |
| 6 | Enterprise customers need OWASP ASVS mapping (not just Top 10) | Medium | Medium | ASVS mapping is a future extension. The registry architecture supports adding ASVS as another taxonomy. |
| 7 | Wrapper detection misclassifies non-security wrappers | Medium | Low | Security primitive registry is curated (not auto-discovered). False positives are limited to functions that call security primitives but aren't wrappers. |
| 8 | Cross-subsystem aggregation performance with 100K+ findings | Low | Medium | Incremental mapping (§26) limits re-enrichment to changed files. Deduplication uses FxHashMap for O(1) lookup. |
