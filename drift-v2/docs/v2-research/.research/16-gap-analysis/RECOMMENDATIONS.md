# 16 Gap Analysis — V2 Recommendations

> **Purpose**: Concrete, actionable recommendations for closing the 150+ gaps identified in the RECAP, informed by the 30 authoritative sources in the RESEARCH encyclopedia. Organized as a gap closure plan that complements (not duplicates) the 42 unified recommendations in MASTER_RECOMMENDATIONS.md. This document focuses on gaps NOT already covered by M1-M42, plus cross-cutting gap closure strategies.
>
> **Inputs**: 16-gap-analysis RECAP.md, 16-gap-analysis RESEARCH.md, MASTER_RECOMMENDATIONS.md (M1-M42)
>
> **Date**: February 2026

---

## Executive Summary

The MASTER_RECOMMENDATIONS document contains 42 unified recommendations (M1-M42) covering the core engine, detection, analysis, scoring, security, bridge, and DX. Those recommendations close approximately 80 of the 150+ identified gaps. This document addresses the remaining ~70 gaps that fall outside the M1-M42 scope — primarily in the areas of: undocumented systems (licensing, workspace, telemetry, skills), operational infrastructure (supply chain security, CI maturity, release orchestration), data integrity, documentation corrections, and cross-cutting gap closure strategies.

Each recommendation is tagged with the specific gaps it closes (GAP-XX from RECAP) and any M-XX recommendations it depends on or extends.

---

## Gap Closure Category A: Undocumented Business-Critical Systems

These systems exist in v1 but were not covered by the 5 core research categories (01-05). They must be rebuilt in v2 with full documentation.

### GA1: Licensing & Feature Gating System (Rust + TS)

**Priority**: P0 | **Effort**: Medium | **Closes**: GAP-01, GAP-15
**Depends on**: M4 (Layered Architecture)

**Current State**: Fully functional in v1 TS — LicenseManager, LicenseValidator, FeatureGuard with 3 tiers, 16 gated features, JWT + simple key validation, 6 guard patterns.

**Proposed Architecture for V2**:
1. **License validation in Rust**: JWT parsing (via `jsonwebtoken` crate), HMAC verification, expiration checks, tier extraction. This is the hot path — checked on every gated operation.
2. **Feature registry in Rust**: Static registry of all gated features with tier requirements. Compile-time feature enumeration via enum.
3. **Guard patterns preserved**: All 6 v1 patterns (`requireFeature`, `checkFeature`, `guardFeature`, `withFeatureGate`, `@RequiresFeature`, `guardMCPTool`) reimplemented. Rust-side guards for Rust operations, TS-side guards for orchestration.
4. **License sources preserved**: env var → file → config → community fallback.
5. **New capabilities**:
   - Telemetry on gated feature attempts (anonymized, opt-in)
   - Graceful degradation with upgrade prompts in MCP responses
   - License caching with configurable TTL (default 1 hour)
   - Offline validation with periodic online refresh for enterprise

**Tier Structure (preserved from v1)**:
- Community (free): All scanning, detection, analysis, CI, MCP, VSCode
- Team: Policy engine, regression detection, custom rules, trends, exports
- Enterprise: Multi-repo governance, impact simulation, security boundaries, audit trails, integrations, self-hosted models, custom detectors, REST API

**Evidence**: Open-core licensing patterns from GitLab, Elastic, HashiCorp (RESEARCH §6.1).

**Risks**: License validation must never block core functionality. Community tier must always work without network access.

### GA2: Workspace Management System (Rust + TS)

**Priority**: P0 | **Effort**: High | **Closes**: GAP-02
**Depends on**: M1 (Incremental-First), M5 (Scanner), M3 (SQLite WAL)

**Current State**: V1 has WorkspaceManager, ProjectSwitcher, ContextLoader, BackupManager, SchemaMigrator, SourceOfTruth — all in TypeScript.

**Proposed Architecture for V2**:
1. **Project discovery (Rust)**: Auto-detect project roots by scanning for marker files (package.json, Cargo.toml, pyproject.toml, go.mod, pom.xml, .csproj, composer.json). Build project dependency graph for monorepos.
2. **Workspace state (Rust)**: Persistent workspace state in `drift.db` — project metadata, configuration, feature flags, scan history. Replaces v1's scattered JSON files.
3. **Context loading (Rust)**: Load all context for a project (patterns, contracts, boundaries, etc.) from SQLite. Lazy loading — only load what's needed for the current operation.
4. **Project switching (TS orchestration)**: Invalidate caches, reload stores, update UI state. Thin TS wrapper over Rust state management.
5. **Backup & migration (Rust)**: SQLite backup API for consistent snapshots. Schema versioning with forward-only migrations. Backup retention policy (configurable, default 10 backups).
6. **Multi-project support**: Multiple project roots in a single workspace (monorepo). Per-project configuration with workspace-level defaults.

**New capabilities**:
- File watcher integration for incremental analysis (LSP `workspace/didChangeWatchedFiles`)
- Project health dashboard (scan frequency, pattern count, drift score over time)
- Workspace export/import for team sharing

**Evidence**: rust-analyzer project model, LSP workspace protocol (RESEARCH §7.1, §7.2).

### GA3: Audit System Rebuild (Rust)

**Priority**: P0 | **Effort**: Medium | **Closes**: GAP-03
**Depends on**: M33 (Temporal Decay), M34 (Bayesian Learning), M40 (Feedback Loop)

**Current State**: V1 AuditEngine does pattern validation, duplicate detection (Jaccard), cross-validation, health scoring, degradation tracking. All in TypeScript.

**Proposed Architecture for V2**:
1. **Health scoring in Rust**: Preserve v1 weights (avgConfidence×0.30 + approvalRatio×0.20 + complianceRate×0.20 + crossValidationRate×0.15 + duplicateFreeRate×0.15). Add temporal component from M33.
2. **Duplicate detection in Rust**: Jaccard similarity on location sets. Threshold 0.85. Auto-merge at >0.95 (new — v1 only flags).
3. **Cross-validation in Rust**: Orphan patterns, high outlier ratio, low confidence approved, constraint alignment.
4. **Degradation tracking**: 90-day history with 7-day rolling averages. Alert thresholds preserved from v1.
5. **New capabilities**:
   - Trend prediction (linear regression on health score history)
   - Anomaly detection on health score changes (sudden drops)
   - Per-category health breakdown
   - Integration with feedback loop (M40) — FP rate feeds into health score

**Evidence**: Google Tricorder feedback model (RESEARCH §10.1).

### GA4: Telemetry System (Rust Client + Cloudflare Worker)

**Priority**: P1 | **Effort**: Low-Medium | **Closes**: GAP-06 (from 12-infrastructure)
**Depends on**: GA1 (Licensing — telemetry on gated features)

**Current State**: V1 has a TS telemetry client + Cloudflare Worker backend with D1 storage. Opt-in, anonymous, privacy-preserving.

**Proposed for V2**:
1. **Rust telemetry client**: Event batching, privacy controls, opt-in model preserved. Rust-side events: parse times, NAPI call counts, memory usage, detection performance.
2. **Cloudflare Worker preserved**: No changes needed — independent infrastructure.
3. **New events**: Gated feature attempts, detector FP rates (anonymized), scan performance metrics, cache hit rates.
4. **Privacy enhancements**: Differential privacy for aggregate statistics, configurable data retention, GDPR-compliant data deletion.

### GA5: MCP Feedback System (Rust)

**Priority**: P1 | **Effort**: Medium | **Closes**: GAP-16
**Depends on**: M40 (Feedback Loop)

**Current State**: V1 FeedbackManager with file/directory-level scoring. Rating system: good (+0.1), bad (-0.15), irrelevant (-0.05). Directory propagation at 30%. Exclusion threshold: boost < -0.5 AND confidence > 0.5.

**Proposed for V2**:
1. **Preserve all v1 scoring mechanics** — these are well-calibrated.
2. **Move to Rust**: Feedback scoring is a hot path during MCP tool responses.
3. **Integrate with detector health**: Feedback scores feed into per-detector FP rate calculation.
4. **New capabilities**:
   - Per-pattern feedback (not just per-example)
   - Feedback aggregation across team members (enterprise)
   - Feedback-driven confidence adjustment (patterns with consistently bad examples get confidence penalty)
   - Feedback export for model training

### GA6: MCP Pack Manager (TS — stays in orchestration)

**Priority**: P2 | **Effort**: Low | **Closes**: GAP-17

**Current State**: V1 PackManager with custom pack creation, staleness detection, usage tracking, suggestion engine.

**Proposed for V2**: Preserve as-is in TypeScript orchestration layer. Packs are a presentation concern — they organize MCP tools for AI consumption. No Rust migration needed. Add: pack versioning, pack sharing (export/import), pack marketplace (enterprise).

---

## Gap Closure Category B: Infrastructure & Operational Maturity

### GB1: Rust CI Integration

**Priority**: P0 | **Effort**: Low | **Closes**: GAP-7.1
**Depends on**: None (can be done immediately)

**Actions**:
1. Add `cargo clippy --all-targets --all-features -- -D warnings` to CI pipeline
2. Add `cargo fmt --all -- --check` to CI pipeline
3. Add `cargo test` to CI pipeline
4. Add `cargo audit` for dependency vulnerability scanning
5. Remove `continue-on-error: true` from build and test steps (fix the debt)
6. Re-enable lint step

**Implementation**: Single GitHub Actions workflow addition. Estimated: 2 hours.

### GB2: Supply Chain Security

**Priority**: P1 | **Effort**: Medium | **Closes**: GAP-7.3
**Depends on**: GB1 (Rust CI)

**Actions**:
1. **SBOM generation**: Add `cargo-sbom` for Rust dependencies, `@cyclonedx/bom` for npm dependencies. Generate in both SPDX and CycloneDX formats. Publish with each release.
2. **Dependency scanning**: Enable Dependabot for both npm and Cargo dependencies. Configure weekly scans with auto-PR for patches.
3. **Provenance attestation**: Use npm provenance (already partial in v1) + Sigstore for Rust artifacts. Target SLSA Level 2.
4. **Signed releases**: Sign npm packages and native binaries with Sigstore.

**Evidence**: SLSA framework, SBOM best practices (RESEARCH §5.1, §5.2).

### GB3: Multi-Architecture Docker Builds

**Priority**: P1 | **Effort**: Medium | **Closes**: GAP-7.4
**Depends on**: GB1 (Rust CI)

**Actions**:
1. Add `docker buildx` with `--platform linux/amd64,linux/arm64` to CI
2. Use pre-built native binaries in Docker (faster build, larger image) rather than compiling Rust in Docker
3. Add Alpine-based image variant (requires linux-x64-musl target)
4. Add linux-x64-musl and linux-arm64-musl to native build matrix

### GB4: Release Orchestration

**Priority**: P1 | **Effort**: Medium | **Closes**: GAP-7.2
**Depends on**: GB2 (Supply Chain)

**Actions**:
1. Adopt Changesets for coordinated monorepo versioning (npm + cargo)
2. Automated release pipeline: version bump → build → test → SBOM → sign → publish
3. Canary releases: publish to `@next` npm tag for pre-release testing
4. Release notes generation from conventional commits

### GB5: Performance Regression CI

**Priority**: P1 | **Effort**: Medium | **Closes**: GAP-7.1 (partial)
**Depends on**: GB1 (Rust CI)

**Actions**:
1. Run `criterion` benchmarks in CI on every PR
2. Compare against baseline (main branch) with statistical significance testing
3. Fail PR if any benchmark regresses by >10% with p < 0.05
4. Track benchmark history for trend analysis
5. Key benchmarks: parse time per language, detection time per file, call graph build time, full scan time

### GB6: E2E Integration Tests

**Priority**: P2 | **Effort**: High | **Closes**: GAP-7.1 (partial)
**Depends on**: GB1 (Rust CI)

**Actions**:
1. Full pipeline test: scan → detect → analyze → store → query via MCP
2. Use demo applications (GAP-09) as test fixtures
3. Snapshot testing: compare analysis results against known-good baselines
4. Cross-language parity testing: same patterns detected in equivalent code across languages

---

## Gap Closure Category C: Data Integrity & Storage

### GC1: Schema Versioning in Rust

**Priority**: P0 | **Effort**: Low | **Closes**: GAP-8.5
**Depends on**: M3 (SQLite WAL)

**Current State**: V1 Rust `CallGraphDb` creates schema on open with no version tracking. Only TS has migration support.

**Proposed for V2**:
1. `schema_version` table in every Rust-managed SQLite database
2. Forward-only migrations with version tracking
3. Migration runner at database open time
4. Rollback support via SQLite backup before migration

```rust
pub struct MigrationRunner {
    migrations: Vec<Migration>,
}

struct Migration {
    version: u32,
    description: &'static str,
    up: &'static str,  // SQL
}

impl MigrationRunner {
    pub fn run(&self, conn: &Connection) -> Result<()> {
        let current = self.current_version(conn)?;
        for migration in &self.migrations {
            if migration.version > current {
                conn.execute_batch(migration.up)?;
                self.set_version(conn, migration.version)?;
            }
        }
        Ok(())
    }
}
```

### GC2: Data Retention Policies

**Priority**: P1 | **Effort**: Low | **Closes**: GAP-8.4
**Depends on**: GC1 (Schema Versioning)

**Actions**:
1. Pattern history: 180-day retention (configurable)
2. Audit snapshots: 90-day retention (preserved from v1)
3. Gate run history: 100 runs max (preserved from v1)
4. Learned patterns: 7-day expiry (up from v1's 24 hours — more stable)
5. Feedback scores: 365-day retention
6. Scan history: 90-day retention
7. Automated cleanup job on scan completion

### GC3: Data Integrity Validation

**Priority**: P1 | **Effort**: Medium | **Closes**: GAP-8.3
**Depends on**: GC1 (Schema Versioning)

**Actions**:
1. Periodic consistency checks: verify foreign key integrity, orphan detection
2. Checksum verification on critical reads (pattern data, call graph)
3. Corruption detection with automatic recovery (re-scan if corrupted)
4. `PRAGMA integrity_check` on database open (configurable — disabled by default for performance)

---

## Gap Closure Category D: Documentation & Corrections

### GD1: Documentation Corrections

**Priority**: P1 | **Effort**: Low | **Closes**: GAP-9.1 through GAP-9.7

**Actions** (all corrections from RECAP §9):
1. CLI command count: Update from "~45" to "65+" in all references
2. MCP tool count: Update from "90+" to "~56 routed tools" in all references
3. Matcher directory: Add `confidence-scorer.ts` and `pattern-matcher.ts` to documentation
4. .drift/ directory: Add `learned/`, `feedback/`, `packs/`, `license.key`, `backups/` to configuration docs
5. Package detector scope: Document all 11 package ecosystems
6. Confidence weights: Standardize on code values (0.40/0.30/0.15/0.15), remove incorrect documentation values
7. MCP dual-path: Document the legacy JSON vs new SQLite tool implementations

### GD2: Skills Library Documentation

**Priority**: P2 | **Effort**: Medium | **Closes**: GAP-07

**Actions**:
1. Catalog all 73 skill templates with categories, descriptions, and use cases
2. Define skill template schema for v2 (TOML-based, machine-readable)
3. Identify which skills map to v2 detectors (cross-reference)
4. Plan skill marketplace for enterprise (custom skill sharing)

### GD3: Wiki Migration Plan

**Priority**: P2 | **Effort**: Low | **Closes**: GAP-08

**Actions**:
1. Audit all 58 wiki pages for accuracy against v2 architecture
2. Identify pages that need rewriting vs. updating
3. Prioritize: Getting Started, CLI Reference, Configuration, MCP, Quality Gates
4. Plan documentation framework for v2 (mdBook, Docusaurus, or similar)

---

## Gap Closure Category E: Cross-Cutting Strategies

### GE1: EventEmitter Architecture Preservation

**Priority**: P1 | **Effort**: Medium | **Closes**: GAP-25, GAP-3.11
**Depends on**: M4 (Layered Architecture)

**Current State**: V1 uses pervasive EventEmitter pattern — nearly every store/manager emits events. No backpressure, no ordering guarantees.

**Proposed for V2**:
1. **Rust event bus**: Typed event system using `tokio::sync::broadcast` or custom channel-based bus.
2. **Event categories**: `PatternEvent` (added, approved, ignored, updated), `ScanEvent` (started, progress, completed), `AnalysisEvent` (call_graph_built, coupling_computed), `GateEvent` (run_started, gate_passed, gate_failed).
3. **Ordering guarantees**: Events within a category are ordered. Cross-category ordering is best-effort.
4. **Backpressure**: Bounded channels with configurable buffer size. Slow consumers get dropped events with a warning (not blocked).
5. **TS bridge**: Events cross the NAPI boundary via callback registration. TS orchestration layer subscribes to Rust events for UI updates, MCP notifications, etc.

### GE2: Incremental Analysis Integration Strategy

**Priority**: P0 | **Effort**: High | **Closes**: GAP-3.8 (the meta-gap)
**Depends on**: M1 (Incremental-First), M5 (Scanner), M13 (Parse Cache), M17 (Incremental Detection)

This is not a single recommendation — it's the integration strategy for how incrementality flows through the entire pipeline.

**Three incrementality modes**:

| Mode | Trigger | Scope | Target Latency |
|------|---------|-------|---------------|
| **Batch** | CLI `drift scan` | All files, full analysis | <60s for 500K files |
| **Incremental** | CLI `drift scan` (repeat) | Changed files only, re-aggregate affected patterns | <5s for 10K files with 10 changes |
| **IDE** | File save / keystroke | Single file, sub-expression | <100ms |

**Pipeline for incremental mode**:
```
1. Scanner detects changed files (content hash comparison)
2. Only changed files are re-parsed (parse cache miss)
3. Only changed files are re-detected (detection cache miss)
4. Only affected patterns are re-aggregated (dependency tracking)
5. Only affected patterns are re-scored (confidence recalculation)
6. Only affected call graph edges are rebuilt (incremental call graph)
7. Only stale views are re-materialized (incremental views)
```

**Pipeline for IDE mode**:
```
1. tree-sitter tree.edit() for sub-millisecond re-parse
2. Single-file detection (visitor pattern on changed AST subtree)
3. Incremental pattern update (add/remove locations for this file)
4. No cross-file analysis (deferred to next incremental scan)
5. Immediate violation feedback (diagnostics pushed to IDE)
```

**Key invariant** (from rust-analyzer): "Typing inside a function body never invalidates global derived data." Separate function signatures (module-level, triggers cross-file invalidation) from function bodies (local, no cross-file impact).

**Evidence**: Salsa framework, rust-analyzer durable incrementality (RESEARCH §3.1, §3.2).

### GE3: Cross-Language Detector Reuse via GAST

**Priority**: P1 | **Effort**: High | **Closes**: GAP-5.1, GAP-5.2 (coverage gaps)
**Depends on**: M16 (GAST Normalization Layer), M6 (Canonical ParseResult)

**Strategy for closing language coverage gaps**:

| Phase | Languages | Approach |
|-------|-----------|----------|
| Launch | TypeScript, JavaScript, Python, Java | Full GAST normalizers + all detectors |
| +3 months | C#, PHP, Go | GAST normalizers + automatic detector coverage |
| +6 months | Rust, C++, C | GAST normalizers + language-specific detectors for unique patterns |

**Framework coverage expansion**:

| Phase | Frameworks | Approach |
|-------|-----------|----------|
| Launch | React, Express, Spring Boot, Django, Laravel | Full framework middleware |
| +3 months | Vue, Angular, FastAPI, ASP.NET, Next.js, NestJS | Framework middleware |
| +6 months | Svelte, Remix, Gin, Axum, Phoenix, Rails | Framework middleware |

**Key insight**: With GAST, adding a new language requires only a normalizer (~500-1000 lines). All existing detectors work automatically for common patterns. Language-specific detectors are only needed for truly unique constructs (PHP attributes, Rust lifetimes, Go goroutines).

**Evidence**: YASA UAST (RESEARCH §8.1), Semgrep Generic AST (RESEARCH §8.2).

### GE4: Security Gap Closure Roadmap

**Priority**: P0-P1 | **Effort**: Very High | **Closes**: GAP-4.1 through GAP-4.6
**Depends on**: M18 (Secret Detection), M27 (Taint Analysis), M36 (OWASP/CWE)

**Phase 1 — Launch (P0)**:
- 100+ secret patterns (up from 21) with Shannon entropy scoring
- OWASP A01 (access control), A02 (crypto), A03 (injection), A07 (auth), A10 (SSRF) detectors
- Every security finding carries CWE IDs and OWASP category
- Intraprocedural taint analysis for SQL injection and XSS

**Phase 2 — +3 months (P1)**:
- Interprocedural taint via call graph integration (function summaries)
- Field-level data flow tracking (users.password_hash vs users.display_name)
- OWASP A04 (insecure design), A05 (misconfiguration), A08 (integrity), A09 (logging) detectors
- Framework-specific source/sink/sanitizer definitions

**Phase 3 — +6 months (P2)**:
- Cross-service taint tracking (via API call graph)
- Compliance report generation (OWASP, CWE, SOC2)
- Security finding deduplication across taint paths
- Integration with external vulnerability databases (NVD, OSV)

**Evidence**: OWASP Top 10, CWE Top 25, FlowDroid, Semgrep taint mode, SemTaint (RESEARCH §2.1-2.4).

### GE5: Algorithm Preservation & Improvement Strategy

**Priority**: P0 | **Effort**: Low | **Closes**: GAP-2.1 through GAP-2.12
**Depends on**: M33 (Temporal Decay), M34 (Bayesian Learning), M35 (Outlier Refinements)

**Preservation** (exact v1 values as baseline, with documented rationale for any changes):

| Algorithm | V1 Value | V2 Value | Rationale |
|-----------|----------|----------|-----------|
| Confidence weights | 0.40/0.30/0.15/0.15 | 0.30/0.25/0.10/0.15/0.20 | Add momentum (0.20), reduce frequency/consistency/age to compensate |
| Confidence thresholds | 0.85/0.70/0.50 | 0.85/0.70/0.50 | Preserve — well-calibrated |
| Outlier Z-score | \|z\| > 2.0 | \|z\| > 2.5 | NIST recommends 3.0; 2.5 balances sensitivity/precision |
| Convention threshold | 60% binary | Bayesian Beta(α+s, β+f) | Eliminates arbitrary threshold |
| Duplicate Jaccard | 0.85 | 0.85 (flag), 0.95 (auto-merge) | Add auto-merge for near-identical patterns |
| Health score weights | 0.30/0.20/0.20/0.15/0.15 | 0.25/0.15/0.20/0.15/0.10/0.15 | Add FP rate (0.15), reduce others proportionally |
| Feedback scoring | +0.1/-0.15/-0.05 | +0.1/-0.15/-0.05 | Preserve — well-calibrated |
| Gate scoring | 10/3/1 penalty | 10/3/1 penalty | Preserve |
| Secret confidence | 0.9/0.8/0.6 base | 0.9/0.8/0.6 base + entropy | Add Shannon entropy adjustment |
| Wrapper confidence | 0.6 base, 0.5 threshold | 0.6 base, 0.5 threshold | Preserve |

**Key principle**: Every algorithm change must be A/B testable. V2 should support running v1 and v2 algorithms side-by-side on the same codebase to validate that changes improve results.

---

## Gap Closure Dependency Graph

```
GA1 (Licensing) ──────────────────────────────────────────────────────┐
GA2 (Workspace) ──→ GE2 (Incremental Integration)                    │
GA3 (Audit) ──→ GE5 (Algorithm Preservation)                         │
                                                                      │
GB1 (Rust CI) ──→ GB2 (Supply Chain) ──→ GB4 (Release Orchestration) │
             ──→ GB3 (Multi-Arch Docker)                              │
             ──→ GB5 (Performance Regression CI)                      │
             ──→ GB6 (E2E Tests)                                      │
                                                                      │
GC1 (Schema Versioning) ──→ GC2 (Retention) ──→ GC3 (Integrity)     │
                                                                      │
GD1 (Doc Corrections) ── standalone                                   │
GD2 (Skills) ── standalone                                            │
GD3 (Wiki) ── standalone                                              │
                                                                      │
GE1 (EventEmitter) ──→ GA2 (Workspace — event-driven state)          │
GE2 (Incremental) ──→ ALL analysis subsystems                        │
GE3 (GAST Coverage) ──→ GE4 (Security — cross-language taint)        │
GE4 (Security Roadmap) ──→ GA1 (Licensing — security features gated) │
GE5 (Algorithms) ──→ GA3 (Audit — health scoring uses new algorithms)│
```

---

## Gap Coverage Matrix

This matrix maps every gap from the RECAP to its closure mechanism — either an M-XX recommendation from MASTER_RECOMMENDATIONS or a GA/GB/GC/GD/GE recommendation from this document.

### Primary Gaps (GAP-01 through GAP-25)

| Gap | Description | Closed By |
|-----|-------------|-----------|
| GAP-01 | Licensing & Feature Gating | **GA1** |
| GAP-02 | Workspace Management | **GA2** |
| GAP-03 | Audit System | **GA3** |
| GAP-04 | Pattern Matcher & Confidence Scorer | M33, M34, **GE5** |
| GAP-05 | Context Generation | ✅ Already documented |
| GAP-06 | Storage Backend Auto-Detection | M3 (SQLite-only eliminates need) |
| GAP-07 | Skills Library | **GD2** |
| GAP-08 | Wiki Documentation | **GD3** |
| GAP-09 | Demo Applications | **GB6** (E2E tests use demos) |
| GAP-10 | GitHub Action | **GB4** (Release orchestration) |
| GAP-11 | Services Layer | ✅ Already documented |
| GAP-12 | Learning System | M34 (Bayesian Learning) |
| GAP-13 | Unified Provider Internals | M15 (Unified Analyzer) |
| GAP-14 | Speculative Execution | Deferred (P3) |
| GAP-15 | Dual Licensing | **GA1** |
| GAP-16 | MCP Feedback System | **GA5** |
| GAP-17 | MCP Pack Manager | **GA6** |
| GAP-18 | Storage Auto-Detection | M3 |
| GAP-19 | JSON↔SQLite Sync | Eliminated (SQLite-only in v2) |
| GAP-20 | Docker Deployment | **GB3** |
| GAP-21 | Husky Git Hooks | **GB4** |
| GAP-22 | Build Scripts | **GB4** |
| GAP-23 | Turborepo Pipeline | **GB4** |
| GAP-24 | Pattern System Consolidation | ✅ Already documented |
| GAP-25 | EventEmitter Architecture | **GE1** |

### Architectural Gaps (GAP-3.1 through GAP-3.11)

| Gap | Description | Closed By |
|-----|-------------|-----------|
| GAP-3.1 | Three ParseResult shapes | M6 (Canonical ParseResult) |
| GAP-3.2 | Dual-layer architecture | M4, M14, M16 (Rust-first) |
| GAP-3.3 | Six storage backends | M3 (SQLite-only) |
| GAP-3.4 | No structured errors | M2 (thiserror) |
| GAP-3.5 | Thread-local parsers | M10 (Parser Pool) |
| GAP-3.6 | Dead code in unified analyzer | M15 (rebuild from scratch) |
| GAP-3.7 | JSON shard duplication | M3 (SQLite-only) |
| GAP-3.8 | No incremental anything | M1, **GE2** |
| GAP-3.9 | No pattern decay | M33 (Temporal Decay) |
| GAP-3.10 | No pattern merging | **GA3** (auto-merge at Jaccard >0.95) |
| GAP-3.11 | EventEmitter without backpressure | **GE1** |

### Security Gaps (GAP-4.1 through GAP-4.6)

| Gap | Description | Closed By |
|-----|-------------|-----------|
| GAP-4.1 | Only 21 secret patterns | M18, **GE4** Phase 1 |
| GAP-4.2 | No OWASP/CWE mapping | M36, **GE4** Phase 1 |
| GAP-4.3 | No taint analysis | M27, **GE4** Phases 1-2 |
| GAP-4.4 | Missing OWASP coverage | M36, **GE4** Phases 1-2 |
| GAP-4.5 | No field-level data flow | M27, **GE4** Phase 2 |
| GAP-4.6 | No cross-file data flow | M27, **GE4** Phase 2 |

### Coverage, Performance, Infrastructure, Data Integrity Gaps

| Gap Category | Gap Count | Closed By |
|-------------|-----------|-----------|
| Language coverage (GAP-5.1) | 10 languages | M16, **GE3** |
| Framework coverage (GAP-5.2) | 12+ frameworks | M42, **GE3** |
| API paradigm (GAP-5.3) | GraphQL, gRPC, WebSocket | M41 |
| Rust parity (GAP-5.5) | 19 features | M6, M7, M14, M15, M20-M32 |
| Performance (GAP-6.x) | 5 areas | M1, M13, M14, **GE2** |
| CI/CD (GAP-7.1) | 5 items | **GB1**, **GB5**, **GB6** |
| Build/Release (GAP-7.2) | 4 items | **GB4** |
| Supply chain (GAP-7.3) | 4 items | **GB2** |
| Operational (GAP-7.4) | 4 items | **GB3**, **GB4** |
| Data integrity (GAP-8.x) | 5 items | **GC1**, **GC2**, **GC3** |
| Doc corrections (GAP-9.x) | 7 items | **GD1** |

---

## Build Phase Alignment

| Phase | M-XX (MASTER) | GA-GE (This Doc) | Gap Count Closed |
|-------|---------------|-------------------|-----------------|
| Phase 0 (Decisions) | M1-M4 | — | 8 |
| Phase 1 (Core Engine) | M5-M13 | GA2, GC1 | 18 |
| Phase 2 (Detection) | M14-M19 | GE3 (partial) | 22 |
| Phase 3 (Analysis) | M20-M32 | GA3, GE4 (Phase 1) | 30 |
| Phase 4 (Scoring) | M33-M35 | GE5 | 12 |
| Phase 5 (Security) | M36-M37 | GE4 (Phase 2) | 10 |
| Phase 6 (Bridge & DX) | M38-M42 | GA1, GA5, GA6, GE1 | 20 |
| Phase 7 (QA & Ecosystem) | — | GB1-GB6, GC2-GC3, GD1-GD3 | 30 |

**Total gaps closed**: ~150 (all identified gaps have a closure mechanism)

---

## Success Metrics for Gap Closure

| Metric | Current (V1) | Target (V2 Launch) | Target (V2 +6mo) |
|--------|-------------|-------------------|-------------------|
| Identified gaps | 150+ | <20 open | <5 open |
| P0 gaps open | 18 | 0 | 0 |
| P1 gaps open | 24 | <10 | 0 |
| OWASP coverage | 2-3 categories | 8+ categories | 10/10 |
| Secret patterns | 21 | 100+ | 150+ |
| Language coverage (full detection) | 2 (TS, JS) | 4 (+ Python, Java) | 7 (+ C#, PHP, Go) |
| Framework coverage (Tier 1) | 6 | 10+ | 15+ |
| Incremental scan latency | N/A (batch only) | <5s | <1s |
| Supply chain security level | SLSA 0 | SLSA 2 | SLSA 3 |
| CI pipeline completeness | 60% (no Rust, no lint) | 95% | 100% |
| Documentation accuracy | ~80% (7 corrections needed) | 99% | 100% |

---

## Quality Checklist

- [x] All 150+ gaps from RECAP have a closure mechanism (M-XX or GA-GE)
- [x] No duplication with MASTER_RECOMMENDATIONS (M1-M42)
- [x] 15 new recommendations (GA1-GA6, GB1-GB6, GC1-GC3, GD1-GD3, GE1-GE5)
- [x] Each recommendation has priority, effort, gap references, and dependencies
- [x] Gap coverage matrix maps every gap to its closure mechanism
- [x] Build phase alignment shows when each gap gets closed
- [x] Dependency graph shows ordering constraints
- [x] Success metrics with V1 baselines and V2 targets
- [x] Evidence cited from RESEARCH.md throughout
- [x] Cross-references to MASTER_RECOMMENDATIONS where recommendations extend M-XX items
- [x] Algorithm preservation table ensures v1 calibration is not lost
- [x] Security roadmap phased across 3 milestones
- [x] Infrastructure recommendations are immediately actionable (GB1 = 2 hours)
