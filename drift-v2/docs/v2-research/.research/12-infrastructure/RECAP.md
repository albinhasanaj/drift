# 12 Infrastructure — Research Recap

> A complete synthesis of Drift v1's infrastructure layer — the operational backbone that makes Drift shippable, testable, deployable, and maintainable. This document serves as the definitive infrastructure requirements specification for the v2 enterprise greenfield build.

---

## Executive Summary

Infrastructure is Drift's operational nervous system — everything outside core analysis that is essential for shipping, testing, deploying, and operating the product. In v1, infrastructure spans ~30 files across 14 subsystems: a pnpm + Turborepo monorepo build system, GitHub Actions CI/CD (4 workflows), NAPI-RS cross-compilation for 7 platform targets, Docker containerization for the MCP server, Cloudflare Workers telemetry, a JWT/key-based licensing system with 3 tiers and 16 gated features, a multi-provider AI abstraction (Anthropic/OpenAI/Ollama), a novel 4-level codebase intelligence benchmark (CIBench), a 3D visualization library (Galaxy), a composite GitHub Action for PR analysis, an autonomous CI agent with 9 analysis passes, and publish/validation scripts.

V1 infrastructure is functional but has significant gaps for enterprise v2: no Rust-aware CI (no `cargo clippy`/`fmt`/`test`), no multi-arch Docker builds, no automated release orchestration across npm + cargo, no infrastructure-as-code, no observability beyond basic telemetry, no supply chain security (no SBOM, no dependency scanning, no provenance), no reproducible builds, and no performance regression detection in CI.


---

## Current Implementation

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        GitHub Actions CI/CD                              │
│  ci.yml │ native-build.yml │ release.yml │ drift-check.yml.template     │
├─────────────────────────────────────────────────────────────────────────┤
│                        Build System                                      │
│  pnpm 8 │ Turborepo │ tsconfig.base │ ESLint │ Vitest │ Prettier       │
├──────────────┬──────────────┬───────────────────────────────────────────┤
│  Rust Core   │  NAPI Bridge │  TypeScript Packages (12)                 │
│  drift-core  │  drift-napi  │  core│detectors│cortex│mcp│cli│lsp│...   │
├──────────────┴──────────────┴───────────────────────────────────────────┤
│                        Deployment                                        │
│  Docker (MCP Server) │ npm publish │ Native binaries (7 platforms)      │
├─────────────────────────────────────────────────────────────────────────┤
│                        Supporting Infrastructure                         │
│  CI Agent │ AI Providers │ Galaxy Viz │ CIBench │ Telemetry │ Licensing │
└─────────────────────────────────────────────────────────────────────────┘
```

### Subsystem Inventory

| # | Subsystem | Location | Language | Files | Purpose |
|---|-----------|----------|----------|-------|---------|
| 1 | Build System | Root configs | YAML/JSON | ~8 | pnpm workspaces + Turborepo orchestration |
| 2 | CI/CD Workflows | `.github/workflows/` | YAML | 4 | Build, test, native compile, release |
| 3 | Rust Build | `crates/` | Rust/TOML | ~5 | Cargo workspace, NAPI-RS, cross-compilation |
| 4 | Docker | Root | Dockerfile | 3 | Containerized MCP server deployment |
| 5 | Telemetry | `infrastructure/telemetry-worker/` | TS | ~5 | Cloudflare Worker for anonymous metrics |
| 6 | Licensing | `packages/core/src/licensing/` | TS | ~4 | Open-core feature gating (3 tiers) |
| 7 | AI Providers | `packages/ai/` | TS | ~10 | Anthropic/OpenAI/Ollama abstraction |
| 8 | CIBench | `packages/cibench/` | TS | ~25 | Codebase intelligence benchmark |
| 9 | Galaxy | `packages/galaxy/` | TS/React | ~25 | 3D schema visualization |
| 10 | GitHub Action | `actions/drift-action/` | YAML | 2 | Composite action for PR analysis |
| 11 | CI Agent | `packages/ci/` | TS | ~10 | Autonomous PR analysis agent |
| 12 | Scripts | `scripts/` | Shell/TS | 5 | Publish, validation, generation |
| 13 | LSP Server | `packages/lsp/` | TS | ~5 | Language Server Protocol for IDE |
| 14 | Dashboard | `packages/dashboard/` | TS/React | ~15 | Vite + React + Tailwind web UI |


---

## Subsystem Deep Dives

### 1. Build System

**Package Manager**: pnpm 8.10.0 with workspace protocol. 12 TypeScript packages + 2 Rust crates.

**Turborepo** (`turbo.json`): Dependency-aware build orchestration with caching. Pipeline: `build` (cached, `^build` deps), `typecheck` (cached), `lint` (cached), `test` (cached), `dev` (persistent, no cache), `clean` (no cache). Outputs cached: `dist/**`, `coverage/**`.

**TypeScript Configuration** (`tsconfig.base.json`):
- Target: ES2022, Module: NodeNext, Module Resolution: NodeNext
- Full strict mode: `strict`, `noImplicitAny`, `strictNullChecks`, `strictFunctionTypes`, `strictBindCallApply`, `strictPropertyInitialization`, `noImplicitThis`, `useUnknownInCatchVariables`, `alwaysStrict`, `noUnusedLocals`, `noUnusedParameters`, `exactOptionalPropertyTypes`, `noImplicitReturns`, `noFallthroughCasesInSwitch`, `noUncheckedIndexedAccess`, `noImplicitOverride`, `noPropertyAccessFromIndexSignature`
- Path aliases: `@drift/<name>` → `packages/<name>/src/index.ts`
- Emit: declarations, declaration maps, source maps, composite, incremental

**ESLint** (flat config): TypeScript-aware with key rules — `explicit-function-return-type` (warn), `no-floating-promises` (warn), `no-misused-promises` (warn), `await-thenable` (error), `eqeqeq` (error), `no-console` (warn). Test files relax `no-explicit-any`, `no-non-null-assertion`, `no-unsafe-*`.

**Vitest**: Node environment, thread pool, 10s timeout, v8 coverage provider. Coverage thresholds: 80% across statements/branches/functions/lines.

**Prettier**: 100 char width, single quotes, trailing commas, 2-space tabs.

**Engine Requirements**: Node.js >= 18.0.0, pnpm >= 8.0.0.

**Package Dependency Graph**:
```
driftdetect (CLI)
├── driftdetect-core (no internal deps)
│   ├── driftdetect-detectors
│   └── drift-native (optional, NAPI)
├── driftdetect-detectors (depends on core)
├── driftdetect-cortex (depends on core)
├── driftdetect-dashboard (depends on core, galaxy)
└── driftdetect-mcp (depends on core, detectors, cortex)

driftdetect-ci (depends on core, cortex, detectors)
@drift/ai (depends on core)
```

**Publish Order**: core → detectors → galaxy → dashboard → CLI → MCP.

### 2. CI/CD Workflows

**4 GitHub Actions workflows**:

#### ci.yml — Main CI Pipeline
- Trigger: Push/PR to `main`
- Matrix: Node 18, 20, 22
- Steps: checkout → pnpm install → build (excludes cibench, galaxy, lsp, vscode) → test (core, detectors, mcp only)
- `continue-on-error: true` on build and test (debt)
- Lint disabled (debt)
- `publish-check` job on main: prints package versions

#### native-build.yml — Cross-Platform Rust Compilation
- Trigger: Push/PR to `main` (paths: `crates/**`), manual dispatch
- Build matrix (5 targets):

| Host | Target | npm Package |
|------|--------|-------------|
| macOS | `x86_64-apple-darwin` | `darwin-x64` |
| macOS | `aarch64-apple-darwin` | `darwin-arm64` |
| Windows | `x86_64-pc-windows-msvc` | `win32-x64-msvc` |
| Ubuntu | `x86_64-unknown-linux-gnu` | `linux-x64-gnu` |
| Ubuntu | `aarch64-unknown-linux-gnu` | `linux-arm64-gnu` |

- Steps: checkout → Node 20 → Rust stable → npm install → NAPI-RS build → upload artifact
- Test matrix: macOS arm64, Linux x64, Windows x64 — verifies `version()` and `supportedLanguages()`
- Publish job (manual): downloads all 5 artifacts → updates versions → publishes platform packages → publishes main `drift-native`
- Uses `--use-napi-cross` for Linux cross-compilation

#### release.yml — Package Release
- Trigger: Manual dispatch with `package` (cli|core|detectors|mcp|dashboard|all) and `version_bump` (patch|minor|major)
- Steps: checkout (full history) → pnpm install → build → test → git config → npm publish with provenance
- Publish order when "all": core → detectors → dashboard → MCP → CLI

#### drift-check.yml.template — User Template
- Template for users to add Drift checking to their repos
- Features: `.drift` directory caching, full scan on push, incremental on PRs, `drift gate --ci --format github`, artifact upload


### 3. Rust Build System

**Workspace Structure**:
```toml
[workspace]
resolver = "2"
members = ["drift-core", "drift-napi"]
```

**drift-core**: Analysis engine. Compiles as `cdylib` (for NAPI) and `rlib` (for Rust consumers).

**drift-napi**: NAPI-RS bindings exposing ~25 functions to Node.js.

**Key Dependencies**:
- Parsing: `tree-sitter` 0.23 + 10 language grammars
- Filesystem: `walkdir` 2, `ignore` 0.4, `globset` 0.4
- Parallelism: `rayon` 1.10
- Storage: `rusqlite` 0.31 (bundled SQLite)
- Hashing: `xxhash-rust` 0.8 (xxh3), `rustc-hash` 2 (FxHashMap)
- Serialization: `serde` 1, `serde_json` 1
- Errors: `thiserror` 1, `anyhow` 1
- Other: `regex` 1, `once_cell` 1, `smallvec` 1.13
- NAPI: `napi` 2 (async, serde-json), `napi-derive` 2, `napi-build` 2

**Release Profile**:
```toml
[profile.release]
lto = true          # Link-time optimization
codegen-units = 1   # Single codegen unit for max optimization
opt-level = 3       # Maximum optimization
```

**NAPI Exports** (~25 functions): `scan`, `parse`, `buildCallGraph`, `scanBoundaries`, `analyzeCoupling`, `analyzeTestTopology`, `analyzeErrorHandling`, `analyzeReachability`, `analyzeInverseReachability`, `analyzeConstants`, `analyzeEnvironment`, `analyzeWrappers`, `analyzeUnified`, `version`, `supportedLanguages`, plus call graph query functions.

**Platform Packages**: Each target gets its own npm package under `crates/drift-napi/npm/` — main package uses `optionalDependencies` to pull the correct platform binary at install time.

**Benchmarks**: `criterion` 0.5 for statistical benchmarking with `parsing` and `full_pipeline` bench targets.

### 4. Docker Deployment

**Multi-stage Dockerfile**:
- Stage 1 (Builder): `node:20-slim`, installs pnpm + build tools (python3, make, g++), builds in dependency order (detectors → core → cortex → mcp), prunes dev dependencies
- Stage 2 (Production): `node:20-slim`, pnpm only, non-root user `drift` (uid 1001), `/workspace` mount point

**Configuration**:
```
PORT=3000, PROJECT_ROOT=/workspace, ENABLE_CACHE=true,
ENABLE_RATE_LIMIT=true, VERBOSE=false, NODE_ENV=production
```

**Health Check**: HTTP GET to `/health` every 30s, 10s timeout, 5s start period, 3 retries.

**docker-compose.yml**:
- Read-only project mount: `${PROJECT_PATH:-.}:/project:ro`
- Persistent cache volume: `drift-cache:/project/.drift`
- Memory: 4G limit, 1G reservation
- `NODE_OPTIONS=--max-old-space-size=4096`

**Endpoints**: `/health` (health check), `/sse` (SSE for MCP), `/message` (POST for MCP messages).

### 5. Telemetry

**Cloudflare Worker** (`infrastructure/telemetry-worker/`): Serverless telemetry collection with D1 (SQLite) storage.

**Endpoints**: `POST /v1/events` (max 100/batch), `GET /v1/health`, `GET /v1/stats` (public aggregates, 30 days).

**Database Schema**:
- `events`: Raw telemetry (type, timestamp, installation_id, drift_version, payload JSON)
- `daily_stats`: Aggregated metrics (date, metric, value)
- `pattern_signatures`: Deduplicated patterns for ML (signature_hash, category, detection_method, language, occurrence_count, avg_confidence)
- `action_aggregates`: User action stats (category, action, confidence_bucket, count, avg_hours_to_decision)

**Privacy**: No source code stored, anonymous UUIDs, SHA-256 pattern hashes (irreversible), 90-day raw event retention.

**Cost**: Cloudflare free tier covers ~1000 active users × 50 events/day.

### 6. Licensing & Feature Gating

**Architecture**: LicenseManager (singleton) → LicenseValidator → FeatureGuard.

**License Sources** (priority order):
1. `DRIFT_LICENSE_KEY` environment variable
2. `.drift/license.key` file
3. `.drift/config.json` `licenseKey` field
4. No license = community tier (always valid)

**License Formats**:
- JWT: header.payload.signature with HMAC verification, expiration, 30-day warning
- Simple key: prefix-based (`DRIFT-COM-`, `DRIFT-TEAM-`, `DRIFT-ENT-`) + 16-32 alphanumeric body

**3 Tiers**:

| Tier | Level | What's Included |
|------|-------|-----------------|
| Community | 0 | All scanning, detection, analysis, CI, MCP, VSCode — everything core |
| Team | 1 | + policy engine, regression detection, custom rules, trends, exports |
| Enterprise | 2 | + multi-repo governance, team analytics, audit trails, impact simulation, security boundaries, Jira/Slack/webhooks, self-hosted models, custom detectors, REST API, team dashboard |

**16 Gated Features**: `gate:policy-engine`, `gate:regression-detection`, `gate:custom-rules`, `dashboard:trends`, `dashboard:export` (Team); `gate:impact-simulation`, `gate:security-boundary`, `governance:multi-repo`, `governance:team-analytics`, `governance:audit-trail`, `integration:webhooks`, `integration:jira`, `integration:slack`, `advanced:self-hosted-models`, `advanced:custom-detectors`, `advanced:api-access`, `dashboard:team-view` (Enterprise).

**Guard Patterns**: `requireFeature()` (throws), `checkFeature()` (returns result), `guardFeature()` (wraps function), `withFeatureGate()` (creates gated version), `@RequiresFeature()` (decorator), `guardMCPTool()` (MCP-specific), `requireTier()` (tier check).


### 7. AI Provider Package

**Unified abstraction** (`packages/ai/`): `AIProvider` interface with `explain()` and `generateFix()` methods.

**3 Providers**: Anthropic (Claude), OpenAI, Ollama (local inference). Auto-detection by API key availability.

**Context Pipeline**: CodeExtractor → ContextBuilder → Sanitizer → PromptTemplate → Provider → Result.

**Types**: `ExplainContext` (violation, pattern, code snippet, similar examples), `FixContext` (violation, pattern, code, surrounding code), `ExplainResult` (explanation, suggested action), `FixResult` (fixed code, explanation, confidence), `AIResponse` (content, token usage).

**Confirmation Flow**: Consent + Preview before applying AI-generated fixes.

### 8. CIBench — Codebase Intelligence Benchmark

**Novel benchmark framework** (`packages/cibench/`): Measures how well tools understand codebases (not just navigate them). 4-level hierarchical evaluation.

**Scoring Framework**:
```
CIBench Score = Σ(level_score × level_weight)
Level 1 (Perception):     30%  — Pattern recognition, call graph, data flow
Level 2 (Understanding):  35%  — Architectural intent, causal reasoning, uncertainty
Level 3 (Application):    25%  — Token efficiency, compositional reasoning, negative knowledge
Level 4 (Validation):     10%  — Human correlation
```

**Novel Features**:
- Counterfactual evaluation: "What would happen if we removed this function?"
- Calibration measurement: ECE (Expected Calibration Error), MCE (Maximum Calibration Error)
- Generative probes: Open-ended questions scored against expected concepts
- Adversarial robustness: Misleading variable names, dead code, outdated comments
- Negative knowledge: Tests whether tools know what NOT to do

**Architecture**: CLI → Adapters (Drift, Baseline) → Evaluators (Perception, Understanding, Application, Calibration, Probe) → Schema (ground truth) → Test Corpus.

**Test Corpus**: `demo-backend/`, `typescript-express/`, `competitive-intelligence-api/` — each with `.cibench/` ground truth directory containing perception, understanding, application, probes, and validation data.

**Benchmark Protocol**: 8 tasks scored 0-2 each (16 points max). Run WITH Drift vs WITHOUT Drift. Expected: Drift 16/16, Baseline 8-11/16. Key differentiator: Task 3 (missing auth) — grep can't find code that doesn't exist.

### 9. Galaxy Visualization

**3D visualization library** (`packages/galaxy/`): Renders database schemas as interactive galaxies. Tables = planets, fields = moons, entry points = space stations, data flows = glowing lanes.

**Tech Stack**: React 18, Three.js 0.160, react-three-fiber 8, @react-three/drei, @react-three/postprocessing, Zustand 4, jsfxr (procedural sound).

**Components**: GalaxyCanvas (root), TablePlanet, FieldMoon, EntryPointStation, DataPathLane, TableRelationship, AccessPulse, GalaxyBloom, StarField, ControlsPanel, DetailsPanel, SearchOverlay, SecurityPanel, StatsOverlay.

**Supporting**: useGalaxyData hook, useAccessStream hook, galaxy-store (Zustand), force-directed layout engine, color/geometry utils, procedural sound effects.

### 10. GitHub Action

**Composite action** (`actions/drift-action/`): Installs `driftdetect-ci` and runs PR analysis.

**Inputs**: `github-token` (required), `fail-on-violation`, `post-comment`, `create-check`, `pattern-check`, `impact-analysis`, `constraint-verification`, `security-boundaries`, `memory-enabled`.

**Outputs**: `status` (pass/warn/fail), `summary`, `violations-count`, `drift-score` (0-100), `result-json`.

**Flow**: Setup Node 20 → Install `driftdetect-ci@latest` → Extract PR number → Run `drift-ci analyze --pr <N> --json` → Parse output → Set outputs → Exit code.

### 11. CI Agent

**Autonomous PR analysis agent** (`packages/ci/`): Published as `driftdetect-ci`.

**Architecture**: CLI → PRAnalyzer (orchestrator, ~1150 lines) → 12 pluggable interfaces → Providers (GitHub/GitLab) → Reporters (GitHub Comment/SARIF).

**12 Dependency Interfaces**: IPatternMatcher, IConstraintVerifier, IImpactAnalyzer, IBoundaryScanner, ITestTopology, IModuleCoupling, IErrorHandling, IContractChecker, IConstantsAnalyzer, IQualityGates, ITrendAnalyzer, ICortex.

**9-Pass Analysis Pipeline**:
1. Pattern matching
2. Constraint verification
3. Impact analysis
4. Security boundary scan
5. Test coverage analysis
6. Module coupling analysis
7. Error handling analysis
8. Contract checking
9. Constants analysis

**Scoring**: Weighted average — patterns (30%), constraints (25%), security (20%), tests (15%), coupling (10%).

**Heuristic Fallbacks**: When Drift core isn't initialized, falls back to regex-based pattern detection, file-based constraint checking, import graph traversal, keyword-based boundary detection, test file co-location checking, import counting, try/catch pattern detection, magic number regex.

**SARIF Reporter**: Generates SARIF 2.1.0 with pattern violations, constraint violations, security issues, error handling gaps, test coverage gaps, coupling issues, suggestions. Severity mapping: critical/high → error, medium → warning, low → note.

**GitHub Provider**: Full Octokit integration — PR context, comments, check runs, review comments, diff content, commit status.

### 12. Scripts & Automation

| Script | Purpose |
|--------|---------|
| `publish.sh` | Dependency-ordered npm publishing (core → detectors → galaxy → dashboard → CLI → MCP) |
| `validate-docs.sh` | CI-ready documentation validator — extracts valid commands from `--help`, scans markdown, reports invalid `drift <cmd>` references |
| `validate-docs.ts` | TypeScript version of doc validation |
| `generate-large-codebase.ts` | Generates synthetic test codebases for benchmarking |
| `transform-detector.ts` | Detector transformation utilities |


---

## Key Algorithms & Patterns

### 1. Cross-Platform Native Build Pipeline
```
Source (Rust) → NAPI-RS compile → .node binary per platform
  → Upload as GitHub artifact → Test on 3 platforms
  → Publish as platform-specific npm packages
  → Main package uses optionalDependencies for auto-selection
```

### 2. CI Agent Scoring
```
overallScore = patternScore × 0.30 + constraintScore × 0.25
             + securityScore × 0.20 + testScore × 0.15
             + couplingScore × 0.10
```

### 3. License Validation
```
Input → Check JWT format → Verify HMAC signature → Check expiration
  → Extract tier + features → Cache result
OR
Input → Check prefix (DRIFT-COM-/TEAM-/ENT-) → Validate body format
  → Map prefix to tier → Cache result
```

### 4. Feature Gating (Multiple Patterns)
```
requireFeature(feature)     → throws FeatureNotLicensedError
checkFeature(feature)       → returns { available, tier, upgradeUrl }
guardFeature(feature, fn)   → returns GatedResult<T>
@RequiresFeature(feature)   → method decorator
guardMCPTool(feature, handler) → MCP-specific error format
```

### 5. CIBench Calibration
```
ECE = Σ (|bin_accuracy - bin_confidence| × bin_weight)
MCE = max(|bin_accuracy - bin_confidence|)
```

### 6. Telemetry Event Processing
```
Batch (max 100) → Validate → Insert events → Update aggregates:
  - Event type counts (events:<type>)
  - Language counts (language:<lang>)
  - Category counts (category:<cat>)
  - Unique installations per day
```

---

## Data Models

### License
```typescript
LicensePayload { tier: 'community'|'team'|'enterprise', org: string,
  seats: number, iat: number, exp: number, iss: string, ver: number,
  features: string[] }
```

### CI Analysis Result
```typescript
AnalysisResult { status: 'pass'|'warn'|'fail', summary: string,
  score: number, patterns: PatternAnalysis, constraints: ConstraintAnalysis,
  impact: ImpactAnalysis, security: SecurityAnalysis, tests: TestAnalysis,
  coupling: CouplingAnalysis, errors: ErrorAnalysis, contracts: ContractAnalysis,
  constants: ConstantsAnalysis, qualityGates: QualityGateResult,
  suggestions: Suggestion[], learnings: Learning[], metadata: AnalysisMetadata }
```

### Telemetry Event
```typescript
TelemetryEvent { type: string, timestamp: string, installation_id: string,
  drift_version: string, payload: object }
```

### CIBench Score
```typescript
CIBenchResult { perception: { score, patternAccuracy, callGraphAccuracy, dataFlowAccuracy },
  understanding: { score, intentAccuracy, causalReasoning, uncertaintyCalibration },
  application: { score, tokenEfficiency, compositionalReasoning, negativeKnowledge },
  validation: { score, humanCorrelation },
  overall: number, calibration: { ece, mce } }
```

---

## Capabilities

### What Infrastructure Can Do Today
1. Build all 12 TS packages with dependency-aware caching (Turborepo)
2. Cross-compile Rust to 5 platform targets via NAPI-RS
3. Run CI on Node 18/20/22 matrix
4. Publish npm packages in dependency order with provenance
5. Deploy MCP server as Docker container with health checks
6. Collect anonymous telemetry via Cloudflare Workers
7. Gate 16 features across 3 license tiers (community/team/enterprise)
8. Abstract AI providers (Anthropic/OpenAI/Ollama) behind unified interface
9. Benchmark codebase intelligence with 4-level hierarchical evaluation
10. Visualize database schemas as interactive 3D galaxies
11. Analyze PRs autonomously with 9 analysis passes and SARIF output
12. Validate documentation commands against CLI help output
13. Generate synthetic codebases for testing
14. Run statistical Rust benchmarks with criterion

### What Infrastructure Cannot Do (Limitations)
1. **No Rust CI integration**: No `cargo clippy`, `cargo fmt`, `cargo test` in CI pipeline
2. **No multi-arch Docker**: Single architecture only (no linux/arm64 Docker image)
3. **No automated cross-publish**: npm and cargo publish are separate manual processes
4. **No SBOM generation**: No Software Bill of Materials for supply chain security
5. **No dependency scanning**: No automated vulnerability scanning (Dependabot/Snyk)
6. **No provenance attestation**: npm provenance exists but no SLSA attestation
7. **No reproducible builds**: No build hash verification or deterministic builds
8. **No performance regression CI**: No automated benchmark comparison in PRs
9. **No infrastructure-as-code**: Docker/Cloudflare configs are manual
10. **No observability stack**: No structured logging, no distributed tracing, no metrics beyond telemetry
11. **No canary/staged releases**: All-or-nothing npm publish
12. **No monorepo version management**: No Changesets or similar tool for coordinated versioning
13. **No E2E integration tests**: CI tests core/detectors/mcp only, not full pipeline
14. **No license server**: JWT validation is local-only, no revocation capability
15. **CI debt**: `continue-on-error: true` on build/test, lint disabled
16. **No Rust workspace feature flags**: No conditional compilation for optional analyzers
17. **No WASM target**: No browser-based analysis capability
18. **Missing Linux musl target**: Only gnu targets, no Alpine Linux support in CI


---

## Integration Points

| Connects To | How |
|---|---|
| **01-rust-core** | NAPI-RS bridge compiles Rust → native Node.js addon; CI builds for 5 platforms |
| **02-parsers** | Rust parsers compiled via NAPI; tree-sitter grammars linked at compile time |
| **03-detectors** | Detectors package built/tested in CI; published as `driftdetect-detectors` |
| **06-cortex** | Cortex package built/tested in CI; AI providers feed into Cortex learning |
| **07-mcp** | MCP server deployed via Docker; published as `driftdetect-mcp` |
| **08-storage** | SQLite bundled with rusqlite; drift.db/cortex.db created at runtime |
| **09-quality-gates** | Quality gates run in CI agent; SARIF output for GitHub Code Scanning |
| **10-cli** | CLI is the primary npm package; CI agent wraps CLI functionality |
| **11-ide** | LSP server and VSCode extension built in monorepo; Galaxy feeds dashboard |
| **All categories** | Licensing gates enterprise features across all subsystems |

---

## V2 Migration Status

### What Stays (Solid Foundation)
- pnpm + Turborepo monorepo structure (proven, cached, fast)
- NAPI-RS cross-compilation pipeline (template for v2)
- Cloudflare Workers telemetry (independent, no changes needed)
- CIBench benchmark framework (highly valuable, extend for v2)
- Galaxy visualization (pure presentation, stays TS/React)
- GitHub Action composite pattern (update for v2 binary distribution)
- CI Agent architecture (12 pluggable interfaces, stays TS)
- Licensing system (defines business model boundary)
- AI provider abstraction (stays TS, API calls to external services)
- Vitest for TS-side testing
- criterion for Rust benchmarks

### What Needs Major Changes
- **CI/CD**: Add Rust toolchain testing (`cargo clippy`, `cargo fmt`, `cargo test`), add performance regression detection, fix `continue-on-error` debt, re-enable lint
- **Docker**: Add multi-arch builds (linux/amd64 + linux/arm64), add Rust compilation stage or pre-built binaries, consider Alpine-based image
- **Release**: Coordinate npm + cargo publish, add Changesets for monorepo versioning, add SBOM generation
- **Native Build**: Add linux-x64-musl target, consider WASM target, add workspace feature flags
- **Build System**: Add `cargo` integration to Turborepo pipeline, add Rust workspace members (drift-cortex, drift-mcp-core, drift-patterns)

### What Gets Added (New for V2)
- Supply chain security (SBOM, dependency scanning, provenance attestation)
- Performance regression CI (benchmark comparison in PRs)
- Reproducible builds (build hash verification)
- Structured observability (logging, metrics, tracing)
- Canary/staged release pipeline
- E2E integration tests (full scan → MCP query → quality gate)
- Infrastructure-as-code (Docker, Cloudflare, GitHub Actions as code)
- License server capability (for enterprise revocation)

---

## Open Questions

1. **Cargo workspace expansion**: How many Rust crates for v2? `drift-core`, `drift-napi`, `drift-patterns`, `drift-cortex-core`, `drift-mcp-core`? Or keep it minimal?
2. **WASM target**: Should v2 support browser-based analysis via `wasm-pack`? What's the use case priority?
3. **Docker strategy**: Pre-built native binaries in Docker (faster build, larger image) vs compile Rust in Docker (slower build, smaller image)?
4. **Release orchestration**: Changesets vs custom script for coordinated npm + cargo versioning?
5. **License server**: Build a license validation server for enterprise revocation, or keep local-only?
6. **Telemetry expansion**: Add Rust-specific events (parse times, NAPI call counts, memory usage)?
7. **CI matrix expansion**: Add Rust nightly for testing? Add more Node versions?
8. **Benchmark CI**: How to handle benchmark noise in CI? Statistical comparison with confidence intervals?
9. **Monorepo vs polyrepo**: Should v2 split Rust crates into a separate repo for faster CI?
10. **Feature flags**: Cargo feature flags for optional analyzers (e.g., `features = ["cortex", "galaxy"]`)?

---

## Quality Checklist

- [x] All 14 files in category 12-infrastructure have been read (overview, build-system, ci-cd, ci-and-actions, docker, rust-build, telemetry, licensing, ai-providers, cibench, galaxy, github-action, ci-agent, scripts)
- [x] Architecture clearly described with diagram
- [x] All 14 subsystems documented with purpose, location, and key details
- [x] Key algorithms documented (native build pipeline, CI scoring, license validation, feature gating, calibration, telemetry processing)
- [x] All data models listed with fields
- [x] Capabilities honestly assessed (14 capabilities, 18 limitations)
- [x] Integration points mapped to 10 other categories
- [x] V2 migration status documented (stays, changes, additions)
- [x] Open questions identified (10 specific questions)
- [x] Cross-referenced with MASTER-RECAP sections 12, 15