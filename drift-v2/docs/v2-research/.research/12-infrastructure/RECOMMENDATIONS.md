# 12 Infrastructure — V2 Build Recommendations

> **Context**: Drift v2 is a greenfield build. These recommendations define how to BUILD the infrastructure layer from scratch using best practices, derived from the v1 recap (14 subsystems, 18 limitations) and targeted external research (IR1-IR12). The v1 codebase is treated as a requirements specification — what capabilities are needed — while these recommendations define HOW to build them right the first time.

## Summary

25 recommendations organized into 7 build phases (3 foundational decisions + 22 phased recommendations). Each defines a capability to build into the new infrastructure from day one, backed by external research from Tier 1-3 sources. Every v1 limitation is addressed. Every recommendation considers full-circle impact on the rest of the pipeline.

---

## Foundational Infrastructure Decisions

These decisions must be made BEFORE writing CI/CD pipelines. They affect every subsystem.

### FA1: Rust-Aware CI Pipeline

**Priority**: P0 (Build First)
**Effort**: Medium
**Impact**: Code quality, correctness, and safety for the entire Rust core — every other recommendation depends on a working CI pipeline
**Evidence**: IR1 (Shuttle.rs, MarkAICode, Rust Clippy)

**What to Build**:
A comprehensive Rust CI pipeline that runs on every PR and push to main. This is the single most critical infrastructure gap in v1 — zero Rust quality checks exist today.

**Pipeline stages** (run in parallel where possible):

```yaml
# Stage 1: Format Check (fastest, fail-fast)
cargo fmt --all --check

# Stage 2: Lint (parallel with Stage 1)
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Stage 3: Test (after format + lint pass)
cargo nextest run --workspace --profile ci

# Stage 4: Dependency Audit (parallel with Stage 3)
cargo deny check
cargo audit
```

**Clippy configuration** (workspace `Cargo.toml`):
```toml
[workspace.lints.clippy]
correctness = { level = "deny" }
suspicious = { level = "deny" }
perf = { level = "deny" }
style = { level = "warn" }
complexity = { level = "warn" }
unwrap_used = { level = "deny" }
panic = { level = "deny" }
expect_used = { level = "warn" }
```

**Test configuration** (`.config/nextest.toml`):
```toml
[profile.ci]
retries = 2
fail-fast = false
slow-timeout = { period = "60s", terminate-after = 2 }
status-level = "fail"
final-status-level = "flaky"

[profile.ci.junit]
path = "target/nextest/ci/junit.xml"
```

**sccache integration**: Use `sccache` with GitHub Actions cache backend to cache Rust compilation across CI runs. Expected 40-60% reduction in Rust build times after first run.

**Why this matters full-circle**: Without Rust CI, bugs in the analysis engine (parsers, call graph, coupling) ship silently. A single incorrect tree-sitter query or off-by-one in the resolution algorithm can produce wrong results for every user. Clippy catches these classes of bugs. Nextest catches logic errors. Fmt ensures consistent code style across contributors.

**V1 limitations addressed**: #1 (no Rust CI), #15 (continue-on-error debt, lint disabled)

---

### FA2: Supply Chain Security Pipeline

**Priority**: P0 (Build First)
**Effort**: Medium
**Impact**: Regulatory compliance (EU CRA by Dec 2027), vulnerability prevention, license compliance — affects every dependency in both Rust and TypeScript
**Evidence**: IR3 (SafeDep, Cloudyrion, OpenSSF), IR4 (GitHub SLSA), IR12 (RustSec, cargo-deny, MarkAICode)

**What to Build**:
A comprehensive supply chain security pipeline covering both Rust and TypeScript dependencies.

**4 pillars**:

1. **Dependency Auditing** (every PR):
   ```yaml
   # Rust
   cargo deny check advisories
   cargo deny check licenses
   cargo deny check bans
   cargo deny check sources
   cargo audit
   # TypeScript
   pnpm audit --audit-level=high
   ```

2. **SBOM Generation** (every release):
   ```yaml
   cargo cyclonedx --format json --output-file drift-core-sbom.cdx.json
   npx @cyclonedx/cyclonedx-npm --output-file drift-sbom.cdx.json
   ```

3. **SLSA Provenance** (every release):
   ```yaml
   npm publish --provenance
   docker buildx build --provenance=true --sbom=true
   - uses: actions/attest-build-provenance@v2
   ```

4. **Automated Dependency Updates** (`.github/dependabot.yml`):
   ```yaml
   updates:
     - package-ecosystem: "cargo"
       schedule: { interval: "weekly" }
     - package-ecosystem: "npm"
       schedule: { interval: "weekly" }
     - package-ecosystem: "github-actions"
       schedule: { interval: "weekly" }
   ```

**`deny.toml` configuration**:
```toml
[licenses]
allow = ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause",
         "ISC", "Zlib", "Unicode-DFS-2016", "OpenSSL"]
deny = ["AGPL-3.0", "GPL-3.0", "SSPL-1.0"]
confidence-threshold = 0.8

[bans]
multiple-versions = "warn"
wildcards = "deny"

[advisories]
vulnerability = "deny"
unmaintained = "warn"
yanked = "deny"
notice = "warn"

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-git = []
```

**Why this matters full-circle**: EU CRA compliance is a hard deadline (Dec 2027). Non-compliance risks EUR 15M fines. Beyond compliance, dependency vulnerabilities in tree-sitter grammars, rusqlite, or any transitive dependency could compromise every codebase Drift analyzes. Supply chain security is not optional for an enterprise tool that runs inside customer CI pipelines.

**V1 limitations addressed**: #4 (no SBOM), #5 (no dependency scanning), #6 (no provenance attestation)

---

### FA3: Cargo Workspace Expansion with Feature Flags

**Priority**: P0 (Build First)
**Effort**: Medium
**Impact**: Compilation speed, crate boundary clarity, conditional compilation for optional subsystems
**Evidence**: IR11 (Cargo Book Features Reference, VPodK workspace compilation)

**What to Build**:
Expand the Rust workspace from v1's 2 crates (`drift-core`, `drift-napi`) to 5-6 crates with feature flags for conditional compilation.

**Workspace structure** (`Cargo.toml`):
```toml
[workspace]
resolver = "2"
members = [
    "crates/drift-core",
    "crates/drift-analysis",
    "crates/drift-storage",
    "crates/drift-napi",
    "crates/drift-bench",
]

[workspace.package]
edition = "2021"
rust-version = "1.75"
license = "MIT"

[workspace.dependencies]
tree-sitter = "0.24"
rusqlite = { version = "0.32", features = ["bundled"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "2"
tracing = "0.1"
```

**Feature flags** (in `drift-core/Cargo.toml`):
```toml
[features]
default = ["cortex", "mcp"]
cortex = ["dep:drift-cortex-core"]
mcp = []
wasm = []
benchmark = ["dep:criterion"]
lang-python = ["dep:tree-sitter-python"]
lang-java = ["dep:tree-sitter-java"]
lang-rust = ["dep:tree-sitter-rust"]
full = ["cortex", "mcp", "lang-python", "lang-java", "lang-rust"]
```

**Crate splitting rationale**:
- `drift-core` + `drift-analysis`: Separates parsing (fast, stateless) from analysis (slower, stateful). Enables parallel compilation and independent testing.
- `drift-storage` extracted: Storage layer changes independently from analysis logic. Schema migrations don't require recompiling parsers.
- `drift-bench` isolated: Benchmark dependencies (criterion) don't pollute production builds.

**Why this matters full-circle**: Workspace structure determines compilation parallelism — 5 independent crates compile faster than 1 monolith. Feature flags enable lightweight deployments (CLI without MCP, WASM without filesystem). Every downstream recommendation (R4 NAPI-RS, R7 zigbuild, R8 Docker) depends on knowing the crate boundaries. Getting this wrong means restructuring later, which invalidates CI caching, breaks cross-compilation targets, and forces NAPI binding rewrites.

**V1 limitations addressed**: #16 (no Rust workspace feature flags)

---

## Phase 1: Supply Chain Security

### R1: Dependency Scanning with cargo-deny

**Priority**: P0
**Effort**: Low
**Impact**: License compliance, vulnerability detection, supply chain integrity

**What to Build**:
Add `cargo-deny` as a blocking CI check. Provides 4 categories of dependency governance in a single tool.

**Configuration** (`deny.toml`):
```toml
[licenses]
allow = [
  "MIT", "Apache-2.0", "Apache-2.0 WITH LLVM-exception",
  "BSD-2-Clause", "BSD-3-Clause", "ISC", "Zlib", "Unicode-DFS-2016",
  "BSL-1.0", "CC0-1.0", "OpenSSL",
]
deny = ["AGPL-3.0", "GPL-3.0", "SSPL-1.0"]
copyleft = "deny"
confidence-threshold = 0.8

[bans]
multiple-versions = "warn"
wildcards = "deny"

[advisories]
vulnerability = "deny"
unmaintained = "warn"
yanked = "deny"

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
```

**CI integration**: `cargo deny check --all` as a blocking step in the Rust CI job group.

**What this catches**: Incompatible licenses, known vulnerabilities (RustSec), yanked versions, non-crates.io sources, dependency bloat.

**Evidence**: cargo-deny (IR12), RustSec Advisory Database (IR12)

---

### R2: SBOM Generation for EU CRA Compliance

**Priority**: P0
**Effort**: Low
**Impact**: Regulatory compliance — EU CRA mandates SBOMs by December 2027

**What to Build**:
Automated SBOM generation in CI for every release, covering both Rust and npm dependencies.

```yaml
- name: Generate Rust SBOM
  run: cargo cyclonedx --format json --output-file drift-rust-sbom.cdx.json
- name: Generate npm SBOM
  run: npx @cyclonedx/cyclonedx-npm --output-file drift-npm-sbom.cdx.json
```

**Why CycloneDX over SPDX**: Better tooling for both Rust and npm ecosystems, explicitly accepted by EU CRA framework.

**Evidence**: SafeDep EU CRA guide (IR3), OpenSSF SBOM guidance (IR3)

---

### R3: SLSA Level 3 Provenance Attestation

**Priority**: P1
**Effort**: Low
**Impact**: Supply chain integrity — proves who built the artifact, from what source

**What to Build**:
Cryptographically verifiable provenance for all published artifacts using GitHub's native attestation support.

```yaml
- name: Publish with provenance
  run: pnpm publish --provenance --access public
- name: Attest build provenance
  uses: actions/attest-build-provenance@v2
  with:
    subject-path: 'crates/drift-napi/artifacts/*.node'
- name: Build Docker with attestation
  uses: docker/build-push-action@v6
  with:
    push: true
    provenance: true
    sbom: true
```

**What this prevents**: Dependency confusion attacks, build server compromise, artifact tampering.

**Evidence**: GitHub SLSA 3 compliance guide (IR4)

---

## Phase 2: Build System & Compilation

### R4: NAPI-RS v3 Migration

**Priority**: P0
**Effort**: Medium
**Impact**: WebAssembly support, safer APIs, simplified cross-compilation

**What to Build**:
Migrate from NAPI-RS v2 to v3 for the Rust-to-Node.js bridge.

**Key benefits**:
1. **WebAssembly target**: Compile to `wasm32-wasip1-threads` with almost no code changes
2. **Lifetime safety**: Prevents `JsObject` from escaping scope — critical for long-running MCP server
3. **ThreadsafeFunction redesign**: Simplifies async bridge between Rust analysis and Node.js event loop
4. **Simplified cross-compilation**: No longer requires large Docker images for Linux targets

**Migration steps**:
1. Update `napi` and `napi-derive` to v3
2. Update `package.json` napi configuration to explicitly list targets
3. Replace deprecated `ThreadsafeFunction` usage with new API
4. Add `Reference` API for struct lifetime management
5. Add `wasm32-wasip1-threads` to target list (optional)

**Evidence**: NAPI-RS v3 announcement (IR2), NAPI-RS cross-build docs (IR2)

---

### R5: Turborepo Remote Caching

**Priority**: P1
**Effort**: Low
**Impact**: 40-70% CI build time reduction for TypeScript packages

**What to Build**:
Enable Turborepo remote caching so CI runs share build artifacts across all PRs and branches.

**Options** (in order of recommendation):
1. **GitHub Actions cache** via `robobat/setup-turbo-cache` — zero external dependencies
2. **Self-hosted S3 backend** — more control, works with any cloud provider
3. **Vercel Remote Cache** — zero setup but requires Vercel account

```yaml
- name: Build affected packages
  run: pnpm turbo build --filter='...[HEAD^1]'
```

**Evidence**: Turborepo remote caching (IR10), WarpBuild monorepo guide (IR10)

---

### R6: Rust Compilation Caching with sccache

**Priority**: P1
**Effort**: Low
**Impact**: 60-80% Rust compilation time reduction in CI

**What to Build**:
Add `sccache` with GitHub Actions cache backend for cross-run Rust compilation caching.

```yaml
- name: Setup sccache
  uses: mozilla-actions/sccache-action@v0.0.6
  with:
    version: "v0.8.2"
- name: Configure Rust to use sccache
  run: |
    echo "SCCACHE_GHA_ENABLED=true" >> $GITHUB_ENV
    echo "RUSTC_WRAPPER=sccache" >> $GITHUB_ENV
```

**Why sccache over actions/cache on target/**: `actions/cache` caches the entire `target/` directory (2-5GB). `sccache` caches individual compilation units, is more granular, and handles cache invalidation correctly.

**Evidence**: Shuttle.rs CI best practices (IR1)

---

## Phase 3: Cross-Compilation & Docker

### R7: Cross-Compilation with cargo-zigbuild

**Priority**: P0
**Effort**: Medium
**Impact**: 5-10x faster Docker builds, musl support, smaller images

**What to Build**:
Replace Docker-based Rust compilation with host-side cross-compilation using `cargo-zigbuild`.

**Target matrix** (7 platforms):
| Host | Target | npm Package | Method |
|------|--------|-------------|--------|
| macOS | `x86_64-apple-darwin` | `darwin-x64` | Native |
| macOS | `aarch64-apple-darwin` | `darwin-arm64` | Native |
| Windows | `x86_64-pc-windows-msvc` | `win32-x64-msvc` | Native |
| Linux | `x86_64-unknown-linux-gnu` | `linux-x64-gnu` | NAPI-cross |
| Linux | `aarch64-unknown-linux-gnu` | `linux-arm64-gnu` | NAPI-cross |
| Linux | `x86_64-unknown-linux-musl` | `linux-x64-musl` | zigbuild |
| Linux | `aarch64-unknown-linux-musl` | `linux-arm64-musl` | zigbuild |

**New musl targets**: V1 only has gnu targets. Adding musl enables Alpine Linux support (smaller Docker images, common in enterprise Kubernetes).

**Why zigbuild**: Bundles a complete C toolchain targeting musl libc. No Docker, no QEMU emulation. Drift's Rust dependencies (`rusqlite` bundled SQLite, `tree-sitter` compiled from source) are fully compatible.

**Evidence**: cargo-zigbuild case study (IR5), Cross-compilation in Rust (IR5)

---

### R8: Multi-Architecture Docker with Pre-Built Binaries

**Priority**: P1
**Effort**: Medium
**Impact**: Enterprise Kubernetes deployments on ARM64 (AWS Graviton, Apple Silicon)

**What to Build**:
Multi-arch Docker images using pre-built binaries from R7 instead of compiling Rust inside Docker.

```dockerfile
FROM node:20-alpine AS base
RUN apk add --no-cache tini
RUN adduser -D -u 1001 drift

FROM base AS production
WORKDIR /app
COPY --chown=drift:drift package.json pnpm-lock.yaml ./
COPY --chown=drift:drift packages/ ./packages/
COPY --chown=drift:drift crates/drift-napi/npm/ ./crates/drift-napi/npm/
RUN corepack enable pnpm && pnpm install --prod --frozen-lockfile

USER drift
EXPOSE 3000
HEALTHCHECK CMD wget -qO- http://localhost:3000/health || exit 1
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "packages/mcp/dist/server.js"]
```

```yaml
- name: Build and push multi-arch
  uses: docker/build-push-action@v6
  with:
    platforms: linux/amd64,linux/arm64
    push: true
    provenance: true
    sbom: true
```

**Key differences from v1**: Alpine-based (5x smaller), pre-built binaries (5-10x faster builds), multi-arch, `tini` init process, provenance attestation.

**Evidence**: Faster multi-arch containers (IR5)

---

## Phase 4: Release Orchestration

### R9: Changesets for npm Version Management

**Priority**: P1
**Effort**: Low
**Impact**: Coordinated npm releases across 12 packages with changelogs

**What to Build**:
Use Changesets for npm monorepo versioning (used by Turborepo, Radix, Chakra UI).

```yaml
- name: Create Release PR or Publish
  uses: changesets/action@v1
  with:
    publish: pnpm changeset publish
    version: pnpm changeset version
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
```

**Internal dependency updates**: When `driftdetect-core` bumps, Changesets automatically bumps all dependent packages.

**Evidence**: Changesets (IR6)

---

### R10: release-plz for Cargo Publishing

**Priority**: P1
**Effort**: Low
**Impact**: Automated Rust crate releases with changelogs

**What to Build**:
Use `release-plz` for Cargo workspace versioning and publishing — the Rust-native equivalent of Changesets.

```yaml
- name: Run release-plz
  uses: MarcoIeni/release-plz-action@v0.5
  with:
    command: release-pr
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}
```

**Version coordination**: Shared `VERSION` file in workspace root as single source of truth. Individual crate/package versions can diverge for independent releases.

**Evidence**: release-plz referenced in Shuttle.rs CI guide (IR1), Sampo and Mono evaluated but less mature (IR6)

---

### R11: Coordinated Cross-Registry Release Pipeline

**Priority**: P1
**Effort**: Medium
**Impact**: Eliminates manual release coordination between npm and cargo

**What to Build**:
A release orchestration workflow that coordinates npm and cargo publishing in the correct order.

**Release order**:
```
1. Rust crates (cargo):  drift-core -> drift-analysis -> drift-storage -> drift-napi
2. Native binaries:      Build for 7 platforms -> upload artifacts
3. npm packages:         core -> detectors -> cortex -> mcp -> cli
4. Docker image:         Build with pre-built binaries -> push multi-arch
5. GitHub Release:       Create release with SBOMs, changelogs, binaries
```

**Trigger**: Manual dispatch with version bump type (patch/minor/major). Automated for patch releases via Changesets + release-plz PRs.

**Rollback**: If any step fails, the workflow stops. npm packages can be unpublished within 72 hours. Cargo crates can only be yanked — so cargo publishes first in the pipeline.

---

## Phase 5: Testing & Performance

### R12: cargo-nextest for Rust Test Execution

**Priority**: P0
**Effort**: Low
**Impact**: 3x faster Rust test execution in CI, better failure output

**What to Build**:
Replace implicit `cargo test` with `cargo-nextest` for all Rust test execution.

```yaml
- name: Install nextest
  uses: taiki-e/install-action@nextest
- name: Run tests
  run: cargo nextest run --all-features --profile ci
```

**Nextest profile** (`.config/nextest.toml`):
```toml
[profile.ci]
retries = 2
fail-fast = false
slow-timeout = { period = "30s", terminate-after = 2 }
status-level = "fail"
final-status-level = "flaky"

[profile.ci.junit]
path = "target/nextest/ci/junit.xml"
```

**Why nextest over cargo test**: Parallel binary execution (3x faster), JUnit XML output, built-in flaky retry, per-test isolation, `--partition` for CI runner splitting.

**Evidence**: cargo-nextest (IR8), Rust Project Primer (IR8)

---

### R13: Performance Regression Detection in CI

**Priority**: P1
**Effort**: Medium
**Impact**: Catches performance regressions before merge

**What to Build**:
Automated benchmark comparison in PRs using criterion baselines.

**Tier 1 — Free (criterion-compare)**:
```yaml
- name: Run benchmarks
  run: cargo bench --bench parsing --bench full_pipeline -- --save-baseline pr
- name: Compare with main
  uses: boa-dev/criterion-compare-action@v3
  with:
    branchName: main
    cwd: crates/drift-core
```

**Tier 2 — Precise (CodSpeed, future)**:
```yaml
- name: Run CodSpeed benchmarks
  uses: CodSpeedHQ/action@v3
  with:
    run: cargo codspeed bench
```

**Statistical gating**: GitHub-hosted runners have 2.66% coefficient of variation. Minimum reliable gate on hosted runners is 10%. CodSpeed enables 5% detection with <1% variance.

**Benchmark targets**: `parsing` (per-language), `full_pipeline` (end-to-end), `detection` (pattern throughput), `call_graph` (graph building).

**Evidence**: CodSpeed CI noise analysis (IR4), CodSpeed Rust benchmarks (IR7)

---

### R14: E2E Integration Test Suite

**Priority**: P1
**Effort**: Medium
**Impact**: Validates the full pipeline — scan -> index -> MCP query -> quality gate

**What to Build**:
End-to-end tests that exercise the complete Drift pipeline against synthetic codebases.

**Test scenarios**:
1. **Full scan**: Scan synthetic codebase -> verify patterns -> verify call graph -> verify storage
2. **MCP query**: Start MCP server -> send `drift_context` request -> verify response
3. **Quality gate**: Run `drift gate --ci` -> verify pass/fail based on known violations
4. **Incremental scan**: Modify files -> re-scan -> verify only changed files re-analyzed

**Synthetic codebases**: Reuse v1's `generate-large-codebase.ts` script, extended with known patterns, violations, and call graph structures as ground truth.

**CI integration**: Separate CI job that depends on both Rust and TS build jobs completing.

**Why this matters**: V1 tests core/detectors/mcp individually but never tests the full pipeline. Integration bugs (NAPI serialization mismatches, storage schema drift, MCP response format changes) are only caught manually.

---

## Phase 6: Operational Infrastructure

### R15: Structured Observability

**Priority**: P1
**Effort**: Medium
**Impact**: Debugging, performance monitoring, operational visibility

**What to Build**:
Structured logging and tracing for both Rust core and TypeScript orchestration layer.

**Rust observability** (using `tracing` crate):
```rust
use tracing::{info, instrument, span, Level};

#[instrument(skip(files), fields(file_count = files.len()))]
pub fn scan_directory(root: &Path, files: &[PathBuf]) -> Result<ScanResult> {
    let span = span!(Level::INFO, "scan", root = %root.display());
    let _enter = span.enter();
    info!(file_count = files.len(), "starting scan");
    // ... scan logic
}
```

**TypeScript observability** (using `pino`):
```typescript
import pino from 'pino';
const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
  transport: process.env.NODE_ENV === 'development'
    ? { target: 'pino-pretty' } : undefined,
});
logger.info({ fileCount: files.length, root }, 'starting scan');
```

**Key metrics**: Scan duration, parser throughput, pattern detection counts, storage query latency, MCP request/response latency, memory usage.

**Why this matters**: V1 has minimal logging (`VERBOSE=true` flag). Tracing spans enable distributed tracing across the Rust-to-NAPI-to-TypeScript boundary.

**V1 limitations addressed**: #10 (no observability stack)

---

### R16: Telemetry Expansion

**Priority**: P2
**Effort**: Low
**Impact**: Product analytics for understanding real-world usage patterns

**What to Build**:
Expand v1's Cloudflare Worker telemetry to include Rust-side events.

**New events** (anonymous, opt-in):
- `rust.scan.completed`: Duration, file count, language distribution
- `rust.parse.error`: Parser failures by language
- `rust.analysis.completed`: Call graph size, coupling metrics, boundary count
- `napi.bridge.latency`: Time spent crossing the Rust-to-Node.js boundary

**Privacy**: All events anonymous, opt-in via `drift config set telemetry true`, disabled by default.

---

### R17: Licensing System Enhancement

**Priority**: P2
**Effort**: Medium
**Impact**: Enterprise feature gating with server-side validation

**What to Build**:
Enhance v1's JWT-based local license validation with optional server-side validation for enterprise.

**Architecture**:
- **Local validation** (default): JWT signature verification, expiry check, feature flag extraction — works offline
- **Server validation** (enterprise): Periodic check-in for seat counting, revocation, usage analytics
- **Grace period**: 7-day grace period if server unreachable

**License server**: Cloudflare Worker (same infrastructure as telemetry). Validates JWT, checks revocation list, returns OK/DENY.

**Evidence**: V1 license system (RECAP subsystem 9), IR9 enterprise licensing patterns

**V1 limitations addressed**: #14 (no license server)

---

### R18: CI Agent Enhancement

**Priority**: P1
**Effort**: Medium
**Impact**: Rust-first CI agent with SARIF output and incremental analysis

**What to Build**:
Enhance v1's CI agent to leverage the Rust core for faster, more accurate CI analysis.

**Key improvements**:
1. **Rust-first analysis**: CI agent calls Rust core directly via NAPI — no TypeScript overhead for the hot path
2. **SARIF output**: Generate SARIF for GitHub Code Scanning integration
3. **Incremental analysis**: Only analyze changed files (git diff) — 10-100x faster for large repos
4. **Parallel file processing**: Use Rust's rayon for parallel file parsing

```yaml
- name: Run Drift analysis
  run: drift ci --format sarif --output drift-results.sarif
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: drift-results.sarif
```

---

### R19: CIBench Integration with CI

**Priority**: P2
**Effort**: Low
**Impact**: Automated benchmark tracking across releases

**What to Build**:
Integrate CIBench (v1's benchmark infrastructure) with the CI pipeline.

```yaml
- name: Run CIBench suite
  run: drift bench --suite full --output cibench-results.json
- name: Upload results
  uses: actions/upload-artifact@v4
  with:
    name: cibench-${{ github.sha }}
    path: cibench-results.json
```

**Trend tracking**: Store results as CI artifacts. Dashboard via GitHub Pages or Cloudflare Pages.

---

## Phase 7: Ecosystem & Distribution

### R20: GitHub Action v2

**Priority**: P1
**Effort**: Low
**Impact**: User adoption — the primary way users integrate Drift into their CI

**What to Build**:
Update the composite GitHub Action for v2's split MCP server architecture and Rust-first execution.

**Changes from v1**:
1. Install `driftdetect` (CLI) instead of `driftdetect-ci` — the CLI is the primary entry point in v2
2. Support both `drift-analysis` and `drift-memory` server configurations
3. Add `drift gate --ci --format sarif` output for GitHub Code Scanning integration
4. Add artifact upload for SARIF results (enables GitHub Security tab integration)
5. Add caching for `.drift/` directory (scan results, pattern database)

**New inputs**:
- `memory-enabled` (boolean, default false) — whether to include Cortex memory analysis
- `sarif-upload` (boolean, default true) — upload SARIF to GitHub Code Scanning
- `fail-threshold` (number, default 70) — minimum drift score to pass

**New outputs**:
- `sarif-file` — path to generated SARIF file
- `patterns-discovered` — number of patterns found
- `violations-count` — number of violations

---

### R21: Pre-Built Binary Distribution

**Priority**: P1
**Effort**: Low
**Impact**: Installation speed — users don't need Rust toolchain

**What to Build**:
Distribute pre-built native binaries via npm's `optionalDependencies` mechanism.

**Package structure**:
```
@drift/native                    # Main package (detects platform)
@drift/native-darwin-x64         # macOS Intel
@drift/native-darwin-arm64       # macOS Apple Silicon
@drift/native-win32-x64-msvc     # Windows x64
@drift/native-linux-x64-gnu      # Linux x64 (glibc)
@drift/native-linux-arm64-gnu    # Linux ARM64 (glibc)
@drift/native-linux-x64-musl     # Linux x64 (musl/Alpine) — NEW
@drift/native-linux-arm64-musl   # Linux ARM64 (musl/Alpine) — NEW
```

**Fallback chain**: Native binary -> WASM (if available) -> TypeScript-only mode.

**V1 limitations addressed**: #17 (no WASM target), #18 (missing Linux musl target)

---

### R22: Developer Experience Infrastructure

**Priority**: P2
**Effort**: Low
**Impact**: Contributor onboarding, development velocity

**What to Build**:
Development environment setup and contributor tooling.

**`drift setup-dev` command**:
1. Verify prerequisites (Node.js >= 18, pnpm >= 8, Rust stable)
2. Install workspace dependencies (`pnpm install`)
3. Build Rust crates (`cargo build`)
4. Run initial scan on the Drift codebase itself (dogfooding)
5. Verify NAPI bridge works (`drift-native version`)

**Pre-commit hooks** (via `husky` + `lint-staged`):
```json
{
  "*.rs": ["cargo fmt --check"],
  "*.ts": ["eslint --fix", "prettier --write"],
  "*.md": ["prettier --write"]
}
```

**VS Code workspace settings** (`.vscode/settings.json`):
```json
{
  "rust-analyzer.check.command": "clippy",
  "rust-analyzer.check.allTargets": true,
  "editor.formatOnSave": true,
  "[rust]": { "editor.defaultFormatter": "rust-lang.rust-analyzer" },
  "[typescript]": { "editor.defaultFormatter": "esbenp.prettier-vscode" }
}
```

**Justfile** (task runner):
```just
build: build-rust build-ts
build-rust:
  cargo build --workspace
build-ts:
  pnpm turbo build

check: check-rust check-ts
check-rust:
  cargo clippy --all-targets --all-features -- -D warnings
  cargo fmt --check
  cargo nextest run --all-features
check-ts:
  pnpm turbo lint test

bench:
  cargo bench --bench parsing --bench full_pipeline
```

---

## Summary Table

| # | Recommendation | Priority | Phase | Evidence |
|---|---------------|----------|-------|----------|
| FA1 | Rust CI as blocking gate (clippy + fmt + nextest) | P0 | Foundation | IR1, IR8 |
| FA2 | Supply chain security pipeline (cargo-deny + SBOM + SLSA) | P0 | Foundation | IR3, IR4, IR12 |
| FA3 | Cargo workspace expansion (5-6 crates + feature flags) | P0 | Foundation | IR11 |
| R1 | Dependency scanning with cargo-deny | P0 | Supply Chain | IR12 |
| R2 | SBOM generation for EU CRA compliance | P0 | Supply Chain | IR3 |
| R3 | SLSA Level 3 provenance attestation | P1 | Supply Chain | IR4 |
| R4 | NAPI-RS v3 migration (WebAssembly + safety) | P0 | Build System | IR2 |
| R5 | Turborepo remote caching | P1 | Build System | IR10 |
| R6 | Rust compilation caching with sccache | P1 | Build System | IR1 |
| R7 | Cross-compilation with cargo-zigbuild | P0 | Cross-Compilation | IR5 |
| R8 | Multi-architecture Docker with pre-built binaries | P1 | Cross-Compilation | IR5 |
| R9 | Changesets for npm version management | P1 | Release | IR6 |
| R10 | release-plz for Cargo publishing | P1 | Release | IR1, IR6 |
| R11 | Coordinated cross-registry release pipeline | P1 | Release | IR6 |
| R12 | cargo-nextest for Rust test execution | P0 | Testing | IR8 |
| R13 | Performance regression detection in CI | P1 | Testing | IR4, IR7 |
| R14 | E2E integration test suite | P1 | Testing | RECAP |
| R15 | Structured observability (tracing + metrics) | P1 | Operations | RECAP |
| R16 | Telemetry expansion (Rust events) | P2 | Operations | RECAP |
| R17 | Licensing system enhancement (server validation) | P2 | Operations | IR9 |
| R18 | CI agent enhancement (Rust-first, SARIF, incremental) | P1 | Operations | RECAP |
| R19 | CIBench integration with CI | P2 | Operations | RECAP |
| R20 | GitHub Action v2 | P1 | Ecosystem | RECAP |
| R21 | Pre-built binary distribution (+ musl targets) | P1 | Ecosystem | IR5, IR2 |
| R22 | Developer experience infrastructure | P2 | Ecosystem | RECAP |

---

## Build Order

```
Phase 0 - Foundations (before code):
  FA1 (Rust CI) + FA2 (Supply chain) + FA3 (Workspace expansion)
  Duration: 1 week
  Deliverables: CI pipeline, workspace structure, clippy config, deny.toml

Phase 1 - Supply Chain Security (parallel with Phase 2):
  R1 (cargo-deny) + R2 (SBOM) + R3 (SLSA)
  Duration: 1 week
  Deliverables: deny.toml, SBOM generation, provenance attestation

Phase 2 - Build System (parallel with Phase 1):
  R4 (NAPI-RS v3) + R5 (Turborepo cache) + R6 (sccache)
  Duration: 2-3 weeks
  Deliverables: NAPI-RS v3 migration, remote caching, compilation caching

Phase 3 - Cross-Compilation & Docker:
  R7 (zigbuild) + R8 (Docker multi-arch)
  Duration: 2 weeks
  Dependencies: R4 (NAPI-RS v3 for target list)
  Deliverables: 7-platform cross-compilation, multi-arch Docker images

Phase 4 - Release Orchestration:
  R9 (Changesets) + R10 (release-plz) + R11 (cross-registry pipeline)
  Duration: 2 weeks
  Dependencies: Phase 3 (binaries to publish)
  Deliverables: Automated npm + cargo + Docker release pipeline

Phase 5 - Testing & Performance:
  R12 (nextest) + R13 (perf regression) + R14 (E2E tests)
  Duration: 2-3 weeks
  Dependencies: Phase 0 (CI pipeline), Phase 2 (build system)
  Deliverables: Fast test execution, benchmark gating, E2E test suite

Phase 6 - Operational Infrastructure:
  R15 (observability) + R16 (telemetry) + R17 (licensing) + R18 (CI agent) + R19 (CIBench)
  Duration: 3-4 weeks
  Dependencies: Phases 1-5
  Deliverables: Structured logging, telemetry, license server, enhanced CI agent

Phase 7 - Ecosystem & Distribution:
  R20 (GitHub Action) + R21 (pre-built binaries) + R22 (developer experience)
  Duration: 2-3 weeks
  Dependencies: Phase 3 (binaries), Phase 4 (release pipeline)
  Deliverables: GitHub Action v2, binary distribution, contributor infrastructure
```

---

## Dependency Graph

```
FA1 (Rust CI) ----------> R1 (cargo-deny) --> R2 (SBOM) --> R3 (SLSA)
              ----------> R12 (nextest)
              ----------> R13 (Perf regression)

FA2 (Supply chain) -----> R5 (Turborepo cache)
                    ----> R6 (sccache)

FA3 (Workspace) --------> R4 (NAPI-RS v3) --> R7 (zigbuild) --> R8 (Docker)
                                                             --> R21 (Binaries)

R12 (nextest) ----------> R14 (E2E tests)
R13 (Perf regression) --> R19 (CIBench CI)

R7 (zigbuild) ----------> R8 (Docker) --> R20 (GitHub Action)
R8 (Docker) ------------> R11 (Cross-registry release)
R9 (Changesets) --------> R11 (Cross-registry release)
R10 (release-plz) ------> R11 (Cross-registry release)

R15 (Observability) ----> R18 (CI agent enhancement)
R18 (CI agent) ---------> R20 (GitHub Action)
```

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| NAPI-RS v3 migration breaks existing bindings | Medium | High | Migrate incrementally. Keep v2 fallback. |
| cargo-zigbuild fails for tree-sitter C compilation | Low | High | Test zigbuild with all 10 grammars early. Fallback: `cross-rs`. |
| Changesets doesn't handle cargo versioning | Low | Medium | Use release-plz for cargo side. Shared `VERSION` file. |
| CodSpeed pricing doesn't fit budget | Medium | Low | Start with free criterion-compare. CodSpeed is optional. |
| E2E test corpus maintenance burden | Medium | Medium | Generate corpus programmatically. Pin expected results. |
| License server adds single point of failure | Low | High | 7-day grace period. Cloudflare Workers (99.99% SLA). |
| Reproducible builds fail due to non-deterministic deps | Medium | Medium | Pin versions via `Cargo.lock`. Use `--locked` flag. |
| Canary releases confuse users | Low | Low | Clear docs. Canary tag is opt-in only. |
| GitHub-hosted runner benchmark noise | High | Medium | Use 10% regression threshold minimum. |
| SBOM tooling gaps between Rust and npm | Low | Medium | Use CycloneDX for both ecosystems. |

---

## V1 Limitation Resolution Map

Every limitation identified in the RECAP is addressed:

| # | V1 Limitation | Resolution | Recommendation |
|---|--------------|------------|----------------|
| 1 | No Rust CI integration | clippy + fmt + nextest as blocking gates | FA1, R12 |
| 2 | No multi-arch Docker | Pre-built binaries + multi-arch manifest | R7, R8 |
| 3 | No automated cross-publish | Changesets + release-plz + orchestration | R9, R10, R11 |
| 4 | No SBOM generation | CycloneDX SBOMs for Rust and npm | R2 |
| 5 | No dependency scanning | cargo-deny + cargo-audit + pnpm audit | R1, FA2 |
| 6 | No provenance attestation | SLSA Level 3 via GitHub attestation | R3 |
| 7 | No reproducible builds | Content-hash-based caching + provenance | R3, R6 |
| 8 | No performance regression CI | criterion-compare + statistical gating | R13 |
| 9 | No infrastructure-as-code | Docker, CI, and configs all in repo | R8, FA2 |
| 10 | No observability stack | tracing + pino structured logging | R15 |
| 11 | No canary/staged releases | Changesets version PRs + manual approval | R9, R11 |
| 12 | No cross-registry coordination | Orchestrated release pipeline | R11 |
| 13 | No E2E integration tests | Full pipeline test suite | R14 |
| 14 | No license server | Optional server-side validation for enterprise | R17 |
| 15 | CI debt (continue-on-error, lint disabled) | Remove debt, all checks blocking | FA1, FA2 |
| 16 | No Rust workspace feature flags | Cargo features for conditional compilation | FA3 |
| 17 | No WASM target | NAPI-RS v3 WebAssembly support | R4 |
| 18 | Missing Linux musl target | cargo-zigbuild musl cross-compilation | R7, R21 |

---

## Quality Checklist

- [x] All 18 limitations from RECAP resolved in recommendations
- [x] All 12 research topics (IR1-IR12) referenced in at least one recommendation
- [x] Every recommendation framed as "build new" not "migrate/port"
- [x] Every recommendation has priority level (P0/P1/P2)
- [x] Every recommendation cites evidence (research section or recap)
- [x] Build order defined with 7 phases and duration estimates
- [x] Dependency graph shows inter-recommendation relationships
- [x] Risk assessment with likelihood, impact, and mitigation for 10 risks
- [x] V1 limitation resolution map traces every gap to its fix
- [x] No feature deferred to "add later" — everything built into the right phase
- [x] Cross-referenced with MASTER-RECOMMENDATIONS infrastructure section (IN1-IN6)
- [x] Traceability: every RECAP limitation maps to at least one recommendation
- [x] Practical: specific tool names, configurations, and CI YAML provided
