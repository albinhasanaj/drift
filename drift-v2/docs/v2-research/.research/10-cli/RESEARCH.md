# 10 CLI — External Research Encyclopedia

> **Purpose**: Curated encyclopedia of external research findings from authoritative sources.
> **Methodology**: Tier 1 (authoritative specs/papers), Tier 2 (industry expert), Tier 3 (community validated).
> **Date**: February 2026

---

## 1. CLI Design Principles & Guidelines

### 1.1 Command Line Interface Guidelines (clig.dev)

**Source**: https://clig.dev/
**Tier**: 2 (Industry expert — Docker Compose co-creators, Squarespace engineers)

**Key Findings** (rephrased for compliance):
1. Modern CLI is human-first — a text-based UI for tools, systems, and platforms.
2. Core principles: discoverable, robust, empathetic errors, composable.
3. Output: stdout for data, stderr for messaging. Disable color when piped. Support `NO_COLOR`.
4. Error handling: rewrite for humans, actionable suggestions, error codes, non-zero exit codes.
5. Config hierarchy: flags > env vars > project config > user config > system config.

**Applicability**: Adopt config hierarchy. Support `NO_COLOR`. Structured error codes. stdout/stderr separation.

### 1.2 12 Factor CLI Apps (Jeff Dickey, oclif creator)

**Source**: https://medium.com/@jdxcode/12-factor-cli-apps-dd3c227a0e46
**Tier**: 2 (Industry expert — Heroku CLI architect)

**Key Findings** (rephrased for compliance):
1. Great help: in-CLI and web. Reserve `-h`/`--help` for help only.
2. Prefer flags to args: self-documenting. 1 arg type fine, 2 suspect, 3 never good.
3. Mind stderr: spinners/progress to stderr, data to stdout. Enables piping.
4. Handle errors: debug mode, friendly messages, report links.
5. Be fancy: colors/spinners only when terminal supports them. Detect CI.
6. Prompt if you can: interactive prompts, but flags skip for CI.
7. Use tables: best for structured data. `--json` for machines.
8. Speed: lazy-load, cache, show progress.
9. Plugins: enable user extension.
10. Follow XDG spec: standard directories for config/data/cache.

**Applicability**: stderr/stdout separation critical. XDG adoption. Lazy-loading. Plugin architecture.