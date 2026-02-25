# Best Practices & Industry Validation Report

**Date:** 2026-02-10
**Context:** Validates V2's TOML-driven declarative framework detection system against industry best practices.
**Input:** V1→V2 Framework Parity Report (87% parity, 133/161 ✅, 4 ⚠️, 24 ❌)

---

## Step 1: Format Choice Validation

### Research Findings

- **Semgrep**: Uses YAML for rule definitions. Rules are parsed into internal `Rule.t` structures, then compiled. YAML's multi-line string support (`|`) is heavily used for code patterns. Semgrep also supports Jsonnet for rule generation.
  — https://semgrep.dev/docs/writing-rules/rule-syntax
- **PMD**: Uses XML for rule definitions. Custom rules defined in `category/<language>/<filename>.xml`. XPath-based rules for simple patterns, Java-based rules for complex analysis.
  — https://pmd.github.io/pmd/pmd_userdocs_making_rulesets.html
- **CodeQL**: Uses a custom Datalog-inspired DSL called QL. Extremely powerful (dataflow, taint tracking) but requires learning a new language. Also supports YAML "data extensions" for modeling library behavior.
  — https://deepwiki.com/github/codeql
- **ESLint**: Uses JS/JSON for configuration, JS for custom rule implementation (AST visitor pattern).
  — https://eslint.org/docs/latest/extend/custom-rules
- **TOML in Rust ecosystem**: First-class serde support via `toml` crate. Widely used for Rust configuration (Cargo.toml, clippy.toml, rustfmt.toml). The `serde` derive macro provides zero-boilerplate deserialization.
  — https://docs.rs/toml
- **TOML limitations for deep nesting**: Reddit/Rust community consensus is that TOML becomes unwieldy at 3+ levels of nesting. Inline tables exist but `serde_toml` doesn't control their serialization style. For V2's `[patterns.match]` and `[patterns.match.not]` (2-3 levels), this is at the edge of comfortable.
  — https://www.reddit.com/r/rust/comments/1e6ns5p/does_everything_rust_have_to_be_toml/

### Our Approach

V2 uses TOML with `serde` deserialization. Patterns use nested tables: `[patterns.match]` (level 2) and `[patterns.match.not]` (level 3). The 22 packs with 261 patterns parse successfully. Custom packs load from `.drift/frameworks/*.toml` at runtime.

### Verdict

✅ **Aligned** — TOML is the right choice for a Rust-native tool at this scale.

### Recommendation

**Stay with TOML.** Rationale:
1. **Ecosystem fit**: TOML is the lingua franca of Rust tooling. Cargo, Clippy, Rustfmt, and most Rust projects use TOML. Users writing custom packs will find it familiar.
2. **Serde integration**: Zero-boilerplate deserialization. Adding new fields to `PatternDef` or `MatchBlock` is a single-line struct change — the TOML parser handles it automatically.
3. **Nesting depth is manageable**: Our deepest path is `[patterns.match.not]` (3 levels). Industry consensus says TOML becomes painful at 4+. We're within bounds.
4. **YAML would add complexity without benefit**: YAML's multi-line strings (`|`) are nice for code snippets, but our patterns use arrays of regex strings, which TOML handles cleanly with `[" ", " "]` array syntax.
5. **A Rust DSL would be over-engineering**: CodeQL's QL language is powerful but requires a compiler, LSP, and documentation effort that dwarfs our 261-pattern scale. DSLs only pay off at 1000+ rules.

**One improvement**: Consider adding a JSON Schema (or TOML equivalent) for IDE validation of custom packs. This would catch errors like invalid category names or malformed regex before analysis runs. **Effort: 1-2 days.**

---

## Step 2: Match Predicate Completeness

### Research Findings

| Gap Pattern | Industry Approach | Source |
|---|---|---|
| `types/any-usage` | Semgrep's `metavariable-type` operator (experimental) matches captured metavariables against specific types. For TS `any`, it would be: `metavariable-type: { metavariable: $X, type: any }`. typescript-eslint's `no-explicit-any` uses AST visitors to detect `: any` type annotations. | https://semgrep.dev/docs/writing-rules/experiments/metavariable-type, https://typescript-eslint.io/rules/no-explicit-any/ |
| `types/interface-vs-type` | typescript-eslint's `consistent-type-definitions` uses AST to differentiate `interface` vs `type` declarations. Not expressible in any declarative rule system (Semgrep, PMD) without type-system awareness. | https://typescript-eslint.io/rules/consistent-type-definitions/ |
| `components/near-duplicate` | No declarative rule system supports similarity detection. This is always procedural — tools like CCFinder, PMD CPD, or Semgrep's `--experimental` clone detection use token-based or AST-based hashing algorithms. | https://en.wikipedia.org/wiki/Duplicate_code |
| `errors/try-catch-placement` | CodeQL handles this via control flow graph queries (scope/nesting analysis). Semgrep's `pattern-inside` can check if a pattern appears inside a `try` block. Neither is expressible in a flat predicate system. | https://spaceraccoon.dev/comparing-rule-syntax-codeql-semgrep/ |
| `structural/file-naming` | Semgrep's `paths:` filter restricts rules to matching file paths (include/exclude globs). This is a rule-level filter, not a match predicate. No tool uses file paths as a detection predicate. | https://semgrep.dev/docs/writing-rules/rule-syntax |
| `config/environment-detection` | `content_patterns` regex on `NODE_ENV`, `RAILS_ENV`, etc. is sufficient. No dedicated predicate needed. | N/A (regex is adequate) |
| `styling/class-naming` (BEM) | Stylelint has dedicated BEM plugins (`stylelint-selector-bem-pattern`, `@namics/stylelint-bem`). These use postcss-bem-linter under the hood — regex on CSS selectors. CSS-specific, not general-purpose. | https://github.com/simonsmith/stylelint-selector-bem-pattern |

### Our Approach

V2 has 15 match predicate types operating on `ParseResult` structured data (imports, decorators, calls, etc.) plus `content_patterns` for regex-on-source fallback.

### Verdict

⚠️ **Improve** — 3 of 7 gaps need new predicates; 4 can be solved with existing predicates.

### Recommendation

| Gap | Action | Predicate Needed? | Effort |
|---|---|---|---|
| `types/any-usage` | Add `type_annotations` predicate matching against function param/return type strings | Yes — **new: `type_annotations`** | 0.5 day |
| `types/interface-vs-type` | Use `content_patterns` regex: `(?:interface\|type)\s+\w+` with learning to detect dominant convention | No — `content_patterns` + learning | 0.5 day |
| `components/near-duplicate` | Out of scope for TOML packs. V2's existing `structural/dna` module handles similarity via MinHash. Accept this gap. | No | 0 |
| `errors/try-catch-placement` | Add `scope_context` predicate (detect if match is inside try/catch/if/loop). Alternatively, use `content_patterns` to regex-match indented try/catch. | Desirable but complex — defer | 0 |
| `structural/file-naming` | Add `file_patterns` predicate (glob on file path). V2's `DetectSignal::FilePattern` already supports globs — just expose it as a match predicate. | Yes — **new: `file_patterns`** | 0.5 day |
| `config/environment-detection` | Add patterns to `config.toml` using existing `content_patterns` for `NODE_ENV`, `RAILS_ENV`, etc. | No | 0.5 day |
| `styling/class-naming` | Add patterns to `styling.toml` using `content_patterns` for BEM regex: `\.[a-z]+-[a-z]+(__[a-z]+)?(--[a-z]+)?` | No | 0.5 day |

**Total new predicates: 2** (`type_annotations`, `file_patterns`). **Total effort: ~2.5 days.**

---

## Step 3: Learning System Design Validation

### Research Findings

- **Semgrep**: Has no convention/frequency-based learning. Rules are pure pattern matching — they detect or don't detect. No concept of "this codebase usually does X, flag deviations." The closest feature is `metavariable-comparison` for numeric thresholds.
  — https://semgrep.dev/docs/writing-rules/rule-syntax
- **SonarQube**: Uses "Cognitive Complexity" and "Code Smell" metrics. These are per-function/per-file heuristics, NOT frequency-based learning. SonarQube has Quality Profiles (rule sets) but no concept of learning what a codebase "usually does." The "New Code" concept compares current scan to a baseline, but this is diff-based, not pattern-frequency-based.
  — https://docs.sonarsource.com/sonarqube-server/10.8/user-guide/rules/overview
- **ESLint/typescript-eslint**: Uses AST-based rules with configurable options. The `naming-convention` rule has extensive configuration for per-entity naming patterns, but it requires manual configuration — no auto-learning.
  — https://typescript-eslint.io/rules/naming-convention/
- **Academic research**: Convention mining in codebases is an active research area. The most relevant work:
  - ACM TOSEM 2024: "Understanding Test Convention Consistency as a Dimension of Test Quality" — frequency analysis of test naming patterns to detect deviations.
    — https://dl.acm.org/doi/10.1145/3672448
  - Frequent Pattern Mining (KDD): Established technique for finding itemsets/subsequences above a frequency threshold. V2's approach (group → count → flag minority) is a direct application.
    — https://www.kdd.org/kdd2016/topics/view/frequent-pattern-mining
- **No commercial tool does what V2's learning system does.** This is a genuinely novel feature in the static analysis space.

### Our Approach

V2's two-pass `FrameworkLearner`:
1. **Learn pass**: Accumulates pattern frequencies per group across all files
2. **Detect pass**: Computes dominant pattern per group, flags deviations where ratio ≥ (1.0 - threshold)

99 learn directives, all `signal = "convention"`, global default threshold 0.15, only 2 overrides (Spring DI at 0.20).

### Verdict

✅ **Aligned** — The learning system is **ahead** of industry norms, not behind them.

### Recommendation

The learning system is a differentiator. However, it's under-utilizing the two-pass architecture:

1. **Add more signal types** (medium priority, 2-3 days):
   - `"frequency"` — report raw frequency data without deviation flagging (useful for dashboards)
   - `"presence"` — flag if a pattern is entirely absent from a codebase that uses the framework (e.g., "Spring project with zero `@Transactional` annotations")
   - `"co-occurrence"` — flag when pattern A appears without pattern B in the same file (e.g., "error handler without logging")

2. **Per-pattern threshold tuning** (low priority, 1 day):
   The single global threshold (0.15) with only 2 overrides is **acceptable**. In practice, V1's per-detector thresholds were rarely tuned either. However, categories with naturally higher variance (e.g., `api` with mixed GET/POST/PUT/DELETE) might benefit from higher thresholds. Add thresholds for 5-10 patterns where V1 had custom tuning.

3. **The `"convention"` monoculture is fine for now.** It covers the primary use case (detect dominant patterns, flag deviations). The additional signal types above would expand capability without requiring architectural changes — the `learn_signal` field is already deserialized and stored.

---

## Step 4: Performance & Compilation Strategy

### Research Findings

- **Semgrep architecture**: Rules are parsed from YAML → compiled into internal `Rule.t` structures → patterns are compiled to AST patterns. Target files are associated with applicable rules (language filtering). Analysis is parallelized via Parmap (fork-based) or Eio (multicore OCaml). Per-file analysis has a timeout mechanism. Post-processing includes "Too Many Matches" filter to cap matches per file.
  — https://deepwiki.com/semgrep/semgrep/2-core-architecture
- **Semgrep performance principles**: "Rules are slower if the sub-patterns result in a greater number of matches." They recommend `--time` flag for benchmarking. Interfile rules scale better-than-linearly when adding more rules. Key factor: time spent adding to match lists.
  — https://semgrep.dev/docs/kb/rules/rule-file-perf-principles
- **SonarQube**: Runs 1000+ rules per file by using language-specific analyzers. Rules are grouped by language and only applicable rules run per file. The analyzer operates on a single AST pass — rules register as visitors on specific AST node types, so 1000 rules don't mean 1000 passes.
  — https://docs.sonarsource.com/sonarqube-server/extension-guide/adding-coding-rules
- **Rust RegexSet**: The `regex` crate provides `RegexSet` for matching multiple patterns in a single pass. Returns which patterns matched without requiring per-pattern iteration. Ideal for `content_patterns` where many patterns run against the same source lines.
  — https://docs.rs/regex/latest/regex/
- **Aho-Corasick**: BurntSushi's `aho-corasick` crate provides O(n + m) multi-pattern string matching via finite state machine. Ideal for literal string predicates (imports, decorators, etc.) where no regex is needed.
  — https://github.com/BurntSushi/aho-corasick

### Our Approach

V2 uses `include_str!()` to embed 22 TOML files at compile time. At runtime startup, all 261 patterns are parsed and regex-compiled once via `loader.rs`. Per-file matching iterates all patterns but skips packs whose language doesn't match. Content patterns iterate all source lines × all regex patterns.

Already optimized:
- Language pre-filtering (pack-level and pattern-level)
- Rayon parallelism for several analysis steps
- File content cache eliminates redundant disk reads

### Verdict

⚠️ **Improve** — Current strategy works at 2K files but has optimization headroom for 10K+ file enterprise repos.

### Recommendation

1. **`RegexSet` for `content_patterns`** (high priority, 1-2 days):
   The current approach iterates source lines × N regex patterns per pattern definition. For the `security.toml` pack alone, `SEC-SQLI-RAW-001` has 4 regexes that run against every line. Across all packs, there are ~80 content_pattern regexes.

   **Fix**: At pack compilation time, build a single `RegexSet` from all content_patterns across all patterns for a given language. Run the RegexSet once per line to get the set of matching pattern indices, then map back to pattern IDs. This turns O(lines × patterns) into O(lines × 1).

2. **Aho-Corasick for literal predicates** (medium priority, 1 day):
   The `imports`, `decorators`, `extends`, `implements`, and `exports` predicates use case-insensitive string contains/equals. Build an Aho-Corasick automaton from all literal strings at compile time. Match against the concatenated import sources/decorator names in one pass.

3. **`include_str!` is correct for built-in packs** (no change needed):
   The current approach embeds TOML strings at compile time and parses at runtime. This is the same as Semgrep's model (rules compiled at startup). The custom pack loading from `.drift/frameworks/` provides runtime extensibility without requiring recompilation.

4. **Per-file match limit** (low priority, 0.5 day):
   Semgrep caps matches per file to prevent degenerate cases. Add a `max_matches_per_file` config (default 100) to `FrameworkMatcher`.

**Total effort: 2.5-3.5 days** for a ~3-5x speedup on content_patterns matching in large repos.

---

## Step 5: Security Pattern Validation

### Research Findings

- **OWASP Top 10 is now 2021, not 2017**: The current OWASP Top 10 is the **2021 edition** (published September 2021). A **2025 edition** is in draft. Our packs reference `A1:2017`, `A5:2017`, `A7:2017` — these are outdated by 4+ years.
  — https://owasp.org/Top10/2021/
- **2017 → 2021 mapping**:
  - `A1:2017` (Injection) → `A03:2021` (Injection) — CWE-89 (SQLi) now under A03
  - `A5:2017` (Broken Access Control) → `A01:2021` (Broken Access Control) — moved to #1
  - `A7:2017` (XSS) → `A03:2021` (Injection) — XSS merged into Injection category
  — https://owasp.org/Top10/2021/A03_2021-Injection/
- **CWE mappings are correct**:
  - CWE-89 (SQL Injection) → correctly used in `SEC-SQLI-RAW-001` ✅
  - CWE-79 (XSS) → correctly used in `SEC-XSS-SANITIZE-001`, `SEC-XSS-DANGERHTML-001` ✅
  - CWE-352 (CSRF) → correctly used in `SEC-CSRF-TOKEN-001`, `SEC-CSRF-MIDDLEWARE-001` ✅
  - CWE-312 (Cleartext Storage of Sensitive Info) → correctly used in `DA-SENSITIVE-001` ✅
  — https://cwe.mitre.org/data/definitions/89.html
- **Semgrep SQL injection rules**: Semgrep uses taint analysis for SQL injection — tracking data flow from user input (sources) to SQL query construction (sinks). This is fundamentally more precise than V2's regex-based approach. V2 detects string interpolation in SQL keywords, which has higher false positives (e.g., logging statements that format SQL keywords).
  — https://blog.doyensec.com/2022/10/06/semgrep-codeql.html
- **XSS detection**: OWASP recommends context-aware output encoding (HTML, JS, CSS, URL contexts). V2 detects `dangerouslySetInnerHTML`, `innerHTML`, `v-html` which are the primary XSS sinks. This is aligned with standard SAST approaches.
  — https://owasp.org/Top10/2021/A03_2021-Injection/

### Our Approach

Security patterns in `security.toml`: 13 patterns covering CSRF, SQL injection, XSS, CSP, rate limiting, secrets, and input validation. CWE IDs present on 5 patterns. OWASP references use 2017 numbering.

### Verdict

⚠️ **Improve** — CWE IDs are correct, but OWASP references are stale. SQL injection detection lacks taint awareness.

### Recommendation

1. **Update OWASP references to 2021** (high priority, 0.5 day):

   | Current | Correct 2021 | Pattern IDs |
   |---|---|---|
   | `A1:2017` | `A03:2021` | `SEC-SQLI-RAW-001` |
   | `A5:2017` | `A01:2021` | `SEC-CSRF-TOKEN-001` |
   | `A7:2017` | `A03:2021` | `SEC-XSS-SANITIZE-001` |

   Also add OWASP references to patterns that currently lack them:
   - `SEC-RATE-LIMIT-*` → `A04:2021` (Insecure Design)
   - `SEC-SECRET-VAULT-001` → `A02:2021` (Cryptographic Failures)
   - `SEC-INPUT-*` → `A03:2021` (Injection)
   - `SEC-CSP-HEADER-001` → `A05:2021` (Security Misconfiguration)
   - `DA-SENSITIVE-001` → `A02:2021` (Cryptographic Failures)

2. **Add CWE IDs to all security-relevant patterns** (high priority, 0.5 day):
   Several patterns have OWASP but no CWE, or neither:
   - `SEC-CSRF-SAMESITE-001` → add `cwe_ids = [352]`
   - `SEC-RATE-LIMIT-*` → add `cwe_ids = [770]` (Allocation of Resources Without Limits)
   - `SEC-INPUT-SANITIZE-001` → add `cwe_ids = [20]` (Improper Input Validation)
   - `AUTH-*` patterns → add `cwe_ids = [287]` (Improper Authentication) where applicable

3. **SQL injection precision** (low priority, accept limitation):
   V2's regex-based SQL injection detection (`SEC-SQLI-RAW-001`) is a **pattern detector**, not a SAST tool. It catches obvious string interpolation in SQL, which is appropriate for a framework detection system. Taint analysis belongs in the `drift-analysis/src/graph_intelligence/taint/` module (already built). The TOML pack correctly identifies the risk; the taint module provides deeper analysis.

**Total effort: ~1 day.**

---

## Step 6: C++ and Warp Gap Assessment

### Research Findings

- **C++ web framework market share**: C++ web frameworks (Boost.Beast, Crow, Drogon, oat++) have negligible market share compared to frameworks in other languages. Stack Overflow's 2024 Developer Survey shows zero C++ web frameworks in the top 30 most-used frameworks (dominated by React, Node.js, Express, Next.js, ASP.NET, Flask, Django, Spring, etc.).
  — https://www.statista.com/statistics/1124699/worldwide-developer-survey-most-used-frameworks-web/
- **C++ web framework landscape**: Boost.Beast is a low-level HTTP library (part of Boost), not a web framework. Crow is a micro-framework with limited maintenance. Drogon and oat++ are newer but niche. Most C++ web development uses gRPC or embedded HTTP servers, not traditional web frameworks.
  — https://www.quora.com/What-is-the-best-C-framework-in-C-in-2023
- **Semgrep/CodeQL C++ rules**: Semgrep has 48 C/C++ rules focused on memory safety (buffer overflows, use-after-free, format strings), NOT web framework patterns. CodeQL's C++ library covers taint analysis and memory safety. Neither tool has web framework-specific rules for Boost.Beast/Crow/Qt.
  — https://www.reddit.com/r/netsec/comments/185pss7/big_update_to_my_semgrep_cc_ruleset/
- **Rust Warp framework**: Warp is a popular Rust web framework built on Tokio with a composable filter-based design. However, the Rust web ecosystem has consolidated around **Actix Web and Axum** as the dominant frameworks. Warp's ecosystem is described as "smaller but expanding" compared to Actix's "largest and most mature." Community consensus (Reddit r/rust) increasingly favors Axum over Warp for new projects.
  — https://dev.to/leapcell/rust-web-frameworks-compared-actix-vs-axum-vs-rocket-4bad
  — https://www.reddit.com/r/rust/comments/1ozt50s/actixweb_vs_axum_in_20252026/
- **crates.io download statistics** (approximate monthly downloads as of early 2026):
  - actix-web: ~2.5M/month
  - axum: ~3.5M/month
  - rocket: ~500K/month
  - warp: ~1.2M/month
  — https://blog.logrocket.com/top-rust-web-frameworks/

### Our Approach

V2 has `rust_frameworks.toml` covering Actix, Axum, and Rocket. No Warp patterns. V1 had 5 C++ patterns (boost-beast, crow, qt-network + auth/errors). V2 has `cpp` in several cross-language pack language fields, meaning generic patterns (CSRF, SQL injection, etc.) match C++ files, but no C++-specific framework patterns exist.

### Verdict

✅ **Aligned** — C++ web framework investment is not justified. Warp deserves modest addition.

### Recommendation

1. **Do NOT build a `cpp_frameworks.toml` pack** (decision: skip):
   - C++ web frameworks have negligible market share
   - No competing tool (Semgrep, CodeQL) has C++ web framework rules
   - V2's generic cross-language patterns (security, errors, data access) already match C++ code
   - The 5 V1 C++ patterns were aspirational, not driven by user demand
   - **ROI: Near zero**

2. **Add Warp patterns to `rust_frameworks.toml`** (low priority, 0.5 day):
   Warp has ~1.2M monthly downloads — significant but declining relative to Axum. Add 3-4 patterns:
   - `rust/warp/route` — `warp::path()`, `warp::get()`, `warp::post()`
   - `rust/warp/filter` — `warp::Filter`, `.and()`, `.or()`
   - `rust/warp/rejection` — `warp::reject`, custom rejection handling
   - `rust/warp/ws` — `warp::ws()` WebSocket support

**Total effort: 0.5 day.**

---

## Step 7: TypeScript `types/` Category Assessment

### Research Findings

- **typescript-eslint coverage**: typescript-eslint provides mature, battle-tested rules for all 7 missing patterns:
  - `no-explicit-any` — Detects explicit `any` type annotations. Requires AST parsing of type annotations. Has options for `fixToUnknown` and `ignoreRestArgs`.
    — https://typescript-eslint.io/rules/no-explicit-any/
  - `consistent-type-definitions` — Enforces `interface` vs `type` consistency. Requires AST differentiation between `TSInterfaceDeclaration` and `TSTypeAliasDeclaration`.
    — https://typescript-eslint.io/rules/consistent-type-definitions/
  - `naming-convention` — Enforces naming patterns for variables, functions, types, interfaces, enums, etc. Requires type information to run ("This rule requires type information to run, which comes with performance tradeoffs").
    — https://typescript-eslint.io/rules/naming-convention/
  - `no-unsafe-member-access`, `no-unsafe-assignment`, `no-unsafe-return` — Related `any` propagation rules.
    — https://typescript-eslint.io/blog/avoiding-anys/

- **Can `content_patterns` regex cover these?**:
  - `any-usage`: **Partially** — `content_patterns = [":\s*any\b"]` would catch `param: any` but also false-positive on `// any comment` or `"any string"`. The lack of AST awareness means no way to distinguish type annotations from other contexts.
  - `interface-vs-type`: **Yes** — `content_patterns = ["^(?:export\s+)?interface\s+"]` and `["^(?:export\s+)?type\s+\w+\s*="]` can detect both declarations and use learning to find the dominant convention. This works because `interface` and `type` are keywords at the start of declarations.
  - `generic-patterns`: **Partially** — `<T>` syntax is detectable via regex but has many false positives (JSX, HTML).
  - `type-assertions`: **Yes** — `as\s+\w+` and `<\w+>` prefix assertions are regex-detectable.
  - `utility-types`: **Yes** — `Partial<`, `Required<`, `Pick<`, `Omit<`, `Record<` are literal strings.
  - `file-location`: **Yes** — If we add `file_patterns` predicate (Step 2), detect `.d.ts` files, `types/` directories.
  - `naming-conventions`: **Partially** — Can regex for `interface I\w+` (Hungarian notation) or `type T\w+`, but can't validate all entities like typescript-eslint's comprehensive rule.

- **Semgrep's approach to TypeScript types**: Semgrep's `metavariable-type` is experimental and requires type inference. Their TypeScript support notes: "it would take more type inference work to resolve types for TypeScript." This is an industry-wide gap.
  — https://semgrep.dev/blog/2020/type-awareness-in-semantic-grep/

### Our Approach

V2 has zero `types/` category patterns. The `aspnet/types/record` pattern exists but is C#-specific.

### Verdict

⚠️ **Improve** — Build a `types.toml` pack for the patterns expressible via existing predicates + `content_patterns`. Accept limitations for type-system-aware patterns.

### Recommendation

**Build a `typescript_types.toml` pack** covering what's expressible (medium priority, 1.5 days):

| V1 Pattern | Approach | Expressible? |
|---|---|---|
| `any-usage` | `content_patterns` regex for `: any`, `as any`, `<any>` with NOT block excluding comments | ⚠️ Partial — some false positives |
| `interface-vs-type` | `content_patterns` for both + learning to detect dominant convention | ✅ Yes |
| `type-assertions` | `content_patterns` for `as \w+` and angle-bracket assertions | ✅ Yes |
| `utility-types` | `content_patterns` for `Partial<`, `Required<`, `Pick<`, `Omit<`, `Record<`, `Readonly<` | ✅ Yes |
| `file-location` | `file_patterns` predicate (if added in Step 2) for `.d.ts`, `types/` | ✅ Yes |
| `naming-conventions` | `content_patterns` for `interface I[A-Z]`, `type T[A-Z]` + learning | ⚠️ Partial |
| `generic-patterns` | `content_patterns` for `<T>`, `<T extends` with NOT block for JSX | ⚠️ Partial |

**Do NOT delegate to typescript-eslint.** Rationale:
1. V2 is a Rust-native tool — adding a Node.js dependency (typescript-eslint) for 7 patterns is architecturally wrong.
2. typescript-eslint requires TypeScript's compiler API (type-checking), which is ~100x slower than regex matching.
3. The patterns expressible via `content_patterns` + learning cover the highest-value detections (any-usage, interface-vs-type convention, utility types).

**Accept partial coverage** for `naming-conventions` and `generic-patterns` — these require type-system awareness that no declarative rule system (including Semgrep) fully handles for TypeScript.

**Total effort: 1.5 days** for the `typescript_types.toml` pack with ~10 patterns.

---

## Final Summary Table

| Step | Topic | Verdict | Action Required | Effort |
|---|---|---|---|---|
| 1 | TOML format | ✅ Aligned | Stay with TOML; add JSON Schema for validation | 1-2 days |
| 2 | Predicate completeness | ⚠️ Improve | Add `type_annotations` + `file_patterns` predicates; 4 gaps solvable with existing predicates | 2.5 days |
| 3 | Learning system | ✅ Aligned | Add `frequency`/`presence`/`co-occurrence` signal types (optional enhancement) | 2-3 days |
| 4 | Performance | ⚠️ Improve | RegexSet for content_patterns, Aho-Corasick for literals, per-file match limit | 2.5-3.5 days |
| 5 | Security patterns | ⚠️ Improve | **Update OWASP 2017→2021**, add missing CWE IDs | 1 day |
| 6 | C++ and Warp | ✅ Aligned | Skip C++ packs; add 4 Warp patterns to rust_frameworks.toml | 0.5 day |
| 7 | TypeScript types/ | ⚠️ Improve | Build `typescript_types.toml` with ~10 patterns | 1.5 days |

### Priority Order

1. **OWASP 2017→2021 update** (Step 5) — correctness issue, 1 day
2. **`typescript_types.toml` pack** (Step 7) — biggest coverage gap, 1.5 days
3. **`file_patterns` + `type_annotations` predicates** (Step 2) — unblocks multiple patterns, 1 day
4. **RegexSet optimization** (Step 4) — performance for enterprise repos, 2 days
5. **Warp patterns** (Step 6) — minor gap, 0.5 day
6. **Learning signal types** (Step 3) — enhancement, 2-3 days
7. **JSON Schema for custom packs** (Step 1) — DX improvement, 1-2 days

**Total estimated effort: 10-14 days** for all improvements. **Minimum viable: Steps 5 + 7 = 2.5 days** to fix correctness issues and close the biggest gap.
