# Prompt 2: Best Practices & Industry Validation — Grounded in Parity Audit

**Context:** The V1→V2 Framework Parity Report (`docs/v2-research/V1-V2-FRAMEWORK-PARITY-REPORT.md`) found **87% parity** (133/161 ✅, 4 ⚠️, 24 ❌). V2 uses a TOML-driven declarative system with 22 packs and 261 patterns to replace V1's 444 hand-written TypeScript detector files. This prompt validates whether the architectural choices we made are industry-aligned and whether the gaps found are acceptable or need action.

---

## Task

Research industry best practices for declarative static analysis pattern systems. Validate the V2 framework definition system's design choices against them. Use internet research to compare with Semgrep, CodeQL, PMD, SonarQube custom rules, and ESLint plugin systems. For every finding, cite a URL source.

---

## Step 1: Format Choice Validation

V2 uses **TOML** for framework pattern definitions. Research and compare:

- **Semgrep** uses YAML. **PMD** uses XML. **CodeQL** uses a custom QL DSL. **ESLint** uses JS/JSON.
- Is TOML the right choice for a Rust-native tool? Consider: serde ecosystem support, human readability, nested structure expressiveness, tooling (LSP, schema validation).
- Specifically: our patterns use nested tables like `[patterns.match]` and `[patterns.match.not]` and `[patterns.learn]`. Does TOML handle this well at scale (261 patterns across 22 files), or do deeply nested structures become unwieldy?
- **Verdict needed:** Should we stay with TOML, migrate to YAML, or consider a Rust DSL?

---

## Step 2: Match Predicate Completeness

V2 has **15 match predicate types**: `imports`, `decorators`, `calls`, `extends`, `implements`, `function_names`, `class_names`, `string_literals`, `param_types`, `return_types`, `content_patterns`, `exports`, `error_handling`, `doc_comments`, `negative_match (NOT block)`.

The parity audit found **24 patterns with no V2 equivalent**. Research whether industry tools have predicate types that would cover our gaps:

| Gap Pattern | What's Missing | Research Question |
|---|---|---|
| `types/any-usage` (TS `any` detection) | No type-system-aware predicate | Does Semgrep's `metavariable-type` solve this? Would a `type_annotations` predicate help? |
| `types/interface-vs-type` | No TS-specific structural predicate | How does ESLint's `@typescript-eslint/consistent-type-definitions` approach this? |
| `components/near-duplicate` | No similarity/hashing predicate | Do any declarative rule systems support similarity detection, or is this always procedural? |
| `errors/try-catch-placement` | No scope/nesting-aware predicate | Does CodeQL's dataflow analysis cover this? Is a `scope_depth` or `parent_node` predicate needed? |
| `structural/file-naming` | No file-path predicate | Does Semgrep's `paths:` filter solve this? Should we add a `file_patterns` predicate? |
| `config/environment-detection` | Env var name pattern matching | Is `content_patterns` sufficient, or do we need an `env_vars` predicate? |
| `styling/class-naming` (BEM) | CSS-specific naming convention | How do stylelint and Semgrep handle CSS convention detection? |

**Verdict needed:** Which of these 7 gaps require new predicate types vs. can be solved with existing predicates (e.g., `content_patterns` regex)?

---

## Step 3: Learning System Design Validation

The parity audit found:
- **99 V2 learn directives** vs **113 V1 learning files** (88% coverage)
- **Only 2 deviation threshold overrides** (both Spring DI at 0.20; everything else uses default 0.15)
- **137 V1 semantic handlers** replaced by 15 predicate types — the report notes: *"V2 trades depth for breadth"*
- V2's `signal` field is always `"convention"` — no other signal types are used

Research:
- How do other tools handle **convention detection** (detecting what a codebase "usually does" and flagging deviations)?
  - Does Semgrep have anything like this?
  - Does SonarQube's "cognitive complexity" or "code smell" detection use frequency-based learning?
  - Are there academic papers on convention mining in codebases?
- Is a **single global threshold (0.15)** with only 2 overrides reasonable? Or should every pattern have its own threshold?
- Is **`"convention"` as the only signal type** a limitation? V1's semantic handlers could reason about pattern *relationships* (e.g., "error handler matches throw site"). Should V2 add signal types like `"relationship"`, `"co-occurrence"`, `"ordering"`?

**Verdict needed:** Is the learning system competitive with industry norms, or is it under-utilizing the two-pass architecture?

---

## Step 4: Performance & Compilation Strategy

V2 uses `include_str!()` to embed all 22 TOML files at **compile time**, then parses and regex-compiles them at runtime (analysis startup). This means:
- 261 patterns × N regex compilations happen once per `drift_analyze()` call
- Per-file matching runs all 261 patterns against each file's `ParseResult`

Research:
- How does **Semgrep** handle rule compilation? (Pre-compiled rule bundles? Lazy compilation?)
- How does **SonarQube** handle 1000+ rules without per-file overhead?
- Is **261 patterns × per-file evaluation** a concern for large repos (10K+ files)?
- Should we consider: **RegexSet** (single-pass multi-pattern matching), **language pre-filtering** (skip patterns whose language doesn't match), **Aho-Corasick** for literal string predicates?
- The `include_str!` approach means adding a custom pack requires recompilation. Is this acceptable, or should built-in packs also be loaded at runtime?

**Verdict needed:** Is the current compile/match strategy production-ready for enterprise-scale repos, or does it need optimization?

---

## Step 5: Security Pattern Validation

The parity report shows **9/9 ✅ security patterns** and framework-specific security patterns in all 8 packs. Validate:

- Are our **CWE IDs correctly mapped**? Cross-reference CWE IDs in the security.toml, auth.toml, and data_access.toml packs against the MITRE CWE database (https://cwe.mitre.org/).
- Are **OWASP categories current**? The packs reference `A1:2017`, `A2:2017`, etc. — the current OWASP Top 10 is **2021**. Should we update to `A01:2021`, `A02:2021`, etc.?
- Compare our SQL injection detection (`SEC-SQLI-RAW-001`, `SEC-SQLI-PARAM-001`) against Semgrep's SQL injection rules. Are we catching the same patterns?
- Compare our XSS detection (`SEC-XSS-SANITIZE-001`, `SEC-XSS-DANGERHTML-001`) against OWASP's recommended detection approaches.

**Verdict needed:** Are our security patterns current, correctly classified, and competitive with dedicated SAST tools?

---

## Step 6: C++ and Warp Gap Assessment

The biggest gaps are:
- **C++ (5 patterns):** boost-beast, crow, qt-network API patterns + auth middleware + error handling
- **Rust/Warp (1 pattern):** No Warp-specific route patterns

Research:
- What is the **current market share** of C++ web frameworks (Boost.Beast, Crow, Drogon, oat++)? Is this worth investing in?
- What is **Warp's usage** compared to Actix/Axum/Rocket? (crates.io download stats)
- Do Semgrep or CodeQL have C++ web framework rules?

**Verdict needed:** Should we build a `cpp_frameworks.toml` pack, or is the ROI too low? Should Warp be added to `rust_frameworks.toml`?

---

## Step 7: TypeScript `types/` Category Assessment

The parity report shows **7/8 ❌** in the `types/` category — the worst single-category result. All 7 are TypeScript-specific:
- `any-usage`, `file-location`, `generic-patterns`, `interface-vs-type`, `naming-conventions`, `type-assertions`, `utility-types`

Research:
- How does **typescript-eslint** handle these? (Rules like `no-explicit-any`, `consistent-type-definitions`, `naming-convention`)
- Are these patterns better handled by a **linter integration** (delegating to typescript-eslint) rather than reimplementing in TOML packs?
- If we do implement them, can `content_patterns` regex cover them, or do they require type-system awareness that TOML packs can't express?

**Verdict needed:** Build a `types.toml` pack, delegate to typescript-eslint, or accept this as out-of-scope for a framework detection system?

---

## Output Format

For each of the 7 steps, produce:

```
## Step N: [Title]

### Research Findings
- [Tool/Source]: [What they do] — [URL]
- ...

### Our Approach
[What V2 currently does]

### Verdict
[✅ Aligned | ⚠️ Improve | ❌ Change]

### Recommendation
[Specific action with estimated effort]
```

Then produce a **final summary table**:

| Step | Topic | Verdict | Action Required | Effort |
|---|---|---|---|---|
| 1 | TOML format | ✅/⚠️/❌ | ... | ... |
| 2 | Predicate completeness | ... | ... | ... |
| ... | ... | ... | ... | ... |
