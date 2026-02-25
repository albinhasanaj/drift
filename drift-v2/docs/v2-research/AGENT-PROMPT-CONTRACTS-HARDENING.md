# Agent Prompt: API Contract Extraction & Breaking Change Detection Hardening

## Your Mission

You are performing a deep audit and hardening of **`crates/drift/drift-analysis/src/structural/contracts/`** — Drift V2's API contract extraction and breaking change detection system. This is the subsystem responsible for detecting breaking API changes across 14 frameworks and 4 schema formats. Your goal is to produce a phased implementation plan identical in rigor to the existing `DETECTOR-PARITY-HARDENING-TASKS.md` and `CALL-GRAPH-AND-GRAPH-INTELLIGENCE-HARDENING-TASKS.md`.

**Speed does not matter. Thoroughness does. Do not fabricate findings. Every claim must have a file path and line number.**

---

## Context: What Has Already Been Audited

Two prior hardening audits have been completed. You MUST read both before starting — they establish the upstream data quality issues that directly affect your subsystem:

1. **`docs/v2-research/DETECTOR-PARITY-HARDENING-TASKS.md`** — Parser extraction audit. Found that `import.specifiers`, `func.is_exported`, `func.decorators`, `class.implements`, `import.source` (full statement text, not module path), `func.doc_comment`, and many other `ParseResult` fields are always empty/default. These parser fields are being fixed in phases.

2. **`docs/v2-research/CALL-GRAPH-AND-GRAPH-INTELLIGENCE-HARDENING-TASKS.md`** — Call graph audit. Found that 4 of 6 resolution strategies are dead, entry point detection is crippled, and all downstream graph systems (taint, impact, coverage, coupling) operate on hollow data.

Your subsystem (`structural/contracts/`) consumes `ParseResult` data — the same data those audits confirmed is broken. You must trace exactly which fields each extractor reads and whether those fields currently produce real data.

---

## Your Subsystem: Complete File Inventory (27 items — account for 100%)

You must read and audit EVERY file listed below. No exceptions. Check off each as you read it.

### Core
- [ ] `contracts/mod.rs` — Module root, public exports
- [ ] `contracts/types.rs` — Core types: ApiContract, Endpoint, Parameter, ResponseSchema, BreakingChange, etc.
- [ ] `contracts/breaking_changes.rs` — Breaking change detection logic
- [ ] `contracts/matching.rs` — Contract matching/comparison between versions
- [ ] `contracts/confidence.rs` — Confidence scoring for contract extraction

### Extractors (14 framework-specific extractors)
- [ ] `contracts/extractors/mod.rs` — Extractor trait, dispatch logic
- [ ] `contracts/extractors/express.rs` — Express.js route extraction
- [ ] `contracts/extractors/fastify.rs` — Fastify route extraction
- [ ] `contracts/extractors/nestjs.rs` — NestJS controller/route extraction
- [ ] `contracts/extractors/nextjs.rs` — Next.js API route extraction
- [ ] `contracts/extractors/trpc.rs` — tRPC router extraction
- [ ] `contracts/extractors/flask.rs` — Flask route extraction
- [ ] `contracts/extractors/django.rs` — Django URL/view extraction
- [ ] `contracts/extractors/spring.rs` — Spring MVC/Boot mapping extraction
- [ ] `contracts/extractors/rails.rs` — Rails route extraction
- [ ] `contracts/extractors/laravel.rs` — Laravel route extraction
- [ ] `contracts/extractors/aspnet.rs` — ASP.NET controller extraction
- [ ] `contracts/extractors/gin.rs` — Gin router extraction
- [ ] `contracts/extractors/actix.rs` — Actix-web handler extraction
- [ ] `contracts/extractors/frontend.rs` — Frontend API client extraction

### Schema Parsers (4 schema formats)
- [ ] `contracts/schema_parsers/mod.rs` — Schema parser dispatch
- [ ] `contracts/schema_parsers/openapi.rs` — OpenAPI/Swagger schema parsing
- [ ] `contracts/schema_parsers/graphql.rs` — GraphQL schema parsing
- [ ] `contracts/schema_parsers/protobuf.rs` — Protocol Buffers schema parsing
- [ ] `contracts/schema_parsers/asyncapi.rs` — AsyncAPI schema parsing

---

## Audit Procedure (follow this exactly)

### Step 1: Read the Reference Documents
Read both existing hardening documents in full:
- `docs/v2-research/DETECTOR-PARITY-HARDENING-TASKS.md`
- `docs/v2-research/CALL-GRAPH-AND-GRAPH-INTELLIGENCE-HARDENING-TASKS.md`

Internalize the format, the level of evidence required, and the phased approach.

### Step 2: Read the Types First
Start with `contracts/types.rs` and `contracts/mod.rs`. Map every struct and enum. These define the data model — you need to know what a "complete" contract looks like before you can judge what's missing.

### Step 3: Trace Upstream Dependencies (what feeds INTO contracts)
For each extractor, identify EXACTLY which `ParseResult` fields it reads:
- `functions` → which fields? (`name`, `decorators`, `parameters`, `return_type`, `is_exported`, `doc_comment`?)
- `classes` → which fields? (`name`, `decorators`, `methods`, `implements`?)
- `imports` → which fields? (`source`, `specifiers`, `is_type_only`?)
- `call_sites` → which fields? (`callee_name`, `receiver`, `argument_count`?)
- `string_literals` → any?
- `decorators` → any?

Cross-reference each consumed field against the Detector Parity findings. If the field is confirmed always-empty, the extractor is hollow for that data path.

### Step 4: Trace Downstream Consumers (what contracts FEED)
Grep the codebase for all consumers of:
- `ApiContract`, `Endpoint`, `BreakingChange`, or whatever the core output types are named
- The public functions exported from `contracts/mod.rs`

Find every downstream system that depends on contract data. Likely consumers:
- `enforcement/gates/` — may gate on breaking changes
- `enforcement/reporters/` — may report breaking changes
- `patterns/` — may aggregate contract findings
- NAPI bindings / MCP tools — may expose contract data to the presentation layer
- Bridge layer (`crates/cortex-drift-bridge/`) — may forward contract results

### Step 5: Audit Each Extractor (14 frameworks)
For each of the 14 extractors, answer:
1. What `ParseResult` fields does it consume?
2. Are those fields currently populated (cross-ref Detector Parity)?
3. Does it use decorators for route detection? (If so, currently broken)
4. Does it use import specifiers for framework detection? (If so, currently broken)
5. Does it extract HTTP method, path, parameters, request body schema, response schema?
6. What's hardcoded vs. dynamically extracted?
7. Are there any framework-specific patterns it should detect but doesn't?

### Step 6: Audit Schema Parsers (4 formats)
For each schema parser, answer:
1. Does it parse the actual schema file format, or does it just pattern-match strings?
2. What types does it extract? (endpoints, types, enums, request/response schemas)
3. Does it handle $ref / type references / imports between schema files?
4. Is it connected to the breaking change detector?

### Step 7: Audit Breaking Change Detection
Answer:
1. What types of breaking changes does it detect? (removed endpoint, changed parameter type, narrowed response, etc.)
2. How does it compare two versions of a contract?
3. Does it distinguish breaking vs. non-breaking changes?
4. Does it use SemVer compatibility rules?
5. Is the confidence scoring calibrated or are values hardcoded?

### Step 8: Research If Needed
If you encounter framework-specific routing patterns you're unsure about, use online search to verify:
- Express 5 vs Express 4 routing differences
- NestJS decorator-based routing patterns
- Spring Boot annotation hierarchy (@RequestMapping, @GetMapping, etc.)
- Django URL patterns vs path() syntax
- tRPC v10/v11 router patterns
- Next.js App Router vs Pages Router API routes
- AsyncAPI 3.0 changes from 2.x

### Step 9: Create the Hardening Document
Produce `docs/v2-research/CONTRACT-EXTRACTION-HARDENING-TASKS.md` following EXACTLY the format of the two reference documents:

1. **Progress Summary Table** — phases, impl tasks, test tasks, status
2. **Audit Findings Reference** — root cause, line-verified evidence table, cascade impact map
3. **Phased Fix Plan** with:
   - Unique task IDs (`CE-{subsystem}-{number}` for impl, `CET-{subsystem}-{number}` for tests)
   - Quality gates per phase
   - Dependency graph showing what must come first
4. **Every finding must have a file path and line number**
5. **Every extractor must be accounted for** — if it works correctly, say so and why. If it's broken, say exactly what's wrong.
6. **No fabricated data** — if you can't determine something from the code, say so explicitly

---

## Upstream Systems That Feed Contracts (verify all)

| System | Data Provided | Status (from prior audits) |
|--------|--------------|---------------------------|
| `parsers/languages/mod.rs` | `ParseResult` with functions, classes, imports, decorators, call_sites | Partially broken — see Detector Parity |
| `parsers/types.rs` | Type definitions for all extracted data | Types are correct, population is incomplete |
| `engine/resolution.rs` | Cross-file symbol resolution | Broken — External strategy never fires |
| `call_graph/` | Function-level dependency graph | Hollow — only same-file edges work |

## Downstream Systems That Consume Contracts (find all)

Search for consumers in:
- `crates/drift/drift-analysis/src/enforcement/`
- `crates/drift/drift-analysis/src/patterns/`
- `crates/drift/drift-napi/src/bindings/`
- `packages/drift-mcp/src/tools/`
- `packages/drift-cli/src/`
- `packages/drift-ci/src/`
- `crates/cortex-drift-bridge/`

---

## Quality Criteria for Your Output

Your hardening document MUST:
- [ ] Account for all 27 items in the file inventory (no file unread)
- [ ] Map every `ParseResult` field consumed by every extractor
- [ ] Cross-reference each field against the Detector Parity confirmed-empty list
- [ ] Identify which extractors are functional vs. hollow
- [ ] Trace all downstream consumers
- [ ] Include line-verified evidence for every finding
- [ ] Produce a phased plan with impl tasks, test tasks, quality gates
- [ ] Not fabricate any findings — only report what the code shows
