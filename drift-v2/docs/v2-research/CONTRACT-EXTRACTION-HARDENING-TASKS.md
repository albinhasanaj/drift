# Drift V2 — API Contract Extraction & Breaking Change Detection Hardening Task Tracker

> **Source of Truth:** Deep audit of `crates/drift/drift-analysis/src/structural/contracts/` — 14 framework extractors, 4 schema parsers, breaking change detection, contract matching, confidence scoring.
> **Target:** Every extractor produces real endpoints with request/response fields. Breaking change detection covers all 19 change types. Schema parsers handle $ref resolution. NAPI binding is wired to real data (not stub).
> **Crate:** `crates/drift/drift-analysis/`
> **Total Phases:** 5 (A–E)
> **Quality Gates:** 5 (QG-A through QG-E)
> **Architectural Decision:** The type system is well-designed — `Contract`, `Endpoint`, `FieldSpec`, `Paradigm` (7 variants), `BreakingChangeType` (19 variants), `MismatchType` (7 variants) are all correct. The `EndpointExtractor` trait and `SchemaParser` trait are sound. The core problem is: **extractors operate on raw `content: &str` via line-by-line string matching instead of consuming `ParseResult` AST data**, and they **never extract request/response field schemas**. All `request_fields` and `response_fields` are always `vec![]`.
> **Dependency:** Independent of Detector Parity Phase A for basic path extraction (extractors use raw text). Phase C depends on Detector Parity Phase A for field extraction via ParseResult.
> **Rule:** No Phase N+1 begins until Phase N quality gate passes.
> **Rule:** All changes must compile with `cargo clippy --workspace -- -D warnings` clean.
> **Rule:** Every impl task has a corresponding test task. No untested code.
> **Verification:** This tracker accounts for 100% of the 25 files in the contracts subsystem.

---

## How To Use This Document

- Agents: check off `[ ]` → `[x]` as you complete each task
- Every implementation task has a unique ID: `CE-{subsystem}-{number}` (CE = Contract Extraction)
- Every test task has a unique ID: `CET-{subsystem}-{number}` (CET = Contract Extraction Test)
- Quality gates are pass/fail — all criteria must pass before proceeding
- For contract types → `crates/drift/drift-analysis/src/structural/contracts/types.rs`
- For extractor trait → `crates/drift/drift-analysis/src/structural/contracts/extractors/mod.rs`
- For schema parser trait → `crates/drift/drift-analysis/src/structural/contracts/schema_parsers/mod.rs`

---

## Progress Summary

| Phase | Description | Impl Tasks | Test Tasks | Status |
|-------|-------------|-----------|-----------|--------|
| A | Extractor Robustness & Coverage Gaps | 18 | 24 | Not Started |
| B | Schema Parser Completeness | 10 | 14 | Not Started |
| C | Field Extraction (ParseResult Integration) | 14 | 18 | Not Started |
| D | Breaking Change Detection Completeness | 10 | 14 | Not Started |
| E | NAPI Wiring, Downstream Integration & Regression | 8 | 16 | Not Started |
| **TOTAL** | | **60** | **86** | |

---

## File Inventory (25 files — 100% accounted for)

### Core (5 files)
- [x] `contracts/mod.rs` (11 lines) — Module root, exports `types::*`.
- [x] `contracts/types.rs` (183 lines) — `Contract`, `Endpoint`, `FieldSpec`, `Paradigm`(7), `BreakingChangeType`(19), `MismatchType`(7), `ContractMatch`.
- [x] `contracts/breaking_changes.rs` (101 lines) — `classify_breaking_changes()`. Only 5 of 19 change types implemented.
- [x] `contracts/matching.rs` (121 lines) — `match_contracts()` O(n²). Only 1 of 7 mismatch types detected.
- [x] `contracts/confidence.rs` (40 lines) — `bayesian_confidence()` 7-signal model. Only 3 signals ever populated.

### Extractors (15 files)
- [x] `extractors/mod.rs` (74 lines) — `EndpointExtractor` trait on raw `&str`. `ExtractorRegistry` with 14 extractors.
- [x] `extractors/express.rs` (59 lines) — `app.get(`/`router.get(` patterns. **No field extraction.**
- [x] `extractors/fastify.rs` (38 lines) — `fastify.get(` patterns. **No field extraction.**
- [x] `extractors/nestjs.rs` (56 lines) — `@Get(`/`@Post(` + `@Controller(` base path. **No field extraction.**
- [x] `extractors/nextjs.rs` (84 lines) — `export async function GET` + file-path-to-route. **No field extraction.**
- [x] `extractors/trpc.rs` (39 lines) — `.query(`/`.mutation(` (v9 only). **No field extraction.**
- [x] `extractors/flask.rs` (71 lines) — `@app.route(` + `methods=[...]`. **No field extraction.**
- [x] `extractors/django.rs` (59 lines) — `path(`/`re_path(`. `@api_view` detected but **not wired**. **No field extraction.**
- [x] `extractors/spring.rs` (65 lines) — `@GetMapping(`/`@RequestMapping(` + base path. **No field extraction.**
- [x] `extractors/rails.rs` (70 lines) — `get '/path'` + `resources :name`. **No field extraction.**
- [x] `extractors/laravel.rs` (41 lines) — `Route::get(`. **No field extraction.**
- [x] `extractors/aspnet.rs` (56 lines) — `[HttpGet(` + `[Route(` base path. **No field extraction.**
- [x] `extractors/gin.rs` (42 lines) — `.GET(` (uppercase). **No field extraction.**
- [x] `extractors/actix.rs` (59 lines) — `#[get(` + `web::resource(`. **No field extraction.**
- [x] `extractors/frontend.rs` (97 lines) — `fetch(`/`axios.get(`/`useSWR(`/`useQuery(`. **No field extraction.**

### Schema Parsers (5 files)
- [x] `schema_parsers/mod.rs` (19 lines) — `SchemaParser` trait on raw `&str`.
- [x] `schema_parsers/openapi.rs` (163 lines) — JSON/YAML parse. **No `$ref` resolution.**
- [x] `schema_parsers/graphql.rs` (146 lines) — String-based SDL parse. **No `extend type` or `input` types.**
- [x] `schema_parsers/protobuf.rs` (115 lines) — `service`/`rpc` parse. **No message field resolution.**
- [x] `schema_parsers/asyncapi.rs` (90 lines) — 2.x channels. **No 3.0 support. `required` always false.**

---

## Audit Findings Reference

### Root Cause

The 14 endpoint extractors operate on **raw source text** (`content: &str`) via line-by-line string matching — they do NOT consume `ParseResult`. This means:

1. **Extractors are NOT affected by Detector Parity parser bugs** — they don't use `ParseResult`.
2. **Extractors cannot extract request/response field schemas** — no access to function parameters, type annotations, or decorators. Every extractor produces `request_fields: vec![]` and `response_fields: vec![]`.
3. **Extractors are fragile** — multi-line definitions, variable receivers, and programmatic route registration are invisible.

### Critical Finding: All 14 Extractors Produce Empty Fields

| Evidence | Location | Value |
|----------|----------|-------|
| `express.rs` request_fields | L27 | `vec![]` |
| `express.rs` response_fields | L28 | `vec![]` |
| `fastify.rs` request_fields | L23 | `vec![]` |
| `nestjs.rs` request_fields | L34 | `vec![]` |
| `flask.rs` request_fields | L24 | `vec![]` |
| `django.rs` request_fields | L22 | `vec![]` |
| `spring.rs` request_fields | L34 | `vec![]` |
| `rails.rs` request_fields | L27 | `vec![]` |
| `laravel.rs` request_fields | L23 | `vec![]` |
| `aspnet.rs` request_fields | L32 | `vec![]` |
| `gin.rs` request_fields | L23 | `vec![]` |
| `actix.rs` request_fields | L24 | `vec![]` |
| `frontend.rs` request_fields | L24 | `vec![]` |
| `trpc.rs` request_fields | L21 | `vec![]` |
| `nextjs.rs` request_fields | L28 | `vec![]` |

### Cascade Impact

| Downstream System | Location | Impact |
|-------------------|----------|--------|
| **Breaking changes** | `breaking_changes.rs:41-95` | FieldRemoved/TypeChanged/OptionalToRequired/RequiredAdded never fire — no fields to compare |
| **Contract matching** | `matching.rs:49-53` | `field_overlap()` always 0.0 — Signal 3 dead |
| **Confidence** | `confidence.rs:13-23` | Only 3/7 signals populated |
| **NAPI binding** | `drift-napi/bindings/structural.rs:109-117` | `drift_contract_tracking()` returns **hardcoded empty stub** |
| **Storage** | `drift-storage/queries/structural.rs:195-253` | Schema correct but never called with real data |
| **MCP/CLI/CI** | TS packages | All get empty contract results |

### Breaking Change Coverage: 5 of 19 Types Implemented

| Variant | Implemented | Location | Fires? |
|---------|------------|----------|--------|
| EndpointRemoved | ✅ | `breaking_changes.rs:25-35` | ✅ Yes |
| FieldRemoved | ✅ | `breaking_changes.rs:41-51` | ❌ No fields |
| TypeChanged | ✅ | `breaking_changes.rs:54-67` | ❌ No fields |
| OptionalToRequired | ✅ | `breaking_changes.rs:70-78` | ❌ No fields |
| RequiredAdded | ✅ | `breaking_changes.rs:83-95` | ❌ No fields |
| EnumValueRemoved | ❌ | — | — |
| PathChanged | ❌ | — | — |
| MethodChanged | ❌ | — | — |
| ResponseShapeChanged | ❌ | — | — |
| AuthRequirementAdded | ❌ | — | — |
| RateLimitAdded | ❌ | — | Non-breaking |
| DeprecationRemoved | ❌ | — | Non-breaking |
| VersionRemoved | ❌ | — | — |
| SchemaIncompatible | ❌ | — | — |
| FieldRenamed | ❌ | — | — |
| NullabilityChanged | ❌ | — | — |
| ArrayToScalar | ❌ | — | — |
| ScalarToArray | ❌ | — | — |
| DefaultRemoved | ❌ | — | — |
| ValidationAdded | ❌ | — | — |

### Extractor Pattern Gaps (line-verified)

| Extractor | Gap | Line(s) | Impact |
|-----------|-----|---------|--------|
| Express | Only `app.`/`router.` receivers | L17-20 | Misses `server.get()`, custom vars |
| Express | Line-by-line scan | L13 | Misses multi-line routes |
| Fastify | Only `fastify.` receiver | L17 | Misses `server.`/`app.` aliases |
| NestJS | No `@All`/`@Head`/`@Options` | L12-15 | 3 HTTP methods missing |
| Next.js | No route groups `(group)` | L63-83 | Wrong paths for grouped routes |
| tRPC | v9 pattern only | L15 | v10/v11 builder pattern invisible |
| Django | `@api_view` stub | L32-35 | DRF views not extracted |
| Django | No `include()` | L16 | Nested URL prefixes invisible |
| Rails | Wrong `resources` paths | L46-57 | All 5 methods get same path |
| Rails | No `namespace`/`scope` | L10-60 | Route prefixes invisible |
| Gin | No `Group()` handling | L10-33 | Route prefixes invisible |
| Gin | `.GET(` too broad | L18-19 | Matches non-gin code |
| Actix | No `#[route()]` macro | L12-15 | Multi-method routes missed |
| Frontend | `useMutation` not extracted | L11-67 | Detected in `matches()` but not `extract()` |
| Frontend | Same-line method inference | L79-96 | Multi-line fetch defaults to GET |

### Schema Parser Gaps (line-verified)

| Parser | Gap | Line(s) | Impact |
|--------|-----|---------|--------|
| OpenAPI | No `$ref` resolution | L131-162 | Referenced schemas produce no fields |
| OpenAPI | No `allOf`/`oneOf`/`anyOf` | L131-162 | Composed schemas empty |
| OpenAPI | No array `items` | L144-148 | Array type info lost |
| GraphQL | Exact string match fragile | L17-31 | Whitespace variations fail |
| GraphQL | No `extend type` | L16-32 | Extended fields invisible |
| GraphQL | No `input` types | L14 | Request schemas invisible |
| Protobuf | No message resolution | L82-114 | Only type names, not fields |
| AsyncAPI | No 3.0 support | L26 | `operations` key invisible |
| AsyncAPI | `required` always false | L81 | All fields appear optional |
| All 4 | Line numbers always 0 | Various | No source location tracking |

---

## Phase A: Extractor Robustness & Coverage Gaps

> **Goal:** Fix pattern matching in all 14 extractors for robust path/method detection.
> **Estimated effort:** 2–3 days
> **Depends on:** Nothing — extractors use raw text.

### A1 — Express (`express.rs`)
- [ ] `CE-EXP-01` — Add configurable receiver list (`server.`, `api.`, any var when file has `require('express')`)
- [ ] `CE-EXP-02` — Handle multi-line route definitions (accumulate lines until closing `)`)
- [ ] `CE-EXP-03` — Handle `app.use('/prefix', router)` middleware path prefixes

### A2 — Fastify (`fastify.rs`)
- [ ] `CE-FAST-01` — Add `server.`/`app.`/`instance.` aliases when file contains `fastify`
- [ ] `CE-FAST-02` — Detect `schema:` key presence for future field extraction

### A3 — NestJS (`nestjs.rs`)
- [ ] `CE-NEST-01` — Add `@All(`, `@Head(`, `@Options(` decorators
- [ ] `CE-NEST-02` — Handle `@Controller()` with no path → mount at `/`

### A4 — Next.js (`nextjs.rs`)
- [ ] `CE-NEXT-01` — Strip route groups `(group)` from file paths
- [ ] `CE-NEXT-02` — Convert `[id]` → `:id` and `[...slug]` → `*slug` dynamic segments

### A5 — tRPC (`trpc.rs`)
- [ ] `CE-TRPC-01` — Support v10/v11 builder: `getUser: publicProcedure.query(...)` pattern
- [ ] `CE-TRPC-02` — Extract router namespace from nested `router({})` calls

### A6 — Django (`django.rs`)
- [ ] `CE-DJNG-01` — Wire `@api_view` decorator → create endpoint from next `def` line
- [ ] `CE-DJNG-02` — Handle `include()` nesting for URL prefixes
- [ ] `CE-DJNG-03` — Handle DRF `@action(detail=True, methods=['post'])` decorator

### A7 — Rails (`rails.rs`)
- [ ] `CE-RAIL-01` — Fix `resources` to generate `/users` + `/users/:id` paths correctly
- [ ] `CE-RAIL-02` — Handle `namespace`/`scope` block prefixes

### A8 — Gin (`gin.rs`)
- [ ] `CE-GIN-01` — Handle `Group()` path prefixes via variable tracking
- [ ] `CE-GIN-02` — Gate `.GET(` matching to files containing gin imports

### A9 — Actix (`actix.rs`)
- [ ] `CE-ACTX-01` — Handle `#[route("/path", method = "GET", method = "POST")]` multi-method macro

### A10 — Frontend (`frontend.rs`)
- [ ] `CE-FE-01` — Extract `useMutation(` calls (detected in `matches()` but not `extract()`)
- [ ] `CE-FE-02` — Multi-line fetch method inference (lookahead 3 lines for `method:`)

### Phase A Tests
- [ ] `CET-EXP-01` — `app.get('/users', handler)` → GET /users
- [ ] `CET-EXP-02` — `server.get('/api/items', handler)` → detected with custom receiver
- [ ] `CET-EXP-03` — Multi-line route → detected
- [ ] `CET-FAST-01` — `server.get('/users', handler)` → detected when file has `fastify`
- [ ] `CET-NEST-01` — `@All('/proxy')` → detected
- [ ] `CET-NEST-02` — `@Controller()` + `@Get('users')` → path=/users
- [ ] `CET-NEXT-01` — `app/api/(auth)/login/route.ts` → /api/login
- [ ] `CET-NEXT-02` — `app/api/users/[id]/route.ts` → /api/users/:id
- [ ] `CET-TRPC-01` — v10: `getUser: publicProcedure.query(...)` → path=getUser
- [ ] `CET-DJNG-01` — `@api_view(['GET', 'POST'])` + `def user_list` → 2 endpoints
- [ ] `CET-DJNG-02` — `path('api/', include(...))` → prefix tracked
- [ ] `CET-RAIL-01` — `resources :users` → 5 endpoints with `/users` and `/users/:id`
- [ ] `CET-RAIL-02` — `namespace :api do get '/status' end` → /api/status
- [ ] `CET-GIN-01` — `v1 := r.Group("/api/v1"); v1.GET("/users", h)` → /api/v1/users
- [ ] `CET-GIN-02` — `.GET(` in non-gin file → NOT matched
- [ ] `CET-ACTX-01` — `#[route("/path", method="GET", method="POST")]` → 2 endpoints
- [ ] `CET-FE-01` — `useMutation('/api/users')` → POST /api/users
- [ ] `CET-FE-02` — Multi-line fetch with method on next line → correct method
- [ ] `CET-REG-01` — All existing `contracts_test.rs` tests pass
- [ ] `CET-REG-02` — All existing `stress_contracts_test.rs` tests pass
- [ ] `CET-REG-03` — `e2e_full_pipeline_test.rs` contract sections pass
- [ ] `CET-LARA-01` — `Route::get('/users', ...)` → GET /users (existing, verify)
- [ ] `CET-ASPN-01` — `[HttpGet("users")]` + `[Route("api")]` → GET api/users (existing, verify)
- [ ] `CET-FLASK-01` — `@app.route('/users', methods=['GET','POST'])` → 2 endpoints (existing, verify)

### Quality Gate A (QG-A)
```
MUST PASS before Phase B begins:
- [ ] Express detects routes with custom receivers
- [ ] NestJS handles all 8 HTTP method decorators
- [ ] Next.js strips route groups and converts dynamic segments
- [ ] tRPC handles v10/v11 builder pattern
- [ ] Django @api_view creates endpoints
- [ ] Rails resources generates correct RESTful paths
- [ ] Gin Group() prefixes tracked
- [ ] Frontend useMutation extracted
- [ ] All CET-* Phase A tests pass
- [ ] cargo clippy clean, cargo test green
```

---

## Phase B: Schema Parser Completeness

> **Goal:** Fix 4 schema parsers: $ref resolution, composed types, message resolution, format versions.
> **Estimated effort:** 1.5–2 days
> **Depends on:** Nothing — schema parsers use raw content.

### B1 — OpenAPI (`openapi.rs`)
- [ ] `CE-OA-01` — Implement `$ref` resolution (navigate JSON pointer, resolve `#/components/schemas/X`, circular ref guard)
- [ ] `CE-OA-02` — Handle `allOf`/`oneOf`/`anyOf` (merge or union fields)
- [ ] `CE-OA-03` — Handle array `items` (set field_type to `array<ItemType>`)
- [ ] `CE-OA-04` — Handle OpenAPI 3.1 `type: ["string", "null"]` → nullable=true

### B2 — GraphQL (`graphql.rs`)
- [ ] `CE-GQL-01` — Handle whitespace variations in `type Query {` declarations
- [ ] `CE-GQL-02` — Handle `extend type Query { ... }` (merge with base)
- [ ] `CE-GQL-03` — Parse `input` type blocks for request field schemas

### B3 — Protobuf (`protobuf.rs`)
- [ ] `CE-PB-01` — Resolve `message` definitions → extract individual fields into request/response
- [ ] `CE-PB-02` — Handle `stream` keyword in rpc returns

### B4 — AsyncAPI (`asyncapi.rs`)
- [ ] `CE-AA-01` — Add AsyncAPI 3.0 `operations` key support
- [ ] `CE-AA-02` — Resolve `$ref` in messages
- [ ] `CE-AA-03` — Fix `required` field extraction (check `required` array, not hardcode false)

### Phase B Tests
- [ ] `CET-OA-01` — `$ref: '#/components/schemas/User'` → User fields extracted
- [ ] `CET-OA-02` — `allOf` → merged fields
- [ ] `CET-OA-03` — `type: "array", items: {$ref}` → array<ItemType>
- [ ] `CET-OA-04` — OpenAPI 3.1 nullable → nullable=true
- [ ] `CET-OA-05` — Circular `$ref` → no infinite loop
- [ ] `CET-GQL-01` — `type Query{` (no space) → fields extracted
- [ ] `CET-GQL-02` — `extend type Query { ... }` → merged
- [ ] `CET-GQL-03` — `input CreateUserInput { name: String! }` → parsed
- [ ] `CET-PB-01` — `rpc GetUser(Req) returns (Resp)` + message defs → individual fields
- [ ] `CET-PB-02` — `returns (stream User)` → streaming indicated
- [ ] `CET-AA-01` — AsyncAPI 3.0 `operations` → channels extracted
- [ ] `CET-AA-02` — `$ref` in message → resolved
- [ ] `CET-AA-03` — `required: ["name"]` → name.required=true
- [ ] `CET-AA-04` — AsyncAPI 2.x still works (regression)

### Quality Gate B (QG-B)
```
MUST PASS before Phase C begins:
- [ ] OpenAPI $ref produces non-empty fields
- [ ] OpenAPI allOf merges fields
- [ ] GraphQL handles whitespace variations
- [ ] Protobuf message fields resolved
- [ ] AsyncAPI 3.0 operations parsed
- [ ] AsyncAPI required fields correct
- [ ] No circular $ref causes infinite loop
- [ ] All CET-* Phase B tests pass
- [ ] cargo clippy clean, cargo test green
```

---

## Phase C: Field Extraction (ParseResult Integration)

> **Goal:** Integrate `ParseResult` into extractors to populate `request_fields`/`response_fields`.
> **Estimated effort:** 3–4 days
> **Depends on:** Detector Parity Phase A (parser must populate `func.parameters`, `func.decorators`, `func.return_type`).

### C1 — Trait Extension
- [ ] `CE-TRAIT-01` — Add `extract_with_context(&self, content, file_path, parse_result: Option<&ParseResult>) -> Vec<Endpoint>` to `EndpointExtractor`. Default calls `extract()`. Update `ExtractorRegistry.extract_all()`.
- [ ] `CE-TRAIT-02` — Add shared helpers: `params_to_fields()`, `return_type_to_fields()` in `extractors/mod.rs`

### C2 — Express Fields
- [ ] `CE-EXP-F01` — Extract request fields from `req.params`/`req.query`/`req.body` usage in handler
- [ ] `CE-EXP-F02` — Extract response fields from `res.json({...})` calls

### C3 — NestJS Fields
- [ ] `CE-NEST-F01` — Extract from `@Body()`, `@Param()`, `@Query()` parameter decorators
- [ ] `CE-NEST-F02` — Resolve DTO class properties as request fields

### C4 — Spring Fields
- [ ] `CE-SPR-F01` — Extract from `@RequestParam`, `@RequestBody`, `@PathVariable` annotations
- [ ] `CE-SPR-F02` — Extract response type from `ResponseEntity<T>` return type

### C5 — Flask Fields
- [ ] `CE-FLASK-F01` — Extract from `request.args.get('name')`, `request.json['field']` usage

### C6 — Django/DRF Fields
- [ ] `CE-DJNG-F01` — Extract from serializer class field definitions

### C7 — ASP.NET Fields
- [ ] `CE-ASPN-F01` — Extract from `[FromBody]`/`[FromQuery]`/`[FromRoute]` parameter attributes

### C8 — Actix Fields
- [ ] `CE-ACTX-F01` — Extract from `web::Json<T>`, `web::Query<T>`, `web::Path<T>` handler params

### C9 — Gin Fields
- [ ] `CE-GIN-F01` — Extract from `c.ShouldBindJSON(&req)`, `c.Query("name")`, `c.Param("id")` calls

### C10 — Frontend Fields
- [ ] `CE-FE-F01` — Extract request fields from fetch body / axios data object keys

### C11 — Wire Confidence Signals
- [ ] `CE-CONF-01` — Populate signals 3-5 in `match_contracts()` now that fields exist (type compat, response shape, temporal stability)
- [ ] `CE-CONF-02` — Populate all 7 mismatch types in `detect_mismatches()` (TypeMismatch, RequiredOptional, EnumValue, NestedShape, ArrayScalar, Nullable)

### Phase C Tests
- [ ] `CET-EXP-F01` — Express handler using `req.query.name` → request_fields contains {name, string, false}
- [ ] `CET-EXP-F02` — Express `res.json({ id, name })` → response_fields contains id, name
- [ ] `CET-NEST-F01` — NestJS `@Body() dto: CreateUserDto` → request_fields from DTO
- [ ] `CET-SPR-F01` — Spring `@RequestParam String name` → request_fields contains name
- [ ] `CET-SPR-F02` — Spring `ResponseEntity<User>` → response_fields from User type
- [ ] `CET-FLASK-F01` — Flask `request.args.get('page')` → request_fields contains page
- [ ] `CET-DJNG-F01` — DRF serializer with `fields = ['id', 'name']` → fields extracted
- [ ] `CET-ASPN-F01` — ASP.NET `[FromBody] CreateUserRequest req` → request_fields
- [ ] `CET-ACTX-F01` — Actix `web::Json<CreateUser>` → request_fields from CreateUser
- [ ] `CET-GIN-F01` — Gin `c.Query("page")` → request_fields contains page
- [ ] `CET-FE-F01` — `axios.post(url, { name, email })` → request_fields contains name, email
- [ ] `CET-CONF-01` — `match_contracts()` with populated fields → field_overlap > 0
- [ ] `CET-CONF-02` — `detect_mismatches()` detects TypeMismatch when field types differ
- [ ] `CET-MATCH-01` — BE response `{id: number}` vs FE expecting `{id: string}` → TypeMismatch
- [ ] `CET-MATCH-02` — BE response `{name: required}` vs FE not using name → FieldMissing
- [ ] `CET-MATCH-03` — `bayesian_confidence()` with 5+ signals → higher confidence than 3 signals
- [ ] `CET-REG-C01` — All existing tests still pass after trait extension
- [ ] `CET-REG-C02` — Extractors without ParseResult still work (graceful fallback)

### Quality Gate C (QG-C)
```
MUST PASS before Phase D begins:
- [ ] At least 5 extractors produce non-empty request_fields with ParseResult
- [ ] At least 3 extractors produce non-empty response_fields
- [ ] field_overlap() returns > 0 when BE/FE have matching fields
- [ ] detect_mismatches() fires TypeMismatch on type differences
- [ ] Extractors without ParseResult gracefully fall back to empty fields
- [ ] All CET-* Phase C tests pass
- [ ] cargo clippy clean, cargo test green
```

---

## Phase D: Breaking Change Detection Completeness

> **Goal:** Implement the remaining 14 of 19 `BreakingChangeType` variants.
> **Estimated effort:** 1.5–2 days
> **Depends on:** Phase C (field data must exist for field-level change detection).

### D1 — Path & Method Changes
- [ ] `CE-BC-01` — **PathChanged** — Detect when an endpoint's path is renamed (fuzzy match old paths to new paths by method + field similarity)
- [ ] `CE-BC-02` — **MethodChanged** — Detect when an endpoint keeps its path but changes HTTP method

### D2 — Field-Level Changes
- [ ] `CE-BC-03` — **FieldRenamed** — Detect when a field disappears and a new field with similar type appears (Levenshtein on names)
- [ ] `CE-BC-04` — **NullabilityChanged** — Detect `nullable: false → true` or vice versa
- [ ] `CE-BC-05` — **ArrayToScalar / ScalarToArray** — Detect `type: array → type: string` and vice versa
- [ ] `CE-BC-06` — **DefaultRemoved** — Detect when a field that had a default value loses it
- [ ] `CE-BC-07` — **ValidationAdded** — Detect when new validation constraints (minLength, pattern, enum restriction) are added

### D3 — Schema-Level Changes
- [ ] `CE-BC-08` — **EnumValueRemoved** — Detect when an enum field loses a value
- [ ] `CE-BC-09` — **ResponseShapeChanged** — Detect when response nesting changes (flat → nested or vice versa)
- [ ] `CE-BC-10` — **SchemaIncompatible** — Detect when the entire response schema type changes (object → array, etc.)

### Phase D Tests
- [ ] `CET-BC-01` — Path `/users` → `/v2/users` → PathChanged detected
- [ ] `CET-BC-02` — Method GET → POST on same path → MethodChanged detected
- [ ] `CET-BC-03` — Field `userName` removed + `user_name` added → FieldRenamed detected
- [ ] `CET-BC-04` — `nullable: false → true` → NullabilityChanged detected
- [ ] `CET-BC-05` — `type: string → type: array` → ScalarToArray detected
- [ ] `CET-BC-06` — Field with default removed → DefaultRemoved detected
- [ ] `CET-BC-07` — New `minLength: 3` added → ValidationAdded detected
- [ ] `CET-BC-08` — Enum `["active","inactive"]` → `["active"]` → EnumValueRemoved detected
- [ ] `CET-BC-09` — `{name: string}` → `{user: {name: string}}` → ResponseShapeChanged
- [ ] `CET-BC-10` — `{id: number}` → `[{id: number}]` → SchemaIncompatible
- [ ] `CET-BC-11` — `is_breaking()` returns false for RateLimitAdded, DeprecationRemoved
- [ ] `CET-BC-12` — EndpointRemoved still works (regression)
- [ ] `CET-BC-13` — FieldRemoved now fires with populated fields
- [ ] `CET-BC-14` — TypeChanged now fires with populated fields

### Quality Gate D (QG-D)
```
MUST PASS before Phase E begins:
- [ ] At least 12 of 19 BreakingChangeType variants implemented
- [ ] PathChanged and MethodChanged detect renames
- [ ] Field-level changes fire with populated field data
- [ ] is_breaking() correctly classifies breaking vs non-breaking
- [ ] All CET-* Phase D tests pass
- [ ] cargo clippy clean, cargo test green
```

---

## Phase E: NAPI Wiring, Downstream Integration & Regression

> **Goal:** Wire `drift_contract_tracking()` NAPI binding to real extraction. Verify full pipeline. Performance.
> **Estimated effort:** 2–3 days
> **Depends on:** Phases A–D complete.

### E1 — Wire NAPI Binding
- [ ] `CE-NAPI-01` — **Wire `drift_contract_tracking()`** — Replace the stub at `drift-napi/bindings/structural.rs:109-117` with real logic: walk the file tree, run `ExtractorRegistry.extract_all()` on source files, run schema parsers on schema files, collect all endpoints and mismatches, populate `JsContractResult`.
- [ ] `CE-NAPI-02` — **Add `JsBreakingChange` type** — Add a NAPI struct for breaking changes and a `drift_breaking_changes(old_root, new_root)` function that compares two versions.
- [ ] `CE-NAPI-03` — **Wire storage** — After extraction, call `upsert_contract()` to persist results to SQLite.

### E2 — Wire Matching Pipeline
- [ ] `CE-PIPE-01` — **Add `drift_contract_match()` NAPI function** — Accept root path, run extraction, separate BE/FE endpoints, run `match_contracts()`, return `Vec<JsContractMatch>`.
- [ ] `CE-PIPE-02` — **Index-based matching** — Replace O(n²) matching with path-indexed lookup for large codebases.

### E3 — Performance
- [ ] `CE-PERF-01` — **Extraction benchmark** — 500 source files through all 14 extractors < 2s
- [ ] `CE-PERF-02` — **Schema parse benchmark** — 50 OpenAPI specs with $ref resolution < 5s
- [ ] `CE-PERF-03` — **Breaking change benchmark** — 100 endpoint pairs comparison < 500ms

### Phase E Tests
- [ ] `CET-NAPI-01` — `drift_contract_tracking(root)` returns non-empty endpoints for Express project
- [ ] `CET-NAPI-02` — `drift_contract_tracking(root)` returns non-empty endpoints for Spring project
- [ ] `CET-NAPI-03` — `drift_contract_tracking(root)` returns non-empty endpoints for OpenAPI spec
- [ ] `CET-NAPI-04` — `drift_breaking_changes(old, new)` detects EndpointRemoved
- [ ] `CET-NAPI-05` — `drift_breaking_changes(old, new)` detects FieldRemoved
- [ ] `CET-PIPE-01` — `drift_contract_match(root)` matches BE Express endpoint to FE fetch call
- [ ] `CET-PIPE-02` — `drift_contract_match(root)` detects FieldMissing mismatch
- [ ] `CET-STORE-01` — `upsert_contract()` + `get_contract()` round-trips correctly
- [ ] `CET-STORE-02` — `get_contracts_by_paradigm("rest")` returns stored contracts
- [ ] `CET-E2E-01` — Full pipeline: Express app → extract → match → detect mismatches → store → NAPI
- [ ] `CET-E2E-02` — Full pipeline: OpenAPI spec → parse → extract fields → breaking changes
- [ ] `CET-E2E-03` — Full pipeline: GraphQL schema → parse → extract fields → breaking changes
- [ ] `CET-E2E-04` — Multi-framework: Express + Django in same project → both extracted
- [ ] `CET-PERF-01` — 500 files extraction < 2s
- [ ] `CET-PERF-02` — 50 OpenAPI specs < 5s
- [ ] `CET-PERF-03` — 100 endpoint pairs breaking change < 500ms

### Quality Gate E (QG-E) — FINAL
```
ALL must pass — this is the completion gate:
- [ ] drift_contract_tracking() returns real data (not stub)
- [ ] At least 10 of 14 extractors produce endpoints on real-world code
- [ ] At least 3 of 4 schema parsers produce endpoints with non-empty fields
- [ ] Breaking change detection covers >= 12 of 19 types
- [ ] Contract matching produces matches with confidence > 0.5
- [ ] Mismatch detection fires for at least 3 of 7 types
- [ ] Storage round-trip works
- [ ] All CET-* Phase E tests pass
- [ ] All existing tests still pass (zero regressions)
- [ ] Performance benchmarks pass
- [ ] cargo clippy --workspace -- -D warnings clean
- [ ] cargo test --workspace passes
```

---

## Dependency Graph

```
Phase A (Extractor Robustness)  ──→  Phase C (Field Extraction)  ──→  Phase D (Breaking Changes)
                                           │                                │
Phase B (Schema Parsers)  ────────────────┘                                │
                                                                           │
                                                                     Phase E (NAPI + Integration)
```

**Critical path:** A (2-3d) → C (3-4d) → D (1.5-2d) → E (2-3d) = **9-12 days**
**Parallel work:** B can run in parallel with A. D can start as soon as C completes.
**External dependency:** Phase C requires Detector Parity Phase A (parser extraction).
**Total calendar time:** 9-12 working days (7-9 if B parallelizes with A).

---

## Files Modified Summary

| File | Phase | Change Type |
|------|-------|-------------|
| `extractors/mod.rs` | A, C | Trait extension + helpers |
| `extractors/express.rs` | A, C | Pattern + field extraction |
| `extractors/fastify.rs` | A, C | Pattern + field extraction |
| `extractors/nestjs.rs` | A, C | Pattern + field extraction |
| `extractors/nextjs.rs` | A | Pattern fixes |
| `extractors/trpc.rs` | A | v10/v11 support |
| `extractors/flask.rs` | C | Field extraction |
| `extractors/django.rs` | A, C | @api_view + field extraction |
| `extractors/spring.rs` | C | Field extraction |
| `extractors/rails.rs` | A | Path generation fix |
| `extractors/laravel.rs` | — | No changes needed (works correctly for basic cases) |
| `extractors/aspnet.rs` | C | Field extraction |
| `extractors/gin.rs` | A, C | Group() + field extraction |
| `extractors/actix.rs` | A, C | #[route] + field extraction |
| `extractors/frontend.rs` | A, C | useMutation + field extraction |
| `schema_parsers/openapi.rs` | B | $ref, allOf, items |
| `schema_parsers/graphql.rs` | B | Whitespace, extend, input |
| `schema_parsers/protobuf.rs` | B | Message resolution |
| `schema_parsers/asyncapi.rs` | B | 3.0 support, $ref, required |
| `breaking_changes.rs` | D | 14 new change type implementations |
| `matching.rs` | C | Mismatch detection + confidence |
| `confidence.rs` | C | Signal population |
| `drift-napi/bindings/structural.rs` | E | Wire to real extraction |
| `drift-storage/queries/structural.rs` | E | Wire storage calls |
