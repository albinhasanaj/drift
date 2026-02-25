# Contract Tracking (BE↔FE Matching, GraphQL, gRPC, Breaking Changes) — V2 Implementation Prep

> Comprehensive build specification for Drift v2's Contract Tracking subsystem (System 21).
> Synthesized from: 20-contracts/overview.md (architecture, pipeline, storage, query API),
> 20-contracts/detection.md (5-phase pipeline, path normalization, field comparison, confidence),
> 20-contracts/types.md (Contract, BackendEndpoint, FrontendApiCall, FieldMismatch, ContractField,
> ContractConfidence, ContractMetadata, ContractQuery, ContractStats — ~400 LOC),
> 20-contracts/storage.md (SQLite schema, ContractRepository, JSON legacy, dual backend),
> 20-contracts/mcp-tools.md (drift_contracts_list, dual backend support, pagination),
> 03-detectors/contracts-system.md (backend-endpoint-detector, frontend-type-detector,
> contract-matcher, schema-parser, Django/Spring/Laravel/ASP.NET extensions — ~4,750 LOC),
> 03-detectors/categories.md (Category 7: 6 contract detectors),
> 03-detectors/detector-contracts.md (ContractMatcher path similarity algorithm),
> 03-detectors/framework-detectors.md (Spring, ASP.NET, Laravel, Django extensions),
> .research/20-contracts/RECAP.md (v1 inventory: 18 files, ~4,750 LOC, 8 frameworks,
> 3 frontend libs, 5 mismatch types, 2 confidence signals, 27 limitations),
> .research/20-contracts/RESEARCH.md (R1-R12: OpenAPI 3.1, GraphQL spec, Protobuf/gRPC,
> AsyncAPI 3.0, breaking change classification, Pact CDC testing, tRPC, WebSocket,
> cross-service tracing, Rust-native engine, confidence improvements, API governance),
> .research/20-contracts/RECOMMENDATIONS.md (R1-R12: unified contract model, schema-first
> detection, code-first enhancement, breaking change classifier, enhanced confidence,
> contract testing integration, drift detection, cross-service tracing, enhanced storage,
> enhanced MCP tools, API governance, Rust-native engine),
> .research/03-detectors/AUDIT.md (R8 contract matching — OpenAPI, API evolution),
> .research/03-detectors/RESEARCH.md (R8 OpenAPI best practices),
> .research/03-detectors/RECOMMENDATIONS.md (R8 contract expansion),
> DRIFT-V2-FULL-SYSTEM-AUDIT.md (Cat 20 — Contracts: REST + GraphQL + gRPC,
> backend framework support, frontend library support, path similarity, verification,
> protocol expansion, breaking change detection),
> DRIFT-V2-STACK-HIERARCHY.md (Level 2C — Structural Intelligence, self-contained,
> doesn't feed other systems, consumed by quality gates/MCP/CLI),
> DRIFT-V2-SYSTEMS-REFERENCE.md §17 (Contract Tracking — TOC entry),
> 06-DETECTOR-SYSTEM.md §12 (Contract Detection System — unified model, REST preserved,
> GraphQL/gRPC new, FrameworkMiddleware trait, ApiParadigm enum, ContractSource enum,
> ApiOperation struct, GraphQLContractDetector, GrpcContractDetector,
> ContractMismatchDetector, 6 contract detectors),
> 02-STORAGE-V2-PREP.md (drift.db schema, batch writer, medallion architecture),
> 03-NAPI-BRIDGE-V2-PREP.md (command/query pattern, async tasks, napi-rs v3),
> 04-INFRASTRUCTURE-V2-PREP.md (thiserror, tracing, FxHashMap, rayon),
> 06-UNIFIED-ANALYSIS-ENGINE-V2-PREP.md (4-phase pipeline, ParseResult, GAST),
> 08-UNIFIED-LANGUAGE-PROVIDER-V2-PREP.md (EntryPointKind::GraphQL, framework detection),
> 07-BOUNDARY-DETECTION-V2-PREP.md (sensitive field classification for API exposure),
> 09-quality-gates/gates.md (contract compliance gate),
> 07-mcp/tools-by-category.md (drift_contracts_list — exploration category),
> 10-cli/commands.md (drift contracts: list/verify/diff subcommands),
> 13-advanced/simulation/scorers.md (breakingChanges, breakingChangeRisks),
> OpenAPI Specification 3.1.0 (https://spec.openapis.org/oas/v3.1.0),
> GraphQL Specification October 2021 (https://spec.graphql.org/October2021/),
> Protocol Buffers Language Guide proto3 (https://protobuf.dev/programming-guides/proto3/),
> AsyncAPI Specification v3.0.0 (https://www.asyncapi.com/docs/reference/specification/v3.0.0),
> oasdiff — OpenAPI diff tool (https://www.oasdiff.com/),
> tree-sitter-graphql (https://github.com/dralletje/tree-sitter-graphql),
> protox-parse — pure Rust protobuf compiler (https://lib.rs/crates/protox-parse),
> jsonschema crate (https://docs.rs/jsonschema),
> Pact Documentation (https://docs.pact.io/),
> PLANNING-DRIFT.md (D1-D7).
>
> Purpose: Everything needed to build the Contract Tracking subsystem from scratch.
> This is the DEDICATED deep-dive — the 06-DETECTOR-SYSTEM doc covers the trait-based
> detector framework; the 06-UNIFIED-ANALYSIS-ENGINE doc covers the per-file detection
> pipeline; this document covers the full contract tracking engine: multi-paradigm
> contract model, schema-first parsing (OpenAPI, GraphQL SDL, Protobuf, AsyncAPI),
> code-first extraction (REST 20+ frameworks, GraphQL code-first, gRPC, event-driven,
> tRPC), path normalization, endpoint matching, recursive field comparison, cross-language
> type normalization, breaking change classification, contract drift detection, temporal
> tracking, cross-service tracing, Bayesian confidence scoring, contract testing
> integration, API governance rules, and the full integration with quality gates,
> simulation, MCP tools, CLI, and storage.
> Every v1 feature accounted for. Zero feature loss. Every algorithm specified.
> Every type defined. Every integration point documented. Every architectural
> decision resolved.
> Generated: 2026-02-08

---

## Table of Contents

1. Architectural Position
2. V1 Complete Feature Inventory
3. V2 Architecture — Unified Contract Engine
4. Core Data Model (Unified Multi-Paradigm)
5. Phase 1: Spec File Discovery & Parsing
6. Phase 2: Schema-First Contract Extraction (OpenAPI, GraphQL SDL, Protobuf, AsyncAPI)
7. Phase 3: Code-First Backend Endpoint Extraction (20+ Frameworks)
8. Phase 4: Code-First Frontend/Consumer Extraction (15+ Libraries)
9. Phase 5: GraphQL Code-First Extraction
10. Phase 6: gRPC Server/Client Extraction
11. Phase 7: Event-Driven Contract Extraction
12. Phase 8: tRPC Extraction (TypeScript-Only)
13. Phase 9: Path Normalization & Endpoint Matching
14. Phase 10: Recursive Field Comparison & Type Normalization
15. Phase 11: Mismatch Detection & Severity Classification
16. Phase 12: Breaking Change Classifier (Cross-Paradigm)
17. Phase 13: Contract Drift Detection (Temporal Tracking)
18. Phase 14: Bayesian Confidence Scoring (7-Signal)
19. Phase 15: Contract Testing Integration (Pact, Spring Cloud Contract)
20. Phase 16: Cross-Service Contract Tracing
21. Phase 17: API Governance Rules Engine
22. Phase 18: Contract Health Score Calculation
23. Incremental Contract Analysis (Content-Hash + Dependency Tracking)
24. Integration with Unified Analysis Engine
25. Integration with Call Graph Builder
26. Integration with Boundary Detection
27. Integration with Quality Gates
28. Integration with Simulation Engine
29. Integration with DNA System
30. Storage Schema (drift.db Contract Tables)
31. NAPI Interface
32. MCP Tool Interface (8 Tools)
33. CLI Interface (drift contracts — 6 Subcommands)
34. Event Interface
35. Tracing & Observability
36. Performance Targets & Benchmarks
37. Build Order & Dependencies
38. V1 → V2 Feature Cross-Reference
39. Inconsistencies & Decisions
40. Risk Register

---

## 1. Architectural Position

Contract Tracking is **Level 2C — Structural Intelligence** in the Drift v2 stack
hierarchy. It is the system that discovers, matches, and monitors API contracts across
all paradigms (REST, GraphQL, gRPC, WebSocket, event-driven, tRPC) — answering the
critical question: "Does the consumer expect the same data the provider returns?"

It is the "silent failure killer" — catching type mismatches that compile fine but
break at runtime. A missing field in a REST response, a type change in a GraphQL
schema, a removed field number in a Protobuf message — these are the bugs that
pass CI, pass code review, and crash in production.

Per DRIFT-V2-STACK-HIERARCHY.md:

> Contract Tracking: BE↔FE matching, path similarity, schema compatibility,
> breaking changes. Important for full-stack. Self-contained — doesn't feed
> other systems.

Per DRIFT-V2-FULL-SYSTEM-AUDIT.md Category 20:

> Contract Tracking (Rust): Discovers API contracts between backend and frontend.
> Matches endpoint definitions (BE) ↔ API calls (FE). Tracks URL, HTTP method,
> request/response schemas, auth requirements. Backend framework support: Express,
> NestJS, FastAPI, Flask, Spring Boot, Laravel, Django, ASP.NET. Frontend library
> support: fetch, axios, React Query, SWR, Angular HttpClient. Path similarity
> algorithm: multi-factor weighted (segment names Jaccard, segment count, suffix
> match, resource name, parameter positions). Verification: schema compatibility
> checking, breaking change detection, unused endpoint detection, orphaned call
> detection. Protocol expansion: REST + GraphQL + gRPC + OpenAPI/Swagger.

### Core Thesis

Contract tracking is fundamentally a matching and comparison problem across API
boundaries. V1 solved this for REST with a 5-phase pipeline (extract → match →
compare → classify → store). V2 generalizes this to all API paradigms through a
unified contract model that normalizes REST endpoints, GraphQL queries/mutations,
gRPC methods, event-driven messages, WebSocket events, and tRPC procedures into
a common representation.

The key architectural insight: **the schema IS the contract**. For GraphQL, the
SDL defines every type and field. For gRPC, the `.proto` file defines every service
and message. For REST, the OpenAPI spec defines every endpoint and schema. V1 only
extracted contracts from code — V2 adds schema-first parsing as the "golden source
of truth" and detects implementation drift where code diverges from spec.

The second insight: **breaking changes are paradigm-specific**. Removing a REST
endpoint is always breaking. Adding a GraphQL field is always safe. Reusing a
Protobuf field number is always catastrophic. The breaking change classifier must
be paradigm-aware, not one-size-fits-all.

### What Lives Here

- Unified multi-paradigm contract model (REST, GraphQL, gRPC, WebSocket, event-driven, tRPC)
- Schema-first parsing: OpenAPI 3.0/3.1, GraphQL SDL, Protobuf, AsyncAPI 2.x/3.0
- Code-first extraction: 20+ backend frameworks, 15+ frontend/consumer libraries
- GraphQL code-first extraction (type-graphql, nexus, pothos, Strawberry, juniper, etc.)
- gRPC server/client extraction (grpc-js, grpcio, tonic, etc.)
- Event-driven extraction (Kafka, RabbitMQ, SNS/SQS, Redis pub/sub)
- tRPC router/procedure extraction (TypeScript-only)
- Path normalization across 10+ framework syntaxes
- Multi-factor weighted endpoint matching (5-factor path similarity)
- Recursive field comparison with cross-language type normalization
- Mismatch detection: 7 types (missing_in_consumer, missing_in_provider, type_mismatch,
  optionality_mismatch, nullability_mismatch, enum_mismatch, constraint_mismatch)
- Breaking change classifier: 20+ change types, 4 severity levels, paradigm-specific rules
- Contract drift detection: temporal tracking, spec-vs-code drift, coverage drift
- Bayesian confidence scoring: 7 signals, temporal decay, calibration tracking
- Contract testing integration: Pact, Spring Cloud Contract, Specmatic, Karate DSL
- Cross-service contract tracing: service graph, blast radius, dependency chains
- API governance rules engine: naming, versioning, pagination, error format, auth, docs
- Contract health score: multi-factor 0-100 score
- Incremental analysis: content-hash invalidation, dependency-aware propagation
- Contract result persistence (drift.db contract tables — 7 tables, 14 indexes)

### What Does NOT Live Here

- Import/export extraction from AST (lives in Unified Analysis Engine / Parsers)
- Call graph construction (lives in Call Graph Builder)
- Sensitive field classification (lives in Boundary Detection — consumed for API exposure)
- Quality gate evaluation (lives in Quality Gates — consumes contract data)
- Simulation scoring (lives in Simulation Engine — consumes breaking change data)
- MCP tool routing (lives in MCP Server)
- CLI command routing (lives in CLI)
- tRPC type resolution (lives in TypeScript layer — requires TS compiler API)

### Critical Path Position

```
Scanner (Level 0)
  → Parsers (Level 0) — AST extraction for all languages
    → Unified Language Provider (Level 1) — framework detection, ORM matchers
      → Unified Analysis Engine (Level 1) — per-file detection pipeline
        → Boundary Detection (Level 1) — sensitive field classification
          → Call Graph Builder (Level 1) — cross-service function tracing
            → Contract Tracking (Level 2C) ← YOU ARE HERE
              → Quality Gates (Level 3) — contract compliance gate
                → Simulation Engine (Level 4) — breaking change scoring
                  → MCP Tools (Level 5) — drift_contracts_* (8 tools)
                    → CLI (Level 5) — drift contracts (6 subcommands)
```

### Consumer Count: 6 Downstream Systems

| Consumer | What It Reads | Why |
|----------|--------------|-----|
| Quality Gates | Contract compliance assessment | Block merges with breaking changes or unverified contracts |
| Simulation Engine | Breaking change data, blast radius | "What if I change this endpoint?" scoring |
| MCP Tools | All contract data (8 tools) | AI-assisted contract analysis and verification |
| CLI | All contract data (6 subcommands) | Developer contract analysis |
| Context Generation | Contract info for API-related features | AI-ready contract summaries |
| CI Agent | Contract compliance in PR analysis | PR-level contract checking |

### Upstream Dependencies (Must Exist Before Contract Tracking)

| Dependency | What It Provides | Why Needed |
|-----------|-----------------|------------|
| Parsers (Level 0) | ParseResult with ASTs, decorators, imports | All endpoint/call extraction depends on parsing |
| Scanner (Level 0) | ScanDiff (added/modified/removed files) | Incremental analysis input, spec file discovery |
| Storage (Level 0) | DatabaseManager with batch writer | Persistence to drift.db |
| Unified Language Provider (Level 1) | Framework detection, language normalizers | Framework-specific extraction patterns |
| Unified Analysis Engine (Level 1) | Per-file detection pipeline, GAST | Detector integration for contract detectors |
| Call Graph Builder (Level 1) | Function→function edges, service boundaries | Cross-service tracing, transitive dependency analysis |
| Boundary Detection (Level 1) | DataAccessPoint, SensitiveField | API data exposure detection, risk scoring |
| Infrastructure (Level 0) | thiserror, tracing, DriftEventHandler, config | Error handling, observability, events |
| String Interning (Level 1) | ThreadedRodeo / RodeoReader | Memory-efficient path/endpoint IDs |

---

## 2. V1 Complete Feature Inventory

Every feature in v1 must be preserved in v2. This is the exhaustive inventory.

### 2.1 Backend Endpoint Extraction (8 Frameworks)

| # | Feature | Location | Status |
|---|---------|----------|--------|
| F1 | Express.js endpoint extraction (`app.get()`, `router.post()`) | backend-endpoint-detector.ts | PRESERVED |
| F2 | FastAPI endpoint extraction (`@app.get()`, `@router.post()`) | backend-endpoint-detector.ts | PRESERVED |
| F3 | Flask endpoint extraction (`@app.route()`) | backend-endpoint-detector.ts | PRESERVED |
| F4 | Django URL pattern extraction (`path()`, `re_path()`) | django/url-extractor.ts | PRESERVED |
| F5 | Django ViewSet action extraction (list, create, retrieve, update, destroy, @action) | django/viewset-extractor.ts | PRESERVED |
| F6 | Django Serializer field extraction (ModelSerializer, Meta.fields, nested) | django/serializer-extractor.ts | PRESERVED |
| F7 | Spring Boot endpoint extraction (@GetMapping, @PostMapping, @RestController) | spring/spring-endpoint-detector.ts | PRESERVED |
| F8 | Spring DTO field extraction (Java DTOs/records, @JsonProperty) | spring/dto-extractor.ts | PRESERVED |
| F9 | Laravel route extraction (Route::get(), resource controllers) | laravel/laravel-endpoint-detector.ts | PRESERVED |
| F10 | ASP.NET endpoint extraction ([HttpGet], [Route], controllers) | aspnet/aspnet-endpoint-detector.ts | PRESERVED |
| F11 | Go framework endpoint extraction (Gin, Echo, Fiber, Chi) | api detectors (partial) | PRESERVED + ENHANCED |
| F12 | HTTP method extraction from decorators/function names | All framework detectors | PRESERVED |
| F13 | Response field extraction from return types/schemas | All framework detectors | PRESERVED |
| F14 | Request field extraction from parameter annotations | All framework detectors | PRESERVED |
| F15 | Framework auto-detection from imports/decorators | backend-endpoint-detector.ts | PRESERVED |

### 2.2 Frontend API Call Extraction (3+ Libraries)

| # | Feature | Location | Status |
|---|---------|----------|--------|
| F16 | fetch() API call extraction | frontend-type-detector.ts | PRESERVED |
| F17 | axios HTTP client extraction (axios.get<T>(), etc.) | frontend-type-detector.ts | PRESERVED |
| F18 | Custom API client extraction | frontend-type-detector.ts | PRESERVED |
| F19 | react-query extraction (useQuery<T>()) | frontend-type-detector.ts | PRESERVED |
| F20 | Angular HttpClient extraction (this.http.get<T>()) | frontend-type-detector.ts | PRESERVED |
| F21 | Generic type parameter extraction (axios.get<User[]>) | frontend-type-detector.ts | PRESERVED |
| F22 | Type assertion extraction (res.json() as User[]) | frontend-type-detector.ts | PRESERVED |
| F23 | Variable type annotation extraction (const data: User[]) | frontend-type-detector.ts | PRESERVED |
| F24 | TypeScript interface resolution to extract fields | frontend-type-detector.ts | PRESERVED |

### 2.3 Path Normalization & Matching

| # | Feature | Location | Status |
|---|---------|----------|--------|
| F25 | Express path normalization (`:id` → `:id`) | contract-matcher.ts | PRESERVED |
| F26 | FastAPI path normalization (`{id}` → `:id`) | contract-matcher.ts | PRESERVED |
| F27 | Flask path normalization (`<id>` → `:id`) | contract-matcher.ts | PRESERVED |
| F28 | Django path normalization (`<int:id>` → `:id`) | contract-matcher.ts | PRESERVED |
| F29 | Spring path normalization (`{id}` → `:id`) | contract-matcher.ts | PRESERVED |
| F30 | ASP.NET path normalization (`{id}` → `:id`) | contract-matcher.ts | PRESERVED |
| F31 | Frontend template literal normalization (`${id}` → `:id`) | contract-matcher.ts | PRESERVED |
| F32 | Leading/trailing slash normalization | contract-matcher.ts | PRESERVED |
| F33 | Type annotation stripping (`<int:id>` → `:id`) | contract-matcher.ts | PRESERVED |
| F34 | Multi-factor path similarity (5 factors, configurable weights) | contract-matcher.ts | PRESERVED |
| F35 | Segment name Jaccard similarity | contract-matcher.ts | PRESERVED |
| F36 | Segment count penalty | contract-matcher.ts | PRESERVED |
| F37 | Suffix match scoring | contract-matcher.ts | PRESERVED |
| F38 | Resource name matching | contract-matcher.ts | PRESERVED |
| F39 | Parameter position alignment | contract-matcher.ts | PRESERVED |
| F40 | Exact path match (confidence 1.0) | contract-matcher.ts | PRESERVED |
| F41 | Fuzzy path match (confidence 0.5) | contract-matcher.ts | PRESERVED |

### 2.4 Field Comparison & Mismatch Detection

| # | Feature | Location | Status |
|---|---------|----------|--------|
| F42 | Recursive field comparison (nested objects) | contract-matcher.ts | PRESERVED |
| F43 | missing_in_frontend detection (warning) | contract-matcher.ts | PRESERVED → RENAMED missing_in_consumer |
| F44 | missing_in_backend detection (error) | contract-matcher.ts | PRESERVED → RENAMED missing_in_provider |
| F45 | type_mismatch detection (error) | contract-matcher.ts | PRESERVED |
| F46 | optionality_mismatch detection (warning) | contract-matcher.ts | PRESERVED |
| F47 | nullability_mismatch detection (warning) | contract-matcher.ts | PRESERVED |
| F48 | Cross-language type normalization (6 canonical types) | contract-matcher.ts | PRESERVED + ENHANCED |
| F49 | Dot-notation field paths for nested mismatches (user.email) | contract-matcher.ts | PRESERVED |
| F50 | Mismatch severity classification (error/warning/info) | contract-matcher.ts | PRESERVED |

### 2.5 Confidence Scoring

| # | Feature | Location | Status |
|---|---------|----------|--------|
| F51 | Match confidence (0.0-1.0) | contract-matcher.ts | PRESERVED + ENHANCED |
| F52 | Field extraction confidence (0.0-1.0) | contract-matcher.ts | PRESERVED + ENHANCED |
| F53 | Overall confidence formula (match×0.6 + field×0.4) | contract-matcher.ts | REPLACED (Bayesian) |
| F54 | Confidence levels (high ≥0.8, medium ≥0.5, low ≥0.3, uncertain) | types.ts | PRESERVED (thresholds adjusted) |

### 2.6 Contract Lifecycle & Storage

| # | Feature | Location | Status |
|---|---------|----------|--------|
| F55 | Contract status lifecycle (discovered → verified/mismatch/ignored) | types.ts | PRESERVED + EXTENDED (+ deprecated) |
| F56 | Contract ID generation (contract-{method}-{hash}) | contract creation | PRESERVED |
| F57 | SQLite contracts table | contract-repository.ts | PRESERVED + ENHANCED |
| F58 | SQLite contract_frontends table | contract-repository.ts | PRESERVED → RENAMED contract_consumers |
| F59 | UNIQUE(method, normalized_endpoint) constraint | schema.sql | PRESERVED → UNIQUE(paradigm, id) |
| F60 | CASCADE DELETE on frontends | schema.sql | PRESERVED |
| F61 | JSON columns for response_fields, mismatches | schema.sql | PRESERVED (mismatches normalized) |
| F62 | ContractRepository CRUD (create, read, update, delete, exists, count) | contract-repository.ts | PRESERVED |
| F63 | findByStatus query | contract-repository.ts | PRESERVED |
| F64 | findByMethod query | contract-repository.ts | PRESERVED |
| F65 | findByEndpoint query (LIKE match) | contract-repository.ts | PRESERVED |
| F66 | findWithMismatches query | contract-repository.ts | PRESERVED |
| F67 | verify() state transition | contract-repository.ts | PRESERVED |
| F68 | markMismatch() state transition | contract-repository.ts | PRESERVED |
| F69 | ignore() state transition | contract-repository.ts | PRESERVED |
| F70 | addFrontend() / getFrontends() | contract-repository.ts | PRESERVED → addConsumer/getConsumers |
| F71 | JSON file storage (.drift/contracts/) | contract-store.ts | REMOVED (v2 SQLite-only) |
| F72 | Hybrid contract store (SQLite↔JSON bridge) | hybrid-contract-store.ts | REMOVED (v2 SQLite-only) |
| F73 | Storage backend auto-detection (_source field) | contracts-list.ts | REMOVED (v2 SQLite-only) |
| F74 | Backup creation (.backups/) | contract-store.ts | PRESERVED (via workspace manager) |

### 2.7 MCP Integration

| # | Feature | Location | Status |
|---|---------|----------|--------|
| F75 | drift_contracts_list tool | contracts-list.ts | PRESERVED + ENHANCED |
| F76 | Status filtering (all/verified/mismatch/discovered) | contracts-list.ts | PRESERVED + EXTENDED |
| F77 | Cursor-based pagination | contracts-list.ts | PRESERVED |
| F78 | Contract stats (verified/mismatch/discovered counts) | contracts-list.ts | PRESERVED + ENHANCED |
| F79 | Warnings for contracts with mismatches | contracts-list.ts | PRESERVED |
| F80 | Next action suggestions | contracts-list.ts | PRESERVED |
| F81 | drift_validate_change contract checking | validate-change.ts | PRESERVED |
| F82 | drift_context API intent contract inclusion | context tools | PRESERVED |

### 2.8 Pipeline Integration

| # | Feature | Location | Status |
|---|---------|----------|--------|
| F83 | Contract scan as step 10 of scan pipeline | scan pipeline | PRESERVED |
| F84 | --no-contracts flag to skip contract scanning | scan options | PRESERVED |
| F85 | Setup wizard Phase 4 contract scanning | setup wizard | PRESERVED |
| F86 | ContractStore in MCP server initialization | MCP server | PRESERVED (via UnifiedStore) |
| F87 | SyncService contract sync (JSON↔SQLite) | sync-service.ts | REMOVED (v2 SQLite-only) |

### 2.9 Query API

| # | Feature | Location | Status |
|---|---------|----------|--------|
| F88 | ContractQuery filter (ids, status, method, endpoint, mismatches, confidence, search) | types.ts | PRESERVED + ENHANCED |
| F89 | ContractSortOptions (6 sort fields, asc/desc) | types.ts | PRESERVED + ENHANCED |
| F90 | ContractQueryOptions (filter + sort + pagination) | types.ts | PRESERVED |
| F91 | ContractQueryResult (contracts, total, hasMore, executionTime) | types.ts | PRESERVED |
| F92 | ContractStats (totalContracts, byStatus, byMethod, totalMismatches, mismatchesByType) | types.ts | PRESERVED + ENHANCED |

### 2.10 Schema Parsing

| # | Feature | Location | Status |
|---|---------|----------|--------|
| F93 | OpenAPI/Swagger schema parsing | schema-parser.ts | PRESERVED + ENHANCED |

**Total v1 features: 93. All preserved or enhanced. Zero feature loss.**

---

## 3. V2 Architecture — Unified Contract Engine

### 3.1 Design Philosophy

V2 replaces the REST-only TypeScript contract pipeline with a Rust-native, multi-paradigm
contract engine. The core principle: **normalize all API paradigms into a unified model,
then apply paradigm-agnostic matching, comparison, and classification algorithms**.

This means a GraphQL query mismatch and a REST field mismatch are represented identically
in the unified model — downstream consumers (quality gates, MCP tools, CLI) don't need
paradigm-specific logic.

### 3.2 Engine Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         CONTRACT ENGINE (Rust)                                  │
│                                                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                    SPEC-FIRST PARSERS                                    │   │
│  │  OpenAPI 3.0/3.1 │ GraphQL SDL │ Protobuf │ AsyncAPI 2.x/3.0          │   │
│  │  (serde_yaml/json)│(tree-sitter)│(protox)  │ (serde_yaml/json)         │   │
│  └────────────────────────────┬────────────────────────────────────────────┘   │
│                               │                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                    CODE-FIRST EXTRACTORS                                 │   │
│  │  REST (20+ fw)  │ GraphQL (8 fw) │ gRPC (5 fw) │ Events │ WebSocket   │   │
│  │  (tree-sitter)  │ (tree-sitter)  │ (tree-sitter)│(regex) │ (regex)     │   │
│  └────────────────────────────┬────────────────────────────────────────────┘   │
│                               │                                                 │
│                               ▼                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │              UNIFIED CONTRACT MODEL (ApiContract)                        │   │
│  │  paradigm │ operations[] │ types[] │ source │ status │ confidence       │   │
│  └────────────────────────────┬────────────────────────────────────────────┘   │
│                               │                                                 │
│  ┌────────────┬───────────────┼───────────────┬────────────────────────────┐   │
│  │            │               │               │                            │   │
│  ▼            ▼               ▼               ▼                            ▼   │
│ ┌──────┐ ┌────────┐ ┌──────────────┐ ┌──────────────┐ ┌────────────────┐     │
│ │Match │ │Compare │ │  Breaking    │ │  Confidence  │ │  Governance    │     │
│ │Engine│ │Engine  │ │  Change     │ │  Scorer      │ │  Rules         │     │
│ │      │ │        │ │  Classifier │ │  (Bayesian)  │ │  Engine        │     │
│ └──┬───┘ └───┬────┘ └──────┬──────┘ └──────┬──────┘ └───────┬────────┘     │
│    │         │              │               │                │               │
│    └─────────┴──────────────┴───────────────┴────────────────┘               │
│                               │                                                 │
│                               ▼                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │              STORAGE (drift.db — 7 tables, 14 indexes)                   │   │
│  │  contracts │ contract_operations │ contract_types │ contract_fields      │   │
│  │  contract_mismatches │ contract_consumers │ contract_breaking_changes    │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
                               │
                    ┌──────────┼──────────┐
                    ▼          ▼          ▼
              ┌──────────┐ ┌──────┐ ┌──────┐
              │NAPI Bridge│ │Events│ │Tracing│
              │(8 exports)│ │      │ │      │
              └──────────┘ └──────┘ └──────┘
                    │
         ┌─────────┼─────────┐
         ▼         ▼         ▼
    ┌──────────┐ ┌────┐ ┌──────────┐
    │MCP Tools │ │CLI │ │Quality   │
    │(8 tools) │ │(6) │ │Gates     │
    └──────────┘ └────┘ └──────────┘
```

### 3.3 Rust Module Structure

```
crates/drift-core/src/contracts/
├── mod.rs                      // Module root, ContractEngine public API
├── model.rs                    // Unified contract model (§4 — all types)
├── config.rs                   // ContractConfig, framework registry, governance rules
├── parsers/
│   ├── mod.rs                  // Parser registry, spec file discovery
│   ├── openapi.rs              // OpenAPI 3.0/3.1 parser (serde_yaml + serde_json)
│   ├── graphql.rs              // GraphQL SDL parser (tree-sitter-graphql)
│   ├── protobuf.rs             // Protobuf parser (protox-parse)
│   ├── asyncapi.rs             // AsyncAPI 2.x/3.0 parser (serde_yaml + serde_json)
│   └── spec_discovery.rs       // Spec file discovery (standard locations + patterns)
├── extractors/
│   ├── mod.rs                  // Extractor registry, framework detection
│   ├── rest/
│   │   ├── mod.rs              // REST extractor dispatcher
│   │   ├── express.rs          // Express/Koa/NestJS extraction
│   │   ├── fastapi.rs          // FastAPI extraction
│   │   ├── flask.rs            // Flask extraction
│   │   ├── django.rs           // Django URL + ViewSet + Serializer extraction
│   │   ├── spring.rs           // Spring Boot extraction + DTO extractor
│   │   ├── aspnet.rs           // ASP.NET extraction
│   │   ├── laravel.rs          // Laravel extraction
│   │   ├── go_frameworks.rs    // Gin, Echo, Fiber, Chi extraction
│   │   ├── rust_frameworks.rs  // Actix, Axum, Rocket extraction
│   │   ├── ruby_frameworks.rs  // Rails, Sinatra extraction
│   │   └── kotlin_frameworks.rs // Ktor, Spring Kotlin extraction
│   ├── graphql/
│   │   ├── mod.rs              // GraphQL code-first dispatcher
│   │   ├── type_graphql.rs     // type-graphql (TS) extraction
│   │   ├── nexus.rs            // Nexus (TS) extraction
│   │   ├── pothos.rs           // Pothos (TS) extraction
│   │   ├── strawberry.rs       // Strawberry (Python) extraction
│   │   ├── juniper.rs          // juniper (Rust) extraction
│   │   └── dgs.rs              // DGS Framework (Java) extraction
│   ├── grpc/
│   │   ├── mod.rs              // gRPC extractor dispatcher
│   │   ├── grpc_js.rs          // @grpc/grpc-js, nice-grpc extraction
│   │   ├── grpcio.rs           // grpcio (Python) extraction
│   │   ├── tonic.rs            // tonic (Rust) extraction
│   │   └── io_grpc.rs          // io.grpc (Java) extraction
│   ├── events/
│   │   ├── mod.rs              // Event-driven extractor dispatcher
│   │   ├── kafka.rs            // kafkajs, confluent-kafka, sarama extraction
│   │   ├── rabbitmq.rs         // amqplib, pika, lapin extraction
│   │   └── aws_messaging.rs    // SNS/SQS SDK extraction
│   └── consumers/
│       ├── mod.rs              // Consumer extractor dispatcher
│       ├── fetch.rs            // Native fetch API extraction
│       ├── axios.rs            // Axios extraction
│       ├── react_query.rs      // React Query / TanStack Query extraction
│       ├── swr.rs              // SWR extraction
│       ├── angular_http.rs     // Angular HttpClient extraction
│       ├── apollo.rs           // Apollo Client (GraphQL) extraction
│       └── urql.rs             // urql (GraphQL) extraction
├── matching/
│   ├── mod.rs                  // Matching engine public API
│   ├── path_normalizer.rs      // Path normalization (10+ framework syntaxes)
│   ├── path_matcher.rs         // Multi-factor path similarity (5 factors)
│   ├── field_comparator.rs     // Recursive field comparison
│   ├── type_normalizer.rs      // Cross-language type normalization (8 languages)
│   └── endpoint_matcher.rs     // Endpoint matching orchestrator
├── analysis/
│   ├── mod.rs                  // Analysis engine public API
│   ├── breaking_changes.rs     // Breaking change classifier (20+ change types)
│   ├── drift_detector.rs       // Temporal drift detection (spec-vs-code, coverage)
│   ├── service_graph.rs        // Cross-service contract tracing
│   ├── governance.rs           // API governance rules engine
│   ├── health_score.rs         // Contract health score calculation
│   └── confidence.rs           // Bayesian confidence scoring (7 signals)
├── testing/
│   ├── mod.rs                  // Contract testing integration
│   ├── pact.rs                 // Pact framework detection + contract extraction
│   ├── spring_cloud.rs         // Spring Cloud Contract detection
│   └── specmatic.rs            // Specmatic detection
└── storage/
    ├── mod.rs                  // Storage public API
    └── repository.rs           // SQLite repository (rusqlite, 7 tables)
```

### 3.4 What Moves to Rust vs Stays in TypeScript

| Component | V1 (TS) | V2 | Rationale |
|-----------|---------|-----|-----------|
| Path normalization | TS string manipulation | **Rust** | Simple, performance-critical |
| Path similarity matching | TS weighted scoring | **Rust** | CPU-intensive for large codebases |
| Field comparison | TS recursive | **Rust** | Pure logic, no TS dependencies |
| Type normalization | TS mapping | **Rust** | Lookup table, trivial to port |
| Backend endpoint extraction | TS (framework-specific) | **Rust** | Decorator/annotation extraction already in Rust parsers |
| OpenAPI parsing | TS (schema-parser.ts) | **Rust** | serde_yaml/serde_json, no TS dependency |
| GraphQL SDL parsing | N/A (new) | **Rust** | tree-sitter-graphql crate exists |
| Protobuf parsing | N/A (new) | **Rust** | protox-parse crate exists (pure Rust, no protoc) |
| AsyncAPI parsing | N/A (new) | **Rust** | serde_yaml/serde_json, no TS dependency |
| Breaking change classifier | N/A (new) | **Rust** | Pure logic, paradigm-specific rules |
| Confidence scoring | TS simple formula | **Rust** | Bayesian math, pure computation |
| SQLite storage | TS (better-sqlite3) | **Rust** (rusqlite) | Rust owns drift.db writes |
| Frontend API call extraction | TS | **TypeScript** | TypeScript compiler API needed for generic type resolution |
| tRPC extraction | N/A (new) | **TypeScript** | Requires TS compiler API for Zod schema extraction |
| MCP tool handlers | TS | **TypeScript** | MCP server is TS-based |
| CLI command handlers | TS | **TypeScript** | CLI is TS-based |

---

## 4. Core Data Model (Unified Multi-Paradigm)

The unified contract model normalizes all API paradigms into a common representation.
This is the architectural foundation — every other component builds on these types.

### 4.1 ApiParadigm

```rust
/// The universal API paradigm enum.
/// V1 only supported Rest. V2 adds 5 paradigms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[napi(string_enum)]
pub enum ApiParadigm {
    Rest,           // HTTP REST APIs (Express, FastAPI, Spring, etc.)
    GraphQL,        // GraphQL APIs (schema-first or code-first)
    Grpc,           // gRPC/Protobuf APIs
    WebSocket,      // WebSocket APIs (Socket.IO, ws, etc.)
    EventDriven,    // Event-driven APIs (Kafka, RabbitMQ, SNS/SQS)
    Trpc,           // tRPC (TypeScript-specific)
}
```

### 4.2 ContractSource

```rust
/// Where the contract was extracted from.
/// V1 only had CodeExtraction. V2 adds SpecFile, ContractTest, Both.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ContractSource {
    /// Extracted from source code (route handlers, decorators, annotations)
    CodeExtraction {
        file: PathBuf,
        line: u32,
        framework: String,
        extraction_confidence: f64,
    },
    /// Parsed from a specification file (OpenAPI, .graphql, .proto, AsyncAPI)
    SpecFile {
        file: PathBuf,
        spec_type: SpecType,
        spec_version: String,
    },
    /// Extracted from contract tests (Pact, Spring Cloud Contract, Specmatic)
    ContractTest {
        file: PathBuf,
        framework: String,
        test_name: String,
    },
    /// Both spec and code — cross-validated (highest confidence)
    Both {
        spec: Box<ContractSource>,
        code: Box<ContractSource>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpecType {
    OpenApi,        // OpenAPI 3.0.x / 3.1.x (YAML or JSON)
    GraphQLSdl,     // GraphQL Schema Definition Language (.graphql, .gql)
    Protobuf,       // Protocol Buffers (.proto)
    AsyncApi,       // AsyncAPI 2.x / 3.0 (YAML or JSON)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpecFormat {
    Yaml,
    Json,
}
```

### 4.3 ApiContract (Primary Entity)

```rust
/// The unified API contract — represents a single API surface.
/// For REST: one contract per service/spec file.
/// For GraphQL: one contract per schema.
/// For gRPC: one contract per .proto service.
/// For event-driven: one contract per channel/topic.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[napi(object)]
pub struct ApiContract {
    pub id: String,
    pub paradigm: ApiParadigm,
    pub service: Option<String>,            // Service name (for microservices)
    pub operations: Vec<ApiOperation>,
    pub types: Vec<ApiType>,
    pub source: ContractSource,
    pub status: ContractStatus,
    pub confidence: ContractConfidence,
    pub metadata: ContractMetadata,
    pub breaking_changes: Vec<BreakingChange>,
    pub governance_violations: Vec<GovernanceViolation>,
    pub consumers: Vec<ContractConsumer>,
    pub mismatches: Vec<ContractMismatch>,
}

/// V2 extends v1's 4-state lifecycle with 'deprecated'.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[napi(string_enum)]
pub enum ContractStatus {
    Discovered,     // Auto-detected, not yet reviewed
    Verified,       // Manually confirmed as correct
    Mismatch,       // Field mismatches detected
    Ignored,        // Manually dismissed
    Deprecated,     // Marked for removal (NEW in v2)
}
```

### 4.4 ApiOperation

```rust
/// A single API operation (endpoint, query, RPC method, event, procedure).
/// Unified across all paradigms.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiOperation {
    pub name: String,
    pub operation_type: OperationType,
    pub input: Option<ApiType>,
    pub output: Option<ApiType>,
    pub parameters: Vec<ApiParameter>,
    pub auth_requirements: Vec<AuthRequirement>,
    pub is_deprecated: bool,
    pub deprecation_info: Option<DeprecationInfo>,
    pub source_location: SourceLocation,
}

/// Paradigm-specific operation types.
/// This enum captures the full semantics of each paradigm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OperationType {
    // REST (v1 preserved)
    HttpGet { path: String },
    HttpPost { path: String },
    HttpPut { path: String },
    HttpPatch { path: String },
    HttpDelete { path: String },
    // GraphQL (NEW)
    GraphQLQuery { field_name: String },
    GraphQLMutation { field_name: String },
    GraphQLSubscription { field_name: String },
    // gRPC (NEW)
    GrpcUnary { service: String, method: String },
    GrpcServerStream { service: String, method: String },
    GrpcClientStream { service: String, method: String },
    GrpcBidiStream { service: String, method: String },
    // Event-Driven (NEW)
    EventPublish { channel: String, event_type: String },
    EventSubscribe { channel: String, event_type: String },
    // WebSocket (NEW)
    WsMessage { event: String, direction: MessageDirection },
    // tRPC (NEW)
    TrpcQuery { procedure: String },
    TrpcMutation { procedure: String },
    TrpcSubscription { procedure: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageDirection {
    ClientToServer,
    ServerToClient,
    Bidirectional,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiParameter {
    pub name: String,
    pub location: ParameterLocation,
    pub param_type: ApiType,
    pub required: bool,
    pub default_value: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParameterLocation {
    Path,
    Query,
    Header,
    Cookie,
    Body,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequirement {
    pub scheme: String,         // bearer, basic, apiKey, oauth2
    pub scopes: Vec<String>,    // OAuth2 scopes
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeprecationInfo {
    pub reason: Option<String>,
    pub sunset_date: Option<String>,    // ISO date
    pub replacement: Option<String>,    // Replacement operation name
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceLocation {
    pub file: PathBuf,
    pub line: u32,
    pub column: Option<u32>,
}
```

### 4.5 ApiType (Unified Type System)

```rust
/// Unified type system for contract fields.
/// Supports recursive types, enums, unions, generics.
/// V1 had 6 canonical types. V2 adds enums, unions, maps, references.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiType {
    pub name: String,
    pub kind: TypeKind,
    pub fields: Vec<ApiField>,
    pub source_location: Option<SourceLocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TypeKind {
    Object,
    Enum { values: Vec<String> },
    Union { variants: Vec<ApiType> },
    Array { element_type: Box<ApiType> },
    Map { key_type: Box<ApiType>, value_type: Box<ApiType> },
    Scalar(ScalarType),
    Reference(String),      // Reference to another named type
}

/// Extended scalar types (v1 had 6, v2 has 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScalarType {
    String,
    Integer,
    Float,
    Boolean,
    DateTime,       // NEW: ISO 8601 date-time
    Binary,         // NEW: binary/bytes data
    Null,
    Any,            // Unknown/unresolvable type
}

/// Unified field definition with constraints.
/// V1's ContractField preserved + enhanced with constraints and deprecation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiField {
    pub name: String,
    pub field_type: ApiType,
    pub required: bool,             // V1: !optional
    pub nullable: bool,             // V1: nullable
    pub default_value: Option<serde_json::Value>,
    pub description: Option<String>,
    pub deprecated: bool,           // NEW
    pub constraints: Vec<FieldConstraint>,  // NEW
    pub source_line: Option<u32>,   // V1: line
}

/// Field-level constraints for validation.
/// Extracted from OpenAPI schemas, Zod validators, Pydantic validators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FieldConstraint {
    MinLength(usize),
    MaxLength(usize),
    Minimum(f64),
    Maximum(f64),
    Pattern(String),        // Regex pattern
    Enum(Vec<serde_json::Value>),
    Format(String),         // email, uri, uuid, date-time, etc.
    UniqueItems,
    MinItems(usize),
    MaxItems(usize),
}
```

### 4.6 ContractMismatch

```rust
/// V2 extends v1's 5 mismatch types to 7.
/// Renamed: missing_in_frontend → missing_in_consumer (paradigm-agnostic)
/// Renamed: missing_in_backend → missing_in_provider (paradigm-agnostic)
/// Added: enum_mismatch, constraint_mismatch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractMismatch {
    pub field_path: String,             // Dot-notation: "user.email"
    pub mismatch_type: MismatchType,
    pub severity: MismatchSeverity,
    pub description: String,
    pub provider_value: Option<String>, // Provider's version
    pub consumer_value: Option<String>, // Consumer's version
    pub operation_name: Option<String>, // Which operation this mismatch belongs to
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MismatchType {
    MissingInConsumer,      // V1: missing_in_frontend (warning)
    MissingInProvider,      // V1: missing_in_backend (error)
    TypeMismatch,           // V1: type_mismatch (error)
    OptionalityMismatch,    // V1: optionality_mismatch (warning)
    NullabilityMismatch,    // V1: nullability_mismatch (warning)
    EnumMismatch,           // NEW: enum value set mismatch (warning)
    ConstraintMismatch,     // NEW: validation constraint mismatch (info)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MismatchSeverity {
    Error,      // Will cause runtime failure
    Warning,    // May cause issues, worth investigating
    Info,       // Informational, unlikely to cause issues
}

/// Severity rules (v1 preserved + v2 additions):
/// MissingInConsumer → Warning (safe but wasteful)
/// MissingInProvider → Error (runtime crash)
/// TypeMismatch → Error (runtime type error)
/// OptionalityMismatch → Warning (potential undefined)
/// NullabilityMismatch → Warning (potential null ref)
/// EnumMismatch → Warning (unexpected enum value)
/// ConstraintMismatch → Info (validation difference)
```

### 4.7 ContractConsumer

```rust
/// V2 replaces v1's FrontendApiCall with paradigm-agnostic ContractConsumer.
/// Supports REST frontend calls, GraphQL clients, gRPC clients, event subscribers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractConsumer {
    pub consumer_type: ConsumerType,
    pub file: PathBuf,
    pub line: u32,
    pub library: Option<String>,        // fetch, axios, apollo, grpc-js, etc.
    pub framework: Option<String>,      // react-query, angular, etc.
    pub expected_type: Option<ApiType>,  // What the consumer expects
    pub method: Option<HttpMethod>,     // REST only
    pub path: Option<String>,           // REST only: normalized path
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsumerType {
    RestFrontendCall,       // V1: FrontendApiCall
    GraphQLClient,          // Apollo, urql, relay
    GrpcClient,             // grpc-js, grpcio, tonic client
    EventSubscriber,        // Kafka consumer, RabbitMQ subscriber
    WebSocketClient,        // Socket.IO client, ws client
    TrpcClient,             // tRPC client
}

/// V1's HttpMethod preserved exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}
```

### 4.8 ContractConfidence (Bayesian, 7-Signal)

```rust
/// V2 replaces v1's simple weighted average with Bayesian 7-signal confidence.
/// V1: score = match×0.6 + field×0.4
/// V2: Bayesian posterior from 7 independent signals with temporal decay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractConfidence {
    pub score: f64,                         // 0.0-1.0 posterior probability
    pub level: ConfidenceLevel,
    pub signals: ConfidenceSignals,
    pub last_verified: Option<String>,      // ISO timestamp
    pub decay_rate: f64,                    // Per-day decay factor (default 0.01)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfidenceLevel {
    High,           // ≥ 0.80 (v1: ≥ 0.8)
    Medium,         // ≥ 0.50 (v1: ≥ 0.5)
    Low,            // ≥ 0.30 (v1: ≥ 0.3)
    Uncertain,      // < 0.30 (v1: < 0.3)
}

/// 7 confidence signals (v1 had 2: match + field extraction).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceSignals {
    pub match_confidence: f64,              // V1: matchConfidence (PRESERVED)
    pub extraction_confidence: f64,         // V1: fieldExtractionConfidence (PRESERVED)
    pub source_quality: f64,                // NEW: schema source reliability
    pub test_coverage: f64,                 // NEW: contract test coverage
    pub historical_stability: f64,          // NEW: stability across scans
    pub usage_frequency: f64,               // NEW: how often endpoint is called
    pub cross_validation: f64,              // NEW: agreement between extraction methods
}

/// Source quality priors (from research R11):
/// OpenAPI spec + code match → 0.95
/// OpenAPI spec only → 0.90
/// Typed code (Pydantic, TS interface) → 0.85
/// Contract test (Pact) → 0.85
/// Code extraction (well-known framework) → 0.75
/// Code extraction (custom framework) → 0.60
/// Inferred from return statements → 0.50
/// Unknown/any types → 0.30
```

### 4.9 BreakingChange

```rust
/// Breaking change classification (NEW in v2).
/// Paradigm-aware — REST, GraphQL, gRPC, event-driven have different rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakingChange {
    pub change_type: ChangeType,
    pub severity: ChangeSeverity,
    pub paradigm: ApiParadigm,
    pub operation: String,
    pub field_path: Option<String>,
    pub description: String,
    pub before: Option<String>,
    pub after: Option<String>,
    pub migration_hint: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChangeSeverity {
    Breaking,       // Will break existing consumers
    Conditional,    // May break depending on consumer usage
    NonBreaking,    // Safe for all consumers
    Deprecation,    // Marked for future removal
}

/// 20+ change types covering all paradigms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChangeType {
    // Operation-level
    OperationRemoved,
    OperationAdded,
    OperationRenamed,
    // Field-level
    RequiredFieldAdded,
    RequiredFieldRemoved,
    OptionalFieldAdded,
    OptionalFieldRemoved,
    FieldTypeChanged,
    FieldRequirednessChanged,
    FieldNullabilityChanged,
    // Type-level
    EnumValueAdded,
    EnumValueRemoved,
    TypeRemoved,
    TypeRenamed,
    // Auth-level
    AuthRequirementAdded,
    AuthRequirementRemoved,
    // Protocol-specific
    ProtoFieldNumberReused,         // gRPC: always breaking
    ProtoFieldNumberChanged,        // gRPC: always breaking
    GraphQLArgumentAdded,           // GraphQL: breaking if required
    GraphQLNullabilityTightened,    // GraphQL: always breaking
}
```

### 4.10 ContractMetadata

```rust
/// V1's ContractMetadata preserved + enhanced with tags and custom data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractMetadata {
    pub first_seen: String,             // V1: firstSeen (ISO timestamp)
    pub last_seen: String,              // V1: lastSeen (ISO timestamp)
    pub verified_at: Option<String>,    // V1: verifiedAt
    pub verified_by: Option<String>,    // V1: verifiedBy
    pub tags: Vec<String>,             // V1: tags (optional)
    pub custom: Option<serde_json::Value>, // V1: custom (extensible)
}
```

---

## 5. Phase 1: Spec File Discovery & Parsing

### 5.1 Spec File Discovery

The scanner discovers specification files in standard locations during file walking.
This runs as part of the scan pipeline, before contract extraction.

```rust
pub struct SpecFileDiscovery;

impl SpecFileDiscovery {
    /// Discover all API specification files in the project.
    /// Called during scan phase, integrated with Scanner's file walking.
    pub fn discover(root: &Path, files: &[PathBuf]) -> Vec<SpecFile> {
        let mut specs = Vec::new();

        for file in files {
            if let Some(spec_type) = Self::classify_spec_file(file) {
                specs.push(SpecFile {
                    path: file.clone(),
                    spec_type,
                    format: Self::detect_format(file),
                });
            }
        }

        specs
    }

    fn classify_spec_file(path: &Path) -> Option<SpecType> {
        let name = path.file_name()?.to_str()?;
        let ext = path.extension()?.to_str()?;

        match ext {
            // OpenAPI
            "yaml" | "yml" | "json" if Self::is_openapi_name(name) => Some(SpecType::OpenApi),
            // GraphQL
            "graphql" | "gql" => Some(SpecType::GraphQLSdl),
            // Protobuf
            "proto" => Some(SpecType::Protobuf),
            // AsyncAPI
            "yaml" | "yml" | "json" if Self::is_asyncapi_name(name) => Some(SpecType::AsyncApi),
            _ => None,
        }
    }

    fn is_openapi_name(name: &str) -> bool {
        let lower = name.to_lowercase();
        lower.starts_with("openapi") ||
        lower.starts_with("swagger") ||
        lower.contains(".openapi.") ||
        lower.contains(".swagger.")
    }

    fn is_asyncapi_name(name: &str) -> bool {
        let lower = name.to_lowercase();
        lower.starts_with("asyncapi") ||
        lower.contains(".asyncapi.")
    }
}

/// Standard directories to check for spec files:
/// api/, specs/, proto/, schemas/, openapi/, graphql/, grpc/
pub const SPEC_DIRECTORIES: &[&str] = &[
    "api", "specs", "proto", "schemas", "openapi", "graphql", "grpc",
    "api-specs", "api-schema", "definitions",
];
```

---

## 6. Phase 2: Schema-First Contract Extraction

### 6.1 OpenAPI Parser (Rust)

Parses OpenAPI 3.0.x and 3.1.x specifications in YAML and JSON format.
Uses `serde_yaml` and `serde_json` for parsing, with custom extraction logic.

```rust
pub struct OpenApiParser;

impl OpenApiParser {
    pub fn parse(content: &str, format: SpecFormat) -> Result<Vec<ApiContract>> {
        // 1. Parse YAML/JSON into serde_json::Value
        let doc: serde_json::Value = match format {
            SpecFormat::Yaml => serde_yaml::from_str(content)?,
            SpecFormat::Json => serde_json::from_str(content)?,
        };

        // 2. Validate OpenAPI version (3.0.x or 3.1.x)
        let version = doc.get("openapi")
            .and_then(|v| v.as_str())
            .ok_or(ContractError::InvalidSpec("Missing openapi version"))?;

        // 3. Extract paths → ApiOperation (one per method per path)
        let operations = Self::extract_paths(&doc)?;

        // 4. Extract components/schemas → ApiType
        let types = Self::extract_schemas(&doc)?;

        // 5. Resolve $ref references
        let resolved_types = Self::resolve_refs(types, &doc)?;

        // 6. Extract security requirements
        let auth = Self::extract_security(&doc)?;

        Ok(vec![ApiContract {
            id: generate_contract_id("openapi", &doc),
            paradigm: ApiParadigm::Rest,
            operations,
            types: resolved_types,
            source: ContractSource::SpecFile { /* ... */ },
            // ...
        }])
    }
}
```

### 6.2 GraphQL SDL Parser (Rust via tree-sitter-graphql)

Parses GraphQL Schema Definition Language files using tree-sitter-graphql.

```rust
pub struct GraphQLSchemaParser;

impl GraphQLSchemaParser {
    pub fn parse(content: &str, file: &Path) -> Result<Vec<ApiContract>> {
        // 1. Parse SDL with tree-sitter-graphql
        let tree = self.parser.parse(content, None)?;

        // 2. Extract type definitions → ApiType
        let types = Self::extract_types(&tree, content)?;

        // 3. Extract Query type fields → ApiOperation::GraphQLQuery
        let queries = Self::extract_query_operations(&tree, content)?;

        // 4. Extract Mutation type fields → ApiOperation::GraphQLMutation
        let mutations = Self::extract_mutation_operations(&tree, content)?;

        // 5. Extract Subscription type fields → ApiOperation::GraphQLSubscription
        let subscriptions = Self::extract_subscription_operations(&tree, content)?;

        // 6. Extract @deprecated directives → DeprecationInfo
        let deprecations = Self::extract_deprecations(&tree, content)?;

        let mut operations = Vec::new();
        operations.extend(queries);
        operations.extend(mutations);
        operations.extend(subscriptions);

        Ok(vec![ApiContract {
            id: generate_contract_id("graphql", file),
            paradigm: ApiParadigm::GraphQL,
            operations,
            types,
            source: ContractSource::SpecFile {
                file: file.to_path_buf(),
                spec_type: SpecType::GraphQLSdl,
                spec_version: "October2021".into(),
            },
            // ...
        }])
    }
}
```

### 6.3 Protobuf Parser (Rust via protox-parse)

Parses `.proto` files using protox-parse (pure Rust, no protoc dependency).

```rust
pub struct ProtobufParser;

impl ProtobufParser {
    pub fn parse(content: &str, file: &Path) -> Result<Vec<ApiContract>> {
        // 1. Parse .proto file with protox-parse
        let file_descriptor = protox_parse::parse(file.to_str().unwrap(), content)?;

        // 2. Extract service definitions → one ApiContract per service
        let mut contracts = Vec::new();

        for service in &file_descriptor.services {
            let operations: Vec<ApiOperation> = service.methods.iter()
                .map(|method| {
                    let op_type = match (method.client_streaming, method.server_streaming) {
                        (false, false) => OperationType::GrpcUnary {
                            service: service.name.clone(),
                            method: method.name.clone(),
                        },
                        (false, true) => OperationType::GrpcServerStream { /* ... */ },
                        (true, false) => OperationType::GrpcClientStream { /* ... */ },
                        (true, true) => OperationType::GrpcBidiStream { /* ... */ },
                    };
                    ApiOperation {
                        name: format!("{}.{}", service.name, method.name),
                        operation_type: op_type,
                        input: Some(Self::resolve_message(&method.input_type, &file_descriptor)),
                        output: Some(Self::resolve_message(&method.output_type, &file_descriptor)),
                        // ...
                    }
                })
                .collect();

            // 3. Extract message definitions → ApiType
            let types = Self::extract_messages(&file_descriptor)?;

            // 4. Track field numbers for breaking change detection
            // Field numbers are stored in ApiField metadata for later comparison

            contracts.push(ApiContract {
                id: generate_contract_id("grpc", &service.name),
                paradigm: ApiParadigm::Grpc,
                operations,
                types,
                source: ContractSource::SpecFile {
                    file: file.to_path_buf(),
                    spec_type: SpecType::Protobuf,
                    spec_version: "proto3".into(),
                },
                // ...
            });
        }

        Ok(contracts)
    }
}
```

### 6.4 AsyncAPI Parser (Rust)

Parses AsyncAPI 2.x and 3.0 specifications for event-driven contracts.

```rust
pub struct AsyncApiParser;

impl AsyncApiParser {
    pub fn parse(content: &str, format: SpecFormat) -> Result<Vec<ApiContract>> {
        let doc: serde_json::Value = match format {
            SpecFormat::Yaml => serde_yaml::from_str(content)?,
            SpecFormat::Json => serde_json::from_str(content)?,
        };

        // 1. Detect AsyncAPI version (2.x vs 3.0)
        let version = Self::detect_version(&doc)?;

        // 2. Extract channels → scoping for operations
        let channels = Self::extract_channels(&doc, version)?;

        // 3. Extract operations → ApiOperation (EventPublish/EventSubscribe)
        let operations = Self::extract_operations(&doc, &channels, version)?;

        // 4. Extract message schemas → ApiType
        let types = Self::extract_message_schemas(&doc)?;

        // 5. Extract protocol bindings (Kafka, AMQP, MQTT, WebSocket)
        let bindings = Self::extract_bindings(&doc)?;

        Ok(vec![ApiContract {
            id: generate_contract_id("asyncapi", &doc),
            paradigm: if bindings.contains(&"websocket") {
                ApiParadigm::WebSocket
            } else {
                ApiParadigm::EventDriven
            },
            operations,
            types,
            source: ContractSource::SpecFile {
                file: PathBuf::new(), // Set by caller
                spec_type: SpecType::AsyncApi,
                spec_version: version.to_string(),
            },
            // ...
        }])
    }
}
```

---

## 7. Phase 3: Code-First Backend Endpoint Extraction (20+ Frameworks)

V1 supported 8 backend frameworks. V2 expands to 20+ across 10 languages.

### 7.1 Framework Registry

```rust
/// Declarative framework registry for REST endpoint extraction.
/// Each entry defines the detection pattern and extraction rules.
pub struct RestFrameworkRegistry {
    pub frameworks: Vec<RestFrameworkDef>,
}

pub struct RestFrameworkDef {
    pub id: &'static str,
    pub language: Language,
    pub detection: FrameworkDetection,
    pub route_patterns: Vec<RoutePattern>,
    pub response_extraction: ResponseExtractionStrategy,
}

/// V1 frameworks (PRESERVED):
/// express, fastapi, flask, django, spring, aspnet, laravel, go-gin/echo/fiber/chi
///
/// V2 additions (NEW):
/// nestjs, rust-actix, rust-axum, rust-rocket, ruby-rails, ruby-sinatra,
/// kotlin-ktor, kotlin-spring, python-starlette, python-litestar
```

### 7.2 Framework Coverage Matrix

| Framework | Language | V1 | V2 | Detection Pattern |
|-----------|----------|-----|-----|-------------------|
| Express/Koa | TypeScript/JS | ✅ | ✅ | `app.get()`, `router.post()` |
| NestJS | TypeScript | ❌ | ✅ | `@Get()`, `@Post()`, `@Controller()` |
| FastAPI | Python | ✅ | ✅ | `@app.get()`, `@router.post()` |
| Flask | Python | ✅ | ✅ | `@app.route()` |
| Starlette | Python | ❌ | ✅ | `Route()`, `@route()` |
| Litestar | Python | ❌ | ✅ | `@get()`, `@post()` |
| Django | Python | ✅ | ✅ | `path()`, ViewSets, Serializers |
| Spring Boot | Java | ✅ | ✅ | `@GetMapping`, `@RestController` |
| ASP.NET | C# | ✅ | ✅ | `[HttpGet]`, `[Route]` |
| Laravel | PHP | ✅ | ✅ | `Route::get()`, resource controllers |
| Gin | Go | ✅ | ✅ | `r.GET()`, `r.POST()` |
| Echo | Go | ✅ | ✅ | `e.GET()`, `e.POST()` |
| Fiber | Go | ✅ | ✅ | `app.Get()`, `app.Post()` |
| Chi | Go | ✅ | ✅ | `r.Get()`, `r.Post()` |
| Actix | Rust | ❌ | ✅ | `#[get("/path")]`, `web::resource()` |
| Axum | Rust | ❌ | ✅ | `Router::new().route("/path", get(handler))` |
| Rocket | Rust | ❌ | ✅ | `#[get("/path")]`, `#[post("/path")]` |
| Rails | Ruby | ❌ | ✅ | `get '/path'`, `resources :users` |
| Sinatra | Ruby | ❌ | ✅ | `get '/path' do` |
| Ktor | Kotlin | ❌ | ✅ | `get("/path")`, `post("/path")` |

---

## 8. Phase 4: Code-First Frontend/Consumer Extraction (15+ Libraries)

V1 supported 3 frontend libraries. V2 expands to 15+ across REST, GraphQL, and gRPC.

### 8.1 Consumer Library Coverage Matrix

| Library | Paradigm | V1 | V2 | Detection Pattern |
|---------|----------|-----|-----|-------------------|
| fetch | REST | ✅ | ✅ | `fetch('/api/path')` |
| axios | REST | ✅ | ✅ | `axios.get<T>('/api/path')` |
| Custom clients | REST | ✅ | ✅ | Configurable patterns |
| react-query / TanStack | REST | ✅ | ✅ | `useQuery<T>()`, `useMutation<T>()` |
| Angular HttpClient | REST | ✅ | ✅ | `this.http.get<T>()` |
| SWR | REST | ❌ | ✅ | `useSWR<T>()` |
| Ky | REST | ❌ | ✅ | `ky.get().json<T>()` |
| Got | REST | ❌ | ✅ | `got.get<T>()` |
| Superagent | REST | ❌ | ✅ | `superagent.get('/path')` |
| Apollo Client | GraphQL | ❌ | ✅ | `useQuery()`, `useMutation()`, `gql` |
| urql | GraphQL | ❌ | ✅ | `useQuery()`, `useMutation()` |
| Relay | GraphQL | ❌ | ✅ | `useLazyLoadQuery()`, `graphql` |
| @grpc/grpc-js | gRPC | ❌ | ✅ | `client.methodName()` |
| nice-grpc | gRPC | ❌ | ✅ | `client.methodName()` |
| tonic (Rust) | gRPC | ❌ | ✅ | `client.method_name()` |

### 8.2 Frontend Type Resolution (TypeScript — Stays in TS)

Frontend type resolution requires the TypeScript compiler API for:
- Generic type parameter extraction: `axios.get<User[]>('/api/users')`
- Type assertion extraction: `res.json() as User[]`
- Interface resolution: resolving `User` to its field definitions
- Zod schema extraction (for tRPC): `z.object({ name: z.string() })`

This stays in TypeScript and is exposed to Rust via NAPI callback.

```rust
/// NAPI function to request TypeScript type resolution from the TS layer.
/// Called when Rust extraction encounters a TypeScript type reference.
#[napi]
pub struct TypeResolutionRequest {
    pub file: String,
    pub type_name: String,
    pub line: u32,
}

#[napi]
pub struct TypeResolutionResult {
    pub fields: Vec<JsApiField>,
    pub confidence: f64,
}
```

---

## 9. Phase 5: GraphQL Code-First Extraction

Detects GraphQL contracts from code-first framework definitions (not schema files).

### 9.1 Supported Code-First Frameworks

| Framework | Language | Detection Pattern |
|-----------|----------|-------------------|
| type-graphql | TypeScript | `@ObjectType()`, `@Field()`, `@Query()`, `@Mutation()` |
| Nexus | TypeScript | `objectType()`, `queryField()`, `mutationField()` |
| Pothos | TypeScript | `builder.objectType()`, `builder.queryField()` |
| graphql-yoga | TypeScript | `createSchema()`, type definitions |
| Strawberry | Python | `@strawberry.type`, `@strawberry.mutation` |
| Ariadne | Python | `make_executable_schema()`, resolver decorators |
| Graphene | Python | `graphene.ObjectType`, `graphene.Mutation` |
| juniper | Rust | `#[graphql_object]`, `#[derive(GraphQLObject)]` |
| async-graphql | Rust | `#[Object]`, `#[derive(SimpleObject)]` |
| gqlgen | Go | `schema.resolvers.go`, directive-based |
| DGS Framework | Java | `@DgsComponent`, `@DgsQuery`, `@DgsMutation` |
| graphql-java | Java | `GraphQLObjectType.newObject()`, `DataFetcher` |

### 9.2 GraphQL-Specific Mismatch Detection

```rust
pub struct GraphQLMismatchDetector;

impl GraphQLMismatchDetector {
    /// Detect mismatches between GraphQL schema and frontend queries.
    pub fn detect(
        &self,
        schema: &ApiContract,          // From schema file or code-first
        frontend_queries: &[GraphQLQuery], // Extracted from frontend code
    ) -> Vec<ContractMismatch> {
        let mut mismatches = Vec::new();

        for query in frontend_queries {
            // 1. Query↔Schema mismatch: query requests fields not in schema
            for field in &query.selected_fields {
                if !schema.has_field(&query.type_name, &field.name) {
                    mismatches.push(ContractMismatch {
                        mismatch_type: MismatchType::MissingInProvider,
                        field_path: format!("{}.{}", query.type_name, field.name),
                        severity: MismatchSeverity::Error,
                        // ...
                    });
                }
            }

            // 2. Deprecated field usage
            for field in &query.selected_fields {
                if schema.is_deprecated(&query.type_name, &field.name) {
                    mismatches.push(ContractMismatch {
                        mismatch_type: MismatchType::EnumMismatch, // Reuse for deprecation
                        severity: MismatchSeverity::Warning,
                        description: format!("Query uses deprecated field {}", field.name),
                        // ...
                    });
                }
            }

            // 3. Type mismatches (query expects different type than schema defines)
            // Compare query variable types against schema argument types
        }

        mismatches
    }
}
```

### 9.3 N+1 Resolver Detection

```rust
/// Detect N+1 query patterns in GraphQL resolvers.
/// A resolver that makes individual DB calls per list item without batching.
pub fn detect_n_plus_one_resolvers(
    resolvers: &[ResolverInfo],
    call_graph: &CallGraphDb,
) -> Vec<GovernanceViolation> {
    let mut violations = Vec::new();

    for resolver in resolvers {
        // Check if resolver is called from a list-returning parent
        if resolver.parent_returns_list {
            // Check if resolver makes DB calls (via call graph)
            let db_calls = call_graph.get_callees(&resolver.function_id)
                .filter(|callee| callee.is_data_access);

            if !db_calls.is_empty() && !resolver.uses_dataloader {
                violations.push(GovernanceViolation {
                    rule_id: "graphql/n-plus-one".into(),
                    severity: Severity::Warning,
                    description: format!(
                        "Resolver '{}' makes DB calls without DataLoader batching",
                        resolver.name
                    ),
                    // ...
                });
            }
        }
    }

    violations
}
```

---

## 10. Phase 6: gRPC Server/Client Extraction

### 10.1 gRPC Framework Detection

```rust
/// Detect gRPC implementations from imports and code patterns.
pub fn detect_grpc_framework(parse_result: &ParseResult) -> Option<GrpcFramework> {
    for import in &parse_result.imports {
        match import.source.as_str() {
            "@grpc/grpc-js" | "@grpc/proto-loader" => return Some(GrpcFramework::GrpcJs),
            "nice-grpc" | "nice-grpc-server-middleware" => return Some(GrpcFramework::NiceGrpc),
            s if s.starts_with("grpcio") => return Some(GrpcFramework::Grpcio),
            s if s.starts_with("io.grpc") => return Some(GrpcFramework::IoGrpc),
            "tonic" => return Some(GrpcFramework::Tonic),
            s if s.starts_with("google.golang.org/grpc") => return Some(GrpcFramework::GoGrpc),
            _ => {}
        }
    }
    None
}
```

### 10.2 Proto↔Implementation Matching

```rust
/// Match .proto service definitions against code implementations.
/// Detects: unimplemented methods, extra methods, type mismatches.
pub fn match_proto_to_implementation(
    proto_contract: &ApiContract,       // From .proto file
    code_contract: &ApiContract,        // From code extraction
) -> Vec<ContractMismatch> {
    let mut mismatches = Vec::new();

    for proto_op in &proto_contract.operations {
        match code_contract.find_operation(&proto_op.name) {
            Some(code_op) => {
                // Compare input/output types
                if let (Some(proto_input), Some(code_input)) = (&proto_op.input, &code_op.input) {
                    mismatches.extend(compare_types(proto_input, code_input, &proto_op.name));
                }
            }
            None => {
                mismatches.push(ContractMismatch {
                    mismatch_type: MismatchType::MissingInProvider,
                    description: format!("Proto method {} not implemented", proto_op.name),
                    severity: MismatchSeverity::Error,
                    // ...
                });
            }
        }
    }

    mismatches
}
```

---

## 11. Phase 7: Event-Driven Contract Extraction

### 11.1 Message Broker Detection

| Broker | Libraries | Detection Pattern |
|--------|-----------|-------------------|
| Kafka | kafkajs, confluent-kafka-python, sarama (Go) | `producer.send()`, `consumer.subscribe()` |
| RabbitMQ | amqplib, pika, lapin (Rust) | `channel.publish()`, `channel.consume()` |
| AWS SNS/SQS | @aws-sdk/client-sns, @aws-sdk/client-sqs | `sns.publish()`, `sqs.receiveMessage()` |
| Redis Pub/Sub | ioredis, redis-py | `redis.publish()`, `redis.subscribe()` |

### 11.2 Event Contract Extraction

```rust
/// Extract event-driven contracts from message broker code patterns.
pub fn extract_event_contracts(parse_result: &ParseResult) -> Vec<ApiContract> {
    let mut contracts = Vec::new();

    // Detect broker library from imports
    let broker = detect_message_broker(parse_result);

    // Extract producer calls (topic, message schema)
    let producers = extract_producers(parse_result, &broker);

    // Extract consumer handlers (topic, expected message schema)
    let consumers = extract_consumers(parse_result, &broker);

    // Build contracts from producer/consumer pairs
    for (topic, ops) in group_by_topic(producers, consumers) {
        contracts.push(ApiContract {
            id: generate_contract_id("event", &topic),
            paradigm: ApiParadigm::EventDriven,
            operations: ops,
            // ...
        });
    }

    contracts
}
```

---

## 12. Phase 8: tRPC Extraction (TypeScript-Only)

tRPC extraction stays in TypeScript because it requires the TS compiler API
for Zod schema extraction and type inference.

```typescript
// TypeScript-side tRPC extraction (exposed to Rust via NAPI callback)
function extractTrpcContracts(file: ParseResult): ApiContract[] {
    const contracts: ApiContract[] = [];

    // 1. Detect tRPC imports (from '@trpc/server')
    const hasTrpc = file.imports.some(i => i.source === '@trpc/server');
    if (!hasTrpc) return contracts;

    // 2. Extract router definitions (t.router({ ... }))
    const routers = extractRouterDefinitions(file);

    // 3. Extract procedure definitions
    //    t.procedure.input(z.object({...})).query(...)
    //    t.procedure.input(z.object({...})).mutation(...)
    for (const router of routers) {
        const operations: ApiOperation[] = [];

        for (const proc of router.procedures) {
            // 4. Extract Zod input schemas as request contracts
            const inputType = extractZodSchema(proc.inputValidator);

            // 5. Infer output types from procedure implementations
            const outputType = inferOutputType(proc.implementation);

            operations.push({
                name: proc.name,
                operationType: proc.type === 'query'
                    ? { TrpcQuery: { procedure: proc.name } }
                    : { TrpcMutation: { procedure: proc.name } },
                input: inputType,
                output: outputType,
                // ...
            });
        }

        contracts.push({
            id: generateContractId('trpc', router.name),
            paradigm: 'Trpc',
            operations,
            source: { CodeExtraction: { framework: 'trpc', /* ... */ } },
            // ...
        });
    }

    return contracts;
}
```

---

## 13. Phase 9: Path Normalization & Endpoint Matching

### 13.1 Path Normalization (V1 Preserved + Enhanced)

V1's path normalization is fully preserved. V2 adds API versioning awareness.

```rust
/// Normalize framework-specific path syntax to unified format.
/// V1 rules preserved exactly:
/// 1. Strip type annotations: <int:id> → :id
/// 2. Convert all parameter syntaxes to :param format
/// 3. Ensure leading /
/// 4. Remove trailing /
/// 5. Lowercase path segments (not parameters)
///
/// V2 additions:
/// 6. API version extraction: /v1/users → version="v1", path=/users
/// 7. Base path stripping: /api/v1/users → base="/api", version="v1", path=/users
pub fn normalize_path(raw: &str, framework: &str) -> NormalizedPath {
    let mut path = raw.to_string();

    // Framework-specific parameter normalization
    match framework {
        "express" | "koa" | "nestjs" => {} // Already :param format
        "fastapi" | "spring" | "ktor" => {
            // {id} → :id
            path = CURLY_PARAM_RE.replace_all(&path, ":$1").to_string();
        }
        "flask" => {
            // <id> or <int:id> → :id
            path = ANGLE_PARAM_RE.replace_all(&path, ":$1").to_string();
        }
        "django" => {
            // <int:id> → :id (strip type annotation)
            path = DJANGO_PARAM_RE.replace_all(&path, ":$2").to_string();
        }
        "aspnet" => {
            // {id} → :id, ensure leading /
            path = CURLY_PARAM_RE.replace_all(&path, ":$1").to_string();
        }
        "frontend" => {
            // ${id} → :id (template literals)
            path = TEMPLATE_PARAM_RE.replace_all(&path, ":$1").to_string();
        }
        // V2 additions
        "actix" | "axum" | "rocket" => {
            path = CURLY_PARAM_RE.replace_all(&path, ":$1").to_string();
        }
        "rails" | "sinatra" => {
            // :id already in correct format
        }
        _ => {}
    }

    // Ensure leading /, remove trailing /
    if !path.starts_with('/') { path = format!("/{}", path); }
    path = path.trim_end_matches('/').to_string();
    if path.is_empty() { path = "/".to_string(); }

    // Extract API version (NEW in v2)
    let (version, base, clean_path) = extract_version_info(&path);

    NormalizedPath {
        full: path,
        clean: clean_path,
        version,
        base,
    }
}
```

### 13.2 Multi-Factor Path Similarity (V1 Algorithm Preserved)

```rust
/// 5-factor weighted path similarity scoring.
/// V1 algorithm preserved exactly. Weights are configurable.
pub fn path_similarity(
    backend: &NormalizedPath,
    frontend: &NormalizedPath,
    weights: &PathSimilarityWeights,
) -> f64 {
    let seg_a: Vec<&str> = backend.clean.split('/').filter(|s| !s.is_empty()).collect();
    let seg_b: Vec<&str> = frontend.clean.split('/').filter(|s| !s.is_empty()).collect();

    // Factor 1: Segment Name Similarity (Jaccard)
    let non_param_a: HashSet<&str> = seg_a.iter()
        .filter(|s| !s.starts_with(':'))
        .copied().collect();
    let non_param_b: HashSet<&str> = seg_b.iter()
        .filter(|s| !s.starts_with(':'))
        .copied().collect();
    let jaccard = if non_param_a.is_empty() && non_param_b.is_empty() {
        1.0
    } else {
        let intersection = non_param_a.intersection(&non_param_b).count() as f64;
        let union = non_param_a.union(&non_param_b).count() as f64;
        intersection / union
    };

    // Factor 2: Segment Count Similarity
    let count_sim = 1.0 - (seg_a.len() as f64 - seg_b.len() as f64).abs()
        / seg_a.len().max(seg_b.len()).max(1) as f64;

    // Factor 3: Suffix Match Score
    let suffix_score = matching_trailing_segments(&seg_a, &seg_b)
        / seg_a.len().max(seg_b.len()).max(1) as f64;

    // Factor 4: Resource Name Match
    let resource_a = last_non_param_segment(&seg_a);
    let resource_b = last_non_param_segment(&seg_b);
    let resource_score = if resource_a == resource_b { 1.0 } else { 0.0 };

    // Factor 5: Parameter Position Alignment
    let param_score = parameter_position_alignment(&seg_a, &seg_b);

    // Weighted sum
    jaccard * weights.segment_names
        + count_sim * weights.segment_count
        + suffix_score * weights.suffix_match
        + resource_score * weights.resource_name
        + param_score * weights.parameter_positions
}

pub struct PathSimilarityWeights {
    pub segment_names: f64,     // Default: 0.30
    pub segment_count: f64,     // Default: 0.15
    pub suffix_match: f64,      // Default: 0.20
    pub resource_name: f64,     // Default: 0.25
    pub parameter_positions: f64, // Default: 0.10
}
```

---

## 14. Phase 10: Recursive Field Comparison & Type Normalization

### 14.1 Cross-Language Type Normalization (V1 Preserved + Enhanced)

V1's 6 canonical types preserved. V2 adds DateTime, Binary, and handles enums/unions.

```rust
/// Normalize language-specific types to canonical types.
/// V1 mapping preserved exactly. V2 adds Rust, Ruby, Kotlin, DateTime, Binary.
pub fn normalize_type(raw_type: &str, language: Language) -> ScalarType {
    let lower = raw_type.to_lowercase();
    match lower.as_str() {
        // String types
        "str" | "string" | "&str" => ScalarType::String,
        // Number types
        "int" | "integer" | "long" | "float" | "double" | "decimal"
        | "number" | "i32" | "i64" | "f32" | "f64" | "u32" | "u64"
        | "float64" | "int64" => ScalarType::Integer, // or Float based on context
        // Boolean types
        "bool" | "boolean" => ScalarType::Boolean,
        // DateTime types (NEW in v2)
        "datetime" | "date" | "time" | "timestamp"
        | "chrono::datetime" | "chrono::naivedate" => ScalarType::DateTime,
        // Null types
        "none" | "null" | "void" | "nil" | "undefined" => ScalarType::Null,
        // Default
        _ => ScalarType::Any,
    }
}
```

### 14.2 Recursive Field Comparison (V1 Algorithm Preserved)

```rust
/// V1's recursive field comparison algorithm preserved exactly.
/// V2 adds enum_mismatch and constraint_mismatch detection.
pub fn compare_fields(
    provider_fields: &[ApiField],
    consumer_fields: &[ApiField],
    path_prefix: &str,
) -> Vec<ContractMismatch> {
    let mut mismatches = Vec::new();

    // Check provider fields against consumer
    for provider_field in provider_fields {
        let field_path = if path_prefix.is_empty() {
            provider_field.name.clone()
        } else {
            format!("{}.{}", path_prefix, provider_field.name)
        };

        match consumer_fields.iter().find(|f| f.name == provider_field.name) {
            None => {
                // V1: missing_in_frontend → V2: MissingInConsumer
                mismatches.push(ContractMismatch {
                    field_path,
                    mismatch_type: MismatchType::MissingInConsumer,
                    severity: MismatchSeverity::Warning,
                    description: format!(
                        "Provider returns field '{}' but consumer doesn't expect it",
                        provider_field.name
                    ),
                    provider_value: Some(format!("{:?}", provider_field.field_type)),
                    consumer_value: None,
                    operation_name: None,
                });
            }
            Some(consumer_field) => {
                // Type comparison (after normalization)
                if !types_compatible(&provider_field.field_type, &consumer_field.field_type) {
                    mismatches.push(ContractMismatch {
                        field_path: field_path.clone(),
                        mismatch_type: MismatchType::TypeMismatch,
                        severity: MismatchSeverity::Error,
                        // ...
                    });
                }

                // Optionality comparison (V1 preserved)
                if provider_field.required != consumer_field.required {
                    mismatches.push(ContractMismatch {
                        field_path: field_path.clone(),
                        mismatch_type: MismatchType::OptionalityMismatch,
                        severity: MismatchSeverity::Warning,
                        // ...
                    });
                }

                // Nullability comparison (V1 preserved)
                if provider_field.nullable != consumer_field.nullable {
                    mismatches.push(ContractMismatch {
                        field_path: field_path.clone(),
                        mismatch_type: MismatchType::NullabilityMismatch,
                        severity: MismatchSeverity::Warning,
                        // ...
                    });
                }

                // Enum comparison (NEW in v2)
                if let (TypeKind::Enum { values: pv }, TypeKind::Enum { values: cv }) =
                    (&provider_field.field_type.kind, &consumer_field.field_type.kind)
                {
                    let provider_set: HashSet<_> = pv.iter().collect();
                    let consumer_set: HashSet<_> = cv.iter().collect();
                    if provider_set != consumer_set {
                        mismatches.push(ContractMismatch {
                            field_path: field_path.clone(),
                            mismatch_type: MismatchType::EnumMismatch,
                            severity: MismatchSeverity::Warning,
                            // ...
                        });
                    }
                }

                // Recursive comparison for nested objects (V1 preserved)
                if !provider_field.field_type.fields.is_empty()
                    && !consumer_field.field_type.fields.is_empty()
                {
                    mismatches.extend(compare_fields(
                        &provider_field.field_type.fields,
                        &consumer_field.field_type.fields,
                        &field_path,
                    ));
                }
            }
        }
    }

    // Check for fields consumer expects but provider doesn't return (V1 preserved)
    for consumer_field in consumer_fields {
        if !provider_fields.iter().any(|f| f.name == consumer_field.name) {
            let field_path = if path_prefix.is_empty() {
                consumer_field.name.clone()
            } else {
                format!("{}.{}", path_prefix, consumer_field.name)
            };
            mismatches.push(ContractMismatch {
                field_path,
                mismatch_type: MismatchType::MissingInProvider,
                severity: MismatchSeverity::Error,
                description: format!(
                    "Consumer expects field '{}' but provider doesn't return it",
                    consumer_field.name
                ),
                provider_value: None,
                consumer_value: Some(format!("{:?}", consumer_field.field_type)),
                operation_name: None,
            });
        }
    }

    mismatches
}
```

---

## 15. Phase 11: Mismatch Detection & Severity Classification

Covered in §14 (recursive field comparison). The severity rules are:

| Mismatch Type | Severity | Runtime Impact | V1 Equivalent |
|--------------|----------|----------------|---------------|
| MissingInConsumer | Warning | Safe but wasteful | missing_in_frontend |
| MissingInProvider | Error | Runtime crash | missing_in_backend |
| TypeMismatch | Error | Runtime type error | type_mismatch |
| OptionalityMismatch | Warning | Potential undefined | optionality_mismatch |
| NullabilityMismatch | Warning | Potential null ref | nullability_mismatch |
| EnumMismatch | Warning | Unexpected enum value | NEW |
| ConstraintMismatch | Info | Validation difference | NEW |

---

## 16. Phase 12: Breaking Change Classifier (Cross-Paradigm)

### 16.1 Paradigm-Specific Breaking Change Rules

```rust
/// Classify a contract change as breaking, conditional, non-breaking, or deprecation.
/// Rules are paradigm-specific — REST, GraphQL, gRPC, and event-driven have
/// different breaking change semantics.
pub fn classify_change(
    change: &FieldChange,
    paradigm: ApiParadigm,
) -> ChangeSeverity {
    match paradigm {
        ApiParadigm::Rest => classify_rest_change(change),
        ApiParadigm::GraphQL => classify_graphql_change(change),
        ApiParadigm::Grpc => classify_grpc_change(change),
        ApiParadigm::EventDriven => classify_event_change(change),
        _ => classify_rest_change(change), // Default to REST rules
    }
}
```

### 16.2 REST Breaking Change Rules

| Change | Severity | Rationale |
|--------|----------|-----------|
| Remove endpoint | Breaking | Consumers will get 404 |
| Remove required response field | Breaking | Consumers will get undefined |
| Change response field type | Breaking | Consumers will get type error |
| Add required request parameter | Breaking | Existing requests will fail validation |
| Change optional → required | Breaking | Existing requests missing field will fail |
| Narrow enum (remove values) | Breaking | Consumers sending removed value will fail |
| Add auth requirement | Breaking | Unauthenticated requests will fail |
| Change default values | Conditional | May affect consumers relying on defaults |
| Rename fields | Conditional | Breaks JSON but not binary |
| Add new endpoint | NonBreaking | No existing consumers affected |
| Add optional response field | NonBreaking | Consumers ignore unknown fields |
| Add optional request parameter | NonBreaking | Existing requests still valid |
| Widen enum (add values) | NonBreaking | Existing values still valid |
| Mark deprecated | Deprecation | Warning, not breaking |

### 16.3 GraphQL Breaking Change Rules

| Change | Severity | Rationale |
|--------|----------|-----------|
| Remove field | Breaking | Queries selecting removed field will fail |
| Change field type | Breaking | Type mismatch in response |
| Add required argument | Breaking | Existing queries missing argument will fail |
| Make nullable → non-nullable | Breaking | Consumers handling null will break |
| Remove enum value | Breaking | Queries using removed value will fail |
| Add field | NonBreaking | Existing queries unaffected |
| Add optional argument | NonBreaking | Existing queries still valid |
| Add enum value | NonBreaking | Existing queries unaffected |
| Deprecate field (@deprecated) | Deprecation | Warning via introspection |

### 16.4 gRPC/Protobuf Breaking Change Rules

| Change | Severity | Rationale |
|--------|----------|-----------|
| Reuse field number | Breaking | Wire format corruption |
| Change field number | Breaking | Wire format incompatibility |
| Remove service/method | Breaking | Client calls will fail |
| Change method input/output type | Breaking | Serialization failure |
| Remove field | Conditional | Binary wire format uses numbers, not names |
| Rename field | NonBreaking | Binary wire format uses numbers |
| Add new field | NonBreaking | Unknown fields ignored in proto3 |
| Add new service/method | NonBreaking | Existing clients unaffected |
| Add new enum value | Conditional | Depends on consumer handling |

### 16.5 Temporal Comparison

```rust
/// Compare contracts between two scans to detect breaking changes.
pub fn detect_breaking_changes(
    before: &[ApiContract],
    after: &[ApiContract],
) -> Vec<BreakingChange> {
    let mut changes = Vec::new();

    // Match contracts by ID
    for before_contract in before {
        match after.iter().find(|c| c.id == before_contract.id) {
            None => {
                // Contract removed — all operations are breaking
                for op in &before_contract.operations {
                    changes.push(BreakingChange {
                        change_type: ChangeType::OperationRemoved,
                        severity: ChangeSeverity::Breaking,
                        paradigm: before_contract.paradigm,
                        operation: op.name.clone(),
                        // ...
                    });
                }
            }
            Some(after_contract) => {
                // Compare operations
                changes.extend(compare_operations(
                    &before_contract.operations,
                    &after_contract.operations,
                    before_contract.paradigm,
                ));

                // Compare types
                changes.extend(compare_types_for_breaking(
                    &before_contract.types,
                    &after_contract.types,
                    before_contract.paradigm,
                ));
            }
        }
    }

    changes
}
```

---

## 17. Phase 13: Contract Drift Detection (Temporal Tracking)

### 17.1 Drift Types

```rust
/// Four types of contract drift detected by temporal analysis.
pub enum DriftType {
    /// Code-extracted contract diverges from spec-defined contract
    SpecDrift {
        spec_contract: ApiContract,
        code_contract: ApiContract,
        divergences: Vec<ContractMismatch>,
    },
    /// Contract changes between scans without corresponding spec update
    TemporalDrift {
        before: ApiContract,
        after: ApiContract,
        changes: Vec<BreakingChange>,
    },
    /// Contract test coverage decreases between scans
    CoverageDrift {
        contract_id: String,
        before_coverage: f64,
        after_coverage: f64,
    },
    /// Contract confidence decreases over time (decay without re-verification)
    ConfidenceDrift {
        contract_id: String,
        before_confidence: f64,
        after_confidence: f64,
        days_since_verification: u32,
    },
}
```

### 17.2 Snapshot Storage

```sql
CREATE TABLE contract_snapshots (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    contract_count INTEGER NOT NULL,
    checksum TEXT NOT NULL
);

CREATE TABLE contract_changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_snapshot TEXT NOT NULL REFERENCES contract_snapshots(id),
    to_snapshot TEXT NOT NULL REFERENCES contract_snapshots(id),
    contract_id TEXT NOT NULL,
    change_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT NOT NULL,
    field_path TEXT,
    before_value TEXT,
    after_value TEXT,
    detected_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

---

## 18. Phase 14: Bayesian Confidence Scoring (7-Signal)

### 18.1 Confidence Calculation

```rust
impl ContractConfidence {
    /// Calculate confidence from 7 signals using Bayesian combination.
    /// V1: score = match×0.6 + field×0.4 (simple weighted average)
    /// V2: Bayesian posterior from 7 independent signals with temporal decay.
    pub fn calculate(signals: &ConfidenceSignals, last_verified: Option<&str>) -> Self {
        // Weighted combination of signals
        let raw_score = Self::combine_signals(signals);

        // Apply temporal decay
        let decayed = Self::apply_decay(raw_score, last_verified);

        Self {
            score: decayed,
            level: ConfidenceLevel::from_score(decayed),
            signals: signals.clone(),
            last_verified: last_verified.map(String::from),
            decay_rate: 0.01,
        }
    }

    fn combine_signals(signals: &ConfidenceSignals) -> f64 {
        let weights: [(f64, f64); 7] = [
            (signals.match_confidence, 0.25),
            (signals.extraction_confidence, 0.20),
            (signals.source_quality, 0.20),
            (signals.test_coverage, 0.10),
            (signals.historical_stability, 0.10),
            (signals.usage_frequency, 0.05),
            (signals.cross_validation, 0.10),
        ];
        weights.iter().map(|(v, w)| v * w).sum::<f64>().clamp(0.0, 1.0)
    }

    fn apply_decay(score: f64, last_verified: Option<&str>) -> f64 {
        match last_verified {
            Some(timestamp) => {
                let days = days_since(timestamp);
                // Exponential decay: score × e^(-0.01 × days)
                score * (-0.01 * days as f64).exp()
            }
            None => score * 0.95 // 5% penalty for never-verified
        }
    }

    fn from_score(score: f64) -> ConfidenceLevel {
        if score >= 0.80 { ConfidenceLevel::High }
        else if score >= 0.50 { ConfidenceLevel::Medium }
        else if score >= 0.30 { ConfidenceLevel::Low }
        else { ConfidenceLevel::Uncertain }
    }
}
```

---

## 19. Phase 15: Contract Testing Integration

### 19.1 Supported Contract Testing Frameworks

| Framework | Language | Detection Pattern | Contract Extraction |
|-----------|----------|-------------------|-------------------|
| Pact (JS/TS) | TypeScript | `@pact-foundation/pact` imports | Parse Pact interaction definitions |
| Pact (Java) | Java | `au.com.dius.pact` imports, `@Pact` | Parse Pact annotations |
| Pact (Python) | Python | `pact-python` imports | Parse Pact DSL |
| Spring Cloud Contract | Java | `spring-cloud-contract` dependency | Parse contract DSL |
| Specmatic | Multi | `specmatic` dependency | Parse OpenAPI spec references |
| Karate DSL | Multi | `karate` dependency, `.feature` files | Parse Karate scenarios |

### 19.2 Contract Test Coverage

```rust
/// Cross-reference contract test coverage with detected contracts.
pub struct ContractTestCoverage {
    pub contract_id: String,
    pub test_framework: String,
    pub test_file: PathBuf,
    pub test_name: String,
    pub interactions_tested: Vec<String>,
    pub last_verified: Option<String>,
    pub verification_status: VerificationStatus,
}

pub enum VerificationStatus {
    Passing,
    Failing,
    Pending,
    Unknown,
}

/// Contracts with passing tests get a confidence boost of +0.10.
/// This feeds into the test_coverage signal in ConfidenceSignals.
```

---

## 20. Phase 16: Cross-Service Contract Tracing

### 20.1 Service Graph

```rust
/// Service dependency graph built from contract data.
/// Enables "what breaks if I change this?" analysis at the service level.
pub struct ServiceGraph {
    pub services: Vec<ServiceNode>,
    pub edges: Vec<ServiceEdge>,
}

pub struct ServiceNode {
    pub name: String,
    pub root_path: PathBuf,
    pub contracts_provided: Vec<String>,
    pub contracts_consumed: Vec<String>,
    pub paradigms: HashSet<ApiParadigm>,
}

pub struct ServiceEdge {
    pub consumer: String,
    pub provider: String,
    pub contract_id: String,
    pub paradigm: ApiParadigm,
}
```

### 20.2 Blast Radius Calculation

```rust
/// Calculate the blast radius of a contract change.
/// BFS from changed contract's provider to find all transitive consumers.
pub fn calculate_blast_radius(
    graph: &ServiceGraph,
    changed_contract: &str,
) -> BlastRadius {
    let provider = graph.find_provider(changed_contract);
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    let mut direct = Vec::new();
    let mut transitive = Vec::new();

    // BFS from provider
    queue.push_back((provider, 0));
    while let Some((service, depth)) = queue.pop_front() {
        if !visited.insert(service.clone()) { continue; }

        let consumers = graph.get_consumers(&service);
        for consumer in consumers {
            if depth == 0 {
                direct.push(consumer.clone());
            } else {
                transitive.push(consumer.clone());
            }
            queue.push_back((consumer, depth + 1));
        }
    }

    BlastRadius {
        direct_consumers: direct,
        transitive_consumers: transitive,
        affected_contracts: graph.contracts_in_path(&visited),
        impact_score: calculate_impact_score(&visited, graph),
    }
}
```

---

## 21. Phase 17: API Governance Rules Engine

### 21.1 Governance Rule Structure

```rust
pub struct GovernanceRule {
    pub id: String,
    pub name: String,
    pub category: GovernanceCategory,
    pub severity: Severity,
    pub paradigm: Option<ApiParadigm>,  // None = applies to all
    pub check: GovernanceCheck,
}

pub enum GovernanceCategory {
    Naming,         // Endpoint/field naming conventions
    Versioning,     // API versioning requirements
    Pagination,     // Pagination pattern requirements
    ErrorFormat,    // Error response format requirements
    Authentication, // Auth requirements per endpoint category
    Documentation,  // Description/summary requirements
    Deprecation,    // Deprecation policy requirements
    Security,       // Security-related API rules
}

pub enum GovernanceCheck {
    EndpointNamingPattern { pattern: String },
    FieldNamingConvention { convention: NamingConvention },
    RequireVersionInPath,
    RequireVersionHeader,
    RequirePaginationForLists,
    PaginationStyle { style: PaginationStyle },
    RequireErrorSchema { schema: String },
    RequireAuthForMutations,
    RequireAuthExceptPublic { public_paths: Vec<String> },
    RequireOperationDescription,
    RequireFieldDescription,
    RequireSunsetHeader,
    MaxDeprecationAge { days: u32 },
}
```

### 21.2 Built-in Rule Sets

| Rule Set | Description | Rules |
|----------|-------------|-------|
| `default` | Basic naming + versioning + error format | 8 rules |
| `strict` | All rules enabled with tight thresholds | 20+ rules |
| `rest-best-practices` | REST-specific (from OpenAPI best practices) | 12 rules |
| `graphql-best-practices` | GraphQL-specific (from GraphQL spec) | 8 rules |

---

## 22. Phase 18: Contract Health Score Calculation

```rust
/// Multi-factor contract health score (0-100).
/// Aggregates across all contracts in the project.
pub fn calculate_health_score(contracts: &[ApiContract]) -> ContractHealthScore {
    let total = contracts.len() as f64;
    if total == 0.0 {
        return ContractHealthScore { score: 100, grade: 'A', factors: default() };
    }

    // Factor 1: Mismatch ratio (weight 0.30)
    let mismatch_count = contracts.iter()
        .filter(|c| c.status == ContractStatus::Mismatch)
        .count() as f64;
    let mismatch_factor = 1.0 - (mismatch_count / total);

    // Factor 2: Verification ratio (weight 0.20)
    let verified_count = contracts.iter()
        .filter(|c| c.status == ContractStatus::Verified)
        .count() as f64;
    let verification_factor = verified_count / total;

    // Factor 3: Average confidence (weight 0.20)
    let avg_confidence = contracts.iter()
        .map(|c| c.confidence.score)
        .sum::<f64>() / total;

    // Factor 4: Breaking change count (weight 0.15)
    let breaking_count = contracts.iter()
        .flat_map(|c| &c.breaking_changes)
        .filter(|bc| bc.severity == ChangeSeverity::Breaking)
        .count() as f64;
    let breaking_factor = 1.0 - (breaking_count / (total * 5.0)).min(1.0);

    // Factor 5: Governance compliance (weight 0.15)
    let violation_count = contracts.iter()
        .flat_map(|c| &c.governance_violations)
        .count() as f64;
    let governance_factor = 1.0 - (violation_count / (total * 10.0)).min(1.0);

    let score = (
        mismatch_factor * 0.30
        + verification_factor * 0.20
        + avg_confidence * 0.20
        + breaking_factor * 0.15
        + governance_factor * 0.15
    ) * 100.0;

    let score = score.round() as u32;
    let grade = match score {
        90..=100 => 'A',
        80..=89 => 'B',
        70..=79 => 'C',
        60..=69 => 'D',
        _ => 'F',
    };

    ContractHealthScore { score, grade, factors: /* ... */ }
}
```

---

## 23. Incremental Contract Analysis

### 23.1 Content-Hash Invalidation

```rust
/// Only re-analyze contracts when source files change.
/// Uses content hashes from the scanner to determine which files need re-extraction.
pub fn incremental_contract_analysis(
    scan_diff: &ScanDiff,
    previous_contracts: &[ApiContract],
    db: &DatabaseManager,
) -> ContractAnalysisResult {
    // 1. Identify changed files that affect contracts
    let changed_backend_files = scan_diff.changed_files()
        .filter(|f| is_backend_file(f));
    let changed_frontend_files = scan_diff.changed_files()
        .filter(|f| is_frontend_file(f));
    let changed_spec_files = scan_diff.changed_files()
        .filter(|f| is_spec_file(f));

    // 2. Re-extract contracts only for changed files
    let new_backend_endpoints = extract_endpoints_for_files(&changed_backend_files);
    let new_frontend_calls = extract_calls_for_files(&changed_frontend_files);
    let new_spec_contracts = parse_spec_files(&changed_spec_files);

    // 3. Merge with unchanged contracts from previous scan
    let merged = merge_contracts(previous_contracts, new_backend_endpoints,
                                  new_frontend_calls, new_spec_contracts);

    // 4. Re-run matching and comparison only for affected contracts
    let affected_contracts = merged.iter()
        .filter(|c| c.is_affected_by(&scan_diff));

    // 5. Persist updated contracts
    db.batch_upsert_contracts(&merged);

    ContractAnalysisResult { contracts: merged, /* ... */ }
}
```

---

## 24-29. Integration Points

### 24. Integration with Unified Analysis Engine

Contract detectors are registered in the Unified Analysis Engine's detector registry
as Category 7 (contracts). The 6 contract detectors run during the per-file detection
phase:

| Detector | Type | V1 | V2 |
|----------|------|-----|-----|
| `contracts/rest-endpoint` | Semantic | ✅ | ✅ PRESERVED |
| `contracts/api-call` | Semantic | ✅ | ✅ PRESERVED |
| `contracts/type-mismatch` | Semantic | ✅ | ✅ UPGRADED (+ cross-paradigm) |
| `contracts/breaking-change` | Semantic | ✅ | ✅ UPGRADED (+ GraphQL/gRPC) |
| `contracts/schema-drift` | Base | ❌ | ✅ NEW |
| `contracts/deprecation` | Base | ✅ | ✅ PRESERVED |

### 25. Integration with Call Graph Builder

The call graph provides function-level tracing for cross-service contract analysis.
When a frontend function calls `fetch('/api/users')`, the call graph traces from
that function through the import chain to identify the service boundary.

### 26. Integration with Boundary Detection

Boundary detection provides sensitive field classification. When a contract exposes
a field marked as sensitive (PII, credentials, financial), the contract system flags
this as a security concern in the governance rules.

### 27. Integration with Quality Gates

```rust
/// Contract compliance quality gate.
/// Blocks merges when:
/// - Breaking changes detected (configurable threshold)
/// - Unverified contracts exceed threshold
/// - Contract health score below minimum
pub struct ContractQualityGate {
    pub max_breaking_changes: u32,          // Default: 0
    pub min_verification_ratio: f64,        // Default: 0.80
    pub min_health_score: u32,              // Default: 70
    pub require_spec_for_new_endpoints: bool, // Default: false
}
```

### 28. Integration with Simulation Engine

The simulation engine uses contract data for "what if" analysis:
- `breakingChanges: boolean` — whether the simulated change introduces breaking changes
- `breakingChangeRisks: string[]` — list of breaking change descriptions
- Blast radius from cross-service tracing feeds impact scoring

### 29. Integration with DNA System

DNA gene extractors consume contract metrics:
- Contract count per service
- Mismatch ratio
- Average confidence
- Breaking change frequency
- Paradigm distribution

---

## 30. Storage Schema (drift.db Contract Tables)

### 30.1 Complete Schema (7 Tables, 14 Indexes)

```sql
-- Core contract table (paradigm-aware)
CREATE TABLE contracts (
    id TEXT PRIMARY KEY,
    paradigm TEXT NOT NULL CHECK (paradigm IN (
        'rest', 'graphql', 'grpc', 'websocket', 'event_driven', 'trpc'
    )),
    service TEXT,
    status TEXT NOT NULL DEFAULT 'discovered' CHECK (status IN (
        'discovered', 'verified', 'mismatch', 'ignored', 'deprecated'
    )),
    source_type TEXT NOT NULL CHECK (source_type IN (
        'code_extraction', 'spec_file', 'contract_test', 'both'
    )),
    source_file TEXT NOT NULL,
    source_line INTEGER,
    source_framework TEXT,
    spec_file TEXT,
    confidence_score REAL DEFAULT 0.0,
    confidence_level TEXT DEFAULT 'low',
    confidence_signals TEXT,         -- JSON: ConfidenceSignals
    first_seen TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen TEXT NOT NULL DEFAULT (datetime('now')),
    last_verified TEXT,
    verified_by TEXT,
    UNIQUE(paradigm, id)
) STRICT;

-- Operations table
CREATE TABLE contract_operations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    contract_id TEXT NOT NULL REFERENCES contracts(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    operation_type TEXT NOT NULL,
    path TEXT,
    input_type_id INTEGER REFERENCES contract_types(id),
    output_type_id INTEGER REFERENCES contract_types(id),
    is_deprecated INTEGER DEFAULT 0,
    deprecation_reason TEXT,
    deprecation_sunset TEXT,
    source_file TEXT NOT NULL,
    source_line INTEGER NOT NULL
) STRICT;

-- Types table (supports recursive types)
CREATE TABLE contract_types (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    contract_id TEXT NOT NULL REFERENCES contracts(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    parent_type_id INTEGER REFERENCES contract_types(id),
    source_file TEXT,
    source_line INTEGER
) STRICT;

-- Fields table
CREATE TABLE contract_fields (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type_id INTEGER NOT NULL REFERENCES contract_types(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    field_type TEXT NOT NULL,
    required INTEGER DEFAULT 1,
    nullable INTEGER DEFAULT 0,
    deprecated INTEGER DEFAULT 0,
    default_value TEXT,
    description TEXT,
    sort_order INTEGER DEFAULT 0
) STRICT;

-- Mismatches table (normalized from JSON blob)
CREATE TABLE contract_mismatches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    contract_id TEXT NOT NULL REFERENCES contracts(id) ON DELETE CASCADE,
    operation_id INTEGER REFERENCES contract_operations(id),
    field_path TEXT NOT NULL,
    mismatch_type TEXT NOT NULL CHECK (mismatch_type IN (
        'missing_in_consumer', 'missing_in_provider', 'type_mismatch',
        'optionality_mismatch', 'nullability_mismatch', 'enum_mismatch',
        'constraint_mismatch'
    )),
    severity TEXT NOT NULL CHECK (severity IN ('error', 'warning', 'info')),
    description TEXT NOT NULL,
    provider_value TEXT,
    consumer_value TEXT,
    detected_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

-- Contract consumers (paradigm-agnostic, replaces contract_frontends)
CREATE TABLE contract_consumers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    contract_id TEXT NOT NULL REFERENCES contracts(id) ON DELETE CASCADE,
    consumer_type TEXT NOT NULL,
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    library TEXT,
    framework TEXT,
    expected_type_id INTEGER REFERENCES contract_types(id)
) STRICT;

-- Breaking changes table
CREATE TABLE contract_breaking_changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    contract_id TEXT NOT NULL REFERENCES contracts(id) ON DELETE CASCADE,
    scan_id TEXT NOT NULL,
    change_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT NOT NULL,
    field_path TEXT,
    before_value TEXT,
    after_value TEXT,
    detected_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

-- Indexes (14 total)
CREATE INDEX idx_contracts_paradigm ON contracts(paradigm);
CREATE INDEX idx_contracts_status ON contracts(status);
CREATE INDEX idx_contracts_service ON contracts(service);
CREATE INDEX idx_contracts_confidence ON contracts(confidence_score);
CREATE INDEX idx_contracts_source_file ON contracts(source_file);
CREATE INDEX idx_operations_contract ON contract_operations(contract_id);
CREATE INDEX idx_types_contract ON contract_types(contract_id);
CREATE INDEX idx_fields_type ON contract_fields(type_id);
CREATE INDEX idx_mismatches_contract ON contract_mismatches(contract_id);
CREATE INDEX idx_mismatches_type ON contract_mismatches(mismatch_type);
CREATE INDEX idx_mismatches_severity ON contract_mismatches(severity);
CREATE INDEX idx_consumers_contract ON contract_consumers(contract_id);
CREATE INDEX idx_consumers_file ON contract_consumers(file);
CREATE INDEX idx_breaking_contract ON contract_breaking_changes(contract_id);
```

### 30.2 Migration from V1

```sql
-- Migrate v1 contracts → v2 contracts
INSERT INTO contracts_v2 (id, paradigm, status, source_type, source_file, ...)
SELECT id, 'rest', status, 'code_extraction', backend_file, ...
FROM contracts_v1;

-- Migrate v1 contract_frontends → v2 contract_consumers
INSERT INTO contract_consumers (contract_id, consumer_type, file, line, library)
SELECT contract_id, 'rest_frontend_call', file, line, library
FROM contract_frontends_v1;

-- Normalize v1 mismatches JSON → v2 contract_mismatches rows
-- (requires JSON extraction in migration script)
```

---

## 31. NAPI Interface

### 31.1 Contract Engine Functions (8 Exports)

```rust
/// Initialize the contract engine with configuration.
#[napi]
pub fn native_init_contract_engine(config: JsContractConfig) -> Result<()> {
    // Initialize parsers, extractors, matching engine
    // Register framework detectors
    // Open database connection
}

/// Run full contract detection pipeline on given files.
/// Returns all detected contracts with mismatches and confidence.
#[napi]
pub fn native_detect_contracts(
    files: Vec<JsFileInfo>,
    spec_files: Vec<JsSpecFile>,
) -> AsyncTask<DetectContractsTask> {
    // Phase 1-5: spec parsing + code extraction
    // Phase 6-8: GraphQL/gRPC/event extraction
    // Phase 9-10: matching + comparison
    // Phase 11-14: mismatch + breaking + confidence
    AsyncTask::new(DetectContractsTask { files, spec_files })
}

/// Parse a single specification file (OpenAPI, GraphQL SDL, Protobuf, AsyncAPI).
#[napi]
pub fn native_parse_spec_file(
    path: String,
    content: String,
    spec_type: String,
) -> Result<JsApiContract> {
    // Dispatch to appropriate parser
}

/// Compare contracts between two scans for breaking changes.
#[napi]
pub fn native_compare_contracts(
    before: Vec<JsApiContract>,
    after: Vec<JsApiContract>,
) -> Result<JsContractDiff> {
    // Breaking change classifier
}

/// Calculate blast radius for a contract change.
#[napi]
pub fn native_calculate_blast_radius(
    contract_id: String,
) -> Result<JsBlastRadius> {
    // Cross-service tracing via service graph
}

/// Check API governance rules against contracts.
#[napi]
pub fn native_check_governance(
    contracts: Vec<JsApiContract>,
    rules: Vec<JsGovernanceRule>,
) -> Result<JsGovernanceResult> {
    // Governance rules engine
}

/// Query contracts from storage with filtering and pagination.
#[napi]
pub fn native_query_contracts(
    options: JsContractQueryOptions,
) -> Result<JsContractQueryResult> {
    // SQLite query with keyset pagination
}

/// Get contract statistics.
#[napi]
pub fn native_contract_stats() -> Result<JsContractStats> {
    // Aggregate stats from drift.db
}
```

---

## 32. MCP Tool Interface (8 Tools)

### 32.1 Tool Inventory

| # | Tool | Layer | Token Cost | V1 | V2 |
|---|------|-------|-----------|-----|-----|
| 1 | drift_contracts_list | Exploration | 500-1500 | ✅ | ✅ ENHANCED |
| 2 | drift_contract_detail | Exploration | 1000-3000 | ❌ | ✅ NEW |
| 3 | drift_contract_diff | Analysis | 1000-2500 | ❌ | ✅ NEW |
| 4 | drift_contract_verify | Action | 200-500 | ❌ | ✅ NEW |
| 5 | drift_contract_coverage | Analysis | 500-1500 | ❌ | ✅ NEW |
| 6 | drift_contract_breaking | Analysis | 500-2000 | ❌ | ✅ NEW |
| 7 | drift_contract_governance | Analysis | 500-2000 | ❌ | ✅ NEW |
| 8 | drift_contract_graph | Exploration | 1000-3000 | ❌ | ✅ NEW |

### 32.2 drift_contracts_list (Enhanced)

```typescript
// Arguments (enhanced from v1)
{
  paradigm?: string;        // 'rest' | 'graphql' | 'grpc' | 'event' | 'websocket' | 'trpc' | 'all'
  status?: string;          // 'all' | 'verified' | 'mismatch' | 'discovered' | 'deprecated'
  service?: string;         // Filter by service name (NEW)
  minConfidence?: number;   // Minimum confidence score (NEW)
  hasMismatches?: boolean;  // Filter by mismatch presence (NEW)
  hasBreakingChanges?: boolean; // Filter by breaking changes (NEW)
  limit?: number;           // Default: 20, max: 50 (V1 preserved)
  cursor?: string;          // Pagination cursor (V1 preserved)
}
```

### 32.3 drift_contract_detail (New)

```typescript
{
  contractId: string;
  includeHistory?: boolean;     // Include change history
  includeConsumers?: boolean;   // Include all consumers
  includeMismatches?: boolean;  // Include detailed mismatches
}
// Returns: Full contract with operations, types, fields, mismatches, consumers, history
```

### 32.4 drift_contract_diff (New)

```typescript
{
  fromScan?: string;        // Scan ID or 'previous'
  toScan?: string;          // Scan ID or 'current'
  paradigm?: string;
  onlyBreaking?: boolean;
}
// Returns: Added, removed, modified contracts with breaking change classification
```

### 32.5 drift_contract_verify (New)

```typescript
{
  contractIds: string[];
  verifiedBy?: string;
}
// Returns: Updated contracts with verification status
```

### 32.6 drift_contract_coverage (New)

```typescript
{
  service?: string;
  paradigm?: string;
}
// Returns: Coverage stats — contracts with/without tests, spec coverage, consumer coverage
```

### 32.7 drift_contract_breaking (New)

```typescript
{
  sinceDate?: string;
  sinceScan?: string;
  severity?: string;        // 'breaking' | 'conditional' | 'all'
  paradigm?: string;
}
// Returns: Breaking changes with affected consumers and migration hints
```

### 32.8 drift_contract_governance (New)

```typescript
{
  service?: string;
  rules?: string[];         // Specific governance rules to check
}
// Returns: Governance violations (naming, versioning, pagination, error format, auth)
```

---

## 33. CLI Interface (drift contracts — 6 Subcommands)

| Subcommand | Description | V1 | V2 |
|-----------|-------------|-----|-----|
| `drift contracts list` | List contracts with filtering | ✅ | ✅ ENHANCED |
| `drift contracts verify` | Mark contracts as verified | ❌ | ✅ NEW |
| `drift contracts diff` | Compare contracts between scans | ❌ | ✅ NEW |
| `drift contracts breaking` | List breaking changes | ❌ | ✅ NEW |
| `drift contracts governance` | Run governance checks | ❌ | ✅ NEW |
| `drift contracts graph` | Show service dependency graph | ❌ | ✅ NEW |

---

## 34. Event Interface

```rust
/// Contract-related events emitted via DriftEventHandler.
/// Per D5: events are emitted with no-op defaults. The bridge consumes them.
pub enum ContractEvent {
    ContractDiscovered { contract_id: String, paradigm: ApiParadigm },
    ContractVerified { contract_id: String, verified_by: String },
    ContractMismatchDetected { contract_id: String, mismatch_count: u32 },
    BreakingChangeDetected { contract_id: String, change_type: ChangeType },
    GovernanceViolation { contract_id: String, rule_id: String },
    ContractDriftDetected { contract_id: String, drift_type: String },
    SpecDriftDetected { spec_file: String, divergence_count: u32 },
}
```

---

## 35. Tracing & Observability

```rust
/// All contract operations are instrumented with tracing spans.
/// Per AD10: structured logging from the first line of code.
#[tracing::instrument(skip(files, spec_files))]
pub fn detect_contracts(files: &[FileInfo], spec_files: &[SpecFile]) -> Result<Vec<ApiContract>> {
    let _span = tracing::info_span!("contract_detection",
        file_count = files.len(),
        spec_count = spec_files.len(),
    );

    // Phase timing
    let spec_timer = tracing::info_span!("spec_parsing").entered();
    let spec_contracts = parse_spec_files(spec_files)?;
    drop(spec_timer);

    let extract_timer = tracing::info_span!("code_extraction").entered();
    let code_contracts = extract_from_code(files)?;
    drop(extract_timer);

    let match_timer = tracing::info_span!("matching").entered();
    let matched = match_contracts(&spec_contracts, &code_contracts)?;
    drop(match_timer);

    tracing::info!(
        contracts = matched.len(),
        mismatches = matched.iter().map(|c| c.mismatches.len()).sum::<usize>(),
        "contract detection complete"
    );

    Ok(matched)
}
```

---

## 36. Performance Targets & Benchmarks

| Metric | Target | Rationale |
|--------|--------|-----------|
| 1K endpoints + 1K frontend calls | < 500ms | Typical medium project |
| 10K endpoints + 10K frontend calls | < 5s | Large enterprise project |
| OpenAPI spec parsing (1MB file) | < 200ms | Large spec file |
| GraphQL SDL parsing (500KB) | < 100ms | Large schema |
| Protobuf parsing (100 .proto files) | < 500ms | Large gRPC project |
| Breaking change comparison (1K contracts) | < 100ms | CI pipeline speed |
| Incremental re-analysis (10 changed files) | < 200ms | Watch mode speed |
| SQLite query (filtered, paginated) | < 10ms | MCP tool response time |

---

## 37. Build Order & Dependencies

### 37.1 Rust Crate Dependencies

```toml
[dependencies]
# Core
serde = { version = "1", features = ["derive"] }
serde_json = "1"
serde_yaml = "0.9"

# Parsing
tree-sitter = "0.22"
tree-sitter-graphql = "0.1"     # GraphQL SDL parsing
protox-parse = "0.7"            # Pure Rust protobuf parsing (no protoc)

# Validation
jsonschema = "0.18"             # JSON Schema validation

# Storage
rusqlite = { version = "0.31", features = ["bundled"] }

# Performance
rustc-hash = "1"                # FxHashMap/FxHashSet
rayon = "1"                     # Parallel extraction

# Infrastructure
thiserror = "1"
tracing = "0.1"
```

### 37.2 Build Order

```
Phase 1 (Foundation — Weeks 1-4):
  1. model.rs — Unified contract model (all types from §4)
  2. storage/repository.rs — SQLite schema + repository
  3. config.rs — Configuration + framework registry
  4. matching/path_normalizer.rs — Path normalization (v1 preserved)
  5. matching/path_matcher.rs — Path similarity (v1 preserved)
  6. matching/field_comparator.rs — Field comparison (v1 preserved)
  7. matching/type_normalizer.rs — Type normalization (v1 preserved)
  8. NAPI scaffolding — native_detect_contracts, native_query_contracts

Phase 2 (Schema-First — Weeks 5-8):
  9. parsers/spec_discovery.rs — Spec file discovery
  10. parsers/openapi.rs — OpenAPI 3.0/3.1 parser
  11. parsers/graphql.rs — GraphQL SDL parser
  12. parsers/protobuf.rs — Protobuf parser
  13. parsers/asyncapi.rs — AsyncAPI parser
  14. native_parse_spec_file NAPI function

Phase 3 (Code-First — Weeks 9-12):
  15. extractors/rest/ — All 20+ REST framework extractors
  16. extractors/graphql/ — GraphQL code-first extractors
  17. extractors/grpc/ — gRPC extractors
  18. extractors/events/ — Event-driven extractors
  19. extractors/consumers/ — Frontend/consumer extractors
  20. tRPC extraction (TypeScript side)

Phase 4 (Analysis — Weeks 13-16):
  21. analysis/breaking_changes.rs — Breaking change classifier
  22. analysis/confidence.rs — Bayesian confidence scoring
  23. analysis/drift_detector.rs — Temporal drift detection
  24. testing/ — Contract testing integration
  25. native_compare_contracts NAPI function

Phase 5 (Enterprise — Weeks 17-20):
  26. analysis/service_graph.rs — Cross-service tracing
  27. analysis/governance.rs — API governance rules
  28. analysis/health_score.rs — Health score calculation
  29. native_calculate_blast_radius, native_check_governance NAPI functions
  30. MCP tools (all 8) + CLI commands (all 6)
```

---

## 38. V1 → V2 Feature Cross-Reference

| V1 Feature | V2 Location | Change |
|-----------|-------------|--------|
| backend-endpoint-detector.ts | extractors/rest/*.rs | Ported to Rust, 8→20+ frameworks |
| frontend-type-detector.ts | extractors/consumers/*.rs + TS layer | Split: Rust extraction + TS type resolution |
| contract-matcher.ts | matching/*.rs | Ported to Rust, algorithm preserved |
| schema-parser.ts | parsers/openapi.rs | Enhanced: 3.0/3.1, YAML+JSON |
| types.ts (~400 LOC) | model.rs | Unified multi-paradigm model |
| contract-repository.ts (~500 LOC) | storage/repository.rs | Ported to Rust (rusqlite) |
| contract-store.ts (~800 LOC) | REMOVED | JSON storage eliminated |
| hybrid-contract-store.ts (~350 LOC) | REMOVED | Dual storage eliminated |
| contracts-list.ts (~250 LOC) | MCP tool handler (TS) | Enhanced: paradigm filter, confidence filter |
| spring/ extension (2 files) | extractors/rest/spring.rs | Ported to Rust |
| django/ extension (4 files) | extractors/rest/django.rs | Ported to Rust |
| laravel/ extension (2+ files) | extractors/rest/laravel.rs | Ported to Rust |
| aspnet/ extension (1 file) | extractors/rest/aspnet.rs | Ported to Rust |
| N/A | parsers/graphql.rs | NEW: GraphQL SDL parsing |
| N/A | parsers/protobuf.rs | NEW: Protobuf parsing |
| N/A | parsers/asyncapi.rs | NEW: AsyncAPI parsing |
| N/A | analysis/breaking_changes.rs | NEW: Breaking change classifier |
| N/A | analysis/service_graph.rs | NEW: Cross-service tracing |
| N/A | analysis/governance.rs | NEW: API governance |
| N/A | analysis/confidence.rs | NEW: Bayesian 7-signal confidence |

---

## 39. Inconsistencies & Decisions

### I1: V1 Mismatch Naming (RESOLVED)

**Inconsistency**: V1 uses `missing_in_frontend` / `missing_in_backend` which is
REST-specific. GraphQL and gRPC don't have "frontend" and "backend" in the same sense.

**Decision**: Rename to `missing_in_consumer` / `missing_in_provider`. These are
paradigm-agnostic terms that work for all API paradigms. V1 data migrated automatically.

### I2: V1 Confidence Formula (RESOLVED)

**Inconsistency**: V1 uses `score = match×0.6 + field×0.4` which is a simple weighted
average with only 2 signals. Research R11 recommends Bayesian updating with 7 signals.

**Decision**: Replace with Bayesian 7-signal confidence. V1 contracts migrated with
`source_quality = 0.75` (code extraction, well-known framework) and other signals
set to 0.5 (neutral). This preserves approximate v1 confidence levels.

### I3: JSON Storage Elimination (RESOLVED)

**Inconsistency**: V1 has dual storage (SQLite + JSON) with sync complexity.
V2 is SQLite-only per architectural decision.

**Decision**: Remove JSON storage entirely. Migration script converts existing
`.drift/contracts/` JSON files to SQLite rows. No backward compatibility needed
after migration.

### I4: Frontend Type Resolution (RESOLVED)

**Inconsistency**: Frontend type resolution requires TypeScript compiler API
(generic type parameters, interface resolution, Zod schema extraction) which
cannot run in Rust.

**Decision**: Frontend type resolution stays in TypeScript. Rust extraction
handles everything except TS-specific type resolution. NAPI callback mechanism
allows Rust to request type resolution from the TS layer when needed.

### I5: tRPC Extraction (RESOLVED)

**Inconsistency**: tRPC is TypeScript-specific and requires the TS compiler API
for Zod schema extraction and type inference.

**Decision**: tRPC extraction stays entirely in TypeScript. Results are passed
to Rust via NAPI for storage and analysis alongside other paradigms.

### I6: AsyncAPI Adoption (RESOLVED)

**Inconsistency**: AsyncAPI is still an emerging standard. Not all event-driven
architectures use AsyncAPI specs.

**Decision**: Implement AsyncAPI parsing as optional. Focus on code-first extraction
for Kafka/RabbitMQ/SNS/SQS patterns. AsyncAPI spec parsing is a bonus for teams
that have adopted it.

---

## 40. Risk Register

| # | Risk | Probability | Impact | Mitigation |
|---|------|------------|--------|-----------|
| R1 | GraphQL code-first extraction complexity (many frameworks, decorator patterns) | High | Medium | Start with schema files, add code-first incrementally. Prioritize type-graphql + Strawberry. |
| R2 | Protobuf import resolution across files | Medium | Medium | Use protox-parse's built-in import resolution. Test with large proto repos. |
| R3 | tRPC extraction requires TS compiler API | High | Low | Keep in TypeScript layer. Well-understood constraint. |
| R4 | Cross-service tracing in multi-repo setups | High | High | Start with monorepo support only. Add multi-repo via contract registries (Pact Broker) in future. |
| R5 | AsyncAPI adoption still growing | Medium | Low | Implement as optional. Focus on code-first Kafka/RabbitMQ patterns. |
| R6 | Breaking change false positives | Medium | Medium | Conservative classification (err on side of "conditional" not "breaking"). User feedback loop for calibration. |
| R7 | Storage migration from v1 (JSON → SQLite) | Low | Medium | Automated migration script with rollback. Test with real v1 data. |
| R8 | OpenAPI spec parsing edge cases (3.0 vs 3.1, $ref resolution) | Medium | Medium | Use well-tested serde_yaml/json. Comprehensive test suite with real-world specs. |
| R9 | Performance regression with 6 paradigms (more extraction work per scan) | Medium | Medium | Incremental analysis (only re-extract changed files). Parallel extraction via rayon. |
| R10 | Frontend type resolution NAPI callback latency | Low | Low | Batch type resolution requests. Cache resolved types. |
| R11 | tree-sitter-graphql grammar completeness | Low | Medium | Fallback to regex extraction for unsupported GraphQL patterns. |
| R12 | Governance rule false positives (too strict defaults) | Medium | Low | Conservative defaults. Easy override via configuration. |

---

## Success Metrics (V1 → V2)

| Metric | V1 Baseline | V2 Target |
|--------|------------|-----------|
| API paradigms supported | 1 (REST) | 6 (REST, GraphQL, gRPC, WebSocket, Event-Driven, tRPC) |
| Backend frameworks | 8 | 20+ |
| Frontend/consumer libraries | 3 | 15+ |
| Mismatch types | 5 | 7 (+ enum_mismatch, constraint_mismatch) |
| Confidence signals | 2 | 7 |
| MCP tools | 1 | 8 |
| CLI subcommands | 1 (list) | 6 |
| SQLite tables | 2 | 7 |
| Indexes | 0 | 14 |
| Contract test frameworks detected | 0 | 6 |
| Breaking change categories | 0 | 20+ |
| Governance rules | 0 | 20+ |
| Spec file formats parsed | 1 (partial OpenAPI) | 4 (OpenAPI, GraphQL SDL, Protobuf, AsyncAPI) |
| Cross-service tracing | No | Yes (monorepo) |
| Temporal drift detection | No | Yes (4 drift types) |
| Health score | No | Yes (0-100, A-F grade) |
| Source files (estimated) | 18 (~4,750 LOC) | 45+ (~12,000 LOC Rust + ~2,000 LOC TS) |
