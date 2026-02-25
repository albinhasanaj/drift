# 20 Contracts — Research Recap

## Executive Summary

The Contract Tracker is Drift's API contract verification engine — a TypeScript-based subsystem that automatically discovers, matches, and monitors API contracts between backend endpoint definitions and frontend API calls. It answers the critical question: "Does the frontend expect the same fields the backend returns?" — catching type mismatches that compile fine but break at runtime. The system operates through a 5-phase pipeline (backend extraction → frontend extraction → endpoint matching → field comparison → contract creation), supports 8 backend frameworks (Express, FastAPI, Flask, Django, Spring, ASP.NET, Laravel, Go) and 3 frontend libraries (fetch, axios, custom clients), uses dual storage (SQLite primary + JSON legacy), and exposes contracts via MCP tools for AI consumption. The v1 implementation is REST-only with a simple weighted confidence model (match 0.6 + field extraction 0.4). The v2 vision expands to GraphQL, gRPC, WebSocket, and event-driven APIs with enterprise-grade confidence scoring, cross-service tracing, breaking change detection, and schema-first support.

---

## Current Implementation

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         PRESENTATION LAYER                              │
│  MCP: drift_contracts_list │ CLI: drift setup (Phase 4) │ drift scan    │
│  drift_context (API intent) │ drift_validate_change (contract check)    │
├─────────────────────────────────────────────────────────────────────────┤
│                         CONTRACT PIPELINE                               │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐ │
│  │ Backend  │  │ Frontend │  │ Endpoint │  │  Field   │  │Contract │ │
│  │ Endpoint │→│ API Call │→│ Matching │→│ Compare  │→│Creation │ │
│  │ Extract  │  │ Extract  │  │          │  │          │  │         │ │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  └─────────┘ │
├─────────────────────────────────────────────────────────────────────────┤
│                    DETECTOR LAYER (Category #7 of 16)                   │
│  backend-endpoint-detector │ frontend-type-detector │ contract-matcher  │
│  schema-parser │ Spring ext │ Laravel ext │ Django ext │ ASP.NET ext   │
├─────────────────────────────────────────────────────────────────────────┤
│                    STORAGE LAYER                                        │
│  SQLite: contracts + contract_frontends tables                          │
│  JSON: .drift/contracts/{discovered,mismatch}/contracts.json            │
│  Repository: IContractRepository (CRUD + queries + state transitions)   │
├─────────────────────────────────────────────────────────────────────────┤
│                    FRAMEWORK EXTENSIONS                                  │
│  Express (built-in) │ FastAPI (built-in) │ Flask (built-in)            │
│  Django (url-extractor, viewset-extractor, serializer-extractor)        │
│  Spring (endpoint-detector, dto-extractor)                              │
│  Laravel (endpoint-detector + extractors)                               │
│  ASP.NET (endpoint-detector)                                            │
└─────────────────────────────────────────────────────────────────────────┘
```

### Component Inventory

| Component | Location | Lines | Purpose |
|-----------|----------|-------|---------|
| Contract types | `packages/core/src/types/contracts.ts` | ~400 | All type definitions |
| Contract repository | `packages/core/src/storage/repositories/contract-repository.ts` | ~500 | SQLite CRUD + queries |
| Contract store | `packages/core/src/store/contract-store.ts` | ~800 | JSON file-based storage |
| Hybrid contract store | `packages/core/src/store/hybrid-contract-store.ts` | ~350 | SQLite↔JSON bridge (deprecated) |
| Backend endpoint detector | `packages/detectors/src/contracts/backend-endpoint-detector.ts` | ~300 | Backend extraction |
| Frontend type detector | `packages/detectors/src/contracts/frontend-type-detector.ts` | ~250 | Frontend extraction |
| Contract matcher | `packages/detectors/src/contracts/contract-matcher.ts` | ~400 | Matching + mismatch detection |
| Schema parser | `packages/detectors/src/contracts/schema-parser.ts` | ~200 | OpenAPI schema parsing |
| Contract types (detector) | `packages/detectors/src/contracts/types.ts` | ~100 | Shared detector types |
| MCP contracts list | `packages/mcp/src/tools/exploration/contracts-list.ts` | ~250 | MCP tool |
| Spring endpoint detector | `packages/detectors/src/contracts/spring/spring-endpoint-detector.ts` | ~200 | Spring Boot extraction |
| Spring DTO extractor | `packages/detectors/src/contracts/spring/dto-extractor.ts` | ~150 | Java DTO field extraction |
| Laravel endpoint detector | `packages/detectors/src/contracts/laravel/laravel-endpoint-detector.ts` | ~200 | Laravel route extraction |
| Django endpoint detector | `packages/detectors/src/contracts/django/django-endpoint-detector.ts` | ~200 | Django URL extraction |
| Django URL extractor | `packages/detectors/src/contracts/django/url-extractor.ts` | ~150 | urls.py parsing |
| Django viewset extractor | `packages/detectors/src/contracts/django/viewset-extractor.ts` | ~150 | DRF ViewSet extraction |
| Django serializer extractor | `packages/detectors/src/contracts/django/serializer-extractor.ts` | ~150 | DRF Serializer fields |
| ASP.NET endpoint detector | `packages/detectors/src/contracts/aspnet/aspnet-endpoint-detector.ts` | ~200 | ASP.NET controller extraction |

**Total estimated lines**: ~4,750 across 18 files.

---

## Core Data Models

### Contract (Primary Entity)

```typescript
interface Contract {
  id: string;                       // "contract-{method}-{hash}" format
  method: HttpMethod;               // GET | POST | PUT | PATCH | DELETE
  endpoint: string;                 // Normalized endpoint path
  backend: BackendEndpoint;         // Single backend definition
  frontend: FrontendApiCall[];      // Multiple frontend calls (1:N)
  mismatches: FieldMismatch[];      // Detected field mismatches
  status: ContractStatus;           // discovered | verified | mismatch | ignored
  confidence: ContractConfidence;   // Composite confidence score
  metadata: ContractMetadata;       // Timestamps, tags, custom data
}
```

**Lifecycle State Machine**:
```
                    ┌──────────┐
                    │discovered│ (initial state — auto-detected)
                    └────┬─────┘
                         │
              ┌──────────┼──────────┐
              ▼          ▼          ▼
         ┌────────┐ ┌────────┐ ┌───────┐
         │verified│ │mismatch│ │ignored│
         └────────┘ └────────┘ └───────┘
```

- `discovered → verified`: Manual confirmation via `verify(id, verifiedBy?)`
- `discovered → mismatch`: Auto-detected when field comparison finds differences
- `discovered → ignored`: Manual dismissal via `ignore(id)`
- All transitions update `last_seen` timestamp
- `verify()` additionally sets `verified_at` and `verified_by`

### BackendEndpoint

```typescript
interface BackendEndpoint {
  method: HttpMethod;
  path: string;                     // Framework-specific: '/api/users/{id}'
  normalizedPath: string;           // Unified: '/api/users/:id'
  file: string;                     // Source file path
  line: number;                     // Line number of route definition
  responseFields: ContractField[];  // Fields in response body
  requestFields?: ContractField[];  // Fields in request body (optional)
  responseTypeName?: string;        // Schema/model name if available
  framework: string;                // 'express' | 'fastapi' | 'flask' | 'django' | 'spring' | 'aspnet' | 'laravel'
}
```

### FrontendApiCall

```typescript
interface FrontendApiCall {
  method: HttpMethod;
  path: string;                     // Template literal: '/api/users/${id}'
  normalizedPath: string;           // Unified: '/api/users/:id'
  file: string;
  line: number;
  responseType?: string;            // TypeScript type name
  responseFields: ContractField[];  // Expected response fields
  requestType?: string;             // TypeScript request type name
  requestFields?: ContractField[];  // Request body fields
  library: string;                  // 'fetch' | 'axios' | 'react-query' | 'angular-http'
}
```

### ContractField (Recursive)

```typescript
interface ContractField {
  name: string;                     // Field name
  type: string;                     // Canonical type: string | number | boolean | object | array
  optional: boolean;                // Whether field is optional
  nullable: boolean;                // Whether field can be null
  children?: ContractField[];       // Nested fields for objects (recursive)
  arrayType?: string;               // Element type for arrays
  line?: number;                    // Source line (when available)
}
```

### FieldMismatch

```typescript
interface FieldMismatch {
  fieldPath: string;                // Dot-notation: 'user.email' for nested
  mismatchType: MismatchType;       // 5 types (see severity table)
  backendField?: ContractField;     // Backend's version of the field
  frontendField?: ContractField;    // Frontend's version of the field
  description: string;              // Human-readable description
  severity: 'error' | 'warning' | 'info';
}
```

**Mismatch Severity Rules**:

| Mismatch Type | Severity | Runtime Impact | Description |
|--------------|----------|----------------|-------------|
| `missing_in_frontend` | warning | Safe but wasteful | Backend returns field, frontend ignores it |
| `missing_in_backend` | error | Runtime crash | Frontend expects field backend doesn't return |
| `type_mismatch` | error | Runtime type error | Same field, different types |
| `optionality_mismatch` | warning | Potential undefined | Required vs optional disagreement |
| `nullability_mismatch` | warning | Potential null ref | Nullable vs non-nullable disagreement |

### ContractConfidence

```typescript
interface ContractConfidence {
  score: number;                    // 0.0-1.0 overall composite
  level: 'high' | 'medium' | 'low' | 'uncertain';
  matchConfidence: number;          // How sure about endpoint matching
  fieldExtractionConfidence: number; // How sure about field extraction
}
```

**Confidence Formula**:
```
score = (matchConfidence × 0.6) + (fieldExtractionConfidence × 0.4)
level = score ≥ 0.8 → 'high'
      | score ≥ 0.5 → 'medium'
      | score ≥ 0.3 → 'low'
      | otherwise   → 'uncertain'
```

### ContractMetadata

```typescript
interface ContractMetadata {
  firstSeen: string;                // ISO timestamp of first detection
  lastSeen: string;                 // ISO timestamp of last detection
  verifiedAt?: string;              // When manually verified
  verifiedBy?: string;              // Who verified (user/agent ID)
  tags?: string[];                  // Custom tags
  custom?: Record<string, unknown>; // Extensible metadata
}
```

### Query Types

```typescript
interface ContractQuery {
  ids?: string[];                   // Filter by specific IDs
  status?: ContractStatus | ContractStatus[];
  method?: HttpMethod | HttpMethod[];
  endpoint?: string;                // Partial match (LIKE)
  hasMismatches?: boolean;
  minMismatches?: number;
  backendFile?: string;
  frontendFile?: string;
  minConfidence?: number;
  search?: string;                  // Full-text search
}

interface ContractSortOptions {
  field: 'endpoint' | 'method' | 'mismatchCount' | 'confidence' | 'firstSeen' | 'lastSeen';
  direction: 'asc' | 'desc';
}

interface ContractQueryOptions {
  filter?: ContractQuery;
  sort?: ContractSortOptions;
  pagination?: { offset?: number; limit?: number };
}

interface ContractQueryResult {
  contracts: Contract[];
  total: number;
  hasMore: boolean;
  executionTime: number;
}

interface ContractStats {
  totalContracts: number;
  byStatus: Record<ContractStatus, number>;
  byMethod: Record<HttpMethod, number>;
  totalMismatches: number;
  mismatchesByType: Record<MismatchType, number>;
  lastUpdated: string;
}
```

---

## Core Algorithms

### Algorithm #1: Contract Detection Pipeline (5-Phase)

```
Phase 1: BACKEND ENDPOINT EXTRACTION
  Input: Source files (backend code)
  Process:
    1. Identify framework from imports/decorators (Express, FastAPI, Flask, Django, Spring, ASP.NET, Laravel)
    2. Extract route definitions:
       - Express: app.get('/path', handler), router.post('/path', handler)
       - FastAPI: @app.get("/path"), @router.post("/path")
       - Flask: @app.route("/path", methods=["GET"])
       - Django: path("path/", view), re_path(r"^path/$", view)
       - Spring: @GetMapping("/path"), @PostMapping("/path"), @RequestMapping
       - ASP.NET: [HttpGet("path")], [Route("path")]
       - Laravel: Route::get('/path', [Controller::class, 'method'])
    3. Extract HTTP method from decorator/function name
    4. Extract response fields from return type annotations/schemas
    5. Extract request fields from parameter annotations (optional)
    6. Normalize path syntax to unified format
  Output: ExtractedEndpoint[]

Phase 2: FRONTEND API CALL EXTRACTION
  Input: Source files (frontend code, TypeScript-focused)
  Process:
    1. Identify HTTP client library from imports (fetch, axios, custom)
    2. Extract API calls:
       - fetch: fetch('/api/path'), fetch(url, { method: 'POST' })
       - axios: axios.get<Type>('/api/path'), axios.post('/api/path', data)
       - react-query: useQuery<Type>('key', () => fetch('/api/path'))
       - Angular: this.http.get<Type>('/api/path')
    3. Extract HTTP method from function name or options
    4. Extract response type from:
       - Generic type parameters: axios.get<User[]>(...)
       - Type assertions: res.json() as User[]
       - Variable annotations: const data: User[] = ...
    5. Resolve TypeScript interface to extract fields
    6. Normalize path syntax
  Output: ExtractedApiCall[]

Phase 3: ENDPOINT MATCHING
  Input: ExtractedEndpoint[] + ExtractedApiCall[]
  Process:
    1. Normalize all paths to common format (see Algorithm #2)
    2. Match by (method, normalizedPath) — exact match first
    3. For non-exact matches, calculate path similarity (see Algorithm #3)
    4. Calculate match confidence based on match quality
  Output: Matched pairs + unmatchedEndpoints[] + unmatchedApiCalls[]

Phase 4: FIELD COMPARISON
  Input: Matched (BackendEndpoint, FrontendApiCall) pairs
  Process:
    1. Normalize types across languages (see Algorithm #5)
    2. Recursive field comparison (see Algorithm #4)
    3. Detect mismatches with severity classification
    4. Calculate field extraction confidence
  Output: FieldMismatch[] per pair

Phase 5: CONTRACT CREATION
  Input: Matched pairs + mismatches + confidence scores
  Process:
    1. Generate contract ID: "contract-{method}-{hash(normalizedPath)}"
    2. Set status: 'mismatch' if mismatches found, else 'discovered'
    3. Calculate overall confidence (Algorithm #6)
    4. Persist to SQLite + JSON
  Output: Contract[]
```

### Algorithm #2: Path Normalization

Converts framework-specific path syntax to a unified format:

| Framework | Input Syntax | Normalized Output |
|-----------|-------------|-------------------|
| Express | `/users/:id` | `/users/:id` |
| FastAPI | `/users/{id}` | `/users/:id` |
| Flask | `/users/<id>` | `/users/:id` |
| Django | `/users/<int:id>` | `/users/:id` |
| Spring | `/users/{id}` | `/users/:id` |
| ASP.NET | `users/{id}` | `/users/:id` |
| Frontend (template literal) | `/users/${id}` | `/users/:id` |

**Rules**:
1. Strip type annotations: `<int:id>` → `:id`
2. Convert all parameter syntaxes to `:param` format
3. Ensure leading `/`
4. Remove trailing `/`
5. Lowercase path segments (not parameters)

### Algorithm #3: Path Similarity Matching (5-Factor Weighted)

Multi-factor weighted scoring for fuzzy endpoint matching:

```
pathSimilarity(backendPath, frontendPath) → score [0.0, 1.0]

Factor 1: Segment Name Similarity (Jaccard)
  segments_a = split(backendPath, '/')
  segments_b = split(frontendPath, '/')
  non_param_a = filter(segments_a, not isParam)
  non_param_b = filter(segments_b, not isParam)
  jaccard = |intersection| / |union|

Factor 2: Segment Count Similarity
  countSim = 1 - |len(segments_a) - len(segments_b)| / max(len(a), len(b))

Factor 3: Suffix Match Score
  Match trailing segments (most specific part of path)
  suffixScore = matchingTrailingSegments / max(len(a), len(b))

Factor 4: Resource Name Match
  Extract resource names (last non-parameter segment)
  resourceScore = 1.0 if match, 0.0 if not

Factor 5: Parameter Position Alignment
  Compare positions of parameter placeholders
  paramScore = matchingPositions / totalPositions

Final: weightedSum(factors, configurable_weights)
```

### Algorithm #4: Recursive Field Comparison

```
compareFields(backendFields[], frontendFields[]) → FieldMismatch[]

  mismatches = []

  // Check backend fields against frontend
  for each backendField in backendFields:
    frontendField = find(frontendFields, f => f.name === backendField.name)

    if frontendField is null:
      mismatches.push({
        fieldPath: backendField.name,
        mismatchType: 'missing_in_frontend',
        severity: 'warning',
        backendField: backendField
      })
    else:
      // Type comparison (after normalization)
      if normalize(backendField.type) !== normalize(frontendField.type):
        mismatches.push({ mismatchType: 'type_mismatch', severity: 'error' })

      // Optionality comparison
      if backendField.optional !== frontendField.optional:
        mismatches.push({ mismatchType: 'optionality_mismatch', severity: 'warning' })

      // Nullability comparison
      if backendField.nullable !== frontendField.nullable:
        mismatches.push({ mismatchType: 'nullability_mismatch', severity: 'warning' })

      // Recursive comparison for nested objects
      if backendField.children && frontendField.children:
        nestedMismatches = compareFields(backendField.children, frontendField.children)
        // Prefix fieldPath with parent name: "user.email"
        mismatches.push(...prefixPaths(nestedMismatches, backendField.name))

  // Check for fields frontend expects but backend doesn't return
  for each frontendField in frontendFields:
    if not find(backendFields, f => f.name === frontendField.name):
      mismatches.push({
        fieldPath: frontendField.name,
        mismatchType: 'missing_in_backend',
        severity: 'error',
        frontendField: frontendField
      })

  return mismatches
```

### Algorithm #5: Cross-Language Type Normalization

Maps language-specific types to 6 canonical types for comparison:

| Canonical Type | Python | TypeScript | Java | C# | PHP | Go | Rust |
|---------------|--------|------------|------|-----|-----|-----|------|
| `string` | `str` | `string` | `String` | `string` | `string` | `string` | `String`, `&str` |
| `number` | `int`, `float` | `number` | `Integer`, `Long`, `Double`, `Float` | `int`, `long`, `double`, `float`, `decimal` | `int`, `float` | `int`, `float64` | `i32`, `i64`, `f32`, `f64` |
| `boolean` | `bool` | `boolean` | `Boolean`, `boolean` | `bool` | `bool` | `bool` | `bool` |
| `array` | `list`, `List[T]` | `T[]`, `Array<T>` | `List<T>`, `T[]` | `List<T>`, `T[]` | `array` | `[]T` | `Vec<T>` |
| `object` | `dict`, `Dict[K,V]` | `object`, `Record<K,V>` | `Map<K,V>` | `Dictionary<K,V>` | `array` (assoc) | `map[K]V` | `HashMap<K,V>` |
| `null` | `None` | `null`, `undefined` | `null` | `null` | `null` | `nil` | `None` (Option) |

### Algorithm #6: Confidence Scoring

```
overallConfidence(matchConfidence, fieldExtractionConfidence) → ContractConfidence

  score = (matchConfidence × 0.6) + (fieldExtractionConfidence × 0.4)

  level = score ≥ 0.8 → 'high'
        | score ≥ 0.5 → 'medium'
        | score ≥ 0.3 → 'low'
        | otherwise   → 'uncertain'

Match Confidence Inputs:
  - Exact path match → 1.0
  - Path match with different parameter names → 0.9
  - Path match with different base paths (/api/ prefix) → 0.7
  - Fuzzy path match → 0.5

Field Extraction Confidence Inputs:
  - Typed response (Pydantic model, TS interface) → 0.9
  - Inferred from return statements → 0.6
  - Unknown/any types → 0.3
```

---

## Storage Architecture

### SQLite Schema (Primary)

```sql
-- contracts table
CREATE TABLE IF NOT EXISTS contracts (
  id TEXT PRIMARY KEY,
  method TEXT NOT NULL CHECK (method IN ('GET', 'POST', 'PUT', 'DELETE', 'PATCH')),
  endpoint TEXT NOT NULL,
  normalized_endpoint TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'discovered'
    CHECK (status IN ('discovered', 'verified', 'mismatch', 'ignored')),
  backend_method TEXT,
  backend_path TEXT,
  backend_normalized_path TEXT,
  backend_file TEXT,
  backend_line INTEGER,
  backend_framework TEXT,
  backend_response_fields TEXT,     -- JSON array of ContractField
  confidence_score REAL DEFAULT 0.0,
  confidence_level TEXT DEFAULT 'low',
  match_confidence REAL,
  field_extraction_confidence REAL,
  mismatches TEXT,                  -- JSON array of FieldMismatch
  first_seen TEXT NOT NULL DEFAULT (datetime('now')),
  last_seen TEXT NOT NULL DEFAULT (datetime('now')),
  verified_at TEXT,
  verified_by TEXT,
  UNIQUE(method, normalized_endpoint)
);

-- contract_frontends table (1:N relationship)
CREATE TABLE IF NOT EXISTS contract_frontends (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  contract_id TEXT NOT NULL REFERENCES contracts(id) ON DELETE CASCADE,
  method TEXT NOT NULL,
  path TEXT NOT NULL,
  normalized_path TEXT NOT NULL,
  file TEXT NOT NULL,
  line INTEGER NOT NULL,
  library TEXT,
  response_fields TEXT             -- JSON array of ContractField
);
```

**Key Design Decisions**:
- One-to-many: one contract → many frontend calls (same endpoint called from multiple places)
- `UNIQUE(method, normalized_endpoint)` prevents duplicate contracts
- `CASCADE DELETE` on frontends when contract is deleted
- JSON columns for flexible nested data (response_fields, mismatches)
- Confidence stored as separate columns for efficient filtering

### ContractRepository Interface

```typescript
// CRUD
create(contract: DbContract): Promise<string>
read(id: string): Promise<DbContract | null>
update(id: string, updates: Partial<DbContract>): Promise<void>
delete(id: string): Promise<boolean>
exists(id: string): Promise<boolean>
count(filter?: Partial<DbContract>): Promise<number>

// Queries
findByStatus(status: DbContractStatus): Promise<DbContract[]>
findByMethod(method: DbHttpMethod): Promise<DbContract[]>
findByEndpoint(endpoint: string): Promise<DbContract[]>    // LIKE match
findWithMismatches(): Promise<DbContract[]>                 // status='mismatch' OR mismatches IS NOT NULL

// State Transitions
verify(id: string, verifiedBy?: string): Promise<void>     // → 'verified'
markMismatch(id: string): Promise<void>                     // → 'mismatch'
ignore(id: string): Promise<void>                           // → 'ignored'

// Frontend Management
addFrontend(contractId: string, frontend: DbContractFrontend): Promise<void>
getFrontends(contractId: string): Promise<DbContractFrontend[]>
```

### JSON File Storage (Legacy)

```
.drift/contracts/
├── discovered/
│   ├── contracts.json
│   └── .backups/
└── mismatch/
    ├── contracts.json
    └── .backups/
```

**File Format**:
```json
{
  "version": "1.0.0",
  "status": "mismatch",
  "contracts": [ /* Contract[] */ ],
  "lastUpdated": "2026-01-31T20:35:49.976Z",
  "checksum": "sha256:..."
}
```

**Migration**: `drift migrate-storage` converts JSON files to SQLite. MCP tools support both backends (SQLite preferred). `_source` field in responses indicates which backend was used.

---

## Framework Extensions

### Built-in Frameworks (3)

| Framework | Language | Detection Pattern | Response Field Extraction |
|-----------|----------|-------------------|--------------------------|
| Express/Koa | TypeScript/JavaScript | `app.get()`, `router.post()`, etc. | Return type annotations, `response.json()` calls |
| FastAPI | Python | `@app.get()`, `@router.post()` decorators | Pydantic model return type annotations |
| Flask | Python | `@app.route()` decorator | `jsonify()` / `Response()` calls |

### Framework Extensions (5)

| Framework | Language | Files | Detection Pattern | Field Extraction |
|-----------|----------|-------|-------------------|-----------------|
| Django | Python | 4 files (endpoint-detector, url-extractor, viewset-extractor, serializer-extractor) | `path()` in urlpatterns, DRF ViewSets, `@action` decorators | DRF Serializer fields, `Meta.fields`, nested serializers |
| Spring Boot | Java | 2 files (endpoint-detector, dto-extractor) | `@GetMapping`, `@PostMapping`, `@RestController`, `@RequestMapping` | Java DTO/record fields, `@JsonProperty` annotations |
| Laravel | PHP | 2+ files (endpoint-detector + extractors) | `Route::get()`, resource controllers | Controller return types |
| ASP.NET | C# | 1 file (endpoint-detector) | `[HttpGet]`, `[Route]`, controller attributes | `ActionResult<T>` generic parameter |
| Go | Go | Built-in (api detectors) | Framework-specific (Gin, Echo, Fiber, Chi) | Limited — api+auth+errors only |

### Framework Coverage Gaps

| Framework | Has Contract Detection? | Has Learning Variant? | Has Semantic Variant? |
|-----------|------------------------|----------------------|----------------------|
| Express | ✅ | ❌ | ❌ |
| FastAPI | ✅ | ❌ | ❌ |
| Flask | ✅ | ❌ | ❌ |
| Django | ✅ | ❌ | ❌ |
| Spring | ✅ | ❌ | ❌ |
| ASP.NET | ✅ | ❌ | ❌ |
| Laravel | ✅ | ❌ | ❌ |
| Go (Gin/Echo/Fiber/Chi) | ⚠️ Partial (api detectors) | ❌ | ❌ |
| Rust (Actix/Axum/Rocket/Warp) | ❌ | ❌ | ❌ |
| C++ (Crow/Boost.Beast/Qt) | ❌ | ❌ | ❌ |
| Ruby (Rails/Sinatra) | ❌ | ❌ | ❌ |
| Kotlin (Ktor/Spring) | ❌ | ❌ | ❌ |

**Critical observation**: No contract detectors have learning or semantic variants. All are base-only. This means contracts cannot learn project-specific conventions or perform deep semantic analysis.

---

## MCP Integration

### drift_contracts_list Tool

**Layer**: Exploration (medium token cost: 500-1500 tokens)

**Arguments**:
```typescript
{
  status?: string;    // 'all' | 'verified' | 'mismatch' | 'discovered' (default: 'all')
  limit?: number;     // Default: 20, max: 50
  cursor?: string;    // Pagination cursor
}
```

**Response Shape**:
```typescript
interface ContractsListData {
  contracts: ContractSummary[];
  stats: { verified: number; mismatch: number; discovered: number };
  _source?: 'sqlite' | 'json';  // Debug: which backend was used
}

interface ContractSummary {
  id: string;
  endpoint: string;
  method: string;
  status: 'verified' | 'mismatch' | 'discovered';
  frontendFile: string | undefined;
  backendFile: string;
  mismatchCount: number;
}
```

**Dual Backend Support**:
1. SQLite (preferred): `handleContractsListWithSqlite()` — queries UnifiedStore.contracts repository
2. JSON (legacy): `handleContractsListWithJson()` — reads from ContractStore (file-based)

**Related MCP Tools**:
- `drift_validate_change`: Checks if new API endpoints have corresponding frontend types
- `drift_context`: When `intent="add_feature"` and focus involves API endpoints, includes contract info

### MCP Tool Gaps (v1)

| Missing Tool | Purpose | Priority |
|-------------|---------|----------|
| `drift_contract_detail` | Deep-dive into a specific contract | P1 |
| `drift_contract_verify` | Mark contracts as verified | P1 |
| `drift_contract_batch` | Batch verify/ignore operations | P2 |
| `drift_contract_diff` | Compare contracts between scans | P2 |
| `drift_contract_breaking` | List breaking changes | P1 |

---

## Pipeline Integration

### Position in Scan Pipeline

Contract scanning is step 10 of 12 in the full scan pipeline (`drift scan`):

```
1. RESOLVE PROJECT
2. FILE DISCOVERY
3. PARSING
4. DETECTION
5. AGGREGATION
6. CONFIDENCE SCORING
7. PATTERN STORAGE
8. CALL GRAPH BUILD (optional)
9. BOUNDARY SCAN (optional)
10. CONTRACT SCAN (optional, --no-contracts to skip)  ← HERE
11. MANIFEST GENERATION (optional)
12. FINALIZATION
```

### Position in Setup Wizard

Contract scanning runs in Phase 4 (Core Features) of the setup wizard:

```
Phase 1: Prerequisites
Phase 2: Init
Phase 3: Scan + Approval
Phase 4: Core Features ← contracts, boundaries, environment, constants
Phase 5: Deep Analysis
Phase 6: Derived Features
Phase 7: Memory
Phase 8: Finalize
```

### Store Architecture Position

ContractStore is 1 of 9 stores in the MCP server initialization:

```typescript
const stores = {
  pattern: PatternStore,
  manifest: ManifestStore,
  history: HistoryStore,
  dna: DNAStore,
  boundary: BoundaryStore,
  contract: ContractStore,      // ← HERE (legacy JSON)
  callGraph: CallGraphStore,
  env: EnvStore,
  unified: UnifiedStore,        // ← SQLite-backed (preferred)
};
```

---

## Cross-Category Dependencies

### Upstream (What Contracts Needs)

| Dependency | Category | Why | Impact if Missing |
|-----------|----------|-----|-------------------|
| Parser output (AST, functions, decorators) | 02-parsers | All endpoint extraction depends on parsing | No contract detection possible |
| Pydantic model extraction | 02-parsers | FastAPI response type resolution | FastAPI contracts have 0.3 confidence (unknown types) |
| Generic type parameters | 02-parsers | TypeScript `axios.get<User[]>()` extraction | Frontend response types unresolvable |
| Tree-sitter grammars (per language) | 02-parsers | Framework-specific decorator/annotation extraction | Framework extension detection fails |

### Downstream (What Depends on Contracts)

| Consumer | Category | How It Uses Contracts | Impact if Contracts Missing |
|---------|----------|----------------------|---------------------------|
| MCP tools | 07-mcp | `drift_contracts_list`, `drift_context` (API intent) | AI has no contract awareness |
| Quality gates | 09-quality-gates | Contract compliance checking in CI/CD | No API contract enforcement |
| CLI | 10-cli | `drift setup` Phase 4, `drift scan` step 10 | Setup wizard skips contracts |
| Test topology | 17-test-topology | Contract test detection (Pact, Spring Cloud Contract) | No contract test coverage mapping |
| Security analysis | 21-security | Sensitive data in API responses | No API data exposure detection |
| Context generation | 07-mcp | `drift_context` for API-related features | AI context missing contract info |
| Storage sync | 08-storage | SyncService syncs contracts JSON↔SQLite | Dual storage inconsistency |
| Data lake views | 08-storage | StatusView includes contract stats | Dashboard missing contract metrics |

---

## Identified Limitations (V1)

### Architectural Limitations

| # | Limitation | Severity | Impact |
|---|-----------|----------|--------|
| L1 | REST-only — no GraphQL support | High | Misses ~30% of modern API surface |
| L2 | REST-only — no gRPC/Protobuf support | High | Misses microservice-to-microservice contracts |
| L3 | No OpenAPI/Swagger spec parsing | High | Cannot use schema-first contracts as source of truth |
| L4 | No breaking change classification | High | Cannot distinguish breaking vs non-breaking API changes |
| L5 | No API versioning awareness | Medium | /v1/users and /v2/users treated as different endpoints |
| L6 | No WebSocket contract detection | Medium | Real-time APIs invisible |
| L7 | No event-driven contract detection | Medium | Kafka/RabbitMQ/SNS/SQS message contracts invisible |
| L8 | No cross-service contract tracing | High | Microservice chains not tracked |

### Detection Limitations

| # | Limitation | Severity | Impact |
|---|-----------|----------|--------|
| L9 | No learning variant for contracts | Medium | Cannot learn project-specific API conventions |
| L10 | No semantic variant for contracts | Medium | Cannot perform deep semantic API analysis |
| L11 | Frontend extraction limited to TypeScript | High | No Python/Java/Go/Rust frontend client detection |
| L12 | Only 3 frontend libraries (fetch, axios, custom) | Medium | Missing react-query, SWR, Apollo, tRPC, etc. |
| L13 | Type mapping limited to 6 canonical types | Medium | Enums, unions, generics not handled |
| L14 | No request body contract validation | Medium | Only response fields compared |
| L15 | No header/query parameter contracts | Medium | Only path + body compared |
| L16 | No contract test detection (Pact, Spring Cloud Contract) | Medium | Cannot verify contracts via tests |

### Confidence & Scoring Limitations

| # | Limitation | Severity | Impact |
|---|-----------|----------|--------|
| L17 | Simple weighted average (0.6/0.4) | Medium | No Bayesian updating, no temporal decay |
| L18 | No confidence decay over time | Medium | Stale contracts retain high confidence |
| L19 | No multi-signal confidence (only match + field extraction) | Medium | Missing signals: test coverage, usage frequency, schema validation |

### Storage Limitations

| # | Limitation | Severity | Impact |
|---|-----------|----------|--------|
| L20 | Dual storage (SQLite + JSON) | Medium | Sync complexity, potential inconsistency |
| L21 | Mismatches stored as JSON blob | Medium | Cannot query individual mismatches efficiently |
| L22 | No indexes on backend_file or confidence_score | Low | Slow queries on large contract sets |
| L23 | No contract history/versioning | Medium | Cannot track contract evolution over time |

### MCP Limitations

| # | Limitation | Severity | Impact |
|---|-----------|----------|--------|
| L24 | Only 1 MCP tool (drift_contracts_list) | High | Limited AI interaction surface |
| L25 | No contract detail tool | Medium | AI cannot deep-dive into specific contracts |
| L26 | No contract verification tool | Medium | AI cannot mark contracts as verified |
| L27 | No batch operations | Low | Tedious for large contract sets |

**Total: 27 limitations identified across 4 categories.**

---

## V2 Migration Considerations

### What Moves to Rust

| Component | Current (TS) | V2 (Rust) | Rationale |
|-----------|-------------|-----------|-----------|
| Path normalization | TS string manipulation | Rust | Simple, performance-critical |
| Path similarity matching | TS weighted scoring | Rust | CPU-intensive for large codebases |
| Field comparison | TS recursive | Rust | Pure logic, no TS dependencies |
| Type normalization | TS mapping | Rust | Lookup table, trivial to port |
| Backend endpoint extraction | TS (framework-specific) | Rust | Decorator/annotation extraction already in Rust parsers |
| SQLite storage | TS (better-sqlite3) | Rust (rusqlite) | Rust owns drift.db writes |

### What Stays in TypeScript

| Component | Rationale |
|-----------|-----------|
| Frontend API call extraction | TypeScript compiler API needed for generic type resolution |
| MCP tools | MCP server is TS-based |
| CLI commands | CLI is TS-based |
| Contract store (JSON legacy) | Deprecated — remove after migration |

### What's New in V2

| Component | Description |
|-----------|-------------|
| GraphQL contract detection | Schema extraction, query↔schema mismatch, N+1 resolver detection |
| gRPC/Protobuf contract detection | .proto parsing, service/message definitions, breaking change detection |
| WebSocket contract detection | Message schema extraction, event contract matching |
| Event-driven contract detection | AsyncAPI spec parsing, message broker contract matching |
| Unified contract model | Cross-paradigm normalization (REST + GraphQL + gRPC + WebSocket + events) |
| Breaking change classifier | Classify API changes as breaking/non-breaking/deprecation |
| Contract drift detection | Temporal tracking of contract changes across scans |
| Cross-service contract tracing | Follow contract chains across microservices |
| Enhanced confidence model | Bayesian updating, temporal decay, multi-signal scoring |
| Contract testing integration | Pact, Spring Cloud Contract, contract test detection |

---

## Key Metrics (V1)

| Metric | Value |
|--------|-------|
| Total source files | ~18 |
| Total estimated lines | ~4,750 |
| Supported backend frameworks | 8 (Express, FastAPI, Flask, Django, Spring, ASP.NET, Laravel, Go) |
| Supported frontend libraries | 3 (fetch, axios, custom) |
| Mismatch types | 5 |
| Confidence signals | 2 (match + field extraction) |
| SQLite tables | 2 (contracts, contract_frontends) |
| MCP tools | 1 (drift_contracts_list) |
| API paradigms supported | 1 (REST only) |
| Detector variants | 1 (base only — no learning, no semantic) |
| Languages with contract detection | 7 (TS, JS, Python, Java, C#, PHP, Go) |
| Languages without contract detection | 3 (Rust, C, C++) |
