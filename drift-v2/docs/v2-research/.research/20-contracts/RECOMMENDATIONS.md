# 20 Contracts — Recommendations

> Concrete, actionable recommendations for Drift v2's contract detection subsystem. Each recommendation is grounded in research findings, addresses specific v1 limitations, and considers full-pipeline impact.

---

## R1: Unified Contract Model — Multi-Paradigm Foundation

**Sources**: Research R1 (OpenAPI), R2 (GraphQL), R3 (gRPC), R4 (AsyncAPI), R7 (tRPC), R8 (WebSocket)
**Priority**: P0 (Architectural foundation — everything else depends on this)
**Effort**: High
**Impact**: Enables all other recommendations; eliminates REST-only limitation (L1, L2)

**Design**:

Build a unified contract model that normalizes all API paradigms into a common representation. This is the architectural foundation — every other recommendation builds on this model.

```rust
/// The universal API paradigm enum
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ApiParadigm {
    Rest,
    GraphQL,
    Grpc,
    WebSocket,
    EventDriven,   // Kafka, RabbitMQ, SNS/SQS
    Trpc,          // TypeScript-specific
}

/// Source of contract truth
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ContractSource {
    CodeExtraction {
        file: PathBuf,
        line: u32,
        framework: String,
        extraction_confidence: f64,
    },
    SpecFile {
        file: PathBuf,
        spec_type: SpecType,       // OpenAPI | GraphQL SDL | Proto | AsyncAPI
        spec_version: String,
    },
    ContractTest {
        file: PathBuf,
        framework: String,         // Pact | SpringCloudContract | Specmatic
        test_name: String,
    },
    Both {
        spec: Box<ContractSource>,
        code: Box<ContractSource>,
    },
}

/// Unified API contract
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiContract {
    pub id: String,
    pub paradigm: ApiParadigm,
    pub service: Option<String>,       // Service name (for microservices)
    pub operations: Vec<ApiOperation>,
    pub types: Vec<ApiType>,
    pub source: ContractSource,
    pub status: ContractStatus,
    pub confidence: ContractConfidence,
    pub metadata: ContractMetadata,
    pub breaking_changes: Vec<BreakingChange>,
    pub governance_violations: Vec<GovernanceViolation>,
}

/// Unified API operation (endpoint, query, RPC method, event)
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OperationType {
    // REST
    HttpGet { path: String },
    HttpPost { path: String },
    HttpPut { path: String },
    HttpPatch { path: String },
    HttpDelete { path: String },
    // GraphQL
    GraphQLQuery { field_name: String },
    GraphQLMutation { field_name: String },
    GraphQLSubscription { field_name: String },
    // gRPC
    GrpcUnary { service: String, method: String },
    GrpcServerStream { service: String, method: String },
    GrpcClientStream { service: String, method: String },
    GrpcBidiStream { service: String, method: String },
    // Event-Driven
    EventPublish { channel: String, event_type: String },
    EventSubscribe { channel: String, event_type: String },
    // WebSocket
    WsMessage { event: String, direction: MessageDirection },
    // tRPC
    TrpcQuery { procedure: String },
    TrpcMutation { procedure: String },
    TrpcSubscription { procedure: String },
}

/// Unified type system for contract fields
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
    Reference(String),  // Reference to another named type
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScalarType {
    String,
    Integer,
    Float,
    Boolean,
    DateTime,
    Binary,
    Null,
    Any,
}

/// Unified field definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiField {
    pub name: String,
    pub field_type: ApiType,
    pub required: bool,
    pub nullable: bool,
    pub default_value: Option<serde_json::Value>,
    pub description: Option<String>,
    pub deprecated: bool,
    pub constraints: Vec<FieldConstraint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FieldConstraint {
    MinLength(usize),
    MaxLength(usize),
    Minimum(f64),
    Maximum(f64),
    Pattern(String),
    Enum(Vec<serde_json::Value>),
    Format(String),  // email, uri, uuid, date-time, etc.
}
```

**Rationale**: V1's contract model is REST-specific (HttpMethod, endpoint path, response fields). This cannot represent GraphQL queries, gRPC methods, or event-driven messages. A unified model enables cross-paradigm analysis ("Does the REST endpoint return the same user fields as the GraphQL query?") and simplifies downstream consumers (MCP tools, quality gates, CLI all work with one model).

**Pipeline Impact**:
- Storage: New SQLite schema with paradigm-aware tables
- MCP: All contract tools work with unified model
- Quality Gates: Paradigm-agnostic contract compliance checking
- CLI: Single `drift contracts` command for all paradigms

**Dependencies**: None — this is the foundation.

---

## R2: Schema-First Contract Detection (OpenAPI, GraphQL SDL, Proto, AsyncAPI)

**Sources**: Research R1 (OpenAPI), R2 (GraphQL), R3 (gRPC), R4 (AsyncAPI)
**Priority**: P0 (Enterprise requirement — schema-first is the industry standard)
**Effort**: High
**Impact**: Addresses L1, L2, L3, L6, L7; enables spec-vs-code drift detection

**Design**:

Build parsers for the four major API specification formats, each producing the unified contract model from R1:

**1. OpenAPI Parser (Rust)**:
```rust
pub struct OpenApiParser {
    // Supports OpenAPI 3.0.x and 3.1.x (YAML and JSON)
}

impl OpenApiParser {
    pub fn parse(content: &str, format: SpecFormat) -> Result<Vec<ApiContract>> {
        // 1. Parse YAML/JSON into serde_json::Value
        // 2. Validate against OpenAPI schema
        // 3. Extract paths → ApiOperation (one per method per path)
        // 4. Extract components/schemas → ApiType
        // 5. Resolve $ref references
        // 6. Extract parameters (path, query, header, cookie)
        // 7. Extract security requirements
        // 8. Build ApiContract with ContractSource::SpecFile
    }
}
```

**2. GraphQL Schema Parser (Rust via tree-sitter-graphql)**:
```rust
pub struct GraphQLSchemaParser {
    // Uses tree-sitter-graphql for SDL parsing
    // Supports .graphql, .gql files
}

impl GraphQLSchemaParser {
    pub fn parse(content: &str) -> Result<Vec<ApiContract>> {
        // 1. Parse SDL with tree-sitter-graphql
        // 2. Extract type definitions → ApiType
        // 3. Extract Query type fields → ApiOperation::GraphQLQuery
        // 4. Extract Mutation type fields → ApiOperation::GraphQLMutation
        // 5. Extract Subscription type fields → ApiOperation::GraphQLSubscription
        // 6. Extract @deprecated directives → DeprecationInfo
        // 7. Build ApiContract with paradigm: GraphQL
    }
}
```

**3. Protobuf Parser (Rust via protox-parse)**:
```rust
pub struct ProtobufParser {
    // Uses protox-parse for pure-Rust .proto parsing
    // No protoc dependency required
}

impl ProtobufParser {
    pub fn parse(content: &str, file: &Path) -> Result<Vec<ApiContract>> {
        // 1. Parse .proto file with protox-parse
        // 2. Extract service definitions → one ApiContract per service
        // 3. Extract rpc methods → ApiOperation (unary, server/client/bidi stream)
        // 4. Extract message definitions → ApiType
        // 5. Track field numbers for breaking change detection
        // 6. Resolve imports for cross-file types
        // 7. Build ApiContract with paradigm: Grpc
    }
}
```

**4. AsyncAPI Parser (Rust)**:
```rust
pub struct AsyncApiParser {
    // Supports AsyncAPI 2.x and 3.0
    // YAML and JSON formats
}

impl AsyncApiParser {
    pub fn parse(content: &str, format: SpecFormat) -> Result<Vec<ApiContract>> {
        // 1. Parse YAML/JSON
        // 2. Extract channels → scoping for operations
        // 3. Extract operations → ApiOperation (EventPublish/EventSubscribe)
        // 4. Extract message schemas → ApiType
        // 5. Extract protocol bindings (Kafka, AMQP, MQTT, WebSocket)
        // 6. Build ApiContract with paradigm: EventDriven or WebSocket
    }
}
```

**Spec File Discovery**:
```rust
pub fn discover_spec_files(root: &Path) -> Vec<SpecFile> {
    // OpenAPI: openapi.yaml, openapi.json, swagger.yaml, swagger.json,
    //          *.openapi.yaml, *.openapi.json
    // GraphQL: schema.graphql, *.graphql, *.gql
    // Protobuf: *.proto
    // AsyncAPI: asyncapi.yaml, asyncapi.json, *.asyncapi.yaml
    // Also check common directories: api/, specs/, proto/, schemas/
}
```

**Rationale**: Enterprise codebases increasingly use schema-first API design. Without spec parsing, Drift misses the "source of truth" for API contracts and cannot detect implementation drift (where code diverges from spec).

**Pipeline Impact**:
- Scanner: Add spec file discovery to file walking
- Parser: New spec parsers alongside code parsers
- Detection: Spec-extracted contracts compared against code-extracted contracts
- Storage: Spec source tracked in ContractSource

**Dependencies**: R1 (Unified Contract Model)

---

## R3: Code-First Contract Extraction (Enhanced)

**Sources**: Research R2 (GraphQL code-first), R3 (gRPC), R7 (tRPC), RECAP (v1 extraction)
**Priority**: P0 (Core functionality — enhanced version of v1)
**Effort**: High
**Impact**: Addresses L9, L10, L11, L12, L13, L14, L15

**Design**:

Enhance v1's code-first extraction to cover all paradigms and more frameworks:

**REST Extraction (Enhanced from v1)**:
- Add Go framework support: Gin (`r.GET`), Echo (`e.GET`), Fiber (`app.Get`), Chi (`r.Get`)
- Add Rust framework support: Actix (`#[get]`), Axum (`Router::new().route`), Rocket (`#[get]`)
- Add Ruby framework support: Rails (`get '/path'`), Sinatra (`get '/path'`)
- Add Kotlin framework support: Ktor (`get("/path")`), Spring Kotlin
- Enhance frontend extraction: Add SWR, react-query v5, Apollo REST Link, tRPC HTTP, Ky, Got, Superagent
- Extract request headers and query parameters (not just body)
- Extract response status codes and error responses
- Extract middleware/interceptor chains for auth detection

**GraphQL Code-First Extraction**:
```rust
// Detect code-first GraphQL frameworks:
// TypeScript: type-graphql, nexus, pothos, graphql-yoga
// Python: Strawberry, Ariadne, Graphene
// Java: graphql-java, DGS Framework
// Rust: juniper, async-graphql
// Go: gqlgen, graphql-go

pub fn extract_graphql_from_code(file: &ParseResult) -> Vec<ApiContract> {
    // 1. Detect GraphQL framework from imports
    // 2. Extract type definitions from decorators/annotations
    // 3. Extract resolver implementations
    // 4. Map resolvers to schema types
    // 5. Detect N+1 patterns (resolver calls DB in loop without batching)
}
```

**gRPC Server/Client Extraction**:
```rust
// Detect gRPC implementations:
// TypeScript: @grpc/grpc-js, nice-grpc
// Python: grpcio
// Java: io.grpc
// Go: google.golang.org/grpc
// Rust: tonic

pub fn extract_grpc_from_code(file: &ParseResult) -> Vec<ApiContract> {
    // 1. Detect gRPC framework from imports
    // 2. Extract service implementations (server-side)
    // 3. Extract client stubs (client-side)
    // 4. Match against .proto definitions
}
```

**Event-Driven Extraction**:
```rust
// Detect message broker patterns:
// Kafka: kafkajs, confluent-kafka, kafka-python, sarama
// RabbitMQ: amqplib, pika, lapin
// AWS: @aws-sdk/client-sns, @aws-sdk/client-sqs
// Redis: ioredis (pub/sub), redis-py

pub fn extract_events_from_code(file: &ParseResult) -> Vec<ApiContract> {
    // 1. Detect message broker library from imports
    // 2. Extract producer calls (topic, message schema)
    // 3. Extract consumer handlers (topic, expected message schema)
    // 4. Infer message schemas from serialization/deserialization code
}
```

**tRPC Extraction (TypeScript-only)**:
```typescript
// Detect tRPC router definitions
// Extract procedure names, input schemas (Zod), output types
// Match client calls against router definitions

function extractTrpcContracts(file: ParseResult): ApiContract[] {
    // 1. Detect tRPC imports (from '@trpc/server')
    // 2. Extract router definitions (t.router({ ... }))
    // 3. Extract procedure definitions (t.procedure.input(z.object({...})).query(...))
    // 4. Extract Zod input schemas as request contracts
    // 5. Infer output types from procedure implementations
    // 6. Detect tRPC client usage and match against router
}
```

**Rationale**: V1 only extracts REST contracts from 8 backend frameworks and 3 frontend libraries. Enterprise codebases use GraphQL, gRPC, event-driven patterns, and tRPC. Code-first extraction must cover all paradigms to match schema-first detection.

**Pipeline Impact**:
- Detectors: New detector files for each paradigm/framework
- Parsers: May need new tree-sitter queries for framework-specific patterns
- Storage: All extracted contracts use unified model from R1

**Dependencies**: R1 (Unified Contract Model), 02-parsers (framework-specific extraction)

---

## R4: Breaking Change Classifier

**Sources**: Research R5 (Breaking change classification), R1 (OpenAPI), R2 (GraphQL), R3 (gRPC)
**Priority**: P1 (Critical for CI/CD integration)
**Effort**: Medium
**Impact**: Addresses L4; enables quality gate enforcement

**Design**:

Implement a paradigm-aware breaking change classifier that compares contracts across scans:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakingChange {
    pub change_type: ChangeType,
    pub severity: ChangeSeverity,
    pub paradigm: ApiParadigm,
    pub operation: String,          // Affected operation name
    pub field_path: Option<String>, // Affected field (if field-level change)
    pub description: String,
    pub before: Option<String>,     // Previous value/type
    pub after: Option<String>,      // New value/type
    pub migration_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChangeSeverity {
    Breaking,       // Will break existing consumers
    Conditional,    // May break depending on consumer usage
    NonBreaking,    // Safe for all consumers
    Deprecation,    // Marked for future removal
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    ProtoFieldNumberReused,     // gRPC-specific: always breaking
    ProtoFieldNumberChanged,    // gRPC-specific: always breaking
    GraphQLArgumentAdded,       // GraphQL-specific: breaking if required
    GraphQLNullabilityTightened, // GraphQL-specific: always breaking
}
```

**Paradigm-Specific Rules**:

| Change | REST | GraphQL | gRPC | Event-Driven |
|--------|------|---------|------|-------------|
| Remove operation | Breaking | Breaking | Breaking | Breaking |
| Add optional field | Non-breaking | Non-breaking | Non-breaking | Non-breaking |
| Add required field | Breaking (request) | Breaking (argument) | Non-breaking (proto3) | Breaking |
| Remove field | Breaking (response) | Breaking | Non-breaking (wire) | Conditional |
| Change field type | Breaking | Breaking | Conditional | Breaking |
| Rename field | Breaking (JSON) | Breaking | Non-breaking (wire) | Breaking (JSON) |
| Reuse field number | N/A | N/A | Breaking | N/A |

**Rationale**: Without breaking change classification, Drift cannot distinguish between safe API evolution and dangerous breaking changes. This is critical for CI/CD quality gates — you want to block breaking changes but allow non-breaking additions.

**Pipeline Impact**:
- Quality Gates: New "contract breaking change" gate
- CLI: `drift contracts diff` command
- MCP: `drift_contract_breaking` tool
- Storage: Breaking changes stored per contract

**Dependencies**: R1 (Unified Contract Model), R2/R3 (spec parsing for before/after comparison)

---

## R5: Enhanced Confidence Model

**Sources**: Research R11 (Confidence improvements), RECAP (v1 confidence model)
**Priority**: P1 (Accuracy improvement)
**Effort**: Medium
**Impact**: Addresses L17, L18, L19

**Design**:

Replace v1's simple weighted average with a multi-signal Bayesian confidence model:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractConfidence {
    pub score: f64,                     // 0.0-1.0 posterior probability
    pub level: ConfidenceLevel,
    pub signals: ConfidenceSignals,
    pub history: Vec<ConfidenceUpdate>, // Bayesian update history
    pub last_verified: Option<DateTime<Utc>>,
    pub decay_rate: f64,                // Per-day decay factor
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceSignals {
    pub match_confidence: f64,          // Endpoint matching quality (0.0-1.0)
    pub extraction_confidence: f64,     // Field extraction quality (0.0-1.0)
    pub source_quality: f64,            // Schema source reliability (0.0-1.0)
    pub test_coverage: f64,             // Contract test coverage (0.0-1.0)
    pub historical_stability: f64,      // Stability across scans (0.0-1.0)
    pub usage_frequency: f64,           // How often endpoint is called (0.0-1.0)
    pub cross_validation: f64,          // Agreement between extraction methods (0.0-1.0)
}

impl ContractConfidence {
    pub fn calculate(signals: &ConfidenceSignals) -> Self {
        // Bayesian combination of signals
        // Prior: based on source quality
        // Evidence: each signal updates the posterior
        let prior = signals.source_quality;
        let likelihood = Self::combine_signals(signals);
        let posterior = Self::bayesian_update(prior, likelihood);

        // Apply temporal decay
        let decayed = Self::apply_decay(posterior, /* last_verified */);

        Self {
            score: decayed,
            level: ConfidenceLevel::from_score(decayed),
            signals: signals.clone(),
            history: vec![],
            last_verified: None,
            decay_rate: 0.01, // 1% per day
        }
    }

    fn combine_signals(signals: &ConfidenceSignals) -> f64 {
        // Weighted combination with diminishing returns
        let weights = [
            (signals.match_confidence, 0.25),
            (signals.extraction_confidence, 0.20),
            (signals.source_quality, 0.20),
            (signals.test_coverage, 0.10),
            (signals.historical_stability, 0.10),
            (signals.usage_frequency, 0.05),
            (signals.cross_validation, 0.10),
        ];
        weights.iter().map(|(v, w)| v * w).sum()
    }

    fn apply_decay(score: f64, last_verified: Option<DateTime<Utc>>) -> f64 {
        match last_verified {
            Some(t) => {
                let days = (Utc::now() - t).num_days() as f64;
                score * (-0.01 * days).exp() // Exponential decay
            }
            None => score * 0.95 // 5% penalty for never-verified
        }
    }
}
```

**Source Quality Priors**:

| Source | Prior Confidence |
|--------|-----------------|
| OpenAPI spec + code match | 0.95 |
| OpenAPI spec only | 0.90 |
| Typed code (Pydantic, TS interface) | 0.85 |
| Contract test (Pact) | 0.85 |
| Code extraction (well-known framework) | 0.75 |
| Code extraction (custom framework) | 0.60 |
| Inferred from return statements | 0.50 |
| Unknown/any types | 0.30 |

**Rationale**: V1's 2-signal weighted average cannot distinguish between a contract extracted from an OpenAPI spec with Pact tests (very reliable) and one inferred from untyped return statements (unreliable). Multi-signal Bayesian confidence provides calibrated accuracy.

**Pipeline Impact**:
- Storage: Additional confidence columns in SQLite
- MCP: Confidence breakdown in contract detail responses
- Quality Gates: Confidence-based filtering (only enforce high-confidence contracts)

**Dependencies**: R1 (Unified Contract Model)

---

## R6: Contract Testing Integration

**Sources**: Research R6 (Pact), R3 (gRPC contract testing)
**Priority**: P1 (Bridges static analysis and runtime verification)
**Effort**: Medium
**Impact**: Addresses L16; adds contract test coverage as confidence signal

**Design**:

Detect and integrate with contract testing frameworks to cross-reference static contracts with test-verified contracts:

**Supported Frameworks**:

| Framework | Detection Pattern | Contract Extraction |
|-----------|-------------------|-------------------|
| Pact (JS/TS) | `@pact-foundation/pact` imports, `.pact.json` files | Parse Pact interaction definitions |
| Pact (Java) | `au.com.dius.pact` imports, `@Pact` annotations | Parse Pact annotations |
| Pact (Python) | `pact-python` imports | Parse Pact DSL |
| Spring Cloud Contract | `spring-cloud-contract` dependency, `.groovy`/`.yaml` stubs | Parse contract DSL |
| Specmatic | `specmatic` dependency, `specmatic.json` config | Parse OpenAPI spec references |
| Karate DSL | `karate` dependency, `.feature` files | Parse Karate scenarios |

**Integration Points**:

1. **Contract Test Discovery**: Scan for contract test files and extract contract definitions
2. **Cross-Reference**: Match test-defined contracts against code-extracted contracts
3. **Coverage Reporting**: Report which contracts have test coverage and which don't
4. **Confidence Boost**: Contracts with passing tests get a confidence boost (+0.10)
5. **Quality Gate**: "Contract test coverage" gate — require N% of contracts to have tests

```rust
pub struct ContractTestCoverage {
    pub contract_id: String,
    pub test_framework: String,
    pub test_file: PathBuf,
    pub test_name: String,
    pub interactions_tested: Vec<String>,
    pub last_verified: DateTime<Utc>,
    pub verification_status: VerificationStatus,
}

pub enum VerificationStatus {
    Passing,
    Failing,
    Pending,
    Unknown,
}
```

**Rationale**: Static contract detection tells you what contracts exist. Contract testing tells you which contracts are verified. Combining both gives the most complete picture of API contract health.

**Dependencies**: R1 (Unified Contract Model), R5 (Confidence Model — test coverage signal)

---

## R7: Contract Drift Detection (Temporal Tracking)

**Sources**: Research R5 (Breaking changes), R12 (API governance)
**Priority**: P1 (Regression prevention)
**Effort**: Medium
**Impact**: Addresses L23; enables temporal contract analysis

**Design**:

Track contract changes across scans to detect drift — gradual, unintentional divergence between API specification and implementation:

```rust
pub struct ContractSnapshot {
    pub scan_id: String,
    pub timestamp: DateTime<Utc>,
    pub contracts: Vec<ApiContract>,
    pub checksum: String,
}

pub struct ContractDiff {
    pub from_scan: String,
    pub to_scan: String,
    pub added: Vec<ApiContract>,
    pub removed: Vec<ApiContract>,
    pub modified: Vec<ContractModification>,
    pub breaking_changes: Vec<BreakingChange>,
}

pub struct ContractModification {
    pub contract_id: String,
    pub changes: Vec<FieldChange>,
    pub severity: ChangeSeverity,
}
```

**Drift Detection Rules**:
1. **Spec drift**: Code-extracted contract diverges from spec-defined contract
2. **Temporal drift**: Contract changes between scans without corresponding spec update
3. **Coverage drift**: Contract test coverage decreases between scans
4. **Confidence drift**: Contract confidence decreases over time (decay without re-verification)

**Storage**:
```sql
CREATE TABLE contract_snapshots (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
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
    after_value TEXT
);
```

**Rationale**: Without temporal tracking, Drift can only show the current state of contracts. Temporal tracking enables trend analysis ("are contracts getting better or worse?"), regression detection ("this scan introduced 3 breaking changes"), and drift alerts ("implementation has diverged from spec").

**Dependencies**: R1 (Unified Contract Model), R4 (Breaking Change Classifier)

---

## R8: Cross-Service Contract Tracing

**Sources**: Research R9 (Microservice contracts)
**Priority**: P2 (Enterprise scale — important but complex)
**Effort**: High
**Impact**: Addresses L8; enables microservice contract analysis

**Design**:

Build a service dependency graph from contract data to trace API contracts across service boundaries:

```rust
pub struct ServiceGraph {
    pub services: Vec<ServiceNode>,
    pub edges: Vec<ServiceEdge>,
}

pub struct ServiceNode {
    pub name: String,
    pub root_path: PathBuf,
    pub contracts_provided: Vec<String>,  // Contract IDs this service provides
    pub contracts_consumed: Vec<String>,  // Contract IDs this service consumes
    pub paradigms: HashSet<ApiParadigm>,
}

pub struct ServiceEdge {
    pub consumer: String,       // Consumer service name
    pub provider: String,       // Provider service name
    pub contract_id: String,    // The contract connecting them
    pub paradigm: ApiParadigm,
}
```

**Service Discovery** (monorepo):
1. Detect service boundaries from project structure (separate `package.json`, `Cargo.toml`, `pom.xml`, etc.)
2. Detect Docker Compose service definitions
3. Detect Kubernetes service manifests
4. Use import analysis to identify cross-service dependencies

**Blast Radius Calculation**:
```rust
pub fn calculate_blast_radius(
    graph: &ServiceGraph,
    changed_contract: &str,
) -> BlastRadius {
    // BFS from changed contract's provider
    // Find all transitive consumers
    // Calculate impact score based on depth and criticality
    BlastRadius {
        direct_consumers: vec![],
        transitive_consumers: vec![],
        affected_contracts: vec![],
        impact_score: 0.0,
    }
}
```

**Rationale**: In microservice architectures, a breaking change in one service can cascade through the dependency chain. Cross-service tracing enables "what breaks if I change this?" analysis at the service level.

**Dependencies**: R1 (Unified Contract Model), R4 (Breaking Change Classifier), 04-call-graph (function-level tracing)

---

## R9: Enhanced Storage Schema

**Sources**: Research R10 (Rust-native engine), RECAP (v1 storage), 08-storage RECOMMENDATIONS
**Priority**: P0 (Required for unified model)
**Effort**: Medium
**Impact**: Addresses L20, L21, L22, L23

**Design**:

Replace v1's dual storage with a single SQLite schema supporting the unified contract model:

```sql
-- Core contract table (paradigm-aware)
CREATE TABLE contracts (
    id TEXT PRIMARY KEY,
    paradigm TEXT NOT NULL CHECK (paradigm IN (
        'rest', 'graphql', 'grpc', 'websocket', 'event_driven', 'trpc'
    )),
    service TEXT,                    -- Service name (for microservices)
    status TEXT NOT NULL DEFAULT 'discovered' CHECK (status IN (
        'discovered', 'verified', 'mismatch', 'ignored', 'deprecated'
    )),
    source_type TEXT NOT NULL CHECK (source_type IN (
        'code_extraction', 'spec_file', 'contract_test', 'both'
    )),
    source_file TEXT NOT NULL,
    source_line INTEGER,
    source_framework TEXT,
    spec_file TEXT,                  -- Associated spec file (if any)
    confidence_score REAL DEFAULT 0.0,
    confidence_level TEXT DEFAULT 'low',
    confidence_signals TEXT,         -- JSON: ConfidenceSignals
    first_seen TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen TEXT NOT NULL DEFAULT (datetime('now')),
    last_verified TEXT,
    verified_by TEXT,
    UNIQUE(paradigm, id)
);

-- Operations table (normalized from JSON)
CREATE TABLE contract_operations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    contract_id TEXT NOT NULL REFERENCES contracts(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    operation_type TEXT NOT NULL,    -- HttpGet, GraphQLQuery, GrpcUnary, etc.
    path TEXT,                       -- REST path, GraphQL field, gRPC method
    input_type_id INTEGER REFERENCES contract_types(id),
    output_type_id INTEGER REFERENCES contract_types(id),
    is_deprecated BOOLEAN DEFAULT FALSE,
    deprecation_reason TEXT,
    deprecation_sunset TEXT,
    source_file TEXT NOT NULL,
    source_line INTEGER NOT NULL
);

-- Types table (normalized, supports recursive types)
CREATE TABLE contract_types (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    contract_id TEXT NOT NULL REFERENCES contracts(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,              -- object, enum, union, array, map, scalar, reference
    parent_type_id INTEGER REFERENCES contract_types(id),
    source_file TEXT,
    source_line INTEGER
);

-- Fields table (normalized from JSON)
CREATE TABLE contract_fields (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type_id INTEGER NOT NULL REFERENCES contract_types(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    field_type TEXT NOT NULL,        -- Scalar type or reference to contract_types.id
    required BOOLEAN DEFAULT TRUE,
    nullable BOOLEAN DEFAULT FALSE,
    deprecated BOOLEAN DEFAULT FALSE,
    default_value TEXT,
    description TEXT,
    sort_order INTEGER DEFAULT 0
);

-- Mismatches table (normalized from JSON blob — addresses L21)
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
);

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
);

-- Contract consumers (replaces contract_frontends — paradigm-agnostic)
CREATE TABLE contract_consumers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    contract_id TEXT NOT NULL REFERENCES contracts(id) ON DELETE CASCADE,
    consumer_type TEXT NOT NULL,     -- frontend_call, grpc_client, event_subscriber, etc.
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    library TEXT,
    framework TEXT,
    expected_type_id INTEGER REFERENCES contract_types(id)
);

-- Indexes for common queries
CREATE INDEX idx_contracts_paradigm ON contracts(paradigm);
CREATE INDEX idx_contracts_status ON contracts(status);
CREATE INDEX idx_contracts_service ON contracts(service);
CREATE INDEX idx_contracts_confidence ON contracts(confidence_score);
CREATE INDEX idx_contracts_source_file ON contracts(source_file);
CREATE INDEX idx_mismatches_contract ON contract_mismatches(contract_id);
CREATE INDEX idx_mismatches_type ON contract_mismatches(mismatch_type);
CREATE INDEX idx_mismatches_severity ON contract_mismatches(severity);
CREATE INDEX idx_operations_contract ON contract_operations(contract_id);
CREATE INDEX idx_consumers_contract ON contract_consumers(contract_id);
CREATE INDEX idx_consumers_file ON contract_consumers(file);
CREATE INDEX idx_breaking_contract ON contract_breaking_changes(contract_id);
CREATE INDEX idx_breaking_scan ON contract_breaking_changes(scan_id);
```

**Migration from v1**:
- Map v1 `contracts` → v2 `contracts` with `paradigm='rest'`
- Map v1 `contract_frontends` → v2 `contract_consumers` with `consumer_type='frontend_call'`
- Normalize v1 `mismatches` JSON → v2 `contract_mismatches` rows
- Drop JSON file storage entirely

**Rationale**: V1's schema is REST-specific and stores mismatches as JSON blobs. V2 needs paradigm-aware tables with normalized mismatches for efficient querying.

**Dependencies**: R1 (Unified Contract Model)

---

## R10: Enhanced MCP Tools

**Sources**: Research R12 (API governance), RECAP (v1 MCP gaps)
**Priority**: P1 (Developer experience)
**Effort**: Medium
**Impact**: Addresses L24, L25, L26, L27

**Design**:

Expand from 1 MCP tool to 8 tools covering the full contract interaction surface:

**1. drift_contracts_list (Enhanced)**:
```typescript
// Arguments (enhanced from v1)
{
  paradigm?: string;      // 'rest' | 'graphql' | 'grpc' | 'event' | 'websocket' | 'trpc' | 'all'
  status?: string;        // 'all' | 'verified' | 'mismatch' | 'discovered' | 'deprecated'
  service?: string;       // Filter by service name
  minConfidence?: number; // Minimum confidence score
  hasMismatches?: boolean;
  hasBreakingChanges?: boolean;
  limit?: number;
  cursor?: string;
}
```

**2. drift_contract_detail (New)**:
```typescript
// Deep-dive into a specific contract
{
  contractId: string;
  includeHistory?: boolean;    // Include change history
  includeConsumers?: boolean;  // Include all consumers
  includeMismatches?: boolean; // Include detailed mismatches
}
// Returns: Full contract with all operations, types, fields, mismatches, consumers, history
```

**3. drift_contract_diff (New)**:
```typescript
// Compare contracts between scans
{
  fromScan?: string;    // Scan ID or 'previous'
  toScan?: string;      // Scan ID or 'current'
  paradigm?: string;
  onlyBreaking?: boolean;
}
// Returns: Added, removed, modified contracts with breaking change classification
```

**4. drift_contract_verify (New)**:
```typescript
// Mark contracts as verified
{
  contractIds: string[];
  verifiedBy?: string;
}
// Returns: Updated contracts with verification status
```

**5. drift_contract_coverage (New)**:
```typescript
// Contract coverage report
{
  service?: string;
  paradigm?: string;
}
// Returns: Coverage stats — contracts with/without tests, spec coverage, consumer coverage
```

**6. drift_contract_breaking (New)**:
```typescript
// List breaking changes
{
  sinceDate?: string;
  sinceScan?: string;
  severity?: string;    // 'breaking' | 'conditional' | 'all'
  paradigm?: string;
}
// Returns: Breaking changes with affected consumers and migration hints
```

**7. drift_contract_governance (New)**:
```typescript
// API governance compliance report
{
  service?: string;
  rules?: string[];     // Specific governance rules to check
}
// Returns: Governance violations (naming, versioning, pagination, error format, auth)
```

**8. drift_contract_graph (New)**:
```typescript
// Service dependency graph from contracts
{
  service?: string;     // Focus on specific service
  depth?: number;       // Traversal depth (default: 2)
  paradigm?: string;
}
// Returns: Service nodes, edges, contract connections, blast radius
```

**Rationale**: V1 has only 1 MCP tool for contracts. AI agents need rich contract interaction capabilities — detail views, diff analysis, verification, coverage reporting, and governance checking.

**Dependencies**: R1 (Unified Contract Model), R4 (Breaking Changes), R5 (Confidence), R8 (Service Graph)

---

## R11: API Governance Rules Engine

**Sources**: Research R12 (API governance)
**Priority**: P2 (Enterprise feature)
**Effort**: Medium
**Impact**: Positions Drift as API governance tool

**Design**:

Implement configurable API governance rules that detect convention violations in contracts:

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
    // Naming
    EndpointNamingPattern { pattern: Regex },
    FieldNamingConvention { convention: NamingConvention }, // camelCase, snake_case, kebab-case
    // Versioning
    RequireVersionInPath,
    RequireVersionHeader,
    // Pagination
    RequirePaginationForLists,
    PaginationStyle { style: PaginationStyle }, // cursor, offset, keyset
    // Error format
    RequireErrorSchema { schema: String },      // RFC 7807, custom
    // Auth
    RequireAuthForMutations,
    RequireAuthExceptPublic { public_paths: Vec<String> },
    // Documentation
    RequireOperationDescription,
    RequireFieldDescription,
    // Deprecation
    RequireSunsetHeader,
    MaxDeprecationAge { days: u32 },
}
```

**Built-in Rule Sets**:
- `default`: Basic naming + versioning + error format
- `strict`: All rules enabled with tight thresholds
- `rest-best-practices`: REST-specific rules (from OpenAPI best practices)
- `graphql-best-practices`: GraphQL-specific rules (from GraphQL spec recommendations)

**Rationale**: Enterprise API teams need governance enforcement. Drift's convention-discovery model naturally extends to API governance — discover what conventions exist, then enforce them.

**Dependencies**: R1 (Unified Contract Model), R2 (Spec parsing for governance rule extraction)

---

## R12: Rust-Native Contract Engine

**Sources**: Research R10 (Rust-native engine), RECAP (v2 migration considerations)
**Priority**: P0 (Architecture — aligns with v2 Rust-first vision)
**Effort**: High
**Impact**: Performance improvement for large codebases

**Design**:

Implement the core contract engine in Rust, exposed via NAPI:

**Rust Core** (crates/drift-core/src/contracts/):
```
contracts/
├── mod.rs                  // Module root
├── model.rs                // Unified contract model (R1)
├── parsers/
│   ├── mod.rs
│   ├── openapi.rs          // OpenAPI 3.0/3.1 parser
│   ├── graphql.rs          // GraphQL SDL parser (tree-sitter-graphql)
│   ├── protobuf.rs         // Protobuf parser (protox-parse)
│   ├── asyncapi.rs         // AsyncAPI parser
│   └── spec_discovery.rs   // Spec file discovery
├── extractors/
│   ├── mod.rs
│   ├── rest.rs             // REST endpoint extraction (all frameworks)
│   ├── graphql.rs          // GraphQL code-first extraction
│   ├── grpc.rs             // gRPC server/client extraction
│   └── events.rs           // Event-driven extraction
├── matching/
│   ├── mod.rs
│   ├── path_matcher.rs     // Path normalization + similarity
│   ├── field_comparator.rs // Recursive field comparison
│   ├── type_normalizer.rs  // Cross-language type normalization
│   └── confidence.rs       // Multi-signal confidence scoring
├── analysis/
│   ├── mod.rs
│   ├── breaking_changes.rs // Breaking change classifier
│   ├── drift_detector.rs   // Temporal drift detection
│   ├── service_graph.rs    // Cross-service tracing
│   └── governance.rs       // API governance rules
└── storage/
    ├── mod.rs
    └── repository.rs       // SQLite repository (rusqlite)
```

**NAPI Exports**:
```rust
#[napi]
pub fn detect_contracts(files: Vec<JsFileInfo>) -> JsContractResult { }

#[napi]
pub fn parse_spec_file(path: String, content: String) -> JsContractResult { }

#[napi]
pub fn compare_contracts(before: JsContracts, after: JsContracts) -> JsContractDiff { }

#[napi]
pub fn calculate_blast_radius(contract_id: String) -> JsBlastRadius { }

#[napi]
pub fn check_governance(contracts: JsContracts, rules: JsRules) -> JsGovernanceResult { }
```

**TypeScript Orchestration** (stays in TS):
- MCP tool handlers
- CLI command handlers
- tRPC extraction (requires TS compiler API)
- Frontend type resolution (requires TS compiler API)

**Rationale**: Aligns with v2's Rust-first architecture. Contract matching is CPU-intensive for large codebases (thousands of endpoints × thousands of frontend calls). Rust provides 10-100x performance improvement over TypeScript for this workload.

**Dependencies**: R1 (Unified Contract Model), all other recommendations (this is the implementation vehicle)

---

## Implementation Phases

### Phase 1: Foundation (Weeks 1-4)
- R1: Unified Contract Model (Rust types)
- R9: Enhanced Storage Schema (SQLite migration)
- R12: Rust module structure + NAPI scaffolding
- Migrate v1 REST contract detection to new model

### Phase 2: Schema-First (Weeks 5-8)
- R2: OpenAPI parser (Rust)
- R2: GraphQL SDL parser (Rust, tree-sitter-graphql)
- R2: Protobuf parser (Rust, protox-parse)
- R2: AsyncAPI parser (Rust)
- R2: Spec file discovery

### Phase 3: Code-First Enhancement (Weeks 9-12)
- R3: Enhanced REST extraction (Go, Rust, Ruby, Kotlin frameworks)
- R3: GraphQL code-first extraction
- R3: gRPC server/client extraction
- R3: Event-driven extraction
- R3: tRPC extraction (TypeScript)
- R3: Enhanced frontend library support

### Phase 4: Analysis (Weeks 13-16)
- R4: Breaking Change Classifier
- R5: Enhanced Confidence Model
- R7: Contract Drift Detection
- R6: Contract Testing Integration

### Phase 5: Enterprise (Weeks 17-20)
- R8: Cross-Service Contract Tracing
- R11: API Governance Rules Engine
- R10: Enhanced MCP Tools (all 8 tools)

---

## Dependency Graph

```
R1 (Unified Model) ──→ ALL other recommendations
  │
  ├──→ R9 (Storage) ──→ R7 (Drift Detection)
  │                  ──→ R10 (MCP Tools)
  │
  ├──→ R2 (Schema-First) ──→ R4 (Breaking Changes)
  │                       ──→ R11 (Governance)
  │
  ├──→ R3 (Code-First) ──→ R4 (Breaking Changes)
  │                     ──→ R6 (Contract Testing)
  │
  ├──→ R5 (Confidence) ──→ R6 (Contract Testing, test coverage signal)
  │
  ├──→ R4 (Breaking Changes) ──→ R7 (Drift Detection)
  │                           ──→ R8 (Service Graph, blast radius)
  │                           ──→ R10 (MCP: drift_contract_breaking)
  │
  ├──→ R8 (Service Graph) ──→ R10 (MCP: drift_contract_graph)
  │
  └──→ R12 (Rust Engine) ──→ Implementation vehicle for R1-R11
```

---

## Cross-Category Impact

| Category | Impact from Contracts R1-R12 | Action Required |
|----------|------------------------------|-----------------|
| 02-parsers | New tree-sitter grammars (GraphQL, Protobuf) | Add tree-sitter-graphql, protox-parse to Rust dependencies |
| 03-detectors | Contract detectors expanded to all paradigms | New detector files for GraphQL, gRPC, event-driven, tRPC |
| 04-call-graph | Service-level tracing extends function-level graph | Add service boundary detection to call graph builder |
| 07-mcp | 8 new/enhanced MCP tools | New tool handlers in MCP server |
| 08-storage | New SQLite schema, drop JSON storage | Schema migration, drop contract-store.ts |
| 09-quality-gates | New contract gates (breaking changes, governance, coverage) | New gate implementations |
| 10-cli | New `drift contracts` subcommands | New CLI commands |
| 17-test-topology | Contract test detection (Pact, Spring Cloud Contract) | New test framework detectors |

---

## Risk Assessment

| Risk | Probability | Impact | Mitigation |
|------|------------|--------|-----------|
| GraphQL code-first extraction complexity | High | Medium | Start with schema files, add code-first incrementally |
| Protobuf import resolution across files | Medium | Medium | Use protox-parse's built-in import resolution |
| tRPC extraction requires TS compiler API | High | Low | Keep in TypeScript layer, don't port to Rust |
| Cross-service tracing in multi-repo | High | High | Start with monorepo support, add multi-repo via contract registries |
| AsyncAPI adoption still growing | Medium | Low | Implement as optional, focus on Kafka/RabbitMQ code patterns |
| Breaking change false positives | Medium | Medium | Conservative classification + user feedback loop |
| Storage migration from v1 | Low | Medium | Automated migration script with rollback |

---

## Success Metrics

| Metric | V1 Baseline | V2 Target |
|--------|------------|-----------|
| API paradigms supported | 1 (REST) | 6 (REST, GraphQL, gRPC, WebSocket, Event-Driven, tRPC) |
| Backend frameworks | 8 | 20+ |
| Frontend libraries | 3 | 15+ |
| Mismatch types | 5 | 7+ (add enum_mismatch, constraint_mismatch) |
| Confidence signals | 2 | 7 |
| MCP tools | 1 | 8 |
| SQLite tables | 2 | 7 |
| Contract test frameworks detected | 0 | 6 |
| Breaking change categories | 0 | 15+ |
| Governance rules | 0 | 20+ |
| Spec file formats parsed | 0 | 4 (OpenAPI, GraphQL SDL, Protobuf, AsyncAPI) |
| Cross-service tracing | No | Yes (monorepo) |
