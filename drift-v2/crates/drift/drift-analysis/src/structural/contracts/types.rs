//! Contract tracking types — contracts, endpoints, paradigms, mismatches.

use serde::{Deserialize, Serialize};

/// An API contract (backend endpoint or frontend consumer).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contract {
    /// Unique contract identifier.
    pub id: String,
    /// The API paradigm.
    pub paradigm: Paradigm,
    /// Endpoints defined in this contract.
    pub endpoints: Vec<Endpoint>,
    /// Source file where the contract was extracted.
    pub source_file: String,
    /// Framework used (e.g., "express", "django", "spring").
    pub framework: String,
    /// Confidence in the extraction accuracy.
    pub confidence: f64,
}

/// An API endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    /// HTTP method (GET, POST, etc.) or operation type.
    pub method: String,
    /// Path or operation name.
    pub path: String,
    /// Request parameters/fields.
    pub request_fields: Vec<FieldSpec>,
    /// Response fields.
    pub response_fields: Vec<FieldSpec>,
    /// Source file and line.
    pub file: String,
    pub line: u32,
}

/// A field specification in a request or response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldSpec {
    pub name: String,
    pub field_type: String,
    pub required: bool,
    pub nullable: bool,
}

/// API paradigm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Paradigm {
    Rest,
    GraphQL,
    Grpc,
    AsyncApi,
    Trpc,
    WebSocket,
    EventDriven,
}

impl Paradigm {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Rest => "rest",
            Self::GraphQL => "graphql",
            Self::Grpc => "grpc",
            Self::AsyncApi => "asyncapi",
            Self::Trpc => "trpc",
            Self::WebSocket => "websocket",
            Self::EventDriven => "event_driven",
        }
    }

    pub fn all() -> &'static [Paradigm] {
        &[
            Self::Rest, Self::GraphQL, Self::Grpc, Self::AsyncApi,
            Self::Trpc, Self::WebSocket, Self::EventDriven,
        ]
    }
}

impl std::fmt::Display for Paradigm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Mismatch between backend and frontend contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractMismatch {
    pub backend_endpoint: String,
    pub frontend_call: String,
    pub mismatch_type: MismatchType,
    pub severity: MismatchSeverity,
    pub message: String,
}

/// Types of contract mismatches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MismatchType {
    FieldMissing,
    TypeMismatch,
    RequiredOptional,
    EnumValue,
    NestedShape,
    ArrayScalar,
    Nullable,
}

impl MismatchType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::FieldMissing => "field_missing",
            Self::TypeMismatch => "type_mismatch",
            Self::RequiredOptional => "required_optional",
            Self::EnumValue => "enum_value",
            Self::NestedShape => "nested_shape",
            Self::ArrayScalar => "array_scalar",
            Self::Nullable => "nullable",
        }
    }
}

/// Mismatch severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MismatchSeverity {
    Critical,
    High,
    Medium,
    Low,
}

/// A breaking change in an API contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakingChange {
    pub change_type: BreakingChangeType,
    pub endpoint: String,
    pub field: Option<String>,
    pub severity: MismatchSeverity,
    pub message: String,
}

/// Types of breaking changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BreakingChangeType {
    EndpointRemoved,
    FieldRemoved,
    TypeChanged,
    RequiredAdded,
    OptionalToRequired,
    EnumValueRemoved,
    PathChanged,
    MethodChanged,
    ResponseShapeChanged,
    AuthRequirementAdded,
    RateLimitAdded,
    DeprecationRemoved,
    VersionRemoved,
    SchemaIncompatible,
    FieldRenamed,
    NullabilityChanged,
    ArrayToScalar,
    ScalarToArray,
    DefaultRemoved,
    ValidationAdded,
}

impl BreakingChangeType {
    pub fn is_breaking(&self) -> bool {
        !matches!(
            self,
            Self::RateLimitAdded | Self::DeprecationRemoved
        )
    }
}

/// A matched pair of backend endpoint and frontend consumer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractMatch {
    pub backend: Endpoint,
    pub frontend: Endpoint,
    pub confidence: f64,
    pub mismatches: Vec<ContractMismatch>,
}
