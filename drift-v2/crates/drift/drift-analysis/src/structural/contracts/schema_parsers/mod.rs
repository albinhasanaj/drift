//! Schema parsers for API contract definitions.

pub mod openapi;
pub mod graphql;
pub mod protobuf;
pub mod asyncapi;

use super::types::Contract;

/// Trait for schema parsers.
pub trait SchemaParser: Send + Sync {
    /// Parse a schema file and extract contracts.
    fn parse(&self, content: &str, file_path: &str) -> Vec<Contract>;
    /// File extensions this parser handles.
    fn extensions(&self) -> &[&str];
    /// Schema type name.
    fn schema_type(&self) -> &str;
}
