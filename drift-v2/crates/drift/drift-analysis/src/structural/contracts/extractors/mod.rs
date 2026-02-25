//! Backend and frontend endpoint extractors.

pub mod express;
pub mod fastify;
pub mod nestjs;
pub mod django;
pub mod flask;
pub mod spring;
pub mod aspnet;
pub mod rails;
pub mod laravel;
pub mod gin;
pub mod actix;
pub mod nextjs;
pub mod trpc;
pub mod frontend;

use super::types::{Endpoint, FieldSpec};
use crate::parsers::types::{ParseResult, FunctionInfo, ParameterInfo, DecoratorInfo};

/// Trait for extracting API endpoints from source code.
pub trait EndpointExtractor: Send + Sync {
    /// Extract endpoints from source code content.
    fn extract(&self, content: &str, file_path: &str) -> Vec<Endpoint>;
    /// Extract endpoints with ParseResult context for field extraction.
    /// Default implementation falls back to extract() with no fields.
    fn extract_with_context(&self, content: &str, file_path: &str, parse_result: Option<&ParseResult>) -> Vec<Endpoint> {
        let _ = parse_result;
        self.extract(content, file_path)
    }
    /// Framework name.
    fn framework(&self) -> &str;
    /// Check if this extractor applies to the given file content.
    fn matches(&self, content: &str) -> bool;
}

/// Registry of all endpoint extractors.
pub struct ExtractorRegistry {
    extractors: Vec<Box<dyn EndpointExtractor>>,
}

impl ExtractorRegistry {
    /// Create a registry with all built-in extractors.
    pub fn new() -> Self {
        Self {
            extractors: vec![
                Box::new(express::ExpressExtractor),
                Box::new(fastify::FastifyExtractor),
                Box::new(nestjs::NestJsExtractor),
                Box::new(django::DjangoExtractor),
                Box::new(flask::FlaskExtractor),
                Box::new(spring::SpringExtractor),
                Box::new(aspnet::AspNetExtractor),
                Box::new(rails::RailsExtractor),
                Box::new(laravel::LaravelExtractor),
                Box::new(gin::GinExtractor),
                Box::new(actix::ActixExtractor),
                Box::new(nextjs::NextJsExtractor),
                Box::new(trpc::TrpcExtractor),
                Box::new(frontend::FrontendExtractor),
            ],
        }
    }

    /// Extract endpoints from a file using all matching extractors.
    pub fn extract_all(&self, content: &str, file_path: &str) -> Vec<(String, Vec<Endpoint>)> {
        self.extractors
            .iter()
            .filter(|e| e.matches(content))
            .map(|e| (e.framework().to_string(), e.extract(content, file_path)))
            .filter(|(_, eps)| !eps.is_empty())
            .collect()
    }

    /// Extract endpoints with ParseResult context for field extraction.
    pub fn extract_all_with_context(
        &self,
        content: &str,
        file_path: &str,
        parse_result: Option<&ParseResult>,
    ) -> Vec<(String, Vec<Endpoint>)> {
        self.extractors
            .iter()
            .filter(|e| e.matches(content))
            .map(|e| (
                e.framework().to_string(),
                e.extract_with_context(content, file_path, parse_result),
            ))
            .filter(|(_, eps)| !eps.is_empty())
            .collect()
    }
}

impl Default for ExtractorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ─── CE-TRAIT-02: Shared field extraction helpers ───────────────────────────

/// Convert function parameters to request FieldSpecs.
pub fn params_to_fields(params: &[ParameterInfo]) -> Vec<FieldSpec> {
    params
        .iter()
        .filter(|p| !is_framework_param(&p.name))
        .map(|p| FieldSpec {
            name: p.name.clone(),
            field_type: p.type_annotation.clone().unwrap_or_else(|| "any".to_string()),
            required: p.default_value.is_none() && !p.is_rest,
            nullable: p.type_annotation.as_deref().is_some_and(|t| {
                t.contains("null") || t.contains("undefined") || t.contains('?')
            }),
        })
        .collect()
}

/// Convert a return type string to response FieldSpecs.
/// For simple types, returns a single field named "value".
/// For object-like types, attempts to extract field names.
pub fn return_type_to_fields(return_type: &str) -> Vec<FieldSpec> {
    let cleaned = return_type
        .trim()
        .trim_start_matches("Promise<")
        .trim_end_matches('>')
        .trim_start_matches("ResponseEntity<")
        .trim_start_matches("ActionResult<")
        .trim_start_matches("IActionResult")
        .trim_start_matches("Response")
        .trim();

    if cleaned.is_empty() || cleaned == "void" || cleaned == "None" || cleaned == "()" {
        return vec![];
    }

    // If it looks like an object type with fields: { name: string, age: number }
    if cleaned.starts_with('{') && cleaned.ends_with('}') {
        return parse_object_fields(&cleaned[1..cleaned.len() - 1]);
    }

    // Single type → one field named "value"
    vec![FieldSpec {
        name: "value".to_string(),
        field_type: cleaned.to_string(),
        required: true,
        nullable: cleaned.contains("null") || cleaned.contains('?'),
    }]
}

/// Parse object-like field definitions: "name: string, age: number"
fn parse_object_fields(fields_str: &str) -> Vec<FieldSpec> {
    fields_str
        .split(',')
        .filter_map(|field| {
            let parts: Vec<&str> = field.splitn(2, ':').collect();
            if parts.len() == 2 {
                let name = parts[0].trim().trim_start_matches('?');
                let field_type = parts[1].trim();
                let optional = parts[0].trim().ends_with('?');
                if !name.is_empty() {
                    return Some(FieldSpec {
                        name: name.to_string(),
                        field_type: field_type.to_string(),
                        required: !optional,
                        nullable: field_type.contains("null") || optional,
                    });
                }
            }
            None
        })
        .collect()
}

/// Check if a parameter name is a framework-injected parameter (not a user field).
fn is_framework_param(name: &str) -> bool {
    matches!(
        name,
        "req" | "res" | "next" | "request" | "response" | "ctx" | "context"
            | "self" | "cls" | "this" | "c" | "w" | "r" | "db" | "conn"
            | "session" | "HttpRequest" | "HttpResponse"
    )
}

/// Find the function at a given line in a ParseResult.
pub fn find_function_at_line(parse_result: &ParseResult, line: u32) -> Option<&FunctionInfo> {
    // Check top-level functions
    if let Some(f) = parse_result.functions.iter().find(|f| f.line <= line && f.end_line >= line) {
        return Some(f);
    }
    // Check class methods
    for class in &parse_result.classes {
        if let Some(m) = class.methods.iter().find(|m| m.line <= line && m.end_line >= line) {
            return Some(m);
        }
    }
    None
}

/// Extract fields from decorator arguments (e.g., @Body(), @Param(), @Query()).
pub fn extract_decorator_fields(decorators: &[DecoratorInfo], decorator_names: &[&str]) -> Vec<FieldSpec> {
    let mut fields = Vec::new();
    for dec in decorators {
        if decorator_names.iter().any(|n| dec.name.contains(n)) {
            for arg in &dec.arguments {
                if let Some(ref key) = arg.key {
                    fields.push(FieldSpec {
                        name: key.clone(),
                        field_type: "any".to_string(),
                        required: true,
                        nullable: false,
                    });
                } else if !arg.value.is_empty() && arg.value != "()" {
                    let name = arg.value.trim_matches('"').trim_matches('\'').to_string();
                    if !name.is_empty() {
                        fields.push(FieldSpec {
                            name,
                            field_type: "any".to_string(),
                            required: true,
                            nullable: false,
                        });
                    }
                }
            }
        }
    }
    fields
}
