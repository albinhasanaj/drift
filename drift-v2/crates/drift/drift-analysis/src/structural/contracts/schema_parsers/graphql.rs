//! GraphQL SDL schema parser.

use super::SchemaParser;
use crate::structural::contracts::types::*;

/// Parses GraphQL Schema Definition Language (SDL).
pub struct GraphqlParser;

impl SchemaParser for GraphqlParser {
    fn parse(&self, content: &str, file_path: &str) -> Vec<Contract> {
        let mut endpoints = Vec::new();

        // CE-GQL-02: Pre-parse input types for field resolution.
        let _input_types = parse_input_types(content);

        // Parse type definitions for Query, Mutation, Subscription
        let operation_types = ["Query", "Mutation", "Subscription"];

        for op_type in &operation_types {
            // CE-GQL-01: Search for both `type X {` and `extend type X {`.
            let patterns = [
                format!("type {} {{", op_type),
                format!("extend type {} {{", op_type),
            ];

            for pattern in &patterns {
                let mut search_from = 0;
                while let Some(start) = content[search_from..].find(pattern.as_str()) {
                    let abs_start = search_from + start;
                    let block = extract_block(content, abs_start + pattern.len());
                    let fields = parse_graphql_fields(&block, file_path);
                    for field in fields {
                        endpoints.push(Endpoint {
                            method: op_type.to_string(),
                            path: field.0,
                            request_fields: field.1,
                            response_fields: field.2,
                            file: file_path.to_string(),
                            line: 0,
                        });
                    }
                    search_from = abs_start + pattern.len();
                }
            }
        }

        if endpoints.is_empty() {
            return vec![];
        }

        vec![Contract {
            id: format!("graphql:{}", file_path),
            paradigm: Paradigm::GraphQL,
            endpoints,
            source_file: file_path.to_string(),
            framework: "graphql".to_string(),
            confidence: 0.90,
        }]
    }

    fn extensions(&self) -> &[&str] {
        &["graphql", "gql"]
    }

    fn schema_type(&self) -> &str {
        "graphql"
    }
}

/// Extract a brace-delimited block.
fn extract_block(content: &str, start: usize) -> String {
    let bytes = content.as_bytes();
    let mut depth = 1;
    let mut end = start;

    for (i, &b) in bytes[start..].iter().enumerate() {
        match b {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    end = start + i;
                    break;
                }
            }
            _ => {}
        }
    }

    content[start..end].to_string()
}

/// Parse GraphQL field definitions into (name, args, return_fields).
fn parse_graphql_fields(
    block: &str,
    _file_path: &str,
) -> Vec<(String, Vec<FieldSpec>, Vec<FieldSpec>)> {
    let mut results = Vec::new();

    for line in block.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Parse: fieldName(arg1: Type!, arg2: Type): ReturnType
        if let Some(colon_pos) = trimmed.rfind(':') {
            let before_return = &trimmed[..colon_pos];
            let return_type = trimmed[colon_pos + 1..].trim().trim_end_matches('!');

            let (name, args) = if let Some(paren_start) = before_return.find('(') {
                let name = before_return[..paren_start].trim().to_string();
                let args_str = &before_return[paren_start + 1..];
                let args_str = args_str.trim_end_matches(')');
                let args = parse_graphql_args(args_str);
                (name, args)
            } else {
                (before_return.trim().to_string(), vec![])
            };

            if !name.is_empty() {
                let response_fields = vec![FieldSpec {
                    name: "result".to_string(),
                    field_type: return_type.trim_start_matches('[').trim_end_matches(']').to_string(),
                    required: trimmed.ends_with('!'),
                    nullable: !trimmed.ends_with('!'),
                }];

                results.push((name, args, response_fields));
            }
        }
    }

    results
}

fn parse_graphql_args(args_str: &str) -> Vec<FieldSpec> {
    args_str
        .split(',')
        .filter_map(|arg| {
            let parts: Vec<&str> = arg.split(':').collect();
            if parts.len() == 2 {
                let name = parts[0].trim().to_string();
                let type_str = parts[1].trim();
                let required = type_str.ends_with('!');
                let field_type = type_str.trim_end_matches('!').to_string();
                Some(FieldSpec {
                    name,
                    field_type,
                    required,
                    nullable: !required,
                })
            } else {
                None
            }
        })
        .collect()
}

/// CE-GQL-02: Parse `input TypeName { ... }` definitions.
/// Returns a map of input type name to their fields.
fn parse_input_types(content: &str) -> Vec<(String, Vec<FieldSpec>)> {
    let mut results = Vec::new();
    let mut search_from = 0;
    let pattern = "input ";

    while let Some(pos) = content[search_from..].find(pattern) {
        let abs_pos = search_from + pos;
        let rest = &content[abs_pos + pattern.len()..];

        // Extract type name
        if let Some(brace_pos) = rest.find('{') {
            let type_name = rest[..brace_pos].trim().to_string();
            if !type_name.is_empty() && !type_name.contains(' ') {
                let block = extract_block(content, abs_pos + pattern.len() + brace_pos + 1);
                let fields = parse_input_fields(&block);
                results.push((type_name, fields));
            }
            search_from = abs_pos + pattern.len() + brace_pos + 1;
        } else {
            break;
        }
    }
    results
}

/// Parse fields from an input type block.
fn parse_input_fields(block: &str) -> Vec<FieldSpec> {
    let mut fields = Vec::new();
    for line in block.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // Parse: fieldName: Type! or fieldName: Type
        if let Some(colon_pos) = trimmed.find(':') {
            let name = trimmed[..colon_pos].trim().to_string();
            let type_str = trimmed[colon_pos + 1..].trim();
            let required = type_str.ends_with('!');
            let field_type = type_str
                .trim_end_matches('!')
                .trim_start_matches('[')
                .trim_end_matches(']')
                .trim_end_matches('!')
                .to_string();
            if !name.is_empty() {
                fields.push(FieldSpec {
                    name,
                    field_type,
                    required,
                    nullable: !required,
                });
            }
        }
    }
    fields
}
