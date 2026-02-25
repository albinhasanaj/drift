//! Protobuf schema parser (gRPC).

use super::SchemaParser;
use crate::structural::contracts::types::*;

/// Parses Protocol Buffer definitions for gRPC services.
pub struct ProtobufParser;

impl SchemaParser for ProtobufParser {
    fn parse(&self, content: &str, file_path: &str) -> Vec<Contract> {
        let mut endpoints = Vec::new();

        // CE-PB-01: Pre-parse message definitions for field resolution.
        let messages = parse_message_definitions(content);

        // Find service definitions: service ServiceName { rpc Method(Request) returns (Response); }
        let mut pos = 0;
        while let Some(svc_start) = content[pos..].find("service ") {
            let abs_start = pos + svc_start;
            let rest = &content[abs_start + 8..];

            if let Some(brace) = rest.find('{') {
                let block_start = abs_start + 8 + brace + 1;
                if let Some(block_end) = find_matching_brace(content, block_start) {
                    let block = &content[block_start..block_end];

                    for line in block.lines() {
                        let trimmed = line.trim();
                        if trimmed.starts_with("rpc ") {
                            if let Some(ep) = parse_rpc_line(trimmed, file_path, &messages) {
                                endpoints.push(ep);
                            }
                        }
                    }

                    pos = block_end;
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        if endpoints.is_empty() {
            return vec![];
        }

        vec![Contract {
            id: format!("grpc:{}", file_path),
            paradigm: Paradigm::Grpc,
            endpoints,
            source_file: file_path.to_string(),
            framework: "grpc".to_string(),
            confidence: 0.90,
        }]
    }

    fn extensions(&self) -> &[&str] {
        &["proto"]
    }

    fn schema_type(&self) -> &str {
        "protobuf"
    }
}

fn find_matching_brace(content: &str, start: usize) -> Option<usize> {
    let mut depth = 1;
    for (i, ch) in content[start..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(start + i);
                }
            }
            _ => {}
        }
    }
    None
}

fn parse_rpc_line(line: &str, file_path: &str, messages: &[(String, Vec<FieldSpec>)]) -> Option<Endpoint> {
    // rpc MethodName(RequestType) returns (ResponseType);
    // rpc MethodName(stream RequestType) returns (stream ResponseType);
    let rest = line.strip_prefix("rpc ")?.trim();
    let paren_start = rest.find('(')?;
    let method_name = rest[..paren_start].trim();
    let after_name = &rest[paren_start + 1..];
    let paren_end = after_name.find(')')?;
    let request_type_raw = after_name[..paren_end].trim();
    // CE-PB-01: Handle `stream` keyword.
    let request_type = request_type_raw.strip_prefix("stream ").unwrap_or(request_type_raw).trim();

    let returns_start = after_name.find("returns")? + 7;
    let resp_paren_start = after_name[returns_start..].find('(')? + returns_start + 1;
    let resp_paren_end = after_name[resp_paren_start..].find(')')? + resp_paren_start;
    let response_type_raw = after_name[resp_paren_start..resp_paren_end].trim();
    let response_type = response_type_raw.strip_prefix("stream ").unwrap_or(response_type_raw).trim();

    // CE-PB-01: Resolve message fields if the message is defined in this file.
    let request_fields = resolve_message_fields(request_type, messages);
    let response_fields = resolve_message_fields(response_type, messages);

    Some(Endpoint {
        method: "RPC".to_string(),
        path: method_name.to_string(),
        request_fields,
        response_fields,
        file: file_path.to_string(),
        line: 0,
    })
}

/// CE-PB-01: Parse all `message TypeName { ... }` definitions in the file.
fn parse_message_definitions(content: &str) -> Vec<(String, Vec<FieldSpec>)> {
    let mut messages = Vec::new();
    let mut pos = 0;
    let pattern = "message ";

    while let Some(msg_start) = content[pos..].find(pattern) {
        let abs_start = pos + msg_start;
        let rest = &content[abs_start + pattern.len()..];

        if let Some(brace_pos) = rest.find('{') {
            let type_name = rest[..brace_pos].trim().to_string();
            if !type_name.is_empty() && !type_name.contains(' ') {
                let block_start = abs_start + pattern.len() + brace_pos + 1;
                if let Some(block_end) = find_matching_brace(content, block_start) {
                    let block = &content[block_start..block_end];
                    let fields = parse_proto_message_fields(block);
                    messages.push((type_name, fields));
                    pos = block_end;
                } else {
                    break;
                }
            } else {
                pos = abs_start + pattern.len();
            }
        } else {
            break;
        }
    }
    messages
}

/// Parse fields from a protobuf message block.
/// Format: `type name = number;` e.g., `string username = 1;`
fn parse_proto_message_fields(block: &str) -> Vec<FieldSpec> {
    let mut fields = Vec::new();
    for line in block.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with("reserved")
            || trimmed.starts_with("option") || trimmed.starts_with("oneof")
            || trimmed.starts_with("message") || trimmed.starts_with("enum")
        {
            continue;
        }
        // Parse: [repeated] type name = number;
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() >= 3 {
            let (field_type, field_name) = if parts[0] == "repeated" || parts[0] == "optional" {
                if parts.len() >= 4 {
                    (format!("{}:{}", parts[0], parts[1]), parts[2].to_string())
                } else {
                    continue;
                }
            } else {
                (parts[0].to_string(), parts[1].to_string())
            };
            // field_name might have '=' after it
            let field_name = field_name.trim_end_matches('=').to_string();
            if !field_name.is_empty() && field_name != "=" {
                let required = !field_type.starts_with("optional");
                fields.push(FieldSpec {
                    name: field_name,
                    field_type,
                    required,
                    nullable: false,
                });
            }
        }
    }
    fields
}

/// CE-PB-01: Resolve a message type name to its fields.
/// Falls back to a single field with the type name if the message isn't found.
fn resolve_message_fields(type_name: &str, messages: &[(String, Vec<FieldSpec>)]) -> Vec<FieldSpec> {
    for (name, fields) in messages {
        if name == type_name {
            return fields.clone();
        }
    }
    // Fallback: return the type name as a single field.
    vec![FieldSpec {
        name: "request".to_string(),
        field_type: type_name.to_string(),
        required: true,
        nullable: false,
    }]
}
