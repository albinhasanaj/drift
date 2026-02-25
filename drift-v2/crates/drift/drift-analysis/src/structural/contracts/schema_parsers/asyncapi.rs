//! AsyncAPI 2.x/3.0 schema parser.

use super::SchemaParser;
use crate::structural::contracts::types::*;

/// Parses AsyncAPI specifications (JSON/YAML).
pub struct AsyncApiParser;

impl SchemaParser for AsyncApiParser {
    fn parse(&self, content: &str, file_path: &str) -> Vec<Contract> {
        let value: Option<serde_json::Value> = serde_json::from_str(content)
            .ok()
            .or_else(|| serde_yaml::from_str(content).ok());

        let value = match value {
            Some(v) => v,
            None => return vec![],
        };

        let mut endpoints = Vec::new();

        // Detect version for parsing strategy.
        let version = value.get("asyncapi")
            .and_then(|v| v.as_str())
            .unwrap_or("2.0.0");
        let is_v3 = version.starts_with("3.");

        if is_v3 {
            // CE-AA-01: AsyncAPI 3.0 uses `operations` key.
            if let Some(operations) = value.get("operations").and_then(|o| o.as_object()) {
                for (op_name, operation) in operations {
                    let action = operation.get("action")
                        .and_then(|a| a.as_str())
                        .unwrap_or("send");
                    let channel_ref = operation.get("channel")
                        .and_then(|c| c.get("$ref"))
                        .and_then(|r| r.as_str())
                        .unwrap_or(op_name);
                    // Extract channel name from $ref like "#/channels/userSignedUp"
                    let channel_name = channel_ref.rsplit('/').next().unwrap_or(channel_ref);

                    let fields = extract_operation_fields_v3(operation, &value);
                    endpoints.push(Endpoint {
                        method: action.to_uppercase(),
                        path: channel_name.to_string(),
                        request_fields: fields,
                        response_fields: vec![],
                        file: file_path.to_string(),
                        line: 0,
                    });
                }
            }
        } else {
            // AsyncAPI 2.x uses "channels" with publish/subscribe.
            if let Some(channels) = value.get("channels").and_then(|c| c.as_object()) {
                for (channel_name, channel) in channels {
                    for op_type in &["publish", "subscribe"] {
                        if let Some(operation) = channel.get(*op_type) {
                            let fields = extract_message_fields(operation);
                            endpoints.push(Endpoint {
                                method: op_type.to_uppercase(),
                                path: channel_name.clone(),
                                request_fields: fields,
                                response_fields: vec![],
                                file: file_path.to_string(),
                                line: 0,
                            });
                        }
                    }
                }
            }
        }

        if endpoints.is_empty() {
            return vec![];
        }

        vec![Contract {
            id: format!("asyncapi:{}", file_path),
            paradigm: Paradigm::AsyncApi,
            endpoints,
            source_file: file_path.to_string(),
            framework: "asyncapi".to_string(),
            confidence: 0.85,
        }]
    }

    fn extensions(&self) -> &[&str] {
        &["yaml", "yml", "json"]
    }

    fn schema_type(&self) -> &str {
        "asyncapi"
    }
}

fn extract_message_fields(operation: &serde_json::Value) -> Vec<FieldSpec> {
    let mut fields = Vec::new();

    if let Some(message) = operation.get("message") {
        if let Some(payload) = message.get("payload") {
            // CE-AA-02: Parse required array from payload schema.
            let required_set: Vec<String> = payload
                .get("required")
                .and_then(|r| r.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default();

            if let Some(properties) = payload.get("properties").and_then(|p| p.as_object()) {
                for (name, prop) in properties {
                    let field_type = prop
                        .get("type")
                        .and_then(|t| t.as_str())
                        .unwrap_or("string")
                        .to_string();
                    fields.push(FieldSpec {
                        name: name.clone(),
                        field_type,
                        required: required_set.contains(name),
                        nullable: false,
                    });
                }
            }
        }
    }

    fields
}

/// CE-AA-01: Extract fields from AsyncAPI 3.0 operations.
fn extract_operation_fields_v3(operation: &serde_json::Value, root: &serde_json::Value) -> Vec<FieldSpec> {
    let mut fields = Vec::new();

    // In AsyncAPI 3.0, messages are referenced via `messages` array.
    if let Some(messages) = operation.get("messages").and_then(|m| m.as_array()) {
        for msg_ref in messages {
            // Resolve $ref if present.
            let resolved = if let Some(ref_str) = msg_ref.get("$ref").and_then(|r| r.as_str()) {
                if let Some(pointer) = ref_str.strip_prefix('#') {
                    root.pointer(pointer)
                } else {
                    None
                }
            } else {
                Some(msg_ref)
            };

            if let Some(message) = resolved {
                if let Some(payload) = message.get("payload") {
                    let required_set: Vec<String> = payload
                        .get("required")
                        .and_then(|r| r.as_array())
                        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                        .unwrap_or_default();

                    if let Some(properties) = payload.get("properties").and_then(|p| p.as_object()) {
                        for (name, prop) in properties {
                            let field_type = prop
                                .get("type")
                                .and_then(|t| t.as_str())
                                .unwrap_or("string")
                                .to_string();
                            fields.push(FieldSpec {
                                name: name.clone(),
                                field_type,
                                required: required_set.contains(name),
                                nullable: false,
                            });
                        }
                    }
                }
            }
        }
    }

    fields
}
