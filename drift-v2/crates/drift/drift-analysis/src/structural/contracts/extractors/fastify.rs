//! Fastify endpoint extractor.

use super::EndpointExtractor;
use super::express::extract_string_arg;
use crate::structural::contracts::types::*;

pub struct FastifyExtractor;

/// CE-FAST-01: Receivers to check — fastify plus common aliases.
const FASTIFY_RECEIVERS: &[&str] = &["fastify", "server", "app", "instance"];

impl EndpointExtractor for FastifyExtractor {
    fn extract(&self, content: &str, file_path: &str) -> Vec<Endpoint> {
        let mut endpoints = Vec::new();
        let methods = ["get", "post", "put", "delete", "patch", "head", "options"];

        for (line_num, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            for method in &methods {
                for receiver in FASTIFY_RECEIVERS {
                    let pattern = format!("{}.{}(", receiver, method);
                    if let Some(pos) = trimmed.find(pattern.as_str()) {
                        if let Some(path) = extract_string_arg(trimmed, pos + pattern.len()) {
                            endpoints.push(Endpoint {
                                method: method.to_uppercase(),
                                path,
                                request_fields: vec![],
                                response_fields: vec![],
                                file: file_path.to_string(),
                                line: (line_num + 1) as u32,
                            });
                        }
                    }
                }
            }
        }
        endpoints
    }

    fn framework(&self) -> &str { "fastify" }
    fn matches(&self, content: &str) -> bool {
        content.contains("fastify") || content.contains("@fastify")
    }
}
