//! tRPC router extractor.

use super::EndpointExtractor;
use crate::structural::contracts::types::*;

pub struct TrpcExtractor;

impl EndpointExtractor for TrpcExtractor {
    fn extract(&self, content: &str, file_path: &str) -> Vec<Endpoint> {
        let mut endpoints = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            let trimmed = line.trim();

            // --- tRPC v9 style: .query('procedureName', ...) ---
            for (method_str, method) in &[(".query(", "QUERY"), (".mutation(", "MUTATION"), (".subscription(", "SUBSCRIPTION")] {
                if let Some(pos) = trimmed.find(method_str) {
                    if let Some(name) = super::express::extract_string_arg(trimmed, pos + method_str.len()) {
                        endpoints.push(Endpoint {
                            method: method.to_string(),
                            path: name,
                            request_fields: vec![],
                            response_fields: vec![],
                            file: file_path.to_string(),
                            line: (line_num + 1) as u32,
                        });
                    }
                }
            }

            // --- CE-TRPC-01: tRPC v10/v11 builder pattern ---
            // Pattern: `procedureName: publicProcedure.query(...)` or
            //          `procedureName: publicProcedure.input(...).query(...)`
            // The procedure name is the object key before the colon.
            if let Some(name) = extract_v10_procedure(trimmed) {
                let method = if trimmed.contains(".query(") {
                    "QUERY"
                } else if trimmed.contains(".mutation(") {
                    "MUTATION"
                } else if trimmed.contains(".subscription(") {
                    "SUBSCRIPTION"
                } else {
                    continue;
                };
                // Avoid double-counting if v9 style already captured a string name.
                let already_found = endpoints.iter().any(|ep| ep.line == (line_num + 1) as u32);
                if !already_found {
                    endpoints.push(Endpoint {
                        method: method.to_string(),
                        path: name,
                        request_fields: vec![],
                        response_fields: vec![],
                        file: file_path.to_string(),
                        line: (line_num + 1) as u32,
                    });
                }
            }
        }
        endpoints
    }

    fn extract_with_context(&self, content: &str, file_path: &str, parse_result: Option<&crate::parsers::types::ParseResult>) -> Vec<Endpoint> {
        let mut endpoints = self.extract(content, file_path);
        if let Some(pr) = parse_result {
            for ep in &mut endpoints {
                if let Some(func) = super::find_function_at_line(pr, ep.line.saturating_sub(1)) {
                    let req_fields = super::params_to_fields(&func.parameters);
                    if !req_fields.is_empty() {
                        ep.request_fields = req_fields;
                    }
                    if let Some(ref rt) = func.return_type {
                        let resp_fields = super::return_type_to_fields(rt);
                        if !resp_fields.is_empty() {
                            ep.response_fields = resp_fields;
                        }
                    }
                }
            }
        }
        endpoints
    }

    fn framework(&self) -> &str { "trpc" }
    fn matches(&self, content: &str) -> bool {
        content.contains("@trpc/server") || content.contains("createTRPCRouter")
            || content.contains("publicProcedure") || content.contains("protectedProcedure")
    }
}

/// CE-TRPC-01: Extract procedure name from v10/v11 builder pattern.
/// Matches lines like: `getUser: publicProcedure.input(...).query(...)`
/// Returns the procedure name (e.g. "getUser").
fn extract_v10_procedure(line: &str) -> Option<String> {
    // Must contain a procedure builder keyword.
    if !line.contains("Procedure") {
        return None;
    }
    // Look for `name:` or `name :` before the procedure builder.
    let colon_pos = line.find(':')?;
    let before_colon = line[..colon_pos].trim();
    // The name is the last word-like token before the colon.
    let name = before_colon
        .rsplit(|c: char| !c.is_alphanumeric() && c != '_')
        .next()?
        .trim();
    if name.is_empty() || name == "export" || name == "const" || name == "let" {
        return None;
    }
    Some(name.to_string())
}
