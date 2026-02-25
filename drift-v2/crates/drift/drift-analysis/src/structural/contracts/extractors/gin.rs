//! Gin (Go) endpoint extractor.

use super::EndpointExtractor;
use super::express::extract_string_arg;
use crate::structural::contracts::types::*;

pub struct GinExtractor;

impl EndpointExtractor for GinExtractor {
    fn extract(&self, content: &str, file_path: &str) -> Vec<Endpoint> {
        let mut endpoints = Vec::new();
        let methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];

        // CE-GIN-02: Only extract if this is actually a gin file.
        let is_gin = content.contains("gin.Default()") || content.contains("gin.New()")
            || content.contains("github.com/gin-gonic/gin");
        if !is_gin {
            return endpoints;
        }

        // CE-GIN-01: Collect Group() prefix assignments.
        // Pattern: `varName := something.Group("/prefix")`
        let group_prefixes = collect_group_prefixes(content);

        for (line_num, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            for method in &methods {
                let pattern = format!(".{}(", method);
                if let Some(pos) = trimmed.find(pattern.as_str()) {
                    if let Some(path) = extract_string_arg(trimmed, pos + pattern.len()) {
                        // CE-GIN-01: Check if the receiver is a group variable.
                        let receiver = &trimmed[..pos];
                        let receiver_name = receiver.rsplit(|c: char| !c.is_alphanumeric() && c != '_').next().unwrap_or("");
                        let prefix = group_prefixes.iter()
                            .find(|(name, _)| name == receiver_name)
                            .map(|(_, p)| p.as_str())
                            .unwrap_or("");

                        let full_path = if prefix.is_empty() {
                            path
                        } else {
                            format!("{}/{}", prefix.trim_end_matches('/'), path.trim_start_matches('/'))
                        };

                        endpoints.push(Endpoint {
                            method: method.to_string(),
                            path: full_path,
                            request_fields: vec![],
                            response_fields: vec![],
                            file: file_path.to_string(),
                            line: (line_num + 1) as u32,
                        });
                    }
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

    fn framework(&self) -> &str { "gin" }
    fn matches(&self, content: &str) -> bool {
        content.contains("gin.Default()") || content.contains("gin.New()")
            || content.contains("github.com/gin-gonic/gin")
    }
}

/// CE-GIN-01: Collect `varName := receiver.Group("/prefix")` assignments.
fn collect_group_prefixes(content: &str) -> Vec<(String, String)> {
    let mut prefixes = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        // Go short variable declaration: `v1 := r.Group("/api/v1")`
        // Or assignment: `v1 = r.Group("/api/v1")`
        if trimmed.contains(".Group(") {
            if let Some(assign_pos) = trimmed.find(":=").or_else(|| {
                // Only match `=` if there's no `:=`
                let eq = trimmed.find('=')?;
                if eq > 0 && trimmed.as_bytes().get(eq - 1) != Some(&b':') {
                    Some(eq)
                } else {
                    None
                }
            }) {
                let var_name = trimmed[..assign_pos].trim();
                // var_name might be just the identifier or have `var` prefix
                let var_name = var_name.rsplit(|c: char| c.is_whitespace()).next().unwrap_or(var_name).trim();
                if let Some(group_pos) = trimmed.find(".Group(") {
                    if let Some(prefix) = extract_string_arg(trimmed, group_pos + 7) {
                        if !var_name.is_empty() {
                            prefixes.push((var_name.to_string(), prefix));
                        }
                    }
                }
            }
        }
    }
    prefixes
}
