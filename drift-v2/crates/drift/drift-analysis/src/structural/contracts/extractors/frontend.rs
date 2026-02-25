//! Frontend/consumer library extractors (fetch, axios, SWR, TanStack Query, Apollo, urql).

use super::EndpointExtractor;
use super::express::extract_string_arg;
use crate::structural::contracts::types::*;

pub struct FrontendExtractor;

impl EndpointExtractor for FrontendExtractor {
    fn extract(&self, content: &str, file_path: &str) -> Vec<Endpoint> {
        let mut endpoints = Vec::new();
        let lines: Vec<&str> = content.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // fetch('/api/users') or fetch("/api/users")
            if let Some(pos) = trimmed.find("fetch(") {
                if let Some(path) = extract_string_arg(trimmed, pos + 6) {
                    if path.starts_with('/') || path.starts_with("http") {
                        // CE-FE-02: Multi-line method inference — check current + next 3 lines.
                        let method = infer_method_multiline(&lines, line_num);
                        endpoints.push(Endpoint {
                            method,
                            path,
                            request_fields: vec![],
                            response_fields: vec![],
                            file: file_path.to_string(),
                            line: (line_num + 1) as u32,
                        });
                    }
                }
            }

            // axios.get('/api/users') or axios.post('/api/users')
            for method in &["get", "post", "put", "delete", "patch"] {
                let pattern = format!("axios.{}(", method);
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

            // useSWR('/api/users', fetcher) or useQuery(['/api/users'])
            for hook in &["useSWR(", "useQuery("] {
                if let Some(pos) = trimmed.find(hook) {
                    if let Some(path) = extract_string_arg(trimmed, pos + hook.len()) {
                        if path.starts_with('/') || path.starts_with("http") {
                            endpoints.push(Endpoint {
                                method: "GET".to_string(),
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

            // CE-FE-01: useMutation('/api/users') or useMutation(['/api/users'])
            if let Some(pos) = trimmed.find("useMutation(") {
                if let Some(path) = extract_string_arg(trimmed, pos + 12) {
                    if path.starts_with('/') || path.starts_with("http") {
                        endpoints.push(Endpoint {
                            method: "POST".to_string(),
                            path,
                            request_fields: vec![],
                            response_fields: vec![],
                            file: file_path.to_string(),
                            line: (line_num + 1) as u32,
                        });
                    }
                }
                // CE-FE-01: Also handle useMutation with mutationFn containing fetch/axios.
                // For TanStack Query: useMutation({ mutationFn: () => fetch('/api/users', ...) })
                // This is handled by the fetch() detection above on subsequent lines.
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

    fn framework(&self) -> &str { "frontend" }
    fn matches(&self, content: &str) -> bool {
        content.contains("fetch(") || content.contains("axios")
            || content.contains("useSWR") || content.contains("useQuery")
            || content.contains("useMutation")
    }
}

/// CE-FE-02: Multi-line method inference — check the current line and next 3 lines for `method:`.
fn infer_method_multiline(lines: &[&str], start: usize) -> String {
    let limit = (start + 4).min(lines.len());
    for line in &lines[start..limit] {
        let result = infer_method_from_line(line);
        if result != "GET" {
            return result;
        }
    }
    "GET".to_string()
}

fn infer_method_from_line(line: &str) -> String {
    if line.contains("method:") || line.contains("method :") {
        let lower = line.to_lowercase();
        if lower.contains("'post'") || lower.contains("\"post\"") {
            return "POST".to_string();
        }
        if lower.contains("'put'") || lower.contains("\"put\"") {
            return "PUT".to_string();
        }
        if lower.contains("'delete'") || lower.contains("\"delete\"") {
            return "DELETE".to_string();
        }
        if lower.contains("'patch'") || lower.contains("\"patch\"") {
            return "PATCH".to_string();
        }
    }
    "GET".to_string()
}
