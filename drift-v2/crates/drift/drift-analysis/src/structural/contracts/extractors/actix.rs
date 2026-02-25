//! Actix-web (Rust) endpoint extractor.

use super::EndpointExtractor;
use super::express::extract_string_arg;
use crate::structural::contracts::types::*;

pub struct ActixExtractor;

impl EndpointExtractor for ActixExtractor {
    fn extract(&self, content: &str, file_path: &str) -> Vec<Endpoint> {
        let mut endpoints = Vec::new();
        let attrs = [
            ("#[get(", "GET"), ("#[post(", "POST"), ("#[put(", "PUT"),
            ("#[delete(", "DELETE"), ("#[patch(", "PATCH"),
            ("#[head(", "HEAD"), ("#[options(", "OPTIONS"),
        ];

        for (line_num, line) in content.lines().enumerate() {
            let trimmed = line.trim();

            // Single-method attributes: #[get("/path")]
            for (attr, method) in &attrs {
                if let Some(pos) = trimmed.find(attr) {
                    if let Some(path) = extract_string_arg(trimmed, pos + attr.len()) {
                        endpoints.push(Endpoint {
                            method: method.to_string(),
                            path,
                            request_fields: vec![],
                            response_fields: vec![],
                            file: file_path.to_string(),
                            line: (line_num + 1) as u32,
                        });
                    }
                }
            }

            // CE-ACTX-01: #[route("/path", method = "GET", method = "POST")]
            if let Some(pos) = trimmed.find("#[route(") {
                if let Some(path) = extract_string_arg(trimmed, pos + 8) {
                    let methods = extract_route_methods(trimmed);
                    if methods.is_empty() {
                        endpoints.push(Endpoint {
                            method: "ANY".to_string(),
                            path,
                            request_fields: vec![],
                            response_fields: vec![],
                            file: file_path.to_string(),
                            line: (line_num + 1) as u32,
                        });
                    } else {
                        for method in methods {
                            endpoints.push(Endpoint {
                                method,
                                path: path.clone(),
                                request_fields: vec![],
                                response_fields: vec![],
                                file: file_path.to_string(),
                                line: (line_num + 1) as u32,
                            });
                        }
                    }
                }
            }

            // web::resource("/users").route(web::get().to(handler))
            if let Some(pos) = trimmed.find("web::resource(") {
                if let Some(path) = extract_string_arg(trimmed, pos + 14) {
                    // Try to extract method from web::get()/web::post() etc.
                    let method = extract_web_method(trimmed).unwrap_or_else(|| "ANY".to_string());
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

    fn framework(&self) -> &str { "actix" }
    fn matches(&self, content: &str) -> bool {
        content.contains("actix_web") || content.contains("actix-web")
            || content.contains("#[get(") || content.contains("web::resource")
            || content.contains("#[route(")
    }
}

/// CE-ACTX-01: Extract methods from `#[route("/path", method = "GET", method = "POST")]`.
fn extract_route_methods(line: &str) -> Vec<String> {
    let mut methods = Vec::new();
    let mut search_from = 0;
    while let Some(pos) = line[search_from..].find("method") {
        let abs_pos = search_from + pos;
        let after = line[abs_pos + 6..].trim_start();
        if let Some(stripped) = after.strip_prefix('=') {
            let after_eq = stripped.trim_start();
            let quote = after_eq.chars().next().unwrap_or(' ');
            if quote == '"' || quote == '\'' {
                if let Some(end) = after_eq[1..].find(quote) {
                    let method = after_eq[1..1 + end].to_uppercase();
                    if !method.is_empty() {
                        methods.push(method);
                    }
                }
            }
        }
        search_from = abs_pos + 6;
    }
    methods
}

/// Extract HTTP method from `web::get()`, `web::post()`, etc. on the same line.
fn extract_web_method(line: &str) -> Option<String> {
    for method in &["get", "post", "put", "delete", "patch", "head"] {
        let pattern = format!("web::{}()", method);
        if line.contains(&pattern) {
            return Some(method.to_uppercase());
        }
    }
    None
}
