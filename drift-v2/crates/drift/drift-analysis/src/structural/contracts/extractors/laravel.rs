//! Laravel endpoint extractor.

use super::EndpointExtractor;
use super::express::extract_string_arg;
use crate::structural::contracts::types::*;

pub struct LaravelExtractor;

impl EndpointExtractor for LaravelExtractor {
    fn extract(&self, content: &str, file_path: &str) -> Vec<Endpoint> {
        let mut endpoints = Vec::new();
        let methods = ["get", "post", "put", "delete", "patch"];

        for (line_num, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            for method in &methods {
                // Route::get('/users', [UserController::class, 'index']);
                let pattern = format!("Route::{}(", method);
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

    fn framework(&self) -> &str { "laravel" }
    fn matches(&self, content: &str) -> bool {
        content.contains("Route::") || content.contains("Illuminate\\Routing")
    }
}
