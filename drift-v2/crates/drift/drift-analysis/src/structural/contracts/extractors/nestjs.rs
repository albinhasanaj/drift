//! NestJS endpoint extractor (decorator-based).

use super::EndpointExtractor;
use super::express::extract_string_arg;
use crate::structural::contracts::types::*;

pub struct NestJsExtractor;

impl EndpointExtractor for NestJsExtractor {
    fn extract(&self, content: &str, file_path: &str) -> Vec<Endpoint> {
        let mut endpoints = Vec::new();
        // CE-NEST-01: All 8 HTTP method decorators.
        let decorators = [
            ("@Get(", "GET"), ("@Post(", "POST"), ("@Put(", "PUT"),
            ("@Delete(", "DELETE"), ("@Patch(", "PATCH"),
            ("@All(", "ALL"), ("@Head(", "HEAD"), ("@Options(", "OPTIONS"),
        ];

        // Extract controller base path
        let base_path = extract_controller_path(content).unwrap_or_default();

        for (line_num, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            for (decorator, method) in &decorators {
                if let Some(pos) = trimmed.find(decorator) {
                    let path = extract_string_arg(trimmed, pos + decorator.len())
                        .unwrap_or_default();
                    let full_path = if base_path.is_empty() {
                        path
                    } else {
                        format!("{}/{}", base_path.trim_end_matches('/'), path.trim_start_matches('/'))
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
        endpoints
    }

    fn extract_with_context(&self, content: &str, file_path: &str, parse_result: Option<&crate::parsers::types::ParseResult>) -> Vec<Endpoint> {
        let mut endpoints = self.extract(content, file_path);
        if let Some(pr) = parse_result {
            for ep in &mut endpoints {
                if let Some(func) = super::find_function_at_line(pr, ep.line.saturating_sub(1)) {
                    // CE-NEST-F01: Extract from @Body(), @Param(), @Query() decorators
                    let dec_fields = super::extract_decorator_fields(&func.decorators, &["Body", "Param", "Query"]);
                    if !dec_fields.is_empty() {
                        ep.request_fields = dec_fields;
                    } else {
                        let req_fields = super::params_to_fields(&func.parameters);
                        if !req_fields.is_empty() {
                            ep.request_fields = req_fields;
                        }
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

    fn framework(&self) -> &str { "nestjs" }
    fn matches(&self, content: &str) -> bool {
        content.contains("@Controller") || content.contains("@nestjs/common")
    }
}

/// CE-NEST-02: Extract controller base path, handling @Controller() with no argument.
fn extract_controller_path(content: &str) -> Option<String> {
    let marker = "@Controller(";
    let pos = content.find(marker)?;
    // Try to extract a string arg; if the decorator has no path (e.g. @Controller()),
    // return an empty string so endpoints use just their own path.
    match extract_string_arg(content, pos + marker.len()) {
        Some(path) => Some(path),
        None => {
            // Check if it's @Controller() with no arg — not @Controller with something else
            let rest = content[pos + marker.len()..].trim_start();
            if rest.starts_with(')') {
                Some(String::new())
            } else {
                None
            }
        }
    }
}
