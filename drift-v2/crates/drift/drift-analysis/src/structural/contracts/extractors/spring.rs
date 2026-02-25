//! Spring Boot endpoint extractor (Java/Kotlin annotations).

use super::EndpointExtractor;
use super::express::extract_string_arg;
use crate::structural::contracts::types::*;

pub struct SpringExtractor;

impl EndpointExtractor for SpringExtractor {
    fn extract(&self, content: &str, file_path: &str) -> Vec<Endpoint> {
        let mut endpoints = Vec::new();
        let annotations = [
            ("@GetMapping(", "GET"), ("@PostMapping(", "POST"),
            ("@PutMapping(", "PUT"), ("@DeleteMapping(", "DELETE"),
            ("@PatchMapping(", "PATCH"), ("@RequestMapping(", "ANY"),
        ];

        let base_path = extract_request_mapping_path(content).unwrap_or_default();

        for (line_num, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            for (annotation, method) in &annotations {
                if let Some(pos) = trimmed.find(annotation) {
                    let path = extract_string_arg(trimmed, pos + annotation.len())
                        .or_else(|| extract_value_attr(trimmed))
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
                    let dec_fields = super::extract_decorator_fields(&func.decorators, &["RequestParam", "RequestBody", "PathVariable"]);
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

    fn framework(&self) -> &str { "spring" }
    fn matches(&self, content: &str) -> bool {
        content.contains("@RestController") || content.contains("@RequestMapping")
            || content.contains("@GetMapping") || content.contains("springframework")
    }
}

fn extract_request_mapping_path(content: &str) -> Option<String> {
    let marker = "@RequestMapping(";
    let pos = content.find(marker)?;
    extract_string_arg(content, pos + marker.len())
        .or_else(|| extract_value_attr(&content[pos..]))
}

fn extract_value_attr(text: &str) -> Option<String> {
    let marker = "value = ";
    let pos = text.find(marker)?;
    extract_string_arg(text, pos + marker.len())
}
