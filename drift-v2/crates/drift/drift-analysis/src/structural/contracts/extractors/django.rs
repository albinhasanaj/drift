//! Django endpoint extractor (urlpatterns + DRF decorators).

use super::EndpointExtractor;
use crate::structural::contracts::types::*;

pub struct DjangoExtractor;

impl EndpointExtractor for DjangoExtractor {
    fn extract(&self, content: &str, file_path: &str) -> Vec<Endpoint> {
        let mut endpoints = Vec::new();
        let lines: Vec<&str> = content.lines().collect();

        // CE-DJNG-02: Collect include() prefixes from urlpatterns.
        let include_prefixes = collect_include_prefixes(content);

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // path('api/users/', views.user_list, name='user-list')
            // re_path(r'^api/users/$', views.user_list)
            for prefix in &["path(", "re_path("] {
                if let Some(pos) = trimmed.find(prefix) {
                    // CE-DJNG-02: Skip include() lines — they define prefixes, not endpoints.
                    if trimmed.contains("include(") {
                        continue;
                    }
                    if let Some(path) = extract_django_path(trimmed, pos + prefix.len()) {
                        endpoints.push(Endpoint {
                            method: "ANY".to_string(),
                            path,
                            request_fields: vec![],
                            response_fields: vec![],
                            file: file_path.to_string(),
                            line: (line_num + 1) as u32,
                        });
                    }
                }
            }

            // CE-DJNG-01: @api_view(['GET', 'POST']) decorator → look ahead for def.
            if trimmed.contains("@api_view") {
                let methods = extract_api_view_methods(trimmed);
                // Look ahead for the next `def function_name(` line.
                if let Some(func_name) = find_next_def(&lines, line_num + 1) {
                    for method in &methods {
                        endpoints.push(Endpoint {
                            method: method.clone(),
                            path: format!("/{}", func_name),
                            request_fields: vec![],
                            response_fields: vec![],
                            file: file_path.to_string(),
                            line: (line_num + 1) as u32,
                        });
                    }
                }
            }

            // CE-DJNG-03: @action(detail=True, methods=['post']) on ViewSet methods.
            if trimmed.contains("@action(") {
                let methods = extract_action_methods(trimmed);
                let is_detail = trimmed.contains("detail=True");
                if let Some(func_name) = find_next_def(&lines, line_num + 1) {
                    for method in &methods {
                        let path = if is_detail {
                            format!("/:id/{}", func_name)
                        } else {
                            format!("/{}", func_name)
                        };
                        endpoints.push(Endpoint {
                            method: method.clone(),
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

        let _ = &include_prefixes; // Stored for Phase C cross-file resolution.
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

    fn framework(&self) -> &str { "django" }
    fn matches(&self, content: &str) -> bool {
        content.contains("urlpatterns") || content.contains("@api_view")
            || content.contains("django") || content.contains("@action(")
    }
}

fn extract_django_path(line: &str, start: usize) -> Option<String> {
    let rest = &line[start..];
    let trimmed = rest.trim_start();
    // Handle both 'path' and "path" and r'regex'
    let trimmed = trimmed.trim_start_matches('r');
    let quote = trimmed.chars().next()?;
    if quote != '\'' && quote != '"' {
        return None;
    }
    let after_quote = &trimmed[1..];
    let end = after_quote.find(quote)?;
    Some(after_quote[..end].to_string())
}

/// CE-DJNG-01: Extract HTTP methods from @api_view(['GET', 'POST']).
fn extract_api_view_methods(line: &str) -> Vec<String> {
    if let Some(start) = line.find('[') {
        if let Some(end) = line.find(']') {
            let inner = &line[start + 1..end];
            return inner
                .split(',')
                .map(|m| m.trim().trim_matches('\'').trim_matches('"').to_uppercase())
                .filter(|m| !m.is_empty())
                .collect();
        }
    }
    vec!["GET".to_string()]
}

/// CE-DJNG-03: Extract methods from @action(detail=True, methods=['post']).
fn extract_action_methods(line: &str) -> Vec<String> {
    if let Some(methods_pos) = line.find("methods=") {
        let rest = &line[methods_pos + 8..];
        if let Some(start) = rest.find('[') {
            if let Some(end) = rest.find(']') {
                let inner = &rest[start + 1..end];
                return inner
                    .split(',')
                    .map(|m| m.trim().trim_matches('\'').trim_matches('"').to_uppercase())
                    .filter(|m| !m.is_empty())
                    .collect();
            }
        }
    }
    vec!["GET".to_string()]
}

/// Look ahead from `start_line` for the next `def function_name(` and return the name.
fn find_next_def(lines: &[&str], start_line: usize) -> Option<String> {
    let limit = (start_line + 5).min(lines.len());
    for line in &lines[start_line..limit] {
        let trimmed = line.trim();
        if let Some(pos) = trimmed.find("def ") {
            let after_def = &trimmed[pos + 4..];
            let name_end = after_def.find('(')?;
            let name = after_def[..name_end].trim();
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }
    }
    None
}

/// CE-DJNG-02: Collect path('prefix/', include(...)) prefixes.
fn collect_include_prefixes(content: &str) -> Vec<(String, String)> {
    let mut prefixes = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.contains("include(") {
            if let Some(pos) = trimmed.find("path(") {
                if let Some(prefix_path) = extract_django_path(trimmed, pos + 5) {
                    // Extract the include module name.
                    if let Some(inc_pos) = trimmed.find("include(") {
                        let rest = &trimmed[inc_pos + 8..];
                        let module = rest.trim_start_matches('\'').trim_start_matches('"');
                        if let Some(end) = module.find(['\'', '"', ')']) {
                            prefixes.push((prefix_path, module[..end].to_string()));
                        }
                    }
                }
            }
        }
    }
    prefixes
}
