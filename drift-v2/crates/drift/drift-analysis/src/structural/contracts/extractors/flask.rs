//! Flask endpoint extractor.

use super::EndpointExtractor;
use crate::structural::contracts::types::*;

pub struct FlaskExtractor;

impl EndpointExtractor for FlaskExtractor {
    fn extract(&self, content: &str, file_path: &str) -> Vec<Endpoint> {
        let mut endpoints = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            // @app.route('/path', methods=['GET', 'POST'])
            // @blueprint.route('/path')
            for prefix in &["@app.route(", "@blueprint.route(", "@bp.route("] {
                if let Some(pos) = trimmed.find(prefix) {
                    if let Some(path) = extract_flask_path(trimmed, pos + prefix.len()) {
                        let methods = extract_flask_methods(trimmed);
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

    fn framework(&self) -> &str { "flask" }
    fn matches(&self, content: &str) -> bool {
        content.contains("flask") || content.contains("@app.route") || content.contains("@blueprint.route")
    }
}

fn extract_flask_path(line: &str, start: usize) -> Option<String> {
    let rest = &line[start..];
    let trimmed = rest.trim_start();
    let quote = trimmed.chars().next()?;
    if quote != '\'' && quote != '"' {
        return None;
    }
    let after_quote = &trimmed[1..];
    let end = after_quote.find(quote)?;
    Some(after_quote[..end].to_string())
}

fn extract_flask_methods(line: &str) -> Vec<String> {
    if let Some(methods_start) = line.find("methods=") {
        let rest = &line[methods_start + 8..];
        if let Some(bracket_start) = rest.find('[') {
            if let Some(bracket_end) = rest.find(']') {
                let methods_str = &rest[bracket_start + 1..bracket_end];
                return methods_str
                    .split(',')
                    .map(|m| m.trim().trim_matches('\'').trim_matches('"').to_uppercase())
                    .filter(|m| !m.is_empty())
                    .collect();
            }
        }
    }
    vec!["GET".to_string()]
}
