//! Rails endpoint extractor (routes.rb).

use super::EndpointExtractor;
use crate::structural::contracts::types::*;

pub struct RailsExtractor;

impl EndpointExtractor for RailsExtractor {
    fn extract(&self, content: &str, file_path: &str) -> Vec<Endpoint> {
        let mut endpoints = Vec::new();
        let methods = ["get", "post", "put", "delete", "patch"];

        // CE-RAIL-02: Track namespace/scope prefixes via indentation depth.
        let namespace_prefixes = collect_namespace_prefixes(content);

        for (line_num, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            let prefix = find_active_prefix(&namespace_prefixes, line_num);

            for method in &methods {
                // get '/users', to: 'users#index'
                let pattern = format!("{} '", method);
                let pattern2 = format!("{} \"", method);
                for pat in &[&pattern, &pattern2] {
                    if trimmed.starts_with(pat.as_str()) {
                        let quote = pat.chars().last().unwrap();
                        let rest = &trimmed[pat.len()..];
                        if let Some(end) = rest.find(quote) {
                            let path = format!("{}{}", prefix, &rest[..end]);
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

            // CE-RAIL-01: resources :users → correct RESTful paths.
            if trimmed.starts_with("resources :") || trimmed.starts_with("resources(") {
                let resource = trimmed
                    .trim_start_matches("resources :")
                    .trim_start_matches("resources(:")
                    .split(|c: char| !c.is_alphanumeric() && c != '_')
                    .next()
                    .unwrap_or("");
                if !resource.is_empty() {
                    let base = format!("{}/{}", prefix, resource);
                    // Collection routes (no :id)
                    for (method, _action) in &[("GET", "index"), ("POST", "create")] {
                        endpoints.push(Endpoint {
                            method: method.to_string(),
                            path: base.clone(),
                            request_fields: vec![],
                            response_fields: vec![],
                            file: file_path.to_string(),
                            line: (line_num + 1) as u32,
                        });
                    }
                    // Member routes (with :id)
                    for (method, _action) in &[("GET", "show"), ("PUT", "update"), ("DELETE", "destroy")] {
                        endpoints.push(Endpoint {
                            method: method.to_string(),
                            path: format!("{}/:id", base),
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

    fn framework(&self) -> &str { "rails" }
    fn matches(&self, content: &str) -> bool {
        content.contains("Rails.application.routes") || content.contains("resources :")
            || content.contains("ActionController")
    }
}

/// CE-RAIL-02: A namespace/scope block with its line range and prefix.
struct NamespaceBlock {
    prefix: String,
    start_line: usize,
    end_line: usize,
}

/// CE-RAIL-02: Collect namespace/scope blocks with their line ranges.
fn collect_namespace_prefixes(content: &str) -> Vec<NamespaceBlock> {
    let mut blocks = Vec::new();
    let lines: Vec<&str> = content.lines().collect();

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        // namespace :api do ... end
        // scope '/api' do ... end
        let name = if trimmed.starts_with("namespace :") {
            let rest = trimmed.trim_start_matches("namespace :");
            let name = rest.split(|c: char| !c.is_alphanumeric() && c != '_').next().unwrap_or("");
            if name.is_empty() { continue; }
            format!("/{}", name)
        } else if trimmed.starts_with("scope '") || trimmed.starts_with("scope \"") {
            let quote = if trimmed.starts_with("scope '") { '\'' } else { '"' };
            let rest = &trimmed[7..]; // skip "scope '"
            if let Some(end) = rest.find(quote) {
                rest[..end].to_string()
            } else {
                continue;
            }
        } else {
            continue;
        };

        // Find the matching `end` by tracking do/end depth.
        let end_line = find_block_end(&lines, i);
        blocks.push(NamespaceBlock { prefix: name, start_line: i, end_line });
    }
    blocks
}

/// Find the `end` that closes a `do` block starting at `start_line`.
fn find_block_end(lines: &[&str], start_line: usize) -> usize {
    let mut depth = 0;
    for (i, line) in lines.iter().enumerate().skip(start_line) {
        let trimmed = line.trim();
        if trimmed.contains(" do") || trimmed.ends_with(" do") {
            depth += 1;
        }
        if trimmed == "end" || trimmed.starts_with("end ") {
            depth -= 1;
            if depth <= 0 {
                return i;
            }
        }
    }
    lines.len().saturating_sub(1)
}

/// Find the active namespace prefix for a given line number.
fn find_active_prefix(blocks: &[NamespaceBlock], line_num: usize) -> String {
    let mut prefix = String::new();
    for block in blocks {
        if line_num > block.start_line && line_num < block.end_line {
            prefix.push_str(&block.prefix);
        }
    }
    prefix
}
