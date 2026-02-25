//! Express.js endpoint extractor.

use super::EndpointExtractor;
use crate::structural::contracts::types::*;

pub struct ExpressExtractor;

/// Default Express-style receivers.
const DEFAULT_RECEIVERS: &[&str] = &["app", "router"];
/// Additional receivers recognised when the file imports express.
const EXPRESS_RECEIVERS: &[&str] = &["server", "api", "route", "routes"];

impl EndpointExtractor for ExpressExtractor {
    fn extract(&self, content: &str, file_path: &str) -> Vec<Endpoint> {
        let mut endpoints = Vec::new();
        let methods = ["get", "post", "put", "delete", "patch"];
        let has_express_import = content.contains("require('express')") || content.contains("require(\"express\")") || content.contains("from 'express'") || content.contains("from \"express\"");

        // CE-EXP-03: Collect app.use('/prefix', ...) path prefixes.
        let use_prefixes = collect_use_prefixes(content);

        // Build the receiver list — always include defaults, add extras for express files.
        let mut receivers: Vec<&str> = DEFAULT_RECEIVERS.to_vec();
        if has_express_import {
            receivers.extend_from_slice(EXPRESS_RECEIVERS);
        }

        let lines: Vec<&str> = content.lines().collect();
        let mut line_idx = 0;
        while line_idx < lines.len() {
            let trimmed = lines[line_idx].trim();
            for method in &methods {
                for receiver in &receivers {
                    let pattern = format!("{}.{}(", receiver, method);
                    if let Some(pos) = trimmed.find(pattern.as_str()) {
                        // CE-EXP-02: Handle multi-line — accumulate until we find the path string arg.
                        let combined = if extract_string_arg(trimmed, pos + pattern.len()).is_none() {
                            accumulate_lines(&lines, line_idx, pos + pattern.len())
                        } else {
                            trimmed.to_string()
                        };

                        if let Some(path) = extract_string_arg(&combined, combined.find(pattern.as_str()).unwrap_or(0) + pattern.len()) {
                            // Apply any matching use-prefix.
                            let full_path = apply_prefix(&path, &use_prefixes);
                            endpoints.push(Endpoint {
                                method: method.to_uppercase(),
                                path: full_path,
                                request_fields: vec![],
                                response_fields: vec![],
                                file: file_path.to_string(),
                                line: (line_idx + 1) as u32,
                            });
                        }
                    }
                }
            }
            line_idx += 1;
        }
        endpoints
    }

    fn extract_with_context(&self, content: &str, file_path: &str, parse_result: Option<&crate::parsers::types::ParseResult>) -> Vec<Endpoint> {
        let mut endpoints = self.extract(content, file_path);
        if let Some(pr) = parse_result {
            for ep in &mut endpoints {
                if let Some(func) = super::find_function_at_line(pr, ep.line.saturating_sub(1)) {
                    // Request fields from non-framework parameters
                    let req_fields = super::params_to_fields(&func.parameters);
                    if !req_fields.is_empty() {
                        ep.request_fields = req_fields;
                    }
                    // Response fields from return type
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

    fn framework(&self) -> &str { "express" }

    fn matches(&self, content: &str) -> bool {
        content.contains("express") || content.contains("app.get(") || content.contains("router.get(")
            || content.contains("server.get(") || content.contains("api.get(")
    }
}

/// CE-EXP-02: Accumulate successive lines until we find a string arg or hit a limit.
fn accumulate_lines(lines: &[&str], start: usize, _offset: usize) -> String {
    let mut combined = lines[start].trim().to_string();
    let limit = (start + 5).min(lines.len());
    for line in &lines[(start + 1)..limit] {
        combined.push(' ');
        combined.push_str(line.trim());
        // Stop once we have a closing paren or a string literal is available.
        if combined.contains(')') {
            break;
        }
    }
    combined
}

/// CE-EXP-03: Collect `app.use('/prefix', ...)` path prefixes.
fn collect_use_prefixes(content: &str) -> Vec<String> {
    let mut prefixes = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(pos) = trimmed.find(".use(") {
            if let Some(path) = extract_string_arg(trimmed, pos + 5) {
                if path.starts_with('/') {
                    prefixes.push(path);
                }
            }
        }
    }
    prefixes
}

/// Apply use-prefix: if the endpoint path is relative (doesn't start with a known prefix),
/// check if any use-prefix is a parent. For now, prefixes are informational — actual sub-router
/// prefix application requires cross-file resolution, so we store them for later use.
fn apply_prefix(path: &str, _prefixes: &[String]) -> String {
    // Direct prefix application is only valid within the same file when the router
    // is mounted via app.use('/prefix', router). Since we cannot yet trace which
    // router variable maps to which use() call, we pass through unchanged.
    // Phase C will add cross-file resolution.
    path.to_string()
}

/// Extract a string argument from a position (handles both ' and " quotes).
pub(crate) fn extract_string_arg(line: &str, start: usize) -> Option<String> {
    let rest = &line[start..];
    let trimmed = rest.trim_start();
    let quote = trimmed.chars().next()?;
    if quote != '\'' && quote != '"' && quote != '`' {
        return None;
    }
    let after_quote = &trimmed[1..];
    let end = after_quote.find(quote)?;
    Some(after_quote[..end].to_string())
}
