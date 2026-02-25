//! Next.js API route extractor.

use super::EndpointExtractor;
use crate::structural::contracts::types::*;

pub struct NextJsExtractor;

impl EndpointExtractor for NextJsExtractor {
    fn extract(&self, content: &str, file_path: &str) -> Vec<Endpoint> {
        let mut endpoints = Vec::new();

        // Next.js App Router: export async function GET/POST/PUT/DELETE/PATCH
        let methods = ["GET", "POST", "PUT", "DELETE", "PATCH"];
        for (line_num, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            for method in &methods {
                let patterns = [
                    format!("export async function {}", method),
                    format!("export function {}", method),
                    format!("export const {} =", method),
                ];
                for pattern in &patterns {
                    if trimmed.starts_with(pattern.as_str()) {
                        let path = file_path_to_api_route(file_path);
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
        }

        // Pages Router: export default function handler
        if content.contains("export default") && file_path.contains("pages/api/") {
            let path = file_path_to_api_route(file_path);
            if endpoints.is_empty() {
                endpoints.push(Endpoint {
                    method: "ANY".to_string(),
                    path,
                    request_fields: vec![],
                    response_fields: vec![],
                    file: file_path.to_string(),
                    line: 1,
                });
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

    fn framework(&self) -> &str { "nextjs" }
    fn matches(&self, content: &str) -> bool {
        content.contains("NextRequest") || content.contains("NextResponse")
            || content.contains("NextApiRequest")
    }
}

fn file_path_to_api_route(file_path: &str) -> String {
    let normalized = file_path.replace('\\', "/");
    // app/api/users/route.ts → /api/users
    if let Some(pos) = normalized.find("app/api/") {
        let route = &normalized[pos + 4..]; // skip "app/"
        let route = route.trim_end_matches("/route.ts")
            .trim_end_matches("/route.js")
            .trim_end_matches("/route.tsx");
        let route = format!("/{}", route.trim_start_matches('/'));
        return normalize_nextjs_route(&route);
    }
    // pages/api/users.ts → /api/users
    if let Some(pos) = normalized.find("pages/api/") {
        let route = &normalized[pos + 6..]; // skip "pages/"
        let route = route.trim_end_matches(".ts")
            .trim_end_matches(".js")
            .trim_end_matches(".tsx")
            .trim_end_matches("/index");
        let route = format!("/{}", route.trim_start_matches('/'));
        return normalize_nextjs_route(&route);
    }
    normalized
}

/// CE-NEXT-01 & CE-NEXT-02: Normalize Next.js route paths.
/// - Strip route groups: `(auth)` → removed
/// - Convert dynamic segments: `[id]` → `:id`
/// - Convert catch-all segments: `[...slug]` → `*slug`
/// - Convert optional catch-all: `[[...slug]]` → `*slug?`
fn normalize_nextjs_route(route: &str) -> String {
    let mut segments: Vec<String> = Vec::new();
    for segment in route.split('/') {
        if segment.is_empty() {
            continue;
        }
        // CE-NEXT-01: Strip route groups — segments wrapped in ()
        if segment.starts_with('(') && segment.ends_with(')') {
            continue;
        }
        // CE-NEXT-02: Optional catch-all [[...param]]
        if segment.starts_with("[[") && segment.ends_with("]]")
            && segment.contains("...")
        {
            let inner = &segment[2..segment.len() - 2]; // strip [[ and ]]
            let param = inner.trim_start_matches("...");
            segments.push(format!("*{}?", param));
            continue;
        }
        // CE-NEXT-02: Catch-all [...param]
        if segment.starts_with('[') && segment.ends_with(']')
            && segment.contains("...")
        {
            let inner = &segment[1..segment.len() - 1]; // strip [ and ]
            let param = inner.trim_start_matches("...");
            segments.push(format!("*{}", param));
            continue;
        }
        // CE-NEXT-02: Dynamic segment [param]
        if segment.starts_with('[') && segment.ends_with(']') {
            let param = &segment[1..segment.len() - 1];
            segments.push(format!(":{}", param));
            continue;
        }
        segments.push(segment.to_string());
    }
    if segments.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", segments.join("/"))
    }
}
