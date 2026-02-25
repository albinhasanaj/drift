//! API detector — endpoint patterns, REST conventions, versioning.

use smallvec::SmallVec;

use crate::detectors::traits::{Detector, DetectorCategory, DetectorVariant};
use crate::engine::types::{DetectionMethod, PatternCategory, PatternMatch};
use crate::engine::visitor::DetectionContext;

pub struct ApiDetector;

impl Detector for ApiDetector {
    fn id(&self) -> &str { "api-base" }
    fn category(&self) -> DetectorCategory { DetectorCategory::Api }
    fn variant(&self) -> DetectorVariant { DetectorVariant::Base }

    fn detect(&self, ctx: &DetectionContext) -> Vec<PatternMatch> {
        let mut matches = Vec::new();

        // Detect REST endpoint route handler patterns (GET/POST/PUT/DELETE)
        // DP-API-FP-01/02: Gate to known router receivers to avoid false positives
        let rest_methods = ["get", "post", "put", "delete", "patch", "options", "head"];
        let known_routers = ["app", "router", "server", "route", "api", "express",
            "fastify", "koa", "hapi", "gin", "mux", "fiber", "chi", "echo", "r"];
        for call in ctx.call_sites {
            let callee_lower = call.callee_name.to_lowercase();
            if rest_methods.contains(&callee_lower.as_str()) {
                // Only match if receiver is a known router/app object
                let receiver_lower = call.receiver.as_deref().unwrap_or("").to_lowercase();
                if known_routers.iter().any(|r| receiver_lower == *r) {
                    let method_upper = call.callee_name.to_uppercase();
                    matches.push(PatternMatch {
                        file: ctx.file.to_string(),
                        line: call.line,
                        column: call.column,
                        pattern_id: "API-REST-001".to_string(),
                        confidence: 0.85,
                        cwe_ids: SmallVec::new(),
                        owasp: None,
                        detection_method: DetectionMethod::AstVisitor,
                        category: PatternCategory::Api,
                        matched_text: format!("{} route handler: {}.{}", method_upper, receiver_lower, call.callee_name),
                    });
                }
            }
        }

        // Detect route/path string literals (e.g., "/api/v1/users")
        for lit in &ctx.parse_result.string_literals {
            if lit.value.starts_with("/api/")
                || lit.value.starts_with("/v1/")
                || lit.value.starts_with("/v2/")
                || (lit.value.starts_with('/') && lit.value.contains("/api"))
            {
                matches.push(PatternMatch {
                    file: ctx.file.to_string(),
                    line: lit.line,
                    column: lit.column,
                    pattern_id: "API-ROUTE-002".to_string(),
                    confidence: 0.80,
                    cwe_ids: SmallVec::new(),
                    owasp: None,
                    detection_method: DetectionMethod::AstVisitor,
                    category: PatternCategory::Api,
                    matched_text: format!("API route: {}", lit.value),
                });
            }
        }

        // Detect API framework imports (express, fastify, koa, flask, etc.)
        let api_frameworks = [
            // JS/TS
            "express", "fastify", "koa", "hapi", "restify", "nest",
            // Python
            "flask", "django", "fastapi", "starlette", "sanic",
            // Rust
            "actix-web", "axum", "rocket", "warp", "tide",
            // Java/Kotlin
            "org.springframework.web", "spring-boot", "javax.ws.rs", "io.ktor", "spring",
            // C#
            "Microsoft.AspNetCore.Mvc", "Microsoft.AspNetCore",
            // Go
            "github.com/gin-gonic/gin", "github.com/gorilla/mux", "github.com/gofiber/fiber", "net/http",
            // Ruby
            "sinatra", "rails", "actionpack", "grape",
            // PHP
            "laravel", "symfony", "slim",
        ];
        for import in ctx.imports {
            let source_lower = import.source.to_lowercase();
            if api_frameworks.iter().any(|fw| source_lower.contains(fw)) {
                matches.push(PatternMatch {
                    file: ctx.file.to_string(),
                    line: import.line,
                    column: 0,
                    pattern_id: "API-FRAMEWORK-003".to_string(),
                    confidence: 0.95,
                    cwe_ids: SmallVec::new(),
                    owasp: None,
                    detection_method: DetectionMethod::AstVisitor,
                    category: PatternCategory::Api,
                    matched_text: format!("API framework import: {}", import.source),
                });
            }
        }

        matches
    }
}
