//! Auth detector — authentication, authorization, JWT, session, and token patterns.

use smallvec::SmallVec;

use crate::detectors::traits::{Detector, DetectorCategory, DetectorVariant};
use crate::engine::types::{DetectionMethod, PatternCategory, PatternMatch};
use crate::engine::visitor::DetectionContext;

pub struct AuthDetector;

impl Detector for AuthDetector {
    fn id(&self) -> &str { "auth-base" }
    fn category(&self) -> DetectorCategory { DetectorCategory::Auth }
    fn variant(&self) -> DetectorVariant { DetectorVariant::Base }

    fn detect(&self, ctx: &DetectionContext) -> Vec<PatternMatch> {
        let mut matches = Vec::new();

        // Detect auth-related function names (login, authenticate, authorize, verify, etc.)
        let auth_keywords = ["login", "logout", "authenticate", "authorize", "signup", "signin",
                             "signout", "verify_token", "validate_token", "refresh_token",
                             "check_permission", "has_role", "is_authenticated"];
        for func in ctx.functions {
            let name_lower = func.name.to_lowercase();
            if auth_keywords.iter().any(|kw| name_lower.contains(kw)) {
                matches.push(PatternMatch {
                    file: ctx.file.to_string(),
                    line: func.line,
                    column: func.column,
                    pattern_id: "AUTH-FUNC-001".to_string(),
                    confidence: 0.90,
                    cwe_ids: SmallVec::new(),
                    owasp: None,
                    detection_method: DetectionMethod::AstVisitor,
                    category: PatternCategory::Auth,
                    matched_text: format!("Auth function: {}", func.name),
                });
            }
        }

        // Detect JWT/token-related imports
        let auth_imports = [
            // JS/TS
            "jsonwebtoken", "jwt", "passport", "bcrypt", "argon2",
            "oauth", "auth0", "firebase-admin", "next-auth", "jose",
            // Python
            "django.contrib.auth", "flask-login", "flask_login", "authlib", "python-jose", "passlib",
            // Java/Kotlin
            "spring-security", "org.springframework.security", "apache.shiro", "io.jsonwebtoken", "com.auth0",
            // C#
            "Microsoft.AspNetCore.Identity", "Microsoft.AspNetCore.Authentication", "System.IdentityModel.Tokens.Jwt",
            // Go
            "golang.org/x/oauth2", "github.com/dgrijalva/jwt-go", "github.com/golang-jwt/jwt",
            // Ruby
            "devise", "omniauth", "warden", "doorkeeper",
            // PHP
            "laravel/sanctum", "tymon/jwt-auth", "laravel/passport", "firebase/php-jwt",
            // Rust
            "actix-identity", "actix-web-httpauth", "oauth2",
        ];
        for import in ctx.imports {
            let source_lower = import.source.to_lowercase();
            if auth_imports.iter().any(|ai| source_lower.contains(ai)) {
                matches.push(PatternMatch {
                    file: ctx.file.to_string(),
                    line: import.line,
                    column: 0,
                    pattern_id: "AUTH-IMPORT-002".to_string(),
                    confidence: 0.95,
                    cwe_ids: SmallVec::new(),
                    owasp: None,
                    detection_method: DetectionMethod::AstVisitor,
                    category: PatternCategory::Auth,
                    matched_text: format!("Auth library import: {}", import.source),
                });
            }
        }

        // Detect auth-related call sites (jwt.sign, jwt.verify, bcrypt.hash, etc.)
        let auth_callees = ["sign", "verify", "hash", "compare", "encode", "decode"];
        let auth_receivers = ["jwt", "bcrypt", "argon2", "passport", "auth",
            "Auth", "devise", "Devise", "security", "Security"];
        for call in ctx.call_sites {
            let callee_lower = call.callee_name.to_lowercase();
            let receiver_lower = call.receiver.as_deref().unwrap_or("").to_lowercase();
            if auth_callees.contains(&callee_lower.as_str())
                && auth_receivers.iter().any(|r| receiver_lower.contains(r))
            {
                matches.push(PatternMatch {
                    file: ctx.file.to_string(),
                    line: call.line,
                    column: call.column,
                    pattern_id: "AUTH-CALL-003".to_string(),
                    confidence: 0.85,
                    cwe_ids: SmallVec::new(),
                    owasp: None,
                    detection_method: DetectionMethod::AstVisitor,
                    category: PatternCategory::Auth,
                    matched_text: format!("Auth call: {}.{}", receiver_lower, call.callee_name),
                });
            }
        }

        matches
    }
}
