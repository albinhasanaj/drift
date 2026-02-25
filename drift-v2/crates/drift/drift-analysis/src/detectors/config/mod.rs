//! Config detector — environment variables, feature flags, configuration files.

use smallvec::SmallVec;

use crate::detectors::traits::{Detector, DetectorCategory, DetectorVariant};
use crate::engine::types::{DetectionMethod, PatternCategory, PatternMatch};
use crate::engine::visitor::DetectionContext;

pub struct ConfigDetector;

impl Detector for ConfigDetector {
    fn id(&self) -> &str { "config-base" }
    fn category(&self) -> DetectorCategory { DetectorCategory::Config }
    fn variant(&self) -> DetectorVariant { DetectorVariant::Base }

    fn detect(&self, ctx: &DetectionContext) -> Vec<PatternMatch> {
        let mut matches = Vec::new();

        // Detect environment variable access patterns (process.env, os.environ, std::env)
        for call in ctx.call_sites {
            let callee_lower = call.callee_name.to_lowercase();
            let receiver_lower = call.receiver.as_deref().unwrap_or("").to_lowercase();
            let is_env_access = receiver_lower == "process.env"
                || receiver_lower == "process"
                || callee_lower == "getenv"
                || (receiver_lower == "os" && callee_lower == "environ")
                || (receiver_lower == "env" && (callee_lower == "var" || callee_lower == "var_os"))
                || callee_lower == "env"
                || (receiver_lower == "system" && callee_lower == "getenv")
                || (receiver_lower == "environment" && callee_lower == "getenvironmentvariable")
                || (receiver_lower == "env" && callee_lower == "fetch")
                || (receiver_lower == "viper" && callee_lower == "get");
            if is_env_access {
                matches.push(PatternMatch {
                    file: ctx.file.to_string(),
                    line: call.line,
                    column: call.column,
                    pattern_id: "CFG-ENV-001".to_string(),
                    confidence: 0.85,
                    cwe_ids: SmallVec::new(),
                    owasp: None,
                    detection_method: DetectionMethod::AstVisitor,
                    category: PatternCategory::Config,
                    matched_text: format!("Env variable access: {}.{}", receiver_lower, call.callee_name),
                });
            }
        }

        // Detect config-related imports (dotenv, config, convict, nconf, etc.)
        let config_imports = [
            // JS/TS
            "dotenv", "config", "convict", "nconf", "rc", "cosmiconfig",
            "envalid", "env-var", "cross-env",
            // Python
            "python-dotenv", "pydantic-settings", "pydantic", "configparser", "dynaconf",
            // Java/Kotlin
            "com.typesafe.config", "io.github.cdimascio.dotenv",
            // Go
            "github.com/spf13/viper", "github.com/kelseyhightower/envconfig", "github.com/joho/godotenv",
            // Ruby
            "figaro", "chamber",
            // PHP
            "vlucas/phpdotenv", "symfony/dotenv",
            // Rust
            "dotenvy", "figment",
            // C#
            "Microsoft.Extensions.Configuration",
        ];
        for import in ctx.imports {
            let source_lower = import.source.to_lowercase();
            if config_imports.iter().any(|ci| source_lower == *ci) {
                matches.push(PatternMatch {
                    file: ctx.file.to_string(),
                    line: import.line,
                    column: 0,
                    pattern_id: "CFG-IMPORT-002".to_string(),
                    confidence: 0.90,
                    cwe_ids: SmallVec::new(),
                    owasp: None,
                    detection_method: DetectionMethod::AstVisitor,
                    category: PatternCategory::Config,
                    matched_text: format!("Config library import: {}", import.source),
                });
            }
        }

        // Detect feature flag patterns in string literals
        for lit in &ctx.parse_result.string_literals {
            let val_lower = lit.value.to_lowercase();
            if val_lower.starts_with("feature_")
                || val_lower.starts_with("ff_")
                || val_lower.starts_with("flag_")
                || val_lower.contains("feature_flag")
                || val_lower.contains("feature-flag")
            {
                matches.push(PatternMatch {
                    file: ctx.file.to_string(),
                    line: lit.line,
                    column: lit.column,
                    pattern_id: "CFG-FLAG-003".to_string(),
                    confidence: 0.75,
                    cwe_ids: SmallVec::new(),
                    owasp: None,
                    detection_method: DetectionMethod::AstVisitor,
                    category: PatternCategory::Config,
                    matched_text: format!("Feature flag: {}", lit.value),
                });
            }
        }

        matches
    }
}
