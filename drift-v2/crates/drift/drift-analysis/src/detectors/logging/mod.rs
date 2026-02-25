//! Logging detector — console.log, logger frameworks, log levels, structured logging.

use smallvec::SmallVec;

use crate::detectors::traits::{Detector, DetectorCategory, DetectorVariant};
use crate::engine::types::{DetectionMethod, PatternCategory, PatternMatch};
use crate::engine::visitor::DetectionContext;

pub struct LoggingDetector;

impl Detector for LoggingDetector {
    fn id(&self) -> &str { "logging-base" }
    fn category(&self) -> DetectorCategory { DetectorCategory::Logging }
    fn variant(&self) -> DetectorVariant { DetectorVariant::Base }

    fn detect(&self, ctx: &DetectionContext) -> Vec<PatternMatch> {
        let mut matches = Vec::new();

        // Detect console/logger call sites (console.log, logger.info, log.warn, etc.)
        let log_receivers = ["console", "logger", "log", "logging", "winston", "bunyan",
                             "pino", "log4j", "slf4j", "spdlog",
                             // Go
                             "slog", "zap", "logrus",
                             // Rust
                             "tracing", "env_logger",
                             // Ruby
                             "Logger", "Rails.logger",
                             // C#
                             "_logger", "Logger", "Log",
                             // PHP
                             "Log",
                             // Kotlin
                             "Timber",
        ];
        let log_methods = ["log", "info", "warn", "error", "debug", "trace", "fatal",
                           "verbose"];
        for call in ctx.call_sites {
            let callee_lower = call.callee_name.to_lowercase();
            let receiver_lower = call.receiver.as_deref().unwrap_or("").to_lowercase();
            if log_receivers.iter().any(|r| receiver_lower == *r)
                && log_methods.contains(&callee_lower.as_str())
            {
                matches.push(PatternMatch {
                    file: ctx.file.to_string(),
                    line: call.line,
                    column: call.column,
                    pattern_id: "LOG-CALL-001".to_string(),
                    confidence: 0.90,
                    cwe_ids: SmallVec::new(),
                    owasp: None,
                    detection_method: DetectionMethod::AstVisitor,
                    category: PatternCategory::Logging,
                    matched_text: format!("Logging call: {}.{}", receiver_lower, call.callee_name),
                });
            }
        }

        // Detect logging framework imports (winston, bunyan, pino, log4j, etc.)
        let logging_imports = [
            // JS/TS
            "winston", "bunyan", "pino", "morgan", "log4js",
            "loglevel", "debug", "signale", "tslog", "roarr",
            // Python
            "loguru", "structlog",
            // Java/Kotlin
            "org.slf4j", "org.apache.logging.log4j", "java.util.logging", "ch.qos.logback",
            "timber",
            // Go
            "go.uber.org/zap", "github.com/sirupsen/logrus", "log/slog",
            // Rust
            "tracing", "env_logger", "log", "slog", "flexi_logger",
            // Ruby
            "logger", "semantic_logger",
            // PHP
            "monolog/monolog", "psr/log",
            // C#
            "Serilog", "NLog", "Microsoft.Extensions.Logging",
        ];
        for import in ctx.imports {
            let source_lower = import.source.to_lowercase();
            if logging_imports.iter().any(|li| source_lower == *li) {
                matches.push(PatternMatch {
                    file: ctx.file.to_string(),
                    line: import.line,
                    column: 0,
                    pattern_id: "LOG-IMPORT-002".to_string(),
                    confidence: 0.90,
                    cwe_ids: SmallVec::new(),
                    owasp: None,
                    detection_method: DetectionMethod::AstVisitor,
                    category: PatternCategory::Logging,
                    matched_text: format!("Logging library import: {}", import.source),
                });
            }
        }

        // Detect bare print/println calls (often debug leftovers)
        let bare_print_calls = ["print", "println", "printf", "puts", "console_log",
                                "print_r", "var_dump", "pp",
                                // Go
                                "fmt.Println", "fmt.Printf", "fmt.Print",
                                // Rust
                                "println!", "eprintln!", "dbg!",
                                // Python
                                "pprint",
                                // Kotlin
                                "println",
                                // PHP
                                "echo", "var_export", "error_log",
        ];
        for call in ctx.call_sites {
            let callee_lower = call.callee_name.to_lowercase();
            if bare_print_calls.contains(&callee_lower.as_str()) && call.receiver.is_none() {
                matches.push(PatternMatch {
                    file: ctx.file.to_string(),
                    line: call.line,
                    column: call.column,
                    pattern_id: "LOG-PRINT-003".to_string(),
                    confidence: 0.70,
                    cwe_ids: SmallVec::new(),
                    owasp: None,
                    detection_method: DetectionMethod::AstVisitor,
                    category: PatternCategory::Logging,
                    matched_text: format!("Bare print call: {}", call.callee_name),
                });
            }
        }

        matches
    }
}
