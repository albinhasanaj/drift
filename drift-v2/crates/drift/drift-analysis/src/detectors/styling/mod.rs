//! Styling detector — CSS patterns, styled-components, CSS-in-JS, Tailwind.

use smallvec::SmallVec;

use crate::detectors::traits::{Detector, DetectorCategory, DetectorVariant};
use crate::engine::types::{DetectionMethod, PatternCategory, PatternMatch};
use crate::engine::visitor::DetectionContext;
use crate::scanner::language_detect::Language;

pub struct StylingDetector;

impl Detector for StylingDetector {
    fn id(&self) -> &str { "styling-base" }
    fn category(&self) -> DetectorCategory { DetectorCategory::Styling }
    fn variant(&self) -> DetectorVariant { DetectorVariant::Base }

    fn detect(&self, ctx: &DetectionContext) -> Vec<PatternMatch> {
        // DP-FE-02: Only run for frontend languages
        if !matches!(ctx.language, Language::TypeScript | Language::JavaScript) {
            return Vec::new();
        }

        let mut matches = Vec::new();

        // Detect CSS-in-JS / styling library imports
        let styling_imports = ["styled-components", "@emotion/styled", "@emotion/css",
                               "tailwindcss", "sass", "less", "postcss", "css-modules",
                               "@stitches/react", "vanilla-extract", "linaria",
                               "styled-jsx", "aphrodite", "jss"];
        for import in ctx.imports {
            let source_lower = import.source.to_lowercase();
            if styling_imports.iter().any(|si| source_lower.contains(si)) {
                matches.push(PatternMatch {
                    file: ctx.file.to_string(),
                    line: import.line,
                    column: 0,
                    pattern_id: "STYLE-IMPORT-001".to_string(),
                    confidence: 0.90,
                    cwe_ids: SmallVec::new(),
                    owasp: None,
                    detection_method: DetectionMethod::AstVisitor,
                    category: PatternCategory::Styling,
                    matched_text: format!("Styling library import: {}", import.source),
                });
            }
        }

        // Detect styled-component / CSS-in-JS call patterns
        let styling_callees = ["styled", "css", "classnames", "clsx", "cx", "tw",
                               "createstyles", "makestyles", "usestyles"];
        for call in ctx.call_sites {
            let callee_lower = call.callee_name.to_lowercase();
            if styling_callees.iter().any(|sc| callee_lower == *sc) {
                matches.push(PatternMatch {
                    file: ctx.file.to_string(),
                    line: call.line,
                    column: call.column,
                    pattern_id: "STYLE-CALL-002".to_string(),
                    confidence: 0.85,
                    cwe_ids: SmallVec::new(),
                    owasp: None,
                    detection_method: DetectionMethod::AstVisitor,
                    category: PatternCategory::Styling,
                    matched_text: format!("Styling call: {}", call.callee_name),
                });
            }
        }

        // Detect CSS class name string literals (Tailwind-like patterns)
        for lit in &ctx.parse_result.string_literals {
            let val = &lit.value;
            // Heuristic: strings with multiple space-separated tokens that look like CSS classes
            let tokens: Vec<&str> = val.split_whitespace().collect();
            let looks_like_classes = tokens.len() >= 3
                && tokens.iter().all(|t| {
                    t.chars().all(|c| c.is_alphanumeric() || c == '-' || c == ':' || c == '/' || c == '[' || c == ']' || c == '.')
                });
            if looks_like_classes {
                matches.push(PatternMatch {
                    file: ctx.file.to_string(),
                    line: lit.line,
                    column: lit.column,
                    pattern_id: "STYLE-CLASS-003".to_string(),
                    confidence: 0.65,
                    cwe_ids: SmallVec::new(),
                    owasp: None,
                    detection_method: DetectionMethod::AstVisitor,
                    category: PatternCategory::Styling,
                    matched_text: format!("CSS classes: {}", if val.len() > 50 { &val[..50] } else { val }),
                });
            }
        }

        matches
    }
}
