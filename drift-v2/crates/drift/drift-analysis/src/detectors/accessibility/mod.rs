//! Accessibility detector — ARIA attributes, semantic HTML, a11y patterns.

use smallvec::SmallVec;

use crate::detectors::traits::{Detector, DetectorCategory, DetectorVariant};
use crate::engine::types::{DetectionMethod, PatternCategory, PatternMatch};
use crate::engine::visitor::DetectionContext;
use crate::scanner::language_detect::Language;

pub struct AccessibilityDetector;

impl Detector for AccessibilityDetector {
    fn id(&self) -> &str { "accessibility-base" }
    fn category(&self) -> DetectorCategory { DetectorCategory::Accessibility }
    fn variant(&self) -> DetectorVariant { DetectorVariant::Base }

    fn detect(&self, ctx: &DetectionContext) -> Vec<PatternMatch> {
        // DP-FE-03: Only run for frontend languages
        if !matches!(ctx.language, Language::TypeScript | Language::JavaScript) {
            return Vec::new();
        }

        let mut matches = Vec::new();

        // Detect a11y-related imports (testing-library, axe-core, etc.)
        let a11y_imports = ["@testing-library/jest-dom", "axe-core", "react-aria",
                            "@react-aria", "react-a11y", "eslint-plugin-jsx-a11y",
                            "@radix-ui", "reach/ui", "downshift"];
        for import in ctx.imports {
            let source_lower = import.source.to_lowercase();
            if a11y_imports.iter().any(|ai| source_lower.contains(ai)) {
                matches.push(PatternMatch {
                    file: ctx.file.to_string(),
                    line: import.line,
                    column: 0,
                    pattern_id: "A11Y-IMPORT-001".to_string(),
                    confidence: 0.90,
                    cwe_ids: SmallVec::new(),
                    owasp: None,
                    detection_method: DetectionMethod::AstVisitor,
                    category: PatternCategory::Accessibility,
                    matched_text: format!("A11y library import: {}", import.source),
                });
            }
        }

        // Detect ARIA-related string literals (aria-label, aria-hidden, role, etc.)
        let aria_prefixes = ["aria-", "role="];
        for lit in &ctx.parse_result.string_literals {
            let val_lower = lit.value.to_lowercase();
            if aria_prefixes.iter().any(|p| val_lower.starts_with(p))
                || val_lower == "button"
                || val_lower == "navigation"
                || val_lower == "main"
                || val_lower == "complementary"
                || val_lower == "banner"
                || val_lower == "contentinfo"
            {
                matches.push(PatternMatch {
                    file: ctx.file.to_string(),
                    line: lit.line,
                    column: lit.column,
                    pattern_id: "A11Y-ARIA-002".to_string(),
                    confidence: 0.75,
                    cwe_ids: SmallVec::new(),
                    owasp: None,
                    detection_method: DetectionMethod::AstVisitor,
                    category: PatternCategory::Accessibility,
                    matched_text: format!("ARIA/semantic attribute: {}", lit.value),
                });
            }
        }

        // Detect a11y-related function/hook calls (useAriaLabel, useFocusTrap, etc.)
        let a11y_hooks = ["usefocustrap", "usefocusring", "usearialabel",
                          "usefocusmanager", "usekeyboard", "usepress"];
        for call in ctx.call_sites {
            let callee_lower = call.callee_name.to_lowercase();
            if a11y_hooks.iter().any(|h| callee_lower.contains(h)) {
                matches.push(PatternMatch {
                    file: ctx.file.to_string(),
                    line: call.line,
                    column: call.column,
                    pattern_id: "A11Y-HOOK-003".to_string(),
                    confidence: 0.85,
                    cwe_ids: SmallVec::new(),
                    owasp: None,
                    detection_method: DetectionMethod::AstVisitor,
                    category: PatternCategory::Accessibility,
                    matched_text: format!("A11y hook: {}", call.callee_name),
                });
            }
        }

        matches
    }
}
