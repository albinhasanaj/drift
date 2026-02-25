//! Structural detector — naming conventions, file organization, module patterns.

use smallvec::SmallVec;

use crate::detectors::traits::{Detector, DetectorCategory, DetectorVariant};
use crate::engine::types::{DetectionMethod, PatternCategory, PatternMatch};
use crate::engine::visitor::DetectionContext;

pub struct StructuralDetector;

impl Detector for StructuralDetector {
    fn id(&self) -> &str { "structural-base" }
    fn category(&self) -> DetectorCategory { DetectorCategory::Structural }
    fn variant(&self) -> DetectorVariant { DetectorVariant::Base }

    fn detect(&self, ctx: &DetectionContext) -> Vec<PatternMatch> {
        let mut matches = Vec::new();

        // Detect naming convention patterns
        for func in ctx.functions {
            let convention = detect_naming_convention(&func.name);
            matches.push(PatternMatch {
                file: ctx.file.to_string(),
                line: func.line,
                column: func.column,
                pattern_id: format!("STRUCT-NAMING-{}", convention),
                confidence: 0.90,
                cwe_ids: SmallVec::new(),
                owasp: None,
                detection_method: DetectionMethod::AstVisitor,
                category: PatternCategory::Structural,
                matched_text: format!("{}: {} naming", func.name, convention),
            });
        }

        // Detect class naming conventions
        for class in ctx.classes {
            if !class.name.is_empty() && class.name.chars().next().is_some_and(|c| c.is_uppercase()) {
                matches.push(PatternMatch {
                    file: ctx.file.to_string(),
                    line: class.range.start.line,
                    column: class.range.start.column,
                    pattern_id: "STRUCT-CLASS-PASCAL".to_string(),
                    confidence: 0.95,
                    cwe_ids: SmallVec::new(),
                    owasp: None,
                    detection_method: DetectionMethod::AstVisitor,
                    category: PatternCategory::Structural,
                    matched_text: format!("PascalCase class: {}", class.name),
                });
            }
        }

        // Detect export patterns
        let export_count = ctx.exports.len();
        if export_count > 0 {
            matches.push(PatternMatch {
                file: ctx.file.to_string(),
                line: 0,
                column: 0,
                pattern_id: "STRUCT-EXPORTS".to_string(),
                confidence: 0.80,
                cwe_ids: SmallVec::new(),
                owasp: None,
                detection_method: DetectionMethod::AstVisitor,
                category: PatternCategory::Structural,
                matched_text: format!("{} exports", export_count),
            });
        }

        matches
    }
}

fn detect_naming_convention(name: &str) -> &'static str {
    if name.contains('_') && name == name.to_lowercase() {
        "snake_case"
    } else if name.chars().next().is_some_and(|c| c.is_uppercase()) {
        "PascalCase"
    } else if name.chars().any(|c| c.is_uppercase()) {
        "camelCase"
    } else {
        "lowercase"
    }
}
