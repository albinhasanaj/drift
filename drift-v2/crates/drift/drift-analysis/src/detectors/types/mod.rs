//! Types detector — type annotations, generics, type narrowing, type safety.

use smallvec::SmallVec;

use crate::detectors::traits::{Detector, DetectorCategory, DetectorVariant};
use crate::engine::types::{DetectionMethod, PatternCategory, PatternMatch};
use crate::engine::visitor::DetectionContext;

pub struct TypesDetector;

impl Detector for TypesDetector {
    fn id(&self) -> &str { "types-base" }
    fn category(&self) -> DetectorCategory { DetectorCategory::Types }
    fn variant(&self) -> DetectorVariant { DetectorVariant::Base }

    fn detect(&self, ctx: &DetectionContext) -> Vec<PatternMatch> {
        let mut matches = Vec::new();

        // Detect functions with return type annotations
        for func in ctx.functions {
            if let Some(ref rt) = func.return_type {
                matches.push(PatternMatch {
                    file: ctx.file.to_string(),
                    line: func.line,
                    column: func.column,
                    pattern_id: "TYPE-RETURN-001".to_string(),
                    confidence: 0.90,
                    cwe_ids: SmallVec::new(),
                    owasp: None,
                    detection_method: DetectionMethod::AstVisitor,
                    category: PatternCategory::Types,
                    matched_text: format!("{} returns: {}", func.name, rt),
                });
            }
        }

        // Detect functions with typed parameters
        for func in ctx.functions {
            let typed_params: Vec<_> = func.parameters.iter()
                .filter(|p| p.type_annotation.is_some())
                .collect();
            let total_params = func.parameters.len();
            if total_params > 0 {
                let coverage = typed_params.len() as f32 / total_params as f32;
                matches.push(PatternMatch {
                    file: ctx.file.to_string(),
                    line: func.line,
                    column: func.column,
                    pattern_id: "TYPE-PARAM-002".to_string(),
                    confidence: coverage,
                    cwe_ids: SmallVec::new(),
                    owasp: None,
                    detection_method: DetectionMethod::AstVisitor,
                    category: PatternCategory::Types,
                    matched_text: format!(
                        "{}: {}/{} params typed",
                        func.name, typed_params.len(), total_params
                    ),
                });
            }
        }

        // Detect generic type parameters on functions and classes
        for func in ctx.functions {
            if !func.generic_params.is_empty() {
                let generics: Vec<_> = func.generic_params.iter()
                    .map(|g| g.name.as_str())
                    .collect();
                matches.push(PatternMatch {
                    file: ctx.file.to_string(),
                    line: func.line,
                    column: func.column,
                    pattern_id: "TYPE-GENERIC-003".to_string(),
                    confidence: 0.90,
                    cwe_ids: SmallVec::new(),
                    owasp: None,
                    detection_method: DetectionMethod::AstVisitor,
                    category: PatternCategory::Types,
                    matched_text: format!("Generic function {}<{}>", func.name, generics.join(", ")),
                });
            }
        }

        for class in ctx.classes {
            if !class.generic_params.is_empty() {
                let generics: Vec<_> = class.generic_params.iter()
                    .map(|g| g.name.as_str())
                    .collect();
                matches.push(PatternMatch {
                    file: ctx.file.to_string(),
                    line: class.range.start.line,
                    column: class.range.start.column,
                    pattern_id: "TYPE-GENERIC-003".to_string(),
                    confidence: 0.90,
                    cwe_ids: SmallVec::new(),
                    owasp: None,
                    detection_method: DetectionMethod::AstVisitor,
                    category: PatternCategory::Types,
                    matched_text: format!("Generic class {}<{}>", class.name, generics.join(", ")),
                });
            }
        }

        matches
    }
}
