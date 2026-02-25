//! Errors detector — error handling patterns, try/catch, Result types.

use smallvec::SmallVec;

use crate::detectors::traits::{Detector, DetectorCategory, DetectorVariant};
use crate::engine::types::{DetectionMethod, PatternCategory, PatternMatch};
use crate::engine::visitor::DetectionContext;
use crate::parsers::types::ErrorHandlingKind;

pub struct ErrorsDetector;

impl Detector for ErrorsDetector {
    fn id(&self) -> &str { "errors-base" }
    fn category(&self) -> DetectorCategory { DetectorCategory::Errors }
    fn variant(&self) -> DetectorVariant { DetectorVariant::Base }

    fn detect(&self, ctx: &DetectionContext) -> Vec<PatternMatch> {
        let mut matches = Vec::new();

        for eh in &ctx.parse_result.error_handling {
            // Detect empty catch blocks
            if !eh.has_body {
                matches.push(PatternMatch {
                    file: ctx.file.to_string(),
                    line: eh.line,
                    column: 0,
                    pattern_id: "ERR-EMPTY-CATCH-001".to_string(),
                    confidence: 0.90,
                    cwe_ids: SmallVec::from_buf([390, 0]),
                    owasp: None,
                    detection_method: DetectionMethod::AstVisitor,
                    category: PatternCategory::Errors,
                    matched_text: "empty catch/except block".to_string(),
                });
            }

            // Detect generic catch-all (no specific type)
            if eh.caught_type.is_none() && matches!(eh.kind, ErrorHandlingKind::TryCatch | ErrorHandlingKind::TryExcept) {
                matches.push(PatternMatch {
                    file: ctx.file.to_string(),
                    line: eh.line,
                    column: 0,
                    pattern_id: "ERR-GENERIC-CATCH-001".to_string(),
                    confidence: 0.70,
                    cwe_ids: SmallVec::from_buf([396, 0]),
                    owasp: None,
                    detection_method: DetectionMethod::AstVisitor,
                    category: PatternCategory::Errors,
                    matched_text: "generic catch-all without specific error type".to_string(),
                });
            }

            // Detect error handling pattern usage
            let pattern_id = match eh.kind {
                ErrorHandlingKind::TryCatch => "ERR-TRY-CATCH-001",
                ErrorHandlingKind::TryExcept => "ERR-TRY-EXCEPT-001",
                ErrorHandlingKind::ResultMatch => "ERR-RESULT-MATCH-001",
                ErrorHandlingKind::QuestionMark => "ERR-QUESTION-MARK-001",
                ErrorHandlingKind::Unwrap => "ERR-UNWRAP-001",
                ErrorHandlingKind::PromiseCatch => "ERR-PROMISE-CATCH-001",
                _ => continue,
            };

            matches.push(PatternMatch {
                file: ctx.file.to_string(),
                line: eh.line,
                column: 0,
                pattern_id: pattern_id.to_string(),
                confidence: 0.85,
                cwe_ids: SmallVec::new(),
                owasp: None,
                detection_method: DetectionMethod::AstVisitor,
                category: PatternCategory::Errors,
                matched_text: format!("{:?} error handling pattern", eh.kind),
            });
        }

        matches
    }
}
