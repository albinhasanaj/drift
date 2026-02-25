//! Documentation detector — doc comments, JSDoc, docstrings, inline documentation.

use smallvec::SmallVec;

use crate::detectors::traits::{Detector, DetectorCategory, DetectorVariant};
use crate::engine::types::{DetectionMethod, PatternCategory, PatternMatch};
use crate::engine::visitor::DetectionContext;

pub struct DocumentationDetector;

impl Detector for DocumentationDetector {
    fn id(&self) -> &str { "documentation-base" }
    fn category(&self) -> DetectorCategory { DetectorCategory::Documentation }
    fn variant(&self) -> DetectorVariant { DetectorVariant::Base }

    fn detect(&self, ctx: &DetectionContext) -> Vec<PatternMatch> {
        let mut matches = Vec::new();

        // Detect doc comments from the parse result
        for doc in &ctx.parse_result.doc_comments {
            matches.push(PatternMatch {
                file: ctx.file.to_string(),
                line: doc.line,
                column: 0,
                pattern_id: "DOC-COMMENT-001".to_string(),
                confidence: 0.95,
                cwe_ids: SmallVec::new(),
                owasp: None,
                detection_method: DetectionMethod::AstVisitor,
                category: PatternCategory::Documentation,
                matched_text: format!("Doc comment ({:?}): {}",
                    doc.style,
                    if doc.text.len() > 60 { &doc.text[..60] } else { &doc.text }
                ),
            });
        }

        // Detect functions with doc comments attached
        for func in ctx.functions {
            if func.doc_comment.is_some() {
                matches.push(PatternMatch {
                    file: ctx.file.to_string(),
                    line: func.line,
                    column: func.column,
                    pattern_id: "DOC-FUNC-002".to_string(),
                    confidence: 0.90,
                    cwe_ids: SmallVec::new(),
                    owasp: None,
                    detection_method: DetectionMethod::AstVisitor,
                    category: PatternCategory::Documentation,
                    matched_text: format!("Documented function: {}", func.name),
                });
            }
        }

        // Detect exported functions missing documentation
        for func in ctx.functions {
            if func.is_exported && func.doc_comment.is_none() {
                matches.push(PatternMatch {
                    file: ctx.file.to_string(),
                    line: func.line,
                    column: func.column,
                    pattern_id: "DOC-MISSING-003".to_string(),
                    confidence: 0.70,
                    cwe_ids: SmallVec::new(),
                    owasp: None,
                    detection_method: DetectionMethod::AstVisitor,
                    category: PatternCategory::Documentation,
                    matched_text: format!("Undocumented exported function: {}", func.name),
                });
            }
        }

        matches
    }
}
