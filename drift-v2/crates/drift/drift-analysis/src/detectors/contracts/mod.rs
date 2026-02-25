//! Contracts detector — API contracts, interface compliance, type contracts.

use smallvec::SmallVec;

use crate::detectors::traits::{Detector, DetectorCategory, DetectorVariant};
use crate::engine::types::{DetectionMethod, PatternCategory, PatternMatch};
use crate::engine::visitor::DetectionContext;
use crate::parsers::types::ClassKind;

pub struct ContractsDetector;

impl Detector for ContractsDetector {
    fn id(&self) -> &str { "contracts-base" }
    fn category(&self) -> DetectorCategory { DetectorCategory::Contracts }
    fn variant(&self) -> DetectorVariant { DetectorVariant::Base }

    fn detect(&self, ctx: &DetectionContext) -> Vec<PatternMatch> {
        let mut matches = Vec::new();

        // Detect interface definitions (TypeScript interfaces, Java interfaces, Rust traits)
        for class in ctx.classes {
            if class.class_kind == ClassKind::Interface || class.class_kind == ClassKind::Trait {
                matches.push(PatternMatch {
                    file: ctx.file.to_string(),
                    line: class.range.start.line,
                    column: class.range.start.column,
                    pattern_id: "CNTR-IFACE-001".to_string(),
                    confidence: 0.95,
                    cwe_ids: SmallVec::new(),
                    owasp: None,
                    detection_method: DetectionMethod::AstVisitor,
                    category: PatternCategory::Contracts,
                    matched_text: format!("Interface/trait definition: {}", class.name),
                });
            }
        }

        // Detect classes implementing interfaces (contract compliance)
        for class in ctx.classes {
            if !class.implements.is_empty() {
                let ifaces = class.implements.join(", ");
                matches.push(PatternMatch {
                    file: ctx.file.to_string(),
                    line: class.range.start.line,
                    column: class.range.start.column,
                    pattern_id: "CNTR-IMPL-002".to_string(),
                    confidence: 0.90,
                    cwe_ids: SmallVec::new(),
                    owasp: None,
                    detection_method: DetectionMethod::AstVisitor,
                    category: PatternCategory::Contracts,
                    matched_text: format!("{} implements: {}", class.name, ifaces),
                });
            }
        }

        // Detect type alias contracts (TypeAlias class kind)
        for class in ctx.classes {
            if class.class_kind == ClassKind::TypeAlias {
                matches.push(PatternMatch {
                    file: ctx.file.to_string(),
                    line: class.range.start.line,
                    column: class.range.start.column,
                    pattern_id: "CNTR-TYPE-003".to_string(),
                    confidence: 0.80,
                    cwe_ids: SmallVec::new(),
                    owasp: None,
                    detection_method: DetectionMethod::AstVisitor,
                    category: PatternCategory::Contracts,
                    matched_text: format!("Type contract: {}", class.name),
                });
            }
        }

        matches
    }
}
