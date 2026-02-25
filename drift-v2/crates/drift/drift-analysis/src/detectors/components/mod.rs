//! Components detector — React, Vue, Angular, and Svelte component definitions.

use smallvec::SmallVec;

use crate::detectors::traits::{Detector, DetectorCategory, DetectorVariant};
use crate::engine::types::{DetectionMethod, PatternCategory, PatternMatch};
use crate::engine::visitor::DetectionContext;
use crate::scanner::language_detect::Language;

pub struct ComponentsDetector;

impl Detector for ComponentsDetector {
    fn id(&self) -> &str { "components-base" }
    fn category(&self) -> DetectorCategory { DetectorCategory::Components }
    fn variant(&self) -> DetectorVariant { DetectorVariant::Base }

    fn detect(&self, ctx: &DetectionContext) -> Vec<PatternMatch> {
        // DP-FE-01: Only run for frontend-capable languages
        if !matches!(ctx.language, Language::TypeScript | Language::JavaScript | Language::Python) {
            return Vec::new();
        }

        let mut matches = Vec::new();

        // Detect React/Vue/Angular component imports
        let component_frameworks = ["react", "vue", "@angular/core", "svelte", "@angular/component",
                                     "preact", "solid-js", "lit"];
        for import in ctx.imports {
            let source_lower = import.source.to_lowercase();
            if component_frameworks.iter().any(|fw| source_lower.contains(fw)) {
                matches.push(PatternMatch {
                    file: ctx.file.to_string(),
                    line: import.line,
                    column: 0,
                    pattern_id: "COMP-IMPORT-001".to_string(),
                    confidence: 0.90,
                    cwe_ids: SmallVec::new(),
                    owasp: None,
                    detection_method: DetectionMethod::AstVisitor,
                    category: PatternCategory::Components,
                    matched_text: format!("Component framework import: {}", import.source),
                });
            }
        }

        // Detect component class definitions (PascalCase classes extending Component/React.Component)
        for class in ctx.classes {
            let is_component = class.extends.as_deref().is_some_and(|ext| {
                ext.contains("Component") || ext.contains("PureComponent")
                    || ext.contains("LitElement") || ext.contains("HTMLElement")
            });
            let has_component_decorator = class.decorators.iter().any(|d| {
                d.name == "Component" || d.name == "Injectable" || d.name == "Directive"
            });
            if is_component || has_component_decorator {
                matches.push(PatternMatch {
                    file: ctx.file.to_string(),
                    line: class.range.start.line,
                    column: class.range.start.column,
                    pattern_id: "COMP-CLASS-002".to_string(),
                    confidence: 0.95,
                    cwe_ids: SmallVec::new(),
                    owasp: None,
                    detection_method: DetectionMethod::AstVisitor,
                    category: PatternCategory::Components,
                    matched_text: format!("Component class: {}", class.name),
                });
            }
        }

        // Detect functional component patterns (PascalCase functions returning JSX)
        for func in ctx.functions {
            let starts_upper = func.name.chars().next().is_some_and(|c| c.is_uppercase());
            let has_jsx_return = func.return_type.as_deref().is_some_and(|rt| {
                rt.contains("JSX") || rt.contains("ReactElement") || rt.contains("ReactNode")
                    || rt.contains("VNode")
            });
            if starts_upper && has_jsx_return {
                matches.push(PatternMatch {
                    file: ctx.file.to_string(),
                    line: func.line,
                    column: func.column,
                    pattern_id: "COMP-FUNC-003".to_string(),
                    confidence: 0.80,
                    cwe_ids: SmallVec::new(),
                    owasp: None,
                    detection_method: DetectionMethod::AstVisitor,
                    category: PatternCategory::Components,
                    matched_text: format!("Functional component: {}", func.name),
                });
            }
        }

        matches
    }
}
