//! Frontend gene: animation-approach — how animations and transitions are implemented.

use crate::structural::dna::extractor::GeneExtractor;
use crate::structural::dna::types::*;
use super::variant_handling::extract_with_definitions;

pub struct AnimationExtractor;

impl GeneExtractor for AnimationExtractor {
    fn gene_id(&self) -> GeneId { GeneId::AnimationApproach }

    fn allele_definitions(&self) -> Vec<AlleleDefinition> {
        vec![
            AlleleDefinition {
                id: "framer-motion".into(), name: "Framer Motion".into(),
                description: "Uses Framer Motion for animations".into(),
                patterns: vec![r"motion\.\w+".into(), r"useAnimate".into(), r"AnimatePresence".into()],
                keywords: vec!["framer-motion".into()],
                import_patterns: vec!["framer-motion".into()],
                priority: 10,
            },
            AlleleDefinition {
                id: "css-transitions".into(), name: "CSS Transitions".into(),
                description: "Uses CSS transitions for animations".into(),
                patterns: vec![r"transition(?:-(?:property|duration|timing|delay))?\s*:".into()],
                keywords: vec!["transition".into()],
                import_patterns: vec![], priority: 5,
            },
            AlleleDefinition {
                id: "css-animations".into(), name: "CSS @keyframes".into(),
                description: "Uses CSS @keyframes animations".into(),
                patterns: vec![r"@keyframes\s+\w+".into(), r"animation(?:-name)?\s*:".into()],
                keywords: vec!["@keyframes".into()],
                import_patterns: vec![], priority: 6,
            },
            AlleleDefinition {
                id: "tailwind-animate".into(), name: "Tailwind Animate".into(),
                description: "Uses Tailwind animation utilities".into(),
                patterns: vec![r"\banimate-(?:spin|ping|pulse|bounce|fade|slide)".into()],
                keywords: vec!["animate-".into()],
                import_patterns: vec![], priority: 8,
            },
            AlleleDefinition {
                id: "react-spring".into(), name: "React Spring".into(),
                description: "Uses React Spring for physics-based animations".into(),
                patterns: vec![r"useSpring".into(), r"useTrail".into(), r"useSprings".into()],
                keywords: vec!["react-spring".into()],
                import_patterns: vec!["@react-spring".into()],
                priority: 9,
            },
        ]
    }

    fn extract_from_file(&self, content: &str, file_path: &str) -> FileExtractionResult {
        extract_with_definitions(content, file_path, &self.allele_definitions())
    }
}
