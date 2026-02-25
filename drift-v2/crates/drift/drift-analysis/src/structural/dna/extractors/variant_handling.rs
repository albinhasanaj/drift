//! Frontend gene: variant-handling — how component variants are managed.
//! Alleles: CVA, clsx/classnames, inline conditionals, CSS modules, styled-components.

use crate::structural::dna::extractor::GeneExtractor;
use crate::structural::dna::types::*;
use regex::Regex;

pub struct VariantHandlingExtractor;

impl GeneExtractor for VariantHandlingExtractor {
    fn gene_id(&self) -> GeneId { GeneId::VariantHandling }

    fn allele_definitions(&self) -> Vec<AlleleDefinition> {
        vec![
            AlleleDefinition {
                id: "cva".into(), name: "CVA (Class Variance Authority)".into(),
                description: "Uses cva() for variant management".into(),
                patterns: vec![r"cva\s*\(".into(), r#"from\s+['"]class-variance-authority['"]"#.into()],
                keywords: vec!["cva".into(), "class-variance-authority".into()],
                import_patterns: vec!["class-variance-authority".into()],
                priority: 10,
            },
            AlleleDefinition {
                id: "clsx".into(), name: "clsx/classnames".into(),
                description: "Uses clsx() or classnames() for conditional classes".into(),
                patterns: vec![r"clsx\s*\(".into(), r"classnames\s*\(".into(), r"cn\s*\(".into()],
                keywords: vec!["clsx".into(), "classnames".into()],
                import_patterns: vec!["clsx".into(), "classnames".into()],
                priority: 8,
            },
            AlleleDefinition {
                id: "inline-conditional".into(), name: "Inline Conditionals".into(),
                description: "Uses ternary operators in className".into(),
                patterns: vec![r"className=\{.*\?.*:".into()],
                keywords: vec![],
                import_patterns: vec![],
                priority: 3,
            },
            AlleleDefinition {
                id: "css-modules".into(), name: "CSS Modules".into(),
                description: "Uses CSS Modules for scoped styling".into(),
                patterns: vec![r"styles\.\w+".into(), r#"from\s+['"].*\.module\.css['"]"#.into()],
                keywords: vec!["module.css".into(), "module.scss".into()],
                import_patterns: vec![".module.css".into(), ".module.scss".into()],
                priority: 7,
            },
            AlleleDefinition {
                id: "styled-components".into(), name: "Styled Components".into(),
                description: "Uses styled-components for variant styling".into(),
                patterns: vec![r"styled\.\w+".into(), r"styled\s*\(".into()],
                keywords: vec!["styled-components".into()],
                import_patterns: vec!["styled-components".into()],
                priority: 7,
            },
        ]
    }

    fn extract_from_file(&self, content: &str, file_path: &str) -> FileExtractionResult {
        extract_with_definitions(content, file_path, &self.allele_definitions())
    }
}

/// Pre-compiled regex patterns for an allele definition set.
/// Compile once per extractor, reuse across all files.
pub(crate) type CompiledDefinitions = Vec<(usize, Vec<Regex>)>;

/// Compile all regex patterns in allele definitions. Call once per extractor.
pub(crate) fn compile_definitions(definitions: &[AlleleDefinition]) -> CompiledDefinitions {
    definitions
        .iter()
        .enumerate()
        .map(|(i, def)| {
            let regexes = def
                .patterns
                .iter()
                .filter_map(|p| Regex::new(p).ok())
                .collect();
            (i, regexes)
        })
        .collect()
}

/// Shared extraction logic used by all gene extractors.
/// Falls back to compiling regexes per call (use extract_with_precompiled for batch).
pub(crate) fn extract_with_definitions(
    content: &str,
    file_path: &str,
    definitions: &[AlleleDefinition],
) -> FileExtractionResult {
    let compiled = compile_definitions(definitions);
    extract_with_precompiled(content, file_path, definitions, &compiled)
}

/// Fast path: uses pre-compiled regexes (no recompilation per file).
pub(crate) fn extract_with_precompiled(
    content: &str,
    file_path: &str,
    definitions: &[AlleleDefinition],
    compiled: &CompiledDefinitions,
) -> FileExtractionResult {
    let mut detected = Vec::new();
    let lines: Vec<&str> = content.lines().collect();

    for (def_idx, regexes) in compiled {
        let def = &definitions[*def_idx];
        for re in regexes {
            for (line_idx, line) in lines.iter().enumerate() {
                if re.is_match(line) {
                    let context = extract_context(&lines, line_idx, 2);
                    detected.push(DetectedAllele {
                        allele_id: def.id.clone(),
                        line: (line_idx + 1) as u32,
                        code: line.trim().to_string(),
                        confidence: 0.8,
                        context,
                    });
                }
            }
        }
    }

    let is_component = is_component_file(file_path, content);

    FileExtractionResult {
        file: file_path.to_string(),
        detected_alleles: detected,
        is_component,
        errors: Vec::new(),
    }
}

/// Check if a file is a component file (frontend).
pub(crate) fn is_component_file(path: &str, content: &str) -> bool {
    let ext_match = path.ends_with(".tsx") || path.ends_with(".jsx")
        || path.ends_with(".vue") || path.ends_with(".svelte");
    if ext_match { return true; }

    // Check for React component exports
    content.contains("export default function")
        || content.contains("export const")
        || content.contains("React.FC")
        || content.contains("React.Component")
}

/// Extract surrounding context lines.
pub(crate) fn extract_context(lines: &[&str], center: usize, radius: usize) -> String {
    let start = center.saturating_sub(radius);
    let end = (center + radius + 1).min(lines.len());
    lines[start..end].join("\n")
}
