//! RegexSet optimization: ~120 patterns matched in single pass per file.
//!
//! Compiles all allele patterns from all gene extractors into a single RegexSet
//! for efficient single-pass matching across file content.

use regex::RegexSet;
use super::extractor::GeneExtractorRegistry;
use super::types::GeneId;

/// A compiled set of all DNA allele patterns for single-pass matching.
pub struct DnaRegexSet {
    /// The compiled RegexSet.
    regex_set: RegexSet,
    /// Mapping from pattern index to (gene_id, allele_id).
    pattern_map: Vec<(GeneId, String)>,
}

/// Result of a single-pass match against file content.
#[derive(Debug, Clone)]
pub struct DnaMatchResult {
    pub gene_id: GeneId,
    pub allele_id: String,
    pub pattern_index: usize,
}

impl DnaRegexSet {
    /// Build from a gene extractor registry.
    /// Compiles all allele patterns into a single RegexSet.
    pub fn from_registry(registry: &GeneExtractorRegistry) -> Result<Self, regex::Error> {
        let mut patterns = Vec::new();
        let mut pattern_map = Vec::new();

        for extractor in registry.extractors() {
            let gene_id = extractor.gene_id();
            for def in extractor.allele_definitions() {
                for pattern in &def.patterns {
                    patterns.push(pattern.clone());
                    pattern_map.push((gene_id, def.id.clone()));
                }
            }
        }

        let regex_set = RegexSet::new(&patterns)?;

        Ok(Self { regex_set, pattern_map })
    }

    /// Single-pass match: returns all (gene, allele) pairs that match in the content.
    pub fn match_content(&self, content: &str) -> Vec<DnaMatchResult> {
        self.regex_set
            .matches(content)
            .into_iter()
            .map(|idx| DnaMatchResult {
                gene_id: self.pattern_map[idx].0,
                allele_id: self.pattern_map[idx].1.clone(),
                pattern_index: idx,
            })
            .collect()
    }

    /// Check if any pattern matches (fast boolean check).
    pub fn is_match(&self, content: &str) -> bool {
        self.regex_set.is_match(content)
    }

    /// Number of compiled patterns.
    pub fn pattern_count(&self) -> usize {
        self.pattern_map.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dna_regex_set_compiles() {
        let registry = GeneExtractorRegistry::with_all_extractors();
        let set = DnaRegexSet::from_registry(&registry).unwrap();
        // 10 extractors × ~4 alleles × ~2 patterns ≈ ~80-120 patterns
        assert!(set.pattern_count() >= 30,
            "Expected 30+ patterns, got {}", set.pattern_count());
    }

    #[test]
    fn test_dna_regex_set_matches() {
        let registry = GeneExtractorRegistry::with_all_extractors();
        let set = DnaRegexSet::from_registry(&registry).unwrap();

        let content = r#"
            import { cva } from 'class-variance-authority';
            const button = cva('base', { variants: {} });
        "#;

        let matches = set.match_content(content);
        assert!(!matches.is_empty(), "Should match CVA pattern");
        assert!(matches.iter().any(|m| m.gene_id == GeneId::VariantHandling));
    }
}
