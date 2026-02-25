//! Gene extractor framework trait and registry.

use super::types::*;
use rustc_hash::FxHashMap;

/// Trait for gene extractors. Each extractor detects alleles for one gene.
pub trait GeneExtractor: Send + Sync {
    /// The gene this extractor handles.
    fn gene_id(&self) -> GeneId;

    /// Allele definitions this extractor can detect.
    fn allele_definitions(&self) -> Vec<AlleleDefinition>;

    /// Extract alleles from a single file's content.
    fn extract_from_file(&self, content: &str, file_path: &str) -> FileExtractionResult;

    /// Extract alleles from multiple files, compiling regexes ONCE.
    /// Default impl compiles allele_definitions() regexes once and reuses across all files.
    /// ~100x faster than calling extract_from_file() in a loop for large codebases.
    fn extract_batch(&self, files: &[(&str, &str)]) -> Vec<FileExtractionResult> {
        use super::extractors::variant_handling::{compile_definitions, extract_with_precompiled};
        let defs = self.allele_definitions();
        let compiled = compile_definitions(&defs);
        files.iter().map(|(content, path)| {
            extract_with_precompiled(content, path, &defs, &compiled)
        }).collect()
    }

    /// Build a Gene from aggregated file extraction results.
    fn build_gene(&self, results: &[FileExtractionResult]) -> Gene {
        let definitions = self.allele_definitions();
        let gene_id = self.gene_id();

        // Count occurrences per allele across all files
        let mut allele_counts: FxHashMap<String, Vec<&DetectedAllele>> = FxHashMap::default();
        let mut total_detections = 0u32;

        for result in results {
            for detected in &result.detected_alleles {
                allele_counts.entry(detected.allele_id.clone())
                    .or_default()
                    .push(detected);
                total_detections += 1;
            }
        }

        // Build alleles with frequency and examples
        let mut alleles: Vec<Allele> = definitions.iter().filter_map(|def| {
            let detections = allele_counts.get(&def.id)?;
            let count = detections.len() as u32;
            if count == 0 {
                return None;
            }

            let frequency = if total_detections > 0 {
                count as f64 / total_detections as f64
            } else {
                0.0
            };

            // Collect unique files from context (which carries the file path)
            let file_count = detections.iter()
                .filter(|d| !d.context.is_empty())
                .map(|d| d.context.as_str())
                .collect::<std::collections::HashSet<_>>()
                .len() as u32;

            // Up to 5 examples — use context as file path (set by extract_from_file callers)
            let examples: Vec<AlleleExample> = detections.iter()
                .take(5)
                .map(|d| AlleleExample {
                    file: d.context.clone(),
                    line: d.line,
                    code: d.code.clone(),
                    context: d.context.clone(),
                })
                .collect();

            Some(Allele {
                id: def.id.clone(),
                name: def.name.clone(),
                description: def.description.clone(),
                frequency,
                file_count: count.min(file_count.max(count)),
                pattern: def.patterns.join("|"),
                examples,
                is_dominant: false, // Set below
            })
        }).collect();

        // Sort by frequency descending
        alleles.sort_by(|a, b| b.frequency.partial_cmp(&a.frequency).unwrap_or(std::cmp::Ordering::Equal));

        // Mark dominant (highest frequency, must be ≥ 30%)
        let dominant = if let Some(first) = alleles.first_mut() {
            if first.frequency >= 0.3 {
                first.is_dominant = true;
                Some(first.clone())
            } else {
                None
            }
        } else {
            None
        };

        // Confidence = dominant allele frequency
        let confidence = dominant.as_ref().map(|d| d.frequency).unwrap_or(0.0);

        // Consistency = gap between dominant and second
        let consistency = if alleles.len() >= 2 {
            alleles[0].frequency - alleles[1].frequency
        } else if alleles.len() == 1 {
            alleles[0].frequency
        } else {
            0.0
        };

        // Exemplar files (up to 5 from dominant allele)
        let exemplars = dominant.as_ref()
            .map(|d| d.examples.iter().take(5).map(|e| e.file.clone()).collect())
            .unwrap_or_default();

        Gene {
            id: gene_id,
            name: gene_id.name().to_string(),
            description: gene_id.description().to_string(),
            dominant,
            alleles,
            confidence,
            consistency,
            exemplars,
        }
    }
}

/// Registry of all gene extractors.
pub struct GeneExtractorRegistry {
    extractors: Vec<Box<dyn GeneExtractor>>,
}

impl GeneExtractorRegistry {
    pub fn new() -> Self {
        Self { extractors: Vec::new() }
    }

    /// Register a gene extractor.
    pub fn register(&mut self, extractor: Box<dyn GeneExtractor>) {
        self.extractors.push(extractor);
    }

    /// Get all registered extractors.
    pub fn extractors(&self) -> &[Box<dyn GeneExtractor>] {
        &self.extractors
    }

    /// Get extractor for a specific gene.
    pub fn get(&self, gene_id: GeneId) -> Option<&dyn GeneExtractor> {
        self.extractors.iter()
            .find(|e| e.gene_id() == gene_id)
            .map(|e| e.as_ref())
    }

    /// Number of registered extractors.
    pub fn len(&self) -> usize {
        self.extractors.len()
    }

    pub fn is_empty(&self) -> bool {
        self.extractors.is_empty()
    }

    /// Create a registry with all 10 built-in extractors.
    pub fn with_all_extractors() -> Self {
        let mut registry = Self::new();
        for extractor in super::extractors::create_all_extractors() {
            registry.register(extractor);
        }
        registry
    }
}

impl Default for GeneExtractorRegistry {
    fn default() -> Self {
        Self::new()
    }
}
