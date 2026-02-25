//! 4-phase per-file analysis pipeline.
//!
//! Phase 1: AST pattern detection via single-pass visitor
//! Phase 2: String literal extraction
//! Phase 3: Regex matching on extracted strings
//! Phase 4: Resolution index building

use std::time::Instant;

use crate::parsers::types::ParseResult;

use super::regex_engine::RegexEngine;
use super::resolution::ResolutionIndex;
use super::string_extraction;
use super::types::AnalysisResult;
use super::visitor::{DetectionContext, DetectionEngine};

/// The 4-phase analysis pipeline.
pub struct AnalysisPipeline {
    engine: DetectionEngine,
    regex_engine: RegexEngine,
}

impl AnalysisPipeline {
    /// Create a new pipeline with the given detection engine and regex engine.
    pub fn new(engine: DetectionEngine, regex_engine: RegexEngine) -> Self {
        Self {
            engine,
            regex_engine,
        }
    }

    /// Create with default regex patterns.
    pub fn with_engine(engine: DetectionEngine) -> Self {
        Self {
            engine,
            regex_engine: RegexEngine::new(),
        }
    }

    /// Analyze a single file through all 4 phases.
    pub fn analyze_file(
        &mut self,
        parse_result: &ParseResult,
        source: &[u8],
        tree: &tree_sitter::Tree,
        resolution_index: &mut ResolutionIndex,
    ) -> AnalysisResult {
        let total_start = Instant::now();
        let mut result = AnalysisResult {
            file: parse_result.file.clone(),
            language: parse_result.language,
            ..Default::default()
        };

        // Phase 1: AST pattern detection via single-pass visitor
        let phase1_start = Instant::now();
        let ctx = DetectionContext::from_parse_result(parse_result, source);
        let ast_matches = self.engine.run(tree, source, &ctx);
        result.matches.extend(ast_matches);
        result.phase_times_us[0] = phase1_start.elapsed().as_micros() as u64;

        // Phase 2: String extraction
        let phase2_start = Instant::now();
        let extracted_strings = string_extraction::extract_strings(
            tree,
            source,
            &parse_result.file,
            parse_result.language,
        );
        result.strings_extracted = extracted_strings.len();
        result.phase_times_us[1] = phase2_start.elapsed().as_micros() as u64;

        // Phase 3: Regex matching on extracted strings
        let phase3_start = Instant::now();
        let regex_matches = self.regex_engine.match_strings(&extracted_strings);
        result.regex_matches = regex_matches.len();
        result.matches.extend(regex_matches);
        result.phase_times_us[2] = phase3_start.elapsed().as_micros() as u64;

        // Phase 4: Resolution index building
        let phase4_start = Instant::now();
        resolution_index.index_parse_result(parse_result);
        result.resolution_entries = resolution_index.entries_for_file(&parse_result.file).len();
        result.phase_times_us[3] = phase4_start.elapsed().as_micros() as u64;

        result.analysis_time_us = total_start.elapsed().as_micros() as u64;
        result
    }

    /// Analyze multiple files.
    pub fn analyze_files(
        &mut self,
        parse_results: &[(ParseResult, Vec<u8>, tree_sitter::Tree)],
    ) -> (Vec<AnalysisResult>, ResolutionIndex) {
        let mut resolution_index = ResolutionIndex::new();
        let mut results = Vec::with_capacity(parse_results.len());

        for (parse_result, source, tree) in parse_results {
            let result = self.analyze_file(parse_result, source, tree, &mut resolution_index);
            results.push(result);
        }

        (results, resolution_index)
    }

    /// Get a reference to the detection engine.
    pub fn engine(&self) -> &DetectionEngine {
        &self.engine
    }

    /// Get a mutable reference to the detection engine.
    pub fn engine_mut(&mut self) -> &mut DetectionEngine {
        &mut self.engine
    }

    /// Get a reference to the regex engine.
    pub fn regex_engine(&self) -> &RegexEngine {
        &self.regex_engine
    }
}
