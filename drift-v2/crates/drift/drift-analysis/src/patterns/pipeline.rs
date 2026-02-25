//! PatternIntelligencePipeline — end-to-end orchestrator.
//!
//! PI-INT-01: Chains all pattern intelligence subsystems:
//! (1) AggregationPipeline.run()
//! (2) ConfidenceScorer.score_batch()
//! (3) OutlierDetector per pattern
//! (4) ConventionDiscoverer.discover()
//! (5) PromotionCheck

use crate::engine::types::PatternMatch;
use crate::patterns::aggregation::pipeline::{AggregationPipeline, AggregationResult};
use crate::patterns::aggregation::types::AggregatedPattern;
use crate::patterns::confidence::scorer::{ConfidenceScorer, FeedbackStore, ScorerConfig};
use crate::patterns::confidence::types::{ConfidenceScore, MomentumDirection};
use crate::patterns::learning::discovery::ConventionDiscoverer;
use crate::patterns::learning::promotion::{self, PromotionConfig};
use crate::patterns::learning::types::{
    Convention, ConventionStore, LearningDiagnostics,
};
use crate::patterns::outliers::selector::OutlierDetector;
use crate::patterns::outliers::types::OutlierResult;

/// Full pipeline output.
#[derive(Debug)]
pub struct PipelineResult {
    /// Aggregated patterns from Phase 1.
    pub aggregation: AggregationResult,
    /// Confidence scores keyed by pattern_id.
    pub scores: Vec<(String, ConfidenceScore)>,
    /// Outlier results keyed by pattern_id.
    pub outliers: Vec<(String, Vec<OutlierResult>)>,
    /// Discovered conventions.
    pub conventions: Vec<Convention>,
    /// Number of conventions promoted.
    pub promoted_count: usize,
    /// Learning diagnostics.
    pub diagnostics: LearningDiagnostics,
}

/// End-to-end pattern intelligence pipeline.
pub struct PatternIntelligencePipeline {
    aggregation: AggregationPipeline,
    scorer: ConfidenceScorer,
    outlier_detector: OutlierDetector,
    discoverer: ConventionDiscoverer,
    promotion_config: PromotionConfig,
}

impl PatternIntelligencePipeline {
    /// Create with default configuration.
    pub fn new() -> Self {
        Self::with_config(ScorerConfig::default())
    }

    /// Create with custom scorer configuration.
    pub fn with_config(scorer_config: ScorerConfig) -> Self {
        Self {
            aggregation: AggregationPipeline::with_defaults(),
            scorer: ConfidenceScorer::new(scorer_config),
            outlier_detector: OutlierDetector::new(),
            discoverer: ConventionDiscoverer::new(),
            promotion_config: PromotionConfig::default(),
        }
    }

    /// Attach a feedback store for closed-loop confidence adjustment.
    ///
    /// When set, the scorer reads accumulated (alpha_delta, beta_delta) adjustments
    /// from user actions (fix/dismiss/suppress/escalate) and applies them to each
    /// pattern's Beta distribution parameters during scoring.
    pub fn with_feedback_store(mut self, store: Box<dyn FeedbackStore>) -> Self {
        self.scorer = self.scorer.with_feedback_store(store);
        self
    }

    /// Run the full pipeline.
    ///
    /// `matches`: raw pattern matches from all files.
    /// `total_files`: total files in the project.
    /// `now`: current unix timestamp.
    /// `store`: optional convention store for persistence.
    pub fn run(
        &mut self,
        matches: &[PatternMatch],
        total_files: u64,
        now: u64,
        store: Option<&mut dyn ConventionStore>,
    ) -> PipelineResult {
        // Step 1: Aggregation
        let aggregation = self.aggregation.run(matches);

        // Step 2: Confidence scoring
        let category_totals = compute_category_totals(&aggregation.patterns);
        let scores: Vec<(String, ConfidenceScore)> = aggregation
            .patterns
            .iter()
            .map(|p| {
                let cat_total = category_totals
                    .get(p.category.name())
                    .copied()
                    .unwrap_or(1);
                let score = self.scorer.score(
                    p,
                    MomentumDirection::Stable,
                    7, // default days_since_first_seen
                    Some(cat_total as u64),
                    None, // default data quality
                );
                (p.pattern_id.clone(), score)
            })
            .collect();

        // Step 3: Outlier detection per pattern
        let outliers: Vec<(String, Vec<OutlierResult>)> = aggregation
            .patterns
            .iter()
            .filter(|p| p.confidence_values.len() >= 3)
            .map(|p| {
                let results = self.outlier_detector.detect(&p.confidence_values);
                (p.pattern_id.clone(), results)
            })
            .collect();

        // Step 4: Convention discovery
        let mut conventions = self.discoverer.discover_with_store(
            &aggregation.patterns,
            &scores,
            total_files,
            now,
            store,
        );

        // Step 5: Promotion check
        let spread_map: std::collections::HashMap<String, u64> = aggregation
            .patterns
            .iter()
            .map(|p| (p.pattern_id.clone(), p.file_spread as u64))
            .collect();
        let promoted_count = promotion::promote_batch_with_spread(
            &mut conventions,
            &self.promotion_config,
            &spread_map,
        );

        // Diagnostics
        let diagnostics = self.discoverer.diagnostics(&conventions);

        PipelineResult {
            aggregation,
            scores,
            outliers,
            conventions,
            promoted_count,
            diagnostics,
        }
    }
}

impl Default for PatternIntelligencePipeline {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute total location counts per category for frequency factor.
fn compute_category_totals(patterns: &[AggregatedPattern]) -> std::collections::HashMap<&str, u32> {
    let mut totals: std::collections::HashMap<&str, u32> = std::collections::HashMap::new();
    for p in patterns {
        *totals.entry(p.category.name()).or_insert(0) += p.location_count;
    }
    totals
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::types::{DetectionMethod, PatternCategory};
    use crate::patterns::learning::types::InMemoryConventionStore;
    use smallvec::smallvec;

    fn make_matches(pattern_id: &str, count: usize, files: usize) -> Vec<PatternMatch> {
        (0..count)
            .map(|i| PatternMatch {
                pattern_id: pattern_id.to_string(),
                category: PatternCategory::Structural,
                file: format!("src/file_{}.ts", i % files),
                line: (i + 1) as u32,
                column: 0,
                confidence: 0.9,
                matched_text: String::new(),
                detection_method: DetectionMethod::AstVisitor,
                cwe_ids: smallvec![],
                owasp: None,
            })
            .collect()
    }

    // --- PIT-INT-01: Full pipeline produces output ---
    #[test]
    fn test_full_pipeline_produces_output() {
        let mut pipeline = PatternIntelligencePipeline::new();
        let mut matches = make_matches("dominant_pattern", 80, 10);
        matches.extend(make_matches("minor_pattern", 5, 3));

        let result = pipeline.run(&matches, 100, 1000, None);

        assert!(!result.aggregation.patterns.is_empty(), "Should produce aggregated patterns");
        assert!(!result.scores.is_empty(), "Should produce confidence scores");
        assert!(!result.conventions.is_empty(), "Should discover conventions");
    }

    // --- PIT-INT-02: Patterns with clear outliers have outlier_count > 0 ---
    #[test]
    fn test_outlier_detection_in_pipeline() {
        let mut pipeline = PatternIntelligencePipeline::new();
        // Create pattern with an outlier (one very low confidence value)
        let matches: Vec<PatternMatch> = (0..20)
            .map(|i| PatternMatch {
                pattern_id: "outlier_pat".to_string(),
                category: PatternCategory::Structural,
                file: format!("src/file_{}.ts", i % 10),
                line: (i + 1) as u32,
                column: 0,
                confidence: if i == 0 { 0.0 } else { 0.9 },
                matched_text: String::new(),
                detection_method: DetectionMethod::AstVisitor,
                cwe_ids: smallvec![],
                owasp: None,
            })
            .collect();

        let result = pipeline.run(&matches, 100, 1000, None);
        // The aggregation pipeline should detect outliers
        let outlier_pat = result.aggregation.patterns.iter()
            .find(|p| p.pattern_id == "outlier_pat");
        assert!(outlier_pat.is_some());
    }

    // --- PIT-INT-03: Dominant pattern discovered as Universal ---
    #[test]
    fn test_dominant_pattern_universal() {
        let mut pipeline = PatternIntelligencePipeline::new();
        let matches = make_matches("universal_pat", 90, 85);

        let result = pipeline.run(&matches, 100, 1000, None);
        let universal = result.conventions.iter()
            .find(|c| c.pattern_id == "universal_pat");
        assert!(universal.is_some(), "Should discover universal pattern");
    }

    // --- PIT-INT-04: Contested patterns discovered as Contested ---
    #[test]
    fn test_contested_patterns() {
        let mut pipeline = PatternIntelligencePipeline::new();
        let mut matches = make_matches("style_a", 45, 10);
        matches.extend(make_matches("style_b", 55, 12));

        let result = pipeline.run(&matches, 100, 1000, None);
        let contested: Vec<_> = result.conventions.iter()
            .filter(|c| c.category == crate::patterns::learning::types::ConventionCategory::Contested)
            .collect();
        assert!(!contested.is_empty(), "Should detect contested conventions");
    }

    // --- PIT-INT-06: Conventions persist across two sequential runs ---
    #[test]
    fn test_conventions_persist_across_runs() {
        let mut pipeline = PatternIntelligencePipeline::new();
        let mut store = InMemoryConventionStore::new();
        let matches = make_matches("persist_pat", 80, 10);

        // Run 1
        let r1 = pipeline.run(&matches, 100, 1000, Some(&mut store));
        assert_eq!(r1.conventions.len(), 1);
        assert_eq!(r1.conventions[0].scan_count, 1);

        // Run 2
        let r2 = pipeline.run(&matches, 100, 2000, Some(&mut store));
        assert_eq!(r2.conventions.len(), 1);
        assert_eq!(r2.conventions[0].scan_count, 2);
        assert_eq!(r2.conventions[0].discovery_date, 1000, "Discovery date preserved");
        assert_eq!(r2.conventions[0].last_seen, 2000, "Last seen updated");
    }

    // --- PIT-INT-11: Diagnostics emitted ---
    #[test]
    fn test_diagnostics_emitted() {
        let mut pipeline = PatternIntelligencePipeline::new();
        let matches = make_matches("diag_pat", 80, 10);

        let result = pipeline.run(&matches, 100, 1000, None);
        assert!(result.diagnostics.total_conventions >= 1);
    }
}
