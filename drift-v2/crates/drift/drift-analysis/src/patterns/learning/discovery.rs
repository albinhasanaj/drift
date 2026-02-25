//! Bayesian convention discovery.
//!
//! Discovers conventions from aggregated + scored patterns.
//! Phase D hardening: ConventionStore persistence, Dirichlet-based contested
//! detection, directory/package scope detection, observation tracking.

use crate::patterns::aggregation::types::AggregatedPattern;
use crate::patterns::confidence::types::{ConfidenceScore, ConfidenceTier, MomentumDirection};

use super::dirichlet::DirichletMultinomial;
use super::types::{
    Convention, ConventionCategory, ConventionScope, ConventionStore, LearningConfig,
    LearningDiagnostics, PromotionStatus,
};

/// Discovers conventions from aggregated and scored patterns.
pub struct ConventionDiscoverer {
    config: LearningConfig,
}

impl ConventionDiscoverer {
    /// Create a new discoverer with default configuration.
    pub fn new() -> Self {
        Self {
            config: LearningConfig::default(),
        }
    }

    /// Create a discoverer with custom configuration.
    pub fn with_config(config: LearningConfig) -> Self {
        Self { config }
    }

    /// Discover conventions from aggregated patterns with their confidence scores.
    ///
    /// `patterns`: aggregated patterns from the aggregation pipeline.
    /// `scores`: confidence scores keyed by pattern_id.
    /// `total_files`: total files in the project.
    /// `now`: current unix timestamp.
    pub fn discover(
        &self,
        patterns: &[AggregatedPattern],
        scores: &[(String, ConfidenceScore)],
        total_files: u64,
        now: u64,
    ) -> Vec<Convention> {
        self.discover_with_store(patterns, scores, total_files, now, None)
    }

    /// Discover conventions with optional persistence store.
    ///
    /// PI-LEARN-03: Load existing conventions, update last_seen for existing,
    /// create new for novel patterns, save all at end.
    pub fn discover_with_store(
        &self,
        patterns: &[AggregatedPattern],
        scores: &[(String, ConfidenceScore)],
        total_files: u64,
        now: u64,
        store: Option<&mut dyn ConventionStore>,
    ) -> Vec<Convention> {
        let score_map: std::collections::HashMap<&str, &ConfidenceScore> = scores
            .iter()
            .map(|(id, s)| (id.as_str(), s))
            .collect();

        // Load existing conventions from store
        let existing: std::collections::HashMap<String, Convention> = store
            .as_ref()
            .map(|s| {
                s.load_all()
                    .into_iter()
                    .map(|c| (c.pattern_id.clone(), c))
                    .collect()
            })
            .unwrap_or_default();

        let mut conventions = Vec::new();

        // Group patterns by category to detect contested conventions
        let mut category_groups: std::collections::HashMap<String, Vec<&AggregatedPattern>> =
            std::collections::HashMap::new();
        for pattern in patterns {
            category_groups
                .entry(pattern.category.name().to_string())
                .or_default()
                .push(pattern);
        }

        // Build Dirichlet models per category (PI-LEARN-05/06)
        let dirichlet_models = self.build_dirichlet_models(&category_groups);

        for pattern in patterns {
            // Check minimum thresholds
            if (pattern.location_count as u64) < self.config.min_occurrences {
                continue;
            }
            if (pattern.file_spread as u64) < self.config.min_files {
                continue;
            }

            // Compute dominance ratio within category
            let category_total: u64 = category_groups
                .get(pattern.category.name())
                .map(|group| group.iter().map(|p| p.location_count as u64).sum())
                .unwrap_or(0);

            let dominance = if category_total > 0 {
                pattern.location_count as f64 / category_total as f64
            } else {
                0.0
            };

            if dominance < self.config.dominance_threshold {
                // PI-LEARN-05: Use Dirichlet for contested detection
                let is_contested = self.check_contested_dirichlet(
                    pattern,
                    &dirichlet_models,
                );
                if !is_contested {
                    continue;
                }
            }

            // Get confidence score
            let score = score_map
                .get(pattern.pattern_id.as_str())
                .cloned()
                .cloned()
                .unwrap_or_else(ConfidenceScore::uniform_prior);

            // Classify category (PI-LEARN-06: use Dirichlet dominant)
            let spread_ratio = if total_files > 0 {
                pattern.file_spread as f64 / total_files as f64
            } else {
                0.0
            };

            let category = self.classify_category_dirichlet(
                spread_ratio,
                &score,
                dominance,
                pattern,
                &dirichlet_models,
            );

            // PI-LEARN-09/10: Detect scope
            let scope = self.detect_scope(pattern, total_files);

            // PI-LEARN-03/04: Update existing or create new
            let (discovery_date, observation_count, scan_count, promotion_status) =
                if let Some(existing_conv) = existing.get(&pattern.pattern_id) {
                    (
                        existing_conv.discovery_date,
                        existing_conv.observation_count + pattern.location_count as u64,
                        existing_conv.scan_count + 1,
                        existing_conv.promotion_status,
                    )
                } else {
                    (now, pattern.location_count as u64, 1, PromotionStatus::Discovered)
                };

            conventions.push(Convention {
                id: format!("conv_{}", pattern.pattern_id),
                pattern_id: pattern.pattern_id.clone(),
                category,
                scope,
                confidence_score: score,
                dominance_ratio: dominance,
                discovery_date,
                last_seen: now,
                promotion_status,
                observation_count,
                scan_count,
            });
        }

        // Save all conventions to store
        if let Some(s) = store {
            for conv in &conventions {
                s.save(conv);
            }
        }

        conventions
    }

    /// Compute learning diagnostics from conventions.
    pub fn diagnostics(&self, conventions: &[Convention]) -> LearningDiagnostics {
        LearningDiagnostics::from_conventions(conventions)
    }

    /// Build Dirichlet models per category from pattern groups.
    fn build_dirichlet_models(
        &self,
        category_groups: &std::collections::HashMap<String, Vec<&AggregatedPattern>>,
    ) -> std::collections::HashMap<String, DirichletMultinomial> {
        let mut models = std::collections::HashMap::new();
        for (cat_name, group) in category_groups {
            if group.len() < 2 {
                continue;
            }
            let labels: Vec<String> = group.iter().map(|p| p.pattern_id.clone()).collect();
            let mut dist = DirichletMultinomial::new(labels);
            for (i, p) in group.iter().enumerate() {
                dist.observe_n(i, p.location_count as u64);
            }
            models.insert(cat_name.clone(), dist);
        }
        models
    }

    /// PI-LEARN-06: Classify using Dirichlet dominant posterior.
    fn classify_category_dirichlet(
        &self,
        spread_ratio: f64,
        score: &ConfidenceScore,
        _dominance: f64,
        pattern: &AggregatedPattern,
        dirichlet_models: &std::collections::HashMap<String, DirichletMultinomial>,
    ) -> ConventionCategory {
        // PI-LEARN-05: Check contested via Dirichlet
        if self.check_contested_dirichlet(pattern, dirichlet_models) {
            return ConventionCategory::Contested;
        }

        // Universal: high spread + established confidence
        if spread_ratio >= self.config.universal_spread_threshold
            && score.tier == ConfidenceTier::Established
        {
            return ConventionCategory::Universal;
        }

        // Emerging: rising momentum
        if score.momentum == MomentumDirection::Rising {
            return ConventionCategory::Emerging;
        }

        // Legacy: falling momentum
        if score.momentum == MomentumDirection::Falling {
            return ConventionCategory::Legacy;
        }

        // Default: project-specific
        ConventionCategory::ProjectSpecific
    }

    /// PI-LEARN-05: Check contested using Dirichlet model.
    fn check_contested_dirichlet(
        &self,
        pattern: &AggregatedPattern,
        dirichlet_models: &std::collections::HashMap<String, DirichletMultinomial>,
    ) -> bool {
        if let Some(dist) = dirichlet_models.get(pattern.category.name()) {
            dist.is_contested(self.config.contested_threshold)
        } else {
            false
        }
    }

    /// PI-LEARN-09/10: Detect convention scope.
    fn detect_scope(&self, pattern: &AggregatedPattern, total_files: u64) -> ConventionScope {
        if total_files == 0 || pattern.locations.is_empty() {
            return ConventionScope::Project;
        }

        let global_ratio = pattern.file_spread as f64 / total_files as f64;

        // Only check for sub-scopes if global ratio is low
        if global_ratio >= 0.30 {
            return ConventionScope::Project;
        }

        // Group locations by directory
        let mut dir_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        let mut dir_total_files: std::collections::HashMap<String, std::collections::HashSet<String>> =
            std::collections::HashMap::new();

        for loc in &pattern.locations {
            if let Some(dir) = loc.file.rsplit_once('/').map(|(d, _)| d.to_string()) {
                *dir_counts.entry(dir.clone()).or_insert(0) += 1;
                dir_total_files.entry(dir).or_default().insert(loc.file.clone());
            }
        }

        // Check if concentrated in a single directory (>80% of pattern's locations)
        let pattern_loc_count = pattern.locations.len();
        for (dir, count) in &dir_counts {
            let dir_ratio = *count as f64 / pattern_loc_count as f64;
            if dir_ratio >= 0.80 {
                return ConventionScope::Directory(dir.clone());
            }
        }

        ConventionScope::Project
    }
}

impl Default for ConventionDiscoverer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::types::PatternCategory;
    use crate::patterns::aggregation::types::PatternLocation;

    fn make_pattern(id: &str, locations: u32, files: u32) -> AggregatedPattern {
        make_pattern_with_dir(id, locations, files, "src")
    }

    fn make_pattern_with_dir(id: &str, locations: u32, files: u32, dir: &str) -> AggregatedPattern {
        let locs: Vec<PatternLocation> = (0..locations)
            .map(|i| PatternLocation {
                file: format!("{}/file_{}.ts", dir, i % files),
                line: i + 1,
                column: 0,
                confidence: 0.9,
                is_outlier: false,
                matched_text: None,
            })
            .collect();
        AggregatedPattern {
            pattern_id: id.to_string(),
            category: PatternCategory::Structural,
            location_count: locations,
            outlier_count: 0,
            file_spread: files,
            hierarchy: None,
            locations: locs,
            aliases: Vec::new(),
            merged_from: Vec::new(),
            confidence_mean: 0.9,
            confidence_stddev: 0.05,
            confidence_values: vec![0.9; locations as usize],
            is_dirty: false,
            location_hash: 0,
        }
    }

    #[test]
    fn test_discover_basic_convention() {
        let discoverer = ConventionDiscoverer::new();
        let patterns = vec![make_pattern("dominant", 80, 10)];
        let scores = vec![(
            "dominant".to_string(),
            ConfidenceScore::from_params(90.0, 10.0, MomentumDirection::Stable),
        )];

        let conventions = discoverer.discover(&patterns, &scores, 100, 1000);
        assert_eq!(conventions.len(), 1);
        assert_eq!(conventions[0].pattern_id, "dominant");
    }

    #[test]
    fn test_below_threshold_not_discovered() {
        let discoverer = ConventionDiscoverer::new();
        let patterns = vec![make_pattern("rare", 2, 1)]; // Below min_occurrences and min_files
        let scores = vec![(
            "rare".to_string(),
            ConfidenceScore::uniform_prior(),
        )];

        let conventions = discoverer.discover(&patterns, &scores, 100, 1000);
        assert!(conventions.is_empty());
    }

    #[test]
    fn test_contested_convention() {
        let discoverer = ConventionDiscoverer::new();
        let patterns = vec![
            make_pattern("style_a", 45, 10),
            make_pattern("style_b", 55, 12),
        ];
        let scores = vec![
            ("style_a".to_string(), ConfidenceScore::from_params(10.0, 5.0, MomentumDirection::Stable)),
            ("style_b".to_string(), ConfidenceScore::from_params(12.0, 5.0, MomentumDirection::Stable)),
        ];

        let conventions = discoverer.discover(&patterns, &scores, 100, 1000);
        let contested: Vec<_> = conventions
            .iter()
            .filter(|c| c.category == ConventionCategory::Contested)
            .collect();
        assert!(!contested.is_empty(), "Should detect contested convention");
    }

    // --- PIT-LEARN-01: ConventionStore save/load round-trip ---
    #[test]
    fn test_convention_store_round_trip() {
        use super::super::types::InMemoryConventionStore;
        let mut store = InMemoryConventionStore::new();
        assert!(store.is_empty());

        let discoverer = ConventionDiscoverer::new();
        let patterns = vec![make_pattern("pat_a", 80, 10)];
        let scores = vec![(
            "pat_a".to_string(),
            ConfidenceScore::from_params(90.0, 10.0, MomentumDirection::Stable),
        )];

        let conventions = discoverer.discover_with_store(
            &patterns, &scores, 100, 1000, Some(&mut store),
        );
        assert_eq!(conventions.len(), 1);
        assert_eq!(store.len(), 1);

        // Load back
        let loaded = store.load_by_pattern_id("pat_a");
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().pattern_id, "pat_a");
    }

    // --- PIT-LEARN-02: Existing convention gets last_seen updated ---
    #[test]
    fn test_existing_convention_last_seen_updated() {
        use super::super::types::InMemoryConventionStore;
        let mut store = InMemoryConventionStore::new();
        let discoverer = ConventionDiscoverer::new();
        let patterns = vec![make_pattern("pat_b", 80, 10)];
        let scores = vec![(
            "pat_b".to_string(),
            ConfidenceScore::from_params(90.0, 10.0, MomentumDirection::Stable),
        )];

        // First scan at t=1000
        let _ = discoverer.discover_with_store(
            &patterns, &scores, 100, 1000, Some(&mut store),
        );
        let first = store.load_by_pattern_id("pat_b").unwrap();
        assert_eq!(first.last_seen, 1000);
        assert_eq!(first.discovery_date, 1000);

        // Second scan at t=2000
        let conventions = discoverer.discover_with_store(
            &patterns, &scores, 100, 2000, Some(&mut store),
        );
        assert_eq!(conventions[0].last_seen, 2000);
        assert_eq!(conventions[0].discovery_date, 1000, "Discovery date should be preserved");
    }

    // --- PIT-LEARN-03: New pattern creates new convention ---
    #[test]
    fn test_new_pattern_creates_convention() {
        use super::super::types::InMemoryConventionStore;
        let mut store = InMemoryConventionStore::new();
        let discoverer = ConventionDiscoverer::new();

        // First scan: pat_c
        let patterns1 = vec![make_pattern("pat_c", 80, 10)];
        let scores1 = vec![(
            "pat_c".to_string(),
            ConfidenceScore::from_params(90.0, 10.0, MomentumDirection::Stable),
        )];
        let _ = discoverer.discover_with_store(&patterns1, &scores1, 100, 1000, Some(&mut store));
        assert_eq!(store.len(), 1);

        // Second scan: pat_c + pat_d (new)
        let patterns2 = vec![make_pattern("pat_c", 80, 10), make_pattern("pat_d", 60, 8)];
        let scores2 = vec![
            ("pat_c".to_string(), ConfidenceScore::from_params(90.0, 10.0, MomentumDirection::Stable)),
            ("pat_d".to_string(), ConfidenceScore::from_params(50.0, 10.0, MomentumDirection::Stable)),
        ];
        let conventions = discoverer.discover_with_store(&patterns2, &scores2, 100, 2000, Some(&mut store));
        assert_eq!(conventions.len(), 2);
        assert_eq!(store.len(), 2);
    }

    // --- PIT-LEARN-04: observation_count increments each scan ---
    #[test]
    fn test_observation_count_increments() {
        use super::super::types::InMemoryConventionStore;
        let mut store = InMemoryConventionStore::new();
        let discoverer = ConventionDiscoverer::new();
        let patterns = vec![make_pattern("pat_obs", 20, 5)];
        let scores = vec![(
            "pat_obs".to_string(),
            ConfidenceScore::from_params(90.0, 10.0, MomentumDirection::Stable),
        )];

        // First scan
        let conv1 = discoverer.discover_with_store(&patterns, &scores, 100, 1000, Some(&mut store));
        assert_eq!(conv1[0].observation_count, 20); // 20 locations
        assert_eq!(conv1[0].scan_count, 1);

        // Second scan
        let conv2 = discoverer.discover_with_store(&patterns, &scores, 100, 2000, Some(&mut store));
        assert_eq!(conv2[0].observation_count, 40); // 20 + 20
        assert_eq!(conv2[0].scan_count, 2);
    }

    // --- PIT-LEARN-05: Dirichlet: 3 patterns at ~33% each = contested ---
    #[test]
    fn test_dirichlet_contested_three_way() {
        let discoverer = ConventionDiscoverer::new();
        let patterns = vec![
            make_pattern("style_1", 35, 10),
            make_pattern("style_2", 33, 10),
            make_pattern("style_3", 32, 10),
        ];
        let scores = vec![
            ("style_1".to_string(), ConfidenceScore::from_params(10.0, 5.0, MomentumDirection::Stable)),
            ("style_2".to_string(), ConfidenceScore::from_params(10.0, 5.0, MomentumDirection::Stable)),
            ("style_3".to_string(), ConfidenceScore::from_params(10.0, 5.0, MomentumDirection::Stable)),
        ];

        let conventions = discoverer.discover(&patterns, &scores, 100, 1000);
        let contested: Vec<_> = conventions.iter()
            .filter(|c| c.category == ConventionCategory::Contested)
            .collect();
        assert!(!contested.is_empty(), "Three-way near-equal should be contested via Dirichlet");
    }

    // --- PIT-LEARN-06: Dirichlet: pattern at 80% = Universal ---
    #[test]
    fn test_dirichlet_dominant_universal() {
        let discoverer = ConventionDiscoverer::new();
        let patterns = vec![make_pattern("dominant", 90, 85)];
        let scores = vec![(
            "dominant".to_string(),
            ConfidenceScore::from_params(200.0, 10.0, MomentumDirection::Stable),
        )];

        let conventions = discoverer.discover(&patterns, &scores, 100, 1000);
        assert_eq!(conventions.len(), 1);
        assert_eq!(conventions[0].category, ConventionCategory::Universal);
    }

    // --- PIT-LEARN-07: Promotion with file_spread ---
    #[test]
    fn test_promotion_with_file_spread() {
        use super::super::promotion;
        use super::super::promotion::PromotionConfig;

        let config = PromotionConfig::default(); // min_files = 5

        let conv = Convention {
            id: "conv_test".to_string(),
            pattern_id: "test".to_string(),
            category: ConventionCategory::ProjectSpecific,
            scope: ConventionScope::Project,
            confidence_score: ConfidenceScore::from_params(200.0, 10.0, MomentumDirection::Stable),
            dominance_ratio: 0.8,
            discovery_date: 1000,
            last_seen: 1000,
            promotion_status: PromotionStatus::Discovered,
            observation_count: 100,
            scan_count: 5,
        };

        // 10 files / 100 total + high confidence = promoted
        assert!(promotion::check_promotion(&conv, &config, Some(10)));

        // 2 files / 100 total + high confidence = NOT promoted
        assert!(!promotion::check_promotion(&conv, &config, Some(2)));
    }

    // --- PIT-LEARN-08: promote_batch_with_spread ---
    #[test]
    fn test_promote_batch_with_spread() {
        use super::super::promotion;
        use super::super::promotion::PromotionConfig;

        let config = PromotionConfig::default();
        let mut conventions = vec![
            Convention {
                id: "conv_a".to_string(),
                pattern_id: "a".to_string(),
                category: ConventionCategory::ProjectSpecific,
                scope: ConventionScope::Project,
                confidence_score: ConfidenceScore::from_params(200.0, 10.0, MomentumDirection::Stable),
                dominance_ratio: 0.8,
                discovery_date: 1000,
                last_seen: 1000,
                promotion_status: PromotionStatus::Discovered,
                observation_count: 100,
                scan_count: 5,
            },
            Convention {
                id: "conv_b".to_string(),
                pattern_id: "b".to_string(),
                category: ConventionCategory::ProjectSpecific,
                scope: ConventionScope::Project,
                confidence_score: ConfidenceScore::from_params(200.0, 10.0, MomentumDirection::Stable),
                dominance_ratio: 0.8,
                discovery_date: 1000,
                last_seen: 1000,
                promotion_status: PromotionStatus::Discovered,
                observation_count: 50,
                scan_count: 3,
            },
        ];

        let mut spread_map = std::collections::HashMap::new();
        spread_map.insert("a".to_string(), 10u64); // >= 5, promoted
        spread_map.insert("b".to_string(), 2u64);  // < 5, not promoted

        let promoted = promotion::promote_batch_with_spread(&mut conventions, &config, &spread_map);
        assert_eq!(promoted, 1);
        assert_eq!(conventions[0].promotion_status, PromotionStatus::Approved);
        assert_eq!(conventions[1].promotion_status, PromotionStatus::Discovered);
    }

    // --- PIT-LEARN-09: Directory scope detection ---
    #[test]
    fn test_directory_scope_detection() {
        let discoverer = ConventionDiscoverer::new();
        // 8 locations in src/utils, 8 files, but only 8/100 globally = <30%
        let patterns = vec![make_pattern_with_dir("dir_pat", 8, 8, "src/utils")];
        let scores = vec![(
            "dir_pat".to_string(),
            ConfidenceScore::from_params(90.0, 10.0, MomentumDirection::Stable),
        )];

        let conventions = discoverer.discover(&patterns, &scores, 100, 1000);
        assert_eq!(conventions.len(), 1);
        match &conventions[0].scope {
            ConventionScope::Directory(dir) => assert_eq!(dir, "src/utils"),
            other => panic!("Expected Directory scope, got {:?}", other),
        }
    }

    // --- PIT-LEARN-10: Project scope when global ratio >= 30% ---
    #[test]
    fn test_project_scope_high_spread() {
        let discoverer = ConventionDiscoverer::new();
        // 40 files out of 100 = 40% globally → Project scope
        let patterns = vec![make_pattern("wide_pat", 40, 40)];
        let scores = vec![(
            "wide_pat".to_string(),
            ConfidenceScore::from_params(90.0, 10.0, MomentumDirection::Stable),
        )];

        let conventions = discoverer.discover(&patterns, &scores, 100, 1000);
        assert_eq!(conventions.len(), 1);
        assert_eq!(conventions[0].scope, ConventionScope::Project);
    }

    // --- PIT-LEARN-11: Narrow CI = convergence > 0.8 ---
    #[test]
    fn test_convergence_score_narrow_ci() {
        let conv = Convention {
            id: "conv_narrow".to_string(),
            pattern_id: "narrow".to_string(),
            category: ConventionCategory::Universal,
            scope: ConventionScope::Project,
            confidence_score: ConfidenceScore::from_params(200.0, 10.0, MomentumDirection::Stable),
            dominance_ratio: 0.9,
            discovery_date: 1000,
            last_seen: 2000,
            promotion_status: PromotionStatus::Approved,
            observation_count: 200,
            scan_count: 10,
        };
        let score = conv.convergence_score();
        assert!(score > 0.8, "Narrow CI should give convergence > 0.8, got {}", score);
    }

    // --- PIT-LEARN-12: Diagnostics per-category counts ---
    #[test]
    fn test_diagnostics_per_category() {
        let discoverer = ConventionDiscoverer::new();
        // Single dominant pattern — guaranteed to pass dominance threshold
        let patterns = vec![make_pattern("universal_p", 90, 85)];
        let scores = vec![
            ("universal_p".to_string(), ConfidenceScore::from_params(200.0, 10.0, MomentumDirection::Stable)),
        ];

        let conventions = discoverer.discover(&patterns, &scores, 100, 1000);
        let diag = discoverer.diagnostics(&conventions);
        assert_eq!(diag.total_conventions, 1);
        assert!(diag.per_category.contains_key(&ConventionCategory::Universal),
            "Should have Universal category entry");
        assert_eq!(diag.per_status[&PromotionStatus::Discovered], 1);
    }

    // --- PIT-LEARN-13: Expiry works with persisted conventions ---
    #[test]
    fn test_expiry_with_store() {
        use super::super::types::InMemoryConventionStore;
        use super::super::expiry;

        let mut store = InMemoryConventionStore::new();
        let discoverer = ConventionDiscoverer::new();
        let patterns = vec![make_pattern("expiry_pat", 80, 10)];
        let scores = vec![(
            "expiry_pat".to_string(),
            ConfidenceScore::from_params(90.0, 10.0, MomentumDirection::Stable),
        )];

        // Discover at t=1000
        let mut conventions = discoverer.discover_with_store(
            &patterns, &scores, 100, 1000, Some(&mut store),
        );
        assert_eq!(conventions.len(), 1);

        // Expire at t=1000 + 91 days
        let now = 1000 + 86400 * 91;
        let expired = expiry::process_expiry(&mut conventions, now, 90);
        assert_eq!(expired, 1);
        assert_eq!(conventions[0].promotion_status, PromotionStatus::Expired);
    }

    // --- PIT-LEARN-14: Relearning works with persisted conventions ---
    #[test]
    fn test_relearning_with_store() {
        use super::super::types::InMemoryConventionStore;
        use super::super::relearning;

        let mut store = InMemoryConventionStore::new();
        let discoverer = ConventionDiscoverer::new();
        let patterns = vec![make_pattern("relearn_pat", 80, 10)];
        let scores = vec![(
            "relearn_pat".to_string(),
            ConfidenceScore::from_params(90.0, 10.0, MomentumDirection::Stable),
        )];

        // First scan
        let _ = discoverer.discover_with_store(&patterns, &scores, 100, 1000, Some(&mut store));
        assert_eq!(store.len(), 1);

        // Trigger relearning check
        let mode = relearning::determine_mode(15, 100, 0.10);
        assert_eq!(mode, relearning::LearningMode::Full);

        // Re-discover with store — should update existing
        let conv2 = discoverer.discover_with_store(&patterns, &scores, 100, 2000, Some(&mut store));
        assert_eq!(conv2[0].scan_count, 2);
        assert_eq!(store.len(), 1, "Should update, not duplicate");
    }

    // --- PIT-LEARN-15: All existing learning tests still pass (verified by test suite) ---

    // --- PIT-LEARN-16: Empty store = same results as current behavior ---
    #[test]
    fn test_empty_store_same_as_no_store() {
        use super::super::types::InMemoryConventionStore;

        let discoverer = ConventionDiscoverer::new();
        let patterns = vec![make_pattern("pat_empty", 80, 10)];
        let scores = vec![(
            "pat_empty".to_string(),
            ConfidenceScore::from_params(90.0, 10.0, MomentumDirection::Stable),
        )];

        // Without store
        let conv_no_store = discoverer.discover(&patterns, &scores, 100, 1000);

        // With empty store
        let mut store = InMemoryConventionStore::new();
        let conv_with_store = discoverer.discover_with_store(
            &patterns, &scores, 100, 1000, Some(&mut store),
        );

        assert_eq!(conv_no_store.len(), conv_with_store.len());
        assert_eq!(conv_no_store[0].pattern_id, conv_with_store[0].pattern_id);
        assert_eq!(conv_no_store[0].category, conv_with_store[0].category);
        assert_eq!(conv_no_store[0].observation_count, conv_with_store[0].observation_count);
    }
}
