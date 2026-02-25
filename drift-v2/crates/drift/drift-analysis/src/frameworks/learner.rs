//! Framework learning handler — implements LearningDetectorHandler.
//!
//! Two-pass learning: first pass accumulates pattern frequencies across all files,
//! second pass flags deviations from the dominant convention per group.

use std::collections::HashMap;

use smallvec::SmallVec;

use crate::engine::types::{DetectionMethod, PatternMatch};
use crate::engine::visitor::{DetectionContext, LearningDetectorHandler};
use crate::scanner::language_detect::Language;

use crate::engine::types::PatternCategory;

use super::diagnostics::FrameworkDiagnostics;
use super::loader::CompiledFrameworkPack;
use super::matcher;

/// LearningDetectorHandler that discovers conventions from framework patterns
/// and flags deviations.
pub struct FrameworkLearner {
    /// Compiled framework packs (shared reference data).
    packs: Vec<CompiledFrameworkPack>,
    /// All languages across all packs.
    all_languages: Vec<Language>,
    /// Learning state: group_key → { pattern_id → count }.
    groups: HashMap<String, HashMap<String, u64>>,
    /// Per-file observations: (file, line, pattern_id, group_key).
    observations: Vec<(String, u32, String, String)>,
    /// Detection results after the detect pass.
    results: Vec<PatternMatch>,
    /// File-level presence tracking: group_key → { pattern_id → set of files }.
    file_presence: HashMap<String, HashMap<String, Vec<String>>>,
    /// Co-occurrence tracking: file → set of pattern_ids that matched.
    file_patterns: HashMap<String, Vec<String>>,
}

impl FrameworkLearner {
    /// Create a new learner with the given framework packs.
    pub fn new(packs: Vec<CompiledFrameworkPack>) -> Self {
        let all_languages: Vec<Language> = packs
            .iter()
            .flat_map(|p| p.languages.iter().copied())
            .collect();
        // Dedup without requiring Ord
        let mut seen = Vec::new();
        for lang in all_languages {
            if !seen.contains(&lang) {
                seen.push(lang);
            }
        }
        let all_languages = seen;

        Self {
            packs,
            all_languages,
            groups: HashMap::new(),
            observations: Vec::new(),
            results: Vec::new(),
            file_presence: HashMap::new(),
            file_patterns: HashMap::new(),
        }
    }

    /// Get learning-time diagnostics.
    pub fn learn_diagnostics(&self) -> FrameworkDiagnostics {
        FrameworkDiagnostics {
            learning_groups: self.groups.len(),
            learning_deviations: self.results.len(),
            ..Default::default()
        }
    }
}

impl LearningDetectorHandler for FrameworkLearner {
    fn id(&self) -> &str {
        "framework-learner"
    }

    fn languages(&self) -> &[Language] {
        &self.all_languages
    }

    fn learn(&mut self, ctx: &DetectionContext) {
        for pack in &self.packs {
            if !pack.languages.contains(&ctx.language) {
                continue;
            }

            for pattern in &pack.patterns {
                if !pattern.has_learn {
                    continue;
                }

                // Check language narrowing
                if let Some(lang) = pattern.match_block.language {
                    if lang != ctx.language {
                        continue;
                    }
                }

                // Check if this pattern matches in this file
                let matches = matcher::match_pattern_pub(pattern, ctx);
                if matches.is_empty() {
                    continue;
                }

                // Determine group key based on learn.group_by
                let group_key = compute_group_key(pattern, ctx);

                // Record observations
                for m in &matches {
                    self.observations.push((
                        m.file.clone(),
                        m.line,
                        pattern.id.clone(),
                        group_key.clone(),
                    ));
                }

                // Update frequency counts
                let group = self.groups.entry(group_key.clone()).or_default();
                *group.entry(pattern.id.clone()).or_insert(0) += matches.len() as u64;

                // Track file-level presence
                let presence_group = self.file_presence.entry(group_key).or_default();
                let files = presence_group.entry(pattern.id.clone()).or_default();
                if !files.contains(&ctx.file.to_string()) {
                    files.push(ctx.file.to_string());
                }

                // Track co-occurrence
                let file_pats = self.file_patterns.entry(ctx.file.to_string()).or_default();
                if !file_pats.contains(&pattern.id) {
                    file_pats.push(pattern.id.clone());
                }
            }
        }
    }

    fn detect(&mut self, ctx: &DetectionContext) {
        // Build signal map: pattern_id → signal type
        let signals: HashMap<String, String> = self
            .packs
            .iter()
            .flat_map(|p| p.patterns.iter())
            .filter(|p| p.has_learn)
            .map(|p| {
                (
                    p.id.clone(),
                    p.learn_signal.clone().unwrap_or_else(|| "convention".to_string()),
                )
            })
            .collect();

        // For each group, find the dominant pattern and flag deviations
        let dominant: HashMap<String, (String, f64)> = self
            .groups
            .iter()
            .map(|(group_key, counts)| {
                let total: u64 = counts.values().sum();
                let (dominant_id, dominant_count) = counts
                    .iter()
                    .max_by_key(|(_, &c)| c)
                    .map(|(id, &c)| (id.clone(), c))
                    .unwrap_or_default();
                let ratio = if total > 0 {
                    dominant_count as f64 / total as f64
                } else {
                    0.0
                };
                (group_key.clone(), (dominant_id, ratio))
            })
            .collect();

        // Find deviation threshold per pattern
        let thresholds: HashMap<String, f64> = self
            .packs
            .iter()
            .flat_map(|p| p.patterns.iter())
            .filter(|p| p.has_learn)
            .map(|p| (p.id.clone(), p.learn_deviation_threshold))
            .collect();

        // --- Convention signal (existing logic) ---
        for (file, line, pattern_id, group_key) in &self.observations {
            if file != ctx.file {
                continue;
            }

            let signal = signals.get(pattern_id).map(|s| s.as_str()).unwrap_or("convention");

            match signal {
                "convention" => {
                    if let Some((dominant_id, ratio)) = dominant.get(group_key) {
                        let threshold = thresholds.get(pattern_id).copied().unwrap_or(0.15);
                        if *ratio >= (1.0 - threshold) && pattern_id != dominant_id {
                            let category = find_pattern_category(&self.packs, pattern_id);
                            self.results.push(PatternMatch {
                                file: file.clone(),
                                line: *line,
                                column: 0,
                                pattern_id: format!("{pattern_id}/deviation"),
                                confidence: (*ratio as f32).min(0.95),
                                cwe_ids: SmallVec::new(),
                                owasp: None,
                                detection_method: DetectionMethod::LearningDeviation,
                                category,
                                matched_text: format!(
                                    "Convention deviation: {pattern_id} (dominant: {dominant_id}, {:.0}%)",
                                    ratio * 100.0
                                ),
                            });
                        }
                    }
                }
                "frequency" => {
                    // Flag patterns below the 10th percentile frequency in their group
                    if let Some(counts) = self.groups.get(group_key) {
                        let mut freqs: Vec<u64> = counts.values().copied().collect();
                        freqs.sort();
                        let min_val = freqs.first().copied().unwrap_or(0);
                        let max_val = freqs.last().copied().unwrap_or(0);
                        let p10_idx = (freqs.len() as f64 * 0.1).ceil() as usize;
                        let p10_val = freqs.get(p10_idx.min(freqs.len().saturating_sub(1))).copied().unwrap_or(0);
                        let my_count = counts.get(pattern_id).copied().unwrap_or(0);
                        // Only flag if there's actual variance and this pattern is at the bottom
                        if my_count <= p10_val && min_val < max_val && freqs.len() > 1 {
                            let category = find_pattern_category(&self.packs, pattern_id);
                            self.results.push(PatternMatch {
                                file: file.clone(),
                                line: *line,
                                column: 0,
                                pattern_id: format!("{pattern_id}/rare"),
                                confidence: 0.7,
                                cwe_ids: SmallVec::new(),
                                owasp: None,
                                detection_method: DetectionMethod::LearningDeviation,
                                category,
                                matched_text: format!(
                                    "Rare usage: {pattern_id} (count: {my_count}, 10th percentile: {p10_val})"
                                ),
                            });
                        }
                    }
                }
                "presence" => {
                    // Flag patterns present in <5% of files when group appears in >50%
                    if let Some(presence) = self.file_presence.get(group_key) {
                        let all_files: std::collections::HashSet<&str> = presence
                            .values()
                            .flat_map(|files| files.iter().map(|f| f.as_str()))
                            .collect();
                        let total_files = all_files.len();
                        if total_files > 1 {
                            let my_files = presence.get(pattern_id).map(|f| f.len()).unwrap_or(0);
                            let my_ratio = my_files as f64 / total_files as f64;
                            if my_ratio < 0.05 {
                                let category = find_pattern_category(&self.packs, pattern_id);
                                self.results.push(PatternMatch {
                                    file: file.clone(),
                                    line: *line,
                                    column: 0,
                                    pattern_id: format!("{pattern_id}/rare-presence"),
                                    confidence: 0.65,
                                    cwe_ids: SmallVec::new(),
                                    owasp: None,
                                    detection_method: DetectionMethod::LearningDeviation,
                                    category,
                                    matched_text: format!(
                                        "Rare presence: {pattern_id} in {my_files}/{total_files} files ({:.0}%)",
                                        my_ratio * 100.0
                                    ),
                                });
                            }
                        }
                    }
                }
                "co_occurrence" => {
                    // Flag files where expected co-occurring patterns are missing
                    if let Some(file_pats) = self.file_patterns.get(file.as_str()) {
                        if let Some(counts) = self.groups.get(group_key) {
                            // Patterns that commonly appear in this group
                            let common_patterns: Vec<&String> = counts.keys().collect();
                            let missing: Vec<&String> = common_patterns
                                .iter()
                                .filter(|p| !file_pats.contains(p) && **p != pattern_id)
                                .copied()
                                .collect();
                            if !missing.is_empty() && common_patterns.len() > 1 {
                                let category = find_pattern_category(&self.packs, pattern_id);
                                self.results.push(PatternMatch {
                                    file: file.clone(),
                                    line: *line,
                                    column: 0,
                                    pattern_id: format!("{pattern_id}/missing-co-occurrence"),
                                    confidence: 0.6,
                                    cwe_ids: SmallVec::new(),
                                    owasp: None,
                                    detection_method: DetectionMethod::LearningDeviation,
                                    category,
                                    matched_text: format!(
                                        "Missing co-occurring patterns: {}",
                                        missing.iter().map(|p| p.as_str()).collect::<Vec<_>>().join(", ")
                                    ),
                                });
                            }
                        }
                    }
                }
                other => {
                    eprintln!("[drift] warning: unknown learn signal type '{other}' in pattern {pattern_id}");
                }
            }
        }
    }

    fn results(&self) -> Vec<PatternMatch> {
        self.results.clone()
    }

    fn reset(&mut self) {
        self.results.clear();
        // NOTE: groups and observations persist across files (they're project-wide)
        // They get cleared in the full reset between learn+detect passes via the
        // engine's handler.reset() call before learn starts.
        self.groups.clear();
        self.observations.clear();
        self.file_presence.clear();
        self.file_patterns.clear();
    }
}

/// Helper to find a pattern's category from packs.
fn find_pattern_category(
    packs: &[CompiledFrameworkPack],
    pattern_id: &str,
) -> PatternCategory {
    packs
        .iter()
        .flat_map(|p| p.patterns.iter())
        .find(|p| p.id == pattern_id)
        .map(|p| p.category)
        .unwrap_or_default()
}

/// Compute the group key for learning based on the pattern's learn.group_by directive.
fn compute_group_key(
    pattern: &super::loader::CompiledPattern,
    _ctx: &DetectionContext,
) -> String {
    match pattern.learn_group_by.as_deref() {
        Some("sub_type") => {
            // Group by category + sub_type
            format!(
                "{}:{}",
                pattern.category.name(),
                pattern.sub_type.as_deref().unwrap_or("default")
            )
        }
        Some("pattern_id") => pattern.id.clone(),
        Some("decorator") | Some("call") | Some("function_name") => {
            // Group by category — all patterns in the same category compete
            pattern.category.name().to_string()
        }
        _ => pattern.category.name().to_string(),
    }
}
