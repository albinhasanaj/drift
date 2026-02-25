use cortex_core::errors::CortexResult;
use cortex_core::traits::{ISanitizer, SanitizedText};

use crate::context_scoring::{
    adjust_confidence, has_sensitive_variable_context, is_in_comment, looks_like_placeholder,
    ScoringContext,
};
use crate::degradation::DegradationTracker;
use crate::patterns;

/// Privacy engine that sanitizes text by detecting and replacing PII, secrets,
/// and connection strings with placeholders.
///
/// Implements `ISanitizer` from cortex-core. Context-aware scoring reduces
/// false positives in code. Sanitization is idempotent.
pub struct PrivacyEngine {
    /// Optional file path for context-aware scoring.
    file_path: Option<String>,
}

impl PrivacyEngine {
    /// Create a new PrivacyEngine without file context.
    pub fn new() -> Self {
        Self { file_path: None }
    }

    /// Create a new PrivacyEngine with file path context for scoring adjustments.
    pub fn with_file_path(file_path: impl Into<String>) -> Self {
        Self {
            file_path: Some(file_path.into()),
        }
    }

    /// Set the file path for context-aware scoring.
    pub fn set_file_path(&mut self, path: Option<String>) {
        self.file_path = path;
    }

    /// Sanitize with full degradation tracking. Returns the tracker alongside
    /// the sanitized text so callers can audit any pattern failures.
    pub fn sanitize_with_tracking(
        &self,
        text: &str,
    ) -> CortexResult<(SanitizedText, DegradationTracker)> {
        let mut tracker = DegradationTracker::new();

        // Scan all patterns. Patterns that failed to compile at init time
        // will simply produce no matches (LazyLock<Option<Regex>> = None).
        // We detect those via the degradation tracker.
        self.check_pattern_health(&mut tracker);

        let raw_matches = patterns::scan_all(text);

        // Apply context scoring to each match.
        let mut kept_matches = Vec::new();
        let mut adjusted_confidences = Vec::new();

        for m in &raw_matches {
            let matched_text = &text[m.start..m.end];

            let ctx = ScoringContext {
                file_path: self.file_path.clone(),
                in_comment: is_in_comment(text, m.start),
                is_placeholder: looks_like_placeholder(matched_text),
                sensitive_variable: has_sensitive_variable_context(text, m.start),
            };

            if let Some(adjusted) = adjust_confidence(m.base_confidence, &ctx) {
                kept_matches.push(m.clone());
                adjusted_confidences.push(adjusted);
            }
        }

        // Build redactions list.
        let redactions = patterns::to_redactions(&kept_matches, &adjusted_confidences);

        // Apply replacements from end to start (matches are already sorted desc by start).
        let sanitized = apply_replacements(text, &kept_matches);

        Ok((
            SanitizedText {
                text: sanitized,
                redactions,
            },
            tracker,
        ))
    }

    /// Check which patterns failed to compile and record in the tracker.
    fn check_pattern_health(&self, tracker: &mut DegradationTracker) {
        for pat in patterns::pii::all_patterns() {
            if pat.regex.is_none() {
                tracker.record_failure(pat.name, "pii", "regex compilation failed");
            }
        }
        for pat in patterns::secrets::all_patterns() {
            if pat.regex.is_none() {
                tracker.record_failure(pat.name, "secret", "regex compilation failed");
            }
        }
        for pat in patterns::connection_strings::all_patterns() {
            if pat.regex.is_none() {
                tracker.record_failure(pat.name, "connection_string", "regex compilation failed");
            }
        }
    }
}

impl Default for PrivacyEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ISanitizer for PrivacyEngine {
    fn sanitize(&self, text: &str) -> CortexResult<SanitizedText> {
        let (result, _tracker) = self.sanitize_with_tracking(text)?;
        Ok(result)
    }
}

/// Apply placeholder replacements to the text. Matches must be sorted
/// descending by start position so replacements don't shift earlier offsets.
fn apply_replacements(text: &str, matches: &[patterns::RawMatch]) -> String {
    // E-06: Sort descending by start position so earlier replacements
    // don't shift offsets of later ones.
    let mut sorted: Vec<&patterns::RawMatch> = matches.iter().collect();
    sorted.sort_by(|a, b| b.start.cmp(&a.start));

    let mut result = text.to_string();
    for m in sorted {
        // Guard against already-replaced text (idempotency).
        let current_slice = &result[m.start..m.end.min(result.len())];
        if current_slice.starts_with('[') && current_slice.ends_with(']') {
            continue;
        }
        if m.end <= result.len() {
            result.replace_range(m.start..m.end, &m.placeholder);
        }
    }
    result
}
