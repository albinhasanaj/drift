pub mod connection_strings;
pub mod pii;
pub mod secrets;

use cortex_core::traits::Redaction;
use regex::Regex;
use std::sync::LazyLock;

/// Unified pattern match result before context scoring.
#[derive(Debug, Clone)]
pub struct RawMatch {
    pub category: String,
    pub pattern_name: String,
    pub placeholder: String,
    pub start: usize,
    pub end: usize,
    pub base_confidence: f64,
}

/// Run all pattern categories against the input text, returning raw matches
/// sorted by start position (descending) for safe replacement.
pub fn scan_all(text: &str) -> Vec<RawMatch> {
    let mut matches = Vec::new();

    // Connection strings FIRST — they contain user:pass@host which looks like email
    for pat in connection_strings::all_patterns() {
        collect_matches(
            text,
            pat.regex,
            "connection_string",
            pat.name,
            pat.placeholder,
            pat.base_confidence,
            &mut matches,
        );
    }

    // Secret patterns SECOND — they're more specific than PII
    for pat in secrets::all_patterns() {
        collect_matches(
            text,
            pat.regex,
            "secret",
            pat.name,
            pat.placeholder,
            pat.base_confidence,
            &mut matches,
        );
    }

    // PII patterns LAST — broadest patterns
    for pat in pii::all_patterns() {
        collect_matches(
            text,
            pat.regex,
            "pii",
            pat.name,
            pat.placeholder,
            pat.base_confidence,
            &mut matches,
        );
    }

    // Sort by start position descending so we can replace from the end
    // without invalidating earlier offsets.
    matches.sort_by(|a, b| b.start.cmp(&a.start));

    // Deduplicate overlapping matches — keep the one with higher confidence.
    dedup_overlapping(&mut matches);

    matches
}

fn collect_matches(
    text: &str,
    regex: &LazyLock<Option<Regex>>,
    category: &str,
    name: &str,
    placeholder: &str,
    base_confidence: f64,
    out: &mut Vec<RawMatch>,
) {
    let Some(re) = regex.as_ref() else { return };
    for m in re.find_iter(text) {
        out.push(RawMatch {
            category: category.to_string(),
            pattern_name: name.to_string(),
            placeholder: placeholder.to_string(),
            start: m.start(),
            end: m.end(),
            base_confidence,
        });
    }
}

/// Remove overlapping matches, keeping the longer (more specific) one,
/// or the higher-confidence one if lengths are equal.
fn dedup_overlapping(matches: &mut Vec<RawMatch>) {
    let mut i = 0;
    while i + 1 < matches.len() {
        let current_start = matches[i].start;
        let current_end = matches[i].end;
        let current_len = current_end - current_start;
        let current_conf = matches[i].base_confidence;

        let next_start = matches[i + 1].start;
        let next_end = matches[i + 1].end;
        let next_len = next_end - next_start;
        let next_conf = matches[i + 1].base_confidence;

        // Check overlap: since sorted desc by start, next.start <= current.start
        if next_end > current_start {
            // Prefer longer match (more specific), then higher confidence
            if next_len > current_len || (next_len == current_len && next_conf > current_conf) {
                matches.remove(i);
            } else {
                matches.remove(i + 1);
            }
        } else {
            i += 1;
        }
    }
}

/// Convert raw matches to Redaction structs (for the trait return type).
pub fn to_redactions(matches: &[RawMatch], adjusted_confidences: &[f64]) -> Vec<Redaction> {
    matches
        .iter()
        .zip(adjusted_confidences.iter())
        .map(|(m, &conf)| Redaction {
            category: format!("{}:{}", m.category, m.pattern_name),
            placeholder: m.placeholder.clone(),
            start: m.start,
            end: m.end,
            confidence: conf,
        })
        .collect()
}
