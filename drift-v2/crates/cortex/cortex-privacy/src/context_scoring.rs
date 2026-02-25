//! Context-aware confidence adjustment for privacy pattern matches.
//!
//! Adjusts the base confidence of a detected pattern based on the surrounding
//! context to reduce false positives in code.

/// Context signals that can adjust pattern confidence.
#[derive(Debug, Clone, Default)]
pub struct ScoringContext {
    /// File path (if known) — used for test file / .env detection.
    pub file_path: Option<String>,
    /// Whether the match is inside a code comment.
    pub in_comment: bool,
    /// Whether the match appears to be a placeholder (e.g., "example@example.com").
    pub is_placeholder: bool,
    /// Whether the match is assigned to a variable with a sensitive name.
    pub sensitive_variable: bool,
}

/// Confidence adjustment table per the spec.
const TEST_FILE_ADJUSTMENT: f64 = -0.20;
const COMMENT_ADJUSTMENT: f64 = -0.30;
const ENV_FILE_ADJUSTMENT: f64 = 0.10;
const SENSITIVE_VAR_ADJUSTMENT: f64 = 0.10;

/// Minimum confidence threshold — matches below this are dropped.
pub const MIN_CONFIDENCE_THRESHOLD: f64 = 0.40;

/// Adjust the base confidence of a pattern match given the context.
/// Returns `None` if the match should be skipped entirely (placeholder).
pub fn adjust_confidence(base_confidence: f64, ctx: &ScoringContext) -> Option<f64> {
    // Placeholders are never real secrets.
    if ctx.is_placeholder {
        return None;
    }

    let mut adjusted = base_confidence;

    // File-level adjustments
    if let Some(ref path) = ctx.file_path {
        let lower = path.to_lowercase();
        if is_test_file(&lower) {
            adjusted += TEST_FILE_ADJUSTMENT;
        }
        if is_env_file(&lower) {
            adjusted += ENV_FILE_ADJUSTMENT;
        }
    }

    // Comment adjustment
    if ctx.in_comment {
        adjusted += COMMENT_ADJUSTMENT;
    }

    // Sensitive variable name boost
    if ctx.sensitive_variable {
        adjusted += SENSITIVE_VAR_ADJUSTMENT;
    }

    // Clamp to [0.0, 1.0]
    adjusted = adjusted.clamp(0.0, 1.0);

    if adjusted < MIN_CONFIDENCE_THRESHOLD {
        return None;
    }

    Some(adjusted)
}

fn is_test_file(path: &str) -> bool {
    path.contains("test")
        || path.contains("spec")
        || path.contains("__tests__")
        || path.contains("_test.")
        || path.contains(".test.")
        || path.contains("_spec.")
        || path.contains(".spec.")
        || path.ends_with("_test.rs")
        || path.ends_with("_test.go")
}

fn is_env_file(path: &str) -> bool {
    path.ends_with(".env")
        || path.ends_with(".env.local")
        || path.ends_with(".env.production")
        || path.ends_with(".env.development")
        || path.contains(".env.")
}

/// Detect if a matched string looks like a well-known placeholder.
pub fn looks_like_placeholder(matched_text: &str) -> bool {
    let lower = matched_text.to_lowercase();

    // Only check for explicit placeholder indicators, not substrings
    // that could appear in real tokens.
    let exact_indicators = ["<", ">", "${", "{{"];
    if exact_indicators.iter().any(|p| lower.contains(p)) {
        return true;
    }

    // For email-like patterns, check for well-known placeholder domains
    if lower.contains('@') {
        let email_placeholders = [
            "example.com",
            "example.org",
            "test.com",
            "dummy.com",
            "fake.com",
            "sample.com",
            "placeholder.com",
        ];
        return email_placeholders.iter().any(|p| lower.contains(p));
    }

    // For other patterns, check if the entire match is a known placeholder
    let full_match_placeholders = ["your_", "my_", "replace_me", "change_me", "todo", "fixme"];
    full_match_placeholders.iter().any(|p| lower.starts_with(p))
}

/// E-07: Detect if a match offset is inside a code comment.
/// Checks for `//`, `/* ... */`, `#`, and `--` comment syntax.
pub fn is_in_comment(text: &str, match_start: usize) -> bool {
    // Find the start of the line containing this match.
    let line_start = text[..match_start].rfind('\n').map_or(0, |p| p + 1);
    let line_prefix = &text[line_start..match_start];

    // Check for single-line comment markers in the prefix.
    if line_prefix.contains("//") || line_prefix.contains('#') || line_prefix.contains("--") {
        return true;
    }

    // Check for block comment: find the last /* before match_start
    // and verify there's no */ between it and the match.
    if let Some(block_start) = text[..match_start].rfind("/*") {
        let block_end = text[block_start..match_start].find("*/");
        if block_end.is_none() {
            return true;
        }
    }

    false
}

/// Detect if the surrounding text suggests a sensitive variable assignment.
pub fn has_sensitive_variable_context(text: &str, match_start: usize) -> bool {
    // Look at the ~60 chars before the match for variable name hints.
    let prefix_start = match_start.saturating_sub(60);
    let prefix = &text[prefix_start..match_start].to_lowercase();
    let sensitive_names = [
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "auth",
        "credential",
        "private_key",
        "access_key",
    ];
    sensitive_names.iter().any(|name| prefix.contains(name))
}
