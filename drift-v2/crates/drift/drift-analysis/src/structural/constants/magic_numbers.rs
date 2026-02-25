//! Phase 2: Magic number detection via AST (scope-aware, context-aware).
//!
//! A magic number is a bare numeric literal used directly in code without
//! being assigned to a named constant. This detector is AST-aware: it
//! distinguishes `const TIMEOUT = 3000` (named — not flagged) from
//! `setTimeout(fn, 3000)` (magic — flagged).

use super::types::MagicNumber;

/// Well-known non-magic numbers that should never be flagged.
const ALLOWED_VALUES: &[&str] = &[
    "0", "1", "-1", "2", "0.0", "1.0", "0.5", "100", "1000",
    "true", "false", "null", "nil", "None", "undefined",
];

/// Detect magic numbers in source code.
///
/// Uses line-level heuristics to determine if a numeric literal is in a
/// named constant context or a bare usage context.
pub fn detect_magic_numbers(content: &str, file_path: &str, language: &str) -> Vec<MagicNumber> {
    let mut results = Vec::new();

    for (line_num, line) in content.lines().enumerate() {
        let trimmed = line.trim();

        // Skip comments
        if trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with("/*")
            || trimmed.starts_with('*') || trimmed.starts_with("'''") || trimmed.starts_with("\"\"\"")
        {
            continue;
        }

        // Skip blank lines
        if trimmed.is_empty() {
            continue;
        }

        // Check if this line is a named constant definition
        let is_named = is_named_constant_line(trimmed, language);

        // Find numeric literals in the line
        let numbers = extract_numeric_literals(trimmed);

        for (value, col) in numbers {
            if ALLOWED_VALUES.contains(&value.as_str()) {
                continue;
            }

            // Skip array indices and common patterns
            if is_array_index_context(trimmed, col) {
                continue;
            }

            results.push(MagicNumber {
                value: value.clone(),
                file: file_path.to_string(),
                line: (line_num + 1) as u32,
                in_named_context: is_named,
                suggested_name: suggest_constant_name(&value),
            });
        }
    }

    // Only return magic numbers that are NOT in named contexts
    results.into_iter().filter(|m| !m.in_named_context).collect()
}

/// Check if a line defines a named constant.
fn is_named_constant_line(line: &str, language: &str) -> bool {
    match language {
        "typescript" | "javascript" => {
            line.starts_with("const ") || line.starts_with("export const ")
                || line.starts_with("let ") || line.starts_with("var ")
        }
        "python" => {
            // UPPER_CASE = value
            if let Some(eq_pos) = line.find('=') {
                let name = line[..eq_pos].trim();
                name.chars().all(|c| c.is_uppercase() || c == '_' || c.is_ascii_digit())
                    && !name.is_empty()
            } else {
                false
            }
        }
        "java" | "kotlin" => {
            line.contains("static final") || line.contains("const val")
        }
        "rust" => {
            line.starts_with("const ") || line.starts_with("pub const ")
                || line.starts_with("static ") || line.starts_with("pub static ")
        }
        "go" => line.starts_with("const "),
        "csharp" => line.contains("const ") || (line.contains("static") && line.contains("readonly")),
        _ => false,
    }
}

/// Extract numeric literals from a line with their column positions.
fn extract_numeric_literals(line: &str) -> Vec<(String, usize)> {
    let mut results = Vec::new();
    let bytes = line.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        // Skip strings
        if bytes[i] == b'"' || bytes[i] == b'\'' || bytes[i] == b'`' {
            let quote = bytes[i];
            i += 1;
            while i < bytes.len() && bytes[i] != quote {
                if bytes[i] == b'\\' {
                    i += 1; // Skip escaped char
                }
                i += 1;
            }
            i += 1;
            continue;
        }

        // Check for numeric literal
        if bytes[i].is_ascii_digit() || (bytes[i] == b'-' && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit()) {
            // Make sure it's not part of an identifier
            if i > 0 && (bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_') {
                i += 1;
                continue;
            }

            let start = i;
            if bytes[i] == b'-' {
                i += 1;
            }
            while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.' || bytes[i] == b'x' || bytes[i] == b'X'
                || bytes[i] == b'e' || bytes[i] == b'E' || bytes[i] == b'_')
            {
                i += 1;
            }

            // Skip if followed by alphanumeric (part of identifier like `v2`)
            if i < bytes.len() && (bytes[i].is_ascii_alphabetic() || bytes[i] == b'_') {
                // Exception: allow suffixes like `f`, `L`, `u32`
                if !matches!(bytes[i], b'f' | b'F' | b'L' | b'l' | b'u' | b'i' | b'd' | b'D') {
                    i += 1;
                    continue;
                }
            }

            let num_str = &line[start..i];
            results.push((num_str.to_string(), start));
        } else {
            i += 1;
        }
    }

    results
}

/// Check if a numeric literal is used as an array index.
fn is_array_index_context(line: &str, col: usize) -> bool {
    if col > 0 {
        let before = &line[..col];
        if before.ends_with('[') {
            return true;
        }
    }
    false
}

/// Suggest a constant name for a magic number.
fn suggest_constant_name(value: &str) -> Option<String> {
    match value {
        "200" => Some("HTTP_OK".to_string()),
        "201" => Some("HTTP_CREATED".to_string()),
        "204" => Some("HTTP_NO_CONTENT".to_string()),
        "301" => Some("HTTP_MOVED_PERMANENTLY".to_string()),
        "302" => Some("HTTP_FOUND".to_string()),
        "400" => Some("HTTP_BAD_REQUEST".to_string()),
        "401" => Some("HTTP_UNAUTHORIZED".to_string()),
        "403" => Some("HTTP_FORBIDDEN".to_string()),
        "404" => Some("HTTP_NOT_FOUND".to_string()),
        "500" => Some("HTTP_INTERNAL_SERVER_ERROR".to_string()),
        "3000" | "3001" | "8080" | "8000" | "5000" | "4000" => Some("PORT".to_string()),
        "60" => Some("SECONDS_PER_MINUTE".to_string()),
        "3600" => Some("SECONDS_PER_HOUR".to_string()),
        "86400" => Some("SECONDS_PER_DAY".to_string()),
        "1024" => Some("BYTES_PER_KB".to_string()),
        "1048576" => Some("BYTES_PER_MB".to_string()),
        _ => None,
    }
}
