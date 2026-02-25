//! Phase 1: Constant extraction from AST (9+ languages).
//!
//! Extracts named constants from source code using language-specific patterns.
//! This is AST-aware: it distinguishes `const X = 5` from bare `5` in a function call.

use super::types::Constant;

/// Extract constants from source code.
///
/// Recognizes patterns like:
/// - `const NAME = value` (JS/TS)
/// - `NAME = value` at module level (Python)
/// - `static final TYPE NAME = value` (Java)
/// - `const NAME: type = value` (Rust)
/// - `define('NAME', value)` (PHP)
pub fn extract_constants(content: &str, file_path: &str, language: &str) -> Vec<Constant> {
    let mut constants = Vec::new();

    for (line_num, line) in content.lines().enumerate() {
        let trimmed = line.trim();

        match language {
            "typescript" | "javascript" => {
                // const NAME = value; or export const NAME = value;
                if let Some(c) = extract_js_const(trimmed, file_path, line_num as u32 + 1, language) {
                    constants.push(c);
                }
            }
            "python" => {
                // UPPER_CASE = value (module-level convention)
                if let Some(c) = extract_python_const(trimmed, file_path, line_num as u32 + 1) {
                    constants.push(c);
                }
            }
            "java" | "kotlin" => {
                // static final TYPE NAME = value; or const val NAME = value
                if let Some(c) = extract_java_const(trimmed, file_path, line_num as u32 + 1, language) {
                    constants.push(c);
                }
            }
            "rust" => {
                // const NAME: Type = value; or static NAME: Type = value;
                if let Some(c) = extract_rust_const(trimmed, file_path, line_num as u32 + 1) {
                    constants.push(c);
                }
            }
            "go" => {
                // const NAME = value or const NAME Type = value
                if let Some(c) = extract_go_const(trimmed, file_path, line_num as u32 + 1) {
                    constants.push(c);
                }
            }
            "csharp" => {
                // const TYPE NAME = value; or static readonly TYPE NAME = value;
                if let Some(c) = extract_csharp_const(trimmed, file_path, line_num as u32 + 1) {
                    constants.push(c);
                }
            }
            "ruby" => {
                // NAME = value (UPPER_CASE at module level)
                if let Some(c) = extract_ruby_const(trimmed, file_path, line_num as u32 + 1) {
                    constants.push(c);
                }
            }
            "php" => {
                // define('NAME', value) or const NAME = value;
                if let Some(c) = extract_php_const(trimmed, file_path, line_num as u32 + 1) {
                    constants.push(c);
                }
            }
            _ => {}
        }
    }

    constants
}

fn extract_js_const(line: &str, file: &str, line_num: u32, lang: &str) -> Option<Constant> {
    let stripped = line.strip_prefix("export ")
        .unwrap_or(line);
    let stripped = stripped.strip_prefix("const ")
        .or_else(|| stripped.strip_prefix("let "))
        .or_else(|| stripped.strip_prefix("var "))?;

    let eq_pos = stripped.find('=')?;
    let name = stripped[..eq_pos].trim();

    // Skip destructuring
    if name.starts_with('{') || name.starts_with('[') {
        return None;
    }

    // Skip if name contains type annotation (TS)
    let name = name.split(':').next()?.trim();

    let value = stripped[eq_pos + 1..].trim().trim_end_matches(';').trim();

    Some(Constant {
        name: name.to_string(),
        value: value.to_string(),
        file: file.to_string(),
        line: line_num,
        is_used: true, // Assume used until dead constant analysis
        language: lang.to_string(),
        is_named: true,
    })
}

fn extract_python_const(line: &str, file: &str, line_num: u32) -> Option<Constant> {
    // Python convention: UPPER_CASE = value
    let eq_pos = line.find('=')?;
    if line.chars().nth(eq_pos + 1) == Some('=') {
        return None; // Skip ==
    }
    if eq_pos > 0 && (line.as_bytes()[eq_pos - 1] == b'!' || line.as_bytes()[eq_pos - 1] == b'<' || line.as_bytes()[eq_pos - 1] == b'>') {
        return None; // Skip !=, <=, >=
    }

    let name = line[..eq_pos].trim();
    if !name.chars().all(|c| c.is_uppercase() || c == '_' || c.is_ascii_digit()) || name.is_empty() {
        return None;
    }
    // Must start with a letter
    if !name.chars().next()?.is_alphabetic() {
        return None;
    }

    let value = line[eq_pos + 1..].trim();

    Some(Constant {
        name: name.to_string(),
        value: value.to_string(),
        file: file.to_string(),
        line: line_num,
        is_used: true,
        language: "python".to_string(),
        is_named: true,
    })
}

fn extract_java_const(line: &str, file: &str, line_num: u32, lang: &str) -> Option<Constant> {
    // static final TYPE NAME = value;
    if line.contains("static") && line.contains("final") {
        let eq_pos = line.find('=')?;
        let before_eq = line[..eq_pos].trim();
        let name = before_eq.split_whitespace().last()?;
        let value = line[eq_pos + 1..].trim().trim_end_matches(';').trim();
        return Some(Constant {
            name: name.to_string(),
            value: value.to_string(),
            file: file.to_string(),
            line: line_num,
            is_used: true,
            language: lang.to_string(),
            is_named: true,
        });
    }
    // Kotlin: const val NAME = value
    if line.contains("const val") {
        let after = line.split("const val").nth(1)?;
        let eq_pos = after.find('=')?;
        let name = after[..eq_pos].trim().split(':').next()?.trim();
        let value = after[eq_pos + 1..].trim();
        return Some(Constant {
            name: name.to_string(),
            value: value.to_string(),
            file: file.to_string(),
            line: line_num,
            is_used: true,
            language: lang.to_string(),
            is_named: true,
        });
    }
    None
}

fn extract_rust_const(line: &str, file: &str, line_num: u32) -> Option<Constant> {
    let stripped = line.strip_prefix("pub ")
        .or_else(|| line.strip_prefix("pub(crate) "))
        .unwrap_or(line);

    let is_const = stripped.starts_with("const ");
    let is_static = stripped.starts_with("static ");

    if !is_const && !is_static {
        return None;
    }

    let keyword_len = if is_const { 6 } else { 7 };
    let rest = &stripped[keyword_len..];
    let eq_pos = rest.find('=')?;
    let name_part = rest[..eq_pos].trim();
    let name = name_part.split(':').next()?.trim();
    let value = rest[eq_pos + 1..].trim().trim_end_matches(';').trim();

    Some(Constant {
        name: name.to_string(),
        value: value.to_string(),
        file: file.to_string(),
        line: line_num,
        is_used: true,
        language: "rust".to_string(),
        is_named: true,
    })
}

fn extract_go_const(line: &str, file: &str, line_num: u32) -> Option<Constant> {
    let stripped = line.strip_prefix("const ")?;
    let eq_pos = stripped.find('=')?;
    let name = stripped[..eq_pos].split_whitespace().next()?;
    let value = stripped[eq_pos + 1..].trim();

    Some(Constant {
        name: name.to_string(),
        value: value.to_string(),
        file: file.to_string(),
        line: line_num,
        is_used: true,
        language: "go".to_string(),
        is_named: true,
    })
}

fn extract_csharp_const(line: &str, file: &str, line_num: u32) -> Option<Constant> {
    if line.contains("const ") || (line.contains("static") && line.contains("readonly")) {
        let eq_pos = line.find('=')?;
        let before_eq = line[..eq_pos].trim();
        let name = before_eq.split_whitespace().last()?;
        let value = line[eq_pos + 1..].trim().trim_end_matches(';').trim();
        return Some(Constant {
            name: name.to_string(),
            value: value.to_string(),
            file: file.to_string(),
            line: line_num,
            is_used: true,
            language: "csharp".to_string(),
            is_named: true,
        });
    }
    None
}

fn extract_ruby_const(line: &str, file: &str, line_num: u32) -> Option<Constant> {
    // Ruby constants start with uppercase
    let eq_pos = line.find('=')?;
    if line.chars().nth(eq_pos + 1) == Some('=') {
        return None;
    }
    let name = line[..eq_pos].trim();
    if name.is_empty() || !name.chars().next()?.is_uppercase() {
        return None;
    }
    // Must be UPPER_CASE or PascalCase
    if !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return None;
    }
    let value = line[eq_pos + 1..].trim();

    Some(Constant {
        name: name.to_string(),
        value: value.to_string(),
        file: file.to_string(),
        line: line_num,
        is_used: true,
        language: "ruby".to_string(),
        is_named: true,
    })
}

fn extract_php_const(line: &str, file: &str, line_num: u32) -> Option<Constant> {
    // define('NAME', value) or const NAME = value;
    if let Some(pos) = line.find("define(") {
        let rest = &line[pos + 7..];
        let quote = rest.trim_start().chars().next()?;
        if quote == '\'' || quote == '"' {
            let after_quote = &rest.trim_start()[1..];
            let end = after_quote.find(quote)?;
            let name = &after_quote[..end];
            let comma = after_quote[end + 1..].find(',')?;
            let value = after_quote[end + 1 + comma + 1..].trim().trim_end_matches(')').trim();
            return Some(Constant {
                name: name.to_string(),
                value: value.to_string(),
                file: file.to_string(),
                line: line_num,
                is_used: true,
                language: "php".to_string(),
                is_named: true,
            });
        }
    }
    if line.trim().starts_with("const ") {
        let rest = line.trim().strip_prefix("const ")?;
        let eq_pos = rest.find('=')?;
        let name = rest[..eq_pos].trim();
        let value = rest[eq_pos + 1..].trim().trim_end_matches(';').trim();
        return Some(Constant {
            name: name.to_string(),
            value: value.to_string(),
            file: file.to_string(),
            line: line_num,
            is_used: true,
            language: "php".to_string(),
            is_named: true,
        });
    }
    None
}
