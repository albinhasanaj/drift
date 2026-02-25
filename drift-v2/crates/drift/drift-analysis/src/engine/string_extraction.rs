//! String literal extraction for regex-based detection (Phase 2 of the pipeline).
//!
//! Extracts string literals, template strings, and interpolations from parsed files.
//! Per-language string node kinds ensure correct extraction across all 10 languages.

use crate::scanner::language_detect::Language;

/// An extracted string with its location and context.
#[derive(Debug, Clone)]
pub struct ExtractedString {
    pub value: String,
    pub file: String,
    pub line: u32,
    pub column: u32,
    pub kind: StringKind,
    pub context: StringExtractionContext,
}

/// The kind of string extracted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringKind {
    /// Plain string literal.
    Literal,
    /// Template/interpolated string.
    Template,
    /// Raw/verbatim string.
    Raw,
    /// Regex literal.
    Regex,
    /// Doc comment.
    DocComment,
}

/// Context in which the string was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringExtractionContext {
    FunctionArgument,
    VariableAssignment,
    ObjectProperty,
    Decorator,
    ReturnValue,
    Import,
    Annotation,
    Unknown,
}

/// Extract strings from a tree-sitter AST.
pub fn extract_strings(
    tree: &tree_sitter::Tree,
    source: &[u8],
    file: &str,
    language: Language,
) -> Vec<ExtractedString> {
    let mut strings = Vec::new();
    let node_kinds = string_node_kinds(language);
    extract_from_node(&tree.root_node(), source, file, &node_kinds, &mut strings);
    strings
}

/// Recursively extract strings from AST nodes.
fn extract_from_node(
    node: &tree_sitter::Node,
    source: &[u8],
    file: &str,
    node_kinds: &[&str],
    strings: &mut Vec<ExtractedString>,
) {
    let kind = node.kind();

    if node_kinds.contains(&kind) {
        if let Ok(text) = node.utf8_text(source) {
            let cleaned = clean_string_literal(text, kind);
            if !cleaned.is_empty() {
                let start = node.start_position();
                strings.push(ExtractedString {
                    value: cleaned,
                    file: file.to_string(),
                    line: start.row as u32,
                    column: start.column as u32,
                    kind: classify_string_kind(kind),
                    context: infer_context(node),
                });
            }
        }
    }

    let child_count = node.child_count();
    for i in 0..child_count {
        if let Some(child) = node.child(i) {
            extract_from_node(&child, source, file, node_kinds, strings);
        }
    }
}

/// Get the tree-sitter node kinds that represent strings for each language.
fn string_node_kinds(language: Language) -> Vec<&'static str> {
    match language {
        Language::TypeScript | Language::JavaScript => vec![
            "string", "template_string", "template_literal_type",
            "string_fragment", "regex_pattern",
        ],
        Language::Python => vec![
            "string", "string_content", "concatenated_string",
            "format_string",
        ],
        Language::Java => vec![
            "string_literal", "text_block", "character_literal",
        ],
        Language::CSharp => vec![
            "string_literal", "verbatim_string_literal",
            "interpolated_string_expression", "raw_string_literal",
        ],
        Language::Go => vec![
            "raw_string_literal", "interpreted_string_literal",
        ],
        Language::Rust => vec![
            "string_literal", "raw_string_literal", "char_literal",
        ],
        Language::Ruby => vec![
            "string", "string_content", "heredoc_body",
            "regex", "symbol",
        ],
        Language::Php => vec![
            "string", "encapsed_string", "heredoc",
            "nowdoc", "string_value",
        ],
        Language::Kotlin => vec![
            "line_string_literal", "multi_line_string_literal",
            "string_literal",
        ],
        Language::Cpp | Language::C => vec![
            "string_literal", "char_literal", "raw_string_literal",
        ],
        Language::Swift => vec![
            "line_str_text", "multi_line_str_text", "string_literal",
        ],
        Language::Scala => vec![
            "string", "interpolated_string", "string_literal",
        ],
    }
}

/// Remove quotes and escape sequences from a string literal.
fn clean_string_literal(text: &str, _kind: &str) -> String {
    let trimmed = text.trim();
    // Remove surrounding quotes
    if ((trimmed.starts_with('"') && trimmed.ends_with('"'))
        || (trimmed.starts_with('\'') && trimmed.ends_with('\'')))
        && trimmed.len() >= 2 {
            return trimmed[1..trimmed.len() - 1].to_string();
        }
    // Template strings
    if trimmed.starts_with('`') && trimmed.ends_with('`')
        && trimmed.len() >= 2 {
            return trimmed[1..trimmed.len() - 1].to_string();
        }
    // Triple-quoted strings (Python, Kotlin)
    if ((trimmed.starts_with("\"\"\"") && trimmed.ends_with("\"\"\""))
        || (trimmed.starts_with("'''") && trimmed.ends_with("'''")))
        && trimmed.len() >= 6 {
            return trimmed[3..trimmed.len() - 3].to_string();
        }
    trimmed.to_string()
}

/// Classify the kind of string from its AST node type.
fn classify_string_kind(kind: &str) -> StringKind {
    match kind {
        "template_string" | "template_literal_type" | "format_string"
        | "interpolated_string_expression" | "encapsed_string" => StringKind::Template,
        "raw_string_literal" | "verbatim_string_literal" | "nowdoc" => StringKind::Raw,
        "regex_pattern" | "regex" => StringKind::Regex,
        _ => StringKind::Literal,
    }
}

/// Infer the context of a string from its parent node.
fn infer_context(node: &tree_sitter::Node) -> StringExtractionContext {
    if let Some(parent) = node.parent() {
        match parent.kind() {
            "arguments" | "argument_list" | "call_expression" => {
                StringExtractionContext::FunctionArgument
            }
            "variable_declarator" | "assignment_expression" | "assignment" => {
                StringExtractionContext::VariableAssignment
            }
            "pair" | "property" | "property_assignment" => {
                StringExtractionContext::ObjectProperty
            }
            "decorator" | "annotation" => StringExtractionContext::Decorator,
            "return_statement" => StringExtractionContext::ReturnValue,
            "import_statement" | "import_declaration" => StringExtractionContext::Import,
            _ => StringExtractionContext::Unknown,
        }
    } else {
        StringExtractionContext::Unknown
    }
}
