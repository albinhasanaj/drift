//! Per-language parser implementations.

pub mod csharp;
pub mod go;
pub mod java;
pub mod javascript;
pub mod kotlin;
pub mod php;
pub mod python;
pub mod ruby;
pub mod rust_lang;
pub mod typescript;

use std::path::Path;
use std::time::Instant;

use drift_core::errors::ParseError;
use smallvec::SmallVec;
use tree_sitter::{Node, Parser};

use super::error_tolerant::count_errors;
use super::types::*;
use crate::scanner::language_detect::Language;
use crate::scanner::hasher::hash_content;

/// Shared parsing logic used by all language parsers via the `define_parser!` macro.
pub fn parse_with_language(
    source: &[u8],
    path: &Path,
    language: Language,
    ts_language: tree_sitter::Language,
) -> Result<ParseResult, ParseError> {
    parse_with_language_and_tree(source, path, language, ts_language).map(|(r, _)| r)
}

/// Like [`parse_with_language`] but also returns the tree-sitter Tree,
/// allowing callers that need the raw AST (e.g. the detection engine) to
/// avoid a redundant re-parse.
pub fn parse_with_language_and_tree(
    source: &[u8],
    path: &Path,
    language: Language,
    ts_language: tree_sitter::Language,
) -> Result<(ParseResult, tree_sitter::Tree), ParseError> {
    let start = Instant::now();
    let file_str = path.to_string_lossy().to_string();
    let content_hash = hash_content(source);

    // Parse with tree-sitter
    let mut parser = Parser::new();
    parser.set_language(&ts_language).map_err(|_e| ParseError::GrammarNotFound {
        language: language.name().to_string(),
    })?;

    let tree = parser.parse(source, None).ok_or_else(|| ParseError::TreeSitterError {
        path: path.to_path_buf(),
        message: "tree-sitter returned None".to_string(),
    })?;

    let root = tree.root_node();
    let (error_count, error_ranges) = count_errors(root);

    // Extract structural elements
    let _source_str = std::str::from_utf8(source).unwrap_or("");
    let mut result = ParseResult {
        file: file_str.clone(),
        language,
        content_hash,
        has_errors: error_count > 0,
        error_count,
        error_ranges,
        ..Default::default()
    };

    // Extract functions, classes, imports, exports from the tree
    extract_structure(&mut result, root, source, &file_str);
    extract_calls(&mut result, root, source, &file_str);

    result.parse_time_us = start.elapsed().as_micros() as u64;
    Ok((result, tree))
}

/// Extract structural elements (functions, classes, imports, exports) from the AST.
fn extract_structure(result: &mut ParseResult, root: Node, source: &[u8], file: &str) {
    let mut cursor = root.walk();
    extract_node_recursive(result, &mut cursor, source, file, 0);
}

fn extract_node_recursive(
    result: &mut ParseResult,
    cursor: &mut tree_sitter::TreeCursor,
    source: &[u8],
    file: &str,
    depth: usize,
) {
    let node = cursor.node();
    let kind = node.kind();

    match kind {
        // Functions
        "function_declaration" | "function_definition" | "function_item"
        | "method_declaration" | "method_definition" | "method" | "singleton_method" => {
            if let Some(func) = extract_function(node, source, file) {
                result.functions.push(func);
            }
        }
        // Arrow functions (JS/TS)
        "arrow_function" => {
            if let Some(func) = extract_arrow_function(node, source, file) {
                result.functions.push(func);
            }
        }
        // Classes
        "class_declaration" | "class_definition" | "class" => {
            if let Some(class) = extract_class(node, source, file, result.language) {
                result.classes.push(class);
            }
        }
        // Interfaces
        "interface_declaration" => {
            if let Some(class) = extract_interface(node, source, file) {
                result.classes.push(class);
            }
        }
        // Structs (Rust, Go)
        "struct_item" | "type_spec" => {
            // Go type_spec: only extract if it contains a struct_type
            if kind == "type_spec" {
                let has_struct = (0..node.child_count()).any(|i| {
                    node.child(i).is_some_and(|c| c.kind() == "struct_type")
                });
                if has_struct {
                    if let Some(class) = extract_struct(node, source, file) {
                        result.classes.push(class);
                    }
                }
            } else if let Some(class) = extract_struct(node, source, file) {
                result.classes.push(class);
            }
        }
        // Enums
        "enum_item" | "enum_declaration" => {
            if let Some(class) = extract_enum(node, source, file) {
                result.classes.push(class);
            }
        }
        // Traits (Rust)
        "trait_item" => {
            if let Some(class) = extract_trait(node, source, file) {
                result.classes.push(class);
            }
        }
        // Imports
        "import_statement" | "import_declaration" | "import_from_statement"
        | "use_declaration" | "using_directive" | "import_header"
        | "namespace_use_declaration" => {
            // Go multi-import: extract each spec as a separate ImportInfo
            if kind == "import_declaration" {
                let mut go_specs = Vec::new();
                collect_go_import_specs(node, source, &mut go_specs);
                if go_specs.len() > 1 {
                    for spec_source in go_specs {
                        result.imports.push(ImportInfo {
                            source: spec_source,
                            specifiers: SmallVec::new(),
                            is_type_only: false,
                            file: file.to_string(),
                            line: node.start_position().row as u32,
                        });
                    }
                } else if let Some(import) = extract_import(node, source, file) {
                    result.imports.push(import);
                }
            } else if let Some(import) = extract_import(node, source, file) {
                result.imports.push(import);
            }
        }
        // Exports
        "export_statement" | "export_declaration" => {
            if let Some(export) = extract_export(node, source, file) {
                result.exports.push(export);
            }
        }
        // Namespace/Package
        "package_declaration" | "package_clause" | "package_header"
        | "namespace_declaration" | "namespace_definition" => {
            result.namespace = extract_text_from_node(node, source);
        }
        _ => {}
    }

    // Recurse into children
    if depth < 50 && cursor.goto_first_child() {
        loop {
            extract_node_recursive(result, cursor, source, file, depth + 1);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
        cursor.goto_parent();
    }
}

/// Extract call sites, decorators, literals from the AST.
fn extract_calls(result: &mut ParseResult, root: Node, source: &[u8], file: &str) {
    let mut cursor = root.walk();
    extract_calls_recursive(result, &mut cursor, source, file, 0);
}

fn extract_calls_recursive(
    result: &mut ParseResult,
    cursor: &mut tree_sitter::TreeCursor,
    source: &[u8],
    file: &str,
    depth: usize,
) {
    let node = cursor.node();
    let kind = node.kind();

    match kind {
        "call_expression" | "call" | "method_invocation" | "invocation_expression"
        | "function_call_expression" | "member_call_expression" => {
            if let Some(call) = extract_call_site(node, source, file) {
                // DP-IMPORT-07: Ruby require/require_relative → ImportInfo
                if (call.callee_name == "require" || call.callee_name == "require_relative")
                    && call.receiver.is_none()
                {
                    // Extract the string argument as the import source
                    if let Some(args) = node.child_by_field_name("arguments") {
                        for i in 0..args.child_count() {
                            if let Some(arg) = args.child(i) {
                                if arg.kind() == "string" || arg.kind() == "string_literal" {
                                    let src = node_text(arg, source)
                                        .trim_matches(|c| c == '"' || c == '\'')
                                        .to_string();
                                    if !src.is_empty() {
                                        result.imports.push(ImportInfo {
                                            source: src,
                                            specifiers: SmallVec::new(),
                                            is_type_only: false,
                                            file: file.to_string(),
                                            line: node.start_position().row as u32,
                                        });
                                    }
                                }
                            }
                        }
                    }
                    // Also try: require 'gem' (Ruby call without parens — argument child)
                    if result.language == Language::Ruby {
                        for i in 0..node.child_count() {
                            if let Some(arg) = node.child(i) {
                                if arg.kind() == "argument_list" {
                                    for j in 0..arg.child_count() {
                                        if let Some(str_node) = arg.child(j) {
                                            if str_node.kind() == "string" || str_node.kind() == "string_content" {
                                                let src = node_text(str_node, source)
                                                    .trim_matches(|c| c == '"' || c == '\'')
                                                    .to_string();
                                                if !src.is_empty() && !result.imports.iter().any(|imp| imp.source == src && imp.line == node.start_position().row as u32) {
                                                    result.imports.push(ImportInfo {
                                                        source: src,
                                                        specifiers: SmallVec::new(),
                                                        is_type_only: false,
                                                        file: file.to_string(),
                                                        line: node.start_position().row as u32,
                                                    });
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // DP-PERR-01: JS/TS .catch() on promises → PromiseCatch
                if call.callee_name == "catch" && call.receiver.is_some() {
                    result.error_handling.push(ErrorHandlingInfo {
                        kind: ErrorHandlingKind::PromiseCatch,
                        file: file.to_string(),
                        line: node.start_position().row as u32,
                        end_line: node.end_position().row as u32,
                        range: Range::from_ts_node(&node),
                        caught_type: None,
                        has_body: true,
                        function_scope: find_enclosing_function_name(node, source),
                    });
                }

                // DP-RERR-02: Rust .unwrap()/.expect() calls → Unwrap
                if matches!(call.callee_name.as_str(), "unwrap" | "unwrap_or" | "unwrap_or_else" | "unwrap_or_default" | "expect") {
                    result.error_handling.push(ErrorHandlingInfo {
                        kind: ErrorHandlingKind::Unwrap,
                        file: file.to_string(),
                        line: node.start_position().row as u32,
                        end_line: node.end_position().row as u32,
                        range: Range::from_ts_node(&node),
                        caught_type: None,
                        has_body: false,
                        function_scope: find_enclosing_function_name(node, source),
                    });
                }

                result.call_sites.push(call);
            }
        }
        "decorator" | "attribute" | "attribute_item" | "annotation"
        | "marker_annotation" => {
            if let Some(dec) = extract_decorator(node, source) {
                result.decorators.push(dec);
            }
        }
        "string" | "string_literal" | "interpreted_string_literal"
        | "raw_string_literal" | "template_string" => {
            if let Some(lit) = extract_string_literal(node, source, file) {
                result.string_literals.push(lit);
            }
        }
        "number" | "integer" | "float" | "integer_literal" | "float_literal"
        | "int_literal" | "decimal_integer_literal" | "decimal_floating_point_literal"
        | "real_literal" | "numeric_literal" => {
            if let Some(lit) = extract_numeric_literal(node, source, file) {
                result.numeric_literals.push(lit);
            }
        }
        // DP-DOC-01: Doc comment extraction
        "comment" | "line_comment" | "block_comment" => {
            let text = node_text(node, source);
            let trimmed = text.trim();
            // Classify by doc comment style
            let style = if trimmed.starts_with("/**") && trimmed.ends_with("*/") {
                // Could be JsDoc, KDoc, or PhpDoc depending on language
                match result.language {
                    Language::Kotlin => Some(DocCommentStyle::KDoc),
                    Language::Php => Some(DocCommentStyle::PhpDoc),
                    _ => Some(DocCommentStyle::JsDoc),
                }
            } else if trimmed.starts_with("///") || trimmed.starts_with("//!") {
                match result.language {
                    Language::CSharp => Some(DocCommentStyle::TripleSlash),
                    Language::Rust => Some(DocCommentStyle::TripleSlash),
                    _ => None,
                }
            } else if trimmed.starts_with('#') && matches!(result.language, Language::Ruby | Language::Python) {
                Some(DocCommentStyle::Pound)
            } else if trimmed.starts_with("//") && result.language == Language::Go {
                // Go doc comments are // comments immediately before declarations
                Some(DocCommentStyle::GoDoc)
            } else {
                None
            };
            if let Some(style) = style {
                result.doc_comments.push(DocCommentInfo {
                    text: text.clone(),
                    style,
                    file: file.to_string(),
                    line: node.start_position().row as u32,
                    range: Range::from_ts_node(&node),
                });
            }
        }
        // Error handling: try/catch with proper has_body and caught_type extraction
        "try_statement" | "try_expression" => {
            let mut eh_kind = ErrorHandlingKind::TryCatch;
            let mut caught_type = None;
            let mut has_body = true;

            // DP-ERR-03: Python try/except → TryExcept
            if result.language == Language::Python {
                eh_kind = ErrorHandlingKind::TryExcept;
            }

            // DP-ERR-01 & DP-ERR-02: Extract catch clause info
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    match child.kind() {
                        "catch_clause" | "except_clause" | "rescue_clause" | "rescue" => {
                            // DP-ERR-02: Extract caught type
                            caught_type = extract_catch_type(child, source);
                            // DP-ERR-01: Check if catch body is empty
                            has_body = catch_has_body(child);
                        }
                        _ => {}
                    }
                }
            }

            result.error_handling.push(ErrorHandlingInfo {
                kind: eh_kind,
                file: file.to_string(),
                line: node.start_position().row as u32,
                end_line: node.end_position().row as u32,
                range: Range::from_ts_node(&node),
                caught_type,
                has_body,
                function_scope: find_enclosing_function_name(node, source),
            });
        }
        "throw_statement" | "throw" | "raise_statement" | "raise" => {
            result.error_handling.push(ErrorHandlingInfo {
                kind: ErrorHandlingKind::Throw,
                file: file.to_string(),
                line: node.start_position().row as u32,
                end_line: node.end_position().row as u32,
                range: Range::from_ts_node(&node),
                caught_type: None,
                has_body: false,
                function_scope: find_enclosing_function_name(node, source),
            });
        }
        // Ruby begin/rescue
        "begin" => {
            let mut caught_type = None;
            let mut has_body = true;
            // Look for rescue clause inside begin block
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() == "rescue" || child.kind() == "rescue_clause" {
                        caught_type = extract_catch_type(child, source);
                        has_body = catch_has_body(child);
                    }
                }
            }
            result.error_handling.push(ErrorHandlingInfo {
                kind: ErrorHandlingKind::Rescue,
                file: file.to_string(),
                line: node.start_position().row as u32,
                end_line: node.end_position().row as u32,
                range: Range::from_ts_node(&node),
                caught_type,
                has_body,
                function_scope: find_enclosing_function_name(node, source),
            });
        }
        // Ruby inline rescue: x = dangerous rescue default
        "rescue_modifier" => {
            result.error_handling.push(ErrorHandlingInfo {
                kind: ErrorHandlingKind::Rescue,
                file: file.to_string(),
                line: node.start_position().row as u32,
                end_line: node.end_position().row as u32,
                range: Range::from_ts_node(&node),
                caught_type: None,
                has_body: true,
                function_scope: find_enclosing_function_name(node, source),
            });
        }
        // Go defer statement
        "defer_statement" => {
            // DP-GERR-02: Check if defer contains recover() → DeferRecover
            let text = node_text(node, source);
            let has_recover = text.contains("recover()");
            result.error_handling.push(ErrorHandlingInfo {
                kind: if has_recover { ErrorHandlingKind::DeferRecover } else { ErrorHandlingKind::Defer },
                file: file.to_string(),
                line: node.start_position().row as u32,
                end_line: node.end_position().row as u32,
                range: Range::from_ts_node(&node),
                caught_type: None,
                has_body: true,
                function_scope: find_enclosing_function_name(node, source),
            });
        }
        // Python with statement → WithStatement (context manager)
        "with_statement" => {
            result.error_handling.push(ErrorHandlingInfo {
                kind: ErrorHandlingKind::WithStatement,
                file: file.to_string(),
                line: node.start_position().row as u32,
                end_line: node.end_position().row as u32,
                range: Range::from_ts_node(&node),
                caught_type: None,
                has_body: true,
                function_scope: find_enclosing_function_name(node, source),
            });
        }
        // DP-RERR-03: Rust match on Result/Option → ResultMatch
        "match_expression" if result.language == Language::Rust => {
            let text = node_text(node, source);
            if text.contains("Ok(") || text.contains("Err(") || text.contains("Some(") || text.contains("None") {
                result.error_handling.push(ErrorHandlingInfo {
                    kind: ErrorHandlingKind::ResultMatch,
                    file: file.to_string(),
                    line: node.start_position().row as u32,
                    end_line: node.end_position().row as u32,
                    range: Range::from_ts_node(&node),
                    caught_type: None,
                    has_body: true,
                    function_scope: find_enclosing_function_name(node, source),
                });
            }
        }
        _ => {}
    }

    if depth < 50 && cursor.goto_first_child() {
        loop {
            extract_calls_recursive(result, cursor, source, file, depth + 1);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
        cursor.goto_parent();
    }
}

// ---- Extraction helpers ----

fn extract_function(node: Node, source: &[u8], file: &str) -> Option<FunctionInfo> {
    let name = find_child_text(&node, source, &["identifier", "property_identifier",
        "field_identifier", "name", "simple_identifier"])?;
    let body = node.child_by_field_name("body");
    let body_text = body.map(|b| node_text(b, source)).unwrap_or_default();
    let params_text = node.child_by_field_name("parameters")
        .map(|p| node_text(p, source))
        .unwrap_or_default();
    let return_type = node.child_by_field_name("return_type")
        .or_else(|| node.child_by_field_name("type"))
        .map(|t| node_text(t, source));

    let sig_return = return_type.as_deref().unwrap_or("");
    let sig_hash = hash_content(format!("{}({}){}", name, params_text, sig_return).as_bytes());

    // DP-FUNC-05: Extract visibility
    let visibility = extract_visibility(node, source);

    // DP-FUNC-01: Determine is_exported based on language conventions
    let is_exported = detect_is_exported(node, source, &name, visibility);

    // DP-FUNC-03: Extract generic type parameters
    let generic_params = extract_generic_params(node, source);

    // DP-FUNC-02: Extract doc comment from previous sibling
    let doc_comment = extract_doc_comment_for_node(node, source);

    // DP-FUNC-04: Link decorators from previous siblings
    let decorators = extract_decorators_for_node(node, source);

    Some(FunctionInfo {
        name: name.clone(),
        qualified_name: None,
        file: file.to_string(),
        line: node.start_position().row as u32,
        column: node.start_position().column as u32,
        end_line: node.end_position().row as u32,
        parameters: extract_parameters(node, source),
        return_type,
        generic_params,
        visibility,
        is_exported,
        is_async: has_child_kind(&node, "async"),
        is_generator: has_child_kind(&node, "generator") || node.kind().contains("generator"),
        is_abstract: has_child_kind(&node, "abstract"),
        range: Range::from_ts_node(&node),
        decorators,
        doc_comment,
        body_hash: hash_content(body_text.as_bytes()),
        signature_hash: sig_hash,
    })
}

fn extract_arrow_function(node: Node, source: &[u8], file: &str) -> Option<FunctionInfo> {
    // Arrow functions may be assigned to a variable
    let name = node.parent()
        .and_then(|p| {
            if p.kind() == "variable_declarator" || p.kind() == "lexical_declaration" {
                find_child_text(&p, source, &["identifier"])
            } else if p.kind() == "pair" || p.kind() == "property" {
                find_child_text(&p, source, &["property_identifier", "identifier"])
            } else {
                None
            }
        })
        .unwrap_or_else(|| "<anonymous>".to_string());

    let body = node.child_by_field_name("body");
    let body_text = body.map(|b| node_text(b, source)).unwrap_or_default();

    // Check if the arrow function is exported
    let is_exported = node.parent().is_some_and(|p| {
        p.parent().is_some_and(|gp| gp.kind() == "export_statement")
            || p.kind() == "export_statement"
    });

    let generic_params = extract_generic_params(node, source);
    let doc_comment = extract_doc_comment_for_node(node, source);

    Some(FunctionInfo {
        name,
        qualified_name: None,
        file: file.to_string(),
        line: node.start_position().row as u32,
        column: node.start_position().column as u32,
        end_line: node.end_position().row as u32,
        parameters: extract_parameters(node, source),
        return_type: None,
        generic_params,
        visibility: Visibility::Public,
        is_exported,
        is_async: node.parent().is_some_and(|p| has_child_kind(&p, "async")),
        is_generator: false,
        is_abstract: false,
        range: Range::from_ts_node(&node),
        decorators: Vec::new(),
        doc_comment,
        body_hash: hash_content(body_text.as_bytes()),
        signature_hash: 0,
    })
}

fn extract_class(node: Node, source: &[u8], file: &str, _lang: Language) -> Option<ClassInfo> {
    let name = find_child_text(&node, source, &[
        "identifier", "type_identifier", "constant", "name",
    ])?;

    let extends = node.child_by_field_name("superclass")
        .or_else(|| find_child_by_kind(&node, "class_heritage"))
        .and_then(|n| extract_text_from_node(n, source));

    // DP-CLASS-01: Extract implements
    let implements = extract_implements(node, source);

    // DP-CLASS-02: Extract generic params on classes
    let generic_params = extract_generic_params(node, source);

    // DP-CLASS-04: is_exported on classes
    let visibility = extract_visibility(node, source);
    let is_exported = detect_is_exported(node, source, &name, visibility);

    // DP-CLASS-03: Link decorators to classes
    let decorators = extract_decorators_for_node(node, source);

    let mut methods = Vec::new();
    let mut properties = Vec::new();

    // Extract methods and properties from class body
    if let Some(body) = node.child_by_field_name("body") {
        let mut cursor = body.walk();
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                match child.kind() {
                    "method_definition" | "method_declaration" | "method"
                    | "function_definition" | "function_item" => {
                        if let Some(mut func) = extract_function(child, source, file) {
                            func.qualified_name = Some(format!("{}.{}", name, func.name));
                            methods.push(func);
                        }
                    }
                    "public_field_definition" | "field_declaration" | "property_declaration" => {
                        if let Some(prop) = extract_property(child, source) {
                            properties.push(prop);
                        }
                    }
                    _ => {}
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    Some(ClassInfo {
        name,
        namespace: None,
        extends,
        implements,
        generic_params,
        is_exported,
        is_abstract: has_child_kind(&node, "abstract"),
        class_kind: ClassKind::Class,
        methods,
        properties,
        range: Range::from_ts_node(&node),
        decorators,
    })
}

fn extract_interface(node: Node, source: &[u8], _file: &str) -> Option<ClassInfo> {
    let name = find_child_text(&node, source, &["identifier", "type_identifier", "name"])?;
    let generic_params = extract_generic_params(node, source);
    let visibility = extract_visibility(node, source);
    let is_exported = detect_is_exported(node, source, &name, visibility);
    Some(ClassInfo {
        name,
        namespace: None,
        extends: None,
        implements: SmallVec::new(),
        generic_params,
        is_exported,
        is_abstract: true,
        class_kind: ClassKind::Interface,
        methods: Vec::new(),
        properties: Vec::new(),
        range: Range::from_ts_node(&node),
        decorators: extract_decorators_for_node(node, source),
    })
}

fn extract_struct(node: Node, source: &[u8], _file: &str) -> Option<ClassInfo> {
    let name = find_child_text(&node, source, &["type_identifier", "identifier"])?;
    let generic_params = extract_generic_params(node, source);
    let visibility = extract_visibility(node, source);
    let is_exported = detect_is_exported(node, source, &name, visibility);
    Some(ClassInfo {
        name,
        namespace: None,
        extends: None,
        implements: SmallVec::new(),
        generic_params,
        is_exported,
        is_abstract: false,
        class_kind: ClassKind::Struct,
        methods: Vec::new(),
        properties: Vec::new(),
        range: Range::from_ts_node(&node),
        decorators: Vec::new(),
    })
}

fn extract_enum(node: Node, source: &[u8], _file: &str) -> Option<ClassInfo> {
    let name = find_child_text(&node, source, &["type_identifier", "identifier", "name"])?;
    let visibility = extract_visibility(node, source);
    let is_exported = detect_is_exported(node, source, &name, visibility);
    Some(ClassInfo {
        name,
        namespace: None,
        extends: None,
        implements: SmallVec::new(),
        generic_params: SmallVec::new(),
        is_exported,
        is_abstract: false,
        class_kind: ClassKind::Enum,
        methods: Vec::new(),
        properties: Vec::new(),
        range: Range::from_ts_node(&node),
        decorators: Vec::new(),
    })
}

fn extract_trait(node: Node, source: &[u8], _file: &str) -> Option<ClassInfo> {
    let name = find_child_text(&node, source, &["type_identifier"])?;
    let generic_params = extract_generic_params(node, source);
    let visibility = extract_visibility(node, source);
    let is_exported = detect_is_exported(node, source, &name, visibility);
    Some(ClassInfo {
        name,
        namespace: None,
        extends: None,
        implements: SmallVec::new(),
        generic_params,
        is_exported,
        is_abstract: true,
        class_kind: ClassKind::Trait,
        methods: Vec::new(),
        properties: Vec::new(),
        range: Range::from_ts_node(&node),
        decorators: Vec::new(),
    })
}

fn extract_import(node: Node, source: &[u8], file: &str) -> Option<ImportInfo> {
    let text = node_text(node, source);
    let kind = node.kind();
    let mut module_source = String::new();
    let mut specifiers: SmallVec<[ImportSpecifier; 4]> = SmallVec::new();
    let mut is_type_only = false;

    match kind {
        // JS/TS: import { a, b } from 'module'; import type { X } from './types'
        "import_statement" => {
            is_type_only = text.contains("import type ");
            // Extract source from the string literal after "from"
            if let Some(src) = node.child_by_field_name("source") {
                module_source = node_text(src, source).trim_matches(|c| c == '"' || c == '\'' || c == '`').to_string();
            }
            // Extract specifiers from import_clause / named_imports
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    extract_import_specifiers_recursive(child, source, &mut specifiers);
                }
            }
            // JS CommonJS: const x = require("module") — not an import_statement
        }
        // Python: from X import a, b
        "import_from_statement" => {
            // module_name is the "from" part
            if let Some(mn) = node.child_by_field_name("module_name") {
                module_source = node_text(mn, source);
            }
            // specifiers are the imported names
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() == "dotted_name" && module_source.is_empty() {
                        module_source = node_text(child, source);
                    }
                    if child.kind() == "import_prefix" && module_source.is_empty() {
                        module_source = node_text(child, source);
                    }
                    extract_import_specifiers_recursive(child, source, &mut specifiers);
                }
            }
        }
        // Java/Kotlin: import java.util.List
        "import_declaration" | "import_header" => {
            // Go multi-import: import (\n"fmt"\n"os"\n)
            // Check for import_spec_list (Go multi-import)
            let mut found_go_specs = false;
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() == "import_spec_list" || child.kind() == "import_spec" {
                        found_go_specs = true;
                    }
                }
            }
            if found_go_specs {
                // Go imports handled separately — return None, they're extracted via extract_go_multi_imports
                // For single Go import, extract the path
                if let Some(spec) = find_child_by_kind(&node, "import_spec") {
                    if let Some(path_node) = find_child_by_kind(&spec, "interpreted_string_literal") {
                        module_source = node_text(path_node, source).trim_matches('"').to_string();
                    }
                }
                if module_source.is_empty() {
                    // Try direct string literal child (single import)
                    for i in 0..node.child_count() {
                        if let Some(child) = node.child(i) {
                            if child.kind() == "interpreted_string_literal" {
                                module_source = node_text(child, source).trim_matches('"').to_string();
                            }
                        }
                    }
                }
            } else {
                // Java/Kotlin: extract the full path
                // The identifier/scoped_identifier child has the full path
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        match child.kind() {
                            "scoped_identifier" | "identifier" | "dotted_name" => {
                                module_source = node_text(child, source);
                            }
                            _ => {}
                        }
                    }
                }
                // Extract the last segment as the specifier
                if !module_source.is_empty() {
                    if let Some(last) = module_source.rsplit('.').next() {
                        if last != "*" {
                            specifiers.push(ImportSpecifier { name: last.to_string(), alias: None });
                        }
                    }
                }
            }
        }
        // Rust: use std::collections::HashMap; use crate::{A, B}
        "use_declaration" => {
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    match child.kind() {
                        "scoped_identifier" | "scoped_use_list" | "use_wildcard" | "identifier" => {
                            let use_text = node_text(child, source);
                            if child.kind() == "scoped_use_list" {
                                // use crate::{A, B} → source=crate, specifiers=[A, B]
                                if let Some(path) = child.child_by_field_name("path") {
                                    module_source = node_text(path, source);
                                }
                                if let Some(list) = child.child_by_field_name("list") {
                                    for j in 0..list.child_count() {
                                        if let Some(item) = list.child(j) {
                                            if item.kind() == "identifier" || item.kind() == "scoped_identifier" {
                                                specifiers.push(ImportSpecifier {
                                                    name: node_text(item, source),
                                                    alias: None,
                                                });
                                            }
                                        }
                                    }
                                }
                            } else {
                                module_source = use_text;
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        // C#: using System.Linq
        "using_directive" => {
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    match child.kind() {
                        "qualified_name" | "identifier" | "name" => {
                            module_source = node_text(child, source);
                        }
                        _ => {}
                    }
                }
            }
        }
        // PHP: use App\Utils\FileHelper (namespace_use_declaration)
        "namespace_use_declaration" => {
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() == "namespace_use_clause" || child.kind() == "qualified_name" || child.kind() == "name" {
                        module_source = node_text(child, source);
                    }
                }
            }
        }
        _ => {
            module_source = text.clone();
        }
    }

    // Fallback: if we didn't extract a module path, use the full text
    if module_source.is_empty() {
        module_source = text;
    }

    Some(ImportInfo {
        source: module_source,
        specifiers,
        is_type_only,
        file: file.to_string(),
        line: node.start_position().row as u32,
    })
}

/// Recursively extract import specifiers from named_imports, import_specifier, etc.
fn extract_import_specifiers_recursive(node: Node, source: &[u8], specifiers: &mut SmallVec<[ImportSpecifier; 4]>) {
    match node.kind() {
        "import_specifier" | "aliased_import" => {
            let name = node.child_by_field_name("name")
                .map(|n| node_text(n, source))
                .unwrap_or_else(|| {
                    find_child_text(&node, source, &["identifier"]).unwrap_or_default()
                });
            let alias = node.child_by_field_name("alias").map(|a| node_text(a, source));
            if !name.is_empty() {
                specifiers.push(ImportSpecifier { name, alias });
            }
        }
        "dotted_name" | "identifier" => {
            // Python: individual imported name in "from X import a, b"
            // Only if parent is import_from_statement and this is after "import" keyword
            let parent = node.parent();
            if let Some(p) = parent {
                if p.kind() == "import_from_statement" {
                    // Check if this identifier comes after the "import" keyword
                    let mut found_import_kw = false;
                    for i in 0..p.child_count() {
                        if let Some(sibling) = p.child(i) {
                            if sibling.kind() == "import" {
                                found_import_kw = true;
                                continue;
                            }
                            if found_import_kw && std::ptr::eq(&sibling as *const _, &node as *const _) {
                                // This doesn't work with tree-sitter nodes directly
                            }
                        }
                    }
                }
            }
        }
        "named_imports" | "import_clause" => {
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    extract_import_specifiers_recursive(child, source, specifiers);
                }
            }
        }
        _ => {}
    }
}

fn extract_export(node: Node, source: &[u8], file: &str) -> Option<ExportInfo> {
    let name = find_child_text(&node, source, &["identifier", "type_identifier"]);
    let is_default = node_text(node, source).contains("default");
    Some(ExportInfo {
        name,
        is_default,
        is_type_only: false,
        source: None,
        file: file.to_string(),
        line: node.start_position().row as u32,
    })
}

fn extract_call_site(node: Node, source: &[u8], file: &str) -> Option<CallSite> {
    let (callee_name, receiver) = extract_call_target(node, source)?;
    let args = node.child_by_field_name("arguments");
    let arg_count = args.map(|a| {
        let mut count = 0u8;
        let mut c = a.walk();
        if c.goto_first_child() {
            loop {
                let child = c.node();
                if child.kind() != "(" && child.kind() != ")" && child.kind() != "," {
                    count = count.saturating_add(1);
                }
                if !c.goto_next_sibling() { break; }
            }
        }
        count
    }).unwrap_or(0);

    let is_await = node.parent().is_some_and(|p| p.kind() == "await_expression");

    Some(CallSite {
        callee_name,
        receiver,
        file: file.to_string(),
        line: node.start_position().row as u32,
        column: node.start_position().column as u32,
        argument_count: arg_count,
        is_await,
    })
}

fn extract_call_target(node: Node, source: &[u8]) -> Option<(String, Option<String>)> {
    // Try function field first
    if let Some(func) = node.child_by_field_name("function") {
        match func.kind() {
            "identifier" | "name" | "simple_identifier" => {
                return Some((node_text(func, source), None));
            }
            "member_expression" | "member_access_expression" | "selector_expression"
            | "field_expression" | "attribute" | "navigation_expression" => {
                let obj = func.child_by_field_name("object")
                    .or_else(|| func.child_by_field_name("operand"))
                    .map(|n| node_text(n, source));
                let prop = func.child_by_field_name("property")
                    .or_else(|| func.child_by_field_name("field"))
                    .or_else(|| func.child_by_field_name("name"))
                    .or_else(|| func.child_by_field_name("attribute"))
                    .map(|n| node_text(n, source));
                if let Some(method) = prop {
                    return Some((method, obj));
                }
            }
            _ => {}
        }
    }
    // Try method field (Java)
    if let Some(method) = node.child_by_field_name("name") {
        let obj = node.child_by_field_name("object").map(|n| node_text(n, source));
        return Some((node_text(method, source), obj));
    }
    // Try direct child identifier
    if let Some(name) = find_child_text(&node, source, &["identifier", "name", "simple_identifier"]) {
        return Some((name, None));
    }
    // Fallback: method field for member calls
    if let Some(method) = node.child_by_field_name("method") {
        return Some((node_text(method, source), None));
    }
    None
}

fn extract_decorator(node: Node, source: &[u8]) -> Option<DecoratorInfo> {
    let name = find_child_text(&node, source, &[
        "identifier", "name", "type_identifier", "call_expression",
    ]).unwrap_or_else(|| node_text(node, source));

    Some(DecoratorInfo {
        name,
        arguments: SmallVec::new(),
        raw_text: node_text(node, source),
        range: Range::from_ts_node(&node),
    })
}

fn extract_string_literal(node: Node, source: &[u8], file: &str) -> Option<StringLiteralInfo> {
    let text = node_text(node, source);
    // Strip quotes
    let value = text.trim_matches(|c| c == '"' || c == '\'' || c == '`').to_string();
    let context = classify_string_context(node);
    Some(StringLiteralInfo {
        value,
        context,
        file: file.to_string(),
        line: node.start_position().row as u32,
        column: node.start_position().column as u32,
        range: Range::from_ts_node(&node),
    })
}

fn extract_numeric_literal(node: Node, source: &[u8], file: &str) -> Option<NumericLiteralInfo> {
    let raw = node_text(node, source);
    let value = raw.replace('_', "").parse::<f64>().unwrap_or(0.0);
    let context = classify_numeric_context(node);
    Some(NumericLiteralInfo {
        value,
        raw,
        context,
        file: file.to_string(),
        line: node.start_position().row as u32,
        column: node.start_position().column as u32,
        range: Range::from_ts_node(&node),
    })
}

fn extract_parameters(node: Node, source: &[u8]) -> SmallVec<[ParameterInfo; 4]> {
    let mut params = SmallVec::new();
    if let Some(param_list) = node.child_by_field_name("parameters") {
        let mut cursor = param_list.walk();
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                match child.kind() {
                    "required_parameter" | "optional_parameter" | "formal_parameter"
                    | "parameter" | "identifier" | "typed_parameter"
                    | "default_parameter" | "rest_parameter" | "spread_parameter" => {
                        let name = find_child_text(&child, source, &[
                            "identifier", "name", "simple_identifier",
                        ]).unwrap_or_else(|| node_text(child, source));
                        let type_ann = child.child_by_field_name("type")
                            .map(|t| node_text(t, source));
                        let default = child.child_by_field_name("value")
                            .or_else(|| child.child_by_field_name("default_value"))
                            .map(|d| node_text(d, source));
                        let is_rest = child.kind().contains("rest") || child.kind().contains("spread");
                        params.push(ParameterInfo {
                            name,
                            type_annotation: type_ann,
                            default_value: default,
                            is_rest,
                        });
                    }
                    _ => {}
                }
                if !cursor.goto_next_sibling() { break; }
            }
        }
    }
    params
}

fn extract_property(node: Node, source: &[u8]) -> Option<PropertyInfo> {
    let name = find_child_text(&node, source, &[
        "property_identifier", "identifier", "name", "field_identifier",
    ])?;
    Some(PropertyInfo {
        name,
        type_annotation: node.child_by_field_name("type").map(|t| node_text(t, source)),
        is_static: has_child_kind(&node, "static"),
        is_readonly: has_child_kind(&node, "readonly"),
        visibility: Visibility::Public,
    })
}

// ---- Phase A/C helper functions ----

/// DP-FUNC-05: Extract visibility from modifier keywords.
fn extract_visibility(node: Node, source: &[u8]) -> Visibility {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            let kind = child.kind();
            let text = node_text(child, source);
            match kind {
                "visibility_modifier" | "modifiers" | "modifier" => {
                    let lower = text.to_lowercase();
                    if lower.contains("private") {
                        return Visibility::Private;
                    } else if lower.contains("protected") {
                        return Visibility::Protected;
                    } else if lower.contains("public") || lower.starts_with("pub") {
                        return Visibility::Public;
                    }
                }
                "private" => return Visibility::Private,
                "protected" => return Visibility::Protected,
                "public" | "pub" => return Visibility::Public,
                "accessibility_modifier" => {
                    let lower = text.to_lowercase();
                    if lower == "private" { return Visibility::Private; }
                    if lower == "protected" { return Visibility::Protected; }
                    return Visibility::Public;
                }
                _ => {}
            }
        }
    }
    // Default: check the text for pub keyword (Rust)
    let full_text = node_text(node, source);
    if full_text.starts_with("pub ") || full_text.starts_with("pub(") {
        return Visibility::Public;
    }
    Visibility::Public
}

/// DP-FUNC-01 / DP-CLASS-04: Determine if a node is exported based on language conventions.
fn detect_is_exported(node: Node, source: &[u8], name: &str, visibility: Visibility) -> bool {
    // Check for export_statement parent (JS/TS)
    if let Some(parent) = node.parent() {
        if parent.kind() == "export_statement" || parent.kind() == "export_declaration" {
            return true;
        }
    }

    // Check for "export" keyword child (JS/TS)
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if child.kind() == "export" {
                return true;
            }
        }
    }

    // Rust: pub keyword via visibility_modifier
    let text = node_text(node, source);
    if text.starts_with("pub ") || text.starts_with("pub(") {
        return true;
    }

    // Go: uppercase first letter = exported
    if let Some(first_char) = name.chars().next() {
        // Check if this looks like a Go function (no explicit visibility modifier)
        let node_kind = node.kind();
        if node_kind == "function_declaration" || node_kind == "method_declaration" 
            || node_kind == "struct_item" || node_kind == "type_declaration" {
            // For Go, check if first char is uppercase (but only for Go-style declarations)
            if first_char.is_uppercase() && !text.contains("class ") && !text.contains("interface ") {
                return true;
            }
        }
    }

    // Java/Kotlin/C#: public modifier
    if visibility == Visibility::Public {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                let kind = child.kind();
                if kind == "modifiers" || kind == "visibility_modifier" || kind == "accessibility_modifier" {
                    let child_text = node_text(child, source).to_lowercase();
                    if child_text.contains("public") {
                        return true;
                    }
                    // If it has a visibility modifier but it's not public, it's not exported
                    if child_text.contains("private") || child_text.contains("protected") {
                        return false;
                    }
                }
            }
        }
    }

    // Python: module-level functions without _ prefix are effectively public
    if !name.starts_with('_') {
        // We can't easily check if module-level here, so we'll be generous
        // and mark non-underscore functions as potentially exported
    }

    // Ruby/PHP: module-level def/function is public by default
    if node.kind() == "method" || node.kind() == "singleton_method"
        || node.kind() == "function_definition" {
        // Check for private/protected keywords in Ruby
        if let Some(parent) = node.parent() {
            let parent_text = node_text(parent, source);
            if parent_text.contains("private") {
                return false;
            }
        }
    }

    false
}

/// DP-FUNC-03 / DP-CLASS-02: Extract generic type parameters from a node.
fn extract_generic_params(node: Node, source: &[u8]) -> SmallVec<[GenericParam; 2]> {
    let mut params = SmallVec::new();

    // Look for type_parameters child
    if let Some(tp) = node.child_by_field_name("type_parameters")
        .or_else(|| find_child_by_kind(&node, "type_parameters"))
        .or_else(|| find_child_by_kind(&node, "type_parameter_list"))
    {
        for i in 0..tp.child_count() {
            if let Some(child) = tp.child(i) {
                match child.kind() {
                    "type_parameter" | "type_identifier" | "identifier" | "simple_identifier" => {
                        let name = find_child_text(&child, source, &["type_identifier", "identifier", "name", "simple_identifier"])
                            .unwrap_or_else(|| node_text(child, source));

                        // Extract bounds (extends, :, where clauses)
                        let mut bounds = SmallVec::new();
                        if let Some(constraint) = child.child_by_field_name("constraint")
                            .or_else(|| child.child_by_field_name("bound"))
                            .or_else(|| find_child_by_kind(&child, "type_bound"))
                            .or_else(|| find_child_by_kind(&child, "constraint"))
                        {
                            let bound_text = node_text(constraint, source);
                            // Split on + for multiple bounds (Rust: Clone + Send)
                            for b in bound_text.split('+') {
                                let trimmed = b.trim().to_string();
                                if !trimmed.is_empty() {
                                    bounds.push(trimmed);
                                }
                            }
                        }

                        if !name.is_empty() && name != "<" && name != ">" && name != "," {
                            params.push(GenericParam { name, bounds });
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    params
}

/// DP-FUNC-02: Extract doc comment from the previous sibling of a node.
fn extract_doc_comment_for_node(node: Node, source: &[u8]) -> Option<String> {
    // Check previous sibling for doc comment
    let mut prev = node.prev_named_sibling();
    let mut doc_lines = Vec::new();

    while let Some(sibling) = prev {
        let kind = sibling.kind();
        if kind == "comment" || kind == "line_comment" || kind == "block_comment" {
            let text = node_text(sibling, source);
            let trimmed = text.trim();
            // Check if it's a doc comment pattern
            if trimmed.starts_with("/**") || trimmed.starts_with("///") || trimmed.starts_with("//!")
                || trimmed.starts_with("///") {
                doc_lines.push(text);
                prev = sibling.prev_named_sibling();
                continue;
            }
            // Go: any // comment immediately before a declaration
            if trimmed.starts_with("//") {
                doc_lines.push(text);
                prev = sibling.prev_named_sibling();
                continue;
            }
            // Ruby/Python: # comments before declarations
            if trimmed.starts_with('#') {
                doc_lines.push(text);
                prev = sibling.prev_named_sibling();
                continue;
            }
        }
        break;
    }

    if doc_lines.is_empty() {
        // Python: check for docstring as first child (triple-quoted string)
        if let Some(body) = node.child_by_field_name("body") {
            if let Some(first) = body.child(0).or_else(|| body.named_child(0)) {
                if first.kind() == "expression_statement" {
                    if let Some(string_node) = first.child(0) {
                        if string_node.kind() == "string" || string_node.kind() == "concatenated_string" {
                            let text = node_text(string_node, source);
                            if text.starts_with("\"\"\"") || text.starts_with("'''") {
                                return Some(text);
                            }
                        }
                    }
                }
            }
        }
        return None;
    }

    doc_lines.reverse();
    Some(doc_lines.join("\n"))
}

/// DP-FUNC-04 / DP-CLASS-03: Extract decorators from previous siblings of a node.
fn extract_decorators_for_node(node: Node, source: &[u8]) -> Vec<DecoratorInfo> {
    let mut decorators = Vec::new();
    let mut prev = node.prev_named_sibling();

    while let Some(sibling) = prev {
        match sibling.kind() {
            "decorator" | "attribute" | "attribute_item" | "annotation" | "marker_annotation" => {
                if let Some(dec) = extract_decorator(sibling, source) {
                    decorators.push(dec);
                }
                prev = sibling.prev_named_sibling();
            }
            _ => break,
        }
    }

    decorators.reverse();
    decorators
}

/// DP-CLASS-01: Extract implements list from a class node.
fn extract_implements(node: Node, source: &[u8]) -> SmallVec<[String; 2]> {
    let mut implements = SmallVec::new();

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            match child.kind() {
                // Java: implements clause
                "super_interfaces" | "implements" => {
                    extract_type_list(child, source, &mut implements);
                }
                // TypeScript: class heritage with implements
                "class_heritage" => {
                    // Look for "implements" followed by types
                    let heritage_text = node_text(child, source);
                    if heritage_text.contains("implements") {
                        // Extract types after "implements"
                        for j in 0..child.child_count() {
                            if let Some(hc) = child.child(j) {
                                if hc.kind() == "implements_clause" {
                                    extract_type_list(hc, source, &mut implements);
                                }
                            }
                        }
                    }
                }
                // C#: base list (can contain both base class and interfaces)
                "base_list" => {
                    extract_type_list(child, source, &mut implements);
                }
                // Kotlin: delegation specifiers
                "delegation_specifier" | "delegation_specifier_list" => {
                    extract_type_list(child, source, &mut implements);
                }
                // PHP: class_interface_clause
                "class_interface_clause" => {
                    extract_type_list(child, source, &mut implements);
                }
                _ => {}
            }
        }
    }

    implements
}

/// Helper to extract type names from a type list node.
fn extract_type_list(node: Node, source: &[u8], types: &mut SmallVec<[String; 2]>) {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            match child.kind() {
                "type_identifier" | "identifier" | "generic_type" | "scoped_type_identifier"
                | "simple_identifier" | "name" | "qualified_name" => {
                    let text = node_text(child, source).trim().to_string();
                    if !text.is_empty() && text != "," && text != "implements" && text != "extends" {
                        types.push(text);
                    }
                }
                _ => {
                    // Recurse for nested structures
                    extract_type_list(child, source, types);
                }
            }
        }
    }
}

/// DP-ERR-02: Extract caught type from a catch/except clause.
fn extract_catch_type(node: Node, source: &[u8]) -> Option<String> {
    // Java/C#/Kotlin: catch (IOException e) — the parameter has a type
    if let Some(param) = node.child_by_field_name("parameter")
        .or_else(|| node.child_by_field_name("parameters"))
        .or_else(|| find_child_by_kind(&node, "catch_formal_parameter"))
    {
        // Extract the type from the parameter
        if let Some(type_node) = param.child_by_field_name("type")
            .or_else(|| find_child_by_kind(&param, "type_identifier"))
            .or_else(|| find_child_by_kind(&param, "catch_type"))
        {
            let t = node_text(type_node, source);
            if !t.is_empty() {
                return Some(t);
            }
        }
        // Also check for bare type_identifier as direct child
        for i in 0..param.child_count() {
            if let Some(child) = param.child(i) {
                if child.kind() == "type_identifier" || child.kind() == "identifier" {
                    let t = node_text(child, source);
                    // Don't return the variable name as the type
                    if !t.is_empty() && child.kind() == "type_identifier" {
                        return Some(t);
                    }
                }
            }
        }
    }

    // Python: except ValueError as e — type is the first identifier
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if child.kind() == "identifier" || child.kind() == "dotted_name" || child.kind() == "attribute" {
                let t = node_text(child, source);
                if !t.is_empty() && t != "as" {
                    return Some(t);
                }
            }
        }
    }

    // Ruby: rescue StandardError => e
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if child.kind() == "constant" || child.kind() == "scope_resolution" {
                let t = node_text(child, source);
                if !t.is_empty() {
                    return Some(t);
                }
            }
        }
    }

    None
}

/// DP-ERR-01: Check if a catch/except block has a non-empty body.
fn catch_has_body(node: Node) -> bool {
    // Look for a body child and check if it has statement children
    if let Some(body) = node.child_by_field_name("body")
        .or_else(|| find_child_by_kind(&node, "block"))
        .or_else(|| find_child_by_kind(&node, "statement_block"))
    {
        // Count non-punctuation children
        let mut statement_count = 0;
        for i in 0..body.child_count() {
            if let Some(child) = body.child(i) {
                let kind = child.kind();
                if kind != "{" && kind != "}" && kind != "(" && kind != ")" && kind != ":" {
                    statement_count += 1;
                }
            }
        }
        return statement_count > 0;
    }

    // If no explicit body, check direct children for statements
    let mut statement_count = 0;
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            let kind = child.kind();
            // Skip keywords and punctuation
            if kind != "catch" && kind != "except" && kind != "rescue"
                && kind != "(" && kind != ")" && kind != "{" && kind != "}"
                && kind != "identifier" && kind != "type_identifier"
                && kind != "catch_formal_parameter" && kind != "as"
                && kind != "=>" && kind != ":"
                && !kind.contains("parameter")
            {
                statement_count += 1;
            }
        }
    }
    statement_count > 0
}

/// DP-IMPORT-04: Collect Go import specs from a multi-import block.
fn collect_go_import_specs(node: Node, source: &[u8], specs: &mut Vec<String>) {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            match child.kind() {
                "import_spec_list" => {
                    collect_go_import_specs(child, source, specs);
                }
                "import_spec" => {
                    // The path is in the interpreted_string_literal child
                    for j in 0..child.child_count() {
                        if let Some(path_node) = child.child(j) {
                            if path_node.kind() == "interpreted_string_literal" {
                                let path = node_text(path_node, source).trim_matches('"').to_string();
                                if !path.is_empty() {
                                    specs.push(path);
                                }
                            }
                        }
                    }
                }
                "interpreted_string_literal" => {
                    let path = node_text(child, source).trim_matches('"').to_string();
                    if !path.is_empty() {
                        specs.push(path);
                    }
                }
                _ => {}
            }
        }
    }
}

/// DP-CTX-01: Classify string context from parent node.
fn classify_string_context(node: Node) -> StringContext {
    if let Some(parent) = node.parent() {
        match parent.kind() {
            "arguments" | "argument_list" => StringContext::FunctionArgument,
            "variable_declarator" | "assignment_expression" | "assignment"
            | "lexical_declaration" | "let_declaration" => StringContext::VariableAssignment,
            "pair" | "property" | "key_value_pair" | "dictionary_splat"
            | "property_assignment" => StringContext::ObjectProperty,
            "decorator" | "attribute" | "annotation" => StringContext::Decorator,
            "return_statement" => StringContext::ReturnValue,
            "array" | "array_expression" | "list" | "tuple" => StringContext::ArrayElement,
            _ => StringContext::Unknown,
        }
    } else {
        StringContext::Unknown
    }
}

/// DP-CTX-02: Classify numeric context from parent node.
fn classify_numeric_context(node: Node) -> NumericContext {
    if let Some(parent) = node.parent() {
        match parent.kind() {
            "const_item" | "const_declaration" => NumericContext::ConstDeclaration,
            "variable_declarator" | "assignment_expression" | "assignment"
            | "lexical_declaration" | "let_declaration" => NumericContext::VariableAssignment,
            "arguments" | "argument_list" => NumericContext::FunctionArgument,
            "array" | "array_expression" | "list" | "tuple" => NumericContext::ArrayElement,
            "binary_expression" => {
                // Check operator for comparison
                for i in 0..parent.child_count() {
                    if let Some(child) = parent.child(i) {
                        let kind = child.kind();
                        if kind == "==" || kind == "!=" || kind == "<" || kind == ">"
                            || kind == "<=" || kind == ">=" {
                            return NumericContext::Comparison;
                        }
                    }
                }
                NumericContext::BinaryOperation
            }
            "return_statement" => NumericContext::ReturnValue,
            "default_value" | "optional_parameter" => NumericContext::DefaultParameter,
            _ => NumericContext::Unknown,
        }
    } else {
        NumericContext::Unknown
    }
}

// ---- Utility functions ----

fn node_text(node: Node, source: &[u8]) -> String {
    node.utf8_text(source).unwrap_or("").to_string()
}

/// Walk up the AST from a node to find the nearest enclosing function/method name.
/// Works across all languages by checking for common function-like node kinds.
/// Returns None only if the node is at module/file scope (no enclosing function).
fn find_enclosing_function_name<'a>(node: Node<'a>, source: &[u8]) -> Option<String> {
    let function_kinds = [
        // JS/TS/Java/C#/PHP/Kotlin
        "function_declaration", "function_definition", "method_declaration",
        "method_definition", "method",
        // Rust
        "function_item",
        // Arrow functions (JS/TS)
        "arrow_function",
        // Ruby
        "singleton_method",
        // Go
        "func_literal",
        // Python
        "lambda",
    ];

    let mut current = node;
    loop {
        match current.parent() {
            Some(parent) => {
                if function_kinds.contains(&parent.kind()) {
                    // Try to extract the function name from the "name" field
                    if let Some(name_node) = parent.child_by_field_name("name") {
                        let name = node_text(name_node, source);
                        if !name.is_empty() {
                            return Some(name);
                        }
                    }
                    // For arrow functions assigned to a variable, check the parent
                    // e.g., const handler = async (req, res) => { ... }
                    if parent.kind() == "arrow_function" {
                        if let Some(grandparent) = parent.parent() {
                            if grandparent.kind() == "variable_declarator"
                                || grandparent.kind() == "assignment_expression"
                            {
                                if let Some(name_node) = grandparent.child_by_field_name("name") {
                                    let name = node_text(name_node, source);
                                    if !name.is_empty() {
                                        return Some(name);
                                    }
                                }
                                // Also try "left" field for assignments
                                if let Some(left) = grandparent.child_by_field_name("left") {
                                    let name = node_text(left, source);
                                    if !name.is_empty() {
                                        return Some(name);
                                    }
                                }
                            }
                        }
                    }
                    // Fallback: couldn't extract name from this function node
                    return None;
                }
                // Rust impl blocks: extract the type name as context
                if parent.kind() == "impl_item" {
                    if let Some(type_node) = parent.child_by_field_name("type") {
                        let type_name = node_text(type_node, source);
                        if !type_name.is_empty() {
                            return Some(format!("<impl {}>", type_name));
                        }
                    }
                }
                current = parent;
            }
            None => return None,
        }
    }
}

fn extract_text_from_node(node: Node, source: &[u8]) -> Option<String> {
    let text = node.utf8_text(source).ok()?;
    if text.is_empty() { None } else { Some(text.to_string()) }
}

fn find_child_text(node: &Node, source: &[u8], kinds: &[&str]) -> Option<String> {
    let child_count = node.child_count();
    for i in 0..child_count {
        if let Some(child) = node.child(i) {
            if kinds.contains(&child.kind()) {
                let text = node_text(child, source);
                if !text.is_empty() {
                    return Some(text);
                }
            }
        }
    }
    // Also check named children via field names
    for kind in kinds {
        if let Some(child) = node.child_by_field_name(kind) {
            let text = node_text(child, source);
            if !text.is_empty() {
                return Some(text);
            }
        }
    }
    None
}

fn find_child_by_kind<'a>(node: &'a Node<'a>, kind: &str) -> Option<Node<'a>> {
    let child_count = node.child_count();
    for i in 0..child_count {
        if let Some(child) = node.child(i) {
            if child.kind() == kind {
                return Some(child);
            }
        }
    }
    None
}

fn has_child_kind(node: &Node, kind: &str) -> bool {
    find_child_by_kind(node, kind).is_some()
}
