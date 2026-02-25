//! Canonical ParseResult and supporting types.
//!
//! This is the single source of truth for parse output. Every downstream system
//! consumes this struct. Rust defines it, nothing else redefines it.

use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

use crate::scanner::language_detect::Language;

/// Canonical parse result produced by every language parser.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParseResult {
    pub file: String,
    pub language: Language,
    pub content_hash: u64,

    // Structural extraction
    pub functions: Vec<FunctionInfo>,
    pub classes: Vec<ClassInfo>,
    pub imports: Vec<ImportInfo>,
    pub exports: Vec<ExportInfo>,

    // Call & reference extraction
    pub call_sites: Vec<CallSite>,
    pub decorators: Vec<DecoratorInfo>,

    // Literal extraction
    pub string_literals: Vec<StringLiteralInfo>,
    pub numeric_literals: Vec<NumericLiteralInfo>,
    pub error_handling: Vec<ErrorHandlingInfo>,
    pub doc_comments: Vec<DocCommentInfo>,

    // Metadata
    pub namespace: Option<String>,
    pub parse_time_us: u64,
    pub error_count: u32,
    pub error_ranges: Vec<Range>,
    pub has_errors: bool,
}

impl Default for ParseResult {
    fn default() -> Self {
        Self {
            file: String::new(),
            language: Language::TypeScript,
            content_hash: 0,
            functions: Vec::new(),
            classes: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            call_sites: Vec::new(),
            decorators: Vec::new(),
            string_literals: Vec::new(),
            numeric_literals: Vec::new(),
            error_handling: Vec::new(),
            doc_comments: Vec::new(),
            namespace: None,
            parse_time_us: 0,
            error_count: 0,
            error_ranges: Vec::new(),
            has_errors: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionInfo {
    pub name: String,
    pub qualified_name: Option<String>,
    pub file: String,
    pub line: u32,
    pub column: u32,
    pub end_line: u32,
    pub parameters: SmallVec<[ParameterInfo; 4]>,
    pub return_type: Option<String>,
    pub generic_params: SmallVec<[GenericParam; 2]>,
    pub visibility: Visibility,
    pub is_exported: bool,
    pub is_async: bool,
    pub is_generator: bool,
    pub is_abstract: bool,
    pub range: Range,
    pub decorators: Vec<DecoratorInfo>,
    pub doc_comment: Option<String>,
    pub body_hash: u64,
    pub signature_hash: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassInfo {
    pub name: String,
    pub namespace: Option<String>,
    pub extends: Option<String>,
    pub implements: SmallVec<[String; 2]>,
    pub generic_params: SmallVec<[GenericParam; 2]>,
    pub is_exported: bool,
    pub is_abstract: bool,
    pub class_kind: ClassKind,
    pub methods: Vec<FunctionInfo>,
    pub properties: Vec<PropertyInfo>,
    pub range: Range,
    pub decorators: Vec<DecoratorInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ClassKind {
    Class,
    Interface,
    Struct,
    Enum,
    Trait,
    Record,
    Union,
    TypeAlias,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecoratorInfo {
    pub name: String,
    pub arguments: SmallVec<[DecoratorArgument; 2]>,
    pub raw_text: String,
    pub range: Range,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecoratorArgument {
    pub key: Option<String>,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallSite {
    pub callee_name: String,
    pub receiver: Option<String>,
    pub file: String,
    pub line: u32,
    pub column: u32,
    pub argument_count: u8,
    pub is_await: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportInfo {
    pub source: String,
    pub specifiers: SmallVec<[ImportSpecifier; 4]>,
    pub is_type_only: bool,
    pub file: String,
    pub line: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportSpecifier {
    pub name: String,
    pub alias: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportInfo {
    pub name: Option<String>,
    pub is_default: bool,
    pub is_type_only: bool,
    pub source: Option<String>,
    pub file: String,
    pub line: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringLiteralInfo {
    pub value: String,
    pub context: StringContext,
    pub file: String,
    pub line: u32,
    pub column: u32,
    pub range: Range,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StringContext {
    FunctionArgument,
    VariableAssignment,
    ObjectProperty,
    Decorator,
    ReturnValue,
    ArrayElement,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NumericLiteralInfo {
    pub value: f64,
    pub raw: String,
    pub context: NumericContext,
    pub file: String,
    pub line: u32,
    pub column: u32,
    pub range: Range,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NumericContext {
    ConstDeclaration,
    VariableAssignment,
    FunctionArgument,
    ArrayElement,
    Comparison,
    BinaryOperation,
    ReturnValue,
    DefaultParameter,
    EnumValue,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorHandlingInfo {
    pub kind: ErrorHandlingKind,
    pub file: String,
    pub line: u32,
    pub end_line: u32,
    pub range: Range,
    pub caught_type: Option<String>,
    pub has_body: bool,
    pub function_scope: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorHandlingKind {
    TryCatch,
    TryExcept,
    TryFinally,
    Throw,
    ResultMatch,
    QuestionMark,
    Unwrap,
    PromiseCatch,
    AsyncAwaitTry,
    Rescue,
    Defer,
    DeferRecover,
    WithStatement,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocCommentInfo {
    pub text: String,
    pub style: DocCommentStyle,
    pub file: String,
    pub line: u32,
    pub range: Range,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DocCommentStyle {
    JsDoc,
    TripleSlash,
    Docstring,
    Pound,
    KDoc,
    PhpDoc,
    GoDoc,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterInfo {
    pub name: String,
    pub type_annotation: Option<String>,
    pub default_value: Option<String>,
    pub is_rest: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropertyInfo {
    pub name: String,
    pub type_annotation: Option<String>,
    pub is_static: bool,
    pub is_readonly: bool,
    pub visibility: Visibility,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenericParam {
    pub name: String,
    pub bounds: SmallVec<[String; 2]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum Visibility {
    #[default]
    Public,
    Private,
    Protected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct Position {
    pub line: u32,
    pub column: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct Range {
    pub start: Position,
    pub end: Position,
}

impl Range {
    pub fn from_ts_node(node: &tree_sitter::Node) -> Self {
        let start = node.start_position();
        let end = node.end_position();
        Self {
            start: Position {
                line: start.row as u32,
                column: start.column as u32,
            },
            end: Position {
                line: end.row as u32,
                column: end.column as u32,
            },
        }
    }
}
