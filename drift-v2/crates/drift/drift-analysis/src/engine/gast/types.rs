//! GAST node types — ~40-50 variants + `Other` catch-all.

use serde::{Deserialize, Serialize};

/// Generic AST node — language-independent representation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum GASTNode {
    // ---- Program Structure ----
    Program { body: Vec<GASTNode> },
    Module { name: Option<String>, body: Vec<GASTNode> },
    Namespace { name: String, body: Vec<GASTNode> },

    // ---- Declarations ----
    Function {
        name: String,
        params: Vec<GASTNode>,
        body: Box<GASTNode>,
        is_async: bool,
        is_generator: bool,
        return_type: Option<String>,
    },
    Class {
        name: String,
        bases: Vec<String>,
        body: Vec<GASTNode>,
        is_abstract: bool,
    },
    Interface {
        name: String,
        extends: Vec<String>,
        body: Vec<GASTNode>,
    },
    Enum {
        name: String,
        members: Vec<GASTNode>,
    },
    TypeAlias {
        name: String,
        type_expr: Box<GASTNode>,
    },

    // ---- Class Members ----
    Method {
        name: String,
        params: Vec<GASTNode>,
        body: Box<GASTNode>,
        is_async: bool,
        is_static: bool,
        visibility: Visibility,
    },
    Constructor {
        params: Vec<GASTNode>,
        body: Box<GASTNode>,
    },
    Property {
        name: String,
        type_annotation: Option<String>,
        value: Option<Box<GASTNode>>,
        is_static: bool,
        visibility: Visibility,
    },
    Getter { name: String, body: Box<GASTNode> },
    Setter { name: String, param: Box<GASTNode>, body: Box<GASTNode> },

    // ---- Parameters ----
    Parameter {
        name: String,
        type_annotation: Option<String>,
        default_value: Option<Box<GASTNode>>,
        is_rest: bool,
    },

    // ---- Statements ----
    Block { statements: Vec<GASTNode> },
    VariableDeclaration {
        name: String,
        type_annotation: Option<String>,
        value: Option<Box<GASTNode>>,
        is_const: bool,
    },
    Assignment { target: Box<GASTNode>, value: Box<GASTNode> },
    Return { value: Option<Box<GASTNode>> },
    If { condition: Box<GASTNode>, then_branch: Box<GASTNode>, else_branch: Option<Box<GASTNode>> },
    ForLoop { init: Option<Box<GASTNode>>, condition: Option<Box<GASTNode>>, update: Option<Box<GASTNode>>, body: Box<GASTNode> },
    ForEach { variable: Box<GASTNode>, iterable: Box<GASTNode>, body: Box<GASTNode> },
    WhileLoop { condition: Box<GASTNode>, body: Box<GASTNode> },
    Switch { discriminant: Box<GASTNode>, cases: Vec<GASTNode> },
    SwitchCase { test: Option<Box<GASTNode>>, body: Vec<GASTNode> },
    TryCatch { try_block: Box<GASTNode>, catch_param: Option<Box<GASTNode>>, catch_block: Option<Box<GASTNode>>, finally_block: Option<Box<GASTNode>> },
    Throw { value: Box<GASTNode> },
    Yield { value: Option<Box<GASTNode>>, is_delegate: bool },
    Await { value: Box<GASTNode> },

    // ---- Expressions ----
    Call { callee: Box<GASTNode>, arguments: Vec<GASTNode> },
    MethodCall { receiver: Box<GASTNode>, method: String, arguments: Vec<GASTNode> },
    NewExpression { callee: Box<GASTNode>, arguments: Vec<GASTNode> },
    MemberAccess { object: Box<GASTNode>, property: String },
    IndexAccess { object: Box<GASTNode>, index: Box<GASTNode> },
    BinaryOp { left: Box<GASTNode>, op: String, right: Box<GASTNode> },
    UnaryOp { op: String, operand: Box<GASTNode>, is_prefix: bool },
    Ternary { condition: Box<GASTNode>, consequent: Box<GASTNode>, alternate: Box<GASTNode> },
    Lambda { params: Vec<GASTNode>, body: Box<GASTNode>, is_async: bool },
    Identifier { name: String },
    StringLiteral { value: String },
    NumberLiteral { value: String },
    BoolLiteral { value: bool },
    NullLiteral,
    ArrayLiteral { elements: Vec<GASTNode> },
    ObjectLiteral { properties: Vec<GASTNode> },
    TemplateLiteral { parts: Vec<GASTNode> },
    SpreadElement { argument: Box<GASTNode> },

    // ---- Imports/Exports ----
    Import { source: String, specifiers: Vec<GASTNode> },
    ImportSpecifier { name: String, alias: Option<String> },
    Export { declaration: Option<Box<GASTNode>>, is_default: bool },

    // ---- Decorators/Annotations ----
    Decorator { name: String, arguments: Vec<GASTNode> },

    // ---- Comments ----
    Comment { text: String, is_doc: bool },

    // ---- Catch-all — no data loss ----
    Other { kind: String, children: Vec<GASTNode> },
}

/// Visibility modifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum Visibility {
    #[default]
    Public,
    Private,
    Protected,
    Internal,
}

impl GASTNode {
    /// Get the kind name of this node.
    pub fn kind(&self) -> &str {
        match self {
            Self::Program { .. } => "program",
            Self::Module { .. } => "module",
            Self::Namespace { .. } => "namespace",
            Self::Function { .. } => "function",
            Self::Class { .. } => "class",
            Self::Interface { .. } => "interface",
            Self::Enum { .. } => "enum",
            Self::TypeAlias { .. } => "type_alias",
            Self::Method { .. } => "method",
            Self::Constructor { .. } => "constructor",
            Self::Property { .. } => "property",
            Self::Getter { .. } => "getter",
            Self::Setter { .. } => "setter",
            Self::Parameter { .. } => "parameter",
            Self::Block { .. } => "block",
            Self::VariableDeclaration { .. } => "variable_declaration",
            Self::Assignment { .. } => "assignment",
            Self::Return { .. } => "return",
            Self::If { .. } => "if",
            Self::ForLoop { .. } => "for_loop",
            Self::ForEach { .. } => "for_each",
            Self::WhileLoop { .. } => "while_loop",
            Self::Switch { .. } => "switch",
            Self::SwitchCase { .. } => "switch_case",
            Self::TryCatch { .. } => "try_catch",
            Self::Throw { .. } => "throw",
            Self::Yield { .. } => "yield",
            Self::Await { .. } => "await",
            Self::Call { .. } => "call",
            Self::MethodCall { .. } => "method_call",
            Self::NewExpression { .. } => "new_expression",
            Self::MemberAccess { .. } => "member_access",
            Self::IndexAccess { .. } => "index_access",
            Self::BinaryOp { .. } => "binary_op",
            Self::UnaryOp { .. } => "unary_op",
            Self::Ternary { .. } => "ternary",
            Self::Lambda { .. } => "lambda",
            Self::Identifier { .. } => "identifier",
            Self::StringLiteral { .. } => "string_literal",
            Self::NumberLiteral { .. } => "number_literal",
            Self::BoolLiteral { .. } => "bool_literal",
            Self::NullLiteral => "null_literal",
            Self::ArrayLiteral { .. } => "array_literal",
            Self::ObjectLiteral { .. } => "object_literal",
            Self::TemplateLiteral { .. } => "template_literal",
            Self::SpreadElement { .. } => "spread_element",
            Self::Import { .. } => "import",
            Self::ImportSpecifier { .. } => "import_specifier",
            Self::Export { .. } => "export",
            Self::Decorator { .. } => "decorator",
            Self::Comment { .. } => "comment",
            Self::Other { kind, .. } => kind,
        }
    }

    /// Check if this is the catch-all `Other` variant.
    pub fn is_other(&self) -> bool {
        matches!(self, Self::Other { .. })
    }

    /// Count total nodes in this subtree.
    pub fn node_count(&self) -> usize {
        1 + self.children_count()
    }

    fn children_count(&self) -> usize {
        match self {
            Self::Program { body } | Self::Module { body, .. } | Self::Namespace { body, .. } => {
                body.iter().map(|n| n.node_count()).sum()
            }
            Self::Function { params, body, .. } => {
                params.iter().map(|n| n.node_count()).sum::<usize>() + body.node_count()
            }
            Self::Class { body, .. } | Self::Interface { body, .. } => {
                body.iter().map(|n| n.node_count()).sum()
            }
            Self::Block { statements } => statements.iter().map(|n| n.node_count()).sum(),
            Self::Call { callee, arguments } | Self::NewExpression { callee, arguments } => {
                callee.node_count() + arguments.iter().map(|n| n.node_count()).sum::<usize>()
            }
            Self::MethodCall { receiver, arguments, .. } => {
                receiver.node_count() + arguments.iter().map(|n| n.node_count()).sum::<usize>()
            }
            Self::Other { children, .. } => children.iter().map(|n| n.node_count()).sum(),
            _ => 0,
        }
    }
}
