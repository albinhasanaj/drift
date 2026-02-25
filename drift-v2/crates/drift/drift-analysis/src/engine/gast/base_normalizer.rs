//! Base normalizer with default behavior for all node types.
//!
//! Language-specific normalizers override methods for their language's AST structure.

use tree_sitter::Node;

use crate::scanner::language_detect::Language;

use super::types::GASTNode;

/// Trait for language-specific GAST normalizers.
pub trait GASTNormalizer: Send + Sync {
    /// The language this normalizer handles.
    fn language(&self) -> Language;

    /// Normalize a tree-sitter AST into a GAST tree.
    fn normalize(&self, tree: &tree_sitter::Tree, source: &[u8]) -> GASTNode {
        self.normalize_node(&tree.root_node(), source)
    }

    /// Normalize a single node and its children.
    fn normalize_node(&self, node: &Node, source: &[u8]) -> GASTNode {
        let kind = node.kind();
        match kind {
            // Program/module root
            "program" | "source_file" | "compilation_unit" | "module" => {
                let body = self.normalize_children(node, source);
                GASTNode::Program { body }
            }

            // Function declarations
            "function_declaration" | "function_definition" | "method_declaration"
            | "function_item" => self.normalize_function(node, source),

            // Arrow functions / lambdas
            "arrow_function" | "lambda" | "lambda_expression" | "closure_expression" => {
                self.normalize_lambda(node, source)
            }

            // Class declarations
            "class_declaration" | "class_definition" | "class_specifier"
            | "struct_item" | "impl_item" => self.normalize_class(node, source),

            // Interface declarations
            "interface_declaration" | "trait_item" | "protocol_declaration" => {
                self.normalize_interface(node, source)
            }

            // Enum declarations
            "enum_declaration" | "enum_item" | "enum_specifier" => {
                self.normalize_enum(node, source)
            }

            // Variable declarations
            "variable_declaration" | "lexical_declaration" | "let_declaration"
            | "const_declaration" | "assignment_expression" | "expression_statement" => {
                self.normalize_variable(node, source)
            }

            // Control flow
            "if_statement" | "if_expression" => self.normalize_if(node, source),
            "for_statement" | "for_in_statement" | "for_of_statement" => {
                self.normalize_for(node, source)
            }
            "while_statement" | "while_expression" => self.normalize_while(node, source),
            "switch_statement" | "match_expression" => self.normalize_switch(node, source),

            // Error handling
            "try_statement" | "try_expression" => self.normalize_try(node, source),
            "throw_statement" | "raise_statement" => self.normalize_throw(node, source),

            // Return/yield/await
            "return_statement" => self.normalize_return(node, source),
            "yield_expression" => self.normalize_yield(node, source),
            "await_expression" => self.normalize_await(node, source),

            // Calls
            "call_expression" | "function_call" | "invocation_expression" => {
                self.normalize_call(node, source)
            }

            // Imports
            "import_statement" | "import_declaration" | "use_declaration" => {
                self.normalize_import(node, source)
            }

            // Exports
            "export_statement" | "export_declaration" => {
                self.normalize_export(node, source)
            }

            // Block
            "statement_block" | "block" | "compound_statement" | "body" => {
                let stmts = self.normalize_children(node, source);
                GASTNode::Block { statements: stmts }
            }

            // Identifiers
            "identifier" | "property_identifier" | "type_identifier"
            | "shorthand_property_identifier" => {
                let name = node.utf8_text(source).unwrap_or("").to_string();
                GASTNode::Identifier { name }
            }

            // Literals
            "string" | "string_literal" | "template_string" => {
                let value = node.utf8_text(source).unwrap_or("").to_string();
                GASTNode::StringLiteral { value }
            }
            "number" | "integer_literal" | "float_literal" | "number_literal" => {
                let value = node.utf8_text(source).unwrap_or("0").to_string();
                GASTNode::NumberLiteral { value }
            }
            "true" | "false" => {
                GASTNode::BoolLiteral { value: kind == "true" }
            }
            "null" | "none" | "nil" | "None" => GASTNode::NullLiteral,

            // Comments
            "comment" | "line_comment" | "block_comment" => {
                let text = node.utf8_text(source).unwrap_or("").to_string();
                let is_doc = text.starts_with("///") || text.starts_with("/**") || text.starts_with("\"\"\"");
                GASTNode::Comment { text, is_doc }
            }

            // Decorator
            "decorator" | "annotation" => self.normalize_decorator(node, source),

            // Catch-all: preserve the node kind and recurse into children
            _ => {
                let children = self.normalize_children(node, source);
                if children.is_empty() {
                    GASTNode::Other { kind: kind.to_string(), children: vec![] }
                } else {
                    GASTNode::Other { kind: kind.to_string(), children }
                }
            }
        }
    }

    /// Normalize all children of a node.
    fn normalize_children(&self, node: &Node, source: &[u8]) -> Vec<GASTNode> {
        let mut children = Vec::new();
        let count = node.child_count();
        for i in 0..count {
            if let Some(child) = node.child(i) {
                // Skip punctuation and keywords
                if !is_punctuation(child.kind()) {
                    children.push(self.normalize_node(&child, source));
                }
            }
        }
        children
    }

    // ---- Override points for language-specific behavior ----

    fn normalize_function(&self, node: &Node, source: &[u8]) -> GASTNode {
        let name = find_child_text(node, "name", source)
            .or_else(|| find_child_text(node, "identifier", source))
            .unwrap_or_default();
        let params = find_child_node(node, "parameters")
            .or_else(|| find_child_node(node, "formal_parameters"))
            .map(|n| self.normalize_children(&n, source))
            .unwrap_or_default();
        let body = find_child_node(node, "body")
            .or_else(|| find_child_node(node, "statement_block"))
            .or_else(|| find_child_node(node, "block"))
            .map(|n| self.normalize_node(&n, source))
            .unwrap_or(GASTNode::Block { statements: vec![] });
        let is_async = has_child_kind(node, "async");

        GASTNode::Function {
            name,
            params,
            body: Box::new(body),
            is_async,
            is_generator: false,
            return_type: None,
        }
    }

    fn normalize_lambda(&self, node: &Node, source: &[u8]) -> GASTNode {
        let params = find_child_node(node, "parameters")
            .or_else(|| find_child_node(node, "formal_parameters"))
            .map(|n| self.normalize_children(&n, source))
            .unwrap_or_default();
        let body = find_child_node(node, "body")
            .or_else(|| node.child(node.child_count().saturating_sub(1)))
            .map(|n| self.normalize_node(&n, source))
            .unwrap_or(GASTNode::Block { statements: vec![] });
        let is_async = has_child_kind(node, "async");

        GASTNode::Lambda {
            params,
            body: Box::new(body),
            is_async,
        }
    }

    fn normalize_class(&self, node: &Node, source: &[u8]) -> GASTNode {
        let name = find_child_text(node, "name", source)
            .or_else(|| find_child_text(node, "identifier", source))
            .or_else(|| find_child_text(node, "type_identifier", source))
            .unwrap_or_default();
        let body = find_child_node(node, "body")
            .or_else(|| find_child_node(node, "class_body"))
            .map(|n| self.normalize_children(&n, source))
            .unwrap_or_default();

        GASTNode::Class {
            name,
            bases: vec![],
            body,
            is_abstract: false,
        }
    }

    fn normalize_interface(&self, node: &Node, source: &[u8]) -> GASTNode {
        let name = find_child_text(node, "name", source)
            .or_else(|| find_child_text(node, "identifier", source))
            .unwrap_or_default();
        let body = find_child_node(node, "body")
            .map(|n| self.normalize_children(&n, source))
            .unwrap_or_default();

        GASTNode::Interface {
            name,
            extends: vec![],
            body,
        }
    }

    fn normalize_enum(&self, node: &Node, source: &[u8]) -> GASTNode {
        let name = find_child_text(node, "name", source)
            .or_else(|| find_child_text(node, "identifier", source))
            .unwrap_or_default();
        let members = find_child_node(node, "body")
            .map(|n| self.normalize_children(&n, source))
            .unwrap_or_default();

        GASTNode::Enum { name, members }
    }

    fn normalize_variable(&self, node: &Node, source: &[u8]) -> GASTNode {
        let children = self.normalize_children(node, source);
        if children.len() == 1 {
            return children.into_iter().next().unwrap();
        }
        GASTNode::VariableDeclaration {
            name: find_child_text(node, "name", source).unwrap_or_default(),
            type_annotation: None,
            value: children.into_iter().last().map(Box::new),
            is_const: node.kind().contains("const") || node.kind().contains("let"),
        }
    }

    fn normalize_if(&self, node: &Node, source: &[u8]) -> GASTNode {
        let condition = find_child_node(node, "condition")
            .or_else(|| find_child_node(node, "parenthesized_expression"))
            .map(|n| self.normalize_node(&n, source))
            .unwrap_or(GASTNode::Other { kind: "missing_condition".to_string(), children: vec![] });
        let then_branch = find_child_node(node, "consequence")
            .or_else(|| find_child_node(node, "body"))
            .or_else(|| find_child_node(node, "statement_block"))
            .map(|n| self.normalize_node(&n, source))
            .unwrap_or(GASTNode::Block { statements: vec![] });
        let else_branch = find_child_node(node, "alternative")
            .or_else(|| find_child_node(node, "else_clause"))
            .map(|n| Box::new(self.normalize_node(&n, source)));

        GASTNode::If {
            condition: Box::new(condition),
            then_branch: Box::new(then_branch),
            else_branch,
        }
    }

    fn normalize_for(&self, node: &Node, source: &[u8]) -> GASTNode {
        let body = find_child_node(node, "body")
            .or_else(|| find_child_node(node, "statement_block"))
            .map(|n| self.normalize_node(&n, source))
            .unwrap_or(GASTNode::Block { statements: vec![] });

        GASTNode::ForLoop {
            init: None,
            condition: None,
            update: None,
            body: Box::new(body),
        }
    }

    fn normalize_while(&self, node: &Node, source: &[u8]) -> GASTNode {
        let condition = find_child_node(node, "condition")
            .map(|n| self.normalize_node(&n, source))
            .unwrap_or(GASTNode::BoolLiteral { value: true });
        let body = find_child_node(node, "body")
            .map(|n| self.normalize_node(&n, source))
            .unwrap_or(GASTNode::Block { statements: vec![] });

        GASTNode::WhileLoop {
            condition: Box::new(condition),
            body: Box::new(body),
        }
    }

    fn normalize_switch(&self, node: &Node, source: &[u8]) -> GASTNode {
        let discriminant = find_child_node(node, "value")
            .or_else(|| node.child(1))
            .map(|n| self.normalize_node(&n, source))
            .unwrap_or(GASTNode::Other { kind: "missing".to_string(), children: vec![] });
        let cases = find_child_node(node, "body")
            .map(|n| self.normalize_children(&n, source))
            .unwrap_or_default();

        GASTNode::Switch {
            discriminant: Box::new(discriminant),
            cases,
        }
    }

    fn normalize_try(&self, node: &Node, source: &[u8]) -> GASTNode {
        let try_block = find_child_node(node, "body")
            .or_else(|| find_child_node(node, "statement_block"))
            .map(|n| self.normalize_node(&n, source))
            .unwrap_or(GASTNode::Block { statements: vec![] });
        let catch_block = find_child_node(node, "handler")
            .or_else(|| find_child_node(node, "catch_clause"))
            .map(|n| self.normalize_node(&n, source));
        let finally_block = find_child_node(node, "finalizer")
            .or_else(|| find_child_node(node, "finally_clause"))
            .map(|n| self.normalize_node(&n, source));

        GASTNode::TryCatch {
            try_block: Box::new(try_block),
            catch_param: None,
            catch_block: catch_block.map(Box::new),
            finally_block: finally_block.map(Box::new),
        }
    }

    fn normalize_throw(&self, node: &Node, source: &[u8]) -> GASTNode {
        let value = node.child(1)
            .map(|n| self.normalize_node(&n, source))
            .unwrap_or(GASTNode::NullLiteral);
        GASTNode::Throw { value: Box::new(value) }
    }

    fn normalize_return(&self, node: &Node, source: &[u8]) -> GASTNode {
        let value = node.child(1).map(|n| self.normalize_node(&n, source));
        GASTNode::Return { value: value.map(Box::new) }
    }

    fn normalize_yield(&self, node: &Node, source: &[u8]) -> GASTNode {
        let value = node.child(1).map(|n| self.normalize_node(&n, source));
        GASTNode::Yield { value: value.map(Box::new), is_delegate: false }
    }

    fn normalize_await(&self, node: &Node, source: &[u8]) -> GASTNode {
        let value = node.child(1)
            .map(|n| self.normalize_node(&n, source))
            .unwrap_or(GASTNode::NullLiteral);
        GASTNode::Await { value: Box::new(value) }
    }

    fn normalize_call(&self, node: &Node, source: &[u8]) -> GASTNode {
        let callee = node.child_by_field_name("function")
            .or_else(|| node.child(0))
            .map(|n| self.normalize_node(&n, source))
            .unwrap_or(GASTNode::Identifier { name: "unknown".to_string() });
        let arguments = find_child_node(node, "arguments")
            .map(|n| self.normalize_children(&n, source))
            .unwrap_or_default();

        // Check if it's a method call (receiver.method pattern)
        if let GASTNode::MemberAccess { object, property } = &callee {
            return GASTNode::MethodCall {
                receiver: object.clone(),
                method: property.clone(),
                arguments,
            };
        }

        GASTNode::Call {
            callee: Box::new(callee),
            arguments,
        }
    }

    fn normalize_import(&self, node: &Node, source: &[u8]) -> GASTNode {
        let source_str = find_child_node(node, "source")
            .and_then(|n| n.utf8_text(source).ok())
            .map(|s| s.trim_matches(|c| c == '"' || c == '\'').to_string())
            .unwrap_or_default();
        let specifiers = self.normalize_children(node, source);

        GASTNode::Import {
            source: source_str,
            specifiers,
        }
    }

    fn normalize_export(&self, node: &Node, source: &[u8]) -> GASTNode {
        let declaration = node.child(1).map(|n| Box::new(self.normalize_node(&n, source)));
        let is_default = has_child_kind(node, "default");

        GASTNode::Export {
            declaration,
            is_default,
        }
    }

    fn normalize_decorator(&self, node: &Node, source: &[u8]) -> GASTNode {
        let name = find_child_text(node, "identifier", source)
            .or_else(|| node.child(1).and_then(|n| n.utf8_text(source).ok()).map(|s| s.to_string()))
            .unwrap_or_default();
        let arguments = find_child_node(node, "arguments")
            .map(|n| self.normalize_children(&n, source))
            .unwrap_or_default();

        GASTNode::Decorator { name, arguments }
    }
}

/// Base normalizer that uses the default trait implementations.
pub struct BaseNormalizer;

impl GASTNormalizer for BaseNormalizer {
    fn language(&self) -> Language {
        Language::TypeScript // Default; overridden by specific normalizers
    }
}

// ---- Helper functions ----

fn find_child_text<'a>(node: &Node<'a>, field: &str, source: &'a [u8]) -> Option<String> {
    node.child_by_field_name(field)
        .and_then(|n| n.utf8_text(source).ok())
        .map(|s| s.to_string())
}

fn find_child_node<'a>(node: &Node<'a>, field: &str) -> Option<Node<'a>> {
    node.child_by_field_name(field).or_else(|| {
        // Fallback: search by kind
        let count = node.child_count();
        for i in 0..count {
            if let Some(child) = node.child(i) {
                if child.kind() == field {
                    return Some(child);
                }
            }
        }
        None
    })
}

fn has_child_kind(node: &Node, kind: &str) -> bool {
    let count = node.child_count();
    for i in 0..count {
        if let Some(child) = node.child(i) {
            if child.kind() == kind {
                return true;
            }
        }
    }
    false
}

fn is_punctuation(kind: &str) -> bool {
    matches!(kind, "(" | ")" | "{" | "}" | "[" | "]" | ";" | "," | ":" | "." | "=>" | "=" | "::")
}
