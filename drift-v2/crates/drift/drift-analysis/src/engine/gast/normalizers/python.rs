//! Python GAST normalizer.

use tree_sitter::Node;

use crate::engine::gast::base_normalizer::GASTNormalizer;
use crate::engine::gast::types::GASTNode;
use crate::scanner::language_detect::Language;

pub struct PythonNormalizer;

impl GASTNormalizer for PythonNormalizer {
    fn language(&self) -> Language {
        Language::Python
    }

    fn normalize_node(&self, node: &Node, source: &[u8]) -> GASTNode {
        match node.kind() {
            "module" => {
                let body = self.normalize_children(node, source);
                GASTNode::Program { body }
            }

            "function_definition" => {
                let name = node.child_by_field_name("name")
                    .and_then(|n| n.utf8_text(source).ok())
                    .unwrap_or("")
                    .to_string();
                let params = node.child_by_field_name("parameters")
                    .map(|n| self.normalize_children(&n, source))
                    .unwrap_or_default();
                let body = node.child_by_field_name("body")
                    .map(|n| self.normalize_node(&n, source))
                    .unwrap_or(GASTNode::Block { statements: vec![] });
                let is_async = node.parent()
                    .map(|p| p.kind() == "decorated_definition")
                    .unwrap_or(false)
                    || has_async_keyword(node, source);
                let return_type = node.child_by_field_name("return_type")
                    .and_then(|n| n.utf8_text(source).ok())
                    .map(|s| s.to_string());

                GASTNode::Function {
                    name,
                    params,
                    body: Box::new(body),
                    is_async,
                    is_generator: false,
                    return_type,
                }
            }

            "class_definition" => {
                let name = node.child_by_field_name("name")
                    .and_then(|n| n.utf8_text(source).ok())
                    .unwrap_or("")
                    .to_string();
                let bases = node.child_by_field_name("superclasses")
                    .map(|n| extract_base_classes(&n, source))
                    .unwrap_or_default();
                let body = node.child_by_field_name("body")
                    .map(|n| self.normalize_children(&n, source))
                    .unwrap_or_default();

                GASTNode::Class { name, bases, body, is_abstract: false }
            }

            "decorated_definition" => {
                // Unwrap to the inner definition
                let child_count = node.child_count();
                for i in 0..child_count {
                    if let Some(child) = node.child(i) {
                        if child.kind() == "function_definition" || child.kind() == "class_definition" {
                            return self.normalize_node(&child, source);
                        }
                    }
                }
                let children = self.normalize_children(node, source);
                GASTNode::Other { kind: "decorated_definition".to_string(), children }
            }

            "import_statement" | "import_from_statement" => {
                let source_str = node.child_by_field_name("module_name")
                    .and_then(|n| n.utf8_text(source).ok())
                    .unwrap_or("")
                    .to_string();
                let specifiers = self.normalize_children(node, source);
                GASTNode::Import { source: source_str, specifiers }
            }

            "if_statement" => self.normalize_if(node, source),
            "for_statement" => {
                let variable = node.child_by_field_name("left")
                    .map(|n| self.normalize_node(&n, source))
                    .unwrap_or(GASTNode::Identifier { name: "_".to_string() });
                let iterable = node.child_by_field_name("right")
                    .map(|n| self.normalize_node(&n, source))
                    .unwrap_or(GASTNode::NullLiteral);
                let body = node.child_by_field_name("body")
                    .map(|n| self.normalize_node(&n, source))
                    .unwrap_or(GASTNode::Block { statements: vec![] });
                GASTNode::ForEach {
                    variable: Box::new(variable),
                    iterable: Box::new(iterable),
                    body: Box::new(body),
                }
            }
            "while_statement" => self.normalize_while(node, source),
            "try_statement" => self.normalize_try(node, source),
            "raise_statement" => self.normalize_throw(node, source),
            "return_statement" => self.normalize_return(node, source),
            "await" => self.normalize_await(node, source),
            "yield" => self.normalize_yield(node, source),
            "call" => self.normalize_call(node, source),

            "block" => {
                let stmts = self.normalize_children(node, source);
                GASTNode::Block { statements: stmts }
            }

            "identifier" => {
                let name = node.utf8_text(source).unwrap_or("").to_string();
                GASTNode::Identifier { name }
            }
            "string" | "concatenated_string" => {
                let value = node.utf8_text(source).unwrap_or("").to_string();
                GASTNode::StringLiteral { value }
            }
            "integer" | "float" => {
                let value = node.utf8_text(source).unwrap_or("0").to_string();
                GASTNode::NumberLiteral { value }
            }
            "true" | "True" => GASTNode::BoolLiteral { value: true },
            "false" | "False" => GASTNode::BoolLiteral { value: false },
            "none" | "None" => GASTNode::NullLiteral,

            "comment" => {
                let text = node.utf8_text(source).unwrap_or("").to_string();
                let is_doc = text.starts_with("\"\"\"") || text.starts_with("'''");
                GASTNode::Comment { text, is_doc }
            }

            "expression_statement" => {
                if let Some(child) = node.child(0) {
                    self.normalize_node(&child, source)
                } else {
                    GASTNode::Other { kind: "expression_statement".to_string(), children: vec![] }
                }
            }

            "decorator" => self.normalize_decorator(node, source),

            _ => {
                let children = self.normalize_children(node, source);
                GASTNode::Other { kind: node.kind().to_string(), children }
            }
        }
    }
}

fn has_async_keyword(node: &Node, source: &[u8]) -> bool {
    if let Some(prev) = node.prev_sibling() {
        prev.kind() == "async" || prev.utf8_text(source).ok() == Some("async")
    } else {
        false
    }
}

fn extract_base_classes(node: &Node, source: &[u8]) -> Vec<String> {
    let mut bases = Vec::new();
    let count = node.child_count();
    for i in 0..count {
        if let Some(child) = node.child(i) {
            if child.kind() == "identifier" || child.kind() == "attribute" {
                if let Ok(text) = child.utf8_text(source) {
                    bases.push(text.to_string());
                }
            }
        }
    }
    bases
}
