//! Rust GAST normalizer.

use tree_sitter::Node;
use crate::engine::gast::base_normalizer::GASTNormalizer;
use crate::engine::gast::types::GASTNode;
use crate::scanner::language_detect::Language;

pub struct RustNormalizer;

impl GASTNormalizer for RustNormalizer {
    fn language(&self) -> Language { Language::Rust }

    fn normalize_node(&self, node: &Node, source: &[u8]) -> GASTNode {
        match node.kind() {
            "source_file" => {
                let body = self.normalize_children(node, source);
                GASTNode::Program { body }
            }
            "function_item" => self.normalize_function(node, source),
            "struct_item" => {
                let name = node.child_by_field_name("name")
                    .and_then(|n| n.utf8_text(source).ok())
                    .unwrap_or("").to_string();
                let body = node.child_by_field_name("body")
                    .map(|n| self.normalize_children(&n, source))
                    .unwrap_or_default();
                GASTNode::Class { name, bases: vec![], body, is_abstract: false }
            }
            "impl_item" => {
                let name = node.child_by_field_name("type")
                    .and_then(|n| n.utf8_text(source).ok())
                    .unwrap_or("").to_string();
                let body = node.child_by_field_name("body")
                    .map(|n| self.normalize_children(&n, source))
                    .unwrap_or_default();
                GASTNode::Class { name, bases: vec![], body, is_abstract: false }
            }
            "trait_item" => self.normalize_interface(node, source),
            "enum_item" => self.normalize_enum(node, source),
            "type_item" => {
                let name = node.child_by_field_name("name")
                    .and_then(|n| n.utf8_text(source).ok())
                    .unwrap_or("").to_string();
                let type_expr = node.child_by_field_name("type")
                    .map(|n| self.normalize_node(&n, source))
                    .unwrap_or(GASTNode::Other { kind: "type".to_string(), children: vec![] });
                GASTNode::TypeAlias { name, type_expr: Box::new(type_expr) }
            }
            "mod_item" => {
                let name = node.child_by_field_name("name")
                    .and_then(|n| n.utf8_text(source).ok())
                    .unwrap_or("").to_string();
                let body = node.child_by_field_name("body")
                    .map(|n| self.normalize_children(&n, source))
                    .unwrap_or_default();
                GASTNode::Module { name: Some(name), body }
            }
            "if_expression" => self.normalize_if(node, source),
            "for_expression" => self.normalize_for(node, source),
            "while_expression" | "loop_expression" => self.normalize_while(node, source),
            "match_expression" => self.normalize_switch(node, source),
            "return_expression" => self.normalize_return(node, source),
            "call_expression" => self.normalize_call(node, source),
            "use_declaration" => self.normalize_import(node, source),
            "block" => {
                let stmts = self.normalize_children(node, source);
                GASTNode::Block { statements: stmts }
            }
            "let_declaration" => {
                let name = node.child_by_field_name("pattern")
                    .and_then(|n| n.utf8_text(source).ok())
                    .unwrap_or("").to_string();
                let value = node.child_by_field_name("value")
                    .map(|n| Box::new(self.normalize_node(&n, source)));
                let type_annotation = node.child_by_field_name("type")
                    .and_then(|n| n.utf8_text(source).ok())
                    .map(|s| s.to_string());
                GASTNode::VariableDeclaration { name, type_annotation, value, is_const: false }
            }
            "identifier" | "type_identifier" | "field_identifier" => {
                let name = node.utf8_text(source).unwrap_or("").to_string();
                GASTNode::Identifier { name }
            }
            "string_literal" | "raw_string_literal" => {
                let value = node.utf8_text(source).unwrap_or("").to_string();
                GASTNode::StringLiteral { value }
            }
            "integer_literal" | "float_literal" => {
                let value = node.utf8_text(source).unwrap_or("0").to_string();
                GASTNode::NumberLiteral { value }
            }
            "true" => GASTNode::BoolLiteral { value: true },
            "false" => GASTNode::BoolLiteral { value: false },
            "line_comment" | "block_comment" => {
                let text = node.utf8_text(source).unwrap_or("").to_string();
                let is_doc = text.starts_with("///") || text.starts_with("//!");
                GASTNode::Comment { text, is_doc }
            }
            "attribute_item" | "inner_attribute_item" => self.normalize_decorator(node, source),
            "macro_invocation" => self.normalize_call(node, source),
            "closure_expression" => self.normalize_lambda(node, source),
            "await_expression" => self.normalize_await(node, source),
            "try_expression" | "question_mark_expression" => {
                // Rust's ? operator
                let value = node.child(0)
                    .map(|n| self.normalize_node(&n, source))
                    .unwrap_or(GASTNode::NullLiteral);
                GASTNode::Await { value: Box::new(value) } // Reuse Await for ? semantics
            }
            _ => {
                let children = self.normalize_children(node, source);
                GASTNode::Other { kind: node.kind().to_string(), children }
            }
        }
    }
}
