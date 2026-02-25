//! C++ GAST normalizer (also covers C).

use tree_sitter::Node;
use crate::engine::gast::base_normalizer::GASTNormalizer;
use crate::engine::gast::types::GASTNode;
use crate::scanner::language_detect::Language;

/// C++ normalizer — used as a fallback for C-family languages without a dedicated normalizer.
pub struct CppNormalizer;

impl GASTNormalizer for CppNormalizer {
    fn language(&self) -> Language { Language::Cpp }

    fn normalize_node(&self, node: &Node, source: &[u8]) -> GASTNode {
        match node.kind() {
            "translation_unit" => {
                let body = self.normalize_children(node, source);
                GASTNode::Program { body }
            }
            "function_definition" | "function_declarator" => self.normalize_function(node, source),
            "class_specifier" | "struct_specifier" => {
                let name = node.child_by_field_name("name")
                    .and_then(|n| n.utf8_text(source).ok())
                    .unwrap_or("").to_string();
                let body = node.child_by_field_name("body")
                    .map(|n| self.normalize_children(&n, source))
                    .unwrap_or_default();
                GASTNode::Class { name, bases: vec![], body, is_abstract: false }
            }
            "enum_specifier" => self.normalize_enum(node, source),
            "namespace_definition" => {
                let name = node.child_by_field_name("name")
                    .and_then(|n| n.utf8_text(source).ok())
                    .unwrap_or("").to_string();
                let body = node.child_by_field_name("body")
                    .map(|n| self.normalize_children(&n, source))
                    .unwrap_or_default();
                GASTNode::Namespace { name, body }
            }
            "if_statement" => self.normalize_if(node, source),
            "for_statement" | "for_range_loop" => self.normalize_for(node, source),
            "while_statement" => self.normalize_while(node, source),
            "switch_statement" => self.normalize_switch(node, source),
            "try_statement" => self.normalize_try(node, source),
            "throw_statement" => self.normalize_throw(node, source),
            "return_statement" => self.normalize_return(node, source),
            "call_expression" => self.normalize_call(node, source),
            "preproc_include" => {
                let path = node.child_by_field_name("path")
                    .and_then(|n| n.utf8_text(source).ok())
                    .unwrap_or("").to_string();
                GASTNode::Import { source: path, specifiers: vec![] }
            }
            "compound_statement" => {
                let stmts = self.normalize_children(node, source);
                GASTNode::Block { statements: stmts }
            }
            "identifier" | "field_identifier" | "type_identifier" | "namespace_identifier" => {
                let name = node.utf8_text(source).unwrap_or("").to_string();
                GASTNode::Identifier { name }
            }
            "string_literal" | "raw_string_literal" | "char_literal" => {
                let value = node.utf8_text(source).unwrap_or("").to_string();
                GASTNode::StringLiteral { value }
            }
            "number_literal" => {
                let value = node.utf8_text(source).unwrap_or("0").to_string();
                GASTNode::NumberLiteral { value }
            }
            "true" => GASTNode::BoolLiteral { value: true },
            "false" => GASTNode::BoolLiteral { value: false },
            "null" | "nullptr" => GASTNode::NullLiteral,
            "comment" => {
                let text = node.utf8_text(source).unwrap_or("").to_string();
                let is_doc = text.starts_with("/**") || text.starts_with("///");
                GASTNode::Comment { text, is_doc }
            }
            "lambda_expression" => self.normalize_lambda(node, source),
            _ => {
                let children = self.normalize_children(node, source);
                GASTNode::Other { kind: node.kind().to_string(), children }
            }
        }
    }
}
