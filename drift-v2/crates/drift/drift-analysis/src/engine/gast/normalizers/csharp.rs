//! C# GAST normalizer.

use tree_sitter::Node;
use crate::engine::gast::base_normalizer::GASTNormalizer;
use crate::engine::gast::types::GASTNode;
use crate::scanner::language_detect::Language;

pub struct CSharpNormalizer;

impl GASTNormalizer for CSharpNormalizer {
    fn language(&self) -> Language { Language::CSharp }

    fn normalize_node(&self, node: &Node, source: &[u8]) -> GASTNode {
        match node.kind() {
            "compilation_unit" => {
                let body = self.normalize_children(node, source);
                GASTNode::Program { body }
            }
            "class_declaration" | "record_declaration" | "struct_declaration" => {
                let name = node.child_by_field_name("name")
                    .and_then(|n| n.utf8_text(source).ok())
                    .unwrap_or("").to_string();
                let body = node.child_by_field_name("body")
                    .map(|n| self.normalize_children(&n, source))
                    .unwrap_or_default();
                GASTNode::Class { name, bases: vec![], body, is_abstract: false }
            }
            "interface_declaration" => self.normalize_interface(node, source),
            "enum_declaration" => self.normalize_enum(node, source),
            "namespace_declaration" => {
                let name = node.child_by_field_name("name")
                    .and_then(|n| n.utf8_text(source).ok())
                    .unwrap_or("").to_string();
                let body = node.child_by_field_name("body")
                    .map(|n| self.normalize_children(&n, source))
                    .unwrap_or_default();
                GASTNode::Namespace { name, body }
            }
            "method_declaration" | "constructor_declaration" => self.normalize_function(node, source),
            "if_statement" => self.normalize_if(node, source),
            "for_statement" | "foreach_statement" | "for_each_statement" => self.normalize_for(node, source),
            "while_statement" => self.normalize_while(node, source),
            "switch_statement" | "switch_expression" => self.normalize_switch(node, source),
            "try_statement" => self.normalize_try(node, source),
            "throw_statement" | "throw_expression" => self.normalize_throw(node, source),
            "return_statement" => self.normalize_return(node, source),
            "await_expression" => self.normalize_await(node, source),
            "invocation_expression" => self.normalize_call(node, source),
            "using_directive" => self.normalize_import(node, source),
            "block" => {
                let stmts = self.normalize_children(node, source);
                GASTNode::Block { statements: stmts }
            }
            "identifier" | "generic_name" => {
                let name = node.utf8_text(source).unwrap_or("").to_string();
                GASTNode::Identifier { name }
            }
            "string_literal" | "verbatim_string_literal" | "interpolated_string_expression" | "raw_string_literal" => {
                let value = node.utf8_text(source).unwrap_or("").to_string();
                GASTNode::StringLiteral { value }
            }
            "integer_literal" | "real_literal" => {
                let value = node.utf8_text(source).unwrap_or("0").to_string();
                GASTNode::NumberLiteral { value }
            }
            "true" => GASTNode::BoolLiteral { value: true },
            "false" => GASTNode::BoolLiteral { value: false },
            "null_literal" => GASTNode::NullLiteral,
            "comment" | "line_comment" | "block_comment" => {
                let text = node.utf8_text(source).unwrap_or("").to_string();
                let is_doc = text.starts_with("///");
                GASTNode::Comment { text, is_doc }
            }
            "attribute" | "attribute_list" => self.normalize_decorator(node, source),
            _ => {
                let children = self.normalize_children(node, source);
                GASTNode::Other { kind: node.kind().to_string(), children }
            }
        }
    }
}
