//! PHP GAST normalizer.

use tree_sitter::Node;
use crate::engine::gast::base_normalizer::GASTNormalizer;
use crate::engine::gast::types::GASTNode;
use crate::scanner::language_detect::Language;

pub struct PhpNormalizer;

impl GASTNormalizer for PhpNormalizer {
    fn language(&self) -> Language { Language::Php }

    fn normalize_node(&self, node: &Node, source: &[u8]) -> GASTNode {
        match node.kind() {
            "program" => {
                let body = self.normalize_children(node, source);
                GASTNode::Program { body }
            }
            "function_definition" | "method_declaration" => self.normalize_function(node, source),
            "class_declaration" => self.normalize_class(node, source),
            "interface_declaration" => self.normalize_interface(node, source),
            "trait_declaration" => {
                let name = node.child_by_field_name("name")
                    .and_then(|n| n.utf8_text(source).ok())
                    .unwrap_or("").to_string();
                let body = node.child_by_field_name("body")
                    .map(|n| self.normalize_children(&n, source))
                    .unwrap_or_default();
                GASTNode::Interface { name, extends: vec![], body }
            }
            "enum_declaration" => self.normalize_enum(node, source),
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
            "for_statement" | "foreach_statement" => self.normalize_for(node, source),
            "while_statement" => self.normalize_while(node, source),
            "switch_statement" | "match_expression" => self.normalize_switch(node, source),
            "try_statement" => self.normalize_try(node, source),
            "throw_expression" => self.normalize_throw(node, source),
            "return_statement" => self.normalize_return(node, source),
            "function_call_expression" | "member_call_expression" | "scoped_call_expression" => {
                self.normalize_call(node, source)
            }
            "use_declaration" => self.normalize_import(node, source),
            "compound_statement" => {
                let stmts = self.normalize_children(node, source);
                GASTNode::Block { statements: stmts }
            }
            "name" | "qualified_name" | "variable_name" => {
                let name = node.utf8_text(source).unwrap_or("").to_string();
                GASTNode::Identifier { name }
            }
            "string" | "encapsed_string" | "heredoc" | "nowdoc" => {
                let value = node.utf8_text(source).unwrap_or("").to_string();
                GASTNode::StringLiteral { value }
            }
            "integer" | "float" => {
                let value = node.utf8_text(source).unwrap_or("0").to_string();
                GASTNode::NumberLiteral { value }
            }
            "true" | "True" | "TRUE" => GASTNode::BoolLiteral { value: true },
            "false" | "False" | "FALSE" => GASTNode::BoolLiteral { value: false },
            "null" | "NULL" => GASTNode::NullLiteral,
            "comment" => {
                let text = node.utf8_text(source).unwrap_or("").to_string();
                let is_doc = text.starts_with("/**");
                GASTNode::Comment { text, is_doc }
            }
            "attribute" | "attribute_group" => self.normalize_decorator(node, source),
            "arrow_function" => self.normalize_lambda(node, source),
            "anonymous_function_creation_expression" => self.normalize_lambda(node, source),
            _ => {
                let children = self.normalize_children(node, source);
                GASTNode::Other { kind: node.kind().to_string(), children }
            }
        }
    }
}
