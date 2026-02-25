//! Java GAST normalizer.

use tree_sitter::Node;
use crate::engine::gast::base_normalizer::GASTNormalizer;
use crate::engine::gast::types::GASTNode;
use crate::scanner::language_detect::Language;

pub struct JavaNormalizer;

impl GASTNormalizer for JavaNormalizer {
    fn language(&self) -> Language {
        Language::Java
    }

    fn normalize_node(&self, node: &Node, source: &[u8]) -> GASTNode {
        match node.kind() {
            "program" | "compilation_unit" => {
                let body = self.normalize_children(node, source);
                GASTNode::Program { body }
            }
            "class_declaration" => {
                let name = node.child_by_field_name("name")
                    .and_then(|n| n.utf8_text(source).ok())
                    .unwrap_or("").to_string();
                let body = node.child_by_field_name("body")
                    .map(|n| self.normalize_children(&n, source))
                    .unwrap_or_default();
                let is_abstract = has_modifier(node, source, "abstract");
                GASTNode::Class { name, bases: vec![], body, is_abstract }
            }
            "interface_declaration" => {
                let name = node.child_by_field_name("name")
                    .and_then(|n| n.utf8_text(source).ok())
                    .unwrap_or("").to_string();
                let body = node.child_by_field_name("body")
                    .map(|n| self.normalize_children(&n, source))
                    .unwrap_or_default();
                GASTNode::Interface { name, extends: vec![], body }
            }
            "enum_declaration" => self.normalize_enum(node, source),
            "method_declaration" | "constructor_declaration" => self.normalize_function(node, source),
            "if_statement" => self.normalize_if(node, source),
            "for_statement" | "enhanced_for_statement" => self.normalize_for(node, source),
            "while_statement" => self.normalize_while(node, source),
            "switch_expression" => self.normalize_switch(node, source),
            "try_statement" | "try_with_resources_statement" => self.normalize_try(node, source),
            "throw_statement" => self.normalize_throw(node, source),
            "return_statement" => self.normalize_return(node, source),
            "method_invocation" => self.normalize_call(node, source),
            "import_declaration" => self.normalize_import(node, source),
            "block" => {
                let stmts = self.normalize_children(node, source);
                GASTNode::Block { statements: stmts }
            }
            "identifier" | "type_identifier" => {
                let name = node.utf8_text(source).unwrap_or("").to_string();
                GASTNode::Identifier { name }
            }
            "string_literal" | "text_block" => {
                let value = node.utf8_text(source).unwrap_or("").to_string();
                GASTNode::StringLiteral { value }
            }
            "decimal_integer_literal" | "decimal_floating_point_literal" => {
                let value = node.utf8_text(source).unwrap_or("0").to_string();
                GASTNode::NumberLiteral { value }
            }
            "true" => GASTNode::BoolLiteral { value: true },
            "false" => GASTNode::BoolLiteral { value: false },
            "null_literal" => GASTNode::NullLiteral,
            "line_comment" | "block_comment" => {
                let text = node.utf8_text(source).unwrap_or("").to_string();
                let is_doc = text.starts_with("/**");
                GASTNode::Comment { text, is_doc }
            }
            "marker_annotation" | "annotation" => self.normalize_decorator(node, source),
            _ => {
                let children = self.normalize_children(node, source);
                GASTNode::Other { kind: node.kind().to_string(), children }
            }
        }
    }
}

fn has_modifier(node: &Node, source: &[u8], modifier: &str) -> bool {
    if let Some(mods) = node.child_by_field_name("modifiers") {
        let count = mods.child_count();
        for i in 0..count {
            if let Some(child) = mods.child(i) {
                if child.utf8_text(source).ok() == Some(modifier) {
                    return true;
                }
            }
        }
    }
    false
}
