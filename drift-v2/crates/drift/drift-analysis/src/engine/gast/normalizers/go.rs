//! Go GAST normalizer.

use tree_sitter::Node;
use crate::engine::gast::base_normalizer::GASTNormalizer;
use crate::engine::gast::types::GASTNode;
use crate::scanner::language_detect::Language;

pub struct GoNormalizer;

impl GASTNormalizer for GoNormalizer {
    fn language(&self) -> Language { Language::Go }

    fn normalize_node(&self, node: &Node, source: &[u8]) -> GASTNode {
        match node.kind() {
            "source_file" => {
                let body = self.normalize_children(node, source);
                GASTNode::Program { body }
            }
            "function_declaration" | "method_declaration" => self.normalize_function(node, source),
            "type_declaration" => {
                // Could be struct, interface, or type alias
                if let Some(spec) = node.child_by_field_name("type") {
                    self.normalize_node(&spec, source)
                } else {
                    let children = self.normalize_children(node, source);
                    GASTNode::Other { kind: "type_declaration".to_string(), children }
                }
            }
            "struct_type" => {
                let name = node.parent()
                    .and_then(|p| p.child_by_field_name("name"))
                    .and_then(|n| n.utf8_text(source).ok())
                    .unwrap_or("").to_string();
                let body = node.child_by_field_name("body")
                    .or_else(|| find_child_by_kind(node, "field_declaration_list"))
                    .map(|n| self.normalize_children(&n, source))
                    .unwrap_or_default();
                GASTNode::Class { name, bases: vec![], body, is_abstract: false }
            }
            "interface_type" => {
                let name = node.parent()
                    .and_then(|p| p.child_by_field_name("name"))
                    .and_then(|n| n.utf8_text(source).ok())
                    .unwrap_or("").to_string();
                let body = self.normalize_children(node, source);
                GASTNode::Interface { name, extends: vec![], body }
            }
            "if_statement" => self.normalize_if(node, source),
            "for_statement" => self.normalize_for(node, source),
            "switch_statement" | "type_switch_statement" => self.normalize_switch(node, source),
            "return_statement" => self.normalize_return(node, source),
            "call_expression" => self.normalize_call(node, source),
            "import_declaration" => self.normalize_import(node, source),
            "block" => {
                let stmts = self.normalize_children(node, source);
                GASTNode::Block { statements: stmts }
            }
            "identifier" | "field_identifier" | "type_identifier" | "package_identifier" => {
                let name = node.utf8_text(source).unwrap_or("").to_string();
                GASTNode::Identifier { name }
            }
            "raw_string_literal" | "interpreted_string_literal" => {
                let value = node.utf8_text(source).unwrap_or("").to_string();
                GASTNode::StringLiteral { value }
            }
            "int_literal" | "float_literal" => {
                let value = node.utf8_text(source).unwrap_or("0").to_string();
                GASTNode::NumberLiteral { value }
            }
            "true" => GASTNode::BoolLiteral { value: true },
            "false" => GASTNode::BoolLiteral { value: false },
            "nil" => GASTNode::NullLiteral,
            "comment" => {
                let text = node.utf8_text(source).unwrap_or("").to_string();
                let is_doc = text.starts_with("//");
                GASTNode::Comment { text, is_doc }
            }
            _ => {
                let children = self.normalize_children(node, source);
                GASTNode::Other { kind: node.kind().to_string(), children }
            }
        }
    }
}

fn find_child_by_kind<'a>(node: &Node<'a>, kind: &str) -> Option<Node<'a>> {
    let count = node.child_count();
    for i in 0..count {
        if let Some(child) = node.child(i) {
            if child.kind() == kind {
                return Some(child);
            }
        }
    }
    None
}
