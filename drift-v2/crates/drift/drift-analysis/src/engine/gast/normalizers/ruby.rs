//! Ruby GAST normalizer.

use tree_sitter::Node;
use crate::engine::gast::base_normalizer::GASTNormalizer;
use crate::engine::gast::types::GASTNode;
use crate::scanner::language_detect::Language;

pub struct RubyNormalizer;

impl GASTNormalizer for RubyNormalizer {
    fn language(&self) -> Language { Language::Ruby }

    fn normalize_node(&self, node: &Node, source: &[u8]) -> GASTNode {
        match node.kind() {
            "program" => {
                let body = self.normalize_children(node, source);
                GASTNode::Program { body }
            }
            "method" | "singleton_method" => self.normalize_function(node, source),
            "class" => {
                let name = node.child_by_field_name("name")
                    .and_then(|n| n.utf8_text(source).ok())
                    .unwrap_or("").to_string();
                let bases = node.child_by_field_name("superclass")
                    .and_then(|n| n.utf8_text(source).ok())
                    .map(|s| vec![s.to_string()])
                    .unwrap_or_default();
                let body = node.child_by_field_name("body")
                    .map(|n| self.normalize_children(&n, source))
                    .unwrap_or_default();
                GASTNode::Class { name, bases, body, is_abstract: false }
            }
            "module" => {
                let name = node.child_by_field_name("name")
                    .and_then(|n| n.utf8_text(source).ok())
                    .unwrap_or("").to_string();
                let body = node.child_by_field_name("body")
                    .map(|n| self.normalize_children(&n, source))
                    .unwrap_or_default();
                GASTNode::Module { name: Some(name), body }
            }
            "if" | "unless" => self.normalize_if(node, source),
            "for" => self.normalize_for(node, source),
            "while" | "until" => self.normalize_while(node, source),
            "case" => self.normalize_switch(node, source),
            "begin" => self.normalize_try(node, source),
            "raise" => self.normalize_throw(node, source),
            "return" => self.normalize_return(node, source),
            "yield" => self.normalize_yield(node, source),
            "call" | "method_call" => self.normalize_call(node, source),
            "require" | "require_relative" => {
                let source_str = node.child(1)
                    .and_then(|n| n.utf8_text(source).ok())
                    .unwrap_or("").to_string();
                GASTNode::Import { source: source_str, specifiers: vec![] }
            }
            "body_statement" | "do_block" | "block" => {
                let stmts = self.normalize_children(node, source);
                GASTNode::Block { statements: stmts }
            }
            "identifier" | "constant" | "symbol" => {
                let name = node.utf8_text(source).unwrap_or("").to_string();
                GASTNode::Identifier { name }
            }
            "string" | "string_content" | "heredoc_body" => {
                let value = node.utf8_text(source).unwrap_or("").to_string();
                GASTNode::StringLiteral { value }
            }
            "integer" | "float" => {
                let value = node.utf8_text(source).unwrap_or("0").to_string();
                GASTNode::NumberLiteral { value }
            }
            "true" => GASTNode::BoolLiteral { value: true },
            "false" => GASTNode::BoolLiteral { value: false },
            "nil" => GASTNode::NullLiteral,
            "comment" => {
                let text = node.utf8_text(source).unwrap_or("").to_string();
                let is_doc = text.starts_with("##");
                GASTNode::Comment { text, is_doc }
            }
            "lambda" => self.normalize_lambda(node, source),
            _ => {
                let children = self.normalize_children(node, source);
                GASTNode::Other { kind: node.kind().to_string(), children }
            }
        }
    }
}
