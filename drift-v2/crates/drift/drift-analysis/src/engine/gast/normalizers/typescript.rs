//! TypeScript/JavaScript GAST normalizer.

use tree_sitter::Node;

use crate::engine::gast::base_normalizer::GASTNormalizer;
use crate::engine::gast::types::GASTNode;
use crate::scanner::language_detect::Language;

pub struct TypeScriptNormalizer;

impl GASTNormalizer for TypeScriptNormalizer {
    fn language(&self) -> Language {
        Language::TypeScript
    }

    fn normalize_node(&self, node: &Node, source: &[u8]) -> GASTNode {
        match node.kind() {
            // TS-specific: type alias
            "type_alias_declaration" => {
                let name = node.child_by_field_name("name")
                    .and_then(|n| n.utf8_text(source).ok())
                    .unwrap_or("")
                    .to_string();
                let type_expr = node.child_by_field_name("value")
                    .map(|n| self.normalize_node(&n, source))
                    .unwrap_or(GASTNode::Other { kind: "type".to_string(), children: vec![] });
                GASTNode::TypeAlias { name, type_expr: Box::new(type_expr) }
            }

            // TS-specific: enum
            "enum_declaration" => {
                let name = node.child_by_field_name("name")
                    .and_then(|n| n.utf8_text(source).ok())
                    .unwrap_or("")
                    .to_string();
                let body = node.child_by_field_name("body")
                    .map(|n| self.normalize_children(&n, source))
                    .unwrap_or_default();
                GASTNode::Enum { name, members: body }
            }

            // TS-specific: interface
            "interface_declaration" => {
                let name = node.child_by_field_name("name")
                    .and_then(|n| n.utf8_text(source).ok())
                    .unwrap_or("")
                    .to_string();
                let body = node.child_by_field_name("body")
                    .map(|n| self.normalize_children(&n, source))
                    .unwrap_or_default();
                GASTNode::Interface { name, extends: vec![], body }
            }

            // Member access (property_access in TS tree-sitter)
            "member_expression" => {
                let object = node.child_by_field_name("object")
                    .map(|n| self.normalize_node(&n, source))
                    .unwrap_or(GASTNode::Identifier { name: "unknown".to_string() });
                let property = node.child_by_field_name("property")
                    .and_then(|n| n.utf8_text(source).ok())
                    .unwrap_or("")
                    .to_string();
                GASTNode::MemberAccess { object: Box::new(object), property }
            }

            // New expression
            "new_expression" => {
                let callee = node.child_by_field_name("constructor")
                    .or_else(|| node.child(1))
                    .map(|n| self.normalize_node(&n, source))
                    .unwrap_or(GASTNode::Identifier { name: "unknown".to_string() });
                let arguments = node.child_by_field_name("arguments")
                    .map(|n| self.normalize_children(&n, source))
                    .unwrap_or_default();
                GASTNode::NewExpression { callee: Box::new(callee), arguments }
            }

            // Template literal
            "template_string" => {
                let parts = self.normalize_children(node, source);
                GASTNode::TemplateLiteral { parts }
            }

            // Spread
            "spread_element" => {
                let arg = node.child(1)
                    .map(|n| self.normalize_node(&n, source))
                    .unwrap_or(GASTNode::NullLiteral);
                GASTNode::SpreadElement { argument: Box::new(arg) }
            }

            // Array
            "array" => {
                let elements = self.normalize_children(node, source);
                GASTNode::ArrayLiteral { elements }
            }

            // Object
            "object" => {
                let properties = self.normalize_children(node, source);
                GASTNode::ObjectLiteral { properties }
            }

            // Ternary
            "ternary_expression" => {
                let condition = node.child_by_field_name("condition")
                    .or_else(|| node.child(0))
                    .map(|n| self.normalize_node(&n, source))
                    .unwrap_or(GASTNode::BoolLiteral { value: true });
                let consequent = node.child_by_field_name("consequence")
                    .or_else(|| node.child(2))
                    .map(|n| self.normalize_node(&n, source))
                    .unwrap_or(GASTNode::NullLiteral);
                let alternate = node.child_by_field_name("alternative")
                    .or_else(|| node.child(4))
                    .map(|n| self.normalize_node(&n, source))
                    .unwrap_or(GASTNode::NullLiteral);
                GASTNode::Ternary {
                    condition: Box::new(condition),
                    consequent: Box::new(consequent),
                    alternate: Box::new(alternate),
                }
            }

            // Binary expression
            "binary_expression" | "augmented_assignment_expression" => {
                let left = node.child_by_field_name("left")
                    .or_else(|| node.child(0))
                    .map(|n| self.normalize_node(&n, source))
                    .unwrap_or(GASTNode::NullLiteral);
                let op = node.child_by_field_name("operator")
                    .or_else(|| node.child(1))
                    .and_then(|n| n.utf8_text(source).ok())
                    .unwrap_or("")
                    .to_string();
                let right = node.child_by_field_name("right")
                    .or_else(|| node.child(2))
                    .map(|n| self.normalize_node(&n, source))
                    .unwrap_or(GASTNode::NullLiteral);
                GASTNode::BinaryOp { left: Box::new(left), op, right: Box::new(right) }
            }

            // Fall through to base normalizer
            _ => {
                // Use the default base normalizer behavior
                let kind = node.kind();
                // Re-implement base matching for common patterns
                match kind {
                    "program" => {
                        let body = self.normalize_children(node, source);
                        GASTNode::Program { body }
                    }
                    "function_declaration" | "method_definition" | "function" => {
                        self.normalize_function(node, source)
                    }
                    "arrow_function" => self.normalize_lambda(node, source),
                    "class_declaration" | "class" => self.normalize_class(node, source),
                    "if_statement" => self.normalize_if(node, source),
                    "for_statement" | "for_in_statement" => self.normalize_for(node, source),
                    "while_statement" => self.normalize_while(node, source),
                    "switch_statement" => self.normalize_switch(node, source),
                    "try_statement" => self.normalize_try(node, source),
                    "throw_statement" => self.normalize_throw(node, source),
                    "return_statement" => self.normalize_return(node, source),
                    "await_expression" => self.normalize_await(node, source),
                    "call_expression" => self.normalize_call(node, source),
                    "import_statement" => self.normalize_import(node, source),
                    "export_statement" => self.normalize_export(node, source),
                    "statement_block" => {
                        let stmts = self.normalize_children(node, source);
                        GASTNode::Block { statements: stmts }
                    }
                    "identifier" | "property_identifier" | "type_identifier" => {
                        let name = node.utf8_text(source).unwrap_or("").to_string();
                        GASTNode::Identifier { name }
                    }
                    "string" | "string_literal" => {
                        let value = node.utf8_text(source).unwrap_or("").to_string();
                        GASTNode::StringLiteral { value }
                    }
                    "number" => {
                        let value = node.utf8_text(source).unwrap_or("0").to_string();
                        GASTNode::NumberLiteral { value }
                    }
                    "true" | "false" => GASTNode::BoolLiteral { value: kind == "true" },
                    "null" | "undefined" => GASTNode::NullLiteral,
                    "comment" => {
                        let text = node.utf8_text(source).unwrap_or("").to_string();
                        let is_doc = text.starts_with("/**");
                        GASTNode::Comment { text, is_doc }
                    }
                    "variable_declaration" | "lexical_declaration" => {
                        self.normalize_variable(node, source)
                    }
                    "expression_statement" => {
                        // Unwrap expression statements to their inner expression
                        if let Some(child) = node.child(0) {
                            self.normalize_node(&child, source)
                        } else {
                            GASTNode::Other { kind: kind.to_string(), children: vec![] }
                        }
                    }
                    _ => {
                        let children = self.normalize_children(node, source);
                        GASTNode::Other { kind: kind.to_string(), children }
                    }
                }
            }
        }
    }
}
