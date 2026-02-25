//! Java parser.

use std::path::Path;
use drift_core::errors::ParseError;
use crate::scanner::language_detect::Language;
use crate::parsers::traits::LanguageParser;
use crate::parsers::types::ParseResult;
use super::parse_with_language;

pub struct JavaParser;

impl Default for JavaParser {
    fn default() -> Self {
        Self::new()
    }
}

impl JavaParser {
    pub fn new() -> Self { Self }
}

impl LanguageParser for JavaParser {
    fn language(&self) -> Language { Language::Java }
    fn extensions(&self) -> &[&str] { &["java"] }

    fn parse(&self, source: &[u8], path: &Path) -> Result<ParseResult, ParseError> {
        parse_with_language(source, path, Language::Java, tree_sitter_java::LANGUAGE.into())
    }
}
