//! Ruby parser.

use std::path::Path;
use drift_core::errors::ParseError;
use crate::scanner::language_detect::Language;
use crate::parsers::traits::LanguageParser;
use crate::parsers::types::ParseResult;
use super::parse_with_language;

pub struct RubyParser;

impl Default for RubyParser {
    fn default() -> Self {
        Self::new()
    }
}

impl RubyParser {
    pub fn new() -> Self { Self }
}

impl LanguageParser for RubyParser {
    fn language(&self) -> Language { Language::Ruby }
    fn extensions(&self) -> &[&str] { &["rb", "rake", "gemspec"] }

    fn parse(&self, source: &[u8], path: &Path) -> Result<ParseResult, ParseError> {
        parse_with_language(source, path, Language::Ruby, tree_sitter_ruby::LANGUAGE.into())
    }
}
