//! TypeScript parser.

use std::path::Path;
use drift_core::errors::ParseError;
use crate::scanner::language_detect::Language;
use crate::parsers::traits::LanguageParser;
use crate::parsers::types::ParseResult;
use super::parse_with_language;

pub struct TypeScriptParser;

impl Default for TypeScriptParser {
    fn default() -> Self {
        Self::new()
    }
}

impl TypeScriptParser {
    pub fn new() -> Self { Self }
}

impl LanguageParser for TypeScriptParser {
    fn language(&self) -> Language { Language::TypeScript }
    fn extensions(&self) -> &[&str] { &["ts", "tsx", "mts", "cts"] }

    fn parse(&self, source: &[u8], path: &Path) -> Result<ParseResult, ParseError> {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("ts");
        let ts_lang = if ext == "tsx" {
            tree_sitter_typescript::LANGUAGE_TSX.into()
        } else {
            tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()
        };
        parse_with_language(source, path, Language::TypeScript, ts_lang)
    }
}
