//! Language-specific GAST normalizers for 9 languages.

pub mod typescript;
pub mod python;
pub mod java;
pub mod csharp;
pub mod go;
pub mod rust_lang;
pub mod php;
pub mod ruby;
pub mod cpp;

use crate::scanner::language_detect::Language;
use super::base_normalizer::GASTNormalizer;

/// Get the normalizer for a given language.
pub fn normalizer_for(language: Language) -> Box<dyn GASTNormalizer> {
    match language {
        Language::TypeScript | Language::JavaScript => Box::new(typescript::TypeScriptNormalizer),
        Language::Python => Box::new(python::PythonNormalizer),
        Language::Java => Box::new(java::JavaNormalizer),
        Language::CSharp => Box::new(csharp::CSharpNormalizer),
        Language::Go => Box::new(go::GoNormalizer),
        Language::Rust => Box::new(rust_lang::RustNormalizer),
        Language::Php => Box::new(php::PhpNormalizer),
        Language::Ruby => Box::new(ruby::RubyNormalizer),
        Language::Kotlin => Box::new(java::JavaNormalizer), // Kotlin shares Java-like AST
        Language::Cpp | Language::C => Box::new(cpp::CppNormalizer),
        Language::Swift | Language::Scala => Box::new(java::JavaNormalizer),
    }
}
