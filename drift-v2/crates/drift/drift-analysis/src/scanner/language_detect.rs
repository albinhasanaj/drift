//! Language detection from file extension.

use serde::{Deserialize, Serialize};

/// Supported programming languages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Language {
    TypeScript,
    JavaScript,
    Python,
    Java,
    CSharp,
    Go,
    Rust,
    Ruby,
    Php,
    Kotlin,
    Cpp,
    C,
    Swift,
    Scala,
}

impl Language {
    /// Detect language from a file extension string.
    pub fn from_extension(ext: Option<&str>) -> Option<Language> {
        match ext? {
            "ts" | "tsx" | "mts" | "cts" => Some(Language::TypeScript),
            "js" | "jsx" | "mjs" | "cjs" => Some(Language::JavaScript),
            "py" | "pyi" => Some(Language::Python),
            "java" => Some(Language::Java),
            "cs" => Some(Language::CSharp),
            "go" => Some(Language::Go),
            "rs" => Some(Language::Rust),
            "rb" | "rake" | "gemspec" => Some(Language::Ruby),
            "php" => Some(Language::Php),
            "kt" | "kts" => Some(Language::Kotlin),
            "cpp" | "cc" | "cxx" | "hpp" | "hxx" | "hh" => Some(Language::Cpp),
            "c" | "h" => Some(Language::C),
            "swift" => Some(Language::Swift),
            "scala" | "sc" => Some(Language::Scala),
            _ => None,
        }
    }

    /// Returns all file extensions associated with this language.
    pub fn extensions(&self) -> &'static [&'static str] {
        match self {
            Language::TypeScript => &["ts", "tsx", "mts", "cts"],
            Language::JavaScript => &["js", "jsx", "mjs", "cjs"],
            Language::Python => &["py", "pyi"],
            Language::Java => &["java"],
            Language::CSharp => &["cs"],
            Language::Go => &["go"],
            Language::Rust => &["rs"],
            Language::Ruby => &["rb", "rake", "gemspec"],
            Language::Php => &["php"],
            Language::Kotlin => &["kt", "kts"],
            Language::Cpp => &["cpp", "cc", "cxx", "hpp", "hxx", "hh"],
            Language::C => &["c", "h"],
            Language::Swift => &["swift"],
            Language::Scala => &["scala", "sc"],
        }
    }

    /// Returns the display name of the language.
    pub fn name(&self) -> &'static str {
        match self {
            Language::TypeScript => "TypeScript",
            Language::JavaScript => "JavaScript",
            Language::Python => "Python",
            Language::Java => "Java",
            Language::CSharp => "C#",
            Language::Go => "Go",
            Language::Rust => "Rust",
            Language::Ruby => "Ruby",
            Language::Php => "PHP",
            Language::Kotlin => "Kotlin",
            Language::Cpp => "C++",
            Language::C => "C",
            Language::Swift => "Swift",
            Language::Scala => "Scala",
        }
    }
}

impl Language {
    /// Get the tree-sitter language grammar for this language.
    ///
    /// Used by the analysis pipeline to re-parse files for AST detection.
    pub fn ts_language(&self) -> tree_sitter::Language {
        match self {
            Language::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            Language::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
            Language::Python => tree_sitter_python::LANGUAGE.into(),
            Language::Java => tree_sitter_java::LANGUAGE.into(),
            Language::CSharp => tree_sitter_c_sharp::LANGUAGE.into(),
            Language::Go => tree_sitter_go::LANGUAGE.into(),
            Language::Rust => tree_sitter_rust::LANGUAGE.into(),
            Language::Ruby => tree_sitter_ruby::LANGUAGE.into(),
            Language::Php => tree_sitter_php::LANGUAGE_PHP.into(),
            Language::Kotlin => tree_sitter_kotlin_sg::LANGUAGE.into(),
            // C/C++ use C# grammar as fallback until tree-sitter-c/tree-sitter-cpp deps are added
            Language::Cpp | Language::C => tree_sitter_c_sharp::LANGUAGE.into(),
            // Swift/Scala use Java grammar as fallback until dedicated deps are added
            Language::Swift | Language::Scala => tree_sitter_java::LANGUAGE.into(),
        }
    }

    /// Get the tree-sitter language, with TSX handling for .tsx files.
    pub fn ts_language_for_ext(&self, ext: Option<&str>) -> tree_sitter::Language {
        if matches!(self, Language::TypeScript) && ext == Some("tsx") {
            tree_sitter_typescript::LANGUAGE_TSX.into()
        } else {
            self.ts_language()
        }
    }
}

impl std::fmt::Display for Language {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}
