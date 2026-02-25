//! Declarative TOML pattern definitions — user-extensible without recompiling (AD3).
//!
//! Each `CompiledQuery` carries `cwe_ids: SmallVec<[u32; 2]>` and `owasp: Option<String>`.

use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

use drift_core::errors::DetectionError;

use super::types::PatternCategory;

/// A TOML-defined pattern definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TomlPatternDef {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub category: String,
    pub pattern: String,
    #[serde(default)]
    pub node_types: Vec<String>,
    #[serde(default)]
    pub languages: Vec<String>,
    #[serde(default = "default_confidence")]
    pub confidence: f32,
    #[serde(default)]
    pub cwe_ids: Vec<u32>,
    pub owasp: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

fn default_confidence() -> f32 {
    0.70
}

/// A compiled query ready for matching.
#[derive(Debug, Clone)]
pub struct CompiledQuery {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub category: PatternCategory,
    pub regex: Option<regex::Regex>,
    pub node_types: Vec<String>,
    pub languages: Vec<String>,
    pub confidence: f32,
    pub cwe_ids: SmallVec<[u32; 2]>,
    pub owasp: Option<String>,
}

/// A collection of TOML pattern definitions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TomlPatternFile {
    #[serde(default)]
    pub patterns: Vec<TomlPatternDef>,
}

/// Loader for TOML pattern definitions.
pub struct TomlPatternLoader;

impl TomlPatternLoader {
    /// Load patterns from a TOML string.
    pub fn load_from_str(toml_str: &str) -> Result<Vec<CompiledQuery>, DetectionError> {
        let file: TomlPatternFile = toml::from_str(toml_str).map_err(|e| {
            DetectionError::InvalidPattern(format!("TOML parse error: {e}"))
        })?;

        let mut queries = Vec::new();
        for def in file.patterns {
            if def.enabled == Some(false) {
                continue;
            }
            queries.push(Self::compile(def)?);
        }
        Ok(queries)
    }

    /// Load patterns from a file path.
    pub fn load_from_file(path: &std::path::Path) -> Result<Vec<CompiledQuery>, DetectionError> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            DetectionError::InvalidPattern(format!("failed to read {}: {e}", path.display()))
        })?;
        Self::load_from_str(&content)
    }

    /// Compile a single pattern definition into a query.
    fn compile(def: TomlPatternDef) -> Result<CompiledQuery, DetectionError> {
        let category = PatternCategory::parse_str(&def.category).ok_or_else(|| {
            DetectionError::InvalidPattern(format!(
                "unknown category '{}' in pattern '{}'",
                def.category, def.id
            ))
        })?;

        let regex = if !def.pattern.is_empty() {
            Some(regex::Regex::new(&def.pattern).map_err(|e| {
                DetectionError::QueryCompilationFailed(format!(
                    "regex error in pattern '{}': {e}",
                    def.id
                ))
            })?)
        } else {
            None
        };

        let mut cwe_ids = SmallVec::new();
        for id in &def.cwe_ids {
            cwe_ids.push(*id);
        }

        Ok(CompiledQuery {
            id: def.id,
            name: def.name,
            description: def.description,
            category,
            regex,
            node_types: def.node_types,
            languages: def.languages,
            confidence: def.confidence,
            cwe_ids,
            owasp: def.owasp,
        })
    }
}
