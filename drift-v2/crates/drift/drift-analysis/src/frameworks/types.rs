//! Core types for the framework definition system.
//!
//! These serde types define the TOML schema for framework packs.

use serde::{Deserialize, Serialize};

/// Top-level framework pack definition (one per TOML file).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FrameworkSpec {
    /// Framework metadata.
    pub framework: FrameworkMeta,
    /// Pattern definitions.
    #[serde(default)]
    pub patterns: Vec<PatternDef>,
}

/// Framework metadata — name, languages, detection signals.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FrameworkMeta {
    /// Unique framework identifier (e.g., "spring-boot", "express").
    pub name: String,
    /// Display name for UI/reporting.
    pub display_name: Option<String>,
    /// Languages this framework targets.
    pub languages: Vec<String>,
    /// How to detect this framework is in use.
    #[serde(default)]
    pub detect_by: Vec<DetectSignal>,
    /// Pack version string (e.g., "1.0.0").
    pub version: Option<String>,
}

/// Signal used to auto-detect a framework in a project.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum DetectSignal {
    /// Match an import source.
    Import { import: String },
    /// Match a file glob pattern.
    FilePattern { file_pattern: String },
    /// Match a decorator name.
    Decorator { decorator: String },
    /// Match a dependency in package.json / Cargo.toml / etc.
    Dependency { dependency: String },
}

/// A single pattern definition within a framework pack.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PatternDef {
    /// Unique pattern ID (e.g., "spring/di/constructor-injection").
    pub id: String,
    /// Pattern category (maps to PatternCategory enum).
    pub category: String,
    /// Human-readable description.
    pub description: Option<String>,
    /// Sub-type for grouping related patterns.
    pub sub_type: Option<String>,
    /// Confidence score (0.0-1.0).
    #[serde(default = "default_confidence")]
    pub confidence: f32,
    /// CWE IDs for security patterns.
    #[serde(default)]
    pub cwe_ids: Vec<u32>,
    /// OWASP category.
    pub owasp: Option<String>,
    /// Match predicates — all must match for the pattern to fire.
    #[serde(rename = "match")]
    pub match_predicates: MatchBlock,
    /// Learning directives (optional).
    pub learn: Option<LearnDirective>,
}

fn default_confidence() -> f32 {
    0.80
}

/// Match block — defines what to look for in a file's ParseResult.
///
/// Multiple fields act as AND (all specified must match).
/// Arrays within a field act as OR (any element can match).
#[derive(Debug, Clone, Serialize, Deserialize, Default, schemars::JsonSchema)]
pub struct MatchBlock {
    /// Match import sources (OR — any source matches).
    #[serde(default)]
    pub imports: Vec<String>,
    /// Match decorator/annotation names (OR).
    #[serde(default)]
    pub decorators: Vec<String>,
    /// Match call site patterns: "receiver.method" or just "method".
    #[serde(default)]
    pub calls: Vec<String>,
    /// Match class extends patterns.
    #[serde(default)]
    pub extends: Vec<String>,
    /// Match class implements patterns.
    #[serde(default)]
    pub implements: Vec<String>,
    /// Match function name patterns (regex).
    #[serde(default)]
    pub function_names: Vec<String>,
    /// Match class name patterns (regex).
    #[serde(default)]
    pub class_names: Vec<String>,
    /// Match string literal values (regex).
    #[serde(default)]
    pub string_literals: Vec<String>,
    /// Match parameter type annotations (substring).
    #[serde(default)]
    pub param_types: Vec<String>,
    /// Match return type annotations (substring).
    #[serde(default)]
    pub return_types: Vec<String>,
    /// Regex patterns on raw file content (line-by-line).
    #[serde(default)]
    pub content_patterns: Vec<String>,
    /// Match export names.
    #[serde(default)]
    pub exports: Vec<String>,
    /// Match error handling kinds.
    #[serde(default)]
    pub error_handling: Vec<String>,
    /// Match doc comment patterns (regex).
    #[serde(default)]
    pub doc_comments: Vec<String>,
    /// Match file path glob patterns (e.g., "*.d.ts", "**/types/**").
    #[serde(default)]
    pub file_patterns: Vec<String>,
    /// Match type annotations on function params/return types (regex).
    #[serde(default)]
    pub type_annotations: Vec<String>,
    /// Require a specific language (narrows framework languages).
    pub language: Option<String>,
    /// Negative match — pattern must NOT be present.
    pub not: Option<Box<MatchBlock>>,
}

/// Learning directive — how to learn conventions from this pattern.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LearnDirective {
    /// Group observations by this field for convention detection.
    /// Values: "pattern_id", "sub_type", "decorator", "call", "function_name"
    pub group_by: String,
    /// What signal to track.
    /// Values: "frequency", "convention", "presence"
    #[serde(default = "default_signal")]
    pub signal: String,
    /// Minimum ratio to be considered the dominant convention.
    #[serde(default = "default_deviation_threshold")]
    pub deviation_threshold: f64,
}

fn default_signal() -> String {
    "convention".to_string()
}

fn default_deviation_threshold() -> f64 {
    0.15
}

/// Generate a JSON Schema for the `FrameworkSpec` type.
///
/// This schema can be used by custom pack authors to validate their TOML files.
pub fn generate_json_schema() -> schemars::schema::RootSchema {
    schemars::schema_for!(FrameworkSpec)
}
