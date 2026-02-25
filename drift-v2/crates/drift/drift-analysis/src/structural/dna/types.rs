//! DNA system types — Gene, Allele, DnaProfile, Mutation, DnaHealthScore.

use serde::{Deserialize, Serialize};

/// All gene identifiers. 10 total: 6 frontend + 4 backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GeneId {
    // Frontend genes (6)
    VariantHandling,
    ResponsiveApproach,
    StateStyling,
    Theming,
    SpacingPhilosophy,
    AnimationApproach,
    // Backend genes (4)
    ApiResponseFormat,
    ErrorResponseFormat,
    LoggingFormat,
    ConfigPattern,
}

impl GeneId {
    pub const FRONTEND: &'static [GeneId] = &[
        GeneId::VariantHandling, GeneId::ResponsiveApproach,
        GeneId::StateStyling, GeneId::Theming,
        GeneId::SpacingPhilosophy, GeneId::AnimationApproach,
    ];

    pub const BACKEND: &'static [GeneId] = &[
        GeneId::ApiResponseFormat, GeneId::ErrorResponseFormat,
        GeneId::LoggingFormat, GeneId::ConfigPattern,
    ];

    pub const ALL: &'static [GeneId] = &[
        GeneId::VariantHandling, GeneId::ResponsiveApproach,
        GeneId::StateStyling, GeneId::Theming,
        GeneId::SpacingPhilosophy, GeneId::AnimationApproach,
        GeneId::ApiResponseFormat, GeneId::ErrorResponseFormat,
        GeneId::LoggingFormat, GeneId::ConfigPattern,
    ];

    pub fn is_frontend(&self) -> bool { Self::FRONTEND.contains(self) }
    pub fn is_backend(&self) -> bool { Self::BACKEND.contains(self) }

    pub fn name(&self) -> &'static str {
        match self {
            Self::VariantHandling => "Variant Handling",
            Self::ResponsiveApproach => "Responsive Approach",
            Self::StateStyling => "State Styling",
            Self::Theming => "Theming",
            Self::SpacingPhilosophy => "Spacing Philosophy",
            Self::AnimationApproach => "Animation Approach",
            Self::ApiResponseFormat => "API Response Format",
            Self::ErrorResponseFormat => "Error Response Format",
            Self::LoggingFormat => "Logging Format",
            Self::ConfigPattern => "Config Pattern",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::VariantHandling => "How component variants are managed",
            Self::ResponsiveApproach => "How responsive design is implemented",
            Self::StateStyling => "How component state affects styling",
            Self::Theming => "How theming and design tokens are managed",
            Self::SpacingPhilosophy => "How spacing and layout are handled",
            Self::AnimationApproach => "How animations and transitions are implemented",
            Self::ApiResponseFormat => "How API responses are structured",
            Self::ErrorResponseFormat => "How error responses are formatted",
            Self::LoggingFormat => "How logging is structured",
            Self::ConfigPattern => "How configuration is managed",
        }
    }
}

/// A code example demonstrating an allele in context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlleleExample {
    pub file: String,
    pub line: u32,
    pub code: String,
    pub context: String,
}

/// An allele — one variant of a gene (one approach to a convention concern).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Allele {
    pub id: String,
    pub name: String,
    pub description: String,
    /// Proportion of occurrences (0.0–1.0).
    pub frequency: f64,
    pub file_count: u32,
    /// Regex source(s) joined by |.
    pub pattern: String,
    /// Up to 5 code examples.
    pub examples: Vec<AlleleExample>,
    pub is_dominant: bool,
}

/// A gene — one convention concern with competing alleles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Gene {
    pub id: GeneId,
    pub name: String,
    pub description: String,
    /// Most common variant (≥30% frequency).
    pub dominant: Option<Allele>,
    /// All detected variants, sorted by frequency descending.
    pub alleles: Vec<Allele>,
    /// Dominant allele frequency (0.0–1.0).
    pub confidence: f64,
    /// Gap between dominant and second allele (0.0–1.0).
    pub consistency: f64,
    /// Up to 5 files demonstrating dominant.
    pub exemplars: Vec<String>,
}

/// Mutation impact severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum MutationImpact {
    High,
    Medium,
    Low,
}

/// A mutation — a deviation from the dominant allele.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mutation {
    /// Deterministic ID: SHA-256(file + geneId + alleleId)[..16].
    pub id: String,
    pub file: String,
    pub line: u32,
    pub gene: GeneId,
    /// Expected (dominant) allele.
    pub expected: String,
    /// Actual (deviant) allele.
    pub actual: String,
    pub impact: MutationImpact,
    pub code: String,
    pub suggestion: String,
    pub detected_at: i64,
    pub resolved: bool,
    pub resolved_at: Option<i64>,
}

/// Complete DNA profile for a codebase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnaProfile {
    pub version: String,
    pub generated_at: i64,
    pub project_root: String,
    pub genes: Vec<Gene>,
    pub mutations: Vec<Mutation>,
    pub health_score: f64,
    pub genetic_diversity: f64,
}

/// DNA health score (0-100).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DnaHealthScore {
    /// Overall health (0-100).
    pub overall: f64,
    /// Consistency component (0-1).
    pub consistency: f64,
    /// Confidence component (0-1).
    pub confidence: f64,
    /// Mutation penalty component (0-1).
    pub mutation_score: f64,
    /// Coverage component (0-1).
    pub coverage: f64,
}

/// Allele definition for gene extractors — defines what patterns to look for.
#[derive(Debug, Clone)]
pub struct AlleleDefinition {
    pub id: String,
    pub name: String,
    pub description: String,
    /// Regex patterns to match.
    pub patterns: Vec<String>,
    /// Keywords that suggest this allele.
    pub keywords: Vec<String>,
    /// Import patterns that suggest this allele.
    pub import_patterns: Vec<String>,
    /// Priority for tie-breaking (higher = preferred).
    pub priority: u32,
}

/// Result of extracting alleles from a single file.
#[derive(Debug, Clone)]
pub struct FileExtractionResult {
    pub file: String,
    pub detected_alleles: Vec<DetectedAllele>,
    pub is_component: bool,
    pub errors: Vec<String>,
}

/// A single allele detection in a file.
#[derive(Debug, Clone)]
pub struct DetectedAllele {
    pub allele_id: String,
    pub line: u32,
    pub code: String,
    pub confidence: f64,
    pub context: String,
}

/// Default DNA thresholds.
pub struct DnaThresholds;

impl DnaThresholds {
    /// Minimum frequency for an allele to be considered dominant.
    pub const DOMINANT_MIN_FREQUENCY: f64 = 0.6;
    /// High-impact mutation threshold.
    pub const MUTATION_IMPACT_HIGH: f64 = 0.1;
    /// Medium-impact mutation threshold.
    pub const MUTATION_IMPACT_MEDIUM: f64 = 0.3;
    /// Health score warning threshold.
    pub const HEALTH_SCORE_WARNING: f64 = 70.0;
    /// Health score critical threshold.
    pub const HEALTH_SCORE_CRITICAL: f64 = 50.0;
}
