//! 10 gene extractors — 6 frontend + 4 backend.

pub mod variant_handling;
pub mod responsive_approach;
pub mod state_styling;
pub mod theming;
pub mod spacing;
pub mod animation;
pub mod api_response;
pub mod error_response;
pub mod logging_format;
pub mod config_pattern;

use super::extractor::GeneExtractor;

/// Create all 10 gene extractors.
pub fn create_all_extractors() -> Vec<Box<dyn GeneExtractor>> {
    let mut extractors: Vec<Box<dyn GeneExtractor>> = Vec::with_capacity(10);
    extractors.extend(create_frontend_extractors());
    extractors.extend(create_backend_extractors());
    extractors
}

/// Create the 6 frontend gene extractors.
pub fn create_frontend_extractors() -> Vec<Box<dyn GeneExtractor>> {
    vec![
        Box::new(variant_handling::VariantHandlingExtractor),
        Box::new(responsive_approach::ResponsiveApproachExtractor),
        Box::new(state_styling::StateStylingExtractor),
        Box::new(theming::ThemingExtractor),
        Box::new(spacing::SpacingExtractor),
        Box::new(animation::AnimationExtractor),
    ]
}

/// Create the 4 backend gene extractors.
pub fn create_backend_extractors() -> Vec<Box<dyn GeneExtractor>> {
    vec![
        Box::new(api_response::ApiResponseExtractor),
        Box::new(error_response::ErrorResponseExtractor),
        Box::new(logging_format::LoggingFormatExtractor),
        Box::new(config_pattern::ConfigPatternExtractor),
    ]
}
