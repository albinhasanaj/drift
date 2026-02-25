//! Boundary Detection — 33+ ORM frameworks, 10 field extractors, sensitive field detection.
//!
//! Two-phase learn-then-detect architecture:
//! 1. Learn: detect frameworks, extract models/fields
//! 2. Detect: identify sensitive fields, data boundaries

pub mod types;
pub mod detector;
pub mod sensitive;
pub mod extractors;

pub use types::{BoundaryScanResult, SensitivityType, OrmFramework, ExtractedModel, ExtractedField};
pub use detector::BoundaryDetector;
pub use sensitive::SensitiveFieldDetector;
