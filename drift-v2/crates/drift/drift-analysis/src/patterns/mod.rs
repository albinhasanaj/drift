//! Pattern Intelligence — aggregation, confidence scoring, outlier detection, and learning.
//!
//! This is what makes Drift *Drift*. Transforms raw per-file pattern detections into
//! ranked, scored, learned conventions.
//!
//! Dependency chain: Aggregation → Confidence → (Outliers ∥ Learning)

pub mod aggregation;
pub mod confidence;
pub mod outliers;
pub mod learning;
pub mod pipeline;
