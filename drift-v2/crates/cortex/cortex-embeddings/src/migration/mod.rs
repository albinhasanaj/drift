//! Embedding migration pipeline.
//!
//! Detects model changes on startup, orchestrates background re-embedding
//! with progress tracking.

pub mod detector;
pub mod progress;
pub mod worker;

pub use detector::{detect_model_change, DetectionResult};
pub use progress::{MigrationProgress, MigrationStatus, ProgressSnapshot};
pub use worker::{prioritize, reembed_batch, WorkerConfig};
