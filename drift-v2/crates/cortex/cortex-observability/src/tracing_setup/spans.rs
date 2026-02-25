//! Span definitions per operation: retrieval, consolidation, decay, validation, learning, embedding.
//!
//! Each span carries duration, result, and metadata via the `tracing` crate.

/// Create a retrieval span.
#[macro_export]
macro_rules! retrieval_span {
    ($query:expr, $intent:expr) => {
        tracing::info_span!("cortex.retrieval", query = %$query, intent = ?$intent)
    };
}

/// Create a consolidation span.
#[macro_export]
macro_rules! consolidation_span {
    ($batch_size:expr) => {
        tracing::info_span!("cortex.consolidation", batch_size = $batch_size)
    };
}

/// Create a decay span.
#[macro_export]
macro_rules! decay_span {
    ($memory_count:expr) => {
        tracing::info_span!("cortex.decay", memory_count = $memory_count)
    };
}

/// Create a validation span.
#[macro_export]
macro_rules! validation_span {
    ($memory_id:expr) => {
        tracing::info_span!("cortex.validation", memory_id = %$memory_id)
    };
}

/// Create a learning span.
#[macro_export]
macro_rules! learning_span {
    ($correction_type:expr) => {
        tracing::info_span!("cortex.learning", correction_type = %$correction_type)
    };
}

/// Create an embedding span.
#[macro_export]
macro_rules! embedding_span {
    ($provider:expr, $dimension:expr) => {
        tracing::info_span!("cortex.embedding", provider = %$provider, dimension = $dimension)
    };
}

/// Span names as constants for programmatic use.
pub mod names {
    pub const RETRIEVAL: &str = "cortex.retrieval";
    pub const CONSOLIDATION: &str = "cortex.consolidation";
    pub const DECAY: &str = "cortex.decay";
    pub const VALIDATION: &str = "cortex.validation";
    pub const LEARNING: &str = "cortex.learning";
    pub const EMBEDDING: &str = "cortex.embedding";
}
