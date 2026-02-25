//! # cortex-privacy
//!
//! PII and secret sanitization engine.
//! 50+ regex patterns for emails, API keys, tokens, connection strings.
//! Context-aware scoring reduces false positives in code.

pub mod context_scoring;
pub mod degradation;
pub mod engine;
pub mod patterns;

pub use engine::PrivacyEngine;
