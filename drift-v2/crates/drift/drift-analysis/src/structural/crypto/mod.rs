//! Cryptographic Failure Detection (System 27) — 14 detection categories,
//! 261 patterns across 12 languages.

pub mod types;
pub mod patterns;
pub mod detector;
pub mod confidence;
pub mod health;
pub mod remediation;

pub use types::*;
pub use detector::CryptoDetector;
