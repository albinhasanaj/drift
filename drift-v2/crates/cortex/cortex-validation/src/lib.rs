//! # cortex-validation
//!
//! 4-dimension memory validation with contradiction detection,
//! confidence propagation, consensus resistance, and automatic healing.
//!
//! ## Dimensions
//! 1. **Citation** — file existence, content hash drift, line validity
//! 2. **Temporal** — expiry, age vs expected lifetime
//! 3. **Contradiction** — 5 detection strategies, consensus support
//! 4. **Pattern Alignment** — linked patterns exist and are consistent
//!
//! ## Healing Strategies
//! - Confidence adjustment
//! - Citation auto-update (git rename detection)
//! - Embedding refresh
//! - Archival with reason tracking
//! - Human review flagging

pub mod contradiction;
pub mod dimensions;
pub mod engine;
pub mod healing;

pub use engine::{ValidationConfig, ValidationEngine};
