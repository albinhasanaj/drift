//! Wrapper Detection (System 23) — 16 categories, 150+ primitive signatures, 7-signal confidence.

pub mod types;
pub mod detector;
pub mod confidence;
pub mod multi_primitive;
pub mod regex_set;
pub mod clustering;
pub mod security;

pub use types::*;
pub use detector::WrapperDetector;
