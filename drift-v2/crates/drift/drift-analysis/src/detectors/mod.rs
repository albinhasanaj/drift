//! Detector system — 16 categories, 3 variants per category.
//!
//! Each detector implements the `Detector` trait and is registered in the `DetectorRegistry`.
//! The 5 priority categories (security, data_access, errors, testing, structural) have
//! full implementations. The remaining 11 have skeleton detectors.

pub mod traits;
pub mod registry;
pub mod api;
pub mod auth;
pub mod components;
pub mod config;
pub mod contracts;
pub mod data_access;
pub mod documentation;
pub mod errors;
pub mod logging;
pub mod performance;
pub mod security;
pub mod structural;
pub mod styling;
pub mod testing;
pub mod types;
pub mod accessibility;

pub use traits::{Detector, DetectorCategory, DetectorVariant};
pub use registry::DetectorRegistry;
