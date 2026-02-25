//! License gating for bridge features.

pub mod feature_matrix;
pub mod gating;
pub mod usage_tracking;

pub use feature_matrix::{is_allowed, lookup_feature, FeatureEntry, FEATURE_MATRIX};
pub use gating::{FeatureGate, LicenseTier};
pub use usage_tracking::{UsageLimitExceeded, UsageTracker};
