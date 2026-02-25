//! Licensing & Feature Gating — 3-tier system with JWT validation.
//!
//! ## Tiers
//! - **Community** (free): Core analysis, pattern detection, call graph, boundaries, quality gates
//! - **Team**: + Advanced analysis, CI integration, scheduled grounding, MCP tools
//! - **Enterprise**: + Taint analysis, full grounding, contradiction gen, cross-DB, telemetry, custom detectors, export
//!
//! ## Components
//! - **features** — 16 gated features mapped to 3 tiers
//! - **jwt** — JWT license token parsing and claim extraction
//! - **manager** — LicenseManager: load, validate, check, hot-reload

pub mod features;
pub mod jwt;
pub mod manager;

pub use features::{features_for_tier, tier_allows, GatedFeature};
pub use jwt::{LicenseClaims, JwtError};
pub use manager::{FeatureAccess, LicenseManager, LicenseSource, LicenseState, LicenseStatus};
