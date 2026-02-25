//! OWASP/CWE Mapping (System 26) — enrichment-only, 173 detector→CWE/OWASP mappings.

pub mod types;
pub mod registry;
pub mod enrichment;
pub mod wrapper_bridge;
pub mod posture;

pub use types::*;
pub use registry::CweOwaspRegistry;
