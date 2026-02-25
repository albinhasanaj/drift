//! Unified Language Provider — 9 language normalizers, 22 ORM/framework matchers.
//!
//! Normalizes language-specific call chains into a universal `UnifiedCallChain`
//! representation for cross-language analysis.

pub mod types;
pub mod normalizers;
pub mod framework_matchers;
pub mod n_plus_one;
pub mod taint_sinks;

pub use types::{UnifiedCallChain, ChainCall, CallArg, DataOperation, OrmPattern};
pub use normalizers::{LanguageNormalizer, normalize_chain};
pub use framework_matchers::{OrmMatcher, MatcherRegistry};
