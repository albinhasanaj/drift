//! Outlier Detection — 6 statistical methods with automatic selection.
//!
//! Auto-selects method based on sample size:
//! - n ≥ 30 → Z-Score with iterative masking
//! - 10 ≤ n < 30 → Grubbs' test
//! - n ≥ 25 + multiple outliers → Generalized ESD
//! - Non-normal data → IQR with Tukey fences
//! - Robust alternative → Modified Z-Score / MAD
//! - Always active → Rule-based detection

pub mod types;
pub mod zscore;
pub mod grubbs;
pub mod esd;
pub mod iqr;
pub mod mad;
pub mod rule_based;
pub mod selector;
pub mod conversion;

pub use types::{OutlierResult, SignificanceTier, DeviationScore, OutlierMethod, OutlierConfig};
pub use selector::OutlierDetector;
