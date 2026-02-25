//! Rules engine — maps detected patterns and outliers to actionable violations.

pub mod types;
pub mod evaluator;
pub mod quick_fixes;
pub mod suppression;

pub use types::*;
pub use evaluator::RulesEvaluator;
pub use quick_fixes::QuickFixGenerator;
pub use suppression::SuppressionChecker;
