//! Data structures and string interning for Drift.
//! FxHashMap, SmallVec, lasso-based interning, Spur-based ID types.

pub mod collections;
pub mod identifiers;
pub mod interning;

pub use collections::{FxHashMap, FxHashSet};
pub use identifiers::{ClassId, DetectorId, FileId, FunctionId, ModuleId, PatternId};
pub use interning::{FunctionInterner, PathInterner};
