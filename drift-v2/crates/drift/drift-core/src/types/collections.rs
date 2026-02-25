//! Re-exports of performance-oriented collection types.

pub use rustc_hash::{FxHashMap, FxHashSet};
pub use smallvec::SmallVec;
pub use std::collections::BTreeMap;

/// SmallVec optimized for pattern locations (usually <4).
pub type SmallVec4<T> = SmallVec<[T; 4]>;

/// SmallVec optimized for call edges (usually <8).
pub type SmallVec8<T> = SmallVec<[T; 8]>;

/// SmallVec optimized for imports (usually <4).
pub type SmallVec2<T> = SmallVec<[T; 2]>;
