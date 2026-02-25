//! VersionManager — memory content evolution tracking.

pub mod query;
pub mod retention;
pub mod rollback;
pub mod tracker;

pub use tracker::VersionTracker;
