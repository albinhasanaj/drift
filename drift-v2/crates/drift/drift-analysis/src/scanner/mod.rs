//! Scanner subsystem — parallel file discovery, content hashing, incremental detection.
//!
//! The scanner is the entry point to the entire Drift pipeline. It discovers files,
//! computes content hashes, detects languages, and produces a `ScanDiff` describing
//! what changed since the last scan.

pub mod cancellation;
pub mod hasher;
pub mod incremental;
pub mod language_detect;
pub mod scanner;
pub mod types;
pub mod walker;

pub use scanner::Scanner;
pub use types::{ScanDiff, ScanEntry, ScanStats};
