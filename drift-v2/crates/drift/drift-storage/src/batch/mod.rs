//! Batch writer: crossbeam-channel bounded(1024), dedicated writer thread.

pub mod commands;
pub mod writer;

pub use commands::BatchCommand;
pub use writer::BatchWriter;
