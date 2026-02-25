//! Healing engine — automatic repair strategies for validated memories.
//!
//! 5 strategies: confidence adjustment, citation update, embedding refresh,
//! archival, and human review flagging.

pub mod archival;
pub mod citation_update;
pub mod confidence_adjust;
pub mod embedding_refresh;
pub mod flagging;
