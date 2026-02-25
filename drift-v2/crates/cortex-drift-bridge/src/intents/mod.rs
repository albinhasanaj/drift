//! Intent extensions: 10 code-specific intents for Cortex.

pub mod extensions;
pub mod resolver;

pub use extensions::{CodeIntent, CODE_INTENTS};
pub use resolver::{resolve_intent, IntentResolution};
