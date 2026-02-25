pub mod level0;
pub mod level1;
pub mod level2;
pub mod level3;

use cortex_core::memory::{BaseMemory, MemoryType};

/// Compression level enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum CompressionLevel {
    /// IDs only. ~5 tokens, max 10.
    L0 = 0,
    /// One-liners + tags. ~50 tokens, max 75.
    L1 = 1,
    /// With examples + evidence. ~200 tokens, max 300.
    L2 = 2,
    /// Full context + causal + links. ~500 tokens, max 1000.
    L3 = 3,
}

impl CompressionLevel {
    /// Convert from a u8 level value, clamping to valid range.
    pub fn from_u8(level: u8) -> Self {
        match level {
            0 => Self::L0,
            1 => Self::L1,
            2 => Self::L2,
            _ => Self::L3,
        }
    }

    /// Maximum token count for this level.
    pub fn max_tokens(self) -> usize {
        match self {
            Self::L0 => 10,
            Self::L1 => 75,
            Self::L2 => 300,
            Self::L3 => 1000,
        }
    }

    /// All levels from highest to lowest (for fit-to-budget iteration).
    pub const ALL_DESC: [CompressionLevel; 4] = [Self::L3, Self::L2, Self::L1, Self::L0];
}

/// Compress a memory at the given level.
pub fn compress_at_level(memory: &BaseMemory, level: CompressionLevel) -> String {
    match level {
        CompressionLevel::L0 => level0::compress(memory),
        CompressionLevel::L1 => level1::compress(memory),
        CompressionLevel::L2 => level2::compress(memory),
        CompressionLevel::L3 => level3::compress(memory),
    }
}

/// Short label for a memory type (used in compressed output).
pub fn memory_type_short(mt: MemoryType) -> &'static str {
    match mt {
        MemoryType::Core => "core",
        MemoryType::Tribal => "tribal",
        MemoryType::Procedural => "proc",
        MemoryType::Semantic => "sem",
        MemoryType::Episodic => "ep",
        MemoryType::Decision => "dec",
        MemoryType::Insight => "ins",
        MemoryType::Reference => "ref",
        MemoryType::Preference => "pref",
        MemoryType::PatternRationale => "pat",
        MemoryType::ConstraintOverride => "con",
        MemoryType::DecisionContext => "dctx",
        MemoryType::CodeSmell => "smell",
        MemoryType::AgentSpawn => "agent",
        MemoryType::Entity => "ent",
        MemoryType::Goal => "goal",
        MemoryType::Feedback => "fb",
        MemoryType::Workflow => "wf",
        MemoryType::Conversation => "conv",
        MemoryType::Incident => "inc",
        MemoryType::Meeting => "mtg",
        MemoryType::Skill => "skill",
        MemoryType::Environment => "env",
    }
}
