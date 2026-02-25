//! MCP server configuration.

use serde::{Deserialize, Serialize};

/// Configuration for the MCP server subsystem.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct McpConfig {
    /// Cache TTL in seconds. Default: 300.
    pub cache_ttl_seconds: Option<u64>,
    /// Maximum response tokens. Default: 8000.
    pub max_response_tokens: Option<u32>,
    /// Transport type: "stdio" | "http". Default: "stdio".
    pub transport: Option<String>,
    /// Enabled MCP tools.
    #[serde(default)]
    pub enabled_tools: Vec<String>,
}

impl McpConfig {
    /// Returns the effective max response tokens, defaulting to 8000.
    pub fn effective_max_response_tokens(&self) -> u32 {
        self.max_response_tokens.unwrap_or(8000)
    }

    /// Returns the effective cache TTL, defaulting to 300 seconds.
    pub fn effective_cache_ttl(&self) -> u64 {
        self.cache_ttl_seconds.unwrap_or(300)
    }
}
