//! Versioned wire protocol — JSON serialization with forward compatibility.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Current protocol version.
pub const PROTOCOL_VERSION: &str = "1.0";

/// Envelope for all cloud API requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudRequest<T: Serialize> {
    /// Protocol version for forward compatibility.
    pub version: String,
    /// Unique request ID for tracing.
    pub request_id: String,
    /// Timestamp of the request.
    pub timestamp: DateTime<Utc>,
    /// The actual payload.
    pub payload: T,
    /// Agent ID for multi-agent sync. Defaults to "default" for backward compat.
    #[serde(default = "default_agent_id")]
    pub agent_id: String,
}

/// Envelope for all cloud API responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudResponse<T> {
    /// Protocol version.
    pub version: String,
    /// Echoed request ID.
    pub request_id: String,
    /// Whether the operation succeeded.
    pub success: bool,
    /// Error message if `success` is false.
    pub error: Option<String>,
    /// The response payload.
    pub data: Option<T>,
    /// Agent ID for multi-agent sync. Defaults to "default" for backward compat.
    #[serde(default = "default_agent_id")]
    pub agent_id: String,
}

/// Default agent ID for backward compatibility.
fn default_agent_id() -> String {
    "default".to_string()
}

/// A batch of memory mutations for push/pull.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncBatch {
    /// Memories to upsert.
    pub upserts: Vec<MemoryPayload>,
    /// Memory IDs to delete.
    pub deletes: Vec<String>,
    /// Sync token for incremental sync.
    pub sync_token: Option<String>,
}

/// A serialized memory for transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryPayload {
    /// Memory ID.
    pub id: String,
    /// Content hash for conflict detection.
    pub content_hash: String,
    /// Full serialized memory JSON.
    pub data: serde_json::Value,
    /// When this version was created.
    pub modified_at: DateTime<Utc>,
}

/// Response from a push operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushResponse {
    /// Number of memories accepted.
    pub accepted: usize,
    /// IDs that conflicted (need resolution).
    pub conflicts: Vec<String>,
    /// New sync token after this push.
    pub sync_token: String,
}

/// Response from a pull operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullResponse {
    /// Memories that changed on the remote.
    pub changes: Vec<MemoryPayload>,
    /// Whether there are more changes to pull.
    pub has_more: bool,
    /// New sync token after this pull.
    pub sync_token: String,
}

impl<T: Serialize> CloudRequest<T> {
    /// Create a new request envelope.
    pub fn new(payload: T) -> Self {
        Self {
            version: PROTOCOL_VERSION.to_string(),
            request_id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            payload,
            agent_id: default_agent_id(),
        }
    }

    /// Create a new request envelope with a specific agent ID.
    pub fn new_with_agent(payload: T, agent_id: String) -> Self {
        Self {
            version: PROTOCOL_VERSION.to_string(),
            request_id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            payload,
            agent_id,
        }
    }
}

impl<T> CloudResponse<T> {
    /// Create a success response.
    pub fn ok(request_id: String, data: T) -> Self {
        Self {
            version: PROTOCOL_VERSION.to_string(),
            request_id,
            success: true,
            error: None,
            data: Some(data),
            agent_id: default_agent_id(),
        }
    }

    /// Create an error response.
    pub fn err(request_id: String, error: String) -> Self {
        Self {
            version: PROTOCOL_VERSION.to_string(),
            request_id,
            success: false,
            error: Some(error),
            data: None,
            agent_id: default_agent_id(),
        }
    }
}
