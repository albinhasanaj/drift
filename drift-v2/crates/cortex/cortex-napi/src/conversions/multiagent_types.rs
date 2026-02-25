//! Multi-agent type conversions: Rust core types ↔ serde_json::Value for NAPI.
//!
//! All multi-agent core types derive Serialize/Deserialize, so we leverage
//! serde_json for zero-boilerplate roundtrip conversion — same pattern as
//! `memory_types.rs`.
//!
//! ## Supported Types
//!
//! - `AgentRegistration` ↔ JSON
//! - `ProvenanceRecord` ↔ JSON
//! - `ProvenanceHop` ↔ JSON
//! - `CrossAgentTrace` ↔ JSON
//! - `AgentTrust` ↔ JSON
//! - `SyncResult` ↔ JSON (custom serialization — not a core type)
//! - `NamespaceACL` ↔ JSON

use cortex_core::models::agent::AgentRegistration;
use cortex_core::models::cross_agent::AgentTrust;
use cortex_core::models::namespace::NamespaceACL;
use cortex_core::models::provenance::{ProvenanceHop, ProvenanceRecord};

/// Serialize an `AgentRegistration` to JSON for JS consumption.
pub fn agent_registration_to_json(reg: &AgentRegistration) -> napi::Result<serde_json::Value> {
    serde_json::to_value(reg).map_err(|e| {
        napi::Error::from_reason(format!("Failed to serialize AgentRegistration: {e}"))
    })
}

/// Deserialize an `AgentRegistration` from JSON received from JS.
pub fn agent_registration_from_json(value: serde_json::Value) -> napi::Result<AgentRegistration> {
    serde_json::from_value(value).map_err(|e| {
        napi::Error::from_reason(format!("Failed to deserialize AgentRegistration: {e}"))
    })
}

/// Serialize a `Vec<AgentRegistration>` to JSON array.
pub fn agent_registrations_to_json(
    regs: &[AgentRegistration],
) -> napi::Result<serde_json::Value> {
    serde_json::to_value(regs).map_err(|e| {
        napi::Error::from_reason(format!("Failed to serialize AgentRegistration list: {e}"))
    })
}

/// Serialize a `ProvenanceRecord` to JSON for JS consumption.
pub fn provenance_record_to_json(record: &ProvenanceRecord) -> napi::Result<serde_json::Value> {
    serde_json::to_value(record).map_err(|e| {
        napi::Error::from_reason(format!("Failed to serialize ProvenanceRecord: {e}"))
    })
}

/// Deserialize a `ProvenanceRecord` from JSON received from JS.
pub fn provenance_record_from_json(value: serde_json::Value) -> napi::Result<ProvenanceRecord> {
    serde_json::from_value(value).map_err(|e| {
        napi::Error::from_reason(format!("Failed to deserialize ProvenanceRecord: {e}"))
    })
}

/// Serialize a `ProvenanceHop` to JSON for JS consumption.
pub fn provenance_hop_to_json(hop: &ProvenanceHop) -> napi::Result<serde_json::Value> {
    serde_json::to_value(hop)
        .map_err(|e| napi::Error::from_reason(format!("Failed to serialize ProvenanceHop: {e}")))
}

/// Deserialize a `ProvenanceHop` from JSON received from JS.
pub fn provenance_hop_from_json(value: serde_json::Value) -> napi::Result<ProvenanceHop> {
    serde_json::from_value(value).map_err(|e| {
        napi::Error::from_reason(format!("Failed to deserialize ProvenanceHop: {e}"))
    })
}

/// Serialize an `AgentTrust` to JSON for JS consumption.
pub fn agent_trust_to_json(trust: &AgentTrust) -> napi::Result<serde_json::Value> {
    serde_json::to_value(trust)
        .map_err(|e| napi::Error::from_reason(format!("Failed to serialize AgentTrust: {e}")))
}

/// Deserialize an `AgentTrust` from JSON received from JS.
pub fn agent_trust_from_json(value: serde_json::Value) -> napi::Result<AgentTrust> {
    serde_json::from_value(value)
        .map_err(|e| napi::Error::from_reason(format!("Failed to deserialize AgentTrust: {e}")))
}

/// Serialize a `NamespaceACL` to JSON for JS consumption.
pub fn namespace_acl_to_json(acl: &NamespaceACL) -> napi::Result<serde_json::Value> {
    serde_json::to_value(acl)
        .map_err(|e| napi::Error::from_reason(format!("Failed to serialize NamespaceACL: {e}")))
}

/// Deserialize a `NamespaceACL` from JSON received from JS.
pub fn namespace_acl_from_json(value: serde_json::Value) -> napi::Result<NamespaceACL> {
    serde_json::from_value(value)
        .map_err(|e| napi::Error::from_reason(format!("Failed to deserialize NamespaceACL: {e}")))
}

/// A serializable sync result for NAPI consumption.
///
/// The internal `SyncResult` from `cortex-multiagent` is not `Serialize`,
/// so we provide a NAPI-friendly wrapper.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NapiSyncResult {
    /// Number of deltas applied during sync.
    pub applied_count: usize,
    /// Number of deltas buffered (waiting for causal predecessors).
    pub buffered_count: usize,
    /// Error messages encountered during sync (empty on success).
    pub errors: Vec<String>,
}

/// Serialize a `NapiSyncResult` to JSON for JS consumption.
pub fn sync_result_to_json(result: &NapiSyncResult) -> napi::Result<serde_json::Value> {
    serde_json::to_value(result)
        .map_err(|e| napi::Error::from_reason(format!("Failed to serialize SyncResult: {e}")))
}

/// A serializable cross-agent trace for NAPI consumption.
///
/// The internal `CrossAgentTrace` from `cortex-causal` is not `Serialize`,
/// so we provide a NAPI-friendly wrapper.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NapiCrossAgentTrace {
    /// Ordered path of agent/memory hops in the trace.
    pub path: Vec<NapiCrossAgentHop>,
}

/// A single hop in a cross-agent trace.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NapiCrossAgentHop {
    /// The agent at this hop.
    pub agent_id: String,
    /// The memory at this hop.
    pub memory_id: String,
    /// Confidence/strength at this hop.
    pub confidence: f64,
}

/// Serialize a `NapiCrossAgentTrace` to JSON for JS consumption.
pub fn cross_agent_trace_to_json(
    trace: &NapiCrossAgentTrace,
) -> napi::Result<serde_json::Value> {
    serde_json::to_value(trace).map_err(|e| {
        napi::Error::from_reason(format!("Failed to serialize CrossAgentTrace: {e}"))
    })
}

/// Validate that an `AgentRegistration` can roundtrip through JSON losslessly.
pub fn validate_agent_registration_roundtrip(
    value: &serde_json::Value,
) -> napi::Result<()> {
    let reg: AgentRegistration = serde_json::from_value(value.clone()).map_err(|e| {
        napi::Error::from_reason(format!(
            "AgentRegistration roundtrip validation failed (deserialize): {e}"
        ))
    })?;
    let _back = serde_json::to_value(&reg).map_err(|e| {
        napi::Error::from_reason(format!(
            "AgentRegistration roundtrip validation failed (serialize): {e}"
        ))
    })?;
    Ok(())
}

/// Validate that a `ProvenanceRecord` can roundtrip through JSON losslessly.
pub fn validate_provenance_roundtrip(value: &serde_json::Value) -> napi::Result<()> {
    let record: ProvenanceRecord = serde_json::from_value(value.clone()).map_err(|e| {
        napi::Error::from_reason(format!(
            "ProvenanceRecord roundtrip validation failed (deserialize): {e}"
        ))
    })?;
    let _back = serde_json::to_value(&record).map_err(|e| {
        napi::Error::from_reason(format!(
            "ProvenanceRecord roundtrip validation failed (serialize): {e}"
        ))
    })?;
    Ok(())
}

/// Validate that an `AgentTrust` can roundtrip through JSON losslessly.
pub fn validate_agent_trust_roundtrip(value: &serde_json::Value) -> napi::Result<()> {
    let trust: AgentTrust = serde_json::from_value(value.clone()).map_err(|e| {
        napi::Error::from_reason(format!(
            "AgentTrust roundtrip validation failed (deserialize): {e}"
        ))
    })?;
    let _back = serde_json::to_value(&trust).map_err(|e| {
        napi::Error::from_reason(format!(
            "AgentTrust roundtrip validation failed (serialize): {e}"
        ))
    })?;
    Ok(())
}
