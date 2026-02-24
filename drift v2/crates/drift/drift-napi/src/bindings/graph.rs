//! NAPI bindings for all 5 graph intelligence systems.
//!
//! Exposes reachability, taint, error handling, impact, and test topology
//! analysis functions to TypeScript/JavaScript.

#[allow(unused_imports)]
use napi::bindgen_prelude::*;
use napi_derive::napi;
use serde::{Deserialize, Serialize};

use crate::conversions::error_codes;
use crate::runtime;

fn storage_err(e: impl std::fmt::Display) -> napi::Error {
    napi::Error::from_reason(format!("[{}] {e}", error_codes::STORAGE_ERROR))
}

// --- Reachability ---

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsReachabilityResult {
    pub source: String,
    pub reachable_count: u32,
    pub sensitivity: String,
    pub max_depth: u32,
    pub engine: String,
}

#[napi]
pub fn drift_reachability(
    function_key: String,
    direction: String,
) -> napi::Result<JsReachabilityResult> {
    let rt = runtime::get()?;

    let cached = rt.storage.with_reader(|conn| {
        drift_storage::queries::graph::get_reachability(conn, &function_key, &direction)
    }).map_err(storage_err)?;

    if let Some(row) = cached {
        let reachable: Vec<String> = serde_json::from_str(&row.reachable_set).unwrap_or_default();
        Ok(JsReachabilityResult {
            source: function_key,
            reachable_count: reachable.len() as u32,
            sensitivity: row.sensitivity,
            max_depth: 0,
            engine: "petgraph".to_string(),
        })
    } else {
        Ok(JsReachabilityResult {
            source: function_key,
            reachable_count: 0,
            sensitivity: "low".to_string(),
            max_depth: 0,
            engine: "petgraph".to_string(),
        })
    }
}

// --- Taint Analysis ---

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsTaintFlow {
    pub source_file: String,
    pub source_line: u32,
    pub source_type: String,
    pub sink_file: String,
    pub sink_line: u32,
    pub sink_type: String,
    pub cwe_id: Option<u32>,
    pub is_sanitized: bool,
    pub confidence: f64,
    pub path_length: u32,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsTaintResult {
    pub flows: Vec<JsTaintFlow>,
    pub vulnerability_count: u32,
    pub source_count: u32,
    pub sink_count: u32,
}

#[napi]
pub fn drift_taint_analysis(_root: String) -> napi::Result<JsTaintResult> {
    let rt = runtime::get()?;

    // Query all taint flows from the DB (they're stored per-file, so we scan root-relative files)
    // For now, query a broad set — the taint_flows table stores all discovered flows
    let flows = rt.storage.with_reader(|conn| {
        conn.prepare_cached(
            "SELECT id, source_file, source_line, source_type, sink_file, sink_line, sink_type, cwe_id, is_sanitized, path, confidence
             FROM taint_flows ORDER BY confidence DESC LIMIT 1000"
        )
        .map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })
        .and_then(|mut stmt| {
            let rows = stmt.query_map([], |row| {
                Ok(drift_storage::queries::graph::TaintFlowRow {
                    id: row.get(0)?,
                    source_file: row.get(1)?,
                    source_line: row.get::<_, u32>(2)?,
                    source_type: row.get(3)?,
                    sink_file: row.get(4)?,
                    sink_line: row.get::<_, u32>(5)?,
                    sink_type: row.get(6)?,
                    cwe_id: row.get(7)?,
                    is_sanitized: row.get::<_, i32>(8)? != 0,
                    path: row.get(9)?,
                    confidence: row.get(10)?,
                })
            }).map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })?;
            let mut result = Vec::new();
            for row in rows {
                result.push(row.map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })?);
            }
            Ok(result)
        })
    }).map_err(storage_err)?;

    let vulnerability_count = flows.iter().filter(|f| !f.is_sanitized).count() as u32;
    let js_flows: Vec<JsTaintFlow> = flows.iter().map(|f| {
        let path_nodes: Vec<String> = serde_json::from_str(&f.path).unwrap_or_default();
        JsTaintFlow {
            source_file: f.source_file.clone(),
            source_line: f.source_line,
            source_type: f.source_type.clone(),
            sink_file: f.sink_file.clone(),
            sink_line: f.sink_line,
            sink_type: f.sink_type.clone(),
            cwe_id: f.cwe_id,
            is_sanitized: f.is_sanitized,
            confidence: f.confidence,
            path_length: path_nodes.len() as u32,
        }
    }).collect();

    Ok(JsTaintResult {
        flows: js_flows,
        vulnerability_count,
        source_count: 0,
        sink_count: 0,
    })
}

// --- Error Handling ---

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsErrorGap {
    pub file: String,
    pub function_name: String,
    pub line: u32,
    pub gap_type: String,
    pub severity: String,
    pub cwe_id: Option<u32>,
    pub remediation: Option<String>,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsErrorHandlingResult {
    pub gaps: Vec<JsErrorGap>,
    pub handler_count: u32,
    pub unhandled_count: u32,
}

#[napi]
pub fn drift_error_handling(_root: String) -> napi::Result<JsErrorHandlingResult> {
    let rt = runtime::get()?;

    let gaps = rt.storage.with_reader(|conn| {
        conn.prepare_cached(
            "SELECT id, file, function_id, gap_type, error_type, propagation_chain, framework, cwe_id, severity
             FROM error_gaps ORDER BY severity DESC LIMIT 1000"
        )
        .map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })
        .and_then(|mut stmt| {
            let rows = stmt.query_map([], |row| {
                Ok(drift_storage::queries::graph::ErrorGapRow {
                    id: row.get(0)?,
                    file: row.get(1)?,
                    function_id: row.get(2)?,
                    gap_type: row.get(3)?,
                    error_type: row.get(4)?,
                    propagation_chain: row.get(5)?,
                    framework: row.get(6)?,
                    cwe_id: row.get(7)?,
                    severity: row.get(8)?,
                })
            }).map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })?;
            let mut result = Vec::new();
            for row in rows {
                result.push(row.map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })?);
            }
            Ok(result)
        })
    }).map_err(storage_err)?;

    let js_gaps: Vec<JsErrorGap> = gaps.iter().map(|g| JsErrorGap {
        file: g.file.clone(),
        function_name: g.function_id.clone(),
        line: 0,
        gap_type: g.gap_type.clone(),
        severity: g.severity.clone(),
        cwe_id: g.cwe_id,
        remediation: None,
    }).collect();

    let unhandled = js_gaps.len() as u32;

    Ok(JsErrorHandlingResult {
        gaps: js_gaps,
        handler_count: 0,
        unhandled_count: unhandled,
    })
}

// --- Impact Analysis ---

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsBlastRadius {
    pub function_id: String,
    pub caller_count: u32,
    pub risk_score: f64,
    pub max_depth: u32,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsDeadCode {
    pub function_id: String,
    pub reason: String,
    pub exclusion: Option<String>,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsImpactResult {
    pub blast_radii: Vec<JsBlastRadius>,
    pub dead_code: Vec<JsDeadCode>,
}

#[napi]
pub fn drift_impact_analysis(_root: String) -> napi::Result<JsImpactResult> {
    let rt = runtime::get()?;

    let scores = rt.storage.with_reader(|conn| {
        conn.prepare_cached(
            "SELECT function_id, blast_radius, risk_score, is_dead_code, dead_code_reason, exclusion_category
             FROM impact_scores ORDER BY risk_score DESC LIMIT 1000"
        )
        .map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })
        .and_then(|mut stmt| {
            let rows = stmt.query_map([], |row| {
                Ok(drift_storage::queries::graph::ImpactScoreRow {
                    function_id: row.get(0)?,
                    blast_radius: row.get::<_, u32>(1)?,
                    risk_score: row.get(2)?,
                    is_dead_code: row.get::<_, i32>(3)? != 0,
                    dead_code_reason: row.get(4)?,
                    exclusion_category: row.get(5)?,
                })
            }).map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })?;
            let mut result = Vec::new();
            for row in rows {
                result.push(row.map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })?);
            }
            Ok(result)
        })
    }).map_err(storage_err)?;

    let mut blast_radii = Vec::new();
    let mut dead_code = Vec::new();
    for s in &scores {
        if s.is_dead_code {
            dead_code.push(JsDeadCode {
                function_id: s.function_id.clone(),
                reason: s.dead_code_reason.clone().unwrap_or_default(),
                exclusion: s.exclusion_category.clone(),
            });
        }
        blast_radii.push(JsBlastRadius {
            function_id: s.function_id.clone(),
            caller_count: s.blast_radius,
            risk_score: s.risk_score,
            max_depth: 0,
        });
    }

    Ok(JsImpactResult { blast_radii, dead_code })
}

// --- Raw Call Graph Access ---

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsGraphNode {
    pub key: String,
    pub file: String,
    pub name: String,
    pub qualified_name: Option<String>,
    pub language: String,
    pub line: u32,
    pub end_line: u32,
    pub is_entry_point: bool,
    pub is_exported: bool,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsGraphEdge {
    pub caller: String,
    pub callee: String,
    pub resolution: String,
    pub confidence: f64,
    pub call_site_line: u32,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsFullCallGraph {
    pub nodes: Vec<JsGraphNode>,
    pub edges: Vec<JsGraphEdge>,
    pub total_functions: u32,
    pub total_edges: u32,
    pub entry_point_count: u32,
}

/// Return the full call graph: all function nodes and call edges.
/// Unlike `drift_call_graph()` which returns aggregated stats, this returns
/// the raw graph structure suitable for import graph building, reachability
/// analysis, and dead code detection on the TypeScript side.
#[napi(js_name = "driftGetCallGraph")]
pub fn drift_get_call_graph() -> napi::Result<JsFullCallGraph> {
    let rt = runtime::get()?;

    let functions = rt.storage.with_reader(|conn| {
        conn.prepare_cached(
            "SELECT file, name, qualified_name, language, line, end_line, is_exported
             FROM functions ORDER BY file, line"
        )
        .map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })
        .and_then(|mut stmt| {
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, u32>(4)?,
                    row.get::<_, u32>(5)?,
                    row.get::<_, bool>(6)?,
                ))
            }).map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })?;
            let mut result = Vec::new();
            for row in rows {
                result.push(row.map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })?);
            }
            Ok(result)
        })
    }).map_err(storage_err)?;

    let edges = rt.storage.with_reader(|conn| {
        conn.prepare_cached(
            "SELECT caller_id, callee_id, resolution, confidence, call_site_line
             FROM call_edges"
        )
        .map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })
        .and_then(|mut stmt| {
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, f64>(3)?,
                    row.get::<_, u32>(4)?,
                ))
            }).map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })?;
            let mut result = Vec::new();
            for row in rows {
                result.push(row.map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })?);
            }
            Ok(result)
        })
    }).map_err(storage_err)?;

    let nodes: Vec<JsGraphNode> = functions.iter().enumerate().map(|(_, f)| {
        JsGraphNode {
            key: format!("{}::{}", f.0, f.1),
            file: f.0.clone(),
            name: f.1.clone(),
            qualified_name: f.2.clone(),
            language: f.3.clone(),
            line: f.4,
            end_line: f.5,
            is_entry_point: false,
            is_exported: f.6,
        }
    }).collect();

    // Build key lookup for edge resolution (caller_id/callee_id are row indices)
    let node_keys: Vec<String> = nodes.iter().map(|n| n.key.clone()).collect();

    let js_edges: Vec<JsGraphEdge> = edges.iter().filter_map(|e| {
        let caller_key = node_keys.get(e.0 as usize)?;
        let callee_key = node_keys.get(e.1 as usize)?;
        Some(JsGraphEdge {
            caller: caller_key.clone(),
            callee: callee_key.clone(),
            resolution: e.2.clone(),
            confidence: e.3,
            call_site_line: e.4,
        })
    }).collect();

    let entry_count = nodes.iter().filter(|n| n.is_exported).count() as u32;

    Ok(JsFullCallGraph {
        total_functions: nodes.len() as u32,
        total_edges: js_edges.len() as u32,
        entry_point_count: entry_count,
        nodes,
        edges: js_edges,
    })
}

// --- Import Graph ---

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsImportEdge {
    pub source_file: String,
    pub target_module: String,
    pub specifiers: Vec<String>,
    pub is_type_only: bool,
    pub line: u32,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsImportGraph {
    pub files: Vec<String>,
    pub edges: Vec<JsImportEdge>,
    pub total_imports: u32,
}

/// Return the file-level import graph: which files import from which modules.
/// Built from the persisted parse results (import statements).
#[napi(js_name = "driftGetImportGraph")]
pub fn drift_get_import_graph() -> napi::Result<JsImportGraph> {
    let rt = runtime::get()?;

    let files = rt.storage.with_reader(|conn| {
        conn.prepare_cached("SELECT DISTINCT path FROM file_metadata ORDER BY path")
            .map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })
            .and_then(|mut stmt| {
                let rows = stmt.query_map([], |row| row.get::<_, String>(0))
                    .map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })?;
                rows.collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })
            })
    }).map_err(storage_err)?;

    // Call edges at file level approximate the import graph
    let file_edges = rt.storage.with_reader(|conn| {
        conn.prepare_cached(
            "SELECT DISTINCT
                f1.file AS source_file,
                f2.file AS target_file
             FROM call_edges ce
             JOIN functions f1 ON f1.rowid = ce.caller_id + 1
             JOIN functions f2 ON f2.rowid = ce.callee_id + 1
             WHERE f1.file != f2.file"
        )
        .map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })
        .and_then(|mut stmt| {
            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            }).map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })?;
            let mut result = Vec::new();
            for row in rows {
                result.push(row.map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })?);
            }
            Ok(result)
        })
    }).map_err(storage_err)?;

    let edges: Vec<JsImportEdge> = file_edges.iter().map(|(src, tgt)| JsImportEdge {
        source_file: src.clone(),
        target_module: tgt.clone(),
        specifiers: Vec::new(),
        is_type_only: false,
        line: 0,
    }).collect();

    let total = edges.len() as u32;
    Ok(JsImportGraph { files, edges, total_imports: total })
}

// --- Entry Points ---

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsEntryPoint {
    pub file: String,
    pub function_name: String,
    pub confidence: f64,
    pub provenance: String,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsEntryPointResult {
    pub entry_points: Vec<JsEntryPoint>,
    pub total: u32,
}

/// Return detected entry points with confidence and provenance.
#[napi(js_name = "driftGetEntryPoints")]
pub fn drift_get_entry_points() -> napi::Result<JsEntryPointResult> {
    let rt = runtime::get()?;

    let functions = rt.storage.with_reader(|conn| {
        conn.prepare_cached(
            "SELECT file, name, is_exported, language FROM functions"
        )
        .map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })
        .and_then(|mut stmt| {
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, bool>(2)?,
                    row.get::<_, String>(3)?,
                ))
            }).map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })?;
            let mut result = Vec::new();
            for row in rows {
                result.push(row.map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })?);
            }
            Ok(result)
        })
    }).map_err(storage_err)?;

    let mut entry_points = Vec::new();
    for (file, name, is_exported, _lang) in &functions {
        let file_lower = file.to_lowercase();
        let name_lower = name.to_lowercase();

        let (is_entry, confidence, provenance) = if *is_exported
            && (file_lower.contains("index.") || file_lower.contains("main.")
                || file_lower.contains("app.") || file_lower.contains("server."))
        {
            (true, 0.92, "exported_main_file")
        } else if matches!(name_lower.as_str(), "main" | "createapp" | "createserver") {
            (true, 0.90, "framework_main")
        } else if name_lower.starts_with("test_") || name_lower.starts_with("spec_") {
            (true, 0.50, "test_function")
        } else if *is_exported && (file_lower.contains("/api/") || file_lower.contains("/routes/")) {
            (true, 0.85, "route_handler")
        } else if *is_exported {
            (true, 0.60, "exported")
        } else {
            (false, 0.0, "")
        };

        if is_entry {
            entry_points.push(JsEntryPoint {
                file: file.clone(),
                function_name: name.clone(),
                confidence,
                provenance: provenance.to_string(),
            });
        }
    }

    let total = entry_points.len() as u32;
    Ok(JsEntryPointResult { entry_points, total })
}

// --- Live Reachability ---

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsReachabilityInfo {
    pub reachable_files: Vec<String>,
    pub unreachable_files: Vec<String>,
    pub orphan_files: Vec<String>,
    pub total_files: u32,
    pub reachable_count: u32,
    pub unreachable_count: u32,
}

/// Compute live reachability from given entry point files.
/// Unlike `drift_reachability()` which reads cached results, this performs
/// a fresh BFS traversal using the call edge data.
#[napi(js_name = "driftGetReachability")]
pub fn drift_get_reachability(entry_point_files: Vec<String>) -> napi::Result<JsReachabilityInfo> {
    let rt = runtime::get()?;

    // Load all files
    let all_files: Vec<String> = rt.storage.with_reader(|conn| {
        conn.prepare_cached("SELECT DISTINCT path FROM file_metadata ORDER BY path")
            .map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })
            .and_then(|mut stmt| {
                let rows = stmt.query_map([], |row| row.get::<_, String>(0))
                    .map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })?;
                rows.collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })
            })
    }).map_err(storage_err)?;

    // Load file-level edges from call graph
    let file_edges: Vec<(String, String)> = rt.storage.with_reader(|conn| {
        conn.prepare_cached(
            "SELECT DISTINCT
                f1.file AS source_file,
                f2.file AS target_file
             FROM call_edges ce
             JOIN functions f1 ON f1.rowid = ce.caller_id + 1
             JOIN functions f2 ON f2.rowid = ce.callee_id + 1"
        )
        .map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })
        .and_then(|mut stmt| {
            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            }).map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })?;
            let mut result = Vec::new();
            for row in rows {
                result.push(row.map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })?);
            }
            Ok(result)
        })
    }).map_err(storage_err)?;

    // Build adjacency list and BFS from entry points
    let mut adjacency: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    let mut has_incoming: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (src, tgt) in &file_edges {
        adjacency.entry(src.clone()).or_default().push(tgt.clone());
        adjacency.entry(tgt.clone()).or_default();
        has_incoming.insert(tgt.clone());
    }

    // BFS from entry point files
    let mut reachable: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut queue: std::collections::VecDeque<String> = std::collections::VecDeque::new();
    for ep in &entry_point_files {
        if !reachable.contains(ep) {
            reachable.insert(ep.clone());
            queue.push_back(ep.clone());
        }
    }
    while let Some(file) = queue.pop_front() {
        if let Some(neighbors) = adjacency.get(&file) {
            for neighbor in neighbors {
                if reachable.insert(neighbor.clone()) {
                    queue.push_back(neighbor.clone());
                }
            }
        }
    }

    let all_file_set: std::collections::HashSet<&String> = all_files.iter().collect();
    let reachable_files: Vec<String> = all_files.iter()
        .filter(|f| reachable.contains(*f))
        .cloned()
        .collect();
    let unreachable_files: Vec<String> = all_files.iter()
        .filter(|f| !reachable.contains(*f))
        .cloned()
        .collect();
    let orphan_files: Vec<String> = all_files.iter()
        .filter(|f| !has_incoming.contains(*f) && !entry_point_files.contains(f))
        .filter(|f| adjacency.get(*f).map(|v| v.is_empty()).unwrap_or(true))
        .cloned()
        .collect();

    let _ = all_file_set;

    Ok(JsReachabilityInfo {
        total_files: all_files.len() as u32,
        reachable_count: reachable_files.len() as u32,
        unreachable_count: unreachable_files.len() as u32,
        reachable_files,
        unreachable_files,
        orphan_files,
    })
}

// --- Dead Code ---

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsDeadCodeEntry {
    pub file: String,
    pub function_name: String,
    pub reason: String,
    pub exclusion: Option<String>,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsDeadCodeResult {
    pub entries: Vec<JsDeadCodeEntry>,
    pub total: u32,
}

/// Return dead code findings from impact analysis.
#[napi(js_name = "driftGetDeadCode")]
pub fn drift_get_dead_code() -> napi::Result<JsDeadCodeResult> {
    let rt = runtime::get()?;

    let scores = rt.storage.with_reader(|conn| {
        conn.prepare_cached(
            "SELECT function_id, dead_code_reason, exclusion_category
             FROM impact_scores WHERE is_dead_code = 1"
        )
        .map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })
        .and_then(|mut stmt| {
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            }).map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })?;
            let mut result = Vec::new();
            for row in rows {
                result.push(row.map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })?);
            }
            Ok(result)
        })
    }).map_err(storage_err)?;

    let entries: Vec<JsDeadCodeEntry> = scores.iter().map(|(function_id, reason, exclusion)| {
        let parts: Vec<&str> = function_id.splitn(2, "::").collect();
        JsDeadCodeEntry {
            file: parts.first().unwrap_or(&"").to_string(),
            function_name: parts.get(1).unwrap_or(&"").to_string(),
            reason: reason.clone().unwrap_or_default(),
            exclusion: exclusion.clone(),
        }
    }).collect();

    let total = entries.len() as u32;
    Ok(JsDeadCodeResult { entries, total })
}

// --- Framework Pattern Detection ---

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsDetectedRoute {
    pub method: String,
    pub path: String,
    pub handler_key: String,
    pub file: String,
    pub confidence: f64,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsDetectedEvent {
    pub kind: String,
    pub event_name: String,
    pub symbol_key: String,
    pub file: String,
    pub confidence: f64,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsFrameworkPatterns {
    pub routes: Vec<JsDetectedRoute>,
    pub events: Vec<JsDetectedEvent>,
    pub route_count: u32,
    pub event_count: u32,
}

/// Detect framework patterns (routes, events) from the call graph.
#[napi(js_name = "driftGetFrameworkPatterns")]
pub fn drift_get_framework_patterns() -> napi::Result<JsFrameworkPatterns> {
    use drift_analysis::call_graph::{
        CallGraph, FunctionNode, CallEdge, Resolution,
        framework_detection::{detect_framework_patterns, EventKind},
    };

    let rt = runtime::get()?;

    let functions: Vec<(String, String, Option<String>, String, u32, u32, bool)> =
        rt.storage.with_reader(|conn| {
            conn.prepare_cached(
                "SELECT file, name, qualified_name, language, line, end_line, is_exported
                 FROM functions ORDER BY file, line",
            )
            .map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })
            .and_then(|mut stmt| {
                let rows = stmt
                    .query_map([], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, Option<String>>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, u32>(4)?,
                            row.get::<_, u32>(5)?,
                            row.get::<_, bool>(6)?,
                        ))
                    })
                    .map_err(|e| drift_core::errors::StorageError::SqliteError {
                        message: e.to_string(),
                    })?;
                let mut result = Vec::new();
                for row in rows {
                    result.push(row.map_err(|e| drift_core::errors::StorageError::SqliteError {
                        message: e.to_string(),
                    })?);
                }
                Ok(result)
            })
        })
        .map_err(storage_err)?;

    let edges_raw: Vec<(i64, i64, f64, u32)> = rt
        .storage
        .with_reader(|conn| {
            conn.prepare_cached(
                "SELECT caller_id, callee_id, confidence, call_site_line FROM call_edges",
            )
            .map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })
            .and_then(|mut stmt| {
                let rows = stmt
                    .query_map([], |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, f64>(2)?,
                            row.get::<_, u32>(3)?,
                        ))
                    })
                    .map_err(|e| drift_core::errors::StorageError::SqliteError {
                        message: e.to_string(),
                    })?;
                let mut result = Vec::new();
                for row in rows {
                    result.push(row.map_err(|e| drift_core::errors::StorageError::SqliteError {
                        message: e.to_string(),
                    })?);
                }
                Ok(result)
            })
        })
        .map_err(storage_err)?;

    let mut cg = CallGraph::new();
    let mut idx_map = Vec::new();
    let mut in_repo_files = drift_core::types::collections::FxHashSet::default();

    for f in &functions {
        let node = FunctionNode {
            file: f.0.clone(),
            name: f.1.clone(),
            qualified_name: f.2.clone(),
            language: f.3.clone(),
            line: f.4,
            end_line: f.5,
            is_entry_point: false,
            is_exported: f.6,
            signature_hash: 0,
            body_hash: 0,
        };
        in_repo_files.insert(f.0.clone());
        let idx = cg.add_function(node);
        idx_map.push(idx);
    }

    for (caller_id, callee_id, confidence, line) in &edges_raw {
        if let (Some(&caller_idx), Some(&callee_idx)) = (
            idx_map.get(*caller_id as usize),
            idx_map.get(*callee_id as usize),
        ) {
            cg.add_edge(
                caller_idx,
                callee_idx,
                CallEdge {
                    resolution: Resolution::ImportBased,
                    confidence: *confidence as f32,
                    call_site_line: *line,
                },
            );
        }
    }

    let result = detect_framework_patterns(&cg, &in_repo_files);

    let routes: Vec<JsDetectedRoute> = result
        .routes
        .into_iter()
        .map(|r| JsDetectedRoute {
            method: r.method,
            path: r.path,
            handler_key: r.handler_key,
            file: r.file,
            confidence: r.confidence as f64,
        })
        .collect();

    let events: Vec<JsDetectedEvent> = result
        .events
        .into_iter()
        .map(|e| JsDetectedEvent {
            kind: match e.kind {
                EventKind::Emit => "emit".to_string(),
                EventKind::Handle => "handle".to_string(),
            },
            event_name: e.event_name,
            symbol_key: e.symbol_key,
            file: e.file,
            confidence: e.confidence as f64,
        })
        .collect();

    let route_count = routes.len() as u32;
    let event_count = events.len() as u32;

    Ok(JsFrameworkPatterns {
        routes,
        events,
        route_count,
        event_count,
    })
}

// --- Test Topology ---

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsTestQuality {
    pub coverage_breadth: f64,
    pub coverage_depth: f64,
    pub assertion_density: f64,
    pub mock_ratio: f64,
    pub isolation: f64,
    pub freshness: f64,
    pub stability: f64,
    pub overall: f64,
    pub smell_count: u32,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsTestTopologyResult {
    pub quality: JsTestQuality,
    pub test_count: u32,
    pub source_count: u32,
    pub coverage_percent: f64,
    pub minimum_test_set_size: u32,
}

#[napi]
pub fn drift_test_topology(_root: String) -> napi::Result<JsTestTopologyResult> {
    let rt = runtime::get()?;

    let qualities = rt.storage.with_reader(|conn| {
        conn.prepare_cached(
            "SELECT function_id, coverage_breadth, coverage_depth, assertion_density, mock_ratio, isolation, freshness, stability, overall_score, smells
             FROM test_quality"
        )
        .map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })
        .and_then(|mut stmt| {
            let rows = stmt.query_map([], |row| {
                Ok(drift_storage::queries::graph::TestQualityRow {
                    function_id: row.get(0)?,
                    coverage_breadth: row.get(1)?,
                    coverage_depth: row.get(2)?,
                    assertion_density: row.get(3)?,
                    mock_ratio: row.get(4)?,
                    isolation: row.get(5)?,
                    freshness: row.get(6)?,
                    stability: row.get(7)?,
                    overall_score: row.get(8)?,
                    smells: row.get(9)?,
                })
            }).map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })?;
            let mut result = Vec::new();
            for row in rows {
                result.push(row.map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })?);
            }
            Ok(result)
        })
    }).map_err(storage_err)?;

    let test_count = qualities.len() as u32;
    let (avg_quality, _total_smells) = if qualities.is_empty() {
        (JsTestQuality {
            coverage_breadth: 0.0, coverage_depth: 0.0, assertion_density: 0.0,
            mock_ratio: 0.0, isolation: 1.0, freshness: 1.0, stability: 1.0,
            overall: 0.0, smell_count: 0,
        }, 0u32)
    } else {
        let n = qualities.len() as f64;
        let mut smells = 0u32;
        let mut cb = 0.0; let mut cd = 0.0; let mut ad = 0.0;
        let mut mr = 0.0; let mut iso = 0.0; let mut fr = 0.0;
        let mut st = 0.0; let mut ov = 0.0;
        for q in &qualities {
            cb += q.coverage_breadth.unwrap_or(0.0);
            cd += q.coverage_depth.unwrap_or(0.0);
            ad += q.assertion_density.unwrap_or(0.0);
            mr += q.mock_ratio.unwrap_or(0.0);
            iso += q.isolation.unwrap_or(1.0);
            fr += q.freshness.unwrap_or(1.0);
            st += q.stability.unwrap_or(1.0);
            ov += q.overall_score;
            if let Some(ref s) = q.smells {
                let arr: Vec<serde_json::Value> = serde_json::from_str(s).unwrap_or_default();
                smells += arr.len() as u32;
            }
        }
        (JsTestQuality {
            coverage_breadth: cb / n, coverage_depth: cd / n,
            assertion_density: ad / n, mock_ratio: mr / n,
            isolation: iso / n, freshness: fr / n,
            stability: st / n, overall: ov / n, smell_count: smells,
        }, smells)
    };

    let func_count = rt.storage.with_reader(|conn| {
        drift_storage::queries::functions::count_functions(conn)
    }).map_err(storage_err)? as u32;

    let coverage_percent = if func_count > 0 { (test_count as f64 / func_count as f64 * 100.0).min(100.0) } else { 0.0 };

    Ok(JsTestTopologyResult {
        quality: avg_quality,
        test_count,
        source_count: func_count,
        coverage_percent,
        minimum_test_set_size: 0,
    })
}
