//! Sensitivity classification for reachability results.
//!
//! Classifies reachability paths based on data sensitivity:
//! - Critical: user input → SQL/command execution
//! - High: user input → file/network operations
//! - Medium: admin → sensitive operations
//! - Low: internal only

use petgraph::graph::NodeIndex;

use crate::call_graph::types::CallGraph;

use super::types::SensitivityCategory;

/// Classify the sensitivity of a reachability result.
///
/// Examines the source and reachable nodes to determine if user input
/// can reach dangerous operations.
pub fn classify_sensitivity(
    graph: &CallGraph,
    source: NodeIndex,
    reachable: &[NodeIndex],
) -> SensitivityCategory {
    let source_node = match graph.graph.node_weight(source) {
        Some(n) => n,
        None => return SensitivityCategory::Low,
    };

    let source_is_user_input = is_user_input_source(&source_node.name, &source_node.file);
    let source_is_admin = is_admin_source(&source_node.name, &source_node.file);

    let mut has_sql_sink = false;
    let mut has_command_sink = false;
    let mut has_file_sink = false;
    let mut has_network_sink = false;

    for &node_idx in reachable {
        if let Some(node) = graph.graph.node_weight(node_idx) {
            if is_sql_sink(&node.name) || is_command_sink(&node.name) {
                if is_sql_sink(&node.name) {
                    has_sql_sink = true;
                }
                if is_command_sink(&node.name) {
                    has_command_sink = true;
                }
            }
            if is_file_sink(&node.name) {
                has_file_sink = true;
            }
            if is_network_sink(&node.name) {
                has_network_sink = true;
            }
        }
    }

    if source_is_user_input && (has_sql_sink || has_command_sink) {
        SensitivityCategory::Critical
    } else if source_is_user_input && (has_file_sink || has_network_sink) {
        SensitivityCategory::High
    } else if source_is_admin && (has_sql_sink || has_command_sink || has_file_sink) {
        SensitivityCategory::Medium
    } else {
        SensitivityCategory::Low
    }
}

/// Check if a function name/file indicates user input source.
fn is_user_input_source(name: &str, file: &str) -> bool {
    let name_lower = name.to_lowercase();
    let file_lower = file.to_lowercase();

    // Route handlers, request handlers, API endpoints
    name_lower.contains("handler")
        || name_lower.contains("controller")
        || name_lower.contains("endpoint")
        || name_lower.starts_with("get_")
        || name_lower.starts_with("post_")
        || name_lower.starts_with("put_")
        || name_lower.starts_with("delete_")
        || name_lower.starts_with("patch_")
        || name_lower.contains("request")
        || name_lower.contains("req")
        || file_lower.contains("route")
        || file_lower.contains("controller")
        || file_lower.contains("handler")
        || file_lower.contains("api")
        || file_lower.contains("view")
}

/// Check if a function name/file indicates admin-only source.
fn is_admin_source(name: &str, file: &str) -> bool {
    let name_lower = name.to_lowercase();
    let file_lower = file.to_lowercase();

    name_lower.contains("admin")
        || name_lower.contains("internal")
        || name_lower.contains("management")
        || file_lower.contains("admin")
        || file_lower.contains("internal")
        || file_lower.contains("management")
}

/// Check if a function name indicates SQL query execution.
fn is_sql_sink(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.contains("query")
        || lower.contains("execute")
        || lower.contains("exec_sql")
        || lower.contains("raw_sql")
        || lower.contains("db_query")
        || lower.contains("sql")
        || lower == "execute"
        || lower == "query"
}

/// Check if a function name indicates command execution.
fn is_command_sink(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.contains("exec")
        || lower.contains("spawn")
        || lower.contains("system")
        || lower.contains("popen")
        || lower.contains("shell")
        || lower.contains("run_command")
        || lower == "exec"
        || lower == "eval"
}

/// Check if a function name indicates file operations.
fn is_file_sink(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.contains("write_file")
        || lower.contains("read_file")
        || lower.contains("open_file")
        || lower.contains("fs_write")
        || lower.contains("fs_read")
        || lower.contains("unlink")
        || lower.contains("readfile")
        || lower.contains("writefile")
}

/// Check if a function name indicates network operations.
fn is_network_sink(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.contains("fetch")
        || lower.contains("http_request")
        || lower.contains("send_request")
        || lower.contains("redirect")
        || lower.contains("forward")
        || lower.contains("proxy")
}
