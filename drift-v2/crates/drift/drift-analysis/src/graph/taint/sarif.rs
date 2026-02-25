//! SARIF code flow generation for taint paths.
//!
//! Generates SARIF v2.1.0 compliant output for CI/CD integration.

use serde::{Deserialize, Serialize};

use super::types::TaintFlow;

/// Generate a SARIF report from taint analysis results.
pub fn generate_sarif(flows: &[TaintFlow], tool_name: &str, tool_version: &str) -> SarifReport {
    let mut results = Vec::new();

    for (i, flow) in flows.iter().enumerate() {
        if !flow.is_sanitized {
            results.push(build_sarif_result(flow, i));
        }
    }

    SarifReport {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json".to_string(),
        version: "2.1.0".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: tool_name.to_string(),
                    version: tool_version.to_string(),
                    rules: build_rules(flows),
                },
            },
            results,
        }],
    }
}

/// Build a SARIF result from a taint flow.
fn build_sarif_result(flow: &TaintFlow, index: usize) -> SarifResult {
    let rule_id = format!(
        "CWE-{}",
        flow.cwe_id.unwrap_or(0)
    );

    let message = format!(
        "Taint flow from {} (line {}) to {} (line {}): {} → {}",
        flow.source.file,
        flow.source.line,
        flow.sink.file,
        flow.sink.line,
        flow.source.source_type.name(),
        flow.sink.sink_type.name(),
    );

    let code_flows = vec![build_code_flow(flow)];

    SarifResult {
        rule_id,
        rule_index: index,
        level: "error".to_string(),
        message: SarifMessage { text: message },
        locations: vec![SarifLocation {
            physical_location: SarifPhysicalLocation {
                artifact_location: SarifArtifactLocation {
                    uri: flow.sink.file.clone(),
                },
                region: SarifRegion {
                    start_line: flow.sink.line,
                    start_column: Some(flow.sink.column),
                },
            },
        }],
        code_flows,
    }
}

/// Build a SARIF code flow from a taint flow.
fn build_code_flow(flow: &TaintFlow) -> SarifCodeFlow {
    let mut thread_flows = Vec::new();

    // Source location
    thread_flows.push(SarifThreadFlowLocation {
        location: SarifLocation {
            physical_location: SarifPhysicalLocation {
                artifact_location: SarifArtifactLocation {
                    uri: flow.source.file.clone(),
                },
                region: SarifRegion {
                    start_line: flow.source.line,
                    start_column: Some(flow.source.column),
                },
            },
        },
        kinds: vec!["source".to_string()],
        message: Some(SarifMessage {
            text: format!("Taint source: {}", flow.source.expression),
        }),
    });

    // Intermediate hops
    for hop in &flow.path {
        thread_flows.push(SarifThreadFlowLocation {
            location: SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: hop.file.clone(),
                    },
                    region: SarifRegion {
                        start_line: hop.line,
                        start_column: Some(hop.column),
                    },
                },
            },
            kinds: vec!["pass-through".to_string()],
            message: Some(SarifMessage {
                text: hop.description.clone(),
            }),
        });
    }

    // Sink location
    thread_flows.push(SarifThreadFlowLocation {
        location: SarifLocation {
            physical_location: SarifPhysicalLocation {
                artifact_location: SarifArtifactLocation {
                    uri: flow.sink.file.clone(),
                },
                region: SarifRegion {
                    start_line: flow.sink.line,
                    start_column: Some(flow.sink.column),
                },
            },
        },
        kinds: vec!["sink".to_string()],
        message: Some(SarifMessage {
            text: format!("Taint sink: {}", flow.sink.expression),
        }),
    });

    SarifCodeFlow {
        thread_flows: vec![SarifThreadFlow {
            locations: thread_flows,
        }],
    }
}

/// Build SARIF rules from taint flows.
fn build_rules(flows: &[TaintFlow]) -> Vec<SarifRule> {
    let mut seen_cwes = std::collections::HashSet::new();
    let mut rules = Vec::new();

    for flow in flows {
        if let Some(cwe_id) = flow.cwe_id {
            if seen_cwes.insert(cwe_id) {
                rules.push(SarifRule {
                    id: format!("CWE-{}", cwe_id),
                    name: flow.sink.sink_type.name().to_string(),
                    short_description: SarifMessage {
                        text: format!("CWE-{}: {}", cwe_id, cwe_description(cwe_id)),
                    },
                    help_uri: Some(format!("https://cwe.mitre.org/data/definitions/{}.html", cwe_id)),
                });
            }
        }
    }

    rules
}

/// Get a short description for a CWE ID.
fn cwe_description(cwe_id: u32) -> &'static str {
    match cwe_id {
        22 => "Improper Limitation of a Pathname to a Restricted Directory",
        78 => "Improper Neutralization of Special Elements used in an OS Command",
        79 => "Improper Neutralization of Input During Web Page Generation",
        89 => "Improper Neutralization of Special Elements used in an SQL Command",
        90 => "Improper Neutralization of Special Elements used in an LDAP Query",
        94 => "Improper Control of Generation of Code",
        113 => "Improper Neutralization of CRLF Sequences in HTTP Headers",
        117 => "Improper Output Neutralization for Logs",
        434 => "Unrestricted Upload of File with Dangerous Type",
        502 => "Deserialization of Untrusted Data",
        601 => "URL Redirection to Untrusted Site",
        611 => "Improper Restriction of XML External Entity Reference",
        643 => "Improper Neutralization of Data within XPath Expressions",
        918 => "Server-Side Request Forgery",
        1333 => "Inefficient Regular Expression Complexity",
        1336 => "Improper Neutralization of Special Elements Used in a Template Engine",
        _ => "Unknown CWE",
    }
}

// --- SARIF data structures ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifReport {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<SarifRun>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifDriver {
    pub name: String,
    pub version: String,
    pub rules: Vec<SarifRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRule {
    pub id: String,
    pub name: String,
    #[serde(rename = "shortDescription")]
    pub short_description: SarifMessage,
    #[serde(rename = "helpUri", skip_serializing_if = "Option::is_none")]
    pub help_uri: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifResult {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    #[serde(rename = "ruleIndex")]
    pub rule_index: usize,
    pub level: String,
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
    #[serde(rename = "codeFlows")]
    pub code_flows: Vec<SarifCodeFlow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifMessage {
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    pub physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,
    pub region: SarifRegion,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifArtifactLocation {
    pub uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRegion {
    #[serde(rename = "startLine")]
    pub start_line: u32,
    #[serde(rename = "startColumn", skip_serializing_if = "Option::is_none")]
    pub start_column: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifCodeFlow {
    #[serde(rename = "threadFlows")]
    pub thread_flows: Vec<SarifThreadFlow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifThreadFlow {
    pub locations: Vec<SarifThreadFlowLocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifThreadFlowLocation {
    pub location: SarifLocation,
    pub kinds: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<SarifMessage>,
}
