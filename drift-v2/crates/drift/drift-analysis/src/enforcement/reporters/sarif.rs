//! SARIF 2.1.0 reporter with CWE + OWASP taxonomies for GitHub Code Scanning.

use serde_json::{json, Value};

use crate::enforcement::gates::GateResult;
use crate::enforcement::rules::Severity;
use super::Reporter;

/// SARIF 2.1.0 reporter.
pub struct SarifReporter {
    pub tool_name: String,
    pub tool_version: String,
}

impl SarifReporter {
    pub fn new() -> Self {
        Self {
            tool_name: "drift".to_string(),
            tool_version: "2.0.0".to_string(),
        }
    }

    fn severity_to_sarif_level(severity: &Severity) -> &'static str {
        match severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Info => "note",
            Severity::Hint => "note",
        }
    }

    fn build_results(&self, gate_results: &[GateResult]) -> Vec<Value> {
        let mut results = Vec::new();

        for gate_result in gate_results {
            for violation in &gate_result.violations {
                if violation.suppressed {
                    continue;
                }

                let mut result = json!({
                    "ruleId": violation.rule_id,
                    "level": Self::severity_to_sarif_level(&violation.severity),
                    "message": {
                        "text": violation.message
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": violation.file,
                                "uriBaseId": "%SRCROOT%"
                            },
                            "region": self.build_region(violation)
                        }
                    }]
                });

                // Add properties (is_new, CWE, OWASP)
                let mut properties = serde_json::Map::new();
                properties.insert("isNew".to_string(), json!(violation.is_new));
                if let Some(cwe_id) = violation.cwe_id {
                    properties.insert("cweId".to_string(), json!(format!("CWE-{cwe_id}")));
                }
                if let Some(ref owasp) = violation.owasp_category {
                    properties.insert("owaspCategory".to_string(), json!(owasp));
                }
                result["properties"] = Value::Object(properties);

                // Add quick fix if available
                if let Some(ref fix) = violation.quick_fix {
                    result["fixes"] = json!([{
                        "description": {
                            "text": fix.description
                        }
                    }]);
                }

                results.push(result);
            }
        }

        results
    }

    fn build_region(
        &self,
        violation: &crate::enforcement::rules::Violation,
    ) -> Value {
        let mut region = json!({
            "startLine": violation.line.max(1)
        });
        if let Some(col) = violation.column {
            region["startColumn"] = json!(col);
        }
        if let Some(end_line) = violation.end_line {
            region["endLine"] = json!(end_line);
        }
        if let Some(end_col) = violation.end_column {
            region["endColumn"] = json!(end_col);
        }
        region
    }

    fn build_rules(&self, gate_results: &[GateResult]) -> Vec<Value> {
        let mut seen = std::collections::HashSet::new();
        let mut rules = Vec::new();

        for gate_result in gate_results {
            for violation in &gate_result.violations {
                if seen.insert(violation.rule_id.clone()) {
                    let mut rule = json!({
                        "id": violation.rule_id,
                        "shortDescription": {
                            "text": violation.message.chars().take(100).collect::<String>()
                        },
                        "defaultConfiguration": {
                            "level": Self::severity_to_sarif_level(&violation.severity)
                        }
                    });

                    // Add taxonomy relationships on the rule (SARIF 2.1.0 §3.49.3)
                    let mut relationships = Vec::new();
                    if let Some(cwe_id) = violation.cwe_id {
                        relationships.push(json!({
                            "target": {
                                "id": format!("CWE-{cwe_id}"),
                                "toolComponent": {
                                    "name": "CWE",
                                    "index": 0
                                }
                            },
                            "kinds": ["superset"]
                        }));
                        rule["properties"] = json!({
                            "tags": [format!("CWE-{cwe_id}")]
                        });
                    }
                    if let Some(ref owasp) = violation.owasp_category {
                        relationships.push(json!({
                            "target": {
                                "id": owasp,
                                "toolComponent": {
                                    "name": "OWASP",
                                    "index": 1
                                }
                            },
                            "kinds": ["superset"]
                        }));
                    }
                    if !relationships.is_empty() {
                        rule["relationships"] = Value::Array(relationships);
                    }

                    rules.push(rule);
                }
            }
        }

        rules
    }

    fn build_taxonomies(&self, gate_results: &[GateResult]) -> Vec<Value> {
        let mut taxonomies = Vec::new();

        // CWE taxonomy
        let mut cwe_taxa = Vec::new();
        let mut seen_cwes = std::collections::HashSet::new();
        for gr in gate_results {
            for v in &gr.violations {
                if let Some(cwe_id) = v.cwe_id {
                    if seen_cwes.insert(cwe_id) {
                        cwe_taxa.push(json!({
                            "id": format!("CWE-{cwe_id}"),
                            "name": format!("CWE-{cwe_id}")
                        }));
                    }
                }
            }
        }
        if !cwe_taxa.is_empty() {
            taxonomies.push(json!({
                "name": "CWE",
                "version": "4.13",
                "organization": "MITRE",
                "shortDescription": {
                    "text": "Common Weakness Enumeration"
                },
                "taxa": cwe_taxa
            }));
        }

        // OWASP taxonomy
        let mut owasp_taxa = Vec::new();
        let mut seen_owasp = std::collections::HashSet::new();
        for gr in gate_results {
            for v in &gr.violations {
                if let Some(ref owasp) = v.owasp_category {
                    if seen_owasp.insert(owasp.clone()) {
                        owasp_taxa.push(json!({
                            "id": owasp,
                            "name": owasp
                        }));
                    }
                }
            }
        }
        if !owasp_taxa.is_empty() {
            taxonomies.push(json!({
                "name": "OWASP",
                "version": "2021",
                "organization": "OWASP Foundation",
                "shortDescription": {
                    "text": "OWASP Top 10"
                },
                "taxa": owasp_taxa
            }));
        }

        taxonomies
    }
}

impl Default for SarifReporter {
    fn default() -> Self {
        Self::new()
    }
}

impl Reporter for SarifReporter {
    fn name(&self) -> &'static str {
        "sarif"
    }

    fn generate(&self, results: &[GateResult]) -> Result<String, String> {
        let sarif_results = self.build_results(results);
        let rules = self.build_rules(results);
        let taxonomies = self.build_taxonomies(results);

        let sarif = json!({
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": self.tool_name,
                        "version": self.tool_version,
                        "informationUri": "https://github.com/drift-lang/drift",
                        "rules": rules
                    }
                },
                "results": sarif_results,
                "taxonomies": taxonomies
            }]
        });

        serde_json::to_string_pretty(&sarif).map_err(|e| e.to_string())
    }
}
