//! ADR (Architecture Decision Record) detection in markdown files.
//!
//! Detects standard ADR format with Status, Context, Decision, Consequences sections.

use super::types::{AdrRecord, AdrStatus};

/// ADR detector — finds Architecture Decision Records in markdown content.
pub struct AdrDetector;

impl AdrDetector {
    pub fn new() -> Self {
        Self
    }

    /// Detect ADRs in a markdown file's content.
    pub fn detect(&self, file_path: &str, content: &str) -> Vec<AdrRecord> {
        let mut records = Vec::new();

        // Try to parse as a single ADR document
        if let Some(record) = self.parse_single_adr(file_path, content) {
            records.push(record);
            return records;
        }

        // Try to find embedded ADR sections
        records.extend(self.find_embedded_adrs(file_path, content));

        records
    }

    /// Parse a single ADR document (standard format).
    fn parse_single_adr(&self, file_path: &str, content: &str) -> Option<AdrRecord> {
        let lines: Vec<&str> = content.lines().collect();

        // Look for title (# heading)
        let title = lines.iter()
            .find(|l| l.starts_with("# "))
            .map(|l| l.trim_start_matches("# ").trim().to_string())?;

        // Must have at least Status and Decision sections
        let status = self.extract_section_value(&lines, "Status")?;
        let adr_status = AdrStatus::from_str_loose(&status)?;

        let context = self.extract_section_content(&lines, "Context")
            .unwrap_or_default();
        let decision = self.extract_section_content(&lines, "Decision")
            .unwrap_or_default();
        let consequences = self.extract_section_content(&lines, "Consequences")
            .unwrap_or_default();

        // Must have at least a decision section with content
        if decision.is_empty() {
            return None;
        }

        Some(AdrRecord {
            title,
            status: adr_status,
            context,
            decision,
            consequences,
            file_path: file_path.to_string(),
        })
    }

    /// Extract a single-line value after a section header.
    /// e.g., "## Status\n\nAccepted" → "Accepted"
    fn extract_section_value(&self, lines: &[&str], section: &str) -> Option<String> {
        let header_patterns = [
            format!("## {}", section),
            format!("### {}", section),
            format!("**{}**", section),
            format!("{}:", section),
        ];

        for (i, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            for pattern in &header_patterns {
                if trimmed.eq_ignore_ascii_case(pattern) || trimmed.starts_with(&format!("{}:", section)) {
                    // Check for inline value (e.g., "Status: Accepted")
                    if let Some(pos) = trimmed.find(':') {
                        let value = trimmed[pos + 1..].trim();
                        if !value.is_empty() {
                            return Some(value.to_string());
                        }
                    }
                    // Look at next non-empty line
                    for next_line in lines.iter().skip(i + 1) {
                        let next = next_line.trim();
                        if !next.is_empty() && !next.starts_with('#') && !next.starts_with("**") {
                            return Some(next.to_string());
                        }
                        if next.starts_with('#') || next.starts_with("**") {
                            break;
                        }
                    }
                }
            }
        }
        None
    }

    /// Extract multi-line content from a section.
    fn extract_section_content(&self, lines: &[&str], section: &str) -> Option<String> {
        let header_patterns = [
            format!("## {}", section),
            format!("### {}", section),
        ];

        let mut in_section = false;
        let mut content = Vec::new();

        for line in lines {
            let trimmed = line.trim();

            if in_section {
                // Stop at next section header
                if trimmed.starts_with("## ") || trimmed.starts_with("### ") {
                    break;
                }
                content.push(*line);
            } else {
                for pattern in &header_patterns {
                    if trimmed.eq_ignore_ascii_case(pattern) {
                        in_section = true;
                        break;
                    }
                }
            }
        }

        let result = content.join("\n").trim().to_string();
        if result.is_empty() { None } else { Some(result) }
    }

    /// Find embedded ADR-like sections in a larger document.
    fn find_embedded_adrs(&self, file_path: &str, content: &str) -> Vec<AdrRecord> {
        let mut records = Vec::new();
        let lines: Vec<&str> = content.lines().collect();

        // Look for ADR-numbered patterns like "ADR-001" or "ADR 1"
        let mut i = 0;
        while i < lines.len() {
            let trimmed = lines[i].trim();
            if (trimmed.contains("ADR") || trimmed.contains("adr"))
                && (trimmed.starts_with("# ") || trimmed.starts_with("## "))
            {
                // Try to parse from this point
                let sub_content = lines[i..].join("\n");
                if let Some(record) = self.parse_single_adr(file_path, &sub_content) {
                    records.push(record);
                }
            }
            i += 1;
        }

        records
    }
}

impl Default for AdrDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_standard_adr() {
        let content = r#"# ADR-001: Use PostgreSQL for primary storage

## Status

Accepted

## Context

We need a reliable relational database for our application data.

## Decision

We will use PostgreSQL as our primary database.

## Consequences

- Need to manage PostgreSQL infrastructure
- Team needs PostgreSQL expertise
- Good ecosystem support
"#;

        let detector = AdrDetector::new();
        let records = detector.detect("docs/adr/001-use-postgresql.md", content);

        assert_eq!(records.len(), 1);
        let adr = &records[0];
        assert!(adr.title.contains("PostgreSQL"));
        assert_eq!(adr.status, AdrStatus::Accepted);
        assert!(!adr.context.is_empty());
        assert!(!adr.decision.is_empty());
        assert!(!adr.consequences.is_empty());
    }

    #[test]
    fn test_detect_proposed_adr() {
        let content = r#"# ADR-002: Migrate to microservices

## Status

Proposed

## Context

Monolith is becoming hard to scale.

## Decision

Split into domain-bounded microservices.

## Consequences

Increased operational complexity.
"#;

        let detector = AdrDetector::new();
        let records = detector.detect("docs/adr/002-microservices.md", content);

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].status, AdrStatus::Proposed);
    }

    #[test]
    fn test_no_adr_in_regular_markdown() {
        let content = "# README\n\nThis is a regular readme file.\n\n## Installation\n\nRun npm install.\n";
        let detector = AdrDetector::new();
        let records = detector.detect("README.md", content);
        assert!(records.is_empty());
    }

    #[test]
    fn test_empty_content_returns_empty() {
        let detector = AdrDetector::new();
        let records = detector.detect("empty.md", "");
        assert!(records.is_empty());
    }
}
