//! Markdown output format.

use crate::generation::builder::ContextOutput;

/// Markdown formatter for context output.
pub struct MarkdownFormatter;

impl MarkdownFormatter {
    pub fn new() -> Self {
        Self
    }

    /// Format context output as Markdown.
    pub fn format(&self, output: &ContextOutput) -> String {
        let mut md = String::new();
        md.push_str(&format!("# Context: {} ({})\n\n", output.intent.name(), output.depth.name()));
        md.push_str(&format!("*Token count: {}*\n\n", output.token_count));

        for (name, content) in &output.sections {
            md.push_str(&format!("## {}\n\n", escape_markdown_header(name)));
            md.push_str(content);
            md.push_str("\n\n");
        }

        md
    }
}

impl Default for MarkdownFormatter {
    fn default() -> Self {
        Self::new()
    }
}

/// Escape markdown injection in headers.
fn escape_markdown_header(s: &str) -> String {
    s.replace('#', "\\#")
        .replace('\n', " ")
        .replace('\r', "")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generation::builder::ContextDepth;
    use crate::generation::intent::ContextIntent;

    #[test]
    fn test_markdown_format() {
        let output = ContextOutput {
            sections: vec![("overview".to_string(), "Test content".to_string())],
            token_count: 10,
            intent: ContextIntent::UnderstandCode,
            depth: ContextDepth::Standard,
            content_hash: 12345,
        };

        let formatter = MarkdownFormatter::new();
        let md = formatter.format(&output);
        assert!(md.contains("# Context:"));
        assert!(md.contains("## overview"));
        assert!(md.contains("Test content"));
    }

    #[test]
    fn test_markdown_header_escaping() {
        let escaped = escape_markdown_header("## Injected Header\n\nMalicious");
        assert!(!escaped.contains("\n"));
        assert!(escaped.contains("\\#\\# Injected Header"));
    }
}
