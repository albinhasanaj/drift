//! XML output format using quick-xml.

use crate::generation::builder::ContextOutput;

/// XML formatter for context output.
pub struct XmlFormatter;

impl XmlFormatter {
    pub fn new() -> Self {
        Self
    }

    /// Format context output as XML.
    pub fn format(&self, output: &ContextOutput) -> String {
        let mut xml = String::new();
        xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str("<context>\n");
        xml.push_str(&format!("  <intent>{}</intent>\n", escape_xml(output.intent.name())));
        xml.push_str(&format!("  <depth>{}</depth>\n", escape_xml(output.depth.name())));
        xml.push_str(&format!("  <token_count>{}</token_count>\n", output.token_count));
        xml.push_str("  <sections>\n");

        for (name, content) in &output.sections {
            xml.push_str(&format!("    <section name=\"{}\">\n", escape_xml(name)));
            xml.push_str(&format!("      {}\n", escape_xml(content)));
            xml.push_str("    </section>\n");
        }

        xml.push_str("  </sections>\n");
        xml.push_str("</context>\n");
        xml
    }
}

impl Default for XmlFormatter {
    fn default() -> Self {
        Self::new()
    }
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generation::builder::ContextDepth;
    use crate::generation::intent::ContextIntent;

    #[test]
    fn test_xml_format() {
        let output = ContextOutput {
            sections: vec![("overview".to_string(), "Test content".to_string())],
            token_count: 10,
            intent: ContextIntent::UnderstandCode,
            depth: ContextDepth::Standard,
            content_hash: 12345,
        };

        let formatter = XmlFormatter::new();
        let xml = formatter.format(&output);
        assert!(xml.contains("<?xml"));
        assert!(xml.contains("<context>"));
        assert!(xml.contains("Test content"));
    }

    #[test]
    fn test_xml_escaping() {
        let output = ContextOutput {
            sections: vec![("test".to_string(), "<script>alert('xss')</script>".to_string())],
            token_count: 5,
            intent: ContextIntent::FixBug,
            depth: ContextDepth::Overview,
            content_hash: 0,
        };

        let formatter = XmlFormatter::new();
        let xml = formatter.format(&output);
        assert!(!xml.contains("<script>"));
        assert!(xml.contains("&lt;script&gt;"));
    }
}
