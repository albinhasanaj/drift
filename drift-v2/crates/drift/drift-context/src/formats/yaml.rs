//! YAML output format using serde_yaml.

use serde::Serialize;
use crate::generation::builder::ContextOutput;

/// YAML formatter for context output.
pub struct YamlFormatter;

impl YamlFormatter {
    pub fn new() -> Self {
        Self
    }

    /// Format context output as YAML.
    pub fn format(&self, output: &ContextOutput) -> String {
        let doc = YamlDoc {
            intent: output.intent.name().to_string(),
            depth: output.depth.name().to_string(),
            token_count: output.token_count,
            sections: output.sections.iter().map(|(name, content)| {
                YamlSection {
                    name: name.clone(),
                    content: content.clone(),
                }
            }).collect(),
        };

        serde_yaml::to_string(&doc).unwrap_or_else(|_| "# Error formatting YAML\n".to_string())
    }
}

impl Default for YamlFormatter {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Serialize)]
struct YamlDoc {
    intent: String,
    depth: String,
    token_count: usize,
    sections: Vec<YamlSection>,
}

#[derive(Serialize)]
struct YamlSection {
    name: String,
    content: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generation::builder::ContextDepth;
    use crate::generation::intent::ContextIntent;

    #[test]
    fn test_yaml_format() {
        let output = ContextOutput {
            sections: vec![("overview".to_string(), "Test content".to_string())],
            token_count: 10,
            intent: ContextIntent::UnderstandCode,
            depth: ContextDepth::Standard,
            content_hash: 12345,
        };

        let formatter = YamlFormatter::new();
        let yaml = formatter.format(&output);
        assert!(yaml.contains("intent:"));
        assert!(yaml.contains("Test content"));
    }
}
