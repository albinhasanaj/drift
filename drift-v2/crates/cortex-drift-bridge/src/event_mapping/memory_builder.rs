//! Builder pattern for BaseMemory construction.
//!
//! Eliminates repetitive `BaseMemory { ... }` blocks across mapper.rs and events.rs.
//! Auto-computes content_hash via blake3.

use chrono::Utc;
use cortex_core::memory::base::{BaseMemory, TypedContent};
use cortex_core::memory::confidence::Confidence;
use cortex_core::memory::importance::Importance;
use cortex_core::memory::links::{ConstraintLink, FileLink, FunctionLink, PatternLink};
use cortex_core::MemoryType;

use crate::errors::{BridgeError, BridgeResult};

/// Fluent builder for `BaseMemory`.
pub struct MemoryBuilder {
    memory_type: MemoryType,
    content: Option<TypedContent>,
    summary: String,
    confidence: f64,
    importance: Importance,
    tags: Vec<String>,
    linked_patterns: Vec<PatternLink>,
    linked_constraints: Vec<ConstraintLink>,
    linked_files: Vec<FileLink>,
    linked_functions: Vec<FunctionLink>,
    supersedes: Option<String>,
}

impl MemoryBuilder {
    /// Start building a memory of the given type.
    pub fn new(memory_type: MemoryType) -> Self {
        Self {
            memory_type,
            content: None,
            summary: String::new(),
            confidence: 0.5,
            importance: Importance::Normal,
            tags: vec!["drift_bridge".to_string()],
            linked_patterns: vec![],
            linked_constraints: vec![],
            linked_files: vec![],
            linked_functions: vec![],
            supersedes: None,
        }
    }

    /// Set the typed content.
    pub fn content(mut self, content: TypedContent) -> Self {
        self.content = Some(content);
        self
    }

    /// Set the summary string.
    pub fn summary(mut self, summary: impl Into<String>) -> Self {
        self.summary = summary.into();
        self
    }

    /// Set the initial confidence (0.0–1.0).
    pub fn confidence(mut self, c: f64) -> Self {
        self.confidence = c.clamp(0.0, 1.0);
        self
    }

    /// Set the importance level.
    pub fn importance(mut self, i: Importance) -> Self {
        self.importance = i;
        self
    }

    /// Add tags (appended to the default "drift_bridge" tag).
    pub fn tags(mut self, tags: Vec<String>) -> Self {
        self.tags.extend(tags);
        self
    }

    /// Add a single tag.
    pub fn tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Set linked pattern links.
    pub fn linked_patterns(mut self, patterns: Vec<PatternLink>) -> Self {
        self.linked_patterns = patterns;
        self
    }

    /// Convenience: set linked patterns from IDs (creates PatternLink with empty name).
    pub fn linked_pattern_ids(mut self, ids: Vec<String>) -> Self {
        self.linked_patterns = ids
            .into_iter()
            .map(|id| PatternLink {
                pattern_name: String::new(),
                pattern_id: id,
            })
            .collect();
        self
    }

    /// Set linked constraint links.
    pub fn linked_constraints(mut self, constraints: Vec<ConstraintLink>) -> Self {
        self.linked_constraints = constraints;
        self
    }

    /// Set linked file links.
    pub fn linked_files(mut self, files: Vec<FileLink>) -> Self {
        self.linked_files = files;
        self
    }

    /// Set linked function links.
    pub fn linked_functions(mut self, functions: Vec<FunctionLink>) -> Self {
        self.linked_functions = functions;
        self
    }

    /// Set the ID of the memory this one supersedes.
    pub fn supersedes(mut self, id: impl Into<String>) -> Self {
        self.supersedes = Some(id.into());
        self
    }

    /// Build the BaseMemory. Returns an error if content was not set.
    pub fn build(self) -> BridgeResult<BaseMemory> {
        let content = self.content.ok_or_else(|| {
            BridgeError::MemoryCreationFailed {
                memory_type: format!("{:?}", self.memory_type),
                reason: "content must be set before build()".to_string(),
            }
        })?;

        let now = Utc::now();

        let content_hash = BaseMemory::compute_content_hash(&content)
            .unwrap_or_else(|_| blake3::hash(b"fallback").to_hex().to_string());

        Ok(BaseMemory {
            id: uuid::Uuid::new_v4().to_string(),
            memory_type: self.memory_type,
            content,
            summary: self.summary,
            transaction_time: now,
            valid_time: now,
            valid_until: None,
            confidence: Confidence::new(self.confidence),
            importance: self.importance,
            last_accessed: now,
            access_count: 0,
            linked_patterns: self.linked_patterns,
            linked_constraints: self.linked_constraints,
            linked_files: self.linked_files,
            linked_functions: self.linked_functions,
            tags: self.tags,
            archived: false,
            superseded_by: None,
            supersedes: self.supersedes,
            content_hash,
            namespace: Default::default(),
            source_agent: Default::default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cortex_core::memory::types::InsightContent;

    #[test]
    fn test_builder_basic() {
        let memory = MemoryBuilder::new(MemoryType::Insight)
            .content(TypedContent::Insight(InsightContent {
                observation: "test".to_string(),
                evidence: vec![],
            }))
            .summary("Test insight")
            .confidence(0.8)
            .importance(Importance::High)
            .tag("test_tag")
            .build()
            .expect("build should succeed");

        assert_eq!(memory.memory_type, MemoryType::Insight);
        assert!((memory.confidence.value() - 0.8).abs() < 0.01);
        assert_eq!(memory.importance, Importance::High);
        assert!(memory.tags.contains(&"drift_bridge".to_string()));
        assert!(memory.tags.contains(&"test_tag".to_string()));
        assert!(!memory.id.is_empty());
        assert!(!memory.content_hash.is_empty());
    }

    #[test]
    fn test_builder_with_links() {
        use cortex_core::memory::links::{FileLink, FunctionLink};

        let memory = MemoryBuilder::new(MemoryType::PatternRationale)
            .content(TypedContent::Insight(InsightContent {
                observation: "linked".to_string(),
                evidence: vec![],
            }))
            .summary("Linked memory")
            .linked_pattern_ids(vec!["p1".to_string()])
            .linked_files(vec![FileLink {
                file_path: "src/main.rs".to_string(),
                line_start: None,
                line_end: None,
                content_hash: None,
            }])
            .linked_functions(vec![FunctionLink {
                function_name: "main".to_string(),
                file_path: "src/main.rs".to_string(),
                signature: None,
            }])
            .build()
            .expect("build should succeed");

        assert_eq!(memory.linked_patterns.len(), 1);
        assert_eq!(memory.linked_patterns[0].pattern_id, "p1");
        assert_eq!(memory.linked_files.len(), 1);
        assert_eq!(memory.linked_functions.len(), 1);
    }

    #[test]
    fn test_builder_confidence_clamped() {
        let memory = MemoryBuilder::new(MemoryType::Insight)
            .content(TypedContent::Insight(InsightContent {
                observation: "clamped".to_string(),
                evidence: vec![],
            }))
            .summary("Clamped")
            .confidence(1.5)
            .build()
            .expect("build should succeed");

        assert!((memory.confidence.value() - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_builder_returns_error_without_content() {
        let result = MemoryBuilder::new(MemoryType::Insight)
            .summary("No content")
            .build();

        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("content must be set"), "Error: {}", msg);
    }
}
