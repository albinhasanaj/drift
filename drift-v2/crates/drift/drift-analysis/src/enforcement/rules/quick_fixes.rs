//! Quick-fix generator — 7 fix strategies for violations.

use super::types::*;

/// Generates quick-fix suggestions for violations.
pub struct QuickFixGenerator {
    /// Language hint for generating language-appropriate templates.
    language: Option<String>,
}

impl QuickFixGenerator {
    pub fn new() -> Self {
        Self { language: None }
    }

    /// Set the language for language-aware fix generation.
    pub fn with_language(mut self, language: impl Into<String>) -> Self {
        self.language = Some(language.into());
        self
    }

    /// Suggest a quick fix for an outlier based on its pattern category.
    pub fn suggest(&self, pattern: &PatternInfo, outlier: &OutlierLocation) -> Option<QuickFix> {
        let strategy = self.select_strategy(pattern, outlier)?;
        let description = self.describe_fix(&strategy, pattern, outlier);
        let replacement = self.generate_replacement(&strategy, pattern, outlier);

        Some(QuickFix {
            strategy,
            description,
            replacement,
        })
    }

    /// Select the appropriate fix strategy based on pattern category.
    fn select_strategy(
        &self,
        pattern: &PatternInfo,
        _outlier: &OutlierLocation,
    ) -> Option<QuickFixStrategy> {
        match pattern.category.as_str() {
            "naming" | "convention" => Some(QuickFixStrategy::Rename),
            "error_handling" => Some(QuickFixStrategy::WrapInTryCatch),
            "import" | "dependency" => Some(QuickFixStrategy::AddImport),
            "type_safety" => Some(QuickFixStrategy::AddTypeAnnotation),
            "documentation" => Some(QuickFixStrategy::AddDocumentation),
            "test_coverage" => Some(QuickFixStrategy::AddTest),
            "complexity" | "decomposition" => Some(QuickFixStrategy::ExtractFunction),
            "security" | "taint" => Some(QuickFixStrategy::UseParameterizedQuery),
            "crypto" => Some(QuickFixStrategy::WrapInTryCatch),
            _ => None,
        }
    }

    /// Generate a human-readable description of the fix.
    fn describe_fix(
        &self,
        strategy: &QuickFixStrategy,
        pattern: &PatternInfo,
        _outlier: &OutlierLocation,
    ) -> String {
        match strategy {
            QuickFixStrategy::AddImport => {
                format!("Add missing import for pattern '{}'", pattern.pattern_id)
            }
            QuickFixStrategy::Rename => {
                format!(
                    "Rename to match '{}' convention pattern",
                    pattern.pattern_id
                )
            }
            QuickFixStrategy::ExtractFunction => {
                "Extract complex logic into a separate function".to_string()
            }
            QuickFixStrategy::WrapInTryCatch => {
                let lang = self.language.as_deref().unwrap_or("javascript");
                match lang {
                    "python" => "Wrap in try/except block for proper error handling".to_string(),
                    "rust" => "Use match on Result for proper error handling".to_string(),
                    "go" => "Add if err != nil check for proper error handling".to_string(),
                    "ruby" => "Wrap in begin/rescue block for proper error handling".to_string(),
                    _ => "Wrap in try/catch block for proper error handling".to_string(),
                }
            }
            QuickFixStrategy::AddTypeAnnotation => {
                "Add type annotation for type safety".to_string()
            }
            QuickFixStrategy::AddTest => {
                format!("Add test coverage for pattern '{}'", pattern.pattern_id)
            }
            QuickFixStrategy::AddDocumentation => {
                "Add documentation comment".to_string()
            }
            QuickFixStrategy::UseParameterizedQuery => {
                "Use parameterized query to prevent injection".to_string()
            }
        }
    }

    /// Generate replacement text for the fix (if applicable).
    fn generate_replacement(
        &self,
        strategy: &QuickFixStrategy,
        _pattern: &PatternInfo,
        _outlier: &OutlierLocation,
    ) -> Option<String> {
        let lang = self.language.as_deref().unwrap_or("javascript");
        match strategy {
            QuickFixStrategy::WrapInTryCatch => {
                Some(self.error_handling_template(lang))
            }
            QuickFixStrategy::AddDocumentation => {
                Some(self.doc_comment_template(lang))
            }
            QuickFixStrategy::AddTypeAnnotation => {
                Some(self.type_annotation_template(lang))
            }
            QuickFixStrategy::UseParameterizedQuery => {
                Some(self.parameterized_query_template(lang))
            }
            _ => None,
        }
    }

    /// Language-aware error handling template.
    fn error_handling_template(&self, lang: &str) -> String {
        match lang {
            "python" => "try:\n    # existing code\nexcept Exception as e:\n    # handle error\n    raise".to_string(),
            "rust" => "match result {\n    Ok(value) => value,\n    Err(e) => return Err(e),\n}".to_string(),
            "go" => "if err != nil {\n    return fmt.Errorf(\"operation failed: %w\", err)\n}".to_string(),
            "java" | "kotlin" => "try {\n    // existing code\n} catch (Exception e) {\n    throw new RuntimeException(e);\n}".to_string(),
            "ruby" => "begin\n  # existing code\nrescue StandardError => e\n  raise\nend".to_string(),
            "csharp" => "try {\n    // existing code\n} catch (Exception ex) {\n    throw;\n}".to_string(),
            _ => "try {\n  // existing code\n} catch (error) {\n  // handle error\n}".to_string(),
        }
    }

    /// Language-aware doc comment template.
    fn doc_comment_template(&self, lang: &str) -> String {
        match lang {
            "python" => "\"\"\"TODO: Add documentation.\"\"\"\n".to_string(),
            "rust" => "/// TODO: Add documentation\n".to_string(),
            "go" => "// TODO: Add documentation\n".to_string(),
            "ruby" => "# TODO: Add documentation\n".to_string(),
            _ => "/** TODO: Add documentation */\n".to_string(),
        }
    }

    /// Language-aware type annotation template.
    fn type_annotation_template(&self, lang: &str) -> String {
        match lang {
            "python" => ": Any".to_string(),
            "rust" => ": todo!()".to_string(),
            "go" => "interface{}".to_string(),
            "java" | "kotlin" => ": Object".to_string(),
            _ => ": unknown".to_string(),
        }
    }

    /// Language-aware parameterized query template.
    fn parameterized_query_template(&self, lang: &str) -> String {
        match lang {
            "python" => "cursor.execute(\"SELECT * FROM t WHERE id = %s\", (user_id,))".to_string(),
            "rust" => "sqlx::query(\"SELECT * FROM t WHERE id = $1\").bind(user_id)".to_string(),
            "go" => "db.Query(\"SELECT * FROM t WHERE id = ?\", userId)".to_string(),
            "java" => "PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM t WHERE id = ?\");\nps.setString(1, userId);".to_string(),
            "ruby" => "Model.where(\"id = ?\", user_id)".to_string(),
            "csharp" => "command.Parameters.AddWithValue(\"@id\", userId);".to_string(),
            "php" => "$stmt = $pdo->prepare(\"SELECT * FROM t WHERE id = :id\");\n$stmt->execute(['id' => $userId]);".to_string(),
            _ => "db.query(\"SELECT * FROM t WHERE id = ?\", [userId])".to_string(),
        }
    }
}

impl Default for QuickFixGenerator {
    fn default() -> Self {
        Self::new()
    }
}
