//! SpecificationRenderer — 11-section spec generation with token budgeting.

use drift_core::traits::{AdaptiveWeightTable, MigrationPath, WeightProvider};

use super::types::*;
use super::weights::WeightApplicator;
use crate::tokenization::counter::TokenCounter;

/// Maximum functions to show in Public API section.
const MAX_PUBLIC_FUNCTIONS: usize = 50;
/// Maximum length for rendered correction display.
const _MAX_CORRECTION_DISPLAY_LEN: usize = 10_000;

/// Specification renderer — generates 11-section specs with adaptive weights.
pub struct SpecificationRenderer {
    weight_applicator: WeightApplicator,
    token_counter: TokenCounter,
}

impl SpecificationRenderer {
    pub fn new() -> Self {
        Self {
            weight_applicator: WeightApplicator::new(),
            token_counter: TokenCounter::default(),
        }
    }

    pub fn with_weight_provider(mut self, provider: Box<dyn WeightProvider>) -> Self {
        self.weight_applicator = WeightApplicator::with_provider(provider);
        self
    }

    /// Generate a complete specification for a logical module.
    pub fn render(
        &self,
        module: &LogicalModule,
        migration_path: Option<&MigrationPath>,
    ) -> SpecOutput {
        let weights = self.weight_applicator.get_weights(migration_path);
        let mut sections = Vec::new();

        for spec_section in SpecSection::ALL {
            let content = self.render_section(spec_section, module, &weights);
            sections.push((*spec_section, content));
        }

        let combined = sections.iter()
            .map(|(s, c)| format!("## {}\n\n{}", escape_markdown(s.name()), c))
            .collect::<Vec<_>>()
            .join("\n\n");

        let total_tokens = self.token_counter.count(&combined)
            .unwrap_or_else(|_| TokenCounter::count_approximate(&combined));

        SpecOutput {
            module_name: module.name.clone(),
            sections,
            total_token_count: total_tokens,
        }
    }

    fn render_section(
        &self,
        section: &SpecSection,
        module: &LogicalModule,
        weights: &AdaptiveWeightTable,
    ) -> String {
        let _weight = weights.get_weight(section.weight_key());

        match section {
            SpecSection::Overview => self.render_overview(module),
            SpecSection::PublicApi => self.render_public_api(module),
            SpecSection::DataModel => self.render_data_model(module),
            SpecSection::DataFlow => self.render_data_flow(module),
            SpecSection::BusinessLogic => self.render_business_logic(module),
            SpecSection::Dependencies => self.render_dependencies(module),
            SpecSection::Conventions => self.render_conventions(module),
            SpecSection::Security => self.render_security(module),
            SpecSection::Constraints => self.render_constraints(module),
            SpecSection::TestRequirements => self.render_test_requirements(module),
            SpecSection::MigrationNotes => self.render_migration_notes(module),
        }
    }

    fn render_overview(&self, module: &LogicalModule) -> String {
        let mut out = String::new();
        out.push_str(&format!("Module: {}\n\n", escape_markdown(&module.name)));
        if !module.description.is_empty() {
            out.push_str(&format!("{}\n\n", escape_markdown(&module.description)));
        }
        out.push_str(&format!("- Public functions: {}\n", module.public_functions.len()));
        out.push_str(&format!("- Data dependencies: {}\n", module.data_dependencies.len()));
        out.push_str(&format!("- Test coverage: {:.0}%\n", module.test_coverage * 100.0));
        out
    }

    fn render_public_api(&self, module: &LogicalModule) -> String {
        if module.public_functions.is_empty() {
            return "No public interface detected.\n".to_string();
        }

        let mut out = String::new();
        let total = module.public_functions.len();
        let show_count = total.min(MAX_PUBLIC_FUNCTIONS);

        // Sort by caller count descending
        let mut funcs = module.public_functions.clone();
        funcs.sort_by(|a, b| b.callers.len().cmp(&a.callers.len()));

        out.push_str("| Function | Signature | Callers |\n");
        out.push_str("|----------|-----------|--------|\n");

        for func in funcs.iter().take(show_count) {
            out.push_str(&format!(
                "| {} | {} | {} |\n",
                escape_markdown(&func.name),
                escape_markdown(&func.signature),
                func.callers.len()
            ));
        }

        if total > MAX_PUBLIC_FUNCTIONS {
            out.push_str(&format!(
                "\n*Showing {} of {} public functions*\n",
                MAX_PUBLIC_FUNCTIONS, total
            ));
        }

        out
    }

    fn render_data_model(&self, module: &LogicalModule) -> String {
        if module.data_dependencies.is_empty() {
            return "No database access detected.\n".to_string();
        }

        let mut out = String::new();
        for dep in &module.data_dependencies {
            out.push_str(&format!("### {} ({})\n\n", escape_markdown(&dep.table_name), escape_markdown(&dep.orm_framework)));
            out.push_str(&format!("Operations: {}\n", dep.operations.join(", ")));
            if !dep.sensitive_fields.is_empty() {
                out.push_str(&format!("⚠️ Sensitive fields: {}\n", dep.sensitive_fields.join(", ")));
            }
            out.push('\n');
        }
        out
    }

    fn render_data_flow(&self, module: &LogicalModule) -> String {
        if module.data_dependencies.is_empty() && module.public_functions.is_empty() {
            return "Insufficient data for data flow analysis.\n".to_string();
        }
        let mut out = String::new();
        out.push_str("Data flows through this module:\n\n");
        for func in &module.public_functions {
            if !func.callers.is_empty() {
                out.push_str(&format!("- {} ← {}\n", escape_markdown(&func.name), func.callers.join(", ")));
            }
        }
        if out.lines().count() <= 2 {
            out.push_str("Insufficient data for detailed data flow analysis.\n");
        }
        out
    }

    fn render_business_logic(&self, module: &LogicalModule) -> String {
        let mut out = String::new();
        out.push_str("⚠️ **This section requires human review.** Business logic extraction is approximate.\n\n");
        if !module.description.is_empty() {
            out.push_str(&format!("{}\n\n", escape_markdown(&module.description)));
        }
        if module.public_functions.is_empty() && module.data_dependencies.is_empty() {
            out.push_str("Insufficient data for business logic analysis.\n");
        } else {
            out.push_str(&format!(
                "This module exposes {} public functions and accesses {} data sources.\n",
                module.public_functions.len(),
                module.data_dependencies.len()
            ));
        }
        out
    }

    fn render_dependencies(&self, module: &LogicalModule) -> String {
        if module.dependencies.is_empty() {
            return "No external dependencies detected.\n".to_string();
        }
        let mut out = String::new();
        for dep in &module.dependencies {
            out.push_str(&format!("- {}\n", escape_markdown(dep)));
        }
        out
    }

    fn render_conventions(&self, module: &LogicalModule) -> String {
        if module.conventions.is_empty() {
            return "No conventions detected for this module.\n".to_string();
        }
        let mut out = String::new();
        for conv in &module.conventions {
            out.push_str(&format!("- {}\n", escape_markdown(conv)));
        }
        out
    }

    fn render_security(&self, module: &LogicalModule) -> String {
        if module.security_findings.is_empty() {
            return "No security findings for this module.\n".to_string();
        }
        let mut out = String::new();
        for finding in &module.security_findings {
            out.push_str(&format!("- {}\n", escape_markdown(finding)));
        }
        out
    }

    fn render_constraints(&self, module: &LogicalModule) -> String {
        if module.constraints.is_empty() {
            return "No constraints detected for this module.\n".to_string();
        }
        let mut out = String::new();
        for constraint in &module.constraints {
            out.push_str(&format!("- {}\n", escape_markdown(constraint)));
        }
        out
    }

    fn render_test_requirements(&self, module: &LogicalModule) -> String {
        let mut out = String::new();
        out.push_str(&format!("Current test coverage: {:.0}%\n\n", module.test_coverage * 100.0));
        if module.test_coverage < 0.8 {
            out.push_str("⚠️ Test coverage below 80% threshold.\n\n");
        }
        out.push_str("Required tests:\n");
        for func in &module.public_functions {
            out.push_str(&format!("- Unit test for `{}`\n", escape_markdown(&func.name)));
        }
        if module.public_functions.is_empty() {
            out.push_str("- No public functions to test.\n");
        }
        out
    }

    fn render_migration_notes(&self, module: &LogicalModule) -> String {
        let mut out = String::new();
        if module.error_handling_patterns.is_empty()
            && module.conventions.is_empty()
            && module.constraints.is_empty()
        {
            out.push_str("Insufficient data for migration notes.\n");
        } else {
            out.push_str("Migration considerations:\n\n");
            if !module.error_handling_patterns.is_empty() {
                out.push_str("Error handling patterns to preserve:\n");
                for p in &module.error_handling_patterns {
                    out.push_str(&format!("- {}\n", escape_markdown(p)));
                }
                out.push('\n');
            }
            if !module.conventions.is_empty() {
                out.push_str(&format!("Conventions to maintain: {}\n", module.conventions.len()));
            }
            if !module.constraints.is_empty() {
                out.push_str(&format!("Constraints to enforce: {}\n", module.constraints.len()));
            }
        }
        out
    }
}

impl Default for SpecificationRenderer {
    fn default() -> Self {
        Self::new()
    }
}

/// Escape markdown injection characters.
fn escape_markdown(s: &str) -> String {
    s.replace('|', "\\|")
        .replace('#', "\\#")
        .replace('\n', " ")
        .replace('\r', "")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
