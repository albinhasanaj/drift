//! NAPI bindings for Phase 7 advanced systems.
//!
//! Exposes: drift_simulate(), drift_decisions(), drift_context(), drift_generate_spec()

use napi::bindgen_prelude::*;
use napi_derive::napi;
use serde_json;

/// Simulate task approaches with Monte Carlo confidence intervals.
#[napi]
pub async fn drift_simulate(
    task_category: String,
    task_description: String,
    context_json: String,
) -> Result<String> {
    use drift_analysis::advanced::simulation::types::*;
    use drift_analysis::advanced::simulation::strategies::StrategyRecommender;

    // PH2-08: Parse affected_files alongside context from JSON input
    #[derive(serde::Deserialize, Default)]
    struct SimulationInput {
        #[serde(flatten)]
        context: SimulationContext,
        #[serde(default)]
        affected_files: Vec<String>,
    }

    let input: SimulationInput = serde_json::from_str(&context_json)
        .unwrap_or_default();
    let context = input.context;
    let affected_files = input.affected_files;

    let category = match task_category.as_str() {
        "add_feature" => TaskCategory::AddFeature,
        "fix_bug" => TaskCategory::FixBug,
        "refactor" => TaskCategory::Refactor,
        "migrate_framework" => TaskCategory::MigrateFramework,
        "add_test" => TaskCategory::AddTest,
        "security_fix" => TaskCategory::SecurityFix,
        "performance_optimization" => TaskCategory::PerformanceOptimization,
        "dependency_update" => TaskCategory::DependencyUpdate,
        "api_change" => TaskCategory::ApiChange,
        "database_migration" => TaskCategory::DatabaseMigration,
        "config_change" => TaskCategory::ConfigChange,
        "documentation" => TaskCategory::Documentation,
        "infrastructure" => TaskCategory::Infrastructure,
        _ => return Err(Error::from_reason(format!("Unknown task category: {}", task_category))),
    };

    let task = SimulationTask {
        category,
        description: task_description,
        affected_files,
        context,
    };

    let recommender = StrategyRecommender::new();
    let result = recommender.recommend(&task);

    serde_json::to_string(&result)
        .map_err(|e| Error::from_reason(format!("Serialization error: {}", e)))
}

/// Mine decisions from git history.
#[napi]
pub async fn drift_decisions(repo_path: String) -> Result<String> {
    use drift_core::events::types::DecisionMinedEvent;
    use drift_analysis::advanced::decisions::git_analysis::GitAnalyzer;

    let analyzer = GitAnalyzer::new().with_max_commits(500);
    let decisions = analyzer.analyze(std::path::Path::new(&repo_path))
        .map_err(|e| Error::from_reason(format!("Git analysis error: {}", e)))?;

    if let Ok(rt) = crate::runtime::get() {
        for decision in &decisions {
            rt.dispatcher.emit_decision_mined(&DecisionMinedEvent {
                decision_id: decision.id.clone(),
                category: decision.category.to_string(),
            });
        }
    }

    serde_json::to_string(&decisions)
        .map_err(|e| Error::from_reason(format!("Serialization error: {}", e)))
}

/// Generate context for a given intent and depth.
#[napi]
pub async fn drift_context(
    intent: String,
    depth: String,
    data_json: String,
) -> Result<String> {
    use drift_context::generation::builder::*;
    use drift_context::generation::intent::ContextIntent;

    let intent = match intent.as_str() {
        "fix_bug" => ContextIntent::FixBug,
        "add_feature" => ContextIntent::AddFeature,
        "understand_code" | "understand" => ContextIntent::UnderstandCode,
        "security_audit" => ContextIntent::SecurityAudit,
        "generate_spec" => ContextIntent::GenerateSpec,
        _ => return Err(Error::from_reason(format!("Unknown intent: {}", intent))),
    };

    let depth = match depth.as_str() {
        "overview" => ContextDepth::Overview,
        "standard" => ContextDepth::Standard,
        "deep" => ContextDepth::Deep,
        _ => return Err(Error::from_reason(format!("Unknown depth: {}", depth))),
    };

    let sections: std::collections::HashMap<String, String> = serde_json::from_str(&data_json)
        .unwrap_or_default();

    let mut data = AnalysisData::new();
    for (k, v) in sections {
        data.add_section(k, v);
    }

    let mut engine = ContextEngine::new();
    let output = engine.generate(intent, depth, &data)
        .map_err(|e| Error::from_reason(format!("Context generation error: {}", e)))?;

    let result = serde_json::json!({
        "sections": output.sections.iter().map(|(n, c)| {
            serde_json::json!({"name": n, "content": c})
        }).collect::<Vec<_>>(),
        "token_count": output.token_count,
        "intent": output.intent.name(),
        "depth": output.depth.name(),
    });

    serde_json::to_string(&result)
        .map_err(|e| Error::from_reason(format!("Serialization error: {}", e)))
}

/// Generate a specification document for a module.
#[napi]
pub async fn drift_generate_spec(
    module_json: String,
    migration_path_json: Option<String>,
) -> Result<String> {
    use drift_context::specification::renderer::SpecificationRenderer;
    use drift_context::specification::types::LogicalModule;
    use drift_core::traits::MigrationPath;

    let module: LogicalModule = serde_json::from_str(&module_json)
        .map_err(|e| Error::from_reason(format!("Invalid module JSON: {}", e)))?;

    let migration_path = migration_path_json
        .as_deref()
        .and_then(|json| serde_json::from_str::<MigrationPathInput>(json).ok())
        .map(|mp| MigrationPath::new(
            mp.source_language,
            mp.target_language,
            mp.source_framework,
            mp.target_framework,
        ));

    let renderer = SpecificationRenderer::new();
    let output = renderer.render(&module, migration_path.as_ref());

    let result = serde_json::json!({
        "module_name": output.module_name,
        "sections": output.sections.iter().map(|(s, c)| {
            serde_json::json!({"section": s.name(), "content": c})
        }).collect::<Vec<_>>(),
        "total_token_count": output.total_token_count,
        "has_all_sections": output.has_all_sections(),
    });

    serde_json::to_string(&result)
        .map_err(|e| Error::from_reason(format!("Serialization error: {}", e)))
}

#[derive(serde::Deserialize)]
struct MigrationPathInput {
    source_language: String,
    target_language: String,
    source_framework: Option<String>,
    target_framework: Option<String>,
}
