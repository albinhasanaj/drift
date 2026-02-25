//! BridgeEventHandler: implements DriftEventHandler, creates Cortex memories from Drift events.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use cortex_core::memory::base::TypedContent;
use cortex_core::memory::importance::Importance;
use cortex_core::memory::links::PatternLink;
use cortex_core::memory::types::*;
use drift_core::events::handler::DriftEventHandler;
use drift_core::events::types::*;
use tracing::{info, warn};

use crate::config::EventConfig;
use crate::errors::BridgeResult;
use crate::license::LicenseTier;
use crate::traits::{CortexMemoryWriter, IBridgeStorage};

use super::memory_types::{self, EventProcessingResult};

/// The bridge's implementation of DriftEventHandler.
/// Creates Cortex memories from Drift events.
pub struct BridgeEventHandler {
    /// Bridge storage for writing memories.
    bridge_store: Option<Arc<dyn IBridgeStorage>>,
    /// Optional cortex.db writer for dual-write (P0-3).
    /// When present, every memory created by the event mapper is also
    /// written to cortex.db so it is visible to Cortex retrieval.
    cortex_writer: Option<Arc<dyn CortexMemoryWriter>>,
    /// License tier for event filtering.
    license_tier: LicenseTier,
    /// Per-event enable/disable toggles.
    event_config: EventConfig,
    /// Whether the bridge is available.
    available: bool,
    /// Count of errors that occurred during event processing.
    /// Exposed via `error_count()` so monitoring systems can detect silent failures.
    error_count: AtomicU64,
}

impl BridgeEventHandler {
    /// Create a new handler. If bridge_store is None, all methods are no-ops.
    pub fn new(bridge_store: Option<Arc<dyn IBridgeStorage>>, license_tier: LicenseTier) -> Self {
        let available = bridge_store.is_some();
        Self {
            bridge_store,
            cortex_writer: None,
            license_tier,
            event_config: EventConfig::default(),
            available,
            error_count: AtomicU64::new(0),
        }
    }

    /// Create a new handler with an explicit EventConfig.
    pub fn with_event_config(
        bridge_store: Option<Arc<dyn IBridgeStorage>>,
        license_tier: LicenseTier,
        event_config: EventConfig,
    ) -> Self {
        let available = bridge_store.is_some();
        Self {
            bridge_store,
            cortex_writer: None,
            license_tier,
            event_config,
            available,
            error_count: AtomicU64::new(0),
        }
    }

    /// Create a new handler with a cortex.db dual-writer (P0-3).
    /// When `cortex_writer` is provided, every memory created by event processing
    /// is also written to cortex.db for Cortex retrieval visibility.
    pub fn with_cortex_writer(
        bridge_store: Option<Arc<dyn IBridgeStorage>>,
        license_tier: LicenseTier,
        cortex_writer: Arc<dyn CortexMemoryWriter>,
    ) -> Self {
        let available = bridge_store.is_some();
        Self {
            bridge_store,
            cortex_writer: Some(cortex_writer),
            license_tier,
            event_config: EventConfig::default(),
            available,
            error_count: AtomicU64::new(0),
        }
    }

    /// Create a no-op handler for standalone mode.
    pub fn no_op() -> Self {
        Self {
            bridge_store: None,
            cortex_writer: None,
            license_tier: LicenseTier::Community,
            event_config: EventConfig::default(),
            available: false,
            error_count: AtomicU64::new(0),
        }
    }

    /// Check if this event type is allowed by the current license tier.
    fn is_event_allowed(&self, event_type: &str) -> bool {
        if !self.available {
            return false;
        }
        // Check operator-configured event toggles first
        if !self.event_config.is_enabled(event_type) {
            return false;
        }
        match self.license_tier {
            LicenseTier::Community => {
                memory_types::community_events().contains(&event_type)
            }
            LicenseTier::Team | LicenseTier::Enterprise => true,
        }
    }

    /// Returns the number of errors that have occurred during event processing.
    /// Use this to monitor for silent failures in production.
    pub fn error_count(&self) -> u64 {
        self.error_count.load(Ordering::Relaxed)
    }

    /// Handle the result of create_memory. Logs errors and increments the error counter
    /// instead of silently swallowing them.
    fn handle_result(&self, event_type: &str, result: BridgeResult<EventProcessingResult>) {
        if let Err(e) = result {
            self.error_count.fetch_add(1, Ordering::Relaxed);
            warn!(
                event = event_type,
                error = %e,
                total_errors = self.error_count.load(Ordering::Relaxed),
                "Failed to create memory from Drift event"
            );
        }
    }

    /// Create a BaseMemory and persist it. Returns the memory ID.
    #[allow(clippy::too_many_arguments)]
    fn create_memory(
        &self,
        event_type: &str,
        memory_type: cortex_core::MemoryType,
        content: TypedContent,
        summary: String,
        confidence: f64,
        importance: Importance,
        tags: Vec<String>,
        linked_patterns: Vec<PatternLink>,
    ) -> BridgeResult<EventProcessingResult> {
        let start = Instant::now();

        let memory = super::MemoryBuilder::new(memory_type)
            .content(content)
            .summary(&summary)
            .confidence(confidence)
            .importance(importance)
            .tags(tags)
            .linked_patterns(linked_patterns)
            .build()?;

        let memory_id = memory.id.clone();

        // Persist via bridge storage (primary)
        if let Some(ref store) = self.bridge_store {
            store.insert_memory(&memory)?;
            store.insert_event(event_type, Some(&format!("{:?}", memory_type)), Some(&memory_id), Some(confidence))?;
        }

        // Dual-write to cortex.db if writer is available (P0-3).
        // Failures are non-fatal — bridge storage is the source of truth.
        if let Some(ref writer) = self.cortex_writer {
            if let Err(e) = writer.write_memory(&memory) {
                warn!(
                    event = event_type,
                    memory_id = %memory_id,
                    error = %e,
                    "Failed to dual-write memory to cortex.db — bridge copy is authoritative"
                );
            }
        }

        let duration_us = start.elapsed().as_micros() as u64;
        info!(
            event = event_type,
            memory_id = %memory_id,
            memory_type = ?memory_type,
            confidence = confidence,
            duration_us = duration_us,
            "Created memory from Drift event"
        );

        Ok(EventProcessingResult {
            event_type: event_type.to_string(),
            memory_created: true,
            memory_id: Some(memory_id),
            memory_type: Some(memory_type),
            links_created: vec![],
            duration_us,
            error: None,
        })
    }

}

impl DriftEventHandler for BridgeEventHandler {
    fn on_pattern_approved(&self, event: &PatternApprovedEvent) {
        if !self.is_event_allowed("on_pattern_approved") { return; }
        self.handle_result("on_pattern_approved", self.create_memory(
            "on_pattern_approved",
            cortex_core::MemoryType::PatternRationale,
            TypedContent::PatternRationale(PatternRationaleContent {
                pattern_name: event.pattern_id.clone(),
                rationale: format!("Pattern '{}' approved by team", event.pattern_id),
                business_context: "Approved as team convention".to_string(),
                examples: vec![],
            }),
            format!("Pattern approved: {}", event.pattern_id),
            0.8,
            Importance::High,
            vec!["drift_bridge".to_string(), "pattern_approved".to_string()],
            vec![PatternLink {
                pattern_id: event.pattern_id.clone(),
                pattern_name: event.pattern_id.clone(),
            }],
        ));
    }

    fn on_pattern_discovered(&self, event: &PatternDiscoveredEvent) {
        if !self.is_event_allowed("on_pattern_discovered") { return; }
        self.handle_result("on_pattern_discovered", self.create_memory(
            "on_pattern_discovered",
            cortex_core::MemoryType::Insight,
            TypedContent::Insight(InsightContent {
                observation: format!(
                    "New pattern '{}' discovered in category '{}' with {:.0}% confidence",
                    event.pattern_id, event.category, event.confidence * 100.0
                ),
                evidence: vec![format!("Drift confidence: {:.2}", event.confidence)],
            }),
            format!("Pattern discovered: {} ({})", event.pattern_id, event.category),
            0.5,
            Importance::Normal,
            vec!["drift_bridge".to_string(), "pattern_discovered".to_string(), format!("pattern:{}", event.pattern_id)],
            vec![],
        ));
    }

    fn on_pattern_ignored(&self, event: &PatternIgnoredEvent) {
        if !self.is_event_allowed("on_pattern_ignored") { return; }
        self.handle_result("on_pattern_ignored", self.create_memory(
            "on_pattern_ignored",
            cortex_core::MemoryType::Feedback,
            TypedContent::Feedback(FeedbackContent {
                feedback: format!("Pattern '{}' ignored: {}", event.pattern_id, event.reason),
                category: "pattern_ignored".to_string(),
                source: "drift_bridge".to_string(),
            }),
            format!("Pattern ignored: {}", event.pattern_id),
            0.6,
            Importance::Normal,
            vec!["drift_bridge".to_string(), "pattern_ignored".to_string(), format!("pattern:{}", event.pattern_id)],
            vec![],
        ));
    }

    fn on_pattern_merged(&self, event: &PatternMergedEvent) {
        if !self.is_event_allowed("on_pattern_merged") { return; }
        self.handle_result("on_pattern_merged", self.create_memory(
            "on_pattern_merged",
            cortex_core::MemoryType::DecisionContext,
            TypedContent::DecisionContext(DecisionContextContent {
                decision: format!("Merged pattern '{}' into '{}'", event.merged_id, event.kept_id),
                context: "Patterns were similar enough to merge".to_string(),
                adr_link: None,
                trade_offs: vec![
                    format!("Kept: {}", event.kept_id),
                    format!("Merged: {}", event.merged_id),
                ],
            }),
            format!("Patterns merged: {} ← {}", event.kept_id, event.merged_id),
            0.7,
            Importance::Normal,
            vec!["drift_bridge".to_string(), "pattern_merged".to_string(), format!("pattern:{}", event.kept_id)],
            vec![],
        ));
    }

    fn on_scan_complete(&self, _event: &ScanCompleteEvent) {
        // Triggers grounding loop — no memory creation.
        // Grounding is handled by the GroundingScheduler.
        if !self.available { return; }
        info!("Scan complete — grounding loop trigger point");
    }

    fn on_regression_detected(&self, event: &RegressionDetectedEvent) {
        if !self.is_event_allowed("on_regression_detected") { return; }
        self.handle_result("on_regression_detected", self.create_memory(
            "on_regression_detected",
            cortex_core::MemoryType::DecisionContext,
            TypedContent::DecisionContext(DecisionContextContent {
                decision: format!(
                    "Regression detected: pattern '{}' compliance dropped from {:.0}% to {:.0}%",
                    event.pattern_id,
                    event.previous_score * 100.0,
                    event.current_score * 100.0,
                ),
                context: "May indicate intentional architectural change or unintended drift".to_string(),
                adr_link: None,
                trade_offs: vec![
                    format!("Previous: {:.0}%", event.previous_score * 100.0),
                    format!("Current: {:.0}%", event.current_score * 100.0),
                ],
            }),
            format!("Regression: {} dropped to {:.0}%", event.pattern_id, event.current_score * 100.0),
            0.9,
            Importance::Critical,
            vec!["drift_bridge".to_string(), "regression".to_string(), format!("pattern:{}", event.pattern_id)],
            vec![PatternLink {
                pattern_id: event.pattern_id.clone(),
                pattern_name: event.pattern_id.clone(),
            }],
        ));
    }

    fn on_violation_detected(&self, _event: &ViolationDetectedEvent) {
        // No memory — too noisy.
    }

    fn on_violation_dismissed(&self, event: &ViolationDismissedEvent) {
        if !self.is_event_allowed("on_violation_dismissed") { return; }
        self.handle_result("on_violation_dismissed", self.create_memory(
            "on_violation_dismissed",
            cortex_core::MemoryType::ConstraintOverride,
            TypedContent::ConstraintOverride(ConstraintOverrideContent {
                constraint_name: event.violation_id.clone(),
                override_reason: event.reason.clone(),
                approved_by: String::new(),
                scope: "violation".to_string(),
                expiry: None,
            }),
            format!("Violation dismissed: {}", event.violation_id),
            0.7,
            Importance::Normal,
            vec!["drift_bridge".to_string(), "violation_dismissed".to_string()],
            vec![],
        ));
    }

    fn on_violation_fixed(&self, event: &ViolationFixedEvent) {
        if !self.is_event_allowed("on_violation_fixed") { return; }
        self.handle_result("on_violation_fixed", self.create_memory(
            "on_violation_fixed",
            cortex_core::MemoryType::Feedback,
            TypedContent::Feedback(FeedbackContent {
                feedback: format!("Violation '{}' fixed — confirms pattern validity", event.violation_id),
                category: "violation_fixed".to_string(),
                source: "drift_bridge".to_string(),
            }),
            format!("Violation fixed: {}", event.violation_id),
            0.8,
            Importance::Normal,
            vec!["drift_bridge".to_string(), "violation_fixed".to_string()],
            vec![],
        ));
    }

    fn on_gate_evaluated(&self, event: &GateEvaluatedEvent) {
        if !self.is_event_allowed("on_gate_evaluated") { return; }
        self.handle_result("on_gate_evaluated", self.create_memory(
            "on_gate_evaluated",
            cortex_core::MemoryType::DecisionContext,
            TypedContent::DecisionContext(DecisionContextContent {
                decision: format!(
                    "Gate '{}' {}: {}",
                    event.gate_name,
                    if event.passed { "passed" } else { "failed" },
                    event.message,
                ),
                context: format!("Score: {:?}", event.score),
                adr_link: None,
                trade_offs: vec![],
            }),
            format!("Gate {}: {}", event.gate_name, if event.passed { "passed" } else { "failed" }),
            0.6,
            Importance::Normal,
            vec!["drift_bridge".to_string(), "gate_evaluated".to_string()],
            vec![],
        ));
    }

    fn on_detector_alert(&self, event: &DetectorAlertEvent) {
        if !self.is_event_allowed("on_detector_alert") { return; }
        self.handle_result("on_detector_alert", self.create_memory(
            "on_detector_alert",
            cortex_core::MemoryType::Tribal,
            TypedContent::Tribal(TribalContent {
                knowledge: format!(
                    "Detector '{}' has elevated false positive rate: {:.1}%",
                    event.detector_id,
                    event.false_positive_rate * 100.0,
                ),
                severity: if event.false_positive_rate > 0.2 { "high" } else { "medium" }.to_string(),
                warnings: vec![format!("FP rate: {:.1}%", event.false_positive_rate * 100.0)],
                consequences: vec!["Patterns from this detector may be unreliable".to_string()],
            }),
            format!("Detector alert: {} (FP: {:.1}%)", event.detector_id, event.false_positive_rate * 100.0),
            0.6,
            Importance::Normal,
            vec!["drift_bridge".to_string(), "detector_alert".to_string()],
            vec![],
        ));
    }

    fn on_detector_disabled(&self, event: &DetectorDisabledEvent) {
        if !self.is_event_allowed("on_detector_disabled") { return; }
        self.handle_result("on_detector_disabled", self.create_memory(
            "on_detector_disabled",
            cortex_core::MemoryType::CodeSmell,
            TypedContent::CodeSmell(CodeSmellContent {
                smell_name: format!("Auto-disabled detector: {}", event.detector_id),
                description: format!("Detector '{}' was auto-disabled: {}", event.detector_id, event.reason),
                bad_example: format!("Detector {} producing excessive false positives", event.detector_id),
                good_example: "Healthy detectors maintain <5% false positive rate".to_string(),
                severity: "high".to_string(),
            }),
            format!("Detector disabled: {}", event.detector_id),
            0.9,
            Importance::High,
            vec!["drift_bridge".to_string(), "detector_disabled".to_string()],
            vec![],
        ));
    }

    fn on_constraint_approved(&self, event: &ConstraintApprovedEvent) {
        if !self.is_event_allowed("on_constraint_approved") { return; }
        self.handle_result("on_constraint_approved", self.create_memory(
            "on_constraint_approved",
            cortex_core::MemoryType::ConstraintOverride,
            TypedContent::ConstraintOverride(ConstraintOverrideContent {
                constraint_name: event.constraint_id.clone(),
                override_reason: "Constraint approved by team".to_string(),
                approved_by: String::new(),
                scope: "global".to_string(),
                expiry: None,
            }),
            format!("Constraint approved: {}", event.constraint_id),
            0.8,
            Importance::High,
            vec!["drift_bridge".to_string(), "constraint_approved".to_string()],
            vec![],
        ));
    }

    fn on_constraint_violated(&self, event: &ConstraintViolatedEvent) {
        if !self.is_event_allowed("on_constraint_violated") { return; }
        self.handle_result("on_constraint_violated", self.create_memory(
            "on_constraint_violated",
            cortex_core::MemoryType::Feedback,
            TypedContent::Feedback(FeedbackContent {
                feedback: format!("Constraint '{}' violated: {}", event.constraint_id, event.message),
                category: "constraint_violated".to_string(),
                source: "drift_bridge".to_string(),
            }),
            format!("Constraint violated: {}", event.constraint_id),
            0.7,
            Importance::Normal,
            vec!["drift_bridge".to_string(), "constraint_violated".to_string()],
            vec![],
        ));
    }

    fn on_decision_mined(&self, event: &DecisionMinedEvent) {
        if !self.is_event_allowed("on_decision_mined") { return; }
        self.handle_result("on_decision_mined", self.create_memory(
            "on_decision_mined",
            cortex_core::MemoryType::DecisionContext,
            TypedContent::DecisionContext(DecisionContextContent {
                decision: format!("Mined decision: {} (category: {})", event.decision_id, event.category),
                context: "Automatically mined from codebase history".to_string(),
                adr_link: None,
                trade_offs: vec![],
            }),
            format!("Decision mined: {} ({})", event.decision_id, event.category),
            0.7,
            Importance::Normal,
            vec!["drift_bridge".to_string(), "decision_mined".to_string()],
            vec![],
        ));
    }

    fn on_decision_reversed(&self, event: &DecisionReversedEvent) {
        if !self.is_event_allowed("on_decision_reversed") { return; }
        self.handle_result("on_decision_reversed", self.create_memory(
            "on_decision_reversed",
            cortex_core::MemoryType::DecisionContext,
            TypedContent::DecisionContext(DecisionContextContent {
                decision: format!("Decision '{}' reversed: {}", event.decision_id, event.reason),
                context: "Previous decision was reversed".to_string(),
                adr_link: None,
                trade_offs: vec![format!("Reason: {}", event.reason)],
            }),
            format!("Decision reversed: {}", event.decision_id),
            0.8,
            Importance::High,
            vec!["drift_bridge".to_string(), "decision_reversed".to_string()],
            vec![],
        ));
    }

    fn on_adr_detected(&self, event: &AdrDetectedEvent) {
        if !self.is_event_allowed("on_adr_detected") { return; }
        self.handle_result("on_adr_detected", self.create_memory(
            "on_adr_detected",
            cortex_core::MemoryType::DecisionContext,
            TypedContent::DecisionContext(DecisionContextContent {
                decision: format!("ADR detected: {}", event.title),
                context: format!("Architecture Decision Record found: {}", event.adr_id),
                adr_link: Some(event.adr_id.clone()),
                trade_offs: vec![],
            }),
            format!("ADR: {}", event.title),
            0.9,
            Importance::High,
            vec!["drift_bridge".to_string(), "adr_detected".to_string()],
            vec![],
        ));
    }

    fn on_boundary_discovered(&self, event: &BoundaryDiscoveredEvent) {
        if !self.is_event_allowed("on_boundary_discovered") { return; }
        self.handle_result("on_boundary_discovered", self.create_memory(
            "on_boundary_discovered",
            cortex_core::MemoryType::Tribal,
            TypedContent::Tribal(TribalContent {
                knowledge: format!(
                    "Data boundary discovered: model '{}' via ORM '{}'",
                    event.model, event.orm,
                ),
                severity: "info".to_string(),
                warnings: vec![],
                consequences: vec!["Boundary affects data flow analysis".to_string()],
            }),
            format!("Boundary: {} ({})", event.model, event.orm),
            0.6,
            Importance::Normal,
            vec!["drift_bridge".to_string(), "boundary_discovered".to_string()],
            vec![],
        ));
    }

    fn on_enforcement_changed(&self, event: &EnforcementChangedEvent) {
        if !self.is_event_allowed("on_enforcement_changed") { return; }
        self.handle_result("on_enforcement_changed", self.create_memory(
            "on_enforcement_changed",
            cortex_core::MemoryType::DecisionContext,
            TypedContent::DecisionContext(DecisionContextContent {
                decision: format!(
                    "Enforcement changed for '{}': {} → {}",
                    event.gate_name, event.old_level, event.new_level,
                ),
                context: "Enforcement mode transition".to_string(),
                adr_link: None,
                trade_offs: vec![
                    format!("Old: {}", event.old_level),
                    format!("New: {}", event.new_level),
                ],
            }),
            format!("Enforcement changed: {} → {}", event.old_level, event.new_level),
            0.8,
            Importance::High,
            vec!["drift_bridge".to_string(), "enforcement_changed".to_string()],
            vec![],
        ));
    }

    fn on_feedback_abuse_detected(&self, event: &FeedbackAbuseDetectedEvent) {
        if !self.is_event_allowed("on_feedback_abuse_detected") { return; }
        self.handle_result("on_feedback_abuse_detected", self.create_memory(
            "on_feedback_abuse_detected",
            cortex_core::MemoryType::Tribal,
            TypedContent::Tribal(TribalContent {
                knowledge: format!(
                    "Feedback abuse detected: user '{}' pattern '{}'",
                    event.user_id, event.pattern,
                ),
                severity: "high".to_string(),
                warnings: vec!["Potential gaming of feedback system".to_string()],
                consequences: vec!["Feedback from this user may be unreliable".to_string()],
            }),
            format!("Feedback abuse: {} ({})", event.user_id, event.pattern),
            0.7,
            Importance::High,
            vec!["drift_bridge".to_string(), "feedback_abuse".to_string()],
            vec![],
        ));
    }

    fn on_error(&self, _event: &ErrorEvent) {
        // Errors are logged, not memorized.
    }
}
