//! Memory type + confidence mappings for all 21 Drift events.

use cortex_core::memory::types::MemoryType;
use cortex_core::memory::Importance;

/// Configuration for how a Drift event maps to a Cortex memory.
#[derive(Debug, Clone)]
pub struct EventMapping {
    /// The Drift event type name.
    pub event_type: &'static str,
    /// The target Cortex memory type (None = no memory created).
    pub memory_type: Option<MemoryType>,
    /// Initial confidence for the created memory.
    pub initial_confidence: f64,
    /// Importance level for the created memory.
    pub importance: Importance,
    /// Whether this event triggers grounding instead of memory creation.
    pub triggers_grounding: bool,
    /// Description for logging/debugging.
    pub description: &'static str,
}

/// Result of processing a Drift event through the bridge.
#[derive(Debug, Clone)]
pub struct EventProcessingResult {
    /// The event that was processed.
    pub event_type: String,
    /// Whether a memory was created.
    pub memory_created: bool,
    /// The created memory ID (if any).
    pub memory_id: Option<String>,
    /// The memory type (if created).
    pub memory_type: Option<MemoryType>,
    /// Any links created.
    pub links_created: Vec<String>,
    /// Processing duration in microseconds.
    pub duration_us: u64,
    /// Error (if processing failed but was non-fatal).
    pub error: Option<String>,
}

/// Complete mapping table for all 21 Drift events.
/// Confidence values are exact per spec.
pub const EVENT_MAPPINGS: &[EventMapping] = &[
    // 1. on_pattern_approved → PatternRationale, 0.8
    EventMapping {
        event_type: "on_pattern_approved",
        memory_type: Some(MemoryType::PatternRationale),
        initial_confidence: 0.8,
        importance: Importance::High,
        triggers_grounding: false,
        description: "Pattern approved → why it exists",
    },
    // 2. on_pattern_discovered → Insight, 0.5
    EventMapping {
        event_type: "on_pattern_discovered",
        memory_type: Some(MemoryType::Insight),
        initial_confidence: 0.5,
        importance: Importance::Normal,
        triggers_grounding: false,
        description: "New pattern found (low confidence until approved)",
    },
    // 3. on_pattern_ignored → Feedback, 0.6
    EventMapping {
        event_type: "on_pattern_ignored",
        memory_type: Some(MemoryType::Feedback),
        initial_confidence: 0.6,
        importance: Importance::Normal,
        triggers_grounding: false,
        description: "Pattern explicitly ignored (learning signal)",
    },
    // 4. on_pattern_merged → DecisionContext, 0.7
    EventMapping {
        event_type: "on_pattern_merged",
        memory_type: Some(MemoryType::DecisionContext),
        initial_confidence: 0.7,
        importance: Importance::Normal,
        triggers_grounding: false,
        description: "Two patterns merged (architectural decision)",
    },
    // 5. on_scan_complete → triggers grounding, no memory
    EventMapping {
        event_type: "on_scan_complete",
        memory_type: None,
        initial_confidence: 0.0,
        importance: Importance::Normal,
        triggers_grounding: true,
        description: "Scan complete — triggers grounding loop",
    },
    // 6. on_regression_detected → DecisionContext, 0.9
    EventMapping {
        event_type: "on_regression_detected",
        memory_type: Some(MemoryType::DecisionContext),
        initial_confidence: 0.9,
        importance: Importance::Critical,
        triggers_grounding: false,
        description: "Regression → review memory with high confidence",
    },
    // 7. on_violation_detected → no memory (too noisy)
    EventMapping {
        event_type: "on_violation_detected",
        memory_type: None,
        initial_confidence: 0.0,
        importance: Importance::Normal,
        triggers_grounding: false,
        description: "Too noisy; only dismissals/fixes create memories",
    },
    // 8. on_violation_dismissed → ConstraintOverride, 0.7
    EventMapping {
        event_type: "on_violation_dismissed",
        memory_type: Some(MemoryType::ConstraintOverride),
        initial_confidence: 0.7,
        importance: Importance::Normal,
        triggers_grounding: false,
        description: "Dismissal reason → override memory",
    },
    // 9. on_violation_fixed → Feedback, 0.8
    EventMapping {
        event_type: "on_violation_fixed",
        memory_type: Some(MemoryType::Feedback),
        initial_confidence: 0.8,
        importance: Importance::Normal,
        triggers_grounding: false,
        description: "Fix confirms pattern validity (positive signal)",
    },
    // 10. on_gate_evaluated → DecisionContext, 0.6
    EventMapping {
        event_type: "on_gate_evaluated",
        memory_type: Some(MemoryType::DecisionContext),
        initial_confidence: 0.6,
        importance: Importance::Normal,
        triggers_grounding: false,
        description: "Gate pass/fail → enforcement decision record",
    },
    // 11. on_detector_alert → Tribal, 0.6
    EventMapping {
        event_type: "on_detector_alert",
        memory_type: Some(MemoryType::Tribal),
        initial_confidence: 0.6,
        importance: Importance::Normal,
        triggers_grounding: false,
        description: "Detector health warning (institutional knowledge)",
    },
    // 12. on_detector_disabled → CodeSmell, 0.9
    EventMapping {
        event_type: "on_detector_disabled",
        memory_type: Some(MemoryType::CodeSmell),
        initial_confidence: 0.9,
        importance: Importance::High,
        triggers_grounding: false,
        description: "Auto-disabled detector → anti-pattern signal",
    },
    // 13. on_constraint_approved → ConstraintOverride, 0.8
    EventMapping {
        event_type: "on_constraint_approved",
        memory_type: Some(MemoryType::ConstraintOverride),
        initial_confidence: 0.8,
        importance: Importance::High,
        triggers_grounding: false,
        description: "Constraint approved → enforcement memory",
    },
    // 14. on_constraint_violated → Feedback, 0.7
    EventMapping {
        event_type: "on_constraint_violated",
        memory_type: Some(MemoryType::Feedback),
        initial_confidence: 0.7,
        importance: Importance::Normal,
        triggers_grounding: false,
        description: "Constraint violation → review signal",
    },
    // 15. on_decision_mined → DecisionContext, 0.7
    EventMapping {
        event_type: "on_decision_mined",
        memory_type: Some(MemoryType::DecisionContext),
        initial_confidence: 0.7,
        importance: Importance::Normal,
        triggers_grounding: false,
        description: "Mined decision → ADR memory",
    },
    // 16. on_decision_reversed → DecisionContext, 0.8
    EventMapping {
        event_type: "on_decision_reversed",
        memory_type: Some(MemoryType::DecisionContext),
        initial_confidence: 0.8,
        importance: Importance::High,
        triggers_grounding: false,
        description: "Decision reversal → linked to original",
    },
    // 17. on_adr_detected → DecisionContext, 0.9
    EventMapping {
        event_type: "on_adr_detected",
        memory_type: Some(MemoryType::DecisionContext),
        initial_confidence: 0.9,
        importance: Importance::High,
        triggers_grounding: false,
        description: "Detected ADR document → high confidence",
    },
    // 18. on_boundary_discovered → Tribal, 0.6
    EventMapping {
        event_type: "on_boundary_discovered",
        memory_type: Some(MemoryType::Tribal),
        initial_confidence: 0.6,
        importance: Importance::Normal,
        triggers_grounding: false,
        description: "Data boundary → institutional knowledge",
    },
    // 19. on_enforcement_changed → DecisionContext, 0.8
    EventMapping {
        event_type: "on_enforcement_changed",
        memory_type: Some(MemoryType::DecisionContext),
        initial_confidence: 0.8,
        importance: Importance::High,
        triggers_grounding: false,
        description: "Enforcement mode transition",
    },
    // 20. on_feedback_abuse_detected → Tribal, 0.7
    EventMapping {
        event_type: "on_feedback_abuse_detected",
        memory_type: Some(MemoryType::Tribal),
        initial_confidence: 0.7,
        importance: Importance::High,
        triggers_grounding: false,
        description: "Abuse pattern → team knowledge",
    },
    // 21. on_error → no memory (logged only)
    EventMapping {
        event_type: "on_error",
        memory_type: None,
        initial_confidence: 0.0,
        importance: Importance::Normal,
        triggers_grounding: false,
        description: "Errors are logged, not memorized",
    },
];

/// Look up the mapping for a given event type.
pub fn get_mapping(event_type: &str) -> Option<&'static EventMapping> {
    EVENT_MAPPINGS.iter().find(|m| m.event_type == event_type)
}

/// Get all event types that create memories (excludes no-memory and grounding-trigger events).
pub fn memory_creating_events() -> Vec<&'static EventMapping> {
    EVENT_MAPPINGS
        .iter()
        .filter(|m| m.memory_type.is_some())
        .collect()
}

/// Get the 5 Community-tier event types.
pub fn community_events() -> Vec<&'static str> {
    vec![
        "on_pattern_approved",
        "on_pattern_discovered",
        "on_violation_dismissed",
        "on_violation_fixed",
        "on_detector_disabled",
    ]
}
