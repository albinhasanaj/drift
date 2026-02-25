//! Config validation: reject invalid combinations at startup.

use super::bridge_config::BridgeConfig;

/// Validation error for bridge configuration.
#[derive(Debug, Clone)]
pub struct ConfigValidationError {
    /// Which field(s) are invalid.
    pub field: String,
    /// Description of the problem.
    pub message: String,
}

impl std::fmt::Display for ConfigValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "config.{}: {}", self.field, self.message)
    }
}

/// Validate a BridgeConfig, returning all errors found.
pub fn validate(config: &BridgeConfig) -> Vec<ConfigValidationError> {
    let mut errors = Vec::new();

    // Grounding config validation
    let g = &config.grounding;

    if g.max_memories_per_loop == 0 {
        errors.push(ConfigValidationError {
            field: "grounding.max_memories_per_loop".to_string(),
            message: "must be > 0".to_string(),
        });
    }

    if g.boost_delta < 0.0 || g.boost_delta > 1.0 {
        errors.push(ConfigValidationError {
            field: "grounding.boost_delta".to_string(),
            message: format!("must be in [0.0, 1.0], got {}", g.boost_delta),
        });
    }

    if g.partial_penalty < 0.0 || g.partial_penalty > 1.0 {
        errors.push(ConfigValidationError {
            field: "grounding.partial_penalty".to_string(),
            message: format!("must be in [0.0, 1.0], got {}", g.partial_penalty),
        });
    }

    if g.weak_penalty < 0.0 || g.weak_penalty > 1.0 {
        errors.push(ConfigValidationError {
            field: "grounding.weak_penalty".to_string(),
            message: format!("must be in [0.0, 1.0], got {}", g.weak_penalty),
        });
    }

    if g.invalidated_floor < 0.0 || g.invalidated_floor > 1.0 {
        errors.push(ConfigValidationError {
            field: "grounding.invalidated_floor".to_string(),
            message: format!("must be in [0.0, 1.0], got {}", g.invalidated_floor),
        });
    }

    if g.contradiction_drop < 0.0 || g.contradiction_drop > 1.0 {
        errors.push(ConfigValidationError {
            field: "grounding.contradiction_drop".to_string(),
            message: format!("must be in [0.0, 1.0], got {}", g.contradiction_drop),
        });
    }

    if g.full_grounding_interval == 0 {
        errors.push(ConfigValidationError {
            field: "grounding.full_grounding_interval".to_string(),
            message: "must be > 0".to_string(),
        });
    }

    // NaN checks
    if g.boost_delta.is_nan() {
        errors.push(ConfigValidationError {
            field: "grounding.boost_delta".to_string(),
            message: "must not be NaN".to_string(),
        });
    }

    if g.invalidated_floor.is_nan() {
        errors.push(ConfigValidationError {
            field: "grounding.invalidated_floor".to_string(),
            message: "must not be NaN".to_string(),
        });
    }

    errors
}

/// Validate and return Ok(()) or Err with all validation errors combined.
pub fn validate_or_error(config: &BridgeConfig) -> Result<(), crate::errors::BridgeError> {
    let errors = validate(config);
    if errors.is_empty() {
        Ok(())
    } else {
        let messages: Vec<String> = errors.iter().map(|e| e.to_string()).collect();
        Err(crate::errors::BridgeError::Config(
            format!("Invalid bridge configuration: {}", messages.join("; ")),
        ))
    }
}
