//! Enhanced 7-signal confidence model for wrapper detection.

use super::types::Wrapper;

/// Compute wrapper confidence from 7 signals.
///
/// 1. Import match: does the file import the framework?
/// 2. Name match: does the wrapper name suggest wrapping (use*, with*, create*)?
/// 3. Call-site match: does the body call the primitive?
/// 4. Export status: is the wrapper exported?
/// 5. Usage count: how many call sites use this wrapper?
/// 6. Depth analysis: is it a thin wrapper (1 level) or deep?
/// 7. Framework specificity: how specific is the framework match?
pub fn compute_confidence(wrapper: &Wrapper, file_content: &str) -> f64 {
    let mut score = 0.0;

    // Signal 1: Import match (0.20)
    let has_import = file_content.contains(&format!("from '{}'", wrapper.framework))
        || file_content.contains(&format!("from \"{}\"", wrapper.framework))
        || file_content.contains(&format!("require('{}')", wrapper.framework))
        || file_content.contains(&format!("import {}", wrapper.framework));
    if has_import {
        score += 0.20;
    }

    // Signal 2: Name match (0.15)
    let name_lower = wrapper.name.to_lowercase();
    if name_lower.starts_with("use") || name_lower.starts_with("with")
        || name_lower.starts_with("create") || name_lower.starts_with("make")
        || name_lower.starts_with("get") || name_lower.starts_with("build")
    {
        score += 0.15;
    }

    // Signal 3: Call-site match (0.25) — always true if we detected it
    if !wrapper.wrapped_primitives.is_empty() {
        score += 0.25;
    }

    // Signal 4: Export status (0.10)
    if wrapper.is_exported {
        score += 0.10;
    }

    // Signal 5: Usage count (0.10)
    if wrapper.usage_count > 0 {
        let usage_score = (wrapper.usage_count as f64 / 10.0).min(1.0) * 0.10;
        score += usage_score;
    }

    // Signal 6: Depth analysis (0.10) — thin wrappers score higher
    if !wrapper.is_multi_primitive {
        score += 0.10; // Single primitive = thin wrapper
    } else {
        score += 0.05; // Multi-primitive = composite, still valid
    }

    // Signal 7: Framework specificity (0.10)
    if wrapper.framework != "builtin" && wrapper.framework != "other" {
        score += 0.10;
    }

    score.clamp(0.0, 1.0)
}
