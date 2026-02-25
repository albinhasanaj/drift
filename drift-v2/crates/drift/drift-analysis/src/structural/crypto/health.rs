//! Crypto health score calculator.

use super::types::{CryptoFinding, CryptoCategory, CryptoHealthScore};
use rustc_hash::FxHashMap;

/// Calculate crypto health score from findings.
///
/// Score = 100 - weighted_penalty
/// Weights: critical(severity 9-10)=15, high(7-8)=8, medium(5-6)=3
/// Capped at 0.
pub fn calculate_crypto_health(findings: &[CryptoFinding]) -> CryptoHealthScore {
    if findings.is_empty() {
        return CryptoHealthScore {
            overall: 100.0,
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            by_category: Vec::new(),
        };
    }

    let mut critical_count = 0u32;
    let mut high_count = 0u32;
    let mut medium_count = 0u32;
    let mut penalty = 0.0;
    let mut by_category: FxHashMap<CryptoCategory, u32> = FxHashMap::default();

    for finding in findings {
        *by_category.entry(finding.category).or_insert(0) += 1;

        let severity = finding.category.severity();
        match severity as u32 {
            9..=10 => {
                critical_count += 1;
                penalty += 15.0 * finding.confidence;
            }
            7..=8 => {
                high_count += 1;
                penalty += 8.0 * finding.confidence;
            }
            _ => {
                medium_count += 1;
                penalty += 3.0 * finding.confidence;
            }
        }
    }

    let overall = (100.0 - penalty).clamp(0.0, 100.0);

    let mut by_category_vec: Vec<(CryptoCategory, u32)> = by_category.into_iter().collect();
    by_category_vec.sort_by(|a, b| b.1.cmp(&a.1));

    CryptoHealthScore {
        overall,
        critical_count,
        high_count,
        medium_count,
        by_category: by_category_vec,
    }
}
