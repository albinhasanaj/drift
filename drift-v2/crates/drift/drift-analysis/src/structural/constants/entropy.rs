//! Shannon entropy scoring for high-entropy string detection.
//!
//! Shannon entropy measures the randomness/information density of a string.
//! High-entropy strings (>3.5 bits/char) are likely secrets or random tokens.
//! Low-entropy strings (<2.0 bits/char) are likely natural language or repetitive.

use std::collections::HashMap;

/// Compute Shannon entropy of a string in bits per character.
///
/// H = -Σ p(x) * log2(p(x)) for each unique character x.
///
/// Returns 0.0 for empty strings.
/// Typical ranges:
/// - English text: ~3.5-4.5
/// - Random hex: ~3.7-4.0
/// - Random base64: ~5.0-6.0
/// - Repeated chars: ~0.0-1.0
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let len = s.len() as f64;
    let mut freq: HashMap<u8, usize> = HashMap::new();

    for &byte in s.as_bytes() {
        *freq.entry(byte).or_default() += 1;
    }

    let entropy: f64 = freq
        .values()
        .map(|&count| {
            let p = count as f64 / len;
            if p > 0.0 {
                -p * p.log2()
            } else {
                0.0
            }
        })
        .sum();

    entropy
}

/// Classify entropy level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropyLevel {
    /// < 2.0 bits/char — likely repetitive or simple.
    Low,
    /// 2.0 - 3.5 bits/char — moderate, could be natural language.
    Medium,
    /// 3.5 - 5.0 bits/char — high, likely a token or key.
    High,
    /// > 5.0 bits/char — very high, almost certainly random/encrypted.
    VeryHigh,
}

impl EntropyLevel {
    pub fn from_entropy(entropy: f64) -> Self {
        if entropy < 2.0 {
            Self::Low
        } else if entropy < 3.5 {
            Self::Medium
        } else if entropy < 5.0 {
            Self::High
        } else {
            Self::VeryHigh
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_string() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn test_single_char() {
        assert_eq!(shannon_entropy("a"), 0.0);
    }

    #[test]
    fn test_repeated_chars() {
        let entropy = shannon_entropy("aaaaaaaaaa");
        assert!(entropy < 0.01, "Repeated chars should have near-zero entropy, got {}", entropy);
    }

    #[test]
    fn test_high_entropy() {
        let entropy = shannon_entropy("aK3$mP9!xQ2@bL7#");
        assert!(entropy > 3.5, "Random-looking string should have high entropy, got {}", entropy);
    }

    #[test]
    fn test_low_entropy() {
        let entropy = shannon_entropy("aaaaaaaaaa");
        let high = shannon_entropy("aK3$mP9!xQ2@");
        assert!(high > entropy, "High-entropy string should score higher than low-entropy");
    }
}
