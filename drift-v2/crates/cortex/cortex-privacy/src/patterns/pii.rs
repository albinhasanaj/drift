use regex::Regex;
use std::sync::LazyLock;

/// A compiled PII detection pattern.
pub struct PiiPattern {
    pub name: &'static str,
    pub regex: &'static LazyLock<Option<Regex>>,
    pub placeholder: &'static str,
    pub base_confidence: f64,
}

macro_rules! pii_pattern {
    ($name:ident, $regex_str:expr) => {
        pub static $name: LazyLock<Option<Regex>> = LazyLock::new(|| Regex::new($regex_str).ok());
    };
}

// ── Email ──────────────────────────────────────────────────────────────────
pii_pattern!(
    RE_EMAIL,
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
);

// ── Phone numbers (international + US formats) ────────────────────────────
pii_pattern!(
    RE_PHONE,
    r"(?:^|\s)(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?:\s|$)"
);

// ── SSN ────────────────────────────────────────────────────────────────────
pii_pattern!(RE_SSN, r"\b\d{3}-\d{2}-\d{4}\b");

// ── Credit card (Visa, MC, Amex, Discover) ─────────────────────────────────
pii_pattern!(
    RE_CREDIT_CARD,
    r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{3,4}\b"
);

// ── IPv4 ───────────────────────────────────────────────────────────────────
pii_pattern!(
    RE_IPV4,
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
);

// ── IPv6 (simplified) ─────────────────────────────────────────────────────
pii_pattern!(RE_IPV6, r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b");

// ── US Passport ────────────────────────────────────────────────────────────
pii_pattern!(RE_PASSPORT, r"\b[A-Z]\d{8}\b");

// ── US Driver's License (generic pattern) ──────────────────────────────────
pii_pattern!(RE_DRIVERS_LICENSE, r"\b[A-Z]\d{7,14}\b");

// ── Date of Birth (common formats) ────────────────────────────────────────
pii_pattern!(
    RE_DOB,
    r"\b(?:0[1-9]|1[0-2])[/\-](?:0[1-9]|[12]\d|3[01])[/\-](?:19|20)\d{2}\b"
);

// ── Physical address (US-style street address) ────────────────────────────
pii_pattern!(
    RE_ADDRESS,
    r"\b\d{1,5}\s+(?:[A-Z][a-z]+\s?){1,4}(?:St|Street|Ave|Avenue|Blvd|Boulevard|Dr|Drive|Ln|Lane|Rd|Road|Ct|Court|Pl|Place|Way)\b"
);

// ── National ID (generic numeric, 8-12 digits) ────────────────────────────
pii_pattern!(RE_NATIONAL_ID, r"\b\d{8,12}\b");

// ── IBAN ───────────────────────────────────────────────────────────────────
pii_pattern!(
    RE_IBAN,
    r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?\d{0,16})\b"
);

// ── MAC Address ────────────────────────────────────────────────────────────
pii_pattern!(
    RE_MAC_ADDRESS,
    r"\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b"
);

// ── VIN (Vehicle Identification Number) ────────────────────────────────────
pii_pattern!(RE_VIN, r"\b[A-HJ-NPR-Z0-9]{17}\b");

// ── Medicare/Health ID ─────────────────────────────────────────────────────
pii_pattern!(RE_MEDICARE, r"\b\d{3}-\d{3}-\d{3}\b");

/// All PII patterns in detection order (most specific first to reduce false positives).
pub fn all_patterns() -> Vec<PiiPattern> {
    vec![
        PiiPattern {
            name: "email",
            regex: &RE_EMAIL,
            placeholder: "[EMAIL]",
            base_confidence: 0.95,
        },
        PiiPattern {
            name: "ssn",
            regex: &RE_SSN,
            placeholder: "[SSN]",
            base_confidence: 0.95,
        },
        PiiPattern {
            name: "credit_card",
            regex: &RE_CREDIT_CARD,
            placeholder: "[CREDIT_CARD]",
            base_confidence: 0.90,
        },
        PiiPattern {
            name: "iban",
            regex: &RE_IBAN,
            placeholder: "[IBAN]",
            base_confidence: 0.85,
        },
        PiiPattern {
            name: "mac_address",
            regex: &RE_MAC_ADDRESS,
            placeholder: "[MAC_ADDRESS]",
            base_confidence: 0.70,
        },
        PiiPattern {
            name: "ipv6",
            regex: &RE_IPV6,
            placeholder: "[IPV6]",
            base_confidence: 0.75,
        },
        PiiPattern {
            name: "ipv4",
            regex: &RE_IPV4,
            placeholder: "[IP_ADDRESS]",
            base_confidence: 0.70,
        },
        PiiPattern {
            name: "phone",
            regex: &RE_PHONE,
            placeholder: "[PHONE]",
            base_confidence: 0.80,
        },
        PiiPattern {
            name: "dob",
            regex: &RE_DOB,
            placeholder: "[DOB]",
            base_confidence: 0.75,
        },
        PiiPattern {
            name: "medicare",
            regex: &RE_MEDICARE,
            placeholder: "[HEALTH_ID]",
            base_confidence: 0.70,
        },
        PiiPattern {
            name: "passport",
            regex: &RE_PASSPORT,
            placeholder: "[PASSPORT]",
            base_confidence: 0.60,
        },
        PiiPattern {
            name: "drivers_license",
            regex: &RE_DRIVERS_LICENSE,
            placeholder: "[DRIVERS_LICENSE]",
            base_confidence: 0.50,
        },
        PiiPattern {
            name: "vin",
            regex: &RE_VIN,
            placeholder: "[VIN]",
            base_confidence: 0.50,
        },
        PiiPattern {
            name: "address",
            regex: &RE_ADDRESS,
            placeholder: "[ADDRESS]",
            base_confidence: 0.65,
        },
        PiiPattern {
            name: "national_id",
            regex: &RE_NATIONAL_ID,
            placeholder: "[NATIONAL_ID]",
            base_confidence: 0.30,
        },
    ]
}
