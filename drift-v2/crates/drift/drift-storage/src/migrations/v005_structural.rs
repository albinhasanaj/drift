//! V005 migration: Phase 5 tables for structural intelligence systems.
//!
//! Tables: coupling_metrics, constraints, contracts, constants, secrets,
//!         wrappers, dna_genes, crypto_findings, owasp_findings,
//!         decomposition_decisions.

pub const MIGRATION_SQL: &str = r#"
-- Coupling metrics (Martin metrics per module)
CREATE TABLE IF NOT EXISTS coupling_metrics (
    module TEXT PRIMARY KEY,
    ce INTEGER NOT NULL,
    ca INTEGER NOT NULL,
    instability REAL NOT NULL,
    abstractness REAL NOT NULL,
    distance REAL NOT NULL,
    zone TEXT NOT NULL,
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX IF NOT EXISTS idx_coupling_metrics_zone ON coupling_metrics(zone);

-- Coupling cycles (detected SCCs)
CREATE TABLE IF NOT EXISTS coupling_cycles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    members TEXT NOT NULL,
    break_suggestions TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

-- Constraints (architectural invariants)
CREATE TABLE IF NOT EXISTS constraints (
    id TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    invariant_type TEXT NOT NULL,
    target TEXT NOT NULL,
    scope TEXT,
    source TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX IF NOT EXISTS idx_constraints_type ON constraints(invariant_type);
CREATE INDEX IF NOT EXISTS idx_constraints_source ON constraints(source);

-- Constraint verification results
CREATE TABLE IF NOT EXISTS constraint_verifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    constraint_id TEXT NOT NULL REFERENCES constraints(id),
    passed INTEGER NOT NULL,
    violations TEXT NOT NULL,
    verified_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX IF NOT EXISTS idx_constraint_verifications_cid ON constraint_verifications(constraint_id);

-- Contracts (API endpoints)
CREATE TABLE IF NOT EXISTS contracts (
    id TEXT PRIMARY KEY,
    paradigm TEXT NOT NULL,
    source_file TEXT NOT NULL,
    framework TEXT NOT NULL,
    confidence REAL NOT NULL,
    endpoints TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX IF NOT EXISTS idx_contracts_paradigm ON contracts(paradigm);
CREATE INDEX IF NOT EXISTS idx_contracts_framework ON contracts(framework);
CREATE INDEX IF NOT EXISTS idx_contracts_source ON contracts(source_file);

-- Contract mismatches (BE↔FE)
CREATE TABLE IF NOT EXISTS contract_mismatches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    backend_endpoint TEXT NOT NULL,
    frontend_call TEXT NOT NULL,
    mismatch_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX IF NOT EXISTS idx_contract_mismatches_type ON contract_mismatches(mismatch_type);

-- Constants (named constants, magic numbers)
CREATE TABLE IF NOT EXISTS constants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    is_used INTEGER NOT NULL DEFAULT 1,
    language TEXT NOT NULL,
    is_named INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX IF NOT EXISTS idx_constants_file ON constants(file);
CREATE INDEX IF NOT EXISTS idx_constants_used ON constants(is_used);

-- Secrets (hardcoded credentials)
CREATE TABLE IF NOT EXISTS secrets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern_name TEXT NOT NULL,
    redacted_value TEXT NOT NULL,
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    severity TEXT NOT NULL,
    entropy REAL NOT NULL,
    confidence REAL NOT NULL,
    cwe_ids TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX IF NOT EXISTS idx_secrets_file ON secrets(file);
CREATE INDEX IF NOT EXISTS idx_secrets_severity ON secrets(severity);
CREATE INDEX IF NOT EXISTS idx_secrets_pattern ON secrets(pattern_name);

-- Environment variables
CREATE TABLE IF NOT EXISTS env_variables (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    access_method TEXT NOT NULL,
    has_default INTEGER NOT NULL DEFAULT 0,
    defined_in_env INTEGER NOT NULL DEFAULT 0,
    framework_prefix TEXT,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX IF NOT EXISTS idx_env_variables_name ON env_variables(name);
CREATE INDEX IF NOT EXISTS idx_env_variables_file ON env_variables(file);

-- Wrappers (detected wrapper functions)
CREATE TABLE IF NOT EXISTS wrappers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    category TEXT NOT NULL,
    wrapped_primitives TEXT NOT NULL,
    framework TEXT NOT NULL,
    confidence REAL NOT NULL,
    is_multi_primitive INTEGER NOT NULL DEFAULT 0,
    is_exported INTEGER NOT NULL DEFAULT 0,
    usage_count INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX IF NOT EXISTS idx_wrappers_file ON wrappers(file);
CREATE INDEX IF NOT EXISTS idx_wrappers_category ON wrappers(category);
CREATE INDEX IF NOT EXISTS idx_wrappers_framework ON wrappers(framework);

-- DNA genes (convention genes with alleles)
CREATE TABLE IF NOT EXISTS dna_genes (
    gene_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    dominant_allele TEXT,
    alleles TEXT NOT NULL,
    confidence REAL NOT NULL,
    consistency REAL NOT NULL,
    exemplars TEXT NOT NULL,
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

-- DNA mutations (deviations from dominant allele)
CREATE TABLE IF NOT EXISTS dna_mutations (
    id TEXT PRIMARY KEY,
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    gene_id TEXT NOT NULL,
    expected TEXT NOT NULL,
    actual TEXT NOT NULL,
    impact TEXT NOT NULL,
    code TEXT NOT NULL,
    suggestion TEXT NOT NULL,
    detected_at INTEGER NOT NULL,
    resolved INTEGER NOT NULL DEFAULT 0,
    resolved_at INTEGER
) STRICT;

CREATE INDEX IF NOT EXISTS idx_dna_mutations_file ON dna_mutations(file);
CREATE INDEX IF NOT EXISTS idx_dna_mutations_gene ON dna_mutations(gene_id);
CREATE INDEX IF NOT EXISTS idx_dna_mutations_impact ON dna_mutations(impact);
CREATE INDEX IF NOT EXISTS idx_dna_mutations_resolved ON dna_mutations(resolved);

-- Crypto findings (cryptographic failures)
CREATE TABLE IF NOT EXISTS crypto_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    category TEXT NOT NULL,
    description TEXT NOT NULL,
    code TEXT NOT NULL,
    confidence REAL NOT NULL,
    cwe_id INTEGER NOT NULL,
    owasp TEXT NOT NULL,
    remediation TEXT NOT NULL,
    language TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX IF NOT EXISTS idx_crypto_findings_file ON crypto_findings(file);
CREATE INDEX IF NOT EXISTS idx_crypto_findings_category ON crypto_findings(category);
CREATE INDEX IF NOT EXISTS idx_crypto_findings_cwe ON crypto_findings(cwe_id);

-- OWASP findings (enriched security findings)
CREATE TABLE IF NOT EXISTS owasp_findings (
    id TEXT PRIMARY KEY,
    detector TEXT NOT NULL,
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    description TEXT NOT NULL,
    severity REAL NOT NULL,
    cwes TEXT NOT NULL,
    owasp_categories TEXT NOT NULL,
    confidence REAL NOT NULL,
    remediation TEXT,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX IF NOT EXISTS idx_owasp_findings_file ON owasp_findings(file);
CREATE INDEX IF NOT EXISTS idx_owasp_findings_detector ON owasp_findings(detector);
CREATE INDEX IF NOT EXISTS idx_owasp_findings_severity ON owasp_findings(severity);

-- Decomposition decisions (boundary adjustments)
CREATE TABLE IF NOT EXISTS decomposition_decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dna_profile_hash TEXT NOT NULL,
    adjustment TEXT NOT NULL,
    confidence REAL NOT NULL,
    dna_similarity REAL NOT NULL,
    narrative TEXT NOT NULL,
    source_dna_hash TEXT NOT NULL,
    applied_weight REAL NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX IF NOT EXISTS idx_decomp_decisions_hash ON decomposition_decisions(dna_profile_hash);
CREATE INDEX IF NOT EXISTS idx_decomp_decisions_source ON decomposition_decisions(source_dna_hash);
"#;
