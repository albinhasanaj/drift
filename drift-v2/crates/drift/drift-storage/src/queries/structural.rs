//! Queries for all 9 structural intelligence systems (Phase 5).

use drift_core::errors::StorageError;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

use super::util::OptionalExt;

// ─── Coupling Metrics ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CouplingMetricsRow {
    pub module: String,
    pub ce: u32,
    pub ca: u32,
    pub instability: f64,
    pub abstractness: f64,
    pub distance: f64,
    pub zone: String,
}

pub fn upsert_coupling_metrics(conn: &Connection, row: &CouplingMetricsRow) -> Result<(), StorageError> {
    conn.execute(
        "INSERT OR REPLACE INTO coupling_metrics (module, ce, ca, instability, abstractness, distance, zone)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![row.module, row.ce, row.ca, row.instability, row.abstractness, row.distance, row.zone],
    )
    .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    Ok(())
}

pub fn get_coupling_metrics(conn: &Connection, module: &str) -> Result<Option<CouplingMetricsRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT module, ce, ca, instability, abstractness, distance, zone
             FROM coupling_metrics WHERE module = ?1",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let result = stmt
        .query_row(params![module], |row| {
            Ok(CouplingMetricsRow {
                module: row.get(0)?,
                ce: row.get::<_, u32>(1)?,
                ca: row.get::<_, u32>(2)?,
                instability: row.get(3)?,
                abstractness: row.get(4)?,
                distance: row.get(5)?,
                zone: row.get(6)?,
            })
        })
        .optional()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    Ok(result)
}

pub fn get_all_coupling_metrics(conn: &Connection) -> Result<Vec<CouplingMetricsRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT module, ce, ca, instability, abstractness, distance, zone
             FROM coupling_metrics ORDER BY distance DESC",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map([], |row| {
            Ok(CouplingMetricsRow {
                module: row.get(0)?,
                ce: row.get::<_, u32>(1)?,
                ca: row.get::<_, u32>(2)?,
                instability: row.get(3)?,
                abstractness: row.get(4)?,
                distance: row.get(5)?,
                zone: row.get(6)?,
            })
        })
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

pub fn get_coupling_metrics_by_zone(conn: &Connection, zone: &str) -> Result<Vec<CouplingMetricsRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT module, ce, ca, instability, abstractness, distance, zone
             FROM coupling_metrics WHERE zone = ?1",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map(params![zone], |row| {
            Ok(CouplingMetricsRow {
                module: row.get(0)?,
                ce: row.get::<_, u32>(1)?,
                ca: row.get::<_, u32>(2)?,
                instability: row.get(3)?,
                abstractness: row.get(4)?,
                distance: row.get(5)?,
                zone: row.get(6)?,
            })
        })
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

// ─── Constraints ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintRow {
    pub id: String,
    pub description: String,
    pub invariant_type: String,
    pub target: String,
    pub scope: Option<String>,
    pub source: String,
    pub enabled: bool,
}

pub fn upsert_constraint(conn: &Connection, row: &ConstraintRow) -> Result<(), StorageError> {
    conn.execute(
        "INSERT OR REPLACE INTO constraints (id, description, invariant_type, target, scope, source, enabled)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![row.id, row.description, row.invariant_type, row.target, row.scope, row.source, row.enabled as i32],
    )
    .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    Ok(())
}

pub fn get_constraint(conn: &Connection, id: &str) -> Result<Option<ConstraintRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, description, invariant_type, target, scope, source, enabled
             FROM constraints WHERE id = ?1",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let result = stmt
        .query_row(params![id], |row| {
            Ok(ConstraintRow {
                id: row.get(0)?,
                description: row.get(1)?,
                invariant_type: row.get(2)?,
                target: row.get(3)?,
                scope: row.get(4)?,
                source: row.get(5)?,
                enabled: row.get::<_, i32>(6)? != 0,
            })
        })
        .optional()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    Ok(result)
}

pub fn get_enabled_constraints(conn: &Connection) -> Result<Vec<ConstraintRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, description, invariant_type, target, scope, source, enabled
             FROM constraints WHERE enabled = 1",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map([], |row| {
            Ok(ConstraintRow {
                id: row.get(0)?,
                description: row.get(1)?,
                invariant_type: row.get(2)?,
                target: row.get(3)?,
                scope: row.get(4)?,
                source: row.get(5)?,
                enabled: row.get::<_, i32>(6)? != 0,
            })
        })
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

// ─── Contracts ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractRow {
    pub id: String,
    pub paradigm: String,
    pub source_file: String,
    pub framework: String,
    pub confidence: f64,
    pub endpoints: String, // JSON
}

pub fn upsert_contract(conn: &Connection, row: &ContractRow) -> Result<(), StorageError> {
    conn.execute(
        "INSERT OR REPLACE INTO contracts (id, paradigm, source_file, framework, confidence, endpoints)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![row.id, row.paradigm, row.source_file, row.framework, row.confidence, row.endpoints],
    )
    .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    Ok(())
}

pub fn get_contract(conn: &Connection, id: &str) -> Result<Option<ContractRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, paradigm, source_file, framework, confidence, endpoints
             FROM contracts WHERE id = ?1",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let result = stmt
        .query_row(params![id], |row| {
            Ok(ContractRow {
                id: row.get(0)?,
                paradigm: row.get(1)?,
                source_file: row.get(2)?,
                framework: row.get(3)?,
                confidence: row.get(4)?,
                endpoints: row.get(5)?,
            })
        })
        .optional()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    Ok(result)
}

pub fn get_contracts_by_paradigm(conn: &Connection, paradigm: &str) -> Result<Vec<ContractRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, paradigm, source_file, framework, confidence, endpoints
             FROM contracts WHERE paradigm = ?1",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map(params![paradigm], |row| {
            Ok(ContractRow {
                id: row.get(0)?,
                paradigm: row.get(1)?,
                source_file: row.get(2)?,
                framework: row.get(3)?,
                confidence: row.get(4)?,
                endpoints: row.get(5)?,
            })
        })
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

// ─── Secrets ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretRow {
    pub id: Option<i64>,
    pub pattern_name: String,
    pub redacted_value: String,
    pub file: String,
    pub line: u32,
    pub severity: String,
    pub entropy: f64,
    pub confidence: f64,
    pub cwe_ids: String, // JSON array
}

pub fn insert_secret(conn: &Connection, row: &SecretRow) -> Result<i64, StorageError> {
    conn.execute(
        "INSERT INTO secrets (pattern_name, redacted_value, file, line, severity, entropy, confidence, cwe_ids)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![row.pattern_name, row.redacted_value, row.file, row.line, row.severity, row.entropy, row.confidence, row.cwe_ids],
    )
    .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    Ok(conn.last_insert_rowid())
}

pub fn get_secrets_by_file(conn: &Connection, file: &str) -> Result<Vec<SecretRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, pattern_name, redacted_value, file, line, severity, entropy, confidence, cwe_ids
             FROM secrets WHERE file = ?1",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map(params![file], |row| {
            Ok(SecretRow {
                id: row.get(0)?,
                pattern_name: row.get(1)?,
                redacted_value: row.get(2)?,
                file: row.get(3)?,
                line: row.get::<_, u32>(4)?,
                severity: row.get(5)?,
                entropy: row.get(6)?,
                confidence: row.get(7)?,
                cwe_ids: row.get(8)?,
            })
        })
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

pub fn get_secrets_by_severity(conn: &Connection, severity: &str) -> Result<Vec<SecretRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, pattern_name, redacted_value, file, line, severity, entropy, confidence, cwe_ids
             FROM secrets WHERE severity = ?1",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map(params![severity], |row| {
            Ok(SecretRow {
                id: row.get(0)?,
                pattern_name: row.get(1)?,
                redacted_value: row.get(2)?,
                file: row.get(3)?,
                line: row.get::<_, u32>(4)?,
                severity: row.get(5)?,
                entropy: row.get(6)?,
                confidence: row.get(7)?,
                cwe_ids: row.get(8)?,
            })
        })
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

// ─── Wrappers ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrapperRow {
    pub id: Option<i64>,
    pub name: String,
    pub file: String,
    pub line: u32,
    pub category: String,
    pub wrapped_primitives: String, // JSON array
    pub framework: String,
    pub confidence: f64,
    pub is_multi_primitive: bool,
    pub is_exported: bool,
    pub usage_count: u32,
}

pub fn insert_wrapper(conn: &Connection, row: &WrapperRow) -> Result<i64, StorageError> {
    conn.execute(
        "INSERT INTO wrappers (name, file, line, category, wrapped_primitives, framework, confidence, is_multi_primitive, is_exported, usage_count)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            row.name, row.file, row.line, row.category, row.wrapped_primitives,
            row.framework, row.confidence, row.is_multi_primitive as i32,
            row.is_exported as i32, row.usage_count,
        ],
    )
    .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    Ok(conn.last_insert_rowid())
}

pub fn get_wrappers_by_file(conn: &Connection, file: &str) -> Result<Vec<WrapperRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, name, file, line, category, wrapped_primitives, framework, confidence, is_multi_primitive, is_exported, usage_count
             FROM wrappers WHERE file = ?1",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map(params![file], |row| {
            Ok(WrapperRow {
                id: row.get(0)?,
                name: row.get(1)?,
                file: row.get(2)?,
                line: row.get::<_, u32>(3)?,
                category: row.get(4)?,
                wrapped_primitives: row.get(5)?,
                framework: row.get(6)?,
                confidence: row.get(7)?,
                is_multi_primitive: row.get::<_, i32>(8)? != 0,
                is_exported: row.get::<_, i32>(9)? != 0,
                usage_count: row.get::<_, u32>(10)?,
            })
        })
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

pub fn get_wrappers_by_category(conn: &Connection, category: &str) -> Result<Vec<WrapperRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, name, file, line, category, wrapped_primitives, framework, confidence, is_multi_primitive, is_exported, usage_count
             FROM wrappers WHERE category = ?1",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map(params![category], |row| {
            Ok(WrapperRow {
                id: row.get(0)?,
                name: row.get(1)?,
                file: row.get(2)?,
                line: row.get::<_, u32>(3)?,
                category: row.get(4)?,
                wrapped_primitives: row.get(5)?,
                framework: row.get(6)?,
                confidence: row.get(7)?,
                is_multi_primitive: row.get::<_, i32>(8)? != 0,
                is_exported: row.get::<_, i32>(9)? != 0,
                usage_count: row.get::<_, u32>(10)?,
            })
        })
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

// ─── DNA Genes ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnaGeneRow {
    pub gene_id: String,
    pub name: String,
    pub description: String,
    pub dominant_allele: Option<String>, // JSON
    pub alleles: String,                 // JSON array
    pub confidence: f64,
    pub consistency: f64,
    pub exemplars: String, // JSON array
}

pub fn upsert_dna_gene(conn: &Connection, row: &DnaGeneRow) -> Result<(), StorageError> {
    conn.execute(
        "INSERT OR REPLACE INTO dna_genes (gene_id, name, description, dominant_allele, alleles, confidence, consistency, exemplars)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![row.gene_id, row.name, row.description, row.dominant_allele, row.alleles, row.confidence, row.consistency, row.exemplars],
    )
    .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    Ok(())
}

pub fn get_dna_gene(conn: &Connection, gene_id: &str) -> Result<Option<DnaGeneRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT gene_id, name, description, dominant_allele, alleles, confidence, consistency, exemplars
             FROM dna_genes WHERE gene_id = ?1",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let result = stmt
        .query_row(params![gene_id], |row| {
            Ok(DnaGeneRow {
                gene_id: row.get(0)?,
                name: row.get(1)?,
                description: row.get(2)?,
                dominant_allele: row.get(3)?,
                alleles: row.get(4)?,
                confidence: row.get(5)?,
                consistency: row.get(6)?,
                exemplars: row.get(7)?,
            })
        })
        .optional()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    Ok(result)
}

pub fn get_all_dna_genes(conn: &Connection) -> Result<Vec<DnaGeneRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT gene_id, name, description, dominant_allele, alleles, confidence, consistency, exemplars
             FROM dna_genes",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map([], |row| {
            Ok(DnaGeneRow {
                gene_id: row.get(0)?,
                name: row.get(1)?,
                description: row.get(2)?,
                dominant_allele: row.get(3)?,
                alleles: row.get(4)?,
                confidence: row.get(5)?,
                consistency: row.get(6)?,
                exemplars: row.get(7)?,
            })
        })
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

// ─── DNA Mutations ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnaMutationRow {
    pub id: String,
    pub file: String,
    pub line: u32,
    pub gene_id: String,
    pub expected: String,
    pub actual: String,
    pub impact: String,
    pub code: String,
    pub suggestion: String,
    pub detected_at: i64,
    pub resolved: bool,
    pub resolved_at: Option<i64>,
}

pub fn upsert_dna_mutation(conn: &Connection, row: &DnaMutationRow) -> Result<(), StorageError> {
    conn.execute(
        "INSERT OR REPLACE INTO dna_mutations (id, file, line, gene_id, expected, actual, impact, code, suggestion, detected_at, resolved, resolved_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            row.id, row.file, row.line, row.gene_id, row.expected, row.actual,
            row.impact, row.code, row.suggestion, row.detected_at,
            row.resolved as i32, row.resolved_at,
        ],
    )
    .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    Ok(())
}

pub fn get_dna_mutations_by_gene(conn: &Connection, gene_id: &str) -> Result<Vec<DnaMutationRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, file, line, gene_id, expected, actual, impact, code, suggestion, detected_at, resolved, resolved_at
             FROM dna_mutations WHERE gene_id = ?1",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map(params![gene_id], |row| {
            Ok(DnaMutationRow {
                id: row.get(0)?,
                file: row.get(1)?,
                line: row.get::<_, u32>(2)?,
                gene_id: row.get(3)?,
                expected: row.get(4)?,
                actual: row.get(5)?,
                impact: row.get(6)?,
                code: row.get(7)?,
                suggestion: row.get(8)?,
                detected_at: row.get(9)?,
                resolved: row.get::<_, i32>(10)? != 0,
                resolved_at: row.get(11)?,
            })
        })
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

pub fn get_unresolved_mutations(conn: &Connection) -> Result<Vec<DnaMutationRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, file, line, gene_id, expected, actual, impact, code, suggestion, detected_at, resolved, resolved_at
             FROM dna_mutations WHERE resolved = 0",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map([], |row| {
            Ok(DnaMutationRow {
                id: row.get(0)?,
                file: row.get(1)?,
                line: row.get::<_, u32>(2)?,
                gene_id: row.get(3)?,
                expected: row.get(4)?,
                actual: row.get(5)?,
                impact: row.get(6)?,
                code: row.get(7)?,
                suggestion: row.get(8)?,
                detected_at: row.get(9)?,
                resolved: row.get::<_, i32>(10)? != 0,
                resolved_at: row.get(11)?,
            })
        })
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

// ─── Crypto Findings ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoFindingRow {
    pub id: Option<i64>,
    pub file: String,
    pub line: u32,
    pub category: String,
    pub description: String,
    pub code: String,
    pub confidence: f64,
    pub cwe_id: u32,
    pub owasp: String,
    pub remediation: String,
    pub language: String,
}

pub fn insert_crypto_finding(conn: &Connection, row: &CryptoFindingRow) -> Result<i64, StorageError> {
    conn.execute(
        "INSERT INTO crypto_findings (file, line, category, description, code, confidence, cwe_id, owasp, remediation, language)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            row.file, row.line, row.category, row.description, row.code,
            row.confidence, row.cwe_id, row.owasp, row.remediation, row.language,
        ],
    )
    .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    Ok(conn.last_insert_rowid())
}

pub fn get_crypto_findings_by_file(conn: &Connection, file: &str) -> Result<Vec<CryptoFindingRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, file, line, category, description, code, confidence, cwe_id, owasp, remediation, language
             FROM crypto_findings WHERE file = ?1",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map(params![file], |row| {
            Ok(CryptoFindingRow {
                id: row.get(0)?,
                file: row.get(1)?,
                line: row.get::<_, u32>(2)?,
                category: row.get(3)?,
                description: row.get(4)?,
                code: row.get(5)?,
                confidence: row.get(6)?,
                cwe_id: row.get::<_, u32>(7)?,
                owasp: row.get(8)?,
                remediation: row.get(9)?,
                language: row.get(10)?,
            })
        })
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

pub fn get_crypto_findings_by_category(conn: &Connection, category: &str) -> Result<Vec<CryptoFindingRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, file, line, category, description, code, confidence, cwe_id, owasp, remediation, language
             FROM crypto_findings WHERE category = ?1",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map(params![category], |row| {
            Ok(CryptoFindingRow {
                id: row.get(0)?,
                file: row.get(1)?,
                line: row.get::<_, u32>(2)?,
                category: row.get(3)?,
                description: row.get(4)?,
                code: row.get(5)?,
                confidence: row.get(6)?,
                cwe_id: row.get::<_, u32>(7)?,
                owasp: row.get(8)?,
                remediation: row.get(9)?,
                language: row.get(10)?,
            })
        })
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

// ─── OWASP Findings ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwaspFindingRow {
    pub id: String,
    pub detector: String,
    pub file: String,
    pub line: u32,
    pub description: String,
    pub severity: f64,
    pub cwes: String,             // JSON array
    pub owasp_categories: String, // JSON array
    pub confidence: f64,
    pub remediation: Option<String>,
}

pub fn upsert_owasp_finding(conn: &Connection, row: &OwaspFindingRow) -> Result<(), StorageError> {
    conn.execute(
        "INSERT OR REPLACE INTO owasp_findings (id, detector, file, line, description, severity, cwes, owasp_categories, confidence, remediation)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            row.id, row.detector, row.file, row.line, row.description,
            row.severity, row.cwes, row.owasp_categories, row.confidence, row.remediation,
        ],
    )
    .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    Ok(())
}

pub fn get_owasp_findings_by_file(conn: &Connection, file: &str) -> Result<Vec<OwaspFindingRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, detector, file, line, description, severity, cwes, owasp_categories, confidence, remediation
             FROM owasp_findings WHERE file = ?1",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map(params![file], |row| {
            Ok(OwaspFindingRow {
                id: row.get(0)?,
                detector: row.get(1)?,
                file: row.get(2)?,
                line: row.get::<_, u32>(3)?,
                description: row.get(4)?,
                severity: row.get(5)?,
                cwes: row.get(6)?,
                owasp_categories: row.get(7)?,
                confidence: row.get(8)?,
                remediation: row.get(9)?,
            })
        })
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

pub fn get_owasp_findings_by_detector(conn: &Connection, detector: &str) -> Result<Vec<OwaspFindingRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, detector, file, line, description, severity, cwes, owasp_categories, confidence, remediation
             FROM owasp_findings WHERE detector = ?1",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map(params![detector], |row| {
            Ok(OwaspFindingRow {
                id: row.get(0)?,
                detector: row.get(1)?,
                file: row.get(2)?,
                line: row.get::<_, u32>(3)?,
                description: row.get(4)?,
                severity: row.get(5)?,
                cwes: row.get(6)?,
                owasp_categories: row.get(7)?,
                confidence: row.get(8)?,
                remediation: row.get(9)?,
            })
        })
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

// ─── Decomposition Decisions ─────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompositionDecisionRow {
    pub id: Option<i64>,
    pub dna_profile_hash: String,
    pub adjustment: String, // JSON
    pub confidence: f64,
    pub dna_similarity: f64,
    pub narrative: String,
    pub source_dna_hash: String,
    pub applied_weight: f64,
}

pub fn insert_decomposition_decision(conn: &Connection, row: &DecompositionDecisionRow) -> Result<i64, StorageError> {
    conn.execute(
        "INSERT INTO decomposition_decisions (dna_profile_hash, adjustment, confidence, dna_similarity, narrative, source_dna_hash, applied_weight)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            row.dna_profile_hash, row.adjustment, row.confidence,
            row.dna_similarity, row.narrative, row.source_dna_hash, row.applied_weight,
        ],
    )
    .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    Ok(conn.last_insert_rowid())
}

pub fn get_decomposition_decisions(conn: &Connection, dna_profile_hash: &str) -> Result<Vec<DecompositionDecisionRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, dna_profile_hash, adjustment, confidence, dna_similarity, narrative, source_dna_hash, applied_weight
             FROM decomposition_decisions WHERE dna_profile_hash = ?1",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map(params![dna_profile_hash], |row| {
            Ok(DecompositionDecisionRow {
                id: row.get(0)?,
                dna_profile_hash: row.get(1)?,
                adjustment: row.get(2)?,
                confidence: row.get(3)?,
                dna_similarity: row.get(4)?,
                narrative: row.get(5)?,
                source_dna_hash: row.get(6)?,
                applied_weight: row.get(7)?,
            })
        })
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

// ─── Coupling Cycles ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CouplingCycleRow {
    pub id: i64,
    pub members: String,
    pub break_suggestions: String,
    pub created_at: i64,
}

/// Insert a coupling cycle record.
pub fn insert_coupling_cycle(
    conn: &Connection,
    members: &str,
    break_suggestions: &str,
) -> Result<(), StorageError> {
    conn.execute(
        "INSERT INTO coupling_cycles (members, break_suggestions) VALUES (?1, ?2)",
        params![members, break_suggestions],
    )
    .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    Ok(())
}

/// Query all coupling cycles.
pub fn query_coupling_cycles(conn: &Connection) -> Result<Vec<CouplingCycleRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, members, break_suggestions, created_at FROM coupling_cycles ORDER BY created_at DESC",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map([], |row| {
            Ok(CouplingCycleRow {
                id: row.get(0)?,
                members: row.get(1)?,
                break_suggestions: row.get(2)?,
                created_at: row.get(3)?,
            })
        })
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

// ─── Constraint Verifications ───────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ConstraintVerificationRow {
    pub id: i64,
    pub constraint_id: String,
    pub passed: bool,
    pub violations: String,
    pub verified_at: i64,
}

/// Insert a constraint verification result.
pub fn insert_constraint_verification(
    conn: &Connection,
    constraint_id: &str,
    passed: bool,
    violations: &str,
) -> Result<(), StorageError> {
    conn.execute(
        "INSERT INTO constraint_verifications (constraint_id, passed, violations) VALUES (?1, ?2, ?3)",
        params![constraint_id, passed as i32, violations],
    )
    .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    Ok(())
}

/// Query constraint verifications by constraint_id.
pub fn query_constraint_verifications(
    conn: &Connection,
    constraint_id: &str,
) -> Result<Vec<ConstraintVerificationRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, constraint_id, passed, violations, verified_at
             FROM constraint_verifications WHERE constraint_id = ?1 ORDER BY verified_at DESC",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map(params![constraint_id], |row| {
            Ok(ConstraintVerificationRow {
                id: row.get(0)?,
                constraint_id: row.get(1)?,
                passed: row.get::<_, i32>(2)? != 0,
                violations: row.get(3)?,
                verified_at: row.get(4)?,
            })
        })
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

// ─── Contract Mismatches ────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ContractMismatchRow {
    pub id: i64,
    pub backend_endpoint: String,
    pub frontend_call: String,
    pub mismatch_type: String,
    pub severity: String,
    pub message: String,
    pub created_at: i64,
}

/// Insert a contract mismatch.
pub fn insert_contract_mismatch(
    conn: &Connection,
    row: &ContractMismatchRow,
) -> Result<(), StorageError> {
    conn.execute(
        "INSERT INTO contract_mismatches (backend_endpoint, frontend_call, mismatch_type, severity, message)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            row.backend_endpoint,
            row.frontend_call,
            row.mismatch_type,
            row.severity,
            row.message,
        ],
    )
    .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    Ok(())
}

/// Query all contract mismatches.
pub fn query_contract_mismatches(conn: &Connection) -> Result<Vec<ContractMismatchRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, backend_endpoint, frontend_call, mismatch_type, severity, message, created_at
             FROM contract_mismatches ORDER BY created_at DESC",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map([], |row| {
            Ok(ContractMismatchRow {
                id: row.get(0)?,
                backend_endpoint: row.get(1)?,
                frontend_call: row.get(2)?,
                mismatch_type: row.get(3)?,
                severity: row.get(4)?,
                message: row.get(5)?,
                created_at: row.get(6)?,
            })
        })
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

/// Query contract mismatches by type.
pub fn query_contract_mismatches_by_type(
    conn: &Connection,
    mismatch_type: &str,
) -> Result<Vec<ContractMismatchRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, backend_endpoint, frontend_call, mismatch_type, severity, message, created_at
             FROM contract_mismatches WHERE mismatch_type = ?1 ORDER BY created_at DESC",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map(params![mismatch_type], |row| {
            Ok(ContractMismatchRow {
                id: row.get(0)?,
                backend_endpoint: row.get(1)?,
                frontend_call: row.get(2)?,
                mismatch_type: row.get(3)?,
                severity: row.get(4)?,
                message: row.get(5)?,
                created_at: row.get(6)?,
            })
        })
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}
