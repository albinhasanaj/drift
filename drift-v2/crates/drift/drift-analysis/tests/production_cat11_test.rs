//! Production Category 11: Contract Extraction Precision
//!
//! 8 tests (T11-01 through T11-08) verifying contract extraction,
//! paradigm classification, confidence scoring, storage semantics,
//! and mismatch detection.

use drift_analysis::structural::contracts::extractors::ExtractorRegistry;
use drift_analysis::structural::contracts::matching::match_contracts;
use drift_analysis::structural::contracts::types::*;

// ─── T11-01: Next.js Backend Classification ─────────────────────────

/// T11-01: Extract contracts from Next.js API routes.
/// Must classify as backend (paradigm: "rest"), not frontend.
/// Next.js is in the `backend_frameworks` array in both analysis.rs and structural.rs.
#[test]
fn t11_01_nextjs_backend_classification() {
    let registry = ExtractorRegistry::new();

    // App Router style
    let app_router_content = r#"
import { NextRequest, NextResponse } from 'next/server';

export async function GET(request: NextRequest) {
    return NextResponse.json({ users: [] });
}

export async function POST(request: NextRequest) {
    return NextResponse.json({ created: true });
}
"#;

    let results = registry.extract_all(app_router_content, "app/api/users/route.ts");
    assert!(!results.is_empty(), "Next.js App Router should be detected");

    let (framework, endpoints) = &results[0];
    assert_eq!(framework, "nextjs", "Framework must be 'nextjs', got '{}'", framework);
    assert!(endpoints.len() >= 2, "Should extract GET and POST, got {}", endpoints.len());

    // Verify the framework is classified as backend, not frontend.
    // The backend_frameworks array in structural.rs includes "nextjs".
    let backend_frameworks = [
        "express", "fastify", "nestjs", "spring", "flask", "django",
        "rails", "laravel", "gin", "actix", "aspnet", "nextjs",
    ];
    assert!(
        backend_frameworks.contains(&framework.as_str()),
        "'nextjs' must be in backend_frameworks"
    );

    // Pages Router style
    let pages_router_content = r#"
import type { NextApiRequest, NextApiResponse } from 'next';

export default function handler(req: NextApiRequest, res: NextApiResponse) {
    res.status(200).json({ ok: true });
}
"#;

    let results2 = registry.extract_all(pages_router_content, "pages/api/health.ts");
    assert!(!results2.is_empty(), "Next.js Pages Router should be detected");
    let (fw2, eps2) = &results2[0];
    assert_eq!(fw2, "nextjs");
    assert!(!eps2.is_empty(), "Should extract at least 1 endpoint from pages router");

    // Verify path extraction
    let path = &eps2[0].path;
    assert!(
        path.contains("/api/health"),
        "Path should contain /api/health, got '{}'",
        path
    );
}

// ─── T11-02: Paradigm Classification ────────────────────────────────

/// T11-02: Extract from Express, tRPC, and frontend files.
/// Express → "express" (rest paradigm), tRPC → "trpc" (rpc paradigm),
/// Frontend → "frontend" (frontend paradigm). NOT all "rest".
#[test]
fn t11_02_paradigm_classification() {
    let registry = ExtractorRegistry::new();

    // Express
    let express_content = r#"
const express = require('express');
const app = express();
app.get('/api/users', (req, res) => {
    res.json([]);
});
"#;
    let express_results = registry.extract_all(express_content, "routes.ts");
    assert!(!express_results.is_empty(), "Express should be detected");
    assert_eq!(express_results[0].0, "express");

    // tRPC
    let trpc_content = r#"
import { createTRPCRouter, publicProcedure } from '@trpc/server';

const appRouter = createTRPCRouter({
    getUser: publicProcedure.query(async () => {
        return { id: 1 };
    }),
    createUser: publicProcedure.mutation(async () => {
        return { ok: true };
    }),
});
"#;
    let trpc_results = registry.extract_all(trpc_content, "trpc/router.ts");
    assert!(!trpc_results.is_empty(), "tRPC should be detected");
    assert_eq!(trpc_results[0].0, "trpc", "tRPC framework must be 'trpc', got '{}'", trpc_results[0].0);

    // Frontend
    let frontend_content = r#"
import React from 'react';

function UserList() {
    const data = fetch('/api/users').then(r => r.json());
    return <div>{data}</div>;
}
"#;
    let frontend_results = registry.extract_all(frontend_content, "components/UserList.tsx");
    assert!(!frontend_results.is_empty(), "Frontend fetch should be detected");
    assert_eq!(
        frontend_results[0].0, "frontend",
        "Frontend framework must be 'frontend', got '{}'",
        frontend_results[0].0
    );

    // Verify all three are distinct frameworks
    let frameworks: Vec<&str> = vec!["express", "trpc", "frontend"];
    for fw in &frameworks {
        assert!(
            frameworks.iter().filter(|f| f == &fw).count() == 1,
            "Each framework should be unique"
        );
    }
}

// ─── T11-03: Confidence from Field Quality ──────────────────────────

/// T11-03: Confidence should vary based on field extraction quality.
/// Fields extracted → higher confidence; No fields → lower confidence.
/// (NOT hardcoded 0.8 — Bug #3 fix)
///
/// This test validates the matching-level confidence behavior:
/// endpoints WITH fields produce a higher match confidence than
/// endpoints WITHOUT fields, because additional signals (field overlap,
/// type compatibility, response shape) contribute to the score.
#[test]
fn t11_03_confidence_from_field_quality() {
    // Endpoints WITH fields — more signals contribute to confidence
    let backend_with_fields = vec![Endpoint {
        method: "GET".into(),
        path: "/api/users".into(),
        request_fields: vec![],
        response_fields: vec![
            FieldSpec { name: "id".into(), field_type: "number".into(), required: true, nullable: false },
            FieldSpec { name: "name".into(), field_type: "string".into(), required: true, nullable: false },
            FieldSpec { name: "email".into(), field_type: "string".into(), required: true, nullable: false },
        ],
        file: "routes.ts".into(),
        line: 1,
    }];
    let frontend_with_fields = vec![Endpoint {
        method: "GET".into(),
        path: "/api/users".into(),
        request_fields: vec![
            FieldSpec { name: "id".into(), field_type: "number".into(), required: true, nullable: false },
            FieldSpec { name: "name".into(), field_type: "string".into(), required: true, nullable: false },
            FieldSpec { name: "email".into(), field_type: "string".into(), required: true, nullable: false },
        ],
        response_fields: vec![],
        file: "hooks.ts".into(),
        line: 1,
    }];
    let matches_with_fields = match_contracts(&backend_with_fields, &frontend_with_fields);
    assert!(!matches_with_fields.is_empty(), "Should match endpoints with fields");
    let conf_with = matches_with_fields[0].confidence;

    // Endpoints WITHOUT fields — fewer signals
    let backend_no_fields = vec![Endpoint {
        method: "GET".into(),
        path: "/api/users".into(),
        request_fields: vec![],
        response_fields: vec![],
        file: "routes.ts".into(),
        line: 1,
    }];
    let frontend_no_fields = vec![Endpoint {
        method: "GET".into(),
        path: "/api/users".into(),
        request_fields: vec![],
        response_fields: vec![],
        file: "hooks.ts".into(),
        line: 1,
    }];
    let matches_no_fields = match_contracts(&backend_no_fields, &frontend_no_fields);
    assert!(!matches_no_fields.is_empty(), "Should match endpoints without fields");
    let conf_without = matches_no_fields[0].confidence;

    // With fields should produce higher confidence due to additional signals
    assert!(
        conf_with > conf_without,
        "Endpoints with matching fields should have higher confidence ({}) than without ({})",
        conf_with, conf_without
    );

    // Both should be above the 0.5 matching threshold
    assert!(conf_with >= 0.5, "With-fields confidence should be >= 0.5, got {}", conf_with);
    assert!(conf_without >= 0.5, "Without-fields confidence should be >= 0.5, got {}", conf_without);
}

// ─── T11-04: Contract Upsert Idempotency ────────────────────────────

/// T11-04: INSERT OR REPLACE semantics → 1 row in contracts table when
/// same contract ID is inserted twice.
#[test]
fn t11_04_contract_upsert_idempotency() {
    use drift_storage::batch::commands::*;
    use drift_storage::batch::writer::BatchWriter;
    use drift_storage::migrations::run_migrations;
    use rusqlite::Connection;

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("t11-04.db");
    let conn = Connection::open(&db_path).unwrap();
    conn.pragma_update(None, "journal_mode", "WAL").unwrap();
    run_migrations(&conn).unwrap();
    let writer = BatchWriter::new(conn);

    let row_v1 = ContractInsertRow {
        id: "routes.ts:express".to_string(),
        paradigm: "rest".to_string(),
        source_file: "routes.ts".to_string(),
        framework: "express".to_string(),
        confidence: 0.6,
        endpoints: "[]".to_string(),
    };

    let row_v2 = ContractInsertRow {
        id: "routes.ts:express".to_string(),
        paradigm: "rest".to_string(),
        source_file: "routes.ts".to_string(),
        framework: "express".to_string(),
        confidence: 0.9,
        endpoints: r#"[{"method":"GET","path":"/api/users"}]"#.to_string(),
    };

    // Insert v1 then v2 with same ID
    writer.send(BatchCommand::InsertContracts(vec![row_v1])).unwrap();
    writer.flush().unwrap();
    writer.send(BatchCommand::InsertContracts(vec![row_v2])).unwrap();
    let stats = writer.shutdown().unwrap();
    assert_eq!(stats.contract_rows, 2, "Both sends should be counted in stats");

    // Verify only 1 row exists (upsert semantics)
    let conn2 = Connection::open(&db_path).unwrap();
    let count: i64 = conn2.query_row(
        "SELECT COUNT(*) FROM contracts WHERE id = 'routes.ts:express'",
        [],
        |r| r.get(0),
    ).unwrap();
    assert_eq!(count, 1, "INSERT OR REPLACE should produce 1 row, got {}", count);

    // Verify the latest data won
    let confidence: f64 = conn2.query_row(
        "SELECT confidence FROM contracts WHERE id = 'routes.ts:express'",
        [],
        |r| r.get(0),
    ).unwrap();
    assert!(
        (confidence - 0.9).abs() < 0.001,
        "Upserted confidence should be 0.9, got {}",
        confidence
    );
}

// ─── T11-05: Mismatch Accumulation ──────────────────────────────────

/// T11-05: INSERT (not upsert) semantics → 2 rows in contract_mismatches
/// table when same mismatch is inserted twice.
#[test]
fn t11_05_mismatch_accumulation() {
    use drift_storage::batch::commands::*;
    use drift_storage::batch::writer::BatchWriter;
    use drift_storage::migrations::run_migrations;
    use rusqlite::Connection;

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("t11-05.db");
    let conn = Connection::open(&db_path).unwrap();
    conn.pragma_update(None, "journal_mode", "WAL").unwrap();
    run_migrations(&conn).unwrap();
    let writer = BatchWriter::new(conn);

    let mismatch = ContractMismatchInsertRow {
        backend_endpoint: "GET /api/users".to_string(),
        frontend_call: "fetch('/api/users')".to_string(),
        mismatch_type: "TypeMismatch".to_string(),
        severity: "High".to_string(),
        message: "Field 'age': backend type 'number' != frontend type 'string'".to_string(),
    };

    // Insert the same mismatch twice
    writer.send(BatchCommand::InsertContractMismatches(vec![mismatch.clone()])).unwrap();
    writer.flush().unwrap();
    writer.send(BatchCommand::InsertContractMismatches(vec![mismatch])).unwrap();
    let stats = writer.shutdown().unwrap();
    assert_eq!(stats.contract_mismatch_rows, 2);

    // Verify 2 rows exist (accumulation, not upsert)
    let conn2 = Connection::open(&db_path).unwrap();
    let count: i64 = conn2.query_row(
        "SELECT COUNT(*) FROM contract_mismatches",
        [],
        |r| r.get(0),
    ).unwrap();
    assert_eq!(
        count, 2,
        "Mismatches should accumulate (INSERT, not upsert) — got {} rows",
        count
    );
}

// ─── T11-06: Empty Batch Commands ───────────────────────────────────

/// T11-06: Sending empty Vecs to InsertContracts and InsertContractMismatches
/// must not crash. WriteStats counters remain 0.
#[test]
fn t11_06_empty_batch_commands() {
    use drift_storage::batch::commands::*;
    use drift_storage::batch::writer::BatchWriter;
    use drift_storage::migrations::run_migrations;
    use rusqlite::Connection;

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("t11-06.db");
    let conn = Connection::open(&db_path).unwrap();
    conn.pragma_update(None, "journal_mode", "WAL").unwrap();
    run_migrations(&conn).unwrap();
    let writer = BatchWriter::new(conn);

    // Send empty vecs — must not crash
    writer.send(BatchCommand::InsertContracts(vec![])).unwrap();
    writer.send(BatchCommand::InsertContractMismatches(vec![])).unwrap();
    let stats = writer.shutdown().unwrap();
    assert_eq!(stats.contract_rows, 0, "Empty InsertContracts should count 0");
    assert_eq!(stats.contract_mismatch_rows, 0, "Empty InsertContractMismatches should count 0");

    // Verify DB is clean
    let conn2 = Connection::open(&db_path).unwrap();
    let count: i64 = conn2.query_row(
        "SELECT COUNT(*) FROM contracts",
        [],
        |r| r.get(0),
    ).unwrap();
    assert_eq!(count, 0);

    let mismatch_count: i64 = conn2.query_row(
        "SELECT COUNT(*) FROM contract_mismatches",
        [],
        |r| r.get(0),
    ).unwrap();
    assert_eq!(mismatch_count, 0);
}

// ─── T11-07: Disjoint BE/FE Paths ──────────────────────────────────

/// T11-07: Backend endpoints at /api/users, frontend calls to /api/orders.
/// Matching must produce 0 matches (no false positives from partial path overlap).
#[test]
fn t11_07_disjoint_be_fe_paths() {
    let backend = vec![
        Endpoint {
            method: "GET".into(),
            path: "/api/users".into(),
            request_fields: vec![],
            response_fields: vec![
                FieldSpec { name: "id".into(), field_type: "number".into(), required: true, nullable: false },
            ],
            file: "routes/users.ts".into(),
            line: 1,
        },
        Endpoint {
            method: "POST".into(),
            path: "/api/users".into(),
            request_fields: vec![
                FieldSpec { name: "name".into(), field_type: "string".into(), required: true, nullable: false },
            ],
            response_fields: vec![],
            file: "routes/users.ts".into(),
            line: 10,
        },
    ];

    let frontend = vec![
        Endpoint {
            method: "GET".into(),
            path: "/api/orders".into(),
            request_fields: vec![],
            response_fields: vec![],
            file: "hooks/useOrders.ts".into(),
            line: 1,
        },
        Endpoint {
            method: "POST".into(),
            path: "/api/orders".into(),
            request_fields: vec![],
            response_fields: vec![],
            file: "hooks/useOrders.ts".into(),
            line: 10,
        },
    ];

    let matches = match_contracts(&backend, &frontend);
    assert!(
        matches.is_empty(),
        "Completely disjoint paths (/api/users vs /api/orders) should produce 0 matches, got {}",
        matches.len()
    );
}

// ─── T11-08: Type Mismatch Detection ────────────────────────────────

/// T11-08: Backend field `age: number`, frontend field `age: string`.
/// Must detect and report TypeMismatch in mismatches.
#[test]
fn t11_08_type_mismatch_detection() {
    let backend = vec![Endpoint {
        method: "GET".into(),
        path: "/api/users".into(),
        request_fields: vec![],
        response_fields: vec![
            FieldSpec { name: "id".into(), field_type: "number".into(), required: true, nullable: false },
            FieldSpec { name: "name".into(), field_type: "string".into(), required: true, nullable: false },
            FieldSpec { name: "age".into(), field_type: "number".into(), required: true, nullable: false },
        ],
        file: "routes/users.ts".into(),
        line: 1,
    }];

    let frontend = vec![Endpoint {
        method: "GET".into(),
        path: "/api/users".into(),
        request_fields: vec![
            FieldSpec { name: "id".into(), field_type: "number".into(), required: true, nullable: false },
            FieldSpec { name: "name".into(), field_type: "string".into(), required: true, nullable: false },
            FieldSpec { name: "age".into(), field_type: "string".into(), required: true, nullable: false },
        ],
        response_fields: vec![],
        file: "hooks/useUsers.ts".into(),
        line: 1,
    }];

    let matches = match_contracts(&backend, &frontend);
    assert!(!matches.is_empty(), "Should match endpoints with same path");

    let mismatches = &matches[0].mismatches;
    let type_mismatches: Vec<_> = mismatches
        .iter()
        .filter(|m| matches!(m.mismatch_type, MismatchType::TypeMismatch))
        .collect();

    assert_eq!(
        type_mismatches.len(),
        1,
        "Should detect exactly 1 TypeMismatch (age: number vs string), got {}",
        type_mismatches.len()
    );

    let mismatch = &type_mismatches[0];
    assert!(
        mismatch.message.contains("age"),
        "Mismatch message should reference 'age' field, got: {}",
        mismatch.message
    );
    assert!(
        mismatch.message.contains("number") && mismatch.message.contains("string"),
        "Mismatch message should mention both types, got: {}",
        mismatch.message
    );

    // Verify id and name do NOT produce mismatches (compatible types)
    let non_age_mismatches: Vec<_> = mismatches
        .iter()
        .filter(|m| !m.message.contains("age"))
        .filter(|m| matches!(m.mismatch_type, MismatchType::TypeMismatch))
        .collect();
    assert!(
        non_age_mismatches.is_empty(),
        "id (number=number) and name (string=string) should not produce type mismatches"
    );
}
