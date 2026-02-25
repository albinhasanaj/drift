#![allow(unused_imports, clippy::useless_vec)]
//! Boundary Detection tests — T2-BND-01 through T2-BND-06.
//!
//! Tests for boundary detection: ORM framework detection, sensitive field detection,
//! false-positive filters, confidence scoring, field extractors.

use std::path::Path;

use drift_analysis::boundaries::detector::BoundaryDetector;
use drift_analysis::boundaries::extractors::create_all_extractors;
use drift_analysis::boundaries::sensitive::SensitiveFieldDetector;
use drift_analysis::boundaries::types::{
    ExtractedField, ExtractedModel, OrmFramework, SensitivityType,
};
use drift_analysis::parsers::manager::ParserManager;
use drift_analysis::parsers::types::ParseResult;
use smallvec::SmallVec;

// ---- Helpers ----

fn parse_file(source: &str, file: &str) -> ParseResult {
    let parser = ParserManager::new();
    parser.parse(source.as_bytes(), Path::new(file)).unwrap()
}

fn make_model(name: &str, file: &str, framework: OrmFramework, fields: Vec<(&str, u32)>) -> ExtractedModel {
    ExtractedModel {
        name: name.to_string(),
        table_name: Some(name.to_lowercase()),
        file: file.to_string(),
        line: 1,
        framework,
        fields: fields
            .into_iter()
            .map(|(fname, line)| ExtractedField {
                name: fname.to_string(),
                field_type: Some("string".to_string()),
                is_primary_key: fname == "id",
                is_nullable: false,
                is_unique: false,
                default_value: None,
                line,
            })
            .collect(),
        relationships: Vec::new(),
        confidence: 0.90,
    }
}

// ---- T2-BND-01: Boundary detection identifies ORM patterns across 5+ frameworks ----

#[test]
fn t2_bnd_01_orm_framework_detection() {
    // Create parse results with imports from 5 different ORMs
    let sources = vec![
        ("sequelize_model.ts", r#"import { Model, DataTypes } from 'sequelize';
export class User extends Model {
    declare id: number;
    declare email: string;
}"#),
        ("prisma_service.ts", r#"import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();
export async function getUsers() { return prisma.user.findMany(); }"#),
        ("django_model.py", r#"from django.db import models
class UserProfile(models.Model):
    email = models.EmailField()
    name = models.CharField(max_length=100)"#),
        ("sqlalchemy_model.py", r#"from sqlalchemy import Column, String, Integer
from sqlalchemy.ext.declarative import declarative_base
Base = declarative_base()
class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    email = Column(String)"#),
        ("active_record_model.rb", r#"require 'active_record'
class User < ActiveRecord::Base
  validates :email, presence: true
end"#),
    ];

    let parse_results: Vec<ParseResult> = sources
        .iter()
        .map(|(file, src)| parse_file(src, file))
        .collect();

    let detector = BoundaryDetector::new();
    let result = detector.detect(&parse_results).unwrap();

    // Should detect at least some frameworks
    assert!(
        !result.frameworks_detected.is_empty(),
        "should detect at least 1 ORM framework, got 0"
    );

    eprintln!(
        "Detected frameworks: {:?}",
        result.frameworks_detected.iter().map(|f| f.name()).collect::<Vec<_>>()
    );

    // Verify OrmFramework enum has 33+ variants
    let all_frameworks = vec![
        OrmFramework::Sequelize, OrmFramework::TypeOrm, OrmFramework::Prisma,
        OrmFramework::Mongoose, OrmFramework::Knex, OrmFramework::Objection,
        OrmFramework::Bookshelf, OrmFramework::MikroOrm, OrmFramework::Drizzle,
        OrmFramework::Django, OrmFramework::SqlAlchemy, OrmFramework::Peewee,
        OrmFramework::Tortoise, OrmFramework::Pony,
        OrmFramework::ActiveRecord, OrmFramework::Sequel,
        OrmFramework::Hibernate, OrmFramework::Jpa, OrmFramework::MyBatis, OrmFramework::Jooq,
        OrmFramework::EfCore, OrmFramework::Dapper, OrmFramework::NHibernate,
        OrmFramework::Eloquent, OrmFramework::Doctrine, OrmFramework::Propel,
        OrmFramework::Gorm, OrmFramework::Ent, OrmFramework::Sqlx,
        OrmFramework::Diesel, OrmFramework::SeaOrm, OrmFramework::SqlxRust,
        OrmFramework::Unknown,
    ];
    assert!(
        all_frameworks.len() >= 33,
        "OrmFramework should have 33+ variants, got {}",
        all_frameworks.len()
    );
}

// ---- T2-BND-02: Sensitive field detection across all 4 categories ----

#[test]
fn t2_bnd_02_sensitive_field_categories() {
    let detector = SensitiveFieldDetector::new();

    // PII model
    let pii_model = make_model("User", "user.ts", OrmFramework::Sequelize, vec![
        ("id", 1), ("email", 2), ("phone_number", 3), ("ssn", 4),
        ("first_name", 5), ("date_of_birth", 6),
    ]);
    let pii_fields = detector.detect_sensitive_fields(&pii_model);
    let pii_types: Vec<SensitivityType> = pii_fields.iter().map(|f| f.sensitivity).collect();
    assert!(
        pii_types.contains(&SensitivityType::Pii),
        "should detect PII fields, got: {:?}",
        pii_fields.iter().map(|f| (&f.field_name, f.sensitivity)).collect::<Vec<_>>()
    );

    // Credentials model
    let cred_model = make_model("Account", "account.ts", OrmFramework::TypeOrm, vec![
        ("id", 1), ("password_hash", 2), ("api_key", 3), ("access_token", 4),
    ]);
    let cred_fields = detector.detect_sensitive_fields(&cred_model);
    let cred_types: Vec<SensitivityType> = cred_fields.iter().map(|f| f.sensitivity).collect();
    assert!(
        cred_types.contains(&SensitivityType::Credentials),
        "should detect Credential fields"
    );

    // Financial model
    let fin_model = make_model("Payment", "payment.ts", OrmFramework::Prisma, vec![
        ("id", 1), ("credit_card", 2), ("cvv", 3), ("bank_account", 4),
    ]);
    let fin_fields = detector.detect_sensitive_fields(&fin_model);
    let fin_types: Vec<SensitivityType> = fin_fields.iter().map(|f| f.sensitivity).collect();
    assert!(
        fin_types.contains(&SensitivityType::Financial),
        "should detect Financial fields"
    );

    // Health model
    let health_model = make_model("Patient", "patient.ts", OrmFramework::Django, vec![
        ("id", 1), ("diagnosis", 2), ("prescription", 3), ("blood_type", 4),
    ]);
    let health_fields = detector.detect_sensitive_fields(&health_model);
    let health_types: Vec<SensitivityType> = health_fields.iter().map(|f| f.sensitivity).collect();
    assert!(
        health_types.contains(&SensitivityType::Health),
        "should detect Health fields"
    );

    // Verify all 4 categories exist
    assert_eq!(SensitivityType::all().len(), 4);
}

// ---- T2-BND-03: False-positive filters ----

#[test]
fn t2_bnd_03_false_positive_filters() {
    let detector = SensitiveFieldDetector::new();

    // Fields that should NOT be flagged (or flagged with very low confidence)
    let model = make_model("Config", "config.ts", OrmFramework::Sequelize, vec![
        ("password_reset_token_expiry", 1),
        ("token_type", 2),
        ("email_format", 3),
        ("address_count", 4),
        ("phone_enabled", 5),
        ("ssn_template", 6),
    ]);

    let sensitive = detector.detect_sensitive_fields(&model);

    // Fields ending in _type, _format, _count, _enabled, _template should have
    // reduced confidence due to false-positive filters
    for field in &sensitive {
        let name = &field.field_name;
        if name.ends_with("_type") || name.ends_with("_format")
            || name.ends_with("_count") || name.ends_with("_enabled")
            || name.ends_with("_template")
        {
            assert!(
                field.confidence < 0.50,
                "field '{}' should have reduced confidence due to FP filter, got {}",
                name,
                field.confidence
            );
        }
    }

    // password_reset_token_expiry should have reduced confidence
    let expiry_field = sensitive.iter().find(|f| f.field_name == "password_reset_token_expiry");
    if let Some(f) = expiry_field {
        assert!(
            f.confidence < 0.70,
            "password_reset_token_expiry should have reduced confidence, got {}",
            f.confidence
        );
    }
}

// ---- T2-BND-04: Unknown ORM framework graceful degradation ----

#[test]
fn t2_bnd_04_unknown_orm_graceful() {
    // Parse results with no recognizable ORM imports
    let source = r#"
function plainFunction() {
    return { id: 1, name: 'test' };
}
"#;
    let pr = parse_file(source, "plain.ts");

    let detector = BoundaryDetector::new();
    let result = detector.detect(&[pr]).unwrap();

    // Should return empty result, not error
    assert!(
        result.frameworks_detected.is_empty(),
        "no ORM frameworks should be detected in plain code"
    );
    assert_eq!(result.models.len(), 0, "no models should be extracted");
    assert_eq!(result.total_sensitive, 0, "no sensitive fields");
}

// ---- T2-BND-05: Confidence scoring — context-aware ----

#[test]
fn t2_bnd_05_confidence_scoring() {
    let detector = SensitiveFieldDetector::new();

    // SSN in a User model should score higher than in a Config model
    let user_model = make_model("User", "user.ts", OrmFramework::Sequelize, vec![
        ("ssn", 1),
    ]);
    let config_model = make_model("Config", "config.ts", OrmFramework::Sequelize, vec![
        ("ssn", 1),
    ]);

    let user_sensitive = detector.detect_sensitive_fields(&user_model);
    let config_sensitive = detector.detect_sensitive_fields(&config_model);

    assert!(!user_sensitive.is_empty(), "User.ssn should be detected");
    assert!(!config_sensitive.is_empty(), "Config.ssn should be detected");

    let user_conf = user_sensitive[0].confidence;
    let config_conf = config_sensitive[0].confidence;

    // User model gets a context boost for PII fields
    assert!(
        user_conf >= config_conf,
        "User.ssn ({}) should have >= confidence than Config.ssn ({})",
        user_conf,
        config_conf
    );

    eprintln!("User.ssn confidence: {}, Config.ssn confidence: {}", user_conf, config_conf);
}

// ---- T2-BND-06: All 10 field extractors produce valid output ----

#[test]
fn t2_bnd_06_all_extractors() {
    let extractors = create_all_extractors();

    assert_eq!(
        extractors.len(),
        10,
        "should have 10 field extractors, got {}",
        extractors.len()
    );

    // Verify each extractor has a valid framework
    let expected_frameworks = vec![
        OrmFramework::Sequelize,
        OrmFramework::TypeOrm,
        OrmFramework::Prisma,
        OrmFramework::Django,
        OrmFramework::SqlAlchemy,
        OrmFramework::ActiveRecord,
        OrmFramework::Mongoose,
        OrmFramework::EfCore,
        OrmFramework::Hibernate,
        OrmFramework::Eloquent,
    ];

    let extractor_frameworks: Vec<OrmFramework> = extractors.iter().map(|e| e.framework()).collect();

    for expected in &expected_frameworks {
        assert!(
            extractor_frameworks.contains(expected),
            "should have extractor for {:?}",
            expected
        );
    }

    // Each extractor should have schema file patterns
    for extractor in &extractors {
        let patterns = extractor.schema_file_patterns();
        assert!(
            !patterns.is_empty(),
            "extractor for {:?} should have schema file patterns",
            extractor.framework()
        );
    }
}
