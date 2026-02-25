//! Data access detector — ORM patterns, query patterns, repository patterns.

use smallvec::SmallVec;

use crate::detectors::traits::{Detector, DetectorCategory, DetectorVariant};
use crate::engine::types::{DetectionMethod, PatternCategory, PatternMatch};
use crate::engine::visitor::DetectionContext;

pub struct DataAccessDetector;

impl Detector for DataAccessDetector {
    fn id(&self) -> &str { "data-access-base" }
    fn category(&self) -> DetectorCategory { DetectorCategory::DataAccess }
    fn variant(&self) -> DetectorVariant { DetectorVariant::Base }

    fn detect(&self, ctx: &DetectionContext) -> Vec<PatternMatch> {
        let mut matches = Vec::new();

        // Detect ORM method calls
        let orm_methods = [
            // Generic ORM
            "findOne", "findAll", "findMany", "findById", "findByPk",
            "create", "update", "delete", "destroy", "save",
            "query", "execute", "raw", "rawQuery",
            "where", "select", "insert", "bulkCreate",
            "aggregate", "count", "sum", "avg",
            // Python (Django/SQLAlchemy)
            "filter", "get_or_create", "bulk_create", "objects",
            // Java (JPA/Hibernate)
            "persist", "merge", "flush", "detach", "getResultList", "getSingleResult",
            "createQuery", "createNativeQuery",
            // Go (GORM)
            "First", "Find", "Create", "Save", "Delete", "Where", "Preload",
            // Ruby (ActiveRecord)
            "find_by", "find_each", "find_in_batches", "where", "pluck", "joins",
            // C# (Entity Framework)
            "Include", "ThenInclude", "AsNoTracking", "FromSqlRaw", "ToListAsync",
            // PHP (Eloquent)
            "firstOrCreate", "updateOrCreate", "firstOrFail", "get", "paginate",
            // Rust (Diesel/SQLx)
            "load", "get_result", "get_results", "fetch_one", "fetch_all",
        ];

        for call in ctx.call_sites {
            if orm_methods.contains(&call.callee_name.as_str()) {
                matches.push(PatternMatch {
                    file: ctx.file.to_string(),
                    line: call.line,
                    column: call.column,
                    pattern_id: "DA-ORM-001".to_string(),
                    confidence: 0.75,
                    cwe_ids: SmallVec::new(),
                    owasp: None,
                    detection_method: DetectionMethod::AstVisitor,
                    category: PatternCategory::DataAccess,
                    matched_text: format!("ORM call: {}", call.callee_name),
                });
            }

            // Detect raw SQL usage
            if matches!(call.callee_name.as_str(), "query" | "execute" | "raw" | "rawQuery"
                | "exec" | "prepare" | "sql") {
                if let Some(ref receiver) = call.receiver {
                    if receiver.contains("db") || receiver.contains("conn") || receiver.contains("pool")
                        || receiver.contains("knex") || receiver.contains("sequelize")
                        || receiver.contains("prisma") || receiver.contains("session")  // Python SQLAlchemy
                        || receiver.contains("entityManager") || receiver.contains("jdbc")  // Java
                        || receiver.contains("gorm") || receiver.contains("sqlx")  // Go/Rust
                        || receiver.contains("ActiveRecord") || receiver.contains("connection")  // Ruby
                        || receiver.contains("DB") || receiver.contains("PDO")  // PHP
                        || receiver.contains("context") || receiver.contains("dbContext")  // C#
                    {
                        matches.push(PatternMatch {
                            file: ctx.file.to_string(),
                            line: call.line,
                            column: call.column,
                            pattern_id: "DA-RAW-001".to_string(),
                            confidence: 0.80,
                            cwe_ids: SmallVec::from_buf([89, 0]),
                            owasp: Some("A03:2021".to_string()),
                            detection_method: DetectionMethod::AstVisitor,
                            category: PatternCategory::DataAccess,
                            matched_text: format!("raw query: {}.{}", receiver, call.callee_name),
                        });
                    }
                }
            }
        }

        // Detect repository pattern from class names
        for class in ctx.classes {
            let lower = class.name.to_lowercase();
            if lower.contains("repository") || lower.contains("repo") || lower.contains("dao") {
                matches.push(PatternMatch {
                    file: ctx.file.to_string(),
                    line: class.range.start.line,
                    column: class.range.start.column,
                    pattern_id: "DA-REPO-001".to_string(),
                    confidence: 0.85,
                    cwe_ids: SmallVec::new(),
                    owasp: None,
                    detection_method: DetectionMethod::AstVisitor,
                    category: PatternCategory::DataAccess,
                    matched_text: format!("repository pattern: {}", class.name),
                });
            }
        }

        matches
    }
}
