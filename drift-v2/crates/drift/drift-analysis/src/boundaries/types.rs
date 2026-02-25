//! Boundary detection types — models, fields, sensitivity, ORM frameworks.

use serde::{Deserialize, Serialize};

/// Result of a boundary scan across the codebase.
#[derive(Debug, Clone, Default)]
pub struct BoundaryScanResult {
    pub models: Vec<ExtractedModel>,
    pub sensitive_fields: Vec<SensitiveField>,
    pub frameworks_detected: Vec<OrmFramework>,
    pub total_fields: usize,
    pub total_sensitive: usize,
}

/// An extracted data model from an ORM framework.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedModel {
    pub name: String,
    pub table_name: Option<String>,
    pub file: String,
    pub line: u32,
    pub framework: OrmFramework,
    pub fields: Vec<ExtractedField>,
    pub relationships: Vec<Relationship>,
    pub confidence: f32,
}

/// A field extracted from a data model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedField {
    pub name: String,
    pub field_type: Option<String>,
    pub is_primary_key: bool,
    pub is_nullable: bool,
    pub is_unique: bool,
    pub default_value: Option<String>,
    pub line: u32,
}

/// A relationship between models.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relationship {
    pub kind: RelationshipKind,
    pub target_model: String,
    pub foreign_key: Option<String>,
}

/// Relationship types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RelationshipKind {
    HasOne,
    HasMany,
    BelongsTo,
    ManyToMany,
}

/// A sensitive field detection result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensitiveField {
    pub model_name: String,
    pub field_name: String,
    pub file: String,
    pub line: u32,
    pub sensitivity: SensitivityType,
    pub confidence: f32,
    pub matched_pattern: String,
}

/// Sensitivity categories for detected fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SensitivityType {
    /// Personally Identifiable Information (name, email, phone, SSN, etc.)
    Pii,
    /// Credentials (password, API key, token, secret)
    Credentials,
    /// Financial data (credit card, bank account, routing number)
    Financial,
    /// Health data (diagnosis, prescription, medical record)
    Health,
}

impl SensitivityType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Pii => "pii",
            Self::Credentials => "credentials",
            Self::Financial => "financial",
            Self::Health => "health",
        }
    }

    pub fn all() -> &'static [SensitivityType] {
        &[Self::Pii, Self::Credentials, Self::Financial, Self::Health]
    }
}

impl std::fmt::Display for SensitivityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Supported ORM frameworks (33+ variants).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OrmFramework {
    // JavaScript/TypeScript
    Sequelize,
    TypeOrm,
    Prisma,
    Mongoose,
    Knex,
    Objection,
    Bookshelf,
    MikroOrm,
    Drizzle,
    // Python
    Django,
    SqlAlchemy,
    Peewee,
    Tortoise,
    Pony,
    // Ruby
    ActiveRecord,
    Sequel,
    // Java
    Hibernate,
    Jpa,
    MyBatis,
    Jooq,
    // C#
    EfCore,
    Dapper,
    NHibernate,
    // PHP
    Eloquent,
    Doctrine,
    Propel,
    // Go
    Gorm,
    Ent,
    Sqlx,
    // Rust
    Diesel,
    SeaOrm,
    SqlxRust,
    // Other
    Unknown,
}

impl OrmFramework {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Sequelize => "sequelize",
            Self::TypeOrm => "typeorm",
            Self::Prisma => "prisma",
            Self::Mongoose => "mongoose",
            Self::Knex => "knex",
            Self::Objection => "objection",
            Self::Bookshelf => "bookshelf",
            Self::MikroOrm => "mikro-orm",
            Self::Drizzle => "drizzle",
            Self::Django => "django",
            Self::SqlAlchemy => "sqlalchemy",
            Self::Peewee => "peewee",
            Self::Tortoise => "tortoise",
            Self::Pony => "pony",
            Self::ActiveRecord => "active_record",
            Self::Sequel => "sequel",
            Self::Hibernate => "hibernate",
            Self::Jpa => "jpa",
            Self::MyBatis => "mybatis",
            Self::Jooq => "jooq",
            Self::EfCore => "ef_core",
            Self::Dapper => "dapper",
            Self::NHibernate => "nhibernate",
            Self::Eloquent => "eloquent",
            Self::Doctrine => "doctrine",
            Self::Propel => "propel",
            Self::Gorm => "gorm",
            Self::Ent => "ent",
            Self::Sqlx => "sqlx",
            Self::Diesel => "diesel",
            Self::SeaOrm => "sea-orm",
            Self::SqlxRust => "sqlx-rust",
            Self::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for OrmFramework {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Signature for detecting an ORM framework from imports/decorators.
#[derive(Debug, Clone)]
pub struct FrameworkSignature {
    pub framework: OrmFramework,
    pub import_patterns: Vec<String>,
    pub decorator_patterns: Vec<String>,
    pub schema_file_patterns: Vec<String>,
}
