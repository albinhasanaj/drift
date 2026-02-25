//! Field extractors for 10 ORM frameworks.

pub mod sequelize;
pub mod typeorm;
pub mod prisma;
pub mod django;
pub mod sqlalchemy;
pub mod active_record;
pub mod mongoose;
pub mod ef_core;
pub mod hibernate;
pub mod eloquent;

use crate::parsers::types::ParseResult;
use super::types::{ExtractedModel, OrmFramework};

/// Trait for extracting models and fields from ORM-specific code.
pub trait FieldExtractor: Send + Sync {
    /// Which ORM framework this extractor handles.
    fn framework(&self) -> OrmFramework;

    /// File patterns that typically contain schema definitions for this ORM.
    fn schema_file_patterns(&self) -> &[&str];

    /// Extract models from a parse result.
    fn extract_models(&self, parse_result: &ParseResult) -> Vec<ExtractedModel>;
}

/// Create all built-in field extractors.
pub fn create_all_extractors() -> Vec<Box<dyn FieldExtractor>> {
    vec![
        Box::new(sequelize::SequelizeExtractor),
        Box::new(typeorm::TypeOrmExtractor),
        Box::new(prisma::PrismaExtractor),
        Box::new(django::DjangoExtractor),
        Box::new(sqlalchemy::SqlAlchemyExtractor),
        Box::new(active_record::ActiveRecordExtractor),
        Box::new(mongoose::MongooseExtractor),
        Box::new(ef_core::EfCoreExtractor),
        Box::new(hibernate::HibernateExtractor),
        Box::new(eloquent::EloquentExtractor),
    ]
}
