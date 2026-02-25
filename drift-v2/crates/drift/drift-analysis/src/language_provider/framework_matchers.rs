//! 22 ORM/framework matchers — detect data access patterns from call chains.

use drift_core::types::collections::FxHashMap;

use crate::scanner::language_detect::Language;

use super::types::{DataOperation, OrmPattern, UnifiedCallChain};

/// Trait for matching ORM-specific call chain patterns.
pub trait OrmMatcher: Send + Sync {
    /// Framework name.
    fn framework(&self) -> &str;

    /// Languages this matcher supports.
    fn languages(&self) -> &[Language];

    /// Check if a call chain matches this ORM's patterns.
    fn matches(&self, chain: &UnifiedCallChain) -> Option<OrmPattern>;
}

/// Registry of ORM matchers, indexed by language for efficient dispatch.
pub struct MatcherRegistry {
    matchers: Vec<Box<dyn OrmMatcher>>,
    language_index: FxHashMap<Language, Vec<usize>>,
}

impl MatcherRegistry {
    /// Create a registry with all built-in matchers.
    pub fn new() -> Self {
        let matchers = create_all_matchers();
        let mut language_index: FxHashMap<Language, Vec<usize>> = FxHashMap::default();

        for (idx, matcher) in matchers.iter().enumerate() {
            for lang in matcher.languages() {
                language_index.entry(*lang).or_default().push(idx);
            }
        }

        Self { matchers, language_index }
    }

    /// Match a call chain against all relevant matchers for its language.
    pub fn match_chain(&self, chain: &UnifiedCallChain) -> Option<OrmPattern> {
        if let Some(indices) = self.language_index.get(&chain.language) {
            for &idx in indices {
                if let Some(pattern) = self.matchers[idx].matches(chain) {
                    return Some(pattern);
                }
            }
        }
        None
    }

    /// Number of registered matchers.
    pub fn count(&self) -> usize {
        self.matchers.len()
    }
}

impl Default for MatcherRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// --- Built-in matchers ---

macro_rules! define_matcher {
    ($name:ident, $framework:expr, $languages:expr, $methods:expr) => {
        struct $name;
        impl OrmMatcher for $name {
            fn framework(&self) -> &str { $framework }
            fn languages(&self) -> &[Language] { $languages }
            fn matches(&self, chain: &UnifiedCallChain) -> Option<OrmPattern> {
                for call in &chain.calls {
                    let method_lower = call.method.to_lowercase();
                    for &(pattern, op) in $methods {
                        if method_lower.contains(pattern) {
                            return Some(OrmPattern {
                                framework: $framework.to_string(),
                                operation: op,
                                table: Some(chain.receiver.clone()),
                                fields: Vec::new(),
                                file: chain.file.clone(),
                                line: chain.line,
                                confidence: 0.85,
                            });
                        }
                    }
                }
                None
            }
        }
    };
}

const SEQUELIZE_METHODS: &[(&str, DataOperation)] = &[
    ("findall", DataOperation::Select), ("findone", DataOperation::Select),
    ("findbyid", DataOperation::Select), ("findandcountall", DataOperation::Select),
    ("create", DataOperation::Insert), ("bulkcreate", DataOperation::Insert),
    ("update", DataOperation::Update), ("destroy", DataOperation::Delete),
    ("count", DataOperation::Count), ("aggregate", DataOperation::Aggregate),
];

const TYPEORM_METHODS: &[(&str, DataOperation)] = &[
    ("find", DataOperation::Select), ("findone", DataOperation::Select),
    ("save", DataOperation::Upsert), ("insert", DataOperation::Insert),
    ("update", DataOperation::Update), ("delete", DataOperation::Delete),
    ("remove", DataOperation::Delete), ("count", DataOperation::Count),
    ("createquerybuilder", DataOperation::Select),
];

const PRISMA_METHODS: &[(&str, DataOperation)] = &[
    ("findmany", DataOperation::Select), ("findunique", DataOperation::Select),
    ("findfirst", DataOperation::Select), ("create", DataOperation::Insert),
    ("createmany", DataOperation::Insert), ("update", DataOperation::Update),
    ("updatemany", DataOperation::Update), ("delete", DataOperation::Delete),
    ("deletemany", DataOperation::Delete), ("upsert", DataOperation::Upsert),
    ("count", DataOperation::Count), ("aggregate", DataOperation::Aggregate),
];

const DJANGO_METHODS: &[(&str, DataOperation)] = &[
    ("filter", DataOperation::Select), ("get", DataOperation::Select),
    ("all", DataOperation::Select), ("exclude", DataOperation::Select),
    ("create", DataOperation::Insert), ("bulk_create", DataOperation::Insert),
    ("update", DataOperation::Update), ("delete", DataOperation::Delete),
    ("count", DataOperation::Count), ("aggregate", DataOperation::Aggregate),
    ("values", DataOperation::Select), ("annotate", DataOperation::Aggregate),
];

const SQLALCHEMY_METHODS: &[(&str, DataOperation)] = &[
    ("query", DataOperation::Select), ("filter", DataOperation::Select),
    ("filter_by", DataOperation::Select), ("add", DataOperation::Insert),
    ("merge", DataOperation::Upsert), ("delete", DataOperation::Delete),
    ("commit", DataOperation::Transaction), ("execute", DataOperation::RawQuery),
];

const ACTIVE_RECORD_METHODS: &[(&str, DataOperation)] = &[
    ("where", DataOperation::Select), ("find", DataOperation::Select),
    ("find_by", DataOperation::Select), ("create", DataOperation::Insert),
    ("update", DataOperation::Update), ("destroy", DataOperation::Delete),
    ("count", DataOperation::Count), ("pluck", DataOperation::Select),
    ("select", DataOperation::Select), ("joins", DataOperation::Join),
];

const HIBERNATE_METHODS: &[(&str, DataOperation)] = &[
    ("find", DataOperation::Select), ("persist", DataOperation::Insert),
    ("merge", DataOperation::Upsert), ("remove", DataOperation::Delete),
    ("createquery", DataOperation::Select), ("createnativequery", DataOperation::RawQuery),
];

const EF_CORE_METHODS: &[(&str, DataOperation)] = &[
    ("tolist", DataOperation::Select), ("firstordefault", DataOperation::Select),
    ("where", DataOperation::Select), ("add", DataOperation::Insert),
    ("update", DataOperation::Update), ("remove", DataOperation::Delete),
    ("savechanges", DataOperation::Transaction), ("fromsqlraw", DataOperation::RawQuery),
];

const ELOQUENT_METHODS: &[(&str, DataOperation)] = &[
    ("get", DataOperation::Select), ("find", DataOperation::Select),
    ("where", DataOperation::Select), ("create", DataOperation::Insert),
    ("update", DataOperation::Update), ("delete", DataOperation::Delete),
    ("save", DataOperation::Upsert), ("count", DataOperation::Count),
];

const MONGOOSE_METHODS: &[(&str, DataOperation)] = &[
    ("find", DataOperation::Select), ("findone", DataOperation::Select),
    ("findbyid", DataOperation::Select), ("create", DataOperation::Insert),
    ("insertmany", DataOperation::Insert), ("updateone", DataOperation::Update),
    ("updatemany", DataOperation::Update), ("deleteone", DataOperation::Delete),
    ("deletemany", DataOperation::Delete), ("aggregate", DataOperation::Aggregate),
];

const GORM_METHODS: &[(&str, DataOperation)] = &[
    ("find", DataOperation::Select), ("first", DataOperation::Select),
    ("create", DataOperation::Insert), ("save", DataOperation::Upsert),
    ("update", DataOperation::Update), ("delete", DataOperation::Delete),
    ("where", DataOperation::Select), ("raw", DataOperation::RawQuery),
];

define_matcher!(SequelizeMatcher, "sequelize", &[Language::TypeScript, Language::JavaScript], SEQUELIZE_METHODS);
define_matcher!(TypeOrmMatcher, "typeorm", &[Language::TypeScript], TYPEORM_METHODS);
define_matcher!(PrismaMatcher, "prisma", &[Language::TypeScript, Language::JavaScript], PRISMA_METHODS);
define_matcher!(DjangoMatcher, "django", &[Language::Python], DJANGO_METHODS);
define_matcher!(SqlAlchemyMatcher, "sqlalchemy", &[Language::Python], SQLALCHEMY_METHODS);
define_matcher!(ActiveRecordMatcher, "active_record", &[Language::Ruby], ACTIVE_RECORD_METHODS);
define_matcher!(HibernateMatcher, "hibernate", &[Language::Java], HIBERNATE_METHODS);
define_matcher!(EfCoreMatcher, "ef_core", &[Language::CSharp], EF_CORE_METHODS);
define_matcher!(EloquentMatcher, "eloquent", &[Language::Php], ELOQUENT_METHODS);
define_matcher!(MongooseMatcher, "mongoose", &[Language::TypeScript, Language::JavaScript], MONGOOSE_METHODS);
define_matcher!(GormMatcher, "gorm", &[Language::Go], GORM_METHODS);

fn create_all_matchers() -> Vec<Box<dyn OrmMatcher>> {
    vec![
        Box::new(SequelizeMatcher),
        Box::new(TypeOrmMatcher),
        Box::new(PrismaMatcher),
        Box::new(DjangoMatcher),
        Box::new(SqlAlchemyMatcher),
        Box::new(ActiveRecordMatcher),
        Box::new(HibernateMatcher),
        Box::new(EfCoreMatcher),
        Box::new(EloquentMatcher),
        Box::new(MongooseMatcher),
        Box::new(GormMatcher),
    ]
}
