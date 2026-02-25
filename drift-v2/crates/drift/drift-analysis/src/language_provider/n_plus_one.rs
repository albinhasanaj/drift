//! N+1 query detection — call graph + ORM pattern matching.
//!
//! Detects N+1 patterns by finding loops that contain ORM query calls.
//! Supports 8 ORM frameworks: ActiveRecord, Django ORM, SQLAlchemy,
//! Hibernate, Entity Framework, Prisma, Sequelize, TypeORM.
//! Also detects GraphQL N+1 resolver patterns.

use crate::parsers::types::ParseResult;

use super::framework_matchers::MatcherRegistry;
use super::normalizers;
use super::types::DataOperation;

/// An N+1 query detection result.
#[derive(Debug, Clone)]
pub struct NPlusOneDetection {
    pub file: String,
    pub line: u32,
    pub loop_line: u32,
    pub query_method: String,
    pub framework: String,
    pub confidence: f32,
    pub detection_type: NPlusOneType,
    pub suggestion: String,
}

/// Type of N+1 detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NPlusOneType {
    /// ORM query inside a loop.
    LoopQuery,
    /// GraphQL resolver that queries per item.
    GraphqlResolver,
    /// Lazy-loaded relationship access in a loop.
    LazyLoadInLoop,
}

/// Loop detection patterns for different languages.
const LOOP_PATTERNS: &[&str] = &[
    "forEach", "map", "filter", "reduce", "for_each",
    "iter", "each", "collect", "flat_map", "flatMap",
    "for", "while", "loop", "do",
    // Python
    "list_comprehension",
    // Ruby
    "each_with_object", "each_with_index", "select", "reject",
];

/// Batch query patterns (false positive exclusions).
const BATCH_PATTERNS: &[&str] = &[
    "WHERE id IN", "where id in", "WHERE id = ANY",
    "findAll", "find_all", "bulk", "batch",
    "in_bulk", "prefetch_related", "select_related",
    "includes", "eager_load", "preload",
    "Include", "ThenInclude", // Entity Framework
    "fetch", "fetchJoin", // Hibernate
    "include", // Prisma
    "with", // Eloquent
];

/// ORM-specific query patterns for 8 frameworks.
#[allow(dead_code)]
struct OrmQueryPatterns {
    framework: &'static str,
    query_methods: &'static [&'static str],
    lazy_load_patterns: &'static [&'static str],
}

const ORM_PATTERNS: &[OrmQueryPatterns] = &[
    OrmQueryPatterns {
        framework: "active_record",
        query_methods: &["find", "find_by", "where", "first", "last", "find_each"],
        lazy_load_patterns: &[".association", ".belongs_to", ".has_many"],
    },
    OrmQueryPatterns {
        framework: "django",
        query_methods: &["get", "filter", "exclude", "all", "values", "values_list"],
        lazy_load_patterns: &["_set.all", "_set.filter"],
    },
    OrmQueryPatterns {
        framework: "sqlalchemy",
        query_methods: &["query", "filter", "filter_by", "get", "first", "one"],
        lazy_load_patterns: &[".lazy", "relationship"],
    },
    OrmQueryPatterns {
        framework: "hibernate",
        query_methods: &["find", "get", "load", "createQuery", "createNativeQuery"],
        lazy_load_patterns: &["FetchType.LAZY", "fetch = FetchType.LAZY"],
    },
    OrmQueryPatterns {
        framework: "ef_core",
        query_methods: &["Find", "FindAsync", "FirstOrDefault", "Where", "Single"],
        lazy_load_patterns: &["virtual", "LazyLoadingEnabled"],
    },
    OrmQueryPatterns {
        framework: "prisma",
        query_methods: &["findUnique", "findFirst", "findMany", "create", "update"],
        lazy_load_patterns: &[],
    },
    OrmQueryPatterns {
        framework: "sequelize",
        query_methods: &["findOne", "findAll", "findByPk", "findAndCountAll", "create"],
        lazy_load_patterns: &["getAssociation", "get"],
    },
    OrmQueryPatterns {
        framework: "typeorm",
        query_methods: &["findOne", "find", "findOneBy", "findBy", "createQueryBuilder"],
        lazy_load_patterns: &["lazy: true"],
    },
];

/// GraphQL resolver patterns that suggest N+1.
const GRAPHQL_RESOLVER_PATTERNS: &[&str] = &[
    "resolve", "resolver", "@ResolveField", "@Query", "@Mutation",
    "fieldResolver", "parentResolver",
];

/// Detect N+1 query patterns in parse results.
///
/// Supports 8 ORM frameworks + GraphQL resolver detection.
/// False positive control: batch queries are NOT flagged.
pub fn detect_n_plus_one(
    parse_results: &[ParseResult],
    matcher_registry: &MatcherRegistry,
) -> Vec<NPlusOneDetection> {
    let mut detections = Vec::new();

    for pr in parse_results {
        let normalizer = normalizers::normalizer_for(pr.language);
        let chains = normalizer.extract_chains(pr);

        for chain in &chains {
            if let Some(pattern) = matcher_registry.match_chain(chain) {
                if matches!(pattern.operation, DataOperation::Select | DataOperation::RawQuery) {
                    // Check if this is a batch query (false positive exclusion)
                    if is_batch_query(chain, pr) {
                        continue;
                    }

                    // Check for loop-query pattern
                    for func in &pr.functions {
                        if chain.line >= func.line && chain.line <= func.end_line {
                            // Check for loop patterns in the same function
                            let loop_info = find_loop_pattern(pr, func.line, func.end_line, chain.line);

                            if let Some((loop_line, loop_type)) = loop_info {
                                detections.push(NPlusOneDetection {
                                    file: pr.file.clone(),
                                    line: chain.line,
                                    loop_line,
                                    query_method: chain.calls.first()
                                        .map(|c| c.method.clone())
                                        .unwrap_or_default(),
                                    framework: pattern.framework.clone(),
                                    confidence: compute_confidence(&pattern.framework, loop_type),
                                    detection_type: match loop_type {
                                        LoopType::Explicit => NPlusOneType::LoopQuery,
                                        LoopType::Iterator => NPlusOneType::LoopQuery,
                                        LoopType::LazyLoad => NPlusOneType::LazyLoadInLoop,
                                    },
                                    suggestion: generate_suggestion(&pattern.framework, loop_type),
                                });
                            }
                        }
                    }
                }
            }
        }

        // GraphQL N+1 resolver detection
        detections.extend(detect_graphql_n_plus_one(pr));
    }

    detections
}

/// Check if a query is a batch query (false positive exclusion).
fn is_batch_query(chain: &super::types::UnifiedCallChain, pr: &ParseResult) -> bool {
    // Check method name for batch patterns
    for call in &chain.calls {
        for pattern in BATCH_PATTERNS {
            if call.method.contains(pattern) {
                return true;
            }
        }
        // Check arguments for IN clause
        for arg in &call.args {
            if let super::types::CallArg::StringLiteral(s) = arg {
                if s.to_lowercase().contains("in (") || s.to_lowercase().contains("in(") {
                    return true;
                }
            }
        }
    }

    // Check surrounding code for batch patterns
    for literal in &pr.string_literals {
        if literal.line == chain.line || literal.line == chain.line.saturating_sub(1) {
            let lower = literal.value.to_lowercase();
            if lower.contains("where") && (lower.contains(" in (") || lower.contains(" in(")) {
                return true;
            }
        }
    }

    false
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
enum LoopType {
    Explicit,
    Iterator,
    LazyLoad,
}

/// Find a loop pattern in a function that contains the query.
fn find_loop_pattern(
    pr: &ParseResult,
    func_start: u32,
    func_end: u32,
    query_line: u32,
) -> Option<(u32, LoopType)> {
    // Check call sites for iterator/loop patterns
    for cs in &pr.call_sites {
        if cs.line >= func_start && cs.line <= func_end && cs.line < query_line {
            let callee = cs.callee_name.as_str();

            // Explicit loop-like iterators
            if LOOP_PATTERNS.contains(&callee) {
                return Some((cs.line, LoopType::Iterator));
            }
        }
    }

    // Check for lazy-load patterns in the query method
    for orm in ORM_PATTERNS {
        for lazy_pattern in orm.lazy_load_patterns {
            // Check if any call site near the query matches lazy load patterns
            for cs in &pr.call_sites {
                if cs.line >= func_start && cs.line <= func_end
                    && cs.callee_name.contains(lazy_pattern)
                {
                    return Some((cs.line, LoopType::LazyLoad));
                }
            }
        }
    }

    None
}

/// Detect GraphQL N+1 resolver patterns.
fn detect_graphql_n_plus_one(pr: &ParseResult) -> Vec<NPlusOneDetection> {
    let mut detections = Vec::new();

    for func in &pr.functions {
        let is_resolver = func.decorators.iter().any(|d| {
            GRAPHQL_RESOLVER_PATTERNS.iter().any(|p| d.name.contains(p))
        }) || GRAPHQL_RESOLVER_PATTERNS.iter().any(|p| func.name.contains(p));

        if !is_resolver {
            continue;
        }

        // Check if resolver contains a DB query
        let has_query = pr.call_sites.iter().any(|cs| {
            cs.line >= func.line && cs.line <= func.end_line
                && ORM_PATTERNS.iter().any(|orm| {
                    orm.query_methods.iter().any(|m| cs.callee_name.contains(m))
                })
        });

        if has_query {
            // This resolver queries the DB — potential N+1 if called per item
            detections.push(NPlusOneDetection {
                file: pr.file.clone(),
                line: func.line,
                loop_line: func.line,
                query_method: func.name.clone(),
                framework: "graphql".to_string(),
                confidence: 0.65,
                detection_type: NPlusOneType::GraphqlResolver,
                suggestion: "Consider using DataLoader to batch resolver queries.".to_string(),
            });
        }
    }

    detections
}

/// Compute confidence based on framework and loop type.
fn compute_confidence(framework: &str, loop_type: LoopType) -> f32 {
    let base = match loop_type {
        LoopType::Explicit => 0.85,
        LoopType::Iterator => 0.75,
        LoopType::LazyLoad => 0.70,
    };

    // Adjust based on framework (some are more reliable to detect)
    let framework_factor = match framework {
        "active_record" | "django" | "sequelize" => 1.0,
        "sqlalchemy" | "prisma" | "typeorm" => 0.95,
        "hibernate" | "ef_core" => 0.90,
        _ => 0.85,
    };

    let result = base * framework_factor;
    if result > 1.0 { 1.0 } else { result }
}

/// Generate a fix suggestion based on framework and loop type.
fn generate_suggestion(framework: &str, loop_type: LoopType) -> String {
    match (framework, loop_type) {
        ("active_record", _) => "Use `includes(:association)` or `eager_load` to preload.".to_string(),
        ("django", _) => "Use `select_related()` or `prefetch_related()` to avoid N+1.".to_string(),
        ("sqlalchemy", _) => "Use `joinedload()` or `subqueryload()` from sqlalchemy.orm.".to_string(),
        ("hibernate", _) => "Use `@Fetch(FetchMode.JOIN)` or `JOIN FETCH` in HQL.".to_string(),
        ("ef_core", _) => "Use `.Include()` or `.ThenInclude()` for eager loading.".to_string(),
        ("prisma", _) => "Use `include` in the Prisma query to load relations.".to_string(),
        ("sequelize", _) => "Use `include` option in findAll to eager load.".to_string(),
        ("typeorm", _) => "Use `relations` option or `leftJoinAndSelect` in QueryBuilder.".to_string(),
        _ => "Consider batching queries or using eager loading.".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_patterns_not_flagged() {
        // Verify batch patterns are recognized
        assert!(BATCH_PATTERNS.contains(&"findAll"));
        assert!(BATCH_PATTERNS.contains(&"prefetch_related"));
        assert!(BATCH_PATTERNS.contains(&"includes"));
    }

    #[test]
    fn test_orm_patterns_cover_8_frameworks() {
        assert_eq!(ORM_PATTERNS.len(), 8);
        let frameworks: Vec<&str> = ORM_PATTERNS.iter().map(|p| p.framework).collect();
        assert!(frameworks.contains(&"active_record"));
        assert!(frameworks.contains(&"django"));
        assert!(frameworks.contains(&"sqlalchemy"));
        assert!(frameworks.contains(&"hibernate"));
        assert!(frameworks.contains(&"ef_core"));
        assert!(frameworks.contains(&"prisma"));
        assert!(frameworks.contains(&"sequelize"));
        assert!(frameworks.contains(&"typeorm"));
    }

    #[test]
    fn test_confidence_computation() {
        let conf = compute_confidence("active_record", LoopType::Explicit);
        assert!(conf > 0.8);
        assert!(conf <= 1.0);

        let conf_lazy = compute_confidence("hibernate", LoopType::LazyLoad);
        assert!(conf_lazy > 0.5);
        assert!(conf_lazy < conf);
    }

    #[test]
    fn test_suggestion_generation() {
        let suggestion = generate_suggestion("django", LoopType::Iterator);
        assert!(suggestion.contains("prefetch_related"));

        let suggestion = generate_suggestion("active_record", LoopType::Explicit);
        assert!(suggestion.contains("includes"));

        let suggestion = generate_suggestion("sequelize", LoopType::Iterator);
        assert!(suggestion.contains("include"));
    }

    #[test]
    fn test_n_plus_one_type_variants() {
        assert_ne!(NPlusOneType::LoopQuery, NPlusOneType::GraphqlResolver);
        assert_ne!(NPlusOneType::LoopQuery, NPlusOneType::LazyLoadInLoop);
    }
}
