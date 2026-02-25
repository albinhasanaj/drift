//! Multi-primitive detection — identifies functions wrapping multiple framework primitives.
//!
//! V1 breaks after the first primitive match per function. V2 records all matches,
//! enabling detection of composite wrappers like `useAuthForm()` that wrap both
//! `useState` and `useForm`.

use super::types::{Wrapper, WrapperCategory};
use rustc_hash::FxHashMap;

/// Result of multi-primitive analysis for a single wrapper.
#[derive(Debug, Clone)]
pub struct MultiPrimitiveInfo {
    /// The wrapper function name.
    pub name: String,
    /// All wrapped primitives.
    pub primitives: Vec<String>,
    /// Primary category (most specific non-Other match).
    pub primary_category: WrapperCategory,
    /// Secondary categories from additional primitives.
    pub secondary_categories: Vec<WrapperCategory>,
    /// Whether this is a composite wrapper (wraps 2+ distinct primitives).
    pub is_composite: bool,
    /// Composition pattern (e.g., "state+effect", "fetch+cache").
    pub composition_pattern: String,
}

/// Known composition patterns — common multi-primitive combinations.
static COMPOSITION_PATTERNS: &[(&[&str], &str)] = &[
    (&["useState", "useEffect"], "state+effect"),
    (&["useState", "useCallback"], "state+callback"),
    (&["useState", "useReducer"], "state+reducer"),
    (&["useQuery", "useMutation"], "query+mutation"),
    (&["useState", "useForm"], "state+form"),
    (&["useEffect", "useRef"], "effect+ref"),
    (&["ref", "watch"], "reactive+watch"),
    (&["ref", "computed"], "reactive+computed"),
    (&["createSignal", "createEffect"], "signal+effect"),
    (&["fetch", "useState"], "fetch+state"),
    (&["useMemo", "useCallback"], "memo+callback"),
];

/// Analyze a wrapper for multi-primitive composition patterns.
pub fn analyze_multi_primitive(wrapper: &Wrapper) -> MultiPrimitiveInfo {
    let primitives = &wrapper.wrapped_primitives;
    let is_composite = primitives.len() > 1;

    // Determine composition pattern
    let composition_pattern = if is_composite {
        detect_composition_pattern(primitives)
    } else {
        "single".to_string()
    };

    // Collect secondary categories (categories from non-primary primitives)
    let secondary_categories = if is_composite {
        collect_secondary_categories(wrapper)
    } else {
        Vec::new()
    };

    MultiPrimitiveInfo {
        name: wrapper.name.clone(),
        primitives: primitives.clone(),
        primary_category: wrapper.category,
        secondary_categories,
        is_composite,
        composition_pattern,
    }
}

/// Detect known composition patterns from a set of primitives.
fn detect_composition_pattern(primitives: &[String]) -> String {
    for (pattern_prims, pattern_name) in COMPOSITION_PATTERNS {
        let all_present = pattern_prims.iter().all(|p| {
            primitives.iter().any(|wp| wp.contains(p))
        });
        if all_present {
            return pattern_name.to_string();
        }
    }

    // Fallback: join primitive names with "+"
    if primitives.len() <= 3 {
        primitives.join("+")
    } else {
        format!("{}+{}_more", primitives[0], primitives.len() - 1)
    }
}

/// Collect secondary categories from a multi-primitive wrapper.
fn collect_secondary_categories(wrapper: &Wrapper) -> Vec<WrapperCategory> {
    // We don't have per-primitive category info in the Wrapper struct,
    // so we infer from primitive names using known mappings.
    let mut categories = Vec::new();
    let category_map = build_primitive_category_map();

    for prim in &wrapper.wrapped_primitives {
        if let Some(&cat) = category_map.get(prim.as_str()) {
            if cat != wrapper.category && !categories.contains(&cat) {
                categories.push(cat);
            }
        }
    }

    categories
}

/// Build a quick lookup from primitive name to category.
fn build_primitive_category_map() -> FxHashMap<&'static str, WrapperCategory> {
    let mut map = FxHashMap::default();

    // State management
    for name in &["useState", "useReducer", "useContext", "useRef",
                   "ref", "reactive", "computed", "watch", "watchEffect",
                   "provide", "inject", "useStore", "writable", "readable",
                   "derived", "createSignal", "useSyncExternalStore",
                   "useTransition", "useDeferredValue"] {
        map.insert(*name, WrapperCategory::StateManagement);
    }

    // Data fetching
    for name in &["useEffect", "useSWR", "useSWRMutation", "useSWRInfinite",
                   "useQuery", "useMutation", "useInfiniteQuery",
                   "useSuspenseQuery", "createEffect", "createResource"] {
        map.insert(*name, WrapperCategory::DataFetching);
    }

    // Form handling
    for name in &["useForm", "useFormContext", "useFieldArray", "useFormik",
                   "FormBuilder"] {
        map.insert(*name, WrapperCategory::FormHandling);
    }

    // Caching
    for name in &["useMemo", "useCallback", "createMemo"] {
        map.insert(*name, WrapperCategory::Caching);
    }

    // Routing
    for name in &["useRouter", "usePathname", "useSearchParams",
                   "useNavigate", "useParams", "useLocation",
                   "useRoute", "ActivatedRoute", "Router"] {
        map.insert(*name, WrapperCategory::Routing);
    }

    // Animation
    for name in &["useSpring", "useTrail", "useAnimate", "motion"] {
        map.insert(*name, WrapperCategory::Animation);
    }

    // Internationalization
    for name in &["useTranslation", "useIntl"] {
        map.insert(*name, WrapperCategory::Internationalization);
    }

    // Error boundary
    for name in &["ErrorBoundary", "componentDidCatch"] {
        map.insert(*name, WrapperCategory::ErrorBoundary);
    }

    // API client
    for name in &["fetch", "axios.create", "axios.get", "axios.post",
                   "HttpClient"] {
        map.insert(*name, WrapperCategory::ApiClient);
    }

    // Logging
    for name in &["console.log", "console.error", "console.warn",
                   "winston.createLogger", "pino"] {
        map.insert(*name, WrapperCategory::Logging);
    }

    // Middleware
    for name in &["express.json", "express.urlencoded", "express.static",
                   "cors", "rateLimit"] {
        map.insert(*name, WrapperCategory::Middleware);
    }

    // Authentication
    for name in &["helmet", "passport.authenticate"] {
        map.insert(*name, WrapperCategory::Authentication);
    }

    map
}

/// Compute a confidence boost for multi-primitive wrappers.
/// Composite wrappers that match known patterns get a small boost.
pub fn multi_primitive_confidence_boost(wrapper: &Wrapper) -> f64 {
    if wrapper.wrapped_primitives.len() <= 1 {
        return 0.0;
    }

    let pattern = detect_composition_pattern(&wrapper.wrapped_primitives);

    // Known patterns get a boost
    let is_known = COMPOSITION_PATTERNS.iter().any(|(_, name)| *name == pattern);
    if is_known {
        0.05
    } else if wrapper.wrapped_primitives.len() <= 3 {
        0.02 // Small boost for reasonable composition
    } else {
        -0.05 // Penalty for overly complex wrappers
    }
}
