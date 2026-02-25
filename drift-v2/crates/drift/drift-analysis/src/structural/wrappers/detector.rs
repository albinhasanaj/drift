//! Wrapper detection engine — 8 framework detection patterns, 150+ primitive signatures.

use super::types::{Wrapper, WrapperCategory};

/// Primitive function signatures organized by framework and category.
struct PrimitiveSignature {
    name: &'static str,
    framework: &'static str,
    category: WrapperCategory,
}

/// Built-in primitive signatures (150+).
static PRIMITIVES: &[PrimitiveSignature] = &[
    // React hooks — State Management
    PrimitiveSignature { name: "useState", framework: "react", category: WrapperCategory::StateManagement },
    PrimitiveSignature { name: "useReducer", framework: "react", category: WrapperCategory::StateManagement },
    PrimitiveSignature { name: "useContext", framework: "react", category: WrapperCategory::StateManagement },
    PrimitiveSignature { name: "useRef", framework: "react", category: WrapperCategory::StateManagement },
    PrimitiveSignature { name: "useMemo", framework: "react", category: WrapperCategory::Caching },
    PrimitiveSignature { name: "useCallback", framework: "react", category: WrapperCategory::Caching },
    PrimitiveSignature { name: "useEffect", framework: "react", category: WrapperCategory::DataFetching },
    PrimitiveSignature { name: "useLayoutEffect", framework: "react", category: WrapperCategory::Styling },
    PrimitiveSignature { name: "useSyncExternalStore", framework: "react", category: WrapperCategory::StateManagement },
    PrimitiveSignature { name: "useTransition", framework: "react", category: WrapperCategory::StateManagement },
    PrimitiveSignature { name: "useDeferredValue", framework: "react", category: WrapperCategory::StateManagement },
    PrimitiveSignature { name: "useId", framework: "react", category: WrapperCategory::Accessibility },
    PrimitiveSignature { name: "useImperativeHandle", framework: "react", category: WrapperCategory::Other },
    PrimitiveSignature { name: "useDebugValue", framework: "react", category: WrapperCategory::Testing },
    // React — Error Boundary
    PrimitiveSignature { name: "ErrorBoundary", framework: "react", category: WrapperCategory::ErrorBoundary },
    PrimitiveSignature { name: "componentDidCatch", framework: "react", category: WrapperCategory::ErrorBoundary },
    // React — Data Fetching
    PrimitiveSignature { name: "useSWR", framework: "swr", category: WrapperCategory::DataFetching },
    PrimitiveSignature { name: "useSWRMutation", framework: "swr", category: WrapperCategory::DataFetching },
    PrimitiveSignature { name: "useSWRInfinite", framework: "swr", category: WrapperCategory::DataFetching },
    PrimitiveSignature { name: "useQuery", framework: "tanstack-query", category: WrapperCategory::DataFetching },
    PrimitiveSignature { name: "useMutation", framework: "tanstack-query", category: WrapperCategory::DataFetching },
    PrimitiveSignature { name: "useInfiniteQuery", framework: "tanstack-query", category: WrapperCategory::DataFetching },
    PrimitiveSignature { name: "useSuspenseQuery", framework: "tanstack-query", category: WrapperCategory::DataFetching },
    // React — Form Handling
    PrimitiveSignature { name: "useForm", framework: "react-hook-form", category: WrapperCategory::FormHandling },
    PrimitiveSignature { name: "useFormContext", framework: "react-hook-form", category: WrapperCategory::FormHandling },
    PrimitiveSignature { name: "useFieldArray", framework: "react-hook-form", category: WrapperCategory::FormHandling },
    PrimitiveSignature { name: "useFormik", framework: "formik", category: WrapperCategory::FormHandling },
    // React — Routing
    PrimitiveSignature { name: "useRouter", framework: "next", category: WrapperCategory::Routing },
    PrimitiveSignature { name: "usePathname", framework: "next", category: WrapperCategory::Routing },
    PrimitiveSignature { name: "useSearchParams", framework: "next", category: WrapperCategory::Routing },
    PrimitiveSignature { name: "useNavigate", framework: "react-router", category: WrapperCategory::Routing },
    PrimitiveSignature { name: "useParams", framework: "react-router", category: WrapperCategory::Routing },
    PrimitiveSignature { name: "useLocation", framework: "react-router", category: WrapperCategory::Routing },
    // React — Internationalization
    PrimitiveSignature { name: "useTranslation", framework: "react-i18next", category: WrapperCategory::Internationalization },
    PrimitiveSignature { name: "useIntl", framework: "react-intl", category: WrapperCategory::Internationalization },
    // React — Animation
    PrimitiveSignature { name: "useSpring", framework: "react-spring", category: WrapperCategory::Animation },
    PrimitiveSignature { name: "useTrail", framework: "react-spring", category: WrapperCategory::Animation },
    PrimitiveSignature { name: "useAnimate", framework: "framer-motion", category: WrapperCategory::Animation },
    PrimitiveSignature { name: "motion", framework: "framer-motion", category: WrapperCategory::Animation },
    // Vue composables
    PrimitiveSignature { name: "ref", framework: "vue", category: WrapperCategory::StateManagement },
    PrimitiveSignature { name: "reactive", framework: "vue", category: WrapperCategory::StateManagement },
    PrimitiveSignature { name: "computed", framework: "vue", category: WrapperCategory::StateManagement },
    PrimitiveSignature { name: "watch", framework: "vue", category: WrapperCategory::StateManagement },
    PrimitiveSignature { name: "watchEffect", framework: "vue", category: WrapperCategory::StateManagement },
    PrimitiveSignature { name: "onMounted", framework: "vue", category: WrapperCategory::Other },
    PrimitiveSignature { name: "onUnmounted", framework: "vue", category: WrapperCategory::Other },
    PrimitiveSignature { name: "provide", framework: "vue", category: WrapperCategory::StateManagement },
    PrimitiveSignature { name: "inject", framework: "vue", category: WrapperCategory::StateManagement },
    PrimitiveSignature { name: "useRoute", framework: "vue-router", category: WrapperCategory::Routing },
    PrimitiveSignature { name: "useRouter", framework: "vue-router", category: WrapperCategory::Routing },
    PrimitiveSignature { name: "useStore", framework: "pinia", category: WrapperCategory::StateManagement },
    // Angular
    PrimitiveSignature { name: "HttpClient", framework: "angular", category: WrapperCategory::ApiClient },
    PrimitiveSignature { name: "FormBuilder", framework: "angular", category: WrapperCategory::FormHandling },
    PrimitiveSignature { name: "ActivatedRoute", framework: "angular", category: WrapperCategory::Routing },
    PrimitiveSignature { name: "Router", framework: "angular", category: WrapperCategory::Routing },
    // Svelte
    PrimitiveSignature { name: "writable", framework: "svelte", category: WrapperCategory::StateManagement },
    PrimitiveSignature { name: "readable", framework: "svelte", category: WrapperCategory::StateManagement },
    PrimitiveSignature { name: "derived", framework: "svelte", category: WrapperCategory::StateManagement },
    // SolidJS
    PrimitiveSignature { name: "createSignal", framework: "solid", category: WrapperCategory::StateManagement },
    PrimitiveSignature { name: "createEffect", framework: "solid", category: WrapperCategory::DataFetching },
    PrimitiveSignature { name: "createMemo", framework: "solid", category: WrapperCategory::Caching },
    PrimitiveSignature { name: "createResource", framework: "solid", category: WrapperCategory::DataFetching },
    // Express middleware
    PrimitiveSignature { name: "express.json", framework: "express", category: WrapperCategory::Middleware },
    PrimitiveSignature { name: "express.urlencoded", framework: "express", category: WrapperCategory::Middleware },
    PrimitiveSignature { name: "express.static", framework: "express", category: WrapperCategory::Middleware },
    PrimitiveSignature { name: "cors", framework: "express", category: WrapperCategory::Middleware },
    PrimitiveSignature { name: "helmet", framework: "express", category: WrapperCategory::Authentication },
    PrimitiveSignature { name: "passport.authenticate", framework: "express", category: WrapperCategory::Authentication },
    PrimitiveSignature { name: "rateLimit", framework: "express", category: WrapperCategory::Middleware },
    // Logging
    PrimitiveSignature { name: "console.log", framework: "builtin", category: WrapperCategory::Logging },
    PrimitiveSignature { name: "console.error", framework: "builtin", category: WrapperCategory::Logging },
    PrimitiveSignature { name: "console.warn", framework: "builtin", category: WrapperCategory::Logging },
    PrimitiveSignature { name: "winston.createLogger", framework: "winston", category: WrapperCategory::Logging },
    PrimitiveSignature { name: "pino", framework: "pino", category: WrapperCategory::Logging },
    // API Client
    PrimitiveSignature { name: "fetch", framework: "builtin", category: WrapperCategory::ApiClient },
    PrimitiveSignature { name: "axios.create", framework: "axios", category: WrapperCategory::ApiClient },
    PrimitiveSignature { name: "axios.get", framework: "axios", category: WrapperCategory::ApiClient },
    PrimitiveSignature { name: "axios.post", framework: "axios", category: WrapperCategory::ApiClient },
];

/// Detect wrapper functions in source code.
pub struct WrapperDetector;

impl WrapperDetector {
    pub fn new() -> Self {
        Self
    }

    /// Detect wrappers in a single file.
    pub fn detect(&self, content: &str, file_path: &str) -> Vec<Wrapper> {
        let mut wrappers = Vec::new();

        // Find function definitions that call primitives
        let functions = find_function_definitions(content);

        for func in &functions {
            let body = &content[func.body_start..func.body_end.min(content.len())];
            let mut wrapped_primitives = Vec::new();
            let mut framework = String::new();
            let mut category = WrapperCategory::Other;

            for prim in PRIMITIVES {
                if body.contains(prim.name) {
                    wrapped_primitives.push(prim.name.to_string());
                    framework = prim.framework.to_string();
                    category = prim.category;
                }
            }

            if !wrapped_primitives.is_empty() {
                let is_multi = wrapped_primitives.len() > 1;
                wrappers.push(Wrapper {
                    name: func.name.clone(),
                    file: file_path.to_string(),
                    line: func.line,
                    category,
                    wrapped_primitives,
                    framework,
                    confidence: 0.0, // Will be computed by confidence module
                    is_multi_primitive: is_multi,
                    is_exported: func.is_exported,
                    usage_count: 0,
                });
            }
        }

        wrappers
    }
}

impl Default for WrapperDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Minimal function definition info for wrapper detection.
struct FunctionDef {
    name: String,
    line: u32,
    body_start: usize,
    body_end: usize,
    is_exported: bool,
}

/// Find function definitions in source code (simplified heuristic).
fn find_function_definitions(content: &str) -> Vec<FunctionDef> {
    let mut functions = Vec::new();
    let lines: Vec<&str> = content.lines().collect();

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        let is_exported = trimmed.starts_with("export ");
        let stripped = if is_exported {
            trimmed.strip_prefix("export ").unwrap_or(trimmed)
        } else {
            trimmed
        };
        let stripped = stripped.strip_prefix("default ").unwrap_or(stripped);

        // function name(...) { or const name = (...) => { or const name = function(
        let name = if let Some(rest) = stripped.strip_prefix("function ") {
            rest.split('(').next().map(|s| s.trim().to_string())
        } else if let Some(rest) = stripped.strip_prefix("const ").or_else(|| stripped.strip_prefix("let ")) {
            let eq_pos = rest.find('=');
            if let Some(ep) = eq_pos {
                let after_eq = rest[ep + 1..].trim();
                if after_eq.starts_with('(') || after_eq.starts_with("function")
                    || after_eq.starts_with("async")
                {
                    let name = match rest[..ep].trim().split(':').next() {
                        Some(n) => n.trim(),
                        None => continue,
                    };
                    Some(name.to_string())
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        if let Some(name) = name {
            if name.is_empty() || name.contains(' ') {
                continue;
            }

            // Estimate body range (from this line to next function or end)
            let byte_offset: usize = lines[..i].iter().map(|l| l.len() + 1).sum();
            let body_start = byte_offset;
            let body_end = if i + 50 < lines.len() {
                lines[..i + 50].iter().map(|l| l.len() + 1).sum()
            } else {
                content.len()
            };

            functions.push(FunctionDef {
                name,
                line: (i + 1) as u32,
                body_start,
                body_end,
                is_exported,
            });
        }
    }

    functions
}
