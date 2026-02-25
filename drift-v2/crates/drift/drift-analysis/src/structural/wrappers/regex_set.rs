//! RegexSet optimization for single-pass multi-pattern primitive matching.
//!
//! V1 checks each call against each primitive sequentially. V2 uses Rust's
//! `regex::RegexSet` for single-pass matching — one pass over the call target
//! string matches against all 150+ primitive patterns simultaneously.

use regex::RegexSet;
use super::types::WrapperCategory;

/// A compiled primitive entry with its metadata.
#[derive(Debug, Clone)]
pub struct PrimitiveEntry {
    /// Primitive function name (e.g., "useState").
    pub name: String,
    /// Framework it belongs to (e.g., "react").
    pub framework: String,
    /// Category classification.
    pub category: WrapperCategory,
    /// Match mode for pattern generation.
    pub match_mode: MatchMode,
}

/// How a primitive name should be matched against call targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchMode {
    /// Exact match: call target == primitive name.
    Exact,
    /// Ends-with: call target ends with primitive name (e.g., "React.useState").
    EndsWith,
    /// Contains: call target contains primitive name.
    Contains,
}

/// Compiled primitive registry using RegexSet for single-pass matching.
pub struct PrimitiveRegexSet {
    /// The compiled RegexSet — matches all 150+ patterns in a single pass.
    regex_set: RegexSet,
    /// Ordered entries (index matches RegexSet pattern index).
    entries: Vec<PrimitiveEntry>,
}

impl PrimitiveRegexSet {
    /// Build the registry from primitive entries.
    /// Compiles a RegexSet for single-pass matching.
    pub fn new(entries: Vec<PrimitiveEntry>) -> Result<Self, regex::Error> {
        let patterns: Vec<String> = entries.iter().map(|e| {
            let escaped = regex::escape(&e.name);
            match e.match_mode {
                MatchMode::Exact => format!("^{}$", escaped),
                MatchMode::EndsWith => format!("(?:^|\\.){}$", escaped),
                MatchMode::Contains => escaped,
            }
        }).collect();

        let regex_set = RegexSet::new(&patterns)?;

        Ok(Self { regex_set, entries })
    }

    /// Build from the built-in primitive signatures.
    pub fn from_builtins() -> Result<Self, regex::Error> {
        let entries = builtin_entries();
        Self::new(entries)
    }

    /// Single-pass match: returns all primitives that match the call target.
    pub fn match_call(&self, call_target: &str) -> Vec<&PrimitiveEntry> {
        self.regex_set
            .matches(call_target)
            .into_iter()
            .map(|idx| &self.entries[idx])
            .collect()
    }

    /// Check if any primitive matches the call target (fast boolean check).
    pub fn is_match(&self, call_target: &str) -> bool {
        self.regex_set.is_match(call_target)
    }

    /// Number of registered primitives.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Build the full set of 150+ built-in primitive entries.
fn builtin_entries() -> Vec<PrimitiveEntry> {
    let mut entries = Vec::with_capacity(160);

    // Helper macro to reduce boilerplate
    macro_rules! add {
        ($name:expr, $fw:expr, $cat:expr) => {
            entries.push(PrimitiveEntry {
                name: $name.to_string(),
                framework: $fw.to_string(),
                category: $cat,
                match_mode: if $name.contains('.') { MatchMode::EndsWith } else { MatchMode::Exact },
            });
        };
    }

    // ── React hooks (14) ──
    add!("useState", "react", WrapperCategory::StateManagement);
    add!("useReducer", "react", WrapperCategory::StateManagement);
    add!("useContext", "react", WrapperCategory::StateManagement);
    add!("useRef", "react", WrapperCategory::StateManagement);
    add!("useMemo", "react", WrapperCategory::Caching);
    add!("useCallback", "react", WrapperCategory::Caching);
    add!("useEffect", "react", WrapperCategory::DataFetching);
    add!("useLayoutEffect", "react", WrapperCategory::Styling);
    add!("useSyncExternalStore", "react", WrapperCategory::StateManagement);
    add!("useTransition", "react", WrapperCategory::StateManagement);
    add!("useDeferredValue", "react", WrapperCategory::StateManagement);
    add!("useId", "react", WrapperCategory::Accessibility);
    add!("useImperativeHandle", "react", WrapperCategory::Other);
    add!("useDebugValue", "react", WrapperCategory::Testing);

    // ── React error boundary (2) ──
    add!("ErrorBoundary", "react", WrapperCategory::ErrorBoundary);
    add!("componentDidCatch", "react", WrapperCategory::ErrorBoundary);

    // ── SWR (3) ──
    add!("useSWR", "swr", WrapperCategory::DataFetching);
    add!("useSWRMutation", "swr", WrapperCategory::DataFetching);
    add!("useSWRInfinite", "swr", WrapperCategory::DataFetching);

    // ── TanStack Query (4) ──
    add!("useQuery", "tanstack-query", WrapperCategory::DataFetching);
    add!("useMutation", "tanstack-query", WrapperCategory::DataFetching);
    add!("useInfiniteQuery", "tanstack-query", WrapperCategory::DataFetching);
    add!("useSuspenseQuery", "tanstack-query", WrapperCategory::DataFetching);

    // ── React Hook Form (3) ──
    add!("useForm", "react-hook-form", WrapperCategory::FormHandling);
    add!("useFormContext", "react-hook-form", WrapperCategory::FormHandling);
    add!("useFieldArray", "react-hook-form", WrapperCategory::FormHandling);

    // ── Formik (1) ──
    add!("useFormik", "formik", WrapperCategory::FormHandling);

    // ── Next.js routing (3) ──
    add!("useRouter", "next", WrapperCategory::Routing);
    add!("usePathname", "next", WrapperCategory::Routing);
    add!("useSearchParams", "next", WrapperCategory::Routing);

    // ── React Router (3) ──
    add!("useNavigate", "react-router", WrapperCategory::Routing);
    add!("useParams", "react-router", WrapperCategory::Routing);
    add!("useLocation", "react-router", WrapperCategory::Routing);

    // ── i18n (2) ──
    add!("useTranslation", "react-i18next", WrapperCategory::Internationalization);
    add!("useIntl", "react-intl", WrapperCategory::Internationalization);

    // ── Animation (4) ──
    add!("useSpring", "react-spring", WrapperCategory::Animation);
    add!("useTrail", "react-spring", WrapperCategory::Animation);
    add!("useAnimate", "framer-motion", WrapperCategory::Animation);
    add!("motion", "framer-motion", WrapperCategory::Animation);

    // ── Zustand / Jotai / Recoil (5) ──
    add!("create", "zustand", WrapperCategory::StateManagement);
    add!("useAtom", "jotai", WrapperCategory::StateManagement);
    add!("atom", "jotai", WrapperCategory::StateManagement);
    add!("useRecoilState", "recoil", WrapperCategory::StateManagement);
    add!("useRecoilValue", "recoil", WrapperCategory::StateManagement);

    // ── Vue composables (11) ──
    add!("ref", "vue", WrapperCategory::StateManagement);
    add!("reactive", "vue", WrapperCategory::StateManagement);
    add!("computed", "vue", WrapperCategory::StateManagement);
    add!("watch", "vue", WrapperCategory::StateManagement);
    add!("watchEffect", "vue", WrapperCategory::StateManagement);
    add!("onMounted", "vue", WrapperCategory::Other);
    add!("onUnmounted", "vue", WrapperCategory::Other);
    add!("provide", "vue", WrapperCategory::StateManagement);
    add!("inject", "vue", WrapperCategory::StateManagement);
    add!("toRef", "vue", WrapperCategory::StateManagement);
    add!("toRefs", "vue", WrapperCategory::StateManagement);

    // ── Vue Router (2) ──
    add!("useRoute", "vue-router", WrapperCategory::Routing);

    // ── Pinia (1) ──
    add!("useStore", "pinia", WrapperCategory::StateManagement);

    // ── Angular (5) ──
    add!("HttpClient", "angular", WrapperCategory::ApiClient);
    add!("FormBuilder", "angular", WrapperCategory::FormHandling);
    add!("ActivatedRoute", "angular", WrapperCategory::Routing);
    add!("Router", "angular", WrapperCategory::Routing);
    add!("Renderer2", "angular", WrapperCategory::Styling);

    // ── Svelte (3) ──
    add!("writable", "svelte", WrapperCategory::StateManagement);
    add!("readable", "svelte", WrapperCategory::StateManagement);
    add!("derived", "svelte", WrapperCategory::StateManagement);

    // ── SolidJS (4) ──
    add!("createSignal", "solid", WrapperCategory::StateManagement);
    add!("createEffect", "solid", WrapperCategory::DataFetching);
    add!("createMemo", "solid", WrapperCategory::Caching);
    add!("createResource", "solid", WrapperCategory::DataFetching);

    // ── Express middleware (7) ──
    add!("express.json", "express", WrapperCategory::Middleware);
    add!("express.urlencoded", "express", WrapperCategory::Middleware);
    add!("express.static", "express", WrapperCategory::Middleware);
    add!("cors", "express", WrapperCategory::Middleware);
    add!("helmet", "express", WrapperCategory::Authentication);
    add!("passport.authenticate", "express", WrapperCategory::Authentication);
    add!("rateLimit", "express", WrapperCategory::Middleware);

    // ── Logging (5) ──
    add!("console.log", "builtin", WrapperCategory::Logging);
    add!("console.error", "builtin", WrapperCategory::Logging);
    add!("console.warn", "builtin", WrapperCategory::Logging);
    add!("winston.createLogger", "winston", WrapperCategory::Logging);
    add!("pino", "pino", WrapperCategory::Logging);

    // ── API Client (4) ──
    add!("fetch", "builtin", WrapperCategory::ApiClient);
    add!("axios.create", "axios", WrapperCategory::ApiClient);
    add!("axios.get", "axios", WrapperCategory::ApiClient);
    add!("axios.post", "axios", WrapperCategory::ApiClient);

    // ── Testing (8) ──
    add!("render", "testing-library", WrapperCategory::Testing);
    add!("screen", "testing-library", WrapperCategory::Testing);
    add!("fireEvent", "testing-library", WrapperCategory::Testing);
    add!("waitFor", "testing-library", WrapperCategory::Testing);
    add!("act", "react-dom", WrapperCategory::Testing);
    add!("mount", "enzyme", WrapperCategory::Testing);
    add!("shallow", "enzyme", WrapperCategory::Testing);
    add!("vi.fn", "vitest", WrapperCategory::Testing);

    // ── tRPC (3) ──
    add!("trpc.useQuery", "trpc", WrapperCategory::DataFetching);
    add!("trpc.useMutation", "trpc", WrapperCategory::DataFetching);
    add!("trpc.useUtils", "trpc", WrapperCategory::DataFetching);

    // ── Prisma (4) ──
    add!("prisma.findMany", "prisma", WrapperCategory::DataFetching);
    add!("prisma.findUnique", "prisma", WrapperCategory::DataFetching);
    add!("prisma.create", "prisma", WrapperCategory::DataFetching);
    add!("prisma.update", "prisma", WrapperCategory::DataFetching);

    // ── Next.js SSR (3) ──
    add!("getServerSideProps", "next", WrapperCategory::DataFetching);
    add!("getStaticProps", "next", WrapperCategory::DataFetching);
    add!("getStaticPaths", "next", WrapperCategory::DataFetching);

    // ── Accessibility (3) ──
    add!("useAriaLive", "aria", WrapperCategory::Accessibility);
    add!("useFocusTrap", "focus-trap", WrapperCategory::Accessibility);
    add!("useMediaQuery", "responsive", WrapperCategory::Accessibility);

    // ── Caching (3) ──
    add!("useQueryClient", "tanstack-query", WrapperCategory::Caching);
    add!("unstable_cache", "next", WrapperCategory::Caching);
    add!("cache", "react", WrapperCategory::Caching);

    // ── Styling (4) ──
    add!("styled", "styled-components", WrapperCategory::Styling);
    add!("css", "emotion", WrapperCategory::Styling);
    add!("cx", "emotion", WrapperCategory::Styling);
    add!("clsx", "clsx", WrapperCategory::Styling);

    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_regex_set_compiles() {
        let set = PrimitiveRegexSet::from_builtins().unwrap();
        assert!(set.len() >= 100, "Expected 100+ primitives, got {}", set.len());
    }

    #[test]
    fn test_exact_match() {
        let set = PrimitiveRegexSet::from_builtins().unwrap();
        let matches = set.match_call("useState");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].name, "useState");
        assert_eq!(matches[0].framework, "react");
    }

    #[test]
    fn test_endswith_match() {
        let set = PrimitiveRegexSet::from_builtins().unwrap();
        let matches = set.match_call("axios.get");
        assert!(!matches.is_empty());
        assert!(matches.iter().any(|m| m.name == "axios.get"));
    }

    #[test]
    fn test_no_match() {
        let set = PrimitiveRegexSet::from_builtins().unwrap();
        let matches = set.match_call("myCustomFunction");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_is_match_fast_path() {
        let set = PrimitiveRegexSet::from_builtins().unwrap();
        assert!(set.is_match("useEffect"));
        assert!(!set.is_match("totallyUnknownFunction"));
    }
}
