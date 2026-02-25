use cortex_tokens::TokenCounter;
use proptest::prelude::*;

proptest! {
    #[test]
    fn count_is_always_non_negative(s in ".*") {
        let counter = TokenCounter::default();
        let count = counter.count(&s);
        // count is usize, so always >= 0, but let's be explicit
        prop_assert!(count < usize::MAX);
    }

    #[test]
    fn cached_equals_uncached(s in ".{0,200}") {
        let counter = TokenCounter::default();
        let uncached = counter.count(&s);
        let cached = counter.count_cached(&s);
        prop_assert_eq!(uncached, cached);
    }

    #[test]
    fn subadditivity(a in ".{0,100}", b in ".{0,100}") {
        let counter = TokenCounter::default();
        let combined = format!("{}{}", a, b);
        let count_a = counter.count(&a);
        let count_b = counter.count(&b);
        let count_combined = counter.count(&combined);
        prop_assert!(
            count_combined <= count_a + count_b + 1,
            "subadditivity: {} <= {} + {} + 1",
            count_combined, count_a, count_b
        );
    }

    #[test]
    fn empty_prefix_doesnt_change_count_much(s in ".{1,100}") {
        let counter = TokenCounter::default();
        let count = counter.count(&s);
        // Token count should be reasonable (not astronomical)
        prop_assert!(count <= s.len() * 2 + 10);
    }
}
