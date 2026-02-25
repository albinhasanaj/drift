use cortex_tokens::{TokenBudget, TokenCounter};

#[test]
fn count_empty_string_is_zero() {
    let counter = TokenCounter::default();
    assert_eq!(counter.count(""), 0);
}

#[test]
fn count_simple_text() {
    let counter = TokenCounter::default();
    let count = counter.count("hello world");
    assert!(count > 0, "non-empty text should have >0 tokens");
    assert!(
        count < 10,
        "hello world should be a few tokens, got {}",
        count
    );
}

#[test]
fn count_cached_equals_uncached() {
    let counter = TokenCounter::default();
    let text = "The quick brown fox jumps over the lazy dog";
    let uncached = counter.count(text);
    let cached = counter.count_cached(text);
    assert_eq!(uncached, cached, "cached and uncached counts must match");
}

#[test]
fn count_cached_is_consistent() {
    let counter = TokenCounter::default();
    let text = "consistent counting test";
    let first = counter.count_cached(text);
    let second = counter.count_cached(text);
    let third = counter.count_cached(text);
    assert_eq!(first, second);
    assert_eq!(second, third);
}

#[test]
fn cjk_characters_count_correctly() {
    let counter = TokenCounter::default();
    let count = counter.count("你好世界");
    // CJK characters typically tokenize to 4-6 tokens, not 1
    assert!(count >= 4, "CJK should be ≥4 tokens, got {}", count);
    assert!(count <= 8, "CJK should be ≤8 tokens, got {}", count);
}

#[test]
fn subadditivity_property() {
    let counter = TokenCounter::default();
    let a = "The quick brown fox";
    let b = " jumps over the lazy dog";
    let combined = format!("{}{}", a, b);

    let count_a = counter.count(a);
    let count_b = counter.count(b);
    let count_combined = counter.count(&combined);

    // Subadditivity: count(a+b) ≤ count(a) + count(b) + 1
    assert!(
        count_combined <= count_a + count_b + 1,
        "subadditivity violated: count({}) = {}, count({}) = {}, count(combined) = {}",
        a,
        count_a,
        b,
        count_b,
        count_combined
    );
}

#[test]
fn budget_fits_returns_true_when_within_budget() {
    let counter = TokenCounter::default();
    let budget = TokenBudget::new(&counter);
    assert!(budget.fits("hello", 100));
}

#[test]
fn budget_fits_returns_false_when_exceeds_budget() {
    let counter = TokenCounter::default();
    let budget = TokenBudget::new(&counter);
    // A very long text should exceed a budget of 1
    let long_text = "a ".repeat(1000);
    assert!(!budget.fits(&long_text, 1));
}

#[test]
fn budget_remaining_saturates_at_zero() {
    assert_eq!(TokenBudget::remaining(100, 50), 50);
    assert_eq!(TokenBudget::remaining(50, 100), 0); // saturating
    assert_eq!(TokenBudget::remaining(0, 0), 0);
}

#[test]
fn budget_allocate_distributes_tokens() {
    let counter = TokenCounter::default();
    let budget = TokenBudget::new(&counter);

    let items: Vec<String> = vec![
        "short".into(),
        "medium length text".into(),
        "another item".into(),
    ];

    let allocations = budget.allocate(&items, 1000);
    // All items should fit in a 1000-token budget
    assert_eq!(allocations.len(), 3);

    // Total allocated should not exceed budget
    let total: usize = allocations.iter().map(|a| a.tokens).sum();
    assert!(total <= 1000);
}

#[test]
fn budget_allocate_respects_budget_limit() {
    let counter = TokenCounter::default();
    let budget = TokenBudget::new(&counter);

    let items: Vec<String> = vec![
        "a ".repeat(500), // ~500 tokens
        "b ".repeat(500), // ~500 tokens
        "c ".repeat(500), // ~500 tokens
    ];

    // Budget of 100 — should only fit a fraction
    let allocations = budget.allocate(&items, 100);
    let total: usize = allocations.iter().map(|a| a.tokens).sum();
    assert!(total <= 100, "total {} should be ≤ 100", total);
}

#[test]
fn various_text_types_count_correctly() {
    let counter = TokenCounter::default();

    // Code
    let code_count = counter.count("fn main() { println!(\"hello\"); }");
    assert!(code_count > 0);

    // Markdown
    let md_count = counter.count("# Heading\n\n- item 1\n- item 2");
    assert!(md_count > 0);

    // JSON
    let json_count = counter.count(r#"{"key": "value", "num": 42}"#);
    assert!(json_count > 0);

    // Unicode
    let emoji_count = counter.count("🚀🔥💻");
    assert!(emoji_count > 0);
}
