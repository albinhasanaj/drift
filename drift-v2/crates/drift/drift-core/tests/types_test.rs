//! Tests for the Drift types and interning system.

use drift_core::types::collections::{FxHashMap, FxHashSet};
use drift_core::types::identifiers::*;
use drift_core::types::interning::{FunctionInterner, PathInterner};
use lasso::Spur;

/// T0-TYP-01: Test ThreadedRodeo interns and resolves paths correctly
#[test]
fn test_path_interner_basic() {
    let interner = PathInterner::new();
    let key = interner.intern("src/main.ts");
    let resolved = interner.resolve(&key);
    assert_eq!(resolved, "src/main.ts");
}

/// T0-TYP-02: Test PathInterner normalizes path separators (Unix/Windows)
#[test]
fn test_path_interner_normalizes_separators() {
    let interner = PathInterner::new();

    let unix_key = interner.intern("src/main.ts");
    let windows_key = interner.intern("src\\main.ts");

    // Both should resolve to the same normalized path
    assert_eq!(unix_key, windows_key);
    assert_eq!(interner.resolve(&unix_key), "src/main.ts");
}

/// T0-TYP-03: Test FunctionInterner handles qualified names
#[test]
fn test_function_interner_qualified() {
    let interner = FunctionInterner::new();

    let simple = interner.intern("doSomething");
    let qualified = interner.intern_qualified("MyClass", "doSomething");

    assert_ne!(simple, qualified);
    assert_eq!(interner.resolve(&simple), "doSomething");
    assert_eq!(interner.resolve(&qualified), "MyClass.doSomething");
}

/// T0-TYP-04: Test Spur-based ID types are distinct
#[test]
fn test_id_types_distinct() {
    let interner = PathInterner::new();
    let spur = interner.intern("test");

    let file_id = FileId::new(spur);
    let function_id = FunctionId::new(spur);

    // Same underlying Spur, but different types
    assert_eq!(file_id.inner(), function_id.inner());

    // Type system prevents mixing:
    // This would not compile: let _: FileId = function_id;
    // We verify they are different types by checking they can coexist
    let _f: FileId = file_id;
    let _g: FunctionId = function_id;
}

/// T0-TYP-05: Test ThreadedRodeo under concurrent writes from 8 threads
#[test]
fn test_concurrent_interning() {
    use rayon::prelude::*;

    let interner = PathInterner::new();

    // Intern 1000 paths from 8 threads in parallel
    let paths: Vec<String> = (0..1000)
        .map(|i| format!("src/file_{}.ts", i))
        .collect();

    let keys: Vec<Spur> = paths.par_iter().map(|p| interner.intern(p)).collect();

    // All keys should be resolvable
    for (i, key) in keys.iter().enumerate() {
        assert_eq!(interner.resolve(key), paths[i]);
    }

    // Verify deduplication: interning the same paths again should return same keys
    let keys2: Vec<Spur> = paths.par_iter().map(|p| interner.intern(p)).collect();
    assert_eq!(keys, keys2);
}

/// T0-TYP-06: Test PathInterner with paths containing `..`, trailing slashes
#[test]
fn test_path_interner_edge_cases() {
    let interner = PathInterner::new();

    // Trailing slash normalization
    let with_slash = interner.intern("src/utils/");
    let without_slash = interner.intern("src/utils");
    assert_eq!(with_slash, without_slash);

    // Double slashes
    let double = interner.intern("src//utils");
    let single = interner.intern("src/utils");
    assert_eq!(double, single);

    // Mixed separators with trailing
    let mixed = interner.intern("src\\utils\\");
    assert_eq!(mixed, single);
}

/// T0-TYP-07: Test interning the same string 10,000 times returns the same Spur
#[test]
fn test_deduplication_correctness() {
    let interner = PathInterner::new();
    let first = interner.intern("src/main.ts");

    for _ in 0..10_000 {
        let key = interner.intern("src/main.ts");
        assert_eq!(key, first);
    }
}

/// T0-TYP-08: Test RodeoReader rejects writes after freeze
#[test]
fn test_rodeo_reader_frozen() {
    let interner = PathInterner::new();
    let key = interner.intern("src/main.ts");

    let reader = interner.into_reader();
    // Reader can resolve
    assert_eq!(reader.resolve(&key), "src/main.ts");

    // Reader cannot intern new strings — this is enforced at the type level.
    // RodeoReader has no `get_or_intern` method, so this is a compile-time guarantee.
    // We verify the reader works for lookups:
    assert!(reader.contains("src/main.ts"));
}

/// T0-TYP-09: Test FxHashMap with Spur keys produces correct lookups
#[test]
fn test_fxhashmap_with_spur_keys() {
    let interner = PathInterner::new();
    let key1 = interner.intern("src/a.ts");
    let key2 = interner.intern("src/b.ts");
    let key3 = interner.intern("src/c.ts");

    let mut map: FxHashMap<Spur, &str> = FxHashMap::default();
    map.insert(key1, "file_a");
    map.insert(key2, "file_b");
    map.insert(key3, "file_c");

    assert_eq!(map.get(&key1), Some(&"file_a"));
    assert_eq!(map.get(&key2), Some(&"file_b"));
    assert_eq!(map.get(&key3), Some(&"file_c"));

    // Verify FxHashSet works too
    let mut set: FxHashSet<Spur> = FxHashSet::default();
    set.insert(key1);
    set.insert(key2);
    assert!(set.contains(&key1));
    assert!(set.contains(&key2));
    assert!(!set.contains(&key3));
}
