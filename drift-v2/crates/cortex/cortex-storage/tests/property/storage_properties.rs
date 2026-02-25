//! Property tests: insert→get roundtrip, bulk ops consistency.

use chrono::Utc;
use proptest::prelude::*;

use cortex_core::memory::types::*;
use cortex_core::memory::*;
use cortex_core::traits::IMemoryStorage;
use cortex_storage::StorageEngine;

fn make_memory_with_summary(id: &str, summary: &str) -> BaseMemory {
    BaseMemory {
        id: id.to_string(),
        memory_type: MemoryType::Core,
        content: TypedContent::Core(CoreContent {
            project_name: "prop test".to_string(),
            description: "testing".to_string(),
            metadata: serde_json::json!({}),
        }),
        summary: summary.to_string(),
        transaction_time: Utc::now(),
        valid_time: Utc::now(),
        valid_until: None,
        confidence: Confidence::new(0.9),
        importance: Importance::Normal,
        last_accessed: Utc::now(),
        access_count: 0,
        linked_patterns: vec![],
        linked_constraints: vec![],
        linked_files: vec![],
        linked_functions: vec![],
        tags: vec![],
        archived: false,
        superseded_by: None,
        supersedes: None,
        content_hash: "prop_hash".to_string(),
        namespace: Default::default(),
        source_agent: Default::default(),
    }
}

proptest! {
    #[test]
    fn prop_insert_get_roundtrip(
        summary in "[a-zA-Z0-9 ]{1,100}"
    ) {
        let engine = StorageEngine::open_in_memory().unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        let memory = make_memory_with_summary(&id, &summary);

        engine.create(&memory).unwrap();
        let retrieved = engine.get(&id).unwrap().unwrap();

        prop_assert_eq!(&retrieved.id, &id);
        prop_assert_eq!(&retrieved.summary, &summary);
        prop_assert_eq!(retrieved.memory_type, MemoryType::Core);
    }

    #[test]
    fn prop_bulk_insert_consistency(
        count in 1usize..20
    ) {
        let engine = StorageEngine::open_in_memory().unwrap();
        let memories: Vec<BaseMemory> = (0..count)
            .map(|i| make_memory_with_summary(
                &uuid::Uuid::new_v4().to_string(),
                &format!("bulk {i}"),
            ))
            .collect();

        let inserted = engine.create_bulk(&memories).unwrap();
        prop_assert_eq!(inserted, count);

        let ids: Vec<String> = memories.iter().map(|m| m.id.clone()).collect();
        let retrieved = engine.get_bulk(&ids).unwrap();
        prop_assert_eq!(retrieved.len(), count);
    }
}
