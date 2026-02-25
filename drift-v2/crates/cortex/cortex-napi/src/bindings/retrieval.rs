//! Retrieval bindings: retrieve, search, getContext.

use napi_derive::napi;

use cortex_core::models::RetrievalContext;
use cortex_core::traits::IRetriever;
use cortex_retrieval::RetrievalEngine;

use crate::conversions::{error_types, search_types};
use crate::runtime;

/// Retrieve memories matching a context, compressed to fit a token budget.
#[napi]
pub fn cortex_retrieval_retrieve(
    context_json: serde_json::Value,
    budget: Option<i64>,
) -> napi::Result<serde_json::Value> {
    let rt = runtime::get()?;
    let context = search_types::retrieval_context_from_json(context_json)?;
    let budget = budget.unwrap_or(4096) as usize;

    let engine = RetrievalEngine::new(&rt.storage, &rt.compression, rt.config.retrieval.clone());
    let results = engine
        .retrieve(&context, budget)
        .map_err(error_types::to_napi_error)?;
    search_types::compressed_memories_to_json(&results)
}

/// Search memories by query with embedding support.
#[napi]
pub fn cortex_retrieval_search(
    query: String,
    budget: Option<i64>,
) -> napi::Result<serde_json::Value> {
    let rt = runtime::get()?;
    let budget = budget.unwrap_or(4096) as usize;

    let context = RetrievalContext {
        focus: query.clone(),
        intent: None,
        active_files: vec![],
        budget,
        sent_ids: vec![],
    };

    // Try to get a query embedding for hybrid search.
    let mut embeddings = rt
        .embeddings
        .lock()
        .map_err(|e| napi::Error::from_reason(format!("Embedding lock poisoned: {e}")))?;
    let query_embedding = embeddings.embed_query_for_search(&query).ok();

    let engine = RetrievalEngine::new(&rt.storage, &rt.compression, rt.config.retrieval.clone());
    let results = engine
        .retrieve_with_embedding(&context, budget, query_embedding.as_deref())
        .map_err(error_types::to_napi_error)?;
    search_types::compressed_memories_to_json(&results)
}

/// Build a retrieval context from parameters.
#[napi]
pub fn cortex_retrieval_get_context(
    focus: String,
    active_files: Option<Vec<String>>,
    sent_ids: Option<Vec<String>>,
    budget: Option<i64>,
) -> napi::Result<serde_json::Value> {
    let context = RetrievalContext {
        focus,
        intent: None,
        active_files: active_files.unwrap_or_default(),
        budget: budget.unwrap_or(4096) as usize,
        sent_ids: sent_ids.unwrap_or_default(),
    };
    search_types::retrieval_context_to_json(&context)
}
