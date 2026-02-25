//! Transport layer: HTTP client with retry/backoff and versioned wire protocol.

pub mod http_client;
pub mod protocol;

pub use http_client::{HttpClient, HttpClientConfig};
pub use protocol::{
    CloudRequest, CloudResponse, MemoryPayload, PullResponse, PushResponse, SyncBatch,
    PROTOCOL_VERSION,
};
