//! Phase G integration tests — harness file.
//! Discovers all tests in the integration/ subdirectory.

#[path = "integration/cloud_swap_test.rs"]
mod cloud_swap_test;

#[path = "integration/connection_leak_test.rs"]
mod connection_leak_test;

#[path = "integration/full_pipeline_test.rs"]
mod full_pipeline_test;

#[path = "integration/send_sync_test.rs"]
mod send_sync_test;
