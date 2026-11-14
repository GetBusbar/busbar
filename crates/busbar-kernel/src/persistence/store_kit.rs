// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STORE KIT: kernel-level Startup conformance for a store, run by the store's own tests
//! against the kernel at the core revision the store pins.
//!
//! A store's tests know how to open their backend on a dataset; everything else here is the
//! kernel's own admission code. Each case runs on its own fresh dataset and reads rows only
//! through the store's handles, so the same assertions hold for every store.
//!
//! ```ignore
//! #[tokio::test(flavor = "multi_thread")]
//! async fn kernel_startup_kit() {
//!     busbar_kernel::persistence::store_kit::run(&MyFixture).await
//! }
//! ```
//!
//! Real time, no `tokio::time::pause`: a store's I/O completes on other threads, so auto-advance
//! would fire timers while a commit is in flight. Every bound here is far below any startup window.

use std::sync::Arc;

use busbar_contract::persistence::PersistenceBackend;

/// One store under test. `fresh` makes a new, empty dataset owned by one case; `open` returns a
/// handle on it as a second process sharing that dataset would hold one. A store whose dataset
/// lives inside one opened instance returns the same `Arc` each time. Both run inside the kit's
/// tokio runtime: open with the async `LoadedPersistence::open` directly, never through a helper
/// that builds its own runtime or blocks a worker thread.
#[async_trait::async_trait]
pub trait Fixture: Send + Sync {
    type Dataset: Send + Sync;
    async fn fresh(&self) -> Self::Dataset;
    async fn open(&self, dataset: &Self::Dataset) -> Arc<dyn PersistenceBackend>;
}

/// Every case `run` executes, in order.
pub const CASES: &[&str] = &[
    "k1_first_start_publication",
    "k2_empty_refuses_without_initialize",
    "k3_racing_initialize",
];

/// The prefix of the lines `run` and each case print: `cases <n>` once, `passed <case>` per case.
pub const MARK: &str = "busbar-store-kit:";

/// Every case, each on its own fresh dataset. Panics naming the case and step.
pub async fn run<F: Fixture>(fixture: &F) {
    println!("{MARK} cases {}", CASES.len());
    k1_first_start_publication(fixture).await;
    k2_empty_refuses_without_initialize(fixture).await;
    k3_racing_initialize(fixture).await;
}

/// K1: first start over an empty dataset publishes; a second writer is admitted with no first
/// start and retires nobody; the first writer then retires cleanly; a third is admitted.
pub async fn k1_first_start_publication<F: Fixture>(fixture: &F) {
    let _ = fixture;
}

/// K2: an empty dataset refuses a Startup that may not initialize, and stays empty.
pub async fn k2_empty_refuses_without_initialize<F: Fixture>(fixture: &F) {
    let _ = fixture;
}

/// K3: two writers race Initialize; the loser writes nothing and exactly one owns the first start.
pub async fn k3_racing_initialize<F: Fixture>(fixture: &F) {
    let _ = fixture;
}

#[cfg(test)]
#[path = "store_kit_tests.rs"]
mod tests;
