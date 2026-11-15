// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Non-upstream retries: the one place a store, secret, auth, export, push, admin or probe retry is decided (IF §12.3). W0-ABI stub: frozen signatures, `todo!()` bodies; W1-K3 fills it.

// The backoff shape core already has (IF §12.3 round 33: every `RetryPolicy` schedule uses it). These names were
// `busbar_kernel::retry::*` before this module existed (`pub use busbar_contract::retry;`), and stay so.
pub use busbar_contract::retry::{spread, unit, Backoff, FLOOR};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetrySite {
    StoreRead,
    StoreScan,
    StoreCommit,
    StoreClock,
    SecretResolve,
    AuthOutbound,
    AuthRefresh,
    ExportDeliver(u32),
    PlaneAdmin,
    PlanePush,
    PlaneProbe,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Retry {
    Stop,
    After(std::time::Duration),
}
// W0-ABI: the `RetryPolicy` trait (`fn next(&self, site: RetrySite, attempt: u32, err: &PortError) -> Retry`, with
// its IF doc lines) names `PortError`, a busbar-plugin-loader type (IF §11.3); the kernel does not depend on the
// loader in wave 0. W1-K3 adds it with that dependency.
