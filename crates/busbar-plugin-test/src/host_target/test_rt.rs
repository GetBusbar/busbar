// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The one runtime the test facade's kind-suite harness builds. It lives under `host_target/`, the
//! directory the R40 source rule exempts for the facade (it may not depend on `busbar-kernel` in
//! its shipped code, so it cannot build through `busbar_kernel::rt`). The crate is never shipped.

use std::future::Future;

/// A current-thread runtime with every driver enabled, owned by one harness.
pub(crate) struct TestRuntime(tokio::runtime::Runtime);

impl TestRuntime {
    pub(crate) fn new() -> std::io::Result<Self> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map(Self)
    }

    pub(crate) fn block_on<F: Future>(&self, future: F) -> F::Output {
        self.0.block_on(future)
    }
}
