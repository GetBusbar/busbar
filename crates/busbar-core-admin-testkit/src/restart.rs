// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Restart fixture orchestration, shared with the admin service's own unit-test binary.

/// Force the real restart handler to see no supervisor on this thread while `f` runs.
/// Restores the prior override when the future completes, panics, or is dropped. Like the
/// underlying thread-local seam, this requires a current-thread executor.
pub async fn with_forced_unsupervised<F, Fut, T>(f: F) -> T
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = T>,
{
    struct Restore(bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            busbar_core_admin::restart::swap_forced_unsupervised(self.0);
        }
    }
    let _restore = Restore(busbar_core_admin::restart::swap_forced_unsupervised(true));
    f().await
}
