// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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
