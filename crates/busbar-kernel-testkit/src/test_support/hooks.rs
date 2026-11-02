// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel::config::HookCfg;
use busbar_kernel::hooks::{resolve_transport_for_test, transport_publication_for_test, HookEnv};

pub async fn await_transport_published(name: &str, hook: &HookCfg, env: &HookEnv) -> bool {
    const ATTEMPTS: usize = 24;

    const HARD_FAILURES: usize = 3;
    if transport_publication_for_test(name, hook, env).is_none() {
        return false;
    }
    let mut failed = 0usize;
    for _ in 0..ATTEMPTS {
        if transport_publication_for_test(name, hook, env).is_some_and(|(published, _)| published) {
            return true;
        }
        if resolve_transport_for_test(name, hook, env, 0).await {
            return transport_publication_for_test(name, hook, env)
                .is_some_and(|(published, _)| published);
        }

        if !transport_publication_for_test(name, hook, env).is_some_and(|(_, in_flight)| in_flight)
        {
            failed += 1;
            if failed >= HARD_FAILURES {
                return false;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }
    panic!(
        "the loader never published a transport for hook '{name}' after {ATTEMPTS} resolve \
         attempts; that is a HANG in plugin resolution, not a slow machine"
    );
}
