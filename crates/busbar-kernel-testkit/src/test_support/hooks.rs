// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Bounded fixture waits over the kernel's actual hook-resolution publication state.

use busbar_kernel::config::HookCfg;
use busbar_kernel::hooks::{resolve_transport_for_test, transport_publication_for_test, HookEnv};

/// Wait for actual publication using production resolve deadlines. Retry counts, transient-error
/// policy, and the hang detector are testkit concerns; the kernel supplies only real state/calls.
pub async fn await_transport_published(name: &str, hook: &HookCfg, env: &HookEnv) -> bool {
    /// Enough attempts that only a genuine hang exhausts them (each attempt is bounded by the
    /// production resolve deadline).
    const ATTEMPTS: usize = 24;
    /// How many FAILED loads (not timeouts — failures) are re-tried before `false` is believed.
    /// A failed load is deliberately NOT published by the production resolution claim precisely
    /// so the next caller retries it, and in production the next control-plane touch is that
    /// caller. Under parallel-suite load the first load can fail TRANSIENTLY — staging I/O or
    /// `dlopen` against an fd-starved, cache-thrashed host — and this helper used to convert that
    /// single transient failure into a permanent-looking `false`, flaking every "the loader must
    /// publish" assertion. Three failures in a row with the host given a beat to recover is an
    /// unloadable plugin; one is weather.
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
            // Resolved inside the deadline; `gate_transport_named` published it on the way through.
            return transport_publication_for_test(name, hook, env)
                .is_some_and(|(published, _)| published);
        }
        // `None` is two different things and only one of them is worth waiting for: a load still
        // running (the caller's deadline elapsed, the claim is still held) versus a load that
        // FAILED (the claim was dropped unpublished). The failed arm retries a bounded number of
        // times — see HARD_FAILURES above — before it is believed.
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
