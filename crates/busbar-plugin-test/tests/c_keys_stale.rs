// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-KEYS-STALE: raw plugin answers and the kernel-owned single-flight refresh gate.

use super::c_verdict_cache::{cx, join_all, Answer, Fake};
use busbar_kernel::plane_grants::KeyRefresh;
use busbar_plugin_abi::auth::KEYS_STALE;
use busbar_plugin_abi::host_side::scrub::Scrub;
use busbar_plugin_loader::adapters::auth::verify_refusal;
use busbar_ports::auth::VerifyAnswer;
use std::time::Duration;

#[tokio::test(flavor = "current_thread")]
async fn an_unknown_kid_refreshes_once() {
    assert!(matches!(
        verify_refusal(KEYS_STALE, "kid k9", &Scrub::new()),
        Ok(VerifyAnswer::KeysStale)
    ));
    let keys = KeyRefresh::new(Duration::from_secs(30));
    let port = Fake::new(0, Answer::KeysStale);
    let rounds = (0..100)
        .map(|_| {
            keys.refresh(&port, cx())
                .expect("joins the refresh in flight")
        })
        .collect();
    for done in join_all(rounds).await {
        assert_eq!(done, Ok(()));
    }
    assert_eq!(port.refreshes(), 1, "100 KEYS_STALE share one refresh");
    assert!(
        keys.refresh(&port, cx()).is_none(),
        "a second refresh inside the interval is declined"
    );
}
