// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use std::{
    future::Future as _,
    task::{Context, Poll, Waker},
};

#[test]
fn typed_builder_refusal_survives_an_async_cleanup_without_lending_thread_authority() {
    let mut future = Box::pin(scoped_async::<(), TxnError>(None, async {
        BUILD_AUTHORITY.with(|held| held.borrow_mut().refusal = Some(TxnError::Forbidden));
        let mut first = true;
        std::future::poll_fn(move |_| {
            if std::mem::take(&mut first) {
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        })
        .await;
        Err(TxnError::Validation(
            "a failed builder finished its cleanup".into(),
        ))
    }));
    let mut context = Context::from_waker(Waker::noop());
    assert!(future.as_mut().poll(&mut context).is_pending());
    assert!(BUILD_AUTHORITY.with(|held| held.borrow().refusal.is_none()));
    assert!(matches!(
        future.as_mut().poll(&mut context),
        Poll::Ready(Err(TxnError::Forbidden))
    ));
    assert!(BUILD_AUTHORITY.with(|held| held.borrow().refusal.is_none()));
}

/// SECRET-SHORTHAND-BOOT F10 (R12 at the digest): `plugins.fetch` is part of the security digest.
/// A candidate that only adds a fetch URL is a security change, so a caller without full-operator
/// authority is refused before the build fetches anything.
#[test]
fn a_plugins_fetch_change_is_security_relevant() {
    let deploy: super::super::DeployCfg =
        serde_json::from_value(serde_json::json!({"providers": {}, "models": {}}))
            .expect("a minimal document reads");
    let cfg = super::super::resolve(&deploy, &std::collections::HashMap::new())
        .expect("a minimal document resolves");
    let plain = super::super::PluginsCfg::default();
    let fetching: super::super::PluginsCfg = serde_json::from_value(serde_json::json!({
        "fetch": [{"url": "https://plugins.example/fixture-plugin.tar.gz"}]
    }))
    .expect("a plugins block with one fetch entry reads");
    assert_ne!(
        root_digest(&cfg, &plain),
        root_digest(&cfg, &fetching),
        "adding a plugins.fetch entry must change the security digest"
    );
    let by_env: super::super::PluginsCfg = serde_json::from_value(serde_json::json!({
        "fetch": [{"env": "FIXTURE_PLUGIN_URL"}]
    }))
    .expect("a plugins block with one env fetch entry reads");
    assert_ne!(
        root_digest(&cfg, &plain),
        root_digest(&cfg, &by_env),
        "an env fetch entry changes the digest by its variable's name"
    );
}
