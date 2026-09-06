// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the warn-capture fixture's interest handling (`testkit/warn_capture.rs`).

use crate::testkit::warn_capture::WarnCapture;

/// ONE callsite, fired twice — once with nobody listening, once under a capture. Both fires must be
/// the SAME callsite for this to be a statement about interest caching rather than about two
/// unrelated events.
fn fire() {
    tracing::warn!("a warn a later capture must still be able to see");
}

/// THE PRECONDITION the capture depends on. `tracing` caches each callsite's interest
/// process-globally, and with no subscriber installed anywhere the process's own answer to "is
/// anyone interested in a WARN" is NO — so a callsite first touched in that state can be cached
/// off, and no later thread-local capture can turn it back on. Building a capture therefore
/// installs a bare global registry once, and the process answers yes from then on.
#[test]
fn building_a_capture_leaves_the_process_interested_in_warns() {
    let _cap = WarnCapture::default();
    assert!(
        tracing::level_filters::LevelFilter::current() >= tracing::Level::WARN,
        "after a capture exists the process must be interested in WARN callsites, not OFF — \
         otherwise a callsite touched outside a capture can be cached off for every later test"
    );
}

/// And the behaviour that precondition buys: a callsite touched with nobody listening is still
/// visible to a capture that fires it afterwards.
#[test]
fn a_warn_fired_without_a_subscriber_does_not_blind_a_later_capture() {
    use tracing_subscriber::layer::SubscriberExt as _;

    // Nobody listening. Before the constructor forced interest on, this is where a callsite could
    // be cached off for the rest of the process.
    fire();

    let cap = WarnCapture::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());
    tracing::subscriber::with_default(subscriber, fire);

    assert!(
        cap.contains("a warn a later capture must still be able to see"),
        "the capture must observe a callsite an earlier listener-less fire touched; captured: {:?}",
        cap.messages()
    );
}
