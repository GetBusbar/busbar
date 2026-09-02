// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOT-FUTURE SIZE TRIPWIRE — the request path is one nested async state machine, and every
//! byte of it is memcpy traffic at await-boundary state transitions (the w7 flame profile
//! attributes ~1.3% of self-time to memcpy under the route/dispatch/forward polls alone). This
//! probe pins the size of the outermost forward future so a change that quietly balloons the
//! state machine (a big local held across an await, an inline array where a box belongs) turns
//! CI red instead of shaving throughput invisibly. Re-baseline DOWNWARD freely; raise only with
//! a written reason in the same commit.

/// Committed bound: measured 3,352 bytes after the wave-8a shrink (was 5,152 when this tripwire
/// landed — the cold policy-decision and buffered cross-protocol-translate arms are boxed off the
/// union, the `first_hop_v` rebind slot is gone, and the two wrapper layers no longer double-store
/// their parameters), +448 headroom for legitimate small growth. Re-baseline DOWNWARD freely.
const FORWARD_FUTURE_MAX_BYTES: usize = 3_800;

#[test]
fn forward_future_size_is_pinned() {
    crate::testkit::install_test_seams();
    let app = crate::test_support::TestApp::new()
        .lane(crate::test_support::LaneSpec::new(
            "gpt-4o",
            crate::proto_codec::PROTO_OPENAI,
            "http://127.0.0.1:1",
        ))
        .pool("", &[(0, 1)])
        .build();
    // App-retype WEDGE 3: measure the PRODUCTION outermost forward future — `forward_with_pool_parsed`,
    // the entry the ingress hot path (`native_ingress::drive`) calls directly. The pre-flip probe used
    // the `forward_with_pool` bytes wrapper as a proxy, but that wrapper is now TEST-ONLY and mints the
    // neutral `host`/`rt` (extra owned Arcs + an async layer) the production path threads in from the
    // arrival — measuring it would pin test-only mint overhead, not the hot future. `host`/`rt` are
    // resolved here (as the arrival does) and BORROWED into the future, exactly as production threads
    // them; the bound is UNCHANGED.
    let (host, rt) = crate::engine::test_host_rt(&app);
    let fut = crate::engine::forward_with_pool_parsed(
        &host,
        &rt,
        vec![],
        bytes::Bytes::new(),
        None,
        crate::engine::APPLICATION_JSON,
        None,
        None,
        "",
        None,
        "openai",
        crate::test_support::CHAT,
        None,
    );
    let size = std::mem::size_of_val(&fut);
    eprintln!("[future-size] forward_with_pool = {size} bytes");
    assert!(
        size <= FORWARD_FUTURE_MAX_BYTES,
        "the forward future grew to {size} bytes (bound {FORWARD_FUTURE_MAX_BYTES}): a large \
         local is being held across an await. Shrink it (scope it, box it) rather than raising \
         the bound."
    );
    drop(fut);
}
