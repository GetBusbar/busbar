// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOT-FUTURE SIZE TRIPWIRE — the request path is one nested async state machine, and every
//! byte of it is memcpy traffic at await-boundary state transitions (the w7 flame profile
//! attributes ~1.3% of self-time to memcpy under the route/dispatch/forward polls alone). This
//! probe pins the size of the outermost forward future so a change that quietly balloons the
//! state machine (a big local held across an await, an inline array where a box belongs) turns
//! CI red instead of shaving throughput invisibly. Re-baseline DOWNWARD freely; raise only with
//! a written reason in the same commit.

/// Committed bound: measured 5,152 bytes when this tripwire landed (pre-shrink), +448 headroom
/// for legitimate small growth. The shrink wave re-baselines this downward.
const FORWARD_FUTURE_MAX_BYTES: usize = 5_600;

#[test]
fn forward_future_size_is_pinned() {
    let app = crate::test_support::TestApp::new()
        .lane(crate::test_support::LaneSpec::new(
            "gpt-4o",
            crate::proto::Protocol::openai(),
            "http://127.0.0.1:1",
        ))
        .pool("", &[(0, 1)])
        .build();
    let fut = crate::proxy::forward_with_pool(
        &app,
        vec![],
        bytes::Bytes::new(),
        None,
        "",
        None,
        "openai",
        crate::handlers::CHAT,
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
