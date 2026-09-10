// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What the root's per-unit context is, proved against the real arena and the real arrival.

use super::*;

use busbar_contract::{transport::surface::Bar, ARENA_BYTES};

/// One arrival's facts, in the order a mount publishes them: reserved keys first.
const FACTS: &[(&str, &str)] = &[
    ("path", "/a2a"),
    ("method", "POST"),
    ("peer", "203.0.113.7:51000"),
    // A capture the declaration happened to name the same as a reserved key. It is published, and
    // it is never the answer, which is the property the ordering exists for.
    ("path", "/somewhere-else"),
];

const CHAIN: &[&str] = &["tcp", "tls", "http"];

fn arrival<'a>(body: &'a [u8]) -> Arrival<'a> {
    Arrival {
        facts: FACTS,
        body,
        transport: "http",
        chain: CHAIN,
        operation: None,
        bar: Bar::Credential,
    }
}

fn clock() -> Clock {
    Clock {
        unix_secs: 1_700_000_000,
        monotonic_nanos: 42,
    }
}

/// The context the root builds carries the arrival's own transport stack, and the mount's fact
/// ordering decides what a plane reads.
///
/// The duplicate `path` is the load-bearing part. A plane asking for the request target has to get
/// the target, not a capture that borrowed the name — a unit answered about the capture is a unit
/// answered about somewhere other than where it was sent.
#[test]
fn the_context_reads_the_arrival_and_reserved_keys_win() {
    let a = arrival(b"{}");
    with_ctx(&a, clock(), |ctx| {
        assert_eq!(ctx.transport().key(), "http");
        assert_eq!(ctx.transport().chain(), CHAIN);
        assert_eq!(ctx.transport().fact("path"), Some("/a2a"));
        assert_eq!(ctx.transport().fact("method"), Some("POST"));
        assert_eq!(ctx.transport().fact("sni"), None);
        assert_eq!(ctx.clock(), clock());
    });
}

/// The arena on the context is the kernel's own, at the contract's own ceiling — not a double.
///
/// This is the whole reason a production context could not be built before: every implementor of
/// `Arena` in the tree was a test's, and a plane handed one of those was
/// being handed something that leaked. What a plane allocates here comes out of 4 KiB that lives on
/// this call's stack, and asking for more than that is refused rather than served.
#[test]
fn the_arena_is_the_kernels_and_refuses_past_its_ceiling() {
    let a = arrival(b"{}");
    with_ctx(&a, clock(), |ctx| {
        let written = ctx
            .arena()
            .alloc_bytes(b"{\"jsonrpc\":\"2.0\"}")
            .expect("a short answer fits");
        assert_eq!(written.as_slice(), b"{\"jsonrpc\":\"2.0\"}");

        let over = vec![b'x'; ARENA_BYTES];
        let refused = ctx
            .arena()
            .alloc_bytes(&over)
            .expect_err("more than the whole arena is refused");
        assert_eq!(refused.wanted, ARENA_BYTES);
    });
}

/// Two arrivals get two arenas, and neither can read the other's bytes.
///
/// A pooled or process-wide arena would make this test pass by accident and fail under load; a
/// fresh space per call makes it a property of the type. The second call asking for the whole arena
/// is what proves the first call's allocation did not survive it.
#[test]
fn each_arrival_gets_its_own_space() {
    let a = arrival(b"{}");
    with_ctx(&a, clock(), |ctx| {
        ctx.arena()
            .alloc_bytes(&vec![b'a'; ARENA_BYTES])
            .expect("the whole arena fits, once");
    });
    with_ctx(&a, clock(), |ctx| {
        let zeroed = ctx
            .arena()
            .alloc_bytes(&vec![0u8; ARENA_BYTES])
            .expect("the next arrival has the whole arena again");
        assert!(
            zeroed.as_slice().iter().all(|b| *b == 0),
            "a second unit read the first unit's bytes"
        );
    });
}

/// A plugin's own configuration block is not something an arrival carries, and the context says so
/// rather than inventing one.
#[test]
fn the_config_view_answers_nothing_and_there_is_no_session() {
    let a = arrival(b"{}");
    with_ctx(&a, clock(), |ctx| {
        assert_eq!(ctx.config().get_str("endpoint"), None);
        assert_eq!(ctx.config().get_int("timeout_ms"), None);
        assert_eq!(ctx.config().get_bool("enabled"), None);
        assert!(
            ctx.session().is_none(),
            "a one-shot arrival opened no session"
        );
    });
}
