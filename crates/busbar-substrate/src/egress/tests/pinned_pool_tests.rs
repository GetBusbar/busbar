// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE UNIFIED EGRESS BACKEND'S OWN PROOFS: the pool keyed by the pinned address, and the resolver
//! that refuses a second lookup. Every plane's real-network transport is built on these two, so the
//! properties are asserted HERE once rather than re-proven per plane. The plane-level suites (the
//! a2a real-TLS / body-cap / zero-second-lookup harness) then exercise the same machinery end to end.

use super::engine::{build_client, EngineClient, EngineSpec};
use super::{PinnedClientPool, RefuseSecondLookup};
use std::net::SocketAddr;
use std::sync::Arc;

/// A host/address pair to key a pinned client on. No socket is opened — building a client does not
/// connect — so an arbitrary address is enough to exercise the pool.
fn addr(n: u16) -> SocketAddr {
    format!("127.0.0.1:{n}").parse().expect("a socket address")
}

/// Build a pinned ENGINE client for `addr`, to the production posture. Building does not connect,
/// so no network is touched.
fn build(host: &str, at: SocketAddr) -> EngineClient {
    build_client(&EngineSpec::pinned(
        Arc::from(host),
        at.ip(),
        None,
        Vec::new(),
    ))
    .expect("a built client")
}

/// A REPEATED destination reuses one client; a DISTINCT one builds a second. This is the whole point
/// of pooling by the pinned address — connection reuse to the already-judged target.
#[test]
fn the_pool_reuses_a_client_for_a_repeated_pinned_destination() {
    let pool = PinnedClientPool::with_capacity(64);
    let a = addr(8001);

    let _first = pool
        .client_for(("host.test".to_string(), a), || {
            Ok::<_, String>(build("host.test", a))
        })
        .expect("first build");
    let _again = pool
        .client_for(
            ("host.test".to_string(), a),
            || -> Result<EngineClient, String> {
                panic!("a repeated destination must NOT rebuild — the cached client is reused")
            },
        )
        .expect("cached hit");
    assert_eq!(pool.len(), 1, "one destination is one pooled client");

    let b = addr(8002);
    let _second = pool
        .client_for(("host.test".to_string(), b), || {
            Ok::<_, String>(build("host.test", b))
        })
        .expect("distinct build");
    assert_eq!(
        pool.len(),
        2,
        "a distinct pinned address is a distinct key, so it builds its own client"
    );
}

/// A rebinding resolver that answers a DIFFERENT address produces a DIFFERENT key, so the pool cannot
/// hand back a client pinned to the address that was never judged.
#[test]
fn a_different_pinned_address_for_the_same_host_is_a_different_pooled_client() {
    let pool = PinnedClientPool::with_capacity(64);
    let _one = pool
        .client_for(("host.test".to_string(), addr(9001)), || {
            Ok::<_, String>(build("host.test", addr(9001)))
        })
        .expect("build one");
    let _two = pool
        .client_for(("host.test".to_string(), addr(9002)), || {
            Ok::<_, String>(build("host.test", addr(9002)))
        })
        .expect("build two");
    assert_eq!(
        pool.len(),
        2,
        "same host, two judged addresses, two clients"
    );
}

/// The pool is BOUNDED: a destination whose DNS round-robins across many addresses cannot grow one
/// client per address forever. Over the cap, a whole entry is evicted.
#[test]
fn the_pool_is_bounded_and_evicts_over_capacity() {
    let pool = PinnedClientPool::with_capacity(2);
    for port in [7001u16, 7002, 7003] {
        let a = addr(port);
        let _c = pool
            .client_for(("host.test".to_string(), a), || {
                Ok::<_, String>(build("host.test", a))
            })
            .expect("build");
    }
    assert_eq!(pool.len(), 2, "the pool never exceeds its capacity");
}

/// The refusing resolver is REACHABLE, not decoration: a client asked to resolve gets an error that
/// names the invariant ("exactly once") and the name it was asked about. Proven by asking the
/// resolver directly, because in production the pin means the fetch path never reaches it — an
/// unreachable guard that has never executed is not a guard.
#[test]
fn the_refusing_resolver_names_the_invariant_and_the_name() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let err = rt.block_on(async {
        reqwest::dns::Resolve::resolve(
            &RefuseSecondLookup,
            "vendor.example".parse().expect("a name"),
        )
        .await
        .err()
        .map(|e| e.to_string())
    });
    let err = err.expect("the client's resolver must refuse every name");
    assert!(
        err.contains("exactly once") && err.contains("vendor.example"),
        "the refusal must name the invariant and the name it was asked about, got: {err}"
    );
}
