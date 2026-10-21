// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE UNIFIED EGRESS BACKEND'S OWN PROOFS: the pool keyed by the pinned address, and the resolver
//! that refuses a second lookup. Every plane's real-network transport is built on these two, so the
//! properties are asserted HERE once rather than re-proven per plane. The plane-level suites (the
//! real-TLS / body-cap / zero-second-lookup harnesses) then exercise the same machinery end to end.

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

/// A HOT DESTINATION SURVIVES A WORKING SET OVER THE CAP. Eviction that picks an arbitrary entry can
/// pick the one destination every request is going to, so a fleet whose working set sits just over
/// the cap rebuilds its busiest client — TLS handshakes and a cold connection pool — again and again.
/// The entry that goes is the one nobody has asked for in the longest time.
#[test]
fn the_pool_evicts_the_coldest_entry_and_keeps_the_hot_one() {
    let pool = PinnedClientPool::with_capacity(4);
    let hot = ("hot.test".to_string(), addr(6000));
    let _c = pool
        .client_for(hot.clone(), || {
            Ok::<_, String>(build("hot.test", addr(6000)))
        })
        .expect("build the hot client");

    // A working set that turns over past the cap, with the hot destination used between each turn.
    for port in 6001u16..6020 {
        let cold = addr(port);
        let _c = pool
            .client_for(("cold.test".to_string(), cold), || {
                Ok::<_, String>(build("cold.test", cold))
            })
            .expect("build a cold client");
        let _hot = pool
            .client_for(hot.clone(), || -> Result<EngineClient, String> {
                panic!("the hot destination was evicted and had to be rebuilt")
            })
            .expect("the hot client is still pooled");
    }
    assert_eq!(pool.len(), 4, "the pool never exceeds its capacity");
}

/// CALLERS ARRIVING ON A COLD KEY TOGETHER BUILD ONE CLIENT. Checking the map and then building
/// outside its lock let every one of them build; the losers' clients — their own TLS handshakes and
/// idle sockets — were dropped on the floor at exactly the moment a destination first went hot.
#[test]
fn concurrent_first_uses_of_one_key_build_a_single_client() {
    let pool = Arc::new(PinnedClientPool::with_capacity(64));
    let builds = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let together = Arc::new(std::sync::Barrier::new(8));

    let callers: Vec<_> = (0..8)
        .map(|_| {
            let pool = pool.clone();
            let builds = builds.clone();
            let together = together.clone();
            std::thread::spawn(move || {
                together.wait();
                pool.client_for(("race.test".to_string(), addr(5000)), || {
                    builds.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                    Ok::<_, String>(build("race.test", addr(5000)))
                })
                .expect("every caller gets a client");
            })
        })
        .collect();
    for c in callers {
        c.join().expect("no caller panicked");
    }

    assert_eq!(
        builds.load(std::sync::atomic::Ordering::Acquire),
        1,
        "one cold key is one build, however many callers arrive on it at once"
    );
    assert_eq!(pool.len(), 1);
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

/// F25 row 106: rehomed from the retired engine crate's src/engine/tests/egress_differential_tests.rs::
/// the_pin_never_consults_the_resolver_and_the_doctrine_refuses_other_names, on the served engine.
/// The pin makes the resolver STRUCTURALLY unreachable for the pinned host: a REBINDING resolver
/// (the fixture first, `203.0.113.9` after) wired in as the client's DNS is never consulted for the
/// pinned name (zero calls across the exchange, which answers 200). The production posture
/// (`EngineSpec::pinned`) goes one step further: any other name is refused with the doctrine text
/// in the error's cause chain.
#[tokio::test]
async fn the_pin_never_consults_the_resolver_and_the_doctrine_refuses_other_names() {
    use super::engine::{egress_request, Dns, PinnedDest, ResolveNames};
    use crate::egress::fixtures::{spawn_http, CannedResponse, RebindingResolver};

    let fixture = spawn_http(CannedResponse::ok("pinned"), 4);
    let evil: SocketAddr = "203.0.113.9:80".parse().expect("addr");
    let rebinding = Arc::new(RebindingResolver::new(fixture.addr, evil));
    let client = build_client(&EngineSpec {
        pin: Some(PinnedDest {
            host: Arc::from("pinned.test"),
            addr: fixture.addr.ip(),
        }),
        dns: Dns::Custom(Arc::clone(&rebinding) as Arc<dyn ResolveNames>),
        ..EngineSpec::pinned(
            Arc::from("pinned.test"),
            fixture.addr.ip(),
            None,
            Vec::new(),
        )
    })
    .expect("a pinned client builds");
    let resp = client
        .request(egress_request(
            format!("http://pinned.test:{}/v1/x", fixture.addr.port())
                .parse()
                .expect("uri"),
            http::HeaderMap::new(),
            bytes::Bytes::new(),
        ))
        .await
        .expect("pinned hop");
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        rebinding.calls(),
        0,
        "the pinned name must resolve through the pin, NEVER the resolver"
    );

    // The production posture: any other name is refused with the doctrine message.
    let production = build("pinned.test", fixture.addr);
    let err = production
        .request(egress_request(
            format!("http://other.test:{}/v1/x", fixture.addr.port())
                .parse()
                .expect("uri"),
            http::HeaderMap::new(),
            bytes::Bytes::new(),
        ))
        .await
        .expect_err("a second lookup must refuse");
    let rendered = super::with_cause(&err);
    assert!(
        rendered.contains("resolves each name exactly once"),
        "the refusal must carry the doctrine text: {rendered}"
    );
}
