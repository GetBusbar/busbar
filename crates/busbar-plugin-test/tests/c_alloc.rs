// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-ALLOC (ABI-MIN3-INTERFACE §14, §0 I5): heap calls per crossing, counted by a counting allocator over the
//! whole process, through the ports core calls (the SDK test host's `Harness`, linked fixture plugins).
//!
//! I5's machinery is the code in abi and the loader between the port call and the return of the port's value; the
//! value itself is the caller's payload and is named separately below. The counts are exact:
//! - a sync crossing makes no heap call: transport `ingest`, `emit` and a session `begin` plus its drop;
//! - an auth `verify` (sync) makes none in the machinery; its value, the `Identity`, is two: the verified
//!   records and the `Arc` the verdict cache shares (`busbar-ports` `decode_verify_ok`);
//! - an async entry in steady state (a never-NEED secret `resolve`) makes exactly I5's three in the machinery
//!   (the port's one box, the plugin future's box, the plugin's `Reply`), plus one for its value (the
//!   `SecureVec` holding the secret).
//!
//! Counts are process-wide, so each arm takes the smallest of three windows of `CALLS` calls (a stray allocation
//! on another thread can only add) and the arms run one at a time (nextest runs each test in its own process).
//! This is the hard gate for the wrapper's allocations; its timing is B-SYNC's and B-OPEN's OK arms.

use std::hint::black_box;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use stats_alloc::{Region, StatsAlloc};

use busbar_plugin_abi::host_side::caller::CallStack;
use busbar_plugin_test::suites::harness::Harness;
use busbar_plugin_test::FakeNeeds;
use busbar_ports::CallCx;

#[global_allocator]
static COUNTING: StatsAlloc<std::alloc::System> = StatsAlloc::new(std::alloc::System);

/// Calls per counting window.
const CALLS: usize = 1_000;
/// Calls before counting: the pool's queues, the thread's buffers and its watchdog word are warm.
const WARM: usize = 10_000;

static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

/// Heap calls (allocations and reallocations) `f` makes, the smallest of three windows.
fn heap_calls(mut f: impl FnMut()) -> usize {
    for _ in 0..WARM {
        f();
    }
    (0..3)
        .map(|_| {
            let region = Region::new(&COUNTING);
            for _ in 0..CALLS {
                f();
            }
            let change = region.change();
            change.allocations + change.reallocations
        })
        .min()
        .unwrap_or(usize::MAX)
}

#[path = "fixtures/min3_transport.rs"]
mod min3_transport;

/// An auth plugin whose `verify` answers a subject and a cache fact and does nothing else.
mod nop_auth {
    use busbar_plugin_abi::auth::{self, AuthReq};
    use busbar_plugin_abi::fail::Fail;
    use busbar_plugin_abi::host::Host;
    use busbar_plugin_abi::need::ChainBytes;
    use busbar_plugin_abi::plugin::{Describe, Endpoints, Open};
    use busbar_plugin_abi::records::{tag, Out, Writer};

    pub struct NopAuth;
    impl Open for NopAuth {
        async fn open(_h: &'static Host, _config: ChainBytes) -> Result<Self, Fail> {
            Ok(NopAuth)
        }
        fn check(_h: &Host, _config: &[u8], _ends: &mut Endpoints<'_>) -> Result<(), Fail> {
            Ok(())
        }
        fn describe(d: &mut Describe<'_>) {
            d.methods(auth::M_VERIFY)
                .schema(r#"{"type":"object"}"#)
                .item_text(auth::tag::D_CRED_HEADER, "authorization");
        }
    }
    impl busbar_plugin_abi::Auth for NopAuth {
        fn verify(&self, _h: &Host, req: &AuthReq<'_>, out: &mut Out<'_>) -> Result<(), Fail> {
            std::hint::black_box(req.flags);
            out.put_text(tag::ID_SUBJECT, "nop")?;
            out.put_fact(auth::F_CACHE_S, 0)?;
            Ok(())
        }
    }
    busbar_plugin_abi::plugin!(Auth, NopAuth, name: "fixture-nop-auth");
}

/// A secret plugin whose `resolve` answers a 32-byte value at once (a never-NEED chain).
mod nop_secret {
    use busbar_plugin_abi::fail::Fail;
    use busbar_plugin_abi::host::Host;
    use busbar_plugin_abi::need::ChainBytes;
    use busbar_plugin_abi::plugin::{Describe, Endpoints, Open};
    use busbar_plugin_abi::records::{Reply, Writer};
    use busbar_plugin_abi::Secret;

    pub struct NopSecret;
    impl Open for NopSecret {
        async fn open(_h: &'static Host, _config: ChainBytes) -> Result<Self, Fail> {
            Ok(NopSecret)
        }
        fn check(_h: &Host, _config: &[u8], _ends: &mut Endpoints<'_>) -> Result<(), Fail> {
            Ok(())
        }
        fn describe(d: &mut Describe<'_>) {
            d.schema(r#"{"type":"object"}"#);
            d.item_text(
                busbar_plugin_abi::secret::tag::D_REF_SCHEMA,
                r#"{"type":"object"}"#,
            );
        }
    }
    impl Secret for NopSecret {
        async fn resolve(&self, _h: &'static Host, _reference: ChainBytes) -> Result<Reply, Fail> {
            let mut reply = Reply::new();
            reply
                .put(
                    busbar_plugin_abi::secret::tag::VALUE,
                    b"0123456789abcdef0123456789abcdef",
                )
                .map_err(Fail::from)?;
            Ok(reply)
        }
    }
    busbar_plugin_abi::plugin!(Secret, NopSecret, name: "fixture-nop-secret");
}

fn cx(deadline: Instant) -> CallCx {
    CallCx {
        deadline,
        request_id: 1,
        stack: CallStack::default(),
    }
}

#[test]
fn sync_zero_and_async_steady_state_three() {
    let _one = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let deadline = Instant::now() + Duration::from_secs(600);

    // Sync: the transport's session methods and a session's open and close.
    {
        use busbar_plugin_abi::transport as tp;
        use busbar_ports::transport::{ConnIn, TransportOut};
        let h = Harness::admit(min3_transport::PLUGIN.plugin(), FakeNeeds::default())
            .unwrap_or_else(|r| panic!("admit: {r:?}"));
        let port = h
            .open_transport("alloc-transport", b"{}")
            .unwrap_or_else(|e| panic!("open: {e:?}"));
        let conn = ConnIn {
            role: tp::ROLE_CLIENT,
            flags: 0,
            alpn: "",
            sni: "",
            peer: "192.0.2.1:50000",
            local: "192.0.2.2:8443",
            tls_peer_cert: &[],
            leftover: &[],
            head: &[],
            local_fingerprint: "",
            mono_ns: 1,
        };
        let mut session = port
            .begin(&conn, &mut |_o: TransportOut<'_>| {})
            .unwrap_or_else(|e| panic!("begin: {e:?}"));
        let kib = vec![7u8; 1024];
        let ingest = heap_calls(|| {
            port.ingest(&mut session, black_box(&kib), &mut |_o: TransportOut<
                '_,
            >| {})
                .expect("ingest");
        });
        assert_eq!(ingest, 0, "transport ingest: heap calls in {CALLS} calls");
        let emit = heap_calls(|| {
            port.emit(
                &mut session,
                1,
                tp::E_BODY,
                0,
                black_box(&kib),
                &mut |_o: TransportOut<'_>| {},
            )
            .expect("emit");
        });
        assert_eq!(emit, 0, "transport emit: heap calls in {CALLS} calls");
        let pair = heap_calls(|| {
            let s = port
                .begin(&conn, &mut |_o: TransportOut<'_>| {})
                .expect("begin");
            drop(black_box(s));
        });
        assert_eq!(
            pair, 0,
            "transport begin + drop: heap calls in {CALLS} pairs"
        );
    }

    // Sync with a value: auth verify. Machinery zero; the Identity is two.
    {
        use busbar_ports::auth::{AuthIn, Verify};
        let h = Harness::admit(nop_auth::PLUGIN.plugin(), FakeNeeds::default())
            .unwrap_or_else(|r| panic!("admit: {r:?}"));
        let port = h
            .open_auth("alloc-auth", b"{}")
            .unwrap_or_else(|e| panic!("open: {e:?}"));
        let req = AuthIn {
            method: "POST",
            path: "/v1/messages",
            query: "",
            authority: "api.example.test",
            headers: &[],
            peer: "192.0.2.1:50000",
            tls_peer_cert: &[],
            body: &[],
            now_s: 1_800_000_000,
        };
        let verify = heap_calls(|| match port.verify(cx(deadline), black_box(&req), None) {
            Verify::Done(done) => {
                black_box(done.expect("a subject"));
            }
            Verify::Io(_) => panic!("a sync verify answers at once"),
        });
        assert_eq!(
            verify,
            2 * CALLS,
            "auth verify: the Identity's records and Arc, nothing else"
        );
    }

    // Async, steady state: a never-NEED secret resolve. I5's three, plus the value.
    {
        let h = Harness::admit(nop_secret::PLUGIN.plugin(), FakeNeeds::default())
            .unwrap_or_else(|r| panic!("admit: {r:?}"));
        let port = h
            .open_secret("alloc-secret", b"{}")
            .unwrap_or_else(|e| panic!("open: {e:?}"));
        let reference = br#"{"name":"db"}"#.to_vec();
        // One runtime entry for every call, so the count is the resolve's alone.
        let resolve = h.block_on(async {
            for _ in 0..WARM {
                black_box(
                    port.resolve(cx(deadline), &reference)
                        .await
                        .expect("a value"),
                );
            }
            let mut least = usize::MAX;
            for _ in 0..3 {
                let region = Region::new(&COUNTING);
                for _ in 0..CALLS {
                    black_box(
                        port.resolve(cx(deadline), &reference)
                            .await
                            .expect("a value"),
                    );
                }
                let change = region.change();
                least = least.min(change.allocations + change.reallocations);
            }
            least
        });
        assert_eq!(
            resolve,
            (3 + 1) * CALLS,
            "secret resolve: the port box, the plugin future box, the plugin's Reply, and the value"
        );
    }
}

#[test]
#[ignore = "owner: W1-L3; blocked (re-checked on dev 2026-11-16): the store adapter port_error(a, inst) is private and needs a live Instance; row 1 (store.rs request todo!) is in flight"]
fn a_store_lane_entry_allocates_four() {
    todo!("owner: W1-L3 (C-ALLOC)")
}

/// The reference auth: its `verify` MACs the id header and the body through the host's HMAC over parts.
#[path = "fixtures/ref_auth.rs"]
mod ref_auth;

/// Interface revision E.1: the host's HMAC over parts makes NO heap call and copies no part. An auth
/// `verify` that MACs a 64 KiB body where the host lent it costs exactly what a `verify` that reads nothing
/// costs: the two allocations of its value (the `Identity`'s records and `Arc`), nothing for the MAC.
#[test]
fn an_auth_verify_that_macs_its_body_over_parts_adds_no_heap_call() {
    use busbar_plugin_abi::types::{Bytes, Pair, Str};
    use busbar_ports::auth::{AuthIn, Verify, VerifyAnswer};

    let _one = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let deadline = Instant::now() + Duration::from_secs(600);
    let h = Harness::admit(ref_auth::PLUGIN.plugin(), FakeNeeds::default())
        .unwrap_or_else(|r| panic!("admit: {r:?}"));
    let port = h
        .open_auth(
            "alloc-ref-auth",
            br#"{"key":"0123456789abcdefghij","subject":"reference-caller"}"#,
        )
        .unwrap_or_else(|e| panic!("open: {e:?}"));

    // A published-style known answer first (computed with openssl): the MAC that is counted is the right one.
    let known = [
        Pair {
            name: Str::new(ref_auth::ID_HEADER),
            value: Bytes::new(b"what do ya want "),
        },
        Pair {
            name: Str::new(ref_auth::SIGNATURE_HEADER),
            value: Bytes::new(b"19cc895f09b77219ab2686e68c0dc433411a0621ab3f8e3f54e214084f931167"),
        },
    ];
    let request = |headers, body| AuthIn {
        method: "POST",
        path: "/hook",
        query: "",
        authority: "example",
        headers,
        peer: "192.0.2.1:50000",
        tls_peer_cert: &[],
        body,
        now_s: 1_800_000_000,
    };
    let accepted = |req: &AuthIn<'_>| match port.verify(cx(deadline), req, None) {
        Verify::Done(Ok(VerifyAnswer::Identity(identity))) => {
            black_box(identity);
            true
        }
        Verify::Done(_) => false,
        Verify::Io(_) => panic!("a sync verify answers at once"),
    };
    assert!(accepted(&request(&known, b"for nothing?")));
    assert!(
        !accepted(&request(&known, b"for nothing!")),
        "one wrong byte of the body is refused"
    );

    // The counted call: a 64 KiB body under a signature that does not match. A refusal has no value, so
    // every heap call counted is the machinery's or the MAC's: there must be none.
    let big = vec![0x5a_u8; 64 << 10];
    let refused = request(&known, &big);
    let calls = heap_calls(|| {
        assert!(!accepted(black_box(&refused)));
    });
    let nothing = request(&[], &[]);
    let baseline = heap_calls(|| {
        assert!(!accepted(black_box(&nothing)));
    });
    assert_eq!(
        calls, baseline,
        "auth verify with an HMAC over parts of a 64 KiB body: the heap calls of a verify that MACs nothing"
    );
}
