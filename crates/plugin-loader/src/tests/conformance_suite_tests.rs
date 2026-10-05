// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The published suite's own mechanics, with no plugin as the subject: the exact comparator, the
//! leg comparison, the perturbation the RED arms run, the profile guard. (Every plugin is proven by
//! its own repo running the suite; busbar tests only its own code.)

use super::{exact, perturbed, profile, same, Step, EXPECT_RELEASE_ENV};

fn step(label: &str, answer: &str, crossed: u64, pinned: u64) -> Step {
    Step {
        label: label.into(),
        answer: answer.into(),
        crossed,
        pinned,
    }
}

fn honest() -> Vec<Step> {
    vec![
        step("open", "Ready", 1, 1),
        step("ready", "Ok(())", 0, 0),
        step("read", "Ready lease=true", 2, 2),
    ]
}

#[test]
fn exact_passes_every_count_at_its_pin() {
    assert_eq!(exact(&honest()), Ok(()));
}

#[test]
fn exact_refuses_a_count_one_above_or_below_its_pin() {
    let mut over = honest();
    over[2].crossed = 3;
    let mut under = honest();
    under[0].crossed = 0;
    let e = exact(&over).expect_err("one crossing too many");
    assert!(e.contains("'read': 3 crossing(s), pinned 2"), "{e}");
    let e = exact(&under).expect_err("a skipped crossing");
    assert!(e.contains("'open': 0 crossing(s), pinned 1"), "{e}");
}

#[test]
fn a_comparator_that_only_wants_more_than_zero_is_not_this_one() {
    // Every op crossing twice is "above zero" everywhere it crossed at all.
    let doubled: Vec<Step> = honest()
        .into_iter()
        .map(|mut s| {
            s.crossed *= 2;
            s
        })
        .collect();
    assert!(doubled
        .iter()
        .filter(|s| s.pinned > 0)
        .all(|s| s.crossed > 0));
    assert!(exact(&doubled).is_err());
}

#[test]
fn perturbed_moves_exactly_one_pin_and_the_comparator_sees_it() {
    for at in 0..honest().len() {
        let p = perturbed(honest(), at);
        let moved: Vec<usize> = p
            .iter()
            .zip(honest())
            .enumerate()
            .filter(|(_, (a, b))| a.pinned != b.pinned)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(moved, [at]);
        assert!(exact(&p).is_err());
    }
}

#[test]
fn same_refuses_a_different_answer_count_or_length() {
    assert_eq!(same(&honest(), &honest()), Ok(()));
    let mut other = honest();
    other[2].answer = "Failed".into();
    assert!(same(&honest(), &other)
        .expect_err("answers differ")
        .contains("part at 'read'"));
    let mut other = honest();
    other[0].crossed = 2;
    assert!(same(&honest(), &other).is_err());
    let mut short = honest();
    short.pop();
    assert!(same(&honest(), &short)
        .expect_err("a leg stopped early")
        .contains("3 steps, the dropped 2"));
}

#[test]
fn the_profile_guard_refuses_a_debug_build_only_when_release_was_asked_for() {
    // Reads the variable only; never sets it (tests share the process environment).
    if std::env::var_os(EXPECT_RELEASE_ENV).is_none() {
        profile(true);
    }
    profile(false);
    let asked = std::panic::catch_unwind(|| {
        if std::env::var_os(EXPECT_RELEASE_ENV).is_some() {
            profile(true);
        }
    });
    assert_eq!(
        asked.is_err(),
        std::env::var_os(EXPECT_RELEASE_ENV).is_some()
    );
}

// ── THE SUITE'S CONNECTION TABLE (ARCHITECT, "SUITE CONNECTIONS") ──
//
// The subject here is the loader's own dispatcher test door (no plugin), restated with the needs
// each case names: the table `Subject::conns` builds is the decision under test.

mod suite_conns {
    use std::io::Read as _;
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicPtr, Ordering};
    use std::sync::Arc;

    use busbar_contract::abi::host::conn::connector::{Need, DIRECTION_OUTBOUND, KEEP_NAMED};
    use busbar_contract::abi::mechanism::call::AbiStr;
    use busbar_contract::abi::mechanism::door::{Door, DoorFn, Statement};
    use busbar_contract::abi::sdk::door::abi_str;
    use busbar_contract::conn::{NeedId, OpenDesc};

    use super::super::{bind, dispatcher, Subject};
    use crate::dispatch::{load_linked, Bind, LinkedRow, NO_BLOB};
    use crate::dispatch_test_plugin as plug;
    use crate::dispatch_tests::TestKind;

    const NONE: AbiStr = AbiStr {
        ptr: std::ptr::null(),
        len: 0,
    };

    const fn need(transport: AbiStr) -> Need {
        Need {
            direction: DIRECTION_OUTBOUND,
            egress_class: 0,
            transport,
            auth: NONE,
            target_from: NONE,
            trust_from: NONE,
            details: NO_BLOB,
            keep_response_headers: std::ptr::null(),
            keep_response_headers_len: 0,
            timeout_ms: 0,
            keep_mode: KEEP_NAMED,
            _reserved: 0,
            deny_response_headers: std::ptr::null(),
            deny_response_headers_len: 0,
        }
    }

    const TCP: [Need; 1] = [need(abi_str("tcp"))];
    const HTTP: [Need; 1] = [need(abi_str("http"))];
    const TCP_AND_HTTP: [Need; 2] = [need(abi_str("tcp")), need(abi_str("http"))];

    static TCP_DOOR: AtomicPtr<Door> = AtomicPtr::new(std::ptr::null_mut());
    static HTTP_DOOR: AtomicPtr<Door> = AtomicPtr::new(std::ptr::null_mut());
    static MIXED_DOOR: AtomicPtr<Door> = AtomicPtr::new(std::ptr::null_mut());

    /// The test door, its Statement declaring `needs`, stored in `slot`.
    fn restate(slot: &AtomicPtr<Door>, needs: &'static [Need]) {
        // SAFETY: the test door and its Statement are `'static`.
        let real: Door = unsafe { *plug::busbar_plugin_door() };
        let st: Statement = unsafe { *real.statement };
        let st: &'static Statement = Box::leak(Box::new(Statement {
            needs: needs.as_ptr(),
            needs_len: needs.len(),
            ..st
        }));
        let door = Box::into_raw(Box::new(Door {
            statement: st,
            ..real
        }));
        slot.store(door, Ordering::SeqCst);
    }

    extern "C" fn tcp_door() -> *const Door {
        if TCP_DOOR.load(Ordering::SeqCst).is_null() {
            restate(&TCP_DOOR, Box::leak(Box::new(TCP)));
        }
        TCP_DOOR.load(Ordering::SeqCst)
    }
    extern "C" fn http_door() -> *const Door {
        if HTTP_DOOR.load(Ordering::SeqCst).is_null() {
            restate(&HTTP_DOOR, Box::leak(Box::new(HTTP)));
        }
        HTTP_DOOR.load(Ordering::SeqCst)
    }
    extern "C" fn mixed_door() -> *const Door {
        if MIXED_DOOR.load(Ordering::SeqCst).is_null() {
            restate(&MIXED_DOOR, Box::leak(Box::new(TCP_AND_HTTP)));
        }
        MIXED_DOOR.load(Ordering::SeqCst)
    }

    fn subject(door: DoorFn) -> Subject {
        Subject::new(door, "unused", "{}")
    }

    #[test]
    fn a_door_with_no_need_is_bound_with_no_table_as_before() {
        let d = dispatcher();
        let s = subject(plug::busbar_plugin_door);
        assert!(s.needs().is_empty());
        assert!(s.conns(&d).is_none());
        assert!(s.bind(&d, "plain").conns.is_none());
    }

    #[test]
    fn a_need_the_table_does_not_serve_keeps_the_bind_with_no_table() {
        let d = dispatcher();
        for door in [http_door as DoorFn, mixed_door] {
            let s = subject(door);
            assert!(!s.needs().is_empty());
            assert!(s.conns(&d).is_none(), "{:?}", s.needs());
        }
    }

    /// A `tcp` need: each leg's bind carries a table of its own, and the instance bound over it
    /// dials a REAL local endpoint through it under its declared need.
    #[test]
    fn a_tcp_need_is_bound_to_a_table_that_dials_a_real_endpoint() {
        let d = dispatcher();
        let s = subject(tcp_door);
        assert_eq!(s.needs().len(), 1);
        assert!(s.bind(&d, "a").conns.is_some());
        let table = s.conns(&d).expect("a tcp need is handed a table");
        let p = load_linked::<TestKind>(
            &LinkedRow::of(tcp_door).expect("the restated door states its Statement"),
            Bind {
                conns: Some(Arc::clone(&table)),
                ..bind(&d, "networked")
            },
        )
        .expect("the networked door binds over the table");
        assert!(
            !p.inner.conns_table().is_null(),
            "the instance holds the table's slots"
        );

        let listener = TcpListener::bind("127.0.0.1:0").expect("a local endpoint");
        let target = listener.local_addr().expect("its address").to_string();
        let conn = table
            .open(
                p.instance(),
                NeedId(0),
                &OpenDesc {
                    target: &target,
                    timeout_ms: 2_000,
                    ..OpenDesc::default()
                },
            )
            .expect("the declared need dials the endpoint");
        table
            .write(p.instance(), conn, b"ping", false, false)
            .expect("the bytes go out");
        let (mut peer, _) = listener.accept().expect("the endpoint is reached");
        let mut got = [0_u8; 4];
        peer.read_exact(&mut got).expect("the endpoint reads them");
        assert_eq!(&got, b"ping");
        table.close(p.instance(), conn).expect("closed");
    }
}
