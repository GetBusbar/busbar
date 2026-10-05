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
        resumes: 0,
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
    use crate::dispatch::{load_linked, Bind, ConnTable, LinkedRow, NO_BLOB};
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
        assert!(matches!(s.bind(&d, "plain").conns, ConnTable::NoNeeds));
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
        assert!(matches!(s.bind(&d, "a").conns, ConnTable::Host(_)));
        let table = s.conns(&d).expect("a tcp need is handed a table");
        let p = load_linked::<TestKind>(
            &LinkedRow::of(tcp_door).expect("the restated door states its Statement"),
            Bind {
                conns: crate::dispatch::ConnTable::Host(Arc::clone(&table)),
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

// ── FIRST INVOCATIONS PINNED, RESUMES REPORTED (Q-P4-5) ──

/// A fold whose dialing step resumed: pinned at one first invocation each.
fn dialled() -> Vec<Step> {
    let mut f = honest();
    f[0].resumes = 26;
    f[2].resumes = 2;
    f
}

#[test]
fn resumes_are_never_pinned_a_moved_first_invocation_count_still_fails() {
    // Resumes, however many, are not crossings the comparator pins.
    assert_eq!(exact(&dialled()), Ok(()));
    let mut moved = dialled();
    moved[0].crossed = 2;
    let e = exact(&moved).expect_err("a second first invocation of `open`");
    assert!(e.contains("'open': 2 crossing(s), pinned 1"), "{e}");
    assert!(e.contains("26 resume(s)"), "{e}");
}

/// RED: a networked door is held to its resumes: a dialing step that answered at once (no resume)
/// is refused, and a networked fold with no resume at all; a door with no need is not held to it.
#[test]
fn red_a_networked_fold_whose_dialing_step_never_resumed_is_refused() {
    use super::resumed;
    let dialing = vec!["open".to_owned(), "read".to_owned()];
    assert_eq!(resumed(&dialled(), true, &dialing), Ok(()));
    let mut lazy = dialled();
    lazy[2].resumes = 0;
    let e = resumed(&lazy, true, &dialing).expect_err("`read` dials and never resumed");
    assert!(e.contains("dialing step 'read' never resumed"), "{e}");
    let e = resumed(&honest(), true, &[]).expect_err("a networked fold with no resume");
    assert!(e.contains("resumed no op"), "{e}");
    assert_eq!(resumed(&honest(), false, &[]), Ok(()));
}

// ── THE KERNEL'S OPEN, RESUMED (Q-P4-6) ──

mod resumed_open {
    use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

    use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome, RawOutcome};
    use busbar_contract::abi::mechanism::door::Door;
    use busbar_contract::abi::mechanism::lifecycle::{OpenIn, OpenOut, OpsHead};

    use super::super::{bind, crossings, dispatcher, open, open_resumed};
    use crate::dispatch::load_linked;
    use crate::dispatch::LinkedRow;
    use crate::dispatch_test_plugin as plug;
    use crate::dispatch_tests::TestKind;

    /// The real `open`, behind the restated one.
    static REAL_OPEN: AtomicPtr<()> = AtomicPtr::new(std::ptr::null_mut());
    /// The restated `open` has pended once (it connects in its `open`, as a networked store).
    static PENDED: AtomicBool = AtomicBool::new(false);
    static SLOT: AtomicPtr<Door> = AtomicPtr::new(std::ptr::null_mut());

    /// An `open` that connects in its connect step: its first invocation opens as the real one
    /// does (its instance box handed back) but answers PENDING, waking its own ticket (the latch);
    /// RESUMED on that box, it answers READY.
    extern "C" fn open_pends(
        instance: *mut std::ffi::c_void,
        input: *const std::ffi::c_void,
        out: *mut std::ffi::c_void,
    ) -> RawOutcome {
        if PENDED.swap(true, Ordering::SeqCst) {
            // SAFETY: the host hands a resumed `open` its box and an `OpenOut`.
            unsafe {
                let o = &mut *out.cast::<OpenOut>();
                o.instance = instance;
                o.head.outcome = RawOutcome::of(Outcome::Ready);
            }
            return RawOutcome::of(Outcome::Ready);
        }
        // SAFETY: stored from the real door's `open` below.
        let real: busbar_contract::abi::mechanism::call::Op =
            unsafe { std::mem::transmute(REAL_OPEN.load(Ordering::SeqCst)) };
        if real(instance, input, out) != RawOutcome::of(Outcome::Ready) {
            return unsafe { (*out.cast::<OutHead>()).outcome };
        }
        // SAFETY: the host hands `open` an `OpenIn` and an `OpenOut`.
        unsafe {
            let head = &*input.cast::<InHead>();
            let tables = &*(*input.cast::<OpenIn>()).host;
            if head.ticket.generation != 0 {
                if let Some(wake) = tables.wake {
                    wake(tables.ctx, head.ticket);
                }
            }
            (*out.cast::<OutHead>()).outcome = RawOutcome::of(Outcome::Pending);
        }
        RawOutcome::of(Outcome::Pending)
    }

    extern "C" fn pending_open_door() -> *const Door {
        let have = SLOT.load(Ordering::SeqCst);
        if !have.is_null() {
            return have;
        }
        // SAFETY: the test plugin's door and its lifecycle table are `'static`.
        let real: Door = unsafe { plug::busbar_plugin_door().read_unaligned() };
        let ops: OpsHead = unsafe { real.ops.read_unaligned() };
        REAL_OPEN.store(
            ops.open.expect("the test plugin opens") as *mut (),
            Ordering::SeqCst,
        );
        let ops: &'static OpsHead = Box::leak(Box::new(OpsHead {
            open: Some(open_pends),
            ..ops
        }));
        let door = Box::into_raw(Box::new(Door { ops, ..real }));
        SLOT.store(door, Ordering::SeqCst);
        door
    }

    /// RED: an `open` that pends (a store connecting in its connect step) cannot be opened by one
    /// raw, ticket-less crossing (its PENDING is a FAULT there); opened as the kernel opens it, on a ticket, it is RESUMED and answers READY:
    /// one first invocation and one resume.
    #[test]
    fn red_a_pending_open_is_resumed_by_the_kernels_open_never_one_raw_crossing() {
        let d = dispatcher();
        let row = LinkedRow::of(pending_open_door).expect("the restated door states itself");
        let raw = load_linked::<TestKind>(&row, bind(&d, "raw")).expect("it loads");
        PENDED.store(false, Ordering::SeqCst);
        // A ticket-less crossing may not pend: the host FAULTs the raw open's PENDING.
        assert_eq!(
            open(&raw, b"{}").outcome,
            Outcome::Fault,
            "one raw crossing cannot open it"
        );

        let p = load_linked::<TestKind>(&row, bind(&d, "resumed")).expect("it loads");
        PENDED.store(false, Ordering::SeqCst);
        let (first, resumes) = crossings(&p).read();
        let o = open_resumed(&p, &d, b"{}");
        assert_eq!(o.outcome, Outcome::Ready, "resumed on its wake, it opens");
        let (first_after, resumes_after) = crossings(&p).read();
        assert_eq!((first_after - first, resumes_after - resumes), (1, 1));
    }
}
