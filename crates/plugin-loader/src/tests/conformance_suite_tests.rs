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

    /// A host connector handed in (`conformance_suite! { …, host: … }`): stands in for busbar's.
    fn a_host(
        wake: Arc<dyn Fn(u64) + Send + Sync>,
        anchors: Option<&str>,
    ) -> Arc<dyn busbar_contract::conn::DeclaredConns> {
        let _ = wake;
        HOSTED.with(|h| h.set(anchors.map(str::to_owned)));
        Arc::new(crate::needs_restated::Inert)
    }

    thread_local! {
        static HOSTED: std::cell::Cell<Option<String>> = const { std::cell::Cell::new(None) };
    }

    /// Q-P4-4's seam: with a HOST connector handed in, a need over a scheme the test table does
    /// not serve (`http`) binds over the host, its TLS handed the suite's test anchors; without
    /// one it binds as a probe; anchors with no host are refused by name.
    #[test]
    fn a_host_connector_handed_in_serves_every_need_and_takes_the_anchors() {
        let d = dispatcher();
        let s = subject(http_door).with_host(a_host).with_anchors("PEM");
        assert!(matches!(s.bind(&d, "hosted").conns, ConnTable::Host(_)));
        assert_eq!(HOSTED.with(std::cell::Cell::take).as_deref(), Some("PEM"));
        let plain = subject(http_door);
        assert!(matches!(plain.bind(&d, "plain").conns, ConnTable::Probe));
        let unhosted = subject(tcp_door).with_anchors("PEM");
        let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            unhosted.conns(&d).is_some()
        }))
        .expect_err("anchors with no host to trust them");
        let text = refused
            .downcast_ref::<&str>()
            .map(ToString::to_string)
            .or_else(|| refused.downcast_ref::<String>().cloned())
            .unwrap_or_default();
        assert!(text.contains("name its `host:` too"), "{text}");
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

/// RED (Q-P4-7): the store script writes, and looks up, the credential kind the plugin's
/// `conformance.json` names (`store.credential_kind`: the one kind the shipped store schemas hold,
/// `sigv4` in 1.5.5's), never a kind of its own a schema-constrained store refuses; a
/// `conformance.json` that names none is refused by name.
#[test]
fn the_store_script_writes_the_credential_kind_the_plugin_names() {
    use super::store::{secret, Inputs};
    assert_eq!(secret("sigv4", "c1", "k1", "pub1").meta.kind, "sigv4");
    let none = serde_json::json!({ "node": 1 });
    let text = std::panic::catch_unwind(|| Inputs::of(&none).credential_kind.to_owned())
        .expect_err("no credential kind named");
    let text = text.downcast_ref::<String>().cloned().unwrap_or_default();
    assert!(text.contains("store.credential_kind"), "{text}");
}

// ── THE PER-FOLD NAMESPACE (Q-P4-8) ──

mod fold_namespace {
    use super::super::{fold_namespace, Leg, Subject, FOLD};

    fn subject(settings: &str) -> Subject {
        extern "C" fn no_door() -> *const busbar_contract::abi::mechanism::door::Door {
            std::ptr::null()
        }
        Subject::new(no_door, "unused", &format!(r#"{{"settings": {settings}}}"#))
    }

    /// Settings that name no placeholder are exactly the plugin's.
    #[test]
    fn settings_without_the_placeholder_are_unchanged() {
        let s = subject(r#"{"url": "db://127.0.0.1/db"}"#);
        assert_eq!(
            Leg::Linked.settings(&s).to_vec(),
            br#"{"url":"db://127.0.0.1/db"}"#.to_vec()
        );
    }

    /// RED: two folds, the two legs of one run and folds run in parallel, each fill the
    /// placeholder with a namespace no other fold uses, so neither reads the other's rows or
    /// tombstones; each is a valid schema name (`[a-z0-9_]`) naming the process and its leg.
    #[test]
    fn red_two_parallel_folds_never_share_a_namespace() {
        let s = std::sync::Arc::new(subject(r#"{"schema": "{fold}", "prefix": "{fold}:"}"#));
        let linked = String::from_utf8(Leg::Linked.settings(&s).to_vec()).unwrap();
        let dropped = String::from_utf8(Leg::Dropped.settings(&s).to_vec()).unwrap();
        assert!(
            !linked.contains(FOLD) && !dropped.contains(FOLD),
            "{linked} {dropped}"
        );
        assert_ne!(linked, dropped, "the two legs of one run");
        let pid = std::process::id().to_string();
        assert!(
            linked.contains(&format!("bbconf_{pid}_linked_")),
            "{linked}"
        );
        assert!(
            dropped.contains(&format!("bbconf_{pid}_dropped_")),
            "{dropped}"
        );

        let parallel: Vec<String> = (0..8)
            .map(|_| {
                let s = std::sync::Arc::clone(&s);
                std::thread::spawn(move || {
                    String::from_utf8(Leg::Linked.settings(&s).to_vec()).unwrap()
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect();
        let mut distinct = parallel.clone();
        distinct.sort();
        distinct.dedup();
        assert_eq!(
            distinct.len(),
            parallel.len(),
            "parallel folds of one leg: {parallel:?}"
        );
        for n in [fold_namespace("linked"), fold_namespace("RED run")] {
            assert!(
                n.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
                "{n}"
            );
        }
    }
}

// ── THE PER-FOLD NAMESPACE HOOKS (Q-P4-8) ──

mod namespace_hooks {
    use std::sync::Mutex;

    use super::super::{Leg, Subject};

    /// Every hook call: (`create` or `drop`, the namespace, the filled settings).
    static CALLS: Mutex<Vec<(&'static str, String, String)>> = Mutex::new(Vec::new());

    fn create(ns: &str, settings: &[u8]) {
        let settings = String::from_utf8_lossy(settings).into_owned();
        CALLS
            .lock()
            .unwrap()
            .push(("create", ns.to_owned(), settings));
    }

    fn drop_ns(ns: &str, settings: &[u8]) {
        let settings = String::from_utf8_lossy(settings).into_owned();
        CALLS
            .lock()
            .unwrap()
            .push(("drop", ns.to_owned(), settings));
    }

    fn calls_for(ns: &str) -> Vec<&'static str> {
        CALLS
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, n, _)| n == ns)
            .map(|(what, _, _)| *what)
            .collect()
    }

    fn subject() -> Subject {
        extern "C" fn no_door() -> *const busbar_contract::abi::mechanism::door::Door {
            std::ptr::null()
        }
        Subject::new(
            no_door,
            "unused",
            r#"{"settings": {"options": "-c search_path={fold}"}}"#,
        )
        .with_namespace(create, drop_ns)
    }

    /// A hook-made namespace is created once before its fold's open and dropped once after the
    /// fold (also when the fold fails); two parallel folds get distinct namespaces; the hooks are
    /// handed the fold's FILLED settings.
    #[test]
    fn a_hook_made_namespace_is_created_and_dropped_once_per_fold() {
        let s = std::sync::Arc::new(subject());
        let ns = {
            let f = Leg::Linked.settings(&s);
            assert_eq!(
                calls_for(f.namespace()),
                ["create"],
                "created before the fold opens"
            );
            assert_eq!(
                &*f,
                format!(r#"{{"options":"-c search_path={}"}}"#, f.namespace()).as_bytes()
            );
            f.namespace().to_owned()
        };
        assert_eq!(
            calls_for(&ns),
            ["create", "drop"],
            "dropped once, at the fold's end"
        );

        let parallel: Vec<String> = [Leg::Linked, Leg::Dropped, Leg::Linked, Leg::Dropped]
            .into_iter()
            .map(|leg| {
                let s = std::sync::Arc::clone(&s);
                std::thread::spawn(move || leg.settings(&s).namespace().to_owned())
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect();
        let mut distinct = parallel.clone();
        distinct.sort();
        distinct.dedup();
        assert_eq!(distinct.len(), 4, "{parallel:?}");
        for n in &parallel {
            assert_eq!(calls_for(n), ["create", "drop"], "{n}");
        }

        let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let f = Leg::Dropped.settings(&s);
            let ns = f.namespace().to_owned();
            *FAILED.lock().unwrap() = ns;
            panic!("the fold fails");
        }));
        assert!(failed.is_err());
        let ns = FAILED.lock().unwrap().clone();
        assert_eq!(
            calls_for(&ns),
            ["create", "drop"],
            "a failed fold's namespace is dropped"
        );
    }

    static FAILED: Mutex<String> = Mutex::new(String::new());

    /// Without hooks, nothing is called and the settings are filled as before.
    #[test]
    fn without_hooks_a_fold_is_filled_and_nothing_is_called() {
        extern "C" fn no_door() -> *const busbar_contract::abi::mechanism::door::Door {
            std::ptr::null()
        }
        let s = Subject::new(no_door, "unused", r#"{"settings": {"schema": "{fold}"}}"#);
        let f = Leg::Linked.settings(&s);
        let ns = f.namespace().to_owned();
        assert_eq!(&*f, format!(r#"{{"schema":"{ns}"}}"#).as_bytes());
        drop(f);
        assert!(calls_for(&ns).is_empty());
    }
}

// ── THE DECLARED NEEDS ARE THE STATEMENT'S (ARCHITECT, one truth) ──

/// RED: a declares file that names a scheme the Statement does not, or misses one it does, is
/// refused; one that names exactly the Statement's schemes (in any order, repeated) passes, and so
/// does a declares file with no `needs` for a Statement that declares none.
#[test]
fn red_declares_needs_that_are_not_the_statements_are_refused() {
    use super::declared_needs_are;
    let http = ["http".to_owned()];
    let tcp_http = ["http".to_owned(), "tcp".to_owned()];
    assert_eq!(declared_needs_are(r#"{"needs": ["http"]}"#, &http), Ok(()));
    assert_eq!(
        declared_needs_are(r#"{"needs": ["tcp", "http", "tcp"]}"#, &tcp_http),
        Ok(())
    );
    assert_eq!(declared_needs_are(r#"{"contract_abi": {}}"#, &[]), Ok(()));
    let e = declared_needs_are(r#"{"needs": ["http", "tcp"]}"#, &http).unwrap_err();
    assert!(e.contains(r#"names ["tcp"] the Statement does not"#), "{e}");
    let e = declared_needs_are(r#"{"needs": ["http"]}"#, &tcp_http).unwrap_err();
    assert!(e.contains(r#"misses ["tcp"]"#), "{e}");
    let e = declared_needs_are(r#"{}"#, &http).unwrap_err();
    assert!(e.contains(r#"misses ["http"]"#), "{e}");
    assert!(declared_needs_are(r#"{"needs": "http"}"#, &http).is_err());
}

/// The declares file is found at the workspace root or one directory below it.
#[test]
fn the_declares_file_is_found_beside_the_plugin_crate() {
    let root = std::env::temp_dir().join(format!("declares-find-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("logic")).unwrap();
    std::fs::create_dir_all(root.join("logic-plugin")).unwrap();
    // A plugin repo's root is its workspace (`Cargo.toml` beside `logic/` and `logic-plugin/`).
    std::fs::write(root.join("Cargo.toml"), "[workspace]\n").unwrap();
    std::fs::write(root.join("logic/declares.json"), "{}").unwrap();
    let found = super::declares_file(root.join("logic-plugin").to_str().unwrap());
    assert_eq!(found, Some(root.join("logic/declares.json")));
    std::fs::remove_file(root.join("logic/declares.json")).unwrap();
    assert_eq!(
        super::declares_file(root.join("logic-plugin").to_str().unwrap()),
        None
    );
    std::fs::remove_dir_all(&root).unwrap();
}

/// A crate in busbar's own tree (its parent, `crates/`, is no plugin repo's workspace root) is
/// judged by its OWN declares file: a sibling crate's `declares.json` is that crate's. RED before
/// the workspace-root rule: the sibling's file was found as this crate's, and two siblings holding
/// one each panicked every in-tree conformance subject.
#[test]
fn a_sibling_crates_declares_file_is_never_this_crates() {
    let tree = std::env::temp_dir().join(format!("declares-tree-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tree);
    let crates = tree.join("crates");
    for c in ["plane-one", "plane-two", "plane-three"] {
        std::fs::create_dir_all(crates.join(c)).unwrap();
    }
    std::fs::write(tree.join("Cargo.toml"), "[workspace]\n").unwrap();
    std::fs::write(crates.join("plane-one/declares.json"), "{}").unwrap();
    std::fs::write(crates.join("plane-two/declares.json"), "{}").unwrap();
    let at = |c: &str| super::declares_file(crates.join(c).to_str().unwrap());
    assert_eq!(
        at("plane-three"),
        None,
        "a sibling's declares file is not this crate's"
    );
    assert_eq!(
        at("plane-one"),
        Some(crates.join("plane-one/declares.json"))
    );
    assert_eq!(
        at("plane-two"),
        Some(crates.join("plane-two/declares.json"))
    );
    std::fs::remove_dir_all(&tree).unwrap();
}

/// The host's secret lending, as the suite lends it: each secret-ref key (a dotted path) is taken
/// out of the settings and its string lent, in the Statement's order; an absent key lends empty
/// bytes; settings with no refs pass through byte for byte.
#[test]
fn the_suite_lends_the_statements_secret_refs_out_of_the_settings() {
    use super::lend_secrets;
    let refs = [
        "token".to_owned(),
        "auth.key".to_owned(),
        "absent".to_owned(),
    ];
    let raw = br#"{"addr":"https://localhost:1","token":"s.t","auth":{"key":"k","x":1}}"#;
    let (settings, secrets) = lend_secrets(&refs, raw, false);
    let v: serde_json::Value = serde_json::from_slice(&settings).unwrap();
    assert_eq!(
        v,
        serde_json::json!({"addr": "https://localhost:1", "auth": {"x": 1}})
    );
    assert_eq!(secrets, [b"s.t".to_vec(), b"k".to_vec(), Vec::new()]);
    // The secret kind's host leaves the keys in the settings, and lends the same material.
    let (kept, lent) = lend_secrets(&refs, raw, true);
    assert_eq!(kept, raw.to_vec());
    assert_eq!(lent, secrets);
    assert_eq!(
        lend_secrets(&[], b"{ \"a\": 1 }", false),
        (b"{ \"a\": 1 }".to_vec(), Vec::new())
    );
}

/// RED (store-mysql #16): the store script meters only keys it has put, so a store whose metering
/// rows reference its keys (MySQL's fk_metering_key) holds every metering write: no `meter(..)` call
/// in the script names a literal key id.
#[test]
fn red_the_store_script_meters_only_keys_it_has_put() {
    let script = include_str!("../conformance/store.rs");
    let literal = regex_lite_meter(script);
    assert!(
        literal.is_empty(),
        "metering names keys it never put: {literal:?}"
    );
}

/// Every `meter("<literal>", ..)` call in `script`.
fn regex_lite_meter(script: &str) -> Vec<String> {
    script
        .match_indices("meter(\"")
        .map(|(at, _)| {
            let rest = &script[at + 7..];
            rest[..rest.find('"').unwrap_or(0)].to_owned()
        })
        .collect()
}

// ── THE ADMISSION AND CONNECTION RED ARMS (`red.rs`), over the loader's own fixtures ─────────────

mod red_arms {
    use std::panic::{catch_unwind, AssertUnwindSafe};

    use busbar_contract::abi::mechanism::door::DoorFn;

    use super::super::{
        red_cross_instance_conn, red_statement, red_undeclared_need, red_wrong_kind, Subject,
    };

    /// The fixtures of two kinds: the plane door and the hook door, each its linked door and the
    /// example `cdylib` that is its dropped-in image.
    fn fixtures() -> Vec<(DoorFn, &'static str)> {
        vec![
            (
                crate::plane_door_plugin::door as DoorFn,
                "plane_door_plugin",
            ),
            (
                crate::hook_door_conformance_tests::hook_door_plugin::conforming::door,
                "hook_door",
            ),
        ]
    }

    fn panics(f: impl FnOnce()) -> String {
        let e = catch_unwind(AssertUnwindSafe(f)).expect_err("the arm fails");
        e.downcast_ref::<String>()
            .cloned()
            .or_else(|| e.downcast_ref::<&str>().map(|s| (*s).to_string()))
            .unwrap_or_default()
    }

    /// GREEN: an honest door of each kind passes all four arms (its mismatched Statement, every
    /// other kind, an undeclared need and another instance's connection all refused; its honest
    /// twin admitted and connected).
    #[test]
    fn an_honest_door_of_each_kind_passes_the_four_arms() {
        for (door, krate) in fixtures() {
            // Absent, the example `cdylib` fails the test naming its build command: never a skip.
            crate::both_ways::example_cdylib(krate);
            let s = Subject::new(door, krate, "{}");
            red_undeclared_need(&s);
            red_cross_instance_conn(&s);
            red_statement(&s);
            red_wrong_kind(&s);
        }
    }

    /// RED: a plugin whose dropped-in library is not its linked door (the plane door shipped with
    /// the hook library) fails the Statement arm and the kind arm, on their honest twins.
    #[test]
    fn red_a_plugin_whose_library_is_not_its_door_fails_the_arms() {
        crate::both_ways::example_cdylib("plane_door_plugin");
        crate::both_ways::example_cdylib("hook_door");
        let s = Subject::new(crate::plane_door_plugin::door, "hook_door", "{}");
        let text = panics(|| red_statement(&s));
        assert!(text.contains("honest library"), "{text}");
        let text = panics(|| red_wrong_kind(&s));
        assert!(text.contains("honest library"), "{text}");
    }
}
