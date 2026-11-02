// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::panic::{catch_unwind, AssertUnwindSafe};

use serde_json::Value;

use super::{cancel, drive, open, sessions, sessions_contract, Carried, Session};
use crate::conformance::{
    crossings, dispatcher, exact, load, perturbed, same, Fold, Leg, Recorder, Subject,
};
use crate::dispatch::kinds::plane::Plane;

const PUBLIC_URL: &str = "https://node.example/base";

const SESSIONS: &str = r#"[
  { "name": "live", "unit": 40, "stream": 40, "claim": 1, "ticket": true, "steps": [
    { "label": "upgrade", "arrive": { "method": "GET", "target": "/upgrade", "body": "hi" },
      "want": { "outcome": "Ready", "route_flags": ["session"],
                "route": { "class": "pool", "entry": "" } } },
    { "label": "uplink", "piece": { "from": "caller", "bytes": "hello" },
      "want": { "outcome": "Ready", "emitted": "", "to_far_end": false, "units": [] } },
    { "label": "drive", "drive": true, "want": { "outcome": "Ready", "ready": [40] } },
    { "label": "collect", "piece": { "from": "kernel" },
      "want": { "outcome": "Ready", "emitted": "ping", "done": false } },
    { "label": "drive again", "drive": true, "want": { "outcome": "Ready", "ready": [] } },
    { "label": "answer head",
      "piece": { "from": "far_end", "status": 200, "fields": [["x-up", "1"]], "bytes": "abc" },
      "want": { "outcome": "Ready", "emitted": "abc", "status": 200, "done": false,
                "fields": [["x-plane", "door"]], "units": [[0, 3]] } },
    { "label": "answer tail", "piece": { "from": "far_end", "bytes": "de" },
      "want": { "outcome": "Ready", "emitted": "de", "done": false, "units": [[0, 2]] } },
    { "label": "answer short",
      "piece": { "from": "far_end",
                 "bytes": [{ "repeat": "x", "times": 3 }], "short": "units" },
      "want": { "outcome": "Ready", "emitted": "xxx", "done": false, "units": [[0, 3]] } },
    { "label": "project", "project": { "target": "/upgrade", "body": "hi" },
      "want": { "outcome": "Ready", "rewritten": false, "body_has": ["hi"] } },
    { "label": "tick", "tick": { "now_ns": 1000 },
      "want": { "outcome": "Ready", "next": 1001000 } },
    { "label": "uplink again", "piece": { "from": "caller", "bytes": "again" },
      "want": { "outcome": "Ready", "to_far_end": false } },
    { "label": "cancel", "cancel": true, "want": { "outcome": "Ready", "disposition": 3 } },
    { "label": "drive after cancel", "drive": true, "want": { "outcome": "Ready", "ready": [] } } ] },
  { "name": "request", "unit": 41, "reply_cap": 4, "steps": [
    { "label": "attempt", "piece": { "from": "kernel", "attempt": 1 },
      "want": { "outcome": "Ready", "emitted": "m1", "to_far_end": true, "verb": "POST",
                "target": "/up", "need": 0 } },
    { "label": "answer", "piece": { "from": "far_end", "status": 200, "last": true,
                                    "bytes": "abcdef" },
      "want": { "outcome": "Ready", "emitted": "abcd", "more": 1, "done": false } } ] },
  { "name": "terminal", "unit": 42, "stream": 42, "claim": 1, "steps": [
    { "label": "upgrade", "arrive": { "method": "GET", "target": "/upgrade", "body": "hi" },
      "want": { "outcome": "Ready", "route_flags": ["session"] } },
    { "label": "answer head", "piece": { "from": "far_end", "status": 200, "bytes": "abc" },
      "want": { "outcome": "Ready", "emitted": "abc", "done": false, "units": [[0, 3]] } },
    { "label": "answer tail", "piece": { "from": "far_end", "last": true, "bytes": "de" },
      "want": { "outcome": "Ready", "emitted": "de", "done": true, "units": [[0, 2]] } } ] },
  { "name": "terminal-short", "unit": 43, "stream": 43, "claim": 1, "steps": [
    { "label": "upgrade", "arrive": { "method": "GET", "target": "/upgrade", "body": "hi" },
      "want": { "outcome": "Ready", "route_flags": ["session"] } },
    { "label": "answer short",
      "piece": { "from": "far_end", "last": true,
                 "bytes": [{ "repeat": "x", "times": 3 }], "short": "units" },
      "want": { "outcome": "Ready", "emitted": "xxx", "done": true, "units": [[0, 3]] } } ] }
]"#;

fn subject() -> Subject {
    Subject::new(
        crate::plane_door_plugin::door,
        "plane_door_plugin",
        &format!(r#"{{ "plane": {{ "sessions": {SESSIONS} }} }}"#),
    )
}

fn fold_over(s: &Subject, leg: Leg, url: Option<&str>, all: &Value) -> Fold {
    let d = dispatcher();
    let p = load::<Plane>(s, leg, s.bind(&d, "plane")).expect("the plane fixture loads");
    let mut r = Recorder::new(crossings(&p));
    r.line("open", 1, || open(&p, b"{}", url.map(str::as_bytes)));
    let carried = Carried {
        member: b"m1".to_vec(),
        pool: Some(b"p1".to_vec()),
        caller_ref: Some(b"c0ffee".to_vec()),
        host: None,
    };
    let driver = d.driver(&p, 0);
    sessions(&mut r, (&p, &d, driver), &Session::all(all), &carried);
    r.fold()
}

fn fold(s: &Subject, leg: Leg) -> Fold {
    fold_over(
        s,
        leg,
        Some(PUBLIC_URL),
        &s.kind_inputs("plane")["sessions"],
    )
}

fn panics(f: impl FnOnce()) -> String {
    let e = catch_unwind(AssertUnwindSafe(f)).expect_err("refused");
    e.downcast_ref::<String>()
        .cloned()
        .or_else(|| e.downcast_ref::<&str>().map(|s| (*s).to_string()))
        .unwrap_or_default()
}

fn dropped_built() -> std::path::PathBuf {
    crate::both_ways::example_cdylib("plane_door_plugin")
}

#[test]
fn the_sessions_leg_runs_both_ways_at_its_pins_and_answers_as_wanted() {
    let s = subject();
    let linked = fold(&s, Leg::Linked);
    dropped_built();
    let dropped = fold(&s, Leg::Dropped);
    for f in [&linked, &dropped] {
        exact(f).unwrap_or_else(|e| panic!("{e}"));
        sessions_contract(f, &s.kind_inputs("plane")["sessions"]);
    }
    same(&linked, &dropped).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        linked[0]
            .answer
            .contains("claims=[POST /echo, GET /upgrade] "),
        "{}",
        linked[0].answer
    );
    for label in ["live answer short", "terminal-short answer short"] {
        let short = linked
            .iter()
            .find(|st| st.label == label)
            .expect("the short step ran");
        assert_eq!((short.crossed, short.pinned), (2, 2), "{}", short.answer);
    }
}

#[test]
fn a_terminal_session_refuses_another_piece_without_crossing_and_allows_a_fresh_unit() {
    use super::{arrive, on_piece, Arrival, Given, Unit, CAP};
    use crate::conformance::close;
    use busbar_contract::abi::mechanism::call::Outcome;
    use busbar_contract::abi::plane::{EMIT_DONE, FROM_FAR_END, PIECE_HAS_STATUS, PIECE_LAST};

    dropped_built();
    let s = subject();
    for leg in [Leg::Linked, Leg::Dropped] {
        let d = dispatcher();
        let p = load::<Plane>(&s, leg, s.bind(&d, "terminal-session"))
            .expect("the real plane fixture loads");
        assert!(open(&p, b"{}", Some(PUBLIC_URL.as_bytes())).starts_with("Ready "));
        let carried = Carried {
            member: b"m1".to_vec(),
            pool: Some(b"p1".to_vec()),
            caller_ref: Some(b"c0ffee".to_vec()),
            host: None,
        };
        let arrival = Arrival {
            unit: 90,
            claim: 1,
            method: b"GET".to_vec(),
            target: b"/upgrade".to_vec(),
            fields: Vec::new(),
            route: false,
        };
        assert!(arrive(&p, &arrival, b"hi").starts_with("Ready "));
        let unit = Unit::mint(&d, 1024);
        let terminal = Given {
            unit: 90,
            stream: 90,
            claim: 1,
            from: FROM_FAR_END,
            flags: PIECE_HAS_STATUS | PIECE_LAST,
            bytes: b"closed",
            attempt_no: 0,
            status: 200,
            head: &[],
        };
        let first = on_piece(&p, &d, &unit, terminal, (CAP, CAP), &carried);
        assert_eq!(first.called.outcome, Outcome::Ready);
        assert_ne!(first.out().flags & EMIT_DONE, 0);
        let before = crossings(&p).read();
        let refused = on_piece(&p, &d, &unit, terminal, (CAP, CAP), &carried);
        assert_eq!(refused.called.outcome, Outcome::Refused);
        assert_eq!(refused.out().emitted, 0);
        assert_eq!(crossings(&p).read(), before, "no post-DONE crossing");

        assert!(arrive(&p, &arrival.for_unit(91), b"hi").starts_with("Ready "));
        let fresh = Unit::mint(&d, 1024);
        let before = crossings(&p).read();
        let answered = on_piece(
            &p,
            &d,
            &fresh,
            Given {
                unit: 91,
                stream: 91,
                bytes: b"fresh",
                ..terminal
            },
            (CAP, CAP),
            &carried,
        );
        assert_eq!(answered.called.outcome, Outcome::Ready);
        assert_eq!(answered.out().emitted, 5);
        assert_ne!(answered.out().flags & EMIT_DONE, 0);
        assert_eq!(crossings(&p).read(), (before.0 + 1, before.1));
        unit.end(&d);
        fresh.end(&d);
        assert_eq!(close(&p).outcome, Outcome::Ready);
    }
}

#[test]
fn absent_a_public_url_open_hands_none() {
    let s = subject();
    let f = fold_over(&s, Leg::Linked, None, &Value::Null);
    assert_eq!(f.len(), 1);
    assert!(
        f[0].answer.contains("claims=[POST /echo] "),
        "{}",
        f[0].answer
    );
}

#[test]
fn red_a_moved_count_on_a_session_step_is_refused() {
    let f = fold(&subject(), Leg::Linked);
    exact(&f).unwrap_or_else(|e| panic!("the honest fold fails before the RED arm: {e}"));
    assert!(f.len() > 10, "the sessions leg ran: {f:?}");
    for at in 0..f.len() {
        assert!(
            exact(&perturbed(f.clone(), at)).is_err(),
            "a moved count at '{}' passed",
            f[at].label
        );
    }
}

fn wanting(label: &str, edit: impl Fn(&mut Value)) -> Value {
    let mut all: Value = serde_json::from_str(SESSIONS).expect("the inputs are JSON");
    for s in all.as_array_mut().into_iter().flatten() {
        let name = s["name"].as_str().unwrap_or_default().to_string();
        for st in s["steps"].as_array_mut().into_iter().flatten() {
            if format!("{name} {}", st["label"].as_str().unwrap_or_default()) == label {
                edit(&mut st["want"]);
            }
        }
    }
    all
}

#[test]
fn red_a_session_step_answering_otherwise_than_wanted_is_refused() {
    let f = fold(&subject(), Leg::Linked);
    for (label, key, v) in [
        ("live answer head", "units", serde_json::json!([[0, 4]])),
        ("live uplink", "outcome", serde_json::json!("Refused")),
        ("live drive", "ready", serde_json::json!([41])),
        ("live project", "body_has", serde_json::json!(["bye"])),
        ("request attempt", "verb", serde_json::json!("GET")),
        (
            "live upgrade",
            "route",
            serde_json::json!({"class": "direct", "entry": "e"}),
        ),
        ("live upgrade", "route_flags", serde_json::json!(["once"])),
        ("live tick", "next", serde_json::json!(1000)),
        ("live cancel", "disposition", serde_json::json!(2)),
        ("live drive after cancel", "ready", serde_json::json!([40])),
    ] {
        let all = wanting(label, |w| w[key] = v.clone());
        let text = panics(|| sessions_contract(&f, &all));
        assert!(text.contains(label), "{label}/{key}: {text}");
    }
}

#[test]
fn red_a_want_the_suite_does_not_know_is_refused() {
    let f = fold(&subject(), Leg::Linked);
    let all = wanting("live uplink", |w| w["emited"] = serde_json::json!("x"));
    let text = panics(|| sessions_contract(&f, &all));
    assert!(text.contains("emited"), "{text}");
}

#[test]
fn red_a_piece_called_short_that_is_not_is_refused() {
    let s = subject();
    let mut all: Value = serde_json::from_str(SESSIONS).expect("the inputs are JSON");
    all[0]["steps"][1]["piece"]["short"] = serde_json::json!("units");
    let f = fold_over(&s, Leg::Linked, Some(PUBLIC_URL), &all);
    let e = exact(&f).expect_err("one crossing where two are pinned");
    assert!(e.contains("live uplink"), "{e}");
    let text = panics(|| sessions_contract(&f, &all));
    assert!(text.contains("live uplink"), "{text}");
}

#[test]
fn a_session_naming_its_member_is_attempted_on_that_member() {
    let s = subject();
    let named = |member: Option<&str>| {
        let mut one = serde_json::json!({ "name": "other", "unit": 42, "steps": [
            { "label": "attempt", "piece": { "from": "kernel", "attempt": 1 },
              "want": { "outcome": "Ready", "emitted": "m2", "to_far_end": true } } ] });
        if let Some(m) = member {
            one["member"] = serde_json::json!(m);
        }
        serde_json::json!([one])
    };
    let all = named(Some("m2"));
    let f = fold_over(&s, Leg::Linked, None, &all);
    exact(&f).unwrap_or_else(|e| panic!("{e}"));
    sessions_contract(&f, &all);

    let all = named(None);
    let f = fold_over(&s, Leg::Linked, None, &all);
    let text = panics(|| sessions_contract(&f, &all));
    assert!(text.contains("other attempt"), "{text}");
}

#[test]
fn red_inputs_naming_a_step_twice_are_refused() {
    let mut all: Value = serde_json::from_str(SESSIONS).expect("the inputs are JSON");
    all[1]["name"] = serde_json::json!("live");
    assert!(panics(|| {
        Session::all(&all);
    })
    .contains("share a name"));
    let mut all: Value = serde_json::from_str(SESSIONS).expect("the inputs are JSON");
    all[0]["steps"][2]["label"] = serde_json::json!("uplink");
    assert!(panics(|| {
        Session::all(&all);
    })
    .contains("share a label"));
}

mod pieces_on_tickets {
    use std::sync::atomic::{AtomicPtr, Ordering};

    use busbar_contract::abi::mechanism::call::{
        InHead, OutHead, Outcome, RawOutcome, FLAG_RESUME,
    };
    use busbar_contract::abi::mechanism::door::Door;
    use busbar_contract::abi::plane::{OnPieceIn, Ops};

    use super::{fold, sessions_contract, SESSIONS};
    use crate::conformance::{exact, test_door, test_op, Leg, Subject, TestDoor, TestOp};
    use crate::dispatch::ticket::host_wake;

    static REAL_ON_PIECE: AtomicPtr<()> = AtomicPtr::new(std::ptr::null_mut());
    static SLOT: AtomicPtr<Door> = AtomicPtr::new(std::ptr::null_mut());

    struct OnPiecePends;

    impl TestOp for OnPiecePends {
        fn op(
            instance: *mut std::ffi::c_void,
            input: *const std::ffi::c_void,
            out: *mut std::ffi::c_void,
        ) -> RawOutcome {
            // SAFETY: the host hands `on_piece` an `OnPieceIn` and an `OnPieceOut`.
            unsafe {
                let head = input.cast::<InHead>().read();
                if head.flags & FLAG_RESUME == 0 {
                    if head.ticket.generation != 0 {
                        host_wake(head.host, head.ticket);
                    }
                    (*out.cast::<OutHead>()).outcome = RawOutcome::of(Outcome::Pending);
                    return RawOutcome::of(Outcome::Pending);
                }
                let mut fresh: OnPieceIn = input.cast::<OnPieceIn>().read();
                fresh.head.flags &= !FLAG_RESUME;
                let real: busbar_contract::abi::mechanism::call::Op =
                    std::mem::transmute(REAL_ON_PIECE.load(Ordering::SeqCst));
                real(instance, std::ptr::from_ref(&fresh).cast(), out)
            }
        }
    }

    struct PendingDoor;

    impl TestDoor for PendingDoor {
        fn door() -> *const Door {
            let have = SLOT.load(Ordering::SeqCst);
            if !have.is_null() {
                return have;
            }
            let real: Door = *crate::plane_door_plugin::door();
            // SAFETY: the fixture's door and its plane table are `'static`.
            let ops: Ops = unsafe { real.ops().cast::<Ops>().read_unaligned() };
            REAL_ON_PIECE.store(
                ops.on_piece.expect("the fixture answers pieces") as *mut (),
                Ordering::SeqCst,
            );
            let ops: &'static Ops = Box::leak(Box::new(Ops {
                on_piece: Some(test_op::<OnPiecePends>),
                ..ops
            }));
            let door = Box::into_raw(Box::new(unsafe {
                Door::__from_parts(busbar_contract::abi::mechanism::door::DoorParts {
                    ops: std::ptr::from_ref(ops).cast(),
                    ..real.parts()
                })
            }));
            SLOT.store(door, Ordering::SeqCst);
            door
        }
    }

    #[test]
    fn red_a_piece_that_waits_is_resumed_on_its_units_ticket_never_faulted_ticketless() {
        let s = Subject::of_raw(
            test_door::<PendingDoor>,
            "plane_door_plugin",
            &format!(r#"{{ "plane": {{ "sessions": {SESSIONS} }} }}"#),
        );
        let f = fold(&s, Leg::Linked);
        exact(&f).unwrap_or_else(|e| panic!("{e}"));
        sessions_contract(&f, &s.kind_inputs("plane")["sessions"]);
        for label in [
            "live uplink",
            "live collect",
            "live answer head",
            "live answer tail",
            "live answer short",
            "terminal answer head",
            "terminal answer tail",
            "terminal-short answer short",
            "request attempt",
            "request answer",
        ] {
            let st = f
                .iter()
                .find(|st| st.label == label)
                .unwrap_or_else(|| panic!("the script ran no step '{label}'"));
            assert!(st.resumes >= 1, "{label} was never resumed: {}", st.answer);
        }
    }
}

#[test]
fn red_a_cancel_naming_no_session_ticket_ends_nothing() {
    let s = subject();
    let d = dispatcher();
    let p = load::<Plane>(&s, Leg::Linked, s.bind(&d, "plane")).expect("the plane fixture loads");
    let mut r = Recorder::new(crossings(&p));
    r.line("open", 1, || open(&p, b"{}", Some(PUBLIC_URL.as_bytes())));
    let all: Value = serde_json::from_str(
        r#"[{ "name": "bare", "unit": 50, "stream": 50, "claim": 1, "steps": [
              { "label": "uplink", "piece": { "from": "caller", "bytes": "x" },
                "want": { "outcome": "Ready" } } ] }]"#,
    )
    .expect("JSON");
    let carried = Carried {
        member: b"m1".to_vec(),
        pool: None,
        caller_ref: None,
        host: None,
    };
    let driver = d.driver(&p, 0);
    sessions(&mut r, (&p, &d, driver), &Session::all(&all), &carried);
    r.line("cancel", 1, || {
        cancel(&p, busbar_contract::abi::mechanism::ticket::Ticket::NONE)
    });
    r.line("drive", 1, || {
        let (c, ready) = drive(&p, driver);
        format!("{} ready={ready:?}", crate::conformance::called(&c))
    });
    let f = r.fold();
    exact(&f).unwrap_or_else(|e| panic!("{e}"));
    assert!(f[3].answer.ends_with("ready=[50]"), "{}", f[3].answer);
}

#[test]
fn red_a_cancel_in_a_session_with_no_ticket_is_refused() {
    let mut all: Value = serde_json::from_str(SESSIONS).expect("the inputs are JSON");
    all[0]["ticket"] = Value::Bool(false);
    assert!(panics(|| {
        Session::all(&all);
    })
    .contains("cancels on its ticket"));
}

#[test]
fn red_a_tick_pinned_to_wake_that_wakes_nothing_is_refused() {
    let s = subject();
    let mut all: Value = serde_json::from_str(SESSIONS).expect("the inputs are JSON");
    all[0]["steps"][9]["tick"]["wakes"] = Value::Bool(true);
    assert_eq!(all[0]["steps"][9]["label"], "tick");
    let f = fold_over(&s, Leg::Linked, Some(PUBLIC_URL), &all);
    let e = exact(&f).expect_err("one crossing where two are pinned");
    assert!(e.contains("live tick") && e.contains("pinned 2"), "{e}");
}

const HOST: &str = r#"{ "entitled": [{ "target": "door:echo", "units": [80, 82] }],
                        "trusted": [["m1", "echo", "none"]] }"#;

const SERVED: &str = r#"[
  { "name": "granted", "unit": 80, "steps": [
    { "label": "attempt", "piece": { "from": "kernel", "attempt": 1 },
      "want": { "outcome": "Ready", "to_far_end": true, "emitted": "m1", "lane": "",
                "records": [] } },
    { "label": "answer", "piece": { "from": "far_end", "status": 200, "last": true,
                                    "bytes": "abc" },
      "want": { "outcome": "Ready", "emitted": "abc", "done": true, "lane": "lane",
                "records": [["put", 0, "k", "v"]], "units": [[0, 3]] } } ] },
  { "name": "ungranted", "unit": 81, "steps": [
    { "label": "attempt", "piece": { "from": "kernel", "attempt": 1 },
      "want": { "outcome": "Refused", "to_far_end": false } } ] },
  { "name": "hooks", "unit": 82, "steps": [
    { "label": "project", "project": { "body": "hi" },
      "want": { "outcome": "Ready", "turns": [["user", "hi"]], "body_has": ["hi"] } } ] }
]"#;

fn served_fold(leg: Leg, host: &str, all: &Value) -> Fold {
    let s = subject();
    let host = super::host::Host::of(&serde_json::from_str(host).expect("JSON"))
        .expect("a host is stated");
    let d = std::sync::Arc::new(crate::dispatch::Dispatcher::with_services(
        crate::dispatch::DispatchConfig::default(),
        std::sync::Arc::new(host),
    ));
    let p = load::<Plane>(&s, leg, s.bind(&d, "plane")).expect("the plane fixture loads");
    let mut r = Recorder::new(crossings(&p));
    r.line("open", 1, || open(&p, b"{}", None));
    let carried = Carried {
        member: b"m1".to_vec(),
        pool: None,
        caller_ref: None,
        host: None,
    };
    let driver = d.driver(&p, 0);
    sessions(&mut r, (&p, &d, driver), &Session::all(all), &carried);
    r.fold()
}

#[test]
fn the_host_tables_gate_the_unit_and_the_lane_records_and_turns_are_judged() {
    let all: Value = serde_json::from_str(SERVED).expect("JSON");
    let linked = served_fold(Leg::Linked, HOST, &all);
    dropped_built();
    let dropped = served_fold(Leg::Dropped, HOST, &all);
    for f in [&linked, &dropped] {
        exact(f).unwrap_or_else(|e| panic!("{e}"));
        sessions_contract(f, &all);
    }
    same(&linked, &dropped).unwrap_or_else(|e| panic!("{e}"));
}

#[test]
fn red_a_member_the_host_does_not_approve_is_not_sent_to() {
    let all: Value = serde_json::from_str(SERVED).expect("JSON");
    let host = HOST.replace(
        r#"["m1", "echo", "none"]"#,
        r#"["m1", "echo", "not_approved"]"#,
    );
    let f = served_fold(Leg::Linked, &host, &all);
    let text = panics(|| sessions_contract(&f, &all));
    assert!(text.contains("granted attempt"), "{text}");
}

#[test]
fn red_a_lane_record_or_turn_other_than_answered_is_refused() {
    let f = served_fold(
        Leg::Linked,
        HOST,
        &serde_json::from_str(SERVED).expect("JSON"),
    );
    for (label, key, v) in [
        ("granted answer", "lane", serde_json::json!("other")),
        ("granted answer", "lane", serde_json::json!("")),
        (
            "granted answer",
            "records",
            serde_json::json!([["put", 0, "k", "w"]]),
        ),
        (
            "granted answer",
            "records",
            serde_json::json!([["audit", 0, "k", "v"]]),
        ),
        ("granted answer", "records", serde_json::json!([])),
        (
            "granted attempt",
            "records",
            serde_json::json!([["put", 0, "k", "v"]]),
        ),
        (
            "hooks project",
            "turns",
            serde_json::json!([["user", "ho"]]),
        ),
        ("hooks project", "turns", serde_json::json!([])),
    ] {
        let mut all: Value = serde_json::from_str(SERVED).expect("JSON");
        for s in all.as_array_mut().into_iter().flatten() {
            let name = s["name"].as_str().unwrap_or_default().to_string();
            for st in s["steps"].as_array_mut().into_iter().flatten() {
                if format!("{name} {}", st["label"].as_str().unwrap_or_default()) == label {
                    st["want"][key] = v.clone();
                }
            }
        }
        let text = panics(|| sessions_contract(&f, &all));
        assert!(text.contains(label), "{label}/{key}={v}: {text}");
    }
}

#[test]
fn red_a_unit_the_grant_does_not_list_is_entitled_to_nothing() {
    let host = super::host::Host::of(&serde_json::from_str(HOST).expect("JSON")).expect("host");
    let caller = busbar_contract::services::Caller {
        instance: std::sync::Arc::from("i"),
        plugin: std::sync::Arc::from("p"),
        kind: busbar_contract::abi::mechanism::KindCode::Plane,
    };
    use crate::dispatch::HostServices;
    use busbar_contract::abi::host::service::{ENTITLED, NOT_ENTITLED};
    assert_eq!(
        host.entitlement_check(&caller, Some(80), "door:echo").value,
        ENTITLED
    );
    assert_eq!(
        host.entitlement_check(&caller, Some(81), "door:echo").value,
        NOT_ENTITLED
    );
    assert_eq!(
        host.entitlement_check(&caller, None, "door:echo").value,
        NOT_ENTITLED
    );
    assert_eq!(
        host.entitlement_check(&caller, Some(80), "door:other")
            .value,
        NOT_ENTITLED
    );
}

fn step(label: &str, answer: &str) -> crate::conformance::Step {
    crate::conformance::Step {
        label: label.into(),
        answer: answer.into(),
        crossed: 1,
        pinned: 1,
        resumes: 0,
    }
}

fn attempts(far: bool, narrow_body: &str) -> Fold {
    let a = format!("Ready lease=false  emitted= more=0 to_far_end={far} done=false");
    let b = "Ready lease=false  emitted=req more=0 to_far_end=true done=false";
    vec![
        step("attempt", &a),
        step("body", b),
        step("narrow arrive", "Ready lease=false  op_class=0"),
        step("narrow attempt", &a),
        step("narrow body", narrow_body),
        step("short arrive", "Ready lease=false  op_class=0"),
        step("short attempt", &a),
        step("short body", b),
    ]
}

#[test]
fn the_attempt_and_every_arrived_units_body_are_judged() {
    let ok = "Ready lease=false  emitted=req more=0 to_far_end=true done=false";
    let taken: Value = serde_json::json!({ "attempt": { "to_far_end": false }, "arrive_each": true, "request_out": "req" });
    super::attempts_and_bodies(&attempts(false, ok), &taken);
    super::attempts_and_bodies(
        &attempts(true, ok),
        &serde_json::json!({ "request_out": "req" }),
    );

    let text = panics(|| {
        super::attempts_and_bodies(
            &attempts(false, ok),
            &serde_json::json!({ "request_out": "req" }),
        );
    });
    assert!(text.contains("attempt"), "{text}");

    let text = panics(|| {
        super::attempts_and_bodies(
            &attempts(
                false,
                "Ready lease=false  emitted=other more=0 to_far_end=true done=false",
            ),
            &taken,
        );
    });
    assert!(text.contains("narrow body"), "{text}");

    let mut f = attempts(false, ok);
    f.retain(|s| s.label != "short arrive");
    let text = panics(|| super::attempts_and_bodies(&f, &taken));
    assert!(text.contains("short arrive"), "{text}");
}

fn request_unit_inputs(extra: Value) -> Value {
    let mut k = serde_json::json!({
        "bad_settings": [{ "nonsense": 1 }],
        "refresh_settings": {},
        "member": "m",
        "claimed": { "unit": 7, "method": "POST", "target": "/v1/x" },
        "unclaimed": { "unit": 8, "method": "GET", "target": "/v1/y", "status": 404 },
        "refusal": { "status": 403, "text": "denied" }
    });
    if let (Some(k), Some(extra)) = (k.as_object_mut(), extra.as_object()) {
        k.extend(extra.clone());
    }
    k
}

#[test]
fn a_plane_with_no_request_unit_states_none_and_a_stray_fixture_is_refused() {
    let none = super::Inputs::of(&request_unit_inputs(serde_json::json!({
        "request_unit": false
    })));
    assert!(!none.request_unit);
    assert!(none.request.is_empty() && none.answer.is_empty());

    let default = super::Inputs::of(&request_unit_inputs(serde_json::json!({
        "request": "q",
        "request_out": "q",
        "far_end": { "status": 200, "fields": [], "answer": "a", "answer_out": "a", "units": [] },
        "narrow": { "unit": 9, "reply_cap": 4, "more": 1 },
        "short": { "unit": 11 }
    })));
    assert!(
        default.request_unit,
        "a plane that states nothing serves a request unit"
    );
    assert_eq!(default.answer, b"a");

    let stray = catch_unwind(AssertUnwindSafe(|| {
        super::Inputs::of(&request_unit_inputs(serde_json::json!({
            "request_unit": false,
            "far_end": { "status": 200, "fields": [], "answer": "a" }
        })))
    }));
    assert!(
        stray.is_err(),
        "a far end beside request_unit: false would be read by no leg"
    );
}
