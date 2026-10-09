// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE SCRIPT'S PUBLIC URL AND SESSIONS LEG (`conformance/plane.rs`), over the loader's own
//! plane fixture (`tests/fixtures/plane_door_plugin.rs`), linked and dropped in: `open` hands the
//! deployment's public URL (the fixture then claims its session door), and the sessions leg drives
//! a live session (its arrival, the caller's piece, `drive`, a collection, the far end's answer in
//! two pieces, one met short, `project`) and a request unit (its ATTEMPT, an answer through a
//! narrow reply buffer), each step at its pinned crossing count, the two folds equal, every step
//! answering as its `want` states. RED: a moved count on any session step, a step answering
//! otherwise than wanted, a want the suite does not know, and a piece called short that is not.

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
    { "label": "answer tail", "piece": { "from": "far_end", "last": true, "bytes": "de" },
      "want": { "outcome": "Ready", "emitted": "de", "done": true, "units": [[0, 2]] } },
    { "label": "answer short",
      "piece": { "from": "far_end", "last": true,
                 "bytes": [{ "repeat": "x", "times": 3 }], "short": "units" },
      "want": { "outcome": "Ready", "emitted": "xxx", "done": true, "units": [[0, 3]] } },
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
      "want": { "outcome": "Ready", "emitted": "abcd", "more": 1, "done": false } } ] }
]"#;

fn subject() -> Subject {
    Subject::new(
        crate::plane_door_plugin::door,
        "plane_door_plugin",
        &format!(r#"{{ "plane": {{ "sessions": {SESSIONS} }} }}"#),
    )
}

/// The fixture opened (under `url`), then the sessions leg over `sessions`, as one fold.
fn fold_over(s: &Subject, leg: Leg, url: Option<&str>, all: &Value) -> Fold {
    let d = dispatcher();
    let p = load::<Plane>(s, leg, s.bind(&d, "plane")).expect("the plane fixture loads");
    let mut r = Recorder::new(crossings(&p));
    r.line("open", 1, || open(&p, b"{}", url.map(str::as_bytes)));
    let carried = Carried {
        member: b"m1".to_vec(),
        pool: Some(b"p1".to_vec()),
        caller_ref: Some(b"c0ffee".to_vec()),
    };
    sessions(&mut r, &p, &d, &Session::all(all), &carried);
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

/// Whether the fixture's example `cdylib` is built in this target dir (`cargo test` builds
/// examples; `--lib` alone does not). Under CI a missing artifact is a failure, never a skip.
fn dropped_built() -> bool {
    let built = std::env::current_exe()
        .ok()
        .and_then(|exe| Some(exe.parent()?.parent()?.join("examples")))
        .is_some_and(|dir| {
            dir.join(crate::plugin_library_filename("plane_door_plugin"))
                .exists()
        });
    assert!(
        built || std::env::var_os("CI").is_none(),
        "the plane_door_plugin example cdylib is not built under CI; a both-ways proof must not skip"
    );
    built
}

/// GREEN: both ways, every session step at its pin, the folds equal, every want met; the open
/// under the public URL claims the session door.
#[test]
fn the_sessions_leg_runs_both_ways_at_its_pins_and_answers_as_wanted() {
    let s = subject();
    let linked = fold(&s, Leg::Linked);
    let mut folds = vec![&linked];
    let dropped = dropped_built().then(|| fold(&s, Leg::Dropped));
    folds.extend(dropped.as_ref());
    for f in &folds {
        exact(f).unwrap_or_else(|e| panic!("{e}"));
        sessions_contract(f, &s.kind_inputs("plane")["sessions"]);
    }
    match &dropped {
        Some(dropped) => same(&linked, dropped).unwrap_or_else(|e| panic!("{e}")),
        None => eprintln!("skip: the plane_door_plugin example cdylib is not built"),
    }
    assert!(
        linked[0]
            .answer
            .contains("claims=[POST /echo, GET /upgrade] "),
        "{}",
        linked[0].answer
    );
    let short = linked
        .iter()
        .find(|st| st.label == "live answer short")
        .expect("the short step ran");
    assert_eq!((short.crossed, short.pinned), (2, 2), "{}", short.answer);
}

/// With no public URL named, `open` hands none: the fixture claims no session door.
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

/// RED: a pinned count moved by one on any session step is refused by the exact comparator.
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

/// The sessions inputs with step `label`'s want edited by `edit`.
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

/// RED: a step that answers otherwise than its want states fails the contract, naming the step:
/// another count, another outcome, another ready stream, another body.
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

/// RED: a want the suite does not know is refused, never read as met.
#[test]
fn red_a_want_the_suite_does_not_know_is_refused() {
    let f = fold(&subject(), Leg::Linked);
    let all = wanting("live uplink", |w| w["emited"] = serde_json::json!("x"));
    let text = panics(|| sessions_contract(&f, &all));
    assert!(text.contains("emited"), "{text}");
}

/// RED: a piece called short that the door answers with room to spare crosses once, not the
/// pinned two, and its answer names no room needed.
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

/// RED: two sessions sharing a name, or two steps of one sharing a label, are refused at once
/// (the contract finds a step by its label).
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

/// RED: the cancel ends the session only because it names the ticket the session's pieces crossed
/// on: a session crossed ticket-less, cancelled naming no ticket, still has output to collect.
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
    };
    sessions(&mut r, &p, &d, &Session::all(&all), &carried);
    r.line("cancel", 1, || {
        cancel(&p, busbar_contract::abi::mechanism::ticket::Ticket::NONE)
    });
    r.line("drive", 1, || drive(&p));
    let f = r.fold();
    exact(&f).unwrap_or_else(|e| panic!("{e}"));
    assert!(f[3].answer.ends_with("ready=[50]"), "{}", f[3].answer);
}

/// RED: a session that cancels but crosses on no ticket of its own is refused at once: its cancel
/// would name no op.
#[test]
fn red_a_cancel_in_a_session_with_no_ticket_is_refused() {
    let mut all: Value = serde_json::from_str(SESSIONS).expect("the inputs are JSON");
    all[0]["ticket"] = Value::Bool(false);
    assert!(panics(|| {
        Session::all(&all);
    })
    .contains("cancels on its ticket"));
}

/// RED: a tick the inputs say wakes its driver ticket, on a door whose tick wakes nothing, crosses
/// once where two (the tick and the `drive` the wake calls) are pinned.
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

// ── THE HOST, THE LEDGER LANE, THE RECORD WRITES AND THE PROMPT TURNS ────────────────────────────

/// The kernel services the fixture asks: `door:echo` entitled for unit 80 alone, the member `m1`'s
/// `echo` approved.
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

/// The fixture opened on a dispatcher serving `host`, then the sessions leg over `all`.
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
    };
    sessions(&mut r, &p, &d, &Session::all(all), &carried);
    r.fold()
}

/// GREEN: on a host serving the inputs' tables, the granted unit's ATTEMPT is sent and its answer
/// names its lane and record write, the ungranted unit's is refused, and `project` writes its
/// turn; both ways, at their pins, the folds equal, every want met.
#[test]
fn the_host_tables_gate_the_unit_and_the_lane_records_and_turns_are_judged() {
    let all: Value = serde_json::from_str(SERVED).expect("JSON");
    let linked = served_fold(Leg::Linked, HOST, &all);
    let mut folds = vec![&linked];
    let dropped = dropped_built().then(|| served_fold(Leg::Dropped, HOST, &all));
    folds.extend(dropped.as_ref());
    for f in &folds {
        exact(f).unwrap_or_else(|e| panic!("{e}"));
        sessions_contract(f, &all);
    }
    if let Some(dropped) = &dropped {
        same(&linked, dropped).unwrap_or_else(|e| panic!("{e}"));
    }
}

/// RED: the gate is the host's answer: the member's `echo` not approved, the granted unit's
/// ATTEMPT is refused and its want fails.
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

/// RED: a lane, a record write or a turn other than the answer's fails the contract, and so does
/// wanting none where the answer carries one.
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

/// RED: a crossing of a unit the grant does not list is entitled to nothing, as the kernel answers
/// a principal the grant does not hold.
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

// ── THE ATTEMPT AND THE CALLER'S BODIES (`plane.attempt`, `plane.arrive_each`) ─────────────────

fn step(label: &str, answer: &str) -> crate::conformance::Step {
    crate::conformance::Step {
        label: label.into(),
        answer: answer.into(),
        crossed: 1,
        pinned: 1,
        resumes: 0,
    }
}

/// A fold of the attempts, the bodies and (with `arrive_each`) the arrivals, the attempts going
/// to the far end or not.
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

/// GREEN and RED: an ATTEMPT taken with nothing sent passes only where the inputs say so, and with
/// `arrive_each` every unit's body is judged as the claimed one's.
#[test]
fn the_attempt_and_every_arrived_units_body_are_judged() {
    let ok = "Ready lease=false  emitted=req more=0 to_far_end=true done=false";
    let taken: Value = serde_json::json!({ "attempt": { "to_far_end": false }, "arrive_each": true, "request_out": "req" });
    super::attempts_and_bodies(&attempts(false, ok), &taken);
    super::attempts_and_bodies(
        &attempts(true, ok),
        &serde_json::json!({ "request_out": "req" }),
    );
    // RED: taken, where the inputs do not say so.
    let text = panics(|| {
        super::attempts_and_bodies(
            &attempts(false, ok),
            &serde_json::json!({ "request_out": "req" }),
        );
    });
    assert!(text.contains("attempt"), "{text}");
    // RED: a unit that arrived whose body is not the request.
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
    // RED: `arrive_each` stated, a unit that never arrived.
    let mut f = attempts(false, ok);
    f.retain(|s| s.label != "short arrive");
    let text = panics(|| super::attempts_and_bodies(&f, &taken));
    assert!(text.contains("short arrive"), "{text}");
}
