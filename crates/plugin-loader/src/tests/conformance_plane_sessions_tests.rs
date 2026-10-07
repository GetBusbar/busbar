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

use super::{open, sessions, sessions_contract, Carried, Session};
use crate::conformance::{
    crossings, dispatcher, exact, load, perturbed, same, Fold, Leg, Recorder, Subject,
};
use crate::dispatch::kinds::plane::Plane;

const PUBLIC_URL: &str = "https://node.example/base";

const SESSIONS: &str = r#"[
  { "name": "live", "unit": 40, "stream": 40, "claim": 1, "steps": [
    { "label": "upgrade", "arrive": { "method": "GET", "target": "/upgrade", "body": "hi" },
      "want": { "outcome": "Ready", "route": { "class": "pool", "entry": "" } } },
    { "label": "uplink", "piece": { "from": "caller", "bytes": "hello" },
      "want": { "outcome": "Ready", "emitted": "", "to_far_end": false, "units": [] } },
    { "label": "drive", "drive": true, "want": { "outcome": "Ready", "streams": [40] } },
    { "label": "collect", "piece": { "from": "kernel" },
      "want": { "outcome": "Ready", "emitted": "ping", "done": false } },
    { "label": "drive again", "drive": true, "want": { "outcome": "Ready", "streams": [] } },
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
      "want": { "outcome": "Ready", "rewritten": false, "body_has": ["hi"] } } ] },
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
    sessions(&mut r, &p, &Session::all(all), &carried);
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
        "the plane_door_plugin example cdylib is not built under CI; a both-ways proof must not skip: \
         run `cargo build --workspace --examples`"
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
        None => eprintln!(
            "skip: the plane_door_plugin example cdylib is not built; run `cargo build --workspace --examples`"
        ),
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
/// another count, another outcome, another stream, another body.
#[test]
fn red_a_session_step_answering_otherwise_than_wanted_is_refused() {
    let f = fold(&subject(), Leg::Linked);
    for (label, key, v) in [
        ("live answer head", "units", serde_json::json!([[0, 4]])),
        ("live uplink", "outcome", serde_json::json!("Refused")),
        ("live drive", "streams", serde_json::json!([41])),
        ("live project", "body_has", serde_json::json!(["bye"])),
        ("request attempt", "verb", serde_json::json!("GET")),
        (
            "live upgrade",
            "route",
            serde_json::json!({"class": "direct", "entry": "e"}),
        ),
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
