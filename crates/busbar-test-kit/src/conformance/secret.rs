// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SECRET KIND'S SCRIPT. Inputs (`conformance.json`):
//!
//! ```json
//! { "settings": <the settings it opens over>,
//!   "secret": {
//!     "bad_settings": ["<settings `validate` must refuse (FAILED, naming why)>", ...],
//!     "known":     { "resolve": <resolve settings>, "material": "<what it resolves to>" },
//!     "unknown":   <resolve settings naming a secret it does not hold: FAILED, NOT_FOUND>,
//!     "malformed": <resolve settings that are not a reference: FAILED, INVALID>
//!                  | [<one such>, ...],
//!     "empty":     <OPTIONAL: resolve settings naming a secret whose value is empty: FAILED,
//!                  INVALID, never READY with no material>,
//!     "check":     <OPTIONAL, for a plugin that serves `check`: { "accepted": [<reference
//!                  settings `check` passes: READY>, ...], "refused": [<ones it refuses: FAILED,
//!                  naming why>, ...] }> } }
//! ```
//!
//! `malformed` may be one input (the original key) or a list; every entry is judged INVALID, and
//! the suite adds `{"name": 5}` (a reference whose settings are the wrong shape) to the list. A
//! refresh over `bad_settings[0]` is refused and leaves the instance serving its last settings: a
//! resolve after it still answers the known material.
//!
//! Every step is one ticket-less crossing of the secret table, but those the HOST answers without
//! one (`Instance::refuse`): a resolve before `open`, a second `open`, a resolve after `close`
//! (FAULT); the host-side read (`facts`); and `ready` ([`super::ready_step`]).
//!
//! THE HOST'S BUFFER (the credential chip, row 6: host-owned secret bytes): every resolve is lent a zeroed buffer the host owns,
//! and a READY value must be written into it, under no lease; a buffer too small for the value is
//! the short-buffer answer (`resolve short`), and the host re-calls with the size it names.

use std::sync::{Arc, Mutex};

use busbar_contract::abi::mechanism::call::{OutHead, Outcome, BLOB_SECRET};
use busbar_contract::abi::secret::{self, CheckIn, ResolveIn, ResolveOut, FIRST_SECRET_CAP};
use busbar_contract::redacted::Secret as Held;

use super::{
    answer, asis, called, closed, crossings, dispatcher, facts, input, input_text, json, listed,
    load, open, opened, output, refresh, refused_settings, release, tick, Fold, Leg, Script,
    Subject, Want,
};
use crate::dispatch::kinds::secret::Secret;
use crate::dispatch::{Dispatcher, Frame, Plugin};

/// One resolve's host memory, owned by the dispatcher while the op runs: the settings and the
/// zeroed holder the value is written into.
struct Lending {
    // settings-leak-lint: allow — NON-PROJECTION engine type: one resolve's settings bytes, lent to
    // the plugin for the call and owned by the dispatcher until it returns. `Lending` implements
    // neither `Debug` nor `Serialize`.
    settings: Vec<u8>,
    held: Mutex<Held<Vec<u8>>>,
}

/// One `resolve`, AS THE HOST'S SECRET ROWS RESOLVE (`secret_calls`): on a ticket of `d`'s, so a
/// networked secret's resolve (a vault read through the host's exchange) that waits on the network
/// answers PENDING and is RESUMED on its wake, lent a zeroed host buffer of `cap` bytes. Its line
/// (outcome, error kind, whether the material is the expected one, flagged secret and written into
/// the host's buffer) and the `needed` a short answer named.
fn resolve_in(
    p: &Plugin<Secret>,
    d: &Dispatcher,
    settings: &[u8],
    material: &[u8],
    cap: usize,
) -> (String, u64) {
    // The settings and the holder ride with the op (THE DESIGN §2): the lending submit owns them.
    let mut held = Held::zeroed(cap);
    let (buf, cap) = held.lend_mut();
    let lending = Arc::new(Lending {
        settings: settings.to_vec(),
        held: Mutex::new(held),
    });
    let mut f: Frame<ResolveIn, ResolveOut> = Frame::new(input(), output());
    f.input.settings = json(&lending.settings);
    f.input.secret_buf = buf;
    f.input.secret_cap = cap;
    let deadline = crate::dispatch::now_ns().saturating_add(RESOLVE_DEADLINE.as_nanos() as u64);
    let (c, f) = super::on_ticket_frame(
        p,
        d,
        secret::slot::RESOLVE,
        f,
        busbar_contract::abi::mechanism::call::DeadlineClass::Call,
        deadline,
        Arc::clone(&lending) as crate::dispatch::Lent,
    );
    let (blob, error_kind, needed) = f.map_or((crate::dispatch::NO_BLOB, 0, 0), |f| {
        (f.out.secret, f.out.error_kind, f.out.needed)
    });
    let in_host_buffer = !blob.ptr.is_null() && blob.ptr == buf.cast_const();
    let what = {
        let mut held = lending
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let got: &[u8] = if c.outcome == Outcome::Ready && in_host_buffer {
            // SAFETY: `buf` is the holder `lending` keeps alive (locked here), `cap` bytes long;
            // the dispatcher's kind check held a READY answer to `len <= cap` bytes at its start.
            unsafe { std::slice::from_raw_parts(buf.cast_const(), blob.len.min(cap)) }
        } else {
            &[]
        };
        let what = if got.is_empty() {
            "none"
        } else if got == material {
            "the-known-material"
        } else {
            "OTHER-material"
        };
        // The host wipes its buffer once it has read it.
        *held = Held::default();
        what
    };
    (
        format!(
            "{} kind={} material={what} secret_flag={} in_host_buffer={in_host_buffer}",
            called(&c),
            error_kind,
            blob.flags & BLOB_SECRET != 0
        ),
        needed,
    )
}

/// [`resolve_in`] with the host's first buffer, re-called once with the size a short answer names.
fn resolve(p: &Plugin<Secret>, d: &Dispatcher, settings: &[u8], material: &[u8]) -> String {
    match resolve_in(p, d, settings, material, FIRST_SECRET_CAP) {
        (_, needed) if needed > 0 => {
            let cap = usize::try_from(needed).unwrap_or(FIRST_SECRET_CAP);
            resolve_in(p, d, settings, material, cap).0
        }
        (line, _) => line,
    }
}

/// One `check` of a reference's `settings`, as the host's secret rows make it: ticket-less, with NO
/// instance, lent a reason buffer. Its line: the call and the reason it wrote.
fn check(p: &Plugin<Secret>, settings: &[u8]) -> String {
    let mut reason = vec![0_u8; 4096];
    let mut f: Frame<CheckIn, OutHead> = Frame::new(input(), output());
    f.input.settings = json(settings);
    f.input.err_buf = reason.as_mut_ptr();
    f.input.err_cap = reason.len();
    called(&p.call(secret::slot::CHECK, &mut f))
}

/// The `malformed` inputs: one value (the original key) or a list, and the suite's own reference
/// of the wrong shape (`{"name": 5}`), each judged INVALID.
fn malformed_inputs(k: &serde_json::Value) -> Vec<Vec<u8>> {
    let text = |v: &serde_json::Value| input_text(v, "a secret");
    let mut all: Vec<Vec<u8>> = match &k["malformed"] {
        serde_json::Value::Array(list) => list.iter().map(text).collect(),
        one => vec![text(one)],
    };
    let wrong_shape = br#"{"name":5}"#.to_vec();
    if !all.contains(&wrong_shape) {
        all.push(wrong_shape);
    }
    all
}

/// The label of the `i`th `malformed` resolve: the first keeps the original label.
fn malformed_label(i: usize) -> String {
    match i {
        0 => "resolve malformed".to_string(),
        i => format!("resolve malformed #{i}"),
    }
}

/// How long the suite waits for one resolve: the host's call deadline.
const RESOLVE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

pub(super) fn fold(s: &Subject, leg: Leg) -> Fold {
    let k = s.kind_inputs("secret");
    assert!(k.is_object(), "conformance.json has no `secret` inputs");
    let settings = leg.settings(s);
    let text = |v: &serde_json::Value| input_text(v, "a secret");
    let bad: Vec<Vec<u8>> = listed(k, "secret", "bad_settings")
        .iter()
        .map(text)
        .collect();
    let known = text(&k["known"]["resolve"]);
    let material = text(&k["known"]["material"]);
    let unknown = text(&k["unknown"]);
    let malformed = malformed_inputs(k);
    let empty = (!k["empty"].is_null()).then(|| text(&k["empty"]));
    let checks = (!k["check"].is_null()).then(|| {
        (
            listed(&k["check"], "secret.check", "accepted")
                .iter()
                .map(text)
                .collect::<Vec<_>>(),
            listed(&k["check"], "secret.check", "refused")
                .iter()
                .map(text)
                .collect::<Vec<_>>(),
        )
    });

    let d = dispatcher();
    let p = load::<Secret>(s, leg, s.bind(&d, "secret")).expect("the secret door loads");
    let mut r = Script::new(crossings(&p));
    r.line("facts", 0, || facts(&p));
    refused_settings(&mut r, &p, &bad, &asis);
    // `check` judges a reference with no instance: it crosses before any `open`.
    if let Some((accepted, refused)) = &checks {
        for (i, c) in accepted.iter().enumerate() {
            r.judged(
                &format!("check accepted #{i}"),
                1,
                Want::Starts("Ready "),
                || check(&p, c),
            );
        }
        for (i, c) in refused.iter().enumerate() {
            r.judged(
                &format!("check refused #{i}"),
                1,
                Want::Starts("Failed lease=false "),
                || check(&p, c),
            );
        }
    }
    // The host refuses an op on an unopened instance before the crossing (`Instance::refuse`).
    r.line("resolve unopened", 0, || resolve(&p, &d, &known, &material));
    opened(&mut r, (s, &p, &d), &settings, &asis);
    // The host refuses a second `open` of an open instance before the crossing.
    r.line("open again", 0, || called(&open(&p, &settings)));
    r.line("resolve known", 1, || resolve(&p, &d, &known, &material));
    r.line("resolve known again", 1, || {
        resolve(&p, &d, &known, &material)
    });
    // A buffer one byte short of the value: the short-buffer answer, naming the value's length.
    r.line("resolve short", 1, || {
        let short = material.len().saturating_sub(1);
        let (line, needed) = resolve_in(&p, &d, &known, &material, short);
        format!("{line} needed={}", needed == material.len() as u64)
    });
    r.line("resolve unknown", 1, || {
        resolve(&p, &d, &unknown, &material)
    });
    for (i, m) in malformed.iter().enumerate() {
        r.line(&malformed_label(i), 1, || resolve(&p, &d, m, &material));
    }
    if let Some(empty) = &empty {
        r.line("resolve empty", 1, || resolve(&p, &d, empty, &material));
    }
    // No lease was granted: a release of one is the plugin's refusal.
    r.line("release", 1, || called(&release(&p, 1)));
    r.line("tick", 1, || {
        let (c, next) = tick(&p, 1);
        format!("{} next={next}", called(&c))
    });
    // A refresh over settings `validate` refuses is refused, naming why, and the instance keeps
    // serving its last settings.
    r.judged(
        "refresh bad",
        1,
        Want::Starts("Failed lease=false "),
        || called(&refresh(&p, &bad[0])),
    );
    r.line("resolve after refused refresh", 1, || {
        resolve(&p, &d, &known, &material)
    });
    r.judged("refresh", 1, Want::Starts("Ready "), || {
        called(&refresh(&p, &settings))
    });
    r.line("resolve after refresh", 1, || {
        resolve(&p, &d, &known, &material)
    });
    closed(&mut r, &p, &asis);
    r.line("resolve after close", 0, || {
        resolve(&p, &d, &known, &material)
    });
    let fold = r.fold();
    contract(&fold);
    fold
}

/// THE KIND'S CONTRACT over the fold, so two equal folds of failures prove nothing: a known name
/// is READY with its material, flagged secret and written into the host's buffer under no lease; a
/// buffer too small is the short-buffer answer naming the value's length; an unknown one is
/// NOT_FOUND, every malformed one and an empty value INVALID, none leased; no lease is held to
/// release; a refused `validate` names why; an instance opens once; a refused `refresh` leaves it
/// serving the known material; a closed instance serves nothing. `validate`, `open`, `refresh`
/// (both), `check` and `close` are judged where they run ([`super::opened`], [`Script::judged`]).
fn contract(fold: &Fold) {
    let at = |label: &str| answer(fold, label);
    let known = format!(
        "kind={} material=the-known-material secret_flag=true in_host_buffer=true",
        secret::ERROR_KIND_UNSET
    );
    for label in [
        "resolve known",
        "resolve known again",
        "resolve after refused refresh",
        "resolve after refresh",
    ] {
        assert!(
            at(label).starts_with("Ready lease=false ") && at(label).ends_with(&known),
            "{label}: {}",
            at(label)
        );
    }
    let short = format!(
        "kind={} material=none secret_flag=false in_host_buffer=false needed=true",
        secret::ERROR_KIND_UNSET
    );
    assert!(
        at("resolve short").starts_with("Failed lease=false ")
            && at("resolve short").ends_with(&short),
        "a value over the host's buffer is the short-buffer answer: {}",
        at("resolve short")
    );
    let malformed = (0..)
        .map(malformed_label)
        .take_while(|l| fold.iter().any(|s| &s.label == l));
    let mut failing: Vec<(String, u32)> =
        vec![("resolve unknown".into(), secret::ERROR_KIND_NOT_FOUND)];
    failing.extend(malformed.map(|l| (l, secret::ERROR_KIND_INVALID)));
    if fold.iter().any(|s| s.label == "resolve empty") {
        failing.push(("resolve empty".into(), secret::ERROR_KIND_INVALID));
    }
    for (label, kind) in &failing {
        let label = label.as_str();
        let tail = format!("kind={kind} material=none secret_flag=false in_host_buffer=false");
        assert!(
            at(label).starts_with("Failed lease=false ") && at(label).ends_with(&tail),
            "{label}: {}",
            at(label)
        );
    }
    let refused = at("validate bad #0");
    assert!(
        refused.starts_with("Failed lease=false ") && refused.len() > "Failed lease=false ".len(),
        "a refused validate names why: {refused}"
    );
    assert!(
        at("open again").starts_with("Refused "),
        "one open per instance: {}",
        at("open again")
    );
    assert!(
        !at("release").starts_with("Ready"),
        "no lease was granted, so none releases: {}",
        at("release")
    );
    assert!(
        !at("resolve after close").starts_with("Ready"),
        "{}",
        at("resolve after close")
    );
}

#[cfg(test)]
mod tests {
    use super::{malformed_inputs, malformed_label};

    /// RED (SC2): `malformed` is one input (the original key, unchanged) or a list, and the
    /// suite always adds the wrong-shape reference `{"name":5}`, once.
    #[test]
    fn malformed_is_one_input_or_a_list_and_always_judges_the_wrong_shape() {
        let one = serde_json::json!({ "malformed": "[]" });
        assert_eq!(
            malformed_inputs(&one),
            vec![b"[]".to_vec(), br#"{"name":5}"#.to_vec()]
        );
        let list = serde_json::json!({ "malformed": ["[]", { "name": 5 }, { "key": [] }] });
        assert_eq!(
            malformed_inputs(&list),
            vec![
                b"[]".to_vec(),
                br#"{"name":5}"#.to_vec(),
                br#"{"key":[]}"#.to_vec()
            ]
        );
        assert_eq!(malformed_label(0), "resolve malformed");
        assert_eq!(malformed_label(2), "resolve malformed #2");
    }
}
