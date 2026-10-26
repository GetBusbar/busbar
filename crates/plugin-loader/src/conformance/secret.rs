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
//!     "malformed": <resolve settings that are not a reference: FAILED, INVALID> } }
//! ```
//!
//! Every step is one ticket-less crossing of the secret table, but those the HOST answers without
//! one (`Instance::refuse`): a resolve before `open`, a second `open`, a resolve after `close`
//! (FAULT); the host-side read (`facts`); and `ready` ([`super::ready_step`]).
//!
//! THE HOST'S BUFFER (the credential chip, row 6: host-owned secret bytes): every resolve is lent a zeroed buffer the host owns,
//! and a READY value must be written into it, under no lease; a buffer too small for the value is
//! the short-buffer answer (`resolve short`), and the host re-calls with the size it names.

use std::sync::{Arc, Mutex};

use busbar_contract::abi::mechanism::call::{Outcome, BLOB_SECRET};
use busbar_contract::abi::secret::{self, ResolveIn, ResolveOut, FIRST_SECRET_CAP};
use busbar_contract::redacted::Secret as Held;

use super::{
    called, close, crossings, dispatcher, input, json, load, open, output, ready_step, refresh,
    release, tick, validate, Fold, Leg, Recorder, Subject,
};
use crate::dispatch::kinds::secret::Secret;
use crate::dispatch::{Dispatcher, Frame, Plugin};

fn text(v: &serde_json::Value) -> Vec<u8> {
    match v {
        serde_json::Value::String(s) => s.as_bytes().to_vec(),
        serde_json::Value::Null => panic!("conformance.json: a secret input is missing"),
        other => other.to_string().into_bytes(),
    }
}

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

/// How long the suite waits for one resolve: the host's call deadline.
const RESOLVE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

pub(super) fn fold(s: &Subject, leg: Leg) -> Fold {
    let k = s.kind_inputs("secret");
    assert!(k.is_object(), "conformance.json has no `secret` inputs");
    let settings = leg.settings(s);
    let bad: Vec<Vec<u8>> = k["bad_settings"]
        .as_array()
        .expect("conformance.json: secret.bad_settings must be an array")
        .iter()
        .map(text)
        .collect();
    assert!(
        !bad.is_empty(),
        "conformance.json: secret.bad_settings is empty"
    );
    let known = text(&k["known"]["resolve"]);
    let material = text(&k["known"]["material"]);
    let unknown = text(&k["unknown"]);
    let malformed = text(&k["malformed"]);

    let d = dispatcher();
    let p = load::<Secret>(s, leg, s.bind(&d, "secret")).expect("the secret door loads");
    let mut r = Recorder::new(crossings(&p));
    r.line("facts", 0, || {
        format!(
            "{:?} {} max_inflight={}",
            p.kind(),
            p.name(),
            p.max_inflight()
        )
    });
    for (i, b) in bad.iter().enumerate() {
        r.line(&format!("validate bad #{i}"), 1, || {
            called(&validate(&p, b))
        });
    }
    r.line("validate", 1, || called(&validate(&p, &settings)));
    // The host refuses an op on an unopened instance before the crossing (`Instance::refuse`).
    r.line("resolve unopened", 0, || resolve(&p, &d, &known, &material));
    r.line("open", 1, || called(&open(&p, &settings)));
    // The host refuses a second `open` of an open instance before the crossing.
    r.line("open again", 0, || called(&open(&p, &settings)));
    ready_step(&mut r, s, &p, &d);
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
    r.line("resolve malformed", 1, || {
        resolve(&p, &d, &malformed, &material)
    });
    // No lease was granted: a release of one is the plugin's refusal.
    r.line("release", 1, || called(&release(&p, 1)));
    r.line("tick", 1, || {
        let (c, next) = tick(&p, 1);
        format!("{} next={next}", called(&c))
    });
    r.line("refresh bad", 1, || called(&refresh(&p, &bad[0])));
    r.line("refresh", 1, || called(&refresh(&p, &settings)));
    r.line("resolve after refresh", 1, || {
        resolve(&p, &d, &known, &material)
    });
    r.line("close", 1, || called(&close(&p)));
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
/// NOT_FOUND, a malformed one INVALID, neither leased; no lease is held to release; a refused `validate` names why; an instance opens once; a closed
/// instance serves nothing. (A `refresh` over the bad settings is recorded, not judged: a plugin
/// whose settings carry nothing it reads may accept them.)
fn contract(fold: &Fold) {
    let at = |label: &str| {
        fold.iter()
            .find(|s| s.label == label)
            .map(|s| s.answer.as_str())
            .unwrap_or_else(|| panic!("the script ran no step '{label}'"))
    };
    for label in ["validate", "open", "refresh", "close"] {
        assert!(at(label).starts_with("Ready "), "{label}: {}", at(label));
    }
    let known = format!(
        "kind={} material=the-known-material secret_flag=true in_host_buffer=true",
        secret::ERROR_KIND_UNSET
    );
    for label in [
        "resolve known",
        "resolve known again",
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
    for (label, kind) in [
        ("resolve unknown", secret::ERROR_KIND_NOT_FOUND),
        ("resolve malformed", secret::ERROR_KIND_INVALID),
    ] {
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
