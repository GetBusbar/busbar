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
//! (FAULT); the host-side reads (`facts`, `own leases`); and `ready` ([`super::ready_step`]).

use busbar_contract::abi::mechanism::call::{Outcome, BLOB_SECRET};
use busbar_contract::abi::secret::{self, ResolveIn, ResolveOut};

use super::{
    called, close, crossings, dispatcher, input, json, load, open, output, ready_step, refresh,
    release, tick, validate, Fold, Leg, Recorder, Subject,
};
use crate::dispatch::kinds::secret::Secret;
use crate::dispatch::{Frame, Plugin};

fn text(v: &serde_json::Value) -> Vec<u8> {
    match v {
        serde_json::Value::String(s) => s.as_bytes().to_vec(),
        serde_json::Value::Null => panic!("conformance.json: a secret input is missing"),
        other => other.to_string().into_bytes(),
    }
}

/// One `resolve`: its line (outcome, error kind, whether the material is the expected one and
/// flagged secret) and its lease, still held.
fn resolve(p: &Plugin<Secret>, settings: &[u8], material: &[u8]) -> (String, u64) {
    let mut f: Frame<ResolveIn, ResolveOut> = Frame::new(input(), output());
    f.input.settings = json(settings);
    let c = p.call(secret::slot::RESOLVE, &mut f);
    let blob = f.out.secret;
    let got = if c.outcome == Outcome::Ready && !blob.ptr.is_null() {
        // SAFETY: a READY resolve's blob is the plugin's, live until `release` of its lease, which
        // has not run; the dispatcher's kind check judged its pointer/length pairing.
        unsafe { std::slice::from_raw_parts(blob.ptr, blob.len) }.to_vec()
    } else {
        Vec::new()
    };
    let what = if got.is_empty() {
        "none"
    } else if got == material {
        "the-known-material"
    } else {
        "OTHER-material"
    };
    (
        format!(
            "{} kind={} material={what} secret_flag={}",
            called(&c),
            f.out.error_kind,
            blob.flags & BLOB_SECRET != 0
        ),
        c.lease,
    )
}

pub(super) fn fold(s: &Subject, leg: Leg) -> Fold {
    let k = s.kind_inputs("secret");
    assert!(k.is_object(), "conformance.json has no `secret` inputs");
    let settings = s.settings();
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
    r.line("resolve unopened", 0, || resolve(&p, &known, &material).0);
    r.line("open", 1, || called(&open(&p, &settings)));
    // The host refuses a second `open` of an open instance before the crossing.
    r.line("open again", 0, || called(&open(&p, &settings)));
    ready_step(&mut r, s, &p, &d);
    let first = r.step("resolve known", 1, || resolve(&p, &known, &material));
    let second = r.step("resolve known again", 1, || resolve(&p, &known, &material));
    r.line("own leases", 0, || {
        format!("distinct={}", first != 0 && second != 0 && first != second)
    });
    r.line("resolve unknown", 1, || resolve(&p, &unknown, &material).0);
    r.line("resolve malformed", 1, || {
        resolve(&p, &malformed, &material).0
    });
    r.line("release", 1, || called(&release(&p, first)));
    r.line("release again", 1, || called(&release(&p, first)));
    r.line("release second", 1, || called(&release(&p, second)));
    r.line("tick", 1, || {
        let (c, next) = tick(&p, 1);
        format!("{} next={next}", called(&c))
    });
    r.line("refresh bad", 1, || called(&refresh(&p, &bad[0])));
    r.line("refresh", 1, || called(&refresh(&p, &settings)));
    let after = r.step("resolve after refresh", 1, || {
        resolve(&p, &known, &material)
    });
    r.line("release after refresh", 1, || called(&release(&p, after)));
    r.line("close", 1, || called(&close(&p)));
    r.line("resolve after close", 0, || {
        resolve(&p, &known, &material).0
    });
    let fold = r.fold();
    contract(&fold);
    fold
}

/// THE KIND'S CONTRACT over the fold, so two equal folds of failures prove nothing: a known name
/// is READY with its material, leased and flagged secret; an unknown one is NOT_FOUND, a malformed
/// one INVALID, neither leased; a refused `validate` names why; an instance opens once; a closed
/// instance serves nothing. (A `refresh` over the bad settings is recorded, not judged: a plugin
/// whose settings carry nothing it reads may accept them.)
fn contract(fold: &Fold) {
    let at = |label: &str| {
        fold.iter()
            .find(|s| s.label == label)
            .map(|s| s.answer.as_str())
            .unwrap_or_else(|| panic!("the script ran no step '{label}'"))
    };
    for label in [
        "validate",
        "open",
        "release",
        "release second",
        "refresh",
        "close",
    ] {
        assert!(at(label).starts_with("Ready "), "{label}: {}", at(label));
    }
    let known = format!(
        "kind={} material=the-known-material secret_flag=true",
        secret::ERROR_KIND_UNSET
    );
    for label in [
        "resolve known",
        "resolve known again",
        "resolve after refresh",
    ] {
        assert!(
            at(label).starts_with("Ready lease=true ") && at(label).ends_with(&known),
            "{label}: {}",
            at(label)
        );
    }
    assert_eq!(
        at("own leases"),
        "distinct=true",
        "each READY material has its own lease"
    );
    for (label, kind) in [
        ("resolve unknown", secret::ERROR_KIND_NOT_FOUND),
        ("resolve malformed", secret::ERROR_KIND_INVALID),
    ] {
        let tail = format!("kind={kind} material=none secret_flag=false");
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
        at("release again").starts_with("Refused "),
        "{}",
        at("release again")
    );
    assert!(
        !at("resolve after close").starts_with("Ready"),
        "{}",
        at("resolve after close")
    );
}
