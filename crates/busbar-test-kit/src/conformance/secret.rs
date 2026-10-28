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
    answer, asis, called, closed, crossings, dispatcher, facts, input, input_text, json, listed,
    load, open, opened, output, refreshed, refused_settings, release, Fold, Leg, Script, Subject,
};
use crate::dispatch::kinds::secret::Secret;
use crate::dispatch::{Dispatcher, Frame, Plugin};

/// One `resolve`, AS THE HOST'S SECRET ROWS RESOLVE (`secret_calls`): on a ticket of `d`'s, so a
/// networked secret's resolve (a vault read through the host's exchange) that waits on the network
/// answers PENDING and is RESUMED on its wake. Its line (outcome, error kind, whether the material
/// is the expected one and flagged secret) and its lease, still held.
fn resolve(p: &Plugin<Secret>, d: &Dispatcher, settings: &[u8], material: &[u8]) -> (String, u64) {
    // The settings ride with the op (THE DESIGN §2): the lending submit owns them.
    let settings: std::sync::Arc<Vec<u8>> = std::sync::Arc::new(settings.to_vec());
    let mut f: Frame<ResolveIn, ResolveOut> = Frame::new(input(), output());
    f.input.settings = json(&settings);
    let deadline = crate::dispatch::now_ns().saturating_add(RESOLVE_DEADLINE.as_nanos() as u64);
    let (c, f) = super::on_ticket_frame(
        p,
        d,
        secret::slot::RESOLVE,
        f,
        busbar_contract::abi::mechanism::call::DeadlineClass::Call,
        deadline,
        settings,
    );
    let (blob, error_kind) = f.map_or((crate::dispatch::NO_BLOB, 0), |f| {
        (f.out.secret, f.out.error_kind)
    });
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
            error_kind,
            blob.flags & BLOB_SECRET != 0
        ),
        c.lease,
    )
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
    let malformed = text(&k["malformed"]);

    let d = dispatcher();
    let p = load::<Secret>(s, leg, s.bind(&d, "secret")).expect("the secret door loads");
    let mut r = Script::new(crossings(&p));
    r.line("facts", 0, || facts(&p));
    refused_settings(&mut r, &p, &bad, &asis);
    // The host refuses an op on an unopened instance before the crossing (`Instance::refuse`).
    r.line("resolve unopened", 0, || {
        resolve(&p, &d, &known, &material).0
    });
    opened(&mut r, (s, &p, &d), &settings, &asis);
    // The host refuses a second `open` of an open instance before the crossing.
    r.line("open again", 0, || called(&open(&p, &settings)));
    let first = r.step("resolve known", 1, || resolve(&p, &d, &known, &material));
    let second = r.step("resolve known again", 1, || {
        resolve(&p, &d, &known, &material)
    });
    r.line("own leases", 0, || {
        format!("distinct={}", first != 0 && second != 0 && first != second)
    });
    r.line("resolve unknown", 1, || {
        resolve(&p, &d, &unknown, &material).0
    });
    r.line("resolve malformed", 1, || {
        resolve(&p, &d, &malformed, &material).0
    });
    r.line("release", 1, || called(&release(&p, first)));
    r.line("release again", 1, || called(&release(&p, first)));
    r.line("release second", 1, || called(&release(&p, second)));
    refreshed(&mut r, &p, Some(&bad[0]), &settings, &asis);
    let after = r.step("resolve after refresh", 1, || {
        resolve(&p, &d, &known, &material)
    });
    r.line("release after refresh", 1, || called(&release(&p, after)));
    closed(&mut r, &p, &asis);
    r.line("resolve after close", 0, || {
        resolve(&p, &d, &known, &material).0
    });
    let fold = r.fold();
    contract(&fold);
    fold
}

/// THE KIND'S CONTRACT over the fold, so two equal folds of failures prove nothing: a known name
/// is READY with its material, leased and flagged secret; an unknown one is NOT_FOUND, a malformed
/// one INVALID, neither leased; a refused `validate` names why; an instance opens once; a closed
/// instance serves nothing. (A `refresh` over the bad settings is recorded, not judged: a plugin
/// whose settings carry nothing it reads may accept them.) `validate`, `open`, `refresh` and
/// `close` answering READY are the shared steps' ([`super::opened`], [`super::refreshed`]).
fn contract(fold: &Fold) {
    let at = |label: &str| answer(fold, label);
    for label in ["release", "release second"] {
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
