// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **`kind: secret`, BOTH WAYS, THROUGH THE ONE DISPATCHER** (TODO ABI-b4). The
//! secret kind's fixture (`secret_door_plugin`) loaded LINKED and DROPPED IN (`door_both_ways`) and
//! driven over one script of the kind's table: `validate` and `open` over bad and good settings,
//! `resolve` of a known name (READY, its material under a lease), an unknown name (FAILED,
//! NOT_FOUND) and malformed settings (FAILED, INVALID), the lease released once (READY) and twice
//! (REFUSED), and `close`. The two transcripts must be equal, line for line.
//!
//! RED ARM, KEPT: [`a_secret_plugin_that_breaks_resolve_is_refused_through_both_doors`] loads the
//! fixture's [`broken`](secret_door_plugin::broken) door — READY while naming an `error_kind` — the
//! same two ways: the dispatcher answers FAULT on both, where the conforming door answers READY.
//!
//! The fixture stands in for the kind's real plugins: none is a row of the both-ways table on this
//! SDK yet, so the proof holds the kind's table, not one plugin.

use busbar_contract::abi::mechanism::call::{OutHead, Outcome};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, ValidateIn};
use busbar_contract::abi::secret::{slot, ResolveIn, ResolveOut};

use super::door_both_ways::{
    self as both, close, input, line, octets, open, output, release, same,
};
use crate::dispatch::kinds::secret::Secret;
use crate::dispatch::{Frame, Plugin};

#[path = "../../tests/fixtures/secret_door_plugin.rs"]
mod secret_door_plugin;

/// The instance's settings: one name and its material.
const SETTINGS: &[u8] = br#"{"values": {"db": "fixture-material"}}"#;

/// `validate` over `settings`.
fn validate(p: &Plugin<Secret>, settings: &[u8]) -> String {
    let mut v: Frame<ValidateIn, OutHead> = Frame::new(input(), output());
    v.input.settings = octets(settings);
    line("validate", &p.call(life::VALIDATE, &mut v))
}

/// `resolve` over `settings`: the host's line, its `error_kind`, and the material it leased.
fn resolve(p: &Plugin<Secret>, settings: &[u8]) -> (String, u64) {
    let mut r: Frame<ResolveIn, ResolveOut> = Frame::new(input(), output());
    r.input.settings = octets(settings);
    let c = p.call(slot::RESOLVE, &mut r);
    let material = if c.outcome == Outcome::Ready && !r.out.secret.ptr.is_null() {
        // SAFETY: a READY resolve's blob is the plugin's, valid until `release` of its lease,
        // which has not run; `check_resolve` judged its pointer/length pairing.
        let bytes = unsafe { std::slice::from_raw_parts(r.out.secret.ptr, r.out.secret.len) };
        String::from_utf8_lossy(bytes).into_owned()
    } else {
        String::new()
    };
    (
        format!(
            "{} error_kind={} material={material:?}",
            line("resolve", &c),
            r.out.error_kind
        ),
        c.lease,
    )
}

/// THE SCRIPT, one line per answer.
fn script(p: &Plugin<Secret>) -> Vec<String> {
    let mut t = vec![
        validate(p, br#"{"values": 1}"#),
        validate(p, SETTINGS),
        line("open, bad settings", &open(p, b"[]")),
        line("open", &open(p, SETTINGS)),
    ];
    let (known, lease) = resolve(p, br#"{"name": "db"}"#);
    t.push(known);
    t.push(resolve(p, br#"{"name": "cache"}"#).0);
    t.push(resolve(p, b"not json").0);
    t.push(line("release", &release(p, lease)));
    t.push(line("release again", &release(p, lease)));
    t.push(line("close", &close(p)));
    t
}

#[test]
fn a_linked_and_a_dropped_in_secret_plugin_resolve_identically() {
    let door = secret_door_plugin::conforming::door;
    let linked = script(&both::linked::<Secret>(door).plugin);
    let Some(dropped) = both::dropped::<Secret>(door, "secret_door") else {
        eprintln!("skip: the secret fixture's cdylib is not built in this scoped run");
        return;
    };
    same(&linked, &script(&dropped.plugin));
    // The script reached every answer it names: equal empty transcripts would prove nothing.
    let find = |p: &str| linked.iter().find(|l| l.starts_with(p)).cloned();
    assert!(find("open:").is_some_and(|l| l.contains("Ready")));
    assert!(linked[4].contains("Ready") && linked[4].contains("fixture-material"));
    assert!(!linked[4].contains("lease=0"), "a READY material is leased");
    assert!(linked[5].contains("Failed") && linked[5].contains("error_kind=1"));
    assert!(linked[6].contains("Failed") && linked[6].contains("error_kind=4"));
    assert!(find("release:").is_some_and(|l| l.contains("Ready")));
    assert!(find("release again").is_some_and(|l| l.contains("Refused")));
}

/// THE RED ARM, KEPT: a `resolve` answering READY while naming an `error_kind` breaks the secret
/// kind's contract. Through either door the dispatcher answers FAULT, never the answer.
#[test]
fn a_secret_plugin_that_breaks_resolve_is_refused_through_both_doors() {
    let broken = secret_door_plugin::broken::door;
    let run = |p: &Plugin<Secret>| {
        let opened = line("open", &open(p, SETTINGS));
        let (resolved, _) = resolve(p, br#"{"name": "db"}"#);
        vec![opened, resolved]
    };
    let linked = run(&both::linked::<Secret>(broken).plugin);
    assert!(linked[0].contains("Ready"), "{}", linked[0]);
    assert!(linked[1].contains("Fault"), "{}", linked[1]);
    let conforming = run(&both::linked::<Secret>(secret_door_plugin::conforming::door).plugin);
    assert!(conforming[1].contains("Ready"), "{}", conforming[1]);
    let Some(dropped) = both::dropped::<Secret>(broken, "secret_broken_door") else {
        eprintln!("skip: the broken secret fixture's cdylib is not built in this scoped run");
        return;
    };
    same(&linked, &run(&dropped.plugin));
}
