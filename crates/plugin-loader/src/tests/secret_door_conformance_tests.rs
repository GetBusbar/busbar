// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **`kind: secret`, BOTH WAYS, THROUGH THE ONE DISPATCHER** (TODO ABI-b4; M6/contract). The
//! secret kind's REAL plugin (the env source, from its own repo, reached by KIND through
//! `[package.metadata.busbar.both-ways]`) is loaded LINKED (the logic crate's door, compiled into this build) and
//! DROPPED IN (its `cdylib`, built from the same crate and `dlopen`ed) and driven over one script of
//! the kind's table: `validate`, `open`, a `resolve` that HITS (READY, its material under a lease,
//! released), a `resolve` that MISSES (FAILED, NOT_FOUND), a `refresh` to the next generation, the
//! same hit again, `retire` of the old generation and `close`. The two transcripts must be equal,
//! line for line, and each door must have made EXACTLY [`CROSSINGS`] crossings: not "above zero", the
//! count the script's calls make, with the call after `close` making none.
//!
//! M6/contract asks for the SHIPPED binary: the proof is run with `--release` and the cdylib built
//! `--release`; nothing here is profile-dependent, so the exact count holds in either profile.
//!
//! RED ARMS, KEPT: [`a_secret_plugin_that_breaks_resolve_is_refused_through_both_doors`] loads a
//! door whose `resolve` is READY while naming an `error_kind` the same two ways, and the dispatcher
//! answers FAULT on both where the conforming door answers READY;
//! [`the_secret_door_is_not_another_kinds_door`] asks the real door to load as another kind.

use busbar_contract::abi::mechanism::call::{Blob, OutHead, Outcome, BLOB_JSON};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, GenIn, RefreshIn, ValidateIn};
use busbar_contract::abi::secret::{slot, ResolveIn, ResolveOut, ERROR_KIND_NOT_FOUND};

use super::door_both_ways::{
    self as both, close, input, line, open, output, release, same, Loaded,
};
use crate::both_ways::{secret_fixture, HOT_FIXTURES};
use crate::dispatch::kinds::export::Export;
use crate::dispatch::kinds::secret::Secret;
use crate::dispatch::{load_linked, Frame, LinkedRow, Plugin};

#[path = "../../tests/fixtures/secret_door_plugin.rs"]
pub(crate) mod secret_door_plugin;

/// The material the hit's variable holds.
const MATERIAL: &str = "s3cr3t-both-ways";
/// The variable the hit names (set) and the one the miss names (never set).
const HIT: &str = "BUSBAR_LOADER_SECRET_BOTH_WAYS_HIT";
const MISS: &str = "BUSBAR_LOADER_SECRET_BOTH_WAYS_MISS";

/// The crossings the script makes: validate, open, hit, release, miss, refresh, hit, release,
/// retire, close. The resolve after `close` is answered without one.
const CROSSINGS: u64 = 10;

/// A JSON blob, lent for one call.
fn json(bytes: &[u8]) -> Blob {
    Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt: BLOB_JSON,
        flags: 0,
    }
}

/// The crossings `p` has made.
fn crossings(p: &Plugin<Secret>) -> u64 {
    p.inner.crossings.load(std::sync::atomic::Ordering::SeqCst)
}

/// `validate` over `settings`.
fn validate(p: &Plugin<Secret>, settings: &[u8]) -> String {
    let mut v: Frame<ValidateIn, OutHead> = Frame::new(input(), output());
    v.input.settings = json(settings);
    line("validate", &p.call(life::VALIDATE, &mut v))
}

/// `refresh` to `generation`.
fn refresh(p: &Plugin<Secret>, generation: u64) -> String {
    let mut r: Frame<RefreshIn, OutHead> = Frame::new(input(), output());
    r.input.generation = generation;
    r.input.settings = json(b"{}");
    line("refresh", &p.call(life::REFRESH, &mut r))
}

/// `retire` of `generation`.
fn retire(p: &Plugin<Secret>, generation: u64) -> String {
    let mut r: Frame<GenIn, OutHead> = Frame::new(input(), output());
    r.input.generation = generation;
    line("retire", &p.call(life::RETIRE, &mut r))
}

/// `resolve` over `settings`: the host's line with its `error_kind` and the material it leased
/// (copied before the lease is released), and the lease.
fn resolve(p: &Plugin<Secret>, settings: &[u8]) -> (String, u64) {
    let mut r: Frame<ResolveIn, ResolveOut> = Frame::new(input(), output());
    r.input.settings = json(settings);
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

/// THE SCRIPT, one line per answer, ending with the resolve after `close` (no crossing).
fn script(p: &Plugin<Secret>) -> Vec<String> {
    let hit = format!(r#"{{"key": "{HIT}"}}"#);
    let miss = format!(r#"{{"key": "{MISS}"}}"#);
    let mut t = vec![validate(p, b"{}"), line("open", &open(p, b"{}"))];
    let (first, lease) = resolve(p, hit.as_bytes());
    t.push(first);
    t.push(line("release", &release(p, lease)));
    t.push(resolve(p, miss.as_bytes()).0);
    t.push(refresh(p, 2));
    let (again, lease) = resolve(p, hit.as_bytes());
    t.push(again);
    t.push(line("release", &release(p, lease)));
    t.push(retire(p, 1));
    t.push(line("close", &close(p)));
    t.push(resolve(p, hit.as_bytes()).0);
    t
}

/// The real secret plugin, LINKED: its door, through the one dispatcher.
fn linked() -> Loaded<Secret> {
    both::linked::<Secret>(secret_fixture::door::door)
}

/// The real secret plugin, DROPPED IN: its built `cdylib`. A missing artifact is a failure, never
/// a skip: this suite is the kind's finish line.
fn dropped() -> Loaded<Secret> {
    let (_, logic) = HOT_FIXTURES
        .iter()
        .find(|(k, _)| *k == "secret")
        .expect("a `secret` row in Cargo.toml's [package.metadata.busbar.both-ways]");
    // The row names the repo's logic crate; the fleet's twin shape names its cdylib `<logic>_plugin`.
    let krate = format!("{logic}_plugin");
    let path = crate::both_ways::cdylib(&krate)
        .unwrap_or_else(|| panic!("the secret plugin's cdylib ({krate}) is not built"));
    both::dropped_from::<Secret>(secret_fixture::door::door, &path)
}

#[test]
fn a_linked_and_a_dropped_in_secret_plugin_resolve_identically() {
    std::env::set_var(HIT, MATERIAL);
    std::env::remove_var(MISS);
    let (linked, dropped) = (linked(), dropped());
    let (a, b) = (script(&linked.plugin), script(&dropped.plugin));
    same(&a, &b);
    // Exact, per door: the script's calls cross once each, and a call after `close` not at all.
    assert_eq!(crossings(&linked.plugin), CROSSINGS, "linked crossings");
    assert_eq!(
        crossings(&dropped.plugin),
        CROSSINGS,
        "dropped-in crossings"
    );
    // The script reached every answer it names: equal empty transcripts would prove nothing.
    assert!(a[1].contains("Ready"), "{}", a[1]);
    assert!(
        a[2].contains("Ready") && a[2].contains(MATERIAL) && !a[2].contains("lease=0"),
        "a hit is READY with its material under a lease: {}",
        a[2]
    );
    assert!(a[3].contains("Ready"), "{}", a[3]);
    assert!(
        a[4].contains("Failed") && a[4].contains(&format!("error_kind={ERROR_KIND_NOT_FOUND}")),
        "a miss is FAILED, NOT_FOUND: {}",
        a[4]
    );
    assert!(
        a[5].contains("Ready"),
        "refresh to the next generation: {}",
        a[5]
    );
    assert!(a[6].contains(MATERIAL), "a hit after the refresh: {}", a[6]);
    assert!(
        a[8].contains("Ready") && a[9].contains("Ready"),
        "retire, close"
    );
    assert!(a[10].contains("Fault"), "a resolve after close: {}", a[10]);
}

/// THE RED ARM, KEPT: a `resolve` answering READY while naming an `error_kind` breaks the secret
/// kind's contract. Through either door the dispatcher answers FAULT, never the answer.
#[test]
fn a_secret_plugin_that_breaks_resolve_is_refused_through_both_doors() {
    let broken = secret_door_plugin::broken::door;
    let run = |p: &Plugin<Secret>| {
        let opened = line("open", &open(p, b"{}"));
        let (resolved, _) = resolve(p, b"{}");
        vec![opened, resolved]
    };
    let linked = run(&both::linked::<Secret>(broken).plugin);
    assert!(linked[0].contains("Ready"), "{}", linked[0]);
    assert!(linked[1].contains("Fault"), "{}", linked[1]);
    let dropped = both::dropped::<Secret>(broken, "secret_broken_door")
        .expect("the broken secret door's cdylib is built beside the test binary");
    same(&linked, &run(&dropped.plugin));
}

/// THE RED ARM, KEPT: the secret door is a secret door. Asked to load as another kind, the
/// dispatcher refuses it, so the table the suite drives is the kind's own.
#[test]
fn the_secret_door_is_not_another_kinds_door() {
    let dispatcher = std::sync::Arc::new(crate::dispatch::Dispatcher::new(
        crate::dispatch::DispatchConfig::default(),
    ));
    let row = LinkedRow::of(secret_fixture::door::door).expect("the linked row states");
    let err = load_linked::<Export>(&row, both::bind(&dispatcher))
        .expect_err("a secret door is not an export door");
    let said = format!("{err:?}");
    assert!(said.contains("Secret") || said.contains("Kind"), "{said}");
}
