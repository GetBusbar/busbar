// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A FAILED `open`'s REASON REACHES THE OPERATOR, in 1.5.5's words, compiled in and dropped in.
//!
//! In 1.5.5 a plugin's `open` error text reached the operator as
//! `plugin '<name>' open failed: <text>`. On the memory ABI a failed `open` has no instance to hold
//! a dynamic text, so the host lends every `open` a reason buffer (`OpenIn::err_buf`): the SDK
//! copies the constructor's `Err` into it, cut on a char boundary to its capacity, and the host
//! rebuilds the 1.5.5 text from its own context ([`Called::open_failure`]).
//!
//! The witness (`tests/fixtures/open_reason_plugins.rs`) is a store built with its kind's SDK door,
//! whose `open` fails with its settings as the reason; it is proven LINKED and DROPPED, and the two
//! must read byte-identically. RED before this: the store door answered a bare REFUSED (read as
//! `the store's validate answered Refused`).

use std::path::PathBuf;
use std::sync::Arc;

use busbar_contract::abi::mechanism::call::{Blob, OutHead, Outcome, BLOB_OCTETS};
use busbar_contract::abi::mechanism::door::DoorFn;
use busbar_contract::abi::mechanism::lifecycle::{slot, OpenIn, OpenOut, ValidateIn};
use busbar_contract::abi::mechanism::{KindCode, MECHANISM_VERSION};
use busbar_contract::abi::sdk::door::{blank_in, blank_out};

use super::open_reason_plugins as witness;
use super::OPEN_REASON_CAP;
use crate::dispatch::kinds::secret::Secret;
use crate::dispatch::kinds::store::Store;
use crate::dispatch::{
    load_dropped, load_linked, Bind, DispatchConfig, Dispatcher, Frame, ManifestFacts, NoSink,
};
use crate::store_v3::LoadedStore;

fn dispatcher() -> Arc<Dispatcher> {
    Arc::new(Dispatcher::new(DispatchConfig::default()))
}

fn bind(d: &Dispatcher) -> Bind {
    Bind {
        max_inflight_cap: 16,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
    }
}

/// The DROPPED door's `cdylib`, when built (`None` only in a scoped non-CI run).
fn dropped_path(example: &str) -> Option<PathBuf> {
    crate::both_ways::example_cdylib(example)
}

fn facts(kind: KindCode) -> ManifestFacts {
    ManifestFacts {
        mechanism_version: MECHANISM_VERSION,
        kind,
        kind_abi: kind.abi_version(),
    }
}

/// The store witness's text through the store host ([`LoadedStore::open`]), LINKED and (when
/// built) DROPPED; both must agree.
fn store_text(settings: &[u8]) -> String {
    let d = dispatcher();
    let door: DoorFn = witness::store::door;
    let linked = load_linked::<Store>(door, bind(&d)).expect("the linked store door loads");
    let text = LoadedStore::open(linked, d.clone(), settings, 1).expect_err("it never opens");
    if let Some(path) = dropped_path("open_reason_store_door") {
        let dropped = load_dropped::<Store>(&path, &facts(KindCode::Store), bind(&d))
            .expect("the dropped store door loads");
        let dropped_text =
            LoadedStore::open(dropped, d.clone(), settings, 1).expect_err("it never opens");
        assert_eq!(dropped_text, text, "linked and dropped in read differently");
    }
    text
}

#[test]
fn a_store_whose_open_fails_reads_as_1_5_5_did() {
    assert_eq!(
        store_text(b"boom: x"),
        "plugin 'open-reason-store' open failed: boom: x"
    );
}

/// An over-long reason is cut to the buffer on a char boundary: `a` then two-byte `é`s put the
/// capacity (even) in the middle of a char, so the cut falls one byte short of it.
#[test]
fn an_over_long_reason_is_cut_on_a_char_boundary() {
    assert_eq!(
        OPEN_REASON_CAP % 2,
        0,
        "the witness assumes an even capacity"
    );
    let long = format!("a{}", "é".repeat(OPEN_REASON_CAP));
    let kept = format!("a{}", "é".repeat((OPEN_REASON_CAP - 2) / 2));
    assert_eq!(kept.len(), OPEN_REASON_CAP - 1);
    let text = store_text(long.as_bytes());
    let reason = text
        .split_once(" open failed: ")
        .map(|(_, r)| r)
        .expect("the 1.5.5 shape");
    assert!(!reason.contains('\u{FFFD}'), "cut inside a char: {reason}");
    assert_eq!(reason, kept);
}

/// A plugin that writes no reason reads as 1.5.5 read a constructor error with no text.
#[test]
fn a_plugin_that_writes_no_reason_reads_as_a_stable_text() {
    assert_eq!(
        store_text(b""),
        "plugin 'open-reason-store' open failed: status 1"
    );
}

fn octets(b: &[u8]) -> Blob {
    Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    }
}

/// A kind on the SDK's generic lifecycle whose `validate` and `open` refuse in their own OWNED words
/// (no instance exists to keep them): each crossing is lent the host's reason buffer, the SDK
/// writes the words there, and the operator reads them byte for byte, with no per-thread slot on
/// the plugin's side.
#[test]
fn an_sdk_validate_and_open_say_their_own_owned_words_through_the_lent_buffers() {
    let d = dispatcher();
    let door: DoorFn = witness::life::door;
    let p = load_linked::<Secret>(door, bind(&d)).expect("the linked life door loads");

    let mut vi: ValidateIn = blank_in();
    vi.settings = octets(b"no port");
    let mut v = Frame::new(vi, blank_out::<OutHead>());
    let c = p.call(slot::VALIDATE, &mut v);
    assert_eq!(c.outcome, Outcome::Failed);
    assert_eq!(c.error.as_deref(), Some(&b"invalid: no port"[..]));

    let mut oi: OpenIn = blank_in();
    oi.settings = octets(b"boom: x");
    let mut o = Frame::new(oi, blank_out::<OpenOut>());
    let c = p.call(slot::OPEN, &mut o);
    assert_eq!(c.outcome, Outcome::Failed);
    assert_eq!(
        c.open_failure(p.name()),
        "plugin 'open-reason-life' open failed: boom: x"
    );
}
