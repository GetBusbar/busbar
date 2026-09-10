// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The per-kind batteries, and the universal rows every kind's battery starts with.
//!
//! `docs/design/PLUGIN-TREE.md` §3 puts one line in every sibling's `src/tests/conformance.rs` —
//! `plugin_testkit::<kind>::battery(&P)` — and §6 step 10 makes the battery a precondition of the
//! kind being gate-enforced at all: *a kind with no battery may not be gate-enforced*. So a kind
//! that has just been named by an owner ruling owes its battery on the same commit as its `Kind`
//! variant, before any crate of it exists, or the gate rows written for it are rows nothing can be
//! held to.
//!
//! ## What these two batteries check, and what they OWE
//!
//! A battery is only as wide as the contract it can call. `control::Control` and
//! `dialect::Dialect` — the ONE trait each kind gets under §6 step 5 — do not ship yet, so what is
//! checkable today is the declaration half: the kind a crate says it is, and the key and interface
//! generation it says that under. That half is not a formality. It is what the isolation gate's
//! registry row cross-checks a crate's NAME against, and it is the whole of the defect the kind
//! variants were added to close: before them the only kind a control surface or a dialect could
//! return was `Plane`, the one kind each is explicitly not.
//!
//! Each battery below names its owed rows in its own doc rather than in a tracking document, so a
//! plugin author calling it is never left believing it checked more than it did.

use busbar_contract::{Kind, Plugin};

/// The rows every kind's battery runs first, whatever its kind trait turns out to be.
///
/// `want` is the kind whose battery is running, so "declares its kind once, and it is THIS one" is
/// one assertion rather than two that could disagree.
fn declaration(p: &dyn Plugin, want: Kind) {
    let kind = p.kind();
    assert_eq!(
        kind, want,
        "this is the `{want}` battery and the plugin declares kind `{kind}`. A plugin's kind is \
         what the registry seals it under and what the kind-isolation gate checks its crate name \
         and its dependency edges against; calling another kind's battery cannot make it that kind"
    );
    assert_eq!(
        p.kind(),
        kind,
        "`kind()` answered two different kinds in one run. It is a constant in practice and the \
         boot seal reads it once"
    );

    let key = p.key();
    assert!(
        !key.is_empty(),
        "a plugin's registry key is what the kernel dispatches on; the empty key dispatches nothing"
    );
    assert_eq!(
        key,
        key.to_ascii_lowercase(),
        "registry keys are lowercase, so `{key}` and its other casings are not two registrations"
    );
    assert_eq!(
        key,
        key.trim(),
        "the registry key `{key:?}` carries surrounding whitespace, which no operator writing it \
         in a configuration will reproduce"
    );
    assert_eq!(
        p.key(),
        key,
        "`key()` answered two different keys in one run; a key is leaked to `&'static str` exactly \
         once, at the boot seal"
    );

    let abi = p.abi();
    assert_eq!(
        p.abi(),
        abi,
        "`abi()` answered two different generations in one run; the registry compares it once"
    );
    assert!(
        abi.0 > 0,
        "generation 0 is not a generation; a plugin declares the interface it was BUILT against, \
         and the registry refuses one below its kind's floor"
    );
}

/// The CONTROL battery: a control surface is well-formed.
///
/// Runs the declaration rows over `Kind::Control`.
///
/// OWED, with `control::Control` and its `ControlMeta` consts (`PLUGIN-TREE.md` §1's control row):
/// claim-table completeness (every route it answers is in its claim table), route uniqueness
/// across control surfaces, unmetered (it declares no meter class), no-upstream, and refusal
/// coverage. Four of those five are ALREADY held over the tree by `kind-isolation:control-path`
/// and the registry row's shared-route check, which read the crate's source and its claim table as
/// data — this battery is what will hold them over an out-of-tree surface the gate cannot read.
///
/// # Panics
/// On any row above, naming the surface and what it declared.
pub fn control(p: &dyn Plugin) {
    declaration(p, Kind::Control);
}

/// The DIALECT battery: a plane's wire dialect is well-formed.
///
/// Runs the declaration rows over `Kind::Dialect`.
///
/// OWED, with `dialect::Dialect` and its `DialectMeta` consts (`PLUGIN-TREE.md` §1's dialect row):
/// purity, determinism, object-safety, round-trip byte-exactness, and claim-rung uniqueness. The
/// byte-exactness row is the one that cannot be approximated by a source scan and is the reason
/// this kind's battery is owed rather than optional: a dialect IS a translation, and a translation
/// with no round-trip is an assertion nobody made.
///
/// # Panics
/// On any row above, naming the dialect and what it declared.
pub fn dialect(p: &dyn Plugin) {
    declaration(p, Kind::Dialect);
}

#[cfg(test)]
#[path = "tests/kinds_tests.rs"]
mod tests;
