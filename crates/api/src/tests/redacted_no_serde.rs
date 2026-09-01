// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SERDE FENCE for [`Redacted`](crate::Redacted) — a compile-time pin that a secret VALUE can
//! NEVER be serialized into an audit record, a wire payload, on-disk config, or a log line by
//! construction. The single structural guarantee the whole secret-hygiene design rests on
//! (`docs/design/1.6.0-secret-hygiene.md`, Part 2 §2.1(b) + Part 3, Check 3) is:
//!
//!   > `Redacted<T>` deliberately implements NEITHER `Serialize` NOR `Deserialize`.
//!
//! `redacted.rs` states this in a comment; this file makes it a TEST that goes RED the instant a
//! future edit adds an `impl serde::Serialize for Redacted` (or a `#[derive(Serialize)]`-adjacent
//! glue) — so the invariant is enforced, not merely documented.
//!
//! ## The mechanism: AUTOREF SPECIALIZATION (no extra deps, genuinely detects the impl)
//!
//! We cannot write a `where Redacted<T>: !Serialize` bound on stable Rust (negative bounds are
//! unstable), and this crate deliberately carries no `static_assertions`/`trybuild` dev-dep. So we
//! detect the impl the way `redacted_tests.rs::redacted_does_not_implement_serialize` already does,
//! generalized to BOTH directions: a `Probe<T>` whose inherent method exists ONLY when `T: Serialize`
//! (resp. `DeserializeOwned`) and thereby SHADOWS a trait-default method that always reports `false`.
//! Method resolution picks the inherent method IFF the bound holds — so the returned bool is a live
//! reflection of "does an impl exist right now". A control probe over a type that IS `Serialize`/
//! `Deserialize` (plain `String`) proves the probe actually detects impls (it isn't vacuously false).

use super::*;

use core::marker::PhantomData;

/// A `Probe<T>` used to detect, at compile time, whether `T` implements a serde trait. The inherent
/// `impl` blocks below add a method that shadows the trait default ONLY when the bound is satisfied.
struct Probe<T>(PhantomData<T>);

// ── Serialize direction ────────────────────────────────────────────────────────────────────────
trait ViaSerDefault {
    /// Trait default: reports NO `Serialize` impl. Shadowed by the inherent `ser()` when `T: Serialize`.
    fn ser(&self) -> bool {
        false
    }
}
impl<T> ViaSerDefault for Probe<T> {}
impl<T: serde::Serialize> Probe<T> {
    fn ser(&self) -> bool {
        true
    }
}

// ── Deserialize direction ──────────────────────────────────────────────────────────────────────
trait ViaDeDefault {
    /// Trait default: reports NO `Deserialize` impl. Shadowed by the inherent `de()` when
    /// `T: DeserializeOwned`.
    fn de(&self) -> bool {
        false
    }
}
impl<T> ViaDeDefault for Probe<T> {}
impl<T: serde::de::DeserializeOwned> Probe<T> {
    fn de(&self) -> bool {
        true
    }
}

/// THE FENCE: `Redacted<String>` implements neither `Serialize` nor `Deserialize`. Either half going
/// green (someone adds an impl) flips this test RED — proving a secret value cannot reach a wire /
/// disk / audit / log sink through serde by construction. Kept a runtime `assert!` rather than a
/// `const` so the failure message names exactly which half regressed.
#[test]
fn redacted_implements_neither_serialize_nor_deserialize() {
    let secret_probe = Probe::<Redacted<String>>(PhantomData);
    assert!(
        !secret_probe.ser(),
        "FENCE BREACH: Redacted<T> must NOT implement serde::Serialize — a secret VALUE could now be \
         written into an audit record / wire payload / config dump / log line. Remove the impl."
    );
    assert!(
        !secret_probe.de(),
        "FENCE BREACH: Redacted<T> must NOT implement serde::Deserialize — a secret VALUE could now be \
         reconstructed from untrusted wire/disk input. Remove the impl."
    );

    // CONTROL: the probe is not vacuously false — over a type that genuinely IS Serialize AND
    // Deserialize (`String`), BOTH halves report true. This proves the fence detects real impls, so a
    // future `impl Serialize for Redacted` truly would be caught above.
    let control = Probe::<String>(PhantomData);
    assert!(
        control.ser(),
        "probe self-check: must detect a real Serialize impl (String is Serialize)"
    );
    assert!(
        control.de(),
        "probe self-check: must detect a real Deserialize impl (String is Deserialize)"
    );
}
