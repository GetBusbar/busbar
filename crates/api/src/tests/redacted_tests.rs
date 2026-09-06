// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/api/src/redacted.rs`.

use super::*;

/// The core guarantee: neither `Debug` nor `Display` ever contains the secret material.
#[test]
fn debug_and_display_never_reveal_the_secret() {
    let secret = "sk-super-secret-value-12345";
    let r = Redacted::new(secret.to_string());
    assert_eq!(format!("{r:?}"), "[REDACTED]");
    assert_eq!(format!("{r}"), "[REDACTED]");
    assert!(!format!("{r:?}").contains(secret));
    assert!(!format!("{r}").contains(secret));
    // And it is reachable only through the explicit audit point.
    assert_eq!(r.expose_secret(), secret);
}

/// A struct that embeds a `Redacted` field and derives `Debug` inherits the redaction — proving
/// the guarantee is STRUCTURAL (the whole point: no call site has to remember to redact).
#[test]
fn embedded_in_a_derived_debug_struct_is_redacted() {
    #[derive(Debug)]
    #[allow(dead_code)] // fields are read via the derived Debug, which dead-code analysis ignores
    struct Holder {
        id: String,
        token: Redacted<String>,
    }
    let h = Holder {
        id: "acct-1".into(),
        token: Redacted::new("bearer-abc-XYZ".to_string()),
    };
    let dbg = format!("{h:?}");
    assert!(
        dbg.contains("acct-1"),
        "non-secret fields still show: {dbg}"
    );
    assert!(
        !dbg.contains("bearer-abc-XYZ"),
        "the secret must not appear in a derived Debug: {dbg}"
    );
    assert!(dbg.contains("[REDACTED]"));
}

#[test]
fn clone_and_eq_operate_on_the_secret() {
    let a = Redacted::new("v".to_string());
    let b = a.clone();
    assert_eq!(a, b);
    assert_ne!(a, Redacted::new("w".to_string()));
}

/// Equality stays a GENUINE equality after being routed through the crate's `constant_time_eq`:
/// equal secrets compare equal, equal-length-but-differing ones do not, ragged lengths do not, and
/// empty compares equal to empty.
///
/// The name says correctness and not timing on purpose. Nothing below observes a duration, and
/// nothing below could: a wall-clock assertion on a comparison this short is a coin flip under a
/// loaded CI box, and a test that flakes is a test that gets deleted. The timing property is a
/// property of `constant_time_eq` itself and is asserted where that primitive lives; what this
/// file owes is that swapping a plain `==` for it did not quietly change what "equal" means — the
/// failure a timing-safe rewrite actually tends to introduce.
#[test]
fn eq_stays_a_correct_equality_through_the_timing_safe_compare() {
    // Equal secrets compare equal.
    assert_eq!(
        Redacted::new("sk-abc-123".to_string()),
        Redacted::new("sk-abc-123".to_string())
    );
    // Equal length, differing bytes (the case a data-dependent `memcmp` would short-circuit) — the
    // constant-time compare still returns not-equal.
    assert_ne!(
        Redacted::new("sk-abc-123".to_string()),
        Redacted::new("sk-abc-124".to_string())
    );
    // Differing lengths compare not-equal.
    assert_ne!(
        Redacted::new("sk-abc".to_string()),
        Redacted::new("sk-abc-123".to_string())
    );
    // Empty vs empty is equal.
    assert_eq!(Redacted::new(String::new()), Redacted::new(String::new()));
}

/// `Drop` for `Redacted<T>` MUST actually call `T::zeroize` — the whole point of the wrapper is
/// that the backing memory is overwritten when it goes out of scope, not left as freed-but-intact
/// plaintext. A test type that records whether `zeroize` ran (rather than asserting on process
/// memory, which isn't reliably observable from safe Rust) pins this directly: mutating the `Drop`
/// body to a no-op `()` must fail this test.
#[test]
fn drop_actually_calls_zeroize() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    struct FlagOnZeroize(Arc<AtomicBool>);
    impl zeroize::Zeroize for FlagOnZeroize {
        fn zeroize(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    let flag = Arc::new(AtomicBool::new(false));
    {
        let _r = Redacted::new(FlagOnZeroize(flag.clone()));
        assert!(!flag.load(Ordering::SeqCst), "must not zeroize before drop");
    }
    assert!(
        flag.load(Ordering::SeqCst),
        "Redacted's Drop must call the backing value's zeroize"
    );
}

/// `Redacted` must NOT implement `serde::Serialize`, so a secret held in engine memory has no
/// implicit path into JSON (the credential-transport boundary uses a plain wire `String`, on
/// purpose). This uses AUTOREF SPECIALIZATION to actually detect the impl at test time: the
/// inherent `ser` (which requires `T: Serialize`) shadows the trait-default `ser` IFF a
/// `Serialize` impl exists — so unlike an unconstrained generic, this test FLIPS to red the moment
/// someone adds `#[derive(Serialize)]` to `Redacted`.
#[test]
fn redacted_does_not_implement_serialize() {
    use core::marker::PhantomData;
    struct Probe<T>(PhantomData<T>);
    trait ViaTraitDefault {
        fn ser(&self) -> bool {
            false
        }
    }
    impl<T> ViaTraitDefault for Probe<T> {}
    // Inherent method: exists ONLY when T: Serialize, and shadows the trait default when present.
    impl<T: serde::Serialize> Probe<T> {
        fn ser(&self) -> bool {
            true
        }
    }
    let probe = Probe::<Redacted<String>>(PhantomData);
    assert!(
        !probe.ser(),
        "Redacted<T> must NOT implement Serialize (add one and this test goes red)"
    );
    // Sanity: the probe DOES report true for a type that is Serialize (proving it detects impls).
    let control = Probe::<String>(PhantomData);
    assert!(control.ser(), "probe must detect a real Serialize impl");
}
