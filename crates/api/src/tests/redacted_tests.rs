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
