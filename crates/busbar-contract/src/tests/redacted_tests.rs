// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-contract/src/redacted.rs`.

use super::*;

/// The core guarantee: neither `Debug` nor `Display` ever contains the secret material.
#[test]
fn debug_and_display_never_reveal_the_secret() {
    let secret = "sk-super-secret-value-12345";
    let r = Secret::new(secret.to_string());
    assert_eq!(format!("{r:?}"), "[REDACTED]");
    assert_eq!(format!("{r}"), "[REDACTED]");
    assert!(!format!("{r:?}").contains(secret));
    assert!(!format!("{r}").contains(secret));

    assert_eq!(r.expose(&crate::plugin::TestKernelSeal), secret);
}

/// RED (Part 2 #54, coordinator ruling 2026-10-14): `Debug`, `Display` and `to_string` render the
#[test]
fn debug_display_and_to_string_are_the_1_5_5_bytes() {
    let text = Secret::new("sk-live-0001".to_string());
    let bytes = Secret::new(b"\x01\x02".to_vec());
    for rendered in [
        format!("{text:?}"),
        format!("{text}"),
        text.to_string(),
        format!("{bytes:?}"),
        format!("{bytes}"),
        bytes.to_string(),
    ] {
        assert_eq!(rendered.as_bytes(), b"[REDACTED]");
    }
}

/// A struct that embeds a `Secret` field and derives `Debug` inherits the redaction — proving
#[test]
fn embedded_in_a_derived_debug_struct_is_redacted() {
    #[derive(Debug)]
    #[allow(dead_code)]
    struct Holder {
        id: String,
        token: Secret<String>,
    }
    let h = Holder {
        id: "acct-1".into(),
        token: Secret::new("token-abc-XYZ".to_string()),
    };
    let dbg = format!("{h:?}");
    assert!(
        dbg.contains("acct-1"),
        "non-secret fields still show: {dbg}"
    );
    assert!(
        !dbg.contains("token-abc-XYZ"),
        "the secret must not appear in a derived Debug: {dbg}"
    );
    assert!(dbg.contains("[REDACTED]"));
}

#[test]
fn clone_and_eq_operate_on_the_secret() {
    let a = Secret::new("v".to_string());
    let b = a.clone();
    assert_eq!(a, b);
    assert_ne!(a, Secret::new("w".to_string()));
}

/// Equality is CONSTANT-TIME: it routes through the crate's `constant_time_eq` over the secret
#[test]
fn eq_is_constant_time_and_correct() {
    assert_eq!(
        Secret::new("sk-abc-123".to_string()),
        Secret::new("sk-abc-123".to_string())
    );

    assert_ne!(
        Secret::new("sk-abc-123".to_string()),
        Secret::new("sk-abc-124".to_string())
    );

    assert_ne!(
        Secret::new("sk-abc".to_string()),
        Secret::new("sk-abc-123".to_string())
    );

    assert_eq!(Secret::new(String::new()), Secret::new(String::new()));
}

/// `Drop` for `Secret<T>` MUST actually call `T::zeroize` — the whole point of the wrapper is
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
        let _r = Secret::new(FlagOnZeroize(flag.clone()));
        assert!(!flag.load(Ordering::SeqCst), "must not zeroize before drop");
    }
    assert!(
        flag.load(Ordering::SeqCst),
        "Secret's Drop must call the backing value's zeroize"
    );
}

#[test]
fn constant_time_eq_basics() {
    assert!(constant_time_eq("secret", "secret"));
    assert!(!constant_time_eq("short", "longer"));
    assert!(!constant_time_eq("secret1", "secret2"));
}

#[test]
fn sha256_hex_is_lowercase_64() {
    let h = sha256_hex(b"busbar");
    assert_eq!(h.len(), 64);
    assert_eq!(h, h.to_lowercase());
}

/// KNOWN-ANSWER VECTORS. The shape assertions above -- 64 chars, lower-case -- are satisfied by a
#[test]
fn sha256_hex_matches_the_published_test_vectors() {
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

crate::own_seal!(Own);

/// A PLUGIN'S OWN SECRET (Part 2 #54, coordinator ruling on #1192): the same `Secret`, under the
#[test]
fn a_secret_the_crate_holds_reads_back_only_under_its_own_seal_and_stays_redacted() {
    let held: Secret<String, Own> = Secret::held("sk-own-0001".to_string());
    assert_eq!(held.expose_own(&Own::here()), "sk-own-0001");
    assert_eq!(format!("{held:?}"), "[REDACTED]");
    assert_eq!(format!("{held}"), "[REDACTED]");
    assert_eq!(held.to_string(), "[REDACTED]");
    assert!(held == held.clone());
    assert!(held != Secret::<String, Own>::held("sk-own-0002".to_string()));

    let kernel = Secret::new("sk-live".to_string());
    assert_eq!(kernel.expose(&crate::plugin::TestKernelSeal), "sk-live");
}
