// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/plane_host/trust_anchor.rs`.

use super::*;

/// A self-signed root certificate, parsed to DER the way the a2a boot resolver parses a
/// `trusting_root` PEM.
fn a_root() -> rustls_pki_types::CertificateDer<'static> {
    use rcgen::{CertificateParams, KeyPair};
    let kp = KeyPair::generate().expect("a key pair");
    let params = CertificateParams::new(vec!["root.test".to_string()]).expect("params");
    let cert = params.self_signed(&kp).expect("self-signed");
    cert.der().clone()
}

#[test]
fn register_then_resolve_returns_the_roots_and_unknown_is_empty() {
    let generation = TrustAnchorGeneration::install();
    let r = generation.register(vec![a_root()]);
    assert_ne!(r, 0, "a live ref is nonzero");
    assert_eq!(
        resolve(r).len(),
        1,
        "the registered ref resolves to its one root"
    );
    assert!(
        resolve(0).is_empty(),
        "the reserved 0 ref adds no extra roots"
    );
    assert!(
        resolve(u64::MAX).is_empty(),
        "an unknown ref resolves to no extra roots (fail-closed)"
    );
}

#[test]
fn distinct_registrations_get_distinct_refs() {
    let generation = TrustAnchorGeneration::install();
    let a = generation.register(vec![a_root()]);
    let b = generation.register(vec![a_root()]);
    assert_ne!(a, b, "each registration is a fresh opaque ref");
}

#[test]
fn an_empty_set_still_mints_a_live_ref() {
    let generation = TrustAnchorGeneration::install();
    let r = generation.register(Vec::new());
    assert_ne!(r, 0, "even an empty anchor set gets a nonzero ref");
    assert!(resolve(r).is_empty(), "which resolves to no extra roots");
}

/// A RETIRED GENERATION'S ANCHORS ARE UNREACHABLE.
///
/// A superseded anchor set must stop being resolvable when its owner lets go of it — otherwise a ref
/// handed out earlier still names roots the operator has since narrowed away. The retired ref adds no
/// extra roots at all, which is the fail-closed direction: the hop trusts only the platform roots.
#[test]
fn a_retired_generation_adds_no_extra_roots() {
    let retired_ref = {
        let generation = TrustAnchorGeneration::install();
        let r = generation.register(vec![a_root()]);
        assert_eq!(generation.len(), 1, "the anchor set is resident while held");
        assert_eq!(resolve(r).len(), 1);
        r
    };
    assert!(
        resolve(retired_ref).is_empty(),
        "a retired generation's ref widens trust nowhere"
    );
}

/// Retiring one generation leaves another's anchors alone — two bundles with private CAs coexist.
#[test]
fn retiring_one_generation_leaves_another_untouched() {
    let kept = TrustAnchorGeneration::install();
    let kept_ref = kept.register(vec![a_root()]);
    let discarded_ref = {
        let discarded = TrustAnchorGeneration::install();
        discarded.register(vec![a_root()])
    };
    assert!(
        resolve(discarded_ref).is_empty(),
        "the released generation's ref is retired"
    );
    assert_eq!(
        resolve(kept_ref).len(),
        1,
        "the generation still held keeps its root"
    );
}
