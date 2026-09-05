// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The registry, its generations, and the boot-time question every pair of claims has to answer.

use std::sync::Arc;

use busbar_kernel::grammar::{Segment, Selector};
use busbar_kernel::registry::{
    bootstrap, check_claims, overlaps, precedence_order, BootstrapVerdict, Claim, Plugin,
    PluginKind, Registry, RegistryError,
};

struct Fake(&'static str, PluginKind);

impl Plugin for Fake {
    fn key(&self) -> &str {
        self.0
    }

    fn kind(&self) -> PluginKind {
        self.1
    }
}

fn plane(key: &'static str) -> Arc<dyn Plugin> {
    Arc::new(Fake(key, PluginKind::Plane))
}

/// One selector of every closed form. The overlap check has to be total over the cross-product of
/// these, which is what this fixture is for.
fn every_form() -> Vec<Selector> {
    vec![
        Selector::ExactPath("/a/b".into()),
        Selector::PrefixOneLevel("/a".into()),
        Selector::PathPattern(vec![Segment::Lit("a".into()), Segment::Var]),
        Selector::PathSuffix("/b".into()),
        Selector::PathContains("a".into()),
        Selector::HeaderExact("x-key".into(), "one".into()),
        Selector::HeaderPresent("x-key".into()),
        Selector::HeaderPrefix("x-key".into(), "on".into()),
        Selector::Sni("example.invalid".into()),
        Selector::ClientCertSubject("CN=one".into()),
        Selector::StreamName("control".into()),
        Selector::Alpn("h2".into()),
        Selector::Port(443),
    ]
}

#[test]
fn overlap_is_total_reflexive_and_symmetric_over_every_form_pair() {
    let forms = every_form();
    for left in &forms {
        assert!(overlaps(left, left), "{left:?} does not overlap itself");
        for right in &forms {
            // Total: every pair has an answer, and it is the same answer either way round.
            assert_eq!(
                overlaps(left, right),
                overlaps(right, left),
                "{left:?} vs {right:?}"
            );
        }
    }
}

#[test]
fn two_claims_that_could_both_match_are_refused_at_boot() {
    let claims = vec![
        Claim {
            plane: "left".into(),
            transport: "wire".into(),
            selector: Selector::ExactPath("/v1/thing".into()),
        },
        Claim {
            plane: "right".into(),
            transport: "wire".into(),
            selector: Selector::PathPattern(vec![Segment::Lit("v1".into()), Segment::Var]),
        },
    ];
    let conflict = check_claims(&claims).expect_err("a variable segment covers the literal one");
    assert_eq!(conflict.left.plane, "left");
    assert_eq!(conflict.right.plane, "right");
}

#[test]
fn claims_on_different_transports_never_collide() {
    let claims = vec![
        Claim {
            plane: "left".into(),
            transport: "wire".into(),
            selector: Selector::ExactPath("/same".into()),
        },
        Claim {
            plane: "right".into(),
            transport: "other".into(),
            selector: Selector::ExactPath("/same".into()),
        },
    ];
    assert!(check_claims(&claims).is_ok(), "the bytes never reach both");
}

#[test]
fn one_plane_may_overlap_its_own_claims_and_they_are_ordered_most_specific_first() {
    let claims = vec![
        Claim {
            plane: "one".into(),
            transport: "wire".into(),
            selector: Selector::PathPattern(vec![Segment::Lit("v1".into()), Segment::Var]),
        },
        Claim {
            plane: "one".into(),
            transport: "wire".into(),
            selector: Selector::ExactPath("/v1/thing".into()),
        },
    ];
    assert!(check_claims(&claims).is_ok());
    // The literal path is tried before the pattern that could also match it.
    assert_eq!(precedence_order(&claims), vec![1, 0]);
}

#[test]
fn distinct_exact_paths_and_distinct_headers_do_not_overlap() {
    assert!(!overlaps(
        &Selector::ExactPath("/one".into()),
        &Selector::ExactPath("/two".into())
    ));
    assert!(!overlaps(
        &Selector::HeaderExact("x-a".into(), "1".into()),
        &Selector::HeaderExact("x-b".into(), "1".into())
    ));
    assert!(!overlaps(&Selector::Port(80), &Selector::Port(443)));
}

#[test]
fn a_present_header_claim_overlaps_every_claim_on_that_header() {
    assert!(overlaps(
        &Selector::HeaderPresent("x-key".into()),
        &Selector::HeaderExact("x-key".into(), "anything".into())
    ));
    assert!(overlaps(
        &Selector::HeaderPrefix("x-key".into(), "ab".into()),
        &Selector::HeaderExact("x-key".into(), "abc".into())
    ));
    assert!(!overlaps(
        &Selector::HeaderPrefix("x-key".into(), "ab".into()),
        &Selector::HeaderExact("x-key".into(), "zz".into())
    ));
}

#[test]
fn a_key_may_be_registered_once_per_kind() {
    let mut registry = Registry::new();
    registry.register(plane("one")).expect("the first one");
    let refused = registry.register(plane("one")).expect_err("the second one");
    assert!(matches!(refused, RegistryError::DuplicateKey { .. }));
    assert_eq!(registry.count(PluginKind::Plane), 1);
}

#[test]
fn a_unit_keeps_the_plugin_it_started_with_across_a_reload() {
    let mut registry = Registry::new();
    let first = registry.register(plane("one")).expect("registered");
    assert!(registry.resolve(PluginKind::Plane, "one").is_some());

    let second = registry.replace(plane("one"));
    assert_ne!(first, second);
    // The unit that started at the first generation still resolves, and resolves to what it
    // started with; a unit starting now gets the replacement.
    assert!(registry
        .resolve_at(PluginKind::Plane, "one", first)
        .is_some());
    assert!(registry
        .resolve_at(PluginKind::Plane, "one", second)
        .is_some());

    let third = registry.retire(PluginKind::Plane, "one");
    assert!(registry.resolve(PluginKind::Plane, "one").is_none());
    assert!(
        registry
            .resolve_at(PluginKind::Plane, "one", second)
            .is_some(),
        "a unit in flight when the plugin was retired still finishes"
    );
    assert!(registry
        .resolve_at(PluginKind::Plane, "one", third)
        .is_none());
}

#[test]
fn a_deployment_is_bootstrapped_exactly_once() {
    let fingerprint = [7u8; 32];
    // First boot of a deployment whose store holds no bootstrap: mint.
    assert_eq!(bootstrap(None, None), BootstrapVerdict::Mint);
    // A second bootstrap attempt on a store that already holds one does NOT mint again.
    assert_eq!(
        bootstrap(Some(fingerprint), Some(fingerprint)),
        BootstrapVerdict::AlreadyOurs
    );
    // And a node that does not hold the deployment's keyset refuses to serve rather than minting a
    // second one, which is the failure where nodes quietly stop trusting each other.
    assert_eq!(
        bootstrap(Some(fingerprint), Some([9u8; 32])),
        BootstrapVerdict::KeysetMissing
    );
    assert_eq!(
        bootstrap(Some(fingerprint), None),
        BootstrapVerdict::KeysetMissing
    );
}
