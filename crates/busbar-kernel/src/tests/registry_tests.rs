// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::overlaps;
use crate::grammar::Selector;

#[test]
fn sni_selectors_that_differ_only_in_case_overlap() {
    let left = Selector::Sni("Example.com");
    let right = Selector::Sni("example.com");
    assert!(
        overlaps(&left, &right),
        "Example.com and example.com are the SAME DNS name"
    );
}

#[test]
fn sni_selectors_for_genuinely_different_hosts_stay_disjoint() {
    let left = Selector::Sni("example.com");
    let right = Selector::Sni("other.example.org");
    assert!(!overlaps(&left, &right));
}

#[test]
fn alpn_selectors_that_differ_only_in_case_stay_disjoint() {
    let left = Selector::Alpn("H2");
    let right = Selector::Alpn("h2");
    assert!(!overlaps(&left, &right));
    assert!(!left.overlaps(&right), "the contract's own answer");
}

#[test]
fn alpn_selectors_for_different_protocols_stay_disjoint() {
    assert!(!overlaps(
        &Selector::Alpn("h2"),
        &Selector::Alpn("http/1.1")
    ));
}

#[test]
fn client_cert_subject_and_stream_name_stay_case_sensitive() {
    assert!(!overlaps(
        &Selector::ClientCertSubject("CN=Example"),
        &Selector::ClientCertSubject("CN=example")
    ));
    assert!(!overlaps(
        &Selector::StreamName("Control"),
        &Selector::StreamName("control")
    ));

    assert!(overlaps(
        &Selector::ClientCertSubject("CN=example"),
        &Selector::ClientCertSubject("CN=example")
    ));
}

#[test]
fn ports_still_compare_as_numbers() {
    assert!(overlaps(&Selector::Port(443), &Selector::Port(443)));
    assert!(!overlaps(&Selector::Port(443), &Selector::Port(8443)));
}

#[test]
fn claims_on_different_transports_never_collide() {
    use busbar_contract::grammar::{Claim, Selector};
    let a = Claim {
        transport: "http",
        selector: Selector::ExactPath("/v1/chat/completions"),
        scheme: Some("token"),
        scheme_alternatives: &[],
        idempotency: None,
    };
    let b = Claim {
        transport: "stdio",
        ..a
    };
    assert!(crate::registry::claims_overlap(&a, &a));
    assert!(!crate::registry::claims_overlap(&a, &b));
}

#[test]
fn different_transport_forms_still_conservatively_coincide() {
    assert!(overlaps(
        &Selector::Sni("example.com"),
        &Selector::Port(443)
    ));
}

#[test]
fn the_boot_seal_and_the_contract_agree_on_every_transport_pair() {
    let forms = [
        Selector::Sni("example.com"),
        Selector::Sni("Example.com"),
        Selector::Sni("other.example"),
        Selector::Alpn("h2"),
        Selector::Alpn("H2"),
        Selector::Alpn("http/1.1"),
        Selector::ClientCertSubject("CN=example"),
        Selector::ClientCertSubject("CN=Example"),
        Selector::StreamName("control"),
        Selector::StreamName("Control"),
        Selector::Port(443),
        Selector::Port(8443),
    ];
    for left in &forms {
        for right in &forms {
            assert_eq!(
                overlaps(left, right),
                left.overlaps(right),
                "the boot seal and the contract disagree on {left:?} vs {right:?}"
            );
        }
    }
}

#[test]
fn process_generation_exhaustion_never_wraps_or_reuses_first() {
    use std::sync::atomic::{AtomicU64, Ordering};
    let sequence = AtomicU64::new(u64::MAX - 1);
    assert_eq!(
        Generation::allocate_from(&sequence).unwrap().get(),
        u64::MAX - 1
    );
    assert!(Generation::allocate_from(&sequence).is_err());
    assert!(Generation::allocate_from(&sequence).is_err());
    assert_eq!(sequence.load(Ordering::Relaxed), u64::MAX);
}

#[test]
fn concurrent_process_generations_are_unique() {
    let mut values = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..16)
            .map(|_| scope.spawn(|| Generation::allocate().unwrap()))
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });
    values.sort_unstable();
    assert!(values.iter().all(|value| *value != Generation::FIRST));
    assert!(values.windows(2).all(|pair| pair[0] < pair[1]));
}
