// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RED-before-GREEN: SNI selectors have to be compared case-insensitively, the way a DNS name — and
//! a header NAME — already is, not byte-wise. Byte-wise comparison let two overlapping transport
//! claims ("Example.com" and "example.com" name the SAME host) clear the boot's claim-disjointness
//! proof as though they were unrelated, which is exactly the shape of two listeners fighting over
//! one name.
//!
//! ALPN is NOT a DNS name: a protocol id is an opaque byte string (RFC 7301) and the contract's
//! published rule compares it byte-exactly. The kernel's boot seal used to fold its case in a
//! transcribed copy of the transport arms, so the engine and the contract answered one question
//! oppositely (item 283). The transport forms are now the contract's rule, read, not copied — and
//! the last test here holds the two to one answer over every transport pair.

use super::overlaps;
use crate::grammar::Selector;

#[test]
fn sni_selectors_that_differ_only_in_case_overlap() {
    // RED before the fix: `Selector::Sni` was compared with plain `==`, which reads
    // "Example.com" and "example.com" as two different strings — false — even though they name
    // the exact same DNS host.
    let left = Selector::Sni("Example.com");
    let right = Selector::Sni("example.com");
    assert!(
        overlaps(&left, &right),
        "Example.com and example.com are the SAME DNS name"
    );
}

#[test]
fn sni_selectors_for_genuinely_different_hosts_stay_disjoint() {
    // The other half of the proof: the fix must not have made every pair overlap. Two hosts that
    // are not the same name under ASCII case-folding are still judged disjoint.
    let left = Selector::Sni("example.com");
    let right = Selector::Sni("other.example.org");
    assert!(!overlaps(&left, &right));
}

#[test]
fn alpn_selectors_that_differ_only_in_case_stay_disjoint() {
    // A protocol id is a byte string, not a name: `H2` is not `h2`, and the published contract says
    // so. RED before item 283: the kernel folded ALPN case and called these one claim.
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
    // Neither a certificate subject nor a multiplexed stream name is a DNS name, so the fix must
    // not have blanket-lowercased the whole function: a subject or a stream name that differs only
    // in case is still a DIFFERENT value and the two claims are NOT judged to overlap on it.
    assert!(!overlaps(
        &Selector::ClientCertSubject("CN=Example"),
        &Selector::ClientCertSubject("CN=example")
    ));
    assert!(!overlaps(
        &Selector::StreamName("Control"),
        &Selector::StreamName("control")
    ));
    // Same value, same case, still overlaps — the arm is exact-match, not "never overlaps".
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
fn different_transport_forms_still_conservatively_coincide() {
    // Unrelated to the case-folding fix, but load-bearing for it: the `_ => true` fallback for
    // two DIFFERENT transport forms (e.g. an SNI claim and a port claim) must survive splitting the
    // match arm apart.
    assert!(overlaps(
        &Selector::Sni("example.com"),
        &Selector::Port(443)
    ));
}

/// ONE RULE FOR THE TRANSPORT FORMS (item 283). The boot seal and the contract's published
/// `Selector::overlaps` must give the same answer for every pair of transport selectors, case
/// variants included — the contract is what a plugin author reads to decide whether a claim is
/// disjoint, and a boot that disagrees with it refuses (or admits) claims the author was told the
/// opposite about.
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

/// THE GENERATION STORY SAYS WHAT DRIVES IT, AND NOTHING DOES (item 559).
///
/// The module doc and `UnitCtx.generation` presented generation pinning as the live reload-safety
/// story ("even while a replacement is being installed underneath it"). Nothing in production
/// installs one: the registry is built once at boot and the configuration reload never touches it.
/// The prose may describe the mechanism; it may not state as a fact a reload that does not happen,
/// and it must own the retention debt `replace` carries.
#[test]
fn the_generation_story_does_not_claim_a_reload_that_never_runs() {
    let registry = include_str!("../registry.rs");
    let teller = include_str!("../teller.rs");
    for (file, src) in [("registry.rs", registry), ("teller.rs", teller)] {
        let prose = src
            .lines()
            .map(str::trim_start)
            .filter(|l| l.starts_with("//"))
            .map(|l| l.trim_start_matches('/').trim_start_matches('!').trim())
            .collect::<Vec<_>>()
            .join(" ");
        for live_claim in [
            "Reloading configuration does not mutate the list a running unit is walking",
            "keeps calling the same plugins all the way to its end, even while a replacement is being installed",
            "with even while a reload installs a replacement",
        ] {
            assert!(
                !prose.contains(live_claim),
                "{file} states a live reload the tree never drives: {live_claim:?}"
            );
        }
    }
    assert!(
        registry.contains("NOTHING in production installs one")
            && registry.contains("push-only"),
        "registry.rs must say the generation mechanism is undriven and its entries are never released"
    );
    // The behaviour the prose now describes: a registry nobody replaces stays at the first
    // generation, which is what every production unit pins.
    assert_eq!(
        super::Registry::new().generation(),
        super::Generation::FIRST
    );
}
