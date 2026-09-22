// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RED-before-GREEN: SNI (and ALPN) selectors have to be compared case-insensitively, the way a
//! DNS name — and a header NAME, at `registry.rs:468` — already is, not byte-wise. Byte-wise
//! comparison let two overlapping transport claims ("Example.com" and "example.com" name the SAME
//! host) clear the boot's claim-disjointness proof as though they were unrelated, which is exactly
//! the shape of two listeners fighting over one name.

use super::{overlaps, transport_overlaps};
use crate::grammar::Selector;

#[test]
fn sni_selectors_that_differ_only_in_case_overlap() {
    // RED before the fix: `Selector::Sni` was compared with plain `==`, which reads
    // "Example.com" and "example.com" as two different strings — false — even though they name
    // the exact same DNS host.
    let left = Selector::Sni("Example.com");
    let right = Selector::Sni("example.com");
    assert!(
        transport_overlaps(&left, &right),
        "Example.com and example.com are the SAME DNS name"
    );
    // And through the public entry point every real caller uses.
    assert!(overlaps(&left, &right));
}

#[test]
fn sni_selectors_for_genuinely_different_hosts_stay_disjoint() {
    // The other half of the proof: the fix must not have made every pair overlap. Two hosts that
    // are not the same name under ASCII case-folding are still judged disjoint.
    let left = Selector::Sni("example.com");
    let right = Selector::Sni("other.example.org");
    assert!(!transport_overlaps(&left, &right));
    assert!(!overlaps(&left, &right));
}

#[test]
fn alpn_selectors_that_differ_only_in_case_overlap() {
    // ALPN is the other name-shaped transport selector the task calls out: same idiom, same rule.
    let left = Selector::Alpn("H2");
    let right = Selector::Alpn("h2");
    assert!(transport_overlaps(&left, &right));
}

#[test]
fn alpn_selectors_for_different_protocols_stay_disjoint() {
    assert!(!transport_overlaps(
        &Selector::Alpn("h2"),
        &Selector::Alpn("http/1.1")
    ));
}

#[test]
fn client_cert_subject_and_stream_name_stay_case_sensitive() {
    // Neither a certificate subject nor a multiplexed stream name is a DNS name, so the fix must
    // not have blanket-lowercased the whole function: a subject or a stream name that differs only
    // in case is still a DIFFERENT value and the two claims are NOT judged to overlap on it.
    assert!(!transport_overlaps(
        &Selector::ClientCertSubject("CN=Example"),
        &Selector::ClientCertSubject("CN=example")
    ));
    assert!(!transport_overlaps(
        &Selector::StreamName("Control"),
        &Selector::StreamName("control")
    ));
    // Same value, same case, still overlaps — the arm is exact-match, not "never overlaps".
    assert!(transport_overlaps(
        &Selector::ClientCertSubject("CN=example"),
        &Selector::ClientCertSubject("CN=example")
    ));
}

#[test]
fn ports_still_compare_as_numbers() {
    assert!(transport_overlaps(
        &Selector::Port(443),
        &Selector::Port(443)
    ));
    assert!(!transport_overlaps(
        &Selector::Port(443),
        &Selector::Port(8443)
    ));
}

#[test]
fn different_transport_forms_still_conservatively_coincide() {
    // Unrelated to the case-folding fix, but load-bearing for it: the `_ => true` fallback for
    // two DIFFERENT transport forms (e.g. an SNI claim and a port claim) must survive splitting the
    // match arm apart.
    assert!(transport_overlaps(
        &Selector::Sni("example.com"),
        &Selector::Port(443)
    ));
}
