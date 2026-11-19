// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-FETCH-STATUS (core 3.0, interface revision E.1 and E.7): the status-only FETCH over the whole crossing,
//! on the test host. One side is the engine's real half (admission, the driver's Need decoder, the secret
//! adapter, reached through [`Harness`]); the other is the reference caller (`fixtures/ref_status_fetch.rs`),
//! which makes the call the way `busbar-export-webhook` does.
//!
//! What is proven here: the flag crosses (the decoder accepts bit 24 on a FETCH and hands the test host a
//! `FetchNeed` with `status_only`), the answer is the status and the headers with NO body whatever the
//! receiver sent, a full FETCH of the same receiver still gets its body, and the test host's judge (`deny`)
//! refuses a status-only FETCH exactly as it refuses a full one. The real egress rules, the proxy and the
//! timeouts are the connector's and are proven there (`need_exchange_tests.rs`,
//! `native_need_authority_tests.rs`).

use std::time::{Duration, Instant};

use busbar_plugin_test::fake_needs::FakeNeeds;
use busbar_plugin_test::suites::harness::Harness;
use busbar_ports::{CallCx, PortError};

use crate::ref_status_fetch;

const URL: &str = "https://hooks.example.test/in";

fn cx() -> CallCx {
    CallCx {
        request_id: 1,
        deadline: Instant::now() + Duration::from_secs(30),
        stack: Default::default(),
        mono_ns: 0,
    }
}

fn reference(url: &str, mode: &str) -> Vec<u8> {
    format!(r#"{{"url":"{url}","mode":"{mode}"}}"#).into_bytes()
}

/// The receiver answers 202 with two headers and a 5-byte body. A full FETCH hands the plugin all three; a
/// status-only FETCH hands it the status and the headers and not one byte of the body.
#[test]
fn a_status_only_fetch_answers_the_status_and_headers_and_no_body() {
    let mut needs = FakeNeeds::new();
    let headers: [(&str, &[u8]); 2] = [("x-request-id", b"7"), ("retry-after", b"1")];
    needs.fetch("POST", URL, 202, &headers, b"hello");
    needs.fetch("POST", URL, 202, &headers, b"hello");
    let h = Harness::admit(ref_status_fetch::PLUGIN.plugin(), needs)
        .expect("the reference is admitted");
    let port = h.open_secret("status-fetch", b"{}").expect("opens");

    let full = h
        .block_on(port.resolve(cx(), &reference(URL, "full")))
        .expect("a full FETCH answers");
    assert_eq!(full.value.as_slice(), b"202 2 5");
    assert!(
        h.needs().status_only_fetches().is_empty(),
        "a full FETCH is not flagged"
    );

    let status = h
        .block_on(port.resolve(cx(), &reference(URL, "status")))
        .expect("a status-only FETCH answers");
    assert_eq!(
        status.value.as_slice(),
        b"202 2 0",
        "the status and both headers, and no body"
    );
    assert_eq!(h.needs().status_only_fetches(), [URL.to_owned()]);
    // Both went through the one FETCH step: the same destination, TLS and stated egress class.
    let seen = h.seen();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0], seen[1]);
    assert_eq!(
        (seen[1].op, seen[1].dest.as_str(), seen[1].tls),
        ("fetch", URL, true)
    );
}

/// A receiver whose answer is far over any cap is one delivery to a status-only FETCH (lean finding 1: with
/// a body cap it was a failure, resent for ever).
#[test]
fn a_status_only_fetch_of_a_receiver_with_a_large_body_is_its_status() {
    let mut needs = FakeNeeds::new();
    needs.fetch("POST", URL, 200, &[], &vec![b'x'; 1 << 20]);
    let h = Harness::admit(ref_status_fetch::PLUGIN.plugin(), needs)
        .expect("the reference is admitted");
    let port = h.open_secret("status-fetch", b"{}").expect("opens");
    let status = h
        .block_on(port.resolve(cx(), &reference(URL, "status")))
        .expect("a status-only FETCH answers");
    assert_eq!(status.value.as_slice(), b"200 0 0");
}

/// A destination the judge refuses is refused to a status-only FETCH as to a full one: the flag is no way
/// around the egress verdict.
#[test]
fn a_denied_destination_is_denied_to_a_status_only_fetch_too() {
    let private = "http://169.254.169.254/latest/meta-data";
    let mut needs = FakeNeeds::new();
    needs.deny(private);
    needs.fetch("POST", private, 200, &[], b"");
    needs.fetch("POST", private, 200, &[], b"");
    let h = Harness::admit(ref_status_fetch::PLUGIN.plugin(), needs)
        .expect("the reference is admitted");
    let port = h.open_secret("status-fetch", b"{}").expect("opens");
    for mode in ["full", "status"] {
        let refused = h.block_on(port.resolve(cx(), &reference(private, mode)));
        assert!(
            matches!(
                refused,
                Err(PortError::Refused { code, .. })
                    if code == busbar_plugin_abi::fail::refused::R_DENIED
            ),
            "{mode}: the judge's refusal reaches the plugin as R_DENIED"
        );
    }
    assert_eq!(h.seen().len(), 2, "both were judged");
    assert!(
        h.needs().status_only_fetches().is_empty(),
        "a denied FETCH never reaches the transport"
    );
}
