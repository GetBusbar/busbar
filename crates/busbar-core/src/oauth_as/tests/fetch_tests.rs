// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PRODUCTION FETCH ITSELF, and the judgment about what names a document.
//!
//! `busbar-control-oauth2`'s own `cimd_tests` drive a STUB fetch, which is right — the document
//! checks are the property under test there and a real socket would only add flakiness. But it
//! means the stub is the only `CimdFetch` those tests have ever constructed, and [`GuardedFetch`] —
//! the one production actually installs — is reached by no test at all. The three tests below are
//! the ones that notice if its bounds, its grammar or its guard call are changed: neither the
//! stub-driven tests in the surface crate nor `net_guard`'s own tests (which judge the guard given
//! a policy, never THIS policy) go red for any of those edits.
//!
//! They live HERE rather than in the surface crate for the same reason `GuardedFetch` does: what
//! they check is where a socket may go, which is the node's question.

use busbar_control_oauth2::cimd::CimdFetch as _;

use super::{fetch_policy, GuardedFetch, FETCH_TIMEOUT, MAX_DOCUMENT_BYTES};

/// A well-formed metadata-document `client_id`.
const URL: &str = "https://client.example/oauth-client";

/// What is a metadata-document `client_id` at all: HTTPS, parseable, fragment-free. Everything
/// else stays an ordinary opaque identifier and never reaches the fetch.
#[test]
fn only_a_fragment_free_https_url_names_a_document() {
    assert!(GuardedFetch.names_a_document(URL));
    assert!(
        !GuardedFetch.names_a_document("flow-test-client"),
        "an opaque id"
    );
    assert!(
        !GuardedFetch.names_a_document("http://client.example/oauth-client"),
        "plaintext cannot bind a document to its owner"
    );
    assert!(!GuardedFetch.names_a_document("https://client.example/doc#frag"));
    assert!(!GuardedFetch.names_a_document("https://"), "no host");
}

/// THE BOUNDS THE PRODUCTION FETCH RUNS UNDER, asserted rather than assumed. Each of the five is
/// load-bearing and none is reachable from configuration — there is deliberately no operator knob
/// on this path, because a CIMD `client_id` is a STRANGER'S URL by definition and there is no
/// operator intent for a knob to carry.
///
/// This is the test that goes red if `allow_private` is ever flipped true here. `net_guard`'s
/// tests would not: they prove the guard refuses internal addresses *when the policy says so*, and
/// this function is where this path says so.
#[test]
fn the_production_fetch_policy_is_the_bounded_one() {
    let policy = fetch_policy();
    assert!(
        !policy.allow_private,
        "the CIMD fetch reaches a URL a stranger chose; opting it into private addressing turns \
         an unauthenticated endpoint into an internal-network probe"
    );
    assert!(
        !policy.allow_plaintext,
        "the document IS the client's identity; one fetched over plaintext is rewritable in flight"
    );
    assert_eq!(
        policy.max_redirects, 0,
        "a 3xx is a fresh, unvalidated URL: the document lives at the `client_id` or it is not \
         that client's document"
    );
    assert_eq!(
        policy.max_body_bytes, MAX_DOCUMENT_BYTES,
        "the fetch must run under the document ceiling, not some other one"
    );
    assert_eq!(
        MAX_DOCUMENT_BYTES,
        5 * 1024,
        "a metadata document is a few kilobytes; anything larger is an allocation whose size the \
         URL's owner chose"
    );
    assert_eq!(
        policy.timeout, FETCH_TIMEOUT,
        "the fetch sits on an interactive authorization request and must fail the one login \
         rather than park a handler"
    );
    assert_eq!(FETCH_TIMEOUT, std::time::Duration::from_secs(10));
}

/// THE GUARD IS ACTUALLY WIRED IN. Every value here is refused STRUCTURALLY — by name, by literal,
/// or by scheme — so this test opens no socket and consults no resolver, which is the guard's own
/// design and the reason a loopback name cannot be won by a rebinding attacker.
///
/// The point is the WIRING, not the ranges: `net_guard`'s tests already prove the predicate. This
/// one proves [`GuardedFetch`] calls it, and goes red if the `judge_scheme` /
/// `resolve_and_pin_async` pair is ever dropped from the fetch — an edit that leaves every other
/// test in the tree green while pointing an unauthenticated endpoint at IMDS.
#[tokio::test]
async fn the_production_fetch_refuses_the_addresses_the_guard_exists_for() {
    for (client_id, expected) in [
        // Loopback, by name and by literal, v4 and v6.
        ("https://localhost/oauth-client", "loopback name"),
        ("https://127.0.0.1/oauth-client", "internal address"),
        ("https://[::1]/oauth-client", "internal address"),
        // Cloud metadata, by address and by name. Refused unconditionally.
        (
            "https://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "cloud-metadata address",
        ),
        (
            "https://100.100.100.200/latest/meta-data/",
            "cloud-metadata address",
        ),
        (
            "https://metadata.google.internal/computeMetadata/v1/",
            "cloud-metadata name",
        ),
        // Plaintext, refused at the scheme before anything is resolved.
        ("http://app.example.com/oauth-client", "plaintext"),
    ] {
        let why = GuardedFetch
            .fetch(client_id)
            .await
            .expect_err("the authorization server fetched `{client_id}`");
        assert!(
            why.contains(expected),
            "`{client_id}` was refused, but not as `{expected}`: {why}"
        );
    }
}
