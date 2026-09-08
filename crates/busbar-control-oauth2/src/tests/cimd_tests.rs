// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOCUMENT CHECKS, adversarially. The flow test proves a GOOD document admits a client end
//! to end; every test here is a document that must NOT, each aimed at the specific escalation its
//! member exists to close. These are busbar's own checks (the tree pins `oauth-as` 0.9.3, which
//! ships a CIMD validator behind an off-by-default `cimd` feature this tree does not enable —
//! see the TODO in [`super`]), so they are the whole of the enforcement today and must each be
//! held red-able on their own.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use oauth_as::client::{ClientAuth, ClientId};
use oauth_as::scope::ScopeSet;
use oauth_as::store::{MemoryStorage, Storage as _};

use super::{
    fetch_policy, is_cimd_client_id, materialize, CimdFetch, CimdStore, GuardedFetch,
    FETCH_TIMEOUT, MAX_DOCUMENT_BYTES,
};

const URL: &str = "https://client.example/oauth-client";

fn ceiling() -> ScopeSet {
    ScopeSet::from_tokens(["read"]).expect("scope")
}

/// A well-formed document, which each refusal test below breaks in exactly one way — so a refusal
/// is about the broken member and not about a second defect the test never meant to have.
fn document() -> serde_json::Value {
    serde_json::json!({
        "client_id": URL,
        "redirect_uris": ["http://127.0.0.1:9999/cb"],
        "token_endpoint_auth_method": "none",
        "client_name": "an agent",
        "scope": "read",
    })
}

fn materialized(doc: &serde_json::Value) -> Result<oauth_as::client::Client, String> {
    materialize(
        URL,
        &serde_json::to_vec(doc).expect("serialises"),
        &ceiling(),
    )
}

/// The well-formed document materialises, and what it materialises is a PUBLIC client under the
/// operator's ceiling. Without this, every refusal below could be a validator that refuses
/// everything.
#[test]
fn a_well_formed_document_materialises_a_public_client_under_the_ceiling() {
    let client = materialized(&document()).expect("a well-formed document materialises");
    assert_eq!(client.client_id.as_str(), URL);
    assert!(matches!(client.auth, ClientAuth::Public));
    assert_eq!(client.allowed_scopes, ceiling());
    assert_eq!(
        client.redirect_uris,
        vec!["http://127.0.0.1:9999/cb".to_string()]
    );
    assert!(
        client.registration.is_none(),
        "a document client is not a stored dynamic registration; there is nothing to manage"
    );
}

/// THE BINDING CHECK. A document whose `client_id` is not the URL it was fetched from is any
/// attacker-controlled HTTPS URL claiming to be any client, which is the whole mechanism defeated.
#[test]
fn a_document_claiming_a_different_client_id_is_refused() {
    let mut doc = document();
    doc["client_id"] = serde_json::json!("https://other.example/victim");
    materialized(&doc).expect_err("a document may only describe the URL it lives at");

    let mut doc = document();
    doc.as_object_mut().expect("object").remove("client_id");
    materialized(&doc).expect_err("a document with no client_id describes nobody");
}

/// THE CEILING IS THE OPERATOR'S. A document asking past `default_grant` is REFUSED — not
/// narrowed — exactly as a DCR registrant is, because the two mechanisms share one ceiling.
#[test]
fn a_document_asking_past_the_default_grant_is_refused() {
    let mut doc = document();
    doc["scope"] = serde_json::json!("read write admin");
    materialized(&doc).expect_err("a self-identified client cannot widen its own grant");
}

/// A CIMD client is PUBLIC by construction: a secret-bearing auth method names a credential
/// nobody could have pre-shared, so believing it would make the URL's owner confidential by
/// self-declaration.
#[test]
fn a_document_asking_for_a_secret_bearing_auth_method_is_refused() {
    let mut doc = document();
    doc["token_endpoint_auth_method"] = serde_json::json!("client_secret_basic");
    materialized(&doc).expect_err("a metadata-document client cannot hold a secret");
}

/// THE GRANT ESCALATION, same as registration's: `client_credentials` mints a token with no
/// resource owner in the loop, so a document that could ask for it converts "I exist at a URL"
/// into "I am authorised".
#[test]
fn a_document_asking_for_client_credentials_is_refused() {
    let mut doc = document();
    doc["grant_types"] = serde_json::json!(["authorization_code", "client_credentials"]);
    materialized(&doc).expect_err("a self-identified client cannot mint unconsented tokens");
}

/// The consent screen must not be made to lie: the SAME impersonation refusal the registration
/// policy applies holds for a document's `client_name`.
#[test]
fn a_document_impersonating_the_deployment_is_refused() {
    let mut doc = document();
    doc["client_name"] = serde_json::json!("Busbar Gateway");
    materialized(&doc).expect_err("a client naming itself after the deployment is phishing");
}

/// The redirect URIs are the document's or there are none: absent, empty, and fragment-carrying
/// lists are refused, because they are what `oauth-as` exact-matches the request against.
#[test]
fn a_document_without_usable_redirect_uris_is_refused() {
    let mut doc = document();
    doc.as_object_mut().expect("object").remove("redirect_uris");
    materialized(&doc).expect_err("no redirect_uris means nowhere a code may be sent");

    let mut doc = document();
    doc["redirect_uris"] = serde_json::json!([]);
    materialized(&doc).expect_err("an empty redirect_uris list is the same absence");

    let mut doc = document();
    doc["redirect_uris"] = serde_json::json!(["http://127.0.0.1:9999/cb#frag"]);
    materialized(&doc).expect_err("RFC 6749 §3.1.2: a redirection endpoint carries no fragment");
}

/// What is a metadata-document `client_id` at all: HTTPS, parseable, fragment-free. Everything
/// else stays an ordinary opaque identifier and never reaches the fetch.
#[test]
fn only_a_fragment_free_https_url_names_a_document() {
    assert!(is_cimd_client_id(URL));
    assert!(!is_cimd_client_id("flow-test-client"), "an opaque id");
    assert!(
        !is_cimd_client_id("http://client.example/oauth-client"),
        "plaintext cannot bind a document to its owner"
    );
    assert!(!is_cimd_client_id("https://client.example/doc#frag"));
    assert!(!is_cimd_client_id("https://"), "no host");
}

/// A fetch stub that records whether it was consulted at all.
struct Recording {
    called: AtomicBool,
    answer: Result<Vec<u8>, String>,
}

impl Recording {
    fn refusing() -> Arc<Self> {
        Arc::new(Self {
            called: AtomicBool::new(false),
            answer: Err("refused".to_string()),
        })
    }
}

impl CimdFetch for Recording {
    fn fetch<'a>(
        &'a self,
        _url: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, String>> + Send + 'a>>
    {
        self.called.store(true, Ordering::SeqCst);
        let answer = self.answer.clone();
        Box::pin(async move { answer })
    }
}

/// THE PRECEDENCE AND THE GATE, at the store seam: a STORED client is answered without any fetch
/// (whatever its id looks like), an opaque unknown id is `None` without any fetch, and a failed
/// fetch is `None` — the same answer an unknown client gets, never an error an attacker can mint.
#[tokio::test]
async fn the_store_wins_and_every_cimd_failure_reads_as_an_unknown_client() {
    let fetch = Recording::refusing();
    let handle: Arc<Recording> = Arc::clone(&fetch);
    let store = CimdStore::new(MemoryStorage::new(), ceiling(), handle);

    // An opaque id misses without consulting the fetch.
    let missed = store
        .get_client(&ClientId::new("flow-test-client"))
        .await
        .expect("a miss is not an error");
    assert!(missed.is_none());
    assert!(
        !fetch.called.load(Ordering::SeqCst),
        "an opaque id is not a document URL and must never reach the fetch"
    );

    // A stored client whose id IS a URL is answered from the store, not fetched: what the
    // operator or the registration endpoint wrote cannot be overridden by what a URL serves.
    let stored = materialized(&document()).expect("valid");
    store.put_client(stored).await.expect("put");
    let found = store
        .get_client(&ClientId::new(URL))
        .await
        .expect("a hit is not an error")
        .expect("the stored client is found");
    assert_eq!(found.client_id.as_str(), URL);
    assert!(
        !fetch.called.load(Ordering::SeqCst),
        "a stored client answers without a fetch"
    );

    // A URL-shaped id that is NOT stored consults the fetch, and a refused fetch is an unknown
    // client — `Ok(None)`, indistinguishable from any other unknown id.
    let unknown = store
        .get_client(&ClientId::new("https://elsewhere.example/client"))
        .await
        .expect("a refused fetch is not a storage error");
    assert!(unknown.is_none());
    assert!(fetch.called.load(Ordering::SeqCst));
}

// ═════════════════════════════════════════════════════════════════════════════════════════════
// THE PRODUCTION FETCH ITSELF. Everything above drives a STUB fetch, which is right — the
// document checks are the property under test and a real socket would only add flakiness. But it
// means the stub is the only `CimdFetch` any test has ever constructed, and [`GuardedFetch`] —
// the one production actually installs at `plane.rs` — is reached by no test at all. The two
// tests below are the ones that notice if its bounds or its guard call are changed: neither the
// stub-driven tests here nor `net_guard`'s own tests (which judge the guard given a policy, never
// this policy) go red for either edit.
// ═════════════════════════════════════════════════════════════════════════════════════════════

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
