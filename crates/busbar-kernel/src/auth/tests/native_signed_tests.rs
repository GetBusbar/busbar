// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The native signed-ingress verifier: what is read before a signature is judged, what a
//! signature admits, and what a sender is told when it admits nothing. The signature itself is
//! core's Standard Webhooks check (`ingress::signed_ingress::check`: HMAC-SHA256 over
//! `id.timestamp.body` in its parts, constant-time, five minutes either way), so a wrong
//! signature, a stale timestamp and a changed body are refused by real arithmetic.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use busbar_contract::crypto;
use busbar_plugin_abi::fail::refused::{R_AUTH_REQUIRED, R_BAD_CREDENTIAL};
use busbar_plugin_abi::types::{Bytes, Pair, Str};

use super::*;
use crate::auth::admission_table::{decide, Authority, Decision, Refusal, Step, Target};
use crate::auth::reference_plane;
use crate::ingress::signed_ingress::{check, TOLERANCE_S};

const NOW: u64 = 1_800_000_000;
const SECRET: &[u8] = b"a-signing-secret-of-thirty-two-b";
const BOUND: u64 = 4096;
const BODY: &[u8] = br#"{"type":"response.completed","data":{"id":"resp_1"}}"#;

/// One received webhook.
struct Webhook {
    headers: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
    now_s: u64,
}

impl Received for Webhook {
    fn raw_body(&self) -> &[u8] {
        &self.body
    }
}

fn signature(id: &str, timestamp: u64, body: &[u8]) -> String {
    let timestamp = timestamp.to_string();
    let mac = crypto::HmacSha256Key::new(SECRET)
        .expect("a usable key")
        .sign_parts(&[id.as_bytes(), b".", timestamp.as_bytes(), b".", body]);
    format!("v1,{}", STANDARD.encode(mac))
}

/// A webhook its sender signed at `timestamp`, received at `NOW`.
fn webhook(id: &str, timestamp: u64, body: &[u8]) -> Webhook {
    Webhook {
        headers: vec![
            ("webhook-id".into(), id.as_bytes().to_vec()),
            (
                "webhook-timestamp".into(),
                timestamp.to_string().into_bytes(),
            ),
            (
                "webhook-signature".into(),
                signature(id, timestamp, body).into_bytes(),
            ),
            ("content-type".into(), b"application/json".to_vec()),
        ],
        body: body.to_vec(),
        now_s: NOW,
    }
}

/// The test's verifier: core's Standard Webhooks check, and a replay book in memory.
struct Sender {
    seen: Mutex<HashSet<String>>,
    calls: AtomicUsize,
    down: AtomicBool,
    replay_down: AtomicBool,
    /// A verifier that accepts a signature and states no replay claim for it.
    unbound: bool,
}

impl Sender {
    fn new() -> Self {
        Self {
            seen: Mutex::new(HashSet::new()),
            calls: AtomicUsize::new(0),
            down: AtomicBool::new(false),
            replay_down: AtomicBool::new(false),
            unbound: false,
        }
    }
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

struct Sighting<'a> {
    sender: &'a Sender,
    key: String,
}

impl Signed for Sighting<'_> {
    fn subject(&self) -> &str {
        "webhook-signature:standard-webhooks"
    }
    fn replay_bound(&self) -> bool {
        !self.sender.unbound
    }
    fn claim(&self) -> BoxFut<'_, Claim> {
        Box::pin(async move {
            if self.sender.replay_down.load(Ordering::SeqCst) {
                return Claim::Unknown;
            }
            if self.sender.seen.lock().unwrap().insert(self.key.clone()) {
                Claim::Won
            } else {
                Claim::Replay
            }
        })
    }
}

impl SignatureVerifier<Webhook> for Sender {
    fn verify<'a>(&'a self, request: &'a Webhook) -> BoxFut<'a, Result<Judged<'a>, VerifierDown>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.down.load(Ordering::SeqCst) {
                return Err(VerifierDown);
            }
            let pairs: Vec<Pair<'_>> = request
                .headers
                .iter()
                .map(|(name, value)| Pair {
                    name: Str::new(name),
                    value: Bytes::new(value),
                })
                .collect();
            if !request
                .headers
                .iter()
                .any(|(name, _)| name == "webhook-signature")
            {
                return Ok(Judged::NotSigned);
            }
            let Some(verified) = check(SECRET, &pairs, request.raw_body(), request.now_s) else {
                return Ok(Judged::Rejected);
            };
            let key = format!("standard-webhooks/{}/{}", verified.timestamp, verified.id);
            Ok(Judged::Verified(Box::new(Sighting { sender: self, key })))
        })
    }
}

fn ingress() -> NativeSignedIngress<Sender> {
    NativeSignedIngress::new(Sender::new(), BOUND)
}

fn signed_route() -> crate::auth::route_record::RouteRecord {
    reference_plane::route_of(Admission::SignedIngress)
        .expect("the reference plane has a signed route")
        .record
}

/// The one answer to a sender that is not verified, as the table gives it.
fn the_one_401(refused: SignedRefused) {
    let record = signed_route();
    let Decision::Refuse { refusal, verified } = decide(Target::Route(&record), &refused.facts())
    else {
        panic!("{refused:?} is refused by the table")
    };
    assert!(
        matches!(refusal, Refusal::Unverified { .. }),
        "{refused:?}: {refusal:?}"
    );
    assert!(
        !verified,
        "the sender was not verified: core writes the answer"
    );
    // The bytes of the answer are one row's, whatever was wrong: only the recorded code says
    // whether a signature was presented at all.
    let row = refusal.row(false);
    let one = Refusal::Unverified { presented: false }.row(false);
    assert_eq!(
        (
            row.status,
            row.text,
            row.challenge,
            row.by,
            row.retry_after_s
        ),
        (401, one.text, one.challenge, one.by, one.retry_after_s)
    );
    assert_eq!(
        row.code,
        if refused == SignedRefused::NotSigned {
            R_AUTH_REQUIRED
        } else {
            R_BAD_CREDENTIAL
        }
    );
}

async fn refused(ingress: &NativeSignedIngress<Sender>, webhook: &Webhook) -> SignedRefused {
    ingress
        .admit(webhook)
        .await
        .expect_err("the request is refused")
}

#[tokio::test]
async fn a_valid_webhook_is_admitted_and_its_body_is_parsed_only_after_verification() {
    let ingress = ingress();
    let received = webhook("msg_1", NOW - 5, BODY);
    let parsed = AtomicUsize::new(0);
    let parse = |body: &[u8]| -> serde_json::Value {
        parsed.fetch_add(1, Ordering::SeqCst);
        serde_json::from_slice(body).expect("the sender's JSON")
    };

    let verified = ingress.admit(&received).await.expect("a signed webhook");
    assert_eq!(
        parsed.load(Ordering::SeqCst),
        0,
        "nothing parsed the body while it was being verified"
    );
    assert!(
        std::ptr::eq(verified.body(), received.raw_body()),
        "the body handed on is the bytes that were verified, where they lie"
    );
    assert_eq!(parse(verified.body())["type"], "response.completed");
    assert_eq!(parsed.load(Ordering::SeqCst), 1);
    assert_eq!(verified.subject(), "webhook-signature:standard-webhooks");

    let record = signed_route();
    assert_eq!(
        decide(Target::Route(&record), &verified.facts()),
        Decision::Serve(Authority::Unbilled),
        "a verified sender is served with no key and no unit"
    );
    assert!(!format!("{verified:?}").contains("response.completed"));
}

#[tokio::test]
async fn a_wrong_signature_is_the_one_401() {
    let ingress = ingress();
    let mut received = webhook("msg_1", NOW, BODY);
    received.headers[2].1 = signature("msg_1", NOW, b"another body").into_bytes();
    let why = refused(&ingress, &received).await;
    assert_eq!(why, SignedRefused::BadSignature);
    the_one_401(why);

    // Signed with another key.
    let other = crypto::HmacSha256Key::new(b"some-other-secret-of-the-sender!")
        .expect("a usable key")
        .sign_parts(&[
            b"msg_1".as_slice(),
            b".",
            NOW.to_string().as_bytes(),
            b".",
            BODY,
        ]);
    received.headers[2].1 = format!("v1,{}", STANDARD.encode(other)).into_bytes();
    assert_eq!(
        refused(&ingress, &received).await,
        SignedRefused::BadSignature
    );

    // No signature at all.
    received.headers.remove(2);
    let why = refused(&ingress, &received).await;
    assert_eq!(why, SignedRefused::NotSigned);
    the_one_401(why);
}

#[tokio::test]
async fn a_stale_timestamp_is_the_one_401() {
    let ingress = ingress();
    for timestamp in [NOW - TOLERANCE_S - 1, NOW + TOLERANCE_S + 1] {
        // Correctly signed by the sender, at a time outside the tolerance.
        let why = refused(&ingress, &webhook("msg_1", timestamp, BODY)).await;
        assert_eq!(why, SignedRefused::BadSignature, "{timestamp}");
        the_one_401(why);
    }
    for timestamp in [NOW - TOLERANCE_S, NOW + TOLERANCE_S] {
        assert!(
            ingress
                .admit(&webhook(&format!("msg_{timestamp}"), timestamp, BODY))
                .await
                .is_ok(),
            "the edge of the tolerance is inside it"
        );
    }
}

#[tokio::test]
async fn a_replay_is_the_one_401() {
    let ingress = ingress();
    let received = webhook("msg_1", NOW, BODY);
    assert!(ingress.admit(&received).await.is_ok());
    let why = refused(&ingress, &received).await;
    assert_eq!(why, SignedRefused::Replayed);
    the_one_401(why);
    // Another message of the same second is not a replay.
    assert!(ingress.admit(&webhook("msg_2", NOW, BODY)).await.is_ok());
}

#[tokio::test]
async fn a_modified_body_is_the_one_401_and_is_never_handed_on() {
    let ingress = ingress();
    let mut received = webhook("msg_1", NOW, BODY);
    // One byte changed after the sender signed.
    let at = received.body.len() - 3;
    received.body[at] ^= 1;
    let why = refused(&ingress, &received).await;
    assert_eq!(why, SignedRefused::BadSignature);
    the_one_401(why);
    // The refused request claimed nothing: the sender's true message is still admitted.
    assert!(ingress.admit(&webhook("msg_1", NOW, BODY)).await.is_ok());
}

#[tokio::test]
async fn a_body_over_the_bound_is_refused_before_any_verifier_runs() {
    let ingress = ingress();
    let big = vec![b'a'; usize::try_from(BOUND).unwrap() + 1];
    let why = refused(&ingress, &webhook("msg_1", NOW, &big)).await;
    assert_eq!(why, SignedRefused::TooLarge);
    assert_eq!(
        ingress.verifier.calls(),
        0,
        "no verifier is handed more than its signature covers"
    );
    let record = signed_route();
    assert_eq!(
        decide(Target::Route(&record), &why.facts()),
        Decision::Refuse {
            refusal: Refusal::BodyTooLarge,
            verified: false
        }
    );
    // Exactly the bound is read and judged.
    let full = vec![b'a'; usize::try_from(BOUND).unwrap()];
    assert!(ingress.admit(&webhook("msg_2", NOW, &full)).await.is_ok());
}

#[tokio::test]
async fn a_verifier_or_replay_store_that_cannot_answer_is_503_never_401() {
    let record = signed_route();
    let unavailable = |why: SignedRefused| {
        assert_eq!(why, SignedRefused::Unavailable);
        let Decision::Refuse { refusal, .. } = decide(Target::Route(&record), &why.facts()) else {
            panic!("a verifier that cannot answer is refused by the table")
        };
        assert_eq!(refusal, Refusal::VerifierUnavailable);
        assert_eq!(refusal.row(false).status, 503);
    };

    let ingress = ingress();
    ingress.verifier.down.store(true, Ordering::SeqCst);
    unavailable(refused(&ingress, &webhook("msg_1", NOW, BODY)).await);

    ingress.verifier.down.store(false, Ordering::SeqCst);
    ingress.verifier.replay_down.store(true, Ordering::SeqCst);
    unavailable(refused(&ingress, &webhook("msg_1", NOW, BODY)).await);

    // Nothing was claimed while the store was down: the message is admitted once it is back.
    ingress.verifier.replay_down.store(false, Ordering::SeqCst);
    assert!(ingress.admit(&webhook("msg_1", NOW, BODY)).await.is_ok());
}

#[tokio::test]
async fn a_signature_bound_to_no_replay_claim_is_refused() {
    let mut sender = Sender::new();
    sender.unbound = true;
    let ingress = NativeSignedIngress::new(sender, BOUND);
    let why = refused(&ingress, &webhook("msg_1", NOW, BODY)).await;
    assert_eq!(why, SignedRefused::NoReplayBound);
    the_one_401(why);
}

#[test]
fn every_denial_is_the_same_fact_and_says_why_only_to_the_log() {
    let denials = [
        SignedRefused::NotSigned,
        SignedRefused::BadSignature,
        SignedRefused::NoReplayBound,
        SignedRefused::Replayed,
    ];
    for refused in denials {
        let facts = refused.facts();
        assert_eq!(
            facts.verified,
            Some(Verified::Denied),
            "{}",
            refused.reason()
        );
        assert_eq!(facts.body, Some(BodyRead::Taken));
        the_one_401(refused);
    }
    assert_eq!(
        SignedRefused::Unavailable.facts().verified,
        Some(Verified::Unavailable)
    );
    assert_eq!(SignedRefused::TooLarge.facts().verified, None);
}

#[test]
fn the_table_asks_for_the_bounded_body_before_the_signature() {
    let record = signed_route();
    let arrived = Facts::arrived(false, false);
    assert_eq!(
        decide(Target::Route(&record), &arrived),
        Decision::Run(Step::Body)
    );
    let mut taken = arrived;
    taken.body = Some(BodyRead::Taken);
    assert_eq!(
        decide(Target::Route(&record), &taken),
        Decision::Run(Step::Verify)
    );
}

#[test]
fn a_signed_route_is_verified_only_by_instances_that_cover_and_bound_the_body() {
    let covers = FB_NEEDS_BODY;
    assert_eq!(coverage([], 1 << 20), Err(NotCovered::NoVerifier));
    assert_eq!(
        coverage([(0, Some(4096))], 1 << 20),
        Err(NotCovered::HeadOnly)
    );
    assert_eq!(
        coverage([(covers, None)], 1 << 20),
        Err(NotCovered::Unbounded)
    );
    assert_eq!(
        coverage([(covers, Some(0))], 1 << 20),
        Err(NotCovered::Empty)
    );
    assert_eq!(
        coverage([(covers, Some(4096)), (0, Some(4096))], 1 << 20),
        Err(NotCovered::HeadOnly),
        "one head-only instance among them and the route is not verified"
    );
    assert_eq!(
        coverage([(covers, Some(65_536)), (covers, Some(4096))], 1 << 20),
        Ok(4096),
        "the least bound of the instances"
    );
    assert_eq!(
        coverage([(covers, Some(1 << 30))], 1 << 20),
        Ok(1 << 20),
        "never over the listener's own cap"
    );
    for refused in [
        NotCovered::NoVerifier,
        NotCovered::HeadOnly,
        NotCovered::Unbounded,
        NotCovered::Empty,
    ] {
        assert!(!refused.reason().is_empty());
    }
}

#[test]
fn the_table_selects_this_verifier_for_a_signed_route_only() {
    use crate::auth::admission_table::plan;
    use crate::auth::route_record::Money;
    for admission in [
        Admission::Walk,
        Admission::Selected,
        Admission::PrincipalOnly,
        Admission::Catalog,
        Admission::Public,
        Admission::Optional,
        Admission::Ticket,
        Admission::SignedIngress,
        Admission::Upgrade,
        Admission::Operator,
    ] {
        let sequence = plan(admission, Money::None).expect("a listener admission has a sequence");
        assert_eq!(
            selected_by(sequence.verify),
            NativeSignedIngress::<Sender>::serves(admission),
            "{admission:?}"
        );
    }
}
