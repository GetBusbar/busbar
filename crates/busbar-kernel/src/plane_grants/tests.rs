// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! W1-K10: entitlements, tickets, host signing, replay claims and the Standard Webhooks verifier (IF §12.11).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use busbar_contract::crypto::{self, LocalSigner, Signer};
use busbar_contract::secret_ref::SecretRef;
use busbar_contract::secure::SecureVec;
use busbar_plugin_abi::host_side::caller::{BoxFut, CallStack, Caller, InstanceLimits};
use busbar_plugin_abi::types::{Bytes, KindCode, Pair, Str};

use super::*;
use crate::ingress::replay::StoreReplay;
use crate::ingress::signed_ingress::{admit, check, Refused, RouteSecrets, StandardWebhooks};
use crate::plugin_records::{PluginRecords, StoreRecords};

const NOW: u64 = 1_800_000_000;

fn clock() -> u64 {
    NOW
}

fn caller<'a>(plugin: &'a str, name: &'a str) -> Caller<'a> {
    Caller {
        plugin,
        kind: KindCode::Plane,
        name,
        instance: 7,
        slot: 0,
        chain: 1,
        deadline: std::time::Instant::now(),
        stack: CallStack::default(),
        out_of_process: false,
        limits: InstanceLimits::default(),
    }
}

async fn records() -> StoreRecords {
    StoreRecords::with_clock(crate::real_store::core().await, clock)
}

async fn tickets() -> SealedTickets<StoreRecords> {
    SealedTickets::new(records().await, &[7u8; 32], clock).expect("a 32-byte key")
}

fn mint<'a>(audience: &'a str, once: bool, record: &'a [u8]) -> TicketMint<'a> {
    TicketMint {
        subject: "alice",
        scope: "read",
        audience,
        ttl_s: 60,
        once,
        prefix: "ek_",
        record,
    }
}

// ---- ENTITLE ----

struct Counting(Arc<AtomicUsize>);
impl GrantResolver for Counting {
    fn grants(&self, _identity: &[u8], sink: &mut dyn FnMut(&str)) {
        self.0.fetch_add(1, Ordering::SeqCst);
        sink("chat");
        sink("embed");
    }
}

#[test]
fn entitle_resolves_once_per_identity_and_checks_by_lookup() {
    let calls = Arc::new(AtomicUsize::new(0));
    let grants = RequestGrants::new(Counting(Arc::clone(&calls)));
    let who = caller("plane-x", "p");
    assert!(grants.check(&who, b"id-1", "chat"));
    assert!(grants.check(&who, b"id-1", "embed"));
    assert!(!grants.check(&who, b"id-1", "admin"));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(grants.check(&who, b"id-2", "chat"));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

// ---- REPLAY ----

#[tokio::test]
async fn replay_claim_is_first_sighting_only_per_namespace() {
    let guard = StoreReplay::new(records().await);
    let a = caller("plane-x", "a");
    let b = caller("plane-x", "b");
    assert_eq!(guard.claim(&a, b"k", 0).await, Ok(true));
    assert_eq!(guard.claim(&a, b"k", 10).await, Ok(false));
    assert_eq!(guard.claim(&b, b"k", 10).await, Ok(true));
}

#[tokio::test]
async fn replay_namespace_is_not_the_plugins_own_records() {
    let store = crate::real_store::core().await;
    let records = StoreRecords::with_clock(Arc::clone(&store), clock);
    let who = caller("plane-x", "a");
    let own = crate::plugin_records::Scope::default();
    let guard = StoreReplay::new(StoreRecords::with_clock(store, clock));
    assert_eq!(guard.claim(&who, b"k", 10).await, Ok(true));
    let mut seen = false;
    let found = records.get(&who, own, b"k", &mut |_| seen = true).await;
    assert_eq!(found, Ok(false));
    assert!(!seen);
}

// ---- TICKETS ----

#[tokio::test]
async fn tickets_are_classified_by_marker_without_opening() {
    let t = tickets().await;
    let who = caller("plane-x", "p");
    let (cred, expires) = t.mint(&who, mint("aud", false, b"")).await.unwrap();
    assert_eq!(expires, NOW + 60);
    assert!(cred.starts_with("ek_bbt1."));
    assert!(t.is_ticket(&cred));
    assert!(t.is_ticket("bbt1.x"));
    assert!(!t.is_ticket("sk-live-123"));
    assert!(!t.is_ticket("a-prefix-that-is-far-too-long-bbt1.x"));
    assert!(!t.is_ticket("bad prefix!bbt1.x"));
}

#[tokio::test]
async fn mint_refuses_bad_prefix_zero_ttl_and_oversize_record() {
    let t = tickets().await;
    let who = caller("plane-x", "p");
    let mut m = mint("aud", false, b"");
    m.prefix = "bad prefix";
    assert_eq!(t.mint(&who, m).await.unwrap_err(), RecordsDenied::Invalid);
    let mut m = mint("aud", false, b"");
    m.ttl_s = 0;
    assert_eq!(t.mint(&who, m).await.unwrap_err(), RecordsDenied::Invalid);
    let big = vec![0u8; 65_537];
    assert_eq!(
        t.mint(&who, mint("aud", false, &big)).await.unwrap_err(),
        RecordsDenied::TooLarge
    );
}

#[tokio::test]
async fn admit_checks_plugin_name_audience_expiry_and_seal() {
    let t = tickets().await;
    let who = caller("plane-x", "p");
    let (cred, _) = t.mint(&who, mint("aud", false, b"")).await.unwrap();
    assert!(t.admit(&who, "aud", &cred, NOW + 1).await.is_ok());
    // Stateless ticket: admitted again.
    assert!(t.admit(&who, "aud", &cred, NOW + 2).await.is_ok());
    let denied = |r: Result<TicketAdmitted, TicketDenied>| r.err();
    assert_eq!(
        denied(t.admit(&who, "other", &cred, NOW + 1).await),
        Some(TicketDenied::Invalid)
    );
    assert_eq!(
        denied(
            t.admit(&caller("plane-x", "q"), "aud", &cred, NOW + 1)
                .await
        ),
        Some(TicketDenied::Invalid)
    );
    assert_eq!(
        denied(
            t.admit(&caller("plane-y", "p"), "aud", &cred, NOW + 1)
                .await
        ),
        Some(TicketDenied::Invalid)
    );
    assert_eq!(
        denied(t.admit(&who, "aud", &cred, NOW + 60).await),
        Some(TicketDenied::Expired)
    );
    let mut tampered = cred.to_string();
    let last = tampered.pop().unwrap();
    tampered.push(if last == 'A' { 'B' } else { 'A' });
    assert_eq!(
        denied(t.admit(&who, "aud", &tampered, NOW + 1).await),
        Some(TicketDenied::Invalid)
    );
    assert_eq!(
        denied(t.admit(&who, "aud", "bbt1.not-a-seal", NOW + 1).await),
        Some(TicketDenied::Invalid)
    );
}

#[tokio::test]
async fn a_ticket_under_another_host_key_does_not_open() {
    let a = tickets().await;
    let b = SealedTickets::new(records().await, &[8u8; 32], clock).unwrap();
    let who = caller("plane-x", "p");
    let (cred, _) = a.mint(&who, mint("aud", false, b"")).await.unwrap();
    assert_eq!(
        b.admit(&who, "aud", &cred, NOW + 1).await.err(),
        Some(TicketDenied::Invalid)
    );
}

/// DES-331 §B4: the seal keys bind the restore epoch. A ticket sealed before a declared restore does not open
/// after it, a ticket sealed after it opens at once, and epoch 0 is the original derivation.
#[tokio::test]
async fn a_ticket_sealed_before_a_declared_restore_does_not_open_after_it() {
    let before = SealedTickets::at_restore_epoch(records().await, &[7u8; 32], clock, 0).unwrap();
    let after = SealedTickets::at_restore_epoch(records().await, &[7u8; 32], clock, 1).unwrap();
    let who = caller("plane-x", "p");
    let (old, _) = before.mint(&who, mint("aud", false, b"")).await.unwrap();
    assert!(tickets()
        .await
        .admit(&who, "aud", &old, NOW + 1)
        .await
        .is_ok());
    assert_eq!(
        after.admit(&who, "aud", &old, NOW + 1).await.err(),
        Some(TicketDenied::Invalid)
    );
    let (fresh, _) = after.mint(&who, mint("aud", false, b"")).await.unwrap();
    assert!(after.admit(&who, "aud", &fresh, NOW + 1).await.is_ok());
    assert_eq!(
        before.admit(&who, "aud", &fresh, NOW + 1).await.err(),
        Some(TicketDenied::Invalid)
    );
}

#[tokio::test]
async fn a_once_ticket_admits_exactly_one_request() {
    let t = tickets().await;
    let who = caller("plane-x", "p");
    let (cred, _) = t.mint(&who, mint("aud", true, b"")).await.unwrap();
    assert!(t.admit(&who, "aud", &cred, NOW + 1).await.is_ok());
    assert_eq!(
        t.admit(&who, "aud", &cred, NOW + 2).await.err(),
        Some(TicketDenied::Replayed)
    );
}

#[tokio::test]
async fn a_ticket_record_is_read_not_taken_unless_once() {
    let t = tickets().await;
    let who = caller("plane-x", "p");
    let (cred, _) = t.mint(&who, mint("aud", false, b"payload")).await.unwrap();
    for _ in 0..2 {
        let got = t.admit(&who, "aud", &cred, NOW + 1).await.unwrap();
        assert_eq!(
            got.record.as_ref().map(SecureVec::as_slice),
            Some(&b"payload"[..])
        );
    }
    let (once, _) = t.mint(&who, mint("aud", true, b"secret")).await.unwrap();
    let got = t.admit(&who, "aud", &once, NOW + 1).await.unwrap();
    assert_eq!(
        got.record.as_ref().map(SecureVec::as_slice),
        Some(&b"secret"[..])
    );
    assert_eq!(
        t.admit(&who, "aud", &once, NOW + 1).await.err(),
        Some(TicketDenied::Replayed)
    );
}

// ---- SIGN ----

#[tokio::test]
async fn host_signer_makes_compact_and_detached_jws() {
    let local = LocalSigner::from_seed(&[3u8; 32]).unwrap();
    let kid = local.public_key().key_id.to_string();
    let signer = CoreJwsSigner::new(Arc::new(local));
    let who = caller("plane-x", "p");
    let SignedJws::Compact(compact) = signer.sign_jws(&who, b"{\"a\":1}", false).await.unwrap()
    else {
        panic!("compact asked");
    };
    let parts: Vec<&str> = compact.split('.').collect();
    assert_eq!(parts.len(), 3);
    let header = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
    assert_eq!(
        String::from_utf8(header).unwrap(),
        format!(r#"{{"alg":"EdDSA","kid":"{kid}"}}"#)
    );
    assert_eq!(URL_SAFE_NO_PAD.decode(parts[1]).unwrap(), b"{\"a\":1}");
    assert_eq!(URL_SAFE_NO_PAD.decode(parts[2]).unwrap().len(), 64);
    let SignedJws::Detached {
        protected,
        signature,
    } = signer.sign_jws(&who, b"{\"a\":1}", true).await.unwrap()
    else {
        panic!("detached asked");
    };
    assert_eq!(&*protected, parts[0]);
    // Ed25519 is deterministic: the detached signature is the compact one.
    assert_eq!(&*signature, parts[2]);
}

// ---- SIGNED INGRESS ----

struct Fixed(Vec<u8>);
impl RouteSecrets for Fixed {
    fn resolve<'a>(&'a self, _reference: &'a SecretRef) -> BoxFut<'a, Option<SecureVec>> {
        Box::pin(async move { Some(SecureVec::from(self.0.as_slice())) })
    }
}

struct Unresolved;
impl RouteSecrets for Unresolved {
    fn resolve<'a>(&'a self, _reference: &'a SecretRef) -> BoxFut<'a, Option<SecureVec>> {
        Box::pin(async { None })
    }
}

const KEY: &[u8] = b"route-secret";

fn sign(key: &[u8], id: &str, ts: &str, body: &[u8]) -> String {
    let mut msg = format!("{id}.{ts}.").into_bytes();
    msg.extend_from_slice(body);
    format!(
        "v1,{}",
        STANDARD.encode(crypto::hmac_sha256(key, &msg).unwrap())
    )
}

fn pairs<'a>(id: &'a str, ts: &'a str, sig: &'a str) -> [Pair<'a>; 3] {
    [
        Pair {
            name: Str::new("Webhook-Id"),
            value: Bytes::new(id.as_bytes()),
        },
        Pair {
            name: Str::new("webhook-timestamp"),
            value: Bytes::new(ts.as_bytes()),
        },
        Pair {
            name: Str::new("webhook-signature"),
            value: Bytes::new(sig.as_bytes()),
        },
    ]
}

#[test]
fn standard_webhooks_accepts_a_good_signature_and_refuses_the_rest() {
    let ts = NOW.to_string();
    let body = b"{\"event\":1}";
    let good = sign(KEY, "msg_1", &ts, body);
    assert!(check(KEY, &pairs("msg_1", &ts, &good), body, NOW).is_some());
    // Any one of several space-separated signatures may match.
    let many = format!("v1,AAAA {good} v2,xx");
    assert!(check(KEY, &pairs("msg_1", &ts, &many), body, NOW).is_some());
    // Wrong body, id, key, version.
    assert!(check(KEY, &pairs("msg_1", &ts, &good), b"other", NOW).is_none());
    assert!(check(KEY, &pairs("msg_2", &ts, &good), body, NOW).is_none());
    assert!(check(b"other-key", &pairs("msg_1", &ts, &good), body, NOW).is_none());
    let v2 = good.replacen("v1,", "v2,", 1);
    assert!(check(KEY, &pairs("msg_1", &ts, &v2), body, NOW).is_none());
    // Tolerance: 300 s either side, not beyond.
    assert!(check(KEY, &pairs("msg_1", &ts, &good), body, NOW + 300).is_some());
    assert!(check(KEY, &pairs("msg_1", &ts, &good), body, NOW + 301).is_none());
    assert!(check(KEY, &pairs("msg_1", &ts, &good), body, NOW - 300).is_some());
    assert!(check(KEY, &pairs("msg_1", &ts, &good), body, NOW - 301).is_none());
    // A missing header.
    assert!(check(KEY, &pairs("msg_1", &ts, &good)[..2], body, NOW).is_none());
}

/// The signature is compared whole: a prefix of the right tag, the right tag with a byte added, and
/// an empty tag verify nothing, alone or beside each other; the right tag still verifies after them.
#[test]
fn standard_webhooks_refuses_a_tag_of_another_length() {
    let ts = NOW.to_string();
    let body = b"{\"event\":1}";
    let mut msg = format!("msg_1.{ts}.").into_bytes();
    msg.extend_from_slice(body);
    let tag = crypto::hmac_sha256(KEY, &msg).unwrap();
    let short = format!("v1,{}", STANDARD.encode(&tag[..16]));
    let mut longer = tag.to_vec();
    longer.push(0);
    let long = format!("v1,{}", STANDARD.encode(&longer));
    for refused in [short.as_str(), long.as_str(), "v1,"] {
        assert!(check(KEY, &pairs("msg_1", &ts, refused), body, NOW).is_none());
    }
    let none = format!("{short} {long} v1,");
    assert!(check(KEY, &pairs("msg_1", &ts, &none), body, NOW).is_none());
    let last = format!("{short} {long} v1,{}", STANDARD.encode(tag));
    assert!(check(KEY, &pairs("msg_1", &ts, &last), body, NOW).is_some());
}

#[test]
fn standard_webhooks_whsec_keys_are_base64() {
    let raw = b"0123456789abcdef";
    let secret = format!("whsec_{}", STANDARD.encode(raw));
    let ts = NOW.to_string();
    let sig = sign(raw, "m", &ts, b"b");
    assert!(check(secret.as_bytes(), &pairs("m", &ts, &sig), b"b", NOW).is_some());
}

#[tokio::test]
async fn signed_ingress_is_admitted_once_and_fails_closed() {
    let verifier = StandardWebhooks::new(Fixed(KEY.to_vec()));
    let guard = StoreReplay::new(records().await);
    let who = caller("plane-x", "p");
    let reference = SecretRef::None;
    let ts = NOW.to_string();
    let body = b"payload";
    let sig = sign(KEY, "msg_9", &ts, body);
    let headers = pairs("msg_9", &ts, &sig);
    assert_eq!(
        admit(&verifier, &guard, &who, &reference, &headers, body, NOW).await,
        Ok(())
    );
    assert_eq!(
        admit(&verifier, &guard, &who, &reference, &headers, body, NOW).await,
        Err(Refused::Replayed)
    );
    let bad = pairs("msg_9", &ts, "v1,AAAA");
    assert_eq!(
        admit(&verifier, &guard, &who, &reference, &bad, body, NOW).await,
        Err(Refused::BadCredential)
    );
    let closed = StandardWebhooks::new(Unresolved);
    assert_eq!(
        admit(&closed, &guard, &who, &reference, &headers, body, NOW).await,
        Err(Refused::BadCredential)
    );
}
