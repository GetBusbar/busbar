// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The replay claim every inbound verify meets, and the public-route verify under a scheme.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use busbar_contract::abi::auth::AuthPoint;
use busbar_contract::auth_calls::{
    AuthCalls, Decision, Replay, Verified, VerifiedIdentity, VerifyAnswer, VerifyRequest, Verifying,
};

use super::{claim_replay, verify_inbound, InboundVerdict};
use crate::auth::{AuthMiddleware, ChainVerdict};
use crate::governance::MemoryStore;

/// A verifier that answers every request with `verdict`.
struct Fixed {
    verdict: Verified,
}

/// An answer that has arrived.
struct Arrived(Option<VerifyAnswer>);

impl Future for Arrived {
    type Output = VerifyAnswer;
    fn poll(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<VerifyAnswer> {
        Poll::Ready(self.0.take().unwrap_or_else(|| Verified::Failed.into()))
    }
}

impl Verifying for Arrived {
    fn settled(&mut self) -> Option<VerifyAnswer> {
        self.0.take()
    }
}

impl AuthCalls for Fixed {
    fn name(&self) -> &str {
        "busbar-auth-webhook-signature"
    }
    fn facts(&self) -> u32 {
        0
    }
    fn verify_now(&self, _: &VerifyRequest) -> Option<VerifyAnswer> {
        Some(VerifyAnswer {
            verified: self.verdict.clone(),
            decision: Decision::Continue,
            strips: Vec::new(),
        })
    }
    fn verify(&self, request: VerifyRequest) -> Box<dyn Verifying> {
        Box::new(Arrived(self.verify_now(&request)))
    }
    fn refresh(&self) -> Result<u64, String> {
        Ok(0)
    }
}

/// An identity carrying the replay key `key`.
fn signed(key: &str) -> Verified {
    Verified::Identity(VerifiedIdentity {
        subject: "webhook-signature:standard-webhooks".to_string(),
        replay: Some(Box::new(Replay {
            key: key.to_string(),
            ttl_secs: 300,
        })),
        ..VerifiedIdentity::default()
    })
}

fn request() -> VerifyRequest {
    VerifyRequest {
        point: AuthPoint::HeadBody,
        conn: 0,
        unit: 0,
        credential: None,
        lines: Vec::new(),
        peer: None,
        body: Some(b"{}".to_vec()),
        method: "POST".to_string(),
        authority: "busbar.example".to_string(),
        path: "/webhooks/sender".to_string(),
        query: None,
        timestamp: 1_700_000_000,
    }
}

fn instance(verdict: Verified) -> Vec<Arc<dyn AuthCalls>> {
    vec![Arc::new(Fixed { verdict })]
}

/// THE REPLAY CLAIM: a key is admitted once within its window, per verifying plugin; an empty key
/// claims nothing.
#[test]
fn a_replay_key_is_claimed_once_per_plugin() {
    let store = MemoryStore::new();
    let replay = Replay {
        key: "msg_1".to_string(),
        ttl_secs: 300,
    };
    let now = 1_700_000_000;
    assert!(
        claim_replay_for_test(&store, "a", &replay, now),
        "first sighting"
    );
    assert!(
        !claim_replay_for_test(&store, "a", &replay, now),
        "a replay"
    );
    assert!(
        claim_replay_for_test(&store, "b", &replay, now),
        "another plugin's key"
    );
    let empty = Replay {
        key: String::new(),
        ttl_secs: 300,
    };
    assert!(claim_replay_for_test(&store, "a", &empty, now));
    assert!(
        claim_replay_for_test(&store, "a", &empty, now),
        "an empty key claims nothing"
    );
}

fn claim_replay_for_test(store: &MemoryStore, plugin: &str, replay: &Replay, now: u64) -> bool {
    claim_replay(store, plugin, replay, now)
}

/// THE PUBLIC-ROUTE VERIFY: a signed request is identified once; the same message again is refused
/// (RED without the claim: identified twice); a pass from every instance, a reject, and a
/// replay-keyed identity with no store to claim in are refused; an overloaded verifier is its own
/// answer.
#[tokio::test]
async fn the_public_route_verify_admits_a_signed_message_once() {
    let store = MemoryStore::new();
    let now = 1_700_000_000;
    let signed_once = instance(signed("msg_1"));
    assert!(matches!(
        verify_inbound(&signed_once, &request(), Some(&store), now).await,
        InboundVerdict::Identified { .. }
    ));
    assert!(matches!(
        verify_inbound(&signed_once, &request(), Some(&store), now).await,
        InboundVerdict::Denied
    ));
    assert!(matches!(
        verify_inbound(&instance(Verified::Pass), &request(), Some(&store), now).await,
        InboundVerdict::Denied
    ));
    assert!(matches!(
        verify_inbound(&instance(Verified::Reject), &request(), Some(&store), now).await,
        InboundVerdict::Denied
    ));
    assert!(matches!(
        verify_inbound(&instance(signed("msg_2")), &request(), None, now).await,
        InboundVerdict::Denied
    ));
    assert!(matches!(
        verify_inbound(&[], &request(), Some(&store), now).await,
        InboundVerdict::Denied
    ));
    assert!(matches!(
        verify_inbound(
            &instance(Verified::Overloaded),
            &request(),
            Some(&store),
            now
        )
        .await,
        InboundVerdict::Overloaded
    ));
}

/// THE DATA-PLANE CHAIN MEETS THE SAME CLAIM: a chain position whose identity carries a replay key
/// admits it once and denies the same key again (RED without the claim: identified twice).
#[test]
fn the_data_chain_denies_a_replayed_identity() {
    let gov = crate::governance::GovState::new(Arc::new(MemoryStore::new()), None).unwrap();
    let auth = AuthMiddleware::from_doors_for_test(vec![(
        "hooks".to_string(),
        Arc::new(Fixed {
            verdict: signed("msg_9"),
        }) as Arc<dyn AuthCalls>,
    )]);
    let now = 1_700_000_000;
    assert!(matches!(
        auth.run_chain_cached(Some("ignored"), None, Some(&gov), now, None),
        ChainVerdict::Identified { .. }
    ));
    assert!(matches!(
        auth.run_chain_cached(Some("ignored"), None, Some(&gov), now, None),
        ChainVerdict::Denied
    ));
}
