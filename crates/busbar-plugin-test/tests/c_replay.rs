// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-REPLAY (ABI-MIN3-INTERFACE §14): A byte-identical replay of a REPLAY-answered request is refused R_REPLAYED
//! and never served from the verdict cache.
//!
//! W1-K10's arms: the replay claim (`ReplayGuard`, one atomic put-if-absent in core's namespace) admits the first
//! sighting only, on every replica: a byte-identical replay on a second replica loses, as does a byte-identical
//! Standard Webhooks delivery on signed ingress. The verdict-cache half needs an auth image answering REPLAY
//! through the adapter (busbar-plugin-test carries no auth fixture image yet).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

use std::sync::Arc;

use busbar_contract::crypto;
use busbar_contract::secret_ref::SecretRef;
use busbar_contract::secure::SecureVec;
use busbar_kernel::ingress::replay::StoreReplay;
use busbar_kernel::ingress::signed_ingress::{admit, Refused, RouteSecrets, StandardWebhooks};
use busbar_kernel::plane_grants::ReplayGuard as _;
use busbar_kernel::plugin_records::StoreRecords;
use busbar_plugin_abi::host_side::caller::{BoxFut, Caller};
use busbar_plugin_abi::types::{Bytes, Pair, Str};

use crate::k10_rig::{b64, plane, runtime, store};

#[test]
fn a_replay_claim_is_won_once_on_every_replica() {
    let rt = runtime();
    let shared = rt.block_on(store());
    let first = StoreReplay::new(StoreRecords::new(Arc::clone(&shared)));
    let second = StoreReplay::new(StoreRecords::new(Arc::clone(&shared)));
    let who = plane();
    let key = b"sigv4/AKIDEXAMPLE/20261116T000000Z/9f2c";
    assert_eq!(rt.block_on(first.claim(&who, key, 300)), Ok(true));
    assert_eq!(
        rt.block_on(second.claim(&who, key, 300)),
        Ok(false),
        "a byte-identical replay on another replica is refused"
    );
    assert_eq!(rt.block_on(first.claim(&who, key, 300)), Ok(false));
    assert_eq!(
        rt.block_on(second.claim(&who, b"sigv4/AKIDEXAMPLE/20261116T000000Z/9f2d", 300)),
        Ok(true),
        "another request is a first sighting"
    );
    let other = Caller {
        name: "other",
        ..plane()
    };
    assert_eq!(
        rt.block_on(second.claim(&other, key, 300)),
        Ok(true),
        "claims are per instance"
    );
}

struct Secret;

impl RouteSecrets for Secret {
    fn resolve<'a>(&'a self, _reference: &'a SecretRef) -> BoxFut<'a, Option<SecureVec>> {
        Box::pin(async { Some(SecureVec::from(b"route-secret".as_slice())) })
    }
}

#[test]
fn a_byte_identical_signed_ingress_delivery_is_refused_on_another_replica() {
    let rt = runtime();
    let shared = rt.block_on(store());
    let now = busbar_kernel::store::now();
    let body = br#"{"type":"realtime.call.incoming"}"#;
    let ts = now.to_string();
    let id = "msg_2Kp9";
    let mut msg = format!("{id}.{ts}.").into_bytes();
    msg.extend_from_slice(body);
    let tag = crypto::hmac_sha256(b"route-secret", &msg).expect("HMAC");
    let signature = format!("v1,{}", b64(&tag));
    let headers = [
        Pair {
            name: Str::new("webhook-id"),
            value: Bytes::new(id.as_bytes()),
        },
        Pair {
            name: Str::new("webhook-timestamp"),
            value: Bytes::new(ts.as_bytes()),
        },
        Pair {
            name: Str::new("webhook-signature"),
            value: Bytes::new(signature.as_bytes()),
        },
    ];
    let verifier = StandardWebhooks::new(Secret);
    let replica_a = StoreReplay::new(StoreRecords::new(Arc::clone(&shared)));
    let replica_b = StoreReplay::new(StoreRecords::new(Arc::clone(&shared)));
    let who = plane();
    let reference = SecretRef::None;
    assert_eq!(
        rt.block_on(admit(
            &verifier, &replica_a, &who, &reference, &headers, body, now
        )),
        Ok(())
    );
    assert_eq!(
        rt.block_on(admit(
            &verifier, &replica_b, &who, &reference, &headers, body, now
        )),
        Err(Refused::Replayed)
    );
}

#[test]
#[ignore = "owner: #275 (an auth fixture image answering REPLAY through the adapter)"]
fn a_replay_answer_is_never_served_from_the_verdict_cache() {
    todo!("owner: #275 (C-REPLAY verdict-cache arm)")
}
