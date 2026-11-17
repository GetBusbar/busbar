// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::response_delivery::{FinalResponseIntent, ResponseDisposition, ResponseKey};

use crate::response_intent::{verify_response_intent, PreparedResponseIntent, ResponseIntentStamp};
use crate::{AuditKeySet, AuditSigningKey, AuditVerifyingKey, BootstrapSigner, LiveSigner};

fn intent(unit: Option<u64>) -> FinalResponseIntent {
    FinalResponseIntent {
        key: ResponseKey {
            node: 9,
            incarnation: 3,
            unit: unit.map(busbar_contract::ids::UnitKey::new),
            connection_generation: 4,
            stream: 7,
        },
        final_publication_ordinal: 11,
        disposition: ResponseDisposition::End { status: Some(200) },
    }
}

fn stamp() -> ResponseIntentStamp {
    ResponseIntentStamp {
        lease_epoch: 2,
        policy_epoch: 5,
        wall: 100,
        mono: 8,
    }
}

fn signer(seed: u8) -> (BootstrapSigner, AuditKeySet) {
    let key = AuditSigningKey::from_seed(&[seed; 32]);
    let public = AuditVerifyingKey::from_hex(&key.public_key_hex()).unwrap();
    let mut keys = AuditKeySet::new();
    keys.insert(public);
    let (_, grant) = key.into_grants(LiveSigner::SameAsBootstrap).unwrap();
    (BootstrapSigner::new(grant), keys)
}

fn signed(unit: Option<u64>) -> (Vec<u8>, AuditKeySet) {
    let (signer, keys) = signer(41);
    let prepared = PreparedResponseIntent::new(intent(unit), stamp(), signer.key_id()).unwrap();
    let signatures = signer.sign_checkpoint(&[prepared.signing_body()]).unwrap();
    (prepared.signed_body(&signatures[0]).unwrap(), keys)
}

#[test]
fn exact_response_intent_roundtrip_and_absent_unit_are_distinct() {
    for unit in [Some(13), None] {
        let (body, keys) = signed(unit);
        let verified = verify_response_intent(&body, 9, stamp(), &keys)
            .unwrap()
            .unwrap();
        assert_eq!(verified.intent, intent(unit));
        assert_eq!(verified.stamp, stamp());
    }
}

#[test]
fn every_signed_payload_byte_and_signature_byte_is_authenticated() {
    let (body, keys) = signed(Some(13));
    // The first three fields are u64-length-prefixed domain, key id and 88-byte payload.
    let payload = 8 + "response.final-intent.v1".len() + 8 + 16 + 8;
    for at in payload..body.len() {
        let mut tampered = body.clone();
        tampered[at] ^= 1;
        assert!(
            verify_response_intent(&tampered, 9, stamp(), &keys).is_err(),
            "byte {at}"
        );
    }
}

#[test]
fn matching_domain_damage_is_error_and_other_domain_is_not_this_record() {
    let (body, keys) = signed(None);
    for end in (8 + "response.final-intent.v1".len())..body.len() {
        assert!(verify_response_intent(&body[..end], 9, stamp(), &keys).is_err());
    }
    let mut trailing = body.clone();
    trailing.push(0);
    assert!(verify_response_intent(&trailing, 9, stamp(), &keys).is_err());
    let mut unrelated = body;
    unrelated[8] = b'x';
    assert!(verify_response_intent(&unrelated, 9, stamp(), &keys)
        .unwrap()
        .is_none());
}

#[test]
fn header_identity_and_each_captured_epoch_clock_must_match() {
    let (body, keys) = signed(Some(13));
    assert!(verify_response_intent(&body, 10, stamp(), &keys).is_err());
    for altered in [
        ResponseIntentStamp {
            lease_epoch: 3,
            ..stamp()
        },
        ResponseIntentStamp {
            policy_epoch: 6,
            ..stamp()
        },
        ResponseIntentStamp {
            wall: 101,
            ..stamp()
        },
        ResponseIntentStamp { mono: 9, ..stamp() },
    ] {
        assert!(verify_response_intent(&body, 9, altered, &keys).is_err());
    }
}

#[test]
fn retired_signing_key_is_required_and_active_key_cannot_substitute() {
    let (body, old) = signed(Some(13));
    let (new_signer, mut retained) = signer(42);
    assert!(verify_response_intent(&body, 9, stamp(), &retained).is_err());
    retained.insert(old.keys()[0].clone());
    assert!(verify_response_intent(&body, 9, stamp(), &retained)
        .unwrap()
        .is_some());
    let prepared =
        PreparedResponseIntent::new(intent(Some(13)), stamp(), old.keys()[0].key_id()).unwrap();
    let wrong = new_signer
        .sign_checkpoint(&[prepared.signing_body()])
        .unwrap();
    let wrong = prepared.signed_body(&wrong[0]).unwrap();
    assert!(verify_response_intent(&wrong, 9, stamp(), &retained).is_err());
}

#[test]
fn invalid_dispositions_and_zero_ordinal_never_reach_signer() {
    let (signer, _) = signer(41);
    let mut bad = intent(Some(13));
    bad.final_publication_ordinal = 0;
    assert!(PreparedResponseIntent::new(bad, stamp(), signer.key_id()).is_err());
    for status in [0, 200, 399, 600] {
        bad = intent(None);
        bad.disposition = ResponseDisposition::Refuse {
            status,
            head_sent: false,
        };
        assert!(PreparedResponseIntent::new(bad, stamp(), signer.key_id()).is_err());
    }
    assert!(PreparedResponseIntent::new(intent(None), stamp(), "00000000000000GG").is_err());
}
