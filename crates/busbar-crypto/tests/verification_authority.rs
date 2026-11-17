// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_crypto::verification::{Authority, Context, Failure, Operation, Phase, Unavailable};
use std::cell::RefCell;

struct Admission {
    deny: Option<Phase>,
    visits: RefCell<Vec<(Operation, Phase)>>,
}

impl Authority for Admission {
    fn check(&self, operation: Operation, phase: Phase) -> Result<(), Unavailable> {
        self.visits.borrow_mut().push((operation, phase));
        if self.deny == Some(phase) {
            Err(Unavailable)
        } else {
            Ok(())
        }
    }
}

#[test]
fn revoked_authority_never_publishes_a_digest() {
    for phase in [Phase::Before, Phase::After] {
        let authority = Admission {
            deny: Some(phase),
            visits: RefCell::new(Vec::new()),
        };
        assert_eq!(
            Context::new(&authority).sha256(b"abc"),
            Err(Failure::AuthorityUnavailable)
        );
        assert_eq!(
            authority.visits.borrow().len(),
            if phase == Phase::Before { 1 } else { 2 }
        );
    }
}

#[test]
fn invalid_signature_still_checks_authority_after_the_primitive() {
    let signer = busbar_crypto::ed25519::SigningKey::from_seed(&[41; 32]).unwrap();
    let authority = Admission {
        deny: Some(Phase::After),
        visits: RefCell::new(Vec::new()),
    };
    assert_eq!(
        Context::new(&authority).verify_ed25519(&signer.verifying_key(), b"x", &[0; 64]),
        Err(Failure::AuthorityUnavailable)
    );
    assert_eq!(
        *authority.visits.borrow(),
        vec![
            (Operation::Ed25519Verify, Phase::Before),
            (Operation::Ed25519Verify, Phase::After),
        ]
    );
}

#[test]
fn unrestricted_verification_retains_known_answer_and_mismatch() {
    let context = Context::unrestricted();
    assert_eq!(
        context.sha256(b"abc").unwrap(),
        busbar_crypto::sha256(b"abc")
    );
    let signer = busbar_crypto::ed25519::SigningKey::from_seed(&[42; 32]).unwrap();
    let signature = signer.sign(b"signed");
    context
        .verify_ed25519(&signer.verifying_key(), b"signed", &signature)
        .unwrap();
    assert_eq!(
        context.verify_ed25519(&signer.verifying_key(), b"changed", &signature),
        Err(Failure::Provider(busbar_crypto::Error::Mismatch))
    );
}

#[test]
fn p256_import_requires_a_real_uncompressed_point() {
    let context = Context::unrestricted();
    let mut off_curve = [0; 65];
    off_curve[0] = 4;
    assert!(matches!(
        context.validate_p256(&off_curve),
        Err(Failure::Provider(busbar_crypto::Error::Invalid(_)))
    ));
    let key = busbar_crypto::ecdsa_p256::from_pkcs8(
        &busbar_crypto::ecdsa_p256::generate_pkcs8().unwrap(),
    )
    .unwrap();
    context.validate_p256(&key.public_key()).unwrap();
}

#[test]
fn provider_failure_is_distinct_from_invalid_proof() {
    assert!(Failure::Provider(busbar_crypto::Error::ProviderUnavailable).is_unavailable());
    assert!(!Failure::Provider(busbar_crypto::Error::Mismatch).is_unavailable());
    assert!(!Failure::Provider(busbar_crypto::Error::Invalid("key")).is_unavailable());
}
