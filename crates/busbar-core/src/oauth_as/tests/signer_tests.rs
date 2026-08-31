// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SIGNER CONFORMANCE GATE.
//!
//! `PROPOSAL-oauth-as-ring-backend.md` §4 states the debt the seam creates in one sentence: *a host
//! can install a broken signer, and wrong signatures fail silently*. A signature that does not
//! verify is indistinguishable, at a resource server, from a token somebody tampered with, so the
//! deployment learns about it from its users. That is why the harness ships WITH the backend and
//! not after it.
//!
//! The harness is `oauth_as::signer_conformance`, and the reason it is worth more than any test
//! written here is that it carries the RFC 7515 appendix A.3 known-answer vector. busbar's signer
//! and busbar's verifier agreeing with each other proves only that they agree; the RFC's vector is
//! a value neither of them produced.

use super::{RingEs256Key, RingEs256Verifier};

/// Build the signer the production plane builds, from a freshly generated key.
fn key(kid: &str) -> RingEs256Key {
    let der = RingEs256Key::generate_pkcs8().expect("generate a P-256 key");
    RingEs256Key::from_pkcs8_der(kid, &der).expect("load the key just generated")
}

/// EVERY CHECK IN THE UPSTREAM HARNESS, GREEN.
///
/// Reported by NAME on failure rather than as a count: "3 violations" sends a reader to a debugger,
/// and `signer/output_is_not_der` sends them to the one constant that is wrong.
#[tokio::test]
async fn the_ring_backend_passes_the_upstream_signer_conformance_harness() {
    let violations = oauth_as::signer_conformance::SignerConformance::new(
        key("busbar-as-test"),
        RingEs256Verifier,
    )
    .run()
    .await;

    assert!(
        violations.is_empty(),
        "the ring ES256 backend failed oauth-as's signer conformance harness:\n{}",
        violations
            .iter()
            .map(|v| format!("  {} — {}", v.check, v.detail))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// THE HARNESS ITSELF CAN GO RED, proven by planting the exact fault it exists to catch.
///
/// Emitting ASN.1 DER instead of the RFC 7518 §3.4 fixed-width `r || s` is THE way to get this
/// wrong: `ring` offers both under constants that differ by one word, both compile, and both
/// produce bytes. The `[u8; 64]` return type refuses the wrong LENGTH — a DER signature is 70-72
/// bytes and would not fit — so this fault is planted at the only place it still fits: a 64-byte
/// value that is not the signature. If this test ever passes, the harness has stopped checking and
/// the green above means nothing.
#[tokio::test]
async fn the_harness_fails_a_signer_that_does_not_actually_sign() {
    /// A signer that returns a fixed 64 bytes: right length, right type, no signature.
    struct ConstantSigner(oauth_as::jwt::Jwk);
    impl oauth_as::jwt::Es256Signer for ConstantSigner {
        async fn sign(
            &self,
            _signing_input: &[u8],
        ) -> Result<[u8; 64], oauth_as::jwt::SignerError> {
            Ok([7u8; 64])
        }
        fn public_jwk(&self) -> oauth_as::jwt::Jwk {
            self.0.clone()
        }
    }

    let real = key("busbar-as-planted-fault");
    let violations = oauth_as::signer_conformance::SignerConformance::new(
        ConstantSigner(oauth_as::jwt::Es256Signer::public_jwk(&real)),
        RingEs256Verifier,
    )
    .run()
    .await;

    assert!(
        !violations.is_empty(),
        "a signer that returns a constant passed the conformance harness, so the harness is not \
         checking anything and the green run above is not evidence"
    );
}

/// THE VERIFIER REFUSES THE DER ENCODING, stated here as well as inside the harness.
///
/// Accepting both encodings of one signature is malleability: a value a deployment recorded as
/// unique stops being unique. The harness has `verifier/rejects_the_der_encoding`; this restates it
/// against busbar's own type so a future refactor of the verifier cannot quietly widen it while the
/// upstream harness is skipped for an unrelated reason.
#[tokio::test]
async fn the_verifier_refuses_an_asn1_der_signature() {
    use oauth_as::jwt::{Es256Signer as _, Es256Verifier as _};

    let signer = key("busbar-as-der");
    let jwk = signer.public_jwk();
    let public = oauth_as::jwt::PublicJwk::from_coordinates(&jwk.x, &jwk.y).expect("coordinates");
    let input = b"the JWS signing input";
    let fixed = signer.sign(input).await.expect("sign");

    assert!(
        super::RingEs256Verifier.verify(&public, input, &fixed),
        "the fixed-width signature must verify, or the rest of this test proves nothing"
    );

    // Re-encode the same signature as the ASN.1 DER `SEQUENCE { r INTEGER, s INTEGER }` that
    // OpenSSL and most KMS APIs emit, so the verifier is presented with the exact wrong thing
    // rather than with random bytes.
    let der = der_encode(&fixed);
    assert!(
        !super::RingEs256Verifier.verify(&public, input, &der),
        "the verifier accepted the DER encoding of a signature it had already accepted in the \
         fixed-width form; two encodings of one signature is malleability"
    );
}

/// `r || s` as `SEQUENCE { r INTEGER, s INTEGER }`. Hand written, in the test, because pulling a
/// DER encoder into the dependency tree to build one test input would undo the reduction the ring
/// backend exists for.
fn der_encode(fixed: &[u8; 64]) -> Vec<u8> {
    fn integer(bytes: &[u8]) -> Vec<u8> {
        let trimmed = bytes
            .iter()
            .position(|b| *b != 0)
            .unwrap_or(bytes.len() - 1);
        let mut value = bytes[trimmed..].to_vec();
        // DER INTEGERs are signed, so a leading bit of 1 needs a zero byte in front of it.
        if value.first().is_some_and(|b| b & 0x80 != 0) {
            value.insert(0, 0x00);
        }
        let mut out = vec![0x02, value.len() as u8];
        out.extend_from_slice(&value);
        out
    }
    let mut body = integer(&fixed[..32]);
    body.extend_from_slice(&integer(&fixed[32..]));
    let mut out = vec![0x30, body.len() as u8];
    out.extend_from_slice(&body);
    out
}
