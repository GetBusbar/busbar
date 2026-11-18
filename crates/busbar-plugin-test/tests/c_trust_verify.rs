// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-TRUST-VERIFY (ABI-MIN3-INTERFACE §14): TRUST(TRUST_VERIFY) verdicts equal today's `trust.verify` on its
//! golden corpus.
//!
//! W1-K10: the plane-facing `TrustBook::verify` of the kernel's `CoreTrustBook`, with the TRUST_APPROVAL root of
//! (`plane.name`, party): a card signed by the root answers SIGNED_VERIFIED; a different key SIGNED_NOT_BY_ROOT; a
//! header naming another algorithm SIGNED_ALGORITHM with the name in `named`; no root SIGNED_MALFORMED_ROOT; and
//! the rest of today's corpus (busbar-kernel `tests/trust_verify_tests.rs`) answers today's verdicts. The kernel's
//! own test (`trust/tests/plane_book_tests.rs`) compares every verdict with today's `trust::signed` body.

use std::sync::Arc;

use busbar_contract::crypto::ed25519::SigningKey;
use busbar_kernel::plugin_records::StoreRecords;
use busbar_kernel::trust::book::TrustBook as Judge;
use busbar_kernel::trust::plane_book::{CoreTrustBook, TrustAudit, TrustBook as _};
use busbar_kernel::trust::reverify::Policy;
use busbar_kernel::trust::section::{DeclaredPin, TrustEntry};
use busbar_plugin_abi::plane::{
    SIGNED_ALGORITHM, SIGNED_CRITICAL, SIGNED_MALFORMED_HEADER, SIGNED_MALFORMED_ROOT,
    SIGNED_MALFORMED_SIGNATURE, SIGNED_NONE, SIGNED_NOT_BY_ROOT, SIGNED_TOO_MANY, SIGNED_VERIFIED,
};

use crate::k10_rig::{b64, b64url, plane, runtime, store};

const PAYLOAD: &[u8] = br#"{"name":"peer","version":"1"}"#;
const KEY_INFO_HEAD: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

fn key(seed: u8) -> SigningKey {
    SigningKey::from_seed(&[seed; 32]).expect("an Ed25519 seed")
}

fn key_info(k: &SigningKey) -> String {
    b64(&[&KEY_INFO_HEAD[..], &k.verifying_key().to_bytes()[..]].concat())
}

fn root(key: Option<String>) -> TrustEntry {
    TrustEntry {
        pin: Some(DeclaredPin {
            mechanism: "jws_issuer_key".into(),
            root: true,
            peer_key: false,
            key,
            fingerprint: None,
        }),
        policy: Policy {
            ttl_ms: 0,
            recovery_backoff_ms: 0,
        },
        approved: Default::default(),
    }
}

fn signature(k: &SigningKey, header: &str, payload: &[u8]) -> String {
    let protected = b64url(header.as_bytes());
    let input = format!("{protected}.{}", b64url(payload));
    let sig = b64url(&k.sign(input.as_bytes()));
    format!(r#"{{"protected":"{protected}","signature":"{sig}"}}"#)
}

const EDDSA: &str = r#"{"alg":"EdDSA","kid":"k1"}"#;

#[test]
fn trust_verify_matches_the_golden_corpus() {
    let rt = runtime();
    let book = CoreTrustBook::new(
        Arc::new(Judge::default()),
        StoreRecords::new(rt.block_on(store())),
        Arc::new(TrustAudit::tracing()),
        busbar_kernel::store::now_ms,
    );
    rt.block_on(book.admit(
        "tools",
        vec![
            ("issuer".to_owned(), root(Some(key_info(&key(1))))),
            ("bad-root".to_owned(), root(Some("not a key".to_owned()))),
        ],
    ))
    .expect("admitted");
    let who = plane();
    let verdict = |party: &str, payload: &[u8], sigs: &str| {
        let mut named = String::new();
        let v = book.verify(&who, party, payload, sigs.as_bytes(), &mut named);
        (v, named)
    };
    let good = signature(&key(1), EDDSA, PAYLOAD);
    let none = (SIGNED_NONE, String::new());

    assert_eq!(
        verdict("issuer", PAYLOAD, &format!("[{good}]")),
        (SIGNED_VERIFIED, String::new())
    );
    assert_eq!(
        verdict(
            "issuer",
            PAYLOAD,
            &format!("[{}]", signature(&key(2), EDDSA, PAYLOAD))
        ),
        (SIGNED_NOT_BY_ROOT, String::new())
    );
    assert_eq!(
        verdict(
            "issuer",
            br#"{"name":"peer","version":"2"}"#.as_slice(),
            &format!("[{good}]")
        ),
        (SIGNED_NOT_BY_ROOT, String::new())
    );
    assert_eq!(
        verdict(
            "issuer",
            PAYLOAD,
            &format!("[{good},{}]", signature(&key(2), EDDSA, PAYLOAD))
        ),
        (SIGNED_VERIFIED, String::new()),
        "one signature by the root is enough"
    );
    assert_eq!(verdict("issuer", PAYLOAD, ""), none);
    assert_eq!(verdict("issuer", PAYLOAD, "[]"), none);
    let nine = vec![good.clone(); 9].join(",");
    assert_eq!(
        verdict("issuer", PAYLOAD, &format!("[{nine}]")),
        (SIGNED_TOO_MANY, String::new())
    );
    assert_eq!(
        verdict(
            "issuer",
            PAYLOAD,
            r#"[{"protected":"!!","signature":"AA"}]"#
        ),
        (SIGNED_MALFORMED_HEADER, String::new())
    );
    assert_eq!(
        verdict(
            "issuer",
            PAYLOAD,
            &format!("[{}]", signature(&key(1), r#"{"alg":"ES256"}"#, PAYLOAD))
        ),
        (SIGNED_ALGORITHM, "ES256".to_owned())
    );
    assert_eq!(
        verdict(
            "issuer",
            PAYLOAD,
            &format!(
                "[{}]",
                signature(&key(1), r#"{"alg":"EdDSA","crit":["exp"]}"#, PAYLOAD)
            )
        ),
        (SIGNED_CRITICAL, "exp".to_owned())
    );
    let protected = b64url(EDDSA.as_bytes());
    assert_eq!(
        verdict(
            "issuer",
            PAYLOAD,
            &format!(r#"[{{"protected":"{protected}","signature":"AAAA"}}]"#)
        ),
        (SIGNED_MALFORMED_SIGNATURE, String::new())
    );
    assert_eq!(
        verdict("unknown", PAYLOAD, &format!("[{good}]")),
        (SIGNED_MALFORMED_ROOT, String::new()),
        "no root configured"
    );
    assert_eq!(
        verdict("bad-root", PAYLOAD, &format!("[{good}]")),
        (SIGNED_MALFORMED_ROOT, String::new())
    );
}
