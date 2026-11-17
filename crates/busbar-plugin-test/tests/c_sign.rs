// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-SIGN (ABI-MIN3-INTERFACE §14): FROM_CORE results arrive in the §8.6 order, before any other call (K10 lands
//! the results; plane serving delivers them).
//!
//! W1-K10: the SIGN of a mixed answer comes back as P_SIGNED in the §8.6 position: a compact JWS over the plane's
//! payload under the host key (core picks alg and kid), verifiable with the host's public key.

use busbar_contract::crypto::ed25519::SigningKey;
use busbar_plugin_abi::plane::{tag, SignedRec, CONNECT_STATUS, P_SIGNED};

use crate::k10_rig::{if_order, order, piece, records_of, resolve, runtime, Deployment};

/// base64url without padding (RFC 4648 §5), decoded.
fn b64url(text: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in text.bytes() {
        let v = ALPHABET
            .iter()
            .position(|&a| a == c)
            .expect("a base64url character");
        acc = (acc << 6) | u32::try_from(v).expect("< 64");
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xff).expect("a byte"));
        }
    }
    out
}

#[test]
fn sign_results_arrive_first_in_order() {
    let rt = runtime();
    let deployment = rt.block_on(Deployment::new());
    let host = deployment.intents(&rt, std::sync::Arc::new(deployment.connections()));
    let pieces = resolve(&host, CONNECT_STATUS);
    assert_eq!(order(&pieces), if_order());
    let signed = records_of::<SignedRec>(piece(&pieces, P_SIGNED), tag::SIGNED);
    assert_eq!(signed.len(), 1);
    let (rec, jws) = &signed[0];
    assert_eq!((rec.check, rec.status), (4, 0));
    let jws = std::str::from_utf8(jws).expect("JWS text");
    let parts: Vec<&str> = jws.split('.').collect();
    assert_eq!(parts.len(), 3, "compact serialization: {jws}");
    let header = String::from_utf8(b64url(parts[0])).expect("header JSON");
    assert!(header.contains(r#""alg":"EdDSA""#), "{header}");
    assert_eq!(b64url(parts[1]), br#"{"name":"agent-card"}"#);
    // The rig's host signer is the Ed25519 key of this seed.
    let key = SigningKey::from_seed(&[3u8; 32])
        .expect("the rig's host seed")
        .verifying_key();
    let signature: [u8; 64] = b64url(parts[2]).try_into().expect("64 signature bytes");
    key.verify_strict(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
        .expect("signed by the host key");
}
