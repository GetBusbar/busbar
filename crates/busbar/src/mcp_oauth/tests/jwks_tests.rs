// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The key-set model: parsing, key selection by `kid`, and the deferred-error discipline that keeps
//! one malformed key from poisoning a whole set.

use super::jwks::{JwkSet, KeyMaterial};
use super::support::*;

/// A key set with no keys can verify nothing, so it is refused at PARSE time rather than at verify
/// time. The difference matters: refused at parse, the operator gets a named boot failure; accepted
/// at parse, they get a deployment that answers 401 to every caller and no explanation.
#[test]
fn an_empty_key_set_is_refused_at_parse() {
    assert!(JwkSet::parse(r#"{"keys":[]}"#).is_err());
    assert!(JwkSet::parse("{}").is_err());
    assert!(JwkSet::parse("not json").is_err());
}

/// A real IdP's key set carries members this verifier has no opinion about (`alg`, `x5c`, `x5t`,
/// `nbf`). Rejecting on an unknown member would reject every production Okta and Entra document.
#[test]
fn unknown_key_members_are_ignored() {
    let set = JwkSet::parse(
        r#"{"keys":[{"kty":"EC","kid":"a","crv":"P-256","x":"AAAA","y":"BBBB",
                    "alg":"ES256","use":"sig","x5c":["..."],"x5t":"..","unheard_of":1}]}"#,
    )
    .expect("parses");
    assert_eq!(set.keys.len(), 1);
}

/// Selection is by `kid`. A non-empty queried id must never fall through to a keyless key: that is a
/// match only when the queried id is itself empty, and the difference is what makes a rotated-away
/// `kid` a miss rather than a silent match against whatever else is in the set.
#[test]
fn keys_are_selected_by_kid_and_a_named_kid_never_matches_a_keyless_key() {
    let set = JwkSet::parse(
        r#"{"keys":[
            {"kty":"EC","kid":"a","crv":"P-256","x":"AAAA","y":"BBBB"},
            {"kty":"EC","crv":"P-256","x":"CCCC","y":"DDDD"}
        ]}"#,
    )
    .expect("parses");
    assert_eq!(set.find_all("a").count(), 1);
    assert_eq!(set.find_all("").count(), 1);
    assert_eq!(set.find_all("nope").count(), 0);
}

/// RFC 7517 §4.5 permits two keys to share a `kid` when `kty` differs, which happens during an
/// algorithm migration. Every match must be offered to the caller, not just the first, or a
/// migration breaks every token signed with the second key.
#[test]
fn a_shared_kid_offers_every_matching_key() {
    let set = JwkSet::parse(
        r#"{"keys":[
            {"kty":"EC","kid":"dup","crv":"P-256","x":"AAAA","y":"BBBB"},
            {"kty":"RSA","kid":"dup","n":"AAAA","e":"AQAB"}
        ]}"#,
    )
    .expect("parses");
    assert_eq!(set.find_all("dup").count(), 2);
}

/// A key whose material is absent or not base64url does not fail the parse — it becomes an
/// `Unusable` carrying the exact reason, surfaced at verify time. One odd key in a set of five must
/// not take the other four down with it.
#[test]
fn a_malformed_key_defers_its_error_instead_of_poisoning_the_set() {
    let set = JwkSet::parse(
        r#"{"keys":[
            {"kty":"RSA","kid":"broken","e":"AQAB"},
            {"kty":"EC","kid":"fine","crv":"P-256","x":"AAAA","y":"BBBB"},
            {"kty":"OKP","kid":"unsupported","crv":"Ed25519","x":"AAAA"}
        ]}"#,
    )
    .expect("a set with one bad key still parses");
    assert_eq!(set.keys.len(), 3);
    assert!(matches!(
        set.keys[0].material(),
        KeyMaterial::Unusable(m) if m.contains("RSA modulus n")
    ));
    assert!(matches!(set.keys[1].material(), KeyMaterial::Ec { .. }));
    assert!(matches!(
        set.keys[2].material(),
        KeyMaterial::Unusable(m) if m.contains("unsupported kty")
    ));
}

/// The EC point handed to `ring` is the uncompressed SEC1 form `0x04 || X || Y`. Asserted on the
/// fixture's own key, whose coordinates are 32 bytes each, so the assembled point is 65 bytes.
#[test]
fn ec_material_is_the_uncompressed_sec1_point() {
    let idp = TestIdp::ec(ISSUER, "k1");
    let set = parse_jwks(&idp.jwks());
    match set.keys[0].material() {
        KeyMaterial::Ec { point } => {
            assert_eq!(point.len(), 65);
            assert_eq!(point[0], 0x04);
        }
        other => panic!("expected EC material, got {other:?}"),
    }
}
