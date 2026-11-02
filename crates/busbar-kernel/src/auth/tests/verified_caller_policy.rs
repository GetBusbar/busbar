// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn the_opaque_caller_uses_only_the_verified_credential_for_every_carrier() {
    for (carrier, verified) in [
        ("bearer", Some("bearer-verified")),
        ("query", Some("query-verified")),
        ("custom", Some("custom-verified")),
        ("transformed", Some("normalized-verified")),
        ("absent", None),
    ] {
        let secret = verified.map(|value| busbar_contract::redacted::Secret::new(value.to_owned()));
        let opaque =
            verified_caller_credential(Some(secret.as_ref()), Some("unverified-wire-value"));
        assert_eq!(
            opaque
                .as_ref()
                .map(|caller| caller.lend().expose(&crate::seal::lend()).clone()),
            verified.map(|value| value.as_bytes().to_vec()),
            "{carrier}"
        );
        if let Some(verified) = verified {
            assert!(!format!("{opaque:?}").contains(verified));
        }
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer unverified-wire-value"),
        );
        headers.insert(
            "x-custom",
            HeaderValue::from_static("unverified-wire-value"),
        );
        headers.insert("x-safe", HeaderValue::from_static("kept"));
        let consumed = ConsumedCredentials::carrying(&[
            HeaderName::from_static("authorization"),
            HeaderName::from_static("x-custom"),
        ]);
        consumed.strip(&mut headers);
        assert!(!headers.contains_key("authorization"));
        assert!(!headers.contains_key("x-custom"));
        assert_eq!(headers.get("x-safe").unwrap(), "kept");
    }
    assert_eq!(
        verified_caller_credential(None, Some("normal-client-token"))
            .unwrap()
            .lend()
            .expose(&crate::seal::lend())
            .as_slice(),
        b"normal-client-token"
    );
    assert!(verified_caller_credential(None, None).is_none());
    assert!(verified_caller_credential(Some(None), Some("must-not-fall-back")).is_none());
}
