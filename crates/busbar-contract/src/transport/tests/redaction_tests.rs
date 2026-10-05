use super::{ClientIdentity, EgressTrust};

/// A byte value that appears NOWHERE in the redacted `Debug` shells (`ClientIdentity { … }`,
/// `EgressTrust { … }`, `[]`, `<redacted>`), so its decimal spelling in the output can only mean
/// the key material leaked. `0xEF` = 239.
const KEY_BYTE: u8 = 0xEF;

#[test]
fn client_identity_debug_redacts_private_key() {
    let id = ClientIdentity {
        cert_chain: Vec::new(),
        private_key: vec![KEY_BYTE; 8].into(),
    };
    let shown = format!("{id:?}");
    assert!(
        shown.contains("<redacted>"),
        "private key must be redacted, got: {shown}"
    );
    assert!(
        !shown.contains(&KEY_BYTE.to_string()),
        "Debug output leaked private key bytes: {shown}"
    );
}

#[test]
fn egress_trust_debug_redacts_client_private_key() {
    let trust = EgressTrust {
        extra_anchors: Vec::new(),
        pinned_public_keys: Vec::new(),
        client_identity: Some(ClientIdentity {
            cert_chain: Vec::new(),
            private_key: vec![KEY_BYTE; 8].into(),
        }),
    };
    let shown = format!("{trust:?}");
    assert!(
        shown.contains("<redacted>"),
        "nested client identity's private key must be redacted, got: {shown}"
    );
    assert!(
        !shown.contains(&KEY_BYTE.to_string()),
        "Debug output leaked nested private key bytes: {shown}"
    );
}

/// THE 1.5.5 TEXT, PINNED: `ClientIdentity`'s `Debug` is customer-visible log text, so it prints
/// exactly what it printed before the key became `Redacted` — the chain as itself, the key as
/// `"<redacted>"` — and not `Redacted`'s own `[REDACTED]`.
#[test]
fn client_identity_debug_text_is_the_1_5_5_text() {
    let id = ClientIdentity {
        cert_chain: vec![vec![1, 2]],
        private_key: vec![KEY_BYTE; 8].into(),
    };
    assert_eq!(
        format!("{id:?}"),
        "ClientIdentity { cert_chain: [[1, 2]], private_key: \"<redacted>\" }"
    );
}
