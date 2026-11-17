// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::native::{NativeCredential, NativeRouteBindings, SelectedCredential};
use busbar_contract::conn::OwnedHead;
use busbar_contract::dest::DestinationId;
use busbar_contract::secure::SecureVec;
use busbar_ports::auth::OutboundAnswer;

#[test]
fn native_selection_requires_exact_pool_member_and_destination() {
    let routes = NativeRouteBindings::new([
        (
            "pool-a".into(),
            "plane/model".into(),
            DestinationId::new(7),
            SelectedCredential::None,
        ),
        (
            "pool-b".into(),
            "plane/model".into(),
            DestinationId::new(8),
            SelectedCredential::None,
        ),
    ])
    .unwrap();
    assert!(routes
        .select("pool-a", "plane/model", DestinationId::new(7))
        .is_ok());
    assert!(routes
        .select("pool-a", "plane/model", DestinationId::new(8))
        .is_err());
    assert!(routes
        .select("pool-c", "plane/model", DestinationId::new(7))
        .is_err());
    assert!(routes
        .select("pool-a", "model", DestinationId::new(7))
        .is_err());
}

#[test]
fn native_credentials_seal_names_and_require_secure_transport() {
    let credential = NativeCredential::Direct(OutboundAnswer {
        headers: vec![(
            "AuThOrIzAtIoN".into(),
            SecureVec::from(&b"canary-secret"[..]),
        )],
        query: vec![("key".into(), SecureVec::from(&b"a &b"[..]))],
        cache_s: 60,
        grant_update: None,
    });
    assert!(credential.require_secure());
    assert!(credential.covers_header(b"authorization"));
    assert!(!credential.covers_header(b"x-other"));
    assert_eq!(credential.sealed_names(), ["authorization"]);
    let mut head = OwnedHead::with_capacity(2);
    credential.append_to(&mut head);
    let fields = head.view();
    assert_eq!(fields[0].1, b"canary-secret");
    assert_eq!(fields[1].1, b"key=a%20%26b");
}

#[test]
fn empty_native_answer_does_not_require_credential_transport() {
    let credential = NativeCredential::Direct(OutboundAnswer {
        headers: Vec::new(),
        query: Vec::new(),
        cache_s: 0,
        grant_update: None,
    });
    assert!(!credential.require_secure());
}
