// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::mechanism::KindCode;

fn caller() -> Caller {
    Caller::issue(&crate::seal::acquire(), Arc::from("plane"), KindCode::Plane)
}

pub(super) fn publication<'a>(
    connection: &'a str,
    credential: &'a [u8],
) -> OutboundAuthorization<'a> {
    OutboundAuthorization {
        action: OUTBOUND_PUBLISH,
        need: 0,
        member: "m0",
        resource: "https://a.test/v1/chat",
        connection,
        expected_revision: 0,
        expires_at_unix: 100,
        field_name: "authorization",
        credential,
    }
}

fn bind<'a>(ask: OutboundAuthorization<'a>, revision: u64) -> OutboundAuthorization<'a> {
    OutboundAuthorization {
        action: OUTBOUND_BIND,
        expected_revision: revision,
        expires_at_unix: 0,
        credential: &[],
        field_name: "",
        ..ask
    }
}

#[test]
fn users_and_plugin_incarnations_cannot_borrow_each_others_connections() {
    let custody = Custody::default();
    let owner = caller();
    let bob = publication("connection", b"Bearer bob");
    let joe = publication("connection", b"Bearer joe");
    custody.authorize(&owner, "bob", &bob, 1).unwrap();
    assert!(custody.authorize(&owner, "joe", &bind(bob, 1), 1).is_err());
    custody.authorize(&owner, "joe", &joe, 1).unwrap();
    for (user, token) in [("bob", b"Bearer bob"), ("joe", b"Bearer joe")] {
        let (_, bound) = custody.authorize(&owner, user, &bind(bob, 1), 1).unwrap();
        let bound = bound.unwrap();
        let field = bound.field(0, bob.member, bob.resource, 1).unwrap();
        assert_eq!(field.value.expose(&crate::seal::lend()), token);
        assert!(field.require_secure);
        assert!(!format!("{bound:?}").contains(user));
        assert!(bound.field(1, bob.member, bob.resource, 1).is_none());
        assert!(bound.field(0, "another", bob.resource, 1).is_none());
        assert!(bound
            .field(0, bob.member, "https://a.test/other", 1)
            .is_none());
        assert!(bound.field(0, bob.member, bob.resource, 100).is_none());
    }
    assert!(custody
        .authorize(&caller(), "bob", &bind(bob, 1), 1)
        .is_err());
}

#[test]
fn refresh_and_revocation_fence_queued_attempts_and_late_completions() {
    let custody = Custody::default();
    let owner = caller();
    let original = publication("account", b"Bearer old");
    custody.authorize(&owner, "bob", &original, 1).unwrap();
    let (_, pending) = custody
        .authorize(&owner, "bob", &bind(original, 1), 1)
        .unwrap();
    let pending = pending.unwrap();
    let replacement = OutboundAuthorization {
        expected_revision: 1,
        credential: b"Bearer new",
        ..original
    };
    assert_eq!(
        custody.authorize(&owner, "bob", &replacement, 2).unwrap().0,
        2
    );
    assert!(pending
        .field(0, original.member, original.resource, 2)
        .is_none());
    assert!(custody.authorize(&owner, "bob", &replacement, 2).is_err());
    let (_, pending) = custody
        .authorize(&owner, "bob", &bind(original, 2), 2)
        .unwrap();
    let revoked = OutboundAuthorization {
        action: OUTBOUND_REVOKE,
        ..bind(original, 2)
    };
    assert_eq!(custody.authorize(&owner, "bob", &revoked, 3).unwrap().0, 3);
    assert!(pending
        .unwrap()
        .field(0, original.member, original.resource, 3)
        .is_none());
    assert!(custody
        .authorize(
            &owner,
            "bob",
            &OutboundAuthorization {
                expected_revision: 2,
                ..original
            },
            4
        )
        .is_err());
    assert!(custody
        .authorize(
            &owner,
            "bob",
            &OutboundAuthorization {
                expected_revision: 3,
                ..original
            },
            4
        )
        .is_err());
    assert!(custody.authorize(&owner, "bob", &original, 4).is_err());
}

#[test]
fn expired_or_malformed_publication_never_replaces_live_custody() {
    let custody = Custody::default();
    let owner = caller();
    let original = publication("account", b"Bearer old");
    custody.authorize(&owner, "bob", &original, 1).unwrap();
    for bad in [
        OutboundAuthorization {
            expires_at_unix: 1,
            ..original
        },
        OutboundAuthorization {
            credential: b"Bearer token\r\nHost: other",
            ..original
        },
        OutboundAuthorization {
            field_name: "host",
            ..original
        },
    ] {
        assert!(custody
            .authorize(
                &owner,
                "bob",
                &OutboundAuthorization {
                    expected_revision: 1,
                    ..bad
                },
                1
            )
            .is_err());
    }
    assert!(custody
        .authorize(&owner, "bob", &bind(original, 1), 1)
        .is_ok());
}

#[test]
fn stored_protected_body_never_becomes_a_header_and_revocation_blocks_late_enrollment() {
    let custody = Custody::default();
    let owner = caller();
    let body = OutboundAuthorization {
        action: OUTBOUND_PUBLISH_BODY,
        field_name: "",
        ..publication("refresh", b"grant_type=refresh_token&refresh_token=private")
    };
    custody.authorize(&owner, "bob", &body, 1).unwrap();
    let (_, bound) = custody.authorize(&owner, "bob", &bind(body, 1), 1).unwrap();
    let bound = bound.unwrap();
    assert!(bound.field(0, body.member, body.resource, 1).is_none());
    let Some(Presentation::Body(material)) = bound.present(0, body.member, body.resource, 1) else {
        panic!("host-owned body")
    };
    assert_eq!(material.expose(&crate::seal::lend()), body.credential);
    custody
        .authorize(
            &owner,
            "bob",
            &OutboundAuthorization {
                action: OUTBOUND_REVOKE,
                ..bind(body, 1)
            },
            1,
        )
        .unwrap();
    assert!(bound.present(0, body.member, body.resource, 1).is_none());
    let pending = publication("callback-still-running", b"Bearer late");
    assert_eq!(
        custody
            .authorize(
                &owner,
                "bob",
                &OutboundAuthorization {
                    action: OUTBOUND_REVOKE,
                    ..bind(pending, 0)
                },
                1
            )
            .unwrap()
            .0,
        1
    );
    assert!(custody.authorize(&owner, "bob", &pending, 1).is_err());
}
