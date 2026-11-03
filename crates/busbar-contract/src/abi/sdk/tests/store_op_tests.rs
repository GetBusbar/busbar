// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One op, one connection: a store op's checkout answers its own stream again for the same need

use std::task::Poll;

use super::{Checkout, Op, Parked};
use crate::abi::mechanism::ticket::Ticket;
use crate::abi::sdk::conn::ConnFailure;

const TICKET: Ticket = Ticket {
    slot: 3,
    generation: 1,
};

fn holding(need: u32, target: Option<&str>) -> Op<'static> {
    Op::enter(
        TICKET,
        None,
        Some(Parked {
            state: None,
            checkout: Some(Checkout {
                need,
                target: target.map(str::to_owned),
                stream: 42,
            }),
            issued: 1,
            replay: None,
            host: None,
            ticket: TICKET,
        }),
        None,
    )
}

#[test]
fn a_second_checkout_for_the_same_need_and_target_is_the_same_stream() {
    let mut op = holding(0, Some("db:5432"));
    assert_eq!(op.checkout(0, Some("db:5432")), Poll::Ready(Ok(42)));
}

#[test]
fn a_second_checkout_for_another_target_or_need_is_refused() {
    let mut op = holding(0, Some("db:5432"));
    assert!(matches!(
        op.checkout(0, Some("other:5432")),
        Poll::Ready(Err(ConnFailure::Refused(_)))
    ));
    assert!(matches!(
        op.checkout(1, Some("db:5432")),
        Poll::Ready(Err(ConnFailure::Refused(_)))
    ));
}

#[test]
fn an_op_on_no_ticket_may_not_pend_or_connect() {
    let mut op = Op::detached();
    assert!(!op.can_pend());
    op.park(7u32);
    assert_eq!(op.resume::<u32>(), None, "nothing is kept on no ticket");
    assert!(matches!(op.connector(), Err(ConnFailure::Unarmed)));
}

/// The typed continuation owns its request across a PENDING boundary. Durable
/// rewrap CAS is proved separately by the actual SQLite product, not this op test.
#[test]
fn a_parked_rewrap_request_owns_its_exact_fields_after_caller_buffers_are_dropped() {
    use crate::abi::sdk::store::rewrap;
    use crate::records::{CredentialMeta, CredentialSecret, SecretForm};

    let expected = CredentialSecret {
        meta: CredentialMeta {
            id: "pending".into(),
            key_id: "owner".into(),
            kind: "signing".into(),
            slot: 0,
            public_id: "public".into(),
            secret_form: SecretForm::Recoverable,
            created_at: 1,
            updated_at: 1,
            expires_at: None,
            revoked_at: None,
            revoke_reason: None,
            revision: 8,
        },
        secret: "v1:plain:OLD_ENVELOPE_CANARY".into(),
    };
    let same_expected = expected.clone();
    let replacement = "v1:aead:NEW_ENVELOPE_CANARY".to_string();
    let mut first = Op::enter(TICKET, None, None, None);
    assert!(first.can_pend(), "the typed continuation has a real ticket");
    first.park(rewrap::Request::new(&expected, &replacement));
    drop(expected);
    drop(replacement);
    let parked = first.into_parked();
    let mut resumed = Op::enter(TICKET, None, Some(parked), None);
    assert!(resumed.resuming());
    let kept = resumed
        .resume::<rewrap::Request>()
        .expect("the exact typed request survives the pending boundary");
    assert!(kept.expected == same_expected);
    assert_eq!(kept.replacement, "v1:aead:NEW_ENVELOPE_CANARY");
    assert!(
        resumed.resume::<rewrap::Request>().is_none(),
        "the owned continuation is taken once"
    );
}
