// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SINGLE-PATH SP-AU3: one door-ticket redemption verifies the ticket's signature once and
//! carries it from the inbound auth point to the final gate. Counted by the dev-only stage probes
//! (`busbar_contract::stage_probe`). A door-ticket request reaches governance twice: the inbound
//! auth point peeks the ticket (`inbound.rs`; a refusal there answers `FLOW_STOP` before any
//! hand-in) and the final gate redeems it (`auth_middleware` -> `claimed_ticket_verdict`).

use super::*;
use busbar_contract::stage_probe::{Derive, Scope};
use std::sync::Arc;

const PREFIX: &str = "tk_";

fn signer(seed: u8) -> crate::governance::signing::TokenSigner {
    crate::governance::signing::TokenSigner::from_secret_bytes(
        &[seed; 32],
        crate::governance::signing::DEFAULT_KID,
    )
}

async fn minted_ticket(label: &str) -> (Arc<crate::governance::GovState>, String, String, u64) {
    let gov = Arc::new(
        crate::governance::GovState::new_with_core(
            crate::real_store::core().await,
            None,
            Some(signer(7)),
        )
        .await
        .unwrap(),
    );
    let now = crate::store::now();
    let (key, _) = gov
        .mint_signed_async(
            crate::governance::NewKeySpec {
                name: label.to_owned(),
                ..Default::default()
            },
            now + 3600,
            now,
        )
        .await
        .unwrap();
    let (ticket, _) = gov
        .mint_ticket(&key.id, PREFIX, 600, None, b"ticket-record", now)
        .await
        .unwrap();
    (gov, key.id, ticket, now)
}

/// What the inbound auth point learned about the ticket: the key and the verified ticket the
/// unit's `Derived` record carries to the final gate.
struct Peeked(
    Arc<busbar_contract::records::VirtualKey>,
    crate::governance::VerifiedTicket,
);

/// The inbound auth point's ticket check.
async fn auth_point(
    gov: &Arc<crate::governance::GovState>,
    ticket: &str,
    now: u64,
) -> Option<Peeked> {
    gov.peek_door_ticket_async(PREFIX, ticket, now)
        .await
        .map(|(key, verified)| Peeked(key, verified))
}

/// The final gate's redemption for the same request.
async fn final_gate(
    gov: &Arc<crate::governance::GovState>,
    ticket: &str,
    peeked: &Peeked,
    now: u64,
) -> Result<Option<ClaimedTicketVerdict>, ()> {
    let _ = &peeked.0;
    claimed_ticket_verdict(
        PresentedTicket {
            signed: false,
            keys_in_chain: true,
            prefix: Some(PREFIX),
            token: Some(ticket),
            carried: Some(&peeked.1),
        },
        Some(gov),
        now,
        &crate::appbuild::AcceptAll,
    )
    .await
}

#[tokio::test]
async fn door_ticket_signature_checked_once() {
    let (gov, id, ticket, now) = minted_ticket("single-path-ticket").await;

    let scope = Scope::open();
    let peeked = auth_point(&gov, &ticket, now)
        .await
        .expect("the auth point admits a live ticket");
    let (verdict, record, _) = final_gate(&gov, &ticket, &peeked, now)
        .await
        .expect("the final gate redeems the ticket")
        .expect("a ticket route yields a ticket verdict");

    assert_eq!(record, b"ticket-record", "today's record is delivered");
    assert!(matches!(verdict, ChainVerdict::Identified { principal, .. } if principal.id == id));
    assert_eq!(
        scope.count(Derive::TicketSig),
        1,
        "the ticket's signature is verified and its claims parsed once per request"
    );
    assert_eq!(
        scope.count(Derive::TicketStanding),
        3,
        "standing is re-checked after the auth point's read, before the spend and after it"
    );
    assert_eq!(
        scope.count(Derive::TicketRead),
        1,
        "the auth point's record read is the spend's condition"
    );
}

#[tokio::test]
async fn a_key_revoked_between_the_auth_point_and_the_final_gate_is_refused() {
    let (gov, id, ticket, now) = minted_ticket("revoked-mid-redemption").await;
    let peeked = auth_point(&gov, &ticket, now)
        .await
        .expect("the auth point admits a live ticket");
    gov.revoke_async(&id, "revoked mid-redemption")
        .await
        .unwrap();
    assert!(
        final_gate(&gov, &ticket, &peeked, now).await.is_err(),
        "a key revoked after the auth point still bites at the final gate"
    );
}

#[tokio::test]
async fn a_signing_key_rotated_or_removed_between_the_auth_point_and_the_final_gate_is_refused() {
    crate::audit::auditlog::ensure_global_audit_stream_registered().await;
    for rotated in [Some(8u8), None] {
        let (gov, id, ticket, now) = minted_ticket("rotated-mid-redemption").await;
        let peeked = auth_point(&gov, &ticket, now)
            .await
            .expect("the auth point admits a live ticket");
        gov.set_signing_key(rotated.map(signer));
        assert!(
            final_gate(&gov, &ticket, &peeked, now).await.is_err(),
            "a ticket whose signing key was rotated ({rotated:?}) mid-redemption is refused"
        );
        let _ = crate::audit::auditlog::flush_pending().await;
        assert!(
            !crate::audit::auditlog::AUDIT_LOG
                .list_filtered(
                    0,
                    16,
                    Some("ticket_signing_rotated"),
                    Some(&format!("key:{id}")),
                )
                .is_empty(),
            "the rotation refusal ({rotated:?}) is audited as ticket_signing_rotated"
        );
        gov.set_signing_key(Some(signer(7)));
        assert!(
            gov.admit_ticket_async(PREFIX, &ticket, now).await.is_some(),
            "the refused redemption spent nothing"
        );
    }
}

#[tokio::test]
async fn reloading_the_same_signing_key_between_the_auth_point_and_the_final_gate_still_redeems() {
    let (gov, _, ticket, now) = minted_ticket("reloaded-mid-redemption").await;
    let peeked = auth_point(&gov, &ticket, now)
        .await
        .expect("the auth point admits a live ticket");
    gov.set_signing_key(Some(signer(7)));
    let (_, record, _) = final_gate(&gov, &ticket, &peeked, now)
        .await
        .expect("a reload that keeps the signing key is not a rotation")
        .expect("a ticket verdict");
    assert_eq!(record, b"ticket-record");
}

#[tokio::test]
async fn a_ticket_spent_by_another_unit_after_the_auth_point_is_refused_at_the_final_gate() {
    let (gov, _, ticket, now) = minted_ticket("spent-mid-redemption").await;
    let first = auth_point(&gov, &ticket, now)
        .await
        .expect("the auth point admits a live ticket");
    let second = auth_point(&gov, &ticket, now)
        .await
        .expect("a second unit's auth point admits the same live ticket");
    let (_, record, _) = final_gate(&gov, &ticket, &second, now)
        .await
        .expect("the second unit spends the ticket")
        .expect("a ticket verdict");
    assert_eq!(record, b"ticket-record");
    assert!(
        final_gate(&gov, &ticket, &first, now).await.is_err(),
        "the spend's condition refuses the unit that peeked before the other spend"
    );
}

#[tokio::test]
async fn an_already_spent_ticket_is_refused_at_the_auth_point() {
    let (gov, _, ticket, now) = minted_ticket("spent-before-auth").await;
    let peeked = auth_point(&gov, &ticket, now)
        .await
        .expect("the auth point admits a live ticket");
    final_gate(&gov, &ticket, &peeked, now)
        .await
        .expect("the ticket is spent")
        .expect("a ticket verdict");

    let scope = Scope::open();
    assert!(
        auth_point(&gov, &ticket, now).await.is_none(),
        "a spent ticket is refused at the auth point (FLOW_STOP), before any hand-in"
    );
    assert_eq!(scope.count(Derive::TicketSig), 1);
    assert_eq!(
        scope.count(Derive::TicketRead),
        1,
        "the auth point reads the spent record once and stops"
    );
}
