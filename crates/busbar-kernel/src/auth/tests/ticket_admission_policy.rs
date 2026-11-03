// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use std::sync::Arc;

fn actual_ticket(label: &str) -> (Arc<crate::governance::GovState>, String, String, u64) {
    let actual = crate::real_store::store();
    let signer = crate::governance::signing::TokenSigner::from_secret_bytes(
        &[7; 32],
        crate::governance::signing::DEFAULT_KID,
    );
    let gov = Arc::new(
        crate::governance::GovState::new_with_signer(actual.clone(), None, Some(signer)).unwrap(),
    );
    assert!(gov.attach_store_calls(actual));
    let now = crate::store::now();
    let (key, _) = gov
        .mint_signed(
            crate::governance::NewKeySpec {
                name: label.to_owned(),
                ..Default::default()
            },
            now + 3600,
            now,
        )
        .unwrap();
    let (ticket, _) = gov
        .mint_ticket(&key.id, "tk_", 600, None, b"ticket-record", now)
        .unwrap();
    (gov, key.id, ticket, now)
}

#[tokio::test]
async fn final_ticket_admission_uses_the_actual_key_and_spends_the_record_once() {
    let (gov, id, ticket, now) = actual_ticket("final-admission");
    assert_eq!(
        gov.peek_ticket_async("tk_", &ticket, now).await.unwrap().id,
        id
    );
    assert_eq!(
        gov.peek_ticket_async("tk_", &ticket, now).await.unwrap().id,
        id
    );
    let (verdict, record) =
        ticket_verdict(false, true, Some("tk_"), Some(&ticket), Some(&gov), now)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(record, b"ticket-record");
    let ChainVerdict::Identified {
        module,
        principal,
        resolved,
    } = verdict
    else {
        panic!("ticket admission must identify its real key")
    };
    assert_eq!(module, crate::config::KEYS_MODULE);
    assert_eq!(principal.id, id);
    assert_eq!(resolved.unwrap().id, id);
    assert!(
        ticket_verdict(false, true, Some("tk_"), Some(&ticket), Some(&gov), now)
            .await
            .is_err()
    );
    assert!(gov.admit_ticket("tk_", &ticket, now).is_none());
}

#[tokio::test]
async fn a_signed_identity_preempts_ticket_consumption_but_a_matched_invalid_ticket_never_falls_through(
) {
    let (gov, _, ticket, now) = actual_ticket("signed-ticket-priority");
    assert!(
        ticket_verdict(true, true, Some("tk_"), Some(&ticket), Some(&gov), now)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        gov.peek_ticket_async("tk_", &ticket, now).await.is_some(),
        "signed precedence leaves the actual ticket unspent"
    );
    for (keys, prefix, token) in [
        (false, Some("tk_"), Some(ticket.as_str())),
        (true, None, Some(ticket.as_str())),
        (true, Some("other_"), Some(ticket.as_str())),
        (true, Some("tk_"), None),
    ] {
        assert!(ticket_verdict(false, keys, prefix, token, Some(&gov), now)
            .await
            .unwrap()
            .is_none());
    }
    assert!(gov.peek_ticket_async("tk_", &ticket, now).await.is_some());
    assert!(
        ticket_verdict(
            false,
            true,
            Some("tk_"),
            Some("tk_malformed"),
            Some(&gov),
            now
        )
        .await
        .is_err(),
        "a prefix-matched failure cannot select the ordinary chain"
    );
    assert!(
        ticket_verdict(false, true, Some("tk_"), Some(&ticket), None, now)
            .await
            .is_err(),
        "missing Store authority refuses instead of falling through"
    );
    assert!(gov.admit_ticket("tk_", &ticket, now).is_some());
}

#[tokio::test(flavor = "current_thread")]
async fn final_ticket_record_wait_keeps_the_reactor_live_and_resolves_the_actual_identity_once() {
    let now = crate::store::now();
    let (gov, id, ticket, release, entered) =
        crate::governance::GovState::paused_ticket_for_test("get", now);
    let mut admitted = Box::pin(ticket_verdict(
        false,
        true,
        Some("tk_"),
        Some(&ticket),
        Some(&gov),
        now,
    ));
    assert!(futures::poll!(&mut admitted).is_pending());
    entered.await.unwrap();
    assert!(release.is_busy());
    tokio::spawn(async {}).await.unwrap();
    release.release();
    let (verdict, record) = admitted.await.unwrap().unwrap();
    assert_eq!(record, b"record");
    assert!(matches!(verdict, ChainVerdict::Identified { principal, .. } if principal.id == id));
    assert!(gov.admit_ticket("tk_", &ticket, now).is_none());
}

#[tokio::test]
async fn refused_host_custody_never_spends_the_durable_ticket() {
    struct Refuse;
    impl crate::appbuild::RootRules for Refuse {
        fn check(&self, _: &crate::config::RootCfg) -> Result<(), String> {
            Ok(())
        }
        fn claim_ticket_admission(
            &self,
            _: &crate::host_services::VerifiedTicketIdentity,
        ) -> crate::host_services::TicketClaimDisposition {
            crate::host_services::TicketClaimDisposition::Refused
        }
    }
    let (gov, _, ticket, now) = actual_ticket("missing-host-custody");
    assert!(claimed_ticket_verdict(
        false,
        true,
        Some("tk_"),
        Some(&ticket),
        Some(&gov),
        now,
        &Refuse,
    )
    .await
    .is_err());
    assert!(gov.peek_ticket_async("tk_", &ticket, now).await.is_some());
    assert!(gov.admit_ticket("tk_", &ticket, now).is_some());
}
