// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::governance::signing::{TokenSigner, DEFAULT_KID};
use crate::persistence::host_records::timed_tests::{attach, Backend};
async fn gov(backend: Arc<Backend>, writer: u8) -> Arc<GovState> {
    Arc::new(
        GovState::new_with_core(
            attach(backend, writer).await,
            None,
            Some(TokenSigner::from_secret_bytes(&[9; 32], DEFAULT_KID)),
        )
        .await
        .unwrap(),
    )
}
async fn key(gov: &GovState) -> String {
    gov.mint_signed_async(
        NewKeySpec {
            name: "ticket principal".into(),
            ..Default::default()
        },
        1000,
        10,
    )
    .await
    .unwrap()
    .0
    .id
}

#[tokio::test]
async fn native_ticket_delivers_original_record_once_across_independent_nodes() {
    let backend = Arc::new(Backend::default());
    let first = gov(backend.clone(), 4).await;
    let id = key(&first).await;
    let (ticket, _) = first
        .mint_ticket(&id, "tk_", 60, None, b"opaque original", 10)
        .await
        .unwrap();
    let second = gov(backend, 5).await;
    let a = first
        .prepare_ticket_redemption_async("tk_", &ticket, 10)
        .await
        .unwrap();
    let b = second
        .prepare_ticket_redemption_async("tk_", &ticket, 10)
        .await
        .unwrap();
    assert_eq!(
        first.redeem_verified_ticket_async(a, 10).await.unwrap().1,
        b"opaque original"
    );
    assert!(second.redeem_verified_ticket_async(b, 10).await.is_none());
    assert!(first
        .prepare_ticket_redemption_async("tk_", &ticket, 10)
        .await
        .is_none());
}
#[tokio::test]
async fn unknown_spend_replays_original_receipt_after_expiry_then_cannot_admit_again() {
    let backend = Arc::new(Backend::default());
    let gov = gov(backend.clone(), 4).await;
    let id = key(&gov).await;
    let (ticket, expiry) = gov
        .mint_ticket(&id, "tk_", 1, None, b"opaque original", 10)
        .await
        .unwrap();
    let prepared = gov
        .prepare_ticket_redemption_async("tk_", &ticket, 10)
        .await
        .unwrap();
    backend.lose_reply.store(true, Ordering::SeqCst);
    assert!(gov
        .redeem_verified_ticket_async(prepared, 10)
        .await
        .is_none());
    assert_eq!(gov.ticket_operations.pending.lock().unwrap().len(), 1);
    backend.now.store(expiry + 1, Ordering::SeqCst);
    let retry = gov
        .prepare_ticket_redemption_async("tk_", &ticket, 10)
        .await
        .unwrap();
    assert_eq!(
        gov.redeem_verified_ticket_async(retry, 10).await.unwrap().1,
        b"opaque original"
    );
    assert!(gov
        .prepare_ticket_redemption_async("tk_", &ticket, 10)
        .await
        .is_none());
}
#[tokio::test]
async fn queue_crossing_native_expiry_spends_nothing_despite_slow_caller_clock() {
    let backend = Arc::new(Backend::default());
    let gov = gov(backend.clone(), 4).await;
    let id = key(&gov).await;
    let (ticket, expiry) = gov
        .mint_ticket(&id, "tk_", 1, None, b"opaque original", 10)
        .await
        .unwrap();
    let prepared = gov
        .prepare_ticket_redemption_async("tk_", &ticket, 10)
        .await
        .unwrap();
    let ticket_id = prepared.id.clone();
    backend.now.store(expiry + 1, Ordering::SeqCst);
    assert!(gov
        .redeem_verified_ticket_async(prepared, 10)
        .await
        .is_none());
    let records = scope(gov.core_store_handle().unwrap()).unwrap();
    assert!(records
        .get(TICKET_RECORD_KIND, ticket_id.as_bytes())
        .await
        .unwrap()
        .is_some());
    assert!(records
        .get(TICKET_SPENT_KIND, ticket_id.as_bytes())
        .await
        .unwrap()
        .is_none());
}
#[tokio::test]
async fn rejected_host_custody_binding_never_publishes_a_credential_and_deletes_exact_record() {
    let backend = Arc::new(Backend::default());
    let gov = gov(backend, 4).await;
    let id = key(&gov).await;
    let captured = std::sync::Mutex::new(None);
    assert_eq!(
        gov.mint_ticket_bound(&id, "tk_", 60, None, b"opaque original", 10, |identity| {
            *captured.lock().unwrap() = Some(identity.id.clone());
            Err(TicketRefusal::NotKept)
        })
        .await,
        Err(TicketRefusal::NotKept)
    );
    let ticket_id = captured.lock().unwrap().clone().unwrap();
    assert!(scope(gov.core_store_handle().unwrap())
        .unwrap()
        .get(TICKET_RECORD_KIND, ticket_id.as_bytes())
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn expiry_cleanup_uses_native_time_and_keeps_valid_records_under_fast_caller_clock() {
    let backend = Arc::new(Backend::default());
    let gov = gov(backend.clone(), 4).await;
    let id = key(&gov).await;
    let (original, expiry) = gov
        .mint_ticket(&id, "tk_", 1, None, b"original", 10)
        .await
        .unwrap();
    let original_id = gov.checked_ticket("tk_", &original, 10).unwrap().1;
    gov.mint_ticket(&id, "tk_", 60, None, b"fast-node", 100)
        .await
        .unwrap();
    let records = scope(gov.core_store_handle().unwrap()).unwrap();
    assert!(records
        .get(TICKET_RECORD_KIND, original_id.as_bytes())
        .await
        .unwrap()
        .is_some());
    backend.now.store(expiry + 1, Ordering::SeqCst);
    gov.mint_ticket(&id, "tk_", 60, None, b"slow-node", 10)
        .await
        .unwrap();
    assert!(records
        .get(TICKET_RECORD_KIND, original_id.as_bytes())
        .await
        .unwrap()
        .is_none());
    assert!(records
        .get(EXPIRY_SCHEMA, &expiry_key(&original_id, expiry))
        .await
        .unwrap()
        .is_none());
}
