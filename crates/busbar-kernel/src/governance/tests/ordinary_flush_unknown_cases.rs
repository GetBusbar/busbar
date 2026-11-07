// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

const MODEL: &str = "ordinary-unknown-model";
const FIRST_INPUT: u64 = 7;
const LATER_INPUT: u64 = 11;

fn accrue_plain(gov: &GovState, bucket: &str, count: u64) {
    let mut cells = gov.budget.write(bucket);
    let cell = cells
        .entry(bucket.to_string())
        .or_insert_with(|| BudgetCell::fresh(0));
    cell.accrue(MODEL, 0, &tt(count));
    cell.dirty = true;
    cell.last_touch = crate::store::now();
}

async fn ordinary_unknown_result_retries_once(unwind: bool) {
    let store = Arc::new(FlakyStore::new().await);
    store.lose_usage_reply.store(true, Ordering::SeqCst);
    store.unwind_usage.store(unwind, Ordering::SeqCst);
    let key = sample_key("vk_ordinary_unknown_commit", "ordinary-unknown-generation");
    store.identity().put_key(&key).await.unwrap();
    let gov = GovState::new_with_core(store.core(), None, None)
        .await
        .unwrap();
    accrue_plain(&gov, &key.id, FIRST_INPUT);
    use futures::FutureExt;
    let first = std::panic::AssertUnwindSafe(gov.flush_budgets())
        .catch_unwind()
        .await;
    assert_eq!(first.is_err(), unwind);
    assert_eq!(
        store
            .ledger()
            .get_usage(&key.id, 0)
            .await
            .unwrap()
            .tokens_for_whole_test(MODEL),
        Some(FIRST_INPUT)
    );
    accrue_plain(&gov, &key.id, LATER_INPUT);
    gov.flush_budgets().await;
    assert_eq!(
        store
            .ledger()
            .get_usage(&key.id, 0)
            .await
            .unwrap()
            .tokens_for_whole_test(MODEL),
        Some(FIRST_INPUT + LATER_INPUT),
        "a committed ordinary flush must not be applied again when its reply was unknown"
    );
}

#[tokio::test]
async fn ordinary_small_usage_unknown_reply_does_not_duplicate_committed_effect() {
    ordinary_unknown_result_retries_once(false).await;
}

#[tokio::test]
async fn ordinary_small_usage_unwind_does_not_duplicate_committed_effect() {
    ordinary_unknown_result_retries_once(true).await;
}

#[derive(Default)]
struct RecoveryJournal(std::sync::Mutex<Vec<super::super::recovery::RecoveryEvent>>);
#[async_trait::async_trait]
impl super::super::recovery::RecoverySink for RecoveryJournal {
    async fn replay(
        &self,
    ) -> Result<Vec<super::super::recovery::RecoveryEvent>, super::super::recovery::RecoveryError>
    {
        Ok(self.0.lock().unwrap().clone())
    }
    async fn persist(
        &self,
        event: &super::super::recovery::RecoveryEvent,
    ) -> Result<(), super::super::recovery::RecoveryError> {
        let mut events = self.0.lock().unwrap();
        if !events.contains(event) {
            events.push(event.clone());
        }
        Ok(())
    }
    async fn verify_origin(
        &self,
        event: &super::super::recovery::RecoveryEvent,
    ) -> Result<(), super::super::recovery::RecoveryError> {
        use super::super::recovery::RecoveryError;

        self.replay_selections().await?;
        let events = self.0.lock().unwrap();
        let genesis = events
            .iter()
            .find(|selected| selected.operation_id == event.operation_id && selected.revision == 0)
            .unwrap_or(event);
        if (event.revision == 0 && event != genesis)
            || event.origin_reference()? != genesis.origin_reference()?
            || event.kind != genesis.kind
            || event.body_fingerprint != genesis.body_fingerprint
            || event.first_sent_at_ms != genesis.first_sent_at_ms
        {
            return Err(RecoveryError::Conflict("child identity changed".into()));
        }
        let Some(origin) = genesis.origin_reference()? else {
            return Ok(());
        };
        let parent = events
            .iter()
            .find(|parent| {
                parent.operation_id == origin.operation_id
                    && parent.fingerprint().ok() == Some(origin.event_fingerprint)
            })
            .ok_or_else(|| RecoveryError::Invalid("origin is not selected".into()))?;
        parent.authorizes_child(genesis)
    }
}

#[tokio::test]
async fn ordinary_product_flush_quarantines_old_unknown_and_continues_fresh_positive_usage() {
    use super::super::recovery::{RecoveryResolution, RecoveryState, RecoveryVerdict};
    let store = Arc::new(FlakyStore::new().await);
    store.lose_usage_reply.store(true, Ordering::SeqCst);
    let key = sample_key("vk_durable_unknown_commit", "durable-unknown-generation");
    store.identity().put_key(&key).await.unwrap();
    let journal = Arc::new(RecoveryJournal::default());
    let original = GovState::new_with_core(store.core(), None, None)
        .await
        .unwrap();
    original
        .attach_recovery_sink(journal.clone())
        .await
        .unwrap();
    accrue_plain(&original, &key.id, FIRST_INPUT);
    original.flush_budgets().await;
    assert_eq!(
        store
            .ledger()
            .get_usage(&key.id, 0)
            .await
            .unwrap()
            .tokens_for_whole_test(MODEL),
        Some(FIRST_INPUT)
    );
    let intent = original
        .recovery()
        .list(None, 10)
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(intent.state, RecoveryState::Intent);
    drop(original);

    let gov = GovState::new_with_core(store.core(), None, None)
        .await
        .unwrap();
    gov.attach_recovery_sink(journal).await.unwrap();
    let cost = flat_cost(0);
    gov.hydrate_budgets_async(&cost, crate::store::now())
        .await
        .unwrap();
    gov.resume_raw_recovery().await.unwrap();
    let unknown = gov.recovery_event(intent.operation_id).unwrap();
    assert_eq!(unknown.state, RecoveryState::LandedUnknown);
    accrue_plain(&gov, &key.id, LATER_INPUT);
    gov.flush_budgets().await;
    assert_eq!(
        store
            .ledger()
            .get_usage(&key.id, 0)
            .await
            .unwrap()
            .tokens_for_whole_test(MODEL),
        Some(FIRST_INPUT + LATER_INPUT)
    );

    {
        let mut cells = gov.budget.write(&key.id);
        let cell = cells.get_mut(&key.id).unwrap();
        cell.mutate(|cell| {
            let units = &mut cell
                .models
                .iter_mut()
                .find(|model| &*model.model == MODEL)
                .unwrap()
                .cur;
            let n = units.get_mut("input").unwrap();
            *n = n.checked_sub(whole_count(FIRST_INPUT)).unwrap();
            cell.dirty = true;
        });
    }
    gov.flush_budgets().await;
    assert_eq!(
        store
            .ledger()
            .get_usage(&key.id, 0)
            .await
            .unwrap()
            .tokens_for_whole_test(MODEL),
        Some(FIRST_INPUT + LATER_INPUT),
        "dependent negative remains quarantined while fresh positive has posted"
    );
    let selected = gov.recovery_event(intent.operation_id).unwrap();
    let resolution = RecoveryResolution {
        operation_id: intent.operation_id,
        body_fingerprint: intent.body_fingerprint,
        expected_revision: selected.revision,
        verdict: RecoveryVerdict::Landed,
        sender_quiesced: true,
        backend_quiesced: true,
        actor: "operator".into(),
        reason: "original backend receipt confirmed after sender retirement".into(),
    };
    let settled = gov
        .recovery()
        .resolve(&cost, resolution.clone())
        .await
        .unwrap();
    assert_eq!(settled.state, RecoveryState::Settled);
    let audit: serde_json::Value =
        serde_json::from_slice(&gov.recovery_event(intent.operation_id).unwrap().payload).unwrap();
    assert_eq!(audit["verdict"]["sender_quiesced"], true);
    assert_eq!(audit["verdict"]["backend_quiesced"], true);
    gov.recovery().resolve(&cost, resolution).await.unwrap();
    assert_eq!(
        store
            .ledger()
            .get_usage(&key.id, 0)
            .await
            .unwrap()
            .tokens_for_whole_test(MODEL),
        Some(LATER_INPUT)
    );
}
