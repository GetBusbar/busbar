// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Selected partition records use the actual signed checkpoint Store fixture. Serialized
//! input keeps the regression runnable against the predecessor that rejects this variant.

use super::*;
use crate::governance::GovState;

fn source_facts(reported: Option<u64>, floor: Option<u64>, estimated: Option<u64>) -> json::Value {
    let high_water = reported
        .into_iter()
        .chain(floor)
        .chain(estimated)
        .max()
        .unwrap_or(0);
    json::json!({
        "reported": reported.map(Count::from),
        "floor": floor.map(Count::from),
        "estimated": estimated.map(Count::from),
        "rate_high_water": Count::from(high_water),
    })
}

fn attempt(
    preparation: u32,
    dispatch: Option<u32>,
    model: &str,
    facts: json::Value,
) -> json::Value {
    json::json!({
        "preparation": preparation,
        "dispatch": dispatch,
        "kind": "model",
        "instance": "plane",
        "selected_pool": "plane\u{1f}pool",
        "resource": model,
        "usage": {
            "lane": format!("plane\u{1f}{model}"),
            "provider": format!("provider-{model}"),
            "classes": { "work": facts },
        },
        "transport": if dispatch.is_some() { "committed" } else { "no_send" },
        "finality": if dispatch.is_some() { "complete" } else { "unknown" },
    })
}

fn selected_value() -> json::Value {
    let mut value = json::to_value(&unit(1)).unwrap();
    value["lane"] = json::json!("");
    value["provider"] = json::json!(null);
    value["units"] = json::json!({});
    value["ended"] = json::json!(true);
    value["partitions"] = json::json!({
        "version": 1,
        "request_pool": "plane\u{1f}pool",
        "routing_generation": 0,
        "attempt_limit": 3,
        "declared_classes": ["work"],
        "attempt_classes": ["work"],
        "physical_classes": ["work"],
        "session_origin": { "instance": "plane", "lane": "plane\u{1f}", "provider": null },
        "fee": { "state": "not_owner", "basis": { "lane": null, "era": { "effective_from": 42, "entry_id": null } } },
        "session": null,
        "attempts": [
            attempt(1, None, "declined", source_facts(None, None, None)),
            attempt(2, Some(1), "A", source_facts(Some(12), Some(18), Some(20))),
            attempt(3, Some(2), "B", source_facts(Some(8), None, None)),
        ],
        "far_end_answered": true,
        "caller_bytes_committed": true,
        "disposition": "end",
        "final_target": 3,
    });
    value
}

fn decode(value: &json::Value) -> UnitCheckpoint {
    let snapshot: UnitCheckpoint = json::from_value(value)
        .expect("the signed checkpoint variant must retain all selected partitions");
    snapshot.validate().unwrap();
    snapshot
}

async fn governance() -> GovState {
    GovState::new_with_core(crate::real_store::core().await, None, None)
        .await
        .unwrap()
}

/// A selected checkpoint with every name the partition records hold: three attempts, a session
/// partition with its own class, and (when `cancelled`) a cancel reason.
fn every_name(cancelled: bool) -> UnitCheckpoint {
    let mut value = selected_value();
    value["partitions"]["declared_classes"] = json::json!(["session.seconds", "work"]);
    value["partitions"]["session"] = json::json!({
        "lane": "plane\u{1f}",
        "provider": null,
        "classes": { "session.seconds": source_facts(Some(3), None, None) },
    });
    if cancelled {
        value["partitions"]["disposition"] = json::json!({ "cancel": { "reason": "client_gone" } });
        value["partitions"]["final_target"] = json::json!(null);
    }
    decode(&value)
}

/// The stored bytes of a selected checkpoint do not change with how its names are held. The
/// expected bytes are what this same fixture wrote at a3456db589, when every name in the
/// partition records was an owned `String`; the records now hold shared text and must write
/// the same bytes, and read them back to the same record.
#[test]
fn selected_checkpoint_stored_bytes_are_the_bytes_written_before_shared_names() {
    let snapshots = [every_name(false), every_name(true)];
    let written = snapshots
        .each_ref()
        .map(|snapshot| json::to_string(snapshot).unwrap());
    assert_eq!(
        written,
        [
            format!("{STORED_BODY}{STORED_END}"),
            format!("{STORED_BODY}{STORED_CANCEL}"),
        ],
        "stored bytes changed"
    );
    for (snapshot, written) in snapshots.iter().zip(&written) {
        let read: UnitCheckpoint = json::parse_str(written).unwrap();
        assert_eq!(&read, snapshot);
        assert_eq!(&json::to_string(&read).unwrap(), written);
    }
}

/// What a3456db589 wrote for [`every_name`], up to the disposition (the two cases differ only
/// from there).
const STORED_BODY: &str = r#"{"id":[162,162,162,162,162,162,162,162,162,162,162,162,162,162,162,162],"revision":1,"unit":17,"principal":"race-principal","group":"","arrived":1700000000,"lane":"","provider":null,"era_at":42,"era_entry":null,"units":{},"targets":[{"bucket":"race-principal","window":0,"group":null}],"metered":true,"ended":true,"terminal":null,"audit":[123,125],"partitions":{"version":1,"request_pool":"plane\u001fpool","routing_generation":0,"attempt_limit":3,"declared_classes":["session.seconds","work"],"attempt_classes":["work"],"physical_classes":["work"],"session_origin":{"instance":"plane","lane":"plane\u001f","provider":null},"fee":{"state":"not_owner","basis":{"lane":null,"era":{"effective_from":42,"entry_id":null}}},"session":{"lane":"plane\u001f","provider":null,"classes":{"session.seconds":{"reported":3,"floor":null,"estimated":null,"rate_high_water":3}}},"attempts":[{"preparation":1,"dispatch":null,"kind":"model","instance":"plane","selected_pool":"plane\u001fpool","resource":"declined","usage":{"lane":"plane\u001fdeclined","provider":"provider-declined","classes":{"work":{"reported":null,"floor":null,"estimated":null,"rate_high_water":0}}},"transport":"no_send","finality":"unknown"},{"preparation":2,"dispatch":1,"kind":"model","instance":"plane","selected_pool":"plane\u001fpool","resource":"A","usage":{"lane":"plane\u001fA","provider":"provider-A","classes":{"work":{"reported":12,"floor":18,"estimated":20,"rate_high_water":20}}},"transport":"committed","finality":"complete"},{"preparation":3,"dispatch":2,"kind":"model","instance":"plane","selected_pool":"plane\u001fpool","resource":"B","usage":{"lane":"plane\u001fB","provider":"provider-B","classes":{"work":{"reported":8,"floor":null,"estimated":null,"rate_high_water":8}}},"transport":"committed","finality":"complete"}],"far_end_answered":true,"caller_bytes_committed":true,"#;
const STORED_END: &str = r#""disposition":"end","final_target":3}}"#;
const STORED_CANCEL: &str =
    r#""disposition":{"cancel":{"reason":"client_gone"}},"final_target":null}}"#;

fn initial_selected() -> UnitCheckpoint {
    let mut value = selected_value();
    value["revision"] = json::json!(0);
    value["ended"] = json::json!(false);
    value["metered"] = json::json!(false);
    value["partitions"]["attempts"] = json::json!([]);
    value["partitions"]["far_end_answered"] = json::json!(false);
    value["partitions"]["caller_bytes_committed"] = json::json!(false);
    value["partitions"]["disposition"] = json::json!("running");
    value["partitions"]["final_target"] = json::json!(null);
    value["partitions"]["fee"]["state"] = json::json!("pending_owner");
    decode(&value)
}

#[tokio::test]
async fn selected_activation_refusal_rolls_back_custody_before_retry() {
    use crate::governance::unit_checkpoint::SelectedActivationError;
    let gov = governance().await;
    let initial = initial_selected();
    let result = gov.activate_selected_checkpoint(initial.clone(), |accepted| {
        assert_eq!(*accepted, initial);
        Err::<(), _>("admission ended before CAS")
    });
    assert!(matches!(result, Err(SelectedActivationError::Publish(_))));
    assert!(!gov.unit_checkpoint_pending(&initial.id));
    assert_eq!(gov.unit_checkpoint_count(), 0);

    let accepted = gov
        .activate_selected_checkpoint(initial.clone(), Ok::<_, ()>)
        .unwrap();
    assert_eq!(*accepted, initial);
    assert!(gov.unit_checkpoint_pending(&initial.id));
    assert_eq!(gov.unit_checkpoint_count(), 1);
    let duplicate: Result<(), SelectedActivationError<()>> = gov
        .activate_selected_checkpoint(initial, |_| {
            panic!("an already owned id must not call the publication callback")
        });
    assert!(matches!(
        duplicate,
        Err(SelectedActivationError::Custody(_))
    ));
    assert_eq!(gov.unit_checkpoint_count(), 1);
}

#[tokio::test]
async fn selected_activation_unwind_removes_unpublished_entry() {
    let gov = governance().await;
    let initial = initial_selected();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        gov.activate_selected_checkpoint(initial.clone(), |_| -> Result<(), ()> {
            panic!("publication unwind")
        })
    }));
    assert!(result.is_err());
    assert!(!gov.unit_checkpoint_pending(&initial.id));
    assert_eq!(gov.unit_checkpoint_count(), 0);
    assert!(gov
        .activate_selected_checkpoint(initial, Ok::<_, ()>)
        .is_ok());
}

async fn prepared_selected(gov: &GovState) -> Arc<UnitCheckpoint> {
    let initial = gov
        .activate_selected_checkpoint(initial_selected(), Ok::<_, ()>)
        .unwrap();
    let mut value = json::to_value(initial.as_ref()).unwrap();
    let mut prepared = attempt(1, None, "A", source_facts(None, None, None));
    prepared["transport"] = json::json!("prepared");
    prepared["finality"] = json::json!("live");
    value["partitions"]["attempts"] = json::json!([prepared]);
    gov.stage_selected_checkpoint(decode(&value), Some(initial.revision))
        .unwrap()
}

fn committed_selected(prepared: &UnitCheckpoint) -> UnitCheckpoint {
    use crate::governance::unit_checkpoint::partitions::Transport;
    let mut snapshot = prepared.clone();
    let attempt = snapshot
        .partitions
        .as_mut()
        .unwrap()
        .attempts
        .last_mut()
        .unwrap();
    attempt.transport = Transport::Committed;
    attempt.dispatch = Some(1);
    snapshot
}

#[tokio::test]
async fn selected_dispatch_commit_refusal_retains_predecessor_and_retry_commits_once() {
    use crate::governance::unit_checkpoint::SelectedCommitError;
    let gov = governance().await;
    let prepared = prepared_selected(&gov).await;
    let next = committed_selected(&prepared);
    let mut token = Some("original reservation");
    let refused = gov.commit_selected_checkpoint(next.clone(), prepared.revision, || {
        Err::<(), _>(token.take().unwrap())
    });
    match refused {
        Err(SelectedCommitError::Commit(original)) => token = Some(original),
        other => panic!("expected rate refusal with original token: {other:?}"),
    }
    let unchanged = gov
        .stage_selected_checkpoint((*prepared).clone(), Some(prepared.revision))
        .unwrap();
    assert_eq!(unchanged, prepared);
    let (accepted, committed) = gov
        .commit_selected_checkpoint(next, prepared.revision, || {
            Ok::<_, ()>(token.take().unwrap())
        })
        .unwrap();
    assert_eq!(committed, "original reservation");
    assert!(token.is_none());
    assert_eq!(accepted.revision, prepared.revision + 1);
    assert_eq!(
        accepted.partitions.as_ref().unwrap().attempts[0].dispatch,
        Some(1)
    );
    let duplicate: Result<(Arc<UnitCheckpoint>, ()), SelectedCommitError<()>> = gov
        .commit_selected_checkpoint((*accepted).clone(), accepted.revision, || {
            panic!("duplicate committed attempt")
        });
    assert!(matches!(duplicate, Err(SelectedCommitError::Custody(_))));
    let current = gov
        .stage_selected_checkpoint((*accepted).clone(), Some(accepted.revision))
        .unwrap();
    assert_eq!(current, accepted);
}

#[tokio::test]
async fn selected_dispatch_commit_preflights_exact_transition_before_consuming_token() {
    use crate::governance::unit_checkpoint::SelectedCommitError;
    let gov = governance().await;
    let prepared = prepared_selected(&gov).await;
    let next = committed_selected(&prepared);
    let mut candidates = vec![(next.clone(), prepared.revision - 1)];
    let mut changed_source = next.clone();
    changed_source.partitions.as_mut().unwrap().attempts[0]
        .usage
        .classes
        .get_mut("work")
        .unwrap()
        .reported = Some(Count::ZERO);
    candidates.push((changed_source, prepared.revision));
    let mut wrong_dispatch = next;
    wrong_dispatch.partitions.as_mut().unwrap().attempts[0].dispatch = Some(2);
    candidates.push((wrong_dispatch, prepared.revision));
    let mut token = Some("unconsumed reservation");
    for (candidate, revision) in candidates {
        let result = gov
            .commit_selected_checkpoint(candidate, revision, || Ok::<_, ()>(token.take().unwrap()));
        assert!(matches!(result, Err(SelectedCommitError::Custody(_))));
        assert_eq!(token, Some("unconsumed reservation"));
    }
    assert_eq!(
        gov.stage_selected_checkpoint((*prepared).clone(), Some(prepared.revision))
            .unwrap(),
        prepared
    );
}

fn meter_events(
    gov: &GovState,
    snapshot: &UnitCheckpoint,
) -> Vec<busbar_contract::records::MeteringDelta> {
    gov.unit_terminal_events(snapshot)
        .unwrap()
        .iter()
        .filter(|event| event.kind == RecoveryKind::Metering)
        .flat_map(|event| GovState::legacy_metering_values(event).unwrap())
        .collect()
}

#[tokio::test]
async fn selected_signed_snapshot_replays_all_sources_and_preparation_identity() {
    let fixture = fixture().await;
    let snapshot = decode(&selected_value());
    fixture.sink.persist(&snapshot).await.unwrap();
    let replay = fixture.sink.replay().await.unwrap();
    assert_eq!(replay, vec![snapshot.clone()]);
    fixture.sink.persist(&snapshot).await.unwrap();
    assert_eq!(fixture.sink.replay().await.unwrap(), replay);
    let encoded = json::to_value(&replay[0]).unwrap();
    assert_eq!(encoded["partitions"]["final_target"].as_u64(), Some(3));
    assert_eq!(
        encoded["partitions"]["attempts"][1]["dispatch"].as_u64(),
        Some(1)
    );
    assert_eq!(
        encoded["partitions"]["attempts"][2]["dispatch"].as_u64(),
        Some(2)
    );
    assert_eq!(
        encoded["partitions"]["attempts"][1]["usage"]["classes"]["work"],
        source_facts(Some(12), Some(18), Some(20))
    );
}

#[tokio::test]
async fn selected_events_keep_both_providers_and_only_one_logical_request() {
    let gov = governance().await;
    let snapshot = decode(&selected_value());
    let events = gov.unit_terminal_events(&snapshot).unwrap();
    let identities: std::collections::BTreeSet<_> =
        events.iter().map(|event| event.operation_id).collect();
    assert_eq!(identities.len(), events.len());
    let meters = meter_events(&gov, &snapshot);
    assert_eq!(meters.len(), 3);
    assert_eq!(meters[0].model, "plane\u{1f}A");
    assert_eq!(meters[0].provider, "provider-A");
    assert_eq!(meters[0].usage_units["work"], Count::from(12u64).micros());
    assert_eq!(meters[0].requests, 0);
    assert_eq!(meters[1].model, "plane\u{1f}B");
    assert_eq!(meters[1].usage_units["work"], Count::from(8u64).micros());
    assert_eq!(meters[1].requests, 0);
    assert_eq!(meters[2].model, "plane\u{1f}B");
    assert_eq!(meters[2].provider, "provider-B");
    assert_eq!(meters[2].requests, 1);
    assert!(meters[2].usage_units.is_empty());
    assert!(meters
        .iter()
        .all(|row| row.priced_from_ms == snapshot.era_at));
}

#[tokio::test]
async fn selected_estimates_never_become_terminal_or_recovery_usage_debt() {
    let gov = governance().await;
    for disposition in ["end", "recovered_running"] {
        let mut value = selected_value();
        value["partitions"]["disposition"] = json::json!(disposition);
        value["partitions"]["attempts"] = json::json!([attempt(
            1,
            Some(1),
            "A",
            source_facts(None, None, Some(500))
        )]);
        value["partitions"]["attempts"][0]["finality"] = json::json!("unknown");
        value["partitions"]["final_target"] = json::json!(null);
        value["metered"] = json::json!(false);
        let snapshot = decode(&value);
        assert!(gov.unit_terminal_events(&snapshot).unwrap().is_empty());
        let encoded = json::to_value(&snapshot).unwrap();
        assert_eq!(
            encoded["partitions"]["attempts"][0]["usage"]["classes"]["work"],
            source_facts(None, None, Some(500))
        );
    }
}

#[tokio::test]
async fn selected_cancel_preserves_the_independent_no_upstream_head_arm() {
    let gov = governance().await;
    for (answered, committed, expected_usage) in [
        (false, false, 0),
        (false, true, 0),
        (true, false, 0),
        (true, true, 2),
    ] {
        let mut value = selected_value();
        value["partitions"]["disposition"] = json::json!({ "cancel": { "reason": "client_gone" } });
        value["partitions"]["far_end_answered"] = json::json!(answered);
        value["partitions"]["caller_bytes_committed"] = json::json!(committed);
        value["partitions"]["final_target"] = json::json!(null);
        value["metered"] = json::json!(expected_usage != 0);
        let meters = meter_events(&gov, &decode(&value));
        assert_eq!(
            meters
                .iter()
                .filter(|row| !row.usage_units.is_empty())
                .count(),
            expected_usage
        );
    }
}

#[tokio::test]
async fn selected_no_winner_recovery_uses_the_captured_host_request_origin() {
    let gov = governance().await;
    let mut value = selected_value();
    value["partitions"]["disposition"] = json::json!("recovered_running");
    value["partitions"]["final_target"] = json::json!(null);
    value["partitions"]["attempts"][2]["usage"]["classes"]["work"] = source_facts(None, None, None);
    value["partitions"]["attempts"][2]["finality"] = json::json!("unknown");
    let meters = meter_events(&gov, &decode(&value));
    assert_eq!(meters.len(), 2);
    assert_eq!(meters[0].model, "plane\u{1f}A");
    assert_eq!(meters[0].usage_units["work"], Count::from(12u64).micros());
    assert_eq!(meters[1].model, "plane\u{1f}");
    assert!(meters[1].provider.is_empty());
    assert_eq!(meters[1].requests, 1);
    assert!(meters[1].usage_units.is_empty());
}

#[tokio::test]
async fn selected_memory_capacity_retains_all_facts_then_retries_once() {
    use crate::governance::unit_checkpoint::SelectedTransfer;
    use crate::governance::{MeterCounts, MAX_PENDING_METERING_PER_SHARD};
    let gov = governance().await;
    let snapshot = decode(&selected_value());
    let mut running = snapshot.clone();
    running.ended = false;
    running.partitions.as_mut().unwrap().disposition =
        crate::governance::unit_checkpoint::partitions::Disposition::Running;
    let accepted = gov.stage_selected_checkpoint(running, None).unwrap();
    {
        let mut shard = gov
            .pending_metering
            .shard_for(&snapshot.principal)
            .lock()
            .unwrap();
        for i in 0..MAX_PENDING_METERING_PER_SHARD {
            shard.insert(
                (
                    snapshot.principal.clone(),
                    0,
                    format!("occupied-{i}"),
                    String::new(),
                    0,
                    String::new(),
                    String::new(),
                )
                    .into(),
                MeterCounts::default(),
            );
        }
    }
    assert!(matches!(
        gov.finish_selected_checkpoint(snapshot.clone(), Some(accepted.revision)),
        SelectedTransfer::RetainedPending(_)
    ));
    assert!(gov
        .budget
        .read(&snapshot.principal)
        .get(&snapshot.principal)
        .is_none());
    assert!(gov.unresolved_unit_target(&snapshot.principal, 0));
    assert!(matches!(
        gov.finish_selected_checkpoint(snapshot.clone(), Some(accepted.revision)),
        SelectedTransfer::RetainedPending(_)
    ));
    assert!(gov
        .budget
        .read(&snapshot.principal)
        .get(&snapshot.principal)
        .is_none());
    drop(gov.pending_metering.drain().collect::<Vec<_>>());
    gov.flush_unit_checkpoints().await.unwrap();
    assert!(gov.unresolved_unit_target(&snapshot.principal, 0));
    assert!(gov
        .take_selected_terminal_snapshot(snapshot.id)
        .unwrap()
        .is_some());
    gov.flush_unit_checkpoints().await.unwrap();
    assert!(!gov.unresolved_unit_target(&snapshot.principal, 0));
    assert_eq!(work_units(&gov, &snapshot.principal), Count::from(20u64));
    let meters: Vec<_> = gov.pending_metering.drain().collect();
    assert_eq!(
        meters
            .iter()
            .map(|(_, counts)| counts.requests)
            .sum::<u64>(),
        1
    );
    gov.flush_unit_checkpoints().await.unwrap();
    assert!(gov.pending_metering.drain().next().is_none());
    assert_eq!(work_units(&gov, &snapshot.principal), Count::from(20u64));
}

#[tokio::test]
async fn selected_replay_refuses_an_incomplete_or_changed_terminal_vector() {
    let gov = governance().await;
    let mut snapshot = decode(&selected_value());
    snapshot.terminal = Some(gov.unit_terminal_events(&snapshot).unwrap());
    gov.validate_selected_terminal(&snapshot).unwrap();
    let original = snapshot.clone();
    snapshot.terminal.as_mut().unwrap().pop();
    assert!(gov.validate_selected_terminal(&snapshot).is_err());
    snapshot = original;
    snapshot.terminal.as_mut().unwrap()[0].payload.push(0);
    assert!(gov.validate_selected_terminal(&snapshot).is_err());
}

#[tokio::test]
async fn selected_refused_publication_retains_the_previous_revision_and_sources() {
    let gov = governance().await;
    let mut value = selected_value();
    value["ended"] = json::json!(false);
    value["partitions"]["disposition"] = json::json!("running");
    let accepted = gov.stage_selected_checkpoint(decode(&value), None).unwrap();
    let mut changed = (*accepted).clone();
    changed.partitions.as_mut().unwrap().attempts[1]
        .usage
        .classes
        .get_mut("work")
        .unwrap()
        .reported = None;
    assert!(gov
        .stage_selected_checkpoint(changed, Some(accepted.revision))
        .is_err());
    let repeated = gov
        .stage_selected_checkpoint((*accepted).clone(), Some(accepted.revision))
        .unwrap();
    assert_eq!(accepted, repeated);
}

#[tokio::test]
async fn selected_pending_fee_keeps_raw_custody_until_nonparticipating_observation() {
    use crate::governance::unit_checkpoint::{partitions::*, SelectedTransfer};
    use busbar_contract::records::MeteringPricingV1;
    let gov = governance().await;
    // The money owner's own completion cell (arch lints section 3.1), published here by hand.
    let completion = Arc::new(SelectedFeeCompletion::default());
    let mut snapshot = decode(&selected_value());
    snapshot.partitions.as_mut().unwrap().fee = CapturedFee::PendingOwner {
        basis: FeeBasis {
            lane: Some("plane\u{1f}original-pool".into()),
            era: busbar_kernel_ledger::cost::RawRateEra::legacy(73),
        },
    };
    let mut running = snapshot.clone();
    running.ended = false;
    running.partitions.as_mut().unwrap().disposition = Disposition::Running;
    let prior = gov.stage_selected_checkpoint(running, None).unwrap();
    let accepted = match gov.finish_selected_checkpoint_with_fee(
        snapshot.clone(),
        Some(prior.revision),
        Some(completion.clone()),
    ) {
        SelectedTransfer::RetainedPending(accepted) => accepted,
        _ => panic!("pending fee must retain custody"),
    };
    let mut handle = gov.selected_terminal_completion(&accepted).unwrap();
    assert!(gov.selected_terminal_completion(&accepted).is_err());
    let other = governance().await;
    assert!(handle.wait(&other).await.is_err());
    let mut forged = (*accepted).clone();
    forged.partitions.as_mut().unwrap().attempts[1].resource = Some("forged".into());
    assert!(gov.selected_terminal_completion(&Arc::new(forged)).is_err());
    drop(handle);
    let mut handle = gov.selected_terminal_completion(&accepted).unwrap();
    struct WakeCount(AtomicUsize);
    impl std::task::Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    let wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
    let waker = std::task::Waker::from(wakes.clone());
    let mut context = std::task::Context::from_waker(&waker);
    let mut waiting = Box::pin(handle.wait(&gov));
    assert!(std::future::Future::poll(waiting.as_mut(), &mut context).is_pending());
    drop(waiting);
    drop(handle);
    assert!(gov.unit_checkpoint_pending(&snapshot.id));
    let mut handle = gov.selected_terminal_completion(&accepted).unwrap();
    let mut waiting = Box::pin(handle.wait(&gov));
    assert!(std::future::Future::poll(waiting.as_mut(), &mut context).is_pending());
    gov.flush_unit_checkpoints().await.unwrap();
    assert!(gov.unresolved_unit_target(&snapshot.principal, 0));
    assert!(gov.pending_metering.drain().next().is_none());
    completion.complete(FeeResult::Charged);
    gov.flush_unit_checkpoints().await.unwrap();
    assert!(gov.unresolved_unit_target(&snapshot.principal, 0));
    assert!(wakes.0.load(Ordering::Relaxed) > 0);
    let final_snapshot = match std::future::Future::poll(waiting.as_mut(), &mut context) {
        std::task::Poll::Ready(Ok(snapshot)) => snapshot,
        _ => panic!("fee successor must wake the final reader"),
    };
    drop(waiting);
    assert!(matches!(
        final_snapshot.partitions.as_ref().unwrap().fee,
        CapturedFee::ResolvedOwner {
            result: FeeResult::Charged,
            ..
        }
    ));
    gov.flush_unit_checkpoints().await.unwrap();
    assert!(!gov.unresolved_unit_target(&snapshot.principal, 0));
    assert!(Arc::ptr_eq(
        &final_snapshot,
        &handle.wait(&gov).await.unwrap()
    ));
    assert!(handle.wait(&other).await.is_err());
    let rows: Vec<_> = gov.pending_metering.drain().collect();
    let (key, fee) = rows
        .iter()
        .find(|(_, counts)| matches!(counts.pricing, Some(MeteringPricingV1::SelectedFee { .. })))
        .unwrap();
    assert_eq!(key.common.4, 73);
    assert_eq!(fee.requests, 0);
    assert!(
        matches!(&fee.pricing, Some(MeteringPricingV1::SelectedFee { lane: Some(lane), charged: 1, refunded: 0, unknown: 0 }) if lane == "plane\u{1f}original-pool")
    );
    assert!(matches!(
        gov.finish_selected_checkpoint(snapshot, Some(prior.revision)),
        SelectedTransfer::RejectedNotOwned { .. }
    ));
}

#[tokio::test]
async fn selected_unknown_fee_is_emitted_even_without_a_logical_request() {
    use crate::governance::unit_checkpoint::partitions::*;
    use busbar_contract::records::MeteringPricingV1;
    let gov = governance().await;
    let mut snapshot = decode(&selected_value());
    snapshot.metered = false;
    let parts = snapshot.partitions.as_mut().unwrap();
    parts.disposition = Disposition::Failed;
    parts.fee = CapturedFee::RecoveredUnknown {
        basis: parts.fee.basis().clone(),
    };
    let rows = meter_events(&gov, &snapshot);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].requests, 0);
    assert!(rows[0].usage_units.is_empty());
    assert!(matches!(
        rows[0].pricing,
        Some(MeteringPricingV1::SelectedFee {
            charged: 0,
            refunded: 0,
            unknown: 1,
            ..
        })
    ));
}

/// The principal's raw `work` counts across its model cells. `total_tokens` is a token-class view
/// that counts `work` only while some admitted plane declares it in the token family, which no
/// plane in this test process does.
fn work_units(gov: &GovState, principal: &str) -> Count {
    let cells = gov.budget.read(principal);
    Count::total(
        cells[principal]
            .models
            .iter()
            .filter_map(|model| model.cur.get("work").copied()),
    )
    .expect("work counts fit Count")
}
